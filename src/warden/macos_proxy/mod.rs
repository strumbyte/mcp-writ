//! PR-11 PoC — macOS loopback CONNECT proxy path:
//! a `sandbox-exec` profile whose only outbound TCP endpoint is a
//! loopback CONNECT proxy, plus an in-process proxy that evaluates the
//! policy's name/IP destination rules and dials outward itself.
//!
//! Why this exists beside the `sandbox-exec`-only path: SBPL remote
//! rules can express `localhost:port` endpoints and nothing else —
//! verified on macOS 26: `(remote ip)` and literal-IP `remote tcp`
//! addresses are rejected at profile load ("host must be * or
//! localhost"). Destination rules therefore stay Auditor-enforced on
//! the native path. The proxy converts that gap into a real control:
//! every outbound `connect(2)` inside the sandbox dead-ends at the
//! loopback listener, whose `CONNECT host:port` authority carries the
//! intended destination explicitly — name rules apply to the authority
//! string, IP rules to the literal or resolved address.
//!
//! What the profile denies in proxy mode:
//!
//! - **all non-loopback TCP** — kernel-`EPERM`; the only outbound
//!   endpoint is `localhost:<proxy>` (plus policy-declared
//!   `localhost:port` rules). Kernel denies are not observable to
//!   user space, so they cannot emit `sandbox.network_denied` — the
//!   audited deny is the proxy's own evaluation result.
//! - **all UDP** — no CONNECT equivalent exists; `sendto`/`connect`
//!   on datagram sockets is denied outright.
//! - **the OS resolver** — `com.apple.mDNSResponder` is not granted,
//!   so `getaddrinfo` fails inside the sandbox. A workload resolves
//!   nothing locally; it hands hostnames to the proxy and the proxy
//!   resolves outside the sandbox. This is the plan's fail-closed
//!   posture: an OS-resolved name could reach an upstream DNS server
//!   the policy never judged (a covert egress channel).
//! - **loopback/private-utility CONNECT destinations at the proxy** —
//!   `CONNECT` to loopback, unspecified, link-local, or multicast
//!   addresses is refused regardless of policy: the proxy runs on the
//!   host network where those addresses name host services, not the
//!   sandbox's own loopback (SSRF guard; the workload cannot run
//!   loopback servers anyway — `network-bind` is granted only for
//!   policy-declared `allow_listen`, pinned to loopback).
//!
//! Process shape (all in the `mcp-writ` parent; the sandbox only ever
//! wraps the workload):
//!
//! ```text
//!   mcp-writ macos-proxy-run --policy p.kdl -- <workload>
//!     ├── CONNECT proxy task  (tokio listener on 127.0.0.1:port)
//!     └── sandbox-exec -p <SBPL> -- <workload>   (egress → proxy only)
//! ```
//!
//! Fail-closed ordering: helper validation, profile build, listener
//! bind, and spawn refuse before launch; proxy-task or audit-sink
//! loss kills the workload's process group rather than let it run
//! unenforced (its egress is loopback-only either way — supervision
//! is about not stranding the workload, not about a wider hole).

mod proxy;
mod report;
mod spawn;

pub(crate) use crate::warden::macos_sandbox::SpawnLiveness;
pub(crate) use proxy::{ConnectProxy, ConnectProxyConfig, ProxyStats};
pub(crate) use report::report_json;
pub(crate) use spawn::spawn_proxy_child;

use std::net::SocketAddr;

/// Proxy env the workload receives. The credential is a per-launch
/// bearer token in the URL userinfo — proxy-aware clients translate it
/// into `Proxy-Authorization` automatically, and a sibling sandboxed
/// (or accidental local) client cannot piggyback the listener without
/// it. `no_proxy`/`NO_PROXY` are scrubbed so nothing bypasses the
/// proxy to a port it could otherwise reach.
pub(crate) const PROXY_ENV_VARS: &[&str] = &[
    "http_proxy",
    "HTTP_PROXY",
    "https_proxy",
    "HTTPS_PROXY",
    "all_proxy",
    "ALL_PROXY",
];

/// Username half of the injected proxy credential — the password half
/// is the per-launch token.
pub(crate) const PROXY_USER: &str = "mcpwrit";

/// TTL cap applied to name→IP grants minted from the proxy's own
/// resolutions. `getaddrinfo` does not return answer TTLs, so a grant
/// cannot inherit the real answer lifetime — a fixed cap bounds the
/// widening window (the grant only ever re-authorizes a flow to an
/// address the resolver actually vended for an allowed name). The DNS
/// gate's answer-accurate TTLs remain the stronger mechanism on paths
/// that run it.
pub(crate) const PROXY_GRANT_TTL: std::time::Duration = std::time::Duration::from_secs(300);

/// Bound on the CONNECT request head — a client sending more gets a
/// plain close; headers beyond this are a protocol violation, not a
/// bigger buffer.
pub(crate) const MAX_HEAD_BYTES: usize = 8192;

/// Per-phase timeouts so a stalled client cannot pin proxy tasks.
pub(crate) const HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
pub(crate) const RESOLVE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
pub(crate) const DIAL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// The listener + credential a spawned workload is pointed at.
pub(crate) struct ProxyEndpoint {
    /// Loopback address the CONNECT proxy accepts on — injected into
    /// the SBPL profile and the child's proxy env vars.
    pub addr: SocketAddr,
    /// The expected `Proxy-Authorization` credential password
    /// ([`PROXY_USER`] is the fixed username).
    pub token: String,
}

/// Destinations the proxy never dials, whatever the policy allows:
/// on the host network these names address the *host's* services, not
/// anything inside the sandbox. A CONNECT to them would turn the
/// proxy into an SSRF relay. The input is judged as the endpoint the
/// dial reaches — [`effective_endpoint`] unwraps v4-mapped, NAT64,
/// 6to4, and Teredo spellings, so `64:ff9b::127.0.0.1` or a 6to4/
/// Teredo address carrying a host-side v4 cannot slip past the guard
/// as an IPv6 destination.
pub(crate) fn is_protected_dest(ip: &std::net::IpAddr) -> bool {
    use std::net::IpAddr;
    match crate::warden::ip_eval::effective_endpoint(*ip) {
        IpAddr::V4(v4) => {
            v4.is_loopback()
                // 0.0.0.0/8 — "this host on this network" (RFC 1122);
                // some stacks route it to local services.
                || v4.octets()[0] == 0
                || v4.is_link_local()
                || v4.is_multicast()
                || v4.is_broadcast()
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || (v6.segments()[0] & 0xffc0) == 0xfe80 // fe80::/10 link-local
        }
    }
}

/// Generate a fresh per-launch proxy credential (32 hex chars).
pub(crate) fn new_proxy_token() -> String {
    uuid::Uuid::new_v4().simple().to_string()
}

/// The `Proxy-Authorization` header value a client with the injected
/// env URL sends — `Basic base64(<PROXY_USER>:<token>)`. Compared
/// byte-exact (the b64 form is canonical).
pub(crate) fn expected_auth(token: &str) -> String {
    format!(
        "Basic {}",
        base64_encode(format!("{PROXY_USER}:{token}").as_bytes())
    )
}

/// RFC 4648 base64, standard alphabet with padding — the credential
/// check needs no external crate.
pub(super) fn base64_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(ALPHABET[(n >> 18) as usize & 63] as char);
        out.push(ALPHABET[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            ALPHABET[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            ALPHABET[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}
