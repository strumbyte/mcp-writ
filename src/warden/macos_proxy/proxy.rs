//! The loopback CONNECT proxy — the only TCP endpoint the sandboxed
//! workload can reach.
//!
//! One accept per inbound flow; each `CONNECT authority` is evaluated
//! and either spliced to a real host socket or refused with a short
//! HTTP status. The proxy is the destination-judgment point the audit
//! contract names: `sandbox.network_denied` records come from *its*
//! verdicts — kernel-level SBPL denies are unobservable and are
//! covered by the report's limitation notes instead.
//!
//! Evaluation order mirrors the two-layer model:
//!
//! 1. `CONNECT` authority parses to an IP literal → the IP layer
//!    alone decides (`FlowGate::verdict` — precedence is static deny,
//!    then static allow, then TTL-scoped grant, then the posture).
//!    The judged — and dialed — address is the endpoint the spelling
//!    reaches: v4-mapped/NAT64/6to4/Teredo spellings unwrap to the
//!    embedded IPv4, so a v4 `deny cidr=` cannot be spelled around
//!    through a translator. Protected destinations — loopback/
//!    link-local/unspecified/multicast, host services on this network
//!    rather than sandbox endpoints — refuse before any rule.
//! 2. Authority parses to a name → `dnsgate::name_policy` evaluates it
//!    (deny wins, `deny_all_others` applies). An allowed name is
//!    resolved by the proxy *outside* the sandbox; every returned
//!    address mints a grant under the covering allow rules' proto/port
//!    qualifiers and is then judged by the same IP layer — so a
//!    `deny cidr=` still refuses an allowed name's address, and a
//!    `proto=udp` name allow never authorizes the TCP flow.
//!
//! The payload is never inspected: after `200 Connection Established`
//! the two sockets splice raw bytes both ways.

use std::io;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::dnsgate::allowlist::DynamicAllowList;
use crate::dnsgate::name_policy;
use crate::policy::{EgressProto, OutboundPolicy};
use crate::warden::flow_gate::FlowGate;
use crate::warden::ip_eval::IpVerdict;

use super::{
    DIAL_TIMEOUT, HANDSHAKE_TIMEOUT, MAX_HEAD_BYTES, PROXY_GRANT_TTL, RESOLVE_TIMEOUT,
    is_protected_dest,
};

/// Counters the report's `proxy_stats` block carries.
#[derive(Default)]
pub(crate) struct ProxyStats {
    /// CONNECT flows allowed and established.
    pub accepted: AtomicU64,
    /// Refused at the name layer (`deny host=`/`deny cidr=` on the
    /// authority name, or `deny_all_others` with no covering allow).
    pub denied_name: AtomicU64,
    /// Refused at the IP layer (literal or resolved address).
    pub denied_ip: AtomicU64,
    /// Refused by the protected-destination guard (loopback,
    /// link-local, unspecified, multicast — policy cannot allow them).
    pub denied_protected: AtomicU64,
    /// Missing/wrong `Proxy-Authorization`.
    pub denied_auth: AtomicU64,
    /// Non-CONNECT requests.
    pub rejected_method: AtomicU64,
    /// Malformed request head or authority.
    pub rejected_head: AtomicU64,
    /// Allowed name that did not resolve (or resolved empty).
    pub resolve_failed: AtomicU64,
    /// Name→IP grant registration refused — the grant table was at
    /// capacity; the allowed name's flow then denies as `not-allowed`,
    /// which this count distinguishes from a policy verdict.
    pub grant_refused: AtomicU64,
    /// Allowed verdict whose outward dial failed.
    pub dial_failed: AtomicU64,
    /// Currently open CONNECT tunnels.
    pub active: AtomicUsize,
    pub bytes_to_workload: AtomicU64,
    pub bytes_from_workload: AtomicU64,
}

/// Everything the accept loop needs. The listener is bound by the
/// caller before the sandbox profile is generated — its port is part
/// of the profile.
pub(crate) struct ConnectProxyConfig {
    pub listener: TcpListener,
    /// Expected `Proxy-Authorization` credential — the client sends
    /// `Basic base64(<PROXY_USER>:<token>)` derived from the injected
    /// env URL's userinfo.
    pub expected_auth: String,
    /// Verdict + audit helper (IP layer) shared with the namespaced
    /// proxy.
    pub gate: FlowGate,
    /// The grant table `gate` consults — the proxy also *mints* into
    /// it from its own resolutions of allowed names.
    pub grants: Arc<DynamicAllowList>,
    /// The bound outbound policy — the name layer's input
    /// (`name_policy::evaluate` mirrors the Auditor's host rules).
    pub outbound: Arc<OutboundPolicy>,
    pub stats: Arc<ProxyStats>,
}

pub(crate) struct ConnectProxy {
    listener: TcpListener,
    expected_auth: String,
    gate: Arc<FlowGate>,
    grants: Arc<DynamicAllowList>,
    outbound: Arc<OutboundPolicy>,
    stats: Arc<ProxyStats>,
}

impl ConnectProxy {
    pub fn new(cfg: ConnectProxyConfig) -> Self {
        Self {
            listener: cfg.listener,
            expected_auth: cfg.expected_auth,
            gate: Arc::new(cfg.gate),
            grants: cfg.grants,
            outbound: cfg.outbound,
            stats: cfg.stats,
        }
    }

    /// Accept until the task is aborted — each connection is its own
    /// task so one stalled client cannot block the launch.
    pub async fn run(self: Arc<Self>) {
        loop {
            match self.listener.accept().await {
                Ok((stream, _peer)) => {
                    let me = self.clone();
                    tokio::spawn(async move {
                        me.handle_conn(stream).await;
                    });
                }
                Err(e) => {
                    // A listener failure is fatal for the path — return
                    // so the supervisor's proxy-loss arm kills the
                    // workload rather than stranding it without egress.
                    tracing::error!("CONNECT proxy accept failed, stopping proxy: {e}");
                    return;
                }
            }
        }
    }

    async fn handle_conn(&self, mut inbound: TcpStream) {
        let (head, early) = match read_head(&mut inbound).await {
            Ok(Some(v)) => v,
            Ok(None) => {
                self.stats.rejected_head.fetch_add(1, Ordering::Relaxed);
                return;
            }
            Err(_) => {
                self.stats.rejected_head.fetch_add(1, Ordering::Relaxed);
                return;
            }
        };
        let (method, target) = match parse_request_line(&head) {
            Some(v) => v,
            None => {
                self.stats.rejected_head.fetch_add(1, Ordering::Relaxed);
                let _ = inbound.write_all(RESPONSE_400).await;
                return;
            }
        };
        if !method.eq_ignore_ascii_case("connect") {
            self.stats.rejected_method.fetch_add(1, Ordering::Relaxed);
            let _ = inbound.write_all(RESPONSE_405).await;
            return;
        }
        if !head_has_auth(&head, &self.expected_auth) {
            self.stats.denied_auth.fetch_add(1, Ordering::Relaxed);
            let _ = inbound.write_all(RESPONSE_407).await;
            return;
        }
        let (host, port) = match parse_connect_target(target) {
            Ok(v) => v,
            Err(()) => {
                self.stats.rejected_head.fetch_add(1, Ordering::Relaxed);
                let _ = inbound.write_all(RESPONSE_400).await;
                return;
            }
        };

        let candidates = match self.evaluate(host, port).await {
            Err(status) => {
                let _ = inbound.write_all(status).await;
                return;
            }
            Ok(c) => c,
        };

        // Dial the policy-allowed candidates in order — a refused
        // verdict is already audited per address; `dial_failed` and
        // the 502 fire only when every allowed candidate's connect
        // fails (a resolved set commonly contains unreachable
        // addresses a sibling candidate can cover).
        let mut dialed = None;
        for cand in &candidates {
            if let Ok(Ok(s)) = tokio::time::timeout(
                DIAL_TIMEOUT,
                TcpStream::connect(std::net::SocketAddr::new(cand.ip, port)),
            )
            .await
            {
                dialed = Some((s, cand));
                break;
            }
        }
        let Some((mut outbound, cand)) = dialed else {
            self.stats.dial_failed.fetch_add(1, Ordering::Relaxed);
            let _ = inbound.write_all(RESPONSE_502).await;
            return;
        };
        if inbound.write_all(RESPONSE_200).await.is_err() {
            return;
        }
        // Bytes the client already pipelined after the request head
        // (a TLS ClientHello is commonly in the same flight) forward
        // before the splice — never inspected, just relayed.
        if !early.is_empty() && outbound.write_all(&early).await.is_err() {
            return;
        }
        // The flow established — the allowed record lands now so it
        // means "allowed and connected", never just "policy said yes".
        self.gate.allowed(
            EgressProto::Tcp,
            cand.ip,
            port,
            cand.basis,
            cand.rule.as_deref(),
        );
        self.stats.accepted.fetch_add(1, Ordering::Relaxed);
        self.stats.active.fetch_add(1, Ordering::Relaxed);
        match tokio::io::copy_bidirectional(&mut inbound, &mut outbound).await {
            Ok((to_peer, from_peer)) => {
                self.stats
                    .bytes_to_workload
                    .fetch_add(from_peer, Ordering::Relaxed);
                self.stats
                    .bytes_from_workload
                    .fetch_add(to_peer, Ordering::Relaxed);
            }
            Err(e) => {
                tracing::debug!(dest = %cand.ip, port, "CONNECT tunnel ended with error: {e}");
            }
        }
        self.stats.active.fetch_sub(1, Ordering::Relaxed);
    }

    /// Name→IP→protected→verdict. Returns the policy-allowed dial
    /// candidates in resolver order, or the refusal status to write —
    /// every refusal path has already emitted its audit record and
    /// bumped its counter.
    async fn evaluate(
        &self,
        host: ConnectHost,
        port: u16,
    ) -> Result<Vec<Candidate>, &'static [u8]> {
        match host {
            ConnectHost::Ip(ip) => match self.evaluate_ip(ip, port).await {
                Some(c) => Ok(vec![c]),
                None => Err(RESPONSE_403),
            },
            ConnectHost::Name(name) => {
                let ev = name_policy::evaluate(&self.outbound, &name);
                let canonical = ev.canonical.clone();
                if let name_policy::Verdict::Deny(reason) = ev.verdict {
                    self.stats.denied_name.fetch_add(1, Ordering::Relaxed);
                    self.gate
                        .denied_name(
                            &canonical,
                            EgressProto::Tcp,
                            port,
                            reason.decision(),
                            reason.rule(),
                        )
                        .await;
                    return Err(RESPONSE_403);
                }
                let ips = match resolve_name(&canonical, port).await {
                    Some(v) if !v.is_empty() => v,
                    _ => {
                        self.stats.resolve_failed.fetch_add(1, Ordering::Relaxed);
                        self.gate
                            .denied_name(&canonical, EgressProto::Tcp, port, "resolve-error", None)
                            .await;
                        return Err(RESPONSE_502);
                    }
                };
                // Name allowed → the resolver vended these addresses:
                // record them as grants under the covering allow
                // rules' scope before the IP layer judges each —
                // registration must precede evaluation so an address
                // the static rules don't cover can still be allowed
                // via the allowlist-grant basis. A protected
                // destination never enters the table (it is refused
                // before the verdict regardless of grants); a
                // policy-denied address's grant is provably inert —
                // denies precede grants in `IpLayerEvaluator::evaluate`.
                // Grants key on the effective endpoint — the same form
                // `evaluate_ip` normalizes to — so a DNS64-synthesized
                // AAAA (`64:ff9b::x`) mints a grant on the v4 endpoint
                // the flow will be judged as. A refusal means the
                // grant table is at capacity (`PROXY_GRANT_TTL` is
                // nonzero and an allowed verdict always carries quals):
                // count and warn — the flow is then denied as
                // `not-allowed`, which must be distinguishable from a
                // policy verdict in the audit stream.
                for ip in &ips {
                    let canon = crate::warden::ip_eval::effective_endpoint(*ip);
                    if !is_protected_dest(&canon)
                        && !self
                            .grants
                            .register(&canonical, canon, &ev.quals, PROXY_GRANT_TTL)
                    {
                        self.stats.grant_refused.fetch_add(1, Ordering::Relaxed);
                        tracing::warn!(
                            name = %canonical,
                            addr = %canon,
                            "name→IP grant refused (grant table at capacity) — the \
                             allowed name's flow will read as not-allowed"
                        );
                    }
                }
                // Emit the name-layer allow before the per-IP
                // judgment — the record order mirrors the evaluation.
                self.gate.allowed_name(&canonical, EgressProto::Tcp, port);
                let mut candidates = Vec::new();
                for ip in ips {
                    if let Some(c) = self.evaluate_ip(ip, port).await {
                        candidates.push(c);
                    }
                }
                // Every resolved address refused — each refusal already
                // emitted its own denied record; the reply is a single
                // refusal.
                if candidates.is_empty() {
                    Err(RESPONSE_403)
                } else {
                    Ok(candidates)
                }
            }
        }
    }

    /// IP-layer verdict for one address — the allowed [`Candidate`],
    /// or `None` after emitting its own denied record so the audit
    /// stream carries the per-destination truth.
    async fn evaluate_ip(&self, ip: IpAddr, port: u16) -> Option<Candidate> {
        // Judge and dial the endpoint the spelling reaches, not the
        // spelling itself: `::ffff:x`, `64:ff9b::x`, 6to4, and Teredo
        // all name an IPv4 destination — the guard, the deny/allow
        // rules, the audit `dest`, and the dialed socket address are
        // the unwrapped endpoint, so a `deny cidr=` on the v4 cannot
        // be sidestepped by a transition spelling.
        let ip = crate::warden::ip_eval::effective_endpoint(ip);
        if is_protected_dest(&ip) {
            self.stats.denied_protected.fetch_add(1, Ordering::Relaxed);
            self.gate
                .denied(EgressProto::Tcp, ip, port, "protected-dest", None)
                .await;
            return None;
        }
        match self.gate.verdict(ip, EgressProto::Tcp, port) {
            IpVerdict::Allow { basis, rule } => Some(Candidate { ip, basis, rule }),
            IpVerdict::Deny { decision, rule } => {
                self.stats.denied_ip.fetch_add(1, Ordering::Relaxed);
                self.gate
                    .denied(EgressProto::Tcp, ip, port, decision, rule.as_deref())
                    .await;
                None
            }
        }
    }
}

/// One policy-allowed dial target — `network_allowed` records it
/// only once its connect succeeds (the record means "flow
/// established", matching the committed-deny contract).
struct Candidate {
    ip: IpAddr,
    basis: &'static str,
    rule: Option<String>,
}

enum ConnectHost {
    Ip(IpAddr),
    Name(String),
}

const RESPONSE_200: &[u8] = b"HTTP/1.1 200 Connection Established\r\n\r\n";
const RESPONSE_400: &[u8] =
    b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
const RESPONSE_403: &[u8] =
    b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
const RESPONSE_405: &[u8] =
    b"HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
const RESPONSE_407: &[u8] = b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"mcp-writ\"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
const RESPONSE_502: &[u8] =
    b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";

/// Read the request head (`…\r\n\r\n`) within the byte cap and
/// handshake timeout, returning `(head, early)` — `early` is whatever
/// the client already pipelined past the head (e.g. a TLS ClientHello
/// in the same flight) and must be relayed once the tunnel opens.
/// `None` = EOF/oversize/protocol break — callers close without
/// answering.
async fn read_head(stream: &mut TcpStream) -> io::Result<Option<(Vec<u8>, Vec<u8>)>> {
    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];
    let deadline = tokio::time::Instant::now() + HANDSHAKE_TIMEOUT;
    loop {
        if let Some(pos) = find_head_end(&buf) {
            let rest = buf.split_off(pos);
            buf.shrink_to_fit();
            return Ok(Some((buf, rest)));
        }
        if buf.len() >= MAX_HEAD_BYTES {
            return Ok(None);
        }
        let read = tokio::time::timeout_at(deadline, stream.read(&mut chunk)).await;
        match read {
            Ok(Ok(0)) => return Ok(None),
            Ok(Ok(n)) => buf.extend_from_slice(&chunk[..n]),
            Ok(Err(e)) => return Err(e),
            Err(_) => return Ok(None), // handshake timeout
        }
    }
}

/// Position just past `\r\n\r\n`, if present.
fn find_head_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + 4)
}

/// `METHOD SP TARGET SP HTTP/x.y` → (method, target).
fn parse_request_line(head: &[u8]) -> Option<(&str, &str)> {
    let line_end = head.windows(2).position(|w| w == b"\r\n")?;
    let line = std::str::from_utf8(&head[..line_end]).ok()?;
    let mut parts = line.split_whitespace();
    let method = parts.next()?;
    let target = parts.next()?;
    let version = parts.next()?;
    if !version.starts_with("HTTP/") {
        return None;
    }
    Some((method, target))
}

/// Whether the head carries `Proxy-Authorization:` with the expected
/// credential (header names are case-insensitive; the credential is
/// exact).
fn head_has_auth(head: &[u8], expected: &str) -> bool {
    let Ok(text) = std::str::from_utf8(head) else {
        return false;
    };
    for line in text.split("\r\n").skip(1) {
        if line.is_empty() {
            break;
        }
        if let Some((name, value)) = line.split_once(':')
            && name.trim().eq_ignore_ascii_case("proxy-authorization")
        {
            return value.trim() == expected;
        }
    }
    false
}

/// `CONNECT` authority → host kind + port. Accepts `host:port`,
/// `[v6]:port`, and bare-v6 spellings (`::1:443` — non-standard but
/// unambiguous once the last colon splits the port). Rejects missing
/// ports, port 0, userinfo, and empty authorities.
fn parse_connect_target(target: &str) -> Result<(ConnectHost, u16), ()> {
    let target = target.trim();
    if target.is_empty() || target.contains('@') {
        return Err(());
    }
    let (host, port_s) = if let Some(rest) = target.strip_prefix('[') {
        let (v6, tail) = rest.split_once(']').ok_or(())?;
        let port = tail.strip_prefix(':').ok_or(())?;
        (format!("[{v6}]"), port)
    } else {
        let (h, p) = target.rsplit_once(':').ok_or(())?;
        (h.to_string(), p)
    };
    let port: u16 = port_s.parse().map_err(|_| ())?;
    if port == 0 {
        return Err(());
    }
    let literal = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host.as_str());
    if let Ok(ip) = literal.parse::<IpAddr>() {
        return Ok((ConnectHost::Ip(ip), port));
    }
    if host.is_empty() {
        return Err(());
    }
    Ok((ConnectHost::Name(host), port))
}

/// Resolve an allowed name through the host resolver (the proxy runs
/// outside the sandbox) into the deduplicated IP set the dial will
/// try, keeping the resolver's preference order (RFC 6724 — sorting
/// would make IPv4 win over a preferred v6). `None` = resolution
/// failed or timed out.
async fn resolve_name(name: &str, port: u16) -> Option<Vec<IpAddr>> {
    let fut = tokio::net::lookup_host((name, port));
    let addrs = tokio::time::timeout(RESOLVE_TIMEOUT, fut)
        .await
        .ok()?
        .ok()?;
    let mut seen = std::collections::HashSet::new();
    let ips: Vec<IpAddr> = addrs
        .map(|sa| sa.ip())
        .filter(|ip| seen.insert(*ip))
        .collect();
    Some(ips)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::warden::macos_proxy::{PROXY_USER, base64_encode, expected_auth, is_protected_dest};

    // ---------------------------------------------------------------
    // parse_connect_target — the CONNECT authority grammar
    // ---------------------------------------------------------------

    fn target(s: &str) -> Result<(ConnectHost, u16), ()> {
        parse_connect_target(s)
    }

    #[test]
    fn target_name_port() {
        let (host, port) = target("api.example.com:443").unwrap();
        assert!(matches!(host, ConnectHost::Name(ref n) if n == "api.example.com"));
        assert_eq!(port, 443);
    }

    #[test]
    fn target_ipv4_literal() {
        let (host, port) = target("192.0.2.10:8080").unwrap();
        assert!(matches!(host, ConnectHost::Ip(IpAddr::V4(v4)) if v4.octets() == [192, 0, 2, 10]));
        assert_eq!(port, 8080);
    }

    #[test]
    fn target_bracketed_ipv6() {
        let (host, port) = target("[2001:db8::1]:443").unwrap();
        assert!(matches!(host, ConnectHost::Ip(IpAddr::V6(_))));
        assert_eq!(port, 443);
    }

    #[test]
    fn target_bare_ipv6_splits_last_colon() {
        // Non-standard but unambiguous: the last colon splits the port.
        let (host, port) = target("::1:8443").unwrap();
        assert!(matches!(host, ConnectHost::Ip(ip) if ip.is_loopback()));
        assert_eq!(port, 8443);
    }

    #[test]
    fn target_rejects_missing_port() {
        assert!(target("example.com").is_err());
        assert!(target("example.com:").is_err());
        assert!(target("[::1]").is_err());
    }

    #[test]
    fn target_rejects_port_zero_and_bad_ports() {
        assert!(target("example.com:0").is_err());
        assert!(target("example.com:notaport").is_err());
        assert!(target("example.com:65536").is_err());
    }

    #[test]
    fn target_rejects_userinfo_and_empty() {
        assert!(target("user@example.com:443").is_err());
        assert!(target("").is_err());
        assert!(target("  ").is_err());
        assert!(target(":443").is_err());
    }

    // ---------------------------------------------------------------
    // parse_request_line / find_head_end / head_has_auth
    // ---------------------------------------------------------------

    #[test]
    fn request_line_parses_connect() {
        let head = b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let (m, t) = parse_request_line(head).unwrap();
        assert_eq!(m, "CONNECT");
        assert_eq!(t, "example.com:443");
    }

    #[test]
    fn request_line_rejects_malformed() {
        assert!(parse_request_line(b"CONNECT example.com\r\n\r\n").is_none());
        assert!(parse_request_line(b"CONNECT x:1 NOTHTTP\r\n\r\n").is_none());
        assert!(parse_request_line(b"garbage\r\n\r\n").is_none());
    }

    #[test]
    fn head_end_detection() {
        assert_eq!(find_head_end(b"A\r\n\r\n"), Some(5));
        assert_eq!(find_head_end(b"no end"), None);
        assert_eq!(find_head_end(b"X\r\n\r\nrest"), Some(5));
    }

    #[test]
    fn auth_header_matches_case_insensitive_name() {
        let expected = expected_auth("deadbeef");
        let head = format!("CONNECT x:1 HTTP/1.1\r\nPrOxY-AuThOrIzAtIoN: {expected}\r\n\r\n");
        assert!(head_has_auth(head.as_bytes(), &expected));
        let wrong = head.replace(&expected, "Basic Zm9v");
        assert!(!head_has_auth(wrong.as_bytes(), &expected));
        let missing = "CONNECT x:1 HTTP/1.1\r\nHost: x\r\n\r\n";
        assert!(!head_has_auth(missing.as_bytes(), &expected));
    }

    #[test]
    fn expected_auth_is_basic_user_token() {
        // base64("mcpwrit:t0ken") — fixed vector, computed independently.
        assert_eq!(base64_encode(b"mcpwrit:t0ken"), "bWNwd3JpdDp0MGtlbg==");
        assert_eq!(
            expected_auth("t0ken"),
            format!(
                "Basic {}",
                base64_encode(format!("{PROXY_USER}:t0ken").as_bytes())
            )
        );
    }

    // ---------------------------------------------------------------
    // is_protected_dest — the SSRF guard
    // ---------------------------------------------------------------

    #[test]
    fn protected_destinations_cover_loopback_linklocal_multicast() {
        for ip in [
            "127.0.0.1",
            "127.90.1.2",
            "0.0.0.0",
            "169.254.1.1",
            "224.0.0.1",
            "255.255.255.255",
            "::1",
            "::",
            "ff02::1",
            "fe80::1",
            // v4-mapped v6 spellings — they dial the mapped v4 address,
            // so they must be judged as that v4 address.
            "::ffff:127.0.0.1",
            "::ffff:7f00:1",
            "::ffff:0.0.0.0",
            "::ffff:169.254.1.1",
            "::ffff:224.0.0.1",
            // NAT64 well-known prefix — the embedded v4 is what the
            // dial actually reaches through the translator.
            "64:ff9b::127.0.0.1",
            "64:ff9b::0.0.0.0",
            "64:ff9b::169.254.1.1",
            "64:ff9b::255.255.255.255",
            // 6to4 / Teredo carrying a host-side v4 — same translation
            // class as NAT64: the dial reaches the embedded endpoint.
            "2002:7f00:1::",        // 127.0.0.1
            "2002:a9fe:101::",      // 169.254.1.1
            "2001:0000::80ff:fffe", // XOR → 127.0.0.1
            "2001:0000::",          // XOR → 255.255.255.255 (broadcast)
            // 0.0.0.0/8 beyond unspecified — "this network" space some
            // stacks route to local services.
            "0.1.2.3",
            "0.255.0.1",
        ] {
            let ip: IpAddr = ip.parse().unwrap();
            assert!(is_protected_dest(&ip), "{ip} must be protected");
        }
        for ip in [
            "93.184.216.34",
            "8.8.8.8",
            "2606:4700:4700::1111",
            "192.168.1.1",
            "10.0.0.1",
            // Transition spellings carrying an ordinary public v4 — a
            // real, policy-decidable destination, not a protected one.
            "64:ff9b::8.8.8.8",
            "2002:0808:0808::",
            "2001:0000::f7f7:f7f7",
        ] {
            let ip: IpAddr = ip.parse().unwrap();
            assert!(
                !is_protected_dest(&ip),
                "{ip} is a policy-decidable destination, not protected"
            );
        }
    }

    // ---------------------------------------------------------------
    // evaluate_ip — canonicalization, protected-dest, verdict
    // ---------------------------------------------------------------

    /// A proxy instance wired for `evaluate_ip` — the listener only
    /// needs to exist, never accept.
    async fn proxy_for_test(outbound: OutboundPolicy) -> ConnectProxy {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let evaluator = crate::warden::IpLayerEvaluator::new_connect_proxy(&outbound).unwrap();
        let grants = Arc::new(DynamicAllowList::new(64));
        let gate = FlowGate::new(
            evaluator,
            grants.clone(),
            crate::audit_log::AuditLogger::to_tracing(),
            uuid::Uuid::now_v7(),
            None,
        );
        ConnectProxy::new(ConnectProxyConfig {
            listener,
            expected_auth: expected_auth("t0ken"),
            gate,
            grants,
            outbound: Arc::new(outbound),
            stats: Arc::new(ProxyStats::default()),
        })
    }

    #[tokio::test]
    async fn evaluate_ip_refuses_mapped_v6_loopback() {
        // `[::ffff:127.0.0.1]` dials 127.0.0.1 — it must hit the
        // protected-destination guard exactly like the v4 spelling,
        // even under an allow-everything policy.
        let mut outbound = OutboundPolicy {
            deny_all_others: false,
            ..OutboundPolicy::default()
        };
        outbound.allowed = vec!["*".to_string()];
        let proxy = proxy_for_test(outbound).await;
        let mapped: IpAddr = "::ffff:127.0.0.1".parse().unwrap();
        assert!(
            proxy.evaluate_ip(mapped, 443).await.is_none(),
            "a v4-mapped v6 loopback must be refused"
        );
        assert_eq!(proxy.stats.denied_protected.load(Ordering::Relaxed), 1);
        // The v4 spelling refuses identically.
        let v4: IpAddr = "127.0.0.1".parse().unwrap();
        assert!(proxy.evaluate_ip(v4, 443).await.is_none());
        assert_eq!(proxy.stats.denied_protected.load(Ordering::Relaxed), 2);
    }

    #[tokio::test]
    async fn evaluate_ip_judges_mapped_v6_by_ipv4_rules() {
        // A mapped v6 spelling of an allowed CIDR's member matches the
        // IPv4 rule — canonical form reaches both the guard and the
        // verdict.
        let outbound = OutboundPolicy {
            allowed_cidrs: vec!["192.0.2.0/24".to_string()],
            ..OutboundPolicy::default()
        };
        let proxy = proxy_for_test(outbound).await;
        let mapped: IpAddr = "::ffff:192.0.2.10".parse().unwrap();
        let cand = proxy
            .evaluate_ip(mapped, 443)
            .await
            .expect("a mapped v6 literal must be judged against the IPv4 rules it maps to");
        assert_eq!(cand.ip, "192.0.2.10".parse::<IpAddr>().unwrap());
        // And a mapped literal outside the allowed CIDRs is denied —
        // under the canonicalized address, not the v6 spelling.
        let outside: IpAddr = "::ffff:192.0.3.10".parse().unwrap();
        assert!(proxy.evaluate_ip(outside, 443).await.is_none());
        assert_eq!(proxy.stats.denied_ip.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn evaluate_ip_judges_transition_spellings_by_the_embedded_v4() {
        // `CONNECT [64:ff9b::203.0.113.5]` reaches 203.0.113.5 through
        // the translator — a `deny cidr=` on the v4 endpoint must
        // refuse it, and an `allow cidr=` must judge it as the v4 it
        // is (the dial target is the unwrapped endpoint too).
        let denied = OutboundPolicy {
            denied_cidrs: vec!["203.0.113.0/24".to_string()],
            deny_all_others: false,
            ..OutboundPolicy::default()
        };
        let proxy = proxy_for_test(denied).await;
        for spelled in ["64:ff9b::cb00:7105", "2002:cb00:7105::"] {
            assert!(
                proxy
                    .evaluate_ip(spelled.parse().unwrap(), 443)
                    .await
                    .is_none(),
                "{spelled} embeds a denied v4 — must be refused"
            );
        }
        assert_eq!(proxy.stats.denied_ip.load(Ordering::Relaxed), 2);

        let allowed = OutboundPolicy {
            allowed_cidrs: vec!["8.8.8.0/24".to_string()],
            deny_all_others: true,
            ..OutboundPolicy::default()
        };
        let proxy = proxy_for_test(allowed).await;
        let cand = proxy
            .evaluate_ip("64:ff9b::808:808".parse().unwrap(), 443)
            .await
            .expect("a NAT64 spelling of an allowed v4 must be allowed");
        // The candidate dials — and the audit records — the endpoint,
        // not the spelling that named it.
        assert_eq!(cand.ip, "8.8.8.8".parse::<IpAddr>().unwrap());
    }

    // ---------------------------------------------------------------
    // read_head — cap, split, and early bytes
    // ---------------------------------------------------------------

    async fn write_then_shutdown(stream: &mut TcpStream, bytes: &[u8]) {
        stream.write_all(bytes).await.unwrap();
        stream.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn read_head_splits_pipelined_payload() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let client = tokio::spawn(async move {
            let mut c = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
            write_then_shutdown(&mut c, b"CONNECT x:1 HTTP/1.1\r\n\r\nEARLYBYTES").await;
        });
        let (mut server, _) = listener.accept().await.unwrap();
        let (head, early) = read_head(&mut server).await.unwrap().unwrap();
        assert!(head.ends_with(b"\r\n\r\n"));
        assert_eq!(early, b"EARLYBYTES");
        client.await.unwrap();
    }

    #[tokio::test]
    async fn read_head_rejects_oversize() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let client = tokio::spawn(async move {
            let mut c = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
            let big = vec![b'x'; MAX_HEAD_BYTES + 16];
            write_then_shutdown(&mut c, &big).await;
        });
        let (mut server, _) = listener.accept().await.unwrap();
        assert!(read_head(&mut server).await.unwrap().is_none());
        client.await.unwrap();
    }
}
