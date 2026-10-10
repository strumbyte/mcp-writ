//! PR-09 PoC — namespaced egress control:
//! `userns + netns + mountns` around the workload, a TUN as the only
//! egress device, and a user-space TCP/UDP proxy that enforces the
//! policy's structured egress rules per flow/datagram.
//!
//! Why this exists beside the PR-07 `unotify` path: `connect(2)`
//! supervision cannot see unconnected `sendto`/`sendmsg` datagrams,
//! `MSG_FASTOPEN` payloads, `io_uring` submits, or raw sockets. Inside
//! a dedicated network namespace the *only* path out is the TUN fd the
//! parent holds, so every IP packet — connected or not — crosses the
//! proxy. The proxy therefore covers what unotify cannot, and the
//! report says so instead of stretching the older mechanism's claims.
//!
//! Data plane, per protocol (IPv4; see `stack` for the drop list):
//!
//! - **TCP** — every inbound SYN is DNAT-rewritten to a fixed smoltcp
//!   listener (`nat`); the accepted flow's original destination is
//!   recovered from the NAT table, evaluated by the `IpLayerEvaluator`
//!   plus the live DNS grants, then spliced to a real host socket or
//!   reset. smoltcp has no wildcard-port listen, so DNAT is the
//!   interception mechanism — the same design gVisor/tun2socks use.
//! - **UDP** — per-datagram evaluation; allowed datagrams are relayed
//!   through a real `UdpSocket` and replies are re-encapsulated onto
//!   the TUN. Port-53 datagrams never leave: they are answered by the
//!   embedded DNS gate regardless of the queried address (DNS
//!   intercept — a raw `8.8.8.8` query cannot bypass the name layer).
//! - **DNS over TCP** — port-53 TCP flows are DNAT'd to the gate's TCP
//!   listener and answered through the same pipeline.
//! - **Everything else** (ICMP, fragments, IPv6, unknown protocols) —
//!   dropped. Fail-closed by construction: a protocol the proxy does
//!   not terminate has no egress at all. IPv6 is additionally disabled
//!   inside the child netns.
//!
//! Process shape:
//!
//! ```text
//!   mcp-writ namespaced-run            (parent — holds tun fd + proxy)
//!     └── mcp-writ namespaced-init     (unprivileged helper, re-exec'd)
//!           unshare(USER|NET|NS) → uid_map → tun → routes →
//!           resolv.conf bind-mount → fd handoff → sandbox → exec workload
//! ```
//!
//! The init helper re-execs `/proc/self/exe` so all setup runs post-exec
//! (no post-fork allocator hazards), hands the TUN fd back over a
//! `SOCK_SEQPACKET` socketpair, and only then applies the Linux sandbox
//! bits and execs the workload. Setup failure at any stage → `ERR` on
//! the socket → the parent refuses the launch; there is no fallback to
//! a natively networked child.

mod eval;
mod init;
pub(crate) mod nat;
mod netlink;
mod probe;
pub(crate) mod report;
mod spawn;
mod stack;

pub use probe::{ProbeReport, run_probe};
pub use spawn::{SpawnConfig, spawn_namespaced_child};
// `NamespacedChild` is the spawn result type — callers hold it by
// inference, so the name stays in `spawn` (private module).
#[allow(unused_imports)]
pub use spawn::NamespacedChild;
pub use stack::{ProxyConfig, ProxyStats, run_proxy};

/// `namespaced-init` / `namespaced-probe` are internal entry points the
/// parent execs on `/proc/self/exe`; `main` dispatches on them before
/// the normal CLI parse so they never appear in `--help`.
pub(crate) const INIT_SUBCOMMAND: &str = "namespaced-init";
pub(crate) const PROBE_SUBCOMMAND: &str = "namespaced-probe";

/// Entry point for the internal `namespaced-init` helper — never
/// returns on success (it execs the workload).
pub(crate) fn init_entry() -> i32 {
    init::init_main()
}

/// Entry point for the internal `namespaced-probe` helper — prints the
/// capability report JSON on stdout and exits 0/1.
pub(crate) fn probe_entry() -> i32 {
    probe::probe_main()
}

/// The proxy's identity inside the netns — gateway, NAT target, and
/// the DNS nameserver the child's `resolv.conf` points at.
pub(crate) const GATEWAY_V4: std::net::Ipv4Addr = std::net::Ipv4Addr::new(10, 250, 0, 1);
/// The workload's fixed address.
pub(crate) const WORKLOAD_V4: std::net::Ipv4Addr = std::net::Ipv4Addr::new(10, 250, 0, 2);
/// smoltcp listener every non-DNS TCP flow is DNAT'd to.
pub(crate) const TCP_NAT_PORT: u16 = 40404;
/// smoltcp listener for DNS-over-TCP interception.
pub(crate) const DNS_TCP_NAT_PORT: u16 = 4053;
/// Environment variables the parent passes to the init helper. They
/// are scrubbed before the workload execs so a restricted environment
/// never leaks them.
pub(crate) mod init_env {
    pub const SOCK_FD: &str = "MCP_WRIT_NS_SOCKFD";
    pub const EXE: &str = "MCP_WRIT_NS_EXE";
    pub const POLICY: &str = "MCP_WRIT_NS_POLICY";
    /// `1` → skip the Landlock/seccomp apply (probe/debug only; the
    /// report records the skipped state honestly). A parent→init
    /// control, not ambient environment: `spawn` strips `MCP_WRIT_NS_*`
    /// from the inherited/policy-filtered env and forwards this flag
    /// only when the supervisor's own env opted in.
    pub const SKIP_SANDBOX: &str = "MCP_WRIT_NS_SKIP_SANDBOX";
    pub const ALL: &[&str] = &[SOCK_FD, EXE, POLICY, SKIP_SANDBOX];
}
