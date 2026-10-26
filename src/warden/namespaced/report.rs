//! Capability report — the namespaced PoC's honest enforcement
//! statement, parallel to `unotify::report`. The shape mirrors the
//! PR-07 report (`capability` / `egress_layers` / `limitations` /
//! counters) so consumers and docs can diff the two PoCs directly.

use crate::audit_log::PolicyAuditContext;

use super::{ProbeReport, ProxyStats};

/// JSON literal `null` for optional report fields.
struct JsonNull;

impl nojson::DisplayJson for JsonNull {
    fn fmt(&self, f: &mut nojson::JsonFormatter<'_, '_>) -> std::fmt::Result {
        write!(f.inner_mut(), "null")
    }
}

/// Fixed limitations + bypass notes for this PoC — surfaced in
/// `--report` output and the docs. Keep in sync with
/// `docs/improvement-pr-guide-2026-10.ja.md` PR-09's known-bypass list.
pub const LIMITATIONS: &[&str] = &[
    "IPv6 is enforced like IPv4 (PR-26a): v6 TCP/UDP flows are DNAT'd \
     and relayed through the same policy tables as v4, the DNS gate \
     answers v6-transport queries and mints AAAA grants, and an \
     explicit `deny host=\"*\"` covers v6 destinations too — but v6 \
     elements the classifier cannot inspect (extension-header chains, \
     fragments, ICMPv6 incl. Packet-Too-Big — unneeded since the proxy \
     re-originates every flow on host sockets) stay default-dropped, \
     and a v6 destination the host cannot dial (e.g. link-local — \
     packets carry no scope id) fails closed per flow",
    "no IP-fragment reassembly: fragmented datagrams are dropped (the \
     TUN MTU is 1500 end-to-end, so well-behaved peers do not fragment; \
     a workload that forces fragmentation loses those flows rather than \
     evading policy)",
    "non-TCP/UDP protocols (ICMP echo, GRE, raw sockets, IPsec) have no \
     egress — the proxy drops every other protocol number, so `ping` \
     and traceroute fail closed rather than escaping",
    "TCP is policy-evaluated once per connection at accept time; UDP \
     is re-evaluated per datagram, so a TTL grant expiring mid-flow \
     stops further datagrams immediately",
    "when a DNS upstream is configured, DNS is answered by the \
     embedded gate no matter which resolver address the workload \
     queries (port-53 UDP/TCP intercept), and a destination-scoped \
     port-53 allow is refused at selection as dead policy; a workload \
     that tunnels data inside DNS payloads still cannot mint IP grants \
     for names the policy denies. With no upstream there is no gate \
     and port-53 falls to the ordinary per-destination evaluator",
    "DoT/DoH to allowed destinations is indistinguishable from ordinary \
     TLS/HTTPS — name-layer enforcement requires plaintext DNS, so a \
     workload using encrypted DNS bypasses name rules but remains \
     subject to IP/CIDR rules only (documented name-layer gap)",
    "every allowed destination is dialed from the *host* network, so a \
     literal `allow` naming a protected-space network address \
     (RFC1918/LAN, ULA, link-local, CGNAT, multicast) grants the \
     workload reachability to those host-network services; loopback \
     and unspecified spellings (`127.0.0.1`/`::1`, `0.0.0.0`/`::`) \
     stay on the netns' own loopback — they reach the proxy only \
     when the workload can put such a packet on egress0 itself \
     (in-namespace root's route/raw control), and the unspecified \
     spellings never dial even then: `connect` folds `::`→`::1` and \
     `0.0.0.0`→`127.0.0.1`, so the backend refuses them rather than \
     reach a service the verdict never named",
    "the proxy runs in the parent process — the workload is init of \
     its own pid namespace with a private /proc, so it cannot even see \
     the supervisor's pid; if the parent dies the TUN fd closes and \
     all egress stops (fail-closed by construction)",
    "the uid_map maps the launcher's euid to namespace-root; the \
     workload sees uid 0 only inside its userns and holds no host \
     privileges — kernel-mediated operations outside netns scope are \
     unaffected by the PoC",
    "non-IP socket domains are closed off entirely: the seccomp filter \
     allows socket() only for AF_INET/AF_INET6 (Landlock does not \
     mediate AF_UNIX connect, the mountns shares the host filesystem, \
     and AF_VSOCK/AF_PACKET/AF_NETLINK are not namespaced by netns — \
     any of them would bypass the TUN). /run is additionally masked \
     by a private tmpfs (and /tmp whenever the resolv.conf redirect \
     bind-mounts from there) — an fs allow rooted under a masked tree \
     can never resolve, so selection refuses it as dead policy; \
     socketpair(AF_UNIX) stays for same-process IPC",
    "the Landlock/seccomp layer is the ordinary Linux pipeline with \
     the socket-family narrowing replaced by the AF_INET/AF_INET6 \
     allowlist (every IP socket still dead-ends at the TUN); Landlock \
     keeps the ConnectTcp port rules only when every TCP-covering \
     allow carries a port qualifier — otherwise destination narrowing \
     is delegated entirely to the proxy rather than silently widened",
    "the PoC does not rate-limit flows or datagrams — a policy-flooding \
     workload costs CPU in the proxy but cannot exceed what the policy \
     allows; every queue between tasks is bounded (a full channel \
     drops packets rather than growing memory) and per-datagram audit \
     emission is deduplicated plus budget-capped, with suppressed \
     events counted in proxy_stats",
];

/// Machine-readable PoC report for `namespaced-run --report`.
#[allow(clippy::too_many_arguments)] // report assembly; a struct would not clarify it
pub fn report_json(
    launch_id: uuid::Uuid,
    state: &str,
    reason: Option<&str>,
    policy: Option<&crate::policy::Policy>,
    policy_ctx: Option<&PolicyAuditContext>,
    probe: Option<&ProbeReport>,
    stats: Option<&ProxyStats>,
    sandbox_applied: Option<bool>,
) -> String {
    // SAFETY: `utsname` is a POD struct of char arrays, so the all-zero
    // bit pattern is valid.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    let mut uname_buf: libc::utsname = unsafe { std::mem::zeroed() };
    // SAFETY: `&mut uname_buf` is a valid, writable utsname — the exact
    // output layout uname(2) fills.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    let kernel = if unsafe { libc::uname(&mut uname_buf) } == 0 {
        // SAFETY: reached only after a successful uname(), so `release`
        // holds a NUL-terminated kernel string inside `uname_buf` —
        // CStr::from_ptr reads within that live buffer.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe {
            std::ffi::CStr::from_ptr(uname_buf.release.as_ptr())
                .to_string_lossy()
                .into_owned()
        }
    } else {
        "unknown".to_string()
    };
    let empty = ProbeReport {
        userns: false,
        netns: false,
        mountns: false,
        id_map: false,
        proc_mount: false,
        tun: false,
        loopback_up: false,
        route: false,
        ipv6_stack: false,
        ipv6: false,
        failed_stage: None,
        detail: None,
    };
    // `missing` is probe evidence: only a probe that actually ran can
    // name unmet requirements — a launch refused before the probe has
    // nothing measured to list (the `&[]` unotify/ebpf pass on their
    // pre-probe failure paths).
    let missing = probe.map(|p| p.missing()).unwrap_or_default();
    let probe = probe.unwrap_or(&empty);
    let empty_stats = ProxyStats::default();
    let stats = stats.unwrap_or(&empty_stats);
    nojson::object(|o| -> std::fmt::Result {
        o.member("schema_version", "1.0")?;
        o.member("component", "namespaced-run")?;
        o.member("launch_id", launch_id.to_string().as_str())?;
        o.member(
            "capability",
            nojson::object(|c| -> std::fmt::Result {
                c.member(
                    "capability_id",
                    crate::enforcement::capability::LINUX_NAMESPACED.id,
                )?;
                c.member("mechanism", "userns+netns+mountns+tun+userspace-proxy")?;
                c.member("kernel_release", kernel.as_str())?;
                c.member("state", state)?;
                if let Some(r) = reason {
                    c.member("reason", r)?;
                }
                c.member(
                    "missing",
                    nojson::array(|a| {
                        for m in &missing {
                            a.element(*m)?;
                        }
                        Ok(())
                    }),
                )?;
                c.member(
                    "namespaces",
                    nojson::object(|n| -> std::fmt::Result {
                        n.member("userns", probe.userns)?;
                        n.member("netns", probe.netns)?;
                        n.member("mountns", probe.mountns)?;
                        // Created unconditionally inside the launch — a
                        // failed unshare is a launch refusal, so reaching
                        // this report means the claim holds.
                        n.member("pidns", true)?;
                        n.member("uid_gid_map", probe.id_map)?;
                        n.member("proc_mount", probe.proc_mount)?;
                        n.member("tun", probe.tun)?;
                        n.member("loopback_up", probe.loopback_up)?;
                        n.member("default_route_via_tun", probe.route)?;
                        n.member("ipv6_stack", probe.ipv6_stack)?;
                        n.member("ipv6_route_via_tun", probe.ipv6)?;
                        Ok(())
                    }),
                )?;
                c.member(
                    "child_sandbox",
                    nojson::object(|s| -> std::fmt::Result {
                        s.member(
                            "landlock_seccomp",
                            match sandbox_applied {
                                Some(true) => "applied",
                                Some(false) => "skipped-or-failed",
                                None => "not-reached",
                            },
                        )?;
                        // The family pin only exists when the child
                        // sandbox actually applied — report the state,
                        // never a narrowing that was never enforced.
                        s.member(
                            "socket_family_narrowing",
                            match sandbox_applied {
                                Some(true) => "af-inet-af-inet6-allowlist",
                                Some(false) => "skipped-or-failed",
                                None => "not-reached",
                            },
                        )?;
                        Ok(())
                    }),
                )?;
                c.member(
                    "data_plane",
                    nojson::object(|d| -> std::fmt::Result {
                        d.member("tcp", "dnat-smoltcp-splice-policy-checked")?;
                        d.member("udp", "per-datagram-relay-policy-checked")?;
                        d.member("dns_udp", "intercepted-embedded-gate")?;
                        d.member("dns_tcp", "intercepted-embedded-gate")?;
                        d.member("ipv6", "dual-stack-evaluated-uninspectable-dropped")?;
                        d.member("fragments", "dropped")?;
                        d.member("icmp_other", "dropped")?;
                        Ok(())
                    }),
                )?;
                Ok(())
            }),
        )?;
        if let Some(policy) = policy {
            let out = &policy.network.outbound;
            o.member(
                "egress_layers",
                nojson::object(|e| -> std::fmt::Result {
                    e.member(
                        "default_action",
                        if out.deny_all_others {
                            "deny_all"
                        } else {
                            "allow_all"
                        },
                    )?;
                    e.member(
                        "layers",
                        nojson::array(|a| {
                            for l in crate::enforcement::capability::LINUX_NAMESPACED
                                .layers
                                .iter()
                            {
                                let l = l.status();
                                a.element(nojson::object(|lo| -> std::fmt::Result {
                                    lo.member("layer", l.layer)?;
                                    lo.member("rpc", l.rpc)?;
                                    match l.os.as_deref() {
                                        Some(os) => lo.member("os", os)?,
                                        None => lo.member("os", JsonNull)?,
                                    }
                                    match l.note.as_deref() {
                                        Some(n) => lo.member("note", n)?,
                                        None => lo.member("note", JsonNull)?,
                                    }
                                    Ok(())
                                }))?;
                            }
                            Ok(())
                        }),
                    )?;
                    e.member(
                        "rules",
                        nojson::array(|a| {
                            for r in crate::warden::plan::egress_rule_table(policy) {
                                a.element(nojson::object(|ro| {
                                    ro.member("effect", r.effect)?;
                                    ro.member("kind", r.kind)?;
                                    ro.member("rule", r.rule.as_str())?;
                                    ro.member("proto", r.proto)?;
                                    ro.member("port", r.port)?;
                                    ro.member("name_layer", r.name_layer)?;
                                    ro.member("ip_layer", r.ip_layer)?;
                                    Ok(())
                                }))?;
                            }
                            Ok(())
                        }),
                    )?;
                    Ok(())
                }),
            )?;
        }
        if let Some(ctx) = policy_ctx {
            o.member(
                "policy",
                nojson::object(|p| -> std::fmt::Result {
                    p.member("id", ctx.id.as_str())?;
                    p.member("version", ctx.version.as_str())?;
                    p.member("hash", ctx.hash.as_str())?;
                    Ok(())
                }),
            )?;
        }
        o.member(
            "limitations",
            nojson::array(|a| {
                for l in LIMITATIONS {
                    a.element(*l)?;
                }
                Ok(())
            }),
        )?;
        o.member(
            "proxy_stats",
            nojson::object(|s| -> std::fmt::Result {
                use std::sync::atomic::Ordering::Relaxed;
                s.member("tcp_accepted", stats.tcp_accepted.load(Relaxed))?;
                s.member("tcp_denied", stats.tcp_denied.load(Relaxed))?;
                s.member("tcp_saturated", stats.tcp_saturated.load(Relaxed))?;
                s.member("udp_flows", stats.udp_flows.load(Relaxed))?;
                s.member("udp_datagrams", stats.udp_datagrams.load(Relaxed))?;
                s.member("udp_denied", stats.udp_denied.load(Relaxed))?;
                s.member(
                    "udp_audit_suppressed",
                    stats.udp_audit_suppressed.load(Relaxed),
                )?;
                s.member("dns_queries", stats.dns_queries.load(Relaxed))?;
                s.member("dropped_packets", stats.dropped_packets.load(Relaxed))?;
                s.member("dropped_non_ip", stats.dropped_non_ip.load(Relaxed))?;
                s.member("dropped_v6_ext", stats.dropped_v6_ext.load(Relaxed))?;
                s.member("dropped_fragment", stats.dropped_fragment.load(Relaxed))?;
                s.member("dropped_proto", stats.dropped_proto.load(Relaxed))?;
                s.member("bytes_to_workload", stats.bytes_to_workload.load(Relaxed))?;
                s.member(
                    "bytes_from_workload",
                    stats.bytes_from_workload.load(Relaxed),
                )?;
                Ok(())
            }),
        )?;
        Ok(())
    })
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `missing` is probe evidence: a failure report emitted before the
    /// probe ever ran (env resolution, policy load, ...) must list *no*
    /// unmet requirements — matching the `&[]` the unotify/ebpf callers
    /// pass on their pre-probe failure paths — while a probe that ran
    /// and failed every stage lists the full catalog ids.
    #[test]
    fn missing_is_empty_when_probe_never_ran() {
        let report = report_json(
            uuid::Uuid::nil(),
            "failed",
            Some("policy load failed"),
            None,
            None,
            None,
            None,
            None,
        );
        assert!(
            report.contains("\"missing\":[]"),
            "pre-probe failure must not claim unmet requirements: {report}"
        );
    }

    #[test]
    fn missing_lists_failed_stages_when_probe_ran() {
        let probed = ProbeReport {
            userns: false,
            netns: false,
            mountns: false,
            id_map: false,
            proc_mount: false,
            tun: false,
            loopback_up: false,
            route: false,
            // Stack present so the failed v6 setup is a real missing
            // requirement — an absent stack would stay v4-only and not
            // list `ipv6_route_via_tun`.
            ipv6_stack: true,
            ipv6: false,
            failed_stage: Some("userns".to_string()),
            detail: Some("EPERM".to_string()),
        };
        let report = report_json(
            uuid::Uuid::nil(),
            "capability_missing",
            None,
            None,
            None,
            Some(&probed),
            None,
            None,
        );
        assert!(
            report.contains("\"missing\":[\"userns\",\"netns\",\"mountns\",\"uid_gid_map\",\"proc_mount\",\"tun\",\"loopback_up\",\"default_route_via_tun\",\"ipv6_route_via_tun\"]"),
            "a failed probe must name the unmet requirements: {report}"
        );
    }
}
