//! Capability report — the namespaced PoC's honest enforcement
//! statement, parallel to `unotify::report`. The shape mirrors the
//! PR-07 report (`capability` / `egress_layers` / `limitations` /
//! counters) so consumers and docs can diff the two PoCs directly.

use crate::audit_log::PolicyAuditContext;

use super::{ProbeReport, ProxyStats};

/// Fixed limitations + bypass notes for this PoC — surfaced in
/// `--report` output and the docs. Keep in sync with
/// `docs/improvement-pr-guide-2026-10.ja.md` PR-09's known-bypass list.
pub const LIMITATIONS: &[&str] = &[
    "IPv4 only — IPv6 is disabled inside the child netns and v6 packets \
     are dropped at the proxy, so a v6 destination cannot be reached at \
     all (fail-closed, not a bypass)",
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
    "DNS is answered by the embedded gate no matter which resolver \
     address the workload queries (port-53 intercept); a workload that \
     tunnels data inside DNS payloads still cannot mint IP grants for \
     names the policy denies",
    "DoT/DoH to allowed destinations is indistinguishable from ordinary \
     TLS/HTTPS — name-layer enforcement requires plaintext DNS, so a \
     workload using encrypted DNS bypasses name rules but remains \
     subject to IP/CIDR rules only (documented name-layer gap)",
    "the proxy runs in the parent process — the workload is init of \
     its own pid namespace with a private /proc, so it cannot even see \
     the supervisor's pid; if the parent dies the TUN fd closes and \
     all egress stops (fail-closed by construction)",
    "the uid_map maps the launcher's euid to namespace-root; the \
     workload sees uid 0 only inside its userns and holds no host \
     privileges — kernel-mediated operations outside netns scope are \
     unaffected by the PoC",
    "host AF_UNIX sockets under /run are hidden by a private tmpfs \
     mount (covers dbus/docker/udev-style proxies); socket paths \
     elsewhere on the shared filesystem remain reachable — Landlock \
     does not mediate AF_UNIX connect, so denying those directories \
     in the fs policy is the only control; IP egress itself still \
     only has the TUN",
    "the Landlock/seccomp layer is the ordinary Linux pipeline with \
     the socket-family narrowing relaxed (sockets of any type still \
     dead-end at the TUN); Landlock keeps the ConnectTcp port rules \
     only when every TCP-covering allow carries a port qualifier — \
     otherwise destination narrowing is delegated entirely to the \
     proxy rather than silently widened",
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
    let mut uname_buf: libc::utsname = unsafe { std::mem::zeroed() };
    let kernel = if unsafe { libc::uname(&mut uname_buf) } == 0 {
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
        tun: false,
        loopback_up: false,
        route: false,
        failed_stage: None,
        detail: None,
    };
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
                c.member("mechanism", "userns+netns+mountns+tun+userspace-proxy")?;
                c.member("kernel_release", kernel.as_str())?;
                c.member("state", state)?;
                if let Some(r) = reason {
                    c.member("reason", r)?;
                }
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
                        n.member("tun", probe.tun)?;
                        n.member("loopback_up", probe.loopback_up)?;
                        n.member("default_route_via_tun", probe.route)?;
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
                        s.member("socket_family_narrowing", "relaxed-namespaced")?;
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
                        d.member("ipv6", "disabled-and-dropped")?;
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
                            for (layer, os) in
                                [("name", "embedded-dns-gate"), ("ip", "tun-userspace-proxy")]
                            {
                                a.element(nojson::object(|lo| -> std::fmt::Result {
                                    lo.member("layer", layer)?;
                                    lo.member("rpc", "auditor")?;
                                    lo.member("os", os)?;
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
                s.member("udp_flows", stats.udp_flows.load(Relaxed))?;
                s.member("udp_datagrams", stats.udp_datagrams.load(Relaxed))?;
                s.member("udp_denied", stats.udp_denied.load(Relaxed))?;
                s.member(
                    "udp_audit_suppressed",
                    stats.udp_audit_suppressed.load(Relaxed),
                )?;
                s.member("dns_queries", stats.dns_queries.load(Relaxed))?;
                s.member("dropped_packets", stats.dropped_packets.load(Relaxed))?;
                s.member("dropped_non_v4", stats.dropped_non_v4.load(Relaxed))?;
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
