use super::*;
use crate::policy::{EgressProto, EgressRule};

fn probe(all_ok: bool) -> Result<ProbeReport, String> {
    Ok(ProbeReport {
        userns: all_ok,
        netns: all_ok,
        mountns: all_ok,
        id_map: all_ok,
        tun: all_ok,
        loopback_up: all_ok,
        route: all_ok,
        ipv6_stack: all_ok,
        ipv6: all_ok,
        failed_stage: None,
        detail: None,
    })
}

fn input<'a>(
    policy: &'a Policy,
    probe: &'a Result<ProbeReport, String>,
    upstream: Option<SocketAddr>,
    abi: u8,
) -> SelectionInput<'a> {
    input_v6(policy, probe, upstream, abi, true)
}

/// `v6_ok` drives the host-side v6 facts the gather step would have
/// measured: `false` simulates a host with no v6 route at all.
fn input_v6<'a>(
    policy: &'a Policy,
    probe: &'a Result<ProbeReport, String>,
    upstream: Option<SocketAddr>,
    abi: u8,
    v6_ok: bool,
) -> SelectionInput<'a> {
    SelectionInput {
        policy,
        probe: Some(probe),
        dns_upstream: upstream,
        landlock_abi: abi,
        native_build_err: None,
        namespaced_build_err: None,
        host_v6_reach: if v6_ok { |_| true } else { |_| false },
        host_v6_range: if v6_ok { |_, _| true } else { |_, _| false },
        host_v6_any: v6_ok,
    }
}

fn upstream() -> Option<SocketAddr> {
    "10.0.0.1:53".parse().ok()
}

fn deny_all_policy() -> Policy {
    Policy::default()
}

fn bare_port_policy() -> Policy {
    let mut p = Policy::default();
    p.network.outbound.egress_rules = vec![EgressRule {
        allow: true,
        dest: EgressDest::Host("*".to_string()),
        proto: EgressProto::Tcp,
        port: Some(443),
    }];
    p
}

fn name_allow_policy() -> Policy {
    let mut p = Policy::default();
    p.network.outbound.egress_rules = vec![EgressRule {
        allow: true,
        dest: EgressDest::Host("api.example.com".to_string()),
        proto: EgressProto::Any,
        port: None,
    }];
    p
}

fn udp_allow_policy() -> Policy {
    let mut p = Policy::default();
    p.network.outbound.egress_rules = vec![EgressRule {
        allow: true,
        dest: EgressDest::Host("*".to_string()),
        proto: EgressProto::Udp,
        port: Some(53),
    }];
    p
}

// --- selection table rows -------------------------------------

#[test]
fn auto_prefers_namespaced_when_capable_and_satisfiable() {
    let p = name_allow_policy();
    let pr = probe(true);
    let sel = decide(LinuxMechanismRequest::Auto, &input(&p, &pr, upstream(), 8));
    assert_eq!(sel.selected, Some(LinuxNativeMechanism::Namespaced));
    assert!(sel.violations.is_empty());
}

#[test]
fn auto_native_when_namespaced_missing_and_native_satisfies() {
    let p = bare_port_policy();
    let mut r = probe(true).unwrap();
    r.tun = false;
    let pr = Ok(r);
    let sel = decide(LinuxMechanismRequest::Auto, &input(&p, &pr, upstream(), 8));
    assert_eq!(sel.selected, Some(LinuxNativeMechanism::Native));
    assert_eq!(sel.missing, vec!["tun".to_string()]);
}

#[test]
fn auto_refuses_when_neither_satisfies() {
    // A dest-scoped allow: namespaced could satisfy it, but the
    // host lacks tun; native can never bind a destination.
    let p = name_allow_policy();
    let mut r = probe(true).unwrap();
    r.tun = false;
    let pr = Ok(r);
    let sel = decide(LinuxMechanismRequest::Auto, &input(&p, &pr, upstream(), 8));
    assert_eq!(sel.selected, None);
    assert!(!sel.violations.is_empty());
}

#[test]
fn explicit_namespaced_refuses_when_probe_missing() {
    let p = deny_all_policy();
    let mut r = probe(true).unwrap();
    r.userns = false;
    let pr = Ok(r);
    let sel = decide(
        LinuxMechanismRequest::Namespaced,
        &input(&p, &pr, upstream(), 8),
    );
    assert_eq!(sel.selected, None);
    assert_eq!(sel.missing, vec!["userns".to_string()]);
}

#[test]
fn explicit_namespaced_refuses_probe_spawn_failure() {
    let p = deny_all_policy();
    let pr: Result<ProbeReport, String> = Err("probe spawn failed".to_string());
    let sel = decide(
        LinuxMechanismRequest::Namespaced,
        &input(&p, &pr, upstream(), 8),
    );
    assert_eq!(sel.selected, None);
    assert_eq!(sel.probe_err.as_deref(), Some("probe spawn failed"));
}

#[test]
fn namespaced_accepts_ipv6_policy_when_host_can_route_it() {
    // PR-26a: the route is dual-stack — an explicit v6 destination is
    // satisfiable wherever the host can route it.
    let mut p = Policy::default();
    p.network.outbound.egress_rules = vec![EgressRule {
        allow: true,
        dest: EgressDest::Cidr("2001:db8::/32".to_string()),
        proto: EgressProto::Any,
        port: None,
    }];
    let pr = probe(true);
    let sel = decide(
        LinuxMechanismRequest::Namespaced,
        &input(&p, &pr, upstream(), 8),
    );
    assert_eq!(sel.selected, Some(LinuxNativeMechanism::Namespaced));
}

#[test]
fn namespaced_refuses_ipv6_policy_when_host_cannot_route_it() {
    // A v6 allow on a v6-less host is dead policy: the flow fails at
    // dial every time — declaring it cannot silently mean "dropped".
    let mut p = Policy::default();
    p.network.outbound.egress_rules = vec![EgressRule {
        allow: true,
        dest: EgressDest::Cidr("2001:db8::/32".to_string()),
        proto: EgressProto::Any,
        port: None,
    }];
    let pr = probe(true);
    let sel = decide(
        LinuxMechanismRequest::Namespaced,
        &input_v6(&p, &pr, upstream(), 8, false),
    );
    assert_eq!(sel.selected, None);
    assert!(sel.violations.iter().any(|s| s.contains("IPv6")));
}

#[test]
fn cidr_allow_reachability_asks_the_range_not_the_network_address() {
    // A host that routes *part* of the spelled range satisfies the
    // allow — the range probe decides, not the single-address probe
    // (which fails when the range's own network address is unrouted).
    let mut p = Policy::default();
    p.network.outbound.egress_rules = vec![EgressRule {
        allow: true,
        dest: EgressDest::Cidr("fd12:3456::/48".to_string()),
        proto: EgressProto::Any,
        port: None,
    }];
    let pr = probe(true);
    let inp = SelectionInput {
        policy: &p,
        probe: Some(&pr),
        dns_upstream: upstream(),
        landlock_abi: 8,
        native_build_err: None,
        namespaced_build_err: None,
        // The network address itself does not route; the range does.
        host_v6_reach: |_| false,
        host_v6_range: |_, _| true,
        host_v6_any: true,
    };
    let sel = decide(LinuxMechanismRequest::Namespaced, &inp);
    assert_eq!(sel.selected, Some(LinuxNativeMechanism::Namespaced));
    // …and the inverse still refuses: the range probe says nothing
    // inside overlaps a host route even though some address probes fine.
    let inp = SelectionInput {
        host_v6_reach: |_| true,
        host_v6_range: |_, _| false,
        ..inp
    };
    let sel = decide(LinuxMechanismRequest::Namespaced, &inp);
    assert_eq!(sel.selected, None);
    assert!(sel.violations.iter().any(|s| s.contains("IPv6")));
}

#[test]
fn cidr_masking_to_unspecified_still_needs_a_route() {
    // `::/64` masks to `::` at load time but is not the wildcard —
    // it must pass the route-overlap probe like any other range, so
    // it stays satisfiable on a host whose only overlapping route is
    // `::1/128` even when `host_v6_any` is false.
    let mut p = Policy::default();
    p.network.outbound.egress_rules = vec![EgressRule {
        allow: true,
        dest: EgressDest::Cidr("::/64".to_string()),
        proto: EgressProto::Any,
        port: None,
    }];
    let pr = probe(true);
    let inp = SelectionInput {
        policy: &p,
        probe: Some(&pr),
        dns_upstream: upstream(),
        landlock_abi: 8,
        native_build_err: None,
        namespaced_build_err: None,
        host_v6_reach: |_| true,
        host_v6_range: |_, _| true,
        host_v6_any: false,
    };
    let sel = decide(LinuxMechanismRequest::Namespaced, &inp);
    assert_eq!(sel.selected, Some(LinuxNativeMechanism::Namespaced));
    // …and `::/128` — `::` alone, a range no route can cover — is
    // dead policy even on a host that carries v6 (it must not reach
    // the `host_v6_any` arm).
    let mut p128 = Policy::default();
    p128.network.outbound.egress_rules = vec![EgressRule {
        allow: true,
        dest: EgressDest::Cidr("::/128".to_string()),
        proto: EgressProto::Any,
        port: None,
    }];
    let inp = SelectionInput {
        policy: &p128,
        host_v6_range: |_, _| false,
        host_v6_any: true,
        ..inp
    };
    let sel = decide(LinuxMechanismRequest::Namespaced, &inp);
    assert_eq!(sel.selected, None);
    assert!(sel.violations.iter().any(|s| s.contains("IPv6")));
}

#[test]
fn wildcard_cidr_still_asks_host_v6_any() {
    // `::/0` is the one range that asks "does the host carry v6 at
    // all" — every address is covered, so the range-overlap probe is
    // not consulted.
    let mut p = Policy::default();
    p.network.outbound.egress_rules = vec![EgressRule {
        allow: true,
        dest: EgressDest::Cidr("::/0".to_string()),
        proto: EgressProto::Any,
        port: None,
    }];
    let pr = probe(true);
    let inp = SelectionInput {
        policy: &p,
        probe: Some(&pr),
        dns_upstream: upstream(),
        landlock_abi: 8,
        native_build_err: None,
        namespaced_build_err: None,
        host_v6_reach: |_| false,
        host_v6_range: |_, _| false,
        host_v6_any: true,
    };
    let sel = decide(LinuxMechanismRequest::Namespaced, &inp);
    assert_eq!(sel.selected, Some(LinuxNativeMechanism::Namespaced));
}

#[test]
fn unspecified_destinations_are_not_route_evidence() {
    // The connect path folds unspecified spellings to loopback —
    // they must never prove a destination or range reachable (the
    // data plane refuses that dial).
    for a in ["::", "0.0.0.0", "::ffff:0.0.0.0"] {
        assert!(!udp_route_probe(a.parse().unwrap()), "{a}");
    }
}

// --- v6 route-table reachability helpers -------------------------

fn v6(s: &str) -> Ipv6Addr {
    s.parse().unwrap()
}

#[test]
fn v6_route_dump_line_parses_dest_and_prefix() {
    // Real fib6-dump shape: dest(32 hex) plen(2 hex) src(32) splen
    // nexthop metric refcnt use flags dev.
    assert_eq!(
        parse_v6_route(
            "fd123456000000000000000000000000 40 \
             00000000000000000000000000000000 00 \
             00000000000000000000000000000000 00000100 00000000 00000000 \
             00000001 eth0"
        ),
        Some((v6("fd12:3456::"), 0x40))
    );
    assert_eq!(
        parse_v6_route(
            "00000000000000000000000000000000 00 \
             00000000000000000000000000000000 00 \
             fe800000000000000000000000000000 00000200 00000001 00000000 \
             00000001 eth0"
        ),
        Some((Ipv6Addr::UNSPECIFIED, 0))
    );
    assert!(parse_v6_route("not a route").is_none());
    assert!(parse_v6_route("").is_none());
}

#[test]
fn v6_prefix_contains_masks_both_sides() {
    assert!(v6_prefix_contains(
        v6("fd12:3456::"),
        48,
        v6("fd12:3456:0:1::")
    ));
    assert!(!v6_prefix_contains(
        v6("fd12:3456::"),
        48,
        v6("fd12:3457::")
    ));
    // /0 contains everything; /128 is an exact match.
    assert!(v6_prefix_contains(
        Ipv6Addr::UNSPECIFIED,
        0,
        v6("2001:db8::1")
    ));
    assert!(v6_prefix_contains(v6("::1"), 128, v6("::1")));
    assert!(!v6_prefix_contains(v6("::1"), 128, v6("::2")));
}

#[test]
fn v6_range_probe_addrs_pick_the_overlap() {
    let routes = [
        (v6("fe80::"), 64),          // link-local — never evidence
        (Ipv6Addr::LOCALHOST, 128),  // real, but disjoint from the allow
        (v6("ff00::"), 8),           // multicast — never evidence
        (v6("fd12:3456:0:1::"), 64), // a /64 carved inside the allow
        (v6("2001:db8::"), 32),      // disjoint
    ];
    // `allow fd12:3456::/48`: only the carved /64 overlaps — probe
    // its network address.
    assert_eq!(
        v6_range_probe_addrs((v6("fd12:3456::"), 48), routes.into_iter()),
        vec![v6("fd12:3456:0:1::")]
    );
    // A covering route probes the range's own network address.
    assert_eq!(
        v6_range_probe_addrs((v6("fd12:3456::"), 48), [(v6("fd12::"), 16)].into_iter()),
        vec![v6("fd12:3456::")]
    );
    // A default route covers every range.
    assert_eq!(
        v6_range_probe_addrs(
            (v6("fd12:3456::"), 48),
            [(Ipv6Addr::UNSPECIFIED, 0)].into_iter()
        ),
        vec![v6("fd12:3456::")]
    );
    // A loopback route is real evidence — the proxy can dial `::1`,
    // so a range containing it is reachable just like `allow host="::1"`.
    assert_eq!(
        v6_range_probe_addrs((v6("::"), 64), [(Ipv6Addr::LOCALHOST, 128)].into_iter()),
        vec![Ipv6Addr::LOCALHOST]
    );
    // Link-local/multicast-only routes never evidence reachability.
    assert!(
        v6_range_probe_addrs(
            (v6("fd00::"), 8),
            [(v6("fe80::"), 64), (v6("ff00::"), 8)].into_iter()
        )
        .is_empty()
    );
}

#[test]
fn deny_all_still_covers_ipv6() {
    // `deny host="*"` under deny-all covers every family — v6 needs no
    // separate deny spelling to stay fail-closed.
    let p = deny_all_policy();
    let pr = probe(true);
    let sel = decide(
        LinuxMechanismRequest::Namespaced,
        &input_v6(&p, &pr, upstream(), 8, false),
    );
    assert_eq!(sel.selected, Some(LinuxNativeMechanism::Namespaced));
}

#[test]
fn explicit_native_refuses_dest_scoped_allow() {
    // proto=tcp isolates the destination-binding refusal — an
    // `any` rule would already refuse on its UDP coverage.
    let mut p = Policy::default();
    p.network.outbound.egress_rules = vec![EgressRule {
        allow: true,
        dest: EgressDest::Host("api.example.com".to_string()),
        proto: EgressProto::Tcp,
        port: Some(443),
    }];
    let pr = probe(true);
    let sel = decide(
        LinuxMechanismRequest::Native,
        &input(&p, &pr, upstream(), 8),
    );
    assert_eq!(sel.selected, None);
    assert!(
        sel.violations
            .iter()
            .any(|s| s.contains("binds a destination"))
    );
}

#[test]
fn explicit_native_accepts_bare_port_tcp() {
    let p = bare_port_policy();
    let pr = probe(true);
    let sel = decide(
        LinuxMechanismRequest::Native,
        &input(&p, &pr, upstream(), 8),
    );
    assert_eq!(sel.selected, Some(LinuxNativeMechanism::Native));
}

#[test]
fn native_refuses_udp_allow_as_dead_policy() {
    let p = udp_allow_policy();
    let pr = probe(true);
    let sel = decide(
        LinuxMechanismRequest::Native,
        &input(&p, &pr, upstream(), 8),
    );
    assert_eq!(sel.selected, None);
    assert!(sel.violations.iter().any(|s| s.contains("grants UDP")));
}

#[test]
fn native_refuses_open_posture() {
    let mut p = Policy::default();
    p.network.outbound.deny_all_others = false;
    let pr = probe(true);
    let sel = decide(
        LinuxMechanismRequest::Native,
        &input(&p, &pr, upstream(), 8),
    );
    assert_eq!(sel.selected, None);
}

#[test]
fn namespaced_needs_upstream_for_name_allows() {
    let p = name_allow_policy();
    let pr = probe(true);
    let sel = decide(LinuxMechanismRequest::Namespaced, &input(&p, &pr, None, 8));
    assert_eq!(sel.selected, None);
    assert!(sel.violations.iter().any(|s| s.contains("host name")));
}

#[test]
fn namespaced_satisfies_name_allow_with_upstream() {
    let p = name_allow_policy();
    let pr = probe(true);
    let sel = decide(
        LinuxMechanismRequest::Namespaced,
        &input(&p, &pr, upstream(), 8),
    );
    assert_eq!(sel.selected, Some(LinuxNativeMechanism::Namespaced));
}

#[test]
fn auto_namespaced_capable_but_policy_unsatisfiable_falls_to_native_check() {
    // A v6 rule on a v6-less host: namespaced cannot satisfy it (the
    // allow is dead policy); the policy's dest scope means native
    // cannot either → refuse (row 3).
    let mut p = Policy::default();
    p.network.outbound.egress_rules = vec![EgressRule {
        allow: true,
        dest: EgressDest::Cidr("2001:db8::/32".to_string()),
        proto: EgressProto::Any,
        port: None,
    }];
    let pr = probe(true);
    let sel = decide(
        LinuxMechanismRequest::Auto,
        &input_v6(&p, &pr, upstream(), 8, false),
    );
    assert_eq!(sel.selected, None);
}

#[test]
fn old_kernel_landlock_blocks_native_tcp_allows() {
    let p = bare_port_policy();
    let pr = probe(true);
    let sel = decide(
        LinuxMechanismRequest::Native,
        &input(&p, &pr, upstream(), 3),
    );
    assert_eq!(sel.selected, None);
    // `allow_degraded` tolerates a *partial* ruleset, but on ABI<4
    // the TCP allow surface is not partially enforced — it is
    // silently absent. A declared control the kernel cannot apply
    // is mandatory (PR-16) and the flag must not skip it.
    let mut p2 = bare_port_policy();
    p2.sandbox.allow_degraded = true;
    let sel = decide(
        LinuxMechanismRequest::Native,
        &input(&p2, &pr, upstream(), 3),
    );
    assert_eq!(sel.selected, None);
    assert!(
        sel.violations.iter().any(|v| v.contains("allow_degraded")),
        "the refusal must name the tolerated-degradation limit: {:?}",
        sel.violations
    );
    // The flag does rescue a launch with no declared net/fs
    // surface — nothing mandatory is dropped.
    let mut p3 = Policy::default();
    p3.sandbox.allow_degraded = true;
    p3.fs.read_only = vec!["/usr".to_string()];
    let sel = decide(
        LinuxMechanismRequest::Native,
        &input(&p3, &pr, upstream(), 3),
    );
    assert_eq!(sel.selected, Some(LinuxNativeMechanism::Native));
}

#[test]
fn namespaced_ignores_low_abi_for_egress() {
    // Landlock <4 cannot express netport rules, but the TUN proxy
    // is the egress authority on this route — only abi==0 fs-rule
    // loss matters.
    let p = bare_port_policy();
    let pr = probe(true);
    let sel = decide(
        LinuxMechanismRequest::Namespaced,
        &input(&p, &pr, upstream(), 3),
    );
    assert_eq!(sel.selected, Some(LinuxNativeMechanism::Namespaced));
}

#[test]
fn inbound_listen_is_unsatisfiable_on_both() {
    let mut p = Policy::default();
    p.network.inbound.allow_listen = true;
    let pr = probe(true);
    for req in [
        LinuxMechanismRequest::Namespaced,
        LinuxMechanismRequest::Native,
    ] {
        let sel = decide(req, &input(&p, &pr, upstream(), 8));
        assert_eq!(sel.selected, None, "{req:?} must refuse inbound listen");
    }
}

#[test]
fn port53_allow_is_dead_policy_when_the_gate_is_armed() {
    // With an upstream configured the embedded gate answers every
    // :53 flow — the destination-scoped allow never evaluates.
    let p = udp_allow_policy();
    let pr = probe(true);
    let sel = decide(
        LinuxMechanismRequest::Namespaced,
        &input(&p, &pr, upstream(), 8),
    );
    assert_eq!(sel.selected, None);
    assert!(
        sel.violations.iter().any(|s| s.contains("port 53")),
        "expected a port-53 intercept violation, got {:?}",
        sel.violations
    );
    // With no upstream there is no gate — :53 falls to the
    // ordinary evaluator and the rule is satisfiable.
    let sel = decide(LinuxMechanismRequest::Namespaced, &input(&p, &pr, None, 8));
    assert_eq!(sel.selected, Some(LinuxNativeMechanism::Namespaced));
}

#[test]
fn fs_allow_under_masked_run_is_a_violation() {
    let mut p = Policy::default();
    p.fs.read_only = vec!["/run/docker.sock".to_string()];
    let pr = probe(true);
    let sel = decide(
        LinuxMechanismRequest::Namespaced,
        &input(&p, &pr, upstream(), 8),
    );
    assert_eq!(sel.selected, None);
    assert!(
        sel.violations.iter().any(|s| s.contains("/run")),
        "expected a masked-fs violation, got {:?}",
        sel.violations
    );
    // The same policy is expressible on the native route.
    let sel = decide(
        LinuxMechanismRequest::Native,
        &input(&p, &pr, upstream(), 8),
    );
    assert_eq!(sel.selected, Some(LinuxNativeMechanism::Native));
}

#[test]
fn tool_fs_allow_under_masked_run_is_a_violation() {
    // Per-tool fs paths are screened the same way as policy-level
    // ones. (`/var/run` spellings are host-dependent — they flag
    // only where the symlink to /run actually exists — so the test
    // uses a literal `/run` path.)
    let mut p = Policy::default();
    let mut tool = crate::policy::ToolPolicy::named("t", true);
    tool.fs = Some(crate::policy::FsToolPolicy {
        allowed_paths: vec!["/run/app.sock".to_string()],
        ..Default::default()
    });
    p.tools = vec![tool];
    let pr = probe(true);
    let sel = decide(
        LinuxMechanismRequest::Namespaced,
        &input(&p, &pr, upstream(), 8),
    );
    assert_eq!(sel.selected, None);
    assert!(
        sel.violations
            .iter()
            .any(|s| s.contains("tool 't'") && s.contains("/run")),
        "expected a masked-fs violation, got {:?}",
        sel.violations
    );
}

#[test]
fn disabled_tool_fs_allow_under_masked_run_is_not_a_violation() {
    // A disabled tool's fs lists never reach the ruleset — its
    // /run-rooted grant is absent policy, not dead policy, and the
    // masked-root scan must not flag it.
    let mut p = Policy::default();
    let mut tool = crate::policy::ToolPolicy::named("t", false);
    tool.fs = Some(crate::policy::FsToolPolicy {
        allowed_paths: vec!["/run/app.sock".to_string()],
        ..Default::default()
    });
    p.tools = vec![tool];
    let pr = probe(true);
    let sel = decide(
        LinuxMechanismRequest::Namespaced,
        &input(&p, &pr, upstream(), 8),
    );
    assert!(
        sel.violations.iter().all(|s| !s.contains("tool 't'")),
        "a disabled tool's grant must not be flagged: {:?}",
        sel.violations
    );
}

#[test]
fn global_fs_listed_in_both_ro_and_rw_reports_once() {
    // The same path under `read_only` and `read_write` is one dead
    // grant, not two — the report dedupes by path.
    let mut p = Policy::default();
    p.fs.read_only = vec!["/run/app.sock".to_string()];
    p.fs.read_write = vec!["/run/app.sock".to_string()];
    let pr = probe(true);
    let sel = decide(
        LinuxMechanismRequest::Namespaced,
        &input(&p, &pr, upstream(), 8),
    );
    let hits = sel
        .violations
        .iter()
        .filter(|s| s.contains("/run/app.sock"))
        .count();
    assert_eq!(
        hits, 1,
        "deduped report expected, got: {:?}",
        sel.violations
    );
}

#[test]
fn masked_fs_root_matches_only_rooted_spellings() {
    assert!(masked_fs_root("/run/x", false).is_some());
    assert!(masked_fs_root("/run/**", false).is_some());
    assert!(masked_fs_root("/run", false).is_some());
    // `.`/`..` normalization — resolves outside, stays reachable.
    assert!(masked_fs_root("/run/../etc/x", false).is_none());
    assert!(masked_fs_root("/etc/run/x", false).is_none());
    assert!(masked_fs_root("/runtime/x", false).is_none());
    // A literal-stem glob can still expand to the masked root.
    assert!(masked_fs_root("/r*/x", false).is_some());
    // Wide ancestors are the documented carve-out, not per-rule
    // dead policy.
    assert!(masked_fs_root("/*", false).is_none());
    assert!(masked_fs_root("/**", false).is_none());
    assert!(masked_fs_root("/", false).is_none());
    // /tmp only flags while the bind-mount path is planned.
    assert!(masked_fs_root("/tmp/x", false).is_none());
    assert!(masked_fs_root("/tmp/x", true).is_some());
}

#[test]
fn native_record_drops_dns_upstream() {
    // dns_upstream is namespaced-route evidence — a native-bound
    // record must not carry it.
    let p = bare_port_policy();
    let pr = probe(true);
    let sel = decide(
        LinuxMechanismRequest::Native,
        &input(&p, &pr, upstream(), 8),
    );
    assert_eq!(sel.selected, Some(LinuxNativeMechanism::Native));
    assert!(sel.to_record().dns_upstream.is_none());
    // auto→native likewise: force the native arm with a missing
    // probe stage.
    let mut r = probe(true).unwrap();
    r.tun = false;
    let pr = Ok(r);
    let sel = decide(LinuxMechanismRequest::Auto, &input(&p, &pr, upstream(), 8));
    assert_eq!(sel.selected, Some(LinuxNativeMechanism::Native));
    assert!(sel.to_record().dns_upstream.is_none());
    // …while a namespaced record keeps it.
    let p2 = name_allow_policy();
    let pr2 = probe(true);
    let sel = decide(
        LinuxMechanismRequest::Namespaced,
        &input(&p2, &pr2, upstream(), 8),
    );
    assert_eq!(sel.selected, Some(LinuxNativeMechanism::Namespaced));
    assert_eq!(sel.to_record().dns_upstream.as_deref(), Some("10.0.0.1:53"));
}

#[test]
fn skipped_probe_fabricates_no_evidence() {
    // An explicit `native` request never runs the namespaced
    // probe — the selection must not carry invented missing or
    // error evidence for a probe that never happened.
    let p = bare_port_policy();
    let inp = SelectionInput {
        policy: &p,
        probe: None,
        dns_upstream: upstream(),
        landlock_abi: 8,
        native_build_err: None,
        namespaced_build_err: None,
        host_v6_reach: |_| true,
        host_v6_range: |_, _| true,
        host_v6_any: true,
    };
    let sel = decide(LinuxMechanismRequest::Native, &inp);
    assert_eq!(sel.selected, Some(LinuxNativeMechanism::Native));
    assert!(sel.probe.is_none() && sel.probe_err.is_none() && sel.missing.is_empty());
}

#[test]
fn refused_reasons_carry_the_real_violations() {
    // F6 — an explicit namespaced refusal must not drop the policy
    // violations just because the probe also failed.
    let mut p = Policy::default();
    p.network.outbound.egress_rules = vec![EgressRule {
        allow: true,
        dest: EgressDest::Cidr("2001:db8::/32".to_string()),
        proto: EgressProto::Any,
        port: None,
    }];
    let mut r = probe(true).unwrap();
    r.tun = false;
    let pr = Ok(r);
    let sel = decide(
        LinuxMechanismRequest::Namespaced,
        &input_v6(&p, &pr, upstream(), 8, false),
    );
    assert_eq!(sel.selected, None);
    assert!(
        sel.violations.iter().any(|s| s.contains("IPv6")),
        "probe-missing refusal must keep the policy violations"
    );
    // …and an `auto` refusal with a *capable* probe names the
    // actual namespaced violation in its reason rather than the
    // "requirement inexpressible" placeholder.
    let pr = probe(true);
    let sel = decide(
        LinuxMechanismRequest::Auto,
        &input_v6(&p, &pr, upstream(), 8, false),
    );
    assert_eq!(sel.selected, None);
    assert!(sel.reason.contains("IPv6"), "reason: {}", sel.reason);
}

// --- PR-26: legacy-dispatch dead-UDP gate -----------------------------

/// The no-selection dispatch (the in-guest runner's `linux_mechanism:
/// None` contract) must flag exactly the allows the native route can
/// never honor — UDP-covered rules under deny-all.
#[test]
fn dead_udp_allows_flags_udp_covering_rules_under_deny_all() {
    let dead = dead_udp_allows_without_selection(&udp_allow_policy());
    assert_eq!(dead.len(), 1);
    assert!(dead[0].contains("grants UDP"), "{dead:?}");
    assert!(dead[0].contains("dead policy"), "{dead:?}");

    // `proto="any"` covers UDP → dead too.
    let mut p = Policy::default();
    p.network.outbound.egress_rules = vec![EgressRule {
        allow: true,
        dest: EgressDest::Host("203.0.113.5".to_string()),
        proto: EgressProto::Any,
        port: None,
    }];
    assert_eq!(dead_udp_allows_without_selection(&p).len(), 1);
}

/// TCP-only allows and deny rules are not dead on the native route;
/// an open posture applies no socket pin, so a UDP allow there is
/// redundant rather than violated.
#[test]
fn dead_udp_allows_ignores_tcp_denies_and_open_posture() {
    assert!(dead_udp_allows_without_selection(&bare_port_policy()).is_empty());
    // A destination-scoped TCP-only allow is widened on the legacy
    // native route (Landlock binds the port, not the host) but is not
    // *dead* — out of this gate's scope.
    let mut p = Policy::default();
    p.network.outbound.egress_rules = vec![EgressRule {
        allow: true,
        dest: EgressDest::Host("api.example.com".to_string()),
        proto: EgressProto::Tcp,
        port: Some(443),
    }];
    assert!(dead_udp_allows_without_selection(&p).is_empty());
    // A deny rule is not an allow — never flagged.
    let mut p = Policy::default();
    p.network.outbound.egress_rules = vec![EgressRule {
        allow: false,
        dest: EgressDest::Host("203.0.113.5".to_string()),
        proto: EgressProto::Any,
        port: None,
    }];
    assert!(dead_udp_allows_without_selection(&p).is_empty());
    // Open posture: the native socket pin is not applied — the UDP
    // grant is redundant, not dead.
    let mut p = udp_allow_policy();
    p.network.outbound.deny_all_others = false;
    assert!(dead_udp_allows_without_selection(&p).is_empty());
}

// --- Landlock-unmediatable filesystems ----------------------------

///  is procfs — always Landlock-mediatable. Nonexistent and
/// mid-glob spellings are indeterminate and must not verdict.
#[test]
fn unmediatable_grant_fs_ignores_mediated_and_unknown() {
    assert_eq!(unmediatable_grant_fs("/proc"), None);
    assert_eq!(unmediatable_grant_fs("/proc/**"), None);
    assert_eq!(unmediatable_grant_fs("/definitely/not/here"), None);
    assert_eq!(unmediatable_grant_fs("/proc/*/status"), None);
}

/// The first 9p/v9fs mount on this host, when one exists — the
/// filesystem Landlock's inode-object walk cannot match (WSL2 mounts
/// Windows drives this way).
fn first_pseudo_fs_mount() -> Option<String> {
    std::fs::read_to_string("/proc/mounts").ok().and_then(|m| {
        m.lines().find_map(|l| {
            let mut f = l.split_whitespace();
            let _dev = f.next()?;
            let dir = f.next()?;
            let fstype = f.next()?;
            (fstype == "9p" || fstype == "v9fs").then(|| dir.replace(r"\040", " "))
        })
    })
}

/// On a host with a real 9p mount the probe must flag it — and the
/// collector must report the declared grant as dead policy. Hosts
/// without such a mount (ordinary Linux CI) skip the positive half.
#[test]
fn unmediatable_fs_violations_flags_pseudo_fs_grants() {
    // With no Landlock at all the no-support violation already covers
    // every fs grant — this check stays silent under ABI 0.
    let mut p = Policy::default();
    p.fs.read_only.push("/proc".to_string());
    assert!(unmediatable_fs_violations(&p, 0).is_empty());
    assert!(unmediatable_fs_violations(&p, 6).is_empty());

    let Some(mnt) = first_pseudo_fs_mount() else {
        return;
    };
    assert!(unmediatable_grant_fs(&mnt).is_some());
    assert!(unmediatable_grant_fs(&format!("{mnt}/**")).is_some());
    let mut p = Policy::default();
    p.fs.read_only.push(mnt.clone());
    let v = unmediatable_fs_violations(&p, 6);
    assert_eq!(v.len(), 1);
    assert!(v[0].contains("Landlock cannot mediate"), "got: {}", v[0]);

    // An allowed tool's grant flags the same way; a disabled tool's
    // never reaches the ruleset — the builders skip it, so the
    // selection must not refuse on its behalf.
    let mut p = Policy::default();
    let mut tool = crate::policy::ToolPolicy::named("t", true);
    tool.fs = Some(crate::policy::FsToolPolicy {
        allowed_paths: vec![mnt.clone()],
        ..Default::default()
    });
    p.tools = vec![tool];
    let v = unmediatable_fs_violations(&p, 6);
    assert_eq!(v.len(), 1);
    let mut tool = crate::policy::ToolPolicy::named("t", false);
    tool.fs = Some(crate::policy::FsToolPolicy {
        allowed_paths: vec![mnt],
        ..Default::default()
    });
    p.tools = vec![tool];
    assert!(unmediatable_fs_violations(&p, 6).is_empty());
}
