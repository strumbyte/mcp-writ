use super::*;
use crate::policy::TransportType;
use crate::warden::SpawnOptions;

// -- a flatbuffer reader just wide enough to verify the wire layout --

fn u16at(b: &[u8], at: usize) -> u16 {
    u16::from_le_bytes(b[at..at + 2].try_into().unwrap())
}
fn u32at(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(b[at..at + 4].try_into().unwrap())
}
/// Absolute position of table field `slot` (0 when the field is absent).
fn field_at(b: &[u8], table: usize, slot: usize) -> usize {
    let vtable = table - u32at(b, table) as usize;
    let vlen = u16at(b, vtable) as usize;
    let entry = vtable + 4 + 2 * slot;
    if entry + 2 > vtable + vlen {
        return 0;
    }
    let off = u16at(b, entry) as usize;
    if off == 0 { 0 } else { table + off }
}
/// Follow a uoffset field to its target table/string/vector position.
fn follow(b: &[u8], at: usize) -> usize {
    at + u32at(b, at) as usize
}
fn string_at(b: &[u8], at: usize) -> String {
    let len = u32at(b, at) as usize;
    String::from_utf8(b[at + 4..at + 4 + len].to_vec()).unwrap()
}
/// `[string]` vector → owned strings.
fn strvec_at(b: &[u8], at: usize) -> Vec<String> {
    let n = u32at(b, at) as usize;
    (0..n)
        .map(|i| string_at(b, follow(b, at + 4 + 4 * i)))
        .collect()
}

#[test]
fn encode_spec_wire_layout() {
    let ro = vec!["C:\\ro".to_string()];
    let rw = vec!["C:\\rw".to_string(), "C:\\rw2".to_string()];
    let deny = vec!["C:\\deny".to_string()];
    let allow = vec!["10.0.0.1".to_string()];
    let b = encode_spec(&ro, &rw, &deny, &allow);

    // file_identifier + root offset.
    assert_eq!(&b[4..8], b"PSEC");
    let root = u32at(&b, 0) as usize;

    // version = {1,0} inline at slot 0.
    let v = field_at(&b, root, 0);
    assert_eq!((u16at(&b, v), u16at(&b, v + 2)), (1, 0));

    // fs vectors at slots 4/5/6.
    assert_eq!(strvec_at(&b, follow(&b, field_at(&b, root, 4))), rw);
    assert_eq!(strvec_at(&b, follow(&b, field_at(&b, root, 5))), ro);
    assert_eq!(strvec_at(&b, follow(&b, field_at(&b, root, 6))), deny);

    // network_policy → egress (slot 1) → default_action 0 + allow rules.
    let net = follow(&b, field_at(&b, root, 7));
    let egress = follow(&b, field_at(&b, net, 1));
    assert_eq!(b[field_at(&b, egress, 0)], 0, "egress default_action=deny");
    let rules = follow(&b, field_at(&b, egress, 1));
    assert_eq!(u32at(&b, rules), 1, "one allow rule");
    let rule = follow(&b, rules + 4);
    let dests = follow(&b, field_at(&b, rule, 0));
    assert_eq!(u32at(&b, dests), 1);
    let dest = follow(&b, dests + 4);
    let subnet = follow(&b, field_at(&b, dest, 0));
    let addr = string_at(&b, follow(&b, field_at(&b, subnet, 0)));
    assert_eq!(addr, "10.0.0.1");
    assert_eq!(b[field_at(&b, subnet, 1)], 32, "prefix_length");

    // EndpointRule.ports (slot 1) — PortRule{ protocol: tcp(1),
    // port: 1, end_port: 65535 }: the grant must pin TCP only; an
    // absent ports clause is transport-blind and widens to UDP.
    let ports = follow(&b, field_at(&b, rule, 1));
    assert_eq!(u32at(&b, ports), 1, "one port rule");
    let port_rule = follow(&b, ports + 4);
    assert_eq!(b[field_at(&b, port_rule, 0)], 1, "protocol = tcp");
    assert_eq!(u16at(&b, field_at(&b, port_rule, 1)), 1, "port = 1");
    assert_eq!(u16at(&b, field_at(&b, port_rule, 2)), u16::MAX, "end_port");
}

/// The audit surface reports `SPEC_VERSION` as
/// `enforcement.psec.schema_version` — the two spellings must name
/// the same pair or the JSONL record would misreport the wire.
#[test]
fn spec_version_matches_audit_constant() {
    assert_eq!(
        format!("{}.{}", SPEC_VERSION.0, SPEC_VERSION.1),
        crate::enforcement::PSEC_SPEC_SCHEMA_VERSION
    );
}

#[test]
fn encode_spec_empty_lists_omit_fields_but_keep_deny_default() {
    let b = encode_spec(&[], &[], &[], &[]);
    let root = u32at(&b, 0) as usize;
    for slot in [4usize, 5, 6] {
        assert_eq!(field_at(&b, root, slot), 0, "slot {slot} absent");
    }
    let net = follow(&b, field_at(&b, root, 7));
    let egress = follow(&b, field_at(&b, net, 1));
    assert_eq!(b[field_at(&b, egress, 0)], 0);
    assert_eq!(field_at(&b, egress, 1), 0, "no allow rules");
}

fn base_policy() -> Policy {
    Policy::default() // deny_all_others = true
}

fn refusal(policy: &Policy, opts: &SpawnOptions) -> Vec<String> {
    match build_launch_spec(policy, None, "child", opts) {
        Ok(_) => panic!("expected refusal"),
        Err(r) => r.problems,
    }
}

#[test]
fn refuses_environment_allow_list_and_tmpdir() {
    let policy = base_policy();
    let opts = SpawnOptions {
        restrict_environment: true,
        allowed_names: vec!["FOO".to_string()],
        tmpdir: Some(std::path::PathBuf::from("C:\\tmp")),
        ..Default::default()
    };
    let r = match build_launch_spec(&policy, None, "child", &opts) {
        Ok(_) => panic!("expected refusal"),
        Err(r) => r,
    };
    // Refusal grants stay attached — the report records what the
    // spec would have carried.
    let _ = &r.grants;
    assert!(
        r.problems.iter().any(|p| p.contains("'FOO'")),
        "{:?}",
        r.problems
    );
    assert!(
        r.problems.iter().any(|p| p.contains("tmpdir")),
        "{:?}",
        r.problems
    );
}

#[test]
fn bare_restrict_environment_is_expressible() {
    let policy = base_policy();
    let opts = SpawnOptions {
        restrict_environment: true,
        allowed_names: vec![],
        tmpdir: None,
        ..Default::default()
    };
    // A bare restriction holds by construction — no refusal, and the
    // spec encodes.
    assert!(build_launch_spec(&policy, None, "child", &opts).is_ok());
}

#[test]
fn refuses_unrestricted_egress_and_inbound_and_http() {
    let mut policy = base_policy();
    policy.network.outbound.deny_all_others = false;
    policy.network.inbound.allow_listen = true;
    policy.transport.type_ = TransportType::Http;
    let problems = refusal(&policy, &SpawnOptions::default());
    assert!(
        problems.iter().any(|p| p.contains("unrestricted outbound")),
        "{problems:?}"
    );
    assert!(
        problems.iter().any(|p| p.contains("allow_listen")),
        "{problems:?}"
    );
    assert!(
        problems.iter().any(|p| p.contains("loopback")),
        "{problems:?}"
    );
}

#[test]
fn refuses_non_ipv4_and_port_qualified_allow_entries() {
    let mut policy = base_policy();
    policy.network.outbound.allowed = vec![
        "api.example.com".to_string(),
        "10.0.0.1:443".to_string(),
        "::1".to_string(),
    ];
    let problems = refusal(&policy, &SpawnOptions::default());
    for needle in ["api.example.com", "10.0.0.1:443", "::1"] {
        assert!(
            problems.iter().any(|p| p.contains(needle)),
            "{needle}: {problems:?}"
        );
    }
}

#[test]
fn refuses_glob_and_relative_fs_paths() {
    let mut policy = base_policy();
    policy.fs.read_only = vec!["C:\\data\\**".to_string(), "rel\\path".to_string()];
    let problems = refusal(&policy, &SpawnOptions::default());
    assert!(problems.iter().any(|p| p.contains("glob")), "{problems:?}");
    assert!(
        problems.iter().any(|p| p.contains("absolute")),
        "{problems:?}"
    );
}

#[test]
fn refuses_allow_entries_recorded_as_port_qualified() {
    // Parse folds `host:port` to the host and records the source
    // spelling; the spec build must refuse the same way load-time
    // validation does — a programmatically built policy skips the
    // validator.
    let mut policy = base_policy();
    policy.network.outbound.allowed = vec!["10.0.0.1".to_string()];
    policy.network.outbound.allowed_port_qualified = vec!["10.0.0.1:443".to_string()];
    match build_launch_spec(&policy, None, "child", &SpawnOptions::default()) {
        Ok(_) => panic!("a port-qualified allow entry must refuse"),
        Err(r) => {
            assert!(
                r.problems
                    .iter()
                    .any(|p| p.contains("10.0.0.1:443") && p.contains("port")),
                "{:?}",
                r.problems
            );
            assert!(r.grants.iter().any(|g| matches!(
                &g.subject,
                GrantSubject::Rule { kind, name }
                    if *kind == "net_destination" && name == "10.0.0.1:443"
            ) && g.state == ControlState::NotApplied));
        }
    }

    // A port-qualified *hostname* additionally spells the
    // name-layer guidance — the same as the bare-name refusal.
    let mut policy = base_policy();
    policy.network.outbound.allowed = vec!["api.example.com".to_string()];
    policy.network.outbound.allowed_port_qualified = vec!["api.example.com:443".to_string()];
    match build_launch_spec(&policy, None, "child", &SpawnOptions::default()) {
        Ok(_) => panic!("a port-qualified hostname must refuse"),
        Err(r) => assert!(
            r.problems.iter().any(|p| p.contains("api.example.com:443")
                && p.contains("port")
                && p.contains("no native-Windows enforcement")),
            "{:?}",
            r.problems
        ),
    }
}

#[test]
fn cidr_ipv4_32_entries_encode_as_destination_rules() {
    // An `allow cidr=` IPv4 /32 is the host-route spelling of a
    // literal destination — it encodes into the same subnet rule.
    let mut policy = base_policy();
    policy.network.outbound.allowed = vec!["10.0.0.1".to_string()];
    policy.network.outbound.allowed_cidrs =
        vec!["10.0.0.1/32".to_string(), "10.0.0.2/32".to_string()];
    let build = build_launch_spec(&policy, None, "child", &SpawnOptions::default())
        .expect("IPv4 /32 cidr entries are expressible");
    // Both cidr entries record as planned destination rules; the
    // duplicate of the `allowed` literal deduplicates in the wire set.
    for name in ["10.0.0.1/32", "10.0.0.2/32"] {
        assert!(build.grants.iter().any(|g| matches!(
            &g.subject,
            GrantSubject::Rule { kind, name: n }
                if *kind == "net_destination_cidr" && n == name
        ) && g.state == ControlState::Planned));
    }
    assert!(!build.spec.is_empty());
}

#[test]
fn refuses_non_host_route_and_port_qualified_cidr_entries() {
    let mut policy = base_policy();
    policy.network.outbound.allowed_cidrs =
        vec!["10.0.0.0/8".to_string(), "2001:db8::/32".to_string()];
    policy.network.outbound.allowed_cidrs_port_qualified = vec!["10.0.0.1/32:443".to_string()];
    // The port-qualified record only counts while its folded rule
    // is present — include the folded rule so it refuses.
    policy
        .network
        .outbound
        .allowed_cidrs
        .push("10.0.0.1/32".to_string());
    let r = match build_launch_spec(&policy, None, "child", &SpawnOptions::default()) {
        Ok(_) => panic!("non-/32 and port-qualified cidr entries must refuse"),
        Err(r) => r,
    };
    for needle in ["10.0.0.0/8", "2001:db8::/32", "10.0.0.1/32:443"] {
        assert!(
            r.problems.iter().any(|p| p.contains(needle)),
            "{needle}: {:?}",
            r.problems
        );
    }
    // Refused entries record NotApplied grants — the report shows
    // what the spec would have carried.
    assert!(r.grants.iter().any(|g| matches!(
        &g.subject,
        GrantSubject::Rule { kind, name }
            if *kind == "net_destination_cidr" && name == "10.0.0.0/8"
    ) && g.state == ControlState::NotApplied));
}

#[test]
fn port_qualified_cidr_records_one_not_applied_grant() {
    // One rule, one record: the folded `/32` must not also encode
    // as a Planned grant beside the port-qualifier refusal.
    let mut policy = base_policy();
    policy.network.outbound.allowed_cidrs = vec!["10.0.0.1/32".to_string()];
    policy.network.outbound.allowed_cidrs_port_qualified = vec!["10.0.0.1/32:443".to_string()];
    let r = match build_launch_spec(&policy, None, "child", &SpawnOptions::default()) {
        Ok(_) => panic!("a port-qualified cidr entry must refuse"),
        Err(r) => r,
    };
    assert!(
        r.problems
            .iter()
            .any(|p| p.contains("10.0.0.1/32:443") && p.contains("port")),
        "{:?}",
        r.problems
    );
    let records: Vec<_> = r
        .grants
        .iter()
        .filter(|g| {
            matches!(
                &g.subject,
                GrantSubject::Rule { kind, name }
                    if *kind == "net_destination_cidr"
                        && (name == "10.0.0.1/32" || name == "10.0.0.1/32:443")
            )
        })
        .collect();
    assert_eq!(records.len(), 1, "{:?}", r.grants);
    assert_eq!(records[0].state, ControlState::NotApplied);
}

#[test]
fn refuses_allow_rules_with_structured_qualifiers() {
    // A parsed `proto=`/`port=` rule carries its qualifier in
    // `egress_rules` without spelling-level provenance — the spec
    // build refuses the qualifier rather than changing the rule's
    // declared port/transport scope.
    let rule = |proto: crate::policy::EgressProto, port: Option<u16>| crate::policy::EgressRule {
        allow: true,
        dest: crate::policy::EgressDest::Host("10.0.0.9".to_string()),
        proto,
        port,
    };
    for r in [
        rule(crate::policy::EgressProto::Udp, None),
        rule(crate::policy::EgressProto::Any, None),
        rule(crate::policy::EgressProto::Tcp, Some(53)),
    ] {
        let mut policy = base_policy();
        policy.network.outbound.egress_rules = vec![r.clone()];
        let problems = refusal(&policy, &SpawnOptions::default());
        assert!(
            problems
                .iter()
                .any(|p| p.contains("qualifier") && p.contains(&r.describe())),
            "{}: {problems:?}",
            r.describe()
        );
    }
    // An unqualified TCP rule to a bare IPv4 literal encodes.
    let mut policy = base_policy();
    policy
        .network
        .outbound
        .egress_rules
        .push(rule(crate::policy::EgressProto::Tcp, None));
    // `egress_rules` alone does not feed the destination list — a
    // parsed policy mirrors the rule into `allowed` too.
    policy.network.outbound.allowed = vec!["10.0.0.9".to_string()];
    build_launch_spec(&policy, None, "child", &SpawnOptions::default())
        .expect("an unqualified TCP allow rule to an IPv4 literal is expressible");
}

#[test]
fn refuses_deny_overlapping_a_declared_allow() {
    // PSEC cannot carve an exception out of an allowed destination —
    // a declared allow intersecting an IP-layer deny refuses rather
    // than silently swallowing the denied share.
    let mut policy = base_policy();
    policy.network.outbound.allowed = vec!["10.0.0.1".to_string()];
    policy.network.outbound.denied_cidrs = vec!["10.0.0.0/24".to_string()];
    let problems = refusal(&policy, &SpawnOptions::default());
    assert!(
        problems.iter().any(|p| p.contains("overlap")),
        "{problems:?}"
    );
    // A disjoint deny is covered by the default-deny — Skipped, not
    // a refusal.
    let mut policy = base_policy();
    policy.network.outbound.allowed = vec!["10.0.0.1".to_string()];
    policy.network.outbound.denied_cidrs = vec!["192.0.2.0/24".to_string()];
    let build = build_launch_spec(&policy, None, "child", &SpawnOptions::default())
        .expect("a disjoint deny is covered by default-deny");
    assert!(build.grants.iter().any(|g| matches!(
        &g.subject,
        GrantSubject::Rule { kind, name }
            if *kind == "net_destination_deny" && name == "192.0.2.0/24"
    ) && g.state == ControlState::Skipped));
}

#[test]
fn verbatim_prefixed_fs_paths_are_expressible() {
    // `\\?\…` is the spelling the runtime itself emits for resolved
    // image paths — a policy entry in that form must be expressible
    // too (a '?' elsewhere still refuses as a glob).
    let mut policy = base_policy();
    policy.fs.read_only = vec!["\\\\?\\C:\\missing\\mcp-writ".to_string()];
    let build = build_launch_spec(&policy, None, "child", &SpawnOptions::default())
        .expect("a verbatim path is expressible (skipped while missing)");
    assert!(build.grants.iter().any(|g| matches!(
        &g.subject,
        GrantSubject::FsPath { path, access }
            if path == "\\\\?\\C:\\missing\\mcp-writ" && *access == FsAccess::Read
    ) && g.state == ControlState::Skipped));
}

#[test]
fn fs_deny_entries_record_as_deny_rules_not_traverse_grants() {
    // A `denied_paths` entry becomes a spec fs_deny rule — it must
    // never surface in a report as if access were granted.
    let mut policy = base_policy();
    policy.fs.denied_paths = vec!["C:\\missing\\mcp-writ-deny".to_string()];
    let build = build_launch_spec(&policy, None, "child", &SpawnOptions::default())
        .expect("a missing deny path skips, never refuses");
    assert!(build.grants.iter().any(|g| matches!(
        &g.subject,
        GrantSubject::Rule { kind, name }
            if *kind == "fs_deny" && name == "C:\\missing\\mcp-writ-deny"
    ) && g.state == ControlState::Skipped));
    assert!(!build.grants.iter().any(|g| matches!(
        &g.subject,
        GrantSubject::FsPath { path, access }
            if path == "C:\\missing\\mcp-writ-deny" && *access == FsAccess::Traverse
    )));
}

#[test]
fn expressible_policy_encodes_ipv4_allow_rules() {
    let mut policy = base_policy();
    policy.network.outbound.allowed = vec!["10.0.0.1".to_string()];
    let build =
        build_launch_spec(&policy, None, "child", &SpawnOptions::default()).expect("expressible");
    // spec carries the egress allow rule (verified structurally above).
    assert!(!build.spec.is_empty());
    // fs_paths is the create-time warm list — read it so the field
    // is exercised even when every fs entry was skipped.
    let _ = &build.fs_paths;
    assert!(
        build
            .grants
            .iter()
            .any(|g| matches!(&g.subject, GrantSubject::Rule { kind, name }
                    if *kind == "net_destination" && name == "10.0.0.1")
                && g.state == ControlState::Planned)
    );
}
