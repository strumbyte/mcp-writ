//! Unit tests for the cgroup-eBPF route — rule-table projection,
//! program generation shape, grant-map encoding, and the startup
//! capability refusal. Kernel-side behavior (actual deny/allow,
//! ring-buffer delivery) is exercised by the privileged e2e path —
//! these tests need no privileges.

use std::net::IpAddr;

use crate::policy::{EgressDest, EgressProto, EgressRule, GrantQual, OutboundPolicy};

use super::prog::{ProgKind, ProgMaps};
use super::rules::{self, ACTION_ALLOW, ACTION_DENY, Family};

fn outbound(
    allowed: &[&str],
    denied: &[&str],
    cidrs: &[&str],
    denied_cidrs: &[&str],
    deny_all: bool,
) -> OutboundPolicy {
    OutboundPolicy {
        allowed: allowed.iter().map(|s| s.to_string()).collect(),
        allowed_port_qualified: Vec::new(),
        allowed_cidrs: cidrs.iter().map(|s| s.to_string()).collect(),
        allowed_cidrs_port_qualified: Vec::new(),
        denied_hosts: denied.iter().map(|s| s.to_string()).collect(),
        denied_cidrs: denied_cidrs.iter().map(|s| s.to_string()).collect(),
        deny_all_others: deny_all,
        egress_rules: Vec::new(),
    }
}

// --- rules::compile ------------------------------------------------------

#[test]
fn compile_denies_precede_allows() {
    let p = outbound(
        &["10.0.0.0/8"],
        &["10.9.0.0/16"],
        &["10.0.0.0/8"],
        &["10.9.0.0/16"],
        true,
    );
    let t = rules::compile(&p).unwrap();
    // deny entry first, allow second — same order the evaluator gives.
    assert_eq!(t.v4.len(), 2);
    assert_eq!(t.v4[0].action, ACTION_DENY);
    assert_eq!(t.v4[1].action, ACTION_ALLOW);
    assert!(!t.default_allow);
    assert_eq!(t.meta_v4[0].rule, "10.9.0.0/16");
    assert_eq!(t.meta_v4[0].decision, "deny-cidr");
}

#[test]
fn compile_deny_star_is_leading_wildcard_deny() {
    let p = outbound(&[], &["*"], &[], &[], true);
    let t = rules::compile(&p).unwrap();
    assert!(t.deny_all);
    // A mask=0 entry in both families — every destination matches it.
    assert_eq!(t.v4[0].mask, [0; 4]);
    assert_eq!(t.v4[0].action, ACTION_DENY);
    assert_eq!(t.v6[0].mask, [0; 4]);
    assert_eq!(t.v6[0].action, ACTION_DENY);
    assert_eq!(t.meta_v4[0].rule, "*");
}

#[test]
fn compile_ip_literal_allow_is_static_v4() {
    let p = outbound(&["192.0.2.9"], &[], &[], &[], true);
    let t = rules::compile(&p).unwrap();
    // full mask, deny-all default → one allow entry
    assert_eq!(t.v4.len(), 1);
    assert_eq!(t.v4[0].action, ACTION_ALLOW);
    assert_eq!(t.v4[0].mask, [u32::MAX, 0, 0, 0]);
    // addr words carry the address bytes verbatim (ctx order).
    assert_eq!(t.v4[0].addr[0].to_ne_bytes(), [192, 0, 2, 9]);
    // tcp/any-port derived defaults
    assert_eq!(t.v4[0].proto, libc::IPPROTO_TCP as u32);
    assert_eq!(t.v4[0].port_raw, 0);
}

#[test]
fn compile_v6_cidr_goes_to_v6_table() {
    let mut p = outbound(&[], &[], &[], &[], true);
    p.egress_rules = vec![EgressRule {
        allow: true,
        dest: EgressDest::Cidr("2001:db8::/32".into()),
        proto: EgressProto::Udp,
        port: Some(53),
    }];
    let t = rules::compile(&p).unwrap();
    assert_eq!(t.v6.len(), 1);
    assert_eq!(t.v6[0].proto, libc::IPPROTO_UDP as u32);
    assert_eq!(t.v6[0].port_raw, 53u16.to_be() as u32);
    // /32 → the first mask word all-ones, the rest zero.
    assert_eq!(t.v6[0].mask, [u32::MAX, 0, 0, 0]);
}

#[test]
fn compile_name_only_allow_is_not_a_static_rule() {
    let p = outbound(&["example.com"], &[], &[], &[], true);
    let t = rules::compile(&p).unwrap();
    assert!(t.v4.is_empty() && t.v6.is_empty());
    assert!(!t.default_allow);
}

#[test]
fn compile_over_limit_refuses() {
    let mut p = outbound(&[], &[], &[], &[], true);
    p.allowed_cidrs = (0..(rules::MAX_RULES_PER_MAP + 1))
        .map(|i| format!("10.{}.0.0/16", i % 250))
        .collect();
    let e = rules::compile(&p).unwrap_err();
    assert!(e.contains("too many"));
}

#[test]
fn compile_bad_cidr_refuses() {
    let mut p = outbound(&[], &[], &[], &[], true);
    p.allowed_cidrs = vec!["10.0.0.0/33".to_string()];
    assert!(rules::compile(&p).is_err());
}

// --- grant entries -------------------------------------------------------

#[test]
fn grant_entries_one_per_qual() {
    let quals = [
        GrantQual {
            proto: EgressProto::Tcp,
            port: Some(443),
        },
        GrantQual {
            proto: EgressProto::Udp,
            port: Some(53),
        },
    ];
    let entries = rules::grant_entries(
        "192.0.2.10".parse::<IpAddr>().unwrap(),
        &quals,
        1_700_000_000,
    );
    // Each v4 grant produces a per-qual pair: the v4 entry plus the
    // IPv4-mapped v6 twin (INET6_CONNECT sees ::ffff:* destinations).
    assert_eq!(entries.len(), 4);
    for (fam, e) in &entries {
        assert_eq!(e.action, ACTION_ALLOW);
        // expiry is unix ns — same clock domain as the program's
        // ktime_get_boot_ns + boot-epoch estimate.
        assert_eq!(e.expires_at_ns, 1_700_000_000u64 * 1_000_000_000);
        match fam {
            Family::V4 => assert_eq!(e.addr[0] & 0xff, 192),
            Family::V6 => {
                assert_eq!(e.addr[0], 0);
                assert_eq!(e.addr[1], 0);
                assert_eq!(e.addr[2], u32::from_ne_bytes([0, 0, 0xff, 0xff]));
            }
        }
    }
    assert_eq!(entries[0].0, Family::V4);
    assert_eq!(entries[0].1.proto, libc::IPPROTO_TCP as u32);
    assert_eq!(entries[0].1.port_raw, 443u16.to_be() as u32);
    assert_eq!(entries[1].0, Family::V6);
    assert_eq!(entries[1].1.proto, libc::IPPROTO_TCP as u32);
    assert_eq!(entries[2].1.proto, libc::IPPROTO_UDP as u32);
    // A v6 grant stays single-family.
    let v6 = rules::grant_entries("2001:db8::1".parse::<IpAddr>().unwrap(), &quals, 1);
    assert!(v6.iter().all(|(f, _)| *f == Family::V6));
}

#[test]
fn grant_sentinel_is_always_past() {
    let s = rules::grant_sentinel();
    assert_eq!(s.expires_at_ns, 1);
    // Matches nothing: mask=0 would match 0.0.0.0, but the program
    // checks expiry *before* the address — a past timestamp skips it.
}

// --- prog::build ---------------------------------------------------------

const BPF_EXIT: u8 = 0x95;
const BPF_JA: u8 = 0x05;

fn insn_code(w: u64) -> u8 {
    w as u8
}

#[test]
fn build_terminates_and_resolves() {
    let maps = ProgMaps {
        rules: 3,
        grants: 4,
        events: 5,
        stats: 6,
    };
    for kind in [ProgKind::V4Connect, ProgKind::V6Connect] {
        let insns = super::prog::build(kind, maps, 2, 1, 4, false, 0);
        // Ends with exit; a deny path + allow tail both present —
        // count exits (allow tail + deny tail + drop tail).
        assert_eq!(insn_code(*insns.last().unwrap()), BPF_EXIT);
        let exits = insns.iter().filter(|i| insn_code(**i) == BPF_EXIT).count();
        assert_eq!(exits, 3, "expected allow/deny/drop tails ({kind:?})");
        // No unresolved JA jumps (offset 0 would mean a broken fixup
        // for a forward jump — a real fall-through JA has a target).
        for (i, w) in insns.iter().enumerate() {
            if insn_code(*w) == BPF_JA {
                let off = ((*w >> 16) & 0xffff) as i16;
                assert_ne!(off, 0, "JA at {i} has no target");
                let target = i as i64 + 1 + off as i64;
                assert!(
                    (0..insns.len() as i64).contains(&target),
                    "JA at {i} jumps out of range"
                );
            }
        }
    }
}

#[test]
fn build_binds_all_entry_count() {
    // n_rules=0 still builds: rule scan is empty, fall-through runs.
    let maps = ProgMaps {
        rules: 3,
        grants: 4,
        events: 5,
        stats: 6,
    };
    let insns = super::prog::build(ProgKind::V4Connect, maps, 0, 0, 2, true, 0);
    assert_eq!(insn_code(*insns.last().unwrap()), BPF_EXIT);
}

// --- capability probe refusal --------------------------------------------

#[test]
fn check_support_names_missing_capability() {
    // Only meaningful where the caller lacks the caps — under a
    // privileged test environment the probe legitimately passes.
    let eff = std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|b| {
            b.lines()
                .find(|l| l.starts_with("CapEff:"))
                .and_then(|l| u64::from_str_radix(l[7..].trim(), 16).ok())
        })
        .unwrap_or(0);
    let privileged = eff & (1 << 21) != 0; // CAP_SYS_ADMIN
    match super::probe::check_support() {
        Ok(()) => {
            assert!(privileged, "unprivileged env must refuse the probe");
        }
        Err(msg) => {
            assert!(
                msg.contains("cgroup") || msg.contains("CAP_") || msg.contains("bpf"),
                "diagnostic must name the missing piece: {msg}"
            );
        }
    }
}
