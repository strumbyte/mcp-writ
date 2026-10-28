//! Resolved-address policy: explicit denies on resolved endpoints,
//! protected-address grant refusal with literal/CIDR opt-in, and
//! IP-literal queries evaluated against CIDR rules.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};

use mcp_writ::dnsgate::Refusal;

use crate::common;
use crate::support::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn resolved_addr_explicit_deny_refuses() {
    // An allowed name whose answer carries an explicitly denied
    // address refuses — deny binds the destination whatever name
    // resolved to it.
    let mut table = HashMap::new();
    table.insert(
        "allowed.example".to_string(),
        MockAnswer {
            rcode: 0,
            tc_on_udp: false,
            answers: vec![Answ::A {
                owner: "allowed.example".into(),
                ip: Ipv4Addr::new(203, 0, 113, 5),
                ttl: 60,
            }],
            silent: false,
            corrupt_id: false,
        },
    );
    let Some(gate) = start_gate(
        policy_with(outbound(
            &["allowed.example"],
            &[],
            &[],
            &["203.0.113.0/24"],
            true,
        )),
        table,
        Refusal::Refused,
        None,
        false,
    )
    .await
    else {
        common::skip_e2e_test("no write-restricted audit root");
        return;
    };

    let resp = udp_query(gate.listen, &dns_query(1, "allowed.example", 1))
        .await
        .expect("refusal answer");
    assert_eq!(rcode(&resp), 5, "denied resolved address refuses");
    assert!(!gate.allowlist.is_allowed(
        &IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5)),
        mcp_writ::policy::EgressProto::Tcp,
        443
    ));
    let lines = stop_gate(gate).await;
    let denied = details_for(&lines, "sandbox.network_denied");
    assert!(
        denied.iter().any(|d| d.contains("decision=deny-cidr")
            && d.contains("rule=203.0.113.0/24")
            && d.contains("resolved-addr=203.0.113.5")),
        "denial must name the resolved address: {denied:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn protected_addr_mints_no_grant() {
    // An allowed name may legitimately resolve into protected space
    // (cloud metadata, loopback, RFC1918) — the answer still relays,
    // but no grant is minted: a name allow never authorizes
    // destinations the operator could not have enumerated.
    let mut table = HashMap::new();
    for (name, ip) in [
        ("meta.example", Ipv4Addr::new(169, 254, 169, 254)),
        ("loop.example", Ipv4Addr::new(127, 0, 0, 1)),
        ("priv.example", Ipv4Addr::new(10, 1, 2, 3)),
        ("cgnat.example", Ipv4Addr::new(100, 100, 100, 200)),
    ] {
        table.insert(
            name.to_string(),
            MockAnswer {
                rcode: 0,
                tc_on_udp: false,
                answers: vec![Answ::A {
                    owner: name.into(),
                    ip,
                    ttl: 60,
                }],
                silent: false,
                corrupt_id: false,
            },
        );
    }
    let Some(gate) = start_gate(
        policy_with(outbound(
            &[
                "meta.example",
                "loop.example",
                "priv.example",
                "cgnat.example",
            ],
            &[],
            &[],
            &[],
            true,
        )),
        table,
        Refusal::Refused,
        None,
        false,
    )
    .await
    else {
        common::skip_e2e_test("no write-restricted audit root");
        return;
    };

    for (i, name) in [
        "meta.example",
        "loop.example",
        "priv.example",
        "cgnat.example",
    ]
    .iter()
    .enumerate()
    {
        let resp = udp_query(gate.listen, &dns_query(i as u16 + 1, name, 1))
            .await
            .expect("answer");
        assert_eq!(rcode(&resp), 0, "{name}: answer still relays");
    }
    for ip in [
        "169.254.169.254",
        "127.0.0.1",
        "10.1.2.3",
        "100.100.100.200",
    ] {
        let addr: IpAddr = ip.parse().unwrap();
        assert!(
            !gate
                .allowlist
                .is_allowed(&addr, mcp_writ::policy::EgressProto::Tcp, 443),
            "no grant may mint for protected {ip}"
        );
        assert!(
            gate.allowlist.names_for(&addr).is_empty(),
            "no names may register against protected {ip}"
        );
    }
    let lines = stop_gate(gate).await;
    let resolved = details_for(&lines, "sandbox.network_resolved");
    for r in &resolved {
        assert!(r.contains("protected_refused=1"), "{r}");
        assert!(r.contains("grants=0") || !r.contains("grants="), "{r}");
    }
    assert_eq!(resolved.len(), 4);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn protected_addr_opt_in_mints_grant() {
    // An explicit literal/CIDR allow names the protected endpoint —
    // the opt-in mints under the *address* rule's qualifiers.
    let mut table = HashMap::new();
    table.insert(
        "svc.example".to_string(),
        MockAnswer {
            rcode: 0,
            tc_on_udp: false,
            answers: vec![Answ::A {
                owner: "svc.example".into(),
                ip: Ipv4Addr::new(169, 254, 169, 254),
                ttl: 60,
            }],
            silent: false,
            corrupt_id: false,
        },
    );
    let Some(gate) = start_gate(
        policy_with(outbound(
            &["svc.example"],
            &[],
            &["169.254.169.254/32"],
            &[],
            true,
        )),
        table,
        Refusal::Refused,
        None,
        false,
    )
    .await
    else {
        common::skip_e2e_test("no write-restricted audit root");
        return;
    };

    let resp = udp_query(gate.listen, &dns_query(1, "svc.example", 1))
        .await
        .expect("answer");
    assert_eq!(rcode(&resp), 0);
    let addr = IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254));
    assert!(
        gate.allowlist
            .is_allowed(&addr, mcp_writ::policy::EgressProto::Tcp, 443),
        "opted-in protected endpoint mints a grant"
    );
    // The grant carries the address rule's proto scope (default TCP) —
    // never UDP.
    assert!(
        !gate
            .allowlist
            .is_allowed(&addr, mcp_writ::policy::EgressProto::Udp, 443),
        "opt-in grant keeps the address rule's proto scope"
    );
    // But no neighboring protected endpoint is authorized — the
    // opt-in is scoped to exactly the allowed address.
    assert!(!gate.allowlist.is_allowed(
        &IpAddr::V4(Ipv4Addr::new(169, 254, 169, 253)),
        mcp_writ::policy::EgressProto::Tcp,
        443
    ));
    let lines = stop_gate(gate).await;
    let resolved = details_for(&lines, "sandbox.network_resolved");
    assert!(
        resolved
            .iter()
            .any(|r| r.contains("grants=1") && !r.contains("protected_refused")),
        "opted-in mint is audited: {resolved:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ip_literal_query_evaluates_cidr_rules() {
    //  constrains IP-literal query names; a denied CIDR
    // refuses the literal even when the name isn't a host rule.
    let mut table = HashMap::new();
    table.insert(
        "10.1.2.3".to_string(),
        MockAnswer {
            rcode: 0,
            tc_on_udp: false,
            answers: vec![Answ::A {
                owner: "10.1.2.3".into(),
                ip: Ipv4Addr::new(10, 1, 2, 3),
                ttl: 30,
            }],
            silent: false,
            corrupt_id: false,
        },
    );
    let Some(gate) = start_gate(
        policy_with(outbound(&[], &[], &["10.0.0.0/8"], &["10.9.0.0/16"], true)),
        table,
        Refusal::Refused,
        None,
        false,
    )
    .await
    else {
        common::skip_e2e_test("no write-restricted audit root");
        return;
    };

    let resp = udp_query(gate.listen, &dns_query(1, "10.1.2.3", 1))
        .await
        .unwrap();
    assert_eq!(rcode(&resp), 0, "allowed cidr covers the literal");
    let resp = udp_query(gate.listen, &dns_query(2, "10.9.1.1", 1))
        .await
        .unwrap();
    assert_eq!(rcode(&resp), 5, "denied cidr refuses the literal");
    let resp = udp_query(gate.listen, &dns_query(3, "172.16.0.1", 1))
        .await
        .unwrap();
    assert_eq!(rcode(&resp), 5, "uncovered literal refused under deny-all");
    let lines = stop_gate(gate).await;
    let denied = details_for(&lines, "sandbox.network_denied");
    assert!(
        denied
            .iter()
            .any(|d| d.contains("decision=deny-cidr") && d.contains("rule=10.9.0.0/16")),
        "cidr deny must name the rule: {denied:?}"
    );
}
