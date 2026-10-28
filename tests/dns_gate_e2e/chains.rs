//! Alias-chain re-judgement: CNAME/DNAME targets receive the same
//! deny-precedence evaluation as the queried name, undeclared chain
//! targets fail under default-deny, and overlong chains are refused
//! as SERVFAIL.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};

use mcp_writ::dnsgate::Refusal;

use crate::common;
use crate::support::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cname_chain_fully_allowed_mints_grants() {
    // Every hop covered by an allow → the chain relays and mints
    // grants under the queried name at chain-min TTL.
    let mut table = HashMap::new();
    table.insert(
        "www.allowed.example".to_string(),
        MockAnswer {
            rcode: 0,
            tc_on_udp: false,
            answers: vec![
                Answ::Cname {
                    owner: "www.allowed.example".into(),
                    target: "edge.allowed.example".into(),
                    // Shorter than the A record's TTL — the grant must
                    // not outlive the alias that vended it.
                    ttl: 20,
                },
                Answ::A {
                    owner: "edge.allowed.example".into(),
                    ip: Ipv4Addr::new(203, 0, 113, 5),
                    ttl: 45,
                },
            ],
            silent: false,
            corrupt_id: false,
        },
    );
    let Some(gate) = start_gate(
        policy_with(outbound(&["*.allowed.example"], &[], &[], &[], true)),
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

    let resp = udp_query(gate.listen, &dns_query(1, "www.allowed.example", 1))
        .await
        .expect("chain answer");
    assert_eq!(rcode(&resp), 0, "admitted chain relays");
    assert_eq!(answer_a_records(&resp), vec![Ipv4Addr::new(203, 0, 113, 5)]);

    // The A record minted a grant under the queried name — chain-min
    // TTL (min(20,45)=20), so the grant expires near now+20, well
    // inside the address record's own 45s.
    let addr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5));
    assert!(
        gate.allowlist
            .is_allowed(&addr, mcp_writ::policy::EgressProto::Tcp, 443),
        "answer IP must be allow-listed"
    );
    assert_eq!(
        gate.allowlist.names_for(&addr),
        vec!["www.allowed.example".to_string()]
    );
    let snapshot = gate.allowlist.snapshot_json();
    let json = nojson::RawJson::parse(&snapshot).unwrap();
    let exp: u64 = json
        .value()
        .to_member("entries")
        .unwrap()
        .required()
        .unwrap()
        .to_array()
        .unwrap()
        .next()
        .unwrap()
        .to_member("expires_at_unix_secs")
        .unwrap()
        .required()
        .unwrap()
        .as_number_str()
        .unwrap()
        .parse()
        .unwrap();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    assert!(
        exp > now && exp <= now + 21,
        "grant expiry must be chain-min TTL, not the A record's 45s: exp={exp} now={now}"
    );

    let lines = stop_gate(gate).await;
    let resolved = details_for(&lines, "sandbox.network_resolved");
    assert_eq!(resolved.len(), 1);
    let r = &resolved[0];
    assert!(r.contains("chain=edge.allowed.example"), "{r}");
    assert!(r.contains("ttl_min=20"), "{r}");
    assert!(r.contains("grants=1"), "{r}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cname_target_denied_refuses_and_mints_nothing() {
    // The CNAME target is *denied* by policy — deny precedence applies
    // to every hop, so the answer refuses (no relayed destination, no
    // grant) and the denial record names the offending target.
    let mut table = HashMap::new();
    table.insert(
        "www.allowed.example".to_string(),
        MockAnswer {
            rcode: 0,
            tc_on_udp: false,
            answers: vec![
                Answ::Cname {
                    owner: "www.allowed.example".into(),
                    target: "edge.denied.example".into(),
                    ttl: 20,
                },
                Answ::A {
                    owner: "edge.denied.example".into(),
                    ip: Ipv4Addr::new(203, 0, 113, 5),
                    ttl: 45,
                },
            ],
            silent: false,
            corrupt_id: false,
        },
    );
    let Some(gate) = start_gate(
        policy_with(outbound(
            &["allowed.example", "*.allowed.example"],
            &["*.denied.example"],
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

    let resp = udp_query(gate.listen, &dns_query(1, "www.allowed.example", 1))
        .await
        .expect("refusal answer");
    assert_eq!(
        rcode(&resp),
        5,
        "a denied CNAME target must refuse the query"
    );
    let addr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5));
    assert!(
        !gate
            .allowlist
            .is_allowed(&addr, mcp_writ::policy::EgressProto::Tcp, 443),
        "a refused chain mints no grant"
    );
    let lines = stop_gate(gate).await;
    let denied = details_for(&lines, "sandbox.network_denied");
    assert!(
        denied.iter().any(|d| d.contains("name=www.allowed.example")
            && d.contains("decision=deny-host")
            && d.contains("rule=*.denied.example")
            && d.contains("chain-target=edge.denied.example")),
        "denial must name the denied chain target: {denied:?}"
    );
    let resolved = details_for(&lines, "sandbox.network_resolved");
    assert!(
        resolved.is_empty(),
        "a refused chain emits no resolution record: {resolved:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn undeclared_chain_target_fails_under_default_deny() {
    // The alias target is neither allowed nor explicitly denied —
    // under `deny_all_others` an uncovered target refuses exactly as
    // an uncovered query name would.
    let mut table = HashMap::new();
    table.insert(
        "www.allowed.example".to_string(),
        MockAnswer {
            rcode: 0,
            tc_on_udp: false,
            answers: vec![
                Answ::Cname {
                    owner: "www.allowed.example".into(),
                    target: "cdn.other.example".into(),
                    ttl: 20,
                },
                Answ::A {
                    owner: "cdn.other.example".into(),
                    ip: Ipv4Addr::new(203, 0, 113, 9),
                    ttl: 30,
                },
            ],
            silent: false,
            corrupt_id: false,
        },
    );
    let Some(gate) = start_gate(
        policy_with(outbound(&["*.allowed.example"], &[], &[], &[], true)),
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

    let resp = udp_query(gate.listen, &dns_query(1, "www.allowed.example", 1))
        .await
        .expect("refusal answer");
    assert_eq!(rcode(&resp), 5, "uncovered chain target refuses");
    assert!(
        !gate.allowlist.is_allowed(
            &IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9)),
            mcp_writ::policy::EgressProto::Tcp,
            443
        ),
        "refused chain mints no grant"
    );
    let lines = stop_gate(gate).await;
    let denied = details_for(&lines, "sandbox.network_denied");
    assert!(
        denied
            .iter()
            .any(|d| d.contains("decision=not-allowed")
                && d.contains("chain-target=cdn.other.example")),
        "undeclared target audits not-allowed: {denied:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dname_synthesized_target_denied_refuses() {
    // A DNAME rewrites the subtree — the synthesized target is judged
    // like a CNAME hop: denied → refused, nothing minted.
    let mut table = HashMap::new();
    table.insert(
        "www.allowed.example".to_string(),
        MockAnswer {
            rcode: 0,
            tc_on_udp: false,
            answers: vec![
                Answ::Dname {
                    owner: "allowed.example".into(),
                    target: "denied.example".into(),
                    ttl: 20,
                },
                Answ::A {
                    owner: "www.denied.example".into(),
                    ip: Ipv4Addr::new(203, 0, 113, 7),
                    ttl: 40,
                },
            ],
            silent: false,
            corrupt_id: false,
        },
    );
    let Some(gate) = start_gate(
        policy_with(outbound(
            &["*.allowed.example"],
            &["*.denied.example"],
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

    let resp = udp_query(gate.listen, &dns_query(1, "www.allowed.example", 1))
        .await
        .expect("refusal answer");
    assert_eq!(rcode(&resp), 5, "denied DNAME-synthesized target refuses");
    assert!(!gate.allowlist.is_allowed(
        &IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)),
        mcp_writ::policy::EgressProto::Tcp,
        443
    ));
    let lines = stop_gate(gate).await;
    let denied = details_for(&lines, "sandbox.network_denied");
    assert!(
        denied
            .iter()
            .any(|d| d.contains("decision=deny-host")
                && d.contains("chain-target=www.denied.example")),
        "denial must name the synthesized target: {denied:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn overlong_alias_chain_is_servfail() {
    // A chain outrunning the depth cap cannot be fully judged —
    // fail closed rather than relay an incompletely seen answer.
    let mut answers = Vec::new();
    let mut prev = "allowed.example".to_string();
    for i in 0..18 {
        let next = format!("hop{i}.allowed.example");
        answers.push(Answ::Cname {
            owner: prev.clone(),
            target: next.clone(),
            ttl: 60,
        });
        prev = next;
    }
    answers.push(Answ::A {
        owner: prev,
        ip: Ipv4Addr::new(203, 0, 113, 50),
        ttl: 60,
    });
    let mut table = HashMap::new();
    table.insert(
        "allowed.example".to_string(),
        MockAnswer {
            rcode: 0,
            tc_on_udp: false,
            answers,
            silent: false,
            corrupt_id: false,
        },
    );
    let Some(gate) = start_gate(
        policy_with(outbound(
            &["allowed.example", "*.allowed.example"],
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

    let resp = udp_query(gate.listen, &dns_query(1, "allowed.example", 1))
        .await
        .expect("servfail");
    assert_eq!(rcode(&resp), 2, "overlong chain → SERVFAIL");
    assert!(!gate.allowlist.is_allowed(
        &IpAddr::V4(Ipv4Addr::new(203, 0, 113, 50)),
        mcp_writ::policy::EgressProto::Tcp,
        443
    ));
    let lines = stop_gate(gate).await;
    let denied = details_for(&lines, "sandbox.network_denied");
    assert!(
        denied
            .iter()
            .any(|d| d.contains("decision=chain-truncated")),
        "truncated chain must be audited: {denied:?}"
    );
}
