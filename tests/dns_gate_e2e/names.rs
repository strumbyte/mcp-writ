//! Name-layer policy evaluation: deny precedence over allow,
//! wildcard scope, NXDOMAIN refusal, IDNA/trailing-dot
//! normalization, and the deny-all vs open postures of the allow
//! list.

use std::collections::HashMap;
use std::net::Ipv4Addr;

use mcp_writ::dnsgate::Refusal;

use crate::common;
use crate::support::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn denied_name_is_refused_and_audited() {
    let mut table = HashMap::new();
    table.insert(
        "allowed.example".to_string(),
        MockAnswer {
            rcode: 0,
            tc_on_udp: false,
            answers: vec![Answ::A {
                owner: "allowed.example".into(),
                ip: Ipv4Addr::new(93, 184, 216, 34),
                ttl: 60,
            }],
            silent: false,
            corrupt_id: false,
        },
    );
    let Some(gate) = start_gate(
        policy_with(outbound(&["allowed.example"], &[], &[], &[], true)),
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

    // Denied: not on the allow list under deny-all-others → REFUSED,
    // and upstream is never contacted (mock would answer NXDOMAIN for
    // an unknown name, but a refusal must not even forward).
    let resp = udp_query(gate.listen, &dns_query(1, "denied.example", 1))
        .await
        .expect("refusal answer");
    assert_eq!(rcode(&resp), 5, "denied name must be REFUSED");
    assert_eq!(resp[0..2], 1u16.to_be_bytes(), "same query id echoed");

    // Allowed: relays the upstream A record.
    let resp = udp_query(gate.listen, &dns_query(2, "allowed.example", 1))
        .await
        .expect("upstream answer");
    assert_eq!(rcode(&resp), 0);
    assert_eq!(
        answer_a_records(&resp),
        vec![Ipv4Addr::new(93, 184, 216, 34)]
    );

    let lines = stop_gate(gate).await;
    // The startup probe also earns a `protocol-error` denial record —
    // match on the queried name rather than the raw record count.
    let denied = details_for(&lines, "sandbox.network_denied");
    let denied: Vec<&String> = denied
        .iter()
        .filter(|d| d.contains("name=denied.example"))
        .collect();
    assert_eq!(denied.len(), 1, "one denial record: {denied:?}");
    let d = denied[0];
    assert!(d.contains("layer=name"), "{d}");
    assert!(d.contains("name=denied.example"), "{d}");
    assert!(d.contains("qtype=A"), "{d}");
    assert!(d.contains("decision=not-allowed"), "{d}");
    assert!(d.contains("session_id="), "{d}");

    let resolved = details_for(&lines, "sandbox.network_resolved");
    assert_eq!(resolved.len(), 1, "one resolution record: {resolved:?}");
    let r = &resolved[0];
    assert!(r.contains("name=allowed.example"), "{r}");
    assert!(r.contains("addrs=[93.184.216.34]"), "{r}");
    assert!(r.contains("ttl_min=60"), "{r}");
    assert!(r.contains("session_id="), "{r}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn deny_host_rule_wins_over_allow() {
    // deny wins even when an allow also covers the name — the same
    // precedence the Auditor applies to argument hosts.
    let Some(gate) = start_gate(
        policy_with(outbound(&["*"], &["bad.example"], &[], &[], false)),
        HashMap::new(),
        Refusal::Refused,
        None,
        false,
    )
    .await
    else {
        common::skip_e2e_test("no write-restricted audit root");
        return;
    };

    let resp = udp_query(gate.listen, &dns_query(1, "bad.example", 1))
        .await
        .unwrap();
    assert_eq!(rcode(&resp), 5);
    let lines = stop_gate(gate).await;
    let denied = details_for(&lines, "sandbox.network_denied");
    assert!(denied.iter().any(|d| d.contains("name=bad.example")
        && d.contains("decision=deny-host")
        && d.contains("rule=bad.example")));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wildcard_covers_subdomain_not_bare() {
    //  covers sub.example.com but NOT bare example.com —
    // the same wildcard semantics as the Auditor.
    let mut table = HashMap::new();
    table.insert(
        "sub.example.com".to_string(),
        MockAnswer {
            rcode: 0,
            tc_on_udp: false,
            answers: vec![Answ::A {
                owner: "sub.example.com".into(),
                ip: Ipv4Addr::new(192, 0, 2, 10),
                ttl: 30,
            }],
            silent: false,
            corrupt_id: false,
        },
    );
    let Some(gate) = start_gate(
        policy_with(outbound(&["*.example.com"], &[], &[], &[], true)),
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

    let resp = udp_query(gate.listen, &dns_query(1, "sub.example.com", 1))
        .await
        .unwrap();
    assert_eq!(rcode(&resp), 0);
    let resp = udp_query(gate.listen, &dns_query(2, "example.com", 1))
        .await
        .unwrap();
    assert_eq!(rcode(&resp), 5, "bare domain must not match wildcard");
    let resp = udp_query(gate.listen, &dns_query(3, "evilexample.com", 1))
        .await
        .unwrap();
    assert_eq!(rcode(&resp), 5, "suffix lookalike must not match");
    stop_gate(gate).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn nxdomain_refusal_rcode() {
    let Some(gate) = start_gate(
        policy_with(outbound(&["allowed.example"], &[], &[], &[], true)),
        HashMap::new(),
        Refusal::Nxdomain,
        None,
        false,
    )
    .await
    else {
        common::skip_e2e_test("no write-restricted audit root");
        return;
    };

    let resp = udp_query(gate.listen, &dns_query(1, "denied.example", 1))
        .await
        .unwrap();
    assert_eq!(rcode(&resp), 3, "configured NXDOMAIN refusal");
    stop_gate(gate).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn idna_and_trailing_dot_normalize() {
    // Full-width spelling and a trailing root dot fold to the same
    // canonical identity — a Unicode variant cannot evade or bypass
    // the rule either way.
    let mut table = HashMap::new();
    table.insert(
        "example.com".to_string(),
        MockAnswer {
            rcode: 0,
            tc_on_udp: false,
            answers: vec![Answ::A {
                owner: "example.com".into(),
                ip: Ipv4Addr::new(93, 184, 216, 34),
                ttl: 300,
            }],
            silent: false,
            corrupt_id: false,
        },
    );
    let Some(gate) = start_gate(
        policy_with(outbound(&["example.com"], &[], &[], &[], true)),
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

    let resp = udp_query(gate.listen, &dns_query(1, "EXAMPLE.com.", 1))
        .await
        .unwrap();
    assert_eq!(rcode(&resp), 0, "case + trailing dot fold to the allow");
    let resp = udp_query(
        gate.listen,
        &dns_query(2, "ｅｘａｍｐｌｅ.com", 1), // full-width letters
    )
    .await
    .unwrap();
    assert_eq!(rcode(&resp), 0, "UTS-46 folds full-width to example.com");
    stop_gate(gate).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn deny_all_empty_allow_list_refuses_all_names() {
    // `deny_all_others` with no allow rules — `deny host="*"` alone, an
    // empty `network` block, or a policy with no `network` block at all
    // (all three load to this shape). The gate is the terminal
    // name-layer enforcement point: the Auditor's empty-allow
    // fall-through relies on the OS sandbox behind it, and there is
    // nothing behind the gate — that carve-out would leave an open
    // resolver.
    let Some(gate) = start_gate(
        policy_with(outbound(&[], &[], &[], &[], true)),
        HashMap::new(),
        Refusal::Refused,
        None,
        false,
    )
    .await
    else {
        common::skip_e2e_test("no write-restricted audit root");
        return;
    };

    let resp = udp_query(gate.listen, &dns_query(1, "anything.example", 1))
        .await
        .expect("deny-all refusal");
    assert_eq!(rcode(&resp), 5, "deny-all + empty allow must refuse");
    let resp = udp_query(gate.listen, &dns_query(2, "192.0.2.1", 1))
        .await
        .expect("deny-all refusal");
    assert_eq!(rcode(&resp), 5, "IP literal under deny-all must refuse");
    let lines = stop_gate(gate).await;
    let denied = details_for(&lines, "sandbox.network_denied");
    assert!(
        denied
            .iter()
            .any(|d| d.contains("name=anything.example") && d.contains("decision=not-allowed")),
        "deny-all-empty must audit not-allowed: {denied:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn open_posture_resolves_unlisted_names() {
    // `allow host="*"` (deny_all_others = false) is the only open
    // posture — names with no covering rule still forward upstream.
    let mut table = HashMap::new();
    table.insert(
        "free.example".to_string(),
        MockAnswer {
            rcode: 0,
            tc_on_udp: false,
            answers: vec![Answ::A {
                owner: "free.example".into(),
                ip: Ipv4Addr::new(192, 0, 2, 55),
                ttl: 60,
            }],
            silent: false,
            corrupt_id: false,
        },
    );
    let Some(gate) = start_gate(
        policy_with(outbound(&[], &[], &[], &[], false)),
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

    let resp = udp_query(gate.listen, &dns_query(1, "free.example", 1))
        .await
        .expect("open-posture answer");
    assert_eq!(rcode(&resp), 0, "open posture forwards unlisted names");
    assert_eq!(answer_a_records(&resp), vec![Ipv4Addr::new(192, 0, 2, 55)]);
    stop_gate(gate).await;
}
