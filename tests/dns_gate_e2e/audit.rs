//! Gate observability: fail-closed refusal when the audit sink is
//! unavailable and the dynamic allow-list snapshot export.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::time::Duration;

use tokio::time::timeout;

use mcp_writ::dnsgate::Refusal;

use crate::common;
use crate::support::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn fail_closed_audit_unavailable_refuses_allowed() {
    // With fail_closed audit, a dead writer turns an *allowed* query
    // into SERVFAIL — resolution must not proceed unaudited.
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
        true, // fail_closed
    )
    .await
    else {
        common::skip_e2e_test("no write-restricted audit root");
        return;
    };

    // Kill the sink: shutting the logger down makes the channel
    // unavailable; the next allowed query must fail closed.
    let _ = gate.logger.shutdown().await;
    let resp = udp_query(gate.listen, &dns_query(1, "allowed.example", 1))
        .await
        .expect("servfail on dead audit sink");
    assert_eq!(
        rcode(&resp),
        2,
        "audit-unavailable → SERVFAIL, never resolve unaudited"
    );
    // No grant may survive a refused resolution — the allow list stays
    // empty of authority the unaudited answer would have vended.
    assert_eq!(
        gate.allowlist.live_len(),
        0,
        "audit failure must retain no grant"
    );
    // Denied queries still refuse — the denial does not depend on the
    // sink — but the failed commit latches `writer_failed`, and a
    // fail-closed gate exits rather than keep serving unaudited.
    let resp = udp_query(gate.listen, &dns_query(2, "denied.example", 1))
        .await
        .expect("refusal on dead audit sink");
    assert_eq!(rcode(&resp), 5);
    let res = timeout(TEST_TIMEOUT, gate.task)
        .await
        .expect("gate must exit once the fail-closed sink is dead");
    assert!(
        matches!(res, Ok(Err(_))),
        "audit loss must end the gate with an error, got: {res:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn allowlist_export_writes_snapshot() {
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
    let tmp = tempfile::tempdir().unwrap();
    let export_path = tmp.path().join("allowlist.json");
    let Some(gate) = start_gate(
        policy_with(outbound(&["allowed.example"], &[], &[], &[], true)),
        table,
        Refusal::Refused,
        Some(export_path.clone()),
        false,
    )
    .await
    else {
        common::skip_e2e_test("no write-restricted audit root");
        return;
    };

    let resp = udp_query(gate.listen, &dns_query(1, "allowed.example", 1))
        .await
        .unwrap();
    assert_eq!(rcode(&resp), 0);
    // The export lands after the registration batch — poll until the
    // snapshot parses and carries at least one entry; a mid-write or
    // absent file is "not ready", not a failure.
    let mut snapshot = String::new();
    for _ in 0..50 {
        if let Ok(text) = std::fs::read_to_string(&export_path) {
            snapshot = text;
            let ready = nojson::RawJson::parse(&snapshot)
                .map(|json| {
                    json.value()
                        .to_member("entries")
                        .ok()
                        .and_then(|m| m.optional())
                        .and_then(|v| v.to_array().ok())
                        .is_some_and(|mut a| a.next().is_some())
                })
                .unwrap_or(false);
            if ready {
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let json = nojson::RawJson::parse(&snapshot).expect("export is valid JSON");
    let entries: Vec<_> = json
        .value()
        .to_member("entries")
        .unwrap()
        .required()
        .unwrap()
        .to_array()
        .unwrap()
        .collect();
    assert_eq!(entries.len(), 1);
    assert_eq!(
        entries[0]
            .to_member("name")
            .unwrap()
            .required()
            .unwrap()
            .to_unquoted_string_str()
            .unwrap(),
        "allowed.example"
    );
    assert_eq!(
        entries[0]
            .to_member("addr")
            .unwrap()
            .required()
            .unwrap()
            .to_unquoted_string_str()
            .unwrap(),
        "93.184.216.34"
    );
    stop_gate(gate).await;
}
