//! Transport handling: TCP round-trip, UDP truncation retry over
//! TCP, upstream timeout and mismatched-answer SERVFAILs, malformed
//! queries, and TCP connection capacity.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::timeout;

use mcp_writ::dnsgate::Refusal;

use crate::common;
use crate::support::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tcp_transport_round_trip() {
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

    let resp = tcp_query(gate.listen, &dns_query(1, "allowed.example", 1))
        .await
        .expect("tcp answer");
    assert_eq!(rcode(&resp), 0);
    assert_eq!(
        answer_a_records(&resp),
        vec![Ipv4Addr::new(93, 184, 216, 34)]
    );
    let resp = tcp_query(gate.listen, &dns_query(2, "denied.example", 1))
        .await
        .expect("tcp refusal");
    assert_eq!(rcode(&resp), 5);
    stop_gate(gate).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tc_answer_retries_over_tcp() {
    // The upstream answers UDP with TC — the gate performs the retry
    // itself so a UDP-only client still gets the full answer.
    let mut table = HashMap::new();
    table.insert(
        "big.allowed.example".to_string(),
        MockAnswer {
            rcode: 0,
            tc_on_udp: true,
            answers: vec![Answ::A {
                owner: "big.allowed.example".into(),
                ip: Ipv4Addr::new(192, 0, 2, 99),
                ttl: 10,
            }],
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

    let resp = udp_query(gate.listen, &dns_query(1, "big.allowed.example", 1))
        .await
        .expect("full answer after TCP retry");
    assert_eq!(resp[2] & 0x02, 0, "relay answer is not truncated");
    assert_eq!(answer_a_records(&resp), vec![Ipv4Addr::new(192, 0, 2, 99)]);
    stop_gate(gate).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn upstream_timeout_is_servfail() {
    let mut table = HashMap::new();
    table.insert(
        "slow.allowed.example".to_string(),
        MockAnswer {
            rcode: 0,
            tc_on_udp: false,
            answers: Vec::new(),
            silent: true, // upstream never answers
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

    let resp = udp_query(gate.listen, &dns_query(1, "slow.allowed.example", 1))
        .await
        .expect("servfail");
    assert_eq!(rcode(&resp), 2, "upstream timeout → SERVFAIL");
    let lines = stop_gate(gate).await;
    let resolved = details_for(&lines, "sandbox.network_resolved");
    assert!(
        resolved
            .iter()
            .any(|r| r.contains("result=upstream-timeout")),
        "timeout must be audited: {resolved:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn malformed_query_is_formerr() {
    let Some(gate) = start_gate(
        policy_with(outbound(&["*"], &[], &[], &[], false)),
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

    // Opcode IQUERY (1) — not a standard query → NOTIMP.
    let mut pkt = dns_query(1, "x.example", 1);
    pkt[2] = 0x08 | (pkt[2] & 0x01); // opcode 1, keep RD
    let resp = udp_query(gate.listen, &pkt).await.expect("notimp");
    assert_eq!(rcode(&resp), 4);
    // qdcount 0 → FORMERR.
    let mut pkt = dns_query(2, "x.example", 1);
    pkt[5] = 0;
    let resp = udp_query(gate.listen, &pkt).await.expect("formerr");
    assert_eq!(rcode(&resp), 1);
    // A packet too short to even parse is dropped (no answer).
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    sock.connect(gate.listen).await.unwrap();
    sock.send(&[0u8; 5]).await.unwrap();
    let mut buf = [0u8; 128];
    let res = timeout(Duration::from_millis(500), sock.recv(&mut buf)).await;
    assert!(res.is_err(), "sub-header packet must be dropped");
    stop_gate(gate).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn upstream_mismatch_is_servfail() {
    // An upstream TCP answer that does not echo our query (here a
    // wrong ID) is not ours to relay — SERVFAIL, and the audit record
    // names the mismatch. (Over UDP a mismatched datagram is dropped
    // and the wait continues, so the wire-visible outcome there is the
    // fixed timeout budget, not an immediate mismatch.)
    let mut table = HashMap::new();
    table.insert(
        "mismatch.allowed.example".to_string(),
        MockAnswer {
            rcode: 0,
            tc_on_udp: false,
            answers: vec![Answ::A {
                owner: "mismatch.allowed.example".into(),
                ip: Ipv4Addr::new(192, 0, 2, 77),
                ttl: 60,
            }],
            silent: false,
            corrupt_id: true,
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

    let resp = tcp_query(gate.listen, &dns_query(1, "mismatch.allowed.example", 1))
        .await
        .expect("servfail on mismatched upstream");
    assert_eq!(rcode(&resp), 2, "upstream mismatch → SERVFAIL");
    let lines = stop_gate(gate).await;
    let resolved = details_for(&lines, "sandbox.network_resolved");
    assert!(
        resolved
            .iter()
            .any(|r| r.contains("result=upstream-mismatch")),
        "mismatch must be audited: {resolved:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tcp_connection_capacity_refuses_overflow() {
    // MAX_TCP_CONNECTIONS (64) bounds simultaneous client connections —
    // a connection accepted past capacity is dropped immediately, not
    // served, and the gate itself keeps answering over UDP.
    let Some(gate) = start_gate(
        policy_with(outbound(&["*"], &[], &[], &[], false)),
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

    let mut held = Vec::new();
    for _ in 0..64 {
        held.push(
            TcpStream::connect(gate.listen)
                .await
                .expect("connection within capacity"),
        );
    }
    // Let the accept loop drain the backlog so every held connection
    // actually occupies its slot before the overflow attempt.
    tokio::time::sleep(Duration::from_millis(500)).await;
    let mut extra = TcpStream::connect(gate.listen)
        .await
        .expect("overflow connection still completes the handshake");
    let pkt = dns_query(1, "x.example", 1);
    extra
        .write_all(&(pkt.len() as u16).to_be_bytes())
        .await
        .ok();
    extra.write_all(&pkt).await.ok();
    let mut len_buf = [0u8; 2];
    match timeout(TEST_TIMEOUT, extra.read_exact(&mut len_buf)).await {
        // Dropped by the gate — EOF on unix-y stacks, an abort/reset
        // error on Windows; either way it was not served.
        Ok(Err(e)) => assert!(
            matches!(
                e.kind(),
                std::io::ErrorKind::UnexpectedEof
                    | std::io::ErrorKind::ConnectionAborted
                    | std::io::ErrorKind::ConnectionReset
            ),
            "overflow connection must be dropped, got {e}"
        ),
        Ok(Ok(n)) => panic!("overflow connection must not be served (read {n} bytes)"),
        Err(_) => panic!("overflow connection must close promptly, not hang"),
    }
    // The gate is not wedged — an unrelated UDP query still resolves
    // (empty mock table → upstream NXDOMAIN relayed).
    let resp = udp_query(gate.listen, &dns_query(2, "x.example", 1))
        .await
        .expect("gate still answers over UDP");
    assert_eq!(rcode(&resp), 3, "upstream NXDOMAIN relayed — gate alive");
    drop(held);
    stop_gate(gate).await;
}
