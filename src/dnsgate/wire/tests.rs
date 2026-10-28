use super::response::{MAX_CHAIN_DEPTH, SVC_PARAM_IPV4HINT, SVC_PARAM_IPV6HINT};
use super::*;

fn name_wire(name: &str) -> Vec<u8> {
    let mut out = Vec::new();
    for label in name.split('.') {
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    out
}

fn query(id: u16, name: &str, qtype: u16) -> Vec<u8> {
    let mut pkt = Vec::new();
    pkt.extend_from_slice(&id.to_be_bytes());
    pkt.extend_from_slice(&0x0100u16.to_be_bytes()); // RD
    pkt.extend_from_slice(&1u16.to_be_bytes()); // qd
    pkt.extend_from_slice(&0u16.to_be_bytes());
    pkt.extend_from_slice(&0u16.to_be_bytes());
    pkt.extend_from_slice(&0u16.to_be_bytes());
    pkt.extend_from_slice(&name_wire(name));
    pkt.extend_from_slice(&qtype.to_be_bytes());
    pkt.extend_from_slice(&1u16.to_be_bytes());
    pkt
}

#[test]
fn parse_basic_query() {
    let pkt = query(0x1234, "www.example.com", 1);
    let q = parse_query(&pkt).unwrap();
    assert_eq!(q.id, 0x1234);
    assert_eq!(q.qname, "www.example.com");
    assert_eq!(q.qtype, 1);
    assert_eq!(q.qclass, 1);
    assert_eq!(q.additional_start, pkt.len());
    assert_eq!(q.edns_udp_size, None);
}

#[test]
fn reject_malformed() {
    assert!(matches!(
        parse_query(&[0u8; 5]),
        Err(QueryError {
            reject: QueryReject::Drop,
            ..
        })
    ));
    // QR set — a response, not a query.
    let mut pkt = query(1, "a.example", 1);
    pkt[2] |= 0x80;
    assert!(matches!(
        parse_query(&pkt),
        Err(QueryError {
            reject: QueryReject::FormErr,
            ..
        })
    ));
    // Opcode nonzero → NOTIMP.
    let mut pkt = query(1, "a.example", 1);
    pkt[2] |= 0x10; // opcode 2
    assert!(matches!(
        parse_query(&pkt),
        Err(QueryError {
            reject: QueryReject::NotImp,
            ..
        })
    ));
    // qdcount 0.
    let mut pkt = query(1, "a.example", 1);
    pkt[5] = 0;
    assert!(matches!(
        parse_query(&pkt),
        Err(QueryError {
            reject: QueryReject::FormErr,
            ..
        })
    ));
}

#[test]
fn forward_reencodes_canonical_name() {
    let pkt = query(0xABCD, "EXAMPLE.com", 28);
    let q = parse_query(&pkt).unwrap();
    let fwd = build_forward_query(&pkt, &q, "example.com").unwrap();
    let fq = parse_query(&fwd).unwrap();
    assert_eq!(fq.id, 0xABCD);
    assert_eq!(fq.qname, "example.com");
    assert_eq!(fq.qtype, 28);
    assert_eq!(fq.flags_relay, 0x0100);
}

#[test]
fn refusal_echoes_question_and_rcode() {
    let pkt = query(7, "denied.example", 1);
    let q = parse_query(&pkt).unwrap();
    let resp = refusal_answer(&pkt, Some(&q), RCODE_REFUSED).unwrap();
    assert_eq!(u16::from_be_bytes([resp[0], resp[1]]), 7);
    assert_eq!(resp[2] & 0x80, 0x80); // QR
    assert_eq!(resp[2] & 0x01, 0x01); // RD echoed
    assert_eq!(resp[3], 0x80 | RCODE_REFUSED); // RA + REFUSED
    assert_eq!(u16::from_be_bytes([resp[6], resp[7]]), 0); // ancount
    // Response packet: verify the question echo by decoding directly.
    let (name, _) = decode_name(&resp, HEADER_LEN, false).unwrap();
    assert_eq!(name, "denied.example");
}

#[test]
fn truncated_answer_sets_tc() {
    let pkt = query(9, "big.example", 16);
    let q = parse_query(&pkt).unwrap();
    let resp = truncated_answer(&pkt, &q);
    assert_eq!(resp[2] & 0x82, 0x82); // QR + TC
}

#[test]
fn response_parse_chain_and_addrs() {
    // header + question + CNAME(www→cdn, ttl 300) + CNAME(cdn→edge, ttl 60)
    // + A(edge 93.184.216.34, ttl 120) + stray A(other, ttl 5)
    let mut pkt = Vec::new();
    pkt.extend_from_slice(&0x1u16.to_be_bytes());
    pkt.extend_from_slice(&0x8180u16.to_be_bytes());
    pkt.extend_from_slice(&1u16.to_be_bytes());
    pkt.extend_from_slice(&4u16.to_be_bytes());
    pkt.extend_from_slice(&0u16.to_be_bytes());
    pkt.extend_from_slice(&0u16.to_be_bytes());
    pkt.extend_from_slice(&name_wire("www.example.com"));
    pkt.extend_from_slice(&1u16.to_be_bytes());
    pkt.extend_from_slice(&1u16.to_be_bytes());
    // RR helper: name ptr → 0xC00C, type, class IN, ttl, rdlen, rdata
    let mut rr = |rtype: u16, ttl: u32, rdata: &[u8]| {
        pkt.extend_from_slice(&[0xC0, 0x0C]);
        pkt.extend_from_slice(&rtype.to_be_bytes());
        pkt.extend_from_slice(&1u16.to_be_bytes());
        pkt.extend_from_slice(&ttl.to_be_bytes());
        pkt.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        pkt.extend_from_slice(rdata);
    };
    // CNAME www.example.com → cdn.example.net (inline name)
    rr(5, 300, &name_wire("cdn.example.net"));
    // CNAME — owner needs a pointer to cdn.example.net… use a full
    // name instead (owner "cdn.example.net" uncompressed).
    let owner = name_wire("cdn.example.net");
    pkt.extend_from_slice(&owner);
    pkt.extend_from_slice(&5u16.to_be_bytes());
    pkt.extend_from_slice(&1u16.to_be_bytes());
    pkt.extend_from_slice(&60u32.to_be_bytes());
    let tgt = name_wire("edge.example.net");
    pkt.extend_from_slice(&(tgt.len() as u16).to_be_bytes());
    pkt.extend_from_slice(&tgt);
    // A edge.example.net → 93.184.216.34 ttl 120
    let owner = name_wire("edge.example.net");
    pkt.extend_from_slice(&owner);
    pkt.extend_from_slice(&1u16.to_be_bytes());
    pkt.extend_from_slice(&1u16.to_be_bytes());
    pkt.extend_from_slice(&120u32.to_be_bytes());
    pkt.extend_from_slice(&4u16.to_be_bytes());
    pkt.extend_from_slice(&[93, 184, 216, 34]);
    // A unrelated.example.org → 10.0.0.1 ttl 5 — off-chain, ignored
    let owner = name_wire("unrelated.example.org");
    pkt.extend_from_slice(&owner);
    pkt.extend_from_slice(&1u16.to_be_bytes());
    pkt.extend_from_slice(&1u16.to_be_bytes());
    pkt.extend_from_slice(&5u32.to_be_bytes());
    pkt.extend_from_slice(&4u16.to_be_bytes());
    pkt.extend_from_slice(&[10, 0, 0, 1]);

    let parsed = parse_response(&pkt, "www.example.com");
    assert_eq!(parsed.rcode, 0);
    assert_eq!(parsed.chain, vec!["cdn.example.net", "edge.example.net"]);
    assert!(!parsed.chain_truncated);
    assert_eq!(parsed.addrs, vec![("93.184.216.34".parse().unwrap(), 120)]);
    assert_eq!(parsed.min_ttl, Some(60));
    assert!(parsed.decoded);
}

/// Build a response packet: `q` is the question name, `rrs` the
/// answer-section records as `(owner, rtype, ttl, rdata)`.
fn response(q: &str, rcode: u8, rrs: &[(&str, u16, u32, &[u8])]) -> Vec<u8> {
    let mut pkt = Vec::new();
    pkt.extend_from_slice(&0x1u16.to_be_bytes());
    pkt.extend_from_slice(&(0x8000u16 | 0x0180 | rcode as u16).to_be_bytes());
    pkt.extend_from_slice(&1u16.to_be_bytes());
    pkt.extend_from_slice(&(rrs.len() as u16).to_be_bytes());
    pkt.extend_from_slice(&0u16.to_be_bytes());
    pkt.extend_from_slice(&0u16.to_be_bytes());
    pkt.extend_from_slice(&name_wire(q));
    pkt.extend_from_slice(&1u16.to_be_bytes());
    pkt.extend_from_slice(&1u16.to_be_bytes());
    for (owner, rtype, ttl, rdata) in rrs {
        pkt.extend_from_slice(&name_wire(owner));
        pkt.extend_from_slice(&rtype.to_be_bytes());
        pkt.extend_from_slice(&1u16.to_be_bytes());
        pkt.extend_from_slice(&ttl.to_be_bytes());
        pkt.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        pkt.extend_from_slice(rdata);
    }
    pkt
}

#[test]
fn response_parse_dname_synthesizes_chain() {
    // question www.a.example + DNAME a.example → b.example
    // + A(www.b.example 203.0.113.9): the DNAME rewrites the
    // subtree, and the synthesized name is what the chain records.
    let a_rdata = [203, 0, 113, 9];
    let pkt = response(
        "www.a.example",
        0,
        &[
            ("a.example", RRTYPE_DNAME, 100, &name_wire("b.example")),
            ("www.b.example", 1, 50, &a_rdata),
        ],
    );
    let parsed = parse_response(&pkt, "www.a.example");
    assert!(parsed.decoded);
    assert_eq!(parsed.chain, vec!["www.b.example"]);
    assert!(!parsed.chain_truncated);
    assert_eq!(parsed.addrs, vec![("203.0.113.9".parse().unwrap(), 50)]);
    assert_eq!(parsed.min_ttl, Some(50));
}

#[test]
fn response_parse_dname_then_cname() {
    // www.a.example --DNAME a.example→b.example--> www.b.example
    // --CNAME--> edge.b.example -> A
    let a_rdata = [203, 0, 113, 7];
    let pkt = response(
        "www.a.example",
        0,
        &[
            ("a.example", RRTYPE_DNAME, 90, &name_wire("b.example")),
            (
                "www.b.example",
                RRTYPE_CNAME,
                80,
                &name_wire("edge.b.example"),
            ),
            ("edge.b.example", 1, 70, &a_rdata),
        ],
    );
    let parsed = parse_response(&pkt, "www.a.example");
    assert_eq!(parsed.chain, vec!["www.b.example", "edge.b.example"]);
    assert_eq!(parsed.min_ttl, Some(70));
    assert_eq!(parsed.addrs, vec![("203.0.113.7".parse().unwrap(), 70)]);
    assert!(!parsed.chain_truncated);
}

#[test]
fn response_parse_dname_owner_itself_not_rewritten() {
    // A DNAME at the queried name does not rewrite the owner —
    // only proper descendants (RFC 6672).
    let pkt = response(
        "a.example",
        0,
        &[("a.example", RRTYPE_DNAME, 90, &name_wire("b.example"))],
    );
    let parsed = parse_response(&pkt, "a.example");
    assert!(parsed.chain.is_empty(), "owner is not a descendant");
    assert!(!parsed.chain_truncated);
}

#[test]
fn response_parse_dname_longest_suffix_wins() {
    // Two DNAMEs cover the head — the longer (closer) owner applies.
    let a_rdata = [203, 0, 113, 11];
    let pkt = response(
        "www.deep.a.example",
        0,
        &[
            ("a.example", RRTYPE_DNAME, 90, &name_wire("outer.example")),
            (
                "deep.a.example",
                RRTYPE_DNAME,
                80,
                &name_wire("inner.example"),
            ),
            ("www.inner.example", 1, 60, &a_rdata),
        ],
    );
    let parsed = parse_response(&pkt, "www.deep.a.example");
    assert_eq!(parsed.chain, vec!["www.inner.example"]);
    assert_eq!(parsed.min_ttl, Some(60));
    assert_eq!(parsed.addrs, vec![("203.0.113.11".parse().unwrap(), 60)]);
}

#[test]
fn response_parse_alias_loop_stops() {
    // a→b→a loop: the chain records what was seen and stops.
    let pkt = response(
        "a.example",
        0,
        &[
            ("a.example", RRTYPE_CNAME, 60, &name_wire("b.example")),
            ("b.example", RRTYPE_CNAME, 60, &name_wire("a.example")),
        ],
    );
    let parsed = parse_response(&pkt, "a.example");
    assert_eq!(parsed.chain, vec!["b.example", "a.example"]);
    assert!(!parsed.chain_truncated);
}

#[test]
fn response_parse_chain_depth_cap_marks_truncated() {
    // The loop creates 18 chained CNAME records — outrunning
    // MAX_CHAIN_DEPTH — so the walk marks truncation and the caller
    // can refuse rather than minting on an incompletely judged chain.
    let mut rrs: Vec<(String, u16, u32, Vec<u8>)> = Vec::new();
    for i in 0..=17usize {
        let (owner, target) = if i == 0 {
            ("q.example".to_string(), "n0.example".to_string())
        } else {
            (format!("n{}.example", i - 1), format!("n{i}.example"))
        };
        rrs.push((owner, RRTYPE_CNAME, 60, name_wire(&target)));
    }
    let rr_refs: Vec<(&str, u16, u32, &[u8])> = rrs
        .iter()
        .map(|(o, t, ttl, r)| (o.as_str(), *t, *ttl, r.as_slice()))
        .collect();
    let pkt = response("q.example", 0, &rr_refs);
    let parsed = parse_response(&pkt, "q.example");
    assert!(parsed.chain_truncated);
    assert_eq!(parsed.chain.len(), MAX_CHAIN_DEPTH);
}

/// SVCB/HTTPS wire helpers: RDATA = SvcPriority + TargetName +
/// SvcParams (`key u16 | len u16 | value`).
fn svcb_rdata(priority: u16, target: &str, params: &[(u16, &[u8])]) -> Vec<u8> {
    let mut rdata = Vec::new();
    rdata.extend_from_slice(&priority.to_be_bytes());
    if target.is_empty() {
        // The root TargetName ("." on the wire) is a single zero
        // byte — name_wire("") would emit it twice.
        rdata.push(0);
    } else {
        rdata.extend_from_slice(&name_wire(target));
    }
    for (key, value) in params {
        rdata.extend_from_slice(&key.to_be_bytes());
        rdata.extend_from_slice(&(value.len() as u16).to_be_bytes());
        rdata.extend_from_slice(value);
    }
    rdata
}

#[test]
fn response_parse_https_service_target_and_hints() {
    // HTTPS q → ServiceMode HTTPS(prio 1, target svc.example.net,
    // ipv4hint 93.184.216.34, ipv6hint) + A(svc.example.net).
    // The target name must join the chain for policy re-judgment
    // and the hinted addresses must surface as destinations.
    let hint4 = [93u8, 184, 216, 34];
    let hint6: [u8; 16] = [
        0x26, 0x06, 0x28, 0x00, 0x00, 0x20, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 0, 1,
    ];
    let a_rdata = [203u8, 0, 113, 5];
    let https = svcb_rdata(
        1,
        "svc.example.net",
        &[(SVC_PARAM_IPV4HINT, &hint4), (SVC_PARAM_IPV6HINT, &hint6)],
    );
    let pkt = response(
        "web.example",
        0,
        &[
            ("web.example", RRTYPE_HTTPS, 60, &https),
            ("svc.example.net", 1, 50, &a_rdata),
        ],
    );
    let parsed = parse_response(&pkt, "web.example");
    assert!(parsed.decoded);
    assert_eq!(parsed.chain, vec!["svc.example.net"]);
    assert!(!parsed.chain_truncated);
    let got: Vec<std::net::IpAddr> = parsed.addrs.iter().map(|(a, _)| *a).collect();
    assert!(got.contains(&"93.184.216.34".parse().unwrap()));
    assert!(got.contains(&"2606:2800:20:1::1".parse().unwrap()));
    assert!(got.contains(&"203.0.113.5".parse().unwrap()));
    assert_eq!(parsed.min_ttl, Some(50));
}

#[test]
fn response_parse_svcb_alias_mode_redirects_chain() {
    // AliasMode (priority 0) SVCB acts like a CNAME hop: the
    // target joins the chain and is itself expanded.
    let alias = svcb_rdata(0, "alias.example.net", &[]);
    let svc = svcb_rdata(1, "svc.example.net", &[]);
    let pkt = response(
        "www.example",
        0,
        &[
            ("www.example", RRTYPE_SVCB, 80, &alias),
            ("alias.example.net", RRTYPE_SVCB, 70, &svc),
        ],
    );
    let parsed = parse_response(&pkt, "www.example");
    assert!(parsed.decoded);
    assert_eq!(parsed.chain, vec!["alias.example.net", "svc.example.net"]);
    assert_eq!(parsed.min_ttl, Some(70));
}

#[test]
fn response_parse_https_malformed_rdata_fails_closed() {
    // A truncated SvcParam list — the record could hide hints the
    // walk never saw, so the answer is undecoded, not partially
    // trusted.
    let mut bad = svcb_rdata(1, "svc.example.net", &[]);
    bad.extend_from_slice(&[0, 4, 0, 10, 1, 2]); // key=4 len=10, 2 bytes only
    let pkt = response("web.example", 0, &[("web.example", RRTYPE_HTTPS, 60, &bad)]);
    let parsed = parse_response(&pkt, "web.example");
    assert!(!parsed.decoded);
}

#[test]
fn response_parse_https_root_target_not_a_hop() {
    // ServiceMode TargetName "." means the service lives at the
    // owner name — no new destination is revealed.
    let svc = svcb_rdata(1, "", &[]);
    let pkt = response("web.example", 0, &[("web.example", RRTYPE_HTTPS, 60, &svc)]);
    let parsed = parse_response(&pkt, "web.example");
    assert!(parsed.decoded);
    assert!(parsed.chain.is_empty());
}

#[test]
fn response_parse_svcb_off_chain_owner_ignored() {
    // An HTTPS record for an unrelated owner reveals no
    // destination for this query — same rule as stray A records.
    let svc = svcb_rdata(1, "evil.example", &[]);
    let pkt = response(
        "web.example",
        0,
        &[("unrelated.example", RRTYPE_HTTPS, 60, &svc)],
    );
    let parsed = parse_response(&pkt, "web.example");
    assert!(parsed.decoded);
    assert!(parsed.chain.is_empty());
}

#[test]
fn response_matches_checks_id_and_name() {
    let mut resp = Vec::new();
    resp.extend_from_slice(&0x42u16.to_be_bytes());
    resp.extend_from_slice(&0x8180u16.to_be_bytes());
    resp.extend_from_slice(&1u16.to_be_bytes());
    resp.extend_from_slice(&0u16.to_be_bytes());
    resp.extend_from_slice(&0u16.to_be_bytes());
    resp.extend_from_slice(&0u16.to_be_bytes());
    resp.extend_from_slice(&name_wire("WWW.Example.COM")); // 0x20 randomization
    resp.extend_from_slice(&1u16.to_be_bytes());
    resp.extend_from_slice(&1u16.to_be_bytes());
    assert!(response_matches(&resp, 0x42, "www.example.com"));
    assert!(!response_matches(&resp, 0x43, "www.example.com"));
    assert!(!response_matches(&resp, 0x42, "other.example.com"));
}
