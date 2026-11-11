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
fn response_parse_cname_undecodable_target_fails_closed() {
    // A CNAME whose target name does not decode (a compression pointer
    // past the end of the packet) could hide a destination the walk
    // never judged — the answer is refused as undecoded rather than
    // relayed with the record silently dropped.
    let pkt = response(
        "web.example",
        0,
        &[("web.example", RRTYPE_CNAME, 60, &[0xC0, 0xFF])],
    );
    let parsed = parse_response(&pkt, "web.example");
    assert!(!parsed.decoded);
    assert!(parsed.chain.is_empty());
}

#[test]
fn response_parse_alias_root_target_records_hop() {
    // A one-byte RDATA of `\x00` decodes to the root: an alias to the
    // DNS root is a real destination the walk must record — dropping
    // the hop would leave a substitution invisible to policy
    // re-judgment, the same failure as dropping the record.
    let pkt = response(
        "web.example",
        0,
        &[("web.example", RRTYPE_CNAME, 60, &[0x00])],
    );
    let parsed = parse_response(&pkt, "web.example");
    assert!(parsed.decoded);
    assert_eq!(parsed.chain, ["".to_string()]);

    // Same for a DNAME whose target is the root: `x.evil.example`
    // substitutes its owner suffix with the root — the hop `x` is a
    // different name under a different zone and must be re-judged.
    let pkt = response(
        "x.evil.example",
        0,
        &[("evil.example", RRTYPE_DNAME, 60, &[0x00])],
    );
    let parsed = parse_response(&pkt, "x.evil.example");
    assert!(parsed.decoded);
    assert_eq!(parsed.chain, ["x".to_string()]);
}

#[test]
fn response_parse_cname_short_rdata_fails_closed() {
    // Empty and one-byte RDATA carry no decodable target either — the
    // alias is part of the answer's semantics, so the response fails
    // closed instead of silently dropping the record.
    for rdata in [&[][..], &[0xC0][..]] {
        let pkt = response(
            "web.example",
            0,
            &[("web.example", RRTYPE_CNAME, 60, rdata)],
        );
        let parsed = parse_response(&pkt, "web.example");
        assert!(!parsed.decoded);
        assert!(parsed.chain.is_empty());
    }
}

#[test]
fn response_parse_cname_target_overrunning_rdata_fails_closed() {
    // The RDATA name must end within the record: a target that decodes
    // only by reading into the following record's bytes is malformed,
    // and the answer fails closed instead of collecting whatever the
    // overrun spelled out.
    let a_rdata = [203u8, 0, 113, 5];
    let pkt = response(
        "web.example",
        0,
        &[
            ("web.example", RRTYPE_CNAME, 60, &[1, b'x', 1, b'y']),
            ("edge.example", 1, 50, &a_rdata),
        ],
    );
    let parsed = parse_response(&pkt, "web.example");
    assert!(!parsed.decoded);
    assert!(parsed.chain.is_empty());
}

#[test]
fn response_parse_dname_target_overrunning_rdata_fails_closed() {
    // Same overrun rule for DNAME — the suffix-rewrite target is
    // destination material and a record that reads past its RDATA is
    // not partially trusted.
    let a_rdata = [203u8, 0, 113, 5];
    let pkt = response(
        "www.a.example",
        0,
        &[
            ("a.example", RRTYPE_DNAME, 60, &[1, b'x', 1, b'y']),
            ("edge.example", 1, 50, &a_rdata),
        ],
    );
    let parsed = parse_response(&pkt, "www.a.example");
    assert!(!parsed.decoded);
    assert!(parsed.chain.is_empty());
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
fn response_parse_conflicting_cnames_fail_closed() {
    // Two different CNAME targets under ONE owner is semantically
    // conflicting wire data — a resolver may select either, so the
    // chain can never judge the unchosen one. Refuse the whole
    // answer rather than relay an unjudged destination.
    let pkt = response(
        "www.example",
        0,
        &[
            ("www.example", RRTYPE_CNAME, 60, &name_wire("ok.example")),
            (
                "www.example",
                RRTYPE_CNAME,
                60,
                &name_wire("denied.example"),
            ),
        ],
    );
    assert!(!parse_response(&pkt, "www.example").decoded);
}

#[test]
fn response_parse_conflicting_dnames_fail_closed() {
    // Same conflict on the DNAME family: one owner, two different
    // substitution targets.
    let pkt = response(
        "www.a.example",
        0,
        &[
            ("a.example", RRTYPE_DNAME, 60, &name_wire("b.example")),
            ("a.example", RRTYPE_DNAME, 60, &name_wire("c.example")),
        ],
    );
    assert!(!parse_response(&pkt, "www.a.example").decoded);
}

#[test]
fn response_parse_duplicate_identical_cname_decodes() {
    // Same owner, same target repeated is not a conflict — some
    // upstreams emit duplicates. The chain still follows the one
    // target the owner names.
    let a_rdata = [203, 0, 113, 9];
    let pkt = response(
        "www.example",
        0,
        &[
            ("www.example", RRTYPE_CNAME, 60, &name_wire("cdn.example")),
            ("www.example", RRTYPE_CNAME, 60, &name_wire("cdn.example")),
            ("cdn.example", RRTYPE_A, 50, &a_rdata),
        ],
    );
    let parsed = parse_response(&pkt, "www.example");
    assert!(parsed.decoded);
    assert_eq!(parsed.chain, vec!["cdn.example"]);
    assert_eq!(parsed.addrs, vec![("203.0.113.9".parse().unwrap(), 50)]);
}

#[test]
fn response_parse_stray_answer_alias_joins_deny_set() {
    // A CNAME whose owner is unrelated to this query never joins the
    // chain — but the relay still ships it, so both ends land in the
    // deny-judged extra set instead of passing unobserved.
    let pkt = response(
        "www.example",
        0,
        &[
            ("www.example", RRTYPE_A, 60, &[203, 0, 113, 9]),
            (
                "unrelated.example",
                RRTYPE_CNAME,
                60,
                &name_wire("hidden.example"),
            ),
        ],
    );
    let parsed = parse_response(&pkt, "www.example");
    assert!(parsed.decoded);
    assert!(parsed.chain.is_empty());
    for name in ["unrelated.example", "hidden.example"] {
        assert!(
            parsed.extra_names.contains(&name.to_string()),
            "missing {name}: {:?}",
            parsed.extra_names
        );
    }
}

/// A response carrying records in all three sections — `an`/`ns`/`ar`
/// are `(owner, rtype, ttl, rdata)` lists in wire order.
fn response_sections(
    q: &str,
    an: &[(&str, u16, u32, &[u8])],
    ns: &[(&str, u16, u32, &[u8])],
    ar: &[(&str, u16, u32, &[u8])],
) -> Vec<u8> {
    let mut pkt = Vec::new();
    pkt.extend_from_slice(&0x1u16.to_be_bytes());
    pkt.extend_from_slice(&0x8180u16.to_be_bytes());
    pkt.extend_from_slice(&1u16.to_be_bytes());
    pkt.extend_from_slice(&(an.len() as u16).to_be_bytes());
    pkt.extend_from_slice(&(ns.len() as u16).to_be_bytes());
    pkt.extend_from_slice(&(ar.len() as u16).to_be_bytes());
    pkt.extend_from_slice(&name_wire(q));
    pkt.extend_from_slice(&1u16.to_be_bytes());
    pkt.extend_from_slice(&1u16.to_be_bytes());
    for (owner, rtype, ttl, rdata) in an.iter().chain(ns).chain(ar) {
        if owner.is_empty() {
            // The root owner (OPT pseudo-RR) is one zero byte —
            // name_wire("") would emit the label terminator twice.
            pkt.push(0);
        } else {
            pkt.extend_from_slice(&name_wire(owner));
        }
        pkt.extend_from_slice(&rtype.to_be_bytes());
        pkt.extend_from_slice(&1u16.to_be_bytes());
        pkt.extend_from_slice(&ttl.to_be_bytes());
        pkt.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        pkt.extend_from_slice(rdata);
    }
    pkt
}

/// An EDNS OPT pseudo-RR — root owner, class = UDP payload size.
fn opt_rr() -> (String, u16, u32, Vec<u8>) {
    (String::new(), RRTYPE_OPT, 0, Vec::new())
}

#[test]
fn response_extra_sections_are_collected() {
    // Authority CNAME + additional A reveal destination material
    // the relay would ship — it is collected for the deny check but
    // never joins the chain or the grant minting.
    let a_rdata = [198, 51, 100, 7];
    let pkt = response_sections(
        "www.example",
        &[("www.example", RRTYPE_A, 60, &[203, 0, 113, 9])],
        &[(
            "zone.example",
            RRTYPE_CNAME,
            300,
            &name_wire("ns.other.net"),
        )],
        &[("ns.other.net", RRTYPE_A, 300, &a_rdata)],
    );
    let parsed = parse_response(&pkt, "www.example");
    assert!(parsed.decoded);
    assert!(parsed.chain.is_empty());
    assert_eq!(parsed.addrs, vec![("203.0.113.9".parse().unwrap(), 60)]);
    assert!(parsed.extra_names.contains(&"zone.example".to_string()));
    assert!(parsed.extra_names.contains(&"ns.other.net".to_string()));
    assert_eq!(
        parsed.extra_addrs,
        vec!["198.51.100.7".parse::<std::net::IpAddr>().unwrap()]
    );
}

#[test]
fn response_undecodable_authority_rr_fails_closed() {
    // NSCOUNT claims a record the bytes do not carry — the unseen
    // record could hold an unjudged destination, so the answer is
    // undecoded, not partially trusted.
    let mut pkt = response_sections(
        "www.example",
        &[("www.example", RRTYPE_A, 60, &[203, 0, 113, 9])],
        &[(
            "zone.example",
            RRTYPE_CNAME,
            300,
            &name_wire("ns.other.net"),
        )],
        &[],
    );
    pkt.truncate(pkt.len() - 3); // clip the authority RDATA
    let parsed = parse_response(&pkt, "www.example");
    assert!(!parsed.decoded);
}

#[test]
fn response_trailing_bytes_fail_closed() {
    // Bytes after the last declared record are malformed material —
    // fail closed rather than relay an unexamined tail.
    let mut pkt = response_sections(
        "www.example",
        &[("www.example", RRTYPE_A, 60, &[203, 0, 113, 9])],
        &[],
        &[],
    );
    pkt.extend_from_slice(&[0xAA, 0xBB]);
    let parsed = parse_response(&pkt, "www.example");
    assert!(!parsed.decoded);
}

#[test]
fn response_opt_rules_enforced() {
    let (name, rtype, ttl, rdata) = opt_rr();
    let opt: (&str, u16, u32, &[u8]) = (name.as_str(), rtype, ttl, rdata.as_slice());
    // One OPT in the additional section is the normal EDNS shape.
    let pkt = response_sections("www.example", &[], &[], &[opt]);
    assert!(parse_response(&pkt, "www.example").decoded);
    // A second OPT is a protocol violation — undecoded, not relayed.
    let pkt = response_sections("www.example", &[], &[], &[opt, opt]);
    assert!(!parse_response(&pkt, "www.example").decoded);
    // OPT belongs to the additional section only.
    let pkt = response_sections("www.example", &[], &[opt], &[]);
    assert!(!parse_response(&pkt, "www.example").decoded);
    // A non-root OPT owner is malformed (RFC 6891).
    let bad: (&str, u16, u32, &[u8]) = ("owner.example", RRTYPE_OPT, 0, &[]);
    let pkt = response_sections("www.example", &[], &[], &[bad]);
    assert!(!parse_response(&pkt, "www.example").decoded);
    // An OPT in the answer section is malformed — the pseudo-RR's
    // CLASS field is a UDP payload size, so it would otherwise slip
    // past the IN-class skip and be relayed unjudged.
    let pkt = response_sections("www.example", &[opt], &[], &[]);
    assert!(!parse_response(&pkt, "www.example").decoded);
    // A legitimate additional-section OPT does not rescue it.
    let pkt = response_sections("www.example", &[opt], &[], &[opt]);
    assert!(!parse_response(&pkt, "www.example").decoded);
}

#[test]
fn response_extra_svcb_hints_collected() {
    // An additional-section HTTPS record still reveals a target name
    // and dialable hint addresses — collected for deny judgment.
    let hint4 = [192u8, 0, 2, 44];
    let svc = svcb_rdata(1, "svc.other.net", &[(SVC_PARAM_IPV4HINT, &hint4)]);
    let pkt = response_sections(
        "www.example",
        &[("www.example", RRTYPE_A, 60, &[203, 0, 113, 9])],
        &[],
        &[("cdn.example", RRTYPE_HTTPS, 60, &svc)],
    );
    let parsed = parse_response(&pkt, "www.example");
    assert!(parsed.decoded);
    assert!(parsed.chain.is_empty());
    assert!(parsed.extra_names.contains(&"cdn.example".to_string()));
    assert!(parsed.extra_names.contains(&"svc.other.net".to_string()));
    assert_eq!(
        parsed.extra_addrs,
        vec!["192.0.2.44".parse::<std::net::IpAddr>().unwrap()]
    );
}

#[test]
fn response_bad_cname_in_additional_fails_closed() {
    // A CNAME whose target overruns its RDATA, in the additional
    // section, fails the whole answer — same rule as the answer
    // section. The stray bytes could spell out an unjudged target.
    let pkt = response_sections(
        "www.example",
        &[("www.example", RRTYPE_A, 60, &[203, 0, 113, 9])],
        &[],
        &[("cdn.example", RRTYPE_CNAME, 60, &[1, b'x', 1, b'y'])],
    );
    assert!(!parse_response(&pkt, "www.example").decoded);
}

/// MX RDATA: preference + exchange name.
fn mx_rdata(preference: u16, exchange: &str) -> Vec<u8> {
    let mut r = preference.to_be_bytes().to_vec();
    r.extend_from_slice(&name_wire(exchange));
    r
}

/// SRV RDATA: priority + weight + port + target name.
fn srv_rdata(target: &str) -> Vec<u8> {
    let mut r = vec![0u8; 6];
    r.extend_from_slice(&name_wire(target));
    r
}

/// NAPTR RDATA: order + preference + three char-strings + replacement.
fn naptr_rdata(replacement: &str) -> Vec<u8> {
    let mut r = vec![0u8; 4];
    for s in ["", "s", ""] {
        r.push(s.len() as u8);
        r.extend_from_slice(s.as_bytes());
    }
    r.extend_from_slice(&name_wire(replacement));
    r
}

#[test]
fn response_extra_named_rdata_collected() {
    // Authority NS/MX and additional SRV targets are destination names
    // the relay ships — collected for policy judgment, never chained.
    let pkt = response_sections(
        "www.example",
        &[("www.example", RRTYPE_A, 60, &[203, 0, 113, 9])],
        &[
            ("zone.example", RRTYPE_NS, 300, &name_wire("ns1.hosts.net")),
            (
                "zone.example",
                RRTYPE_MX,
                300,
                &mx_rdata(10, "mail.zone.example"),
            ),
        ],
        &[(
            "svc.zone.example",
            RRTYPE_SRV,
            300,
            &srv_rdata("srv.target.net"),
        )],
    );
    let parsed = parse_response(&pkt, "www.example");
    assert!(parsed.decoded);
    assert!(parsed.chain.is_empty());
    for name in [
        "zone.example",
        "ns1.hosts.net",
        "mail.zone.example",
        "svc.zone.example",
        "srv.target.net",
    ] {
        assert!(
            parsed.extra_names.contains(&name.to_string()),
            "missing {name}: {:?}",
            parsed.extra_names
        );
    }
}

#[test]
fn response_extra_naptr_target_collected() {
    let pkt = response_sections(
        "www.example",
        &[],
        &[],
        &[(
            "sip.example",
            RRTYPE_NAPTR,
            300,
            &naptr_rdata("sip.provider.net"),
        )],
    );
    let parsed = parse_response(&pkt, "www.example");
    assert!(parsed.decoded);
    assert!(parsed.extra_names.contains(&"sip.provider.net".to_string()));
}

#[test]
fn response_extra_named_rdata_malformed_fails_closed() {
    // A truncated MX exchange (pointer past the packet) and an SRV
    // record too short to hold its fixed fields are malformed
    // destination material — undecoded, not relayed unjudged.
    let bad_mx = mx_rdata(10, "mail.zone.example");
    let pkt = response_sections(
        "www.example",
        &[],
        &[("zone.example", RRTYPE_MX, 300, &bad_mx[..3])],
        &[],
    );
    assert!(!parse_response(&pkt, "www.example").decoded);
    let pkt = response_sections(
        "www.example",
        &[],
        &[],
        &[("svc.example", RRTYPE_SRV, 300, &[0u8, 1, 2])],
    );
    assert!(!parse_response(&pkt, "www.example").decoded);
}

#[test]
fn response_answer_named_rdata_collected() {
    // Name-bearing records in the answer itself reveal destinations
    // too — judged like extra-section material, never chained or minted.
    let pkt = response_sections(
        "mail.example",
        &[
            (
                "mail.example",
                RRTYPE_MX,
                60,
                &mx_rdata(10, "mx1.mail.example"),
            ),
            (
                "ptr.example",
                RRTYPE_PTR,
                60,
                &name_wire("host.ptr.example"),
            ),
        ],
        &[],
        &[],
    );
    let parsed = parse_response(&pkt, "mail.example");
    assert!(parsed.decoded);
    assert!(parsed.chain.is_empty());
    assert!(parsed.addrs.is_empty());
    for name in [
        "mail.example",
        "mx1.mail.example",
        "ptr.example",
        "host.ptr.example",
    ] {
        assert!(
            parsed.extra_names.contains(&name.to_string()),
            "missing {name}: {:?}",
            parsed.extra_names
        );
    }
}

/// SOA RDATA: mname + rname + five u32 counters.
fn soa_rdata(mname: &str, rname: &str) -> Vec<u8> {
    let mut r = name_wire(mname);
    r.extend_from_slice(&name_wire(rname));
    r.extend_from_slice(&[0u8; 20]);
    r
}

#[test]
fn response_soa_nsec_are_metadata_not_destinations() {
    // A negative-style answer carries an authority SOA and an NSEC
    // proof record. Their names — mname/rname, the next-name, and the
    // record owners — are zone metadata the workload never dials: the
    // records decode for structural validation but contribute nothing
    // to the judged name set (a deny-all policy must not kill every
    // negative answer over its SOA).
    let nsec_rdata = {
        let mut r = name_wire("next.example");
        r.extend_from_slice(&[0, 2, 0x40, 0x01]); // window 0, len 2
        r.extend_from_slice(&[3, 1, 0x80]); // window 3, len 1 — increasing
        r
    };
    let pkt = response_sections(
        "www.example",
        &[],
        &[
            (
                "example",
                RRTYPE_SOA,
                300,
                &soa_rdata("ns.example", "hostmaster.example"),
            ),
            ("www.example", RRTYPE_NSEC, 300, &nsec_rdata),
        ],
        &[],
    );
    let parsed = parse_response(&pkt, "www.example");
    assert!(parsed.decoded);
    for name in [
        "example",
        "ns.example",
        "hostmaster.example",
        "www.example",
        "next.example",
    ] {
        assert!(
            !parsed.extra_names.contains(&name.to_string()),
            "metadata leaked into extra_names: {name}"
        );
    }
}

#[test]
fn response_metadata_rdata_malformed_fails_closed() {
    // A truncated SOA (missing counters) and an NSEC with an
    // out-of-bounds bitmap block are malformed records — undecoded.
    let pkt = response_sections(
        "www.example",
        &[],
        &[(
            "example",
            RRTYPE_SOA,
            300,
            &soa_rdata("ns.example", "h.example")[..8],
        )],
        &[],
    );
    assert!(!parse_response(&pkt, "www.example").decoded);
    let bad_nsec = {
        let mut r = name_wire("next.example");
        r.extend_from_slice(&[0, 40]); // bitmap length 40 > 32, overruns record
        r
    };
    let pkt = response_sections(
        "www.example",
        &[],
        &[("www.example", RRTYPE_NSEC, 300, &bad_nsec)],
        &[],
    );
    assert!(!parse_response(&pkt, "www.example").decoded);
    // No bitmap blocks at all — RFC 4034 requires at least one.
    let pkt = response_sections(
        "www.example",
        &[],
        &[("www.example", RRTYPE_NSEC, 300, &name_wire("next.example"))],
        &[],
    );
    assert!(!parse_response(&pkt, "www.example").decoded);
    // Window numbers must strictly increase (1 then 0 is out of order).
    let bad_order = {
        let mut r = name_wire("next.example");
        r.extend_from_slice(&[1, 2, 0x40, 0x01]); // window 1
        r.extend_from_slice(&[0, 2, 0x40, 0x01]); // window 0 — regression
        r
    };
    let pkt = response_sections(
        "www.example",
        &[],
        &[("www.example", RRTYPE_NSEC, 300, &bad_order)],
        &[],
    );
    assert!(!parse_response(&pkt, "www.example").decoded);
    // A trailing partial block header is malformed too.
    let partial = {
        let mut r = name_wire("next.example");
        r.extend_from_slice(&[0, 2, 0x40, 0x01]);
        r.push(3); // lone window byte, no length
        r
    };
    let pkt = response_sections(
        "www.example",
        &[],
        &[("www.example", RRTYPE_NSEC, 300, &partial)],
        &[],
    );
    assert!(!parse_response(&pkt, "www.example").decoded);
}

/// IPSECKEY RDATA: precedence + gateway type + algorithm + gateway +
/// opaque public key.
fn ipseckey_rdata(gw_type: u8, gateway: &[u8]) -> Vec<u8> {
    let mut r = vec![10, gw_type, 5];
    r.extend_from_slice(gateway);
    r.extend_from_slice(&[0xDE, 0xAD]); // public key blob
    r
}

#[test]
fn response_extra_ipseckey_gateway_collected() {
    // A name gateway is a destination; an IP gateway is an address.
    let pkt = response_sections(
        "www.example",
        &[],
        &[(
            "key.example",
            RRTYPE_IPSECKEY,
            300,
            &ipseckey_rdata(3, &name_wire("gw.ipsec.net")),
        )],
        &[(
            "key2.example",
            RRTYPE_IPSECKEY,
            300,
            &ipseckey_rdata(1, &[192, 0, 2, 77]),
        )],
    );
    let parsed = parse_response(&pkt, "www.example");
    assert!(parsed.decoded);
    for name in ["key.example", "gw.ipsec.net", "key2.example"] {
        assert!(
            parsed.extra_names.contains(&name.to_string()),
            "missing {name}: {:?}",
            parsed.extra_names
        );
    }
    assert!(
        parsed
            .extra_addrs
            .contains(&"192.0.2.77".parse::<std::net::IpAddr>().unwrap())
    );
    // An unknown gateway type cannot be decoded — fail closed.
    let pkt = response_sections(
        "www.example",
        &[],
        &[(
            "key.example",
            RRTYPE_IPSECKEY,
            300,
            &ipseckey_rdata(9, &name_wire("gw.ipsec.net")),
        )],
        &[],
    );
    assert!(!parse_response(&pkt, "www.example").decoded);
    // A gateway field truncated inside the record — malformed.
    let pkt = response_sections(
        "www.example",
        &[],
        &[("key.example", RRTYPE_IPSECKEY, 300, &[10, 1, 5, 192, 0])],
        &[],
    );
    assert!(!parse_response(&pkt, "www.example").decoded);
}

#[test]
fn response_extra_hip_rendezvous_collected() {
    // HIP carries rendezvous server names after the PK/HIT fields.
    let hip = {
        let mut r = vec![4, 7, 0, 3]; // HIT len 4, algo 7, PK len 3
        r.extend_from_slice(&[0xAA, 0xBB, 0xCC]); // public key
        r.extend_from_slice(&[1, 2, 3, 4]); // HIT
        r.extend_from_slice(&name_wire("rvs1.example"));
        r.extend_from_slice(&name_wire("rvs2.example"));
        r
    };
    let pkt = response_sections(
        "www.example",
        &[],
        &[("hip.example", RRTYPE_HIP, 300, &hip)],
        &[],
    );
    let parsed = parse_response(&pkt, "www.example");
    assert!(parsed.decoded);
    for name in ["hip.example", "rvs1.example", "rvs2.example"] {
        assert!(
            parsed.extra_names.contains(&name.to_string()),
            "missing {name}: {:?}",
            parsed.extra_names
        );
    }
    // PK/HIT fields overrunning the record — malformed.
    let short = vec![200, 7, 0, 3, 0xAA];
    let pkt = response_sections(
        "www.example",
        &[],
        &[("hip.example", RRTYPE_HIP, 300, &short)],
        &[],
    );
    assert!(!parse_response(&pkt, "www.example").decoded);
    // A rendezvous name clipped mid-record — malformed.
    let mut bad = vec![0, 7, 0, 1, 0xAA];
    bad.extend_from_slice(&name_wire("rvs1.example")[..4]);
    let pkt = response_sections(
        "www.example",
        &[],
        &[("hip.example", RRTYPE_HIP, 300, &bad)],
        &[],
    );
    assert!(!parse_response(&pkt, "www.example").decoded);
}

#[test]
fn response_extra_uri_host_collected() {
    // URI's authority host is the connect destination — judged as a
    // name or, for IP literals, an address.
    let uri = |t: &str| -> Vec<u8> {
        let mut r = vec![0, 10, 0, 20]; // priority + weight
        r.extend_from_slice(t.as_bytes());
        r
    };
    let pkt = response_sections(
        "www.example",
        &[],
        &[
            (
                "ftp.example",
                RRTYPE_URI,
                300,
                &uri("https://user@svc.other.net:8443/x?y=1"),
            ),
            (
                "lit.example",
                RRTYPE_URI,
                300,
                &uri("https://[2001:db8::9]/"),
            ),
            ("mail.example", RRTYPE_URI, 300, &uri("mailto:a@b.example")),
        ],
        &[],
    );
    let parsed = parse_response(&pkt, "www.example");
    assert!(parsed.decoded);
    for name in [
        "ftp.example",
        "svc.other.net",
        "lit.example",
        "mail.example",
    ] {
        assert!(
            parsed.extra_names.contains(&name.to_string()),
            "missing {name}: {:?}",
            parsed.extra_names
        );
    }
    assert!(
        parsed
            .extra_addrs
            .contains(&"2001:db8::9".parse::<std::net::IpAddr>().unwrap())
    );
    // No-name URIs carry no judged host.
    assert!(!parsed.extra_names.contains(&"b.example".to_string()));
    // `//`-less schemes that carry the dial target directly — SIP
    // userinfo then host, STUN/TURN host[:port] — are judged too: an
    // IP literal there is dialed without DNS.
    let pkt = response_sections(
        "www.example",
        &[],
        &[
            ("s1.example", RRTYPE_URI, 300, &uri("sip:alice@127.0.0.1")),
            (
                "s2.example",
                RRTYPE_URI,
                300,
                &uri("sips:bob@voip.provider.net"),
            ),
            (
                "t1.example",
                RRTYPE_URI,
                300,
                &uri("turn:203.0.113.9:3478?transport=udp"),
            ),
            ("t2.example", RRTYPE_URI, 300, &uri("stun:stun.public.net")),
            // `maddr` overrides the base host as the dial target —
            // both are judged.
            (
                "s3.example",
                RRTYPE_URI,
                300,
                &uri("sip:alice@allowed.example;maddr=127.0.0.1"),
            ),
            (
                "s4.example",
                RRTYPE_URI,
                300,
                &uri("sip:alice@allowed.example;maddr=[2001:db8::7]"),
            ),
        ],
        &[],
    );
    let parsed = parse_response(&pkt, "www.example");
    assert!(parsed.decoded);
    for name in [
        "s1.example",
        "s2.example",
        "voip.provider.net",
        "t1.example",
        "t2.example",
        "stun.public.net",
        "s3.example",
        "s4.example",
        "allowed.example",
    ] {
        assert!(
            parsed.extra_names.contains(&name.to_string()),
            "missing {name}: {:?}",
            parsed.extra_names
        );
    }
    for addr in ["127.0.0.1", "203.0.113.9", "2001:db8::7"] {
        assert!(
            parsed
                .extra_addrs
                .contains(&addr.parse::<std::net::IpAddr>().unwrap()),
            "missing addr {addr}"
        );
    }
    // A non-UTF-8 target cannot be judged — fail closed.
    let bad = {
        let mut r = vec![0, 10, 0, 20];
        r.extend_from_slice(&[0xFF, 0xFE]);
        r
    };
    let pkt = response_sections(
        "www.example",
        &[],
        &[("u.example", RRTYPE_URI, 300, &bad)],
        &[],
    );
    assert!(!parse_response(&pkt, "www.example").decoded);
}

#[test]
fn response_extra_uri_numeric_ip_forms_judged_as_addrs() {
    // Every WHATWG IPv4 spelling — hex, decimal, octal, short — folds
    // to the canonical address, so the deny rules see the same
    // destination the workload will dial. None may fall through to
    // the name path.
    let uri = |t: &str| -> Vec<u8> {
        let mut r = vec![0, 10, 0, 20];
        r.extend_from_slice(t.as_bytes());
        r
    };
    for spelling in [
        "https://0x7f000001/",
        "https://2130706433/",
        "https://0177.0.0.1/",
        "https://127.1/",
    ] {
        let pkt = response_sections(
            "www.example",
            &[],
            &[("u.example", RRTYPE_URI, 300, &uri(spelling))],
            &[],
        );
        let parsed = parse_response(&pkt, "www.example");
        assert!(parsed.decoded, "{spelling} must decode");
        assert!(
            parsed
                .extra_addrs
                .contains(&"127.0.0.1".parse::<std::net::IpAddr>().unwrap()),
            "{spelling} must surface 127.0.0.1 as an address"
        );
    }
}

#[test]
fn response_extra_uri_unjudgeable_hosts_fail_closed() {
    // Spellings a WHATWG parser could read differently than a strict
    // authority split — backslashes redrawing the authority boundary,
    // an empty authority the parser fills from the path, `//`-less
    // special-scheme targets, percent-encoded hosts (which can spell
    // any decoded byte, including a zone ID), and hosts that are not
    // DNS names at all — cannot be judged: malformed, not skipped.
    let uri = |t: &str| -> Vec<u8> {
        let mut r = vec![0, 10, 0, 20];
        r.extend_from_slice(t.as_bytes());
        r
    };
    for spelling in [
        // WHATWG treats '\' as '/': the gate's authority is
        // `127.0.0.1\@allowed.example` → userinfo split gives
        // allowed.example, but the client dials 127.0.0.1.
        "https://127.0.0.1\\@allowed.example/",
        // Empty authority — WHATWG reads the next segment as host.
        "https:///127.0.0.1/",
        // `//`-less special schemes are re-parsed with a host.
        "http:127.0.0.1",
        "file:/etc/passwd",
        // '\' inside a non-special authority — invalid host char.
        "foo://ok.example\\path",
        // Empty authority under a non-special scheme — unjudgeable.
        "foo:///path",
        // Unknown `//`-less schemes — their grammar may hide a dial
        // target this parser cannot see.
        "skype:+1-555-0100",
        "futuresip:alice@127.0.0.1",
        // SIP forms whose dial target cannot be fully recovered —
        // `?` headers can carry arbitrary URIs, and `;` inside
        // userinfo blurs the authority boundary.
        "sip:alice@h.example?Route=<sip:127.0.0.1>",
        "sip:alice;corp@gw.example",
        "https://%31%32%37.0.0.1/",
        "https://[fe80::1%25eth0]/",
        "https://[fe80::1%eth0]/",
        "https://ev il.com/",
    ] {
        let pkt = response_sections(
            "www.example",
            &[],
            &[("u.example", RRTYPE_URI, 300, &uri(spelling))],
            &[],
        );
        assert!(
            !parse_response(&pkt, "www.example").decoded,
            "{spelling} must fail closed"
        );
    }
}

#[test]
fn response_extra_px_talink_pairs_collected() {
    // PX packs two names after a preference; TALINK packs two bare
    // names — both are destination material.
    let px = {
        let mut r = vec![0, 10];
        r.extend_from_slice(&name_wire("map822.example"));
        r.extend_from_slice(&name_wire("mapx400.example"));
        r
    };
    let talink = {
        let mut r = name_wire("prev.example");
        r.extend_from_slice(&name_wire("next.example"));
        r
    };
    let pkt = response_sections(
        "www.example",
        &[],
        &[
            ("px.example", RRTYPE_PX, 300, &px),
            ("tal.example", RRTYPE_TALINK, 300, &talink),
        ],
        &[],
    );
    let parsed = parse_response(&pkt, "www.example");
    assert!(parsed.decoded);
    for name in [
        "px.example",
        "map822.example",
        "mapx400.example",
        "tal.example",
        "prev.example",
        "next.example",
    ] {
        assert!(
            parsed.extra_names.contains(&name.to_string()),
            "missing {name}: {:?}",
            parsed.extra_names
        );
    }
    // A PX with only one name does not fill the record — malformed.
    let half = {
        let mut r = vec![0, 10];
        r.extend_from_slice(&name_wire("map822.example"));
        r
    };
    let pkt = response_sections(
        "www.example",
        &[],
        &[("px.example", RRTYPE_PX, 300, &half)],
        &[],
    );
    assert!(!parse_response(&pkt, "www.example").decoded);
}

#[test]
fn response_extra_amtrelay_collected() {
    // AMTRELAY's relay is none / IPv4 / IPv6 / name per its type bits.
    let amt = |ty: u8, relay: &[u8]| -> Vec<u8> {
        let mut r = vec![10, ty];
        r.extend_from_slice(relay);
        r
    };
    let pkt = response_sections(
        "www.example",
        &[],
        &[
            (
                "a1.example",
                RRTYPE_AMTRELAY,
                300,
                &amt(3, &name_wire("relay.net")),
            ),
            (
                "a2.example",
                RRTYPE_AMTRELAY,
                300,
                &amt(1, &[203, 0, 113, 5]),
            ),
            ("a3.example", RRTYPE_AMTRELAY, 300, &amt(0, &[])),
        ],
        &[],
    );
    let parsed = parse_response(&pkt, "www.example");
    assert!(parsed.decoded);
    assert!(parsed.extra_names.contains(&"relay.net".to_string()));
    assert!(
        parsed
            .extra_addrs
            .contains(&"203.0.113.5".parse::<std::net::IpAddr>().unwrap())
    );
    // Type 0 with stray relay bytes is malformed.
    let pkt = response_sections(
        "www.example",
        &[],
        &[("a1.example", RRTYPE_AMTRELAY, 300, &amt(0, &[1, 2, 3, 4]))],
        &[],
    );
    assert!(!parse_response(&pkt, "www.example").decoded);
}

#[test]
fn response_extra_sections_empty_when_absent() {
    // A plain answer-only response reports no extra material.
    let pkt = response(
        "www.example",
        0,
        &[("www.example", RRTYPE_A, 60, &[203, 0, 113, 9])],
    );
    let parsed = parse_response(&pkt, "www.example");
    assert!(parsed.decoded);
    assert!(parsed.extra_names.is_empty());
    assert!(parsed.extra_addrs.is_empty());
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
    assert!(response_matches(&resp, 0x42, "www.example.com", 1, 1));
    assert!(!response_matches(&resp, 0x43, "www.example.com", 1, 1));
    assert!(!response_matches(&resp, 0x42, "other.example.com", 1, 1));
    // A same-name answer under another qtype or qclass is not ours.
    assert!(!response_matches(&resp, 0x42, "www.example.com", 28, 1));
    assert!(!response_matches(&resp, 0x42, "www.example.com", 1, 3));
}
