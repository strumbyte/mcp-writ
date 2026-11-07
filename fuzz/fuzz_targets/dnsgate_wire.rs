//! Fuzz target: the DNS wire boundary the embedded gate defends.
//!
//! Input layout: `[b"DNS1"][u8 name_len][name][u8 arm][message]`.
//! `name` is the canonical forwarded query name; `arm` records which
//! generator produced `message` so arm-specific oracles hold (the
//! planted-extras arm's names/addrs are demanded back verbatim). The
//! property decodes the message as a workload query (`parse_query`),
//! feeds the gate's rebuild/refusal/truncated compositions, then
//! reads it as an upstream response (`parse_response`,
//! `response_matches`, `response_truncated`). The tag rejects stale
//! artifacts — an older `.bin` would decode into a shifted message.
//!
//! Search space: random byte soups, structured messages (compression
//! pointers incl. loops and forward refs, CNAME/DNAME/SVCB/HTTPS
//! chains toward the 16-deep bound, OPT/additional sections, bad
//! rdlen/truncation, trailing garbage), and accepted queries mutated
//! into matching responses.

use std::cell::Cell;
use std::net::IpAddr;

/// Coverage counters the property ticks — the gate at the end of a
/// passing run asserts each boundary actually ran.
#[derive(Default)]
struct Gates {
    cases: Cell<usize>,
    query_ok: Cell<usize>,
    query_rej: Cell<usize>,
    forwarded: Cell<usize>,
    refused: Cell<usize>,
    truncated: Cell<usize>,
    resp_seen: Cell<usize>,
    decoded: Cell<usize>,
    chained: Cell<usize>,
    trunc_chain: Cell<usize>,
    matched: Cell<usize>,
    extras_hit: Cell<usize>,
}

/// Format tag prefixed to every generated input — a saved artifact
/// from a different layout fails loudly instead of decoding into a
/// shifted, unrecognizable message.
const INPUT_TAG: &[u8; 4] = b"DNS1";

/// An uncompressed question name — `parse_query` rejects compression
/// pointers here, so accepted queries must carry labels (UTF-8 only:
/// the decoder refuses anything else).
fn question_name(ctx: &mut noprop::TestCaseContext, out: &mut Vec<u8>, name: &str) {
    if name.is_empty() || noprop::sample_ratio(ctx, noprop::Ratio::new(1, 10)) {
        out.push(0);
        return;
    }
    for label in name.split('.').filter(|l| !l.is_empty()) {
        out.push(label.len().min(63) as u8);
        out.extend_from_slice(&label.as_bytes()[..label.len().min(63)]);
    }
    out.push(0);
}

/// A well-formed QUERY message the gate accepts: QUERY opcode, one
/// uncompressed question, optionally one honest OPT record.
fn query_message(ctx: &mut noprop::TestCaseContext, name: &str) -> Vec<u8> {
    let mut m = Vec::new();
    m.extend_from_slice(&noprop::sample_u16(ctx).to_be_bytes()); // id
    // QUERY, Z clear; RD/AD/CD ride along.
    let flags = noprop::sample_choice(ctx, &[0x0000u16, 0x0100, 0x0110, 0x0130]);
    m.extend_from_slice(&flags.to_be_bytes());
    m.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    m.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
    m.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    let ar = u16::from(noprop::sample_bool(ctx));
    m.extend_from_slice(&ar.to_be_bytes());
    question_name(ctx, &mut m, name);
    let qtype = noprop::sample_choice(ctx, &[1u16, 1, 28, 5, 64, 65, 33, 255, 12, 15, 6, 2, 99]);
    m.extend_from_slice(&qtype.to_be_bytes());
    m.extend_from_slice(&noprop::sample_choice(ctx, &[1u16, 1, 1, 3, 255]).to_be_bytes());
    if ar == 1 {
        // One OPT: root owner, honest UDP size + rdlen.
        m.push(0);
        m.extend_from_slice(&41u16.to_be_bytes());
        m.extend_from_slice(&noprop::sample_choice(ctx, &[512u16, 1232, 4096]).to_be_bytes());
        m.extend_from_slice(&0u32.to_be_bytes());
        let n = noprop::sample_usize_in(ctx, 0..=8);
        m.extend_from_slice(&(n as u16).to_be_bytes());
        m.extend_from_slice(&noprop::sample_bytes_vec(ctx, n));
    }
    m
}

/// A question/answer name on the wire — labels, root, or a
/// compression pointer (some deliberately broken).
fn wire_name(ctx: &mut noprop::TestCaseContext, out: &mut Vec<u8>, name: &str) {
    match noprop::sample_weighted_index(ctx, &[5, 2, 2, 1]) {
        0 => {
            // Labels of the forwarded name, or an ASCII label soup —
            // the decoder requires UTF-8 labels.
            if noprop::sample_bool(ctx) && !name.is_empty() {
                for label in name.split('.').filter(|l| !l.is_empty()) {
                    out.push(label.len().min(63) as u8);
                    out.extend_from_slice(&label.as_bytes()[..label.len().min(63)]);
                }
            } else {
                for _ in 0..noprop::sample_usize_in(ctx, 0..=4) {
                    let n = noprop::sample_usize_in(ctx, 1..=63);
                    out.push(n as u8);
                    out.extend_from_slice(&noprop::sample_ascii_string(ctx, n).into_bytes());
                }
            }
            out.push(0);
        }
        1 => out.extend_from_slice(&[0xC0, 0x0C]), // ptr to the question name
        2 => {
            // Pointer to a sampled offset — often invalid or looping.
            out.extend_from_slice(&[
                0xC0 | (noprop::sample_u8(ctx) & 0x3f),
                noprop::sample_u8(ctx),
            ]);
        }
        _ => out.push(0), // root
    }
}

/// One resource record — destination-bearing types embed names so the
/// response walker's chain logic runs.
fn rr(ctx: &mut noprop::TestCaseContext, out: &mut Vec<u8>, name: &str) {
    wire_name(ctx, out, name);
    let rtype = noprop::sample_choice(
        ctx,
        &[
            1u16, 1, 5, 5, 28, 39, 64, 65, 2, 6, 12, 15, 16, 33, 35, 41, 46, 47, 99, 255, 256,
        ],
    );
    out.extend_from_slice(&rtype.to_be_bytes());
    out.extend_from_slice(&noprop::sample_choice(ctx, &[1u16, 1, 1, 3, 255]).to_be_bytes());
    out.extend_from_slice(&noprop::sample_u32(ctx).to_be_bytes()); // ttl
    let rdlen_pos = out.len();
    out.extend_from_slice(&[0, 0]);
    let start = out.len();
    match rtype {
        // Name-bearing rdata — chains and nested pointers.
        2 | 5 | 12 | 39 | 107 => wire_name(ctx, out, name),
        6 => {
            // SOA: mname + rname + 5 u32s.
            wire_name(ctx, out, name);
            wire_name(ctx, out, name);
            out.extend_from_slice(&noprop::sample_bytes_vec(ctx, 20));
        }
        1 => out.extend_from_slice(&noprop::sample_bytes_vec(ctx, 4)),
        28 => out.extend_from_slice(&noprop::sample_bytes_vec(ctx, 16)),
        15 | 33 | 35 => {
            let n = noprop::sample_usize_in(ctx, 0..=8);
            out.extend_from_slice(&noprop::sample_bytes_vec(ctx, n));
            wire_name(ctx, out, name);
        }
        41 => {
            let n = noprop::sample_usize_in(ctx, 0..=16);
            out.extend_from_slice(&noprop::sample_bytes_vec(ctx, n));
        }
        64 | 65 => {
            // SVCB/HTTPS: priority + target name + params.
            out.extend_from_slice(&noprop::sample_u16(ctx).to_be_bytes());
            wire_name(ctx, out, name);
            let n = noprop::sample_usize_in(ctx, 0..=16);
            out.extend_from_slice(&noprop::sample_bytes_vec(ctx, n));
        }
        _ => {
            let n = noprop::sample_usize_in(ctx, 0..=64);
            out.extend_from_slice(&noprop::sample_bytes_vec(ctx, n));
        }
    }
    let rdlen = (out.len() - start) as u16;
    // Mostly honest rdlen; sometimes lie — the decoder must fail closed.
    let claimed = if noprop::sample_ratio(ctx, noprop::Ratio::new(4, 5)) {
        rdlen
    } else {
        noprop::sample_u16_in(ctx, 0..=rdlen.saturating_add(32))
    };
    out[rdlen_pos] = (claimed >> 8) as u8;
    out[rdlen_pos + 1] = claimed as u8;
    // An undershooting rdlen either cuts the record short — the wire
    // then carries exactly `claimed` bytes — or keeps the full rdata
    // so the surplus parses as the next record's bytes. The decoder
    // must fail closed on both shapes.
    if claimed < rdlen && noprop::sample_bool(ctx) {
        out.truncate(start + claimed as usize);
    }
}

/// Write a dotted name as uncompressed wire labels (no pointers).
fn put_name(m: &mut Vec<u8>, n: &str) {
    for label in n.split('.').filter(|l| !l.is_empty()) {
        m.push(label.len().min(63) as u8);
        m.extend_from_slice(&label.as_bytes()[..label.len().min(63)]);
    }
    m.push(0);
}

/// A response carrying exactly `hops` CNAME aliases — hop counts
/// straddle the 16-deep chain bound so the truncated-at-cap path
/// actually runs. An optional A record on the leaf exercises the
/// visited-owner address collection.
fn chain_message(ctx: &mut noprop::TestCaseContext, name: &str) -> Vec<u8> {
    let hops = noprop::sample_choice(ctx, &[0usize, 1, 14, 15, 16, 17, 18, 24]);
    let leaf_a = noprop::sample_bool(ctx);
    let mut m = Vec::new();
    m.extend_from_slice(&noprop::sample_u16(ctx).to_be_bytes()); // id
    m.extend_from_slice(&0x8180u16.to_be_bytes()); // QR + RD + RA
    m.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    m.extend_from_slice(&((hops + usize::from(leaf_a)) as u16).to_be_bytes());
    m.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    m.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
    put_name(&mut m, name);
    m.extend_from_slice(&1u16.to_be_bytes()); // A
    m.extend_from_slice(&1u16.to_be_bytes()); // IN
    // Hop i rewrites owner h{i-1}.<name> to target h{i}.<name> —
    // h0.<name> is <name> itself, the forwarded name the chain starts
    // from.
    for i in 0..hops {
        let owner = if i == 0 {
            name.to_string()
        } else {
            format!("h{i}.{name}")
        };
        put_name(&mut m, &owner);
        m.extend_from_slice(&5u16.to_be_bytes()); // CNAME
        m.extend_from_slice(&1u16.to_be_bytes()); // IN
        m.extend_from_slice(&noprop::sample_u32(ctx).to_be_bytes()); // ttl
        let target = format!("h{}.{name}", i + 1);
        let rdlen: usize = target
            .split('.')
            .filter(|l| !l.is_empty())
            .map(|l| l.len().min(63) + 1)
            .sum::<usize>()
            + 1;
        m.extend_from_slice(&(rdlen as u16).to_be_bytes());
        put_name(&mut m, &target);
    }
    if leaf_a {
        // h0 is the forwarded name itself, so a 0-hop leaf's owner is
        // `name`, not a literal `h0.` label — otherwise the record
        // never binds to the question and `addrs` stays unreachable.
        let leaf = if hops == 0 {
            name.to_string()
        } else {
            format!("h{hops}.{name}")
        };
        put_name(&mut m, &leaf);
        m.extend_from_slice(&1u16.to_be_bytes()); // A
        m.extend_from_slice(&1u16.to_be_bytes()); // IN
        m.extend_from_slice(&noprop::sample_u32(ctx).to_be_bytes()); // ttl
        m.extend_from_slice(&4u16.to_be_bytes()); // rdlen
        m.extend_from_slice(&noprop::sample_bytes_vec(ctx, 4));
    }
    m
}

/// A response with planted destination material outside the answer
/// section: an authority CNAME and an additional A record, both with
/// names derived from `name` so the property can demand them back in
/// `extra_names`/`extra_addrs` — an implementation that drops them
/// fails on comparison, not on a guess.
fn extras_message(ctx: &mut noprop::TestCaseContext, name: &str) -> Vec<u8> {
    let mut m = Vec::new();
    m.extend_from_slice(&noprop::sample_u16(ctx).to_be_bytes()); // id
    m.extend_from_slice(&0x8180u16.to_be_bytes()); // QR + RD + RA
    m.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    m.extend_from_slice(&1u16.to_be_bytes()); // ANCOUNT
    m.extend_from_slice(&1u16.to_be_bytes()); // NSCOUNT
    m.extend_from_slice(&1u16.to_be_bytes()); // ARCOUNT
    put_name(&mut m, name);
    m.extend_from_slice(&1u16.to_be_bytes()); // A
    m.extend_from_slice(&1u16.to_be_bytes()); // IN
    // Answer: a direct A record on the question name.
    put_name(&mut m, name);
    m.extend_from_slice(&1u16.to_be_bytes()); // A
    m.extend_from_slice(&1u16.to_be_bytes()); // IN
    m.extend_from_slice(&noprop::sample_u32(ctx).to_be_bytes()); // ttl
    m.extend_from_slice(&4u16.to_be_bytes()); // rdlen
    m.extend_from_slice(&EXTRAS_ANSWER_ADDR);
    // Authority: `auth.<name>` CNAME → `ns1.<name>` — both names are
    // destination material the verdict must collect.
    put_name(&mut m, &extras_auth_name(name));
    m.extend_from_slice(&5u16.to_be_bytes()); // CNAME
    m.extend_from_slice(&1u16.to_be_bytes()); // IN
    m.extend_from_slice(&noprop::sample_u32(ctx).to_be_bytes()); // ttl
    let target = wire_len(&extras_ns_name(name));
    m.extend_from_slice(&(target as u16).to_be_bytes());
    put_name(&mut m, &extras_ns_name(name));
    // Additional: `ns1.<name>` A → a dialable hint address.
    put_name(&mut m, &extras_ns_name(name));
    m.extend_from_slice(&1u16.to_be_bytes()); // A
    m.extend_from_slice(&1u16.to_be_bytes()); // IN
    m.extend_from_slice(&noprop::sample_u32(ctx).to_be_bytes()); // ttl
    m.extend_from_slice(&4u16.to_be_bytes()); // rdlen
    m.extend_from_slice(&EXTRAS_HINT_ADDR);
    m
}

/// Planted address material for `extras_message` — fixed so the
/// property can demand it back byte-for-byte.
const EXTRAS_ANSWER_ADDR: [u8; 4] = [203, 0, 113, 7];
const EXTRAS_HINT_ADDR: [u8; 4] = [198, 51, 100, 9];

/// Authority-section owner — `auth.<name>` (or just `auth` for the
/// root query name).
fn extras_auth_name(name: &str) -> String {
    if name.is_empty() {
        "auth".to_string()
    } else {
        format!("auth.{name}")
    }
}

/// The planted CNAME target / additional-A owner — `ns1.<name>`.
fn extras_ns_name(name: &str) -> String {
    if name.is_empty() {
        "ns1".to_string()
    } else {
        format!("ns1.{name}")
    }
}

/// Byte length a dotted name occupies on the wire (labels + root).
fn wire_len(name: &str) -> usize {
    name.split('.')
        .filter(|l| !l.is_empty())
        .map(|l| l.len().min(63) + 1)
        .sum::<usize>()
        + 1
}

/// An anything-goes message — sampled flag words and section counts
/// filled by `wire_name`/`rr`, plus occasional trailing garbage the
/// parser must reject.
fn wild_message(ctx: &mut noprop::TestCaseContext, name: &str) -> Vec<u8> {
    let mut m = Vec::new();
    m.extend_from_slice(&noprop::sample_u16(ctx).to_be_bytes()); // id
    // flags: qr/opcode/aa/tc/rd/ra/rcode — bit salad weighted toward sane.
    let flags: u16 = if noprop::sample_ratio(ctx, noprop::Ratio::new(1, 2)) {
        noprop::sample_choice(
            ctx,
            &[0x0100u16, 0x8180, 0x8183, 0x8000, 0x8400, 0x8500, 0x0580],
        )
    } else {
        noprop::sample_u16(ctx)
    };
    m.extend_from_slice(&flags.to_be_bytes());
    let qd = noprop::sample_choice(ctx, &[1u16, 1, 1, 2, 0, 255]);
    let an = noprop::sample_usize_in(ctx, 0..=8);
    let ns = noprop::sample_usize_in(ctx, 0..=3);
    let ar = noprop::sample_usize_in(ctx, 0..=3);
    m.extend_from_slice(&qd.to_be_bytes());
    m.extend_from_slice(&(an as u16).to_be_bytes());
    m.extend_from_slice(&(ns as u16).to_be_bytes());
    m.extend_from_slice(&(ar as u16).to_be_bytes());
    for _ in 0..qd {
        wire_name(ctx, &mut m, name);
        let qtype =
            noprop::sample_choice(ctx, &[1u16, 1, 28, 5, 64, 65, 33, 255, 12, 15, 6, 2, 99]);
        m.extend_from_slice(&qtype.to_be_bytes());
        m.extend_from_slice(&noprop::sample_choice(ctx, &[1u16, 1, 1, 3, 255]).to_be_bytes());
    }
    for _ in 0..an + ns + ar {
        rr(ctx, &mut m, name);
    }
    // Trailing garbage the parser must reject.
    if noprop::sample_ratio(ctx, noprop::Ratio::new(1, 5)) {
        let n = noprop::sample_usize_in(ctx, 1..=8);
        m.extend_from_slice(&noprop::sample_bytes_vec(ctx, n));
    }
    m
}

/// Emit one tagged input: `[DNS1][u8 name_len][name][u8
/// arm][message]` — `arm` records which generator produced `message`
/// so its arm-specific oracles apply.
fn gen_input(ctx: &mut noprop::TestCaseContext) -> Vec<u8> {
    let name = noprop::sample_choice(
        ctx,
        &[
            "example.com".to_string(),
            "a.b.example.com".to_string(),
            "cdn.example.net".to_string(),
            "".to_string(),
            "x".repeat(63) + ".example.com",
            "MiXeD.Case.Example".to_string(),
        ],
    );
    let (arm, msg) = match noprop::sample_weighted_index(ctx, &[20, 35, 28, 10, 15, 8]) {
        0 => {
            let n = noprop::sample_with_boundaries(
                ctx,
                &[0usize, 1, 11, 12, 13, 20, 511, 512, 4096],
                noprop::Ratio::new(1, 3),
                |ctx| noprop::sample_usize_in(ctx, 0..=4096),
            );
            (0u8, noprop::sample_bytes_vec(ctx, n))
        }
        // A query the gate should accept — keeps the Ok arm busy.
        1 => (1, query_message(ctx, &name)),
        // Anything-goes message: rejections and response-side parses.
        2 => (2, wild_message(ctx, &name)),
        // A CNAME chain sized around the 16-hop bound.
        3 => (3, chain_message(ctx, &name)),
        // Response carrying planted authority/additional destinations.
        4 => (5, extras_message(ctx, &name)),
        _ => {
            // Structured then truncated — the short-read paths.
            let mut m = wild_message(ctx, &name);
            if !m.is_empty() {
                m.truncate(noprop::sample_usize_in(ctx, 0..=m.len()));
            }
            (4, m)
        }
    };
    let mut input = INPUT_TAG.to_vec();
    input.push(name.len().min(255) as u8);
    input.extend_from_slice(&name.as_bytes()[..name.len().min(255)]);
    input.push(arm);
    input.extend_from_slice(&msg);
    input
}

/// Run one input across the query and response boundaries, asserting
/// parser verdicts and ticking the coverage gates.
fn property(g: &Gates, data: &[u8]) {
    let Some(data) = data.strip_prefix(INPUT_TAG) else {
        panic!(
            "dnsgate_wire input lacks the {} tag — stale or foreign artifact",
            String::from_utf8_lossy(INPUT_TAG)
        );
    };
    let Some(&nl) = data.first() else { return };
    let Some(name_bytes) = data.get(1..1 + nl as usize) else {
        return;
    };
    let name = String::from_utf8_lossy(name_bytes);
    let Some(&arm) = data.get(1 + nl as usize) else {
        return;
    };
    let msg = &data[2 + nl as usize..];
    // `parse_response`/`forward_query` take the canonical forwarded
    // name — the gate canonicalizes before upstream exchange; feeding
    // the wire-verbatim qname would never bind answer records.
    let canon = mcp_writ::fuzz::dns_canonical_name(&name);
    let rcode = msg.get(3).map_or(5, |b| b & 0x0f);

    // ---- query boundary (workload → gate) ----
    if let mcp_writ::fuzz::DnsQueryOutcome::Ok(q) = mcp_writ::fuzz::dns_parse_query(msg) {
        g.query_ok.set(g.query_ok.get() + 1);
        // The section walk only moves forward and never past the buffer.
        assert!(
            q.question_end <= q.additional_start && q.additional_start <= msg.len(),
            "section offsets out of order"
        );
        // `flags_relay`/`arcount` are the header words masked/copied —
        // they must agree with the wire bytes.
        assert_eq!(
            q.flags_relay,
            u16::from_be_bytes([msg[2], msg[3]]) & 0x0130,
            "relay flags diverged from the header mask"
        );
        assert_eq!(
            q.arcount,
            u16::from_be_bytes([msg[10], msg[11]]),
            "arcount diverged from the header"
        );
        // An OPT can only be seen if the additional section held one.
        assert!(q.edns_udp_size.is_none() || q.arcount >= 1);
        // Forward composition must re-parse as a query.
        if let Some(fwd) = mcp_writ::fuzz::dns_forward_query(msg, &canon) {
            g.forwarded.set(g.forwarded.get() + 1);
            assert!(
                matches!(
                    mcp_writ::fuzz::dns_parse_query(&fwd),
                    mcp_writ::fuzz::DnsQueryOutcome::Ok(_)
                ),
                "forwarded query no longer decodes"
            );
        }
        // Truncated answer must carry the TC bit the retry path reads.
        if let Some(t) = mcp_writ::fuzz::dns_truncated(msg) {
            g.truncated.set(g.truncated.get() + 1);
            assert!(mcp_writ::fuzz::dns_response_truncated(&t));
        }
        // The accepted query with QR flipped must satisfy the
        // response-matches gate — the same name the upstream echoes.
        let mut resp = msg.to_vec();
        resp[2] |= 0x80;
        assert!(
            mcp_writ::fuzz::dns_response_matches(&resp, q.id, &q.qname, q.qtype, q.qclass),
            "accepted query does not match itself as a response"
        );
        g.matched.set(g.matched.get() + 1);
        // And the gate must refuse the same bytes once one field
        // diverges — QR clear, wrong id/name, or another type/class.
        assert!(
            !mcp_writ::fuzz::dns_response_matches(msg, q.id, &q.qname, q.qtype, q.qclass),
            "query with QR clear passed the response gate"
        );
        assert!(
            !mcp_writ::fuzz::dns_response_matches(
                &resp,
                q.id.wrapping_add(1),
                &q.qname,
                q.qtype,
                q.qclass
            ),
            "wrong response id accepted"
        );
        let other = format!("{}.gate.invalid", q.qname);
        assert!(
            !mcp_writ::fuzz::dns_response_matches(&resp, q.id, &other, q.qtype, q.qclass),
            "wrong response name accepted"
        );
        assert!(
            !mcp_writ::fuzz::dns_response_matches(
                &resp,
                q.id,
                &q.qname,
                q.qtype.wrapping_add(1),
                q.qclass
            ),
            "wrong response type accepted"
        );
        assert!(
            !mcp_writ::fuzz::dns_response_matches(
                &resp,
                q.id,
                &q.qname,
                q.qtype,
                q.qclass.wrapping_add(1)
            ),
            "wrong response class accepted"
        );
    } else {
        g.query_rej.set(g.query_rej.get() + 1);
    }
    // Refusal works on every input — decoded or not (header echo).
    if let Some(r) = mcp_writ::fuzz::dns_refusal(msg, rcode) {
        g.refused.set(g.refused.get() + 1);
        assert!(r.len() >= 12 && r[2] & 0x80 != 0, "refusal lost the QR bit");
        assert_eq!(r[3] & 0x0f, rcode, "refusal rcode mismatch");
    }
    let _ = mcp_writ::fuzz::dns_encode_name(&name);

    // ---- response boundary (upstream → gate) ----
    let resp = mcp_writ::fuzz::dns_parse_response(msg, &canon);
    g.resp_seen.set(g.resp_seen.get() + 1);
    g.decoded.set(g.decoded.get() + usize::from(resp.decoded));
    g.chained
        .set(g.chained.get() + usize::from(!resp.chain.is_empty()));
    g.trunc_chain
        .set(g.trunc_chain.get() + usize::from(resp.chain_truncated));
    assert!(resp.chain.len() <= 16, "alias chain escaped its bound");
    if resp.chain_truncated {
        assert_eq!(
            resp.chain.len(),
            16,
            "chain flagged truncated below the depth bound"
        );
    }
    // Field consistency: `min_ttl` covers exactly the followed
    // aliases and the collected address records — present iff either
    // exists, and never above any collected record's ttl. `rcode` is
    // the header nibble for a full header and 0 below it, where every
    // observation field must stay empty.
    assert_eq!(
        resp.min_ttl.is_some(),
        !resp.chain.is_empty() || !resp.addrs.is_empty(),
        "min_ttl disagreed with the collected chain/addrs"
    );
    if let Some(min) = resp.min_ttl {
        assert!(
            resp.addrs.iter().all(|(_, ttl)| min <= *ttl),
            "min_ttl above an address record's ttl"
        );
    }
    let expect_rcode = if msg.len() >= 12 { msg[3] & 0x0f } else { 0 };
    assert_eq!(resp.rcode, expect_rcode, "rcode diverged from the header");
    // Arm-specific oracles: a fully-walked chain arm holds no
    // unfollowed destination records — nothing survives into extras —
    // and the extras arm's planted authority/additional records must
    // be reported back, so an implementation that drops destination
    // material fails on comparison, not on silence.
    if arm == 3 && resp.decoded && !resp.chain_truncated {
        assert!(
            resp.extra_names.is_empty() && resp.extra_addrs.is_empty(),
            "fully-walked chain message produced extra destinations"
        );
    }
    if arm == 5 {
        g.extras_hit.set(g.extras_hit.get() + 1);
        let auth = extras_auth_name(&canon);
        let ns1 = extras_ns_name(&canon);
        assert!(resp.decoded, "planted extras response failed to decode");
        assert!(
            resp.extra_names
                .iter()
                .any(|n| n.eq_ignore_ascii_case(&auth)),
            "authority owner name missing from extra_names"
        );
        assert!(
            resp.extra_names
                .iter()
                .any(|n| n.eq_ignore_ascii_case(&ns1)),
            "authority target name missing from extra_names"
        );
        assert!(
            resp.extra_addrs
                .iter()
                .any(|a| *a == IpAddr::from(EXTRAS_HINT_ADDR)),
            "hint address missing from extra_addrs"
        );
        assert!(
            resp.addrs
                .iter()
                .any(|(a, _)| *a == IpAddr::from(EXTRAS_ANSWER_ADDR)),
            "answer address missing from addrs"
        );
    }
    if msg.len() < 12 {
        assert!(
            !resp.decoded
                && resp.chain.is_empty()
                && resp.addrs.is_empty()
                && resp.min_ttl.is_none()
                && resp.extra_names.is_empty()
                && resp.extra_addrs.is_empty(),
            "short message produced observations"
        );
    }
    let _ = mcp_writ::fuzz::dns_response_truncated(msg);
    if msg.len() >= 12 {
        let id = u16::from_be_bytes([msg[0], msg[1]]);
        let _ = mcp_writ::fuzz::dns_response_matches(msg, id, &canon, 1, 1);
    }
    g.cases.set(g.cases.get() + 1);
}

/// Parse the shared CLI and run the harness for this target.
fn main() {
    let args = mcp_writ_fuzz::parse_args("dnsgate_wire");
    let g = Gates::default();
    std::process::exit(mcp_writ_fuzz::run(
        "dnsgate_wire",
        &args,
        gen_input,
        |data| property(&g, data),
        || {
            assert!(g.query_ok.get() > 0, "no query decoded");
            assert!(g.query_rej.get() > 0, "no query rejected");
            assert!(g.decoded.get() > 0, "no response decoded");
            assert!(g.trunc_chain.get() > 0, "chain bound never tripped");
            assert!(g.extras_hit.get() > 0, "extras arm never ran");
            format!(
                "query_ok={} rej={} fwd={} refused={} trunc={} decoded={} chained={} trunc_chain={} matched={} extras={}",
                g.query_ok.get(),
                g.query_rej.get(),
                g.forwarded.get(),
                g.refused.get(),
                g.truncated.get(),
                g.decoded.get(),
                g.chained.get(),
                g.trunc_chain.get(),
                g.matched.get(),
                g.extras_hit.get()
            )
        },
    ));
}
