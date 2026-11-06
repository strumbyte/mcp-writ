//! Fuzz target: the DNS wire boundary the embedded gate defends.
//!
//! Input layout: `[u8 name_len][name][message]`. `name` is the
//! canonical forwarded query name; `message` is a raw DNS packet.
//! The property decodes it as a workload query (`parse_query`), feeds
//! the gate's rebuild/refusal/truncated compositions, then reads it
//! as an upstream response (`parse_response`, `response_matches`,
//! `response_truncated`).
//!
//! Search space: random byte soups, structured messages (compression
//! pointers incl. loops and forward refs, CNAME/DNAME/SVCB/HTTPS
//! chains toward the 16-deep bound, OPT/additional sections, bad
//! rdlen/truncation, trailing garbage), and accepted queries mutated
//! into matching responses.

use std::cell::Cell;

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
    matched: Cell<usize>,
}

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
    // A lying rdlen that overshoots the buffer needs the bytes cut too.
    if claimed < rdlen {
        out.truncate(start + claimed as usize);
    }
}

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
    let msg = match noprop::sample_weighted_index(ctx, &[20, 35, 30, 15]) {
        0 => {
            let n = noprop::sample_with_boundaries(
                ctx,
                &[0usize, 1, 11, 12, 13, 20, 511, 512, 4096],
                noprop::Ratio::new(1, 3),
                |ctx| noprop::sample_usize_in(ctx, 0..=4096),
            );
            noprop::sample_bytes_vec(ctx, n)
        }
        // A query the gate should accept — keeps the Ok arm busy.
        1 => query_message(ctx, &name),
        // Anything-goes message: rejections and response-side parses.
        2 => wild_message(ctx, &name),
        _ => {
            // Structured then truncated — the short-read paths.
            let mut m = wild_message(ctx, &name);
            if !m.is_empty() {
                m.truncate(noprop::sample_usize_in(ctx, 0..=m.len()));
            }
            m
        }
    };
    let mut input = vec![name.len().min(255) as u8];
    input.extend_from_slice(&name.as_bytes()[..name.len().min(255)]);
    input.extend_from_slice(&msg);
    input
}

fn property(g: &Gates, data: &[u8]) {
    let Some(&nl) = data.first() else { return };
    let Some(name_bytes) = data.get(1..1 + nl as usize) else {
        return;
    };
    let name = String::from_utf8_lossy(name_bytes);
    let msg = &data[1 + nl as usize..];
    let rcode = msg.get(3).map_or(5, |b| b & 0x0f);

    // ---- query boundary (workload → gate) ----
    if let mcp_writ::fuzz::DnsQueryOutcome::Ok(q) = mcp_writ::fuzz::dns_parse_query(msg) {
        g.query_ok.set(g.query_ok.get() + 1);
        // Forward composition must re-parse as a query.
        if let Some(fwd) = mcp_writ::fuzz::dns_forward_query(msg, &name) {
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
    let resp = mcp_writ::fuzz::dns_parse_response(msg, &name);
    g.resp_seen.set(g.resp_seen.get() + 1);
    g.decoded.set(g.decoded.get() + usize::from(resp.decoded));
    g.chained
        .set(g.chained.get() + usize::from(!resp.chain.is_empty()));
    assert!(resp.chain.len() <= 16, "alias chain escaped its bound");
    let _ = mcp_writ::fuzz::dns_response_truncated(msg);
    if msg.len() >= 12 {
        let id = u16::from_be_bytes([msg[0], msg[1]]);
        let _ = mcp_writ::fuzz::dns_response_matches(msg, id, &name, 1, 1);
    }
    g.cases.set(g.cases.get() + 1);
}

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
            format!(
                "query_ok={} rej={} fwd={} refused={} trunc={} decoded={} chained={} matched={}",
                g.query_ok.get(),
                g.query_rej.get(),
                g.forwarded.get(),
                g.refused.get(),
                g.truncated.get(),
                g.decoded.get(),
                g.chained.get(),
                g.matched.get()
            )
        },
    ));
}
