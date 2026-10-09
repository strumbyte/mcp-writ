//! Minimal DNS wire handling for the policy-evaluating resolver.
//!
//! Only what a relay needs: decode a client query's question,
//! re-encode it under the canonical policy name for the upstream hop,
//! walk an upstream answer's answer-section for CNAME/address records
//! and TTLs (observational — the response body is relayed verbatim and
//! never rewritten), and build refusal/truncated answers. This codec
//! deliberately understands no record payload beyond CNAME/A/AAAA —
//! inspecting content is not the gate's job (destination policy only).

/// DNS header length (fixed 12 octets).
pub(crate) const HEADER_LEN: usize = 12;

// RCODEs this gate emits itself.
pub(crate) const RCODE_FORMERR: u8 = 1;
pub(crate) const RCODE_SERVFAIL: u8 = 2;
pub(crate) const RCODE_NXDOMAIN: u8 = 3;
pub(crate) const RCODE_NOTIMP: u8 = 4;
pub(crate) const RCODE_REFUSED: u8 = 5;

// Record types the codec names explicitly; every other type is carried
// by number (`TYPE<n>` in audit details) and relayed uninterpreted.
pub(crate) const RRTYPE_A: u16 = 1;
pub(crate) const RRTYPE_CNAME: u16 = 5;
pub(crate) const RRTYPE_AAAA: u16 = 28;
pub(crate) const RRTYPE_OPT: u16 = 41;

/// A decoded client query — everything the pipeline needs to evaluate
/// the name, rebuild an upstream query, and echo the question back in
/// refusal/truncated answers.
pub(crate) struct DnsQuery {
    /// Query ID — echoed unchanged to the client and upstream (each
    /// upstream exchange runs on its own socket, so client ids need no
    /// rewrite to stay unambiguous).
    pub id: u16,
    /// Flag bits relayed upstream: RD | AD | CD. QR/opcode/AA/TC/Z are
    /// never copied into the forwarded query.
    pub flags_relay: u16,
    /// Decoded question name, dotted text, original case, no trailing
    /// dot. Canonicalization is the evaluator's job.
    pub qname: String,
    pub qtype: u16,
    pub qclass: u16,
    /// Offset one past the question section (name + qtype + qclass).
    pub question_end: usize,
    /// Offset where the additional section begins — the bytes from here
    /// to the packet end (EDNS OPT and friends) are copied verbatim
    /// into the forwarded query and refusal answers.
    pub additional_start: usize,
    /// ARCOUNT copied from the query header — it counts exactly the
    /// additional bytes carried verbatim.
    pub arcount: u16,
    /// The client's advertised EDNS UDP payload size (OPT RR CLASS),
    /// when present. Caps the UDP answer; absent means the classic 512.
    pub edns_udp_size: Option<u16>,
}

/// Why a packet was refused at decode time. `Drop` is unanswerable
/// (no header to echo); the rest map to an RCODE.
#[derive(Debug)]
pub(crate) enum QueryReject {
    Drop,
    FormErr,
    NotImp,
}

/// A decode failure carrying whatever question fields were recovered —
/// the audit record names what could still be read.
#[derive(Debug)]
pub(crate) struct QueryError {
    pub reject: QueryReject,
    pub qname: Option<String>,
    pub qtype: Option<u16>,
}

/// Decode a domain name at `off` into dotted text.
///
/// `follow_ptr` permits compression pointers (answers use them); they
/// are followed only when strictly backward-pointing, which is the only
/// position RFC 1035 allows and also bounds loops. Returns the name
/// (empty for the root) and the offset just past the name's wire form
/// at the original position.
fn decode_name(buf: &[u8], off: usize, follow_ptr: bool) -> Option<(String, usize)> {
    let mut labels: Vec<String> = Vec::new();
    let mut total_len = 1usize; // the terminating root byte
    let mut pos = off;
    let mut end: Option<usize> = None;
    let mut jumps = 0usize;
    loop {
        let b = *buf.get(pos)?;
        if b & 0xC0 == 0xC0 {
            if !follow_ptr {
                return None;
            }
            let ptr = (((b & 0x3F) as usize) << 8) | *buf.get(pos + 1)? as usize;
            if end.is_none() {
                end = Some(pos + 2);
            }
            if ptr >= pos {
                // Not a "prior occurrence" — a pointer may only point
                // backward; forward/self pointers are malformed.
                return None;
            }
            pos = ptr;
            jumps += 1;
            if jumps > 16 {
                return None;
            }
            continue;
        }
        if b & 0xC0 != 0 {
            // 0x40/0x80 label types are reserved.
            return None;
        }
        if b == 0 {
            let after = pos + 1;
            return Some((labels.join("."), end.unwrap_or(after)));
        }
        let len = b as usize;
        total_len += len + 1;
        if len > 63 || total_len > 255 {
            return None;
        }
        let bytes = buf.get(pos + 1..pos + 1 + len)?;
        // A label that is not UTF-8 cannot be evaluated by the
        // UTS-46/canonicalization path — undecodable names are
        // malformed for this resolver's purposes.
        labels.push(std::str::from_utf8(bytes).ok()?.to_string());
        pos += 1 + len;
    }
}

/// A resource record header + payload slice.
struct Rr<'a> {
    name: String,
    rtype: u16,
    class: u16,
    ttl: u32,
    /// Absolute offset of the RDATA (its bytes may contain compression
    /// pointers into the message — decoders need the whole buffer).
    rdata_off: usize,
    rdata_len: usize,
    _marker: std::marker::PhantomData<&'a ()>,
}

fn read_rr(buf: &[u8], off: usize) -> Option<(Rr<'_>, usize)> {
    let (name, pos) = decode_name(buf, off, true)?;
    let fixed = buf.get(pos..pos + 10)?;
    let rtype = u16::from_be_bytes([fixed[0], fixed[1]]);
    let class = u16::from_be_bytes([fixed[2], fixed[3]]);
    let ttl = u32::from_be_bytes([fixed[4], fixed[5], fixed[6], fixed[7]]);
    let rdata_len = u16::from_be_bytes([fixed[8], fixed[9]]) as usize;
    let rdata_off = pos + 10;
    let next = rdata_off.checked_add(rdata_len)?;
    if next > buf.len() {
        return None;
    }
    Some((
        Rr {
            name,
            rtype,
            class,
            ttl,
            rdata_off,
            rdata_len,
            _marker: std::marker::PhantomData,
        },
        next,
    ))
}

/// Parse a client query packet. Anything other than a well-formed
/// single-question QUERY is rejected — forwarding cannot guess intent.
pub(crate) fn parse_query(buf: &[u8]) -> Result<DnsQuery, QueryError> {
    let err = |reject, qname, qtype| QueryError {
        reject,
        qname,
        qtype,
    };
    if buf.len() < HEADER_LEN {
        return Err(err(QueryReject::Drop, None, None));
    }
    let flags = u16::from_be_bytes([buf[2], buf[3]]);
    if flags & 0x8000 != 0 {
        // A response where a query belongs is malformed here.
        return Err(err(QueryReject::FormErr, None, None));
    }
    if flags & 0x7800 != 0 {
        // Non-QUERY opcode — this resolver only answers standard queries.
        return Err(err(QueryReject::NotImp, None, None));
    }
    if flags & 0x0040 != 0 {
        // Z bit set.
        return Err(err(QueryReject::FormErr, None, None));
    }
    let qd = u16::from_be_bytes([buf[4], buf[5]]);
    if qd != 1 {
        // Zero or multi-question messages cannot be answered safely —
        // the refusal must echo exactly one question to be meaningful.
        return Err(err(QueryReject::FormErr, None, None));
    }
    let an = u16::from_be_bytes([buf[6], buf[7]]);
    let ns = u16::from_be_bytes([buf[8], buf[9]]);
    let ar = u16::from_be_bytes([buf[10], buf[11]]);

    // A compressed QNAME would have to point into the header — there is
    // nothing to point at — so pointers are rejected outright here.
    let Some((qname, pos)) = decode_name(buf, HEADER_LEN, false) else {
        return Err(err(QueryReject::FormErr, None, None));
    };
    let Some(qf) = buf.get(pos..pos + 4) else {
        return Err(err(QueryReject::FormErr, Some(qname), None));
    };
    let qtype = u16::from_be_bytes([qf[0], qf[1]]);
    let qclass = u16::from_be_bytes([qf[2], qf[3]]);
    let question_end = pos + 4;

    // Answer/authority records in a QUERY are unusual but legal (e.g.
    // UPDATE-shaped uses are out of scope — opcode 0 carries them only
    // as inert payload). Walk them to find the additional section; a
    // RR that does not parse fails the whole message.
    let mut p = question_end;
    for _ in 0..an.saturating_add(ns) {
        let Some((_rr, next)) = read_rr(buf, p) else {
            return Err(err(QueryReject::FormErr, Some(qname), Some(qtype)));
        };
        p = next;
    }
    let additional_start = p;

    // Walk the additional section once: structural validation plus the
    // EDNS OPT payload size. A second OPT or a non-root OPT owner is a
    // protocol violation (RFC 6891 §6.1.1) — FORMERR, not silent relay.
    let mut edns_udp_size = None;
    for _ in 0..ar {
        let Some((rr, next)) = read_rr(buf, p) else {
            return Err(err(QueryReject::FormErr, Some(qname), Some(qtype)));
        };
        if rr.rtype == RRTYPE_OPT {
            if !rr.name.is_empty() || edns_udp_size.is_some() {
                return Err(err(QueryReject::FormErr, Some(qname), Some(qtype)));
            }
            edns_udp_size = Some(rr.class);
        }
        p = next;
    }
    if p != buf.len() {
        // Trailing bytes after the last RR — the packet is malformed.
        return Err(err(QueryReject::FormErr, Some(qname), Some(qtype)));
    }

    Ok(DnsQuery {
        id: u16::from_be_bytes([buf[0], buf[1]]),
        flags_relay: flags & 0x0130, // RD | AD | CD
        qname,
        qtype,
        qclass,
        question_end,
        additional_start,
        arcount: ar,
        edns_udp_size,
    })
}

/// Encode a dotted name into label-wire form (root = single zero byte).
/// Labels over 63 bytes or names over 255 wire bytes return `None` —
/// a canonicalized policy name that cannot encode is unreachable.
pub(crate) fn encode_name(name: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(name.len() + 2);
    if !name.is_empty() {
        for label in name.split('.') {
            let b = label.as_bytes();
            if b.is_empty() || b.len() > 63 {
                return None;
            }
            out.push(b.len() as u8);
            out.extend_from_slice(b);
        }
    }
    out.push(0);
    if out.len() > 255 {
        return None;
    }
    Some(out)
}

/// Rebuild the client query for the upstream hop: the same ID (each
/// exchange runs on its own socket, so client ids need no rewrite),
/// relayed flag bits only, the question re-encoded under the canonical
/// name the policy evaluated, and the additional section copied
/// verbatim (the client's EDNS settings ride along unchanged).
pub(crate) fn build_forward_query(pkt: &[u8], q: &DnsQuery, canonical: &str) -> Option<Vec<u8>> {
    let enc = encode_name(canonical)?;
    let mut out = Vec::with_capacity(HEADER_LEN + enc.len() + 4 + (pkt.len() - q.additional_start));
    out.extend_from_slice(&pkt[0..2]); // id
    out.extend_from_slice(&q.flags_relay.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    out.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
    out.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    out.extend_from_slice(&q.arcount.to_be_bytes());
    out.extend_from_slice(&enc);
    out.extend_from_slice(&q.qtype.to_be_bytes());
    out.extend_from_slice(&q.qclass.to_be_bytes());
    out.extend_from_slice(&pkt[q.additional_start..]);
    Some(out)
}

/// A refusal answer to `pkt`: QR + copied RD, RA, the given RCODE, the
/// question echoed when it was decoded, and the additional section
/// preserved (the client's OPT keeps EDNS working on refusals).
/// `q` is `None` for packets whose question never decoded — the
/// answer then carries an empty question section.
pub(crate) fn refusal_answer(pkt: &[u8], q: Option<&DnsQuery>, rcode: u8) -> Option<Vec<u8>> {
    if pkt.len() < HEADER_LEN {
        return None;
    }
    let mut out = Vec::with_capacity(pkt.len().min(HEADER_LEN + 300));
    out.extend_from_slice(&pkt[0..2]); // id
    out.push((pkt[2] & 0x01) | 0x80); // QR + copied RD; opcode stays QUERY
    out.push(0x80 | rcode); // RA | rcode
    match q {
        Some(q) => {
            out.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
            out.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
            out.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
            out.extend_from_slice(&q.arcount.to_be_bytes());
            out.extend_from_slice(&pkt[HEADER_LEN..q.question_end]);
            out.extend_from_slice(&pkt[q.additional_start..]);
        }
        None => {
            out.extend_from_slice(&[0u8; 8]); // all counts zero
        }
    }
    Some(out)
}

/// A truncated (TC) answer to the client's own question — tells a UDP
/// client the full answer is waiting over TCP. Counts other than
/// QDCOUNT/ARCOUNT are zero; the question and additional echo verbatim.
pub(crate) fn truncated_answer(pkt: &[u8], q: &DnsQuery) -> Vec<u8> {
    let mut out = Vec::with_capacity(q.additional_start);
    out.extend_from_slice(&pkt[0..2]); // id
    out.push((pkt[2] & 0x01) | 0x82); // QR + copied RD + TC
    out.push(0x80); // RA, NOERROR
    out.extend_from_slice(&1u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&q.arcount.to_be_bytes());
    out.extend_from_slice(&pkt[HEADER_LEN..q.question_end]);
    out.extend_from_slice(&pkt[q.additional_start..]);
    out
}

/// What the upstream answer looked like — the observational digest
/// that drives the audit record and the dynamic allow list.
pub(crate) struct ParsedResponse {
    /// RCODE from the upstream answer.
    pub rcode: u8,
    /// The CNAME chain followed from the forwarded query name, in
    /// order, each entry canonicalized. Empty when the answer named no
    /// alias — the query name itself is not repeated here.
    pub chain: Vec<String>,
    /// The chain walk stopped at the depth cap — the recorded chain is
    /// a prefix, not the whole alias sequence.
    pub chain_truncated: bool,
    /// `(addr, ttl)` pairs from answer-section A/AAAA records owned by
    /// the query name or a chain member.
    pub addrs: Vec<(std::net::IpAddr, u32)>,
    /// Minimum TTL across the followed CNAMEs and the collected
    /// address records — the lifetime of any grant this answer mints.
    /// `None` when nothing TTL-scoped was observed.
    pub min_ttl: Option<u32>,
    /// `false` when the answer's wire form could not be fully walked —
    /// the bytes are still relayed, but the record says the parse was
    /// partial instead of implying an empty observation.
    pub decoded: bool,
}

/// Maximum CNAME hops followed in one answer — a bound against
/// malformed or malicious chains, not a policy limit.
const MAX_CHAIN_DEPTH: usize = 16;

/// Walk an upstream answer's answer section. `forwarded_name` is the
/// canonical name the query asked for — the chain starts there, and
/// only records owned by the query name or a chain member count as
/// policy-relevant destinations.
pub(crate) fn parse_response(buf: &[u8], forwarded_name: &str) -> ParsedResponse {
    let mut out = ParsedResponse {
        rcode: 0,
        chain: Vec::new(),
        chain_truncated: false,
        addrs: Vec::new(),
        min_ttl: None,
        decoded: false,
    };
    if buf.len() < HEADER_LEN {
        return out;
    }
    out.rcode = buf[3] & 0x0F;
    let qd = u16::from_be_bytes([buf[4], buf[5]]) as usize;
    let an = u16::from_be_bytes([buf[6], buf[7]]) as usize;

    let mut pos = HEADER_LEN;
    for _ in 0..qd {
        let Some((_name, next)) = decode_name(buf, pos, true) else {
            return out;
        };
        let Some(next) = next.checked_add(4) else {
            return out;
        };
        if next > buf.len() {
            return out;
        }
        pos = next;
    }

    // Collect first, then walk: answer records are not guaranteed to be
    // ordered along the alias chain.
    let mut cnames: Vec<(String, String, u32)> = Vec::new();
    let mut addrs: Vec<(String, std::net::IpAddr, u32)> = Vec::new();
    let mut decoded = true;
    for _ in 0..an {
        let Some((rr, next)) = read_rr(buf, pos) else {
            decoded = false;
            break;
        };
        pos = next;
        if rr.class != 1 {
            // IN is the only class this resolver serves; foreign-class
            // records are not destinations for the allow list.
            continue;
        }
        let owner = super::canonical_name(&rr.name);
        match rr.rtype {
            RRTYPE_CNAME if rr.rdata_len >= 2 => {
                if let Some((target, _)) = decode_name(buf, rr.rdata_off, true) {
                    cnames.push((owner, super::canonical_name(&target), rr.ttl));
                }
            }
            RRTYPE_A if rr.rdata_len == 4 => {
                let b = &buf[rr.rdata_off..rr.rdata_off + 4];
                addrs.push((
                    owner,
                    std::net::IpAddr::V4(std::net::Ipv4Addr::new(b[0], b[1], b[2], b[3])),
                    rr.ttl,
                ));
            }
            RRTYPE_AAAA if rr.rdata_len == 16 => {
                let b: [u8; 16] = buf[rr.rdata_off..rr.rdata_off + 16].try_into().unwrap();
                addrs.push((
                    owner,
                    std::net::IpAddr::V6(std::net::Ipv6Addr::from(b)),
                    rr.ttl,
                ));
            }
            _ => {}
        }
    }
    out.decoded = decoded;

    // Follow the alias chain from the query name — hop order is
    // resolved by name, not by record position.
    let mut head = forwarded_name.to_string();
    let mut visited: std::collections::HashSet<String> = [head.clone()].into_iter().collect();
    let mut min_ttl: Option<u32> = None;
    loop {
        if out.chain.len() >= MAX_CHAIN_DEPTH {
            // Only truncated when another hop actually remains.
            if cnames.iter().any(|(owner, _, _)| *owner == head) {
                out.chain_truncated = true;
            }
            break;
        }
        let Some((_, target, ttl)) = cnames.iter().find(|(owner, _, _)| *owner == head) else {
            break;
        };
        out.chain.push(target.clone());
        min_ttl = Some(min_ttl.map_or(*ttl, |m: u32| m.min(*ttl)));
        if !visited.insert(target.clone()) {
            break; // alias loop — stop following, keep what we saw
        }
        head = target.clone();
    }
    for (owner, addr, ttl) in addrs {
        if visited.contains(&owner) {
            min_ttl = Some(min_ttl.map_or(ttl, |m: u32| m.min(ttl)));
            out.addrs.push((addr, ttl));
        }
    }
    out.min_ttl = min_ttl;
    out
}

/// `true` when the response header carries the TC bit — the UDP answer
/// was cut and the full answer needs a TCP retry.
pub(crate) fn response_truncated(buf: &[u8]) -> bool {
    buf.len() >= HEADER_LEN && buf[2] & 0x02 != 0
}

/// Whether `resp` is plausibly the answer to our forwarded query: ID
/// match, QR set, and a first question echoing the canonical name
/// (case-insensitive — upstreams may apply 0x20 case randomization).
pub(crate) fn response_matches(resp: &[u8], id: u16, canonical: &str) -> bool {
    if resp.len() < HEADER_LEN
        || u16::from_be_bytes([resp[0], resp[1]]) != id
        || resp[2] & 0x80 == 0
    {
        return false;
    }
    let qd = u16::from_be_bytes([resp[4], resp[5]]);
    if qd < 1 {
        return false;
    }
    let Some((name, _)) = decode_name(resp, HEADER_LEN, true) else {
        return false;
    };
    name.eq_ignore_ascii_case(canonical)
}

/// `qtype` as a display label — common types by name, the rest as
/// `TYPE<n>` per RFC 3597.
pub(crate) fn qtype_name(qtype: u16) -> String {
    let name = match qtype {
        1 => "A",
        2 => "NS",
        5 => "CNAME",
        6 => "SOA",
        12 => "PTR",
        15 => "MX",
        16 => "TXT",
        28 => "AAAA",
        33 => "SRV",
        41 => "OPT",
        43 => "DS",
        46 => "RRSIG",
        47 => "NSEC",
        48 => "DNSKEY",
        65 => "HTTPS",
        255 => "ANY",
        _ => return format!("TYPE{qtype}"),
    };
    name.to_string()
}

/// `rcode` as a display label for audit details.
pub(crate) fn rcode_name(rcode: u8) -> String {
    let name = match rcode {
        0 => "noerror",
        1 => "formerr",
        2 => "servfail",
        3 => "nxdomain",
        4 => "notimp",
        5 => "refused",
        _ => return format!("RCODE{rcode}"),
    };
    name.to_string()
}

#[cfg(test)]
mod tests {
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
}
