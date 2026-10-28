//! Upstream-answer side of the wire codec: walk the answer section,
//! collect the destinations it reveals — CNAME/DNAME aliases, A/AAAA
//! records, and SVCB/HTTPS target names with address hints — and
//! answer the relay's freshness/correlation questions.
//!
//! Query decode and answer construction live in the parent module.

use super::super::canonical_name;
use super::{
    HEADER_LEN, RRTYPE_A, RRTYPE_AAAA, RRTYPE_CNAME, RRTYPE_DNAME, RRTYPE_HTTPS, RRTYPE_SVCB,
    decode_name, read_rr,
};

/// What the upstream answer looked like — the observational digest
/// that drives the audit record and the dynamic allow list.
pub(crate) struct ParsedResponse {
    /// RCODE from the upstream answer.
    pub rcode: u8,
    /// The alias chain followed from the forwarded query name, in
    /// order, each entry canonicalized: CNAME targets plus DNAME-
    /// synthesized names. Empty when the answer named no alias — the
    /// query name itself is not repeated here.
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
pub(super) const MAX_CHAIN_DEPTH: usize = 16;

/// SVCB/HTTPS `SvcParam` keys carrying destination material the name
/// layer must judge: `ipv4hint`/`ipv6hint` hold addresses a client may
/// dial without further lookups. Other params (alpn, port, ech,
/// dohpath…) shape the connection, not its destination name/address,
/// and stay uninterpreted.
pub(super) const SVC_PARAM_IPV4HINT: u16 = 4;
pub(super) const SVC_PARAM_IPV6HINT: u16 = 6;

/// Decoded SVCB/HTTPS RDATA: `SvcPriority`, `TargetName`, and the
/// `key/value` SvcParam list in wire order.
type SvcbRdata = (u16, String, Vec<(u16, Vec<u8>)>);

/// Decode an SVCB/HTTPS RDATA: `SvcPriority` + `TargetName` + the
/// `key/len/value` SvcParam list. `None` on a truncated name, a
/// param that overruns RDATA, or trailing bytes — an unparseable
/// record is undecoded evidence, not a partially-trusted one.
fn decode_svcb_rdata(buf: &[u8], off: usize, len: usize) -> Option<SvcbRdata> {
    let end = off.checked_add(len)?;
    let &hi = buf.get(off)?;
    let &lo = buf.get(off + 1)?;
    let priority = u16::from_be_bytes([hi, lo]);
    let (target, mut pos) = decode_name(buf, off + 2, true)?;
    if pos > end {
        return None;
    }
    let mut params = Vec::new();
    while pos < end {
        let fixed = buf.get(pos..pos + 4)?;
        let key = u16::from_be_bytes([fixed[0], fixed[1]]);
        let plen = u16::from_be_bytes([fixed[2], fixed[3]]) as usize;
        pos += 4;
        if pos + plen > end {
            return None;
        }
        params.push((key, buf[pos..pos + plen].to_vec()));
        pos += plen;
    }
    Some((priority, target, params))
}

/// The hop a DNAME synthesizes for `head`: a DNAME rewrites only
/// proper descendants of its owner (RFC 6672 — the owner itself is
/// not rewritten), replacing the owner suffix with the target. The
/// longest covering owner wins; `None` when no DNAME applies.
fn dname_target(dnames: &[(String, String, u32)], head: &str) -> Option<(String, u32)> {
    let (owner, target, ttl) = dnames
        .iter()
        .filter(|(owner, _, _)| {
            head.len() > owner.len()
                && head.ends_with(owner.as_str())
                && head.as_bytes()[head.len() - owner.len() - 1] == b'.'
        })
        .max_by_key(|(owner, _, _)| owner.len())?;
    let prefix = &head[..head.len() - owner.len() - 1];
    Some((canonical_name(&format!("{prefix}.{target}")), *ttl))
}

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
    let mut dnames: Vec<(String, String, u32)> = Vec::new();
    // SVCB/HTTPS targets the answer reveals — `(owner, target, ttl)`
    // for both AliasMode (priority 0) and ServiceMode (priority >0)
    // records. Both modes name a destination the workload may next
    // resolve or dial, so both join the policy chain.
    let mut svc_targets: Vec<(String, String, u32)> = Vec::new();
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
        let owner = canonical_name(&rr.name);
        match rr.rtype {
            RRTYPE_CNAME if rr.rdata_len >= 2 => match decode_name(buf, rr.rdata_off, true) {
                Some((target, end)) if end <= rr.rdata_off + rr.rdata_len => {
                    cnames.push((owner, canonical_name(&target), rr.ttl));
                }
                _ => {
                    decoded = false;
                    break;
                }
            },
            RRTYPE_DNAME if rr.rdata_len >= 2 => match decode_name(buf, rr.rdata_off, true) {
                Some((target, end)) if end <= rr.rdata_off + rr.rdata_len => {
                    dnames.push((owner, canonical_name(&target), rr.ttl));
                }
                _ => {
                    decoded = false;
                    break;
                }
            },
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
            RRTYPE_SVCB | RRTYPE_HTTPS if rr.rdata_len >= 3 => {
                // The record carries a destination name (TargetName —
                // an alias in AliasMode, the service endpoint name in
                // ServiceMode) and may embed dialable addresses in
                // ipv4hint/ipv6hint. Relaying it unjudged would let an
                // allowed query name smuggle a denied destination past
                // the name layer, so an undecodable payload fails the
                // whole answer rather than passing a partial read.
                match decode_svcb_rdata(buf, rr.rdata_off, rr.rdata_len) {
                    Some((_priority, target, params)) => {
                        let target = canonical_name(&target);
                        if !target.is_empty() {
                            svc_targets.push((owner.clone(), target, rr.ttl));
                        }
                        for (key, value) in params {
                            match key {
                                SVC_PARAM_IPV4HINT => {
                                    if value.len() % 4 != 0 {
                                        decoded = false;
                                        break;
                                    }
                                    for b in value.as_chunks::<4>().0 {
                                        addrs.push((
                                            owner.clone(),
                                            std::net::IpAddr::V4(std::net::Ipv4Addr::new(
                                                b[0], b[1], b[2], b[3],
                                            )),
                                            rr.ttl,
                                        ));
                                    }
                                }
                                SVC_PARAM_IPV6HINT => {
                                    if value.len() % 16 != 0 {
                                        decoded = false;
                                        break;
                                    }
                                    for b in value.as_chunks::<16>().0 {
                                        addrs.push((
                                            owner.clone(),
                                            std::net::IpAddr::V6(std::net::Ipv6Addr::from(*b)),
                                            rr.ttl,
                                        ));
                                    }
                                }
                                _ => {}
                            }
                        }
                    }
                    None => decoded = false,
                }
            }
            _ => {}
        }
    }
    out.decoded = decoded;

    // Follow every destination the answer reveals from the query name
    // — CNAME/DNAME alias hops and SVCB/HTTPS targets alike (an
    // AliasMode record redirects like a CNAME; a ServiceMode record
    // names the endpoint the workload connects to). Hop order is
    // resolved by name, not record position, expanding breadth-first
    // so every revealed name reaches the chain for policy re-judgment;
    // its visited set is also what authorizes A/AAAA/hint minting.
    // A DNAME whose owner is an ancestor of the current head
    // synthesizes the next hop by substituting its target for the
    // owner suffix (RFC 6672); the longest matching owner wins,
    // mirroring resolver behavior.
    let mut visited: std::collections::HashSet<String> =
        [forwarded_name.to_string()].into_iter().collect();
    let mut heads: std::collections::VecDeque<String> =
        [forwarded_name.to_string()].into_iter().collect();
    let mut min_ttl: Option<u32> = None;
    while let Some(head) = heads.pop_front() {
        let mut candidates: Vec<(String, u32)> = Vec::new();
        if let Some((target, ttl)) = cnames
            .iter()
            .find(|(owner, _, _)| *owner == head)
            .map(|(_, t, ttl)| (t.clone(), *ttl))
        {
            candidates.push((target, ttl));
        }
        if let Some((target, ttl)) = dname_target(&dnames, &head) {
            candidates.push((target, ttl));
        }
        candidates.extend(
            svc_targets
                .iter()
                .filter(|(owner, _, _)| *owner == head)
                .map(|(_, t, ttl)| (t.clone(), *ttl)),
        );
        for (target, ttl) in candidates {
            if out.chain.len() >= MAX_CHAIN_DEPTH {
                out.chain_truncated = true;
                break;
            }
            out.chain.push(target.clone());
            min_ttl = Some(min_ttl.map_or(ttl, |m: u32| m.min(ttl)));
            if visited.insert(target.clone()) {
                heads.push_back(target);
            }
            // A previously visited target still records — the alias
            // loop is evidence — but is never expanded twice.
        }
        if out.chain_truncated {
            break;
        }
    }
    if !heads.is_empty() {
        // The walk stopped with unexpanded heads — the recorded chain
        // is a prefix, never the whole alias/target sequence.
        out.chain_truncated = true;
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
