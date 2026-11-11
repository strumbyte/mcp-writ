//! Upstream-answer side of the wire codec: walk every section of the
//! answer — the answer section's CNAME/DNAME aliases, A/AAAA records,
//! and SVCB/HTTPS target names with address hints feed the chain and
//! grant minting; authority/additional records decode under the same
//! rules and surface their destinations for deny judgment — and
//! answer the relay's freshness/correlation questions.
//!
//! Query decode and answer construction live in the parent module.

use super::super::canonical_name;
use super::{
    HEADER_LEN, RRTYPE_A, RRTYPE_AAAA, RRTYPE_AFSDB, RRTYPE_AMTRELAY, RRTYPE_CNAME, RRTYPE_DNAME,
    RRTYPE_HIP, RRTYPE_HTTPS, RRTYPE_IPSECKEY, RRTYPE_KX, RRTYPE_LP, RRTYPE_MB, RRTYPE_MD,
    RRTYPE_MF, RRTYPE_MG, RRTYPE_MR, RRTYPE_MX, RRTYPE_NAPTR, RRTYPE_NS, RRTYPE_NSAP_PTR,
    RRTYPE_NSEC, RRTYPE_OPT, RRTYPE_PTR, RRTYPE_PX, RRTYPE_RT, RRTYPE_SOA, RRTYPE_SRV, RRTYPE_SVCB,
    RRTYPE_TALINK, RRTYPE_URI, RRTYPE_WKS, Rr, decode_name, read_rr,
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
    /// Names the answer's destination-bearing records and the
    /// authority/additional sections reveal: owner names of
    /// destination-carrying records plus CNAME/DNAME/SVCB targets and
    /// the NS/PTR/MX/KX/SRV/NAPTR/PX/TALINK/IPSECKEY/HIP/URI/AMTRELAY
    /// RDATA names. The relay ships their bytes to the workload, so
    /// the full name policy judges them — but they never mint grants.
    pub extra_names: Vec<String>,
    /// Addresses the authority/additional sections reveal — A/AAAA
    /// records and SVCB/HTTPS hints outside the answer chain. Checked
    /// against the explicit address denies; they never mint grants.
    pub extra_addrs: Vec<std::net::IpAddr>,
    /// `false` when the answer's wire form could not be fully walked —
    /// any section, including a malformed authority/additional record,
    /// OPT violation, or trailing bytes — so the record says the parse
    /// was partial instead of implying an empty observation.
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

/// Decode the domain name inside `rr`'s RDATA after `prefix` bytes of
/// fixed fields (NS/PTR = 0, MX/KX = preference, SRV = priority+weight+
/// port), canonicalized. `None` when the name does not decode or would
/// read past the record — undecoded evidence, not a partial read.
fn decode_named_rdata(buf: &[u8], rr: &Rr<'_>, prefix: usize) -> Option<String> {
    let end = rr.rdata_off.checked_add(rr.rdata_len)?;
    let start = rr.rdata_off.checked_add(prefix)?;
    if start > end {
        return None;
    }
    let (name, stop) = decode_name(buf, start, true)?;
    if stop > end {
        return None;
    }
    Some(canonical_name(&name))
}

/// Decode a NAPTR replacement name: ORDER + PREFERENCE + three
/// length-prefixed character-strings + a domain name. `None` on any
/// truncation or overrun — the whole record is judged or nothing is.
fn decode_naptr_rdata(buf: &[u8], rr: &Rr<'_>) -> Option<String> {
    let end = rr.rdata_off.checked_add(rr.rdata_len)?;
    let mut pos = rr.rdata_off.checked_add(4)?;
    for _ in 0..3 {
        let len = *buf.get(pos)? as usize;
        pos = pos.checked_add(1 + len)?;
        if pos > end {
            return None;
        }
    }
    let (name, stop) = decode_name(buf, pos, true)?;
    if stop > end {
        return None;
    }
    Some(canonical_name(&name))
}

/// Whether `rtype`'s RDATA can carry a destination — the complete set
/// of destination-bearing record types this gate judges. Types left
/// out are genuinely opaque for destination policy: DNSSEC material
/// whose names are chain metadata, not dial targets (RRSIG signer
/// name, NXT next-name, NSEC3/DS/DNSKEY/DSO, TSIG/TKEY algorithm
/// names), crypto/identity blobs (TXT/CAA/TLSA/SSHFP/HINFO/KEY/CERT),
/// mailbox-agent names the workload never dials (MINFO/RP), locator
/// and prefix identifiers rather than socket destinations (APL, NID,
/// L32, L64), and X.25/ISDN numbering records. Whatever a still-opaque
/// type's bytes may embed, they mint nothing — and a name a workload
/// derives from them resolves only through this gate, where it is
/// judged on its own query.
fn rdata_names_target(rtype: u16) -> bool {
    matches!(
        rtype,
        // Name at RDATA offset 0: nameserver, alias targets, agent and
        // mailbox hosts, NSAP pointers.
        RRTYPE_NS | RRTYPE_PTR | RRTYPE_MD | RRTYPE_MF | RRTYPE_MB | RRTYPE_MG | RRTYPE_MR
        | RRTYPE_NSAP_PTR
        // Name after one u16 (preference/subtype/priority).
        | RRTYPE_MX | RRTYPE_KX | RRTYPE_AFSDB | RRTYPE_RT | RRTYPE_LP
        // SRV's three u16s precede its target; NAPTR's walks strings;
        // PX and TALINK pack two names; IPSECKEY/AMTRELAY gateways are
        // an address or a name; HIP lists rendezvous servers; URI's
        // authority host is a dial destination.
        | RRTYPE_SRV | RRTYPE_NAPTR | RRTYPE_PX | RRTYPE_TALINK | RRTYPE_IPSECKEY
        | RRTYPE_HIP | RRTYPE_URI | RRTYPE_AMTRELAY
    )
}

/// The destinations a record's RDATA reveals — names judged by the
/// name policy, addresses by the address deny rules. The record owner
/// is collected by the caller, not here.
#[derive(Default)]
struct RdataDest {
    names: Vec<String>,
    addrs: Vec<std::net::IpAddr>,
}

impl RdataDest {
    fn one_name(name: String) -> Self {
        Self {
            names: vec![name],
            addrs: Vec::new(),
        }
    }
}

/// `n` domain names packed back-to-back inside `rr`'s RDATA after
/// `prefix` bytes of fixed fields, filling the record exactly (PX has
/// preference + two names; TALINK has two). `None` on any undecodable
/// or overrunning name — undecoded evidence, not a partial read.
fn decode_name_seq(buf: &[u8], rr: &Rr<'_>, prefix: usize, n: usize) -> Option<Vec<String>> {
    let end = rr.rdata_off.checked_add(rr.rdata_len)?;
    let mut pos = rr.rdata_off.checked_add(prefix)?;
    let mut names = Vec::with_capacity(n);
    for _ in 0..n {
        let (name, stop) = decode_name(buf, pos, true)?;
        if stop > end {
            return None;
        }
        names.push(canonical_name(&name));
        pos = stop;
    }
    (pos == end).then_some(names)
}

/// A fixed-length address field at `off` — IPv4 (4 bytes) or IPv6
/// (16) per `v6`. `None` when it would read past the record.
fn decode_addr_field(buf: &[u8], off: usize, end: usize, v6: bool) -> Option<std::net::IpAddr> {
    let len = if v6 { 16 } else { 4 };
    let b = buf.get(off..off.checked_add(len)?)?;
    if off + len > end {
        return None;
    }
    Some(if v6 {
        std::net::IpAddr::V6(std::net::Ipv6Addr::from(<[u8; 16]>::try_from(b).ok()?))
    } else {
        std::net::IpAddr::V4(std::net::Ipv4Addr::new(b[0], b[1], b[2], b[3]))
    })
}

/// Whether `name` is a DNS name the wire could legitimately carry —
/// non-empty labels of at most 63 ASCII alphanumeric/hyphen/underscore
/// bytes joined by dots, at most 253 bytes total. Anything else is not
/// a name the name layer can judge.
fn is_dns_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 253
        && name.split('.').all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && l.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        })
}

/// The hosts a URI RR target dials, read under RFC 3986 authority
/// rules — usually one, but SIP carries the routing override `maddr`
/// alongside the base host. An empty vec covers URIs provably
/// carrying no dial target — opaque forms whose embedded names
/// resolve back through this gate (`mailto:`, `xmpp:`, …) or carry
/// none at all (`urn:`, `data:`).
/// `Err` marks spellings a client could read with a host the gate
/// never judged — unjudgeable, so the record must fail closed rather
/// than relay a guessed host: `\` anywhere in a special-scheme target
/// (WHATWG folds it to `/` and can redraw the authority boundary), a
/// `\` inside the authority itself, an empty authority (`scheme:///x`
/// — special schemes read the next segment as host), `//`-less
/// targets of WHATWG special schemes (`http:host`, `file:/path`),
/// and `//`-less targets of unknown schemes — URI RRs resolve under
/// scheme-specific rules (RFC 7553), so only schemes whose grammar
/// this parser knows are opaque-passed.
fn uri_host(target: &str) -> Result<Vec<&str>, ()> {
    let (scheme, rest) = target.split_once(':').ok_or(())?;
    if scheme.is_empty()
        || !scheme.bytes().enumerate().all(|(i, b)| {
            if i == 0 {
                b.is_ascii_alphabetic()
            } else {
                b.is_ascii_alphanumeric() || matches!(b, b'+' | b'-' | b'.')
            }
        })
    {
        return Err(());
    }
    if matches!(
        scheme.to_ascii_lowercase().as_str(),
        "http" | "https" | "ws" | "wss" | "ftp" | "file"
    ) && (rest.contains('\\') || !rest.starts_with("//"))
    {
        return Err(());
    }
    let Some(auth) = rest.strip_prefix("//") else {
        return opaque_scheme_hosts(&scheme.to_ascii_lowercase(), rest);
    };
    let authority = auth.split(['/', '?', '#']).next().unwrap_or(auth);
    if authority.is_empty() || authority.contains('\\') {
        return Err(());
    }
    let host = authority_host(authority)?;
    Ok(vec![host])
}

/// `user@host[:port]` / `[v6]:port` authority's host part.
fn authority_host(authority: &str) -> Result<&str, ()> {
    let hostport = authority.rsplit('@').next().unwrap_or(authority);
    let host = match hostport.strip_prefix('[') {
        Some(b) => b.split(']').next().unwrap_or_default(),
        None => hostport.split(':').next().unwrap_or_default(),
    };
    if host.is_empty() || host.contains('%') {
        return Err(());
    }
    Ok(host)
}

/// The dial targets of a `//`-less URI RR, for the schemes whose
/// grammar puts them there. An empty vec only for schemes proven to
/// carry no direct destination — opaque identifiers and mailbox/IM
/// addresses whose embedded domain resolves through this gate on its
/// own query; every other scheme's grammar is unknown territory and
/// fails closed rather than guess.
fn opaque_scheme_hosts<'a>(scheme: &str, rest: &'a str) -> Result<Vec<&'a str>, ()> {
    match scheme {
        // RFC 3261 (SIP): `user@host[:port];params` — the `maddr`
        // parameter overrides the host as the actual dial target, so
        // every `maddr` value is judged alongside the host. `?`
        // headers and `;` inside userinfo make the boundary
        // unrecoverable — fail closed.
        "sip" | "sips" => {
            if rest.contains('?') || rest.contains('\\') {
                return Err(());
            }
            let authority = rest.split(';').next().unwrap_or(rest);
            if !authority.contains('@') && rest[authority.len()..].contains('@') {
                // A `;` inside userinfo would split the authority
                // wrong — the real host sits past it, unjudged.
                return Err(());
            }
            let mut hosts = vec![authority_host(authority)?];
            for param in rest[authority.len()..].split(';').skip(1) {
                if let Some(v) = param
                    .split_once('=')
                    .filter(|(k, _)| k.eq_ignore_ascii_case("maddr"))
                    .map(|(_, v)| v)
                {
                    hosts.push(authority_host(v)?);
                }
            }
            Ok(hosts)
        }
        // RFC 7064 (STUN/TURN): `host[:port][?transport=]` sits
        // directly after the colon; an IP literal there is dialed
        // without DNS, so it must reach the address rules. `;` is
        // not part of the grammar — unjudgeable params, fail closed.
        "stun" | "stuns" | "turn" | "turns" => {
            if rest.contains(';') || rest.contains('\\') {
                return Err(());
            }
            let authority = rest.split('?').next().unwrap_or(rest);
            Ok(vec![authority_host(authority)?])
        }
        // Mailbox/IM/acct addresses embed a domain the client resolves
        // via DNS — this gate judges that query. E.164 numbers, URNs,
        // inline data, message IDs, geo coordinates, and browser-local
        // references name no host at all.
        "mailto" | "tel" | "sms" | "urn" | "data" | "mid" | "cid" | "acct" | "im" | "pres"
        | "xmpp" | "news" | "nntp" | "geo" | "about" | "javascript" | "blob" | "dns" | "tag" => {
            Ok(Vec::new())
        }
        _ => Err(()),
    }
}

/// Every destination an RDATA reveals — the nameserver of NS/AFSDB,
/// the exchange of MX/KX/RT/LP, the target of SRV, the replacement of
/// NAPTR, the pointed-to name of PTR/MD/MF/MB/MG/MR/NSAP-PTR, PX and
/// TALINK's name pairs, IPSECKEY/AMTRELAY's gateway or relay (address
/// or name), HIP's rendezvous servers, URI's authority host. `None`
/// when the RDATA does not decode; callers treat that as malformed,
/// never as "no destination". Caller only consults this for
/// `rdata_names_target` types.
fn decode_rdata_dest(buf: &[u8], rr: &Rr<'_>) -> Option<RdataDest> {
    let end = rr.rdata_off.checked_add(rr.rdata_len)?;
    let dest = match rr.rtype {
        RRTYPE_MX | RRTYPE_KX | RRTYPE_AFSDB | RRTYPE_RT | RRTYPE_LP => {
            RdataDest::one_name(decode_named_rdata(buf, rr, 2)?)
        }
        RRTYPE_SRV => RdataDest::one_name(decode_named_rdata(buf, rr, 6)?),
        RRTYPE_NAPTR => RdataDest::one_name(decode_naptr_rdata(buf, rr)?),
        RRTYPE_PX => RdataDest {
            names: decode_name_seq(buf, rr, 2, 2)?,
            addrs: Vec::new(),
        },
        RRTYPE_TALINK => RdataDest {
            names: decode_name_seq(buf, rr, 0, 2)?,
            addrs: Vec::new(),
        },
        RRTYPE_IPSECKEY => {
            // precedence, gateway type, algorithm, then a gateway
            // (none / IPv4 / IPv6 / name) and an opaque public key.
            if rr.rdata_len < 3 {
                return None;
            }
            let gw_off = rr.rdata_off + 3;
            let mut dest = RdataDest::default();
            match buf[rr.rdata_off + 1] {
                0 => {}
                1 => dest.addrs.push(decode_addr_field(buf, gw_off, end, false)?),
                2 => dest.addrs.push(decode_addr_field(buf, gw_off, end, true)?),
                3 => dest.names.push(decode_named_rdata(buf, rr, 3)?),
                _ => return None,
            }
            dest
        }
        RRTYPE_AMTRELAY => {
            // precedence + discovery/relay-type byte, then the relay —
            // none / IPv4 / IPv6 / name — filling the record.
            if rr.rdata_len < 2 {
                return None;
            }
            let relay_off = rr.rdata_off + 2;
            let mut dest = RdataDest::default();
            match buf[rr.rdata_off + 1] & 0x7F {
                0 if relay_off == end => {}
                1 => dest
                    .addrs
                    .push(decode_addr_field(buf, relay_off, end, false)?),
                2 => dest
                    .addrs
                    .push(decode_addr_field(buf, relay_off, end, true)?),
                3 => {
                    let (name, stop) = decode_name(buf, relay_off, true)?;
                    if stop != end {
                        return None;
                    }
                    dest.names.push(canonical_name(&name));
                }
                _ => return None,
            }
            dest
        }
        RRTYPE_HIP => {
            // HIT length, PK algorithm, PK length, public key, HIT —
            // then rendezvous server names packed to the record end.
            if rr.rdata_len < 4 {
                return None;
            }
            let hit_len = buf[rr.rdata_off] as usize;
            let pk_len =
                u16::from_be_bytes([buf[rr.rdata_off + 2], buf[rr.rdata_off + 3]]) as usize;
            let mut pos = rr
                .rdata_off
                .checked_add(4)?
                .checked_add(pk_len)?
                .checked_add(hit_len)?;
            if pos > end {
                return None;
            }
            let mut dest = RdataDest::default();
            while pos < end {
                let (name, stop) = decode_name(buf, pos, true)?;
                if stop > end {
                    return None;
                }
                dest.names.push(canonical_name(&name));
                pos = stop;
            }
            dest
        }
        RRTYPE_URI => {
            // priority, weight, then a URI target — its authority host
            // is the connect destination, folded to canonical form and
            // judged as an address or a name. Encoded spellings and
            // non-name hosts are unjudgeable — malformed, not skipped.
            if rr.rdata_len < 4 {
                return None;
            }
            let target = std::str::from_utf8(&buf[rr.rdata_off + 4..end]).ok()?;
            let mut dest = RdataDest::default();
            for host in uri_host(target).ok()? {
                let canonical = canonical_name(host);
                match canonical.parse::<std::net::IpAddr>() {
                    // The WHATWG fold already flattened every numeric
                    // IPv4 spelling — hex, octal, decimal, short —
                    // into the dotted form the deny rules judge.
                    Ok(ip) => dest.addrs.push(ip),
                    Err(_) if is_dns_name(&canonical) => dest.names.push(canonical),
                    Err(_) => return None,
                }
            }
            dest
        }
        _ => RdataDest::one_name(decode_named_rdata(buf, rr, 0)?),
    };
    Some(dest)
}

/// Validate an SOA/NSEC RDATA structurally — names must decode inside
/// the record and trailing fields must be well-formed. Their names are
/// zone metadata (the zone's primary server and responsible mailbox;
/// the NSEC proof boundary), never destinations the workload dials, so
/// nothing is collected or returned: `Some(())` is well-formed,
/// `None` marks the record — and response — undecodable.
fn validate_metadata_rdata(buf: &[u8], rr: &Rr<'_>) -> Option<()> {
    let end = rr.rdata_off.checked_add(rr.rdata_len)?;
    match rr.rtype {
        RRTYPE_SOA => {
            let (_, mid) = decode_name(buf, rr.rdata_off, true)?;
            if mid > end {
                return None;
            }
            let (_, tail) = decode_name(buf, mid, true)?;
            // SERIAL/REFRESH/RETRY/EXPIRE/MINIMUM — five u32s exactly.
            (tail.checked_add(20)? == end).then_some(())
        }
        RRTYPE_NSEC => {
            let (_, mut pos) = decode_name(buf, rr.rdata_off, true)?;
            // Type bitmaps (RFC 4034 §4.1.2): at least one
            // (window, length 1..=32, bitmap) block, window
            // numbers strictly increasing, blocks tiled to `end`.
            let mut prev_window: Option<u8> = None;
            while pos < end {
                if end - pos < 2 {
                    return None;
                }
                let window = buf[pos];
                let len = buf[pos + 1] as usize;
                if !(1..=32).contains(&len)
                    || pos + 2 + len > end
                    || prev_window.is_some_and(|w| window <= w)
                {
                    return None;
                }
                prev_window = Some(window);
                pos += 2 + len;
            }
            prev_window.is_some().then_some(())
        }
        _ => None,
    }
}

/// Judge one authority/additional record. `read_rr` already bounded
/// the record on the wire; here the OPT placement rules hold (RFC
/// 6891 — additional section only, root owner, at most one per
/// message) and destination-carrying RDATA decode under the same
/// rules the answer section applies. Returns `false` to mark the
/// whole response undecoded — an unparseable record in any section
/// means the relay would ship bytes the checks never walked.
fn read_extra_rr(
    buf: &[u8],
    rr: &Rr<'_>,
    in_additional: bool,
    opt_seen: &mut bool,
    extra_names: &mut Vec<String>,
    extra_addrs: &mut Vec<std::net::IpAddr>,
) -> bool {
    if rr.rtype == RRTYPE_OPT {
        return in_additional && rr.name.is_empty() && !std::mem::replace(opt_seen, true);
    }
    if rr.class != 1 {
        // IN is the only class this resolver serves; foreign-class
        // records are not destinations for the allow list.
        return true;
    }
    let owner = canonical_name(&rr.name);
    match rr.rtype {
        RRTYPE_CNAME | RRTYPE_DNAME => match decode_name(buf, rr.rdata_off, true) {
            Some((target, end)) if end <= rr.rdata_off + rr.rdata_len => {
                extra_names.push(owner);
                extra_names.push(canonical_name(&target));
                true
            }
            _ => false,
        },
        RRTYPE_A if rr.rdata_len == 4 => {
            extra_names.push(owner);
            let b = &buf[rr.rdata_off..rr.rdata_off + 4];
            extra_addrs.push(std::net::IpAddr::V4(std::net::Ipv4Addr::new(
                b[0], b[1], b[2], b[3],
            )));
            true
        }
        RRTYPE_AAAA if rr.rdata_len == 16 => {
            extra_names.push(owner);
            let b: [u8; 16] = buf[rr.rdata_off..rr.rdata_off + 16].try_into().unwrap();
            extra_addrs.push(std::net::IpAddr::V6(std::net::Ipv6Addr::from(b)));
            true
        }
        RRTYPE_SVCB | RRTYPE_HTTPS if rr.rdata_len >= 3 => {
            match decode_svcb_rdata(buf, rr.rdata_off, rr.rdata_len) {
                Some((_priority, target, params)) => {
                    extra_names.push(owner);
                    let target = canonical_name(&target);
                    if !target.is_empty() {
                        extra_names.push(target);
                    }
                    for (key, value) in params {
                        match key {
                            SVC_PARAM_IPV4HINT => {
                                if value.len() % 4 != 0 {
                                    return false;
                                }
                                for b in value.as_chunks::<4>().0 {
                                    extra_addrs.push(std::net::IpAddr::V4(
                                        std::net::Ipv4Addr::new(b[0], b[1], b[2], b[3]),
                                    ));
                                }
                            }
                            SVC_PARAM_IPV6HINT => {
                                if value.len() % 16 != 0 {
                                    return false;
                                }
                                for b in value.as_chunks::<16>().0 {
                                    extra_addrs
                                        .push(std::net::IpAddr::V6(std::net::Ipv6Addr::from(*b)));
                                }
                            }
                            _ => {}
                        }
                    }
                    true
                }
                None => false,
            }
        }
        RRTYPE_WKS if rr.rdata_len >= 5 => {
            // Ancient but address-bearing: the first four RDATA bytes
            // name an IPv4 destination.
            extra_names.push(owner);
            let b = &buf[rr.rdata_off..rr.rdata_off + 4];
            extra_addrs.push(std::net::IpAddr::V4(std::net::Ipv4Addr::new(
                b[0], b[1], b[2], b[3],
            )));
            true
        }
        rtype if rdata_names_target(rtype) => {
            // These RDATA carry destinations the relay ships — they
            // decode completely or the answer is undecodable.
            match decode_rdata_dest(buf, rr) {
                Some(dest) => {
                    extra_names.push(owner);
                    extra_names.extend(dest.names.into_iter().filter(|n| !n.is_empty()));
                    extra_addrs.extend(dest.addrs);
                    true
                }
                None => false,
            }
        }
        RRTYPE_SOA | RRTYPE_NSEC => {
            // Zone metadata, not a destination: validated so malformed
            // bytes still fail closed, but none of its names — owner
            // included — is a policy name.
            validate_metadata_rdata(buf, rr).is_some()
        }
        _ => true,
    }
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
        extra_names: Vec::new(),
        extra_addrs: Vec::new(),
        decoded: false,
    };
    if buf.len() < HEADER_LEN {
        return out;
    }
    out.rcode = buf[3] & 0x0F;
    let qd = u16::from_be_bytes([buf[4], buf[5]]) as usize;
    let an = u16::from_be_bytes([buf[6], buf[7]]) as usize;
    let ns = u16::from_be_bytes([buf[8], buf[9]]) as usize;
    let ar = u16::from_be_bytes([buf[10], buf[11]]) as usize;

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
        if rr.rtype == RRTYPE_OPT {
            // OPT belongs only to the additional section (RFC 6891) —
            // a pseudo-RR in the answer section is malformed, and its
            // CLASS field is a payload size, not IN, so it must be
            // refused before the class check would silently skip it.
            decoded = false;
            break;
        }
        if rr.class != 1 {
            // IN is the only class this resolver serves; foreign-class
            // records are not destinations for the allow list.
            continue;
        }
        let owner = canonical_name(&rr.name);
        match rr.rtype {
            // Deliberate hardening (not a verbatim move of the pre-split
            // parser): the alias target must decode *and* end within its
            // own RDATA. A target that silently read into the next
            // record's bytes used to be relayed as a chain hop; a name
            // that failed to decode at all was dropped while the rest of
            // the answer shipped. Both now mark the answer undecoded —
            // the caller SERVFAILs rather than relay a partial read.
            RRTYPE_CNAME => match decode_name(buf, rr.rdata_off, true) {
                Some((target, end)) if end <= rr.rdata_off + rr.rdata_len => {
                    let target = canonical_name(&target);
                    // The relay ships this record whether or not the
                    // chain walk reaches its owner — an unrelated
                    // owner's alias still names a destination the name
                    // policy never sees. Feed both ends through the
                    // deny sets so it cannot smuggle a denied target.
                    out.extra_names.push(owner.clone());
                    out.extra_names.push(target.clone());
                    cnames.push((owner, target, rr.ttl));
                }
                _ => {
                    decoded = false;
                    break;
                }
            },
            RRTYPE_DNAME => match decode_name(buf, rr.rdata_off, true) {
                Some((target, end)) if end <= rr.rdata_off + rr.rdata_len => {
                    let target = canonical_name(&target);
                    out.extra_names.push(owner.clone());
                    out.extra_names.push(target.clone());
                    dnames.push((owner, target, rr.ttl));
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
            RRTYPE_WKS if rr.rdata_len >= 5 => {
                // Address-bearing ancient type — judged, never minted.
                out.extra_names.push(owner);
                let b = &buf[rr.rdata_off..rr.rdata_off + 4];
                out.extra_addrs
                    .push(std::net::IpAddr::V4(std::net::Ipv4Addr::new(
                        b[0], b[1], b[2], b[3],
                    )));
            }
            rtype if rdata_names_target(rtype) => {
                // Destination-bearing RDATA in the answer itself are
                // relayed verbatim — the revealed targets join the
                // extra sets for the same policy judgment (never the
                // chain: these records are data, not aliases).
                match decode_rdata_dest(buf, &rr) {
                    Some(dest) => {
                        out.extra_names.push(owner);
                        out.extra_names
                            .extend(dest.names.into_iter().filter(|n| !n.is_empty()));
                        out.extra_addrs.extend(dest.addrs);
                    }
                    None => {
                        decoded = false;
                        break;
                    }
                }
            }
            // Metadata, not destinations — structure validated, nothing
            // collected; an invalid record is undecodable.
            RRTYPE_SOA | RRTYPE_NSEC if validate_metadata_rdata(buf, &rr).is_none() => {
                decoded = false;
                break;
            }
            _ => {}
        }
    }

    // One owner carrying two *different* alias targets is malformed
    // wire data — an owner may hold exactly one CNAME and one
    // applicable DNAME — and following only the first would relay the
    // rest unjudged while a downstream resolver might pick either.
    // Fail closed like every other undecodable shape. Identical
    // duplicate targets are tolerated (some upstreams emit them);
    // two same-owner DNAMEs with different targets are refused too,
    // while DNAMEs at different owners stay the RFC-longest-match
    // selection `dname_target` performs.
    if decoded {
        for aliases in [&cnames, &dnames] {
            let mut selected: std::collections::HashMap<&str, &str> =
                std::collections::HashMap::new();
            for (owner, target, _) in aliases {
                if selected
                    .insert(owner.as_str(), target.as_str())
                    .is_some_and(|prev| prev != target.as_str())
                {
                    decoded = false;
                }
            }
        }
    }

    // Authority and additional sections are walked just as completely —
    // the relay ships their bytes verbatim, so a record this layer
    // could not parse would carry destinations the name/address checks
    // never saw. Destination-carrying records decode under the same
    // rules as the answer section; what they reveal is judged for
    // denies only, never minted into grants.
    if decoded {
        let mut opt_seen = false;
        for (count, in_additional) in [(ns, false), (ar, true)] {
            for _ in 0..count {
                let Some((rr, next)) = read_rr(buf, pos) else {
                    decoded = false;
                    break;
                };
                pos = next;
                if !read_extra_rr(
                    buf,
                    &rr,
                    in_additional,
                    &mut opt_seen,
                    &mut out.extra_names,
                    &mut out.extra_addrs,
                ) {
                    decoded = false;
                    break;
                }
            }
            if !decoded {
                break;
            }
        }
        if decoded && pos != buf.len() {
            // Trailing bytes after the last record — the message is
            // malformed, not partially relayed.
            decoded = false;
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
/// (case-insensitive — upstreams may apply 0x20 case randomization),
/// type, and class. A same-name answer under another type or class is
/// not the exchange we forwarded.
pub(crate) fn response_matches(
    resp: &[u8],
    id: u16,
    canonical: &str,
    qtype: u16,
    qclass: u16,
) -> bool {
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
    let Some((name, pos)) = decode_name(resp, HEADER_LEN, true) else {
        return false;
    };
    if !name.eq_ignore_ascii_case(canonical) {
        return false;
    }
    let Some(qf) = resp.get(pos..pos + 4) else {
        return false;
    };
    u16::from_be_bytes([qf[0], qf[1]]) == qtype && u16::from_be_bytes([qf[2], qf[3]]) == qclass
}
