//! Policy → BPF rule-table projection.
//!
//! The connect program cannot hold policy strings — every matchable
//! rule is compiled into a fixed [`RuleEntry`] map slot, and the deny
//! verdict's `rule=` audit text comes back through the parallel
//! [`RuleMeta`] list (entry index → source rule).
//!
//! Ordering contract (mirrors [`IpLayerEvaluator`](crate::warden::unotify::IpLayerEvaluator)):
//! every deny entry precedes every allow entry in the map, and deny
//! matching is address-only — so a scanned first match is the same
//! verdict the evaluator computes (deny wins over every allow source).
//! Within the deny run, host literals precede CIDRs — the evaluator's
//! check order — so an overlapping deny set reports the same
//! `decision=`/`rule=` labels on both IP routes.
//! Dynamic grants live in their own map so userspace can resync them
//! without touching the static program.

use std::net::IpAddr;

use crate::policy::{EgressDest, EgressProto, OutboundPolicy, host};

/// One rule/grant map slot — 56 bytes, shared by the IPv4 and IPv6
/// tables and by the static-rule and dynamic-grant maps.
///
/// Layout (all fields host-endian — the program reads them as scalars):
/// ```text
///   0  u32 addr[4]        destination words in ctx byte order
///                         (v4 uses [0]; v6 all four)
///  16  u32 mask[4]        per-word network masks (same encoding)
///  32  u32 proto          0 = any transport, else IPPROTO_* (6/17)
///  36  u32 port_raw       0 = any port, else the raw ctx->user_port value
///  40  u32 action         0 = deny, 1 = allow
///  44  u32 pad            (alignment)
///  48  u64 expires_at_ns  unix *nanoseconds* (the program compares
///                         against ktime_get_boot_ns + boot-epoch —
///                         same clock domain); 0 = never expires;
///                         the grant-map empty sentinel uses 1
///                         (always past)
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct RuleEntry {
    pub addr: [u32; 4],
    pub mask: [u32; 4],
    pub proto: u32,
    pub port_raw: u32,
    pub action: u32,
    pub pad: u32,
    /// Unix-epoch nanoseconds (`expires_at_unix_secs * 1e9`), 0 = never.
    pub expires_at_ns: u64,
}

pub const RULE_ENTRY_SIZE: usize = size_of::<RuleEntry>();
const _: () = assert!(RULE_ENTRY_SIZE == 56);

/// `action` values the program reads back.
pub const ACTION_DENY: u32 = 0;
pub const ACTION_ALLOW: u32 = 1;

/// Rule index the kernel writes when the default action fired (no rule
/// or grant matched). `usize::MAX`-safe: never indexes the meta table.
pub const RULE_IDX_NONE: u32 = u32::MAX;
/// Or-ed into `rule_idx` when a *grant* entry matched — the audit text
/// distinguishes grants from static rules.
pub const RULE_IDX_GRANT: u32 = 0x8000_0000;

/// Hard cap per family on the static-rule maps. The program is
/// generated with one lookup per slot, so this bound keeps generated
/// code under the verifier's instruction limit.
pub const MAX_RULES_PER_MAP: usize = 96;
/// Slots reserved in each grant map for dynamic allowlist entries
/// (one entry per `(addr, qual)` pair).
pub const GRANT_SLOTS: usize = 64;

/// Compiled projection of one `OutboundPolicy` for the connect hooks.
#[derive(Debug)]
pub struct RuleTable {
    /// Static rules (denies first, then allows), v4 map order.
    pub v4: Vec<RuleEntry>,
    /// Same for v6.
    pub v6: Vec<RuleEntry>,
    /// Default verdict when nothing matched (`!deny_all_others`).
    pub default_allow: bool,
    /// Per-entry audit metadata parallel to `v4`/`v6`
    /// (`v4[i]` ↔ `meta_v4[i]`).
    pub meta_v4: Vec<RuleMeta>,
    pub meta_v6: Vec<RuleMeta>,
}

/// Audit text for one map entry — what a deny event's `rule=` and
/// `decision=` fields spell.
#[derive(Clone, Debug)]
pub struct RuleMeta {
    pub decision: &'static str,
    pub rule: String,
}

/// `EgressProto` → the `IPPROTO_*` value `ctx->protocol` carries (0 =
/// any transport).
fn proto_num(p: EgressProto) -> u32 {
    match p {
        EgressProto::Tcp => libc::IPPROTO_TCP as u32,
        EgressProto::Udp => libc::IPPROTO_UDP as u32,
        EgressProto::Any => 0,
    }
}

/// Address family of a parsed CIDR/literal.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Family {
    V4,
    V6,
}

/// Parse `addr/prefix` into ctx-order addr+mask words plus the family.
///
/// `ip_layer_*` projections are already canonical; a sloppy CIDR with
/// host bits set (e.g. `10.0.0.1/24`) is masked to its network here —
/// the kernel compare ANDs the mask against both sides, so an
/// unmasked host bit would compile to a dead entry that matches
/// nothing. Masking is plain CIDR semantics, not a widening.
fn parse_cidr_words(cidr: &str) -> Result<(Family, [u32; 4], [u32; 4]), String> {
    let (addr_s, prefix_s) = cidr
        .split_once('/')
        .ok_or_else(|| format!("invalid CIDR '{cidr}' (missing prefix)"))?;
    let addr: IpAddr = addr_s
        .parse()
        .map_err(|_| format!("invalid CIDR '{cidr}' (bad address)"))?;
    let prefix: u32 = prefix_s
        .parse()
        .map_err(|_| format!("invalid CIDR '{cidr}' (bad prefix)"))?;
    let (fam, mut octets, max_prefix): (Family, Vec<u8>, u32) = match addr {
        IpAddr::V4(v4) => (Family::V4, v4.octets().to_vec(), 32),
        IpAddr::V6(v6) => (Family::V6, v6.octets().to_vec(), 128),
    };
    if prefix > max_prefix {
        return Err(format!(
            "invalid CIDR '{cidr}' (prefix exceeds address length)"
        ));
    }
    let mut mask_bytes = vec![0u8; octets.len()];
    for (i, b) in mask_bytes.iter_mut().enumerate() {
        let bits = prefix.saturating_sub(i as u32 * 8).min(8);
        *b = (0xffu32 << (8 - bits)) as u8;
    }
    // Host bits carry no meaning in a CIDR — mask them off so a sloppy
    // spelling cannot compile to an entry that matches nothing.
    for (i, b) in octets.iter_mut().enumerate() {
        *b &= mask_bytes[i];
    }
    let to_words = |bytes: &[u8]| -> [u32; 4] {
        let mut w = [0u32; 4];
        for (i, c) in bytes.chunks(4).enumerate() {
            // ctx carries the address bytes verbatim; a native-endian
            // u32 read of four address bytes is exactly this pattern.
            w[i] = u32::from_ne_bytes([c[0], c[1], c[2], c[3]]);
        }
        w
    };
    Ok((fam, to_words(&octets), to_words(&mask_bytes)))
}

/// All-ones mask of `fam` — exact-address matching (literals, grants).
fn full_mask(fam: Family) -> [u32; 4] {
    match fam {
        Family::V4 => [u32::MAX, 0, 0, 0],
        Family::V6 => [u32::MAX; 4],
    }
}

fn family_of_ip(ip: IpAddr) -> Family {
    match ip {
        IpAddr::V4(_) => Family::V4,
        IpAddr::V6(_) => Family::V6,
    }
}

/// The v6 twin of a v4 rule — `::ffff:a.b.c.d` with the v4 mask moved
/// past the mapped /96. A `connect` to an IPv4-mapped IPv6 destination
/// runs the AF_INET6 socket through `INET6_CONNECT`, not the v4 hook,
/// so every v4 entry needs this projection or the rule never sees it.
fn v4_mapped(addr: [u32; 4], mask: [u32; 4]) -> ([u32; 4], [u32; 4]) {
    const MAPPED: u32 = u32::from_ne_bytes([0, 0, 0xff, 0xff]);
    (
        [0, 0, MAPPED, addr[0]],
        [u32::MAX, u32::MAX, u32::MAX, mask[0]],
    )
}

/// Compile the policy's IP-layer projection into rule tables.
///
/// Semantics preserved from `IpLayerEvaluator::evaluate`:
/// - `deny host="*"` → a leading mask=0 deny entry in both families —
///   every destination matches it before any other rule scans
/// - deny rules are protocol/port-blind and precede all allow entries
/// - allow rules keep their `proto=`/`port=` qualifiers — the checks
///   are in the program, enforcing the same narrowing `unotify`'s
///   evaluator applies. The protocol read differs by route: this one
///   compares the socket's real `ctx->protocol` (`IPPROTO_*`), while
///   unotify derives the flow protocol from `SO_TYPE`
///   (`SOCK_STREAM`→tcp). A non-TCP stream socket (e.g. SCTP) is `tcp`
///   under unotify but its real protocol here, so a `proto=tcp` allow
///   matches it there and not here — the strict side is the safe side.
/// - `deny_all_others` becomes the program's default verdict
///
/// Fails closed: an over-limit rule set or an unparseable CIDR refuses
/// the launch instead of silently dropping rules.
pub fn compile(outbound: &OutboundPolicy) -> Result<RuleTable, String> {
    let mut v4 = Vec::new();
    let mut v6 = Vec::new();
    let mut meta_v4 = Vec::new();
    let mut meta_v6 = Vec::new();

    fn push(
        table: &mut Vec<RuleEntry>,
        meta: &mut Vec<RuleMeta>,
        entry: RuleEntry,
        m: RuleMeta,
    ) -> Result<(), String> {
        if table.len() >= MAX_RULES_PER_MAP {
            return Err(format!(
                "too many IP-layer rules for the cgroup-eBPF route (>{MAX_RULES_PER_MAP} \
                 per family) — reduce the rule set"
            ));
        }
        table.push(entry);
        meta.push(m);
        Ok(())
    }

    // Deny side first — every deny entry precedes every allow so the
    // program's first-match scan equals the evaluator's deny-precedence.
    // `deny host="*"` compiles to a leading mask=0 deny entry in both
    // families — the program needs no separate posture flag.
    if outbound.denied_hosts.iter().any(|h| h == "*") {
        let entry = RuleEntry {
            addr: [0; 4],
            mask: [0; 4],
            proto: 0,
            port_raw: 0,
            action: ACTION_DENY,
            pad: 0,
            expires_at_ns: 0,
        };
        for (t, m) in [(&mut v4, &mut meta_v4), (&mut v6, &mut meta_v6)] {
            push(
                t,
                m,
                entry,
                RuleMeta {
                    decision: "deny-host",
                    rule: "*".to_string(),
                },
            )?;
        }
    }
    // `denied_hosts` IP literals then `denied_cidrs` — the order
    // `unotify`'s evaluator checks them (`denied_literals` before
    // `denied_cidrs`), so a destination covered by both sources gets
    // the same `deny-host`/`rule=` audit label on both IP routes
    // (`ip_layer_denies`' flat CIDR-first list orders for coverage,
    // not for verdict labeling). `decision=` names the declaring
    // source (the vocabulary `unotify`'s evaluator reports):
    // `deny-cidr` for a CIDR rule, `deny-host` for a host literal —
    // including a `/32`/`/128` CIDR, which `deny-cidr` reports because
    // the *declaration* was a CIDR. Name-only `deny host=` rules are
    // name-layer entries (dns-gate/grants) — a connect arrives as an
    // address. Denies are read from the flat lists deliberately — the
    // evaluator sources them the same way, so a deny stored only in
    // `egress_rules` (a programmatic policy) is inert on *both* IP
    // routes, never just this one. Dedup is on the compiled
    // `(family, addr, mask)` form: two declarations that compile to
    // the same match set keep only the first emitted — the same entry
    // the evaluator's first-match would report.
    // One staged deny row: family + compiled words + `decision=` + `rule=`.
    type DenyRow = (Family, [u32; 4], [u32; 4], &'static str, String);
    let mut seen: Vec<(Family, [u32; 4], [u32; 4])> = Vec::new();
    let mut denies: Vec<DenyRow> = Vec::new();
    for h in &outbound.denied_hosts {
        if h == "*" {
            continue; // the leading wildcard deny above
        }
        if let Ok(addr) = h.parse::<IpAddr>() {
            let (fam, a, m) = parse_cidr_words(&host::ip_literal_cidr(addr))?;
            if !seen.contains(&(fam, a, m)) {
                seen.push((fam, a, m));
                // `rule=` is the literal's canonical spelling — the
                // evaluator reports `dest.to_string()` for a literal
                // deny, which is the same text (only the literal
                // itself can match this exact-match entry).
                denies.push((fam, a, m, "deny-host", addr.to_string()));
            }
        }
    }
    for cidr in &outbound.denied_cidrs {
        let (fam, a, m) = parse_cidr_words(cidr)?;
        if !seen.contains(&(fam, a, m)) {
            seen.push((fam, a, m));
            denies.push((fam, a, m, "deny-cidr", cidr.clone()));
        }
    }
    for (fam, addr, mask, decision, rule) in denies {
        let entry = RuleEntry {
            addr,
            mask,
            proto: 0,
            port_raw: 0,
            action: ACTION_DENY,
            pad: 0,
            expires_at_ns: 0,
        };
        let m = RuleMeta { decision, rule };
        match fam {
            Family::V4 => {
                // IPv4-mapped v6 destinations reach the v6 hook — the
                // same deny must live there too, in the same order.
                let (maddr, mmask) = v4_mapped(addr, mask);
                push(&mut v4, &mut meta_v4, entry, m.clone())?;
                push(
                    &mut v6,
                    &mut meta_v6,
                    RuleEntry {
                        addr: maddr,
                        mask: mmask,
                        ..entry
                    },
                    m,
                )?;
            }
            Family::V6 => push(&mut v6, &mut meta_v6, entry, m)?,
        }
    }

    // Allow side — qualifiers preserved. `allow host=` names are
    // name-layer only (a connect arrives as an address); they reach
    // this layer through the dynamic grant map, not the static table.
    for rule in outbound.egress_rules() {
        if !rule.allow {
            continue;
        }
        let proto = proto_num(rule.proto);
        let port_raw = rule.port.map(super::sys::raw_port).unwrap_or(0);
        let decision = if matches!(rule.dest, EgressDest::Cidr(_)) {
            "allow-cidr"
        } else {
            "allow-host"
        };
        let m = RuleMeta {
            decision,
            rule: rule.describe(),
        };
        match &rule.dest {
            EgressDest::Cidr(c) => {
                let (fam, addr, mask) = parse_cidr_words(c)?;
                let entry = RuleEntry {
                    addr,
                    mask,
                    proto,
                    port_raw,
                    action: ACTION_ALLOW,
                    pad: 0,
                    expires_at_ns: 0,
                };
                match fam {
                    Family::V4 => {
                        let (maddr, mmask) = v4_mapped(addr, mask);
                        push(&mut v4, &mut meta_v4, entry, m.clone())?;
                        push(
                            &mut v6,
                            &mut meta_v6,
                            RuleEntry {
                                addr: maddr,
                                mask: mmask,
                                ..entry
                            },
                            m,
                        )?;
                    }
                    Family::V6 => push(&mut v6, &mut meta_v6, entry, m)?,
                }
            }
            EgressDest::Host(h) if h == "*" => {
                // `allow host="*"` (or a port/proto-scoped wildcard)
                // covers every destination — a /0 in both families.
                for (fam, (addr, mask)) in [
                    (Family::V4, ([0, 0, 0, 0], [0, 0, 0, 0])),
                    (Family::V6, ([0, 0, 0, 0], [0, 0, 0, 0])),
                ] {
                    let entry = RuleEntry {
                        addr,
                        mask,
                        proto,
                        port_raw,
                        action: ACTION_ALLOW,
                        pad: 0,
                        expires_at_ns: 0,
                    };
                    match fam {
                        Family::V4 => push(&mut v4, &mut meta_v4, entry, m.clone())?,
                        Family::V6 => push(&mut v6, &mut meta_v6, entry, m.clone())?,
                    }
                }
            }
            EgressDest::Host(h) => {
                // Name-layer only when it fails to parse — grants
                // handle it at runtime.
                if let Ok(ip) = h.parse::<IpAddr>() {
                    let fam = family_of_ip(ip);
                    let (_, addr, _) = parse_cidr_words(&host::ip_literal_cidr(ip))?;
                    let mask = full_mask(fam);
                    let entry = RuleEntry {
                        addr,
                        mask,
                        proto,
                        port_raw,
                        action: ACTION_ALLOW,
                        pad: 0,
                        expires_at_ns: 0,
                    };
                    match fam {
                        Family::V4 => {
                            let (maddr, mmask) = v4_mapped(addr, mask);
                            push(&mut v4, &mut meta_v4, entry, m.clone())?;
                            push(
                                &mut v6,
                                &mut meta_v6,
                                RuleEntry {
                                    addr: maddr,
                                    mask: mmask,
                                    ..entry
                                },
                                m,
                            )?;
                        }
                        Family::V6 => push(&mut v6, &mut meta_v6, entry, m)?,
                    }
                }
            }
        }
    }

    Ok(RuleTable {
        v4,
        v6,
        default_allow: !outbound.deny_all_others,
        meta_v4,
        meta_v6,
    })
}

/// One dynamic grant flattened to map entries — one per (addr, qual)
/// pair so the program's compare stays a straight line. `expires_at`
/// is unix secs; the program enforces it against boot-time-adjusted
/// `ktime_get_boot_ns`.
pub fn grant_entries(
    addr: IpAddr,
    quals: &[crate::policy::GrantQual],
    expires_at: u64,
) -> Vec<(Family, RuleEntry)> {
    let fam = family_of_ip(addr);
    let (_, a, _) = parse_cidr_words(&host::ip_literal_cidr(addr))
        .unwrap_or_else(|_| unreachable!("literal CIDR always parses"));
    let mask = full_mask(fam);
    let expires_ns = expires_at.saturating_mul(1_000_000_000);
    let mut out = Vec::with_capacity(quals.len() * 2);
    for q in quals {
        let proto = proto_num(q.proto);
        let port_raw = q.port.map(super::sys::raw_port).unwrap_or(0);
        let entry = RuleEntry {
            addr: a,
            mask,
            proto,
            port_raw,
            action: ACTION_ALLOW,
            pad: 0,
            expires_at_ns: expires_ns,
        };
        out.push((fam, entry));
        if fam == Family::V4 {
            // A granted workload may still connect through an AF_INET6
            // socket to the mapped form — the v6 grant map needs the
            // twin or the grant reads as absent there.
            let (maddr, mmask) = v4_mapped(a, mask);
            out.push((
                Family::V6,
                RuleEntry {
                    addr: maddr,
                    mask: mmask,
                    ..entry
                },
            ));
        }
    }
    out
}

/// The never-live grant-map sentinel — `expires_at = 1` is always in
/// the past, so the program's expiry check skips the slot.
pub fn grant_sentinel() -> RuleEntry {
    RuleEntry {
        addr: [0; 4],
        mask: [0; 4],
        proto: 0,
        port_raw: 0,
        action: ACTION_ALLOW,
        pad: 0,
        expires_at_ns: 1,
    }
}
