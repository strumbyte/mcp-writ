//! Outbound/egress policy surface — `EgressProto`, `EgressDest`,
//! `EgressRule`, `GrantQual`, `OutboundPolicy`, and the deny-precedence
//! plus host-canonicalization helpers that act on them. Re-exported
//! from `policy` (`pub use outbound::*`) so `crate::policy::X` spellings
//! stay stable.

use super::*;

/// Transport protocol a structured egress rule applies to (`proto=`).
///
/// `allow` rules default to `Tcp` — a pre-schema `allow` rule only ever
/// described TCP reachability, so the default must not silently widen
/// it to UDP. `deny` rules are protocol-blind (`Any` — the parse layer
/// refuses an explicit `proto=` on `deny` so a narrowing can never be
/// silently mis-scoped).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum EgressProto {
    Tcp,
    Udp,
    /// Both transports. `proto="any"` on an allow rule; also the deny
    /// rule's fixed protocol coverage.
    Any,
}

impl EgressProto {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
            Self::Any => "any",
        }
    }

    pub fn parse(value: &str) -> Result<Self, String> {
        match value {
            "tcp" => Ok(Self::Tcp),
            "udp" => Ok(Self::Udp),
            "any" => Ok(Self::Any),
            other => Err(format!("unknown proto '{other}', expected tcp|udp|any")),
        }
    }

    /// Whether a rule carrying this protocol covers a flow of protocol
    /// `flow`. `Any` covers both transports; an exact tag covers itself.
    pub fn covers(self, flow: EgressProto) -> bool {
        self == Self::Any || self == flow
    }
}

/// Destination a structured egress rule names — the post-normalization
/// `host=`/`cidr=` target. A `Host("*")` destination is a rule that
/// covers every destination (a `allow host="*"` carrying a `proto=`
/// attribute, or a bare-port `allow host="443"` rule, which is
/// destination-independent by definition).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum EgressDest {
    /// `host=` — a name-layer destination. May be an FQDN, wildcard,
    /// `"*"`, or an IP literal (a literal is an IP-layer rule too).
    Host(String),
    /// `cidr=` — a canonical `addr/prefix` IP-layer destination.
    Cidr(String),
    /// `unix=` — an AF_UNIX opt-in grant (schema v2, allow only). The
    /// value is the socket's filesystem path, or `"*"` for the whole
    /// family. On the Linux native route Landlock ABI v9
    /// `ResolveUnix` binds pathname sockets beneath the parent
    /// directory; below v9 only `"*"` is expressible and opens the
    /// family without path scoping. No name- or IP-layer evaluation
    /// ever reads this destination.
    Unix(String),
}

impl EgressDest {
    /// The rule text as reports and refusals spell it.
    pub fn text(&self) -> &str {
        match self {
            Self::Host(h) | Self::Cidr(h) | Self::Unix(h) => h,
        }
    }
}

/// One declared `allow`/`deny` network rule with the qualifiers the flat
/// lists cannot carry: the transport protocol and the destination port.
///
/// The flat `allowed`/`allowed_cidrs`/`denied_*` lists remain the
/// name-/IP-layer projections every existing consumer reads; this list
/// is the same rule set with its qualifiers preserved so mechanisms
/// that can express proto/port (the namespaced proxy) enforce exactly
/// what was written, and mechanisms that cannot (unotify, PSEC) refuse
/// the qualifier rather than silently widening it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EgressRule {
    /// `true` = `allow` node, `false` = `deny` node.
    pub allow: bool,
    pub dest: EgressDest,
    pub proto: EgressProto,
    /// `Some(p)` pins the destination port; `None` matches every port.
    /// A spelling whose qualifier was empty (`host:`) parses to `None`
    /// here and is distinguishable only through the
    /// `*_port_qualified` provenance lists — mechanisms that need the
    /// concrete port refuse on those lists.
    pub port: Option<u16>,
}

impl EgressRule {
    /// The rule text as reports and refusals spell it, including the
    /// qualifiers (`cidr=10.0.0.0/8 proto=udp port=53`).
    pub fn describe(&self) -> String {
        let kind = match &self.dest {
            EgressDest::Host(h) => format!("host={h}"),
            EgressDest::Cidr(c) => format!("cidr={c}"),
            EgressDest::Unix(u) => format!("unix={u}"),
        };
        let mut s = kind;
        if self.proto != EgressProto::Tcp || !self.allow {
            s.push_str(&format!(" proto={}", self.proto.as_str()));
        }
        if let Some(p) = self.port {
            s.push_str(&format!(" port={p}"));
        }
        s
    }

    /// Whether this rule's (proto, port) qualifiers cover a flow of
    /// protocol `proto` to destination port `port`.
    pub fn covers_flow(&self, proto: EgressProto, port: u16) -> bool {
        self.proto.covers(proto) && self.port.is_none_or(|p| p == port)
    }
}

/// The protocol/port qualifiers a DNS-derived grant was minted under.
/// The gate tags every dynamic grant with the qualifiers of the allow
/// rules the resolved name matched, so the IP layer enforces the same
/// proto/port scope the name-layer allow declared — a grant minted by a
/// `proto=udp` rule authorizes UDP flows, never TCP.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct GrantQual {
    pub proto: EgressProto,
    /// `Some(p)` scopes the grant to destination port `p`.
    pub port: Option<u16>,
}

impl GrantQual {
    pub fn covers(self, proto: EgressProto, port: u16) -> bool {
        self.proto.covers(proto) && self.port.is_none_or(|p| p == port)
    }

    /// Default tag for a grant minted without qualifier information —
    /// the pre-schema semantics (`tcp`, any port).
    pub const TCP_ANY: Self = Self {
        proto: EgressProto::Tcp,
        port: None,
    };
}

/// Outbound rules are evaluated at two layers:
///
/// - **Name layer** — `host=` entries (FQDNs, wildcards, URL spellings).
///   Evaluated by the Auditor's argument checks and, on paths that
///   provide one, a DNS-gateway name policy.
/// - **IP layer** — `cidr=` entries (static `addr/prefix` rules), plus
///   every `host=` entry that is an IP literal: a literal needs no
///   resolution, so `allow host="192.0.2.1"` is a static IP-layer rule
///   (`/32` or `/128`) too. The same holds on the deny side — an IP
///   literal in `denied_hosts` is an IP-layer deny.
///
/// [`Self::ip_layer_allows`] / [`Self::ip_layer_denies`] project the
/// effective rule set for the IP layer; [`Self::egress_rules`] carries
/// each declared rule with its `proto=`/`port=` qualifiers for
/// mechanisms that can express them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboundPolicy {
    /// Name-layer allow rules (`allow host=`), normalized.
    pub allowed: Vec<String>,
    /// Source spellings of `allowed` entries that carried an explicit
    /// port qualifier (`host:port`, `[v6]:port`, or a URL authority
    /// port). Normalization folds the port away — the auditor's
    /// identity is the host — but the spelling is retained so a
    /// mechanism emitting real destination rules (PSEC) refuses the
    /// qualifier it cannot express instead of silently widening the
    /// entry to every port. Empty for programmatically built policies.
    pub allowed_port_qualified: Vec<String>,
    /// IP-layer allow rules (`allow cidr=`) — canonical `addr/prefix`
    /// with host bits masked.
    pub allowed_cidrs: Vec<String>,
    /// Source spellings of `allowed_cidrs` entries that carried a port
    /// qualifier — same refusal contract as `allowed_port_qualified`.
    pub allowed_cidrs_port_qualified: Vec<String>,
    /// Deny rules evaluated at both layers (`deny host=`); IP literals
    /// here are IP-layer denies.
    pub denied_hosts: Vec<String>,
    /// IP-layer deny rules (`deny cidr=`) — canonical `addr/prefix`.
    pub denied_cidrs: Vec<String>,
    pub deny_all_others: bool,
    /// Every declared non-posture `allow`/`deny` rule with its
    /// `proto=`/`port=` qualifiers, in canonical order (allows first,
    /// then denies). Posture nodes — bare `allow host="*"` /
    /// `deny host="*"` — are postures, not rules, and live only in
    /// `deny_all_others`.
    ///
    /// Populated by the KDL parser. [`Self::egress_rules`] derives the
    /// equivalent rule set for policies built without parsing, so
    /// consumers always read through the accessor.
    pub egress_rules: Vec<EgressRule>,
}

impl Default for OutboundPolicy {
    fn default() -> Self {
        Self {
            allowed: Vec::new(),
            allowed_port_qualified: Vec::new(),
            allowed_cidrs: Vec::new(),
            allowed_cidrs_port_qualified: Vec::new(),
            denied_hosts: Vec::new(),
            denied_cidrs: Vec::new(),
            deny_all_others: true,
            egress_rules: Vec::new(),
        }
    }
}

impl OutboundPolicy {
    /// The effective IP-layer allow set in canonical `addr/prefix`
    /// form: declared `allowed_cidrs` plus a host route (`/32` or
    /// `/128`) for every `allowed` entry that is an IP literal —
    /// `allow host=` on a literal needs no resolution, so it is a
    /// static IP-layer rule as well.
    ///
    /// Entries covered by an IP-layer deny rule
    /// ([`Self::ip_layer_denies`]) are not returned: deny wins over
    /// allow at every evaluation point.
    ///
    /// This is the *effective* projection an IP-layer enforcement
    /// mechanism consumes. The declared lists stay authoritative for
    /// reporting — the plan's egress table enumerates every declared
    /// rule so a deny-covered allow stays visible rather than silently
    /// absent.
    pub fn ip_layer_allows(&self) -> Vec<String> {
        let denies = self.ip_layer_denies();
        let mut out: Vec<String> = Vec::new();
        for cidr in self
            .allowed_cidrs
            .iter()
            .cloned()
            .chain(self.allowed.iter().filter_map(|h| {
                h.parse::<std::net::IpAddr>()
                    .ok()
                    .map(host::ip_literal_cidr)
            }))
        {
            if !out.contains(&cidr) && !denies.iter().any(|d| host::cidr_covers(d, &cidr)) {
                out.push(cidr);
            }
        }
        out
    }

    /// The effective IP-layer deny set in canonical `addr/prefix` form:
    /// declared `denied_cidrs` plus a host route for every IP literal
    /// in `denied_hosts` — `denied_hosts` evaluates at both layers.
    /// A `*` in `denied_hosts` is the deny-all posture and is not an
    /// IP-layer entry.
    pub fn ip_layer_denies(&self) -> Vec<String> {
        let mut out: Vec<String> = self.denied_cidrs.clone();
        for h in &self.denied_hosts {
            if let Ok(addr) = h.parse::<std::net::IpAddr>() {
                let cidr = host::ip_literal_cidr(addr);
                if !out.contains(&cidr) {
                    out.push(cidr);
                }
            }
        }
        out
    }

    /// The declared rule set with `proto=`/`port=` qualifiers — the
    /// stored [`Self::egress_rules`] when the parser populated them, or
    /// an equivalent rule set derived from the flat lists for a
    /// programmatically built policy. Derived rules carry the pre-schema
    /// defaults: allows are `proto=tcp` any-port, denies are
    /// protocol-blind. `port=` qualifiers recoverable from the
    /// `*_port_qualified` provenance spellings are re-attached so a
    /// re-serialized policy does not lose them.
    ///
    /// Consumers that evaluate flows must read this accessor, never the
    /// field directly — a programmatically built policy leaves the field
    /// empty and expects the flat-list semantics to hold.
    pub fn egress_rules(&self) -> Vec<EgressRule> {
        if !self.egress_rules.is_empty() {
            return self.egress_rules.clone();
        }
        let mut rules = Vec::new();
        for h in &self.allowed {
            // A programmatic `allowed` entry in bare-port form
            // (`"443"`) is the pre-schema spelling of a port-only rule —
            // the parser never produces it, but a constructed policy
            // may still carry it; derive the same rule a parsed
            // `allow host="443"` yields so Landlock netport semantics
            // survive the conversion.
            if let Some(port) = host::bare_port_spelling(h) {
                rules.push(EgressRule {
                    allow: true,
                    dest: EgressDest::Host("*".to_string()),
                    proto: EgressProto::Tcp,
                    port: Some(port),
                });
                continue;
            }
            let port = self.allowed_port_qualified.iter().find_map(|raw| {
                let (norm, port, _) = host::analyze_policy_host(raw);
                (norm == *h).then_some(port).flatten()
            });
            rules.push(EgressRule {
                allow: true,
                dest: EgressDest::Host(h.clone()),
                proto: EgressProto::Tcp,
                port,
            });
        }
        for c in &self.allowed_cidrs {
            let port = self.allowed_cidrs_port_qualified.iter().find_map(|raw| {
                host::analyze_policy_cidr(raw)
                    .ok()
                    .and_then(|(norm, port, _)| (norm == *c).then_some(port).flatten())
            });
            rules.push(EgressRule {
                allow: true,
                dest: EgressDest::Cidr(c.clone()),
                proto: EgressProto::Tcp,
                port,
            });
        }
        for h in &self.denied_hosts {
            rules.push(EgressRule {
                allow: false,
                dest: EgressDest::Host(h.clone()),
                proto: EgressProto::Any,
                port: None,
            });
        }
        for c in &self.denied_cidrs {
            rules.push(EgressRule {
                allow: false,
                dest: EgressDest::Cidr(c.clone()),
                proto: EgressProto::Any,
                port: None,
            });
        }
        rules
    }

    /// Destination ports a port-only allow rule grants for TCP —
    /// `allow host="443"` / `allow host="*" port=443` rules and their
    /// `proto="any"` variants. This is the only spelling Landlock
    /// `ConnectTcp` netport rules can express (a port with no
    /// destination bound), so it is the netport rule set.
    pub fn tcp_port_rules(&self) -> Vec<u16> {
        let mut ports: Vec<u16> = self
            .egress_rules()
            .iter()
            .filter(|r| {
                r.allow
                    && matches!(r.dest, EgressDest::Host(ref h) if h == "*")
                    && r.proto.covers(EgressProto::Tcp)
            })
            .filter_map(|r| r.port)
            .collect();
        ports.sort_unstable();
        ports.dedup();
        ports
    }

    /// The declared `allow unix=` values (`"/path"` or `"*"`). These
    /// opt-ins live beside the host/IP egress model — they never fold
    /// into `allowed`/`allowed_cidrs` — so the Linux sandbox builders
    /// read them through this accessor rather than the flat lists.
    pub fn unix_allows(&self) -> Vec<String> {
        self.egress_rules()
            .iter()
            .filter(|r| r.allow)
            .filter_map(|r| match &r.dest {
                EgressDest::Unix(u) => Some(u.clone()),
                _ => None,
            })
            .collect()
    }
}

/// Canonical ordering for a stored/derived rule set — allows first
/// (by dest text, proto, port), then denies — so `PartialEq` on a
/// parsed-then-emitted policy holds regardless of declaration order.
/// Rule order is semantically irrelevant (deny precedence is absolute),
/// so canonicalizing is always safe.
pub(crate) fn sort_egress_rules(rules: &mut [EgressRule]) {
    rules.sort_by(|a, b| {
        (b.allow, a.dest.text(), a.proto, a.port).cmp(&(a.allow, b.dest.text(), b.proto, b.port))
    });
}

/// Remove allowed destinations that are covered by a deny rule.
///
/// `denied_hosts` prunes `allowed` (name layer); the IP-layer deny set
/// — `denied_cidrs` plus IP literals in `denied_hosts` — prunes
/// `allowed_cidrs` entries the deny range covers entirely. A denied
/// rule that only *partially* overlaps an allowed range does not
/// prune: deny-vs-allow is evaluated per destination at check time,
/// and the overlap stays visible to mechanisms that must refuse
/// carve-outs they cannot express (PSEC).
pub fn apply_outbound_deny_precedence(outbound: &mut OutboundPolicy) {
    outbound.allowed.retain(|allowed| {
        !outbound
            .denied_hosts
            .iter()
            .any(|denied| host_covered_by_deny(allowed, denied))
    });
    // Port-qualifier provenance tracks `allowed` membership — a
    // spelling whose folded host a deny rule covered must not still
    // refuse as port-qualified.
    outbound.allowed_port_qualified.retain(|raw| {
        outbound
            .allowed
            .contains(&crate::policy::host::normalize_policy_host(raw))
    });
    // IP layer: an `allow cidr` inside a denied range can never pass.
    // A programmatic `denied_hosts` `*` is the deny-all posture and
    // clears the IP layer the same way it clears `allowed`.
    let deny_all_ip = outbound.denied_hosts.iter().any(|d| d == "*");
    let denied_ip = outbound.ip_layer_denies();
    outbound
        .allowed_cidrs
        .retain(|cidr| !deny_all_ip && !denied_ip.iter().any(|d| host::cidr_covers(d, cidr)));
    outbound.allowed_cidrs_port_qualified.retain(|raw| {
        host::analyze_policy_cidr(raw)
            .map(|(cidr, _, _)| outbound.allowed_cidrs.contains(&cidr))
            .unwrap_or(false)
    });
    // Same coverage predicate on the qualified rule set: a deny-covered
    // allow rule can never pass, so it leaves the stored rules with its
    // flat-list projection. Deny rules are sticky — never pruned.
    // `unix=` opt-ins sit beside the host/IP deny model — no `deny host=`
    // or `deny cidr=` entry names a socket path, so they always survive.
    let denied_hosts = outbound.denied_hosts.clone();
    outbound.egress_rules.retain(|r| {
        !r.allow
            || match &r.dest {
                EgressDest::Host(h) => !denied_hosts.iter().any(|d| host_covered_by_deny(h, d)),
                EgressDest::Cidr(c) => {
                    !deny_all_ip && !denied_ip.iter().any(|d| host::cidr_covers(d, c))
                }
                EgressDest::Unix(_) => true,
            }
    });
}

/// Apply the same wildcard-aware deny reducer to a per-tool network policy.
pub fn apply_tool_network_deny_precedence(network: &mut ToolNetworkPolicy) {
    let denied_hosts = network.denied_hosts.clone();
    network.allowed_hosts.retain(|allowed| {
        !denied_hosts
            .iter()
            .any(|denied| host_covered_by_deny(allowed, denied))
    });
    // One layer down: a denied CIDR (or an IP literal in
    // `denied_hosts`, which is a `/32`/`/128` IP-layer deny) covers an
    // allowed CIDR the allow sits entirely inside.
    let denied_ip: Vec<String> = network
        .denied_cidrs
        .iter()
        .cloned()
        .chain(network.denied_hosts.iter().filter_map(|h| {
            h.parse::<std::net::IpAddr>()
                .ok()
                .map(host::ip_literal_cidr)
        }))
        .collect();
    let deny_all_ip = network.denied_hosts.iter().any(|d| d == "*");
    network
        .allowed_cidrs
        .retain(|cidr| !deny_all_ip && !denied_ip.iter().any(|d| host::cidr_covers(d, cidr)));
    // Qualified rules prune under the same coverage predicate as their
    // flat projections; deny rules stay sticky. `unix=` opt-ins are
    // outside the host/IP deny model and always survive.
    let denied_hosts = network.denied_hosts.clone();
    network.egress_rules.retain(|r| {
        !r.allow
            || match &r.dest {
                EgressDest::Host(h) => !denied_hosts.iter().any(|d| host_covered_by_deny(h, d)),
                EgressDest::Cidr(c) => {
                    !deny_all_ip && !denied_ip.iter().any(|d| host::cidr_covers(d, c))
                }
                EgressDest::Unix(_) => true,
            }
    });
}

pub fn host_covered_by_deny(allowed: &str, denied: &str) -> bool {
    let a = canonicalize_policy_host(allowed);
    let d = canonicalize_policy_host(denied);
    if d == "*" || a == d {
        return true;
    }
    if let Some(suffix) = d.strip_prefix("*.") {
        let with_dot = format!(".{suffix}");
        return a == suffix || a.ends_with(&with_dot);
    }
    false
}

/// Lowercase, strip a trailing DNS root dot, and fold every equivalent
/// spelling of the same network address into one canonical form —
/// WHATWG IPv4 numbers (`127.1`, `0x7f.1`, `2130706433`), IPv6 literals
/// (expanded, uppercase, `::ffff:`-mapped), IDN domain names (Unicode
/// and `xn--` spellings of the same name), and ASCII DNS names — so a
/// denylist entry cannot be evaded by a non-canonical spelling.
///
/// Hosts the URL grammar cannot represent keep their trimmed lowercase
/// form: they can never equal a parsed host and so stay unmatchable
/// rather than accidentally permissive. The same holds for an invalid
/// IDN — UTS-46 rejects it and the unmatchable fallback stands.
pub fn canonicalize_policy_host(host: &str) -> String {
    let trimmed = host.trim().trim_end_matches('.');
    // A wildcard covers the canonical form of its suffix, so normalize
    // the suffix the same way and re-pin the marker.
    if let Some(suffix) = trimmed.strip_prefix("*.") {
        return format!("*.{}", canonicalize_policy_host(suffix));
    }
    if !trimmed.is_ascii() {
        // Unicode domain names canonicalize to their IDNA (Punycode)
        // spelling — the form a parsed URL host already carries — so a
        // denylist entry in either spelling matches the same wire host.
        // UTS-46 also maps full-width spellings to ASCII (`１２７.１` →
        // `127.1`), so the result re-enters the URL host grammar to fold
        // WHATWG IPv4/IPv6 forms rather than surviving as an unmatched
        // ASCII string. An invalid IDN keeps the lowercase fallback —
        // never equal to a parsed host.
        return match idna::domain_to_ascii(trimmed) {
            Ok(ascii) => host::canonicalize_url_host(ascii.trim_end_matches('.'))
                .unwrap_or_else(|| ascii.to_ascii_lowercase()),
            Err(_) => trimmed.to_ascii_lowercase(),
        };
    }
    host::canonicalize_url_host(trimmed).unwrap_or_else(|| trimmed.to_ascii_lowercase())
}
