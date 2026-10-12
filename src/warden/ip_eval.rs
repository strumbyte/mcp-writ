//! IP-layer evaluator — the policy's static CIDR/literal rules, in the
//! same order `dnsgate::name_policy` decides the name layer.
//!
//! Every IP-layer enforcement point evaluates the same verdict function:
//! `unotify`'s supervisor sees the full flow tuple from a `connect(2)`
//! notification (`sockaddr` destination + `SO_TYPE` transport), the PR-09
//! namespaced proxy sees it from intercepted packets, and the PR-11 macOS
//! CONNECT proxy sees it from the `CONNECT` authority. The evaluator
//! therefore enforces the structured egress rules *with* their
//! `proto=`/`port=` qualifiers — a `proto=udp` allow never covers a TCP
//! connect, and a `port=443` rule covers only 443. What a given consumer
//! still cannot see is caller context: unconnected `sendto`/`sendmsg`
//! datagrams are invisible to the `connect(2)` supervisor, DNS names
//! never reach this layer — they arrive through the TTL-scoped grant
//! path instead.

use std::net::IpAddr;

use crate::policy::OutboundPolicy;
use crate::policy::host;
use crate::policy::{EgressDest, EgressProto};

/// The endpoint a `connect(2)` to `ip` reaches as far as the socket
/// layer decides — only the kernel's own fold (`to_canonical`): a
/// v4-mapped v6 spelling (`::ffff:1.2.3.4`) collapses to the v4
/// socket destination the kernel really dials. Every other spelling
/// — NAT64, 6to4, Teredo — connects as the v6 it is written:
/// translation happens downstream on the wire, so a supervised
/// syscall (and any intercepted packet) is judged as the v6 address
/// it carries. This is the same fold `unotify`'s `inspect` applies
/// to the `sockaddr` itself and the policy layer applies to mapped
/// literals at load time — folding any other v6 spelling here would
/// let a v6 destination slip into a v4 `allow` the policy never
/// granted it, while a `deny` written on the v6 form would stop
/// matching the rewritten destination.
pub(crate) fn socket_endpoint(ip: IpAddr) -> IpAddr {
    ip.to_canonical()
}

/// The endpoint a proxy *dial* of `ip` reaches — the proxy is itself
/// the translator on the one spelling whose embedded v4 *is* the
/// endpoint: a NAT64 well-known-prefix address (`64:ff9b::/96`,
/// RFC 6052) carries the destination v4 in its last 32 bits, so
/// `CONNECT [64:ff9b::x]` dials `x` and is judged as `x`. Without
/// this a `deny cidr=`/`deny host=` on an IPv4 endpoint is bypassed
/// by spelling it through the well-known prefix (DNS64/NAT64
/// networks, OS CLAT). Spellings carrying an embedded v4 under a
/// *non-well-known* prefix (site-specific NAT64/translation space)
/// are undetectable and judged as the v6 they spell.
///
/// 6to4 (`2002::/16`) and Teredo (`2001:0000::/32`) deliberately do
/// NOT unwrap: bits 16–48 of a 6to4 address name the site's *relay
/// router* and Teredo's last 32 bits name the *client's* mapped
/// address — neither is the TCP endpoint a connect reaches, so the
/// embedded v4 is a different host than the one addressed.
pub(crate) fn dialed_endpoint(ip: IpAddr) -> IpAddr {
    match socket_endpoint(ip) {
        IpAddr::V6(v6) => nat64_embedded_v4(&v6).map_or(IpAddr::V6(v6), IpAddr::V4),
        v => v,
    }
}

/// The IPv4 a NAT64 well-known-prefix spelling (`64:ff9b::/96`,
/// RFC 6052) embeds in its last 32 bits — the v4 endpoint a
/// translator forwards to, per [`dialed_endpoint`].
fn nat64_embedded_v4(v6: &std::net::Ipv6Addr) -> Option<std::net::Ipv4Addr> {
    if v6.segments()[..6] == [0x0064, 0xff9b, 0, 0, 0, 0] {
        let o = v6.octets();
        return Some(std::net::Ipv4Addr::new(o[12], o[13], o[14], o[15]));
    }
    None
}

/// One connect verdict — `rule` is the matching policy text when one
/// exists, `decision` the `sandbox.network_denied` vocabulary
/// (`deny-host`/`deny-cidr`/`not-allowed`, mirroring
/// `dnsgate::name_policy::DenyReason::decision`).
#[derive(Debug, PartialEq, Eq)]
pub enum IpVerdict {
    Allow {
        basis: &'static str,
        rule: Option<String>,
    },
    Deny {
        decision: &'static str,
        rule: Option<String>,
    },
}

/// What an allow rule's destination binds at the IP layer.
enum AllowDest {
    /// `Host("*")` — every destination (a scoped wildcard rule or a
    /// bare-port `allow host="443"`).
    Any,
    /// `Host(<ip-literal>)` — an exact address.
    Literal(IpAddr),
    /// `Cidr(<addr/prefix>)`.
    Cidr(String),
    /// `Host(<name>)` — inert here: a connect arrives as an address,
    /// never a name. DNS-derived grants carry the name rule's scope.
    Name,
}

impl AllowDest {
    fn matches(&self, dest: &IpAddr) -> bool {
        match self {
            Self::Any => true,
            Self::Literal(ip) => ip == dest,
            Self::Cidr(cidr) => host::cidr_contains(cidr, dest),
            Self::Name => false,
        }
    }

    fn basis(&self) -> &'static str {
        match self {
            Self::Cidr(_) => "allow-cidr",
            _ => "allow-host",
        }
    }
}

/// Which consumer built the evaluator — only controls which
/// capability warnings are emitted, never the verdicts.
/// `#[allow(dead_code)]`: each variant is constructed only on the OS
/// whose consumer exists (Linux unotify/namespaced, macOS proxy).
#[allow(dead_code)]
#[derive(Clone, Copy, Debug)]
enum Context {
    Unotify,
    Namespaced,
    /// PR-11 macOS loopback CONNECT proxy: every outbound TCP flow in
    /// the sandbox is pinned to the proxy by SBPL, so *all* TCP egress
    /// is evaluated — but UDP has no CONNECT equivalent and is fully
    /// kernel-denied, so UDP-capable allow rules stay unenforced.
    ConnectProxy,
}

/// One allow rule projected for flow checks — destination matcher plus
/// the `proto`/`port` qualifiers.
struct AllowRule {
    dest: AllowDest,
    proto: EgressProto,
    port: Option<u16>,
    /// The rule text as audit spells it (`describe()`).
    text: String,
}

/// The IP-layer half of `OutboundPolicy`, pre-projected for the
/// supervisor: denies stay protocol/port-blind (the grammar rejects
/// qualifiers on `deny`), allows keep their qualifiers so the verdict
/// enforces exactly what was declared.
pub struct IpLayerEvaluator {
    ctx: Context,
    deny_all_others: bool,
    denied_any: bool,
    denied_literals: Vec<IpAddr>,
    denied_cidrs: Vec<String>,
    allows: Vec<AllowRule>,
}

impl IpLayerEvaluator {
    /// Build the evaluator from the structured rule set
    /// ([`OutboundPolicy::egress_rules`] — stored or derived). Deny
    /// rules are protocol/port-blind by grammar; allow rules keep
    /// `proto`/`port` so a qualifier narrows rather than widens.
    #[cfg(target_os = "linux")]
    pub fn new(outbound: &OutboundPolicy) -> Result<Self, String> {
        Self::build(outbound, Context::Unotify)
    }

    /// PR-09 variant for the namespaced TUN proxy: the datagram
    /// warning does not apply — the proxy *does* see every datagram,
    /// which is exactly why it exists.
    #[cfg(target_os = "linux")]
    pub fn new_namespaced(outbound: &OutboundPolicy) -> Result<Self, String> {
        Self::build(outbound, Context::Namespaced)
    }

    /// PR-11 variant for the macOS loopback CONNECT proxy: the sandbox
    /// pins all outbound TCP to the proxy, so every TCP connect is
    /// evaluated — but UDP has no proxy path at all (the SBPL profile
    /// denies it outright), so a UDP-capable allow rule is dead policy
    /// rather than a visibility gap and the warning says so.
    #[cfg(target_os = "macos")]
    pub fn new_connect_proxy(outbound: &OutboundPolicy) -> Result<Self, String> {
        Self::build(outbound, Context::ConnectProxy)
    }

    fn build(outbound: &OutboundPolicy, ctx: Context) -> Result<Self, String> {
        // A `deny host=` on a name (or wildcard suffix) is inert at this
        // layer — a connect arrives as an address, never a hostname, and
        // grants only ever *allow*. Say so instead of leaving the rule
        // looking enforced.
        let name_only_denies: Vec<&str> = outbound
            .denied_hosts
            .iter()
            .map(String::as_str)
            .filter(|h| *h != "*" && !host::host_is_ip_literal(h))
            .collect();
        if !name_only_denies.is_empty() {
            match ctx {
                Context::ConnectProxy => tracing::warn!(
                    rules = ?name_only_denies,
                    "deny host rules on names are name-layer only — the IP \
                     layer never sees a hostname, so they are not in this \
                     table; the CONNECT proxy's name layer evaluates them \
                     per CONNECT authority"
                ),
                _ => tracing::warn!(
                    rules = ?name_only_denies,
                    "deny host rules on names are name-layer only — the IP layer \
                     never sees a hostname, so they stay unenforced here; dns-gate \
                     is the name-layer enforcement point"
                ),
            }
        }
        let mut allows = Vec::new();
        let mut udp_capable = false;
        for rule in outbound.egress_rules() {
            if !rule.allow {
                continue;
            }
            let dest = match &rule.dest {
                EgressDest::Host(h) if h == "*" => AllowDest::Any,
                EgressDest::Host(h) => match h.parse::<IpAddr>() {
                    Ok(ip) => AllowDest::Literal(ip),
                    Err(_) => AllowDest::Name,
                },
                EgressDest::Cidr(c) => AllowDest::Cidr(c.clone()),
            };
            if rule.proto.covers(EgressProto::Udp) {
                udp_capable = true;
            }
            allows.push(AllowRule {
                dest,
                proto: rule.proto,
                port: rule.port,
                text: rule.describe(),
            });
        }
        if udp_capable {
            match ctx {
                Context::Unotify => tracing::warn!(
                    "a UDP-capable allow rule exists (proto=udp/any or a \
                     UDP-scoped grant) — connect(2) is supervised per flow, \
                     but unconnected sendto/sendmsg datagrams are not \
                     visible to this layer (documented unotify limitation)"
                ),
                Context::ConnectProxy => tracing::warn!(
                    "a UDP-capable allow rule exists (proto=udp/any) — the \
                     CONNECT proxy terminates TCP only and the SBPL profile \
                     denies all UDP egress, so this rule's UDP coverage is \
                     unenforced on this path"
                ),
                Context::Namespaced => {}
            }
        }
        Ok(Self {
            ctx,
            deny_all_others: outbound.deny_all_others,
            denied_any: outbound.denied_hosts.iter().any(|d| d == "*"),
            denied_literals: outbound
                .denied_hosts
                .iter()
                .filter_map(|h| h.parse::<IpAddr>().ok())
                .collect(),
            denied_cidrs: outbound.denied_cidrs.clone(),
            allows,
        })
    }

    /// The endpoint this consumer's verdict binds `dest` to. A
    /// supervised `connect(2)` (and the namespaced packet path)
    /// connects to the `sockaddr` as written — the judged address is
    /// the kernel's own fold ([`socket_endpoint`]). The CONNECT
    /// proxy *dials* the destination itself, so its judged address is
    /// the address the dial reaches ([`dialed_endpoint`]) — a NAT64
    /// well-known spelling unwraps to the v4 the proxy's socket
    /// connects to. Grants key on this same form, so a
    /// DNS64-synthesized answer mints a grant on the judged endpoint.
    pub(crate) fn judged_endpoint(&self, dest: IpAddr) -> IpAddr {
        match self.ctx {
            Context::ConnectProxy => dialed_endpoint(dest),
            _ => socket_endpoint(dest),
        }
    }

    /// Decide one connect. `proto`/`port` are the socket's transport
    /// and the `sockaddr` destination port; `grant_names` are the live
    /// dynamic-grant names covering the judged endpoint for audit,
    /// `grant_covered` whether any of those grants' qualifiers
    /// authorize this (proto, port) flow. Deny always precedes allow
    /// — a denied rule wins over every allow source, grants included.
    ///
    /// `dest` is judged as the endpoint its flow actually reaches
    /// ([`Self::judged_endpoint`]). Deny rules bind on *every*
    /// spelling of the destination — a `deny` on the written spelling
    /// and a `deny` on the endpoint it unwraps to both win, so a
    /// transition form can neither step around a `deny` on the v4
    /// endpoint nor silence a `deny` written on the v6 spelling
    /// itself. Allow rules, grants, and the posture judge only the
    /// endpoint the flow reaches — an `allow` never covers a spelling
    /// whose reached endpoint the rule did not declare.
    pub fn evaluate(
        &self,
        dest: &IpAddr,
        proto: EgressProto,
        port: u16,
        grant_names: &[String],
        grant_covered: bool,
    ) -> IpVerdict {
        let endpoint = self.judged_endpoint(*dest);
        if self.denied_any {
            return IpVerdict::Deny {
                decision: "deny-host",
                rule: Some("*".to_string()),
            };
        }
        for spelled in std::iter::once(dest).chain((endpoint != *dest).then_some(&endpoint)) {
            if self.denied_literals.contains(spelled) {
                return IpVerdict::Deny {
                    decision: "deny-host",
                    rule: Some(spelled.to_string()),
                };
            }
            if let Some(rule) = self
                .denied_cidrs
                .iter()
                .find(|c| host::cidr_contains(c, spelled))
            {
                return IpVerdict::Deny {
                    decision: "deny-cidr",
                    rule: Some(rule.clone()),
                };
            }
        }
        if let Some(rule) = self.allows.iter().find(|r| {
            r.dest.matches(&endpoint) && r.proto.covers(proto) && r.port.is_none_or(|p| p == port)
        }) {
            return IpVerdict::Allow {
                basis: rule.dest.basis(),
                rule: Some(rule.text.clone()),
            };
        }
        if grant_covered {
            return IpVerdict::Allow {
                basis: "allowlist-grant",
                rule: Some(grant_names.join(",")),
            };
        }
        if self.deny_all_others {
            return IpVerdict::Deny {
                decision: "not-allowed",
                rule: None,
            };
        }
        IpVerdict::Allow {
            basis: "open",
            rule: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn socket_endpoint_folds_only_what_the_kernel_folds() {
        // v4-mapped v6 collapses to the v4 socket destination — the
        // kernel's own fold (`to_canonical`, the same one the
        // `sockaddr` inspection applies).
        for (spelled, endpoint) in [
            ("::ffff:8.8.8.8", "8.8.8.8"),
            ("::ffff:7f00:1", "127.0.0.1"),
        ] {
            assert_eq!(
                socket_endpoint(spelled.parse().unwrap()),
                endpoint.parse::<IpAddr>().unwrap(),
                "{spelled} must fold to {endpoint}"
            );
        }
        // NAT64/6to4/Teredo spellings connect as the v6 they are
        // written — translation happens downstream of the socket, so
        // the supervised destination is the v6 itself.
        for ip in [
            "64:ff9b::808:808",
            "2002:0808:0808::",
            "2001:0000::f7f7:f7f7",
            "8.8.8.8",
            "2606:4700:4700::1111",
            "fd00::1",
        ] {
            let parsed: IpAddr = ip.parse().unwrap();
            assert_eq!(socket_endpoint(parsed), parsed, "{ip} must not fold");
        }
    }

    #[test]
    fn dialed_endpoint_unwraps_only_the_nat64_well_known_prefix() {
        // The proxy is the translator for a WKP spelling — the last
        // 32 bits really are the endpoint its dial reaches.
        for (spelled, endpoint) in [
            ("64:ff9b::8.8.8.8", "8.8.8.8"),
            ("64:ff9b::cb00:7105", "203.0.113.5"),
            ("::ffff:8.8.8.8", "8.8.8.8"),
        ] {
            assert_eq!(
                dialed_endpoint(spelled.parse().unwrap()),
                endpoint.parse::<IpAddr>().unwrap(),
                "{spelled} must unwrap to {endpoint}"
            );
        }
        // 6to4/Teredo embed a router's or client's v4 — never the TCP
        // endpoint — so the dial (and the verdict) sees the v6 as
        // written.
        for ip in [
            "2002:0808:0808::",
            "2002:cb00:7105::",
            "2001:0000::f7f7:f7f7",
            "2001:0000::",
        ] {
            let parsed: IpAddr = ip.parse().unwrap();
            assert_eq!(dialed_endpoint(parsed), parsed, "{ip} must not unwrap");
        }
    }

    #[test]
    fn evaluate_denies_the_embedded_v4_endpoint() {
        // The proxy dials the NAT64-embedded v4 — a deny on that
        // endpoint must win on the spelling, exactly as it does for
        // v4-mapped and v4 forms.
        let outbound = OutboundPolicy {
            denied_cidrs: vec!["203.0.113.0/24".to_string()],
            denied_hosts: vec!["192.0.2.7".to_string()],
            deny_all_others: false,
            ..OutboundPolicy::default()
        };
        let ev = IpLayerEvaluator::build(&outbound, Context::ConnectProxy).unwrap();
        for dest in [
            "64:ff9b::cb00:7105", // NAT64 of 203.0.113.5
            "::ffff:203.0.113.5",
            "203.0.113.5",
        ] {
            let verdict = ev.evaluate(&dest.parse().unwrap(), EgressProto::Tcp, 443, &[], false);
            assert!(
                matches!(
                    verdict,
                    IpVerdict::Deny {
                        decision: "deny-cidr",
                        ..
                    }
                ),
                "{dest} must hit the embedded v4's deny-cidr"
            );
        }
        let verdict = ev.evaluate(
            &"64:ff9b::c000:207".parse().unwrap(), // NAT64 of 192.0.2.7
            EgressProto::Tcp,
            443,
            &[],
            false,
        );
        assert!(matches!(
            verdict,
            IpVerdict::Deny {
                decision: "deny-host",
                ..
            }
        ));
    }

    #[test]
    fn evaluate_binds_denies_on_every_spelling() {
        // A deny written on the *translation spelling* still fires
        // when the judged endpoint unwraps past it — `deny
        // cidr="64:ff9b::/96"` forbids the translated path itself.
        let outbound = OutboundPolicy {
            denied_cidrs: vec!["64:ff9b::/96".to_string(), "2002::/16".to_string()],
            deny_all_others: false,
            ..OutboundPolicy::default()
        };
        let ev = IpLayerEvaluator::build(&outbound, Context::ConnectProxy).unwrap();
        for dest in ["64:ff9b::808:808", "2002:0808:0808::"] {
            let verdict = ev.evaluate(&dest.parse().unwrap(), EgressProto::Tcp, 443, &[], false);
            assert!(
                matches!(
                    verdict,
                    IpVerdict::Deny {
                        decision: "deny-cidr",
                        ..
                    }
                ),
                "{dest} must hit the deny written on its own spelling"
            );
        }
    }

    #[test]
    fn evaluate_allows_the_embedded_v4_endpoint() {
        // An allow for the endpoint legitimately covers its NAT64
        // spelling — the proxy dials that v4. v4-mapped folds the
        // same way on every path.
        let outbound = OutboundPolicy {
            allowed_cidrs: vec!["8.8.8.0/24".to_string()],
            deny_all_others: true,
            ..OutboundPolicy::default()
        };
        let ev = IpLayerEvaluator::build(&outbound, Context::ConnectProxy).unwrap();
        for dest in ["64:ff9b::808:808", "::ffff:8.8.8.8", "8.8.8.8"] {
            let verdict = ev.evaluate(&dest.parse().unwrap(), EgressProto::Tcp, 443, &[], false);
            assert!(
                matches!(
                    verdict,
                    IpVerdict::Allow {
                        basis: "allow-cidr",
                        ..
                    }
                ),
                "{dest} must hit the embedded v4's allow-cidr"
            );
        }
        // An address outside the rule still falls to the posture.
        let verdict = ev.evaluate(
            &"64:ff9b::909:909".parse().unwrap(),
            EgressProto::Tcp,
            443,
            &[],
            false,
        );
        assert!(matches!(
            verdict,
            IpVerdict::Deny {
                decision: "not-allowed",
                ..
            }
        ));
    }

    #[test]
    fn evaluate_judges_transition_spellings_as_the_v6_they_connect_to() {
        // On the supervised-connect path the kernel connects to the
        // v6 sockaddr — never to the embedded router/client v4 or a
        // translator's endpoint — so a v4 `allow` must not carry any
        // transition spelling and a v6 `deny` on the spelling must.
        let outbound = OutboundPolicy {
            allowed_cidrs: vec!["1.2.3.0/24".to_string()],
            deny_all_others: true,
            ..OutboundPolicy::default()
        };
        let ev = IpLayerEvaluator::build(&outbound, Context::Unotify).unwrap();
        for dest in [
            "2002:0102:0304::5",    // 6to4 — embedded v4 is the site router
            "2001:0000::fefd:fcfb", // Teredo — XOR → 1.2.3.4 client map
            "64:ff9b::1.2.3.4",     // NAT64 — the socket connects v6
        ] {
            let verdict = ev.evaluate(&dest.parse().unwrap(), EgressProto::Tcp, 443, &[], false);
            assert!(
                matches!(
                    verdict,
                    IpVerdict::Deny {
                        decision: "not-allowed",
                        ..
                    }
                ),
                "{dest} must not match the v4 allow on the supervised path — \
                 the syscall connects to the v6 as written"
            );
        }
        // The proxy dials the NAT64-embedded v4 itself, so there the
        // same spelling legitimately matches the v4 allow — but
        // 6to4/Teredo still connect to the v6 they spell.
        let ev = IpLayerEvaluator::build(&outbound, Context::ConnectProxy).unwrap();
        let verdict = ev.evaluate(
            &"64:ff9b::1.2.3.4".parse().unwrap(),
            EgressProto::Tcp,
            443,
            &[],
            false,
        );
        assert!(
            matches!(
                verdict,
                IpVerdict::Allow {
                    basis: "allow-cidr",
                    ..
                }
            ),
            "the proxy dials — and judges — the NAT64 endpoint"
        );
        for dest in ["2002:0102:0304::5", "2001:0000::fefd:fcfb"] {
            let verdict = ev.evaluate(&dest.parse().unwrap(), EgressProto::Tcp, 443, &[], false);
            assert!(
                matches!(
                    verdict,
                    IpVerdict::Deny {
                        decision: "not-allowed",
                        ..
                    }
                ),
                "{dest} dials the v6 it spells — the v4 allow must not cover it"
            );
        }
        // A v6 `deny` written on the spelling's own prefix binds on
        // both paths.
        let outbound = OutboundPolicy {
            denied_cidrs: vec!["2002::/16".to_string()],
            deny_all_others: false,
            ..OutboundPolicy::default()
        };
        for ctx in [Context::Unotify, Context::ConnectProxy] {
            let ev = IpLayerEvaluator::build(&outbound, ctx).unwrap();
            let verdict = ev.evaluate(
                &"2002:0808:0808::".parse().unwrap(),
                EgressProto::Tcp,
                443,
                &[],
                false,
            );
            assert!(
                matches!(
                    verdict,
                    IpVerdict::Deny {
                        decision: "deny-cidr",
                        ..
                    }
                ),
                "ctx {ctx:?}: a v6 deny on the spelling must still fire"
            );
        }
    }
}
