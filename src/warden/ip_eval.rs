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

/// The endpoint a `connect(2)` to `ip` actually reaches once
/// translator spellings are unwrapped — the address policy must
/// judge, not the spelling that names it:
///
/// - **v4-mapped v6** (`::ffff:1.2.3.4`) — `to_canonical` folds it to
///   the v4 socket destination the kernel dials;
/// - **NAT64 well-known prefix** (`64:ff9b::/96`, RFC 6052) — the
///   last 32 bits carry the v4 endpoint the translator forwards to;
/// - **6to4** (`2002::/16`, RFC 3056) — bits 16–48 name the relayed
///   v4 endpoint;
/// - **Teredo** (`2001:0000::/32`, RFC 4380) — the last 32 bits XOR
///   `0xffff_ffff` carry the client's v4 endpoint.
///
/// Without this a `deny cidr=`/`deny host=` on an IPv4 endpoint is
/// bypassed by spelling the same endpoint in a transition form —
/// `CONNECT [64:ff9b::203.0.113.5]` reaches `203.0.113.5` wherever a
/// translator exists (DNS64/NAT64 networks, OS CLAT). Judging the
/// endpoint keeps denies effective on every spelling; an allow for
/// the endpoint legitimately covers them all, since they are the same
/// destination. Spellings carrying an embedded v4 under a
/// *non-well-known* prefix (site-specific NAT64/translation space)
/// are undetectable and still judged as the v6 they spell.
pub(crate) fn effective_endpoint(ip: IpAddr) -> IpAddr {
    match ip.to_canonical() {
        IpAddr::V6(v6) => embedded_v4(&v6).map_or(IpAddr::V6(v6), IpAddr::V4),
        v => v,
    }
}

/// The IPv4 a v6 transition spelling embeds, per [`effective_endpoint`].
fn embedded_v4(v6: &std::net::Ipv6Addr) -> Option<std::net::Ipv4Addr> {
    let s = v6.segments();
    if s[..6] == [0x0064, 0xff9b, 0, 0, 0, 0] {
        // NAT64 well-known prefix: last 32 bits are the v4 endpoint.
        let o = v6.octets();
        return Some(std::net::Ipv4Addr::new(o[12], o[13], o[14], o[15]));
    }
    if s[0] == 0x2002 {
        // 6to4: bits 16–48 are the relayed v4 endpoint.
        let o = v6.octets();
        return Some(std::net::Ipv4Addr::new(o[2], o[3], o[4], o[5]));
    }
    if s[..2] == [0x2001, 0x0000] {
        // Teredo: the last 32 bits XOR 0xffffffff name the client v4.
        let v = !u32::from_be_bytes([
            v6.octets()[12],
            v6.octets()[13],
            v6.octets()[14],
            v6.octets()[15],
        ]);
        return Some(std::net::Ipv4Addr::from(v));
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

    /// Decide one connect. `proto`/`port` are the socket's transport
    /// and the `sockaddr` destination port; `grant_names` are the live
    /// dynamic-grant names covering `dest` for audit, `grant_covered`
    /// whether any of those grants' qualifiers authorize this
    /// (proto, port) flow. Deny always precedes allow — a denied rule
    /// wins over every allow source, grants included.
    ///
    /// `dest` is judged as its [`effective_endpoint`]: a transition
    /// spelling (v4-mapped, NAT64, 6to4, Teredo) matches the deny and
    /// allow rules of the IPv4 endpoint it carries, so a v4 `deny`
    /// cannot be spelled around through a translator.
    pub fn evaluate(
        &self,
        dest: &IpAddr,
        proto: EgressProto,
        port: u16,
        grant_names: &[String],
        grant_covered: bool,
    ) -> IpVerdict {
        let dest = &effective_endpoint(*dest);
        if self.denied_any {
            return IpVerdict::Deny {
                decision: "deny-host",
                rule: Some("*".to_string()),
            };
        }
        if self.denied_literals.contains(dest) {
            return IpVerdict::Deny {
                decision: "deny-host",
                rule: Some(dest.to_string()),
            };
        }
        if let Some(rule) = self
            .denied_cidrs
            .iter()
            .find(|c| host::cidr_contains(c, dest))
        {
            return IpVerdict::Deny {
                decision: "deny-cidr",
                rule: Some(rule.clone()),
            };
        }
        if let Some(rule) = self.allows.iter().find(|r| {
            r.dest.matches(dest) && r.proto.covers(proto) && r.port.is_none_or(|p| p == port)
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
    fn effective_endpoint_unwraps_transition_spellings() {
        let cases: &[(&str, &str)] = &[
            // v4-mapped v6 — folded by to_canonical.
            ("::ffff:8.8.8.8", "8.8.8.8"),
            ("::ffff:7f00:1", "127.0.0.1"),
            // NAT64 well-known prefix (RFC 6052) — last 32 bits.
            ("64:ff9b::8.8.8.8", "8.8.8.8"),
            ("64:ff9b::cb00:7105", "203.0.113.5"),
            // 6to4 (RFC 3056) — bits 16–48.
            ("2002:0808:0808::", "8.8.8.8"),
            ("2002:cb00:7105::", "203.0.113.5"),
            // Teredo (RFC 4380) — last 32 bits XOR 0xffffffff.
            ("2001:0000::f7f7:f7f7", "8.8.8.8"),
        ];
        for (spelled, endpoint) in cases {
            assert_eq!(
                effective_endpoint(spelled.parse().unwrap()),
                endpoint.parse::<IpAddr>().unwrap(),
                "{spelled} must unwrap to {endpoint}"
            );
        }
        // Ordinary addresses pass through unchanged.
        for ip in ["8.8.8.8", "2606:4700:4700::1111", "fd00::1"] {
            let parsed: IpAddr = ip.parse().unwrap();
            assert_eq!(effective_endpoint(parsed), parsed);
        }
    }

    #[test]
    fn evaluate_denies_the_embedded_v4_endpoint() {
        // `CONNECT`/`connect(2)` to a transition spelling reaches the
        // embedded v4 endpoint — a deny on that endpoint must win on
        // every spelling.
        let outbound = OutboundPolicy {
            denied_cidrs: vec!["203.0.113.0/24".to_string()],
            denied_hosts: vec!["192.0.2.7".to_string()],
            deny_all_others: false,
            ..OutboundPolicy::default()
        };
        let ev = IpLayerEvaluator::build(&outbound, Context::ConnectProxy).unwrap();
        for dest in [
            "64:ff9b::cb00:7105", // NAT64 of 203.0.113.5
            "2002:cb00:7105::",   // 6to4 of 203.0.113.5
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
    fn evaluate_allows_the_embedded_v4_endpoint() {
        // An allow for the endpoint legitimately covers its transition
        // spellings — they are the same destination.
        let outbound = OutboundPolicy {
            allowed_cidrs: vec!["8.8.8.0/24".to_string()],
            deny_all_others: true,
            ..OutboundPolicy::default()
        };
        let ev = IpLayerEvaluator::build(&outbound, Context::ConnectProxy).unwrap();
        for dest in ["64:ff9b::808:808", "2002:0808:0808::", "8.8.8.8"] {
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
}
