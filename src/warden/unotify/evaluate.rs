//! IP-layer evaluator — the policy's static CIDR/literal rules, in the
//! same order `dnsgate::name_policy` decides the name layer.
//!
//! A `connect(2)` notification carries the full flow tuple: destination
//! address and port from the `sockaddr`, transport from the socket's
//! `SO_TYPE`. The evaluator therefore enforces the structured egress
//! rules *with* their `proto=`/`port=` qualifiers — a `proto=udp` allow
//! never covers a TCP connect, and a `port=443` rule covers only 443.
//! What this layer still cannot see is spelled out in the module docs:
//! datagram egress that never calls `connect` (unconnected
//! `sendto`/`sendmsg`), and DNS names — those arrive through the
//! TTL-scoped grant path instead.

use std::net::IpAddr;

use crate::policy::OutboundPolicy;
use crate::policy::host;
use crate::policy::{EgressDest, EgressProto};

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
enum Context {
    Unotify,
    Namespaced,
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
    pub fn new(outbound: &OutboundPolicy) -> Result<Self, String> {
        Self::build(outbound, Context::Unotify)
    }

    /// PR-09 variant for the namespaced TUN proxy: the datagram
    /// warning does not apply — the proxy *does* see every datagram,
    /// which is exactly why it exists.
    pub fn new_namespaced(outbound: &OutboundPolicy) -> Result<Self, String> {
        Self::build(outbound, Context::Namespaced)
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
            tracing::warn!(
                rules = ?name_only_denies,
                "deny host rules on names are name-layer only — the IP layer \
                 never sees a hostname, so they stay unenforced here; dns-gate \
                 is the name-layer enforcement point"
            );
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
        if udp_capable && matches!(ctx, Context::Unotify) {
            tracing::warn!(
                "a UDP-capable allow rule exists (proto=udp/any or a \
                 UDP-scoped grant) — connect(2) is supervised per flow, \
                 but unconnected sendto/sendmsg datagrams are not \
                 visible to this layer (documented unotify limitation)"
            );
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
    pub fn evaluate(
        &self,
        dest: &IpAddr,
        proto: EgressProto,
        port: u16,
        grant_names: &[String],
        grant_covered: bool,
    ) -> IpVerdict {
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
