//! IP-layer evaluator — the policy's static CIDR/literal rules, in the
//! same order `dnsgate::name_policy` decides the name layer.

use std::net::IpAddr;

use crate::policy::OutboundPolicy;
use crate::policy::host;

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

/// The IP-layer half of `OutboundPolicy`, pre-projected for the
/// supervisor: literal `host=` entries stand as `/32`/`/128` routes
/// (a literal needs no resolution — the same projection
/// `OutboundPolicy::ip_layer_allows`/`ip_layer_denies` documents),
/// `cidr=` rules stay canonical.
pub struct IpLayerEvaluator {
    deny_all_others: bool,
    denied_any: bool,
    denied_literals: Vec<IpAddr>,
    denied_cidrs: Vec<String>,
    allow_any: bool,
    allowed_literals: Vec<IpAddr>,
    allowed_cidrs: Vec<String>,
}

impl IpLayerEvaluator {
    /// Build the evaluator, refusing what this layer cannot express:
    /// an `allow` entry carrying an explicit `:port` would widen to
    /// every port at the IP layer — the same refusal contract PSEC
    /// applies (`allowed_*_port_qualified` provenance lists).
    pub fn new(outbound: &OutboundPolicy) -> Result<Self, String> {
        let ported: Vec<String> = outbound
            .allowed_port_qualified
            .iter()
            .filter(|raw| outbound.allowed.contains(&host::normalize_policy_host(raw)))
            .map(|e| format!("'{e}'"))
            .collect();
        let ported_cidrs: Vec<String> = outbound
            .allowed_cidrs_port_qualified
            .iter()
            .filter(|raw| {
                host::analyze_policy_cidr(raw)
                    .map(|(cidr, _)| outbound.allowed_cidrs.contains(&cidr))
                    .unwrap_or(false)
            })
            .map(|e| format!("'{e}'"))
            .collect();
        let mut refused = ported;
        refused.extend(ported_cidrs);
        if !refused.is_empty() {
            return Err(format!(
                "outbound allow entries {} carry a port qualifier the IP layer \
                 cannot express — drop the port (every port to the destination \
                 is allowed) or do not use unotify-run",
                refused.join(", ")
            ));
        }
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
        Ok(Self {
            deny_all_others: outbound.deny_all_others,
            denied_any: outbound.denied_hosts.iter().any(|d| d == "*"),
            denied_literals: outbound
                .denied_hosts
                .iter()
                .filter_map(|h| h.parse::<IpAddr>().ok())
                .collect(),
            denied_cidrs: outbound.denied_cidrs.clone(),
            allow_any: outbound.allowed.iter().any(|a| a == "*"),
            allowed_literals: outbound
                .allowed
                .iter()
                .filter_map(|h| h.parse::<IpAddr>().ok())
                .collect(),
            allowed_cidrs: outbound.allowed_cidrs.clone(),
        })
    }

    /// Decide one destination. `grant_names` is the live dynamic-grant
    /// set for `dest` (empty = no grant). Deny always precedes allow —
    /// a denied rule wins over every allow source, grants included.
    pub fn evaluate(&self, dest: &IpAddr, grant_names: &[String]) -> IpVerdict {
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
        if self.allow_any {
            return IpVerdict::Allow {
                basis: "allow-host",
                rule: Some("*".to_string()),
            };
        }
        if self.allowed_literals.contains(dest) {
            return IpVerdict::Allow {
                basis: "allow-host",
                rule: Some(dest.to_string()),
            };
        }
        if let Some(rule) = self
            .allowed_cidrs
            .iter()
            .find(|c| host::cidr_contains(c, dest))
        {
            return IpVerdict::Allow {
                basis: "allow-cidr",
                rule: Some(rule.clone()),
            };
        }
        if !grant_names.is_empty() {
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
