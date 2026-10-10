//! Name-layer evaluation of a DNS query name against `OutboundPolicy`.
//!
//! The decision deliberately mirrors the Auditor's RPC argument check
//! (`auditor::checker::sub_policy`): same `host_matches` semantics, same
//! deny-precedence — a name the Auditor would allow in an argument is
//! the name this gate resolves, and vice versa. `deny_all_others`
//! applies unconditionally: the Auditor's global check carves out the
//! empty-allow case because the tool layer and the OS sandbox still sit
//! behind it, but the gate is the terminal name-layer enforcement
//! point — `deny host="*"` with no allow rules refuses every name
//! rather than falling through to a lower layer that does not exist
//! here. `allow cidr=`/`deny cidr=` evaluate only IP-literal query
//! names; a DNS name is never resolved for policy (evaluation touches
//! the queried name alone — CNAME targets the answer reveals are
//! observed, never re-judged).

/// The policy verdict for one query name.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Verdict {
    /// The name resolves — forward under the canonical spelling.
    Allow,
    /// The name is refused — the matching rule is recorded for audit.
    Deny(DenyReason),
}

/// Why a name was refused — each variant names the rule space that
/// matched (`Host`/`Cidr` carry the matching rule's text for audit).
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum DenyReason {
    /// A `deny host=` rule matched.
    Host(String),
    /// A `deny cidr=` rule matched an IP-literal query name.
    Cidr(String),
    /// `deny_all_others` is in force and no allow rule covered the name.
    NotAllowed,
}

impl DenyReason {
    /// Short stable token for the audit `decision=` field.
    pub(crate) fn decision(&self) -> &'static str {
        match self {
            Self::Host(_) => "deny-host",
            Self::Cidr(_) => "deny-cidr",
            Self::NotAllowed => "not-allowed",
        }
    }

    /// The matching rule's policy text, when one exists.
    pub(crate) fn rule(&self) -> Option<&str> {
        match self {
            Self::Host(r) | Self::Cidr(r) => Some(r),
            Self::NotAllowed => None,
        }
    }
}

/// Result of evaluating one query name: the canonical spelling that
/// goes on the wire upstream and into the audit record, plus the verdict.
pub(crate) struct EvalOutcome {
    pub canonical: String,
    pub verdict: Verdict,
    /// The proto/port qualifiers of every allow rule covering the
    /// name — the scope under which the answer mints destination
    /// grants. Empty when the verdict is `Deny`; on `Allow` it always
    /// carries at least one qualifier set (an open posture yields the
    /// unconstrained `{any, *}` tag).
    pub quals: Vec<crate::policy::GrantQual>,
}

/// Canonicalize `qname` through the same pipeline the Auditor applies
/// to a host argument (strip → UTS-46/IDNA → URL-grammar fold) and
/// evaluate the name layer of `outbound`.
///
/// Deny wins over allow, exactly as the Auditor decides: a `deny
/// host=`/`deny cidr=` match refuses even when an allow rule also
/// covers the name. Under `deny_all_others` every name without a
/// covering allow rule is refused — including when the allow lists are
/// empty, since nothing sits behind the gate to close that hole.
pub(crate) fn evaluate(outbound: &crate::policy::OutboundPolicy, qname: &str) -> EvalOutcome {
    let canonical = super::canonical_name(qname);

    for denied in &outbound.denied_hosts {
        if crate::policy::host::host_matches(&canonical, denied) {
            return EvalOutcome {
                canonical,
                verdict: Verdict::Deny(DenyReason::Host(denied.clone())),
                quals: Vec::new(),
            };
        }
    }
    // IP layer: an IP-literal query name is also evaluated against the
    // `cidr` rules — `denied_hosts` IP literals already matched exactly
    // via `host_matches` above. Mirrors the Auditor's argument check.
    let ip = canonical.parse::<std::net::IpAddr>().ok();
    if let Some(ip) = ip {
        for denied in &outbound.denied_cidrs {
            if crate::policy::host::cidr_contains(denied, &ip) {
                return EvalOutcome {
                    canonical,
                    verdict: Verdict::Deny(DenyReason::Cidr(denied.clone())),
                    quals: Vec::new(),
                };
            }
        }
    }
    // The covering allow rules' qualifiers — what a minted grant
    // authorizes. `host=` rules match names and `*` covers every
    // name; `cidr=` rules cover IP-literal query names. A bare-port
    // rule (`allow host="443"`, `Host("*")` + port) resolves any name
    // and scopes the grant to its proto/port — resolving a name never
    // itself commits to a transport.
    let mut quals: Vec<crate::policy::GrantQual> = outbound
        .egress_rules()
        .iter()
        .filter(|r| r.allow)
        .filter(|r| match &r.dest {
            crate::policy::EgressDest::Host(h) => crate::policy::host::host_matches(&canonical, h),
            crate::policy::EgressDest::Cidr(c) => {
                ip.is_some_and(|ip| crate::policy::host::cidr_contains(c, &ip))
            }
        })
        .map(|r| crate::policy::GrantQual {
            proto: r.proto,
            port: r.port,
        })
        .collect();
    quals.sort();
    quals.dedup();
    if outbound.deny_all_others && quals.is_empty() {
        return EvalOutcome {
            canonical,
            verdict: Verdict::Deny(DenyReason::NotAllowed),
            quals: Vec::new(),
        };
    }
    if quals.is_empty() {
        // Open posture (`deny_all_others=false`): resolution is free,
        // and the grants minted from it must authorize any flow.
        quals.push(crate::policy::GrantQual {
            proto: crate::policy::EgressProto::Any,
            port: None,
        });
    }
    EvalOutcome {
        canonical,
        verdict: Verdict::Allow,
        quals,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{NetworkPolicy, OutboundPolicy, Policy};

    fn outbound(
        allowed: &[&str],
        denied: &[&str],
        cidrs: &[&str],
        deny_all: bool,
    ) -> OutboundPolicy {
        OutboundPolicy {
            allowed: allowed.iter().map(|s| s.to_string()).collect(),
            allowed_port_qualified: Vec::new(),
            allowed_cidrs: cidrs.iter().map(|s| s.to_string()).collect(),
            allowed_cidrs_port_qualified: Vec::new(),
            denied_hosts: denied.iter().map(|s| s.to_string()).collect(),
            denied_cidrs: Vec::new(),
            deny_all_others: deny_all,
            egress_rules: Vec::new(),
        }
    }

    #[test]
    fn exact_allow_under_deny_all() {
        let p = outbound(&["api.example.com"], &[], &[], true);
        let r = evaluate(&p, "api.example.com");
        assert_eq!(r.canonical, "api.example.com");
        assert_eq!(r.verdict, Verdict::Allow);
        let r = evaluate(&p, "other.example.com");
        assert_eq!(r.verdict, Verdict::Deny(DenyReason::NotAllowed));
    }

    #[test]
    fn deny_wins_over_allow() {
        let p = outbound(&["*.example.com"], &["bad.example.com"], &[], true);
        assert_eq!(
            evaluate(&p, "bad.example.com").verdict,
            Verdict::Deny(DenyReason::Host("bad.example.com".into()))
        );
        assert_eq!(evaluate(&p, "ok.example.com").verdict, Verdict::Allow);
    }

    #[test]
    fn wildcard_bare_domain_not_covered() {
        // `*.example.com` must not cover the bare domain — same as the
        // Auditor's `host_matches`.
        let p = outbound(&["*.example.com"], &[], &[], true);
        assert_eq!(
            evaluate(&p, "example.com").verdict,
            Verdict::Deny(DenyReason::NotAllowed)
        );
        assert_eq!(evaluate(&p, "a.example.com").verdict, Verdict::Allow);
    }

    #[test]
    fn deny_all_empty_allow_list_refuses_all() {
        // deny_all_others with no allow rules — `deny host="*"` alone,
        // an empty `network` block, or no `network` block at all —
        // refuses every name. The Auditor's empty-allow carve-out relies
        // on the OS sandbox behind it; the gate has nothing behind it,
        // so the same shape would leave it an open resolver.
        let p = outbound(&[], &[], &[], true);
        assert_eq!(
            evaluate(&p, "anything.example").verdict,
            Verdict::Deny(DenyReason::NotAllowed)
        );
        assert_eq!(
            evaluate(&p, "10.1.2.3").verdict,
            Verdict::Deny(DenyReason::NotAllowed)
        );
    }

    #[test]
    fn open_posture_allows_all_names() {
        // `allow host="*"` clears deny_all_others — the only genuinely
        // unrestricted posture.
        let p = outbound(&[], &[], &[], false);
        assert_eq!(evaluate(&p, "anything.example").verdict, Verdict::Allow);
    }

    #[test]
    fn deny_star_refuses_everything() {
        let p = outbound(&["api.example.com"], &["*"], &[], true);
        assert_eq!(
            evaluate(&p, "api.example.com").verdict,
            Verdict::Deny(DenyReason::Host("*".into()))
        );
    }

    #[test]
    fn uts46_and_trailing_dot_canonicalize() {
        let p = outbound(&["example.com"], &[], &[], true);
        // Trailing root dot and case fold to the same identity.
        assert_eq!(evaluate(&p, "EXAMPLE.com.").verdict, Verdict::Allow);
        // Full-width dot spelling of the same name.
        assert_eq!(evaluate(&p, "ｅｘａｍｐｌｅ.com").verdict, Verdict::Allow);
    }

    #[test]
    fn ip_literal_qname_against_cidr_rules() {
        let mut p = outbound(&["10.0.0.0/8"], &[], &["10.0.0.0/8"], true);
        assert_eq!(evaluate(&p, "10.1.2.3").verdict, Verdict::Allow);
        p.denied_cidrs = vec!["10.9.0.0/16".into()];
        assert_eq!(
            evaluate(&p, "10.9.9.9").verdict,
            Verdict::Deny(DenyReason::Cidr("10.9.0.0/16".into()))
        );
    }

    #[test]
    fn canonical_name_is_used_for_matching() {
        // URL-shaped allow rule collapses to its host — matching happens
        // on the canonical host, so `https://` spellings cannot be used
        // to smuggle a different identity.
        let p = outbound(&["https://api.example.com"], &[], &[], true);
        assert_eq!(evaluate(&p, "api.example.com").verdict, Verdict::Allow);
    }

    #[test]
    fn policy_level_outbound_field_is_evaluated() {
        // The evaluator consumes `Policy::network.outbound` — the same
        // effective rules the Auditor reads.
        let policy = Policy {
            network: NetworkPolicy {
                outbound: outbound(&["allowed.example"], &[], &[], true),
                ..NetworkPolicy::default()
            },
            ..Policy::default()
        };
        assert_eq!(
            evaluate(&policy.network.outbound, "allowed.example").verdict,
            Verdict::Allow
        );
    }
}
