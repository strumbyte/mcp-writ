//! PR-16 — Linux egress-mechanism selection.
//!
//! The selection table (`docs/improvement-pr-guide-2026-10.ja.md`
//! `#linux-egress-selection`):
//!
//! | request / facts | outcome |
//! |---|---|
//! | `auto`, namespaced capable + satisfies the policy | `namespaced` |
//! | `auto`, namespaced unavailable, native satisfies | `native` |
//! | `auto`, neither satisfies | **refuse** |
//! | `namespaced`, unavailable or unsatisfiable | **refuse** — never falls back |
//! | `native`, unsatisfiable policy | **refuse** |
//!
//! "Satisfies" means every declared requirement lands on an
//! enforcement point that actually applies — never a silently wider
//! or narrower mapping:
//!
//! - **native** can express only a deny-all posture whose TCP allows
//!   are bare-port rules (`allow host="*" proto="tcp" port=N` —
//!   Landlock `ConnectTcp` binds a port, never a destination). A
//!   destination-scoped allow is kernel-denied with no rule matching,
//!   a UDP-covered allow is dead policy (datagram socket creation is
//!   denied outright under deny-all), an open posture or a
//!   destination deny cannot be subtracted, and inbound listen is
//!   never granted.
//! - **namespaced** covers TCP+UDP destination IP+port and name rules
//!   via the TUN proxy + embedded DNS gate — but only for IPv4 (v6
//!   destinations are dropped, so declaring them is unsatisfiable),
//!   name *allow* rules need a resolver the gate can forward to, and
//!   inbound listen has no path.
//!
//! `decide` is pure — the host facts (probe, upstream, kernel ABI,
//! both sandbox-bit builds) are gathered once in
//! [`select_linux_mechanism`] and passed in, so every row of the
//! selection table is unit-testable without namespaces.

use std::net::SocketAddr;

use crate::execution::{
    LinuxMechanismRequest, LinuxNativeMechanism, MechanismSelection, NamespacedProbeEvidence,
};
use crate::policy::{EgressDest, EgressProto, Policy};

use super::namespaced::{self, ProbeReport};

/// Host facts a selection decision reads — gathered once per
/// selection run and injected into [`decide`].
struct SelectionInput<'a> {
    policy: &'a Policy,
    /// The `namespaced-probe` result — `Err` when the helper could not
    /// run at all (spawn/parse failure), distinct from a ran probe
    /// that found missing stages.
    probe: &'a Result<ProbeReport, String>,
    /// The DNS upstream the embedded gate would forward to:
    /// `--dns-upstream`, else the first IPv4 nameserver in
    /// `/etc/resolv.conf`, else `None`.
    dns_upstream: Option<SocketAddr>,
    /// Kernel Landlock ABI — 0 when the kernel has no Landlock
    /// support. Measured through the same channel the apply record
    /// reports (`landlock_create_ruleset` version query).
    landlock_abi: u8,
    /// `prepare_linux_child_sandbox` build error, when the native
    /// rule build itself fails.
    native_build_err: Option<String>,
    /// `prepare_linux_child_sandbox_namespaced` build error.
    namespaced_build_err: Option<String>,
}

/// The selection outcome `run`/`plan` share. `selected == None` is a
/// refusal: `reason` + `violations` + `missing` state why, and the
/// caller refuses the launch rather than dispatch another mechanism.
pub struct LinuxSelection {
    pub requested: LinuxMechanismRequest,
    /// `None` = refused — no mechanism binds this launch.
    pub selected: Option<LinuxNativeMechanism>,
    /// One-line rationale (the pick's basis, or the refusal cause).
    pub reason: String,
    /// `linux-namespaced` `requires` ids unmet on this host (probe).
    pub missing: Vec<String>,
    /// Requirements a candidate mechanism could not satisfy — the
    /// strings themselves name the mechanism they belong to.
    pub violations: Vec<String>,
    /// Probe evidence — `Some` whenever the probe ran, regardless of
    /// outcome.
    pub probe: Option<ProbeReport>,
    /// Probe spawn/parse failure — distinct from "probe ran and found
    /// missing stages".
    pub probe_err: Option<String>,
    /// The upstream the embedded DNS gate would forward to on the
    /// namespaced route.
    pub dns_upstream: Option<SocketAddr>,
}

impl LinuxSelection {
    /// The plan/report `mechanism` member.
    pub fn to_record(&self) -> MechanismSelection {
        MechanismSelection {
            requested: self.requested.name(),
            selected: self.selected.map(LinuxNativeMechanism::capability_id),
            reason: Some(self.reason.clone()),
            missing: self.missing.clone(),
            violations: self.violations.clone(),
            dns_upstream: self.dns_upstream.map(|u| u.to_string()),
            probe: self.probe.as_ref().map(|p| NamespacedProbeEvidence {
                userns: p.userns,
                netns: p.netns,
                mountns: p.mountns,
                id_map: p.id_map,
                tun: p.tun,
                loopback_up: p.loopback_up,
                route: p.route,
                failed_stage: p.failed_stage.clone(),
                detail: p.detail.clone(),
            }),
            // The `namespaced` session member exists on the namespaced
            // route only — pre-allocated so the report's finalize step
            // can fill `stats`/`sandbox_applied` in place.
            namespaced: (self.selected == Some(LinuxNativeMechanism::Namespaced))
                .then(crate::execution::NamespacedSession::default),
        }
    }

    /// The mechanism id the launch target records (`Some` iff a
    /// mechanism is bound).
    pub fn target_mechanism(&self) -> Option<LinuxNativeMechanism> {
        self.selected
    }
}

/// Gather the host facts and run the selection — the one entry point
/// `run` (launch) and `plan` share so the pre-launch diagnosis and the
/// actual setup check can never diverge.
pub fn select_linux_mechanism(
    request: LinuxMechanismRequest,
    policy: &Policy,
    upstream_flag: Option<SocketAddr>,
) -> LinuxSelection {
    let probe = namespaced::run_probe();
    let dns_upstream = upstream_flag.or_else(resolv_conf_upstream);
    let landlock_abi = landlock_kernel_abi();
    // Both candidates' rule builds run now: a build failure is a
    // refusal reason, and building twice (here and at spawn) keeps the
    // judgment identical to what the launch would apply.
    let native_build_err = super::linux_spawn::prepare_linux_child_sandbox(policy)
        .map(|_| ())
        .err()
        .map(|e| e.to_string());
    let namespaced_build_err = super::linux_spawn::prepare_linux_child_sandbox_namespaced(policy)
        .map(|_| ())
        .err()
        .map(|e| e.to_string());
    decide(
        request,
        &SelectionInput {
            policy,
            probe: &probe,
            dns_upstream,
            landlock_abi,
            native_build_err,
            namespaced_build_err,
        },
    )
}

fn decide(request: LinuxMechanismRequest, input: &SelectionInput<'_>) -> LinuxSelection {
    // The report record carries the ran probe's evidence — cloned so
    // `input`'s borrow never conflicts with the move into the result.
    let probe = input.probe.clone().ok();
    let (missing, probe_err) = match &input.probe {
        Ok(p) => (p.missing().iter().map(|s| s.to_string()).collect(), None),
        Err(e) => (Vec::new(), Some(e.clone())),
    };
    let probe_capable = matches!(&input.probe, Ok(p) if p.capable());

    let namespaced_violations = namespaced_policy_violations(input);
    let native_violations = native_policy_violations(input);
    let ns_available = probe_capable && namespaced_violations.is_empty();
    let native_available = native_violations.is_empty();

    let (selected, reason, violations) = match request {
        LinuxMechanismRequest::Namespaced => {
            if !probe_capable {
                (
                    None,
                    format!(
                        "namespaced: launch refused — {}",
                        probe_unavailable_reason(input.probe, &missing)
                    ),
                    Vec::new(),
                )
            } else if !namespaced_violations.is_empty() {
                (
                    None,
                    "namespaced: launch refused — the policy exceeds what the \
                     namespaced route can satisfy; it never falls back to native"
                        .to_string(),
                    namespaced_violations,
                )
            } else {
                (
                    Some(LinuxNativeMechanism::Namespaced),
                    "namespaced: host probe passed and the route satisfies every \
                     policy requirement"
                        .to_string(),
                    Vec::new(),
                )
            }
        }
        LinuxMechanismRequest::Native => {
            if !native_violations.is_empty() {
                (
                    None,
                    "native: launch refused — the policy exceeds what the native \
                     Landlock+seccomp route can satisfy"
                        .to_string(),
                    native_violations,
                )
            } else {
                (
                    Some(LinuxNativeMechanism::Native),
                    "native: the route satisfies every policy requirement".to_string(),
                    Vec::new(),
                )
            }
        }
        LinuxMechanismRequest::Auto => {
            if ns_available {
                (
                    Some(LinuxNativeMechanism::Namespaced),
                    "auto: namespaced selected — host probe passed and the route \
                     satisfies every policy requirement"
                        .to_string(),
                    Vec::new(),
                )
            } else if native_available {
                (
                    Some(LinuxNativeMechanism::Native),
                    format!(
                        "auto: native selected — {} and native satisfies the policy",
                        ns_unavailable_reason(input.probe, &namespaced_violations, &missing)
                    ),
                    Vec::new(),
                )
            } else {
                let mut violations = namespaced_violations;
                violations.extend(native_violations);
                (
                    None,
                    format!(
                        "auto: launch refused — {} and native cannot satisfy the \
                         policy either; there is no weaker mechanism to fall back to",
                        ns_unavailable_reason(input.probe, &[], &missing)
                    ),
                    violations,
                )
            }
        }
    };
    LinuxSelection {
        requested: request,
        selected,
        reason,
        missing,
        violations,
        probe,
        probe_err,
        dns_upstream: input.dns_upstream,
    }
}

/// Why the namespaced route is out for `auto`: the probe's missing
/// ids when it is incapable, else the policy's first violation.
fn ns_unavailable_reason(
    probe: &Result<ProbeReport, String>,
    violations: &[String],
    missing: &[String],
) -> String {
    match probe {
        Err(e) => format!("namespaced is unavailable (probe failed: {e})"),
        Ok(p) if !p.capable() => {
            format!(
                "namespaced is unavailable (missing: {})",
                missing.join(", ")
            )
        }
        Ok(_) => format!(
            "namespaced cannot satisfy the policy ({})",
            violations
                .first()
                .cloned()
                .unwrap_or_else(|| "requirement inexpressible".to_string())
        ),
    }
}

fn probe_unavailable_reason(probe: &Result<ProbeReport, String>, missing: &[String]) -> String {
    match probe {
        Err(e) => format!("the capability probe could not run: {e}"),
        Ok(p) if !p.capable() => format!(
            "the capability probe found missing stages: {}",
            missing.join(", ")
        ),
        Ok(_) => "unreachable: a capable probe cannot refuse".to_string(),
    }
}

// ---------------------------------------------------------------------------
// Policy ↔ mechanism expressibility checks
// ---------------------------------------------------------------------------

fn is_v6_cidr(c: &str) -> bool {
    c.contains(':')
}

/// `allow host=` entries that are host *names* (not `*`, not an IP
/// literal) need the DNS gate's upstream resolver to mint grants.
fn dest_needs_dns(dest: &EgressDest) -> Option<&str> {
    match dest {
        EgressDest::Host(h) if h != "*" && !crate::policy::host::host_is_ip_literal(h) => {
            Some(h.as_str())
        }
        _ => None,
    }
}

/// Requirements the namespaced route cannot satisfy — every string
/// names the rule and the limitation, so a refusal is diagnosable
/// without source access.
fn namespaced_policy_violations(input: &SelectionInput<'_>) -> Vec<String> {
    let policy = input.policy;
    let out = &policy.network.outbound;
    let mut v = Vec::new();

    for rule in out.egress_rules() {
        if !rule.allow {
            continue;
        }
        let text = rule.describe();
        match &rule.dest {
            // IPv6 destinations are unsatisfiable: the route is
            // IPv4-only and the flow would be dropped — declaring it
            // cannot silently mean "dropped on purpose".
            EgressDest::Host(h) if h.parse::<std::net::Ipv6Addr>().is_ok() => {
                v.push(format!(
                    "egress rule '{text}' names an IPv6 destination — the \
                     namespaced route is IPv4-only and would drop the flow"
                ));
            }
            EgressDest::Cidr(c) if is_v6_cidr(c) => {
                v.push(format!(
                    "egress rule '{text}' names an IPv6 destination — the \
                     namespaced route is IPv4-only and would drop the flow"
                ));
            }
            _ => {}
        }
        if let Some(_) = dest_needs_dns(&rule.dest)
            && input.dns_upstream.is_none()
        {
            v.push(format!(
                "egress rule '{text}' allows a host name — no upstream resolver \
                 is configured (pass --dns-upstream or set an IPv4 nameserver in \
                 /etc/resolv.conf); a name allow can never mint a grant"
            ));
        }
    }

    if policy.network.inbound.allow_listen {
        v.push(
            "inbound listen cannot be granted — the namespaced network \
             namespace has no inbound path (all egress dead-ends at the TUN \
             proxy)"
                .to_string(),
        );
    }

    if input.landlock_abi == 0 && !policy.sandbox.allow_degraded {
        v.push(
            "the kernel has no Landlock support — the filesystem rules the \
             in-namespace sandbox applies cannot be enforced (and \
             sandbox.allow_degraded does not tolerate their absence)"
                .to_string(),
        );
    }
    if let Some(e) = &input.namespaced_build_err {
        v.push(format!("namespaced sandbox rule build failed: {e}"));
    }
    v
}

/// Requirements the native Landlock+seccomp route cannot satisfy.
/// The predicate mirrors exactly what the route enforces today:
/// deny-all posture + bare-port TCP allows + no UDP + no inbound —
/// plus the enforcement level the apply gate accepts
/// (`allow_degraded` tolerates a partial/absent Landlock ruleset just
/// as the launch-time `enforcement_gate` does).
fn native_policy_violations(input: &SelectionInput<'_>) -> Vec<String> {
    let policy = input.policy;
    let out = &policy.network.outbound;
    let mut v = Vec::new();

    if !out.deny_all_others {
        v.push(
            "the outbound posture is open (deny-all is off) — the native \
             path's Landlock ConnectTcp handling has no open-posture rule, \
             so every TCP connect would be kernel-denied and deny rules \
             cannot be subtracted"
                .to_string(),
        );
    } else {
        for rule in out.egress_rules() {
            if !rule.allow {
                continue;
            }
            let text = rule.describe();
            if rule.proto.covers(EgressProto::Udp) {
                v.push(format!(
                    "egress rule '{text}' grants UDP — under deny-all the native \
                     path denies datagram socket creation outright, so the \
                     allow is dead policy; UDP needs the namespaced route"
                ));
                continue;
            }
            match &rule.dest {
                EgressDest::Host(h) if h == "*" => {
                    if rule.port.is_none() {
                        v.push(format!(
                            "egress rule '{text}' grants TCP to any destination on \
                             any port — Landlock netport rules bind a port only, \
                             so the whole allow surface would be kernel-denied"
                        ));
                    }
                }
                _ => {
                    v.push(format!(
                        "egress rule '{text}' binds a destination — Landlock \
                         netport rules bind a port only, so the allow's \
                         connects would be kernel-denied; destination \
                         narrowing needs the namespaced route"
                    ));
                }
            }
        }
    }

    if policy.network.inbound.allow_listen {
        v.push(
            "inbound listen cannot be granted — Landlock BindTcp is not used \
             on this path, so the permission is never delivered"
                .to_string(),
        );
    }

    if !policy.sandbox.allow_degraded {
        if input.landlock_abi == 0 {
            v.push(
                "the kernel has no Landlock support — the fs/net rules cannot \
                 be enforced (and sandbox.allow_degraded does not tolerate \
                 their absence)"
                    .to_string(),
            );
        } else if input.landlock_abi < 4
            && out
                .egress_rules()
                .iter()
                .any(|r| r.allow && r.proto.covers(EgressProto::Tcp))
        {
            v.push(format!(
                "kernel Landlock ABI v{} predates network rules (v4) — the TCP \
                 port allow surface would be dropped",
                input.landlock_abi
            ));
        }
    }
    if let Some(e) = &input.native_build_err {
        v.push(format!("native sandbox rule build failed: {e}"));
    }
    v
}

// ---------------------------------------------------------------------------
// Host facts
// ---------------------------------------------------------------------------

/// Kernel Landlock ABI via `landlock_create_ruleset(_, 0,
/// LANDLOCK_CREATE_RULESET_VERSION)` — the documented runtime query
/// (returns the ABI version, or <0 when the syscall does not exist).
/// 0 = Landlock unavailable.
fn landlock_kernel_abi() -> u8 {
    const LANDLOCK_CREATE_RULESET_VERSION: u32 = 1;
    let ret = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            std::ptr::null::<libc::c_void>(),
            0usize,
            LANDLOCK_CREATE_RULESET_VERSION,
        )
    };
    if ret < 0 { 0 } else { ret as u8 }
}

/// First IPv4 `nameserver` in `/etc/resolv.conf` — the resolver the
/// embedded DNS gate forwards to when `--dns-upstream` is absent.
/// IPv6 resolvers are unusable (the namespaced route is IPv4-only)
/// and skipped, never aliased to a v4 placeholder.
fn resolv_conf_upstream() -> Option<SocketAddr> {
    let body = std::fs::read_to_string("/etc/resolv.conf").ok()?;
    for line in body.lines() {
        let line = line.trim();
        if line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        let mut it = line.split_whitespace();
        if it.next() != Some("nameserver") {
            continue;
        }
        if let Some(addr) = it.next().and_then(|a| a.parse::<std::net::Ipv4Addr>().ok()) {
            return Some(SocketAddr::new(addr.into(), 53));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{EgressProto, EgressRule};

    fn probe(all_ok: bool) -> Result<ProbeReport, String> {
        Ok(ProbeReport {
            userns: all_ok,
            netns: all_ok,
            mountns: all_ok,
            id_map: all_ok,
            tun: all_ok,
            loopback_up: all_ok,
            route: all_ok,
            failed_stage: None,
            detail: None,
        })
    }

    fn input<'a>(
        policy: &'a Policy,
        probe: &'a Result<ProbeReport, String>,
        upstream: Option<SocketAddr>,
        abi: u8,
    ) -> SelectionInput<'a> {
        SelectionInput {
            policy,
            probe,
            dns_upstream: upstream,
            landlock_abi: abi,
            native_build_err: None,
            namespaced_build_err: None,
        }
    }

    fn upstream() -> Option<SocketAddr> {
        "10.0.0.1:53".parse().ok()
    }

    fn deny_all_policy() -> Policy {
        Policy::default()
    }

    fn bare_port_policy() -> Policy {
        let mut p = Policy::default();
        p.network.outbound.egress_rules = vec![EgressRule {
            allow: true,
            dest: EgressDest::Host("*".to_string()),
            proto: EgressProto::Tcp,
            port: Some(443),
        }];
        p
    }

    fn name_allow_policy() -> Policy {
        let mut p = Policy::default();
        p.network.outbound.egress_rules = vec![EgressRule {
            allow: true,
            dest: EgressDest::Host("api.example.com".to_string()),
            proto: EgressProto::Any,
            port: None,
        }];
        p
    }

    fn udp_allow_policy() -> Policy {
        let mut p = Policy::default();
        p.network.outbound.egress_rules = vec![EgressRule {
            allow: true,
            dest: EgressDest::Host("*".to_string()),
            proto: EgressProto::Udp,
            port: Some(53),
        }];
        p
    }

    // --- selection table rows -------------------------------------

    #[test]
    fn auto_prefers_namespaced_when_capable_and_satisfiable() {
        let p = name_allow_policy();
        let pr = probe(true);
        let sel = decide(LinuxMechanismRequest::Auto, &input(&p, &pr, upstream(), 8));
        assert_eq!(sel.selected, Some(LinuxNativeMechanism::Namespaced));
        assert!(sel.violations.is_empty());
    }

    #[test]
    fn auto_native_when_namespaced_missing_and_native_satisfies() {
        let p = bare_port_policy();
        let mut r = probe(true).unwrap();
        r.tun = false;
        let pr = Ok(r);
        let sel = decide(LinuxMechanismRequest::Auto, &input(&p, &pr, upstream(), 8));
        assert_eq!(sel.selected, Some(LinuxNativeMechanism::Native));
        assert_eq!(sel.missing, vec!["tun".to_string()]);
    }

    #[test]
    fn auto_refuses_when_neither_satisfies() {
        // A dest-scoped allow: namespaced could satisfy it, but the
        // host lacks tun; native can never bind a destination.
        let p = name_allow_policy();
        let mut r = probe(true).unwrap();
        r.tun = false;
        let pr = Ok(r);
        let sel = decide(LinuxMechanismRequest::Auto, &input(&p, &pr, upstream(), 8));
        assert_eq!(sel.selected, None);
        assert!(!sel.violations.is_empty());
    }

    #[test]
    fn explicit_namespaced_refuses_when_probe_missing() {
        let p = deny_all_policy();
        let mut r = probe(true).unwrap();
        r.userns = false;
        let pr = Ok(r);
        let sel = decide(
            LinuxMechanismRequest::Namespaced,
            &input(&p, &pr, upstream(), 8),
        );
        assert_eq!(sel.selected, None);
        assert_eq!(sel.missing, vec!["userns".to_string()]);
    }

    #[test]
    fn explicit_namespaced_refuses_probe_spawn_failure() {
        let p = deny_all_policy();
        let pr: Result<ProbeReport, String> = Err("probe spawn failed".to_string());
        let sel = decide(
            LinuxMechanismRequest::Namespaced,
            &input(&p, &pr, upstream(), 8),
        );
        assert_eq!(sel.selected, None);
        assert_eq!(sel.probe_err.as_deref(), Some("probe spawn failed"));
    }

    #[test]
    fn explicit_namespaced_refuses_ipv6_policy() {
        let mut p = Policy::default();
        p.network.outbound.egress_rules = vec![EgressRule {
            allow: true,
            dest: EgressDest::Cidr("2001:db8::/32".to_string()),
            proto: EgressProto::Any,
            port: None,
        }];
        let pr = probe(true);
        let sel = decide(
            LinuxMechanismRequest::Namespaced,
            &input(&p, &pr, upstream(), 8),
        );
        assert_eq!(sel.selected, None);
        assert!(sel.violations.iter().any(|s| s.contains("IPv6")));
    }

    #[test]
    fn explicit_native_refuses_dest_scoped_allow() {
        // proto=tcp isolates the destination-binding refusal — an
        // `any` rule would already refuse on its UDP coverage.
        let mut p = Policy::default();
        p.network.outbound.egress_rules = vec![EgressRule {
            allow: true,
            dest: EgressDest::Host("api.example.com".to_string()),
            proto: EgressProto::Tcp,
            port: Some(443),
        }];
        let pr = probe(true);
        let sel = decide(
            LinuxMechanismRequest::Native,
            &input(&p, &pr, upstream(), 8),
        );
        assert_eq!(sel.selected, None);
        assert!(
            sel.violations
                .iter()
                .any(|s| s.contains("binds a destination"))
        );
    }

    #[test]
    fn explicit_native_accepts_bare_port_tcp() {
        let p = bare_port_policy();
        let pr = probe(true);
        let sel = decide(
            LinuxMechanismRequest::Native,
            &input(&p, &pr, upstream(), 8),
        );
        assert_eq!(sel.selected, Some(LinuxNativeMechanism::Native));
    }

    #[test]
    fn native_refuses_udp_allow_as_dead_policy() {
        let p = udp_allow_policy();
        let pr = probe(true);
        let sel = decide(
            LinuxMechanismRequest::Native,
            &input(&p, &pr, upstream(), 8),
        );
        assert_eq!(sel.selected, None);
        assert!(sel.violations.iter().any(|s| s.contains("grants UDP")));
    }

    #[test]
    fn native_refuses_open_posture() {
        let mut p = Policy::default();
        p.network.outbound.deny_all_others = false;
        let pr = probe(true);
        let sel = decide(
            LinuxMechanismRequest::Native,
            &input(&p, &pr, upstream(), 8),
        );
        assert_eq!(sel.selected, None);
    }

    #[test]
    fn namespaced_needs_upstream_for_name_allows() {
        let p = name_allow_policy();
        let pr = probe(true);
        let sel = decide(LinuxMechanismRequest::Namespaced, &input(&p, &pr, None, 8));
        assert_eq!(sel.selected, None);
        assert!(sel.violations.iter().any(|s| s.contains("host name")));
    }

    #[test]
    fn namespaced_satisfies_name_allow_with_upstream() {
        let p = name_allow_policy();
        let pr = probe(true);
        let sel = decide(
            LinuxMechanismRequest::Namespaced,
            &input(&p, &pr, upstream(), 8),
        );
        assert_eq!(sel.selected, Some(LinuxNativeMechanism::Namespaced));
    }

    #[test]
    fn auto_namespaced_capable_but_policy_unsatisfiable_falls_to_native_check() {
        // IPv6 rule: namespaced cannot satisfy (v6 dropped); the
        // policy's TCP allow is also dest-scoped, so native cannot
        // either → refuse (row 3).
        let mut p = Policy::default();
        p.network.outbound.egress_rules = vec![EgressRule {
            allow: true,
            dest: EgressDest::Cidr("2001:db8::/32".to_string()),
            proto: EgressProto::Any,
            port: None,
        }];
        let pr = probe(true);
        let sel = decide(LinuxMechanismRequest::Auto, &input(&p, &pr, upstream(), 8));
        assert_eq!(sel.selected, None);
    }

    #[test]
    fn old_kernel_landlock_blocks_native_tcp_allows() {
        let p = bare_port_policy();
        let pr = probe(true);
        let sel = decide(
            LinuxMechanismRequest::Native,
            &input(&p, &pr, upstream(), 3),
        );
        assert_eq!(sel.selected, None);
        // allow_degraded tolerates the partial enforcement level.
        let mut p2 = bare_port_policy();
        p2.sandbox.allow_degraded = true;
        let sel = decide(
            LinuxMechanismRequest::Native,
            &input(&p2, &pr, upstream(), 3),
        );
        assert_eq!(sel.selected, Some(LinuxNativeMechanism::Native));
    }

    #[test]
    fn namespaced_ignores_low_abi_for_egress() {
        // Landlock <4 cannot express netport rules, but the TUN proxy
        // is the egress authority on this route — only abi==0 fs-rule
        // loss matters.
        let p = bare_port_policy();
        let pr = probe(true);
        let sel = decide(
            LinuxMechanismRequest::Namespaced,
            &input(&p, &pr, upstream(), 3),
        );
        assert_eq!(sel.selected, Some(LinuxNativeMechanism::Namespaced));
    }

    #[test]
    fn inbound_listen_is_unsatisfiable_on_both() {
        let mut p = Policy::default();
        p.network.inbound.allow_listen = true;
        let pr = probe(true);
        for req in [
            LinuxMechanismRequest::Namespaced,
            LinuxMechanismRequest::Native,
        ] {
            let sel = decide(req, &input(&p, &pr, upstream(), 8));
            assert_eq!(sel.selected, None, "{req:?} must refuse inbound listen");
        }
    }
}
