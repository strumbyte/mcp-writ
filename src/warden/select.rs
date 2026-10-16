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
    /// that found missing stages. `None` when the probe never ran
    /// (an explicit `native` request skips it — the route it measures
    /// cannot be selected anyway).
    probe: Option<&'a Result<ProbeReport, String>>,
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
            // The upstream is namespaced-route evidence — a record for
            // the native route (selected, or a native-only request)
            // must not carry a configuration that route never consults.
            dns_upstream: self
                .dns_upstream
                .filter(|_| {
                    self.requested != LinuxMechanismRequest::Native
                        && self.selected != Some(LinuxNativeMechanism::Native)
                })
                .map(|u| u.to_string()),
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
    // An explicit `native` request never dispatches the namespaced
    // route — skip the namespaced probe (a re-exec plus a full
    // namespace exercise) rather than pay for evidence no outcome
    // reads. `auto`/`namespaced` still probe: the evidence decides
    // the route and lands in the report either way.
    let probe = match request {
        LinuxMechanismRequest::Native => None,
        _ => Some(namespaced::run_probe()),
    };
    let dns_upstream = upstream_flag.or_else(resolv_conf_upstream);
    let landlock_abi = crate::warden::landlock_impl::kernel_abi();
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
            probe: probe.as_ref(),
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
    // `None` probe = the probe never ran (explicit native request) —
    // no missing evidence and no error is fabricated for it.
    let probe = input.probe.and_then(|r| r.clone().ok());
    let (missing, probe_err) = match &input.probe {
        Some(Ok(p)) => (p.missing().iter().map(|s| s.to_string()).collect(), None),
        Some(Err(e)) => (Vec::new(), Some(e.clone())),
        None => (Vec::new(), None),
    };
    let probe_capable = matches!(&input.probe, Some(Ok(p)) if p.capable());

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
                    // Policy violations are real evidence even when the
                    // probe failed first — a refusal that hides them
                    // would misdiagnose "fix the host" over "fix both".
                    namespaced_violations,
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
                // The reason names the actual policy violations too —
                // an empty slice would collapse it to the "requirement
                // inexpressible" placeholder and hide why namespaced
                // was out.
                let mut violations = namespaced_violations;
                let reason = format!(
                    "auto: launch refused — {} and native cannot satisfy the \
                     policy either; there is no weaker mechanism to fall back to",
                    ns_unavailable_reason(input.probe, &violations, &missing)
                );
                violations.extend(native_violations);
                (None, reason, violations)
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
    probe: Option<&Result<ProbeReport, String>>,
    violations: &[String],
    missing: &[String],
) -> String {
    match probe {
        Some(Err(e)) => format!("namespaced is unavailable (probe failed: {e})"),
        Some(Ok(p)) if !p.capable() => {
            format!(
                "namespaced is unavailable (missing: {})",
                missing.join(", ")
            )
        }
        Some(Ok(_)) => format!(
            "namespaced cannot satisfy the policy ({})",
            violations
                .first()
                .cloned()
                .unwrap_or_else(|| "requirement inexpressible".to_string())
        ),
        // `auto` always probes — kept only so the signature stays
        // honest if a future request mode skips it.
        None => "namespaced is unavailable (capability probe not run)".to_string(),
    }
}

fn probe_unavailable_reason(
    probe: Option<&Result<ProbeReport, String>>,
    missing: &[String],
) -> String {
    match probe {
        Some(Err(e)) => format!("the capability probe could not run: {e}"),
        Some(Ok(p)) if !p.capable() => format!(
            "the capability probe found missing stages: {}",
            missing.join(", ")
        ),
        // An explicit `namespaced` request always probes — these arms
        // exist so the helper stays total if that ever changes.
        Some(Ok(_)) => "unreachable: a capable probe cannot refuse".to_string(),
        None => "the capability probe did not run".to_string(),
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
            // The in-namespace seccomp pin denies AF_UNIX creation
            // unconditionally — a unix opt-in can never resolve inside
            // the namespace, so declaring one is dead policy.
            EgressDest::Unix(_) => {
                v.push(format!(
                    "egress rule '{text}' grants an AF_UNIX opt-in — the \
                     namespaced route pins socket() families to \
                     AF_INET/AF_INET6 and cannot express it; the native \
                     route can"
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
        // A port-53 allow is dead policy while the DNS gate is armed:
        // every :53 flow (UDP and TCP alike) is intercepted to the
        // gate, which answers by query *name* — the destination-scoped
        // grant is never evaluated. With no upstream there is no gate
        // and :53 falls through to the ordinary evaluator.
        if rule.allow && rule.port == Some(53) && input.dns_upstream.is_some() {
            v.push(format!(
                "egress rule '{text}' allows port 53 — the namespaced route \
                 intercepts all DNS traffic at the embedded gate, so the \
                 destination-scoped allow never reaches the evaluator"
            ));
        }
    }
    for rule in out.egress_rules() {
        // A destination-scoped :53 *deny* is dead under the gate for
        // the same reason: the flow never reaches the evaluator, so the
        // resolver it meant to block is silently reachable.
        if !rule.allow && rule.port == Some(53) && input.dns_upstream.is_some() {
            v.push(format!(
                "egress deny '{}' names port 53 — the namespaced route \
                 intercepts all DNS traffic at the embedded gate, so the \
                 denied resolver is unreachable only through the gate's \
                 name policy, never by destination",
                rule.describe()
            ));
        }
    }

    // fs grants rooted under a mount point init covers with a private
    // tmpfs can never resolve — the namespaced route must not claim a
    // silently narrower filesystem than the policy wrote. `/run` is
    // always covered (host IPC socket hiding); `/tmp` whenever the
    // resolv.conf redirect needs a bind-mount source there.
    let tmp_masked = tmp_mask_planned();
    for path in policy
        .fs
        .read_only
        .iter()
        .chain(policy.fs.read_write.iter())
        .chain(policy.fs.executable.iter())
    {
        if let Some(why) = masked_fs_root(path, tmp_masked) {
            v.push(format!(
                "fs allow '{path}' is rooted under a masked tree — {why}, so \
                 the grant can never resolve"
            ));
        }
    }
    for tool in &policy.tools {
        let Some(fs) = &tool.fs else { continue };
        // `allowed_paths` is the union spelling of the mode lists —
        // dedupe so one rule does not report twice.
        let paths: std::collections::BTreeSet<&str> = fs
            .allowed_paths
            .iter()
            .chain(fs.read_only_paths.iter())
            .chain(fs.read_write_paths.iter())
            .map(String::as_str)
            .collect();
        for path in paths {
            if let Some(why) = masked_fs_root(path, tmp_masked) {
                v.push(format!(
                    "tool '{}' fs allow '{path}' is rooted under a masked \
                     tree — {why}, so the grant can never resolve",
                    tool.name
                ));
            }
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

    // The in-namespace sandbox requests the same fs ruleset — on a
    // kernel without Landlock it applies nothing. `allow_degraded`
    // tolerates the missing ruleset only when no declared fs control
    // depended on it; a declared grant that silently vanishes is a
    // mandatory control the flag must not skip (PR-16).
    let has_fs_surface = !policy.fs.read_only.is_empty()
        || !policy.fs.read_write.is_empty()
        || !policy.fs.executable.is_empty()
        || policy.tools.iter().any(|t| {
            t.allowed
                && t.fs.as_ref().is_some_and(|f| {
                    !f.allowed_paths.is_empty()
                        || !f.read_only_paths.is_empty()
                        || !f.read_write_paths.is_empty()
                })
        });
    if input.landlock_abi == 0 {
        if !policy.sandbox.allow_degraded {
            v.push(
                "the kernel has no Landlock support — the filesystem rules \
                 the in-namespace sandbox applies cannot be enforced (and \
                 sandbox.allow_degraded is not set to tolerate the absent \
                 ruleset)"
                    .to_string(),
            );
        } else if has_fs_surface {
            v.push(
                "the kernel has no Landlock support — the declared fs grants \
                 would be silently unenforced inside the namespace; \
                 sandbox.allow_degraded tolerates a weaker ruleset, not \
                 absent mandatory controls"
                    .to_string(),
            );
        }
    }
    if let Some(e) = &input.namespaced_build_err {
        v.push(format!("namespaced sandbox rule build failed: {e}"));
    }
    v
}

/// `true` when init's resolv.conf redirect will cover `/tmp` with a
/// private tmpfs. Mirrors `init.rs`: the bind-mount path is taken iff
/// `/etc/resolv.conf`'s real target is outside `/run` (an absent or
/// unresolvable resolv.conf only warns — nothing is masked).
fn tmp_mask_planned() -> bool {
    std::fs::canonicalize("/etc/resolv.conf")
        .map(|t| !t.starts_with("/run"))
        .unwrap_or(false)
}

/// `Some("/run" | "/var/run" | "/tmp")` when the fs allow `spelling`
/// is rooted under a tree init masks with a private tmpfs — the grant
/// would name a host path the workload can never reach, i.e. silently
/// dead policy.
///
/// Rooted-under is glob-aware: `/run/**` and a literal-stem glob like
/// `/r*` (which can still expand to `/run`) both match, while a wide
/// ancestor spelling such as `/**` or `/*` is left alone — the hidden
/// subtree is an intentional IPC carve-out, not a per-rule surprise
/// (it is listed in the route's `limitations` instead).
fn masked_fs_root(spelling: &str, tmp_masked: bool) -> Option<&'static str> {
    // Normalize `.`/`..`/`//` so a spelling cannot duck under or
    // escape a masked root by naming (`/run/../x` resolves outside
    // and is reachable — correctly not flagged).
    let mut segs: Vec<&str> = Vec::new();
    for seg in spelling.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                segs.pop();
            }
            s => segs.push(s),
        }
    }
    // `/var/run` is a `/run` symlink on modern distros — masked iff
    // the host link actually resolves there (checked per selection:
    // distros with a real /var/run dir keep it reachable).
    let var_run_masked = std::fs::canonicalize("/var/run")
        .map(|t| t.starts_with("/run"))
        .unwrap_or(false);
    let roots: &[(&[&str], &'static str)] = &[
        (
            &["run"],
            "the namespaced mount setup covers /run with a private tmpfs",
        ),
        (
            &["var", "run"],
            "the namespaced mount setup covers /run (which /var/run \
             resolves to) with a private tmpfs",
        ),
        (
            &["tmp"],
            "init covers /tmp with a private tmpfs to host the \
             resolv.conf bind-mount source",
        ),
    ];
    for &(root, why) in roots {
        if root == ["var", "run"] && !var_run_masked {
            continue;
        }
        if root == ["tmp"] && !tmp_masked {
            continue;
        }
        if segs.len() < root.len() {
            continue;
        }
        let mut rooted = true;
        for (seg, want) in segs.iter().zip(root.iter()) {
            if seg == want {
                continue;
            }
            // A glob component whose literal stem is a prefix of the
            // root component can still expand to it (`/r*` → `/run`).
            let stem: &str = seg.split(['*', '?', '[']).next().unwrap_or("");
            if seg.contains(['*', '?', '[']) && !stem.is_empty() && want.starts_with(stem) {
                continue;
            }
            rooted = false;
            break;
        }
        if rooted {
            return Some(why);
        }
    }
    None
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
        // `"*"` opens the family unscoped on any kernel and supersedes
        // every path-bound opt-in beside it — a superseded path adds no
        // `ResolveUnix` requirement, so it is not flagged below.
        let unix_family_open = out.unix_allows().iter().any(|u| u == "*");
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
                EgressDest::Unix(u) => {
                    // D-2: a non-superseded path-bound opt-in needs the
                    // ABI v9 `ResolveUnix` mediation right — below it
                    // the rule could only be honored by opening the
                    // family, which must not happen silently.
                    if u.as_str() != "*" && !unix_family_open && input.landlock_abi < 9 {
                        v.push(format!(
                            "egress rule '{text}' binds an AF_UNIX path — path \
                             scoping needs Landlock ABI v9 (ResolveUnix, kernel \
                             7.1) and this kernel reports v{}; use 'allow \
                             unix=\"*\"' to open the family instead",
                            input.landlock_abi
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

    // The launch-time `enforcement_gate` refuses anything short of
    // `FullyEnforced` unless `sandbox.allow_degraded` opted in — the
    // selection must mirror that *before* the workload launches, or a
    // route that can never pass the gate is claimed selectable. The
    // ruleset requests fs v1..v3 plus net v4 (and, on ABI >= 6, the
    // scope rights — which then always land), so: ABI 0 → NotEnforced,
    // ABI 1..3 → PartiallyEnforced (the request includes v4 rights the
    // kernel cannot apply); ABI >= 4 can land the whole request. Under
    // `allow_degraded` a partial or
    // absent ruleset is tolerated, but never for a *declared* control
    // the kernel cannot apply at all — a dropped mandatory control is
    // exactly what PR-16 says the flag must not skip.
    let has_fs_surface = !policy.fs.read_only.is_empty()
        || !policy.fs.read_write.is_empty()
        || !policy.fs.executable.is_empty()
        || policy.tools.iter().any(|t| {
            t.allowed
                && t.fs.as_ref().is_some_and(|f| {
                    !f.allowed_paths.is_empty()
                        || !f.read_only_paths.is_empty()
                        || !f.read_write_paths.is_empty()
                })
        });
    let has_tcp_surface = out.egress_rules().iter().any(|r| {
        r.allow && r.proto.covers(EgressProto::Tcp) && !matches!(r.dest, EgressDest::Unix(_))
    });
    if input.landlock_abi == 0 {
        if !policy.sandbox.allow_degraded {
            v.push(
                "the kernel has no Landlock support — the fs/net rules cannot \
                 be enforced (and sandbox.allow_degraded is not set to \
                 tolerate the absent ruleset)"
                    .to_string(),
            );
        } else if has_fs_surface || has_tcp_surface {
            v.push(
                "the kernel has no Landlock support — the declared fs grants \
                 and TCP allow surface would be silently unenforced; \
                 sandbox.allow_degraded tolerates a weaker ruleset, not \
                 absent mandatory controls"
                    .to_string(),
            );
        }
    } else if input.landlock_abi < 4 {
        if !policy.sandbox.allow_degraded {
            v.push(format!(
                "kernel Landlock ABI v{} predates network rules (v4) — the \
                 requested ruleset would only be PartiallyEnforced and the \
                 launch gate refuses; set sandbox.allow_degraded to accept a \
                 weaker ruleset",
                input.landlock_abi
            ));
        } else if has_tcp_surface {
            v.push(format!(
                "kernel Landlock ABI v{} predates network rules (v4) — the \
                 TCP allow surface would be dropped, and \
                 sandbox.allow_degraded must not skip a mandatory control",
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
mod tests;
