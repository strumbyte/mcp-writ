use std::collections::HashSet;
use std::path::{Path, PathBuf};

use crate::policy::provenance::{LoadWarning, LoadWarningKind};
use crate::policy::{Policy, TrajectoryRule};

/// The fail-secure settings an overlay application can move in the
/// weakening direction — captured before each merge so the merge can
/// record which postures it relaxed. An overlay applies declared
/// values symmetrically, so a declaration riding an included subtree
/// (an ancestor's or a matching `when` block's) can silently downgrade
/// a posture the including file never asked about: `confused_deputy_
/// protection #false`, `trajectory #false` or dropped trajectory
/// rules, a different non-default `logging level`, `fail_closed
/// #false`, `sandbox allow_degraded=#true`, `secret-overlay #false`,
/// an open `allow host="*"` outbound posture, an `inbound` listener
/// grant, or a relaxed `environment` restriction. The same applies to
/// an extending file's own declarations, which the operator reviewing
/// the parent policy cannot see. Each weakening is surfaced once —
/// deferred and re-validated against the final merged policy (see
/// [`WeakenedPosture::message`]) so a later declaration that restores
/// the posture does not leave a stale warning behind.
#[derive(Debug)]
pub(in crate::policy::kdl_inherit) struct SecurityPosture {
    confused_deputy_protection: bool,
    trajectory: bool,
    trajectory_rules: Vec<TrajectoryRule>,
    logging_level: String,
    logging_fail_closed: bool,
    sandbox_allow_degraded: bool,
    secret_overlay: bool,
    deny_all_others: bool,
    allow_listen: bool,
    environment_restrict: bool,
    environment_allowed: Vec<String>,
}

impl SecurityPosture {
    pub(in crate::policy::kdl_inherit) fn capture(policy: &Policy) -> Self {
        Self {
            confused_deputy_protection: policy.confused_deputy_protection,
            trajectory: policy.trajectory,
            trajectory_rules: policy.trajectory_rules.clone(),
            logging_level: policy.logging.level.clone(),
            logging_fail_closed: policy.logging.fail_closed,
            sandbox_allow_degraded: policy.sandbox.allow_degraded,
            secret_overlay: policy.fs.secret_overlay,
            deny_all_others: policy.network.outbound.deny_all_others,
            allow_listen: policy.network.inbound.allow_listen,
            environment_restrict: policy.environment.restrict,
            environment_allowed: policy.environment.allowed.clone(),
        }
    }

    /// The weakenings `after` carries relative to this snapshot.
    /// `"info"` as the before-level means the logging level was never
    /// chosen — there is no posture to weaken (mirroring the pre-decl
    /// include clamp, which let only a non-`info` level move an
    /// `info`-level base).
    pub(in crate::policy::kdl_inherit) fn weakened(&self, after: &Policy) -> Vec<WeakenedPosture> {
        let mut weakened = Vec::new();
        if self.confused_deputy_protection && !after.confused_deputy_protection {
            weakened.push(WeakenedPosture::ConfusedDeputyProtection);
        }
        if self.trajectory && !after.trajectory {
            weakened.push(WeakenedPosture::Trajectory);
        } else if after.trajectory {
            let dropped: Vec<_> = self
                .trajectory_rules
                .iter()
                .filter(|r| !after.trajectory_rules.contains(r))
                .cloned()
                .collect();
            if !dropped.is_empty() {
                weakened.push(WeakenedPosture::TrajectoryRules(dropped));
            }
        }
        if self.logging_level != "info" && after.logging.level != self.logging_level {
            weakened.push(WeakenedPosture::LoggingLevel(self.logging_level.clone()));
        }
        if self.logging_fail_closed && !after.logging.fail_closed {
            weakened.push(WeakenedPosture::LoggingFailClosed);
        }
        if !self.sandbox_allow_degraded && after.sandbox.allow_degraded {
            weakened.push(WeakenedPosture::SandboxAllowDegraded);
        }
        if self.secret_overlay && !after.fs.secret_overlay {
            weakened.push(WeakenedPosture::SecretOverlay);
        }
        if self.deny_all_others && !after.network.outbound.deny_all_others {
            weakened.push(WeakenedPosture::OutboundPosture);
        }
        if !self.allow_listen && after.network.inbound.allow_listen {
            weakened.push(WeakenedPosture::InboundListen);
        }
        if self.environment_restrict && !after.environment.restrict {
            weakened.push(WeakenedPosture::EnvironmentRestrict);
        } else if self.environment_restrict
            && after.environment.restrict
            && after
                .environment
                .allowed
                .iter()
                .any(|v| !self.environment_allowed.contains(v))
        {
            // An allow list that gained names is a weakening only while
            // the restriction held on both sides — re-imposing
            // restriction on an unrestricted base is a strengthening.
            weakened.push(WeakenedPosture::EnvironmentAllowed(
                self.environment_allowed.clone(),
            ));
        }
        weakened
    }
}

/// One weakening observed across a single overlay application. The
/// variant carries the state needed to re-validate against the final
/// merged policy — a later declaration may have restored the posture,
/// in which case the warning must not fire.
#[derive(Debug, PartialEq)]
pub(in crate::policy::kdl_inherit) enum WeakenedPosture {
    ConfusedDeputyProtection,
    /// `trajectory` flag turned off (the rules go with it).
    Trajectory,
    /// Trajectory rules dropped while the flag stayed on — the payload
    /// holds the rules lost at that merge.
    TrajectoryRules(Vec<TrajectoryRule>),
    /// `logging level` moved off an explicitly chosen level — the
    /// payload is the previous level.
    LoggingLevel(String),
    LoggingFailClosed,
    SandboxAllowDegraded,
    SecretOverlay,
    /// `deny host="*"` posture opened to `allow host="*"`.
    OutboundPosture,
    /// `inbound allow=#true` granted where none was.
    InboundListen,
    /// `environment` restriction lifted via `inherit-parent`.
    EnvironmentRestrict,
    /// `environment` allow list widened — the payload is the previous
    /// list, so the message names the variables still gained.
    EnvironmentAllowed(Vec<String>),
}

impl WeakenedPosture {
    /// True when `other` is the same weakening variant — used by
    /// tests to locate a kind regardless of its payload.
    #[cfg(test)]
    pub(in crate::policy::kdl_inherit) fn same_kind(&self, other: &Self) -> bool {
        std::mem::discriminant(self) == std::mem::discriminant(other)
    }

    /// Warning text while the weakening is still in effect on the
    /// final merged policy — `None` once a later declaration restored
    /// the posture.
    pub(in crate::policy::kdl_inherit) fn message(&self, policy: &Policy) -> Option<String> {
        match self {
            Self::ConfusedDeputyProtection => (!policy.confused_deputy_protection)
                .then(|| "disables 'confused_deputy_protection'".to_string()),
            Self::Trajectory => {
                (!policy.trajectory).then(|| "disables 'trajectory' recording".to_string())
            }
            Self::TrajectoryRules(dropped) => {
                let still = dropped
                    .iter()
                    .filter(|r| !policy.trajectory_rules.contains(r))
                    .count();
                (still > 0).then(|| format!("drops {still} inherited 'trajectory' rule(s)"))
            }
            Self::LoggingLevel(from) => (policy.logging.level != *from).then(|| {
                format!(
                    "moves 'logging level' from '{from}' to '{}'",
                    policy.logging.level
                )
            }),
            Self::LoggingFailClosed => {
                (!policy.logging.fail_closed).then(|| "disables 'logging fail_closed'".to_string())
            }
            Self::SandboxAllowDegraded => (policy.sandbox.allow_degraded)
                .then(|| "enables 'sandbox allow_degraded'".to_string()),
            Self::SecretOverlay => {
                (!policy.fs.secret_overlay).then(|| "disables 'secret-overlay'".to_string())
            }
            Self::OutboundPosture => (!policy.network.outbound.deny_all_others)
                .then(|| "opens the outbound posture to 'allow host=\"*\"'".to_string()),
            Self::InboundListen => (policy.network.inbound.allow_listen)
                .then(|| "grants 'inbound allow=#true' listeners".to_string()),
            Self::EnvironmentRestrict => (!policy.environment.restrict).then(|| {
                "lifts 'defaults.environment' restriction via 'inherit-parent'".to_string()
            }),
            Self::EnvironmentAllowed(before) => {
                let gained: Vec<_> = policy
                    .environment
                    .allowed
                    .iter()
                    .filter(|v| !before.contains(v))
                    .collect();
                (policy.environment.restrict && !gained.is_empty()).then(|| {
                    format!(
                        "widens the 'environment' allow list with {}",
                        gained
                            .iter()
                            .map(|v| format!("'{v}'"))
                            .collect::<Vec<_>>()
                            .join(", ")
                    )
                })
            }
        }
    }
}

/// Warnings deferred to the end of the whole load. Each subtree
/// returns its pending entries to the caller rather than emitting them
/// against an intermediate merge state, so every warning is evaluated
/// once — against the policy the load actually produced: a later file
/// that restores the posture or closes the listener grant leaves no
/// stale warning behind.
#[derive(Debug, Default)]
pub(in crate::policy::kdl_inherit) struct PendingWarnings {
    inbound: Vec<PathBuf>,
    weakened: Vec<(PathBuf, WeakenedPosture)>,
}

impl PendingWarnings {
    /// `path` re-declared `defaults.network` without `inbound` while a
    /// listener grant was live — warn at emit if the final policy
    /// still keeps it.
    pub(in crate::policy::kdl_inherit) fn push_inbound(&mut self, path: &Path) {
        if !self.inbound.iter().any(|p| p == path) {
            self.inbound.push(path.to_path_buf());
        }
    }

    /// `path` weakened a fail-secure posture. Each distinct loss is
    /// kept — two merge points in the same file can produce the same
    /// kind with different payloads (the doc merge and a `when` block
    /// each dropping different trajectory rules), and discarding one
    /// would hide a loss the final policy still carries. Only exact
    /// duplicates are dropped here; warnings deduplicate at `emit`,
    /// after every entry has been evaluated.
    pub(in crate::policy::kdl_inherit) fn push_weakened(
        &mut self,
        path: &Path,
        weakened: WeakenedPosture,
    ) {
        if !self
            .weakened
            .iter()
            .any(|(p, w)| p == path && *w == weakened)
        {
            self.weakened.push((path.to_path_buf(), weakened));
        }
    }

    /// A resolved subtree's pending entries join the caller's.
    pub(in crate::policy::kdl_inherit) fn absorb(&mut self, other: Self) {
        for path in other.inbound {
            self.push_inbound(&path);
        }
        for (path, weakened) in other.weakened {
            self.push_weakened(&path, weakened);
        }
    }

    /// The warnings still in effect on the final merged policy —
    /// every retained entry is evaluated first (a restored posture
    /// yields no message), then identical warnings are deduplicated so
    /// a repeated loss reports once without hiding a distinct one.
    /// The load collects them into [`LoadDiagnostics`] so `plan`,
    /// `check` and `policy resolve` carry the same warnings the
    /// enforcing loaders print.
    pub(in crate::policy::kdl_inherit) fn collect(
        &self,
        policy: &Policy,
        out: &mut Vec<LoadWarning>,
    ) {
        let mut seen = HashSet::new();
        if policy.network.inbound.allow_listen {
            for path in &self.inbound {
                if seen.insert((path.clone(), LoadWarningKind::Inbound, String::new())) {
                    out.push(LoadWarning {
                        kind: LoadWarningKind::Inbound,
                        file: path.clone(),
                        line: None,
                        message: "declares 'defaults.network' without 'inbound' — an \
                                 inherited `inbound allow=#true` grant stays in effect; \
                                 declare `inbound allow=#false` to refuse listeners"
                            .to_string(),
                    });
                }
            }
        }
        for (path, weakened) in &self.weakened {
            if let Some(message) = weakened.message(policy)
                && seen.insert((path.clone(), LoadWarningKind::Posture, message.clone()))
            {
                out.push(LoadWarning {
                    kind: LoadWarningKind::Posture,
                    file: path.clone(),
                    line: None,
                    message,
                });
            }
        }
    }

    /// The warning lines still in effect on the final merged policy —
    /// every retained entry is evaluated first (a restored posture
    /// yields no message), then identical lines are deduplicated so a
    /// repeated loss prints once without hiding a distinct one.
    #[cfg(test)]
    pub(in crate::policy::kdl_inherit) fn warning_lines(&self, policy: &Policy) -> Vec<String> {
        let mut seen = HashSet::new();
        let mut lines = Vec::new();
        for (path, weakened) in &self.weakened {
            if let Some(message) = weakened.message(policy) {
                let line = format!("'{}' {message}", path.display());
                if seen.insert(line.clone()) {
                    lines.push(line);
                }
            }
        }
        lines
    }
}
