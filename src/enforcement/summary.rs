//! The structured `enforcement` member carried on
//! `server.connected`/`server.error` JSONL audit records.

use super::json::JsonNull;
use super::model::*;
use super::{
    LANDLOCK_FULLY_ENFORCED, LANDLOCK_NOT_ENFORCED, LANDLOCK_PARTIALLY_ENFORCED,
    RESTRICT_SELF_REPORTED,
};
use crate::audit_log::EmbeddedJson;

// ---------------------------------------------------------------------------
// `server.connected`/`server.error` enforcement summary (JSONL member)
// ---------------------------------------------------------------------------

/// The PSEC spec `version` this binary emits — the value reported as
/// `enforcement.psec.schema_version` on `server.connected` records. The
/// wire encoder (`warden::psec_spec`) pins the same pair and a unit test
/// keeps the two in lockstep.
pub const PSEC_SPEC_SCHEMA_VERSION: &str = "1.0";

/// The native OS sandbox backend a launch's sandboxed dispatch is bound
/// to — on `server.connected`, the mechanism the process boundary
/// actually came from; on `server.error`, the mechanism the refused or
/// failed attempt was bound to ([`None`](Self::None) when there is no
/// such binding: skipped sandbox, a mechanism absent on this host, or
/// no backend on this platform). Per-tool RPC-layer restrictions
/// (`plan.tools`, `rpc.*` controls) exist on every platform and are not
/// what this names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SandboxBackend {
    /// Linux: Landlock LSM + seccomp-BPF (may be degraded per
    /// `restriction` when Landlock fails part-way).
    LandlockSeccomp,
    /// Windows AppContainer profile (`--windows-mechanism appcontainer`).
    AppContainer,
    /// Windows PSEC spec env (`--windows-mechanism psec`).
    Psec,
    /// macOS `sandbox-exec` (`seatbelt` profile).
    SandboxExec,
    /// Nothing OS-enforced: `--dry-run`, `MCP_WRIT_SKIP_SANDBOX` /
    /// `--sandbox-unsupported`, `sandbox=disabled`, a requested mechanism
    /// that does not exist on this host, or a platform with no sandbox
    /// backend.
    None,
}

impl SandboxBackend {
    /// The stable name written to `enforcement.backend` and the
    /// `backend=` detail token.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::LandlockSeccomp => "landlock+seccomp",
            Self::AppContainer => "appcontainer",
            Self::Psec => "psec",
            Self::SandboxExec => "sandbox-exec",
            Self::None => "none",
        }
    }
}

/// One planned control with the state it effectively reached for this
/// launch — the observation state when the warden/runtime recorded one
/// for the control, else the plan state. Computed once here so the audit
/// consumer never has to reconcile the two lists itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ControlOutcome {
    pub id: &'static str,
    pub mechanism: &'static str,
    pub state: ControlState,
}

/// PSEC-specific launch facts — present only when the launch ran under
/// the PSEC mechanism. `egress_*` counts describe what the
/// policy-to-spec translation *accepted/refused*: allow rules the spec
/// carries vs rules that could not be expressed and were refused
/// (recorded `not_applied` in the plan).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PsecSummary {
    /// Spec `version` the encoder emitted (`PSEC_SPEC_SCHEMA_VERSION`).
    pub schema_version: &'static str,
    /// The spec always encodes deny-all egress with explicit allow rules;
    /// this is true while the launch's `os.net.outbound` control survived
    /// — its *effective* state (observation over plan) is neither
    /// `not_applied` nor `failed`.
    pub egress_default_deny: bool,
    /// `net_destination` rule grants the spec accepted.
    pub egress_allow_rules: usize,
    /// `net_destination` rule grants the spec refused.
    pub egress_rules_refused: usize,
}

/// Per-state grant counts — the `enforcement.grants` member shape.
/// `planned` = entries still in the not-yet-applied state when the
/// summary was built (e.g. a launch that failed before apply).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GrantStateCounts {
    pub planned: usize,
    pub verified: usize,
    pub partially_applied: usize,
    pub not_applied: usize,
    pub skipped: usize,
    pub unknown: usize,
    pub failed: usize,
    pub not_applicable: usize,
}

/// Structured `enforcement` member attached to `server.connected` and
/// `server.error` JSONL records — the machine-readable digest of the same
/// [`EnforcementPlan`]/[`EnforcementObservation`] data the `--report`
/// file carries, built once from the shared facts rather than a second
/// opinion. `details` stays the flat human summary; if an audit need
/// ever outgrows this object it graduates to a dedicated event instead
/// of growing the member. It is a launch-time snapshot: `report.result`
/// finalizes at session end, but `plan`/`observations` are never
/// appended after the record emits, so the digest stays consistent with
/// the finalized report's enforcement facts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnforcementSummary {
    /// The OS sandbox backend the launch's dispatch is bound to — see
    /// [`SandboxBackend`] for what `none` covers.
    pub backend: SandboxBackend,
    /// Mirrors `LaunchReport::dry_run` — a dry-run launch never applied
    /// OS enforcement regardless of what `controls` show.
    pub dry_run: bool,
    /// Landlock `RulesetStatus` level parsed back from observation
    /// reasons: `fully_enforced` | `partially_enforced` | `not_enforced`,
    /// or null when no Landlock observation reported a level (other
    /// platforms, or no apply attempted).
    pub restriction: Option<&'static str>,
    /// Every planned control with its effective state — the observation
    /// where recorded, else the plan state.
    pub controls: Vec<ControlOutcome>,
    /// Controls whose effective state is `verified`.
    pub controls_applied: usize,
    pub grants: GrantStateCounts,
    /// Human-readable labels of `skipped` grants (bounded — see
    /// `SKIPPED_GRANT_SUMMARY_CAP`; overflow folds into a `"(+N more)"`
    /// tail entry).
    pub skipped_grants: Vec<String>,
    pub psec: Option<PsecSummary>,
}

/// `skipped_grants` summary cap — keeps one JSONL line bounded when a
/// policy skips many grants.
pub const SKIPPED_GRANT_SUMMARY_CAP: usize = 8;

impl EnforcementSummary {
    /// Build the digest from the same `plan`/`observations` the
    /// `--report` file carries. `backend`/`dry_run` come from the launch
    /// path that owns the sandbox decision; everything else derives here.
    pub fn build(
        plan: &EnforcementPlan,
        observations: &[EnforcementObservation],
        backend: SandboxBackend,
        dry_run: bool,
    ) -> Self {
        let controls: Vec<ControlOutcome> = plan
            .controls
            .iter()
            .map(|c| {
                let state = observations
                    .iter()
                    .rfind(|o| o.control == c.id)
                    .map(|o| o.state)
                    .unwrap_or(c.state);
                ControlOutcome {
                    id: c.id,
                    mechanism: c.mechanism,
                    state,
                }
            })
            .collect();
        let controls_applied = controls
            .iter()
            .filter(|c| c.state == ControlState::Verified)
            .count();

        let restriction = observations.iter().find_map(|o| {
            let reason = o.reason.as_deref()?;
            let at = reason.find(RESTRICT_SELF_REPORTED)?;
            let level = &reason[at + RESTRICT_SELF_REPORTED.len()..];
            if level.starts_with(LANDLOCK_FULLY_ENFORCED) {
                Some("fully_enforced")
            } else if level.starts_with(LANDLOCK_PARTIALLY_ENFORCED) {
                Some("partially_enforced")
            } else if level.starts_with(LANDLOCK_NOT_ENFORCED) {
                Some("not_enforced")
            } else {
                None
            }
        });

        let mut grants = GrantStateCounts::default();
        for g in &plan.grants {
            match g.state {
                ControlState::Planned => grants.planned += 1,
                ControlState::Verified => grants.verified += 1,
                ControlState::PartiallyApplied => grants.partially_applied += 1,
                ControlState::NotApplied => grants.not_applied += 1,
                ControlState::Skipped => grants.skipped += 1,
                ControlState::Unknown => grants.unknown += 1,
                ControlState::Failed => grants.failed += 1,
                ControlState::NotApplicable => grants.not_applicable += 1,
            }
        }

        let mut skipped_grants = Vec::new();
        let mut skipped_omitted = 0usize;
        for g in plan
            .grants
            .iter()
            .filter(|g| g.state == ControlState::Skipped)
        {
            if skipped_grants.len() >= SKIPPED_GRANT_SUMMARY_CAP {
                skipped_omitted += 1;
            } else {
                skipped_grants.push(grant_label(g));
            }
        }
        if skipped_omitted > 0 {
            skipped_grants.push(format!("(+{skipped_omitted} more)"));
        }

        let psec = (backend == SandboxBackend::Psec).then(|| PsecSummary {
            schema_version: PSEC_SPEC_SCHEMA_VERSION,
            egress_default_deny: controls
                .iter()
                .find(|c| c.id == "os.net.outbound")
                .is_some_and(|c| {
                    !matches!(c.state, ControlState::NotApplied | ControlState::Failed)
                }),
            egress_allow_rules: plan
                .grants
                .iter()
                .filter(|g| {
                    matches!(&g.subject, GrantSubject::Rule { kind, .. } if *kind == "net_destination")
                        && matches!(g.state, ControlState::Planned | ControlState::Verified)
                })
                .count(),
            egress_rules_refused: plan
                .grants
                .iter()
                .filter(|g| {
                    matches!(&g.subject, GrantSubject::Rule { kind, .. } if *kind == "net_destination")
                        && g.state == ControlState::NotApplied
                })
                .count(),
        });

        Self {
            backend,
            dry_run,
            restriction,
            controls,
            controls_applied,
            grants,
            skipped_grants,
            psec,
        }
    }

    /// Serialize to the JSON object stored verbatim in the audit event's
    /// `enforcement` member — the [`EmbeddedJson`] return type means the
    /// member can only ever hold serializer output, never an arbitrary
    /// string. States render as snake_case (`state.as_str`).
    pub fn to_json(&self) -> EmbeddedJson {
        let text = nojson::object(|f| {
            f.member("backend", self.backend.as_str())?;
            f.member("dry_run", self.dry_run)?;
            match self.restriction {
                Some(r) => f.member("restriction", r)?,
                None => f.member("restriction", JsonNull)?,
            }
            f.member("controls_applied", self.controls_applied as u64)?;
            f.member(
                "controls",
                nojson::array(|f| {
                    for c in &self.controls {
                        f.element(nojson::object(|f| {
                            f.member("id", c.id)?;
                            f.member("mechanism", c.mechanism)?;
                            f.member("state", c.state.as_str())
                        }))?;
                    }
                    Ok(())
                }),
            )?;
            f.member(
                "grants",
                nojson::object(|f| {
                    f.member("planned", self.grants.planned as u64)?;
                    f.member("verified", self.grants.verified as u64)?;
                    f.member("partially_applied", self.grants.partially_applied as u64)?;
                    f.member("not_applied", self.grants.not_applied as u64)?;
                    f.member("skipped", self.grants.skipped as u64)?;
                    f.member("unknown", self.grants.unknown as u64)?;
                    f.member("failed", self.grants.failed as u64)?;
                    f.member("not_applicable", self.grants.not_applicable as u64)
                }),
            )?;
            f.member(
                "skipped_grants",
                nojson::array(|f| {
                    for g in &self.skipped_grants {
                        f.element(g.as_str())?;
                    }
                    Ok(())
                }),
            )?;
            match &self.psec {
                Some(p) => f.member(
                    "psec",
                    nojson::object(|f| {
                        f.member("schema_version", p.schema_version)?;
                        f.member("egress_default_deny", p.egress_default_deny)?;
                        f.member("egress_allow_rules", p.egress_allow_rules as u64)?;
                        f.member("egress_rules_refused", p.egress_rules_refused as u64)
                    }),
                )?,
                None => f.member("psec", JsonNull)?,
            }
            Ok(())
        })
        .to_string();
        EmbeddedJson::new(text)
    }
}

/// One-line human label for a skipped grant — `<subject>[ — <reason>]`.
fn grant_label(g: &ProcessGrant) -> String {
    let subject = match &g.subject {
        GrantSubject::FsPath { path, access } => {
            format!("fs_path:{path} ({})", access.as_str())
        }
        GrantSubject::TcpConnect { port } => format!("tcp_connect:{port}"),
        GrantSubject::Capability { name } => format!("capability:{name}"),
        GrantSubject::Syscall { name } => format!("syscall:{name}"),
        GrantSubject::PrivateTmpdir => "private_tmpdir".to_string(),
        GrantSubject::Rule { kind, name } => format!("{kind}:{name}"),
    };
    match &g.reason {
        Some(r) => format!("{subject} — {r}"),
        None => subject,
    }
}
