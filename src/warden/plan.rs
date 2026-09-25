//! Enforcement-plan assembly — the `Policy` → leaf-model conversion the
//! module guide assigns to `warden`.
//!
//! The plan is generated from the *same normalized data* the sandbox
//! builders consume: on Linux the grants come out of
//! `prepare_linux_child_sandbox` itself; on macOS from the SBPL emitter;
//! on Windows from the shared grant intents. The plan never recomputes a
//! parallel permission table.

use std::path::Path;

use crate::enforcement::{
    ControlLayer, ControlPhase, ControlState, EnforcementObservation, EnforcementPlan,
    ObservationBasis, PlannedControl, ProcessGrant, ToolDisposition,
};
#[cfg(target_os = "windows")]
use crate::enforcement::{GrantOrigin, GrantSubject};
use crate::policy::Policy;
#[cfg(target_os = "windows")]
use crate::policy::TransportType;

use super::SpawnOptions;
use super::child::RunningChild;
#[cfg(target_os = "linux")]
use super::linux_spawn;
#[cfg(target_os = "macos")]
use super::macos_sandbox::SpawnLiveness;
#[cfg(target_os = "windows")]
use super::windows_sandbox::{WinSpawnError, WinStage};
use crate::error::WardenError;

/// Plan plus the apply observations recorded while spawning one child.
pub struct WardenReport {
    /// The plan the spawn was built from.
    pub plan: EnforcementPlan,
    /// What applying it observably did at spawn time.
    pub observations: Vec<EnforcementObservation>,
}

/// Result of a spawn attempt. `report` is present on success *and*
/// failure so a refused/failed launch stays describable.
pub struct SpawnAttempt {
    pub report: WardenReport,
    pub outcome: Result<RunningChild, WardenError>,
}

impl SpawnAttempt {
    pub(super) fn ok(report: WardenReport, child: RunningChild) -> Self {
        Self {
            report,
            outcome: Ok(child),
        }
    }

    pub(super) fn err(report: WardenReport, source: WardenError) -> Self {
        Self {
            report,
            outcome: Err(source),
        }
    }
}

// ---------------------------------------------------------------------------
// Small constructors
// ---------------------------------------------------------------------------

fn control(
    id: &'static str,
    layer: ControlLayer,
    mechanism: &'static str,
    state: ControlState,
    reason: Option<String>,
) -> PlannedControl {
    PlannedControl {
        id,
        layer,
        mechanism,
        state,
        reason,
    }
}

fn planned(id: &'static str, layer: ControlLayer, mechanism: &'static str) -> PlannedControl {
    control(id, layer, mechanism, ControlState::Planned, None)
}

fn observation(
    control: &'static str,
    state: ControlState,
    basis: ObservationBasis,
    phase: ControlPhase,
    reason: Option<String>,
) -> EnforcementObservation {
    EnforcementObservation {
        control,
        state,
        basis,
        phase,
        reason,
    }
}

/// Mark every still-planned OS control `Failed` — used when the sandbox
/// could not be constructed or its pipeline did not run to a spawned
/// child, so the controls cannot be effective for this launch. `stage`
/// names the failed step ("rule build failed", "sandbox pipeline
/// failed", ...).
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
pub(super) fn fail_os_controls(controls: &mut [PlannedControl], stage: &str, err: &WardenError) {
    for c in controls.iter_mut() {
        if c.layer == ControlLayer::Os && c.state == ControlState::Planned {
            c.state = ControlState::Failed;
            c.reason = Some(format!("{stage}: {err}"));
        }
    }
}

/// Sandbox-skip mode: every OS control that could have applied becomes
/// `Skipped` with the caller's reason; `NotApplied`/`NotApplicable`
/// entries keep their build-time state (they would not apply anyway).
fn mark_skipped(controls: &mut [PlannedControl], reason: &str) {
    for c in controls.iter_mut() {
        if c.layer == ControlLayer::Os && c.state == ControlState::Planned {
            c.state = ControlState::Skipped;
            c.reason = Some(format!("OS sandbox skipped ({reason})"));
        }
    }
}

// ---------------------------------------------------------------------------
// Shared controls (launch contract + RPC layer)
// ---------------------------------------------------------------------------

/// Launch-contract and RPC-layer controls — identical on every OS.
///
/// `launch.*` entries are neither kernel nor RPC enforcement: environment
/// restriction is part of the spawn contract, identity verification ran
/// before spawn. `rpc.*` entries are enforced by the Auditor while
/// forwarding MCP traffic — never kernel-level per-tool isolation.
///
/// `private_tmpdir` is true only when the spawn path itself overrides
/// TMPDIR with a private sandbox directory (the sandboxed macOS path);
/// explicit `opts.tmpdir` overrides are handled separately.
pub(super) fn shared_controls(
    policy: &Policy,
    opts: &SpawnOptions,
    dry_run: bool,
    private_tmpdir: bool,
) -> Vec<PlannedControl> {
    let mut v = Vec::new();

    v.push(if policy.hash_entries.is_empty() {
        control(
            "launch.identity",
            ControlLayer::Launch,
            "hash verify + bind + reverify",
            ControlState::Skipped,
            Some("no hash entries in policy".to_string()),
        )
    } else {
        control(
            "launch.identity",
            ControlLayer::Launch,
            "hash verify + bind + reverify",
            ControlState::Planned,
            None,
        )
    });

    // Only the sandboxed macOS path overrides TMPDIR with a private
    // sandbox directory; an unsandboxed macOS spawn keeps the parent's.
    let tmpdir_overridden = opts.tmpdir.is_some() || private_tmpdir;
    let (env_state, env_reason) = match (opts.restrict_environment, tmpdir_overridden) {
        (false, false) => (
            ControlState::NotApplicable,
            "no environment restriction declared; the child inherits the parent environment"
                .to_string(),
        ),
        (true, true) => (
            ControlState::Planned,
            format!(
                "restricted to the base set + {} allowlisted name(s); TMPDIR overridden",
                opts.allowed_names.len()
            ),
        ),
        (true, false) => (
            ControlState::Planned,
            format!(
                "restricted to the base set + {} allowlisted name(s)",
                opts.allowed_names.len()
            ),
        ),
        (false, true) => (
            ControlState::Planned,
            "TMPDIR override only; the parent environment is otherwise inherited".to_string(),
        ),
    };
    v.push(control(
        "launch.env",
        ControlLayer::Launch,
        "spawn env",
        env_state,
        Some(env_reason),
    ));

    let dry = dry_run.then(|| {
        "dry-run: violations are forwarded and logged as observed, not blocked".to_string()
    });
    v.push(control(
        "rpc.tools",
        ControlLayer::Rpc,
        "auditor",
        ControlState::Planned,
        dry.clone(),
    ));
    v.push(control(
        "rpc.tools_list",
        ControlLayer::Rpc,
        "auditor",
        ControlState::Planned,
        dry.clone(),
    ));
    v.push(if policy.fs.secret_overlay {
        control(
            "rpc.secret_overlay",
            ControlLayer::Rpc,
            "auditor",
            ControlState::Planned,
            dry.clone(),
        )
    } else {
        control(
            "rpc.secret_overlay",
            ControlLayer::Rpc,
            "auditor",
            ControlState::Skipped,
            Some("fs secret-overlay is off in the policy".to_string()),
        )
    });
    v.push(if policy.trajectory {
        control(
            "rpc.trajectory",
            ControlLayer::Rpc,
            "auditor",
            ControlState::Planned,
            dry.clone(),
        )
    } else {
        control(
            "rpc.trajectory",
            ControlLayer::Rpc,
            "auditor",
            ControlState::Skipped,
            Some("trajectory rules not enabled (opt-in)".to_string()),
        )
    });
    v.push(if policy.confused_deputy_protection {
        control(
            "rpc.confused_deputy",
            ControlLayer::Rpc,
            "auditor",
            ControlState::Planned,
            dry,
        )
    } else {
        control(
            "rpc.confused_deputy",
            ControlLayer::Rpc,
            "auditor",
            ControlState::Skipped,
            Some("confused-deputy protection not enabled (opt-in)".to_string()),
        )
    });
    v
}

/// Declared tools with their RPC-layer dispositions — denied tools stay
/// listed so the report shows they were denied, not absent.
pub(super) fn tools_table(policy: &Policy) -> Vec<ToolDisposition> {
    policy
        .tools
        .iter()
        .map(|t| ToolDisposition {
            name: t.name.clone(),
            server: t.server.clone(),
            allowed: t.allowed,
            side_effect: t.side_effect.clone(),
        })
        .collect()
}

/// Scope notes every plan carries. These are the load-bearing honest
/// statements: grants are process-wide, ambient permissions are not
/// enumerated, and deny rules never appear as grants.
pub(super) fn base_limitations() -> Vec<String> {
    vec![
        "OS grants are process-wide: a path granted for one tool is reachable by \
         every tool at kernel level; per-tool restrictions are enforced at the \
         RPC layer only."
            .to_string(),
        "The grant table lists permissions this launch's rules add; ambient \
         access outside the sandbox model (kernel-internal defaults, other \
         mechanism grants) is not enumerated."
            .to_string(),
        "Policy deny rules are enforced by the absence of an OS grant plus \
         RPC-layer argument checks; they do not appear as grant entries."
            .to_string(),
    ]
}

/// The `launch.env` observation: the env contract is applied as part of
/// the spawn call, so a successful spawn verifies it. `applied` is false
/// when no restriction/override exists — the control stays
/// `NotApplicable` in the plan and carries no observation.
pub(super) fn env_observation(
    applied: bool,
    spawn_err: Option<String>,
) -> Option<EnforcementObservation> {
    if !applied {
        return None;
    }
    Some(observation(
        "launch.env",
        if spawn_err.is_some() {
            ControlState::Unknown
        } else {
            ControlState::Verified
        },
        ObservationBasis::SpawnResult,
        ControlPhase::Spawn,
        spawn_err.map(|e| format!("spawn failed: {e}")),
    ))
}

// ---------------------------------------------------------------------------
// Per-OS control lists and plan-time grants
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
pub(super) fn os_controls(policy: &Policy) -> Vec<PlannedControl> {
    let degraded_note =
        || Some("sandbox.allow_degraded=#true: partial enforcement is tolerated".to_string());
    let v = vec![
        planned("os.privileges", ControlLayer::Os, "no_new_privs"),
        control(
            "os.fs",
            ControlLayer::Os,
            "landlock",
            ControlState::Planned,
            if policy.sandbox.allow_degraded {
                degraded_note()
            } else {
                None
            },
        ),
        control(
            "os.net.outbound",
            ControlLayer::Os,
            "landlock",
            ControlState::Planned,
            if policy.sandbox.allow_degraded {
                degraded_note()
            } else {
                None
            },
        ),
        if policy.network.inbound.allow_listen {
            control(
                "os.net.inbound",
                ControlLayer::Os,
                "landlock",
                ControlState::NotApplied,
                Some("Landlock does not grant TCP bind; inbound listen stays denied".to_string()),
            )
        } else {
            control(
                "os.net.inbound",
                ControlLayer::Os,
                "landlock",
                ControlState::NotApplicable,
                Some("no inbound listen requested".to_string()),
            )
        },
        {
            let mut c = planned("os.syscalls", ControlLayer::Os, "seccomp");
            if policy.sandbox.allow_degraded && !super::seccomp_impl::policy_allows_execve(policy) {
                c.reason = Some(
                    "sandbox.allow_degraded=#true: leftover execve stays available \
                     after spawn"
                        .to_string(),
                );
            }
            c
        },
    ];
    v
}

/// Spawn-result observations for the Linux controls. The evidence is the
/// shared apply record the pre-exec child filled
/// ([`linux_spawn::ApplySnapshot`]) — a mechanism result per apply stage,
/// not just "spawn returned". The `no_new_privs` → Landlock → seccomp
/// order is fixed, so a completed stage proves the earlier ones ran too;
/// a failed or truncated stage is never reported as applied.
#[cfg(target_os = "linux")]
pub(super) fn os_spawn_observations(
    controls: &[PlannedControl],
    apply: Option<&linux_spawn::ApplySnapshot>,
    spawn_err: Option<&std::io::Error>,
) -> Vec<EnforcementObservation> {
    controls
        .iter()
        .filter(|c| c.layer == ControlLayer::Os && c.state == ControlState::Planned)
        .map(|c| linux_control_observation(c, apply, spawn_err))
        .collect()
}

/// The fixed pipeline stage a control's mechanism occupies — same order
/// as `linux_spawn::apply_in_child`. Controls with no stage mapping get
/// an `Unknown` observation rather than a guessed success.
#[cfg(target_os = "linux")]
fn linux_control_stage(id: &str) -> Option<u8> {
    use super::linux_spawn::stage;
    match id {
        "os.privileges" => Some(stage::NO_NEW_PRIVS),
        "os.fs" | "os.net.outbound" => Some(stage::LANDLOCK),
        "os.syscalls" => Some(stage::SECCOMP),
        _ => None,
    }
}

#[cfg(target_os = "linux")]
fn linux_control_observation(
    c: &PlannedControl,
    apply: Option<&linux_spawn::ApplySnapshot>,
    spawn_err: Option<&std::io::Error>,
) -> EnforcementObservation {
    let Some(my_stage) = linux_control_stage(c.id) else {
        return observation(
            c.id,
            ControlState::Unknown,
            ObservationBasis::NotObserved,
            ControlPhase::Spawn,
            Some("no apply stage is bound to this control".to_string()),
        );
    };

    let Some(snap) = apply else {
        return observation(
            c.id,
            ControlState::Unknown,
            ObservationBasis::NotObserved,
            ControlPhase::Spawn,
            Some(match spawn_err {
                Some(e) => format!("spawn failed ({e}); no apply record was collected"),
                None => "apply record unavailable (shared page was not mapped)".to_string(),
            }),
        );
    };

    // A recorded failure implies the spawn failed: `failed_stage` is
    // written only on the `pre_exec` error path, and an honest record
    // then has `stage == failed_stage - 1` (the stage right before the
    // failed one completed, nothing after it did). A success alongside
    // a recorded failure, or any other `stage`/`failed_stage` pairing,
    // is corrupt — report Unknown, never applied.
    let record_inconsistent = snap.failed_stage != linux_spawn::stage::NONE
        && (spawn_err.is_none() || snap.stage.checked_add(1) != Some(snap.failed_stage));
    if record_inconsistent {
        return observation(
            c.id,
            ControlState::Unknown,
            ObservationBasis::MechanismResult,
            ControlPhase::Spawn,
            Some(
                "apply record is inconsistent (a recorded failure cannot pair \
                 with the recorded stages)"
                    .to_string(),
            ),
        );
    }

    if snap.failed_stage == my_stage {
        return observation(
            c.id,
            ControlState::Failed,
            ObservationBasis::MechanismResult,
            ControlPhase::Spawn,
            Some(linux_stage_failure_reason(snap)),
        );
    }

    if snap.stage >= my_stage {
        // This stage verifiably completed. A spawn error afterwards
        // (e.g. execve ENOENT) does not undo the apply — the reason
        // names it so a verified control is never read as a live launch.
        let (state, mut reason) = linux_stage_outcome(c.id, snap);
        if let Some(e) = spawn_err {
            reason.push_str(&format!("; the spawn itself then failed: {e}"));
        }
        return observation(
            c.id,
            state,
            ObservationBasis::MechanismResult,
            ControlPhase::Spawn,
            Some(reason),
        );
    }

    if snap.failed_stage != linux_spawn::stage::NONE {
        return observation(
            c.id,
            ControlState::Failed,
            ObservationBasis::MechanismResult,
            ControlPhase::Spawn,
            Some(format!(
                "the apply pipeline aborted at an earlier stage (os error {})",
                snap.errno
            )),
        );
    }

    observation(
        c.id,
        ControlState::Unknown,
        ObservationBasis::MechanismResult,
        ControlPhase::Spawn,
        Some(match spawn_err {
            Some(e) => {
                format!("spawn failed ({e}) and the apply record stops before this stage")
            }
            None => "apply record stops before this stage although spawn succeeded".to_string(),
        }),
    )
}

/// Reason for the stage that returned `Err` to `pre_exec`. For Landlock
/// the kernel-reported level is included — a refusal because the ruleset
/// was only partially enforced reads differently from a syscall error.
#[cfg(target_os = "linux")]
fn linux_stage_failure_reason(snap: &linux_spawn::ApplySnapshot) -> String {
    use super::linux_spawn::{landlock_level, stage};
    let base = match snap.failed_stage {
        stage::NO_NEW_PRIVS => "no_new_privs prctl failed in the child",
        stage::LANDLOCK => "Landlock apply stage failed in the child",
        stage::SECCOMP => "seccomp apply failed in the child",
        _ => "an apply stage failed in the child",
    };
    let mut reason = format!("{base} (os error {})", snap.errno);
    if snap.failed_stage == stage::LANDLOCK {
        match snap.landlock {
            landlock_level::PARTIAL => reason.push_str(
                "; restrict_self reported PartiallyEnforced and \
                 sandbox.allow_degraded is off",
            ),
            landlock_level::NOT_ENFORCED => reason.push_str(
                "; restrict_self reported NotEnforced and \
                 sandbox.allow_degraded is off",
            ),
            _ => {}
        }
    }
    reason
}

/// Observation for a control whose stage the record marks complete.
/// For Landlock-backed controls this maps the kernel-reported
/// enforcement level; `os.net.outbound` additionally splits on the
/// kernel ABI — Landlock network rules exist only since ABI v4.
#[cfg(target_os = "linux")]
fn linux_stage_outcome(id: &str, snap: &linux_spawn::ApplySnapshot) -> (ControlState, String) {
    use super::linux_spawn::landlock_level;
    match id {
        "os.privileges" => (
            ControlState::Verified,
            "no_new_privs confirmed set in the child's pre_exec".to_string(),
        ),
        "os.syscalls" => (
            ControlState::Verified,
            "seccomp program confirmed installed in the child's pre_exec".to_string(),
        ),
        "os.fs" | "os.net.outbound" => {
            let abi = if snap.landlock_abi > 0 {
                format!(" (kernel Landlock ABI v{})", snap.landlock_abi)
            } else {
                String::new()
            };
            match snap.landlock {
                landlock_level::FULL => (
                    ControlState::Verified,
                    format!("restrict_self reported FullyEnforced{abi}"),
                ),
                landlock_level::PARTIAL => {
                    if id == "os.net.outbound" && (1..4).contains(&snap.landlock_abi) {
                        (
                            ControlState::NotApplied,
                            format!(
                                "kernel Landlock ABI v{} predates network rules (v4); \
                                 outbound port rules were not enforceable",
                                snap.landlock_abi
                            ),
                        )
                    } else {
                        (
                            ControlState::PartiallyApplied,
                            format!(
                                "restrict_self reported PartiallyEnforced{abi}; tolerated \
                                 by sandbox.allow_degraded — which rules were dropped is not \
                                 decomposed per control"
                            ),
                        )
                    }
                }
                landlock_level::NOT_ENFORCED => (
                    ControlState::NotApplied,
                    format!(
                        "restrict_self reported NotEnforced{abi}; tolerated by \
                         sandbox.allow_degraded — no Landlock enforcement is in effect"
                    ),
                ),
                // Currently unreachable: `prepare_linux_child_sandbox`
                // always installs a ruleset, so the child never records
                // NO_RULESET today. Kept so the mapping stays honest if
                // a "policy without Landlock" path is ever added.
                landlock_level::NO_RULESET => (
                    ControlState::NotApplied,
                    "no Landlock ruleset was applied".to_string(),
                ),
                landlock_level::NOT_RUN => (
                    ControlState::Unknown,
                    "the record shows the Landlock stage ran but stored no status".to_string(),
                ),
                _ => (
                    ControlState::Unknown,
                    "the apply record carries no Landlock result".to_string(),
                ),
            }
        }
        _ => (
            ControlState::Unknown,
            "no outcome mapping for this control".to_string(),
        ),
    }
}

#[cfg(target_os = "macos")]
pub(super) fn os_controls(policy: &Policy) -> Vec<PlannedControl> {
    vec![
        control(
            "os.sandbox",
            ControlLayer::Os,
            "sandbox-exec",
            ControlState::Planned,
            Some(
                "sandbox-exec launch of the generated SBPL profile; kernel \
                 acceptance of the rules is reported per domain"
                    .to_string(),
            ),
        ),
        planned("os.fs", ControlLayer::Os, "sbpl"),
        planned("os.net.outbound", ControlLayer::Os, "sbpl"),
        if !policy.network.inbound.allow_listen {
            control(
                "os.net.inbound",
                ControlLayer::Os,
                "sbpl",
                ControlState::NotApplicable,
                Some("no inbound listen requested".to_string()),
            )
        } else if policy.network.outbound.deny_all_others {
            control(
                "os.net.inbound",
                ControlLayer::Os,
                "sbpl",
                ControlState::NotApplied,
                Some("network-bind is not granted while outbound deny-all is set".to_string()),
            )
        } else {
            planned("os.net.inbound", ControlLayer::Os, "sbpl")
        },
        control(
            "os.process",
            ControlLayer::Os,
            "sbpl",
            ControlState::Planned,
            Some("fixed baseline (fork/exec/signal/sysctl/mach services)".to_string()),
        ),
        control(
            "os.syscalls",
            ControlLayer::Os,
            "seccomp",
            ControlState::NotApplicable,
            Some("no syscall allowlist mechanism on macOS".to_string()),
        ),
    ]
}

/// Build-phase observation for `os.sandbox`: the SBPL profile text and
/// the private TMPDIR were produced — that is all it verifies. Kernel
/// acceptance is a spawn-time question `sandbox-exec` cannot answer.
#[cfg(target_os = "macos")]
pub(super) fn macos_prepare_observation(
    failure: Option<(&'static str, &WardenError)>,
) -> EnforcementObservation {
    match failure {
        None => observation(
            "os.sandbox",
            ControlState::Verified,
            ObservationBasis::VerificationRun,
            ControlPhase::Build,
            Some(
                "SBPL profile generated and private TMPDIR created; the \
                 profile contents are listed as plan grants"
                    .to_string(),
            ),
        ),
        Some((stage, e)) => observation(
            "os.sandbox",
            ControlState::Failed,
            ObservationBasis::VerificationRun,
            ControlPhase::Build,
            Some(format!("{stage}: {e}")),
        ),
    }
}

/// `sandbox-exec` does not expose whether the kernel accepted the
/// profile, so the per-domain SBPL controls stay `Unknown` after a
/// successful spawn. What *is* observable is the launcher itself: a
/// spawn error (a missing `sandbox-exec`), or an exit inside the
/// initial-exit window — a rejected profile or an un-exec'able workload
/// surfaces that way, but so does any workload that simply finishes
/// quickly. The exit status is recorded on `os.sandbox` as the child's
/// termination state; an early exit alone is not evidence the mechanism
/// failed, so the control stays `Unknown`. The domain controls never
/// upgrade on inference: an early exit says the process died, not
/// which side of profile acceptance it died on.
#[cfg(target_os = "macos")]
pub(super) fn os_spawn_observations(
    controls: &[PlannedControl],
    spawn_err: Option<&std::io::Error>,
    liveness: Option<&SpawnLiveness>,
) -> Vec<EnforcementObservation> {
    controls
        .iter()
        .filter(|c| c.layer == ControlLayer::Os && c.state == ControlState::Planned)
        .map(|c| {
            if c.id == "os.sandbox" {
                return sandbox_exec_observation(spawn_err, liveness);
            }
            match (spawn_err, liveness) {
                (Some(e), _) => observation(
                    c.id,
                    ControlState::Failed,
                    ObservationBasis::SpawnResult,
                    ControlPhase::Spawn,
                    Some(format!(
                        "sandbox-exec could not be started: {e}; no profile was applied"
                    )),
                ),
                (None, Some(SpawnLiveness::Exited(status))) => observation(
                    c.id,
                    ControlState::Unknown,
                    ObservationBasis::SpawnResult,
                    ControlPhase::Spawn,
                    Some(format!(
                        "the process exited ({status}) inside the initial-exit \
                         window; whether the kernel had accepted the profile \
                         cannot be determined"
                    )),
                ),
                (None, Some(SpawnLiveness::Running)) => observation(
                    c.id,
                    ControlState::Unknown,
                    ObservationBasis::SpawnResult,
                    ControlPhase::Spawn,
                    Some(
                        "sandbox-exec spawned and the process kept running; \
                         in-kernel profile acceptance is not observable"
                            .to_string(),
                    ),
                ),
                (None, Some(SpawnLiveness::PollFailed)) | (None, None) => observation(
                    c.id,
                    ControlState::Unknown,
                    ObservationBasis::SpawnResult,
                    ControlPhase::Spawn,
                    Some(
                        "sandbox-exec spawned; the liveness probe failed and \
                         in-kernel profile acceptance is not observable"
                            .to_string(),
                    ),
                ),
            }
        })
        .collect()
}

/// The `os.sandbox` spawn observation: whether the `sandbox-exec` launch
/// produced a process that survived the initial-exit window. `Verified`
/// states only that fact — per-rule kernel acceptance stays on the
/// domain controls above. An exit inside the window is recorded as the
/// child's termination state but stays `Unknown`: a short-lived workload
/// ends the same way a rejected profile does, so the exit alone does not
/// establish that sandbox application failed.
#[cfg(target_os = "macos")]
fn sandbox_exec_observation(
    spawn_err: Option<&std::io::Error>,
    liveness: Option<&SpawnLiveness>,
) -> EnforcementObservation {
    match (spawn_err, liveness) {
        (Some(e), _) => observation(
            "os.sandbox",
            ControlState::Failed,
            ObservationBasis::SpawnResult,
            ControlPhase::Spawn,
            Some(format!("sandbox-exec could not be started: {e}")),
        ),
        (None, Some(SpawnLiveness::Exited(status))) => observation(
            "os.sandbox",
            ControlState::Unknown,
            ObservationBasis::SpawnResult,
            ControlPhase::Spawn,
            Some(format!(
                "the process exited ({status}) inside the initial-exit window; \
                 whether the kernel had accepted the profile cannot be determined"
            )),
        ),
        (None, Some(SpawnLiveness::Running)) => observation(
            "os.sandbox",
            ControlState::Verified,
            ObservationBasis::SpawnResult,
            ControlPhase::Spawn,
            Some(
                "sandbox-exec spawned and the process stayed running through \
                 the initial-exit window"
                    .to_string(),
            ),
        ),
        (None, Some(SpawnLiveness::PollFailed)) | (None, None) => observation(
            "os.sandbox",
            ControlState::Unknown,
            ObservationBasis::SpawnResult,
            ControlPhase::Spawn,
            Some("post-spawn liveness could not be established".to_string()),
        ),
    }
}

#[cfg(target_os = "windows")]
pub(super) fn os_controls(policy: &Policy) -> Vec<PlannedControl> {
    let lpac = super::windows_profile::lpac_enabled();
    let v = vec![
        control(
            "os.process",
            ControlLayer::Os,
            "appcontainer + job",
            ControlState::Planned,
            Some(
                if lpac {
                    "AppContainer profile + kill-on-close Job Object (LPAC mode via \
                 MCP_WRIT_WINDOWS_LPAC)"
                } else {
                    "AppContainer profile + kill-on-close Job Object"
                }
                .to_string(),
            ),
        ),
        planned("os.fs", ControlLayer::Os, "appcontainer + dacl"),
        if policy.network.outbound.deny_all_others {
            control(
                "os.net.outbound",
                ControlLayer::Os,
                "appcontainer capabilities",
                ControlState::Planned,
                Some("default-deny: no network capabilities are granted".to_string()),
            )
        } else {
            control(
                "os.net.outbound",
                ControlLayer::Os,
                "appcontainer capabilities",
                ControlState::Planned,
                Some(
                    "internetClient + privateNetworkClientServer (all-or-none; \
                     per-destination rules stay RPC-layer)"
                        .to_string(),
                ),
            )
        },
        if !policy.network.inbound.allow_listen {
            control(
                "os.net.inbound",
                ControlLayer::Os,
                "appcontainer capabilities",
                ControlState::NotApplicable,
                Some("no inbound listen requested".to_string()),
            )
        } else if policy.network.outbound.deny_all_others {
            control(
                "os.net.inbound",
                ControlLayer::Os,
                "appcontainer capabilities",
                ControlState::NotApplied,
                Some(
                    "inbound requires internet capabilities that outbound \
                     deny-all withholds"
                        .to_string(),
                ),
            )
        } else {
            control(
                "os.net.inbound",
                ControlLayer::Os,
                "appcontainer capabilities",
                ControlState::Planned,
                Some("internetClientServer".to_string()),
            )
        },
        if matches!(policy.transport.type_, TransportType::Http) {
            // A deliberate isolation *opening*: HTTP transport needs
            // loopback to the container, so the exemption is a mandatory
            // pipeline stage and gets its own control — an unconfirmed
            // exemption must not hide inside the capability grants.
            control(
                "os.net.loopback",
                ControlLayer::Os,
                "CheckNetIsolation loopback exemption",
                ControlState::Planned,
                Some("HTTP transport requires loopback to the container".to_string()),
            )
        } else {
            control(
                "os.net.loopback",
                ControlLayer::Os,
                "CheckNetIsolation loopback exemption",
                ControlState::NotApplicable,
                Some("no HTTP transport; loopback stays denied".to_string()),
            )
        },
        control(
            "os.syscalls",
            ControlLayer::Os,
            "seccomp",
            ControlState::NotApplicable,
            Some("no syscall allowlist mechanism on Windows".to_string()),
        ),
    ];
    v
}

/// The Windows pipeline applies controls in the parent before and after
/// `CreateProcessW`; the call itself is authoritative for the container
/// token. The evidence is the [`WinSpawnError`] stage tag (plus the
/// per-grant record `spawn_sandboxed` fills as it applies):
///
/// - a *setup* abort (stages before `CreateProcessW`) means no container
///   process ever existed, so every still-planned control is `Failed`
///   with the stage named;
/// - a `CreateProcessW` failure fuses attribute and image checks —
///   undetermined, so controls read `Unknown`;
/// - a *post-create* abort (Job or execution start) ran against a real
///   suspended container process: `os.process` is `Failed`, while
///   controls whose apply work had provably completed keep that outcome
///   with the abort appended to their reason — the same convention as
///   the Linux exec-failure path;
/// - a spawned child gives each control its mechanism result — the
///   container token for `os.process`, the ACL API results for `os.fs`,
///   the token capabilities for the net controls.
#[cfg(target_os = "windows")]
pub(super) fn os_spawn_observations(
    controls: &[PlannedControl],
    grants: &[ProcessGrant],
    outcome: Option<&WinSpawnError>,
) -> Vec<EnforcementObservation> {
    controls
        .iter()
        .filter(|c| c.layer == ControlLayer::Os && c.state == ControlState::Planned)
        .map(|c| match outcome {
            None => windows_success_observation(c, grants, None),
            Some(err) => windows_abort_observation(c, grants, err),
        })
        .collect()
}

/// Per-control outcome after a completed or post-create-aborted spawn.
/// `abort` is the post-`CreateProcessW` failure, when the spawn died on
/// Job/execution-start cleanup; it is appended to the reason so the
/// observation can never read as a live launch.
#[cfg(target_os = "windows")]
fn windows_success_observation(
    c: &PlannedControl,
    grants: &[ProcessGrant],
    abort: Option<&WinSpawnError>,
) -> EnforcementObservation {
    let mut o = match c.id {
        "os.process" => {
            let lpac = if super::windows_profile::lpac_enabled() {
                " (LPAC)"
            } else {
                ""
            };
            observation(
                c.id,
                ControlState::Verified,
                ObservationBasis::MechanismResult,
                ControlPhase::Spawn,
                Some(format!(
                    "AppContainer{lpac} profile created; the process was \
                     created suspended inside the container, assigned to a \
                     kill-on-close Job, and execution resumed — \
                     CreateProcessW is authoritative for the container token"
                )),
            )
        }
        "os.fs" => {
            let failed = grants
                .iter()
                .filter(|g| matches!(g.subject, GrantSubject::FsPath { .. }))
                .filter(|g| g.origin == GrantOrigin::Policy)
                .filter(|g| g.state == ControlState::Failed)
                .count();
            if failed > 0 {
                observation(
                    c.id,
                    ControlState::PartiallyApplied,
                    ObservationBasis::MechanismResult,
                    ControlPhase::Spawn,
                    Some(format!(
                        "{failed} filesystem ACL grant(s) failed; \
                         effective access is unverified"
                    )),
                )
            } else {
                observation(
                    c.id,
                    ControlState::Verified,
                    ObservationBasis::MechanismResult,
                    ControlPhase::Spawn,
                    Some(
                        "all path DACL writes returned success \
                         (SetNamedSecurityInfoW); the child was created \
                         inside the container"
                            .to_string(),
                    ),
                )
            }
        }
        "os.net.outbound" => {
            let caps = grants
                .iter()
                .filter(|g| {
                    matches!(g.subject, GrantSubject::Capability { .. })
                        && g.state == ControlState::Verified
                })
                .map(|g| match &g.subject {
                    GrantSubject::Capability { name } => name.clone(),
                    _ => String::new(),
                })
                .collect::<Vec<_>>();
            let reason = if caps.is_empty() {
                "no network capability SIDs in the container token — \
                 outbound stays default-deny"
                    .to_string()
            } else {
                format!(
                    "capability SIDs in the container token: {} \
                     (all-or-none; per-destination rules stay RPC-layer)",
                    caps.join(", ")
                )
            };
            observation(
                c.id,
                ControlState::Verified,
                ObservationBasis::MechanismResult,
                ControlPhase::Spawn,
                Some(reason),
            )
        }
        "os.net.inbound" => observation(
            c.id,
            ControlState::Verified,
            ObservationBasis::MechanismResult,
            ControlPhase::Spawn,
            Some(
                "internetClientServer capability SID is in the container \
                 token"
                    .to_string(),
            ),
        ),
        "os.net.loopback" => {
            let exempt = grants.iter().find(|g| {
                matches!(&g.subject, GrantSubject::Rule { kind, .. }
                    if *kind == "loopback_exemption")
            });
            match exempt.map(|g| g.state) {
                Some(ControlState::Verified) => observation(
                    c.id,
                    ControlState::Verified,
                    ObservationBasis::MechanismResult,
                    ControlPhase::Spawn,
                    Some(
                        "CheckNetIsolation reported the loopback exemption \
                         applied"
                            .to_string(),
                    ),
                ),
                Some(ControlState::Unknown) => observation(
                    c.id,
                    ControlState::Unknown,
                    ObservationBasis::MechanismResult,
                    ControlPhase::Spawn,
                    Some(
                        "CheckNetIsolation exited nonzero; the exemption \
                         was not confirmed"
                            .to_string(),
                    ),
                ),
                _ => observation(
                    c.id,
                    ControlState::Unknown,
                    ObservationBasis::NotObserved,
                    ControlPhase::Spawn,
                    Some("no loopback exemption record".to_string()),
                ),
            }
        }
        _ => observation(
            c.id,
            ControlState::Unknown,
            ObservationBasis::NotObserved,
            ControlPhase::Spawn,
            Some("no outcome mapping for this control".to_string()),
        ),
    };
    if let Some(err) = abort {
        let note = format!(
            "the launch then aborted at the {} stage: {}; the suspended \
             process was terminated and the created handles/Job were \
             cleaned up",
            err.stage.label(),
            err.source
        );
        o.reason = Some(match o.reason {
            Some(r) => format!("{r}; {note}"),
            None => note,
        });
    }
    o
}

/// Every still-planned control after an aborted Windows spawn.
#[cfg(target_os = "windows")]
fn windows_abort_observation(
    c: &PlannedControl,
    grants: &[ProcessGrant],
    err: &WinSpawnError,
) -> EnforcementObservation {
    match err.stage {
        // CreateProcessW fuses the attribute and image checks — an
        // undetermined failure, not a sandbox-apply failure.
        WinStage::CreateProcess => observation(
            c.id,
            ControlState::Unknown,
            ObservationBasis::SpawnResult,
            ControlPhase::Spawn,
            Some(format!(
                "spawn failed; sandbox application undetermined: {}",
                err.source
            )),
        ),
        // After CreateProcessW a real container process existed and had
        // to be torn down — that is an explicit failure for os.process.
        WinStage::Job | WinStage::Resume if c.id == "os.process" => observation(
            c.id,
            ControlState::Failed,
            ObservationBasis::MechanismResult,
            ControlPhase::Spawn,
            Some(format!(
                "the {} stage failed: {}; the suspended process inside \
                 the container was terminated and the created handles/Job \
                 were cleaned up",
                err.stage.label(),
                err.source
            )),
        ),
        // Other controls' apply work had provably completed — keep their
        // mechanism outcomes, with the abort appended to the reason.
        WinStage::Job | WinStage::Resume => windows_success_observation(c, grants, Some(err)),
        // Any earlier stage died before process creation: nothing ever
        // went live, so every planned control is an explicit failure
        // that names the stage.
        _ => observation(
            c.id,
            ControlState::Failed,
            ObservationBasis::MechanismResult,
            ControlPhase::Spawn,
            Some(format!(
                "the {} stage failed: {}; the launch aborted before \
                 process creation and created objects were cleaned up",
                err.stage.label(),
                err.source
            )),
        ),
    }
}

/// Windows spawn outcome → per-control observations, plus the plan
/// update a provable construction failure calls for. This is the
/// assembly `spawn_child_async_impl` runs for every Windows launch.
///
/// The observations are generated *before* the plan is touched:
/// [`os_spawn_observations`] reports only controls still `Planned`, so
/// failing the plan first would leave a setup abort with failed
/// controls and no per-control evidence at all. Only then does a
/// *pre-`CreateProcessW`* failure (`profile-creation`,
/// `grant-application`, `process-setup`) whose source is a provable
/// `Policy`/`Prepare` setup error mark the planned controls `Failed` —
/// the same convention as the Linux/macOS build-failure paths. Later
/// stages never collapse the plan: `CreateProcessW` fuses its inputs so
/// the failing one is undetermined, and a Job/execution-start abort ran
/// against a real container process whose per-control outcomes the
/// observations already carry.
#[cfg(target_os = "windows")]
pub(super) fn windows_spawn_outcome(
    controls: &mut [PlannedControl],
    grants: &[ProcessGrant],
    outcome: Option<&WinSpawnError>,
) -> Vec<EnforcementObservation> {
    let observations = os_spawn_observations(controls, grants, outcome);
    if let Some(e) = outcome
        && matches!(
            e.stage,
            WinStage::Profile | WinStage::Grants | WinStage::ProcessSetup
        )
        && matches!(
            &e.source,
            WardenError::SandboxSetup { stage, .. }
                if matches!(
                    stage,
                    crate::error::SandboxStage::Policy | crate::error::SandboxStage::Prepare
                )
        )
    {
        fail_os_controls(
            controls,
            &format!("sandbox pipeline failed at the {} stage", e.stage.label()),
            &e.source,
        );
    }
    observations
}

/// Fallback control list for platforms without an OS sandbox.
#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
pub(super) fn os_controls(_policy: &Policy) -> Vec<PlannedControl> {
    vec![control(
        "os.sandbox",
        ControlLayer::Os,
        "none",
        ControlState::NotApplied,
        Some("no OS sandbox mechanism exists on this platform".to_string()),
    )]
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
pub(super) fn os_spawn_observations(_controls: &[PlannedControl]) -> Vec<EnforcementObservation> {
    Vec::new()
}

// ---------------------------------------------------------------------------
// Plan-time grants (runs the same builders the spawn path uses)
// ---------------------------------------------------------------------------

/// Plan-mode grants for the sandboxed case: runs the same rule builders
/// as the spawn path (their artifacts are discarded — nothing is applied)
/// and marks OS controls `Failed` when the build itself fails.
#[cfg(target_os = "linux")]
pub(super) fn os_plan_grants(
    policy: &Policy,
    _program: Option<&Path>,
    _command: &str,
    _opts: &SpawnOptions,
    controls: &mut [PlannedControl],
) -> Vec<ProcessGrant> {
    match super::linux_spawn::prepare_linux_child_sandbox(policy) {
        Ok(bits) => bits.grants,
        Err(e) => {
            fail_os_controls(controls, "rule build failed", &e);
            Vec::new()
        }
    }
}

#[cfg(target_os = "macos")]
pub(super) fn os_plan_grants(
    policy: &Policy,
    _program: Option<&Path>,
    _command: &str,
    opts: &SpawnOptions,
    controls: &mut [PlannedControl],
) -> Vec<ProcessGrant> {
    // A private TMPDIR is always created at spawn; use the caller's
    // override when present, else the real temp dir so ancestor
    // traversal grants resolve against the launch-time location.
    let tmp = opts
        .tmpdir
        .clone()
        .unwrap_or_else(|| std::env::temp_dir().join("mcp-writ-sbx-<launch>"));
    match super::macos_sandbox::sbpl_profile(policy, &tmp.to_string_lossy()) {
        Ok((_text, grants)) => grants,
        Err(e) => {
            fail_os_controls(controls, "profile build failed", &e);
            Vec::new()
        }
    }
}

#[cfg(target_os = "windows")]
pub(super) fn os_plan_grants(
    policy: &Policy,
    program: Option<&Path>,
    command: &str,
    opts: &SpawnOptions,
    _controls: &mut [PlannedControl],
) -> Vec<ProcessGrant> {
    // Intents only — no profile is created and nothing is applied.
    super::windows_sandbox::grant_intents(policy, program, command, opts.tmpdir.as_deref())
        .into_iter()
        .map(|(grant, _)| grant)
        .collect()
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
pub(super) fn os_plan_grants(
    _policy: &Policy,
    _program: Option<&Path>,
    _command: &str,
    _opts: &SpawnOptions,
    _controls: &mut [PlannedControl],
) -> Vec<ProcessGrant> {
    Vec::new()
}

// ---------------------------------------------------------------------------
// Per-OS scope notes
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
pub(super) fn os_limitations(policy: &Policy, out: &mut Vec<String>) {
    if policy.sandbox.allow_degraded {
        out.push(
            "sandbox.allow_degraded=#true: partial or absent Landlock enforcement \
             is tolerated instead of aborting the launch; the kernel-reported \
             level is collected from the child and shown per control."
                .to_string(),
        );
    }
}

#[cfg(target_os = "macos")]
pub(super) fn os_limitations(_policy: &Policy, out: &mut Vec<String>) {
    out.push(
        "sandbox-exec does not expose whether the kernel accepted the SBPL \
         profile; the report records profile generation, the spawn result, \
         and a bounded initial-exit check — the per-domain OS controls stay \
         unobserved."
            .to_string(),
    );
}

#[cfg(target_os = "windows")]
pub(super) fn os_limitations(_policy: &Policy, out: &mut Vec<String>) {
    out.push(
        "AppContainer inherits ambient read access via ALL_APPLICATION_PACKAGES \
         (program files, registry keys); only explicit ACL grants are enumerated."
            .to_string(),
    );
    out.push(
        "A 'verified' ACL grant records the SetNamedSecurityInfoW API result \
         (the ACE was written); whether access is actually allowed or denied \
         follows each object's resulting ACL — deny coverage is exercised by \
         the warden tests, not by this report."
            .to_string(),
    );
    out.push(
        "AppContainer network capabilities are all-or-none; per-destination \
         outbound rules are not expressible and stay RPC-layer checks."
            .to_string(),
    );
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
pub(super) fn os_limitations(_policy: &Policy, out: &mut Vec<String>) {
    out.push("no OS sandbox mechanism exists on this platform.".to_string());
}

// ---------------------------------------------------------------------------
// Assembly
// ---------------------------------------------------------------------------

/// Assemble the full plan for a spawn under `opts`. `sandbox_skip` marks
/// the OS controls `Skipped` and produces no grants — the plan describes
/// what this launch *did*, and a skipped sandbox granted nothing.
pub(super) fn build_plan(
    policy: &Policy,
    program: Option<&Path>,
    command: &str,
    opts: &SpawnOptions,
    sandbox_skip: Option<&'static str>,
    dry_run: bool,
) -> EnforcementPlan {
    // Only a sandboxed macOS spawn creates a private TMPDIR; a skipped
    // sandbox keeps the parent's TMPDIR.
    let private_tmpdir = cfg!(target_os = "macos") && sandbox_skip.is_none();
    let mut controls = shared_controls(policy, opts, dry_run, private_tmpdir);
    let tools = tools_table(policy);
    let mut limitations = base_limitations();
    let grants;
    match sandbox_skip {
        Some(reason) => {
            let mut os = os_controls(policy);
            mark_skipped(&mut os, reason);
            controls.extend(os);
            grants = Vec::new();
        }
        None => {
            let mut os = os_controls(policy);
            grants = os_plan_grants(policy, program, command, opts, &mut os);
            controls.extend(os);
            os_limitations(policy, &mut limitations);
        }
    }
    EnforcementPlan {
        controls,
        grants,
        tools,
        limitations,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(any(target_os = "linux", target_os = "windows"))]
    use crate::enforcement::{FsAccess, GrantOrigin, GrantSubject};
    use crate::policy::{FsToolPolicy, ToolPolicy};

    /// A policy with an allowed read tool, an allowed write tool, and a
    /// denied tool — the "read/write tools coexist + denied tool" case
    /// the PR-03 verification list calls for.
    fn policy_with_tools() -> Policy {
        let mut policy = Policy::default();
        // The Linux spawn path refuses policies without an execve
        // allowance; every test here declares it.
        policy.syscalls.allowed = vec!["execve".to_string()];

        let mut read = ToolPolicy::named("read_file", true);
        read.server = Some("fs".to_string());
        read.side_effect = Some("read_only".to_string());
        // allowed_paths=[/usr] is the tool grant; read_only_paths adds
        // /deny-me which the global deny list overrides — an exact-match
        // deny produces a Skipped grant (a deny *subpath* of an allowed
        // path is rejected by validation before the build).
        let mut fs = FsToolPolicy::new(vec!["/usr".to_string()], vec![]);
        fs.read_only_paths = vec!["/usr".to_string(), "/deny-me".to_string()];
        read.fs = Some(fs);

        let mut write = ToolPolicy::named("write_file", true);
        write.side_effect = Some("write".to_string());

        let denied = ToolPolicy::named("rm_rf", false);

        policy.tools = vec![read, write, denied];
        policy
    }

    fn control_state<'a>(plan: &'a EnforcementPlan, id: &str) -> (ControlState, &'a str) {
        let c = plan
            .controls
            .iter()
            .find(|c| c.id == id)
            .unwrap_or_else(|| panic!("control {id} missing"));
        (c.state, c.reason.as_deref().unwrap_or(""))
    }

    #[test]
    fn tools_table_keeps_read_write_and_denied_tools() {
        let tools = tools_table(&policy_with_tools());
        assert_eq!(tools.len(), 3);
        let read = tools.iter().find(|t| t.name == "read_file").unwrap();
        assert!(read.allowed);
        assert_eq!(read.server.as_deref(), Some("fs"));
        assert_eq!(read.side_effect.as_deref(), Some("read_only"));
        let write = tools.iter().find(|t| t.name == "write_file").unwrap();
        assert!(write.allowed);
        assert_eq!(write.side_effect.as_deref(), Some("write"));
        let denied = tools.iter().find(|t| t.name == "rm_rf").unwrap();
        assert!(!denied.allowed);
    }

    #[test]
    fn shared_controls_distinguish_optional_features() {
        let policy = policy_with_tools();
        let opts = SpawnOptions {
            restrict_environment: true,
            allowed_names: vec!["FOO".to_string()],
            tmpdir: None,
        };
        let controls = shared_controls(&policy, &opts, false, false);
        let by_id = |id: &str| controls.iter().find(|c| c.id == id).unwrap();

        // Identity planned? default policy has no hash entries.
        assert_eq!(by_id("launch.identity").state, ControlState::Skipped);
        assert_eq!(by_id("launch.env").state, ControlState::Planned);
        // RPC controls are always planned (the auditor runs them).
        for id in ["rpc.tools", "rpc.tools_list"] {
            assert_eq!(by_id(id).state, ControlState::Planned);
            assert_eq!(by_id(id).layer, ControlLayer::Rpc);
        }
        // secret_overlay defaults on; trajectory / confused_deputy are opt-in.
        assert_eq!(by_id("rpc.secret_overlay").state, ControlState::Planned);
        assert_eq!(by_id("rpc.trajectory").state, ControlState::Skipped);
        assert_eq!(by_id("rpc.confused_deputy").state, ControlState::Skipped);

        // Opt-ins flip to Planned.
        let mut on = policy.clone();
        on.trajectory = true;
        on.confused_deputy_protection = true;
        on.fs.secret_overlay = false;
        let controls = shared_controls(&on, &opts, false, false);
        let by_id = |id: &str| controls.iter().find(|c| c.id == id).unwrap();
        assert_eq!(by_id("rpc.trajectory").state, ControlState::Planned);
        assert_eq!(by_id("rpc.confused_deputy").state, ControlState::Planned);
        assert_eq!(by_id("rpc.secret_overlay").state, ControlState::Skipped);
    }

    #[test]
    fn env_observation_only_exists_when_the_contract_applies() {
        assert!(env_observation(false, None).is_none());
        let ok = env_observation(true, None).unwrap();
        assert_eq!(ok.state, ControlState::Verified);
        assert_eq!(ok.phase, ControlPhase::Spawn);
        let err = env_observation(true, Some("boom".to_string())).unwrap();
        assert_eq!(err.state, ControlState::Unknown);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_plan_grants_come_from_the_same_build() {
        let mut policy = policy_with_tools();
        policy.fs.read_only = vec!["/tmp".to_string()];
        policy.fs.read_write = vec!["/definitely/missing/mcp-writ".to_string()];
        policy.fs.denied_paths = vec!["/deny-me".to_string()];
        policy.network.outbound.allowed = vec!["443".to_string(), "api.example.com".to_string()];
        policy.network.inbound.allow_listen = true;

        let plan = build_plan(
            &policy,
            None,
            "child",
            &SpawnOptions::default(),
            None,
            false,
        );

        // The plan's grants are exactly what the spawn-path builder
        // produced — the two cannot diverge.
        let direct = super::super::linux_spawn::prepare_linux_child_sandbox(&policy)
            .expect("sandbox build")
            .grants;
        assert_eq!(plan.grants, direct);

        let fs = |path: &str| {
            plan.grants
                .iter()
                .find(|g| matches!(&g.subject, GrantSubject::FsPath { path: p, .. } if p == path))
                .unwrap_or_else(|| panic!("no fs grant for {path}"))
        };
        // Default (policy-level) permissions.
        let tmp = fs("/tmp");
        assert_eq!(tmp.state, ControlState::Planned);
        assert_eq!(tmp.origin, GrantOrigin::Policy);
        assert!(matches!(
            tmp.subject,
            GrantSubject::FsPath {
                access: FsAccess::Read,
                ..
            }
        ));
        // Deny rule wins over the tool's read listing.
        let denied = fs("/deny-me");
        assert_eq!(denied.state, ControlState::Skipped);
        assert_eq!(denied.origin, GrantOrigin::Tool("read_file".to_string()));
        // Missing path: the rule could not be constructed.
        let missing = fs("/definitely/missing/mcp-writ");
        assert_eq!(missing.state, ControlState::Skipped);
        assert!(missing.reason.as_deref().unwrap().contains("cannot open"));
        // Tool-contributed grant: process-wide, but provenance is the tool.
        let tool_grant = fs("/usr");
        assert_eq!(
            tool_grant.origin,
            GrantOrigin::Tool("read_file".to_string())
        );
        assert_eq!(tool_grant.state, ControlState::Planned);
        // Numeric port is a real Landlock rule; the hostname is not
        // expressible and stays RPC-layer only.
        let port = plan
            .grants
            .iter()
            .find(|g| matches!(g.subject, GrantSubject::TcpConnect { port: 443 }))
            .unwrap();
        assert_eq!(port.state, ControlState::Planned);
        let host = plan
            .grants
            .iter()
            .find(|g| matches!(&g.subject, GrantSubject::Rule { name, .. } if name == "api.example.com"))
            .unwrap();
        assert_eq!(host.state, ControlState::Skipped);
        // The execve allowance the policy declares is a Policy grant.
        let execve = plan
            .grants
            .iter()
            .find(|g| matches!(&g.subject, GrantSubject::Syscall { name } if name == "execve"))
            .unwrap();
        assert_eq!(execve.origin, GrantOrigin::Policy);
        assert_eq!(execve.state, ControlState::Planned);

        // Landlock cannot grant TCP bind — an accepted inbound rule is
        // reported NotApplied, never as success.
        assert_eq!(
            control_state(&plan, "os.net.inbound").0,
            ControlState::NotApplied
        );
        assert!(
            control_state(&plan, "os.net.inbound")
                .1
                .contains("Landlock")
        );
    }

    // -- Linux apply-record → observation mapping --------------------------
    // The record written by the pre-exec child is the only evidence; the
    // mapping below must never upgrade a missing/truncated record to an
    // applied state.

    #[cfg(target_os = "linux")]
    mod linux_observations {
        use super::*;
        use crate::warden::linux_spawn::{ApplySnapshot, landlock_level, stage};

        fn full_record() -> ApplySnapshot {
            ApplySnapshot {
                stage: stage::SECCOMP,
                landlock: landlock_level::FULL,
                landlock_abi: 4,
                failed_stage: 0,
                errno: 0,
            }
        }

        fn controls() -> Vec<PlannedControl> {
            let mut policy = policy_with_tools();
            policy.sandbox.allow_degraded = true;
            os_controls(&policy)
        }

        fn state_of(obs: &[EnforcementObservation], id: &str) -> ControlState {
            obs.iter().find(|o| o.control == id).unwrap().state
        }

        #[test]
        fn full_apply_reads_verified_even_with_allow_degraded() {
            // allow_degraded tolerates degradation; a kernel-reported
            // FullyEnforced must still read Verified — the flag never
            // decides the observed state on its own.
            let obs = os_spawn_observations(&controls(), Some(&full_record()), None);
            for id in ["os.privileges", "os.fs", "os.net.outbound", "os.syscalls"] {
                assert_eq!(state_of(&obs, id), ControlState::Verified, "{id}");
            }
        }

        #[test]
        fn partial_apply_is_reported_not_flattened() {
            // allow_degraded permits a partially enforced ruleset; the
            // record still reports PARTIAL, so fs reads PartiallyApplied.
            let snap = ApplySnapshot {
                landlock: landlock_level::PARTIAL,
                ..full_record()
            };
            let obs = os_spawn_observations(&controls(), Some(&snap), None);
            assert_eq!(state_of(&obs, "os.fs"), ControlState::PartiallyApplied);
            assert_eq!(state_of(&obs, "os.privileges"), ControlState::Verified);
            assert_eq!(state_of(&obs, "os.syscalls"), ControlState::Verified);
        }

        #[test]
        fn pre_v4_kernel_network_rules_read_not_applied() {
            // Landlock network rules exist since ABI v4: on an older
            // kernel the port rules were never enforceable, so the net
            // control reads NotApplied while fs is PartiallyApplied.
            let snap = ApplySnapshot {
                landlock: landlock_level::PARTIAL,
                landlock_abi: 1,
                ..full_record()
            };
            let obs = os_spawn_observations(&controls(), Some(&snap), None);
            assert_eq!(state_of(&obs, "os.net.outbound"), ControlState::NotApplied);
            assert_eq!(state_of(&obs, "os.fs"), ControlState::PartiallyApplied);
        }

        #[test]
        fn not_enforced_is_not_applied_not_unknown() {
            let snap = ApplySnapshot {
                landlock: landlock_level::NOT_ENFORCED,
                landlock_abi: 0,
                ..full_record()
            };
            let obs = os_spawn_observations(&controls(), Some(&snap), None);
            assert_eq!(state_of(&obs, "os.fs"), ControlState::NotApplied);
            assert_eq!(state_of(&obs, "os.net.outbound"), ControlState::NotApplied);
            assert_eq!(state_of(&obs, "os.syscalls"), ControlState::Verified);
        }

        #[test]
        fn failed_stage_marks_that_control_failed_and_later_unreached() {
            // The Landlock gate refused a partial ruleset: nnp completed,
            // the Landlock stage failed, seccomp never ran.
            let snap = ApplySnapshot {
                stage: stage::NO_NEW_PRIVS,
                landlock: landlock_level::PARTIAL,
                landlock_abi: 1,
                failed_stage: stage::LANDLOCK,
                errno: libc::EACCES,
            };
            let err = std::io::Error::from_raw_os_error(libc::EACCES);
            let obs = os_spawn_observations(&controls(), Some(&snap), Some(&err));
            assert_eq!(state_of(&obs, "os.privileges"), ControlState::Verified);
            assert_eq!(state_of(&obs, "os.fs"), ControlState::Failed);
            assert_eq!(state_of(&obs, "os.net.outbound"), ControlState::Failed);
            assert_eq!(state_of(&obs, "os.syscalls"), ControlState::Failed);
            let reason = &obs.iter().find(|o| o.control == "os.fs").unwrap().reason;
            assert!(reason.as_deref().unwrap().contains("PartiallyEnforced"));
        }

        #[test]
        fn exec_failure_after_apply_keeps_stages_but_notes_failure() {
            // execve failed after the whole pipeline ran (e.g. ENOENT):
            // the applies did happen; the reason names the spawn failure
            // so a verified stage is never read as a live launch.
            let err = std::io::Error::from_raw_os_error(libc::ENOENT);
            let obs = os_spawn_observations(&controls(), Some(&full_record()), Some(&err));
            assert_eq!(state_of(&obs, "os.fs"), ControlState::Verified);
            let reason = obs
                .iter()
                .find(|o| o.control == "os.fs")
                .unwrap()
                .reason
                .clone()
                .unwrap();
            assert!(reason.contains("spawn"));
        }

        #[test]
        fn missing_or_truncated_record_reads_unknown() {
            let controls = controls();
            // No shared page at all.
            let obs = os_spawn_observations(&controls, None, None);
            for id in ["os.privileges", "os.fs", "os.net.outbound", "os.syscalls"] {
                assert_eq!(state_of(&obs, id), ControlState::Unknown, "{id}");
            }
            // Page present but never written past stage 0 — the spawn
            // somehow returned anyway (child killed mid-pipeline).
            let snap = ApplySnapshot {
                stage: stage::NONE,
                ..full_record()
            };
            let obs = os_spawn_observations(&controls, Some(&snap), None);
            for id in ["os.fs", "os.net.outbound", "os.syscalls"] {
                assert_eq!(state_of(&obs, id), ControlState::Unknown, "{id}");
            }
        }

        #[test]
        fn inconsistent_record_reads_unknown() {
            // failed_stage is written only before pre_exec returns Err —
            // a success result beside it cannot be produced honestly.
            let snap = ApplySnapshot {
                failed_stage: stage::SECCOMP,
                errno: libc::EPERM,
                ..full_record()
            };
            let obs = os_spawn_observations(&controls(), Some(&snap), None);
            for id in ["os.privileges", "os.fs", "os.net.outbound", "os.syscalls"] {
                assert_eq!(state_of(&obs, id), ControlState::Unknown, "{id}");
            }

            // An honest record always has stage == failed_stage - 1: a
            // `stage` that does not sit exactly one below `failed_stage`
            // is corrupt too — even beside the expected spawn error.
            let snap = ApplySnapshot {
                stage: stage::NONE,
                landlock: landlock_level::NOT_RUN,
                failed_stage: stage::SECCOMP,
                errno: libc::EPERM,
                ..full_record()
            };
            let err = std::io::Error::from_raw_os_error(libc::EPERM);
            let obs = os_spawn_observations(&controls(), Some(&snap), Some(&err));
            for id in ["os.privileges", "os.fs", "os.net.outbound", "os.syscalls"] {
                assert_eq!(state_of(&obs, id), ControlState::Unknown, "{id}");
            }
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_allow_degraded_does_not_decide_plan_state() {
        // allow_degraded tolerates partial enforcement at apply time; it
        // must not change what the plan claims was requested — the state
        // stays Planned (with a qualifier), not PartiallyApplied.
        let mut policy = policy_with_tools();
        policy.sandbox.allow_degraded = true;
        let plan = build_plan(
            &policy,
            None,
            "child",
            &SpawnOptions::default(),
            None,
            false,
        );
        for id in ["os.fs", "os.net.outbound"] {
            let (state, reason) = control_state(&plan, id);
            assert_eq!(state, ControlState::Planned, "{id}");
            assert!(reason.contains("allow_degraded"), "{id}");
        }
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn failed_fs_grant_marks_os_fs_partially_applied() {
        let controls = os_controls(&policy_with_tools());
        let failed = ProcessGrant {
            subject: GrantSubject::FsPath {
                path: "C:\\deny".to_string(),
                access: FsAccess::Read,
            },
            origin: GrantOrigin::Policy,
            state: ControlState::Failed,
            reason: Some("ACL write denied".to_string()),
        };
        let obs = os_spawn_observations(&controls, &[failed], None);
        let get = |id: &str| obs.iter().find(|o| o.control == id).unwrap().state;
        assert_eq!(get("os.fs"), ControlState::PartiallyApplied);
        assert_eq!(get("os.process"), ControlState::Verified);

        // All fs grants applied (or none attempted) keeps the Verified result.
        let obs = os_spawn_observations(&controls, &[], None);
        assert_eq!(
            obs.iter().find(|o| o.control == "os.fs").unwrap().state,
            ControlState::Verified
        );
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn failed_runtime_fs_grant_does_not_mark_os_fs_partial() {
        // Runtime grants (private TMPDIR, executable image, ancestors) are
        // best-effort: a failure stays on the grant's own entry but does
        // not mark the policy fs control partially applied.
        let controls = os_controls(&policy_with_tools());
        let failed = ProcessGrant {
            subject: GrantSubject::FsPath {
                path: "C:\\tmp".to_string(),
                access: FsAccess::ReadWrite,
            },
            origin: GrantOrigin::Runtime,
            state: ControlState::Failed,
            reason: Some("ACL write denied".to_string()),
        };
        let obs = os_spawn_observations(&controls, &[failed], None);
        let os_fs = obs.iter().find(|o| o.control == "os.fs").unwrap();
        assert_eq!(os_fs.state, ControlState::Verified);
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn sandbox_setup_error_fails_planned_controls() {
        // A provable pre-`CreateProcessW` failure (profile, capability,
        // loopback, pipes) means nothing ever ran inside a container:
        // every still-planned control reads Failed and names the stage.
        let controls = os_controls(&policy_with_tools());
        let err = WinSpawnError {
            stage: WinStage::Grants,
            source: WardenError::sandbox_setup(
                crate::error::SandboxStage::Apply,
                "enable_loopback".to_string(),
            ),
        };
        let obs = os_spawn_observations(&controls, &[], Some(&err));
        assert!(!obs.is_empty());
        for o in &obs {
            assert_eq!(o.state, ControlState::Failed, "{}", o.control);
            assert!(
                o.reason
                    .as_deref()
                    .unwrap_or_default()
                    .contains("grant-application"),
                "{}",
                o.control
            );
        }
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn prepare_source_failure_through_spawn_outcome_assembly() {
        // `windows_spawn_outcome` is the outcome assembly
        // `spawn_child_async_impl` runs for a Windows launch: the
        // observations are produced while the controls are still
        // `Planned`, so a `Prepare`-sourced setup abort yields
        // per-control evidence (never an empty result), and only then
        // does the plan agree by failing the same controls — with the
        // pipeline stage named in the reason.
        let mut controls = os_controls(&policy_with_tools());
        let planned_ids: Vec<&'static str> = controls
            .iter()
            .filter(|c| c.layer == ControlLayer::Os && c.state == ControlState::Planned)
            .map(|c| c.id)
            .collect();
        assert!(!planned_ids.is_empty());
        let err = WinSpawnError {
            stage: WinStage::ProcessSetup,
            source: WardenError::sandbox_setup(
                crate::error::SandboxStage::Prepare,
                "CreatePipe".to_string(),
            ),
        };
        let obs = windows_spawn_outcome(&mut controls, &[], Some(&err));
        assert_eq!(obs.len(), planned_ids.len());
        for o in &obs {
            assert_eq!(o.state, ControlState::Failed, "{}", o.control);
            assert!(
                o.reason
                    .as_deref()
                    .unwrap_or_default()
                    .contains("process-setup"),
                "{}",
                o.control
            );
        }
        for c in controls
            .iter()
            .filter(|c| c.layer == ControlLayer::Os && planned_ids.contains(&c.id))
        {
            assert_eq!(c.state, ControlState::Failed, "{}", c.id);
            assert!(
                c.reason
                    .as_deref()
                    .unwrap_or_default()
                    .contains("process-setup"),
                "{}",
                c.id
            );
        }
        for c in controls
            .iter()
            .filter(|c| c.layer == ControlLayer::Os && !planned_ids.contains(&c.id))
        {
            assert_ne!(c.state, ControlState::Failed, "{}", c.id);
        }

        // A `Prepare`-sourced failure at a *post-create* stage — e.g.
        // `CreateJobObjectW` failing inside `job-assignment` — does not
        // collapse the plan: a real container process existed, so the
        // observations carry `os.process` as `Failed` while controls
        // whose apply work completed keep their mechanism outcomes.
        let mut controls = os_controls(&policy_with_tools());
        let before: Vec<(&'static str, ControlState)> = controls
            .iter()
            .filter(|c| c.layer == ControlLayer::Os)
            .map(|c| (c.id, c.state))
            .collect();
        let err = WinSpawnError {
            stage: WinStage::Job,
            source: WardenError::sandbox_setup(
                crate::error::SandboxStage::Prepare,
                "CreateJobObjectW".to_string(),
            ),
        };
        let obs = windows_spawn_outcome(&mut controls, &[], Some(&err));
        for (id, state) in before {
            let c = controls.iter().find(|c| c.id == id).unwrap();
            assert_eq!(
                c.state, state,
                "post-create failure must not change plan state: {id}"
            );
        }
        let get = |id: &str| obs.iter().find(|o| o.control == id).unwrap();
        assert_eq!(get("os.process").state, ControlState::Failed);
        assert_eq!(get("os.fs").state, ControlState::Verified);
        assert!(
            get("os.fs")
                .reason
                .as_deref()
                .unwrap_or_default()
                .contains("job-assignment"),
            "applied controls must name the abort stage"
        );
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn process_spawn_error_leaves_controls_unknown() {
        // CreateProcessW fuses the attribute and image checks — the
        // failing stage is undetermined, so the controls read Unknown
        // (SpawnResult), not Failed.
        let controls = os_controls(&policy_with_tools());
        let err = WinSpawnError {
            stage: WinStage::CreateProcess,
            source: WardenError::ProcessSpawn(std::io::Error::from_raw_os_error(2)),
        };
        let obs = os_spawn_observations(&controls, &[], Some(&err));
        assert!(!obs.is_empty());
        for o in &obs {
            assert_eq!(o.state, ControlState::Unknown, "{}", o.control);
            assert_eq!(o.basis, ObservationBasis::SpawnResult, "{}", o.control);
        }
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn post_create_abort_fails_os_process_but_keeps_apply_outcomes() {
        // A Job/execution-start failure ran against a real suspended
        // container process: os.process reads Failed while controls
        // whose apply work provably completed keep their mechanism
        // outcomes — with the abort named in the reason.
        let controls = os_controls(&policy_with_tools());
        let err = WinSpawnError {
            stage: WinStage::Job,
            source: WardenError::sandbox_setup(
                crate::error::SandboxStage::Apply,
                "AssignProcessToJobObject".to_string(),
            ),
        };
        let obs = os_spawn_observations(&controls, &[], Some(&err));
        let get = |id: &str| obs.iter().find(|o| o.control == id).unwrap();
        assert_eq!(get("os.process").state, ControlState::Failed);
        assert!(
            get("os.process")
                .reason
                .as_deref()
                .unwrap_or_default()
                .contains("job-assignment")
        );
        let fs = get("os.fs");
        assert_eq!(fs.state, ControlState::Verified);
        assert!(
            fs.reason
                .as_deref()
                .unwrap_or_default()
                .contains("job-assignment")
        );
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn loopback_observation_reflects_exemption_outcome() {
        // HTTP transport plans the loopback exemption as its own control;
        // the observation mirrors the recorded grant result.
        let policy = {
            let mut p = policy_with_tools();
            p.transport.type_ = TransportType::Http;
            p
        };
        let controls = os_controls(&policy);
        assert!(
            controls
                .iter()
                .any(|c| c.id == "os.net.loopback" && c.state == ControlState::Planned)
        );

        let grant = |state: ControlState| ProcessGrant {
            subject: GrantSubject::Rule {
                kind: "loopback_exemption",
                name: "localhost".to_string(),
            },
            origin: GrantOrigin::Runtime,
            state,
            reason: None,
        };
        let find = |grants: &[ProcessGrant]| {
            os_spawn_observations(&controls, grants, None)
                .into_iter()
                .find(|o| o.control == "os.net.loopback")
                .unwrap()
        };
        assert_eq!(
            find(&[grant(ControlState::Verified)]).state,
            ControlState::Verified
        );
        assert_eq!(
            find(&[grant(ControlState::Unknown)]).state,
            ControlState::Unknown
        );

        // Non-HTTP policy leaves the control NotApplicable — no
        // observation is emitted for it.
        let controls = os_controls(&policy_with_tools());
        let obs = os_spawn_observations(&controls, &[], None);
        assert!(obs.iter().all(|o| o.control != "os.net.loopback"));
    }

    #[test]
    fn sandbox_skip_marks_os_controls_and_grants_nothing() {
        let policy = policy_with_tools();
        let sandboxed = build_plan(
            &policy,
            None,
            "child",
            &SpawnOptions::default(),
            None,
            false,
        );
        let plan = build_plan(
            &policy,
            None,
            "child",
            &SpawnOptions::default(),
            Some("dry-run"),
            true,
        );
        // Every OS control that was Planned in the sandboxed plan is
        // Skipped here; build-time states (NotApplicable / NotApplied)
        // survive — they would not have applied anyway.
        for normal in sandboxed
            .controls
            .iter()
            .filter(|c| c.layer == ControlLayer::Os)
        {
            let skipped = plan.controls.iter().find(|c| c.id == normal.id).unwrap();
            match normal.state {
                ControlState::Planned => assert_eq!(
                    skipped.state,
                    ControlState::Skipped,
                    "{} should be skipped",
                    normal.id
                ),
                other => assert_eq!(skipped.state, other, "{} should keep its state", normal.id),
            }
        }
        assert!(plan.grants.is_empty());
        // RPC-layer enforcement is not part of the OS sandbox and stays
        // planned, carrying the dry-run qualifier.
        assert_eq!(control_state(&plan, "rpc.tools").0, ControlState::Planned);
        assert!(control_state(&plan, "rpc.tools").1.contains("dry-run"));
    }

    // -- macOS spawn-fact → observation mapping ------------------------
    // sandbox-exec exposes no kernel-acceptance query: the domain
    // controls must stay Unknown, while the launch itself (`os.sandbox`)
    // records the facts the mechanism does produce.

    #[cfg(target_os = "macos")]
    mod macos_observations {
        use super::*;
        use crate::warden::macos_sandbox::SpawnLiveness;
        use std::os::unix::process::ExitStatusExt;

        fn controls() -> Vec<PlannedControl> {
            os_controls(&policy_with_tools())
        }

        fn state_of(obs: &[EnforcementObservation], id: &str) -> ControlState {
            obs.iter().find(|o| o.control == id).unwrap().state
        }

        fn exited() -> SpawnLiveness {
            SpawnLiveness::Exited(std::process::ExitStatus::from_raw(3 << 8))
        }

        #[test]
        fn os_sandbox_is_a_planned_sandbox_exec_control() {
            let c = controls()
                .into_iter()
                .find(|c| c.id == "os.sandbox")
                .expect("os.sandbox control must exist");
            assert_eq!(c.state, ControlState::Planned);
            assert_eq!(c.mechanism, "sandbox-exec");
        }

        #[test]
        fn surviving_child_verifies_the_launch_only() {
            let obs = os_spawn_observations(&controls(), None, Some(&SpawnLiveness::Running));
            let launch = obs.iter().find(|o| o.control == "os.sandbox").unwrap();
            assert_eq!(launch.state, ControlState::Verified);
            assert_eq!(launch.basis, ObservationBasis::SpawnResult);
            // A live process is not kernel acceptance: every SBPL domain
            // stays Unknown rather than being upgraded on inference.
            for id in ["os.fs", "os.net.outbound", "os.process"] {
                assert_eq!(state_of(&obs, id), ControlState::Unknown, "{id}");
            }
            let fs = obs.iter().find(|o| o.control == "os.fs").unwrap();
            assert!(fs.reason.as_deref().unwrap().contains("not observable"));
        }

        #[test]
        fn spawn_error_fails_every_planned_control() {
            // A spawn() error means sandbox-exec never ran — nothing was
            // applied, so the controls read Failed, not Unknown.
            let err = std::io::Error::from_raw_os_error(libc::ENOENT);
            let obs = os_spawn_observations(&controls(), Some(&err), None);
            for id in ["os.sandbox", "os.fs", "os.net.outbound", "os.process"] {
                assert_eq!(state_of(&obs, id), ControlState::Failed, "{id}");
            }
        }

        #[test]
        fn early_exit_leaves_launch_and_rules_unknown() {
            // The process died inside the window: the exit status is the
            // child's recorded termination state, but a short-lived
            // workload ends the same way — the exit alone is not evidence
            // the kernel rejected the profile, so the launch stays
            // Unknown (basis SpawnResult) and the domains stay Unknown.
            let obs = os_spawn_observations(&controls(), None, Some(&exited()));
            let launch = obs.iter().find(|o| o.control == "os.sandbox").unwrap();
            assert_eq!(launch.state, ControlState::Unknown);
            assert_eq!(launch.basis, ObservationBasis::SpawnResult);
            assert!(launch.reason.as_deref().unwrap().contains("exit status: 3"));
            for id in ["os.fs", "os.net.outbound", "os.process"] {
                assert_eq!(state_of(&obs, id), ControlState::Unknown, "{id}");
                let reason = obs
                    .iter()
                    .find(|o| o.control == id)
                    .unwrap()
                    .reason
                    .clone()
                    .unwrap();
                assert!(reason.contains("exited"), "{id}: {reason}");
            }
        }

        #[test]
        fn failed_liveness_probe_stays_unknown() {
            let obs = os_spawn_observations(&controls(), None, Some(&SpawnLiveness::PollFailed));
            assert_eq!(state_of(&obs, "os.sandbox"), ControlState::Unknown);
            assert_eq!(state_of(&obs, "os.fs"), ControlState::Unknown);
        }

        #[test]
        fn build_observation_covers_generation_not_acceptance() {
            let ok = macos_prepare_observation(None);
            assert_eq!(ok.control, "os.sandbox");
            assert_eq!(ok.state, ControlState::Verified);
            assert_eq!(ok.phase, ControlPhase::Build);
            assert_eq!(ok.basis, ObservationBasis::VerificationRun);

            let err =
                WardenError::sandbox_setup(crate::error::SandboxStage::Policy, "boom".to_string());
            let bad = macos_prepare_observation(Some(("profile build failed", &err)));
            assert_eq!(bad.state, ControlState::Failed);
            assert_eq!(bad.phase, ControlPhase::Build);
            assert!(
                bad.reason
                    .as_deref()
                    .unwrap()
                    .contains("profile build failed")
            );
        }
    }
}
