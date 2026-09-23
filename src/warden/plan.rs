//! Enforcement-plan assembly — the `Policy` → leaf-model conversion the
//! module guide assigns to `warden`.
//!
//! The plan is generated from the *same normalized data* the sandbox
//! builders consume: on Linux the grants come out of
//! `prepare_linux_child_sandbox` itself; on macOS from the SBPL emitter;
//! on Windows from the shared grant intents. The plan never recomputes a
//! parallel permission table.

use std::path::Path;

#[cfg(target_os = "windows")]
use crate::enforcement::GrantSubject;
use crate::enforcement::{
    ControlLayer, ControlPhase, ControlState, EnforcementObservation, EnforcementPlan,
    ObservationBasis, PlannedControl, ProcessGrant, ToolDisposition,
};
use crate::policy::Policy;

use super::SpawnOptions;
use super::child::RunningChild;
#[cfg(target_os = "linux")]
use super::linux_spawn;
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
    // written only on the `pre_exec` error path. A success alongside it,
    // or a `stage` that claims the failed stage completed, is corrupt —
    // report Unknown, never applied.
    let record_inconsistent = snap.failed_stage != linux_spawn::stage::NONE
        && (spawn_err.is_none() || snap.stage >= snap.failed_stage);
    if record_inconsistent {
        return observation(
            c.id,
            ControlState::Unknown,
            ObservationBasis::MechanismResult,
            ControlPhase::Spawn,
            Some("apply record is inconsistent (a failed stage is marked complete)".to_string()),
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

/// `sandbox-exec` does not expose whether the kernel accepted the
/// profile: on a successful spawn the OS controls stay `Unknown` rather
/// than claimed applied.
#[cfg(target_os = "macos")]
pub(super) fn os_spawn_observations(
    controls: &[PlannedControl],
    spawn_err: Option<&std::io::Error>,
) -> Vec<EnforcementObservation> {
    controls
        .iter()
        .filter(|c| c.layer == ControlLayer::Os && c.state == ControlState::Planned)
        .map(|c| match spawn_err {
            Some(e) => observation(
                c.id,
                ControlState::Unknown,
                ObservationBasis::SpawnResult,
                ControlPhase::Spawn,
                Some(format!("sandbox-exec spawn failed: {e}")),
            ),
            None => observation(
                c.id,
                ControlState::Unknown,
                ObservationBasis::SpawnResult,
                ControlPhase::Spawn,
                Some(
                    "sandbox-exec spawned; whether the kernel accepted the \
                     profile is not observable"
                        .to_string(),
                ),
            ),
        })
        .collect()
}

#[cfg(target_os = "windows")]
pub(super) fn os_controls(policy: &Policy) -> Vec<PlannedControl> {
    let lpac = std::env::var_os("MCP_WRIT_WINDOWS_LPAC").is_some();
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

/// The Windows pipeline applies controls in the parent and `CreateProcessW`
/// is authoritative: a spawned child was created inside the AppContainer
/// token. Successful spawn ⇒ `Verified` (mechanism result, not guesswork).
/// `os.fs` additionally reflects the ACL grant outcomes: a failed `FsPath`
/// grant means the explicit allow was not written and effective access is
/// unverified, so the control is `PartiallyApplied`.
#[cfg(target_os = "windows")]
pub(super) fn os_spawn_observations(
    controls: &[PlannedControl],
    grants: &[ProcessGrant],
    spawn_err: Option<&WardenError>,
) -> Vec<EnforcementObservation> {
    let failed_fs_grants = grants
        .iter()
        .filter(|g| matches!(g.subject, GrantSubject::FsPath { .. }))
        .filter(|g| g.state == ControlState::Failed)
        .count();
    controls
        .iter()
        .filter(|c| c.layer == ControlLayer::Os && c.state == ControlState::Planned)
        .map(|c| match spawn_err {
            Some(e) => observation(
                c.id,
                ControlState::Failed,
                ObservationBasis::MechanismResult,
                ControlPhase::Spawn,
                Some(format!("sandbox pipeline failed: {e}")),
            ),
            None if c.id == "os.fs" && failed_fs_grants > 0 => observation(
                c.id,
                ControlState::PartiallyApplied,
                ObservationBasis::MechanismResult,
                ControlPhase::Spawn,
                Some(format!(
                    "{failed_fs_grants} filesystem ACL grant(s) failed; \
                     effective access is unverified"
                )),
            ),
            None => observation(
                c.id,
                ControlState::Verified,
                ObservationBasis::MechanismResult,
                ControlPhase::Spawn,
                Some(
                    "child created inside the AppContainer (CreateProcessW is \
                     authoritative)"
                        .to_string(),
                ),
            ),
        })
        .collect()
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
         profile; OS controls are reported as unobserved after spawn."
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
}
