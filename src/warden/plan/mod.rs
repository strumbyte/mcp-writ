//! Enforcement-plan assembly — the `Policy` → leaf-model conversion the
//! module guide assigns to `warden`.
//!
//! The plan is generated from the *same normalized data* the sandbox
//! builders consume: on Linux the grants come out of
//! `prepare_linux_child_sandbox` itself; on macOS from the SBPL emitter;
//! on Windows from the shared grant intents. The plan never recomputes a
//! parallel permission table.
//!
//! The per-OS control lists and spawn observations live in sibling
//! modules (`linux`, `macos`, `windows`, `fallback`); this file keeps the
//! shared controls, the plan assembly, and the report types.

use std::path::Path;

use crate::enforcement::{
    ControlLayer, ControlPhase, ControlState, EnforcementObservation, EnforcementPlan,
    ObservationBasis, PlannedControl, ToolDisposition,
};
use crate::error::WardenError;
use crate::execution::WindowsNativeMechanism;
use crate::policy::Policy;

use super::SpawnOptions;
use super::child::RunningChild;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "windows")]
mod windows;
#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
mod fallback;
#[cfg(test)]
mod tests;

#[cfg(target_os = "linux")]
pub(super) use linux::{os_controls, os_limitations, os_plan_grants, os_spawn_observations};
#[cfg(target_os = "macos")]
pub(super) use macos::{
    macos_prepare_observation, os_controls, os_limitations, os_plan_grants,
    os_spawn_observations,
};
#[cfg(target_os = "windows")]
pub(super) use windows::{
    os_controls, os_limitations, os_plan_grants, windows_spawn_outcome,
};
// No non-test caller on Windows — the spawn path consumes
// `windows_spawn_outcome`; the unit tests exercise the per-control
// mapping directly.
#[cfg(all(target_os = "windows", test))]
pub(super) use windows::os_spawn_observations;
#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
pub(super) use fallback::{os_controls, os_limitations, os_plan_grants, os_spawn_observations};
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
///
/// `psec_env` is true when the child will run under a PSEC security
/// environment: its environment is mechanism-managed — no parent
/// variable propagates and no `SpawnOptions` block reaches
/// `lpEnvironment`. `environment.allowed` names and a `tmpdir`
/// override are undeliverable there — the launch refuses — so the
/// control reads `NotApplied`; a bare restriction is satisfied by
/// construction and stays `Planned`.
pub(super) fn shared_controls(
    policy: &Policy,
    opts: &SpawnOptions,
    dry_run: bool,
    private_tmpdir: bool,
    psec_env: bool,
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
    let (env_state, env_reason) = if psec_env {
        if !opts.allowed_names.is_empty() || opts.tmpdir.is_some() {
            (
                ControlState::NotApplied,
                "a PSEC child's environment is mechanism-managed — named \
                 variables and a TMPDIR override cannot be delivered; the \
                 launch refuses rather than silently dropping them"
                    .to_string(),
            )
        } else if opts.restrict_environment {
            (
                ControlState::Planned,
                "the child receives a mechanism-managed environment — no \
                 parent variable propagates, so the restriction holds by \
                 construction"
                    .to_string(),
            )
        } else {
            (
                ControlState::NotApplicable,
                "a PSEC child's environment is mechanism-managed — the \
                 parent's is not inherited (the measured contract, not a \
                 choice this launch made)"
                    .to_string(),
            )
        }
    } else {
        match (opts.restrict_environment, tmpdir_overridden) {
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
        }
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
/// enumerated, and a deny never surfaces as an access grant.
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
         RPC-layer argument checks; where a mechanism encodes a deny \
         explicitly (PSEC fs_deny) it appears as a `*_deny` rule record, \
         never as an access grant."
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
    mechanism: WindowsNativeMechanism,
) -> EnforcementPlan {
    // Only a sandboxed macOS spawn creates a private TMPDIR; a skipped
    // sandbox keeps the parent's TMPDIR.
    let private_tmpdir = cfg!(target_os = "macos") && sandbox_skip.is_none();
    let psec_env = cfg!(target_os = "windows") && mechanism == WindowsNativeMechanism::Psec;
    let mut controls = shared_controls(policy, opts, dry_run, private_tmpdir, psec_env);
    let tools = tools_table(policy);
    let mut limitations = base_limitations();
    let grants;
    match sandbox_skip {
        Some(reason) => {
            let mut os = os_controls(policy, mechanism);
            mark_skipped(&mut os, reason);
            controls.extend(os);
            grants = Vec::new();
        }
        None => {
            let mut os = os_controls(policy, mechanism);
            grants = os_plan_grants(policy, program, command, opts, &mut os, mechanism);
            controls.extend(os);
            os_limitations(policy, &mut limitations, mechanism);
        }
    }
    EnforcementPlan {
        controls,
        grants,
        tools,
        limitations,
    }
}
