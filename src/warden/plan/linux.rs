//! Linux controls and apply observations — the Landlock/seccomp
//! pipeline reports through the apply record the pre-exec child
//! writes ([`linux_spawn::ApplySnapshot`]).

use std::path::Path;

use crate::enforcement::{
    ControlLayer, ControlPhase, ControlState, EgressLayerStatus, EnforcementObservation,
    LANDLOCK_FULLY_ENFORCED, LANDLOCK_NOT_ENFORCED, LANDLOCK_PARTIALLY_ENFORCED, ObservationBasis,
    PlannedControl, ProcessGrant, RESTRICT_SELF_REPORTED,
};
use crate::execution::WindowsNativeMechanism;
use crate::policy::Policy;

use super::super::SpawnOptions;
use super::super::linux_spawn;
use super::{control, fail_os_controls, observation, planned};

pub(crate) fn os_controls(
    policy: &Policy,
    _mechanism: WindowsNativeMechanism,
) -> Vec<PlannedControl> {
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
            if policy.sandbox.allow_degraded
                && !super::super::seccomp_impl::policy_allows_execve(policy)
            {
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
pub(crate) fn os_spawn_observations(
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
fn linux_control_stage(id: &str) -> Option<u8> {
    use super::super::linux_spawn::stage;
    match id {
        "os.privileges" => Some(stage::NO_NEW_PRIVS),
        "os.fs" | "os.net.outbound" => Some(stage::LANDLOCK),
        "os.syscalls" => Some(stage::SECCOMP),
        _ => None,
    }
}

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
fn linux_stage_failure_reason(snap: &linux_spawn::ApplySnapshot) -> String {
    use super::super::linux_spawn::{landlock_level, stage};
    let base = match snap.failed_stage {
        stage::NO_NEW_PRIVS => "no_new_privs prctl failed in the child",
        stage::LANDLOCK => "Landlock apply stage failed in the child",
        stage::UNOTIFY => {
            "seccomp user-notification setup failed in the child \
             (filter install or listener-fd handoff)"
        }
        stage::CGROUP => {
            "cgroup join failed in the child (cgroup.procs write for the \
             private cgroup)"
        }
        stage::SECCOMP => "seccomp apply failed in the child",
        _ => "an apply stage failed in the child",
    };
    let mut reason = format!("{base} (os error {})", snap.errno);
    if snap.failed_stage == stage::LANDLOCK {
        match snap.landlock {
            landlock_level::PARTIAL => reason.push_str(&format!(
                "; {RESTRICT_SELF_REPORTED}{LANDLOCK_PARTIALLY_ENFORCED} and \
                 sandbox.allow_degraded is off"
            )),
            landlock_level::NOT_ENFORCED => reason.push_str(&format!(
                "; {RESTRICT_SELF_REPORTED}{LANDLOCK_NOT_ENFORCED} and \
                 sandbox.allow_degraded is off"
            )),
            _ => {}
        }
    }
    reason
}

/// Observation for a control whose stage the record marks complete.
/// For Landlock-backed controls this maps the kernel-reported
/// enforcement level; `os.net.outbound` additionally splits on the
/// kernel ABI — Landlock network rules exist only since ABI v4.
fn linux_stage_outcome(id: &str, snap: &linux_spawn::ApplySnapshot) -> (ControlState, String) {
    use super::super::linux_spawn::landlock_level;
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
                    format!("{RESTRICT_SELF_REPORTED}{LANDLOCK_FULLY_ENFORCED}{abi}"),
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
                                "{RESTRICT_SELF_REPORTED}{LANDLOCK_PARTIALLY_ENFORCED}{abi}; \
                                 tolerated by sandbox.allow_degraded — which rules were \
                                 dropped is not decomposed per control"
                            ),
                        )
                    }
                }
                landlock_level::NOT_ENFORCED => (
                    ControlState::NotApplied,
                    format!(
                        "{RESTRICT_SELF_REPORTED}{LANDLOCK_NOT_ENFORCED}{abi}; tolerated by \
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

/// Plan-mode grants for the sandboxed case: runs the same rule builders
/// as the spawn path (their artifacts are discarded — nothing is applied)
/// and marks OS controls `Failed` when the build itself fails.
pub(crate) fn os_plan_grants(
    policy: &Policy,
    _program: Option<&Path>,
    _command: &str,
    _opts: &SpawnOptions,
    controls: &mut [PlannedControl],
    _mechanism: WindowsNativeMechanism,
) -> Vec<ProcessGrant> {
    match super::super::linux_spawn::prepare_linux_child_sandbox(policy) {
        Ok(bits) => bits.grants,
        Err(e) => {
            fail_os_controls(controls, "rule build failed", &e);
            Vec::new()
        }
    }
}

pub(crate) fn os_limitations(
    policy: &Policy,
    out: &mut Vec<String>,
    _mechanism: WindowsNativeMechanism,
) {
    if policy.sandbox.allow_degraded {
        out.push(
            "sandbox.allow_degraded=#true: partial or absent Landlock enforcement \
             is tolerated instead of aborting the launch; the kernel-reported \
             level is collected from the child and shown per control."
                .to_string(),
        );
    }
}

/// Per-layer egress disposition under Landlock: neither destination
/// layer is expressible — Landlock network rules bind a TCP port, not
/// a destination — so both layers stay at the RPC/Auditor surface.
pub(crate) fn os_egress_layer_status(
    _mechanism: WindowsNativeMechanism,
) -> (EgressLayerStatus, EgressLayerStatus) {
    (
        EgressLayerStatus {
            layer: "name",
            rpc: "auditor",
            os: None,
            note: Some(
                "Landlock network rules bind a TCP port, not a destination — host \
                 rules are enforced by the Auditor's argument checks only; the \
                 `dns-gate` component can apply the same name rules to a \
                 workload that resolves through it, but it is not wired into \
                 this path"
                    .to_string(),
            ),
        },
        EgressLayerStatus {
            layer: "ip",
            rpc: "auditor",
            os: None,
            note: Some(
                "Landlock cannot express a destination CIDR — cidr rules and \
                 literal-IP host rules are enforced by the Auditor's argument \
                 checks only on this path; the opt-in `unotify-run` PoC \
                 supervises connect(2) destinations through seccomp user \
                 notification, and the opt-in `ebpf-run` route enforces them \
                 in-kernel through cgroup eBPF (needs privileges)"
                    .to_string(),
            ),
        },
    )
}
