//! macOS controls and spawn observations — `sandbox-exec` exposes no
//! kernel-acceptance query, so the per-domain controls stay `Unknown`
//! while the launch control records the facts the mechanism produces.

use std::path::Path;

use crate::enforcement::{
    ControlLayer, ControlPhase, ControlState, EgressLayerStatus, EnforcementObservation,
    ObservationBasis, PlannedControl, ProcessGrant,
};
use crate::error::WardenError;
use crate::execution::WindowsNativeMechanism;
use crate::policy::Policy;

use super::super::SpawnOptions;
use super::super::macos_sandbox::SpawnLiveness;
use super::{control, fail_os_controls, observation, planned};

pub(crate) fn os_controls(
    policy: &Policy,
    _mechanism: WindowsNativeMechanism,
) -> Vec<PlannedControl> {
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
pub(crate) fn macos_prepare_observation(
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
pub(crate) fn os_spawn_observations(
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

pub(crate) fn os_plan_grants(
    policy: &Policy,
    _program: Option<&Path>,
    _command: &str,
    opts: &SpawnOptions,
    controls: &mut [PlannedControl],
    _mechanism: WindowsNativeMechanism,
) -> Vec<ProcessGrant> {
    // A private TMPDIR is always created at spawn; use the caller's
    // override when present, else the real temp dir so ancestor
    // traversal grants resolve against the launch-time location.
    let tmp = opts
        .tmpdir
        .clone()
        .unwrap_or_else(|| std::env::temp_dir().join("mcp-writ-sbx-<launch>"));
    match super::super::macos_sandbox::sbpl_profile(policy, &tmp.to_string_lossy()) {
        Ok((_text, grants)) => grants,
        Err(e) => {
            fail_os_controls(controls, "profile build failed", &e);
            Vec::new()
        }
    }
}

pub(crate) fn os_limitations(
    _policy: &Policy,
    out: &mut Vec<String>,
    _mechanism: WindowsNativeMechanism,
) {
    out.push(
        "sandbox-exec does not expose whether the kernel accepted the SBPL \
         profile; the report records profile generation, the spawn result, \
         and a bounded initial-exit check — the per-domain OS controls stay \
         unobserved."
            .to_string(),
    );
}

/// Per-layer egress disposition under sandbox-exec: the SBPL profile
/// can only express `localhost:port` remote-TCP rules, so neither
/// destination layer is expressible — both stay at the RPC/Auditor
/// surface.
pub(crate) fn os_egress_layer_status(
    _mechanism: WindowsNativeMechanism,
) -> (EgressLayerStatus, EgressLayerStatus) {
    (
        EgressLayerStatus {
            layer: "name",
            rpc: "auditor",
            os: None,
            note: Some(
                "the SBPL profile can only express localhost TCP destinations — \
                 host rules are enforced by the Auditor's argument checks only; \
                 the `dns-gate` component can apply the same name rules to a \
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
                "the SBPL profile cannot express a destination CIDR — cidr rules \
                 and literal-IP host rules are enforced by the Auditor's \
                 argument checks only"
                    .to_string(),
            ),
        },
    )
}
