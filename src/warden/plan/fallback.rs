//! Fallback controls for platforms without an OS sandbox.

use std::path::Path;

use crate::enforcement::{
    ControlLayer, ControlState, EnforcementObservation, PlannedControl, ProcessGrant,
};
use crate::execution::WindowsNativeMechanism;
use crate::policy::Policy;

use super::super::SpawnOptions;
use super::control;

/// Fallback control list for platforms without an OS sandbox.
pub(crate) fn os_controls(
    _policy: &Policy,
    _mechanism: WindowsNativeMechanism,
) -> Vec<PlannedControl> {
    vec![control(
        "os.sandbox",
        ControlLayer::Os,
        "none",
        ControlState::NotApplied,
        Some("no OS sandbox mechanism exists on this platform".to_string()),
    )]
}

pub(crate) fn os_spawn_observations(_controls: &[PlannedControl]) -> Vec<EnforcementObservation> {
    Vec::new()
}

pub(crate) fn os_plan_grants(
    _policy: &Policy,
    _program: Option<&Path>,
    _command: &str,
    _opts: &SpawnOptions,
    _controls: &mut [PlannedControl],
    _mechanism: WindowsNativeMechanism,
) -> Vec<ProcessGrant> {
    Vec::new()
}

pub(crate) fn os_limitations(
    _policy: &Policy,
    out: &mut Vec<String>,
    _mechanism: WindowsNativeMechanism,
) {
    out.push("no OS sandbox mechanism exists on this platform.".to_string());
}
