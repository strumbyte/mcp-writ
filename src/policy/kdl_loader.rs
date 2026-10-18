use std::collections::HashSet;
use std::path::Path;

use super::Policy;
use crate::error::PolicyError;
use crate::execution::ExecutionTarget;

pub use super::kdl_parse::{parse_kdl_policy, parse_kdl_policy_with_profiles};
pub use super::provenance::LoadDiagnostics;

/// Emit the load's warnings and apply `MCP_WRIT_REPLACE_MODE` and
/// `MCP_WRIT_REVIEW_MODE` — the enforce-side half of a scanned load.
fn enforce_load_diagnostics(diag: &LoadDiagnostics) -> Result<(), PolicyError> {
    diag.emit_warnings();
    super::provenance::ReplaceMode::from_env().enforce(diag)?;
    super::review::ReviewMode::from_env().enforce(&diag.review_markers)?;
    Ok(())
}

/// Load a KDL policy file from disk, process extends/include/when directives,
/// and validate for the OS this process runs on.
///
/// This is the native-compatibility entry point: it validates against the OS
/// this process runs on. The in-guest runner goes through
/// [`super::loader::load_policy_for_target`] with `ExecutionTarget::native()`,
/// which lands here — so a host-supplied target name can never stand in for
/// guest-side checking. Use [`load_kdl_policy_for_target`] when the workload
/// runs under another OS.
pub fn load_kdl_policy(path: &Path) -> Result<Policy, PolicyError> {
    let env = std::env::var("MCP_WRIT_ENV").unwrap_or_default();
    load_kdl_policy_for_target(path, &env, &ExecutionTarget::native())
}

/// Load a KDL policy file with an explicit environment value for `when` evaluation.
/// This avoids reading MCP_WRIT_ENV from the process environment, making it
/// safe for concurrent test execution. Validates for the host OS.
pub fn load_kdl_policy_with_env(path: &Path, env: &str) -> Result<Policy, PolicyError> {
    load_kdl_policy_for_target(path, env, &ExecutionTarget::native())
}

/// Load a KDL policy file, process extends/include/when directives, and
/// validate against an explicit execution target.
///
/// Inheritance and `when` resolution are target-independent; validation
/// runs once on the fully merged policy, so inherited constraints are
/// checked under `target.workload_os` — never the build host's OS unless
/// the target says so. Load warnings print before the mode gates run,
/// so a refused load still shows what was refused.
pub fn load_kdl_policy_for_target(
    path: &Path,
    env: &str,
    target: &ExecutionTarget,
) -> Result<Policy, PolicyError> {
    let (policy, diag) = load_kdl_policy_for_target_scanned(path, env, target)?;
    enforce_load_diagnostics(&diag)?;
    Ok(policy)
}

/// Same load as [`load_kdl_policy_for_target`], but returns the
/// [`LoadDiagnostics`] — `// REVIEW` markers, schema laxity warnings,
/// replacement/posture warnings — instead of printing them or enforcing
/// `MCP_WRIT_REPLACE_MODE`/`MCP_WRIT_REVIEW_MODE`. `check` reports them
/// in-band; callers that only need the policy use the enforcing variant.
pub fn load_kdl_policy_for_target_scanned(
    path: &Path,
    env: &str,
    target: &ExecutionTarget,
) -> Result<(Policy, LoadDiagnostics), PolicyError> {
    let mut visited = HashSet::new();
    let (policy, diagnostics) =
        super::kdl_inherit::load_kdl_policy_internal(path, &mut visited, env)?;
    super::validator::validate_policy_for_target(&policy, target)?;
    Ok((policy, diagnostics))
}

/// Load a KDL policy for a policy-evaluating component that is not the
/// workload's OS sandbox — the `dns-gate` resolver.
///
/// Inheritance and `when` resolution run identically to a launch load;
/// only the workload-side enforceability checks differ. The gate never
/// launches a workload: it is itself the name-layer enforcement the
/// AppContainer/PSEC checks say the OS lacks, and the fs/syscall layers
/// it does not touch are re-validated by whichever launch actually
/// enforces them. Refusing a name-ruled policy at the gate would deny
/// the broker the error message itself prescribes.
pub fn load_kdl_policy_for_resolver(path: &Path, env: &str) -> Result<Policy, PolicyError> {
    let mut visited = HashSet::new();
    let (policy, diagnostics) =
        super::kdl_inherit::load_kdl_policy_internal(path, &mut visited, env)?;
    super::validator::validate_policy_document(&policy)?;
    enforce_load_diagnostics(&diagnostics)?;
    Ok(policy)
}

#[cfg(test)]
mod tests;
