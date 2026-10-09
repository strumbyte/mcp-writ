use std::collections::HashSet;
use std::path::Path;

use super::Policy;
use crate::error::PolicyError;
use crate::execution::ExecutionTarget;

pub use super::kdl_parse::{parse_kdl_policy, parse_kdl_policy_with_profiles};

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
/// the target says so.
pub fn load_kdl_policy_for_target(
    path: &Path,
    env: &str,
    target: &ExecutionTarget,
) -> Result<Policy, PolicyError> {
    let mut visited = HashSet::new();
    let policy = super::kdl_inherit::load_kdl_policy_internal(path, &mut visited, env)?;
    super::validator::validate_policy_for_target(&policy, target)?;
    Ok(policy)
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
    let policy = super::kdl_inherit::load_kdl_policy_internal(path, &mut visited, env)?;
    super::validator::validate_policy_document(&policy)?;
    Ok(policy)
}

#[cfg(test)]
mod tests;
