use std::collections::HashSet;

use super::{MAX_SUPPORTED_VERSION, MIN_SUPPORTED_VERSION, Policy, TransportType};
use crate::error::PolicyError;
use crate::execution::{ExecutionTarget, TargetOs};

mod paths;
mod psec;

pub(crate) use paths::is_strict_subpath_or_descendant_for;
pub use paths::{is_strict_subpath_or_descendant, normalize_fs_pattern};
#[cfg(any(target_os = "windows", test))]
pub(crate) use psec::{psec_fs_path_expressible, psec_ipv4_expressible};
use psec::{validate_psec_expressibility, validate_target_network_enforcement};

/// Run all policy validations for the OS this process runs on.
///
/// Compatibility wrapper for native launches and the in-guest runner, where
/// the workload target is the process's own OS. Callers that know the
/// workload runs elsewhere (e.g. a container guest on another OS) must use
/// [`validate_policy_for_target`] instead.
pub fn validate_policy(policy: &Policy) -> Result<(), PolicyError> {
    validate_policy_for_target(policy, &ExecutionTarget::native())
}

/// Run all policy validations against an explicit execution target.
///
/// General consistency checks (version, duplicates, shape contracts, …) are
/// target-independent; checks about what the target OS can represent or
/// enforce — path separators, drive notation, case sensitivity, and
/// OS-specific enforcement limits — decide against `target.workload_os`,
/// never against the build host.
pub fn validate_policy_for_target(
    policy: &Policy,
    target: &ExecutionTarget,
) -> Result<(), PolicyError> {
    let target_os = target.workload_os;
    validate_version(policy)?;
    validate_mcp_rules(policy)?;
    validate_required_fields(policy)?;
    validate_duplicate_tools(policy)?;
    validate_paths(policy)?;
    validate_subpath_denials(policy, target_os)?;
    validate_hash_entries(policy)?;
    validate_target_network_enforcement(policy, target)?;
    validate_psec_expressibility(policy, target)?;
    validate_per_tool_syscalls(policy)?;
    validate_per_tool_environment(policy)?;
    validate_environment_names(policy)?;
    validate_hash_workload_identity(policy)?;
    validate_side_effect_consistency(policy)?;
    validate_trajectory_requires_side_effect(policy)?;
    validate_deputy_contracts(policy)?;
    Ok(())
}

/// A `deputy` block requires `confused_deputy_protection` — with the
/// feature off, the declared role/extraction rules would be silently
/// inert, which is the "configuration lost" failure mode the contract
/// forbids. It also requires schema v2 (an older parser has no closed
/// tool shape to reject it with). `DeputyPolicy::validate` re-applies the
/// structural role/rule checks so policies built without parsing hit the
/// same contract.
fn validate_deputy_contracts(policy: &Policy) -> Result<(), PolicyError> {
    for tool in &policy.tools {
        let Some(ref dep) = tool.deputy else {
            continue;
        };
        if policy.version < 2 {
            return Err(PolicyError::Validation(format!(
                "'deputy' on tool '{}' requires 'policy version=2'",
                tool.name
            )));
        }
        if !policy.confused_deputy_protection {
            return Err(PolicyError::Validation(format!(
                "tool '{}' declares 'deputy' but 'confused_deputy_protection' is not enabled",
                tool.name
            )));
        }
        dep.validate()
            .map_err(|e| PolicyError::Validation(format!("tool '{}': {e}", tool.name)))?;
    }
    Ok(())
}

/// Trajectory matching is fail-closed on `side_effect`. An allowed tool
/// without one would skip every `after` rule.
fn validate_trajectory_requires_side_effect(policy: &Policy) -> Result<(), PolicyError> {
    if !policy.trajectory {
        return Ok(());
    }
    for tool in &policy.tools {
        if !tool.allowed {
            continue;
        }
        if tool
            .side_effect
            .as_deref()
            .is_none_or(|s| s.trim().is_empty())
        {
            return Err(PolicyError::Validation(format!(
                "trajectory is enabled but allowed tool '{}' is missing side_effect",
                tool.name
            )));
        }
    }
    Ok(())
}

/// Enforce documented `side_effect` values and their load-time contracts.
///
/// Allowed values: `read_only` / `write` / `network` / `execute`.
/// `read_only` forbids write globs, a tool-explicit network sub-policy, and
/// process exec. `write` combined with process exec (anything other than
/// `process deny-all`) is an error in v1.
fn validate_side_effect_consistency(policy: &Policy) -> Result<(), PolicyError> {
    use crate::policy::SideEffect;

    for tool in &policy.tools {
        let Some(ref raw) = tool.side_effect else {
            continue;
        };
        let side_effect = SideEffect::parse(raw).map_err(PolicyError::Validation)?;
        match side_effect {
            SideEffect::ReadOnly => {
                if tool_has_write_glob(tool) {
                    return Err(PolicyError::Validation(format!(
                        "tool '{}' has side_effect=\"read_only\" but declares a write glob \
                         (mode=\"write\" / read_write_paths)",
                        tool.name
                    )));
                }
                if tool.network_explicit {
                    return Err(PolicyError::Validation(format!(
                        "tool '{}' has side_effect=\"read_only\" but declares a network sub-policy",
                        tool.name
                    )));
                }
                if tool.process_exec_allowed {
                    return Err(PolicyError::Validation(format!(
                        "tool '{}' has side_effect=\"read_only\" but allows process execution",
                        tool.name
                    )));
                }
            }
            SideEffect::Write => {
                if tool.process_exec_allowed {
                    return Err(PolicyError::Validation(format!(
                        "tool '{}' has side_effect=\"write\" combined with process execution; \
                         v1 is strict (process deny-all is the only allowed exec pairing)",
                        tool.name
                    )));
                }
            }
            SideEffect::Network | SideEffect::Execute => {}
        }
    }
    Ok(())
}

fn tool_has_write_glob(tool: &crate::policy::ToolPolicy) -> bool {
    tool.fs
        .as_ref()
        .is_some_and(|fs| !fs.read_write_paths.is_empty())
}

/// Check that the policy version is supported: v1 (open `tool` shape) and
/// v2 (closed `tool` shape + `mcp` passage rules) both load; anything
/// else fails closed.
fn validate_version(policy: &Policy) -> Result<(), PolicyError> {
    if !(MIN_SUPPORTED_VERSION..=MAX_SUPPORTED_VERSION).contains(&policy.version) {
        return Err(PolicyError::Validation(format!(
            "unsupported policy version {}, expected {MIN_SUPPORTED_VERSION}..={MAX_SUPPORTED_VERSION}",
            policy.version,
        )));
    }
    Ok(())
}

/// `mcp` passage rules are a schema-v2 contract.
///
/// The parser already enforces this for KDL input; this guards
/// programmatically constructed policies, so a v1 `Policy` assembled
/// in code cannot smuggle `mcp` rules past the load boundary.
///
/// Atom overlap is deliberately not checked here: rules merged across
/// documents (`include`, `extends`, `when`) union per server and resolve
/// deny-first in `resolve_atoms`; same-document collisions remain a
/// `kdl_parse` load error. What remains guarded is atom reachability —
/// a programmatically built rule that expands to no ledger atom would
/// otherwise be dead weight the parser never got to reject.
fn validate_mcp_rules(policy: &Policy) -> Result<(), PolicyError> {
    if policy.mcp_rules.is_empty() {
        return Ok(());
    }
    if policy.version < 2 {
        return Err(PolicyError::Validation(
            "mcp rules require 'policy version=2'".to_string(),
        ));
    }
    for entry in &policy.mcp_rules {
        let server = entry.server_name.as_deref().unwrap_or("<unnamed>");
        for rule in entry.rules() {
            if super::mcp::method_slots(&rule.method).is_empty() {
                return Err(PolicyError::Validation(format!(
                    "unknown MCP method \"{}\" in mcp rules for server '{server}'",
                    rule.method
                )));
            }
            if rule.atoms().is_empty() {
                return Err(PolicyError::Validation(format!(
                    "mcp rule for method \"{}\" in server '{server}' targets no valid \
                     rule-key combination after protocol=/direction= filtering",
                    rule.method
                )));
            }
        }
    }
    Ok(())
}

/// Check that required fields are present and valid.
fn validate_required_fields(policy: &Policy) -> Result<(), PolicyError> {
    if matches!(policy.transport.type_, TransportType::Http)
        && policy.transport.listen_addr.is_none()
    {
        return Err(PolicyError::Validation(
            "transport type 'http' requires 'listen_addr'".to_string(),
        ));
    }

    for (i, tool) in policy.tools.iter().enumerate() {
        if tool.name.trim().is_empty() {
            return Err(PolicyError::Validation(format!(
                "tool entry at index {i} has an empty 'name'",
            )));
        }
    }

    Ok(())
}

/// Detect duplicate tool identities `(server, name)`.
fn validate_duplicate_tools(policy: &Policy) -> Result<(), PolicyError> {
    let mut seen = HashSet::new();
    for tool in &policy.tools {
        let trimmed = tool.name.trim();
        let server = tool.server.as_deref().unwrap_or("");
        let key = format!("{server}\0{trimmed}");
        if !seen.insert(key) {
            return Err(PolicyError::Validation(format!(
                "duplicate tool name '{}' for server '{}'",
                trimmed,
                if server.is_empty() {
                    "<default>"
                } else {
                    server
                },
            )));
        }
    }
    Ok(())
}

/// Validate paths in tool fs policies and global fs policy.
fn validate_paths(policy: &Policy) -> Result<(), PolicyError> {
    for tool in &policy.tools {
        if let Some(ref fs) = tool.fs {
            validate_fs_target_contract(fs, &format!("tool '{}'", tool.name))?;
            for path in &fs.allowed_paths {
                if path.trim().is_empty() {
                    return Err(PolicyError::Validation(format!(
                        "tool '{}' contains an empty 'allowed_paths' entry",
                        tool.name,
                    )));
                }
            }
            for path in &fs.denied_paths {
                if path.trim().is_empty() {
                    return Err(PolicyError::Validation(format!(
                        "tool '{}' contains an empty 'denied_paths' entry",
                        tool.name,
                    )));
                }
            }
        }
    }

    for path in &policy.fs.read_only {
        if path.trim().is_empty() {
            return Err(PolicyError::Validation(
                "fs.read_only contains an empty path".to_string(),
            ));
        }
    }
    for path in &policy.fs.read_write {
        if path.trim().is_empty() {
            return Err(PolicyError::Validation(
                "fs.read_write contains an empty path".to_string(),
            ));
        }
    }

    Ok(())
}

/// The opt-in removes only a required argument, never a path restriction.
pub(crate) fn validate_fs_target_contract(
    fs: &super::FsToolPolicy,
    context: &str,
) -> Result<(), PolicyError> {
    if fs.require_path == Some(false) && !fs.allows_pathless_call() {
        return Err(PolicyError::Validation(format!(
            "{context}: filesystem require-path #false requires an explicitly empty allow-list \
             (allow none=#true); filesystem grants are not permitted on this tool"
        )));
    }
    Ok(())
}

fn validate_subpath_denials(policy: &Policy, os: TargetOs) -> Result<(), PolicyError> {
    // 1. Tool-level: allowed_paths vs denied_paths
    for tool in &policy.tools {
        if !tool.allowed {
            continue;
        }
        if let Some(ref fs) = tool.fs {
            for denied in &fs.denied_paths {
                for allowed in &fs.allowed_paths {
                    if is_strict_subpath_or_descendant_for(allowed, denied, os) {
                        return Err(PolicyError::Validation(format!(
                            "tool '{}' path '{}' is denied under allowed parent path '{}'. Landlock additive rulesets cannot carve out sub-path denials under an allowed directory",
                            tool.name, denied, allowed
                        )));
                    }
                }
                for global_allowed in policy
                    .fs
                    .read_only
                    .iter()
                    .chain(policy.fs.read_write.iter())
                {
                    if is_strict_subpath_or_descendant_for(global_allowed, denied, os) {
                        return Err(PolicyError::Validation(format!(
                            "tool '{}' path '{}' is denied under global allowed parent path '{}'. Landlock additive rulesets cannot carve out sub-path denials under an allowed directory",
                            tool.name, denied, global_allowed
                        )));
                    }
                }
            }
        }
    }

    // 2. Global defaults: denied_paths vs read_only/read_write
    for denied in &policy.fs.denied_paths {
        for allowed in policy
            .fs
            .read_only
            .iter()
            .chain(policy.fs.read_write.iter())
        {
            if is_strict_subpath_or_descendant_for(allowed, denied, os) {
                return Err(PolicyError::Validation(format!(
                    "global path '{}' is denied under global allowed parent path '{}'. Landlock additive rulesets cannot carve out sub-path denials under an allowed directory",
                    denied, allowed
                )));
            }
        }
    }

    Ok(())
}

fn validate_per_tool_syscalls(policy: &Policy) -> Result<(), PolicyError> {
    for tool in &policy.tools {
        if tool.syscalls_explicit {
            return Err(PolicyError::Validation(format!(
                "tool '{}' declares per-tool syscalls, which are not enforced; \
                 move syscall rules to defaults.syscalls",
                tool.name
            )));
        }
    }
    Ok(())
}

/// `environment` under a tool, profile, or server-defaults is not a
/// per-tool category; only `defaults.environment` is enforced.
fn validate_per_tool_environment(policy: &Policy) -> Result<(), PolicyError> {
    for tool in &policy.tools {
        if tool.environment_explicit {
            return Err(PolicyError::Validation(format!(
                "tool '{}' declares per-tool environment, which is not enforced; \
                 move environment rules to defaults.environment",
                tool.name
            )));
        }
    }
    Ok(())
}

/// Environment variable names in `defaults.environment` must be usable in a
/// `KEY=value` pair: non-empty, no `=`, no NUL.
fn validate_environment_names(policy: &Policy) -> Result<(), PolicyError> {
    for name in &policy.environment.allowed {
        if name.is_empty() || name.contains('=') || name.contains('\0') {
            return Err(PolicyError::Validation(format!(
                "invalid environment variable name '{}' in defaults.environment; \
                 names must be non-empty and must not contain '=' or NUL",
                name.escape_debug()
            )));
        }
    }
    Ok(())
}

fn validate_hash_workload_identity(policy: &Policy) -> Result<(), PolicyError> {
    use super::HashType;
    let file_hashes: Vec<_> = policy
        .hash_entries
        .iter()
        .filter(|e| {
            matches!(
                e.hash_type,
                HashType::Binary | HashType::Lockfile | HashType::Entrypoint
            )
        })
        .collect();
    if file_hashes.is_empty() {
        return Ok(());
    }
    let has_identity = file_hashes
        .iter()
        .any(|e| matches!(e.hash_type, HashType::Binary | HashType::Entrypoint));
    if !has_identity {
        return Err(PolicyError::Validation(
            "hash entries include lockfile hashes but no binary-hash or entrypoint-hash; \
             lockfiles are dependency evidence and cannot authorize a launched workload"
                .into(),
        ));
    }
    Ok(())
}

fn validate_hash_entries(policy: &Policy) -> Result<(), PolicyError> {
    let mut seen_targets = HashSet::new();
    for entry in &policy.hash_entries {
        if entry.target.trim().is_empty() {
            return Err(PolicyError::Validation(format!(
                "hash entry for server '{}' has an empty target",
                entry.server_name
            )));
        }
        let key = format!(
            "{}:{}:{}",
            entry.server_name,
            entry.hash_type.as_str(),
            entry.target
        );
        if !seen_targets.insert(key) {
            return Err(PolicyError::Validation(format!(
                "duplicate hash target '{}' for server '{}'",
                entry.target, entry.server_name
            )));
        }
    }
    Ok(())
}
