use std::collections::HashSet;

use super::{Policy, SUPPORTED_VERSION, TransportType};
use crate::error::PolicyError;

/// Run all policy validations. Call this after parsing, before using the policy.
pub fn validate_policy(policy: &Policy) -> Result<(), PolicyError> {
    validate_version(policy)?;
    validate_required_fields(policy)?;
    validate_duplicate_tools(policy)?;
    validate_paths(policy)?;
    validate_subpath_denials(policy)?;
    validate_hash_entries(policy)?;
    validate_windows_network_enforcement(policy)?;
    validate_per_tool_syscalls(policy)?;
    validate_per_tool_environment(policy)?;
    validate_environment_names(policy)?;
    validate_hash_workload_identity(policy)?;
    validate_side_effect_consistency(policy)?;
    validate_trajectory_requires_side_effect(policy)?;
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

/// Check that the policy version is supported.
fn validate_version(policy: &Policy) -> Result<(), PolicyError> {
    if policy.version != SUPPORTED_VERSION {
        return Err(PolicyError::Validation(format!(
            "unsupported policy version {}, expected {SUPPORTED_VERSION}",
            policy.version,
        )));
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

/// Normalize a filesystem path for Landlock/validator comparison:
/// - Replaces '\' with '/'
/// - Strips trailing wildcards (e.g. '/**', '/*')
/// - Resolves '.' and '..' segments
/// - Strips trailing '/' (except root "/")
pub fn normalize_fs_pattern(path: &str) -> String {
    let unified = path.replace('\\', "/");
    let trimmed = if let Some(stripped) = unified.strip_suffix("/**") {
        stripped
    } else if let Some(stripped) = unified.strip_suffix("/*") {
        stripped
    } else {
        unified.trim_end_matches('*')
    };

    let mut segments: Vec<&str> = Vec::new();
    for comp in std::path::Path::new(trimmed).components() {
        match comp {
            std::path::Component::RootDir => {
                segments.clear();
                segments.push("");
            }
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                if segments.len() > 1 {
                    segments.pop();
                }
            }
            std::path::Component::Normal(s) => {
                if let Some(s) = s.to_str() {
                    segments.push(s);
                }
            }
            std::path::Component::Prefix(p) => {
                if let Some(s) = p.as_os_str().to_str() {
                    segments.clear();
                    segments.push(s);
                }
            }
        }
    }
    if segments.is_empty() || (segments.len() == 1 && segments[0].is_empty()) {
        return "/".to_string();
    }
    segments.join("/")
}

/// Landlock rulesets are strictly additive within a layer (Linux Kernel documentation:
/// <https://docs.kernel.org/userspace-api/landlock.html#layers-of-file-path-access-rights>).
/// When a parent directory is allowed (or exact same path is allowed), a deny rule for a sub-path
/// beneath it cannot be carved out by Landlock. Such conflicting policies cannot provide kernel-level
/// confinement against compromised servers, so they are rejected at load/validation time.
pub fn is_strict_subpath_or_descendant(allowed: &str, denied: &str) -> bool {
    let a_norm = normalize_fs_pattern(allowed);
    let d_norm = normalize_fs_pattern(denied);

    // 1. Same entity / path collision: e.g. /data vs /data/**
    if path_components_equal(&a_norm, &d_norm) {
        return true;
    }

    // 2. Root allow covers everything
    if a_norm == "/" {
        return true;
    }

    // 3. Component-wise containment. `*` matches exactly one path component
    // so a wildcard allow such as `/data/*` detects denied descendants.
    path_covers(allowed, denied)
}

fn split_path_components(path: &str) -> Vec<&str> {
    path.split('/').filter(|part| !part.is_empty()).collect()
}

fn path_components_equal(left: &str, right: &str) -> bool {
    let l = split_path_components(left);
    let r = split_path_components(right);
    if l.len() != r.len() {
        return false;
    }
    l.iter().zip(r.iter()).all(|(a, b)| path_seg_eq(a, b))
}

fn path_seg_eq(a: &str, b: &str) -> bool {
    if cfg!(windows) {
        a.eq_ignore_ascii_case(b)
    } else {
        a == b
    }
}

fn pattern_components(path: &str) -> Vec<String> {
    let unified = path.replace('\\', "/");
    let mut segments = Vec::new();
    for comp in unified.split('/') {
        if comp.is_empty() || comp == "." {
            continue;
        }
        if comp == ".." {
            if !segments.is_empty() {
                segments.pop();
            }
            continue;
        }
        segments.push(comp.to_string());
    }
    segments
}

/// True when the allow pattern covers the denied path.
///
/// `*` matches exactly one component. `**` matches the rest of the path.
/// A denied path that continues past a matched allow prefix is a descendant.
fn path_covers(allowed: &str, denied: &str) -> bool {
    let allow_parts = pattern_components(allowed);
    let deny_parts = pattern_components(denied);
    if allow_parts.is_empty() {
        return false;
    }
    for (deny_index, allow_part) in allow_parts.iter().enumerate() {
        if allow_part == "**" {
            return true;
        }
        if deny_index >= deny_parts.len() {
            return false;
        }
        if allow_part != "*" && !path_seg_eq(allow_part, &deny_parts[deny_index]) {
            return false;
        }
    }
    true
}

fn validate_subpath_denials(policy: &Policy) -> Result<(), PolicyError> {
    // 1. Tool-level: allowed_paths vs denied_paths
    for tool in &policy.tools {
        if !tool.allowed {
            continue;
        }
        if let Some(ref fs) = tool.fs {
            for denied in &fs.denied_paths {
                for allowed in &fs.allowed_paths {
                    if is_strict_subpath_or_descendant(allowed, denied) {
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
                    if is_strict_subpath_or_descendant(global_allowed, denied) {
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
            if is_strict_subpath_or_descendant(allowed, denied) {
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

fn validate_windows_network_enforcement(policy: &Policy) -> Result<(), PolicyError> {
    if !cfg!(windows) {
        return Ok(());
    }
    if policy.network.outbound.deny_all_others && !policy.network.outbound.allowed.is_empty() {
        return Err(PolicyError::Validation(
            "Windows AppContainer cannot enforce per-destination outbound allowlists; \
             use an empty allow list (deny all) or deny_all_others=false (unrestricted), \
             or place a network broker in front of the sandbox"
                .to_string(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{
        FsToolPolicy, InputResponsesMode, ToolPolicy, TransportType, default_policy,
    };

    #[test]
    fn test_valid_default_policy_passes() {
        let policy = default_policy();
        assert!(validate_policy(&policy).is_ok());
    }

    // --- version ---

    #[test]
    fn test_unsupported_version() {
        let mut policy = default_policy();
        policy.version = 99;
        let err = validate_policy(&policy).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("unsupported policy version 99"));
        assert!(msg.contains("expected 1"));
    }

    #[test]
    fn test_version_zero_rejected() {
        let mut policy = default_policy();
        policy.version = 0;
        assert!(validate_policy(&policy).is_err());
    }

    #[test]
    fn test_version_two_rejected() {
        let mut policy = default_policy();
        policy.version = 2;
        let err = validate_policy(&policy).unwrap_err();
        assert!(err.to_string().contains("unsupported policy version 2"));
    }

    // --- required fields ---

    #[test]
    fn test_http_without_listen_addr() {
        let mut policy = default_policy();
        policy.transport.type_ = TransportType::Http;
        let err = validate_policy(&policy).unwrap_err();
        assert!(err.to_string().contains("listen_addr"));
    }

    #[test]
    fn test_http_with_listen_addr_passes() {
        let mut policy = default_policy();
        policy.transport.type_ = TransportType::Http;
        policy.transport.listen_addr = Some("127.0.0.1:8080".to_string());
        assert!(validate_policy(&policy).is_ok());
    }

    #[test]
    fn test_empty_tool_name() {
        let mut policy = default_policy();
        policy.tools.push(ToolPolicy {
            name: String::new(),
            allowed: true,
            args_schema: None,
            side_effect: None,
            server: None,
            fs: None,
            syscalls: None,
            network: None,
            input_responses: InputResponsesMode::Auto,
            input_responses_specified: false,
            fs_explicit: false,
            network_explicit: false,
            syscalls_explicit: false,
            environment_explicit: false,
            process_exec_allowed: false,
            process_explicit: false,
        });
        let err = validate_policy(&policy).unwrap_err();
        assert!(err.to_string().contains("empty 'name'"));
    }

    #[test]
    fn test_whitespace_tool_name() {
        let mut policy = default_policy();
        policy.tools.push(ToolPolicy {
            name: "  ".to_string(),
            allowed: true,
            args_schema: None,
            side_effect: None,
            server: None,
            fs: None,
            syscalls: None,
            network: None,
            input_responses: InputResponsesMode::Auto,
            input_responses_specified: false,
            fs_explicit: false,
            network_explicit: false,
            syscalls_explicit: false,
            environment_explicit: false,
            process_exec_allowed: false,
            process_explicit: false,
        });
        let err = validate_policy(&policy).unwrap_err();
        assert!(err.to_string().contains("empty 'name'"));
    }

    // --- duplicate tools ---

    #[test]
    fn test_duplicate_tool_names() {
        let mut policy = default_policy();
        policy.tools.push(ToolPolicy {
            name: "read_file".to_string(),
            allowed: true,
            args_schema: None,
            side_effect: None,
            server: None,
            fs: None,
            syscalls: None,
            network: None,
            input_responses: InputResponsesMode::Auto,
            input_responses_specified: false,
            fs_explicit: false,
            network_explicit: false,
            syscalls_explicit: false,
            environment_explicit: false,
            process_exec_allowed: false,
            process_explicit: false,
        });
        policy.tools.push(ToolPolicy {
            name: "read_file".to_string(),
            allowed: false,
            args_schema: None,
            side_effect: None,
            server: None,
            fs: None,
            syscalls: None,
            network: None,
            input_responses: InputResponsesMode::Auto,
            input_responses_specified: false,
            fs_explicit: false,
            network_explicit: false,
            syscalls_explicit: false,
            environment_explicit: false,
            process_exec_allowed: false,
            process_explicit: false,
        });
        let err = validate_policy(&policy).unwrap_err();
        assert!(err.to_string().contains("duplicate tool name 'read_file'"));
    }

    #[test]
    fn test_duplicate_tool_names_after_trimming() {
        let mut policy = default_policy();
        policy.tools.push(ToolPolicy {
            name: "read_file".to_string(),
            allowed: true,
            args_schema: None,
            side_effect: None,
            server: None,
            fs: None,
            syscalls: None,
            network: None,
            input_responses: InputResponsesMode::Auto,
            input_responses_specified: false,
            fs_explicit: false,
            network_explicit: false,
            syscalls_explicit: false,
            environment_explicit: false,
            process_exec_allowed: false,
            process_explicit: false,
        });
        policy.tools.push(ToolPolicy {
            name: " read_file ".to_string(),
            allowed: false,
            args_schema: None,
            side_effect: None,
            server: None,
            fs: None,
            syscalls: None,
            network: None,
            input_responses: InputResponsesMode::Auto,
            input_responses_specified: false,
            fs_explicit: false,
            network_explicit: false,
            syscalls_explicit: false,
            environment_explicit: false,
            process_exec_allowed: false,
            process_explicit: false,
        });
        let err = validate_policy(&policy).unwrap_err();
        assert!(err.to_string().contains("duplicate tool name 'read_file'"));
    }

    #[test]
    fn test_unique_tool_names_pass() {
        let mut policy = default_policy();
        policy.tools.push(ToolPolicy {
            name: "read_file".to_string(),
            allowed: true,
            args_schema: None,
            side_effect: None,
            server: None,
            fs: None,
            syscalls: None,
            network: None,
            input_responses: InputResponsesMode::Auto,
            input_responses_specified: false,
            fs_explicit: false,
            network_explicit: false,
            syscalls_explicit: false,
            environment_explicit: false,
            process_exec_allowed: false,
            process_explicit: false,
        });
        policy.tools.push(ToolPolicy {
            name: "write_file".to_string(),
            allowed: true,
            args_schema: None,
            side_effect: None,
            server: None,
            fs: None,
            syscalls: None,
            network: None,
            input_responses: InputResponsesMode::Auto,
            input_responses_specified: false,
            fs_explicit: false,
            network_explicit: false,
            syscalls_explicit: false,
            environment_explicit: false,
            process_exec_allowed: false,
            process_explicit: false,
        });
        assert!(validate_policy(&policy).is_ok());
    }

    // --- paths ---

    #[test]
    fn test_empty_allowed_path_in_tool() {
        let mut policy = default_policy();
        policy.tools.push(ToolPolicy {
            name: "read_file".to_string(),
            allowed: true,
            args_schema: None,
            side_effect: None,
            server: None,
            fs: Some(FsToolPolicy::new(vec![String::new()], vec![])),
            syscalls: None,
            network: None,
            input_responses: InputResponsesMode::Auto,
            input_responses_specified: false,
            fs_explicit: false,
            network_explicit: false,
            syscalls_explicit: false,
            environment_explicit: false,
            process_exec_allowed: false,
            process_explicit: false,
        });
        let err = validate_policy(&policy).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("empty 'allowed_paths'"));
        assert!(msg.contains("read_file"));
    }

    #[test]
    fn test_whitespace_denied_path_in_tool() {
        let mut policy = default_policy();
        policy.tools.push(ToolPolicy {
            name: "write_file".to_string(),
            allowed: true,
            args_schema: None,
            side_effect: None,
            server: None,
            fs: Some(FsToolPolicy::new(
                vec!["/workspace/**".to_string()],
                vec!["  ".to_string()],
            )),
            syscalls: None,
            network: None,
            input_responses: InputResponsesMode::Auto,
            input_responses_specified: false,
            fs_explicit: false,
            network_explicit: false,
            syscalls_explicit: false,
            environment_explicit: false,
            process_exec_allowed: false,
            process_explicit: false,
        });
        let err = validate_policy(&policy).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("empty 'denied_paths'"));
        assert!(msg.contains("write_file"));
    }

    #[test]
    fn test_empty_global_read_only_path() {
        let mut policy = default_policy();
        policy.fs.read_only.push(String::new());
        let err = validate_policy(&policy).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("fs.read_only"));
        assert!(msg.contains("empty path"));
    }

    #[test]
    fn test_empty_global_read_write_path() {
        let mut policy = default_policy();
        policy.fs.read_write.push("  ".to_string());
        let err = validate_policy(&policy).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("fs.read_write"));
        assert!(msg.contains("empty path"));
    }

    #[test]
    fn test_valid_paths_pass() {
        let mut policy = default_policy();
        policy.tools.push(ToolPolicy {
            name: "read_file".to_string(),
            allowed: true,
            args_schema: None,
            side_effect: None,
            server: None,
            fs: Some(FsToolPolicy::new(
                vec!["/workspace/**".to_string()],
                vec!["/home/*/.ssh/**".to_string()],
            )),
            syscalls: None,
            network: None,
            input_responses: InputResponsesMode::Auto,
            input_responses_specified: false,
            fs_explicit: false,
            network_explicit: false,
            syscalls_explicit: false,
            environment_explicit: false,
            process_exec_allowed: false,
            process_explicit: false,
        });
        policy.fs.read_only = vec!["/usr/lib/**".to_string()];
        policy.fs.read_write = vec!["/workspace/**".to_string()];
        assert!(validate_policy(&policy).is_ok());
    }

    // --- integration: example policy ---

    #[test]
    fn test_example_policy_passes_validation() {
        let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("policy.example.kdl");
        let policy = crate::policy::loader::load_policy(&path).unwrap();
        assert!(validate_policy(&policy).is_ok());
    }

    #[test]
    fn test_windows_rejects_per_destination_outbound_allowlist() {
        let mut policy = default_policy();
        policy.network.outbound.deny_all_others = true;
        policy.network.outbound.allowed = vec!["api.example.com".to_string()];
        let result = validate_policy(&policy);
        if cfg!(windows) {
            let err = result.expect_err("Windows cannot pin outbound destinations");
            assert!(err.to_string().contains("Windows AppContainer"));
        } else {
            assert!(result.is_ok());
        }
    }

    #[test]
    fn test_r06_parent_allow_child_deny_rejected() {
        let mut policy = default_policy();
        policy.tools.push(ToolPolicy {
            name: "write_file".to_string(),
            allowed: true,
            args_schema: None,
            side_effect: None,
            server: None,
            fs: Some(FsToolPolicy::new(
                vec!["/workspace/**".to_string()],
                vec!["/workspace/secret.txt".to_string()],
            )),
            syscalls: None,
            network: None,
            input_responses: InputResponsesMode::Auto,
            input_responses_specified: false,
            fs_explicit: false,
            network_explicit: false,
            syscalls_explicit: false,
            environment_explicit: false,
            process_exec_allowed: false,
            process_explicit: false,
        });
        let err = validate_policy(&policy).unwrap_err();
        assert!(
            err.to_string()
                .contains("Landlock additive rulesets cannot carve out sub-path denials")
        );
    }

    #[test]
    fn test_per_tool_syscalls_are_rejected() {
        let mut policy = default_policy();
        policy.tools.push(ToolPolicy {
            name: "exec_cmd".to_string(),
            allowed: true,
            args_schema: None,
            side_effect: None,
            server: None,
            fs: None,
            syscalls: Some(crate::policy::ToolSyscallPolicy {
                allowed: vec!["read".to_string()],
                denied: vec!["execve".to_string()],
            }),
            network: None,
            input_responses: InputResponsesMode::Auto,
            input_responses_specified: false,
            fs_explicit: false,
            network_explicit: false,
            syscalls_explicit: true,
            environment_explicit: false,
            process_exec_allowed: false,
            process_explicit: false,
        });
        let err = validate_policy(&policy).unwrap_err();
        assert!(err.to_string().contains("per-tool syscalls"), "got: {err}");
    }

    #[test]
    fn test_per_tool_environment_is_rejected() {
        let mut policy = default_policy();
        let mut tool = ToolPolicy::named("read_file", true);
        tool.environment_explicit = true;
        policy.tools.push(tool);
        let err = validate_policy(&policy).unwrap_err();
        assert!(
            err.to_string().contains("per-tool environment"),
            "got: {err}"
        );
        assert!(
            err.to_string().contains("defaults.environment"),
            "rejection must point at defaults.environment: {err}"
        );
    }

    #[test]
    fn test_environment_names_rejected_when_unusable() {
        for name in ["", "A=B", "A\0B"] {
            let mut policy = default_policy();
            policy.environment.restrict = true;
            policy.environment.allowed = vec![name.to_string()];
            let err = validate_policy(&policy).unwrap_err();
            assert!(
                matches!(err, PolicyError::Validation(_)),
                "name {name:?} must be a validation error, got: {err}"
            );
            assert!(
                err.to_string().contains("environment variable name"),
                "got: {err}"
            );
        }
    }

    #[test]
    fn test_environment_names_valid_pass() {
        let mut policy = default_policy();
        policy.environment.restrict = true;
        policy.environment.allowed = vec!["MEMORY_FILE_PATH".to_string(), "LANG".to_string()];
        assert!(validate_policy(&policy).is_ok());
    }

    #[test]
    fn test_side_effect_read_only_with_write_glob_fails() {
        let kdl = r#"
            policy version=1
            server "s" {
                tool "read_file" side_effect="read_only" {
                    filesystem {
                        allow "/workspace/**" mode="write"
                    }
                }
            }
        "#;
        let policy = crate::policy::kdl_loader::parse_kdl_policy(kdl).unwrap();
        let err = validate_policy(&policy).unwrap_err();
        assert!(
            err.to_string().contains("read_only") && err.to_string().contains("write"),
            "got: {err}"
        );
    }

    #[test]
    fn test_side_effect_read_only_with_network_subpolicy_fails() {
        let kdl = r#"
            policy version=1
            server "s" {
                tool "read_file" side_effect="read_only" {
                    filesystem {
                        allow "/workspace/**"
                    }
                    network {
                        allow host="api.example.com"
                    }
                }
            }
        "#;
        let policy = crate::policy::kdl_loader::parse_kdl_policy(kdl).unwrap();
        let err = validate_policy(&policy).unwrap_err();
        assert!(err.to_string().contains("network"), "got: {err}");
    }

    #[test]
    fn test_side_effect_write_plus_exec_fails() {
        let kdl = r#"
            policy version=1
            server "s" {
                tool "write_file" side_effect="write" {
                    filesystem {
                        allow "/workspace/**" mode="write"
                    }
                    process deny-all=#false
                }
            }
        "#;
        let policy = crate::policy::kdl_loader::parse_kdl_policy(kdl).unwrap();
        let err = validate_policy(&policy).unwrap_err();
        assert!(
            err.to_string().contains("write") && err.to_string().contains("process"),
            "got: {err}"
        );
    }

    #[test]
    fn test_side_effect_write_with_process_deny_all_passes() {
        let kdl = r#"
            policy version=1
            server "s" {
                tool "write_file" side_effect="write" {
                    filesystem {
                        allow "/workspace/**" mode="write"
                    }
                    process deny-all=#true
                }
            }
        "#;
        let policy = crate::policy::kdl_loader::parse_kdl_policy(kdl).unwrap();
        assert!(validate_policy(&policy).is_ok());
    }

    #[test]
    fn test_side_effect_consistent_read_only_passes() {
        let kdl = r#"
            policy version=1
            server "s" {
                tool "read_file" side_effect="read_only" {
                    filesystem {
                        allow "/workspace/**"
                    }
                }
            }
        "#;
        let policy = crate::policy::kdl_loader::parse_kdl_policy(kdl).unwrap();
        assert!(validate_policy(&policy).is_ok());
    }

    #[test]
    fn test_unknown_side_effect_is_load_error() {
        let kdl = r#"
            policy version=1
            server "s" {
                tool "read_file" side_effect="mutate"
            }
        "#;
        let err = crate::policy::kdl_loader::parse_kdl_policy(kdl).unwrap_err();
        assert!(
            err.to_string().contains("unknown side_effect"),
            "got: {err}"
        );
    }

    #[test]
    fn test_trajectory_requires_side_effect_on_allowed_tools() {
        let kdl = r#"
            policy version=1
            trajectory #true {
                after side_effect="read_only" deny-next="network"
            }
            server "s" {
                tool "read_file"
            }
        "#;
        let policy = crate::policy::kdl_loader::parse_kdl_policy(kdl).unwrap();
        let err = validate_policy(&policy).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("side_effect"), "got: {err}");
        assert!(msg.contains("read_file"), "got: {err}");
    }

    #[test]
    fn test_trajectory_allows_denied_tools_without_side_effect() {
        let kdl = r#"
            policy version=1
            trajectory #true {
                after side_effect="read_only" deny-next="network"
            }
            server "s" {
                tool "evil" deny=#true
                tool "read_file" side_effect="read_only"
            }
        "#;
        let policy = crate::policy::kdl_loader::parse_kdl_policy(kdl).unwrap();
        validate_policy(&policy).unwrap();
    }
}
