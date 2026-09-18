use landlock::{
    ABI, Access, AccessFs, AccessNet, CompatLevel, Compatible, Errno, NetPort, PathBeneath, PathFd,
    Ruleset, RulesetAttr, RulesetCreated, RulesetCreatedAttr, RulesetStatus,
};

use crate::error::WardenError;
use crate::policy::Policy;

/// Apply Landlock filesystem restrictions based on the given policy.
///
/// Creates a default-deny ruleset and selectively opens access to paths
/// listed in the policy's `fs.read_only` and `fs.read_write` sections,
/// plus any per-tool `fs.allowed_paths`.
///
/// After `restrict_self()`, the calling process (and all future children)
/// are permanently constrained. The restrictions cannot be removed, only
/// tightened further.
pub fn create_landlock_ruleset(policy: &Policy) -> Result<RulesetCreated, WardenError> {
    let read_access = AccessFs::from_read(ABI::V3);
    // Narrower access mask for read-write paths: read + write + truncate (V3)
    let read_write_access = AccessFs::from_read(ABI::V3) | AccessFs::from_write(ABI::V3);

    // Create a default-deny ruleset: V1/V2/V3 filesystem (including Truncate) + V4 network.
    // BestEffort ensures graceful degradation on older kernels:
    // - Kernel < 5.13: no Landlock at all
    // - Kernel 5.13–6.1: V1/V2 filesystem, truncate silently degraded
    // - Kernel 6.2–6.6: V3 filesystem with truncate enforcement
    // - Kernel >= 6.7: full filesystem (with truncate) + TCP network enforcement
    let mut ruleset = Ruleset::default()
        .set_compatibility(CompatLevel::BestEffort)
        .handle_access(AccessFs::from_all(ABI::V1))
        .map_err(|e| {
            WardenError::SandboxSetup(format!("Landlock: failed to handle access rights V1: {e}"))
        })?
        .set_compatibility(CompatLevel::BestEffort)
        .handle_access(AccessFs::from_all(ABI::V2))
        .map_err(|e| {
            WardenError::SandboxSetup(format!("Landlock: failed to handle access rights V2: {e}"))
        })?
        .set_compatibility(CompatLevel::BestEffort)
        .handle_access(AccessFs::from_all(ABI::V3))
        .map_err(|e| {
            WardenError::SandboxSetup(format!(
                "Landlock: failed to handle access rights V3 (truncate): {e}"
            ))
        })?
        .set_compatibility(CompatLevel::BestEffort)
        .handle_access(AccessNet::from_all(ABI::V4))
        .map_err(|e| {
            WardenError::SandboxSetup(format!("Landlock: failed to handle net access rights: {e}"))
        })?
        .create()
        .map_err(|e| {
            WardenError::SandboxSetup(format!("Landlock: failed to create ruleset: {e}"))
        })?;

    // Check for parent allow + child deny in global fs rules
    for denied in &policy.fs.denied_paths {
        for allowed in policy
            .fs
            .read_only
            .iter()
            .chain(policy.fs.read_write.iter())
        {
            if crate::policy::validator::is_strict_subpath_or_descendant(allowed, denied) {
                return Err(WardenError::SandboxSetup(format!(
                    "Landlock policy error: denied path '{denied}' is a subpath of allowed path '{allowed}'. Landlock cannot carve out sub-paths from parent directory grants",
                )));
            }
        }
    }

    // Allow read-only access to specified paths (denied paths excluded).
    for path in &policy.fs.read_only {
        if policy.fs.denied_paths.contains(path) {
            continue;
        }
        match open_landlock_path(path) {
            Ok(fd) => {
                ruleset = ruleset
                    .add_rule(PathBeneath::new(fd, read_access))
                    .map_err(|e| {
                        WardenError::SandboxSetup(format!(
                            "Landlock: failed to add read rule for '{path}': {e}"
                        ))
                    })?;
            }
            Err(e) => {
                tracing::warn!("Landlock: skipping read_only path '{path}': {e}");
            }
        }
    }

    // Allow read-write access to specified paths (denied paths excluded).
    for path in &policy.fs.read_write {
        if policy.fs.denied_paths.contains(path) {
            continue;
        }
        match open_landlock_path(path) {
            Ok(fd) => {
                ruleset = ruleset
                    .add_rule(PathBeneath::new(fd, read_write_access))
                    .map_err(|e| {
                        WardenError::SandboxSetup(format!(
                            "Landlock: failed to add read-write rule for '{path}': {e}"
                        ))
                    })?;
            }
            Err(e) => {
                tracing::warn!("Landlock: skipping read_write path '{path}': {e}");
            }
        }
    }

    // Apply per-tool filesystem rules.
    // Only allowed tools contribute paths. Paths are given read or read-write access based on mode.
    for tool in &policy.tools {
        if !tool.allowed {
            tracing::debug!("Landlock: skipping paths for denied tool '{}'", tool.name);
            continue;
        }

        if let Some(ref fs) = tool.fs {
            // Reject if Landlock additive model cannot carve out a sub-path denial
            for denied in fs.denied_paths.iter().chain(policy.fs.denied_paths.iter()) {
                for allowed in &fs.allowed_paths {
                    if crate::policy::validator::is_strict_subpath_or_descendant(allowed, denied) {
                        return Err(WardenError::SandboxSetup(format!(
                            "Landlock policy error: tool '{}' path '{denied}' is denied but parent '{allowed}' is allowed. Landlock cannot carve out sub-paths from parent grants",
                            tool.name
                        )));
                    }
                }
            }

            // Read-only paths from tool
            for path in &fs.read_only_paths {
                if fs.denied_paths.contains(path) || policy.fs.denied_paths.contains(path) {
                    continue;
                }
                match open_landlock_path(path) {
                    Ok(fd) => {
                        ruleset = ruleset
                            .add_rule(PathBeneath::new(fd, read_access))
                            .map_err(|e| {
                                WardenError::SandboxSetup(format!(
                                    "Landlock: failed to add read tool rule for '{}' path '{path}': {e}",
                                    tool.name
                                ))
                            })?;
                    }
                    Err(e) => {
                        tracing::warn!(
                            "Landlock: skipping tool '{}' read_only path '{path}': {e}",
                            tool.name
                        );
                    }
                }
            }

            // Read-write paths from tool
            for path in &fs.read_write_paths {
                if fs.denied_paths.contains(path) || policy.fs.denied_paths.contains(path) {
                    continue;
                }
                match open_landlock_path(path) {
                    Ok(fd) => {
                        ruleset = ruleset
                            .add_rule(PathBeneath::new(fd, read_write_access))
                            .map_err(|e| {
                                WardenError::SandboxSetup(format!(
                                    "Landlock: failed to add read-write tool rule for '{}' path '{path}': {e}",
                                    tool.name
                                ))
                            })?;
                    }
                    Err(e) => {
                        tracing::warn!(
                            "Landlock: skipping tool '{}' read_write path '{path}': {e}",
                            tool.name
                        );
                    }
                }
            }

            // Backward compatibility: allowed_paths without explicit mode defaults to read-only
            for path in &fs.allowed_paths {
                if fs.read_only_paths.contains(path)
                    || fs.read_write_paths.contains(path)
                    || fs.denied_paths.contains(path)
                    || policy.fs.denied_paths.contains(path)
                {
                    continue;
                }
                match open_landlock_path(path) {
                    Ok(fd) => {
                        ruleset = ruleset
                            .add_rule(PathBeneath::new(fd, read_access))
                            .map_err(|e| {
                                WardenError::SandboxSetup(format!(
                                    "Landlock: failed to add fallback tool rule for '{}' path '{path}': {e}",
                                    tool.name
                                ))
                            })?;
                    }
                    Err(e) => {
                        tracing::warn!(
                            "Landlock: skipping tool '{}' fallback path '{path}': {e}",
                            tool.name
                        );
                    }
                }
            }
        }
    }

    // Add TCP connect rules from policy.network.outbound.allowed.
    // Each entry is a port number string (e.g., "443", "80").
    // BindTcp is NOT whitelisted: all TCP bind is denied by default.
    let allowed_ports = collect_allowed_ports(&policy.network.outbound.allowed);
    for port in &allowed_ports {
        ruleset = ruleset
            .add_rule(NetPort::new(*port, AccessNet::ConnectTcp))
            .map_err(|e| {
                WardenError::SandboxSetup(format!(
                    "Landlock: failed to add connect rule for port {port}: {e}"
                ))
            })?;
    }

    Ok(ruleset)
}

/// Apply a created ruleset in a `pre_exec` hook. Fail unless FullyEnforced
/// or `allow_degraded` is set.
///
/// Errors are `io::Error` built from raw errnos (extracted via
/// [`landlock::Errno`], EACCES when enforcement is only partial) so no heap
/// allocation happens on the post-fork error path.
pub fn restrict_self_fail_closed(
    ruleset: landlock::RulesetCreated,
    allow_degraded: bool,
) -> Result<(), std::io::Error> {
    let status = ruleset
        .restrict_self()
        .map_err(|e| std::io::Error::from_raw_os_error(*Errno::from(e)))?;
    match status.ruleset {
        RulesetStatus::FullyEnforced => Ok(()),
        RulesetStatus::NotEnforced | RulesetStatus::PartiallyEnforced => {
            if allow_degraded {
                Ok(())
            } else {
                Err(std::io::Error::from_raw_os_error(libc::EACCES))
            }
        }
    }
}

/// Apply the Landlock ruleset to the calling process.
#[allow(dead_code)]
pub fn apply_landlock(policy: &Policy) -> Result<(), WardenError> {
    let ruleset = create_landlock_ruleset(policy)?;

    // Lock down the process.  After this call, the constraints are permanent.
    let status = ruleset
        .restrict_self()
        .map_err(|e| WardenError::SandboxSetup(format!("Landlock: restrict_self failed: {e}")))?;

    match status.ruleset {
        RulesetStatus::FullyEnforced => {
            tracing::info!("Landlock: filesystem and network sandbox applied successfully");
            Ok(())
        }
        RulesetStatus::NotEnforced | RulesetStatus::PartiallyEnforced => {
            if policy.sandbox.allow_degraded {
                tracing::warn!(
                    status = ?status.ruleset,
                    "Landlock not fully enforced; continuing because sandbox.allow_degraded=true"
                );
                Ok(())
            } else {
                Err(WardenError::SandboxSetup(format!(
                    "Landlock not fully enforced ({:?}); refuse to launch. \
                     Set sandbox.allow_degraded=true only when a weaker kernel is an accepted risk",
                    status.ruleset
                )))
            }
        }
    }
}

/// Extract TCP port numbers from policy strings.
///
/// Landlock netport rules cannot bind a hostname to a destination. Only a
/// bare port number (`"443"`, `"80"`) is accepted. Hostnames and URLs are
/// skipped so they cannot be widened into an any-host connect on that port.
fn collect_allowed_ports(allowed: &[String]) -> Vec<u16> {
    let mut ports = Vec::new();
    for s in allowed {
        if let Some(port) = parse_port_from_entry(s) {
            if !ports.contains(&port) {
                ports.push(port);
            }
        } else {
            tracing::warn!(
                "Landlock: skipping non-numeric network entry '{s}' (hostnames are Auditor-only)"
            );
        }
    }
    ports
}

/// Accept only a bare TCP port. Port 0 is not a valid connect target.
fn parse_port_from_entry(entry: &str) -> Option<u16> {
    let trimmed = entry.trim();
    if trimmed.is_empty() {
        return None;
    }
    match trimmed.parse::<u16>() {
        Ok(0) => None,
        Ok(port) => Some(port),
        Err(_) => None,
    }
}

/// Strip glob suffixes (`/**`, `/*`, trailing `*`) so Landlock can open a real
/// directory. Policy paths are globs for the Auditor; Landlock needs an fd.
///
/// Returns `None` when the path is empty or still contains wildcards
/// (e.g. `/home/*/.ssh`).
fn landlock_base_path(path: &str) -> Option<&str> {
    let mut p = path.trim();
    if p.is_empty() {
        return None;
    }
    loop {
        if let Some(rest) = p.strip_suffix("/**") {
            p = rest;
            continue;
        }
        if let Some(rest) = p.strip_suffix("/*") {
            p = rest;
            continue;
        }
        if let Some(rest) = p.strip_suffix('*') {
            p = rest.trim_end_matches('/');
            continue;
        }
        break;
    }
    if p.is_empty() || p.contains(['*', '?']) {
        None
    } else {
        Some(p)
    }
}

fn open_landlock_path(path: &str) -> Result<PathFd, String> {
    let Some(base) = landlock_base_path(path) else {
        return Err(format!("cannot map glob path to a directory: {path}"));
    };
    PathFd::new(base).map_err(|e| format!("{e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- landlock_base_path ---------------------------------------------------

    #[test]
    fn test_landlock_base_path_strips_recursive_glob() {
        assert_eq!(landlock_base_path("/usr/lib/**"), Some("/usr/lib"));
        assert_eq!(landlock_base_path("/workspace/**"), Some("/workspace"));
    }

    #[test]
    fn test_landlock_base_path_strips_single_star() {
        assert_eq!(landlock_base_path("/tmp/*"), Some("/tmp"));
    }

    #[test]
    fn test_landlock_base_path_plain_directory() {
        assert_eq!(landlock_base_path("/usr/bin"), Some("/usr/bin"));
    }

    #[test]
    fn test_landlock_base_path_rejects_mid_glob() {
        assert_eq!(landlock_base_path("/home/*/.ssh/**"), None);
        assert_eq!(landlock_base_path(""), None);
    }

    // -- collect_allowed_ports -------------------------------------------------

    #[test]
    fn test_collect_bare_ports() {
        let allowed = vec!["80".to_string(), "443".to_string(), "8080".to_string()];
        let ports = collect_allowed_ports(&allowed);
        assert_eq!(ports, vec![80, 443, 8080]);
    }

    #[test]
    fn test_collect_https_url() {
        let allowed = vec!["https://api.example.com".to_string()];
        let ports = collect_allowed_ports(&allowed);
        assert!(ports.is_empty());
    }

    #[test]
    fn test_collect_http_url() {
        let allowed = vec!["http://example.com".to_string()];
        let ports = collect_allowed_ports(&allowed);
        assert!(ports.is_empty());
    }

    #[test]
    fn test_collect_url_with_explicit_port() {
        let allowed = vec!["https://api.example.com:8443".to_string()];
        let ports = collect_allowed_ports(&allowed);
        assert!(ports.is_empty());
    }

    #[test]
    fn test_collect_http_url_with_explicit_port() {
        let allowed = vec!["http://example.com:3000".to_string()];
        let ports = collect_allowed_ports(&allowed);
        assert!(ports.is_empty());
    }

    #[test]
    fn test_collect_bare_hostname() {
        let allowed = vec!["api.openai.com".to_string()];
        let ports = collect_allowed_ports(&allowed);
        assert!(ports.is_empty());
    }

    #[test]
    fn test_collect_bare_hostname_with_port() {
        let allowed = vec!["api.example.com:9090".to_string()];
        let ports = collect_allowed_ports(&allowed);
        assert!(ports.is_empty());
    }

    #[test]
    fn test_collect_localhost() {
        let allowed = vec!["localhost".to_string()];
        let ports = collect_allowed_ports(&allowed);
        assert!(ports.is_empty());
    }

    #[test]
    fn test_collect_mixed_inputs() {
        let allowed = vec![
            "443".to_string(),
            "https://api.openai.com".to_string(),
            "http://example.com".to_string(),
            "https://api.anthropic.com:8443".to_string(),
            "cdn.example.com".to_string(),
        ];
        let ports = collect_allowed_ports(&allowed);
        assert_eq!(ports, vec![443]);
    }

    #[test]
    fn test_collect_ports_skips_invalid() {
        let allowed = vec![
            "443".to_string(),
            "not_a_port".to_string(), // no dots, not a number → skipped
            "99999".to_string(),      // > u16::MAX, no dots → skipped
            "80".to_string(),
        ];
        let ports = collect_allowed_ports(&allowed);
        assert_eq!(ports, vec![443, 80]);
    }

    #[test]
    fn test_collect_ports_empty() {
        let allowed: Vec<String> = vec![];
        let ports = collect_allowed_ports(&allowed);
        assert!(ports.is_empty());
    }

    #[test]
    fn test_collect_ports_boundary_values() {
        let allowed = vec!["0".to_string(), "65535".to_string(), "65536".to_string()];
        let ports = collect_allowed_ports(&allowed);
        // Port 0 is not a valid connect target (skipped), 65536 exceeds u16::MAX (skipped)
        assert_eq!(ports, vec![65535]);
    }

    #[test]
    fn test_collect_ports_negative() {
        let allowed = vec!["-1".to_string(), "443".to_string()];
        let ports = collect_allowed_ports(&allowed);
        assert_eq!(ports, vec![443]); // negative is invalid for u16
    }

    #[test]
    fn test_collect_url_with_path() {
        let allowed = vec!["https://api.example.com/v1/chat".to_string()];
        let ports = collect_allowed_ports(&allowed);
        assert!(ports.is_empty());
    }

    #[test]
    fn test_collect_deduplicates() {
        let allowed = vec![
            "443".to_string(),
            "https://api.example.com".to_string(),
            "443".to_string(),
        ];
        let ports = collect_allowed_ports(&allowed);
        assert_eq!(ports, vec![443]);
    }

    #[test]
    fn test_collect_localhost_with_port() {
        let allowed = vec!["localhost:8080".to_string()];
        let ports = collect_allowed_ports(&allowed);
        assert!(ports.is_empty());
    }

    #[test]
    fn test_collect_empty_string_entry() {
        let allowed = vec!["".to_string(), "443".to_string()];
        let ports = collect_allowed_ports(&allowed);
        assert_eq!(ports, vec![443]);
    }

    #[test]
    fn test_collect_whitespace_port() {
        let allowed = vec![" 443 ".to_string()];
        let ports = collect_allowed_ports(&allowed);
        assert_eq!(ports, vec![443]);
    }

    // -- apply_landlock is not called in-process ------------------------------
    // restrict_self() would lock down the cargo test binary (and parallel tests).
    // These tests only verify that the policy used by apply_landlock is well-formed.

    #[test]
    fn test_network_policy_ports_are_collectable() {
        use crate::policy::{NetworkPolicy, OutboundPolicy, default_policy};

        let mut policy = default_policy();
        policy.network = NetworkPolicy {
            outbound: OutboundPolicy {
                allowed: vec!["443".to_string(), "80".to_string()],
                denied_hosts: vec![],
                deny_all_others: true,
            },
            inbound: Default::default(),
        };

        let ports = collect_allowed_ports(&policy.network.outbound.allowed);
        assert_eq!(ports, vec![443, 80]);
    }

    #[test]
    fn test_empty_network_policy_collects_no_ports() {
        use crate::policy::default_policy;

        let policy = default_policy();
        let ports = collect_allowed_ports(&policy.network.outbound.allowed);
        assert!(ports.is_empty());
    }
}
