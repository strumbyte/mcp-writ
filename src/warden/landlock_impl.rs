use landlock::{
    ABI, Access, AccessFs, AccessNet, BitFlags, CompatLevel, Compatible, Errno, NetPort,
    PathBeneath, PathFd, Ruleset, RulesetAttr, RulesetCreated, RulesetCreatedAttr, RulesetStatus,
};

use crate::enforcement::{ControlState, FsAccess, GrantOrigin, GrantSubject, ProcessGrant};
use crate::error::{SandboxStage, WardenError};
use crate::policy::Policy;

/// The ruleset built for a policy together with the process-wide grant
/// entries it produced — the launch report describes exactly this data.
pub struct LandlockBuild {
    pub ruleset: RulesetCreated,
    /// Per-entry outcomes of the same decisions that added (or skipped)
    /// rules: `Planned` entries became ruleset rules, `Skipped` entries
    /// name the policy element and the reason no rule exists for it.
    pub grants: Vec<ProcessGrant>,
}

fn fs_grant(
    path: &str,
    access: FsAccess,
    origin: GrantOrigin,
    state: ControlState,
    reason: Option<String>,
) -> ProcessGrant {
    ProcessGrant {
        subject: GrantSubject::FsPath {
            path: path.to_string(),
            access,
        },
        origin,
        state,
        reason,
    }
}

/// Reason attached to a grant whose glob spelling was resolved to a base
/// directory (`/**` → its root, ...). `None` for plain paths.
fn glob_base_reason(path: &str) -> Option<String> {
    landlock_base_path(path)
        .filter(|base| *base != path.trim())
        .map(|base| format!("glob resolved to base '{base}'"))
}

/// Apply Landlock filesystem restrictions based on the given policy.
///
/// Creates a default-deny ruleset and selectively opens access to paths
/// listed in the policy's `fs.read_only` and `fs.read_write` sections,
/// plus any per-tool `fs.allowed_paths`.
///
/// After `restrict_self()`, the calling process (and all future children)
/// are permanently constrained. The restrictions cannot be removed, only
/// tightened further.
pub fn create_landlock_ruleset(policy: &Policy) -> Result<LandlockBuild, WardenError> {
    let mut grants = Vec::new();
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
            WardenError::sandbox_setup(
                SandboxStage::Prepare,
                format!("Landlock: failed to handle access rights V1: {e}"),
            )
        })?
        .set_compatibility(CompatLevel::BestEffort)
        .handle_access(AccessFs::from_all(ABI::V2))
        .map_err(|e| {
            WardenError::sandbox_setup(
                SandboxStage::Prepare,
                format!("Landlock: failed to handle access rights V2: {e}"),
            )
        })?
        .set_compatibility(CompatLevel::BestEffort)
        .handle_access(AccessFs::from_all(ABI::V3))
        .map_err(|e| {
            WardenError::sandbox_setup(
                SandboxStage::Prepare,
                format!("Landlock: failed to handle access rights V3 (truncate): {e}"),
            )
        })?
        .set_compatibility(CompatLevel::BestEffort)
        .handle_access(AccessNet::from_all(ABI::V4))
        .map_err(|e| {
            WardenError::sandbox_setup(
                SandboxStage::Prepare,
                format!("Landlock: failed to handle net access rights: {e}"),
            )
        })?
        .create()
        .map_err(|e| {
            WardenError::sandbox_setup(
                SandboxStage::Prepare,
                format!("Landlock: failed to create ruleset: {e}"),
            )
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
                return Err(WardenError::sandbox_setup(
                    SandboxStage::Policy,
                    format!(
                        "Landlock policy error: denied path '{denied}' is a subpath of allowed path '{allowed}'. Landlock cannot carve out sub-paths from parent directory grants"
                    ),
                ));
            }
        }
    }

    // Allow read-only access to specified paths (denied paths excluded).
    for path in &policy.fs.read_only {
        if policy.fs.denied_paths.contains(path) {
            grants.push(fs_grant(
                path,
                FsAccess::Read,
                GrantOrigin::Policy,
                ControlState::Skipped,
                Some("denied by a policy deny rule".to_string()),
            ));
            continue;
        }
        match open_landlock_path(path) {
            Ok(fd) => {
                ruleset = ruleset
                    .add_rule(path_beneath(fd, read_access))
                    .map_err(|e| {
                        WardenError::sandbox_setup(
                            SandboxStage::Prepare,
                            format!("Landlock: failed to add read rule for '{path}': {e}"),
                        )
                    })?;
                grants.push(fs_grant(
                    path,
                    FsAccess::Read,
                    GrantOrigin::Policy,
                    ControlState::Planned,
                    glob_base_reason(path),
                ));
            }
            Err(e) => {
                tracing::warn!("Landlock: skipping read_only path '{path}': {e}");
                grants.push(fs_grant(
                    path,
                    FsAccess::Read,
                    GrantOrigin::Policy,
                    ControlState::Skipped,
                    Some(format!("cannot open for a Landlock rule: {e}")),
                ));
            }
        }
    }

    // Allow read-write access to specified paths (denied paths excluded).
    for path in &policy.fs.read_write {
        if policy.fs.denied_paths.contains(path) {
            grants.push(fs_grant(
                path,
                FsAccess::ReadWrite,
                GrantOrigin::Policy,
                ControlState::Skipped,
                Some("denied by a policy deny rule".to_string()),
            ));
            continue;
        }
        match open_landlock_path(path) {
            Ok(fd) => {
                ruleset = ruleset
                    .add_rule(path_beneath(fd, read_write_access))
                    .map_err(|e| {
                        WardenError::sandbox_setup(
                            SandboxStage::Prepare,
                            format!("Landlock: failed to add read-write rule for '{path}': {e}"),
                        )
                    })?;
                grants.push(fs_grant(
                    path,
                    FsAccess::ReadWrite,
                    GrantOrigin::Policy,
                    ControlState::Planned,
                    glob_base_reason(path),
                ));
            }
            Err(e) => {
                tracing::warn!("Landlock: skipping read_write path '{path}': {e}");
                grants.push(fs_grant(
                    path,
                    FsAccess::ReadWrite,
                    GrantOrigin::Policy,
                    ControlState::Skipped,
                    Some(format!("cannot open for a Landlock rule: {e}")),
                ));
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
                        return Err(WardenError::sandbox_setup(
                            SandboxStage::Policy,
                            format!(
                                "Landlock policy error: tool '{}' path '{denied}' is denied but parent '{allowed}' is allowed. Landlock cannot carve out sub-paths from parent grants",
                                tool.name
                            ),
                        ));
                    }
                }
            }

            let tool_origin = || GrantOrigin::Tool(tool.name.clone());

            // Read-only paths from tool
            for path in &fs.read_only_paths {
                if fs.denied_paths.contains(path) || policy.fs.denied_paths.contains(path) {
                    grants.push(fs_grant(
                        path,
                        FsAccess::Read,
                        tool_origin(),
                        ControlState::Skipped,
                        Some("denied by a deny rule".to_string()),
                    ));
                    continue;
                }
                match open_landlock_path(path) {
                    Ok(fd) => {
                        ruleset = ruleset
                            .add_rule(path_beneath(fd, read_access))
                            .map_err(|e| {
                                WardenError::sandbox_setup(
                                    SandboxStage::Prepare,
                                    format!(
                                        "Landlock: failed to add read tool rule for '{}' path '{path}': {e}",
                                        tool.name
                                    ),
                                )
                            })?;
                        grants.push(fs_grant(
                            path,
                            FsAccess::Read,
                            tool_origin(),
                            ControlState::Planned,
                            glob_base_reason(path),
                        ));
                    }
                    Err(e) => {
                        tracing::warn!(
                            "Landlock: skipping tool '{}' read_only path '{path}': {e}",
                            tool.name
                        );
                        grants.push(fs_grant(
                            path,
                            FsAccess::Read,
                            tool_origin(),
                            ControlState::Skipped,
                            Some(format!("cannot open for a Landlock rule: {e}")),
                        ));
                    }
                }
            }

            // Read-write paths from tool
            for path in &fs.read_write_paths {
                if fs.denied_paths.contains(path) || policy.fs.denied_paths.contains(path) {
                    grants.push(fs_grant(
                        path,
                        FsAccess::ReadWrite,
                        tool_origin(),
                        ControlState::Skipped,
                        Some("denied by a deny rule".to_string()),
                    ));
                    continue;
                }
                match open_landlock_path(path) {
                    Ok(fd) => {
                        ruleset = ruleset
                            .add_rule(path_beneath(fd, read_write_access))
                            .map_err(|e| {
                                WardenError::sandbox_setup(
                                    SandboxStage::Prepare,
                                    format!(
                                        "Landlock: failed to add read-write tool rule for '{}' path '{path}': {e}",
                                        tool.name
                                    ),
                                )
                            })?;
                        grants.push(fs_grant(
                            path,
                            FsAccess::ReadWrite,
                            tool_origin(),
                            ControlState::Planned,
                            glob_base_reason(path),
                        ));
                    }
                    Err(e) => {
                        tracing::warn!(
                            "Landlock: skipping tool '{}' read_write path '{path}': {e}",
                            tool.name
                        );
                        grants.push(fs_grant(
                            path,
                            FsAccess::ReadWrite,
                            tool_origin(),
                            ControlState::Skipped,
                            Some(format!("cannot open for a Landlock rule: {e}")),
                        ));
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
                    if !fs.read_only_paths.contains(path) && !fs.read_write_paths.contains(path) {
                        grants.push(fs_grant(
                            path,
                            FsAccess::Read,
                            tool_origin(),
                            ControlState::Skipped,
                            Some("denied by a deny rule".to_string()),
                        ));
                    }
                    continue;
                }
                match open_landlock_path(path) {
                    Ok(fd) => {
                        ruleset = ruleset
                            .add_rule(path_beneath(fd, read_access))
                            .map_err(|e| {
                                WardenError::sandbox_setup(
                                    SandboxStage::Prepare,
                                    format!(
                                        "Landlock: failed to add fallback tool rule for '{}' path '{path}': {e}",
                                        tool.name
                                    ),
                                )
                            })?;
                        grants.push(fs_grant(
                            path,
                            FsAccess::Read,
                            tool_origin(),
                            ControlState::Planned,
                            glob_base_reason(path),
                        ));
                    }
                    Err(e) => {
                        tracing::warn!(
                            "Landlock: skipping tool '{}' fallback path '{path}': {e}",
                            tool.name
                        );
                        grants.push(fs_grant(
                            path,
                            FsAccess::Read,
                            tool_origin(),
                            ControlState::Skipped,
                            Some(format!("cannot open for a Landlock rule: {e}")),
                        ));
                    }
                }
            }
        }
    }

    // Add TCP connect rules from policy.network.outbound.allowed.
    // Each entry is a port number string (e.g., "443", "80").
    // BindTcp is NOT whitelisted: all TCP bind is denied by default.
    let mut seen_ports: Vec<u16> = Vec::new();
    for (entry, port) in net_intents(&policy.network.outbound.allowed) {
        let Some(port) = port else {
            tracing::warn!(
                "Landlock: skipping non-numeric network entry '{entry}' (hostnames are Auditor-only)"
            );
            grants.push(ProcessGrant {
                subject: GrantSubject::Rule {
                    kind: "tcp_host",
                    name: entry,
                },
                origin: GrantOrigin::Policy,
                state: ControlState::Skipped,
                reason: Some(
                    "not a bare TCP port; Landlock netport rules cannot bind a \
                     destination — this entry is enforced at the RPC layer only"
                        .to_string(),
                ),
            });
            continue;
        };
        if seen_ports.contains(&port) {
            continue;
        }
        seen_ports.push(port);
        ruleset = ruleset
            .add_rule(NetPort::new(port, AccessNet::ConnectTcp))
            .map_err(|e| {
                WardenError::sandbox_setup(
                    SandboxStage::Prepare,
                    format!("Landlock: failed to add connect rule for port {port}: {e}"),
                )
            })?;
        grants.push(ProcessGrant {
            subject: GrantSubject::TcpConnect { port },
            origin: GrantOrigin::Policy,
            state: ControlState::Planned,
            reason: Some(
                "grants connect to any destination on this port; per-destination \
                 rules are enforced at the RPC layer"
                    .to_string(),
            ),
        });
    }

    Ok(LandlockBuild { ruleset, grants })
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
    let ruleset = create_landlock_ruleset(policy)?.ruleset;

    // Lock down the process.  After this call, the constraints are permanent.
    let status = ruleset.restrict_self().map_err(|e| {
        WardenError::sandbox_setup(
            SandboxStage::Apply,
            format!("Landlock: restrict_self failed: {e}"),
        )
    })?;

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
                Err(WardenError::sandbox_setup(
                    SandboxStage::Apply,
                    format!(
                        "Landlock not fully enforced ({:?}); refuse to launch. \
                         Set sandbox.allow_degraded=true only when a weaker kernel is an accepted risk",
                        status.ruleset
                    ),
                ))
            }
        }
    }
}

/// Per-entry network intents: `(entry, Some(port))` becomes a `ConnectTcp`
/// netport rule; `(entry, None)` is a policy element Landlock cannot
/// express (hostname, URL, empty, port 0) and is reported as skipped.
///
/// Landlock netport rules cannot bind a hostname to a destination. Only a
/// bare port number (`"443"`, `"80"`) is accepted. Hostnames and URLs are
/// skipped so they cannot be widened into an any-host connect on that port.
fn net_intents(allowed: &[String]) -> Vec<(String, Option<u16>)> {
    allowed
        .iter()
        .map(|s| (s.clone(), parse_port_from_entry(s)))
        .collect()
}

/// Extract TCP port numbers from policy strings — the `Some` half of
/// [`net_intents`], deduplicated. Retained for tests.
#[cfg(test)]
fn collect_allowed_ports(allowed: &[String]) -> Vec<u16> {
    let mut ports = Vec::new();
    for (_, port) in net_intents(allowed) {
        if let Some(p) = port
            && !ports.contains(&p)
        {
            ports.push(p);
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

/// Build a `PathBeneath` rule, first dropping rights that are meaningless on
/// non-directory targets (`ReadDir`, `Make*`, `Remove*`, `Refer`).
///
/// The landlock crate masks those off itself before issuing the rule (the
/// kernel would reject them with EINVAL), but records the rule as only
/// partially applied, which marks the whole ruleset `PartiallyEnforced` and
/// makes `restrict_self_fail_closed` refuse the spawn. Masking up front
/// keeps the ruleset `FullyEnforced`; the effective kernel rights are
/// identical either way. On stat failure the full set is kept — matching
/// the crate's own `path_beneath_rules` behaviour.
fn path_beneath(fd: PathFd, access: BitFlags<AccessFs>) -> PathBeneath<PathFd> {
    let access = if fd_is_non_dir(&fd) {
        access & AccessFs::from_file(ABI::V3)
    } else {
        access
    };
    PathBeneath::new(fd, access)
}

/// `fstat` check matching the landlock crate's `is_file`: every
/// non-directory inode (regular file, device node, socket, fifo) may carry
/// only the `ACCESS_FILE` subset of rights.
fn fd_is_non_dir(fd: &PathFd) -> bool {
    use std::os::fd::{AsFd, AsRawFd};
    let mut stat = unsafe { std::mem::zeroed::<libc::stat>() };
    let stat_ok = unsafe { libc::fstat(fd.as_fd().as_raw_fd(), &mut stat) } == 0;
    stat_ok && (stat.st_mode & libc::S_IFMT) != libc::S_IFDIR
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

    // -- path_beneath file/dir access masking ----------------------------------
    // A file rule carrying directory-only rights (e.g. ReadDir on /dev/null)
    // makes the crate downgrade the ruleset to PartiallyEnforced, which
    // restrict_self_fail_closed rejects with EACCES. These tests pin the
    // predicate and the masked right set.

    #[test]
    fn test_fd_is_non_dir_detects_files_and_dirs() {
        assert!(fd_is_non_dir(&PathFd::new("/dev/null").unwrap()));
        assert!(!fd_is_non_dir(&PathFd::new("/").unwrap()));
    }

    #[test]
    fn test_file_access_mask_drops_directory_only_rights() {
        let file_ok = AccessFs::from_file(ABI::V3);
        let read = AccessFs::from_read(ABI::V3);
        let rw = read | AccessFs::from_write(ABI::V3);
        assert!(file_ok.contains(AccessFs::ReadFile));
        assert!(file_ok.contains(AccessFs::WriteFile));
        assert!(file_ok.contains(AccessFs::Execute));
        assert!(file_ok.contains(AccessFs::Truncate));
        assert!(!file_ok.contains(AccessFs::ReadDir));
        assert!(!file_ok.contains(AccessFs::MakeReg));
        // A masked file rule still keeps the rights that matter for files.
        assert_eq!(read & file_ok, AccessFs::Execute | AccessFs::ReadFile);
        assert_eq!(
            rw & file_ok,
            AccessFs::Execute | AccessFs::ReadFile | AccessFs::WriteFile | AccessFs::Truncate
        );
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
