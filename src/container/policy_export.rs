use std::fmt;
use std::path::Path;

use crate::execution::ExecutionTarget;
use crate::policy::Policy;

/// Failure of the load/bind stages of the self-contained policy export.
///
/// Produced only by [`load_and_bind_policy`]; the later inline/emit stages
/// report [`PolicyExportError`], which this converts into.
#[derive(Debug)]
pub enum PolicyBindError {
    /// `load_policy` failed.
    Load(String),
    /// `bind_to_server` failed.
    Bind(String),
}

impl fmt::Display for PolicyBindError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Load(m) => write!(f, "failed to load policy: {m}"),
            Self::Bind(m) => write!(f, "failed to bind policy to server: {m}"),
        }
    }
}

impl std::error::Error for PolicyBindError {}

impl From<PolicyBindError> for PolicyExportError {
    fn from(e: PolicyBindError) -> Self {
        match e {
            PolicyBindError::Load(m) => Self::Load(m),
            PolicyBindError::Bind(m) => Self::Bind(m),
        }
    }
}

/// Failure of one stage of the self-contained policy export.
///
/// Carries the inner error message; callers attach their own context
/// prefix when converting to their error type.
#[derive(Debug)]
pub enum PolicyExportError {
    /// `load_policy` failed.
    Load(String),
    /// `bind_to_server` failed.
    Bind(String),
    /// `inlined_schemas` failed.
    Inline(String),
    /// The emitted self-contained KDL failed its round-trip check
    /// (re-parse, target re-validation, or semantic equivalence).
    Emit(String),
}

impl fmt::Display for PolicyExportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Load(m) => write!(f, "failed to load policy: {m}"),
            Self::Bind(m) => write!(f, "failed to bind policy to server: {m}"),
            Self::Inline(m) => write!(f, "failed to inline schema: {m}"),
            Self::Emit(m) => write!(f, "self-contained policy export failed: {m}"),
        }
    }
}

impl std::error::Error for PolicyExportError {}

/// Load a policy file and bind it to a single server identity.
///
/// The file is read and canonicalized on the host — a missing or
/// unreadable policy stays a host-side `Load` error — while validation
/// accepts rules the `target` workload OS can represent, so a Windows host
/// can validate a policy for a Linux container guest.
///
/// Does not inline schemas: callers that need to inspect the bound
/// policy (e.g. docker-manifest-hash checks) run this before inlining.
pub fn load_and_bind_policy(
    policy_path: &Path,
    server: Option<&str>,
    target: &ExecutionTarget,
) -> Result<Policy, PolicyBindError> {
    let effective_policy = crate::policy::loader::load_policy_for_target(policy_path, target)
        .map_err(|e| PolicyBindError::Load(e.to_string()))?;
    effective_policy
        .bind_to_server(server)
        .map_err(|e| PolicyBindError::Bind(e.to_string()))
}

/// Inline `@file` args_schema references relative to `base_dir` and
/// serialize the result to a self-contained KDL string.
///
/// `@file` reads are host-side lookups against `base_dir`. The emitted
/// KDL is verified to round-trip — re-parse, re-validate for `target`'s
/// workload OS, and semantic equality with the inlined policy — so a
/// control node can never be dropped silently on export.
pub fn inline_policy_to_kdl(
    bound: &Policy,
    base_dir: &Path,
    target: &ExecutionTarget,
) -> Result<String, PolicyExportError> {
    let inlined = bound
        .inlined_schemas(base_dir)
        .map_err(PolicyExportError::Inline)?;
    inlined
        .to_kdl_verified(target)
        .map_err(|e| PolicyExportError::Emit(e.to_string()))
}

/// Export a policy as a self-contained KDL string:
/// `load_policy_for_target` → `bind_to_server` → `inlined_schemas` → `to_kdl`.
///
/// The result contains no `extends` and no `@schema.json` references.
pub fn export_self_contained_kdl(
    policy_path: &Path,
    server: Option<&str>,
    target: &ExecutionTarget,
) -> Result<String, PolicyExportError> {
    let bound = load_and_bind_policy(policy_path, server, target)?;
    let base_dir = policy_path.parent().unwrap_or_else(|| Path::new("."));
    inline_policy_to_kdl(&bound, base_dir, target)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::execution::TargetOs;

    fn linux_target() -> ExecutionTarget {
        ExecutionTarget::linux_container(None, None)
    }

    fn target_with_os(os: TargetOs) -> ExecutionTarget {
        ExecutionTarget {
            workload_os: os,
            ..ExecutionTarget::native()
        }
    }

    fn windows_target() -> ExecutionTarget {
        target_with_os(TargetOs::Windows)
    }

    fn write_policy(dir: &Path, name: &str, body: &str) -> std::path::PathBuf {
        let path = dir.join(name);
        std::fs::write(&path, body).unwrap();
        path
    }

    /// A per-destination allowlist (`allow host=...` while `deny_all_others`
    /// holds) is representable on a Linux guest — accepted even when the
    /// host OS doing the export is Windows. This is the core cross-target
    /// case: the guest contract, not `cfg!(windows)`, decides acceptance.
    #[test]
    fn linux_guest_accepts_per_destination_allowlist_on_any_host() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_policy(
            dir.path(),
            "policy.kdl",
            r#"policy version=1
defaults {
    network {
        allow host="api.example.com"
    }
}
server "test" {
    tool "t"
}
"#,
        );
        export_self_contained_kdl(&path, None, &linux_target())
            .expect("per-destination allowlist must be accepted for a Linux guest");
    }

    /// The same policy must be rejected when the declared workload OS is
    /// Windows — the per-destination allowlist is not representable there.
    #[test]
    fn windows_target_rejects_per_destination_allowlist() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_policy(
            dir.path(),
            "policy.kdl",
            r#"policy version=1
defaults {
    network {
        allow host="api.example.com"
    }
}
server "test" {
    tool "t"
}
"#,
        );
        let err = export_self_contained_kdl(&path, None, &windows_target())
            .expect_err("per-destination allowlist must be rejected for a Windows target");
        assert!(
            matches!(err, PolicyExportError::Load(_)),
            "expected Load error, got: {err}"
        );
    }

    /// A missing policy file is a host-side `Load` error regardless of
    /// the declared target — file existence is checked on the host.
    #[test]
    fn missing_policy_file_is_host_side_load_error_for_any_target() {
        let missing = Path::new("/nonexistent/policy.kdl");
        for target in [linux_target(), windows_target()] {
            let err = export_self_contained_kdl(missing, None, &target)
                .expect_err("missing file must fail");
            assert!(
                matches!(err, PolicyExportError::Load(_)),
                "expected Load error for target '{}', got: {err}",
                target.workload_os.name()
            );
        }
    }

    /// A missing `@schema.json` is a host-side error regardless of the
    /// declared target — `@file` references are resolved against the host
    /// filesystem while loading (the parser knows the policy's directory),
    /// so the failure surfaces as `Load`, never as a target-side
    /// representability error.
    #[test]
    fn missing_inline_schema_is_host_side_error_for_any_target() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_policy(
            dir.path(),
            "policy.kdl",
            r#"policy version=1
server "test" {
    tool "t" args_schema="@schema.json"
}
"#,
        );
        for target in [linux_target(), windows_target()] {
            let err = export_self_contained_kdl(&path, None, &target)
                .expect_err("missing schema must fail");
            assert!(
                matches!(err, PolicyExportError::Load(_)),
                "expected Load error for target '{}', got: {err}",
                target.workload_os.name()
            );
        }
    }

    /// A constraint that only exists after inheritance must still be
    /// validated against the target: the child declares no network rules,
    /// the parent's per-destination allowlist must reject for a Windows
    /// target and accept for a Linux guest.
    #[test]
    fn inherited_constraint_is_validated_against_the_target() {
        let dir = tempfile::tempdir().unwrap();
        write_policy(
            dir.path(),
            "parent.kdl",
            r#"policy version=1
defaults {
    network {
        allow host="api.example.com"
    }
}
server "test" {
    tool "parent_tool"
}
"#,
        );
        let child = write_policy(
            dir.path(),
            "child.kdl",
            r#"policy version=1
extends "parent.kdl"
server "test" {
    tool "child_tool"
}
"#,
        );

        export_self_contained_kdl(&child, None, &linux_target())
            .expect("inherited allowlist must be accepted for a Linux guest");
        let err = export_self_contained_kdl(&child, None, &windows_target())
            .expect_err("inherited allowlist must be rejected for a Windows target");
        assert!(
            matches!(err, PolicyExportError::Load(_)),
            "expected Load error, got: {err}"
        );
    }

    /// An explicit empty tool allow-list (`allow none=#true`) narrows the
    /// tool to *no* filesystem access despite the `/base` default — dropping
    /// it on export would silently re-widen the tool. The round-trip guard
    /// must keep it.
    #[test]
    fn explicit_empty_tool_filesystem_block_is_preserved_on_export() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_policy(
            dir.path(),
            "policy.kdl",
            r#"policy version=1
defaults {
    filesystem {
        allow "/base" mode="read"
    }
}
server "test" {
    tool "t" {
        filesystem {
            allow none=#true
        }
    }
}
"#,
        );
        let kdl = export_self_contained_kdl(&path, None, &linux_target()).unwrap();
        assert!(
            kdl.contains("none=#true"),
            "exported KDL lost the explicit empty allow-list:\n{kdl}"
        );
        let reparsed = crate::policy::kdl_loader::parse_kdl_policy(&kdl).unwrap();
        let tool = reparsed.tools.iter().find(|t| t.name == "t").unwrap();
        let fs = tool.fs.as_ref().expect("tool must keep a filesystem block");
        assert!(
            fs.allow_specified && fs.allowed_paths.is_empty(),
            "explicit-empty filesystem block did not round-trip: {fs:?}"
        );
    }

    /// Regression: a tool that merely inherits the default deny-all network
    /// must not gain an explicit `network` block on export — re-parsing it
    /// would mark the tool `network_explicit`, which `side_effect="read_only"`
    /// rejects. The repo's container fixture is the canonical shape.
    #[test]
    fn fixture_with_read_only_tools_exports_for_linux_guest() {
        let path =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/test_container_policy.kdl");
        let kdl = export_self_contained_kdl(&path, None, &linux_target())
            .expect("fixture policy must export for a Linux guest");
        // No tool needs a network block (the defaults posture re-parses to
        // the same deny-all state without one).
        assert!(
            !kdl.contains("network"),
            "export introduced a network block for an inheriting tool:\n{kdl}"
        );
        let reparsed = crate::policy::kdl_loader::parse_kdl_policy(&kdl).unwrap();
        for tool in &reparsed.tools {
            assert!(
                !tool.network_explicit,
                "tool '{}' gained an explicit network block on export",
                tool.name
            );
        }
    }

    /// The shipped example uses the same shape (read_only tools under a
    /// deny-all default) and must export cleanly.
    #[test]
    fn example_policy_exports_for_linux_guest() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("policy.example.kdl");
        export_self_contained_kdl(&path, None, &linux_target())
            .expect("policy.example.kdl must export for a Linux guest");
    }

    /// An explicitly open outbound posture (`allow host="*"`, i.e.
    /// `deny_all_others=false`) must round-trip: omitting the block would
    /// re-parse to the deny-all default and silently tighten the policy.
    #[test]
    fn open_outbound_posture_is_preserved_on_export() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_policy(
            dir.path(),
            "policy.kdl",
            r#"policy version=1
defaults {
    network {
        allow host="*"
    }
}
server "test" {
    tool "t"
}
"#,
        );
        let kdl = export_self_contained_kdl(&path, None, &linux_target())
            .expect("open outbound policy must export");
        assert!(kdl.contains("allow host=\"*\""), "got:\n{kdl}");
        let reparsed = crate::policy::kdl_loader::parse_kdl_policy(&kdl).unwrap();
        assert!(
            !reparsed.network.outbound.deny_all_others,
            "deny-all silently re-enabled on export"
        );
    }
}
