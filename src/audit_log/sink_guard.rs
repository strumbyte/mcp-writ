//! Audit-sink protection: the launch must refuse an `--audit-log` path
//! a sandboxed workload can write. A workload with write authority over
//! its own audit file — or a parent directory of it, where it could
//! rename/unlink/replace the file — can rewrite or erase the evidence
//! the fail-closed audit path exists to keep. The check runs before the
//! sink opens so the refusal never depends on the file it protects.
//!
//! Coverage is the *effective* write surface —
//! [`Policy::write_grant_spellings`], the same enumeration the OS grant
//! builders (Landlock, AppContainer DACL, SBPL, PSEC) reduce to write
//! access. Glob spellings reduce to their real base directory, the same
//! reduction the grant builders apply; a glob whose base cannot be
//! reduced still counts — unresolvable means "could cover", which stays
//! on the refuse side.
//!
//! The private per-launch TMPDIR grant is intentionally not checked:
//! it is minted at spawn time and cannot be named by an `--audit-log`
//! argument taken earlier.

use std::path::Path;

use crate::fsoverlap::{path_covers, resolve_grant_spelling};
use crate::policy::Policy;

/// `Some(conflict)` when `audit_path` falls under a write grant the
/// workload will receive — the launch must refuse. The returned text
/// names the conflicting grant and the resolved sink path.
pub fn audit_sink_write_conflict(policy: &Policy, audit_path: &Path) -> Option<String> {
    // The sink's own open reports an unresolvable path; nothing to
    // compare against here.
    let audit = resolve_grant_spelling(&audit_path.to_string_lossy())?;
    for grant in policy.write_grant_spellings() {
        let Some(g) = resolve_grant_spelling(&grant) else {
            // A grant spelling that cannot be normalized cannot be
            // proven disjoint — refuse rather than assume.
            return Some(format!(
                "grant '{grant}' cannot be resolved against audit sink '{}'",
                audit.display()
            ));
        };
        if path_covers(&g, &audit) {
            return Some(format!(
                "grant '{grant}' (resolves to '{}') covers audit sink '{}'",
                g.display(),
                audit.display()
            ));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_grant_covering_audit_parent_conflicts() {
        let dir = tempfile::tempdir().unwrap();
        let grant_root = dir.path().join("work");
        std::fs::create_dir_all(&grant_root).unwrap();
        let audit = grant_root.join("audit.jsonl");

        let mut policy = Policy::default();
        policy.fs.read_write = vec![grant_root.to_string_lossy().into_owned()];

        let conflict = audit_sink_write_conflict(&policy, &audit);
        assert!(conflict.is_some(), "audit under a write grant must refuse");
    }

    #[test]
    fn audit_outside_grants_is_clean() {
        let dir = tempfile::tempdir().unwrap();
        let grant_root = dir.path().join("work");
        let audit_dir = dir.path().join("audit");
        std::fs::create_dir_all(&grant_root).unwrap();
        std::fs::create_dir_all(&audit_dir).unwrap();
        let audit = audit_dir.join("audit.jsonl");

        let mut policy = Policy::default();
        policy.fs.read_write = vec![grant_root.to_string_lossy().into_owned()];

        assert!(audit_sink_write_conflict(&policy, &audit).is_none());
    }

    #[test]
    fn exact_file_grant_conflicts() {
        let dir = tempfile::tempdir().unwrap();
        let audit = dir.path().join("audit.jsonl");
        std::fs::write(&audit, b"").unwrap();

        let mut policy = Policy::default();
        policy.fs.read_write = vec![audit.to_string_lossy().into_owned()];

        assert!(audit_sink_write_conflict(&policy, &audit).is_some());
    }

    #[test]
    fn sibling_spelling_does_not_conflict() {
        // `audit` and `audit.jsonl` share a string prefix but not a
        // path-component prefix — the common false positive.
        let dir = tempfile::tempdir().unwrap();
        let grant = dir.path().join("audit");
        std::fs::create_dir_all(&grant).unwrap();
        let audit = dir.path().join("audit.jsonl");

        let mut policy = Policy::default();
        policy.fs.read_write = vec![grant.to_string_lossy().into_owned()];

        assert!(audit_sink_write_conflict(&policy, &audit).is_none());
    }

    #[test]
    fn glob_grant_conflicts_through_its_base() {
        let dir = tempfile::tempdir().unwrap();
        let grant_root = dir.path().join("work");
        std::fs::create_dir_all(&grant_root).unwrap();
        let audit = grant_root.join("sub").join("audit.jsonl");

        let mut policy = Policy::default();
        policy.fs.read_write = vec![format!("{}/**", grant_root.display())];

        assert!(audit_sink_write_conflict(&policy, &audit).is_some());
    }

    #[test]
    fn tool_read_write_conflicts() {
        let dir = tempfile::tempdir().unwrap();
        let grant_root = dir.path().join("tooldir");
        std::fs::create_dir_all(&grant_root).unwrap();
        let audit = grant_root.join("audit.jsonl");

        let mut fs = crate::policy::FsToolPolicy::new(vec![], vec![]);
        fs.read_write_paths = vec![grant_root.to_string_lossy().into_owned()];
        let mut policy = Policy::default();
        policy.tools.push(crate::policy::ToolPolicy {
            name: "fs_write".to_string(),
            allowed: true,
            args_schema: None,
            side_effect: None,
            server: None,
            fs: Some(fs),
            syscalls: None,
            network: None,
            input_responses: crate::policy::InputResponsesMode::Auto,
            input_responses_specified: false,
            fs_explicit: true,
            network_explicit: false,
            syscalls_explicit: false,
            environment_explicit: false,
            process_exec_allowed: false,
            process_explicit: false,
            deputy: None,
        });

        assert!(audit_sink_write_conflict(&policy, &audit).is_some());
    }

    #[test]
    fn denied_grant_spelling_is_skipped() {
        let dir = tempfile::tempdir().unwrap();
        let grant_root = dir.path().join("work");
        std::fs::create_dir_all(&grant_root).unwrap();
        let audit = grant_root.join("audit.jsonl");

        let mut policy = Policy::default();
        let g = grant_root.to_string_lossy().into_owned();
        policy.fs.read_write = vec![g.clone()];
        policy.fs.denied_paths = vec![g];

        assert!(audit_sink_write_conflict(&policy, &audit).is_none());
    }
}
