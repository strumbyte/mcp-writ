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

/// `Some(conflict)` when `audit_path` falls under a write grant the
/// workload will receive — the launch must refuse. `write_grants` is the
/// workload's effective write-grant spellings
/// (`Policy::write_grant_spellings`), enumerated by the caller so this
/// leaf does not depend on `policy`. The returned text names the
/// conflicting grant and the resolved sink path.
pub fn audit_sink_write_conflict(
    write_grants: impl IntoIterator<Item = String>,
    audit_path: &Path,
) -> Option<String> {
    protected_path_write_conflict(write_grants, audit_path, "audit sink")
}

/// `Some(conflict)` when `snapshot_path` falls under a write grant the
/// workload will receive — the launch must refuse. A workload that can
/// write or rename its own `--allowlist` snapshot mints the grants its
/// own egress depends on, which is exactly the privilege the snapshot
/// contract takes away.
pub fn snapshot_write_conflict(
    write_grants: impl IntoIterator<Item = String>,
    snapshot_path: &Path,
) -> Option<String> {
    protected_path_write_conflict(write_grants, snapshot_path, "allowlist snapshot")
}

/// Shared coverage check: `Some(conflict)` when `protected_path`
/// (resolved the way a grant spelling resolves) falls under any
/// workload write grant, or when a grant spelling cannot be proven
/// disjoint. `label` names the protected object in the diagnostic.
fn protected_path_write_conflict(
    write_grants: impl IntoIterator<Item = String>,
    protected_path: &Path,
    label: &str,
) -> Option<String> {
    // The object's own open reports an unresolvable path; nothing to
    // compare against here.
    let protected = resolve_grant_spelling(&protected_path.to_string_lossy())?;
    for grant in write_grants {
        let Some(g) = resolve_grant_spelling(&grant) else {
            // A grant spelling that cannot be normalized cannot be
            // proven disjoint — refuse rather than assume.
            return Some(format!(
                "grant '{grant}' cannot be resolved against {label} '{}'",
                protected.display()
            ));
        };
        if path_covers(&g, &protected) {
            return Some(format!(
                "grant '{grant}' (resolves to '{}') covers {label} '{}'",
                g.display(),
                protected.display()
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

        let grants = vec![grant_root.to_string_lossy().into_owned()];

        let conflict = audit_sink_write_conflict(grants, &audit);
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

        let grants = vec![grant_root.to_string_lossy().into_owned()];

        assert!(audit_sink_write_conflict(grants, &audit).is_none());
    }

    #[test]
    fn exact_file_grant_conflicts() {
        let dir = tempfile::tempdir().unwrap();
        let audit = dir.path().join("audit.jsonl");
        std::fs::write(&audit, b"").unwrap();

        let grants = vec![audit.to_string_lossy().into_owned()];

        assert!(audit_sink_write_conflict(grants, &audit).is_some());
    }

    #[test]
    fn sibling_spelling_does_not_conflict() {
        // `audit` and `audit.jsonl` share a string prefix but not a
        // path-component prefix — the common false positive.
        let dir = tempfile::tempdir().unwrap();
        let grant = dir.path().join("audit");
        std::fs::create_dir_all(&grant).unwrap();
        let audit = dir.path().join("audit.jsonl");

        let grants = vec![grant.to_string_lossy().into_owned()];

        assert!(audit_sink_write_conflict(grants, &audit).is_none());
    }

    #[test]
    fn glob_grant_conflicts_through_its_base() {
        let dir = tempfile::tempdir().unwrap();
        let grant_root = dir.path().join("work");
        std::fs::create_dir_all(&grant_root).unwrap();
        let audit = grant_root.join("sub").join("audit.jsonl");

        let grants = vec![format!("{}/**", grant_root.display())];

        assert!(audit_sink_write_conflict(grants, &audit).is_some());
    }

    #[test]
    fn multiple_grants_any_conflict_reports() {
        let dir = tempfile::tempdir().unwrap();
        let grant_root = dir.path().join("tooldir");
        std::fs::create_dir_all(&grant_root).unwrap();
        let audit = grant_root.join("audit.jsonl");

        let grants = vec![
            dir.path().join("elsewhere").to_string_lossy().into_owned(),
            grant_root.to_string_lossy().into_owned(),
        ];

        assert!(audit_sink_write_conflict(grants, &audit).is_some());
    }

    #[test]
    fn snapshot_under_write_grant_conflicts() {
        // The allowlist snapshot is a protected object exactly like
        // the audit sink: a grant covering it (directly or through a
        // replaceable parent) must refuse the launch.
        let dir = tempfile::tempdir().unwrap();
        let grant_root = dir.path().join("work");
        std::fs::create_dir_all(&grant_root).unwrap();
        let snapshot = grant_root.join("allowlist.json");

        let grants = vec![grant_root.to_string_lossy().into_owned()];
        let conflict = snapshot_write_conflict(grants, &snapshot);
        assert!(conflict.is_some());
        assert!(conflict.unwrap().contains("allowlist snapshot"));

        // A snapshot outside every grant is clean.
        let elsewhere = dir.path().join("private");
        std::fs::create_dir_all(&elsewhere).unwrap();
        let snapshot = elsewhere.join("allowlist.json");
        let grants = vec![grant_root.to_string_lossy().into_owned()];
        assert!(snapshot_write_conflict(grants, &snapshot).is_none());
    }

    #[test]
    fn no_grants_never_conflicts() {
        // `Policy::write_grant_spellings` already drops denied spellings;
        // an empty effective list cannot conflict.
        let dir = tempfile::tempdir().unwrap();
        let audit = dir.path().join("audit.jsonl");

        assert!(audit_sink_write_conflict(Vec::new(), &audit).is_none());
    }
}
