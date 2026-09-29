//! `sandbox-exec` helper resolution for the macOS sandbox.
//!
//! The helper is launched by its absolute system path — `PATH` is never
//! consulted. An earlier `PATH` entry under attacker control could supply
//! a substitute helper that runs the workload with no SBPL profile at
//! all, so before every spawn the file at [`SANDBOX_EXEC_PATH`] is
//! validated as the expected system object: a regular executable file
//! that resolves to itself (no symlink substitution), is owned by root,
//! and is not writable by group or others. A missing, replaced, or
//! downgraded helper refuses the enforcing launch instead of running
//! unsandboxed.
//!
//! The module is compiled for macOS launches and for the unit tests that
//! exercise the validation on any Unix host.

use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use crate::error::{SandboxStage, WardenError};

/// The only `sandbox-exec` the launcher accepts — absolute, `PATH`-free.
pub(super) const SANDBOX_EXEC_PATH: &str = "/usr/bin/sandbox-exec";

/// Path of the trusted `sandbox-exec` helper — [`SANDBOX_EXEC_PATH`],
/// validated as the expected system object. Never consults `PATH`, so a
/// helper planted earlier in `PATH` is never even a candidate.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub(super) fn sandbox_exec_path() -> Result<PathBuf, WardenError> {
    validate_helper(Path::new(SANDBOX_EXEC_PATH))
}

/// `path` names the trusted helper when it resolves to itself (no
/// symlink substitution), is a regular file, is owned by root, and is
/// not writable by group or others. Anything less refuses the launch.
fn validate_helper(path: &Path) -> Result<PathBuf, WardenError> {
    let reject = |detail: String| -> WardenError {
        WardenError::sandbox_setup(SandboxStage::Prepare, detail)
    };
    let canonical = fs::canonicalize(path).map_err(|e| {
        reject(format!(
            "sandbox-exec helper '{}' is not usable: {e}",
            path.display()
        ))
    })?;
    if canonical != path {
        return Err(reject(format!(
            "sandbox-exec helper '{}' resolves to '{}' — refusing a substituted helper",
            path.display(),
            canonical.display()
        )));
    }
    let meta = fs::metadata(&canonical).map_err(|e| {
        reject(format!(
            "sandbox-exec helper '{}' cannot be inspected: {e}",
            path.display()
        ))
    })?;
    if !helper_metadata_is_trusted(&meta) {
        return Err(reject(format!(
            "sandbox-exec helper '{}' is not a root-owned, non-writable system executable",
            path.display()
        )));
    }
    Ok(canonical)
}

/// The helper must be a regular executable file, owned by root, that
/// group and other users cannot write — properties SIP already gives
/// the real system binary, asserted here so a planted or weakened file
/// is never invoked.
fn helper_metadata_is_trusted(meta: &fs::Metadata) -> bool {
    meta.is_file() && meta.uid() == 0 && (meta.mode() & 0o022) == 0 && (meta.mode() & 0o111) != 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;

    /// The helper is always reached by its absolute system path — never
    /// through `PATH`, so a fake `sandbox-exec` earlier in `PATH` is
    /// never invoked.
    #[test]
    fn helper_path_is_the_absolute_system_binary() {
        assert_eq!(SANDBOX_EXEC_PATH, "/usr/bin/sandbox-exec");
        assert!(Path::new(SANDBOX_EXEC_PATH).is_absolute());
    }

    /// A helper that does not exist — or cannot be validated — refuses
    /// the enforcing launch rather than running unsandboxed.
    #[test]
    fn missing_helper_is_rejected() {
        let err = validate_helper(Path::new("/definitely/not/sandbox-exec")).unwrap_err();
        assert!(err.to_string().contains("sandbox-exec helper"));
    }

    /// The helper must be a non-group/other-writable regular file —
    /// attacker-writable or replaced helpers are refused even when the
    /// test happens to run as root.
    #[test]
    fn writable_or_non_file_helper_is_rejected() {
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        tmp.write_all(b"#!/bin/sh\n").unwrap();

        std::fs::set_permissions(tmp.path(), fs::Permissions::from_mode(0o777)).unwrap();
        let meta = tmp.path().metadata().unwrap();
        assert!(!helper_metadata_is_trusted(&meta));
        assert!(validate_helper(tmp.path()).is_err());

        // Non-writable + executable: trusted exactly when root-owned.
        std::fs::set_permissions(tmp.path(), fs::Permissions::from_mode(0o755)).unwrap();
        let meta = tmp.path().metadata().unwrap();
        assert_eq!(helper_metadata_is_trusted(&meta), meta.uid() == 0);

        // A directory is never a helper.
        let dir = tempfile::tempdir().unwrap();
        assert!(!helper_metadata_is_trusted(&dir.path().metadata().unwrap()));
    }

    /// A symlink planted at the helper location must not be followed:
    /// the path must resolve to itself or the launch is refused.
    #[test]
    fn symlinked_helper_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("real-sandbox-exec");
        std::fs::write(&target, "#!/bin/sh\n").unwrap();
        let link = dir.path().join("sandbox-exec");
        std::os::unix::fs::symlink(&target, &link).unwrap();

        let err = validate_helper(&link).unwrap_err();
        assert!(err.to_string().contains("sandbox-exec helper"));
    }
}
