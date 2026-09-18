//! Owner-only temporary directories for policy and build staging.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

/// Create a new directory under the system temp dir with owner-only access.
///
/// Fails closed if the directory already exists or permissions cannot be set.
pub fn create_private_tempdir(label: &str) -> io::Result<PathBuf> {
    let dir = std::env::temp_dir().join(format!(
        "mcp-writ-{label}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ));
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        fs::DirBuilder::new().mode(0o700).create(&dir)?;
    }
    #[cfg(not(unix))]
    {
        fs::create_dir(&dir)?;
    }
    restrict_owner_only(&dir)?;
    Ok(dir)
}

/// Restrict `dir` to the current user. No-op restriction on Windows beyond
/// the creating user's default ACL; Unix sets mode 0700.
pub fn restrict_owner_only(dir: &Path) -> io::Result<()> {
    let meta = fs::symlink_metadata(dir)?;
    if meta.file_type().is_symlink() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("refusing to use symlink temp directory '{}'", dir.display()),
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
        let mode = fs::metadata(dir)?.permissions().mode() & 0o777;
        if mode != 0o700 {
            return Err(io::Error::other(format!(
                "failed to set owner-only permissions on '{}': mode {mode:o}",
                dir.display()
            )));
        }
    }
    Ok(())
}

/// Names that must never be copied into a generated image context.
pub fn should_skip_build_entry(name: &str) -> bool {
    name.starts_with('.')
        || name == "node_modules"
        || name == "__pycache__"
        || name == "target"
        || name == ".git"
        || name == ".env"
        || name == ".venv"
        || name == "venv"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_tempdir_is_directory() {
        let dir = create_private_tempdir("test").unwrap();
        assert!(dir.is_dir());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn skip_nested_secrets() {
        assert!(should_skip_build_entry(".env"));
        assert!(should_skip_build_entry("node_modules"));
        assert!(!should_skip_build_entry("src"));
    }
}
