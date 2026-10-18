//! Helpers shared by `#[cfg(test)]` modules across the crate.

use std::path::PathBuf;

/// Real spelling of the system temp dir, resolving platform links such
/// as macOS's `/var` → `/private/var`. Paths under `$TMPDIR` are handed
/// to the audit sink and other strict `O_NOFOLLOW` ancestor walks, which
/// refuse any linked component — tests must spell them the way the
/// filesystem actually lays them out. The verbatim `\\?\` prefix Windows
/// canonicalize adds is stripped — device-namespace spellings break
/// `current_dir` and policy authorization.
pub(crate) fn real_temp_base() -> PathBuf {
    let base = std::env::temp_dir() // nosemgrep: rust.lang.security.temp-dir.temp-dir
        .canonicalize()
        .unwrap_or_else(|_| std::env::temp_dir()); // nosemgrep: rust.lang.security.temp-dir.temp-dir
    #[cfg(windows)]
    let base = {
        let s = base.to_string_lossy();
        if let Some(rest) = s.strip_prefix(r"\\?\UNC\") {
            PathBuf::from(format!(r"\\{rest}"))
        } else {
            s.strip_prefix(r"\\?\").map(PathBuf::from).unwrap_or(base)
        }
    };
    base
}

/// `tempfile::tempdir()` rooted at [`real_temp_base`].
pub(crate) fn real_tempdir() -> std::io::Result<tempfile::TempDir> {
    tempfile::Builder::new().tempdir_in(real_temp_base())
}
