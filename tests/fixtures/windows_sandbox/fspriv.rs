// std-only stand-in for `src/fspriv.rs` inside the plain-rustc fixture
// crate: `agent.rs` refers to `crate::fspriv`, which resolves to this
// file's parent (the fixture root) — the shipped module's Windows arms
// need the `windows` crate, which the rustc fixture build has no access
// to. Same signatures and skip semantics for the legs this fixture
// exercises: links and other non-regular entries are `Skipped`, copies
// are proven inside `canonical_root`, and `Copied` carries the byte
// count. The shipped module's handle-pinned no-follow and DACL
// hardening are not representable in std — the loopback harness stages
// host-written regular files only, so that gap never widens a leg.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

#[allow(dead_code)] // `Copied`'s byte count is read by other shipped callers
pub enum SafeCopyOutcome {
    /// Bytes copied from the verified open file.
    Copied(u64),
    /// A link or other non-regular entry — never followed, never copied.
    Skipped,
}

/// Resolve `dir` for use as the `canonical_root` argument of
/// [`safe_copy_file`].
pub fn canonical_root(dir: &Path) -> io::Result<PathBuf> {
    fs::canonicalize(dir)
}

/// Copy `src` to `dst` only while it provably resolves inside
/// `canonical_root`; links and other non-regular entries are `Skipped`.
pub fn safe_copy_file(
    src: &Path,
    dst: &Path,
    canonical_root: &Path,
) -> io::Result<SafeCopyOutcome> {
    let meta = fs::symlink_metadata(src)?;
    if !meta.file_type().is_file() {
        return Ok(SafeCopyOutcome::Skipped);
    }
    if !fs::canonicalize(src)?.starts_with(canonical_root) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "refusing to copy '{}': resolves outside the staged root",
                src.display()
            ),
        ));
    }
    if let Some(parent) = dst.parent() {
        fs::create_dir_all(parent)?;
    }
    let bytes = fs::copy(src, dst)?;
    // Carry the source mode (executables must stay executable).
    fs::set_permissions(dst, meta.permissions())?;
    Ok(SafeCopyOutcome::Copied(bytes))
}
