//! Copy primitives that cannot be raced out of a staged source tree:
//! every copied file is opened without following a final-component
//! link and proven to resolve inside the canonicalized source root,
//! and the bytes stream from that same open handle — a pathname
//! swapped for a link mid-copy can never redirect the read to an
//! out-of-tree target. Entry and byte budgets make the traversal's
//! cost bounded rather than attacker-proportional.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use super::handle::{open_dir_handle, open_no_follow, real_path_of};

/// What [`safe_copy_file`] did with one source entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SafeCopyOutcome {
    /// Bytes copied from the verified open file.
    Copied(u64),
    /// A link or other non-regular entry — never followed, never copied.
    Skipped,
}

/// Deepest directory nesting [`safe_copy_dir`] recurses into before
/// refusing outright — a swapped link could otherwise loop the walk.
const MAX_COPY_DEPTH: usize = 64;

/// Open `src` without following a final-component link and copy it to
/// `dst`, but only while the opened object provably resolves inside
/// `canonical_root` (a `fs::canonicalize`d source directory).
///
/// The containment proof and the copy act on the same open handle, so a
/// pathname swapped for a link between the check and the read can never
/// pull in an out-of-tree file: the handle still names the object that
/// was verified. `Ok(SafeCopyOutcome::Skipped)` for links, devices,
/// pipes and other non-regular entries.
pub fn safe_copy_file(
    src: &Path,
    dst: &Path,
    canonical_root: &Path,
) -> io::Result<SafeCopyOutcome> {
    let Some(file) = open_verified_source(src, canonical_root)? else {
        return Ok(SafeCopyOutcome::Skipped);
    };
    if let Some(parent) = dst.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut from = file;
    let mut out = fs::File::create(dst)?;
    let bytes = io::copy(&mut from, &mut out)?;
    // Carry the source mode (executables must stay executable).
    fs::set_permissions(dst, from.metadata()?.permissions())?;
    Ok(SafeCopyOutcome::Copied(bytes))
}

/// [`safe_copy_file`] with a hard source byte ceiling: at most
/// `max_bytes` are ever read from the verified handle, so a file grown
/// or swapped by a local actor after any metadata pre-check cannot
/// push more than the caller's remaining budget into `dst`. When the
/// source exceeds `max_bytes` the partial destination is removed and
/// an error is returned.
pub fn safe_copy_file_bounded(
    src: &Path,
    dst: &Path,
    canonical_root: &Path,
    max_bytes: u64,
) -> io::Result<SafeCopyOutcome> {
    let Some(file) = open_verified_source(src, canonical_root)? else {
        return Ok(SafeCopyOutcome::Skipped);
    };
    if let Some(parent) = dst.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut from = io::Read::take(file, max_bytes);
    let mut out = fs::File::create(dst)?;
    let bytes = io::copy(&mut from, &mut out)?;
    // Probe one byte past the ceiling: a source that still yields data
    // grew past the budget — drop the partial copy and refuse.
    let mut extra = [0u8; 1];
    let mut from = from.into_inner();
    if io::Read::read(&mut from, &mut extra)? != 0 {
        drop(out);
        let _ = fs::remove_file(dst);
        return Err(io::Error::new(
            io::ErrorKind::QuotaExceeded,
            format!(
                "refusing to copy '{}': exceeds the remaining staging budget ({max_bytes} bytes)",
                src.display()
            ),
        ));
    }
    fs::set_permissions(dst, from.metadata()?.permissions())?;
    Ok(SafeCopyOutcome::Copied(bytes))
}

/// The open + in-root containment proof shared by the copy variants —
/// the returned handle names the object that was verified.
fn open_verified_source(src: &Path, canonical_root: &Path) -> io::Result<Option<fs::File>> {
    let Some(file) = open_no_follow(src)? else {
        return Ok(None);
    };
    let real = real_path_of(&file)?;
    if !real.starts_with(canonical_root) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "refusing to copy '{}': resolves outside the staged root",
                src.display()
            ),
        ));
    }
    Ok(Some(file))
}

/// Aggregate staging budget shared across one [`safe_copy_dir`] walk.
/// Every enumerated directory entry decrements `entries_left`, every
/// byte actually streamed decrements `bytes_left`, and each single
/// file may use at most `per_file` bytes — the ceiling is enforced by
/// the limiting copy itself, so a file grown after any metadata check
/// still cannot exceed its allowance. Exhaustion aborts the walk with
/// an error; the caller's context cleanup removes the partial tree.
pub struct CopyBudget {
    entries_left: u64,
    bytes_left: u64,
    per_file: u64,
}

impl CopyBudget {
    pub fn new(max_entries: u64, max_bytes: u64, per_file: u64) -> Self {
        Self {
            entries_left: max_entries,
            bytes_left: max_bytes,
            per_file,
        }
    }

    fn take_entry(&mut self, what: &Path) -> io::Result<()> {
        match self.entries_left.checked_sub(1) {
            Some(rest) => {
                self.entries_left = rest;
                Ok(())
            }
            None => Err(io::Error::new(
                io::ErrorKind::QuotaExceeded,
                format!("staging entry budget exceeded at '{}'", what.display()),
            )),
        }
    }
}

/// Recursively copy `src_dir`'s regular files into `dst_dir`, never
/// following links. Every leaf is verified and byte-limited by
/// [`safe_copy_file_bounded`]: a directory swapped for a link mid-walk
/// cannot smuggle an out-of-tree file in — its children fail the
/// per-file containment proof even when the enumeration itself was
/// redirected — and a file grown after enumeration cannot exceed the
/// shared byte budget. `skip_name` filters basenames (e.g.
/// `should_skip_build_entry`); `budget` makes entry, aggregate-byte,
/// and per-file limits mandatory rather than caller-optional.
pub fn safe_copy_dir(
    src_dir: &Path,
    dst_dir: &Path,
    canonical_root: &Path,
    depth: usize,
    skip_name: &dyn Fn(&str) -> bool,
    budget: &mut CopyBudget,
) -> io::Result<()> {
    if depth > MAX_COPY_DEPTH {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "directory nesting exceeds {MAX_COPY_DEPTH}: '{}'",
                src_dir.display()
            ),
        ));
    }
    fs::create_dir_all(dst_dir)?;
    for entry in fs::read_dir(src_dir)? {
        let entry = entry?;
        let name = entry.file_name();
        // Enumeration itself is attacker-proportional work — count
        // every entry, not just the files that end up copied.
        budget.take_entry(&entry.path())?;
        if skip_name(&name.to_string_lossy()) {
            continue;
        }
        let kind = entry.file_type()?;
        let src = entry.path();
        let dst = dst_dir.join(&name);
        if kind.is_dir() {
            safe_copy_dir(&src, &dst, canonical_root, depth + 1, skip_name, budget)?;
        } else if kind.is_file() {
            let allowance = budget.per_file.min(budget.bytes_left);
            match safe_copy_file_bounded(&src, &dst, canonical_root, allowance)? {
                SafeCopyOutcome::Copied(n) => budget.bytes_left -= n,
                SafeCopyOutcome::Skipped => {}
            }
        }
        // Anything else — links, sockets, devices — is never followed.
    }
    Ok(())
}

/// Resolve `dir` for use as the `canonical_root` argument of the
/// safe-copy functions.
///
/// The root is resolved through the same handle-based primitive
/// `real_path_of` uses, so the containment `starts_with` compares
/// paths on one normalization basis. On Windows `fs::canonicalize`
/// expands 8.3 short-name components while `GetFinalPathNameByHandle`
/// keeps the spelling used at open — mixing the two either refuses
/// every copy or misjudges containment. Following links here is
/// correct: the user-supplied root resolves to its target, and every
/// leaf opened beneath it resolves through the same junction.
pub fn canonical_root(dir: &Path) -> io::Result<PathBuf> {
    let root = open_dir_handle(dir)?;
    real_path_of(&root)
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
