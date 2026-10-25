//! Bounded reads and the atomic write: a file's bytes are only ever
//! taken from a handle whose open already proved what the object is
//! (no-follow, nonblocking, in-root where required), and a report is
//! installed by rename over a verified destination so a link at the
//! target is replaced rather than written through.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use super::handle::{open_no_follow, real_path_of};

/// Write `contents` to `path` atomically: an unpredictable sibling
/// temp file created with `create_new` (a planted link or file at the
/// temp name fails the open instead of being followed), synced, then
/// renamed over `path`. The rename replaces a symlink at `path`
/// outright — it never writes through to the link's target, which is
/// the difference between this and reopening `path` for `write` after
/// a caller-side validation.
///
/// Windows additionally pins the destination's *ancestry*: existing
/// ancestors must be real directories (no junction/mount substitution)
/// whose DACLs deny replace rights to broad principals, the temp file
/// gets an owner+SYSTEM DACL on its handle before the rename, and the
/// renamed handle's real path must equal the literal spelling — a
/// junction swapped into the chain after the checks fails the proof
/// instead of landing the report at a redirected location.
pub fn write_file_atomic(path: &Path, contents: &[u8]) -> io::Result<()> {
    #[cfg(windows)]
    {
        super::winsec::require_no_reparse_ancestors(path)?;
    }
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or_default();
    let mut tmp_os = path.as_os_str().to_os_string();
    tmp_os.push(format!(".tmp-{}-{nanos}", std::process::id()));
    let tmp = PathBuf::from(tmp_os);
    // `create_new` failing means the temp name is already taken (e.g.
    // planted) — that file is not ours to delete, so the cleanup below
    // only runs once this open succeeded.
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        // A report carries policy and path detail — pin a restrictive
        // mode instead of letting the process umask decide read access.
        opts.mode(0o600);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        use windows::Win32::Storage::FileSystem::{FILE_GENERIC_WRITE, WRITE_DAC};
        // `restrict_handle_owner_only` calls `SetSecurityInfo` on this
        // handle — a plain write handle carries no DACL rights, so the
        // open must request WRITE_DAC alongside the data-write rights or
        // the rewrite fails ACCESS_DENIED.
        opts.access_mode((FILE_GENERIC_WRITE | WRITE_DAC).0);
    }
    let mut file = opts.open(&tmp)?;
    #[cfg(windows)]
    let mut renamed = false;
    let result = (|| -> io::Result<()> {
        use std::io::Write;
        #[cfg(windows)]
        {
            // Owner+SYSTEM protected DACL applied to the open handle —
            // an inherited broad DACL on the temp name is replaced
            // before the contents land at the destination.
            super::tempdir::restrict_handle_owner_only(&file)?;
        }
        file.write_all(contents)?;
        file.sync_data()?;
        fs::rename(&tmp, path)?;
        #[cfg(windows)]
        {
            renamed = true;
            // The rename resolved the destination *parent* by name —
            // prove the handle's final path is the literal spelling so
            // a junction swapped into the chain between the checks and
            // the rename cannot redirect the report.
            if !super::winsec::opened_at_literal_path(&file, path)? {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!(
                        "rename destination '{}' resolved outside its literal path",
                        path.display()
                    ),
                ));
            }
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
        #[cfg(windows)]
        {
            // Only once the rename has landed is `path` ours to remove —
            // a failure before it left any pre-existing destination
            // intact, and deleting it would destroy a file this write
            // never touched. After it, remove the placed file rather
            // than leave a report where a redirect check refused it.
            if renamed {
                let _ = fs::remove_file(path);
            }
        }
    }
    result
}

/// Read a whole file only when it fits within `limit` bytes — the read
/// is refused rather than truncated so analysis never silently runs on
/// a prefix. The open is no-follow and nonblocking so a FIFO, device,
/// or retargeted link can neither substitute bytes nor hang the read;
/// a file grown past the limit check is still cut at `limit` and
/// refused.
pub fn read_file_bounded(path: &Path, limit: u64) -> io::Result<Vec<u8>> {
    use std::io::Read;
    let Some(file) = open_no_follow(path)? else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("'{}' is a link or non-regular entry", path.display()),
        ));
    };
    let mut bytes = Vec::new();
    let n = file.take(limit + 1).read_to_end(&mut bytes)?;
    if n as u64 > limit {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "file '{}' exceeds the {}-byte analysis limit",
                path.display(),
                limit
            ),
        ));
    }
    Ok(bytes)
}

/// [`read_file_bounded`] opened through `open_no_follow`: the
/// returned bytes provably come from the object `path` named at open
/// time, so a pathname raced to a link or a different file between a
/// caller's metadata check and the read cannot substitute bytes the
/// caller never validated. `Ok(None)` for links and other non-regular
/// entries.
pub fn read_no_follow_bounded(path: &Path, limit: u64) -> io::Result<Option<Vec<u8>>> {
    use std::io::Read;
    let Some(file) = open_no_follow(path)? else {
        return Ok(None);
    };
    let mut bytes = Vec::new();
    let n = file.take(limit + 1).read_to_end(&mut bytes)?;
    if n as u64 > limit {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "file '{}' exceeds the {}-byte analysis limit",
                path.display(),
                limit
            ),
        ));
    }
    Ok(Some(bytes))
}

/// Open `path` and read it as UTF-8 text under `limit` bytes — the
/// metadata length is checked before allocation and `take` bounds the
/// read itself, so a file growing between the two cannot overrun the
/// budget. Over-limit is `InvalidData`, never a silent truncation.
/// Symlinks are followed (a policy path may legitimately be linked), but
/// the open is nonblocking and the target must be a regular file so a
/// FIFO or device cannot stall the read.
pub fn read_text_bounded_follow_links(path: &Path, limit: u64) -> io::Result<String> {
    Ok(read_text_bounded_follow_links_resolved(path, limit)?.0)
}

/// [`read_text_bounded_follow_links`] plus the opened file's real
/// path: identity and bytes come from the same open handle, so a link
/// repointed between an earlier canonicalization and this read
/// resolves to the path reported here — the identity the caller
/// records is the object actually read.
pub fn read_text_bounded_follow_links_resolved(
    path: &Path,
    limit: u64,
) -> io::Result<(String, PathBuf)> {
    use std::io::Read;
    let file = open_text_file(path)?;
    let real = real_path_of(&file)?;
    let meta = file.metadata()?;
    if !meta.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("'{}' is not a regular file", path.display()),
        ));
    }
    if meta.len() > limit {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("file '{}' exceeds the {}-byte limit", path.display(), limit),
        ));
    }
    let mut text = String::new();
    file.take(limit + 1).read_to_string(&mut text)?;
    if text.len() as u64 > limit {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("file '{}' exceeds the {}-byte limit", path.display(), limit),
        ));
    }
    Ok((text, real))
}

/// [`read_no_follow_bounded`] plus the containment proof
/// [`safe_copy_file`](super::copy::safe_copy_file) performs: the opened
/// object's real path must resolve inside `canonical_root`, checked on
/// the same open handle the bytes stream from. A link, non-regular
/// entry, out-of-root object, or oversized file is a hard error —
/// callers staging validated bytes never want a silent skip.
pub fn read_no_follow_bounded_in(
    path: &Path,
    limit: u64,
    canonical_root: &Path,
) -> io::Result<Vec<u8>> {
    use std::io::Read;
    let file = open_no_follow(path)?.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("'{}' is a link or non-regular entry", path.display()),
        )
    })?;
    let real = real_path_of(&file)?;
    if !real.starts_with(canonical_root) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "refusing to read '{}': resolves outside the staged root",
                path.display()
            ),
        ));
    }
    let mut bytes = Vec::new();
    let n = file.take(limit + 1).read_to_end(&mut bytes)?;
    if n as u64 > limit {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "file '{}' exceeds the {}-byte analysis limit",
                path.display(),
                limit
            ),
        ));
    }
    Ok(bytes)
}

/// [`read_file_bounded`] for text inputs — the UTF-8 failure is the
/// same `InvalidData` error `fs::read_to_string` raises.
pub fn read_text_bounded(path: &Path, limit: u64) -> io::Result<String> {
    let bytes = read_file_bounded(path, limit)?;
    String::from_utf8(bytes).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

/// Open `path` for [`read_text_bounded_follow_links`]: links are followed, but the
/// open never blocks on a special file. `O_NONBLOCK` makes a raced FIFO
/// return immediately; on Windows a path-level type check skips devices
/// and pipes before `CreateFile` could wait on them, and the caller's
/// post-open `is_file` still confirms the opened object.
#[cfg(unix)]
fn open_text_file(path: &Path) -> io::Result<fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)
}

#[cfg(windows)]
fn open_text_file(path: &Path) -> io::Result<fs::File> {
    if !fs::metadata(path)?.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("'{}' is not a regular file", path.display()),
        ));
    }
    fs::File::open(path)
}
