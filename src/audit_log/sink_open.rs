//! Opening the audit sink is part of the trust boundary: the operator
//! chose the path, but a co-located actor may have planted a link at
//! the leaf or anywhere along the ancestor chain, and a file created
//! with ambient permissions leaks security metadata to other local
//! users. `open_audit_sink` therefore binds the append handle to the
//! verified object instead of trusting the spelling:
//!
//! - Ancestor components are resolved without following links (Unix:
//!   per-component `openat` with `O_DIRECTORY|O_NOFOLLOW`; Windows:
//!   reparse-point refusal per ancestor).
//! - The leaf opens `O_NOFOLLOW` (Unix) / `FILE_FLAG_OPEN_REPARSE_POINT`
//!   + attribute check (Windows), so a link swapped in after the
//!     metadata check fails the open rather than being followed through.
//! - The opened handle is fstat-verified as a regular file, its owner
//!   must be the effective user (Unix), and it is tightened to
//!   owner-only access — `fchmod(0600)` on Unix, an owner+SYSTEM
//!   protected DACL on Windows — so an existing broadly readable sink
//!   is repaired and a sink that cannot be made private is refused.
//! - The parent directory handle is returned for a freshly created
//!   file so the writer can fsync the *same* directory entry the
//!   create landed in — no path re-resolution.

use std::fs;
use std::io;
use std::path::Path;

/// The verified sink: the append handle, the parent-directory handle
/// the file's entry is fsynced and re-verified through (Unix only —
/// Windows commits and re-checks the entry through the file's own
/// handle), and the leaf name the entry check resolves under that
/// directory.
pub(crate) struct OpenedSink {
    pub file: fs::File,
    pub dir: Option<fs::File>,
    /// The leaf the visible-entry proof looks up under `dir` —
    /// `Some` whenever `dir` is held. Always `None` on Windows.
    pub leaf: Option<std::ffi::OsString>,
}

/// `true` when the sink's leaf name under its pinned parent still
/// names the same object the open returned — a directory entry swapped
/// out after verification would hide the committed records behind a
/// substitute the handle never wrote to. The writer runs this before
/// acknowledging durable commits and at shutdown. `path` is the
/// configured sink spelling: the pinned fd binds the parent's *inode*,
/// not its name, so the check first proves the configured parent still
/// resolves to that inode — a renamed-away directory would leave the
/// committed records under a name `path` no longer reaches.
#[cfg(unix)]
pub(crate) fn entry_names_opened_file(
    dir: Option<&fs::File>,
    path: &Path,
    leaf: Option<&std::ffi::OsStr>,
    file: &fs::File,
) -> io::Result<bool> {
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::MetadataExt;
    use std::os::unix::io::AsRawFd;

    let (Some(dir), Some(leaf)) = (dir, leaf) else {
        return Ok(true);
    };
    // `path`'s parent must still resolve to the pinned directory —
    // `fs::metadata` re-resolves the configured spelling (any symlink
    // planted in the chain redirecting to the *same* inode is a benign
    // aliasing; a different inode is a moved binding). A parent that no
    // longer resolves at all hides the records just as a swap does.
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    match fs::metadata(parent) {
        Ok(pmeta) => {
            let dmeta = dir.metadata()?;
            if pmeta.dev() != dmeta.dev() || pmeta.ino() != dmeta.ino() {
                return Ok(false);
            }
        }
        Err(_) => return Ok(false),
    }
    let c = std::ffi::CString::new(leaf.as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "audit leaf contains NUL"))?;
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    let rc = unsafe {
        libc::fstatat(
            dir.as_raw_fd(),
            c.as_ptr(),
            &mut st,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if rc != 0 {
        // Missing or unreadable — the entry no longer names anything
        // the handle wrote, so the records are hidden regardless of
        // what the lookup failed on.
        return Ok(false);
    }
    if (st.st_mode & libc::S_IFMT) != libc::S_IFREG {
        return Ok(false);
    }
    let meta = file.metadata()?;
    // `st_dev` is `dev_t` — `i32` on macOS, `u64` on Linux — so the
    // widen is required on one target and a deliberate no-op cast on
    // the other.
    #[allow(clippy::unnecessary_cast)]
    let same_object = st.st_dev as u64 == meta.dev() && st.st_ino == meta.ino();
    Ok(same_object)
}

/// Non-Unix counterpart of [`entry_names_opened_file`]. On Windows
/// the sink handle itself pins the leaf entry — the open denies
/// delete-sharing (see `open_audit_sink_impl`), so the name cannot be
/// swapped for another object while held. What remains checkable is
/// that the handle still sits at the configured literal spelling —
/// an ancestor rename or junction swap would move its real path off
/// `path`, which `opened_at_literal_path` reports.
#[cfg(windows)]
pub(crate) fn entry_names_opened_file(
    _dir: Option<&fs::File>,
    path: &Path,
    _leaf: Option<&std::ffi::OsStr>,
    file: &fs::File,
) -> io::Result<bool> {
    crate::fspriv::opened_at_literal_path(file, path)
}

/// Targets without a directory-entry binding verify nothing.
#[cfg(not(any(unix, windows)))]
pub(crate) fn entry_names_opened_file(
    _dir: Option<&fs::File>,
    _path: &Path,
    _leaf: Option<&std::ffi::OsStr>,
    _file: &fs::File,
) -> io::Result<bool> {
    Ok(true)
}

pub(crate) fn open_audit_sink(path: &Path) -> io::Result<OpenedSink> {
    // A replaceable ancestor lets a lower-trust principal swap the
    // sink's containing directory out from under the verified walk —
    // committed records would land wherever the substitute points.
    // The per-component `O_NOFOLLOW`/reparse open below pins the path
    // it resolved; this proves the resolved path was worth pinning.
    crate::fspriv::require_unreplaceable_ancestry(path)?;
    open_audit_sink_impl(path)
}

#[cfg(unix)]
fn open_audit_sink_impl(path: &Path) -> io::Result<OpenedSink> {
    use std::ffi::{CString, OsStr};
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::MetadataExt;
    use std::os::unix::io::{AsRawFd, FromRawFd};

    fn cname(name: &OsStr) -> io::Result<CString> {
        CString::new(name.as_bytes()).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "audit log path component contains NUL",
            )
        })
    }

    // One ancestor step: open `name` beneath `dir` (or the cwd) as a
    // real directory, never through a link — a planted symlink in the
    // chain fails the walk instead of redirecting the sink.
    fn openat_dir(dir: Option<&fs::File>, name: &OsStr) -> io::Result<fs::File> {
        let c = cname(name)?;
        let at = dir.map(|d| d.as_raw_fd()).unwrap_or(libc::AT_FDCWD);
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        let fd = unsafe {
            libc::openat(
                at,
                c.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        Ok(unsafe { fs::File::from_raw_fd(fd) })
    }

    let mut comps = path.components().peekable();
    let mut dir: Option<fs::File> = None;
    let mut leaf_os: Option<std::ffi::OsString> = None;
    while let Some(comp) = comps.next() {
        let is_last = comps.peek().is_none();
        match comp {
            std::path::Component::RootDir => {
                dir = Some(openat_dir(dir.as_ref(), OsStr::new("/"))?);
            }
            std::path::Component::CurDir => {
                dir = Some(openat_dir(dir.as_ref(), OsStr::new("."))?);
            }
            std::path::Component::ParentDir => {
                dir = Some(openat_dir(dir.as_ref(), OsStr::new(".."))?);
            }
            std::path::Component::Normal(name) => {
                if is_last {
                    leaf_os = Some(name.to_os_string());
                } else {
                    dir = Some(openat_dir(dir.as_ref(), name)?);
                }
            }
            std::path::Component::Prefix(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "Windows path prefix on a Unix sink",
                ));
            }
        }
    }
    let Some(leaf_os) = leaf_os else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("audit log '{}' names no file", path.display()),
        ));
    };
    let leaf = cname(&leaf_os)?;

    // A pre-existing leaf must already be a regular file — a link,
    // FIFO, or device at the sink path is refused before the open.
    let at = dir
        .as_ref()
        .map(|d| d.as_raw_fd())
        .unwrap_or(libc::AT_FDCWD);
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    let rc = unsafe { libc::fstatat(at, leaf.as_ptr(), &mut st, libc::AT_SYMLINK_NOFOLLOW) };
    if rc == 0 {
        if (st.st_mode & libc::S_IFMT) != libc::S_IFREG {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("audit log '{}' is not a regular file", path.display()),
            ));
        }
    } else {
        let e = io::Error::last_os_error();
        if e.raw_os_error() != Some(libc::ENOENT) {
            return Err(e);
        }
    }

    // `O_NOFOLLOW` re-checks the leaf at open — a link swapped in
    // after `fstatat` fails the open rather than being followed.
    // `O_NONBLOCK` keeps a raced FIFO from blocking the open; the
    // fstat below still gates the type, and the flag is cleared
    // before the handle is handed on.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    let fd = unsafe {
        libc::openat(
            at,
            leaf.as_ptr(),
            libc::O_WRONLY
                | libc::O_CREAT
                | libc::O_APPEND
                | libc::O_NOFOLLOW
                | libc::O_NONBLOCK
                | libc::O_CLOEXEC,
            0o600,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    let file = unsafe { fs::File::from_raw_fd(fd) };
    let meta = file.metadata()?;
    if !meta.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("audit log '{}' is not a regular file", path.display()),
        ));
    }
    // A file owned by another uid can be rewritten or truncated by
    // that uid — the audit record must live in an object the logging
    // identity owns. `MCP_WRIT_ALLOW_REPLACEABLE_PATHS` waives the
    // check for shared trees whose ownership cannot map to the
    // logging identity (drvfs or network mounts) — the same
    // documented downgrade the ancestry gate takes.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    let euid = unsafe { libc::geteuid() };
    if !crate::fspriv::replaceable_permitted_for(path) && meta.uid() != euid {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "audit log '{}' is owned by uid {}, expected {euid}",
                path.display(),
                meta.uid(),
            ),
        ));
    }
    // Owner-only, applied to the opened handle: a broadly readable
    // pre-created sink is tightened rather than trusted, and a sink
    // that cannot be tightened is refused — unless the opt-out is
    // armed, where a mount that cannot chmod runs untightened under
    // the same documented downgrade.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    if unsafe { libc::fchmod(file.as_raw_fd(), 0o600) } != 0
        && !crate::fspriv::replaceable_permitted_for(path)
    {
        return Err(io::Error::last_os_error());
    }
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    unsafe {
        let fl = libc::fcntl(file.as_raw_fd(), libc::F_GETFL);
        if fl >= 0 {
            libc::fcntl(file.as_raw_fd(), libc::F_SETFL, fl & !libc::O_NONBLOCK);
        }
    }
    // The parent handle is retained for every open, not just a fresh
    // file's entry fsync — `entry_names_opened_file` re-resolves the
    // leaf under it before durable-commit acknowledgments so a
    // swapped-out entry cannot hide the records this handle wrote.
    let dir = match dir {
        Some(d) => d,
        None => openat_dir(None, OsStr::new("."))?,
    };
    Ok(OpenedSink {
        file,
        dir: Some(dir),
        leaf: Some(leaf_os),
    })
}

#[cfg(windows)]
fn open_audit_sink_impl(path: &Path) -> io::Result<OpenedSink> {
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
    use windows::Win32::Storage::FileSystem::{
        FILE_APPEND_DATA, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ, FILE_SHARE_WRITE,
    };

    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    const SYNCHRONIZE: u32 = 0x0010_0000;
    const READ_CONTROL: u32 = 0x0002_0000;
    const WRITE_DAC: u32 = 0x0004_0000;

    // Ancestor components must resolve without redirect — a
    // symlink/junction/mount point in the chain would land the sink
    // outside the operator's directory. This path-based walk is only
    // the fast reject: a directory swapped for a junction *between*
    // the check and the open below is caught by the
    // `opened_at_literal_path` proof on the handle, which the
    // spellings can never satisfy through a redirect.
    crate::fspriv::require_no_reparse_ancestors(path)?;

    // `FILE_FLAG_OPEN_REPARSE_POINT` opens a leaf link itself instead
    // of its target, so the attribute check refuses it rather than
    // appending through to a redirected file. `WRITE_DAC` is requested
    // at open time because `restrict_handle_owner_only` below calls
    // `SetSecurityInfo` on this handle — an append-only handle carries
    // no DACL rights and the call would fail `ACCESS_DENIED`.
    // The share mode omits `FILE_SHARE_DELETE`: while this handle is
    // held the leaf entry cannot be renamed or replaced, which is what
    // makes `entry_names_opened_file`'s literal-path re-check the whole
    // binding rather than a best-effort snapshot.
    let file = fs::OpenOptions::new()
        .append(true)
        .create(true)
        .access_mode(FILE_APPEND_DATA.0 | SYNCHRONIZE | READ_CONTROL | WRITE_DAC)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT.0)
        .share_mode(FILE_SHARE_READ.0 | FILE_SHARE_WRITE.0)
        .open(path)?;
    let meta = file.metadata()?;
    if meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 || !meta.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "audit log '{}' is a link or non-regular entry",
                path.display()
            ),
        ));
    }
    // The open must have landed at the literal spelling — an ancestor
    // swapped for a junction between the walk and the open shows up as
    // a different real path on the handle.
    if !crate::fspriv::opened_at_literal_path(&file, path)? {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "audit log '{}' resolved outside its literal path",
                path.display()
            ),
        ));
    }
    // A pre-existing sink whose owner is a foreign principal keeps
    // implicit WRITE_DAC control over the audit record — only an owner
    // the logging identity itself (or SYSTEM/Administrators) represents
    // is trusted. `MCP_WRIT_ALLOW_REPLACEABLE_PATHS` waives the check
    // for shared trees whose owner SIDs cannot map to the logging
    // identity (a host-mapped share) — the same documented downgrade
    // the ancestry gate takes.
    if !crate::fspriv::replaceable_permitted_for(path)
        && !crate::fspriv::handle_owner_is_trusted(&file, true)?
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "audit log '{}' is owned by an untrusted principal",
                path.display()
            ),
        ));
    }
    // Owner+SYSTEM protected DACL on the opened handle — the same
    // contract as the Unix 0600 mode, without a path re-resolution a
    // swapped name could redirect. Under the opt-out a share that
    // cannot store a DACL runs untightened — the same downgrade.
    if let Err(e) = crate::fspriv::restrict_handle_owner_only(&file)
        && !crate::fspriv::replaceable_permitted_for(path)
    {
        return Err(io::Error::new(
            e.kind(),
            format!("cannot make audit log '{}' private: {e}", path.display()),
        ));
    }
    Ok(OpenedSink {
        file,
        dir: None,
        leaf: None,
    })
}
