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

/// The verified sink: the append handle, the parent-directory handle a
/// fresh file's entry is fsynced through (Unix only — Windows commits
/// the entry through the file's own flush), and whether this open
/// created the file.
pub(crate) struct OpenedSink {
    pub file: fs::File,
    pub dir: Option<fs::File>,
}

pub(crate) fn open_audit_sink(path: &Path) -> io::Result<OpenedSink> {
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
        Ok(unsafe { fs::File::from_raw_fd(fd) })
    }

    let mut comps = path.components().peekable();
    let mut dir: Option<fs::File> = None;
    let mut leaf: Option<CString> = None;
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
                    leaf = Some(cname(name)?);
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
    let Some(leaf) = leaf else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("audit log '{}' names no file", path.display()),
        ));
    };

    // A pre-existing leaf must already be a regular file — a link,
    // FIFO, or device at the sink path is refused before the open.
    let at = dir
        .as_ref()
        .map(|d| d.as_raw_fd())
        .unwrap_or(libc::AT_FDCWD);
    let mut was_new = false;
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
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
        if e.raw_os_error() == Some(libc::ENOENT) {
            was_new = true;
        } else {
            return Err(e);
        }
    }

    // `O_NOFOLLOW` re-checks the leaf at open — a link swapped in
    // after `fstatat` fails the open rather than being followed.
    // `O_NONBLOCK` keeps a raced FIFO from blocking the open; the
    // fstat below still gates the type, and the flag is cleared
    // before the handle is handed on.
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
    // identity owns.
    let euid = unsafe { libc::geteuid() };
    if meta.uid() != euid {
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
    // that cannot be tightened is refused.
    if unsafe { libc::fchmod(file.as_raw_fd(), 0o600) } != 0 {
        return Err(io::Error::last_os_error());
    }
    unsafe {
        let fl = libc::fcntl(file.as_raw_fd(), libc::F_GETFL);
        if fl >= 0 {
            libc::fcntl(file.as_raw_fd(), libc::F_SETFL, fl & !libc::O_NONBLOCK);
        }
    }
    // The fsync anchor for a fresh file's directory entry: reuse the
    // trusted parent handle when the walk produced one, else anchor
    // the cwd for a bare filename.
    let dir = if was_new {
        match dir {
            Some(d) => Some(d),
            None => Some(openat_dir(None, OsStr::new("."))?),
        }
    } else {
        None
    };
    Ok(OpenedSink { file, dir })
}

#[cfg(windows)]
fn open_audit_sink_impl(path: &Path) -> io::Result<OpenedSink> {
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
    use windows::Win32::Storage::FileSystem::{FILE_APPEND_DATA, FILE_FLAG_OPEN_REPARSE_POINT};

    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    const SYNCHRONIZE: u32 = 0x0010_0000;
    const READ_CONTROL: u32 = 0x0002_0000;
    const WRITE_DAC: u32 = 0x0004_0000;

    // Ancestor components must resolve without redirect — a
    // symlink/junction/mount point in the chain would land the sink
    // outside the operator's directory. Windows has no portable
    // no-follow component open, so each ancestor is attribute-checked;
    // the leaf itself is verified on the opened handle below.
    for anc in path.ancestors().skip(1) {
        match fs::symlink_metadata(anc) {
            Ok(m) if m.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 => {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!("audit log ancestor '{}' is a reparse point", anc.display()),
                ));
            }
            Ok(m) if !m.is_dir() => {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!("audit log ancestor '{}' is not a directory", anc.display()),
                ));
            }
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
    }

    // `FILE_FLAG_OPEN_REPARSE_POINT` opens a leaf link itself instead
    // of its target, so the attribute check refuses it rather than
    // appending through to a redirected file. `WRITE_DAC` is requested
    // at open time because `restrict_handle_owner_only` below calls
    // `SetSecurityInfo` on this handle — an append-only handle carries
    // no DACL rights and the call would fail `ACCESS_DENIED`.
    let file = fs::OpenOptions::new()
        .write(true)
        .append(true)
        .create(true)
        .access_mode(FILE_APPEND_DATA.0 | SYNCHRONIZE | READ_CONTROL | WRITE_DAC)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT.0)
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
    // Owner+SYSTEM protected DACL on the opened handle — the same
    // contract as the Unix 0600 mode, without a path re-resolution a
    // swapped name could redirect.
    crate::fspriv::restrict_handle_owner_only(&file).map_err(|e| {
        io::Error::new(
            e.kind(),
            format!("cannot make audit log '{}' private: {e}", path.display()),
        )
    })?;
    Ok(OpenedSink { file, dir: None })
}
