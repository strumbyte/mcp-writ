//! Directory pinning and replace-detection: a host directory bound to
//! an open handle plus its platform identity, and the ancestor checks
//! that prove a lower-trust principal cannot swap the pinned object
//! out between validation and use.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

/// Platform identity of a filesystem object — `(st_dev, st_ino)` on
/// unix, `(volume serial, file index)` on Windows. Two opens naming
/// the same object agree on it; an entry renamed away and recreated
/// (or swapped for a link target) does not, which is what makes the
/// pin usable as a replace-detector.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileIdentity {
    pub device: u64,
    pub index: u64,
}

/// `true` when the process runs with effective uid 0. Permission-mode
/// tests cannot exercise denial under root — the kernel bypasses the
/// discretionary checks — so tests asserting `PermissionDenied` skip
/// there. Always `false` off unix: Windows admin rights do not bypass
/// ACLs the same way.
pub fn running_as_root() -> bool {
    #[cfg(unix)]
    {
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe { libc::geteuid() == 0 }
    }
    #[cfg(not(unix))]
    {
        false
    }
}

/// The identity of the object an open `file` handle names.
pub fn file_identity(file: &fs::File) -> io::Result<FileIdentity> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let meta = file.metadata()?;
        Ok(FileIdentity {
            device: meta.dev(),
            index: meta.ino(),
        })
    }
    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawHandle;
        use windows::Win32::Foundation::HANDLE;
        use windows::Win32::Storage::FileSystem::{
            BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle,
        };
        let mut info = BY_HANDLE_FILE_INFORMATION::default();
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe {
            GetFileInformationByHandle(HANDLE(file.as_raw_handle() as _), &mut info)
                .map_err(|e| io::Error::other(format!("GetFileInformationByHandle: {e}")))?;
        }
        Ok(FileIdentity {
            device: u64::from(info.dwVolumeSerialNumber),
            index: (u64::from(info.nFileIndexHigh) << 32) | u64::from(info.nFileIndexLow),
        })
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = file;
        Err(io::Error::other("file identity is unsupported on this OS"))
    }
}

/// A host directory pinned by an open handle and its platform identity.
/// The share/mount argument still names `path` (the engine CLI has no
/// handle-passing channel), but [`verify_current`](Self::verify_current)
/// re-opens the path immediately before the mount is used and refuses
/// when it no longer resolves to the pinned object — a rename-swap or
/// reparse substitution cannot redirect the guest's writable share to
/// an unintended host path.
pub struct PinnedDir {
    /// The canonical spelling the mount names.
    pub path: PathBuf,
    identity: FileIdentity,
    /// Retained open handle — the pinned object cannot be deleted out
    /// from under the verification while it lives.
    _handle: fs::File,
}

/// Open a directory *as a pinned object*: unix opens with
/// `O_DIRECTORY|O_NOFOLLOW` (a final-component link fails `ELOOP`),
/// Windows opens the reparse point itself and rejects it by attribute
/// so a junction/symlink is never accepted. The handle is returned
/// alongside the identity captured from it.
pub fn open_dir_pinned(path: &Path) -> io::Result<(fs::File, FileIdentity)> {
    let file = open_dir_no_link(path)?;
    let meta = file.metadata()?;
    if !meta.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("'{}' is not a directory", path.display()),
        ));
    }
    let identity = file_identity(&file)?;
    Ok((file, identity))
}

#[cfg(unix)]
fn open_dir_no_link(path: &Path) -> io::Result<fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
}

#[cfg(windows)]
fn open_dir_no_link(path: &Path) -> io::Result<fs::File> {
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
    use windows::Win32::Storage::FileSystem::{
        FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
    };
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS.0 | FILE_FLAG_OPEN_REPARSE_POINT.0)
        .open(path)?;
    // OPEN_REPARSE_POINT surfaces the link object itself — a directory
    // that is a junction/symlink must be refused, not traversed into.
    if file.metadata()?.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("'{}' is a reparse point, not a directory", path.display()),
        ));
    }
    Ok(file)
}

#[cfg(not(any(unix, windows)))]
fn open_dir_no_link(path: &Path) -> io::Result<fs::File> {
    fs::OpenOptions::new().read(true).open(path)
}

impl PinnedDir {
    /// Pin `path` (expected canonical): open the directory without
    /// following a final-component link and capture its identity.
    pub fn pin(path: &Path) -> io::Result<Self> {
        let (file, identity) = open_dir_pinned(path)?;
        Ok(Self {
            path: path.to_path_buf(),
            identity,
            _handle: file,
        })
    }

    /// The identity captured at pin time — a caller can hand it to a
    /// later stage so that stage proves a path still names this object.
    pub fn identity(&self) -> FileIdentity {
        self.identity
    }

    /// Re-resolve `path` and prove it still names the pinned object —
    /// run immediately before the mount is handed to the engine.
    pub fn verify_current(&self) -> io::Result<()> {
        let (file, identity) = open_dir_pinned(&self.path)?;
        drop(file);
        if identity != self.identity {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "'{}' was replaced since it was validated",
                    self.path.display()
                ),
            ));
        }
        Ok(())
    }
}

/// Refuse `dir` when its parent directory lets a lower-trust principal
/// replace the entry: an ancestor owned by a uid that is neither root
/// nor the caller is replaceable by that foreign principal outright;
/// and a group- or world-writable parent without the sticky bit allows
/// anyone in that set to rename the pinned object away and substitute
/// another (a symlink, or a directory staging a different path)
/// between validation and mount. A sticky world-writable parent
/// (`/tmp`) constrains renames to the entry's owner and is acceptable.
/// Unix only — the Windows check inspects the parent DACL instead.
#[cfg(unix)]
pub fn require_parent_write_restricted(dir: &Path) -> io::Result<()> {
    use std::os::unix::fs::MetadataExt;
    // Every ancestor matters, not just the immediate parent: renaming a
    // grandparent's child re-resolves the whole path to a different
    // object. `/` and other sticky/root-owned levels pass through.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    let euid = unsafe { libc::geteuid() };
    let mut ancestor = dir.parent();
    while let Some(parent) = ancestor {
        let meta = match fs::metadata(parent) {
            Ok(m) => m,
            // A not-yet-created level cannot be replaced — its parent's
            // restriction is what matters and is checked on the way up.
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                ancestor = parent.parent();
                continue;
            }
            Err(e) => return Err(e),
        };
        // A foreign uid owns the entry's slot in its parent — that
        // principal can rename or rewrite it regardless of mode bits.
        if meta.uid() != 0 && meta.uid() != euid {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "refusing '{}': ancestor '{}' is owned by a foreign principal — \
                     another user could replace the directory",
                    dir.display(),
                    parent.display()
                ),
            ));
        }
        let mode = meta.mode() & 0o1777;
        let shared_write = mode & 0o022 != 0;
        let sticky = mode & 0o1000 != 0;
        if shared_write && !sticky {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "refusing '{}': ancestor '{}' is group/world-writable without the \
                     sticky bit — another principal could replace the directory",
                    dir.display(),
                    parent.display()
                ),
            ));
        }
        ancestor = parent.parent();
    }
    Ok(())
}

/// Windows: refuse `dir` when any existing ancestor's DACL grants
/// write/delete access to an untrusted principal — any trustee outside
/// the current user and the administrator set (SYSTEM, Administrators,
/// TrustedInstaller, and owner-delegating placeholders). Any such
/// grant lets a lower-trust session rename a directory in the chain or
/// plant a replacement beneath it. Absence of a DACL (null DACL) means
/// unrestricted access and is refused outright.
#[cfg(windows)]
pub fn require_parent_write_restricted(dir: &Path) -> io::Result<()> {
    let mut ancestor = dir.parent();
    while let Some(parent) = ancestor {
        match super::winsec::dacl_grants_replace_rights(parent, true) {
            Ok(true) => {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!(
                        "refusing '{}': ancestor '{}' grants replace access to an \
                         untrusted principal — another session could swap it out",
                        dir.display(),
                        parent.display()
                    ),
                ));
            }
            Ok(false) => {}
            // A not-yet-created level cannot be replaced — walk past it.
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
        ancestor = parent.parent();
    }
    Ok(())
}

#[cfg(not(any(unix, windows)))]
pub fn require_parent_write_restricted(dir: &Path) -> io::Result<()> {
    let _ = dir;
    Err(io::Error::other(
        "parent-directory write restrictions cannot be verified on this OS",
    ))
}

/// True when `dir` grants write access to a principal other than its
/// owner — group/other permission bits on Unix, a broad-trustee DACL
/// allow on Windows. The auditor uses this to refuse authorization
/// over components a non-owner could replace or retarget between the
/// policy check and the child's independent open.
#[cfg(unix)]
pub fn dir_shared_writable(dir: &Path) -> io::Result<bool> {
    use std::os::unix::fs::MetadataExt;
    Ok(fs::metadata(dir)?.mode() & 0o022 != 0)
}

#[cfg(windows)]
pub fn dir_shared_writable(dir: &Path) -> io::Result<bool> {
    super::winsec::dacl_grants_replace_rights(dir, true)
}

#[cfg(not(any(unix, windows)))]
pub fn dir_shared_writable(dir: &Path) -> io::Result<bool> {
    let _ = dir;
    Err(io::Error::other(
        "shared-write checks are unavailable on this OS",
    ))
}
