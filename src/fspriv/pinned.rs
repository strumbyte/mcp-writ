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

/// The operator opt-out shared by every replaceable-path refusal:
/// `MCP_WRIT_ALLOW_REPLACEABLE_PATHS=1` restores pre-hardening
/// behavior for deployments that deliberately run under group-shared
/// trees (a group-writable workspace, a drvfs mount reporting 0777) —
/// every path bound by name then carries the swap race the callers
/// refuse by default.
pub(crate) fn replaceable_paths_permitted() -> bool {
    std::env::var_os("MCP_WRIT_ALLOW_REPLACEABLE_PATHS").is_some_and(|v| !v.is_empty() && v != "0")
}

/// Paths a controlling process exempts from the replaceable-path
/// gates one name at a time — the scoped counterpart of
/// `MCP_WRIT_ALLOW_REPLACEABLE_PATHS`. The in-guest runner uses it
/// for the host-mounted contract paths (the read-only policy
/// bind-mount and the writable audit/report channels): the mount
/// reports the *host* uid, which no guest principal maps to under
/// the VM/container backends' documented uid mapping, so the
/// ownership requirement can never be satisfied there. Registering
/// only those paths keeps the ownership and ancestry checks armed
/// for everything else — the workload's entrypoint script included —
/// where a guest-wide opt-out would silence them. Registration is
/// in-process only: no image, config file, or environment variable
/// can arm it.
static REPLACEABLE_PATH_EXEMPTIONS: std::sync::OnceLock<
    std::sync::Mutex<std::collections::HashSet<PathBuf>>,
> = std::sync::OnceLock::new();

fn replaceable_path_exemptions() -> &'static std::sync::Mutex<std::collections::HashSet<PathBuf>> {
    REPLACEABLE_PATH_EXEMPTIONS
        .get_or_init(|| std::sync::Mutex::new(std::collections::HashSet::new()))
}

/// Register `path` — exactly that path — as carrying the documented
/// host-mount exemption described at [`REPLACEABLE_PATH_EXEMPTIONS`].
/// The canonicalized spelling is stored when the object exists so a
/// check arriving under an equal-but-different spelling still
/// matches; a not-yet-created path is stored as spelled.
pub fn permit_replaceable_path(path: &Path) {
    if let Ok(mut set) = replaceable_path_exemptions().lock() {
        set.insert(path.to_path_buf());
        if let Ok(canonical) = fs::canonicalize(path)
            && canonical != *path
        {
            set.insert(canonical);
        }
    }
}

/// [`replaceable_paths_permitted`] for the whole process, or a
/// per-path exemption registered via [`permit_replaceable_path`] —
/// the gate every trusted-path check consults once it knows the path
/// it guards.
pub(crate) fn replaceable_permitted_for(path: &Path) -> bool {
    if replaceable_paths_permitted() {
        return true;
    }
    let Ok(set) = replaceable_path_exemptions().lock() else {
        return false;
    };
    set.contains(path)
        || fs::canonicalize(path)
            .ok()
            .is_some_and(|canonical| set.contains(&canonical))
}

/// Guest-visible roots that name host-mounted share directories —
/// WSB `<MappedFolder>`s and container bind mounts. From inside the
/// guest such a root always reports as replaceable: the *host* can
/// retarget it, and that is the mount's documented purpose (the host
/// is the launcher — a principal already able to corrupt the launch
/// without a rename race). No guest principal can rename or swap a
/// mount point itself, so the ancestry walk
/// [`resolve_for_authorization`](crate::pathutil::resolve_for_authorization)
/// performs has nothing to prove *at that boundary*: paths beneath a
/// registered share root are treated as boundary-stable, while the
/// spelled-component check stays armed — a symlink the workload
/// plants under the share is still refused. Registration is
/// in-process only: only the guest runner registers, and only the
/// roots its launch contract declares — never workload grant paths.
static SHARE_ROOTS: std::sync::OnceLock<std::sync::Mutex<Vec<PathBuf>>> =
    std::sync::OnceLock::new();

fn share_roots() -> &'static std::sync::Mutex<Vec<PathBuf>> {
    SHARE_ROOTS.get_or_init(|| std::sync::Mutex::new(Vec::new()))
}

/// Register `path` as a host-mounted share root for this process —
/// see [`SHARE_ROOTS`]. The canonicalized spelling is stored when the
/// root already exists so a check arriving under the canonical
/// spelling still matches; a not-yet-created root is stored as
/// spelled. Duplicates are ignored.
pub fn register_share_root(path: &Path) {
    if let Ok(mut roots) = share_roots().lock() {
        let mut push = |p: PathBuf| {
            if !roots.contains(&p) {
                roots.push(p);
            }
        };
        if let Ok(canonical) = fs::canonicalize(path) {
            push(canonical);
        }
        push(path.to_path_buf());
    }
}

/// Whether `path` is or descends from a root registered via
/// [`register_share_root`]. Component-wise `starts_with` — a
/// `relay-rw2` sibling does not match a `relay-rw` root.
pub(crate) fn path_under_share_root(path: &Path) -> bool {
    let Ok(roots) = share_roots().lock() else {
        return false;
    };
    if roots.is_empty() {
        return false;
    }
    if roots.iter().any(|root| path.starts_with(root)) {
        return true;
    }
    fs::canonicalize(path)
        .ok()
        .is_some_and(|canonical| roots.iter().any(|root| canonical.starts_with(root)))
}

/// [`require_parent_write_restricted`] honoring the
/// `MCP_WRIT_ALLOW_REPLACEABLE_PATHS` opt-out and registered path
/// exemptions — the shared ancestry gate for a path a trusted read
/// or write binds by spelling (policy source, audit sink, report
/// destination, entrypoint script).
pub fn require_unreplaceable_ancestry(path: &Path) -> io::Result<()> {
    if replaceable_permitted_for(path) {
        return Ok(());
    }
    require_parent_write_restricted(path)
}

/// Refuse a *source* file `path` — a document read verbatim into
/// trusted authority (a policy document, an `args_schema` `@file`, an
/// interpreted entrypoint script) — when a lower-trust principal could
/// substitute or rewrite it. On Unix the leaf must be a regular file
/// owned by this euid or root carrying no group/other write bit, and
/// every ancestor must pass [`require_parent_write_restricted`] — a
/// foreign owner could rewrite the bytes outright, a group-writable
/// file lets group members rewrite them in place, and a replaceable
/// ancestor lets a directory or leaf be renamed away between the
/// check and the read. Both the *spelled* path — the chain the
/// use-time open actually re-traverses — and the canonicalized
/// object are checked, so a symlink, `..`, or reparse component in
/// the spelling cannot route the open around the verified ancestry:
/// on Unix each link component must sit under a write-restricted
/// parent, and on Windows the spelled chain must be reparse-free
/// with the leaf not a reparse point itself. Windows proves the leaf
/// contract through an owner/DACL that admits no untrusted write
/// grant.
///
/// `MCP_WRIT_ALLOW_REPLACEABLE_PATHS` accepts the substitution risk
/// explicitly — the documented downgrade for intentionally shared
/// trees — and [`permit_replaceable_path`] registers the same
/// exemption for one path at a time.
#[cfg(unix)]
pub fn require_trusted_source_file(path: &Path) -> io::Result<()> {
    if replaceable_permitted_for(path) {
        return Ok(());
    }
    use std::os::unix::fs::MetadataExt;
    // Check the object the caller's read will actually open: a spelled
    // path whose leaf is a link — or whose `..` components alias
    // another directory — resolves elsewhere, so the metadata and
    // ancestor checks must follow the resolution, not the spelling.
    let resolved = fs::canonicalize(path)?;
    let meta = fs::metadata(&resolved)?;
    if !meta.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("'{}' is not a regular file", path.display()),
        ));
    }
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    let euid = unsafe { libc::geteuid() };
    if meta.uid() != 0 && meta.uid() != euid {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "refusing '{}': owned by foreign uid {} — that principal \
                 can rewrite it between verification and use",
                path.display(),
                meta.uid()
            ),
        ));
    }
    if meta.mode() & 0o022 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "refusing '{}': group/world-writable — another principal \
                 can rewrite it between verification and use (set \
                 MCP_WRIT_ALLOW_REPLACEABLE_PATHS=1 to accept)",
                path.display()
            ),
        ));
    }
    require_parent_write_restricted(&resolved)?;
    // The resolved checks alone are not enough: the caller's open
    // re-traverses the *spelled* path, whose lexical ancestry can
    // contain a component the resolved chain never names — a symlink
    // or `..` through a directory a lower-trust principal controls.
    // Hold the spelled chain to the same ancestor standard, and refuse
    // every link component that sits under a shared-writable
    // directory: only that directory's write access protects the link
    // from being retargeted after this check.
    let spelled = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    require_parent_write_restricted(&spelled)?;
    let mut cursor = PathBuf::new();
    for component in spelled.components() {
        cursor.push(component.as_os_str());
        let meta = match fs::symlink_metadata(&cursor) {
            Ok(m) => m,
            Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
            Err(e) => return Err(e),
        };
        if !meta.file_type().is_symlink() {
            continue;
        }
        if let Some(parent) = cursor.parent()
            && dir_shared_writable(parent)?
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "refusing '{}': component '{}' is a symbolic link under \
                     shared-writable '{}' — it can be retargeted after \
                     verification (set MCP_WRIT_ALLOW_REPLACEABLE_PATHS=1 \
                     to accept)",
                    path.display(),
                    cursor.display(),
                    parent.display()
                ),
            ));
        }
    }
    Ok(())
}

/// Windows counterpart of the Unix [`require_trusted_source_file`]: a
/// source document must resolve through reparse-free ancestry whose
/// DACLs deny untrusted principals replace access, and the leaf itself
/// must be owned by a trusted principal with no DACL grant that lets
/// an untrusted trustee write or delete it.
#[cfg(windows)]
pub fn require_trusted_source_file(path: &Path) -> io::Result<()> {
    if replaceable_permitted_for(path) {
        return Ok(());
    }
    use std::os::windows::fs::MetadataExt;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    // Resolve `..`/reparse components first so the ancestor walk and
    // the owner/DACL checks below cover the object the caller's open
    // will actually reach, not merely the spelled chain.
    let resolved = fs::canonicalize(path)?;
    super::winsec::require_no_reparse_ancestors(&resolved)?;
    require_parent_write_restricted(&resolved)?;
    // The resolved checks alone are not enough: the caller's open
    // re-traverses the *spelled* path, so its chain is held to the
    // same contract — reparse-free ancestors whose DACLs deny
    // untrusted replace access, and a leaf that is not itself a
    // reparse point an untrusted principal could retarget.
    let spelled = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    super::winsec::require_no_reparse_ancestors(&spelled)?;
    require_parent_write_restricted(&spelled)?;
    if fs::symlink_metadata(&spelled)?.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "refusing '{}': the spelled leaf is a reparse point — its \
                 owner can retarget the open after verification (set \
                 MCP_WRIT_ALLOW_REPLACEABLE_PATHS=1 to accept)",
                path.display()
            ),
        ));
    }
    let file = fs::File::open(&resolved)?;
    let meta = file.metadata()?;
    if !meta.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("'{}' is not a regular file", path.display()),
        ));
    }
    if !super::winsec::handle_owner_is_trusted(&file, true)? {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "refusing '{}': owned by an untrusted principal",
                path.display()
            ),
        ));
    }
    if super::winsec::dacl_grants_file_write(&resolved, true)? {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "refusing '{}': its DACL grants write access to an untrusted \
                 principal — another session could rewrite it between \
                 verification and use (set MCP_WRIT_ALLOW_REPLACEABLE_PATHS=1 \
                 to accept)",
                path.display()
            ),
        ));
    }
    Ok(())
}

#[cfg(not(any(unix, windows)))]
pub fn require_trusted_source_file(path: &Path) -> io::Result<()> {
    let _ = path;
    Err(io::Error::other(
        "source-file trust cannot be verified on this OS",
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
