//! Owner-only temporary directories for policy and build staging, plus
//! copy primitives that cannot be raced out of a staged source tree:
//! every copied file is opened without following a final-component link
//! and proven to resolve inside the canonicalized source root, and the
//! bytes stream from that same open handle — a pathname swapped for a
//! link mid-copy can never redirect the read to an out-of-tree target.

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
        (unsafe { libc::geteuid() }) == 0
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
/// replace the entry: a group- or world-writable parent without the
/// sticky bit allows anyone in that set to rename the pinned object
/// away and substitute another (a symlink, or a directory staging a
/// different path) between validation and mount. A sticky
/// world-writable parent (`/tmp`) constrains renames to the entry's
/// owner and is acceptable. Unix only — the Windows check inspects the
/// parent DACL instead.
#[cfg(unix)]
pub fn require_parent_write_restricted(dir: &Path) -> io::Result<()> {
    use std::os::unix::fs::MetadataExt;
    // Every ancestor matters, not just the immediate parent: renaming a
    // grandparent's child re-resolves the whole path to a different
    // object. `/` and other sticky/root-owned levels pass through.
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
/// write/delete access to a broad well-known principal (Everyone,
/// Anonymous, Authenticated Users, BUILTIN\Users, INTERACTIVE, NETWORK)
/// — any such grant lets a lower-trust session rename a directory in
/// the chain or plant a replacement beneath it. Absence of a DACL
/// (null DACL) means unrestricted access and is refused outright.
#[cfg(windows)]
pub fn require_parent_write_restricted(dir: &Path) -> io::Result<()> {
    let mut ancestor = dir.parent();
    while let Some(parent) = ancestor {
        match dacl_grants_replace_rights(parent) {
            Ok(true) => {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!(
                        "refusing '{}': ancestor '{}' grants replace access to a \
                         broad principal — another session could swap it out",
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
    dacl_grants_replace_rights(dir)
}

#[cfg(not(any(unix, windows)))]
pub fn dir_shared_writable(dir: &Path) -> io::Result<bool> {
    let _ = dir;
    Err(io::Error::other(
        "shared-write checks are unavailable on this OS",
    ))
}

/// Walk `dir`'s DACL for allow-ACEs that hand a broad trustee the
/// rights needed to *replace* a child entry — delete/delete-child or
/// ACL/ownership control. Add-only rights (FILE_ADD_FILE,
/// FILE_ADD_SUBDIRECTORY, FILE_APPEND_DATA) are deliberately absent:
/// they let a principal plant a sibling, not retarget an existing
/// component, and drive roots grant them to Authenticated Users —
/// counting them would refuse every path on the volume.
#[cfg(windows)]
fn dacl_grants_replace_rights(dir: &Path) -> io::Result<bool> {
    use std::ffi::c_void;

    use windows::Win32::Foundation::{GENERIC_ALL, GENERIC_WRITE, HLOCAL, LocalFree};
    use windows::Win32::Security::Authorization::{GetNamedSecurityInfoW, SE_FILE_OBJECT};
    use windows::Win32::Security::{
        ACCESS_ALLOWED_ACE, ACL, ACL_SIZE_INFORMATION, AclSizeInformation,
        DACL_SECURITY_INFORMATION, GetAce, GetAclInformation, IsWellKnownSid, PSID,
        WinAnonymousSid, WinAuthenticatedUserSid, WinBuiltinUsersSid, WinInteractiveSid,
        WinNetworkSid, WinWorldSid,
    };
    use windows::Win32::Storage::FileSystem::{DELETE, FILE_DELETE_CHILD, WRITE_DAC, WRITE_OWNER};
    use windows::core::HSTRING;

    /// ACE header type byte for an access-allowed ACE (`winnt.h`).
    const ACCESS_ALLOWED_ACE_TYPE: u8 = 0;
    /// `AceFlags` bit marking an ACE that never applies to the object
    /// itself (`winnt.h` `INHERIT_ONLY_ACE`) — it exists only to be
    /// inherited by children, so it cannot grant replace rights on this
    /// directory. `0x10` is `INHERITED_ACE` — a different flag, and one
    /// that must NOT be skipped: a non-inherit-only ACE that arrived by
    /// inheritance still governs access to this directory.
    const INHERIT_ONLY_ACE: u8 = 0x08;
    const REPLACE_RIGHTS: u32 = DELETE.0
        | FILE_DELETE_CHILD.0
        | WRITE_DAC.0
        | WRITE_OWNER.0
        | GENERIC_WRITE.0
        | GENERIC_ALL.0;

    let text = dir.to_string_lossy();
    // `\\?\` verbatim spellings fail the object-name lookup.
    let name = if let Some(rest) = text.strip_prefix(r"\\?\UNC\") {
        format!(r"\\{rest}")
    } else {
        text.strip_prefix(r"\\?\").unwrap_or(&text).to_string()
    };
    let mut dacl: *mut ACL = std::ptr::null_mut();
    let mut sd: windows::Win32::Security::PSECURITY_DESCRIPTOR =
        windows::Win32::Security::PSECURITY_DESCRIPTOR(std::ptr::null_mut());
    let status = unsafe {
        GetNamedSecurityInfoW(
            &HSTRING::from(name.as_str()),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            None,
            None,
            Some(&mut dacl),
            None,
            &mut sd,
        )
    };
    status.ok().map_err(|e| {
        // FILE_NOT_FOUND / PATH_NOT_FOUND must surface as NotFound so
        // ancestor walks can skip not-yet-created levels. The API
        // reports Win32 codes wrapped in HRESULTs (0x8007xxxx), so the
        // low word is what matches ERROR_FILE_NOT_FOUND /
        // ERROR_PATH_NOT_FOUND.
        let win32 = e.code().0 as u32 & 0xFFFF;
        if win32 == 2 || win32 == 3 {
            io::Error::new(io::ErrorKind::NotFound, format!("'{}': {e}", dir.display()))
        } else {
            io::Error::other(format!(
                "GetNamedSecurityInfoW for '{}': {e}",
                dir.display()
            ))
        }
    })?;
    // The SD heap allocation must be freed whatever the walk finds.
    struct SdGuard(*mut c_void);
    impl Drop for SdGuard {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe {
                    let _ = LocalFree(Some(HLOCAL(self.0)));
                }
            }
        }
    }
    let _sd_guard = SdGuard(sd.0);

    // A null DACL pointer = unrestricted access — fail toward "broad
    // write possible" rather than declaring the parent safe.
    if dacl.is_null() {
        return Ok(true);
    }
    let mut info = ACL_SIZE_INFORMATION::default();
    unsafe {
        GetAclInformation(
            dacl,
            &mut info as *mut _ as *mut c_void,
            size_of::<ACL_SIZE_INFORMATION>() as u32,
            AclSizeInformation,
        )
    }
    .map_err(|e| io::Error::other(format!("GetAclInformation: {e}")))?;

    let broad = [
        WinWorldSid,
        WinAnonymousSid,
        WinAuthenticatedUserSid,
        WinBuiltinUsersSid,
        WinInteractiveSid,
        WinNetworkSid,
    ];
    for i in 0..info.AceCount {
        let mut ace: *mut c_void = std::ptr::null_mut();
        unsafe {
            GetAce(dacl, i, &mut ace).map_err(|e| io::Error::other(format!("GetAce: {e}")))?;
        }
        let ace = ace.cast::<ACCESS_ALLOWED_ACE>();
        if unsafe { (*ace).Header.AceType } != ACCESS_ALLOWED_ACE_TYPE {
            continue;
        }
        if unsafe { (*ace).Header.AceFlags } & INHERIT_ONLY_ACE != 0 {
            continue;
        }
        let (mask, sid) = unsafe { ((*ace).Mask, PSID(&raw const (*ace).SidStart as *mut c_void)) };
        if mask & REPLACE_RIGHTS == 0 {
            continue;
        }
        for kind in broad {
            if unsafe { IsWellKnownSid(sid, kind).as_bool() } {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

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
    // Return the real spelling: `$TMPDIR` may traverse a platform link
    // (macOS `/var` → `/private/var`), and strict `O_NOFOLLOW` ancestor
    // walks on paths under this directory refuse linked components.
    Ok(dir.canonicalize().unwrap_or(dir))
}

/// Restrict `dir` to the current user. Unix sets mode 0700; Windows
/// applies a protected DACL granting the current user and SYSTEM —
/// the session credentials staged under a sandbox state directory must
/// not be readable by other local users just because the user-chosen
/// parent happens to have a permissive ACL. A failure refuses the
/// directory rather than leaving shared-readable state behind.
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
    #[cfg(windows)]
    restrict_owner_only_windows(dir)?;
    Ok(())
}

/// The Windows half of [`restrict_owner_only`]: replace `dir`'s DACL with
/// a protected one — no inherited entries — granting `GENERIC_ALL` to the
/// current process's user SID and to the local SYSTEM account. SYSTEM
/// stays in so OS-level services staging under the directory (a container
/// engine reading an exported policy mount, the Sandbox host stack) are
/// not locked out of data the product itself created. The entries inherit
/// to children, so files written later — including the relay credentials
/// under `ro/` — get the same restriction.
#[cfg(windows)]
fn restrict_owner_only_windows(dir: &Path) -> io::Result<()> {
    use std::ffi::c_void;

    use windows::Win32::Foundation::{HLOCAL, LocalFree};
    use windows::Win32::Security::Authorization::{SE_FILE_OBJECT, SetNamedSecurityInfoW};
    use windows::Win32::Security::{
        DACL_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION,
    };
    use windows::core::HSTRING;

    let (dacl, _user, _system) = protected_owner_dacl()?;
    // `\\?\` verbatim spellings fail the object-name lookup — strip
    // the prefix the same way the warden's grant path does.
    let text = dir.to_string_lossy();
    let name = if let Some(rest) = text.strip_prefix(r"\\?\UNC\") {
        format!(r"\\{rest}")
    } else {
        text.strip_prefix(r"\\?\").unwrap_or(&text).to_string()
    };
    let result = unsafe {
        SetNamedSecurityInfoW(
            &HSTRING::from(name),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            None,
            None,
            Some(dacl),
            None,
        )
    };
    if !dacl.is_null() {
        unsafe {
            LocalFree(Some(HLOCAL(dacl as *mut c_void)));
        }
    }
    result.ok().map_err(|e| {
        io::Error::other(format!(
            "SetNamedSecurityInfoW for '{}': {e}",
            dir.display()
        ))
    })
}

/// Build the owner+SYSTEM protected DACL shared by the path-based and
/// handle-based restrictors. Returns the DACL pointer plus the SID
/// buffers that must outlive both the ACL build and its application —
/// `EXPLICIT_ACCESS` entries store `PSID` *pointers* into those
/// buffers. The caller frees the DACL with `LocalFree`.
#[cfg(windows)]
fn protected_owner_dacl() -> io::Result<(*mut windows::Win32::Security::ACL, Vec<usize>, Vec<u8>)> {
    use windows::Win32::Foundation::{CloseHandle, GENERIC_ALL};
    use windows::Win32::Security::Authorization::{
        EXPLICIT_ACCESS_W, GRANT_ACCESS, SetEntriesInAclW, TRUSTEE_IS_SID, TRUSTEE_IS_USER,
        TRUSTEE_IS_WELL_KNOWN_GROUP, TRUSTEE_W,
    };
    use windows::Win32::Security::{
        ACL, CONTAINER_INHERIT_ACE, CreateWellKnownSid, GetTokenInformation, OBJECT_INHERIT_ACE,
        PSID, TOKEN_QUERY, TOKEN_USER, TokenUser, WinLocalSystemSid,
    };
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
    use windows::core::PWSTR;

    let os_err = |e: windows::core::Error| io::Error::other(e.to_string());

    // The session's own user SID via the process token — the ACE must
    // name the real user (an elevated process would otherwise grant the
    // Administrators group, not the account holding the credentials).
    let mut token = windows::Win32::Foundation::HANDLE::default();
    unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) }.map_err(os_err)?;
    let result = (|| {
        let mut need = 0u32;
        let _ = unsafe { GetTokenInformation(token, TokenUser, None, 0, &mut need) };
        // TOKEN_USER contains a SID_AND_ATTRIBUTES pointer — the buffer
        // must be pointer-aligned, not merely byte-aligned.
        let mut user = vec![0usize; (need as usize).div_ceil(size_of::<usize>())];
        unsafe {
            GetTokenInformation(
                token,
                TokenUser,
                Some(user.as_mut_ptr().cast()),
                need,
                &mut need,
            )
        }
        .map_err(os_err)?;
        // SAFETY: the buffer holds a TOKEN_USER whose Sid member points
        // into `user`, which must outlive the ACL application.
        let user_sid = unsafe { (*user.as_ptr().cast::<TOKEN_USER>()).User.Sid };

        // SECURITY_MAX_SID_SIZE; CreateWellKnownSid fills caller memory,
        // nothing to free.
        let mut system = vec![0u8; 68];
        let mut size = system.len() as u32;
        unsafe {
            CreateWellKnownSid(
                WinLocalSystemSid,
                None,
                Some(PSID(system.as_mut_ptr().cast())),
                &mut size,
            )
        }
        .map_err(os_err)?;
        let system_sid = PSID(system.as_mut_ptr().cast());

        let inherit =
            windows::Win32::Security::ACE_FLAGS(CONTAINER_INHERIT_ACE.0 | OBJECT_INHERIT_ACE.0);
        let entry = |sid: PSID, trustee_type| EXPLICIT_ACCESS_W {
            grfAccessPermissions: GENERIC_ALL.0,
            grfAccessMode: GRANT_ACCESS,
            grfInheritance: inherit,
            Trustee: TRUSTEE_W {
                TrusteeForm: TRUSTEE_IS_SID,
                TrusteeType: trustee_type,
                ptstrName: PWSTR(sid.0 as *mut u16),
                ..Default::default()
            },
        };
        let entries = [
            entry(user_sid, TRUSTEE_IS_USER),
            entry(system_sid, TRUSTEE_IS_WELL_KNOWN_GROUP),
        ];
        let mut dacl: *mut ACL = std::ptr::null_mut();
        // A null old ACL builds a fresh list containing only our entries.
        unsafe { SetEntriesInAclW(Some(&entries), None, &mut dacl) }
            .ok()
            .map_err(os_err)?;
        Ok((dacl, user, system))
    })();
    unsafe {
        let _ = CloseHandle(token);
    }
    result
}

/// [`restrict_owner_only`]'s DACL applied to an *open file handle* via
/// `SetSecurityInfo` — no path re-resolution, so a name swapped for a
/// link between validation and tightening cannot redirect the change
/// to a different object. Used for the audit sink, whose append handle
/// must itself carry the confidentiality contract.
#[cfg(windows)]
pub fn restrict_handle_owner_only(file: &fs::File) -> io::Result<()> {
    use std::ffi::c_void;
    use std::os::windows::io::AsRawHandle;

    use windows::Win32::Foundation::{HANDLE, HLOCAL, LocalFree};
    use windows::Win32::Security::Authorization::{SE_FILE_OBJECT, SetSecurityInfo};
    use windows::Win32::Security::{
        DACL_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION,
    };

    let (dacl, _user, _system) = protected_owner_dacl()?;
    let result = unsafe {
        SetSecurityInfo(
            HANDLE(file.as_raw_handle()),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            None,
            None,
            Some(dacl),
            None,
        )
    };
    if !dacl.is_null() {
        unsafe {
            LocalFree(Some(HLOCAL(dacl as *mut c_void)));
        }
    }
    result
        .ok()
        .map_err(|e| io::Error::other(format!("SetSecurityInfo: {e}")))
}

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
        if skip_name(&name.to_string_lossy()) {
            continue;
        }
        // Enumeration itself is attacker-proportional work — count
        // every entry, not just the files that end up copied.
        budget.take_entry(&entry.path())?;
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

/// Open a directory so [`real_path_of`] can resolve its true path.
#[cfg(unix)]
fn open_dir_handle(dir: &Path) -> io::Result<fs::File> {
    fs::File::open(dir)
}

/// Windows: directories need `FILE_FLAG_BACKUP_SEMANTICS` to open.
#[cfg(windows)]
fn open_dir_handle(dir: &Path) -> io::Result<fs::File> {
    use std::os::windows::fs::OpenOptionsExt;
    use windows::Win32::Storage::FileSystem::FILE_FLAG_BACKUP_SEMANTICS;
    fs::OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS.0)
        .open(dir)
}

/// Write `contents` to `path` atomically: an unpredictable sibling
/// temp file created with `create_new` (a planted link or file at the
/// temp name fails the open instead of being followed), synced, then
/// renamed over `path`. The rename replaces a symlink at `path`
/// outright — it never writes through to the link's target, which is
/// the difference between this and reopening `path` for `write` after
/// a caller-side validation.
pub fn write_file_atomic(path: &Path, contents: &[u8]) -> io::Result<()> {
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
    let mut file = opts.open(&tmp)?;
    let result = (|| -> io::Result<()> {
        use std::io::Write;
        file.write_all(contents)?;
        file.sync_data()?;
        fs::rename(&tmp, path)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result
}

/// Read a whole file only when it fits within `limit` bytes — the read
/// is refused rather than truncated so analysis never silently runs on
/// a prefix. The metadata check is pre-allocated advice only: a file
/// grown past the check is still cut at `limit` and refused.
pub fn read_file_bounded(path: &Path, limit: u64) -> io::Result<Vec<u8>> {
    use std::io::Read;
    if fs::metadata(path)?.len() > limit {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "file '{}' exceeds the {}-byte analysis limit",
                path.display(),
                limit
            ),
        ));
    }
    let mut bytes = Vec::new();
    let n = fs::File::open(path)?
        .take(limit + 1)
        .read_to_end(&mut bytes)?;
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
pub fn read_bounded_text(path: &Path, limit: u64) -> io::Result<String> {
    use std::io::Read;
    let file = std::fs::File::open(path)?;
    if file.metadata().map(|m| m.len()).unwrap_or(0) > limit {
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
    Ok(text)
}

/// [`read_no_follow_bounded`] plus the containment proof
/// [`safe_copy_file`] performs: the opened object's real path must
/// resolve inside `canonical_root`, checked on the same open handle the
/// bytes stream from. A link, non-regular entry, out-of-root object, or
/// oversized file is a hard error — callers staging validated bytes
/// never want a silent skip.
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

/// Open `path` for reading without following a final-component link.
/// `Ok(None)` when the entry is a link or other non-regular object.
/// `O_NONBLOCK` keeps a raced FIFO from blocking the open before the
/// file-type check can reject it.
#[cfg(unix)]
fn open_no_follow(path: &Path) -> io::Result<Option<fs::File>> {
    use std::os::unix::fs::OpenOptionsExt;
    match fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)
    {
        Ok(f) => {
            if f.metadata()?.is_file() {
                Ok(Some(f))
            } else {
                Ok(None)
            }
        }
        Err(e) if e.raw_os_error() == Some(libc::ELOOP) => Ok(None),
        Err(e) => Err(e),
    }
}

/// Windows: `FILE_FLAG_OPEN_REPARSE_POINT` opens the reparse point
/// itself rather than its target; the attributes then tell whether the
/// entry is a link/junction (skipped) or a real file.
#[cfg(windows)]
fn open_no_follow(path: &Path) -> io::Result<Option<fs::File>> {
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
    use windows::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    // A missing path is an open error like on Unix — `Ok(None)` is
    // reserved for an entry that exists but is a link/non-regular.
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT.0)
        .open(path)?;
    let meta = file.metadata()?;
    if meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 || !meta.is_file() {
        return Ok(None);
    }
    Ok(Some(file))
}

/// The real path of an open file — the same object the copy reads.
#[cfg(target_os = "linux")]
fn real_path_of(file: &fs::File) -> io::Result<PathBuf> {
    use std::os::unix::io::AsRawFd;
    fs::read_link(format!("/proc/self/fd/{}", file.as_raw_fd()))
}

#[cfg(target_os = "macos")]
fn real_path_of(file: &fs::File) -> io::Result<PathBuf> {
    use std::os::unix::io::AsRawFd;
    let mut buf = vec![0u8; libc::PATH_MAX as usize];
    let rc = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETPATH, buf.as_mut_ptr()) };
    if rc == -1 {
        return Err(io::Error::last_os_error());
    }
    let end = buf.iter().position(|b| *b == 0).unwrap_or(buf.len());
    Ok(PathBuf::from(
        String::from_utf8_lossy(&buf[..end]).into_owned(),
    ))
}

#[cfg(windows)]
fn real_path_of(file: &fs::File) -> io::Result<PathBuf> {
    use std::os::windows::io::AsRawHandle;
    use windows::Win32::Storage::FileSystem::{
        FILE_NAME_NORMALIZED, GETFINALPATHNAMEBYHANDLE_FLAGS, GetFinalPathNameByHandleW,
        VOLUME_NAME_DOS,
    };
    // FILE_NAME_NORMALIZED resolves every path component to its true
    // on-disk name — 8.3 short-name spellings, intermediate junctions
    // and case differences all collapse — so the containment
    // `starts_with` judges real locations, not open-time spellings.
    // Returns the `\\?\`-prefixed DOS path for the opened object.
    let mut buf = vec![0u16; 32 * 1024];
    let len = unsafe {
        GetFinalPathNameByHandleW(
            windows::Win32::Foundation::HANDLE(file.as_raw_handle() as _),
            &mut buf,
            GETFINALPATHNAMEBYHANDLE_FLAGS(FILE_NAME_NORMALIZED.0 | VOLUME_NAME_DOS.0),
        )
    };
    if len == 0 || len as usize >= buf.len() {
        return Err(io::Error::last_os_error());
    }
    Ok(PathBuf::from(String::from_utf16_lossy(
        &buf[..len as usize],
    )))
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

    /// The Windows restriction is a real protected DACL — user + SYSTEM
    /// only — that children inherit, not a default-ACL no-op.
    #[cfg(windows)]
    #[test]
    fn windows_restriction_is_protected_owner_and_system_dacl() {
        use windows::Win32::Foundation::HLOCAL;
        use windows::Win32::Security::{
            ACL, DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, SE_DACL_PROTECTED,
        };
        use windows::core::HSTRING;

        let dir = create_private_tempdir("acl").unwrap();
        let child = dir.join("child.txt");
        fs::write(&child, "credentials").unwrap();

        let mut dacl: *mut ACL = std::ptr::null_mut();
        let mut sd = PSECURITY_DESCRIPTOR(std::ptr::null_mut());
        unsafe {
            windows::Win32::Security::Authorization::GetNamedSecurityInfoW(
                &HSTRING::from(dir.to_string_lossy().as_ref()),
                windows::Win32::Security::Authorization::SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                None,
                None,
                Some(&mut dacl),
                None,
                &mut sd,
            )
            .ok()
            .expect("DACL query");
            let mut control = 0u16;
            let mut revision = 0u32;
            windows::Win32::Security::GetSecurityDescriptorControl(sd, &mut control, &mut revision)
                .expect("SD control");
            assert_ne!(
                control & SE_DACL_PROTECTED.0,
                0,
                "session DACL must block inherited entries"
            );
            // SetEntriesInAclW splits each entry into a direct ACE and an
            // inherit-only (OI|CI|IO) ACE: user + SYSTEM twice over.
            assert_eq!((*dacl).AceCount, 4, "user + SYSTEM ACEs only");
            windows::Win32::Foundation::LocalFree(Some(HLOCAL(sd.0)));
        }
        // The restriction inherits to files created after it was applied.
        let mut child_dacl: *mut ACL = std::ptr::null_mut();
        let mut child_sd = PSECURITY_DESCRIPTOR(std::ptr::null_mut());
        unsafe {
            windows::Win32::Security::Authorization::GetNamedSecurityInfoW(
                &HSTRING::from(child.to_string_lossy().as_ref()),
                windows::Win32::Security::Authorization::SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                None,
                None,
                Some(&mut child_dacl),
                None,
                &mut child_sd,
            )
            .ok()
            .expect("child DACL query");
            assert_eq!((*child_dacl).AceCount, 2, "children inherit the DACL");
            windows::Win32::Foundation::LocalFree(Some(HLOCAL(child_sd.0)));
        }
        let _ = fs::remove_dir_all(&dir);
    }

    // ── safe_copy_file / safe_copy_dir ───────────────────────────────

    #[test]
    fn safe_copy_file_copies_contents() {
        let dir = create_private_tempdir("cp").unwrap();
        let src = dir.join("src.txt");
        fs::write(&src, b"payload bytes").unwrap();
        let dst = dir.join("nested").join("dst.txt");
        let root = canonical_root(&dir).unwrap();
        assert_eq!(
            safe_copy_file(&src, &dst, &root).unwrap(),
            SafeCopyOutcome::Copied(13)
        );
        assert_eq!(fs::read(&dst).unwrap(), b"payload bytes");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn safe_copy_file_refuses_outside_root() {
        let dir = create_private_tempdir("cp-out").unwrap();
        let outside = create_private_tempdir("cp-root").unwrap();
        let src = dir.join("src.txt");
        fs::write(&src, b"data").unwrap();
        let dst = outside.join("dst.txt");
        let wrong_root = canonical_root(&outside).unwrap();
        // A root that does not contain the source fails the containment
        // proof — the same check a swapped-in link trips.
        assert!(safe_copy_file(&src, &dst, &wrong_root).is_err());
        assert!(!dst.exists());
        let _ = fs::remove_dir_all(&dir);
        let _ = fs::remove_dir_all(&outside);
    }

    #[cfg(unix)]
    #[test]
    fn safe_copy_file_skips_symlink() {
        let dir = create_private_tempdir("cp-link").unwrap();
        let real = dir.join("real.txt");
        fs::write(&real, b"secret").unwrap();
        let link = dir.join("link.txt");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let dst = dir.join("dst.txt");
        let root = canonical_root(&dir).unwrap();
        assert_eq!(
            safe_copy_file(&link, &dst, &root).unwrap(),
            SafeCopyOutcome::Skipped
        );
        assert!(!dst.exists());
        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn safe_copy_dir_skips_links_and_filtered_names() {
        let dir = create_private_tempdir("cpdir").unwrap();
        let src = dir.join("src");
        fs::create_dir_all(src.join("sub")).unwrap();
        fs::write(src.join("main.js"), "code").unwrap();
        fs::write(src.join("sub/helper.js"), "more").unwrap();
        fs::write(src.join(".env"), "SECRET=x").unwrap();
        std::os::unix::fs::symlink(&src, src.join("loop")).unwrap();
        std::os::unix::fs::symlink("/etc/passwd", src.join("evil")).unwrap();

        let dst = dir.join("dst");
        let root = canonical_root(&src).unwrap();
        safe_copy_dir(
            &src,
            &dst,
            &root,
            0,
            &|name| should_skip_build_entry(name),
            &mut CopyBudget::new(1024, 1 << 20, 1 << 20),
        )
        .unwrap();

        assert!(dst.join("main.js").exists());
        assert!(dst.join("sub/helper.js").exists());
        assert!(!dst.join(".env").exists());
        assert!(!dst.join("loop").exists());
        assert!(!dst.join("evil").exists());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn read_file_bounded_refuses_oversize() {
        let dir = create_private_tempdir("bounded").unwrap();
        let path = dir.join("f.bin");
        fs::write(&path, vec![0xABu8; 100]).unwrap();
        assert_eq!(read_file_bounded(&path, 100).unwrap().len(), 100);
        assert!(read_file_bounded(&path, 99).is_err());
        assert!(read_text_bounded(&path, 4).is_err());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn write_file_atomic_writes_and_overwrites() {
        let dir = create_private_tempdir("atomic").unwrap();
        let path = dir.join("report.json");
        write_file_atomic(&path, b"one").unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"one");
        // A second write replaces via rename — no residue.
        write_file_atomic(&path, b"two").unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"two");
        assert_eq!(
            fs::read_dir(&dir).unwrap().count(),
            1,
            "temp file leaked alongside destination"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    /// When the temp create itself fails (unwritable directory), the
    /// destination and every sibling must be left exactly as found —
    /// cleanup only runs on files we created.
    #[cfg(unix)]
    #[test]
    fn write_file_atomic_failed_create_touches_nothing() {
        use std::os::unix::fs::PermissionsExt;
        if running_as_root() {
            eprintln!("SKIP: root bypasses the 0o555 mode — cannot exercise EACCES");
            return;
        }
        let dir = create_private_tempdir("atomic-ro").unwrap();
        let dest = dir.join("report.json");
        fs::write(&dest, b"pre-existing").unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o555)).unwrap();

        let err = write_file_atomic(&dest, b"new").unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(fs::read(&dest).unwrap(), b"pre-existing");
        assert_eq!(fs::read_dir(&dir).unwrap().count(), 1);

        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        let _ = fs::remove_dir_all(&dir);
    }

    /// The pinned mode must not depend on the process umask: a report
    /// carries policy detail and is never other-readable.
    #[cfg(unix)]
    #[test]
    fn write_file_atomic_uses_restrictive_mode() {
        use std::os::unix::fs::PermissionsExt;
        let dir = create_private_tempdir("atomic-mode").unwrap();
        let path = dir.join("report.json");
        write_file_atomic(&path, b"{}").unwrap();
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "report mode was {mode:o}");
        let _ = fs::remove_dir_all(&dir);
    }

    /// A pinned directory verifies while it is the same object, and a
    /// rename-away + recreate (a replacement that would redirect a
    /// guest mount) fails verification.
    #[cfg(unix)]
    #[test]
    fn pinned_dir_detects_replacement() {
        let root = create_private_tempdir("pin").unwrap();
        let dir = root.join("logs");
        fs::create_dir(&dir).unwrap();
        let pinned = PinnedDir::pin(&dir).unwrap();
        pinned.verify_current().expect("same object verifies");

        // Swap: rename the real dir away and plant a fresh one —
        // same path, different inode.
        let decoy = root.join("logs-moved");
        fs::rename(&dir, &decoy).unwrap();
        fs::create_dir(&dir).unwrap();
        assert!(
            pinned.verify_current().is_err(),
            "a replaced directory must fail the identity check"
        );

        let _ = fs::remove_dir_all(&root);
    }

    /// A symlink where the directory is expected never pins — the mount
    /// would otherwise follow the link to an unintended host path.
    #[cfg(unix)]
    #[test]
    fn pinned_dir_rejects_symlink() {
        let root = create_private_tempdir("pin-link").unwrap();
        let real = root.join("real");
        fs::create_dir(&real).unwrap();
        let link = root.join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        assert!(PinnedDir::pin(&link).is_err());
        let _ = fs::remove_dir_all(&root);
    }

    /// A group/world-writable parent without the sticky bit allows a
    /// lower-trust principal to rename the pinned object away — the
    /// launch must refuse it. A sticky parent (/tmp-style) is fine.
    #[cfg(unix)]
    #[test]
    fn parent_write_restriction() {
        use std::os::unix::fs::PermissionsExt;
        let root = create_private_tempdir("parent-restrict").unwrap();
        let loose = root.join("loose");
        fs::create_dir(&loose).unwrap();
        fs::set_permissions(&loose, fs::Permissions::from_mode(0o777)).unwrap();
        let child = loose.join("logs");
        fs::create_dir(&child).unwrap();
        assert!(
            require_parent_write_restricted(&child).is_err(),
            "world-writable non-sticky parent must refuse"
        );

        fs::set_permissions(&loose, fs::Permissions::from_mode(0o1777)).unwrap();
        assert!(
            require_parent_write_restricted(&child).is_ok(),
            "sticky world-writable parent (/tmp-style) is safe"
        );
        fs::set_permissions(&loose, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(require_parent_write_restricted(&child).is_ok());

        let _ = fs::remove_dir_all(&root);
    }

    /// The default drive-root DACL carries an *inherit-only*
    /// `Authenticated Users` Modify ACE — it grants rights to children
    /// created below, never to the root itself. An earlier revision
    /// tested `AceFlags` against `INHERITED_ACE` (0x10) instead of
    /// `INHERIT_ONLY_ACE` (0x08): the root's inherit-only grant was
    /// evaluated and refused every absolute path on the volume, while
    /// genuinely inherited broad ACEs on deeper directories were
    /// skipped. The root must pass; a path under a *broadly
    /// replaceable* ancestor must still fail.
    #[cfg(windows)]
    #[test]
    fn inherit_only_grants_do_not_replace_the_directory_itself() {
        let root = PathBuf::from(r"C:\");
        if !root.exists() {
            return;
        }
        assert!(
            matches!(dacl_grants_replace_rights(&root), Ok(false)),
            "drive root's inherit-only Authenticated Users ACE must be skipped: {:?}",
            dacl_grants_replace_rights(&root)
        );
    }
}
