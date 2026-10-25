//! Owner-only temporary directories for policy and build staging: a
//! directory another local principal can read or replace leaks session
//! credentials and staging artifacts, so creation always tightens the
//! object itself — mode 0700 on unix, a protected owner+SYSTEM DACL on
//! Windows — and refuses when the restriction cannot be proven.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

/// Create a new directory under the system temp dir with owner-only access.
///
/// Fails closed if the directory already exists or permissions cannot be set.
pub fn create_private_tempdir(label: &str) -> io::Result<PathBuf> {
    let dir = std::env::temp_dir() // nosemgrep: rust.lang.security.temp-dir.temp-dir
        .join(format!(
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
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
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
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
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
    use super::winsec::process_user_sid;
    use windows::Win32::Foundation::GENERIC_ALL;
    use windows::Win32::Security::Authorization::{
        EXPLICIT_ACCESS_W, GRANT_ACCESS, SetEntriesInAclW, TRUSTEE_IS_SID, TRUSTEE_IS_USER,
        TRUSTEE_IS_WELL_KNOWN_GROUP, TRUSTEE_W,
    };
    use windows::Win32::Security::{
        ACL, CONTAINER_INHERIT_ACE, CreateWellKnownSid, OBJECT_INHERIT_ACE, PSID, TOKEN_USER,
        WinLocalSystemSid,
    };
    use windows::core::PWSTR;

    let os_err = |e: windows::core::Error| io::Error::other(e.to_string());

    // The session's own user SID via the process token — the ACE must
    // name the real user (an elevated process would otherwise grant the
    // Administrators group, not the account holding the credentials).
    // SAFETY: the buffer holds a TOKEN_USER whose Sid member points
    // into `user`, which must outlive the ACL application.
    (|| {
        let user = process_user_sid()?;
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        let user_sid = unsafe { (*user.as_ptr().cast::<TOKEN_USER>()).User.Sid };

        // SECURITY_MAX_SID_SIZE; CreateWellKnownSid fills caller memory,
        // nothing to free.
        let mut system = vec![0u8; 68];
        let mut size = system.len() as u32;
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
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
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe { SetEntriesInAclW(Some(&entries), None, &mut dacl) }
            .ok()
            .map_err(os_err)?;
        Ok((dacl, user, system))
    })()
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
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
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
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe {
            LocalFree(Some(HLOCAL(dacl as *mut c_void)));
        }
    }
    result
        .ok()
        .map_err(|e| io::Error::other(format!("SetSecurityInfo: {e}")))
}
