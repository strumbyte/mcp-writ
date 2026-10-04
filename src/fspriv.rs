//! Owner-only temporary directories for policy and build staging.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

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
    Ok(dir)
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

    use windows::Win32::Foundation::{CloseHandle, GENERIC_ALL, HLOCAL, LocalFree};
    use windows::Win32::Security::Authorization::{
        EXPLICIT_ACCESS_W, GRANT_ACCESS, SE_FILE_OBJECT, SetEntriesInAclW, SetNamedSecurityInfoW,
        TRUSTEE_IS_SID, TRUSTEE_IS_USER, TRUSTEE_IS_WELL_KNOWN_GROUP, TRUSTEE_W,
    };
    use windows::Win32::Security::{
        ACL, CONTAINER_INHERIT_ACE, CreateWellKnownSid, DACL_SECURITY_INFORMATION,
        GetTokenInformation, OBJECT_INHERIT_ACE, PROTECTED_DACL_SECURITY_INFORMATION, PSID,
        TOKEN_QUERY, TOKEN_USER, TokenUser, WinLocalSystemSid,
    };
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
    use windows::core::{HSTRING, PWSTR};

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
        // into `user`, which outlives the ACL build below.
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
        result.ok().map_err(os_err).map_err(|e| {
            io::Error::other(format!(
                "SetNamedSecurityInfoW for '{}': {e}",
                dir.display()
            ))
        })
    })();
    unsafe {
        let _ = CloseHandle(token);
    }
    result
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
}
