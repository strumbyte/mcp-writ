//! One-time trusted resolution of isolation drivers and OS helpers.
//!
//! An executable that prepares or attests a sandbox boundary must
//! never be reached through caller-mutable search order or a relative
//! spelling: a substituted binary would run with the launcher's full
//! host authority *before* any containment exists. Resolution here is
//! therefore once-only and validated — the resolved canonical path is
//! bound and reused for every probe, build, launch, monitor, cleanup,
//! and teardown the driver performs.

use std::path::{Path, PathBuf};

/// Validate a candidate driver/helper path for execution: a canonical
/// absolute path that names a real file no *different* user can
/// replace.
///
/// - **Unix**: the file and every ancestor directory must be owned by
///   the caller or by root — and a root-owned entry must not be
///   world-writable (a group-writable admin dir like Homebrew's
///   `/usr/local` is accepted; an `o+w` shared dir never is).
/// - **Windows**: absolute + canonical + regular file, and the leaf
///   plus every ancestor must be owned by a trusted principal
///   (the caller, SYSTEM, Administrators, TrustedInstaller) with no
///   DACL grant that hands a broad trustee write/delete/ACL control —
///   the same "no different user can replace it" contract the Unix
///   walk enforces, expressed through SIDs instead of modes.
///
/// Errors name the rejected candidate class — callers must refuse,
/// never fall through to a later PATH entry (the same-name shadow is
/// the attack this closes).
pub(crate) fn validate_driver_path(path: &Path) -> Result<PathBuf, String> {
    if !path.is_absolute() {
        return Err(format!("'{}' is not an absolute path", path.display()));
    }
    let canon = path
        .canonicalize()
        .map_err(|e| format!("'{}' cannot be canonicalized: {e}", path.display()))?;
    let md = std::fs::metadata(&canon)
        .map_err(|e| format!("'{}' cannot be inspected: {e}", canon.display()))?;
    if !md.is_file() {
        return Err(format!("'{}' is not a regular file", canon.display()));
    }
    #[cfg(any(unix, windows))]
    if let Some(bad) = driver_replacement_gap(&canon) {
        return Err(format!(
            "'{}' (or ancestor '{}') is replaceable by a different user — a \
             substituted driver runs before sandbox setup",
            canon.display(),
            bad.display()
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if md.permissions().mode() & 0o111 == 0 {
            return Err(format!("'{}' is not executable", canon.display()));
        }
    }
    Ok(canon)
}

/// Unix gap check: the first path component — walking the file up
/// through its ancestors — that a *different* user could replace.
///
/// A component is a gap when any of these hold:
///
/// - it cannot be inspected — an unexaminable component may be
///   replaceable by whoever holds its parent, so it counts rather than
///   being silently skipped;
/// - it is owned by a user that is neither the caller nor root;
/// - it is a directory with `o+w` and no sticky bit — entries inside
///   can be renamed or swapped by anyone, whatever the owner;
/// - it is the resolved file itself with `o+w` — its contents can be
///   rewritten by anyone.
///
/// Group-write is *not* a gap on root- or caller-owned entries: the
/// admin-group convention (Homebrew's `/usr/local`, system package
/// dirs) is exactly the trust class a driver lives in, and group
/// membership is already the authority being exercised.
#[cfg(unix)]
fn driver_replacement_gap(path: &Path) -> Option<PathBuf> {
    use std::os::unix::fs::MetadataExt;
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    let euid = unsafe { libc::geteuid() };
    let mut leaf = true;
    let mut cur: Option<&Path> = Some(path);
    while let Some(p) = cur {
        let md = match std::fs::metadata(p) {
            Ok(md) => md,
            Err(_) => return Some(p.to_path_buf()),
        };
        let owner = md.uid();
        if owner != euid && owner != 0 {
            return Some(p.to_path_buf());
        }
        let world_writable = md.mode() & 0o002 != 0;
        let sticky = md.mode() & 0o1000 != 0;
        if world_writable && (leaf || !sticky) {
            return Some(p.to_path_buf());
        }
        leaf = false;
        cur = p.parent();
    }
    None
}

/// Windows gap check mirroring the Unix walk: the first component —
/// from the resolved leaf up through its ancestors — a *different*
/// principal could replace. A component is a gap when:
///
/// - its owner is not a trusted principal (`path_owner_is_trusted`
///   fails or errors — an unanswerable owner question counts as a
///   gap rather than a pass);
/// - the leaf file's DACL grants a broad trustee content-write,
///   delete, or ACL control (`dacl_grants_file_write`);
/// - an ancestor directory's DACL grants a broad trustee
///   delete/delete-child/ACL control (`dir_dacl_grants_replace_rights`)
///   — the rights to rename a component out and plant a same-name
///   substitute.
///
/// Grants to Administrators or SYSTEM are not broad: they name the
/// very authority being validated, matching the Unix "owned by root"
/// class.
#[cfg(windows)]
fn driver_replacement_gap(path: &Path) -> Option<PathBuf> {
    let mut leaf = true;
    let mut cur: Option<&Path> = Some(path);
    while let Some(p) = cur {
        match crate::fspriv::path_owner_is_trusted(p) {
            Ok(true) => {}
            _ => return Some(p.to_path_buf()),
        }
        let broad = if leaf {
            crate::fspriv::dacl_grants_file_write(p)
        } else {
            crate::fspriv::dir_dacl_grants_replace_rights(p)
        };
        match broad {
            Ok(false) => {}
            _ => return Some(p.to_path_buf()),
        }
        leaf = false;
        cur = p.parent();
    }
    None
}

/// The first `name` on PATH resolved to a *validated* canonical path.
/// An invalid hit refuses — it never falls through to the next PATH
/// entry: the shadow binary in a writable earlier directory is
/// exactly what this check exists to reject.
pub(crate) fn resolve_cli(name: &str) -> Result<PathBuf, String> {
    let found =
        crate::workload::search_path(name).ok_or_else(|| format!("'{name}' not found on PATH"))?;
    validate_driver_path(&found)
        .map_err(|e| format!("resolved '{name}' at '{}': {e}", found.display()))
}

/// An OS-owned helper resolved by its system-directory spelling —
/// never through PATH or the current directory. `rel` is the
/// System32-relative path (`"tasklist.exe"`,
/// `"WindowsPowerShell\\v1.0\\powershell.exe"`). `None` off Windows or
/// when the resolved file fails [`validate_driver_path`] — callers
/// turn that into their own refusal.
///
/// The system directory comes from `GetSystemDirectoryW` — the
/// kernel's own answer, not a caller-mutable `SystemRoot`. The x86-64
/// build is native on every supported Windows host, so the returned
/// directory *is* the native system directory — WOW64's Sysnative
/// distinction does not apply (a 32-bit process would need
/// `Sysnative`, but no such target ships).
#[cfg(windows)]
pub(crate) fn system32_exe(rel: &str) -> Option<PathBuf> {
    let dir = system_dir()?;
    validate_driver_path(&dir.join(rel)).ok()
}

#[cfg(not(windows))]
pub(crate) fn system32_exe(_rel: &str) -> Option<PathBuf> {
    None
}

/// The kernel-reported System32 directory — `GetSystemDirectoryW`,
/// never `%SystemRoot%`.
#[cfg(windows)]
fn system_dir() -> Option<PathBuf> {
    use windows::Win32::System::SystemInformation::GetSystemDirectoryW;
    let mut buf = vec![0u16; 32767];
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    let n = unsafe { GetSystemDirectoryW(Some(&mut buf)) };
    if n == 0 || n as usize >= buf.len() {
        return None;
    }
    buf.truncate(n as usize);
    Some(PathBuf::from(String::from_utf16_lossy(&buf)))
}

/// The Store-WSL install root — the system `Program Files` directory
/// joined with `WSL`, an admin-writable-only location. `None` off
/// Windows (test builds may still shape the path so resolution logic
/// is exercised).
///
/// The directory comes from `SHGetKnownFolderPath(FOLDERID_ProgramFiles)`
/// — the shell's own answer, not a caller-mutable `ProgramFiles`
/// variable. Test builds keep the env spelling so fixtures can stage a
/// fake install root; it never reaches a shipped binary.
pub(crate) fn wsl_install_dir() -> Option<PathBuf> {
    if !cfg!(windows) && !cfg!(test) {
        return None;
    }
    #[cfg(all(windows, not(test)))]
    let root = program_files_dir()?;
    #[cfg(any(not(windows), test))]
    let root = std::env::var_os("ProgramFiles")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\Program Files"));
    Some(root.join("WSL"))
}

/// `%ProgramFiles%` without the environment —
/// `SHGetKnownFolderPath` answers the admin-writable install root the
/// shell itself reports, so a poisoned environment cannot retarget the
/// resolution.
#[cfg(all(windows, not(test)))]
fn program_files_dir() -> Option<PathBuf> {
    use windows::Win32::System::Com::CoTaskMemFree;
    use windows::Win32::UI::Shell::{FOLDERID_ProgramFiles, KF_FLAG_DEFAULT, SHGetKnownFolderPath};
    let raw =
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe { SHGetKnownFolderPath(&FOLDERID_ProgramFiles, KF_FLAG_DEFAULT, None) }.ok()?;
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    let text = unsafe { raw.to_string() }.ok();
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    unsafe { CoTaskMemFree(Some(raw.0 as *const std::ffi::c_void)) };
    text.map(PathBuf::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A path under the caller's own writable directory is *their*
    /// file — replacement is their own privilege, not a driver
    /// substitution gap.
    #[cfg(unix)]
    #[test]
    fn caller_owned_path_validates() {
        let dir = tempfile::tempdir().unwrap();
        let exe = dir.path().join("tool");
        std::fs::write(&exe, b"#!/bin/sh\n").unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&exe, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(validate_driver_path(&exe).is_ok());
    }

    /// A relative spelling never reaches canonicalization — overrides
    /// and helper spellings must already be absolute.
    #[test]
    fn relative_path_refuses() {
        let err = validate_driver_path(Path::new("bin/tool")).unwrap_err();
        assert!(err.contains("absolute"), "{err}");
    }

    /// A world-writable ancestor without the sticky bit lets any user
    /// swap directory entries — caller ownership changes nothing about
    /// that. Exactly the shared-dir shape PATH resolution must not
    /// bless.
    #[cfg(unix)]
    #[test]
    fn world_writable_unsticky_ancestor_refuses() {
        let dir = tempfile::tempdir().unwrap();
        let sub = dir.path().join("sub");
        std::fs::create_dir(&sub).unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&sub, std::fs::Permissions::from_mode(0o777)).unwrap();
        let exe = sub.join("tool");
        std::fs::write(&exe, b"#!/bin/sh\n").unwrap();
        std::fs::set_permissions(&exe, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(validate_driver_path(&exe).is_err());
    }

    /// The same world-writable ancestor *with* the sticky bit is not a
    /// replacement gap — `/tmp` semantics: entries cannot be renamed
    /// away by non-owners, and the caller-owned file itself stays
    /// unwritable to others.
    #[cfg(unix)]
    #[test]
    fn world_writable_sticky_ancestor_validates() {
        let dir = tempfile::tempdir().unwrap();
        let sub = dir.path().join("sub");
        std::fs::create_dir(&sub).unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&sub, std::fs::Permissions::from_mode(0o1777)).unwrap();
        let exe = sub.join("tool");
        std::fs::write(&exe, b"#!/bin/sh\n").unwrap();
        std::fs::set_permissions(&exe, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(validate_driver_path(&exe).is_ok());
    }

    /// A world-writable resolved file can be rewritten by anyone —
    /// sticky ancestors do not protect file contents.
    #[cfg(unix)]
    #[test]
    fn world_writable_file_refuses() {
        let dir = tempfile::tempdir().unwrap();
        let exe = dir.path().join("tool");
        std::fs::write(&exe, b"#!/bin/sh\n").unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&exe, std::fs::Permissions::from_mode(0o777)).unwrap();
        assert!(validate_driver_path(&exe).is_err());
    }

    /// A non-executable regular file is never a driver.
    #[cfg(unix)]
    #[test]
    fn non_executable_refuses() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("tool");
        std::fs::write(&f, b"data").unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o644)).unwrap();
        let err = validate_driver_path(&f).unwrap_err();
        assert!(err.contains("executable"), "{err}");
    }
}
