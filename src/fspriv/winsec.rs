//! Windows security-descriptor machinery: the DACL/owner queries that
//! decide whether a path can be retargeted or rewritten by a
//! lower-trust principal, and the literal-path proofs that an open
//! handle traversed no junction/reparse substitution. Everything here
//! is `cfg(windows)` — the unix halves of the callers use permission
//! bits instead.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use super::handle::real_path_of;

/// `\\?\` verbatim spellings fail the object-name lookup, so the
/// security APIs take the de-verbatized spelling (`\\?\UNC\x` → `\\x`,
/// `\\?\C:` → `C:`).
#[cfg(windows)]
fn security_lookup_name(path: &Path) -> String {
    let text = path.to_string_lossy();
    if let Some(rest) = text.strip_prefix(r"\\?\UNC\") {
        format!(r"\\{rest}")
    } else {
        text.strip_prefix(r"\\?\").unwrap_or(&text).to_string()
    }
}

/// `GetNamedSecurityInfoW` error → `io`: FILE_NOT_FOUND/PATH_NOT_FOUND
/// must surface as `NotFound` so ancestor walks can skip not-yet-created
/// levels. The API reports Win32 codes wrapped in HRESULTs (0x8007xxxx),
/// so the low word is what matches ERROR_FILE_NOT_FOUND /
/// ERROR_PATH_NOT_FOUND.
#[cfg(windows)]
fn named_security_err(e: windows::core::Error, path: &Path) -> io::Error {
    let win32 = e.code().0 as u32 & 0xFFFF;
    if win32 == 2 || win32 == 3 {
        io::Error::new(
            io::ErrorKind::NotFound,
            format!("'{}': {e}", path.display()),
        )
    } else {
        io::Error::other(format!(
            "GetNamedSecurityInfoW for '{}': {e}",
            path.display()
        ))
    }
}

/// The SD heap allocation `GetNamedSecurityInfoW`/`GetSecurityInfo`
/// returns must be `LocalFree`d whatever the walk finds.
#[cfg(windows)]
pub(crate) struct SdGuard(pub(crate) *mut std::ffi::c_void);

#[cfg(windows)]
impl Drop for SdGuard {
    fn drop(&mut self) {
        if !self.0.is_null() {
            use windows::Win32::Foundation::{HLOCAL, LocalFree};
            // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
            unsafe {
                let _ = LocalFree(Some(HLOCAL(self.0)));
            }
        }
    }
}

/// ACE header type byte for an access-allowed ACE (`winnt.h`).
#[cfg(windows)]
const ACCESS_ALLOWED_ACE_TYPE: u8 = 0;
/// Conditional allow-ACE — same layout as the plain allow-ACE, but
/// the grant is gated on a condition evaluated against the caller's
/// token at access time (`winnt.h` `ACCESS_ALLOWED_CALLBACK_ACE_TYPE`).
#[cfg(windows)]
const ACCESS_ALLOWED_CALLBACK_ACE_TYPE: u8 = 0x09;
/// Allow-ACE variants whose layout moves the trustee SID off the
/// plain-ACE offset (`winnt.h`): compound (0x04), object (0x05),
/// callback-object (0x0B).
#[cfg(windows)]
const ACCESS_ALLOWED_COMPOUND_ACE_TYPE: u8 = 0x04;
#[cfg(windows)]
const ACCESS_ALLOWED_OBJECT_ACE_TYPE: u8 = 0x05;
#[cfg(windows)]
const ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE: u8 = 0x0B;
/// `AceFlags` bit marking an ACE that never applies to the object
/// itself (`winnt.h` `INHERIT_ONLY_ACE`) — it exists only to be
/// inherited by children, so it cannot grant rights on this object.
/// `0x10` is `INHERITED_ACE` — a different flag, and one that must
/// NOT be skipped: a non-inherit-only ACE that arrived by
/// inheritance still governs access to this object.
#[cfg(windows)]
const INHERIT_ONLY_ACE: u8 = 0x08;

/// True when `sid` names an administrative principal: SYSTEM, the
/// Administrators group, or TrustedInstaller — the authorities a
/// stock install entrusts with `C:\Windows`/`C:\Program Files`.
#[cfg(windows)]
fn sid_is_admin_principal(sid: windows::Win32::Security::PSID) -> bool {
    use windows::Win32::Security::{
        IsWellKnownSid, WinBuiltinAdministratorsSid, WinLocalSystemSid,
    };

    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    if unsafe {
        IsWellKnownSid(sid, WinLocalSystemSid).as_bool()
            || IsWellKnownSid(sid, WinBuiltinAdministratorsSid).as_bool()
    } {
        return true;
    }
    sid_is_trusted_installer(sid)
}

/// True when `sid` names a principal whose dangerous-rights grants a
/// driver path may carry: an administrative principal, or the
/// owner-delegating placeholders CREATOR OWNER and OWNER RIGHTS —
/// their grants resolve to the object's owner, which the caller
/// separately requires to be a trusted principal. With `caller_ok` the
/// invoking user also counts (driver paths the caller may already
/// control); administrator-only resolution passes `false`.
#[cfg(windows)]
fn trustee_sid_is_trusted(
    sid: windows::Win32::Security::PSID,
    caller_ok: bool,
) -> io::Result<bool> {
    use windows::Win32::Security::{IsWellKnownSid, WinCreatorOwnerSid};

    if sid_is_admin_principal(sid) {
        return Ok(true);
    }
    // CREATOR OWNER (well-known) and OWNER RIGHTS (S-1-3-4, not in the
    // enum) delegate to the object's owner — trusted only because the
    // owner check separately requires a trusted principal.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    if unsafe { IsWellKnownSid(sid, WinCreatorOwnerSid).as_bool() } || sid_is_string(sid, "S-1-3-4")
    {
        return Ok(true);
    }
    if caller_ok {
        return sid_is_current_user(sid);
    }
    Ok(false)
}

/// True when `sid` equals the SID spelled `sddl` — for principals the
/// `WELL_KNOWN_SID_TYPE` enum does not name (TrustedInstaller, OWNER
/// RIGHTS), so the comparison SID is built from its string form.
#[cfg(windows)]
fn sid_is_string(sid: windows::Win32::Security::PSID, sddl: &str) -> bool {
    use windows::Win32::Security::Authorization::ConvertStringSidToSidW;
    use windows::Win32::Security::{EqualSid, PSID};
    use windows::core::HSTRING;

    let mut other = PSID(std::ptr::null_mut());
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    if unsafe { ConvertStringSidToSidW(&HSTRING::from(sddl), &mut other) }.is_ok() {
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        let equal = unsafe { EqualSid(sid, other).map(|_| true).unwrap_or(false) };
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe {
            let _ = windows::Win32::Foundation::LocalFree(Some(
                windows::Win32::Foundation::HLOCAL(other.0),
            ));
        }
        return equal;
    }
    false
}

/// NT SERVICE\TrustedInstaller — not a WELL_KNOWN_SID_TYPE, so the
/// comparison SID is built from its string form.
#[cfg(windows)]
fn sid_is_trusted_installer(sid: windows::Win32::Security::PSID) -> bool {
    sid_is_string(
        sid,
        "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464",
    )
}

/// True when `sid` is the process token's user SID.
#[cfg(windows)]
fn sid_is_current_user(sid: windows::Win32::Security::PSID) -> io::Result<bool> {
    use windows::Win32::Security::{EqualSid, TOKEN_USER};

    let user = process_user_sid()?;
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    let user_sid = unsafe { (*user.as_ptr().cast::<TOKEN_USER>()).User.Sid };
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    Ok(unsafe { EqualSid(sid, user_sid).map(|_| true).unwrap_or(false) })
}

/// Walk `path`'s DACL for access-allowed ACEs that hand an *untrusted*
/// trustee any right in `rights` — every trustee outside the
/// administrator/owner set (and the caller, when `caller_ok`). Named
/// users and custom groups count: a grant to a specific non-admin
/// account is as much a replacement right as one to Everyone. A null
/// DACL pointer means unrestricted access — fail toward "untrusted
/// grant possible" rather than declaring the object safe.
#[cfg(windows)]
fn dacl_grants_untrusted(path: &Path, rights: u32, caller_ok: bool) -> io::Result<bool> {
    use windows::Win32::Security::Authorization::{GetNamedSecurityInfoW, SE_FILE_OBJECT};
    use windows::Win32::Security::{ACL, DACL_SECURITY_INFORMATION};
    use windows::core::HSTRING;

    let name = security_lookup_name(path);
    let mut dacl: *mut ACL = std::ptr::null_mut();
    let mut sd: windows::Win32::Security::PSECURITY_DESCRIPTOR =
        windows::Win32::Security::PSECURITY_DESCRIPTOR(std::ptr::null_mut());
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
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
    status.ok().map_err(|e| named_security_err(e, path))?;
    let _sd_guard = SdGuard(sd.0);
    dacl_has_untrusted_grant(dacl, rights, caller_ok)
}

/// The ACE walk shared by the path and handle DACL variants — a null
/// `dacl` is unrestricted access and answers `true` rather than
/// declaring the object safe.
#[cfg(windows)]
pub(crate) fn dacl_has_untrusted_grant(
    dacl: *mut windows::Win32::Security::ACL,
    rights: u32,
    caller_ok: bool,
) -> io::Result<bool> {
    use std::ffi::c_void;

    use windows::Win32::Security::{
        ACCESS_ALLOWED_ACE, ACL_SIZE_INFORMATION, AclSizeInformation, GetAce, GetAclInformation,
        PSID,
    };

    if dacl.is_null() {
        return Ok(true);
    }
    let mut info = ACL_SIZE_INFORMATION::default();
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    unsafe {
        GetAclInformation(
            dacl,
            &mut info as *mut _ as *mut c_void,
            size_of::<ACL_SIZE_INFORMATION>() as u32,
            AclSizeInformation,
        )
    }
    .map_err(|e| io::Error::other(format!("GetAclInformation: {e}")))?;

    for i in 0..info.AceCount {
        let mut ace: *mut c_void = std::ptr::null_mut();
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe {
            GetAce(dacl, i, &mut ace).map_err(|e| io::Error::other(format!("GetAce: {e}")))?;
        }
        let ace = ace.cast::<ACCESS_ALLOWED_ACE>();
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        let ace_type = unsafe { (*ace).Header.AceType };
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        if unsafe { (*ace).Header.AceFlags } & INHERIT_ONLY_ACE != 0 {
            continue;
        }
        // `Mask` sits at the same offset in every ACCESS_ALLOWED_*
        // variant, so the rights check runs before the layout differs.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        let mask = unsafe { (*ace).Mask };
        if mask & rights == 0 {
            continue;
        }
        match ace_type {
            // The plain allow-ACE and the callback variant share this
            // layout. A callback ACE's grant condition is evaluated
            // against the caller's token at access time and cannot be
            // proven statically, so an applicable callback grant to an
            // untrusted trustee counts as untrusted access.
            ACCESS_ALLOWED_ACE_TYPE | ACCESS_ALLOWED_CALLBACK_ACE_TYPE => {
                // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
                let sid = unsafe { PSID(&raw const (*ace).SidStart as *mut c_void) };
                if !trustee_sid_is_trusted(sid, caller_ok)? {
                    return Ok(true);
                }
            }
            // Compound, object, and callback-object allow-ACEs move the
            // SID off the plain-ACE offset, so the trustee cannot be
            // inspected — a rights-bearing allow-ACE that cannot be
            // proven narrow fails toward "untrusted access possible".
            ACCESS_ALLOWED_COMPOUND_ACE_TYPE
            | ACCESS_ALLOWED_OBJECT_ACE_TYPE
            | ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE => return Ok(true),
            _ => {}
        }
    }
    Ok(false)
}

/// `GetSecurityInfo`-based variant of [`dacl_grants_untrusted`] on an
/// *open* handle — the DACL inspected is the pinned object's own, not
/// whatever the path happens to name when the caller gets to it.
#[cfg(windows)]
fn handle_dacl_grants_untrusted(file: &fs::File, rights: u32, caller_ok: bool) -> io::Result<bool> {
    use std::os::windows::io::AsRawHandle;

    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::Security::Authorization::{GetSecurityInfo, SE_FILE_OBJECT};
    use windows::Win32::Security::{ACL, DACL_SECURITY_INFORMATION};

    let mut dacl: *mut ACL = std::ptr::null_mut();
    let mut sd = windows::Win32::Security::PSECURITY_DESCRIPTOR(std::ptr::null_mut());
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    unsafe {
        GetSecurityInfo(
            HANDLE(file.as_raw_handle()),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            None,
            None,
            Some(&mut dacl),
            None,
            Some(&mut sd),
        )
    }
    .ok()
    .map_err(|e| io::Error::other(format!("GetSecurityInfo: {e}")))?;
    let _sd_guard = SdGuard(sd.0);
    dacl_has_untrusted_grant(dacl, rights, caller_ok)
}

/// Walk `dir`'s DACL for allow-ACEs that hand an untrusted trustee the
/// rights needed to *replace* a child entry — delete/delete-child or
/// ACL/ownership control. Add-only rights (FILE_ADD_FILE,
/// FILE_ADD_SUBDIRECTORY, FILE_APPEND_DATA) are deliberately absent:
/// they let a principal plant a sibling, not retarget an existing
/// component, and drive roots grant them to Authenticated Users —
/// counting them would refuse every path on the volume.
/// The rights mask [`dacl_grants_replace_rights`] checks on a
/// directory: the rights needed to *replace* a child entry —
/// delete/delete-child or ACL/ownership control. Add-only rights
/// (FILE_ADD_FILE, FILE_ADD_SUBDIRECTORY, FILE_APPEND_DATA) are
/// deliberately absent: they let a principal plant a sibling, not
/// retarget an existing component, and drive roots grant them to
/// Authenticated Users — counting them would refuse every path on the
/// volume.
#[cfg(windows)]
pub(crate) fn dir_replace_rights() -> u32 {
    use windows::Win32::Foundation::{GENERIC_ALL, GENERIC_WRITE};
    use windows::Win32::Storage::FileSystem::{DELETE, FILE_DELETE_CHILD, WRITE_DAC, WRITE_OWNER};

    DELETE.0 | FILE_DELETE_CHILD.0 | WRITE_DAC.0 | WRITE_OWNER.0 | GENERIC_WRITE.0 | GENERIC_ALL.0
}

#[cfg(windows)]
pub(crate) fn dacl_grants_replace_rights(dir: &Path, caller_ok: bool) -> io::Result<bool> {
    dacl_grants_untrusted(dir, dir_replace_rights(), caller_ok)
}

/// True when `dir`'s DACL hands an untrusted trustee the rights to
/// replace a child entry — exposed for the driver-validation walk in
/// `trusted_path`, which applies the same check to every ancestor of a
/// candidate executable. `caller_ok` selects the trust class: driver
/// resolution under administrator-only provenance passes `false` so a
/// grant to the invoking user counts as replaceable too.
#[cfg(windows)]
pub(crate) fn dir_dacl_grants_replace_rights(dir: &Path, caller_ok: bool) -> io::Result<bool> {
    dacl_grants_replace_rights(dir, caller_ok)
}

/// The rights mask [`dacl_grants_file_write`] and its handle variant
/// check: an untrusted trustee holding any of these on an *executable*
/// can rewrite or replace the image itself — FILE_WRITE_DATA/APPEND
/// cover content mutation, DELETE covers remove-and-recreate, and
/// WRITE_DAC/WRITE_OWNER hand over the file's own protection.
#[cfg(windows)]
pub(crate) fn file_write_rights() -> u32 {
    use windows::Win32::Foundation::{GENERIC_ALL, GENERIC_WRITE};
    use windows::Win32::Storage::FileSystem::{
        DELETE, FILE_APPEND_DATA, FILE_WRITE_DATA, WRITE_DAC, WRITE_OWNER,
    };

    DELETE.0
        | FILE_WRITE_DATA.0
        | FILE_APPEND_DATA.0
        | WRITE_DAC.0
        | WRITE_OWNER.0
        | GENERIC_WRITE.0
        | GENERIC_ALL.0
}

/// File-leaf variant of [`dacl_grants_replace_rights`]. Used by
/// `trusted_path`'s driver validation on the resolved leaf (ancestors
/// take the directory mask).
#[cfg(windows)]
pub(crate) fn dacl_grants_file_write(path: &Path, caller_ok: bool) -> io::Result<bool> {
    dacl_grants_untrusted(path, file_write_rights(), caller_ok)
}

/// [`dacl_grants_file_write`] on an open handle — the pinned object's
/// own DACL, bound to the object rather than the path spelling.
#[cfg(windows)]
pub(crate) fn handle_dacl_grants_file_write(file: &fs::File, caller_ok: bool) -> io::Result<bool> {
    handle_dacl_grants_untrusted(file, file_write_rights(), caller_ok)
}

/// The owner SID the process token reports for the current user —
/// the buffer keeps the TOKEN_USER allocation alive; read the SID
/// pointer from it at the call site.
#[cfg(windows)]
pub(crate) fn process_user_sid() -> io::Result<Vec<usize>> {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::Security::{GetTokenInformation, TOKEN_QUERY, TokenUser};
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    let os_err = |e: windows::core::Error| io::Error::other(e.to_string());
    let mut token = windows::Win32::Foundation::HANDLE::default();
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) }.map_err(os_err)?;
    let result = (|| {
        let mut need = 0u32;
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        let _ = unsafe { GetTokenInformation(token, TokenUser, None, 0, &mut need) };
        let mut user = vec![0usize; (need as usize).div_ceil(size_of::<usize>())];
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
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
        Ok(user)
    })();
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    unsafe {
        let _ = CloseHandle(token);
    }
    result
}

/// True when `sid` names a principal allowed to own a security-boundary
/// object: an administrative principal always; the current user only
/// when `caller_ok` (it already controls the account's own files). Any
/// *other* owner is a foreign principal that retains implicit control
/// (WRITE_DAC) over the object.
#[cfg(windows)]
fn owner_sid_is_trusted(sid: windows::Win32::Security::PSID, caller_ok: bool) -> io::Result<bool> {
    if sid_is_admin_principal(sid) {
        return Ok(true);
    }
    if caller_ok {
        return sid_is_current_user(sid);
    }
    Ok(false)
}

/// Owner check on an *open* handle (`GetSecurityInfo` — no path
/// re-resolution): true when the object's owner SID is a trusted
/// principal per [`owner_sid_is_trusted`]. The audit sink applies this
/// to refuse an existing sink a foreign user still controls; driver
/// binding passes `caller_ok = false` so a caller-owned executable is
/// not administrator provenance.
#[cfg(windows)]
pub(crate) fn handle_owner_is_trusted(file: &fs::File, caller_ok: bool) -> io::Result<bool> {
    use std::os::windows::io::AsRawHandle;

    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::Security::Authorization::{GetSecurityInfo, SE_FILE_OBJECT};
    use windows::Win32::Security::{OWNER_SECURITY_INFORMATION, PSID};

    let mut owner = PSID(std::ptr::null_mut());
    let mut sd = windows::Win32::Security::PSECURITY_DESCRIPTOR(std::ptr::null_mut());
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    unsafe {
        GetSecurityInfo(
            HANDLE(file.as_raw_handle()),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION,
            Some(&mut owner),
            None,
            None,
            None,
            Some(&mut sd),
        )
    }
    .ok()
    .map_err(|e| io::Error::other(format!("GetSecurityInfo: {e}")))?;
    let _sd_guard = SdGuard(sd.0);
    if owner.0.is_null() {
        return Ok(false);
    }
    owner_sid_is_trusted(owner, caller_ok)
}

/// Path-based variant of [`handle_owner_is_trusted`] for validation-time
/// checks where no handle exists yet (`trusted_path` driver candidates —
/// the canonical path is fixed and race-free for this purpose).
#[cfg(windows)]
pub(crate) fn path_owner_is_trusted(path: &Path, caller_ok: bool) -> io::Result<bool> {
    use windows::Win32::Security::Authorization::{GetNamedSecurityInfoW, SE_FILE_OBJECT};
    use windows::Win32::Security::{OWNER_SECURITY_INFORMATION, PSID};
    use windows::core::HSTRING;

    let name = security_lookup_name(path);
    let mut owner = PSID(std::ptr::null_mut());
    let mut sd = windows::Win32::Security::PSECURITY_DESCRIPTOR(std::ptr::null_mut());
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    let status = unsafe {
        GetNamedSecurityInfoW(
            &HSTRING::from(name.as_str()),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION,
            Some(&mut owner),
            None,
            None,
            None,
            &mut sd,
        )
    };
    status.ok().map_err(|e| named_security_err(e, path))?;
    let _sd_guard = SdGuard(sd.0);
    if owner.0.is_null() {
        return Ok(false);
    }
    owner_sid_is_trusted(owner, caller_ok)
}

/// Windows: every existing ancestor of `path` must be a real directory
/// — a symlink/junction/mount point in the chain would redirect opens
/// outside the operator's tree. Missing components are skipped (a
/// not-yet-created level cannot redirect). This is the fast pre-check;
/// the *authoritative* proof is `opened_at_literal_path` on the final
/// handle, which the ancestor walk alone can never provide because the
/// path can be swapped between the two.
#[cfg(windows)]
pub(crate) fn require_no_reparse_ancestors(path: &Path) -> io::Result<()> {
    use std::os::windows::fs::MetadataExt;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    for anc in path.ancestors().skip(1) {
        match fs::symlink_metadata(anc) {
            Ok(m) if m.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 => {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!("ancestor '{}' is a reparse point", anc.display()),
                ));
            }
            Ok(m) if !m.is_dir() => {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!("ancestor '{}' is not a directory", anc.display()),
                ));
            }
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// Windows: the *literal* normalized spelling of `path` — absolute
/// (cwd-joined), `.`/`..` resolved lexically, `\\?\` verbatim prefix
/// stripped. Comparing [`real_path_of`]'s answer against this spelling
/// proves the open traversed no junction/symlink: any reparse point in
/// the chain would have redirected the handle's final path.
#[cfg(windows)]
pub(crate) fn literal_normalized_path(path: &Path) -> PathBuf {
    let joined = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map(|cwd| cwd.join(path))
            .unwrap_or_else(|_| path.to_path_buf())
    };
    let spelled = crate::pathutil::lexical_normalize_path(&joined).unwrap_or(joined);
    on_disk_component_names(&spelled)
}

/// Windows: fold each existing component of `path` to its on-disk
/// directory-entry name — the same names a `FILE_NAME_NORMALIZED`
/// handle path reports — so an 8.3 (`RUNNER~1`) or case-only variant
/// of the spelled chain still compares equal to the open handle's
/// real path. `FindFirstFileW` reads the entry in its parent without
/// traversing it, so a junction keeps its own name here while the
/// handle path shows the reparse target — the substitution proof is
/// preserved. Components that do not resolve (absent leaf, remote
/// share) keep their spelled form.
#[cfg(windows)]
fn on_disk_component_names(path: &Path) -> PathBuf {
    use std::os::windows::ffi::OsStrExt;
    use std::path::Component;
    use windows::Win32::Storage::FileSystem::{FindClose, FindFirstFileW, WIN32_FIND_DATAW};
    use windows::core::HSTRING;

    // FindFirstFileW pattern metacharacters — none can appear in a real
    // on-disk name.
    const WILDCARDS: [u16; 5] = [
        b'*' as u16,
        b'?' as u16,
        b'<' as u16,
        b'>' as u16,
        b'"' as u16,
    ];
    let mut out = PathBuf::new();
    for comp in path.components() {
        out.push(comp.as_os_str());
        if !matches!(comp, Component::Normal(_)) {
            continue;
        }
        // A spelled component carrying wildcard characters is not an
        // on-disk name, but FindFirstFileW would treat it as a pattern
        // and fold to an unrelated entry — keep the spelling.
        if comp
            .as_os_str()
            .encode_wide()
            .any(|c| WILDCARDS.contains(&c))
        {
            continue;
        }
        // Query the parent dir for this entry's on-disk name; a miss
        // keeps the spelled component.
        let mut data: WIN32_FIND_DATAW = unsafe { std::mem::zeroed() };
        let Ok(handle) = (unsafe { FindFirstFileW(&HSTRING::from(out.as_os_str()), &mut data) })
        else {
            continue;
        };
        unsafe {
            let _ = FindClose(handle);
        }
        let end = data
            .cFileName
            .iter()
            .position(|&c| c == 0)
            .unwrap_or(data.cFileName.len());
        if end == 0 {
            continue;
        }
        out.set_file_name(String::from_utf16_lossy(&data.cFileName[..end]));
    }
    out
}

/// Windows: true when the open `file`'s real path equals the literal
/// normalized spelling of `path` — i.e. opening `path` traversed no
/// junction/reparse substitution. Compared case-insensitively with
/// `\\?\`-prefix normalization, matching `FILE_NAME_NORMALIZED`'s
/// on-disk casing.
#[cfg(windows)]
pub(crate) fn opened_at_literal_path(file: &fs::File, path: &Path) -> io::Result<bool> {
    let real = real_path_of(file)?;
    let expected = literal_normalized_path(path);
    let strip = |p: &Path| -> String {
        let s = p.to_string_lossy();
        if let Some(rest) = s.strip_prefix(r"\\?\UNC\") {
            format!(r"\\{rest}")
        } else {
            s.strip_prefix(r"\\?\").unwrap_or(&s).to_string()
        }
    };
    Ok(crate::pathutil::paths_equal(
        &strip(&real),
        &strip(&expected),
    ))
}
