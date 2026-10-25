//! AppContainer profile lifecycle.
//!
//! Owns the sandbox profile: creation via `CreateAppContainerProfile`,
//! capability SIDs, filesystem ACL grants, loopback exemption, and cleanup.
//! Process creation inside the profile lives in `windows_proc` (which
//! implements [`AppContainerSandbox::spawn`]); UTF-16 environment blocks live
//! in `windows_env`.

use std::ffi::c_void;
use std::path::{Path, PathBuf};

use std::os::windows::io::AsRawHandle;

use windows::Win32::Foundation::HANDLE;
use windows::Win32::Security::Authorization::{
    EXPLICIT_ACCESS_W, GRANT_ACCESS, GetSecurityInfo, REVOKE_ACCESS, SE_FILE_OBJECT,
    SetEntriesInAclW, SetSecurityInfo, TRUSTEE_IS_SID, TRUSTEE_IS_WELL_KNOWN_GROUP, TRUSTEE_W,
};
use windows::Win32::Security::Isolation::{CreateAppContainerProfile, DeleteAppContainerProfile};
use windows::Win32::Security::{
    ACE_FLAGS, ACL, CONTAINER_INHERIT_ACE, CreateWellKnownSid, DACL_SECURITY_INFORMATION, FreeSid,
    GetSecurityDescriptorControl, OBJECT_INHERIT_ACE, PROTECTED_DACL_SECURITY_INFORMATION,
    PSECURITY_DESCRIPTOR, PSID, SE_DACL_PROTECTED, SECURITY_CAPABILITIES, SID_AND_ATTRIBUTES,
    UNPROTECTED_DACL_SECURITY_INFORMATION, WELL_KNOWN_SID_TYPE,
    WinCapabilityInternetClientServerSid, WinCapabilityInternetClientSid,
    WinCapabilityPrivateNetworkClientServerSid,
};
use windows::Win32::Storage::FileSystem::{
    BY_HANDLE_FILE_INFORMATION, FILE_FLAG_BACKUP_SEMANTICS, FILE_SHARE_DELETE, FILE_SHARE_READ,
    FILE_SHARE_WRITE, GetFileInformationByHandle,
};
use windows::core::HSTRING;

use crate::error::{SandboxStage, WardenError};
use crate::policy::Policy;

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────────

/// SE_GROUP_ENABLED attribute for SID_AND_ATTRIBUTES.
const SE_GROUP_ENABLED: u32 = 0x0000_0004;

/// Maximum SID size for well-known SID allocation.
const MAX_SID_SIZE: usize = 68; // SECURITY_MAX_SID_SIZE

/// Generic access rights for ACL manipulation.
const GENERIC_READ: u32 = 0x8000_0000;
#[allow(dead_code)]
const GENERIC_WRITE: u32 = 0x4000_0000;
const GENERIC_EXECUTE: u32 = 0x2000_0000;
const FILE_TRAVERSE: u32 = 0x0000_0020;
const FILE_READ_ATTRIBUTES: u32 = 0x0000_0080;
const FILE_WRITE_DATA: u32 = 0x0000_0002;
const FILE_APPEND_DATA: u32 = 0x0000_0004;
const FILE_WRITE_EA: u32 = 0x0000_0010;
const FILE_WRITE_ATTRIBUTES: u32 = 0x0000_0100;
const DELETE: u32 = 0x0001_0000;
const SYNCHRONIZE: u32 = 0x0010_0000;
/// Data-plane write without WRITE_DAC / WRITE_OWNER (not GENERIC_ALL).
const FILE_DATA_WRITE: u32 = GENERIC_READ
    | GENERIC_EXECUTE
    | FILE_WRITE_DATA
    | FILE_APPEND_DATA
    | FILE_WRITE_EA
    | FILE_WRITE_ATTRIBUTES
    | DELETE
    | SYNCHRONIZE;

// ─────────────────────────────────────────────────────────────────────────────
// Capability mapping
// ─────────────────────────────────────────────────────────────────────────────

/// Maps policy-level capability names to well-known SID types.
struct CapabilityEntry {
    name: &'static str,
    sid_type: WELL_KNOWN_SID_TYPE,
}

/// Well-known AppContainer capabilities.
const KNOWN_CAPABILITIES: &[CapabilityEntry] = &[
    CapabilityEntry {
        name: "internetClient",
        sid_type: WinCapabilityInternetClientSid,
    },
    CapabilityEntry {
        name: "internetClientServer",
        sid_type: WinCapabilityInternetClientServerSid,
    },
    CapabilityEntry {
        name: "privateNetworkClientServer",
        sid_type: WinCapabilityPrivateNetworkClientServerSid,
    },
];

/// Map a capability name to its well-known SID type.
fn lookup_capability(name: &str) -> Option<WELL_KNOWN_SID_TYPE> {
    KNOWN_CAPABILITIES
        .iter()
        .find(|entry| entry.name == name)
        .map(|entry| entry.sid_type)
}

/// Determine which capabilities a policy requires.
pub(super) fn capabilities_for_policy(policy: &Policy) -> Vec<&'static str> {
    let mut caps = Vec::new();

    // Fine-grained host allowlists are not enforceable by AppContainer.
    // Validation rejects that combination on Windows; do not grant Internet
    // when deny_all_others is set, even if `allowed` is nonempty.
    if !policy.network.outbound.deny_all_others {
        caps.push("internetClient");
        caps.push("privateNetworkClientServer");
        if policy.network.inbound.allow_listen {
            caps.push("internetClientServer");
        }
    }

    caps
}

/// Strip a `\\?\` verbatim prefix where a regular spelling exists:
/// `\\?\C:\…` becomes `C:\…` and `\\?\UNC\…` becomes `\\…`.
///
/// `std::fs::canonicalize` returns verbatim paths on Windows, so a verified
/// executable arrives in that spelling. The ACL-grant open and the
/// diagnostics both want the regular spelling.
///
/// Only the drive-letter and UNC forms have a non-verbatim equivalent.
/// Other `\\?\` namespaces — `\\?\Volume{guid}\…`, `\\?\GLOBALROOT\…` —
/// name device-namespace objects with no regular spelling; stripping the
/// prefix would produce a path that resolves differently, so they pass
/// through unchanged.
fn strip_verbatim_prefix(path: &str) -> String {
    if let Some(rest) = path.strip_prefix(r"\\?\UNC\") {
        return format!(r"\\{rest}");
    }
    let Some(rest) = path.strip_prefix(r"\\?\") else {
        return path.to_string();
    };
    let mut chars = rest.chars();
    let is_drive_path = chars.next().is_some_and(|c| c.is_ascii_alphabetic())
        && chars.next() == Some(':')
        && chars.next() == Some('\\');
    if is_drive_path {
        rest.to_string()
    } else {
        path.to_string()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Owned SID buffer
// ─────────────────────────────────────────────────────────────────────────────

/// A heap-allocated SID buffer whose lifetime is managed by Rust.
///
/// Used for capability SIDs created via `CreateWellKnownSid`.
/// The backing `Vec<u8>` owns the memory; `as_psid()` returns a borrowed pointer.
struct OwnedSid {
    buffer: Vec<u8>,
}

impl OwnedSid {
    /// Create a well-known SID by type.
    fn from_well_known(sid_type: WELL_KNOWN_SID_TYPE) -> Result<Self, WardenError> {
        let mut buffer = vec![0u8; MAX_SID_SIZE];
        let mut size = MAX_SID_SIZE as u32;

        // Safety: CreateWellKnownSid writes into our buffer up to `size` bytes.
        // We pre-allocate MAX_SID_SIZE which is the documented maximum.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe {
            CreateWellKnownSid(
                sid_type,
                None,
                Some(PSID(buffer.as_mut_ptr().cast())),
                &mut size,
            )
            .map_err(|e| {
                WardenError::sandbox_setup(
                    SandboxStage::Prepare,
                    format!("CreateWellKnownSid (call): {e}"),
                )
            })?;
        }

        buffer.truncate(size as usize);
        Ok(OwnedSid { buffer })
    }

    /// Return a PSID pointer into this buffer.
    ///
    /// The pointer is valid as long as `self` is alive.
    fn as_psid(&self) -> PSID {
        PSID(self.buffer.as_ptr() as *mut c_void)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// AppContainerSandbox
// ─────────────────────────────────────────────────────────────────────────────

/// Whether LPAC mode is opted into — `MCP_WRIT_WINDOWS_LPAC` must equal
/// exactly `1`. Shared by the child-process configuration and the launch
/// report's `os.process` reason so the two cannot disagree.
pub(crate) fn lpac_enabled() -> bool {
    std::env::var("MCP_WRIT_WINDOWS_LPAC").as_deref() == Ok("1")
}

/// One filesystem object this sandbox granted — pinned by open handle,
/// never re-resolved by name. The handle keeps the *object* constant
/// across path churn; `identity` is the (volume serial, file index)
/// pair the teardown re-verifies before every mutation.
struct GrantedObject {
    file: std::fs::File,
    identity: (u64, u64),
    /// Spelling at grant time — diagnostics only.
    path: PathBuf,
    /// Any ACE on this object was written inheritable: its copies were
    /// propagated to descendants, so the revoke must propagate too
    /// (`SetSecurityInfo`). Objects holding only non-inherited ACEs
    /// revoke through `SetKernelObjectSecurity` — nothing propagated
    /// out, so no descendant walk is needed (see `write_object_dacl`).
    propagates: bool,
}

/// Open an ACL-grant target once so the handle pins the file object.
/// `READ_CONTROL | WRITE_DAC` is exactly what the get/set DACL calls
/// need; `FILE_FLAG_BACKUP_SEMANTICS` opens directories; full sharing
/// keeps the pin from blocking a legitimate rename of the path.
fn open_acl_object(path: &Path) -> Result<std::fs::File, WardenError> {
    use std::os::windows::fs::OpenOptionsExt;
    const READ_CONTROL: u32 = 0x0002_0000;
    const WRITE_DAC: u32 = 0x0004_0000;
    std::fs::OpenOptions::new()
        .access_mode(READ_CONTROL | WRITE_DAC)
        .share_mode((FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE).0)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS.0)
        .open(path)
        .map_err(|e| {
            WardenError::sandbox_setup(
                SandboxStage::Apply,
                format!("open for ACL grant '{}': {e}", path.display()),
            )
        })
}

/// Write `new_dacl` onto the object `handle` pins without touching
/// descendants. `SetSecurityInfo` walks the whole subtree re-applying
/// every inheritable ACE in the written DACL — the right behavior when
/// an inheritable grant or revoke must reach children, but pure waste
/// (and a failure surface on huge or restricted trees) when the ACE
/// being written is not inherited by anything. Non-inherited ACEs
/// therefore go through `SetKernelObjectSecurity`, which mutates only
/// the object the handle pins.
///
/// `dacl_protected` re-applies the object's `SE_DACL_PROTECTED` state:
/// the descriptor built here is fresh, so the flag travels on the
/// `SecurityInformation` parameter instead.
fn write_object_dacl(
    handle: HANDLE,
    new_dacl: *mut ACL,
    dacl_protected: bool,
) -> Result<(), String> {
    // A NULL DACL means unrestricted access — never write one; an
    // empty-but-present ACL is the fail-closed spelling.
    if new_dacl.is_null() {
        return Err("merged DACL is null".to_string());
    }
    use windows::Win32::Security::{
        InitializeSecurityDescriptor, MakeSelfRelativeSD, SECURITY_DESCRIPTOR,
        SetKernelObjectSecurity, SetSecurityDescriptorDacl,
    };
    const SECURITY_DESCRIPTOR_REVISION: u32 = 1;

    // Safety: `abs` is initialized before use; `new_dacl` is a live
    // ACL built by SetEntriesInAclW; `buf` outlives the kernel call.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    unsafe {
        let mut abs = SECURITY_DESCRIPTOR::default();
        let abs_ptr = PSECURITY_DESCRIPTOR(&mut abs as *mut _ as _);
        InitializeSecurityDescriptor(abs_ptr, SECURITY_DESCRIPTOR_REVISION)
            .map_err(|e| format!("InitializeSecurityDescriptor: {e}"))?;
        SetSecurityDescriptorDacl(abs_ptr, true, Some(new_dacl), false)
            .map_err(|e| format!("SetSecurityDescriptorDacl: {e}"))?;
        let mut size = 0u32;
        let _ = MakeSelfRelativeSD(abs_ptr, None, &mut size);
        let mut buf = vec![0u8; size as usize];
        MakeSelfRelativeSD(
            abs_ptr,
            Some(PSECURITY_DESCRIPTOR(buf.as_mut_ptr() as _)),
            &mut size,
        )
        .map_err(|e| format!("MakeSelfRelativeSD: {e}"))?;
        let mut info = DACL_SECURITY_INFORMATION;
        info |= if dacl_protected {
            PROTECTED_DACL_SECURITY_INFORMATION
        } else {
            UNPROTECTED_DACL_SECURITY_INFORMATION
        };
        SetKernelObjectSecurity(handle, info, PSECURITY_DESCRIPTOR(buf.as_ptr() as _))
            .map_err(|e| format!("SetKernelObjectSecurity: {e}"))
    }
}

/// `(volume serial, file index)` of an open handle — the stable object
/// identity that survives path renames.
fn acl_object_identity(file: &std::fs::File) -> Option<(u64, u64)> {
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    // Safety: `info` is a live, correctly-sized out-buffer.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    unsafe { GetFileInformationByHandle(HANDLE(file.as_raw_handle() as _), &mut info) }.ok()?;
    let index = ((info.nFileIndexHigh as u64) << 32) | info.nFileIndexLow as u64;
    Some((info.dwVolumeSerialNumber as u64, index))
}

/// Remove every ACE naming `sid` from `grant`'s *current* DACL —
/// trustee-scoped REVOKE via `SetEntriesInAclW` applied to the object
/// the retained handle pins. Unlike whole-snapshot DACL restore, a
/// concurrent launch's grant and unrelated ACL edits survive teardown.
/// The object's identity is re-verified first: a handle whose identity
/// changed is left untouched (and reported) rather than mutated.
fn revoke_granted_aces(grant: &GrantedObject, sid: PSID) -> Result<(), String> {
    use std::ffi::c_void;
    use windows::Win32::Foundation::{HLOCAL, LocalFree};
    use windows::core::PWSTR;

    let now = acl_object_identity(&grant.file)
        .ok_or_else(|| "GetFileInformationByHandle failed".to_string())?;
    if now != grant.identity {
        return Err(format!(
            "identity changed {:?} -> {:?}",
            grant.identity, now
        ));
    }
    let handle = HANDLE(grant.file.as_raw_handle() as _);

    let mut dacl: *mut ACL = std::ptr::null_mut();
    let mut sd = PSECURITY_DESCRIPTOR(std::ptr::null_mut());
    // Safety: `dacl`/`sd` are live out-parameters; `sd` is LocalFree'd below.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    unsafe {
        GetSecurityInfo(
            handle,
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            None,
            None,
            Some(&mut dacl),
            None,
            Some(&mut sd),
        )
        .ok()
        .map_err(|e| format!("GetSecurityInfo: {e}"))?;
    }
    if sd.0.is_null() || dacl.is_null() {
        // A present-but-null DACL grants everyone — nothing of ours to
        // revoke; an absent descriptor means nothing was readable.
        if !sd.0.is_null() {
            // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
            unsafe { LocalFree(Some(HLOCAL(sd.0))) };
        }
        return Ok(());
    }
    // Preserve the DACL's protection bit across the rewrite.
    let mut control = 0u16;
    let mut revision = 0u32;
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    unsafe {
        let _ = GetSecurityDescriptorControl(sd, &mut control, &mut revision);
    }
    let trustee = TRUSTEE_W {
        TrusteeForm: TRUSTEE_IS_SID,
        TrusteeType: TRUSTEE_IS_WELL_KNOWN_GROUP,
        ptstrName: PWSTR(sid.0 as *mut u16),
        ..Default::default()
    };
    let ea = EXPLICIT_ACCESS_W {
        grfAccessPermissions: 0,
        grfAccessMode: REVOKE_ACCESS,
        grfInheritance: ACE_FLAGS(0),
        Trustee: trustee,
    };
    let mut new_dacl: *mut ACL = std::ptr::null_mut();
    let result = (|| -> Result<(), String> {
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe {
            SetEntriesInAclW(Some(&[ea]), Some(dacl), &mut new_dacl)
                .ok()
                .map_err(|e| format!("SetEntriesInAclW: {e}"))?;
            // A NULL DACL means unrestricted access — never write one;
            // an empty-but-present ACL is the fail-closed spelling.
            if new_dacl.is_null() {
                return Err("merged DACL is null".to_string());
            }
            if grant.propagates {
                let mut info = DACL_SECURITY_INFORMATION;
                if control & SE_DACL_PROTECTED.0 != 0 {
                    info |= PROTECTED_DACL_SECURITY_INFORMATION;
                } else {
                    info |= UNPROTECTED_DACL_SECURITY_INFORMATION;
                }
                // Inheritable ACEs left propagated copies on
                // descendants — the rewrite must walk them back out.
                SetSecurityInfo(
                    handle,
                    SE_FILE_OBJECT,
                    info,
                    None,
                    None,
                    Some(new_dacl),
                    None,
                )
                .ok()
                .map_err(|e| format!("SetSecurityInfo: {e}"))?;
            } else {
                write_object_dacl(handle, new_dacl, control & SE_DACL_PROTECTED.0 != 0)?;
            }
        }
        Ok(())
    })();
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    unsafe {
        LocalFree(Some(HLOCAL(sd.0)));
        if !new_dacl.is_null() {
            LocalFree(Some(HLOCAL(new_dacl as *mut c_void)));
        }
    }
    result
}

/// Windows AppContainer sandbox (regular AppContainer by default; LPAC when
/// `MCP_WRIT_WINDOWS_LPAC=1` — see `windows_sandbox.rs`).
///
/// Manages the lifecycle of an AppContainer profile:
/// - Creation via `CreateAppContainerProfile`
/// - Capability assignment via well-known SIDs
/// - Filesystem ACL grants
/// - Loopback exemption for HTTP transport
/// - Process spawning with SECURITY_CAPABILITIES
/// - Cleanup via `DeleteAppContainerProfile` + `FreeSid` on Drop
pub struct AppContainerSandbox {
    /// Unique profile name (used for identification and cleanup).
    profile_name: String,
    /// Container SID allocated by Windows. Must be freed with `FreeSid`.
    container_sid: PSID,
    /// Capability SIDs (owned memory, freed on drop).
    capability_sids: Vec<OwnedSid>,
    /// Whether LPAC is enabled (opt out of ALL_APPLICATION_PACKAGES;
    /// `MCP_WRIT_WINDOWS_LPAC=1`).
    pub(super) is_lpac: bool,
    /// Granted objects pinned by handle — teardown revokes this
    /// profile's ACEs from each object's current DACL, never restores a
    /// whole-DACL snapshot that could erase a concurrent session's
    /// grant or an unrelated ACL edit.
    granted_objects: Vec<GrantedObject>,
}

impl AppContainerSandbox {
    /// Create a new AppContainer sandbox profile.
    ///
    /// The profile name is unique per launch — a per-call UUIDv7 random
    /// suffix — so two launches of the same command can never collide on
    /// a shared profile name (previously a second launch could delete a
    /// still-in-use profile out from under the first). Profile names
    /// are bounded to 50 characters, so the caller's `name` component
    /// is truncated before the suffix is appended.
    ///
    /// A name collision is possible only through a stale leftover —
    /// the existing profile may still belong to another live launch, so
    /// it is never deleted here; a fresh unique name is tried instead.
    /// Only profiles this call actually creates are ever cleaned up
    /// (on Drop).
    pub fn new(name: &str) -> Result<Self, WardenError> {
        // `mcp-writ-` + name + `-` + 12 hex chars must stay under the
        // documented 50-char AppContainer name bound. The suffix takes
        // the UUIDv7's final hex chars — its random bits, not the
        // timestamp prefix — so launches inside the same millisecond
        // cannot derive the same name.
        const MAX_CREATE_ATTEMPTS: usize = 4;
        let description = "Sandboxed MCP server process";
        let mut attempts = 0;
        let (profile_name, container_sid) = loop {
            let unique = &uuid::Uuid::now_v7().simple().to_string()[20..];
            let name_budget = 50 - "mcp-writ--".len() - unique.len();
            let truncated: String = name.chars().take(name_budget).collect();
            let profile_name = format!("mcp-writ-{truncated}-{unique}");
            let display = format!("MCP Writ: {truncated}");

            let h_name = HSTRING::from(&profile_name);
            let h_display = HSTRING::from(&display);
            let h_desc = HSTRING::from(description);

            // Safety: CreateAppContainerProfile allocates the SID; we
            // free it in Drop.
            // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
            match unsafe { CreateAppContainerProfile(&h_name, &h_display, &h_desc, None) } {
                Ok(sid) => break (profile_name, sid),
                Err(e) => {
                    attempts += 1;
                    // HRESULT 0x800700B7 = ERROR_ALREADY_EXISTS — a
                    // collision with a profile this attempt did not
                    // create. It is never deleted; a fresh name is tried.
                    let collision = e.code()
                        == windows::core::HRESULT::from_win32(
                            windows::Win32::Foundation::ERROR_ALREADY_EXISTS.0,
                        );
                    if !collision || attempts >= MAX_CREATE_ATTEMPTS {
                        return Err(WardenError::sandbox_setup(
                            SandboxStage::Prepare,
                            format!("CreateAppContainerProfile failed: {e}"),
                        ));
                    }
                }
            }
        };

        Ok(AppContainerSandbox {
            profile_name,
            container_sid,
            capability_sids: Vec::new(),
            // Regular AppContainer by default. LPAC (opting out of
            // ALL_APPLICATION_PACKAGES) is stronger but unusable for real
            // interpreters: the Winsock catalog and other system resources
            // rely on ALL_APPLICATION_PACKAGES ACEs, so Node dies at
            // WSAStartup and Python's network calls fail — and a
            // non-elevated user cannot ACL-grant registry keys. Isolation
            // still holds: user-private files lack package ACEs and stay
            // denied unless granted. `MCP_WRIT_WINDOWS_LPAC=1` opts back in
            // for experimentation with LPAC-only workloads.
            is_lpac: lpac_enabled(),
            granted_objects: Vec::new(),
        })
    }

    /// Add a well-known network capability to the sandbox.
    ///
    /// Valid names: `"internetClient"`, `"internetClientServer"`,
    /// `"privateNetworkClientServer"`.
    pub fn add_capability(&mut self, cap_name: &str) -> Result<(), WardenError> {
        let sid_type = lookup_capability(cap_name).ok_or_else(|| {
            WardenError::sandbox_setup(
                SandboxStage::Policy,
                format!("Unknown capability: {cap_name}"),
            )
        })?;

        let owned_sid = OwnedSid::from_well_known(sid_type)?;
        self.capability_sids.push(owned_sid);
        Ok(())
    }

    /// Grant the sandboxed process access to a filesystem path.
    ///
    /// Modifies the path's DACL to include the AppContainer SID with
    /// appropriate access rights (read-only or read-write). The ACE is
    /// inherited by children created after the grant.
    pub fn grant_path(&mut self, path: &Path, read_only: bool) -> Result<(), WardenError> {
        let access_mask = if read_only {
            GENERIC_READ | GENERIC_EXECUTE
        } else {
            FILE_DATA_WRITE
        };
        self.grant_access(path, access_mask, true)
    }

    /// Grant traverse-only access on a directory: the AppContainer can
    /// pass through to named children and stat the directory itself, but
    /// cannot list the contents or read file data.
    ///
    /// `FILE_READ_ATTRIBUTES` rides along so `lstat`-style path
    /// resolution (git's realpath, `os.path.realpath`, …) succeeds on
    /// the ancestor — that bit exposes metadata only. Used for ancestors
    /// of the launch image and of granted fs paths so reaching a grant
    /// does not depend on bypass-traverse-checking. The ACE applies to
    /// the directory itself and is not inherited by children.
    pub(super) fn grant_traverse(&mut self, path: &Path) -> Result<(), WardenError> {
        self.grant_access(path, FILE_TRAVERSE | FILE_READ_ATTRIBUTES, false)
    }

    fn grant_access(
        &mut self,
        path: &Path,
        access_mask: u32,
        inherit_children: bool,
    ) -> Result<(), WardenError> {
        let raw_str = path.to_str().ok_or_else(|| {
            WardenError::sandbox_setup(SandboxStage::Policy, "Invalid path encoding")
        })?;
        let path_str = strip_verbatim_prefix(raw_str);

        // Pin the object by handle — pathname-based security calls
        // re-resolve the name on each use, so an actor replacing the
        // target (or a writable ancestor) between grant and teardown
        // could redirect the ACE or the restore onto another object.
        // The handle pins the file object itself; `identity` lets the
        // teardown re-verify it before every mutation.
        let file = open_acl_object(Path::new(&path_str))?;
        let identity = acl_object_identity(&file).ok_or_else(|| {
            WardenError::sandbox_setup(
                SandboxStage::Apply,
                format!("GetFileInformationByHandle for '{path_str}' failed"),
            )
        })?;
        let handle = HANDLE(file.as_raw_handle() as _);

        let inheritance = if inherit_children {
            (OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE).0
        } else {
            0
        };

        // Build EXPLICIT_ACCESS entry for the AppContainer SID
        let trustee = TRUSTEE_W {
            TrusteeForm: TRUSTEE_IS_SID,
            TrusteeType: TRUSTEE_IS_WELL_KNOWN_GROUP,
            ptstrName: windows::core::PWSTR(self.container_sid.0 as *mut u16),
            ..Default::default()
        };

        let ea = EXPLICIT_ACCESS_W {
            grfAccessPermissions: access_mask,
            grfAccessMode: GRANT_ACCESS,
            grfInheritance: ACE_FLAGS(inheritance),
            Trustee: trustee,
        };

        // Read the current DACL on the pinned handle.
        let mut existing_dacl: *mut ACL = std::ptr::null_mut();
        let mut sd: PSECURITY_DESCRIPTOR = PSECURITY_DESCRIPTOR(std::ptr::null_mut());
        // Safety: `existing_dacl`/`sd` are live out-parameters; `sd` is
        // LocalFree'd on every path below.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe {
            if let Err(e) = GetSecurityInfo(
                handle,
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                None,
                None,
                Some(&mut existing_dacl),
                None,
                Some(&mut sd),
            )
            .ok()
            {
                return Err(WardenError::sandbox_setup(
                    SandboxStage::Apply,
                    format!("GetSecurityInfo for '{path_str}': {e}"),
                ));
            }
        }

        // Merge our entry with the existing DACL
        let mut new_dacl: *mut ACL = std::ptr::null_mut();
        // Safety: SetEntriesInAclW creates a new ACL combining our entry
        // with the existing one; `sd` is freed whether or not it errs.
        let merged =
            // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
            unsafe { SetEntriesInAclW(Some(&[ea]), Some(existing_dacl), &mut new_dacl) }
                .ok()
                .map_err(|e| e.to_string());

        // `sd`'s protection bit is preserved on the write — the
        // kernel-object path rebuilds it explicitly; SetSecurityInfo
        // keeps the current state on its own.
        let mut control = 0u16;
        let mut revision = 0u32;
        // Safety: `sd` is the object's live descriptor until the free
        // below; `control`/`revision` are live out-params.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        let dacl_protected = unsafe {
            GetSecurityDescriptorControl(sd, &mut control, &mut revision)
                .map(|()| control & SE_DACL_PROTECTED.0 != 0)
                .unwrap_or(false)
        };

        // Write the merged DACL back to the pinned object. Inheritable
        // ACEs must reach children created earlier too, so they go
        // through SetSecurityInfo's descendant propagation; a
        // non-inherited ACE applies to this object alone, so the write
        // skips the descendant walk entirely. A NULL merged DACL means
        // unrestricted access and is never written.
        // Safety: `new_dacl` is valid only when the merge succeeded.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        let applied = merged.and_then(|()| unsafe {
            if new_dacl.is_null() {
                return Err("merged DACL is null".to_string());
            }
            if inherit_children {
                SetSecurityInfo(
                    handle,
                    SE_FILE_OBJECT,
                    DACL_SECURITY_INFORMATION,
                    None,
                    None,
                    Some(new_dacl),
                    None,
                )
                .ok()
                .map_err(|e| e.to_string())
            } else {
                write_object_dacl(handle, new_dacl, dacl_protected)
            }
        });

        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe {
            if !sd.0.is_null() {
                windows::Win32::Foundation::LocalFree(Some(windows::Win32::Foundation::HLOCAL(
                    sd.0,
                )));
            }
            if !new_dacl.is_null() {
                windows::Win32::Foundation::LocalFree(Some(windows::Win32::Foundation::HLOCAL(
                    new_dacl as *mut c_void,
                )));
            }
        }
        applied.map_err(|e| {
            WardenError::sandbox_setup(
                SandboxStage::Apply,
                format!("ACL grant for '{path_str}': {e}"),
            )
        })?;

        // Track by stable identity — differently-spelled grants of one
        // object collapse to a single teardown entry; the revoke is
        // trustee-scoped so repeat entries would be redundant anyway.
        // `propagates` is OR'd across grants of the same object: one
        // inheritable ACE among them means the revoke has copies to
        // walk back off descendants.
        match self
            .granted_objects
            .iter_mut()
            .find(|g| g.identity == identity)
        {
            Some(existing) => existing.propagates |= inherit_children,
            None => self.granted_objects.push(GrantedObject {
                file,
                identity,
                path: PathBuf::from(path_str),
                propagates: inherit_children,
            }),
        }

        Ok(())
    }

    /// Enable loopback network access for the AppContainer.
    ///
    /// By default, AppContainers cannot connect to localhost. MCP servers
    /// using HTTP transport need loopback enabled.
    ///
    /// Uses `CheckNetIsolation.exe` CLI as the API
    /// `NetworkIsolationSetAppContainerConfig` requires additional
    /// feature flags not present in our Cargo.toml.
    ///
    /// `Ok(true)` = the exemption was confirmed applied; `Ok(false)` =
    /// the tool ran but exited nonzero — nonfatal (stdio transport needs
    /// no loopback) but unconfirmed; `Err` only when the tool itself
    /// could not be launched. The tool is resolved by its System32
    /// spelling — the loopback exemption modifies the AppContainer's
    /// network boundary, so a PATH shadow must never answer for it.
    pub fn enable_loopback(&self) -> Result<bool, WardenError> {
        let tool = crate::trusted_path::system32_exe("CheckNetIsolation.exe").ok_or_else(|| {
            WardenError::sandbox_setup(
                SandboxStage::Apply,
                "CheckNetIsolation.exe not found in System32".to_string(),
            )
        })?;
        let output = tool
            .std_command()
            .map_err(|e| {
                WardenError::sandbox_setup(
                    SandboxStage::Apply,
                    format!("CheckNetIsolation.exe re-verification failed: {e}"),
                )
            })?
            .args(["LoopbackExempt", "-a", &format!("-n={}", self.profile_name)])
            .output()
            .map_err(|e| {
                WardenError::sandbox_setup(
                    SandboxStage::Apply,
                    format!("CheckNetIsolation.exe failed to launch: {e}"),
                )
            })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            tracing::warn!(
                "CheckNetIsolation loopback exemption failed for '{}': {}",
                self.profile_name,
                stderr.trim()
            );
            return Ok(false);
        }

        Ok(true)
    }

    /// Build the SECURITY_CAPABILITIES struct for process creation.
    ///
    /// The returned struct borrows from `self` — the caller must ensure
    /// `self` outlives the struct and the `SID_AND_ATTRIBUTES` Vec.
    pub(super) fn build_security_capabilities<'a>(
        &'a self,
        cap_attrs: &'a mut Vec<SID_AND_ATTRIBUTES>,
    ) -> SECURITY_CAPABILITIES {
        cap_attrs.clear();
        for owned_sid in &self.capability_sids {
            cap_attrs.push(SID_AND_ATTRIBUTES {
                Sid: owned_sid.as_psid(),
                Attributes: SE_GROUP_ENABLED,
            });
        }

        SECURITY_CAPABILITIES {
            AppContainerSid: self.container_sid,
            Capabilities: if cap_attrs.is_empty() {
                std::ptr::null_mut()
            } else {
                cap_attrs.as_mut_ptr()
            },
            CapabilityCount: cap_attrs.len() as u32,
            Reserved: 0,
        }
    }
}

impl Drop for AppContainerSandbox {
    fn drop(&mut self) {
        // Teardown removes only this profile's ACEs from each object's
        // current DACL — a whole-snapshot restore would rewind a
        // concurrent launch's grant or an unrelated ACL edit. Every
        // mutation runs on the retained handle (no path re-resolution)
        // after re-verifying the object's identity.
        while let Some(grant) = self.granted_objects.pop() {
            if let Err(e) = revoke_granted_aces(&grant, self.container_sid) {
                // Drop cannot propagate — surface the failure instead of
                // silently leaving a stale grant in place.
                tracing::warn!(
                    "AppContainer ACL revoke for '{}' failed: {e} — \
                     this profile's ACE may be left behind",
                    grant.path.display()
                );
            }
        }

        let h_name = HSTRING::from(&self.profile_name);

        // Safety: DeleteAppContainerProfile removes the container profile.
        // FreeSid releases the SID allocated by CreateAppContainerProfile.
        // A failed delete leaves a stale profile behind — `Drop` cannot
        // propagate, so the failure is recorded, not silently ignored.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe {
            if let Err(e) = DeleteAppContainerProfile(&h_name) {
                tracing::warn!(
                    "DeleteAppContainerProfile('{}') failed: {e} — \
                     sandbox profile may be left behind",
                    self.profile_name
                );
            }
            if !self.container_sid.0.is_null() {
                let _ = FreeSid(self.container_sid);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::default_policy;

    /// A unique directory under TEMP for DACL-grant tests. Tests run in
    /// parallel, and granting TEMP itself would let one test's Drop
    /// restore wipe a sibling's ACE mid-assertion — each test owns a
    /// private child directory for the backup/grant/restore cycle.
    fn unique_grant_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("mcp_writ_acl_{tag}_{}", std::process::id())); // nosemgrep: rust.lang.security.temp-dir.temp-dir
        std::fs::create_dir_all(&dir).expect("create unique grant dir");
        dir
    }

    #[test]
    fn test_strip_verbatim_prefix() {
        assert_eq!(
            strip_verbatim_prefix(r"\\?\C:\dir\file.exe"),
            r"C:\dir\file.exe"
        );
        assert_eq!(
            strip_verbatim_prefix(r"\\?\d:\lowercase.exe"),
            r"d:\lowercase.exe"
        );
        assert_eq!(
            strip_verbatim_prefix(r"\\?\UNC\server\share\f"),
            r"\\server\share\f"
        );
        assert_eq!(strip_verbatim_prefix(r"C:\plain\path"), r"C:\plain\path");
        assert_eq!(strip_verbatim_prefix(r"\\server\share"), r"\\server\share");
        // Non-drive/UNC verbatim namespaces have no regular spelling —
        // stripping would corrupt the object they name.
        for path in [
            r"\\?\Volume{26a21bda-a627-11d7-9931-806e6f6e6963}\dir\f",
            r"\\?\GLOBALROOT\Device\HarddiskVolume3\dir\f",
            r"\\?\C:",    // drive without a rooted path
            r"\\?\C:rel", // drive-relative spelling
        ] {
            assert_eq!(strip_verbatim_prefix(path), path, "{path} unchanged");
        }
    }

    #[test]
    fn test_grant_path_verbatim_spelling() {
        let dir = unique_grant_dir("verbatim");
        let mut sandbox = AppContainerSandbox::new("test-verbatim").expect("create");
        // canonicalize emits the \\?\ verbatim spelling on Windows; the
        // grant must succeed on it just as on the plain path.
        let verbatim = std::fs::canonicalize(&dir).expect("canonicalize");
        let result = sandbox.grant_path(&verbatim, true);
        // Restore the DACL (Drop) before removing the directory.
        drop(sandbox);
        let _ = std::fs::remove_dir(&dir);
        assert!(
            result.is_ok(),
            "verbatim-spelled grant must succeed: {result:?}"
        );
    }

    #[test]
    fn test_grant_dedupes_verbatim_and_plain_spelling() {
        let dir = unique_grant_dir("dedupe");
        let mut sandbox = AppContainerSandbox::new("test-dedupe").expect("create");
        let verbatim = std::fs::canonicalize(&dir).expect("canonicalize");
        let stripped = PathBuf::from(strip_verbatim_prefix(&verbatim.to_string_lossy()));
        sandbox.grant_path(&verbatim, true).expect("verbatim grant");
        sandbox.grant_path(&stripped, true).expect("stripped grant");
        assert_eq!(
            sandbox.granted_objects.len(),
            1,
            "verbatim and plain spellings of one object share one teardown \
             entry — dedupe is by (volume, file index), not spelling"
        );
        // An alias spelling the string compare cannot recognize (8.3 name,
        // case variant) still collapses to one entry: the identity key is
        // the object, not the path text.
        drop(sandbox);
        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn test_lookup_known_capabilities() {
        assert!(lookup_capability("internetClient").is_some());
        assert!(lookup_capability("internetClientServer").is_some());
        assert!(lookup_capability("privateNetworkClientServer").is_some());
    }

    #[test]
    fn test_lookup_unknown_capability() {
        assert!(lookup_capability("unknownCap").is_none());
        assert!(lookup_capability("").is_none());
    }

    #[test]
    fn test_create_and_drop_sandbox() {
        let sandbox = AppContainerSandbox::new("test-create-drop");
        assert!(sandbox.is_ok(), "should create sandbox profile");
        // Drop cleans up automatically
    }

    #[test]
    fn test_create_duplicate_name_recovers() {
        let _s1 = AppContainerSandbox::new("test-dup").expect("first create");
        let s2 = AppContainerSandbox::new("test-dup");
        assert!(
            s2.is_ok(),
            "second create should succeed after deleting stale profile"
        );
    }

    #[test]
    fn test_add_well_known_capabilities() {
        let mut sandbox = AppContainerSandbox::new("test-caps").expect("create");
        assert!(sandbox.add_capability("internetClient").is_ok());
        assert!(sandbox.add_capability("internetClientServer").is_ok());
        assert_eq!(sandbox.capability_sids.len(), 2);
    }

    #[test]
    fn test_add_unknown_capability_fails() {
        let mut sandbox = AppContainerSandbox::new("test-badcap").expect("create");
        assert!(sandbox.add_capability("nonExistent").is_err());
    }

    #[test]
    fn test_grant_path_nonexistent_fails() {
        let mut sandbox = AppContainerSandbox::new("test-badpath").expect("create");
        let result = sandbox.grant_path(Path::new("C:\\__nonexistent_path_42__"), false);
        assert!(result.is_err());
    }

    #[test]
    fn test_grant_path_temp_dir() {
        let dir = unique_grant_dir("tmpgrant");
        let mut sandbox = AppContainerSandbox::new("test-tmpgrant").expect("create");
        let result = sandbox.grant_path(&dir, true);
        drop(sandbox);
        let _ = std::fs::remove_dir(&dir);
        assert!(result.is_ok(), "should grant read access to temp dir");
    }

    #[test]
    fn test_enable_loopback() {
        let sandbox = AppContainerSandbox::new("test-loopback").expect("create");
        // enable_loopback uses CheckNetIsolation.exe — may warn but shouldn't error
        let result = sandbox.enable_loopback();
        assert!(result.is_ok());
    }

    #[test]
    fn test_capabilities_for_policy_deny_all_empty() {
        let policy = default_policy();
        // deny_all_others = true, allowed = [] → no capabilities
        let caps = capabilities_for_policy(&policy);
        assert!(caps.is_empty(), "fully isolated policy should have no caps");
    }

    #[test]
    fn test_capabilities_for_policy_deny_all_with_allowed() {
        let mut policy = default_policy();
        policy.network.outbound.deny_all_others = true;
        policy.network.outbound.allowed = vec!["*:443".to_string()];
        let caps = capabilities_for_policy(&policy);
        assert!(
            caps.is_empty(),
            "fine-grained allowlists must not grant internetClient"
        );
    }

    #[test]
    fn test_capabilities_for_policy_open_network() {
        let mut policy = default_policy();
        policy.network.outbound.deny_all_others = false;
        let caps = capabilities_for_policy(&policy);
        assert_eq!(caps.len(), 2);
        assert!(caps.contains(&"internetClient"));
        assert!(!caps.contains(&"internetClientServer"));
        assert!(caps.contains(&"privateNetworkClientServer"));
    }

    #[test]
    fn test_capabilities_for_policy_open_network_with_inbound() {
        let mut policy = default_policy();
        policy.network.outbound.deny_all_others = false;
        policy.network.inbound.allow_listen = true;
        let caps = capabilities_for_policy(&policy);
        assert_eq!(caps.len(), 3);
        assert!(caps.contains(&"internetClient"));
        assert!(caps.contains(&"internetClientServer"));
        assert!(caps.contains(&"privateNetworkClientServer"));
    }
}
