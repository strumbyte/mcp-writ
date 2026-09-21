//! AppContainer profile lifecycle.
//!
//! Owns the sandbox profile: creation via `CreateAppContainerProfile`,
//! capability SIDs, filesystem ACL grants, loopback exemption, and cleanup.
//! Process creation inside the profile lives in `windows_proc` (which
//! implements [`AppContainerSandbox::spawn`]); UTF-16 environment blocks live
//! in `windows_env`.

use std::ffi::c_void;
use std::path::{Path, PathBuf};

use windows::Win32::Security::Authorization::{
    EXPLICIT_ACCESS_W, GRANT_ACCESS, SE_FILE_OBJECT, SetEntriesInAclW, SetNamedSecurityInfoW,
    TRUSTEE_IS_SID, TRUSTEE_IS_WELL_KNOWN_GROUP, TRUSTEE_W,
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
use windows::core::{BOOL, HSTRING};

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
    /// Original DACLs to restore when the sandbox is dropped.
    granted_acls: Vec<(PathBuf, Vec<u8>)>,
}

impl AppContainerSandbox {
    /// Create a new AppContainer sandbox profile.
    ///
    /// If a profile with the same name already exists, it is deleted first.
    pub fn new(name: &str) -> Result<Self, WardenError> {
        let profile_name = format!("mcp-writ-{name}");
        let display = format!("MCP Writ: {name}");
        let description = "Sandboxed MCP server process";

        let h_name = HSTRING::from(&profile_name);
        let h_display = HSTRING::from(&display);
        let h_desc = HSTRING::from(description);

        // Try to create the profile. If it already exists, delete and retry.
        // Safety: CreateAppContainerProfile allocates the SID; we free it in Drop.
        let create_result =
            unsafe { CreateAppContainerProfile(&h_name, &h_display, &h_desc, None) };

        let container_sid = match create_result {
            Ok(sid) => sid,
            Err(e) => {
                // HRESULT 0x800700B7 = ERROR_ALREADY_EXISTS
                // Delete the stale profile and retry.
                let _ = unsafe { DeleteAppContainerProfile(&h_name) };

                unsafe {
                    CreateAppContainerProfile(&h_name, &h_display, &h_desc, None).map_err(|e2| {
                        WardenError::sandbox_setup(
                            SandboxStage::Prepare,
                            format!("CreateAppContainerProfile retry failed: {e2} (original: {e})"),
                        )
                    })?
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
            is_lpac: std::env::var("MCP_WRIT_WINDOWS_LPAC").as_deref() == Ok("1"),
            granted_acls: Vec::new(),
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
    /// pass through to named children but cannot list the contents.
    ///
    /// Used for ancestors of the launch image so reaching a granted file
    /// does not depend on bypass-traverse-checking. The ACE applies to the
    /// directory itself and is not inherited by children.
    pub(super) fn grant_traverse(&mut self, path: &Path) -> Result<(), WardenError> {
        self.grant_access(path, FILE_TRAVERSE, false)
    }

    fn grant_access(
        &mut self,
        path: &Path,
        access_mask: u32,
        inherit_children: bool,
    ) -> Result<(), WardenError> {
        let path_str = path.to_str().ok_or_else(|| {
            WardenError::sandbox_setup(SandboxStage::Policy, "Invalid path encoding")
        })?;
        let h_path = HSTRING::from(path_str);

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

        // Get the current DACL
        let mut existing_dacl: *mut ACL = std::ptr::null_mut();
        let mut sd: PSECURITY_DESCRIPTOR = PSECURITY_DESCRIPTOR(std::ptr::null_mut());

        // Safety: GetNamedSecurityInfoW reads the existing DACL.
        // The returned sd must be freed with LocalFree.
        unsafe {
            let result = windows::Win32::Security::Authorization::GetNamedSecurityInfoW(
                &h_path,
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                None,
                None,
                Some(&mut existing_dacl),
                None,
                &mut sd,
            );
            if result.is_err() {
                return Err(WardenError::sandbox_setup(
                    SandboxStage::Apply,
                    format!("GetNamedSecurityInfoW for '{}': {:?}", path_str, result),
                ));
            }
        }

        let sd_len = unsafe { windows::Win32::Security::GetSecurityDescriptorLength(sd) };
        if sd_len > 0 && !sd.0.is_null() {
            let mut backup = vec![0u8; sd_len as usize];
            unsafe {
                std::ptr::copy_nonoverlapping(
                    sd.0 as *const u8,
                    backup.as_mut_ptr(),
                    sd_len as usize,
                );
            }
            if !self
                .granted_acls
                .iter()
                .any(|(existing, _)| existing == path)
            {
                self.granted_acls.push((path.to_path_buf(), backup));
            }
        }

        // Merge our entry with the existing DACL
        let mut new_dacl: *mut ACL = std::ptr::null_mut();

        // Safety: SetEntriesInAclW creates a new ACL combining our entry with the existing one.
        if let Err(e) =
            unsafe { SetEntriesInAclW(Some(&[ea]), Some(existing_dacl), &mut new_dacl) }.ok()
        {
            // Free the security descriptor from GetNamedSecurityInfoW.
            if !sd.0.is_null() {
                unsafe {
                    windows::Win32::Foundation::LocalFree(Some(
                        windows::Win32::Foundation::HLOCAL(sd.0),
                    ));
                }
            }
            return Err(WardenError::sandbox_setup(
                SandboxStage::Apply,
                format!("SetEntriesInAclW: {e}"),
            ));
        }

        // Apply the new DACL
        // Safety: SetNamedSecurityInfoW writes the new DACL to the path's security descriptor.
        unsafe {
            let result = SetNamedSecurityInfoW(
                &h_path,
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                None,
                None,
                Some(new_dacl),
                None,
            );
            // Free the security descriptor from GetNamedSecurityInfoW
            if !sd.0.is_null() {
                windows::Win32::Foundation::LocalFree(Some(windows::Win32::Foundation::HLOCAL(
                    sd.0,
                )));
            }
            // Free the new DACL from SetEntriesInAclW
            if !new_dacl.is_null() {
                windows::Win32::Foundation::LocalFree(Some(windows::Win32::Foundation::HLOCAL(
                    new_dacl as *mut c_void,
                )));
            }
            if result.is_err() {
                return Err(WardenError::sandbox_setup(
                    SandboxStage::Apply,
                    format!("SetNamedSecurityInfoW for '{}': {:?}", path_str, result),
                ));
            }
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
    pub fn enable_loopback(&self) -> Result<(), WardenError> {
        let output = std::process::Command::new("CheckNetIsolation.exe")
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
            // Non-fatal: stdio transport doesn't need loopback
        }

        Ok(())
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
        for (path, mut sd_bytes) in self.granted_acls.drain(..) {
            if sd_bytes.is_empty() {
                continue;
            }
            let h_path = HSTRING::from(path.to_string_lossy().as_ref());
            let psd = PSECURITY_DESCRIPTOR(sd_bytes.as_mut_ptr() as *mut c_void);
            let mut present = BOOL::default();
            let mut defaulted = BOOL::default();
            let mut dacl: *mut ACL = std::ptr::null_mut();
            let mut control: u16 = 0;
            let mut revision = 0u32;
            unsafe {
                if windows::Win32::Security::GetSecurityDescriptorDacl(
                    psd,
                    &mut present,
                    &mut dacl,
                    &mut defaulted,
                )
                .is_ok()
                    && present.as_bool()
                    && !dacl.is_null()
                {
                    let _ = GetSecurityDescriptorControl(psd, &mut control, &mut revision);
                    let mut info = DACL_SECURITY_INFORMATION;
                    if control & SE_DACL_PROTECTED.0 != 0 {
                        info |= PROTECTED_DACL_SECURITY_INFORMATION;
                    } else {
                        info |= UNPROTECTED_DACL_SECURITY_INFORMATION;
                    }
                    let _ = SetNamedSecurityInfoW(
                        &h_path,
                        SE_FILE_OBJECT,
                        info,
                        None,
                        None,
                        Some(dacl),
                        None,
                    );
                }
            }
        }

        let h_name = HSTRING::from(&self.profile_name);

        // Safety: DeleteAppContainerProfile removes the container profile.
        // FreeSid releases the SID allocated by CreateAppContainerProfile.
        unsafe {
            let _ = DeleteAppContainerProfile(&h_name);
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
        let mut sandbox = AppContainerSandbox::new("test-tmpgrant").expect("create");
        let tmp = std::env::temp_dir();
        let result = sandbox.grant_path(&tmp, true);
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
