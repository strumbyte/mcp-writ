//! Process Security Environment (PSEC) launch path — the PR-31
//! conditional integration of the Windows-native mechanism selected by
//! `--windows-mechanism psec`.
//!
//! A PSEC child is created by building a FlatBuffers spec (see
//! [`super::psec_spec`]), compiling it into an environment handle with
//! `CreateProcessSecurityEnvironment` (`processmodel.dll`, resolved
//! under `LOAD_LIBRARY_SEARCH_SYSTEM32`), and spawning with
//! `PROC_THREAD_ATTRIBUTE_SECURITY_ENVIRONMENT`. The child runs with an
//! AppContainer-derived identity; filesystem deny/read-only/read-write
//! lists and the egress deny-all posture come from the spec, descendant
//! cleanup from the same kill-on-close Job the AppContainer path uses.
//!
//! Conditional status — what this module may never claim: there is no
//! published stability commitment for the schema beyond the measured
//! v1.0 wire layout, and the host contract is narrow (see
//! `docs/validation/windows-isolation.md`). Every absent or
//! unverifiable prerequisite refuses the launch; the path never falls
//! back to AppContainer or an unsandboxed spawn.

use std::ffi::c_void;
use std::path::Path;

use windows::Win32::Foundation::{FreeLibrary, HANDLE, HMODULE};
use windows::Win32::System::LibraryLoader::{
    GetProcAddress, LOAD_LIBRARY_SEARCH_SYSTEM32, LoadLibraryExW,
};
use windows::core::{PCSTR, PCWSTR};

use crate::enforcement::ProcessGrant;
use crate::error::{SandboxStage, WardenError};
use crate::policy::Policy;

use super::SpawnOptions;
use super::psec_spec::{self, PsecBuild, PsecRefusal};
use super::windows_proc::WindowsChild;
use super::windows_sandbox::{WinSpawnError, WinStage};

/// `processmodel.dll` — the PSEC contract host. Resolved under
/// `System32` only: a caller-planted `processmodel.dll` beside the
/// workload must never become the capability decision.
const PSEC_MODULE: &str = "processmodel.dll";

/// The exports a launch needs; anything beyond this set (learning-mode,
/// experimental sandbox) is deliberately unused.
const REQUIRED_EXPORTS: &[&str] = &[
    "CreateProcessSecurityEnvironment",
    "QueryProcessSecurityEnvironmentSupport",
    "IsProcessSecurityEnvironmentVersionSupported",
    "CloseProcessSecurityEnvironment",
];

type CreateEnvFn = unsafe extern "system" fn(*const c_void, u32, u32, *mut HANDLE) -> i32;
type CloseEnvFn = unsafe extern "system" fn(HANDLE);
type QuerySupportFn = unsafe extern "system" fn(*mut u64) -> i32;
type VersionSupportedFn = unsafe extern "system" fn(u32, *mut u8, *mut u32) -> i32;

/// Capability facts the probe recorded — carried into the plan check
/// and the launch-report reason strings; never a "supported" claim
/// beyond what was answered.
pub(super) struct PsecProbe {
    module: HMODULE,
    create_env: CreateEnvFn,
    close_env: CloseEnvFn,
    /// Raw `QueryProcessSecurityEnvironmentSupport` flags — recorded,
    /// never interpreted (no documented bit contract on the measured
    /// build).
    pub(super) support_flags: u64,
    /// Highest supported minor for major version 1 the version query
    /// reported.
    pub(super) version_minor: u32,
}

/// `HRESULT_FROM_WIN32(ERROR_PATH_NOT_FOUND)` — one spelling of the
/// measured cold-name-resolution transient.
const HRESULT_PATH_NOT_FOUND: i32 = 0x8007_0003_u32 as i32;
/// `STATUS_OBJECT_PATH_NOT_FOUND` delivered in the same return slot —
/// the other spelling the measured host produces for the transient.
const STATUS_OBJECT_PATH_NOT_FOUND: i32 = 0xC000_003A_u32 as i32;

/// Whether a `CreateProcessSecurityEnvironment` return code is the
/// measured cold-name-resolution transient worth one warm-and-retry.
fn is_env_create_path_not_found(hr: i32) -> bool {
    hr == HRESULT_PATH_NOT_FOUND || hr == STATUS_OBJECT_PATH_NOT_FOUND
}

/// A failed `CreateProcessSecurityEnvironment` — the stage-tagged spawn
/// error plus the raw-code classification the retry decision needs
/// (the error message text is for reporting, not control flow).
struct CreateEnvFailure {
    err: WinSpawnError,
    /// The measured transient `PATH_NOT_FOUND` answer — either spelling.
    path_not_found: bool,
}

impl PsecProbe {
    /// `CreateProcessSecurityEnvironment` for an already-encoded spec.
    /// On success the module's ownership moves into the returned
    /// environment so the create/close vtable stays loaded exactly as
    /// long as the handle it produced (a failed create keeps the module
    /// here and the drop frees it).
    fn create_environment(mut self, spec: &[u8]) -> Result<PsecEnvironment, CreateEnvFailure> {
        let mut env = HANDLE::default();
        let hr = unsafe {
            (self.create_env)(
                spec.as_ptr() as *const c_void,
                spec.len() as u32,
                0,
                &mut env,
            )
        };
        if hr != 0 || env.is_invalid() {
            return Err(CreateEnvFailure {
                err: WinSpawnError {
                    stage: WinStage::EnvironmentCreate,
                    source: WardenError::sandbox_setup(
                        SandboxStage::Prepare,
                        format!(
                            "CreateProcessSecurityEnvironment rejected the spec (HRESULT 0x{hr:08x})"
                        ),
                    ),
                },
                path_not_found: is_env_create_path_not_found(hr),
            });
        }
        let env = PsecEnvironment {
            env,
            close_env: self.close_env,
            module: self.module,
        };
        // Ownership moved into the environment — the probe's drop must
        // not free a module the env still closes handles through.
        self.module = HMODULE::default();
        Ok(env)
    }
}

impl Drop for PsecProbe {
    fn drop(&mut self) {
        // A probe that never produced an environment still releases the
        // module — the exports were borrowed, not owned.
        if !self.module.is_invalid() {
            unsafe {
                let _ = FreeLibrary(self.module);
            }
        }
    }
}

/// An environment handle owned for the child's lifetime; `Drop` closes
/// it, then releases the module — the handle stays valid through every
/// CreateProcessW the child setup performs, and the library stays loaded
/// until the handle is closed.
pub(super) struct PsecEnvironment {
    env: HANDLE,
    close_env: CloseEnvFn,
    module: HMODULE,
}

// HANDLE/HMODULE are process-global values; the environment is handed
// to WindowsChild which is Send+Sync — the close path is a plain
// function call with no thread affinity.
unsafe impl Send for PsecEnvironment {}
unsafe impl Sync for PsecEnvironment {}

impl PsecEnvironment {
    /// The handle placed in `PROC_THREAD_ATTRIBUTE_SECURITY_ENVIRONMENT`.
    pub(super) fn handle(&self) -> HANDLE {
        self.env
    }
}

impl Drop for PsecEnvironment {
    fn drop(&mut self) {
        unsafe {
            (self.close_env)(self.env);
            if !self.module.is_invalid() {
                let _ = FreeLibrary(self.module);
            }
        }
    }
}

fn probe_err(detail: impl Into<String>) -> WardenError {
    WardenError::sandbox_setup(SandboxStage::Prepare, detail.into())
}

fn cstr(name: &str) -> std::ffi::CString {
    // Export/module names are static ASCII — NUL-free by construction.
    std::ffi::CString::new(name).expect("static export name")
}

/// Bounded capability probe — the gate every PSEC launch runs first and
/// the evidence `plan` reports. Answers, never inference:
///
/// 1. `processmodel.dll` loads from `System32` (presence);
/// 2. the four contract exports resolve (contract surface);
/// 3. `IsProcessSecurityEnvironmentVersionSupported` reports a
///    supported 1.x (schema this binary emits);
/// 4. `QueryProcessSecurityEnvironmentSupport` returns success
///    (support answer — flags recorded, not interpreted).
///
/// Creating an environment is deliberately *not* probed here: the spec
/// itself is the create-time evidence and a failed create is the
/// `environment-create` stage of the launch pipeline.
pub(super) fn capability_probe() -> Result<PsecProbe, WardenError> {
    let wide_name: Vec<u16> =
        std::os::windows::ffi::OsStrExt::encode_wide(std::ffi::OsStr::new(PSEC_MODULE))
            .chain(std::iter::once(0))
            .collect();
    let module = unsafe {
        LoadLibraryExW(
            PCWSTR(wide_name.as_ptr()),
            None,
            LOAD_LIBRARY_SEARCH_SYSTEM32,
        )
    }
    .map_err(|e| probe_err(format!("{PSEC_MODULE} could not be loaded: {e}")))?;

    struct LibraryGuard(HMODULE);
    impl Drop for LibraryGuard {
        fn drop(&mut self) {
            if !self.0.is_invalid() {
                unsafe {
                    let _ = FreeLibrary(self.0);
                }
            }
        }
    }
    let guard = LibraryGuard(module);

    let mut addrs: [Option<*mut c_void>; REQUIRED_EXPORTS.len()] = [None; REQUIRED_EXPORTS.len()];
    for (i, name) in REQUIRED_EXPORTS.iter().enumerate() {
        let p = unsafe { GetProcAddress(guard.0, PCSTR(cstr(name).as_ptr() as _)) };
        match p {
            // GetProcAddress returns FARPROC (Option<fn>) in windows-rs
            // 0.62 — `None` means unresolved.
            Some(f) => addrs[i] = Some(f as *mut c_void),
            None => {
                return Err(probe_err(format!(
                    "{PSEC_MODULE} does not export {name} — the PSEC contract \
                     surface is incomplete on this host"
                )));
            }
        }
    }

    // Transmute between raw function addresses and typed externs —
    // signatures match the measured contract (see the probe fixture).
    let create_env: CreateEnvFn = unsafe { std::mem::transmute(addrs[0].unwrap()) };
    let query_support: QuerySupportFn = unsafe { std::mem::transmute(addrs[1].unwrap()) };
    let version_supported: VersionSupportedFn = unsafe { std::mem::transmute(addrs[2].unwrap()) };
    let close_env: CloseEnvFn = unsafe { std::mem::transmute(addrs[3].unwrap()) };

    // Version gate — the v1.0 spec shape is the only one this binary
    // emits; a host that cannot answer "1.x supported" is refused, as
    // is a failed query.
    let mut available: u8 = 0;
    let mut minor: u32 = 0;
    let hr = unsafe { version_supported(1, &mut available, &mut minor) };
    if hr != 0 {
        return Err(probe_err(format!(
            "IsProcessSecurityEnvironmentVersionSupported(1,…) failed (HRESULT \
             0x{hr:08x}) — support cannot be established"
        )));
    }
    if available == 0 {
        return Err(probe_err(
            "the host reports no supported PSEC schema version 1.x — only the \
             v1.0 wire layout is implemented",
        ));
    }

    // Support query — a real API answer, not presence inference.
    let mut flags: u64 = 0;
    let hr = unsafe { query_support(&mut flags) };
    if hr != 0 {
        return Err(probe_err(format!(
            "QueryProcessSecurityEnvironmentSupport failed (HRESULT 0x{hr:08x})"
        )));
    }

    let module = guard.0;
    std::mem::forget(guard);
    Ok(PsecProbe {
        module,
        create_env,
        close_env,
        support_flags: flags,
        version_minor: minor,
    })
}

/// One-line probe summary for checks and report reasons.
pub(super) fn probe_detail(probe: &PsecProbe) -> String {
    format!(
        "processmodel.dll exports resolved; schema 1.x supported (minor {minor}); \
         support flags 0x{flags:016x}",
        minor = probe.version_minor,
        flags = probe.support_flags
    )
}

/// The refusal message for an inexpressible policy — names every problem.
fn refusal_error(problems: &[String]) -> WardenError {
    WardenError::sandbox_setup(
        SandboxStage::Policy,
        format!(
            "policy is not expressible as a PSEC security environment: {}",
            problems.join("; ")
        ),
    )
}

/// Warm a filesystem path for the name cache — the measured host
/// intermittently answers `PATH_NOT_FOUND` at env creation for a path
/// the server has never resolved in this process's namespace. A
/// `metadata` call resolves the same path server-side; the result is
/// intentionally ignored (missing paths were already excluded from the
/// spec — this only warms the ones it carries).
fn warm_path(path: &str) {
    let _ = std::fs::metadata(path);
}

/// Mark every still-planned spec grant Skipped — the environment was
/// never created, so nothing it would have carried was applied.
fn skip_unapplied_grants(grants: &mut [ProcessGrant]) {
    for grant in grants {
        if grant.state == crate::enforcement::ControlState::Planned {
            grant.state = crate::enforcement::ControlState::Skipped;
            grant.reason =
                Some("not applied — the security environment was not created".to_string());
        }
    }
}

/// Spawn a child inside a PSEC security environment — the parallel of
/// `windows_sandbox::spawn_sandboxed` for `--windows-mechanism psec`.
///
/// Pipeline (every stage fail-closed, none falls back):
/// 1. `capability-probe` — module, exports, schema version, support
///    answer; refusal otherwise.
/// 2. `policy-check` — policy→spec translation; every inexpressible
///    requirement is collected and refused together.
/// 3. `environment-create` — `CreateProcessSecurityEnvironment` on the
///    encoded spec; a measured transient `PATH_NOT_FOUND` is retried
///    once after warming the referenced path names.
/// 4. `process-setup` → `create-process` → `job-setup` →
///    `job-assignment` → `execution-start` — the shared
///    `windows_proc::spawn_inner` pipeline with
///    `PROC_THREAD_ATTRIBUTE_SECURITY_ENVIRONMENT` and a `NULL`
///    environment block (the measured contract: a custom
///    `lpEnvironment` is rejected, the child receives a
///    mechanism-managed environment).
///
/// `grants_out` receives the spec's grant entries — `Verified` once the
/// environment exists (the server accepted the ruleset), `Skipped`
/// when an abort left them unapplied.
pub(super) fn spawn_sandboxed(
    policy: &Policy,
    program: Option<&Path>,
    command: &str,
    args: &[String],
    opts: &SpawnOptions,
    grants_out: &mut Vec<ProcessGrant>,
) -> Result<WindowsChild, WinSpawnError> {
    let at = |stage: WinStage| move |source: WardenError| WinSpawnError { stage, source };

    let probe = capability_probe()
        .map_err(at(WinStage::Probe))
        .inspect_err(|e| {
            tracing::warn!(
                "Warden: PSEC pipeline aborted at the {} stage: {}",
                e.stage.label(),
                e.source
            );
        })?;
    tracing::debug!("Warden: PSEC capability probe — {}", probe_detail(&probe));

    let build: PsecBuild = match psec_spec::build_launch_spec(policy, program, command, opts) {
        Ok(b) => b,
        Err(PsecRefusal { problems, grants }) => {
            grants_out.extend(grants);
            let err = WinSpawnError {
                stage: WinStage::PolicyCheck,
                source: refusal_error(&problems),
            };
            tracing::warn!(
                "Warden: PSEC pipeline aborted at the {} stage: {}",
                err.stage.label(),
                err.source
            );
            return Err(err);
        }
    };
    let mut grants = build.grants;

    for path in &build.fs_paths {
        warm_path(path);
    }
    let env = match probe.create_environment(&build.spec) {
        Ok(env) => env,
        Err(first) => {
            // The measured transient: a cold name resolution can answer
            // PATH_NOT_FOUND (as an HRESULT or the NTSTATUS spelling)
            // even for existing paths. Warm again, retry once —
            // anything else, and a second failure, refuses.
            if !first.path_not_found {
                skip_unapplied_grants(&mut grants);
                grants_out.extend(grants);
                return Err(first.err);
            }
            for path in &build.fs_paths {
                warm_path(path);
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
            let probe = match capability_probe().map_err(at(WinStage::Probe)) {
                Ok(probe) => probe,
                Err(err) => {
                    skip_unapplied_grants(&mut grants);
                    grants_out.extend(grants);
                    tracing::warn!(
                        "Warden: PSEC pipeline aborted at the {} stage: {}",
                        err.stage.label(),
                        err.source
                    );
                    return Err(err);
                }
            };
            match probe.create_environment(&build.spec) {
                Ok(env) => env,
                Err(second) => {
                    skip_unapplied_grants(&mut grants);
                    grants_out.extend(grants);
                    tracing::warn!(
                        "Warden: PSEC pipeline aborted at the {} stage: {}",
                        second.err.stage.label(),
                        second.err.source
                    );
                    return Err(second.err);
                }
            }
        }
    };

    // The environment exists — the spec it encodes is what the child
    // runs under; grants are applied by construction.
    for grant in &mut grants {
        if grant.state == crate::enforcement::ControlState::Planned {
            grant.state = crate::enforcement::ControlState::Verified;
            if grant.reason.is_none() {
                grant.reason = Some(
                    "encoded in the spec CreateProcessSecurityEnvironment accepted".to_string(),
                );
            }
        }
    }
    grants_out.extend(grants);

    let mut child =
        match super::windows_proc::spawn_inner_psec(env.handle(), program, command, args) {
            Ok(child) => child,
            Err(e) => {
                tracing::warn!(
                    "Warden: PSEC pipeline aborted at the {} stage: {}",
                    e.stage.label(),
                    e.source
                );
                return Err(e);
            }
        };
    // The env handle must outlive process creation; hand ownership to
    // the child so it closes after the process handle — never while a
    // suspended (or running) PSEC child exists.
    child._psec_env = Some(env);
    Ok(child)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn env_create_path_not_found_recognizes_both_spellings() {
        // HRESULT_FROM_WIN32(ERROR_PATH_NOT_FOUND) and the NTSTATUS
        // STATUS_OBJECT_PATH_NOT_FOUND in the same slot are the one
        // measured transient; any other failure must not retry.
        assert!(is_env_create_path_not_found(HRESULT_PATH_NOT_FOUND));
        assert!(is_env_create_path_not_found(STATUS_OBJECT_PATH_NOT_FOUND));
        assert!(!is_env_create_path_not_found(0x8007_0005_u32 as i32));
        assert!(!is_env_create_path_not_found(0));
    }
}
