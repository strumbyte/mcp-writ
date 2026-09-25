//! Windows AppContainer sandbox implementation.
//!
//! Creates an AppContainer sandbox for MCP server processes.
//! This module is only compiled on Windows via `#[cfg(target_os = "windows")]`.
//!
//! # Architecture
//!
//! The default is a regular AppContainer token:
//! - Default-deny filesystem access: per-directory explicit ACL grants
//! - Network uses coarse capability SIDs (internetClient, etc.)
//! - Loopback (localhost) is blocked by default — important for MCP servers
//!
//! `MCP_WRIT_WINDOWS_LPAC=1` switches to LPAC (Less Privileged AppContainer),
//! which additionally opts out of `ALL_APPLICATION_PACKAGES`. That is more
//! restrictive but breaks real interpreters: the Winsock catalog and other
//! system resources rely on `ALL_APPLICATION_PACKAGES` ACEs, so Node dies at
//! `WSAStartup` — and a non-elevated user cannot ACL-grant registry keys.
//! Isolation is unchanged for user-private files, which lack package ACEs
//! and stay denied unless granted.
//!
//! # Module layout
//!
//! - `windows_profile`: profile lifecycle — `AppContainerSandbox`, capability
//!   SIDs, path ACL grants, loopback exemption
//! - `windows_proc`: process creation — pipes, handle inheritance,
//!   `CreateProcessW`, kill-on-close Job, `WindowsChild`
//! - `windows_env`: UTF-16 environment block encoding
//!
//! # Safety
//!
//! This module contains `unsafe` blocks for Win32 FFI calls (~15-25 blocks).
//! All unsafe code is confined to the `windows_*` modules with safe public
//! wrappers.

use std::path::{Path, PathBuf};

use crate::enforcement::{ControlState, FsAccess, GrantOrigin, GrantSubject, ProcessGrant};
use crate::error::WardenError;
use crate::policy::{Policy, TransportType};

use super::SpawnOptions;
use super::windows_profile::capabilities_for_policy;

pub use super::windows_proc::WindowsChild;
pub use super::windows_profile::AppContainerSandbox;

// ─────────────────────────────────────────────────────────────────────────────
// Pipeline stages and abort error
// ─────────────────────────────────────────────────────────────────────────────

/// The stage of the Windows sandboxed-spawn pipeline a [`WinSpawnError`]
/// occurred at. The pipeline aborts on the first failed *mandatory*
/// stage, so a failure at stage N proves the stages before it ran and
/// the stages after it never did — the per-stage outcomes never collapse
/// into one ambiguous "sandbox failed".
///
/// Best-effort grant intents (per-path DACL writes) cannot fail the
/// pipeline: they mark only their own grant entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum WinStage {
    /// `CreateAppContainerProfile` produced the container profile/SID.
    Profile,
    /// The mandatory grant intents ran: capability SID creation and
    /// (for HTTP transport) the loopback exemption launch. Per-path
    /// DACL writes are best-effort inside this stage.
    Grants,
    /// Stdio pipes, handle inheritance, and the proc-thread attribute
    /// list (security capabilities, LPAC opt-out, handle list).
    ProcessSetup,
    /// `CreateProcessW` created the suspended process inside the
    /// container. Failure here is `WardenError::ProcessSpawn`: which
    /// input of the fused call (attributes, image, environment) was
    /// rejected is undetermined.
    CreateProcess,
    /// The kill-on-close Job object was created and its limit flags set
    /// (`CreateJobObjectW` + `SetInformationJobObject`) — preparation of
    /// the teardown mechanism, before any process is assigned.
    JobSetup,
    /// The suspended process was assigned to the Job
    /// (`AssignProcessToJobObject`).
    Job,
    /// `ResumeThread` started execution — the launch went live.
    Resume,
}

impl WinStage {
    /// Stable label used in report reasons and log records.
    pub(super) fn label(self) -> &'static str {
        match self {
            Self::Profile => "profile-creation",
            Self::Grants => "grant-application",
            Self::ProcessSetup => "process-setup",
            Self::CreateProcess => "create-process",
            Self::JobSetup => "job-setup",
            Self::Job => "job-assignment",
            Self::Resume => "execution-start",
        }
    }
}

/// A sandbox-pipeline abort: the stage it failed at plus the original
/// error. `stage` is always identified; `source` keeps the original
/// [`WardenError`] (a `SandboxSetup` with its own coarse stage, or
/// `ProcessSpawn` for `CreateProcessW` where the failing input is
/// undetermined).
pub(super) struct WinSpawnError {
    pub stage: WinStage,
    pub source: WardenError,
}

impl std::fmt::Display for WinSpawnError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} ({} stage)", self.source, self.stage.label())
    }
}

impl WinSpawnError {
    /// Collapse into the [`WardenError`] a spawn caller receives. The
    /// pipeline stage label is folded into the error text so the
    /// propagated error alone still names where the launch died — the
    /// coarse [`SandboxStage`](crate::error::SandboxStage) inside
    /// `source` reports only `policy`/`prepare`/`apply`.
    pub(super) fn into_warden_error(self) -> WardenError {
        match self.source {
            WardenError::SandboxSetup { stage, detail } => WardenError::SandboxSetup {
                stage,
                detail: format!("{}: {detail}", self.stage.label()),
            },
            // `ProcessSpawn` carries a bare io::Error: wrap it so the
            // message keeps the `create-process` label and the original
            // os-error text; `kind()` is preserved, the raw code stays
            // in the message.
            WardenError::ProcessSpawn(e) => WardenError::ProcessSpawn(std::io::Error::new(
                e.kind(),
                format!("{e} ({} stage)", self.stage.label()),
            )),
        }
    }
}

/// One grant's apply step inside the sandbox pipeline. `None` marks a
/// record-only entry (skipped at intent time — nothing to apply).
pub(super) enum WinApply {
    Capability(&'static str),
    GrantPath { path: PathBuf, read_only: bool },
    Traverse(PathBuf),
    Loopback,
}

/// The grant intents the spawn pipeline applies, in application order —
/// capabilities → policy fs paths → tmpdir → executable image + parent
/// traversal → loopback. Both the spawn path and the plan-only report
/// enumerate the same intents; the spawn path additionally applies each
/// and records the outcome on the grant entry.
pub(super) fn grant_intents(
    policy: &Policy,
    program: Option<&Path>,
    command: &str,
    tmpdir: Option<&Path>,
) -> Vec<(ProcessGrant, Option<WinApply>)> {
    let mut out: Vec<(ProcessGrant, Option<WinApply>)> = Vec::new();
    let mut push = |subject: GrantSubject,
                    origin: GrantOrigin,
                    state: ControlState,
                    reason: Option<String>,
                    apply: Option<WinApply>| {
        out.push((
            ProcessGrant {
                subject,
                origin,
                state,
                reason,
            },
            apply,
        ));
    };

    // Network capabilities based on policy (all-or-none; the AppContainer
    // model cannot express per-destination rules — those stay RPC-layer).
    for cap in capabilities_for_policy(policy) {
        push(
            GrantSubject::Capability {
                name: cap.to_string(),
            },
            GrantOrigin::Policy,
            ControlState::Planned,
            None,
            Some(WinApply::Capability(cap)),
        );
    }

    // Per-destination outbound entries are kept visible: AppContainer
    // capabilities are all-or-none and cannot pin a destination, so the
    // entry is applied nowhere — it is enforced at the RPC layer only.
    // (A `deny_all_others` + nonempty `allowed` policy is rejected at
    // load for a Windows target; surviving entries here come from an
    // unrestricted-outbound policy.)
    for dest in &policy.network.outbound.allowed {
        push(
            GrantSubject::Rule {
                kind: "net_destination",
                name: dest.clone(),
            },
            GrantOrigin::Policy,
            ControlState::Skipped,
            Some(
                "AppContainer cannot express per-destination rules — this \
                 entry is enforced at the RPC layer only"
                    .to_string(),
            ),
            None,
        );
    }

    // Filesystem paths. Best-effort like the executable/traverse grants
    // below: a failed grant never widens access, but it does not guarantee
    // denial either — effective access still follows the object's existing
    // ACL — and system locations (`C:\Program Files`, `C:\Windows`)
    // are covered by ALL_APPLICATION_PACKAGES ACEs that a non-elevated
    // user cannot modify anyway (SetNamedSecurityInfoW returns
    // ERROR_ACCESS_DENIED). Access problems surface at the operation.
    for (list, access, read_only) in [
        (&policy.fs.read_only, FsAccess::Read, true),
        (&policy.fs.read_write, FsAccess::ReadWrite, false),
    ] {
        for path_str in list {
            let path = Path::new(path_str);
            let subject = GrantSubject::FsPath {
                path: path_str.clone(),
                access,
            };
            if path.exists() {
                push(
                    subject,
                    GrantOrigin::Policy,
                    ControlState::Planned,
                    None,
                    Some(WinApply::GrantPath {
                        path: path.to_path_buf(),
                        read_only,
                    }),
                );
            } else {
                push(
                    subject,
                    GrantOrigin::Policy,
                    ControlState::Skipped,
                    Some("path does not exist; no ACL grant is attempted".to_string()),
                    None,
                );
            }
        }
    }
    if let Some(tmp) = tmpdir {
        let subject = GrantSubject::FsPath {
            path: tmp.to_string_lossy().into_owned(),
            access: FsAccess::ReadWrite,
        };
        if tmp.exists() {
            push(
                subject,
                GrantOrigin::Runtime,
                ControlState::Planned,
                Some("private TMPDIR".to_string()),
                Some(WinApply::GrantPath {
                    path: tmp.to_path_buf(),
                    read_only: false,
                }),
            );
        } else {
            push(
                subject,
                GrantOrigin::Runtime,
                ControlState::Skipped,
                Some("tmpdir does not exist; no ACL grant is attempted".to_string()),
                None,
            );
        }
    }

    // The launch image must be readable/executable inside the container
    // and its parent directory traversable — the policy grant list names
    // data paths, not the image itself. Best-effort: a grant fails on
    // filesystems without DACLs or on objects whose security descriptor
    // the user cannot modify (e.g. System32), where the default
    // traverse-bypass still applies; CreateProcessW remains the
    // authoritative check.
    let exe = match program {
        Some(p) => Some(p.to_path_buf()),
        None => crate::workload::resolve_command_path(command).ok(),
    };
    if let Some(exe) = exe {
        let subject = GrantSubject::FsPath {
            path: exe.to_string_lossy().into_owned(),
            access: FsAccess::Read,
        };
        if exe.is_file() {
            push(
                subject,
                GrantOrigin::Runtime,
                ControlState::Planned,
                Some("executable image".to_string()),
                Some(WinApply::GrantPath {
                    path: exe.clone(),
                    read_only: true,
                }),
            );
            if let Some(parent) = exe.parent().filter(|p| p.is_dir()) {
                push(
                    GrantSubject::FsPath {
                        path: parent.to_string_lossy().into_owned(),
                        access: FsAccess::Traverse,
                    },
                    GrantOrigin::Runtime,
                    ControlState::Planned,
                    Some("ancestor of the executable image".to_string()),
                    Some(WinApply::Traverse(parent.to_path_buf())),
                );
            }
        } else {
            push(
                subject,
                GrantOrigin::Runtime,
                ControlState::Skipped,
                Some("resolved executable is not a file".to_string()),
                None,
            );
        }
    }

    // Loopback exemption for HTTP transport.
    if matches!(policy.transport.type_, TransportType::Http) {
        push(
            GrantSubject::Rule {
                kind: "loopback_exemption",
                name: "localhost".to_string(),
            },
            GrantOrigin::Runtime,
            ControlState::Planned,
            Some("HTTP transport requires loopback".to_string()),
            Some(WinApply::Loopback),
        );
    }

    out
}

/// Create and configure a sandboxed child process from a Policy.
///
/// This is the primary entry point called from `Warden::spawn_child()`.
///
/// The pipeline:
/// 1. Create an AppContainer sandbox profile
/// 2. Add network capabilities based on policy
/// 3. Grant filesystem paths (read-only and read-write) from policy
/// 4. Enable loopback if HTTP transport is configured
/// 5. Spawn the child process inside the sandbox
///
/// `program` selects the executable image independently of `command` (the
/// child's `argv[0]`) — used to exec a verified canonical path when
/// `argv[0]` is a symlink.
///
/// `grants_out` receives one [`ProcessGrant`] per applied intent — with
/// the entry's own outcome (`Verified`/`Failed`/`Skipped`) — so the
/// launch report describes exactly the DACL/capability writes this spawn
/// attempted. Entries are appended even when the pipeline aborts — the
/// intents a `Grants`-stage abort left unreached are recorded `Skipped`,
/// so 'planned but never applied' stays distinct from 'not an intent'.
///
/// An `Err` carries the [`WinStage`] the pipeline died at: every earlier
/// mandatory stage provably ran, every later stage provably did not, and
/// the partially constructed launch (suspended process, profile, handles)
/// was cleaned up under the existing ownership rules — `SpawnCleanup`,
/// `AppContainerSandbox::drop`, `WindowsChild::drop`.
pub fn spawn_sandboxed(
    policy: &Policy,
    program: Option<&Path>,
    command: &str,
    args: &[String],
    opts: &SpawnOptions,
    grants_out: &mut Vec<ProcessGrant>,
) -> Result<WindowsChild, WinSpawnError> {
    // Generate a unique sandbox name from the command
    let sanitized_cmd = command
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(command)
        .replace('.', "_");
    let sandbox_name = format!("{sanitized_cmd}-{}", std::process::id());

    let mut sandbox = AppContainerSandbox::new(&sandbox_name).map_err(|e| {
        let err = WinSpawnError {
            stage: WinStage::Profile,
            source: e,
        };
        tracing::warn!(
            "Warden: sandbox pipeline aborted at the {} stage: {}",
            err.stage.label(),
            err.source
        );
        err
    })?;

    let intents = grant_intents(policy, program, command, opts.tmpdir.as_deref());
    let mut pending: Vec<ProcessGrant> = Vec::with_capacity(intents.len());
    let mut intents = intents.into_iter();
    for (mut grant, apply) in intents.by_ref() {
        let Some(apply) = apply else {
            pending.push(grant);
            continue;
        };
        // `enable_loopback` reports whether the exemption was actually
        // applied: `Ok(false)` means CheckNetIsolation ran but exited
        // nonzero — the launch stays nonfatal but the grant is `Unknown`,
        // not `Verified`. Other intents report `Ok(true)` on success.
        let result = match &apply {
            WinApply::Capability(name) => sandbox.add_capability(name).map(|_| true),
            WinApply::GrantPath { path, read_only } => {
                sandbox.grant_path(path, *read_only).map(|_| true)
            }
            WinApply::Traverse(path) => sandbox.grant_traverse(path).map(|_| true),
            WinApply::Loopback => sandbox.enable_loopback(),
        };
        match result {
            Ok(applied) => {
                if applied {
                    grant.state = ControlState::Verified;
                } else {
                    grant.state = ControlState::Unknown;
                    grant.reason = Some("loopback exemption was not confirmed".to_string());
                }
                pending.push(grant);
            }
            Err(e) => {
                grant.state = ControlState::Failed;
                grant.reason = Some(e.to_string());
                pending.push(grant);
                match apply {
                    // Capability and loopback failures abort the spawn
                    // (unchanged behavior — they are fail-closed). The
                    // already-applied DACL writes are restored by
                    // `AppContainerSandbox::drop` on the way out.
                    WinApply::Capability(_) | WinApply::Loopback => {
                        // Record the intents the abort leaves unreached —
                        // they were planned but never applied, which the
                        // report must distinguish from intents that never
                        // existed. Record-only entries keep the state
                        // they were created with.
                        for (mut unreached, apply) in intents.by_ref() {
                            if apply.is_some() {
                                unreached.state = ControlState::Skipped;
                                unreached.reason = Some(format!(
                                    "not applied — the pipeline aborted at \
                                     the {} stage",
                                    WinStage::Grants.label()
                                ));
                            }
                            pending.push(unreached);
                        }
                        grants_out.extend(pending);
                        let err = WinSpawnError {
                            stage: WinStage::Grants,
                            source: e,
                        };
                        tracing::warn!(
                            "Warden: sandbox pipeline aborted at the {} stage: {}",
                            err.stage.label(),
                            err.source
                        );
                        return Err(err);
                    }
                    // ACL grant failures stay best-effort — the requested
                    // access is not guaranteed, but a pre-existing ACE may
                    // still allow it; the grant is recorded Failed.
                    WinApply::GrantPath { path, read_only } => {
                        tracing::warn!(
                            "{} ACL grant failed for '{}': {e}",
                            if read_only { "read" } else { "read-write" },
                            path.display()
                        );
                    }
                    WinApply::Traverse(path) => {
                        tracing::warn!("traverse ACL grant failed for '{}': {e}", path.display());
                    }
                }
            }
        }
    }
    grants_out.extend(pending);

    // Spawn the sandboxed process. A spawn error carries its pipeline
    // stage; `AppContainerSandbox::drop` still restores the granted DACLs
    // and deletes the profile on the way out.
    let mut child = match sandbox.spawn(program, command, args, opts) {
        Ok(child) => child,
        Err(e) => {
            tracing::warn!(
                "Warden: sandbox pipeline aborted at the {} stage: {}",
                e.stage.label(),
                e.source
            );
            return Err(e);
        }
    };

    // Transfer sandbox ownership to the child so the AppContainer profile
    // stays alive for the lifetime of the child process. The profile is
    // deleted when WindowsChild is dropped (after the process exits).
    child._sandbox = Some(sandbox);

    Ok(child)
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::default_policy;

    #[test]
    fn test_spawn_sandboxed_with_default_policy() {
        let policy = default_policy();
        let mut grants = Vec::new();
        let result = spawn_sandboxed(
            &policy,
            None,
            "cmd.exe",
            &["/c".to_string(), "echo hello".to_string()],
            &SpawnOptions::default(),
            &mut grants,
        );
        match result {
            Ok(child) => {
                let status = child.wait().expect("should wait");
                // Process ran successfully inside the sandbox
                assert!(status.success());
            }
            Err(e) => {
                // On some Windows versions, sandbox creation may require elevation
                eprintln!("Sandbox spawn failed (may need elevation): {e}");
            }
        }
    }

    #[test]
    fn test_sandbox_blocks_write_outside_allowed() {
        let policy = default_policy();
        // Policy has no read_write paths → all writes should be blocked.
        // The redirect target is unquoted — argv-escaped `\"` does not
        // survive `cmd /c` parsing — and a `>` filename ends at the
        // first whitespace, so the fixture path must be whitespace-free:
        // with a spaced TEMP the redirect would write to a truncated
        // path and the deny assertion would hold vacuously.
        let tmp = std::env::temp_dir().join(format!("mcp_writ_deny_{}", std::process::id()));
        if tmp.to_string_lossy().contains(char::is_whitespace) {
            eprintln!("fixture path contains whitespace; skipping");
            return;
        }
        std::fs::create_dir_all(&tmp).expect("fixture dir");
        let test_file = tmp.join("denied.txt");

        let mut grants = Vec::new();
        if let Ok(child) = spawn_sandboxed(
            &policy,
            None,
            "cmd.exe",
            &[
                "/c".to_string(),
                format!("echo denied > {}", test_file.display()),
            ],
            &SpawnOptions::default(),
            &mut grants,
        ) {
            let _ = child.wait();
            let blocked = !test_file.exists();
            let _ = std::fs::remove_dir_all(&tmp);
            assert!(blocked, "sandbox should block writes outside allowed paths");
        } else {
            let _ = std::fs::remove_dir_all(&tmp);
        }
    }

    #[test]
    fn restricted_env_does_not_inherit_sentinel_and_uses_private_tmp() {
        use std::io::Read;

        let _env = crate::warden::env::lock_process_env();
        let sentinel_key = "MCP_WRIT_R04_SENTINEL";
        // Safety: test-only process env; unique key unused by product code.
        unsafe {
            std::env::set_var(sentinel_key, "inherited");
        }
        let tmp = std::env::temp_dir().join(format!("mcp_writ_r04_tmp_{}", std::process::id()));
        let _ = std::fs::create_dir_all(&tmp);
        let opts = SpawnOptions {
            restrict_environment: true,
            allowed_names: Vec::new(),
            tmpdir: Some(tmp.clone()),
        };
        let policy = default_policy();
        let mut grants = Vec::new();
        let result = spawn_sandboxed(
            &policy,
            None,
            "cmd.exe",
            &[
                "/c".to_string(),
                format!("echo SENTINEL=%{sentinel_key}%& echo TEMP=%TEMP%"),
            ],
            &opts,
            &mut grants,
        );
        match result {
            Ok(mut child) => {
                drop(child.stdin.take());
                let mut stdout = child.stdout.take().expect("stdout");
                let _ = child.wait();
                let mut buf = String::new();
                let _ = stdout.read_to_string(&mut buf);
                let lower = buf.to_ascii_lowercase();
                assert!(
                    !lower.contains("inherited"),
                    "restricted env must not inherit sentinel, got {buf:?}"
                );
                // Two private-temp outcomes are both correct: our TMP/TEMP
                // override points at `tmp`, but once LOCALAPPDATA is in the
                // block (required for AppContainer spawn) CreateProcessW
                // remaps TMP/TEMP to the container-private `Packages\<name>\
                // AC\Temp` — a private temp directory managed by the OS.
                let tmp_s = tmp.to_string_lossy().to_ascii_lowercase();
                let container_tmp = buf
                    .to_ascii_lowercase()
                    .contains("\\appdata\\local\\packages\\mcp-writ-cmd_exe-");
                assert!(
                    lower.contains(&tmp_s)
                        || buf.contains(&*tmp.to_string_lossy())
                        || container_tmp,
                    "child TEMP must be a private tmpdir {tmp_s} or the AppContainer AC\\Temp, got {buf:?}"
                );
            }
            Err(e) => {
                eprintln!("Sandbox spawn failed (may need elevation): {e}");
            }
        }
        let _ = std::fs::remove_dir_all(&tmp);
    }

    /// A granted path is writable inside the container, and dropping the
    /// sandbox revokes the grant: a second container (same profile name,
    /// hence the same AppContainer SID) with no grant is denied again.
    /// Phase 1 is the positive control — without it a DACL write that
    /// never took effect would pass phase 2 vacuously.
    ///
    /// The redirect target is passed unquoted (a `>` filename ends at
    /// the first whitespace) — argv-escaped `\"` inside `/c` tails does
    /// not round-trip, so a quoted path would fail on a syntax error,
    /// not on the ACL. The fixture path must be whitespace-free; the
    /// test skips when TEMP is not.
    #[test]
    fn acl_grant_allows_write_and_drop_restores_denial() {
        let tmp = std::env::temp_dir().join(format!("mcp_writ_acl_{}", std::process::id()));
        if tmp.to_string_lossy().contains(char::is_whitespace) {
            eprintln!("fixture path contains whitespace; skipping");
            return;
        }
        std::fs::create_dir_all(&tmp).expect("fixture dir");
        let write = |file: &PathBuf| -> String { format!("echo ok > {}", file.display()) };

        // Phase 1 — the policy grant makes the fixture dir writable
        // inside the container (proves the ACE was actually written, not
        // merely that the API reported success).
        let probe_granted = tmp.join("granted.txt");
        {
            let mut policy = default_policy();
            policy
                .fs
                .read_write
                .push(tmp.to_string_lossy().into_owned());
            let mut grants = Vec::new();
            match spawn_sandboxed(
                &policy,
                None,
                "cmd.exe",
                &["/c".to_string(), write(&probe_granted)],
                &SpawnOptions::default(),
                &mut grants,
            ) {
                Ok(child) => {
                    let _ = child.wait();
                    // The grant must be visible as a verified per-path
                    // entry in the apply record.
                    assert!(grants.iter().any(|g| {
                        matches!(&g.subject, GrantSubject::FsPath { path, .. }
                            if path == &tmp.to_string_lossy())
                            && g.state == ControlState::Verified
                    }));
                }
                Err(e) => {
                    let _ = std::fs::remove_dir_all(&tmp);
                    eprintln!("Sandbox spawn failed (may need elevation): {e}");
                    return;
                }
            }
        }
        assert!(
            probe_granted.exists(),
            "write to a granted path must succeed inside the container"
        );

        // Phase 2 — same spawn without the grant must be denied again:
        // the restored DACL no longer carries the container ACE.
        let probe_restored = tmp.join("restored.txt");
        {
            let policy = default_policy();
            let mut grants = Vec::new();
            if let Ok(child) = spawn_sandboxed(
                &policy,
                None,
                "cmd.exe",
                &["/c".to_string(), write(&probe_restored)],
                &SpawnOptions::default(),
                &mut grants,
            ) {
                let _ = child.wait();
            }
        }
        let leaked = probe_restored.exists();
        let _ = std::fs::remove_dir_all(&tmp);
        assert!(
            !leaked,
            "DACL restore failed — a container without the grant could still write"
        );
    }

    /// Descendant creation is not blocked by policy: children of an
    /// AppContainer process normally inherit the container token, the
    /// spawn applies no `PROC_THREAD_ATTRIBUTE_CHILD_PROCESS_POLICY`,
    /// and `KILL_ON_JOB_CLOSE` only kills the job's members on close —
    /// it does not prevent creation. Empirically, though, a workload
    /// spawned under this launch configuration cannot create a child:
    /// it inherits a working directory outside the container's grants,
    /// has no console, and receives only the stdio pipe handles, so the
    /// inner `cmd` launch is denied. The test asserts the observed
    /// denial under these launch conditions — an inner `cmd` spawned by
    /// the workload must neither produce output nor exit successfully —
    /// not a child-process-restriction guarantee.
    #[test]
    fn sandboxed_workload_cannot_spawn_children() {
        use std::io::Read;

        let policy = default_policy();
        let mut grants = Vec::new();
        let Ok(mut child) = spawn_sandboxed(
            &policy,
            None,
            "cmd.exe",
            &["/c".to_string(), "cmd /c echo CHILD_OK".to_string()],
            &SpawnOptions::default(),
            &mut grants,
        ) else {
            eprintln!("Sandbox spawn failed (may need elevation); skipping spawn-denial check");
            return;
        };
        let mut out = String::new();
        let _ = child
            .stdout
            .take()
            .expect("stdout")
            .read_to_string(&mut out);
        let status = child.wait().expect("wait");
        assert!(
            !out.contains("CHILD_OK"),
            "a descendant ran inside the container — the observed launch \
             conditions must keep denying it: {out:?}"
        );
        assert!(
            !status.success(),
            "workload spawning a child must fail under these launch \
             conditions, got success exit: {status:?}"
        );
    }

    /// `try_wait` reports a natural exit (with its real exit code) and
    /// `None` while the process still runs — without forcing a kill.
    #[test]
    fn try_wait_reports_running_and_natural_exit() {
        let policy = default_policy();
        let mut grants = Vec::new();
        let Ok(child) = spawn_sandboxed(
            &policy,
            None,
            "cmd.exe",
            &["/c".to_string(), "exit /b 7".to_string()],
            &SpawnOptions::default(),
            &mut grants,
        ) else {
            eprintln!("Sandbox spawn failed (may need elevation); skipping try_wait check");
            return;
        };
        let mut status = None;
        for _ in 0..100 {
            match child.try_wait() {
                Ok(Some(s)) => {
                    status = Some(s);
                    break;
                }
                Ok(None) => std::thread::sleep(std::time::Duration::from_millis(50)),
                Err(e) => panic!("try_wait failed: {e}"),
            }
        }
        assert_eq!(status.and_then(|s| s.code()), Some(7));

        // A `cmd` blocked reading our stdin pipe reports None until it
        // is killed — deterministic, unlike timer-based sleepers that
        // die early inside a container without console input.
        let mut grants = Vec::new();
        if let Ok(running) = spawn_sandboxed(
            &policy,
            None,
            "cmd.exe",
            &["/q".to_string()],
            &SpawnOptions::default(),
            &mut grants,
        ) {
            assert!(running.try_wait().expect("try_wait").is_none());
            running.kill().expect("kill");
            let mut observed = false;
            for _ in 0..100 {
                if matches!(running.try_wait(), Ok(Some(_))) {
                    observed = true;
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            assert!(observed, "killed child never reported an exit status");
        }
    }

    /// The `WardenError` a caller receives keeps the fine-grained
    /// pipeline stage label in its text — the coarse `SandboxStage`
    /// alone would not name the abort site.
    #[test]
    fn into_warden_error_preserves_stage_label() {
        let err = WinSpawnError {
            stage: WinStage::Job,
            source: WardenError::sandbox_setup(
                crate::error::SandboxStage::Apply,
                "AssignProcessToJobObject".to_string(),
            ),
        };
        let WardenError::SandboxSetup { detail, .. } = err.into_warden_error() else {
            panic!("expected SandboxSetup");
        };
        assert!(detail.contains("job-assignment"), "{detail}");

        // `ProcessSpawn` has no detail field — the label is folded into
        // the wrapped io::Error message.
        let err = WinSpawnError {
            stage: WinStage::CreateProcess,
            source: WardenError::ProcessSpawn(std::io::Error::from_raw_os_error(2)),
        };
        let warden_err = err.into_warden_error();
        assert!(
            warden_err.to_string().contains("create-process"),
            "{warden_err}"
        );
    }
}
