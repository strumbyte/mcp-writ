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
// Public integration function
// ─────────────────────────────────────────────────────────────────────────────

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
/// attempted. Entries are appended even when the pipeline aborts.
pub fn spawn_sandboxed(
    policy: &Policy,
    program: Option<&Path>,
    command: &str,
    args: &[String],
    opts: &SpawnOptions,
    grants_out: &mut Vec<ProcessGrant>,
) -> Result<WindowsChild, WardenError> {
    // Generate a unique sandbox name from the command
    let sanitized_cmd = command
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(command)
        .replace('.', "_");
    let sandbox_name = format!("{sanitized_cmd}-{}", std::process::id());

    let mut sandbox = AppContainerSandbox::new(&sandbox_name)?;

    let intents = grant_intents(policy, program, command, opts.tmpdir.as_deref());
    let mut pending: Vec<ProcessGrant> = Vec::with_capacity(intents.len());
    for (mut grant, apply) in intents {
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
                    // (unchanged behavior — they are fail-closed).
                    WinApply::Capability(_) | WinApply::Loopback => {
                        grants_out.extend(pending);
                        return Err(e);
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

    // Spawn the sandboxed process
    let mut child = sandbox.spawn(program, command, args, opts)?;

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
        // Policy has no read_write paths → all writes should be blocked
        let test_file = std::env::temp_dir().join("mcp_writ_sandbox_deny_test.txt");
        let _ = std::fs::remove_file(&test_file);

        let mut grants = Vec::new();
        if let Ok(child) = spawn_sandboxed(
            &policy,
            None,
            "cmd.exe",
            &[
                "/c".to_string(),
                format!("echo denied > \"{}\"", test_file.display()),
            ],
            &SpawnOptions::default(),
            &mut grants,
        ) {
            let _ = child.wait();
            let blocked = !test_file.exists();
            let _ = std::fs::remove_file(&test_file);
            assert!(blocked, "sandbox should block writes outside allowed paths");
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
}
