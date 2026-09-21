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

use std::path::Path;

use crate::error::WardenError;
use crate::policy::{Policy, TransportType};

use super::SpawnOptions;
use super::windows_profile::capabilities_for_policy;

pub use super::windows_proc::WindowsChild;
pub use super::windows_profile::AppContainerSandbox;

// ─────────────────────────────────────────────────────────────────────────────
// Public integration function
// ─────────────────────────────────────────────────────────────────────────────

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
pub fn spawn_sandboxed(
    policy: &Policy,
    program: Option<&Path>,
    command: &str,
    args: &[String],
    opts: &SpawnOptions,
) -> Result<WindowsChild, WardenError> {
    // Generate a unique sandbox name from the command
    let sanitized_cmd = command
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(command)
        .replace('.', "_");
    let sandbox_name = format!("{sanitized_cmd}-{}", std::process::id());

    let mut sandbox = AppContainerSandbox::new(&sandbox_name)?;

    // Add network capabilities based on policy
    for cap_name in capabilities_for_policy(policy) {
        sandbox.add_capability(cap_name)?;
    }

    // Grant filesystem paths. Best-effort like the executable/traverse
    // grants below: a failed grant never widens access — the path simply
    // stays denied — and system locations (`C:\Program Files`, `C:\Windows`)
    // are covered by ALL_APPLICATION_PACKAGES ACEs that a non-elevated user
    // cannot modify anyway (SetNamedSecurityInfoW returns
    // ERROR_ACCESS_DENIED). Access problems surface at the operation.
    for path_str in &policy.fs.read_only {
        let path = Path::new(path_str);
        if path.exists()
            && let Err(e) = sandbox.grant_path(path, true)
        {
            tracing::warn!("read ACL grant failed for '{path_str}': {e}");
        }
    }
    for path_str in &policy.fs.read_write {
        let path = Path::new(path_str);
        if path.exists()
            && let Err(e) = sandbox.grant_path(path, false)
        {
            tracing::warn!("read-write ACL grant failed for '{path_str}': {e}");
        }
    }
    if let Some(tmp) = opts.tmpdir.as_deref()
        && tmp.exists()
        && let Err(e) = sandbox.grant_path(tmp, false)
    {
        tracing::warn!("tmpdir ACL grant failed for '{}': {e}", tmp.display());
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
        None => crate::verifier::hash::resolve_command_path(command).ok(),
    };
    if let Some(exe) = exe.filter(|e| e.is_file()) {
        if let Err(e) = sandbox.grant_path(&exe, true) {
            tracing::warn!("executable ACL grant failed for '{}': {e}", exe.display());
        }
        if let Some(parent) = exe.parent().filter(|p| p.is_dir())
            && let Err(e) = sandbox.grant_traverse(parent)
        {
            tracing::warn!("traverse ACL grant failed for '{}': {e}", parent.display());
        }
    }

    // Enable loopback for HTTP transport
    if matches!(policy.transport.type_, TransportType::Http) {
        sandbox.enable_loopback()?;
    }

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
        let result = spawn_sandboxed(
            &policy,
            None,
            "cmd.exe",
            &["/c".to_string(), "echo hello".to_string()],
            &SpawnOptions::default(),
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

        if let Ok(child) = spawn_sandboxed(
            &policy,
            None,
            "cmd.exe",
            &[
                "/c".to_string(),
                format!("echo denied > \"{}\"", test_file.display()),
            ],
            &SpawnOptions::default(),
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
            tmpdir: Some(tmp.clone()),
        };
        let policy = default_policy();
        let result = spawn_sandboxed(
            &policy,
            None,
            "cmd.exe",
            &[
                "/c".to_string(),
                format!("echo SENTINEL=%{sentinel_key}%& echo TEMP=%TEMP%"),
            ],
            &opts,
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
                let tmp_s = tmp.to_string_lossy().to_ascii_lowercase();
                assert!(
                    lower.contains(&tmp_s) || buf.contains(&*tmp.to_string_lossy()),
                    "child TEMP must be the private tmpdir {tmp_s}, got {buf:?}"
                );
            }
            Err(e) => {
                eprintln!("Sandbox spawn failed (may need elevation): {e}");
            }
        }
        let _ = std::fs::remove_dir_all(&tmp);
    }
}
