//! Workload launch for the CONNECT-proxy path — a mirror of the
//! audited `sandbox-exec` spawn in `warden/mod.rs` with two deltas:
//!
//! - the SBPL profile is generated in [`EgressProfile::ConnectProxy`]
//!   mode, pinning outbound TCP to the proxy's loopback port; and
//! - proxy env (`http_proxy`/`https_proxy`/`all_proxy` + uppercase)
//!   carries the loopback URL with the per-launch credential in
//!   userinfo, and `no_proxy`/`NO_PROXY` are scrubbed so nothing
//!   bypasses the proxy to a port it could otherwise reach.
//!
//! Everything else — private `TMPDIR`, the bash `exec -a` wrapper for
//! a distinct verified executable, `env_clear` semantics, process
//! group, the `initial_exit_check` liveness probe — matches the
//! audited spawn exactly, so rollback to the native path is a no-op
//! for the workload contract. The command is a PoC launcher (not an
//! MCP session): stdio is inherited, never piped.

use std::path::Path;
use std::process::Stdio;

use tokio::process::{Child, Command};

use crate::error::WardenError;
use crate::policy::Policy;
use crate::warden::SpawnOptions;
use crate::warden::macos_sandbox::{EgressProfile, PrivateTmpDir, SpawnLiveness};

use super::{PROXY_ENV_VARS, PROXY_USER, ProxyEndpoint};

/// The running workload plus the private `TMPDIR` guard that must
/// outlive it — same ownership shape as `RunningChild`.
pub(crate) struct ProxyChild {
    pub child: Child,
    /// `process_group(0)` makes pid == pgid — the supervisor's
    /// signal-forward/kill-group path uses it.
    pub pgid: i32,
    pub liveness: SpawnLiveness,
    _tmpdir: PrivateTmpDir,
}

/// Build the `sandbox-exec` command for proxy mode — factored out of
/// [`spawn_proxy_child`] so the profile/env assembly can be examined
/// without spawning. Returns the command and the private tmpdir guard.
async fn build_proxy_command(
    policy: &Policy,
    program: Option<&Path>,
    command: &str,
    args: &[String],
    opts: &SpawnOptions,
    endpoint: &ProxyEndpoint,
) -> Result<(Command, PrivateTmpDir), WardenError> {
    let helper = super::super::sandbox_exec::sandbox_exec_path()?;
    let tmpdir = super::super::macos_sandbox::create_private_tmpdir()?;
    let proxy_port = endpoint.addr.port();
    let (sbpl, _grants) = super::super::macos_sandbox::sbpl_profile_with_egress(
        policy,
        &tmpdir.path().to_string_lossy(),
        EgressProfile::ConnectProxy { proxy_port },
        &opts.exec_map_dirs,
    )?;

    let mut cmd = Command::new(&helper);
    cmd.arg("-p").arg(&sbpl).arg("--");
    // Same `exec -a` dance as the audited spawn: a distinct verified
    // executable goes through bash -p so argv[0] stays `command`.
    match program {
        Some(p) if p != Path::new(command) => {
            // Same SIP-pruning workaround as the audited spawn: the
            // relocated exe's dyld fallback dirs must be re-exported
            // inside the wrapper or the stripped env never reaches it.
            cmd.arg("/bin/bash")
                .arg("-p")
                .arg("-c")
                .arg(super::super::macos_sandbox::exec_a_command(
                    &opts.exec_dyld_fallback,
                ))
                .arg(command)
                .arg(p)
                .args(args);
        }
        _ => {
            cmd.arg(command).args(args);
        }
    }
    cmd.stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .kill_on_drop(true);
    let mut env_opts = opts.clone();
    if env_opts.tmpdir.is_none() {
        env_opts.tmpdir = Some(tmpdir.path().to_path_buf());
    }
    crate::warden::env::apply_spawn_env(&mut cmd, &env_opts);
    // Proxy env lands on top of the policy's env so restriction-mode
    // handling stays identical; no_proxy is scrubbed rather than set.
    let url = proxy_url(endpoint);
    for key in PROXY_ENV_VARS {
        cmd.env(key, &url);
    }
    cmd.env_remove("no_proxy").env_remove("NO_PROXY");
    // Same Python-venv fix the native path applies — the profile lets
    // the symlink target execute while blocking the wrapper.
    if let Some(exe) = super::super::python_executable_override(command, program) {
        cmd.env("PYTHONEXECUTABLE", exe);
    }
    Ok((cmd, tmpdir))
}

/// Spawn the workload under the proxy-pinned profile. Fails closed:
/// a missing `sandbox-exec` helper, a profile-build refusal, or a
/// spawn error all refuse the launch — the same contract the audited
/// spawn carries. `spawn()` succeeding only proves the helper ran;
/// `initial_exit_check` covers the profile-rejection window.
pub(crate) async fn spawn_proxy_child(
    policy: &Policy,
    program: Option<&Path>,
    command: &str,
    args: &[String],
    opts: &SpawnOptions,
    endpoint: &ProxyEndpoint,
) -> Result<ProxyChild, WardenError> {
    let (mut cmd, tmpdir) =
        build_proxy_command(policy, program, command, args, opts, endpoint).await?;
    crate::warden::child::apply_unix_process_group_tokio(&mut cmd);
    // fd hygiene + fd-exec handoff: the child's pre_exec seals every
    // ambient descriptor above stdio, then uncloaks the pin's dup'd
    // descriptors so the `/dev/fd` spellings stay resolvable through
    // the sandbox-exec → bash → exec chain. Enumeration failure aborts
    // the launch — an fd table that cannot be inspected cannot be
    // proven clean.
    crate::warden::attach_fd_hygiene_tokio(&mut cmd, &opts.exec_uncloak_fds).map_err(|e| {
        WardenError::sandbox_setup(crate::error::SandboxStage::Prepare, e.to_string())
    })?;
    let mut child = cmd.spawn().map_err(WardenError::ProcessSpawn)?;
    // Pin the pgid before the liveness probe — the probe may reap a
    // leader that exits inside the window, after which `id()` can no
    // longer resolve.
    let pgid = child.id().unwrap_or(0) as i32;
    let liveness = super::super::macos_sandbox::initial_exit_check(&mut child).await;
    Ok(ProxyChild {
        child,
        pgid,
        liveness,
        _tmpdir: tmpdir,
    })
}

/// The proxy URL the workload's env vars receive — one value shared
/// across [`PROXY_ENV_VARS`]; `no_proxy`/`NO_PROXY` are removed rather
/// than set.
fn proxy_url(endpoint: &ProxyEndpoint) -> String {
    format!("http://{PROXY_USER}:{}@{}", endpoint.token, endpoint.addr)
}
