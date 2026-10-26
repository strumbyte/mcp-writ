//! Spawn — the opt-in supervised launch.

use std::fs::File;
use std::io;
use std::path::Path;

use crate::error::{SandboxStage, WardenError};
use crate::warden::{SpawnOptions, env, linux_spawn};

use super::filter::CONNECT_NR;
use super::handoff::enable_unotify;

/// A spawned, supervised child. `listener` is the notification fd the
/// child handed over; pass it to
/// [`Supervisor::start`](super::Supervisor::start).
pub struct SupervisedSpawn {
    pub child: std::process::Child,
    pub listener: File,
}

/// Spawn `argv` under the full Linux sandbox pipeline plus the
/// notification filter — the opt-in entry point. Preparation runs in
/// the parent; the child only applies. On any post-spawn failure the
/// spawned child is killed before the error returns — an unsupervised
/// child never survives this call.
///
/// The launch contract beyond the OS sandbox is the `run` path's: the
/// child execs `resolved_exe` (the canonicalized, hash-verified image)
/// while keeping the caller's `argv[0]` spelling, the
/// `defaults.environment` restriction applies to the child's
/// environment block, and a [`SpawnPin`](crate::verifier::hash::SpawnPin)
/// re-checks the image's identity immediately before the spawn.
pub fn spawn_supervised(
    policy: &crate::policy::Policy,
    argv: &[String],
    resolved_exe: &Path,
    spawn_pin: Option<&crate::verifier::hash::SpawnPin>,
) -> Result<SupervisedSpawn, WardenError> {
    let Some(argv0) = argv.first() else {
        return Err(WardenError::sandbox_setup(
            SandboxStage::Policy,
            "unotify-run requires a command after `--`",
        ));
    };
    let mut bits = linux_spawn::prepare_linux_child_sandbox(policy)?;
    let parent = enable_unotify(&mut bits, &[CONNECT_NR])?;

    let env_opts = SpawnOptions {
        restrict_environment: policy.environment.restrict,
        allowed_names: policy.environment.allowed.clone(),
        // No workload-private TMPDIR exists on this launch surface —
        // the guest contract's override belongs to the runner.
        tmpdir: None,
        ..Default::default()
    };
    // The allowlist-gap warning `run` prints — same contract, same
    // stderr surface on this front-end too.
    env::warn_env_allowlist_gaps(&env_opts);
    // Exec the executable through the pinned descriptor's
    // `/proc/self/fd` spelling when a pin exists — the kernel maps the
    // verified object itself, so a pathname swap after verification
    // cannot reach the exec. A pinned entrypoint script instead keeps
    // its real path inside argv (`exec_argv` re-spells the payload
    // arg): an interpreter resolves its module and imports relative to
    // that path, which the fd spelling cannot carry. The plan holds
    // the inherited dup handles and must outlive `cmd.spawn()`.
    let fd_exec_plan = match spawn_pin {
        Some(pin) => Some(pin.fd_exec_plan(argv, resolved_exe).map_err(|e| {
            WardenError::sandbox_setup(
                SandboxStage::Policy,
                format!("supply chain verification failed at spawn: {e}"),
            )
        })?),
        None => None,
    };
    if let Some(plan) = &fd_exec_plan {
        bits.exec_uncloak_fds = plan.uncloak_fds();
    }
    let (exec_target, exec_args_storage);
    match &fd_exec_plan {
        Some(plan) => {
            exec_target = plan.exe_path().to_path_buf();
            exec_args_storage = plan.exec_argv(argv);
        }
        None => {
            exec_target = resolved_exe.to_path_buf();
            exec_args_storage = argv.to_vec();
        }
    }
    let mut cmd = std::process::Command::new(&exec_target);
    std::os::unix::process::CommandExt::arg0(&mut cmd, argv0);
    cmd.args(&exec_args_storage[1..])
        .stdin(std::process::Stdio::inherit())
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit());
    env::apply_spawn_env_sync(&mut cmd, &env_opts);
    // Own process group so the fail-closed teardown can kill the whole
    // supervised tree, not just the exec'd image.
    std::os::unix::process::CommandExt::process_group(&mut cmd, 0);
    let record = linux_spawn::attach_linux_pre_exec(&mut cmd, bits);
    // The pin's identity re-check still runs last — a retargeted path
    // fails the launch rather than silently diverging from argv's own
    // resolution; for a path-launched entrypoint this same-object +
    // stamp check is the exec-time guarantee, while the exe's exec is
    // immune via the fd spelling above.
    if let Some(pin) = spawn_pin {
        pin.verify_spawn_path(resolved_exe).map_err(|e| {
            WardenError::sandbox_setup(
                SandboxStage::Policy,
                format!("supply chain verification failed at spawn: {e}"),
            )
        })?;
    }
    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            // Fold the child's apply record into the error text — the
            // recorded stage/errno is the only signal a pre_exec failure
            // leaves behind.
            let detail = record
                .as_ref()
                .map(|r| {
                    let s = r.snapshot();
                    format!(
                        " (sandbox apply record: stage={} failed_stage={} errno={})",
                        s.stage, s.failed_stage, s.errno
                    )
                })
                .unwrap_or_default();
            return Err(WardenError::ProcessSpawn(io::Error::new(
                e.kind(),
                format!("{e}{detail}"),
            )));
        }
    };
    // Spawn returning Ok means pre_exec completed — the handoff byte is
    // already queued or the spawn would have failed. A missing fd is
    // still fatal: kill the child rather than leave it supervised-None.
    match parent.recv_listener() {
        Ok(listener) => Ok(SupervisedSpawn { child, listener }),
        Err(e) => {
            kill_tree(&mut child);
            Err(WardenError::sandbox_setup(
                SandboxStage::Apply,
                format!("listener fd handoff failed after spawn: {e}"),
            ))
        }
    }
}

/// SIGKILL the child's process group, then reap — the supervised tree
/// never outlives a lost supervisor/handoff.
fn kill_tree(child: &mut std::process::Child) {
    let pid = child.id() as libc::pid_t;
    // Safety: kill() on a process group the child owns; -ESRCH when the
    // group already exited is fine. A 0 pid must not reach the calls —
    // `kill(0)` would signal *this* process's own group.
    if pid > 0 {
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe {
            libc::kill(-pid, libc::SIGKILL);
            libc::kill(pid, libc::SIGKILL);
        }
    }
    let _ = child.wait();
}
