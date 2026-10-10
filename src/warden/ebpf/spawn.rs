//! Spawn — the opt-in cgroup-eBPF launch. Mirrors
//! `unotify::spawn_supervised`: the ordinary Linux sandbox pipeline
//! (no_new_privs → Landlock → seccomp) stays in force, plus the child
//! joins the runtime's private cgroup between the (absent) unotify
//! stage and the policy filter so every `connect(2)` from exec onward
//! hits the attached `INET4/6_CONNECT` programs.

use std::path::Path;

use crate::error::{SandboxStage, WardenError};
use crate::warden::{SpawnOptions, env, linux_spawn};

use super::runtime::Runtime;

/// Spawn `argv` under the Linux sandbox pipeline plus the cgroup-eBPF
/// enforcement — the opt-in entry point. `rt` must already be prepared
/// (capability probing happened there); the child only applies.
///
/// The launch contract matches the `run`/`unotify-run` paths: the
/// child execs `resolved_exe` keeping `argv[0]`'s spelling, the
/// `defaults.environment` restriction applies, and a
/// [`SpawnPin`](crate::verifier::hash::SpawnPin) re-checks image
/// identity immediately before spawn.
pub fn spawn_supervised(
    policy: &crate::policy::Policy,
    argv: &[String],
    resolved_exe: &Path,
    spawn_pin: Option<&crate::verifier::hash::SpawnPin>,
    rt: &Runtime,
) -> Result<std::process::Child, WardenError> {
    let Some(argv0) = argv.first() else {
        return Err(WardenError::sandbox_setup(
            SandboxStage::Policy,
            "ebpf-run requires a command after `--`",
        ));
    };
    // The eBPF variant of `prepare_linux_child_sandbox` builds a
    // Landlock ruleset with no net handling: the cgroup connect hooks
    // are the connect authority on this route, and a Landlock
    // `socket_connect` denial would fire first and starve the
    // ring-buffer deny events.
    let mut bits = linux_spawn::prepare_linux_child_sandbox_ebpf(policy)?;
    bits.cgroup_procs = Some(rt.procs_writer().try_clone().map_err(|e| {
        WardenError::sandbox_setup(
            SandboxStage::Prepare,
            format!("cgroup.procs fd clone failed: {e}"),
        )
    })?);

    let env_opts = SpawnOptions {
        restrict_environment: policy.environment.restrict,
        allowed_names: policy.environment.allowed.clone(),
        tmpdir: None,
    };
    let mut cmd = std::process::Command::new(resolved_exe);
    std::os::unix::process::CommandExt::arg0(&mut cmd, argv0);
    cmd.args(&argv[1..])
        .stdin(std::process::Stdio::inherit())
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit());
    env::apply_spawn_env_sync(&mut cmd, &env_opts);
    // Own process group so teardown can kill the whole supervised tree.
    std::os::unix::process::CommandExt::process_group(&mut cmd, 0);
    let record = linux_spawn::attach_linux_pre_exec(&mut cmd, bits);
    if let Some(pin) = spawn_pin {
        pin.verify_spawn_path(resolved_exe).map_err(|e| {
            WardenError::sandbox_setup(
                SandboxStage::Policy,
                format!("supply chain verification failed at spawn: {e}"),
            )
        })?;
    }
    match cmd.spawn() {
        Ok(c) => Ok(c),
        Err(e) => {
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
            Err(WardenError::ProcessSpawn(std::io::Error::new(
                e.kind(),
                format!("{e}{detail}"),
            )))
        }
    }
}
