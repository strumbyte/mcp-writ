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

pub(crate) use crate::warden::linux_spawn::CredDrop;

/// Decide the workload's final credentials for the privilege split —
/// the setup that `ebpf-run` needs (BPF program+map ops, cgroup
/// attach, the `cgroup.procs` write) is privileged, but the untrusted
/// image must never inherit it.
///
/// - Launcher is **not** root: there is no setup privilege to shed;
///   the plan keeps the launcher's own ids and only strips ambient
///   capabilities in the child (the one set a setcap'd binary can hand
///   through `execve`).
/// - Launcher **is** root: the child demotes to the invoking user —
///   `SUDO_UID`/`SUDO_GID` (or `PKEXEC_UID` + the passwd primary gid).
///   Both ids must validate; a partial, root-valued, or absent pair is
///   refused rather than guessed at — *unless* `privileged` is the
///   explicit `--privileged-workload` opt-in, which keeps the
///   launcher's credentials by operator request (capability-sensitive
///   syscalls stay governed by the policy filter regardless of uid).
pub(crate) fn resolve_workload_cred(privileged: bool) -> Result<Option<CredDrop>, String> {
    // Safety: geteuid/getegid cannot fail.
    let euid = unsafe { libc::geteuid() };
    if euid != 0 {
        return Ok(Some(CredDrop {
            uid: euid,
            gid: unsafe { libc::getegid() },
            full: false,
        }));
    }
    if privileged {
        return Ok(None);
    }
    let env_id = |name: &str| -> Option<u32> {
        std::env::var(name)
            .ok()?
            .parse::<u32>()
            .ok()
            .filter(|v| *v != 0 && *v != u32::MAX)
    };
    plan_root_demote(
        env_id("SUDO_UID").or_else(|| env_id("PKEXEC_UID")),
        env_id("SUDO_GID"),
        primary_gid_for,
    )
}

/// Root-launcher case of [`resolve_workload_cred`], split out for
/// tests: `sudo_uid`/`sudo_gid` are already-parsed env ids (zero and
/// unparseable values must arrive as `None`), `primary_gid` resolves
/// the passwd fallback when `SUDO_GID` is absent (`pkexec` sets only
/// the uid).
pub(super) fn plan_root_demote(
    sudo_uid: Option<u32>,
    sudo_gid: Option<u32>,
    primary_gid: impl FnOnce(u32) -> Result<u32, String>,
) -> Result<Option<CredDrop>, String> {
    match (sudo_uid, sudo_gid) {
        (Some(uid), Some(gid)) => Ok(Some(CredDrop {
            uid,
            gid,
            full: true,
        })),
        (Some(uid), None) => Ok(Some(CredDrop {
            uid,
            gid: primary_gid(uid)?,
            full: true,
        })),
        _ => Err(
            "ebpf-run is running as root — the workload would inherit the launcher's \
             setup privileges. Run through sudo or pkexec so the invoking user is \
             known (SUDO_UID/SUDO_GID), or pass --privileged-workload to opt in to \
             privileged workload execution"
                .to_string(),
        ),
    }
}

/// The target's primary gid when only `PKEXEC_UID`/`SUDO_UID` exists.
/// Runs in the parent — allocation and the nss lookup are safe here.
fn primary_gid_for(uid: u32) -> Result<u32, String> {
    // Safety: `pwd`/`buf`/`result` are valid locals for getpwuid_r.
    let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
    let mut result: *mut libc::passwd = std::ptr::null_mut();
    let mut buf = vec![0u8; 4096];
    let rc = unsafe {
        libc::getpwuid_r(
            uid,
            &mut pwd,
            buf.as_mut_ptr().cast(),
            buf.len(),
            &mut result,
        )
    };
    if rc == 0 && !result.is_null() {
        // `result` aliases `pwd` on success, so read the field off the
        // local directly instead of dereferencing the raw pointer.
        let gid = pwd.pw_gid;
        if gid != 0 {
            return Ok(gid);
        }
    }
    Err(format!(
        "cannot resolve a primary gid for uid {uid} — set SUDO_GID or pass \
         --privileged-workload"
    ))
}

/// Spawn `argv` under the Linux sandbox pipeline plus the cgroup-eBPF
/// enforcement — the opt-in entry point. `rt` must already be prepared
/// (capability probing happened there); the child only applies.
///
/// The launch contract matches the `run`/`unotify-run` paths: the
/// child execs `resolved_exe` keeping `argv[0]`'s spelling, the
/// `defaults.environment` restriction applies, and a
/// [`SpawnPin`](crate::verifier::hash::SpawnPin) re-checks image
/// identity immediately before spawn.
pub(crate) fn spawn_supervised(
    policy: &crate::policy::Policy,
    argv: &[String],
    resolved_exe: &Path,
    spawn_pin: Option<&crate::verifier::hash::SpawnPin>,
    rt: &Runtime,
    demote: Option<CredDrop>,
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
    bits.demote = demote;
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
        ..Default::default()
    };
    // Exec through the pinned descriptors' `/proc/self/fd` spellings
    // when a pin exists — the kernel maps the verified object itself,
    // so a pathname swap after verification cannot reach the exec.
    // The plan holds the inherited dup handles and must outlive
    // `cmd.spawn()`.
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
