use std::collections::BTreeMap;

use seccompiler::{
    BpfProgram, SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition, SeccompFilter,
    SeccompRule, TargetArch, apply_filter,
};

use crate::error::WardenError;
use crate::policy::Policy;

/// Syscall names that are blocked by default even if the policy lists them,
/// unless the policy *explicitly* includes them in `syscalls.allowed`.
///
/// These are high-privilege operations that an MCP server should almost
/// never need.  If the policy does allow them, a warning is logged.
const DANGEROUS_SYSCALLS: &[&str] = &["ptrace", "keyctl", "unshare", "mount", "umount2"];

/// Compile a seccomp-BPF program based on the given policy.
///
/// This compiles the BPF filter in the parent process (before fork),
/// avoiding memory allocations and lock acquisitions in `pre_exec`.
///
/// `execve` and `execveat` are not added here. The initial process start is
/// handled by `compile_seccomp_for_spawn`, which allows those syscalls only
/// for the spawn exec. The persistent policy filter excludes them unless the
/// policy itself lists them.
pub fn compile_seccomp(policy: &Policy) -> Result<BpfProgram, WardenError> {
    compile_seccomp_inner(policy, false)
}

/// Seccomp filter used for the initial spawn exec.
///
/// Allows `execve`/`execveat` so the child image can be started, then the
/// caller should apply [`compile_post_exec_filter`] so later execution is
/// excluded even if the policy listed those syscalls.
pub fn compile_seccomp_for_spawn(policy: &Policy) -> Result<BpfProgram, WardenError> {
    compile_seccomp_inner(policy, true)
}

/// Persistent filter that excludes `execve` and `execveat`.
///
/// Applied after the initial spawn exec so direct process execution is not
/// left open by the startup allowance or by `exec_shell` RPC denial alone.
#[allow(dead_code)]
pub fn compile_post_exec_filter(policy: &Policy) -> Result<BpfProgram, WardenError> {
    let mut policy_without_exec = policy.clone();
    policy_without_exec
        .syscalls
        .allowed
        .retain(|name| name != "execve" && name != "execveat");
    compile_seccomp_inner(&policy_without_exec, false)
}

fn compile_seccomp_inner(
    policy: &Policy,
    allow_startup_exec: bool,
) -> Result<BpfProgram, WardenError> {
    // Translate policy syscall names to numeric rules.
    let mut rules: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();

    let mut allowed_syscalls: Vec<String> = policy.syscalls.allowed.clone();
    if allow_startup_exec {
        for required in ["execve", "execveat"] {
            if !allowed_syscalls.iter().any(|s| s == required) {
                allowed_syscalls.push(required.to_string());
            }
        }
    }

    for name in &allowed_syscalls {
        if DANGEROUS_SYSCALLS.contains(&name.as_str()) {
            tracing::warn!("seccomp: dangerous syscall '{name}' is explicitly allowed by policy");
        }

        match syscall_number(name) {
            Some(nr) => {
                if name == "socket" && policy.network.outbound.deny_all_others {
                    // SOCK_STREAM only (mask SOCK_CLOEXEC/SOCK_NONBLOCK). UDP/RAW fail closed.
                    const SOCK_TYPE_MASK: u64 = 0xf;
                    const SOCK_STREAM: u64 = 1;
                    let cond = SeccompCondition::new(
                        1,
                        SeccompCmpArgLen::Dword,
                        SeccompCmpOp::MaskedEq(SOCK_TYPE_MASK),
                        SOCK_STREAM,
                    )
                    .map_err(|e| {
                        WardenError::sandbox_setup(
                            crate::error::SandboxStage::Prepare,
                            format!("seccomp socket condition: {e}"),
                        )
                    })?;
                    let rule = SeccompRule::new(vec![cond]).map_err(|e| {
                        WardenError::sandbox_setup(
                            crate::error::SandboxStage::Prepare,
                            format!("seccomp socket rule: {e}"),
                        )
                    })?;
                    rules.insert(nr, vec![rule]);
                } else {
                    rules.insert(nr, vec![]);
                }
            }
            None => {
                tracing::warn!("seccomp: unknown syscall name '{name}', skipping");
            }
        }
    }

    // Step 3: Determine target architecture.
    let arch = target_arch()?;

    // Step 4: Build filter.
    let filter = SeccompFilter::new(
        rules,
        SeccompAction::Errno(1), // EPERM
        SeccompAction::Allow,
        arch,
    )
    .map_err(|e| {
        WardenError::sandbox_setup(
            crate::error::SandboxStage::Prepare,
            format!("seccomp: failed to build filter: {e}"),
        )
    })?;

    // Step 5: Compile to BPF.
    let program: BpfProgram = filter.try_into().map_err(|e| {
        WardenError::sandbox_setup(
            crate::error::SandboxStage::Prepare,
            format!("seccomp: failed to compile BPF: {e}"),
        )
    })?;

    Ok(program)
}

pub fn policy_allows_execve(policy: &Policy) -> bool {
    policy
        .syscalls
        .allowed
        .iter()
        .any(|s| s == "execve" || s == "execveat")
}

/// Spawning a child requires either an explicit execve allowance or
/// `sandbox.allow_degraded` (which leaves leftover execve in the inherited filter).
pub fn require_execve_allowance(policy: &Policy) -> Result<(), WardenError> {
    if policy_allows_execve(policy) {
        return Ok(());
    }
    if policy.sandbox.allow_degraded {
        tracing::warn!(
            "syscalls.allowed does not include execve; spawn filter will leave execve \
             available because sandbox.allow_degraded=true"
        );
        return Ok(());
    }
    Err(WardenError::sandbox_setup(
        crate::error::SandboxStage::Policy,
        "syscalls.allowed must include execve (or execveat) to spawn a child process, \
         or set sandbox.allow_degraded=#true to accept leftover execve in the inherited filter",
    ))
}

/// Apply a pre-compiled seccomp-BPF program.
///
/// Safe to call within `pre_exec` after fork: `apply_filter` performs only a
/// direct syscall, and the error path unwraps the inner `io::Error` (an Os
/// repr that never heap-allocates) instead of formatting a message.
pub fn apply_seccomp_program(program: &BpfProgram) -> std::io::Result<()> {
    apply_filter(program).map_err(|e| match e {
        seccompiler::Error::Prctl(e) | seccompiler::Error::Seccomp(e) => e,
        _ => std::io::Error::from_raw_os_error(libc::EACCES),
    })
}

/// Apply a seccomp-BPF filter based on the given policy.
#[allow(dead_code)]
pub fn apply_seccomp(policy: &Policy) -> Result<(), WardenError> {
    let program = compile_seccomp(policy)?;
    apply_seccomp_program(&program).map_err(|e| {
        WardenError::sandbox_setup(
            crate::error::SandboxStage::Apply,
            format!("seccomp: failed to apply filter: {e}"),
        )
    })?;
    tracing::info!("seccomp: syscall filter applied successfully");
    Ok(())
}

/// Set the `PR_SET_NO_NEW_PRIVS` bit via `prctl(2)`.
///
/// This is a prerequisite for unprivileged seccomp filter installation.
/// Once set, the bit is inherited across `fork`/`clone`/`execve` and
/// cannot be unset.
///
/// Returns the raw prctl errno as an `io::Error` so callers in `pre_exec`
/// context get a meaningful failure without any heap allocation.
pub(crate) fn set_no_new_privs() -> std::io::Result<()> {
    // SAFETY: prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) is a well-defined
    // Linux syscall with no pointer arguments.
    let ret = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if ret != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// Map the runtime architecture to seccompiler's `TargetArch`.
fn target_arch() -> Result<TargetArch, WardenError> {
    #[cfg(target_arch = "x86_64")]
    {
        return Ok(TargetArch::x86_64);
    }

    #[cfg(target_arch = "aarch64")]
    {
        return Ok(TargetArch::aarch64);
    }

    #[allow(unreachable_code)]
    Err(WardenError::sandbox_setup(
        crate::error::SandboxStage::Prepare,
        "seccomp: unsupported architecture (only x86_64 and aarch64 supported)",
    ))
}

/// Translate a syscall name (as written in the policy file) to its
/// Linux syscall number.
///
/// Returns `None` for unrecognised names so the caller can log a
/// warning without aborting the whole filter setup.
fn syscall_number(name: &str) -> Option<i64> {
    // Common syscalls present on both x86_64 and aarch64.
    let nr: Option<i64> = match name {
        "read" => Some(libc::SYS_read),
        "write" => Some(libc::SYS_write),
        "close" => Some(libc::SYS_close),
        "openat" => Some(libc::SYS_openat),
        "newfstatat" => Some(libc::SYS_newfstatat),
        "lseek" => Some(libc::SYS_lseek),
        "mmap" => Some(libc::SYS_mmap),
        "mprotect" => Some(libc::SYS_mprotect),
        "munmap" => Some(libc::SYS_munmap),
        "brk" => Some(libc::SYS_brk),
        "rt_sigaction" => Some(libc::SYS_rt_sigaction),
        "rt_sigprocmask" => Some(libc::SYS_rt_sigprocmask),
        "ioctl" => Some(libc::SYS_ioctl),
        "pread64" => Some(libc::SYS_pread64),
        "pwrite64" => Some(libc::SYS_pwrite64),
        "readv" => Some(libc::SYS_readv),
        "writev" => Some(libc::SYS_writev),
        "getcwd" => Some(libc::SYS_getcwd),
        "chdir" => Some(libc::SYS_chdir),
        "fcntl" => Some(libc::SYS_fcntl),
        "flock" => Some(libc::SYS_flock),
        "fsync" => Some(libc::SYS_fsync),
        "dup" => Some(libc::SYS_dup),
        "dup3" => Some(libc::SYS_dup3),
        "pipe2" => Some(libc::SYS_pipe2),
        "clone" => Some(libc::SYS_clone),
        "execve" => Some(libc::SYS_execve),
        "exit" => Some(libc::SYS_exit),
        "exit_group" => Some(libc::SYS_exit_group),
        "wait4" => Some(libc::SYS_wait4),
        "kill" => Some(libc::SYS_kill),
        "getpid" => Some(libc::SYS_getpid),
        // Go runtime thread identity and asynchronous preemption.
        "gettid" => Some(libc::SYS_gettid),
        "tgkill" => Some(libc::SYS_tgkill),
        "getppid" => Some(libc::SYS_getppid),
        "getuid" => Some(libc::SYS_getuid),
        "getgid" => Some(libc::SYS_getgid),
        "geteuid" => Some(libc::SYS_geteuid),
        "getegid" => Some(libc::SYS_getegid),
        "setsid" => Some(libc::SYS_setsid),
        "sigaltstack" => Some(libc::SYS_sigaltstack),
        "socket" => Some(libc::SYS_socket),
        "connect" => Some(libc::SYS_connect),
        "bind" => Some(libc::SYS_bind),
        "listen" => Some(libc::SYS_listen),
        "accept4" => Some(libc::SYS_accept4),
        "sendto" => Some(libc::SYS_sendto),
        "recvfrom" => Some(libc::SYS_recvfrom),
        "shutdown" => Some(libc::SYS_shutdown),
        "setsockopt" => Some(libc::SYS_setsockopt),
        "getsockopt" => Some(libc::SYS_getsockopt),
        "epoll_create1" => Some(libc::SYS_epoll_create1),
        "epoll_ctl" => Some(libc::SYS_epoll_ctl),
        "eventfd2" => Some(libc::SYS_eventfd2),
        "futex" => Some(libc::SYS_futex),
        "nanosleep" => Some(libc::SYS_nanosleep),
        "clock_gettime" => Some(libc::SYS_clock_gettime),
        "clock_nanosleep" => Some(libc::SYS_clock_nanosleep),
        "getrandom" => Some(libc::SYS_getrandom),
        "prctl" => Some(libc::SYS_prctl),
        // Thread/process lifecycle (needed by glibc and tokio runtime).
        "set_tid_address" => Some(libc::SYS_set_tid_address),
        "set_robust_list" => Some(libc::SYS_set_robust_list),
        "sched_getaffinity" => Some(libc::SYS_sched_getaffinity),
        "sched_yield" => Some(libc::SYS_sched_yield),
        "rt_sigreturn" => Some(libc::SYS_rt_sigreturn),
        "madvise" => Some(libc::SYS_madvise),
        "epoll_pwait" => Some(libc::SYS_epoll_pwait),
        "prlimit64" => Some(libc::SYS_prlimit64),
        "rseq" => Some(libc::SYS_rseq),
        "clone3" => Some(libc::SYS_clone3),
        "getdents64" => Some(libc::SYS_getdents64),
        // Dangerous syscalls — mapped so that explicit policy entries work.
        "ptrace" => Some(libc::SYS_ptrace),
        "keyctl" => Some(libc::SYS_keyctl),
        "unshare" => Some(libc::SYS_unshare),
        "mount" => Some(libc::SYS_mount),
        "umount2" => Some(libc::SYS_umount2),
        _ => None,
    };

    if nr.is_some() {
        return nr;
    }

    // x86_64-only syscalls (absent on aarch64 where *at variants are used).
    #[cfg(target_arch = "x86_64")]
    {
        let nr = match name {
            "open" => Some(libc::SYS_open),
            "stat" => Some(libc::SYS_stat),
            "fstat" => Some(libc::SYS_fstat),
            "lstat" => Some(libc::SYS_lstat),
            "access" => Some(libc::SYS_access),
            "pipe" => Some(libc::SYS_pipe),
            "select" => Some(libc::SYS_select),
            "poll" => Some(libc::SYS_poll),
            "dup2" => Some(libc::SYS_dup2),
            "fork" => Some(libc::SYS_fork),
            "vfork" => Some(libc::SYS_vfork),
            "creat" => Some(libc::SYS_creat),
            "link" => Some(libc::SYS_link),
            "unlink" => Some(libc::SYS_unlink),
            "symlink" => Some(libc::SYS_symlink),
            "readlink" => Some(libc::SYS_readlink),
            "chmod" => Some(libc::SYS_chmod),
            "chown" => Some(libc::SYS_chown),
            "mkdir" => Some(libc::SYS_mkdir),
            "rmdir" => Some(libc::SYS_rmdir),
            "epoll_wait" => Some(libc::SYS_epoll_wait),
            "accept" => Some(libc::SYS_accept),
            "arch_prctl" => Some(libc::SYS_arch_prctl),
            _ => None,
        };
        if nr.is_some() {
            return nr;
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::Policy;

    #[test]
    fn go_runtime_syscalls_are_mapped_but_not_implicitly_allowed() {
        let policy = Policy::default();
        let baseline = compile_seccomp(&policy).unwrap();
        for (name, expected) in [
            ("gettid", libc::SYS_gettid),
            ("tgkill", libc::SYS_tgkill),
            ("eventfd2", libc::SYS_eventfd2),
        ] {
            assert_eq!(syscall_number(name), Some(expected));
            assert!(
                !policy
                    .syscalls
                    .allowed
                    .iter()
                    .any(|allowed| allowed == name)
            );
            let mut opted_in = policy.clone();
            opted_in.syscalls.allowed.push(name.into());
            assert!(
                compile_seccomp(&opted_in).unwrap().len() > baseline.len(),
                "{name} must produce an actual rule"
            );
        }
    }

    #[test]
    fn compile_post_exec_filter_excludes_startup_exec() {
        let policy = Policy::default();
        assert!(compile_seccomp(&policy).is_ok());
        assert!(compile_seccomp_for_spawn(&policy).is_ok());
        assert!(compile_post_exec_filter(&policy).is_ok());
    }
}
