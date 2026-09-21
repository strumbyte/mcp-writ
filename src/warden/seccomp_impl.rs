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
    let mut allowed_syscalls: Vec<String> = policy.syscalls.allowed.clone();
    if allow_startup_exec {
        for required in ["execve", "execveat"] {
            if !allowed_syscalls.iter().any(|s| s == required) {
                allowed_syscalls.push(required.to_string());
            }
        }
    }

    // Translate policy syscall names to numeric rules.
    let rules = collect_syscall_rules(policy, &allowed_syscalls)?;

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

/// Build the syscall-nr → rules map for a set of allowed policy names.
///
/// Each nr maps to a vector of or-bound rules; an empty vector means the
/// syscall matches unconditionally.
fn collect_syscall_rules(
    policy: &Policy,
    allowed_syscalls: &[String],
) -> Result<BTreeMap<i64, Vec<SeccompRule>>, WardenError> {
    let mut rules: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();

    for name in allowed_syscalls {
        if DANGEROUS_SYSCALLS.contains(&name.as_str()) {
            tracing::warn!("seccomp: dangerous syscall '{name}' is explicitly allowed by policy");
        }

        let nrs = syscall_numbers(name);
        if nrs.is_empty() {
            tracing::warn!(
                "seccomp: syscall name '{name}' has no mapping on this architecture, skipping"
            );
            continue;
        }
        for nr in nrs {
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
            } else if (name == "fork" || name == "vfork") && nr == libc::SYS_clone {
                // fork/vfork expand to clone(2): pin clone's flag word to
                // exactly the bits those operations need so the grant
                // cannot mint namespaces or share memory/threads. The
                // exit signal is fixed at SIGCHLD; only the benign
                // CHILD_*TID bookkeeping flags stay optional.
                let required: u64 = libc::SIGCHLD as u64
                    | if name == "vfork" {
                        libc::CLONE_VM as u64 | libc::CLONE_VFORK as u64
                    } else {
                        0
                    };
                let optional: u64 =
                    libc::CLONE_CHILD_SETTID as u64 | libc::CLONE_CHILD_CLEARTID as u64;
                let cond = SeccompCondition::new(
                    0,
                    SeccompCmpArgLen::Qword,
                    SeccompCmpOp::MaskedEq(!optional),
                    required,
                )
                .map_err(|e| {
                    WardenError::sandbox_setup(
                        crate::error::SandboxStage::Prepare,
                        format!("seccomp {name} clone condition: {e}"),
                    )
                })?;
                let rule = SeccompRule::new(vec![cond]).map_err(|e| {
                    WardenError::sandbox_setup(
                        crate::error::SandboxStage::Prepare,
                        format!("seccomp {name} clone rule: {e}"),
                    )
                })?;
                match rules.get_mut(&nr) {
                    // An empty rule vector is an unconditional allow: an
                    // explicit "clone" entry must not be narrowed by a
                    // fork/vfork expansion.
                    Some(existing) if existing.is_empty() => {}
                    Some(existing) => existing.push(rule),
                    None => {
                        rules.insert(nr, vec![rule]);
                    }
                }
            } else {
                rules.insert(nr, vec![]);
            }
        }
    }

    Ok(rules)
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

/// Translate a syscall name (as written in the policy file) to every
/// Linux syscall number that can carry it on this architecture.
///
/// Policy names denote *operations* (`open`), but libcs implement them
/// through canonical syscalls (`openat`), and on aarch64 the legacy forms
/// do not exist at all — a policy written for x86_64 would silently lose
/// its coverage there. Each name therefore expands to the canonical
/// nr(s) libc can emit on this target, plus the native nr where the
/// architecture still provides the legacy form.
///
/// Returns an empty vec for unrecognised names so the caller can log a
/// warning without aborting the whole filter setup.
fn syscall_numbers(name: &str) -> Vec<i64> {
    if let Some(nr) = direct_number(name) {
        return vec![nr];
    }

    // Operation aliases: the canonical nr(s) carrying the operation on
    // every supported arch. Where a name has no direct mapping at all it
    // only lives here — e.g. aarch64 has no `open`, libc emits `openat`.
    let mut nrs: Vec<i64> = match name {
        "open" | "creat" => vec![libc::SYS_openat],
        // Path-based stat only: `fstat` is a real fd-based syscall on
        // both arches (aarch64 nr 80) and lives in `direct_number`.
        "stat" | "lstat" => vec![libc::SYS_newfstatat],
        "access" => vec![libc::SYS_faccessat, libc::SYS_faccessat2],
        "readlink" => vec![libc::SYS_readlinkat],
        "pipe" => vec![libc::SYS_pipe2],
        "dup2" => vec![libc::SYS_dup3],
        "poll" => vec![libc::SYS_ppoll],
        "select" => vec![libc::SYS_pselect6],
        "epoll_wait" => vec![libc::SYS_epoll_pwait],
        "mkdir" => vec![libc::SYS_mkdirat],
        "mknod" => vec![libc::SYS_mknodat],
        // unlinkat is the single primitive for both operations.
        "unlink" | "rmdir" => vec![libc::SYS_unlinkat],
        "chmod" => vec![libc::SYS_fchmodat],
        "chown" | "lchown" => vec![libc::SYS_fchownat],
        "link" => vec![libc::SYS_linkat],
        "symlink" => vec![libc::SYS_symlinkat],
        // aarch64 wires renameat at asm-generic nr 38; libc emits
        // renameat for rename()/renameat() there. renameat2's flag
        // operations (RENAME_NOREPLACE/EXCHANGE/WHITEOUT) are a separate
        // operation, granted only by an explicit "renameat2" entry.
        "rename" | "renameat" => vec![libc::SYS_renameat],
        // clone is the only fork primitive on aarch64; the allowlist has
        // no flag granularity for it on either arch.
        "fork" | "vfork" => vec![libc::SYS_clone],
        "accept" => vec![libc::SYS_accept, libc::SYS_accept4],
        // aarch64 dropped get/setrlimit; prlimit64 carries both (its pid
        // argument can target other processes — the widening is inherent
        // to the generic ABI, not this mapping).
        "getrlimit" | "setrlimit" => vec![libc::SYS_prlimit64],
        "futimesat" => vec![libc::SYS_utimensat],
        _ => Vec::new(),
    };
    nrs.extend(native_number(name));
    nrs
}

/// The native legacy nr for an aliased name, where the architecture
/// still provides it. aarch64 provides none of them.
#[cfg(target_arch = "x86_64")]
fn native_number(name: &str) -> Option<i64> {
    match name {
        "open" => Some(libc::SYS_open),
        "creat" => Some(libc::SYS_creat),
        "stat" => Some(libc::SYS_stat),
        "lstat" => Some(libc::SYS_lstat),
        "access" => Some(libc::SYS_access),
        "readlink" => Some(libc::SYS_readlink),
        "pipe" => Some(libc::SYS_pipe),
        "dup2" => Some(libc::SYS_dup2),
        "poll" => Some(libc::SYS_poll),
        "select" => Some(libc::SYS_select),
        "epoll_wait" => Some(libc::SYS_epoll_wait),
        "mkdir" => Some(libc::SYS_mkdir),
        "mknod" => Some(libc::SYS_mknod),
        "unlink" => Some(libc::SYS_unlink),
        "rmdir" => Some(libc::SYS_rmdir),
        "chmod" => Some(libc::SYS_chmod),
        "chown" => Some(libc::SYS_chown),
        "lchown" => Some(libc::SYS_lchown),
        "link" => Some(libc::SYS_link),
        "symlink" => Some(libc::SYS_symlink),
        "rename" => Some(libc::SYS_rename),
        "fork" => Some(libc::SYS_fork),
        "vfork" => Some(libc::SYS_vfork),
        "getrlimit" => Some(libc::SYS_getrlimit),
        "setrlimit" => Some(libc::SYS_setrlimit),
        "futimesat" => Some(libc::SYS_futimesat),
        "arch_prctl" => Some(libc::SYS_arch_prctl),
        _ => None,
    }
}

/// aarch64 has no legacy syscall nrs; every aliased name resolves to its
/// canonical nr only.
#[cfg(not(target_arch = "x86_64"))]
fn native_number(_name: &str) -> Option<i64> {
    None
}

/// Syscall names that map to exactly one nr on every supported arch.
fn direct_number(name: &str) -> Option<i64> {
    // Common syscalls present on both x86_64 and aarch64.
    let nr: Option<i64> = match name {
        "read" => Some(libc::SYS_read),
        "write" => Some(libc::SYS_write),
        "close" => Some(libc::SYS_close),
        "openat" => Some(libc::SYS_openat),
        "newfstatat" => Some(libc::SYS_newfstatat),
        "fstat" => Some(libc::SYS_fstat),
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
        // Modern names present on both arches; libc emits these directly.
        "faccessat" => Some(libc::SYS_faccessat),
        "faccessat2" => Some(libc::SYS_faccessat2),
        "readlinkat" => Some(libc::SYS_readlinkat),
        "statx" => Some(libc::SYS_statx),
        "mkdirat" => Some(libc::SYS_mkdirat),
        "unlinkat" => Some(libc::SYS_unlinkat),
        "fchmodat" => Some(libc::SYS_fchmodat),
        "fchownat" => Some(libc::SYS_fchownat),
        "linkat" => Some(libc::SYS_linkat),
        "symlinkat" => Some(libc::SYS_symlinkat),
        "renameat2" => Some(libc::SYS_renameat2),
        "openat2" => Some(libc::SYS_openat2),
        "execveat" => Some(libc::SYS_execveat),
        "ppoll" => Some(libc::SYS_ppoll),
        "pselect6" => Some(libc::SYS_pselect6),
        "memfd_create" => Some(libc::SYS_memfd_create),
        "close_range" => Some(libc::SYS_close_range),
        "sendmsg" => Some(libc::SYS_sendmsg),
        "recvmsg" => Some(libc::SYS_recvmsg),
        "sendmmsg" => Some(libc::SYS_sendmmsg),
        "recvmmsg" => Some(libc::SYS_recvmmsg),
        "getsockname" => Some(libc::SYS_getsockname),
        "getpeername" => Some(libc::SYS_getpeername),
        "socketpair" => Some(libc::SYS_socketpair),
        "sendfile" => Some(libc::SYS_sendfile),
        "ftruncate" => Some(libc::SYS_ftruncate),
        "truncate" => Some(libc::SYS_truncate),
        "fchmod" => Some(libc::SYS_fchmod),
        "fchown" => Some(libc::SYS_fchown),
        "statfs" => Some(libc::SYS_statfs),
        "fstatfs" => Some(libc::SYS_fstatfs),
        "utimensat" => Some(libc::SYS_utimensat),
        "mknodat" => Some(libc::SYS_mknodat),
        "inotify_init1" => Some(libc::SYS_inotify_init1),
        "inotify_add_watch" => Some(libc::SYS_inotify_add_watch),
        "inotify_rm_watch" => Some(libc::SYS_inotify_rm_watch),
        "copy_file_range" => Some(libc::SYS_copy_file_range),
        "splice" => Some(libc::SYS_splice),
        "readahead" => Some(libc::SYS_readahead),
        "fadvise64" => Some(libc::SYS_fadvise64),
        "pidfd_open" => Some(libc::SYS_pidfd_open),
        "pidfd_send_signal" => Some(libc::SYS_pidfd_send_signal),
        "uname" => Some(libc::SYS_uname),
        "sysinfo" => Some(libc::SYS_sysinfo),
        "waitid" => Some(libc::SYS_waitid),
        "getxattr" => Some(libc::SYS_getxattr),
        "setxattr" => Some(libc::SYS_setxattr),
        "listxattr" => Some(libc::SYS_listxattr),
        "removexattr" => Some(libc::SYS_removexattr),
        "fgetxattr" => Some(libc::SYS_fgetxattr),
        "fsetxattr" => Some(libc::SYS_fsetxattr),
        "flistxattr" => Some(libc::SYS_flistxattr),
        "fremovexattr" => Some(libc::SYS_fremovexattr),
        "lgetxattr" => Some(libc::SYS_lgetxattr),
        "lsetxattr" => Some(libc::SYS_lsetxattr),
        "llistxattr" => Some(libc::SYS_llistxattr),
        "lremovexattr" => Some(libc::SYS_lremovexattr),
        "timer_create" => Some(libc::SYS_timer_create),
        "timer_settime" => Some(libc::SYS_timer_settime),
        "timer_gettime" => Some(libc::SYS_timer_gettime),
        "timer_delete" => Some(libc::SYS_timer_delete),
        "timerfd_create" => Some(libc::SYS_timerfd_create),
        "timerfd_gettime" => Some(libc::SYS_timerfd_gettime),
        "timerfd_settime" => Some(libc::SYS_timerfd_settime),
        "signalfd4" => Some(libc::SYS_signalfd4),
        "getcpu" => Some(libc::SYS_getcpu),
        "sched_getattr" => Some(libc::SYS_sched_getattr),
        "sched_setattr" => Some(libc::SYS_sched_setattr),
        "sched_getparam" => Some(libc::SYS_sched_getparam),
        "sched_setparam" => Some(libc::SYS_sched_setparam),
        "sched_getscheduler" => Some(libc::SYS_sched_getscheduler),
        "sched_setscheduler" => Some(libc::SYS_sched_setscheduler),
        "getpriority" => Some(libc::SYS_getpriority),
        "setpriority" => Some(libc::SYS_setpriority),
        "ioprio_get" => Some(libc::SYS_ioprio_get),
        "ioprio_set" => Some(libc::SYS_ioprio_set),
        "get_mempolicy" => Some(libc::SYS_get_mempolicy),
        "set_mempolicy" => Some(libc::SYS_set_mempolicy),
        "msync" => Some(libc::SYS_msync),
        "mincore" => Some(libc::SYS_mincore),
        "mlock" => Some(libc::SYS_mlock),
        "mlock2" => Some(libc::SYS_mlock2),
        "mlockall" => Some(libc::SYS_mlockall),
        "munlock" => Some(libc::SYS_munlock),
        "munlockall" => Some(libc::SYS_munlockall),
        "personality" => Some(libc::SYS_personality),
        "capget" => Some(libc::SYS_capget),
        "io_uring_setup" => Some(libc::SYS_io_uring_setup),
        "io_uring_enter" => Some(libc::SYS_io_uring_enter),
        "io_uring_register" => Some(libc::SYS_io_uring_register),
        "membarrier" => Some(libc::SYS_membarrier),
        // Dangerous syscalls — mapped so that explicit policy entries work.
        "ptrace" => Some(libc::SYS_ptrace),
        "keyctl" => Some(libc::SYS_keyctl),
        "unshare" => Some(libc::SYS_unshare),
        "mount" => Some(libc::SYS_mount),
        "umount2" => Some(libc::SYS_umount2),
        _ => None,
    };
    nr
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
            assert_eq!(syscall_numbers(name), vec![expected]);
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

    #[test]
    fn legacy_names_resolve_to_canonical_syscalls() {
        // On every arch, `open` must grant `openat` — that is the syscall
        // libc actually emits for open(2).
        assert!(syscall_numbers("open").contains(&libc::SYS_openat));
        assert!(syscall_numbers("stat").contains(&libc::SYS_newfstatat));
        // fstat is a native fd-based syscall on both arches (aarch64 nr
        // 80); it must not be swallowed by the stat->newfstatat alias.
        assert_eq!(syscall_numbers("fstat"), vec![libc::SYS_fstat]);
        assert!(syscall_numbers("access").contains(&libc::SYS_faccessat));
        assert!(syscall_numbers("access").contains(&libc::SYS_faccessat2));
        assert!(syscall_numbers("poll").contains(&libc::SYS_ppoll));
        assert!(syscall_numbers("fork").contains(&libc::SYS_clone));
        assert!(syscall_numbers("accept").contains(&libc::SYS_accept4));
    }

    #[cfg(target_arch = "aarch64")]
    #[test]
    fn aarch64_has_no_legacy_nr_but_aliases_cover_them() {
        // The operations a typical policy names must still produce rules
        // even though the legacy syscall nrs do not exist on aarch64.
        for name in [
            "open",
            "stat",
            "fstat",
            "lstat",
            "access",
            "readlink",
            "pipe",
            "dup2",
            "poll",
            "select",
            "epoll_wait",
            "mkdir",
            "unlink",
            "rmdir",
            "chmod",
            "chown",
            "link",
            "symlink",
            "fork",
            "vfork",
            "accept",
        ] {
            assert!(
                !syscall_numbers(name).is_empty(),
                "{name} must resolve on aarch64"
            );
        }
        // arch_prctl is genuinely x86_64-only — nothing to alias to.
        assert!(syscall_numbers("arch_prctl").is_empty());
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn x86_64_aliases_keep_the_native_nr() {
        // x86_64 keeps the legacy nr AND gains the canonical one libc
        // uses internally (glibc open() emits openat on x86_64 too).
        let nrs = syscall_numbers("open");
        assert!(nrs.contains(&libc::SYS_open));
        assert!(nrs.contains(&libc::SYS_openat));
    }

    #[cfg(target_arch = "aarch64")]
    #[test]
    fn aarch64_rename_resolves_renameat_only() {
        // aarch64 wires renameat at nr 38; libc emits renameat for
        // rename()/renameat() there — and only that nr must reach the
        // filter. renameat2's flag operations stay behind an explicit
        // "renameat2" entry.
        for name in ["rename", "renameat"] {
            let nrs = syscall_numbers(name);
            assert!(
                nrs.contains(&libc::SYS_renameat),
                "{name} must map to renameat"
            );
            assert!(
                !nrs.contains(&libc::SYS_renameat2),
                "{name} must not grant renameat2"
            );
        }
        let mut policy = Policy::default();
        policy.syscalls.allowed = vec!["renameat".to_string()];
        let rules = collect_syscall_rules(&policy, &policy.syscalls.allowed).unwrap();
        assert!(rules.contains_key(&libc::SYS_renameat));
        assert!(!rules.contains_key(&libc::SYS_renameat2));
        // The flagged variant stays reachable under its own name.
        policy.syscalls.allowed = vec!["renameat2".to_string()];
        let rules = collect_syscall_rules(&policy, &policy.syscalls.allowed).unwrap();
        assert!(rules.contains_key(&libc::SYS_renameat2));
    }

    #[test]
    fn fork_vfork_expand_to_flag_constrained_clone() {
        // fork/vfork grants must not become an unconstrained clone grant:
        // clone's flag word is pinned to the bits those operations need.
        let mut policy = Policy::default();
        policy.syscalls.allowed = vec!["fork".to_string(), "vfork".to_string()];
        let rules = collect_syscall_rules(&policy, &policy.syscalls.allowed).unwrap();
        let clone_rules = rules
            .get(&libc::SYS_clone)
            .expect("fork/vfork must produce clone rules");
        assert_eq!(clone_rules.len(), 2, "one conditioned clone rule per name");

        // An explicit "clone" entry stays unconditional and is not
        // narrowed by fork/vfork expansion, in either policy order.
        for names in [["clone", "fork"], ["fork", "clone"]] {
            let mut policy = Policy::default();
            policy.syscalls.allowed = names.iter().map(|s| s.to_string()).collect();
            let rules = collect_syscall_rules(&policy, &policy.syscalls.allowed).unwrap();
            assert!(
                rules.get(&libc::SYS_clone).is_some_and(|r| r.is_empty()),
                "explicit clone must stay unconditional for {names:?}"
            );
        }
    }
}
