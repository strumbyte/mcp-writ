use super::*;
use crate::policy::Policy;

/// Syscall names a glibc `/bin/true` needs to exec and exit — the
/// spawn filter must let the dynamic loader and the exit path run.
/// The assertion only reads the apply record, so a missing runtime
/// syscall degrades the child, not the test.
fn true_policy() -> Policy {
    let mut policy = Policy::default();
    // Tolerate partial/absent Landlock so the spawn proceeds on
    // kernels without full support — the record still reports the
    // kernel's actual level.
    policy.sandbox.allow_degraded = true;
    policy.fs.read_only = vec!["/".to_string()];
    policy.syscalls.allowed = [
        "execve",
        "execveat",
        "read",
        "write",
        "close",
        "openat",
        "open",
        "newfstatat",
        "fstat",
        "stat",
        "lstat",
        "access",
        "readlink",
        "lseek",
        "pread64",
        "mmap",
        "mprotect",
        "munmap",
        "brk",
        "rt_sigaction",
        "rt_sigprocmask",
        "rt_sigreturn",
        "ioctl",
        "getcwd",
        "fcntl",
        "dup",
        "dup2",
        "dup3",
        "pipe",
        "pipe2",
        "clone",
        "clone3",
        "exit",
        "exit_group",
        "wait4",
        "getpid",
        "getppid",
        "getuid",
        "getgid",
        "geteuid",
        "getegid",
        "setsid",
        "sigaltstack",
        "futex",
        "nanosleep",
        "clock_gettime",
        "getrandom",
        "prctl",
        "arch_prctl",
        "set_tid_address",
        "set_robust_list",
        "sched_getaffinity",
        "sched_yield",
        "madvise",
        "prlimit64",
        "rseq",
        "getdents64",
        "statx",
        "faccessat",
        "faccessat2",
        "readlinkat",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    policy
}

#[test]
fn apply_record_round_trips_through_the_shared_page() {
    let record = SharedApplyRecord::map().expect("mmap a shared page");
    assert_eq!(record.snapshot().stage, stage::NONE);

    // Simulate the child-side writers through the shared pointer —
    // the same atomic stores apply_in_child performs.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    let page = unsafe { &*(record.child_ptr() as *const ApplyRecordPage) };
    page.landlock_abi.store(1, Ordering::Relaxed);
    page.landlock
        .store(landlock_level::PARTIAL, Ordering::Relaxed);
    page.stage.store(stage::LANDLOCK, Ordering::Release);
    page.errno.store(libc::EPERM, Ordering::Relaxed);
    page.failed_stage.store(stage::SECCOMP, Ordering::Release);

    let snap = record.snapshot();
    assert!(snap.landlock_completed());
    assert!(!snap.seccomp_applied());
    assert_eq!(snap.landlock, landlock_level::PARTIAL);
    assert_eq!(snap.landlock_abi, 1);
    assert_eq!(snap.failed_stage, stage::SECCOMP);
    assert_eq!(snap.errno, libc::EPERM);
}

/// Refused counterpart of the happy path: with `allow_degraded` off,
/// a kernel that only partially enforces the ruleset must abort the
/// spawn — and the record must still carry the real level and the
/// failing stage (the record write precedes the error return).
#[test]
fn real_spawn_refusal_records_the_failing_stage() {
    if !std::path::Path::new("/bin/true").exists() {
        return;
    }
    let mut policy = true_policy();
    policy.sandbox.allow_degraded = false;
    let Ok(bits) = prepare_linux_child_sandbox(&policy) else {
        return;
    };
    let mut cmd = std::process::Command::new("/bin/true");
    let record = attach_linux_pre_exec(&mut cmd, bits).expect("shared record page");
    match cmd.spawn() {
        Ok(mut child) => {
            // Fully-enforced kernels legitimately pass the gate.
            let snap = record.snapshot();
            let _ = child.wait();
            assert_eq!(snap.stage, stage::SECCOMP);
            assert_eq!(snap.landlock, landlock_level::FULL);
        }
        Err(e) => {
            let snap = record.snapshot();
            assert_eq!(snap.failed_stage, stage::LANDLOCK);
            assert_eq!(snap.errno, e.raw_os_error().unwrap_or(-1));
            assert!(
                matches!(
                    snap.landlock,
                    landlock_level::PARTIAL | landlock_level::NOT_ENFORCED
                ),
                "refusal without a degraded kernel level: {snap:?}"
            );
        }
    }
}

/// An exec-time failure (ENOENT) still records the full pipeline —
/// the applies ran; only execve failed. The record distinguishes
/// "sandbox applied, image missing" from "apply failed".
#[test]
fn exec_failure_still_records_completed_stages() {
    let Ok(bits) = prepare_linux_child_sandbox(&true_policy()) else {
        return;
    };
    let mut cmd = std::process::Command::new("/definitely-not-a-real-binary-mcpwrit");
    let record = attach_linux_pre_exec(&mut cmd, bits).expect("shared record page");
    match cmd.spawn() {
        Ok(mut child) => {
            // The path is absolute, so no PATH search runs and the
            // spawn is expected to fail — but if it unexpectedly
            // succeeded the record must still be complete.
            let snap = record.snapshot();
            let _ = child.wait();
            assert_eq!(snap.stage, stage::SECCOMP);
        }
        Err(_) => {
            let snap = record.snapshot();
            if snap.stage == stage::NONE && snap.failed_stage == stage::NONE {
                // The child never ran (a fork-level failure such as
                // EAGAIN): nothing reached the record, so the
                // exec-failure path this test targets did not run.
                return;
            }
            if snap.failed_stage != stage::NONE {
                // A genuine apply-stage refusal — covered by
                // real_spawn_refusal_records_the_failing_stage. The
                // record must still satisfy the honest invariant
                // (stage == failed_stage - 1) the parent relies on.
                assert_eq!(snap.stage.checked_add(1), Some(snap.failed_stage));
                assert_ne!(snap.errno, 0);
                return;
            }
            // The expected case: execve failed (e.g. ENOENT) after
            // the sandbox pipeline ran to completion.
            assert_eq!(snap.stage, stage::SECCOMP);
        }
    }
}

/// End-to-end channel check: a real `pre_exec` run fills the record
/// in the child, and the parent reads it after `spawn()`. Both
/// branches prove the channel — a sandboxed spawn carries a complete
/// record; a refused spawn carries the failing stage and errno.
#[test]
fn real_spawn_collects_the_child_apply_record() {
    if !std::path::Path::new("/bin/true").exists() {
        return;
    }
    let Ok(bits) = prepare_linux_child_sandbox(&true_policy()) else {
        return; // policy build unsupported in this environment
    };
    let mut cmd = std::process::Command::new("/bin/true");
    let record = attach_linux_pre_exec(&mut cmd, bits).expect("shared record page");
    match cmd.spawn() {
        Ok(mut child) => {
            let snap = record.snapshot();
            let _ = child.wait();
            assert_eq!(snap.stage, stage::SECCOMP);
            assert_eq!(snap.failed_stage, 0);
            assert!(snap.no_new_privs_applied());
            assert!(snap.seccomp_applied());
            assert!(
                matches!(
                    snap.landlock,
                    landlock_level::FULL | landlock_level::PARTIAL | landlock_level::NOT_ENFORCED
                ),
                "unexpected landlock level {}",
                snap.landlock
            );
        }
        Err(_) => {
            let snap = record.snapshot();
            // A refusal must name the stage that failed — the record
            // is never a silent zero on a failed spawn.
            assert_ne!(snap.failed_stage, stage::NONE);
            assert_ne!(snap.errno, 0);
        }
    }
}

/// The ambient-fd seal runs in a forked child (it flags every fd —
/// running it in the test process would orphan the harness's
/// descriptors at its next exec): the child seals with the report
/// fd kept, writes back the errno (0 on success), and `_exit`s.
/// The parent asserts the seal succeeded and that an fd opened
/// before the fork now carries FD_CLOEXEC in the child's view.
#[test]
fn seal_ambient_fds_flags_everything_except_keep() {
    use std::os::unix::io::AsRawFd;
    let spare = std::fs::File::open("/dev/null").expect("/dev/null");
    let spare_fd = spare.as_raw_fd();
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    unsafe {
        let mut p = [0i32; 2];
        assert_eq!(libc::pipe(p.as_mut_ptr()), 0);
        let pid = libc::fork();
        assert!(pid >= 0, "fork failed");
        if pid == 0 {
            libc::close(p[0]);
            let r = match open_fd_table() {
                Ok(dirfd) => seal_ambient_fds(dirfd, &[p[1]]),
                Err(e) => Err(e),
            };
            let code: i32 = r.map_or_else(|e| e.raw_os_error().unwrap_or(-1), |()| 0);
            libc::write(p[1], (&code as *const i32).cast(), 4);
            // spare must carry FD_CLOEXEC in the sealed child.
            let stat = libc::fcntl(spare_fd, libc::F_GETFD);
            libc::write(p[1], (&stat as *const i32).cast(), 4);
            // p[1] was kept — still live and unflagged.
            let kept = libc::fcntl(p[1], libc::F_GETFD);
            libc::write(p[1], (&kept as *const i32).cast(), 4);
            libc::_exit(0);
        }
        libc::close(p[1]);
        let mut code = -999i32;
        let mut stat = 0i32;
        let mut kept = 0i32;
        libc::read(p[0], (&mut code as *mut i32).cast(), 4);
        libc::read(p[0], (&mut stat as *mut i32).cast(), 4);
        libc::read(p[0], (&mut kept as *mut i32).cast(), 4);
        libc::close(p[0]);
        let mut st = 0i32;
        libc::waitpid(pid, &mut st, 0);
        assert_eq!(code, 0, "seal failed with errno {code}");
        assert_eq!(stat, libc::FD_CLOEXEC, "spare fd was not sealed");
        assert_eq!(kept, 0, "kept fd was sealed");
    }
}

/// Regression coverage for the seal-ordering fix: the ambient-fd
/// seal used to open `/proc/self/fd` *after* Landlock
/// `restrict_self`, so any policy that did not grant `/proc` failed
/// every launch at the seal. The dirfd is now opened before
/// restriction, so a realistic policy — the interpreter's own tree
/// and nothing else, no `/proc` — must still run the pipeline to
/// SECCOMP on a Landlock-enforcing kernel.
#[test]
fn spawn_under_policy_without_proc_grant_completes() {
    if !std::path::Path::new("/bin/true").exists() {
        return;
    }
    let mut policy = true_policy();
    // read_only covering just the dynamic image's tree: /bin/true,
    // the loader, libc and ld.so.cache. `/proc` is deliberately
    // absent — on a fully enforced kernel the old ordering died
    // here at the seal with EACCES.
    policy.fs.read_only = ["/bin", "/usr", "/lib", "/lib64", "/etc"]
        .iter()
        .map(|s| s.to_string())
        .collect();
    let Ok(bits) = prepare_linux_child_sandbox(&policy) else {
        return;
    };
    let mut cmd = std::process::Command::new("/bin/true");
    let record = attach_linux_pre_exec(&mut cmd, bits).expect("shared record page");
    match cmd.spawn() {
        Ok(mut child) => {
            let snap = record.snapshot();
            let status = child.wait();
            assert_eq!(snap.stage, stage::SECCOMP);
            assert_eq!(snap.failed_stage, 0);
            assert!(status.map(|s| s.success()).unwrap_or(false));
        }
        Err(_) => {
            let snap = record.snapshot();
            assert_ne!(snap.failed_stage, stage::NONE);
            assert_ne!(snap.errno, 0);
            // The seal must never be the failing stage under a
            // /proc-less policy — that was the ordering bug.
            assert!(
                !(snap.failed_stage == stage::SECCOMP && snap.errno == libc::EACCES),
                "fd-table open regressed past Landlock: {snap:?}"
            );
        }
    }
}
