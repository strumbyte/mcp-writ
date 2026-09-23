//! Linux spawn-time sandbox wiring (Landlock + seccomp via `pre_exec`).
//!
//! The kernel sandbox is applied inside the child between fork and exec.
//! Everything that allocates (the BPF program, the Landlock ruleset) is built
//! in the parent before spawn so the `pre_exec` closure performs no heap work.
//!
//! Child-side order is fixed and must not be reordered:
//! `no_new_privs` → Landlock `restrict_self` → seccomp apply.
//! Neither restriction may run in the parent process — that would kill the
//! proxy. This module is compiled only on Linux.
//!
//! ## Apply-state collection
//!
//! The child's apply result reaches the parent through one `MAP_SHARED`
//! anonymous page allocated by the parent before spawn
//! ([`SharedApplyRecord`]). The `pre_exec` closure fills it with plain
//! atomic stores — no allocation, formatting, tracing, locking, *or
//! syscall* — so the record is still writable after the seccomp filter is
//! installed and no `write`-shaped allowance is added for reporting.
//!
//! The record cannot be forged by the exec'd workload: `execve` drops
//! every mapping of the old address space, and an anonymous shared page
//! has no fd or name the new image could use to reach it. Only the
//! not-yet-exec'd child writes it. A partially filled record reads as
//! "stage N completed, stage N+1 failed with errno E" or simply
//! truncated — never as confirmed.

use std::sync::atomic::{AtomicI32, AtomicU8, Ordering};

use landlock::{LandlockStatus, RestrictionStatus, RulesetCreated, RulesetStatus};
use seccompiler::BpfProgram;

use crate::enforcement::ProcessGrant;
use crate::error::WardenError;
use crate::policy::Policy;

use super::{landlock_impl, seccomp_impl};

// ---------------------------------------------------------------------------
// Shared apply record (parent <-> pre-exec child)
// ---------------------------------------------------------------------------

/// Apply-stage codes stored in [`ApplyRecordPage::stage`]: the highest
/// stage the child *completed*, increasing monotonically. `stage` stores
/// carry `Release`; a parent `Acquire` load of `stage`/`failed_stage`
/// publishes the fields written before them.
pub(super) mod stage {
    /// No stage completed (fresh page, or the child died before
    /// `no_new_privs` returned).
    pub const NONE: u8 = 0;
    /// `prctl(PR_SET_NO_NEW_PRIVS)` returned success.
    pub const NO_NEW_PRIVS: u8 = 1;
    /// `restrict_self` ran and the enforcement-level gate passed (or no
    /// ruleset existed — see the `landlock` field).
    pub const LANDLOCK: u8 = 2;
    /// The seccomp program was installed — the whole pipeline ran.
    pub const SECCOMP: u8 = 3;
}

/// Landlock enforcement levels stored in [`ApplyRecordPage::landlock`].
/// Valid only when `stage >= stage::LANDLOCK`.
pub(super) mod landlock_level {
    /// The Landlock stage never ran (record default).
    pub const NOT_RUN: u8 = 0;
    /// `RulesetStatus::FullyEnforced`.
    pub const FULL: u8 = 1;
    /// `RulesetStatus::PartiallyEnforced`.
    pub const PARTIAL: u8 = 2;
    /// `RulesetStatus::NotEnforced`.
    pub const NOT_ENFORCED: u8 = 3;
    /// No ruleset existed — nothing was applied.
    pub const NO_RULESET: u8 = 4;
}

/// Fixed-size record the pre-exec child fills through the shared page.
/// Layout is plain atomics; the kernel zero-fills the page so the parent
/// can tell "never reached" from "completed" without initialization in
/// the child.
#[repr(C)]
struct ApplyRecordPage {
    /// Highest completed stage (`stage::*`).
    stage: AtomicU8,
    /// Kernel-reported Landlock level (`landlock_level::*`).
    landlock: AtomicU8,
    /// Kernel Landlock ABI the ruleset ran against (0 = unknown).
    landlock_abi: AtomicU8,
    /// Stage that returned `Err` to `pre_exec` (0 = none recorded).
    failed_stage: AtomicU8,
    /// Raw errno of `failed_stage` (0 = none recorded).
    errno: AtomicI32,
}

/// Parent-side handle to the shared apply-record page. Created per spawn;
/// the parent keeps it alive through `Command::spawn` and reads
/// [`Self::snapshot`] afterwards.
pub(super) struct SharedApplyRecord {
    ptr: *mut ApplyRecordPage,
    len: usize,
}

impl SharedApplyRecord {
    /// Allocate one zeroed shared page. `None` (mmap failure) still lets
    /// the spawn run sandboxed — the observations then read `Unknown`
    /// because collection was impossible, never "applied".
    fn map() -> Option<Self> {
        let len = std::mem::size_of::<ApplyRecordPage>();
        // Safety: standard anonymous shared mapping; no fd, no file.
        let ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        if ptr == libc::MAP_FAILED {
            return None;
        }
        Some(Self {
            ptr: ptr.cast(),
            len,
        })
    }

    /// Raw page address copied into the `pre_exec` closure as a `usize`
    /// (raw pointers are not `Send`). Valid while `self` is alive.
    fn child_ptr(&self) -> usize {
        self.ptr as usize
    }

    /// Decode the record after `spawn()` returned. Spawn returning (Ok or
    /// Err) means the child's pre-exec writes finished: either exec
    /// succeeded (the stage stores preceded it) or the child wrote the
    /// error packet / died after recording `failed_stage`.
    pub(super) fn snapshot(&self) -> ApplySnapshot {
        // Safety: `ptr` refers to a live mapping owned by `self`.
        let page = unsafe { &*self.ptr };
        ApplySnapshot {
            stage: page.stage.load(Ordering::Acquire),
            landlock: page.landlock.load(Ordering::Acquire),
            landlock_abi: page.landlock_abi.load(Ordering::Acquire),
            failed_stage: page.failed_stage.load(Ordering::Acquire),
            errno: page.errno.load(Ordering::Acquire),
        }
    }
}

impl Drop for SharedApplyRecord {
    fn drop(&mut self) {
        // Safety: `ptr`/`len` name the mapping created in `map`.
        unsafe { libc::munmap(self.ptr.cast(), self.len) };
    }
}

/// Decoded copy of the child's apply record — what the parent can trust
/// once `spawn()` returned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct ApplySnapshot {
    /// Highest completed stage (`stage::*`).
    pub stage: u8,
    /// Kernel-reported Landlock level (`landlock_level::*`); meaningful
    /// only when `stage >= stage::LANDLOCK`.
    pub landlock: u8,
    /// Kernel Landlock ABI in effect (0 = unknown / not reached).
    pub landlock_abi: u8,
    /// Stage that returned `Err` to `pre_exec` (0 = none recorded).
    pub failed_stage: u8,
    /// Raw errno of `failed_stage` (0 = none recorded).
    pub errno: i32,
}

impl ApplySnapshot {
    /// `prctl(PR_SET_NO_NEW_PRIVS)` completed in the child.
    #[cfg(test)]
    pub fn no_new_privs_applied(&self) -> bool {
        self.stage >= stage::NO_NEW_PRIVS
    }

    /// The Landlock stage completed (a status was recorded; see
    /// `landlock` for *which* result the kernel reported).
    #[cfg(test)]
    pub fn landlock_completed(&self) -> bool {
        self.stage >= stage::LANDLOCK
    }

    /// The seccomp program was installed in the child.
    #[cfg(test)]
    pub fn seccomp_applied(&self) -> bool {
        self.stage >= stage::SECCOMP
    }
}

// Child-side record writes: single atomic stores, no allocation, no
// syscall, no lock — safe between fork and exec and still writable after
// the seccomp filter is installed.

fn record_complete(rec: Option<&ApplyRecordPage>, stage: u8) {
    if let Some(p) = rec {
        p.stage.store(stage, Ordering::Release);
    }
}

fn record_landlock(rec: Option<&ApplyRecordPage>, level: u8, abi: u8) {
    if let Some(p) = rec {
        p.landlock_abi.store(abi, Ordering::Relaxed);
        p.landlock.store(level, Ordering::Relaxed);
    }
}

fn record_fail(rec: Option<&ApplyRecordPage>, stage: u8, e: &std::io::Error) {
    if let Some(p) = rec {
        p.errno
            .store(e.raw_os_error().unwrap_or(libc::EIO), Ordering::Relaxed);
        p.failed_stage.store(stage, Ordering::Release);
    }
}

/// `RulesetStatus` → [`landlock_level`] code.
fn landlock_level_of(status: &RestrictionStatus) -> u8 {
    match status.ruleset {
        RulesetStatus::FullyEnforced => landlock_level::FULL,
        RulesetStatus::PartiallyEnforced => landlock_level::PARTIAL,
        RulesetStatus::NotEnforced => landlock_level::NOT_ENFORCED,
    }
}

/// The kernel's effective Landlock ABI (`status.landlock`), or 0 when
/// Landlock is not available on the running kernel.
fn landlock_abi_of(status: &RestrictionStatus) -> u8 {
    match status.landlock {
        LandlockStatus::Available { effective_abi, .. } => effective_abi as u8,
        _ => 0,
    }
}

// ---------------------------------------------------------------------------
// Sandbox artifacts
// ---------------------------------------------------------------------------

/// Sandbox artifacts compiled in the parent (pre-fork) for a single spawn.
pub(super) struct LinuxSandboxBits {
    landlock_ruleset: Option<RulesetCreated>,
    seccomp_program: BpfProgram,
    /// `sandbox.allow_degraded` — the child applies it; the report reads
    /// the kernel-reported level, so the enforcement-level observation
    /// stays honest regardless of this flag.
    allow_degraded: bool,
    /// Grant entries produced by the same rule build that produced
    /// `landlock_ruleset`/`seccomp_program` — the launch report reads
    /// these so it never recomputes a separate permission table.
    pub(super) grants: Vec<ProcessGrant>,
    /// Address of the shared apply-record page, or 0 when the parent has
    /// no record for this spawn. Copied into the `pre_exec` closure; the
    /// page itself stays owned by the parent-side [`SharedApplyRecord`].
    record_ptr: usize,
}

/// Parent-side preparation, in fixed order:
/// `require_execve_allowance` → `create_landlock_ruleset` → seccomp compile
/// (`compile_seccomp` when the policy already allows execve, otherwise
/// `compile_seccomp_for_spawn`). `allow_degraded` is captured for the child.
pub(super) fn prepare_linux_child_sandbox(
    policy: &Policy,
) -> Result<LinuxSandboxBits, WardenError> {
    seccomp_impl::require_execve_allowance(policy)?;
    let landlock = landlock_impl::create_landlock_ruleset(policy)?;
    let allows_execve = seccomp_impl::policy_allows_execve(policy);
    let seccomp_program = if allows_execve {
        seccomp_impl::compile_seccomp(policy)?
    } else {
        seccomp_impl::compile_seccomp_for_spawn(policy)?
    };
    let mut grants = landlock.grants;
    grants.extend(seccomp_impl::syscall_grant_intents(policy, !allows_execve));
    Ok(LinuxSandboxBits {
        landlock_ruleset: Some(landlock.ruleset),
        seccomp_program,
        allow_degraded: policy.sandbox.allow_degraded,
        grants,
        record_ptr: 0,
    })
}

impl LinuxSandboxBits {
    /// Child-side `pre_exec` body. Order is fixed:
    /// 1. `set_no_new_privs` (prctl; failure aborts the spawn)
    /// 2. Landlock `restrict_self` + the `allow_degraded` gate
    /// 3. `apply_seccomp_program`
    ///
    /// After each step the outcome is stored into the shared record page
    /// (`record_ptr`, when nonzero). A stage that fails stores its errno
    /// into `failed_stage` before the error aborts the spawn.
    ///
    /// No heap allocation may happen here: post-fork the allocator lock can
    /// be held by another thread. The helpers therefore return `io::Error`
    /// built from raw errnos (no formatted messages), so the real errno
    /// reaches the spawn error on every failure path — fail-closed behavior
    /// is unchanged.
    fn apply_in_child(&mut self) -> std::io::Result<()> {
        // Safety: `record_ptr` is 0 or points at the parent's shared page,
        // which stays mapped until `spawn()` has returned in the parent.
        let rec = unsafe { (self.record_ptr as *const ApplyRecordPage).as_ref() };

        if let Err(e) = seccomp_impl::set_no_new_privs() {
            record_fail(rec, stage::NO_NEW_PRIVS, &e);
            return Err(e);
        }
        record_complete(rec, stage::NO_NEW_PRIVS);

        match self.landlock_ruleset.take() {
            Some(rs) => match landlock_impl::restrict_self_observed(rs) {
                Ok(status) => {
                    record_landlock(rec, landlock_level_of(&status), landlock_abi_of(&status));
                    if let Err(e) = landlock_impl::enforcement_gate(&status, self.allow_degraded) {
                        record_fail(rec, stage::LANDLOCK, &e);
                        return Err(e);
                    }
                    record_complete(rec, stage::LANDLOCK);
                }
                Err(e) => {
                    record_fail(rec, stage::LANDLOCK, &e);
                    return Err(e);
                }
            },
            // Defensive arm: `prepare_linux_child_sandbox` currently
            // always installs a ruleset, so `None` is unreachable today.
            // Kept so a future "policy without Landlock" path records a
            // truthful no-op instead of silently skipping the stage.
            None => {
                record_landlock(rec, landlock_level::NO_RULESET, 0);
                record_complete(rec, stage::LANDLOCK);
            }
        }

        if let Err(e) = seccomp_impl::apply_seccomp_program(&self.seccomp_program) {
            record_fail(rec, stage::SECCOMP, &e);
            return Err(e);
        }
        record_complete(rec, stage::SECCOMP);
        Ok(())
    }
}

/// Attach the child-sandbox `pre_exec` to a synchronous command.
///
/// Child-side order is fixed by [`LinuxSandboxBits::apply_in_child`]:
/// `no_new_privs` → Landlock → seccomp.
///
/// Returns the parent side of the shared apply record (`None` when the
/// page could not be mapped). Keep it alive until after `spawn()` returns,
/// then read [`SharedApplyRecord::snapshot`].
pub(super) fn attach_linux_pre_exec(
    cmd: &mut std::process::Command,
    mut bits: LinuxSandboxBits,
) -> Option<SharedApplyRecord> {
    use std::os::unix::process::CommandExt;
    let record = SharedApplyRecord::map();
    bits.record_ptr = record.as_ref().map_or(0, SharedApplyRecord::child_ptr);
    // Safety: the closure only invokes prctl / Landlock / seccomp apply on
    // pre-built artifacts and stores into the shared record page; no heap
    // allocation happens after fork. The page outlives the call: the
    // returned guard is dropped only after spawn() has returned.
    unsafe {
        cmd.pre_exec(move || bits.apply_in_child());
    }
    record
}

/// Attach the child-sandbox `pre_exec` to a tokio command (async spawn).
///
/// Child-side order is fixed by [`LinuxSandboxBits::apply_in_child`]:
/// `no_new_privs` → Landlock → seccomp. Returns the parent side of the
/// shared apply record — see [`attach_linux_pre_exec`].
pub(super) fn attach_linux_pre_exec_tokio(
    cmd: &mut tokio::process::Command,
    mut bits: LinuxSandboxBits,
) -> Option<SharedApplyRecord> {
    let record = SharedApplyRecord::map();
    bits.record_ptr = record.as_ref().map_or(0, SharedApplyRecord::child_ptr);
    // Safety: same contract as `attach_linux_pre_exec`.
    unsafe {
        cmd.pre_exec(move || bits.apply_in_child());
    }
    record
}

#[cfg(test)]
mod tests {
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
                        landlock_level::FULL
                            | landlock_level::PARTIAL
                            | landlock_level::NOT_ENFORCED
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
}
