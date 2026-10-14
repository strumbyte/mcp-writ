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
    /// The PR-07 user-notification stage passed — the connect filter
    /// was installed and its listener fd handed to the parent, or the
    /// stage was disabled and is a recorded no-op pass-through. It runs
    /// before the policy filter because the install/handoff needs
    /// `seccomp(2)`/`sendmsg(2)`, syscalls the policy may not allow.
    pub const UNOTIFY: u8 = 3;
    /// The PR-10 cgroup-move stage passed — the child wrote its pid to
    /// the private cgroup's `cgroup.procs`, so the attached
    /// `INET4/6_CONNECT` programs see its connects from exec onward. A
    /// recorded pass-through when the opt-in route is not enabled. Runs
    /// after UNOTIFY and before the policy filter: `write(2)` to an
    /// already-open fd is not path-mediated, so Landlock cannot deny it,
    /// and it must land before the policy seccomp filter could restrict
    /// `write(2)` anyway.
    pub const CGROUP: u8 = 4;
    /// The privilege-split stage passed — the workload's final
    /// credentials were installed (supplementary groups cleared, ids
    /// demoted, every capability set purged) and verified, or a
    /// recorded pass-through when the route does not demote. Runs
    /// *after* the cgroup join — that write needs the setup
    /// credentials — and *before* the policy filter, which may deny
    /// `setgroups(2)`/`setgid(2)`/`setuid(2)`/`capset(2)`/`prctl(2)`
    /// outright.
    pub const DEMOTE: u8 = 5;
    /// The seccomp program was installed — the whole pipeline ran.
    pub const SECCOMP: u8 = 6;
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
        let len = size_of::<ApplyRecordPage>();
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
    /// PR-07 opt-in: the seccomp user-notification filter the child
    /// installs between Landlock and the policy filter — `None` on every
    /// ordinary spawn, `Some` only through [`unotify::enable_unotify`]
    /// (the `unotify-run` PoC path).
    pub(super) unotify: Option<super::unotify::UnotifyChild>,
    /// PR-10 opt-in: a pre-opened `cgroup.procs` write fd for the
    /// private cgroup the workload must join before exec — `Some` only
    /// through [`ebpf::spawn_supervised`](crate::warden::ebpf::spawn_supervised).
    pub(super) cgroup_procs: Option<std::fs::File>,
    /// fd-exec handoff: the pin's `F_DUPFD_CLOEXEC` descriptor numbers.
    /// The child clears `FD_CLOEXEC` here so the `/proc/self/fd` exec
    /// spellings resolve through `execve`; in the parent the dups stay
    /// cloexec so concurrent sibling spawns cannot inherit them.
    pub(super) exec_uncloak_fds: Vec<std::os::fd::RawFd>,
    /// PR-10 privilege split: the final workload credentials the child
    /// installs between the cgroup join and the policy filter — `Some`
    /// only on routes whose setup needs privilege the untrusted image
    /// must never inherit (`ebpf-run`).
    pub(super) demote: Option<CredDrop>,
}

/// Workload credential plan for the DEMOTE stage. Setup stages run
/// with the launcher's credentials; the demote stage installs these
/// before exec so the untrusted image never inherits setup privilege.
///
/// `full` selects the two flavors:
/// - `true` — the launcher is root: purge every capability set while
///   the privileges to do so still exist (ambient clear → bounding
///   drop → inheritable clear via `capset`), clear supplementary
///   groups, drop gid then uid, and verify all ids plus an empty group
///   list afterwards.
/// - `false` — the launcher was never privileged: the target ids are
///   its own; only ambient capabilities (the one set a setcap'd binary
///   can hand through `execve`) are stripped and the ids re-verified.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CredDrop {
    /// Final real+effective+saved uid.
    pub uid: libc::uid_t,
    /// Final real+effective+saved gid.
    pub gid: libc::gid_t,
    /// Root-launcher demotion vs. ambient-capability strip — see above.
    pub full: bool,
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
    grants.extend(seccomp_impl::syscall_grant_intents(
        policy,
        !allows_execve,
        false,
    ));
    Ok(LinuxSandboxBits {
        landlock_ruleset: Some(landlock.ruleset),
        seccomp_program,
        allow_degraded: policy.sandbox.allow_degraded,
        grants,
        record_ptr: 0,
        unotify: None,
        cgroup_procs: None,
        exec_uncloak_fds: Vec::new(),
        demote: None,
    })
}

/// Write the child's pid to `fd` (an open `cgroup.procs`) — no
/// allocation, `write(2)` only; `pre_exec`-safe.
fn write_self_pid(fd: std::os::unix::io::RawFd) -> std::io::Result<()> {
    // Safety: getpid has no failure mode.
    let mut pid = unsafe { libc::getpid() } as u64;
    let mut buf = [0u8; 20];
    let mut i = buf.len();
    loop {
        i -= 1;
        buf[i] = b'0' + (pid % 10) as u8;
        pid /= 10;
        if pid == 0 {
            break;
        }
    }
    let s = &buf[i..];
    // Safety: `s` is live stack memory; `fd` is a live write fd.
    let rc = unsafe { libc::write(fd, s.as_ptr().cast::<libc::c_void>(), s.len()) };
    if rc < 0 {
        return Err(std::io::Error::last_os_error());
    }
    if rc as usize != s.len() {
        return Err(std::io::Error::from_raw_os_error(libc::EIO));
    }
    Ok(())
}

/// DEMOTE stage — install `drop` as the workload's final credentials.
/// Child-side: raw libc only, no allocation.
///
/// Call order is privilege-driven: the bounding/inheritable/group
/// operations need `CAP_SETPCAP`/`CAP_SETGID`, which are gone the
/// moment `capset`/`setuid` run — so capabilities are *modified* while
/// still held and *cleared* by the uid change itself (POSIX clears
/// permitted+effective on a 0→nonzero `setuid`).
fn apply_cred_drop(drop: &CredDrop) -> std::io::Result<()> {
    const PR_CAP_AMBIENT_CLEAR_ALL: u64 = 4;
    // Bounding-drop range: kernel caps beyond `CAP_LAST_CAP` answer
    // EINVAL — there is nothing to drop at an unknown id.
    const CAP_MAX_BOUND: i32 = 40;
    let last_error = std::io::Error::last_os_error;
    let eio = || std::io::Error::from_raw_os_error(libc::EIO);

    if drop.full {
        // Ambient first: EINVAL means pre-4.3 kernel — the set cannot
        // exist there, so nothing is left to clear.
        // Safety: prctl with a literal command and no pointers.
        if unsafe { libc::prctl(libc::PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0) } != 0 {
            let e = last_error();
            if e.raw_os_error() != Some(libc::EINVAL) {
                return Err(e);
            }
        }
        // Bounding set, while CAP_SETPCAP is still effective.
        for cap in 0..=CAP_MAX_BOUND {
            // Safety: prctl with a literal command and no pointers.
            if unsafe { libc::prctl(libc::PR_CAPBSET_DROP, cap, 0, 0, 0) } != 0 {
                let e = last_error();
                if e.raw_os_error() != Some(libc::EINVAL) {
                    return Err(e);
                }
            }
        }
        // Inheritable only — permitted/effective stay populated so the
        // remaining demote syscalls still pass their capability checks;
        // the `setuid` below clears both for real. (libc does not export
        // the capget/capset payload types — they are stable uapi.)
        const LINUX_CAPABILITY_VERSION_3: u32 = 0x2008_0522;
        #[repr(C)]
        struct CapUserHeader {
            version: u32,
            pid: i32,
        }
        #[repr(C)]
        #[derive(Clone, Copy)]
        struct CapUserData {
            effective: u32,
            permitted: u32,
            inheritable: u32,
        }
        // Safety: zeroed is a valid all-zero capability payload.
        let header = CapUserHeader {
            version: LINUX_CAPABILITY_VERSION_3,
            pid: 0,
        };
        let mut data: [CapUserData; 2] = unsafe { std::mem::zeroed() };
        // Safety: valid stack pointers; SYS_capget fills `data`.
        if unsafe { libc::syscall(libc::SYS_capget, &header, data.as_mut_ptr()) } != 0 {
            return Err(last_error());
        }
        for d in &mut data {
            d.inheritable = 0;
        }
        // Safety: valid stack pointers; SYS_capset semantics.
        if unsafe { libc::syscall(libc::SYS_capset, &header, data.as_ptr()) } != 0 {
            return Err(last_error());
        }
        // Supplementary groups — needs CAP_SETGID, still held.
        // Safety: null list + 0 count is the documented clear call.
        if unsafe { libc::setgroups(0, std::ptr::null()) } != 0 {
            return Err(last_error());
        }
        // gid before uid — a root uid may still setgid without CAP_SETGID
        // only while it *is* root; drop the group first, then the uid.
        // Safety: plain setgid/setuid.
        if unsafe { libc::setgid(drop.gid) } != 0 {
            return Err(last_error());
        }
        if unsafe { libc::setuid(drop.uid) } != 0 {
            return Err(last_error());
        }
    } else {
        // Ambient is the only set an unprivileged launcher can hand
        // execve — strip it; everything else the kernel recomputes.
        if unsafe { libc::prctl(libc::PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0) } != 0 {
            let e = last_error();
            if e.raw_os_error() != Some(libc::EINVAL) {
                return Err(e);
            }
        }
    }

    // Prove the final credentials — a demotion that cannot be shown is
    // a spawn failure, not a tolerated degrade.
    // Safety: the get*id/getgroups calls cannot fail.
    let ok = unsafe {
        libc::getuid() == drop.uid
            && libc::geteuid() == drop.uid
            && libc::getgid() == drop.gid
            && libc::getegid() == drop.gid
            && (!drop.full || libc::getgroups(0, std::ptr::null_mut()) == 0)
    };
    if !ok {
        return Err(eio());
    }
    Ok(())
}

/// PR-10 variant for `ebpf-run`: same bits except the Landlock ruleset
/// handles no net access — the cgroup `INET4/6_CONNECT` programs own
/// connect verdicts on this route and must see denied connects to emit
/// their ring-buffer events (a Landlock `socket_connect` denial would
/// fire first and hide them). Filesystem enforcement is unchanged.
pub(super) fn prepare_linux_child_sandbox_ebpf(
    policy: &Policy,
) -> Result<LinuxSandboxBits, WardenError> {
    seccomp_impl::require_execve_allowance(policy)?;
    let landlock = landlock_impl::create_landlock_ruleset_ebpf(policy)?;
    let allows_execve = seccomp_impl::policy_allows_execve(policy);
    let seccomp_program = if allows_execve {
        seccomp_impl::compile_seccomp(policy)?
    } else {
        seccomp_impl::compile_seccomp_for_spawn(policy)?
    };
    let mut grants = landlock.grants;
    grants.extend(seccomp_impl::syscall_grant_intents(
        policy,
        !allows_execve,
        false,
    ));
    Ok(LinuxSandboxBits {
        landlock_ruleset: Some(landlock.ruleset),
        seccomp_program,
        // F44: `sandbox.allow_degraded` does not cover this route.
        // Landlock is the control that keeps the workload from opening
        // a parent or sibling `cgroup.procs` and migrating out of the
        // enforced cgroup — a partial or absent ruleset would silently
        // remove it, so `ebpf-run` requires `FullyEnforced`.
        allow_degraded: false,
        grants,
        record_ptr: 0,
        unotify: None,
        cgroup_procs: None,
        exec_uncloak_fds: Vec::new(),
        demote: None,
    })
}

/// PR-09 variant for `namespaced-init`: same bits except the seccomp
/// socket-family narrowing — inside the dedicated netns every socket
/// type dead-ends at the TUN the parent holds, and the UDP proxy path
/// needs datagram sockets to exist at all. Landlock keeps the
/// `ConnectTcp` port narrowing only when the collected ports are
/// exactly the policy's TCP allow surface (every TCP allow carries a
/// port); otherwise the netport handling is dropped rather than
/// widened and the proxy is the TCP layer. The syscall grant reasons
/// record the relaxed state.
pub(super) fn prepare_linux_child_sandbox_namespaced(
    policy: &Policy,
) -> Result<LinuxSandboxBits, WardenError> {
    seccomp_impl::require_execve_allowance(policy)?;
    let landlock = landlock_impl::create_landlock_ruleset_namespaced(policy)?;
    let allows_execve = seccomp_impl::policy_allows_execve(policy);
    let seccomp_program = if allows_execve {
        seccomp_impl::compile_seccomp_inner_namespaced(policy, false)?
    } else {
        seccomp_impl::compile_seccomp_inner_namespaced(policy, true)?
    };
    let mut grants = landlock.grants;
    grants.extend(seccomp_impl::syscall_grant_intents(
        policy,
        !allows_execve,
        true,
    ));
    Ok(LinuxSandboxBits {
        landlock_ruleset: Some(landlock.ruleset),
        seccomp_program,
        allow_degraded: policy.sandbox.allow_degraded,
        grants,
        record_ptr: 0,
        unotify: None,
        cgroup_procs: None,
        exec_uncloak_fds: Vec::new(),
        demote: None,
    })
}

impl LinuxSandboxBits {
    /// Child-side `pre_exec` body. Order is fixed:
    /// 1. `set_no_new_privs` (prctl; failure aborts the spawn)
    /// 2. Landlock `restrict_self` + the `allow_degraded` gate
    /// 3. PR-07 unotify filter + listener-fd handoff (opt-in; a
    ///    recorded pass-through when disabled — the stage numbering
    ///    stays monotonic either way)
    /// 4. PR-10 cgroup join (opt-in; a recorded pass-through when the
    ///    route is not enabled — same monotonicity contract)
    /// 5. PR-10 privilege split (opt-in; a recorded pass-through when
    ///    the route does not demote — same monotonicity contract)
    /// 6. `apply_seccomp_program`
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
    ///
    /// `pub(super)`: the PR-09 `namespaced-init` helper applies the same
    /// bits inside its own (re-exec'd) process, not a `pre_exec` hook —
    /// the sequence and semantics are identical.
    pub(super) fn apply_in_child(&mut self) -> std::io::Result<()> {
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

        // PR-07 opt-in: install the connect-notification filter while
        // the child can still call `seccomp(2)`/`sendmsg(2)`/`close(2)`
        // (the policy filter below may not allow them). Recorded either
        // way so the stage monotonicity holds for the ordinary path too.
        if let Some(unotify) = &self.unotify
            && let Err(e) = unotify.apply()
        {
            record_fail(rec, stage::UNOTIFY, &e);
            return Err(e);
        }
        record_complete(rec, stage::UNOTIFY);

        // PR-10 opt-in: join the private cgroup before exec so the
        // attached INET4/6_CONNECT programs govern every connect this
        // process (and its descendants — cgroup membership inherits)
        // makes. Recorded either way.
        use std::os::unix::io::AsRawFd;
        if let Some(procs) = &self.cgroup_procs
            && let Err(e) = write_self_pid(procs.as_raw_fd())
        {
            record_fail(rec, stage::CGROUP, &e);
            return Err(e);
        }
        record_complete(rec, stage::CGROUP);

        // PR-10 privilege split: install the workload's final
        // credentials *after* the privileged cgroup join and *before*
        // the policy filter — demotion that cannot be proven aborts
        // the spawn, never a degrade.
        if let Some(demote) = &self.demote
            && let Err(e) = apply_cred_drop(demote)
        {
            record_fail(rec, stage::DEMOTE, &e);
            return Err(e);
        }
        record_complete(rec, stage::DEMOTE);

        // fd-exec handoff: uncloak the pin's dup'd descriptors so their
        // `/proc/self/fd` spellings survive the `execve` — done inside
        // the SECCOMP stage so the policy filter installed next cannot
        // have denied `fcntl(2)` yet. Failure aborts like any apply
        // stage (a CLOEXEC fd path would fail exec anyway).
        if !self.exec_uncloak_fds.is_empty()
            && let Err(e) = super::uncloak_exec_fds(&self.exec_uncloak_fds)
        {
            record_fail(rec, stage::SECCOMP, &e);
            return Err(e);
        }

        // Ambient-fd seal: an inherited non-CLOEXEC descriptor is a
        // capability the path rules never mediated — the workload must
        // not start holding the launcher's pipes, sockets, or memfds.
        // Sealing (FD_CLOEXEC) not closing: the runtime's spawn-error
        // pipe lives in this same fd table and must stay writable until
        // `execve`. Runs here, after the stage fds are consumed and
        // before the policy filter can deny `getdents64`/`fcntl`.
        if let Err(e) = seal_ambient_fds(&self.exec_uncloak_fds) {
            record_fail(rec, stage::SECCOMP, &e);
            return Err(e);
        }

        if let Err(e) = seccomp_impl::apply_seccomp_program(&self.seccomp_program) {
            record_fail(rec, stage::SECCOMP, &e);
            return Err(e);
        }
        record_complete(rec, stage::SECCOMP);
        Ok(())
    }
}

/// Seal every fd above stderr except `keep` — set `FD_CLOEXEC` on each,
/// so `execve` drops them atomically — via a raw `getdents64` walk of
/// `/proc/self/fd` into a stack buffer. Allocation-free in `pre_exec`
/// and reads the child's *actual* fd table.
///
/// Sealing instead of `close(2)` is load-bearing: the runtime's
/// spawn-error pipe is a live CLOEXEC descriptor in this same table —
/// `close`ing it would break both the parent's "EOF means exec
/// reached" synchronization and errno reporting for every later stage
/// failure. `F_SETFD` leaves the pipe (already CLOEXEC) functional and
/// is idempotent on every other slot; the sealed fds die at `execve`
/// just as a `close` would, so the workload still inherits nothing
/// beyond stdio and `keep`. An un-readable table aborts the launch:
/// fds that cannot be inspected cannot be proven sealed.
fn seal_ambient_fds(keep: &[libc::c_int]) -> std::io::Result<()> {
    // Safety: `open(2)` on a C-string literal; returns -1 on error.
    let dirfd = unsafe {
        libc::open(
            b"/proc/self/fd\0".as_ptr().cast(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if dirfd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let mut buf = [0u8; 4096];
    loop {
        // Safety: getdents64 writes at most `buf.len()` bytes into
        // valid stack storage. linux_dirent64 layout: u64 ino,
        // i64 offset, u16 reclen, u8 d_type, then NUL-terminated name.
        let n = unsafe { libc::syscall(libc::SYS_getdents64, dirfd, buf.as_mut_ptr(), buf.len()) };
        if n < 0 {
            let e = std::io::Error::last_os_error();
            unsafe { libc::close(dirfd) };
            return Err(e);
        }
        if n == 0 {
            break;
        }
        let mut off = 0usize;
        while off + 19 <= n as usize {
            let reclen = u16::from_ne_bytes([buf[off + 16], buf[off + 17]]) as usize;
            if reclen < 19 || off + reclen > n as usize {
                break;
            }
            // d_name starts at off+19, NUL-terminated within reclen.
            let name = &buf[off + 19..off + reclen];
            let mut fd: libc::c_int = 0;
            let mut numeric = true;
            for &b in name {
                if b == 0 {
                    break;
                }
                if !b.is_ascii_digit() {
                    numeric = false;
                    break;
                }
                fd = fd.saturating_mul(10).saturating_add((b - b'0') as i32);
            }
            if numeric && fd > 2 && fd != dirfd && !keep.contains(&fd) {
                // Safety: F_SETFD only touches the descriptor's
                // close-on-exec flag — the fd stays live for anything
                // the spawn machinery still needs until execve.
                unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) };
            }
            off += reclen;
        }
    }
    unsafe { libc::close(dirfd) };
    Ok(())
}

/// Attach the child-sandbox `pre_exec` to a synchronous command.
///
/// Child-side order is fixed by [`LinuxSandboxBits::apply_in_child`]:
/// `no_new_privs` → Landlock → seccomp.
///
/// Returns the parent side of the shared apply record (`None` when the
/// page could not be mapped). Keep it alive until after `spawn()` returns,
/// then read [`SharedApplyRecord::snapshot`].
#[must_use = "the apply record must stay alive until spawn() returns — \
              dropping it early unmaps the page the child writes to"]
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
#[must_use = "the apply record must stay alive until spawn() returns — \
              dropping it early unmaps the page the child writes to"]
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
        unsafe {
            let mut p = [0i32; 2];
            assert_eq!(libc::pipe(p.as_mut_ptr()), 0);
            let pid = libc::fork();
            assert!(pid >= 0, "fork failed");
            if pid == 0 {
                libc::close(p[0]);
                let r = seal_ambient_fds(&[p[1]]);
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
}
