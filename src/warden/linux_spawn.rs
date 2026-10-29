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

use super::{cgroup, landlock_impl, seccomp_impl};

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
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
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
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
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
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
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
    /// `sandbox.require_lifetime_boundary` — tightens the LANDLOCK
    /// stage: the armed cgroup is a descendant boundary only while the
    /// member's own `cgroup.procs` writes are restrained, so anything
    /// short of `FullyEnforced` aborts the spawn even when
    /// `allow_degraded` would otherwise tolerate the gap.
    require_lifetime_boundary: bool,
    /// Grant entries produced by the same rule build that produced
    /// `landlock_ruleset`/`seccomp_program` — the launch report reads
    /// these so it never recomputes a separate permission table.
    pub(super) grants: Vec<ProcessGrant>,
    /// The rights the Landlock ruleset *requested* (`fs=… net=…
    /// scope=…`) — the kernel's `FullyEnforced` verdict says only that
    /// the request landed, so the report names the request itself.
    pub(super) requested_rights: String,
    /// Address of the shared apply-record page, or 0 when the parent has
    /// no record for this spawn. Copied into the `pre_exec` closure; the
    /// page itself stays owned by the parent-side [`SharedApplyRecord`].
    record_ptr: usize,
    /// PR-07 opt-in: the seccomp user-notification filter the child
    /// installs between Landlock and the policy filter — `None` on every
    /// ordinary spawn, `Some` only through [`unotify::enable_unotify`]
    /// (the `unotify-run` PoC path).
    pub(super) unotify: Option<super::unotify::UnotifyChild>,
    /// A pre-opened `cgroup.procs` write fd for the private cgroup the
    /// workload must join before exec — `Some` through
    /// [`ebpf::spawn_supervised`](crate::warden::ebpf::spawn_supervised)
    /// (mandatory: enforcement depends on it) and through the ordinary
    /// launch paths under `sandbox.require_lifetime_boundary` (a failed
    /// join aborts the spawn pre-exec, which is the refusal the flag
    /// asks for).
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
    // `require_lifetime_boundary` needs the fs boundary *enforced*,
    // not merely requested: the private cgroup holds a member only
    // while Landlock restrains its writes to a parent or sibling
    // `cgroup.procs`. A kernel whose ABI cannot take the full handled
    // set (`AccessNet` is claimed at ABI V4, fs at V3) comes back
    // `PartiallyEnforced` — leaving ambient write access and an
    // escapable boundary — so refuse at prepare rather than spawn a
    // child only to tear it down. `allow_degraded` cannot waive this:
    // the flag exists precisely to refuse the gap it tolerates.
    if policy.sandbox.require_lifetime_boundary && landlock_impl::kernel_abi() < 4 {
        return Err(WardenError::sandbox_setup(
            crate::error::SandboxStage::Policy,
            "sandbox.require_lifetime_boundary: the kernel cannot fully \
             enforce the Landlock ruleset (ABI below the handled set, or \
             no Landlock support) — fs writes to a parent or sibling \
             `cgroup.procs` would stay unrestricted, so the private \
             cgroup cannot be a kernel-enforced descendant-lifetime \
             boundary, refusing",
        ));
    }
    // The private cgroup itself must also be creatable: without a
    // mounted v2 hierarchy there is nothing to arm. Refusing here —
    // before the mechanism is selected — lets the launcher fall back
    // to the namespaced route, whose PID namespace satisfies the flag
    // without a cgroup at all.
    if policy.sandbox.require_lifetime_boundary
        && !std::path::Path::new(cgroup::CGROUP_ROOT)
            .join("cgroup.controllers")
            .exists()
    {
        return Err(WardenError::sandbox_setup(
            crate::error::SandboxStage::Policy,
            "sandbox.require_lifetime_boundary: no cgroup v2 hierarchy \
             mounted — the native route cannot arm a private subtree; \
             the namespaced route's PID namespace can still satisfy the \
             boundary",
        ));
    }
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
        require_lifetime_boundary: policy.sandbox.require_lifetime_boundary,
        grants,
        requested_rights: landlock.requested_rights,
        record_ptr: 0,
        unotify: None,
        cgroup_procs: None,
        exec_uncloak_fds: Vec::new(),
        demote: None,
    })
}

/// Write the child's pid to `fd` (an open `cgroup.procs`) — no
/// allocation, `write(2)` only; `pre_exec`-safe. Shared by the bits'
/// CGROUP stage and [`cgroup::LifetimeCgroup::attach_join`].
pub(super) fn write_self_pid(fd: std::os::unix::io::RawFd) -> std::io::Result<()> {
    let mut pid = std::process::id() as u64;
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
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
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
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        if unsafe { libc::prctl(libc::PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0) } != 0 {
            let e = last_error();
            if e.raw_os_error() != Some(libc::EINVAL) {
                return Err(e);
            }
        }
        // Bounding set, while CAP_SETPCAP is still effective.
        for cap in 0..=CAP_MAX_BOUND {
            // Safety: prctl with a literal command and no pointers.
            // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
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
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        let mut data: [CapUserData; 2] = unsafe { std::mem::zeroed() };
        // Safety: valid stack pointers; SYS_capget fills `data`.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        if unsafe { libc::syscall(libc::SYS_capget, &header, data.as_mut_ptr()) } != 0 {
            return Err(last_error());
        }
        for d in &mut data {
            d.inheritable = 0;
        }
        // Safety: valid stack pointers; SYS_capset semantics.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        if unsafe { libc::syscall(libc::SYS_capset, &header, data.as_ptr()) } != 0 {
            return Err(last_error());
        }
        // Supplementary groups — needs CAP_SETGID, still held.
        // Safety: null list + 0 count is the documented clear call.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        if unsafe { libc::setgroups(0, std::ptr::null()) } != 0 {
            return Err(last_error());
        }
        // gid before uid — a root uid may still setgid without CAP_SETGID
        // only while it *is* root; drop the group first, then the uid.
        // Safety: plain setgid/setuid.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        if unsafe { libc::setgid(drop.gid) } != 0 {
            return Err(last_error());
        }
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        if unsafe { libc::setuid(drop.uid) } != 0 {
            return Err(last_error());
        }
    } else {
        // Ambient is the only set an unprivileged launcher can hand
        // execve — strip it; everything else the kernel recomputes.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
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
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
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
        // `allow_degraded: false` above already refuses anything short
        // of `FullyEnforced` — the flag's fs-boundary requirement is
        // this route's standing contract, not an extra gate.
        require_lifetime_boundary: false,
        grants,
        requested_rights: landlock.requested_rights,
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
        // The PID namespace is this route's descendant-lifetime
        // boundary — it holds independently of fs enforcement, so the
        // flag does not tighten the LANDLOCK stage here.
        require_lifetime_boundary: false,
        grants,
        requested_rights: landlock.requested_rights,
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
    /// 2. Landlock `restrict_self` + the `allow_degraded` gate — the
    ///    fd-table dirfd for the stage-6 seal is opened at the top of
    ///    this step, before restriction removes path access
    /// 3. PR-07 unotify filter + listener-fd handoff (opt-in; a
    ///    recorded pass-through when disabled — the stage numbering
    ///    stays monotonic either way)
    /// 4. PR-10 cgroup join (opt-in; a recorded pass-through when the
    ///    route is not enabled — same monotonicity contract)
    /// 5. PR-10 privilege split (opt-in; a recorded pass-through when
    ///    the route does not demote — same monotonicity contract)
    /// 6. fd-exec uncloak + ambient-fd seal + `apply_seccomp_program`
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
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        let rec = unsafe { (self.record_ptr as *const ApplyRecordPage).as_ref() };

        if let Err(e) = seccomp_impl::set_no_new_privs() {
            record_fail(rec, stage::NO_NEW_PRIVS, &e);
            return Err(e);
        }
        record_complete(rec, stage::NO_NEW_PRIVS);

        // Open the fd-table dirfd *before* Landlock `restrict_self`:
        // the ruleset is default-deny and a policy has no reason to
        // grant `/proc`, so an `open(2)` attempted after restriction
        // fails EACCES and aborts every launch. `getdents64` on the
        // already-open dirfd performs no path resolution — Landlock
        // cannot observe it — and `/proc/self/fd` enumerates the table
        // at read time, so descriptors the intervening stages open
        // (the unotify listener, the runtime's spawn pipe) still land
        // in the seal. A failed open aborts under the LANDLOCK label —
        // the stage boundary it precedes.
        let fd_table = match open_fd_table() {
            Ok(fd) => fd,
            Err(e) => {
                record_fail(rec, stage::LANDLOCK, &e);
                return Err(e);
            }
        };

        match self.landlock_ruleset.take() {
            Some(rs) => match landlock_impl::restrict_self_observed(rs) {
                Ok(status) => {
                    record_landlock(rec, landlock_level_of(&status), landlock_abi_of(&status));
                    if let Err(e) = landlock_impl::enforcement_gate(&status, self.allow_degraded) {
                        record_fail(rec, stage::LANDLOCK, &e);
                        return Err(e);
                    }
                    // `require_lifetime_boundary`: the private cgroup
                    // holds a member only while the workload's own
                    // `cgroup.procs` writes are restrained — a degraded
                    // fs restriction leaves ambient write access to a
                    // parent or sibling hierarchy, so the join below
                    // would arm an escapable boundary. The flag refuses
                    // anything short of `FullyEnforced`, independent of
                    // `allow_degraded` (which tolerates exactly this
                    // gap). `ebpf-run` pins this floor unconditionally.
                    if self.require_lifetime_boundary
                        && status.ruleset != RulesetStatus::FullyEnforced
                    {
                        let e = std::io::Error::from_raw_os_error(libc::EACCES);
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
                // No fs boundary at all — under
                // `require_lifetime_boundary` the cgroup join below
                // would arm an escapable boundary, so refuse instead.
                if self.require_lifetime_boundary {
                    let e = std::io::Error::from_raw_os_error(libc::EACCES);
                    record_fail(rec, stage::LANDLOCK, &e);
                    return Err(e);
                }
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
        // before the policy filter can deny `getdents64`/`fcntl`, on
        // the dirfd opened before Landlock — the walk itself performs
        // no path access.
        if let Err(e) = seal_ambient_fds(fd_table, &self.exec_uncloak_fds) {
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

/// Open the child's fd-table directory for the deferred seal walk —
/// `/proc/self/fd` with `O_DIRECTORY|O_CLOEXEC`. Must run before
/// Landlock `restrict_self` (see [`LinuxSandboxBits::apply_in_child`]):
/// afterwards the default-deny ruleset makes the open fail `EACCES`.
/// The returned dirfd needs no further path resolution — `getdents64`
/// on it is outside Landlock's view — and the listing reflects the fd
/// table at read time, so descriptors opened between this call and the
/// seal are still enumerated.
fn open_fd_table() -> std::io::Result<libc::c_int> {
    // Safety: `open(2)` on a C-string literal; returns -1 on error.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    let dirfd = unsafe {
        libc::open(
            c"/proc/self/fd".as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if dirfd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(dirfd)
}

/// Seal every fd above stderr except `keep` — set `FD_CLOEXEC` on each,
/// so `execve` drops them atomically — via a raw `getdents64` walk of
/// the pre-opened fd-table `dirfd` into a stack buffer. Allocation-free
/// in `pre_exec`, performs no path lookup, and reads the child's
/// *actual* fd table — including anything opened after `dirfd` was
/// taken. `dirfd` is closed on every exit, malformed records included.
///
/// Sealing instead of `close(2)` is load-bearing: the runtime's
/// spawn-error pipe is a live CLOEXEC descriptor in this same table —
/// `close`ing it would break both the parent's "EOF means exec
/// reached" synchronization and errno reporting for every later stage
/// failure. `F_SETFD` leaves the pipe (already CLOEXEC) functional and
/// is idempotent on every other slot; the sealed fds die at `execve`
/// just as a `close` would, so the workload still inherits nothing
/// beyond stdio and `keep`. An un-readable or malformed table aborts
/// the launch: fds that cannot be inspected cannot be proven sealed.
fn seal_ambient_fds(dirfd: libc::c_int, keep: &[libc::c_int]) -> std::io::Result<()> {
    let result = seal_ambient_fds_walk(dirfd, keep);
    // Safety: `dirfd` came from `open_fd_table` and is closed exactly
    // once, on whichever path the walk left.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    unsafe { libc::close(dirfd) };
    result
}

fn seal_ambient_fds_walk(dirfd: libc::c_int, keep: &[libc::c_int]) -> std::io::Result<()> {
    let mut buf = [0u8; 4096];
    loop {
        // Safety: getdents64 writes at most `buf.len()` bytes into
        // valid stack storage. linux_dirent64 layout: u64 ino,
        // i64 offset, u16 reclen, u8 d_type, then NUL-terminated name.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        let n = unsafe { libc::syscall(libc::SYS_getdents64, dirfd, buf.as_mut_ptr(), buf.len()) };
        if n < 0 {
            return Err(std::io::Error::last_os_error());
        }
        if n == 0 {
            return Ok(());
        }
        let mut off = 0usize;
        while off + 19 <= n as usize {
            let reclen = u16::from_ne_bytes([buf[off + 16], buf[off + 17]]) as usize;
            if reclen < 19 || off + reclen > n as usize {
                // A record that cannot be parsed leaves a tail of
                // uninspected fds — uninspected means unproven, so the
                // launch aborts rather than sealing a subset.
                return Err(std::io::Error::from_raw_os_error(libc::EIO));
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
                // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
                unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) };
            }
            off += reclen;
        }
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
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
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
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    unsafe {
        cmd.pre_exec(move || bits.apply_in_child());
    }
    record
}

#[cfg(test)]
mod tests;
