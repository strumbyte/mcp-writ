//! Linux IP-layer PoC — a seccomp user-notification supervisor for
//! `connect(2)` (improvement plan PR-07).
//!
//! An opted-in launch (`mcp-writ unotify-run …`) runs the ordinary Linux
//! sandbox pipeline in the child's `pre_exec` — `no_new_privs` →
//! Landlock → *this module's notification filter* → the policy seccomp
//! program — with the notification stage inserted before the policy
//! filter on purpose: installing it needs `seccomp(2)` plus
//! `sendmsg(2)`/`close(2)` for the listener-fd handoff, syscalls the
//! policy allowlist may not grant the workload. Return-action
//! precedence is fixed by the kernel regardless of install order
//! (`ERRNO` still beats `USER_NOTIF`, `USER_NOTIF` beats `ALLOW`), so
//! the insertion changes nothing about which verdict a syscall gets.
//!
//! The child installs a filter that returns `SECCOMP_RET_USER_NOTIF`
//! for `connect`, `SECCOMP_RET_ALLOW` for everything else on the
//! native architecture, and `SECCOMP_RET_KILL_PROCESS` for a foreign
//! arch or an x32-ABI syscall number (both carry a syscall table this
//! filter's numbers do not line up with — an x32 task even reports the
//! native `arch` word, so the `nr >= 0x4000_0000` bound is what closes
//! that hole; killing it is the fail-closed answer). The kernel
//! hands the filter's listener fd to the child; the child passes it to
//! the supervisor over an `SCM_RIGHTS` socketpair before `exec`, and the
//! parent polls that fd.
//!
//! For each notification the supervisor:
//!
//! 1. reads the child's `sockaddr` with `process_vm_readv` (the
//!    documented alternative `/proc/<pid>/mem` needs the same
//!    ptrace-read capability; the PoC uses `process_vm_readv` only),
//! 2. revalidates the notification id
//!    (`SECCOMP_IOCTL_NOTIF_ID_VALID` — checked after the memory read
//!    so a task that died mid-handling is never answered or audited;
//!    a dead id means the triggering task was killed and needs no
//!    answer),
//! 3. decodes IPv4/IPv6 destination + port (a non-`AF_INET`/`AF_INET6`
//!    family is *not* an IP destination — it is continued unsupervised
//!    and counted, see
//!    [`LIMITATIONS`](crate::warden::unotify::LIMITATIONS)),
//! 4. detects the socket's `SOCK_STREAM`/`SOCK_DGRAM` type through
//!    `pidfd_open` + `pidfd_getfd` + `getsockopt(SO_TYPE)` for the
//!    audit `proto` field (`"unknown"` when the fd cannot be resolved),
//! 5. evaluates the destination against the policy's IP-layer rules
//!    ([`IpLayerEvaluator`](crate::warden::unotify::IpLayerEvaluator))
//!    and the TTL-scoped dynamic grants
//!    ([`GrantSource`](crate::warden::unotify::GrantSource)),
//! 6. answers `SECCOMP_USER_NOTIF_FLAG_CONTINUE` for an allowed
//!    connect (kernel ≥ 5.5 — the syscall then runs exactly once,
//!    still through every other installed filter) after emitting a
//!    buffered `sandbox.network_allowed`, or an `EACCES` error for a
//!    denied one after committing `sandbox.network_denied` through the
//!    launch's fail-closed audit path.
//!
//! Fail-closed contract:
//!
//! - `check_support` refuses at startup when the kernel lacks user
//!   notification / `CONTINUE` — never silently degrades, regardless of
//!   `sandbox.allow_degraded` (that dial covers *Landlock* level, not
//!   this feature).
//! - Listener install or fd handoff failure aborts the spawn
//!   (`SandboxStage::Apply`/`ProcessSpawn`), not a degraded run.
//! - Supervisor death fails closed at the kernel itself: a released
//!   listener fd makes pending and future `connect` calls return
//!   `ENOSYS`; the command additionally kills the supervised child.
//! - A fail-closed audit sink that has failed flips *allowed* connects
//!   to denied — protected traffic never passes unaudited. Allowed
//!   connects are themselves recorded (`sandbox.network_allowed`,
//!   buffered like the dns-gate's allow-side records).
//! - The `sockaddr` read is a TOCTOU window: the child may rewrite the
//!   buffer between inspection and use — see
//!   [`LIMITATIONS`](crate::warden::unotify::LIMITATIONS).
//!
//! `connect` needs to be present in `syscalls.allowed` for this layer
//! to ever see it: a policy filter that denies `connect` at `ERRNO`
//! wins over the notification (the deny stays denied — it is enforced
//! one layer lower, just unaudited here).

mod evaluate;
mod filter;
mod grants;
mod handoff;
mod inspect;
mod notif;
mod probe;
mod report;
mod spawn;
mod supervisor;
#[cfg(test)]
mod tests;

pub use evaluate::{IpLayerEvaluator, IpVerdict};
pub use grants::GrantSource;
pub(crate) use grants::{SnapshotGrant, load_snapshot};
pub use probe::check_support;
pub use report::{LIMITATIONS, ip_layer_status, report_json};
pub use spawn::{SupervisedSpawn, spawn_supervised};
pub use supervisor::{
    Supervisor, SupervisorConfig, SupervisorEnd, SupervisorExit, SupervisorStats,
};

// The child-side half `linux_spawn` stores on `LinuxSandboxBits`.
pub(crate) use handoff::UnotifyChild;
