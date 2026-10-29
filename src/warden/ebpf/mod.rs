//! Linux IP-layer enforcement via cgroup eBPF — the opt-in PR-10 route
//! (`mcp-writ ebpf-run …`).
//!
//! Where `unotify` intercepts `connect(2)` in a seccomp trap and
//! answers from userspace, this route decides *in the kernel*:
//! `BPF_PROG_TYPE_CGROUP_SOCK_ADDR` programs attached to a private
//! cgroup v2 — `BPF_CGROUP_INET4_CONNECT`, `BPF_CGROUP_INET6_CONNECT`,
//! and the `BPF_CGROUP_UDP*_SENDMSG` pair covering datagram sends —
//! evaluate the destination against the policy's IP-layer rules and
//! dynamic grants on every connect/sendmsg and return `0` (the
//! syscall fails `EPERM`) or `1`.
//!
//! The decision content is the same projection `unotify` computes —
//! deny rules match address-only and precede every allow, allows and
//! grants keep their `proto=`/`port=` qualifiers (this mechanism *can*
//! express them: `ctx->protocol`/`user_port` are checked per entry),
//! and `deny_all_others` becomes the program's fall-through verdict.
//! Rule entries live in ARRAY maps so userspace reads a straight-line
//! generated program with no loop for the verifier.
//!
//! Enforcement is in-kernel and so is the failure mode: a denied
//! connect never waits on userspace. Denials are *observed* through a
//! ring buffer the deny tail fills (`magic, rule_idx, family, proto,
//! addr[4], port, pid_tgid`); the supervisor drains it and emits
//! `sandbox.network_denied` under the launch's correlation. A full
//! buffer cannot lose the verdict — the deny still applies and a
//! `denied_dropped` counter records the lost record.
//!
//! Dynamic grants (`--allowlist` snapshot from dns-gate) live in their
//! own ARRAY maps — one entry per `(addr, proto, port)` qualifier
//! pair — and are resynced by the drain loop on snapshot change.
//! Expiry is enforced in-kernel (`expires_at` in unix ns vs
//! `ktime_get_boot_ns` adjusted to the epoch); a missing/unreadable
//! snapshot means an empty grant set — fail closed.
//!
//! Privilege contract: `CAP_BPF`/`CAP_SYS_ADMIN` for program+map ops,
//! `CAP_NET_ADMIN` for the cgroup attach, and write access to the
//! cgroup v2 hierarchy — [`crate::warden::ebpf::probe::check_support`]
//! refuses at startup with a
//! named diagnostic; `sandbox.allow_degraded` does not cover this
//! check, and the route never falls back to `unotify` or the ordinary
//! pipeline.
//!
//! ## Limitations (see also `report::LIMITATIONS`)
//!
//! - **UDP coverage is send-side, connect-scoped** — the
//!   `UDP*_SENDMSG` hooks evaluate every datagram's destination (an
//!   unconnected `sendto`/`sendmsg` carries `msg_name` into the ctx);
//!   a connected socket's nameless sends are passed because the
//!   connect hook already gated the peer. `recvmsg`/`recvfrom` and
//!   non-UDP datagram flows are outside this layer.
//! - **Connect coverage is cgroup-scoped** — only the workload's
//!   process tree (it joins the private cgroup in `pre_exec`; children
//!   inherit membership).
//! - A process that duplicates its socket fd *into* the cgroup from
//!   outside (SCM_RIGHTS) bypasses the hook for that socket's early
//!   connect — same residual every cgroup-based scheme carries.
//! - Teardown SIGKILLs workload members still inside the private
//!   cgroup — a setsid'd daemon or orphaned worker that outlives the
//!   supervised child cannot keep running enforced-but-unsupervised
//!   (or block the rmdir). If the supervisor itself dies abruptly the
//!   cgroup and attached programs are left behind; members stay
//!   kernel-denied until the residue is removed.

#[cfg(test)]
mod tests;

pub mod events;
pub mod probe;
pub mod prog;
pub mod report;
pub mod rules;
pub mod runtime;
pub mod spawn;
pub mod supervisor;
pub mod sys;

pub use crate::warden::cgroup::cgroup_write_grant_conflict;
pub use probe::check_support;
pub use runtime::{PrepareError, Runtime};
pub(crate) use spawn::{resolve_workload_cred, spawn_supervised};
pub use supervisor::{Drain, DrainConfig, DrainEnd, DrainExit, DrainStats, sync_grants_once};
