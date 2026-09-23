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

use landlock::RulesetCreated;
use seccompiler::BpfProgram;

use crate::enforcement::ProcessGrant;
use crate::error::WardenError;
use crate::policy::Policy;

use super::{landlock_impl, seccomp_impl};

/// Sandbox artifacts compiled in the parent (pre-fork) for a single spawn.
pub(super) struct LinuxSandboxBits {
    landlock_ruleset: Option<RulesetCreated>,
    seccomp_program: BpfProgram,
    /// `sandbox.allow_degraded` — the child applies it; the report reads
    /// it so the enforcement-level observation stays honest.
    pub(super) allow_degraded: bool,
    /// Grant entries produced by the same rule build that produced
    /// `landlock_ruleset`/`seccomp_program` — the launch report reads
    /// these so it never recomputes a separate permission table.
    pub(super) grants: Vec<ProcessGrant>,
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
    })
}

impl LinuxSandboxBits {
    /// Child-side `pre_exec` body. Order is fixed:
    /// 1. `set_no_new_privs` (prctl; failure aborts the spawn)
    /// 2. Landlock `restrict_self_fail_closed`
    /// 3. `apply_seccomp_program`
    ///
    /// No heap allocation may happen here: post-fork the allocator lock can
    /// be held by another thread. The helpers therefore return `io::Error`
    /// built from raw errnos (no formatted messages), so the real errno
    /// reaches the spawn error on every failure path — fail-closed behavior
    /// is unchanged.
    fn apply_in_child(&mut self) -> std::io::Result<()> {
        seccomp_impl::set_no_new_privs()?;
        if let Some(rs) = self.landlock_ruleset.take() {
            landlock_impl::restrict_self_fail_closed(rs, self.allow_degraded)?;
        }
        seccomp_impl::apply_seccomp_program(&self.seccomp_program)?;
        Ok(())
    }
}

/// Attach the child-sandbox `pre_exec` to a synchronous command.
///
/// Child-side order is fixed by [`LinuxSandboxBits::apply_in_child`]:
/// `no_new_privs` → Landlock → seccomp.
pub(super) fn attach_linux_pre_exec(cmd: &mut std::process::Command, mut bits: LinuxSandboxBits) {
    use std::os::unix::process::CommandExt;
    // Safety: the closure only invokes prctl / Landlock / seccomp apply on
    // pre-built artifacts; no heap allocation happens after fork.
    unsafe {
        cmd.pre_exec(move || bits.apply_in_child());
    }
}

/// Attach the child-sandbox `pre_exec` to a tokio command (async spawn).
///
/// Child-side order is fixed by [`LinuxSandboxBits::apply_in_child`]:
/// `no_new_privs` → Landlock → seccomp.
pub(super) fn attach_linux_pre_exec_tokio(
    cmd: &mut tokio::process::Command,
    mut bits: LinuxSandboxBits,
) {
    // Safety: the closure only invokes prctl / Landlock / seccomp apply on
    // pre-built artifacts; no heap allocation happens after fork.
    unsafe {
        cmd.pre_exec(move || bits.apply_in_child());
    }
}
