use std::cell::Cell;
#[cfg(unix)]
use std::os::unix::process::CommandExt as _;
use std::path::{Path, PathBuf};

#[cfg(target_os = "macos")]
use crate::enforcement::{ControlState, GrantSubject};
use crate::enforcement::{EnforcementPlan, SandboxBackend};
use crate::error::WardenError;
#[cfg(target_os = "linux")]
use crate::execution::LinuxNativeMechanism;
use crate::execution::WindowsNativeMechanism;
use crate::policy::Policy;

/// Descriptor-number type [`SpawnOptions::exec_uncloak_fds`] carries:
/// `RawFd` on unix, where fd paths exist, and an unused placeholder
/// elsewhere so the options struct stays shape-identical across
/// platforms (literals can keep `..Default::default()`).
#[cfg(unix)]
pub type SpawnFd = std::os::fd::RawFd;
/// Non-unix placeholder for [`SpawnFd`].
#[cfg(not(unix))]
pub type SpawnFd = i32;

/// Options for child spawn. `run` builds them from the policy's
/// `defaults.environment` (restriction + allow list); without an
/// `environment` node the child inherits the ambient env unchanged.
///
/// Self-test (`generate-policy --self-test`) sets `restrict_environment` and a
/// private `tmpdir` so the short-lived child matches live-discovery's restricted
/// environment without using `--unsafe-unsandboxed-discovery`.
#[derive(Debug, Clone, Default)]
pub struct SpawnOptions {
    /// Clear the environment except PATH (and Windows roots) plus TMPDIR and
    /// each `allowed_names` entry found in the parent environment.
    pub restrict_environment: bool,
    /// Parent-environment variable names allowed through a restricted child
    /// environment (policy `defaults.environment` allow list). Consulted only
    /// when `restrict_environment` is set; a listed name missing from the
    /// parent stays unset.
    pub allowed_names: Vec<String>,
    /// Private temporary directory exported as `TMPDIR` / `TMP` / `TEMP`.
    pub tmpdir: Option<PathBuf>,
    /// Unix-only: descriptor numbers an `FdExecPlan` duplicated with
    /// `FD_CLOEXEC` — the spawn clears the flag inside the child
    /// (`pre_exec` / init-side), so the fd spellings stay resolvable
    /// through `execve` without leaving inheritable pin descriptors in
    /// the parent (a concurrent sibling spawn would inherit them).
    /// Ignored on Windows, where fd paths do not exist.
    pub exec_uncloak_fds: Vec<SpawnFd>,
    /// Directories whose contents the child may read *and map
    /// executable*: a pin plan's staged snapshot dirs plus the workload's
    /// derived code roots (runtime prefix, linked-dylib package dirs,
    /// payload package dir). Only meaningful where the sandbox gates
    /// `file-map-executable` (macOS SBPL); ignored elsewhere. Never
    /// grant these dirs write — a writable+executable dir is a
    /// drop-and-run channel.
    pub exec_map_dirs: Vec<PathBuf>,
    /// Linux namespaced handoff: the pinned entrypoint's
    /// `(CLOEXEC-dup fd, resolved real path, sha256)` — init re-reads
    /// the pinned object through the descriptor, re-hashes it against
    /// the digest, and mounts the verified bytes over the path inside
    /// its mount namespace, so the interpreter's real-path open reaches
    /// the pinned content whatever the host later does. Set from
    /// `FdExecPlan::entrypoint_bind_pin`; unused on every other route.
    pub exec_entry_pin: Option<(SpawnFd, PathBuf, String)>,
    /// macOS staged-exe support: when the verified executable is exec'd
    /// through its relocated snapshot path, `LC_RPATH` entries spelled
    /// relative to `@executable_path`/`@loader_path` resolve against the
    /// empty staging dir — a shared build (`@rpath/libnode.N.dylib`)
    /// dies in dyld before main. These are the dirs those rpaths would
    /// have meant at the real path; the spawn exports them as
    /// `DYLD_FALLBACK_LIBRARY_PATH`, dyld's last-resort lookup consulted
    /// only after every `LC_RPATH` candidate misses. See
    /// `macos_sandbox::staged_exec_dyld_fallback_dirs`. Empty elsewhere.
    pub exec_dyld_fallback: Vec<PathBuf>,
}

/// Unix fd-exec handoff: clear `FD_CLOEXEC` on the pin's duplicated
/// descriptors — called inside the child (a `pre_exec` closure or the
/// init-side equivalent), never in the parent. A failure aborts the
/// spawn like any other pre-exec failure.
#[cfg(unix)]
fn uncloak_exec_fds(fds: &[std::os::fd::RawFd]) -> std::io::Result<()> {
    for &fd in fds {
        // Safety: `fd` is a live descriptor owned by the parent's pin
        // plan; F_SETFD arg 0 clears FD_CLOEXEC, the only fd flag.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        if unsafe { libc::fcntl(fd, libc::F_SETFD, 0) } < 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(())
}

/// Parent-side snapshot of fds above stderr not in `keep` — every
/// inherited non-CLOEXEC descriptor is a capability the path rules
/// never mediated. Enumerated here where allocation is allowed; the
/// child's seal loop allocates nothing. A table that cannot be
/// inspected fails the launch: fds that cannot be listed cannot be
/// proven sealed.
#[cfg(unix)]
pub(super) fn ambient_fds_except(
    keep: &[std::os::fd::RawFd],
) -> std::io::Result<Vec<std::os::fd::RawFd>> {
    #[cfg(target_os = "linux")]
    const FD_DIR: &str = "/proc/self/fd";
    #[cfg(not(target_os = "linux"))]
    const FD_DIR: &str = "/dev/fd";
    let mut out = Vec::new();
    for entry in std::fs::read_dir(FD_DIR)? {
        let entry = entry?;
        let Ok(fd) = entry
            .file_name()
            .to_string_lossy()
            .parse::<std::os::fd::RawFd>()
        else {
            continue;
        };
        if fd > 2 && !keep.contains(&fd) {
            out.push(fd);
        }
    }
    Ok(out)
}

/// Seal `fds` — set `FD_CLOEXEC` on each; child-side, `pre_exec`-safe:
/// `fcntl` only, no allocation. Sealing instead of `close(2)` is
/// load-bearing: the runtime's spawn-error pipe may occupy a captured
/// number (it was opened after the parent's snapshot), and `close`ing
/// it would break both the parent's "EOF means exec reached"
/// synchronization and errno reporting for later `pre_exec` failures.
/// `F_SETFD` is idempotent — a recycled slot that now carries an
/// already-CLOEXEC internal fd just gets flagged again — and sealed
/// fds die at `execve` exactly as a `close` would have arranged.
/// Errors are ignored: a slot that vanished since the snapshot needs
/// no sealing.
#[cfg(unix)]
pub(super) fn seal_fds(fds: &[std::os::fd::RawFd]) {
    for &fd in fds {
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) };
    }
}

/// Attach a `pre_exec` hook to a tokio command that seals every
/// ambient fd except `keep` (they die at `execve`), then uncloaks the
/// `keep` pins — the spawn hygiene for arms with no sandbox bits
/// (macOS `sandbox-exec`, the unsandboxed launch arm). The fd table is
/// snapshotted in the parent before fork; the child never allocates.
#[cfg(unix)]
pub(crate) fn attach_fd_hygiene_tokio(
    cmd: &mut tokio::process::Command,
    keep: &[std::os::fd::RawFd],
) -> std::io::Result<()> {
    let seal_list = ambient_fds_except(keep)?;
    let keep_v: Vec<std::os::fd::RawFd> = keep.to_vec();
    // Safety: both captured lists are read-only after capture; the
    // closure performs `fcntl` only — no heap, no lock.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    unsafe {
        cmd.pre_exec(move || {
            seal_fds(&seal_list);
            uncloak_exec_fds(&keep_v)
        });
    }
    Ok(())
}

/// `std::process::Command` variant of [`attach_fd_hygiene_tokio`].
#[cfg(unix)]
pub(super) fn attach_fd_hygiene(
    cmd: &mut std::process::Command,
    keep: &[std::os::fd::RawFd],
) -> std::io::Result<()> {
    let seal_list = ambient_fds_except(keep)?;
    let keep_v: Vec<std::os::fd::RawFd> = keep.to_vec();
    // Safety: same contract as `attach_fd_hygiene_tokio`.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    unsafe {
        cmd.pre_exec(move || {
            seal_fds(&seal_list);
            uncloak_exec_fds(&keep_v)
        });
    }
    Ok(())
}

/// The launch report's `process_lifetime` grant entry — records whether
/// the cgroup v2 descendant boundary was armed for this spawn so a
/// fallback teardown never reads as a stronger guarantee than it is.
#[cfg(target_os = "linux")]
fn lifetime_grant(cg: &Option<cgroup::LifetimeCgroup>) -> crate::enforcement::ProcessGrant {
    use crate::enforcement::{ControlState, GrantOrigin, GrantSubject, ProcessGrant};
    let (state, reason) = if cg.is_some() {
        (
            // `try_adopt` runs after `cmd.spawn()` returned — a child
            // could already have forked, and descendants created before
            // adoption are outside the cgroup the teardown kills.
            ControlState::PartiallyApplied,
            "private cgroup v2 adopted after spawn — teardown kills the \
             adopted subtree (setsid'd daemons and reparented orphans \
             inside it included), but descendants created before \
             adoption are outside the boundary"
                .to_string(),
        )
    } else {
        (
            ControlState::Skipped,
            "cgroup v2 unavailable or unwritable — teardown sweeps the \
             process group and /proc ancestry only; a descendant that \
             left the group and reparented before the sweep can outlive \
             the session"
                .to_string(),
        )
    };
    ProcessGrant {
        subject: GrantSubject::Rule {
            kind: "process_lifetime",
            name: "cgroup v2".to_string(),
        },
        origin: GrantOrigin::Runtime,
        state,
        reason: Some(reason),
    }
}

/// Per-launch cgroup v2 lifetime boundary — the subtree kill sweep
/// shared by the eBPF route's `Runtime`, every generic spawn that can
/// adopt its child into a private cgroup, and the namespaced run's
/// teardown.
#[cfg(target_os = "linux")]
pub(crate) mod cgroup;
mod child;
mod env;
// OS-agnostic verdict core shared by the user-space egress proxies —
// compiled only where a consumer exists (Linux unotify/namespaced,
// macOS CONNECT proxy).
#[cfg(any(target_os = "linux", target_os = "macos"))]
mod flow_gate;
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) mod ip_eval;
#[cfg(target_os = "linux")]
mod landlock_impl;
#[cfg(target_os = "linux")]
mod linux_spawn;
#[cfg(target_os = "macos")]
pub(crate) mod macos_sandbox;
mod plan;
/// PR-07 PoC — seccomp user-notification supervision of `connect(2)`
/// for the Linux IP layer (`mcp-writ unotify-run`).
#[cfg(target_os = "linux")]
pub mod unotify;

/// PR-09 PoC — `userns+netns+mountns` + TUN + user-space TCP/UDP proxy
/// (`mcp-writ namespaced-run`). `pub(crate)`: the init/probe helpers
/// are internal entry points dispatched from `main`, not user API.
#[cfg(target_os = "linux")]
pub(crate) mod namespaced;

/// PR-16 — Linux egress-mechanism selection (`auto`/`namespaced`/
/// `native`): host-capability probe + policy-expressibility checks,
/// shared by `run` (launch) and `plan` so the diagnosis and the
/// applied setup can never diverge.
#[cfg(target_os = "linux")]
pub(crate) mod select;

/// PR-10 opt-in — cgroup eBPF `INET4/6_CONNECT` enforcement for the
/// Linux IP layer (`mcp-writ ebpf-run`).
#[cfg(target_os = "linux")]
pub mod ebpf;

/// PR-11 opt-in — loopback CONNECT proxy path for macOS
/// (`mcp-writ macos-proxy-run`): SBPL pins outbound TCP to a loopback
/// listener that evaluates name+IP destination rules and dials
/// outward itself.
#[cfg(target_os = "macos")]
pub(crate) mod macos_proxy;

/// Shared verdict helpers for the PR-11 command layer — `flow_gate`
/// and `ip_eval` stay private modules; the types are the
/// `pub(crate)` surface (Linux consumers reach them through
/// `unotify`/`namespaced`'s own re-exports and in-warden paths).
#[cfg(target_os = "macos")]
pub(crate) use flow_gate::FlowGate;
#[cfg(target_os = "macos")]
pub(crate) use ip_eval::IpLayerEvaluator;

/// `plan --image` records the egress correspondence table from the host
/// side — the guest mechanism is the guest report's concern.
pub(crate) use plan::egress_layers_guest_plan;
// `sandbox-exec` helper resolution — built for macOS launches and for
// the unit tests that exercise its validation on any Unix host.
/// The PSEC spec encoder — pure data transformation; compiled on
/// Windows (the only consumer) and in test builds everywhere so the
/// byte layout and the policy→spec refusals are unit-testable
/// off-Windows too.
#[cfg(any(target_os = "windows", test))]
mod psec_spec;
#[cfg(any(target_os = "macos", all(unix, test)))]
mod sandbox_exec;
#[cfg(target_os = "linux")]
mod seccomp_impl;
/// The `spawn_*` family — unsandboxed launch, sandboxed spawn, and the
/// async spawn/report pipeline — kept beside the `Warden` core so this
/// module stays the type-and-selection surface.
mod spawn;
#[cfg(target_os = "windows")]
mod windows_env;
#[cfg(target_os = "windows")]
mod windows_proc;
#[cfg(target_os = "windows")]
mod windows_profile;
#[cfg(target_os = "windows")]
mod windows_psec;
#[cfg(target_os = "windows")]
mod windows_sandbox;

pub use child::{
    ChildProcess, ChildStdin, ChildStdout, NamespacedLaunchCtx, NaturalExit, RunningChild, StdChild,
};
pub use plan::{SpawnAttempt, WardenReport};

use child::{RunningChildInner, apply_unix_process_group, apply_unix_process_group_tokio};
use env::apply_spawn_env;

/// The process-env mutex unit tests outside `warden` share — env
/// mutations in tests are global, so every test that sets or reads a
/// steering env var serializes on the same lock.
#[cfg(test)]
pub(crate) use env::lock_process_env;

/// `spawn_env_pairs` for the namespaced launch (PR-09), the macOS
/// spawn/env-observation path, and the Windows env-observation calls —
/// same env block contract as the native spawns. (Was linux-gated,
/// which broke the macOS build, then linux+macOS-gated, which broke
/// the Windows build: the spawn blocks call it unconditionally.)
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
pub(crate) use env::spawn_env_pairs;

pub struct Warden {
    policy: Policy,
    /// When set, `spawn_child*` falls back to the unsandboxed spawn path.
    ///
    /// Sandboxing is applied per child, never to this (parent) process:
    /// Linux runs `no_new_privs` + Landlock + seccomp in the child's `pre_exec`
    /// (see `linux_spawn`), macOS wraps each child in `sandbox-exec`, and
    /// Windows places each child inside an AppContainer profile.
    ///
    /// `apply_sandbox()` is a deprecated no-op and never sets this flag.
    /// Unit tests set it via `mark_sandbox_applied` so `spawn_child*` takes
    /// the unsandboxed path instead of sandboxing test children.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    sandbox_applied: Cell<bool>,
    /// The native-Windows sandbox mechanism `spawn_child*` dispatches on
    /// (`--windows-mechanism`). Non-default selections are fail-closed:
    /// a mechanism absent on this host — including every
    /// `WindowsNativeMechanism` on a non-Windows host — refuses the
    /// launch instead of silently running the default path.
    windows_mechanism: WindowsNativeMechanism,
    /// PR-16 — the resolved Linux egress selection (`auto` /
    /// `--linux-mechanism`). `None` keeps the legacy dispatch (native
    /// Landlock+seccomp) for callers that never ran the selector —
    /// in-guest runners, unit tests. A stored refusal (`selected ==
    /// None`) never reaches a spawn: the launch layer refuses first.
    #[cfg(target_os = "linux")]
    linux_selection: Option<select::LinuxSelection>,
}

impl Warden {
    pub fn new(policy: Policy) -> Self {
        Self::with_windows_mechanism(policy, WindowsNativeMechanism::default())
    }

    /// [`Self::new`] with an explicit native Windows sandbox mechanism.
    /// The selection is fail-closed: `Psec` on a host whose capability
    /// probe fails — or on a non-Windows host — refuses the launch, it
    /// never downgrades to AppContainer.
    pub fn with_windows_mechanism(policy: Policy, mechanism: WindowsNativeMechanism) -> Self {
        Warden {
            policy,
            sandbox_applied: Cell::new(false),
            windows_mechanism: mechanism,
            #[cfg(target_os = "linux")]
            linux_selection: None,
        }
    }

    /// Bind the PR-16 Linux egress selection `run`/`plan` computed.
    /// The selection is evidence: `selected` picks the dispatch route
    /// (namespaced spawn vs native `pre_exec`), `probe`/`missing`/
    /// `violations`/`dns_upstream` flow into every plan/report the
    /// warden produces. A refused selection stays recorded (the
    /// mechanism member says what was asked and why it refused) —
    /// spawn paths refuse before dispatch.
    #[cfg(target_os = "linux")]
    pub fn set_linux_selection(&mut self, selection: select::LinuxSelection) {
        self.linux_selection = Some(selection);
    }

    /// The bound mechanism from the Linux selection — `None` when no
    /// selection ran (legacy callers) or the selection refused.
    #[cfg(target_os = "linux")]
    pub fn linux_selected_mechanism(&self) -> Option<LinuxNativeMechanism> {
        self.linux_selection
            .as_ref()
            .and_then(|s| s.target_mechanism())
    }

    /// The stored selection evidence — `Some` once the selector ran,
    /// including on a refusal (`selected == None`).
    #[cfg(target_os = "linux")]
    pub fn linux_selection(&self) -> Option<&select::LinuxSelection> {
        self.linux_selection.as_ref()
    }

    /// The plan/report `mechanism` member — `Some` whenever the Linux
    /// selector ran, so a refused selection still records its
    /// evidence; `None` for callers that never selected.
    #[cfg(target_os = "linux")]
    fn mechanism_record(&self) -> Option<crate::execution::MechanismSelection> {
        self.linux_selection.as_ref().map(|s| s.to_record())
    }

    #[cfg(not(target_os = "linux"))]
    fn mechanism_record(&self) -> Option<crate::execution::MechanismSelection> {
        None
    }

    /// On non-Windows hosts a non-default `windows_mechanism` cannot
    /// exist — the refusal reason for plans and spawn paths.
    #[cfg(not(target_os = "windows"))]
    fn mechanism_unavailable_reason(&self) -> Option<&'static str> {
        (self.windows_mechanism != WindowsNativeMechanism::AppContainer).then_some(
            "the requested native Windows mechanism does not exist on this \
             host — the launch refuses, no fallback applies",
        )
    }

    /// Same guard on Windows: every mechanism name is implemented there;
    /// the keep-for-symmetry check catches a future mechanism with no
    /// host implementation rather than silently dropping it.
    #[cfg(target_os = "windows")]
    fn mechanism_unavailable_reason(&self) -> Option<&'static str> {
        None
    }

    /// The native OS sandbox backend `spawn_child*` dispatch is bound to
    /// on this host — the value `server.connected`/`server.error` records
    /// report as `enforcement.backend`. [`SandboxBackend::None`] when no
    /// such binding exists: the selected mechanism is absent on this
    /// host (the dispatch refuses rather than silently downgrade, so
    /// there is no backend to name) or the platform has no backend at
    /// all. A caller-side sandbox skip (`--dry-run`,
    /// `MCP_WRIT_SKIP_SANDBOX`, `--sandbox-unsupported`,
    /// `sandbox=disabled`) reports [`SandboxBackend::None`] itself — the
    /// caller maps it before dispatch.
    pub fn sandbox_backend(&self) -> SandboxBackend {
        if self.mechanism_unavailable_reason().is_some() {
            return SandboxBackend::None;
        }
        #[cfg(target_os = "linux")]
        {
            return match self.linux_selected_mechanism() {
                Some(LinuxNativeMechanism::Namespaced) => SandboxBackend::Namespaced,
                Some(LinuxNativeMechanism::Native) => SandboxBackend::LandlockSeccomp,
                // A selection that ran and refused binds to no backend —
                // same `None` semantics as `mechanism_unavailable_reason`.
                // A legacy warden that never selected dispatches the
                // native route.
                None if self.linux_selection.is_some() => SandboxBackend::None,
                None => SandboxBackend::LandlockSeccomp,
            };
        }
        #[cfg(target_os = "macos")]
        {
            return SandboxBackend::SandboxExec;
        }
        #[cfg(target_os = "windows")]
        {
            return match self.windows_mechanism {
                WindowsNativeMechanism::AppContainer => SandboxBackend::AppContainer,
                WindowsNativeMechanism::Psec => SandboxBackend::Psec,
            };
        }
        #[allow(unreachable_code)]
        SandboxBackend::None
    }

    /// Deprecated no-op.
    ///
    /// This method does not apply `no_new_privs`, Landlock, or seccomp.
    /// Child-process sandboxing is applied during `spawn_child`.
    #[deprecated(
        note = "sandboxing is applied to the child during spawn_child; this method is a no-op"
    )]
    pub fn apply_sandbox(&self) -> Result<(), WardenError> {
        tracing::debug!(
            "Warden: apply_sandbox is a no-op; child process sandboxing is applied during spawn_child"
        );
        Ok(())
    }

    /// The enforcement plan for a spawn under `opts` — generated by the
    /// same rule builders the spawn paths use (their artifacts are
    /// discarded). Nothing is applied and no process is spawned.
    ///
    /// `sandbox_skip` describes a deliberately unsandboxed launch
    /// (dry-run / `MCP_WRIT_SKIP_SANDBOX`): OS controls become `Skipped`
    /// and no grants are produced — the plan reflects what that launch
    /// does, which is "no OS sandbox".
    /// Whether the plan/report should describe the namespaced route —
    /// the selection's pick, or (for a refused selection) the route
    /// that was attempted/preferred: explicit `namespaced` plans
    /// namespaced, `auto` plans its namespaced preference, explicit
    /// `native` plans native. A refused selection still produces the
    /// attempted route's plan so the refusal is diagnosable.
    #[cfg(target_os = "linux")]
    fn namespaced_plan_route(&self) -> bool {
        match self.linux_selection.as_ref() {
            Some(s) => match s.selected {
                Some(LinuxNativeMechanism::Namespaced) => true,
                Some(_) => false,
                None => s.requested != crate::execution::LinuxMechanismRequest::Native,
            },
            None => false,
        }
    }

    pub fn enforcement_plan(
        &self,
        program: Option<&Path>,
        command: &str,
        opts: &SpawnOptions,
        sandbox_skip: Option<&'static str>,
        dry_run: bool,
    ) -> EnforcementPlan {
        // A requested mechanism that does not exist on this host marks
        // the OS controls Skipped with the refusal reason — the plan
        // describes what a launch would do, and this launch would refuse.
        let sandbox_skip = sandbox_skip.or_else(|| self.mechanism_unavailable_reason());
        #[cfg(target_os = "linux")]
        if self.namespaced_plan_route() {
            return plan::build_plan_namespaced(
                &self.policy,
                opts,
                sandbox_skip,
                dry_run,
                self.mechanism_record(),
            );
        }
        let mut plan = plan::build_plan(
            &self.policy,
            program,
            command,
            opts,
            sandbox_skip,
            dry_run,
            self.windows_mechanism,
        );
        plan.mechanism = self.mechanism_record();
        plan
    }

    /// Access the policy associated with this Warden instance.
    pub fn policy(&self) -> &Policy {
        &self.policy
    }
}

/// The PSEC capability probe `plan` reports as a check — `Ok` carries
/// the one-line probe detail; `Err` is the refusal reason a launch
/// would hit. Off-Windows the probe is a fixed refusal: the mechanism
/// does not exist there.
#[cfg(target_os = "windows")]
pub(crate) fn psec_capability_probe() -> Result<String, WardenError> {
    windows_psec::capability_probe().map(|p| windows_psec::probe_detail(&p))
}

#[cfg(not(target_os = "windows"))]
pub(crate) fn psec_capability_probe() -> Result<String, WardenError> {
    Err(WardenError::sandbox_setup(
        crate::error::SandboxStage::Prepare,
        "PSEC does not exist on this host — a psec launch would refuse".to_string(),
    ))
}

/// macOS CPython finds its install prefix from the exec'd image path
/// (`_NSGetExecutablePath`), not `argv[0]`: a venv's `bin/python` exec'd
/// by its resolved base-interpreter path loses `pyvenv.cfg` discovery and
/// runs as the base install. `PYTHONEXECUTABLE` is the getpath hook
/// consulted before the image path, so the child receives the caller's
/// spelled interpreter path whenever the verified image differs from it.
/// A bare `command` (no path separator) has no spelled path: it is
/// resolved through PATH, and the hit is exported only when it
/// canonicalizes to the same `program` that was hash-verified — a
/// mismatch would anchor getpath at an interpreter other than the
/// validated image, so it is left unset.
#[cfg(target_os = "macos")]
fn python_executable_override(command: &str, program: Option<&Path>) -> Option<PathBuf> {
    let program = program?;
    let spelled = Path::new(command);
    if program == spelled {
        return None;
    }
    // The verified image's file name classifies alongside the spelled
    // command — a renamed alias exec'd as CPython still needs the hook.
    if crate::workload::CommandNames::new(command, Some(program)).interpreter()
        != Some(crate::workload::InterpreterKind::Python)
    {
        return None;
    }
    if command.contains(['/', '\\']) {
        if spelled.is_absolute() {
            Some(spelled.to_path_buf())
        } else {
            std::env::current_dir().ok().map(|d| d.join(spelled))
        }
    } else {
        let hit = crate::workload::search_path(command)?;
        if crate::workload::same_file(&hit, program) {
            Some(hit)
        } else {
            tracing::warn!(
                "PYTHONEXECUTABLE not set: PATH resolution of '{command}' ({}) does not match the verified image {}",
                hit.display(),
                program.display()
            );
            None
        }
    }
}

#[cfg(test)]
mod tests;
