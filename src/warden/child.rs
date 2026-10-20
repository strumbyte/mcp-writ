//! Child process lifecycle management.
//!
//! [`ChildProcess`] is the unified synchronous child type; [`RunningChild`]
//! wraps a spawned child for async proxying. Both preserve the wait/kill
//! contract: `wait` / `kill` / `Drop` tear down the child's process group
//! (SIGKILL on unix) before reaping. `wait_for_natural_exit` and `try_wait`
//! observe the child's own lifetime without signaling the leader — but once
//! a natural exit is observed the retained process group is still killed, so
//! descendants the leader spawned cannot outlive the session.

#[cfg(target_os = "linux")]
use super::cgroup::LifetimeCgroup;
#[cfg(target_os = "macos")]
use super::macos_sandbox;
#[cfg(target_os = "windows")]
use super::windows_sandbox;

/// A `std::process::Child` plus its per-launch lifetime boundary.
///
/// On Linux, `lifetime_cgroup` is `Some` when the launch adopted the
/// child into a private cgroup v2 subtree — teardown then sweeps the
/// whole subtree (`cgroup.kill`), which reaches descendants a
/// `setsid`/`setpgid` escape or reparenting hid from the process-group
/// kill. `None` means the boundary is unarmed (hierarchy absent or
/// unwritable) and teardown relies on the group + `/proc` sweep alone.
pub struct StdChild {
    child: std::process::Child,
    #[cfg(target_os = "linux")]
    lifetime_cgroup: Option<LifetimeCgroup>,
}

impl StdChild {
    /// Wrap a just-spawned child, adopting it into a private cgroup
    /// when the v2 hierarchy allows — the non-escapable descendant
    /// boundary the group kill alone cannot give.
    pub fn spawned(child: std::process::Child) -> Self {
        Self {
            #[cfg(target_os = "linux")]
            lifetime_cgroup: LifetimeCgroup::try_adopt("run", child.id()),
            child,
        }
    }
}

/// Unified child process type that works across all platforms.
///
/// On macOS/Linux, the child is a standard `std::process::Child`.
/// On Windows, an AppContainer-sandboxed process uses a custom `WindowsChild`
/// because `std::process::Child` cannot be constructed from raw handles in
/// stable Rust.
pub enum ChildProcess {
    Standard(StdChild),
    #[cfg(target_os = "macos")]
    Macos(macos_sandbox::MacosChild),
    #[cfg(target_os = "windows")]
    Windows(windows_sandbox::WindowsChild),
}

pub enum ChildStdin {
    Standard(std::process::ChildStdin),
    #[cfg(target_os = "windows")]
    Windows(std::fs::File),
}

pub enum ChildStdout {
    Standard(std::process::ChildStdout),
    #[cfg(target_os = "windows")]
    Windows(std::fs::File),
}

impl ChildProcess {
    /// Wait for the child process to exit.
    ///
    /// On unix this is not a bare `wait()`: the leader's exit is first
    /// observed without reaping (`WNOWAIT` keeps the zombie so its
    /// pid/pgid stay reserved), the process group / descendant sweep /
    /// cgroup members are torn down while the leader is still pinned,
    /// and only then is the leader reaped — descendants a natural exit
    /// orphaned cannot outlive the session.
    pub fn wait(&mut self) -> std::io::Result<std::process::ExitStatus> {
        match self {
            ChildProcess::Standard(child) => {
                #[cfg(unix)]
                sweep_std_descendants(child, true);
                child.child.wait()
            }
            #[cfg(target_os = "macos")]
            ChildProcess::Macos(child) => child.wait(),
            #[cfg(target_os = "windows")]
            ChildProcess::Windows(child) => child.wait(),
        }
    }

    /// Forcefully terminate the child process.
    pub fn kill(&mut self) -> std::io::Result<()> {
        match self {
            ChildProcess::Standard(child) => {
                #[cfg(unix)]
                sweep_std_descendants(child, false);
                child.child.kill()
            }
            #[cfg(target_os = "macos")]
            ChildProcess::Macos(child) => child.kill(),
            #[cfg(target_os = "windows")]
            ChildProcess::Windows(child) => child.kill(),
        }
    }

    /// Get the OS-assigned process ID.
    ///
    /// Returns `None` on Windows if the process handle is invalid.
    /// On other platforms, always returns `Some`.
    pub fn id(&self) -> Option<u32> {
        match self {
            ChildProcess::Standard(child) => Some(child.child.id()),
            #[cfg(target_os = "macos")]
            ChildProcess::Macos(child) => Some(child.id()),
            #[cfg(target_os = "windows")]
            ChildProcess::Windows(child) => child.id(),
        }
    }

    /// Take the child's stdin handle, leaving `None` in its place.
    pub fn take_stdin(&mut self) -> Option<ChildStdin> {
        match self {
            ChildProcess::Standard(child) => child.child.stdin.take().map(ChildStdin::Standard),
            #[cfg(target_os = "macos")]
            ChildProcess::Macos(child) => child.stdin.take().map(ChildStdin::Standard),
            #[cfg(target_os = "windows")]
            ChildProcess::Windows(child) => child.stdin.take().map(ChildStdin::Windows),
        }
    }

    /// Take the child's stdout handle, leaving `None` in its place.
    pub fn take_stdout(&mut self) -> Option<ChildStdout> {
        match self {
            ChildProcess::Standard(child) => child.child.stdout.take().map(ChildStdout::Standard),
            #[cfg(target_os = "macos")]
            ChildProcess::Macos(child) => child.stdout.take().map(ChildStdout::Standard),
            #[cfg(target_os = "windows")]
            ChildProcess::Windows(child) => child.stdout.take().map(ChildStdout::Windows),
        }
    }

    /// Check if stdin is available.
    pub fn has_stdin(&self) -> bool {
        match self {
            ChildProcess::Standard(child) => child.child.stdin.is_some(),
            #[cfg(target_os = "macos")]
            ChildProcess::Macos(child) => child.stdin.is_some(),
            #[cfg(target_os = "windows")]
            ChildProcess::Windows(child) => child.stdin.is_some(),
        }
    }

    /// Check if stdout is available.
    pub fn has_stdout(&self) -> bool {
        match self {
            ChildProcess::Standard(child) => child.child.stdout.is_some(),
            #[cfg(target_os = "macos")]
            ChildProcess::Macos(child) => child.stdout.is_some(),
            #[cfg(target_os = "windows")]
            ChildProcess::Windows(child) => child.stdout.is_some(),
        }
    }
}

/// Tear down the descendants of a [`StdChild`] before its leader is
/// reaped — the synchronous-path counterpart of
/// [`RunningChild::kill_descendants`].
///
/// `wait_mode` distinguishes the two callers: `kill` signals a possibly
/// live leader's group directly, while `wait` first blocks on a
/// `WNOWAIT` exit report so the group sweep provably runs while the
/// zombie still reserves the pgid (a leader that already exited
/// naturally must not leave orphans behind, and a *reaped* leader's
/// freed pgid must never be signaled).
#[cfg(unix)]
fn sweep_std_descendants(child: &StdChild, wait_mode: bool) {
    let pid = child.child.id() as libc::pid_t;
    if wait_mode {
        // Block until the leader reports exit while keeping the zombie
        // — mirrors `sweep_group_after_exit`; EINTR is retried.
        loop {
            // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
            let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
            // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
            let ret = unsafe {
                libc::waitid(
                    libc::P_PID,
                    pid as libc::id_t,
                    &mut info,
                    libc::WEXITED | libc::WNOWAIT,
                )
            };
            if ret == 0 {
                break;
            }
            if std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
                // Could not observe the exit (already reaped, not our
                // child): skip the sweep — the pgid may be recycled.
                return;
            }
        }
    }
    kill_unix_process_group(pid as u32);
    #[cfg(target_os = "linux")]
    {
        if let Some(cg) = &child.lifetime_cgroup {
            if cg.kill_members() > 0 {
                tracing::warn!(
                    "lifetime cgroup still lists workload members after \
                     the kill sweep — orphaned descendants may outlive \
                     this teardown"
                );
            }
        } else {
            kill_proc_descendants(pid as u32);
        }
    }
    #[cfg(target_os = "macos")]
    kill_proc_descendants(pid as u32);
}

/// PR-16 — the supervision state a namespaced launch owns beside the
/// child itself. The workload's *only* egress path is the TUN fd the
/// proxy reads, so the proxy task is a hard dependency of the launch:
/// its end while the leader still runs is a fail-closed loss
/// (`wait_for_natural_exit` reports `NaturalExit::SupervisionLost`),
/// never a silent degradation.
#[cfg(target_os = "linux")]
pub(crate) struct NamespacedRuntime {
    /// The egress proxy task (TUN readers + TCP/UDP/DNS pipeline).
    /// Polled by `wait_for_natural_exit`; aborted on kill/drop.
    pub proxy: tokio::task::JoinHandle<()>,
    /// The parent's TUN handle — closing it ends the proxy's reader;
    /// kept so `kill`/`drop` closes the device even when the abort
    /// raced it.
    pub tun: std::fs::File,
    /// Set when the wait loop observed the proxy's completion while
    /// the leader still ran — the report's failure detail reads it.
    /// Shared (`Arc`) so a report source cloned before the flag was
    /// set still sees it once the supervision loss lands.
    pub proxy_lost: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

/// PR-16 — the session facts a namespaced launch needs beside the
/// spawn config: the audit sink + correlation the proxy/DNS gate share
/// with the session's own records, and the resolved DNS upstream.
/// Platform-neutral so `Warden`'s spawn signatures need no `cfg`ed
/// parameter; it is only ever populated on Linux.
pub struct NamespacedLaunchCtx {
    /// The launch's correlation id — the proxy's `network_*` and the
    /// gate's `dns_*` records carry the same id the session's
    /// `server.*`/`guard.*` records do.
    pub launch_id: uuid::Uuid,
    /// The DNS upstream the embedded gate forwards to — the resolved
    /// `--dns-upstream`/resolv.conf value the selection recorded.
    /// `None` runs the route without the gate: port-53 flows then fall
    /// to the ordinary IP-layer evaluator (deny-all still refuses
    /// them), which is only reachable when the policy declares no
    /// name-bound rule — the selection flags a needed-but-missing
    /// upstream as a violation before this point.
    pub upstream: Option<std::net::SocketAddr>,
    /// The session audit logger — the same sink `server.*` records
    /// write, so a fail-closed audit loss kills the workload under the
    /// same watch as every other route.
    pub audit: crate::audit_log::AuditLogger,
    /// The bound-policy audit context the gate/proxy records carry.
    pub policy_ctx: Option<crate::audit_log::PolicyAuditContext>,
}

/// A running child process wrapped for asynchronous proxying.
pub struct RunningChild {
    pub stdin: Option<Box<dyn tokio::io::AsyncWrite + Unpin + Send>>,
    pub stdout: Option<Box<dyn tokio::io::AsyncRead + Unpin + Send>>,
    pub(super) inner: RunningChildInner,
    /// Process group id captured at spawn — `process_group(0)` makes it
    /// equal to the child pid, and the group outlives its leader while
    /// any descendant still belongs to it. Kept separately because a
    /// fresh `id()` read is tied to the live (unreaped) handle: a leader
    /// that exited naturally may no longer resolve, yet its descendants
    /// are still killable through the group it left behind.
    #[cfg(unix)]
    pub(super) pgid: u32,
    /// Whether the leader has been reaped by `wait`/`try_wait`. Once
    /// reaped, the freed pid/pgid may name a recycled, unrelated
    /// process group — group signaling must stop.
    #[cfg(unix)]
    pub(super) reaped: bool,
    /// Linux only, `Some` only when the spawn armed the seccomp
    /// user-notification stage (`spawn_child_async_unotify`): the
    /// listener fd the child's `pre_exec` handed over. The consumer
    /// takes it and answers the notifications it reports — leaving it
    /// makes the kernel fail every watched syscall `ENOSYS`.
    pub(crate) unotify_listener: Option<std::fs::File>,
    /// Linux only: the private cgroup v2 subtree this launch's leader
    /// was adopted into — the non-escapable descendant boundary
    /// (`cgroup.kill` covers setsid'd daemons and reparented orphans
    /// that `kill(-pgid)` cannot reach). `None` when the v2 hierarchy
    /// was absent or unwritable — teardown then relies on the
    /// group + `/proc` sweep, and the launch report's
    /// `process_lifetime` grant entry records the fallback.
    #[cfg(target_os = "linux")]
    pub(crate) lifetime_cgroup: Option<LifetimeCgroup>,
    /// Linux only: the namespaced launch's supervision side-channel —
    /// `Some` only for `linux-namespaced` spawns.
    #[cfg(target_os = "linux")]
    pub(crate) namespaced: Option<Box<NamespacedRuntime>>,
    /// Linux only: the report-facing handle on the namespaced session
    /// — cloned Arcs held separately from `namespaced` so `kill`/`drop`
    /// taking the runtime cannot take the report's evidence with it.
    #[cfg(target_os = "linux")]
    pub(crate) namespaced_report: Option<NamespacedReportSource>,
    #[cfg(target_os = "macos")]
    pub(super) _tmpdir: Option<macos_sandbox::PrivateTmpDir>,
}

pub(super) enum RunningChildInner {
    Tokio(Box<tokio::process::Child>),
    #[cfg(target_os = "windows")]
    Windows(std::sync::Arc<windows_sandbox::WindowsChild>),
}

/// The result of [`RunningChild::wait_for_natural_exit`] — a natural
/// exit, or a supervision-channel loss that demands the same teardown
/// (a namespaced launch whose egress proxy ended while the workload
/// still runs must be killed, not left unenforced).
pub enum NaturalExit {
    /// The leader's own exit (or a wait error).
    Exited(std::io::Result<std::process::ExitStatus>),
    /// A hard supervision dependency ended while the workload was
    /// still alive — the string names the channel for the report.
    #[cfg(target_os = "linux")]
    SupervisionLost(&'static str),
}

impl RunningChild {
    pub fn take_io(
        &mut self,
    ) -> Option<(
        Box<dyn tokio::io::AsyncWrite + Unpin + Send>,
        Box<dyn tokio::io::AsyncRead + Unpin + Send>,
    )> {
        if self.stdin.is_none() || self.stdout.is_none() {
            return None;
        }
        let stdin = self.stdin.take()?;
        let stdout = self.stdout.take()?;
        Some((stdin, stdout))
    }

    /// Take the seccomp user-notification listener this spawn armed
    /// (Linux `spawn_child_async_unotify` only — `None` everywhere
    /// else). The taker owns answering the notifications.
    pub fn take_unotify_listener(&mut self) -> Option<std::fs::File> {
        self.unotify_listener.take()
    }

    /// The namespaced session's report source (`Some` only for a
    /// `linux-namespaced` spawn) — cloned Arcs, so the caller's handle
    /// reads the live counters until the proxy exits. Refreshes the
    /// `proxy_lost` flag from the proxy handle first, so exit paths
    /// that did not go through `wait_for_natural_exit` still report a
    /// supervision loss.
    #[cfg(target_os = "linux")]
    pub(crate) fn namespaced_report_source(&mut self) -> Option<NamespacedReportSource> {
        self.refresh_proxy_state();
        self.namespaced_report.clone()
    }

    /// Refresh `self`'s `proxy_lost` flag from the (possibly already
    /// finalized) proxy handle — used by exit paths that did not go
    /// through `wait_for_natural_exit`.
    #[cfg(target_os = "linux")]
    pub(crate) fn refresh_proxy_state(&mut self) {
        if let Some(ns) = self.namespaced.as_mut()
            && ns.proxy.is_finished()
        {
            ns.proxy_lost
                .store(true, std::sync::atomic::Ordering::Relaxed);
        }
    }

    /// Process group id captured at spawn (`process_group(0)` ⇒ pgid ==
    /// child pid). Unlike a fresh `id()` read, this stays a valid group
    /// target after the leader has exited: the group persists while any
    /// descendant still belongs to it. A reaped leader yields `None`:
    /// the freed pid/pgid may have been recycled into an unrelated
    /// process group that must not be signaled.
    #[cfg(unix)]
    fn process_group_id(&self) -> Option<u32> {
        (self.pgid != 0 && !self.reaped).then_some(self.pgid)
    }

    /// True when the leader has exited but not yet been reaped. The
    /// `WNOWAIT` probe reports the exit while keeping the zombie, so the
    /// pid — and the process-group id the sweep names — stays reserved
    /// until a real wait consumes it. `waitid` is the call where
    /// `WNOWAIT` is specified (its effect on `waitpid` is unspecified);
    /// under `WNOHANG` it returns 0 for both a report and "nothing to
    /// report", so `si_pid` distinguishes the two. EINTR is retried — a
    /// caught signal landing mid-probe is not evidence of state
    /// (`sweep_group_after_exit`'s blocking probe already retries it).
    #[cfg(unix)]
    fn exited_unreaped(&self) -> bool {
        let Some(pid) = self.id() else {
            return false;
        };
        loop {
            // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
            let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
            // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
            let ret = unsafe {
                libc::waitid(
                    libc::P_PID,
                    pid as libc::id_t,
                    &mut info,
                    libc::WEXITED | libc::WNOWAIT | libc::WNOHANG,
                )
            };
            if ret == 0 {
                // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
                return unsafe { info.si_pid() } == pid as libc::pid_t;
            }
            if std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
                return false;
            }
        }
    }

    /// SIGKILL the child's whole process group by the pgid captured at
    /// spawn, then sweep descendants that escaped the group via
    /// `setpgid`/`setsid` while their ancestry is still inspectable.
    /// Harmless once the group is empty — the group kill is skipped
    /// once the leader has been reaped, since the freed pid/pgid could
    /// by then name a recycled group belonging to someone else.
    ///
    /// The lifetime cgroup is different: its member list is the
    /// authoritative, pid-recycle-safe record of this launch's
    /// descendants (`cgroup.kill` is atomic over the subtree, and the
    /// fallback re-verifies membership per pid). It is swept even
    /// after the leader was reaped — a reaped leader says nothing
    /// about orphaned members still alive in the cgroup.
    #[cfg(unix)]
    fn kill_descendants(&self) {
        #[cfg(target_os = "linux")]
        if let Some(cg) = &self.lifetime_cgroup {
            // cgroup membership cannot be shed by setsid/setpgid or
            // reparenting — this is the authoritative descendant sweep.
            // A residue means members outlived the bounded drain: warn
            // rather than let teardown read as clean.
            if cg.kill_members() > 0 {
                tracing::warn!(
                    "lifetime cgroup still lists workload members after \
                     the kill sweep — orphaned descendants may outlive \
                     this teardown"
                );
            }
        }
        if self.reaped {
            return;
        }
        if let Some(pgid) = self.process_group_id() {
            kill_unix_process_group(pgid);
        }
        #[cfg(target_os = "linux")]
        if self.lifetime_cgroup.is_none() {
            // No cgroup boundary: fall back to the /proc ancestry walk
            // for descendants that escaped the process group.
            if let Some(root) = self.id() {
                kill_proc_descendants(root);
            }
        }
        #[cfg(target_os = "macos")]
        if let Some(root) = self.id() {
            kill_proc_descendants(root);
        }
    }

    pub async fn kill(&mut self) -> std::io::Result<()> {
        // Namespaced supervision ends with the kill decision: abort the
        // proxy and close the TUN now — not at Drop — so a killed
        // workload's egress device dies with the kill rather than at
        // report-write time. The abort is awaited so the task cannot
        // still be mid-commit when the audit sink's teardown runs.
        #[cfg(target_os = "linux")]
        self.quiesce_namespaced_proxy().await;
        #[cfg(unix)]
        self.kill_descendants();
        let result = match &mut self.inner {
            RunningChildInner::Tokio(child) => child.kill().await,
            #[cfg(target_os = "windows")]
            RunningChildInner::Windows(child) => {
                let c = child.clone();
                tokio::task::spawn_blocking(move || c.kill())
                    .await
                    .map_err(|e| std::io::Error::other(e.to_string()))?
            }
        };
        #[cfg(unix)]
        if result.is_ok() {
            self.reaped = true;
        }
        result
    }

    /// Wait for the child to exit without sending SIGKILL first.
    ///
    /// Use this whenever the caller must observe the child's own lifetime
    /// (`mcp-writ run` / `mcp-secure-runner` select, self-test EACCES/SIGSYS,
    /// SIGTERM/SIGINT grace). [`Self::wait`] tears down the process group and
    /// must not be polled as "wait until the MCP server exits".
    ///
    /// After a natural exit is observed the process group is still torn
    /// down: descendants the exited leader spawned (direct children,
    /// detached grandchildren) must not outlive the session. The exit is
    /// detected without reaping (`WNOWAIT` leaves the zombie) so the
    /// retained pgid still names the live group when it is signaled —
    /// the leader is reaped only afterwards. `reaped` is marked only
    /// after this sweep so no later path can signal a recycled
    /// process-group id.
    ///
    /// On a namespaced launch the wait additionally polls the egress
    /// proxy task: its completion while the leader still runs is a
    /// fail-closed supervision loss — reported as
    /// [`NaturalExit::SupervisionLost`] so the caller kills the tree
    /// rather than leave it without an egress enforcement point.
    pub async fn wait_for_natural_exit(&mut self) -> NaturalExit {
        // Namespaced launches poll the egress proxy alongside the
        // leader's exit — the proxy poll wraps the entire wait
        // (including the WNOWAIT sweep), so a dead proxy is observed
        // even while the leader lives. `ns` is taken out of `self` so
        // the select arm's borrow does not conflict with the inner
        // wait's.
        #[cfg(target_os = "linux")]
        if self.namespaced.is_some() {
            let mut ns = self.namespaced.take().expect("checked above");
            enum NsWait {
                Status(std::io::Result<std::process::ExitStatus>),
                Lost,
            }
            let outcome = tokio::select! {
                status = self.wait_inner_natural() => NsWait::Status(status),
                _ = &mut ns.proxy => NsWait::Lost,
            };
            match outcome {
                NsWait::Lost => {
                    ns.proxy_lost
                        .store(true, std::sync::atomic::Ordering::Relaxed);
                    self.namespaced = Some(ns);
                    return NaturalExit::SupervisionLost(
                        "egress proxy task ended while the workload was still \
                         running (fail-closed)",
                    );
                }
                NsWait::Status(status) => {
                    self.namespaced = Some(ns);
                    #[cfg(unix)]
                    if status.is_ok() {
                        self.reaped = true;
                    }
                    return NaturalExit::Exited(status);
                }
            }
        }
        #[cfg(unix)]
        if !self.reaped {
            self.sweep_group_after_exit().await;
        }
        let status = match &mut self.inner {
            RunningChildInner::Tokio(child) => child.wait().await,
            #[cfg(target_os = "windows")]
            RunningChildInner::Windows(child) => {
                let c = child.clone();
                match tokio::task::spawn_blocking(move || c.wait()).await {
                    Ok(status) => status,
                    Err(e) => Err(std::io::Error::other(e.to_string())),
                }
            }
        };
        #[cfg(unix)]
        if status.is_ok() {
            self.reaped = true;
        }
        NaturalExit::Exited(status)
    }

    /// Stop a namespaced launch's egress proxy deterministically:
    /// abort the task and await its cancellation, then close the
    /// parent's TUN handle. Wait paths call this before audit-sink
    /// teardown so a late proxy commit cannot race the channel close
    /// (a `channel_closed` commit error would read as an audit fault
    /// when it is really teardown ordering). No-op on non-Linux,
    /// non-namespaced launches, and after a previous `kill`/`quiesce`
    /// already took the runtime.
    pub(crate) async fn quiesce_namespaced_proxy(&mut self) {
        #[cfg(target_os = "linux")]
        if let Some(ns) = self.namespaced.take() {
            let mut proxy = ns.proxy;
            // A finished task is already quiesced — aborting it would
            // only re-poll a completed JoinHandle. The abort cascades:
            // `run_proxy`'s JoinSets drop with its frame, aborting the
            // reader/writer/gate/udp tasks and every backend pump, so
            // no sub-task or cloned TUN fd outlives the proxy.
            if !proxy.is_finished() {
                proxy.abort();
                let _ = (&mut proxy).await;
            }
            drop(ns.tun);
        }
    }

    /// The WNOWAIT sweep + inner wait shared by [`Self::wait_for_natural_exit`]'s
    /// namespaced-select arm — identical semantics to the plain path.
    #[cfg(target_os = "linux")]
    async fn wait_inner_natural(&mut self) -> std::io::Result<std::process::ExitStatus> {
        #[cfg(unix)]
        if !self.reaped {
            self.sweep_group_after_exit().await;
        }
        match &mut self.inner {
            RunningChildInner::Tokio(child) => child.wait().await,
            #[cfg(target_os = "windows")]
            RunningChildInner::Windows(child) => {
                let c = child.clone();
                tokio::task::spawn_blocking(move || c.wait())
                    .await
                    .map_err(|e| std::io::Error::other(e.to_string()))?
            }
        }
    }

    /// Block (on a blocking thread) until the leader has exited but is
    /// still an unreaped zombie, then sweep the process group while the
    /// pid — and the pgid the group kill names — is still reserved. The
    /// inner `wait` afterwards reaps the leader. An undetectable exit
    /// (e.g. reaped elsewhere) skips the sweep: a freed pgid must never
    /// be signaled. If this future is cancelled, the probe thread stays
    /// parked until the leader exits — bounded by the child's lifetime.
    #[cfg(unix)]
    async fn sweep_group_after_exit(&self) {
        let Some(pid) = self.id() else {
            return;
        };
        let exited = tokio::task::spawn_blocking(move || {
            loop {
                // Blocking `waitid` with WNOWAIT: reports the exit while
                // keeping the zombie, so the pid stays reserved while the
                // group is signaled. ret == 0 always means a report here
                // (no WNOHANG), so si_pid needs no inspection.
                // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
                let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
                // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
                let ret = unsafe {
                    libc::waitid(
                        libc::P_PID,
                        pid as libc::id_t,
                        &mut info,
                        libc::WEXITED | libc::WNOWAIT,
                    )
                };
                if ret == 0 {
                    return true;
                }
                if std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
                    return false;
                }
            }
        })
        .await
        .unwrap_or(false);
        if exited {
            self.kill_descendants();
        }
    }

    /// Non-blocking poll for a natural exit (no SIGKILL).
    ///
    /// Narrow gap a caller must accept: if the leader exits between the
    /// probe below and the inner `try_wait` — i.e. the probe saw it
    /// alive, then the inner call reaps it — the sweep never ran and
    /// detached descendants can outlive the session (the freed pgid
    /// must still never be signaled, so skipping is the safe direction).
    /// Callers that must guarantee descendant cleanup use
    /// [`Self::wait`] or [`Self::wait_for_natural_exit`].
    pub fn try_wait(&mut self) -> std::io::Result<Option<std::process::ExitStatus>> {
        // Probe for the exit without reaping first: a leader the inner
        // `try_wait` already reaped frees its pid, and the recorded pgid
        // may by then name a recycled group that must not be signaled.
        #[cfg(unix)]
        if !self.reaped && self.exited_unreaped() {
            self.kill_descendants();
        }
        let status = match &mut self.inner {
            RunningChildInner::Tokio(child) => child.try_wait(),
            #[cfg(target_os = "windows")]
            RunningChildInner::Windows(child) => child.try_wait(),
        };
        #[cfg(unix)]
        if matches!(status, Ok(Some(_))) {
            self.reaped = true;
        }
        status
    }

    /// Tear down the process group, then reap.
    ///
    /// Do not use this to observe a live MCP server: the first poll sends
    /// SIGKILL. After [`Self::kill`] or when abandoning the child, this keeps
    /// the PID allocated until leftovers are signaled.
    pub async fn wait(&mut self) -> std::io::Result<std::process::ExitStatus> {
        // Kill leftovers while this PID is still allocated. Signaling after
        // wait() reaps the child can hit an unrelated process group.
        #[cfg(unix)]
        self.kill_descendants();
        let status = match &mut self.inner {
            RunningChildInner::Tokio(child) => child.wait().await,
            #[cfg(target_os = "windows")]
            RunningChildInner::Windows(child) => {
                let c = child.clone();
                tokio::task::spawn_blocking(move || c.wait())
                    .await
                    .map_err(|e| std::io::Error::other(e.to_string()))?
            }
        };
        #[cfg(unix)]
        if status.is_ok() {
            self.reaped = true;
        }
        status
    }

    pub fn id(&self) -> Option<u32> {
        match &self.inner {
            RunningChildInner::Tokio(child) => child.id(),
            #[cfg(target_os = "windows")]
            RunningChildInner::Windows(child) => child.id(),
        }
    }

    #[cfg(unix)]
    pub fn signal(&self, sig: i32) -> std::io::Result<()> {
        if let Some(pgid) = self.process_group_id() {
            // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
            let ret = unsafe { libc::kill(-(pgid as i32), sig) };
            if ret != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        } else {
            Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "child already reaped or has no process group",
            ))
        }
    }
}

/// The namespaced session facts the launch report finalizes with —
/// `ProxyStats` and `proxy_lost` are `Arc`-shared, so cloning the
/// handle keeps reading the live values through report-write time.
#[cfg(target_os = "linux")]
#[derive(Clone)]
pub struct NamespacedReportSource {
    pub stats: super::namespaced::ProxyStats,
    pub sandbox_applied: Option<bool>,
    /// Shared flag — `wait_for_natural_exit`/`refresh_proxy_state` set
    /// it when the proxy ended while the workload still ran.
    pub proxy_lost: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

impl Drop for RunningChild {
    fn drop(&mut self) {
        // A namespaced launch's supervision ends with the child: abort
        // the proxy task and close the TUN — the abort cascades through
        // `run_proxy`'s JoinSets to every sub-task (reader, writer,
        // gate, udp, backend pumps), so no detached task keeps the
        // cloned TUN fd (or its netns pin) alive. The workload's egress
        // is never left attached to an unwatched fd.
        #[cfg(target_os = "linux")]
        if let Some(ns) = self.namespaced.take() {
            ns.proxy.abort();
            drop(ns.tun);
        }
        #[cfg(unix)]
        self.kill_descendants();
        match &mut self.inner {
            RunningChildInner::Tokio(child) => {
                let _ = child.start_kill();
            }
            #[cfg(target_os = "windows")]
            RunningChildInner::Windows(child) => {
                let _ = child.kill();
            }
        }
    }
}

pub(super) fn apply_unix_process_group(cmd: &mut std::process::Command) {
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        cmd.process_group(0);
    }
    let _ = cmd;
}

pub(super) fn apply_unix_process_group_tokio(cmd: &mut tokio::process::Command) {
    #[cfg(unix)]
    {
        cmd.process_group(0);
    }
    let _ = cmd;
}

#[cfg(unix)]
fn kill_unix_process_group(pgid: u32) {
    // `kill(0)` signals *this* process's own group — a pgid that never
    // materialized must not reach the call.
    if pgid == 0 {
        return;
    }
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    let _ = unsafe { libc::kill(-(pgid as i32), libc::SIGKILL) };
}

/// Best-effort SIGKILL of every descendant of `root_pid`, including
/// processes that escaped the child's process group via `setpgid` or
/// `setsid` (which `kill(-pgid)` cannot reach). Walks `/proc/*/stat`
/// ppid links once, then signals by pid — the parentage snapshot is
/// taken before any kill, so mid-sweep reparenting cannot hide a
/// descendant. Post-exit, a dead leader's children are reparented away
/// before this runs; the group kill above is what must catch those.
#[cfg(target_os = "linux")]
fn kill_proc_descendants(root_pid: u32) {
    use std::collections::HashMap;

    let Ok(entries) = std::fs::read_dir("/proc") else {
        return;
    };
    let mut children_of: HashMap<u32, Vec<u32>> = HashMap::new();
    for entry in entries.flatten() {
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<u32>().ok())
        else {
            continue;
        };
        if pid == root_pid {
            continue;
        }
        let Ok(stat) = std::fs::read_to_string(entry.path().join("stat")) else {
            continue;
        };
        let Some(ppid) = stat_ppid(&stat) else {
            continue;
        };
        children_of.entry(ppid).or_default().push(pid);
    }

    let mut pending = vec![root_pid];
    while let Some(parent) = pending.pop() {
        let Some(kids) = children_of.get(&parent) else {
            continue;
        };
        for &kid in kids {
            // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
            let _ = unsafe { libc::kill(kid as i32, libc::SIGKILL) };
            pending.push(kid);
        }
    }
}

/// macOS counterpart of the `/proc` walk: `proc_listpids` +
/// `PROC_PIDTBSDINFO` yields every live pid's ppid; the BFS from
/// `root_pid` reaches descendants that escaped the process group
/// while still parent-linked. Orphans already reparented to launchd
/// are missed — the same residual the Linux walk carries; the group
/// kill above catches them while they kept the launch pgid.
#[cfg(target_os = "macos")]
fn kill_proc_descendants(root_pid: u32) {
    use std::collections::HashMap;
    // One bounded listing — the buffer caps the pid count examined;
    // a truncated listing sweeps less of the tree, never more.
    const MAX_PIDS: usize = 8192;
    // Darwin's PROC_ALL_PIDS listing kind — not exported by this libc.
    const PROC_ALL_PIDS: u32 = 1;
    let mut pids = vec![0i32; MAX_PIDS];
    // Safety: `pids` is a live, correctly-sized buffer; the return is
    // a byte count.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    let n = unsafe {
        libc::proc_listpids(
            PROC_ALL_PIDS,
            0,
            pids.as_mut_ptr() as *mut libc::c_void,
            (MAX_PIDS * std::mem::size_of::<i32>()) as i32,
        )
    };
    if n <= 0 {
        return;
    }
    let count = (n as usize / std::mem::size_of::<i32>()).min(MAX_PIDS);
    let mut children_of: HashMap<u32, Vec<u32>> = HashMap::new();
    for &raw in &pids[..count] {
        let pid = raw as u32;
        if pid == 0 || pid == root_pid {
            continue;
        }
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
        // Safety: `info` is a live, correctly-sized out-buffer.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        let sz = unsafe {
            libc::proc_pidinfo(
                raw,
                libc::PROC_PIDTBSDINFO,
                0,
                &mut info as *mut libc::proc_bsdinfo as *mut libc::c_void,
                std::mem::size_of::<libc::proc_bsdinfo>() as i32,
            )
        };
        if sz != std::mem::size_of::<libc::proc_bsdinfo>() as i32 {
            continue;
        }
        children_of.entry(info.pbi_ppid).or_default().push(pid);
    }

    let mut pending = vec![root_pid];
    while let Some(parent) = pending.pop() {
        let Some(kids) = children_of.get(&parent) else {
            continue;
        };
        for &kid in kids {
            // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
            let _ = unsafe { libc::kill(kid as i32, libc::SIGKILL) };
            pending.push(kid);
        }
    }
}

/// `ppid` out of `/proc/<pid>/stat`. The real end of `comm` is the last
/// `)` on the line — no field after `comm` can contain one — so a
/// crafted `comm` value cannot hide the ancestry fields from this parse.
#[cfg(target_os = "linux")]
fn stat_ppid(stat: &str) -> Option<u32> {
    let tail = stat.get(stat.rfind(')')? + 1..)?;
    let mut fields = tail.split_whitespace();
    fields.next()?; // state
    fields.next()?.parse().ok()
}

#[cfg(all(unix, test))]
mod tests {
    use super::*;

    fn spawn_sh(script: &str) -> RunningChild {
        let mut cmd = tokio::process::Command::new("sh");
        cmd.arg("-c").arg(script);
        apply_unix_process_group_tokio(&mut cmd);
        let child = cmd.spawn().expect("spawn sh");
        let pgid = child.id().unwrap_or(0);
        RunningChild {
            stdin: None,
            stdout: None,
            unotify_listener: None,
            inner: RunningChildInner::Tokio(Box::new(child)),
            pgid,
            reaped: false,
            #[cfg(target_os = "linux")]
            lifetime_cgroup: LifetimeCgroup::try_adopt("test", pgid),
            #[cfg(target_os = "linux")]
            namespaced: None,
            #[cfg(target_os = "linux")]
            namespaced_report: None,
            #[cfg(target_os = "macos")]
            _tmpdir: None,
        }
    }

    /// `wait_for_natural_exit` → the leader's own status; a supervision
    /// loss fails the test (these children are never namespaced).
    async fn natural_exit(child: &mut RunningChild) -> std::process::ExitStatus {
        match child.wait_for_natural_exit().await {
            NaturalExit::Exited(status) => status.expect("natural exit status"),
            #[cfg(target_os = "linux")]
            NaturalExit::SupervisionLost(detail) => {
                panic!("unexpected supervision loss: {detail}")
            }
        }
    }

    /// A reaped leader frees its pid — the recorded pgid could belong
    /// to a recycled group, so `signal` and the descendant sweep must
    /// no longer target it.
    #[tokio::test]
    async fn group_signaling_stops_after_natural_exit() {
        let mut child = spawn_sh("exit 0");
        natural_exit(&mut child).await;
        assert!(child.process_group_id().is_none());
        assert_eq!(
            child.signal(libc::SIGTERM).unwrap_err().kind(),
            std::io::ErrorKind::NotFound
        );
    }

    /// `try_wait` reaps too — the same guard must engage.
    #[tokio::test]
    async fn group_signaling_stops_after_try_wait() {
        let mut child = spawn_sh("exit 0");
        let status = loop {
            if let Some(s) = child.try_wait().expect("try_wait") {
                break s;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        };
        assert!(status.success());
        assert!(child.process_group_id().is_none());
        assert_eq!(
            child.signal(libc::SIGTERM).unwrap_err().kind(),
            std::io::ErrorKind::NotFound
        );
    }

    /// While the leader is still alive the group must stay signalable —
    /// the reaped guard must not regress descendant cleanup.
    #[tokio::test]
    async fn group_is_signaled_while_leader_lives() {
        let mut child = spawn_sh("sleep 30");
        assert!(child.process_group_id().is_some());
        child.signal(libc::SIGKILL).expect("signal group");
        let status = natural_exit(&mut child).await;
        assert!(status.code().is_none(), "SIGKILL leaves no exit code");
    }
}
