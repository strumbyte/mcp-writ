//! Child process lifecycle management.
//!
//! [`ChildProcess`] is the unified synchronous child type; [`RunningChild`]
//! wraps a spawned child for async proxying. Both preserve the wait/kill
//! contract: `wait` / `kill` / `Drop` tear down the child's process group
//! (SIGKILL on unix) before reaping. `wait_for_natural_exit` and `try_wait`
//! observe the child's own lifetime without signaling the leader — but once
//! a natural exit is observed the retained process group is still killed, so
//! descendants the leader spawned cannot outlive the session.

#[cfg(target_os = "macos")]
use super::macos_sandbox;
#[cfg(target_os = "windows")]
use super::windows_sandbox;

/// Unified child process type that works across all platforms.
///
/// On macOS/Linux, the child is a standard `std::process::Child`.
/// On Windows, an AppContainer-sandboxed process uses a custom `WindowsChild`
/// because `std::process::Child` cannot be constructed from raw handles in
/// stable Rust.
pub enum ChildProcess {
    Standard(std::process::Child),
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
    pub fn wait(&mut self) -> std::io::Result<std::process::ExitStatus> {
        match self {
            ChildProcess::Standard(child) => child.wait(),
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
                kill_unix_process_group(child.id());
                child.kill()
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
            ChildProcess::Standard(child) => Some(child.id()),
            #[cfg(target_os = "macos")]
            ChildProcess::Macos(child) => Some(child.id()),
            #[cfg(target_os = "windows")]
            ChildProcess::Windows(child) => child.id(),
        }
    }

    /// Take the child's stdin handle, leaving `None` in its place.
    pub fn take_stdin(&mut self) -> Option<ChildStdin> {
        match self {
            ChildProcess::Standard(child) => child.stdin.take().map(ChildStdin::Standard),
            #[cfg(target_os = "macos")]
            ChildProcess::Macos(child) => child.stdin.take().map(ChildStdin::Standard),
            #[cfg(target_os = "windows")]
            ChildProcess::Windows(child) => child.stdin.take().map(ChildStdin::Windows),
        }
    }

    /// Take the child's stdout handle, leaving `None` in its place.
    pub fn take_stdout(&mut self) -> Option<ChildStdout> {
        match self {
            ChildProcess::Standard(child) => child.stdout.take().map(ChildStdout::Standard),
            #[cfg(target_os = "macos")]
            ChildProcess::Macos(child) => child.stdout.take().map(ChildStdout::Standard),
            #[cfg(target_os = "windows")]
            ChildProcess::Windows(child) => child.stdout.take().map(ChildStdout::Windows),
        }
    }

    /// Check if stdin is available.
    pub fn has_stdin(&self) -> bool {
        match self {
            ChildProcess::Standard(child) => child.stdin.is_some(),
            #[cfg(target_os = "macos")]
            ChildProcess::Macos(child) => child.stdin.is_some(),
            #[cfg(target_os = "windows")]
            ChildProcess::Windows(child) => child.stdin.is_some(),
        }
    }

    /// Check if stdout is available.
    pub fn has_stdout(&self) -> bool {
        match self {
            ChildProcess::Standard(child) => child.stdout.is_some(),
            #[cfg(target_os = "macos")]
            ChildProcess::Macos(child) => child.stdout.is_some(),
            #[cfg(target_os = "windows")]
            ChildProcess::Windows(child) => child.stdout.is_some(),
        }
    }
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
    #[cfg(target_os = "macos")]
    pub(super) _tmpdir: Option<macos_sandbox::PrivateTmpDir>,
}

pub(super) enum RunningChildInner {
    Tokio(Box<tokio::process::Child>),
    #[cfg(target_os = "windows")]
    Windows(std::sync::Arc<windows_sandbox::WindowsChild>),
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
    /// report", so `si_pid` distinguishes the two.
    #[cfg(unix)]
    fn exited_unreaped(&self) -> bool {
        let Some(pid) = self.id() else {
            return false;
        };
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        unsafe {
            libc::waitid(
                libc::P_PID,
                pid as libc::id_t,
                &mut info,
                libc::WEXITED | libc::WNOWAIT | libc::WNOHANG,
            ) == 0
                && info.si_pid() == pid as libc::pid_t
        }
    }

    /// SIGKILL the child's whole process group by the pgid captured at
    /// spawn, then sweep descendants that escaped the group via
    /// `setpgid`/`setsid` while their ancestry is still inspectable.
    /// Harmless once the group is empty — but skipped entirely once
    /// the leader has been reaped, since the freed pid/pgid could by
    /// then name a recycled group belonging to someone else.
    #[cfg(unix)]
    fn kill_descendants(&self) {
        if self.reaped {
            return;
        }
        if let Some(pgid) = self.process_group_id() {
            kill_unix_process_group(pgid);
        }
        #[cfg(target_os = "linux")]
        if let Some(root) = self.id() {
            kill_proc_descendants(root);
        }
    }

    pub async fn kill(&mut self) -> std::io::Result<()> {
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
    pub async fn wait_for_natural_exit(&mut self) -> std::io::Result<std::process::ExitStatus> {
        #[cfg(unix)]
        if !self.reaped {
            self.sweep_group_after_exit().await;
        }
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
                let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
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

impl Drop for RunningChild {
    fn drop(&mut self) {
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
            inner: RunningChildInner::Tokio(Box::new(child)),
            pgid,
            reaped: false,
            #[cfg(target_os = "macos")]
            _tmpdir: None,
        }
    }

    /// A reaped leader frees its pid — the recorded pgid could belong
    /// to a recycled group, so `signal` and the descendant sweep must
    /// no longer target it.
    #[tokio::test]
    async fn group_signaling_stops_after_natural_exit() {
        let mut child = spawn_sh("exit 0");
        child.wait_for_natural_exit().await.expect("natural exit");
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
        let status = child.wait_for_natural_exit().await.expect("wait");
        assert!(status.code().is_none(), "SIGKILL leaves no exit code");
    }
}
