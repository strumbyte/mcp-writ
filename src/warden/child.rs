//! Child process lifecycle management.
//!
//! [`ChildProcess`] is the unified synchronous child type; [`RunningChild`]
//! wraps a spawned child for async proxying. Both preserve the wait/kill
//! contract: `wait` / `kill` / `Drop` tear down the child's process group
//! (SIGKILL on unix) before reaping, while `wait_for_natural_exit` and
//! `try_wait` observe the child's own lifetime without signaling it.

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

    pub async fn kill(&mut self) -> std::io::Result<()> {
        #[cfg(unix)]
        if let Some(pid) = self.id() {
            kill_unix_process_group(pid);
        }
        match &mut self.inner {
            RunningChildInner::Tokio(child) => child.kill().await,
            #[cfg(target_os = "windows")]
            RunningChildInner::Windows(child) => {
                let c = child.clone();
                tokio::task::spawn_blocking(move || c.kill())
                    .await
                    .map_err(|e| std::io::Error::other(e.to_string()))?
            }
        }
    }

    /// Wait for the child to exit without sending SIGKILL first.
    ///
    /// Use this whenever the caller must observe the child's own lifetime
    /// (`mcp-writ run` / `mcp-secure-runner` select, self-test EACCES/SIGSYS,
    /// SIGTERM/SIGINT grace). [`Self::wait`] tears down the process group and
    /// must not be polled as "wait until the MCP server exits".
    pub async fn wait_for_natural_exit(&mut self) -> std::io::Result<std::process::ExitStatus> {
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

    /// Non-blocking poll for a natural exit (no SIGKILL).
    pub fn try_wait(&mut self) -> std::io::Result<Option<std::process::ExitStatus>> {
        match &mut self.inner {
            RunningChildInner::Tokio(child) => child.try_wait(),
            #[cfg(target_os = "windows")]
            RunningChildInner::Windows(child) => child.try_wait(),
        }
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
        if let Some(pid) = self.id() {
            kill_unix_process_group(pid);
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

    pub fn id(&self) -> Option<u32> {
        match &self.inner {
            RunningChildInner::Tokio(child) => child.id(),
            #[cfg(target_os = "windows")]
            RunningChildInner::Windows(child) => child.id(),
        }
    }

    #[cfg(unix)]
    pub fn signal(&self, sig: i32) -> std::io::Result<()> {
        if let Some(pid) = self.id() {
            let ret = unsafe { libc::kill(-(pid as i32), sig) };
            if ret != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        } else {
            Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "child process has no PID",
            ))
        }
    }
}

impl Drop for RunningChild {
    fn drop(&mut self) {
        #[cfg(unix)]
        if let Some(pid) = self.id() {
            kill_unix_process_group(pid);
        }
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
fn kill_unix_process_group(pid: u32) {
    let _ = unsafe { libc::kill(-(pid as i32), libc::SIGKILL) };
}
