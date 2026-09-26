use std::path::PathBuf;

use tokio::task::JoinHandle;

use crate::audit_log::AuditLogger;
use crate::enforcement::{LaunchOutcome, LaunchReport};
use crate::error::AuditorError;
use crate::warden::RunningChild;

/// How [`wait_for_shutdown`] reacts to termination signals.
pub enum ShutdownPolicy {
    /// Host `mcp-writ run`: ctrl_c kills the child immediately, exit 130.
    /// No SIGTERM handler.
    Host,
    /// Container PID1 on Unix: forward SIGTERM/SIGINT to the child, allow a
    /// fixed grace period, then SIGKILL. Exit 143/130 or the child's own code.
    #[cfg(unix)]
    Pid1Unix,
    /// Container PID1 on non-Unix: ctrl_c kills the child, exit 130.
    Pid1NonUnix,
}

/// An explicitly requested (`--report <path>`) launch report destination.
///
/// `report` starts as the launch-time [`LaunchReport`] (`result = running`)
/// and is finalized with the observed outcome on every exit path — a
/// session's final result is recorded in the same schema as its plan.
pub struct ReportTarget {
    pub report: LaunchReport,
    pub path: PathBuf,
}

impl ReportTarget {
    /// Set `result` to `outcome`, write the JSON to `path` (replacing any
    /// existing file — each launch overwrites its report), and print a
    /// one-line human summary on stderr. The JSON never goes to stdout.
    ///
    /// Returns the process exit code to use: `code` when the write
    /// succeeded, `1` when it failed — an explicitly requested report that
    /// could not be saved must never exit successfully.
    pub fn finish(mut self, outcome: LaunchOutcome, code: i32) -> i32 {
        let status = outcome.status;
        self.report.result = Some(outcome);
        match self.report.write_to(&self.path) {
            Ok(()) => {
                eprintln!(
                    "launch report ({status}) written to {}",
                    self.path.display()
                );
                code
            }
            Err(e) => {
                eprintln!(
                    "Error: failed to write launch report to '{}': {e}",
                    self.path.display()
                );
                1
            }
        }
    }
}

/// Apply `outcome` to `target` and return the exit code to exit with.
fn finalize_report(target: Option<ReportTarget>, outcome: LaunchOutcome, code: i32) -> i32 {
    match target {
        Some(t) => t.finish(outcome, code),
        None => code,
    }
}

/// Grace period for PID1 signal forwarding before SIGKILL (fixed at 5s).
#[cfg(unix)]
const SIGNAL_GRACE_PERIOD: std::time::Duration = std::time::Duration::from_secs(5);

/// Per-binary stderr/tracing wording for the shared wait loop.
struct WaitLabels {
    /// Emit `tracing::info!("Auditor relay finished")` on clean auditor exit.
    auditor_finished: bool,
    /// Emit `tracing::info!("{label} with code {code}")` on natural child exit.
    child_exited: Option<&'static str>,
    /// `eprintln!("{prefix}: {e}")` when waiting on the child fails.
    wait_error: &'static str,
    /// `tracing::info!` emitted on ctrl_c before killing the child.
    interrupt: Option<&'static str>,
}

const HOST_LABELS: WaitLabels = WaitLabels {
    auditor_finished: true,
    child_exited: Some("MCP server exited"),
    wait_error: "Error waiting for MCP server",
    interrupt: Some("Received SIGINT, terminating MCP server"),
};

const PID1_LABELS: WaitLabels = WaitLabels {
    auditor_finished: false,
    child_exited: None,
    wait_error: "mcp-secure-runner: error waiting for child",
    interrupt: None,
};

#[cfg(unix)]
const PID1_UNIX_LABELS: WaitLabels = WaitLabels {
    auditor_finished: true,
    child_exited: Some("Child exited"),
    wait_error: "mcp-secure-runner: error waiting for child",
    // Signals are forwarded, not handled by the ctrl_c arm.
    interrupt: None,
};

/// Wait for the auditor relay, natural child exit, or a termination signal,
/// then shut down the audit logger, finalize any `--report` destination,
/// and exit the process.
///
/// `report` is `Some` only when the caller requested `--report <path>`;
/// on every exit path the session's final `result` is written to it and
/// a write failure turns a would-be-success exit into `1`.
pub async fn wait_for_shutdown(
    policy: ShutdownPolicy,
    child: RunningChild,
    auditor_handle: JoinHandle<Result<(), AuditorError>>,
    audit_logger: AuditLogger,
    report: Option<ReportTarget>,
) -> ! {
    match policy {
        ShutdownPolicy::Host => {
            wait_interruptible(child, auditor_handle, audit_logger, &HOST_LABELS, report).await
        }
        #[cfg(unix)]
        ShutdownPolicy::Pid1Unix => {
            wait_pid1_unix(child, auditor_handle, audit_logger, report).await
        }
        ShutdownPolicy::Pid1NonUnix => {
            wait_interruptible(child, auditor_handle, audit_logger, &PID1_LABELS, report).await
        }
    }
}

/// Host / non-Unix PID1 wait: auditor, natural child exit, or ctrl_c.
async fn wait_interruptible(
    mut child: RunningChild,
    auditor_handle: JoinHandle<Result<(), AuditorError>>,
    audit_logger: AuditLogger,
    labels: &WaitLabels,
    report: Option<ReportTarget>,
) -> ! {
    tokio::select! {
        result = auditor_handle => {
            let code = auditor_exit_code(result, labels.auditor_finished);
            let _ = child.kill().await;
            let _ = child.wait().await;
            audit_logger.shutdown().await;
            drop(child);
            let code = finalize_report(
                report,
                LaunchOutcome {
                    status: if code == 0 { "exited" } else { "failed" },
                    detail: Some("auditor relay finished first".to_string()),
                    exit_code: Some(code),
                },
                code,
            );
            std::process::exit(code);
        }
        status = child.wait_for_natural_exit() => {
            match status {
                Ok(s) => {
                    let code = observed_exit_code(&s);
                    if let Some(label) = labels.child_exited {
                        tracing::info!("{label} with code {code}");
                    }
                    audit_logger.shutdown().await;
                    drop(child);
                    let code = finalize_report(
                        report,
                        LaunchOutcome {
                            status: "exited",
                            detail: None,
                            exit_code: Some(code),
                        },
                        code,
                    );
                    std::process::exit(code);
                }
                Err(e) => {
                    eprintln!("{}: {e}", labels.wait_error);
                    audit_logger.shutdown().await;
                    drop(child);
                    let code = finalize_report(
                        report,
                        LaunchOutcome {
                            status: "failed",
                            detail: Some(format!("error waiting for child: {e}")),
                            exit_code: Some(1),
                        },
                        1,
                    );
                    std::process::exit(code);
                }
            }
        }
        _ = tokio::signal::ctrl_c() => {
            if let Some(msg) = labels.interrupt {
                tracing::info!("{msg}");
            }
            let _ = child.kill().await;
            audit_logger.shutdown().await;
            drop(child);
            let code = finalize_report(
                report,
                LaunchOutcome {
                    status: "interrupted",
                    detail: Some("SIGINT".to_string()),
                    exit_code: Some(130),
                },
                130,
            );
            std::process::exit(code);
        }
    }
}

/// Unix PID1 wait: auditor, natural child exit, SIGTERM, or SIGINT.
/// Signals are forwarded to the child with a fixed grace period.
#[cfg(unix)]
async fn wait_pid1_unix(
    mut child: RunningChild,
    auditor_handle: JoinHandle<Result<(), AuditorError>>,
    audit_logger: AuditLogger,
    report: Option<ReportTarget>,
) -> ! {
    use tokio::signal::unix::{SignalKind, signal};

    let mut sigterm = signal(SignalKind::terminate()).expect("failed to register SIGTERM handler");
    let mut sigint = signal(SignalKind::interrupt()).expect("failed to register SIGINT handler");

    tokio::select! {
        result = auditor_handle => {
            let code = auditor_exit_code(result, PID1_UNIX_LABELS.auditor_finished);
            let _ = child.kill().await;
            let _ = child.wait().await;
            audit_logger.shutdown().await;
            drop(child);
            let code = finalize_report(
                report,
                LaunchOutcome {
                    status: if code == 0 { "exited" } else { "failed" },
                    detail: Some("auditor relay finished first".to_string()),
                    exit_code: Some(code),
                },
                code,
            );
            std::process::exit(code);
        }
        status = child.wait_for_natural_exit() => {
            match status {
                Ok(s) => {
                    let code = observed_exit_code(&s);
                    if let Some(label) = PID1_UNIX_LABELS.child_exited {
                        tracing::info!("{label} with code {code}");
                    }
                    audit_logger.shutdown().await;
                    drop(child);
                    let code = finalize_report(
                        report,
                        LaunchOutcome {
                            status: "exited",
                            detail: None,
                            exit_code: Some(code),
                        },
                        code,
                    );
                    std::process::exit(code);
                }
                Err(e) => {
                    eprintln!("{}: {e}", PID1_UNIX_LABELS.wait_error);
                    audit_logger.shutdown().await;
                    drop(child);
                    let code = finalize_report(
                        report,
                        LaunchOutcome {
                            status: "failed",
                            detail: Some(format!("error waiting for child: {e}")),
                            exit_code: Some(1),
                        },
                        1,
                    );
                    std::process::exit(code);
                }
            }
        }
        _ = sigterm.recv() => {
            let status =
                forward_signal_with_grace(&mut child, libc::SIGTERM, "SIGTERM").await;
            audit_logger.shutdown().await;
            drop(child);
            let code = match status {
                Ok(s) => observed_exit_code(&s),
                Err(_) => 143,
            };
            let code = finalize_report(
                report,
                LaunchOutcome {
                    status: "interrupted",
                    detail: Some("SIGTERM forwarded to child".to_string()),
                    exit_code: Some(code),
                },
                code,
            );
            std::process::exit(code);
        }
        _ = sigint.recv() => {
            let status =
                forward_signal_with_grace(&mut child, libc::SIGINT, "SIGINT").await;
            audit_logger.shutdown().await;
            drop(child);
            let code = match status {
                Ok(s) => observed_exit_code(&s),
                Err(_) => 130,
            };
            let code = finalize_report(
                report,
                LaunchOutcome {
                    status: "interrupted",
                    detail: Some("SIGINT forwarded to child".to_string()),
                    exit_code: Some(code),
                },
                code,
            );
            std::process::exit(code);
        }
    }
}

/// Exit code reflecting what was actually observed for a naturally exited
/// child. A signal death reports `128 + signal` instead of a bare `1` so a
/// seccomp/Landlock kill (SIGSYS/SIGKILL) is not mistaken for an ordinary
/// application error.
fn observed_exit_code(status: &std::process::ExitStatus) -> i32 {
    if let Some(code) = status.code() {
        return code;
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        if let Some(sig) = status.signal() {
            tracing::info!("child terminated by signal {sig}");
            return 128 + sig;
        }
    }
    1
}

/// Map an auditor JoinHandle result to an exit code.
fn auditor_exit_code(
    result: Result<Result<(), AuditorError>, tokio::task::JoinError>,
    log_finished: bool,
) -> i32 {
    match result {
        Ok(Ok(())) => {
            if log_finished {
                tracing::info!("Auditor relay finished");
            }
            0
        }
        Ok(Err(e)) => {
            tracing::error!("Auditor error: {e}");
            1
        }
        Err(e) => {
            tracing::error!("Auditor task panicked: {e}");
            1
        }
    }
}

/// Forward `sig` to the child's process group, wait up to the grace period
/// for a natural exit, then SIGKILL and reap.
#[cfg(unix)]
async fn forward_signal_with_grace(
    child: &mut RunningChild,
    sig: i32,
    sig_name: &'static str,
) -> std::io::Result<std::process::ExitStatus> {
    tracing::info!("Received {sig_name}, forwarding to child");
    let _ = child.signal(sig);
    let wait_result =
        tokio::time::timeout(SIGNAL_GRACE_PERIOD, child.wait_for_natural_exit()).await;
    match wait_result {
        Ok(s) => s,
        Err(_) => {
            tracing::warn!("Child did not exit within grace period, sending SIGKILL");
            let _ = child.kill().await;
            child.wait().await
        }
    }
}

#[cfg(test)]
mod tests {
    /// `observed_exit_code` must report the observed signal as `128 + sig`,
    /// not collapse a signal death to exit code 1.
    #[cfg(unix)]
    #[test]
    fn signal_death_reports_128_plus_signal() {
        let status = std::process::Command::new("sh")
            .args(["-c", "kill -9 $$"])
            .status()
            .expect("spawn sh");
        assert!(status.code().is_none(), "killed by signal has no code");
        assert_eq!(super::observed_exit_code(&status), 128 + 9);
    }

    /// A natural child exit code propagates unchanged.
    #[cfg(unix)]
    #[test]
    fn natural_exit_code_propagates() {
        let status = std::process::Command::new("sh")
            .args(["-c", "exit 7"])
            .status()
            .expect("spawn sh");
        assert_eq!(super::observed_exit_code(&status), 7);
    }

    /// A natural child exit code propagates unchanged (Windows).
    #[cfg(windows)]
    #[test]
    fn natural_exit_code_propagates() {
        let status = std::process::Command::new("cmd")
            .args(["/c", "exit", "7"])
            .status()
            .expect("spawn cmd");
        assert_eq!(super::observed_exit_code(&status), 7);
    }
}
