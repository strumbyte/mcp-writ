//! `mcp-writ unotify-run` — the PR-07 Linux IP-layer PoC.
//!
//! Launches `-- <command>` under the ordinary Linux sandbox pipeline
//! (`no_new_privs` → Landlock → seccomp) plus a seccomp
//! user-notification filter on `connect(2)`, supervised in-process by
//! [`crate::warden::unotify`]. Wiring mirrors the `run`/`dns-gate`
//! pre-launch contract: policy load/bind → tracing → audit sink →
//! `guard.started`/`policy.loaded` → supervise → `guard.stopped`. The
//! command is not an MCP session — no `session.*`/`server.*` records
//! apply; denied connects emit `sandbox.network_denied` with the
//! launch's correlation id.
//!
//! Fail-closed ordering: capability and policy checks refuse before
//! spawn; supervisor loss or a dead fail-closed audit sink kill the
//! supervised child rather than let it continue unenforced.

use crate::cli::UnotifyArgs;

/// Entry point for the `unotify-run` subcommand. Always exits the
/// process (like `run`/`dns-gate`).
pub async fn run_unotify(args: UnotifyArgs) -> ! {
    imp::run(args).await
}

#[cfg(target_os = "linux")]
mod imp {
    use std::time::Duration;

    use super::UnotifyArgs;
    use crate::runtime::lifecycle::{self, SessionAuditContext};
    use crate::verifier::fail_on::{FailOn, NONE_STARTUP_WARNING};
    use crate::warden::unotify::{
        self, GrantSource, IpLayerEvaluator, Supervisor, SupervisorConfig, SupervisorEnd,
        SupervisorExit, SupervisorStats,
    };

    /// How the supervised run ended — the select arm that fired.
    enum RunExit {
        /// The child exited on its own.
        Child(std::io::Result<std::process::Output>),
        /// The supervisor loop died — the child must be killed
        /// (its connects are already ENOSYS at the kernel).
        SupervisorLost {
            reason: String,
            stats: SupervisorStats,
        },
        /// SIGINT/SIGTERM arrived — forwarded to the supervised tree.
        Signal { signo: i32, code: i32 },
        /// The fail-closed audit sink failed mid-run.
        AuditFailed,
    }

    pub async fn run(args: UnotifyArgs) -> ! {
        let launch_id = uuid::Uuid::now_v7();
        let mut session_audit = SessionAuditContext::pre_policy(launch_id, "mcp-writ-unotify");

        // An explicitly requested report that cannot be written must
        // never exit successfully — validate the destination before
        // anything runs (same contract as `run --report`).
        if let Some(path) = &args.report
            && let Err(e) = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(path)
        {
            eprintln!("Error: cannot write report to '{}': {e}", path.display());
            std::process::exit(1);
        }
        // The report writer captures the fixed identifiers; each call
        // stamps the current state + counters.
        let report_path = args.report.clone();
        let allowlist_path = args.allowlist.clone();
        let write_report = move |state: &str,
                                 reason: Option<&str>,
                                 policy: Option<&crate::policy::Policy>,
                                 ctx: Option<&crate::audit_log::PolicyAuditContext>,
                                 stats: Option<&SupervisorStats>| {
            let Some(path) = &report_path else {
                return;
            };
            let body = unotify::report_json(
                launch_id,
                state,
                reason,
                policy,
                ctx,
                allowlist_path.as_deref(),
                stats,
            );
            if let Err(e) = std::fs::write(path, body + "\n") {
                eprintln!("Error: failed to write report to '{}': {e}", path.display());
            }
        };

        let fail_on = match FailOn::resolve_from_process_env(None) {
            Ok(v) => v,
            Err(e) => {
                let detail = e.to_string();
                eprintln!("Error: {e}");
                write_report("failed", Some(&detail), None, None, None);
                lifecycle::prelaunch_abort(
                    args.audit_log.as_deref(),
                    &session_audit,
                    None,
                    &detail,
                )
                .await;
                std::process::exit(1);
            }
        };
        if fail_on == FailOn::None {
            eprintln!("{NONE_STARTUP_WARNING}");
        }

        // Policy load + bind — the workload launches natively, so the
        // policy validates against this host the same way `run` does.
        let policy = match crate::policy::loader::load_policy_or_default_for_target(
            args.policy.as_deref(),
            &crate::execution::ExecutionTarget::native(),
        ) {
            Ok(p) => p,
            Err(e) => {
                let detail = format!("failed to load policy: {e}");
                eprintln!("Error loading policy: {e}");
                write_report("failed", Some(&detail), None, None, None);
                lifecycle::prelaunch_abort(
                    args.audit_log.as_deref(),
                    &session_audit,
                    Some("load"),
                    &detail,
                )
                .await;
                std::process::exit(1);
            }
        };
        let policy = match policy.bind_to_server(args.server.as_deref()) {
            Ok(p) => p,
            Err(e) => {
                let detail = format!("failed to bind policy to server: {e}");
                eprintln!("Error binding policy to server: {e}");
                write_report("failed", Some(&detail), None, None, None);
                lifecycle::prelaunch_abort(
                    args.audit_log.as_deref(),
                    &session_audit,
                    Some("bind"),
                    &detail,
                )
                .await;
                std::process::exit(1);
            }
        };
        let policy_context = match policy.audit_context() {
            Ok(ctx) => Some(ctx),
            Err(e) => {
                eprintln!("Warning: could not compute effective policy hash: {e}");
                None
            }
        };

        let trace_level = if args.verbose > 0 {
            match args.verbose {
                1 => tracing::Level::DEBUG,
                _ => tracing::Level::TRACE,
            }
        } else {
            crate::policy::tracing_level_from_policy(&policy.logging.level)
        };
        crate::commands::tracing_init::init_tracing_with_level(trace_level);

        if policy.logging.fail_closed && args.audit_log.is_none() {
            let detail =
                "--audit-log <path> is required when logging.fail_closed is true (the default)"
                    .to_string();
            eprintln!("Error: {detail}");
            write_report(
                "failed",
                Some(&detail),
                Some(&policy),
                policy_context.as_ref(),
                None,
            );
            lifecycle::prelaunch_abort(args.audit_log.as_deref(), &session_audit, None, &detail)
                .await;
            std::process::exit(1);
        }

        let audit_logger = match args.audit_log {
            Some(ref path) => {
                let sync_mode = if args.audit_sync {
                    crate::audit_log::AuditSyncMode::EveryEvent
                } else {
                    crate::audit_log::AuditSyncMode::Buffered
                };
                match crate::audit_log::AuditLogger::to_file_with_options(
                    path,
                    policy.logging.fail_closed,
                    sync_mode,
                ) {
                    Ok(logger) => logger,
                    Err(e) => {
                        let detail = format!("failed to open audit log '{}': {e}", path.display());
                        eprintln!("Error: {detail}");
                        write_report(
                            "failed",
                            Some(&detail),
                            Some(&policy),
                            policy_context.as_ref(),
                            None,
                        );
                        lifecycle::prelaunch_abort(None, &session_audit, None, &detail).await;
                        std::process::exit(1);
                    }
                }
            }
            None => crate::audit_log::AuditLogger::to_tracing(),
        };

        session_audit.policy = policy_context.clone();
        let mut started_extra = String::from("unotify=true");
        if args.audit_sync {
            started_extra.push_str(" audit_sync=true");
        }
        lifecycle::guard_started(&audit_logger, &session_audit, Some(started_extra.as_str()));
        lifecycle::policy_loaded(
            &audit_logger,
            &session_audit,
            policy.version,
            fail_on.as_str(),
            policy.sandbox.allow_degraded,
            &args
                .policy
                .as_ref()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|| "default".into()),
        );

        // Capability probe — refuses with an explicit diagnostic when
        // the kernel lacks user notification or CONTINUE. There is no
        // silent degrade: an unsupported launch stops here, audited.
        if let Err(reason) = unotify::check_support() {
            eprintln!("Error: seccomp user notification unsupported: {reason}");
            write_report(
                "unsupported",
                Some(&reason),
                Some(&policy),
                policy_context.as_ref(),
                None,
            );
            lifecycle::guard_stopped(
                &audit_logger,
                &session_audit,
                "failed",
                Some(2),
                Some(&reason),
            );
            audit_logger.shutdown().await;
            std::process::exit(2);
        }

        // The policy's IP-layer projection — refuses rules this layer
        // would silently widen (port-qualified allows).
        let evaluator = match IpLayerEvaluator::new(&policy.network.outbound) {
            Ok(e) => e,
            Err(detail) => {
                eprintln!("Error: {detail}");
                write_report(
                    "invalid-policy",
                    Some(&detail),
                    Some(&policy),
                    policy_context.as_ref(),
                    None,
                );
                lifecycle::guard_stopped(
                    &audit_logger,
                    &session_audit,
                    "failed",
                    Some(2),
                    Some(&detail),
                );
                audit_logger.shutdown().await;
                std::process::exit(2);
            }
        };

        // Spawn the workload under the sandbox + notification filter.
        let spawned = match unotify::spawn_supervised(&policy, &args.command) {
            Ok(s) => s,
            Err(e) => {
                let detail = format!("supervised spawn failed: {e}");
                eprintln!("Error: {detail}");
                write_report(
                    "failed",
                    Some(&detail),
                    Some(&policy),
                    policy_context.as_ref(),
                    None,
                );
                lifecycle::guard_stopped(
                    &audit_logger,
                    &session_audit,
                    "failed",
                    Some(1),
                    Some(&detail),
                );
                audit_logger.shutdown().await;
                std::process::exit(1);
            }
        };
        let child_pid = spawned.child.id() as i32;
        // The wait runs on a blocking thread that owns the handle; the
        // select loop talks to the child by pid only (group signals)
        // and to this task for the exit status.
        let mut wait_task = tokio::task::spawn_blocking(move || spawned.child.wait_with_output());

        let mut supervisor = match Supervisor::start(
            spawned.listener,
            SupervisorConfig {
                evaluator,
                grants: match &args.allowlist {
                    Some(p) => GrantSource::SnapshotFile(p.clone()),
                    None => GrantSource::None,
                },
                logger: audit_logger.clone(),
                launch_id,
                policy_context: policy_context.clone(),
            },
        ) {
            Ok(s) => s,
            Err(e) => {
                let detail = format!("supervisor start failed: {e}");
                eprintln!("Error: {detail}");
                kill_group(child_pid);
                let _ = wait_task.await;
                write_report(
                    "failed",
                    Some(&detail),
                    Some(&policy),
                    policy_context.as_ref(),
                    None,
                );
                lifecycle::guard_stopped(
                    &audit_logger,
                    &session_audit,
                    "failed",
                    Some(1),
                    Some(&detail),
                );
                audit_logger.shutdown().await;
                std::process::exit(1);
            }
        };
        write_report(
            "running",
            None,
            Some(&policy),
            policy_context.as_ref(),
            None,
        );

        // Wait on: child exit | supervisor loss | signal | audit-sink
        // failure. The fail-closed arms kill the supervised tree.
        let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("SIGTERM handler");
        let audit_watch = audit_logger.clone();
        let outcome = tokio::select! {
            res = &mut wait_task => match res {
                Ok(st) => RunExit::Child(st),
                Err(e) => RunExit::SupervisorLost {
                    reason: format!("child wait task failed: {e}"),
                    stats: SupervisorStats::default(),
                },
            },
            end = supervisor.exited() => match end {
                Ok(SupervisorEnd { reason: SupervisorExit::Lost(m), stats }) => {
                    RunExit::SupervisorLost { reason: m, stats }
                }
                Ok(SupervisorEnd { reason: SupervisorExit::Shutdown, stats }) => {
                    // The stop fd is only written by `shutdown` — a
                    // Shutdown without one is a corrupted stop signal;
                    // treat it as a lost supervisor either way.
                    RunExit::SupervisorLost {
                        reason: "supervisor exited without a stop request".to_string(),
                        stats,
                    }
                }
                Err(e) => RunExit::SupervisorLost {
                    reason: format!("supervisor task failed: {e}"),
                    stats: SupervisorStats::default(),
                },
            },
            _ = tokio::signal::ctrl_c() => RunExit::Signal { signo: libc::SIGINT, code: 130 },
            _ = sigterm.recv() => RunExit::Signal { signo: libc::SIGTERM, code: 143 },
            _ = async {
                loop {
                    tokio::time::sleep(Duration::from_millis(200)).await;
                    if audit_watch.is_failed() {
                        break;
                    }
                }
            } => RunExit::AuditFailed,
        };

        let (status, detail, exit_code, stats) = match outcome {
            RunExit::Child(st) => {
                // Child gone — nothing left to supervise.
                let end = supervisor.shutdown().await;
                use std::os::unix::process::ExitStatusExt;
                let code = match st {
                    Ok(out) => out
                        .status
                        .code()
                        .unwrap_or_else(|| 128 + out.status.signal().unwrap_or(0)),
                    Err(_) => 1,
                };
                ("completed", None, code, Some(end.stats))
            }
            RunExit::SupervisorLost { reason, stats } => {
                let detail = format!("supervisor lost — supervised child killed: {reason}");
                eprintln!("Error: {detail}");
                kill_group(child_pid);
                let _ = wait_task.await;
                ("failed", Some(detail), 1, Some(stats))
            }
            RunExit::Signal { signo, code } => {
                // Forward the signal to the supervised process group,
                // then give the child a moment before the hard kill.
                unsafe {
                    libc::kill(-child_pid, signo);
                }
                if (tokio::time::timeout(Duration::from_secs(5), &mut wait_task).await).is_err() {
                    kill_group(child_pid);
                    let _ = wait_task.await;
                }
                let end = supervisor.shutdown().await;
                ("interrupted", None, code, Some(end.stats))
            }
            RunExit::AuditFailed => {
                let detail = "audit sink failed while the run was live (fail-closed): \
                     supervised child killed"
                    .to_string();
                eprintln!("Error: {detail}");
                kill_group(child_pid);
                let _ = wait_task.await;
                let end = supervisor.shutdown().await;
                ("failed", Some(detail), 1, Some(end.stats))
            }
        };

        write_report(
            status,
            detail.as_deref(),
            Some(&policy),
            policy_context.as_ref(),
            stats.as_ref(),
        );
        lifecycle::guard_stopped(
            &audit_logger,
            &session_audit,
            status,
            Some(exit_code),
            detail.as_deref(),
        );
        audit_logger.shutdown().await;
        std::process::exit(exit_code);
    }

    /// SIGKILL the supervised process group — the child was spawned
    /// with `process_group(0)`, so `-pid` reaches the whole tree.
    fn kill_group(pid: i32) {
        // Safety: signal to a pgid/pid; ESRCH on an exited group is fine.
        unsafe {
            libc::kill(-pid, libc::SIGKILL);
            libc::kill(pid, libc::SIGKILL);
        }
    }
}

#[cfg(not(target_os = "linux"))]
mod imp {
    use super::UnotifyArgs;

    /// `unotify-run` compiles elsewhere for CLI/help parity but refuses
    /// to run — the mechanism is Linux seccomp user notification.
    pub async fn run(_args: UnotifyArgs) -> ! {
        eprintln!(
            "Error: `unotify-run` is a Linux-only PoC (seccomp user notification); \
             this build has no notification filter"
        );
        std::process::exit(1);
    }
}
