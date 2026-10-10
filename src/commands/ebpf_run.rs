//! `mcp-writ ebpf-run` — the PR-10 opt-in cgroup-eBPF launch.
//!
//! Launches `-- <command>` under the ordinary Linux sandbox pipeline
//! (`no_new_privs` → Landlock → seccomp) plus in-kernel IP-layer
//! enforcement: `BPF_CGROUP_INET4_CONNECT`/`INET6_CONNECT` programs
//! attached to a private cgroup the child joins in `pre_exec`. Denied
//! connects fail `EPERM` in-kernel and are observed through a ring
//! buffer the drain thread turns into `sandbox.network_denied`
//! records under the launch's correlation.
//!
//! Pre-launch contract mirrors `run`/`unotify-run`: policy load/bind →
//! tracing → audit sink → `guard.started`/`policy.loaded` → capability
//! probe → rule compile → cgroup runtime → spawn → drain →
//! `guard.stopped`.
//!
//! Fail-closed ordering: capability probes and `Runtime::prepare`
//! refuse before spawn — never a degrade to `unotify` or the ordinary
//! path; drain loss or a dead fail-closed audit sink kill the
//! supervised child rather than let it run unobserved.

use crate::cli::EbpfArgs;

/// Entry point for the `ebpf-run` subcommand. Always exits the
/// process (like `run`/`unotify-run`).
pub async fn run_ebpf(args: EbpfArgs) -> ! {
    imp::run(args).await
}

#[cfg(target_os = "linux")]
mod imp {
    use std::time::Duration;

    use super::EbpfArgs;
    use crate::runtime::lifecycle::{self, SessionAuditContext};
    use crate::verifier::fail_on::{FailOn, NONE_STARTUP_WARNING};
    use crate::warden::ebpf::{self, Drain, DrainConfig, DrainEnd, DrainExit, DrainStats, Runtime};

    /// How the supervised run ended — the select arm that fired.
    enum RunExit {
        /// The child exited on its own.
        Child(std::io::Result<std::process::Output>),
        /// The drain loop died — observability is gone (enforcement
        /// continues in-kernel); the child is killed anyway: running
        /// supervised-without-audit is not the launch contract.
        DrainLost { reason: String, stats: DrainStats },
        /// The `wait_with_output` task itself failed (JoinError). The
        /// join handle is already consumed — it must never be polled
        /// again (a completed handle can pend forever), so this is a
        /// separate variant from `DrainLost` whose arm re-awaits it.
        WaitFailed { reason: String },
        /// SIGINT/SIGTERM/SIGHUP/SIGQUIT arrived — forwarded to the
        /// supervised tree.
        Signal { signo: i32, code: i32 },
        /// The fail-closed audit sink failed mid-run.
        AuditFailed,
    }

    pub async fn run(args: EbpfArgs) -> ! {
        let launch_id = uuid::Uuid::now_v7();
        let mut session_audit = SessionAuditContext::pre_policy(launch_id, "mcp-writ-ebpf");

        // An explicitly requested report that cannot be written must
        // never exit successfully — validate the destination before
        // anything runs.
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
        let report_path = args.report.clone();
        let allowlist_path = args.allowlist.clone();
        let write_report = move |state: &str,
                                 reason: Option<&str>,
                                 policy: Option<&crate::policy::Policy>,
                                 ctx: Option<&crate::audit_log::PolicyAuditContext>,
                                 stats: Option<&DrainStats>| {
            let Some(path) = &report_path else {
                return;
            };
            let body = ebpf::report::report_json(
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
        let mut started_extra = String::from("ebpf=true");
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
        // the kernel lacks cgroup-BPF support or the caller lacks the
        // capabilities. There is no silent degrade: an unsupported
        // launch stops here, audited.
        if let Err(reason) = ebpf::check_support() {
            eprintln!("Error: cgroup eBPF route unsupported: {reason}");
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

        // The policy's IP-layer projection — refuses rule sets that
        // exceed the generated-program bound rather than silently
        // dropping rules.
        let table = match ebpf::rules::compile(&policy.network.outbound) {
            Ok(t) => t,
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

        // The authoritative capability check — every real setup step
        // runs here before any child exists.
        let runtime = match Runtime::prepare(&table) {
            Ok(rt) => rt,
            Err(e) => {
                let detail = format!("cgroup eBPF setup failed — {e}");
                eprintln!("Error: {detail}");
                write_report(
                    "unsupported",
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

        // Grants must be live before the child's first connect — the
        // drain's resync cadence is for *updates*; an allowlist-attached
        // launch whose map writes fail refuses here rather than running
        // with silently-absent grants.
        if !ebpf::sync_grants_once(&runtime, args.allowlist.as_deref()) {
            let detail = "grant map population failed — refusing to launch with \
                 silently-absent grants"
                .to_string();
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
                Some(2),
                Some(&detail),
            );
            audit_logger.shutdown().await;
            drop(runtime);
            std::process::exit(2);
        }

        // The launch contract beyond the OS sandbox — same steps as
        // `run`/`unotify-run`: resolve argv[0] to the exec'd image and
        // run verify → bind → reverify when the policy pins hashes.
        let resolved_exe = match crate::workload::resolve_command_path(&args.command[0]) {
            Ok(p) => p,
            Err(e) => {
                let detail = format!("cannot resolve command '{}': {e}", args.command[0]);
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
                drop(runtime);
                std::process::exit(1);
            }
        };
        let spawn_pin = if policy.hash_entries.is_empty() {
            None
        } else {
            let verify = || -> Result<crate::verifier::hash::SpawnPin, String> {
                let server_names: std::collections::HashSet<_> = policy
                    .hash_entries
                    .iter()
                    .map(|e| e.server_name.as_str())
                    .collect();
                for s_name in server_names {
                    crate::verifier::hash::verify_server_hashes(
                        s_name,
                        &policy.hash_entries,
                        &audit_logger,
                    )
                    .map_err(|e| format!("supply chain verification failed for '{s_name}': {e}"))?;
                }
                crate::verifier::hash::bind_launched_workload(
                    &args.command,
                    &resolved_exe,
                    &policy.hash_entries,
                    &audit_logger,
                )
                .map_err(|e| format!("supply chain verification failed: {e}"))?;
                crate::verifier::hash::reverify_immediately_before_spawn(
                    &args.command,
                    &resolved_exe,
                    &policy.hash_entries,
                    &audit_logger,
                )
                .map_err(|e| format!("supply chain verification failed at spawn: {e}"))
            };
            match verify() {
                Ok(pin) => Some(pin),
                Err(detail) => {
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
                    drop(runtime);
                    std::process::exit(1);
                }
            }
        };

        // `deny host=` name rules are name-layer only — a `connect`
        // arrives as an address, never a hostname, so they cannot act
        // at this layer regardless of a grant source. List them rather
        // than letting them look enforced (`dns-gate` is the name-layer
        // enforcement point).
        let name_only_denies: Vec<&str> = policy
            .network
            .outbound
            .denied_hosts
            .iter()
            .map(String::as_str)
            .filter(|h| *h != "*" && !crate::policy::host::host_is_ip_literal(h))
            .collect();
        if !name_only_denies.is_empty() {
            tracing::warn!(
                rules = ?name_only_denies,
                "deny host rules on names cannot act at the IP layer — \
                 they stay name-layer rules (dns-gate)"
            );
        }

        // Without a grant source, `allow host=` name rules have no way
        // to take effect at this layer — surface that instead of
        // letting them look enforced.
        if args.allowlist.is_none() {
            let name_only_allows: Vec<&str> = policy
                .network
                .outbound
                .allowed
                .iter()
                .map(String::as_str)
                .filter(|h| *h != "*" && !crate::policy::host::host_is_ip_literal(h))
                .collect();
            if !name_only_allows.is_empty() {
                tracing::warn!(
                    rules = ?name_only_allows,
                    "allow host rules on names need a name-layer grant — no \
                     --allowlist snapshot is attached, so they stay unenforced \
                     at the IP layer"
                );
            }
        }

        // Spawn under the sandbox + private-cgroup move.
        let child = match ebpf::spawn_supervised(
            &policy,
            &args.command,
            &resolved_exe,
            spawn_pin.as_ref(),
            &runtime,
        ) {
            Ok(c) => c,
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
                drop(runtime);
                std::process::exit(1);
            }
        };
        let child_pid = child.id() as i32;
        let mut wait_task = tokio::task::spawn_blocking(move || child.wait_with_output());

        let mut drain = match Drain::start(
            &runtime,
            DrainConfig {
                allowlist: args.allowlist.clone(),
                logger: audit_logger.clone(),
                launch_id,
                policy_context: policy_context.clone(),
            },
        ) {
            Ok(d) => d,
            Err(e) => {
                let detail = format!("event drain start failed: {e}");
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
                drop(runtime);
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

        let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("SIGTERM handler");
        let mut sighup = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())
            .expect("SIGHUP handler");
        let mut sigquit = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::quit())
            .expect("SIGQUIT handler");
        let audit_watch = audit_logger.clone();
        let outcome = tokio::select! {
            res = &mut wait_task => match res {
                Ok(st) => RunExit::Child(st),
                Err(e) => RunExit::WaitFailed {
                    reason: format!("child wait task failed: {e}"),
                },
            },
            end = drain.exited() => match end {
                Ok(DrainEnd { reason: DrainExit::Lost(m), stats }) => {
                    RunExit::DrainLost { reason: m, stats }
                }
                Ok(DrainEnd { reason: DrainExit::Shutdown, stats }) => {
                    RunExit::DrainLost {
                        reason: "drain exited without a stop request".to_string(),
                        stats,
                    }
                }
                Err(e) => RunExit::DrainLost {
                    reason: format!("drain task failed: {e}"),
                    stats: DrainStats::default(),
                },
            },
            _ = tokio::signal::ctrl_c() => RunExit::Signal { signo: libc::SIGINT, code: 130 },
            _ = sigterm.recv() => RunExit::Signal { signo: libc::SIGTERM, code: 143 },
            _ = sighup.recv() => RunExit::Signal { signo: libc::SIGHUP, code: 129 },
            _ = sigquit.recv() => RunExit::Signal { signo: libc::SIGQUIT, code: 131 },
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
                // Child gone — nothing left to observe. Descendants
                // that escaped the process group (setsid'd daemons,
                // orphaned workers) are still private-cgroup members
                // and still enforced: kill them while the drain can
                // still audit their last denies — `Runtime::drop`
                // would sweep them anyway, after observation stopped.
                runtime.kill_members();
                let end = drain.shutdown().await;
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
            RunExit::WaitFailed { reason } => {
                // The wait task's join already resolved — `wait_task`
                // must not be polled again. The child itself is
                // probably still running unobserved: kill the tree and
                // any cgroup stragglers.
                let detail = format!("child wait task failed — supervised child killed: {reason}");
                eprintln!("Error: {detail}");
                kill_group(child_pid);
                runtime.kill_members();
                let end = drain.shutdown().await;
                ("failed", Some(detail), 1, Some(end.stats))
            }
            RunExit::DrainLost { reason, stats } => {
                // Unlike unotify's HUP-on-dead-listener, a lost drain
                // does not mean the child died — check whether the run
                // actually completed before calling it a failure.
                match tokio::time::timeout(Duration::from_secs(2), &mut wait_task).await {
                    Ok(Ok(Ok(out))) => {
                        use std::os::unix::process::ExitStatusExt;
                        let code = out
                            .status
                            .code()
                            .unwrap_or_else(|| 128 + out.status.signal().unwrap_or(0));
                        runtime.kill_members();
                        ("completed", None, code, Some(stats))
                    }
                    Ok(Ok(Err(e))) => {
                        let detail = format!("child wait failed: {e}");
                        runtime.kill_members();
                        ("failed", Some(detail), 1, Some(stats))
                    }
                    _ => {
                        let detail = format!(
                            "event drain lost — supervised child killed (unobserved): {reason}"
                        );
                        eprintln!("Error: {detail}");
                        kill_group(child_pid);
                        runtime.kill_members();
                        let _ = wait_task.await;
                        ("failed", Some(detail), 1, Some(stats))
                    }
                }
            }
            RunExit::Signal { signo, code } => {
                unsafe {
                    libc::kill(-child_pid, signo);
                }
                if (tokio::time::timeout(Duration::from_secs(5), &mut wait_task).await).is_err() {
                    kill_group(child_pid);
                    let _ = wait_task.await;
                }
                // The forwarded signal only reached the child's
                // process group — members that escaped it (setsid)
                // stay cgroup members; sweep before teardown.
                runtime.kill_members();
                let end = drain.shutdown().await;
                ("interrupted", None, code, Some(end.stats))
            }
            RunExit::AuditFailed => {
                let detail = "audit sink failed while the run was live (fail-closed): \
                     supervised child killed"
                    .to_string();
                eprintln!("Error: {detail}");
                kill_group(child_pid);
                runtime.kill_members();
                let _ = wait_task.await;
                let end = drain.shutdown().await;
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
        // `process::exit` runs no destructors — drop the runtime so the
        // private cgroup is actually removed (its Drop impl rmdirs).
        drop(runtime);
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
    use super::EbpfArgs;

    /// `ebpf-run` compiles elsewhere for CLI/help parity but refuses
    /// to run — the mechanism is Linux cgroup eBPF.
    pub async fn run(_args: EbpfArgs) -> ! {
        eprintln!(
            "Error: `ebpf-run` is a Linux-only opt-in (cgroup eBPF connect hooks); \
             this build has no cgroup-BPF support"
        );
        std::process::exit(1);
    }
}
