//! `mcp-writ namespaced-run` — the PR-09 Linux namespaced-egress PoC.
//!
//! Launches `-- <command>` through `namespaced-init` (userns+netns+
//! mountns + TUN) and runs the in-process TCP/UDP policy proxy. Wiring
//! mirrors the `unotify-run` pre-launch contract: policy load/bind →
//! tracing → audit sink → `guard.started`/`policy.loaded` → capability
//! probe → spawn → supervise → `guard.stopped`. The command is not an
//! MCP session — no `session.*`/`server.*` records apply; allowed
//! flows emit `sandbox.network_allowed` (buffered) and denied ones
//! `sandbox.network_denied` under the launch's correlation id.
//!
//! Fail-closed ordering: capability, policy, and handshake failures
//! refuse before/instead of launch; proxy or audit-sink loss kills the
//! namespaced child rather than let it continue unenforced (its only
//! egress device dies with the fd anyway).

use crate::cli::NamespacedArgs;

/// Entry point for the `namespaced-run` subcommand. Always exits the
/// process (like `run`/`unotify-run`).
pub async fn run_namespaced(args: NamespacedArgs) -> ! {
    imp::run(args).await
}

/// Internal entry point for the init helper (`main` dispatches before
/// the CLI parse — this name never reaches `parse_args`).
#[cfg(target_os = "linux")]
pub fn namespaced_init_entry() -> i32 {
    crate::warden::namespaced::init_entry()
}

/// Internal entry point for the capability probe helper.
#[cfg(target_os = "linux")]
pub fn namespaced_probe_entry() -> i32 {
    crate::warden::namespaced::probe_entry()
}

// `pub` (not `pub(crate)`) so the binary crate's early dispatch can
// match on them — they name internal entry points, not a user CLI.
#[cfg(target_os = "linux")]
pub const INIT_SUBCOMMAND: &str = "namespaced-init";
#[cfg(target_os = "linux")]
pub const PROBE_SUBCOMMAND: &str = "namespaced-probe";

#[cfg(not(target_os = "linux"))]
mod imp {
    use super::NamespacedArgs;

    /// `namespaced-run` compiles elsewhere for CLI/help parity but
    /// refuses to run — the mechanism is Linux namespaces + TUN.
    pub async fn run(_args: NamespacedArgs) -> ! {
        eprintln!(
            "Error: `namespaced-run` is a Linux-only PoC (userns+netns+TUN); \
             this build has no namespace support"
        );
        std::process::exit(1);
    }
}

#[cfg(target_os = "linux")]
mod imp {
    use std::io::Write;
    use std::sync::Arc;
    use std::time::Duration;

    use super::NamespacedArgs;
    use crate::runtime::lifecycle::{self, SessionAuditContext};
    use crate::verifier::fail_on::{FailOn, NONE_STARTUP_WARNING};
    use crate::warden::namespaced::{self, ProxyConfig, ProxyStats, SpawnConfig};
    use crate::warden::unotify::IpLayerEvaluator;

    /// How the supervised run ended — the select arm that fired.
    enum RunExit {
        /// The workload exited on its own.
        Child(std::io::Result<std::process::ExitStatus>),
        /// SIGINT/SIGTERM/SIGHUP/SIGQUIT arrived — forwarded to the
        /// namespaced tree.
        Signal { signo: i32, code: i32 },
        /// The fail-closed audit sink failed mid-run.
        AuditFailed,
        /// The proxy task ended while the workload still runs — its
        /// egress is dead; tear down rather than strand the child.
        ProxyLost,
    }

    pub async fn run(args: NamespacedArgs) -> ! {
        let launch_id = uuid::Uuid::now_v7();
        let mut session_audit = SessionAuditContext::pre_policy(launch_id, "mcp-writ-namespaced");

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
        // The probe result is captured at capability-check time so the
        // final report shows what the launch actually saw.
        let probe_state: Arc<std::sync::Mutex<Option<namespaced::ProbeReport>>> =
            Arc::new(std::sync::Mutex::new(None));
        let stats_state: Arc<std::sync::Mutex<Option<ProxyStats>>> =
            Arc::new(std::sync::Mutex::new(None));
        let sandbox_state: Arc<std::sync::Mutex<Option<bool>>> =
            Arc::new(std::sync::Mutex::new(None));
        let write_report = {
            let probe_state = probe_state.clone();
            let stats_state = stats_state.clone();
            let sandbox_state = sandbox_state.clone();
            move |state: &str,
                  reason: Option<&str>,
                  policy: Option<&crate::policy::Policy>,
                  ctx: Option<&crate::audit_log::PolicyAuditContext>| {
                let Some(path) = &report_path else {
                    return;
                };
                let body = namespaced::report::report_json(
                    launch_id,
                    state,
                    reason,
                    policy,
                    ctx,
                    probe_state.lock().unwrap().as_ref(),
                    stats_state.lock().unwrap().as_ref(),
                    *sandbox_state.lock().unwrap(),
                );
                if let Err(e) = std::fs::write(path, body + "\n") {
                    eprintln!("Error: failed to write report to '{}': {e}", path.display());
                }
            }
        };

        let fail_on = match FailOn::resolve_from_process_env(None) {
            Ok(v) => v,
            Err(e) => {
                let detail = e.to_string();
                eprintln!("Error: {e}");
                write_report("failed", Some(&detail), None, None);
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

        // Policy load + bind — native target: the child runs on this
        // host, inside namespaces that do not change policy semantics.
        let policy = match crate::policy::loader::load_policy_or_default_for_target(
            args.policy.as_deref(),
            &crate::execution::ExecutionTarget::native(),
        ) {
            Ok(p) => p,
            Err(e) => {
                let detail = format!("failed to load policy: {e}");
                eprintln!("Error loading policy: {e}");
                write_report("failed", Some(&detail), None, None);
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
                write_report("failed", Some(&detail), None, None);
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
                        );
                        lifecycle::prelaunch_abort(None, &session_audit, None, &detail).await;
                        std::process::exit(1);
                    }
                }
            }
            None => crate::audit_log::AuditLogger::to_tracing(),
        };

        session_audit.policy = policy_context.clone();
        let mut started_extra = String::from("namespaced=true");
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

        // Capability probe — real setup in a throwaway process. Any
        // missing stage refuses: no degraded namespace exists to fall
        // back to.
        match namespaced::run_probe() {
            Ok(rep) => {
                if !rep.capable() {
                    let reason = rep
                        .reason()
                        .unwrap_or_else(|| "namespaced capability probe incomplete".into());
                    *probe_state.lock().unwrap() = Some(rep);
                    eprintln!("Error: {reason}");
                    write_report(
                        "unsupported",
                        Some(&reason),
                        Some(&policy),
                        policy_context.as_ref(),
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
                *probe_state.lock().unwrap() = Some(rep);
            }
            Err(detail) => {
                eprintln!("Error: capability probe failed: {detail}");
                write_report(
                    "unsupported",
                    Some(&detail),
                    Some(&policy),
                    policy_context.as_ref(),
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
        }

        // The namespaced evaluator — same verdicts as unotify's,
        // without the datagram-visibility warning (this layer does see
        // every datagram).
        let evaluator = match IpLayerEvaluator::new_namespaced(&policy.network.outbound) {
            Ok(e) => e,
            Err(detail) => {
                eprintln!("Error: {detail}");
                write_report(
                    "invalid-policy",
                    Some(&detail),
                    Some(&policy),
                    policy_context.as_ref(),
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

        // Resolve argv[0] + run the hash-pin chain — same launch
        // contract as `run`/`unotify-run`.
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
            }
        };
        // The pin's identity re-check must happen while init still
        // holds the verified object — init execs `resolved_exe` and
        // the pin stays open across the whole supervised lifetime.
        let _held_spawn_pin = spawn_pin;

        // Effective policy → read-only memfd — init rebuilds its
        // Landlock/seccomp bits from byte-identical policy.
        let policy_kdl_fd = match make_policy_memfd(&policy) {
            Ok(f) => f,
            Err(e) => {
                let detail = format!("policy serialization for init failed: {e}");
                eprintln!("Error: {detail}");
                write_report(
                    "failed",
                    Some(&detail),
                    Some(&policy),
                    policy_context.as_ref(),
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

        // The environment restriction is part of the launch contract —
        // applies identically in the namespaced child (init forwards
        // the filtered block, minus its own MCP_WRIT_NS_* vars).
        let spawn_opts = crate::warden::SpawnOptions {
            restrict_environment: policy.environment.restrict,
            allowed_names: policy.environment.allowed.clone(),
            tmpdir: None,
        };
        let env_pairs = crate::warden::spawn_env_pairs(&spawn_opts);

        // Spawn the init helper; complete the handshake.
        let spawn_res = {
            let cfg = SpawnConfig {
                argv: args.command.clone(),
                resolved_exe: resolved_exe.clone(),
                policy_kdl_fd,
                env: env_pairs,
            };
            tokio::task::spawn_blocking(move || namespaced::spawn_namespaced_child(&cfg))
                .await
                .unwrap_or_else(|e| Err(format!("spawn task failed: {e}")))
        };
        let mut launched = match spawn_res {
            Ok(c) => c,
            Err(detail) => {
                eprintln!("Error: namespaced spawn failed: {detail}");
                write_report(
                    "failed",
                    Some(&detail),
                    Some(&policy),
                    policy_context.as_ref(),
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
        let child_pid = launched.pid();

        // Build the embedded DNS gate + the shared grant table the
        // proxy evaluates against — in-process, so a minted grant is
        // authoritative the moment the answer relays (no snapshot hop).
        let allowlist = Arc::new(crate::dnsgate::DynamicAllowList::new(
            crate::dnsgate::server::DEFAULT_MAX_GRANTS,
        ));
        let gate_core = Arc::new(crate::dnsgate::server::QueryCore::new(
            crate::dnsgate::GateConfig {
                upstream: args.upstream.expect("upstream validated by parse"),
                refusal: crate::dnsgate::Refusal::Refused,
                allowlist_export: None,
                ..Default::default()
            },
            Arc::new(policy.network.outbound.clone()),
            allowlist.clone(),
            audit_logger.clone(),
            launch_id,
            policy_context.clone(),
        ));

        // Start the proxy before GO — a workload that starts dialing
        // before its packets have anywhere to go would just see black
        // holes, but ordering keeps the semantics exact.
        // The stats handle is shared by `Arc` — the report reads live
        // counters, so an aborted proxy still reports what it measured.
        let proxy_stats = namespaced::ProxyStats::default();
        *stats_state.lock().unwrap() = Some(proxy_stats.clone());
        // The proxy needs its own TUN handle — a clone failure (e.g.
        // EMFILE) is a launch failure, not a panic: the namespaced
        // child dies by group kill like every other refused stage.
        let proxy_tun = match launched.tun.try_clone() {
            Ok(f) => f,
            Err(e) => {
                let detail = format!("tun clone for the proxy failed: {e}");
                eprintln!("Error: {detail}");
                kill_group(child_pid);
                let _ = launched.child.wait();
                write_report(
                    "failed",
                    Some(&detail),
                    Some(&policy),
                    policy_context.as_ref(),
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
        let mut proxy_task = tokio::spawn({
            let stats = proxy_stats.clone();
            let cfg = ProxyConfig {
                tun: proxy_tun,
                evaluator,
                allowlist,
                gate: Some(gate_core),
                logger: audit_logger.clone(),
                launch_id,
                policy_ctx: policy_context.clone(),
            };
            async move {
                namespaced::run_proxy(cfg, stats).await;
            }
        });

        if let Err(detail) = launched.go() {
            eprintln!("Error: {detail}");
            kill_group(child_pid);
            // The group is dead; the reap is bounded.
            let _ = launched.child.wait();
            proxy_task.abort();
            write_report(
                "failed",
                Some(&detail),
                Some(&policy),
                policy_context.as_ref(),
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
        *sandbox_state.lock().unwrap() = launched.sandbox_applied.get();
        write_report("running", None, Some(&policy), policy_context.as_ref());

        // Wait on: workload exit | signal | audit-sink failure | proxy
        // loss. The failure arms kill the namespaced tree.
        let mut wait_task = tokio::task::spawn_blocking({
            let mut child = launched.child;
            move || child.wait()
        });
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
                Err(_) => RunExit::Signal {
                    signo: -1,
                    code: 1,
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
            _ = &mut proxy_task => RunExit::ProxyLost,
        };

        let (exit_code, final_state, reason) = match outcome {
            RunExit::Child(Ok(status)) => {
                use std::os::unix::process::ExitStatusExt;
                let code = status
                    .code()
                    .unwrap_or_else(|| 128 + status.signal().unwrap_or(0));
                let state = if status.success() {
                    "stopped"
                } else {
                    "failed"
                };
                let reason = status.signal().map(|s| format!("terminated by signal {s}"));
                (code, state, reason)
            }
            RunExit::Child(Err(e)) => (1, "failed", Some(format!("child wait failed: {e}"))),
            RunExit::Signal { signo, code } => {
                if signo > 0 {
                    // Forward to the workload's process group, give it
                    // a moment, then hard-kill.
                    unsafe { libc::kill(-child_pid, signo) };
                    if (tokio::time::timeout(Duration::from_secs(5), &mut wait_task).await).is_err()
                    {
                        kill_group(child_pid);
                        let _ = wait_task.await;
                    }
                    (code, "stopped", Some(format!("signal {signo} forwarded")))
                } else {
                    (1, "failed", Some("child wait task failed".to_string()))
                }
            }
            RunExit::AuditFailed => {
                kill_group(child_pid);
                let _ = wait_task.await;
                (
                    1,
                    "failed",
                    Some("fail-closed audit sink failed".to_string()),
                )
            }
            RunExit::ProxyLost => {
                kill_group(child_pid);
                let _ = wait_task.await;
                (1, "failed", Some("egress proxy task ended".to_string()))
            }
        };

        // Dropping the tun fd ends the proxy's reader; abort to be
        // sure — `write_report` reads the counters itself.
        proxy_task.abort();

        write_report(
            final_state,
            reason.as_deref(),
            Some(&policy),
            policy_context.as_ref(),
        );
        lifecycle::guard_stopped(
            &audit_logger,
            &session_audit,
            final_state,
            Some(exit_code),
            reason.as_deref(),
        );
        audit_logger.shutdown().await;
        std::process::exit(if exit_code >= 0 { exit_code } else { 1 });
    }

    /// SIGKILL the workload's process group — init was spawned with
    /// `process_group(0)`, so `-pid` reaches the whole tree.
    fn kill_group(pid: i32) {
        unsafe { libc::kill(-pid, libc::SIGKILL) };
    }

    /// Serialize the effective policy into a read-only memfd init
    /// inherits. `memfd_create` without `MFD_CLOEXEC` — the fd must
    /// survive the exec into the helper.
    fn make_policy_memfd(policy: &crate::policy::Policy) -> std::io::Result<std::fs::File> {
        let fd = unsafe {
            libc::syscall(libc::SYS_memfd_create, c"mcp-writ-policy".as_ptr(), 0u32) as i32
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        let mut f = unsafe {
            use std::os::unix::io::FromRawFd;
            std::fs::File::from_raw_fd(fd)
        };
        let kdl = crate::policy::kdl_emit::to_kdl(policy);
        f.write_all(kdl.as_bytes())?;
        use std::io::Seek;
        f.seek(std::io::SeekFrom::Start(0))?;
        Ok(f)
    }
}
