//! `mcp-writ macos-proxy-run` — the PR-11 macOS opt-in PoC.
//!
//! Launches `-- <command>` under `sandbox-exec` with an SBPL profile
//! whose only outbound TCP endpoint is a loopback CONNECT proxy; the
//! proxy evaluates the policy's name/IP destination rules and dials
//! outward. Wiring mirrors the `namespaced-run` pre-launch contract:
//! policy load/bind → tracing → audit sink →
//! `guard.started`/`policy.loaded` → evaluator → listener bind →
//! proxy task → spawn → supervise → `guard.stopped`. The command is
//! not an MCP session — no `session.*`/`server.*` records apply;
//! proxy-judged refusals emit `sandbox.network_denied` (committed)
//! and established flows `sandbox.network_allowed` under the launch's
//! correlation id.
//!
//! Fail-closed ordering: helper validation, policy load/bind,
//! evaluator construction, listener bind, and spawn refuse before
//! launch; proxy-task or audit-sink loss kills the workload's process
//! group rather than let it run unenforced. The plain `run` path is
//! untouched — this subcommand is the only way onto the route.

use crate::cli::MacosProxyArgs;

/// Entry point for the `macos-proxy-run` subcommand. Always exits the
/// process (like `run`/`namespaced-run`).
pub async fn run_macos_proxy(args: MacosProxyArgs) -> ! {
    imp::run(args).await
}

#[cfg(not(target_os = "macos"))]
mod imp {
    use super::MacosProxyArgs;

    /// `macos-proxy-run` compiles elsewhere for CLI/help parity but
    /// refuses to run — the mechanism is `sandbox-exec` + loopback
    /// SBPL rules.
    pub async fn run(_args: MacosProxyArgs) -> ! {
        eprintln!(
            "Error: `macos-proxy-run` is a macOS-only opt-in (sandbox-exec + \
             loopback CONNECT proxy); this build has no macOS sandbox support"
        );
        std::process::exit(1);
    }
}

#[cfg(target_os = "macos")]
mod imp {
    use std::sync::Arc;
    use std::time::Duration;

    use super::MacosProxyArgs;
    use crate::runtime::lifecycle::{self, SessionAuditContext};
    use crate::verifier::fail_on::{FailOn, NONE_STARTUP_WARNING};
    use crate::warden::FlowGate;
    use crate::warden::IpLayerEvaluator;
    use crate::warden::macos_proxy::{
        self, ConnectProxy, ConnectProxyConfig, ProxyEndpoint, ProxyStats, SpawnLiveness,
    };

    /// How the supervised run ended — the select arm that fired.
    enum RunExit {
        /// The workload exited on its own.
        Child(std::io::Result<std::process::ExitStatus>),
        /// SIGINT/SIGTERM/SIGHUP/SIGQUIT arrived — forwarded to the
        /// workload's process group.
        Signal { signo: i32, code: i32 },
        /// The fail-closed audit sink failed mid-run.
        AuditFailed,
        /// The proxy task ended while the workload still runs — its
        /// egress is dead; tear down rather than strand the child.
        ProxyLost,
    }

    pub async fn run(args: MacosProxyArgs) -> ! {
        let launch_id = uuid::Uuid::now_v7();
        let mut session_audit = SessionAuditContext::pre_policy(launch_id, "mcp-writ-macos-proxy");

        if let Some(path) = &args.report
            && let Err(e) = crate::fspriv::write_file_atomic(path, b"")
        {
            eprintln!("Error: cannot write report to '{}': {e}", path.display());
            std::process::exit(1);
        }
        let report_path = args.report.clone();
        let stats_state: Arc<ProxyStats> = Arc::new(ProxyStats::default());
        let endpoint_state: Arc<std::sync::Mutex<Option<std::net::SocketAddr>>> =
            Arc::new(std::sync::Mutex::new(None));
        let write_report = {
            let stats_state = stats_state.clone();
            let endpoint_state = endpoint_state.clone();
            move |state: &str,
                  reason: Option<&str>,
                  policy: Option<&crate::policy::Policy>,
                  ctx: Option<&crate::audit_log::PolicyAuditContext>| {
                let Some(path) = &report_path else {
                    return true;
                };
                let body = macos_proxy::report_json(
                    launch_id,
                    state,
                    reason,
                    policy,
                    ctx,
                    *endpoint_state.lock().unwrap(),
                    Some(stats_state.as_ref()),
                );
                match crate::fspriv::write_file_atomic(path, (body + "\n").as_bytes()) {
                    Ok(()) => true,
                    Err(e) => {
                        eprintln!("Error: failed to write report to '{}': {e}", path.display());
                        false
                    }
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
        // host inside the sandbox-exec profile.
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
        // A policy source a lower-trust principal could swap or rewrite
        // grants launch authority the operator never reviewed —
        // require trusted (owned, write-restricted, replacement-
        // resistant) paths for the root document and every file it
        // reached.
        if let Err(e) = crate::policy::loader::require_trusted_policy_sources(&policy) {
            let detail = format!("refusing launch: {e}");
            eprintln!("Error: {detail}");
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

        // Fail-closed write-grant conflicts: a grant covering a file
        // this policy load read lets the workload rewrite what every
        // later launch trusts; a grant covering --report lets it
        // fabricate launch evidence.
        let launch_write_grants = policy.write_grant_spellings();
        for source in policy.source_files() {
            if let Some(conflict) = crate::audit_log::policy_source_write_conflict(
                launch_write_grants.iter().cloned(),
                &source,
            ) {
                let detail = format!(
                    "refusing launch: write grant reaches policy source '{}': {conflict}",
                    source.display()
                );
                eprintln!("Error: {detail}");
                write_report(
                    "failed",
                    Some(&detail),
                    Some(&policy),
                    policy_context.as_ref(),
                );
                lifecycle::prelaunch_abort(
                    args.audit_log.as_deref(),
                    &session_audit,
                    None,
                    &detail,
                )
                .await;
                std::process::exit(1);
            }
        }
        if let Some(ref report) = args.report
            && let Some(conflict) =
                crate::audit_log::report_write_conflict(launch_write_grants.iter().cloned(), report)
        {
            let detail = format!("refusing --report '{}': {conflict}", report.display());
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
                // A workload-writable audit sink can rewrite its own
                // record; refuse before the file opens.
                if let Some(conflict) = crate::audit_log::audit_sink_write_conflict(
                    policy.write_grant_spellings(),
                    path,
                ) {
                    let detail = format!("refusing audit log '{}': {conflict}", path.display());
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
        let mut started_extra = String::from("macos_connect_proxy=true");
        if args.audit_sync {
            started_extra.push_str(" audit_sync=true");
        }
        if policy.environment.inherit_parent {
            tracing::warn!(
                "environment.inherit-parent — the child inherits every launcher \
                 environment variable, including secrets"
            );
            started_extra.push_str(" env=inherit-parent");
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

        // The proxy-path evaluator — same verdicts as the namespaced
        // proxy's; the UDP-capable-rule warning says the profile denies
        // UDP outright on this route.
        let evaluator = match IpLayerEvaluator::new_connect_proxy(&policy.network.outbound) {
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
                let _ = audit_logger.shutdown().await;
                std::process::exit(2);
            }
        };

        // Resolve argv[0] + run the hash-pin chain — same launch
        // contract as `run`/`namespaced-run` (a `#!` script expands to
        // its pinned interpreter launch when hashes are configured).
        let (command_argv, resolved_exe) = match crate::workload::resolve_launch(
            &args.command[0],
            !policy.hash_entries.is_empty(),
        ) {
            Ok(resolution) => (resolution.into_argv(&args.command), resolution.exe),
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
                let _ = audit_logger.shutdown().await;
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
                    &command_argv,
                    &resolved_exe,
                    &policy.hash_entries,
                    &audit_logger,
                )
                .map_err(|e| format!("supply chain verification failed: {e}"))?;
                crate::verifier::hash::reverify_immediately_before_spawn(
                    &command_argv,
                    &resolved_exe,
                    &policy.hash_entries,
                    &audit_logger,
                    // No mount handoff on this route — the entrypoint's
                    // trusted-source gate stays required.
                    false,
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
                    let _ = audit_logger.shutdown().await;
                    std::process::exit(1);
                }
            }
        };
        let _held_spawn_pin = spawn_pin;

        // A hash-pinned launch execs the verified *executable's*
        // snapshot — the spawn sees the staged copy's owner-only path
        // (macOS has no exec'able fd spelling), never the workload
        // pathname it could race a swap against (F75). A pinned
        // entrypoint script instead keeps its real path inside argv
        // (`exec_argv` re-spells the payload arg): the interpreter
        // realpaths its main module and resolves sibling/relative
        // imports from its directory, which a staged copy in an empty
        // dir cannot carry — the real path's read grant comes from the
        // payload package dirs `code_map_dirs` derives plus the
        // policy's own fs grants. The plan is held for the session so
        // the staged exe path still resolves at the child's execve;
        // `_held_fd_exec_plan`'s drop removes the staging dirs.
        let fd_exec_plan = match &_held_spawn_pin {
            Some(pin) => match pin.fd_exec_plan(&command_argv, &resolved_exe) {
                Ok(plan) => Some(plan),
                Err(e) => {
                    let detail = format!("fd exec plan failed: {e}");
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
                    let _ = audit_logger.shutdown().await;
                    std::process::exit(1);
                }
            },
            None => None,
        };
        let _held_fd_exec_plan = fd_exec_plan;
        let (spawn_exe, spawn_argv) = match &_held_fd_exec_plan {
            Some(plan) => (plan.exe_path().to_path_buf(), plan.exec_argv(&command_argv)),
            None => (resolved_exe.clone(), command_argv.clone()),
        };

        // Bind the loopback listener before the profile is built — the
        // port is baked into the SBPL rule, so it must exist already.
        let listener = match tokio::net::TcpListener::bind(std::net::SocketAddr::new(
            std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            args.listen_port,
        ))
        .await
        {
            Ok(l) => l,
            Err(e) => {
                let detail = format!(
                    "CONNECT proxy bind on 127.0.0.1:{} failed: {e}",
                    args.listen_port
                );
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
                let _ = audit_logger.shutdown().await;
                std::process::exit(1);
            }
        };
        let endpoint = ProxyEndpoint {
            addr: listener
                .local_addr()
                .expect("bound listener has an address"),
            token: macos_proxy::new_proxy_token(),
        };
        *endpoint_state.lock().unwrap() = Some(endpoint.addr);

        // The grant table the proxy mints name→IP entries into and the
        // FlowGate consults per CONNECT flow — in-process, so a minted
        // grant is authoritative the moment the resolver answers.
        let grants = Arc::new(crate::dnsgate::DynamicAllowList::new(
            crate::dnsgate::server::DEFAULT_MAX_GRANTS,
        ));
        let gate = FlowGate::new(
            evaluator,
            grants.clone(),
            audit_logger.clone(),
            launch_id,
            policy_context.clone(),
        );
        let proxy = Arc::new(ConnectProxy::new(ConnectProxyConfig {
            listener,
            expected_auth: macos_proxy::expected_auth(&endpoint.token),
            gate,
            grants,
            outbound: Arc::new(policy.network.outbound.clone()),
            stats: stats_state.clone(),
        }));
        let mut proxy_task = tokio::spawn(async move { proxy.run().await });

        // Spawn the workload under the proxy-pinned profile — the env
        // restriction + proxy env injection are part of the launch
        // contract.
        let mut spawn_opts = crate::warden::SpawnOptions {
            restrict_environment: policy.environment.restrict,
            allowed_names: policy.environment.allowed.clone(),
            tmpdir: None,
            exec_uncloak_fds: _held_fd_exec_plan
                .as_ref()
                .map(|p| p.uncloak_fds())
                .unwrap_or_default(),
            // macOS execs the staged exe copy by path — the sandbox
            // profile must grant each staging dir.
            exec_map_dirs: _held_fd_exec_plan
                .as_ref()
                .map(|p| p.staged_dirs().to_vec())
                .unwrap_or_default(),
            // The bind-mount handoff exists only on Linux.
            exec_entry_pin: None,
            // The staged exe's `@executable_path`-relative rpaths
            // resolve against the staging dir — restore the real
            // install prefix as dyld's fallback so shared builds
            // (e.g. libnode.dylib) still link under a relocated exec.
            exec_dyld_fallback: _held_fd_exec_plan
                .as_ref()
                .map(|p| {
                    crate::warden::macos_sandbox::staged_exec_dyld_fallback_dirs(
                        p.exe_path(),
                        &resolved_exe,
                    )
                })
                .unwrap_or_default(),
        };
        // Plus the dirs dyld will load the runtime's own libraries and
        // modules from — without exec-map on them the child dies in dyld.
        spawn_opts
            .exec_map_dirs
            .extend(crate::warden::macos_sandbox::code_map_dirs(
                &resolved_exe,
                &command_argv,
            ));
        // The allowlist-gap warning `run` prints — same contract, same
        // stderr surface on this front-end too.
        crate::warden::warn_env_allowlist_gaps(&spawn_opts);
        // Register the signal streams before the child exists — a
        // signal landing between the spawn and stream creation would
        // otherwise take the default disposition, killing the
        // supervisor while the sandboxed group outlives it. A signal
        // that arrives before the select polls the stream is buffered
        // and still forwards.
        let mut sigint = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
            .expect("SIGINT handler");
        let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("SIGTERM handler");
        let mut sighup = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())
            .expect("SIGHUP handler");
        let mut sigquit = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::quit())
            .expect("SIGQUIT handler");
        // Re-stat right before the exec chain: the fd plan pins the
        // launched bytes, so this catches the descriptor having been
        // severed since verification rather than any pathname race.
        if let Some(pin) = &_held_spawn_pin
            && let Err(e) = pin.verify_spawn_path(&resolved_exe)
        {
            let detail = format!("supply chain re-verification failed: {e}");
            eprintln!("Error: {detail}");
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
            let _ = audit_logger.shutdown().await;
            std::process::exit(1);
        }
        let launched = match macos_proxy::spawn_proxy_child(
            &policy,
            Some(&spawn_exe),
            &spawn_argv[0],
            &spawn_argv[1..],
            &spawn_opts,
            &endpoint,
        )
        .await
        {
            Ok(c) => c,
            Err(e) => {
                let detail = format!("proxy-mode spawn failed: {e}");
                eprintln!("Error: {detail}");
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
                let _ = audit_logger.shutdown().await;
                std::process::exit(1);
            }
        };
        let child_pgid = launched.pgid;
        // An exit inside the liveness window is ambiguous — a rejected
        // profile and a workload that simply finished quickly look the
        // same (the native path documents exactly this). Record it and
        // take the workload's own exit status rather than refusing a
        // legitimate short-lived workload.
        let early_exit = match &launched.liveness {
            SpawnLiveness::Exited(status) => Some(*status),
            _ => None,
        };
        if early_exit.is_some() {
            tracing::warn!(
                "Warden: sandbox-exec child exited inside the initial-exit \
                 window — profile rejection, exec failure, or a workload \
                 that simply finished quickly all surface this way"
            );
        }
        write_report("running", None, Some(&policy), policy_context.as_ref());

        // Wait on: workload exit | signal | audit-sink failure | proxy
        // loss. The failure arms kill the workload's process group —
        // its egress is loopback-only either way, so group kill is
        // about not stranding it, not about closing a wider hole.
        let mut child = launched.child;
        let wait_fut = child.wait();
        tokio::pin!(wait_fut);
        let audit_watch = audit_logger.clone();
        let outcome = if let Some(status) = early_exit {
            // The leader already exited inside the liveness window —
            // sweep the group so descendants it spawned do not
            // outlive the supervised run. A still-live member answers
            // kill(-pgid); an empty group yields ESRCH. A fresh
            // process inheriting the reaped pid could in principle
            // form a same-numbered group — the narrow, inherent
            // kill-by-pgid race the select paths share; `pgid > 0`
            // keeps `-0` from ever naming the launcher's own group.
            kill_group(child_pgid);
            RunExit::Child(Ok(status))
        } else {
            tokio::select! {
                res = &mut wait_fut => RunExit::Child(res),
                _ = sigint.recv() => RunExit::Signal { signo: libc::SIGINT, code: 130 },
                _ = sigterm.recv() => RunExit::Signal { signo: libc::SIGTERM, code: 143 },
                _ = sighup.recv() => RunExit::Signal { signo: libc::SIGHUP, code: 129 },
                _ = sigquit.recv() => RunExit::Signal { signo: libc::SIGQUIT, code: 131 },
                _ = async {
                    let mut fail_watch = audit_watch.failure_watch();
                    loop {
                        if audit_watch.is_failed() {
                            break;
                        }
                        if fail_watch.changed().await.is_err() {
                            std::future::pending::<()>().await;
                        }
                    }
                } => RunExit::AuditFailed,
                _ = &mut proxy_task => RunExit::ProxyLost,
            }
        };

        let (exit_code, final_state, reason) = match outcome {
            RunExit::Child(Ok(status)) => {
                // The leader is reaped — sweep the group too, so a
                // workload that exits while leaving descendants does
                // not strand them past the supervised run (the same
                // pgid-reuse caveat as the early-exit sweep applies).
                kill_group(child_pgid);
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
            RunExit::Child(Err(e)) => {
                kill_group(child_pgid);
                (1, "failed", Some(format!("child wait failed: {e}")))
            }
            RunExit::Signal { signo, code } => {
                if child_pgid > 0 {
                    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
                    unsafe { libc::kill(-child_pgid, signo) };
                }
                if (tokio::time::timeout(Duration::from_secs(5), &mut wait_fut).await).is_err() {
                    kill_group(child_pgid);
                    let _ = wait_fut.await;
                }
                // The forwarded signal is a graceful request: a member
                // that trapped it to clean up (print, flush, close)
                // loses to an immediate SIGKILL, so give the group a
                // bounded window to finish after the leader is reaped
                // — then sweep whatever still outlived it (a member
                // may have caught or ignored the signal) before the
                // supervisor itself exits.
                let grace = std::time::Instant::now() + Duration::from_millis(500);
                while child_pgid > 0
                    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
                    && unsafe { libc::kill(-child_pgid, 0) } == 0
                    && std::time::Instant::now() < grace
                {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
                kill_group(child_pgid);
                (code, "stopped", Some(format!("signal {signo} forwarded")))
            }
            RunExit::AuditFailed => {
                kill_group(child_pgid);
                let _ = wait_fut.await;
                (
                    1,
                    "failed",
                    Some("fail-closed audit sink failed".to_string()),
                )
            }
            RunExit::ProxyLost => {
                kill_group(child_pgid);
                let _ = wait_fut.await;
                (1, "failed", Some("egress proxy task ended".to_string()))
            }
        };

        proxy_task.abort();

        // A requested report that cannot be written must never pair
        // with a success status.
        let report_ok = write_report(
            final_state,
            reason.as_deref(),
            Some(&policy),
            policy_context.as_ref(),
        );
        let final_code = if exit_code >= 0 && report_ok {
            exit_code
        } else {
            1
        };
        lifecycle::guard_stopped(
            &audit_logger,
            &session_audit,
            final_state,
            Some(final_code),
            reason.as_deref(),
        );
        // A terminal audit flush failure must not exit successfully.
        let final_code = match audit_logger.shutdown().await {
            Err(e) => {
                tracing::error!("audit shutdown failed (fail-closed): {e}");
                if final_code == 0 { 1 } else { final_code }
            }
            Ok(()) => final_code,
        };
        std::process::exit(final_code);
    }

    /// SIGKILL the workload's process group — the child was spawned
    /// with `process_group(0)`, so `-pgid` reaches the whole tree.
    /// `pgid == 0` (the child was reaped before its id could be read)
    /// must never reach `kill`: `-0` names the *launcher's* group.
    fn kill_group(pgid: i32) {
        if pgid > 0 {
            // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
            unsafe { libc::kill(-pgid, libc::SIGKILL) };
        }
    }
}
