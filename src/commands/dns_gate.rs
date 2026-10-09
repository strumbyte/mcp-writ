//! `mcp-writ dns-gate` — serve the policy-evaluating DNS resolver.
//!
//! Wiring mirrors the `run` pre-launch contract: policy load/bind →
//! tracing → audit sink → `guard.started`/`policy.loaded` bracket →
//! serve → `guard.stopped`. The gate is a long-running service, not a
//! launch — no `session.started`/`server.*` records apply; every
//! emitted `sandbox.*` record carries the logger `session_id` in
//! `details`, so gate decisions correlate to this bracket.

use crate::cli::DnsGateArgs;
use crate::dnsgate::{DynamicAllowList, GateConfig};
use crate::policy::loader::load_policy_or_default_for_resolver;
use crate::runtime::lifecycle::{self, SessionAuditContext};
use crate::verifier::fail_on::{FailOn, NONE_STARTUP_WARNING};

/// Entry point for the `dns-gate` subcommand. Always exits the process
/// (like the `run` path) — the only "return" is a graceful shutdown.
pub async fn run_dns_gate(args: DnsGateArgs) -> ! {
    let launch_id = uuid::Uuid::now_v7();
    let mut session_audit = SessionAuditContext::pre_policy(launch_id, "mcp-writ-dns-gate");

    // `upstream` stays optional in the args type so "unspecified" is
    // representable — the parser requires the flag, and a caller that
    // bypassed it is refused here before anything else starts: no
    // implicit resolver may ever stand in for an explicit one.
    let upstream = match args.upstream {
        Some(u) => u,
        None => {
            let detail = "dns-gate requires --upstream <ip>[:port] — an explicit upstream resolver"
                .to_string();
            eprintln!("Error: {detail}");
            lifecycle::prelaunch_abort(args.audit_log.as_deref(), &session_audit, None, &detail)
                .await;
            std::process::exit(1);
        }
    };

    let fail_on = match FailOn::resolve_from_process_env(None) {
        Ok(v) => v,
        Err(e) => {
            let detail = e.to_string();
            eprintln!("Error: {e}");
            lifecycle::prelaunch_abort(args.audit_log.as_deref(), &session_audit, None, &detail)
                .await;
            std::process::exit(1);
        }
    };
    if fail_on == FailOn::None {
        eprintln!("{NONE_STARTUP_WARNING}");
    }

    // Policy load + bind — required for this command (parse enforces
    // the flag); a refused load emits `policy.error` under this
    // launch's correlation id, same contract as `run`. The resolver
    // load is document-validated, not workload-OS validated: the gate
    // launches nothing and is itself the name-layer enforcement that
    // e.g. AppContainer lacks, so refusing a name-ruled policy here
    // would make the broker unusable exactly where it is needed.
    let policy = match load_policy_or_default_for_resolver(args.policy.as_deref()) {
        Ok(p) => p,
        Err(e) => {
            let detail = format!("failed to load policy: {e}");
            eprintln!("Error loading policy: {e}");
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
        lifecycle::prelaunch_abort(args.audit_log.as_deref(), &session_audit, None, &detail).await;
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
                    lifecycle::prelaunch_abort(None, &session_audit, None, &detail).await;
                    std::process::exit(1);
                }
            }
        }
        None => crate::audit_log::AuditLogger::to_tracing(),
    };

    session_audit.policy = policy_context.clone();
    let started_extra = args.audit_sync.then_some("audit_sync=true");
    lifecycle::guard_started(&audit_logger, &session_audit, started_extra);
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

    let config = GateConfig {
        listen: args.listen,
        upstream,
        refusal: args.refusal,
        allowlist_export: args.allowlist_export.clone(),
        ..GateConfig::default()
    };
    let allowlist = std::sync::Arc::new(DynamicAllowList::new(config.max_grants));

    // Which signal stopped the gate decides the exit code — the
    // conventional 128+signo (SIGINT 130, SIGTERM 143). `serve` only
    // waits on the future, so the code crosses on the side: the
    // shutdown future resolves only after storing it.
    let exit_code = std::sync::Arc::new(std::sync::atomic::AtomicI32::new(130));
    let code = exit_code.clone();
    let result = crate::dnsgate::serve(
        config,
        policy,
        allowlist,
        audit_logger.clone(),
        session_audit.launch_id,
        session_audit.policy.clone(),
        async move {
            code.store(
                shutdown_signal().await,
                std::sync::atomic::Ordering::Relaxed,
            );
        },
    )
    .await;

    match result {
        Ok(()) => {
            // A graceful stop is a signal (SIGINT/SIGTERM) — the same
            // outcome vocabulary as `run`'s interrupted bracket.
            let code = exit_code.load(std::sync::atomic::Ordering::Relaxed);
            lifecycle::guard_stopped(
                &audit_logger,
                &session_audit,
                "interrupted",
                Some(code),
                None,
            );
            audit_logger.shutdown().await;
            std::process::exit(code);
        }
        Err(e) => {
            let detail = format!("dns gate failed: {e}");
            eprintln!("Error: {detail}");
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
}

/// SIGINT (all platforms) or SIGTERM (unix) — the ordinary stop for a
/// long-running gate. Returns the conventional exit code, 128+signo:
/// 130 on SIGINT, 143 on SIGTERM.
async fn shutdown_signal() -> i32 {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut sigterm = signal(SignalKind::terminate()).ok();
        tokio::select! {
            _ = tokio::signal::ctrl_c() => 130,
            _ = async {
                match &mut sigterm {
                    Some(s) => { s.recv().await; }
                    None => std::future::pending::<()>().await,
                }
            } => 143,
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
        130
    }
}
