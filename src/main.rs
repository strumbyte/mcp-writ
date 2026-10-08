use mcp_writ::cli::{self, CliOutput};
use mcp_writ::container::options::{ContainerizeOptions, RunImageOptions, WrapOptions};
use mcp_writ::execution::ExecutionTarget;
use mcp_writ::policy::loader::load_policy_or_default_for_target;
use mcp_writ::runtime::lifecycle::{self, SessionAuditContext};
use mcp_writ::verifier::fail_on::{FailOn, NONE_STARTUP_WARNING};

#[tokio::main]
async fn main() {
    // 1. Parse CLI arguments
    let args = match cli::parse_args() {
        Ok(CliOutput::Run(a)) => a,
        Ok(CliOutput::Inspect(a)) => {
            mcp_writ::commands::inspect::run_inspect(a);
            return;
        }
        Ok(CliOutput::GeneratePolicy(a)) => {
            mcp_writ::commands::generate_policy::run_generate_policy(a).await;
            return;
        }
        Ok(CliOutput::Plan(a)) => {
            mcp_writ::commands::plan::run_plan(a).await;
        }
        Ok(CliOutput::RunImage(a)) => {
            match mcp_writ::container::runner::run_image(&RunImageOptions::from(a)).await {
                // A workload that ran to an outcome exits with its own
                // code — the same value the launch report records.
                Ok(code) => std::process::exit(code),
                Err(e) => {
                    eprintln!("Error: {e}");
                    std::process::exit(1);
                }
            }
        }
        Ok(CliOutput::WrapImage(a)) => {
            match mcp_writ::container::wrap::wrap_image(&WrapOptions::from(a)).await {
                Ok(result) => {
                    println!("{result}");
                }
                Err(e) => {
                    eprintln!("Error: {e}");
                    std::process::exit(1);
                }
            }
            return;
        }
        Ok(CliOutput::Containerize(a)) => {
            match mcp_writ::container::containerize::containerize(&ContainerizeOptions::from(a))
                .await
            {
                Ok(result) => {
                    println!("{result}");
                }
                Err(e) => {
                    eprintln!("Error: {e}");
                    std::process::exit(1);
                }
            }
            return;
        }
        Ok(CliOutput::Info(msg)) => {
            print!("{msg}");
            std::process::exit(0);
        }
        Err(e) => {
            eprintln!("Error: {e}");
            std::process::exit(1);
        }
    };

    if args.isolation == Some(mcp_writ::execution::IsolationKind::WindowsSandbox) {
        let fail_on = match FailOn::resolve_from_process_env(args.fail_on_cli.map(|v| v.as_str())) {
            Ok(value) => value,
            Err(e) => {
                eprintln!("Error: {e}");
                std::process::exit(1);
            }
        };
        if fail_on == FailOn::None {
            eprintln!("{NONE_STARTUP_WARNING}");
        }
        let options = mcp_writ::container::sandbox::SandboxRunOptions {
            sandbox: args.sandbox,
            policy: args.policy,
            server: args.server,
            command: args.command,
            report: args.report,
            fail_on,
        };
        match mcp_writ::container::sandbox::run(&options).await {
            Ok(code) => std::process::exit(code),
            Err(e) => {
                eprintln!("Error: {e}");
                std::process::exit(1);
            }
        }
    }

    // Validate the --report destination up front: an explicitly requested
    // report that cannot be written must never exit successfully — and the
    // failure must surface before the workload starts, not after it ran.
    // The file is created (truncating any previous report); every launch
    // stage then overwrites it with the current state.
    if let Some(path) = &args.report
        && let Err(e) = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)
    {
        eprintln!(
            "Error: cannot write launch report to '{}': {e}",
            path.display()
        );
        std::process::exit(1);
    }

    // The launch correlation id is minted before the first fallible
    // stage so every audit record and every report — including a
    // pre-launch refusal — shares it.
    let launch_id = uuid::Uuid::now_v7();
    let mut session_audit = SessionAuditContext::pre_policy(launch_id, "mcp-writ");

    // An early exit still owes an explicitly requested --report a valid
    // JSON body: the up-front validation left a truncated (empty) file,
    // so a refused launch records a `failed` result, not a non-JSON hole.
    let report_path = args.report.clone();
    let report_dry_run = args.dry_run;
    // The launch target records the mechanism choice even for a
    // pre-launch failure report — `--windows-mechanism` must be visible
    // in the artifact a refused launch leaves behind.
    let target = match args.windows_mechanism {
        Some(m) => ExecutionTarget::native().with_native_windows_mechanism(m),
        None => ExecutionTarget::native(),
    };
    let report_target = target.clone();
    let write_prelaunch_failure =
        move |detail: String, policy: Option<mcp_writ::audit_log::PolicyAuditContext>| {
            let Some(path) = &report_path else {
                return;
            };
            let report = mcp_writ::enforcement::LaunchReport {
                schema_version: mcp_writ::enforcement::LAUNCH_REPORT_SCHEMA_VERSION,
                launch_id,
                created_at: mcp_writ::audit_log::now_iso8601_millis(),
                target: report_target.clone(),
                policy,
                dry_run: report_dry_run,
                plan: mcp_writ::enforcement::EnforcementPlan {
                    controls: Vec::new(),
                    grants: Vec::new(),
                    tools: Vec::new(),
                    limitations: vec![
                        "launch aborted before the enforcement plan was computed".to_string(),
                    ],
                },
                observations: Vec::new(),
                result: Some(mcp_writ::enforcement::LaunchOutcome {
                    status: "failed",
                    detail: Some(detail),
                    exit_code: Some(1),
                }),
                // No launch pipeline ran — identity was never assessed.
                code_identity: None,
                guest_runner: None,
                guest: None,
                isolation: None,
            };
            if let Err(e) = report.write_to(path) {
                eprintln!(
                    "Error: failed to write launch report to '{}': {e}",
                    path.display()
                );
            }
        };

    let fail_on = match FailOn::resolve_from_process_env(args.fail_on_cli.map(|v| v.as_str())) {
        Ok(v) => v,
        Err(e) => {
            let detail = e.to_string();
            eprintln!("Error: {e}");
            write_prelaunch_failure(detail.clone(), None);
            lifecycle::prelaunch_abort(args.audit_log.as_deref(), &session_audit, None, &detail)
                .await;
            std::process::exit(1);
        }
    };
    if fail_on == FailOn::None {
        eprintln!("{NONE_STARTUP_WARNING}");
    }

    // 2. Validate transport (MVP: stdio only)
    if args.transport != "stdio" {
        let detail = format!(
            "only 'stdio' transport is supported (got '{}')",
            args.transport
        );
        eprintln!("Error: {detail}");
        write_prelaunch_failure(detail.clone(), None);
        lifecycle::prelaunch_abort(args.audit_log.as_deref(), &session_audit, None, &detail).await;
        std::process::exit(1);
    }

    // 3. Load policy and bind to a single server identity.
    //    `mcp-writ run` spawns the workload natively, so the policy is
    //    validated against this host's OS — the native target. A refused
    //    load/bind is a `policy.error` under this launch's correlation id.
    let policy = match load_policy_or_default_for_target(args.policy.as_deref(), &target) {
        Ok(p) => p,
        Err(e) => {
            let detail = format!("failed to load policy: {e}");
            eprintln!("Error loading policy: {e}");
            write_prelaunch_failure(detail.clone(), None);
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
            write_prelaunch_failure(detail.clone(), None);
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
    // Policy identity for the launch report and correlated audit events.
    // A hash failure here is diagnostic-only — never blocks the launch.
    let policy_context = match policy.audit_context() {
        Ok(ctx) => Some(ctx),
        Err(e) => {
            eprintln!("Warning: could not compute effective policy hash: {e}");
            None
        }
    };

    // 4. Initialize tracing based on verbosity or policy.logging.level
    let trace_level = if args.verbose > 0 {
        match args.verbose {
            1 => tracing::Level::DEBUG,
            _ => tracing::Level::TRACE,
        }
    } else {
        mcp_writ::policy::tracing_level_from_policy(&policy.logging.level)
    };
    mcp_writ::commands::tracing_init::init_tracing_with_level(trace_level);
    tracing::info!("Policy loaded (version {})", policy.version);

    if policy.logging.fail_closed && args.audit_log.is_none() {
        let detail =
            "--audit-log <path> is required when logging.fail_closed is true (the default)"
                .to_string();
        eprintln!("Error: {detail}");
        write_prelaunch_failure(detail.clone(), policy_context.clone());
        lifecycle::prelaunch_abort(args.audit_log.as_deref(), &session_audit, None, &detail).await;
        std::process::exit(1);
    }

    // MCP_WRIT_SKIP_SANDBOX / --dry-run downgrade what the launch
    // enforces; the flags are read before the sink opens so
    // guard.started can record them.
    let env_skip_sandbox = std::env::var("MCP_WRIT_SKIP_SANDBOX")
        .map(|v| {
            let v = v.trim().to_lowercase();
            v == "1" || v == "true"
        })
        .unwrap_or(false);

    // 5. Initialize audit logger, then open the lifecycle bracket:
    //    `guard.started` records the sink's open (with the sandbox
    //    bypass / dry-run flags in details), `policy.loaded` the policy
    //    and fail_on dial that gate this launch.
    let audit_logger = match args.audit_log {
        Some(ref path) => {
            match mcp_writ::audit_log::AuditLogger::to_file_with_fail_closed(
                path,
                policy.logging.fail_closed,
            ) {
                Ok(logger) => logger,
                Err(e) => {
                    let detail = format!("failed to open audit log '{}': {e}", path.display());
                    eprintln!("Error: {detail}");
                    write_prelaunch_failure(detail.clone(), policy_context.clone());
                    // The sink path just failed to open and the failure
                    // was already reported — the abort bracket goes to
                    // the tracing sink rather than re-opening (and
                    // re-reporting) the same path.
                    lifecycle::prelaunch_abort(None, &session_audit, None, &detail).await;
                    std::process::exit(1);
                }
            }
        }
        None => {
            if policy.logging.fail_closed {
                let detail =
                    "--audit-log <path> is required when logging.fail_closed is true".to_string();
                eprintln!("Error: {detail}");
                write_prelaunch_failure(detail.clone(), policy_context.clone());
                lifecycle::prelaunch_abort(None, &session_audit, None, &detail).await;
                std::process::exit(1);
            }
            mcp_writ::audit_log::AuditLogger::to_tracing()
        }
    };

    session_audit.policy = policy_context.clone();
    let mut started_extra = String::new();
    if env_skip_sandbox {
        started_extra.push_str("sandbox=skipped via MCP_WRIT_SKIP_SANDBOX");
    }
    if args.dry_run {
        if !started_extra.is_empty() {
            started_extra.push(' ');
        }
        started_extra.push_str("dry_run=true");
    }
    lifecycle::guard_started(
        &audit_logger,
        &session_audit,
        (!started_extra.is_empty()).then_some(started_extra.as_str()),
    );
    let policy_source = args
        .policy
        .as_ref()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| "default".to_string());
    lifecycle::policy_loaded(
        &audit_logger,
        &session_audit,
        policy.version,
        fail_on.as_str(),
        policy.sandbox.allow_degraded,
        &policy_source,
    );

    // 6. Supply chain verification, spawn, and auditor relay
    //    (shared with mcp-secure-runner via runtime::launch)
    let skip_sandbox = args.dry_run || env_skip_sandbox;
    let skip_reason = if skip_sandbox {
        Some(match (args.dry_run, env_skip_sandbox) {
            (true, true) => "dry-run and MCP_WRIT_SKIP_SANDBOX",
            (true, false) => "dry-run",
            (false, true) => "MCP_WRIT_SKIP_SANDBOX",
            (false, false) => "unspecified",
        })
    } else {
        None
    };
    let launched = match mcp_writ::runtime::launch::launch(
        mcp_writ::runtime::launch::LaunchConfig {
            argv: args.command,
            policy,
            fail_on,
            dry_run: args.dry_run,
            skip_sandbox,
            skip_reason,
            spawned_log_label: "MCP server spawned",
            policy_context,
            launch_id: Some(launch_id),
            // A native run inherits the machine's temp configuration —
            // the guest contract's TMPDIR override is the runner's job.
            workload_tmpdir: None,
            windows_mechanism: args.windows_mechanism,
            component: "mcp-writ",
        },
        &audit_logger,
    )
    .await
    {
        Ok(l) => l,
        Err(e) => {
            use mcp_writ::runtime::launch::LaunchError;
            // Every launch failure carries the plan plus a `failed`
            // result — a `--report` write records exactly that, never an
            // empty success. The same report goes to stderr for every
            // variant, so a failure is diagnosable without --report too.
            let report = match e {
                LaunchError::ResolveCommand {
                    command,
                    source,
                    report,
                } => {
                    eprintln!("Error: cannot resolve command '{command}': {source}");
                    report
                }
                LaunchError::VerifyServerHashes {
                    server_name,
                    source,
                    report,
                } => {
                    eprintln!("Supply chain verification failed for '{server_name}': {source}");
                    report
                }
                LaunchError::BindLaunchedWorkload { source, report } => {
                    eprintln!("Supply chain verification failed: {source}");
                    report
                }
                LaunchError::ReverifyBeforeSpawn { source, report } => {
                    eprintln!("Supply chain verification failed at spawn: {source}");
                    report
                }
                LaunchError::Spawn {
                    argv,
                    source,
                    report,
                } => {
                    let command_name = argv.first().map(String::as_str).unwrap_or("(empty)");
                    eprintln!("Error: failed to spawn MCP server '{command_name}': {source}");
                    report
                }
                LaunchError::TakeIo { mut child, report } => {
                    eprintln!("Error: failed to capture child process stdin/stdout");
                    let _ = child.kill().await;
                    let _ = child.wait().await;
                    drop(child);
                    report
                }
            };
            eprintln!("launch report: {}", report.to_json());
            if let Some(path) = &args.report {
                match report.write_to(path) {
                    Ok(()) => {
                        eprintln!("launch report (failed) written to {}", path.display())
                    }
                    Err(e2) => eprintln!(
                        "Error: failed to write launch report to '{}': {e2}",
                        path.display()
                    ),
                }
            }
            // The launch already emitted `server.error`; close the guard
            // bracket with the same failed outcome the report carries.
            lifecycle::guard_stopped(
                &audit_logger,
                &session_audit,
                "failed",
                Some(1),
                report.result.as_ref().and_then(|r| r.detail.as_deref()),
            );
            audit_logger.shutdown().await;
            std::process::exit(1);
        }
    };

    // The report reflects the running session until the wait loop
    // rewrites it with the final result.
    if let Some(path) = &args.report
        && let Err(e) = launched.report.write_to(path)
    {
        eprintln!(
            "Error: failed to write launch report to '{}': {e}",
            path.display()
        );
        // A session whose report cannot be recorded must not exit
        // successfully — kill the just-spawned child and fail now.
        let mut child = launched.child;
        let _ = child.kill().await;
        let _ = child.wait().await;
        drop(child);
        launched.auditor_handle.abort();
        let outcome = mcp_writ::enforcement::LaunchOutcome {
            status: "failed",
            detail: Some(format!("failed to write launch report: {e}")),
            exit_code: Some(1),
        };
        lifecycle::teardown(&audit_logger, &launched.session_audit, "killed", &outcome).await;
        std::process::exit(1);
    }
    let report_target = args
        .report
        .map(|path| mcp_writ::runtime::wait::ReportTarget {
            report: launched.report,
            path,
        });

    // 7. Wait for child exit, auditor completion, or SIGINT. The wait
    //    loop closes the audit bracket (server.disconnected →
    //    session.ended → guard.stopped) on every exit path.
    mcp_writ::runtime::wait::wait_for_shutdown(
        mcp_writ::runtime::wait::ShutdownPolicy::Host,
        launched.child,
        launched.auditor_handle,
        audit_logger,
        launched.session_audit,
        report_target,
    )
    .await
}
