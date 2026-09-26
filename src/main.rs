use mcp_writ::cli::{self, CliOutput};
use mcp_writ::container::options::{ContainerizeOptions, RunImageOptions, WrapOptions};
use mcp_writ::execution::ExecutionTarget;
use mcp_writ::policy::loader::load_policy_or_default_for_target;
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
            if let Err(e) = mcp_writ::container::runner::run_image(&RunImageOptions::from(a)).await
            {
                eprintln!("Error: {e}");
                std::process::exit(1);
            }
            return;
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

    let fail_on = match FailOn::resolve_from_process_env(args.fail_on_cli.map(|v| v.as_str())) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Error: {e}");
            std::process::exit(1);
        }
    };
    if fail_on == FailOn::None {
        eprintln!("{NONE_STARTUP_WARNING}");
    }

    // 2. Validate transport (MVP: stdio only)
    if args.transport != "stdio" {
        eprintln!(
            "Error: only 'stdio' transport is supported (got '{}')",
            args.transport
        );
        std::process::exit(1);
    }

    // 3. Load policy and bind to a single server identity.
    //    `mcp-writ run` spawns the workload natively, so the policy is
    //    validated against this host's OS — the native target.
    let policy =
        match load_policy_or_default_for_target(args.policy.as_deref(), &ExecutionTarget::native())
        {
            Ok(p) => p,
            Err(e) => {
                eprintln!("Error loading policy: {e}");
                std::process::exit(1);
            }
        };
    let policy = match policy.bind_to_server(args.server.as_deref()) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("Error binding policy to server: {e}");
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
        eprintln!(
            "Error: --audit-log <path> is required when logging.fail_closed is true (the default)"
        );
        std::process::exit(1);
    }

    // 5. Initialize audit logger
    let audit_logger = match args.audit_log {
        Some(ref path) => {
            match mcp_writ::audit_log::AuditLogger::to_file_with_fail_closed(
                path,
                policy.logging.fail_closed,
            ) {
                Ok(logger) => logger,
                Err(e) => {
                    eprintln!("Error: failed to open audit log '{}': {e}", path.display());
                    std::process::exit(1);
                }
            }
        }
        None => {
            if policy.logging.fail_closed {
                eprintln!("Error: --audit-log <path> is required when logging.fail_closed is true");
                std::process::exit(1);
            }
            mcp_writ::audit_log::AuditLogger::to_tracing()
        }
    };

    // 6. Supply chain verification, spawn, and auditor relay
    //    (shared with mcp-secure-runner via runtime::launch)
    let env_skip_sandbox = std::env::var("MCP_WRIT_SKIP_SANDBOX")
        .map(|v| {
            let v = v.trim().to_lowercase();
            v == "1" || v == "true"
        })
        .unwrap_or(false);
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
            launch_id: None,
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
            // empty success.
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
                    eprintln!("launch report: {}", report.to_json());
                    report
                }
                LaunchError::TakeIo {
                    mut child, report, ..
                } => {
                    eprintln!("Error: failed to capture child process stdin/stdout");
                    let _ = child.kill().await;
                    let _ = child.wait().await;
                    drop(child);
                    report
                }
            };
            // The pre-launch validation above already created/truncated
            // the report file, so a failure here leaves `path` as an
            // empty file — not valid JSON — while the process still
            // exits 1 for the launch failure itself.
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
        audit_logger.shutdown().await;
        std::process::exit(1);
    }
    let report_target = args
        .report
        .map(|path| mcp_writ::runtime::wait::ReportTarget {
            report: launched.report,
            path,
        });

    // 7. Wait for child exit, auditor completion, or SIGINT
    mcp_writ::runtime::wait::wait_for_shutdown(
        mcp_writ::runtime::wait::ShutdownPolicy::Host,
        launched.child,
        launched.auditor_handle,
        audit_logger,
        report_target,
    )
    .await
}
