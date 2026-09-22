use std::path::Path;

use mcp_writ::audit_log;
use mcp_writ::execution::ExecutionTarget;
use mcp_writ::policy::loader::load_policy_for_target;
use mcp_writ::verifier::fail_on::{FailOn, NONE_STARTUP_WARNING};

const POLICY_PATH: &str = "/etc/mcp-secure/policy.kdl";

#[tokio::main]
async fn main() {
    // 1. Load policy from /etc/mcp-secure/policy.kdl and re-validate it
    //    against the OS this process actually runs on (the guest OS).
    //    Whatever target name the host used at export time cannot stand in
    //    for this check.
    let policy = match load_policy_for_target(Path::new(POLICY_PATH), &ExecutionTarget::native()) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("mcp-secure-runner: failed to load policy: {e}");
            std::process::exit(1);
        }
    };

    // 2. Initialize tracing with policy logging level to stderr
    let log_level = mcp_writ::policy::tracing_level_from_policy(&policy.logging.level);
    mcp_writ::commands::tracing_init::init_tracing_with_level(log_level);

    tracing::info!("Policy loaded (version {})", policy.version);

    let fail_on = match FailOn::resolve_from_process_env(None) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("mcp-secure-runner: {e}");
            std::process::exit(1);
        }
    };
    if fail_on == FailOn::None {
        eprintln!("{NONE_STARTUP_WARNING}");
    }

    let host_server = std::env::var("MCP_WRIT_SERVER")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    // SAFETY: no other threads have been spawned yet besides the tokio runtime;
    // inherited image ENV must not skip the sandbox or override the host server bind.
    unsafe {
        std::env::remove_var("MCP_WRIT_ENV");
        std::env::remove_var("MCP_WRIT_SKIP_SANDBOX");
    }

    let policy = match policy.bind_to_server(host_server.as_deref()) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("mcp-secure-runner: failed to bind policy to server: {e}");
            std::process::exit(1);
        }
    };

    // 3. Read MCP_ORIG_ENTRYPOINT and MCP_ORIG_CMD environment variables
    let entrypoint_raw = std::env::var("MCP_ORIG_ENTRYPOINT").unwrap_or_default();
    let cmd_raw = std::env::var("MCP_ORIG_CMD").unwrap_or_default();

    // 4. Parse and combine into the original command line
    let mut argv = match mcp_writ::runtime::argv::parse_shell_or_json(&entrypoint_raw) {
        Ok(args) => args,
        Err(e) => {
            eprintln!("mcp-secure-runner: {e}");
            std::process::exit(1);
        }
    };
    match mcp_writ::runtime::argv::parse_shell_or_json(&cmd_raw) {
        Ok(args) => argv.extend(args),
        Err(e) => {
            eprintln!("mcp-secure-runner: {e}");
            std::process::exit(1);
        }
    };

    if argv.is_empty() {
        eprintln!(
            "mcp-secure-runner: no command to run (MCP_ORIG_ENTRYPOINT and MCP_ORIG_CMD are both empty)"
        );
        std::process::exit(1);
    }
    tracing::info!("Restored command: {:?}", argv);

    // Set up audit logger (file if /var/log/mcp-secure exists, otherwise stderr tracing)
    let audit_log_dir = Path::new("/var/log/mcp-secure");
    let audit_logger = if audit_log_dir.is_dir() {
        let log_file = audit_log_dir.join("audit.jsonl");
        match audit_log::AuditLogger::to_file_with_fail_closed(
            &log_file,
            policy.logging.fail_closed,
        ) {
            Ok(logger) => {
                tracing::info!("Audit log enabled: {}", log_file.display());
                logger
            }
            Err(e) => {
                eprintln!("mcp-secure-runner: failed to open audit log: {e}");
                if policy.logging.fail_closed {
                    std::process::exit(1);
                }
                audit_log::AuditLogger::to_tracing()
            }
        }
    } else if policy.logging.fail_closed {
        eprintln!(
            "mcp-secure-runner: audit log directory '{}' is required when logging.fail_closed is true",
            audit_log_dir.display()
        );
        std::process::exit(1);
    } else {
        audit_log::AuditLogger::to_tracing()
    };

    // 5. Supply chain verification, spawn, and auditor relay
    //    (shared with mcp-writ run via runtime::launch)
    let launched = match mcp_writ::runtime::launch::launch(
        mcp_writ::runtime::launch::LaunchConfig {
            argv,
            policy,
            fail_on,
            dry_run: false,
            skip_sandbox: false,
            skip_reason: None,
            spawned_log_label: "Child process spawned",
        },
        &audit_logger,
    )
    .await
    {
        Ok(l) => l,
        Err(e) => {
            use mcp_writ::runtime::launch::LaunchError;
            match e {
                LaunchError::ResolveCommand { command, source } => {
                    eprintln!("mcp-secure-runner: cannot resolve command '{command}': {source}");
                }
                LaunchError::VerifyServerHashes {
                    server_name,
                    source,
                } => {
                    eprintln!(
                        "mcp-secure-runner: supply chain verification failed for '{server_name}': {source}"
                    );
                }
                LaunchError::BindLaunchedWorkload { source } => {
                    eprintln!("mcp-secure-runner: supply chain verification failed: {source}");
                }
                LaunchError::ReverifyBeforeSpawn { source } => {
                    eprintln!(
                        "mcp-secure-runner: supply chain verification failed at spawn: {source}"
                    );
                }
                LaunchError::Spawn { argv, source } => {
                    eprintln!(
                        "mcp-secure-runner: failed to spawn child process '{argv:?}': {source}"
                    );
                }
                LaunchError::TakeIo { mut child } => {
                    eprintln!("mcp-secure-runner: failed to capture child stdin/stdout");
                    let _ = child.kill().await;
                    let _ = child.wait().await;
                    drop(child);
                }
            }
            audit_logger.shutdown().await;
            std::process::exit(1);
        }
    };

    // 6. PID1 signal management: SIGTERM, SIGINT → forward to child, exit with child's code
    #[cfg(unix)]
    let shutdown_policy = mcp_writ::runtime::wait::ShutdownPolicy::Pid1Unix;
    #[cfg(not(unix))]
    let shutdown_policy = mcp_writ::runtime::wait::ShutdownPolicy::Pid1NonUnix;
    mcp_writ::runtime::wait::wait_for_shutdown(
        shutdown_policy,
        launched.child,
        launched.auditor_handle,
        audit_logger,
    )
    .await;
}
