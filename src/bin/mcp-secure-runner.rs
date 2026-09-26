use std::path::{Path, PathBuf};

use mcp_writ::audit_log;
use mcp_writ::container::guest_report;
use mcp_writ::enforcement::{
    EnforcementPlan, GuestRunnerIdentity, LAUNCH_REPORT_SCHEMA_VERSION, LaunchOutcome, LaunchReport,
};
use mcp_writ::execution::ExecutionTarget;
use mcp_writ::policy::loader::load_policy_for_target;
use mcp_writ::verifier::fail_on::{FailOn, NONE_STARTUP_WARNING};

const POLICY_PATH: &str = "/etc/mcp-secure/policy.kdl";

/// Capability marker scanned for by `wrap-image`/`containerize` on the
/// build host — the image records it so `run-image` can tell this
/// runner from a pre-report-channel one without executing it.
/// Referenced below so the string survives into the shipped binary.
/// `#[used]` retention is toolchain-dependent: it holds on the Linux
/// ELF targets the runner ships as, while MSVC builds drop the string —
/// expected, since only ELF artifacts are ever scanned. The release
/// workflow and the container e2e tests verify the marker on the real
/// binaries, so a retention change fails loudly instead of silently
/// disabling the report channel.
#[used]
static RUNNER_CAPS_MARKER: &str = guest_report::RUNNER_CAPS_MARKER;

fn runner_identity() -> GuestRunnerIdentity {
    // The marker bytes and this identity are the same capability claim.
    let _ = RUNNER_CAPS_MARKER;
    guest_report::this_runner_identity()
}

/// The file `run-image` reads back through the dedicated report mount.
fn guest_report_path(report_dir: &Path) -> PathBuf {
    report_dir.join(guest_report::GUEST_REPORT_FILENAME)
}

/// Write `report` to the guest report channel; failures go to stderr —
/// the missing file is itself the failure signal on the host side.
fn write_guest_report(report_dir: Option<&Path>, report: &LaunchReport) {
    let Some(dir) = report_dir else {
        return;
    };
    let path = guest_report_path(dir);
    if let Err(e) = report.write_to(&path) {
        eprintln!(
            "mcp-secure-runner: failed to write guest launch report '{}': {e}",
            path.display()
        );
    }
}

/// A minimal failure report for exits that happen before a launch plan
/// could be built — distinguishes "runner ran and failed early" from
/// "runner never produced a report" on the host side.
fn write_early_failure_report(report_dir: Option<&Path>, launch_id: uuid::Uuid, detail: String) {
    let Some(_dir) = report_dir else {
        return;
    };
    let report = LaunchReport {
        schema_version: LAUNCH_REPORT_SCHEMA_VERSION,
        launch_id,
        created_at: audit_log::now_iso8601_millis(),
        target: ExecutionTarget::native(),
        policy: None,
        dry_run: false,
        plan: EnforcementPlan {
            controls: Vec::new(),
            grants: Vec::new(),
            tools: Vec::new(),
            limitations: vec![
                "guest runner exited before a launch plan could be built".to_string(),
            ],
        },
        observations: Vec::new(),
        result: Some(LaunchOutcome {
            status: "failed",
            detail: Some(detail),
            exit_code: Some(1),
        }),
        guest_runner: Some(runner_identity()),
        guest: None,
    };
    write_guest_report(report_dir, &report);
}

#[tokio::main]
async fn main() {
    // The dedicated report channel and the host correlation id are read
    // first — both are stripped from the workload environment below, so
    // an inherited/baked value cannot redirect the handoff or rebind the
    // launch to a different host record.
    let report_dir = std::env::var(guest_report::REPORT_OUT_ENV)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .map(PathBuf::from);
    let host_server = std::env::var("MCP_WRIT_SERVER")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    // The host passes its launch report's id so guest audit events and
    // the guest launch report correlate with it.
    let guest_launch_id = std::env::var("MCP_WRIT_LAUNCH_ID")
        .ok()
        .and_then(|s| uuid::Uuid::parse_str(s.trim()).ok());
    // SAFETY: no other threads have been spawned yet besides the tokio runtime;
    // inherited image ENV must not skip the sandbox or override the host server bind.
    unsafe {
        std::env::remove_var("MCP_WRIT_ENV");
        std::env::remove_var("MCP_WRIT_SKIP_SANDBOX");
        std::env::remove_var("MCP_WRIT_LAUNCH_ID");
        std::env::remove_var(guest_report::REPORT_OUT_ENV);
    }
    let launch_id = guest_launch_id.unwrap_or_else(uuid::Uuid::now_v7);

    // 1. Load policy from /etc/mcp-secure/policy.kdl and re-validate it
    //    against the OS this process actually runs on (the guest OS).
    //    Whatever target name the host used at export time cannot stand in
    //    for this check.
    let policy = match load_policy_for_target(Path::new(POLICY_PATH), &ExecutionTarget::native()) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("mcp-secure-runner: failed to load policy: {e}");
            write_early_failure_report(
                report_dir.as_deref(),
                launch_id,
                format!("failed to load policy: {e}"),
            );
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
            write_early_failure_report(report_dir.as_deref(), launch_id, e.to_string());
            std::process::exit(1);
        }
    };
    if fail_on == FailOn::None {
        eprintln!("{NONE_STARTUP_WARNING}");
    }

    let policy = match policy.bind_to_server(host_server.as_deref()) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("mcp-secure-runner: failed to bind policy to server: {e}");
            write_early_failure_report(
                report_dir.as_deref(),
                launch_id,
                format!("failed to bind policy to server: {e}"),
            );
            std::process::exit(1);
        }
    };
    let policy_context = match policy.audit_context() {
        Ok(ctx) => Some(ctx),
        Err(e) => {
            eprintln!("mcp-secure-runner: could not compute effective policy hash: {e}");
            None
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
            write_early_failure_report(report_dir.as_deref(), launch_id, e.to_string());
            std::process::exit(1);
        }
    };
    match mcp_writ::runtime::argv::parse_shell_or_json(&cmd_raw) {
        Ok(args) => argv.extend(args),
        Err(e) => {
            eprintln!("mcp-secure-runner: {e}");
            write_early_failure_report(report_dir.as_deref(), launch_id, e.to_string());
            std::process::exit(1);
        }
    };

    if argv.is_empty() {
        eprintln!(
            "mcp-secure-runner: no command to run (MCP_ORIG_ENTRYPOINT and MCP_ORIG_CMD are both empty)"
        );
        write_early_failure_report(
            report_dir.as_deref(),
            launch_id,
            "no command to run (MCP_ORIG_ENTRYPOINT and MCP_ORIG_CMD are both empty)".to_string(),
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
                    write_early_failure_report(
                        report_dir.as_deref(),
                        launch_id,
                        format!("failed to open audit log: {e}"),
                    );
                    std::process::exit(1);
                }
                audit_log::AuditLogger::to_tracing()
            }
        }
    } else if policy.logging.fail_closed {
        let detail = format!(
            "audit log directory '{}' is required when logging.fail_closed is true",
            audit_log_dir.display()
        );
        eprintln!("mcp-secure-runner: {detail}");
        write_early_failure_report(report_dir.as_deref(), launch_id, detail);
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
            policy_context,
            launch_id: guest_launch_id,
        },
        &audit_logger,
    )
    .await
    {
        Ok(l) => l,
        Err(e) => {
            use mcp_writ::runtime::launch::LaunchError;
            let report = match e {
                LaunchError::ResolveCommand {
                    command,
                    source,
                    report,
                } => {
                    eprintln!("mcp-secure-runner: cannot resolve command '{command}': {source}");
                    report
                }
                LaunchError::VerifyServerHashes {
                    server_name,
                    source,
                    report,
                } => {
                    eprintln!(
                        "mcp-secure-runner: supply chain verification failed for '{server_name}': {source}"
                    );
                    report
                }
                LaunchError::BindLaunchedWorkload { source, report } => {
                    eprintln!("mcp-secure-runner: supply chain verification failed: {source}");
                    report
                }
                LaunchError::ReverifyBeforeSpawn { source, report } => {
                    eprintln!(
                        "mcp-secure-runner: supply chain verification failed at spawn: {source}"
                    );
                    report
                }
                LaunchError::Spawn {
                    argv,
                    source,
                    report,
                } => {
                    eprintln!(
                        "mcp-secure-runner: failed to spawn child process '{argv:?}': {source}"
                    );
                    report
                }
                LaunchError::TakeIo { mut child, report } => {
                    eprintln!("mcp-secure-runner: failed to capture child stdin/stdout");
                    let _ = child.kill().await;
                    let _ = child.wait().await;
                    drop(child);
                    report
                }
            };
            // The carried plan/observations plus the runner identity are
            // the guest's record of this launch — sent through the
            // dedicated channel, never through the MCP stdout relay.
            let mut report = *report;
            report.guest_runner = Some(runner_identity());
            eprintln!("mcp-secure-runner: launch report: {}", report.to_json());
            write_guest_report(report_dir.as_deref(), &report);
            audit_logger.shutdown().await;
            std::process::exit(1);
        }
    };

    // The guest report is finalized on every exit path (child exit,
    // signals, auditor failure) by wait_for_shutdown.
    let mut report = launched.report;
    report.guest_runner = Some(runner_identity());
    let report_target = report_dir.map(|dir| mcp_writ::runtime::wait::ReportTarget {
        report,
        path: guest_report_path(&dir),
    });

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
        report_target,
    )
    .await;
}
