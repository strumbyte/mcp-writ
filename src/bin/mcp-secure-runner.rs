use std::path::{Path, PathBuf};

use mcp_writ::audit_log;
use mcp_writ::container::guest_layout::{self, GuestLayout};
use mcp_writ::container::guest_report;
use mcp_writ::enforcement::{
    EnforcementPlan, GuestRunnerIdentity, LAUNCH_REPORT_SCHEMA_VERSION, LaunchOutcome, LaunchReport,
};
use mcp_writ::execution::ExecutionTarget;
use mcp_writ::policy::loader::load_policy_for_target;
use mcp_writ::runtime::lifecycle::{self, SessionAuditContext};
use mcp_writ::verifier::fail_on::{FailOn, NONE_STARTUP_WARNING};

/// The guest contract this build serves — selected by the OS the runner
/// is compiled for, since the runner binary is itself the guest payload
/// (a PE build runs under Windows, an ELF build under Linux).
#[cfg(windows)]
const GUEST: &GuestLayout = &guest_layout::WINDOWS;
#[cfg(not(windows))]
const GUEST: &GuestLayout = &guest_layout::LINUX;

/// Fallback policy path when `MCP_WRIT_POLICY_PATH` is not set — the
/// guest contract's default (`/etc/mcp-secure/policy.kdl` on Linux,
/// `C:/etc/mcp-secure/policy.kdl` on Windows).
fn default_policy_path() -> String {
    guest_layout::policy_file(GUEST)
}

/// Capability marker scanned for by `wrap-image`/`containerize` on the
/// build host — the image records it so `run-image` can tell this
/// runner from a pre-report-channel one without executing it.
/// `#[used]` alone does not retain the string on every toolchain
/// (MSVC-linked builds garbage-collect it), so `runner_identity()`
/// additionally passes it through `black_box` — a real use the
/// optimizer cannot prove dead. The release workflow and the
/// container/hyperv e2e tests verify the marker on the real binaries,
/// so a retention regression fails loudly instead of silently
/// disabling the report channel.
#[used]
static RUNNER_CAPS_MARKER: &str = guest_report::RUNNER_CAPS_MARKER;

/// `container_e2e` guest-ABI probe env — see
/// [`guest_report::PROBE_LANDLOCK_ABI_ENV`].
///
/// The probe answer: `landlock_create_ruleset(NULL, 0,
/// LANDLOCK_CREATE_RULESET_VERSION)` returns the kernel's ABI level;
/// `-ENOSYS` (not implemented) and `-EOPNOTSUPP` (built but disabled)
/// both collapse to 0, matching `landlock::ABI::Unsupported`.
#[cfg(target_os = "linux")]
fn probe_landlock_abi() -> i32 {
    const LANDLOCK_CREATE_RULESET_VERSION: usize = 1;
    let abi = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            std::ptr::null::<u8>(),
            0usize,
            LANDLOCK_CREATE_RULESET_VERSION,
        )
    };
    println!("{}", abi.max(0));
    0
}

/// Non-Linux builds still answer the probe (0 = unsupported) so a
/// wrong-arch binary reads as "probed, unsupported", never as silence.
#[cfg(not(target_os = "linux"))]
fn probe_landlock_abi() -> i32 {
    println!("0");
    0
}

fn runner_identity() -> GuestRunnerIdentity {
    // The marker bytes and this identity are the same capability claim.
    // `black_box` is the load-bearing reference: without it the literal
    // is dead-stripped (observed on MSVC builds) and host-side
    // capability scans would misread this runner as a legacy one.
    std::hint::black_box(RUNNER_CAPS_MARKER);
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
    // The host can read the startup report while the runner is still live.
    // Publish the complete JSON with a rename, never an empty/partial file.
    let pending = dir.join("report.pending.json");
    if let Err(e) = report
        .write_to(&pending)
        .and_then(|()| std::fs::rename(&pending, &path))
    {
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
        // The runner exited before the launch pipeline ran — identity
        // was never assessed.
        code_identity: None,
        guest_runner: Some(runner_identity()),
        guest: None,
        // The host records the isolation it applied; the guest-side
        // report does not re-assert it.
        isolation: None,
    };
    write_guest_report(report_dir, &report);
}

#[tokio::main]
async fn main() {
    // The guest-ABI probe answers before anything else: the probe
    // container mounts this binary as the entrypoint with no policy,
    // no report channel, and no original command to restore. Only a
    // non-empty value triggers it — `container_run_args` clears the
    // variable on production launches so an image-baked default cannot
    // divert a real run into probe mode.
    if std::env::var_os(guest_report::PROBE_LANDLOCK_ABI_ENV).is_some_and(|v| !v.is_empty()) {
        std::process::exit(probe_landlock_abi());
    }
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
    // The host-supplied channel paths — the mounted policy, the audit
    // log directory, and the workload's temp area. Empty values fall
    // back to the guest contract's defaults.
    let read_channel = |name: &str| -> Option<PathBuf> {
        std::env::var(name)
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .map(PathBuf::from)
    };
    let policy_path =
        read_channel(GUEST.policy_path_env).unwrap_or_else(|| PathBuf::from(default_policy_path()));
    let audit_dir =
        read_channel(GUEST.audit_dir_env).unwrap_or_else(|| PathBuf::from(GUEST.log_dir));
    let workload_tmpdir =
        read_channel(GUEST.temp_dir_env).or_else(|| Some(PathBuf::from(GUEST.workload_temp)));
    // An image-baked MCP_WRIT_SKIP_SANDBOX is neutralized below, not
    // honored — but its presence is itself auditworthy, so note it for
    // `guard.started` before stripping.
    let skip_sandbox_stripped =
        std::env::var_os("MCP_WRIT_SKIP_SANDBOX").is_some_and(|v| !v.is_empty());
    // SAFETY: no other threads have been spawned yet besides the tokio runtime;
    // inherited image ENV must not skip the sandbox, override the host
    // server bind, or leak the channel variables into the workload.
    unsafe {
        std::env::remove_var("MCP_WRIT_ENV");
        std::env::remove_var("MCP_WRIT_SKIP_SANDBOX");
        std::env::remove_var("MCP_WRIT_LAUNCH_ID");
        std::env::remove_var(guest_report::REPORT_OUT_ENV);
        std::env::remove_var(GUEST.policy_path_env);
        std::env::remove_var(GUEST.audit_dir_env);
        std::env::remove_var(GUEST.temp_dir_env);
    }
    let launch_id = guest_launch_id.unwrap_or_else(uuid::Uuid::now_v7);
    let mut session_audit = SessionAuditContext::pre_policy(launch_id, "mcp-secure-runner");
    // The sink a prelaunch abort would use — the guest contract's audit
    // file when its directory is mounted.
    let prelaunch_audit_log = audit_dir.is_dir().then(|| audit_dir.join("audit.jsonl"));

    // 1. Load policy from the guest contract's path and re-validate it
    //    against the OS this process actually runs on (the guest OS).
    //    Whatever target name the host used at export time cannot stand in
    //    for this check.
    let policy = match load_policy_for_target(&policy_path, &ExecutionTarget::native()) {
        Ok(p) => p,
        Err(e) => {
            let detail = format!("failed to load policy: {e}");
            eprintln!("mcp-secure-runner: {detail}");
            write_early_failure_report(report_dir.as_deref(), launch_id, detail.clone());
            lifecycle::prelaunch_abort(
                prelaunch_audit_log.as_deref(),
                &session_audit,
                Some("load"),
                &detail,
            )
            .await;
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
            let detail = e.to_string();
            eprintln!("mcp-secure-runner: {e}");
            write_early_failure_report(report_dir.as_deref(), launch_id, detail.clone());
            lifecycle::prelaunch_abort(
                prelaunch_audit_log.as_deref(),
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

    let policy = match policy.bind_to_server(host_server.as_deref()) {
        Ok(p) => p,
        Err(e) => {
            let detail = format!("failed to bind policy to server: {e}");
            eprintln!("mcp-secure-runner: {detail}");
            write_early_failure_report(report_dir.as_deref(), launch_id, detail.clone());
            lifecycle::prelaunch_abort(
                prelaunch_audit_log.as_deref(),
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
            eprintln!("mcp-secure-runner: could not compute effective policy hash: {e}");
            None
        }
    };

    // 3. Read MCP_ORIG_ENTRYPOINT and MCP_ORIG_CMD environment variables
    let entrypoint_raw = std::env::var("MCP_ORIG_ENTRYPOINT").unwrap_or_default();
    let cmd_raw = std::env::var("MCP_ORIG_CMD").unwrap_or_default();

    // 4. Parse and combine into the original command line. Windows
    //    guests need the non-POSIX fallback split — `shlex` would eat
    //    backslashes out of `C:\…` paths.
    #[cfg(windows)]
    let parse_argv = mcp_writ::runtime::argv::parse_shell_or_json_windows;
    #[cfg(not(windows))]
    let parse_argv = mcp_writ::runtime::argv::parse_shell_or_json;
    let mut argv = match parse_argv(&entrypoint_raw) {
        Ok(args) => args,
        Err(e) => {
            let detail = e.to_string();
            eprintln!("mcp-secure-runner: {e}");
            write_early_failure_report(report_dir.as_deref(), launch_id, detail.clone());
            lifecycle::prelaunch_abort(
                prelaunch_audit_log.as_deref(),
                &session_audit,
                None,
                &detail,
            )
            .await;
            std::process::exit(1);
        }
    };
    match parse_argv(&cmd_raw) {
        Ok(args) => argv.extend(args),
        Err(e) => {
            let detail = e.to_string();
            eprintln!("mcp-secure-runner: {e}");
            write_early_failure_report(report_dir.as_deref(), launch_id, detail.clone());
            lifecycle::prelaunch_abort(
                prelaunch_audit_log.as_deref(),
                &session_audit,
                None,
                &detail,
            )
            .await;
            std::process::exit(1);
        }
    };

    if argv.is_empty() {
        let detail =
            "no command to run (MCP_ORIG_ENTRYPOINT and MCP_ORIG_CMD are both empty)".to_string();
        eprintln!("mcp-secure-runner: {detail}");
        write_early_failure_report(report_dir.as_deref(), launch_id, detail.clone());
        lifecycle::prelaunch_abort(
            prelaunch_audit_log.as_deref(),
            &session_audit,
            None,
            &detail,
        )
        .await;
        std::process::exit(1);
    }
    tracing::info!("Restored command: {:?}", argv);

    // Set up audit logger (file in the guest contract's log directory —
    // /var/log/mcp-secure on Linux, C:/var/log/mcp-secure on Windows —
    // overridable by the launch's channel var; stderr tracing otherwise)
    let audit_log_dir = audit_dir;
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
                    let detail = format!("failed to open audit log: {e}");
                    write_early_failure_report(report_dir.as_deref(), launch_id, detail.clone());
                    // `log_file` just failed to open and the failure was
                    // already reported — the abort bracket goes to the
                    // tracing sink rather than re-opening the same path.
                    lifecycle::prelaunch_abort(None, &session_audit, None, &detail).await;
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
        write_early_failure_report(report_dir.as_deref(), launch_id, detail.clone());
        lifecycle::prelaunch_abort(None, &session_audit, None, &detail).await;
        std::process::exit(1);
    } else {
        audit_log::AuditLogger::to_tracing()
    };

    // The lifecycle bracket opens: `guard.started` marks the guest
    // sink's open (and whether a baked MCP_WRIT_SKIP_SANDBOX was
    // stripped rather than honored), `policy.loaded` the policy and
    // fail_on dial the launch runs under.
    session_audit.policy = policy_context.clone();
    lifecycle::guard_started(
        &audit_logger,
        &session_audit,
        skip_sandbox_stripped
            .then_some("MCP_WRIT_SKIP_SANDBOX stripped from workload env (ignored)"),
    );
    let policy_source = policy_path.display().to_string();
    lifecycle::policy_loaded(
        &audit_logger,
        &session_audit,
        policy.version,
        fail_on.as_str(),
        &policy_source,
    );

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
            launch_id: Some(launch_id),
            workload_tmpdir,
            // The in-guest runner always uses the platform default —
            // `--windows-mechanism` is a host-native `run` selection and
            // is not part of the guest launch contract.
            windows_mechanism: None,
            component: "mcp-secure-runner",
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

    // The guest report is finalized on every exit path (child exit,
    // signals, auditor failure) by wait_for_shutdown.
    let mut report = launched.report;
    report.guest_runner = Some(runner_identity());
    write_guest_report(report_dir.as_deref(), &report);
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
        launched.session_audit,
        report_target,
    )
    .await;
}
