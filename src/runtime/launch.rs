use crate::audit_log::{
    Action, AuditEvent, AuditLogger, EventType, Outcome, PolicyAuditContext, Severity,
    now_iso8601_millis,
};
use crate::auditor::Auditor;
use crate::enforcement::{
    ControlLayer, ControlPhase, ControlState, EnforcementObservation, LAUNCH_REPORT_SCHEMA_VERSION,
    LaunchReport, ObservationBasis,
};
use crate::error::{AuditorError, WardenError};
use crate::execution::ExecutionTarget;
use crate::policy::Policy;
use crate::verifier::fail_on::FailOn;
use crate::verifier::hash::{self, VerifyError};
use crate::warden::{RunningChild, Warden, WardenReport};

/// Per-binary inputs to [`launch`].
///
/// Callers resolve policy loading, `bind_to_server`, `FailOn`, and audit-log
/// requirements before calling. `skip_sandbox` is also computed by the caller:
/// this function never reads `MCP_WRIT_SKIP_SANDBOX` itself (the container
/// runner strips that variable before launch, and reading it here would break
/// image ENV handling and tests).
pub struct LaunchConfig {
    /// Command argv as the caller spelled it; `argv[0]` is resolved and
    /// verified here but keeps its spelling as the child's `argv[0]` —
    /// the resolved path is exec'd as the process image. Must be non-empty.
    pub argv: Vec<String>,
    pub policy: Policy,
    pub fail_on: FailOn,
    /// Forwarded to `Auditor::with_dry_run` (`mcp-secure-runner` passes false).
    pub dry_run: bool,
    /// Caller-computed sandbox skip (`mcp-writ run --dry-run` or
    /// `MCP_WRIT_SKIP_SANDBOX`; `mcp-secure-runner` always passes false).
    pub skip_sandbox: bool,
    /// Reason interpolated into `sandboxing disabled ({reason})`. Expected to
    /// be set when `skip_sandbox` is true.
    pub skip_reason: Option<&'static str>,
    /// First half of the post-spawn `tracing::info!` (`"{label}: {argv:?}"`).
    pub spawned_log_label: &'static str,
    /// Identity of the enforced (bound) policy — file id, version, and the
    /// hash of its effective `to_kdl` form. Stamped on the launch report and
    /// on the correlated `server.connected`/`server.error` audit events.
    pub policy_context: Option<PolicyAuditContext>,
}

/// A spawned MCP server child plus its running Auditor relay task.
pub struct Launched {
    pub child: RunningChild,
    pub auditor_handle: tokio::task::JoinHandle<Result<(), AuditorError>>,
    /// What this launch intended to enforce and what applying it observably
    /// did (`enforcement` module). Nothing emits it by default — a future
    /// `--report`/diagnostics surface decides where it goes; it never rides
    /// on MCP stdout.
    pub report: LaunchReport,
}

/// Failure at one step of [`launch`]. Callers render the message with their
/// own error prefix, shut down the audit logger, and exit.
pub enum LaunchError {
    /// `resolve_command_path` failed; `command` is the unresolved `argv[0]`.
    ResolveCommand {
        command: String,
        source: std::io::Error,
    },
    /// `verify_server_hashes` failed for `server_name`.
    VerifyServerHashes {
        server_name: String,
        source: VerifyError,
    },
    /// `bind_launched_workload` failed.
    BindLaunchedWorkload { source: VerifyError },
    /// `reverify_immediately_before_spawn` failed.
    ReverifyBeforeSpawn { source: VerifyError },
    /// Warden spawn failed; `argv` is the launch argv. `report` carries the
    /// plan the failed spawn was built from and the failure observations —
    /// a refused launch is still describable.
    Spawn {
        argv: Vec<String>,
        source: WardenError,
        report: Box<LaunchReport>,
    },
    /// `take_io` failed; ownership of the child is returned so the caller can
    /// kill/wait/drop in the usual order.
    TakeIo { child: RunningChild },
}

/// Shared sequence: resolve argv0 → verify hashes → bind → reverify →
/// Warden spawn (exec'ing the verified path while the child keeps the
/// caller's `argv[0]`) → `take_io` → `Auditor` relay on a spawned task.
///
/// Ordering is fixed (verify → bind → reverify closes the TOCTOU gap).
/// Signal waiting and shutdown are NOT part of this function.
///
/// Every attempt produces a [`LaunchReport`]: the plan comes from the same
/// normalized rule data the spawn used, the observations come from the
/// spawn's own outcome, and `launch_id` correlates them with the audit
/// events emitted here.
pub async fn launch(
    config: LaunchConfig,
    audit_logger: &AuditLogger,
) -> Result<Launched, LaunchError> {
    let LaunchConfig {
        argv,
        policy,
        fail_on,
        dry_run,
        skip_sandbox,
        skip_reason,
        spawned_log_label,
        policy_context,
    } = config;

    let launch_id = uuid::Uuid::now_v7();
    let target = ExecutionTarget::native();
    let hash_entry_count = policy.hash_entries.len();
    let has_hashes = hash_entry_count > 0;

    let resolved_exe = match crate::workload::resolve_command_path(&argv[0]) {
        Ok(p) => p,
        Err(source) => {
            return Err(LaunchError::ResolveCommand {
                command: argv[0].clone(),
                source,
            });
        }
    };
    if has_hashes {
        let server_names: std::collections::HashSet<_> = policy
            .hash_entries
            .iter()
            .map(|e| e.server_name.as_str())
            .collect();
        for s_name in server_names {
            if let Err(source) =
                hash::verify_server_hashes(s_name, &policy.hash_entries, audit_logger)
            {
                return Err(LaunchError::VerifyServerHashes {
                    server_name: s_name.to_string(),
                    source,
                });
            }
        }
        if let Err(source) =
            hash::bind_launched_workload(&argv, &resolved_exe, &policy.hash_entries, audit_logger)
        {
            return Err(LaunchError::BindLaunchedWorkload { source });
        }
        if let Err(source) = hash::reverify_immediately_before_spawn(
            &argv,
            &resolved_exe,
            &policy.hash_entries,
            audit_logger,
        ) {
            return Err(LaunchError::ReverifyBeforeSpawn { source });
        }
    }

    // The child execs `resolved_exe` — the canonicalized, hash-verified
    // image — while `argv` keeps the caller's spelling as the child's
    // argv[0]: a venv `bin/python` locates `pyvenv.cfg` relative to it
    // (on macOS, where CPython ignores argv[0], the Warden passes the
    // spelling via PYTHONEXECUTABLE). Passing the symlink itself to
    // spawn would exec the unverified link.
    let warden = Warden::new(policy.clone());
    let skip_reason = if skip_sandbox {
        let reason = skip_reason.unwrap_or("unspecified");
        tracing::warn!("sandboxing disabled ({reason})");
        Some(reason)
    } else {
        None
    };
    // The environment restriction is part of the launch contract, not the OS
    // sandbox: it applies identically on the sandboxed path and when
    // `skip_sandbox` (`--dry-run` / `MCP_WRIT_SKIP_SANDBOX`) is set.
    let spawn_opts = crate::warden::SpawnOptions {
        restrict_environment: policy.environment.restrict,
        allowed_names: policy.environment.allowed.clone(),
        tmpdir: None,
    };
    let attempt = match skip_reason {
        Some(reason) => warden.spawn_unsandboxed_async_exe_with_report(
            &resolved_exe,
            &argv,
            &spawn_opts,
            reason,
            dry_run,
        ),
        None => {
            warden.spawn_child_async_exe_with_report(&resolved_exe, &argv, &spawn_opts, dry_run)
        }
    };
    let WardenReport {
        plan,
        mut observations,
    } = attempt.report;
    let mut child = match attempt.outcome {
        Ok(child) => child,
        Err(source) => {
            // Hash verification ran before the spawn attempt — record it
            // even though the launch fails here.
            if has_hashes {
                observations.push(identity_observation(hash_entry_count));
            }
            let report = LaunchReport {
                schema_version: LAUNCH_REPORT_SCHEMA_VERSION,
                launch_id,
                created_at: now_iso8601_millis(),
                target,
                policy: policy_context.clone(),
                dry_run,
                plan,
                observations,
            };
            // The responsible component (Warden) and stage are inside
            // `source`; record the failure before returning so the JSONL
            // audit log carries the same fact stderr reports.
            let mut event = AuditEvent::new(
                launch_id,
                EventType::ServerError,
                Severity::High,
                Outcome::Failure,
                Action::Observed,
            );
            event.policy_context = policy_context;
            event.details = Some(format!("server spawn failed: {source}"));
            audit_logger.log(event);
            return Err(LaunchError::Spawn {
                argv,
                source,
                report: Box::new(report),
            });
        }
    };
    tracing::info!("{spawned_log_label}: {argv:?}");

    let (child_stdin, child_stdout) = match child.take_io() {
        Some(io) => io,
        None => return Err(LaunchError::TakeIo { child }),
    };

    let auditor = Auditor::new(policy, audit_logger.clone())
        .with_dry_run(dry_run)
        .with_fail_on(fail_on);
    let auditor_handle = tokio::spawn(async move { auditor.run(child_stdin, child_stdout).await });

    // Observations only the launch path can take: the pre-spawn identity
    // checks and placeholders for the session checks the running Auditor
    // performs — spawning the relay is not itself evidence they ran.
    if has_hashes {
        observations.push(identity_observation(hash_entry_count));
    }
    let rpc_reason = if dry_run {
        Some("dry-run: violations are forwarded and logged as observed, not blocked".to_string())
    } else {
        Some("auditor relay running".to_string())
    };
    for ctrl in plan.controls.iter() {
        if ctrl.layer == ControlLayer::Rpc && ctrl.state == ControlState::Planned {
            observations.push(EnforcementObservation {
                control: ctrl.id,
                state: ControlState::Unknown,
                basis: ObservationBasis::NotObserved,
                phase: ControlPhase::Session,
                reason: rpc_reason.clone(),
            });
        }
    }

    let report = LaunchReport {
        schema_version: LAUNCH_REPORT_SCHEMA_VERSION,
        launch_id,
        created_at: now_iso8601_millis(),
        target,
        policy: policy_context.clone(),
        dry_run,
        plan,
        observations,
    };
    tracing::debug!("launch report: {}", report.to_json());

    let mut event = AuditEvent::new(
        launch_id,
        EventType::ServerConnected,
        Severity::Info,
        Outcome::Success,
        Action::Allowed,
    );
    event.policy_context = policy_context;
    event.details = Some(if dry_run {
        format!("spawned {} (dry-run)", resolved_exe.display())
    } else {
        format!("spawned {}", resolved_exe.display())
    });
    audit_logger.log(event);

    Ok(Launched {
        child,
        auditor_handle,
        report,
    })
}

/// `launch.identity` observation: hash verification, workload binding, and
/// the pre-spawn reverify all ran to completion — a failed verification
/// never reaches this point (it aborts the launch earlier).
fn identity_observation(entries: usize) -> EnforcementObservation {
    EnforcementObservation {
        control: "launch.identity",
        state: ControlState::Verified,
        basis: ObservationBasis::VerificationRun,
        phase: ControlPhase::Build,
        reason: Some(format!(
            "{entries} hash entries verified; workload bound and re-verified before spawn"
        )),
    }
}
