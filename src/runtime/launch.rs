use crate::audit_log::{
    Action, AuditEvent, AuditLogger, EventType, Outcome, PolicyAuditContext, Severity,
    now_iso8601_millis,
};
use crate::auditor::Auditor;
use crate::enforcement::{
    ControlLayer, ControlPhase, ControlState, EnforcementObservation, EnforcementPlan,
    LAUNCH_REPORT_SCHEMA_VERSION, LaunchOutcome, LaunchReport, ObservationBasis,
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
    /// Identity of the enforced (bound) policy — the bound server name (or
    /// `default` for a server-less policy), the declared policy version,
    /// and the hash of its effective `to_kdl` form. Stamped on the launch
    /// report and on the correlated `server.connected`/`server.error`
    /// audit events.
    pub policy_context: Option<PolicyAuditContext>,
    /// Launch correlation ID override. `None` mints a fresh v7 UUID; the
    /// in-guest runner passes the host-supplied `MCP_WRIT_LAUNCH_ID` so
    /// guest audit events correlate with the host's launch report.
    pub launch_id: Option<uuid::Uuid>,
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
///
/// Every variant carries `report`: the enforcement plan this launch was
/// built on plus a `result` of `failed`, so a `--report` consumer always
/// gets the same schema for a refused or failed launch — never an empty
/// success and never an unsupported shape.
pub enum LaunchError {
    /// `resolve_command_path` failed; `command` is the unresolved `argv[0]`.
    ResolveCommand {
        command: String,
        source: std::io::Error,
        report: Box<LaunchReport>,
    },
    /// `verify_server_hashes` failed for `server_name`.
    VerifyServerHashes {
        server_name: String,
        source: VerifyError,
        report: Box<LaunchReport>,
    },
    /// `bind_launched_workload` failed.
    BindLaunchedWorkload {
        source: VerifyError,
        report: Box<LaunchReport>,
    },
    /// `reverify_immediately_before_spawn` failed.
    ReverifyBeforeSpawn {
        source: VerifyError,
        report: Box<LaunchReport>,
    },
    /// Warden spawn failed; `argv` is the launch argv. `report` carries the
    /// plan the failed spawn was built from and the failure observations —
    /// a refused launch is still describable.
    Spawn {
        argv: Vec<String>,
        source: WardenError,
        report: Box<LaunchReport>,
    },
    /// `take_io` failed; ownership of the child is returned so the caller can
    /// kill/wait/drop in the usual order. `report` describes the launch the
    /// child was spawned under.
    TakeIo {
        child: RunningChild,
        report: Box<LaunchReport>,
    },
}

/// Shared sequence: resolve argv0 → verify hashes → bind → reverify →
/// Warden spawn (exec'ing the verified path while the child keeps the
/// caller's `argv[0]`) → `take_io` → `Auditor` relay on a spawned task.
///
/// Ordering is fixed (verify → bind → reverify closes the TOCTOU gap).
/// Signal waiting and shutdown are NOT part of this function.
///
/// A [`LaunchReport`] is assembled for every outcome of [`launch`]: it is
/// returned inside [`Launched`] with `result = running` (the caller
/// finalizes it at session end) and inside every [`LaunchError`] variant
/// with `result = failed`, so a refused or failed launch stays
/// describable in the same schema. The plan comes from the same
/// normalized rule data the spawn used, the observations from the
/// spawn's own outcome, and `launch_id` correlates them with the audit
/// events emitted here — including a `server.error` event on every
/// failure path, so a failed launch is auditable under the same id.
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
        launch_id,
    } = config;

    let launch_id = launch_id.unwrap_or_else(uuid::Uuid::now_v7);
    let target = ExecutionTarget::native();
    let hash_entry_count = policy.hash_entries.len();
    let has_hashes = hash_entry_count > 0;
    let argv0 = argv.first().map(String::as_str).unwrap_or("");

    let warden = Warden::new(policy.clone());
    let sandbox_skip_reason: Option<&'static str> = if skip_sandbox {
        Some(skip_reason.unwrap_or("unspecified"))
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

    // The plan a report describes: for a failed launch the same builders
    // still run (nothing is applied), so the report shows what the launch
    // intended to enforce, not an empty result.
    let launch_plan = |program: Option<&std::path::Path>| -> EnforcementPlan {
        warden.enforcement_plan(program, argv0, &spawn_opts, sandbox_skip_reason, dry_run)
    };
    let fail = |report: Box<LaunchReport>| {
        let mut event = AuditEvent::new(
            launch_id,
            EventType::ServerError,
            Severity::High,
            Outcome::Failure,
            Action::Observed,
        );
        event.policy_context = policy_context.clone();
        event.details = report.result.as_ref().and_then(|r| r.detail.clone());
        audit_logger.log(event);
        report
    };

    let resolved_exe = match crate::workload::resolve_command_path(argv0) {
        Ok(p) => p,
        Err(source) => {
            let detail = format!("cannot resolve command '{argv0}': {source}");
            let report = fail(failure_report(
                launch_id,
                target,
                &policy_context,
                dry_run,
                launch_plan(None),
                Vec::new(),
                detail,
            ));
            return Err(LaunchError::ResolveCommand {
                command: argv0.to_string(),
                source,
                report,
            });
        }
    };
    if has_hashes {
        let identity_fail = |detail: String| -> Vec<EnforcementObservation> {
            vec![identity_observation_failed(&detail)]
        };
        let server_names: std::collections::HashSet<_> = policy
            .hash_entries
            .iter()
            .map(|e| e.server_name.as_str())
            .collect();
        for s_name in server_names {
            if let Err(source) =
                hash::verify_server_hashes(s_name, &policy.hash_entries, audit_logger)
            {
                let detail = format!("supply chain verification failed for '{s_name}': {source}");
                let report = fail(failure_report(
                    launch_id,
                    target,
                    &policy_context,
                    dry_run,
                    launch_plan(Some(&resolved_exe)),
                    identity_fail(detail.clone()),
                    detail,
                ));
                return Err(LaunchError::VerifyServerHashes {
                    server_name: s_name.to_string(),
                    source,
                    report,
                });
            }
        }
        if let Err(source) =
            hash::bind_launched_workload(&argv, &resolved_exe, &policy.hash_entries, audit_logger)
        {
            let detail = format!("supply chain verification failed: {source}");
            let report = fail(failure_report(
                launch_id,
                target,
                &policy_context,
                dry_run,
                launch_plan(Some(&resolved_exe)),
                identity_fail(detail.clone()),
                detail,
            ));
            return Err(LaunchError::BindLaunchedWorkload { source, report });
        }
        if let Err(source) = hash::reverify_immediately_before_spawn(
            &argv,
            &resolved_exe,
            &policy.hash_entries,
            audit_logger,
        ) {
            let detail = format!("supply chain verification failed at spawn: {source}");
            let report = fail(failure_report(
                launch_id,
                target,
                &policy_context,
                dry_run,
                launch_plan(Some(&resolved_exe)),
                identity_fail(detail.clone()),
                detail,
            ));
            return Err(LaunchError::ReverifyBeforeSpawn { source, report });
        }
        // Hash verification, binding, and the pre-spawn reverify all ran
        // to completion — the identity control is verified for this launch.
    }

    // The child execs `resolved_exe` — the canonicalized, hash-verified
    // image — while `argv` keeps the caller's spelling as the child's
    // argv[0]: a venv `bin/python` locates `pyvenv.cfg` relative to it
    // (on macOS, where CPython ignores argv[0], the Warden passes the
    // spelling via PYTHONEXECUTABLE). Passing the symlink itself to
    // spawn would exec the unverified link.
    if let Some(reason) = sandbox_skip_reason {
        tracing::warn!("sandboxing disabled ({reason})");
    }
    let attempt = match sandbox_skip_reason {
        Some(reason) => warden.spawn_unsandboxed_async_exe_with_report(
            &resolved_exe,
            &argv,
            &spawn_opts,
            reason,
            dry_run,
        ),
        None => {
            warden
                .spawn_child_async_exe_with_report(&resolved_exe, &argv, &spawn_opts, dry_run)
                .await
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
            // even though the launch fails here. It is a Build-phase
            // observation, so it precedes the spawn-phase ones.
            if has_hashes {
                observations.insert(0, identity_observation(hash_entry_count));
            }
            // The responsible component (Warden) and stage are inside
            // `source`; the `fail` helper records a `server.error` audit
            // event under the same launch_id so the JSONL log carries the
            // same fact the report does.
            let report = fail(failure_report(
                launch_id,
                target,
                &policy_context,
                dry_run,
                plan,
                observations,
                format!("server spawn failed: {source}"),
            ));
            return Err(LaunchError::Spawn {
                argv,
                source,
                report,
            });
        }
    };
    tracing::info!("{spawned_log_label}: {argv:?}");

    let (child_stdin, child_stdout) = match child.take_io() {
        Some(io) => io,
        None => {
            if has_hashes {
                observations.insert(0, identity_observation(hash_entry_count));
            }
            let report = fail(failure_report(
                launch_id,
                target,
                &policy_context,
                dry_run,
                plan,
                observations,
                "failed to capture child process stdin/stdout".to_string(),
            ));
            return Err(LaunchError::TakeIo { child, report });
        }
    };

    let auditor = Auditor::new(policy, audit_logger.clone())
        .with_dry_run(dry_run)
        .with_fail_on(fail_on);
    let auditor_handle = tokio::spawn(async move { auditor.run(child_stdin, child_stdout).await });

    // Observations only the launch path can take: the pre-spawn identity
    // checks (Build phase — inserted ahead of the spawn-phase entries)
    // and placeholders for the session checks the running Auditor
    // performs — spawning the relay is not itself evidence they ran.
    if has_hashes {
        observations.insert(0, identity_observation(hash_entry_count));
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
        // The session is now running; the caller rewrites this with the
        // observed outcome at exit.
        result: Some(LaunchOutcome {
            status: "running",
            detail: None,
            exit_code: None,
        }),
        // `mcp-secure-runner` fills this in when it re-emits the report
        // as its own guest-side record.
        guest_runner: None,
        guest: None,
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

/// `launch.identity` observation for a verification that ran and failed:
/// the check did execute (`VerificationRun`), its outcome is `Failed`,
/// and `reason` carries the refused detail.
fn identity_observation_failed(detail: &str) -> EnforcementObservation {
    EnforcementObservation {
        control: "launch.identity",
        state: ControlState::Failed,
        basis: ObservationBasis::VerificationRun,
        phase: ControlPhase::Build,
        reason: Some(detail.to_string()),
    }
}

/// A report for a launch that never reached a running session: the plan
/// the launch was built on plus whatever observations the failed stage
/// produced, and `result = failed` so a `--report` write is never an
/// empty success.
fn failure_report(
    launch_id: uuid::Uuid,
    target: ExecutionTarget,
    policy_context: &Option<PolicyAuditContext>,
    dry_run: bool,
    plan: EnforcementPlan,
    observations: Vec<EnforcementObservation>,
    detail: String,
) -> Box<LaunchReport> {
    Box::new(LaunchReport {
        schema_version: LAUNCH_REPORT_SCHEMA_VERSION,
        launch_id,
        created_at: now_iso8601_millis(),
        target,
        policy: policy_context.clone(),
        dry_run,
        plan,
        observations,
        result: Some(LaunchOutcome {
            status: "failed",
            detail: Some(detail),
            exit_code: Some(1),
        }),
        guest_runner: None,
        guest: None,
    })
}
