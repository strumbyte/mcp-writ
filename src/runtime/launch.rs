use crate::audit_log::{
    Action, AuditEvent, AuditLogger, EventType, Outcome, PolicyAuditContext, Severity,
    now_iso8601_millis,
};
use crate::auditor::Auditor;
use crate::enforcement::CodeIdentity;
use crate::enforcement::{
    ControlLayer, ControlPhase, ControlState, EnforcementObservation, EnforcementPlan,
    EnforcementSummary, LAUNCH_REPORT_SCHEMA_VERSION, LaunchOutcome, LaunchReport,
    ObservationBasis, PinCheck, SandboxBackend,
};
use crate::error::{AuditorError, WardenError};
use crate::execution::ExecutionTarget;
use crate::policy::Policy;
use crate::verifier::fail_on::FailOn;
use crate::verifier::hash::{self, VerifyError};
use crate::verifier::identity::LaunchIdentity;
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
    /// Guest-side directory the workload's TMPDIR/TMP/TEMP are pointed
    /// at — set by the in-guest runner from its contract env. `None`
    /// keeps the inherited variables untouched (the native `run` path).
    pub workload_tmpdir: Option<std::path::PathBuf>,
    /// `--windows-mechanism` — the native Windows sandbox mechanism the
    /// Warden dispatches on (`None` = the platform default,
    /// AppContainer). Recorded on the launch target so the report names
    /// the mechanism actually selected.
    pub windows_mechanism: Option<crate::execution::WindowsNativeMechanism>,
    /// Emitting binary for `guard.*` lifecycle records
    /// (`mcp-writ` on the host, `mcp-secure-runner` in the guest).
    pub component: &'static str,
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
    /// Audit identity the session-teardown events are stamped with —
    /// passed to `wait_for_shutdown`.
    pub session_audit: crate::runtime::lifecycle::SessionAuditContext,
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
/// Ordering is fixed: verify → bind → reverify reruns the binding —
/// including the content re-hash — immediately before spawn, narrowing
/// but not closing the hash-to-exec window. `code_identity` in the
/// report records which check points each pin passed.
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
        workload_tmpdir,
        windows_mechanism,
        component,
    } = config;

    let launch_id = launch_id.unwrap_or_else(uuid::Uuid::now_v7);
    let target = match windows_mechanism {
        Some(m) => ExecutionTarget::native().with_native_windows_mechanism(m),
        None => ExecutionTarget::native(),
    };
    let hash_entry_count = policy.hash_entries.len();
    let has_hashes = hash_entry_count > 0;
    let argv0 = argv.first().map(String::as_str).unwrap_or("");

    // The selected mechanism is fail-closed in the Warden: an explicit
    // non-default mechanism that cannot run refuses — it never silently
    // becomes AppContainer.
    let warden =
        Warden::with_windows_mechanism(policy.clone(), windows_mechanism.unwrap_or_default());
    let sandbox_skip_reason: Option<&'static str> = if skip_sandbox {
        Some(skip_reason.unwrap_or("unspecified"))
    } else {
        None
    };
    // The backend the `enforcement` member reports — the mechanism the
    // sandboxed dispatch uses (`Warden::sandbox_backend`), or `none`
    // when the launch skips the OS sandbox entirely.
    let backend = if sandbox_skip_reason.is_some() {
        SandboxBackend::None
    } else {
        warden.sandbox_backend()
    };
    // The environment restriction is part of the launch contract, not the OS
    // sandbox: it applies identically on the sandboxed path and when
    // `skip_sandbox` (`--dry-run` / `MCP_WRIT_SKIP_SANDBOX`) is set.
    let spawn_opts = crate::warden::SpawnOptions {
        restrict_environment: policy.environment.restrict,
        allowed_names: policy.environment.allowed.clone(),
        tmpdir: workload_tmpdir,
    };

    // The code-identity record accumulates which check points each hash
    // pin passed — built before resolution so even a resolve failure
    // reports the launch shape.
    let mut identity = LaunchIdentity::for_launch(&argv, &policy.hash_entries);

    // The verified executable/entrypoint handles, when the policy pins
    // hashes — held open across the spawn so the checked object is the
    // executed object (Windows: replacement-preventing share mode;
    // Unix: the final path-identity re-check anchor).
    let mut spawn_pin: Option<hash::SpawnPin> = None;

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
        // The bound server name only — never the "default" label a
        // server-less policy reports.
        if let Some(ctx) = &policy_context
            && ctx.id != "default"
        {
            event.target_server = Some(ctx.id.clone());
        }
        // `session_id` keeps the record attributable when the host's
        // and the guest runner's JSONL streams merge under one launch
        // id; the failure detail follows verbatim.
        let mut details = format!("session_id={}", audit_logger.session_id());
        if let Some(detail) = report.result.as_ref().and_then(|r| r.detail.as_deref()) {
            details.push_str(&format!(" {detail}"));
        }
        event.details = Some(details);
        // The same plan/observations the `--report` file carries, as the
        // record's structured `enforcement` member — a failed launch
        // states what it attempted, not just the error string.
        event.enforcement = Some(
            EnforcementSummary::build(&report.plan, &report.observations, backend, report.dry_run)
                .to_json(),
        );
        audit_logger.log(event);
        report
    };

    let resolved_exe = match crate::workload::resolve_command_path(argv0) {
        Ok(p) => {
            identity.set_resolved(&p);
            p
        }
        Err(source) => {
            let detail = format!("cannot resolve command '{argv0}': {source}");
            let report = fail(failure_report(
                launch_id,
                target,
                &policy_context,
                dry_run,
                launch_plan(None),
                Vec::new(),
                identity.finish(),
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
            match hash::verify_server_hashes(s_name, &policy.hash_entries, audit_logger) {
                Ok(_) => identity.mark_server_verified(s_name),
                Err(source) => {
                    identity.mark_server_failed(s_name, &source);
                    let detail =
                        format!("supply chain verification failed for '{s_name}': {source}");
                    let report = fail(failure_report(
                        launch_id,
                        target,
                        &policy_context,
                        dry_run,
                        launch_plan(Some(&resolved_exe)),
                        identity_fail(detail.clone()),
                        identity.finish(),
                        detail,
                    ));
                    return Err(LaunchError::VerifyServerHashes {
                        server_name: s_name.to_string(),
                        source,
                        report,
                    });
                }
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
                identity.finish(),
                detail,
            ));
            return Err(LaunchError::BindLaunchedWorkload { source, report });
        }
        identity.mark_bound();
        match hash::reverify_immediately_before_spawn(
            &argv,
            &resolved_exe,
            &policy.hash_entries,
            audit_logger,
        ) {
            Ok(pin) => spawn_pin = Some(pin),
            Err(source) => {
                let detail = format!("supply chain verification failed at spawn: {source}");
                let report = fail(failure_report(
                    launch_id,
                    target,
                    &policy_context,
                    dry_run,
                    launch_plan(Some(&resolved_exe)),
                    identity_fail(detail.clone()),
                    identity.finish(),
                    detail,
                ));
                return Err(LaunchError::ReverifyBeforeSpawn { source, report });
            }
        }
        identity.mark_reverified();
        // Hash verification, binding, and the pre-spawn reverify all ran
        // to completion — the identity control is verified for this launch.
    }
    // Snapshot the record now — `identity` borrows `argv` and `policy`,
    // which move into the spawn and the Auditor below.
    let code_identity = identity.finish();

    // The child execs `resolved_exe` — the canonicalized, hash-verified
    // image — while `argv` keeps the caller's spelling as the child's
    // argv[0]: a venv `bin/python` locates `pyvenv.cfg` relative to it
    // (on macOS, where CPython ignores argv[0], the Warden passes the
    // spelling via PYTHONEXECUTABLE). Passing the symlink itself to
    // spawn would exec the unverified link.
    if let Some(reason) = sandbox_skip_reason {
        tracing::warn!("sandboxing disabled ({reason})");
    }
    // The last check before the pathname-based spawn opens the image —
    // the path must still resolve to the held, verified object.
    if let Some(pin) = &spawn_pin
        && let Err(source) = pin.verify_spawn_path(&resolved_exe)
    {
        let detail = format!("supply chain verification failed at spawn: {source}");
        let report = fail(failure_report(
            launch_id,
            target,
            &policy_context,
            dry_run,
            launch_plan(Some(&resolved_exe)),
            vec![identity_observation_failed(&detail)],
            code_identity.clone(),
            detail,
        ));
        return Err(LaunchError::ReverifyBeforeSpawn { source, report });
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
                observations.insert(0, identity_observation(&code_identity));
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
                code_identity.clone(),
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
                observations.insert(0, identity_observation(&code_identity));
            }
            let report = fail(failure_report(
                launch_id,
                target,
                &policy_context,
                dry_run,
                plan,
                observations,
                code_identity.clone(),
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
        observations.insert(0, identity_observation(&code_identity));
    }
    let rpc_reason = if dry_run {
        Some("dry-run: observable tools/call denials are forwarded and logged; other violations stay blocked".to_string())
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
        code_identity: Some(code_identity),
        // `mcp-secure-runner` fills this in when it re-emits the report
        // as its own guest-side record.
        guest_runner: None,
        guest: None,
        // A native launch involves no isolation backend.
        isolation: None,
    };
    tracing::debug!("launch report: {}", report.to_json());

    let session_audit = crate::runtime::lifecycle::SessionAuditContext {
        launch_id,
        policy: policy_context.clone(),
        component,
    };
    // The audited session opens: `session.started` brackets the relay's
    // lifetime, `server.connected` records the spawn inside it. Both
    // share the launch_id correlation the report carries.
    crate::runtime::lifecycle::session_started(audit_logger, &session_audit);
    let mut event = AuditEvent::new(
        launch_id,
        EventType::ServerConnected,
        Severity::Info,
        Outcome::Success,
        Action::Observed,
    );
    if let Some(ctx) = &policy_context
        && ctx.id != "default"
    {
        event.target_server = Some(ctx.id.clone());
    }
    event.policy_context = policy_context;
    let mut details = format!(
        "spawned {} backend={}",
        resolved_exe.display(),
        backend.as_str()
    );
    if dry_run {
        details.push_str(" (dry-run)");
    }
    if sandbox_skip_reason.is_some() {
        // A skipped OS sandbox is stated on the spawn record itself —
        // `guard.started` carries the cause, this event the effect.
        details.push_str(" sandbox=skipped");
    }
    // OS controls the launch tolerated below full enforcement ride the
    // same observations the report carries — not a separate computation.
    details.push_str(&weakened_os_tokens(&report.observations));
    details.push_str(&format!(" session_id={}", audit_logger.session_id()));
    event.details = Some(details);
    // The machine-readable mirror of `details`: backend, effective
    // control states, grant counts, and the PSEC digest — built from the
    // same `plan`/`observations` the report file carries.
    event.enforcement = Some(
        EnforcementSummary::build(&report.plan, &report.observations, backend, dry_run).to_json(),
    );
    audit_logger.log(event);

    Ok(Launched {
        child,
        auditor_handle,
        report,
        session_audit,
    })
}

/// `launch.identity` observation: hash verification, workload binding, and
/// the pre-spawn reverify all ran to completion — a failed verification
/// never reaches this point (it aborts the launch earlier). The reason
/// keeps binding distinct from content-only verification: only pins that
/// earned the `bind_path` check bind the process, and re-verification
/// narrows the hash-to-exec window without closing it.
fn identity_observation(identity: &CodeIdentity) -> EnforcementObservation {
    let total = identity.pins.len();
    // A pin binds the process only when its bind-path check actually
    // passed — role alone overstates it (`binary-hash` whose target is
    // not the resolved exe verifies content but binds nothing).
    let binding = identity
        .pins
        .iter()
        .filter(|p| p.checks.contains(&PinCheck::BindPath))
        .count();
    let content_only = total - binding;
    let reason = if content_only == 0 {
        format!(
            "{total} hash entries verified and bound to the launch; \
             re-verified immediately before spawn (the hash-to-exec window \
             narrows but is not closed)"
        )
    } else {
        let rest = if content_only == 1 {
            "1 entry verifies content only and does not bind the process".to_string()
        } else {
            format!("{content_only} entries verify content only and do not bind the process")
        };
        format!(
            "{binding} of {total} hash entries bind the launched process and \
             were re-verified before spawn; {rest}"
        )
    };
    EnforcementObservation {
        control: "launch.identity",
        state: ControlState::Verified,
        basis: ObservationBasis::VerificationRun,
        phase: ControlPhase::Build,
        reason: Some(reason),
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

/// `server.connected` detail tokens for OS-layer controls the launch
/// tolerated below full enforcement — one `<control>=<state>` pair per
/// `os.*` observation that came back `partially_applied`, `not_applied`,
/// or `failed` (a tolerated `allow_degraded` outcome, an unenforceable
/// rule set, a failed grant on a spawn that still completed).
/// `launch.*`/`rpc.*` observations never express kernel enforcement and
/// are filtered by the `os.` prefix; `unknown` is deliberately absent —
/// it records an observation limit (e.g. in-kernel profile acceptance),
/// not a weakening the launch accepted. Token-free therefore means only
/// *no accepted weakening was observed* — `skipped` and `not_applicable`
/// controls emit no token either, so whether a control actually
/// enforced is answered by the report's `observations`, never inferred
/// from token absence. A skipped OS sandbox is the one absence that
/// names itself: `sandbox=skipped`.
fn weakened_os_tokens(observations: &[EnforcementObservation]) -> String {
    let mut out = String::new();
    for o in observations {
        if o.control.starts_with("os.")
            && matches!(
                o.state,
                ControlState::PartiallyApplied | ControlState::NotApplied | ControlState::Failed
            )
        {
            out.push_str(&format!(" {}={}", o.control, o.state.as_str()));
        }
    }
    out
}

/// A report for a launch that never reached a running session: the plan
/// the launch was built on plus whatever observations the failed stage
/// produced, and `result = failed` so a `--report` write is never an
/// empty success.
#[expect(clippy::too_many_arguments)]
fn failure_report(
    launch_id: uuid::Uuid,
    target: ExecutionTarget,
    policy_context: &Option<PolicyAuditContext>,
    dry_run: bool,
    plan: EnforcementPlan,
    observations: Vec<EnforcementObservation>,
    code_identity: CodeIdentity,
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
        code_identity: Some(code_identity),
        guest_runner: None,
        guest: None,
        isolation: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn obs(control: &'static str, state: ControlState) -> EnforcementObservation {
        EnforcementObservation {
            control,
            state,
            basis: ObservationBasis::MechanismResult,
            phase: ControlPhase::Spawn,
            reason: None,
        }
    }

    /// Every OS control verified — no weakening tokens on the record.
    #[test]
    fn weakened_os_tokens_silent_on_full_enforcement() {
        let observations = vec![
            obs("os.privileges", ControlState::Verified),
            obs("os.fs", ControlState::Verified),
            obs("os.net.outbound", ControlState::Verified),
            obs("launch.identity", ControlState::Verified),
            obs("rpc.tools", ControlState::Unknown),
        ];
        assert_eq!(weakened_os_tokens(&observations), "");
    }

    /// A tolerated partial/absent application names the affected
    /// controls with the same state vocabulary the report uses.
    #[test]
    fn weakened_os_tokens_names_degraded_controls() {
        let observations = vec![
            obs("os.fs", ControlState::PartiallyApplied),
            obs("os.net.outbound", ControlState::NotApplied),
            obs("os.syscalls", ControlState::Verified),
        ];
        assert_eq!(
            weakened_os_tokens(&observations),
            " os.fs=partially_applied os.net.outbound=not_applied"
        );
    }

    /// Non-OS observations never leak into the token list, and `unknown`
    /// stays silent — an observation limit is not a tolerated weakening.
    #[test]
    fn weakened_os_tokens_excludes_non_os_and_unknown() {
        let observations = vec![
            obs("os.sandbox", ControlState::Unknown),
            obs("os.fs", ControlState::Unknown),
            obs("launch.env", ControlState::Failed),
            obs("launch.identity", ControlState::Failed),
            obs("rpc.tools", ControlState::Failed),
        ];
        assert_eq!(weakened_os_tokens(&observations), "");
    }

    /// An OS control whose apply failed beside a completed spawn is a
    /// weakening too — it must not read as full enforcement.
    #[test]
    fn weakened_os_tokens_records_failed_os_control() {
        let observations = vec![
            obs("os.fs", ControlState::Failed),
            obs("os.privileges", ControlState::Verified),
        ];
        assert_eq!(weakened_os_tokens(&observations), " os.fs=failed");
    }

    /// `Warden::sandbox_backend` names the mechanism this host's
    /// sandboxed dispatch uses — the value `enforcement.backend` and the
    /// `backend=` detail token report. A caller-side sandbox skip maps
    /// to `SandboxBackend::None` at the call site, not here.
    #[test]
    fn sandbox_backend_matches_platform_dispatch() {
        let warden = Warden::new(Policy::default());
        #[cfg(target_os = "linux")]
        assert_eq!(warden.sandbox_backend(), SandboxBackend::LandlockSeccomp);
        #[cfg(target_os = "macos")]
        assert_eq!(warden.sandbox_backend(), SandboxBackend::SandboxExec);
        #[cfg(target_os = "windows")]
        assert_eq!(warden.sandbox_backend(), SandboxBackend::AppContainer);
        #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
        assert_eq!(warden.sandbox_backend(), SandboxBackend::None);

        #[cfg(target_os = "windows")]
        {
            let psec = Warden::with_windows_mechanism(
                Policy::default(),
                crate::execution::WindowsNativeMechanism::Psec,
            );
            assert_eq!(psec.sandbox_backend(), SandboxBackend::Psec);
        }
    }
}
