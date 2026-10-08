//! Lifecycle and configuration audit events: `guard.started` /
//! `guard.stopped`, `policy.loaded` / `policy.error`, `session.started` /
//! `session.ended`, and `server.disconnected`. Both binaries emit them
//! through these helpers so a JSONL stream reconstructs the whole
//! session from a single `correlation_id` — the same launch id the
//! `--report` artifact carries — with the logger's `session_id` in
//! `details` tying the records to one process run.
//!
//! Semantics: a lifecycle record states a fact the guard observed or a
//! decision it made — never proof that an OS mechanism enforced
//! anything. Events carry `Action::Observed`; whether a kernel boundary
//! then blocked the workload is a separate property that kernel-internal
//! denials cannot report.

use std::path::Path;

use uuid::Uuid;

use crate::audit_log::{
    Action, AuditEvent, AuditLogger, EventType, Outcome, PolicyAuditContext, Severity,
};
use crate::enforcement::LaunchOutcome;

/// Identity shared by every audit record of one launch.
///
/// `launch_id` is minted by the binary before policy load so the
/// earliest failure records correlate with the launch report the same
/// way the session records do. `policy` is `None` until the policy is
/// loaded, bound, and hashed — a `policy.error` record that aborted the
/// launch therefore carries no `policy_*` fields: the policy never
/// became effective. `component` names the emitting binary on `guard.*`
/// records — the host (`mcp-writ run`) and guest (`mcp-secure-runner`)
/// JSONL sinks may be merged by a collector.
#[derive(Clone)]
pub struct SessionAuditContext {
    pub launch_id: Uuid,
    pub policy: Option<PolicyAuditContext>,
    pub component: &'static str,
}

impl SessionAuditContext {
    /// The context before policy load: the launch id and component are
    /// known, the policy identity is not.
    pub fn pre_policy(launch_id: Uuid, component: &'static str) -> Self {
        Self {
            launch_id,
            policy: None,
            component,
        }
    }
}

/// Map a launch-report status onto the audit outcome vocabulary.
/// `interrupted`/`aborted` are `Unknown` — the session did not run to a
/// success/failure result of its own.
fn outcome_of(status: &str) -> Outcome {
    match status {
        "exited" => Outcome::Success,
        "failed" => Outcome::Failure,
        _ => Outcome::Unknown,
    }
}

fn lifecycle_event(
    ctx: &SessionAuditContext,
    event_type: EventType,
    outcome: Outcome,
) -> AuditEvent {
    let mut event = AuditEvent::new(
        ctx.launch_id,
        event_type,
        Severity::Info,
        outcome,
        Action::Observed,
    );
    event.policy_context = ctx.policy.clone();
    if let Some(policy) = &ctx.policy {
        // `target_server` names the bound server identity only — the
        // "default" label a server-less policy reports is never recorded
        // there (the same convention the tools-list filter applies).
        if policy.id != "default" {
            event.target_server = Some(policy.id.clone());
        }
    }
    event
}

/// `guard.started`: the guard process opened its audit sink. Details
/// carry `component`, `pid`, and the logger `session_id`; `extra`
/// appends session-level flags the launch was configured with (e.g.
/// `sandbox=skipped via MCP_WRIT_SKIP_SANDBOX`, `dry_run=true`).
pub fn guard_started(logger: &AuditLogger, ctx: &SessionAuditContext, extra: Option<&str>) {
    let mut event = lifecycle_event(ctx, EventType::GuardStarted, Outcome::Success);
    let mut details = format!(
        "component={} pid={} session_id={}",
        ctx.component,
        std::process::id(),
        logger.session_id()
    );
    if let Some(extra) = extra {
        details.push_str(&format!(" {extra}"));
    }
    event.details = Some(details);
    logger.log(event);
}

/// `guard.stopped`: the guard is exiting. `status` mirrors the launch
/// outcome vocabulary (`exited`, `failed`, `interrupted`); pre-session
/// aborts use `aborted`. Emitted immediately before the logger shuts
/// down — it is the last record of a session.
pub fn guard_stopped(
    logger: &AuditLogger,
    ctx: &SessionAuditContext,
    status: &'static str,
    exit_code: Option<i32>,
    detail: Option<&str>,
) {
    let mut event = lifecycle_event(ctx, EventType::GuardStopped, outcome_of(status));
    let mut details = format!(
        "component={} session_id={} status={status}",
        ctx.component,
        logger.session_id()
    );
    if let Some(code) = exit_code {
        details.push_str(&format!(" exit_code={code}"));
    }
    if let Some(detail) = detail {
        details.push_str(&format!(" detail={detail}"));
    }
    event.details = Some(details);
    logger.log(event);
}

/// `policy.loaded`: the effective policy was loaded and bound. The
/// `policy_*` fields carry its identity; `details` repeats
/// version/hash and adds the resolved `fail_on` dial, the source
/// path (or `default`), and the logger `session_id`, so the record
/// still shows version and dial when the context hash could not be
/// computed.
pub fn policy_loaded(
    logger: &AuditLogger,
    ctx: &SessionAuditContext,
    version: u32,
    fail_on: &str,
    source: &str,
) {
    let mut event = lifecycle_event(ctx, EventType::PolicyLoaded, Outcome::Success);
    let hash = ctx
        .policy
        .as_ref()
        .map(|p| p.hash.as_str())
        .unwrap_or("unavailable");
    event.details = Some(format!(
        "version={version} hash={hash} fail_on={fail_on} source={source} session_id={}",
        logger.session_id()
    ));
    logger.log(event);
}

/// `policy.error`: policy load/validate/bind failed and the launch is
/// refused. `stage` names the step (`load`, `bind`); `details` also
/// carries the logger `session_id` before the free-form `error`. A
/// refused launch never produced an effective policy, so `policy_*`
/// fields stay null.
pub fn policy_error(
    logger: &AuditLogger,
    ctx: &SessionAuditContext,
    stage: &'static str,
    detail: &str,
) {
    let mut event = AuditEvent::new(
        ctx.launch_id,
        EventType::PolicyError,
        Severity::High,
        Outcome::Failure,
        Action::Observed,
    );
    event.details = Some(format!(
        "stage={stage} session_id={} error={detail}",
        logger.session_id()
    ));
    logger.log(event);
}

/// `session.started`: the audited session is open — the child was
/// spawned and the Auditor relay is running. Pairs with
/// `session.ended`; a launch that fails earlier emits `server.error`
/// instead.
pub fn session_started(logger: &AuditLogger, ctx: &SessionAuditContext) {
    let mut event = lifecycle_event(ctx, EventType::SessionStarted, Outcome::Success);
    event.details = Some(format!("session_id={}", logger.session_id()));
    logger.log(event);
}

/// `session.ended`: the audited session closed. `outcome` is the same
/// `LaunchOutcome` the `--report` result carries, so report and JSONL
/// state the same fact.
pub fn session_ended(logger: &AuditLogger, ctx: &SessionAuditContext, outcome: &LaunchOutcome) {
    let mut event = lifecycle_event(ctx, EventType::SessionEnded, outcome_of(outcome.status));
    let mut details = format!(
        "session_id={} status={}",
        logger.session_id(),
        outcome.status
    );
    if let Some(code) = outcome.exit_code {
        details.push_str(&format!(" exit_code={code}"));
    }
    if let Some(detail) = &outcome.detail {
        details.push_str(&format!(" detail={detail}"));
    }
    event.details = Some(details);
    logger.log(event);
}

/// `server.disconnected`: the link to the child server ended. `reason`
/// names how — `child_exited`, `auditor_closed`, `killed` (interrupted
/// or after an internal failure), `wait_error`, or a forwarded signal
/// name (`sigterm`, `sigint`).
pub fn server_disconnected(
    logger: &AuditLogger,
    ctx: &SessionAuditContext,
    reason: &'static str,
    outcome: &LaunchOutcome,
) {
    let mut event = lifecycle_event(
        ctx,
        EventType::ServerDisconnected,
        outcome_of(outcome.status),
    );
    let mut details = format!("reason={reason} session_id={}", logger.session_id());
    if let Some(code) = outcome.exit_code {
        details.push_str(&format!(" exit_code={code}"));
    }
    event.details = Some(details);
    logger.log(event);
}

/// Emit `server.disconnected` → `session.ended` → `guard.stopped` under
/// the launch correlation id, in that order, then flush and stop the
/// logger. Every session exit path calls this once, so a started
/// session always closes its bracket in the log.
pub async fn teardown(
    logger: &AuditLogger,
    ctx: &SessionAuditContext,
    disconnect_reason: &'static str,
    outcome: &LaunchOutcome,
) {
    server_disconnected(logger, ctx, disconnect_reason, outcome);
    session_ended(logger, ctx, outcome);
    guard_stopped(
        logger,
        ctx,
        outcome.status,
        outcome.exit_code,
        outcome.detail.as_deref(),
    );
    logger.shutdown().await;
}

/// Bracketed lifecycle record for a failure that precedes the session
/// logger — `guard.started` → `policy.error` (when `policy_stage` is
/// set) → `guard.stopped` — through a one-shot logger on `audit_log`,
/// the file the session sink would have used. With no log path the
/// records go to the tracing sink, visible only once a subscriber is
/// installed; an unopenable log path is reported on stderr and falls
/// back the same way. Callers that already failed to open the session
/// sink pass `None` — the path is known unopenable and the failure was
/// already reported, so the bracket goes straight to tracing.
pub async fn prelaunch_abort(
    audit_log: Option<&Path>,
    ctx: &SessionAuditContext,
    policy_stage: Option<&'static str>,
    detail: &str,
) {
    let logger = match audit_log {
        Some(path) => match AuditLogger::to_file_with_fail_closed(path, false) {
            Ok(logger) => logger,
            Err(e) => {
                eprintln!("Error: failed to open audit log '{}': {e}", path.display());
                AuditLogger::to_tracing()
            }
        },
        None => AuditLogger::to_tracing(),
    };
    guard_started(&logger, ctx, None);
    if let Some(stage) = policy_stage {
        policy_error(&logger, ctx, stage, detail);
    }
    guard_stopped(&logger, ctx, "aborted", Some(1), Some(detail));
    logger.shutdown().await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn test_dir() -> PathBuf {
        tempfile::tempdir().unwrap().keep()
    }

    fn ctx_with_policy(policy_id: &str) -> SessionAuditContext {
        SessionAuditContext {
            launch_id: Uuid::now_v7(),
            policy: Some(PolicyAuditContext {
                id: policy_id.to_string(),
                version: "2".to_string(),
                hash: "sha256:test".to_string(),
            }),
            component: "test-component",
        }
    }

    fn read_events(path: &Path) -> Vec<String> {
        std::fs::read_to_string(path)
            .unwrap()
            .lines()
            .map(|l| l.to_string())
            .collect()
    }

    /// `teardown` writes the close bracket in order — disconnected →
    /// ended → stopped — all under the launch correlation id, and
    /// flushes the sink before returning.
    #[tokio::test]
    async fn teardown_emits_close_bracket_in_order() {
        let dir = test_dir();
        let path = dir.join("audit.jsonl");
        let logger = AuditLogger::to_file(&path).unwrap();
        let ctx = ctx_with_policy("srv");
        let outcome = LaunchOutcome {
            status: "exited",
            detail: Some("workload exited with code 0".into()),
            exit_code: Some(0),
        };

        teardown(&logger, &ctx, "child_exited", &outcome).await;

        let lines = read_events(&path);
        assert_eq!(lines.len(), 3, "got: {lines:?}");
        assert!(lines[0].contains("\"event_type\":\"server.disconnected\""));
        assert!(lines[0].contains("reason=child_exited"));
        assert!(lines[1].contains("\"event_type\":\"session.ended\""));
        assert!(lines[1].contains("status=exited"));
        assert!(lines[2].contains("\"event_type\":\"guard.stopped\""));
        assert!(lines[2].contains("component=test-component"));
        let corr = format!("\"correlation_id\":\"{}\"", ctx.launch_id);
        for line in &lines {
            assert!(line.contains(&corr), "wrong correlation: {line}");
            assert!(line.contains("\"outcome\":\"success\""), "got: {line}");
            // A named bound server is the target, not the policy id's
            // "default" fallback label.
            assert!(line.contains("\"target_server\":\"srv\""), "got: {line}");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A server-less policy leaves `target_server` null — the "default"
    /// identity label is not a server name.
    #[tokio::test]
    async fn default_policy_id_is_not_a_target_server() {
        let dir = test_dir();
        let path = dir.join("audit.jsonl");
        let logger = AuditLogger::to_file(&path).unwrap();
        let ctx = ctx_with_policy("default");

        guard_started(&logger, &ctx, None);
        logger.shutdown().await;

        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("\"target_server\":null"), "got: {content}");
        // …but the policy context itself is still stamped.
        assert!(content.contains("\"policy_id\":\"default\""));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `guard.started` carries component, pid, session_id, and the
    /// caller's session-level flags (sandbox bypass, dry-run).
    #[tokio::test]
    async fn guard_started_records_flags_and_identity() {
        let dir = test_dir();
        let path = dir.join("audit.jsonl");
        let logger = AuditLogger::to_file(&path).unwrap();
        let ctx = ctx_with_policy("srv");

        guard_started(
            &logger,
            &ctx,
            Some("sandbox=skipped via MCP_WRIT_SKIP_SANDBOX dry_run=true"),
        );
        logger.shutdown().await;

        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("\"event_type\":\"guard.started\""));
        assert!(content.contains("component=test-component"));
        assert!(content.contains(&format!("pid={}", std::process::id())));
        assert!(content.contains(&format!("session_id={}", logger.session_id())));
        assert!(content.contains("sandbox=skipped via MCP_WRIT_SKIP_SANDBOX"));
        assert!(content.contains("dry_run=true"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `policy.loaded` repeats the effective policy identity and the
    /// resolved fail_on dial so the record stands alone even when the
    /// context hash could not be computed.
    #[tokio::test]
    async fn policy_loaded_records_version_dial_and_source() {
        let dir = test_dir();
        let path = dir.join("audit.jsonl");
        let logger = AuditLogger::to_file(&path).unwrap();
        let ctx = ctx_with_policy("srv");

        policy_loaded(&logger, &ctx, 2, "none", "/etc/mcp-secure/policy.kdl");
        logger.shutdown().await;

        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("\"event_type\":\"policy.loaded\""));
        assert!(content.contains("\"policy_version\":\"2\""));
        assert!(content.contains("fail_on=none"), "got: {content}");
        assert!(content.contains("source=/etc/mcp-secure/policy.kdl"));
        assert!(content.contains(&format!("session_id={}", logger.session_id())));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `policy.error` is a high-severity failure naming the refused
    /// stage; a refused launch carries no `policy_*` fields.
    #[tokio::test]
    async fn policy_error_marks_stage_without_policy_context() {
        let dir = test_dir();
        let path = dir.join("audit.jsonl");
        let logger = AuditLogger::to_file(&path).unwrap();
        let ctx = SessionAuditContext::pre_policy(Uuid::now_v7(), "test-component");

        policy_error(&logger, &ctx, "load", "boom");
        logger.shutdown().await;

        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("\"event_type\":\"policy.error\""));
        assert!(content.contains("\"severity\":\"high\""));
        assert!(content.contains("\"outcome\":\"failure\""));
        assert!(content.contains("stage=load"));
        assert!(content.contains(&format!("session_id={}", logger.session_id())));
        assert!(content.contains("\"policy_id\":null"), "got: {content}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `session.started` / `session.ended` bracket the relay with the
    /// same correlation id, and the report's outcome words are reused.
    #[tokio::test]
    async fn session_bracket_shares_correlation_and_outcome() {
        let dir = test_dir();
        let path = dir.join("audit.jsonl");
        let logger = AuditLogger::to_file(&path).unwrap();
        let ctx = ctx_with_policy("srv");
        let outcome = LaunchOutcome {
            status: "failed",
            detail: Some("auditor relay failed".into()),
            exit_code: Some(1),
        };

        session_started(&logger, &ctx);
        session_ended(&logger, &ctx, &outcome);
        logger.shutdown().await;

        let lines = read_events(&path);
        assert_eq!(lines.len(), 2);
        assert!(lines[0].contains("\"event_type\":\"session.started\""));
        assert!(lines[0].contains("\"outcome\":\"success\""));
        assert!(lines[1].contains("\"event_type\":\"session.ended\""));
        assert!(lines[1].contains("\"outcome\":\"failure\""));
        assert!(lines[1].contains("status=failed"));
        assert!(lines[1].contains("exit_code=1"));
        let corr = format!("\"correlation_id\":\"{}\"", ctx.launch_id);
        assert!(lines.iter().all(|l| l.contains(&corr)));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A pre-session abort still lands a bracketed record on the file
    /// the session sink would have used, under the launch correlation id.
    #[tokio::test]
    async fn prelaunch_abort_writes_policy_error_bracket() {
        let dir = test_dir();
        let path = dir.join("audit.jsonl");
        let ctx = SessionAuditContext::pre_policy(Uuid::now_v7(), "test-component");

        prelaunch_abort(Some(&path), &ctx, Some("bind"), "unknown server 'x'").await;

        let lines = read_events(&path);
        assert_eq!(lines.len(), 3, "got: {lines:?}");
        assert!(lines[0].contains("\"event_type\":\"guard.started\""));
        assert!(lines[1].contains("\"event_type\":\"policy.error\""));
        assert!(lines[1].contains("stage=bind"));
        assert!(lines[2].contains("\"event_type\":\"guard.stopped\""));
        assert!(lines[2].contains("status=aborted"));
        let corr = format!("\"correlation_id\":\"{}\"", ctx.launch_id);
        assert!(lines.iter().all(|l| l.contains(&corr)));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
