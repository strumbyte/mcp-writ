use super::emit::days_to_civil;
use super::*;
use std::path::PathBuf;
use uuid::Uuid;

fn make_test_dir(label: &str) -> PathBuf {
    let id = std::process::id();
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = crate::testutil::real_temp_base().join(format!("mcp_writ_{label}_{id}_{ts}"));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn make_test_event() -> AuditEvent {
    let cid = Uuid::now_v7();
    let mut evt = AuditEvent::new(
        cid,
        EventType::ToolCallAllowed,
        Severity::Info,
        Outcome::Success,
        Action::Allowed,
    );
    evt.target_tool = Some("read_file".to_string());
    evt
}

// ─── EventType as_str / category ────────────────────────────────────────

#[test]
fn test_event_type_as_str() {
    assert_eq!(EventType::ToolCallAllowed.as_str(), "tool_call.allowed");
    assert_eq!(EventType::ToolCallDenied.as_str(), "tool_call.denied");
    assert_eq!(EventType::ToolCallModified.as_str(), "tool_call.modified");
    assert_eq!(EventType::ToolsListFiltered.as_str(), "tools_list.filtered");
    assert_eq!(EventType::SandboxFileDenied.as_str(), "sandbox.file_denied");
    assert_eq!(
        EventType::SandboxNetworkAllowed.as_str(),
        "sandbox.network_allowed"
    );
    assert_eq!(
        EventType::SandboxNetworkDenied.as_str(),
        "sandbox.network_denied"
    );
    assert_eq!(
        EventType::SandboxNetworkResolved.as_str(),
        "sandbox.network_resolved"
    );
    assert_eq!(
        EventType::SandboxProcessDenied.as_str(),
        "sandbox.process_denied"
    );
    assert_eq!(
        EventType::ValidationPathTraversal.as_str(),
        "validation.path_traversal"
    );
    assert_eq!(
        EventType::ValidationArgumentInvalid.as_str(),
        "validation.argument_invalid"
    );
    assert_eq!(EventType::GuardStarted.as_str(), "guard.started");
    assert_eq!(EventType::GuardStopped.as_str(), "guard.stopped");
    assert_eq!(EventType::PolicyLoaded.as_str(), "policy.loaded");
    assert_eq!(EventType::PolicyReloaded.as_str(), "policy.reloaded");
    assert_eq!(EventType::PolicyError.as_str(), "policy.error");
    assert_eq!(EventType::SessionStarted.as_str(), "session.started");
    assert_eq!(EventType::SessionEnded.as_str(), "session.ended");
    assert_eq!(EventType::ServerConnected.as_str(), "server.connected");
    assert_eq!(
        EventType::ServerDisconnected.as_str(),
        "server.disconnected"
    );
    assert_eq!(EventType::ServerError.as_str(), "server.error");
    assert_eq!(EventType::HashVerified.as_str(), "hash.verified");
    assert_eq!(EventType::HashMismatch.as_str(), "hash.mismatch");
    assert_eq!(EventType::ToolsListChanged.as_str(), "tools_list.changed");
    assert_eq!(EventType::ManifestFinding.as_str(), "manifest.finding");
}

#[test]
fn test_event_type_category() {
    assert_eq!(EventType::ToolCallAllowed.category(), "policy_enforcement");
    assert_eq!(EventType::ToolCallDenied.category(), "policy_enforcement");
    assert_eq!(
        EventType::ToolsListFiltered.category(),
        "policy_enforcement"
    );
    assert_eq!(EventType::SandboxFileDenied.category(), "sandbox");
    assert_eq!(EventType::ValidationPathTraversal.category(), "validation");
    assert_eq!(EventType::GuardStarted.category(), "system");
    assert_eq!(EventType::PolicyLoaded.category(), "configuration");
    assert_eq!(EventType::SessionStarted.category(), "session");
    assert_eq!(EventType::ServerConnected.category(), "server");
    assert_eq!(EventType::HashVerified.category(), "supply_chain");
}

// ─── Severity ───────────────────────────────────────────────────────────

#[test]
fn test_severity_as_str() {
    assert_eq!(Severity::Info.as_str(), "info");
    assert_eq!(Severity::Low.as_str(), "low");
    assert_eq!(Severity::Medium.as_str(), "medium");
    assert_eq!(Severity::High.as_str(), "high");
    assert_eq!(Severity::Critical.as_str(), "critical");
}

#[test]
fn test_severity_id() {
    assert_eq!(Severity::Info.id(), 1);
    assert_eq!(Severity::Low.id(), 2);
    assert_eq!(Severity::Medium.id(), 3);
    assert_eq!(Severity::High.id(), 4);
    assert_eq!(Severity::Critical.id(), 5);
}

// ─── Outcome ────────────────────────────────────────────────────────────

#[test]
fn test_outcome_as_str() {
    assert_eq!(Outcome::Success.as_str(), "success");
    assert_eq!(Outcome::Failure.as_str(), "failure");
    assert_eq!(Outcome::Unknown.as_str(), "unknown");
}

// ─── Action ─────────────────────────────────────────────────────────────

#[test]
fn test_action_as_str() {
    assert_eq!(Action::Allowed.as_str(), "allowed");
    assert_eq!(Action::Denied.as_str(), "denied");
    assert_eq!(Action::Observed.as_str(), "observed");
    assert_eq!(Action::Modified.as_str(), "modified");
}

// ─── write_event_jsonl ──────────────────────────────────────────────────

#[test]
fn test_write_event_jsonl_valid_json() {
    let event = make_test_event();
    let json = write_event_jsonl(&event);
    let parsed = nojson::RawJson::parse(&json).expect("must be valid JSON");

    let sv = parsed
        .value()
        .to_member("schema_version")
        .unwrap()
        .required()
        .unwrap()
        .as_string_str()
        .unwrap();
    assert_eq!(sv, "1.0");

    let et = parsed
        .value()
        .to_member("event_type")
        .unwrap()
        .required()
        .unwrap()
        .as_string_str()
        .unwrap();
    assert_eq!(et, "tool_call.allowed");

    let ec = parsed
        .value()
        .to_member("event_category")
        .unwrap()
        .required()
        .unwrap()
        .as_string_str()
        .unwrap();
    assert_eq!(ec, "policy_enforcement");

    let sev = parsed
        .value()
        .to_member("severity")
        .unwrap()
        .required()
        .unwrap()
        .as_string_str()
        .unwrap();
    assert_eq!(sev, "info");

    let sid = parsed
        .value()
        .to_member("severity_id")
        .unwrap()
        .required()
        .unwrap()
        .as_raw_str();
    assert_eq!(sid, "1");

    let outcome = parsed
        .value()
        .to_member("outcome")
        .unwrap()
        .required()
        .unwrap()
        .as_string_str()
        .unwrap();
    assert_eq!(outcome, "success");

    let action = parsed
        .value()
        .to_member("action")
        .unwrap()
        .required()
        .unwrap()
        .as_string_str()
        .unwrap();
    assert_eq!(action, "allowed");

    let tool = parsed
        .value()
        .to_member("target_tool")
        .unwrap()
        .required()
        .unwrap()
        .as_string_str()
        .unwrap();
    assert_eq!(tool, "read_file");
}

#[test]
fn test_write_event_jsonl_denied_event() {
    let cid = Uuid::now_v7();
    let mut event = AuditEvent::new(
        cid,
        EventType::ToolCallDenied,
        Severity::High,
        Outcome::Failure,
        Action::Denied,
    );
    event.target_tool = Some("exec_shell".to_string());
    event.details = Some("Path matches denied pattern: /etc/shadow".to_string());

    let json = write_event_jsonl(&event);
    let parsed = nojson::RawJson::parse(&json).expect("must be valid JSON");

    let et = parsed
        .value()
        .to_member("event_type")
        .unwrap()
        .required()
        .unwrap()
        .as_string_str()
        .unwrap();
    assert_eq!(et, "tool_call.denied");

    let details = parsed
        .value()
        .to_member("details")
        .unwrap()
        .required()
        .unwrap()
        .as_string_str()
        .unwrap();
    assert!(details.contains("/etc/shadow"));
}

#[test]
fn test_write_event_jsonl_null_fields() {
    let cid = Uuid::now_v7();
    let event = AuditEvent::new(
        cid,
        EventType::GuardStarted,
        Severity::Info,
        Outcome::Success,
        Action::Observed,
    );
    let json = write_event_jsonl(&event);
    assert!(json.contains("\"target_server\":null"), "got: {json}");
    assert!(json.contains("\"target_tool\":null"), "got: {json}");
    assert!(json.contains("\"policy_id\":null"), "got: {json}");
    assert!(json.contains("\"parent_event_id\":null"), "got: {json}");
    assert!(json.contains("\"details\":null"), "got: {json}");
}

/// The `enforcement` member serializes a verbatim JSON object (not a
/// quoted string) when set, and `null` otherwise — consumers parse it
/// as a real member. The member only accepts `EmbeddedJson`, so the
/// verbatim text always comes from an in-crate serializer.
#[test]
fn test_write_event_jsonl_enforcement_member() {
    let mut event = make_test_event();
    assert!(
        write_event_jsonl(&event).contains("\"enforcement\":null"),
        "absent member must serialize null"
    );

    event.enforcement = Some(EmbeddedJson::new(
        "{\"backend\":\"none\",\"dry_run\":true}".to_string(),
    ));
    let json = write_event_jsonl(&event);
    assert!(
        json.contains("\"enforcement\":{\"backend\":\"none\",\"dry_run\":true}"),
        "object must be verbatim, got: {json}"
    );
    let parsed = nojson::RawJson::parse(&json).expect("must be valid JSON");
    let e = parsed
        .value()
        .to_member("enforcement")
        .unwrap()
        .required()
        .unwrap();
    assert_eq!(e.kind(), nojson::JsonValueKind::Object);
    assert_eq!(
        e.to_member("backend")
            .unwrap()
            .required()
            .unwrap()
            .as_string_str()
            .unwrap(),
        "none"
    );
}

#[test]
fn test_write_event_jsonl_with_policy_context() {
    let cid = Uuid::now_v7();
    let mut event = AuditEvent::new(
        cid,
        EventType::ToolCallAllowed,
        Severity::Info,
        Outcome::Success,
        Action::Allowed,
    );
    event.policy_context = Some(PolicyAuditContext {
        id: "default".to_string(),
        version: "1".to_string(),
        hash: "sha256:a1b2c3".to_string(),
    });

    let json = write_event_jsonl(&event);
    let parsed = nojson::RawJson::parse(&json).expect("must be valid JSON");

    let pid = parsed
        .value()
        .to_member("policy_id")
        .unwrap()
        .required()
        .unwrap()
        .as_string_str()
        .unwrap();
    assert_eq!(pid, "default");

    let pv = parsed
        .value()
        .to_member("policy_version")
        .unwrap()
        .required()
        .unwrap()
        .as_string_str()
        .unwrap();
    assert_eq!(pv, "1");

    let ph = parsed
        .value()
        .to_member("policy_hash")
        .unwrap()
        .required()
        .unwrap()
        .as_string_str()
        .unwrap();
    assert_eq!(ph, "sha256:a1b2c3");
}

#[test]
fn test_write_event_jsonl_uuid_format() {
    let event = make_test_event();
    let json = write_event_jsonl(&event);
    let parsed = nojson::RawJson::parse(&json).expect("must be valid JSON");

    let eid = parsed
        .value()
        .to_member("event_id")
        .unwrap()
        .required()
        .unwrap()
        .as_string_str()
        .unwrap();
    // UUID v7 hyphenated format: 8-4-4-4-12
    assert_eq!(eid.len(), 36);
    assert_eq!(&eid[8..9], "-");
    assert_eq!(&eid[13..14], "-");
    assert_eq!(&eid[18..19], "-");
    assert_eq!(&eid[23..24], "-");
}

#[test]
fn test_write_event_jsonl_with_parent_event_id() {
    let cid = Uuid::now_v7();
    let parent = Uuid::now_v7();
    let mut event = AuditEvent::new(
        cid,
        EventType::ToolCallAllowed,
        Severity::Info,
        Outcome::Success,
        Action::Allowed,
    );
    event.parent_event_id = Some(parent);

    let json = write_event_jsonl(&event);
    let parsed = nojson::RawJson::parse(&json).expect("must be valid JSON");

    let peid = parsed
        .value()
        .to_member("parent_event_id")
        .unwrap()
        .required()
        .unwrap()
        .as_string_str()
        .unwrap();
    assert_eq!(peid.len(), 36);
}

#[test]
fn test_write_event_jsonl_guard_version() {
    let event = make_test_event();
    let json = write_event_jsonl(&event);
    let parsed = nojson::RawJson::parse(&json).expect("must be valid JSON");

    let gv = parsed
        .value()
        .to_member("guard_version")
        .unwrap()
        .required()
        .unwrap()
        .as_string_str()
        .unwrap();
    assert_eq!(gv, env!("CARGO_PKG_VERSION"));
}

// ─── Time Utilities ─────────────────────────────────────────────────────

#[test]
fn test_now_iso8601_millis_format() {
    let ts = now_iso8601_millis();
    assert!(ts.ends_with('Z'), "got: {ts}");
    assert_eq!(ts.len(), 24, "got: {ts}"); // YYYY-MM-DDTHH:MM:SS.mmmZ
    assert_eq!(&ts[4..5], "-");
    assert_eq!(&ts[7..8], "-");
    assert_eq!(&ts[10..11], "T");
    assert_eq!(&ts[13..14], ":");
    assert_eq!(&ts[16..17], ":");
    assert_eq!(&ts[19..20], ".");
}

#[test]
fn test_now_iso8601_format() {
    let ts = now_iso8601();
    assert!(ts.ends_with('Z'), "got: {ts}");
    assert_eq!(ts.len(), 20, "got: {ts}");
}

#[test]
fn test_days_to_civil_epoch() {
    assert_eq!(days_to_civil(0), (1970, 1, 1));
}

#[test]
fn test_days_to_civil_y2k() {
    assert_eq!(days_to_civil(10957), (2000, 1, 1));
}

#[test]
fn test_days_to_civil_2026() {
    // 56*365 = 20440, leap years in [1972..2025]: 14 → 20454
    assert_eq!(days_to_civil(20454), (2026, 1, 1));
}

#[test]
fn test_days_to_civil_overflow_clamp() {
    assert_eq!(days_to_civil(i64::MAX), (1970, 1, 1));
    assert_eq!(days_to_civil(i64::MIN), (1970, 1, 1));
    assert_eq!(days_to_civil(365_000_001), (1970, 1, 1));
    assert_eq!(days_to_civil(-365_000_001), (1970, 1, 1));
}

#[test]
fn test_generate_session_id_not_empty() {
    let id = generate_session_id();
    assert!(!id.is_empty());
    assert!(id.contains('-'));
}

// ─── AuditLogger integration tests ──────────────────────────────────────

#[tokio::test]
async fn test_logger_to_file_writes_jsonl() {
    let dir = make_test_dir("audit_new");
    let path = dir.join("test_audit.jsonl");

    let logger = AuditLogger::to_file(&path).expect("should create logger");
    let event = make_test_event();
    logger.log(event);

    // Gracefully shutdown: closes channel and awaits writer task flush
    let _ = logger.shutdown().await;

    let content = std::fs::read_to_string(&path).expect("should read file");
    assert!(!content.is_empty(), "file should not be empty");
    assert!(content.contains("\"event_type\":\"tool_call.allowed\""));
    assert!(content.contains("\"target_tool\":\"read_file\""));

    // Verify each line is valid JSON
    for line in content.lines() {
        nojson::RawJson::parse(line).expect("each line must be valid JSON");
    }

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn test_logger_multiple_events() {
    let dir = make_test_dir("audit_multi_new");
    let path = dir.join("multi.jsonl");

    let logger = AuditLogger::to_file(&path).expect("should create logger");
    for _ in 0..5 {
        logger.log(make_test_event());
    }

    let _ = logger.shutdown().await;

    let content = std::fs::read_to_string(&path).expect("should read file");
    let lines: Vec<&str> = content.lines().collect();
    assert_eq!(lines.len(), 5);

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn test_logger_channel_close_flushes() {
    let dir = make_test_dir("audit_flush");
    let path = dir.join("flush.jsonl");

    let logger = AuditLogger::to_file(&path).expect("should create logger");

    // Send a few events
    for _ in 0..3 {
        logger.log(make_test_event());
    }

    // Shutdown closes channel — writer flushes and exits
    let _ = logger.shutdown().await;

    let content = std::fs::read_to_string(&path).expect("should read file");
    let lines: Vec<&str> = content.lines().collect();
    assert_eq!(
        lines.len(),
        3,
        "all 3 events must be flushed on channel close"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn test_logger_critical_event_triggers_flush() {
    let dir = make_test_dir("audit_critical");
    let path = dir.join("critical.jsonl");

    let logger = AuditLogger::to_file(&path).expect("should create logger");

    let cid = Uuid::now_v7();
    let event = AuditEvent::new(
        cid,
        EventType::ToolCallDenied,
        Severity::Critical,
        Outcome::Failure,
        Action::Denied,
    );
    logger.log(event);

    // Critical events trigger immediate flush; give the writer task a moment
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let content = std::fs::read_to_string(&path).expect("should read file");
    assert!(
        content.contains("\"severity\":\"critical\""),
        "critical event should be flushed immediately"
    );

    let _ = logger.shutdown().await;
    let _ = std::fs::remove_dir_all(&dir);
}

/// A High-severity record skips the buffered tail the same way a
/// Critical one does — it is flushed (and fsync'd) as soon as the
/// writer dequeues it, so a reader sees it well inside the 1s
/// periodic-flush window.
#[tokio::test]
async fn test_logger_high_severity_persists_immediately() {
    let dir = make_test_dir("audit_high");
    let path = dir.join("high.jsonl");

    let logger = AuditLogger::to_file(&path).expect("should create logger");
    let cid = Uuid::now_v7();
    let event = AuditEvent::new(
        cid,
        EventType::ToolCallDenied,
        Severity::High,
        Outcome::Failure,
        Action::Denied,
    );
    logger.log(event);

    // High+ records take the immediate sync path; give the writer a
    // moment well under the 1s periodic flush.
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    let content = std::fs::read_to_string(&path).expect("should read file");
    assert!(
        content.contains("\"severity\":\"high\""),
        "high event should be persisted immediately, got: {content}"
    );

    let _ = logger.shutdown().await;
    let _ = std::fs::remove_dir_all(&dir);
}

/// A sub-High record rides the buffered tail: still in the BufWriter
/// inside the 1s window, it reaches the file on the periodic flush or
/// the shutdown flush — never eagerly.
#[tokio::test]
async fn test_logger_medium_stays_buffered() {
    let dir = make_test_dir("audit_medium");
    let path = dir.join("medium.jsonl");

    let logger = AuditLogger::to_file(&path).expect("should create logger");
    let cid = Uuid::now_v7();
    let event = AuditEvent::new(
        cid,
        EventType::McpMessageUndecided,
        Severity::Medium,
        Outcome::Success,
        Action::Allowed,
    );
    logger.log(event);

    tokio::time::sleep(std::time::Duration::from_millis(150)).await;
    let early = std::fs::read_to_string(&path).expect("should read file");
    assert!(
        early.is_empty(),
        "medium event must stay buffered inside the flush window, got: {early}"
    );

    let _ = logger.shutdown().await;
    let content = std::fs::read_to_string(&path).expect("should read file");
    assert!(content.contains("\"severity\":\"medium\""));
    let _ = std::fs::remove_dir_all(&dir);
}

/// `AuditSyncMode::EveryEvent` (`--audit-sync`) persists even an Info
/// record as soon as the writer dequeues it — no buffered tail at all.
#[tokio::test]
async fn test_logger_every_event_syncs_info_records() {
    let dir = make_test_dir("audit_sync_mode");
    let path = dir.join("sync.jsonl");

    let logger = AuditLogger::to_file_with_options(&path, true, AuditSyncMode::EveryEvent)
        .expect("should create logger");
    for _ in 0..3 {
        logger.log(make_test_event());
    }

    // Each record is flushed+fsync'd on dequeue; ~300ms is far under
    // the 1s tick, so presence here proves the per-record path.
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;

    let content = std::fs::read_to_string(&path).expect("should read file");
    let lines: Vec<&str> = content.lines().collect();
    assert_eq!(
        lines.len(),
        3,
        "every-event mode must persist each record eagerly, got: {content}"
    );

    let _ = logger.shutdown().await;
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn test_severity_ordering() {
    assert!(Severity::Critical > Severity::High);
    assert!(Severity::High > Severity::Medium);
    assert!(Severity::Medium > Severity::Low);
    assert!(Severity::Low > Severity::Info);
    assert!(Severity::High >= IMMEDIATE_SYNC_SEVERITY);
    assert!(Severity::Medium < IMMEDIATE_SYNC_SEVERITY);
}

#[tokio::test]
async fn test_logger_backpressure_channel_full() {
    let dir = make_test_dir("audit_bp");
    let path = dir.join("bp.jsonl");

    let file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .unwrap();
    let writer = std::io::BufWriter::with_capacity(BUF_WRITER_CAPACITY, file);
    let (tx, rx) = mpsc::channel(2);
    let session_id = generate_session_id();
    let writer_failed = super::FailureFlag::new();
    let writer_handle = tokio::spawn(file_writer_task(
        rx,
        writer,
        writer_failed.clone(),
        None,
        AuditSyncMode::Buffered,
    ));
    let logger = AuditLogger {
        inner: std::sync::Arc::new(AuditLoggerInner {
            tx: std::sync::Mutex::new(Some(tx)),
            session_id,
            writer_handle: tokio::sync::Mutex::new(Some(writer_handle)),
            fail_closed: true,
            dropped: AtomicU64::new(0),
            writer_failed,
            bytes_budget: std::sync::Arc::new(tokio::sync::Semaphore::new(QUEUE_BYTE_BUDGET)),
        }),
    };

    for _ in 0..64 {
        logger.log(make_test_event());
    }
    assert!(
        logger.is_failed(),
        "fail-closed logger must become unavailable when the channel fills"
    );
    assert!(logger.ensure_available().is_err());

    let _ = logger.shutdown().await;
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn test_logger_channel_full_best_effort_stays_available() {
    let dir = make_test_dir("audit_bp_open");
    let path = dir.join("bp.jsonl");

    let file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .unwrap();
    let writer = std::io::BufWriter::with_capacity(BUF_WRITER_CAPACITY, file);
    let (tx, rx) = mpsc::channel(2);
    let session_id = generate_session_id();
    let writer_failed = super::FailureFlag::new();
    let writer_handle = tokio::spawn(file_writer_task(
        rx,
        writer,
        writer_failed.clone(),
        None,
        AuditSyncMode::Buffered,
    ));
    let logger = AuditLogger {
        inner: std::sync::Arc::new(AuditLoggerInner {
            tx: std::sync::Mutex::new(Some(tx)),
            session_id,
            writer_handle: tokio::sync::Mutex::new(Some(writer_handle)),
            fail_closed: false,
            dropped: AtomicU64::new(0),
            writer_failed,
            bytes_budget: std::sync::Arc::new(tokio::sync::Semaphore::new(QUEUE_BYTE_BUDGET)),
        }),
    };

    for _ in 0..64 {
        logger.log(make_test_event());
    }
    // A saturated channel in best-effort mode is a counted drop, not
    // a writer fault — the flag that drives `is_failed` must stay
    // clear (that flag, not `is_failed`, is what the change affects:
    // `is_failed` already masks it under `fail_closed == false`).
    assert!(
        !logger.inner.writer_failed.get(),
        "best-effort saturation must not mark the writer failed"
    );
    assert!(
        !logger.is_failed(),
        "fail-open logger must stay available when the channel fills"
    );
    assert!(logger.ensure_available().is_ok());
    assert!(
        logger.dropped_count() > 0,
        "a saturated channel must leave a counted drop"
    );

    let _ = logger.shutdown().await;
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn test_logger_to_tracing_no_panic() {
    let logger = AuditLogger::to_tracing();
    logger.log(make_test_event());
    let _ = logger.shutdown().await;
}

#[tokio::test]
async fn test_logger_log_ordered_enqueues_on_live_channel() {
    // The pre-forward record path: on a healthy fail-closed logger the
    // record is enqueued and reaches the file like any other event.
    let dir = make_test_dir("audit_ord_live");
    let path = dir.join("ord.jsonl");
    let logger = AuditLogger::to_file(&path).unwrap();
    logger.log_ordered(make_test_event()).await.unwrap();
    let _ = logger.shutdown().await;
    let body = std::fs::read_to_string(&path).unwrap();
    assert!(
        body.contains("tool_call.allowed"),
        "ordered record must reach the file, got: {body}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn test_logger_log_ordered_refuses_after_shutdown() {
    // A closed channel refuses the forward instead of dropping the
    // record silently — and poisons the fail-closed session.
    let dir = make_test_dir("audit_ord_dead");
    let path = dir.join("ord.jsonl");
    let logger = AuditLogger::to_file(&path).unwrap();
    let _ = logger.shutdown().await;
    let err = logger.log_ordered(make_test_event()).await.unwrap_err();
    assert!(
        matches!(err, crate::error::AuditorError::AuditUnavailable(_)),
        "expected AuditUnavailable, got: {err:?}"
    );
    assert!(logger.is_failed());
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn test_logger_shutdown_reports_clean_writer() {
    let dir = make_test_dir("audit_sd_ok");
    let path = dir.join("ok.jsonl");
    let logger = AuditLogger::to_file(&path).unwrap();
    logger.log(make_test_event());
    assert!(logger.shutdown().await.is_ok(), "clean shutdown must be Ok");
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn test_logger_shutdown_reports_writer_failure() {
    // A latched writer fault must surface in the shutdown result —
    // fail-closed callers fold it into the command outcome so a session
    // that lost audit records cannot report success.
    let dir = make_test_dir("audit_sd_err");
    let path = dir.join("err.jsonl");

    let file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .unwrap();
    let writer = std::io::BufWriter::with_capacity(BUF_WRITER_CAPACITY, file);
    let (tx, rx) = mpsc::channel(2);
    let writer_failed = super::FailureFlag::new();
    let writer_handle = tokio::spawn(file_writer_task(
        rx,
        writer,
        writer_failed.clone(),
        None,
        AuditSyncMode::Buffered,
    ));
    let logger = AuditLogger {
        inner: std::sync::Arc::new(AuditLoggerInner {
            tx: std::sync::Mutex::new(Some(tx)),
            session_id: generate_session_id(),
            writer_handle: tokio::sync::Mutex::new(Some(writer_handle)),
            fail_closed: true,
            dropped: AtomicU64::new(0),
            writer_failed,
            bytes_budget: std::sync::Arc::new(tokio::sync::Semaphore::new(QUEUE_BYTE_BUDGET)),
        }),
    };

    // Drop the sender — a subsequent log attempt latches the writer
    // fault deterministically (no saturation race).
    logger.inner.tx.lock().unwrap().take();
    logger.log(make_test_event());
    assert!(logger.is_failed());
    let err = logger.shutdown().await.unwrap_err();
    assert!(
        matches!(err, crate::error::AuditorError::AuditUnavailable(_)),
        "expected AuditUnavailable, got: {err:?}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn test_logger_failure_watch_fires_on_set() {
    // The idle-relay contract: a subscribed watch wakes the moment the
    // writer fault is recorded, not on the next logging call.
    let dir = make_test_dir("audit_watch");
    let path = dir.join("watch.jsonl");
    let logger = AuditLogger::to_file(&path).unwrap();
    let mut watch = logger.failure_watch();
    let _ = logger.shutdown().await;
    // A log attempt after shutdown records a writer fault.
    logger.log(make_test_event());
    tokio::time::timeout(std::time::Duration::from_secs(5), watch.changed())
        .await
        .expect("failure watch must fire on writer fault")
        .unwrap();
    assert!(logger.is_failed());
    let _ = std::fs::remove_dir_all(&dir);
}

// ─── Sink hardening (F18/F47) and field bounding (F68) ─────────────────

/// A planted symlink at the sink path must refuse the open — the audit
/// stream must never append through a link to an attacker-selected file.
#[cfg(unix)]
#[tokio::test]
async fn test_audit_sink_refuses_symlink_leaf() {
    let dir = make_test_dir("audit_sink_link");
    let target = dir.join("sentinel.txt");
    std::fs::write(&target, b"sentinel").unwrap();
    let link = dir.join("audit.jsonl");
    std::os::unix::fs::symlink(&target, &link).unwrap();

    let result = AuditLogger::to_file(&link);
    assert!(result.is_err(), "symlink sink must be refused");
    assert_eq!(
        std::fs::read_to_string(&target).unwrap(),
        "sentinel",
        "refused open must not have written through the link"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// A symlinked ancestor directory is just as redirecting — the trusted
/// openat walk must reject it before the leaf is even opened.
#[cfg(unix)]
#[tokio::test]
async fn test_audit_sink_refuses_symlinked_ancestor() {
    let dir = make_test_dir("audit_sink_ancestor");
    let real_dir = dir.join("real");
    std::fs::create_dir(&real_dir).unwrap();
    let link_dir = dir.join("linked");
    std::os::unix::fs::symlink(&real_dir, &link_dir).unwrap();

    let path = link_dir.join("audit.jsonl");
    let result = AuditLogger::to_file(&path);
    assert!(
        result.is_err(),
        "a symlinked ancestor must refuse the sink open"
    );
    assert!(
        !real_dir.join("audit.jsonl").exists(),
        "refused open must not create the file through the link"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// A pre-existing sink with ambient (group/other-readable) permissions
/// is tightened to owner-only on the opened handle — security metadata
/// must not be left world-readable just because the operator pre-created
/// the file.
#[cfg(unix)]
#[tokio::test]
async fn test_audit_sink_tightens_existing_perms() {
    use std::os::unix::fs::PermissionsExt;
    let dir = make_test_dir("audit_sink_perms");
    let path = dir.join("audit.jsonl");
    std::fs::write(&path, b"").unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();

    let logger = AuditLogger::to_file(&path).unwrap();
    let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "existing sink must be tightened to 0600");
    let _ = logger.shutdown().await;
    let _ = std::fs::remove_dir_all(&dir);
}

/// A non-regular sink (FIFO) must be refused — appending to a pipe
/// would block the writer or feed a reader that is not the audit trail.
#[cfg(unix)]
#[tokio::test]
async fn test_audit_sink_refuses_fifo() {
    let dir = make_test_dir("audit_sink_fifo");
    let path = dir.join("audit.jsonl");
    let c = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);

    let result = AuditLogger::to_file(&path);
    assert!(result.is_err(), "FIFO sink must be refused");
    let _ = std::fs::remove_dir_all(&dir);
}

/// Attacker-sized string members are bounded at enqueue: a UTF-8-safe
/// prefix plus the original-length marker reaches the file, not the
/// full payload.
#[tokio::test]
async fn test_logger_bounds_wire_fields() {
    let dir = make_test_dir("audit_bound_field");
    let path = dir.join("b.jsonl");
    let logger = AuditLogger::to_file(&path).unwrap();

    let mut ev = make_test_event();
    ev.details = Some("x".repeat(10_000));
    ev.target_tool = Some("t".repeat(5_000));
    logger.log_committed(ev).await.unwrap();
    let _ = logger.shutdown().await;

    let body = std::fs::read_to_string(&path).unwrap();
    assert!(
        body.contains("truncated 10000 bytes"),
        "oversized details must record the truncation marker, got: {body}"
    );
    assert!(body.contains("truncated 5000 bytes"));
    assert!(
        !body.contains(&"x".repeat(2000)),
        "the full oversized payload must not reach the file"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// The bound_audit_field helper keeps short values verbatim and cuts
/// at a UTF-8 boundary for multi-byte content.
#[test]
fn test_bound_audit_field_contract() {
    assert_eq!(bound_audit_field("short"), "short");
    let long = "é".repeat(2000); // 2-byte chars — 1024 lands mid-char
    let bound = bound_audit_field(&long);
    assert!(bound.contains(&format!("truncated {} bytes", long.len())));
    assert!(bound.len() < long.len());
    // The kept prefix is valid UTF-8 (the assertion above would panic
    // on an invalid boundary via the format! anyway).
    assert!(bound.starts_with('é'));
}

/// `encode_audit_field_value` keeps benign `k=v` values verbatim — the
/// flat `details` field stays greppable — and percent-encodes every
/// byte that could delimit the field or sigil an escape.
#[test]
fn test_encode_audit_field_value() {
    // Benign values pass through unchanged.
    assert_eq!(encode_audit_field_value("2025-06-18"), "2025-06-18");
    assert_eq!(encode_audit_field_value("Az-._~09"), "Az-._~09");
    assert_eq!(encode_audit_field_value(""), "");

    // Flat-field delimiters are encoded — a peer-controlled value can
    // never forge `k=v` members or `; `-joined notes.
    assert_eq!(
        encode_audit_field_value("evil supported=2026-07-28"),
        "evil%20supported%3D2026-07-28"
    );
    assert_eq!(
        encode_audit_field_value("a;b\nreason=allow\"q'"),
        "a%3Bb%0Areason%3Dallow%22q%27"
    );
    // The escape sigil itself and non-ASCII bytes are encoded too.
    assert_eq!(encode_audit_field_value("100%é"), "100%25%C3%A9");
}

/// The encoder's output alphabet is unreserved characters plus `%` —
/// nothing in it can act as a `details` delimiter, a quoting
/// character, or a terminal control.
#[test]
fn test_encode_audit_field_value_output_alphabet() {
    let hostile = "a b=c;d\te\nf\u{202e}\x1b[0m%'\"\\/  ";
    let out = encode_audit_field_value(hostile);
    assert!(!out.is_empty());
    for ch in out.chars() {
        assert!(
            ch.is_ascii_alphanumeric() || matches!(ch, '-' | '.' | '_' | '~' | '%'),
            "output must stay a single unreserved token, got {out:?} (char {ch:?})"
        );
    }
}

/// The byte budget is the aggregate bound the count cap misses: a queue
/// full of oversized records must refuse (counted drop) and latch the
/// fail-closed fault — not grow memory unboundedly.
#[tokio::test]
async fn test_logger_byte_budget_fail_closed() {
    let dir = make_test_dir("audit_byte_budget");

    let (tx, rx) = mpsc::channel(64);
    let writer_failed = super::FailureFlag::new();
    // Park the receiver so the budget stays consumed — the byte
    // accounting is queue-side, so no writer task is needed.
    let rx = Some(rx);
    let writer_handle = tokio::spawn(async move {});
    let logger = AuditLogger {
        inner: std::sync::Arc::new(AuditLoggerInner {
            tx: std::sync::Mutex::new(Some(tx)),
            session_id: generate_session_id(),
            writer_handle: tokio::sync::Mutex::new(Some(writer_handle)),
            fail_closed: true,
            dropped: AtomicU64::new(0),
            writer_failed,
            // One record (~300 wire bytes) fits; a second cannot.
            bytes_budget: std::sync::Arc::new(tokio::sync::Semaphore::new(600)),
        }),
    };

    let mut big = make_test_event();
    big.details = Some("y".repeat(500));
    logger.log(big); // ~756 wire bytes > 600 budget → refused outright
    assert!(logger.dropped_count() > 0);
    assert!(
        logger.is_failed(),
        "exhausted byte budget must latch the fail-closed fault"
    );

    drop(rx);
    let _ = logger.shutdown().await;
    let _ = std::fs::remove_dir_all(&dir);
}
