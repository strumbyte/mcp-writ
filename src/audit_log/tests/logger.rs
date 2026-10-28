//! `AuditLogger` behavior: queue backpressure and the byte budget,
//! durability modes, ordered/committed logging, and shutdown
//! accounting — plus the sink fixtures that drive them.

use std::path::Path;

use super::super::*;
use super::{make_test_dir, make_test_event};
use uuid::Uuid;

// ─── AuditLogger integration tests ──────────────────────────────────────

/// Assemble an `AuditLogger` from parts the test controls — the
/// writer-level tests drive the channel ends and writer task directly
/// instead of going through `to_file`, so fail-closed mode, channel
/// capacity, and the byte budget stay test-tunable. The logger's own
/// `reopen_tx` stays empty: these fixtures never expose a live reopen
/// sink to `AuditLogger::reopen`.
fn assemble_logger(
    tx: mpsc::Sender<AuditItem>,
    writer_handle: tokio::task::JoinHandle<()>,
    fail_closed: bool,
    byte_budget: usize,
    writer_failed: FailureFlag,
) -> AuditLogger {
    AuditLogger {
        inner: std::sync::Arc::new(AuditLoggerInner {
            tx: std::sync::Mutex::new(Some(tx)),
            reopen_tx: std::sync::Mutex::new(None),
            session_id: generate_session_id(),
            writer_handle: tokio::sync::Mutex::new(Some(writer_handle)),
            fail_closed,
            dropped: AtomicU64::new(0),
            writer_failed,
            bytes_budget: std::sync::Arc::new(tokio::sync::Semaphore::new(byte_budget)),
        }),
    }
}

/// A file-sink fixture: a real file at `path` drained by a spawned
/// `file_writer_task`, behind a record channel of `channel_capacity`.
/// Returns the logger plus the reopen sender — held by the test so the
/// writer's reopen arm stays live for the test's scope.
fn file_sink_logger(
    path: &Path,
    channel_capacity: usize,
    fail_closed: bool,
) -> (AuditLogger, mpsc::Sender<ReopenRequest>) {
    let file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .unwrap();
    let writer = std::io::BufWriter::with_capacity(BUF_WRITER_CAPACITY, file);
    let (tx, rx) = mpsc::channel(channel_capacity);
    let (reopen_tx, reopen_rx) = mpsc::channel(REOPEN_QUEUE_CAPACITY);
    let writer_failed = FailureFlag::new();
    let writer_handle = tokio::spawn(file_writer_task(
        rx,
        writer,
        writer_failed.clone(),
        SinkAnchor {
            dir: None,
            leaf: None,
        },
        AuditSyncMode::Buffered,
        path.to_path_buf(),
        reopen_rx,
    ));
    (
        assemble_logger(
            tx,
            writer_handle,
            fail_closed,
            QUEUE_BYTE_BUDGET,
            writer_failed,
        ),
        reopen_tx,
    )
}

#[tokio::test]
async fn test_logger_to_file_writes_jsonl() {
    let Some(dir) = make_test_dir("audit_new") else {
        crate::testutil::skip_unless_required("no write-restricted root for audit fixture");
        return;
    };
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
    let Some(dir) = make_test_dir("audit_multi_new") else {
        crate::testutil::skip_unless_required("no write-restricted root for audit fixture");
        return;
    };
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
    let Some(dir) = make_test_dir("audit_flush") else {
        crate::testutil::skip_unless_required("no write-restricted root for audit fixture");
        return;
    };
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
    let Some(dir) = make_test_dir("audit_critical") else {
        crate::testutil::skip_unless_required("no write-restricted root for audit fixture");
        return;
    };
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
    let Some(dir) = make_test_dir("audit_high") else {
        crate::testutil::skip_unless_required("no write-restricted root for audit fixture");
        return;
    };
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
    let Some(dir) = make_test_dir("audit_medium") else {
        crate::testutil::skip_unless_required("no write-restricted root for audit fixture");
        return;
    };
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
    let Some(dir) = make_test_dir("audit_sync_mode") else {
        crate::testutil::skip_unless_required("no write-restricted root for audit fixture");
        return;
    };
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
    let Some(dir) = make_test_dir("audit_bp") else {
        crate::testutil::skip_unless_required("no write-restricted root for audit fixture");
        return;
    };
    let path = dir.join("bp.jsonl");

    let (logger, _reopen_tx) = file_sink_logger(&path, 2, true);

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
    let Some(dir) = make_test_dir("audit_bp_open") else {
        crate::testutil::skip_unless_required("no write-restricted root for audit fixture");
        return;
    };
    let path = dir.join("bp.jsonl");

    let (logger, _reopen_tx) = file_sink_logger(&path, 2, false);

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
    let Some(dir) = make_test_dir("audit_ord_live") else {
        crate::testutil::skip_unless_required("no write-restricted root for audit fixture");
        return;
    };
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
    let Some(dir) = make_test_dir("audit_ord_dead") else {
        crate::testutil::skip_unless_required("no write-restricted root for audit fixture");
        return;
    };
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
    let Some(dir) = make_test_dir("audit_sd_ok") else {
        crate::testutil::skip_unless_required("no write-restricted root for audit fixture");
        return;
    };
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
    let Some(dir) = make_test_dir("audit_sd_err") else {
        crate::testutil::skip_unless_required("no write-restricted root for audit fixture");
        return;
    };
    let path = dir.join("err.jsonl");

    let (logger, _reopen_tx) = file_sink_logger(&path, 2, true);

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
    let Some(dir) = make_test_dir("audit_watch") else {
        crate::testutil::skip_unless_required("no write-restricted root for audit fixture");
        return;
    };
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

/// Attacker-sized string members are bounded at enqueue: a UTF-8-safe
/// prefix plus the original-length marker reaches the file, not the
/// full payload.
#[tokio::test]
async fn test_logger_bounds_wire_fields() {
    let Some(dir) = make_test_dir("audit_bound_field") else {
        crate::testutil::skip_unless_required("no write-restricted root for audit fixture");
        return;
    };
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
/// The byte budget is the aggregate bound the count cap misses: a queue
/// full of oversized records must refuse (counted drop) and latch the
/// fail-closed fault — not grow memory unboundedly.
#[tokio::test]
async fn test_logger_byte_budget_fail_closed() {
    let Some(dir) = make_test_dir("audit_byte_budget") else {
        crate::testutil::skip_unless_required("no write-restricted root for audit fixture");
        return;
    };

    let (tx, rx) = mpsc::channel(64);
    let writer_failed = FailureFlag::new();
    // Park the receiver so the budget stays consumed — the byte
    // accounting is queue-side, so no writer task is needed.
    let rx = Some(rx);
    let writer_handle = tokio::spawn(async move {});
    // One record (~300 wire bytes) fits the 600 budget; a second cannot.
    let logger = assemble_logger(tx, writer_handle, true, 600, writer_failed);

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
