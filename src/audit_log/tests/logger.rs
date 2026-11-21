//! `AuditLogger` behavior: queue backpressure and the byte budget,
//! durability modes, ordered/committed logging, and shutdown
//! accounting — plus the sink fixtures that drive them.

use std::path::Path;

use super::super::writer::AuditSink;
use super::super::*;
use super::{make_test_dir, make_test_event};
use uuid::Uuid;

// ─── AuditLogger integration tests ──────────────────────────────────────

/// A file-sink fixture: a real file at `path` drained by the
/// dedicated writer thread over a `FileSink`/`TokioClock` core,
/// behind an intake queue with `event_capacity` record slots. The
/// logger is a real file-sink logger — `reopen()` routes through the
/// same queue.
fn file_sink_logger(path: &Path, event_capacity: usize, fail_closed: bool) -> AuditLogger {
    let file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .unwrap();
    let writer = std::io::BufWriter::with_capacity(BUF_WRITER_CAPACITY, file);
    let (tx, rx) = mpsc::channel(event_capacity + CONTROL_QUEUE_CAPACITY + TICK_QUEUE_RESERVE);
    let writer_failed = FailureFlag::new();
    let session_id = generate_session_id();
    let sink = FileSink::new(
        writer,
        SinkAnchor {
            dir: None,
            leaf: None,
        },
    );
    let core = WriterCore::new(
        sink,
        TokioClock,
        writer_failed.clone(),
        AuditSyncMode::Buffered,
        session_id.clone(),
        path.to_path_buf(),
    );
    let writer_end = WriterEnd::Thread(spawn_file_writer(&tx, rx, core).unwrap());
    super::assemble_logger(
        tx,
        writer_end,
        fail_closed,
        event_capacity,
        QUEUE_BYTE_BUDGET,
        true,
        writer_failed,
        session_id,
    )
}

/// A `FileSink` wrapper whose first `write_record` parks until
/// released — the dedicated writer thread sits inside the blocking
/// I/O, so the intake queue cannot drain while a test fills it.
struct GateSink {
    inner: FileSink,
    gate: Option<(std::sync::mpsc::Sender<()>, std::sync::mpsc::Receiver<()>)>,
}

impl AuditSink for GateSink {
    fn write_record(&mut self, line: &[u8]) -> std::io::Result<()> {
        if let Some((entered, proceed)) = self.gate.take() {
            let _ = entered.send(());
            let _ = proceed.recv();
        }
        self.inner.write_record(line)
    }
    fn flush_buffer(&mut self) -> std::io::Result<()> {
        self.inner.flush_buffer()
    }
    fn sync_file(&mut self) -> std::io::Result<()> {
        self.inner.sync_file()
    }
    fn needs_dir_sync(&self) -> bool {
        self.inner.needs_dir_sync()
    }
    fn sync_dir(&mut self) -> std::io::Result<()> {
        self.inner.sync_dir()
    }
    fn entry_visible(&self, path: &Path) -> bool {
        self.inner.entry_visible(path)
    }
    fn reopen(&mut self, path: &Path) -> std::io::Result<()> {
        self.inner.reopen(path)
    }
}

/// The `file_sink_logger` fixture behind the write gate — returns the
/// logger plus the gate's entered/proceed ends, so the test can hold
/// the writer inside its first write while it fills the queue.
fn gated_file_sink_logger(
    path: &Path,
    event_capacity: usize,
    fail_closed: bool,
) -> (
    AuditLogger,
    std::sync::mpsc::Receiver<()>,
    std::sync::mpsc::Sender<()>,
) {
    let file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .unwrap();
    let writer = std::io::BufWriter::with_capacity(BUF_WRITER_CAPACITY, file);
    let (tx, rx) = mpsc::channel(event_capacity + CONTROL_QUEUE_CAPACITY + TICK_QUEUE_RESERVE);
    let writer_failed = FailureFlag::new();
    let session_id = generate_session_id();
    let (entered_tx, entered_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let sink = GateSink {
        inner: FileSink::new(
            writer,
            SinkAnchor {
                dir: None,
                leaf: None,
            },
        ),
        gate: Some((entered_tx, release_rx)),
    };
    let core = WriterCore::new(
        sink,
        TokioClock,
        writer_failed.clone(),
        AuditSyncMode::Buffered,
        session_id.clone(),
        path.to_path_buf(),
    );
    let writer_end = WriterEnd::Thread(spawn_file_writer(&tx, rx, core).unwrap());
    (
        super::assemble_logger(
            tx,
            writer_end,
            fail_closed,
            event_capacity,
            QUEUE_BYTE_BUDGET,
            true,
            writer_failed,
            session_id,
        ),
        entered_rx,
        release_tx,
    )
}

/// A `FileSink` wrapper reporting each completed sink step over a
/// std channel — the drop-drain test's completion signal. The drain
/// tail runs flush → fsync → visible-entry proof in order on the
/// writer thread, so an `entry_visible` report proves the final
/// `sync_file` already finished — the file is complete before the
/// test reads or removes it.
struct OpReportSink {
    inner: FileSink,
    ops: std::sync::mpsc::Sender<&'static str>,
}

impl OpReportSink {
    fn report(&self, op: &'static str) {
        let _ = self.ops.send(op);
    }
}

impl AuditSink for OpReportSink {
    fn write_record(&mut self, line: &[u8]) -> std::io::Result<()> {
        let result = self.inner.write_record(line);
        self.report("write_record");
        result
    }
    fn flush_buffer(&mut self) -> std::io::Result<()> {
        let result = self.inner.flush_buffer();
        self.report("flush_buffer");
        result
    }
    fn sync_file(&mut self) -> std::io::Result<()> {
        let result = self.inner.sync_file();
        self.report("sync_file");
        result
    }
    fn needs_dir_sync(&self) -> bool {
        self.inner.needs_dir_sync()
    }
    fn sync_dir(&mut self) -> std::io::Result<()> {
        let result = self.inner.sync_dir();
        self.report("sync_dir");
        result
    }
    fn entry_visible(&self, path: &Path) -> bool {
        let visible = self.inner.entry_visible(path);
        self.report("entry_visible");
        visible
    }
    fn reopen(&mut self, path: &Path) -> std::io::Result<()> {
        let result = self.inner.reopen(path);
        self.report("reopen");
        result
    }
}

/// `file_sink_logger` over `OpReportSink` — returns the logger plus
/// the receiver the test reads as the drain's completion signal.
fn reported_file_sink_logger(
    path: &Path,
    event_capacity: usize,
    fail_closed: bool,
) -> (AuditLogger, std::sync::mpsc::Receiver<&'static str>) {
    let file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .unwrap();
    let writer = std::io::BufWriter::with_capacity(BUF_WRITER_CAPACITY, file);
    let (tx, rx) = mpsc::channel(event_capacity + CONTROL_QUEUE_CAPACITY + TICK_QUEUE_RESERVE);
    let writer_failed = FailureFlag::new();
    let session_id = generate_session_id();
    let (ops_tx, ops_rx) = std::sync::mpsc::channel();
    let sink = OpReportSink {
        inner: FileSink::new(
            writer,
            SinkAnchor {
                dir: None,
                leaf: None,
            },
        ),
        ops: ops_tx,
    };
    let core = WriterCore::new(
        sink,
        TokioClock,
        writer_failed.clone(),
        AuditSyncMode::Buffered,
        session_id.clone(),
        path.to_path_buf(),
    );
    let writer_end = WriterEnd::Thread(spawn_file_writer(&tx, rx, core).unwrap());
    (
        super::assemble_logger(
            tx,
            writer_end,
            fail_closed,
            event_capacity,
            QUEUE_BYTE_BUDGET,
            true,
            writer_failed,
            session_id,
        ),
        ops_rx,
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

/// The writer attaches the logger's own session id at serialization —
/// every line a `log`ged event produces must carry the id
/// `AuditLogger::session_id()` reports, proving the structured member
/// is wired to the same id the `details` strings quote.
#[tokio::test]
async fn test_logger_written_records_carry_logger_session_id() {
    let Some(dir) = make_test_dir("audit_session_id") else {
        crate::testutil::skip_unless_required("no write-restricted root for audit fixture");
        return;
    };
    let path = dir.join("session_id.jsonl");

    let logger = AuditLogger::to_file(&path).expect("should create logger");
    let session_id = logger.session_id().to_owned();
    for _ in 0..3 {
        logger.log(make_test_event());
    }
    let _ = logger.shutdown().await;

    let stamped = format!("\"session_id\":\"{session_id}\"");
    let content = std::fs::read_to_string(&path).expect("should read file");
    assert!(!content.is_empty(), "file should not be empty");
    for line in content.lines() {
        assert!(
            line.contains(&stamped),
            "written record must carry the logger's session_id: {line}"
        );
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

    // The writer parks inside the first record's write — the queue
    // cannot drain while the test fills it, so permit exhaustion is
    // deterministic instead of racing the sink's write speed.
    let (logger, entered_rx, release_tx) = gated_file_sink_logger(&path, 2, true);
    logger.log(make_test_event());
    // The blocking closure's receive is bounded too — the outer
    // timeout abandons the await but cannot cancel the parked
    // `recv()`, so without its own deadline the spawned blocking
    // task could outlive the test still waiting on the gate.
    tokio::time::timeout(
        std::time::Duration::from_secs(10),
        tokio::task::spawn_blocking(move || {
            entered_rx.recv_timeout(std::time::Duration::from_secs(10))
        }),
    )
    .await
    .expect("writer must reach the write gate")
    .expect("spawn_blocking")
    .expect("gate sender");

    for _ in 0..64 {
        logger.log(make_test_event());
    }
    assert!(
        logger.is_failed(),
        "fail-closed logger must become unavailable when the channel fills"
    );
    assert!(logger.ensure_available().is_err());

    release_tx.send(()).unwrap();
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

    // The writer parks inside the first record's write — the queue
    // cannot drain while the submissions land, so the counted drops
    // below are deterministic instead of racing the sink's speed.
    let (logger, entered_rx, release_tx) = gated_file_sink_logger(&path, 2, false);
    logger.log(make_test_event());
    tokio::time::timeout(
        std::time::Duration::from_secs(10),
        tokio::task::spawn_blocking(move || {
            entered_rx.recv_timeout(std::time::Duration::from_secs(10))
        }),
    )
    .await
    .expect("writer must reach the write gate")
    .expect("spawn_blocking")
    .expect("gate sender");

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

    release_tx.send(()).unwrap();
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

    let logger = file_sink_logger(&path, 2, true);

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
/// Dropping the logger without `shutdown()` is still a real stop
/// position: the channel close tells the dedicated writer thread to
/// drain, so the queued records reach the file even though nothing
/// awaited — the drain is not aborted like the old task kill.
#[tokio::test]
async fn test_logger_drop_still_drains() {
    let Some(dir) = make_test_dir("audit_drop_drain") else {
        crate::testutil::skip_unless_required("no write-restricted root for audit fixture");
        return;
    };
    let path = dir.join("drop.jsonl");
    let ops_rx = {
        let (logger, ops_rx) = reported_file_sink_logger(&path, 8, true);
        for _ in 0..4 {
            logger.log(make_test_event());
        }
        drop(logger);
        ops_rx
    };
    // The drain finishes on the writer thread after the logger is
    // gone. Its tail is flush → fsync → the visible-entry proof, so
    // the sink's own `entry_visible` report — arrived after a
    // `sync_file` — is the test's completion signal: the file is
    // durably complete before it is read or removed. A deadline
    // bounds the wait; expiring is a drain failure, not a slow poll.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    let mut saw_sync = false;
    loop {
        match ops_rx.recv_timeout(deadline.saturating_duration_since(std::time::Instant::now())) {
            Ok("sync_file") => saw_sync = true,
            Ok("entry_visible") => break,
            Ok(_) => {}
            Err(e) => panic!("the dropped logger's drain did not finish: {e}"),
        }
    }
    assert!(
        saw_sync,
        "the drain's final entry check must follow its sync_file"
    );
    let lines = std::fs::read_to_string(&path)
        .unwrap_or_default()
        .lines()
        .count();
    assert_eq!(
        lines, 4,
        "the dropped logger's drain must still commit the queued records"
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

    let (tx, rx) = mpsc::channel::<WriterItem>(64);
    let writer_failed = FailureFlag::new();
    // Park the receiver so the budget stays consumed — the byte
    // accounting is queue-side, so no writer task is needed.
    let rx = Some(rx);
    let writer_end = WriterEnd::Task(tokio::spawn(async move {}));
    // One record (~300 wire bytes) fits the 600 budget; a second cannot.
    let logger = super::assemble_logger(
        tx,
        writer_end,
        true,
        64,
        600,
        true,
        writer_failed,
        generate_session_id(),
    );

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
