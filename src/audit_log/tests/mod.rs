//! `audit_log` unit tests, split by surface:
//!
//! - `record`: the event vocabulary, `write_event_jsonl`, and the time
//!   and bounded-field helpers.
//! - `logger`: `AuditLogger` behavior — backpressure, byte budget,
//!   durability modes, ordered/committed logging, shutdown — plus the
//!   fixtures that drive a real writer task.
//! - `sink`: `open_audit_sink` trust-boundary refusals and the
//!   signal-driven reopen rotation path.
//! - `fairness`: the RF03 ordering regression — a manual clock and a
//!   scripted sink reproduce sustained input, saturation, multiple
//!   rotations and mid-rotation shutdown deterministically.

use super::*;
use std::path::PathBuf;
use uuid::Uuid;

mod fairness;
mod logger;
mod record;
mod sink;

/// An audit-sink fixture root must satisfy the sink's own ancestry
/// gate — a replaceable parent is exactly what `open_audit_sink`
/// refuses — so fixtures live under `restricted_tempdir` and tests
/// skip when the host offers no write-restricted root.
fn make_test_dir(_label: &str) -> Option<PathBuf> {
    crate::testutil::restricted_tempdir().map(|d| d.keep())
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

/// Assemble an `AuditLogger` from parts the test controls — the
/// writer-level tests drive the channel ends and writer task directly
/// instead of going through `to_file`, so fail-closed mode, the record
/// slot bound, and the byte budget stay test-tunable.
#[expect(clippy::too_many_arguments)]
fn assemble_logger(
    tx: mpsc::Sender<WriterItem>,
    writer_handle: tokio::task::JoinHandle<()>,
    fail_closed: bool,
    event_capacity: usize,
    byte_budget: usize,
    file_sink: bool,
    writer_failed: FailureFlag,
    session_id: String,
) -> AuditLogger {
    AuditLogger {
        inner: std::sync::Arc::new(AuditLoggerInner {
            tx: std::sync::Mutex::new(Some(tx)),
            file_sink,
            session_id,
            writer_handle: tokio::sync::Mutex::new(Some(writer_handle)),
            fail_closed,
            dropped: AtomicU64::new(0),
            writer_failed,
            bytes_budget: std::sync::Arc::new(tokio::sync::Semaphore::new(byte_budget)),
            event_slots: std::sync::Arc::new(tokio::sync::Semaphore::new(event_capacity)),
            control_slots: std::sync::Arc::new(tokio::sync::Semaphore::new(CONTROL_QUEUE_CAPACITY)),
        }),
    }
}
