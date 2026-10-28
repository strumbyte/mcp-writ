//! `audit_log` unit tests, split by surface:
//!
//! - `record`: the event vocabulary, `write_event_jsonl`, and the time
//!   and bounded-field helpers.
//! - `logger`: `AuditLogger` behavior — backpressure, byte budget,
//!   durability modes, ordered/committed logging, shutdown — plus the
//!   fixtures that drive a real writer task.
//! - `sink`: `open_audit_sink` trust-boundary refusals and the
//!   signal-driven reopen rotation path.

use super::*;
use std::path::PathBuf;
use uuid::Uuid;

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
