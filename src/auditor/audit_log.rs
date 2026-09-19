use std::io::Write;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use tokio::sync::mpsc;
use uuid::Uuid;

// ═══════════════════════════════════════════════════════════════════════════════
// Event Type Taxonomy (OCSF-compatible)
// ═══════════════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventType {
    // policy_enforcement
    ToolCallAllowed,
    ToolCallDenied,
    ToolCallModified,
    // sandbox
    SandboxFileDenied,
    SandboxNetworkDenied,
    SandboxProcessDenied,
    // validation
    ValidationPathTraversal,
    ValidationArgumentInvalid,
    // system
    GuardStarted,
    GuardStopped,
    // configuration
    PolicyLoaded,
    PolicyReloaded,
    PolicyError,
    // session
    SessionStarted,
    SessionEnded,
    // server
    ServerConnected,
    ServerDisconnected,
    ServerError,
    // supply_chain
    HashVerified,
    HashMismatch,
    ToolsListChanged,
    ManifestFinding,
}

impl EventType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ToolCallAllowed => "tool_call.allowed",
            Self::ToolCallDenied => "tool_call.denied",
            Self::ToolCallModified => "tool_call.modified",
            Self::SandboxFileDenied => "sandbox.file_denied",
            Self::SandboxNetworkDenied => "sandbox.network_denied",
            Self::SandboxProcessDenied => "sandbox.process_denied",
            Self::ValidationPathTraversal => "validation.path_traversal",
            Self::ValidationArgumentInvalid => "validation.argument_invalid",
            Self::GuardStarted => "guard.started",
            Self::GuardStopped => "guard.stopped",
            Self::PolicyLoaded => "policy.loaded",
            Self::PolicyReloaded => "policy.reloaded",
            Self::PolicyError => "policy.error",
            Self::SessionStarted => "session.started",
            Self::SessionEnded => "session.ended",
            Self::ServerConnected => "server.connected",
            Self::ServerDisconnected => "server.disconnected",
            Self::ServerError => "server.error",
            Self::HashVerified => "hash.verified",
            Self::HashMismatch => "hash.mismatch",
            Self::ToolsListChanged => "tools_list.changed",
            Self::ManifestFinding => "manifest.finding",
        }
    }

    pub fn category(&self) -> &'static str {
        match self {
            Self::ToolCallAllowed | Self::ToolCallDenied | Self::ToolCallModified => {
                "policy_enforcement"
            }
            Self::SandboxFileDenied | Self::SandboxNetworkDenied | Self::SandboxProcessDenied => {
                "sandbox"
            }
            Self::ValidationPathTraversal | Self::ValidationArgumentInvalid => "validation",
            Self::GuardStarted | Self::GuardStopped => "system",
            Self::PolicyLoaded | Self::PolicyReloaded | Self::PolicyError => "configuration",
            Self::SessionStarted | Self::SessionEnded => "session",
            Self::ServerConnected | Self::ServerDisconnected | Self::ServerError => "server",
            Self::HashVerified
            | Self::HashMismatch
            | Self::ToolsListChanged
            | Self::ManifestFinding => "supply_chain",
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Severity / Outcome / Action
// ═══════════════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    Info = 1,
    Low = 2,
    Medium = 3,
    High = 4,
    Critical = 5,
}

impl Severity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }

    pub fn id(&self) -> u8 {
        *self as u8
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Success,
    Failure,
    Unknown,
}

impl Outcome {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Failure => "failure",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Allowed,
    Denied,
    Observed,
    Modified,
}

impl Action {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Allowed => "allowed",
            Self::Denied => "denied",
            Self::Observed => "observed",
            Self::Modified => "modified",
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Policy Audit Context
// ═══════════════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone)]
pub struct PolicyAuditContext {
    pub id: String,
    pub version: String,
    pub hash: String,
}

// ═══════════════════════════════════════════════════════════════════════════════
// Audit Event
// ═══════════════════════════════════════════════════════════════════════════════

pub struct AuditEvent {
    pub timestamp: String,
    pub event_id: Uuid,
    pub correlation_id: Uuid,
    pub parent_event_id: Option<Uuid>,
    pub event_type: EventType,
    pub severity: Severity,
    pub outcome: Outcome,
    pub action: Action,
    pub target_server: Option<String>,
    pub target_tool: Option<String>,
    /// Raw JSON-RPC `id` of the client request this event answers, when the
    /// event is tied to a specific request. Lets a `tool_call.denied`
    /// record be correlated with the request it responded to. Stored as a
    /// string because JSON-RPC ids may be numbers, strings, or null.
    pub request_id: Option<String>,
    pub policy_context: Option<PolicyAuditContext>,
    pub details: Option<String>,
    pub schema_version: &'static str,
}

impl AuditEvent {
    pub fn new(
        correlation_id: Uuid,
        event_type: EventType,
        severity: Severity,
        outcome: Outcome,
        action: Action,
    ) -> Self {
        Self {
            timestamp: now_iso8601_millis(),
            event_id: Uuid::now_v7(),
            correlation_id,
            parent_event_id: None,
            event_type,
            severity,
            outcome,
            action,
            target_server: None,
            target_tool: None,
            request_id: None,
            policy_context: None,
            details: None,
            schema_version: "1.0",
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// AuditLogger (mpsc channel + dedicated writer task)
// ═══════════════════════════════════════════════════════════════════════════════

const CHANNEL_CAPACITY: usize = 4096;
const BUF_WRITER_CAPACITY: usize = 65536; // 64KB
const FLUSH_EVENT_THRESHOLD: u32 = 100;

#[derive(Clone)]
pub struct AuditLogger {
    inner: std::sync::Arc<AuditLoggerInner>,
}

struct AuditLoggerInner {
    tx: std::sync::Mutex<Option<mpsc::Sender<AuditEvent>>>,
    session_id: String,
    writer_handle: tokio::sync::Mutex<Option<tokio::task::JoinHandle<()>>>,
    fail_closed: bool,
    dropped: AtomicU64,
    writer_failed: std::sync::Arc<AtomicBool>,
}

impl AuditLogger {
    /// Create a logger that appends JSONL to a file.
    /// Spawns a dedicated writer task on the tokio runtime.
    pub fn to_file(path: &Path) -> Result<Self, std::io::Error> {
        Self::to_file_with_fail_closed(path, true)
    }

    /// Create a file logger. When `fail_closed` is true, enqueue or write
    /// failures mark the logger unavailable so enforcement can stop.
    pub fn to_file_with_fail_closed(
        path: &Path,
        fail_closed: bool,
    ) -> Result<Self, std::io::Error> {
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)?;
        let writer = std::io::BufWriter::with_capacity(BUF_WRITER_CAPACITY, file);
        let (tx, rx) = mpsc::channel(CHANNEL_CAPACITY);
        let session_id = generate_session_id();
        let writer_failed = std::sync::Arc::new(AtomicBool::new(false));
        let writer_handle = tokio::spawn(file_writer_task(rx, writer, writer_failed.clone()));
        Ok(Self {
            inner: std::sync::Arc::new(AuditLoggerInner {
                tx: std::sync::Mutex::new(Some(tx)),
                session_id,
                writer_handle: tokio::sync::Mutex::new(Some(writer_handle)),
                fail_closed,
                dropped: AtomicU64::new(0),
                writer_failed,
            }),
        })
    }

    /// Create a logger that outputs via tracing (stderr).
    /// Spawns a dedicated writer task on the tokio runtime.
    pub fn to_tracing() -> Self {
        Self::to_tracing_with_fail_closed(false)
    }

    /// Tracing/stderr logger. `fail_closed` makes a full channel abort the session.
    pub fn to_tracing_with_fail_closed(fail_closed: bool) -> Self {
        let (tx, rx) = mpsc::channel(CHANNEL_CAPACITY);
        let session_id = generate_session_id();
        let writer_failed = std::sync::Arc::new(AtomicBool::new(false));
        let writer_handle = tokio::spawn(tracing_writer_task(rx));
        Self {
            inner: std::sync::Arc::new(AuditLoggerInner {
                tx: std::sync::Mutex::new(Some(tx)),
                session_id,
                writer_handle: tokio::sync::Mutex::new(Some(writer_handle)),
                fail_closed,
                dropped: AtomicU64::new(0),
                writer_failed,
            }),
        }
    }

    /// Get the session ID for this logger instance.
    pub fn session_id(&self) -> &str {
        &self.inner.session_id
    }

    /// Log an audit event. Non-blocking.
    ///
    /// When `fail_closed` is set, a full or closed channel marks the logger
    /// unavailable instead of silently discarding the event.
    pub fn log(&self, event: AuditEvent) {
        let tx_opt = self.inner.tx.lock().unwrap();
        if let Some(tx) = tx_opt.as_ref() {
            if let Err(e) = tx.try_send(event) {
                match e {
                    mpsc::error::TrySendError::Full(evt) => {
                        self.inner.dropped.fetch_add(1, Ordering::Relaxed);
                        self.inner.writer_failed.store(true, Ordering::SeqCst);
                        tracing::error!(
                            event_type = evt.event_type.as_str(),
                            fail_closed = self.inner.fail_closed,
                            "Audit log channel full"
                        );
                    }
                    mpsc::error::TrySendError::Closed(evt) => {
                        self.inner.writer_failed.store(true, Ordering::SeqCst);
                        tracing::error!(
                            event_type = evt.event_type.as_str(),
                            "Audit log channel closed"
                        );
                    }
                }
            }
        } else {
            self.inner.writer_failed.store(true, Ordering::SeqCst);
            tracing::error!(
                event_type = event.event_type.as_str(),
                "Audit log channel unavailable after shutdown"
            );
        }
    }

    /// Enqueue an event and, in fail-closed mode, wait until it is accepted
    /// by the writer channel before continuing.
    pub async fn log_committed(&self, event: AuditEvent) -> Result<(), crate::error::AuditorError> {
        if !self.inner.fail_closed {
            self.log(event);
            return self.ensure_available();
        }
        let tx = {
            let guard = self.inner.tx.lock().unwrap();
            guard.as_ref().cloned()
        };
        match tx {
            Some(tx) => {
                if tx.send(event).await.is_err() {
                    self.inner.writer_failed.store(true, Ordering::SeqCst);
                    return Err(crate::error::AuditorError::AuditUnavailable(
                        "audit log channel closed".into(),
                    ));
                }
            }
            None => {
                self.inner.writer_failed.store(true, Ordering::SeqCst);
                return Err(crate::error::AuditorError::AuditUnavailable(
                    "audit log channel unavailable".into(),
                ));
            }
        }
        self.ensure_available()
    }

    /// True when durable audit recording has failed.
    pub fn is_failed(&self) -> bool {
        self.inner.fail_closed && self.inner.writer_failed.load(Ordering::SeqCst)
    }

    /// Fail-closed check for the proxy: returns an error when audit is required
    /// and unavailable.
    pub fn ensure_available(&self) -> Result<(), crate::error::AuditorError> {
        if self.is_failed() {
            Err(crate::error::AuditorError::AuditUnavailable(format!(
                "dropped={} writer_failed=true",
                self.inner.dropped.load(Ordering::Relaxed)
            )))
        } else {
            Ok(())
        }
    }

    /// Gracefully shutdown the logger.
    /// Closes the channel and waits for the writer task to complete.
    pub async fn shutdown(&self) {
        // Drop the sender to close the channel, signaling the writer task to flush and exit
        {
            let mut tx_lock = self.inner.tx.lock().unwrap();
            tx_lock.take();
        }

        // Wait for the writer task to complete
        let mut handle_lock = self.inner.writer_handle.lock().await;
        if let Some(handle) = handle_lock.take()
            && let Err(e) = handle.await
        {
            tracing::error!("Writer task join error: {e}");
        }
    }
}

impl Drop for AuditLoggerInner {
    fn drop(&mut self) {
        // Abort the writer task if it's still running.
        // This means shutdown() was not called — buffered events may be lost.
        if let Ok(mut handle_lock) = self.writer_handle.try_lock()
            && let Some(handle) = handle_lock.take()
        {
            tracing::warn!(
                "AuditLogger dropped without shutdown(); \
                 aborting writer task — buffered events may be lost. \
                 Call AuditLogger::shutdown().await for graceful flush."
            );
            self.writer_failed.store(true, Ordering::SeqCst);
            handle.abort();
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Writer Tasks
// ═══════════════════════════════════════════════════════════════════════════════

async fn file_writer_task(
    mut rx: mpsc::Receiver<AuditEvent>,
    mut writer: std::io::BufWriter<std::fs::File>,
    writer_failed: std::sync::Arc<AtomicBool>,
) {
    let mut events_since_flush: u32 = 0;
    let mut flush_interval = tokio::time::interval(std::time::Duration::from_secs(1));
    let mut fsync_interval = tokio::time::interval(std::time::Duration::from_secs(5));

    // Consume initial ticks (tokio intervals fire immediately on first tick)
    flush_interval.tick().await;
    fsync_interval.tick().await;

    loop {
        tokio::select! {
            biased;

            event = rx.recv() => {
                match event {
                    Some(evt) => {
                        let is_critical = matches!(evt.severity, Severity::Critical);
                        let json = write_event_jsonl(&evt);
                        if let Err(e) = writeln!(writer, "{}", json) {
                            tracing::error!("Audit log write failed: {e}");
                            writer_failed.store(true, Ordering::SeqCst);
                        }
                        events_since_flush += 1;

                        if is_critical || events_since_flush >= FLUSH_EVENT_THRESHOLD {
                            if let Err(e) = writer.flush() {
                                tracing::error!("Audit log flush failed: {e}");
                                writer_failed.store(true, Ordering::SeqCst);
                            }
                            events_since_flush = 0;
                        }
                    }
                    None => {
                        if let Err(e) = writer.flush() {
                            tracing::error!("Audit log final flush failed: {e}");
                            writer_failed.store(true, Ordering::SeqCst);
                        }
                        if let Err(e) = writer.get_ref().sync_all() {
                            tracing::error!("Audit log final sync failed: {e}");
                            writer_failed.store(true, Ordering::SeqCst);
                        }
                        return;
                    }
                }
            }
            _ = flush_interval.tick() => {
                if events_since_flush > 0 {
                    if let Err(e) = writer.flush() {
                        tracing::error!("Audit log periodic flush failed: {e}");
                        writer_failed.store(true, Ordering::SeqCst);
                    }
                    events_since_flush = 0;
                }
            }
            _ = fsync_interval.tick() => {
                if let Err(e) = writer.get_ref().sync_all() {
                    tracing::error!("Audit log fsync failed: {e}");
                    writer_failed.store(true, Ordering::SeqCst);
                }
            }
        }
    }
}

async fn tracing_writer_task(mut rx: mpsc::Receiver<AuditEvent>) {
    while let Some(evt) = rx.recv().await {
        let json = write_event_jsonl(&evt);
        match evt.severity {
            Severity::Critical | Severity::High => {
                tracing::error!(target: "audit", "{}", json);
            }
            Severity::Medium => {
                tracing::warn!(target: "audit", "{}", json);
            }
            Severity::Low | Severity::Info => {
                tracing::info!(target: "audit", "{}", json);
            }
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// JSON Serialization (nojson — no serde)
// ═══════════════════════════════════════════════════════════════════════════════

/// Outputs the JSON literal `null`.
struct JsonNull;

impl nojson::DisplayJson for JsonNull {
    fn fmt(&self, f: &mut nojson::JsonFormatter<'_, '_>) -> std::fmt::Result {
        write!(f.inner_mut(), "null")
    }
}

/// Outputs a u64 as a raw numeric literal.
struct NumLiteral(u64);

impl nojson::DisplayJson for NumLiteral {
    fn fmt(&self, f: &mut nojson::JsonFormatter<'_, '_>) -> std::fmt::Result {
        write!(f.inner_mut(), "{}", self.0)
    }
}

/// Outputs a UUID as a JSON string (quoted, hyphenated lowercase).
struct UuidStr(Uuid);

impl nojson::DisplayJson for UuidStr {
    fn fmt(&self, f: &mut nojson::JsonFormatter<'_, '_>) -> std::fmt::Result {
        write!(f.inner_mut(), "\"{}\"", self.0)
    }
}

/// Serialize an AuditEvent to a single-line JSON string (JSONL format).
/// Uses nojson builder — no serde dependency.
pub fn write_event_jsonl(event: &AuditEvent) -> String {
    nojson::object(|f| {
        f.member("schema_version", event.schema_version)?;
        f.member("timestamp", event.timestamp.as_str())?;
        f.member("event_id", UuidStr(event.event_id))?;
        f.member("correlation_id", UuidStr(event.correlation_id))?;
        match event.parent_event_id {
            Some(id) => f.member("parent_event_id", UuidStr(id))?,
            None => f.member("parent_event_id", &JsonNull)?,
        };
        f.member("event_type", event.event_type.as_str())?;
        f.member("event_category", event.event_type.category())?;
        f.member("severity", event.severity.as_str())?;
        f.member("severity_id", NumLiteral(event.severity.id() as u64))?;
        f.member("outcome", event.outcome.as_str())?;
        f.member("action", event.action.as_str())?;
        match &event.target_server {
            Some(s) => f.member("target_server", s.as_str())?,
            None => f.member("target_server", &JsonNull)?,
        };
        match &event.target_tool {
            Some(s) => f.member("target_tool", s.as_str())?,
            None => f.member("target_tool", &JsonNull)?,
        };
        match &event.request_id {
            Some(s) => f.member("request_id", s.as_str())?,
            None => f.member("request_id", &JsonNull)?,
        };
        match &event.policy_context {
            Some(ctx) => {
                f.member("policy_id", ctx.id.as_str())?;
                f.member("policy_version", ctx.version.as_str())?;
                f.member("policy_hash", ctx.hash.as_str())?;
            }
            None => {
                f.member("policy_id", &JsonNull)?;
                f.member("policy_version", &JsonNull)?;
                f.member("policy_hash", &JsonNull)?;
            }
        };
        match &event.details {
            Some(s) => f.member("details", s.as_str())?,
            None => f.member("details", &JsonNull)?,
        };
        f.member("guard_version", env!("CARGO_PKG_VERSION"))
    })
    .to_string()
}

// ═══════════════════════════════════════════════════════════════════════════════
// Time Utilities
// ═══════════════════════════════════════════════════════════════════════════════

/// Format current UTC time as ISO 8601 with millisecond precision.
/// Example: `2026-02-21T14:30:00.123Z`
pub fn now_iso8601_millis() -> String {
    let duration = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = duration.as_secs();
    let millis = duration.subsec_millis();
    let days = (secs / 86400) as i64;
    let time_of_day = secs % 86400;
    let hours = time_of_day / 3600;
    let minutes = (time_of_day % 3600) / 60;
    let seconds = time_of_day % 60;
    let (year, month, day) = days_to_civil(days);
    format!("{year:04}-{month:02}-{day:02}T{hours:02}:{minutes:02}:{seconds:02}.{millis:03}Z")
}

/// Format current UTC time as ISO 8601 (second precision).
/// Example: `2026-02-17T10:00:00Z`
pub fn now_iso8601() -> String {
    let duration = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = duration.as_secs();
    let days = (secs / 86400) as i64;
    let time_of_day = secs % 86400;
    let hours = time_of_day / 3600;
    let minutes = (time_of_day % 3600) / 60;
    let seconds = time_of_day % 60;
    let (year, month, day) = days_to_civil(days);
    format!("{year:04}-{month:02}-{day:02}T{hours:02}:{minutes:02}:{seconds:02}Z")
}

fn generate_session_id() -> String {
    let pid = std::process::id();
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    format!("{pid}-{ts}")
}

/// Convert days since Unix epoch to (year, month, day).
/// Howard Hinnant's civil_from_days algorithm.
///
/// Input values outside ±365,000,000 (~1M years) are clamped to the Unix
/// epoch fallback `(1970, 1, 1)` to prevent integer overflow in the
/// intermediate arithmetic.
fn days_to_civil(days: i64) -> (i32, u32, u32) {
    if !(-365_000_000..=365_000_000).contains(&days) {
        return (1970, 1, 1);
    }
    let z = days + 719468;
    let cycle_400_years = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - cycle_400_years * 146097) as u32;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + cycle_400_years * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if m <= 2 { y + 1 } else { y };
    (year as i32, m, d)
}

// ═══════════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn make_test_dir(label: &str) -> PathBuf {
        let id = std::process::id();
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("mcp_writ_{label}_{id}_{ts}"));
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
        assert_eq!(EventType::SandboxFileDenied.as_str(), "sandbox.file_denied");
        assert_eq!(
            EventType::SandboxNetworkDenied.as_str(),
            "sandbox.network_denied"
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
        logger.shutdown().await;

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

        logger.shutdown().await;

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
        logger.shutdown().await;

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

        logger.shutdown().await;
        let _ = std::fs::remove_dir_all(&dir);
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
        let writer_failed = std::sync::Arc::new(AtomicBool::new(false));
        let writer_handle = tokio::spawn(file_writer_task(rx, writer, writer_failed.clone()));
        let logger = AuditLogger {
            inner: std::sync::Arc::new(AuditLoggerInner {
                tx: std::sync::Mutex::new(Some(tx)),
                session_id,
                writer_handle: tokio::sync::Mutex::new(Some(writer_handle)),
                fail_closed: true,
                dropped: AtomicU64::new(0),
                writer_failed,
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

        logger.shutdown().await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn test_logger_to_tracing_no_panic() {
        let logger = AuditLogger::to_tracing();
        logger.log(make_test_event());
        logger.shutdown().await;
    }
}
