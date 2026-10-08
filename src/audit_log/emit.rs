//! Audit record emission: JSONL serialization via `nojson` and the
//! civil-time conversions behind the `now_iso8601*` helpers.

use uuid::Uuid;

use super::event::AuditEvent;

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

/// Emits already-encoded JSON text verbatim — the `enforcement` member
/// carries a complete object serialized by `crate::enforcement` and
/// delivered as [`EmbeddedJson`](crate::audit_log::EmbeddedJson).
struct JsonRaw<'a>(&'a str);

impl nojson::DisplayJson for JsonRaw<'_> {
    fn fmt(&self, f: &mut nojson::JsonFormatter<'_, '_>) -> std::fmt::Result {
        write!(f.inner_mut(), "{}", self.0)
    }
}

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
        match &event.enforcement {
            Some(j) => f.member("enforcement", JsonRaw(j.as_str()))?,
            None => f.member("enforcement", &JsonNull)?,
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

pub(crate) fn generate_session_id() -> String {
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
pub(crate) fn days_to_civil(days: i64) -> (i32, u32, u32) {
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
