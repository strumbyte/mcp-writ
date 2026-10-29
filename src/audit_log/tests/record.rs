//! Event-record surface: the `EventType`/`Severity`/`Outcome`/`Action`
//! vocabularies, `write_event_jsonl` serialization, and the time and
//! bounded-field helpers.

use super::super::emit::days_to_civil;
use super::super::*;
use super::make_test_event;
use uuid::Uuid;

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
    assert_eq!(EventType::AuditReopened.as_str(), "audit.reopened");
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
    assert_eq!(EventType::AuditReopened.category(), "system");
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
