use super::super::proxy_state::PendingToolsList;
use super::*;
use std::sync::Arc;
use tokio::sync::{Mutex, watch};

fn shared_for_test(dry_run: bool) -> (ProxyShared<tokio::io::DuplexStream>, watch::Receiver<bool>) {
    shared_for_test_with(
        dry_run,
        crate::policy::Policy::default(),
        crate::audit_log::AuditLogger::to_tracing(),
    )
}

fn shared_for_test_with(
    dry_run: bool,
    policy: crate::policy::Policy,
    audit: crate::audit_log::AuditLogger,
) -> (ProxyShared<tokio::io::DuplexStream>, watch::Receiver<bool>) {
    let (abort_tx, abort_rx) = watch::channel(false);
    let (_child_read, child_write) = tokio::io::duplex(64);
    let shared = ProxyShared {
        policy,
        dry_run,
        fail_on: crate::verifier::fail_on::FailOn::DEFAULT,
        max_frame_bytes: crate::framing::DEFAULT_MAX_FRAME_BYTES,
        audit: Arc::new(audit),
        session: None,
        wire: Arc::new(Mutex::new(proxy_rpc::WireState::new())),
        pending_tools_list: Arc::new(Mutex::new(PendingToolsList::new())),
        client_out: Arc::new(Mutex::new(tokio::io::stdout())),
        child_stdin: Arc::new(Mutex::new(Some(child_write))),
        original_tools_list: Arc::new(Mutex::new(std::collections::HashMap::new())),
        list_busy: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        list_kick: Arc::new(tokio::sync::Notify::new()),
        cancelled_list_id: Arc::new(Mutex::new(None)),
        held_client_list: Arc::new(Mutex::new(None)),
        internal_list_failure: Arc::new(tokio::sync::Mutex::new(None)),
        list_generation: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        verified_tools: Arc::new(std::sync::Mutex::new(
            crate::auditor::proxy_state::VerifiedToolSet {
                generation: 0,
                names: std::collections::HashSet::new(),
            },
        )),
        last_list_template: Arc::new(Mutex::new(String::new())),
        next_internal_id: Arc::new(std::sync::atomic::AtomicU64::new(910_001)),
        init_order_warned: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        abort_tx,
    };
    (shared, abort_rx)
}

#[tokio::test]
async fn verified_list_releases_busy_before_client_can_reply() {
    let (shared, _abort_rx) = shared_for_test(false);
    shared.list_busy.store(true, Ordering::SeqCst);
    let mut st = S2cListState::new();
    st.bind_client("1".into(), String::new());

    // Pause at the response write to exercise the scheduling window
    // where a client can read the result before the write future resumes.
    let output_lock = shared.client_out.lock().await;
    let verification = verify_and_emit_list(&shared, &mut st, Some("1"), false);
    tokio::pin!(verification);
    tokio::select! {
        biased;
        _ = &mut verification => panic!("verification must wait for client output"),
        _ = std::future::ready(()) => {}
    }
    assert!(
        !shared.list_busy.load(Ordering::SeqCst),
        "completed verification must be visible before the response"
    );

    // A new client tools/list can start immediately after receiving the
    // response. Finishing the old write must not clear that new request.
    shared.list_busy.store(true, Ordering::SeqCst);
    drop(output_lock);
    verification.await.unwrap();
    assert!(shared.list_busy.load(Ordering::SeqCst));
}

/// F10: a successful verification publishes a new list generation —
/// `tools/call` admissions capture it and unwind on any later bump.
#[tokio::test]
async fn verified_list_publishes_a_new_generation() {
    let (shared, _abort_rx) = shared_for_test(false);
    assert_eq!(shared.list_generation.load(Ordering::SeqCst), 0);
    let mut st = S2cListState::new();
    st.bind_client("1".into(), String::new());
    verify_and_emit_list(&shared, &mut st, Some("1"), false)
        .await
        .unwrap();
    assert_eq!(shared.list_generation.load(Ordering::SeqCst), 1);
    // A second verification publishes the next generation.
    verify_and_emit_list(&shared, &mut st, Some("1"), false)
        .await
        .unwrap();
    assert_eq!(shared.list_generation.load(Ordering::SeqCst), 2);
}

/// F10: the enforcement predicate — a pinned hash or a `fail-on`
/// setting stricter than `none` requires a verified listing before
/// `tools/call` may run.
#[test]
fn list_verification_required_predicate() {
    let mut policy = crate::policy::Policy::default();
    assert!(crate::auditor::proxy_state::list_verification_required(
        &policy,
        crate::verifier::fail_on::FailOn::High
    ));
    assert!(!crate::auditor::proxy_state::list_verification_required(
        &policy,
        crate::verifier::fail_on::FailOn::None
    ));
    policy
        .tools_list_hashes
        .push(crate::policy::ToolsListHashEntry {
            server_name: "s".to_string(),
            hash_value: "sha256:00".to_string(),
            approved: None,
        });
    assert!(crate::auditor::proxy_state::list_verification_required(
        &policy,
        crate::verifier::fail_on::FailOn::None
    ));
}

#[tokio::test]
async fn queued_revalidation_keeps_calls_blocked_while_response_is_emitted() {
    let (shared, _abort_rx) = shared_for_test(false);
    shared.list_busy.store(true, Ordering::SeqCst);
    let mut st = S2cListState::new();
    st.bind_client("1".into(), String::new());
    assert!(st.hold_list_changed(
        r#"{"jsonrpc":"2.0","method":"notifications/tools/list_changed"}"#,
        true,
    ));

    let _output_lock = shared.client_out.lock().await;
    let verification = verify_and_emit_list(&shared, &mut st, Some("1"), false);
    tokio::pin!(verification);
    tokio::select! {
        biased;
        _ = &mut verification => panic!("verification must wait for client output"),
        _ = std::future::ready(()) => {}
    }
    assert!(
        shared.list_busy.load(Ordering::SeqCst),
        "a queued revalidation must keep tools/call blocked"
    );
}

/// Build the `S2cFrame` the S2C loop derives for a top-level array:
/// `to_member` fails on non-objects, so no id/method is extracted and
/// `value_is_response` is false.
fn batch_frame<'a>(
    line: &'a str,
    parsed: &'a Result<nojson::RawJson<'a>, nojson::JsonParseError>,
) -> S2cFrame<'a> {
    S2cFrame {
        line,
        parsed,
        rpc_id: None,
        raw_id: None,
        has_method: false,
        is_response: false,
        malformed_reason: None,
    }
}

#[tokio::test]
async fn batch_frame_with_pending_tools_list_id_is_blocked() {
    let (shared, abort_rx) = shared_for_test(false);
    assert!(
        shared
            .pending_tools_list
            .lock()
            .await
            .try_insert(RpcId::Number("1".into()))
    );
    let line = r#"[{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"evil_tool"}]}}]"#;
    let parsed = nojson::RawJson::parse(line);
    let mut st = S2cListState::new();
    let result = handle_tools_list_response(&shared, &mut st, batch_frame(line, &parsed)).await;
    assert!(matches!(result, Err(AuditorError::VerificationFailed(_))));
    assert!(*abort_rx.borrow());
}

#[tokio::test]
async fn batch_frame_without_pending_ids_is_blocked() {
    let (shared, abort_rx) = shared_for_test(false);
    let line = r#"[{"jsonrpc":"2.0","method":"notifications/progress","params":{}}]"#;
    let parsed = nojson::RawJson::parse(line);
    let mut st = S2cListState::new();
    let result = handle_tools_list_response(&shared, &mut st, batch_frame(line, &parsed)).await;
    assert!(matches!(result, Err(AuditorError::VerificationFailed(_))));
    assert!(*abort_rx.borrow());
}

/// A frame that failed the wire-level envelope gate but carries
/// response members on a tracked tools/list id is rejected —
/// never verified, emitted, or silently discarded.
#[tokio::test]
async fn malformed_result_and_error_on_pending_id_is_rejected() {
    let (shared, abort_rx) = shared_for_test(false);
    let id = RpcId::Number("1".into());
    assert!(
        shared
            .pending_tools_list
            .lock()
            .await
            .try_insert(id.clone())
    );
    // Both `result` and `error` — `classify_frame` rejects the
    // envelope; a routed frame must be blocked, not interpreted.
    let line = r#"{"id":1,"result":{"tools":[{"name":"evil_tool"}]},"error":{"code":-32000,"message":"ambiguous"}}"#;
    let parsed = nojson::RawJson::parse(line);
    let mut st = S2cListState::new();
    let result = handle_tools_list_response(
        &shared,
        &mut st,
        S2cFrame {
            line,
            parsed: &parsed,
            rpc_id: Some(&id),
            raw_id: Some("1"),
            has_method: false,
            is_response: true,
            malformed_reason: Some("response carries both result and error"),
        },
    )
    .await;
    assert!(matches!(result, Err(AuditorError::VerificationFailed(_))));
    assert!(*abort_rx.borrow());
    // The pending entry is not consumed by the malformed frame — in
    // dry-run a genuine response can still resolve the listing.
    assert!(shared.pending_tools_list.lock().await.contains(&id));
}

/// An envelope-invalid frame carrying `result` on a tracked id is
/// likewise rejected: without a `jsonrpc` member it must not be
/// parsed and emitted as a verified listing.
#[tokio::test]
async fn jsonrpc_less_response_on_pending_id_is_rejected() {
    let (shared, abort_rx) = shared_for_test(false);
    let id = RpcId::Number("2".into());
    assert!(
        shared
            .pending_tools_list
            .lock()
            .await
            .try_insert(id.clone())
    );
    let line = r#"{"id":2,"result":{"tools":[{"name":"evil_tool"}]}}"#;
    let parsed = nojson::RawJson::parse(line);
    let mut st = S2cListState::new();
    let result = handle_tools_list_response(
        &shared,
        &mut st,
        S2cFrame {
            line,
            parsed: &parsed,
            rpc_id: Some(&id),
            raw_id: Some("2"),
            has_method: false,
            is_response: true,
            malformed_reason: Some("missing or invalid jsonrpc member"),
        },
    )
    .await;
    assert!(matches!(result, Err(AuditorError::VerificationFailed(_))));
    assert!(*abort_rx.borrow());
}

/// An unverifiable batch frame is blocked in dry-run the same as in
/// enforce mode — dry-run must never raw-forward frames verification
/// cannot cover.
#[tokio::test]
async fn batch_frame_is_blocked_in_dry_run() {
    let (shared, abort_rx) = shared_for_test(true);
    let line = r#"[{"jsonrpc":"2.0","id":1,"result":{"tools":[]}}]"#;
    let parsed = nojson::RawJson::parse(line);
    let mut st = S2cListState::new();
    let result = handle_tools_list_response(&shared, &mut st, batch_frame(line, &parsed)).await;
    assert!(matches!(result, Err(AuditorError::VerificationFailed(_))));
    assert!(*abort_rx.borrow());
}

/// Fail-closed ordering: the authoritative `tools_list.verified`
/// record must commit before `record_verified_digest`, the busy-gate
/// release, or the client emit. A dead sink refuses the whole
/// transition — the response never leaves and calls stay gated.
#[tokio::test]
async fn dead_audit_sink_blocks_verified_transitions() {
    let Some((_dir, log_path, audit)) = audit_log_fixture() else {
        crate::testutil::skip_unless_required("no write-restricted root for audit fixture");
        return;
    };
    let (shared, _abort_rx) = shared_for_test_with(false, policy_allowing("alpha"), audit);
    // Kill the sink before verification — the commit must refuse.
    shared.audit.shutdown().await.unwrap();

    shared.list_busy.store(true, Ordering::SeqCst);
    let mut st = S2cListState::new();
    st.bind_client("1".into(), String::new());
    st.append_page(two_tools()).unwrap();

    let result = verify_and_emit_list(&shared, &mut st, Some("1"), false).await;
    let err = match result {
        Err(e) => e,
        Ok(_) => panic!("dead audit sink must refuse verified transitions"),
    };
    assert!(
        matches!(err, AuditorError::AuditUnavailable(_)),
        "expected AuditUnavailable, got: {err:?}"
    );
    assert!(
        shared.list_busy.load(Ordering::SeqCst),
        "a refused verification must leave tools/call gated"
    );
    let log = std::fs::read_to_string(&log_path).unwrap_or_default();
    assert!(
        !log.contains("\"event_type\":\"tools_list.verified\""),
        "no verified record may be claimed durable: {log}"
    );
}

/// On a live fail-closed sink the verification record is durable —
/// the committed `tools_list.verified` precedes the client response
/// in the stream.
#[tokio::test]
async fn verified_record_commits_before_client_emit() {
    let Some((_dir, log_path, audit)) = audit_log_fixture() else {
        crate::testutil::skip_unless_required("no write-restricted root for audit fixture");
        return;
    };
    let (shared, _abort_rx) = shared_for_test_with(false, policy_allowing("alpha"), audit);
    let mut st = S2cListState::new();
    st.bind_client("1".into(), String::new());
    st.append_page(two_tools()).unwrap();
    verify_and_emit_list(&shared, &mut st, Some("1"), false)
        .await
        .unwrap();
    let _ = shared.audit.shutdown().await;
    let log = std::fs::read_to_string(&log_path).expect("read audit log");
    assert!(
        log.contains("\"event_type\":\"tools_list.verified\""),
        "verified record must persist, got: {log}"
    );
    assert!(log.contains("digest="), "got: {log}");
}

fn policy_allowing(name: &str) -> crate::policy::Policy {
    let mut policy = crate::policy::Policy::default();
    policy
        .tools
        .push(crate::policy::ToolPolicy::named(name, true));
    policy
}

fn two_tools() -> Vec<ToolDefinition> {
    vec![
        ToolDefinition::new("alpha", ""),
        ToolDefinition::new("beta", ""),
    ]
}

async fn revalidate_with(
    shared: &ProxyShared<tokio::io::DuplexStream>,
    st: &mut S2cListState,
    internal_id: u64,
    tools: Vec<ToolDefinition>,
) {
    st.begin_revalidation(String::new(), internal_id);
    st.append_page(tools).unwrap();
    let raw_id = internal_id.to_string();
    verify_and_emit_list(shared, st, Some(&raw_id), true)
        .await
        .unwrap();
}

/// A fail-closed `AuditLogger` writing `audit.jsonl` inside a fresh
/// write-restricted tempdir — `to_file` refuses a replaceable
/// parent, so the fixture must satisfy the sink's own ancestry
/// gate. `None` when the host offers no restricted root; callers
/// skip. Bind the `TempDir` (as `_dir` where unused) so the log
/// outlives `shared.audit.shutdown()` for the assertions below.
fn audit_log_fixture() -> Option<(
    tempfile::TempDir,
    std::path::PathBuf,
    crate::audit_log::AuditLogger,
)> {
    let dir = crate::testutil::restricted_tempdir()?;
    let log_path = dir.path().join("audit.jsonl");
    let audit = crate::audit_log::AuditLogger::to_file(&log_path).expect("audit log");
    Some((dir, log_path, audit))
}

/// First audit-log line whose `"event_type"` field is `event_type`.
fn event_line<'a>(log: &'a str, event_type: &str) -> Option<&'a str> {
    log.lines()
        .find(|l| l.contains(&format!("\"event_type\":\"{event_type}\"")))
}

/// The `tools_list.verified` record a blocked listing still commits:
/// `blocked=true` with `outcome=failure`/`action=observed`.
fn blocked_verified_line(log: &str) -> &str {
    let line = event_line(log, "tools_list.verified")
        .unwrap_or_else(|| panic!("blocked listing must commit tools_list.verified: {log}"));
    assert!(line.contains("\"outcome\":\"failure\""), "got: {line}");
    assert!(line.contains("\"action\":\"observed\""), "got: {line}");
    assert!(line.contains("blocked=true"), "got: {line}");
    line
}

/// A `list_changed` revalidation that yields the same advertised set
/// as the last verified listing must not repeat the
/// `tools_list.filtered` event — the hidden set it would enumerate was
/// already audited.
#[tokio::test]
async fn identical_revalidation_does_not_repeat_filtered_event() {
    let Some((_dir, log_path, audit)) = audit_log_fixture() else {
        crate::testutil::skip_unless_required("no write-restricted root for audit fixture");
        return;
    };
    let (shared, _abort_rx) = shared_for_test_with(false, policy_allowing("alpha"), audit);
    let mut st = S2cListState::new();

    // Client-initiated listing hides `beta` and logs the event once.
    st.bind_client("1".into(), String::new());
    st.append_page(two_tools()).unwrap();
    verify_and_emit_list(&shared, &mut st, Some("1"), false)
        .await
        .unwrap();

    // Identical internal revalidations add no new information.
    revalidate_with(&shared, &mut st, 910_001, two_tools()).await;
    revalidate_with(&shared, &mut st, 910_002, two_tools()).await;

    let _ = shared.audit.shutdown().await;
    let log = std::fs::read_to_string(&log_path).expect("read audit log");
    let events = log
        .matches("\"event_type\":\"tools_list.filtered\"")
        .count();
    assert_eq!(events, 1, "unchanged revalidations must not re-log: {log}");
}

/// Suppression applies only to identical relists: a revalidation whose
/// advertised set changed still emits the filtered event.
#[tokio::test]
async fn changed_revalidation_logs_filtered_event() {
    let Some((_dir, log_path, audit)) = audit_log_fixture() else {
        crate::testutil::skip_unless_required("no write-restricted root for audit fixture");
        return;
    };
    let (shared, _abort_rx) = shared_for_test_with(false, policy_allowing("alpha"), audit);
    let mut st = S2cListState::new();

    // First listing advertises only the allowed tool: nothing hidden.
    st.bind_client("1".into(), String::new());
    st.append_page(vec![ToolDefinition::new("alpha", "")])
        .unwrap();
    verify_and_emit_list(&shared, &mut st, Some("1"), false)
        .await
        .unwrap();

    // The relist now advertises an extra unlisted tool: logged.
    revalidate_with(&shared, &mut st, 910_001, two_tools()).await;
    // An identical relist is suppressed.
    revalidate_with(&shared, &mut st, 910_002, two_tools()).await;
    // A relist with yet another tool is a new set: logged again.
    let mut grown = two_tools();
    grown.push(ToolDefinition::new("gamma", ""));
    revalidate_with(&shared, &mut st, 910_003, grown).await;

    let _ = shared.audit.shutdown().await;
    let log = std::fs::read_to_string(&log_path).expect("read audit log");
    let events = log
        .matches("\"event_type\":\"tools_list.filtered\"")
        .count();
    assert_eq!(events, 2, "changed revalidations must each log: {log}");
    assert!(
        log.contains("gamma"),
        "new hidden tool must be named: {log}"
    );
}

/// Under dry-run the hidden set is forwarded, so the event must say
/// the tools *would be* hidden. Without a tools-list-hash pin,
/// `target_server` falls back to the single declared server identity.
#[tokio::test]
async fn dry_run_filtered_event_reports_would_be_hidden_and_declared_server() {
    let Some((_dir, log_path, audit)) = audit_log_fixture() else {
        crate::testutil::skip_unless_required("no write-restricted root for audit fixture");
        return;
    };
    let mut policy = policy_allowing("alpha");
    policy.tools[0].server = Some("bound-server".to_string());
    let (shared, _abort_rx) = shared_for_test_with(true, policy, audit);
    let mut st = S2cListState::new();

    st.bind_client("9".into(), String::new());
    st.append_page(two_tools()).unwrap();
    verify_and_emit_list(&shared, &mut st, Some("9"), false)
        .await
        .unwrap();

    let _ = shared.audit.shutdown().await;
    let log = std::fs::read_to_string(&log_path).expect("read audit log");
    let line = event_line(&log, "tools_list.filtered").expect("filtered event missing");
    assert!(line.contains("\"action\":\"observed\""), "got: {line}");
    // The filtered response was delivered: a would-be denial under
    // dry-run still completes the operation — outcome is `success`.
    assert!(line.contains("\"outcome\":\"success\""), "got: {line}");
    assert!(line.contains("would be hidden"), "got: {line}");
    assert!(line.contains("beta"), "got: {line}");
    assert!(
        line.contains("\"target_server\":\"bound-server\""),
        "declared server name must be recorded: {line}"
    );
}

/// With no declared server identity the filtered event records no
/// `target_server` — a synthetic name is never written.
#[tokio::test]
async fn filtered_event_without_declared_server_has_no_target() {
    let Some((_dir, log_path, audit)) = audit_log_fixture() else {
        crate::testutil::skip_unless_required("no write-restricted root for audit fixture");
        return;
    };
    let (shared, _abort_rx) = shared_for_test_with(false, policy_allowing("alpha"), audit);
    let mut st = S2cListState::new();

    st.bind_client("1".into(), String::new());
    st.append_page(two_tools()).unwrap();
    verify_and_emit_list(&shared, &mut st, Some("1"), false)
        .await
        .unwrap();

    let _ = shared.audit.shutdown().await;
    let log = std::fs::read_to_string(&log_path).expect("read audit log");
    let line = event_line(&log, "tools_list.filtered").expect("filtered event missing");
    assert!(line.contains("\"target_server\":null"), "got: {line}");
    // A normal run delivers the filtered list — `action=denied`
    // carries the refusal, `outcome=success` the completed delivery.
    assert!(line.contains("\"action\":\"denied\""), "got: {line}");
    assert!(line.contains("\"outcome\":\"success\""), "got: {line}");
    assert!(line.contains("beta"), "got: {line}");
}

/// Multiple declared server identities are ambiguous — the event
/// records no `target_server` rather than guessing one.
#[tokio::test]
async fn filtered_event_with_multiple_declared_servers_has_no_target() {
    let Some((_dir, log_path, audit)) = audit_log_fixture() else {
        crate::testutil::skip_unless_required("no write-restricted root for audit fixture");
        return;
    };
    let mut policy = policy_allowing("alpha");
    policy.tools[0].server = Some("srv-a".to_string());
    let mut second = crate::policy::ToolPolicy::named("beta", true);
    second.server = Some("srv-b".to_string());
    policy.tools.push(second);
    let (shared, _abort_rx) = shared_for_test_with(false, policy, audit);
    let mut st = S2cListState::new();

    st.bind_client("1".into(), String::new());
    let mut advertised = two_tools();
    advertised.push(ToolDefinition::new("gamma", ""));
    st.append_page(advertised).unwrap();
    verify_and_emit_list(&shared, &mut st, Some("1"), false)
        .await
        .unwrap();

    let _ = shared.audit.shutdown().await;
    let log = std::fs::read_to_string(&log_path).expect("read audit log");
    let line = event_line(&log, "tools_list.filtered").expect("filtered event missing");
    assert!(line.contains("\"target_server\":null"), "got: {line}");
    assert!(line.contains("\"outcome\":\"success\""), "got: {line}");
    assert!(line.contains("gamma"), "got: {line}");
}

/// A listing refused by the pin check still commits its
/// `tools_list.verified` record — `blocked=true` with
/// `outcome=failure`/`action=observed` — before the refusal emit.
/// `outcome=failure` stays reserved for operations that did not
/// complete; the filtering event above is `success` by contrast.
#[tokio::test]
async fn blocked_listing_commits_failure_verified_record() {
    let Some((_dir, log_path, audit)) = audit_log_fixture() else {
        crate::testutil::skip_unless_required("no write-restricted root for audit fixture");
        return;
    };
    let mut policy = policy_allowing("alpha");
    // A pin that cannot match the advertised set blocks verification.
    policy
        .tools_list_hashes
        .push(crate::policy::ToolsListHashEntry {
            server_name: "bound-server".to_string(),
            hash_value: format!("sha256:{}", "0".repeat(64)),
            approved: None,
        });
    let (shared, _abort_rx) = shared_for_test_with(false, policy, audit);
    let mut st = S2cListState::new();

    st.bind_client("1".into(), String::new());
    st.append_page(two_tools()).unwrap();
    let res = verify_and_emit_list(&shared, &mut st, Some("1"), false).await;
    assert!(
        matches!(res, Err(AuditorError::VerificationFailed(_))),
        "a mismatched pin must refuse the listing"
    );

    let _ = shared.audit.shutdown().await;
    let log = std::fs::read_to_string(&log_path).expect("read audit log");
    blocked_verified_line(&log);
    // The paired refusal record — the hash diff that blocked the
    // listing — is a `tools_list.changed` failure, unchanged.
    let changed = event_line(&log, "tools_list.changed").expect("the mismatch must be recorded");
    assert!(
        changed.contains("\"outcome\":\"failure\""),
        "got: {changed}"
    );
}

/// A listing whose advertised set cannot be canonicalized commits
/// its `tools_list.verified` record too — `blocked=true` with
/// `outcome=failure`/`action=observed` and no `digest=` — through
/// the same blocked path as a pin mismatch, so a refusal never
/// goes unrecorded.
#[tokio::test]
async fn uncanonicalizable_listing_commits_failure_verified_record() {
    let Some((_dir, log_path, audit)) = audit_log_fixture() else {
        crate::testutil::skip_unless_required("no write-restricted root for audit fixture");
        return;
    };
    let (shared, _abort_rx) = shared_for_test_with(false, policy_allowing("alpha"), audit);
    let mut st = S2cListState::new();

    st.bind_client("1".into(), String::new());
    // An optional JSON field that cannot be normalized fails
    // `hash_tools_list` — canonicalization is an integrity check.
    let bad = ToolDefinition::new("alpha", "").with_input_schema("{ not json");
    st.append_page(vec![bad]).unwrap();
    let res = verify_and_emit_list(&shared, &mut st, Some("1"), false).await;
    assert!(
        matches!(res, Err(AuditorError::VerificationFailed(_))),
        "an uncanonicalizable manifest must refuse the listing"
    );

    let _ = shared.audit.shutdown().await;
    let log = std::fs::read_to_string(&log_path).expect("read audit log");
    let line = blocked_verified_line(&log);
    assert!(
        !line.contains("digest="),
        "an unhashable set has no digest to record: {line}"
    );
}

/// When the verification record cannot be committed — a dead
/// fail-closed audit sink — the blocked path still fires the
/// session abort and records the refusal for the abort drain: a
/// held `tools/list` must not be left to EOF just because the
/// record could not be committed.
#[tokio::test]
async fn blocked_listing_on_dead_sink_still_aborts() {
    // `to_file` is the fail-closed logger: a closed channel refuses
    // every later commit.
    let Some((_dir, _log_path, audit)) = audit_log_fixture() else {
        crate::testutil::skip_unless_required("no write-restricted root for audit fixture");
        return;
    };
    let mut policy = policy_allowing("alpha");
    policy
        .tools_list_hashes
        .push(crate::policy::ToolsListHashEntry {
            server_name: "bound-server".to_string(),
            hash_value: format!("sha256:{}", "0".repeat(64)),
            approved: None,
        });
    let (shared, abort_rx) = shared_for_test_with(false, policy, audit);
    let mut st = S2cListState::new();

    st.bind_client("1".into(), String::new());
    st.append_page(two_tools()).unwrap();
    let _ = shared.audit.shutdown().await;

    let res = verify_and_emit_list(&shared, &mut st, Some("1"), false).await;
    assert!(
        matches!(res, Err(AuditorError::AuditUnavailable(_))),
        "a dead fail-closed sink refuses the transition"
    );
    assert!(*abort_rx.borrow(), "the session must still abort");
    assert!(
        shared.internal_list_failure.lock().await.is_some(),
        "the abort drain must see the recorded refusal"
    );
}

#[tokio::test]
async fn cancelled_list_kick_drives_queued_revalidation() {
    let (shared, _abort_rx) = shared_for_test(false);
    let mut st = S2cListState::new();
    // A client listing that already collected a page, cancelled while
    // a list_changed waited behind it.
    st.bind_client("7".into(), "{}".into());
    st.append_page(vec![]).unwrap();
    assert!(st.hold_list_changed("{}", true));
    shared.list_busy.store(true, Ordering::SeqCst);
    *shared.cancelled_list_id.lock().await = Some(RpcId::from_line(r#"{"id":7}"#).unwrap());
    // The resumed revalidation emits an internal tools/list request —
    // keep a live read half so the child_stdin write succeeds.
    let (_child_read, child_write) = tokio::io::duplex(4096);
    *shared.child_stdin.lock().await = Some(child_write);

    resume_queued_revalidation(&shared, &mut st).await.unwrap();

    assert!(st.is_revalidating());
    assert!(st.client_id().is_none());
    assert!(shared.list_busy.load(Ordering::SeqCst));
}

#[tokio::test]
async fn cancelled_list_kick_releases_gate_when_nothing_queued() {
    let (shared, _abort_rx) = shared_for_test(false);
    let mut st = S2cListState::new();
    st.bind_client("7".into(), "{}".into());
    st.append_page(vec![]).unwrap();
    shared.list_busy.store(true, Ordering::SeqCst);
    *shared.cancelled_list_id.lock().await = Some(RpcId::from_line(r#"{"id":7}"#).unwrap());

    resume_queued_revalidation(&shared, &mut st).await.unwrap();

    assert!(st.idle());
    assert!(!shared.list_busy.load(Ordering::SeqCst));
    assert!(!st.has_incomplete_listing());
}

#[tokio::test]
async fn cancelled_list_kick_leaves_a_live_collection_alone() {
    let (shared, _abort_rx) = shared_for_test(false);
    let mut st = S2cListState::new();
    // The cancelled id is 7 but a *different* collection (id 9) is in
    // flight — it must not be released, and the gate must stay up
    // until that listing completes and drains the queue itself.
    st.bind_client("9".into(), "{}".into());
    st.append_page(vec![]).unwrap();
    shared.list_busy.store(true, Ordering::SeqCst);
    *shared.cancelled_list_id.lock().await = Some(RpcId::from_line(r#"{"id":7}"#).unwrap());

    resume_queued_revalidation(&shared, &mut st).await.unwrap();

    assert!(!st.idle());
    assert_eq!(st.client_id(), Some("9"));
    assert!(shared.list_busy.load(Ordering::SeqCst));
}

/// A cancel for an already-finished listing reaches the S2C loop
/// *after* a new client `tools/list` has registered: the pending id
/// is invisible to the local collection state (`st` is idle and no
/// collection is bound), so only `pending_tools_list` tells resume
/// that the raised gate now belongs to the new request. Clearing it
/// would admit tools/call against an unverified listing; the queued
/// revalidation must also stay queued for the new listing's own
/// completion to drain.
#[tokio::test]
async fn cancelled_list_kick_keeps_the_gate_for_a_pending_listing() {
    let (shared, _abort_rx) = shared_for_test(false);
    let mut st = S2cListState::new();
    assert!(st.hold_list_changed("{}", true));
    shared.list_busy.store(true, Ordering::SeqCst);
    // id 7 finished on the S2C side already; id 8 registered its own
    // pending entry and re-acquired the gate.
    *shared.cancelled_list_id.lock().await = Some(RpcId::from_line(r#"{"id":7}"#).unwrap());
    shared
        .pending_tools_list
        .lock()
        .await
        .try_insert(RpcId::from_line(r#"{"id":8}"#).unwrap());

    resume_queued_revalidation(&shared, &mut st).await.unwrap();

    assert!(shared.list_busy.load(Ordering::SeqCst));
    assert!(
        !st.is_revalidating(),
        "a pending client listing owns the queue — revalidation must wait for its completion"
    );

    // Once the pending entry unwinds (its CAS lost, or its listing
    // completed), the same kick path re-drives the queued
    // revalidation instead of dropping the gate.
    let (_child_read, child_write) = tokio::io::duplex(4096);
    *shared.child_stdin.lock().await = Some(child_write);
    shared
        .pending_tools_list
        .lock()
        .await
        .remove(&RpcId::from_line(r#"{"id":8}"#).unwrap());
    resume_queued_revalidation(&shared, &mut st).await.unwrap();

    assert!(st.is_revalidating());
    assert!(shared.list_busy.load(Ordering::SeqCst));
}

/// A client `tools/list` held behind the post-`initialize` probe is
/// answered from the verified emit the internal listing produces —
/// the gate releases and the hold drains in the same completion.
#[tokio::test]
async fn held_client_list_is_answered_by_the_verified_emit() {
    let (shared, _abort_rx) = shared_for_test(false);
    let mut st = S2cListState::new();
    st.begin_revalidation("{}".into(), 910_001);
    shared.list_busy.store(true, Ordering::SeqCst);
    *shared.held_client_list.lock().await =
        Some((RpcId::from_line(r#"{"id":0}"#).unwrap(), "0".to_string()));
    st.append_page(vec![ToolDefinition::new("read_file", "")])
        .unwrap();

    verify_and_emit_list(&shared, &mut st, Some("910001"), true)
        .await
        .unwrap();

    assert!(shared.held_client_list.lock().await.is_none());
    assert!(!shared.list_busy.load(Ordering::SeqCst));
}

/// The residual-gate counterpart: a held listing that outlives its
/// internal owner is answered with an error, not orphaned — the
/// client retries on a clean path.
#[tokio::test]
async fn held_client_list_is_errored_by_a_residual_release() {
    let (shared, _abort_rx) = shared_for_test(false);
    let mut st = S2cListState::new();
    shared.list_busy.store(true, Ordering::SeqCst);
    *shared.held_client_list.lock().await =
        Some((RpcId::from_line(r#"{"id":0}"#).unwrap(), "0".to_string()));

    resume_queued_revalidation(&shared, &mut st).await.unwrap();

    assert!(shared.held_client_list.lock().await.is_none());
    assert!(!shared.list_busy.load(Ordering::SeqCst));
}
