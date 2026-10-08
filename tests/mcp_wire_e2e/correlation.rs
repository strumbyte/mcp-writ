//! Server→client request correlation and frame integrity: same-id
//! collision handling, orphan/duplicate/malformed frame drops, mixed
//! envelopes, unknown methods, and dry-run forwarding of denials.

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::time::{Duration, timeout};

use crate::common;
use crate::support::*;

// ─── S2C request correlation: same id, opposite direction ───────────────

/// A server→client `ping` carrying the same numeric id as an in-flight
/// client→server call must be forwarded (direction keys them apart) and the
/// call's own response still completes the pending request.
#[tokio::test]
async fn s2c_request_same_id_does_not_steal_pending_response() {
    let dir = make_test_dir("s2c_same_id");
    let policy = write_policy(dir.path(), WIRE_POLICY);
    let audit_log = common::next_audit_log_path();
    let mut child = spawn_guard(
        &policy,
        false,
        common::scripted_stdio_argv("s2c_id_collision"),
        &audit_log,
    );
    let mut stdin = child.stdin.take().expect("stdin");
    let stdout = child.stdout.take().expect("stdout");
    let _guard = ChildGuard(child);
    let mut reader = BufReader::new(stdout).lines();
    handshake_2025(&mut stdin, &mut reader).await;

    let req = call("read_file", 77);
    stdin
        .write_all(format!("{req}\n").as_bytes())
        .await
        .expect("write call");
    stdin.flush().await.expect("flush");

    // The server request (id 77, direction S2C) forwards before the answer.
    let first = recv_jsonrpc(&mut reader).await;
    assert_eq!(json_method(&first).as_deref(), Some("ping"), "got: {first}");
    assert_eq!(json_id(&first).as_deref(), Some("77"));

    // The client answers the server request, then the call result arrives.
    send_notify(&mut stdin, r#"{"jsonrpc":"2.0","id":77,"result":{}}"#).await;
    let second = recv_jsonrpc(&mut reader).await;
    assert!(
        has_result(&second) && json_method(&second).is_none(),
        "the call response must complete the pending request: {second}"
    );
    assert_eq!(json_id(&second).as_deref(), Some("77"));

    drop(stdin);
}

/// A server→client request the client actually answers: the response
/// correlates with the tracked server request and lets the server finish
/// the original call.
#[tokio::test]
async fn s2c_request_answered_by_client_completes_call() {
    let dir = make_test_dir("s2c_ping_wait");
    let policy = write_policy(dir.path(), WIRE_POLICY);
    let audit_log = common::next_audit_log_path();
    let mut child = spawn_guard(
        &policy,
        false,
        common::scripted_stdio_argv("s2c_ping_wait"),
        &audit_log,
    );
    let mut stdin = child.stdin.take().expect("stdin");
    let stdout = child.stdout.take().expect("stdout");
    let _guard = ChildGuard(child);
    let mut reader = BufReader::new(stdout).lines();
    handshake_2025(&mut stdin, &mut reader).await;

    let req = call("read_file", 5);
    stdin
        .write_all(format!("{req}\n").as_bytes())
        .await
        .expect("write call");
    stdin.flush().await.expect("flush");

    let ping = recv_jsonrpc(&mut reader).await;
    assert_eq!(json_method(&ping).as_deref(), Some("ping"), "got: {ping}");
    assert_eq!(json_id(&ping).as_deref(), Some("\"srv-ping\""));

    // Client→server response correlates with the tracked server request.
    send_notify(
        &mut stdin,
        r#"{"jsonrpc":"2.0","id":"srv-ping","result":{}}"#,
    )
    .await;
    let result = recv_jsonrpc(&mut reader).await;
    assert!(
        has_result(&result) && json_id(&result).as_deref() == Some("5"),
        "call must complete after the server request is answered: {result}"
    );

    drop(stdin);
}

/// A denied S2C request is answered to the *server*, not forwarded to the
/// client — the fixture's pending sampling request gets a proxy-generated
/// error and completes the original call.
#[tokio::test]
async fn denied_s2c_request_errors_server_and_keeps_call_alive() {
    let dir = make_test_dir("s2c_denied");
    let policy = write_policy(dir.path(), WIRE_POLICY);
    let audit_log = common::next_audit_log_path();
    let mut child = spawn_guard(
        &policy,
        false,
        common::scripted_stdio_argv("s2c_sampling"),
        &audit_log,
    );
    let mut stdin = child.stdin.take().expect("stdin");
    let stdout = child.stdout.take().expect("stdout");
    let _guard = ChildGuard(child);
    let mut reader = BufReader::new(stdout).lines();
    handshake_2025(&mut stdin, &mut reader).await;

    let req = call("read_file", 9);
    let resp = send_and_recv(&mut stdin, &mut reader, &req).await;
    // The first client-visible frame is the call result: the unruly
    // sampling request never crossed to the client.
    assert!(
        has_result(&resp) && json_method(&resp).is_none(),
        "denied server request must not reach the client: {resp}"
    );
    assert_eq!(json_id(&resp).as_deref(), Some("9"));

    drop(stdin);
}

// ─── Orphan / malformed / duplicate frames ──────────────────────────────

/// An uncorrelated response and an unmatched progress notification are
/// dropped (never reach the client) and audited.
#[tokio::test]
async fn orphan_response_and_unmatched_progress_are_dropped() {
    let dir = make_test_dir("rogue");
    let policy = write_policy(dir.path(), WIRE_POLICY);
    let audit_log = common::next_audit_log_path();
    let mut child = spawn_guard(
        &policy,
        false,
        common::scripted_stdio_argv("rogue_frames"),
        &audit_log,
    );
    let mut stdin = child.stdin.take().expect("stdin");
    let stdout = child.stdout.take().expect("stdout");
    let mut guard = ChildGuard(child);
    let mut reader = BufReader::new(stdout).lines();
    handshake_2025(&mut stdin, &mut reader).await;

    let resp = send_and_recv(&mut stdin, &mut reader, &call("read_file", 3)).await;
    // The first client-visible frame must be the real answer — the ghost
    // response and bogus progress notification never cross the proxy.
    assert_eq!(json_id(&resp).as_deref(), Some("3"), "got: {resp}");
    assert!(has_result(&resp), "got: {resp}");

    drop(stdin);
    let _ = timeout(Duration::from_secs(TIMEOUT_SECS), guard.0.wait()).await;

    let audit = read_audit(&audit_log);
    assert!(
        audit_lines(&audit, "mcp_message.denied")
            .iter()
            .any(|l| l.contains("uncorrelated") && l.contains("ghost-9")),
        "orphan response must be audited as denied/uncorrelated: {audit}"
    );
    assert!(
        audit_lines(&audit, "mcp_message.dropped")
            .iter()
            .any(|l| l.contains("notifications/progress")),
        "unmatched progress must be audited as dropped: {audit}"
    );
}

/// The second response to a completed request is an orphan: it is dropped
/// and cannot impersonate the next request's answer.
#[tokio::test]
async fn duplicate_response_is_dropped_not_replayed() {
    let dir = make_test_dir("dup_resp");
    let policy = write_policy(dir.path(), WIRE_POLICY);
    let audit_log = common::next_audit_log_path();
    let mut child = spawn_guard(
        &policy,
        false,
        common::scripted_stdio_argv("double_response"),
        &audit_log,
    );
    let mut stdin = child.stdin.take().expect("stdin");
    let stdout = child.stdout.take().expect("stdout");
    let mut guard = ChildGuard(child);
    let mut reader = BufReader::new(stdout).lines();
    handshake_2025(&mut stdin, &mut reader).await;

    let resp1 = send_and_recv(&mut stdin, &mut reader, &call("read_file", 10)).await;
    assert!(has_result(&resp1), "got: {resp1}");

    // The duplicate result for id 10 must not surface before (or as) the
    // next request's answer.
    let resp2 = send_and_recv(&mut stdin, &mut reader, &call("read_file", 11)).await;
    assert_eq!(json_id(&resp2).as_deref(), Some("11"), "got: {resp2}");
    assert!(has_result(&resp2), "got: {resp2}");

    drop(stdin);
    let _ = timeout(Duration::from_secs(TIMEOUT_SECS), guard.0.wait()).await;

    let audit = read_audit(&audit_log);
    assert!(
        audit_lines(&audit, "mcp_message.denied")
            .iter()
            .any(|l| l.contains("uncorrelated")),
        "duplicate response must be audited: {audit}"
    );
}

/// Malformed JSON-RPC frames are answered with a protocol error, never
/// forwarded to the child.
#[tokio::test]
async fn malformed_frame_is_rejected_with_error() {
    let dir = make_test_dir("malformed");
    let policy = write_policy(dir.path(), WIRE_POLICY);
    let audit_log = common::next_audit_log_path();
    let mut child = spawn_guard(
        &policy,
        false,
        common::scripted_stdio_argv("tools_call_ok"),
        &audit_log,
    );
    let mut stdin = child.stdin.take().expect("stdin");
    let stdout = child.stdout.take().expect("stdout");
    let _guard = ChildGuard(child);
    let mut reader = BufReader::new(stdout).lines();
    handshake_2025(&mut stdin, &mut reader).await;

    // `method` must be a string.
    let bad = r#"{"jsonrpc":"2.0","id":7,"method":42}"#;
    let resp = send_and_recv(&mut stdin, &mut reader, bad).await;
    assert!(has_error(&resp), "malformed request must error: {resp}");
    assert!(error_message(&resp).contains("malformed"), "got: {resp}");

    // A `method`+`result` hybrid is malformed too — it must never reach
    // the server, where a result-first parser could read a forged answer.
    let hybrid = r#"{"jsonrpc":"2.0","id":7,"method":"ping","result":{"planted":true}}"#;
    let resp = send_and_recv(&mut stdin, &mut reader, hybrid).await;
    assert!(has_error(&resp), "hybrid frame must error: {resp}");
    assert!(error_message(&resp).contains("malformed"), "got: {resp}");

    // A response carrying both `result` and `error` is ambiguous.
    let both = r#"{"jsonrpc":"2.0","id":7,"result":{},"error":{"code":-32000,"message":"x"}}"#;
    let resp = send_and_recv(&mut stdin, &mut reader, both).await;
    assert!(has_error(&resp), "result+error frame must error: {resp}");

    // The session keeps working afterwards.
    let resp = send_and_recv(&mut stdin, &mut reader, &call("read_file", 8)).await;
    assert!(has_result(&resp), "session must survive: {resp}");

    drop(stdin);
}

/// A server→client `method`+`result` hybrid carrying the in-flight
/// call's id is a malformed envelope: it terminates the call — the
/// tracked entry is consumed, the pending call bookkeeping released,
/// and the client gets a JSON-RPC error instead of waiting on a wire
/// answer that never arrives cleanly. A result-first parser can never
/// read the smuggled `result` as the pending request's answer, and the
/// late genuine response correlates nothing.
#[tokio::test]
async fn s2c_mixed_envelope_is_dropped() {
    let dir = make_test_dir("mixed_env");
    let policy = write_policy(dir.path(), WIRE_POLICY);
    let audit_log = common::next_audit_log_path();
    let mut child = spawn_guard(
        &policy,
        false,
        common::scripted_stdio_argv("s2c_mixed_envelope"),
        &audit_log,
    );
    let mut stdin = child.stdin.take().expect("stdin");
    let stdout = child.stdout.take().expect("stdout");
    let mut guard = ChildGuard(child);
    let mut reader = BufReader::new(stdout).lines();
    handshake_2025(&mut stdin, &mut reader).await;

    let resp = send_and_recv(&mut stdin, &mut reader, &call("read_file", 55)).await;
    // The only frame the client sees for id 55 is the guard's error —
    // the hybrid terminated the call; the smuggled result never crosses.
    assert_eq!(json_id(&resp).as_deref(), Some("55"), "got: {resp}");
    assert!(
        has_error(&resp) && error_message(&resp).contains("malformed"),
        "malformed response must be answered with an error: {resp}"
    );
    assert!(
        !resp.contains("forged"),
        "smuggled result must not leak: {resp}"
    );

    drop(stdin);
    let _ = timeout(Duration::from_secs(TIMEOUT_SECS), guard.0.wait()).await;

    let audit = read_audit(&audit_log);
    assert!(
        audit_lines(&audit, "mcp_message.denied")
            .iter()
            .filter(|l| l.contains("malformed") && l.contains("55"))
            .count()
            >= 2,
        "hybrid and ambiguous frames must both be audited as malformed: {audit}"
    );
    // The late genuine response finds no tracked entry — audited as an
    // uncorrelated deny, never forwarded.
    assert!(
        audit_lines(&audit, "mcp_message.denied")
            .iter()
            .any(|l| l.contains("uncorrelated") && l.contains("55")),
        "the late genuine response must be audited as uncorrelated: {audit}"
    );
}

/// A tools/list response whose envelope carries both `result` and
/// `error` is ambiguous — the guard rejects it fail-closed (client gets
/// an error, the session aborts) instead of verifying and emitting the
/// `result` payload.
#[tokio::test]
async fn list_response_with_result_and_error_is_rejected() {
    let dir = make_test_dir("list_both");
    let policy = write_policy(dir.path(), WIRE_POLICY);
    let audit_log = common::next_audit_log_path();
    let mut child = spawn_guard(
        &policy,
        false,
        common::scripted_stdio_argv("list_both_members"),
        &audit_log,
    );
    let mut stdin = child.stdin.take().expect("stdin");
    let stdout = child.stdout.take().expect("stdout");
    let mut guard = ChildGuard(child);
    let mut reader = BufReader::new(stdout).lines();
    handshake_2025(&mut stdin, &mut reader).await;

    let resp = send_and_recv(
        &mut stdin,
        &mut reader,
        r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#,
    )
    .await;
    assert_eq!(json_id(&resp).as_deref(), Some("1"), "got: {resp}");
    assert!(
        has_error(&resp) && error_message(&resp).contains("malformed"),
        "ambiguous envelope must be rejected, not emitted: {resp}"
    );
    assert!(
        !resp.contains("evil_tool"),
        "rejected payload must not leak: {resp}"
    );

    drop(stdin);
    // The fail-closed abort ends the session: the proxy exits.
    let status = timeout(Duration::from_secs(TIMEOUT_SECS), guard.0.wait())
        .await
        .expect("proxy must exit after aborting on the malformed list response");
    assert!(status.is_ok(), "wait must succeed: {status:?}");
}

/// Unknown methods are denied before any forwarding.
#[tokio::test]
async fn unknown_method_is_denied() {
    let dir = make_test_dir("unknown");
    let policy = write_policy(dir.path(), WIRE_POLICY);
    let audit_log = common::next_audit_log_path();
    let mut child = spawn_guard(
        &policy,
        false,
        common::scripted_stdio_argv("tools_call_ok"),
        &audit_log,
    );
    let mut stdin = child.stdin.take().expect("stdin");
    let stdout = child.stdout.take().expect("stdout");
    let mut guard = ChildGuard(child);
    let mut reader = BufReader::new(stdout).lines();
    handshake_2025(&mut stdin, &mut reader).await;

    let req = r#"{"jsonrpc":"2.0","id":21,"method":"exotic/thing","params":{}}"#;
    let resp = send_and_recv(&mut stdin, &mut reader, req).await;
    assert!(has_error(&resp), "unknown method must error: {resp}");
    assert!(error_message(&resp).contains("exotic/thing"), "got: {resp}");

    drop(stdin);
    let _ = timeout(Duration::from_secs(TIMEOUT_SECS), guard.0.wait()).await;
    let audit = read_audit(&audit_log);
    assert!(
        audit_lines(&audit, "mcp_message.denied")
            .iter()
            .any(|l| l.contains("exotic/thing")),
        "unknown method denial must be audited: {audit}"
    );
}

// ─── Dry-run ────────────────────────────────────────────────────────────

/// Under --dry-run a denied request still forwards — and its response comes
/// back as a normal correlated answer, not an orphan.
#[tokio::test]
async fn dry_run_denied_request_response_is_correlated() {
    let dir = make_test_dir("dryrun_wire");
    let deny_policy = r#"
policy version=1
logging level="info" fail_closed=#false
server "wire" {
    tool "read_file"
    tool "exec_shell" deny=#true
}
"#;
    let policy = write_policy(dir.path(), deny_policy);
    let audit_log = common::next_audit_log_path();
    let mut child = spawn_guard(
        &policy,
        true,
        common::scripted_stdio_argv("tools_call_ok"),
        &audit_log,
    );
    let mut stdin = child.stdin.take().expect("stdin");
    let stdout = child.stdout.take().expect("stdout");
    let mut guard = ChildGuard(child);
    let mut reader = BufReader::new(stdout).lines();
    handshake_2025(&mut stdin, &mut reader).await;

    let req = r#"{"jsonrpc":"2.0","id":20,"method":"tools/call","params":{"name":"exec_shell","arguments":{"cmd":"id"}}}"#;
    let resp = send_and_recv(&mut stdin, &mut reader, req).await;
    assert!(
        has_result(&resp),
        "dry-run must forward and correlate the response: {resp}"
    );
    assert!(!has_error(&resp), "got: {resp}");

    drop(stdin);
    let _ = timeout(Duration::from_secs(TIMEOUT_SECS), guard.0.wait()).await;

    // The audit log distinguishes "observed" dry-run forwarding from a
    // normal allow: the denied request must not appear as enforced-allow.
    let audit = read_audit(&audit_log);
    let denied = audit_lines(&audit, "tool_call.denied");
    assert!(
        denied.iter().any(|l| l.contains("exec_shell")),
        "dry-run denial must be audited: {audit}"
    );
    assert!(
        denied.iter().any(|l| l.contains("\"action\":\"observed\"")),
        "dry-run forward must be observed, not allowed: {}",
        denied.first().unwrap_or(&"")
    );
}
