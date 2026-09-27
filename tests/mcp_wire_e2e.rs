//! PR-10 wire-level enforcement end-to-end tests.
//!
//! These exercise the bidirectional JSON-RPC contract the Auditor proxy
//! enforces in front of `tests/fixtures/mcp_servers/scripted_stdio.py`:
//! direction-keyed request/response correlation, orphan and duplicate
//! responses, notifications that never get answers, cancellation and
//! progress correlation, the bounded in-flight request table, the 2026
//! subscription lifecycle, and dry-run forwarding of denied requests.

use std::path::{Path, PathBuf};
use std::process::Stdio;
use tempfile::TempDir;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::Command;
use tokio::time::{Duration, timeout};

mod common;

const TIMEOUT_SECS: u64 = 15;

struct ChildGuard(tokio::process::Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.start_kill();
    }
}

fn make_test_dir(label: &str) -> TempDir {
    tempfile::Builder::new()
        .prefix(&format!("mcp_writ_wire_{label}_"))
        .tempdir()
        .expect("failed to create temp directory")
}

/// Tools the fixture advertises under `tools_call_ok`; the policy allows all
/// three so tools/list filtering never rewrites the verified result.
const WIRE_POLICY: &str = r#"
policy version=1
logging level="info" fail_closed=#false
server "wire" {
    tool "read_file"
    tool "write_file"
    tool "fail_write"
    tool "fetch_url"
}
"#;

fn write_policy(dir: &Path, content: &str) -> PathBuf {
    let path = dir.join("policy.kdl");
    std::fs::write(&path, content).expect("write policy");
    path
}

fn spawn_guard(
    policy: &Path,
    dry_run: bool,
    argv: Vec<String>,
    audit_log: &Path,
) -> tokio::process::Child {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_mcp-writ"));
    cmd.args([
        "run",
        "--transport",
        "stdio",
        "--policy",
        policy.to_str().expect("policy path utf-8"),
        "--audit-log",
        audit_log.to_str().expect("audit log path utf-8"),
    ]);
    if dry_run {
        cmd.arg("--dry-run");
    }
    cmd.arg("--");
    cmd.args(argv)
        .env("MCP_WRIT_SKIP_SANDBOX", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn mcp-writ binary")
}

async fn send_and_recv(
    stdin: &mut tokio::process::ChildStdin,
    reader: &mut tokio::io::Lines<BufReader<tokio::process::ChildStdout>>,
    request: &str,
) -> String {
    stdin
        .write_all(format!("{request}\n").as_bytes())
        .await
        .expect("write request");
    stdin.flush().await.expect("flush request");
    recv_jsonrpc(reader).await
}

async fn recv_jsonrpc(
    reader: &mut tokio::io::Lines<BufReader<tokio::process::ChildStdout>>,
) -> String {
    timeout(Duration::from_secs(TIMEOUT_SECS), async {
        loop {
            let line = reader
                .next_line()
                .await
                .expect("IO error reading mcp-writ stdout")
                .expect("unexpected EOF on mcp-writ stdout");
            if line.starts_with("{\"jsonrpc\"") {
                return line;
            }
        }
    })
    .await
    .expect("timeout waiting for JSON-RPC frame")
}

async fn send_notify(stdin: &mut tokio::process::ChildStdin, frame: &str) {
    stdin
        .write_all(format!("{frame}\n").as_bytes())
        .await
        .expect("write notification");
    stdin.flush().await.expect("flush");
}

/// 2025-11-25 handshake.
async fn handshake_2025(
    stdin: &mut tokio::process::ChildStdin,
    reader: &mut tokio::io::Lines<BufReader<tokio::process::ChildStdout>>,
) {
    let response = send_and_recv(stdin, reader, common::INIT_REQUEST).await;
    assert!(
        response.contains("\"protocolVersion\":\"2025-11-25\""),
        "initialize must complete: {response}"
    );
    send_notify(stdin, common::INITIALIZED_NOTIF).await;
}

fn json_method(frame: &str) -> Option<String> {
    let json = nojson::RawJson::parse(frame).ok()?;
    json.value()
        .to_member("method")
        .ok()
        .and_then(|m| m.optional())
        .and_then(|v| v.to_unquoted_string_str().ok())
        .map(|s| s.into_owned())
}

fn json_id(frame: &str) -> Option<String> {
    let json = nojson::RawJson::parse(frame).ok()?;
    json.value()
        .to_member("id")
        .ok()
        .and_then(|m| m.optional())
        .map(|v| v.as_raw_str().to_string())
}

fn has_result(frame: &str) -> bool {
    nojson::RawJson::parse(frame)
        .ok()
        .and_then(|j| {
            j.value()
                .to_member("result")
                .ok()
                .and_then(|m| m.optional().map(|_| ()))
        })
        .is_some()
}

fn has_error(frame: &str) -> bool {
    nojson::RawJson::parse(frame)
        .ok()
        .and_then(|j| {
            j.value()
                .to_member("error")
                .ok()
                .and_then(|m| m.optional().map(|_| ()))
        })
        .is_some()
}

fn error_message(frame: &str) -> String {
    nojson::RawJson::parse(frame)
        .ok()
        .and_then(|j| {
            j.value()
                .to_member("error")
                .ok()
                .and_then(|m| m.optional())
                .and_then(|e| {
                    e.to_member("message")
                        .ok()
                        .and_then(|m| m.optional())
                        .and_then(|v| v.to_unquoted_string_str().ok())
                        .map(|s| s.into_owned())
                })
        })
        .unwrap_or_default()
}

fn read_audit(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap_or_default()
}

fn audit_lines<'a>(audit: &'a str, event_type: &str) -> Vec<&'a str> {
    audit
        .lines()
        .filter(|l| l.contains(&format!("\"event_type\":\"{event_type}\"")))
        .collect()
}

fn call(name: &str, id: u32) -> String {
    format!(
        r#"{{"jsonrpc":"2.0","id":{id},"method":"tools/call","params":{{"name":"{name}","arguments":{{"path":"/workspace/notes.txt"}}}}}}"#
    )
}

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
/// call's id is a malformed envelope: it is dropped and audited, never
/// reaching the client where a result-first parser could read the
/// smuggled `result` as the pending request's answer. The genuine
/// response still completes the call.
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
    // The only frame the client sees for id 55 is the genuine response —
    // the hybrid (which would look like a request) never crosses.
    assert_eq!(json_id(&resp).as_deref(), Some("55"), "got: {resp}");
    assert!(
        has_result(&resp) && json_method(&resp).is_none(),
        "client must see only the real response: {resp}"
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
    timeout(Duration::from_secs(TIMEOUT_SECS), guard.0.wait())
        .await
        .expect("proxy must exit after aborting on the malformed list response");
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

// ─── Cancellation and progress correlation ──────────────────────────────

/// `notifications/cancelled` forwards only when it names a live request of
/// the same direction; an unrelated cancel id is dropped and audited.
#[tokio::test]
async fn cancelled_notification_correlates_with_inflight_request() {
    let dir = make_test_dir("cancel");
    let policy = write_policy(dir.path(), WIRE_POLICY);
    let audit_log = common::next_audit_log_path();
    let mut child = spawn_guard(
        &policy,
        false,
        common::scripted_stdio_argv("black_hole"),
        &audit_log,
    );
    let mut stdin = child.stdin.take().expect("stdin");
    let stdout = child.stdout.take().expect("stdout");
    let mut guard = ChildGuard(child);
    let mut reader = BufReader::new(stdout).lines();
    handshake_2025(&mut stdin, &mut reader).await;

    // A call the fixture never answers stays in flight.
    send_notify(&mut stdin, &call("read_file", 50)).await;
    // Give the guard a beat to register the request.
    tokio::time::sleep(Duration::from_millis(120)).await;

    send_notify(
        &mut stdin,
        r#"{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":50}}"#,
    )
    .await;
    send_notify(
        &mut stdin,
        r#"{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":999}}"#,
    )
    .await;
    tokio::time::sleep(Duration::from_millis(120)).await;

    drop(stdin);
    let _ = timeout(Duration::from_secs(TIMEOUT_SECS), guard.0.wait()).await;

    let audit = read_audit(&audit_log);
    assert!(
        audit_lines(&audit, "mcp_message.allowed")
            .iter()
            .any(|l| l.contains("notifications/cancelled")),
        "correlated cancel must be forwarded and audited: {audit}"
    );
    assert!(
        audit_lines(&audit, "mcp_message.dropped")
            .iter()
            .any(|l| l.contains("notifications/cancelled")),
        "unrelated cancel must be dropped and audited: {audit}"
    );
}

/// A progress notification keyed to the in-flight request's progressToken
/// forwards; the request's own result still completes it.
#[tokio::test]
async fn progress_notification_correlates_via_token() {
    let dir = make_test_dir("progress");
    let policy = write_policy(dir.path(), WIRE_POLICY);
    let audit_log = common::next_audit_log_path();
    let mut child = spawn_guard(
        &policy,
        false,
        common::scripted_stdio_argv("progress_ok"),
        &audit_log,
    );
    let mut stdin = child.stdin.take().expect("stdin");
    let stdout = child.stdout.take().expect("stdout");
    let _guard = ChildGuard(child);
    let mut reader = BufReader::new(stdout).lines();
    handshake_2025(&mut stdin, &mut reader).await;

    let req = r#"{"jsonrpc":"2.0","id":60,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/workspace/notes.txt"},"_meta":{"progressToken":"tok-1"}}}"#;
    stdin
        .write_all(format!("{req}\n").as_bytes())
        .await
        .expect("write call");
    stdin.flush().await.expect("flush");

    let progress = recv_jsonrpc(&mut reader).await;
    assert_eq!(
        json_method(&progress).as_deref(),
        Some("notifications/progress"),
        "correlated progress must forward: {progress}"
    );
    let result = recv_jsonrpc(&mut reader).await;
    assert!(
        has_result(&result) && json_id(&result).as_deref() == Some("60"),
        "call result must arrive after progress: {result}"
    );

    drop(stdin);
}

// ─── Bounded in-flight table ────────────────────────────────────────────

/// Once MAX_IN_FLIGHT_REQUESTS (128) unanswered requests fill the table,
/// the next request is denied without evicting any pending entry.
#[tokio::test]
async fn inflight_request_table_is_bounded() {
    let dir = make_test_dir("capacity");
    let policy = write_policy(dir.path(), WIRE_POLICY);
    let audit_log = common::next_audit_log_path();
    let mut child = spawn_guard(
        &policy,
        false,
        common::scripted_stdio_argv("black_hole"),
        &audit_log,
    );
    let mut stdin = child.stdin.take().expect("stdin");
    let stdout = child.stdout.take().expect("stdout");
    let _guard = ChildGuard(child);
    let mut reader = BufReader::new(stdout).lines();
    handshake_2025(&mut stdin, &mut reader).await;

    // Fill the table: black_hole never answers, so every ping stays in
    // flight. `ping` avoids the tools/call pending-call accounting.
    let mut out = String::new();
    for id in 1..=128u32 {
        out.push_str(&format!(r#"{{"jsonrpc":"2.0","id":{id},"method":"ping"}}"#));
        out.push('\n');
    }
    stdin.write_all(out.as_bytes()).await.expect("write pings");
    stdin.flush().await.expect("flush pings");
    tokio::time::sleep(Duration::from_millis(300)).await;

    let resp = send_and_recv(
        &mut stdin,
        &mut reader,
        r#"{"jsonrpc":"2.0","id":129,"method":"ping"}"#,
    )
    .await;
    assert!(has_error(&resp), "129th request must be denied: {resp}");
    assert!(
        error_message(&resp).contains("in-flight request limit"),
        "capacity denial must name the limit: {resp}"
    );

    drop(stdin);
}

// ─── 2026-07-28 revision ────────────────────────────────────────────────

/// A 2026 request travels without the 2025 handshake; its response carries
/// the revision's result envelope (resultType/ttlMs/cacheScope).
#[tokio::test]
async fn v26_request_with_meta_round_trips() {
    let dir = make_test_dir("v26_call");
    let policy = write_policy(dir.path(), WIRE_POLICY);
    let audit_log = common::next_audit_log_path();
    let mut child = spawn_guard(
        &policy,
        false,
        common::scripted_stdio_argv_v26("tools_call_ok"),
        &audit_log,
    );
    let mut stdin = child.stdin.take().expect("stdin");
    let stdout = child.stdout.take().expect("stdout");
    let _guard = ChildGuard(child);
    let mut reader = BufReader::new(stdout).lines();

    let req = format!(
        r#"{{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{{"name":"read_file","arguments":{{"path":"/workspace/notes.txt"}},{meta}}}}}"#,
        meta = common::META_2026
    );
    let resp = send_and_recv(&mut stdin, &mut reader, &req).await;
    assert!(has_result(&resp), "2026 call must pass: {resp}");
    assert!(
        resp.contains("\"resultType\":\"complete\""),
        "2026 result must carry the revision's envelope: {resp}"
    );
    assert!(resp.contains("\"ttlMs\""), "got: {resp}");
    assert!(resp.contains("\"cacheScope\""), "got: {resp}");

    drop(stdin);
}

/// A 2025-style request without `_meta` on an unestablished wire is judged
/// as 2025 — and denied before initialization.
#[tokio::test]
async fn request_without_meta_denied_before_init() {
    let dir = make_test_dir("no_meta");
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

    let resp = send_and_recv(&mut stdin, &mut reader, &call("read_file", 1)).await;
    assert!(has_error(&resp), "pre-init request must be denied: {resp}");
    assert!(
        error_message(&resp).contains("init-order"),
        "expected init-order denial: {resp}"
    );

    drop(stdin);
}

/// 2026 forbids server→client top-level requests entirely: the frame is
/// audited and stopped, and no client→server response is generated back.
#[tokio::test]
async fn v26_s2c_request_is_stopped_without_c2s_response() {
    let dir = make_test_dir("v26_s2c");
    let policy = write_policy(dir.path(), WIRE_POLICY);
    let audit_log = common::next_audit_log_path();
    let mut child = spawn_guard(
        &policy,
        false,
        common::scripted_stdio_argv_v26("s2c_id_collision"),
        &audit_log,
    );
    let mut stdin = child.stdin.take().expect("stdin");
    let stdout = child.stdout.take().expect("stdout");
    let mut guard = ChildGuard(child);
    let mut reader = BufReader::new(stdout).lines();

    let req = format!(
        r#"{{"jsonrpc":"2.0","id":80,"method":"tools/call","params":{{"name":"read_file","arguments":{{"path":"/workspace/notes.txt"}},{meta}}}}}"#,
        meta = common::META_2026
    );
    let resp = send_and_recv(&mut stdin, &mut reader, &req).await;
    // The forbidden server request never crosses: the first frame is the
    // call's own result.
    assert!(
        has_result(&resp) && json_method(&resp).is_none(),
        "2026 server request must not reach the client: {resp}"
    );
    assert_eq!(json_id(&resp).as_deref(), Some("80"));

    drop(stdin);
    let _ = timeout(Duration::from_secs(TIMEOUT_SECS), guard.0.wait()).await;
    let audit = read_audit(&audit_log);
    assert!(
        audit_lines(&audit, "mcp_message.denied")
            .iter()
            .any(|l| l.contains("dir=s2c")),
        "forbidden 2026 server request must be audited denied: {audit}"
    );
}

/// The 2026 subscription lifecycle: listen → result (request stays tracked)
/// → acknowledged → subscription-scoped list_changed → revalidation →
/// forwarded notification. A list_changed under an unknown subscriptionId
/// is dropped before the real one.
#[tokio::test]
async fn v26_subscription_lifecycle_and_revalidation() {
    let dir = make_test_dir("v26_subs");
    let policy = write_policy(dir.path(), WIRE_POLICY);
    let audit_log = common::next_audit_log_path();
    let mut child = spawn_guard(
        &policy,
        false,
        common::scripted_stdio_argv_v26("subscriptions_mixed"),
        &audit_log,
    );
    let mut stdin = child.stdin.take().expect("stdin");
    let stdout = child.stdout.take().expect("stdout");
    let _guard = ChildGuard(child);
    let mut reader = BufReader::new(stdout).lines();

    let listen = format!(
        r#"{{"jsonrpc":"2.0","id":"sub-1","method":"subscriptions/listen","params":{{"notifications":{{"toolsListChanged":true}},{meta}}}}}"#,
        meta = common::META_2026
    );
    stdin
        .write_all(format!("{listen}\n").as_bytes())
        .await
        .expect("write listen");
    stdin.flush().await.expect("flush");

    // 1. The listen result carries the subscription id and completes.
    let result = recv_jsonrpc(&mut reader).await;
    assert!(
        has_result(&result) && result.contains("\"subscriptionId\":\"sub-1\""),
        "listen must complete with its subscription id: {result}"
    );

    // 2. The acknowledgement notification resolves against the still-open
    //    subscription entry.
    let ack = recv_jsonrpc(&mut reader).await;
    assert_eq!(
        json_method(&ack).as_deref(),
        Some("notifications/subscriptions/acknowledged"),
        "ack must forward: {ack}"
    );

    // 3. The bogus-subscription list_changed is dropped; the correlated one
    //    triggers relist + verification, then forwards.
    let changed = recv_jsonrpc(&mut reader).await;
    assert_eq!(
        json_method(&changed).as_deref(),
        Some("notifications/tools/list_changed"),
        "correlated list_changed must forward after revalidation: {changed}"
    );
    assert!(
        !changed.contains("bogus-sub"),
        "the dropped notification must not leak: {changed}"
    );

    // The wire still answers requests afterwards (`ping` is removed in
    // 2026, so the liveness probe is another tools/call).
    let call2 = format!(
        r#"{{"jsonrpc":"2.0","id":90,"method":"tools/call","params":{{"name":"read_file","arguments":{{"path":"/workspace/notes.txt"}},{meta}}}}}"#,
        meta = common::META_2026
    );
    let resp2 = send_and_recv(&mut stdin, &mut reader, &call2).await;
    assert!(has_result(&resp2), "call after subscription: {resp2}");

    drop(stdin);
}

/// `notifications/cancelled` naming a live 2026 subscription ends it.
#[tokio::test]
async fn v26_subscription_cancel_ends_tracking() {
    let dir = make_test_dir("v26_sub_cancel");
    let policy = write_policy(dir.path(), WIRE_POLICY);
    let audit_log = common::next_audit_log_path();
    let mut child = spawn_guard(
        &policy,
        false,
        common::scripted_stdio_argv_v26("subscriptions_ok"),
        &audit_log,
    );
    let mut stdin = child.stdin.take().expect("stdin");
    let stdout = child.stdout.take().expect("stdout");
    let mut guard = ChildGuard(child);
    let mut reader = BufReader::new(stdout).lines();

    let listen = format!(
        r#"{{"jsonrpc":"2.0","id":"sub-7","method":"subscriptions/listen","params":{{"notifications":{{"toolsListChanged":true}},{meta}}}}}"#,
        meta = common::META_2026
    );
    let result = send_and_recv(&mut stdin, &mut reader, &listen).await;
    assert!(has_result(&result), "listen must complete: {result}");
    // Drain the ack + correlated list_changed.
    let _ = recv_jsonrpc(&mut reader).await;
    let _ = recv_jsonrpc(&mut reader).await;

    send_notify(
        &mut stdin,
        r#"{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":"sub-7","_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}}"#,
    )
    .await;
    tokio::time::sleep(Duration::from_millis(150)).await;

    drop(stdin);
    let _ = timeout(Duration::from_secs(TIMEOUT_SECS), guard.0.wait()).await;
    let audit = read_audit(&audit_log);
    assert!(
        audit_lines(&audit, "mcp_message.allowed")
            .iter()
            .any(|l| l.contains("notifications/cancelled")),
        "subscription cancel must forward and audit: {audit}"
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
