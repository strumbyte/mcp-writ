//! In-flight request bookkeeping: cancellation and progress
//! correlation, the bounded pending table, tools/list busy gating,
//! and pending-state release when responses are denied.

use std::process::Stdio;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::Command;
use tokio::time::{Duration, timeout};

use crate::common;
use crate::support::*;

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

/// A forwarded `notifications/cancelled` naming an in-flight client
/// `tools/list` releases the list bookkeeping the missing response would
/// have unwound — the busy gate, the pending id, the stored request
/// template. A later `tools/call` must be admitted: a latched busy gate
/// would deny every call (fail-closed degrading into a liveness fault).
#[tokio::test]
async fn cancelled_tools_list_releases_busy_gate() {
    let dir = make_test_dir("cancel_list");
    let policy = write_policy(dir.path(), WIRE_POLICY);
    let audit_log = common::next_audit_log_path();
    let mut child = spawn_guard(
        &policy,
        false,
        common::scripted_stdio_argv("black_hole_list"),
        &audit_log,
    );
    let mut stdin = child.stdin.take().expect("stdin");
    let stdout = child.stdout.take().expect("stdout");
    let mut guard = ChildGuard(child);
    let mut reader = BufReader::new(stdout).lines();
    handshake_2025(&mut stdin, &mut reader).await;

    // A list the fixture never answers stays in flight and holds the
    // busy gate.
    send_notify(
        &mut stdin,
        r#"{"jsonrpc":"2.0","id":70,"method":"tools/list","params":{}}"#,
    )
    .await;
    // Give the guard a beat to register the request.
    tokio::time::sleep(Duration::from_millis(120)).await;

    // The client cancels it — the cancel forwards to the server, which
    // honours it by dropping the request without a response.
    send_notify(
        &mut stdin,
        r#"{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":70}}"#,
    )
    .await;
    tokio::time::sleep(Duration::from_millis(120)).await;

    // Must be admitted — a stuck busy gate would deny it.
    send_notify(&mut stdin, &call("read_file", 71)).await;
    tokio::time::sleep(Duration::from_millis(150)).await;

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
        audit_lines(&audit, "mcp_message.allowed")
            .iter()
            .any(|l| l.contains("tools/call")),
        "tools/call after a cancelled tools/list must be allowed: {audit}"
    );
    assert!(
        !audit_lines(&audit, "mcp_message.denied")
            .iter()
            .any(|l| l.contains("tools/call")),
        "the post-cancel tools/call must not be busy-denied: {audit}"
    );
}

/// Insert a `tools-list-hash` pin into [`WIRE_POLICY`]'s server block.
fn wire_policy_with_hash(hash: &str) -> String {
    WIRE_POLICY.replacen(
        "server \"wire\" {",
        &format!("server \"wire\" {{\n    tools-list-hash \"{hash}\""),
        1,
    )
}

/// Query the scripted fixture directly for its advertised tools/list so a
/// pinned hash is computed on the real response, not a retyped copy.
async fn advertised_tools(fixture: &str) -> Vec<mcp_writ::tool_def::ToolDefinition> {
    let argv = common::scripted_stdio_argv(fixture);
    let mut server = Command::new(&argv[0])
        .args(&argv[1..])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("failed to spawn scripted fixture");
    let mut stdin = server.stdin.take().expect("stdin");
    let stdout = server.stdout.take().expect("stdout");
    let mut server = ChildGuard(server);
    let mut reader = BufReader::new(stdout).lines();
    handshake_2025(&mut stdin, &mut reader).await;
    let list = r#"{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}"#;
    let line = send_and_recv(&mut stdin, &mut reader, list).await;
    drop(stdin);
    let _ = server.0.kill().await;
    mcp_writ::protocol::tools_list::parse_tools_list_response(&line)
        .expect("fixture tools/list must parse")
}

/// A `tools/list` response that arrives only after the client cancelled
/// the request is dead traffic. Under a tools-list-hash pin its
/// tools-shaped payload would otherwise re-enter the verification
/// pipeline — resurrecting a listing nobody awaits — so the guard must
/// consume the wire entry, audit the anomaly, and keep the frame off
/// the wire: the first response the client sees is the next request's
/// own answer.
#[tokio::test]
async fn late_tools_list_response_after_cancel_is_dropped() {
    // `late_list_answer` advertises the default `clean_tools()` set;
    // query it in `black_hole` mode, which answers immediately with the
    // same list.
    let advertised = advertised_tools("black_hole").await;
    let pin =
        mcp_writ::verifier::tools_diff::hash_tools_list(&advertised).expect("hash advertised set");
    let dir = make_test_dir("late_list");
    let policy = write_policy(dir.path(), &wire_policy_with_hash(&pin));
    let audit_log = common::next_audit_log_path();
    let mut child = spawn_guard(
        &policy,
        false,
        common::scripted_stdio_argv("late_list_answer"),
        &audit_log,
    );
    let mut stdin = child.stdin.take().expect("stdin");
    let stdout = child.stdout.take().expect("stdout");
    let mut guard = ChildGuard(child);
    let mut reader = BufReader::new(stdout).lines();
    handshake_2025(&mut stdin, &mut reader).await;

    // The fixture holds the listing; the client cancels, and the server
    // emits the dead response anyway.
    send_notify(
        &mut stdin,
        r#"{"jsonrpc":"2.0","id":70,"method":"tools/list","params":{}}"#,
    )
    .await;
    tokio::time::sleep(Duration::from_millis(120)).await;
    send_notify(
        &mut stdin,
        r#"{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":70}}"#,
    )
    .await;
    tokio::time::sleep(Duration::from_millis(200)).await;

    // A resurrected listing would surface as a response carrying id 70 —
    // the next frame must instead be the tools/call answer.
    let resp = send_and_recv(&mut stdin, &mut reader, &call("read_file", 71)).await;
    assert_eq!(
        json_id(&resp).as_deref(),
        Some("71"),
        "the first post-cancel frame must be the call's own answer: {resp}"
    );
    assert!(has_result(&resp), "tools/call must succeed: {resp}");

    drop(stdin);
    let _ = timeout(Duration::from_secs(TIMEOUT_SECS), guard.0.wait()).await;

    let audit = read_audit(&audit_log);
    assert!(
        audit_lines(&audit, "mcp_message.denied")
            .iter()
            .any(|l| l.contains("response to cancelled tools/list")),
        "the dead listing response must be audited as malformed: {audit}"
    );
}

/// A `tools/list` denied under `--dry-run` must not cross to the server:
/// observation-only forwarding is limited to `tools/call` policy
/// denials, and a non-tool method denial fails closed with the policy
/// error back to the client — no server traffic, no listing pipeline.
#[tokio::test]
async fn dry_run_denied_tools_list_is_blocked() {
    let dir = make_test_dir("dry_denied_list");
    let policy = write_policy(dir.path(), WIRE_POLICY);
    let audit_log = common::next_audit_log_path();
    let mut child = spawn_guard(
        &policy,
        true,
        common::scripted_stdio_argv_v26("tools_call_ok"),
        &audit_log,
    );
    let mut stdin = child.stdin.take().expect("stdin");
    let stdout = child.stdout.take().expect("stdout");
    let mut guard = ChildGuard(child);
    let mut reader = BufReader::new(stdout).lines();

    // Establish the 2026 wire with a meta-carrying call.
    let req = format!(
        r#"{{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{{"name":"read_file","arguments":{{"path":"/workspace/notes.txt"}},{meta}}}}}"#,
        meta = common::META_2026
    );
    let resp = send_and_recv(&mut stdin, &mut reader, &req).await;
    assert!(has_result(&resp), "2026 call must pass: {resp}");

    // A `tools/list` without the required `_meta` is denied — under
    // dry-run the non-tool denial is no longer forwarded, so the client
    // receives the policy error and the server never sees the request.
    let list = r#"{"jsonrpc":"2.0","id":70,"method":"tools/list","params":{}}"#;
    let resp = send_and_recv(&mut stdin, &mut reader, list).await;
    assert!(
        has_error(&resp),
        "the denied listing must fail closed, not forward: {resp}"
    );
    assert!(
        resp.contains("meta-missing"),
        "the denial reason must reach the client: {resp}"
    );

    drop(stdin);
    let _ = timeout(Duration::from_secs(TIMEOUT_SECS), guard.0.wait()).await;

    let audit = read_audit(&audit_log);
    assert!(
        audit_lines(&audit, "mcp_message.denied")
            .iter()
            .any(|l| l.contains("tools/list") && l.contains("forwarded=false")),
        "the denied listing must be audited denied+not forwarded: {audit}"
    );
    assert!(
        !audit
            .lines()
            .any(|l| l.contains("response to cancelled tools/list")),
        "a denied-but-forwarded listing is not cancelled traffic: {audit}"
    );
}

/// Client frames squatting on the reserved internal-request id namespace
/// (`__mcp_writ_internal__*`) are refused: the request is answered with a
/// JSON-RPC error and never reaches the server, a `notifications/cancelled`
/// naming a reserved id is consumed rather than forwarded, and an
/// ordinary numeric id carrying the same sequence still correlates.
#[tokio::test]
async fn reserved_internal_id_frames_are_refused() {
    let dir = make_test_dir("reserved_id");
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

    // A request minted inside the internal namespace is denied at the
    // gate — the error answer proves the server never saw it (the
    // fixture would answer tools/list with a result).
    let reserved =
        r#"{"jsonrpc":"2.0","id":"__mcp_writ_internal__910001","method":"tools/list","params":{}}"#;
    let resp = send_and_recv(&mut stdin, &mut reader, reserved).await;
    assert!(
        has_error(&resp),
        "a reserved-namespace id must be refused: {resp}"
    );
    assert_eq!(
        json_id(&resp).as_deref(),
        Some("\"__mcp_writ_internal__910001\"")
    );

    // A cancel naming the same reserved id is consumed — the server must
    // not learn to drop an internal request mid-revalidation.
    send_notify(
        &mut stdin,
        r#"{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":"__mcp_writ_internal__910001"}}"#,
    )
    .await;

    // Same sequence as a *numeric* client id: a different namespace, so
    // the call still forwards and completes normally.
    let resp = send_and_recv(&mut stdin, &mut reader, &call("read_file", 910_001)).await;
    assert!(
        has_result(&resp) && json_id(&resp).as_deref() == Some("910001"),
        "a numeric id sharing the internal sequence must not collide: {resp}"
    );

    drop(stdin);
    let _ = timeout(Duration::from_secs(TIMEOUT_SECS), guard.0.wait()).await;

    let audit = read_audit(&audit_log);
    assert!(
        audit_lines(&audit, "mcp_message.denied")
            .iter()
            .any(|l| l.contains("__mcp_writ_internal__910001") && l.contains("forwarded=false")),
        "the reserved-id request must be audited denied+not forwarded: {audit}"
    );
    let cancel_audit: Vec<_> = audit_lines(&audit, "mcp_message.dropped")
        .into_iter()
        .filter(|l| l.contains("notifications/cancelled"))
        .collect();
    assert!(
        cancel_audit
            .iter()
            .any(|l| l.contains("forwarded=false") && l.contains("reserved")),
        "the reserved-id cancel must be audited dropped, not forwarded: {audit}"
    );
    assert!(
        !audit
            .lines()
            .any(|l| l.contains("notifications/cancelled") && l.contains("forwarded=true")),
        "no cancel for the reserved namespace may reach the server: {audit}"
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
    assert!(
        has_error(&resp) && json_id(&resp).as_deref() == Some("129"),
        "request 129 itself must be denied: {resp}"
    );
    assert!(
        error_message(&resp).contains("in-flight request limit"),
        "capacity denial must name the limit: {resp}"
    );

    drop(stdin);
}

// ─── Denied responses release session bookkeeping ──────────────────────

/// A denied response still terminates the RPC — the pending call a
/// forwarded tools/call registered must be released. Without the
/// release, a hostile server answering every call with a rejected shape
/// drains the 128-entry pending table and every later tools/call dies
/// at registration.
#[tokio::test]
async fn denied_response_releases_pending_tool_call() {
    let dir = make_test_dir("deny_pending");
    // trajectory on → every allowed tools/call registers a pending call.
    let policy_kdl = r#"
policy version=1
trajectory #true {
    after side_effect="read_only" deny-next="network"
}
server "wire" {
    tool "read_file" side_effect="read_only"
    tool "deny_me" side_effect="read_only"
}
"#;
    let policy = write_policy(dir.path(), policy_kdl);
    let audit_log = common::next_audit_log_path();
    let mut child = spawn_guard(
        &policy,
        false,
        common::scripted_stdio_argv_v26("denied_result"),
        &audit_log,
    );
    let mut stdin = child.stdin.take().expect("stdin");
    let stdout = child.stdout.take().expect("stdout");
    let _guard = ChildGuard(child);
    let mut reader = BufReader::new(stdout).lines();

    // Each deny_me call is allowed and forwarded, then its response is
    // rejected (missing resultType) — one pending entry each.
    for id in 2..=131u32 {
        let resp = send_and_recv(
            &mut stdin,
            &mut reader,
            &call_2026("deny_me", id, common::META_2026),
        )
        .await;
        assert!(
            has_error(&resp) && error_message(&resp).contains("response rejected"),
            "deny_me response must be rejected: {resp}"
        );
    }
    // Past 128 leaked entries the next call would fail at registration
    // ("too many pending tool calls") instead of reaching the server.
    let resp = send_and_recv(
        &mut stdin,
        &mut reader,
        &call_2026("read_file", 200, common::META_2026),
    )
    .await;
    assert!(
        has_result(&resp),
        "pending table must be released on deny — read_file must still run: {resp}"
    );

    drop(stdin);
}

/// Same release for the Confused-Deputy pending list: a denied response
/// must close the `list_files` bookkeeping or the bounded pending set
/// deadlocks every later listing call.
#[tokio::test]
async fn denied_response_releases_pending_list() {
    let dir = make_test_dir("deny_pending_list");
    let policy_kdl = r#"
policy version=1
confused_deputy_protection #true
server "wire" {
    tool "read_file"
    tool "list_files"
    tool "list_directory"
}
"#;
    let policy = write_policy(dir.path(), policy_kdl);
    let audit_log = common::next_audit_log_path();
    let mut child = spawn_guard(
        &policy,
        false,
        common::scripted_stdio_argv_v26("denied_result"),
        &audit_log,
    );
    let mut stdin = child.stdin.take().expect("stdin");
    let stdout = child.stdout.take().expect("stdout");
    let _guard = ChildGuard(child);
    let mut reader = BufReader::new(stdout).lines();

    for id in 2..=131u32 {
        let resp = send_and_recv(
            &mut stdin,
            &mut reader,
            &call_2026("list_files", id, common::META_2026),
        )
        .await;
        assert!(
            has_error(&resp) && error_message(&resp).contains("response rejected"),
            "list_files response must be rejected: {resp}"
        );
    }
    let resp = send_and_recv(
        &mut stdin,
        &mut reader,
        &call_2026("list_directory", 200, common::META_2026),
    )
    .await;
    assert!(
        has_result(&resp),
        "pending list must be released on deny — list_directory must still run: {resp}"
    );

    drop(stdin);
}
