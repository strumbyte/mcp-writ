//! MCP 2026-07-28 revision behavior: `_meta` envelopes, pre-init
//! gating, the subscription lifecycle, and the generic `requestState`
//! size cap on non-tools/call methods.

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::time::{Duration, timeout};

use crate::common;
use crate::support::*;

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

/// `params.requestState` is capped on every request method, not just
/// tools/call — a non-tool MRTR retry (e.g. `resources/read`) cannot push
/// an oversized opaque blob through the generic request path.
#[tokio::test]
async fn request_state_cap_applies_beyond_tools_call() {
    let dir = make_test_dir("rs_cap");
    // resources/read is allowed for one uri; the fixture has no such
    // handler, so a *forwarded* request comes back as `-32601`.
    let policy_kdl = r#"
policy version=2
logging level="info" fail_closed=#false
server "wire" {
    tool "read_file"
    mcp {
        allow "resources/read" { uri "file:///workspace/notes.txt" }
    }
}
"#;
    let policy = write_policy(dir.path(), policy_kdl);
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

    let huge = "x".repeat(70_000);
    let req = format!(
        r#"{{"jsonrpc":"2.0","id":2,"method":"resources/read","params":{{"uri":"file:///workspace/notes.txt","requestState":"{huge}",{meta}}}}}"#,
        meta = common::META_2026
    );
    let resp = send_and_recv(&mut stdin, &mut reader, &req).await;
    assert!(has_error(&resp), "oversized requestState must deny: {resp}");
    assert!(
        error_message(&resp).contains("size cap"),
        "expected the size-cap denial: {resp}"
    );

    // Within the cap the same request forwards — the fixture answers
    // with its generic method-not-found error.
    let ok = format!(
        r#"{{"jsonrpc":"2.0","id":3,"method":"resources/read","params":{{"uri":"file:///workspace/notes.txt","requestState":"small",{meta}}}}}"#,
        meta = common::META_2026
    );
    let resp = send_and_recv(&mut stdin, &mut reader, &ok).await;
    assert!(
        error_message(&resp).contains("Method not found"),
        "under-cap requestState must reach the server: {resp}"
    );

    drop(stdin);
}
