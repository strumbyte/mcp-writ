//! PR-20: the Auditor's JSON-RPC frame cap is configurable
//! (`--max-frame-bytes`) and a frame over the cap fails only its own
//! request — a recovered correlation id gets a per-request JSON-RPC
//! error, tracking bookkeeping unwinds, and the session continues on
//! the next frame instead of dropping.

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::time::{Duration, timeout};

use crate::common;
use crate::support::*;

/// `run --max-frame-bytes 1048576` — the fixture's `big_*` modes pad to
/// ~2 MiB, comfortably over this cap and comfortably under the 10 MiB
/// default.
const SMALL_CAP: &[&str] = &["--max-frame-bytes", "1048576"];

/// Padding that keeps a request frame just over the 1 MiB test cap.
fn pad() -> String {
    "x".repeat(1_500_000)
}

/// Poll the audit log for a marker — the writer is asynchronous, so a
/// record committed before the verdict surfaced can still lag a poll
/// behind.
fn wait_audit_contains(audit_log: &std::path::Path, needle: &str) -> String {
    let deadline = std::time::Instant::now() + Duration::from_secs(TIMEOUT_SECS);
    loop {
        let audit = read_audit(audit_log);
        if audit.contains(needle) {
            return audit;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "audit log never contained {needle:?}:\n{audit}"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// A ~2 MiB response (`id` serialized last, the TS-SDK layout) crosses a
/// 1 MiB cap: the request gets a JSON-RPC error on its recovered id, the
/// audit record carries `frame-too-large`, and a following request still
/// completes — the refusal stays per-request.
#[tokio::test]
async fn oversized_response_errors_per_request_and_session_continues() {
    let dir = make_test_dir("oversize_s2c");
    let policy = write_policy(dir.path(), WIRE_POLICY);
    let audit_log = common::next_audit_log_path();
    let mut child = spawn_guard_with_args(
        &policy,
        false,
        SMALL_CAP,
        common::scripted_stdio_argv("big_reply"),
        &audit_log,
    );
    let mut stdin = child.stdin.take().expect("stdin");
    let stdout = child.stdout.take().expect("stdout");
    let _guard = ChildGuard(child);
    let mut reader = BufReader::new(stdout).lines();
    handshake_2025(&mut stdin, &mut reader).await;

    let err = send_and_recv(&mut stdin, &mut reader, &call("read_file", 41)).await;
    assert!(has_error(&err), "oversized response must error: {err}");
    // The frame's `id` sits at its very end — recovering `41` proves
    // the tail-window scan.
    assert_eq!(json_id(&err).as_deref(), Some("41"), "got: {err}");
    assert!(
        error_message(&err).contains("frame-too-large"),
        "got: {err}"
    );

    // The session continues on the next frame.
    let pong = send_and_recv(
        &mut stdin,
        &mut reader,
        r#"{"jsonrpc":"2.0","id":42,"method":"ping"}"#,
    )
    .await;
    assert!(has_result(&pong), "ping after refusal must pass: {pong}");

    let audit = wait_audit_contains(&audit_log, "frame-too-large");
    let denied = audit_lines(&audit, "mcp_message.denied");
    assert!(
        denied
            .iter()
            .any(|l| l.contains("dir=s2c") && l.contains("frame-too-large")),
        "s2c frame-too-large denial must be audited:\n{audit}"
    );
}

/// The same ~2 MiB response under the default 10 MiB cap forwards
/// untouched — the cap is a refusal bound, not a rewrite.
#[tokio::test]
async fn two_mib_response_passes_under_the_default_cap() {
    let dir = make_test_dir("oversize_default");
    let policy = write_policy(dir.path(), WIRE_POLICY);
    let audit_log = common::next_audit_log_path();
    let mut child = spawn_guard(
        &policy,
        false,
        common::scripted_stdio_argv("big_reply"),
        &audit_log,
    );
    let mut stdin = child.stdin.take().expect("stdin");
    let stdout = child.stdout.take().expect("stdout");
    let _guard = ChildGuard(child);
    let mut reader = BufReader::new(stdout).lines();
    handshake_2025(&mut stdin, &mut reader).await;

    let resp = send_and_recv(&mut stdin, &mut reader, &call("read_file", 43)).await;
    assert!(
        has_result(&resp) && resp.len() > 2 * 1024 * 1024,
        "the ~2 MiB result must forward intact under the default cap"
    );
    assert_eq!(json_id(&resp).as_deref(), Some("43"));
}

/// A *configured* cap above the fixture's ~2 MiB response forwards it —
/// proving the CLI value reaches the proxy rather than only the default
/// doing so.
#[tokio::test]
async fn configured_larger_cap_passes_the_two_mib_response() {
    let dir = make_test_dir("oversize_raised");
    let policy = write_policy(dir.path(), WIRE_POLICY);
    let audit_log = common::next_audit_log_path();
    let mut child = spawn_guard_with_args(
        &policy,
        false,
        &["--max-frame-bytes", "4194304"],
        common::scripted_stdio_argv("big_reply"),
        &audit_log,
    );
    let mut stdin = child.stdin.take().expect("stdin");
    let stdout = child.stdout.take().expect("stdout");
    let _guard = ChildGuard(child);
    let mut reader = BufReader::new(stdout).lines();
    handshake_2025(&mut stdin, &mut reader).await;

    let resp = send_and_recv(&mut stdin, &mut reader, &call("read_file", 45)).await;
    assert!(
        has_result(&resp) && resp.len() > 2 * 1024 * 1024,
        "the ~2 MiB result must forward intact under the raised cap"
    );
    assert_eq!(json_id(&resp).as_deref(), Some("45"));
}

/// A >cap client→server request never reaches the server — the client
/// gets a JSON-RPC error on its own id, the refusal audits as
/// `frame-too-large`, and the next request completes.
#[tokio::test]
async fn oversized_request_is_denied_and_never_forwarded() {
    let dir = make_test_dir("oversize_c2s");
    let policy = write_policy(dir.path(), WIRE_POLICY);
    let audit_log = common::next_audit_log_path();
    let mut child = spawn_guard_with_args(
        &policy,
        false,
        SMALL_CAP,
        common::scripted_stdio_argv("tools_call_ok"),
        &audit_log,
    );
    let mut stdin = child.stdin.take().expect("stdin");
    let stdout = child.stdout.take().expect("stdout");
    let _guard = ChildGuard(child);
    let mut reader = BufReader::new(stdout).lines();
    handshake_2025(&mut stdin, &mut reader).await;

    let big_req = format!(
        r#"{{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{{"name":"read_file","arguments":{{"path":"{}"}}}}}}"#,
        pad()
    );
    let err = send_and_recv(&mut stdin, &mut reader, &big_req).await;
    assert!(has_error(&err), "oversized request must error: {err}");
    assert_eq!(json_id(&err).as_deref(), Some("9"), "got: {err}");
    // An error proves non-forwarding: the fixture would have answered a
    // result had the frame reached it.
    assert!(
        error_message(&err).contains("frame-too-large"),
        "got: {err}"
    );

    let ok = send_and_recv(&mut stdin, &mut reader, &call("read_file", 10)).await;
    assert!(
        has_result(&ok) && json_id(&ok).as_deref() == Some("10"),
        "the request after the refusal must complete: {ok}"
    );

    let audit = wait_audit_contains(&audit_log, "frame-too-large");
    assert!(
        audit_lines(&audit, "mcp_message.denied")
            .iter()
            .any(|l| l.contains("dir=c2s") && l.contains("frame-too-large")),
        "c2s frame-too-large denial must be audited:\n{audit}"
    );
    assert!(
        !audit
            .lines()
            .any(|l| l.contains("forwarded=true") && l.contains(r#""request_id":"9""#)),
        "the oversized request must never have been forwarded:\n{audit}"
    );
}

/// An oversized client *notification* is dropped without a reply — a
/// notification is never owed one — and the next request still works.
#[tokio::test]
async fn oversized_notification_dropped_without_client_error() {
    let dir = make_test_dir("oversize_notif");
    let policy = write_policy(dir.path(), WIRE_POLICY);
    let audit_log = common::next_audit_log_path();
    let mut child = spawn_guard_with_args(
        &policy,
        false,
        SMALL_CAP,
        common::scripted_stdio_argv("tools_call_ok"),
        &audit_log,
    );
    let mut stdin = child.stdin.take().expect("stdin");
    let stdout = child.stdout.take().expect("stdout");
    let _guard = ChildGuard(child);
    let mut reader = BufReader::new(stdout).lines();
    handshake_2025(&mut stdin, &mut reader).await;

    send_notify(
        &mut stdin,
        &format!(
            r#"{{"jsonrpc":"2.0","method":"notifications/message","params":{{"level":"info","data":"{}"}}}}"#,
            pad()
        ),
    )
    .await;
    // The first frame back must be the ping's own result — an `id: null`
    // error here would mean the notification was wrongly answered.
    let pong = send_and_recv(
        &mut stdin,
        &mut reader,
        r#"{"jsonrpc":"2.0","id":7,"method":"ping"}"#,
    )
    .await;
    assert!(
        has_result(&pong) && json_id(&pong).as_deref() == Some("7"),
        "ping must answer, not a phantom error: {pong}"
    );

    let audit = wait_audit_contains(&audit_log, "frame-too-large");
    assert!(
        audit_lines(&audit, "mcp_message.denied")
            .iter()
            .any(|l| l.contains("notification") && l.contains("frame-too-large")),
        "the oversized notification must audit as a dropped frame:\n{audit}"
    );
}

/// An oversized response whose recovered id names no tracked request is
/// refused with `id: null` — the JSON-RPC convention for an
/// uncorrelatable error — and the call's real answer still completes it.
#[tokio::test]
async fn oversized_uncorrelated_response_errors_null_and_continues() {
    let dir = make_test_dir("oversize_ghost");
    let policy = write_policy(dir.path(), WIRE_POLICY);
    let audit_log = common::next_audit_log_path();
    let mut child = spawn_guard_with_args(
        &policy,
        false,
        SMALL_CAP,
        common::scripted_stdio_argv("big_reply_ghost"),
        &audit_log,
    );
    let mut stdin = child.stdin.take().expect("stdin");
    let stdout = child.stdout.take().expect("stdout");
    let _guard = ChildGuard(child);
    let mut reader = BufReader::new(stdout).lines();
    handshake_2025(&mut stdin, &mut reader).await;

    // The fixture emits the oversized ghost response first, then the
    // call's real result.
    stdin
        .write_all(format!("{}\n", call("read_file", 51)).as_bytes())
        .await
        .expect("write call");
    stdin.flush().await.expect("flush");
    let first = recv_jsonrpc(&mut reader).await;
    assert!(
        has_error(&first) && json_id(&first).as_deref() == Some("null"),
        "the uncorrelatable refusal must carry id null: {first}"
    );
    let second = recv_jsonrpc(&mut reader).await;
    assert!(
        has_result(&second) && json_id(&second).as_deref() == Some("51"),
        "the real response must still complete the call: {second}"
    );
}

/// An oversized client→server *response* to a server request resolves
/// the tracked entry the other way around: the server gets a JSON-RPC
/// error on the request's id so its request does not hang — and the
/// original call completes.
#[tokio::test]
async fn oversized_client_response_rejects_the_server_request() {
    let dir = make_test_dir("oversize_c2s_resp");
    let policy = write_policy(dir.path(), WIRE_POLICY);
    let audit_log = common::next_audit_log_path();
    let mut child = spawn_guard_with_args(
        &policy,
        false,
        SMALL_CAP,
        common::scripted_stdio_argv("s2c_ping_wait"),
        &audit_log,
    );
    let mut stdin = child.stdin.take().expect("stdin");
    let stdout = child.stdout.take().expect("stdout");
    let _guard = ChildGuard(child);
    let mut reader = BufReader::new(stdout).lines();
    handshake_2025(&mut stdin, &mut reader).await;

    stdin
        .write_all(format!("{}\n", call("read_file", 1)).as_bytes())
        .await
        .expect("write call");
    stdin.flush().await.expect("flush");
    let ping = recv_jsonrpc(&mut reader).await;
    assert_eq!(json_method(&ping).as_deref(), Some("ping"), "got: {ping}");
    assert_eq!(json_id(&ping).as_deref(), Some("\"srv-ping\""));

    // Answer the server request with a frame over the cap — it must be
    // refused, the server error'd on its own id, and the call completed.
    send_notify(
        &mut stdin,
        &format!(
            r#"{{"jsonrpc":"2.0","id":"srv-ping","result":{{"pad":"{}"}}}}"#,
            pad()
        ),
    )
    .await;
    let result = recv_jsonrpc(&mut reader).await;
    assert!(
        has_result(&result) && json_id(&result).as_deref() == Some("1"),
        "the original call must complete after the refused response: {result}"
    );

    let audit = wait_audit_contains(&audit_log, "frame-too-large");
    assert!(
        audit_lines(&audit, "mcp_message.denied")
            .iter()
            .any(|l| l.contains("dir=c2s")
                && l.contains("kind=response")
                && l.contains("frame-too-large")),
        "the oversized c2s response must audit as denied:\n{audit}"
    );
}

/// A client-facing tools/list refused on size unwinds the pending
/// listing and answers the client — the session continues. Runs under
/// `--fail-on none` so no internal verification probe beats the client
/// listing to the oversized response.
#[tokio::test]
async fn oversized_client_listing_errors_and_continues() {
    let dir = make_test_dir("oversize_list");
    let policy = write_policy(dir.path(), WIRE_POLICY);
    let audit_log = common::next_audit_log_path();
    let mut child = spawn_guard_with_args(
        &policy,
        false,
        &["--max-frame-bytes", "1048576", "--fail-on", "none"],
        common::scripted_stdio_argv("big_list"),
        &audit_log,
    );
    let mut stdin = child.stdin.take().expect("stdin");
    let stdout = child.stdout.take().expect("stdout");
    let _guard = ChildGuard(child);
    let mut reader = BufReader::new(stdout).lines();
    handshake_2025_init_only(&mut stdin, &mut reader).await;

    let err = send_and_recv(
        &mut stdin,
        &mut reader,
        r#"{"jsonrpc":"2.0","id":61,"method":"tools/list","params":{}}"#,
    )
    .await;
    assert!(has_error(&err), "oversized listing must error: {err}");
    assert_eq!(json_id(&err).as_deref(), Some("61"), "got: {err}");

    let ok = send_and_recv(&mut stdin, &mut reader, &call("read_file", 62)).await;
    assert!(
        has_result(&ok) && json_id(&ok).as_deref() == Some("62"),
        "the session must continue after the refused listing: {ok}"
    );
}

/// The Auditor's own internal tools/list answer refused on size can
/// never verify — the session fails closed: it aborts and the reason
/// lands in the audit log (the refused frame carries an internal id and
/// is never echoed to the client).
#[tokio::test]
async fn oversized_internal_listing_aborts_the_session() {
    let dir = make_test_dir("oversize_internal");
    let policy = write_policy(dir.path(), WIRE_POLICY);
    let audit_log = common::next_audit_log_path();
    let mut child = spawn_guard_with_args(
        &policy,
        false,
        SMALL_CAP,
        common::scripted_stdio_argv("big_list"),
        &audit_log,
    );
    let mut stdin = child.stdin.take().expect("stdin");
    let stdout = child.stdout.take().expect("stdout");
    let mut guard = ChildGuard(child);
    let mut reader = BufReader::new(stdout).lines();

    // initialize itself is a small frame and completes; the internal
    // verification probe's ~2 MiB answer is refused right after.
    let init = send_and_recv(&mut stdin, &mut reader, common::INIT_REQUEST).await;
    assert!(
        init.contains("\"protocolVersion\":\"2025-11-25\""),
        "initialize must complete: {init}"
    );

    // The internal answer's refusal aborts the session — stdout EOFs.
    let reached_eof = timeout(Duration::from_secs(TIMEOUT_SECS), async {
        loop {
            match reader.next_line().await {
                Ok(Some(_)) => continue,
                Ok(None) => return true,
                Err(_) => return true,
            }
        }
    })
    .await
    .unwrap_or(false);
    assert!(reached_eof, "the session must EOF after the abort");
    let status = timeout(Duration::from_secs(TIMEOUT_SECS), guard.0.wait())
        .await
        .expect("guard must exit")
        .expect("wait");
    assert!(!status.success(), "the aborted launch must fail: {status}");

    let audit = wait_audit_contains(&audit_log, "frame-too-large");
    assert!(
        audit.contains("__mcp_writ_internal__") || audit.contains("verification"),
        "the internal refusal must be visible in the audit log:\n{audit}"
    );
}
