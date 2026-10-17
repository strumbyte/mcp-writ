//! PR-23: an `initialize` result negotiating a protocol revision
//! mcp-writ does not implement is diagnosed identically on all three
//! surfaces — the client JSON-RPC error, a one-line stderr diagnostic,
//! and the `mcp_message.denied` audit record (`revision=` is the judged
//! wire revision; `server_protocol_version=` records the version the
//! server actually returned). The denial stays per-request: the session
//! is not aborted, so a retry may renegotiate.

use tokio::io::{AsyncBufReadExt, BufReader};

use crate::common;
use crate::support::*;

/// Assert the negotiated + supported revisions on all three surfaces for
/// a denied initialize whose server returned `server_version`.
async fn assert_three_surface_diagnosis(
    err: &str,
    err_reader: &mut tokio::io::Lines<BufReader<tokio::process::ChildStderr>>,
    audit_log: &std::path::Path,
    server_version: &str,
) {
    // 1. Client-facing JSON-RPC error: reason code + negotiated + the
    //    versions an `initialize` result may negotiate — `2025-11-25`
    //    only; `2026-07-28` is never acceptable here and must not be
    //    presented as supported.
    assert!(
        has_error(err),
        "unsupported negotiated version must error: {err}"
    );
    let msg = error_message(err);
    for needle in ["unsupported-version", server_version, "2025-11-25"] {
        assert!(msg.contains(needle), "client error missing {needle}: {msg}");
    }
    assert!(
        !msg.contains("2026-07-28"),
        "2026-07-28 is not negotiable via initialize: {msg}"
    );

    // 2. stderr: the same negotiated/supported pair on one diagnostic line.
    let line = stderr_line_containing(err_reader, "unsupported protocol version").await;
    for needle in [server_version, "2025-11-25"] {
        assert!(
            line.contains(needle),
            "stderr line missing {needle}: {line}"
        );
    }
    assert!(
        !line.contains("2026-07-28"),
        "stderr line must not present 2026-07-28 as supported: {line}"
    );

    // 3. Audit: denied response carrying the server-returned version and
    //    the judged wire revision under the unambiguous `revision=` key —
    //    `supported=` lists the initialize-negotiable set only.
    let audit = wait_audit_contains(audit_log, "unsupported-version");
    let denied = audit_lines(&audit, "mcp_message.denied");
    assert!(
        denied.iter().any(|l| l.contains("dir=s2c")
            && l.contains("kind=response")
            && l.contains("reason=unsupported-version")
            && l.contains("forwarded=false")
            && l.contains(&format!("server_protocol_version={server_version}"))
            && l.contains("supported=2025-11-25")
            && l.contains("revision=2025-11-25")),
        "unsupported-version denial must be audited:\n{audit}"
    );
}

/// The server answers `initialize` with `protocolVersion: "2025-06-18"`
/// even though the client asked for 2025-11-25. The response is denied,
/// all three surfaces name the negotiated and supported revisions, and
/// the session stays open — a retried `initialize` is admitted and
/// denied again on the same pin rather than wedging or aborting.
#[tokio::test]
async fn server_negotiating_old_version_is_diagnosed_and_session_continues() {
    let dir = make_test_dir("ver_s2c");
    let policy = write_policy(dir.path(), WIRE_POLICY);
    let audit_log = common::next_audit_log_path();
    let mut child = spawn_guard(
        &policy,
        false,
        common::scripted_stdio_argv_versioned("tools_call_ok", "2025-06-18"),
        &audit_log,
    );
    let mut stdin = child.stdin.take().expect("stdin");
    let stdout = child.stdout.take().expect("stdout");
    let stderr = child.stderr.take().expect("stderr");
    let _guard = ChildGuard(child);
    let mut reader = BufReader::new(stdout).lines();
    let mut err_reader = BufReader::new(stderr).lines();

    let err = send_and_recv(&mut stdin, &mut reader, common::INIT_REQUEST).await;
    assert_eq!(json_id(&err).as_deref(), Some("\"init\""), "got: {err}");
    assert_three_surface_diagnosis(&err, &mut err_reader, &audit_log, "2025-06-18").await;

    // Session is not aborted: a retried initialize is forwarded and
    // denied on the same pin — the failure is repeatable, not terminal.
    let retry = send_and_recv(&mut stdin, &mut reader, common::INIT_REQUEST).await;
    assert!(
        has_error(&retry) && error_message(&retry).contains("unsupported-version"),
        "retried initialize must be rejected the same way: {retry}"
    );
    // The audit writer lags the wire — poll until both denials commit.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(TIMEOUT_SECS);
    loop {
        let audit = read_audit(&audit_log);
        if audit_lines(&audit, "mcp_message.denied")
            .iter()
            .filter(|l| l.contains("reason=unsupported-version"))
            .count()
            >= 2
        {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "each denied negotiation must audit:\n{audit}"
        );
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
}

/// The client requests `initialize` with `protocolVersion: "2025-06-18"`
/// and the fixture echoes it (`--protocol-version=echo`), simulating a
/// server that honours the client's old-version ask. The negotiated
/// answer is unsupported → the same three-surface diagnosis; a `ping`
/// afterwards proves the session continued.
#[tokio::test]
async fn client_requesting_old_version_is_diagnosed_and_session_continues() {
    let dir = make_test_dir("ver_c2s");
    let policy = write_policy(dir.path(), WIRE_POLICY);
    let audit_log = common::next_audit_log_path();
    let mut child = spawn_guard(
        &policy,
        false,
        common::scripted_stdio_argv_versioned("tools_call_ok", "echo"),
        &audit_log,
    );
    let mut stdin = child.stdin.take().expect("stdin");
    let stdout = child.stdout.take().expect("stdout");
    let stderr = child.stderr.take().expect("stderr");
    let _guard = ChildGuard(child);
    let mut reader = BufReader::new(stdout).lines();
    let mut err_reader = BufReader::new(stderr).lines();

    let init_old = r#"{"jsonrpc":"2.0","id":"init","method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"e2e-test","version":"0"}}}"#;
    let err = send_and_recv(&mut stdin, &mut reader, init_old).await;
    assert_eq!(json_id(&err).as_deref(), Some("\"init\""), "got: {err}");
    assert_three_surface_diagnosis(&err, &mut err_reader, &audit_log, "2025-06-18").await;

    // `ping` is admitted at every 2025 init stage — a result proves the
    // session kept running after the failed negotiation.
    let pong = send_and_recv(
        &mut stdin,
        &mut reader,
        r#"{"jsonrpc":"2.0","id":7,"method":"ping"}"#,
    )
    .await;
    assert!(has_result(&pong), "ping after the denial must pass: {pong}");
}
