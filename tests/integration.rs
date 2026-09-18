//! Integration tests for mcp-writ.
//!
//! Uses a stdin→stdout echo process as a mock MCP server (`cat` on Unix,
//! `py -3 tests/fixtures/echo_stdio.py` on Windows). The mcp-writ binary sits
//! between the test and that echo process, applying policy checks.
//!
//! Warden (Landlock/seccomp) is a no-op on macOS. On Linux, `policy.example.kdl`
//! installs a seccomp allowlist that is too tight for the guard process itself
//! (it cannot spawn the echo child / run tokio). These tests therefore set
//! `MCP_WRIT_SKIP_SANDBOX` and exercise only the Auditor path.

use std::process::Stdio;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::Command;
use tokio::time::{Duration, timeout};

mod common;

const TIMEOUT_SECS: u64 = 10;

/// Drop guard that ensures the child process is killed even if a test panics.
struct ChildGuard(tokio::process::Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.start_kill();
    }
}

fn policy_path() -> String {
    format!("{}/policy.example.kdl", env!("CARGO_MANIFEST_DIR"))
}

/// Helper: spawn the mcp-writ binary with optional dry-run flag.
fn spawn_guard_impl(dry_run: bool) -> tokio::process::Child {
    let policy = policy_path();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_mcp-writ"));

    let audit_log = common::next_audit_log_path();
    cmd.args([
        "run",
        "--transport",
        "stdio",
        "--policy",
        &policy,
        "--audit-log",
        audit_log.to_str().expect("audit log path is utf-8"),
    ]);

    if dry_run {
        cmd.arg("--dry-run");
    }

    cmd.arg("--");
    cmd.args(common::echo_stdio_argv())
        .env("MCP_WRIT_SKIP_SANDBOX", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect(if dry_run {
            "failed to spawn mcp-writ binary (dry-run) - did you run `cargo build`?"
        } else {
            "failed to spawn mcp-writ binary - did you run `cargo build`?"
        })
}

/// Spawn the mcp-writ binary with `cat` as the child MCP server.
/// Returns the child process with piped stdin/stdout.
fn spawn_guard() -> tokio::process::Child {
    spawn_guard_impl(false)
}

/// Spawn the mcp-writ binary with `--dry-run` and `cat` as the child MCP server.
fn spawn_guard_dry_run() -> tokio::process::Child {
    spawn_guard_impl(true)
}

/// Helper: send a JSON line and read the next JSON-RPC response line.
/// Skips non-JSON-RPC lines (tracing logs, etc.) that may appear on stdout.
///
/// Uses `starts_with("{\"jsonrpc\"")` rather than just `starts_with('{')` to
/// avoid false positives from structured tracing output that may be valid JSON
/// but is not a JSON-RPC message.
async fn send_and_recv(
    stdin: &mut tokio::process::ChildStdin,
    reader: &mut tokio::io::Lines<BufReader<tokio::process::ChildStdout>>,
    request: &str,
) -> String {
    stdin
        .write_all(format!("{request}\n").as_bytes())
        .await
        .expect("failed to write request to mcp-writ stdin");
    stdin.flush().await.expect("failed to flush mcp-writ stdin");

    // Read lines until we get a JSON-RPC response (starts with {"jsonrpc").
    // This defensively skips any non-JSON-RPC output such as tracing log lines.
    timeout(Duration::from_secs(TIMEOUT_SECS), async {
        loop {
            let line = reader
                .next_line()
                .await
                .expect("IO error reading mcp-writ stdout")
                .expect("unexpected EOF on mcp-writ stdout - child process may have exited");
            if line.starts_with("{\"jsonrpc\"") {
                return line;
            }
        }
    })
    .await
    .expect("timeout waiting for JSON-RPC response from mcp-writ")
}

// ─── Allowed tool: should pass through (echoed by cat) ───

#[tokio::test]
async fn test_client_eof_closes_server_stdin_and_exits_cleanly() {
    let mut child = ChildGuard(spawn_guard());
    let mut stdin = child.0.stdin.take().expect("stdin should be piped");
    let stdout = child.0.stdout.take().expect("stdout should be piped");
    let mut reader = BufReader::new(stdout).lines();
    let request = r#"{"jsonrpc":"2.0","id":1,"method":"ping","params":{}}"#;
    assert_eq!(
        send_and_recv(&mut stdin, &mut reader, request).await,
        request
    );
    drop(stdin);
    let status = timeout(Duration::from_secs(TIMEOUT_SECS), child.0.wait())
        .await
        .expect("client EOF must not deadlock while S2C owns a stdin reference")
        .expect("wait for guard");
    assert!(status.success(), "unexpected exit: {status}");
}

#[tokio::test]
async fn test_allowed_tool_passes_through() {
    let mut child = spawn_guard();
    let mut stdin = child.stdin.take().expect("stdin should be piped");
    let stdout = child.stdout.take().expect("stdout should be piped");
    let _guard = ChildGuard(child);
    let mut reader = BufReader::new(stdout).lines();

    // read_file is allowed in policy.example.kdl
    let request = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/workspace/test.txt"}}}"#;
    let response = send_and_recv(&mut stdin, &mut reader, request).await;

    // cat echoes the exact same line back
    assert_eq!(response, request);

    drop(stdin);
}

// ─── Denied tool: should be blocked with JSON-RPC error ───

#[tokio::test]
async fn test_denied_tool_blocked() {
    let mut child = spawn_guard();
    let mut stdin = child.stdin.take().expect("stdin should be piped");
    let stdout = child.stdout.take().expect("stdout should be piped");
    let _guard = ChildGuard(child);
    let mut reader = BufReader::new(stdout).lines();

    // exec_shell is denied in policy.example.kdl
    let request = r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"exec_shell","arguments":{"cmd":"rm -rf /"}}}"#;
    let response = send_and_recv(&mut stdin, &mut reader, request).await;

    // Should be an error response, not the original request
    assert_ne!(response, request);

    // Verify JSON-RPC error structure
    let json = nojson::RawJson::parse(&response).expect("response should be valid JSON");
    let error = json
        .value()
        .to_member("error")
        .expect("should have error field")
        .optional()
        .expect("error should be present");

    let code = error
        .to_member("code")
        .expect("error.code")
        .required()
        .expect("code required")
        .as_raw_str();
    assert_eq!(code, "-32001");

    let msg = json
        .value()
        .to_member("error")
        .expect("response should have 'error' field")
        .required()
        .expect("'error' field should be present")
        .to_member("message")
        .expect("error should have 'message' field")
        .required()
        .expect("'message' field should be present")
        .as_string_str()
        .expect("error message should be a string");
    assert!(
        msg.contains("exec_shell"),
        "error message should mention the tool name"
    );

    // Verify the response id matches the request id
    let id = json
        .value()
        .to_member("id")
        .expect("response should have 'id' field")
        .required()
        .expect("'id' field should be present")
        .as_raw_str();
    assert_eq!(id, "2");

    drop(stdin);
}

// ─── Unknown tool: should also be blocked (fail-secure default deny) ───

#[tokio::test]
async fn test_unknown_tool_blocked() {
    let mut child = spawn_guard();
    let mut stdin = child.stdin.take().expect("stdin should be piped");
    let stdout = child.stdout.take().expect("stdout should be piped");
    let _guard = ChildGuard(child);
    let mut reader = BufReader::new(stdout).lines();

    // "delete_everything" is not in the policy at all
    let request = r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"delete_everything","arguments":{}}}"#;
    let response = send_and_recv(&mut stdin, &mut reader, request).await;

    let json = nojson::RawJson::parse(&response).expect("valid JSON");
    let has_error = json
        .value()
        .to_member("error")
        .ok()
        .and_then(|m| m.optional())
        .is_some();
    assert!(has_error, "unknown tool should be blocked");

    let msg = json
        .value()
        .to_member("error")
        .expect("response should have 'error' field")
        .required()
        .expect("'error' field should be present")
        .to_member("message")
        .expect("error should have 'message' field")
        .required()
        .expect("'message' field should be present")
        .as_string_str()
        .expect("error message should be a string");
    assert!(msg.contains("delete_everything"));

    drop(stdin);
}

// ─── Non-tools/call: should pass through transparently ───

#[tokio::test]
async fn test_non_tools_call_passes_through() {
    let mut child = spawn_guard();
    let mut stdin = child.stdin.take().expect("stdin should be piped");
    let stdout = child.stdout.take().expect("stdout should be piped");
    let _guard = ChildGuard(child);
    let mut reader = BufReader::new(stdout).lines();

    // initialize is not tools/call; tools/list is reserved and validated on return
    let request = r#"{"jsonrpc":"2.0","id":4,"method":"initialize","params":{}}"#;
    let response = send_and_recv(&mut stdin, &mut reader, request).await;

    // cat echoes unchanged
    assert_eq!(response, request);

    drop(stdin);
}

// ─── Multiple sequential requests in a single session ───

#[tokio::test]
async fn test_multiple_requests_same_session() {
    let mut child = spawn_guard();
    let mut stdin = child.stdin.take().expect("stdin should be piped");
    let stdout = child.stdout.take().expect("stdout should be piped");
    let _guard = ChildGuard(child);
    let mut reader = BufReader::new(stdout).lines();

    // 1. Allowed tool → pass through
    let req1 = r#"{"jsonrpc":"2.0","id":10,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/workspace/test.txt"}}}"#;
    let resp1 = send_and_recv(&mut stdin, &mut reader, req1).await;
    assert_eq!(resp1, req1);

    // 2. Denied tool → error response
    let req2 = r#"{"jsonrpc":"2.0","id":11,"method":"tools/call","params":{"name":"exec_shell","arguments":{}}}"#;
    let resp2 = send_and_recv(&mut stdin, &mut reader, req2).await;
    assert!(resp2.contains("error"));
    assert!(resp2.contains("exec_shell"));

    // 3. Another allowed tool → pass through (session still works)
    let req3 = r#"{"jsonrpc":"2.0","id":12,"method":"tools/call","params":{"name":"write_file","arguments":{"path":"/workspace/output/out.txt"}}}"#;
    let resp3 = send_and_recv(&mut stdin, &mut reader, req3).await;
    assert_eq!(resp3, req3);

    // 4. Non-JSON-RPC → pass through
    let req4 = r#"{"jsonrpc":"2.0","id":13,"method":"initialize","params":{}}"#;
    let resp4 = send_and_recv(&mut stdin, &mut reader, req4).await;
    assert_eq!(resp4, req4);

    drop(stdin);
}

// ─── Dry-run: denied tool should NOT be blocked (forwarded to server) ───

#[tokio::test]
async fn test_dry_run_allows_denied_tool() {
    let mut child = spawn_guard_dry_run();
    let mut stdin = child.stdin.take().expect("stdin should be piped");
    let stdout = child.stdout.take().expect("stdout should be piped");
    let _guard = ChildGuard(child);
    let mut reader = BufReader::new(stdout).lines();

    // exec_shell is denied in policy.example.kdl, but --dry-run should forward it
    let request = r#"{"jsonrpc":"2.0","id":20,"method":"tools/call","params":{"name":"exec_shell","arguments":{"cmd":"rm -rf /"}}}"#;
    let response = send_and_recv(&mut stdin, &mut reader, request).await;

    // In dry-run mode, cat echoes the original request back (no error response)
    assert_eq!(
        response, request,
        "dry-run should forward denied tool to server"
    );

    // Verify there is NO error field
    let json = nojson::RawJson::parse(&response).expect("valid JSON");
    let has_error = json
        .value()
        .to_member("error")
        .ok()
        .and_then(|m| m.optional())
        .is_some();
    assert!(!has_error, "dry-run should not produce error response");

    drop(stdin);
}

// ─── Dry-run: unknown tool should also pass through ───

#[tokio::test]
async fn test_dry_run_allows_unknown_tool() {
    let mut child = spawn_guard_dry_run();
    let mut stdin = child.stdin.take().expect("stdin should be piped");
    let stdout = child.stdout.take().expect("stdout should be piped");
    let _guard = ChildGuard(child);
    let mut reader = BufReader::new(stdout).lines();

    // Unknown tool: normally blocked by default-deny, but dry-run forwards it
    let request = r#"{"jsonrpc":"2.0","id":21,"method":"tools/call","params":{"name":"delete_everything","arguments":{}}}"#;
    let response = send_and_recv(&mut stdin, &mut reader, request).await;

    assert_eq!(
        response, request,
        "dry-run should forward unknown tool to server"
    );

    drop(stdin);
}

// ─── Dry-run: allowed tool should still pass through normally ───

#[tokio::test]
async fn test_dry_run_allowed_tool_still_passes() {
    let mut child = spawn_guard_dry_run();
    let mut stdin = child.stdin.take().expect("stdin should be piped");
    let stdout = child.stdout.take().expect("stdout should be piped");
    let _guard = ChildGuard(child);
    let mut reader = BufReader::new(stdout).lines();

    // read_file is allowed — should work identically in dry-run
    let request = r#"{"jsonrpc":"2.0","id":22,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/workspace/test.txt"}}}"#;
    let response = send_and_recv(&mut stdin, &mut reader, request).await;

    assert_eq!(response, request);

    drop(stdin);
}

fn mrtr_fixture(name: &str) -> String {
    let path = format!("{}/tests/fixtures/mrtr/{name}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("fixture {name}: {e}"))
        .trim()
        .to_string()
}

// ─── MRTR retry still hits allowlist; input_required passthrough ───

#[tokio::test]
async fn test_mrtr_retry_denied_tool_still_blocked() {
    let mut child = spawn_guard();
    let mut stdin = child.stdin.take().expect("stdin should be piped");
    let stdout = child.stdout.take().expect("stdout should be piped");
    let _guard = ChildGuard(child);
    let mut reader = BufReader::new(stdout).lines();

    let request = mrtr_fixture("retry_denied_tool.json");
    let response = send_and_recv(&mut stdin, &mut reader, &request).await;

    let json = nojson::RawJson::parse(&response).expect("valid JSON");
    let error = json
        .value()
        .to_member("error")
        .expect("should have error field")
        .optional()
        .expect("error should be present");
    let code = error
        .to_member("code")
        .expect("error.code")
        .required()
        .expect("code required")
        .as_raw_str();
    assert_eq!(code, "-32001");
    assert!(response.contains("exec_shell"));

    drop(stdin);
}

#[tokio::test]
async fn test_input_required_result_passthrough() {
    let mut child = spawn_guard();
    let mut stdin = child.stdin.take().expect("stdin should be piped");
    let stdout = child.stdout.take().expect("stdout should be piped");
    let _guard = ChildGuard(child);
    let mut reader = BufReader::new(stdout).lines();

    // Not tools/call: C2S passthrough → cat echoes → S2C must not rewrite to -32001.
    let request = mrtr_fixture("input_required_result.json");
    let response = send_and_recv(&mut stdin, &mut reader, &request).await;
    assert_eq!(response, request);
    assert!(response.contains("\"resultType\":\"input_required\""));
    assert!(!response.contains("-32001"));

    drop(stdin);
}

#[tokio::test]
async fn test_mcp_2026_07_28_tools_call_with_meta_allowed_passthrough() {
    let mut child = spawn_guard();
    let mut stdin = child.stdin.take().expect("stdin should be piped");
    let stdout = child.stdout.take().expect("stdout should be piped");
    let _guard = ChildGuard(child);
    let mut reader = BufReader::new(stdout).lines();

    // read_file has a filesystem contract in policy.example.kdl, so Auto denies
    // MRTR inputResponses unless the tool opts in.
    let request = mrtr_fixture("mcp_2026_07_28_tools_call_retry.json");
    let response = send_and_recv(&mut stdin, &mut reader, &request).await;
    assert_ne!(response, request);
    assert!(response.contains("inputResponses"), "got: {response}");
    assert!(response.contains("-32001"), "got: {response}");

    // MCP 2026-07-28 _meta + requestState without inputResponses still pass through.
    let passthrough = r#"{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/workspace/test.txt"},"requestState":"eyJsb2NhdGlvbiI6Ik5ldyBZb3JrIn0","_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}}"#;
    let echoed = send_and_recv(&mut stdin, &mut reader, passthrough).await;
    assert_eq!(echoed, passthrough);

    drop(stdin);
}
