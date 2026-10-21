//! End-to-end integration tests for KDL policy features.
//!
//! These tests exercise the full mcp-writ binary with custom KDL policy files,
//! verifying tool allow/deny, policy merge (defaults →
//! server-defaults → tool), extends/include/when directives, and dry-run mode.
//!
//! Each test creates temporary KDL policy files and spawns the mcp-writ binary
//! with a stdio echo process as a mock MCP server (same pattern as
//! `tests/integration.rs`). `MCP_WRIT_SKIP_SANDBOX` is set so Linux
//! Landlock/seccomp does not kill the guard+echo process (these tests cover
//! Auditor/policy, not Warden).

use std::path::{Path, PathBuf};
use std::process::Stdio;
use tempfile::TempDir;
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
        // Reap the child process to avoid zombies. try_wait() is synchronous,
        // unlike wait() which is async and unusable in Drop.
        for _ in 0..20 {
            match self.0.try_wait() {
                Ok(Some(_)) => return,
                Ok(None) => std::thread::sleep(std::time::Duration::from_millis(50)),
                Err(_) => return,
            }
        }
    }
}

/// Create a unique temp directory under /tmp for test isolation.
/// Returns a TempDir that automatically deletes the directory when dropped.
fn make_test_dir(label: &str) -> TempDir {
    tempfile::Builder::new()
        .prefix(&format!("mcp_writ_e2e_{}_", label))
        .tempdir()
        .expect("failed to create temp directory")
}

/// Write a KDL policy string to a file in the given directory.
fn write_policy(dir: &Path, name: &str, content: &str) -> PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, content).unwrap();
    path
}

/// Every tool name the policies in this file may legitimately call —
/// advertised by the fixture so the verified tools/list gate admits
/// them. Unknown-tool tests use names outside this set.
const KDL_FIXTURE_TOOLS: &str = "allowed_tool,another_safe,blocked_tool,dangerous_tool,\
debug_tool,exec,fetch_url,fail_write,my_read,only_this_tool,read_file,safe_tool,search,\
search_repos,tool_a,tool_b,write_file";

/// Spawn mcp-writ with a custom policy file and optional dry-run flag.
fn spawn_guard_with_policy(policy_path: &Path, dry_run: bool) -> tokio::process::Child {
    spawn_guard_with_options(policy_path, dry_run, None, &[])
}

fn spawn_guard_with_policy_env(
    policy_path: &Path,
    dry_run: bool,
    envs: &[(&str, &str)],
) -> tokio::process::Child {
    spawn_guard_with_options(policy_path, dry_run, None, envs)
}

fn spawn_guard_with_server(policy_path: &Path, server: &str) -> tokio::process::Child {
    spawn_guard_with_options(policy_path, false, Some(server), &[])
}

fn spawn_guard_with_options(
    policy_path: &Path,
    dry_run: bool,
    server: Option<&str>,
    envs: &[(&str, &str)],
) -> tokio::process::Child {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_mcp-writ"));
    let audit_log = common::next_audit_log_path();

    cmd.args([
        "run",
        "--transport",
        "stdio",
        "--policy",
        policy_path.to_str().unwrap(),
        "--audit-log",
        audit_log.to_str().expect("audit log path is utf-8"),
    ]);

    if let Some(name) = server {
        cmd.args(["--server", name]);
    }

    if dry_run {
        cmd.arg("--dry-run");
    }

    for (key, val) in envs {
        cmd.env(key, val);
    }

    cmd.arg("--");
    // The Auditor admits tools/call only for names the verified
    // tools/list advertised — the fixture must actually advertise the
    // arbitrary names these policies declare, so the union of every
    // tool name exercised here is added to the fixture's set.
    let mut argv = common::scripted_stdio_argv("tools_call_ok");
    argv.push(format!("--advertise-tools={KDL_FIXTURE_TOOLS}"));
    cmd.args(argv)
        .env("MCP_WRIT_SKIP_SANDBOX", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn mcp-writ binary")
}

/// Send a JSON line and read the next JSON-RPC response line.
/// Skips non-JSON-RPC lines (tracing logs, etc.).
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
    .expect("timeout waiting for JSON-RPC response from mcp-writ")
}

/// 2025-11-25 handshake — the wire layer denies ordinary requests before
/// `notifications/initialized` forwards. Also publishes a verified
/// `tools/list`: the generation gate denies `tools/call` until a client
/// listing has completed, so the call assertions below need it in-band.
async fn handshake_2025(
    stdin: &mut tokio::process::ChildStdin,
    reader: &mut tokio::io::Lines<BufReader<tokio::process::ChildStdout>>,
) {
    let response = send_and_recv(stdin, reader, common::INIT_REQUEST).await;
    assert!(
        response.contains("\"protocolVersion\":\"2025-11-25\""),
        "initialize must complete: {response}"
    );
    stdin
        .write_all(format!("{}\n", common::INITIALIZED_NOTIF).as_bytes())
        .await
        .expect("write initialized");
    stdin.flush().await.expect("flush initialized");
    let list = send_and_recv(
        stdin,
        reader,
        r#"{"jsonrpc":"2.0","id":"hs-list","method":"tools/list","params":{}}"#,
    )
    .await;
    assert!(
        has_result(&list),
        "handshake tools/list must verify and emit: {list}"
    );
}

/// `{"result": ...}` present on the line.
fn has_result(response: &str) -> bool {
    nojson::RawJson::parse(response)
        .ok()
        .and_then(|json| {
            json.value()
                .to_member("result")
                .ok()
                .and_then(|m| m.optional().map(|_| ()))
        })
        .is_some()
}

// ═══════════════════════════════════════════════════════════════════
// 1. KDL policy file: tool allow/deny via run command
// ═══════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_custom_kdl_policy_allowed_tool() {
    let dir = make_test_dir("allowed_tool");
    let policy = write_policy(
        dir.path(),
        "policy.kdl",
        r#"
            policy version=1
            server "test" {
                tool "my_read"
            }
        "#,
    );

    let mut child = spawn_guard_with_policy(&policy, false);
    let mut stdin = child.stdin.take().unwrap();
    let stdout = child.stdout.take().unwrap();
    let _guard = ChildGuard(child);
    let mut reader = BufReader::new(stdout).lines();
    handshake_2025(&mut stdin, &mut reader).await;

    let request = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"my_read","arguments":{}}}"#;
    let response = send_and_recv(&mut stdin, &mut reader, request).await;
    assert!(
        has_result(&response),
        "allowed tool should pass through: {response}"
    );

    drop(stdin);
}

#[tokio::test]
async fn test_custom_kdl_policy_denied_tool() {
    let dir = make_test_dir("denied_tool");
    let policy = write_policy(
        dir.path(),
        "policy.kdl",
        r#"
            policy version=1
            server "test" {
                tool "allowed_tool"
                tool "blocked_tool" deny=#true
            }
        "#,
    );

    let mut child = spawn_guard_with_policy(&policy, false);
    let mut stdin = child.stdin.take().unwrap();
    let stdout = child.stdout.take().unwrap();
    let _guard = ChildGuard(child);
    let mut reader = BufReader::new(stdout).lines();
    handshake_2025(&mut stdin, &mut reader).await;

    let request = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"blocked_tool","arguments":{}}}"#;
    let response = send_and_recv(&mut stdin, &mut reader, request).await;
    assert_ne!(response, request, "denied tool should be blocked");

    let json = nojson::RawJson::parse(&response).expect("valid JSON");
    let has_error = json
        .value()
        .to_member("error")
        .ok()
        .and_then(|m| m.optional())
        .is_some();
    assert!(has_error, "response should contain error field");

    let msg = json
        .value()
        .to_member("error")
        .unwrap()
        .required()
        .unwrap()
        .to_member("message")
        .unwrap()
        .required()
        .unwrap()
        .as_string_str()
        .unwrap();
    assert!(
        msg.contains("blocked_tool"),
        "error should mention tool name"
    );

    drop(stdin);
}

#[tokio::test]
async fn test_custom_kdl_policy_unknown_tool_default_deny() {
    let dir = make_test_dir("unknown_tool");
    let policy = write_policy(
        dir.path(),
        "policy.kdl",
        r#"
            policy version=1
            server "test" {
                tool "only_this_tool"
            }
        "#,
    );

    let mut child = spawn_guard_with_policy(&policy, false);
    let mut stdin = child.stdin.take().unwrap();
    let stdout = child.stdout.take().unwrap();
    let _guard = ChildGuard(child);
    let mut reader = BufReader::new(stdout).lines();
    handshake_2025(&mut stdin, &mut reader).await;

    // Tool not in policy → default deny
    let request = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"unknown_tool","arguments":{}}}"#;
    let response = send_and_recv(&mut stdin, &mut reader, request).await;
    let json = nojson::RawJson::parse(&response).unwrap();
    let has_error = json
        .value()
        .to_member("error")
        .ok()
        .and_then(|m| m.optional())
        .is_some();
    assert!(has_error, "unknown tool should be blocked by default deny");

    drop(stdin);
}

// ═══════════════════════════════════════════════════════════════════
// 2. Tool-level sub-policies (fs allow/deny)
// ═══════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_tool_fs_sub_policy_allowed_path() {
    let dir = make_test_dir("fs_allowed");
    let policy = write_policy(
        dir.path(),
        "policy.kdl",
        r#"
            policy version=1
            server "fs" {
                tool "read_file" {
                    filesystem {
                        allow "/workspace/**"
                    }
                }
            }
        "#,
    );

    // `/workspace/**` resolves against the current drive's root — a
    // broadly-writable root (default ACLs on secondary data drives) is
    // refused as replaceable, which is host-ACL dependent and not what
    // this test exercises.
    let mut child =
        spawn_guard_with_policy_env(&policy, false, &[("MCP_WRIT_ALLOW_REPLACEABLE_PATHS", "1")]);
    let mut stdin = child.stdin.take().unwrap();
    let stdout = child.stdout.take().unwrap();
    let _guard = ChildGuard(child);
    let mut reader = BufReader::new(stdout).lines();
    handshake_2025(&mut stdin, &mut reader).await;

    let request = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/workspace/test.txt"}}}"#;
    let response = send_and_recv(&mut stdin, &mut reader, request).await;
    assert!(
        has_result(&response),
        "path within allowed should pass through: {response}"
    );

    drop(stdin);
}

#[tokio::test]
async fn test_tool_fs_sub_policy_denied_path() {
    let dir = make_test_dir("fs_denied");
    let policy = write_policy(
        dir.path(),
        "policy.kdl",
        r#"
            policy version=1
            server "fs" {
                tool "read_file" {
                    filesystem {
                        allow "/workspace/**"
                        deny "/etc/**"
                    }
                }
            }
        "#,
    );

    let mut child = spawn_guard_with_policy(&policy, false);
    let mut stdin = child.stdin.take().unwrap();
    let stdout = child.stdout.take().unwrap();
    let _guard = ChildGuard(child);
    let mut reader = BufReader::new(stdout).lines();
    handshake_2025(&mut stdin, &mut reader).await;

    let request = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/etc/secrets/key.pem"}}}"#;
    let response = send_and_recv(&mut stdin, &mut reader, request).await;
    let json = nojson::RawJson::parse(&response).unwrap();
    let has_error = json
        .value()
        .to_member("error")
        .ok()
        .and_then(|m| m.optional())
        .is_some();
    assert!(has_error, "denied path should produce error");

    drop(stdin);
}

#[tokio::test]
async fn test_tool_network_sub_policy_denied_host() {
    let dir = make_test_dir("net_denied");
    let policy = write_policy(
        dir.path(),
        "policy.kdl",
        r#"
            policy version=1
            server "api" {
                tool "fetch_url" {
                    network {
                        allow host="api.example.com"
                        deny host="evil.com"
                    }
                }
            }
        "#,
    );

    let mut child = spawn_guard_with_policy(&policy, false);
    let mut stdin = child.stdin.take().unwrap();
    let stdout = child.stdout.take().unwrap();
    let _guard = ChildGuard(child);
    let mut reader = BufReader::new(stdout).lines();
    handshake_2025(&mut stdin, &mut reader).await;

    let request = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"fetch_url","arguments":{"url":"https://evil.com/steal"}}}"#;
    let response = send_and_recv(&mut stdin, &mut reader, request).await;
    let json = nojson::RawJson::parse(&response).unwrap();
    let has_error = json
        .value()
        .to_member("error")
        .ok()
        .and_then(|m| m.optional())
        .is_some();
    assert!(has_error, "denied host should produce error");

    drop(stdin);
}

#[tokio::test]
async fn test_tool_network_sub_policy_denied_cidr() {
    // IP-layer rule: a literal-IP destination inside `deny cidr` is
    // refused by the auditor — the entry needs no name resolution.
    let dir = make_test_dir("net_denied_cidr");
    let policy = write_policy(
        dir.path(),
        "policy.kdl",
        r#"
            policy version=1
            server "api" {
                tool "fetch_url" {
                    network {
                        deny cidr="169.254.0.0/16"
                    }
                }
            }
        "#,
    );

    let mut child = spawn_guard_with_policy(&policy, false);
    let mut stdin = child.stdin.take().unwrap();
    let stdout = child.stdout.take().unwrap();
    let _guard = ChildGuard(child);
    let mut reader = BufReader::new(stdout).lines();
    handshake_2025(&mut stdin, &mut reader).await;

    let request = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"fetch_url","arguments":{"url":"https://169.254.1.1/meta"}}}"#;
    let response = send_and_recv(&mut stdin, &mut reader, request).await;
    let json = nojson::RawJson::parse(&response).unwrap();
    let has_error = json
        .value()
        .to_member("error")
        .ok()
        .and_then(|m| m.optional())
        .is_some();
    assert!(has_error, "denied cidr should produce error");

    drop(stdin);
}

// ═══════════════════════════════════════════════════════════════════
// 4. Policy merge: defaults → server → tool override
// ═══════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_policy_merge_tool_deny_overrides_defaults() {
    let dir = make_test_dir("merge_deny");
    let policy = write_policy(
        dir.path(),
        "policy.kdl",
        r#"
            policy version=1
            defaults {
                filesystem {
                    allow "/workspace/**" mode="write"
                }
            }
            server "fs" {
                tool "read_file" {
                    filesystem {
                        allow "/workspace/**"
                    }
                }
                tool "write_file" {
                    filesystem {
                        allow "/workspace/output/**"
                    }
                }
                tool "exec" deny=#true
            }
        "#,
    );

    // See test_tool_fs_sub_policy_allowed_path — `/workspace` is
    // drive-root relative and host-ACL dependent.
    let mut child =
        spawn_guard_with_policy_env(&policy, false, &[("MCP_WRIT_ALLOW_REPLACEABLE_PATHS", "1")]);
    let mut stdin = child.stdin.take().unwrap();
    let stdout = child.stdout.take().unwrap();
    let _guard = ChildGuard(child);
    let mut reader = BufReader::new(stdout).lines();
    handshake_2025(&mut stdin, &mut reader).await;

    // read_file to allowed path → pass
    let req1 = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/workspace/src/main.rs"}}}"#;
    let resp1 = send_and_recv(&mut stdin, &mut reader, req1).await;
    assert!(
        has_result(&resp1),
        "allowed path should pass through: {resp1}"
    );

    // read_file to path outside allow → blocked
    let req2 = r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/etc/passwd"}}}"#;
    let resp2 = send_and_recv(&mut stdin, &mut reader, req2).await;
    assert_ne!(resp2, req2);
    assert!(
        resp2.contains("error"),
        "path outside allow should produce error"
    );

    // exec tool explicitly denied → blocked
    let req3 =
        r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"exec","arguments":{}}}"#;
    let resp3 = send_and_recv(&mut stdin, &mut reader, req3).await;
    assert!(resp3.contains("error"), "denied tool should produce error");

    // write_file to allowed output path → pass
    let req4 = r#"{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"write_file","arguments":{"path":"/workspace/output/result.txt"}}}"#;
    let resp4 = send_and_recv(&mut stdin, &mut reader, req4).await;
    assert!(
        has_result(&resp4),
        "write_file to allowed path should pass: {resp4}"
    );

    drop(stdin);
}

// ═══════════════════════════════════════════════════════════════════
// 5. extends / include / when directives
// ═══════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_extends_inherits_parent_tools() {
    let dir = make_test_dir("extends_e2e");

    // Base policy allows read_file
    write_policy(
        dir.path(),
        "base.kdl",
        r#"
            policy version=1
            server "fs" {
                tool "read_file"
                tool "exec" deny=#true
            }
        "#,
    );

    // Child extends base and adds write_file
    let child_policy = write_policy(
        dir.path(),
        "child.kdl",
        r#"
            extends "base.kdl"
            policy version=1
            server "fs" {
                tool "write_file"
            }
        "#,
    );

    let mut child = spawn_guard_with_policy(&child_policy, false);
    let mut stdin = child.stdin.take().unwrap();
    let stdout = child.stdout.take().unwrap();
    let _guard = ChildGuard(child);
    let mut reader = BufReader::new(stdout).lines();
    handshake_2025(&mut stdin, &mut reader).await;

    // read_file inherited from base → pass
    let req1 = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{}}}"#;
    let resp1 = send_and_recv(&mut stdin, &mut reader, req1).await;
    assert!(
        has_result(&resp1),
        "inherited tool should pass through: {resp1}"
    );

    // write_file added by child → pass
    let req2 = r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"write_file","arguments":{}}}"#;
    let resp2 = send_and_recv(&mut stdin, &mut reader, req2).await;
    assert!(
        has_result(&resp2),
        "child-added tool should pass through: {resp2}"
    );

    // exec denied in base → blocked
    let req3 =
        r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"exec","arguments":{}}}"#;
    let resp3 = send_and_recv(&mut stdin, &mut reader, req3).await;
    assert!(
        resp3.contains("error"),
        "denied tool from base should still be blocked"
    );

    drop(stdin);
}

#[tokio::test]
async fn test_include_merges_tools() {
    let dir = make_test_dir("include_e2e");

    // Extra policy fragment with additional tools
    write_policy(
        dir.path(),
        "extra_tools.kdl",
        r#"
            policy version=1
            server "github" {
                tool "search_repos"
            }
        "#,
    );

    let main_policy = write_policy(
        dir.path(),
        "main.kdl",
        r#"
            include "extra_tools.kdl"
            policy version=1
            server "fs" {
                tool "read_file"
            }
        "#,
    );

    let mut child = spawn_guard_with_server(&main_policy, "fs");
    let mut stdin = child.stdin.take().unwrap();
    let stdout = child.stdout.take().unwrap();
    let _guard = ChildGuard(child);
    let mut reader = BufReader::new(stdout).lines();
    handshake_2025(&mut stdin, &mut reader).await;

    // Bound to server "fs": read_file from main → pass
    let req1 = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{}}}"#;
    let resp1 = send_and_recv(&mut stdin, &mut reader, req1).await;
    assert!(has_result(&resp1), "main tool should pass through: {resp1}");

    // search_repos belongs to server "github" and must not be borrowed
    let req2 = r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"search_repos","arguments":{}}}"#;
    let resp2 = send_and_recv(&mut stdin, &mut reader, req2).await;
    assert!(
        resp2.contains("error"),
        "other server's tool must not be granted"
    );

    drop(stdin);

    let mut child = spawn_guard_with_server(&main_policy, "github");
    let mut stdin = child.stdin.take().unwrap();
    let stdout = child.stdout.take().unwrap();
    let _guard = ChildGuard(child);
    let mut reader = BufReader::new(stdout).lines();
    handshake_2025(&mut stdin, &mut reader).await;

    let req3 = r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"search_repos","arguments":{}}}"#;
    let resp3 = send_and_recv(&mut stdin, &mut reader, req3).await;
    assert!(
        has_result(&resp3),
        "included tool should pass through when bound to github: {resp3}"
    );

    let req4 = r#"{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"read_file","arguments":{}}}"#;
    let resp4 = send_and_recv(&mut stdin, &mut reader, req4).await;
    assert!(
        resp4.contains("error"),
        "fs tool must not leak into github bind"
    );

    drop(stdin);
}

#[tokio::test]
async fn test_when_environment_overrides_tool() {
    let dir = make_test_dir("when_e2e");

    let policy = write_policy(
        dir.path(),
        "policy.kdl",
        r#"
            policy version=1
            server "s1" {
                tool "debug_tool"
            }
            when environment="production" {
                server "s1" {
                    tool "debug_tool" deny=#true
                }
            }
        "#,
    );

    // Pass environment to child process only (thread-safe)
    let mut child = spawn_guard_with_policy_env(&policy, false, &[("MCP_WRIT_ENV", "production")]);
    let mut stdin = child.stdin.take().unwrap();
    let stdout = child.stdout.take().unwrap();
    let _guard = ChildGuard(child);
    let mut reader = BufReader::new(stdout).lines();
    handshake_2025(&mut stdin, &mut reader).await;

    // debug_tool is denied in production
    let request = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"debug_tool","arguments":{}}}"#;
    let response = send_and_recv(&mut stdin, &mut reader, request).await;

    assert!(
        response.contains("error"),
        "debug_tool should be denied in production environment"
    );

    drop(stdin);
}

#[tokio::test]
async fn test_extends_with_include_combined() {
    let dir = make_test_dir("ext_inc_combined");

    // Base policy
    write_policy(
        dir.path(),
        "base.kdl",
        r##"
            policy version=1
            server "core" {
                tool "read_file"
            }
        "##,
    );

    // Extra tools included by child
    write_policy(
        dir.path(),
        "plugins.kdl",
        r#"
            policy version=1
            server "plugins" {
                tool "search"
            }
        "#,
    );

    // Child extends base and includes plugins
    let child_policy = write_policy(
        dir.path(),
        "child.kdl",
        r#"
            extends "base.kdl"
            include "plugins.kdl"
            policy version=1
            server "core" {
                tool "write_file"
            }
        "#,
    );

    let mut child = spawn_guard_with_server(&child_policy, "core");
    let mut stdin = child.stdin.take().unwrap();
    let stdout = child.stdout.take().unwrap();
    let _guard = ChildGuard(child);
    let mut reader = BufReader::new(stdout).lines();
    handshake_2025(&mut stdin, &mut reader).await;

    // Bound to "core": read_file from base → pass
    let req1 = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{}}}"#;
    let resp1 = send_and_recv(&mut stdin, &mut reader, req1).await;
    assert!(has_result(&resp1), "base tool should pass through: {resp1}");

    // search belongs to server "plugins"
    let req2 = r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"search","arguments":{}}}"#;
    let resp2 = send_and_recv(&mut stdin, &mut reader, req2).await;
    assert!(
        resp2.contains("error"),
        "plugins tool must not leak into core bind"
    );

    // write_file from child → pass
    let req3 = r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"write_file","arguments":{}}}"#;
    let resp3 = send_and_recv(&mut stdin, &mut reader, req3).await;
    assert!(
        has_result(&resp3),
        "child tool should pass through: {resp3}"
    );

    drop(stdin);
}

// ═══════════════════════════════════════════════════════════════════
// 5b. Circular reference detection (unit-level, not binary-spawning)
// ═══════════════════════════════════════════════════════════════════

#[test]
fn test_circular_extends_detected_e2e() {
    let dir = make_test_dir("circ_e2e");
    std::fs::write(
        dir.path().join("a.kdl"),
        r#"
            extends "b.kdl"
            policy version=1
        "#,
    )
    .unwrap();
    std::fs::write(
        dir.path().join("b.kdl"),
        r#"
            extends "a.kdl"
            policy version=1
        "#,
    )
    .unwrap();

    let err = mcp_writ::policy::kdl_loader::load_kdl_policy(&dir.path().join("a.kdl")).unwrap_err();
    assert!(
        err.to_string().contains("circular reference"),
        "should detect circular extends: {err}"
    );
}

#[test]
fn test_circular_include_detected_e2e() {
    let dir = make_test_dir("circ_inc_e2e");
    std::fs::write(
        dir.path().join("a.kdl"),
        r#"
            include "b.kdl"
            policy version=1
        "#,
    )
    .unwrap();
    std::fs::write(
        dir.path().join("b.kdl"),
        r#"
            include "a.kdl"
            policy version=1
        "#,
    )
    .unwrap();

    let err = mcp_writ::policy::kdl_loader::load_kdl_policy(&dir.path().join("a.kdl")).unwrap_err();
    assert!(
        err.to_string().contains("circular reference"),
        "should detect circular include: {err}"
    );
}

// ═══════════════════════════════════════════════════════════════════
// 6. Dry-run mode compatibility
// ═══════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_dry_run_allows_denied_tool_custom_policy() {
    let dir = make_test_dir("dryrun_denied");
    let policy = write_policy(
        dir.path(),
        "policy.kdl",
        r#"
            policy version=1
            server "test" {
                tool "allowed_tool"
                tool "blocked_tool" deny=#true
            }
        "#,
    );

    let mut child = spawn_guard_with_policy(&policy, true);
    let mut stdin = child.stdin.take().unwrap();
    let stdout = child.stdout.take().unwrap();
    let _guard = ChildGuard(child);
    let mut reader = BufReader::new(stdout).lines();
    handshake_2025(&mut stdin, &mut reader).await;

    // Denied tool in dry-run → should be forwarded (echoed by cat)
    let request = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"blocked_tool","arguments":{}}}"#;
    let response = send_and_recv(&mut stdin, &mut reader, request).await;
    assert!(
        has_result(&response),
        "dry-run should forward denied tool to server: {response}"
    );

    drop(stdin);
}

#[tokio::test]
async fn test_dry_run_allows_unknown_tool_custom_policy() {
    let dir = make_test_dir("dryrun_unknown");
    let policy = write_policy(
        dir.path(),
        "policy.kdl",
        r#"
            policy version=1
            server "test" {
                tool "only_this_tool"
            }
        "#,
    );

    let mut child = spawn_guard_with_policy(&policy, true);
    let mut stdin = child.stdin.take().unwrap();
    let stdout = child.stdout.take().unwrap();
    let _guard = ChildGuard(child);
    let mut reader = BufReader::new(stdout).lines();
    handshake_2025(&mut stdin, &mut reader).await;

    // Unknown tool in dry-run → forwarded
    let request = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"undefined_tool","arguments":{}}}"#;
    let response = send_and_recv(&mut stdin, &mut reader, request).await;
    assert!(
        has_result(&response),
        "dry-run should forward unknown tool to server: {response}"
    );

    drop(stdin);
}

// ═══════════════════════════════════════════════════════════════════
// 7. Non-tools/call passthrough
// ═══════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_non_tools_call_passes_with_custom_policy() {
    let dir = make_test_dir("non_tools_call");
    let policy = write_policy(
        dir.path(),
        "policy.kdl",
        r#"
            policy version=1
            server "test" {
                tool "read_file"
            }
        "#,
    );

    let mut child = spawn_guard_with_policy(&policy, false);
    let mut stdin = child.stdin.take().unwrap();
    let stdout = child.stdout.take().unwrap();
    let _guard = ChildGuard(child);
    let mut reader = BufReader::new(stdout).lines();

    // Non-tools/call methods pass through: `ping` is allowed even before
    // the handshake, and `initialize` itself round-trips.
    let req1 = r#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#;
    let resp1 = send_and_recv(&mut stdin, &mut reader, req1).await;
    assert!(has_result(&resp1), "ping should pass through: {resp1}");

    let resp2 = send_and_recv(&mut stdin, &mut reader, common::INIT_REQUEST).await;
    assert!(
        resp2.contains("\"protocolVersion\":\"2025-11-25\""),
        "initialize should pass through: {resp2}"
    );

    drop(stdin);
}

// ═══════════════════════════════════════════════════════════════════
// 8. Multiple sequential requests in session with custom policy
// ═══════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_multiple_requests_mixed_verdicts() {
    let dir = make_test_dir("multi_req");
    let policy = write_policy(
        dir.path(),
        "policy.kdl",
        r#"
            policy version=1
            server "mixed" {
                tool "safe_tool"
                tool "dangerous_tool" deny=#true
                tool "another_safe"
            }
        "#,
    );

    let mut child = spawn_guard_with_policy(&policy, false);
    let mut stdin = child.stdin.take().unwrap();
    let stdout = child.stdout.take().unwrap();
    let _guard = ChildGuard(child);
    let mut reader = BufReader::new(stdout).lines();
    handshake_2025(&mut stdin, &mut reader).await;

    // 1. Allowed → pass
    let req1 = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"safe_tool","arguments":{}}}"#;
    let resp1 = send_and_recv(&mut stdin, &mut reader, req1).await;
    assert!(has_result(&resp1), "safe_tool: {resp1}");

    // 2. Denied → error
    let req2 = r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"dangerous_tool","arguments":{}}}"#;
    let resp2 = send_and_recv(&mut stdin, &mut reader, req2).await;
    assert!(resp2.contains("error"));

    // 3. Another allowed → session still works
    let req3 = r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"another_safe","arguments":{}}}"#;
    let resp3 = send_and_recv(&mut stdin, &mut reader, req3).await;
    assert!(has_result(&resp3), "another_safe: {resp3}");

    // 4. Non-tools/call → pass
    let req4 = r#"{"jsonrpc":"2.0","id":4,"method":"ping"}"#;
    let resp4 = send_and_recv(&mut stdin, &mut reader, req4).await;
    assert!(has_result(&resp4), "ping: {resp4}");

    // 5. Unknown → blocked
    let req5 = r#"{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"totally_unknown","arguments":{}}}"#;
    let resp5 = send_and_recv(&mut stdin, &mut reader, req5).await;
    assert!(resp5.contains("error"));

    drop(stdin);
}

// ═══════════════════════════════════════════════════════════════════
// 9. policy.example.kdl loads successfully (sanity check)
// ═══════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_example_kdl_policy_e2e() {
    let policy = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("policy.example.kdl");

    // See test_tool_fs_sub_policy_allowed_path — `/workspace` is
    // drive-root relative and host-ACL dependent.
    let mut child =
        spawn_guard_with_policy_env(&policy, false, &[("MCP_WRIT_ALLOW_REPLACEABLE_PATHS", "1")]);
    let mut stdin = child.stdin.take().unwrap();
    let stdout = child.stdout.take().unwrap();
    let _guard = ChildGuard(child);
    let mut reader = BufReader::new(stdout).lines();
    handshake_2025(&mut stdin, &mut reader).await;

    // read_file allowed in example policy
    let req = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/workspace/test.txt"}}}"#;
    let resp = send_and_recv(&mut stdin, &mut reader, req).await;
    assert!(
        has_result(&resp),
        "example policy: read_file should pass: {resp}"
    );

    // exec_shell denied in example policy
    let req2 = r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"exec_shell","arguments":{}}}"#;
    let resp2 = send_and_recv(&mut stdin, &mut reader, req2).await;
    assert!(
        resp2.contains("error"),
        "example policy: exec_shell should be blocked"
    );

    drop(stdin);
}

// ═══════════════════════════════════════════════════════════════════
// 7. `policy resolve` — composed-policy inspection (PR-24)
// ═══════════════════════════════════════════════════════════════════

/// Run `policy resolve` against `path` with extra args and env, returning
/// (exit code, stdout, stderr).
fn resolve_policy(path: &Path, extra: &[&str], envs: &[(&str, &str)]) -> (i32, String, String) {
    let mut cmd = std::process::Command::new(env!("CARGO_BIN_EXE_mcp-writ"));
    cmd.args(["policy", "resolve", "--policy"])
        .arg(path)
        .args(extra)
        .env("MCP_WRIT_SKIP_SANDBOX", "1")
        .env_remove("MCP_WRIT_ENV")
        .env_remove("MCP_WRIT_REPLACE_MODE")
        .env_remove("MCP_WRIT_REVIEW_MODE");
    for (k, v) in envs {
        cmd.env(k, v);
    }
    let out = cmd.output().expect("failed to run mcp-writ");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// Parse `resolve --format json` stdout and read one member.
fn resolve_json_member<'j>(
    v: nojson::RawJsonValue<'j, 'j>,
    key: &str,
) -> nojson::RawJsonValue<'j, 'j> {
    v.to_member(key)
        .unwrap_or_else(|_| panic!("member '{key}' must exist"))
        .required()
        .unwrap_or_else(|_| panic!("member '{key}' must exist"))
}

fn resolve_json(text: &str) -> nojson::RawJson<'_> {
    nojson::RawJson::parse(text).expect("resolve --format json emits valid JSON")
}

#[test]
fn test_policy_resolve_kdl_output() {
    let dir = make_test_dir("resolve_kdl");
    let policy = write_policy(
        dir.path(),
        "policy.kdl",
        r#"
            policy version=1
            defaults {
                syscalls {
                    allow "execve" "read"
                }
            }
            server "s" {
                tool "read_file" side_effect="read_only" {
                    filesystem {
                        allow "/data"
                    }
                }
            }
        "#,
    );

    let (code, stdout, _stderr) = resolve_policy(&policy, &[], &[]);
    assert_eq!(code, 0);
    // The composed document — the same `to_kdl` serialization — is
    // re-loadable KDL naming the effective fields.
    assert!(stdout.contains("policy"), "stdout carries KDL: {stdout}");
    assert!(stdout.contains("execve"), "effective syscalls: {stdout}");
    assert!(stdout.contains("read_file"), "effective tools: {stdout}");
}

#[test]
fn test_policy_resolve_json_provenance() {
    let dir = make_test_dir("resolve_json");
    std::fs::write(
        dir.path().join("base.kdl"),
        r#"
            policy version=1
            defaults {
                syscalls {
                    allow "read" "write" "execve"
                }
            }
        "#,
    )
    .unwrap();
    let child = write_policy(
        dir.path(),
        "child.kdl",
        r#"
            extends "base.kdl"
            policy version=1
            defaults {
                syscalls {
                    allow "read" "execve"
                }
            }
        "#,
    );

    let (code, stdout, _stderr) = resolve_policy(&child, &["--format", "json"], &[]);
    assert_eq!(code, 0, "resolve exits 0: {stdout}");
    let json = resolve_json(&stdout);
    assert_eq!(
        resolve_json_member(json.value(), "status")
            .as_string_str()
            .unwrap(),
        "resolved"
    );
    assert_eq!(
        resolve_json_member(json.value(), "schema_version")
            .as_string_str()
            .unwrap(),
        "1"
    );
    // Provenance names which file wrote the effective field and what
    // the write dropped.
    let mut replace = None;
    for rec in resolve_json_member(json.value(), "provenance")
        .to_array()
        .expect("provenance array")
    {
        if resolve_json_member(rec, "field").as_string_str().unwrap() == "defaults.syscalls"
            && resolve_json_member(rec, "op").as_string_str().unwrap() == "replace"
        {
            replace = Some(rec);
        }
    }
    let replace = replace.expect("replace record for defaults.syscalls");
    assert!(
        resolve_json_member(replace, "file")
            .to_unquoted_string_str()
            .unwrap()
            .ends_with("child.kdl"),
        "replacing file recorded"
    );
    assert!(
        resolve_json_member(replace, "items")
            .to_array()
            .unwrap()
            .any(|i| i.as_string_str().unwrap() == "write"),
        "dropped item recorded"
    );
    let warnings: Vec<_> = resolve_json_member(json.value(), "warnings")
        .to_array()
        .expect("warnings array")
        .collect();
    assert!(
        warnings.iter().any(|w| {
            resolve_json_member(*w, "kind").as_string_str().unwrap() == "replaced"
                && resolve_json_member(*w, "file")
                    .to_unquoted_string_str()
                    .unwrap()
                    .ends_with("child.kdl")
        }),
        "replaced warning names the child: {warnings:?}"
    );
}

#[test]
fn test_policy_resolve_env_selects_when() {
    let dir = make_test_dir("resolve_env");
    let policy = write_policy(
        dir.path(),
        "policy.kdl",
        r#"
            policy version=1
            defaults {
                syscalls {
                    allow "read" "execve"
                }
            }
            when environment="prod" {
                defaults {
                    syscalls {
                        allow "read" "execve" "io_uring_setup"
                    }
                }
            }
        "#,
    );

    let (code, dev_out, _) = resolve_policy(&policy, &["--format", "json"], &[]);
    assert_eq!(code, 0);
    let dev = resolve_json(&dev_out);
    assert!(
        !resolve_json_member(dev.value(), "kdl")
            .to_unquoted_string_str()
            .unwrap()
            .contains("io_uring_setup"),
        "no env: when block not applied"
    );

    let (code, prod_out, _) = resolve_policy(&policy, &["--format", "json", "--env", "prod"], &[]);
    assert_eq!(code, 0);
    let prod = resolve_json(&prod_out);
    let kdl = resolve_json_member(prod.value(), "kdl")
        .to_unquoted_string_str()
        .unwrap();
    assert!(
        kdl.contains("io_uring_setup"),
        "--env prod applies the when block: {kdl}"
    );
}

#[test]
fn test_policy_resolve_server_binding() {
    let dir = make_test_dir("resolve_server");
    let policy = write_policy(
        dir.path(),
        "policy.kdl",
        r#"
            policy version=1
            server "a" {
                tool "tool_a" side_effect="read_only"
            }
            server "b" {
                tool "tool_b" side_effect="write"
            }
        "#,
    );

    // A multi-server policy without --server does not bind — resolve
    // reports the bind failure like a launch does.
    let (code, _stdout, stderr) = resolve_policy(&policy, &[], &[]);
    assert_eq!(code, 1, "unbound multi-server policy fails: {stderr}");

    let (code, stdout, _) = resolve_policy(&policy, &["--server", "b", "--format", "json"], &[]);
    assert_eq!(code, 0, "--server b binds: {stdout}");
    let json = resolve_json(&stdout);
    let kdl = resolve_json_member(json.value(), "kdl")
        .to_unquoted_string_str()
        .unwrap();
    assert!(kdl.contains("tool_b"), "bound server tools resolve: {kdl}");
}

#[test]
fn test_policy_resolve_invalid_and_load_failure() {
    let dir = make_test_dir("resolve_invalid");
    // Missing --policy → status invalid, exit 2.
    let mut cmd = std::process::Command::new(env!("CARGO_BIN_EXE_mcp-writ"));
    cmd.args(["policy", "resolve", "--format", "json"]);
    let out = cmd.output().unwrap();
    assert_eq!(out.status.code(), Some(2));
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    let json = resolve_json(&text);
    assert_eq!(
        resolve_json_member(json.value(), "status")
            .as_string_str()
            .unwrap(),
        "invalid"
    );

    // Unloadable policy → exit 1 (status error in json mode).
    let (code, stdout, _) =
        resolve_policy(&dir.path().join("missing.kdl"), &["--format", "json"], &[]);
    assert_eq!(code, 1);
    let json = resolve_json(&stdout);
    assert_eq!(
        resolve_json_member(json.value(), "status")
            .as_string_str()
            .unwrap(),
        "error"
    );
}

#[test]
fn test_replace_mode_refuse_e2e() {
    let dir = make_test_dir("replace_mode_e2e");
    std::fs::write(
        dir.path().join("base.kdl"),
        r#"
            policy version=1
            defaults {
                syscalls {
                    allow "read" "execve"
                }
            }
        "#,
    )
    .unwrap();
    let child = write_policy(
        dir.path(),
        "child.kdl",
        r#"
            extends "base.kdl"
            policy version=1
            defaults {
                syscalls {
                    allow "execve"
                }
            }
        "#,
    );

    // Default (warn) loads — the warning is still emitted on stderr.
    let (code, _, stderr) = resolve_policy(&child, &[], &[]);
    assert_eq!(code, 0);
    assert!(stderr.contains("Warning"), "warn mode prints: {stderr}");

    // `resolve` itself never enforces — it is the inspector.
    let (code, _, _) = resolve_policy(&child, &[], &[("MCP_WRIT_REPLACE_MODE", "refuse")]);
    assert_eq!(code, 0, "resolve reports, never enforces");

    // The launch path enforces: `run` fails the load under refuse
    // before any spawn, so a never-runnable command still proves the
    // gate.
    let mut run = std::process::Command::new(env!("CARGO_BIN_EXE_mcp-writ"));
    run.args(["run", "--policy"])
        .arg(&child)
        .args(["--", "definitely-not-a-real-command-mcp-writ-xyz"])
        .env("MCP_WRIT_REPLACE_MODE", "refuse")
        .env_remove("MCP_WRIT_REVIEW_MODE");
    let out = run.output().expect("failed to run mcp-writ");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !out.status.success() && stderr.contains("replaced inherited entries"),
        "refuse rejects the replacement at load: {stderr}"
    );
}

#[test]
fn test_schema_v2_refuse_v1_warn_e2e() {
    let dir = make_test_dir("schema_modes_e2e");
    let v1 = write_policy(dir.path(), "v1.kdl", "policy version=1\nbogus {}\n");
    let v2 = write_policy(dir.path(), "v2.kdl", "policy version=2\nbogus {}\n");

    let (code, stdout, stderr) = resolve_policy(&v1, &["--format", "json"], &[]);
    assert_eq!(code, 0, "v1 warns and resolves: {stderr}");
    let json = resolve_json(&stdout);
    assert!(
        resolve_json_member(json.value(), "warnings")
            .to_array()
            .unwrap()
            .any(|w| resolve_json_member(w, "kind").as_string_str().unwrap() == "schema"),
        "v1 carries a schema warning: {stdout}"
    );

    let (code, _, _) = resolve_policy(&v2, &[], &[]);
    assert_ne!(code, 0, "v2 refuses the unknown node");
}

// `resolve` never enforces `// REVIEW` markers — but the findings the
// load collected must stay visible: listed on stderr in `kdl` mode
// (the same listing a warn-mode load prints) and carried in-band as
// `review_markers` in `json` mode.
#[test]
fn test_policy_resolve_reports_review_markers() {
    let dir = make_test_dir("resolve_review_markers");
    let policy = write_policy(
        dir.path(),
        "policy.kdl",
        r#"
            policy version=1
            // REVIEW: confirm the workload list before pinning
            server "s" {
                tool "read_file" side_effect="read_only"
            }
        "#,
    );

    let (code, _stdout, stderr) = resolve_policy(&policy, &[], &[]);
    assert_eq!(code, 0);
    assert!(
        stderr.contains("confirm the workload list"),
        "kdl mode lists the unresolved marker: {stderr}"
    );

    let (code, stdout, _) = resolve_policy(&policy, &["--format", "json"], &[]);
    assert_eq!(code, 0);
    let json = resolve_json(&stdout);
    let markers: Vec<_> = resolve_json_member(json.value(), "review_markers")
        .to_array()
        .expect("review_markers array")
        .collect();
    assert_eq!(markers.len(), 1, "one marker: {stdout}");
    let m = markers[0];
    assert!(
        resolve_json_member(m, "file")
            .to_unquoted_string_str()
            .unwrap()
            .ends_with("policy.kdl"),
        "marker names the file"
    );
    assert!(
        resolve_json_member(m, "text")
            .as_string_str()
            .unwrap()
            .contains("confirm the workload list"),
        "marker carries the text"
    );

    // `policy.hash` is the `sha256:` digest of the canonical KDL —
    // present on success, `null` (never an empty string) on failure.
    let hash = resolve_json_member(resolve_json_member(json.value(), "policy"), "hash")
        .as_string_str()
        .expect("hash is a string on success");
    assert!(
        hash.starts_with("sha256:") && hash.len() == 7 + 64,
        "hash is the sha256 digest: {hash}"
    );
}
