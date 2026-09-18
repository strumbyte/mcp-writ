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
    cmd.args(common::echo_stdio_argv())
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

    let request = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"my_read","arguments":{}}}"#;
    let response = send_and_recv(&mut stdin, &mut reader, request).await;
    assert_eq!(response, request, "allowed tool should pass through");

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

    let mut child = spawn_guard_with_policy(&policy, false);
    let mut stdin = child.stdin.take().unwrap();
    let stdout = child.stdout.take().unwrap();
    let _guard = ChildGuard(child);
    let mut reader = BufReader::new(stdout).lines();

    let request = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/workspace/test.txt"}}}"#;
    let response = send_and_recv(&mut stdin, &mut reader, request).await;
    assert_eq!(response, request, "path within allowed should pass through");

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

    let mut child = spawn_guard_with_policy(&policy, false);
    let mut stdin = child.stdin.take().unwrap();
    let stdout = child.stdout.take().unwrap();
    let _guard = ChildGuard(child);
    let mut reader = BufReader::new(stdout).lines();

    // read_file to allowed path → pass
    let req1 = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/workspace/src/main.rs"}}}"#;
    let resp1 = send_and_recv(&mut stdin, &mut reader, req1).await;
    assert_eq!(resp1, req1, "allowed path should pass through");

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
    assert_eq!(resp4, req4, "write_file to allowed path should pass");

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

    // read_file inherited from base → pass
    let req1 = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{}}}"#;
    let resp1 = send_and_recv(&mut stdin, &mut reader, req1).await;
    assert_eq!(resp1, req1, "inherited tool should pass through");

    // write_file added by child → pass
    let req2 = r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"write_file","arguments":{}}}"#;
    let resp2 = send_and_recv(&mut stdin, &mut reader, req2).await;
    assert_eq!(resp2, req2, "child-added tool should pass through");

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

    // Bound to server "fs": read_file from main → pass
    let req1 = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{}}}"#;
    let resp1 = send_and_recv(&mut stdin, &mut reader, req1).await;
    assert_eq!(resp1, req1, "main tool should pass through");

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

    let req3 = r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"search_repos","arguments":{}}}"#;
    let resp3 = send_and_recv(&mut stdin, &mut reader, req3).await;
    assert_eq!(
        resp3, req3,
        "included tool should pass through when bound to github"
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

    // Bound to "core": read_file from base → pass
    let req1 = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{}}}"#;
    let resp1 = send_and_recv(&mut stdin, &mut reader, req1).await;
    assert_eq!(resp1, req1, "base tool should pass through");

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
    assert_eq!(resp3, req3, "child tool should pass through");

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

    // Denied tool in dry-run → should be forwarded (echoed by cat)
    let request = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"blocked_tool","arguments":{}}}"#;
    let response = send_and_recv(&mut stdin, &mut reader, request).await;
    assert_eq!(
        response, request,
        "dry-run should forward denied tool to server"
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

    // Unknown tool in dry-run → forwarded
    let request = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"undefined_tool","arguments":{}}}"#;
    let response = send_and_recv(&mut stdin, &mut reader, request).await;
    assert_eq!(
        response, request,
        "dry-run should forward unknown tool to server"
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

    // Non-tools/call methods pass through. tools/list is reserved and the
    // echoed request is not a valid tools/list *response*, so it is not used here.
    let req1 = r#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#;
    let resp1 = send_and_recv(&mut stdin, &mut reader, req1).await;
    assert_eq!(resp1, req1, "ping should pass through");

    let req2 = r#"{"jsonrpc":"2.0","id":2,"method":"initialize","params":{}}"#;
    let resp2 = send_and_recv(&mut stdin, &mut reader, req2).await;
    assert_eq!(resp2, req2, "initialize should pass through");

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

    // 1. Allowed → pass
    let req1 = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"safe_tool","arguments":{}}}"#;
    let resp1 = send_and_recv(&mut stdin, &mut reader, req1).await;
    assert_eq!(resp1, req1);

    // 2. Denied → error
    let req2 = r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"dangerous_tool","arguments":{}}}"#;
    let resp2 = send_and_recv(&mut stdin, &mut reader, req2).await;
    assert!(resp2.contains("error"));

    // 3. Another allowed → session still works
    let req3 = r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"another_safe","arguments":{}}}"#;
    let resp3 = send_and_recv(&mut stdin, &mut reader, req3).await;
    assert_eq!(resp3, req3);

    // 4. Non-tools/call → pass
    let req4 = r#"{"jsonrpc":"2.0","id":4,"method":"resources/list"}"#;
    let resp4 = send_and_recv(&mut stdin, &mut reader, req4).await;
    assert_eq!(resp4, req4);

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

    let mut child = spawn_guard_with_policy(&policy, false);
    let mut stdin = child.stdin.take().unwrap();
    let stdout = child.stdout.take().unwrap();
    let _guard = ChildGuard(child);
    let mut reader = BufReader::new(stdout).lines();

    // read_file allowed in example policy
    let req = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/workspace/test.txt"}}}"#;
    let resp = send_and_recv(&mut stdin, &mut reader, req).await;
    assert_eq!(resp, req, "example policy: read_file should pass");

    // exec_shell denied in example policy
    let req2 = r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"exec_shell","arguments":{}}}"#;
    let resp2 = send_and_recv(&mut stdin, &mut reader, req2).await;
    assert!(
        resp2.contains("error"),
        "example policy: exec_shell should be blocked"
    );

    drop(stdin);
}
