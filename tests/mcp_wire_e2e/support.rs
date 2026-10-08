//! Shared harness for the wire-level e2e suite: guard-process
//! spawn/wait, JSON-RPC frame send/recv helpers, the 2025 handshake,
//! frame predicates, audit-log readers, and the shared policies and
//! `_meta` constants the submodules build requests from.

use std::path::{Path, PathBuf};
use std::process::Stdio;
use tempfile::TempDir;
use tokio::io::{AsyncWriteExt, BufReader};
use tokio::process::Command;
use tokio::time::{Duration, timeout};

use crate::common;

pub const TIMEOUT_SECS: u64 = 15;

pub struct ChildGuard(pub tokio::process::Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.start_kill();
    }
}

pub fn make_test_dir(label: &str) -> TempDir {
    tempfile::Builder::new()
        .prefix(&format!("mcp_writ_wire_{label}_"))
        .tempdir()
        .expect("failed to create temp directory")
}

/// Tools the fixture advertises under `tools_call_ok`; the policy allows all
/// three so tools/list filtering never rewrites the verified result.
pub const WIRE_POLICY: &str = r#"
policy version=1
logging level="info" fail_closed=#false
server "wire" {
    tool "read_file"
    tool "write_file"
    tool "fail_write"
    tool "fetch_url"
}
"#;

pub fn write_policy(dir: &Path, content: &str) -> PathBuf {
    let path = dir.join("policy.kdl");
    std::fs::write(&path, content).expect("write policy");
    path
}

pub fn spawn_guard(
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

pub async fn send_and_recv(
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

pub async fn recv_jsonrpc(
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

pub async fn send_notify(stdin: &mut tokio::process::ChildStdin, frame: &str) {
    stdin
        .write_all(format!("{frame}\n").as_bytes())
        .await
        .expect("write notification");
    stdin.flush().await.expect("flush");
}

/// 2025-11-25 handshake.
pub async fn handshake_2025(
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

pub fn json_method(frame: &str) -> Option<String> {
    let json = nojson::RawJson::parse(frame).ok()?;
    json.value()
        .to_member("method")
        .ok()
        .and_then(|m| m.optional())
        .and_then(|v| v.to_unquoted_string_str().ok())
        .map(|s| s.into_owned())
}

pub fn json_id(frame: &str) -> Option<String> {
    let json = nojson::RawJson::parse(frame).ok()?;
    json.value()
        .to_member("id")
        .ok()
        .and_then(|m| m.optional())
        .map(|v| v.as_raw_str().to_string())
}

pub fn has_result(frame: &str) -> bool {
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

pub fn has_error(frame: &str) -> bool {
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

pub fn error_message(frame: &str) -> String {
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

pub fn read_audit(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap_or_default()
}

pub fn audit_lines<'a>(audit: &'a str, event_type: &str) -> Vec<&'a str> {
    audit
        .lines()
        .filter(|l| l.contains(&format!("\"event_type\":\"{event_type}\"")))
        .collect()
}

pub fn call(name: &str, id: u32) -> String {
    format!(
        r#"{{"jsonrpc":"2.0","id":{id},"method":"tools/call","params":{{"name":"{name}","arguments":{{"path":"/workspace/notes.txt"}}}}}}"#
    )
}

/// `_meta` marking a 2026-07-28 request with the `elicitation` client
/// capability the `elicitation/create` additional request needs.
pub const META_2026_ELICIT: &str = concat!(
    r#""_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","#,
    r#""io.modelcontextprotocol/clientCapabilities":{"elicitation":{}}}"#,
);

/// 2026 `_meta` declaring both `elicitation` and `sampling`.
pub const META_2026_TWO_CAPS: &str = concat!(
    r#""_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","#,
    r#""io.modelcontextprotocol/clientCapabilities":{"elicitation":{},"sampling":{}}}"#,
);

pub fn call_2026(name: &str, id: u32, meta: &str) -> String {
    format!(
        r#"{{"jsonrpc":"2.0","id":{id},"method":"tools/call","params":{{"name":"{name}","arguments":{{"path":"/workspace/notes.txt"}},{meta}}}}}"#
    )
}
