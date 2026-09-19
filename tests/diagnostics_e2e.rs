//! P3-A diagnostics e2e: only established facts are reported, and they stay
//! on stderr / the JSONL audit log — never on stdout.
//!
//! Classification under test:
//!
//! - **Auditor denial** — a `tools/call` that violates the tool fs policy is
//!   answered with a JSON-RPC error, and the `tool_call.denied` audit event
//!   carries the client's request id.
//! - **Sandbox policy-stage failure** — (Linux) `syscalls.allowed` without
//!   `execve` is rejected before any OS call as
//!   `SandboxSetup{stage: policy}`, distinct from a generic spawn failure.
//! - **Generic spawn failure** — an existing but non-executable child fails
//!   at spawn; the failure is audited as `server.error` and reported on
//!   stderr without claiming a sandbox denial.
//! - **Child-side access failure** — the Auditor allows a request, the child
//!   performs a real `open` and reports `ENOENT`/`EACCES` as
//!   `result.isError`. That is a tool result, not a Warden/policy denial:
//!   no `tool_call.denied`, no `server.error`, and no sandbox claim.

use std::path::{Path, PathBuf};
use std::process::Stdio;

use tempfile::TempDir;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::Command;
use tokio::time::{Duration, timeout};

mod common;

const TIMEOUT_SECS: u64 = 20;

struct ChildGuard(tokio::process::Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.start_kill();
    }
}

// ─── layout / policy ─────────────────────────────────────────────────────────

struct Layout {
    _root: TempDir,
    a_dir: PathBuf,
    b_marker: PathBuf,
}

fn layout() -> Layout {
    let temp = tempfile::Builder::new()
        .prefix("mcp_writ_p3a_")
        .tempdir()
        .expect("tempdir");
    let root = temp.path().canonicalize().expect("canonical temp root");
    let a_dir = root.join("allowed_a");
    let b_dir = root.join("granted_b");
    std::fs::create_dir_all(&a_dir).expect("mkdir A");
    std::fs::create_dir_all(&b_dir).expect("mkdir B");
    let b_marker = b_dir.join("marker.txt");
    std::fs::write(&b_marker, "MARKER-B\n").expect("write B marker");
    Layout {
        _root: temp,
        a_dir,
        b_marker,
    }
}

/// `read_file` may name only objects under A. Other tools are undeclared
/// (default-deny) — the tests below call only `read_file`/`tools/list`.
fn write_policy(lay: &Layout) -> (TempDir, PathBuf) {
    let dir = tempfile::Builder::new()
        .prefix("mcp_writ_p3a_policy_")
        .tempdir()
        .expect("policy tempdir");
    let a_glob = format!("{}/**", lay.a_dir.to_string_lossy().replace('\\', "/"));
    let kdl = format!(
        "policy version=1\ndefaults {{\n    filesystem {{\n        secret-overlay #true\n    }}\n}}\nlogging level=\"info\" fail_closed=#false\nserver \"diagnostics\" {{\n    tool \"read_file\" {{\n        filesystem {{\n            allow \"{a_glob}\"\n        }}\n    }}\n}}\n"
    );
    let path = dir.path().join("policy.kdl");
    std::fs::write(&path, kdl).expect("write policy");
    (dir, path)
}

// ─── spawn helpers ───────────────────────────────────────────────────────────

struct Guard {
    _guard: ChildGuard,
    stdin: tokio::process::ChildStdin,
    reader: tokio::io::Lines<BufReader<tokio::process::ChildStdout>>,
}

fn spawn_guard(policy: &Path, audit_log: &Path, argv: &[String], skip_sandbox: bool) -> Guard {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_mcp-writ"));
    cmd.args([
        "run",
        "--transport",
        "stdio",
        "--policy",
        policy.to_str().expect("policy path utf-8"),
        "--audit-log",
        audit_log.to_str().expect("audit path utf-8"),
        "--",
    ]);
    cmd.args(argv);
    if skip_sandbox {
        cmd.env("MCP_WRIT_SKIP_SANDBOX", "1");
    } else {
        cmd.env_remove("MCP_WRIT_SKIP_SANDBOX");
    }
    let mut child = cmd
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("failed to spawn mcp-writ binary - did you run `cargo build`?");
    let stdin = child.stdin.take().expect("guard stdin");
    let stdout = child.stdout.take().expect("guard stdout");
    Guard {
        _guard: ChildGuard(child),
        stdin,
        reader: BufReader::new(stdout).lines(),
    }
}

/// Send one request and return the next JSON-RPC frame. Any non-JSON-RPC
/// line on stdout fails immediately — stdout carries frames only.
async fn send_and_recv(guard: &mut Guard, request: &str) -> String {
    guard
        .stdin
        .write_all(format!("{request}\n").as_bytes())
        .await
        .expect("write request");
    guard.stdin.flush().await.expect("flush request");
    let line = timeout(Duration::from_secs(TIMEOUT_SECS), guard.reader.next_line())
        .await
        .expect("response timeout")
        .expect("mcp-writ stdout error")
        .expect("mcp-writ closed stdout before a response");
    assert!(
        line.starts_with("{\"jsonrpc\""),
        "stdout must carry only JSON-RPC frames, got: {line}"
    );
    line
}

fn parse(resp: &str) -> nojson::RawJson<'_> {
    nojson::RawJson::parse(resp).expect("response must be JSON")
}

fn json_has_error(resp: &str) -> bool {
    parse(resp)
        .value()
        .to_member("error")
        .ok()
        .and_then(|m| m.optional())
        .is_some()
}

fn sc<'j>(json: &'j nojson::RawJson<'j>) -> Option<nojson::RawJsonValue<'j, 'j>> {
    json.value()
        .to_member("result")
        .ok()?
        .optional()?
        .to_member("structuredContent")
        .ok()?
        .optional()
}

fn sc_str<'j>(json: &'j nojson::RawJson<'j>, key: &str) -> Option<String> {
    sc(json)?
        .to_member(key)
        .ok()?
        .optional()?
        .to_unquoted_string_str()
        .ok()
        .map(|s| s.into_owned())
}

fn is_error_result(json: &nojson::RawJson) -> bool {
    json.value()
        .to_member("result")
        .ok()
        .and_then(|m| m.optional())
        .and_then(|r| r.to_member("isError").ok().and_then(|m| m.optional()))
        .and_then(|v| v.as_boolean_str().ok())
        == Some("true")
}

fn json_str(s: &str) -> String {
    let mut out = String::from("\"");
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn read_audit(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap_or_default()
}

// ─── 1. Auditor denial ───────────────────────────────────────────────────────

#[tokio::test]
async fn auditor_denial_carries_request_id_and_keeps_stdout_clean() {
    let Some(exe) = common::compiled_open_path_fixture() else {
        return;
    };
    let lay = layout();
    let (_dir, policy) = write_policy(&lay);
    let audit_log = common::next_audit_log_path();
    let mut guard = spawn_guard(
        &policy,
        &audit_log,
        &[exe.to_string_lossy().into_owned()],
        true,
    );

    // tools/list sanity — manifest verification must pass before the
    // denial case is meaningful.
    let list = send_and_recv(
        &mut guard,
        r#"{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}"#,
    )
    .await;
    assert!(!json_has_error(&list), "tools/list must verify: {list}");

    // B is outside the tool's fs allow glob: an Auditor-side denial.
    let req = format!(
        "{{\"jsonrpc\":\"2.0\",\"id\":\"req-42\",\"method\":\"tools/call\",\"params\":{{\"name\":\"read_file\",\"arguments\":{{\"path\":{}}}}}}}",
        json_str(&lay.b_marker.to_string_lossy())
    );
    let resp = send_and_recv(&mut guard, &req).await;
    assert!(json_has_error(&resp), "B must be auditor-denied: {resp}");

    drop(guard.stdin);
    let _ = timeout(Duration::from_secs(TIMEOUT_SECS), guard._guard.0.wait()).await;

    let audit = read_audit(&audit_log);
    let denied = audit
        .lines()
        .find(|l| l.contains("\"event_type\":\"tool_call.denied\""))
        .unwrap_or_else(|| panic!("audit log missing tool_call.denied: {audit}"));
    let denied_json = parse(denied);
    let request_id = denied_json
        .value()
        .to_member("request_id")
        .ok()
        .and_then(|m| m.optional())
        .and_then(|v| v.to_unquoted_string_str().ok().map(|s| s.into_owned()));
    // Raw JSON-RPC id token is preserved verbatim — a string id keeps its
    // quotes (`"req-42"`), a numeric id stays bare.
    assert_eq!(
        request_id.as_deref(),
        Some("\"req-42\""),
        "denied event must carry the client request id verbatim: {denied}"
    );
    assert!(
        denied.contains("\"target_tool\":\"read_file\""),
        "denied event must name the tool: {denied}"
    );
    // An Auditor denial is not a server failure and not a sandbox event.
    assert!(
        !audit.contains("\"event_type\":\"server.error\""),
        "policy denial must not be recorded as server.error: {audit}"
    );
}

// ─── 2. child-side access failure ────────────────────────────────────────────

#[tokio::test]
async fn child_enoent_is_tool_error_not_warden_denial() {
    let Some(exe) = common::compiled_open_path_fixture() else {
        return;
    };
    let lay = layout();
    let (_dir, policy) = write_policy(&lay);
    let audit_log = common::next_audit_log_path();
    let mut guard = spawn_guard(
        &policy,
        &audit_log,
        &[exe.to_string_lossy().into_owned()],
        true,
    );

    let list = send_and_recv(
        &mut guard,
        r#"{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}"#,
    )
    .await;
    assert!(!json_has_error(&list), "tools/list must verify: {list}");

    // Inside the allowed glob but does not exist: the Auditor allows, the
    // child's real open fails ENOENT → isError result, not a denial.
    let missing = lay.a_dir.join("missing.txt");
    let req = format!(
        "{{\"jsonrpc\":\"2.0\",\"id\":7,\"method\":\"tools/call\",\"params\":{{\"name\":\"read_file\",\"arguments\":{{\"path\":{}}}}}}}",
        json_str(&missing.to_string_lossy())
    );
    let resp = send_and_recv(&mut guard, &req).await;
    let json = parse(&resp);
    assert!(
        !json_has_error(&resp),
        "child-side failure is a tool result, not a protocol error: {resp}"
    );
    assert!(is_error_result(&json), "expected isError result: {resp}");
    assert_eq!(
        sc_str(&json, "error").as_deref(),
        Some("ENOENT"),
        "the child reports its own errno: {resp}"
    );

    drop(guard.stdin);
    let _ = timeout(Duration::from_secs(TIMEOUT_SECS), guard._guard.0.wait()).await;

    let audit = read_audit(&audit_log);
    assert!(
        !audit.contains("\"event_type\":\"tool_call.denied\""),
        "a child-side ENOENT must not be recorded as a policy denial: {audit}"
    );
    assert!(
        !audit.contains("\"event_type\":\"server.error\""),
        "a child-side ENOENT must not be recorded as server.error: {audit}"
    );
    assert!(
        !audit.contains("sandbox."),
        "a child-side ENOENT must not be recorded as a sandbox event: {audit}"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn child_eperm_is_tool_error_not_warden_denial() {
    use std::os::unix::fs::PermissionsExt;

    let Some(exe) = common::compiled_open_path_fixture() else {
        return;
    };
    let lay = layout();
    let (_dir, policy) = write_policy(&lay);
    let audit_log = common::next_audit_log_path();
    let mut guard = spawn_guard(
        &policy,
        &audit_log,
        &[exe.to_string_lossy().into_owned()],
        true,
    );

    // Inside the allowed glob, exists, but chmod 000: the child-side open
    // fails EACCES. The Auditor allowed it — this is not a Warden denial.
    let locked = lay.a_dir.join("locked.txt");
    std::fs::write(&locked, "LOCKED\n").expect("write locked file");
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).expect("chmod 000");
    let req = format!(
        "{{\"jsonrpc\":\"2.0\",\"id\":8,\"method\":\"tools/call\",\"params\":{{\"name\":\"read_file\",\"arguments\":{{\"path\":{}}}}}}}",
        json_str(&locked.to_string_lossy())
    );
    let resp = send_and_recv(&mut guard, &req).await;
    let json = parse(&resp);
    assert!(
        !json_has_error(&resp),
        "child-side EACCES is a tool result: {resp}"
    );
    assert!(is_error_result(&json), "expected isError result: {resp}");
    assert_eq!(
        sc_str(&json, "error").as_deref(),
        Some("EACCES"),
        "the child reports its own errno: {resp}"
    );

    drop(guard.stdin);
    let _ = timeout(Duration::from_secs(TIMEOUT_SECS), guard._guard.0.wait()).await;
    // Restore permissions so the TempDir cleanup cannot fail on read-only
    // entries.
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o644)).ok();

    let audit = read_audit(&audit_log);
    assert!(
        !audit.contains("\"event_type\":\"tool_call.denied\""),
        "a child-side EACCES must not be recorded as a policy denial: {audit}"
    );
    assert!(
        !audit.contains("\"event_type\":\"server.error\""),
        "a child-side EACCES must not be recorded as server.error: {audit}"
    );
}

// ─── 3. generic spawn failure ────────────────────────────────────────────────

#[tokio::test]
async fn spawn_failure_is_audited_as_server_error_and_off_stdout() {
    let lay = layout();
    let (_dir, policy) = write_policy(&lay);
    let audit_log = common::next_audit_log_path();

    // An existing but non-executable child: path resolution succeeds,
    // exec fails. Deterministic on both platforms (EACCES / bad exe).
    let non_exe = lay.a_dir.join("not_a_program.txt");
    std::fs::write(&non_exe, "not an executable\n").expect("write non-exe");

    let output = Command::new(env!("CARGO_BIN_EXE_mcp-writ"))
        .args([
            "run",
            "--transport",
            "stdio",
            "--policy",
            policy.to_str().expect("policy path utf-8"),
            "--audit-log",
            audit_log.to_str().expect("audit path utf-8"),
            "--",
            non_exe.to_str().expect("non-exe path utf-8"),
        ])
        .env("MCP_WRIT_SKIP_SANDBOX", "1")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await
        .expect("run mcp-writ");

    assert!(!output.status.success(), "spawn failure must exit non-zero");
    assert!(
        output.stdout.is_empty(),
        "diagnostics must never touch stdout: {:?}",
        String::from_utf8_lossy(&output.stdout)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("failed to spawn MCP server"),
        "stderr must name the spawn stage: {stderr}"
    );
    assert!(
        !stderr.contains("Sandbox setup failed"),
        "a generic exec failure must not be reported as sandbox setup: {stderr}"
    );

    let audit = read_audit(&audit_log);
    let server_error = audit
        .lines()
        .find(|l| l.contains("\"event_type\":\"server.error\""))
        .unwrap_or_else(|| panic!("audit log missing server.error: {audit}"));
    assert!(
        server_error.contains("spawn"),
        "server.error must describe the spawn failure: {server_error}"
    );
}

// ─── 4. sandbox policy-stage failure (Linux: missing execve allowance) ───────

#[cfg(target_os = "linux")]
#[tokio::test]
async fn sandbox_policy_stage_failure_is_distinct_from_spawn() {
    let Some(exe) = common::compiled_open_path_fixture() else {
        return;
    };
    let dir = tempfile::Builder::new()
        .prefix("mcp_writ_p3a_policy_")
        .tempdir()
        .expect("policy tempdir");
    // No execve in syscalls.allowed and no sandbox.allow_degraded:
    // require_execve_allowance rejects before any OS call (stage=policy).
    let kdl = "policy version=1\ndefaults {\n    syscalls {\n        allow \"read\" \"write\" \"exit_group\"\n    }\n}\nlogging level=\"info\" fail_closed=#false\nserver \"diagnostics\" {\n    tool \"read_file\"\n}\n";
    let policy = dir.path().join("policy.kdl");
    std::fs::write(&policy, kdl).expect("write policy");
    let audit_log = common::next_audit_log_path();

    let output = Command::new(env!("CARGO_BIN_EXE_mcp-writ"))
        .args([
            "run",
            "--transport",
            "stdio",
            "--policy",
            policy.to_str().expect("policy path utf-8"),
            "--audit-log",
            audit_log.to_str().expect("audit path utf-8"),
            "--",
            exe.to_str().expect("exe path utf-8"),
        ])
        .env_remove("MCP_WRIT_SKIP_SANDBOX")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await
        .expect("run mcp-writ");

    assert!(
        !output.status.success(),
        "policy-stage failure exits non-zero"
    );
    assert!(
        output.stdout.is_empty(),
        "diagnostics must never touch stdout: {:?}",
        String::from_utf8_lossy(&output.stdout)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Sandbox setup failed during 'policy' stage"),
        "the established stage must be named, not a generic spawn error: {stderr}"
    );
    assert!(
        stderr.contains("execve"),
        "the diagnostic must identify the missing allowance: {stderr}"
    );

    let audit = read_audit(&audit_log);
    let server_error = audit
        .lines()
        .find(|l| l.contains("\"event_type\":\"server.error\""))
        .unwrap_or_else(|| panic!("audit log missing server.error: {audit}"));
    assert!(
        server_error.contains("policy"),
        "server.error must carry the policy stage: {server_error}"
    );
}
