//! run --report: the completed/failed session document — schema
//! contents, audit correlation via launch_id, and stdout hygiene.

use std::process::Stdio;

use tokio::io::AsyncWriteExt;
use tokio::process::Command;
use tokio::time::{Duration, timeout};

use crate::common;
use crate::support::*;

// ─── run --report ────────────────────────────────────────────────────────

/// A completed `run --report` session records plan + observations +
/// result in one schema; audit events correlate via launch_id; stdout
/// carries only JSON-RPC.
#[tokio::test]
async fn run_report_records_result_and_correlates_audit() {
    let dir = tempfile::tempdir().unwrap();
    let policy = write_policy(&dir);
    let audit_log = dir.path().join("audit.jsonl");
    let report_path = dir.path().join("report.json");

    let argv = common::echo_stdio_argv();
    let mut args: Vec<String> = vec![
        "--dry-run".into(),
        "--policy".into(),
        policy.to_string_lossy().into_owned(),
        "--audit-log".into(),
        audit_log.to_string_lossy().into_owned(),
        "--report".into(),
        report_path.to_string_lossy().into_owned(),
        "--".into(),
    ];
    args.extend(argv);

    // Relay one real JSON-RPC frame, then close stdin: the echo child
    // answers and exits — the session ends with the child's observed exit.
    let mut child = Command::new(bin())
        .arg("run")
        .args(&args)
        .env_remove("MCP_WRIT_SKIP_SANDBOX")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn mcp-writ");
    let mut stdin = child.stdin.take().expect("stdin");
    stdin
        .write_all(b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}\n")
        .await
        .expect("write frame");
    stdin.flush().await.expect("flush");
    drop(stdin);
    let out = timeout(Duration::from_secs(TIMEOUT_SECS), child.wait_with_output())
        .await
        .expect("run timed out")
        .expect("wait mcp-writ");

    // The workload exited 0 on EOF; the run ends 0.
    assert_eq!(
        out.status.code(),
        Some(0),
        "dry-run echo exits 0 (stderr: {})",
        String::from_utf8_lossy(&out.stderr)
    );

    // stdout carries only JSON-RPC frames — never report JSON.
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        !stdout.contains("schema_version"),
        "report JSON must never touch MCP stdout: {stdout}"
    );
    for line in stdout.lines() {
        assert!(
            line.starts_with("{\"jsonrpc\""),
            "stdout must carry only JSON-RPC frames, got: {line}"
        );
    }

    let json = read_report(&report_path);
    assert_eq!(
        member(json.value(), "schema_version")
            .as_string_str()
            .unwrap(),
        "1"
    );
    let result = member(json.value(), "result");
    assert_eq!(member(result, "status").as_string_str().unwrap(), "exited");
    assert_eq!(member(result, "exit_code").as_integer_str().unwrap(), "0");
    // Plan + observations are populated in the same schema.
    assert!(member(json.value(), "plan").to_member("controls").is_ok());
    assert!(json.value().to_member("observations").is_ok());
    assert_eq!(
        member(json.value(), "dry_run").as_boolean_str().unwrap(),
        "true"
    );

    // The audit trail correlates with the report through launch_id.
    let launch_id = member(json.value(), "launch_id")
        .as_string_str()
        .unwrap()
        .to_string();
    let audit = std::fs::read_to_string(&audit_log).unwrap_or_default();
    let connected = audit
        .lines()
        .find(|l| l.contains("\"event_type\":\"server.connected\""))
        .unwrap_or_else(|| panic!("audit log missing server.connected: {audit}"));
    assert!(
        connected.contains(&format!("\"correlation_id\":\"{launch_id}\"")),
        "server.connected must correlate with the report's launch_id {launch_id}: {connected}"
    );
}

/// A launch that never reaches a session still records the plan and a
/// `failed` result — never an empty success.
#[tokio::test]
async fn run_report_on_launch_failure_is_failed_not_empty() {
    let dir = tempfile::tempdir().unwrap();
    let policy = write_policy(&dir);
    let audit_log = dir.path().join("audit.jsonl");
    let report_path = dir.path().join("report.json");

    let out = run_with_report(&[
        "--policy".into(),
        policy.to_string_lossy().into_owned(),
        "--audit-log".into(),
        audit_log.to_string_lossy().into_owned(),
        "--report".into(),
        report_path.to_string_lossy().into_owned(),
        "--".into(),
        "mcp-writ-definitely-not-a-real-command-xyz".into(),
    ])
    .await;

    assert_eq!(out.status.code(), Some(1), "launch failure exits 1");
    let json = read_report(&report_path);
    let result = member(json.value(), "result");
    assert_eq!(member(result, "status").as_string_str().unwrap(), "failed");
    // The plan the failed launch was built on is still reported.
    assert!(member(json.value(), "plan").to_member("controls").is_ok());

    // server.error audit event shares the same launch_id.
    let launch_id = member(json.value(), "launch_id")
        .as_string_str()
        .unwrap()
        .to_string();
    let audit = std::fs::read_to_string(&audit_log).unwrap_or_default();
    let server_error = audit
        .lines()
        .find(|l| l.contains("\"event_type\":\"server.error\""))
        .unwrap_or_else(|| panic!("audit log missing server.error: {audit}"));
    assert!(
        server_error.contains(&format!("\"correlation_id\":\"{launch_id}\"")),
        "server.error must correlate with launch_id {launch_id}: {server_error}"
    );
}
