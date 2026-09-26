//! PR-07 e2e: `plan` diagnostics (4 statuses / fixed exit codes, no
//! workload launch) and `run --report` (same-schema plan+observations+
//! result; JSON off stdout; failures recorded, never empty success).

use std::path::{Path, PathBuf};
use std::process::Stdio;

use tempfile::TempDir;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;
use tokio::time::{Duration, timeout};

mod common;

const TIMEOUT_SECS: u64 = 20;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_mcp-writ")
}

/// Minimal policy that loads on every host OS (`fail_closed` off so no
/// `--audit-log` is required; no server blocks to bind).
fn write_policy(dir: &TempDir) -> PathBuf {
    let path = dir.path().join("policy.kdl");
    std::fs::write(
        &path,
        "policy version=1\ndefaults {\n    filesystem {\n        secret-overlay #true\n    }\n}\nlogging level=\"info\" fail_closed=#false\n",
    )
    .expect("write policy");
    path
}

fn member<'j>(v: nojson::RawJsonValue<'j, 'j>, key: &str) -> nojson::RawJsonValue<'j, 'j> {
    v.to_member(key)
        .unwrap_or_else(|_| panic!("member '{key}' must exist"))
        .required()
        .unwrap_or_else(|_| panic!("member '{key}' must exist"))
}

fn plan_json(stdout: &[u8]) -> nojson::RawJson<'static> {
    let s = String::from_utf8(stdout.to_vec()).expect("utf8 stdout");
    let trimmed = s.trim();
    nojson::RawJson::parse(Box::leak(trimmed.to_string().into_boxed_str()))
        .expect("stdout must be the plan JSON result")
}

fn status_of(json: &nojson::RawJson) -> String {
    member(json.value(), "status")
        .as_string_str()
        .unwrap()
        .to_string()
}

fn reason_code_of(json: &nojson::RawJson) -> Option<String> {
    json.value()
        .to_member("reason")
        .ok()
        .and_then(|m| m.optional())
        .and_then(|r| {
            r.to_member("code")
                .ok()
                .and_then(|m| m.optional())
                .and_then(|c| c.as_string_str().ok().map(|s| s.to_string()))
        })
}

async fn run_plan(args: &[&str]) -> std::process::Output {
    timeout(
        Duration::from_secs(TIMEOUT_SECS),
        Command::new(bin())
            .arg("plan")
            .args(args)
            .env_remove("MCP_WRIT_SKIP_SANDBOX")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output(),
    )
    .await
    .expect("plan timed out — it must never wait on a workload")
    .expect("run mcp-writ plan")
}

// ─── plan: four fixed states ─────────────────────────────────────────────

#[tokio::test]
async fn plan_invalid_no_target_exits_2() {
    let out = run_plan(&[]).await;
    assert_eq!(out.status.code(), Some(2), "invalid exits 2: {out:?}");
    let json = plan_json(&out.stdout);
    assert_eq!(status_of(&json), "invalid");
    assert_eq!(reason_code_of(&json).as_deref(), Some("invalid_input"));
    // Human remediation on stderr, JSON only on stdout.
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("plan: invalid"), "stderr summary: {stderr}");
    assert!(
        !stderr.contains("\"schema_version\""),
        "JSON must stay off stderr"
    );
}

#[tokio::test]
async fn plan_invalid_image_and_command_exits_2() {
    let out = run_plan(&["--image", "app@sha256:abc", "--", "node", "s.js"]).await;
    assert_eq!(out.status.code(), Some(2), "invalid exits 2: {out:?}");
    assert_eq!(status_of(&plan_json(&out.stdout)), "invalid");
}

#[tokio::test]
async fn plan_blocked_missing_policy_exits_1() {
    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("no_such_policy.kdl");
    let out = run_plan(&["--policy", missing.to_str().unwrap(), "--", "anything"]).await;
    assert_eq!(out.status.code(), Some(1), "blocked exits 1: {out:?}");
    let json = plan_json(&out.stdout);
    assert_eq!(status_of(&json), "blocked");
    assert_eq!(reason_code_of(&json).as_deref(), Some("policy_not_found"));
    // A blocked result still gives machine-readable checks + remediation.
    let checks = member(json.value(), "checks");
    assert!(checks.to_array().is_ok(), "checks must be an array");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("plan: blocked"), "stderr summary: {stderr}");
}

#[tokio::test]
async fn plan_blocked_unresolvable_command_exits_1() {
    let dir = tempfile::tempdir().unwrap();
    let policy = write_policy(&dir);
    let out = run_plan(&[
        "--policy",
        policy.to_str().unwrap(),
        "--",
        "mcp-writ-definitely-not-a-real-command-xyz",
    ])
    .await;
    assert_eq!(out.status.code(), Some(1), "blocked exits 1: {out:?}");
    let json = plan_json(&out.stdout);
    assert_eq!(status_of(&json), "blocked");
    assert_eq!(reason_code_of(&json).as_deref(), Some("command_not_found"));
    // The computed plan is still reported — a blocked plan is describable.
    let plan = member(json.value(), "plan");
    assert!(plan.to_member("controls").is_ok(), "plan must be present");
}

/// A path-spelled command that does not exist must not pass
/// `command.resolve` — the check certifies what `run` could spawn.
#[tokio::test]
async fn plan_blocked_missing_command_path_exits_1() {
    let dir = tempfile::tempdir().unwrap();
    let policy = write_policy(&dir);
    let missing = dir.path().join("definitely-missing-binary");
    let out = run_plan(&[
        "--policy",
        policy.to_str().unwrap(),
        "--",
        missing.to_str().unwrap(),
    ])
    .await;
    assert_eq!(out.status.code(), Some(1), "blocked exits 1: {out:?}");
    let json = plan_json(&out.stdout);
    assert_eq!(status_of(&json), "blocked");
    assert_eq!(reason_code_of(&json).as_deref(), Some("command_not_found"));
}

/// `logging.fail_closed` (the policy default) requires `--audit-log` at
/// `run` time — a flag `plan` cannot verify, so `audit.config` is `warn`
/// and `ready` stays reachable under the default policy.
#[tokio::test]
async fn plan_ready_default_fail_closed_warns_audit_config() {
    let dir = tempfile::tempdir().unwrap();
    // No `logging` line: `fail_closed` defaults to true.
    let policy_path = dir.path().join("policy.kdl");
    std::fs::write(
        &policy_path,
        "policy version=1\ndefaults {\n    filesystem {\n        secret-overlay #true\n    }\n}\n",
    )
    .expect("write policy");
    let out = run_plan(&["--policy", policy_path.to_str().unwrap(), "--", bin()]).await;
    let stderr = String::from_utf8_lossy(&out.stderr);
    let json = plan_json(&out.stdout);
    assert_eq!(
        out.status.code(),
        Some(0),
        "ready exits 0 (stderr: {stderr})"
    );
    assert_eq!(status_of(&json), "ready");
    let audit = member(json.value(), "checks")
        .to_array()
        .unwrap()
        .find(|c| member(*c, "id").as_string_str().unwrap() == "audit.config")
        .expect("audit.config check must be present");
    assert_eq!(member(audit, "status").as_string_str().unwrap(), "warn");
    // The run-time requirement stays visible as remediation.
    assert!(member(audit, "remediation").as_string_str().is_ok());
}

#[tokio::test]
async fn plan_error_unwritable_report_exits_1() {
    let dir = tempfile::tempdir().unwrap();
    let policy = write_policy(&dir);
    // Parent directory does not exist → saving the result fails → status error.
    let bad_report = dir.path().join("no_such_dir").join("plan.json");
    let out = run_plan(&[
        "--report",
        bad_report.to_str().unwrap(),
        "--policy",
        policy.to_str().unwrap(),
        "--",
        bin(),
    ])
    .await;
    assert_eq!(out.status.code(), Some(1), "error exits 1: {out:?}");
    let json = plan_json(&out.stdout);
    assert_eq!(status_of(&json), "error");
    assert_eq!(
        reason_code_of(&json).as_deref(),
        Some("report_write_failed")
    );
    assert!(!bad_report.exists(), "no report file may be created");
}

#[tokio::test]
async fn plan_ready_exits_0_with_plan() {
    let dir = tempfile::tempdir().unwrap();
    let policy = write_policy(&dir);
    // The mcp-writ binary itself is a resolvable, existing command — and
    // `plan` never spawns it.
    let out = run_plan(&[
        "--policy",
        policy.to_str().unwrap(),
        "--",
        bin(),
        "--version",
    ])
    .await;
    let stderr = String::from_utf8_lossy(&out.stderr);
    let json = plan_json(&out.stdout);
    assert_eq!(
        out.status.code(),
        Some(0),
        "ready exits 0 (stderr: {stderr})"
    );
    assert_eq!(status_of(&json), "ready");
    // One result must show the target, control layers, and the plan.
    let target = member(json.value(), "target");
    assert!(target.to_member("host_os").is_ok());
    let plan = member(json.value(), "plan");
    let controls = member(plan, "controls");
    let mut layers = std::collections::HashSet::new();
    for c in controls.to_array().unwrap() {
        let layer = member(c, "layer").as_string_str().unwrap().to_string();
        layers.insert(layer);
    }
    assert!(
        layers.contains("launch"),
        "launch-layer controls: {layers:?}"
    );
    assert!(layers.contains("rpc"), "rpc-layer controls: {layers:?}");
}

// ─── plan: no workload launch, no environment mutation ───────────────────

#[cfg(unix)]
#[tokio::test]
async fn plan_does_not_spawn_the_command() {
    let dir = tempfile::tempdir().unwrap();
    let policy = write_policy(&dir);
    let marker = dir.path().join("spawned_marker");
    // If `plan` launched this, the marker would exist afterwards.
    let out = run_plan(&[
        "--policy",
        policy.to_str().unwrap(),
        "--",
        "sh",
        "-c",
        &format!("touch {}", marker.display()),
    ])
    .await;
    let _ = out;
    assert!(
        !marker.exists(),
        "plan must not start the workload (marker exists)"
    );
}

#[cfg(windows)]
#[tokio::test]
async fn plan_does_not_spawn_the_command() {
    let dir = tempfile::tempdir().unwrap();
    let policy = write_policy(&dir);
    let marker = dir.path().join("spawned_marker");
    let out = run_plan(&[
        "--policy",
        policy.to_str().unwrap(),
        "--",
        "cmd",
        "/c",
        &format!("echo. > {}", marker.display()),
    ])
    .await;
    let _ = out;
    assert!(
        !marker.exists(),
        "plan must not start the workload (marker exists)"
    );
}

#[tokio::test]
async fn plan_report_goes_to_file_not_stdout() {
    let dir = tempfile::tempdir().unwrap();
    let policy = write_policy(&dir);
    let report_path = dir.path().join("plan-report.json");
    let out = run_plan(&[
        "--report",
        report_path.to_str().unwrap(),
        "--policy",
        policy.to_str().unwrap(),
        "--",
        bin(),
    ])
    .await;
    assert_eq!(out.status.code(), Some(0), "ready exits 0: {out:?}");
    assert!(
        out.stdout.is_empty(),
        "with --report, JSON goes to the file, not stdout: {:?}",
        String::from_utf8_lossy(&out.stdout)
    );
    let text = std::fs::read_to_string(&report_path).expect("report file written");
    let json = nojson::RawJson::parse(Box::leak(text.into_boxed_str())).unwrap();
    assert_eq!(status_of(&json), "ready");
}

// ─── run --report ────────────────────────────────────────────────────────

async fn run_with_report(args: &[String]) -> std::process::Output {
    timeout(
        Duration::from_secs(TIMEOUT_SECS),
        Command::new(bin())
            .arg("run")
            .args(args)
            .env_remove("MCP_WRIT_SKIP_SANDBOX")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output(),
    )
    .await
    .expect("run timed out")
    .expect("run mcp-writ")
}

fn read_report(path: &Path) -> nojson::RawJson<'static> {
    let text = std::fs::read_to_string(path).expect("report file must exist");
    nojson::RawJson::parse(Box::leak(text.into_boxed_str())).expect("report must be valid JSON")
}

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

/// `--report` to an unwritable destination fails before the workload
/// starts — and never exits successfully.
#[cfg(unix)]
#[tokio::test]
async fn run_report_unwritable_path_fails_before_spawn() {
    let dir = tempfile::tempdir().unwrap();
    let policy = write_policy(&dir);
    let audit_log = dir.path().join("audit.jsonl");
    let bad_report = dir.path().join("no_such_dir").join("report.json");
    let marker = dir.path().join("spawned_marker");

    let out = run_with_report(&[
        "--policy".into(),
        policy.to_string_lossy().into_owned(),
        "--audit-log".into(),
        audit_log.to_string_lossy().into_owned(),
        "--report".into(),
        bad_report.to_string_lossy().into_owned(),
        "--".into(),
        "sh".into(),
        "-c".into(),
        format!("touch {}", marker.display()),
    ])
    .await;

    assert_eq!(
        out.status.code(),
        Some(1),
        "an unsavable --report must never exit successfully"
    );
    assert!(
        !marker.exists(),
        "the workload must not start when --report is unsavable"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("launch report"),
        "stderr must name the report failure: {stderr}"
    );
}
