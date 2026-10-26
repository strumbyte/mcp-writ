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
    let dir = common::real_tempdir();
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

    // The `enforcement` member is a digest of the same plan/observations
    // the report carries — not a second computation. Each plan control's
    // effective state (last matching observation, else the plan state)
    // must read identically in both places.
    let connected_json =
        nojson::RawJson::parse(connected).expect("server.connected line must be JSON");
    let enf = member(connected_json.value(), "enforcement");
    assert_eq!(member(enf, "backend").as_string_str().unwrap(), "none");
    assert_eq!(member(enf, "dry_run").as_boolean_str().unwrap(), "true");

    let plan_controls: Vec<(String, String)> = member(json.value(), "plan")
        .to_member("controls")
        .unwrap()
        .required()
        .unwrap()
        .to_array()
        .unwrap()
        .map(|c| {
            (
                member(c, "id").as_string_str().unwrap().to_string(),
                member(c, "state").as_string_str().unwrap().to_string(),
            )
        })
        .collect();
    let observations: Vec<(String, String)> = member(json.value(), "observations")
        .to_array()
        .unwrap()
        .map(|o| {
            (
                member(o, "control").as_string_str().unwrap().to_string(),
                member(o, "state").as_string_str().unwrap().to_string(),
            )
        })
        .collect();
    let enf_controls: Vec<(String, String)> = member(enf, "controls")
        .to_array()
        .unwrap()
        .map(|c| {
            (
                member(c, "id").as_string_str().unwrap().to_string(),
                member(c, "state").as_string_str().unwrap().to_string(),
            )
        })
        .collect();
    for (id, plan_state) in &plan_controls {
        let effective = observations
            .iter()
            .rev()
            .find(|(cid, _)| cid == id)
            .map(|(_, s)| s.clone())
            .unwrap_or_else(|| plan_state.clone());
        let jsonl_state = enf_controls
            .iter()
            .find(|(cid, _)| cid == id)
            .map(|(_, s)| s.clone())
            .unwrap_or_else(|| panic!("enforcement.controls missing {id}: {connected}"));
        assert_eq!(
            jsonl_state, effective,
            "control {id} disagrees between server.connected and the report"
        );
    }
}

/// A launch that never reaches a session still records the plan and a
/// `failed` result — never an empty success.
#[tokio::test]
async fn run_report_on_launch_failure_is_failed_not_empty() {
    let dir = common::real_tempdir();
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

/// PR-33 — allowlisted names the parent environment lacks (or whose
/// value reads as a single absolute path with nothing behind it) are
/// diagnosed by name on the `launch.env` observation, the
/// `server.connected` details, and stderr — values never leak into any
/// of them, and the gap is recorded, never a refusal.
#[tokio::test]
async fn run_env_allowlist_gaps_are_diagnosed() {
    let dir = common::real_tempdir();
    let mut policy = common::sandboxed_policy("", "");
    let at = common::kdl_named_insert_pos(&policy, "defaults", 0).expect("defaults block");
    policy.insert_str(
        at,
        "    environment {\n        allow \"MCP_WRIT_E2E_KEEP\" \"MCP_WRIT_E2E_MISSING\" \"MCP_WRIT_E2E_PATH_GONE\"\n    }\n",
    );
    let policy_path = dir.path().join("policy.kdl");
    std::fs::write(&policy_path, &policy).expect("write policy");
    let audit_log = dir.path().join("audit.jsonl");
    let report_path = dir.path().join("report.json");
    // A dangling single absolute path: absolute, nonexistent.
    let gone = dir.path().join("mcp_writ_e2e_gone_9b7f.bin");

    let mut args: Vec<String> = vec![
        "--dry-run".into(),
        "--policy".into(),
        policy_path.to_string_lossy().into_owned(),
        "--audit-log".into(),
        audit_log.to_string_lossy().into_owned(),
        "--report".into(),
        report_path.to_string_lossy().into_owned(),
        "--".into(),
    ];
    args.extend(common::echo_stdio_argv());

    let mut child = Command::new(bin())
        .arg("run")
        .args(&args)
        .env("MCP_WRIT_E2E_KEEP", "mcp-writ-e2e-secret-6w3v")
        .env("MCP_WRIT_E2E_PATH_GONE", &gone)
        .env_remove("MCP_WRIT_E2E_MISSING")
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
    assert_eq!(
        out.status.code(),
        Some(0),
        "a missing allowlisted var is a diagnosis, not a refusal (stderr: {})",
        String::from_utf8_lossy(&out.stderr)
    );

    // stdout stays JSON-RPC only — the diagnosis never touches the wire.
    let stdout = String::from_utf8_lossy(&out.stdout);
    for line in stdout.lines() {
        assert!(
            line.starts_with("{\"jsonrpc\""),
            "stdout must carry only JSON-RPC frames: {line}"
        );
    }

    // stderr warns, naming the absent name and the dangling-path name —
    // never a value.
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains(
            "warning: allowlisted environment variable(s) not set in the parent \
             environment: MCP_WRIT_E2E_MISSING"
        ),
        "stderr must name the absent allowlisted var: {stderr}"
    );
    assert!(
        stderr.contains(
            "warning: allowlisted environment variable(s) whose value names a path \
             that does not exist: MCP_WRIT_E2E_PATH_GONE"
        ),
        "stderr must name the dangling-path allowlisted var: {stderr}"
    );

    // The launch.env observation records the launch-time snapshot.
    let json = read_report(&report_path);
    let reason = member(json.value(), "observations")
        .to_array()
        .expect("observations array")
        .find(|o| member(*o, "control").as_string_str().unwrap() == "launch.env")
        .and_then(|o| {
            o.to_member("reason")
                .ok()
                .and_then(|m| m.optional())
                .and_then(|v| v.as_string_str().ok().map(|s| s.to_string()))
        })
        .expect("launch.env observation must carry the contract reason");
    assert!(
        reason.contains("env contract: 3 allowlisted name(s): 2 present, 1 missing"),
        "contract counts: {reason}"
    );
    assert!(
        reason.contains("missing: MCP_WRIT_E2E_MISSING"),
        "the absent name is diagnosed: {reason}"
    );
    assert!(
        reason.contains("path missing: MCP_WRIT_E2E_PATH_GONE"),
        "the dangling path is diagnosed by name: {reason}"
    );

    // The plan side of the same report carries the same names under the
    // plan wording — `run` builds its own plan, so the snapshot matches
    // the observation's launch-time one here.
    let plan_reason = member(json.value(), "plan")
        .to_member("controls")
        .expect("plan.controls")
        .required()
        .expect("plan.controls")
        .to_array()
        .expect("controls array")
        .find(|c| member(*c, "id").as_string_str().unwrap() == "launch.env")
        .and_then(|c| {
            member(c, "reason")
                .as_string_str()
                .ok()
                .map(|s| s.to_string())
        })
        .expect("launch.env plan reason");
    assert!(
        plan_reason
            .contains("restricted to the base set + 3 allowlisted name(s): 2 present, 1 missing"),
        "plan-side contract counts: {plan_reason}"
    );
    assert!(
        plan_reason.contains("missing: MCP_WRIT_E2E_MISSING")
            && plan_reason.contains("path missing: MCP_WRIT_E2E_PATH_GONE"),
        "the plan reason names the same gaps: {plan_reason}"
    );

    // The same gaps ride the server.connected audit details — names only.
    let audit = std::fs::read_to_string(&audit_log).expect("audit log");
    let connected = audit
        .lines()
        .find(|l| l.contains("\"event_type\":\"server.connected\""))
        .unwrap_or_else(|| panic!("audit log missing server.connected: {audit}"));
    assert!(
        connected.contains("env_missing=MCP_WRIT_E2E_MISSING"),
        "server.connected names the absent allowlisted var: {connected}"
    );
    assert!(
        connected.contains("env_path_missing=MCP_WRIT_E2E_PATH_GONE"),
        "server.connected names the dangling-path var: {connected}"
    );

    // Values never leak — not the secret, not the checked path spelling —
    // into the report, the audit log, or stderr.
    let report_text = std::fs::read_to_string(&report_path).expect("report text");
    for sink in [report_text.as_str(), audit.as_str(), stderr.as_ref()] {
        assert!(
            !sink.contains("mcp-writ-e2e-secret-6w3v"),
            "the variable value must never be recorded: {sink}"
        );
        assert!(
            !sink.contains("mcp_writ_e2e_gone_9b7f"),
            "the checked path spelling must never be recorded: {sink}"
        );
    }
}
