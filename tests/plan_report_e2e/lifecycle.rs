//! Launch lifecycle audit records: the guard/policy/session/server
//! event bracket around a run, each correlated to the launch_id,
//! across policy errors, skip-sandbox, fail-on, and launch failure.

use std::path::Path;
use std::process::Stdio;

use tokio::io::AsyncWriteExt;
use tokio::process::Command;
use tokio::time::{Duration, timeout};

use crate::common;
use crate::support::*;

// ─── audit lifecycle events ──────────────────────────────────────────────

/// The JSONL audit stream's event types, in file order.
fn audit_event_types(path: &Path) -> Vec<String> {
    std::fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .filter_map(|l| {
            l.split("\"event_type\":\"")
                .nth(1)
                .and_then(|rest| rest.split('"').next())
                .map(|s| s.to_string())
        })
        .collect()
}

/// Event types that bracket a launch lifecycle — the records whose
/// `correlation_id` must equal the report's `launch_id`. Per-request
/// `mcp_message.*` records carry their own request correlation.
const LIFECYCLE_TYPES: &[&str] = &[
    "guard.started",
    "policy.loaded",
    "policy.error",
    "session.started",
    "server.connected",
    "server.disconnected",
    "session.ended",
    "guard.stopped",
    "server.error",
];

fn lifecycle_lines(path: &Path) -> Vec<String> {
    std::fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .filter(|l| {
            LIFECYCLE_TYPES
                .iter()
                .any(|t| l.contains(&format!("\"event_type\":\"{t}\"")))
        })
        .map(|l| l.to_string())
        .collect()
}

fn type_index(types: &[String], t: &str) -> Option<usize> {
    types.iter().position(|x| x == t)
}

/// A completed session writes the full lifecycle bracket — started →
/// loaded → session/server open → close — each record correlated to the
/// report's launch_id, and the session's flags are on `guard.started`.
#[tokio::test]
async fn run_audit_lifecycle_brackets_session() {
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
    drop(stdin);
    let out = timeout(Duration::from_secs(TIMEOUT_SECS), child.wait_with_output())
        .await
        .expect("run timed out")
        .expect("wait mcp-writ");
    assert_eq!(
        out.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // The full bracket, in order. `mcp_message.allowed` records sit
    // inside it carrying their own request correlation ids.
    let types = audit_event_types(&audit_log);
    for expected in [
        "guard.started",
        "policy.loaded",
        "session.started",
        "server.connected",
        "server.disconnected",
        "session.ended",
        "guard.stopped",
    ] {
        assert!(
            types.iter().any(|t| t == expected),
            "audit log missing {expected}: {types:?}"
        );
    }
    assert!(
        type_index(&types, "guard.started") < type_index(&types, "policy.loaded"),
        "order: {types:?}"
    );
    assert!(
        type_index(&types, "policy.loaded") < type_index(&types, "session.started"),
        "order: {types:?}"
    );
    assert!(
        type_index(&types, "session.started") < type_index(&types, "server.connected"),
        "order: {types:?}"
    );
    assert!(
        type_index(&types, "server.disconnected") < type_index(&types, "session.ended"),
        "order: {types:?}"
    );
    assert!(
        type_index(&types, "session.ended") < type_index(&types, "guard.stopped"),
        "order: {types:?}"
    );

    // Every lifecycle record correlates with the report's launch_id.
    let json = read_report(&report_path);
    let launch_id = member(json.value(), "launch_id")
        .as_string_str()
        .unwrap()
        .to_string();
    let corr = format!("\"correlation_id\":\"{launch_id}\"");
    for line in lifecycle_lines(&audit_log) {
        assert!(
            line.contains(&corr),
            "lifecycle record uncorrelated: {line}"
        );
        // Every lifecycle record also stamps the emitting logger's
        // session_id — the per-process attribution when host and guest
        // JSONL streams merge under one launch id.
        assert!(
            line.contains("session_id="),
            "lifecycle record missing session_id: {line}"
        );
    }

    // Session-level flags land on guard.started; the fail_on dial and
    // policy identity land on policy.loaded. The skipped sandbox and the
    // spawn's own record agree: server.connected names the same effect.
    let started = lifecycle_lines(&audit_log)
        .into_iter()
        .find(|l| l.contains("\"event_type\":\"guard.started\""))
        .unwrap();
    assert!(started.contains("dry_run=true"), "got: {started}");
    assert!(started.contains("component=mcp-writ"), "got: {started}");
    let connected = lifecycle_lines(&audit_log)
        .into_iter()
        .find(|l| l.contains("\"event_type\":\"server.connected\""))
        .unwrap();
    assert!(connected.contains("sandbox=skipped"), "got: {connected}");
    assert!(connected.contains("(dry-run)"), "got: {connected}");
    assert!(connected.contains("backend=none"), "got: {connected}");
    // The structured `enforcement` member mirrors the same plan facts —
    // a dry-run launch skips the OS sandbox, so `backend` is `none` and
    // no `os.*` control reads as applied (`skipped` for the ones that
    // could have applied; `not_applicable`/`not_applied` for controls
    // already ineligible at plan build).
    let connected_json =
        nojson::RawJson::parse(&connected).expect("server.connected line must be JSON");
    let enf = member(connected_json.value(), "enforcement");
    assert_eq!(member(enf, "backend").as_string_str().unwrap(), "none");
    assert_eq!(member(enf, "dry_run").as_boolean_str().unwrap(), "true");
    for c in member(enf, "controls").to_array().unwrap() {
        let id = member(c, "id").as_string_str().unwrap();
        if id.starts_with("os.") {
            let state = member(c, "state").as_string_str().unwrap();
            assert_ne!(
                state, "verified",
                "dry-run os control {id} must never read applied: {connected}"
            );
            assert_ne!(
                state, "partially_applied",
                "dry-run os control {id} must never read applied: {connected}"
            );
        }
    }
    assert!(
        member(enf, "psec").kind().is_null(),
        "non-psec launch serializes enforcement.psec as null"
    );
    let loaded = std::fs::read_to_string(&audit_log)
        .unwrap()
        .lines()
        .find(|l| l.contains("\"event_type\":\"policy.loaded\""))
        .unwrap()
        .to_string();
    assert!(loaded.contains("fail_on=high"), "got: {loaded}");
    assert!(loaded.contains("\"policy_version\":\"1\""), "got: {loaded}");
    // No weakening dial was configured, so none is recorded — an absent
    // token is what "full configured control" looks like.
    assert!(!loaded.contains("allow_degraded"), "got: {loaded}");

    // A server-less policy never reports "default" as the target server.
    for line in lifecycle_lines(&audit_log) {
        assert!(
            !line.contains("\"target_server\":\"default\""),
            "the default label is not a target server: {line}"
        );
    }
}

/// A refused policy load still brackets the audit stream —
/// `guard.started` → `policy.error` → `guard.stopped` — under the same
/// launch_id the failed report carries.
#[tokio::test]
async fn run_audit_policy_error_is_bracketed() {
    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("no_such_policy.kdl");
    let audit_log = dir.path().join("audit.jsonl");
    let report_path = dir.path().join("report.json");

    let out = run_with_report(&[
        "--policy".into(),
        missing.to_string_lossy().into_owned(),
        "--audit-log".into(),
        audit_log.to_string_lossy().into_owned(),
        "--report".into(),
        report_path.to_string_lossy().into_owned(),
        "--".into(),
        "cat".into(),
    ])
    .await;

    assert_eq!(out.status.code(), Some(1), "refused launch exits 1");
    let json = read_report(&report_path);
    assert_eq!(
        member(member(json.value(), "result"), "status")
            .as_string_str()
            .unwrap(),
        "failed"
    );
    let launch_id = member(json.value(), "launch_id")
        .as_string_str()
        .unwrap()
        .to_string();

    let types = audit_event_types(&audit_log);
    assert_eq!(
        types,
        vec!["guard.started", "policy.error", "guard.stopped"],
        "a refused load writes exactly the abort bracket: {types:?}"
    );
    let corr = format!("\"correlation_id\":\"{launch_id}\"");
    for line in std::fs::read_to_string(&audit_log).unwrap().lines() {
        assert!(line.contains(&corr), "uncorrelated: {line}");
        assert!(line.contains("session_id="), "missing session_id: {line}");
    }
    let content = std::fs::read_to_string(&audit_log).unwrap();
    assert!(content.contains("stage=load"), "got: {content}");
    assert!(content.contains("status=aborted"), "got: {content}");
    // A refused launch never produced an effective policy.
    assert!(
        content.contains("\"policy_id\":null"),
        "policy.error carries no policy identity: {content}"
    );
}

/// `MCP_WRIT_SKIP_SANDBOX` is a recorded weakening — `guard.started`
/// names it — not just a stderr note.
#[tokio::test]
async fn run_audit_skip_sandbox_is_recorded() {
    let dir = tempfile::tempdir().unwrap();
    let policy = write_policy(&dir);
    let audit_log = dir.path().join("audit.jsonl");

    let argv = common::echo_stdio_argv();
    let mut args: Vec<String> = vec![
        "--policy".into(),
        policy.to_string_lossy().into_owned(),
        "--audit-log".into(),
        audit_log.to_string_lossy().into_owned(),
        "--".into(),
    ];
    args.extend(argv);

    let out = timeout(
        Duration::from_secs(TIMEOUT_SECS),
        Command::new(bin())
            .arg("run")
            .args(&args)
            .env("MCP_WRIT_SKIP_SANDBOX", "1")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output(),
    )
    .await
    .expect("run timed out")
    .expect("run mcp-writ");
    assert_eq!(
        out.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let content = std::fs::read_to_string(&audit_log).unwrap();
    let started = content
        .lines()
        .find(|l| l.contains("\"event_type\":\"guard.started\""))
        .expect("guard.started must exist");
    assert!(
        started.contains("sandbox=skipped via MCP_WRIT_SKIP_SANDBOX"),
        "the bypass must be on the record: {started}"
    );
    let connected = content
        .lines()
        .find(|l| l.contains("\"event_type\":\"server.connected\""))
        .expect("server.connected must exist");
    assert!(
        connected.contains("sandbox=skipped"),
        "the skipped sandbox must be visible on the spawn record: {connected}"
    );
    // Same fact on the structured member: `MCP_WRIT_SKIP_SANDBOX` means
    // `backend` is `none` — the record never implies enforcement ran.
    let connected_json =
        nojson::RawJson::parse(connected).expect("server.connected line must be JSON");
    let enf = member(connected_json.value(), "enforcement");
    assert_eq!(
        member(enf, "backend").as_string_str().unwrap(),
        "none",
        "a skipped OS sandbox must report backend=none"
    );
}

/// `sandbox allow_degraded=#true` is a configured weakening — the dial
/// lands on `policy.loaded` so a tolerated-partial launch never reads
/// as full control.
#[tokio::test]
async fn run_audit_allow_degraded_is_recorded() {
    let dir = tempfile::tempdir().unwrap();
    let policy_path = dir.path().join("policy.kdl");
    std::fs::write(
        &policy_path,
        format!(
            "{}\nsandbox allow_degraded=#true\n",
            common::sandboxed_policy("", "")
        ),
    )
    .expect("write policy");
    let audit_log = dir.path().join("audit.jsonl");

    let argv = common::echo_stdio_argv();
    let mut args: Vec<String> = vec![
        "--dry-run".into(),
        "--policy".into(),
        policy_path.to_string_lossy().into_owned(),
        "--audit-log".into(),
        audit_log.to_string_lossy().into_owned(),
        "--".into(),
    ];
    args.extend(argv);

    let out = timeout(
        Duration::from_secs(TIMEOUT_SECS),
        Command::new(bin())
            .arg("run")
            .args(&args)
            .env_remove("MCP_WRIT_SKIP_SANDBOX")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output(),
    )
    .await
    .expect("run timed out")
    .expect("run mcp-writ");
    assert_eq!(
        out.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let content = std::fs::read_to_string(&audit_log).unwrap();
    let loaded = content
        .lines()
        .find(|l| l.contains("\"event_type\":\"policy.loaded\""))
        .expect("policy.loaded must exist");
    assert!(loaded.contains("allow_degraded=true"), "got: {loaded}");
}

/// `fail-on none` lands on `policy.loaded` even when the session
/// produced no findings — the dial is part of the launch's record.
#[tokio::test]
async fn run_audit_fail_on_none_is_recorded() {
    let dir = tempfile::tempdir().unwrap();
    let policy = write_policy(&dir);
    let audit_log = dir.path().join("audit.jsonl");

    let argv = common::echo_stdio_argv();
    let mut args: Vec<String> = vec![
        "--dry-run".into(),
        "--policy".into(),
        policy.to_string_lossy().into_owned(),
        "--audit-log".into(),
        audit_log.to_string_lossy().into_owned(),
        "--".into(),
    ];
    args.extend(argv);

    let out = timeout(
        Duration::from_secs(TIMEOUT_SECS),
        Command::new(bin())
            .arg("run")
            .args(&args)
            .env_remove("MCP_WRIT_SKIP_SANDBOX")
            .env("MCP_WRIT_FAIL_ON", "none")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output(),
    )
    .await
    .expect("run timed out")
    .expect("run mcp-writ");
    assert_eq!(
        out.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let content = std::fs::read_to_string(&audit_log).unwrap();
    let loaded = content
        .lines()
        .find(|l| l.contains("\"event_type\":\"policy.loaded\""))
        .expect("policy.loaded must exist");
    assert!(loaded.contains("fail_on=none"), "got: {loaded}");
}

/// A launch that fails before the session opens never silently drops
/// the bracket — `server.error` plus `guard.stopped` land, and no
/// `session.started` pretends a session ran.
#[tokio::test]
async fn run_audit_launch_failure_closes_guard_without_session() {
    let dir = tempfile::tempdir().unwrap();
    let policy = write_policy(&dir);
    let audit_log = dir.path().join("audit.jsonl");

    let out = run_with_report(&[
        "--policy".into(),
        policy.to_string_lossy().into_owned(),
        "--audit-log".into(),
        audit_log.to_string_lossy().into_owned(),
        "--".into(),
        "mcp-writ-definitely-not-a-real-command-xyz".into(),
    ])
    .await;

    assert_eq!(out.status.code(), Some(1), "launch failure exits 1");
    let types = audit_event_types(&audit_log);
    assert!(
        types.iter().any(|t| t == "server.error"),
        "missing server.error: {types:?}"
    );
    assert_eq!(
        types.last().map(String::as_str),
        Some("guard.stopped"),
        "the guard bracket closes last: {types:?}"
    );
    assert!(
        !types.iter().any(|t| t == "session.started"),
        "no session ran: {types:?}"
    );
    let stopped = std::fs::read_to_string(&audit_log)
        .unwrap()
        .lines()
        .find(|l| l.contains("\"event_type\":\"guard.stopped\""))
        .unwrap()
        .to_string();
    assert!(stopped.contains("status=failed"), "got: {stopped}");

    // `server.error` carries the same structured member — the failed
    // launch's plan digest, under the same correlation, naming the
    // mechanism the launch would have enforced with.
    let server_error = std::fs::read_to_string(&audit_log)
        .unwrap()
        .lines()
        .find(|l| l.contains("\"event_type\":\"server.error\""))
        .unwrap()
        .to_string();
    let parsed = nojson::RawJson::parse(&server_error).expect("server.error line must be JSON");
    let enf = member(parsed.value(), "enforcement");
    assert_eq!(enf.kind(), nojson::JsonValueKind::Object);
    let backend = member(enf, "backend").as_string_str().unwrap();
    #[cfg(target_os = "windows")]
    assert_eq!(backend, "appcontainer");
    #[cfg(target_os = "linux")]
    assert_eq!(backend, "landlock+seccomp");
    #[cfg(target_os = "macos")]
    assert_eq!(backend, "sandbox-exec");
    // Fallback hosts (and any future mechanism) still name a member of
    // the backend vocabulary — never an empty string.
    assert!(
        [
            "landlock+seccomp",
            "appcontainer",
            "psec",
            "sandbox-exec",
            "none"
        ]
        .contains(&backend),
        "unknown backend name: {backend}"
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
