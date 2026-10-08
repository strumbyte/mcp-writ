//! plan subcommand diagnostics: the four fixed statuses and their
//! exit codes, the never-launch contract, and --report file output.

use std::process::Stdio;

use tokio::process::Command;
use tokio::time::{Duration, timeout};

use crate::common;
use crate::support::*;

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
    // No `logging` line: `fail_closed` defaults to true. Same unix
    // requirement as `write_policy`: `defaults.syscalls` must carry the
    // `execve` startup grant or the Linux rule build fails the plan.
    let syscalls = if cfg!(unix) {
        common::FIXTURE_SYSCALLS_KDL
    } else {
        ""
    };
    let policy_path = dir.path().join("policy.kdl");
    std::fs::write(
        &policy_path,
        format!(
            "policy version=1\ndefaults {{\n    filesystem {{\n        secret-overlay #true\n    }}\n{syscalls}}}\n"
        ),
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

/// A `docker-manifest-hash`-only policy (passes policy validation — it is
/// not a file hash) carries no launch-target pin: `hash.identity` must
/// fail rather than counting the entries as process bindings.
#[tokio::test]
async fn plan_image_only_hash_entries_fail_hash_identity() {
    let dir = tempfile::tempdir().unwrap();
    let policy_path = dir.path().join("policy.kdl");
    std::fs::write(
        &policy_path,
        common::sandboxed_policy(
            "",
            "server \"img-only\" {\n    docker-manifest-hash \"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\" {\n        target \"registry.example/app\"\n    }\n}\n",
        ),
    )
    .expect("write policy");
    let out = run_plan(&[
        "--policy",
        policy_path.to_str().unwrap(),
        "--",
        bin(),
        "--version",
    ])
    .await;
    let stderr = String::from_utf8_lossy(&out.stderr);
    let json = plan_json(&out.stdout);
    assert_eq!(
        out.status.code(),
        Some(1),
        "unbound launch must block (stderr: {stderr})"
    );
    assert_eq!(status_of(&json), "blocked");
    let check = member(json.value(), "checks")
        .to_array()
        .unwrap()
        .find(|c| member(*c, "id").as_string_str().unwrap() == "hash.identity")
        .expect("hash.identity check must be present");
    assert_eq!(member(check, "status").as_string_str().unwrap(), "fail");
    assert!(
        member(check, "detail")
            .as_string_str()
            .unwrap()
            .contains("no binary-hash/entrypoint-hash"),
        "the detail must name the missing launch-target pins"
    );
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
    // The marker check is only meaningful when `plan` itself ran to a
    // ready result — a crashed or refused plan says nothing about
    // workload launch.
    assert!(out.status.success(), "plan run must succeed: {out:?}");
    assert_eq!(status_of(&plan_json(&out.stdout)), "ready");
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
    // The marker check is only meaningful when `plan` itself ran to a
    // ready result — a crashed or refused plan says nothing about
    // workload launch.
    assert!(out.status.success(), "plan run must succeed: {out:?}");
    assert_eq!(status_of(&plan_json(&out.stdout)), "ready");
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
