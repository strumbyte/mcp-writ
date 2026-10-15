//! PR-14 e2e: `check` drift re-verification (clean / drifted / invalid /
//! error exit codes, per-pin outcomes, REVIEW markers in-band) and the
//! `MCP_WRIT_REVIEW_MODE` load-time gate (`warn` default, `refuse`
//! strict opt-in).

// The repo-wide test helpers live in tests/common/mod.rs.
mod common;

use std::path::{Path, PathBuf};
use std::process::Stdio;

use tempfile::TempDir;
use tokio::process::Command;
use tokio::time::{Duration, timeout};

const TIMEOUT_SECS: u64 = 30;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_mcp-writ")
}

fn sha256_of(path: &Path) -> String {
    mcp_writ::verifier::hash::hash_file(path).expect("hash fixture file")
}

/// Minimal loadable policy: the shared sandboxed skeleton plus `server_kdl`.
fn write_policy(dir: &TempDir, server_kdl: &str) -> PathBuf {
    let path = dir.path().join("policy.kdl");
    std::fs::write(&path, common::sandboxed_policy("", server_kdl)).expect("write policy");
    path
}

/// `server "<name>"` block carrying one `kind` pin for `target`.
fn server_with_pin(name: &str, kind: &str, digest: &str, target: &Path) -> String {
    format!(
        "server \"{name}\" {{\n    tool \"probe\"\n    {kind} \"{digest}\" target=\"{}\"\n}}\n",
        target.display()
    )
}

async fn run_check(args: &[String]) -> std::process::Output {
    run_check_env(args, &[]).await
}

/// `run_check` with extra environment overrides.
async fn run_check_env(args: &[String], env: &[(&str, &str)]) -> std::process::Output {
    let mut cmd = Command::new(bin());
    cmd.arg("check")
        .args(args)
        .env_remove("MCP_WRIT_REVIEW_MODE")
        .env_remove("MCP_WRIT_ENV")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (k, v) in env {
        cmd.env(k, v);
    }
    timeout(Duration::from_secs(TIMEOUT_SECS), cmd.output())
        .await
        .expect("check timed out")
        .expect("run mcp-writ check")
}

fn check_json(stdout: &[u8]) -> nojson::RawJson<'static> {
    let s = String::from_utf8(stdout.to_vec()).expect("utf8 stdout");
    let trimmed = s.trim();
    nojson::RawJson::parse(Box::leak(trimmed.to_string().into_boxed_str()))
        .expect("stdout must be the check JSON result")
}

fn member<'j>(v: nojson::RawJsonValue<'j, 'j>, key: &str) -> nojson::RawJsonValue<'j, 'j> {
    v.to_member(key)
        .unwrap_or_else(|_| panic!("member '{key}' must exist"))
        .required()
        .unwrap_or_else(|_| panic!("member '{key}' must exist"))
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

fn pin_statuses(json: &nojson::RawJson) -> Vec<String> {
    member(json.value(), "pins")
        .to_array()
        .unwrap()
        .map(|p| member(p, "status").as_string_str().unwrap().to_string())
        .collect()
}

fn policy_arg(path: &Path) -> String {
    path.display().to_string()
}

// ── clean ─────────────────────────────────────────────────────────────

#[tokio::test]
async fn check_clean_when_file_pins_match() {
    let dir = common::real_tempdir();
    let bin_file = dir.path().join("server-bin");
    let entry_file = dir.path().join("server.py");
    let lock_file = dir.path().join("requirements.txt");
    std::fs::write(&bin_file, b"binary-payload").unwrap();
    std::fs::write(&entry_file, b"print('entrypoint')").unwrap();
    std::fs::write(&lock_file, b"dep==1.0\n").unwrap();

    let server_kdl = format!(
        "server \"svc\" {{\n    tool \"probe\"\n    binary-hash \"{}\" target=\"{}\"\n    entrypoint-hash \"{}\" target=\"{}\"\n    lockfile-hash \"{}\" target=\"{}\"\n}}\n",
        sha256_of(&bin_file),
        bin_file.display(),
        sha256_of(&entry_file),
        entry_file.display(),
        sha256_of(&lock_file),
        lock_file.display(),
    );
    let policy = write_policy(&dir, &server_kdl);

    let out = run_check(&["--policy".into(), policy_arg(&policy)]).await;
    assert_eq!(out.status.code(), Some(0), "stderr: {}", stderr_text(&out));
    let json = check_json(&out.stdout);
    assert_eq!(status_of(&json), "clean");
    assert_eq!(reason_code_of(&json), None);
    assert_eq!(
        pin_statuses(&json),
        vec!["verified", "verified", "verified"]
    );
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("3 pin(s) verified"),
        "stderr summary must name the verified count: {}",
        stderr_text(&out)
    );
}

// ── drifted: mismatch / unreadable / unverified / review ──────────────

#[tokio::test]
async fn check_binary_mismatch_is_drifted() {
    let dir = common::real_tempdir();
    let target = dir.path().join("server-bin");
    std::fs::write(&target, b"original").unwrap();
    let policy = write_policy(
        &dir,
        &server_with_pin("svc", "binary-hash", &sha256_of(&target), &target),
    );
    // Drift after review: the artifact changed since the pin was taken.
    std::fs::write(&target, b"tampered").unwrap();

    let out = run_check(&["--policy".into(), policy_arg(&policy)]).await;
    assert_eq!(out.status.code(), Some(1), "stderr: {}", stderr_text(&out));
    let json = check_json(&out.stdout);
    assert_eq!(status_of(&json), "drifted");
    assert_eq!(reason_code_of(&json).as_deref(), Some("hash_mismatch"));
    assert_eq!(pin_statuses(&json), vec!["mismatch"]);
    // The observed digest is reported, not just the verdict.
    let pins: Vec<_> = member(json.value(), "pins").to_array().unwrap().collect();
    assert_eq!(
        member(pins[0], "pin_type").as_string_str().unwrap(),
        "binary-hash"
    );
    assert_eq!(
        member(pins[0], "actual").as_string_str().unwrap(),
        sha256_of(&target)
    );
}

#[tokio::test]
async fn check_unreadable_pin_target_is_drifted() {
    let dir = common::real_tempdir();
    let missing = dir.path().join("gone.py");
    let policy = write_policy(
        &dir,
        &server_with_pin(
            "svc",
            "entrypoint-hash",
            &format!("sha256:{}", "0".repeat(64)),
            &missing,
        ),
    );

    let out = run_check(&["--policy".into(), policy_arg(&policy)]).await;
    assert_eq!(out.status.code(), Some(1));
    let json = check_json(&out.stdout);
    assert_eq!(status_of(&json), "drifted");
    assert_eq!(reason_code_of(&json).as_deref(), Some("target_unreadable"));
    assert_eq!(pin_statuses(&json), vec!["unreadable"]);
}

#[tokio::test]
async fn check_tools_list_pin_without_command_is_unverified() {
    let dir = common::real_tempdir();
    let server_kdl = format!(
        "server \"svc\" {{\n    tool \"probe\"\n    tools-list-hash \"sha256:{}\"\n}}\n",
        "0".repeat(64)
    );
    let policy = write_policy(&dir, &server_kdl);

    let out = run_check(&["--policy".into(), policy_arg(&policy)]).await;
    assert_eq!(out.status.code(), Some(1));
    let json = check_json(&out.stdout);
    assert_eq!(status_of(&json), "drifted");
    assert_eq!(reason_code_of(&json).as_deref(), Some("pin_unverified"));
    assert_eq!(pin_statuses(&json), vec!["unverified"]);
}

#[tokio::test]
async fn check_tools_list_match_and_mismatch() {
    // The fixture serves one `read_file` tool over MCP 2025-11-25; the
    // in-test fetch computes the digest `check` must reproduce.
    let name = if cfg!(windows) { "py" } else { "python3" };
    if mcp_writ::workload::resolve_command_path(name).is_err() {
        common::skip_e2e_test("check_tools_list: interpreter not on PATH");
        return;
    }
    let argv = common::python3_script_argv("tests/fixtures/mcp_servers/mcp_2025_11_25.py");
    let fetched = mcp_writ::legislator::tools_list::fetch_tools_list(&argv, None)
        .await
        .expect("fixture tools/list fetch");
    let digest =
        mcp_writ::verifier::tools_diff::hash_tools_list(&fetched).expect("hash fetched tools list");

    let dir = common::real_tempdir();
    let policy = write_policy(
        &dir,
        &format!("server \"svc\" {{\n    tool \"probe\"\n    tools-list-hash \"{digest}\"\n}}\n"),
    );
    // check options first, then `-- <command>` as the tools/list source.
    let mut args = vec!["--policy".into(), policy_arg(&policy), "--".into()];
    args.extend(argv.iter().cloned());

    let out = run_check(&args).await;
    assert_eq!(out.status.code(), Some(0), "stderr: {}", stderr_text(&out));
    let json = check_json(&out.stdout);
    assert_eq!(status_of(&json), "clean");
    assert_eq!(pin_statuses(&json), vec!["verified"]);

    // Same fetch source, wrong pin → drift.
    let bad_dir = common::real_tempdir();
    let bad = write_policy(
        &bad_dir,
        &format!(
            "server \"svc\" {{\n    tool \"probe\"\n    tools-list-hash \"sha256:{}\"\n}}\n",
            "f".repeat(64)
        ),
    );
    let mut args = vec!["--policy".into(), policy_arg(&bad), "--".into()];
    args.extend(argv.iter().cloned());
    let out = run_check(&args).await;
    assert_eq!(out.status.code(), Some(1));
    let json = check_json(&out.stdout);
    assert_eq!(status_of(&json), "drifted");
    assert_eq!(reason_code_of(&json).as_deref(), Some("hash_mismatch"));
    assert_eq!(pin_statuses(&json), vec!["mismatch"]);
}

#[tokio::test]
async fn check_review_markers_are_drift() {
    let dir = common::real_tempdir();
    let path = dir.path().join("draft.kdl");
    std::fs::write(
        &path,
        format!(
            "// Policy Draft - Auto-generated by MCP Writ\n// REVIEW all entries before deploying\n{}\n// REVIEW: unbound payload npx\n",
            common::sandboxed_policy("", "server \"svc\" {\n    tool \"probe\"\n}\n")
        ),
    )
    .unwrap();

    let out = run_check(&["--policy".into(), policy_arg(&path)]).await;
    assert_eq!(out.status.code(), Some(1), "stderr: {}", stderr_text(&out));
    let json = check_json(&out.stdout);
    assert_eq!(status_of(&json), "drifted");
    assert_eq!(reason_code_of(&json).as_deref(), Some("unresolved_review"));
    let markers: Vec<_> = member(json.value(), "review_markers")
        .to_array()
        .unwrap()
        .collect();
    assert_eq!(markers.len(), 2, "header + payload marker: {markers:?}");
    assert_eq!(
        member(markers[0], "line").as_integer_str().unwrap(),
        "2",
        "the generated header marker sits on line 2"
    );
    assert!(
        member(markers[1], "text")
            .as_string_str()
            .unwrap()
            .contains("unbound payload npx"),
        "the tail marker text is reported verbatim"
    );
}

#[tokio::test]
async fn check_reports_markers_even_under_env_refuse() {
    // `check` is the diagnostics surface: MCP_WRIT_REVIEW_MODE=refuse
    // must not turn it into a load failure — the markers are reported
    // in-band as drift.
    let dir = common::real_tempdir();
    let path = dir.path().join("draft.kdl");
    std::fs::write(
        &path,
        format!(
            "{}\n// REVIEW: payload not bindable\n",
            common::sandboxed_policy("", "server \"svc\" {\n    tool \"probe\"\n}\n")
        ),
    )
    .unwrap();

    let out = run_check_env(
        &["--policy".into(), policy_arg(&path)],
        &[("MCP_WRIT_REVIEW_MODE", "refuse")],
    )
    .await;
    assert_eq!(out.status.code(), Some(1), "stderr: {}", stderr_text(&out));
    let json = check_json(&out.stdout);
    assert_eq!(status_of(&json), "drifted");
    assert_eq!(reason_code_of(&json).as_deref(), Some("unresolved_review"));
}

// ── invalid ───────────────────────────────────────────────────────────

#[tokio::test]
async fn check_missing_policy_file_is_invalid() {
    let dir = common::real_tempdir();
    let missing = dir.path().join("no-such.kdl");
    let out = run_check(&["--policy".into(), policy_arg(&missing)]).await;
    assert_eq!(out.status.code(), Some(2));
    let json = check_json(&out.stdout);
    assert_eq!(status_of(&json), "invalid");
    assert_eq!(reason_code_of(&json).as_deref(), Some("policy_not_found"));
}

#[tokio::test]
async fn check_malformed_policy_is_invalid() {
    let dir = common::real_tempdir();
    let path = dir.path().join("broken.kdl");
    std::fs::write(&path, "{{{{not kdl").unwrap();
    let out = run_check(&["--policy".into(), policy_arg(&path)]).await;
    assert_eq!(out.status.code(), Some(2));
    let json = check_json(&out.stdout);
    assert_eq!(status_of(&json), "invalid");
    assert_eq!(reason_code_of(&json).as_deref(), Some("policy_invalid"));
}

#[tokio::test]
async fn check_without_policy_is_invalid() {
    let out = run_check(&[]).await;
    assert_eq!(out.status.code(), Some(2));
    let json = check_json(&out.stdout);
    assert_eq!(status_of(&json), "invalid");
    assert_eq!(reason_code_of(&json).as_deref(), Some("invalid_input"));
}

#[tokio::test]
async fn check_multi_server_policy_requires_server_flag() {
    let dir = common::real_tempdir();
    let f1 = dir.path().join("bin-a");
    let f2 = dir.path().join("bin-b");
    std::fs::write(&f1, b"a").unwrap();
    std::fs::write(&f2, b"b").unwrap();
    let server_kdl = format!(
        "{}{}",
        server_with_pin("s1", "binary-hash", &sha256_of(&f1), &f1),
        server_with_pin("s2", "binary-hash", &sha256_of(&f2), &f2),
    );
    let policy = write_policy(&dir, &server_kdl);

    // No --server: same refusal a launch would give.
    let out = run_check(&["--policy".into(), policy_arg(&policy)]).await;
    assert_eq!(out.status.code(), Some(2));
    let json = check_json(&out.stdout);
    assert_eq!(reason_code_of(&json).as_deref(), Some("policy_bind_failed"));

    // Bound to s1: only s1's pin is re-verified.
    let out = run_check(&[
        "--policy".into(),
        policy_arg(&policy),
        "--server".into(),
        "s1".into(),
    ])
    .await;
    assert_eq!(out.status.code(), Some(0), "stderr: {}", stderr_text(&out));
    let json = check_json(&out.stdout);
    assert_eq!(status_of(&json), "clean");
    assert_eq!(pin_statuses(&json), vec!["verified"]);
    let pins: Vec<_> = member(json.value(), "pins").to_array().unwrap().collect();
    assert_eq!(member(pins[0], "server").as_string_str().unwrap(), "s1");
}

// ── docker-manifest-hash ──────────────────────────────────────────────

#[tokio::test]
async fn check_docker_manifest_pin_reports_engine_state() {
    // `check` never pulls: with no engine the pin is `unverified`; with
    // an engine but no such image it is `unreadable`. Either way the
    // report is `drifted` and the pin row names its state — a CI gate
    // sees the same verdict on a bare runner and on one with docker.
    let dir = common::real_tempdir();
    let image = "mcp-writ-check-nonexistent.invalid/img:0.0.0";
    let policy = write_policy(
        &dir,
        &format!(
            "server \"svc\" {{\n    tool \"probe\"\n    docker-manifest-hash \"sha256:{}\" target=\"{image}\"\n}}\n",
            "0".repeat(64)
        ),
    );

    let out = run_check(&["--policy".into(), policy_arg(&policy)]).await;
    assert_eq!(out.status.code(), Some(1), "stderr: {}", stderr_text(&out));
    let json = check_json(&out.stdout);
    assert_eq!(status_of(&json), "drifted");
    let statuses = pin_statuses(&json);
    assert_eq!(statuses.len(), 1);
    assert!(
        statuses[0] == "unverified" || statuses[0] == "unreadable",
        "docker-manifest pin must report unverified/unreadable, got {statuses:?}"
    );
}

// ── --report ──────────────────────────────────────────────────────────

#[tokio::test]
async fn check_report_goes_to_file_not_stdout() {
    let dir = common::real_tempdir();
    let policy = write_policy(&dir, "server \"svc\" {\n    tool \"probe\"\n}\n");
    let report_path = dir.path().join("check-report.json");

    let out = run_check(&[
        "--policy".into(),
        policy_arg(&policy),
        "--report".into(),
        policy_arg(&report_path),
    ])
    .await;
    assert_eq!(out.status.code(), Some(0), "stderr: {}", stderr_text(&out));
    assert!(
        out.stdout.is_empty(),
        "--report keeps stdout clear of the JSON result"
    );
    let text = std::fs::read_to_string(&report_path).expect("report file exists");
    let json = nojson::RawJson::parse(Box::leak(text.into_boxed_str()))
        .expect("report file must be valid JSON");
    assert_eq!(
        member(json.value(), "status").as_string_str().unwrap(),
        "clean"
    );
}

// ── MCP_WRIT_REVIEW_MODE at policy load (via `plan`) ──────────────────

async fn run_plan_env(args: &[String], env: &[(&str, &str)]) -> std::process::Output {
    let mut cmd = Command::new(bin());
    cmd.arg("plan")
        .args(args)
        .env_remove("MCP_WRIT_SKIP_SANDBOX")
        .env_remove("MCP_WRIT_FAIL_ON")
        .env_remove("MCP_WRIT_REVIEW_MODE")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (k, v) in env {
        cmd.env(k, v);
    }
    timeout(Duration::from_secs(TIMEOUT_SECS), cmd.output())
        .await
        .expect("plan timed out")
        .expect("run mcp-writ plan")
}

#[tokio::test]
async fn review_mode_warns_by_default_and_refuse_fails_the_load() {
    let dir = common::real_tempdir();
    let path = dir.path().join("draft.kdl");
    std::fs::write(
        &path,
        format!(
            "{}\n// REVIEW: draft marker left unresolved\n",
            common::sandboxed_policy("", "server \"svc\" {\n    tool \"probe\"\n}\n")
        ),
    )
    .unwrap();
    // The test binary itself always resolves — the plan may be `ready`
    // or `blocked` depending on sandbox availability, but never
    // `invalid`: the warn default does not fail the load.
    let plan_args = vec![
        "--policy".into(),
        policy_arg(&path),
        "--".into(),
        bin().to_string(),
    ];

    let out = run_plan_env(&plan_args, &[]).await;
    let stderr = stderr_text(&out);
    assert!(
        stderr.contains("unresolved REVIEW marker"),
        "warn default must print the marker to stderr: {stderr}"
    );
    let json = check_json(&out.stdout);
    assert_ne!(
        reason_code_of(&json).as_deref(),
        Some("policy_invalid"),
        "warn mode must not fail the load: {json:?}"
    );

    // refuse is the opt-in strict gate: the same draft fails the load.
    let out = run_plan_env(&plan_args, &[("MCP_WRIT_REVIEW_MODE", "refuse")]).await;
    assert_eq!(out.status.code(), Some(2), "stderr: {}", stderr_text(&out));
    let json = check_json(&out.stdout);
    assert_eq!(status_of(&json), "invalid");
    assert_eq!(
        reason_code_of(&json).as_deref(),
        Some("policy_invalid"),
        "refuse must fail the load as a policy error"
    );
    let reason = member(json.value(), "reason")
        .to_member("detail")
        .unwrap()
        .required()
        .unwrap()
        .as_string_str()
        .unwrap()
        .to_string();
    assert!(
        reason.contains("REVIEW"),
        "refuse reason must name the markers: {reason}"
    );

    // off silences even the warning — for an intentionally kept draft.
    let out = run_plan_env(&plan_args, &[("MCP_WRIT_REVIEW_MODE", "off")]).await;
    let stderr = stderr_text(&out);
    assert!(
        !stderr.contains("unresolved REVIEW marker"),
        "off must not print the marker warning: {stderr}"
    );
    let json = check_json(&out.stdout);
    assert_ne!(
        reason_code_of(&json).as_deref(),
        Some("policy_invalid"),
        "off must not fail the load: {json:?}"
    );
}

fn stderr_text(out: &std::process::Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}
