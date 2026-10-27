//! PR-14 e2e: `check` drift re-verification (clean / drifted / invalid /
//! error exit codes, per-pin outcomes, `-- <command>` launch binding,
//! REVIEW markers in-band) and the `MCP_WRIT_REVIEW_MODE` load-time
//! gate (`warn` default, `refuse` strict opt-in).

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
/// `policy_path_str` spells the target the way KDL text needs it —
/// forward slashes, no `\\?\` prefix (a Windows `display()` spelling
/// would embed `\` escapes the parser rejects).
fn server_with_pin(name: &str, kind: &str, digest: &str, target: &Path) -> String {
    format!(
        "server \"{name}\" {{\n    tool \"probe\"\n    {kind} \"{digest}\" target=\"{}\"\n}}\n",
        common::policy_path_str(target)
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
        common::policy_path_str(&bin_file),
        sha256_of(&entry_file),
        common::policy_path_str(&entry_file),
        sha256_of(&lock_file),
        common::policy_path_str(&lock_file),
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
    // One marker per classification surface: a generated-template kind,
    // another kind, and a hand-written note that stays `custom`.
    std::fs::write(
        &path,
        format!(
            "// Policy Draft - Auto-generated by MCP Writ\n\
             // REVIEW: header: all entries before deploying\n\
             {}\n\
             // REVIEW: unbound-workload: entrypoint-hash not emitted: test\n\
             // REVIEW: unbound payload npx\n",
            common::sandboxed_policy("", "server \"svc\" {\n    tool \"probe\"\n}\n")
        ),
    )
    .unwrap();

    let out = run_check(&["--policy".into(), policy_arg(&path)]).await;
    assert_eq!(out.status.code(), Some(1), "stderr: {}", stderr_text(&out));
    let json = check_json(&out.stdout);
    assert_eq!(
        member(json.value(), "schema_version")
            .as_string_str()
            .unwrap(),
        "1",
        "enriched markers must not move the schema version"
    );
    assert_eq!(status_of(&json), "drifted");
    assert_eq!(reason_code_of(&json).as_deref(), Some("unresolved_review"));
    let markers: Vec<_> = member(json.value(), "review_markers")
        .to_array()
        .unwrap()
        .collect();
    assert_eq!(markers.len(), 3, "header + workload + custom: {markers:?}");
    assert_eq!(
        member(markers[0], "line").as_integer_str().unwrap(),
        "2",
        "the generated header marker sits on line 2"
    );
    let kinds: Vec<_> = markers
        .iter()
        .map(|m| member(*m, "kind").as_string_str().unwrap().to_string())
        .collect();
    assert_eq!(kinds, ["header", "unbound-workload", "custom"]);
    for m in &markers {
        for field in ["why", "how"] {
            assert!(
                !member(*m, field)
                    .to_unquoted_string_str()
                    .unwrap()
                    .is_empty(),
                "{field} must carry the kind's fixed guidance: {m:?}"
            );
        }
    }
    // The custom marker keeps the generic guidance — no generated
    // template's text may leak into a hand-written note.
    assert_eq!(
        member(markers[2], "why")
            .to_unquoted_string_str()
            .unwrap()
            .as_ref(),
        "a marker matching no known generator kind — a hand-written or hand-edited note"
    );

    // stderr prints each marker's location and kind followed by the
    // kind's why and how; remediation enumerates one next action per
    // kind present.
    let stderr = stderr_text(&out);
    assert_eq!(
        stderr.matches("kind:").count(),
        3,
        "one kind line per single-marker kind: {stderr}"
    );
    assert!(
        stderr.contains("kind: unbound-workload") && stderr.contains("kind: custom"),
        "kind lines name the classification: {stderr}"
    );
    assert_eq!(
        stderr.matches("why:").count(),
        3,
        "one why per marker kind: {stderr}"
    );
    assert_eq!(
        stderr.matches("how:").count(),
        3,
        "one how per marker kind: {stderr}"
    );
    assert!(
        stderr.contains("unbound-workload: read the named reason"),
        "remediation must name the kind's next action: {stderr}"
    );
}

#[tokio::test]
async fn check_review_marker_kinds_fixture() {
    // A fixture policy carrying one marker of every known kind plus a
    // hand-written custom note — pins the JSON kind names, that every
    // entry carries the kind's fixed why/how, and that status/exit code
    // stay drifted/1.
    let dir = common::real_tempdir();
    let path = dir.path().join("draft.kdl");
    let marker_lines = [
        "// REVIEW: header: all entries before deploying",
        "// REVIEW: unbound-tool: Tool 'x' is not bound to a literal handler; Capability is not proven",
        "// REVIEW: blocked-capability: CC-001 (critical) — hidden instruction in description",
        "// REVIEW: schema-unsupported: inputSchema uses unsupported schema features ('if'); args_schema omitted",
        "// REVIEW: hash-pin-host: workload hashes pin this host's files — recompute them on the deployment host",
        "// REVIEW: regenerate-on-update: regenerate this draft when the server or its interpreter is updated",
        "// REVIEW: unbound-workload: entrypoint-hash not emitted: inline evaluation is not hash-bindable",
        "// REVIEW: syscall-analysis: syscall analysis status=partial reason=partial_coverage",
        "// REVIEW: syscall-analysis: allowlist below may be incomplete; do not deploy without manual review",
        "// REVIEW: syscall-blocked: execve detected in binary but blocked (excess capability)",
        "// REVIEW: baseline-dropped: baseline entries dropped by blocked permissions: socket, connect",
        "// REVIEW: interpreter-baseline: covers interpreter runtime needs; workload-specific",
        "// REVIEW: non-linux-abi: target uses a non-Linux syscall ABI — the entries below are",
        "// REVIEW: network-outbound: NetworkOutbound capability detected — deny-all stays the",
        "// REVIEW: datagram: datagram syscalls (sendto) — compatible with UDP but",
        "// REVIEW: hand-written note to self",
    ];
    std::fs::write(
        &path,
        format!(
            "{}\n{}\n",
            common::sandboxed_policy("", "server \"svc\" {\n    tool \"probe\"\n}\n"),
            marker_lines.join("\n")
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
    let kinds: Vec<_> = markers
        .iter()
        .map(|m| member(*m, "kind").as_string_str().unwrap().to_string())
        .collect();
    assert_eq!(
        kinds,
        [
            "header",
            "unbound-tool",
            "blocked-capability",
            "schema-unsupported",
            "hash-pin-host",
            "regenerate-on-update",
            "unbound-workload",
            "syscall-analysis",
            "syscall-analysis",
            "syscall-blocked",
            "baseline-dropped",
            "interpreter-baseline",
            "non-linux-abi",
            "network-outbound",
            "datagram",
            "custom",
        ]
    );
    for m in &markers {
        for field in ["why", "how"] {
            assert!(
                !member(*m, field)
                    .to_unquoted_string_str()
                    .unwrap()
                    .is_empty(),
                "{field} must carry the kind's fixed guidance: {m:?}"
            );
        }
    }

    // The two-marker kind aggregates to a count + locations + one
    // why/how; every other kind prints per-marker with its kind line.
    let stderr = stderr_text(&out);
    assert!(
        stderr.contains("syscall-analysis (2 marker(s)):"),
        "multi-marker kind must aggregate: {stderr}"
    );
    assert_eq!(
        stderr.matches("kind:").count(),
        14,
        "kind line per single-marker kind (the grouped kind's header names it): {stderr}"
    );
    assert_eq!(
        stderr.matches("why:").count(),
        15,
        "one why per kind group: {stderr}"
    );
    // Remediation enumerates one next action per kind present, in
    // first-seen order — the numbered prefix keeps a marker's own
    // `REVIEW: <kind>:` line from satisfying the assertion.
    for (n, kind) in [
        "header",
        "unbound-tool",
        "blocked-capability",
        "schema-unsupported",
        "hash-pin-host",
        "regenerate-on-update",
        "unbound-workload",
        "syscall-analysis",
        "syscall-blocked",
        "baseline-dropped",
        "interpreter-baseline",
        "non-linux-abi",
        "network-outbound",
        "datagram",
        "custom",
    ]
    .iter()
    .enumerate()
    {
        assert!(
            stderr.contains(&format!("{}. {kind}:", n + 1)),
            "remediation must list {kind:?}: {stderr}"
        );
    }
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

// ── launch binding via `-- <command>` ─────────────────────────────────

#[tokio::test]
async fn check_command_binds_binary_pin_to_launch_argv() {
    // The check binary itself resolves on every host — pin its image
    // and pass it as the launch argv: the pin binds and verifies.
    let exe = Path::new(bin());
    let dir = common::real_tempdir();
    let server_kdl = format!(
        "server \"svc\" {{\n    tool \"probe\"\n    binary-hash \"{}\" target=\"{}\"\n}}\n",
        sha256_of(exe),
        common::policy_path_str(exe),
    );
    let policy = write_policy(&dir, &server_kdl);

    let out = run_check(&[
        "--policy".into(),
        policy_arg(&policy),
        "--".into(),
        bin().to_string(),
    ])
    .await;
    assert_eq!(out.status.code(), Some(0), "stderr: {}", stderr_text(&out));
    let json = check_json(&out.stdout);
    assert_eq!(status_of(&json), "clean");
    assert_eq!(pin_statuses(&json), vec!["verified"]);
}

#[tokio::test]
async fn check_command_marks_binary_pin_off_the_launch_argv() {
    // The pinned file still holds its digest, but its `target=` no
    // longer names the launched executable — `run` would refuse this
    // binding, so the pin is `mismatch`, not `verified`.
    let dir = common::real_tempdir();
    let moved = dir.path().join("moved-server-bin");
    std::fs::write(&moved, b"binary-payload").unwrap();
    let policy = write_policy(
        &dir,
        &server_with_pin("svc", "binary-hash", &sha256_of(&moved), &moved),
    );

    let out = run_check(&[
        "--policy".into(),
        policy_arg(&policy),
        "--".into(),
        bin().to_string(),
    ])
    .await;
    assert_eq!(out.status.code(), Some(1), "stderr: {}", stderr_text(&out));
    let json = check_json(&out.stdout);
    assert_eq!(status_of(&json), "drifted");
    assert_eq!(reason_code_of(&json).as_deref(), Some("hash_mismatch"));
    assert_eq!(pin_statuses(&json), vec!["mismatch"]);
    let pins: Vec<_> = member(json.value(), "pins").to_array().unwrap().collect();
    // `to_unquoted_string_str` unescapes — the detail carries a Windows
    // path spelling.
    let detail = member(pins[0], "detail").to_unquoted_string_str().unwrap();
    assert!(
        detail.contains("canonicalizes"),
        "the binding failure names the path correspondence, not the content: {detail}"
    );
}

#[tokio::test]
async fn check_command_marks_entrypoint_pin_off_the_payload() {
    // An entrypoint-hash target that is neither the resolved
    // executable nor the first payload argument cannot bind — `run`
    // refuses, so the pin reports `mismatch`.
    let dir = common::real_tempdir();
    let script = dir.path().join("server.py");
    std::fs::write(&script, b"print('entrypoint')").unwrap();
    let policy = write_policy(
        &dir,
        &server_with_pin("svc", "entrypoint-hash", &sha256_of(&script), &script),
    );

    let out = run_check(&[
        "--policy".into(),
        policy_arg(&policy),
        "--".into(),
        bin().to_string(),
    ])
    .await;
    assert_eq!(out.status.code(), Some(1), "stderr: {}", stderr_text(&out));
    let json = check_json(&out.stdout);
    assert_eq!(status_of(&json), "drifted");
    assert_eq!(pin_statuses(&json), vec!["mismatch"]);
    let pins: Vec<_> = member(json.value(), "pins").to_array().unwrap().collect();
    let detail = member(pins[0], "detail").to_unquoted_string_str().unwrap();
    assert!(
        detail.contains("first payload argument"),
        "the detail names the entrypoint correspondence rule: {detail}"
    );
}

#[tokio::test]
async fn check_command_marks_payload_pin_without_interpreter_binary() {
    // `python server.py` with only an entrypoint pin on the script:
    // the pin's `target=` binds the payload argument, but nothing pins
    // the resolved interpreter — `run` refuses that binding, so the
    // pin reports `mismatch`, not `verified`.
    let name = if cfg!(windows) { "py" } else { "python3" };
    if mcp_writ::workload::resolve_command_path(name).is_err() {
        common::skip_e2e_test("payload binding: interpreter not on PATH");
        return;
    }
    let script = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/echo_stdio.py");
    let argv = common::python3_script_argv("tests/fixtures/echo_stdio.py");
    let dir = common::real_tempdir();
    let policy = write_policy(
        &dir,
        &server_with_pin("svc", "entrypoint-hash", &sha256_of(&script), &script),
    );

    let mut args = vec!["--policy".into(), policy_arg(&policy), "--".into()];
    args.extend(argv);
    let out = run_check(&args).await;
    assert_eq!(out.status.code(), Some(1), "stderr: {}", stderr_text(&out));
    let json = check_json(&out.stdout);
    assert_eq!(status_of(&json), "drifted");
    assert_eq!(reason_code_of(&json).as_deref(), Some("hash_mismatch"));
    assert_eq!(pin_statuses(&json), vec!["mismatch"]);
    let pins: Vec<_> = member(json.value(), "pins").to_array().unwrap().collect();
    let detail = member(pins[0], "detail").to_unquoted_string_str().unwrap();
    assert!(
        detail.contains("no binary-hash binds the resolved interpreter"),
        "the detail names the missing interpreter pin: {detail}"
    );
}

#[tokio::test]
async fn check_command_marks_payload_pin_on_unmodeled_executable() {
    // A payload-bound entrypoint additionally needs the resolved
    // executable's option grammar to be modeled — on an unmodeled exe
    // the payload boundary cannot be proven, so `run` refuses and the
    // pin reports `mismatch`. The check binary itself has no modeled
    // grammar: a binary pin on it verifies and binds, the payload
    // entrypoint fails the grammar rule.
    let exe = Path::new(bin());
    let dir = common::real_tempdir();
    let payload = dir.path().join("payload.py");
    std::fs::write(&payload, b"print('payload')").unwrap();
    let server_kdl = format!(
        "server \"svc\" {{\n    tool \"probe\"\n    binary-hash \"{}\" target=\"{}\"\n    entrypoint-hash \"{}\" target=\"{}\"\n}}\n",
        sha256_of(exe),
        common::policy_path_str(exe),
        sha256_of(&payload),
        common::policy_path_str(&payload),
    );
    let policy = write_policy(&dir, &server_kdl);

    let out = run_check(&[
        "--policy".into(),
        policy_arg(&policy),
        "--".into(),
        bin().to_string(),
        payload.to_string_lossy().into_owned(),
    ])
    .await;
    assert_eq!(out.status.code(), Some(1), "stderr: {}", stderr_text(&out));
    let json = check_json(&out.stdout);
    assert_eq!(status_of(&json), "drifted");
    assert_eq!(reason_code_of(&json).as_deref(), Some("hash_mismatch"));
    // Policy order: the binary pin verifies and binds; the entrypoint
    // binds the payload but fails the modeled-grammar rule.
    assert_eq!(pin_statuses(&json), vec!["verified", "mismatch"]);
    let pins: Vec<_> = member(json.value(), "pins").to_array().unwrap().collect();
    let detail = member(pins[1], "detail").to_unquoted_string_str().unwrap();
    assert!(
        detail.contains("no modeled option grammar"),
        "the detail names the grammar rule: {detail}"
    );
}

#[tokio::test]
async fn check_command_unresolvable_leaves_identity_pin_unverified() {
    // `-- <command>` that cannot resolve cannot be binding-checked:
    // the pin reports `unverified`, never a false `verified`.
    let dir = common::real_tempdir();
    let target = dir.path().join("server-bin");
    std::fs::write(&target, b"binary-payload").unwrap();
    let policy = write_policy(
        &dir,
        &server_with_pin("svc", "binary-hash", &sha256_of(&target), &target),
    );

    let out = run_check(&[
        "--policy".into(),
        policy_arg(&policy),
        "--".into(),
        "mcp-writ-no-such-command-9f3d2".to_string(),
    ])
    .await;
    assert_eq!(out.status.code(), Some(1), "stderr: {}", stderr_text(&out));
    let json = check_json(&out.stdout);
    assert_eq!(status_of(&json), "drifted");
    assert_eq!(reason_code_of(&json).as_deref(), Some("pin_unverified"));
    assert_eq!(pin_statuses(&json), vec!["unverified"]);
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

#[tokio::test]
async fn check_report_write_failure_is_error() {
    // A `--report` destination inside a directory that does not exist
    // fails the atomic write — status `error` (exit 1), and the
    // machine-readable result still lands on stdout.
    let dir = common::real_tempdir();
    let policy = write_policy(&dir, "server \"svc\" {\n    tool \"probe\"\n}\n");
    let report_path = dir.path().join("no-such-dir").join("report.json");

    let out = run_check(&[
        "--policy".into(),
        policy_arg(&policy),
        "--report".into(),
        policy_arg(&report_path),
    ])
    .await;
    assert_eq!(out.status.code(), Some(1), "stderr: {}", stderr_text(&out));
    let json = check_json(&out.stdout);
    assert_eq!(status_of(&json), "error");
    assert_eq!(
        reason_code_of(&json).as_deref(),
        Some("report_write_failed")
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
        .to_unquoted_string_str()
        .unwrap()
        .into_owned();
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

// ── version-3 migration preview (PR-36) ──────────────────────────────

#[tokio::test]
async fn check_reports_version3_migration_diff() {
    // A v2 `extends` pair whose composition changes under v3 rules —
    // the child's `allow` replaces the base list under v2 but unions
    // under v3. `check` reports the preview in-band; status and exit
    // code do not move.
    let dir = common::real_tempdir();
    std::fs::write(
        dir.path().join("base.kdl"),
        "policy version=2\ndefaults {\n    syscalls {\n        allow \"read\" \"execve\"\n    }\n}\n",
    )
    .unwrap();
    let policy = dir.path().join("policy.kdl");
    std::fs::write(
        &policy,
        "extends \"base.kdl\"\npolicy version=2\ndefaults {\n    syscalls {\n        allow \"write\"\n    }\n}\nserver \"svc\" {\n    tool \"probe\"\n}\n",
    )
    .unwrap();

    let out = run_check(&["--policy".into(), policy_arg(&policy)]).await;
    assert_eq!(
        out.status.code(),
        Some(0),
        "migration info must not move the exit code: {}",
        stderr_text(&out)
    );
    let json = check_json(&out.stdout);
    assert_eq!(status_of(&json), "clean");

    let migration = member(json.value(), "migration");
    assert_eq!(
        member(migration, "declared_version")
            .as_number_str()
            .unwrap(),
        "2"
    );
    assert_eq!(
        member(migration, "candidate_version")
            .as_number_str()
            .unwrap(),
        "3"
    );
    assert_eq!(
        member(migration, "status").as_string_str().unwrap(),
        "fields_differ"
    );
    let fields: Vec<_> = member(migration, "fields").to_array().unwrap().collect();
    let entry = fields
        .iter()
        .find(|f| member(**f, "field").as_string_str().unwrap() == "defaults.syscalls.allowed")
        .expect("defaults.syscalls.allowed must be listed");
    let declared: Vec<String> = member(*entry, "declared")
        .to_array()
        .unwrap()
        .map(|v| v.as_string_str().unwrap().to_string())
        .collect();
    let simulated: Vec<String> = member(*entry, "simulated")
        .to_array()
        .unwrap()
        .map(|v| v.as_string_str().unwrap().to_string())
        .collect();
    assert_eq!(declared, vec!["write"], "v2 replaces the base list");
    assert_eq!(
        simulated,
        vec!["execve", "read", "write"],
        "v3 unions the base list"
    );

    // Two rows move, not one: the defaults list, and the same list
    // materialized onto `tool "probe"` — the tool's effective
    // `syscalls.allowed` is a distinct field in the diff.
    assert_eq!(
        fields.len(),
        2,
        "defaults.syscalls.allowed and its materialized tool copy: {fields:?}"
    );
    let stderr = stderr_text(&out);
    assert!(
        stderr.contains(
            "info: policy version 2 — 2 field(s) would compose differently under version 3 (see policy resolve --version-diff)"
        ),
        "stderr carries the one-line preview: {stderr}"
    );
}

#[tokio::test]
async fn check_reports_version3_migration_unchanged() {
    // A single-file policy has no composition to re-interpret — v3
    // rules compose it identically, and that is still reported.
    let dir = common::real_tempdir();
    let policy = write_policy(&dir, "server \"svc\" {\n    tool \"probe\"\n}\n");

    let out = run_check(&["--policy".into(), policy_arg(&policy)]).await;
    assert_eq!(out.status.code(), Some(0), "stderr: {}", stderr_text(&out));
    let json = check_json(&out.stdout);
    assert_eq!(status_of(&json), "clean");
    let migration = member(json.value(), "migration");
    assert_eq!(
        member(migration, "declared_version")
            .as_number_str()
            .unwrap(),
        "1"
    );
    assert_eq!(
        member(migration, "candidate_version")
            .as_number_str()
            .unwrap(),
        "3"
    );
    assert_eq!(
        member(migration, "status").as_string_str().unwrap(),
        "unchanged"
    );
    assert_eq!(
        member(migration, "fields").to_array().unwrap().count(),
        0,
        "unchanged carries no field rows"
    );
    assert!(
        member(migration, "reason").kind().is_null(),
        "reason is null unless the simulated load failed"
    );
    let stderr = stderr_text(&out);
    assert!(
        stderr.contains("info: policy version 1 — composes identically under version 3"),
        "stderr carries the identical-composition line: {stderr}"
    );
}

#[tokio::test]
async fn check_reports_version3_migration_simulation_failed() {
    // The v2 extends pair loads because the child's `allow` replaces
    // the base tool's filesystem allow side — deny stays accumulated,
    // and "/srv/secret" sits under no allowed path. Under v3 the allow
    // side unions instead, so the inherited deny lands under the
    // inherited "/srv" grant and the simulated load fails validation:
    // `check` reports that failure as the preview, and status and
    // exit code still do not move.
    let dir = common::real_tempdir();
    std::fs::write(
        dir.path().join("base.kdl"),
        "policy version=2\nserver \"svc\" {\n    tool \"probe\" {\n        filesystem {\n            allow \"/srv\"\n            deny \"/srv/secret\"\n        }\n    }\n}\n",
    )
    .unwrap();
    let policy = dir.path().join("policy.kdl");
    std::fs::write(
        &policy,
        "extends \"base.kdl\"\npolicy version=2\nserver \"svc\" {\n    tool \"probe\" {\n        filesystem {\n            allow \"/other\"\n        }\n    }\n}\n",
    )
    .unwrap();

    let out = run_check(&["--policy".into(), policy_arg(&policy)]).await;
    assert_eq!(
        out.status.code(),
        Some(0),
        "a failed simulation is informational, not a finding: {}",
        stderr_text(&out)
    );
    let json = check_json(&out.stdout);
    assert_eq!(status_of(&json), "clean");

    let migration = member(json.value(), "migration");
    assert_eq!(
        member(migration, "status").as_string_str().unwrap(),
        "simulation_failed"
    );
    assert_eq!(
        member(migration, "fields").to_array().unwrap().count(),
        0,
        "a failed simulation carries no field rows"
    );
    let reason = member(migration, "reason").as_string_str().unwrap();
    assert!(
        reason.contains("denied under allowed parent path"),
        "reason names the v3-rules load failure: {reason}"
    );

    let stderr = stderr_text(&out);
    assert!(
        stderr.contains("info: policy version 2 — simulated version 3 load failed:"),
        "stderr carries the simulation-failure line: {stderr}"
    );
}

#[tokio::test]
async fn check_v3_policy_reports_null_migration() {
    // Already on version 3 — nothing to preview: `migration` is `null`
    // and no info line is printed.
    let dir = common::real_tempdir();
    let path = dir.path().join("policy.kdl");
    std::fs::write(
        &path,
        "policy version=3\nserver \"svc\" {\n    tool \"probe\"\n}\n",
    )
    .unwrap();

    let out = run_check(&["--policy".into(), policy_arg(&path)]).await;
    assert_eq!(out.status.code(), Some(0), "stderr: {}", stderr_text(&out));
    let json = check_json(&out.stdout);
    let migration = member(json.value(), "migration");
    assert!(
        migration.kind().is_null(),
        "v3 policies report migration: null — got {migration:?}"
    );
    assert!(
        !stderr_text(&out).contains("info: policy version"),
        "no info line when there is nothing to migrate"
    );
}

fn stderr_text(out: &std::process::Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}
