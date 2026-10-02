//! Workload-hash end-to-end tests (PR5).
//!
//! `generate-policy` emits launch-target hashes inside the `server` block and
//! `run` binds and verifies those same targets:
//!   native:      `binary-hash` pins the resolved argv[0] image. Tampering
//!                with the file after drafting fails the launch closed.
//!   interpreted: `binary-hash` pins the interpreter and `entrypoint-hash`
//!                pins the first payload argument (the script). Tampering
//!                with the script fails the launch.
//!   unbindable:  `python -m`, inline eval — no hash is fabricated; the
//!                draft carries the reason as a REVIEW comment, and running
//!                an inline-eval argv against a pinned binary fails closed.
//!
//! Warden is skipped via `--dry-run` / `MCP_WRIT_SKIP_SANDBOX` (same contract
//! as `tests/tool_enforcement_e2e.rs`); hash verification runs before spawn
//! regardless of dry-run.

use std::path::{Path, PathBuf};
use std::process::Stdio;

use tempfile::TempDir;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::Command;
use tokio::time::{Duration, timeout};

mod common;

const TIMEOUT_SECS: u64 = 12;

struct ChildGuard(tokio::process::Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.start_kill();
    }
}

fn make_test_dir(label: &str) -> TempDir {
    tempfile::Builder::new()
        .prefix(&format!("mcp_writ_workload_hash_{label}_"))
        .tempdir()
        .expect("failed to create temp directory")
}

fn mcp_writ() -> PathBuf {
    common::mcp_writ_bin()
}

/// `generate-policy` over `child_argv`; returns (stdout draft, stderr).
async fn generate_policy(child_argv: &[String], extra: &[&str]) -> (String, String) {
    let mut cmd = Command::new(mcp_writ());
    cmd.arg("generate-policy");
    cmd.args(extra);
    cmd.arg("--");
    cmd.args(child_argv);
    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
    let out = cmd.output().await.expect("spawn generate-policy");
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    assert!(
        out.status.success(),
        "generate-policy failed: {stderr}\nstdout: {stdout}"
    );
    (stdout, stderr)
}

/// Write the generated draft as `<dir>/policy.kdl` and return its path.
fn write_policy(dir: &Path, content: &str) -> PathBuf {
    let path = dir.join("policy.kdl");
    std::fs::write(&path, content).expect("write policy");
    path
}

fn spawn_guard_args(
    policy_path: &Path,
    child_argv: &[String],
    extra: &[&str],
) -> tokio::process::Child {
    let mut cmd = Command::new(mcp_writ());
    cmd.args([
        "run",
        "--transport",
        "stdio",
        "--policy",
        policy_path.to_str().expect("policy path utf-8"),
        "--audit-log",
        common::next_audit_log_path()
            .to_str()
            .expect("audit log path is utf-8"),
        "--dry-run",
    ]);
    cmd.args(extra);
    cmd.arg("--");
    cmd.args(child_argv);
    cmd.env("MCP_WRIT_SKIP_SANDBOX", "1");
    // A timed-out `wait_with_output` drops the Child mid-poll — the
    // process must not be left running.
    cmd.kill_on_drop(true);
    cmd.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn mcp-writ binary - did you run `cargo build`?")
}

fn spawn_guard(policy_path: &Path, child_argv: &[String]) -> tokio::process::Child {
    spawn_guard_args(policy_path, child_argv, &[])
}

/// `spawn_guard` plus `--report <path>` — the launch report lands in the
/// file at every outcome (including pre-spawn failures).
fn spawn_guard_report(
    policy_path: &Path,
    child_argv: &[String],
    report_path: &Path,
) -> tokio::process::Child {
    spawn_guard_args(
        policy_path,
        child_argv,
        &["--report", report_path.to_str().expect("report path utf-8")],
    )
}

const INITIALIZE: &str = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"workload-hash-e2e","version":"0.0.0"}}}"#;

/// Drive one `initialize` over the child's pipes; the response must be a
/// JSON-RPC result (the server answered through the Auditor relay).
async fn drive_handshake(child: &mut tokio::process::Child) {
    let mut stdin = child.stdin.take().expect("stdin");
    let stdout = child.stdout.take().expect("stdout");
    let mut reader = BufReader::new(stdout).lines();

    stdin
        .write_all(format!("{INITIALIZE}\n").as_bytes())
        .await
        .expect("write initialize");
    stdin.flush().await.expect("flush initialize");

    let line = timeout(Duration::from_secs(TIMEOUT_SECS), async {
        loop {
            let line = reader
                .next_line()
                .await
                .expect("IO error reading mcp-writ stdout")
                .expect("unexpected EOF on mcp-writ stdout - child may have exited");
            if line.starts_with("{\"jsonrpc\"") {
                return line;
            }
        }
    })
    .await
    .expect("timeout waiting for initialize response");

    let json = nojson::RawJson::parse(&line).expect("response is JSON");
    assert!(
        json.value()
            .to_member("result")
            .ok()
            .and_then(|m| m.optional())
            .is_some(),
        "initialize must return a result, got: {line}"
    );
}

/// Launch `run` under the draft policy and drive one `initialize`; the
/// response must be a JSON-RPC result (the server answered through the
/// Auditor relay).
async fn assert_handshake_ok(policy_path: &Path, child_argv: &[String]) {
    let mut child = ChildGuard(spawn_guard(policy_path, child_argv));
    drive_handshake(&mut child.0).await;
    // Wait for the kill to complete — Windows keeps the exe image locked
    // until the process actually exits.
    child.0.kill().await.expect("kill guard");
}

/// Spawn `run` and wait for it to exit on its own (verification failure
/// exits 1). Returns (exit code, stderr).
async fn spawn_and_wait(policy_path: &Path, child_argv: &[String]) -> (Option<i32>, String) {
    let child = spawn_guard(policy_path, child_argv);
    let out = timeout(Duration::from_secs(TIMEOUT_SECS), child.wait_with_output())
        .await
        .expect("run must exit after supply-chain refusal")
        .expect("wait on mcp-writ");
    (
        out.status.code(),
        String::from_utf8_lossy(&out.stderr).to_string(),
    )
}

fn hash_entry(
    policy: &mcp_writ::policy::Policy,
    hash_type: mcp_writ::policy::HashType,
) -> &mcp_writ::policy::HashEntry {
    policy
        .hash_entries
        .iter()
        .find(|e| e.hash_type == hash_type)
        .unwrap_or_else(|| panic!("{} must land in Policy.hash_entries", hash_type.as_str()))
}

/// The policy loader needs a `.kdl` file; write the draft and load it through
/// the same path `run` uses.
fn load_draft(dir: &Path, draft: &str) -> mcp_writ::policy::Policy {
    let path = write_policy(dir, draft);
    mcp_writ::policy::kdl_loader::load_kdl_policy(&path).expect("draft loads as policy")
}

#[tokio::test]
async fn native_binary_hash_binds_and_tamper_fails() {
    let Some(fixture) = common::compiled_open_path_fixture() else {
        return; // helper already reported the skip reason
    };
    let dir = make_test_dir("native");
    // Per-test copy: the tamper step must not corrupt the shared fixture.
    let exe = dir
        .path()
        .join(format!("srv{}", std::env::consts::EXE_SUFFIX));
    std::fs::copy(&fixture, &exe).expect("copy fixture exe");
    let argv = vec![exe.to_string_lossy().into_owned()];

    let (draft, _stderr) = generate_policy(&argv, &["--static-only"]).await;
    assert!(
        draft.contains("binary-hash \"sha256:"),
        "native draft must carry binary-hash: {draft}"
    );

    let policy = load_draft(dir.path(), &draft);
    let entry = hash_entry(&policy, mcp_writ::policy::HashType::Binary);
    let canonical_exe = std::fs::canonicalize(&exe).expect("canonicalize exe");
    let expected = mcp_writ::verifier::hash::hash_file(&canonical_exe).expect("hash exe");
    assert_eq!(
        entry.hash_value, expected,
        "emitted binary-hash must equal the file's digest"
    );
    assert!(
        mcp_writ::verifier::hash::verify_hash(Path::new(&entry.target), &expected)
            .expect("target readable"),
        "binary-hash target must be the launched file"
    );

    let policy_path = write_policy(dir.path(), &draft);
    assert_handshake_ok(&policy_path, &argv).await;

    // Tamper with the pinned file: the launch must fail closed. The
    // grandchild server exits on stdin EOF after the guard dies; on Windows
    // the exe image stays locked until it does, so poll the write.
    let mut tampered = false;
    for _ in 0..(TIMEOUT_SECS * 20) {
        if std::fs::write(&exe, b"tampered workload").is_ok() {
            tampered = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(tampered, "tamper exe");
    let (code, stderr) = spawn_and_wait(&policy_path, &argv).await;
    assert_eq!(
        code,
        Some(1),
        "tampered launch must exit 1, stderr: {stderr}"
    );
    assert!(
        stderr.contains("Supply chain verification failed"),
        "tampered launch must report supply-chain refusal: {stderr}"
    );
}

/// The interpreter these tests draft and launch (`py` on Windows, `python3`
/// elsewhere) is a prerequisite like the rustc fixture — absent it, the
/// generated draft simply lacks `binary-hash`, so skip instead of failing.
fn interpreter_or_skip(test: &str) -> Option<&'static str> {
    let name = if cfg!(windows) { "py" } else { "python3" };
    if mcp_writ::workload::resolve_command_path(name).is_err() {
        common::skip_e2e_test(&format!("{test}: {name} not on PATH"));
        return None;
    }
    Some(name)
}

#[tokio::test]
async fn interpreted_entrypoint_hash_binds_and_tamper_fails() {
    let Some(interp) = interpreter_or_skip("interpreted") else {
        return;
    };
    let dir = make_test_dir("interp");
    // Per-test script copy so tampering does not touch the repo fixture.
    let script_src = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/mcp_servers/scripted_stdio.py");
    let script = dir.path().join("server.py");
    std::fs::copy(&script_src, &script).expect("copy script fixture");

    let argv: Vec<String> = if cfg!(windows) {
        vec![
            interp.to_string(),
            "-3".to_string(),
            script.to_string_lossy().into_owned(),
        ]
    } else {
        vec![interp.to_string(), script.to_string_lossy().into_owned()]
    };

    let (draft, _stderr) = generate_policy(&argv, &["--static-only"]).await;
    assert!(
        draft.contains("binary-hash \"sha256:"),
        "interpreted draft must pin the interpreter: {draft}"
    );
    assert!(
        draft.contains("entrypoint-hash \"sha256:"),
        "interpreted draft must pin the script: {draft}"
    );

    let policy = load_draft(dir.path(), &draft);
    let entry = hash_entry(&policy, mcp_writ::policy::HashType::Entrypoint);
    let canonical_script = std::fs::canonicalize(&script).expect("canonicalize script");
    let expected = mcp_writ::verifier::hash::hash_file(&canonical_script).expect("hash script");
    assert_eq!(
        entry.hash_value, expected,
        "emitted entrypoint-hash must equal the script's digest"
    );

    let policy_path = write_policy(dir.path(), &draft);
    assert_handshake_ok(&policy_path, &argv).await;

    // Tamper with the script: verify_server_hashes catches the mismatch
    // before the process is even spawned. Retry briefly — Windows keeps a
    // just-exited child's files locked momentarily.
    let mut tampered = false;
    for _ in 0..(TIMEOUT_SECS * 20) {
        if std::fs::write(&script, "# tampered\n").is_ok() {
            tampered = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(tampered, "tamper script");
    let (code, stderr) = spawn_and_wait(&policy_path, &argv).await;
    assert_eq!(
        code,
        Some(1),
        "tampered launch must exit 1, stderr: {stderr}"
    );
    assert!(
        stderr.contains("Supply chain verification failed"),
        "tampered launch must report supply-chain refusal: {stderr}"
    );
}

#[tokio::test]
async fn module_and_inline_eval_emit_reason_not_fabricated_hash() {
    let Some(python0) = interpreter_or_skip("module/inline-eval") else {
        return;
    };
    let dir = make_test_dir("unbound");

    // `python -m <module>`: the module object cannot be bound from argv.
    let argv = vec![
        python0.to_string(),
        "-m".to_string(),
        "some_uninstalled_module_xyz".to_string(),
    ];
    let (draft, _stderr) = generate_policy(&argv, &["--static-only"]).await;
    assert!(
        draft.contains("// REVIEW: entrypoint-hash not emitted"),
        "module launch must explain the missing pin: {draft}"
    );
    assert!(
        !draft.contains("entrypoint-hash \""),
        "module launch must not fabricate a hash: {draft}"
    );

    // `python -c '...'`: inline evaluation has no file to pin.
    let argv = vec![
        python0.to_string(),
        "-c".to_string(),
        "import sys".to_string(),
    ];
    let (draft, _stderr) = generate_policy(&argv, &["--static-only"]).await;
    assert!(
        draft.contains("// REVIEW: entrypoint-hash not emitted"),
        "inline eval must explain the missing pin: {draft}"
    );
    assert!(
        !draft.contains("entrypoint-hash \""),
        "inline eval must not fabricate a hash: {draft}"
    );

    // When the interpreter itself resolved (binary-hash in the draft), `run`
    // on the inline-eval argv must refuse: inline eval is not hash-bindable.
    if draft.contains("binary-hash \"") {
        let policy_path = write_policy(dir.path(), &draft);
        let (code, stderr) = spawn_and_wait(&policy_path, &argv).await;
        assert_eq!(code, Some(1), "inline eval must be refused: {stderr}");
        assert!(
            stderr.contains("Supply chain verification failed"),
            "inline eval refusal must be a supply-chain failure: {stderr}"
        );
    }

    // Delegating launchers exec a command selected at run time: the draft
    // must record that the launcher pin does not bind the inner command,
    // instead of presenting the policy as fully bound.
    let argv = if cfg!(windows) {
        vec!["py".to_string(), "-3".to_string(), "server.py".to_string()]
    } else {
        vec![
            "env".to_string(),
            "FOO=1".to_string(),
            "python3".to_string(),
            "server.py".to_string(),
        ]
    };
    let (draft, _stderr) = generate_policy(&argv, &["--static-only"]).await;
    let launcher_note = if cfg!(windows) {
        "'py' selects the Python interpreter"
    } else {
        "delegating launcher 'env'"
    };
    assert!(
        draft.contains(launcher_note),
        "delegating launcher must flag the unbound selection: {draft}"
    );
}

fn member<'j>(v: nojson::RawJsonValue<'j, 'j>, key: &str) -> nojson::RawJsonValue<'j, 'j> {
    v.to_member(key)
        .unwrap_or_else(|_| panic!("member '{key}' must exist"))
        .required()
        .unwrap_or_else(|_| panic!("member '{key}' must exist"))
}

fn read_report(path: &Path) -> nojson::RawJson<'static> {
    let text = std::fs::read_to_string(path).expect("report file must exist");
    nojson::RawJson::parse(Box::leak(text.into_boxed_str())).expect("report must be valid JSON")
}

fn checks_of(pin: nojson::RawJsonValue<'_, '_>) -> Vec<String> {
    member(pin, "checks")
        .to_array()
        .unwrap()
        .map(|c| c.as_string_str().unwrap().to_string())
        .collect()
}

/// The launch report's `code_identity` records the actual scope and
/// timing of the hash pins — per pin `role` and which check points ran —
/// and what stays mutable.
#[tokio::test]
async fn report_records_code_identity_checkpoints() {
    let Some(interp) = interpreter_or_skip("code-identity") else {
        return;
    };
    let dir = make_test_dir("identity");
    let script_src = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/mcp_servers/scripted_stdio.py");
    let script = dir.path().join("server.py");
    std::fs::copy(&script_src, &script).expect("copy script fixture");

    let argv: Vec<String> = if cfg!(windows) {
        vec![
            interp.to_string(),
            "-3".to_string(),
            script.to_string_lossy().into_owned(),
        ]
    } else {
        vec![interp.to_string(), script.to_string_lossy().into_owned()]
    };

    let (draft, _stderr) = generate_policy(&argv, &["--static-only"]).await;
    if !draft.contains("binary-hash \"") || !draft.contains("entrypoint-hash \"") {
        common::skip_e2e_test("code-identity: draft lacks both pins");
        return;
    }
    let policy_path = write_policy(dir.path(), &draft);
    let report_path = dir.path().join("launch-report.json");

    // A launch that reaches the session recorded every check point on
    // both pins — initial verification, binding, and the pre-spawn
    // re-verify each ran and passed.
    {
        let mut child = ChildGuard(spawn_guard_report(&policy_path, &argv, &report_path));
        drive_handshake(&mut child.0).await;
        child.0.kill().await.expect("kill guard");
    }
    let report = read_report(&report_path);
    let ci = member(report.value(), "code_identity");
    assert_eq!(
        member(ci, "kind").as_string_str().unwrap(),
        "interpreted_script"
    );
    assert!(
        member(ci, "resolved").to_unquoted_string_str().is_ok(),
        "resolved must be the (possibly escaped) executable path"
    );
    let pins: Vec<_> = member(ci, "pins").to_array().unwrap().collect();
    assert_eq!(pins.len(), 2, "binary + entrypoint pins: {pins:?}");
    let all_points = [
        "initial",
        "bind_path",
        "bind_content",
        "pre_spawn_path",
        "pre_spawn_content",
    ];
    for pin in &pins {
        let checks = checks_of(*pin);
        assert_eq!(
            checks,
            all_points.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
            "pin {} must record all five check points",
            member(*pin, "type").as_string_str().unwrap()
        );
    }
    let roles: Vec<String> = pins
        .iter()
        .map(|p| member(*p, "role").as_string_str().unwrap().to_string())
        .collect();
    assert!(roles.contains(&"exec_image".to_string()), "{roles:?}");
    assert!(roles.contains(&"payload_file".to_string()), "{roles:?}");
    // The residual scope is stated, not hidden.
    assert!(member(ci, "pinned").to_array().unwrap().count() > 0);
    let mutable: Vec<String> = member(ci, "mutable")
        .to_array()
        .unwrap()
        .map(|m| m.as_string_str().unwrap().to_string())
        .collect();
    assert!(
        mutable.iter().any(|m| m.contains("immutable")),
        "the hash-to-exec window must be named: {mutable:?}"
    );

    // A tampered script fails at the initial verification — the failure
    // report still carries the record, and the failed pin shows only the
    // check points that actually passed.
    let mut tampered = false;
    for _ in 0..(TIMEOUT_SECS * 20) {
        if std::fs::write(&script, "# tampered\n").is_ok() {
            tampered = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(tampered, "tamper script");
    let fail_report_path = dir.path().join("fail-report.json");
    let child = spawn_guard_report(&policy_path, &argv, &fail_report_path);
    let out = timeout(Duration::from_secs(TIMEOUT_SECS), child.wait_with_output())
        .await
        .expect("run must exit after supply-chain refusal")
        .expect("wait on mcp-writ");
    assert_eq!(out.status.code(), Some(1), "tampered launch must exit 1");
    let report = read_report(&fail_report_path);
    assert_eq!(
        member(member(report.value(), "result"), "status")
            .as_string_str()
            .unwrap(),
        "failed"
    );
    let ci = member(report.value(), "code_identity");
    let pins: Vec<_> = member(ci, "pins").to_array().unwrap().collect();
    let entrypoint = pins
        .iter()
        .find(|p| member(**p, "type").as_string_str().unwrap() == "entrypoint-hash")
        .expect("entrypoint pin must be present");
    assert!(
        !checks_of(*entrypoint).contains(&"pre_spawn_content".to_string()),
        "a pin that failed initial verification must not claim pre-spawn checks"
    );
}
