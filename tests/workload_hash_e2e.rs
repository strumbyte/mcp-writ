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

fn spawn_guard(policy_path: &Path, child_argv: &[String]) -> tokio::process::Child {
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
        "--",
    ]);
    cmd.args(child_argv);
    cmd.env("MCP_WRIT_SKIP_SANDBOX", "1");
    cmd.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn mcp-writ binary - did you run `cargo build`?")
}

const INITIALIZE: &str = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"workload-hash-e2e","version":"0.0.0"}}}"#;

/// Launch `run` under the draft policy and drive one `initialize`; the
/// response must be a JSON-RPC result (the server answered through the
/// Auditor relay).
async fn assert_handshake_ok(policy_path: &Path, child_argv: &[String]) {
    let mut child = ChildGuard(spawn_guard(policy_path, child_argv));
    let mut stdin = child.0.stdin.take().expect("stdin");
    let stdout = child.0.stdout.take().expect("stdout");
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
        std::thread::sleep(Duration::from_millis(50));
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

#[tokio::test]
async fn interpreted_entrypoint_hash_binds_and_tamper_fails() {
    let dir = make_test_dir("interp");
    // Per-test script copy so tampering does not touch the repo fixture.
    let script_src = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/mcp_servers/scripted_stdio.py");
    let script = dir.path().join("server.py");
    std::fs::copy(&script_src, &script).expect("copy script fixture");

    let argv: Vec<String> = if cfg!(windows) {
        vec![
            "py".to_string(),
            "-3".to_string(),
            script.to_string_lossy().into_owned(),
        ]
    } else {
        vec!["python3".to_string(), script.to_string_lossy().into_owned()]
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
        std::thread::sleep(Duration::from_millis(50));
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
    let python0 = if cfg!(windows) { "py" } else { "python3" };
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
