#![allow(dead_code)]

use std::path::PathBuf;
use std::process::Command;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};

static AUDIT_DIR: OnceLock<tempfile::TempDir> = OnceLock::new();
static AUDIT_SEQ: AtomicU64 = AtomicU64::new(0);

/// Local development may omit Docker. The release verification job must
/// fail when a prerequisite or fixture build is unavailable instead of
/// reporting an unexecuted container test as successful.
pub fn skip_container_test(reason: &str) {
    assert!(
        std::env::var("MCP_WRIT_REQUIRE_CONTAINER_TESTS").as_deref() != Ok("1"),
        "container test prerequisite failed: {reason} (MCP_WRIT_REQUIRE_CONTAINER_TESTS=1)"
    );
    eprintln!("SKIP: {reason}");
}

/// Evidence e2e tests (`diagnostics_e2e`, `path_resolution_e2e`) may skip
/// when a prerequisite — the rustc fixture build, a sandboxed spawn,
/// symlink/junction creation — is unavailable. The release verification
/// job must fail instead of reporting an unexecuted test as successful.
pub fn skip_e2e_test(reason: &str) {
    assert!(
        std::env::var("MCP_WRIT_REQUIRE_E2E_TESTS").as_deref() != Ok("1"),
        "e2e test prerequisite failed: {reason} (MCP_WRIT_REQUIRE_E2E_TESTS=1)"
    );
    eprintln!("SKIP: {reason}");
}

/// Unique fail-closed audit log path for spawned `mcp-writ run` processes.
pub fn next_audit_log_path() -> PathBuf {
    let dir = AUDIT_DIR.get_or_init(|| {
        tempfile::Builder::new()
            .prefix("mcp_writ_audit_")
            .tempdir()
            .expect("failed to create audit log temp directory")
    });
    dir.path().join(format!(
        "audit-{}.jsonl",
        AUDIT_SEQ.fetch_add(1, Ordering::Relaxed)
    ))
}

/// Path to the compiled mcp-writ binary (from cargo build).
pub fn mcp_writ_bin() -> PathBuf {
    // cargo test puts the test binary in target/debug/deps/;
    // the main binary is in target/debug/
    let mut path = std::env::current_exe().unwrap();
    // Go up from deps/ to debug/
    path.pop();
    if path.ends_with("deps") {
        path.pop();
    }
    let exe_name = format!("mcp-writ{}", std::env::consts::EXE_SUFFIX);
    path.join(exe_name)
}

/// Argv for a Python interpreter plus a fixture script under `tests/`.
pub fn python3_script_argv(relative_script: &str) -> Vec<String> {
    let script = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(relative_script);
    if cfg!(windows) {
        vec![
            "py".to_string(),
            "-3".to_string(),
            script.to_string_lossy().into_owned(),
        ]
    } else {
        vec!["python3".to_string(), script.to_string_lossy().into_owned()]
    }
}

/// Argv for a stdin→stdout echo process (mock MCP server).
///
/// Linux CI has `cat`. Windows developer machines often do not put Git's
/// `cat.exe` on PATH, so tests use the Python launcher instead.
pub fn echo_stdio_argv() -> Vec<String> {
    if cfg!(windows) {
        let script = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("fixtures")
            .join("echo_stdio.py");
        vec![
            "py".to_string(),
            "-3".to_string(),
            script.to_string_lossy().into_owned(),
        ]
    } else {
        vec!["cat".to_string()]
    }
}

/// Compile `tests/fixtures/mcp_servers/open_path_server.rs` once per test
/// binary with plain `rustc` (no cargo, no crates — same contract the
/// fixture file documents). `None` when rustc is unavailable or fails;
/// callers should skip with a diagnostic rather than fail.
pub fn compiled_open_path_fixture() -> Option<PathBuf> {
    static FIXTURE_EXE: OnceLock<Option<PathBuf>> = OnceLock::new();
    FIXTURE_EXE
        .get_or_init(|| {
            let src = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("tests")
                .join("fixtures")
                .join("mcp_servers")
                .join("open_path_server.rs");
            let dir = match tempfile::Builder::new()
                .prefix("mcp_writ_open_path_build_")
                .tempdir()
            {
                Ok(d) => d,
                Err(e) => {
                    skip_e2e_test(&format!("fixture build tempdir failed: {e}"));
                    return None;
                }
            };
            let out = dir
                .path()
                .join(format!("open_path_server{}", std::env::consts::EXE_SUFFIX));
            let status = std::process::Command::new("rustc")
                .arg("-O")
                .arg("-o")
                .arg(&out)
                .arg(&src)
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::inherit())
                .status();
            match status {
                Ok(s) if s.success() && out.exists() => {
                    let kept = dir.keep();
                    Some(kept.join(format!("open_path_server{}", std::env::consts::EXE_SUFFIX)))
                }
                Ok(s) => {
                    skip_e2e_test(&format!("rustc -O open_path_server.rs failed: {s}"));
                    None
                }
                Err(e) => {
                    skip_e2e_test(&format!("rustc unavailable: {e}"));
                    None
                }
            }
        })
        .clone()
}

/// Check if Docker daemon is available and running.
///
/// Uses `docker info` (not `--version`) to verify daemon connectivity, because
/// `--version` only checks the CLI binary and succeeds even when the daemon is stopped.
/// Uses a 5-second timeout to avoid hanging if the daemon is unresponsive.
pub fn docker_available() -> bool {
    let child = Command::new("docker")
        .arg("info")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn();

    match child {
        Ok(mut child) => {
            let start = std::time::Instant::now();
            loop {
                match child.try_wait() {
                    Ok(Some(status)) => break status.success(),
                    Ok(None) => {
                        if start.elapsed().as_secs() > 5 {
                            let _ = child.kill();
                            let _ = child.wait(); // ゾンビプロセスを回避するためにプロセスを回収
                            break false;
                        }
                        std::thread::sleep(std::time::Duration::from_millis(100));
                    }
                    Err(_) => break false,
                }
            }
        }
        Err(_) => false,
    }
}
