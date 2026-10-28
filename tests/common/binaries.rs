//! Binary and runtime fixtures: the compiled `mcp-writ` binary,
//! interpreter-backed fixture argv, the rustc-built open_path
//! server, Docker availability, and Landlock ABI probes.

use std::path::PathBuf;
use std::process::Command;
use std::sync::OnceLock;

use super::env::skip_e2e_test;

pub fn mcp_writ_bin() -> PathBuf {
    // cargo test puts the test binary in target/debug/deps/;
    // the main binary is in target/debug/
    let mut path = std::env::current_exe().unwrap(); // nosemgrep: rust.lang.security.current-exe.current-exe
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

/// Make `image` present in the local Docker image store before a command
/// inspects it. Clean CI runners have no image cache, and the image
/// commands under test deliberately never pull: `wrap-image` inspects the
/// image as given, and `containerize` refuses a base it cannot inspect
/// locally (an uninspected base could carry ONBUILD triggers).
pub fn ensure_docker_image(image: &str) {
    let inspect = Command::new("docker")
        .args(["image", "inspect", image])
        .output()
        .expect("Docker image inspection should run");
    if inspect.status.success() {
        return;
    }
    let pull = Command::new("docker")
        .args(["pull", image])
        .output()
        .expect("Docker image pull should run");
    assert!(
        pull.status.success(),
        "failed to prepare {image}: {}",
        String::from_utf8_lossy(&pull.stderr)
    );
}

/// True when the running kernel predates Landlock ABI V4 (Linux 6.7) —
/// the shared `sandbox allow_degraded` gate for policies that would
/// otherwise refuse a partially enforced ruleset (e.g. WSL2's 5.15).
/// An unreadable or unparsable `/proc/sys/kernel/osrelease` reads as a
/// modern kernel: the flag only loosens enforcement, so an undetermined
/// version must not add it.
#[cfg(target_os = "linux")]
pub fn linux_below_landlock_v4() -> bool {
    let Ok(release) = std::fs::read_to_string("/proc/sys/kernel/osrelease") else {
        return false;
    };
    kernel_release_below_landlock_v4(&release)
}

/// Same predicate as [`linux_below_landlock_v4`] applied to a kernel
/// release string — the container tests ask the engine for *its* kernel
/// (a remote or VM-based engine's kernel can differ from the CLI host's),
/// and this host may not be Linux at all. An unparsable release reads as
/// a modern kernel.
pub fn kernel_release_below_landlock_v4(release: &str) -> bool {
    let mut it = release.split(['.', '-']);
    let Some(major) = it.next().and_then(|s| s.trim().parse::<u32>().ok()) else {
        return false;
    };
    let Some(minor) = it.next().and_then(|s| s.trim().parse::<u32>().ok()) else {
        return false;
    };
    (major, minor) < (6, 7)
}
