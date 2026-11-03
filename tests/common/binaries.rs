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
    // Compile-time selection: `windows_python_argv0` exists only on
    // Windows, so a runtime `cfg!` branch would not compile elsewhere.
    #[cfg(windows)]
    let mut argv = windows_python_argv0();
    #[cfg(not(windows))]
    let mut argv = vec!["python3".to_string()];
    argv.push(script.to_string_lossy().into_owned());
    argv
}

/// Windows fixture interpreter prefix. `py -3` resolves the user's
/// install through the per-user registry hive, which an AppContainer
/// token cannot see — so fixtures that may spawn inside the OS
/// sandbox carry the resolved `python.exe` path instead. Falls back
/// to `py -3` when the launcher cannot report an executable (hosts
/// without the sandbox see no difference).
#[cfg(windows)]
fn windows_python_argv0() -> Vec<String> {
    static RESOLVED: OnceLock<Vec<String>> = OnceLock::new();
    RESOLVED
        .get_or_init(|| {
            let exe = Command::new("py")
                .args(["-3", "-c", "import sys;print(sys.executable)"])
                .output()
                .ok()
                .filter(|o| o.status.success())
                .and_then(|o| String::from_utf8(o.stdout).ok())
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty() && PathBuf::from(s).is_file());
            match exe {
                Some(exe) => vec![exe],
                None => vec!["py".to_string(), "-3".to_string()],
            }
        })
        .clone()
}

/// Argv for a stdin→stdout echo process (mock MCP server).
///
/// Linux CI has `cat`. Windows developer machines often do not put Git's
/// `cat.exe` on PATH, so tests use the Python fixture interpreter.
pub fn echo_stdio_argv() -> Vec<String> {
    if cfg!(windows) {
        python3_script_argv("tests/fixtures/echo_stdio.py")
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

/// True when this host cannot arm the per-launch descendant-lifetime
/// boundary — the capability `sandbox require_lifetime_boundary`
/// demands. The probe performs the same steps a launch does: create a
/// private cgroup under the v2 root, then migrate a process into it
/// (which also requires write access on the common ancestor's
/// `cgroup.procs`). GitHub-hosted runners expose the hierarchy but
/// withhold both permissions, so every supervised launch would be
/// refused — the waiver an operator must declare there.
///
/// The probe writes a spawned child's pid, never this process's own:
/// membership moves the whole thread-group, and a test runner parked in
/// a probe cgroup could not put itself back if its original
/// `cgroup.procs` proves unwritable. A child that cannot spawn reads as
/// "unavailable" — the launch would fare no better.
#[cfg(target_os = "linux")]
pub fn linux_cgroup_v2_unwritable() -> bool {
    let root = std::path::Path::new("/sys/fs/cgroup");
    if !root.join("cgroup.controllers").exists() {
        return true;
    }
    // Concurrent boundary probes in one process share the pid — the
    // sequence keeps their dir names distinct, and a leftover from a
    // killed probe retries on a fresh name rather than reading a
    // `create_dir` collision as "unsupported".
    static PROBE_SEQ: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let mut created = None;
    for _ in 0..8 {
        let seq = PROBE_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let candidate = root.join(format!(
            "mcp-writ-boundary-probe-{}-{}",
            std::process::id(),
            seq
        ));
        match std::fs::create_dir(&candidate) {
            Ok(()) => {
                created = Some(candidate);
                break;
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(_) => return true,
        }
    }
    let Some(dir) = created else { return true };
    let mut child = match std::process::Command::new("/bin/sleep").arg("30").spawn() {
        Ok(child) => child,
        Err(_) => {
            let _ = std::fs::remove_dir(&dir);
            return true;
        }
    };
    let join_failed = std::fs::write(dir.join("cgroup.procs"), child.id().to_string()).is_err();
    let _ = child.kill();
    let _ = child.wait();
    let _ = std::fs::remove_dir(&dir);
    join_failed
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
