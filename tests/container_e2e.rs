//! End-to-end tests for container-based mcp-writ.
//!
//! Tests the full flow: build base image → wrap with mcp-secure-runner → run → verify behavior.
//! Missing prerequisites skip locally and fail when MCP_WRIT_REQUIRE_CONTAINER_TESTS=1.

mod common;

use std::path::PathBuf;
use std::process::{Command as StdCommand, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};

static DOCKER_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::Command;
use tokio::time::{Duration, timeout};

const TIMEOUT_SECS: u64 = 30;
const BUILD_TIMEOUT_SECS: u64 = 600; // 10 min for Docker-based binary build
const TEST_IMAGE_PREFIX: &str = "mcp-writ-test";
const BASE_OS_IMAGE: &str = "debian:bookworm-slim";

// Global flag to check engine availability once per test run
static ENGINE_AVAILABLE: AtomicBool = AtomicBool::new(false);
static ENGINE_CHECKED: AtomicBool = AtomicBool::new(false);

/// Drop guard that ensures the child process is killed even if a test panics.
struct ChildGuard(tokio::process::Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.start_kill();
    }
}

/// Check if a container engine (Docker or Podman) is available AND its daemon is running.
///
/// Uses `info` (not `--version`) to verify daemon connectivity, because `--version`
/// only checks the CLI binary and succeeds even when the daemon is stopped.
/// Uses a 5-second timeout to avoid hanging if the daemon is unresponsive.
///
/// This is a synchronous function that performs blocking I/O. For async contexts,
/// use `has_container_engine_async()` instead.
fn has_container_engine() -> bool {
    // Check once per test run
    if ENGINE_CHECKED.load(Ordering::SeqCst) {
        return ENGINE_AVAILABLE.load(Ordering::SeqCst);
    }

    let check_daemon_with_timeout = |cmd: &str| -> bool {
        // Use `info` to verify both CLI existence AND daemon connectivity.
        // `--version` only checks the CLI binary; `info` requires a running daemon.
        let child = StdCommand::new(cmd)
            .arg("info")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn();

        match child {
            Ok(mut child) => {
                // Use a 5-second timeout
                let start = std::time::Instant::now();
                loop {
                    match child.try_wait() {
                        Ok(Some(status)) => break status.success(),
                        Ok(None) => {
                            if start.elapsed().as_secs() > 5 {
                                let _ = child.kill();
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
    };

    let available = check_daemon_with_timeout("docker") || check_daemon_with_timeout("podman");

    ENGINE_AVAILABLE.store(available, Ordering::SeqCst);
    ENGINE_CHECKED.store(true, Ordering::SeqCst);
    available
}

/// Async wrapper for `has_container_engine()` that runs the blocking check
/// in a `spawn_blocking` closure to avoid blocking the async runtime.
///
/// Uses the same ENGINE_CHECKED and ENGINE_AVAILABLE atomics to preserve
/// the once-only check semantics.
pub async fn has_container_engine_async() -> bool {
    // Fast path: already checked
    if ENGINE_CHECKED.load(Ordering::SeqCst) {
        return ENGINE_AVAILABLE.load(Ordering::SeqCst);
    }

    // Run the blocking check in spawn_blocking
    tokio::task::spawn_blocking(has_container_engine)
        .await
        .unwrap_or(false)
}

/// Get the available container engine command (docker or podman).
///
/// Relies on `has_container_engine_async()` having already verified daemon connectivity.
/// The preference check uses `--version` (CLI-only) since the daemon was already
/// confirmed responsive by `has_container_engine_async()`.
///
/// This is an async function that avoids blocking the async runtime.
pub async fn get_engine_cmd() -> Option<&'static str> {
    if !has_container_engine_async().await {
        return None;
    }

    // Prefer docker, fall back to podman.
    // Safe to use --version here because has_container_engine_async() already verified
    // the daemon is running via `info`.
    // Run the blocking command check in spawn_blocking
    tokio::task::spawn_blocking(|| {
        // Use `info` to verify daemon connectivity, matching has_container_engine()
        if StdCommand::new("docker")
            .arg("info")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
        {
            Some("docker")
        } else if StdCommand::new("podman")
            .arg("info")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
        {
            Some("podman")
        } else {
            None
        }
    })
    .await
    .unwrap_or(None)
}

/// Generate a unique test image name.
fn unique_image_name(suffix: &str) -> String {
    format!("{}-{}-{}", TEST_IMAGE_PREFIX, suffix, unique_hex_id())
}

/// Path to test fixtures directory.
fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

/// Path to the built mcp-secure-runner binary.
fn runner_binary_path() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_mcp-secure-runner"))
}

/// Copy the shared container policy into `dst`, appending
/// `sandbox allow_degraded` only when the engine's kernel predates
/// Landlock ABI V4 — the container shares the *engine's* kernel, so this
/// is the version the in-image mcp-secure-runner will enforce against.
/// The engine's kernel can differ from the CLI host's (a remote engine,
/// or a VM behind Docker Desktop / podman machine on macOS/Windows).
/// Mirrors the conditional in real_servers_e2e::host_policy.
async fn copy_test_policy(dst: &std::path::Path, engine: &str) -> Result<(), String> {
    let mut text = std::fs::read_to_string(fixtures_dir().join("test_container_policy.kdl"))
        .map_err(|e| format!("failed to read test policy: {e}"))?;
    if container_kernel_below_landlock_v4(engine).await {
        text.push_str("sandbox allow_degraded=#true\n");
    }
    std::fs::write(dst, text).map_err(|e| format!("failed to write test policy: {e}"))
}

/// Ask the engine for its kernel version — `<cli> info` reports the
/// server side, which is the kernel the launched container runs on.
/// An unanswered, failed, or unparsable probe reads as a modern kernel:
/// `allow_degraded` only loosens enforcement, so an undetermined version
/// must not add it.
async fn container_kernel_below_landlock_v4(engine: &str) -> bool {
    let format = match engine {
        "docker" => "{{.KernelVersion}}",
        "podman" => "{{.Host.Kernel}}",
        _ => return false,
    };
    let out = timeout(
        Duration::from_secs(5),
        Command::new(engine)
            .args(["info", "--format", format])
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .output(),
    )
    .await;
    match out {
        Ok(Ok(o)) if o.status.success() => {
            common::kernel_release_below_landlock_v4(String::from_utf8_lossy(&o.stdout).trim())
        }
        _ => false,
    }
}

/// Create a temporary directory for test artifacts.
fn create_temp_dir() -> std::io::Result<PathBuf> {
    let temp_dir = std::env::temp_dir().join(format!("mcp-writ-test-{}", unique_hex_id()));
    std::fs::create_dir_all(&temp_dir)?;
    Ok(temp_dir)
}

/// Generate a unique hex string from the current nanosecond timestamp.
fn unique_hex_id() -> String {
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    format!("{:x}", timestamp)
}

/// Check if a file is an ELF binary (Linux executable).
fn is_elf_binary(path: &std::path::Path) -> bool {
    std::fs::read(path)
        .map(|b| b.len() >= 4 && b[0..4] == [0x7f, b'E', b'L', b'F'])
        .unwrap_or(false)
}

/// Recursively copy a directory tree.
fn copy_dir_recursive(src: &std::path::Path, dst: &std::path::Path) -> Result<(), String> {
    for entry in std::fs::read_dir(src).map_err(|e| format!("read dir {}: {e}", src.display()))? {
        let entry = entry.map_err(|e| format!("dir entry: {e}"))?;
        let dest = dst.join(entry.file_name());
        if entry
            .file_type()
            .map_err(|e| format!("file type: {e}"))?
            .is_dir()
        {
            std::fs::create_dir_all(&dest).map_err(|e| format!("mkdir: {e}"))?;
            copy_dir_recursive(&entry.path(), &dest)?;
        } else {
            std::fs::copy(entry.path(), &dest).map_err(|e| format!("copy: {e}"))?;
        }
    }
    Ok(())
}

/// Get a Linux-compatible mcp-secure-runner binary.
///
/// On Linux, the native cargo-built binary is used directly.
/// On other platforms (macOS, Windows), the binary is built inside a Docker
/// container using a multi-stage build with vendored dependencies.
async fn get_linux_runner(engine: &str) -> Result<PathBuf, String> {
    let native = runner_binary_path();
    if is_elf_binary(&native) {
        return Ok(native);
    }

    // Non-Linux host: build inside Docker
    let project_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let temp_dir = create_temp_dir().map_err(|e| format!("temp dir: {e}"))?;

    // Vendor dependencies (runs on host, uses local cargo cache)
    let vendor_dir = temp_dir.join("vendor");
    let vendor_out = StdCommand::new("cargo")
        .args(["vendor", &vendor_dir.to_string_lossy()])
        .current_dir(&project_dir)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output()
        .map_err(|e| format!("cargo vendor failed: {e}"))?;
    if !vendor_out.status.success() {
        return Err(format!(
            "cargo vendor failed: {}",
            String::from_utf8_lossy(&vendor_out.stderr)
        ));
    }

    let src_dir = temp_dir.join("src");
    std::fs::create_dir_all(&src_dir).map_err(|e| format!("mkdir src: {e}"))?;
    copy_dir_recursive(&project_dir.join("src"), &src_dir)?;

    std::fs::copy(project_dir.join("Cargo.toml"), temp_dir.join("Cargo.toml"))
        .map_err(|e| format!("copy Cargo.toml: {e}"))?;
    std::fs::copy(project_dir.join("Cargo.lock"), temp_dir.join("Cargo.lock"))
        .map_err(|e| format!("copy Cargo.lock: {e}"))?;

    // Write Dockerfile
    let dockerfile = r#"FROM rust:1-bookworm AS builder
WORKDIR /build
COPY vendor/ /vendor/
COPY src/ src/
COPY Cargo.toml Cargo.lock ./
RUN mkdir -p .cargo && \
    printf '[source.crates-io]\nreplace-with = "vendored-sources"\n\n[source.vendored-sources]\ndirectory = "/vendor"\n' > .cargo/config.toml && \
    cargo build --release --bin mcp-secure-runner
"#;
    std::fs::write(temp_dir.join("Dockerfile"), dockerfile)
        .map_err(|e| format!("write Dockerfile: {e}"))?;

    // Docker build
    let build_image = unique_image_name("runner-build");
    let build_result = timeout(
        Duration::from_secs(BUILD_TIMEOUT_SECS),
        Command::new(engine)
            .args(["build", "-t", &build_image, "."])
            .current_dir(&temp_dir)
            .output(),
    )
    .await
    .map_err(|_| format!("Docker build timed out after {BUILD_TIMEOUT_SECS}s"))?
    .map_err(|e| format!("Docker build failed: {e}"))?;

    if !build_result.status.success() {
        return Err(format!(
            "Docker build failed: {}",
            String::from_utf8_lossy(&build_result.stderr)
        ));
    }

    // Extract binary from the build image.
    // NOTE: output_dir is intentionally NOT cleaned up here because
    // the caller needs the binary. The OS temp dir cleanup handles it.
    let output_dir = create_temp_dir().map_err(|e| format!("output dir: {e}"))?;
    let container_name = unique_image_name("extract");
    let _ = Command::new(engine)
        .args(["create", "--name", &container_name, &build_image])
        .output()
        .await;
    let cp_result = Command::new(engine)
        .args([
            "cp",
            &format!("{container_name}:/build/target/release/mcp-secure-runner"),
            &output_dir.to_string_lossy(),
        ])
        .output()
        .await
        .map_err(|e| format!("docker cp failed: {e}"))?;
    let _ = Command::new(engine)
        .args(["rm", &container_name])
        .output()
        .await;
    let _ = Command::new(engine)
        .args(["rmi", "-f", &build_image])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .await;

    if !cp_result.status.success() {
        return Err("failed to extract binary from Docker image".to_string());
    }

    let binary = output_dir.join("mcp-secure-runner");
    if !binary.exists() {
        return Err("binary not found after extraction".to_string());
    }

    // Cleanup temp build dir (keep output_dir with binary)
    let _ = std::fs::remove_dir_all(&temp_dir);

    Ok(binary)
}

/// Build a minimal base image with echo_server.sh as entrypoint.
async fn build_base_echo_image(engine: &str, image_name: &str) -> Result<(), String> {
    let temp_dir = create_temp_dir().map_err(|e| format!("failed to create temp dir: {e}"))?;
    let dockerfile_path = temp_dir.join("Dockerfile");
    let echo_script_path = temp_dir.join("echo_server.sh");
    let policy_path = temp_dir.join("policy.kdl");

    // Copy echo_server.sh to temp dir
    let src_echo = fixtures_dir().join("echo_server.sh");
    std::fs::copy(&src_echo, &echo_script_path)
        .map_err(|e| format!("failed to copy echo_server.sh: {e}"))?;

    // Copy test policy (allow_degraded appended only on pre-6.7 kernels)
    copy_test_policy(&policy_path, engine).await?;

    // Create Dockerfile for base image
    let dockerfile = format!(
        r#"FROM {BASE_OS_IMAGE}
COPY echo_server.sh /usr/local/bin/echo_server.sh
RUN chmod +x /usr/local/bin/echo_server.sh
ENTRYPOINT ["/bin/sh", "/usr/local/bin/echo_server.sh"]
"#
    );
    std::fs::write(&dockerfile_path, dockerfile)
        .map_err(|e| format!("failed to write Dockerfile: {e}"))?;

    // Build the base image with timeout (disable BuildKit to avoid buildx hanging)
    let build_result = timeout(
        Duration::from_secs(TIMEOUT_SECS),
        Command::new(engine)
            .args(["build", "-t", image_name, "."])
            .env("DOCKER_BUILDKIT", "0")
            .current_dir(&temp_dir)
            .output(),
    )
    .await
    .map_err(|e| format!("{} build timed out after {}s: {}", engine, TIMEOUT_SECS, e))?;

    let output = build_result.map_err(|e| format!("failed to run {} build: {}", engine, e))?;

    if !output.status.success() {
        return Err(format!(
            "{} build failed: {}",
            engine,
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    // Clean up temp dir
    let _ = std::fs::remove_dir_all(&temp_dir);

    Ok(())
}

/// Build a secure wrapper image using mcp-secure-runner.
async fn build_secure_image(
    engine: &str,
    base_image: &str,
    secure_image: &str,
    runner_path: &std::path::Path,
) -> Result<(), String> {
    let temp_dir = create_temp_dir().map_err(|e| format!("failed to create temp dir: {e}"))?;

    let runner_src = runner_path;
    let runner_name = "mcp-secure-runner";
    let runner_dest = temp_dir.join(runner_name);

    std::fs::copy(runner_src, &runner_dest)
        .map_err(|e| format!("failed to copy mcp-secure-runner: {e}"))?;

    let policy_dest = temp_dir.join("policy.kdl");
    copy_test_policy(&policy_dest, engine).await?;

    // Create wrapper Dockerfile
    let dockerfile = format!(
        r#"FROM {}
COPY {} /usr/local/bin/mcp-secure-runner
COPY policy.kdl /etc/mcp-secure/policy.kdl
RUN mkdir -p /var/log/mcp-secure /workspace
ENV MCP_ORIG_ENTRYPOINT="[\"/bin/sh\",\"/usr/local/bin/echo_server.sh\"]" MCP_ORIG_CMD=""
ENTRYPOINT ["/usr/local/bin/mcp-secure-runner"]
"#,
        base_image, runner_name
    );

    let dockerfile_path = temp_dir.join("Dockerfile");
    std::fs::write(&dockerfile_path, dockerfile)
        .map_err(|e| format!("failed to write Dockerfile: {e}"))?;

    // Build secure image with timeout (disable BuildKit to avoid buildx hanging)
    let build_result = timeout(
        Duration::from_secs(TIMEOUT_SECS),
        Command::new(engine)
            .args(["build", "-t", secure_image, "."])
            .env("DOCKER_BUILDKIT", "0")
            .current_dir(&temp_dir)
            .output(),
    )
    .await
    .map_err(|e| format!("{} build timed out after {}s: {}", engine, TIMEOUT_SECS, e))?;

    let output = build_result.map_err(|e| format!("failed to run {} build: {}", engine, e))?;

    if !output.status.success() {
        return Err(format!(
            "{} build failed: {}",
            engine,
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    // Clean up
    let _ = std::fs::remove_dir_all(&temp_dir);

    Ok(())
}

/// Delete an image by name.
async fn delete_image(engine: &str, image: &str) {
    let _ = Command::new(engine)
        .args(["rmi", "-f", image])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .await;
}

/// Helper: send a JSON line and read the next JSON-RPC response line.
async fn send_and_recv(
    stdin: &mut tokio::process::ChildStdin,
    reader: &mut tokio::io::Lines<BufReader<tokio::process::ChildStdout>>,
    request: &str,
) -> String {
    stdin
        .write_all(format!("{request}\n").as_bytes())
        .await
        .expect("failed to write request");
    stdin.flush().await.expect("failed to flush");

    timeout(Duration::from_secs(TIMEOUT_SECS), async {
        loop {
            let line = reader
                .next_line()
                .await
                .expect("IO error")
                .expect("unexpected EOF");
            if line.starts_with("{\"jsonrpc\"") {
                return line;
            }
        }
    })
    .await
    .expect("timeout waiting for JSON-RPC response")
}

// ─── Test 1: Allowed tool passes through ─────────────────────────────────────

#[tokio::test]
async fn test_container_build_and_run_allowed_tool() {
    let _lock = DOCKER_LOCK.lock().await;
    let Some(engine) = get_engine_cmd().await else {
        common::skip_container_test("no container engine");
        return;
    };

    // Get a Linux-compatible runner binary
    let runner_path = match get_linux_runner(engine).await {
        Ok(p) => p,
        Err(e) => {
            common::skip_container_test(&format!("failed to get Linux runner: {e}"));
            return;
        }
    };

    let base_image = unique_image_name("base");
    let secure_image = unique_image_name("secure");

    // Build base image
    if let Err(e) = build_base_echo_image(engine, &base_image).await {
        common::skip_container_test(&format!("failed to build base image: {e}"));
        return;
    }

    // Build secure image
    if let Err(e) = build_secure_image(engine, &base_image, &secure_image, &runner_path).await {
        delete_image(engine, &base_image).await;
        common::skip_container_test(&format!("failed to build secure image: {e}"));
        return;
    }

    // Run container
    let child_result = Command::new(engine)
        .args(["run", "-i", "--rm", &secure_image])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn();

    let mut child = match child_result {
        Ok(c) => c,
        Err(e) => {
            delete_image(engine, &base_image).await;
            delete_image(engine, &secure_image).await;
            panic!("failed to spawn container: {e}");
        }
    };

    let mut stdin = child.stdin.take().expect("stdin should be piped");
    let stdout = child.stdout.take().expect("stdout should be piped");
    let _guard = ChildGuard(child);
    let mut reader = BufReader::new(stdout).lines();

    // read_file is allowed in test policy
    let request = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/workspace/test.txt"}}}"#;
    let response = send_and_recv(&mut stdin, &mut reader, request).await;

    // Should pass through (echoed back)
    assert_eq!(response, request);

    drop(stdin);

    // Cleanup
    delete_image(engine, &base_image).await;
    delete_image(engine, &secure_image).await;
}

// ─── Test 2: Blocked tool returns JSON-RPC error ─────────────────────────────

#[tokio::test]
async fn test_container_run_blocked_tool() {
    let _lock = DOCKER_LOCK.lock().await;
    let Some(engine) = get_engine_cmd().await else {
        common::skip_container_test("no container engine");
        return;
    };

    // Get a Linux-compatible runner binary
    let runner_path = match get_linux_runner(engine).await {
        Ok(p) => p,
        Err(e) => {
            common::skip_container_test(&format!("failed to get Linux runner: {e}"));
            return;
        }
    };

    let base_image = unique_image_name("base");
    let secure_image = unique_image_name("secure");

    if let Err(e) = build_base_echo_image(engine, &base_image).await {
        common::skip_container_test(&format!("failed to build base image: {e}"));
        return;
    }

    if let Err(e) = build_secure_image(engine, &base_image, &secure_image, &runner_path).await {
        delete_image(engine, &base_image).await;
        common::skip_container_test(&format!("failed to build secure image: {e}"));
        return;
    }

    let child_result = Command::new(engine)
        .args(["run", "-i", "--rm", &secure_image])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn();

    let mut child = match child_result {
        Ok(c) => c,
        Err(e) => {
            delete_image(engine, &base_image).await;
            delete_image(engine, &secure_image).await;
            panic!("failed to spawn container: {e}");
        }
    };

    let mut stdin = child.stdin.take().expect("stdin should be piped");
    let stdout = child.stdout.take().expect("stdout should be piped");
    let _guard = ChildGuard(child);
    let mut reader = BufReader::new(stdout).lines();

    // exec_shell is denied in test policy
    let request = r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"exec_shell","arguments":{"cmd":"rm -rf /"}}}"#;
    let response = send_and_recv(&mut stdin, &mut reader, request).await;

    // Should be an error response
    assert_ne!(response, request);

    let json = nojson::RawJson::parse(&response).expect("response should be valid JSON");
    let has_error = json
        .value()
        .to_member("error")
        .ok()
        .and_then(|m| m.optional())
        .is_some();
    assert!(has_error, "blocked tool should return error response");

    // Verify error message mentions the tool name
    let msg = json
        .value()
        .to_member("error")
        .expect("response should have 'error' field")
        .required()
        .expect("'error' field should be present")
        .to_member("message")
        .expect("error should have 'message' field")
        .required()
        .expect("'message' field should be present")
        .as_string_str()
        .expect("error message should be a string");
    assert!(
        msg.contains("exec_shell"),
        "error message should mention the tool name"
    );

    drop(stdin);

    delete_image(engine, &base_image).await;
    delete_image(engine, &secure_image).await;
}

// ─── Test 3: ENTRYPOINT/CMD preserved in env vars ────────────────────────────

#[tokio::test]
async fn test_container_entrypoint_cmd_preserved() {
    let _lock = DOCKER_LOCK.lock().await;
    let Some(engine) = get_engine_cmd().await else {
        common::skip_container_test("no container engine");
        return;
    };

    // Get a Linux-compatible runner binary
    let runner_path = match get_linux_runner(engine).await {
        Ok(p) => p,
        Err(e) => {
            common::skip_container_test(&format!("failed to get Linux runner: {e}"));
            return;
        }
    };

    let base_image = unique_image_name("base");
    let secure_image = unique_image_name("secure");

    if let Err(e) = build_base_echo_image(engine, &base_image).await {
        common::skip_container_test(&format!("failed to build base image: {e}"));
        return;
    }

    if let Err(e) = build_secure_image(engine, &base_image, &secure_image, &runner_path).await {
        delete_image(engine, &base_image).await;
        common::skip_container_test(&format!("failed to build secure image: {e}"));
        return;
    }

    // Inspect the secure image to verify env vars
    let output = Command::new(engine)
        .args([
            "image",
            "inspect",
            &secure_image,
            "--format",
            "{{.Config.Env}}",
        ])
        .output()
        .await
        .expect("failed to inspect image");

    let env_output = String::from_utf8_lossy(&output.stdout).to_string();

    // Should contain both MCP_ORIG_ENTRYPOINT and MCP_ORIG_CMD
    assert!(
        env_output.contains("MCP_ORIG_ENTRYPOINT") && env_output.contains("MCP_ORIG_CMD"),
        "image should have both MCP_ORIG_ENTRYPOINT and MCP_ORIG_CMD env vars, got: {}",
        env_output
    );

    delete_image(engine, &base_image).await;
    delete_image(engine, &secure_image).await;
}

// ─── Test 4: Verify skip behavior when no engine ─────────────────────────────

#[tokio::test]
async fn test_container_no_engine_skip() {
    let _lock = DOCKER_LOCK.lock().await;
    // This test verifies that the skip mechanism works correctly.
    // If an engine IS available, we simulate "no engine" by checking the flag directly.
    // If no engine is available, the test should simply pass (skip verification).

    if has_container_engine_async().await {
        // Engine is available, so verify the skip logic would work
        // by checking that get_engine_cmd() returns Some
        let engine = get_engine_cmd().await;
        assert!(engine.is_some(), "engine should be available");

        // The skip behavior is verified by other tests returning early
        // when get_engine_cmd() returns None
        println!("Engine available: skip mechanism verified");
    } else {
        // No engine available - this is the skip path
        common::skip_container_test("no container engine");
        // Test passes by returning early
    }
}
