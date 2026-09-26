//! E2E tests for the `wrap-image` subcommand.
//!
//! Missing prerequisites skip locally and fail when MCP_WRIT_REQUIRE_CONTAINER_TESTS=1.

mod common;

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Mutex;

static DOCKER_LOCK: Mutex<()> = Mutex::new(());

// ─── Helpers ─────────────────────────────────────────────────────────────────

/// Prepare the image before wrap-image inspects it. Clean CI runners have
/// no local image cache, and inspect deliberately does not pull images.
fn ensure_alpine_image() {
    let inspect = Command::new("docker")
        .args(["image", "inspect", "alpine:3.19"])
        .output()
        .expect("Docker image inspection should run");
    if inspect.status.success() {
        return;
    }
    let pull = Command::new("docker")
        .args(["pull", "alpine:3.19"])
        .output()
        .expect("Docker image pull should run");
    assert!(
        pull.status.success(),
        "failed to prepare alpine:3.19: {}",
        String::from_utf8_lossy(&pull.stderr)
    );
}

/// Create a uniquely named temp directory. Caller must clean up.
fn make_test_dir(label: &str) -> PathBuf {
    let id = std::process::id();
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("mcp_writ_wrap_e2e_{label}_{id}_{ts}"));
    fs::create_dir_all(&dir).unwrap();
    dir
}

/// Write a minimal KDL policy file into the given directory.
fn write_policy(dir: &Path, content: &str) -> PathBuf {
    let path = dir.join("policy.kdl");
    fs::write(&path, content).unwrap();
    path
}

/// Create a fake runner binary (a shell script) that is executable.
/// This is used when the real mcp-secure-runner is not needed for the test
/// (e.g., --output-dockerfile or build-only tests).
fn create_fake_runner(dir: &Path) -> PathBuf {
    let runner = dir.join("fake-runner");
    fs::write(&runner, "#!/bin/sh\nexec \"$@\"\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&runner, fs::Permissions::from_mode(0o755)).unwrap();
    }
    runner
}

/// Run `mcp-writ wrap-image` with the given arguments and return (stdout, stderr, exit_code).
fn run_wrap_image(args: &[&str]) -> (String, String, i32) {
    let bin = common::mcp_writ_bin();
    let mut cmd_args = vec!["wrap-image"];
    cmd_args.extend_from_slice(args);

    let output = Command::new(&bin)
        .args(&cmd_args)
        .output()
        .unwrap_or_else(|e| panic!("failed to run mcp-writ: {e}"));

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let code = output.status.code().unwrap_or(-1);
    (stdout, stderr, code)
}

// ─── Docker-independent tests ────────────────────────────────────────────────

#[test]
fn test_wrap_image_no_args_shows_error() {
    let bin = common::mcp_writ_bin();
    let output = Command::new(&bin).args(["wrap-image"]).output().unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !output.status.success(),
        "should fail without image argument"
    );
    assert!(
        stderr.contains("image") || stderr.contains("required") || stderr.contains("usage"),
        "stderr should mention missing image: {stderr}"
    );
}

#[test]
fn test_wrap_image_help_flag() {
    let bin = common::mcp_writ_bin();
    let output = Command::new(&bin)
        .args(["wrap-image", "--help"])
        .output()
        .unwrap();
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.contains("wrap-image")
            || combined.contains("USAGE")
            || combined.contains("usage")
            || combined.contains("--policy")
            || combined.contains("--tag"),
        "help should mention wrap-image options: {combined}"
    );
}

#[test]
fn test_wrap_image_runner_not_found_error() {
    // Without --runner-binary and no runners/ directory, should fail with a descriptive error.
    let (_stdout, stderr, code) = run_wrap_image(&[
        "--runner-binary",
        "/nonexistent/path/to/runner",
        "alpine:3.19",
    ]);
    assert_ne!(code, 0, "should fail with nonexistent runner");
    assert!(
        stderr.contains("not found"),
        "stderr should mention runner not found: {stderr}"
    );
}

#[cfg(unix)]
#[test]
fn test_wrap_image_runner_not_executable() {
    let dir = make_test_dir("runner_noexec");
    let runner = dir.join("runner-noexec");
    fs::write(&runner, "not executable").unwrap();

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&runner, fs::Permissions::from_mode(0o644)).unwrap();
    }

    let (_stdout, stderr, code) =
        run_wrap_image(&["--runner-binary", runner.to_str().unwrap(), "alpine:3.19"]);
    assert_ne!(code, 0, "should fail with non-executable runner");
    assert!(
        stderr.contains("not executable") || stderr.contains("chmod"),
        "stderr should mention not executable: {stderr}"
    );

    let _ = fs::remove_dir_all(&dir);
}

// ─── Docker-required tests ───────────────────────────────────────────────────

#[test]
fn test_output_dockerfile_records_runner_caps() {
    let _lock = DOCKER_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    if !common::docker_available() {
        common::skip_container_test("Docker not available");
        return;
    }

    ensure_alpine_image();

    // A fake runner carrying the NUL-terminated capability marker — the
    // scan is byte-level, so a comment containing the marker suffices.
    let dir = make_test_dir("output_df_caps");
    let runner = dir.join("fake-runner");
    fs::write(
        &runner,
        b"#!/bin/sh\n# MCP_WRIT_RUNNER_CAPS:{\"v\":\"9.9.9-test\",\"caps\":[\"guest-report-1\"]}\0\nexec \"$@\"\n",
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&runner, fs::Permissions::from_mode(0o755)).unwrap();
    }
    let output_path = dir.join("Dockerfile.out");

    let (_stdout, stderr, code) = run_wrap_image(&[
        "--runner-binary",
        runner.to_str().unwrap(),
        "--output-dockerfile",
        output_path.to_str().unwrap(),
        "alpine:3.19",
    ]);

    assert_eq!(code, 0, "should succeed: stderr={stderr}");
    let content = fs::read_to_string(&output_path).unwrap();
    assert!(
        content.contains("MCP_WRIT_RUNNER_CAPS=") && content.contains("guest-report-1"),
        "Dockerfile should record the runner's caps env: {content}"
    );
    assert!(
        stderr.contains("guest report capability recorded"),
        "stderr should note the recorded capability: {stderr}"
    );

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn test_output_dockerfile_legacy_runner_note() {
    let _lock = DOCKER_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    if !common::docker_available() {
        common::skip_container_test("Docker not available");
        return;
    }

    ensure_alpine_image();

    let dir = make_test_dir("output_df_legacy");
    let runner = create_fake_runner(&dir);
    let output_path = dir.join("Dockerfile.out");

    let (_stdout, stderr, code) = run_wrap_image(&[
        "--runner-binary",
        runner.to_str().unwrap(),
        "--output-dockerfile",
        output_path.to_str().unwrap(),
        "alpine:3.19",
    ]);

    // Generation is still allowed — the artifact records an empty caps
    // env and the note warns that run-image --report will refuse.
    assert_eq!(code, 0, "should succeed: stderr={stderr}");
    let content = fs::read_to_string(&output_path).unwrap();
    assert!(
        content.contains("MCP_WRIT_RUNNER_CAPS=\"\""),
        "Dockerfile should record an empty caps env for a legacy runner: {content}"
    );
    assert!(
        stderr.contains("run-image --report will refuse"),
        "stderr should note the missing capability: {stderr}"
    );

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn test_output_dockerfile_generates_file() {
    let _lock = DOCKER_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    if !common::docker_available() {
        common::skip_container_test("Docker not available");
        return;
    }

    ensure_alpine_image();

    let dir = make_test_dir("output_df");
    let runner = create_fake_runner(&dir);
    let output_path = dir.join("Dockerfile.out");

    let (_stdout, stderr, code) = run_wrap_image(&[
        "--runner-binary",
        runner.to_str().unwrap(),
        "--output-dockerfile",
        output_path.to_str().unwrap(),
        "alpine:3.19",
    ]);

    assert_eq!(code, 0, "should succeed: stderr={stderr}");
    assert!(output_path.exists(), "Dockerfile should be written");

    let content = fs::read_to_string(&output_path).unwrap();
    assert!(
        content.contains("FROM alpine:3.19"),
        "Dockerfile should contain FROM: {content}"
    );
    assert!(
        content.contains("COPY mcp-secure-runner /usr/local/bin/mcp-secure-runner"),
        "Dockerfile should COPY runner: {content}"
    );
    assert!(
        content.contains("COPY policy.kdl /etc/mcp-secure/policy.kdl"),
        "Dockerfile should COPY policy: {content}"
    );
    assert!(
        content.contains("ENTRYPOINT [\"/usr/local/bin/mcp-secure-runner\"]"),
        "Dockerfile should set ENTRYPOINT: {content}"
    );
    assert!(
        content.contains("MCP_WRIT_FAIL_ON=\"\""),
        "Dockerfile must clear MCP_WRIT_FAIL_ON: {content}"
    );

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn test_output_dockerfile_no_build() {
    let _lock = DOCKER_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    if !common::docker_available() {
        common::skip_container_test("Docker not available");
        return;
    }

    ensure_alpine_image();

    let dir = make_test_dir("output_df_no_build");
    let runner = create_fake_runner(&dir);
    let output_path = dir.join("Dockerfile.out");

    // The --output-dockerfile flag should cause it to NOT build an image.
    // We verify the Dockerfile is written and there's no image build attempt
    // (would fail anyway since the runner is fake).
    let (_stdout, stderr, code) = run_wrap_image(&[
        "--runner-binary",
        runner.to_str().unwrap(),
        "--output-dockerfile",
        output_path.to_str().unwrap(),
        "alpine:3.19",
    ]);

    assert_eq!(code, 0, "should succeed without building: stderr={stderr}");
    assert!(output_path.exists(), "Dockerfile should exist");

    // Verify the success message mentions Dockerfile
    assert!(
        stderr.contains("Dockerfile") || _stdout.contains("Dockerfile"),
        "output should mention Dockerfile: stdout={_stdout}, stderr={stderr}"
    );

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn test_output_dockerfile_captures_entrypoint_and_cmd() {
    let _lock = DOCKER_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    if !common::docker_available() {
        common::skip_container_test("Docker not available");
        return;
    }

    ensure_alpine_image();

    let dir = make_test_dir("output_df_entrypoint");
    let runner = create_fake_runner(&dir);
    let output_path = dir.join("Dockerfile.out");

    // Use an image that has both ENTRYPOINT and CMD set.
    // alpine:3.19 has CMD ["/bin/sh"] and no ENTRYPOINT.
    let (_stdout, stderr, code) = run_wrap_image(&[
        "--runner-binary",
        runner.to_str().unwrap(),
        "--output-dockerfile",
        output_path.to_str().unwrap(),
        "alpine:3.19",
    ]);

    assert_eq!(code, 0, "should succeed: stderr={stderr}");

    let content = fs::read_to_string(&output_path).unwrap();
    // alpine has CMD ["/bin/sh"], no ENTRYPOINT
    assert!(
        content.contains("MCP_ORIG_ENTRYPOINT=\"\""),
        "ENTRYPOINT should be empty for alpine: {content}"
    );
    assert!(
        content.contains("MCP_ORIG_CMD="),
        "CMD env should be set: {content}"
    );
    // alpine's CMD is ["/bin/sh"]
    assert!(
        content.contains("/bin/sh"),
        "CMD should include /bin/sh for alpine: {content}"
    );

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn test_output_dockerfile_with_custom_policy() {
    let _lock = DOCKER_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    if !common::docker_available() {
        common::skip_container_test("Docker not available");
        return;
    }

    ensure_alpine_image();

    let dir = make_test_dir("output_df_custom_policy");
    let runner = create_fake_runner(&dir);
    let output_path = dir.join("Dockerfile.out");

    // --policy is only used for the build step, not --output-dockerfile.
    // With --output-dockerfile, it should succeed regardless of policy existence.
    let (_stdout, stderr, code) = run_wrap_image(&[
        "--runner-binary",
        runner.to_str().unwrap(),
        "--output-dockerfile",
        output_path.to_str().unwrap(),
        "--policy",
        "/nonexistent/policy.kdl",
        "alpine:3.19",
    ]);

    assert_eq!(
        code, 0,
        "output-dockerfile should not need policy file: stderr={stderr}"
    );
    assert!(output_path.exists(), "Dockerfile should be written");

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn test_wrap_image_build_missing_policy() {
    let _lock = DOCKER_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    if !common::docker_available() {
        common::skip_container_test("Docker not available");
        return;
    }

    ensure_alpine_image();

    let dir = make_test_dir("build_no_policy");
    let runner = create_fake_runner(&dir);

    // Without --output-dockerfile, it tries to build → needs policy file.
    // Default is ./policy.kdl which doesn't exist in temp dir.
    let (_stdout, stderr, code) = run_wrap_image(&[
        "--runner-binary",
        runner.to_str().unwrap(),
        "--policy",
        dir.join("nonexistent.kdl").to_str().unwrap(),
        "alpine:3.19",
    ]);

    assert_ne!(code, 0, "should fail without policy file");
    assert!(
        stderr.contains("not found") || stderr.contains("policy"),
        "stderr should mention missing policy: {stderr}"
    );

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn test_wrap_image_build_full_flow() {
    let _lock = DOCKER_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    if !common::docker_available() {
        common::skip_container_test("Docker not available");
        return;
    }

    ensure_alpine_image();

    let dir = make_test_dir("build_full");
    let runner = create_fake_runner(&dir);
    let policy_path = write_policy(
        &dir,
        r#"
        policy version=1
        server "test" {
            tool "echo_tool"
        }
    "#,
    );

    let tag = format!("mcp-writ-test-wrap:{}", std::process::id());

    let (_stdout, stderr, code) = run_wrap_image(&[
        "--runner-binary",
        runner.to_str().unwrap(),
        "--policy",
        policy_path.to_str().unwrap(),
        "--tag",
        &tag,
        "alpine:3.19",
    ]);

    assert_eq!(code, 0, "build should succeed: stderr={stderr}");

    // Verify image was created
    let inspect_output = Command::new("docker")
        .args(["image", "inspect", &tag])
        .output()
        .unwrap();
    assert!(
        inspect_output.status.success(),
        "built image should exist: {}",
        String::from_utf8_lossy(&inspect_output.stderr)
    );

    // Verify image has the runner binary at expected path
    let run_output = Command::new("docker")
        .args([
            "run",
            "--rm",
            &tag,
            "ls",
            "/usr/local/bin/mcp-secure-runner",
        ])
        .output()
        .unwrap();
    assert!(
        run_output.status.success(),
        "runner should be in image: {}",
        String::from_utf8_lossy(&run_output.stderr)
    );

    // Verify policy file is in the image
    let policy_check = Command::new("docker")
        .args(["run", "--rm", &tag, "cat", "/etc/mcp-secure/policy.kdl"])
        .output()
        .unwrap();
    assert!(
        policy_check.status.success(),
        "policy should be in image: {}",
        String::from_utf8_lossy(&policy_check.stderr)
    );
    let policy_content = String::from_utf8_lossy(&policy_check.stdout);
    assert!(
        policy_content.contains("echo_tool"),
        "policy should contain echo_tool: {policy_content}"
    );

    // Clean up: remove the test image
    let _ = Command::new("docker").args(["rmi", "-f", &tag]).output();

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn test_wrap_image_default_tag() {
    let _lock = DOCKER_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    if !common::docker_available() {
        common::skip_container_test("Docker not available");
        return;
    }

    ensure_alpine_image();

    let dir = make_test_dir("default_tag");
    let runner = create_fake_runner(&dir);
    let _policy_path = write_policy(&dir, "policy version=1\n");

    let output_df = dir.join("Dockerfile.out");

    // Use --output-dockerfile to avoid actually building
    // Just check the stdout/stderr message for the default tag generation.
    // The default tag logic is: <image>-secured:latest (stripping existing tag)
    // Use a real image with a tag to verify FROM line and default tag derivation.
    // (Previously used "my-mcp-server:v2.1" which doesn't exist locally,
    //  causing inspect to fail.)
    let (_stdout, stderr, code) = run_wrap_image(&[
        "--runner-binary",
        runner.to_str().unwrap(),
        "--output-dockerfile",
        output_df.to_str().unwrap(),
        "alpine:3.19",
    ]);

    assert_eq!(code, 0, "should succeed: stderr={stderr}");

    // The --output-dockerfile path doesn't produce the tag in output,
    // but the Dockerfile should reference the original image
    let content = fs::read_to_string(&output_df).unwrap();
    assert!(
        content.contains("FROM alpine:3.19"),
        "Dockerfile should reference source image: {content}"
    );

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn test_wrap_image_build_with_no_cache() {
    let _lock = DOCKER_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    if !common::docker_available() {
        common::skip_container_test("Docker not available");
        return;
    }

    ensure_alpine_image();

    let dir = make_test_dir("no_cache");
    let runner = create_fake_runner(&dir);
    let policy_path = write_policy(&dir, "policy version=1\n");

    let tag = format!("mcp-writ-test-nocache:{}", std::process::id());

    let (_stdout, stderr, code) = run_wrap_image(&[
        "--runner-binary",
        runner.to_str().unwrap(),
        "--policy",
        policy_path.to_str().unwrap(),
        "--tag",
        &tag,
        "--no-cache",
        "alpine:3.19",
    ]);

    assert_eq!(
        code, 0,
        "build with --no-cache should succeed: stderr={stderr}"
    );

    // Clean up
    let _ = Command::new("docker").args(["rmi", "-f", &tag]).output();
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn test_wrap_image_build_with_engine_docker() {
    let _lock = DOCKER_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    if !common::docker_available() {
        common::skip_container_test("Docker not available");
        return;
    }

    ensure_alpine_image();

    let dir = make_test_dir("engine_docker");
    let runner = create_fake_runner(&dir);
    let policy_path = write_policy(&dir, "policy version=1\n");

    let tag = format!("mcp-writ-test-engine:{}", std::process::id());

    let (_stdout, stderr, code) = run_wrap_image(&[
        "--runner-binary",
        runner.to_str().unwrap(),
        "--policy",
        policy_path.to_str().unwrap(),
        "--tag",
        &tag,
        "--engine",
        "docker",
        "alpine:3.19",
    ]);

    assert_eq!(
        code, 0,
        "build with --engine docker should succeed: stderr={stderr}"
    );

    // Clean up
    let _ = Command::new("docker").args(["rmi", "-f", &tag]).output();
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn test_wrap_image_build_invalid_engine() {
    let (_stdout, stderr, code) = run_wrap_image(&["--engine", "containerd", "alpine:3.19"]);

    assert_ne!(code, 0, "should fail with invalid engine");
    assert!(
        stderr.contains("containerd") || stderr.contains("unknown") || stderr.contains("engine"),
        "stderr should mention invalid engine: {stderr}"
    );
}

#[test]
fn test_wrap_image_entrypoint_is_runner() {
    let _lock = DOCKER_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    if !common::docker_available() {
        common::skip_container_test("Docker not available");
        return;
    }

    ensure_alpine_image();

    let dir = make_test_dir("entrypoint_runner");
    let runner = create_fake_runner(&dir);
    let policy_path = write_policy(&dir, "policy version=1\n");

    let tag = format!("mcp-writ-test-entrypoint:{}", std::process::id());

    let (_stdout, stderr, code) = run_wrap_image(&[
        "--runner-binary",
        runner.to_str().unwrap(),
        "--policy",
        policy_path.to_str().unwrap(),
        "--tag",
        &tag,
        "alpine:3.19",
    ]);

    assert_eq!(code, 0, "build should succeed: stderr={stderr}");

    // Inspect the built image to verify ENTRYPOINT
    let inspect = Command::new("docker")
        .args(["image", "inspect", &tag])
        .output()
        .unwrap();
    assert!(inspect.status.success());
    let inspect_json = String::from_utf8_lossy(&inspect.stdout);
    assert!(
        inspect_json.contains("/usr/local/bin/mcp-secure-runner"),
        "ENTRYPOINT should be mcp-secure-runner: {inspect_json}"
    );

    // Clean up
    let _ = Command::new("docker").args(["rmi", "-f", &tag]).output();
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn test_wrap_image_preserves_env_vars() {
    let _lock = DOCKER_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    if !common::docker_available() {
        common::skip_container_test("Docker not available");
        return;
    }

    ensure_alpine_image();

    let dir = make_test_dir("env_vars");
    let runner = create_fake_runner(&dir);
    let policy_path = write_policy(&dir, "policy version=1\n");

    let tag = format!("mcp-writ-test-env:{}", std::process::id());

    let (_stdout, stderr, code) = run_wrap_image(&[
        "--runner-binary",
        runner.to_str().unwrap(),
        "--policy",
        policy_path.to_str().unwrap(),
        "--tag",
        &tag,
        "alpine:3.19",
    ]);

    assert_eq!(code, 0, "build should succeed: stderr={stderr}");

    // Check that MCP_ORIG_ENTRYPOINT and MCP_ORIG_CMD env vars exist
    let env_output = Command::new("docker")
        .args(["run", "--rm", "--entrypoint", "env", &tag])
        .output()
        .unwrap();
    let env_str = String::from_utf8_lossy(&env_output.stdout);
    assert!(
        env_str.contains("MCP_ORIG_ENTRYPOINT="),
        "should have MCP_ORIG_ENTRYPOINT env var: {env_str}"
    );
    assert!(
        env_str.contains("MCP_ORIG_CMD="),
        "should have MCP_ORIG_CMD env var: {env_str}"
    );

    // Clean up
    let _ = Command::new("docker").args(["rmi", "-f", &tag]).output();
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn test_wrap_image_inspect_nonexistent_image() {
    let _lock = DOCKER_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    if !common::docker_available() {
        common::skip_container_test("Docker not available");
        return;
    }

    let dir = make_test_dir("nonexistent_image");
    let runner = create_fake_runner(&dir);
    let output_path = dir.join("Dockerfile.out");

    // Use a non-existent image - inspect should fail
    let (_stdout, stderr, code) = run_wrap_image(&[
        "--runner-binary",
        runner.to_str().unwrap(),
        "--output-dockerfile",
        output_path.to_str().unwrap(),
        "nonexistent-image-xyzzy:v999",
    ]);

    assert_ne!(code, 0, "should fail with nonexistent image");
    assert!(
        stderr.contains("inspect")
            || stderr.contains("No such image")
            || stderr.contains("nonexistent"),
        "stderr should mention inspect failure: {stderr}"
    );

    let _ = fs::remove_dir_all(&dir);
}
