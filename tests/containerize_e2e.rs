//! E2E tests for the `containerize` subcommand.
//!
//! Missing Docker skips locally and fails when MCP_WRIT_REQUIRE_CONTAINER_TESTS=1.
//! Each test uses a unique temp directory and Docker tag for parallel safety.

mod common;

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Mutex;

static DOCKER_LOCK: Mutex<()> = Mutex::new(());

// ─── Helpers ─────────────────────────────────────────────────────────────────

/// Create a uniquely named temp directory. Caller must clean up.
fn make_test_dir(label: &str) -> PathBuf {
    let id = std::process::id();
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("mcp_writ_containerize_e2e_{label}_{id}_{ts}"));
    fs::create_dir_all(&dir).unwrap();
    dir
}

/// Generate a unique Docker image tag for this test invocation.
fn unique_tag(label: &str) -> String {
    let id = std::process::id();
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    format!("mcp-writ-ctrz-e2e-{label}-{id}-{ts}")
}

/// Write a KDL policy file into the given directory.
fn write_policy(dir: &Path, content: &str) -> PathBuf {
    let path = dir.join("policy.kdl");
    fs::write(&path, content).unwrap();
    path
}

/// Create a minimal Node.js MCP server source directory with package.json.
fn create_nodejs_source(dir: &Path) -> PathBuf {
    let source = dir.join("myapp");
    fs::create_dir_all(&source).unwrap();
    fs::write(
        source.join("package.json"),
        r#"{"name":"test-mcp-server","main":"server.js"}"#,
    )
    .unwrap();
    fs::write(
        source.join("server.js"),
        r#"console.log("MCP server running");"#,
    )
    .unwrap();
    source
}

/// Create a minimal Python MCP server source directory.
fn create_python_source(dir: &Path) -> PathBuf {
    let source = dir.join("pyapp");
    fs::create_dir_all(&source).unwrap();
    fs::write(source.join("requirements.txt"), "# no deps\n").unwrap();
    fs::write(source.join("app.py"), "print('MCP server running')\n").unwrap();
    source
}

/// Run `mcp-writ containerize` with the given arguments and return (stdout, stderr, exit_code).
fn run_containerize(args: &[&str]) -> (String, String, i32) {
    let bin = common::mcp_writ_bin();
    let mut cmd_args = vec!["containerize"];
    cmd_args.extend_from_slice(args);

    let output = Command::new(&bin)
        .args(&cmd_args)
        .output()
        .unwrap_or_else(|e| panic!("failed to run mcp-writ containerize: {e}"));

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let code = output.status.code().unwrap_or(-1);
    (stdout, stderr, code)
}

/// Remove a Docker image, ignoring errors.
fn docker_rmi(tag: &str) {
    let _ = Command::new("docker")
        .args(["rmi", "-f", tag])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .output();
}

/// Ensure a fake mcp-secure-runner binary exists at the auto-detection path.
///
/// The `containerize` subcommand doesn't accept `--runner-binary`; it auto-resolves
/// the runner from `<exe_dir>/runners/mcp-secure-runner-linux-<arch>`.
/// For E2E tests we place a small shell script there so Docker build succeeds.
/// Returns `true` if the runner is in place.
fn ensure_fake_runner() -> bool {
    let mut exe_dir = std::env::current_exe().unwrap();
    exe_dir.pop();
    if exe_dir.ends_with("deps") {
        exe_dir.pop();
    }
    let arch = if cfg!(target_arch = "x86_64") {
        "x86_64"
    } else if cfg!(target_arch = "aarch64") {
        "aarch64"
    } else {
        "unknown"
    };
    let runners_dir = exe_dir.join("runners");
    let runner_path = runners_dir.join(format!("mcp-secure-runner-linux-{arch}"));

    if runner_path.exists() {
        return true;
    }

    if fs::create_dir_all(&runners_dir).is_err() {
        return false;
    }
    // Write a minimal shell script that just execs its arguments
    if fs::write(&runner_path, "#!/bin/sh\nexec \"$@\"\n").is_err() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&runner_path, fs::Permissions::from_mode(0o755));
    }
    runner_path.exists()
}

// ─── Docker-independent tests ────────────────────────────────────────────────

#[test]
fn test_containerize_no_args_shows_error() {
    let _lock = DOCKER_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let bin = common::mcp_writ_bin();
    let output = Command::new(&bin).args(["containerize"]).output().unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !output.status.success(),
        "should fail without required arguments"
    );
    assert!(
        stderr.contains("source-dir") || stderr.contains("required"),
        "stderr should mention missing --source-dir: {stderr}"
    );
}

#[test]
fn test_containerize_missing_policy_arg() {
    let _lock = DOCKER_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let dir = make_test_dir("missing_policy_arg");
    let source = create_nodejs_source(&dir);

    let (_, stderr, code) = run_containerize(&["--source-dir", source.to_str().unwrap()]);
    assert_ne!(code, 0, "should fail without --policy");
    assert!(
        stderr.contains("policy") || stderr.contains("required"),
        "stderr should mention missing --policy: {stderr}"
    );

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn test_containerize_nonexistent_source_dir() {
    let _lock = DOCKER_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let dir = make_test_dir("nonexist_src");
    let policy = write_policy(&dir, "policy version=1\n");

    let (_, stderr, code) = run_containerize(&[
        "--source-dir",
        "/nonexistent/path/to/source",
        "--policy",
        policy.to_str().unwrap(),
        "--output-dockerfile",
        dir.join("Dockerfile.out").to_str().unwrap(),
    ]);
    assert_ne!(code, 0, "should fail with nonexistent source dir");
    assert!(
        stderr.contains("not found")
            || stderr.contains("not a directory")
            || stderr.contains("source directory"),
        "stderr should mention source dir issue: {stderr}"
    );

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn test_containerize_help_flag() {
    let _lock = DOCKER_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let bin = common::mcp_writ_bin();
    let output = Command::new(&bin)
        .args(["containerize", "--help"])
        .output()
        .unwrap();
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.contains("source-dir") || combined.contains("containerize"),
        "help should mention containerize options: {combined}"
    );
}

// ─── --output-dockerfile tests (no Docker build needed) ──────────────────────

#[test]
fn test_containerize_output_dockerfile() {
    let _lock = DOCKER_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let dir = make_test_dir("output_df");
    let source = create_nodejs_source(&dir);
    let policy = write_policy(&dir, "policy version=1\n");
    let output_df = dir.join("Dockerfile.out");

    let (_, stderr, code) = run_containerize(&[
        "--source-dir",
        source.to_str().unwrap(),
        "--policy",
        policy.to_str().unwrap(),
        "--output-dockerfile",
        output_df.to_str().unwrap(),
    ]);

    assert_eq!(
        code, 0,
        "should succeed with --output-dockerfile: stderr={stderr}"
    );
    assert!(output_df.exists(), "Dockerfile should be written");

    let content = fs::read_to_string(&output_df).unwrap();
    // Node.js detected → base image should be node:22-slim
    assert!(
        content.contains("FROM node:22-slim"),
        "Dockerfile should use node:22-slim for Node.js source: {content}"
    );
    assert!(
        content.contains("WORKDIR /app"),
        "Dockerfile should set WORKDIR: {content}"
    );
    assert!(
        content.contains(r#"COPY ["mcp-secure-runner", "/usr/local/bin/mcp-secure-runner"]"#),
        "Dockerfile should COPY runner: {content}"
    );
    assert!(
        content.contains(r#"COPY ["policy.kdl", "/etc/mcp-secure/policy.kdl"]"#),
        "Dockerfile should COPY policy: {content}"
    );
    assert!(
        content.contains("MCP_ORIG_CMD="),
        "Dockerfile should set MCP_ORIG_CMD env: {content}"
    );
    assert!(
        content.contains("MCP_WRIT_FAIL_ON=\"\""),
        "Dockerfile must clear MCP_WRIT_FAIL_ON: {content}"
    );
    assert!(
        content.contains("ENTRYPOINT [\"/usr/local/bin/mcp-secure-runner\"]"),
        "Dockerfile should set ENTRYPOINT: {content}"
    );
    // Source files should be COPYed
    assert!(
        content.contains(r#"COPY ["source/"#),
        "Dockerfile should COPY source files: {content}"
    );

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn test_containerize_output_dockerfile_python() {
    let _lock = DOCKER_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let dir = make_test_dir("output_df_py");
    let source = create_python_source(&dir);
    let policy = write_policy(&dir, "policy version=1\n");
    let output_df = dir.join("Dockerfile.out");

    let (_, stderr, code) = run_containerize(&[
        "--source-dir",
        source.to_str().unwrap(),
        "--policy",
        policy.to_str().unwrap(),
        "--output-dockerfile",
        output_df.to_str().unwrap(),
    ]);

    assert_eq!(code, 0, "should succeed: stderr={stderr}");
    assert!(output_df.exists(), "Dockerfile should be written");

    let content = fs::read_to_string(&output_df).unwrap();
    assert!(
        content.contains("FROM python:3.13-slim"),
        "Dockerfile should use python base image: {content}"
    );

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn test_containerize_output_dockerfile_no_build() {
    let _lock = DOCKER_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let dir = make_test_dir("output_df_no_build");
    let source = create_nodejs_source(&dir);
    let policy = write_policy(&dir, "policy version=1\n");
    let output_df = dir.join("Dockerfile.out");

    let (stdout, stderr, code) = run_containerize(&[
        "--source-dir",
        source.to_str().unwrap(),
        "--policy",
        policy.to_str().unwrap(),
        "--output-dockerfile",
        output_df.to_str().unwrap(),
    ]);

    assert_eq!(
        code, 0,
        "should succeed without Docker build: stderr={stderr}"
    );
    // Verify the success message mentions Dockerfile (printed to stdout)
    assert!(
        stdout.contains("Dockerfile"),
        "output should mention Dockerfile written: stdout={stdout}"
    );

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn test_containerize_base_image_override_in_dockerfile() {
    let _lock = DOCKER_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let dir = make_test_dir("base_img_df");
    let source = create_nodejs_source(&dir);
    let policy = write_policy(&dir, "policy version=1\n");
    let output_df = dir.join("Dockerfile.out");

    let (_, stderr, code) = run_containerize(&[
        "--source-dir",
        source.to_str().unwrap(),
        "--policy",
        policy.to_str().unwrap(),
        "--base-image",
        "alpine:3.19",
        "--output-dockerfile",
        output_df.to_str().unwrap(),
    ]);

    assert_eq!(
        code, 0,
        "should succeed with --base-image override: stderr={stderr}"
    );

    let content = fs::read_to_string(&output_df).unwrap();
    assert!(
        content.contains("FROM alpine:3.19"),
        "Dockerfile should use overridden base image: {content}"
    );
    // Should NOT use node:22-slim even though source is Node.js
    assert!(
        !content.contains("FROM node:22-slim"),
        "Dockerfile should NOT use auto-detected base image when overridden: {content}"
    );

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn test_containerize_unknown_runtime_without_base_image_fails() {
    let _lock = DOCKER_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let dir = make_test_dir("unknown_rt");
    // Create a source directory with no recognizable runtime
    let source = dir.join("unknown-src");
    fs::create_dir_all(&source).unwrap();
    fs::write(source.join("README.md"), "not a server").unwrap();
    let policy = write_policy(&dir, "policy version=1\n");
    let output_df = dir.join("Dockerfile.out");

    let (_, stderr, code) = run_containerize(&[
        "--source-dir",
        source.to_str().unwrap(),
        "--policy",
        policy.to_str().unwrap(),
        "--output-dockerfile",
        output_df.to_str().unwrap(),
    ]);

    assert_ne!(code, 0, "should fail when runtime cannot be detected");
    assert!(
        stderr.contains("cannot detect runtime") || stderr.contains("--base-image"),
        "stderr should suggest --base-image: {stderr}"
    );

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn test_containerize_unknown_runtime_with_base_image_but_no_command_fails() {
    let _lock = DOCKER_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    // Unknown runtime yields an empty command, which ContainerizeDockerfileTemplate rejects.
    // Even with --base-image, the source directory must contain recognizable files.
    let dir = make_test_dir("unknown_rt_override");
    let source = dir.join("unknown-src2");
    fs::create_dir_all(&source).unwrap();
    fs::write(source.join("README.md"), "not a server").unwrap();
    let policy = write_policy(&dir, "policy version=1\n");
    let output_df = dir.join("Dockerfile.out");

    let (_, stderr, code) = run_containerize(&[
        "--source-dir",
        source.to_str().unwrap(),
        "--policy",
        policy.to_str().unwrap(),
        "--base-image",
        "ubuntu:24.04",
        "--output-dockerfile",
        output_df.to_str().unwrap(),
    ]);

    assert_ne!(
        code, 0,
        "should fail when command is empty for unknown runtime"
    );
    assert!(
        stderr.contains("command") || stderr.contains("empty"),
        "stderr should mention command issue: {stderr}"
    );

    let _ = fs::remove_dir_all(&dir);
}

// ─── Docker-required tests ───────────────────────────────────────────────────

#[test]
fn test_containerize_nodejs_basic() {
    let _lock = DOCKER_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    if !common::docker_available() {
        common::skip_container_test("Docker not available");
        return;
    }
    if !ensure_fake_runner() {
        common::skip_container_test("could not place fake runner binary");
        return;
    }

    let dir = make_test_dir("nodejs_basic");
    let source = create_nodejs_source(&dir);
    let policy = write_policy(
        &dir,
        r#"
        policy version=1
        server "test" {
            tool "echo_tool"
        }
    "#,
    );
    let tag = unique_tag("nodejs");

    let (_, stderr, code) = run_containerize(&[
        "--source-dir",
        source.to_str().unwrap(),
        "--policy",
        policy.to_str().unwrap(),
        "--tag",
        &tag,
    ]);

    assert_eq!(code, 0, "containerize should succeed: stderr={stderr}");

    // Verify image was created
    let inspect = Command::new("docker")
        .args(["image", "inspect", &tag])
        .output()
        .unwrap();
    assert!(
        inspect.status.success(),
        "built image should exist: {}",
        String::from_utf8_lossy(&inspect.stderr)
    );

    // Verify runner binary is in the image
    let runner_check = Command::new("docker")
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
        runner_check.status.success(),
        "runner should be in image: {}",
        String::from_utf8_lossy(&runner_check.stderr)
    );

    // Verify policy is in the image
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

    // Verify source files are in the image
    let source_check = Command::new("docker")
        .args(["run", "--rm", &tag, "ls", "/app/"])
        .output()
        .unwrap();
    assert!(
        source_check.status.success(),
        "source files should be in /app/: {}",
        String::from_utf8_lossy(&source_check.stderr)
    );
    let ls_output = String::from_utf8_lossy(&source_check.stdout);
    assert!(
        ls_output.contains("server.js") || ls_output.contains("package.json"),
        "source files should be visible in /app/: {ls_output}"
    );

    // Verify ENTRYPOINT is the runner
    let entrypoint_check = Command::new("docker")
        .args(["inspect", "--format", "{{json .Config.Entrypoint}}", &tag])
        .output()
        .unwrap();
    let ep = String::from_utf8_lossy(&entrypoint_check.stdout);
    assert!(
        ep.contains("mcp-secure-runner"),
        "ENTRYPOINT should be mcp-secure-runner: {ep}"
    );

    // Clean up
    docker_rmi(&tag);
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn test_containerize_custom_tag() {
    let _lock = DOCKER_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    if !common::docker_available() {
        common::skip_container_test("Docker not available");
        return;
    }
    if !ensure_fake_runner() {
        common::skip_container_test("could not place fake runner binary");
        return;
    }

    let dir = make_test_dir("custom_tag");
    let source = create_nodejs_source(&dir);
    let policy = write_policy(&dir, "policy version=1\n");
    let tag = unique_tag("custom");

    let (_, stderr, code) = run_containerize(&[
        "--source-dir",
        source.to_str().unwrap(),
        "--policy",
        policy.to_str().unwrap(),
        "--tag",
        &tag,
    ]);

    assert_eq!(code, 0, "should succeed with custom tag: stderr={stderr}");

    // Verify the image exists with our custom tag
    let inspect = Command::new("docker")
        .args(["image", "inspect", &tag])
        .output()
        .unwrap();
    assert!(
        inspect.status.success(),
        "image should exist with custom tag '{}': {}",
        tag,
        String::from_utf8_lossy(&inspect.stderr)
    );

    // Verify the output mentions the tag
    assert!(
        stderr.contains(&tag),
        "stderr should mention the image tag: stderr={stderr}"
    );

    // Clean up
    docker_rmi(&tag);
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn test_containerize_base_image_override() {
    let _lock = DOCKER_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    if !common::docker_available() {
        common::skip_container_test("Docker not available");
        return;
    }
    if !ensure_fake_runner() {
        common::skip_container_test("could not place fake runner binary");
        return;
    }

    let dir = make_test_dir("base_override");
    let source = create_nodejs_source(&dir);
    let policy = write_policy(&dir, "policy version=1\n");
    let tag = unique_tag("baseimg");

    // Override base image to alpine instead of node:22-slim
    let (_, stderr, code) = run_containerize(&[
        "--source-dir",
        source.to_str().unwrap(),
        "--policy",
        policy.to_str().unwrap(),
        "--tag",
        &tag,
        "--base-image",
        "alpine:3.19",
    ]);

    assert_eq!(code, 0, "should succeed with --base-image: stderr={stderr}");

    // Verify image was created
    let inspect = Command::new("docker")
        .args(["image", "inspect", &tag])
        .output()
        .unwrap();
    assert!(
        inspect.status.success(),
        "image should exist: {}",
        String::from_utf8_lossy(&inspect.stderr)
    );

    // Verify the image is based on alpine (not node)
    // Check that /etc/alpine-release exists in the image
    let alpine_check = Command::new("docker")
        .args(["run", "--rm", &tag, "cat", "/etc/alpine-release"])
        .output()
        .unwrap();
    assert!(
        alpine_check.status.success(),
        "image should be based on alpine: {}",
        String::from_utf8_lossy(&alpine_check.stderr)
    );

    // Clean up
    docker_rmi(&tag);
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn test_containerize_policy_injection() {
    let _lock = DOCKER_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    if !common::docker_available() {
        common::skip_container_test("Docker not available");
        return;
    }
    if !ensure_fake_runner() {
        common::skip_container_test("could not place fake runner binary");
        return;
    }

    let dir = make_test_dir("policy_inject");
    let source = create_nodejs_source(&dir);
    let policy_content = r#"
        policy version=1
        server "test" {
            tool "read_file"
            tool "write_file" deny=#true
        }
    "#;
    let policy = write_policy(&dir, policy_content);
    let tag = unique_tag("policy");

    let (_, stderr, code) = run_containerize(&[
        "--source-dir",
        source.to_str().unwrap(),
        "--policy",
        policy.to_str().unwrap(),
        "--tag",
        &tag,
    ]);

    assert_eq!(code, 0, "should succeed: stderr={stderr}");

    // Read the policy back from the container
    let policy_read = Command::new("docker")
        .args(["run", "--rm", &tag, "cat", "/etc/mcp-secure/policy.kdl"])
        .output()
        .unwrap();
    assert!(
        policy_read.status.success(),
        "should be able to read policy from container: {}",
        String::from_utf8_lossy(&policy_read.stderr)
    );
    let container_policy = String::from_utf8_lossy(&policy_read.stdout);
    assert!(
        container_policy.contains("read_file"),
        "policy should contain read_file tool: {container_policy}"
    );
    assert!(
        container_policy.contains("write_file"),
        "policy should contain write_file tool: {container_policy}"
    );
    assert!(
        container_policy.contains("version"),
        "policy should contain version: {container_policy}"
    );

    // Clean up
    docker_rmi(&tag);
    let _ = fs::remove_dir_all(&dir);
}
