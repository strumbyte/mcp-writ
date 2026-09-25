//! Child-environment allowlist end-to-end tests (PR6).
//!
//! The `env_probe` fixture tool reports `os.environ` values from the spawned
//! server process, so the tests observe the environment the Warden actually
//! constructed: restricted allowlist, full inheritance, dry-run,
//! `MCP_WRIT_SKIP_SANDBOX`, and a real sandboxed spawn.
//!
//! The guard process carries `MCP_WRIT_TEST_KEEP=keep` and
//! `MCP_WRIT_TEST_DROP=drop`; the policy allowlists only `KEEP`.

use std::path::Path;
use std::process::Stdio;
use tempfile::TempDir;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::Command;
use tokio::time::{Duration, timeout};

mod common;

const TIMEOUT_SECS: u64 = 15;

struct ChildGuard(tokio::process::Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.start_kill();
    }
}

fn make_test_dir(label: &str) -> TempDir {
    tempfile::Builder::new()
        .prefix(&format!("mcp_writ_environment_{label}_"))
        .tempdir()
        .expect("failed to create temp directory")
}

fn write_policy(dir: &Path, content: &str) -> std::path::PathBuf {
    let path = dir.join("policy.kdl");
    std::fs::write(&path, content).expect("write policy");
    path
}

/// Restricted policy: only MCP_WRIT_TEST_KEEP (plus the automatic baseline)
/// survives into the child. MCP_WRIT_TEST_MISSING is listed but never set on
/// the parent, exercising the listed-but-absent-stays-unset case end to end.
const RESTRICTED_POLICY: &str = r#"
policy version=1
defaults {
    environment {
        allow "MCP_WRIT_TEST_KEEP" "MCP_WRIT_TEST_MISSING"
    }
}
logging level="info" fail_closed=#false
server "env-probe" {
    tool "env_probe"
}
"#;

/// No `environment` node: the child inherits the parent environment.
const INHERIT_POLICY: &str = r#"
policy version=1
logging level="info" fail_closed=#false
server "env-probe" {
    tool "env_probe"
}
"#;

/// `environment` under a tool is a load-time rejection (fail-closed).
const PER_TOOL_ENV_POLICY: &str = r#"
policy version=1
logging level="info" fail_closed=#false
server "env-probe" {
    tool "env_probe" {
        environment {
            allow "MCP_WRIT_TEST_KEEP"
        }
    }
}
"#;

const PARENT_ENV: &[(&str, &str)] = &[
    ("MCP_WRIT_TEST_KEEP", "keep"),
    ("MCP_WRIT_TEST_DROP", "drop"),
];

fn spawn_guard(
    policy_path: &Path,
    dry_run: bool,
    skip_sandbox: bool,
    child_argv: &[String],
    extra_env: &[(&str, &str)],
    cwd: Option<&Path>,
) -> tokio::process::Child {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_mcp-writ"));
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
    ]);
    if dry_run {
        cmd.arg("--dry-run");
    }
    cmd.arg("--");
    cmd.args(child_argv);
    if skip_sandbox {
        cmd.env("MCP_WRIT_SKIP_SANDBOX", "1");
    } else {
        // A parent-level skip var must not leak into the run.
        cmd.env_remove("MCP_WRIT_SKIP_SANDBOX");
    }
    for (key, val) in extra_env {
        cmd.env(key, val);
    }
    if let Some(cwd) = cwd {
        cmd.current_dir(cwd);
    }
    cmd.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn mcp-writ binary - did you run `cargo build`?")
}

fn env_probe_argv() -> Vec<String> {
    let mut argv = common::python3_script_argv("tests/fixtures/mcp_servers/scripted_stdio.py");
    // argv mode selection: MCP_WRIT_FIXTURE would not reach a restricted child.
    argv.push("env_probe".to_string());
    argv
}

async fn send_and_recv(
    stdin: &mut tokio::process::ChildStdin,
    reader: &mut tokio::io::Lines<BufReader<tokio::process::ChildStdout>>,
    request: &str,
) -> Option<String> {
    if stdin
        .write_all(format!("{request}\n").as_bytes())
        .await
        .is_err()
    {
        return None;
    }
    if stdin.flush().await.is_err() {
        return None;
    }
    timeout(Duration::from_secs(TIMEOUT_SECS), async {
        loop {
            match reader.next_line().await {
                Ok(Some(line)) if line.starts_with("{\"jsonrpc\"") => return Some(line),
                Ok(Some(_)) => continue,
                Ok(None) | Err(_) => return None,
            }
        }
    })
    .await
    .ok()
    .flatten()
}

/// Extract `result.content[0].text` — the env_probe payload — as the inner
/// JSON object it carries. `(None, raw)` when the call produced no result.
fn probe_values(response: &str) -> Option<String> {
    let json = nojson::RawJson::parse(response).expect("valid JSON");
    let content = json
        .value()
        .to_member("result")
        .ok()?
        .optional()?
        .to_member("content")
        .ok()?
        .optional()?;
    let items = content.to_array().ok()?;
    let first = items.into_iter().next()?;
    first
        .to_member("text")
        .ok()?
        .optional()?
        .to_unquoted_string_str()
        .ok()
        .map(|s| s.into_owned())
}

/// True when the inner env_probe JSON maps `name` to a string value equal
/// to `expected` (`expected = None` asserts the name maps to null/absent).
fn inner_value_is(inner: &str, name: &str, expected: Option<&str>) -> bool {
    let json = nojson::RawJson::parse(inner).expect("env_probe payload is JSON");
    let member = json.value().to_member(name).ok().and_then(|m| m.optional());
    match (member, expected) {
        (None, None) => true,
        (Some(v), None) => v.kind() == nojson::JsonValueKind::Null,
        (Some(v), Some(want)) => v
            .to_unquoted_string_str()
            .ok()
            .map(|s| s == want)
            .unwrap_or(false),
        (None, Some(_)) => false,
    }
}

/// Call `env_probe` with `arguments.names` and return the inner JSON object
/// text (`{"NAME":"value"|null,...}`).
async fn probe_env(
    stdin: &mut tokio::process::ChildStdin,
    reader: &mut tokio::io::Lines<BufReader<tokio::process::ChildStdout>>,
    id: u32,
    names: &[&str],
) -> Option<String> {
    let names_json = names
        .iter()
        .map(|n| format!("\"{n}\""))
        .collect::<Vec<_>>()
        .join(",");
    let request = format!(
        r#"{{"jsonrpc":"2.0","id":{id},"method":"tools/call","params":{{"name":"env_probe","arguments":{{"names":[{names_json}]}}}}}}"#
    );
    let response = send_and_recv(stdin, reader, &request).await?;
    probe_values(&response)
}

/// The contract asserted by every restricted-environment run: KEEP is
/// copied, DROP is not, PATH survives, the listed-but-unset MISSING stays
/// null.
async fn assert_restricted_env(
    stdin: &mut tokio::process::ChildStdin,
    reader: &mut tokio::io::Lines<BufReader<tokio::process::ChildStdout>>,
    context: &str,
) {
    let inner = probe_env(
        stdin,
        reader,
        1,
        &[
            "MCP_WRIT_TEST_KEEP",
            "MCP_WRIT_TEST_DROP",
            "PATH",
            "MCP_WRIT_TEST_MISSING",
        ],
    )
    .await
    .unwrap_or_else(|| panic!("{context}: env_probe produced no result"));
    assert!(
        inner_value_is(&inner, "MCP_WRIT_TEST_KEEP", Some("keep")),
        "{context}: allowlisted var must reach the child: {inner}"
    );
    assert!(
        inner_value_is(&inner, "MCP_WRIT_TEST_DROP", None),
        "{context}: unlisted parent var must not reach the child: {inner}"
    );
    assert!(
        inner_value_is(&inner, "MCP_WRIT_TEST_MISSING", None),
        "{context}: listed-but-unset var must stay unset: {inner}"
    );
    let path_is_set = {
        let json = nojson::RawJson::parse(&inner).expect("payload JSON");
        json.value()
            .to_member("PATH")
            .ok()
            .and_then(|m| m.optional())
            .and_then(|v| v.to_unquoted_string_str().ok().map(|s| s.into_owned()))
            .is_some_and(|p| !p.is_empty())
    };
    assert!(
        path_is_set,
        "{context}: baseline PATH must survive: {inner}"
    );
}

#[tokio::test]
async fn environment_inherits_by_default() {
    let dir = make_test_dir("inherit");
    let policy = write_policy(dir.path(), INHERIT_POLICY);
    let mut child = spawn_guard(&policy, false, true, &env_probe_argv(), PARENT_ENV, None);
    let mut stdin = child.stdin.take().expect("stdin");
    let stdout = child.stdout.take().expect("stdout");
    let _guard = ChildGuard(child);
    let mut reader = BufReader::new(stdout).lines();

    let inner = probe_env(
        &mut stdin,
        &mut reader,
        1,
        &["MCP_WRIT_TEST_KEEP", "MCP_WRIT_TEST_DROP"],
    )
    .await
    .expect("env_probe produced no result");
    assert!(
        inner_value_is(&inner, "MCP_WRIT_TEST_DROP", Some("drop")),
        "unrestricted child must inherit parent vars: {inner}"
    );
    assert!(
        inner_value_is(&inner, "MCP_WRIT_TEST_KEEP", Some("keep")),
        "unrestricted child must inherit parent vars: {inner}"
    );

    drop(stdin);
}

/// `MCP_WRIT_SKIP_SANDBOX` bypasses only the OS sandbox layer; the
/// environment restriction is part of the launch contract and still applies.
#[tokio::test]
async fn environment_applies_when_sandbox_skipped() {
    let dir = make_test_dir("skip_sandbox");
    let policy = write_policy(dir.path(), RESTRICTED_POLICY);
    let mut child = spawn_guard(&policy, false, true, &env_probe_argv(), PARENT_ENV, None);
    let mut stdin = child.stdin.take().expect("stdin");
    let stdout = child.stdout.take().expect("stdout");
    let _guard = ChildGuard(child);
    let mut reader = BufReader::new(stdout).lines();

    assert_restricted_env(&mut stdin, &mut reader, "skip-sandbox").await;

    drop(stdin);
}

/// `--dry-run` skips the OS sandbox but still spawns the child through the
/// same launch path — the restriction applies there too. `skip_sandbox`
/// stays off so the test exercises the dry-run path alone, not the
/// separate `MCP_WRIT_SKIP_SANDBOX` bypass.
#[tokio::test]
async fn environment_applies_in_dry_run() {
    let dir = make_test_dir("dry_run");
    let policy = write_policy(dir.path(), RESTRICTED_POLICY);
    let mut child = spawn_guard(&policy, true, false, &env_probe_argv(), PARENT_ENV, None);
    let mut stdin = child.stdin.take().expect("stdin");
    let stdout = child.stdout.take().expect("stdout");
    let _guard = ChildGuard(child);
    let mut reader = BufReader::new(stdout).lines();

    assert_restricted_env(&mut stdin, &mut reader, "dry-run").await;

    drop(stdin);
}

/// The interpreter the sandboxed run launches: on Windows `py` delegates to
/// a real `python.exe` whose tree the policy grants must name, so resolve
/// the delegate; elsewhere `python3` resolves through PATH.
fn sandboxed_python_argv0() -> Option<String> {
    if cfg!(windows) {
        let out = std::process::Command::new("py")
            .args(["-3", "-c", "import sys; print(sys.executable)"])
            .output();
        let exe = match out {
            Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).trim().to_string(),
            _ => {
                common::skip_e2e_test("py -3 cannot resolve a python.exe");
                return None;
            }
        };
        if Path::new(&exe).is_file() {
            Some(exe)
        } else {
            common::skip_e2e_test(&format!("resolved python is not a file: {exe}"));
            None
        }
    } else {
        match mcp_writ::workload::resolve_command_path("python3") {
            Ok(p) => Some(p.to_string_lossy().into_owned()),
            Err(_) => {
                common::skip_e2e_test("python3 not on PATH");
                None
            }
        }
    }
}

/// Restricted environment under a real OS sandbox: same policy shape as the
/// real-server tests (`host_defaults_kdl` covers the interpreter), plus an
/// `environment` allowlist. Requires a working sandboxed spawn — when the
/// host cannot provide one the test skips (fail under
/// `MCP_WRIT_REQUIRE_E2E_TESTS=1`).
#[tokio::test]
async fn environment_applies_under_sandbox() {
    let dir = make_test_dir("sandboxed");
    let Some(py) = sandboxed_python_argv0() else {
        return;
    };
    let script =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/mcp_servers/scripted_stdio.py");
    // The sandboxed child needs a granted working directory (Windows refuses
    // to spawn with an ungranted cwd).
    let scratch = dir.path().join("scratch");
    std::fs::create_dir_all(&scratch).expect("mkdir scratch");

    let f = |p: &Path| p.to_string_lossy().replace('\\', "/");
    let mut defaults = common::host_defaults_kdl(&py);
    // Filesystem grants: the fixture script's directory (plus the file
    // itself on Windows, where ACEs are per-object) and the scratch cwd.
    {
        let at = defaults.find("    }\n").expect("filesystem block");
        let mut inject = String::new();
        if let Some(parent) = script.parent() {
            inject.push_str(&format!("        allow \"{}\" mode=\"read\"\n", f(parent)));
        }
        if cfg!(windows) {
            inject.push_str(&format!("        allow \"{}\" mode=\"read\"\n", f(&script)));
        }
        inject.push_str(&format!(
            "        allow \"{}\" mode=\"write\"\n",
            f(&scratch)
        ));
        defaults.insert_str(at, &inject);
    }
    // The environment allowlist inside `defaults` (closes at column 0).
    {
        let at = defaults.rfind("\n}").expect("defaults close") + 1;
        defaults.insert_str(
            at,
            "    environment {\n        allow \"MCP_WRIT_TEST_KEEP\" \"MCP_WRIT_TEST_MISSING\"\n    }\n",
        );
    }
    // `defaults.filesystem` is populated by host_defaults_kdl, so env_probe
    // would inherit a filesystem restriction that demands a path argument.
    // `allow none=#true` + `require-path #false` is the documented opt-out.
    #[allow(unused_mut)]
    let mut policy_text = format!(
        "policy version=1\n{defaults}logging level=\"info\" fail_closed=#false\nserver \"env-probe\" {{\n    tool \"env_probe\" {{\n        filesystem {{\n            allow none=#true\n            require-path #false\n        }}\n    }}\n}}\n"
    );
    #[cfg(target_os = "linux")]
    if common::linux_below_landlock_v4() {
        // Kernel < 6.7 (WSL2's 5.15) applies Landlock ABI V1 partially; a
        // fail-closed spawn would refuse. V1 still enforces the fs ops this
        // test needs; environment restriction is orthogonal to the sandbox.
        policy_text.push_str("sandbox allow_degraded=#true\n");
    }
    let policy = write_policy(dir.path(), &policy_text);

    let argv = vec![py.clone(), f(&script), "env_probe".to_string()];
    let mut child = spawn_guard(&policy, false, false, &argv, PARENT_ENV, Some(&scratch));
    let mut stdin = child.stdin.take().expect("stdin");
    let stdout = child.stdout.take().expect("stdout");
    let mut stderr = child.stderr.take().expect("stderr");
    let mut reader = BufReader::new(stdout).lines();

    let inner = probe_env(
        &mut stdin,
        &mut reader,
        1,
        &["MCP_WRIT_TEST_KEEP", "MCP_WRIT_TEST_DROP", "PATH"],
    )
    .await;
    let Some(inner) = inner else {
        let _ = child.kill().await;
        let mut buf = String::new();
        let _ = timeout(
            Duration::from_secs(TIMEOUT_SECS),
            tokio::io::AsyncReadExt::read_to_string(&mut stderr, &mut buf),
        )
        .await;
        common::skip_e2e_test(&format!(
            "sandboxed spawn produced no result; stderr: {buf}"
        ));
        return;
    };
    let _guard = ChildGuard(child);

    assert!(
        inner_value_is(&inner, "MCP_WRIT_TEST_KEEP", Some("keep")),
        "sandboxed: allowlisted var must reach the child: {inner}"
    );
    assert!(
        inner_value_is(&inner, "MCP_WRIT_TEST_DROP", None),
        "sandboxed: unlisted parent var must not reach the child: {inner}"
    );
    let path_is_set = {
        let json = nojson::RawJson::parse(&inner).expect("payload JSON");
        json.value()
            .to_member("PATH")
            .ok()
            .and_then(|m| m.optional())
            .and_then(|v| v.to_unquoted_string_str().ok().map(|s| s.into_owned()))
            .is_some_and(|p| !p.is_empty())
    };
    assert!(
        path_is_set,
        "sandboxed: baseline PATH must survive: {inner}"
    );

    drop(stdin);
}

/// `environment` beneath a tool is not a per-tool category — the policy is
/// rejected at load with exit code 1 before the server is spawned.
#[tokio::test]
async fn per_tool_environment_is_rejected_at_load() {
    let dir = make_test_dir("per_tool_reject");
    let policy = write_policy(dir.path(), PER_TOOL_ENV_POLICY);

    let output = Command::new(env!("CARGO_BIN_EXE_mcp-writ"))
        .args([
            "run",
            "--transport",
            "stdio",
            "--policy",
            policy.to_str().expect("policy path utf-8"),
            "--audit-log",
            common::next_audit_log_path()
                .to_str()
                .expect("audit log path is utf-8"),
            "--",
            "echo",
        ])
        .env("MCP_WRIT_SKIP_SANDBOX", "1")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await
        .expect("failed to spawn mcp-writ");

    assert!(
        !output.status.success(),
        "per-tool environment must fail policy load: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("per-tool environment"),
        "stderr must carry the rejection reason: {stderr}"
    );
}
