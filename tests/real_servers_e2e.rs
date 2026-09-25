//! PR2: real pinned MCP servers as the verification foundation.
//!
//! The servers are the actual pinned packages under
//! `tests/fixtures/real_servers` (install via `setup.sh` / `setup.ps1`);
//! no mock servers are used here.
//!
//! Six stages per server (docs/archive/stdio-hardening-runbook.ja.md, PR2):
//!   1. `generate-policy --live-discovery` — the generated policy's
//!      `tools-list-hash` must equal the hash pinned in
//!      `examples/policies/<name>.kdl`, and the tool count must match.
//!   2. `run --dry-run` — initialize + tools/list + an allowed tools/call.
//!      The Auditor runs; the OS sandbox does not.
//!   3. `run` sandboxed — the same allowed call must succeed at the OS.
//!   4. `run` sandboxed — an Auditor-layer denial: JSON-RPC error plus a
//!      `tool_call.denied` audit event.
//!   5. `run` sandboxed — a denial below the Auditor: `result.isError` or
//!      a failed startup, and the audit log must NOT carry
//!      `tool_call.denied`. Linux composes every per-tool fs grant into the
//!      process-wide Landlock ruleset, so the filesystem server's stage-5
//!      call succeeds there — a recorded divergence, not a workaround.
//!   6. Hash pinning — `run` passes tools/list with the pinned hash; a
//!      corrupted pin must fail.
//!
//! Missing prerequisites (fixture not installed, interpreter absent,
//! sandboxed spawn unavailable) skip a stage; `MCP_WRIT_REQUIRE_SERVER_TESTS=1`
//! turns every skip into a failure.

use std::path::{Path, PathBuf};
use std::process::Stdio;

use tempfile::TempDir;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::time::{Duration, timeout};

mod common;

const TIMEOUT_SECS: u64 = 30;

/// Serialize the per-server stages on Windows: concurrent guards grant the
/// same shared fixture trees (`node/`, `python/.venv`) with per-process
/// container SIDs, and a guard's teardown restores the pre-grant DACL,
/// wiping any sibling guard's propagated ACEs mid-run.
static STAGE_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

// ─── server descriptors ───────────────────────────────────────────────────

struct ServerSpec {
    /// `server` identity and the `examples/policies/<name>.kdl` stem.
    name: &'static str,
    /// `examples/policies/runtime/<runtime>.kdl`.
    runtime: &'static str,
    /// tools-list-hash pinned in the example policy (mcp-guard-tools-list-v4).
    expected_hash: &'static str,
    /// Tool count observed by live discovery at the pinned version.
    tool_count: usize,
}

const FILESYSTEM: ServerSpec = ServerSpec {
    name: "filesystem",
    runtime: "node",
    expected_hash: "sha256:1ef36fd736d82bacdbb5bce1dda540553a2b59e07c625249845296845a335a26",
    tool_count: 14,
};
const MEMORY: ServerSpec = ServerSpec {
    name: "memory",
    runtime: "node",
    expected_hash: "sha256:0ae46ff5e9dee8192e577615964eb12d3b3b4ddcaee608049c201267842c3fa8",
    tool_count: 9,
};
const TIME: ServerSpec = ServerSpec {
    name: "time",
    runtime: "python",
    // Launched with `--local-timezone UTC`: the server embeds the detected
    // local zone in its tool schemas, so the hash is host-dependent unless
    // the zone is pinned.
    expected_hash: "sha256:194aba9e881fd6f061b6c80175838c4d82a30ad2f8a53a68e68585f39422bb7c",
    tool_count: 2,
};
const GIT: ServerSpec = ServerSpec {
    name: "git",
    runtime: "python",
    expected_hash: "sha256:6d33f714008a03d44fcb8458e95fa8b5374240837f04e6bd5db86e49ac7e6410",
    tool_count: 12,
};

fn fixtures_dir() -> PathBuf {
    common::real_servers_dir()
}

fn venv_python() -> PathBuf {
    let venv = fixtures_dir().join("python/.venv");
    if cfg!(windows) {
        venv.join("Scripts/python.exe")
    } else {
        venv.join("bin/python")
    }
}

fn node_entry(spec: &ServerSpec) -> PathBuf {
    fixtures_dir()
        .join("node/node_modules/@modelcontextprotocol")
        .join(format!("server-{}", spec.name))
        .join("dist/index.js")
}

/// Windows-only preload: Node's `fs.realpath` (libuv →
/// `GetFinalPathNameByHandleW`) cannot work under an AppContainer token — the
/// NT volume namespace is not DACL-grantable — so the stub replaces realpath
/// with the identity function. See the fixture file for details.
#[cfg(windows)]
fn win_realpath_stub() -> PathBuf {
    fixtures_dir().join("node/win-realpath-stub.cjs")
}

/// Launch argv for a server, or `None` when a prerequisite is missing.
fn server_argv(spec: &ServerSpec, extra_args: &[String]) -> Option<Vec<String>> {
    match spec.runtime {
        "node" => {
            let entry = node_entry(spec);
            if mcp_writ::workload::resolve_command_path("node").is_err() {
                common::skip_server_test("node not on PATH");
                return None;
            }
            if !entry.is_file() {
                common::skip_server_test(&format!(
                    "node fixture not installed: {}",
                    entry.display()
                ));
                return None;
            }
            let mut argv = vec!["node".to_string()];
            #[cfg(windows)]
            {
                let stub = win_realpath_stub();
                if !stub.is_file() {
                    common::skip_server_test(&format!(
                        "windows realpath stub missing: {}",
                        stub.display()
                    ));
                    return None;
                }
                // AppContainer cannot resolve entry-path ancestors (the drive
                // root is ungrantable), so the module loader's realpath walk
                // must be skipped; the stub covers runtime fs.realpath calls.
                argv.extend([
                    "--preserve-symlinks-main".to_string(),
                    "--preserve-symlinks".to_string(),
                    "--require".to_string(),
                    stub.to_string_lossy().into_owned(),
                ]);
            }
            argv.push(entry.to_string_lossy().into_owned());
            argv.extend(extra_args.iter().cloned());
            Some(argv)
        }
        "python" => {
            let py = venv_python();
            if !py.is_file() {
                common::skip_server_test(&format!("python venv not installed: {}", py.display()));
                return None;
            }
            let module = match spec.name {
                "time" => "mcp_server_time",
                "git" => "mcp_server_git",
                other => panic!("unknown python server: {other}"),
            };
            let mut argv = vec![
                py.to_string_lossy().into_owned(),
                "-m".to_string(),
                module.to_string(),
            ];
            // mcp-server-time detects the local zone at startup and embeds
            // it in its tool schemas; pin it so tools/list — and the hash
            // pinned in time.kdl — is host-independent.
            if spec.name == "time" {
                argv.extend(["--local-timezone".to_string(), "UTC".to_string()]);
            }
            argv.extend(extra_args.iter().cloned());
            Some(argv)
        }
        other => panic!("unknown runtime: {other}"),
    }
}

// ─── JSON helpers ─────────────────────────────────────────────────────────

fn json_str(s: &str) -> String {
    let mut out = String::from("\"");
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// A path inside a KDL string: forward slashes are safe on every platform.
fn kdl_path(p: &Path) -> String {
    p.to_string_lossy().replace('\\', "/")
}

fn parse(resp: &str) -> nojson::RawJson<'_> {
    nojson::RawJson::parse(resp).expect("response must be JSON")
}

fn json_has_error(resp: &str) -> bool {
    parse(resp)
        .value()
        .to_member("error")
        .ok()
        .and_then(|m| m.optional())
        .is_some()
}

fn is_error_result(resp: &str) -> bool {
    parse(resp)
        .value()
        .to_member("result")
        .ok()
        .and_then(|m| m.optional())
        .and_then(|r| r.to_member("isError").ok().and_then(|m| m.optional()))
        .and_then(|v| v.as_boolean_str().ok())
        == Some("true")
}

fn negotiated_protocol(resp: &str) -> Option<String> {
    parse(resp)
        .value()
        .to_member("result")
        .ok()?
        .optional()?
        .to_member("protocolVersion")
        .ok()?
        .optional()?
        .to_unquoted_string_str()
        .ok()
        .map(|s| s.into_owned())
}

/// True when `line` is the response to the in-flight request: it parses
/// as JSON, carries a top-level `id` equal to `seq`, and has no `method`
/// member. Malformed lines, notifications, and server-initiated requests
/// are skipped.
fn is_response_for(line: &str, seq: u64) -> bool {
    let Ok(json) = nojson::RawJson::parse(line.trim()) else {
        return false;
    };
    if mcp_writ::protocol::value_has_member(json.value(), "method") {
        return false;
    }
    json.value()
        .to_member("id")
        .ok()
        .and_then(|m| m.optional())
        .and_then(|id| id.as_raw_str().parse::<u64>().ok())
        == Some(seq)
}

/// Extract `tools-list-hash "<value>"` from a policy text.
fn pinned_hash_in(text: &str) -> Option<String> {
    let needle = "tools-list-hash \"";
    let at = text.find(needle)? + needle.len();
    let rest = &text[at..];
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

/// `tool "name"` entries declared in `examples/policies/<spec>.kdl`.
fn example_tool_names(spec: &ServerSpec) -> Vec<String> {
    let text = std::fs::read_to_string(example_policy_path(spec)).expect("example policy readable");
    text.lines()
        .filter_map(|line| {
            line.trim_start()
                .strip_prefix("tool \"")?
                .split('"')
                .next()
                .map(str::to_string)
        })
        .collect()
}

/// Names in `result.tools` of a tools/list response line.
fn response_tool_names(resp: &str) -> Vec<String> {
    let mut names = Vec::new();
    let json = parse(resp);
    let Some(tools) = json
        .value()
        .to_member("result")
        .ok()
        .and_then(|m| m.optional())
        .and_then(|r| r.to_member("tools").ok().and_then(|m| m.optional()))
    else {
        return names;
    };
    if let Ok(items) = tools.to_array() {
        for item in items {
            if let Some(name) = item
                .to_member("name")
                .ok()
                .and_then(|m| m.optional())
                .and_then(|v| v.to_unquoted_string_str().ok())
            {
                names.push(name.into_owned());
            }
        }
    }
    names
}

// ─── guard session ────────────────────────────────────────────────────────

struct GuardSession {
    child: tokio::process::Child,
    stdin: Option<tokio::process::ChildStdin>,
    reader: tokio::io::Lines<BufReader<tokio::process::ChildStdout>>,
    stderr_task: Option<tokio::task::JoinHandle<String>>,
    seq: u64,
}

impl Drop for GuardSession {
    fn drop(&mut self) {
        let _ = self.child.start_kill();
    }
}

impl GuardSession {
    fn spawn(
        policy_path: &Path,
        audit_log: &Path,
        argv: &[String],
        env: &[(&str, &str)],
        dry_run: bool,
        cwd: Option<&Path>,
    ) -> Self {
        let mut child = common::spawn_guard(policy_path, audit_log, argv, env, dry_run, cwd);
        let stdin = child.stdin.take().expect("guard stdin");
        let stdout = child.stdout.take().expect("guard stdout");
        let mut stderr = child.stderr.take().expect("guard stderr");
        let stderr_task = tokio::spawn(async move {
            let mut buf = String::new();
            tokio::io::AsyncReadExt::read_to_string(&mut stderr, &mut buf)
                .await
                .ok();
            buf
        });
        Self {
            child,
            stdin: Some(stdin),
            reader: BufReader::new(stdout).lines(),
            stderr_task: Some(stderr_task),
            seq: 0,
        }
    }

    async fn send(&mut self, line: &str) -> bool {
        let Some(stdin) = self.stdin.as_mut() else {
            return false;
        };
        if stdin
            .write_all(format!("{line}\n").as_bytes())
            .await
            .is_err()
        {
            return false;
        }
        stdin.flush().await.is_ok()
    }

    async fn recv(&mut self) -> Option<String> {
        timeout(Duration::from_secs(TIMEOUT_SECS), async {
            loop {
                match self.reader.next_line().await {
                    // JSON-RPC member order is not fixed: the filesystem
                    // server emits `{"result":{...},"jsonrpc":"2.0","id":1}`.
                    // Only the response to the in-flight request id counts;
                    // notifications and unrelated responses are skipped.
                    Ok(Some(line)) if is_response_for(&line, self.seq) => {
                        return Some(line);
                    }
                    Ok(Some(_)) => continue,
                    Ok(None) | Err(_) => return None,
                }
            }
        })
        .await
        .ok()
        .flatten()
    }

    fn request(&mut self, method: &str, params: &str) -> String {
        self.seq += 1;
        format!(
            "{{\"jsonrpc\":\"2.0\",\"id\":{},\"method\":\"{method}\",\"params\":{params}}}",
            self.seq
        )
    }

    /// initialize + notifications/initialized; returns the negotiated
    /// protocol version on success.
    async fn handshake(&mut self) -> Option<String> {
        let req = self.request(
            "initialize",
            "{\"protocolVersion\":\"2025-11-25\",\"capabilities\":{},\"clientInfo\":{\"name\":\"real-servers-e2e\",\"version\":\"0\"}}",
        );
        if !self.send(&req).await {
            return None;
        }
        let resp = self.recv().await?;
        if json_has_error(&resp) {
            return None;
        }
        let version = negotiated_protocol(&resp);
        self.send("{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\",\"params\":{}}")
            .await;
        version
    }

    async fn tools_list(&mut self) -> Option<String> {
        let req = self.request("tools/list", "{}");
        if !self.send(&req).await {
            return None;
        }
        self.recv().await
    }

    async fn call(&mut self, tool: &str, args: &str) -> Option<String> {
        let req = self.request(
            "tools/call",
            &format!(
                "{{\"name\":{json},\"arguments\":{args}}}",
                json = json_str(tool)
            ),
        );
        if !self.send(&req).await {
            return None;
        }
        self.recv().await
    }

    /// Kill the guard and drain stderr for diagnostics.
    async fn shutdown_stderr(mut self) -> String {
        drop(self.stdin.take());
        let _ = self.child.start_kill();
        let _ = self.child.wait().await;
        let stderr = match self.stderr_task.take() {
            Some(task) => timeout(Duration::from_secs(5), task)
                .await
                .ok()
                .and_then(|r| r.ok())
                .unwrap_or_default(),
            None => String::new(),
        };
        format!("--- guard stderr ---\n{stderr}")
    }

    /// Close stdin, wait briefly for the guard to exit so the audit log is
    /// flushed, then return the audit text plus stderr for diagnostics.
    async fn finish_audit(mut self, audit_log: &Path) -> String {
        drop(self.stdin.take());
        let _ = timeout(Duration::from_secs(TIMEOUT_SECS), self.child.wait()).await;
        let _ = self.child.start_kill();
        let stderr = match self.stderr_task.take() {
            Some(task) => timeout(Duration::from_secs(5), task)
                .await
                .ok()
                .and_then(|r| r.ok())
                .unwrap_or_default(),
            None => String::new(),
        };
        let audit = std::fs::read_to_string(audit_log).unwrap_or_default();
        format!("{audit}\n--- guard stderr ---\n{stderr}")
    }
}

/// `Some(line)` if the audit log carries a `tool_call.denied` event.
fn audit_denied_line(audit: &str) -> Option<String> {
    audit
        .lines()
        .find(|l| l.contains("\"event_type\":\"tool_call.denied\""))
        .map(str::to_string)
}

// ─── per-stage policy composition ─────────────────────────────────────────

fn example_policy_path(spec: &ServerSpec) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("examples/policies")
        .join(format!("{}.kdl", spec.name))
}

/// Insert `allow` entries into the `filesystem` block of a host policy
/// (the first `    }` line closes it — `host_defaults_kdl` emits the
/// filesystem block first inside `defaults`).
fn inject_fs_grants(policy: &mut String, grants: &[(&Path, &str)]) {
    if grants.is_empty() {
        return;
    }
    let at = policy.find("    }\n").expect("filesystem block");
    let mut inject = String::new();
    for (dir, mode) in grants {
        inject.push_str(&format!(
            "        allow \"{}\" mode=\"{mode}\"\n",
            kdl_path(dir)
        ));
    }
    policy.insert_str(at, &inject);
}

/// Insert an `environment { allow ... }` block into the `defaults` block of
/// a host policy (the defaults close is the first `}` at column 0). A
/// non-empty overlay replaces an `environment` block inherited via
/// `extends` — the same rule as `syscalls`.
fn inject_environment(policy: &mut String, allow_names: &[&str]) {
    let start = policy.find("defaults {").expect("defaults block");
    let close = policy[start..]
        .find("\n}\n")
        .map(|i| start + i + 1)
        .expect("defaults close");
    let mut inject = String::from("    environment {\n");
    if !allow_names.is_empty() {
        inject.push_str("        allow");
        for name in allow_names {
            inject.push_str(&format!(" \"{name}\""));
        }
        inject.push('\n');
    }
    inject.push_str("    }\n");
    policy.insert_str(close, &inject);
}

/// host.kdl = extends <example> + host defaults + logging + extra server
/// overrides (per-tool fs with real paths, or a corrupted hash pin).
fn host_policy(spec: &ServerSpec, argv0: &str, extra_kdl: &str) -> String {
    #[allow(unused_mut)]
    let mut out = format!(
        "policy version=1\nextends \"{}\"\n{}logging level=\"info\" fail_closed=#false\n{}",
        kdl_path(&example_policy_path(spec)),
        common::host_defaults_kdl(argv0),
        extra_kdl
    );
    #[cfg(target_os = "linux")]
    if common::linux_below_landlock_v4() {
        // Kernel < 6.7 (e.g. WSL2's 5.15) supports only Landlock ABI V1, so
        // the ruleset applies partially and a fail-closed spawn would refuse
        // to launch. V1 still denies the read/write ops these stages
        // exercise; CI (kernel >= 6.7) runs fully enforced. Recorded in
        // docs/archive/stdio-hardening-results.ja.md.
        out.push_str("sandbox allow_degraded=#true\n");
    }
    out
}

fn write_policy(dir: &Path, name: &str, text: &str) -> PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, text).expect("write host policy");
    path
}

// ─── stage 1: live discovery ──────────────────────────────────────────────

fn stage1_live_discovery(spec: &ServerSpec, argv: &[String], work: &Path) {
    let out = work.join(format!("genpol-{}.kdl", spec.name));
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_mcp-writ"))
        .args(["generate-policy", "--live-discovery", "--output"])
        .arg(&out)
        .arg("--")
        .args(argv)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output()
        .expect("spawn generate-policy");
    assert!(
        output.status.success(),
        "stage1 {0}: generate-policy --live-discovery failed: {1}",
        spec.name,
        String::from_utf8_lossy(&output.stderr)
    );
    let text = std::fs::read_to_string(&out).expect("generated policy readable");
    let hash = pinned_hash_in(&text).expect("generated policy has tools-list-hash");
    assert_eq!(
        hash, spec.expected_hash,
        "stage1 {}: generated hash must equal the pinned example hash",
        spec.name
    );
    let tools =
        text.matches("\n    tool \"").count() + usize::from(text.starts_with("    tool \""));
    assert_eq!(
        tools, spec.tool_count,
        "stage1 {}: generated tool count",
        spec.name
    );
    stage1_workload_hashes(spec, &text, &out);
}

/// PR5: the draft must also pin the launch target. Both runtimes get a
/// `binary-hash` for the resolved argv[0]. A `node <entry>` launch binds the
/// script via `entrypoint-hash`; `python -m` cannot bind the module from
/// argv, so the draft records the reason instead of fabricating a hash.
/// Every emitted hash must match the file it names.
fn stage1_workload_hashes(spec: &ServerSpec, text: &str, out: &Path) {
    assert!(
        text.contains("binary-hash \"sha256:"),
        "stage1 {}: generated policy must pin argv[0] with binary-hash",
        spec.name
    );
    match spec.runtime {
        "node" => assert!(
            text.contains("entrypoint-hash \"sha256:"),
            "stage1 {}: node launch must pin the script with entrypoint-hash",
            spec.name
        ),
        "python" => {
            assert!(
                text.contains("// REVIEW: entrypoint-hash not emitted"),
                "stage1 {}: python -m must record why the payload is unbound",
                spec.name
            );
            assert!(
                !text.contains("entrypoint-hash \""),
                "stage1 {}: python -m must not fabricate an entrypoint hash",
                spec.name
            );
        }
        other => panic!("unknown runtime: {other}"),
    }
    let policy =
        mcp_writ::policy::kdl_loader::load_kdl_policy(out).expect("generated policy must load");
    assert!(
        !policy.hash_entries.is_empty(),
        "stage1 {}: generated policy must carry workload hash entries",
        spec.name
    );
    if spec.runtime == "node" {
        // The entrypoint pin must name dist/index.js — not the operand of a
        // value-taking option (Windows preloads win-realpath-stub.cjs via
        // `--require`, which must not become the pinned payload).
        let entry = policy
            .hash_entries
            .iter()
            .find(|e| e.hash_type == mcp_writ::policy::HashType::Entrypoint)
            .expect("node draft carries entrypoint-hash");
        assert_eq!(
            std::fs::canonicalize(&entry.target).expect("entrypoint target canonicalizes"),
            std::fs::canonicalize(node_entry(spec)).expect("node entry canonicalizes"),
            "stage1 {}: entrypoint-hash must pin dist/index.js, not an option operand",
            spec.name
        );
    }
    for e in &policy.hash_entries {
        assert!(
            mcp_writ::verifier::hash::verify_hash(Path::new(&e.target), &e.hash_value)
                .unwrap_or(false),
            "stage1 {}: {} target '{}' must hash to {}",
            spec.name,
            e.hash_type.as_str(),
            e.target,
            e.hash_value
        );
    }
}

// ─── shared session drivers ───────────────────────────────────────────────

/// Canonicalized temp root so resolved paths compare cleanly. The `\\?\`
/// verbatim prefix is stripped — it is neither a valid argv spelling for the
/// servers nor a usable DACL-grant path.
fn temp_root(prefix: &str) -> (TempDir, PathBuf) {
    let t = tempfile::Builder::new()
        .prefix(prefix)
        .tempdir()
        .expect("tempdir");
    let root = t.path().canonicalize().expect("canonical temp root");
    let root = match root.to_string_lossy().strip_prefix(r"\\?\") {
        Some(rest) => PathBuf::from(rest),
        None => root,
    };
    (t, root)
}

/// An allowed tools/call exercised in stage 2: tool name, JSON args, and a
/// substring the response must carry (empty = no marker check).
struct PositiveCall<'a> {
    tool: &'a str,
    args: &'a str,
    marker: &'a str,
}

/// Stage 2: `run --dry-run` — handshake, tools/list, one allowed call.
async fn stage2_dry_run(
    spec: &ServerSpec,
    policy_path: &Path,
    argv: &[String],
    env: &[(&str, &str)],
    cwd: Option<&Path>,
    positive: PositiveCall<'_>,
) -> bool {
    let audit_log = common::next_audit_log_path();
    let mut session = GuardSession::spawn(policy_path, &audit_log, argv, env, true, cwd);
    let Some(version) = session.handshake().await else {
        let stderr = session.shutdown_stderr().await;
        common::skip_server_test(&format!(
            "stage2 {}: no initialize response; stderr: {stderr}",
            spec.name
        ));
        return false;
    };
    eprintln!("{}: negotiated protocol {}", spec.name, version);
    let Some(list) = session.tools_list().await else {
        let stderr = session.shutdown_stderr().await;
        common::skip_server_test(&format!(
            "stage2 {}: no tools/list response; stderr: {stderr}",
            spec.name
        ));
        return false;
    };
    assert!(
        !json_has_error(&list),
        "stage2 {}: tools/list must pass hash pinning: {list}",
        spec.name
    );
    let Some(resp) = session.call(positive.tool, positive.args).await else {
        let stderr = session.shutdown_stderr().await;
        common::skip_server_test(&format!(
            "stage2 {}: allowed call produced no response; stderr: {stderr}",
            spec.name
        ));
        return false;
    };
    assert!(
        !json_has_error(&resp) && !is_error_result(&resp),
        "stage2 {}: allowed call must succeed: {resp}",
        spec.name
    );
    if !positive.marker.is_empty() {
        assert!(
            resp.contains(positive.marker),
            "stage2 {}: response must carry the marker '{}': {resp}",
            spec.name,
            positive.marker
        );
    }
    true
}

/// Stage 3 start: sandboxed spawn + handshake + tools/list.
/// Returns `None` (after `skip_server_test`) when the sandboxed spawn is
/// unavailable on this host.
async fn stage3_spawn(
    spec: &ServerSpec,
    policy_path: &Path,
    argv: &[String],
    env: &[(&str, &str)],
    cwd: Option<&Path>,
) -> Option<(GuardSession, PathBuf)> {
    let audit_log = common::next_audit_log_path();
    let mut session = GuardSession::spawn(policy_path, &audit_log, argv, env, false, cwd);
    if session.handshake().await.is_none() {
        let stderr = session.shutdown_stderr().await;
        common::skip_server_test(&format!(
            "stage3 {}: sandboxed spawn produced no initialize response; stderr: {stderr}",
            spec.name
        ));
        return None;
    }
    let list = session.tools_list().await;
    assert!(
        list.as_deref().is_some_and(|l| !json_has_error(l)),
        "stage3 {}: tools/list must pass hash pinning: {list:?}",
        spec.name
    );
    Some((session, audit_log))
}

/// Stage 6: a corrupted `tools-list-hash` pin must fail tools/list. The bad
/// policy carries the same OS grants as the main one so the failure can only
/// come from the pin mismatch.
async fn stage6_bad_hash(
    spec: &ServerSpec,
    argv0: &str,
    argv: &[String],
    env: &[(&str, &str)],
    dir: &Path,
    grants: &[(&Path, &str)],
    cwd: Option<&Path>,
) {
    // Flip every hex digit so the pin differs from the recorded hash no
    // matter which characters it happens to contain; the `sha256:` prefix
    // must survive or the policy fails parse instead of the pin check.
    let (alg, hex) = spec
        .expected_hash
        .split_once(':')
        .expect("expected_hash must be '<alg>:<hex>'");
    let wrong_hash = format!(
        "{alg}:{}",
        hex.chars()
            .map(|c| if c == 'f' { '0' } else { 'f' })
            .collect::<String>()
    );
    assert_ne!(wrong_hash, spec.expected_hash);
    let mut bad = host_policy(
        spec,
        argv0,
        &format!(
            "server \"{}\" {{\n    tools-list-hash \"{wrong_hash}\"\n}}\n",
            spec.name
        ),
    );
    inject_fs_grants(&mut bad, grants);
    let bad_path = write_policy(dir, &format!("host-{}-bad.kdl", spec.name), &bad);
    let audit = common::next_audit_log_path();
    let mut s = GuardSession::spawn(&bad_path, &audit, argv, env, false, cwd);
    // The pin check applies to tools/list: a failed handshake is a startup
    // failure, not a pin-check pass — require it before proceeding.
    let hs = s.handshake().await;
    assert!(
        hs.is_some(),
        "stage6 {}: handshake must succeed before the tools/list pin check",
        spec.name
    );
    let list = s.tools_list().await;
    assert!(
        list.is_none() || json_has_error(list.as_deref().unwrap_or("")),
        "stage6 {}: corrupted tools-list-hash must fail tools/list: {list:?}",
        spec.name
    );
    s.shutdown_stderr().await;
}

// ─── filesystem ───────────────────────────────────────────────────────────

#[tokio::test]
async fn filesystem_stages() {
    let _stage_lock = STAGE_LOCK.lock().await;
    let spec = &FILESYSTEM;
    let (_t, root) = temp_root("mcp_writ_rs_fs_");
    let srv = root.join("srv");
    let data = srv.join("data");
    let restricted = srv.join("restricted");
    let secret_dir = srv.join(".ssh");
    for d in [&data, &restricted, &secret_dir] {
        std::fs::create_dir_all(d).expect("mkdir");
    }
    let marker = format!("MARKER-FS-{}", std::process::id());
    let marker_file = data.join("marker.txt");
    std::fs::write(&marker_file, format!("{marker}\n")).expect("marker");
    let restricted_file = restricted.join("secret.txt");
    std::fs::write(&restricted_file, "SECRET-FS\n").expect("restricted");
    let ssh_file = secret_dir.join("id_rsa");
    std::fs::write(&ssh_file, "FAKE-PRIVATE-KEY\n").expect("ssh file");

    // stage 1: live discovery (argv allowed dir = data)
    let argv_main = match server_argv(spec, &[kdl_path(&data)]) {
        Some(a) => a,
        None => return,
    };
    stage1_live_discovery(spec, &argv_main, &root);

    // host policy: tool fs = srv/** (Auditor scope), defaults grant = data
    // only — `restricted` is never granted, so the OS layer denies it.
    let srv_glob = format!("{}/**", kdl_path(&srv));
    let server_extra = format!(
        "server \"filesystem\" {{\n    tool \"read_file\" {{\n        filesystem {{\n            allow \"{srv_glob}\"\n        }}\n    }}\n}}\n"
    );
    let mut host_kdl = host_policy(spec, &argv_main[0], &server_extra);
    let fs_grants: &[(&Path, &str)] = &[(&data, "read")];
    inject_fs_grants(&mut host_kdl, fs_grants);
    let policy_path = write_policy(&root, "host-fs.kdl", &host_kdl);

    let positive_args = format!("{{\"path\":{}}}", json_str(&kdl_path(&marker_file)));

    // stage 2: dry-run (Auditor only). The guard cwd is a granted dir so a
    // spawned child inherits a working directory it may access.
    if !stage2_dry_run(
        spec,
        &policy_path,
        &argv_main,
        &[],
        Some(&data),
        PositiveCall {
            tool: "read_file",
            args: &positive_args,
            marker: &marker,
        },
    )
    .await
    {
        return;
    }

    // stage 3 + 4: sandboxed session — allowed call, then Auditor denial
    let Some((mut s3, audit3)) =
        stage3_spawn(spec, &policy_path, &argv_main, &[], Some(&data)).await
    else {
        return;
    };
    let resp = s3.call("read_file", &positive_args).await;
    assert!(
        resp.as_deref()
            .is_some_and(|r| !json_has_error(r) && !is_error_result(r)),
        "stage3 filesystem: sandboxed allowed call must succeed: {resp:?}"
    );
    assert!(
        resp.as_deref().is_some_and(|r| r.contains(&marker)),
        "stage3 filesystem: marker must reach the client: {resp:?}"
    );

    // stage 4: Auditor deny — secret-overlay on .ssh inside the allowed root
    let denied_args = format!("{{\"path\":{}}}", json_str(&kdl_path(&ssh_file)));
    let denied_resp = s3.call("read_file", &denied_args).await;
    let denied_resp = denied_resp.expect("stage4 filesystem: denied call must still answer");
    assert!(
        json_has_error(&denied_resp),
        "stage4 filesystem: .ssh read must be a JSON-RPC error: {denied_resp}"
    );
    let audit3_text = s3.finish_audit(&audit3).await;
    let denied = audit_denied_line(&audit3_text).unwrap_or_else(|| {
        panic!("stage4 filesystem: audit log missing tool_call.denied: {audit3_text}")
    });
    assert!(
        denied.contains("\"target_tool\":\"read_file\""),
        "stage4 filesystem: denied event must name the tool: {denied}"
    );

    // stage 5: OS-layer deny below the Auditor — restricted/secret.txt is
    // inside the tool's `srv/**` allow and inside an argv allowed dir, but
    // outside the defaults OS grant.
    let argv5 = match server_argv(spec, &[kdl_path(&data), kdl_path(&restricted)]) {
        Some(a) => a,
        None => return,
    };
    let audit5 = common::next_audit_log_path();
    let mut s5 = GuardSession::spawn(&policy_path, &audit5, &argv5, &[], false, Some(&data));
    let init5 = s5.handshake().await;
    let denied5_args = format!("{{\"path\":{}}}", json_str(&kdl_path(&restricted_file)));
    let resp5 = if init5.is_some() {
        let _ = s5.tools_list().await;
        s5.call("read_file", &denied5_args).await
    } else {
        None
    };
    let audit5_text = s5.finish_audit(&audit5).await;
    assert!(
        audit_denied_line(&audit5_text).is_none(),
        "stage5 filesystem: OS-layer deny must not log tool_call.denied: {audit5_text}"
    );
    if cfg!(target_os = "linux") {
        // Landlock composes every per-tool fs grant into the process-wide
        // ruleset, so `srv/**` covers restricted/ — the call succeeds. A
        // recorded design constraint of process-level sandboxing.
        let resp = resp5.expect("stage5 filesystem: composed-grant call must answer");
        assert!(
            !json_has_error(&resp) && !is_error_result(&resp),
            "stage5 filesystem: Linux composed grant must allow the read: {resp}"
        );
    } else {
        // Windows/macOS: the OS denies — either at startup (realpath of the
        // ungranted argv dir on macOS) or at the read itself.
        match resp5 {
            Some(r) => assert!(
                json_has_error(&r) || is_error_result(&r),
                "stage5 filesystem: OS must deny the restricted read: {r}"
            ),
            None => eprintln!(
                "stage5 filesystem: server failed to start under the OS sandbox (recorded)"
            ),
        }
    }

    // stage 6: corrupted hash pin must fail tools/list
    stage6_bad_hash(
        spec,
        &argv_main[0],
        &argv_main,
        &[],
        &root,
        fs_grants,
        Some(&data),
    )
    .await;
}

/// `tools/list` visibility follows the policy allowlist on a real server.
/// `filesystem.kdl` allows all 14 advertised tools; denying one through the
/// host overlay hides exactly that tool, while the advertised-set hash pin
/// still verifies because hashing ran before filtering.
#[tokio::test]
async fn real_filesystem_server_lists_only_allowed_tools() {
    let _stage_lock = STAGE_LOCK.lock().await;
    let spec = &FILESYSTEM;
    let (_t, root) = temp_root("mcp_writ_rs_fs_filter_");
    let data = root.join("data");
    std::fs::create_dir_all(&data).expect("mkdir data");
    let argv = match server_argv(spec, &[kdl_path(&data)]) {
        Some(a) => a,
        None => return,
    };

    let denied = "move_file";
    let server_extra = format!("server \"filesystem\" {{\n    tool \"{denied}\" deny=#true\n}}\n");
    let mut host_kdl = host_policy(spec, &argv[0], &server_extra);
    let grants: &[(&Path, &str)] = &[(&data, "read")];
    inject_fs_grants(&mut host_kdl, grants);
    let policy_path = write_policy(&root, "host-fs-filter.kdl", &host_kdl);

    let audit_log = common::next_audit_log_path();
    let mut s = GuardSession::spawn(&policy_path, &audit_log, &argv, &[], false, Some(&data));
    if s.handshake().await.is_none() {
        let stderr = s.shutdown_stderr().await;
        common::skip_server_test(&format!(
            "filesystem filter: sandboxed spawn produced no initialize response; stderr: {stderr}"
        ));
        return;
    }
    let Some(list) = s.tools_list().await else {
        let stderr = s.shutdown_stderr().await;
        common::skip_server_test(&format!(
            "filesystem filter: no tools/list response; stderr: {stderr}"
        ));
        return;
    };
    assert!(
        !json_has_error(&list),
        "filesystem filter: tools/list must pass the advertised-set hash pin: {list}"
    );

    let mut expected = example_tool_names(spec);
    expected.retain(|name| name != denied);
    let mut names = response_tool_names(&list);
    names.sort();
    expected.sort();
    assert_eq!(
        names, expected,
        "filesystem filter: visible tools must equal the example allowlist minus denied: {list}"
    );
    assert!(
        !list.contains(denied),
        "denied tool must not appear in the response: {list}"
    );

    let audit_text = s.finish_audit(&audit_log).await;
    let filtered_line = audit_text
        .lines()
        .find(|l| l.contains("\"event_type\":\"tools_list.filtered\""))
        .unwrap_or_else(|| {
            panic!("filesystem filter: audit log missing tools_list.filtered: {audit_text}")
        });
    assert!(
        filtered_line.contains("\"action\":\"denied\""),
        "normal-run filter event must be denied: {filtered_line}"
    );
    assert!(
        filtered_line.contains(denied),
        "hidden tool must be named in details: {filtered_line}"
    );
}

// ─── memory ───────────────────────────────────────────────────────────────

#[tokio::test]
async fn memory_stages() {
    let _stage_lock = STAGE_LOCK.lock().await;
    let spec = &MEMORY;
    let (_t, root) = temp_root("mcp_writ_rs_mem_");
    let data = root.join("data");
    let restricted = root.join("restricted");
    for d in [&data, &restricted] {
        std::fs::create_dir_all(d).expect("mkdir");
    }
    let mem_file = data.join("memory.json");
    let mem_file_outside = restricted.join("memory.json");

    let argv = match server_argv(spec, &[]) {
        Some(a) => a,
        None => return,
    };

    // stage 1: live discovery
    stage1_live_discovery(spec, &argv, &root);

    // The server's data file is chosen by MEMORY_FILE_PATH, not by an RPC
    // argument — the OS sandbox (defaults grant) is the only layer that can
    // scope it. data/ is granted read-write; restricted/ is never granted.
    let mut host_kdl = host_policy(spec, &argv[0], "");
    let mem_grants: &[(&Path, &str)] = &[(&data, "write")];
    inject_fs_grants(&mut host_kdl, mem_grants);
    let policy_path = write_policy(&root, "host-mem.kdl", &host_kdl);
    let env = [("MEMORY_FILE_PATH", mem_file.to_string_lossy().into_owned())];
    let env_refs: Vec<(&str, &str)> = env.iter().map(|(k, v)| (*k, v.as_str())).collect();

    let create_args = "{\"entities\":[{\"name\":\"e2e-entity\",\"entityType\":\"marker\",\"observations\":[\"obs-1\"]}]}";

    // stage 2: dry-run
    if !stage2_dry_run(
        spec,
        &policy_path,
        &argv,
        &env_refs,
        Some(&data),
        PositiveCall {
            tool: "create_entities",
            args: create_args,
            marker: "e2e-entity",
        },
    )
    .await
    {
        return;
    }

    // stage 3 + 4: sandboxed session
    let Some((mut s3, audit3)) =
        stage3_spawn(spec, &policy_path, &argv, &env_refs, Some(&data)).await
    else {
        return;
    };
    let resp = s3.call("create_entities", create_args).await;
    assert!(
        resp.as_deref()
            .is_some_and(|r| !json_has_error(r) && !is_error_result(r)),
        "stage3 memory: sandboxed create_entities must succeed: {resp:?}"
    );

    // stage 4: Auditor deny — a tool name the policy does not list
    let denied = s3.call("drop_everything", "{}").await;
    let denied = denied.expect("stage4 memory: denied call must still answer");
    assert!(
        json_has_error(&denied),
        "stage4 memory: unlisted tool must be a JSON-RPC error: {denied}"
    );
    let audit3_text = s3.finish_audit(&audit3).await;
    let denied_line = audit_denied_line(&audit3_text).unwrap_or_else(|| {
        panic!("stage4 memory: audit log missing tool_call.denied: {audit3_text}")
    });
    assert!(
        denied_line.contains("drop_everything"),
        "stage4 memory: denied event must name the tool: {denied_line}"
    );

    // stage 5: OS-layer deny — MEMORY_FILE_PATH outside the defaults grant.
    // The Auditor never sees it (it is an env var, not an RPC argument).
    let env5 = [(
        "MEMORY_FILE_PATH",
        mem_file_outside.to_string_lossy().into_owned(),
    )];
    let env5_refs: Vec<(&str, &str)> = env5.iter().map(|(k, v)| (*k, v.as_str())).collect();
    let audit5 = common::next_audit_log_path();
    let mut s5 = GuardSession::spawn(&policy_path, &audit5, &argv, &env5_refs, false, Some(&data));
    let init5 = s5.handshake().await;
    let resp5 = if init5.is_some() {
        let _ = s5.tools_list().await;
        s5.call("create_entities", create_args).await
    } else {
        None
    };
    let audit5_text = s5.finish_audit(&audit5).await;
    assert!(
        audit_denied_line(&audit5_text).is_none(),
        "stage5 memory: OS-layer deny must not log tool_call.denied: {audit5_text}"
    );
    match resp5 {
        Some(r) => assert!(
            json_has_error(&r) || is_error_result(&r),
            "stage5 memory: write outside the grant must fail: {r}"
        ),
        None => {
            eprintln!("stage5 memory: server failed at startup on the ungranted file (recorded)")
        }
    }

    // stage 6: corrupted hash pin must fail tools/list
    stage6_bad_hash(
        spec,
        &argv[0],
        &argv,
        &env_refs,
        &root,
        mem_grants,
        Some(&data),
    )
    .await;
}

/// PR6: `defaults.environment` controls which parent variables reach the
/// real server. MEMORY_FILE_PATH is the observable lever: listed, the
/// server writes to the granted path; unlisted, the variable never reaches
/// the child and the server falls back to `dist/memory.jsonl` inside the
/// read-only package tree — the mutation then fails at the OS layer (the
/// server resolves the path lazily, so startup itself still succeeds).
#[tokio::test]
async fn real_memory_server_needs_listed_env() {
    let _stage_lock = STAGE_LOCK.lock().await;
    let spec = &MEMORY;
    let (_t, root) = temp_root("mcp_writ_rs_memenv_");
    let data = root.join("data");
    std::fs::create_dir_all(&data).expect("mkdir data");
    let mem_file = data.join("memory-allowed.json");
    let mem_file_blocked = data.join("memory-blocked.json");

    let argv = match server_argv(spec, &[]) {
        Some(a) => a,
        None => return,
    };

    let create_args = "{\"entities\":[{\"name\":\"env-e2e\",\"entityType\":\"marker\",\"observations\":[\"obs\"]}]}";

    // Listed: MEMORY_FILE_PATH is copied into the child and the write lands
    // on the granted data dir.
    let mut allowed_kdl = host_policy(spec, &argv[0], "");
    inject_fs_grants(&mut allowed_kdl, &[(&data, "write")]);
    inject_environment(&mut allowed_kdl, &["MEMORY_FILE_PATH"]);
    let allowed_path = write_policy(&root, "host-mem-env-allowed.kdl", &allowed_kdl);
    let env = [("MEMORY_FILE_PATH", mem_file.to_string_lossy().into_owned())];
    let env_refs: Vec<(&str, &str)> = env.iter().map(|(k, v)| (*k, v.as_str())).collect();

    let Some((mut session, _audit)) =
        stage3_spawn(spec, &allowed_path, &argv, &env_refs, Some(&data)).await
    else {
        return;
    };
    let resp = session.call("create_entities", create_args).await;
    assert!(
        resp.as_deref()
            .is_some_and(|r| !json_has_error(r) && !is_error_result(r)),
        "listed MEMORY_FILE_PATH: create_entities must succeed: {resp:?}"
    );
    assert!(
        mem_file.exists(),
        "listed MEMORY_FILE_PATH: server must write the named file"
    );
    session.shutdown_stderr().await;

    // Unlisted: the overlay replaces the allow list, so MEMORY_FILE_PATH is
    // not copied; the server falls back to dist/memory.jsonl under the
    // read-only package dir and the write is denied by the OS sandbox.
    let mut blocked_kdl = host_policy(spec, &argv[0], "");
    inject_fs_grants(&mut blocked_kdl, &[(&data, "write")]);
    inject_environment(&mut blocked_kdl, &["MCP_WRIT_UNRELATED_UNUSED"]);
    let blocked_path = write_policy(&root, "host-mem-env-blocked.kdl", &blocked_kdl);
    let env_b = [(
        "MEMORY_FILE_PATH",
        mem_file_blocked.to_string_lossy().into_owned(),
    )];
    let env_b_refs: Vec<(&str, &str)> = env_b.iter().map(|(k, v)| (*k, v.as_str())).collect();

    let audit_b = common::next_audit_log_path();
    let mut s = GuardSession::spawn(
        &blocked_path,
        &audit_b,
        &argv,
        &env_b_refs,
        false,
        Some(&data),
    );
    let init = s.handshake().await;
    let resp_b = if init.is_some() {
        let _ = s.tools_list().await;
        s.call("create_entities", create_args).await
    } else {
        None
    };
    let audit_b_text = s.finish_audit(&audit_b).await;
    assert!(
        !mem_file_blocked.exists(),
        "unlisted MEMORY_FILE_PATH must not reach the child — the named file must not appear"
    );
    match resp_b {
        Some(r) => assert!(
            json_has_error(&r) || is_error_result(&r),
            "unlisted MEMORY_FILE_PATH: fallback write outside the grant must fail: {r}"
        ),
        None => {
            eprintln!("env-blocked memory: server failed at startup (recorded): {audit_b_text}")
        }
    }
}

// ─── time ─────────────────────────────────────────────────────────────────

#[tokio::test]
async fn time_stages() {
    let _stage_lock = STAGE_LOCK.lock().await;
    let spec = &TIME;
    let (_t, root) = temp_root("mcp_writ_rs_time_");
    let argv = match server_argv(spec, &[]) {
        Some(a) => a,
        None => return,
    };

    // stage 1: live discovery
    stage1_live_discovery(spec, &argv, &root);

    // A granted scratch dir gives the sandboxed child a valid working
    // directory (Windows refuses to spawn a child whose inherited cwd is
    // outside the grant).
    let scratch = root.join("scratch");
    std::fs::create_dir_all(&scratch).expect("mkdir scratch");
    let mut host_kdl = host_policy(spec, &argv[0], "");
    let time_grants: &[(&Path, &str)] = &[(&scratch, "read")];
    inject_fs_grants(&mut host_kdl, time_grants);
    let policy_path = write_policy(&root, "host-time.kdl", &host_kdl);

    let time_args = "{\"timezone\":\"UTC\"}";

    // stage 2: dry-run
    if !stage2_dry_run(
        spec,
        &policy_path,
        &argv,
        &[],
        Some(&scratch),
        PositiveCall {
            tool: "get_current_time",
            args: time_args,
            marker: "UTC",
        },
    )
    .await
    {
        return;
    }

    // stage 3 + 4: sandboxed session
    let Some((mut s3, audit3)) = stage3_spawn(spec, &policy_path, &argv, &[], Some(&scratch)).await
    else {
        return;
    };
    let resp = s3.call("get_current_time", time_args).await;
    assert!(
        resp.as_deref()
            .is_some_and(|r| !json_has_error(r) && !is_error_result(r)),
        "stage3 time: sandboxed get_current_time must succeed: {resp:?}"
    );

    // stage 4: Auditor deny — unlisted tool name
    let denied = s3.call("format_time_as_iso", "{}").await;
    let denied = denied.expect("stage4 time: denied call must still answer");
    assert!(
        json_has_error(&denied),
        "stage4 time: unlisted tool must be a JSON-RPC error: {denied}"
    );
    let audit3_text = s3.finish_audit(&audit3).await;
    assert!(
        audit_denied_line(&audit3_text).is_some(),
        "stage4 time: audit log missing tool_call.denied: {audit3_text}"
    );

    // stage 5: the server performs no filesystem or network I/O, so there is
    // no OS-layer-deny axis to exercise. Recorded as not applicable.
    eprintln!("stage5 time: skipped — the server has no fs/network I/O surface to deny at the OS");

    // stage 6: corrupted hash pin must fail tools/list
    stage6_bad_hash(
        spec,
        &argv[0],
        &argv,
        &[],
        &root,
        time_grants,
        Some(&scratch),
    )
    .await;
}

// ─── git ──────────────────────────────────────────────────────────────────

/// `git init` + one commit so `git_log` has content. The branch must be
/// `master`: `mcp_server_git` resolves `repo.active_branch`, and GitPython
/// reports an unborn `HEAD` as a missing `refs/heads/master`.
fn git_init(dir: &Path, git_exe: &Path) -> bool {
    let git = |args: &[&str]| -> bool {
        matches!(
            std::process::Command::new(git_exe)
                .args(args)
                .current_dir(dir)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status(),
            Ok(s) if s.success()
        )
    };
    let ok = git(&["init", "-q", "-b", "master", "."])
        && git(&["config", "user.email", "e2e@test"])
        && git(&["config", "user.name", "e2e"])
        && { std::fs::write(dir.join("seed.txt"), "seed\n").is_ok() }
        && git(&["add", "seed.txt"])
        && git(&["commit", "-qm", "init"])
        && git(&["rev-parse", "--verify", "refs/heads/master"]);
    if !ok {
        common::skip_server_test("git repo fixture setup failed");
    }
    ok
}

#[tokio::test]
async fn git_stages() {
    let _stage_lock = STAGE_LOCK.lock().await;
    let spec = &GIT;
    let (_t, root) = temp_root("mcp_writ_rs_git_");
    let repo = root.join("repo");
    let cwd = root.join("work");
    let outside_repo = cwd.join("repo");
    std::fs::create_dir_all(&repo).expect("mkdir repo");
    std::fs::create_dir_all(&outside_repo).expect("mkdir outside repo");

    // `git` is spawned by the server as a subprocess; it must resolve and be
    // readable inside the sandbox. On Windows a system git under
    // `Program Files` is neither grantable nor package-readable, so the
    // pinned MinGit fixture (fetched by setup.ps1) provides the executable.
    let git_exe = if cfg!(windows) {
        let exe = fixtures_dir().join("mingit/cmd/git.exe");
        if !exe.is_file() {
            common::skip_server_test(&format!(
                "mingit fixture not installed: {} (run setup.ps1)",
                exe.display()
            ));
            return;
        }
        exe
    } else {
        match mcp_writ::workload::resolve_command_path("git") {
            Ok(p) => p,
            Err(_) => {
                common::skip_server_test("git not on PATH");
                return;
            }
        }
    };
    if !git_init(&repo, &git_exe) || !git_init(&outside_repo, &git_exe) {
        return;
    }

    // On Windows the `work` grant propagates into `work/repo`; protect it so
    // stage 5 stays an OS-layer deny. On Linux Landlock grants cover the
    // whole `work` subtree — there is no carve-out, so the call succeeds
    // (recorded divergence, same as the filesystem server).
    #[cfg(windows)]
    {
        let ok = std::process::Command::new("icacls")
            .arg(&outside_repo)
            .args(["/inheritance:d"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        if !matches!(ok, Ok(s) if s.success()) {
            common::skip_server_test("icacls /inheritance:d unavailable");
            return;
        }
    }
    let git_env = (
        "GIT_PYTHON_GIT_EXECUTABLE",
        git_exe.to_string_lossy().into_owned(),
    );
    // Git also consults the global/system config; inside the sandbox $HOME is
    // outside every grant so `~/.gitconfig` reads fail — and git treats that
    // as a fatal "unknown error ... reading the configuration files" in some
    // code paths. Point both config files at readable non-entities instead.
    // (Windows can't exec git under AppContainer at all, so these are inert.)
    let cfg_env: &[(&str, &str)] = if cfg!(windows) {
        &[]
    } else {
        &[
            ("GIT_CONFIG_GLOBAL", "/dev/null"),
            ("GIT_CONFIG_NOSYSTEM", "1"),
        ]
    };
    let mut env_vec: Vec<(&str, &str)> = vec![(git_env.0, git_env.1.as_str())];
    env_vec.extend_from_slice(cfg_env);
    let env_refs: &[(&str, &str)] = &env_vec;

    let argv = match server_argv(spec, &["--repository".to_string(), kdl_path(&repo)]) {
        Some(a) => a,
        None => return,
    };

    // stage 1: live discovery
    stage1_live_discovery(spec, &argv, &root);

    // defaults: interpreter runtime + the repo + the child cwd `work/` +
    // git's own prefix for the subprocess image. `work/` is granted so the
    // child has a valid working directory; `work/repo` is denied by its
    // protected DACL on Windows, and by nothing on Linux (subtree grant).
    // The Auditor scope is `root/**` so both `repo` and `work/repo` are
    // policy-visible; the OS grant is what differentiates them.
    let root_glob = format!("{}/**", kdl_path(&root));
    let server_extra = format!(
        "server \"git\" {{\n    tool \"git_log\" {{\n        filesystem {{\n            allow \"{root_glob}\"\n        }}\n    }}\n}}\n"
    );
    let mut host_kdl = host_policy(spec, &argv[0], &server_extra);
    let mut git_grant_dirs = vec![repo.clone(), cwd.clone()];
    git_grant_dirs.extend(common::exe_read_grant_dirs(&git_exe));
    let git_grants: Vec<(&Path, &str)> = git_grant_dirs
        .iter()
        .map(|d| (d.as_path(), "read"))
        .collect();
    inject_fs_grants(&mut host_kdl, &git_grants);
    let policy_path = write_policy(&root, "host-git.kdl", &host_kdl);

    let log_args = format!("{{\"repo_path\":{}}}", json_str(&kdl_path(&repo)));

    // stage 2: dry-run
    if !stage2_dry_run(
        spec,
        &policy_path,
        &argv,
        env_refs,
        Some(&cwd),
        PositiveCall {
            tool: "git_log",
            args: &log_args,
            marker: "",
        },
    )
    .await
    {
        return;
    }

    // stage 3 + 4: sandboxed session (guard cwd = work/, granted so the
    // AppContainer child has a valid working directory)
    let Some((mut s3, audit3)) =
        stage3_spawn(spec, &policy_path, &argv, env_refs, Some(&cwd)).await
    else {
        return;
    };
    let resp = s3.call("git_log", &log_args).await;
    if cfg!(windows) {
        // Recorded platform limitation: git.exe (MinGW runtime) resolves its
        // working directory through GetFinalPathNameByHandleW, which no
        // AppContainer token can perform — the git subprocess cannot function
        // under the Windows sandbox at all, so the allowed call fails below
        // the Auditor. Stage 3's positive path is a Windows-only divergence.
        let r = resp.expect("stage3 git: call must still answer on Windows");
        assert!(
            json_has_error(&r) || is_error_result(&r),
            "stage3 git (windows): the git subprocess must fail closed under \
             AppContainer: {r}"
        );
        eprintln!(
            "stage3 git: recorded platform limitation — git.exe cannot resolve \
             cwd under AppContainer (GetFinalPathNameByHandleW)"
        );
    } else {
        assert!(
            resp.as_deref()
                .is_some_and(|r| !json_has_error(r) && !is_error_result(r)),
            "stage3 git: sandboxed git_log must succeed: {resp:?}"
        );
    }

    // stage 4: Auditor deny — repo_path outside the tool's fs allow. An
    // absolute path outside the temp root: `repo_path` is a named `*_path`
    // field (and `looks_like_path` would pick it up regardless).
    let outside_abs = fixtures_dir();
    let denied_args = format!("{{\"repo_path\":{}}}", json_str(&kdl_path(&outside_abs)));
    let denied = s3.call("git_log", &denied_args).await;
    let denied = denied.expect("stage4 git: denied call must still answer");
    assert!(
        json_has_error(&denied),
        "stage4 git: repo_path outside the allow must be a JSON-RPC error: {denied}"
    );
    let audit3_text = s3.finish_audit(&audit3).await;
    let denied_line = audit_denied_line(&audit3_text)
        .unwrap_or_else(|| panic!("stage4 git: audit log missing tool_call.denied: {audit3_text}"));
    assert!(
        denied_line.contains("git_log"),
        "stage4 git: denied event must name the tool: {denied_line}"
    );

    // stage 5: OS-layer reach — `work/repo` is inside the Auditor's `root/**`
    // scope AND the server scope (`--repository` is pointed at it below), so
    // the call reaches the OS. On Windows the protected DACL denies git's
    // access (git.exe also cannot resolve its cwd under AppContainer); on
    // Linux/macOS the composed process-level grant covers the subtree — a
    // recorded divergence of process-level sandboxing.
    let audit5 = common::next_audit_log_path();
    let argv5 = server_argv(spec, &["--repository".to_string(), kdl_path(&outside_repo)])
        .expect("stage5 git: server_argv for outside repo");
    let mut s5 = GuardSession::spawn(&policy_path, &audit5, &argv5, env_refs, false, Some(&cwd));
    let init5 = s5.handshake().await;
    let denied5_args = format!("{{\"repo_path\":{}}}", json_str(&kdl_path(&outside_repo)));
    let resp5 = if init5.is_some() {
        let _ = s5.tools_list().await;
        s5.call("git_log", &denied5_args).await
    } else {
        None
    };
    let audit5_text = s5.finish_audit(&audit5).await;
    assert!(
        audit_denied_line(&audit5_text).is_none(),
        "stage5 git: OS-layer deny must not log tool_call.denied: {audit5_text}"
    );
    match resp5 {
        Some(r) => {
            if cfg!(windows) {
                assert!(
                    json_has_error(&r) || is_error_result(&r),
                    "stage5 git: out-of-grant repo access must fail: {r}"
                );
            } else {
                assert!(
                    !json_has_error(&r) && !is_error_result(&r),
                    "stage5 git: composed-grant call must succeed: {r}"
                );
            }
        }
        None => eprintln!("stage5 git: server failed at startup under the sandbox (recorded)"),
    }

    // stage 6: corrupted hash pin must fail tools/list
    stage6_bad_hash(
        spec,
        &argv[0],
        &argv,
        env_refs,
        &root,
        &git_grants,
        Some(&cwd),
    )
    .await;
}
