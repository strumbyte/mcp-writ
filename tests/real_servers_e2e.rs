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
//!      PR-25: the draft is then "reviewed" (the `auto-generated` server
//!      block is renamed to the real identity and the deny is lifted on
//!      exactly the tools the stages exercise) and the *reviewed draft* —
//!      not a hand-written example — is the workload half of the host
//!      policy stages 2–6 `extend`. The generated `args_schema` pins the
//!      argument contract those calls run under.
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
//! Only a missing prerequisite — the pinned server fixture, `git`, or
//! MinGit — may skip a stage; `MCP_WRIT_REQUIRE_SERVER_TESTS=1` turns
//! that skip into a failure. Once the prerequisites are met, a missing
//! response or a failed startup is a test failure, so a run can never
//! pass on stages that did not execute.

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
    expected_hash: "sha256:356bc86bb96625f3c4cd1dc9405ed09425d441ea884972148bec3dd1808cfea2",
    tool_count: 14,
};
const MEMORY: ServerSpec = ServerSpec {
    name: "memory",
    runtime: "node",
    expected_hash: "sha256:75e8f7889cc05510689e9fe237983e2ae9490155eb38aab8a99b5396a047b1f8",
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
    expected_hash: "sha256:185000d12e4a14677cc13bda254c6f2b54c4d583e908c7896751bd13913506fc",
    tool_count: 12,
};
const FETCH: ServerSpec = ServerSpec {
    name: "fetch",
    runtime: "python",
    // Launched with `--allow-private-ips --ignore-robots-txt`: the flags do
    // not change tools/list, they make the local HTTP fixture reachable —
    // without `--allow-private-ips` the server itself refuses
    // loopback/RFC1918 destinations before policy is consulted.
    expected_hash: "sha256:ce464f2ab20921047330f580117eb0d5d9c04640021ee2c1e7d26a3acef78eaa",
    tool_count: 1,
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
                "fetch" => "mcp_server_fetch",
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
            // mcp-server-fetch refuses loopback/private destinations and
            // honours robots.txt by default; the e2e fetches a local HTTP
            // fixture, so both restrictions are lifted at launch — the
            // destination list still lives in the policy.
            if spec.name == "fetch" {
                argv.extend([
                    "--allow-private-ips".to_string(),
                    "--ignore-robots-txt".to_string(),
                ]);
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

/// Insert a `network { ... }` block into `defaults` — `inner` is the
/// block's body (the `allow`/`deny` lines at the 8-space child indent).
/// Merged `network` blocks union their allow/deny entries, while the
/// posture spellings (`deny host="*"` / `allow host="*"`) move the
/// `deny_all_others` flag — an open posture in the overlay is the only
/// spelling AppContainer accepts when outbound is needed at all.
fn inject_network(policy: &mut String, inner: &str) {
    if inner.is_empty() {
        return;
    }
    let start = policy.find("defaults {").expect("defaults block");
    let close = policy[start..]
        .find("\n}\n")
        .map(|i| start + i + 1)
        .expect("defaults close");
    let mut inject = String::from("    network {\n");
    inject.push_str(inner);
    inject.push_str("    }\n");
    policy.insert_str(close, &inject);
}

/// host.kdl = extends <base> + host defaults + logging + extra server
/// overrides (per-tool fs with real paths, or a corrupted hash pin).
/// `version` is the extended file's `policy version` — a v2 base (the
/// generated draft) requires a v2 overlay.
fn host_policy_base(base: &Path, version: u32, argv0: &str, extra_kdl: &str) -> String {
    #[allow(unused_mut)]
    let mut out = format!(
        "policy version={version}\nextends \"{}\"\n{}logging level=\"info\" fail_closed=#false\n{}",
        kdl_path(base),
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

fn host_policy(spec: &ServerSpec, argv0: &str, extra_kdl: &str) -> String {
    host_policy_base(&example_policy_path(spec), 1, argv0, extra_kdl)
}

/// The run stages' host policy when the workload half is the reviewed
/// generated draft (v2), not `examples/policies/<spec>.kdl`.
fn draft_host_policy(draft: &Path, argv0: &str, extra_kdl: &str) -> String {
    host_policy_base(draft, 2, argv0, extra_kdl)
}

fn write_policy(dir: &Path, name: &str, text: &str) -> PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, text).expect("write host policy");
    path
}

// ─── stage 1: live discovery ──────────────────────────────────────────────

fn stage1_live_discovery(spec: &ServerSpec, argv: &[String], work: &Path) {
    let out = work.join(format!("genpol-{}.kdl", spec.name));
    // First-run imports (fetch pulls httpx/lxml/…) can overrun the
    // discovery handshake's 5s response budget on a contended host —
    // discovery is read-only and idempotent, so one retry exercises the
    // same live path with a warm module cache.
    let mut stderr = String::new();
    let mut succeeded = false;
    for attempt in 0..2 {
        let output = std::process::Command::new(env!("CARGO_BIN_EXE_mcp-writ"))
            .args(["generate-policy", "--live-discovery", "--output"])
            .arg(&out)
            .arg("--")
            .args(argv)
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .output()
            .expect("spawn generate-policy");
        if output.status.success() {
            succeeded = true;
            break;
        }
        stderr = String::from_utf8_lossy(&output.stderr).into_owned();
        if attempt == 1 || !stderr.contains("Timed out") {
            break;
        }
        eprintln!("stage1 {}: discovery timed out — retrying once", spec.name);
    }
    assert!(
        succeeded,
        "stage1 {}: generate-policy --live-discovery failed: {stderr}",
        spec.name
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

/// PR-25: turn the stage-1 generated draft into the policy the run stages
/// actually extend. The draft is dispatcher-shaped — every discovered tool
/// was emitted `deny=#true` under a `server "auto-generated"` block — so
/// the simulated review is the minimal honest transform: rename the server
/// to its real identity and lift the deny on exactly the tools the stages
/// exercise (`deny=#false`). Every other tool stays denied, the generated
/// `args_schema`, `tools-list-hash`, and workload hash entries are
/// untouched — except the Node `entrypoint-hash`, which the review drops
/// because the pinned-payload exec cannot resolve `node_modules` — and the
/// `// REVIEW` markers ride along (warn mode) — the same state a
/// maintainer's partial review leaves. The returned path is the file
/// `extends` points at in `draft_host_policy`.
fn stage1_review_draft(spec: &ServerSpec, work: &Path, allow_tools: &[&str]) -> PathBuf {
    let generated = work.join(format!("genpol-{}.kdl", spec.name));
    let draft = std::fs::read_to_string(&generated).expect("stage1 draft readable");
    let mut reviewed = draft.replacen(
        "server \"auto-generated\" {",
        &format!("server \"{}\" {{", spec.name),
        1,
    );
    assert_ne!(
        reviewed, draft,
        "stage1 {}: draft must carry the auto-generated server block",
        spec.name
    );
    for tool in allow_tools {
        let denied = format!("tool \"{tool}\" deny=#true");
        assert!(
            reviewed.contains(&denied),
            "stage1 {}: draft must emit `{denied}`",
            spec.name
        );
        reviewed = reviewed.replacen(&denied, &format!("tool \"{tool}\" deny=#false"), 1);
    }
    if spec.runtime == "node" {
        // The entrypoint pin is dropped at review: `run` binds the pinned
        // script by exec'ing a snapshot — an inherited sealed memfd on
        // Linux, an owner-only staged copy on macOS and Windows — and
        // Node's ESM resolver walks ancestors of *that* path, so the
        // server's `import` statements never reach the real node_modules
        // and the process dies before initialize. The pin is verified
        // emitted (and target-correct) in stage1; the launch still binds
        // node itself via `binary-hash` and the tool surface via
        // `tools-list-hash`.
        let mut stripped = String::with_capacity(reviewed.len());
        let mut found = false;
        for line in reviewed.lines() {
            if line.trim_start().starts_with("entrypoint-hash \"") {
                found = true;
                stripped.push_str(
                    "    // REVIEW: entrypoint-hash dropped — pinned-payload exec cannot \
                     resolve node_modules\n",
                );
                continue;
            }
            stripped.push_str(line);
            stripped.push('\n');
        }
        assert!(
            found,
            "stage1 {}: node draft must carry the entrypoint-hash line",
            spec.name
        );
        reviewed = stripped;
    }
    let path = work.join(format!("genpol-{}-reviewed.kdl", spec.name));
    std::fs::write(&path, &reviewed).expect("write reviewed draft");
    // The reviewed draft is what `run` extends — it must still load, keep
    // its pins, and carry the workload hash entries.
    let policy =
        mcp_writ::policy::kdl_loader::load_kdl_policy(&path).expect("reviewed draft must load");
    assert!(
        !policy.tools_list_hashes.is_empty(),
        "stage1 {}: reviewed draft must keep the tools-list-hash",
        spec.name
    );
    assert!(
        !policy.hash_entries.is_empty(),
        "stage1 {}: reviewed draft must keep the workload hash entries",
        spec.name
    );
    path
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
/// A missing response is a real failure (the prerequisites were checked
/// by `server_argv`), so this driver panics instead of skipping.
async fn stage2_dry_run(
    spec: &ServerSpec,
    policy_path: &Path,
    argv: &[String],
    env: &[(&str, &str)],
    cwd: Option<&Path>,
    positive: PositiveCall<'_>,
) {
    let audit_log = common::next_audit_log_path();
    let mut session = GuardSession::spawn(policy_path, &audit_log, argv, env, true, cwd);
    let Some(version) = session.handshake().await else {
        let stderr = session.shutdown_stderr().await;
        panic!(
            "stage2 {}: no initialize response; stderr: {stderr}",
            spec.name
        );
    };
    eprintln!("{}: negotiated protocol {}", spec.name, version);
    let Some(list) = session.tools_list().await else {
        let stderr = session.shutdown_stderr().await;
        panic!(
            "stage2 {}: no tools/list response; stderr: {stderr}",
            spec.name
        );
    };
    assert!(
        !json_has_error(&list),
        "stage2 {}: tools/list must pass hash pinning: {list}",
        spec.name
    );
    let Some(resp) = session.call(positive.tool, positive.args).await else {
        let stderr = session.shutdown_stderr().await;
        panic!(
            "stage2 {}: allowed call produced no response; stderr: {stderr}",
            spec.name
        );
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
}

/// Stage 3 start: sandboxed spawn + handshake + tools/list. A failed
/// handshake or a missing/error tools/list is a genuine launch failure —
/// never a skip.
async fn stage3_spawn(
    spec: &ServerSpec,
    policy_path: &Path,
    argv: &[String],
    env: &[(&str, &str)],
    cwd: Option<&Path>,
) -> (GuardSession, PathBuf) {
    let audit_log = common::next_audit_log_path();
    let mut session = GuardSession::spawn(policy_path, &audit_log, argv, env, false, cwd);
    if session.handshake().await.is_none() {
        let stderr = session.shutdown_stderr().await;
        panic!(
            "stage3 {}: sandboxed spawn produced no initialize response; stderr: {stderr}",
            spec.name
        );
    }
    let list = session.tools_list().await;
    assert!(
        list.as_deref().is_some_and(|l| !json_has_error(l)),
        "stage3 {}: tools/list must pass hash pinning: {list:?}",
        spec.name
    );
    (session, audit_log)
}

/// Stage 6: a corrupted `tools-list-hash` pin must fail tools/list. The bad
/// policy extends the same workload base (`base`) at the same `version` as
/// the main host policy and carries the same OS grants so the failure can
/// only come from the pin mismatch.
async fn stage6_bad_hash(
    spec: &ServerSpec,
    base: &Path,
    base_version: u32,
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
    let mut bad = host_policy_base(
        base,
        base_version,
        argv0,
        &format!(
            "server \"{}\" {{\n    tools-list-hash \"{wrong_hash}\"\n}}\n",
            spec.name
        ),
    );
    inject_fs_grants(&mut bad, grants);
    // Any env the spawn passes must be allowed through the restricted
    // child environment or the server cannot start (e.g. Windows git's
    // GIT_PYTHON_REFRESH=quiet deferral).
    let env_names: Vec<&str> = env.iter().map(|(name, _)| *name).collect();
    inject_environment(&mut bad, &env_names);
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
    // Numbered lines for `head` (optional argument), and a ~9MiB file for
    // the large-response path.
    let numbered = data.join("numbered.txt");
    std::fs::write(
        &numbered,
        "FS-LINE-1\nFS-LINE-2\nFS-LINE-3\nFS-LINE-4\nFS-LINE-5\n",
    )
    .expect("numbered");
    // Two sizes bracket the PR-20 frame cap: the filesystem server returns
    // the body twice in one frame (content + structuredContent), so ~4MiB
    // lands near it (~8.4MB) and ~9MiB (~18.9MB) is refused by it.
    let mid = data.join("mid.bin");
    let mut mid_body = vec![b'X'; 4 * 1024 * 1024];
    mid_body.extend_from_slice(b"\nMARKER-FS-MID-TAIL\n");
    std::fs::write(&mid, &mid_body).expect("mid file");
    let big = data.join("big.bin");
    let mut big_body = vec![b'X'; 9 * 1024 * 1024];
    big_body.extend_from_slice(b"\nMARKER-FS-BIG-TAIL\n");
    std::fs::write(&big, &big_body).expect("big file");
    let restricted_file = restricted.join("secret.txt");
    std::fs::write(&restricted_file, "SECRET-FS\n").expect("restricted");
    let ssh_file = secret_dir.join("id_rsa");
    std::fs::write(&ssh_file, "FAKE-PRIVATE-KEY\n").expect("ssh file");

    // stage 1: live discovery (argv allowed dir = data), then the reviewed
    // draft — the workload half of the host policy the run stages extend.
    let argv_main = match server_argv(spec, &[kdl_path(&data)]) {
        Some(a) => a,
        None => return,
    };
    stage1_live_discovery(spec, &argv_main, &root);
    let reviewed = stage1_review_draft(spec, &root, &["read_file", "read_multiple_files"]);

    // host policy: tool fs = srv/** (Auditor scope), defaults grant = data
    // only — `restricted` is never granted, so the OS layer denies it.
    let srv_glob = format!("{}/**", kdl_path(&srv));
    let server_extra = format!(
        "server \"filesystem\" {{\n    tool \"read_file\" {{\n        filesystem {{\n            allow \"{srv_glob}\"\n        }}\n    }}\n    tool \"read_multiple_files\" {{\n        filesystem {{\n            allow \"{srv_glob}\"\n        }}\n    }}\n}}\n"
    );
    let mut host_kdl = draft_host_policy(&reviewed, &argv_main[0], &server_extra);
    let fs_grants: &[(&Path, &str)] = &[(&data, "read")];
    inject_fs_grants(&mut host_kdl, fs_grants);
    let policy_path = write_policy(&root, "host-fs.kdl", &host_kdl);

    let positive_args = format!("{{\"path\":{}}}", json_str(&kdl_path(&marker_file)));

    // stage 2: dry-run (Auditor only). The guard cwd is a granted dir so a
    // spawned child inherits a working directory it may access.
    stage2_dry_run(
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
    .await;

    // stage 3 + 4: sandboxed session — allowed call, then Auditor denial
    let (mut s3, audit3) = stage3_spawn(spec, &policy_path, &argv_main, &[], Some(&data)).await;
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

    // Optional argument on the same tool: `head` truncates the read — the
    // schema accepts it and the server applies it (line 5 never arrives).
    let head_args = format!("{{\"path\":{},\"head\":2}}", json_str(&kdl_path(&numbered)));
    let head_resp = s3.call("read_file", &head_args).await;
    let head_resp = head_resp.expect("stage3 filesystem: head call must answer");
    assert!(
        !json_has_error(&head_resp) && !is_error_result(&head_resp),
        "stage3 filesystem: optional `head` call must succeed: {head_resp}"
    );
    assert!(
        head_resp.contains("FS-LINE-1") && !head_resp.contains("FS-LINE-5"),
        "stage3 filesystem: head=2 must return the first lines only: {head_resp}"
    );

    // `paths` — the array-valued selector — through the same fs scope.
    let multi_args = format!(
        "{{\"paths\":[{},{}]}}",
        json_str(&kdl_path(&marker_file)),
        json_str(&kdl_path(&numbered))
    );
    let multi_resp = s3.call("read_multiple_files", &multi_args).await;
    let multi_resp = multi_resp.expect("stage3 filesystem: read_multiple_files must answer");
    assert!(
        !json_has_error(&multi_resp) && !is_error_result(&multi_resp),
        "stage3 filesystem: read_multiple_files must succeed: {multi_resp}"
    );
    assert!(
        multi_resp.contains(&marker) && multi_resp.contains("FS-LINE-5"),
        "stage3 filesystem: both files' contents must arrive: {multi_resp}"
    );

    // Large response at the PR-20 frame cap: ~4MiB of content (~8.4MB as
    // the server frames it) must arrive intact — the tail marker proves
    // the whole body was delivered.
    let mid_args = format!("{{\"path\":{}}}", json_str(&kdl_path(&mid)));
    let mid_resp = s3.call("read_file", &mid_args).await;
    let mid_resp = mid_resp.expect("stage3 filesystem: mid read must answer");
    assert!(
        !json_has_error(&mid_resp) && !is_error_result(&mid_resp),
        "stage3 filesystem: ~4MiB read must succeed: {}",
        &mid_resp[..mid_resp.len().min(400)]
    );
    assert!(
        mid_resp.len() > 8 * 1024 * 1024 && mid_resp.contains("MARKER-FS-MID-TAIL"),
        "stage3 filesystem: the full body must arrive — len={}",
        mid_resp.len()
    );

    // …and the over-cap side of the same boundary: ~9MiB is ~18.9MB on the
    // wire, so the frame cap refuses it — the PR-20 refusal itself is the
    // asserted evidence.
    let big_args = format!("{{\"path\":{}}}", json_str(&kdl_path(&big)));
    let big_resp = s3.call("read_file", &big_args).await;
    let big_resp = big_resp.expect("stage3 filesystem: big read must answer");
    assert!(
        json_has_error(&big_resp) && big_resp.contains("frame-too-large"),
        "stage3 filesystem: ~9MiB read must hit the frame cap: {}",
        &big_resp[..big_resp.len().min(400)]
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
            // On macOS the sandbox refuses the spawn itself (realpath of
            // the ungranted argv dir) — that refusal is the OS-layer deny
            // this stage measures. Anywhere else a failed startup is a
            // genuine failure, and a handshake that succeeded followed by
            // a silent call is a failure on every OS.
            None => {
                assert!(
                    init5.is_none() && cfg!(target_os = "macos"),
                    "stage5 filesystem: sandboxed session produced no response \
                     (init5={init5:?})"
                );
                eprintln!("stage5 filesystem: spawn refused by the OS sandbox (macOS, recorded)");
            }
        }
    }

    // stage 6: corrupted hash pin must fail tools/list — the bad policy
    // extends the same reviewed draft as the main one.
    stage6_bad_hash(
        spec,
        &reviewed,
        2,
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
        panic!(
            "filesystem filter: sandboxed spawn produced no initialize response; stderr: {stderr}"
        );
    }
    let Some(list) = s.tools_list().await else {
        let stderr = s.shutdown_stderr().await;
        panic!("filesystem filter: no tools/list response; stderr: {stderr}");
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

    // stage 1: live discovery, then the reviewed draft as the run policy's
    // workload half.
    stage1_live_discovery(spec, &argv, &root);
    let reviewed = stage1_review_draft(spec, &root, &["create_entities"]);

    // The server's data file is chosen by MEMORY_FILE_PATH, not by an RPC
    // argument — the OS sandbox (defaults grant) is the only layer that can
    // scope it. data/ is granted read-write; restricted/ is never granted.
    // The tool takes no path argument: the explicit empty fs block keeps the
    // inherited `defaults.filesystem` grants from requiring one.
    let server_extra = "server \"memory\" {\n    tool \"create_entities\" {\n        filesystem {\n            allow none=#true\n            require-path #false\n        }\n    }\n}\n";
    let mut host_kdl = draft_host_policy(&reviewed, &argv[0], server_extra);
    let mem_grants: &[(&Path, &str)] = &[(&data, "write")];
    inject_fs_grants(&mut host_kdl, mem_grants);
    // The restricted default environment drops unlisted names — the
    // server's data file is chosen by MEMORY_FILE_PATH, so it must be
    // allowed through or the server falls back to dist/memory.jsonl
    // inside the read-only package tree.
    inject_environment(&mut host_kdl, &["MEMORY_FILE_PATH"]);
    let policy_path = write_policy(&root, "host-mem.kdl", &host_kdl);
    let env = [("MEMORY_FILE_PATH", mem_file.to_string_lossy().into_owned())];
    let env_refs: Vec<(&str, &str)> = env.iter().map(|(k, v)| (*k, v.as_str())).collect();

    let create_args = "{\"entities\":[{\"name\":\"e2e-entity\",\"entityType\":\"marker\",\"observations\":[\"obs-1\"]}]}";

    // stage 2: dry-run
    stage2_dry_run(
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
    .await;

    // stage 3 + 4: sandboxed session
    let (mut s3, audit3) = stage3_spawn(spec, &policy_path, &argv, &env_refs, Some(&data)).await;
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
            // server-memory@1.0.0 wraps writes in a `.lock` retry loop:
            // under AppContainer the denied create reports EPERM — which
            // the server reads as "lock held" — and its ENOENT continue
            // path bypasses the retry deadline, so the write denial
            // manifests as a permanently hung call (verified: >130s, no
            // response) rather than a tool error. The denial evidence
            // stands on the missing file + absent denied event + the
            // stage-3 success on the granted path.
            assert!(
                cfg!(windows) && init5.is_some(),
                "stage5 memory: sandboxed session produced no response (init5={init5:?}); \
                 the server must start and fail at the write"
            );
            eprintln!(
                "stage5 memory: Windows deny surfaces as a hung call (server-memory lock retry) — recorded divergence"
            );
        }
    }

    // stage 6: corrupted hash pin must fail tools/list
    stage6_bad_hash(
        spec,
        &reviewed,
        2,
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
/// server resolves the path lazily, so startup itself still succeeds). On
/// Windows the failure surfaces as a hung call — server-memory@1.0.0's
/// lock retry reads the denied EPERM as "held" and its ENOENT path never
/// reaches the retry deadline.
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

    let (mut session, _audit) =
        stage3_spawn(spec, &allowed_path, &argv, &env_refs, Some(&data)).await;
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
            // Same server-memory lock-retry divergence as stage5: on
            // Windows the denied write hangs the call with no response
            // (the EPERM-as-busy retry never reaches its deadline on the
            // ENOENT path). The block evidence is the missing file and
            // the absence of a denied audit event.
            assert!(
                cfg!(windows) && init.is_some(),
                "env-blocked memory: sandboxed session produced no response (init={init:?}): \
                 {audit_b_text}"
            );
            eprintln!(
                "env-blocked memory: Windows deny surfaces as a hung call (server-memory lock retry) — recorded divergence"
            );
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

    // stage 1: live discovery, then the reviewed draft as the run policy's
    // workload half.
    stage1_live_discovery(spec, &argv, &root);
    let reviewed = stage1_review_draft(spec, &root, &["get_current_time"]);

    // A granted scratch dir gives the sandboxed child a valid working
    // directory (Windows refuses to spawn a child whose inherited cwd is
    // outside the grant). The tool is pathless: the empty fs block keeps the
    // inherited defaults from demanding a path argument it does not take.
    let scratch = root.join("scratch");
    std::fs::create_dir_all(&scratch).expect("mkdir scratch");
    let server_extra = "server \"time\" {\n    tool \"get_current_time\" {\n        filesystem {\n            allow none=#true\n            require-path #false\n        }\n    }\n}\n";
    let mut host_kdl = draft_host_policy(&reviewed, &argv[0], server_extra);
    let time_grants: &[(&Path, &str)] = &[(&scratch, "read")];
    inject_fs_grants(&mut host_kdl, time_grants);
    let policy_path = write_policy(&root, "host-time.kdl", &host_kdl);

    let time_args = "{\"timezone\":\"UTC\"}";

    // stage 2: dry-run
    stage2_dry_run(
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
    .await;

    // stage 3 + 4: sandboxed session
    let (mut s3, audit3) = stage3_spawn(spec, &policy_path, &argv, &[], Some(&scratch)).await;
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
        &reviewed,
        2,
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
/// reports an unborn `HEAD` as a missing `refs/heads/master`. A setup
/// failure is a genuine failure — only a *missing* `git` is a skip
/// prerequisite, and that is checked before this runs.
fn git_init(dir: &Path, git_exe: &Path) {
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
    assert!(
        ok,
        "git repo fixture setup failed at {} — `git` resolved but could not init/commit",
        dir.display()
    );
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
    git_init(&repo, &git_exe);
    git_init(&outside_repo, &git_exe);

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
        assert!(
            matches!(ok, Ok(s) if s.success()),
            "icacls /inheritance:d failed on {}",
            outside_repo.display()
        );
    }
    let git_env = (
        "GIT_PYTHON_GIT_EXECUTABLE",
        git_exe.to_string_lossy().into_owned(),
    );
    // Git also consults the global/system config; inside the sandbox $HOME is
    // outside every grant so `~/.gitconfig` reads fail — and git treats that
    // as a fatal "unknown error ... reading the configuration files" in some
    // code paths. Point both config files at readable non-entities instead.
    // Windows sets neither: there is no /dev/null spelling, the restricted
    // child env carries no HOME/USERPROFILE for git to locate a user config
    // with, and MinGit's system gitconfig sits under the granted exe prefix
    // anyway.
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
    // GitPython probes `git --version` at import. On Windows `quiet` defers
    // that subprocess to the first real git command, keeping `import git` —
    // and therefore the handshake — independent of an extra sandboxed exec;
    // an exec regression then surfaces as the stage-3 tool-call error rather
    // than a dead session.
    if cfg!(windows) {
        env_vec.push(("GIT_PYTHON_REFRESH", "quiet"));
    }
    let env_refs: &[(&str, &str)] = &env_vec;

    let argv = match server_argv(spec, &["--repository".to_string(), kdl_path(&repo)]) {
        Some(a) => a,
        None => return,
    };

    // stage 1: live discovery, then the reviewed draft as the run policy's
    // workload half. The stages exercise three tools — the review lifts
    // exactly those denies.
    stage1_live_discovery(spec, &argv, &root);
    let reviewed = stage1_review_draft(spec, &root, &["git_log", "git_status", "git_branch"]);

    // defaults: interpreter runtime + the repo + the child cwd `work/` +
    // git's own prefix for the subprocess image. `work/` is granted so the
    // child has a valid working directory; `work/repo` is denied by its
    // protected DACL on Windows, and by nothing on Linux (subtree grant).
    // The Auditor scope is `root/**` so both `repo` and `work/repo` are
    // policy-visible; the OS grant is what differentiates them.
    let root_glob = format!("{}/**", kdl_path(&root));
    let server_extra = format!(
        "server \"git\" {{\n    tool \"git_log\" {{\n        filesystem {{\n            allow \"{root_glob}\"\n        }}\n    }}\n    tool \"git_status\" {{\n        filesystem {{\n            allow \"{root_glob}\"\n        }}\n    }}\n    tool \"git_branch\" {{\n        filesystem {{\n            allow \"{root_glob}\"\n        }}\n    }}\n}}\n"
    );
    let mut host_kdl = draft_host_policy(&reviewed, &argv[0], &server_extra);
    let mut git_grant_dirs = vec![repo.clone(), cwd.clone()];
    git_grant_dirs.extend(common::exe_read_grant_dirs(&git_exe));
    let git_grants: Vec<(&Path, &str)> = git_grant_dirs
        .iter()
        .map(|d| (d.as_path(), "read"))
        .collect();
    inject_fs_grants(&mut host_kdl, &git_grants);
    // The child environment is restricted by default — every name the
    // spawn passes must be allowed through or it never reaches the
    // server: GIT_PYTHON_GIT_EXECUTABLE locates the granted git exe,
    // the GIT_CONFIG_GLOBAL/GIT_CONFIG_NOSYSTEM redirects keep git off
    // the ungranted real config, and on Windows GIT_PYTHON_REFRESH=quiet
    // defers `import git`'s `git --version` probe (see the note above).
    let env_names: Vec<&str> = env_vec.iter().map(|(name, _)| *name).collect();
    inject_environment(&mut host_kdl, &env_names);
    let policy_path = write_policy(&root, "host-git.kdl", &host_kdl);

    let log_args = format!("{{\"repo_path\":{}}}", json_str(&kdl_path(&repo)));
    // Optional args the generated args_schema accepts: max_count and the
    // timestamp window — the window exercises them for real.
    let log_args_optional = format!(
        "{{\"repo_path\":{},\"max_count\":1,\"start_timestamp\":\"1970-01-01\",\"end_timestamp\":\"2099-12-31\"}}",
        json_str(&kdl_path(&repo))
    );

    // stage 2: dry-run
    stage2_dry_run(
        spec,
        &policy_path,
        &argv,
        env_refs,
        Some(&cwd),
        PositiveCall {
            tool: "git_log",
            args: &log_args_optional,
            marker: "init",
        },
    )
    .await;

    // stage 3 + 4: sandboxed session (guard cwd = work/, granted so the
    // AppContainer child has a valid working directory)
    let (mut s3, audit3) = stage3_spawn(spec, &policy_path, &argv, env_refs, Some(&cwd)).await;
    let resp = s3.call("git_log", &log_args).await;
    // Earlier Windows builds could not run the MinGW git subprocess under
    // AppContainer (the runtime resolved its cwd through
    // GetFinalPathNameByHandleW, which the token could not perform); on
    // current builds the granted repo/cwd/exe paths make the call succeed.
    // Either way the call must answer — and the boundary that matters is
    // asserted by stage 5's out-of-grant deny below.
    let r = resp.expect("stage3 git: allowed call must answer");
    assert!(
        !json_has_error(&r) && !is_error_result(&r),
        "stage3 git: sandboxed git_log on granted paths must succeed: {r}"
    );

    // The omitted-vs-explicit optional-argument matrix: a window in the
    // future filters the single commit out — the optional args reached the
    // server and were applied, which is what distinguishes this from a
    // bare required-argument call.
    let r_opt = s3.call("git_log", &log_args_optional).await;
    let r_opt = r_opt.expect("stage3 git: optional-args call must answer");
    assert!(
        !json_has_error(&r_opt) && !is_error_result(&r_opt) && r_opt.contains("init"),
        "stage3 git: windowed git_log must return the commit: {r_opt}"
    );
    let filtered_args = format!(
        "{{\"repo_path\":{},\"start_timestamp\":\"2030-01-01\",\"end_timestamp\":\"2030-12-31\"}}",
        json_str(&kdl_path(&repo))
    );
    let r_f = s3.call("git_log", &filtered_args).await;
    let r_f = r_f.expect("stage3 git: filtered call must answer");
    assert!(
        !json_has_error(&r_f) && !is_error_result(&r_f) && !r_f.contains("init"),
        "stage3 git: a future window must filter the commit out: {r_f}"
    );

    // Two more reviewed tools — `git_status` takes only the required
    // `repo_path`; `git_branch` adds the required `branch_type` while its
    // `contains`/`not_contains` options stay omitted.
    let status_resp = s3.call("git_status", &log_args).await;
    let status_resp = status_resp.expect("stage3 git: git_status must answer");
    assert!(
        !json_has_error(&status_resp) && !is_error_result(&status_resp),
        "stage3 git: sandboxed git_status must succeed: {status_resp}"
    );
    let branch_args = format!(
        "{{\"repo_path\":{},\"branch_type\":\"local\"}}",
        json_str(&kdl_path(&repo))
    );
    let branch_resp = s3.call("git_branch", &branch_args).await;
    let branch_resp = branch_resp.expect("stage3 git: git_branch must answer");
    assert!(
        !json_has_error(&branch_resp) && !is_error_result(&branch_resp),
        "stage3 git: sandboxed git_branch must succeed: {branch_resp}"
    );
    assert!(
        branch_resp.contains("master"),
        "stage3 git: git_branch must list the seed branch: {branch_resp}"
    );

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
    // access; on Linux/macOS the composed process-level grant covers the
    // subtree — a recorded divergence of process-level sandboxing.
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
        // A silent session is not blanket "recorded evidence" — it is
        // the deny manifesting at startup only when stderr proves the
        // child really ran under the sandbox and died on the denied
        // path (GitPython validates `--repository` at boot; the DACL
        // deny on `work/repo` makes the valid repo read as invalid, so
        // the server exits before `initialize`). Any other startup
        // failure is a genuine failure.
        None => {
            if cfg!(windows) {
                assert!(
                    audit5_text.contains("mechanism=appcontainer"),
                    "stage5 git: no sandbox evidence — spawn failed before the \
                     deny could act: {audit5_text}"
                );
                assert!(
                    audit5_text.contains("not a valid Git repository"),
                    "stage5 git: startup failure must name the denied repo as \
                     unreadable: {audit5_text}"
                );
                eprintln!(
                    "stage5 git: OS deny observed at startup — the sandboxed \
                     server could not read the ungranted repo"
                );
            } else {
                panic!(
                    "stage5 git: sandboxed session produced no response \
                     (init5={init5:?}): {audit5_text}"
                );
            }
        }
    }

    // stage 6: corrupted hash pin must fail tools/list
    stage6_bad_hash(
        spec,
        &reviewed,
        2,
        &argv[0],
        &argv,
        env_refs,
        &root,
        &git_grants,
        Some(&cwd),
    )
    .await;
}

// ─── fetch ────────────────────────────────────────────────────────────────

/// Deterministic local HTTP fixture for the fetch server. Binds 0.0.0.0 so
/// it answers on 127.0.0.1 (macOS loopback allowance) and on the machine's
/// LAN IPv4 (Windows AppContainer children cannot loop back to the host,
/// and Linux names the LAN spelling so any namespace-level routing still
/// reaches it). Static bodies except `/big` (~200KB, exercises the
/// `max_length`/`start_index` pagination contract).
struct LocalHttp {
    port: u16,
}

impl LocalHttp {
    fn start() -> Self {
        let listener = std::net::TcpListener::bind(("0.0.0.0", 0)).expect("bind fixture http");
        let port = listener.local_addr().expect("local addr").port();
        std::thread::spawn(move || {
            while let Ok((stream, _)) = listener.accept() {
                std::thread::spawn(move || serve_http_conn(stream));
            }
        });
        Self { port }
    }
}

fn fetch_big_body() -> String {
    // HEAD at 0, TAIL near the end — pagination assertions name both.
    format!("MARKER-BIG-HEAD\n{}\nMARKER-BIG-TAIL", "x".repeat(200_000))
}

fn serve_http_conn(mut stream: std::net::TcpStream) {
    use std::io::{Read, Write};
    let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(10)));
    let mut buf: Vec<u8> = Vec::with_capacity(4096);
    let mut chunk = [0u8; 4096];
    while !buf.windows(4).any(|w| w == b"\r\n\r\n") && buf.len() < 16 * 1024 {
        match stream.read(&mut chunk) {
            Ok(0) | Err(_) => return,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
        }
    }
    let text = String::from_utf8_lossy(&buf);
    let path = text
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .unwrap_or("/");
    let (status, ctype, body) = match path {
        "/" => (200, "text/plain", "MARKER-FSERVE-OK\n".to_string()),
        "/big" => (200, "text/plain", fetch_big_body()),
        "/html" => (
            200,
            "text/html",
            "<html><body>MARKER-HTML-PAGE</body></html>\n".to_string(),
        ),
        // A permissive robots file — the server is also launched with
        // --ignore-robots-txt, so this is only a fallback.
        "/robots.txt" => (200, "text/plain", "User-agent: *\nAllow: /\n".to_string()),
        _ => (404, "text/plain", "not found\n".to_string()),
    };
    let resp = format!(
        "HTTP/1.1 {status} {}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        if status == 200 { "OK" } else { "Not Found" },
        body.len(),
    );
    let _ = stream.write_all(resp.as_bytes());
    let _ = stream.shutdown(std::net::Shutdown::Both);
}

/// The LAN IPv4 the sandboxed child uses to reach the fixture — a UDP
/// `connect` picks the source address without sending anything. A host
/// with no non-loopback interface cannot run the fetch stages at all —
/// every other route to the child is the restricted one.
#[cfg(not(target_os = "macos"))]
fn lan_ipv4() -> Option<String> {
    let sock = std::net::UdpSocket::bind(("0.0.0.0", 0)).ok()?;
    sock.connect(("192.0.2.1", 80)).ok()?;
    match sock.local_addr().ok()?.ip() {
        std::net::IpAddr::V4(v4) => Some(v4.to_string()),
        std::net::IpAddr::V6(_) => None,
    }
}

/// True only where a granted TCP connect(2) port cannot be expressed at
/// all — a sub-V4 Landlock ABI (kernel < 6.7, e.g. WSL2) drops ConnectTcp
/// handling, so the ungranted-port call *succeeds* as a recorded
/// divergence. macOS pins the SBPL endpoint port (the denied port is
/// refused at the RPC layer there — the same rules feed both layers), and
/// Windows AppContainer isolation blocks the local connect wholesale, so
/// those paths take the error branch, not this one.
#[cfg(target_os = "linux")]
fn port_grant_unexpressible() -> bool {
    common::linux_below_landlock_v4()
}
#[cfg(not(target_os = "linux"))]
fn port_grant_unexpressible() -> bool {
    false
}

/// The host spelling the fetch URL uses. macOS names 127.0.0.1 — its
/// loopback proxy is the destination-aware layer and the SBPL endpoint is
/// port-pinned. Everywhere else names the LAN IPv4: Windows AppContainer
/// children cannot loop back to the host at all, and the Linux netport
/// grant does not care which address a connect(2) targets.
fn fetch_url_host() -> Option<String> {
    #[cfg(target_os = "macos")]
    {
        Some("127.0.0.1".to_string())
    }
    #[cfg(not(target_os = "macos"))]
    {
        lan_ipv4()
    }
}

#[tokio::test]
async fn fetch_stages() {
    let _stage_lock = STAGE_LOCK.lock().await;
    let spec = &FETCH;
    let (_t, root) = temp_root("mcp_writ_rs_fetch_");
    let scratch = root.join("scratch");
    std::fs::create_dir_all(&scratch).expect("mkdir scratch");

    let argv = match server_argv(spec, &[]) {
        Some(a) => a,
        None => return,
    };

    // stage 1: live discovery, then the reviewed draft as the run policy's
    // workload half — the single `fetch` tool's deny is lifted.
    stage1_live_discovery(spec, &argv, &root);
    let reviewed = stage1_review_draft(spec, &root, &["fetch"]);

    // Two fixture servers on distinct ports: the allowed one and the one
    // whose port the OS grant never names (stage 5).
    let http = LocalHttp::start();
    let http2 = LocalHttp::start();
    let Some(host) = fetch_url_host() else {
        common::skip_server_test("no LAN IPv4 address for the fetch fixture");
        return;
    };
    let page_url = format!("http://{host}:{}/", http.port);
    let big_url = format!("http://{host}:{}/big", http.port);
    let html_url = format!("http://{host}:{}/html", http.port);
    let other_url = format!("http://{host}:{}/", http2.port);

    // defaults.network — the OS-layer egress shape per mechanism:
    //   Linux   deny-all + `allow host="*" port=<P>` — the bare-port
    //           spelling is the only egress shape a ConnectTcp netport
    //           rule can express (a port with no destination bound); the
    //           flat `allow host="<ip>"` is Auditor-only, so the granted
    //           port reaches the OS while the ungranted one passes the
    //           RPC layer and dies in connect(2).
    //   macOS   deny-all + `allow host="127.0.0.1:<P>"` becomes a
    //           port-pinned `remote tcp` endpoint.
    //   Windows AppContainer capabilities are all-or-none — a deny posture
    //           withholds them entirely, so the only network-capable
    //           policy is the open posture.
    #[cfg(target_os = "linux")]
    let net_inner = format!(
        "        deny host=\"*\"\n        allow host=\"*\" port={0}\n        allow host=\"{1}\"\n",
        http.port, host
    );
    #[cfg(target_os = "macos")]
    let net_inner = format!(
        "        deny host=\"*\"\n        allow host=\"127.0.0.1:{0}\"\n",
        http.port
    );
    #[cfg(target_os = "windows")]
    let net_inner = "        allow host=\"*\"\n".to_string();
    // The tool-level block is the RPC-layer destination list — the allowed
    // host on any port, so stage 5's ungranted port reaches the OS. The
    // empty fs block keeps the inherited grants from demanding a path the
    // url-only tool does not carry.
    let server_extra = format!(
        "server \"fetch\" {{\n    tool \"fetch\" {{\n        filesystem {{\n            allow none=#true\n            require-path #false\n        }}\n        network {{\n            allow host=\"{host}\"\n        }}\n    }}\n}}\n"
    );
    let mut host_kdl = draft_host_policy(&reviewed, &argv[0], &server_extra);
    let fetch_grants: &[(&Path, &str)] = &[(&scratch, "read")];
    inject_fs_grants(&mut host_kdl, fetch_grants);
    inject_network(&mut host_kdl, &net_inner);
    let policy_path = write_policy(&root, "host-fetch.kdl", &host_kdl);

    // stage 2: dry-run — the required `url` only; every optional argument
    // (max_length, start_index, raw) is omitted.
    let page_args = format!("{{\"url\":{}}}", json_str(&page_url));
    stage2_dry_run(
        spec,
        &policy_path,
        &argv,
        &[],
        Some(&scratch),
        PositiveCall {
            tool: "fetch",
            args: &page_args,
            marker: "MARKER-FSERVE-OK",
        },
    )
    .await;

    // stage 3 + 4: session calls — the same allowed call, the optional
    // arguments, then an Auditor-layer destination denial. Windows runs
    // them unsandboxed: the AppContainer grants no loopback exemption for
    // stdio launches (HTTP transport only), so a same-host fixture is
    // unreachable from inside the sandbox whatever the posture — the
    // Auditor still enforces args_schema and the allow list, and stage 5
    // keeps the sandboxed OS-layer evidence.
    #[cfg(windows)]
    let s3_env: &[(&str, &str)] = &[("MCP_WRIT_SKIP_SANDBOX", "1")];
    #[cfg(not(windows))]
    let s3_env: &[(&str, &str)] = &[];
    let (mut s3, audit3) = stage3_spawn(spec, &policy_path, &argv, s3_env, Some(&scratch)).await;
    let resp = s3.call("fetch", &page_args).await;
    let resp = resp.expect("stage3 fetch: allowed call must answer");
    assert!(
        !json_has_error(&resp) && !is_error_result(&resp),
        "stage3 fetch: sandboxed fetch must succeed: {resp}"
    );
    assert!(
        resp.contains("MARKER-FSERVE-OK"),
        "stage3 fetch: page body must reach the client: {resp}"
    );

    // `max_length` truncates the ~200KB body and the server names the
    // continuation index — the large-response path exercises both.
    let trunc_args = format!("{{\"url\":{},\"max_length\":100}}", json_str(&big_url));
    let trunc = s3.call("fetch", &trunc_args).await;
    let trunc = trunc.expect("stage3 fetch: truncated call must answer");
    assert!(
        !json_has_error(&trunc) && !is_error_result(&trunc),
        "stage3 fetch: max_length call must succeed: {trunc}"
    );
    assert!(
        trunc.contains("MARKER-BIG-HEAD") && trunc.contains("start_index of 100"),
        "stage3 fetch: truncation must carry the continuation index: {trunc}"
    );

    // `start_index` slices deep into the same page.
    let tail_args = format!("{{\"url\":{},\"start_index\":199900}}", json_str(&big_url));
    let tail = s3.call("fetch", &tail_args).await;
    let tail = tail.expect("stage3 fetch: start_index call must answer");
    assert!(
        !json_has_error(&tail) && !is_error_result(&tail),
        "stage3 fetch: start_index call must succeed: {tail}"
    );
    assert!(
        tail.contains("MARKER-BIG-TAIL"),
        "stage3 fetch: the slice must reach the page tail: {tail}"
    );

    // The full large response: max_length=999999 returns the whole ~200KB
    // body through the wire framing intact.
    let full_args = format!("{{\"url\":{},\"max_length\":999999}}", json_str(&big_url));
    let full = s3.call("fetch", &full_args).await;
    let full = full.expect("stage3 fetch: full-page call must answer");
    assert!(
        !json_has_error(&full) && !is_error_result(&full),
        "stage3 fetch: the ~200KB fetch must succeed: len={}",
        full.len()
    );
    assert!(
        full.contains("MARKER-BIG-HEAD") && full.contains("MARKER-BIG-TAIL"),
        "stage3 fetch: head and tail must both arrive — len={}",
        full.len()
    );

    // `raw` returns the HTML unsimplified.
    let raw_args = format!("{{\"url\":{},\"raw\":true}}", json_str(&html_url));
    let raw = s3.call("fetch", &raw_args).await;
    let raw = raw.expect("stage3 fetch: raw call must answer");
    assert!(
        !json_has_error(&raw) && !is_error_result(&raw),
        "stage3 fetch: raw call must succeed: {raw}"
    );
    assert!(
        raw.contains("<html") && raw.contains("MARKER-HTML-PAGE"),
        "stage3 fetch: raw=true must return the unprocessed HTML: {raw}"
    );

    // stage 4: Auditor deny — a destination the tool's allow list does not
    // cover. On macOS a `localhost` spelling is additionally refused by the
    // name layer (no resolution before the check): host `localhost` is not
    // the declared `127.0.0.1`.
    let denied_args = if cfg!(target_os = "macos") {
        format!("{{\"url\":\"http://localhost:{}/\"}}", http.port)
    } else {
        "{\"url\":\"http://example.invalid/\"}".to_string()
    };
    let denied = s3.call("fetch", &denied_args).await;
    let denied = denied.expect("stage4 fetch: denied call must still answer");
    assert!(
        json_has_error(&denied),
        "stage4 fetch: uncovered destination must be a JSON-RPC error: {denied}"
    );
    let audit3_text = s3.finish_audit(&audit3).await;
    let denied_line = audit_denied_line(&audit3_text).unwrap_or_else(|| {
        panic!("stage4 fetch: audit log missing tool_call.denied: {audit3_text}")
    });
    assert!(
        denied_line.contains("fetch"),
        "stage4 fetch: denied event must name the tool: {denied_line}"
    );

    // stage 5: OS-layer reach — the tool scope allows the host on any port,
    // so the Auditor passes http2's port; only the OS grant differentiates.
    let audit5 = common::next_audit_log_path();
    let mut s5 = GuardSession::spawn(&policy_path, &audit5, &argv, &[], false, Some(&scratch));
    let init5 = s5.handshake().await;
    let denied5_args = format!("{{\"url\":{}}}", json_str(&other_url));
    let resp5 = if init5.is_some() {
        let _ = s5.tools_list().await;
        s5.call("fetch", &denied5_args).await
    } else {
        None
    };
    let audit5_text = s5.finish_audit(&audit5).await;
    match resp5 {
        Some(r) => {
            if cfg!(target_os = "macos") {
                // The SBPL endpoint and the Auditor's egress check draw
                // from the same `egress_rules`, so a port the profile
                // denies is refused at the RPC layer first — the denial
                // is observable only as tool_call.denied.
                assert!(
                    json_has_error(&r) || is_error_result(&r),
                    "stage5 fetch: the ungranted port must be refused: {r}"
                );
                assert!(
                    audit_denied_line(&audit5_text).is_some(),
                    "stage5 fetch: macOS denies at the RPC layer — tool_call.denied expected: {audit5_text}"
                );
            } else {
                // Linux (netport) and Windows (AppContainer isolation)
                // refuse the connect beneath the Auditor — an OS-layer
                // denial must never log tool_call.denied. On Windows the
                // denial is broader than the grant (no loopback exemption
                // for stdio), but the evidence shape is the same.
                assert!(
                    audit_denied_line(&audit5_text).is_none(),
                    "stage5 fetch: OS-layer deny must not log tool_call.denied: {audit5_text}"
                );
                if port_grant_unexpressible() {
                    // A sub-V4 Landlock ABI cannot express ConnectTcp —
                    // the ungranted-port fetch succeeds. A recorded
                    // capability-matrix divergence.
                    assert!(
                        !json_has_error(&r) && !is_error_result(&r),
                        "stage5 fetch: no per-port mechanism — the call must succeed: {r}"
                    );
                    eprintln!(
                        "stage5 fetch: ungranted port allowed — recorded divergence (no per-port mechanism)"
                    );
                } else {
                    // Linux netport pins http.port only; Windows blocks
                    // the local connect outright — either way the OS
                    // refuses what the Auditor allowed.
                    assert!(
                        json_has_error(&r) || is_error_result(&r),
                        "stage5 fetch: the OS must deny the ungranted destination: {r}"
                    );
                }
            }
        }
        None => panic!(
            "stage5 fetch: sandboxed session produced no response (init5={init5:?}): {audit5_text}"
        ),
    }

    // stage 6: corrupted hash pin must fail tools/list
    stage6_bad_hash(
        spec,
        &reviewed,
        2,
        &argv[0],
        &argv,
        &[],
        &root,
        fetch_grants,
        Some(&scratch),
    )
    .await;
}
