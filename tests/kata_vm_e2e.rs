//! Real-machine validation of the Kata VM isolation path (PR-16).
//!
//! Drives the same stdio MCP contract as `container_e2e.rs`, but the
//! workload runs inside a Kata guest VM: `docker run --runtime kata`
//! plus the runner/image/policy/mount contract of `run-image`. The
//! assertions split evidence by layer — engine-level (Kata shim, QEMU,
//! guest kernel), kernel-level (Landlock/seccomp in the guest), and
//! RPC-level (auditor denies) — because each is proven differently.
//!
//! Prerequisites (any missing → skip, or fail with
//! `MCP_WRIT_REQUIRE_KATA_TESTS=1`; see `docs/validation/kata.md`):
//!   - a running Docker daemon with a `kata` runtime registered
//!   - /dev/kvm and /dev/vhost-vsock on the host
//!   - `rustc` to compile tests/fixtures/kata/kata_probe_server.rs
//!   - a Linux ELF mcp-secure-runner (host cargo build suffices)
//!
//! This test never falls back to `runc`: a host without a working Kata
//! runtime skips (or fails when required) — it does not "pass" a weaker
//! isolation path in Kata's place.

mod common;

use std::path::{Path, PathBuf};
use std::process::{Command as StdCommand, Stdio};
use std::sync::OnceLock;
use std::time::Instant;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::Command;
use tokio::time::{Duration, timeout};

/// A Kata VM launch takes seconds, not milliseconds; the budget covers
/// image pulls on a cold cache and VM boot on a slow host without
/// turning a hang into a pass.
const SESSION_TIMEOUT_SECS: u64 = 180;
const STOP_TIMEOUT_SECS: u64 = 60;

/// Run at most one Kata VM at a time. Concurrent VMs double the memory
/// footprint (~1 GiB guest allocation each on top of QEMU overhead), and
/// hosts near their memory ceiling (this validation ran on a ~3.8 GiB
/// WSL2 VM) can crash the whole WSL instance mid-test.
static VM_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// ubuntu:24.04 pinned by digest — the guest rootfs of the recorded
/// validation run (docs/validation/kata.md). Matches glibc for a runner
/// built on Ubuntu 24.04.
const BASE_IMAGE_PINNED: &str =
    "ubuntu@sha256:008173c23f95b170204355c12626cb5a965d779a7e1283b09e9cffbb1bf33ca3";

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/kata")
}

// ─── prerequisites ─────────────────────────────────────────────────────

fn docker_available() -> bool {
    let child = StdCommand::new("docker")
        .arg("info")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn();
    match child {
        Ok(mut c) => {
            let start = Instant::now();
            loop {
                match c.try_wait() {
                    Ok(Some(s)) => return s.success(),
                    Ok(None) if start.elapsed().as_secs() > 5 => {
                        let _ = c.kill();
                        return false;
                    }
                    Ok(None) => std::thread::sleep(Duration::from_millis(100)),
                    Err(_) => return false,
                }
            }
        }
        Err(_) => false,
    }
}

/// `docker info` reports the registered runtimes; a `kata` entry is the
/// Docker-side registration of the runtime-rs shim this validation uses.
fn kata_runtime_registered() -> bool {
    let out = StdCommand::new("docker")
        .args(["info", "--format", "{{json .Runtimes}}"])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output();
    match out {
        Ok(o) if o.status.success() => {
            let s = String::from_utf8_lossy(&o.stdout);
            s.contains("\"kata\"")
        }
        _ => false,
    }
}

fn dev_node_ok(path: &str) -> bool {
    Path::new(path).exists()
}

fn check_prereqs() -> Option<String> {
    if !docker_available() {
        return Some("docker daemon unavailable".into());
    }
    if !kata_runtime_registered() {
        return Some("no 'kata' runtime registered with dockerd".into());
    }
    for dev in ["/dev/kvm", "/dev/vhost-vsock"] {
        if !dev_node_ok(dev) {
            return Some(format!("{dev} missing (Kata needs KVM and vhost-vsock)"));
        }
    }
    None
}

// ─── fixture build ─────────────────────────────────────────────────────

/// Compile `kata_probe_server.rs` once per test binary with plain rustc —
/// same contract as `common::compiled_open_path_fixture`.
fn compiled_kata_probe() -> Option<PathBuf> {
    static FIXTURE: OnceLock<Option<PathBuf>> = OnceLock::new();
    FIXTURE
        .get_or_init(|| {
            let src = fixtures_dir().join("kata_probe_server.rs");
            let dir = match tempfile::Builder::new()
                .prefix("mcp_writ_kata_probe_")
                .tempdir()
            {
                Ok(d) => d,
                Err(e) => {
                    common::skip_kata_test(&format!("probe tempdir failed: {e}"));
                    return None;
                }
            };
            let out = dir.path().join("kata-probe");
            let status = StdCommand::new("rustc")
                .args(["-O", "-o"])
                .arg(&out)
                .arg(&src)
                .stdout(Stdio::null())
                .stderr(Stdio::inherit())
                .status();
            match status {
                Ok(s) if s.success() && out.exists() => Some(dir.keep().join("kata-probe")),
                Ok(s) => {
                    common::skip_kata_test(&format!("rustc kata_probe_server.rs failed: {s}"));
                    None
                }
                Err(e) => {
                    common::skip_kata_test(&format!("rustc unavailable: {e}"));
                    None
                }
            }
        })
        .clone()
}

/// Linux ELF runner. Kata validation is Linux-only — a non-ELF runner
/// means the host cannot produce the guest binary and the test skips.
fn linux_runner() -> Option<PathBuf> {
    let path = PathBuf::from(env!("CARGO_BIN_EXE_mcp-secure-runner"));
    let is_elf = std::fs::read(&path)
        .map(|b| b.len() >= 4 && b[0..4] == [0x7f, b'E', b'L', b'F'])
        .unwrap_or(false);
    if !is_elf {
        common::skip_kata_test("mcp-secure-runner is not a Linux ELF binary");
        return None;
    }
    let bytes = std::fs::read(&path).ok()?;
    if mcp_writ::container::guest_report::scan_runner_caps(&bytes).is_none() {
        common::skip_kata_test("runner has no MCP_WRIT_RUNNER_CAPS marker");
        return None;
    }
    Some(path)
}

// ─── image build ───────────────────────────────────────────────────────

fn temp_dir(prefix: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "{prefix}-{:x}-{}",
        std::process::id(),
        uuid::Uuid::now_v7().simple()
    ));
    std::fs::create_dir_all(&dir).expect("temp dir");
    dir
}

async fn docker_build(context: &Path, tag: &str, dockerfile: &str) -> Result<(), String> {
    let out = timeout(
        Duration::from_secs(600),
        Command::new("docker")
            .args(["build", "-t", tag, "-f"])
            .arg(dockerfile)
            .arg(context)
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .output(),
    )
    .await
    .map_err(|_| "docker build timed out".to_string())?
    .map_err(|e| format!("docker build spawn failed: {e}"))?;
    if out.status.success() {
        Ok(())
    } else {
        Err(format!(
            "docker build {tag} failed: {}",
            String::from_utf8_lossy(&out.stderr)
        ))
    }
}

/// Base + secure images, mirroring the product's wrap contract: the
/// probe is the payload, `mcp-secure-runner` is PID 1, the policy is
/// baked in AND mounted read-only at run time, and the runner's own
/// capability marker is recorded on the image as `MCP_WRIT_RUNNER_CAPS`.
async fn build_images(runner: &Path, probe: &Path) -> Result<(PathBuf, String), String> {
    let work = temp_dir("mcp-writ-kata-img");
    let base_dir = work.join("base");
    let secure_dir = work.join("secure");
    std::fs::create_dir_all(&base_dir).map_err(|e| e.to_string())?;
    std::fs::create_dir_all(&secure_dir).map_err(|e| e.to_string())?;

    std::fs::copy(probe, base_dir.join("kata-probe")).map_err(|e| e.to_string())?;
    let base_df = format!(
        "FROM {BASE_IMAGE_PINNED}\n\
         COPY kata-probe /usr/local/bin/kata-probe\n\
         RUN chmod +x /usr/local/bin/kata-probe\n\
         ENTRYPOINT [\"/usr/local/bin/kata-probe\"]\n"
    );
    let base_df_path = base_dir.join("Dockerfile");
    std::fs::write(&base_df_path, base_df).map_err(|e| e.to_string())?;
    let base_tag = "mcp-writ-kata-probe-base:test";
    docker_build(&base_dir, base_tag, base_df_path.to_str().unwrap()).await?;

    let caps = mcp_writ::container::guest_report::this_runner_identity();
    let caps_json = format!(
        "{{\"v\":\"{}\",\"caps\":[{}]}}",
        caps.version,
        caps.capabilities
            .iter()
            .map(|c| format!("\"{c}\""))
            .collect::<Vec<_>>()
            .join(",")
    );
    std::fs::copy(runner, secure_dir.join("mcp-secure-runner")).map_err(|e| e.to_string())?;
    std::fs::copy(
        fixtures_dir().join("policy.kdl"),
        secure_dir.join("policy.kdl"),
    )
    .map_err(|e| e.to_string())?;
    let secure_df = format!(
        "FROM {base_tag}\n\
         COPY mcp-secure-runner /usr/local/bin/mcp-secure-runner\n\
         COPY policy.kdl /etc/mcp-secure/policy.kdl\n\
         RUN mkdir -p /var/log/mcp-secure /workspace && chmod +x /usr/local/bin/mcp-secure-runner\n\
         ENV MCP_ORIG_ENTRYPOINT=\"[\\\"/usr/local/bin/kata-probe\\\"]\" MCP_ORIG_CMD=\"\" \
         MCP_WRIT_ENV=\"\" MCP_WRIT_SERVER=\"\" MCP_WRIT_SKIP_SANDBOX=\"\" MCP_WRIT_FAIL_ON=\"\"\n\
         ENV MCP_WRIT_RUNNER_CAPS='{caps_json}'\n\
         ENTRYPOINT [\"/usr/local/bin/mcp-secure-runner\"]\n"
    );
    let secure_df_path = secure_dir.join("Dockerfile");
    std::fs::write(&secure_df_path, secure_df).map_err(|e| e.to_string())?;
    let secure_tag = "mcp-writ-kata-probe-secure:test";
    docker_build(&secure_dir, secure_tag, secure_df_path.to_str().unwrap()).await?;
    Ok((work, secure_tag.to_string()))
}

/// Both tests need the same two images — build once per test binary so
/// a parallel run never races on a shared build context or tag.
static IMAGES: tokio::sync::OnceCell<Result<(PathBuf, String), String>> =
    tokio::sync::OnceCell::const_new();

async fn shared_images(runner: &Path, probe: &Path) -> Result<(PathBuf, String), String> {
    IMAGES
        .get_or_init(|| async { build_images(runner, probe).await })
        .await
        .clone()
}

// ─── session driver ────────────────────────────────────────────────────

struct SessionDirs {
    _root: tempfile::TempDir,
    workspace: PathBuf,
    logs: PathBuf,
    report: PathBuf,
    policy: PathBuf,
}

fn session_dirs() -> SessionDirs {
    let root = tempfile::Builder::new()
        .prefix("mcp_writ_kata_run_")
        .tempdir()
        .expect("session tempdir");
    let workspace = root.path().join("workspace");
    let logs = root.path().join("logs");
    let report = root.path().join("report");
    for d in [&workspace, &logs, &report] {
        std::fs::create_dir_all(d).expect("session dir");
    }
    let policy = root.path().join("policy.kdl");
    std::fs::copy(fixtures_dir().join("policy.kdl"), &policy).expect("copy policy");
    SessionDirs {
        _root: root,
        workspace,
        logs,
        report,
        policy,
    }
}

/// Spawn `docker run --runtime kata` replicating the product's
/// `run-image` argument shape: read-only policy share, audit + report
/// mounts, workspace, launch id env. `--rm` owns container cleanup; the
/// VM itself is torn down by the shim on exit.
fn spawn_kata_session(image: &str, dirs: &SessionDirs, launch_id: &str) -> tokio::process::Child {
    let mut cmd = Command::new("docker");
    cmd.args([
        "run",
        "-i",
        "--rm",
        "--runtime",
        "kata",
        "--no-healthcheck",
        "--entrypoint",
        "/usr/local/bin/mcp-secure-runner",
        "-e",
        "MCP_WRIT_ENV=",
        "-e",
        "MCP_WRIT_SKIP_SANDBOX=",
        "-e",
        "MCP_WRIT_SERVER=kata-probe",
        "-e",
        &format!("MCP_WRIT_LAUNCH_ID={launch_id}"),
        "-e",
        &format!(
            "{}={}",
            mcp_writ::container::guest_report::REPORT_OUT_ENV,
            mcp_writ::container::guest_report::GUEST_REPORT_MOUNT_PATH
        ),
    ]);
    cmd.args([
        "-v",
        &format!("{}:/etc/mcp-secure/policy.kdl:ro", dirs.policy.display()),
        "-v",
        &format!("{}:/workspace", dirs.workspace.display()),
        "-v",
        &format!("{}:/var/log/mcp-secure", dirs.logs.display()),
        "-v",
        &format!(
            "{}:{}",
            dirs.report.display(),
            mcp_writ::container::guest_report::GUEST_REPORT_MOUNT_PATH
        ),
        image,
    ]);
    cmd.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("docker run spawn failed")
}

/// One request/response round-trip tracked by id; responses may arrive
/// out of order, so buffered lines are kept for later lookups.
struct Wire {
    lines: Vec<String>,
    reader: BufReader<tokio::process::ChildStdout>,
    writer: tokio::process::ChildStdin,
}

impl Wire {
    async fn send(&mut self, line: &str) {
        self.writer
            .write_all(line.as_bytes())
            .await
            .expect("write request");
        self.writer.write_all(b"\n").await.expect("write newline");
        self.writer.flush().await.expect("flush request");
    }

    /// Read until a response for `id` arrives; earlier lines are kept in
    /// the buffer so out-of-order responses are still found.
    async fn wait_id(&mut self, id: i64, secs: u64) -> Option<String> {
        let deadline = Instant::now() + Duration::from_secs(secs);
        loop {
            if let Some(pos) = self.lines.iter().position(|l| frame_id(l) == Some(id)) {
                return Some(self.lines.remove(pos));
            }
            let remaining = deadline.checked_duration_since(Instant::now())?;
            let mut buf = String::new();
            match timeout(remaining, self.reader.read_line(&mut buf)).await {
                Ok(Ok(0)) => return None, // EOF
                Ok(Ok(_)) => self.lines.push(buf),
                Ok(Err(_)) | Err(_) => return None, // read error or deadline hit
            }
        }
    }

    async fn close_stdin(self) {
        drop(self.writer);
    }
}

fn frame_id(line: &str) -> Option<i64> {
    mcp_writ::protocol::jsonrpc_id_as_i64(line)
}

fn request(id: i64, method: &str, params: &str) -> String {
    format!("{{\"jsonrpc\":\"2.0\",\"id\":{id},\"method\":\"{method}\",\"params\":{params}}}")
}

fn tool_call(id: i64, name: &str, args: &str) -> String {
    request(
        id,
        "tools/call",
        &format!("{{\"name\":\"{name}\",\"arguments\":{args}}}"),
    )
}

// ─── the validation session ────────────────────────────────────────────

#[tokio::test]
async fn kata_vm_stdio_session() {
    if let Some(reason) = check_prereqs() {
        common::skip_kata_test(&reason);
        return;
    }
    let _vm_guard = VM_LOCK.lock().await;
    let Some(probe) = compiled_kata_probe() else {
        return;
    };
    let Some(runner) = linux_runner() else {
        return;
    };
    let (_img_dir, image) = match shared_images(&runner, &probe).await {
        Ok(v) => v,
        Err(e) => {
            common::skip_kata_test(&format!("image build failed: {e}"));
            return;
        }
    };

    let dirs = session_dirs();
    let launch_id = uuid::Uuid::now_v7().to_string();
    let t0 = Instant::now();
    let mut child = spawn_kata_session(&image, &dirs, &launch_id);
    let mut wire = Wire {
        lines: Vec::new(),
        reader: BufReader::new(child.stdout.take().unwrap()),
        writer: child.stdin.take().unwrap(),
    };

    // initialize — the auditor pins the negotiated revision to exactly
    // 2025-11-25; anything else is a shape rejection.
    wire.send(&request(
        0,
        "initialize",
        "{\"protocolVersion\":\"2025-11-25\",\"capabilities\":{},\"clientInfo\":{\"name\":\"kata-vm-e2e\",\"version\":\"0\"}}",
    ))
    .await;
    let init = wire
        .wait_id(0, SESSION_TIMEOUT_SECS)
        .await
        .expect("initialize response never arrived — VM or runner failed");
    let first_response_s = t0.elapsed().as_secs_f64();
    assert!(
        init.contains("\"result\"") && init.contains("\"protocolVersion\":\"2025-11-25\""),
        "initialize must return a pinned 2025-11-25 result, got: {init}"
    );

    // Real-client ordering: initialized notification, then the internal
    // tools/list revalidation must settle before tool calls — waiting on
    // our own tools/list response is what proves that pipeline finished.
    wire.send("{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}")
        .await;
    wire.send(&request(1, "tools/list", "{}")).await;
    let list = wire
        .wait_id(1, 60)
        .await
        .expect("tools/list response never arrived");
    assert!(
        list.contains("\"result\"") && list.contains("net_probe"),
        "tools/list must return the probe's tool inventory, got: {list}"
    );

    // Probe legs — the expected mix of kernel denies, RPC-layer denies,
    // and allowed operations, each attributable to a specific control.
    let legs: &[(i64, &str, &str)] = &[
        (2, "vm_identity", "{\"path\":\"/proc/self/status\"}"),
        (
            3,
            "create_file",
            "{\"path\":\"/workspace/kata-ok.txt\",\"content\":\"kata\"}",
        ),
        (4, "read_file", "{\"path\":\"/workspace/kata-ok.txt\"}"),
        // Secret-overlay deny at the RPC layer — never reaches the tool.
        (5, "read_file", "{\"path\":\"/etc/shadow\"}"),
        // Seccomp: chmod/fchmodat/fchmodat2 are outside the allowlist.
        (6, "chmod_666", "{\"path\":\"/workspace/kata-ok.txt\"}"),
        // Seccomp: `socket` is removed when network deny-all is set.
        (
            7,
            "net_probe",
            "{\"addr\":\"192.0.2.1:80\",\"path\":\"/proc/self/status\"}",
        ),
        // Landlock: /etc is granted to nothing at kernel level.
        (
            8,
            "create_file",
            "{\"path\":\"/etc/evil.txt\",\"content\":\"x\"}",
        ),
        // Landlock: a readable-by-default file outside every grant.
        (11, "read_file", "{\"path\":\"/etc/hostname\"}"),
        // Auditor tool gate.
        (9, "exec_shell", "{\"cmd\":\"id\"}"),
    ];
    for (id, name, args) in legs {
        wire.send(&tool_call(*id, name, args)).await;
    }
    wire.send(&request(10, "evil/method", "{}")).await;

    let mut got = std::collections::HashMap::new();
    for (id, ..) in legs.iter().chain([(10, "", "")].iter()) {
        let line = wire
            .wait_id(*id, 60)
            .await
            .unwrap_or_else(|| panic!("no response for id={id}"));
        got.insert(*id, line);
    }
    let last_response_s = t0.elapsed().as_secs_f64();

    // stdin EOF must wind the session down: child exits, VM is destroyed.
    wire.close_stdin().await;
    let status = timeout(Duration::from_secs(STOP_TIMEOUT_SECS), child.wait())
        .await
        .expect("container did not exit after stdin EOF")
        .expect("wait failed");
    let exit_s = t0.elapsed().as_secs_f64();

    // ── leg assertions ────────────────────────────────────────────────
    let text_of = |id: i64| got.get(&id).cloned().unwrap_or_default();

    // Guest identity: different kernel than the host, Kata markers, and
    // the probe's own /proc view showing the controls applied to it.
    let ident = text_of(2);
    assert!(
        ident.contains("uname.osrelease=") && ident.contains("NoNewPrivs=1"),
        "vm_identity must report guest kernel + no_new_privs: {ident}"
    );
    assert!(
        ident.contains("Seccomp=2"),
        "guest must report an active seccomp filter: {ident}"
    );
    let host_release = std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .unwrap_or_default()
        .trim()
        .to_string();
    if !host_release.is_empty() {
        assert!(
            !ident.contains(&format!("uname.osrelease={host_release}")),
            "guest kernel must differ from host kernel {host_release}: {ident}"
        );
    }

    assert!(
        text_of(3).contains("created /workspace/kata-ok.txt"),
        "write inside the workspace grant must succeed: {}",
        text_of(3)
    );
    assert!(
        text_of(4).contains("opened /workspace/kata-ok.txt"),
        "read inside the workspace grant must succeed: {}",
        text_of(4)
    );
    assert!(
        text_of(5).contains("secret-path overlay"),
        "secret paths must deny at the RPC layer: {}",
        text_of(5)
    );
    assert!(
        text_of(6).contains("Operation not permitted"),
        "chmod must hit the seccomp deny: {}",
        text_of(6)
    );
    assert!(
        text_of(7).contains("Operation not permitted") || text_of(7).contains("Permission denied"),
        "TCP connect must hit the network deny: {}",
        text_of(7)
    );
    assert!(
        text_of(8).contains("Permission denied"),
        "write outside the grants must hit Landlock: {}",
        text_of(8)
    );
    assert!(
        text_of(11).contains("Permission denied"),
        "read outside the grants must hit Landlock: {}",
        text_of(11)
    );
    assert!(
        text_of(9).contains("tool is not allowed"),
        "deny=#true tool must be refused by the auditor: {}",
        text_of(9)
    );
    assert!(
        text_of(10).contains("unknown-method"),
        "unknown method must be refused: {}",
        text_of(10)
    );

    // ── exit + artifacts ──────────────────────────────────────────────
    assert!(
        status.success(),
        "guest session must exit 0 on stdin EOF, got {status:?}"
    );

    let report_path = dirs.report.join("report.json");
    let report = std::fs::read_to_string(&report_path)
        .unwrap_or_else(|e| panic!("guest report missing at {}: {e}", report_path.display()));
    mcp_writ::container::guest_report::validate_guest_report_text(
        &report,
        uuid::Uuid::parse_str(&launch_id).unwrap(),
        Some(env!("CARGO_PKG_VERSION")),
    )
    .expect("guest report must carry this launch's id and runner identity");
    for needle in [
        "\"os.fs\",\"layer\":\"os\",\"mechanism\":\"landlock\",\"state\":\"planned\"",
        "FullyEnforced",
        "no_new_privs confirmed",
        "seccomp program confirmed",
    ] {
        assert!(
            report.contains(needle),
            "guest report must contain {needle:?}"
        );
    }

    let audit = std::fs::read_to_string(dirs.logs.join("audit.jsonl")).expect("audit log missing");
    assert!(
        audit.contains("tool_call.denied") && audit.contains("mcp_message.allowed"),
        "audit log must record allows and denies"
    );

    eprintln!(
        "kata session evidence: first_response={first_response_s:.2}s \
         last_response={last_response_s:.2}s exit_after_eof={exit_s:.2}s"
    );
}

fn qemu_process_running(pattern: &str) -> bool {
    StdCommand::new("pgrep")
        .args(["-f", pattern])
        .stdout(Stdio::piped())
        .output()
        .map(|o| !o.stdout.is_empty())
        .unwrap_or(false)
}

fn container_exited(name: &str) -> bool {
    StdCommand::new("docker")
        .args(["inspect", name, "--format", "{{.State.Status}}"])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim() == "exited")
        .unwrap_or(false)
}

/// Poll `f` until it holds or `secs` elapse — VM boot/teardown speed
/// varies with host load, so lifecycle checks must not rely on fixed
/// sleeps.
async fn poll(secs: u64, ms: u64, f: impl Fn() -> bool) -> bool {
    let deadline = Instant::now() + Duration::from_secs(secs);
    while Instant::now() < deadline {
        if f() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(ms)).await;
    }
    false
}

/// Removes the named container on drop — including on panic — so a
/// failed assertion cannot leave a running VM behind.
struct ContainerGuard(String);

impl Drop for ContainerGuard {
    fn drop(&mut self) {
        // Poll with a deadline instead of blocking on .status(): a wedged
        // docker daemon must not hang the test process inside Drop.
        let Ok(mut child) = StdCommand::new("docker")
            .args(["rm", "-f", &self.0])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
        else {
            return;
        };
        let deadline = Instant::now() + Duration::from_secs(STOP_TIMEOUT_SECS);
        while Instant::now() < deadline {
            match child.try_wait() {
                Ok(Some(_)) | Err(_) => return,
                Ok(None) => std::thread::sleep(Duration::from_millis(100)),
            }
        }
        let _ = child.kill();
        let _ = child.wait();
    }
}

/// `docker kill -s SIGINT` must terminate the VM workload and leave no
/// QEMU/shim/virtiofsd processes behind — the VM cleanup contract.
#[tokio::test]
async fn kata_vm_sigint_terminates_and_cleans_up() {
    if let Some(reason) = check_prereqs() {
        common::skip_kata_test(&reason);
        return;
    }
    let _vm_guard = VM_LOCK.lock().await;
    let Some(probe) = compiled_kata_probe() else {
        return;
    };
    let Some(runner) = linux_runner() else {
        return;
    };
    let (_img_dir, image) = match shared_images(&runner, &probe).await {
        Ok(v) => v,
        Err(e) => {
            common::skip_kata_test(&format!("image build failed: {e}"));
            return;
        }
    };

    let dirs = session_dirs();
    let name = format!("kata-e2e-sigint-{}", std::process::id());
    let dirs_policy = dirs.policy.display().to_string();
    let dirs_workspace = dirs.workspace.display().to_string();
    let dirs_logs = dirs.logs.display().to_string();
    let dirs_report = dirs.report.display().to_string();
    let launch_id = uuid::Uuid::now_v7().to_string();

    // Detached container kept alive by `-i` (stdin open, no input).
    let out = Command::new("docker")
        .args([
            "run",
            "-d",
            "-i",
            "--runtime",
            "kata",
            "--name",
            &name,
            "--no-healthcheck",
            "--entrypoint",
            "/usr/local/bin/mcp-secure-runner",
            "-e",
            "MCP_WRIT_ENV=",
            "-e",
            "MCP_WRIT_SKIP_SANDBOX=",
            "-e",
            "MCP_WRIT_SERVER=kata-probe",
            "-e",
            &format!("MCP_WRIT_LAUNCH_ID={launch_id}"),
            "-e",
            "MCP_WRIT_REPORT_OUT=/run/mcp-secure/report",
            "-v",
            &format!("{dirs_policy}:/etc/mcp-secure/policy.kdl:ro"),
            "-v",
            &format!("{dirs_workspace}:/workspace"),
            "-v",
            &format!("{dirs_logs}:/var/log/mcp-secure"),
            "-v",
            &format!("{dirs_report}:/run/mcp-secure/report"),
            &image,
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await
        .expect("docker run -d failed");
    if !out.status.success() {
        common::skip_kata_test(&format!(
            "detached kata run failed: {}",
            String::from_utf8_lossy(&out.stderr)
        ));
        return;
    }
    let container_id = String::from_utf8_lossy(&out.stdout).trim().to_string();
    assert!(
        !container_id.is_empty(),
        "docker run -d returned no container id"
    );
    let _guard = ContainerGuard(name.clone());

    // VM entity evidence on the host: a QEMU process named after the
    // sandbox must exist while the container runs. Poll — VM boot speed
    // varies under load; a fixed sleep flakes the assertion.
    let qemu_pat = format!("sandbox-{container_id}");
    let qemu_alive = poll(STOP_TIMEOUT_SECS, 500, || qemu_process_running(&qemu_pat)).await;
    assert!(
        qemu_alive,
        "a QEMU process for sandbox-{container_id} must exist while the container runs"
    );

    // SIGINT the workload PID — the runner must unwind, the shim must
    // destroy the VM.
    let kill = Command::new("docker")
        .args(["kill", "-s", "SIGINT", &name])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .await
        .expect("docker kill failed");
    assert!(kill.status.success(), "docker kill -s SIGINT failed");

    let exited = poll(STOP_TIMEOUT_SECS, 500, || container_exited(&name)).await;
    assert!(exited, "container must exit after SIGINT");

    // No VM leftovers: the QEMU/shim processes for this sandbox must be
    // gone after the container exits.
    let qemu_gone = poll(STOP_TIMEOUT_SECS, 500, || !qemu_process_running(&qemu_pat)).await;
    assert!(
        qemu_gone,
        "QEMU for sandbox-{container_id} must be gone after exit"
    );
}
