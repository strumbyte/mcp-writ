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

use mcp_writ::container::guest_report;

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

/// Run a blocking step (subprocess probe, fixture compile, dir setup)
/// off the async runtime — the same `spawn_blocking` convention as
/// `container_e2e.rs`. A panic inside (e.g. a `MCP_WRIT_REQUIRE_*`
/// assertion in `skip_kata_test`) is re-raised on the test task so
/// required-test failures are never swallowed into a skip.
async fn blocking<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> T {
    match tokio::task::spawn_blocking(f).await {
        Ok(v) => v,
        Err(e) => std::panic::resume_unwind(e.into_panic()),
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
    if !common::docker_available() {
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
                Ok(s) if s.success() && out.exists() => {
                    // Same gate as `linux_runner`: the probe runs inside the
                    // pinned ubuntu:24.04 guest (glibc 2.39), so a host-built
                    // binary requiring a newer GLIBC_* must skip rather than
                    // die in the guest's loader.
                    if let Some((major, minor)) = std::fs::read(&out)
                        .ok()
                        .as_deref()
                        .and_then(common::elf_verneed_glibc)
                        && (major, minor) > (2, 39)
                    {
                        common::skip_kata_test(&format!(
                            "kata probe requires glibc {major}.{minor}, above the pinned guest's 2.39"
                        ));
                        return None;
                    }
                    Some(dir.keep().join("kata-probe"))
                }
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
    if guest_report::scan_runner_caps(&bytes).is_none() {
        common::skip_kata_test("runner has no MCP_WRIT_RUNNER_CAPS marker");
        return None;
    }
    // The pinned ubuntu:24.04 guest carries glibc 2.39 — a host-built
    // runner linking a newer GLIBC_* dies in the guest's loader with
    // `GLIBC_x.y not found`, so gate on the binary's verneed rather
    // than discovering it mid-launch. A static/musl build names no
    // GLIBC_* versions and runs on any userland.
    if let Some((major, minor)) = common::elf_verneed_glibc(&bytes)
        && (major, minor) > (2, 39)
    {
        common::skip_kata_test(&format!(
            "runner requires glibc {major}.{minor}, above the pinned guest's 2.39"
        ));
        return None;
    }
    Some(path)
}

// ─── image build ───────────────────────────────────────────────────────

/// Build-context tempdir scoped to `build_images`: `docker build` copies
/// the context to the daemon, so nothing referenced later needs it — a
/// raw `PathBuf` would leak `mcp_writ_kata_img_*` under %TEMP% per run.
fn build_context_dir() -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix("mcp_writ_kata_img_")
        .tempdir()
        .expect("image build context tempdir")
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
            // A dropped future must kill the CLI — otherwise an
            // interrupted build keeps running detached, growing the
            // daemon's cache with nobody watching it.
            .kill_on_drop(true)
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
/// Returns the secure image tag; the build context drops with this call.
async fn build_images(runner: &Path, probe: &Path) -> Result<String, String> {
    let work = build_context_dir();
    let base_dir = work.path().join("base");
    let secure_dir = work.path().join("secure");
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

    let caps = guest_report::this_runner_identity();
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
    Ok(secure_tag.to_string())
}

/// Both tests need the same two images — build once per test binary so
/// a parallel run never races on a shared build context or tag.
static IMAGES: tokio::sync::OnceCell<Result<String, String>> = tokio::sync::OnceCell::const_new();

async fn shared_images(runner: &Path, probe: &Path) -> Result<String, String> {
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
            guest_report::REPORT_OUT_ENV,
            guest_report::GUEST_REPORT_MOUNT_PATH
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
            guest_report::GUEST_REPORT_MOUNT_PATH
        ),
        image,
    ]);
    // stderr inherits the test's own (container_e2e convention): the
    // runner's tracing is diagnostic on failure, and a piped stderr that
    // nobody drains can deadlock the guest once the pipe buffer fills.
    cmd.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("docker run --runtime kata failed to spawn — the runtime is registered but may be unusable")
}

/// One request/response round-trip tracked by id; responses may arrive
/// out of order, so buffered lines are kept for later lookups.
struct Wire {
    lines: Vec<String>,
    reader: BufReader<tokio::process::ChildStdout>,
    writer: Option<tokio::process::ChildStdin>,
}

impl Wire {
    async fn send(&mut self, line: &str) {
        let w = self.writer.as_mut().expect("stdin is still open");
        w.write_all(line.as_bytes()).await.expect("write request");
        w.write_all(b"\n").await.expect("write newline");
        w.flush().await.expect("flush request");
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

    /// Signal EOF on stdin while keeping `self` — and therefore the
    /// stdout reader — alive. Dropping the reader before `child.wait()`
    /// would close the stdout pipe early: a late write from the guest
    /// could then EPIPE the docker CLI into a nonzero exit status.
    fn close_stdin(&mut self) {
        drop(self.writer.take());
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
    if let Some(reason) = blocking(check_prereqs).await {
        common::skip_kata_test(&reason);
        return;
    }
    let _vm_guard = VM_LOCK.lock().await;
    let Some(probe) = blocking(compiled_kata_probe).await else {
        return;
    };
    let Some(runner) = blocking(linux_runner).await else {
        return;
    };
    let image = match shared_images(&runner, &probe).await {
        Ok(tag) => tag,
        Err(e) => {
            common::skip_kata_test(&format!("image build failed: {e}"));
            return;
        }
    };

    let dirs = blocking(session_dirs).await;
    let launch_id = uuid::Uuid::now_v7().to_string();
    let t0 = Instant::now();
    let mut child = spawn_kata_session(&image, &dirs, &launch_id);
    let mut wire = Wire {
        lines: Vec::new(),
        reader: BufReader::new(child.stdout.take().unwrap()),
        writer: Some(child.stdin.take().unwrap()),
    };

    // initialize — the auditor pins the negotiated revision to exactly
    // 2025-11-25; anything else is a shape rejection.
    wire.send(&request(
        0,
        "initialize",
        "{\"protocolVersion\":\"2025-11-25\",\"capabilities\":{},\"clientInfo\":{\"name\":\"kata-vm-e2e\",\"version\":\"0\"}}",
    ))
    .await;
    let init = wire.wait_id(0, SESSION_TIMEOUT_SECS).await.expect(
        "initialize response never arrived — the kata runtime is \
                 registered but the VM/runner failed to come up; runner \
                 stderr (inherited above) names the cause",
    );
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
        (9, "read_file", "{\"path\":\"/etc/hostname\"}"),
        // Auditor tool gate.
        (10, "exec_shell", "{\"cmd\":\"id\"}"),
    ];
    for (id, name, args) in legs {
        wire.send(&tool_call(*id, name, args)).await;
    }
    wire.send(&request(11, "evil/method", "{}")).await;

    let mut got = std::collections::HashMap::new();
    for (id, ..) in legs.iter().chain([(11, "", "")].iter()) {
        let line = wire
            .wait_id(*id, 60)
            .await
            .unwrap_or_else(|| panic!("no response for id={id}"));
        got.insert(*id, line);
    }
    let last_response_s = t0.elapsed().as_secs_f64();

    // stdin EOF must wind the session down: child exits, VM is destroyed.
    wire.close_stdin();
    let status = timeout(Duration::from_secs(STOP_TIMEOUT_SECS), child.wait())
        .await
        .expect("container did not exit after stdin EOF")
        .expect("wait failed");
    let exit_s = t0.elapsed().as_secs_f64();

    // ── leg assertions ────────────────────────────────────────────────
    let text_of = |id: i64| got.get(&id).cloned().unwrap_or_default();

    // Guest identity: Kata's own VM markers are the hard proof — the
    // guest /proc/cmdline carries the kata agent handoff and virtiofs/9p
    // is how shares enter the VM. The probe's /proc/self/status fields
    // show the controls applied to it.
    let ident = text_of(2);
    assert!(
        ident.contains("uname.osrelease=") && ident.contains("NoNewPrivs=1"),
        "vm_identity must report guest kernel + no_new_privs: {ident}"
    );
    assert!(
        ident.contains("Seccomp=2"),
        "guest must report an active seccomp filter: {ident}"
    );
    assert!(
        ident.contains("cmdline_has_kata=true"),
        "guest /proc/cmdline must carry the kata marker: {ident}"
    );
    assert!(
        ident.contains("virtiofs_in_filesystems=true"),
        "guest must expose virtiofs/9p (the share mechanism): {ident}"
    );
    // Informational, not an assert: a host could legitimately run the same
    // kernel release the guest ships, so release equality is weak evidence
    // either way — the kata markers above are the identity proof.
    let host_release = std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .unwrap_or_default()
        .trim()
        .to_string();
    if !host_release.is_empty() && ident.contains(&format!("uname.osrelease={host_release}")) {
        eprintln!(
            "note: guest kernel release matches the host ({host_release}); \
             identity evidence rests on the kata cmdline/virtiofs markers"
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
        text_of(9).contains("Permission denied"),
        "read outside the grants must hit Landlock: {}",
        text_of(9)
    );
    assert!(
        text_of(10).contains("tool is not allowed"),
        "deny=#true tool must be refused by the auditor: {}",
        text_of(10)
    );
    assert!(
        text_of(11).contains("unknown-method"),
        "unknown method must be refused: {}",
        text_of(11)
    );

    // ── exit + artifacts ──────────────────────────────────────────────
    assert!(
        status.success(),
        "guest session must exit 0 on stdin EOF, got {status:?}"
    );

    let report_path = dirs.report.join("report.json");
    let report = std::fs::read_to_string(&report_path)
        .unwrap_or_else(|e| panic!("guest report missing at {}: {e}", report_path.display()));
    guest_report::validate_guest_report_text(
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

/// Async so each poll tick doesn't block the runtime on a subprocess —
/// the spawn_blocking equivalent used in `container_e2e.rs`, expressed
/// directly with `tokio::process::Command`.
async fn qemu_process_running(pattern: &str) -> bool {
    Command::new("pgrep")
        .args(["-f", pattern])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .await
        .map(|o| !o.stdout.is_empty())
        .unwrap_or(false)
}

async fn container_exited(name: &str) -> bool {
    Command::new("docker")
        .args(["inspect", name, "--format", "{{.State.Status}}"])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .await
        .map(|o| String::from_utf8_lossy(&o.stdout).trim() == "exited")
        .unwrap_or(false)
}

/// Poll `f` until it holds or `secs` elapse — VM boot/teardown speed
/// varies with host load, so lifecycle checks must not rely on fixed
/// sleeps. `f` is async so subprocess probes don't block the runtime.
async fn poll<Fut>(secs: u64, ms: u64, mut f: impl FnMut() -> Fut) -> bool
where
    Fut: std::future::Future<Output = bool>,
{
    let deadline = Instant::now() + Duration::from_secs(secs);
    while Instant::now() < deadline {
        if f().await {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(ms)).await;
    }
    false
}

/// The `Option` variant of [`poll`]: returns the first `Some` `f`
/// yields, or `None` when `secs` elapse.
async fn poll_some<T, Fut>(secs: u64, ms: u64, mut f: impl FnMut() -> Fut) -> Option<T>
where
    Fut: std::future::Future<Output = Option<T>>,
{
    let deadline = Instant::now() + Duration::from_secs(secs);
    while Instant::now() < deadline {
        if let Some(v) = f().await {
            return Some(v);
        }
        tokio::time::sleep(Duration::from_millis(ms)).await;
    }
    None
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
    if let Some(reason) = blocking(check_prereqs).await {
        common::skip_kata_test(&reason);
        return;
    }
    let _vm_guard = VM_LOCK.lock().await;
    let Some(probe) = blocking(compiled_kata_probe).await else {
        return;
    };
    let Some(runner) = blocking(linux_runner).await else {
        return;
    };
    let image = match shared_images(&runner, &probe).await {
        Ok(tag) => tag,
        Err(e) => {
            common::skip_kata_test(&format!("image build failed: {e}"));
            return;
        }
    };

    let dirs = blocking(session_dirs).await;
    let name = format!("kata-e2e-sigint-{}", std::process::id());
    let dirs_policy = dirs.policy.display().to_string();
    let dirs_workspace = dirs.workspace.display().to_string();
    let dirs_logs = dirs.logs.display().to_string();
    let dirs_report = dirs.report.display().to_string();
    let launch_id = uuid::Uuid::now_v7().to_string();

    // Attached container: piped stdin/stdout serve the guest runner's
    // stdio session, and the `initialize` handshake proves the runner is
    // live before the signal — a SIGINT arriving before the runner
    // installs its handlers would test startup teardown, not session
    // unwind. `--name` pins cleanup; the container object stays for the
    // exit-state poll (ContainerGuard removes it).
    let mut cmd = Command::new("docker");
    cmd.args([
        "run",
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
        &format!(
            "{}={}",
            guest_report::REPORT_OUT_ENV,
            guest_report::GUEST_REPORT_MOUNT_PATH
        ),
        "-v",
        &format!("{dirs_policy}:/etc/mcp-secure/policy.kdl:ro"),
        "-v",
        &format!("{dirs_workspace}:/workspace"),
        "-v",
        &format!("{dirs_logs}:/var/log/mcp-secure"),
        "-v",
        &format!("{dirs_report}:{}", guest_report::GUEST_REPORT_MOUNT_PATH),
        &image,
    ]);
    let mut child = cmd
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("docker run --runtime kata failed to spawn");
    let _guard = ContainerGuard(name.clone());
    let mut wire = Wire {
        lines: Vec::new(),
        reader: BufReader::new(child.stdout.take().unwrap()),
        writer: Some(child.stdin.take().unwrap()),
    };
    wire.send(&request(
        0,
        "initialize",
        "{\"protocolVersion\":\"2025-11-25\",\"capabilities\":{},\"clientInfo\":{\"name\":\"kata-vm-e2e\",\"version\":\"0\"}}",
    ))
    .await;
    let init = wire
        .wait_id(0, SESSION_TIMEOUT_SECS)
        .await
        .expect("initialize response never arrived — the runner is not live");
    assert!(
        init.contains("\"result\"") && init.contains("\"protocolVersion\":\"2025-11-25\""),
        "initialize must return a pinned 2025-11-25 result, got: {init}"
    );

    // Attached mode does not print the container id — `docker inspect`
    // names it for the QEMU process pattern below.
    let inspect = Command::new("docker")
        .args(["inspect", &name, "--format", "{{.Id}}"])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .await
        .expect("docker inspect failed");
    assert!(inspect.status.success(), "docker inspect {{.Id}} failed");
    let container_id = String::from_utf8_lossy(&inspect.stdout).trim().to_string();
    assert!(
        !container_id.is_empty(),
        "docker inspect returned no container id"
    );

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
    let qemu_gone = poll(STOP_TIMEOUT_SECS, 500, || async {
        !qemu_process_running(&qemu_pat).await
    })
    .await;
    assert!(
        qemu_gone,
        "QEMU for sandbox-{container_id} must be gone after exit"
    );
}

// ─── the product path: `run-image --isolation kata` ────────────────────
//
// The two sessions above drive `docker run --runtime kata` directly —
// the PR-16 validation harness. The tests below drive the product CLI
// (`mcp-writ run-image --isolation kata`), which must apply the same VM
// boundary through the shared backend contract and record it on the
// launch report — never silently degrade to a runc container.

/// Spawn the product CLI: `mcp-writ run-image --isolation kata` over the
/// shared secure image, with the launch report written to `report_path`.
/// stdin/stdout are piped for the stdio session; stderr is piped and
/// drained into a returned task so a verbose child cannot deadlock on a
/// full pipe buffer while the failure text stays available to assert on.
fn spawn_run_image(
    image: &str,
    dirs: &SessionDirs,
    report_path: &Path,
    engine: &str,
) -> (tokio::process::Child, tokio::task::JoinHandle<Vec<u8>>) {
    let mut cmd = Command::new(common::mcp_writ_bin());
    cmd.args([
        "run-image",
        "--isolation",
        "kata",
        "--engine",
        engine,
        "--server",
        "kata-probe",
        "--policy",
        &dirs.policy.to_string_lossy(),
        "--log-dir",
        &dirs.logs.to_string_lossy(),
        "--report",
        &report_path.to_string_lossy(),
        "--allow-mutable-tag",
        image,
    ])
    .stdin(Stdio::piped())
    .stdout(Stdio::piped())
    .stderr(Stdio::piped());
    let mut child = cmd.spawn().expect("mcp-writ run-image failed to spawn");
    // Drain stderr in the background — a full pipe would wedge the run.
    let mut stderr = child.stderr.take().unwrap();
    let stderr_task = tokio::spawn(async move {
        use tokio::io::AsyncReadExt;
        let mut buf = Vec::new();
        let _ = stderr.read_to_end(&mut buf).await;
        buf
    });
    (child, stderr_task)
}

/// The single running container id for `image`, if exactly one exists —
/// the launch's unit id (the shim names its VM `sandbox-<id>`).
async fn running_container_for(image: &str) -> Option<String> {
    let out = Command::new("docker")
        .args([
            "ps",
            "-q",
            "--no-trunc",
            "--filter",
            &format!("ancestor={image}"),
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .await
        .ok()?;
    let ids: Vec<String> = String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter(|l| !l.is_empty())
        .map(str::to_string)
        .collect();
    (ids.len() == 1).then(|| ids[0].clone())
}

/// `docker inspect`'s recorded runtime for `cid` — `kata` when the VM
/// boundary was applied, `runc` for a plain container.
async fn container_runtime(cid: &str) -> Option<String> {
    Command::new("docker")
        .args(["inspect", cid, "--format", "{{.HostConfig.Runtime}}"])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .await
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .filter(|s| !s.is_empty())
}

fn json_str(v: &nojson::RawJsonValue<'_, '_>, name: &str) -> String {
    v.to_member(name)
        .unwrap()
        .required()
        .unwrap()
        .to_unquoted_string_str()
        .expect("expected a JSON string")
        .into_owned()
}

/// `run-image --isolation kata` must serve the same stdio contract as
/// the direct `docker run --runtime kata` session — and the launch
/// report must record the *confirmed* VM boundary, not just the request.
#[tokio::test]
async fn run_image_kata_stdio_session() {
    if let Some(reason) = blocking(check_prereqs).await {
        common::skip_kata_test(&reason);
        return;
    }
    let _vm_guard = VM_LOCK.lock().await;
    let Some(probe) = blocking(compiled_kata_probe).await else {
        return;
    };
    let Some(runner) = blocking(linux_runner).await else {
        return;
    };
    let image = match shared_images(&runner, &probe).await {
        Ok(tag) => tag,
        Err(e) => {
            common::skip_kata_test(&format!("image build failed: {e}"));
            return;
        }
    };

    let dirs = blocking(session_dirs).await;
    let host_report = dirs.report.join("host-launch-report.json");
    let (mut child, _stderr_drain) = spawn_run_image(&image, &dirs, &host_report, "docker");
    let mut wire = Wire {
        lines: Vec::new(),
        reader: BufReader::new(child.stdout.take().unwrap()),
        writer: Some(child.stdin.take().unwrap()),
    };

    // initialize — same pinned revision the harness session asserts.
    wire.send(&request(
        0,
        "initialize",
        "{\"protocolVersion\":\"2025-11-25\",\"capabilities\":{},\"clientInfo\":{\"name\":\"kata-run-image-e2e\",\"version\":\"0\"}}",
    ))
    .await;
    let init = wire.wait_id(0, SESSION_TIMEOUT_SECS).await.expect(
        "initialize response never arrived — the kata VM/runner failed \
         to come up through the product path",
    );
    assert!(
        init.contains("\"result\"") && init.contains("\"protocolVersion\":\"2025-11-25\""),
        "initialize must return a pinned 2025-11-25 result, got: {init}"
    );

    // While the VM runs: the engine must report the kata runtime for
    // this launch's unit, and the QEMU process for its sandbox must be
    // alive — the host-side VM-boundary proof, not a report claim.
    let cid = poll_some(STOP_TIMEOUT_SECS, 500, || {
        let image = image.clone();
        async move { running_container_for(&image).await }
    })
    .await
    .expect("no running container for the kata image");
    assert_eq!(
        container_runtime(&cid).await.as_deref(),
        Some("kata"),
        "the launch must run under the kata runtime, not runc"
    );
    let qemu_pat = format!("sandbox-{cid}");
    assert!(
        qemu_process_running(&qemu_pat).await,
        "a QEMU process for sandbox-{cid} must exist — the boundary is a VM"
    );

    // Guest-side probe legs through the product path's stdio relay.
    wire.send("{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}")
        .await;
    // Same ordering proof as the harness session: waiting on our own
    // tools/list response is what shows the auditor's list pipeline
    // settled, so the probe calls below cannot race an in-flight
    // revalidation.
    wire.send(&request(9, "tools/list", "{}")).await;
    let list = wire
        .wait_id(9, 60)
        .await
        .expect("tools/list response never arrived");
    assert!(
        list.contains("\"result\"") && list.contains("vm_identity"),
        "tools/list must return the probe's tool inventory, got: {list}"
    );
    let legs: &[(i64, &str, &str)] = &[
        (1, "vm_identity", "{\"path\":\"/proc/self/status\"}"),
        (2, "read_file", "{\"path\":\"/etc/shadow\"}"),
        (3, "exec_shell", "{\"cmd\":\"id\"}"),
        (
            4,
            "create_file",
            "{\"path\":\"/workspace/kata-run-image.txt\",\"content\":\"kata\"}",
        ),
    ];
    for (id, name, args) in legs {
        wire.send(&tool_call(*id, name, args)).await;
    }
    let mut got = std::collections::HashMap::new();
    for (id, ..) in legs {
        let line = wire
            .wait_id(*id, 60)
            .await
            .unwrap_or_else(|| panic!("no response for id={id}"));
        got.insert(*id, line);
    }
    let text_of = |id: i64| got.get(&id).cloned().unwrap_or_default();

    // The guest-side VM markers — cmdline kata handoff + virtiofs share
    // mechanism — prove the workload ran in the Kata guest, matching the
    // harness session's assertions.
    let ident = text_of(1);
    assert!(
        ident.contains("cmdline_has_kata=true") && ident.contains("virtiofs_in_filesystems=true"),
        "guest identity must carry the kata markers through run-image: {ident}"
    );
    assert!(ident.contains("Seccomp=2") && ident.contains("NoNewPrivs=1"));
    assert!(
        text_of(2).contains("secret-path overlay"),
        "secret path deny must come from the in-guest auditor: {}",
        text_of(2)
    );
    assert!(
        text_of(3).contains("tool is not allowed"),
        "deny=#true tool must be refused by the auditor: {}",
        text_of(3)
    );
    assert!(
        text_of(4).contains("created /workspace/kata-run-image.txt"),
        "workspace write inside the grant must succeed: {}",
        text_of(4)
    );

    // stdin EOF ends the session; the VM is destroyed with the container.
    wire.close_stdin();
    let status = timeout(Duration::from_secs(STOP_TIMEOUT_SECS), child.wait())
        .await
        .expect("run-image did not exit after stdin EOF")
        .expect("wait failed");
    assert!(
        status.success(),
        "run-image must exit 0 on a clean kata session, got {status:?}"
    );
    let qemu_gone = poll(STOP_TIMEOUT_SECS, 500, || async {
        !qemu_process_running(&qemu_pat).await
    })
    .await;
    assert!(qemu_gone, "QEMU for sandbox-{cid} must be gone after exit");

    // ── the host launch report records the confirmed VM boundary ────
    let report_text = std::fs::read_to_string(&host_report)
        .unwrap_or_else(|e| panic!("launch report missing at {}: {e}", host_report.display()));
    let parsed = nojson::RawJson::parse(&report_text).expect("report is valid JSON");
    let root = parsed.value();

    let target = root.to_member("target").unwrap().required().unwrap();
    assert_eq!(json_str(&target, "substrate"), "vm");
    assert_eq!(json_str(&target, "engine"), "docker");
    assert_eq!(json_str(&target, "workload_os"), "linux");

    let iso = root.to_member("isolation").unwrap().required().unwrap();
    assert_eq!(json_str(&iso, "configured"), "kata");
    assert_eq!(
        json_str(&iso, "verified"),
        "kata",
        "the backend must confirm kata was applied — never a runc fallback"
    );
    assert_eq!(json_str(&iso, "unit"), "vm");
    assert_eq!(
        json_str(&iso, "unit_id"),
        cid,
        "the recorded unit id is the container id the VM is named after"
    );
    assert!(
        json_str(&iso, "detail").contains("runtime: kata"),
        "the isolation detail records the runtime registration"
    );

    let result = root.to_member("result").unwrap().required().unwrap();
    assert_eq!(json_str(&result, "status"), "exited");
    assert_eq!(
        result
            .to_member("exit_code")
            .unwrap()
            .required()
            .unwrap()
            .as_number_str()
            .unwrap(),
        "0"
    );

    // The guest report channel works through the kata mount the same
    // way — received, validated, and correlated by launch id.
    let guest = root.to_member("guest").unwrap().required().unwrap();
    assert_eq!(json_str(&guest, "state"), "received");
    let guest_report = guest.to_member("report").unwrap().required().unwrap();
    assert_eq!(
        json_str(&guest_report, "launch_id"),
        json_str(&root, "launch_id"),
        "guest report launch_id must correlate with the host launch"
    );

    let audit = std::fs::read_to_string(dirs.logs.join("audit.jsonl")).expect("audit log missing");
    assert!(
        audit.contains("tool_call.denied"),
        "the kata-mounted audit log must record the auditor's denies"
    );
}

/// SIGINT to the `run-image` process must terminate the kata workload
/// and leave no QEMU/container behind — the shared session driver's
/// interrupt path owns the VM teardown through the unit id.
#[tokio::test]
async fn run_image_kata_sigint_interrupts_and_cleans_up() {
    if let Some(reason) = blocking(check_prereqs).await {
        common::skip_kata_test(&reason);
        return;
    }
    let _vm_guard = VM_LOCK.lock().await;
    let Some(probe) = blocking(compiled_kata_probe).await else {
        return;
    };
    let Some(runner) = blocking(linux_runner).await else {
        return;
    };
    let image = match shared_images(&runner, &probe).await {
        Ok(tag) => tag,
        Err(e) => {
            common::skip_kata_test(&format!("image build failed: {e}"));
            return;
        }
    };

    let dirs = blocking(session_dirs).await;
    let host_report = dirs.report.join("host-interrupt-report.json");
    let (mut child, _stderr_drain) = spawn_run_image(&image, &dirs, &host_report, "docker");
    let mut wire = Wire {
        lines: Vec::new(),
        reader: BufReader::new(child.stdout.take().unwrap()),
        writer: Some(child.stdin.take().unwrap()),
    };

    // Wait for the workload to be live inside the VM.
    wire.send(&request(
        0,
        "initialize",
        "{\"protocolVersion\":\"2025-11-25\",\"capabilities\":{},\"clientInfo\":{\"name\":\"kata-run-image-sigint\",\"version\":\"0\"}}",
    ))
    .await;
    wire.wait_id(0, SESSION_TIMEOUT_SECS)
        .await
        .expect("initialize response never arrived — the kata VM failed to come up");
    let cid = poll_some(STOP_TIMEOUT_SECS, 500, || {
        let image = image.clone();
        async move { running_container_for(&image).await }
    })
    .await
    .expect("no running container for the kata image");
    let qemu_pat = format!("sandbox-{cid}");

    // SIGINT the mcp-writ process itself — the shared session driver
    // catches ctrl_c, terminates the unit (docker rm -f by cidfile), and
    // reports `interrupted`.
    let pid = child.id().expect("run-image pid");
    let kill = StdCommand::new("kill")
        .args(["-INT", &pid.to_string()])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("kill -INT failed to spawn");
    assert!(kill.success(), "kill -INT {pid} failed");

    let status = timeout(Duration::from_secs(STOP_TIMEOUT_SECS), child.wait())
        .await
        .expect("run-image did not exit after SIGINT")
        .expect("wait failed");
    assert!(
        !status.success(),
        "an interrupted run must not exit 0, got {status:?}"
    );

    // The interrupt path removed the unit — the container and its QEMU
    // are gone without manual cleanup.
    let cid_gone = poll(STOP_TIMEOUT_SECS, 500, || {
        let cid = cid.clone();
        async move { container_runtime(&cid).await.is_none() }
    })
    .await;
    assert!(cid_gone, "container {cid} must be removed after SIGINT");
    let qemu_gone = poll(STOP_TIMEOUT_SECS, 500, || async {
        !qemu_process_running(&qemu_pat).await
    })
    .await;
    assert!(
        qemu_gone,
        "QEMU for sandbox-{cid} must be gone after SIGINT"
    );

    // The report records the configured+verified boundary and the
    // interrupted outcome — the verification happened before the signal.
    let report_text = std::fs::read_to_string(&host_report)
        .unwrap_or_else(|e| panic!("launch report missing at {}: {e}", host_report.display()));
    let parsed = nojson::RawJson::parse(&report_text).unwrap();
    let root = parsed.value();
    let iso = root.to_member("isolation").unwrap().required().unwrap();
    assert_eq!(json_str(&iso, "configured"), "kata");
    assert_eq!(json_str(&iso, "verified"), "kata");
    assert_eq!(json_str(&iso, "unit"), "vm");
    let result = root.to_member("result").unwrap().required().unwrap();
    assert_eq!(json_str(&result, "status"), "interrupted");
}

/// `--isolation kata` through a non-docker engine must refuse — the
/// dockerd runtime registration is the validated configuration, and a
/// refusal never degrades to a plain container launch. Nothing is left
/// running: the report shows kata configured but never verified.
#[tokio::test]
async fn run_image_kata_refusal_leaves_nothing_running() {
    if let Some(reason) = blocking(check_prereqs).await {
        common::skip_kata_test(&reason);
        return;
    }
    let _vm_guard = VM_LOCK.lock().await;
    let Some(probe) = blocking(compiled_kata_probe).await else {
        return;
    };
    let Some(runner) = blocking(linux_runner).await else {
        return;
    };
    let image = match shared_images(&runner, &probe).await {
        Ok(tag) => tag,
        Err(e) => {
            common::skip_kata_test(&format!("image build failed: {e}"));
            return;
        }
    };

    let dirs = blocking(session_dirs).await;
    let host_report = dirs.report.join("host-refusal-report.json");
    let (mut child, stderr_drain) = spawn_run_image(&image, &dirs, &host_report, "podman");
    let status = timeout(Duration::from_secs(STOP_TIMEOUT_SECS), child.wait())
        .await
        .expect("run-image did not exit")
        .expect("wait failed");
    let stderr = String::from_utf8_lossy(&stderr_drain.await.unwrap_or_default()).into_owned();
    assert!(
        !status.success(),
        "kata over a non-docker engine must refuse, not fall back"
    );

    // Whether podman exists decides how far the launch gets: absent,
    // engine resolution refuses; present, later stages refuse first —
    // a remote CONTAINER_HOST trips the locality gate, and the
    // docker-built image is absent from podman's store, so the
    // backend's docker-only gate is reached only by a podman that can
    // actually see the image. Which stage fired is asserted from the
    // report's stage-tagged detail below, not the engine's stderr
    // wording.
    let podman_present = StdCommand::new("podman")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);

    // No container for this image is running or lingering.
    assert!(
        running_container_for(&image).await.is_none(),
        "a refused launch must leave nothing running"
    );

    let report_text = std::fs::read_to_string(&host_report)
        .unwrap_or_else(|e| panic!("launch report missing at {}: {e}", host_report.display()));
    let parsed = nojson::RawJson::parse(&report_text).unwrap();
    let root = parsed.value();
    let iso = root.to_member("isolation").unwrap().required().unwrap();
    assert_eq!(json_str(&iso, "configured"), "kata");
    // The backend never confirmed — verified/unit stay absent (a plain
    // container would record verified=container here; that is the
    // fallback this test exists to prove absent).
    assert!(
        iso.to_member("verified")
            .unwrap()
            .required()
            .unwrap()
            .kind()
            .is_null(),
        "verified must be null when the launch refuses"
    );
    assert!(
        iso.to_member("unit")
            .unwrap()
            .required()
            .unwrap()
            .kind()
            .is_null()
    );
    let result = root.to_member("result").unwrap().required().unwrap();
    assert_eq!(json_str(&result, "status"), "failed");
    // Every refusal names its stage in the report detail — a bare crash
    // leaves it empty. When the run did reach the backend check, the
    // refusal must name the validated (docker) configuration.
    let detail = json_str(&result, "detail");
    assert!(
        !detail.is_empty(),
        "a refused launch records its stage; stderr: {stderr}"
    );
    if podman_present && detail.starts_with("check isolation backend") {
        assert!(
            detail.contains("validated") && detail.contains("docker"),
            "the kata backend refusal must name the validated engine: {detail}"
        );
    }
}
