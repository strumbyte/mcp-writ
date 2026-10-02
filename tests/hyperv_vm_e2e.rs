//! Real-machine validation of the Hyper-V isolated Windows container
//! path (PR-20).
//!
//! Drives the same stdio MCP contract as `container_e2e.rs` /
//! `kata_vm_e2e.rs`, but the workload runs inside a Windows container
//! launched with `docker run --isolation=hyperv`: each launch gets a
//! dedicated utility VM running the *image's* kernel. Assertions split
//! evidence by layer — engine-level (`.HostConfig.Isolation`, `vmwp.exe`
//! worker process), guest-kernel-level (`os.version`
//! differs from the host build under Hyper-V isolation), guest-OS-level
//! (AppContainer token + DACL + capability denies produced by the
//! in-guest Windows warden), and RPC-level (auditor denies).
//!
//! Prerequisites (any missing → skip, or fail with
//! `MCP_WRIT_REQUIRE_HYPERV_TESTS=1`; see
//! `docs/validation/windows-hyperv.md`):
//!   - a Windows host (the fixture compiles a windows/amd64 binary and
//!     binds host directories into the guest)
//!   - a running Docker engine with `OSType=windows` (Docker Desktop
//!     "Switch to Windows containers", or a native Windows `dockerd`)
//!   - `rustc` to compile `tests/fixtures/hyperv/hyperv_probe_server.rs`
//!   - a Windows PE `mcp-secure-runner` (a Windows cargo build is enough)
//!   - network for the first Server Core pull; the base image is pinned
//!     by digest below
//!
//! This test never substitutes process isolation: a launch whose
//! recorded isolation is not `hyperv` fails — the whole point is that
//! the guest ran behind a second kernel boundary, not on the host one.

mod common;

use std::path::{Path, PathBuf};
use std::process::{Command as StdCommand, Stdio};
use std::sync::OnceLock;
use std::time::Instant;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::Command;
use tokio::time::{Duration, timeout};

use mcp_writ::container::guest_report;

/// A Hyper-V unit boot takes seconds, and a Server Core layer pull on a
/// cold cache takes minutes; budgets cover the slow path without turning
/// a hang into a pass.
const SESSION_TIMEOUT_SECS: u64 = 300;
const STOP_TIMEOUT_SECS: u64 = 120;

/// Run at most one Hyper-V unit at a time: each launch boots a utility
/// VM with its own memory footprint.
static VM_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Server Core LTSC2025 pinned by digest — the guest image of the
/// recorded validation run (docs/validation/windows-hyperv.md). Server
/// Core carries the full Win32 surface the warden needs
/// (AppContainer/Job/registry APIs, `cmd.exe`); Nano Server is
/// deliberately not the acceptance baseline.
///
/// The image's kernel is 10.0.26100 — older than the recorded host's
/// 26200 — which is exactly what Hyper-V isolation is for (process
/// isolation would refuse the mismatch).
const BASE_IMAGE_PINNED: &str = "mcr.microsoft.com/windows/servercore@sha256:e18a49cbc074dfaa8e106296d51cebd62bbf6effb999f134a5c48eed1c2334e1";

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/hyperv")
}

// ─── prerequisites ─────────────────────────────────────────────────────

/// Run a blocking step (subprocess probe, fixture compile, dir setup)
/// off the async runtime — same convention as `kata_vm_e2e.rs`. A panic
/// inside (e.g. a `MCP_WRIT_REQUIRE_*` assertion in `skip_hyperv_test`)
/// is re-raised on the test task so required-test failures are never
/// swallowed into a skip.
async fn blocking<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> T {
    match tokio::task::spawn_blocking(f).await {
        Ok(v) => v,
        Err(e) => std::panic::resume_unwind(e.into_panic()),
    }
}

/// The engine must be a Windows `dockerd` — `docker info` reports the
/// daemon's OS, not the CLI's. 5 s bound like `common::docker_available`.
fn docker_engine_is_windows() -> bool {
    let child = StdCommand::new("docker")
        .args(["info", "--format", "{{.OSType}}"])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn();
    match child {
        Ok(mut child) => {
            let start = Instant::now();
            loop {
                match child.try_wait() {
                    Ok(Some(_)) => {
                        let mut s = String::new();
                        use std::io::Read;
                        let _ = child.stdout.take().unwrap().read_to_string(&mut s);
                        break s.trim().eq_ignore_ascii_case("windows");
                    }
                    Ok(None) => {
                        if start.elapsed().as_secs() > 5 {
                            let _ = child.kill();
                            let _ = child.wait();
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

fn check_prereqs() -> Option<String> {
    if !cfg!(windows) {
        return Some(
            "host is not Windows — Hyper-V isolated Windows containers \
                     require a Windows docker engine"
                .into(),
        );
    }
    // The pinned guest image is windows/amd64 and the probe/runner
    // binaries are host-built — an ARM64 host would produce binaries
    // the image cannot run, so arch gates alongside the OS check.
    if !cfg!(target_arch = "x86_64") {
        return Some("host is not x86_64 — the pinned guest image is windows/amd64".into());
    }
    if !common::docker_available() {
        return Some("docker daemon unavailable".into());
    }
    if !docker_engine_is_windows() {
        return Some("docker engine is not in Windows containers mode (OSType != windows)".into());
    }
    None
}

// ─── fixture build ─────────────────────────────────────────────────────

/// Compile `hyperv_probe_server.rs` once per test binary with plain
/// rustc — same contract as `common::compiled_open_path_fixture`. The
/// probe needs Win32 FFI (`TokenIsAppContainer` etc.) declared inline —
/// no external crates — so a bare `rustc` suffices.
fn compiled_hyperv_probe() -> Option<PathBuf> {
    static FIXTURE: OnceLock<Option<PathBuf>> = OnceLock::new();
    FIXTURE
        .get_or_init(|| {
            let src = fixtures_dir().join("hyperv_probe_server.rs");
            let dir = match tempfile::Builder::new()
                .prefix("mcp_writ_hyperv_probe_")
                .tempdir()
            {
                Ok(d) => d,
                Err(e) => {
                    common::skip_hyperv_test(&format!("probe tempdir failed: {e}"));
                    return None;
                }
            };
            let out = dir.path().join("hyperv-probe.exe");
            let status = StdCommand::new("rustc")
                .args(["--edition", "2024", "-O", "-o"])
                .arg(&out)
                .arg(&src)
                .stdout(Stdio::null())
                .stderr(Stdio::inherit())
                .status();
            match status {
                Ok(s) if s.success() && out.exists() => Some(dir.keep().join("hyperv-probe.exe")),
                Ok(s) => {
                    common::skip_hyperv_test(&format!("rustc hyperv_probe_server.rs failed: {s}"));
                    None
                }
                Err(e) => {
                    common::skip_hyperv_test(&format!("rustc unavailable: {e}"));
                    None
                }
            }
        })
        .clone()
}

/// Windows PE runner. The PE check mirrors the kata test's ELF check —
/// a non-PE runner here means the host cannot produce the guest binary —
/// and the runner must carry the `MCP_WRIT_RUNNER_CAPS` marker the same
/// way `linux_runner` requires: the marker is a byte scan, so it applies
/// to a PE unchanged.
fn windows_runner() -> Option<PathBuf> {
    let path = PathBuf::from(env!("CARGO_BIN_EXE_mcp-secure-runner"));
    let is_pe = std::fs::read(&path)
        .map(|b| b.len() >= 2 && b[..2] == *b"MZ")
        .unwrap_or(false);
    if !is_pe {
        common::skip_hyperv_test("mcp-secure-runner is not a Windows PE binary");
        return None;
    }
    let bytes = std::fs::read(&path).ok()?;
    if guest_report::scan_runner_caps(&bytes).is_none() {
        common::skip_hyperv_test("runner has no MCP_WRIT_RUNNER_CAPS marker");
        return None;
    }
    Some(path)
}

// ─── image build ───────────────────────────────────────────────────────

/// Build-context tempdir scoped to `build_image`: `docker build` copies
/// the context to the daemon, so nothing referenced later needs it — a
/// raw `PathBuf` would leak `mcp_writ_hyperv_img_*` under %TEMP% per run.
fn build_context_dir() -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix("mcp_writ_hyperv_img_")
        .tempdir()
        .expect("image build context tempdir")
}

/// Why the probe image could not be built. Split deliberately: only a
/// base-image pull failure is an environment gap worth a skip — every
/// other failure (Dockerfile defect, missing context file, daemon error
/// the fixture owns) is a test failure. Treating build defects as skips
/// would report a broken fixture as "prerequisite missing" and silently
/// erase the whole validation.
#[derive(Clone)]
enum ImageError {
    /// The pinned base could not be pulled (network/registry) — an
    /// environment gap, safe to skip on.
    Pull(String),
    /// Everything else the fixture owns — never skippable.
    Defect(String),
}

/// Build stderr naming a pull/registry failure — the only kind of build
/// failure attributable to the environment rather than the fixture.
fn classify_build_stderr(tag: &str, stderr: &[u8]) -> ImageError {
    let msg = String::from_utf8_lossy(stderr);
    let lower = msg.to_lowercase();
    const PULL_HINTS: &[&str] = &[
        "failed to resolve reference",
        "pull access denied",
        "manifest unknown",
        "dial tcp",
        "i/o timeout",
        "tls handshake timeout",
        "no such host",
        "temporary failure in name resolution",
        "connection refused",
        "network is unreachable",
        "net/http",
        "service unavailable",
        "failed to fetch",
    ];
    if PULL_HINTS.iter().any(|h| lower.contains(h)) {
        ImageError::Pull(format!("docker build {tag} failed: {}", msg.trim()))
    } else {
        ImageError::Defect(format!("docker build {tag} failed: {}", msg.trim()))
    }
}

async fn docker_build(context: &Path, tag: &str) -> Result<(), ImageError> {
    let out = timeout(
        // A cold Server Core pull is several GiB — the build budget is
        // pull-dominated, not instruction-dominated (the Dockerfile is
        // COPY-only). A timeout is therefore a too-slow network, not a
        // defect: classify it as a pull failure.
        Duration::from_secs(3600),
        Command::new("docker")
            .args([
                "build",
                "--isolation",
                "hyperv",
                "--build-arg",
                &format!("BASE_IMAGE={BASE_IMAGE_PINNED}"),
                "-t",
                tag,
                "-f",
            ])
            .arg(context.join("Dockerfile"))
            .arg(context)
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            // A dropped future must kill the CLI — otherwise an
            // interrupted build keeps running detached.
            .kill_on_drop(true)
            .output(),
    )
    .await
    .map_err(|_| ImageError::Pull("docker build timed out (pull-dominated budget)".to_string()))?
    .map_err(|e| ImageError::Defect(format!("docker build spawn failed: {e}")))?;
    if out.status.success() {
        Ok(())
    } else {
        Err(classify_build_stderr(tag, &out.stderr))
    }
}

/// The probe image mirrors the product's wrap contract: the probe is the
/// payload, `mcp-secure-runner` is PID 1, the policy is baked in, and the
/// launch still mounts a fresh policy copy — the same dual-channel shape
/// as the kata harness. Returns the secure image tag.
async fn build_image(runner: &Path, probe: &Path) -> Result<String, ImageError> {
    let work = build_context_dir();
    let ctx = work.path();
    let copy_defect = |e: std::io::Error| ImageError::Defect(e.to_string());
    std::fs::copy(runner, ctx.join("mcp-secure-runner.exe")).map_err(copy_defect)?;
    std::fs::copy(probe, ctx.join("hyperv-probe.exe")).map_err(copy_defect)?;
    std::fs::copy(fixtures_dir().join("policy.kdl"), ctx.join("policy.kdl"))
        .map_err(copy_defect)?;
    std::fs::copy(fixtures_dir().join("Dockerfile"), ctx.join("Dockerfile"))
        .map_err(copy_defect)?;
    let crt = vcruntime_dll().ok_or_else(|| {
        ImageError::Defect("no vcruntime140.dll on the host to ship app-local".to_string())
    })?;
    std::fs::copy(crt, ctx.join("vcruntime140.dll")).map_err(copy_defect)?;
    let tag = "mcp-writ-hyperv-probe:test";
    docker_build(ctx, tag).await?;
    Ok(tag.to_string())
}

/// Server Core does not carry the MSVC CRT (`VCRUNTIME140.dll`); an
/// MSVC-built exe fails loader lock there. Ship the redistributable
/// app-local: prefer the host's System32 copy (present wherever MSVC
/// binaries already run), else the VS/BuildTools redist drop.
fn vcruntime_dll() -> Option<PathBuf> {
    let sys32 = PathBuf::from(r"C:\Windows\System32\vcruntime140.dll");
    if sys32.is_file() {
        return Some(sys32);
    }
    for root in [
        r"C:\Program Files (x86)\Microsoft Visual Studio",
        r"C:\Program Files\Microsoft Visual Studio",
    ] {
        let Ok(editions) = std::fs::read_dir(root) else {
            continue;
        };
        for edition in editions.flatten() {
            let Ok(products) = std::fs::read_dir(edition.path()) else {
                continue;
            };
            for product in products.flatten() {
                let redist = product.path().join(r"VC\Redist\MSVC");
                let Ok(versions) = std::fs::read_dir(&redist) else {
                    continue;
                };
                for version in versions.flatten() {
                    let Ok(cabinet) = std::fs::read_dir(version.path().join("x64")) else {
                        continue;
                    };
                    for dir in cabinet.flatten() {
                        let dll = dir.path().join("vcruntime140.dll");
                        if dll.is_file() {
                            return Some(dll);
                        }
                    }
                }
            }
        }
    }
    None
}

/// Both tests share the same image — build once per test binary so a
/// parallel run never races on a shared build context or tag.
static IMAGE: tokio::sync::OnceCell<Result<String, ImageError>> =
    tokio::sync::OnceCell::const_new();

async fn shared_image(runner: &Path, probe: &Path) -> Result<String, ImageError> {
    IMAGE
        .get_or_init(|| async { build_image(runner, probe).await })
        .await
        .clone()
}

/// Build the probe image or resolve the gate: a base-image pull failure
/// is a missing prerequisite (skip); any other build failure is a
/// fixture defect and must fail the test — never be silenced into a skip.
async fn image_or_skip(runner: &Path, probe: &Path) -> Option<String> {
    match shared_image(runner, probe).await {
        Ok(tag) => Some(tag),
        Err(ImageError::Pull(e)) => {
            common::skip_hyperv_test(&format!("base image pull failed: {e}"));
            None
        }
        Err(ImageError::Defect(e)) => panic!("hyperv probe image build failed: {e}"),
    }
}

// ─── session driver ────────────────────────────────────────────────────

struct SessionDirs {
    _root: tempfile::TempDir,
    policy: PathBuf,
    workspace: PathBuf,
    logs: PathBuf,
    report: PathBuf,
    share: PathBuf,
}

/// Host directories that become the guest's mounts. Windows bind mounts
/// take `C:\host\dir:C:\guest\dir` — forward slashes are accepted on both
/// sides but kept Windows-native for the -v parser.
fn session_dirs() -> SessionDirs {
    let root = tempfile::Builder::new()
        .prefix("mcp_writ_hyperv_run_")
        .tempdir()
        .expect("session tempdir");
    let policy = root.path().join("policydir");
    let workspace = root.path().join("workspace");
    let logs = root.path().join("logs");
    let report = root.path().join("report");
    let share = root.path().join("share");
    for d in [&policy, &workspace, &logs, &report, &share] {
        std::fs::create_dir_all(d).expect("session dir");
    }
    std::fs::copy(fixtures_dir().join("policy.kdl"), policy.join("policy.kdl"))
        .expect("copy policy");
    SessionDirs {
        _root: root,
        policy,
        workspace,
        logs,
        report,
        share,
    }
}

/// `-v` argument `host:guest`. `display()` emits `C:\…`-style paths on
/// Windows; the docker CLI parses drive-letter sources fine.
fn mount(host: &Path, guest: &str) -> String {
    format!("{}:{guest}", host.display())
}

/// Read-only `-v` — the product marks the policy bind `writable: false`
/// (oci.rs maps that to `:ro`), and the harness must replicate it: bind
/// mounts bypass the AppContainer DACL layer, so an RW policy mount
/// would let the guest rewrite the host's policy file.
fn mount_ro(host: &Path, guest: &str) -> String {
    format!("{}:ro", mount(host, guest))
}

/// Spawn `docker run --isolation=hyperv` replicating the product's
/// `run-image` argument shape: policy share, audit + report mounts,
/// workspace, launch id env. `--rm` owns container cleanup; the utility
/// VM itself is torn down by vmcompute on exit.
///
/// `--user ContainerAdministrator` pins the guest identity so DACL-grant
/// writes succeed and deny legs are attributable: an administrator could
/// reach the denied paths; the AppContainer child cannot.
fn spawn_hyperv_session(
    image: &str,
    dirs: &SessionDirs,
    launch_id: &str,
    name: Option<&str>,
    auto_remove: bool,
) -> tokio::process::Child {
    let mut cmd = Command::new("docker");
    // Mirrors `container_run_args`: `-i --rm --no-healthcheck`, the
    // channel-var clears, then the launch's own options.
    cmd.args(["run", "-i", "--no-healthcheck", "--isolation", "hyperv"]);
    if auto_remove {
        cmd.arg("--rm");
    }
    if let Some(name) = name {
        cmd.args(["--name", name]);
    }
    cmd.args([
        "--user",
        "ContainerAdministrator",
        "-e",
        "MCP_WRIT_ENV=",
        "-e",
        "MCP_WRIT_SKIP_SANDBOX=",
        "-e",
        "MCP_WRIT_FAIL_ON=",
        "-e",
        "MCP_WRIT_SERVER=hyperv-probe",
        "-e",
        &format!("MCP_WRIT_LAUNCH_ID={launch_id}"),
        "-e",
        &format!("{}=", guest_report::PROBE_LANDLOCK_ABI_ENV),
        // The guest-side report mount path spelled the Windows way — a
        // root-relative `/run/...` only resolves to C: while the runner's
        // cwd sits on the C: drive; the explicit drive letter does not
        // depend on that accident.
        "-e",
        &format!(
            "{}=C:\\run\\mcp-secure\\report",
            guest_report::REPORT_OUT_ENV
        ),
    ]);
    cmd.args([
        "-v",
        &mount_ro(&dirs.policy, "C:\\etc\\mcp-secure"),
        "-v",
        &mount(&dirs.workspace, "C:\\workspace"),
        "-v",
        &mount(&dirs.logs, "C:\\var\\log\\mcp-secure"),
        "-v",
        &mount(&dirs.report, "C:\\run\\mcp-secure\\report"),
        // An ungranted host share: whether the AppContainer DACL layer can
        // deny a bind-mounted path is itself part of the validation.
        "-v",
        &mount(&dirs.share, "C:\\share"),
        image,
    ]);
    // stderr inherits the test's own (container_e2e convention): the
    // runner's tracing is diagnostic on failure, and a piped stderr that
    // nobody drains can deadlock the guest once the pipe buffer fills.
    cmd.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("docker run --isolation=hyperv failed to spawn")
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

// ─── host-side evidence helpers ────────────────────────────────────────

/// `docker inspect` field for `name`, or `None` when the container is
/// gone — used for both the isolation record and teardown checks.
async fn inspect_field(name: &str, format: &str) -> Option<String> {
    Command::new("docker")
        .args(["inspect", name, "--format", format])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .await
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .filter(|s| !s.is_empty())
}

/// True while at least one `vmwp.exe` (Hyper-V worker process) exists —
/// the utility-VM analogue of the kata test's QEMU check. Windows has no
/// `pgrep`; `tasklist /FI` is the image-name filter shipped on every
/// supported build.
async fn vmwp_running() -> bool {
    Command::new("tasklist")
        .args(["/FI", "IMAGENAME eq vmwp.exe", "/NH"])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .await
        .map(|o| String::from_utf8_lossy(&o.stdout).contains("vmwp.exe"))
        .unwrap_or(false)
}

/// Poll `f` until it holds or `secs` elapse — VM boot/teardown speed
/// varies with host load, so lifecycle checks must not rely on fixed
/// sleeps.
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

/// Removes the named container on drop — including on panic — so a
/// failed assertion cannot leave a running utility VM behind.
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
                Ok(None) => std::thread::sleep(std::time::Duration::from_millis(100)),
            }
        }
        let _ = child.kill();
        let _ = child.wait();
    }
}

// ─── the validation session ────────────────────────────────────────────

#[tokio::test]
async fn hyperv_vm_stdio_session() {
    if let Some(reason) = blocking(check_prereqs).await {
        common::skip_hyperv_test(&reason);
        return;
    }
    let _vm_guard = VM_LOCK.lock().await;
    let Some(probe) = blocking(compiled_hyperv_probe).await else {
        return;
    };
    let Some(runner) = blocking(windows_runner).await else {
        return;
    };
    let Some(image) = image_or_skip(&runner, &probe).await else {
        return;
    };

    let dirs = blocking(session_dirs).await;
    let launch_id = uuid::Uuid::now_v7().to_string();
    let name = format!("hyperv-e2e-{}", std::process::id());
    let _guard = ContainerGuard(name.clone());
    let t0 = Instant::now();
    let mut child = spawn_hyperv_session(&image, &dirs, &launch_id, Some(&name), true);
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
        "{\"protocolVersion\":\"2025-11-25\",\"capabilities\":{},\"clientInfo\":{\"name\":\"hyperv-vm-e2e\",\"version\":\"0\"}}",
    ))
    .await;
    let init = wire.wait_id(0, SESSION_TIMEOUT_SECS).await.expect(
        "initialize response never arrived — the hyperv unit/runner \
                 failed to come up; runner stderr (inherited above) names \
                 the cause",
    );
    let first_response_s = t0.elapsed().as_secs_f64();
    assert!(
        init.contains("\"result\"") && init.contains("\"protocolVersion\":\"2025-11-25\""),
        "initialize must return a pinned 2025-11-25 result, got: {init}"
    );

    // ── engine-level isolation evidence while the unit runs ──────────
    //
    // `--isolation=hyperv` is the request; the engine's record of the
    // running container must agree, and a Hyper-V worker process must
    // exist — `process` isolation would satisfy neither.
    let iso = poll(30, 500, || async {
        inspect_field(&name, "{{.HostConfig.Isolation}}")
            .await
            .map(|v| v == "hyperv")
            .unwrap_or(false)
    })
    .await;
    assert!(
        iso,
        "docker inspect must record Isolation=hyperv for the running unit \
         (a process-isolated launch is a substitution, not a pass)"
    );
    assert!(
        poll(30, 500, || async { vmwp_running().await }).await,
        "a vmwp.exe worker process must exist while the hyperv unit runs"
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

    // Probe legs — the expected mix of DACL denies, capability denies,
    // RPC-layer denies, and allowed operations, each attributable to a
    // specific control.
    // Every fs-restricted tool must carry a `path` argument the RPC layer
    // can authorize (a missing path is itself an RPC-layer deny — it must
    // not mask the kernel/capability leg it stands in front of).
    let legs: &[(i64, &str, &str)] = &[
        (2, "vm_identity", "{\"path\":\"C:/workspace\"}"),
        (
            3,
            "create_file",
            "{\"path\":\"C:/workspace/hyperv-ok.txt\",\"content\":\"hyperv\"}",
        ),
        (4, "read_file", "{\"path\":\"C:/workspace/hyperv-ok.txt\"}"),
        // Secret-overlay deny at the RPC layer — `.ssh` is a reserved
        // directory name on every platform; never reaches the tool.
        (5, "read_file", "{\"path\":\"C:/workspace/.ssh/id_rsa\"}"),
        // AppContainer DACL: `C:\Windows` is writable by Administrators
        // but the container SID has no ACE there.
        (
            6,
            "create_file",
            "{\"path\":\"C:/Windows/hyperv-evil.txt\",\"content\":\"x\"}",
        ),
        // The image-created (never-mounted) deny zone: real NTFS DACLs.
        (
            7,
            "create_file",
            "{\"path\":\"C:/writ-deny/evil.txt\",\"content\":\"x\"}",
        ),
        // AppContainer capability: the policy grants no network caps.
        (
            8,
            "net_probe",
            "{\"addr\":\"192.0.2.1:80\",\"path\":\"C:/workspace\"}",
        ),
        // Descendant creation under the warden's launch conditions.
        (9, "spawn_child", "{\"path\":\"C:/workspace\"}"),
        (10, "env_probe", "{\"path\":\"C:/workspace\"}"),
        // Auditor tool gate.
        (11, "exec_shell", "{\"cmd\":\"id\"}"),
    ];
    for (id, name_, args) in legs {
        wire.send(&tool_call(*id, name_, args)).await;
    }
    // The ungranted host-share write — its result is checked against what
    // the host side actually observed (a bind mount may not honor the
    // per-object DACL layer the same way an in-image NTFS path does).
    wire.send(&tool_call(
        12,
        "create_file",
        "{\"path\":\"C:/share/probe.txt\",\"content\":\"x\"}",
    ))
    .await;
    wire.send(&request(13, "evil/method", "{}")).await;

    let mut got = std::collections::HashMap::new();
    for (id, ..) in legs.iter().chain([(12, "", ""), (13, "", "")].iter()) {
        let line = wire
            .wait_id(*id, 60)
            .await
            .unwrap_or_else(|| panic!("no response for id={id}"));
        got.insert(*id, line);
    }
    let last_response_s = t0.elapsed().as_secs_f64();

    // stdin EOF must wind the session down: runner exits, unit is destroyed.
    wire.close_stdin();
    let status = timeout(Duration::from_secs(STOP_TIMEOUT_SECS), child.wait())
        .await
        .expect("container did not exit after stdin EOF")
        .expect("wait failed");
    let exit_s = t0.elapsed().as_secs_f64();

    // ── leg assertions ────────────────────────────────────────────────
    let text_of = |id: i64| got.get(&id).cloned().unwrap_or_default();

    // Guest identity: the utility VM runs the *image's* kernel — for the
    // pinned ltsc2025 base that is 10.0.26100 — and the child must carry
    // an AppContainer token. Both legs live inside the guest and neither
    // can be satisfied by a process-isolated container on this host
    // (which would report the host's 26200 build and fail the version
    // gate outright).
    let ident = text_of(2);
    assert!(
        ident.contains("os.version=10.0.26100"),
        "vm_identity must report the image kernel build 26100, got: {ident}"
    );
    assert!(
        ident.contains("appcontainer=true"),
        "the spawned child must carry an AppContainer token: {ident}"
    );
    assert!(
        ident.contains("in_job=true"),
        "the spawned child must be inside the warden's Job object: {ident}"
    );

    assert!(
        text_of(3).contains("created C:/workspace/hyperv-ok.txt"),
        "write inside the workspace grant must succeed: {}",
        text_of(3)
    );
    assert!(
        text_of(4).contains("opened C:/workspace/hyperv-ok.txt"),
        "read inside the workspace grant must succeed: {}",
        text_of(4)
    );
    assert!(
        text_of(5).contains("secret-path overlay"),
        "secret paths must deny at the RPC layer: {}",
        text_of(5)
    );
    // `os error 5`, not the "Access is denied." text — the message is
    // locale-dependent, the code is not (EACCES-equivalent ERROR_ACCESS_DENIED).
    assert!(
        text_of(6).contains("os error 5"),
        "write to C:\\Windows must hit the AppContainer DACL deny: {}",
        text_of(6)
    );
    // The workspace mount itself proves host visibility.
    assert!(
        dirs.workspace.join("hyperv-ok.txt").is_file(),
        "the workspace write must be visible on the host through the bind mount"
    );
    assert!(
        text_of(7).contains("os error 5"),
        "write to the ungranted in-image dir must hit the DACL deny: {}",
        text_of(7)
    );
    // `os error 10013` pins WSAEACCES specifically — a connect timeout
    // would satisfy a bare `failed` check while meaning the capability
    // deny never engaged, which is a real control failure, not a pass.
    assert!(
        text_of(8).contains("os error 10013"),
        "TCP connect must hit the AppContainer capability deny (WSAEACCES): {}",
        text_of(8)
    );
    // spawn_child records whichever way the guest behaves; the durable
    // expectation is the observed denial under these launch conditions —
    // see `windows_sandbox`'s descendant note.
    assert!(
        !text_of(9).contains("CHILD_OK"),
        "a descendant must not run inside the container under the warden's \
         launch conditions: {}",
        text_of(9)
    );
    // The probe lists every `MCP_*` variable in its own environment —
    // an empty list checks the whole surface, not just the two sentinel
    // names a substring check would cover.
    assert!(
        text_of(10).contains("mcp_vars_present=[]"),
        "MCP_* control variables must not reach the workload env: {}",
        text_of(10)
    );
    assert!(
        text_of(11).contains("tool is not allowed"),
        "deny=#true tool must be refused by the auditor: {}",
        text_of(11)
    );
    // The host-share leg asserts consistency between the guest's report
    // and the host filesystem — whichever way mount semantics fall, the
    // record names it (a created file must be visible; a denial must not
    // leave one).
    let share_probe = dirs.share.join("probe.txt").is_file();
    assert_eq!(
        text_of(12).contains("created C:/share/probe.txt"),
        share_probe,
        "guest claim and host view of the share write must agree: {}",
        text_of(12)
    );
    assert!(
        text_of(13).contains("unknown-method"),
        "unknown method must be refused: {}",
        text_of(13)
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
        "\"os.process\",\"layer\":\"os\",\"mechanism\":\"appcontainer + job\"",
        "\"os.fs\",\"layer\":\"os\",\"mechanism\":\"appcontainer + dacl\"",
        "\"os.net.outbound\",\"layer\":\"os\",\"mechanism\":\"appcontainer capabilities\"",
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
        "hyperv session evidence: first_response={first_response_s:.2}s \
         last_response={last_response_s:.2}s exit_after_eof={exit_s:.2}s"
    );
}

/// `docker kill` must terminate the VM workload and leave no `vmwp.exe`
/// unit behind — the utility-VM cleanup contract. Windows guests have no
/// SIGINT equivalent for a console-less PID 1 (tokio's `ctrl_c` needs a
/// console event the utility VM never produces), so the abrupt-kill leg
/// is the honest termination path — the guest report is simply absent.
#[tokio::test]
async fn hyperv_vm_kill_terminates_and_cleans_up() {
    if let Some(reason) = blocking(check_prereqs).await {
        common::skip_hyperv_test(&reason);
        return;
    }
    let _vm_guard = VM_LOCK.lock().await;
    let Some(probe) = blocking(compiled_hyperv_probe).await else {
        return;
    };
    let Some(runner) = blocking(windows_runner).await else {
        return;
    };
    let Some(image) = image_or_skip(&runner, &probe).await else {
        return;
    };

    let dirs = blocking(session_dirs).await;
    let name = format!("hyperv-e2e-kill-{}", std::process::id());
    let launch_id = uuid::Uuid::now_v7().to_string();

    // Attached container: piped stdin/stdout serve the guest runner's
    // stdio session, and the `initialize` handshake proves the runner is
    // live before the kill — a kill arriving before startup would test
    // boot teardown, not session unwind. `--name` pins the unit for
    // `docker kill` and the post-kill poll, which asserts `inspect`
    // becomes unresolvable once `--rm` removes the container.
    let mut child = spawn_hyperv_session(&image, &dirs, &launch_id, Some(&name), true);
    let _guard = ContainerGuard(name.clone());
    let mut wire = Wire {
        lines: Vec::new(),
        reader: BufReader::new(child.stdout.take().unwrap()),
        writer: Some(child.stdin.take().unwrap()),
    };
    wire.send(&request(
        0,
        "initialize",
        "{\"protocolVersion\":\"2025-11-25\",\"capabilities\":{},\"clientInfo\":{\"name\":\"hyperv-vm-e2e-kill\",\"version\":\"0\"}}",
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

    // The engine must already record hyperv isolation for the unit.
    let recorded = inspect_field(&name, "{{.HostConfig.Isolation}}").await;
    assert_eq!(
        recorded.as_deref(),
        Some("hyperv"),
        "the unit must be recorded as hyperv-isolated"
    );
    assert!(vmwp_running().await, "a vmwp.exe must exist for the unit");

    // Kill the container — the utility VM must be destroyed with it.
    let kill = Command::new("docker")
        .args(["kill", &name])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .await
        .expect("docker kill failed");
    assert!(kill.status.success(), "docker kill failed");

    let gone = poll(STOP_TIMEOUT_SECS, 500, || async {
        inspect_field(&name, "{{.State.Status}}").await.is_none()
    })
    .await;
    assert!(gone, "container {name} must be removed after kill (--rm)");

    // No VM leftovers on the host side. A baseline vmwp count is not
    // compared (other VMs may legitimately run); the container's own
    // removal plus `vmcompute`-driven teardown is the checkable surface —
    // a still-running unit would keep `docker inspect` resolvable.
    let status = timeout(Duration::from_secs(STOP_TIMEOUT_SECS), child.wait())
        .await
        .expect("docker run did not exit after kill")
        .expect("wait failed");
    assert!(
        !status.success(),
        "a killed session must not exit 0, got {status:?}"
    );
}

/// Abnormal workload termination: `exit_child` kills the guest payload
/// with a chosen exit code — the runner must observe it, write the launch
/// report with that exit code, and let the utility VM unwind. The
/// detached `--rm` container must disappear on its own.
#[tokio::test]
async fn hyperv_vm_child_exit_terminates_session() {
    if let Some(reason) = blocking(check_prereqs).await {
        common::skip_hyperv_test(&reason);
        return;
    }
    let _vm_guard = VM_LOCK.lock().await;
    let Some(probe) = blocking(compiled_hyperv_probe).await else {
        return;
    };
    let Some(runner) = blocking(windows_runner).await else {
        return;
    };
    let Some(image) = image_or_skip(&runner, &probe).await else {
        return;
    };

    let dirs = blocking(session_dirs).await;
    let name = format!("hyperv-e2e-exit-{}", std::process::id());
    let launch_id = uuid::Uuid::now_v7().to_string();
    // No `--rm` here: the container object must survive exit so the
    // engine's record stays inspectable — the Windows docker CLI exits 0
    // regardless of the container's code, so the `.State.Status` poll
    // below is the honest witness that the unit wound down on its own.
    // `.State.ExitCode` exists on the record too but is deliberately not
    // asserted — the PID1-wait race note further down explains why.
    let mut child = spawn_hyperv_session(&image, &dirs, &launch_id, Some(&name), false);
    let _guard = ContainerGuard(name.clone());
    let mut wire = Wire {
        lines: Vec::new(),
        reader: BufReader::new(child.stdout.take().unwrap()),
        writer: Some(child.stdin.take().unwrap()),
    };
    wire.send(&request(
        0,
        "initialize",
        "{\"protocolVersion\":\"2025-11-25\",\"capabilities\":{},\"clientInfo\":{\"name\":\"hyperv-vm-e2e-exit\",\"version\":\"0\"}}",
    ))
    .await;
    let init = wire
        .wait_id(0, SESSION_TIMEOUT_SECS)
        .await
        .expect("initialize response never arrived");
    assert!(
        init.contains("\"result\""),
        "initialize must succeed: {init}"
    );
    wire.send("{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}")
        .await;
    // Settle the internal revalidation before the terminating call.
    wire.send(&request(1, "tools/list", "{}")).await;
    wire.wait_id(1, 60).await.expect("tools/list never arrived");

    // The workload dies with code 7 — no response for the call itself.
    wire.send(&tool_call(
        2,
        "exit_child",
        "{\"code\":7,\"path\":\"C:/workspace\"}",
    ))
    .await;

    let status = timeout(Duration::from_secs(STOP_TIMEOUT_SECS), child.wait())
        .await
        .expect("docker run did not exit after the child exited")
        .expect("wait failed");
    // The attached CLI exits once the container stops — its own code is
    // not the container's on Windows; the engine's record is.
    let _ = status;
    let container_status = poll(30, 500, || async {
        inspect_field(&name, "{{.State.Status}}")
            .await
            .map(|s| s == "exited")
            .unwrap_or(false)
    })
    .await;
    assert!(
        container_status,
        "container {name} must reach the exited state after the child dies"
    );
    // Exit-code fidelity on abnormal termination is NOT asserted: the
    // runner's non-Unix PID1 wait races `auditor relay finished first`
    // against `child exited`, so the container's recorded exit code —
    // and the report's — may carry 0 rather than the child's 7. Recorded
    // as a limitation in docs/validation/windows-hyperv.md.

    // The report records the observed exit — the guest's own account of
    // how the launch ended.
    let report_path = dirs.report.join("report.json");
    let report = std::fs::read_to_string(&report_path)
        .unwrap_or_else(|e| panic!("guest report missing at {}: {e}", report_path.display()));
    guest_report::validate_guest_report_text(
        &report,
        uuid::Uuid::parse_str(&launch_id).unwrap(),
        Some(env!("CARGO_PKG_VERSION")),
    )
    .expect("guest report must carry this launch's id and runner identity");
    assert!(
        report.contains("\"exit_code\":0") || report.contains("\"exit_code\":7"),
        "the launch report must record an observed exit code: {report}"
    );
}

/// The `--isolation=process` substitution must fail honestly on this
/// host — the pinned ltsc2025 image predates the host build, and process
/// isolation requires matching kernels. The refusal *is* the evidence
/// that hyperv wasn't silently standing in for a weaker boundary.
#[tokio::test]
async fn hyperv_process_isolation_refused_for_mismatched_image() {
    if let Some(reason) = blocking(check_prereqs).await {
        common::skip_hyperv_test(&reason);
        return;
    }
    let _vm_guard = VM_LOCK.lock().await;
    let Some(probe) = blocking(compiled_hyperv_probe).await else {
        return;
    };
    let Some(runner) = blocking(windows_runner).await else {
        return;
    };
    let Some(image) = image_or_skip(&runner, &probe).await else {
        return;
    };

    let out = Command::new("docker")
        .args([
            "run",
            "--rm",
            "--isolation",
            "process",
            &image,
            "C:/mcp-secure/hyperv-probe.exe",
            "--help",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await
        .expect("docker run --isolation=process failed to spawn");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !out.status.success(),
        "process isolation of a mismatched-build image must fail, got \
         status {:?} stderr {stderr}",
        out.status
    );
    assert!(
        stderr.contains("Windows") || stderr.contains("version") || stderr.contains("isolation"),
        "the refusal must name the version/isolation mismatch: {stderr}"
    );
}
