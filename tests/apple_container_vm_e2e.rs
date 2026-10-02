//! Real-machine validation of the Apple `container` VM isolation path
//! (PR-18).
//!
//! Drives the same stdio MCP contract as `kata_vm_e2e.rs`, but the
//! workload runs inside an Apple `container` lightweight VM on macOS:
//! `container run` plus the runner/policy/mount contract of `run-image`.
//! Apple's substrate boots one Linux VM per container on a kata-derived
//! guest kernel, so the in-guest control evidence is the same
//! Landlock/seccomp/no_new_privs layer — while the host-side VM evidence
//! is Apple-specific (the `container-runtime-linux --uuid` per-unit
//! manager and a `Virtualization.framework` VM process).
//!
//! The base image is deliberately a **standard registry image** —
//! `gcr.io/distroless/static-debian12` pinned by index digest — not a
//! hand-assembled one: users run `run-image` against the distro image
//! of their choice, so this validation must not depend on a bespoke
//! image. distroless `static` is the smallest standard image that
//! matches the workload (no shell/libc/userspace beyond CA certs and
//! passwd — musl-static binaries need none of it). The runner and probe
//! enter the guest as read-only bind mounts, mirroring what the
//! product's wrap step produces (our binaries injected into a user
//! image); the policy likewise mounts read-only from the host.
//! `container build`/`image save`/`load` and ubuntu multi-arch pull
//! behaviour were exercised separately and are recorded in
//! `docs/validation/apple-container.md`.
//!
//! The guest-side contract fixtures are shared with PR-16:
//! `tests/fixtures/kata/kata_probe_server.rs` and `policy.kdl` — the VM
//! substrate under test changed, the workload contract did not.
//!
//! Prerequisites (any missing → skip, or fail with
//! `MCP_WRIT_REQUIRE_APPLE_TESTS=1`; see `docs/validation/apple-container.md`):
//!   - macOS on Apple silicon (arm64)
//!   - the official `container` CLI on PATH with `container system` running
//!   - network access for the distroless pulls (once per variant)
//!   - rustc + `aarch64-unknown-linux-musl` for the probe/runner, and
//!     `x86_64-unknown-linux-musl` for the rosetta-emulation leg
//!     (the cargo test binary itself is a macOS Mach-O, so guest
//!     binaries are always cross-compiled here)
//!
//! This test never substitutes the native macOS path: a host without a
//! running `container` system skips (or fails when required) — it does
//! not "pass" a weaker or different isolation path in its place.

mod common;

use std::path::{Path, PathBuf};
use std::process::{Command as StdCommand, Stdio};
use std::sync::OnceLock;
use std::time::Instant;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::Command;
use tokio::time::{Duration, timeout};

use mcp_writ::container::guest_report;
use mcp_writ::execution::{TargetArch, TargetOs};

/// An Apple container launch takes seconds, not milliseconds; the budget
/// covers VM boot on a loaded host without turning a hang into a pass.
const SESSION_TIMEOUT_SECS: u64 = 180;
const STOP_TIMEOUT_SECS: u64 = 60;

/// One Apple VM at a time — each is a full `Virtualization.framework`
/// guest (default 1 GiB).
static VM_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// distroless static-debian12 pinned by OCI index digest — the smallest
/// standard multi-arch base (no shell, no libc; ~0.7 MiB per variant
/// manifest). arm64 is the session leg; the amd64 variant drives the
/// rosetta-emulation leg.
const BASE_IMAGE: &str = "gcr.io/distroless/static-debian12@sha256:d75cdd72874d4790092fcb1b058493ecf6bb5bf2b2b897045b00ff01d91843f2";

/// The guest-side contract fixtures are shared with PR-16 (the probe and
/// policy exercise the *guest kernel's* control layer, which is
/// substrate-independent).
fn kata_fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/kata")
}

/// The linux-musl cross flags: rustc/cargo default to `cc`, which is
/// Apple clang + ld64 here — it cannot link Linux objects. The
/// toolchain's own `rust-lld` does, with no external cross toolchain.
const MUSL_RUSTFLAGS: &str = "-C linker=rust-lld -C linker-flavor=ld.lld";

// ─── prerequisites ─────────────────────────────────────────────────────

/// Run a blocking step (subprocess probe, fixture compile, dir setup)
/// off the async runtime — the same `spawn_blocking` convention as
/// `container_e2e.rs` / `kata_vm_e2e.rs`. A panic inside (e.g. a
/// `MCP_WRIT_REQUIRE_*` assertion in `skip_apple_test`) is re-raised on
/// the test task so required-test failures are never swallowed into a
/// skip.
async fn blocking<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> T {
    match tokio::task::spawn_blocking(f).await {
        Ok(v) => v,
        Err(e) => std::panic::resume_unwind(e.into_panic()),
    }
}

fn cli_available() -> bool {
    StdCommand::new("container")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn system_running() -> bool {
    StdCommand::new("container")
        .args(["system", "status"])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .map(|o| o.status.success() && String::from_utf8_lossy(&o.stdout).contains("running"))
        .unwrap_or(false)
}

fn check_prereqs() -> Option<String> {
    if TargetOs::host() != TargetOs::MacOs || TargetArch::host() != TargetArch::Aarch64 {
        return Some(format!(
            "apple container validation needs a macOS arm64 host — this is {}/{}",
            TargetOs::host().name(),
            TargetArch::host().name()
        ));
    }
    if !cli_available() {
        return Some("no `container` CLI on PATH".into());
    }
    if !system_running() {
        return Some("`container system` is not running (container system start)".into());
    }
    None
}

/// `container image pull --platform <p> <digest-pinned ref>`; `run` on a
/// never-pulled image would fetch every index variant, so pulls always
/// name the platform explicitly. Once per platform per test binary.
fn ensure_base_pulled(platform: &str) -> Option<()> {
    match platform {
        "linux/arm64" => {
            static DONE: OnceLock<Option<()>> = OnceLock::new();
            *DONE.get_or_init(|| pull_platform(platform))
        }
        _ => {
            static DONE: OnceLock<Option<()>> = OnceLock::new();
            *DONE.get_or_init(|| pull_platform(platform))
        }
    }
}

fn pull_platform(platform: &str) -> Option<()> {
    let out = match StdCommand::new("container")
        .args(["image", "pull", "--platform", platform])
        .arg(BASE_IMAGE)
        .output()
    {
        Ok(o) => o,
        Err(e) => {
            // A spawn failure is a missing-CLI prerequisite like the
            // gates above — skip, not panic.
            common::skip_apple_test(&format!("container image pull spawn failed: {e}"));
            return None;
        }
    };
    if out.status.success() {
        return Some(());
    }
    common::skip_apple_test(&format!(
        "container image pull --platform {platform} failed (network/registry?): {}",
        String::from_utf8_lossy(&out.stderr)
    ));
    None
}

// ─── fixture builds ────────────────────────────────────────────────────

/// e_machine values in the ELF header (LE at offset 18).
const EM_AARCH64: u16 = 0xB7;
const EM_X86_64: u16 = 0x3E;

/// ELF magic + class/data + machine check on a produced binary.
fn is_elf(path: &Path, machine: u16) -> bool {
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(_) => return false,
    };
    bytes.len() >= 20
        && bytes[0..4] == [0x7f, b'E', b'L', b'F']
        && bytes[4] == 2 // EI_CLASS = ELFCLASS64 — both musl targets are 64-bit
        && bytes[5] == 1 // EI_DATA = little-endian
        && u16::from_le_bytes([bytes[18], bytes[19]]) == machine
}

/// Compile the shared VM probe to a static musl ELF for `target`. The
/// artifact lives under `target/apple-e2e/` so `cargo clean` reaps it
/// with the rest of the build tree (the validation doc's teardown claim);
/// a scratch name + rename keeps a concurrent test binary building the
/// same probe from serving a torn ELF.
fn compile_probe(target: &str, machine: u16) -> Option<PathBuf> {
    let src = kata_fixtures_dir().join("kata_probe_server.rs");
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("target/apple-e2e");
    if let Err(e) = std::fs::create_dir_all(&dir) {
        common::skip_apple_test(&format!("probe artifact dir failed: {e}"));
        return None;
    }
    let out = dir.join(format!("kata-probe-{target}"));
    let tmp = dir.join(format!(".kata-probe-{target}-{}", std::process::id()));
    let status = StdCommand::new("rustc")
        .args(["--target", target, "-O", "-C"])
        .arg("linker=rust-lld")
        .args(["-C", "linker-flavor=ld.lld", "-C", "strip=symbols", "-o"])
        .arg(&tmp)
        .arg(&src)
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .status();
    match status {
        Ok(s) if s.success() && is_elf(&tmp, machine) => match std::fs::rename(&tmp, &out) {
            Ok(()) => Some(out),
            Err(e) => {
                let _ = std::fs::remove_file(&tmp);
                common::skip_apple_test(&format!("probe artifact rename failed: {e}"));
                None
            }
        },
        Ok(s) => {
            let _ = std::fs::remove_file(&tmp);
            common::skip_apple_test(&format!("rustc {target} kata_probe_server.rs failed: {s}"));
            None
        }
        Err(e) => {
            common::skip_apple_test(&format!("rustc unavailable: {e}"));
            None
        }
    }
}

fn compiled_vm_probe() -> Option<PathBuf> {
    static FIXTURE: OnceLock<Option<PathBuf>> = OnceLock::new();
    FIXTURE
        .get_or_init(|| compile_probe("aarch64-unknown-linux-musl", EM_AARCH64))
        .clone()
}

/// The amd64 probe build for the rosetta-emulation leg — a foreign-arch
/// static ELF the substrate runs translated.
fn compiled_vm_probe_x86_64() -> Option<PathBuf> {
    static FIXTURE: OnceLock<Option<PathBuf>> = OnceLock::new();
    FIXTURE
        .get_or_init(|| compile_probe("x86_64-unknown-linux-musl", EM_X86_64))
        .clone()
}

/// A Linux aarch64 `mcp-secure-runner`. The cargo test binary on this
/// host is a macOS Mach-O, so the guest runner is produced by an
/// explicit `aarch64-unknown-linux-musl` cargo build — musl links a
/// fully static binary that runs on the kata-derived guest kernel. The
/// release+strip build keeps the artifact small (~3 MiB vs ~79 MiB
/// debug). The build runs once per test binary; the produced ELF is
/// checked for arch and the `MCP_WRIT_RUNNER_CAPS` marker the image
/// records.
fn linux_runner() -> Option<PathBuf> {
    static RUNNER: OnceLock<Option<PathBuf>> = OnceLock::new();
    RUNNER
        .get_or_init(|| {
            let target_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("target");
            let out = target_dir
                .join("aarch64-unknown-linux-musl")
                .join("release")
                .join("mcp-secure-runner");
            let status = StdCommand::new("cargo")
                .args([
                    "build",
                    "--locked",
                    "--release",
                    "--target",
                    "aarch64-unknown-linux-musl",
                    "--bin",
                    "mcp-secure-runner",
                ])
                // Pin the output to the manifest's target dir so a
                // caller-set CARGO_TARGET_DIR cannot place the runner
                // where `is_elf` below does not look.
                .arg("--target-dir")
                .arg(&target_dir)
                // Deliberately *replaces* the caller's RUSTFLAGS: the
                // musl link only works through the toolchain's rust-lld,
                // and an arbitrary caller linker flag would win over
                // `-C linker=rust-lld`.
                .env("RUSTFLAGS", format!("{MUSL_RUSTFLAGS} -C strip=symbols"))
                .current_dir(env!("CARGO_MANIFEST_DIR"))
                .stdout(Stdio::null())
                .stderr(Stdio::inherit())
                .status();
            match status {
                Ok(s) if s.success() => {}
                Ok(s) => {
                    common::skip_apple_test(&format!(
                        "cargo build --target aarch64-unknown-linux-musl failed: {s}"
                    ));
                    return None;
                }
                Err(e) => {
                    common::skip_apple_test(&format!("cargo unavailable: {e}"));
                    return None;
                }
            }
            if !is_elf(&out, EM_AARCH64) {
                common::skip_apple_test("mcp-secure-runner is not an aarch64 ELF binary");
                return None;
            }
            let bytes = std::fs::read(&out).ok()?;
            if guest_report::scan_runner_caps(&bytes).is_none() {
                common::skip_apple_test("runner has no MCP_WRIT_RUNNER_CAPS marker");
                return None;
            }
            Some(out)
        })
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
        .prefix("mcp_writ_apple_run_")
        .tempdir()
        .expect("session tempdir");
    let workspace = root.path().join("workspace");
    let logs = root.path().join("logs");
    let report = root.path().join("report");
    for d in [&workspace, &logs, &report] {
        std::fs::create_dir_all(d).expect("session dir");
    }
    let policy = root.path().join("policy.kdl");
    std::fs::copy(kata_fixtures_dir().join("policy.kdl"), &policy).expect("copy policy");
    SessionDirs {
        _root: root,
        workspace,
        logs,
        report,
        policy,
    }
}

/// The `container run` argument list replicating the product's
/// `run-image` launch shape against an arbitrary user image: the runner
/// and probe mounted read-only at their in-image paths (what wrap
/// produces baked, injected here for the unmodified standard image),
/// `MCP_ORIG_*` env restored to the probe command, the read-only policy
/// share, audit + report mounts, workspace, and the launch-id env.
/// `--rm` owns cleanup — the Apple substrate destroys the VM when the
/// unit exits.
fn run_args(dirs: &SessionDirs, launch_id: &str, runner: &Path, probe: &Path) -> Vec<String> {
    vec![
        "run".into(),
        "-i".into(),
        "--rm".into(),
        "-v".into(),
        format!("{}:/usr/local/bin/mcp-secure-runner:ro", runner.display()),
        "-v".into(),
        format!("{}:/usr/local/bin/kata-probe:ro", probe.display()),
        "--entrypoint".into(),
        "/usr/local/bin/mcp-secure-runner".into(),
        "-e".into(),
        "MCP_ORIG_ENTRYPOINT=[\"/usr/local/bin/kata-probe\"]".into(),
        "-e".into(),
        "MCP_ORIG_CMD=".into(),
        "-e".into(),
        "MCP_WRIT_ENV=".into(),
        "-e".into(),
        "MCP_WRIT_SKIP_SANDBOX=".into(),
        "-e".into(),
        "MCP_WRIT_SERVER=kata-probe".into(),
        "-e".into(),
        format!("MCP_WRIT_LAUNCH_ID={launch_id}"),
        "-e".into(),
        format!(
            "{}={}",
            guest_report::REPORT_OUT_ENV,
            guest_report::GUEST_REPORT_MOUNT_PATH
        ),
        "-v".into(),
        format!("{}:/etc/mcp-secure/policy.kdl:ro", dirs.policy.display()),
        "-v".into(),
        format!("{}:/workspace", dirs.workspace.display()),
        "-v".into(),
        format!("{}:/var/log/mcp-secure", dirs.logs.display()),
        "-v".into(),
        format!(
            "{}:{}",
            dirs.report.display(),
            guest_report::GUEST_REPORT_MOUNT_PATH
        ),
    ]
}

/// The attached `-i` session command: stdin/stdout piped, stderr
/// inherited (container_e2e convention — the runner's tracing and the
/// CLI's progress lines are diagnostic on failure, and a piped stderr
/// nobody drains can deadlock the guest). stdin stays held by the
/// caller — `container run -d` does NOT hold the workload's stdin open
/// (unlike docker), so there is no detached way to keep this session
/// alive.
fn apple_session_command(
    dirs: &SessionDirs,
    launch_id: &str,
    runner: &Path,
    probe: &Path,
    name: &str,
) -> Command {
    let mut cmd = Command::new("container");
    cmd.args(run_args(dirs, launch_id, runner, probe));
    cmd.args(["--platform", "linux/arm64", "--name", name])
        .arg(BASE_IMAGE);
    cmd.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit());
    cmd
}

/// Spawn the session container (see [`apple_session_command`] for why
/// the caller must hold stdin).
fn spawn_apple_session(
    dirs: &SessionDirs,
    launch_id: &str,
    runner: &Path,
    probe: &Path,
    name: &str,
) -> tokio::process::Child {
    apple_session_command(dirs, launch_id, runner, probe, name)
        .spawn()
        .expect("container run failed to spawn — the system reports running but may be unusable")
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
                Ok(Err(_)) | Err(_) => return None,
            }
        }
    }

    /// Signal EOF on stdin while keeping `self` — and therefore the
    /// stdout reader — alive (see `kata_vm_e2e.rs`: dropping the reader
    /// before `wait()` could EPIPE the CLI into a nonzero exit).
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

// ─── host-side unit evidence ───────────────────────────────────────────

/// The per-unit host manager: each running Apple container has a
/// `container-runtime-linux start --root …/containers/<id> --uuid <id>`
/// process — the VM-side equivalent of the kata shim owning a sandbox.
async fn runtime_process_running(name: &str) -> bool {
    Command::new("pgrep")
        .args(["-f", &format!("container-runtime-linux.*--uuid {name}")])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .await
        .map(|o| !o.stdout.is_empty())
        .unwrap_or(false)
}

/// `container inspect`'s recorded state for `name` (`running`, `stopped`,
/// …). `None` when the unit no longer exists (`--rm` removed it) or the
/// inspect failed.
async fn container_state(name: &str) -> Option<String> {
    let out = Command::new("container")
        .args(["inspect", name])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .await
        .ok()?;
    if !out.status.success() {
        return None;
    }
    inspect_state(&String::from_utf8_lossy(&out.stdout))
}

/// `status.state` of the first record `container inspect` printed —
/// parsed structurally so pretty-print spacing, compact output, a
/// trailing comma on the value line, or a nested same-named key cannot
/// silently corrupt the extracted value.
fn inspect_state(stdout: &str) -> Option<String> {
    let json = nojson::RawJson::parse(stdout.trim()).ok()?;
    // inspect prints an array of unit records (a bare object in some CLI
    // versions) — take the first record either way.
    let record = match json.value().to_array() {
        Ok(mut arr) => arr.next()?,
        Err(_) => json.value(),
    };
    let state = record
        .to_member("status")
        .ok()
        .and_then(|m| m.optional())?
        .to_member("state")
        .ok()
        .and_then(|m| m.optional())?;
    Some(state.to_unquoted_string_str().ok()?.into_owned())
}

/// `container stats <name> --no-stream --format json` — one JSON record
/// per running container with per-guest memory accounting (the Apple
/// equivalent of `docker stats`, except it actually reports VM memory).
async fn stats_json_for(name: &str) -> Option<String> {
    let out = Command::new("container")
        .args(["stats", name, "--no-stream", "--format", "json"])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .await
        .ok()?;
    (out.status.success() && !out.stdout.is_empty())
        .then(|| String::from_utf8_lossy(&out.stdout).to_string())
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
        let Ok(mut child) = StdCommand::new("container")
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

// ─── the validation session ────────────────────────────────────────────

#[tokio::test]
async fn apple_vm_stdio_session() {
    if let Some(reason) = blocking(check_prereqs).await {
        common::skip_apple_test(&reason);
        return;
    }
    let _vm_guard = VM_LOCK.lock().await;
    if blocking(|| ensure_base_pulled("linux/arm64"))
        .await
        .is_none()
    {
        return;
    }
    let Some(probe) = blocking(compiled_vm_probe).await else {
        return;
    };
    let Some(runner) = blocking(linux_runner).await else {
        return;
    };

    let dirs = blocking(session_dirs).await;
    let launch_id = uuid::Uuid::now_v7().to_string();
    let name = format!("apple-e2e-stdio-{}", std::process::id());
    let t0 = Instant::now();
    let mut child = spawn_apple_session(&dirs, &launch_id, &runner, &probe, &name);
    let _guard = ContainerGuard(name.clone());
    let mut wire = Wire {
        lines: Vec::new(),
        reader: BufReader::new(child.stdout.take().unwrap()),
        writer: Some(child.stdin.take().unwrap()),
    };

    // initialize — the auditor pins the negotiated revision to exactly
    // 2025-11-25; anything else is a shape rejection. The response must
    // be awaited before more traffic: requests sent inside the same
    // burst race the init handshake and are denied `init-order`.
    wire.send(&request(
        0,
        "initialize",
        "{\"protocolVersion\":\"2025-11-25\",\"capabilities\":{},\"clientInfo\":{\"name\":\"apple-vm-e2e\",\"version\":\"0\"}}",
    ))
    .await;
    let init = wire.wait_id(0, SESSION_TIMEOUT_SECS).await.expect(
        "initialize response never arrived — the container system is \
                 running but the VM/runner failed to come up; runner \
                 stderr (inherited above) names the cause",
    );
    let first_response_s = t0.elapsed().as_secs_f64();
    assert!(
        init.contains("\"result\"") && init.contains("\"protocolVersion\":\"2025-11-25\""),
        "initialize must return a pinned 2025-11-25 result, got: {init}"
    );

    // Host-side unit evidence while the VM runs: the substrate records
    // this launch as a `container-runtime-linux` unit with state=running
    // and live per-guest stats.
    let state = poll_some(STOP_TIMEOUT_SECS, 500, || container_state(&name)).await;
    assert_eq!(
        state.as_deref(),
        Some("running"),
        "container must report state=running while the session is live"
    );
    assert!(
        runtime_process_running(&name).await,
        "a container-runtime-linux --uuid {name} process must exist while the unit runs"
    );
    let stats = stats_json_for(&name).await;
    assert!(
        stats
            .as_deref()
            // Whitespace-normalised: the CLI's pretty-print spacing is
            // not part of the stats contract.
            .is_some_and(|s| s
                .split_whitespace()
                .collect::<String>()
                .contains(&format!("\"id\":\"{name}\""))),
        "container stats must report this unit's resource usage, got: {stats:?}"
    );

    // Real-client ordering: initialized notification, then the internal
    // tools/list revalidation must settle before tool calls.
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
            "{\"path\":\"/workspace/apple-ok.txt\",\"content\":\"apple\"}",
        ),
        (4, "read_file", "{\"path\":\"/workspace/apple-ok.txt\"}"),
        // Secret-overlay deny at the RPC layer — never reaches the tool.
        (5, "read_file", "{\"path\":\"/etc/shadow\"}"),
        // Seccomp: chmod/fchmodat/fchmodat2 are outside the allowlist.
        (6, "chmod_666", "{\"path\":\"/workspace/apple-ok.txt\"}"),
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
        // Landlock: a file that exists (vminitd provides it) but is
        // covered by no grant — EACCES is the kernel deny. (/etc/passwd
        // would hit the auditor's secret overlay first; /etc/os-release
        // resolves through a symlink into the granted /usr tree — both
        // verified on this base, so neither proves the kernel deny.)
        (9, "read_file", "{\"path\":\"/etc/hostname\"}"),
        // Auditor tool gate.
        (10, "exec_shell", "{\"cmd\":\"id\"}"),
    ];
    for (id, name_, args) in legs {
        wire.send(&tool_call(*id, name_, args)).await;
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

    // Guest identity: an Apple `container` VM is Linux-on-virtio — the
    // kernel release differs from the (Darwin) host by construction,
    // virtiofs is how shares enter the guest, and the probe's own
    // /proc/self/status fields show the controls applied to it. The
    // kata-agent cmdline marker is absent here (vminitd init, not
    // kata-agent); identity rests on the host-side runtime unit plus
    // the guest's own mechanism state.
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
        ident.contains("virtiofs_in_filesystems=true"),
        "guest must expose virtiofs (the Apple share mechanism): {ident}"
    );

    assert!(
        text_of(3).contains("created /workspace/apple-ok.txt"),
        "write inside the workspace grant must succeed: {}",
        text_of(3)
    );
    assert!(
        text_of(4).contains("opened /workspace/apple-ok.txt"),
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
        "\"status\":\"exited\"",
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
        "apple session evidence: first_response={first_response_s:.2}s \
         last_response={last_response_s:.2}s exit_after_eof={exit_s:.2}s"
    );
}

/// `container kill -s SIGINT` must terminate the VM workload and leave
/// no runtime unit or VM behind — the Apple substrate's VM cleanup
/// contract. The runner forwards SIGINT to the child and reports
/// `interrupted`, identical to the docker/kata session end.
#[tokio::test]
async fn apple_vm_sigint_terminates_and_cleans_up() {
    if let Some(reason) = blocking(check_prereqs).await {
        common::skip_apple_test(&reason);
        return;
    }
    let _vm_guard = VM_LOCK.lock().await;
    if blocking(|| ensure_base_pulled("linux/arm64"))
        .await
        .is_none()
    {
        return;
    }
    let Some(probe) = blocking(compiled_vm_probe).await else {
        return;
    };
    let Some(runner) = blocking(linux_runner).await else {
        return;
    };

    let dirs = blocking(session_dirs).await;
    let name = format!("apple-e2e-sigint-{}", std::process::id());
    let launch_id = uuid::Uuid::now_v7().to_string();

    // Attached `-i` run with the test holding stdin open — `container
    // run -d` does not hold the workload's stdin (the runner sees EOF
    // and exits immediately), so the signal test must keep the pipe.
    let mut child = apple_session_command(&dirs, &launch_id, &runner, &probe, &name)
        .spawn()
        .expect("container run failed to spawn");
    let _guard = ContainerGuard(name.clone());
    // The Wire holds stdin open — EOF would end the session.
    let mut wire = Wire {
        lines: Vec::new(),
        reader: BufReader::new(child.stdout.take().unwrap()),
        writer: Some(child.stdin.take().unwrap()),
    };

    // Wait for the unit to be reported running with its manager process.
    let running = poll(STOP_TIMEOUT_SECS, 500, || async {
        container_state(&name).await.as_deref() == Some("running")
    })
    .await;
    assert!(running, "container must reach state=running");
    assert!(
        runtime_process_running(&name).await,
        "a container-runtime-linux --uuid {name} process must exist while the unit runs"
    );

    // Unit state does not prove the guest runner is serving — SIGINT
    // must land only after its signal path exists. An answered
    // `initialize` is the gate (same handshake as the stdio session).
    wire.send(&request(
        0,
        "initialize",
        "{\"protocolVersion\":\"2025-11-25\",\"capabilities\":{},\"clientInfo\":{\"name\":\"apple-vm-e2e\",\"version\":\"0\"}}",
    ))
    .await;
    let init = wire
        .wait_id(0, SESSION_TIMEOUT_SECS)
        .await
        .expect("initialize response never arrived — the runner was not serving yet");
    assert!(
        init.contains("\"protocolVersion\":\"2025-11-25\""),
        "initialize must return a pinned 2025-11-25 result, got: {init}"
    );

    // SIGINT the unit — the runner unwinds (report records `interrupted`),
    // the substrate destroys the VM.
    let kill = Command::new("container")
        .args(["kill", "-s", "SIGINT", &name])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .await
        .expect("container kill failed");
    assert!(kill.status.success(), "container kill -s SIGINT failed");

    let status = timeout(Duration::from_secs(STOP_TIMEOUT_SECS), child.wait())
        .await
        .expect("container CLI did not return after SIGINT")
        .expect("container CLI wait failed after SIGINT");

    // No VM leftovers: the unit must be gone (`--rm` removed it) or
    // stopped, and its manager process must be gone.
    let unit_gone = poll(STOP_TIMEOUT_SECS, 500, || async {
        container_state(&name).await.is_none()
    })
    .await;
    assert!(
        unit_gone,
        "--rm must remove the unit after SIGINT exit (state: {:?})",
        container_state(&name).await
    );
    let runtime_gone = poll(STOP_TIMEOUT_SECS, 500, || async {
        !runtime_process_running(&name).await
    })
    .await;
    assert!(
        runtime_gone,
        "container-runtime-linux for {name} must be gone after exit"
    );

    // The runner forwards SIGINT to the child and reports the
    // interrupted result over the dedicated report mount.
    let report_path = dirs.report.join("report.json");
    let report = std::fs::read_to_string(&report_path)
        .unwrap_or_else(|e| panic!("guest report missing at {}: {e}", report_path.display()));
    assert!(
        report.contains("\"status\":\"interrupted\""),
        "guest report must record the interrupted session end (cli exit {status:?}): {report}"
    );
}

/// Substrate platform refusals and non-refusals the product contract
/// must know: `--os windows` errors at the CLI (no Windows guest exists
/// on this substrate), while a foreign `--arch` does NOT refuse — the
/// image runs emulated via Rosetta inside the arm64 VM. The latter is
/// recorded because an `IsolationBackend` that pins guest-arch checks to
/// the substrate would silently pass a translated workload; the backend
/// must gate `guest_arch` itself.
#[tokio::test]
async fn apple_vm_platform_refusals() {
    if let Some(reason) = blocking(check_prereqs).await {
        common::skip_apple_test(&reason);
        return;
    }
    let _vm_guard = VM_LOCK.lock().await;
    if blocking(|| ensure_base_pulled("linux/arm64"))
        .await
        .is_none()
    {
        return;
    }

    let out = Command::new("container")
        .args(["run", "--rm", "--os", "windows", BASE_IMAGE, "true"])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output()
        .await
        .expect("container run --os windows spawn failed");
    assert!(
        !out.status.success(),
        "container run --os windows must be refused, got success"
    );
    // The refusal must be the documented platform refusal, not an
    // unrelated failure (e.g. a missing image or a CLI regression).
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("platform windows"),
        "container run --os windows must be refused as an unsupported platform, stderr: {stderr}"
    );

    // amd64 does not refuse — it emulates. Assert the inspect record
    // proves emulation (rosetta=true), not native execution. The amd64
    // probe is bind-mounted and set as the entrypoint; it blocks on
    // stdin, keeping the unit alive long enough to inspect.
    if blocking(|| ensure_base_pulled("linux/amd64"))
        .await
        .is_none()
    {
        return;
    }
    let Some(probe64) = blocking(compiled_vm_probe_x86_64).await else {
        return;
    };
    let name = format!("apple-e2e-amd64-{}", std::process::id());
    let _guard = ContainerGuard(name.clone());
    let mut child = Command::new("container")
        .args([
            "run",
            "-i",
            "--rm",
            "--name",
            &name,
            "--platform",
            "linux/amd64",
            "-v",
            &format!("{}:/usr/local/bin/kata-probe:ro", probe64.display()),
            "--entrypoint",
            "/usr/local/bin/kata-probe",
            BASE_IMAGE,
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("container run amd64 variant spawn failed");
    let stdin_held = child.stdin.take().unwrap();

    let inspect = poll_some(STOP_TIMEOUT_SECS, 500, || async {
        let out = Command::new("container")
            .args(["inspect", &name])
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .output()
            .await
            .ok()?;
        (out.status.success() && !out.stdout.is_empty())
            .then(|| String::from_utf8_lossy(&out.stdout).to_string())
    })
    .await
    .expect("amd64 unit inspect never became available");
    // Whitespace-normalised: the CLI's pretty-print spacing is not part
    // of the inspect contract.
    let squashed: String = inspect.split_whitespace().collect();
    assert!(
        squashed.contains("\"amd64\"") && squashed.contains("\"rosetta\":true"),
        "amd64 unit must be recorded as rosetta-emulated, got: {inspect}"
    );
    let running = poll(STOP_TIMEOUT_SECS, 500, || async {
        container_state(&name).await.as_deref() == Some("running")
    })
    .await;
    assert!(
        running,
        "amd64 unit must actually run (emulated), state: {:?}",
        container_state(&name).await
    );
    // Close the held stdin (workload EOF) and reap the run process —
    // leaving the pipe open keeps the unit alive past the test.
    drop(stdin_held);
    let status = timeout(Duration::from_secs(STOP_TIMEOUT_SECS), child.wait())
        .await
        .expect("amd64 unit did not exit after stdin EOF")
        .expect("amd64 unit wait failed");
    assert!(
        status.success(),
        "amd64 unit must exit 0 on stdin EOF, got {status:?}"
    );
}

// ─── the product path: `run-image --isolation apple-container` ─────────
//
// The sessions above drive `container run` directly — the PR-18
// substrate validation harness. The tests below drive the product CLI
// (`mcp-writ run-image --isolation apple-container`), which must apply
// the same per-unit VM boundary through the shared backend contract and
// record it on the launch report — never silently degrade to a native
// run or another isolation method.

/// `container build` — Apple's builder speaks the Dockerfile contract
/// through its buildkit shim, so the wrapped image is the same shape
/// `wrap-image` produces, built by the substrate's own tooling.
async fn container_build(context: &Path, tag: &str, dockerfile: &str) -> Result<(), String> {
    let out = timeout(
        Duration::from_secs(600),
        Command::new("container")
            .args(["build", "--platform", "linux/arm64", "-t", tag, "-f"])
            .arg(dockerfile)
            .arg(context)
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            // A dropped future must kill the CLI — otherwise an
            // interrupted build keeps running detached, growing the
            // substrate's store with nobody watching it.
            .kill_on_drop(true)
            .output(),
    )
    .await
    .map_err(|_| "container build timed out".to_string())?
    .map_err(|e| format!("container build spawn failed: {e}"))?;
    if out.status.success() {
        Ok(())
    } else {
        Err(format!(
            "container build {tag} failed: {}",
            String::from_utf8_lossy(&out.stderr)
        ))
    }
}

/// The wrapped image the product path launches, mirroring the product's
/// wrap contract: `mcp-secure-runner` is the entrypoint, the probe is
/// the payload `MCP_ORIG_ENTRYPOINT` restores, the policy is baked in
/// AND mounted read-only at run time, and the runner's capability
/// marker is recorded as `MCP_WRIT_RUNNER_CAPS`. `FROM scratch` keeps
/// the build hermetic — runner and probe are static musl ELFs, so no
/// base-image pull or userspace is needed — while the image itself is a
/// real OCI record the `container image inspect` parser must read.
async fn build_secure_image(runner: &Path, probe: &Path) -> Result<String, String> {
    let work = tempfile::Builder::new()
        .prefix("mcp_writ_apple_img_")
        .tempdir()
        .map_err(|e| e.to_string())?;
    let ctx = work.path();
    std::fs::copy(runner, ctx.join("mcp-secure-runner")).map_err(|e| e.to_string())?;
    std::fs::copy(probe, ctx.join("kata-probe")).map_err(|e| e.to_string())?;
    std::fs::copy(
        kata_fixtures_dir().join("policy.kdl"),
        ctx.join("policy.kdl"),
    )
    .map_err(|e| e.to_string())?;
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
    // The product mounts no host workspace — `/workspace` exists
    // in-image (the kata image used `RUN mkdir -p`; scratch has no RUN,
    // so a WORKDIR pair creates the dir and restores cwd=/).
    let dockerfile = format!(
        "FROM scratch\n\
         COPY mcp-secure-runner /usr/local/bin/mcp-secure-runner\n\
         COPY kata-probe /usr/local/bin/kata-probe\n\
         COPY policy.kdl /etc/mcp-secure/policy.kdl\n\
         WORKDIR /workspace\n\
         WORKDIR /\n\
         ENV MCP_ORIG_ENTRYPOINT=\"[\\\"/usr/local/bin/kata-probe\\\"]\" MCP_ORIG_CMD=\"\" \
         MCP_WRIT_ENV=\"\" MCP_WRIT_SERVER=\"\" MCP_WRIT_SKIP_SANDBOX=\"\" MCP_WRIT_FAIL_ON=\"\"\n\
         ENV MCP_WRIT_RUNNER_CAPS='{caps_json}'\n\
         ENTRYPOINT [\"/usr/local/bin/mcp-secure-runner\"]\n"
    );
    let df_path = ctx.join("Dockerfile");
    std::fs::write(&df_path, dockerfile).map_err(|e| e.to_string())?;
    let tag = "mcp-writ-apple-secure:test";
    container_build(ctx, tag, df_path.to_str().unwrap()).await?;
    // The context drops here — buildkit holds the image in the store.
    Ok(tag.to_string())
}

/// Both product-path sessions use the same image — build once per test
/// binary so a parallel run never races on a shared build context.
static SECURE_IMAGE: tokio::sync::OnceCell<Result<String, String>> =
    tokio::sync::OnceCell::const_new();

async fn shared_secure_image(runner: &Path, probe: &Path) -> Result<String, String> {
    SECURE_IMAGE
        .get_or_init(|| async { build_secure_image(runner, probe).await })
        .await
        .clone()
}

/// Spawn the product CLI: `mcp-writ run-image --isolation apple-container`
/// over the wrapped image, with the launch report written to
/// `report_path`. stdin/stdout are piped for the stdio session; stderr
/// is piped and drained into a returned task so a verbose child cannot
/// deadlock on a full pipe buffer while the failure text stays
/// available to assert on. `engine`, when passed, is forwarded as
/// `--engine` — the apple substrate drives its own CLI, so any value
/// must refuse.
fn spawn_run_image(
    image: &str,
    dirs: &SessionDirs,
    report_path: &Path,
    engine: Option<&str>,
) -> (tokio::process::Child, tokio::task::JoinHandle<Vec<u8>>) {
    let mut cmd = Command::new(common::mcp_writ_bin());
    cmd.args([
        "run-image",
        "--isolation",
        "apple-container",
        "--server",
        "kata-probe",
        "--policy",
        &dirs.policy.to_string_lossy(),
        "--log-dir",
        &dirs.logs.to_string_lossy(),
        "--report",
        &report_path.to_string_lossy(),
        "--allow-mutable-tag",
    ]);
    if let Some(engine) = engine {
        cmd.args(["--engine", engine]);
    }
    cmd.arg(image)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cmd.spawn().expect("mcp-writ run-image failed to spawn");
    let mut stderr = child.stderr.take().unwrap();
    let stderr_task = tokio::spawn(async move {
        use tokio::io::AsyncReadExt;
        let mut buf = Vec::new();
        let _ = stderr.read_to_end(&mut buf).await;
        buf
    });
    (child, stderr_task)
}

/// The id of the running unit whose recorded image reference names the
/// launched tag. The product launch lets the substrate auto-name the
/// unit (no `--name`), so the test discovers the id through
/// `container ls` rather than prescribing it.
async fn running_unit_for(image_tag: &str) -> Option<String> {
    let out = Command::new("container")
        .args(["ls", "--format", "json"])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .await
        .ok()?;
    if !out.status.success() {
        return None;
    }
    ls_unit_id_for(&String::from_utf8_lossy(&out.stdout), image_tag)
}

/// `container ls --format json` → the `id` of the *running* unit whose
/// image reference contains `image_tag` — structural JSON extraction,
/// same contract as [`inspect_state`].
fn ls_unit_id_for(stdout: &str, image_tag: &str) -> Option<String> {
    fn member<'a>(
        v: &nojson::RawJsonValue<'a, 'a>,
        name: &str,
    ) -> Option<nojson::RawJsonValue<'a, 'a>> {
        v.to_member(name).ok().and_then(|m| m.optional())
    }
    let json = nojson::RawJson::parse(stdout.trim()).ok()?;
    let mut arr = json.value().to_array().ok()?;
    arr.find_map(|record| {
        let state = member(&record, "status")
            .and_then(|s| member(&s, "state"))
            .and_then(|s| s.to_unquoted_string_str().ok())?;
        if state != "running" {
            return None;
        }
        let reference = member(&record, "configuration")
            .and_then(|c| member(&c, "image"))
            .and_then(|i| member(&i, "reference"))
            .and_then(|r| r.to_unquoted_string_str().ok())?;
        if !reference.contains(image_tag) {
            return None;
        }
        member(&record, "id")
            .and_then(|i| i.to_unquoted_string_str().ok())
            .map(|s| s.into_owned())
    })
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

/// `run-image --isolation apple-container` must serve the same stdio
/// contract as the direct `container run` session — and the launch
/// report must record the *confirmed* per-unit VM boundary, not just
/// the request.
#[tokio::test]
async fn run_image_apple_stdio_session() {
    if let Some(reason) = blocking(check_prereqs).await {
        common::skip_apple_test(&reason);
        return;
    }
    let _vm_guard = VM_LOCK.lock().await;
    let Some(probe) = blocking(compiled_vm_probe).await else {
        return;
    };
    let Some(runner) = blocking(linux_runner).await else {
        return;
    };
    let image = match shared_secure_image(&runner, &probe).await {
        Ok(tag) => tag,
        Err(e) => {
            common::skip_apple_test(&format!("image build failed: {e}"));
            return;
        }
    };

    let dirs = blocking(session_dirs).await;
    let host_report = dirs.report.join("host-launch-report.json");
    let (mut child, _stderr_drain) = spawn_run_image(&image, &dirs, &host_report, None);
    let mut wire = Wire {
        lines: Vec::new(),
        reader: BufReader::new(child.stdout.take().unwrap()),
        writer: Some(child.stdin.take().unwrap()),
    };

    // initialize — same pinned revision the harness session asserts.
    wire.send(&request(
        0,
        "initialize",
        "{\"protocolVersion\":\"2025-11-25\",\"capabilities\":{},\"clientInfo\":{\"name\":\"apple-run-image-e2e\",\"version\":\"0\"}}",
    ))
    .await;
    let init = wire.wait_id(0, SESSION_TIMEOUT_SECS).await.expect(
        "initialize response never arrived — the apple VM/runner failed \
         to come up through the product path",
    );
    assert!(
        init.contains("\"result\"") && init.contains("\"protocolVersion\":\"2025-11-25\""),
        "initialize must return a pinned 2025-11-25 result, got: {init}"
    );

    // While the VM runs: `container ls` must show this launch's unit
    // running the wrapped image, and its `container-runtime-linux
    // --uuid <id>` manager must be alive — the host-side VM-boundary
    // proof, not a report claim.
    let unit = poll_some(STOP_TIMEOUT_SECS, 500, || {
        let image = image.clone();
        async move { running_unit_for(&image).await }
    })
    .await
    .expect("no running unit for the wrapped image");
    assert!(
        runtime_process_running(&unit).await,
        "a container-runtime-linux --uuid {unit} process must exist — the boundary is a VM"
    );

    // Guest-side probe legs through the product path's stdio relay.
    wire.send("{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}")
        .await;
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
            "{\"path\":\"/workspace/apple-run-image.txt\",\"content\":\"apple\"}",
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

    // The guest-side VM markers — virtiofs share mechanism plus the
    // guest kernel's own controls — prove the workload ran in the Apple
    // `container` guest, matching the harness session's assertions.
    let ident = text_of(1);
    assert!(
        ident.contains("uname.osrelease=") && ident.contains("virtiofs_in_filesystems=true"),
        "guest identity must carry the apple VM markers through run-image: {ident}"
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
        text_of(4).contains("created /workspace/apple-run-image.txt"),
        "workspace write inside the grant must succeed: {}",
        text_of(4)
    );

    // stdin EOF ends the session; the VM is destroyed with the unit.
    wire.close_stdin();
    let status = timeout(Duration::from_secs(STOP_TIMEOUT_SECS), child.wait())
        .await
        .expect("run-image did not exit after stdin EOF")
        .expect("wait failed");
    assert!(
        status.success(),
        "run-image must exit 0 on a clean apple session, got {status:?}"
    );
    let unit_gone = poll(STOP_TIMEOUT_SECS, 500, || {
        let unit = unit.clone();
        async move { container_state(&unit).await.is_none() }
    })
    .await;
    assert!(
        unit_gone,
        "--rm must remove unit {unit} after the session (state: {:?})",
        container_state(&unit).await
    );
    let runtime_gone = poll(STOP_TIMEOUT_SECS, 500, || {
        let unit = unit.clone();
        async move { !runtime_process_running(&unit).await }
    })
    .await;
    assert!(
        runtime_gone,
        "container-runtime-linux for {unit} must be gone after exit"
    );

    // ── the host launch report records the confirmed VM boundary ────
    let report_text = std::fs::read_to_string(&host_report)
        .unwrap_or_else(|e| panic!("launch report missing at {}: {e}", host_report.display()));
    let parsed = nojson::RawJson::parse(&report_text).expect("report is valid JSON");
    let root = parsed.value();

    let target = root.to_member("target").unwrap().required().unwrap();
    assert_eq!(json_str(&target, "substrate"), "vm");
    assert_eq!(json_str(&target, "engine"), "apple-container");
    assert_eq!(json_str(&target, "workload_os"), "linux");
    assert_eq!(json_str(&target, "host_os"), "macos");

    let iso = root.to_member("isolation").unwrap().required().unwrap();
    assert_eq!(json_str(&iso, "configured"), "apple-container");
    assert_eq!(
        json_str(&iso, "verified"),
        "apple-container",
        "the backend must confirm the VM boundary was applied — never a fallback"
    );
    assert_eq!(json_str(&iso, "unit"), "vm");
    assert_eq!(
        json_str(&iso, "unit_id"),
        unit,
        "the recorded unit id is the apple container id the runtime is named after"
    );
    let detail = json_str(&iso, "detail");
    assert!(
        detail.contains("container-runtime-linux") && detail.contains("driver: container"),
        "the isolation detail records the substrate identity: {detail}"
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

    // The guest report channel works through the apple mount the same
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
        "the apple-mounted audit log must record the auditor's denies"
    );
}

/// SIGINT to the `run-image` process must terminate the apple workload
/// and leave no VM unit or runtime process behind — the shared session
/// driver's interrupt path owns the teardown through the unit id.
#[tokio::test]
async fn run_image_apple_sigint_interrupts_and_cleans_up() {
    if let Some(reason) = blocking(check_prereqs).await {
        common::skip_apple_test(&reason);
        return;
    }
    let _vm_guard = VM_LOCK.lock().await;
    let Some(probe) = blocking(compiled_vm_probe).await else {
        return;
    };
    let Some(runner) = blocking(linux_runner).await else {
        return;
    };
    let image = match shared_secure_image(&runner, &probe).await {
        Ok(tag) => tag,
        Err(e) => {
            common::skip_apple_test(&format!("image build failed: {e}"));
            return;
        }
    };

    let dirs = blocking(session_dirs).await;
    let host_report = dirs.report.join("host-interrupt-report.json");
    let (mut child, _stderr_drain) = spawn_run_image(&image, &dirs, &host_report, None);
    let mut wire = Wire {
        lines: Vec::new(),
        reader: BufReader::new(child.stdout.take().unwrap()),
        writer: Some(child.stdin.take().unwrap()),
    };

    // Wait for the workload to be live inside the VM.
    wire.send(&request(
        0,
        "initialize",
        "{\"protocolVersion\":\"2025-11-25\",\"capabilities\":{},\"clientInfo\":{\"name\":\"apple-run-image-sigint\",\"version\":\"0\"}}",
    ))
    .await;
    wire.wait_id(0, SESSION_TIMEOUT_SECS)
        .await
        .expect("initialize response never arrived — the apple VM failed to come up");
    let unit = poll_some(STOP_TIMEOUT_SECS, 500, || {
        let image = image.clone();
        async move { running_unit_for(&image).await }
    })
    .await
    .expect("no running unit for the wrapped image");

    // SIGINT the mcp-writ process itself — the shared session driver
    // catches ctrl_c, terminates the unit (container rm -f by cidfile),
    // and reports `interrupted`.
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

    // The interrupt path removed the unit — the container record and
    // its runtime process are gone without manual cleanup.
    let unit_gone = poll(STOP_TIMEOUT_SECS, 500, || {
        let unit = unit.clone();
        async move { container_state(&unit).await.is_none() }
    })
    .await;
    assert!(unit_gone, "unit {unit} must be removed after SIGINT");
    let runtime_gone = poll(STOP_TIMEOUT_SECS, 500, || {
        let unit = unit.clone();
        async move { !runtime_process_running(&unit).await }
    })
    .await;
    assert!(
        runtime_gone,
        "container-runtime-linux for {unit} must be gone after SIGINT"
    );

    // The report records the configured+verified boundary and the
    // interrupted outcome — the verification happened before the signal.
    let report_text = std::fs::read_to_string(&host_report)
        .unwrap_or_else(|e| panic!("launch report missing at {}: {e}", host_report.display()));
    let parsed = nojson::RawJson::parse(&report_text).unwrap();
    let root = parsed.value();
    let iso = root.to_member("isolation").unwrap().required().unwrap();
    assert_eq!(json_str(&iso, "configured"), "apple-container");
    assert_eq!(json_str(&iso, "verified"), "apple-container");
    assert_eq!(json_str(&iso, "unit"), "vm");
    let result = root.to_member("result").unwrap().required().unwrap();
    assert_eq!(json_str(&result, "status"), "interrupted");
}

/// `--isolation apple-container` with an `--engine` flag must refuse —
/// the substrate is driven by Apple's own `container` CLI, and a
/// refusal never degrades to a normal container launch. Nothing is left
/// running: the report shows apple-container configured but never
/// verified.
#[tokio::test]
async fn run_image_apple_engine_flag_refuses() {
    if let Some(reason) = blocking(check_prereqs).await {
        common::skip_apple_test(&reason);
        return;
    }
    let _vm_guard = VM_LOCK.lock().await;

    let dirs = blocking(session_dirs).await;
    let host_report = dirs.report.join("host-refusal-report.json");
    // The refusal fires at engine resolution — before any image or
    // substrate work — so the launch never needs a real image.
    let (mut child, stderr_drain) = spawn_run_image(
        "mcp-writ-apple-secure:test",
        &dirs,
        &host_report,
        Some("docker"),
    );
    let status = timeout(Duration::from_secs(STOP_TIMEOUT_SECS), child.wait())
        .await
        .expect("run-image did not exit")
        .expect("wait failed");
    let stderr = String::from_utf8_lossy(&stderr_drain.await.unwrap_or_default()).into_owned();
    assert!(
        !status.success(),
        "apple-container over an --engine selection must refuse, not fall back"
    );
    assert!(
        stderr.contains("--engine"),
        "the refusal must name the rejected flag, stderr: {stderr}"
    );

    let report_text = std::fs::read_to_string(&host_report)
        .unwrap_or_else(|e| panic!("launch report missing at {}: {e}", host_report.display()));
    let parsed = nojson::RawJson::parse(&report_text).unwrap();
    let root = parsed.value();
    let iso = root.to_member("isolation").unwrap().required().unwrap();
    assert_eq!(json_str(&iso, "configured"), "apple-container");
    // The backend never confirmed — verified/unit stay null (a plain
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
    let detail = json_str(&result, "detail");
    assert!(
        detail.contains("--engine") && detail.starts_with("resolve engine"),
        "the refusal must record its stage and reason: {detail}"
    );
}

// ─── inspect_state regression tests ────────────────────────────────────
//
// Pure parsing — no VM prerequisites. The `container inspect` contract is
// a JSON record stream; the pretty-print layout the CLI happens to emit
// today must not be load-bearing.

#[test]
fn inspect_state_parses_pretty_array() {
    let out = r#"[
        {
            "id" : "apple-e2e",
            "status" : {
                "state" : "running"
            }
        }
    ]"#;
    assert_eq!(inspect_state(out).as_deref(), Some("running"));
}

#[test]
fn inspect_state_parses_compact_object() {
    let out = r#"{"status":{"state":"stopped"}}"#;
    assert_eq!(inspect_state(out).as_deref(), Some("stopped"));
}

#[test]
fn inspect_state_reads_status_state_only() {
    // The value must come from `status.state` — a same-named key earlier
    // in the record, or a trailing comma on the value line, must not
    // corrupt the extraction.
    let out = r#"[
        {
            "config" : { "state" : "bogus" },
            "status" : { "state" : "exited", "code" : 0 }
        }
    ]"#;
    assert_eq!(inspect_state(out).as_deref(), Some("exited"));
}

#[test]
fn inspect_state_malformed_or_missing_is_none() {
    assert_eq!(inspect_state("not json"), None);
    assert_eq!(inspect_state("[]"), None);
    assert_eq!(inspect_state(r#"[{"status":{}}]"#), None);
    assert_eq!(inspect_state(r#"[{"status":{"state":7}}]"#), None);
    assert_eq!(inspect_state(r#"[{"config":{"state":"running"}}]"#), None);
}
