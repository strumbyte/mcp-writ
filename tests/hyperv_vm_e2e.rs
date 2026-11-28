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

/// Record descendant-containment evidence as inconclusive without
/// letting it masquerade as a pass. The certification host sets
/// `MCP_WRIT_REQUIRE_HYPERV_TESTS=1`; there the descendant probe must
/// actually run, so an inconclusive platform refusal fails the test.
fn descendant_inconclusive(leg: &str, reason: &str) {
    assert!(
        std::env::var("MCP_WRIT_REQUIRE_HYPERV_TESTS").as_deref() != Ok("1"),
        "{leg} descendant validation is required on the certification host: {reason}"
    );
    eprintln!("INCONCLUSIVE: {leg} descendant validation did not run: {reason}");
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
    docker_build_with_args(context, tag, &[]).await
}

async fn docker_build_with_args(
    context: &Path,
    tag: &str,
    extra_build_args: &[String],
) -> Result<(), ImageError> {
    let mut cmd = Command::new("docker");
    cmd.args(["build", "--isolation", "hyperv"])
        .args(["--build-arg", &format!("BASE_IMAGE={BASE_IMAGE_PINNED}")]);
    for a in extra_build_args {
        cmd.args(["--build-arg", a]);
    }
    cmd.args(["-t", tag, "-f"])
        .arg(context.join("Dockerfile"))
        .arg(context);
    let out = timeout(
        // A cold Server Core pull is several GiB — the build budget is
        // pull-dominated, not instruction-dominated (the Dockerfile is
        // COPY-only). A timeout is therefore a too-slow network, not a
        // defect: classify it as a pull failure.
        Duration::from_secs(3600),
        cmd.stdout(Stdio::null())
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
    // Record the runner's capability marker as the image env — the same
    // contract `wrap-image`/`containerize` emit — so the product
    // `run-image --report` gate accepts the fixture image.
    let caps = guest_report::scan_runner_caps(&std::fs::read(runner).map_err(copy_defect)?)
        .ok_or_else(|| ImageError::Defect("runner has no MCP_WRIT_RUNNER_CAPS marker".into()))?;
    let tag = "mcp-writ-hyperv-probe:test";
    docker_build_with_args(ctx, tag, &[format!("RUNNER_CAPS={}", caps.env_value())]).await?;
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

/// Evidence the validation job retains per session: guest + host launch
/// reports, the audit trail, and the test's own metrics / lifecycle /
/// host-identity records — never staged executables, the workspace's
/// arbitrary writes, or RPC bodies.
const SESSION_EVIDENCE: &[&str] = &[
    "metrics.json",
    "lifecycle.json",
    "host-identity.json",
    "report/report.json",
    "report/host-launch-report.json",
    "report/host-kill-report.json",
    "report/host-refusal-report.json",
    "logs/audit.jsonl",
];

impl Drop for SessionDirs {
    fn drop(&mut self) {
        common::copy_session_evidence(
            "MCP_WRIT_HYPERV_EVIDENCE_DIR",
            self._root.path(),
            SESSION_EVIDENCE,
        );
    }
}

/// Scratch root: the validation job's `MCP_WRIT_HYPERV_TEST_ROOT`, else
/// `target/hyperv-tests` under the checkout.
fn test_root() -> PathBuf {
    common::vm_test_root("MCP_WRIT_HYPERV_TEST_ROOT", "hyperv-tests")
}

/// Host directories that become the guest's mounts. Windows bind mounts
/// take `C:\host\dir:C:\guest\dir` — forward slashes are accepted on both
/// sides but kept Windows-native for the -v parser.
fn session_dirs() -> SessionDirs {
    session_dirs_in(&test_root())
}

fn session_dirs_in(parent: &Path) -> SessionDirs {
    let root = tempfile::Builder::new()
        .prefix("mcp_writ_hyperv_run_")
        .tempdir_in(parent)
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

/// Session dirs for the `run-image` legs under a write-restricted
/// ancestry. `run-image` pins `--log-dir` and walks every ancestor for
/// untrusted replace access — a dev checkout's `target/` grants it
/// (`Authenticated Users: Modify` by construction), so the launch's
/// mount gate refuses the scratch root the harness sessions use. The
/// user profile admits write only to the owner and trusted services.
fn run_image_session_dirs() -> SessionDirs {
    let profile = std::env::var_os("USERPROFILE")
        .map(PathBuf::from)
        .expect("USERPROFILE must be set for the run-image session dirs");
    let parent = profile.join(".mcp-writ").join("hyperv-tests");
    std::fs::create_dir_all(&parent).expect("create run-image session root");
    let dirs = session_dirs_in(&parent);
    // The launch mounts only the contract channels, so the mount-scoped
    // policy variant replaces the copied harness policy — see
    // `policy-run-image.kdl` for why in-image grants cannot resolve on
    // a Windows guest.
    std::fs::copy(
        fixtures_dir().join("policy-run-image.kdl"),
        dirs.policy.join("policy.kdl"),
    )
    .expect("copy run-image policy");
    // The policy mount's host source is NOT `dirs.policy`: the runner
    // exports the bound policy into its private launch staging dir and
    // binds that read-only (`runner.rs` `policy_share_host`). Leg 5's
    // matching `sub/` + ACE prep therefore happens in the stdio session
    // against the daemon-recorded mount `Source`, not here.
    dirs
}

/// Session dirs for the stdio test, including the writable audit-mount
/// subtree only that test uses. The external-kill test intentionally does
/// not depend on icacls/DACL verification to reach `docker kill`.
fn run_image_stdio_session_dirs() -> SessionDirs {
    let dirs = run_image_session_dirs();
    // The allowed-write leg targets `sub/` inside the writable audit
    // mount — `dirs.logs` is that bind's actual host source (the launch
    // pins and mounts it as-is), so the dir must exist before launch
    // for the guest to see it. The guest sees the host object's DACL
    // through the bind, and the workload's AppContainer SID has no ACE
    // on `sub/` — without a grant every write dies at the DACL layer
    // and mount mode is never reached. A host-side `ALL APPLICATION
    // PACKAGES` ACE — a group the non-LPAC token keeps — makes DACL
    // allow the write, and `verify_sid_write_grant` asserts that ACE
    // on `sub/` so "guest DACL allows it" is verified, not assumed.
    std::fs::create_dir_all(dirs.logs.join("sub")).expect("create audit-mount sub");
    grant_all_app_packages(&dirs.logs.join("sub"));
    dirs
}

/// Grant `ALL APPLICATION PACKAGES` modify on `dir`, spelled as a SID
/// so the grant is locale-independent. The outcome is verified through
/// the security-descriptor API rather than icacls's localized output —
/// the command's exit status is checked, then the DACL is walked for
/// the trustee's write-allowing ACE.
#[cfg(windows)]
fn grant_all_app_packages(dir: &Path) {
    let out = StdCommand::new("icacls")
        .arg(dir)
        .args(["/grant", "*S-1-15-2-1:(OI)(CI)(M)"])
        .output()
        .expect("icacls must spawn on a Windows host");
    assert!(
        out.status.success(),
        "icacls grant on {} failed: {}{}",
        dir.display(),
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    verify_sid_write_grant(dir, "S-1-15-2-1");
}

/// `GetNamedSecurityInfoW`'s heap allocation and any SID built by
/// `ConvertStringSidToSidW` are `LocalFree`d on every path.
#[cfg(windows)]
struct LocalFreeGuard(*mut std::ffi::c_void);

#[cfg(windows)]
impl Drop for LocalFreeGuard {
    fn drop(&mut self) {
        use windows::Win32::Foundation::{HLOCAL, LocalFree};
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe {
            let _ = LocalFree(Some(HLOCAL(self.0)));
        }
    }
}

/// Structured proof that `dir`'s DACL carries an access-allowed ACE
/// handing the `sddl` trustee write rights — `GetNamedSecurityInfoW` +
/// `GetAce` + `EqualSid`, no localized tool output involved.
#[cfg(windows)]
fn verify_sid_write_grant(dir: &Path, sddl: &str) {
    use std::ffi::c_void;

    use windows::Win32::Security::Authorization::{
        ConvertStringSidToSidW, GetNamedSecurityInfoW, SE_FILE_OBJECT,
    };
    use windows::Win32::Security::{
        ACCESS_ALLOWED_ACE, ACL, ACL_SIZE_INFORMATION, AclSizeInformation,
        DACL_SECURITY_INFORMATION, EqualSid, GetAce, GetAclInformation, PSECURITY_DESCRIPTOR, PSID,
    };
    use windows::core::HSTRING;

    let mut trustee = PSID(std::ptr::null_mut());
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    unsafe { ConvertStringSidToSidW(&HSTRING::from(sddl), &mut trustee) }
        .expect("the SDDL trustee SID must parse");
    let _trustee_guard = LocalFreeGuard(trustee.0);

    let name = dir.to_string_lossy();
    let mut dacl: *mut ACL = std::ptr::null_mut();
    let mut sd = PSECURITY_DESCRIPTOR(std::ptr::null_mut());
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    unsafe {
        GetNamedSecurityInfoW(
            &HSTRING::from(name.as_ref()),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            None,
            None,
            Some(&mut dacl),
            None,
            &mut sd,
        )
    }
    .ok()
    .unwrap_or_else(|e| panic!("GetNamedSecurityInfoW on {}: {e}", dir.display()));
    let _sd_guard = LocalFreeGuard(sd.0);
    assert!(
        !dacl.is_null(),
        "a null DACL is unrestricted — the fixture dir must carry a real DACL"
    );
    let mut info = ACL_SIZE_INFORMATION::default();
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    unsafe {
        GetAclInformation(
            dacl,
            &mut info as *mut _ as *mut c_void,
            size_of::<ACL_SIZE_INFORMATION>() as u32,
            AclSizeInformation,
        )
    }
    .expect("GetAclInformation on the fixture dir DACL");

    // An (M) grant expands to specific rights; FILE_WRITE_DATA (0x2,
    // FILE_ADD_FILE on a directory) is the bit the create_file leg
    // needs. Only ACEs that apply to `dir` itself count — an
    // inherit-only ACE grants children, not this object.
    const ACCESS_ALLOWED_ACE_TYPE: u8 = 0x00;
    const INHERIT_ONLY_ACE: u8 = 0x08;
    const FILE_WRITE_DATA_BIT: u32 = 0x2;
    let acl_end = dacl.cast::<u8>().wrapping_add(info.AclBytesInUse as usize);
    let mut granted = false;
    for i in 0..info.AceCount {
        let mut ace: *mut c_void = std::ptr::null_mut();
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe { GetAce(dacl, i, &mut ace) }.expect("GetAce inside the DACL bounds");
        let ace = ace.cast::<ACCESS_ALLOWED_ACE>();
        if ace.is_null()
            || ace.cast::<u8>() < dacl.cast::<u8>()
            || ace
                .cast::<u8>()
                .wrapping_add(size_of::<ACCESS_ALLOWED_ACE>())
                > acl_end
        {
            continue;
        }
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        let (ace_type, ace_flags, mask) =
            unsafe { ((*ace).Header.AceType, (*ace).Header.AceFlags, (*ace).Mask) };
        if ace_type != ACCESS_ALLOWED_ACE_TYPE
            || ace_flags & INHERIT_ONLY_ACE != 0
            || mask & FILE_WRITE_DATA_BIT == 0
        {
            continue;
        }
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        let sid = unsafe { PSID(&raw const (*ace).SidStart as *mut c_void) };
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        if unsafe { EqualSid(sid, trustee) }.is_ok() {
            granted = true;
            break;
        }
    }
    assert!(
        granted,
        "the {sddl} write-allowing ACE is missing from {}'s DACL",
        dir.display()
    );
}

#[cfg(not(windows))]
fn grant_all_app_packages(_dir: &Path) {}

/// Extract one mount's typed `RW`/`Source` fields from `{{json .Mounts}}`
/// — slash/case-normalized because inspect echoes the `-v` spelling the
/// launch passed. JSON keeps a Windows source containing `;` intact, which
/// the old delimiter rendering could not.
fn mount_entry(mounts: &str, guest_path: &str) -> Option<(bool, String)> {
    let want = guest_path.replace('/', "\\");
    let json = nojson::RawJson::parse(mounts).ok()?;
    for mount in json.value().to_array().ok()? {
        let dest = mount
            .to_member("Destination")
            .ok()
            .and_then(|m| m.optional())
            .and_then(|v| v.to_unquoted_string_str().ok())?;
        if !dest.replace('/', "\\").eq_ignore_ascii_case(&want) {
            continue;
        }
        let rw = mount
            .to_member("RW")
            .ok()
            .and_then(|m| m.optional())
            .and_then(|v| v.as_boolean_str().ok())?
            == "true";
        let source = mount
            .to_member("Source")
            .ok()
            .and_then(|m| m.optional())
            .and_then(|v| v.to_unquoted_string_str().ok())?
            .into_owned();
        return Some((rw, source));
    }
    None
}

fn mount_rw(mounts: &str, guest_path: &str) -> Option<bool> {
    mount_entry(mounts, guest_path).map(|(rw, _)| rw)
}

/// The bind's host `Source` — for the product's policy mount this is
/// the runner's private launch staging dir, not the harness policy dir
/// the `--policy` file came from.
fn mount_source(mounts: &str, guest_path: &str) -> Option<PathBuf> {
    mount_entry(mounts, guest_path).map(|(_, s)| PathBuf::from(s))
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
        // `MCP_WRIT_SHARE_ROOTS` is the launch channel the product's
        // `container_run_args` fills from the mount list — the harness
        // replicates that contract by hand. Every tool-arg path under a
        // listed root skips the replaceable-ancestry walk, which the
        // utility VM's C:\ root DACL could never pass. `C:\share` and
        // the in-image dirs the legs exercise (`C:\writ-deny`,
        // `C:\Windows`) are declared for the same reason: a denied leg
        // must reach the DACL layer to record `os error 5`, and only
        // the guest workload — never the host — could retarget them.
        // `C:\mcp-secure`/`C:\probe`/`C:\etc\mcp-secure` cover the image
        // content the launch binds (entrypoint exe, runner dir, policy
        // tree).
        "-e",
        "MCP_WRIT_SHARE_ROOTS=C:\\workspace;C:\\share;C:\\writ-deny;C:\\Windows;C:\\mcp-secure;C:\\probe;C:\\etc\\mcp-secure",
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

/// `docker stats --no-stream` memory usage (MiB) for `name` — the
/// utility VM's accounting. `None` when unreadable: the metric is
/// supplemental to the session assertions, not a gate.
async fn docker_mem_mib(name: &str) -> Option<f64> {
    let out = Command::new("docker")
        .args(["stats", name, "--no-stream", "--format", "{{.MemUsage}}"])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .await
        .ok()?;
    // "12.34MiB / 2GiB" — take the usage side and normalise the unit.
    let usage = String::from_utf8_lossy(&out.stdout).trim().to_string();
    let first = usage.split('/').next()?.trim().to_string();
    let num: String = first
        .chars()
        .take_while(|c| c.is_ascii_digit() || *c == '.')
        .collect();
    let value: f64 = num.parse().ok()?;
    let mib = match first[num.len()..].trim_start().to_lowercase().as_str() {
        "b" => value / (1024.0 * 1024.0),
        "kib" => value / 1024.0,
        "gib" => value * 1024.0,
        _ => value,
    };
    Some(mib)
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
        // `addr` is omitted — the probe defaults to 192.0.2.1:80 —
        // because a `read_only` tool carrying a host/URL argument is
        // refused by the auditor before the capability check can engage.
        (8, "net_probe", "{\"path\":\"C:/workspace\"}"),
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
    // Read while the utility VM is still alive — it exits on stdin EOF.
    let mem_mib = docker_mem_mib(&name).await;

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
        text_of(3).contains("create_ok C:/workspace/hyperv-ok.txt"),
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
    // guarantee is containment inheritance, not spawn denial — the
    // launch sets no child-process policy, and the host leg's denial is
    // an inherited-cwd accident the utility VM does not reproduce. The
    // leg must first be a real tool result — an RPC error here would
    // satisfy the escape check vacuously. Then only two outcomes count:
    // the permitted spawn refusal, or a spawned descendant whose denied
    // write provably left no file (`child_txt=absent` — the probe checks
    // the path itself, so no stderr wording is parsed).
    let spawn_leg = text_of(9);
    assert!(
        spawn_leg.contains("\"result\""),
        "spawn_child must return a tool result, not an RPC error: {spawn_leg}"
    );
    let write_spawn_refusal = spawn_leg
        .split_once("spawn failed:")
        .map(|(_, rest)| {
            rest.chars()
                .take_while(|c| c.is_ascii_digit())
                .collect::<String>()
        })
        .as_deref()
        == Some("5");
    assert!(
        !spawn_leg.contains("spawn failed:") || write_spawn_refusal,
        "only the documented access-denied platform refusal is tolerated; \
         executable-format and other fixture launch errors fail the test: {spawn_leg}"
    );
    if write_spawn_refusal {
        descendant_inconclusive(
            "write",
            "the platform refused the probe spawn with os error 5",
        );
    }
    assert!(
        write_spawn_refusal
            || (spawn_leg.contains("spawn ok:")
                && spawn_leg.contains("child_write=denied:5")
                && spawn_leg.contains("child_txt=absent")),
        "the descendant write must report the explicit access-denied verdict; \
         success, a missing directory, another OS error, or an unreported \
         attempt is not containment evidence: {spawn_leg}"
    );
    if spawn_leg.contains("spawn ok:") {
        // The denied write is the effect; the descendant's *own*
        // security context is the containment-inheritance evidence —
        // interrogated on the child's process handle, not inferred.
        assert!(
            spawn_leg.contains("child_token_ac=true"),
            "a spawned descendant must carry the AppContainer token: {spawn_leg}"
        );
        assert!(
            spawn_leg.contains("child_job=true"),
            "a spawned descendant must remain inside a Job: {spawn_leg}"
        );
        // `child_warden_job` is job-specific: the probe lists the PIDs
        // of *its own* job — the one the launch put the workload in —
        // and checks the child's PID is among them, so a descendant in
        // an unrelated job cannot pass as contained. (The warden's job
        // sets KILL_ON_JOB_CLOSE without BREAKAWAY flags, so leaving it
        // is impossible anyway — this pins that rather than trusts it.)
        assert!(
            spawn_leg.contains("child_warden_job=true"),
            "a spawned descendant must join the warden's Job, not just \
             any Job: {spawn_leg}"
        );
    }
    // The comm leg is independent of the write-descendant outcome — its
    // descendant is the probe's own `--net-check` re-spawn, so `spawn failed:`
    // for the write-check process
    // can coexist with a successful comm descendant and these checks
    // must not sit behind the `spawn ok:` guard.
    assert!(
        spawn_leg.contains("comm_control="),
        "spawn_child must run the comm leg: {spawn_leg}"
    );
    // The leg must also name its descendant outcome — `comm_control`
    // alone proves nothing. `child_net_out=` means a descendant ran
    // and is checked below; `child_net=spawn:`/`child_net=exe:` are
    // the documented creation-failure shapes (descendant creation is
    // not policy-guaranteed, so they are tolerated). Anything else —
    // a control-only report — is a defect, not evidence.
    assert!(
        !spawn_leg.contains("child_net_fixture="),
        "comm-leg fixture setup/collection must not be mistaken for a spawn refusal: {spawn_leg}"
    );
    let net_spawn_refusal = spawn_leg.contains("child_net=spawn:5:");
    assert!(
        !spawn_leg.contains("child_net=spawn:") || net_spawn_refusal,
        "only the documented access-denied platform refusal is tolerated for \
         the network descendant; executable-format and other fixture launch \
         errors fail the test: {spawn_leg}"
    );
    assert!(
        spawn_leg.contains("child_net_out=") || net_spawn_refusal,
        "the comm leg must report a descendant outcome or a documented spawn \
         refusal — control-only output is no evidence: {spawn_leg}"
    );
    if net_spawn_refusal {
        descendant_inconclusive(
            "network",
            "the platform refused the network probe spawn with os error 5",
        );
    }
    if spawn_leg.contains("child_net_out=") {
        assert!(
            spawn_leg.contains("child_net_token_ac=true"),
            "the network descendant itself must carry the AppContainer token: {spawn_leg}"
        );
        assert!(
            spawn_leg.contains("child_net_job=true"),
            "the network descendant itself must remain inside a Job: {spawn_leg}"
        );
        assert!(
            spawn_leg.contains("child_net_warden_job=true"),
            "the network descendant itself must join the warden's Job: {spawn_leg}"
        );
        // The outbound denial needs no reachable endpoint — WSAEACCES
        // fires *before* routing, so the error code itself is the
        // capability gate's verdict and cannot be an
        // unavailable-endpoint failure passing as containment.
        assert!(
            spawn_leg.contains("child_net_out=denied:10013"),
            "a contained descendant's outbound connect must hit the \
             capability deny (WSAEACCES/10013) — any other result \
             means TCP left unconfined: {spawn_leg}"
        );
        // The loopback target is a *listening* endpoint (the parent's
        // bind succeeded), so the child's posture there must equal the
        // parent's own control verdict — inherited rights, not escape.
        if spawn_leg.contains("comm_control=ok") {
            assert!(
                spawn_leg.contains("child_net_loop=ok"),
                "intra-package loopback worked for the workload — its \
                 descendant must reach it too: {spawn_leg}"
            );
        } else if spawn_leg.contains("comm_control=fail:10013") {
            assert!(
                spawn_leg.contains("child_net_loop=denied:10013")
                    || spawn_leg.contains("child_net_loop=fail:10013"),
                "a 10013 loopback control denial must carry the same denial \
                 code into the descendant: {spawn_leg}"
            );
        } else if !spawn_leg.contains("comm_control=unavailable") {
            panic!(
                "loopback control failed in a non-permission way — the \
                 comparison is inconclusive, not containment evidence: {spawn_leg}"
            );
        }
        // `comm_control=unavailable` — the endpoint itself could not
        // be created; the loopback check is unverifiable there and the
        // outbound deny above is the comm evidence (it fires
        // pre-route, so it stays meaningful without a live endpoint).
    }
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
    let share_text = text_of(12);
    let share_create_ok = share_text.contains("create_ok C:/share/probe.txt");
    let share_create_denied = share_text.contains("create_denied:5 C:/share/probe.txt");
    assert!(
        share_create_ok || share_create_denied,
        "the share write must produce an explicit create_ok or access-denied verdict: {share_text}"
    );
    assert!(
        !(share_create_ok && share_create_denied),
        "the share write verdicts must be unambiguous: {share_text}"
    );
    assert_eq!(
        share_create_ok, share_probe,
        "a successful share write must be host-visible: {share_text}"
    );
    assert!(
        !share_create_denied || !share_probe,
        "an access-denied share write must leave no host file: {share_text}"
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
    let metrics = format!(
        "{{\"tier\":\"vm\",\"test\":\"hyperv_vm_stdio_session\",\"first_response_s\":{first_response_s:.3},\"last_response_s\":{last_response_s:.3},\"exit_s\":{exit_s:.3},\"memory_mib\":{}}}",
        common::json_num(mem_mib)
    );
    std::fs::write(dirs._root.path().join("metrics.json"), metrics).unwrap();
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
    let stop_t = Instant::now();
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

    let lifecycle = format!(
        "{{\"tier\":\"vm\",\"test\":\"hyperv_vm_kill_terminates_and_cleans_up\",\"unit_id\":\"{name}\",\"unit_gone\":{gone},\"stop_s\":{:.3}}}",
        stop_t.elapsed().as_secs_f64()
    );
    std::fs::write(dirs._root.path().join("lifecycle.json"), lifecycle).unwrap();
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
    // Exit-code fidelity: the runner's wait loop gives the exiting
    // child a settle window when the auditor relay's EOF races it
    // (runtime/wait.rs `auditor_first_outcome`), so the observed code
    // is the child's own — the relay-EOF-beats-exit race that could
    // report 0 instead of 7 is closed.

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
        report.contains("\"exit_code\":7"),
        "the launch report must record the child's own exit code 7: {report}"
    );

    let lifecycle = format!(
        "{{\"tier\":\"vm\",\"test\":\"hyperv_vm_child_exit_terminates_session\",\"unit_id\":\"{name}\",\"unit_exited\":{container_status},\"exit_code\":7}}"
    );
    std::fs::write(dirs._root.path().join("lifecycle.json"), lifecycle).unwrap();
}

/// PR-21 product path: the wrapped image is produced by the real
/// `mcp-writ wrap-image` — Windows guest layout, PE runner check,
/// app-local CRT staging, capability marker — then booted under Hyper-V
/// isolation exactly like the fixture image. This proves the shipping
/// contract a `run-image --isolation hyperv` backend (PR-22) consumes.
///
/// The payload image is a plain Windows image whose ENTRYPOINT is the
/// probe; `wrap-image` rewrites it into the runner-first contract.
#[tokio::test]
async fn hyperv_wrap_image_product_path() {
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
    let Some(crt) = vcruntime_dll() else {
        panic!("no vcruntime140.dll on the host to ship app-local");
    };

    // ── payload image: probe + its own CRT + a plain ENTRYPOINT ─────
    let work = build_context_dir();
    let ctx = work.path();
    std::fs::copy(&probe, ctx.join("hyperv-probe.exe"))
        .expect("copy probe into the payload context");
    std::fs::copy(&crt, ctx.join("vcruntime140.dll"))
        .expect("copy vcruntime into the payload context");
    std::fs::write(
        ctx.join("Dockerfile"),
        "ARG BASE_IMAGE\nFROM ${BASE_IMAGE}\n\
         COPY hyperv-probe.exe C:/probe/hyperv-probe.exe\n\
         COPY vcruntime140.dll C:/probe/vcruntime140.dll\n\
         WORKDIR C:/writ-deny\n\
         WORKDIR C:/\n\
         ENTRYPOINT [\"C:/probe/hyperv-probe.exe\"]\n",
    )
    .expect("payload Dockerfile");
    let payload_tag = "mcp-writ-hyperv-payload:test";
    if let Err(e) = docker_build(ctx, payload_tag).await {
        match e {
            ImageError::Pull(m) => {
                common::skip_hyperv_test(&format!("base image pull failed: {m}"));
                return;
            }
            ImageError::Defect(m) => panic!("payload image build failed: {m}"),
        }
    }

    // ── wrap it through the real CLI — guest OS, PE/arch check, CRT
    //    staging, and the image contract all come from the product ───
    let wrapped_tag = "mcp-writ-hyperv-wrapped:test";
    let out = timeout(
        Duration::from_secs(3600),
        Command::new(env!("CARGO_BIN_EXE_mcp-writ"))
            .args([
                "wrap-image",
                "--engine",
                "docker",
                // The payload below is a locally built tag-only image;
                // the base-pin rule targets registry pulls, so the leg
                // opts in like the run-image helper does.
                "--allow-mutable-tag",
                "--runner-binary",
            ])
            .arg(&runner)
            .arg("--crt-dll")
            .arg(&crt)
            .arg("--policy")
            .arg(fixtures_dir().join("policy.kdl"))
            .args([
                "--server",
                "hyperv-probe",
                "--tag",
                wrapped_tag,
                payload_tag,
            ])
            // The fixture policy sits under a dev checkout — a
            // user-writable ancestor the trusted-source gate refuses;
            // same waiver used for `.local` in development docs.
            .env("MCP_WRIT_ALLOW_REPLACEABLE_PATHS", "1")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .output(),
    )
    .await
    .expect("wrap-image timed out")
    .expect("wrap-image failed to spawn");
    let stderr = String::from_utf8_lossy(&out.stderr);
    if !out.status.success() {
        if matches!(
            classify_build_stderr(wrapped_tag, stderr.as_bytes()),
            ImageError::Pull(_)
        ) {
            common::skip_hyperv_test(&format!("wrap-image pull failed: {stderr}"));
            return;
        }
        panic!("wrap-image failed: {stderr}");
    }
    // The runner embed is a PE with the capability marker — record it in
    // the image env so run-image's capability gate accepts the image.
    let caps_env = inspect_field(wrapped_tag, "{{json .Config.Env}}")
        .await
        .unwrap_or_default();
    assert!(
        caps_env.contains("MCP_WRIT_RUNNER_CAPS="),
        "wrapped image must record the runner capability marker: {caps_env}"
    );
    let ep = inspect_field(wrapped_tag, "{{json .Config.Entrypoint}}")
        .await
        .unwrap_or_default();
    assert!(
        ep.contains("C:/mcp-secure/mcp-secure-runner.exe"),
        "wrapped image ENTRYPOINT must be the Windows runner path: {ep}"
    );

    // ── launch the wrapped image under Hyper-V isolation ────────────
    let dirs = blocking(session_dirs).await;
    let launch_id = uuid::Uuid::now_v7().to_string();
    let name = format!("hyperv-e2e-wrap-{}", std::process::id());
    let _guard = ContainerGuard(name.clone());
    let mut child = spawn_hyperv_session(wrapped_tag, &dirs, &launch_id, Some(&name), true);
    let mut wire = Wire {
        lines: Vec::new(),
        reader: BufReader::new(child.stdout.take().unwrap()),
        writer: Some(child.stdin.take().unwrap()),
    };
    wire.send(&request(
        0,
        "initialize",
        "{\"protocolVersion\":\"2025-11-25\",\"capabilities\":{},\"clientInfo\":{\"name\":\"hyperv-vm-e2e-wrap\",\"version\":\"0\"}}",
    ))
    .await;
    let init = wire.wait_id(0, SESSION_TIMEOUT_SECS).await.expect(
        "initialize response never arrived — the wrap-image-produced \
         guest failed to boot; runner stderr (inherited above) names \
         the cause",
    );
    assert!(
        init.contains("\"result\"") && init.contains("\"protocolVersion\":\"2025-11-25\""),
        "initialize must return a pinned 2025-11-25 result, got: {init}"
    );

    let iso = poll(30, 500, || async {
        inspect_field(&name, "{{.HostConfig.Isolation}}")
            .await
            .map(|v| v == "hyperv")
            .unwrap_or(false)
    })
    .await;
    assert!(iso, "the wrapped unit must record Isolation=hyperv");

    wire.send("{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}")
        .await;
    wire.send(&request(1, "tools/list", "{}")).await;
    let list = wire
        .wait_id(1, 60)
        .await
        .expect("tools/list response never arrived");
    assert!(
        list.contains("net_probe"),
        "tools/list must return the probe's inventory: {list}"
    );

    // A minimal leg set — the full enforcement matrix is the fixture
    // session's job; this leg proves the product-built image enforces.
    wire.send(&tool_call(2, "vm_identity", "{\"path\":\"C:/workspace\"}"))
        .await;
    wire.send(&tool_call(
        3,
        "create_file",
        "{\"path\":\"C:/workspace/wrap-ok.txt\",\"content\":\"wrap\"}",
    ))
    .await;
    wire.send(&tool_call(4, "env_probe", "{\"path\":\"C:/workspace\"}"))
        .await;
    let ident = wire
        .wait_id(2, 60)
        .await
        .expect("vm_identity never arrived");
    let write = wire
        .wait_id(3, 60)
        .await
        .expect("create_file never arrived");
    let envp = wire.wait_id(4, 60).await.expect("env_probe never arrived");

    wire.close_stdin();
    let status = timeout(Duration::from_secs(STOP_TIMEOUT_SECS), child.wait())
        .await
        .expect("wrapped container did not exit after stdin EOF")
        .expect("wait failed");
    assert!(status.success(), "wrapped session must exit 0: {status:?}");

    assert!(
        ident.contains("appcontainer=true") && ident.contains("in_job=true"),
        "the wrapped image's warden must apply AppContainer+Job: {ident}"
    );
    assert!(
        write.contains("create_ok C:/workspace/wrap-ok.txt"),
        "workspace write through the wrapped runner must succeed: {write}"
    );
    assert!(
        dirs.workspace.join("wrap-ok.txt").is_file(),
        "the wrapped session's workspace write must be host-visible"
    );
    assert!(
        envp.contains("mcp_vars_present=[]"),
        "MCP_* control variables must not reach the workload: {envp}"
    );

    // Guest report through the contract mount — the wrapped runner is a
    // current build, so the capability was recorded and honored.
    let report = std::fs::read_to_string(dirs.report.join("report.json"))
        .expect("wrapped session must leave a guest report");
    guest_report::validate_guest_report_text(
        &report,
        uuid::Uuid::parse_str(&launch_id).unwrap(),
        Some(env!("CARGO_PKG_VERSION")),
    )
    .expect("wrapped session's guest report must validate");

    let lifecycle = format!(
        "{{\"tier\":\"vm\",\"test\":\"hyperv_wrap_image_product_path\",\"unit_id\":\"{name}\",\"wrapped\":true,\"isolation_recorded\":{iso}}}"
    );
    std::fs::write(dirs._root.path().join("lifecycle.json"), lifecycle).unwrap();
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
    let dirs = blocking(session_dirs).await;

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

    let lifecycle = "{\"tier\":\"vm\",\"test\":\"hyperv_process_isolation_refused_for_mismatched_image\",\"unit_id\":null,\"process_isolation_refused\":true}";
    std::fs::write(dirs._root.path().join("lifecycle.json"), lifecycle).unwrap();
}

// ─── PR-22: the product `run-image --isolation hyperv` path ────────────

/// Spawn the product CLI: `mcp-writ run-image --isolation hyperv` over
/// the shared probe image, with the host launch report written to
/// `report_path`. stdin/stdout are piped for the stdio session; stderr
/// is piped and drained into a returned task so a verbose child cannot
/// deadlock on a full pipe buffer while the failure text stays
/// available to assert on.
fn spawn_run_image(
    image: &str,
    dirs: &SessionDirs,
    report_path: &Path,
    engine: &str,
    runner: &Path,
) -> (tokio::process::Child, tokio::task::JoinHandle<Vec<u8>>) {
    let mut cmd = Command::new(common::mcp_writ_bin());
    cmd.args([
        "run-image",
        "--isolation",
        "hyperv",
        "--engine",
        engine,
        "--server",
        "hyperv-probe",
        "--policy",
        &dirs.policy.join("policy.kdl").to_string_lossy(),
        "--log-dir",
        &dirs.logs.to_string_lossy(),
        "--report",
        &report_path.to_string_lossy(),
        "--allow-mutable-tag",
        "--runner-binary",
        &runner.to_string_lossy(),
        image,
    ])
    // The staged policy/log/report dirs live under a dev checkout's
    // target dir — user-writable ancestors the trusted-source gate
    // would refuse. Same waiver the development docs use for `.local`.
    .env("MCP_WRIT_ALLOW_REPLACEABLE_PATHS", "1")
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
/// the launch's unit id (the cidfile record).
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

/// Host-path comparison for docker's recorded mount source — inspect may
/// echo slash/case spelling differently from the harness's `PathBuf`.
fn same_host_path(a: &Path, b: &Path) -> bool {
    let norm = |p: &Path| {
        // Resolve junction/symlink aliases when the path exists; inspect's
        // recorded source and the harness spelling can differ only by that
        // alias. Fall back to lexical normalization for absent paths.
        let resolved = std::fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf());
        resolved
            .to_string_lossy()
            .replace('/', "\\")
            .trim_end_matches('\\')
            .to_ascii_lowercase()
    };
    norm(a) == norm(b)
}

/// The running container for *this* launch, not merely this shared image:
/// another concurrently certified session uses the same ancestor tag, so
/// selection is keyed by the launch-unique audit bind source as well.
async fn running_container_for_launch(image: &str, audit_source: &Path) -> Option<String> {
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
    let mut matches = Vec::new();
    for id in ids {
        let Some(mounts) = inspect_field(&id, "{{json .Mounts}}").await else {
            continue;
        };
        if mount_source(&mounts, "C:\\var\\log\\mcp-secure")
            .is_some_and(|source| same_host_path(&source, audit_source))
        {
            matches.push(id);
        }
    }
    (matches.len() == 1).then(|| matches[0].clone())
}

/// Poll `f` until it yields `Some` or `secs` elapse.
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

fn json_str(v: &nojson::RawJsonValue<'_, '_>, name: &str) -> String {
    v.to_member(name)
        .unwrap()
        .required()
        .unwrap()
        .to_unquoted_string_str()
        .expect("expected a JSON string")
        .into_owned()
}

/// Decode the first text content item of a raw JSON-RPC tool response.
/// Assertions must compare this decoded text, not the JSON spelling, so
/// escaping in the wire encoding cannot hide a successful read.
fn tool_response_text(line: &str) -> String {
    let json = nojson::RawJson::parse(line).expect("tool response is valid JSON");
    let result = json
        .value()
        .to_member("result")
        .expect("result member")
        .required()
        .expect("result present");
    let mut content = result
        .to_member("content")
        .expect("content member")
        .required()
        .expect("content present")
        .to_array()
        .expect("content array");
    let first = content.next().expect("first content item");
    first
        .to_member("text")
        .expect("text member")
        .required()
        .expect("text present")
        .to_unquoted_string_str()
        .expect("text string")
        .into_owned()
}

/// `run-image --isolation hyperv` must serve the same stdio contract as
/// the direct `docker run --isolation=hyperv` session — and the launch
/// report must record the *confirmed* VM boundary, not just the
/// request: `--isolation hyperv` on the launch plus the daemon's
/// recorded `HostConfig.Isolation`, verified by the backend before the
/// workload is trusted.
#[tokio::test]
async fn run_image_hyperv_stdio_session() {
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

    let dirs = blocking(run_image_stdio_session_dirs).await;
    let host_report = dirs.report.join("host-launch-report.json");
    let t0 = Instant::now();
    let (mut child, stderr_drain) = spawn_run_image(&image, &dirs, &host_report, "docker", &runner);
    let mut wire = Wire {
        lines: Vec::new(),
        reader: BufReader::new(child.stdout.take().unwrap()),
        writer: Some(child.stdin.take().unwrap()),
    };

    // initialize — same pinned revision the harness session asserts.
    wire.send(&request(
        0,
        "initialize",
        "{\"protocolVersion\":\"2025-11-25\",\"capabilities\":{},\"clientInfo\":{\"name\":\"hyperv-run-image-e2e\",\"version\":\"0\"}}",
    ))
    .await;
    let init = wire.wait_id(0, SESSION_TIMEOUT_SECS).await.expect(
        "initialize response never arrived — the hyperv unit/runner \
         failed to come up through the product path",
    );
    let first_response_s = t0.elapsed().as_secs_f64();
    assert!(
        init.contains("\"result\"") && init.contains("\"protocolVersion\":\"2025-11-25\""),
        "initialize must return a pinned 2025-11-25 result, got: {init}"
    );

    // While the unit runs: the engine must record hyperv isolation for
    // this launch's container, and a Hyper-V worker process must be
    // alive — the host-side VM-boundary proof, not a report claim.
    let cid = poll_some(STOP_TIMEOUT_SECS, 500, || {
        let image = image.clone();
        let audit_source = dirs.logs.clone();
        async move { running_container_for_launch(&image, &audit_source).await }
    })
    .await
    .expect("no running container for the hyperv image");
    assert_eq!(
        inspect_field(&cid, "{{.HostConfig.Isolation}}")
            .await
            .as_deref(),
        Some("hyperv"),
        "the launch must record Isolation=hyperv, not process"
    );
    assert!(
        vmwp_running().await,
        "a vmwp.exe worker must exist while the product-launched unit runs"
    );

    // Engine-level mount-mode evidence, independent of any write
    // outcome: the product mounts the policy share `writable: false`
    // (oci.rs maps that to `:ro`), and the daemon's recorded .Mounts is
    // the authoritative account — the policy bind must read `RW=false`
    // and the audit bind `RW=true`. A policy mount recorded writable
    // would make leg 5's failure attributable to the DACL, not the
    // mount; this check pins the attribution before the legs run.
    let mounts = inspect_field(&cid, "{{json .Mounts}}")
        .await
        .expect("docker inspect .Mounts must enumerate the launch's binds");
    assert_eq!(
        mount_rw(&mounts, "C:\\etc\\mcp-secure"),
        Some(false),
        "the policy bind must be recorded read-only: {mounts}"
    );
    assert_eq!(
        mount_rw(&mounts, "C:\\var\\log\\mcp-secure"),
        Some(true),
        "the audit bind must be recorded writable: {mounts}"
    );

    // Leg 5's DACL-allow evidence must live on the bind's *actual* host
    // source — the product mounts its private launch staging dir as the
    // policy share (`runner.rs` `policy_share_host`), not `dirs.policy`,
    // which is only where `--policy` read the kdl from. Prepare `sub/`
    // inside the discovered source and grant the same verified `ALL
    // APPLICATION PACKAGES` write ACE the audit mount carries, so the
    // guest DACL permits the write and only the read-only mount's own
    // enforcement can refuse it.
    let policy_sub = mount_source(&mounts, "C:\\etc\\mcp-secure")
        .expect("docker inspect must name the policy bind's host Source")
        .join("sub");
    std::fs::create_dir_all(&policy_sub).expect("create `sub` inside the mounted policy source");
    std::fs::write(policy_sub.join("sentinel.txt"), "sentinel")
        .expect("write the policy-sub sentinel");
    grant_all_app_packages(&policy_sub);

    // Guest-side probe legs through the product path's stdio relay.
    // `run-image` mounts only the contract channels (policy dir, audit
    // dir, report dir, staged runner), and the mount-scoped policy
    // variant scopes every tool fs pattern beneath those roots — an
    // in-image dir under the container-writable `C:\` can never pass
    // the guest's replaceable-ancestry gate (the mount contract is what
    // makes a guest path boundary-stable). The legs therefore exercise
    // enforcement through the mounts: an allowed write inside the audit
    // mount's `sub/`, a mount-layer deny against the read-only policy
    // mount, a real read of the mounted policy, plus the same
    // RPC/capability/tool-gate legs the harness session runs.
    wire.send("{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}")
        .await;
    // Same ordering proof as the harness session: waiting on our own
    // tools/list response shows the auditor's list pipeline settled.
    wire.send(&request(9, "tools/list", "{}")).await;
    let list = wire
        .wait_id(9, 60)
        .await
        .expect("tools/list response never arrived");
    assert!(
        list.contains("\"result\"") && list.contains("net_probe"),
        "tools/list must return the probe's tool inventory, got: {list}"
    );
    let legs: &[(i64, &str, &str)] = &[
        (1, "vm_identity", "{\"path\":\"C:/etc/mcp-secure\"}"),
        (
            2,
            "create_file",
            "{\"path\":\"C:/var/log/mcp-secure/sub/run-image-ok.txt\",\"content\":\"hyperv\"}",
        ),
        (
            3,
            "read_file",
            "{\"path\":\"C:/etc/mcp-secure/policy.kdl\"}",
        ),
        // Secret-overlay deny at the RPC layer.
        (
            4,
            "read_file",
            "{\"path\":\"C:/etc/mcp-secure/.ssh/id_rsa\"}",
        ),
        // Mount-mode deny — the auditor grants `sub/**` and the
        // verified `ALL APPLICATION PACKAGES` ACE on the mounted
        // source's `sub/` makes the guest DACL permit the write, so
        // only the read-only mount's enforcement can refuse it. Leg 2
        // is the same write shape through a writable mount (the product
        // cannot express a writable *policy* mount — `writable: false`
        // is the enforced contract), and the daemon's recorded `RW`
        // flags were asserted before these legs ran.
        (
            5,
            "create_file",
            "{\"path\":\"C:/etc/mcp-secure/sub/evil.txt\",\"content\":\"x\"}",
        ),
        (
            10,
            "read_file",
            "{\"path\":\"C:/etc/mcp-secure/sub/sentinel.txt\"}",
        ),
        // AppContainer capability deny — no network SIDs granted.
        // `addr` is omitted — the probe defaults to 192.0.2.1:80 —
        // because a `read_only` tool carrying a host/URL argument is
        // refused by the auditor before the capability check can engage.
        (6, "net_probe", "{\"path\":\"C:/etc/mcp-secure\"}"),
        (7, "env_probe", "{\"path\":\"C:/etc/mcp-secure\"}"),
        // Auditor tool gate.
        (8, "exec_shell", "{\"cmd\":\"id\"}"),
    ];
    for (id, name_, args) in legs {
        wire.send(&tool_call(*id, name_, args)).await;
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

    // The guest's own kernel build (the image's 10.0.26100) differs from
    // the host's 26200 — a process-isolated launch could not report it.
    let ident = text_of(1);
    assert!(
        ident.contains("os.version=10.0.26100"),
        "vm_identity must report the image kernel build: {ident}"
    );
    assert!(
        ident.contains("appcontainer=true") && ident.contains("in_job=true"),
        "the in-guest warden must apply AppContainer+Job: {ident}"
    );
    assert!(
        text_of(2).contains("create_ok C:/var/log/mcp-secure/sub/run-image-ok.txt"),
        "write inside the granted audit-mount subtree must succeed: {}",
        text_of(2)
    );
    assert!(
        dirs.logs.join("sub").join("run-image-ok.txt").is_file(),
        "the audit-mount write must be host-visible through the bind"
    );
    assert!(
        text_of(3).contains("opened C:/etc/mcp-secure/policy.kdl"),
        "read of the mounted policy must succeed: {}",
        text_of(3)
    );
    assert!(
        text_of(4).contains("secret-path overlay"),
        "secret paths must deny at the RPC layer: {}",
        text_of(4)
    );
    assert!(
        tool_response_text(&text_of(10))
            .contains("opened C:/etc/mcp-secure/sub/sentinel.txt: head=\"sentinel\""),
        "the guest must reach the exact policy sub directory before its write denial means anything: {}",
        text_of(10)
    );
    // Mount-mode evidence stacked three ways: the daemon recorded the
    // policy bind `RW=false` at session start, leg 2 ran the same
    // `create_file` shape through a writable mount and landed the file
    // on the host, and `verify_sid_write_grant` proved the guest DACL
    // permits this write on the mounted source's `sub/` — the read-only
    // mount's own enforcement is the only remaining refuser. A
    // misconfigured writable mount would let the write land as a
    // host-visible file.
    assert!(
        text_of(5).contains("create_denied:5"),
        "the tool-level create into the read-only policy mount must report \
         ERROR_ACCESS_DENIED; lookup errors such as ERROR_PATH_NOT_FOUND are \
         fixture failures, not mount enforcement: {}",
        text_of(5)
    );
    assert!(
        !text_of(5).contains("create_ok"),
        "the read-only policy mount must not accept the create: {}",
        text_of(5)
    );
    // The host-side absence check inspects the same source the bind
    // serves — the runner's staging dir, not `dirs.policy`.
    assert!(
        !policy_sub.join("evil.txt").exists(),
        "a writable-by-mistake policy mount would let the DACL-permitted \
         write through — evil.txt must stay absent on the mounted source"
    );
    assert!(
        text_of(6).contains("os error 10013"),
        "TCP connect must hit the AppContainer capability deny (WSAEACCES): {}",
        text_of(6)
    );
    assert!(
        text_of(7).contains("mcp_vars_present=[]"),
        "MCP_* control variables must not reach the workload env: {}",
        text_of(7)
    );
    assert!(
        text_of(8).contains("tool is not allowed"),
        "deny=#true tool must be refused by the auditor: {}",
        text_of(8)
    );
    let last_response_s = t0.elapsed().as_secs_f64();
    let mem_mib = docker_mem_mib(&cid).await;
    let identity = format!(
        "{{\"tier\":\"product\",\"unit_id\":\"{cid}\",\"engine_runtime\":\"hyperv\",\"verified\":\"hyperv\"}}"
    );
    std::fs::write(dirs._root.path().join("host-identity.json"), identity).unwrap();

    // stdin EOF ends the session; the unit is destroyed with it.
    wire.close_stdin();
    let status = timeout(Duration::from_secs(STOP_TIMEOUT_SECS), child.wait())
        .await
        .expect("run-image did not exit after stdin EOF")
        .expect("wait failed");
    let exit_s = t0.elapsed().as_secs_f64();
    assert!(
        status.success(),
        "run-image must exit 0 on a clean hyperv session, got {status:?}"
    );
    let cid_gone = poll(STOP_TIMEOUT_SECS, 500, || {
        let cid = cid.clone();
        async move { inspect_field(&cid, "{{.State.Status}}").await.is_none() }
    })
    .await;
    assert!(cid_gone, "container {cid} must be removed after EOF exit");

    // ── the host launch report records the confirmed VM boundary ────
    let report_text = std::fs::read_to_string(&host_report)
        .unwrap_or_else(|e| panic!("launch report missing at {}: {e}", host_report.display()));
    let parsed = nojson::RawJson::parse(&report_text).expect("report is valid JSON");
    let root = parsed.value();

    let target = root.to_member("target").unwrap().required().unwrap();
    assert_eq!(json_str(&target, "substrate"), "vm");
    assert_eq!(json_str(&target, "engine"), "docker");
    assert_eq!(json_str(&target, "workload_os"), "windows");

    let iso = root.to_member("isolation").unwrap().required().unwrap();
    assert_eq!(json_str(&iso, "configured"), "hyperv");
    assert_eq!(
        json_str(&iso, "verified"),
        "hyperv",
        "the backend must confirm hyperv was applied — never a process-isolation fallback"
    );
    assert_eq!(json_str(&iso, "unit"), "vm");
    assert_eq!(
        json_str(&iso, "unit_id"),
        cid,
        "the recorded unit id is the container id the utility VM backs"
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

    // The guest report channel works through the hyperv mount the same
    // way — received, validated, and correlated by launch id.
    let guest = root.to_member("guest").unwrap().required().unwrap();
    assert_eq!(json_str(&guest, "state"), "received");
    let guest_report_json = guest.to_member("report").unwrap().required().unwrap();
    assert_eq!(
        json_str(&guest_report_json, "launch_id"),
        json_str(&root, "launch_id"),
        "guest report launch_id must correlate with the host launch"
    );

    let audit = std::fs::read_to_string(dirs.logs.join("audit.jsonl")).expect("audit log missing");
    assert!(
        audit.contains("tool_call.denied"),
        "the hyperv-mounted audit log must record the auditor's denies"
    );
    drop(stderr_drain);

    let metrics = format!(
        "{{\"tier\":\"product\",\"test\":\"run_image_hyperv_stdio_session\",\"first_response_s\":{first_response_s:.3},\"last_response_s\":{last_response_s:.3},\"exit_s\":{exit_s:.3},\"memory_mib\":{}}}",
        common::json_num(mem_mib)
    );
    std::fs::write(dirs._root.path().join("metrics.json"), metrics).unwrap();
}

/// Killing the unit externally while `run-image` waits must unwind the
/// session honestly: the `docker run` child exits, the shared session
/// driver records the outcome, and the `--rm` unit leaves nothing
/// running behind. Windows has no targeted SIGINT for a console-less
/// child the way the kata leg sends `kill -INT`, so the external-kill
/// leg is the honest termination path on this substrate.
#[tokio::test]
async fn run_image_hyperv_external_kill_cleans_up() {
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

    let dirs = blocking(run_image_session_dirs).await;
    let host_report = dirs.report.join("host-kill-report.json");
    let (mut child, _stderr_drain) =
        spawn_run_image(&image, &dirs, &host_report, "docker", &runner);
    let mut wire = Wire {
        lines: Vec::new(),
        reader: BufReader::new(child.stdout.take().unwrap()),
        writer: Some(child.stdin.take().unwrap()),
    };

    // Wait for the workload to be live inside the unit.
    wire.send(&request(
        0,
        "initialize",
        "{\"protocolVersion\":\"2025-11-25\",\"capabilities\":{},\"clientInfo\":{\"name\":\"hyperv-run-image-kill\",\"version\":\"0\"}}",
    ))
    .await;
    wire.wait_id(0, SESSION_TIMEOUT_SECS)
        .await
        .expect("initialize response never arrived — the hyperv unit failed to come up");
    let cid = poll_some(STOP_TIMEOUT_SECS, 500, || {
        let image = image.clone();
        let audit_source = dirs.logs.clone();
        async move { running_container_for_launch(&image, &audit_source).await }
    })
    .await
    .expect("no running container for the hyperv image");

    // Kill the unit underneath the product — the run-image child sees
    // its `docker run` die and must unwind: session end recorded, the
    // unit removed (it owned the unit by cidfile), nothing left running.
    let stop_t = Instant::now();
    let kill = Command::new("docker")
        .args(["kill", &cid])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .await
        .expect("docker kill failed");
    assert!(kill.status.success(), "docker kill failed");

    let status = timeout(Duration::from_secs(STOP_TIMEOUT_SECS), child.wait())
        .await
        .expect("run-image did not exit after the unit was killed")
        .expect("wait failed");
    let _ = status; // the propagated code is the CLI's, not a contract

    let cid_gone = poll(STOP_TIMEOUT_SECS, 500, || {
        let cid = cid.clone();
        async move { inspect_field(&cid, "{{.State.Status}}").await.is_none() }
    })
    .await;
    assert!(
        cid_gone,
        "container {cid} must be removed after the external kill"
    );

    // The report records the verified boundary — verification happened
    // at launch, before the kill — and the session's end state.
    let report_text = std::fs::read_to_string(&host_report)
        .unwrap_or_else(|e| panic!("launch report missing at {}: {e}", host_report.display()));
    let parsed = nojson::RawJson::parse(&report_text).unwrap();
    let root = parsed.value();
    let iso = root.to_member("isolation").unwrap().required().unwrap();
    assert_eq!(json_str(&iso, "configured"), "hyperv");
    assert_eq!(json_str(&iso, "verified"), "hyperv");
    assert_eq!(json_str(&iso, "unit"), "vm");
    assert_eq!(json_str(&iso, "unit_id"), cid);

    let lifecycle = format!(
        "{{\"tier\":\"product\",\"test\":\"run_image_hyperv_external_kill_cleans_up\",\"unit_id\":\"{cid}\",\"unit_gone\":{cid_gone},\"stop_s\":{:.3}}}",
        stop_t.elapsed().as_secs_f64()
    );
    std::fs::write(dirs._root.path().join("lifecycle.json"), lifecycle).unwrap();
}

/// `--isolation hyperv` through a non-docker engine must refuse — the
/// Windows-mode dockerd is the validated configuration, and a refusal
/// never degrades to a plain container launch (or process isolation).
/// Nothing is left running: the report shows hyperv configured but
/// never verified.
#[tokio::test]
async fn run_image_hyperv_refusal_leaves_nothing_running() {
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
    let host_report = dirs.report.join("host-refusal-report.json");
    let (mut child, stderr_drain) = spawn_run_image(&image, &dirs, &host_report, "podman", &runner);
    let status = timeout(Duration::from_secs(STOP_TIMEOUT_SECS), child.wait())
        .await
        .expect("run-image did not exit")
        .expect("wait failed");
    let stderr = String::from_utf8_lossy(&stderr_drain.await.unwrap_or_default()).into_owned();
    assert!(
        !status.success(),
        "hyperv over a non-docker engine must refuse, not fall back"
    );

    // Where the refusal lands depends on this host's podman
    // installation — an absent CLI is refused at engine resolution, a
    // resolvable podman later at the remote-daemon locality check, the
    // windows-image inspect, or the hyperv backend's own engine gate.
    // The stderr must name one of those designed refusal points so the
    // test cannot pass on an unrelated failure.
    const DESIGNED_REFUSALS: &[&str] = &[
        "engine not available on PATH: 'podman'",
        "the podman endpoint is a remote ssh host",
        "points at a remote daemon",
        "failed to inspect image",
        "engine 'podman' is not the validated configuration",
    ];
    assert!(
        DESIGNED_REFUSALS.iter().any(|s| stderr.contains(s)),
        "the refusal must come from a designed gate, not an unrelated error — stderr: {stderr}"
    );

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
    assert_eq!(json_str(&iso, "configured"), "hyperv");
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
        "verified must stay unset on a refused launch: {report_text} (stderr: {stderr})"
    );

    let lifecycle = "{\"tier\":\"product\",\"test\":\"run_image_hyperv_refusal_leaves_nothing_running\",\"unit_id\":null,\"refused\":true}";
    std::fs::write(dirs._root.path().join("lifecycle.json"), lifecycle).unwrap();
}
