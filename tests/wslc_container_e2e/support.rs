//! Shared harness for the PR-28 `wslc` real-machine suite: CLI
//! plumbing, prerequisite gates, fixture/image builds, session
//! dirs and evidence, unit/session helpers, the mount contract,
//! the session driver, and the JSON-RPC wire. See the crate
//! root (`main.rs`) for the asserted contract.

use std::path::{Path, PathBuf};
use std::process::{Command as StdCommand, Stdio};
use std::sync::OnceLock;
use std::time::Instant;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::time::{Duration, timeout};

use mcp_writ::container::guest_report;
use mcp_writ::container::windows_probe::{self, WSLC_MIN_WSL};
use mcp_writ::execution::{TargetArch, TargetOs};

use crate::common;

/// A wslc session VM boot plus possible image pull can take minutes on a
/// cold host; the budget covers that without turning a hang into a pass.
pub const SESSION_TIMEOUT_SECS: u64 = 300;
pub const STOP_TIMEOUT_SECS: u64 = 120;
/// Bounded one-shot CLI calls — a wedged `wslc` must never park the
/// suite. Inventory/status calls only: `wslc run` legs go through
/// [`wslc_bounded`] with [`SESSION_TIMEOUT_SECS`] — any `run` can hit a
/// session-VM cold boot, which minutes-scale exceeds a 30s bound and
/// would misreport a healthy-but-cold host as a refusal.
pub const CLI_TIMEOUT_SECS: u64 = 30;

/// One wslc workload at a time — session-VM boot is heavy and the suite
/// must never run two validation units concurrently on a laptop-class
/// host (same rationale as the kata VM_LOCK).
pub static SESSION_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// ubuntu:24.04 pinned by digest — the same OCI index pin the kata
/// validation records (docs/validation/kata.md); on x86-64 the amd64
/// variant is what the session VM runs.
pub const BASE_IMAGE: &str =
    "ubuntu@sha256:008173c23f95b170204355c12626cb5a965d779a7e1283b09e9cffbb1bf33ca3";

/// The musl cross flags for the guest binaries — identical to the apple
/// suite (`cc` is an MSVC toolchain here; `rust-lld` links musl ELFs).
pub const MUSL_RUSTFLAGS: &str = "-C linker=rust-lld -C linker-flavor=ld.lld";

pub fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/wslc")
}

// ─── CLI plumbing ────────────────────────────────────────────────────

/// Decode a Windows CLI's stdout/stderr: `wsl.exe` emits UTF-16LE when
/// piped, `wslc` emits UTF-8. A NUL in the head is the UTF-16 tell.
pub fn decode_cli(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return String::new();
    }
    let head_nul = bytes.iter().take(64).any(|b| *b == 0);
    if head_nul || bytes.starts_with(&[0xFF, 0xFE]) {
        let u16s: Vec<u16> = bytes
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| u16::from_le_bytes(*c))
            .collect();
        return String::from_utf16_lossy(&u16s)
            .trim_start_matches('\u{feff}')
            .to_string();
    }
    String::from_utf8_lossy(bytes).to_string()
}

/// Run a bounded one-shot `wslc`/`wsl.exe` invocation off the async
/// runtime — spawn + `try_wait` poll + kill, never a plain `wait()`:
/// a wedged CLI is reported, not waited on (the cleanup script's
/// `probe()` convention expressed in-process).
pub fn run_cli(prog: &str, args: &[&str], secs: u64) -> Option<std::process::Output> {
    let mut child = StdCommand::new(prog)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .stdin(Stdio::null())
        .spawn()
        .ok()?;
    let deadline = Instant::now() + Duration::from_secs(secs);
    loop {
        match child.try_wait() {
            Ok(Some(_)) => return child.wait_with_output().ok(),
            Ok(None) => {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    return None;
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
        }
    }
}

/// Run a blocking step (subprocess probe, fixture compile, dir setup)
/// off the async runtime — the same `spawn_blocking` convention as
/// `container_e2e.rs` / `apple_container_vm_e2e.rs`. A panic inside
/// (e.g. a `MCP_WRIT_REQUIRE_*` assertion in `skip_wslc_test`) is
/// re-raised on the test task so required-test failures are never
/// swallowed into a skip.
pub async fn blocking<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> T {
    match tokio::task::spawn_blocking(f).await {
        Ok(v) => v,
        Err(e) => std::panic::resume_unwind(e.into_panic()),
    }
}

/// The wslc CLI to invoke, resolved once with the product's own
/// precedence: `MCP_WRIT_WSLC_EXE` (the override `WslcEngine` honors)
/// → `wslc` on PATH → the stock install dir `C:\Program Files\WSL\
/// wslc.exe`. The stock install does not export PATH — the product's
/// resolver accepts it and the harness must measure the same host.
fn wslc_prog() -> &'static str {
    static PROG: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    PROG.get_or_init(|| {
        if let Some(p) = std::env::var_os("MCP_WRIT_WSLC_EXE") {
            let p = p.to_string_lossy().into_owned();
            if !p.is_empty() {
                return p;
            }
        }
        if run_cli("wslc", &["--version"], CLI_TIMEOUT_SECS).is_some() {
            return "wslc".into();
        }
        let installed = r"C:\Program Files\WSL\wslc.exe";
        if Path::new(installed).is_file() {
            return installed.into();
        }
        "wslc".into()
    })
}

/// `wslc` one-shot with an explicit bound, off the runtime.
pub async fn wslc_bounded(args: &[&str], secs: u64) -> Option<std::process::Output> {
    let args: Vec<String> = args.iter().map(|s| s.to_string()).collect();
    blocking(move || {
        let refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
        run_cli(wslc_prog(), &refs, secs)
    })
    .await
}

/// `wslc` one-shot at the inventory bound, off the runtime. Workload
/// launches (`run`, `system session run`) must use [`wslc_bounded`]
/// with [`SESSION_TIMEOUT_SECS`] instead — see [`CLI_TIMEOUT_SECS`].
pub async fn wslc(args: &[&str]) -> Option<std::process::Output> {
    wslc_bounded(args, CLI_TIMEOUT_SECS).await
}

/// Try each candidate argv (flat `wslc <verb>` then the `wslc container
/// <verb>` noun form the 2.9.x previews expose) until one exits 0 —
/// CLI-dialect drift is recorded, never assumed.
pub async fn wslc_any(candidates: &[Vec<String>]) -> Option<std::process::Output> {
    let mut last: Option<std::process::Output> = None;
    for c in candidates {
        let refs: Vec<&str> = c.iter().map(|s| s.as_str()).collect();
        match wslc(&refs).await {
            Some(o) if o.status.success() => return Some(o),
            other => last = other,
        }
    }
    last
}

pub fn wslc_ok(args: &[&str]) -> Option<std::process::Output> {
    run_cli(wslc_prog(), args, CLI_TIMEOUT_SECS).filter(|o| o.status.success())
}

/// Byte-boundary-safe truncate for evidence records — a multi-byte char
/// boundary would panic a raw slice.
pub fn clip(s: &str, n: usize) -> String {
    if s.len() <= n {
        return s.to_string();
    }
    s.chars().take(n).collect()
}

// ─── prerequisites ───────────────────────────────────────────────────

/// `wsl.exe --version` → the product version triple (e.g. `2.9.3`) plus
/// the kernel and Windows-build fields, for the environment record.
/// Parsing goes through the product probe's localized-label parser —
/// a Japanese host emits `WSL バージョン:` which an English-literal
/// `WSL version` match would silently miss (observed on the PR-28
/// reference host).
pub fn wsl_versions() -> Option<(u64, u64, u64)> {
    let out = run_cli("wsl.exe", &["--version"], CLI_TIMEOUT_SECS)?;
    let text = decode_cli(&out.stdout);
    let parsed = windows_probe::parse_wsl_version(&text);
    let ver = parsed.product?;
    let mut it = ver.split('.');
    Some((
        it.next()?.parse().ok()?,
        it.next()?.parse().ok()?,
        it.next()?.parse().ok()?,
    ))
}

/// The raw `wsl.exe --version` text for evidence.
pub fn wsl_version_text() -> String {
    run_cli("wsl.exe", &["--version"], CLI_TIMEOUT_SECS)
        .map(|o| decode_cli(&o.stdout))
        .unwrap_or_default()
}

pub fn wslc_version_text() -> String {
    run_cli(wslc_prog(), &["--version"], CLI_TIMEOUT_SECS)
        .map(|o| {
            let s = decode_cli(&o.stdout);
            if s.trim().is_empty() {
                decode_cli(&o.stderr)
            } else {
                s
            }
        })
        .unwrap_or_default()
}

/// The documented `wslc` floor is the product probe's own constant —
/// imported from `src/container/windows_probe.rs` (`WSLC_MIN_WSL`) so
/// the two gates cannot drift.
pub fn check_prereqs() -> Option<String> {
    if TargetOs::host() != TargetOs::Windows {
        return Some(format!(
            "wslc validation needs a Windows host — this is {}",
            TargetOs::host().name()
        ));
    }
    if TargetArch::host() != TargetArch::X86_64 {
        return Some(format!(
            "wslc validation starts with Windows x86-64 — this is {}",
            TargetArch::host().name()
        ));
    }
    match wsl_versions() {
        None => {
            return Some(
                "could not parse `wsl.exe --version` — WSL product version unknown".into(),
            );
        }
        Some(v) if v < WSLC_MIN_WSL => {
            return Some(format!(
                "WSL {}.{}.{} is below the documented wslc floor {}.{}.{} — \
                 the suite does not run `wsl --update`",
                v.0, v.1, v.2, WSLC_MIN_WSL.0, WSLC_MIN_WSL.1, WSLC_MIN_WSL.2
            ));
        }
        Some(_) => {}
    }
    match wslc_version_text() {
        t if t.trim().is_empty() => {
            return Some(
                "no `wslc` CLI resolvable (PATH, MCP_WRIT_WSLC_EXE, or the stock install dir — or `wslc --version` produced no output)".into(),
            );
        }
        _ => {}
    }
    None
}

// ─── fixture builds ──────────────────────────────────────────────────

pub const EM_X86_64: u16 = 0x3E;

/// ELF magic + class/data + machine check on a produced binary.
pub fn is_elf(path: &Path, machine: u16) -> bool {
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(_) => return false,
    };
    bytes.len() >= 20
        && bytes[0..4] == [0x7f, b'E', b'L', b'F']
        && bytes[4] == 2 // ELFCLASS64
        && bytes[5] == 1 // little-endian
        && u16::from_le_bytes([bytes[18], bytes[19]]) == machine
}

/// Compile `wslc_probe_server.rs` to a static musl ELF — the guest is a
/// Linux amd64 container regardless of the Windows host toolchain.
/// Artifacts live under `target/wslc-e2e/` so `cargo clean` reaps them;
/// a scratch name + rename keeps a concurrent binary from serving a
/// torn ELF.
pub fn compiled_probe() -> Option<PathBuf> {
    static FIXTURE: OnceLock<Option<PathBuf>> = OnceLock::new();
    FIXTURE
        .get_or_init(|| {
            let src = fixtures_dir().join("wslc_probe_server.rs");
            let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("target/wslc-e2e");
            if let Err(e) = std::fs::create_dir_all(&dir) {
                common::skip_wslc_test(&format!("probe artifact dir failed: {e}"));
                return None;
            }
            let out = dir.join("wslc-probe");
            let tmp = dir.join(format!(".wslc-probe-{}", std::process::id()));
            let status = StdCommand::new("rustc")
                .args(["--target", "x86_64-unknown-linux-musl", "-O", "-C"])
                .arg("linker=rust-lld")
                .args(["-C", "linker-flavor=ld.lld", "-C", "strip=symbols", "-o"])
                .arg(&tmp)
                .arg(&src)
                .stdout(Stdio::null())
                .stderr(Stdio::inherit())
                .status();
            match status {
                Ok(s) if s.success() && is_elf(&tmp, EM_X86_64) => {
                    match std::fs::rename(&tmp, &out) {
                        Ok(()) => Some(out),
                        Err(e) => {
                            let _ = std::fs::remove_file(&tmp);
                            common::skip_wslc_test(&format!("probe artifact rename failed: {e}"));
                            None
                        }
                    }
                }
                Ok(s) => {
                    let _ = std::fs::remove_file(&tmp);
                    common::skip_wslc_test(&format!(
                        "rustc x86_64-unknown-linux-musl wslc_probe_server.rs failed: {s}"
                    ));
                    None
                }
                Err(e) => {
                    common::skip_wslc_test(&format!("rustc unavailable: {e}"));
                    None
                }
            }
        })
        .clone()
}

/// A Linux amd64 `mcp-secure-runner`. The cargo test binary on this
/// host is a Windows PE, so the guest runner is produced by an explicit
/// `x86_64-unknown-linux-musl` cargo build — musl links a fully static
/// binary that runs on the session VM's userland. Release+strip keeps
/// it small; the produced ELF is checked for arch and the
/// `MCP_WRIT_RUNNER_CAPS` marker.
pub fn linux_runner() -> Option<PathBuf> {
    static RUNNER: OnceLock<Option<PathBuf>> = OnceLock::new();
    RUNNER
        .get_or_init(|| {
            let target_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("target");
            let out = target_dir
                .join("x86_64-unknown-linux-musl")
                .join("release")
                .join("mcp-secure-runner");
            let status = StdCommand::new("cargo")
                .args([
                    "build",
                    "--locked",
                    "--release",
                    "--target",
                    "x86_64-unknown-linux-musl",
                    "--bin",
                    "mcp-secure-runner",
                ])
                .arg("--target-dir")
                .arg(&target_dir)
                // Replaces the caller's RUSTFLAGS deliberately — the
                // musl link only works through rust-lld on this host.
                .env("RUSTFLAGS", format!("{MUSL_RUSTFLAGS} -C strip=symbols"))
                .current_dir(env!("CARGO_MANIFEST_DIR"))
                .stdout(Stdio::null())
                .stderr(Stdio::inherit())
                .status();
            match status {
                Ok(s) if s.success() => {}
                Ok(s) => {
                    common::skip_wslc_test(&format!(
                        "cargo build --target x86_64-unknown-linux-musl failed: {s}"
                    ));
                    return None;
                }
                Err(e) => {
                    common::skip_wslc_test(&format!("cargo unavailable: {e}"));
                    return None;
                }
            }
            if !is_elf(&out, EM_X86_64) {
                common::skip_wslc_test("mcp-secure-runner is not an x86_64 ELF binary");
                return None;
            }
            let bytes = std::fs::read(&out).ok()?;
            if guest_report::scan_runner_caps(&bytes).is_none() {
                common::skip_wslc_test("runner has no MCP_WRIT_RUNNER_CAPS marker");
                return None;
            }
            Some(out)
        })
        .clone()
}

// ─── images ──────────────────────────────────────────────────────────

/// `wslc pull <digest-pinned ref>` once per test binary. A puller that
/// cannot pin by digest is itself a finding — the suite records the
/// failure text in the environment record and skips.
pub fn ensure_base_pulled() -> Option<()> {
    static DONE: OnceLock<Option<()>> = OnceLock::new();
    *DONE.get_or_init(|| match run_cli(wslc_prog(), &["pull", BASE_IMAGE], 900) {
        Some(o) if o.status.success() => Some(()),
        Some(o) => {
            common::skip_wslc_test(&format!(
                "wslc pull {BASE_IMAGE} failed: {}",
                decode_cli(&o.stderr)
            ));
            None
        }
        None => {
            common::skip_wslc_test("wslc pull timed out or wslc unavailable");
            None
        }
    })
}

/// `wslc build -t <tag> -f <dockerfile> <ctx>` bounded — a wedged build
/// is killed, never waited on.
pub fn wslc_build(context: &Path, tag: &str, dockerfile: &Path) -> Result<(), String> {
    let ctx = context.to_string_lossy().into_owned();
    let df = dockerfile.to_string_lossy().into_owned();
    match run_cli(wslc_prog(), &["build", "-t", tag, "-f", &df, &ctx], 900) {
        Some(o) if o.status.success() => Ok(()),
        Some(o) => Err(format!(
            "wslc build {tag} failed: {}",
            decode_cli(&o.stderr)
        )),
        None => Err("wslc build timed out or wslc unavailable".into()),
    }
}

/// The probe image: `ENTRYPOINT` is the probe itself; argv selects the
/// substrate-mode command (or nothing → the MCP loop).
pub async fn probe_image(probe: &Path) -> Result<String, String> {
    let work = tempfile::Builder::new()
        .prefix("mcp_writ_wslc_img_")
        .tempdir()
        .map_err(|e| e.to_string())?;
    let dir = work.path();
    std::fs::copy(probe, dir.join("wslc-probe")).map_err(|e| e.to_string())?;
    let df = format!(
        "FROM {BASE_IMAGE}\n\
         COPY wslc-probe /usr/local/bin/wslc-probe\n\
         RUN chmod +x /usr/local/bin/wslc-probe\n\
         ENTRYPOINT [\"/usr/local/bin/wslc-probe\"]\n"
    );
    let df_path = dir.join("Dockerfile");
    std::fs::write(&df_path, df).map_err(|e| e.to_string())?;
    let tag = "mcp-writ-wslc-probe:test";
    blocking({
        let dir = dir.to_path_buf();
        let df_path = df_path.clone();
        move || wslc_build(&dir, tag, &df_path)
    })
    .await?;
    Ok(tag.to_string())
}

/// The secure image, mirroring the product's wrap contract: probe as
/// payload, `mcp-secure-runner` as PID 1, policy baked in, and the
/// runner's capability marker recorded as `MCP_WRIT_RUNNER_CAPS`.
pub async fn secure_image(runner: &Path, probe: &Path, base_tag: &str) -> Result<String, String> {
    let work = tempfile::Builder::new()
        .prefix("mcp_writ_wslc_secure_")
        .tempdir()
        .map_err(|e| e.to_string())?;
    let dir = work.path();
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
    std::fs::copy(runner, dir.join("mcp-secure-runner")).map_err(|e| e.to_string())?;
    std::fs::copy(probe, dir.join("wslc-probe")).map_err(|e| e.to_string())?;
    std::fs::copy(fixtures_dir().join("policy.kdl"), dir.join("policy.kdl"))
        .map_err(|e| e.to_string())?;
    let df = format!(
        "FROM {base_tag}\n\
         COPY mcp-secure-runner /usr/local/bin/mcp-secure-runner\n\
         COPY wslc-probe /usr/local/bin/wslc-probe\n\
         COPY policy.kdl /etc/mcp-secure/policy.kdl\n\
         RUN mkdir -p /var/log/mcp-secure /workspace /run/mcp-secure/report \
         && chmod +x /usr/local/bin/mcp-secure-runner /usr/local/bin/wslc-probe\n\
         ENV MCP_ORIG_ENTRYPOINT=\"[\\\"/usr/local/bin/wslc-probe\\\"]\" MCP_ORIG_CMD=\"\" \
         MCP_WRIT_ENV=\"\" MCP_WRIT_SERVER=\"wslc-probe\" MCP_WRIT_SKIP_SANDBOX=\"\" MCP_WRIT_FAIL_ON=\"\"\n\
         ENV MCP_WRIT_RUNNER_CAPS='{caps_json}'\n\
         ENTRYPOINT [\"/usr/local/bin/mcp-secure-runner\"]\n"
    );
    let df_path = dir.join("Dockerfile");
    std::fs::write(&df_path, df).map_err(|e| e.to_string())?;
    let tag = "mcp-writ-wslc-probe-secure:test";
    blocking({
        let dir = dir.to_path_buf();
        let df_path = df_path.clone();
        move || wslc_build(&dir, tag, &df_path)
    })
    .await?;
    Ok(tag.to_string())
}

/// The two images the suite needs — build once per test binary.
pub static IMAGES: tokio::sync::OnceCell<Result<(String, String), String>> =
    tokio::sync::OnceCell::const_new();

pub async fn shared_images(runner: &Path, probe: &Path) -> Result<(String, String), String> {
    IMAGES
        .get_or_init(|| async {
            let base = probe_image(probe).await?;
            let secure = secure_image(runner, probe, &base).await?;
            Ok((base, secure))
        })
        .await
        .clone()
}

// ─── session dirs / evidence ─────────────────────────────────────────

pub struct SessionDirs {
    pub _root: tempfile::TempDir,
    pub workspace: PathBuf,
    pub logs: PathBuf,
    pub report: PathBuf,
    /// Own dir holding only `policy.kdl` — mounted at `/etc/mcp-secure`
    /// when the substrate cannot bind a single file.
    pub policy_dir: PathBuf,
    pub policy: PathBuf,
}

/// Evidence the validation job retains per session: guest + host launch
/// reports, the audit trail, and the test's own records — never staged
/// executables, workspace payloads, or RPC bodies.
pub const SESSION_EVIDENCE: &[&str] = &[
    "metrics.json",
    "lifecycle.json",
    "host-identity.json",
    "capability-map.json",
    "stdio-contract.json",
    "session-model.json",
    "share-semantics.json",
    "network-semantics.json",
    "storage.json",
    "mrtr.json",
    "perf-stats.json",
    "product.json",
    "report/report.json",
    "logs/audit.jsonl",
];

impl Drop for SessionDirs {
    fn drop(&mut self) {
        common::copy_session_evidence(
            "MCP_WRIT_WSLC_EVIDENCE_DIR",
            self._root.path(),
            SESSION_EVIDENCE,
        );
    }
}

/// Scratch root: the validation job's `MCP_WRIT_WSLC_TEST_ROOT`, else
/// `target/wslc-tests` under the checkout. Shares cross into the guest
/// over virtiofs, so any NTFS path on a normal drive is shareable —
/// unlike Kata-on-WSL2 there is no `/mnt/*` drvfs restriction.
pub fn test_root() -> PathBuf {
    common::vm_test_root("MCP_WRIT_WSLC_TEST_ROOT", "wslc-tests")
}

/// Storage root for *dedicated* sessions (`wslc system session enter
/// <path>`): the validation job's `MCP_WRIT_WSLC_SESSION_ROOT`, else a
/// `session-storage` dir under the test root. The session VHD and its
/// image store live here — fully test-owned, so cleanup may delete it.
pub fn session_storage_root() -> PathBuf {
    let root = std::env::var_os("MCP_WRIT_WSLC_SESSION_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|| test_root().join("session-storage"));
    std::fs::create_dir_all(&root).expect("create wslc session storage root");
    root
}

/// Locate an existing session store (`<base>\wslc\sessions\<name>\
/// storage.vhdx`). `system session enter` never *creates* session
/// storage — the manager calls `EnterSession` with
/// `WSLCSessionStorageFlagsNoCreate`, so a dedicated session needs a
/// VHD pre-seeded from another session's store (fresh-store creation
/// is SDK-only via `WslcCreateSession`). Bases checked: a configured
/// `session.storagePath` in `%LOCALAPPDATA%\wslc\settings.yaml`, then
/// `%LOCALAPPDATA%` itself (the built-in default).
pub fn session_store_vhdx() -> Option<PathBuf> {
    let local = std::env::var_os("LOCALAPPDATA").map(PathBuf::from)?;
    let mut bases = vec![local.clone()];
    let settings = local.join("wslc").join("settings.yaml");
    if let Ok(text) = std::fs::read_to_string(&settings) {
        for line in text.lines() {
            if let Some(v) = line.trim().strip_prefix("storagePath:") {
                let v = v.trim().trim_matches('"').trim_matches('\'');
                if !v.is_empty() && v != "default" {
                    bases.insert(0, PathBuf::from(v));
                }
            }
        }
    }
    for base in bases {
        let sessions = base.join("wslc").join("sessions");
        if let Ok(rd) = std::fs::read_dir(&sessions) {
            for e in rd.flatten() {
                let vhdx = e.path().join("storage.vhdx");
                if vhdx.is_file() {
                    return Some(vhdx);
                }
            }
        }
    }
    None
}

/// Seed `dir` as an enterable session store: `enter` only reattaches
/// existing storage (NoCreate), so the dedicated session's dir must
/// already hold a `storage.vhdx` — cloned here from the default
/// session's. The copy is crash-consistent against a live source,
/// which the guest ext4 tolerates.
pub fn seed_session_store(dir: &Path) -> bool {
    session_store_vhdx()
        .and_then(|src| {
            std::fs::copy(src, dir.join("storage.vhdx"))
                .ok()
                .map(|_| ())
        })
        .is_some()
}

pub fn session_dirs() -> SessionDirs {
    let root = tempfile::Builder::new()
        .prefix("mcp_writ_wslc_run_")
        .tempdir_in(test_root())
        .expect("session tempdir");
    let workspace = root.path().join("workspace");
    let logs = root.path().join("logs");
    let report = root.path().join("report");
    let policy_dir = root.path().join("policy");
    for d in [&workspace, &logs, &report, &policy_dir] {
        std::fs::create_dir_all(d).expect("session dir");
    }
    let policy = policy_dir.join("policy.kdl");
    std::fs::copy(fixtures_dir().join("policy.kdl"), &policy).expect("copy policy");
    SessionDirs {
        _root: root,
        workspace,
        logs,
        report,
        policy_dir,
        policy,
    }
}

// ─── wslc unit / session helpers ─────────────────────────────────────

/// `wslc system session list` raw table rows (ID | CreatorPid |
/// DisplayName) — recorded verbatim; a parse failure is a finding.
/// Dialect-tolerant like the other helpers: the GA noun form first,
/// then the plausible flat/`ls` spellings a renamed surface might take.
pub async fn session_list_raw() -> String {
    wslc_any(&[
        vec!["system".into(), "session".into(), "list".into()],
        vec!["session".into(), "list".into()],
        vec!["system".into(), "session".into(), "ls".into()],
    ])
    .await
    .map(|o| decode_cli(&o.stdout))
    .unwrap_or_default()
}

/// `wslc info --format json` (GA surface; previews may only have
/// `system info`) — tolerated both ways and recorded either way.
pub async fn wslc_info_json() -> Option<String> {
    wslc_any(&[
        vec!["info".into(), "--format".into(), "json".into()],
        vec![
            "system".into(),
            "info".into(),
            "--format".into(),
            "json".into(),
        ],
    ])
    .await
    .filter(|o| !o.stdout.is_empty())
    .map(|o| decode_cli(&o.stdout))
}

/// `wslc list -a --no-trunc` (flat) / `wslc container list -a
/// --no-trunc` (noun) — does a unit name appear anywhere in the
/// listing? `--no-trunc` is required: the default table truncates the
/// name column with an ellipsis (measured on 3.0.1 — a `mcp-writ-*`
/// name never survives the column width), so an untruncated surface is
/// the only one a substring match may check. The pre-flag forms stay
/// as fallbacks for preview dialects.
pub async fn unit_listed(name: &str) -> bool {
    wslc_any(&[
        vec!["list".into(), "-a".into(), "--no-trunc".into()],
        vec![
            "container".into(),
            "list".into(),
            "-a".into(),
            "--no-trunc".into(),
        ],
        vec!["list".into(), "-a".into()],
        vec!["container".into(), "list".into(), "-a".into()],
    ])
    .await
    .map(|o| decode_cli(&o.stdout).contains(name))
    .unwrap_or(false)
}

/// `wslc inspect <name>` — raw text + a loose state token
/// (`running`/`exited`/…) extracted for assertions.
pub async fn unit_state(name: &str) -> Option<String> {
    let out = wslc_any(&[
        vec!["inspect".into(), name.into()],
        vec!["container".into(), "inspect".into(), name.into()],
    ])
    .await?;
    let text = decode_cli(&out.stdout);
    for needle in ["running", "exited", "stopped", "created", "dead"] {
        if text.contains(&format!("\"{needle}\"")) || text.contains(&format!(":{needle}")) {
            return Some(needle.to_string());
        }
    }
    Some(format!("unparsed:{}", clip(&text, 200)))
}

/// `wslc kill <name> [-s|--signal] <sig>` — the signal flag's exact
/// spelling is a recorded surface detail; try `-s`, fall back to
/// `--signal`, then the noun form.
pub async fn unit_kill(name: &str, sig: &str) -> bool {
    wslc_any(&[
        vec!["kill".into(), name.into(), "-s".into(), sig.into()],
        vec!["kill".into(), name.into(), "--signal".into(), sig.into()],
        vec![
            "container".into(),
            "kill".into(),
            name.into(),
            "-s".into(),
            sig.into(),
        ],
        vec![
            "container".into(),
            "kill".into(),
            name.into(),
            "--signal".into(),
            sig.into(),
        ],
    ])
    .await
    .map(|o| o.status.success())
    .unwrap_or(false)
}

/// `wslc rm -f <name>` — owned-unit removal.
pub async fn unit_rm(name: &str) -> bool {
    wslc_any(&[
        vec!["rm".into(), "-f".into(), name.into()],
        vec!["container".into(), "rm".into(), "-f".into(), name.into()],
    ])
    .await
    .map(|o| o.status.success())
    .unwrap_or(false)
}

/// `wslc logs <name>` — the detached unit's captured output.
pub async fn unit_logs(name: &str) -> String {
    wslc_any(&[
        vec!["logs".into(), name.into()],
        vec!["container".into(), "logs".into(), name.into()],
    ])
    .await
    .map(|o| decode_cli(&o.stdout))
    .unwrap_or_default()
}

/// Removes the named unit on drop — including on panic — so a failed
/// assertion cannot leave a running workload behind.
pub struct UnitGuard(pub String);

impl Drop for UnitGuard {
    fn drop(&mut self) {
        if wslc_ok(&["rm", "-f", self.0.as_str()]).is_none() {
            let _ = wslc_ok(&["container", "rm", "-f", self.0.as_str()]);
        }
    }
}

/// Poll `f` until it holds or `secs` elapse.
pub async fn poll<Fut>(secs: u64, ms: u64, mut f: impl FnMut() -> Fut) -> bool
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

// ─── mount contract ──────────────────────────────────────────────────

/// How host shares cross the boundary — the arg spellings that produced
/// a visible virtiofs mount in a probe leg. Resolved once by measuring
/// the substrate, then reused by every mounting test.
#[derive(Clone, Copy)]
pub struct MountContract {
    /// `-v h:g[:ro]` works.
    pub dash_v: bool,
    /// `--mount type=bind,source=h,target=g[,readonly]` works.
    pub long_mount: bool,
    /// A single file mounts (not just directories).
    pub file_mounts: bool,
    /// `:ro`/`readonly` is honored (write inside guest denied).
    pub ro_honored: bool,
}

pub fn mount_args(c: &MountContract, host: &Path, guest: &str, ro: bool) -> Vec<String> {
    let h = host.display().to_string();
    if c.dash_v {
        vec![
            "-v".into(),
            format!("{h}:{guest}{}", if ro { ":ro" } else { "" }),
        ]
    } else {
        vec![
            "--mount".into(),
            format!(
                "type=bind,source={h},target={guest}{}",
                if ro { ",readonly" } else { "" }
            ),
        ]
    }
}

/// `wslc run --rm <args…> <probe-image> <probe-cmd>` — a one-shot
/// substrate probe. Returns (success, stdout, stderr). Bounded by
/// [`SESSION_TIMEOUT_SECS`]: any `run` can trigger a session-VM cold
/// boot, which the 30s inventory bound would misreport as a refusal.
pub async fn probe_run(args: &[String], image: &str, cmd: &[&str]) -> (bool, String, String) {
    let mut all: Vec<String> = vec!["run".into(), "--rm".into()];
    all.extend(args.iter().cloned());
    all.push(image.into());
    all.extend(cmd.iter().map(|s| s.to_string()));
    let argrefs: Vec<&str> = all.iter().map(|s| s.as_str()).collect();
    match wslc_bounded(&argrefs, SESSION_TIMEOUT_SECS).await {
        Some(o) => (
            o.status.success(),
            decode_cli(&o.stdout),
            decode_cli(&o.stderr),
        ),
        None => (false, String::new(), "wslc timed out".into()),
    }
}

/// `wslc --session <name> run --rm <args> <img> <cmd>` — scoped probe
/// run. Same session budget as [`probe_run`]: a scoped `run` can still
/// hit session-VM setup, which the 30s inventory bound would misreport.
pub async fn probe_run_scoped(
    session: &str,
    args: &[String],
    image: &str,
    cmd: &[&str],
) -> (bool, String, String) {
    let mut all: Vec<String> = vec![
        "--session".into(),
        session.into(),
        "run".into(),
        "--rm".into(),
    ];
    all.extend(args.iter().cloned());
    all.push(image.into());
    all.extend(cmd.iter().map(|s| s.to_string()));
    let argrefs: Vec<&str> = all.iter().map(|s| s.as_str()).collect();
    match wslc_bounded(&argrefs, SESSION_TIMEOUT_SECS).await {
        Some(o) => (
            o.status.success(),
            decode_cli(&o.stdout),
            decode_cli(&o.stderr),
        ),
        None => (false, String::new(), "wslc timed out".into()),
    }
}

/// Measure the mount contract once per test binary: which spelling
/// produces a real mount, whether `:ro` is honored, whether a single
/// file mounts. Each leg's raw output lands in `capability-map.json`.
pub async fn mount_contract(image: &str) -> MountContract {
    static CONTRACT: tokio::sync::OnceCell<MountContract> = tokio::sync::OnceCell::const_new();
    CONTRACT
        .get_or_init(|| async {
            let probe_dir = test_root().join("mount-probe");
            std::fs::create_dir_all(&probe_dir).expect("mount probe dir");
            std::fs::write(probe_dir.join("marker.txt"), "wslc-mount-probe")
                .expect("mount probe marker");
            let mut c = MountContract {
                dash_v: false,
                long_mount: false,
                file_mounts: false,
                ro_honored: false,
            };
            // -v directory mount
            let args = vec!["-v".into(), format!("{}:/mnt/probe", probe_dir.display())];
            let (ok, out, _) = probe_run(&args, image, &["share-probe", "/mnt/probe"]).await;
            c.dash_v = ok && out.contains("marker.txt");
            if !c.dash_v {
                let args = vec![
                    "--mount".into(),
                    format!("type=bind,source={},target=/mnt/probe", probe_dir.display()),
                ];
                let (ok, out, _) = probe_run(&args, image, &["share-probe", "/mnt/probe"]).await;
                c.long_mount = ok && out.contains("marker.txt");
            }
            // RO on the winning form
            if c.dash_v || c.long_mount {
                let args = mount_args(&c, &probe_dir, "/mnt/probe", true);
                let (_, out, _) = probe_run(&args, image, &["share-probe", "/mnt/probe"]).await;
                c.ro_honored = out.contains("write=failed");
                // single file mount
                let file = probe_dir.join("marker.txt");
                let args = mount_args(&c, &file, "/mnt/probe-file", true);
                let (ok, out, _) =
                    probe_run(&args, image, &["share-probe", "/mnt/probe-file"]).await;
                // `mount=` alone is not proof — an unmounted path still
                // prints the covering rootfs entry. The run must have
                // succeeded AND `share-probe` read the marker back.
                c.file_mounts = ok && out.contains("head=wslc-mount-probe");
            }
            c
        })
        .await
        .to_owned()
}

// ─── session driver ──────────────────────────────────────────────────

/// The `wslc run` argument list against the *secure* image — the wrap
/// product form: baked runner entrypoint + `MCP_ORIG_*` envs carry the
/// contract, the per-run mount/env surface is policy (:ro), workspace,
/// audit log, guest report, launch id — the same shape the Kata/Apple
/// sessions drive. The policy mount is a single file where the
/// substrate supports it, its holding dir at `/etc/mcp-secure` where it
/// does not (recorded via `mount_contract.file_mounts`).
pub fn session_run_args(
    dirs: &SessionDirs,
    launch_id: &str,
    contract: &MountContract,
    name: &str,
    secure_image: &str,
) -> Vec<String> {
    let mut v: Vec<String> = vec![
        "run".into(),
        "-i".into(),
        "--rm".into(),
        "--name".into(),
        name.into(),
        "--no-healthcheck".into(),
        "-e".into(),
        "MCP_WRIT_ENV=".into(),
        "-e".into(),
        "MCP_WRIT_SKIP_SANDBOX=".into(),
        "-e".into(),
        "MCP_WRIT_SERVER=wslc-probe".into(),
        "-e".into(),
        format!("MCP_WRIT_LAUNCH_ID={launch_id}"),
        "-e".into(),
        format!(
            "{}={}",
            guest_report::REPORT_OUT_ENV,
            guest_report::GUEST_REPORT_MOUNT_PATH
        ),
    ];
    if contract.file_mounts {
        v.extend(mount_args(
            contract,
            &dirs.policy,
            "/etc/mcp-secure/policy.kdl",
            true,
        ));
    } else {
        // The baked policy is overmounted by the holding dir — either
        // way the runner reads /etc/mcp-secure/policy.kdl.
        v.extend(mount_args(
            contract,
            &dirs.policy_dir,
            "/etc/mcp-secure",
            true,
        ));
    }
    v.extend(mount_args(contract, &dirs.workspace, "/workspace", false));
    v.extend(mount_args(
        contract,
        &dirs.logs,
        "/var/log/mcp-secure",
        false,
    ));
    v.extend(mount_args(
        contract,
        &dirs.report,
        guest_report::GUEST_REPORT_MOUNT_PATH,
        false,
    ));
    v.push(secure_image.into());
    v
}

/// One request/response round-trip tracked by id — same convention as
/// the kata/apple sessions.
pub struct Wire {
    pub lines: Vec<String>,
    pub reader: BufReader<tokio::process::ChildStdout>,
    pub writer: Option<tokio::process::ChildStdin>,
}

impl Wire {
    pub async fn send(&mut self, line: &str) {
        let w = self.writer.as_mut().expect("stdin is still open");
        w.write_all(line.as_bytes()).await.expect("write request");
        w.write_all(b"\n").await.expect("write newline");
        w.flush().await.expect("flush request");
    }

    pub async fn wait_id(&mut self, id: i64, secs: u64) -> Option<String> {
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

    /// Read lines until one contains `prefix` — wslc may emit session
    /// creation or pull chatter on stdout before the probe's first line.
    pub async fn wait_for_prefix(&mut self, prefix: &str, secs: u64) -> Option<String> {
        let deadline = Instant::now() + Duration::from_secs(secs);
        while let Some(line) = self
            .next_line(
                deadline
                    .checked_duration_since(Instant::now())?
                    .as_secs()
                    .max(1),
            )
            .await
        {
            if line.contains(prefix) {
                return Some(line);
            }
        }
        None
    }

    pub async fn next_line(&mut self, secs: u64) -> Option<String> {
        let deadline = Instant::now() + Duration::from_secs(secs);
        loop {
            if let Some(l) = self.lines.first() {
                let l = l.clone();
                self.lines.remove(0);
                return Some(l);
            }
            let remaining = deadline.checked_duration_since(Instant::now())?;
            let mut buf = String::new();
            match timeout(remaining, self.reader.read_line(&mut buf)).await {
                Ok(Ok(0)) => return None,
                Ok(Ok(_)) => self.lines.push(buf),
                Ok(Err(_)) | Err(_) => return None,
            }
        }
    }

    /// Signal EOF on stdin while keeping `self` — and therefore the
    /// stdout reader — alive.
    pub fn close_stdin(&mut self) {
        drop(self.writer.take());
    }
}

pub fn frame_id(line: &str) -> Option<i64> {
    mcp_writ::protocol::jsonrpc_id_as_i64(line)
}

pub fn request(id: i64, method: &str, params: &str) -> String {
    format!("{{\"jsonrpc\":\"2.0\",\"id\":{id},\"method\":\"{method}\",\"params\":{params}}}")
}

pub fn tool_call(id: i64, name: &str, args: &str) -> String {
    request(
        id,
        "tools/call",
        &format!("{{\"name\":\"{name}\",\"arguments\":{args}}}"),
    )
}

pub fn json_str(s: &str) -> String {
    let mut out = String::from("\"");
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

// ─── shared filesystem helpers ───

/// One-level dir listing (`name:size` entries) for the storage record.
pub fn dir_listing(dir: &Path) -> String {
    match std::fs::read_dir(dir) {
        Ok(rd) => rd
            .filter_map(|e| {
                let e = e.ok()?;
                let size = e.metadata().ok().map(|m| m.len()).unwrap_or(0);
                Some(format!("{}:{}", e.file_name().to_string_lossy(), size))
            })
            .collect::<Vec<_>>()
            .join(","),
        Err(e) => format!("unreadable:{e}"),
    }
}
