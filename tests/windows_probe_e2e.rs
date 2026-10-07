//! PR-27 e2e: `plan` Windows/WSL edition-and-capability diagnostics.
//!
//! The probes behind `host.os`, `wsl.*`, `wslc.*`, and `wsb.store` are
//! exercised end-to-end through the `MCP_WRIT_*_EXE` overrides the
//! probe layer exposes, with `tests/fixtures/windows_probe_stub.rs`
//! playing every probed CLI from a `scenario.txt` payload file. That
//! keeps the evidence-tier contract verifiable on any CI host: presence
//! (the binary resolves), version facts (what `--version` answered),
//! and the runtime contract (`plan` never exercises it — a skipped
//! check, never a claim).
//!
//! The scenarios under test are the ones the PR-27 contract calls out:
//! legacy/inbox WSL (`--version` fails), WSL below the WSL Containers
//! floor, WSLC absent, a disabled WSL feature, an unparseable version
//! answer, UTF-16 output, and the non-Windows guarantee that native
//! diagnostics spawn no Windows tools at all.

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::OnceLock;

use tempfile::TempDir;
use tokio::process::Command;
use tokio::time::{Duration, timeout};

mod common;

const TIMEOUT_SECS: u64 = 30;
const IMAGE: &str = "app:latest";

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_mcp-writ")
}

/// Compile the probe stub once per test binary — same contract as
/// `common::compiled_open_path_fixture` / the wsb `compiled_fixture`.
fn compiled_stub() -> Option<PathBuf> {
    static STUB: OnceLock<Option<PathBuf>> = OnceLock::new();
    STUB.get_or_init(|| {
        let src =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/windows_probe_stub.rs");
        let dir = match tempfile::Builder::new()
            .prefix("mcp_writ_wslstub_build_")
            .tempdir()
        {
            Ok(d) => d,
            Err(e) => {
                common::skip_e2e_test(&format!("stub build tempdir failed: {e}"));
                return None;
            }
        };
        let name = if cfg!(windows) {
            "probe-stub.exe"
        } else {
            "probe-stub"
        };
        let out = dir.path().join(name);
        let status = std::process::Command::new("rustc")
            .args(["--edition", "2021", "-O", "-o"])
            .arg(&out)
            .arg(&src)
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .status();
        match status {
            Ok(s) if s.success() && out.exists() => Some(dir.keep().join(name)),
            Ok(s) => {
                common::skip_e2e_test(&format!("rustc windows_probe_stub.rs failed: {s}"));
                None
            }
            Err(e) => {
                common::skip_e2e_test(&format!("rustc unavailable: {e}"));
                None
            }
        }
    })
    .clone()
}

/// Build a scenario directory: `scenario.txt` plus stub copies under
/// the CLI names the probes resolve. `tools` names the *installed*
/// CLIs — an env override pointing at a missing file reads as absent,
/// which is how "not installed" stays deterministic on every host.
fn scenario_dir(stub: &Path, scenario: &str, tools: &[&str]) -> TempDir {
    let dir = tempfile::tempdir().expect("scenario tempdir");
    std::fs::write(dir.path().join("scenario.txt"), scenario).expect("write scenario");
    for tool in tools {
        std::fs::copy(stub, dir.path().join(format!("{tool}.exe")))
            .unwrap_or_else(|e| panic!("copy stub as {tool}.exe: {e}"));
    }
    dir
}

fn write_policy(dir: &TempDir) -> PathBuf {
    let path = dir.path().join("policy.kdl");
    std::fs::write(&path, common::sandboxed_policy("", "")).expect("write policy");
    path
}

/// `plan --engine wslc --image <ref>` with every probe override
/// pointing into the scenario dir — missing copies read as "not
/// installed".
async fn plan_wslc(scenario: &TempDir, policy: &Path) -> std::process::Output {
    let mut cmd = Command::new(bin());
    cmd.args([
        "plan",
        "--engine",
        "wslc",
        "--image",
        IMAGE,
        "--allow-mutable-tag",
        "--policy",
        policy.to_str().expect("policy path utf-8"),
    ])
    .env("MCP_WRIT_WSL_EXE", scenario.path().join("wsl.exe"))
    .env("MCP_WRIT_WSLC_EXE", scenario.path().join("wslc.exe"))
    .env("MCP_WRIT_REG_EXE", scenario.path().join("reg.exe"))
    .env("MCP_WRIT_PWSH_EXE", scenario.path().join("powershell.exe"))
    .env_remove("MCP_WRIT_SKIP_SANDBOX")
    .stdin(Stdio::null())
    .stdout(Stdio::piped())
    .stderr(Stdio::piped());
    timeout(Duration::from_secs(TIMEOUT_SECS), cmd.output())
        .await
        .expect("plan timed out — diagnostics must never wait on a workload")
        .expect("run mcp-writ plan")
}

fn plan_json(stdout: &[u8]) -> nojson::RawJson<'static> {
    let s = String::from_utf8(stdout.to_vec()).expect("utf8 stdout");
    nojson::RawJson::parse(Box::leak(s.trim().to_string().into_boxed_str()))
        .expect("stdout must be the plan JSON result")
}

fn member<'j>(v: nojson::RawJsonValue<'j, 'j>, key: &str) -> nojson::RawJsonValue<'j, 'j> {
    v.to_member(key)
        .unwrap_or_else(|_| panic!("member '{key}' must exist"))
        .required()
        .unwrap_or_else(|_| panic!("member '{key}' must exist"))
}

fn check<'j>(json: &'j nojson::RawJson<'j>, id: &str) -> Option<nojson::RawJsonValue<'j, 'j>> {
    member(json.value(), "checks")
        .to_array()
        .unwrap()
        .find(|c| member(*c, "id").as_string_str().unwrap() == id)
}

fn check_status(json: &nojson::RawJson, id: &str) -> String {
    member(
        check(json, id).unwrap_or_else(|| panic!("check '{id}' must be present")),
        "status",
    )
    .as_string_str()
    .unwrap()
    .to_string()
}

fn check_detail(json: &nojson::RawJson, id: &str) -> String {
    let c = check(json, id).unwrap_or_else(|| panic!("check '{id}' must be present"));
    // Details carry Windows paths (`\\` escapes) — the unquoting
    // accessor, not the raw-string one.
    c.to_member("detail")
        .ok()
        .and_then(|m| m.optional())
        .and_then(|d| d.to_unquoted_string_str().ok().map(|s| s.into_owned()))
        .unwrap_or_else(|| panic!("check '{id}' has no readable detail"))
}

// ─── scenarios ──────────────────────────────────────────────────────────

const GOOD: &str = "\
=== wsl.version ===
WSL version: 3.0.1
Kernel version: 6.6.36.3-1
WSLg version: 1.0.65
Windows version: 10.0.26200.9457
=== wsl.list ===
  NAME            STATE     VERSION
* Ubuntu-24.04    Running   2
  docker-desktop  Stopped   2
=== wslc.version ===
wslc version 0.1.0+abc1234
=== reg.query ===
HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion
    ProductName    REG_SZ    Windows 11 Pro
    EditionID    REG_SZ    Professional
    DisplayVersion    REG_SZ    25H2
    CurrentBuild    REG_SZ    26200
    UBR    REG_DWORD    0x24f1
=== pwsh.package ===
Microsoft.WindowsSandbox 1.0.5.0
";

/// Inbox/legacy WSL: `wsl.exe` resolves but `--version` is not a
/// contract it implements — the binary presence and the version
/// contract stay separate tiers.
const OLD_WSL: &str = "\
=== wsl.version ===
Invalid command line option: --version
=== wsl.version.exit ===
1
=== wsl.list ===
Invalid command line option: -v
=== wsl.list.exit ===
1
";

/// Store WSL below the WSL Containers floor (≥ 2.9.3).
const BELOW_FLOOR: &str = "\
=== wsl.version ===
WSL version: 2.4.12.0
Kernel version: 5.15.167.4-1
=== wsl.list ===
  NAME      STATE     VERSION
* Ubuntu    Running   2
";

/// WSL healthy but `wslc.exe` absent — the *candidate* tier.
const NO_WSLC: &str = "\
=== wsl.version ===
WSL version: 3.0.1
Kernel version: 6.6.36.3-1
=== wsl.list ===
  NAME      STATE     VERSION
* Ubuntu    Running   2
";

/// The feature is disabled: `wsl.exe` answers every probe with a
/// localized "not enabled" error on stderr.
const DISABLED: &str = "\
=== wsl.version ===
The Windows Subsystem for Linux is not enabled.
=== wsl.version.exit ===
1
=== wsl.list ===
The Windows Subsystem for Linux is not enabled.
=== wsl.list.exit ===
1
";

/// `wsl --version` answers but the layout is unrecognized — an
/// unverified version is recorded as such, never guessed.
const UNKNOWN_VERSION: &str = "\
=== wsl.version ===
This is not a recognized version report
=== wsl.list ===
  NAME      STATE     VERSION
* Ubuntu    Running   2
";

/// The WSL product line in UTF-16LE with a BOM — what `wsl.exe`
/// actually emits on several builds when piped.
const UTF16: &str = "\
=== wsl.version ===
WSL version: 3.0.1
Kernel version: 6.6.36.3-1
=== wsl.version.utf16 ===
1
=== wsl.list ===
  NAME      STATE     VERSION
* Ubuntu    Running   2
=== wslc.version ===
wslc version 0.1.0
";

/// `wsl --version` floods stdout past the probe's output cap and keeps
/// producing — the writer blocks on the full pipe, so the probe must
/// kill it and record the output-limit failure, not wait the deadline
/// out and report a timeout.
const FLOOD: &str = "\
=== wsl.version ===
noise
=== wsl.version.flood ===
1
=== wsl.list ===
  NAME      STATE     VERSION
* Ubuntu    Running   2
";

/// `wsl -l -v` with zero registered distros answers localized guidance
/// prose with no table rows — a "no distros" answer, not an
/// unparseable format.
const ZERO_DISTROS: &str = "\
=== wsl.version ===
WSL version: 3.0.1
Kernel version: 6.6.36.3-1
=== wsl.list ===
Windows Subsystem for Linux has no installed distributions.
Distributions can be installed by visiting the Microsoft Store:
https://aka.ms/wslstore
=== wslc.version ===
wslc version 0.1.0
";

/// A `wsl -l -v` answer holding row-shaped lines the parser cannot
/// read (a mode value outside the 1|2 contract) stays a warning — an
/// unrecognized layout is recorded, never assumed to be "no distros".
const UNPARSEABLE_LIST: &str = "\
=== wsl.version ===
WSL version: 3.0.1
=== wsl.list ===
  NAME      STATE     VERSION
* Ubuntu    Running   3
=== wslc.version ===
wslc version 0.1.0
";

/// A failing CLI that reports its error on stdout instead of stderr —
/// the probe must record the message whichever stream it arrived on.
const STDOUT_ERROR: &str = "\
=== wsl.version ===
wsl : The service is not responding
=== wsl.version.exit ===
1
=== wsl.version.exitout ===
1
=== wsl.list ===
  NAME      STATE     VERSION
* Ubuntu    Running   2
";

// ─── tests ──────────────────────────────────────────────────────────────

/// The healthy-WSL environment: every evidence tier recorded, and the
/// plan still blocked because the stub's `wslc --version` answer is off
/// the validated 3.0.x line — an unverified engine version refuses the
/// launch, never a silent fallback or a claimed launch.
#[tokio::test]
async fn wslc_plan_records_environment_and_refuses_launch() {
    let Some(stub) = compiled_stub() else {
        return;
    };
    let scenario = scenario_dir(&stub, GOOD, &["wsl", "wslc", "reg", "powershell"]);
    let dir = tempfile::tempdir().unwrap();
    let policy = write_policy(&dir);

    let out = plan_wslc(&scenario, &policy).await;
    assert_eq!(out.status.code(), Some(1), "blocked exits 1: {out:?}");
    let json = plan_json(&out.stdout);
    assert_eq!(
        member(json.value(), "status").as_string_str().unwrap(),
        "blocked"
    );

    // The report names the diagnosed host — recorded on every plan
    // result. On Windows the reg.exe stub adds edition/build facts.
    assert_eq!(check_status(&json, "host.os"), "pass");
    assert!(
        !check_detail(&json, "host.os").is_empty(),
        "host.os must name the diagnosed host"
    );
    if cfg!(windows) {
        assert!(
            check_detail(&json, "host.os").contains("build=26200.9457"),
            "host.os: {}",
            check_detail(&json, "host.os")
        );
    }

    // The requested (not resolved) engine identity is recorded.
    let target = member(json.value(), "target");
    assert_eq!(member(target, "engine").as_string_str().unwrap(), "wslc");
    // The launch refuses: an answered-but-unvalidated version is an
    // unusable engine, recorded with the reason. Off Windows the
    // production lib has no wslc launch path at all, so resolution
    // refuses earlier — at the host gate, before the version answer.
    assert_eq!(check_status(&json, "engine.resolve"), "fail");
    if cfg!(windows) {
        assert!(
            check_detail(&json, "engine.resolve").contains("unrecognized"),
            "engine.resolve: {}",
            check_detail(&json, "engine.resolve")
        );
    } else {
        assert!(
            check_detail(&json, "engine.resolve").contains("Windows host"),
            "engine.resolve: {}",
            check_detail(&json, "engine.resolve")
        );
    }

    // Environment evidence — each tier in its own check.
    assert_eq!(check_status(&json, "wsl.cli"), "pass");
    assert_eq!(check_status(&json, "wsl.product"), "pass");
    assert!(
        check_detail(&json, "wsl.product").contains("3.0.1"),
        "wsl.product: {}",
        check_detail(&json, "wsl.product")
    );
    assert!(
        check_detail(&json, "wsl.product").contains("6.6.36"),
        "the guest kernel is its own fact: {}",
        check_detail(&json, "wsl.product")
    );
    assert_eq!(check_status(&json, "wsl.distro"), "pass");
    assert!(
        check_detail(&json, "wsl.distro").contains("Ubuntu-24.04"),
        "wsl.distro: {}",
        check_detail(&json, "wsl.distro")
    );
    // The version answer is recorded verbatim but flagged: off the
    // validated line, the check is a warning, not a pass.
    assert_eq!(check_status(&json, "wslc.cli"), "warn");
    assert!(
        check_detail(&json, "wslc.cli").contains("0.1.0"),
        "wslc.cli: {}",
        check_detail(&json, "wslc.cli")
    );
    // The runtime contract is never probed — a skipped record, not a
    // claim, and never unit=vm by implication.
    assert_eq!(check_status(&json, "wslc.runtime"), "skipped");
    assert!(
        check_detail(&json, "wslc.runtime").contains("unverified"),
        "wslc.runtime: {}",
        check_detail(&json, "wslc.runtime")
    );

    // Read-only means read-only: the stub logged only the bounded
    // query invocations — no update, no feature enable, no start.
    let calls =
        std::fs::read_to_string(scenario.path().join("calls.txt")).expect("probes must have run");
    for line in calls.lines() {
        let args = line.split('\t').nth(1).unwrap_or("");
        for forbidden in ["--update", "install", "install-dist", "--set-version"] {
            assert!(
                !args.contains(forbidden),
                "probe must never run '{forbidden}': {calls}"
            );
        }
    }
}

/// Inbox/legacy WSL: `wsl.exe` resolves (presence) but `--version`
/// fails — an old WSL is recorded as such, not as "no WSL".
#[tokio::test]
async fn wslc_plan_legacy_wsl_fails_product_version() {
    let Some(stub) = compiled_stub() else {
        return;
    };
    let scenario = scenario_dir(&stub, OLD_WSL, &["wsl"]);
    let dir = tempfile::tempdir().unwrap();
    let policy = write_policy(&dir);

    let out = plan_wslc(&scenario, &policy).await;
    let json = plan_json(&out.stdout);
    assert_eq!(check_status(&json, "wsl.cli"), "pass");
    assert_eq!(check_status(&json, "wsl.product"), "fail");
    assert!(
        check_detail(&json, "wsl.product").contains("failed"),
        "wsl.product: {}",
        check_detail(&json, "wsl.product")
    );
    // The distro query failing is a warning, not a block on its own.
    assert_eq!(check_status(&json, "wsl.distro"), "warn");
    // No wslc.exe copy → the override path is absent → "not found".
    assert_eq!(check_status(&json, "wslc.cli"), "fail");
    assert!(
        check_detail(&json, "wslc.cli").contains("not found"),
        "wslc.cli: {}",
        check_detail(&json, "wslc.cli")
    );
    assert_eq!(check_status(&json, "wslc.runtime"), "skipped");
}

/// Store WSL below the 2.9.3 WSL Containers floor: the product version
/// parses fine and is still a hard fail — a version fact is not a
/// capability claim.
#[tokio::test]
async fn wslc_plan_below_floor_wsl_is_blocked() {
    let Some(stub) = compiled_stub() else {
        return;
    };
    let scenario = scenario_dir(&stub, BELOW_FLOOR, &["wsl"]);
    let dir = tempfile::tempdir().unwrap();
    let policy = write_policy(&dir);

    let out = plan_wslc(&scenario, &policy).await;
    let json = plan_json(&out.stdout);
    assert_eq!(check_status(&json, "wsl.cli"), "pass");
    assert_eq!(check_status(&json, "wsl.product"), "fail");
    assert!(
        check_detail(&json, "wsl.product").contains("below"),
        "wsl.product: {}",
        check_detail(&json, "wsl.product")
    );
    assert_eq!(check_status(&json, "wsl.distro"), "pass");
    assert_eq!(check_status(&json, "wslc.cli"), "fail");
}

/// WSL present and new enough, but no `wslc.exe` — the candidate is
/// absent, which is a fail on its own check, not a WSL failure.
#[tokio::test]
async fn wslc_plan_missing_wslc_binary_fails_wslc_cli() {
    let Some(stub) = compiled_stub() else {
        return;
    };
    let scenario = scenario_dir(&stub, NO_WSLC, &["wsl"]);
    let dir = tempfile::tempdir().unwrap();
    let policy = write_policy(&dir);

    let out = plan_wslc(&scenario, &policy).await;
    let json = plan_json(&out.stdout);
    assert_eq!(check_status(&json, "wsl.product"), "pass");
    assert_eq!(check_status(&json, "wslc.cli"), "fail");
    assert!(
        check_detail(&json, "wslc.cli").contains("not found"),
        "wslc.cli: {}",
        check_detail(&json, "wslc.cli")
    );
    assert_eq!(check_status(&json, "wslc.runtime"), "skipped");
}

/// Disabled WSL feature: `wsl.exe` exists but every query errors.
/// Presence of the CLI is still recorded truthfully.
#[tokio::test]
async fn wslc_plan_disabled_feature_reports_not_enabled() {
    let Some(stub) = compiled_stub() else {
        return;
    };
    let scenario = scenario_dir(&stub, DISABLED, &["wsl", "wslc"]);
    let dir = tempfile::tempdir().unwrap();
    let policy = write_policy(&dir);

    let out = plan_wslc(&scenario, &policy).await;
    let json = plan_json(&out.stdout);
    assert_eq!(check_status(&json, "wsl.cli"), "pass");
    assert_eq!(check_status(&json, "wsl.product"), "fail");
    assert!(
        check_detail(&json, "wsl.product").contains("not enabled"),
        "the stub's stderr must surface: {}",
        check_detail(&json, "wsl.product")
    );
    assert_eq!(check_status(&json, "wsl.distro"), "warn");
}

/// An answer in an unrecognized layout is *unverified*, not a guessed
/// version — the product check fails closed.
#[tokio::test]
async fn wslc_plan_unknown_version_fails_closed() {
    let Some(stub) = compiled_stub() else {
        return;
    };
    let scenario = scenario_dir(&stub, UNKNOWN_VERSION, &["wsl", "wslc"]);
    let dir = tempfile::tempdir().unwrap();
    let policy = write_policy(&dir);

    let out = plan_wslc(&scenario, &policy).await;
    let json = plan_json(&out.stdout);
    assert_eq!(check_status(&json, "wsl.product"), "fail");
    assert!(
        check_detail(&json, "wsl.product").contains("no product version"),
        "wsl.product: {}",
        check_detail(&json, "wsl.product")
    );
    // `wslc --version` was not stubbed: the section is missing → empty
    // stdout → "present but unverified", still not a pass.
    assert_eq!(check_status(&json, "wslc.cli"), "fail");
    assert!(
        check_detail(&json, "wslc.cli").contains("no output")
            || check_detail(&json, "wslc.cli").contains("unverified"),
        "wslc.cli: {}",
        check_detail(&json, "wslc.cli")
    );
}

/// `wsl --version` emitted as UTF-16LE (what several builds produce
/// when piped) still parses — the product check passes.
#[tokio::test]
async fn wslc_plan_utf16_output_parses() {
    let Some(stub) = compiled_stub() else {
        return;
    };
    let scenario = scenario_dir(&stub, UTF16, &["wsl", "wslc"]);
    let dir = tempfile::tempdir().unwrap();
    let policy = write_policy(&dir);

    let out = plan_wslc(&scenario, &policy).await;
    let json = plan_json(&out.stdout);
    assert_eq!(check_status(&json, "wsl.product"), "pass");
    assert!(
        check_detail(&json, "wsl.product").contains("3.0.1"),
        "wsl.product: {}",
        check_detail(&json, "wsl.product")
    );
}

/// A flooding writer never exits on its own once the pipe is full —
/// the probe must kill it at the cap and record the output-limit
/// failure; a `no answer within` detail would mean it waited out the
/// deadline instead.
#[tokio::test]
async fn wslc_plan_flooding_output_reports_limit_not_timeout() {
    let Some(stub) = compiled_stub() else {
        return;
    };
    let scenario = scenario_dir(&stub, FLOOD, &["wsl"]);
    let dir = tempfile::tempdir().unwrap();
    let policy = write_policy(&dir);

    let out = plan_wslc(&scenario, &policy).await;
    let json = plan_json(&out.stdout);
    assert_eq!(check_status(&json, "wsl.product"), "fail");
    let detail = check_detail(&json, "wsl.product");
    assert!(
        detail.contains("exceeds"),
        "a flood must record the cap, not a deadline: {detail}"
    );
    assert!(
        !detail.contains("no answer within"),
        "overflow misreported as timeout: {detail}"
    );
    // The quiet distro listing still answers normally.
    assert_eq!(check_status(&json, "wsl.distro"), "pass");
}

/// A native `plan` on a non-Windows host must not execute a single
/// Windows probe — even with every `MCP_WRIT_*_EXE` override pointing
/// at a live stub. `host.os` records the compile-time host facts only.
#[cfg(not(windows))]
#[tokio::test]
async fn native_plan_never_invokes_windows_probes() {
    let Some(stub) = compiled_stub() else {
        return;
    };
    // All four CLIs "installed" — if any probe ran, calls.txt appears.
    let scenario = scenario_dir(&stub, GOOD, &["wsl", "wslc", "reg", "powershell"]);
    let dir = tempfile::tempdir().unwrap();
    let policy = write_policy(&dir);

    let out = timeout(
        Duration::from_secs(TIMEOUT_SECS),
        Command::new(bin())
            .args([
                "plan",
                "--policy",
                policy.to_str().expect("policy path utf-8"),
                "--",
                bin(),
                "--version",
            ])
            .env("MCP_WRIT_WSL_EXE", scenario.path().join("wsl.exe"))
            .env("MCP_WRIT_WSLC_EXE", scenario.path().join("wslc.exe"))
            .env("MCP_WRIT_REG_EXE", scenario.path().join("reg.exe"))
            .env("MCP_WRIT_PWSH_EXE", scenario.path().join("powershell.exe"))
            .env_remove("MCP_WRIT_SKIP_SANDBOX")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output(),
    )
    .await
    .expect("plan timed out")
    .expect("run mcp-writ plan");

    let json = plan_json(&out.stdout);
    assert_eq!(check_status(&json, "host.os"), "pass");
    assert!(
        !scenario.path().join("calls.txt").exists(),
        "native plan on this host must spawn no Windows probe: {:?}",
        std::fs::read_to_string(scenario.path().join("calls.txt")).unwrap_or_default()
    );
}

/// `wsb.store` records the Windows Sandbox Store package version from
/// the `Get-AppxPackage` probe — a separate fact from the `wsb.exe`
/// client string `isolation.backend` validates. It is emitted on the
/// command-mode `--isolation windows-sandbox` plan even when the
/// payload prerequisites are not met.
#[tokio::test]
async fn windows_sandbox_plan_records_store_package_version() {
    let Some(stub) = compiled_stub() else {
        return;
    };
    let scenario = scenario_dir(&stub, GOOD, &["powershell"]);
    let dir = tempfile::tempdir().unwrap();
    let policy = write_policy(&dir);

    let out = timeout(
        Duration::from_secs(TIMEOUT_SECS),
        Command::new(bin())
            .args([
                "plan",
                "--isolation",
                "windows-sandbox",
                "--policy",
                policy.to_str().expect("policy path utf-8"),
                "--",
                "server.exe",
            ])
            .env("MCP_WRIT_PWSH_EXE", scenario.path().join("powershell.exe"))
            .env_remove("MCP_WRIT_SKIP_SANDBOX")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output(),
    )
    .await
    .expect("plan timed out")
    .expect("run mcp-writ plan");

    let json = plan_json(&out.stdout);
    assert_eq!(check_status(&json, "wsb.store"), "pass");
    assert!(
        check_detail(&json, "wsb.store").contains("Microsoft.WindowsSandbox"),
        "wsb.store: {}",
        check_detail(&json, "wsb.store")
    );
}

/// A zero-distro `wsl -l -v` is localized guidance prose with no table
/// rows — recorded as "no distros registered" (pass), not mistaken for
/// an unparseable-format warning.
#[tokio::test]
async fn wslc_plan_zero_distros_reads_as_none_registered() {
    let Some(stub) = compiled_stub() else {
        return;
    };
    let scenario = scenario_dir(&stub, ZERO_DISTROS, &["wsl", "wslc"]);
    let dir = tempfile::tempdir().unwrap();
    let policy = write_policy(&dir);

    let out = plan_wslc(&scenario, &policy).await;
    let json = plan_json(&out.stdout);
    assert_eq!(check_status(&json, "wsl.distro"), "pass");
    assert!(
        check_detail(&json, "wsl.distro").contains("no distros registered"),
        "wsl.distro: {}",
        check_detail(&json, "wsl.distro")
    );
}

/// A row-shaped `wsl -l -v` line that does not parse (a mode value the
/// contract does not define) stays a warn — never silently read as
/// "no distros".
#[tokio::test]
async fn wslc_plan_unparseable_distro_rows_warns() {
    let Some(stub) = compiled_stub() else {
        return;
    };
    let scenario = scenario_dir(&stub, UNPARSEABLE_LIST, &["wsl", "wslc"]);
    let dir = tempfile::tempdir().unwrap();
    let policy = write_policy(&dir);

    let out = plan_wslc(&scenario, &policy).await;
    let json = plan_json(&out.stdout);
    assert_eq!(check_status(&json, "wsl.distro"), "warn");
    assert!(
        check_detail(&json, "wsl.distro").contains("parseable"),
        "wsl.distro: {}",
        check_detail(&json, "wsl.distro")
    );
}

/// A CLI that reports its failure on stdout still has the message
/// recorded — stderr is not the only failure channel CLIs use.
#[tokio::test]
async fn wslc_plan_stdout_error_detail_surfaces() {
    let Some(stub) = compiled_stub() else {
        return;
    };
    let scenario = scenario_dir(&stub, STDOUT_ERROR, &["wsl"]);
    let dir = tempfile::tempdir().unwrap();
    let policy = write_policy(&dir);

    let out = plan_wslc(&scenario, &policy).await;
    let json = plan_json(&out.stdout);
    assert_eq!(check_status(&json, "wsl.product"), "fail");
    assert!(
        check_detail(&json, "wsl.product").contains("service is not responding"),
        "wsl.product: {}",
        check_detail(&json, "wsl.product")
    );
}
