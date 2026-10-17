//! Payload preparation, reporting and session driving for Windows Sandbox.
use std::path::{Path, PathBuf};

use super::backends::windows_sandbox::WindowsSandboxBackend;
use super::backends::{self, IsolationBackend, LaunchSpec, ShareMount};
use super::{guest_report, pe_magic, policy_export};
use crate::enforcement::*;
use crate::execution::{ExecutionTarget, IsolationKind, IsolationUnit, TargetArch, TargetOs};
use crate::verifier::fail_on::FailOn;

/// Host paths for the explicit command backend. Bulk state has no C: default.
#[derive(Debug, Clone, Default)]
pub struct SandboxOptions {
    pub payload: Option<PathBuf>,
    pub state_dir: Option<PathBuf>,
    /// Directory holding the matching runner and relay (default: beside CLI).
    pub runtime_dir: Option<PathBuf>,
}

pub struct SandboxRunOptions {
    pub sandbox: SandboxOptions,
    pub policy: Option<PathBuf>,
    pub server: Option<String>,
    pub command: Vec<String>,
    pub report: Option<PathBuf>,
    pub fail_on: FailOn,
    /// `--max-frame-bytes` — carried to the in-guest runner as
    /// `MCP_WRIT_MAX_FRAME_BYTES`; `None` keeps the runner's default.
    pub max_frame_bytes: Option<usize>,
}

pub fn target() -> ExecutionTarget {
    ExecutionTarget {
        workload_os: TargetOs::Windows,
        workload_arch: TargetArch::X86_64,
        substrate_os: TargetOs::Windows,
        substrate: IsolationKind::WindowsSandbox.substrate(),
        engine: None,
        ..ExecutionTarget::native()
    }
}

pub fn plan() -> EnforcementPlan {
    EnforcementPlan {
        controls: vec![
            PlannedControl { id: "launch.isolation", layer: ControlLayer::Launch,
                mechanism: "Windows Sandbox owned ID", state: ControlState::Planned, reason: None },
            PlannedControl { id: "launch.relay", layer: ControlLayer::Launch,
                mechanism: "authenticated bounded TCP relay", state: ControlState::Planned, reason: None },
            PlannedControl { id: "launch.guest_report", layer: ControlLayer::Launch,
                mechanism: "dedicated mapped report directory", state: ControlState::Planned, reason: None },
            PlannedControl { id: "rpc.guest", layer: ControlLayer::Rpc,
                mechanism: "guest Warden and Auditor", state: ControlState::Unknown, reason: Some("guest report carries the guest's own observations".into()) },
        ], grants: vec![], tools: vec![], limitations: vec![
            "Interactive host and guest logon required; one VM; headless services and concurrent Sandbox sessions unsupported".into(),
            "Host OS, wsb management, guest relay and Default Switch are trusted. TCP carries plaintext bearer credentials; no network-observer protection or remote attestation".into(),
            "Only dedicated launch RO/RW directories are mapped; RW contains audit, reports, workspace and bounded relay diagnostics. Guest data is untrusted".into(),
            "4096 MiB configured; guest Warden/AppContainer/Job and Auditor enforce policy. Host relay startup alone proves none of these controls".into(),
        ], egress_layers: None, mechanism: None,
    }
}

struct Prepared {
    payload: PathBuf,
    payload_root: PathBuf,
    runtime_root: PathBuf,
    state: PathBuf,
    command: Vec<String>,
    /// Validated runner bytes — the staged copy is written from this
    /// buffer, never a reopened source path.
    runner: crate::container::common::BoundArtifact,
    /// Validated relay bytes — same binding contract as `runner`.
    relay: crate::container::common::BoundArtifact,
    /// Validated payload entrypoint bytes.
    payload_exe: crate::container::common::BoundArtifact,
    kdl: String,
    policy: crate::audit_log::PolicyAuditContext,
    server: Option<String>,
}

fn local_directory(path: &Path) -> Result<PathBuf, String> {
    let path = path
        .canonicalize()
        .map_err(|e| format!("{}: {e}", path.display()))?;
    let text = path.to_string_lossy();
    let stripped = text.strip_prefix(r"\\?\").unwrap_or(&text);
    let path = PathBuf::from(stripped);
    if !path.is_dir() || !local_path_text(stripped) {
        return Err("Sandbox directories must be existing local directories".into());
    }
    Ok(path)
}

/// `\\server\share` and the canonicalized `\\?\UNC\server\share` — which
/// the `\\?\` strip reduces to `UNC\server\share` — are both network
/// paths, not local directories.
fn local_path_text(stripped: &str) -> bool {
    !stripped.starts_with(r"\\")
        && !stripped
            .get(..4)
            .is_some_and(|p| p.eq_ignore_ascii_case(r"UNC\"))
}

fn payload_command(
    payload: &Path,
    payload_root: &Path,
    command: &[String],
) -> Result<(Vec<String>, crate::container::common::BoundArtifact), String> {
    let first = command
        .first()
        .ok_or("missing payload command")?
        .replace('\\', "/");
    if first.is_empty()
        || first.starts_with('/')
        || first.contains(':')
        || first
            .split('/')
            .any(|s| s.is_empty() || s == "." || s == "..")
    {
        return Err("command must be a relative executable path inside --sandbox-payload".into());
    }
    let executable = payload.join(&first);
    // Bind the exact bytes validated — a payload entrypoint raced to a
    // different PE between this check and staging never reaches the
    // sandbox share.
    let bound = crate::container::common::BoundArtifact::bind_in(
        &executable,
        "payload executable",
        payload_root,
    )
    .map_err(|e| e.to_string())?;
    if pe_magic::pe_arch(&bound.bytes) != Some(TargetArch::X86_64) {
        return Err("payload command must be a Windows x86-64 PE executable; bundle its runtime and dependencies".into());
    }
    let mut argv = command.to_vec();
    argv[0] = format!("C:/mcp-secure/workload/{first}");
    if argv.iter().any(|s| s.contains('\0')) || json_argv(&argv).len() > 64 * 1024 {
        return Err("payload command contains NUL or exceeds 64 KiB".into());
    }
    Ok((argv, bound))
}

/// Read + bind one runtime artifact inside `runtime_root`: a Windows
/// x86-64 PE whose staged copy is later written from these same bytes.
/// `pin_env` names an optional operator SHA-256 pin — set, it must
/// match the bound bytes; the embedded markers prove compatibility,
/// not provenance.
fn artifact(
    runtime: &Path,
    name: &str,
    runtime_root: &Path,
    pin_env: &str,
) -> Result<crate::container::common::BoundArtifact, String> {
    let bound =
        crate::container::common::BoundArtifact::bind_in(&runtime.join(name), name, runtime_root)
            .map_err(|e| e.to_string())?;
    if pe_magic::pe_arch(&bound.bytes) != Some(TargetArch::X86_64) {
        return Err(format!("{name} must be Windows x86-64 PE"));
    }
    crate::container::common::check_digest_pin(&bound, pin_env).map_err(|e| e.to_string())?;
    Ok(bound)
}

fn prepare(
    options: &SandboxOptions,
    policy: Option<&Path>,
    server: Option<&str>,
    command: &[String],
) -> Result<Prepared, String> {
    let payload = local_directory(
        options
            .payload
            .as_deref()
            .ok_or("--sandbox-payload is required")?,
    )?;
    let state =
        local_directory(options.state_dir.as_deref().ok_or(
            "--sandbox-state is required (use a local drive with sufficient free space)",
        )?)?;
    if state.starts_with(&payload) {
        return Err("--sandbox-state must be outside --sandbox-payload".into());
    }
    let runtime = match &options.runtime_dir {
        Some(p) => local_directory(p)?,
        None => std::env::current_exe()
            .map_err(|e| e.to_string())?
            .parent()
            .ok_or("CLI directory missing")?
            .to_path_buf(),
    };
    // `--sandbox-runtime` is an operator-trusted input: every required
    // artifact is opened once inside the canonical runtime root, checked
    // as a PE of the right arch, marker-scanned on those same bytes, and
    // bound so staging can only write what was validated. The optional
    // MCP_WRIT_WSB_*_SHA256 pins add a cryptographic provenance anchor
    // on top of the forgeable compatibility markers.
    let runtime_root = crate::fspriv::canonical_root(&runtime).map_err(|e| e.to_string())?;
    let runner = artifact(
        &runtime,
        "mcp-secure-runner.exe",
        &runtime_root,
        "MCP_WRIT_WSB_RUNNER_SHA256",
    )?;
    // The WSB runner is still *the* runner — a generic release pin
    // applies alongside the WSB-specific one.
    crate::container::common::check_digest_pin(&runner, "MCP_WRIT_RUNNER_SHA256")
        .map_err(|e| e.to_string())?;
    let caps = guest_report::scan_runner_caps(&runner.bytes)
        .ok_or("runner lacks guest report capability marker")?;
    if caps.version != env!("CARGO_PKG_VERSION") || !caps.guest_report_capable() {
        return Err(
            "install runner, relay and CLI from the same release (guest-report-1 required)".into(),
        );
    }
    let relay = artifact(
        &runtime,
        "mcp-writ-wsb-relay.exe",
        &runtime_root,
        "MCP_WRIT_WSB_RELAY_SHA256",
    )?;
    let marker = concat!("MCP_WRIT_WSB_RELAY:", env!("CARGO_PKG_VERSION"), ":1\0").as_bytes();
    if !relay.bytes.windows(marker.len()).any(|part| part == marker) {
        return Err("relay version/protocol mismatch; install matching artifacts".into());
    }
    // Size/read pass only — the canonical root still binds the walk so a
    // swapped component cannot smuggle an out-of-tree byte count in.
    let payload_root = crate::fspriv::canonical_root(&payload).map_err(|e| e.to_string())?;
    inventory(&payload, None, 0, &payload_root, &mut (0, 0, 0))?;
    let (command, payload_exe) = payload_command(&payload, &payload_root, command)?;
    let policy_path = policy.ok_or("--policy is required for windows-sandbox")?;
    let bound = policy_export::load_and_bind_policy(policy_path, server, &target())
        .map_err(|e| e.to_string())?;
    // Keeping logs is mandatory for this opt-in backend.
    if !bound.logging.fail_closed {
        return Err("windows-sandbox requires logging fail_closed=#true".into());
    }
    let policy = bound.audit_context().map_err(|e| e.to_string())?;
    let server = bound.declared_servers().first().cloned();
    let kdl = policy_export::inline_policy_to_kdl(
        &bound,
        policy_path.parent().unwrap_or(Path::new(".")),
        &target(),
    )
    .map_err(|e| e.to_string())?;
    Ok(Prepared {
        payload,
        payload_root,
        runtime_root,
        state,
        command,
        runner,
        relay,
        payload_exe,
        policy,
        kdl,
        server,
    })
}

/// Read-only diagnostic; validates the same payload/artifacts/policy as launch.
pub fn check_configuration(
    options: &SandboxOptions,
    policy: Option<&Path>,
    server: Option<&str>,
    command: &[String],
) -> Result<(), String> {
    prepare(options, policy, server, command).map(|_| ())
}

fn json_argv(argv: &[String]) -> String {
    nojson::array(|f| {
        for arg in argv {
            f.element(arg.as_str())?;
        }
        Ok(())
    })
    .to_string()
}

fn reparse(meta: &std::fs::Metadata) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if meta.file_attributes() & 0x400 != 0 {
            return true;
        }
    }
    meta.file_type().is_symlink()
}

/// Limit staging before allocating/copying; never follow links or junctions.
///
/// The copy half cannot be raced: each file is opened without following
/// its final-component link and proven to resolve inside `canonical_root`
/// before its bytes stream from that same open handle — a pathname
/// swapped for a link between the metadata check and the copy cannot
/// pull an out-of-tree object into the guest.
fn inventory(
    source: &Path,
    dest: Option<&Path>,
    depth: usize,
    canonical_root: &Path,
    total: &mut (u64, u64, u64),
) -> Result<(), String> {
    const MAX_PAYLOAD_ENTRIES: u64 = 10_000;
    const MAX_PAYLOAD_BYTES: u64 = 1024 * 1024 * 1024;
    if depth > 32 {
        return Err("payload nesting exceeds 32".into());
    }
    if let Some(dest) = dest {
        std::fs::create_dir_all(dest).map_err(|e| e.to_string())?;
    }
    for entry in std::fs::read_dir(source).map_err(|e| e.to_string())? {
        let entry = entry.map_err(|e| e.to_string())?;
        let meta = std::fs::symlink_metadata(entry.path()).map_err(|e| e.to_string())?;
        if reparse(&meta) {
            return Err(format!(
                "payload link/reparse point refused: {}",
                entry.path().display()
            ));
        }
        total.0 += 1;
        // The metadata size is only an early-refusal estimate — a local
        // actor can grow the file before its handle is opened. The hard
        // cap is charged from bytes actually copied below.
        total.1 += meta.len();
        if total.0 > MAX_PAYLOAD_ENTRIES || total.1 > MAX_PAYLOAD_BYTES {
            return Err("payload exceeds 10,000 entries or 1 GiB".into());
        }
        let dst = dest.map(|p| p.join(entry.file_name()));
        if meta.is_dir() {
            inventory(
                &entry.path(),
                dst.as_deref(),
                depth + 1,
                canonical_root,
                total,
            )?;
        } else if meta.is_file() {
            if let Some(dst) = dst {
                let remaining = MAX_PAYLOAD_BYTES.saturating_sub(total.2);
                match crate::fspriv::safe_copy_file_bounded(
                    &entry.path(),
                    &dst,
                    canonical_root,
                    remaining,
                )
                .map_err(|e| format!("{}: {e}", entry.path().display()))?
                {
                    // Charge the bytes the verified handle actually
                    // streamed — growth after the metadata read cannot
                    // slip past the ceiling.
                    crate::fspriv::SafeCopyOutcome::Copied(n) => total.2 += n,
                    crate::fspriv::SafeCopyOutcome::Skipped => {
                        return Err(format!(
                            "payload link/reparse point refused: {}",
                            entry.path().display()
                        ));
                    }
                }
            }
        } else {
            return Err("payload contains a special file".into());
        }
    }
    Ok(())
}

/// Stage an artifact's validated bytes to `dest` plus every MSVC CRT
/// DLL its import table needs — the import names come from the *bound
/// bytes*, never a re-read of the source name, so a swapped PE cannot
/// desync the DLL set it was checked against.
///
/// Adjacent DLLs stage only as real files inside `canonical_root`
/// (link/out-of-tree candidates are refused); a name the local dir
/// cannot supply falls back to System32, whose copy is bound and
/// PE-checked before staging.
fn stage_bound(
    bound: &crate::container::common::BoundArtifact,
    dest: &Path,
    canonical_root: &Path,
) -> Result<(), String> {
    bound
        .stage_to(dest, true)
        .map_err(|e| format!("{}: {e}", bound.source.display()))?;
    for dll in pe_magic::required_redist_dlls(&bound.bytes).ok_or("invalid PE")? {
        if dll.contains(['/', '\\', ':']) {
            return Err("invalid DLL import path".into());
        }
        let local = bound
            .source
            .parent()
            .ok_or("executable directory missing")?
            .join(&dll);
        let output = dest.parent().ok_or("staging directory missing")?.join(&dll);
        if output.exists() {
            continue;
        }
        // A locally-adjacent DLL stages only as a validated PE bound
        // inside the root — anything else (absent, link, out-of-tree,
        // wrong arch) falls back to the system copy instead of dragging
        // an attacker-chosen object into the guest.
        let local_bound =
            crate::container::common::BoundArtifact::bind_in(&local, "CRT DLL", canonical_root)
                .ok()
                .filter(|b| pe_magic::pe_arch(&b.bytes) == Some(TargetArch::X86_64));
        let crt = match local_bound {
            Some(b) => b,
            None => {
                let origin =
                    PathBuf::from(std::env::var_os("SystemRoot").ok_or("SystemRoot is missing")?)
                        .join("System32")
                        .join(&dll);
                let system = crate::container::common::BoundArtifact::bind(&origin, "CRT DLL")
                    .map_err(|e| format!("required app-local CRT {dll}: {e}"))?;
                if pe_magic::pe_arch(&system.bytes) != Some(TargetArch::X86_64) {
                    return Err(format!("required app-local CRT {dll} is not x86-64 PE"));
                }
                system
            }
        };
        crt.stage_to(&output, false)
            .map_err(|e| format!("failed to stage CRT {dll}: {e}"))?;
    }
    Ok(())
}

fn observation(report: &mut LaunchReport, id: &'static str, state: ControlState, detail: &str) {
    report.observations.push(EnforcementObservation {
        control: id,
        state,
        basis: ObservationBasis::VerificationRun,
        phase: ControlPhase::Session,
        reason: Some(detail.into()),
    });
}

async fn collect(
    report: &mut LaunchReport,
    rw: &Path,
    require_controls: bool,
    startup: bool,
) -> Result<(), String> {
    // The startup read gates MCP forwarding on the guest runner's first
    // report — runner setup inside the VM is in the window, so it gets a
    // wider deadline than the post-exit mount-visibility poll.
    let wait = if startup {
        guest_report::GUEST_REPORT_STARTUP_WAIT
    } else {
        guest_report::GUEST_REPORT_WAIT
    };
    let read = guest_report::read_guest_report_within(
        &rw.join("report"),
        report.launch_id,
        Some(env!("CARGO_PKG_VERSION")),
        wait,
    )
    .await;
    let (state, text, error) = match read {
        guest_report::GuestReportRead::Received(text) => {
            let error = if require_controls {
                validate_controls(&text).err()
            } else {
                None
            };
            (GuestReportState::Received, Some(text), error)
        }
        guest_report::GuestReportRead::Missing(e) => (GuestReportState::Missing, None, Some(e)),
        guest_report::GuestReportRead::Invalid(e) => (GuestReportState::Invalid, None, Some(e)),
    };
    report.guest = Some(GuestReportLink {
        state,
        report_json: text,
        detail: error.clone(),
        runner: Some(guest_report::this_runner_identity()),
    });
    error.map_or(Ok(()), Err)
}

fn validate_controls(text: &str) -> Result<(), String> {
    let json = nojson::RawJson::parse(text).map_err(|e| e.to_string())?;
    let observations = json
        .value()
        .to_member("observations")
        .and_then(|v| v.required())
        .map_err(|e| e.to_string())?;
    for id in ["os.process", "os.fs", "os.net.outbound"] {
        let observed = observations
            .to_array()
            .map_err(|e| e.to_string())?
            .any(|o| {
                let get = |key| {
                    o.to_member(key)
                        .and_then(|v| v.required())
                        .and_then(|v| v.as_string_str())
                        .ok()
                };
                if get("control") != Some(id) {
                    return false;
                }
                let state = get("state");
                // `os.fs` honestly reports `unknown` on the default
                // non-LPAC AppContainer — ambient ALL_APPLICATION_PACKAGES
                // read access means the effective boundary cannot be
                // claimed verified without LPAC/PSEC. `unknown` is an
                // observation limit, not a tolerated weakening; `failed`,
                // `partially_applied`, and `not_applied` still refuse.
                if id == "os.fs" {
                    matches!(state, Some("verified") | Some("unknown"))
                } else {
                    state == Some("verified")
                }
            });
        if !observed {
            return Err(format!(
                "guest did not report required control {id} as verified"
            ));
        }
    }
    Ok(())
}

pub async fn run(options: &SandboxRunOptions) -> Result<i32, Box<dyn std::error::Error>> {
    let mut report = LaunchReport {
        schema_version: LAUNCH_REPORT_SCHEMA_VERSION,
        launch_id: uuid::Uuid::now_v7(),
        created_at: crate::audit_log::now_iso8601_millis(),
        target: target(),
        policy: None,
        dry_run: false,
        plan: plan(),
        observations: vec![],
        result: None,
        code_identity: None,
        guest_runner: None,
        guest: None,
        isolation: Some(IsolationRecord {
            configured: IsolationKind::WindowsSandbox,
            verified: None,
            unit: None,
            unit_id: None,
            detail: None,
        }),
    };
    if let Some(path) = &options.report {
        // Check report storage before any VM or workload is started.
        report.write_to(path)?;
    }
    let mut session_dir = None;
    // Register before any start, so Ctrl-C during staging/guest logon also
    // unwinds the owned-ID guard. The session driver uses the same signal.
    let mut result = tokio::select! {
        result = run_inner(options, &mut report, &mut session_dir) => result,
        _ = tokio::signal::ctrl_c() => Ok(backends::SessionEnd::Interrupted),
    };
    if let Some(dir) = &session_dir {
        if matches!(result, Ok(backends::SessionEnd::Interrupted)) {
            let _ = collect(&mut report, &dir.join("rw"), false, false).await;
        }
        let cleanup = match std::fs::read_to_string(dir.join("unit-id")) {
            Ok(id) => {
                if let Some(i) = report.isolation.as_mut() {
                    i.unit_id.get_or_insert(id.clone());
                }
                super::backends::windows_sandbox::confirm_stopped(&id).await
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e.to_string()),
        };
        match cleanup {
            Ok(()) => {
                if dir.join("ro").exists()
                    && let Err(e) = std::fs::remove_dir_all(dir.join("ro"))
                {
                    result = Err(format!("staging cleanup failed: {e}"));
                }
                if let Some(i) = report.isolation.as_mut() {
                    i.detail = Some("cleanup confirmed".into());
                }
            }
            Err(e) => result = Err(format!("cleanup unconfirmed: {e}")),
        }
    }
    report.result = Some(match &result {
        Ok(backends::SessionEnd::Exited(code)) => LaunchOutcome {
            status: "exited",
            exit_code: Some(*code),
            detail: None,
        },
        Ok(backends::SessionEnd::Interrupted) => LaunchOutcome {
            status: "interrupted",
            exit_code: Some(130),
            detail: Some("Ctrl-C".into()),
        },
        Err(e) => LaunchOutcome {
            status: "failed",
            exit_code: Some(1),
            detail: Some(e.clone()),
        },
    });
    if let Some(dir) = session_dir {
        report.write_to(&dir.join("launch-report.json"))?;
        eprintln!("Windows Sandbox session record: {}", dir.display());
    }
    if let Some(path) = &options.report {
        report.write_to(path)?;
    }
    match result {
        Ok(backends::SessionEnd::Exited(code)) => Ok(code),
        Ok(backends::SessionEnd::Interrupted) => Ok(130),
        Err(e) => Err(e.into()),
    }
}

async fn run_inner(
    options: &SandboxRunOptions,
    report: &mut LaunchReport,
    session_dir: &mut Option<PathBuf>,
) -> Result<backends::SessionEnd, String> {
    let host_ip = super::backends::windows_sandbox::prerequisites().await?;
    let prepared = prepare(
        &options.sandbox,
        options.policy.as_deref(),
        options.server.as_deref(),
        &options.command,
    )?;
    report.policy = Some(prepared.policy);
    // The state root holds relay credentials and the staged policy for
    // every session beneath it — it must be owner-only, and it is pinned
    // so a swapped root cannot redirect the session dirs created next.
    crate::fspriv::restrict_owner_only(&prepared.state).map_err(|e| e.to_string())?;
    let state_pin = crate::fspriv::PinnedDir::pin(&prepared.state).map_err(|e| e.to_string())?;
    let dir = prepared.state.join(report.launch_id.to_string());
    std::fs::create_dir(&dir).map_err(|e| e.to_string())?;
    crate::fspriv::restrict_owner_only(&dir).map_err(|e| e.to_string())?;
    *session_dir = Some(dir.clone());
    let ro = dir.join("ro");
    let rw = dir.join("rw");
    std::fs::create_dir(&ro).map_err(|e| e.to_string())?;
    std::fs::create_dir(&rw).map_err(|e| e.to_string())?;
    // Pin the mapped destinations: the .wsb XML names these paths, and
    // Windows Sandbox maps whatever object the name resolves to — the
    // pins let launch verify the names still resolve to the staged dirs.
    let session_pin = crate::fspriv::PinnedDir::pin(&dir).map_err(|e| e.to_string())?;
    let ro_pin = crate::fspriv::PinnedDir::pin(&ro).map_err(|e| e.to_string())?;
    let rw_pin = crate::fspriv::PinnedDir::pin(&rw).map_err(|e| e.to_string())?;
    // Payload content copies through the contained no-follow walk; the
    // *validated* artifacts stage from their bound byte buffers — the
    // share hands the sandbox exactly the bytes that passed the PE,
    // marker, and digest-pin checks.
    inventory(
        &prepared.payload,
        Some(&ro.join("workload")),
        0,
        &prepared.payload_root,
        &mut (0, 0, 0),
    )?;
    stage_bound(
        &prepared.runner,
        &ro.join("mcp-secure-runner.exe"),
        &prepared.runtime_root,
    )?;
    stage_bound(
        &prepared.relay,
        &ro.join("mcp-writ-wsb-relay.exe"),
        &prepared.runtime_root,
    )?;
    let relative = prepared.command[0]
        .strip_prefix("C:/mcp-secure/workload/")
        .ok_or("invalid staged command")?;
    stage_bound(
        &prepared.payload_exe,
        &ro.join("workload").join(relative),
        &prepared.payload_root,
    )?;
    std::fs::write(ro.join("policy.kdl"), prepared.kdl).map_err(|e| e.to_string())?;
    let mut env = vec![
        ("MCP_WRIT_LAUNCH_ID".into(), report.launch_id.to_string()),
        ("MCP_WRIT_FAIL_ON".into(), options.fail_on.as_str().into()),
    ];
    if let Some(max_frame_bytes) = options.max_frame_bytes {
        env.push((
            "MCP_WRIT_MAX_FRAME_BYTES".into(),
            max_frame_bytes.to_string(),
        ));
    }
    if let Some(server) = prepared.server {
        env.push(("MCP_WRIT_SERVER".into(), server));
    }
    // Carry the already-probed Default Switch IPv4 through the spec so
    // the backend performs one PowerShell/wsb probe per launch instead of
    // one per trait call.
    env.push((
        super::backends::windows_sandbox::HOST_IP_ENV.into(),
        host_ip,
    ));
    let spec = LaunchSpec {
        isolation: IsolationKind::WindowsSandbox,
        image: None,
        command: Some(prepared.command),
        guest_os: TargetOs::Windows,
        guest_arch: TargetArch::X86_64,
        image_os_version: None,
        shares: vec![
            ShareMount {
                host: ro,
                guest: r"C:\relay-ro".into(),
                writable: false,
                // The backend writes launch files into `ro` and maps
                // both dirs into the WSB config — the pinned identities
                // let it prove the names still resolve to these staged
                // objects at that point.
                pin: Some(ro_pin.identity()),
            },
            ShareMount {
                host: rw.clone(),
                guest: r"C:\relay-rw".into(),
                writable: true,
                pin: Some(rw_pin.identity()),
            },
        ],
        env,
        unit_id_file: Some(dir.join("unit-id")),
        // Windows Sandbox launches are tracked by the .wsb session, not
        // an engine unit — no `--name` equivalent applies.
        unit_name: None,
    };
    let backend = WindowsSandboxBackend;
    let checked = backend.check(&spec).await.map_err(|e| e.to_string())?;
    backends::ensure_confirmed(&spec, &checked).map_err(|e| e.to_string())?;
    // Last-mile check before the XML mapping is generated inside launch:
    // every mapped destination must still be the staged object.
    for pin in [&state_pin, &session_pin, &ro_pin, &rw_pin] {
        pin.verify_current()
            .map_err(|e| format!("staging destination replaced: {e}"))?;
    }
    eprintln!(
        "Windows Sandbox needs an interactive desktop; relay TCP trusts the host and Default Switch. Audit/report: {}",
        rw.display()
    );
    let mut handle = backend.launch(&spec).await.map_err(|e| e.to_string())?;
    if let Some(isolation) = report.isolation.as_mut() {
        isolation.verified = Some(IsolationKind::WindowsSandbox);
        isolation.unit = Some(IsolationUnit::Vm);
        isolation.unit_id = handle.unit_id();
        isolation.detail = checked.detail;
    }
    observation(
        report,
        "launch.isolation",
        ControlState::Verified,
        "owned ID observed in wsb list",
    );
    observation(
        report,
        "launch.relay",
        ControlState::Verified,
        "mutual launch credentials and protocol version accepted",
    );
    let result = match collect(report, &rw, true, true).await {
        Ok(()) => {
            observation(
                report,
                "launch.guest_report",
                ControlState::Verified,
                "guest report received and required guest observations checked; self-reported evidence",
            );
            report
                .write_to(&dir.join("launch-report.json"))
                .map_err(|e| e.to_string())?;
            backends::drive_stdio_session(handle.as_mut())
                .await
                .map_err(|e| e.to_string())
        }
        Err(e) => Err(e),
    };
    let cleanup = handle.cleanup().await.map_err(|e| e.to_string());
    if cleanup.is_ok()
        && let Some(i) = report.isolation.as_mut()
    {
        i.detail = Some("cleanup confirmed".into());
    }
    // Preserve the final guest record on failure and cancellation as well.
    let collected = collect(
        report,
        &rw,
        matches!(result, Ok(backends::SessionEnd::Exited(0))),
        false,
    )
    .await;
    cleanup?;
    let end = result?;
    if matches!(end, backends::SessionEnd::Exited(0)) {
        collected?;
        if !rw.join("logs/audit.jsonl").is_file() {
            return Err("required guest audit file is missing".into());
        }
    }
    Ok(end)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payload_rejects_escape_and_special_entries() {
        let dir = tempfile::tempdir().unwrap();
        let root = crate::fspriv::canonical_root(dir.path()).unwrap();
        for executable in [
            "../server.exe",
            "C:/server.exe",
            r"..\server.exe",
            "/server.exe",
            "x//y.exe",
        ] {
            assert!(
                payload_command(dir.path(), &root, &[executable.into()])
                    .unwrap_err()
                    .contains("relative executable")
            );
        }
        std::fs::write(dir.path().join("data.txt"), "payload").unwrap();
        let dest = tempfile::tempdir().unwrap();
        let root = crate::fspriv::canonical_root(dir.path()).unwrap();
        inventory(dir.path(), Some(dest.path()), 0, &root, &mut (0, 0, 0)).unwrap();
        assert_eq!(
            std::fs::read_to_string(dest.path().join("data.txt")).unwrap(),
            "payload"
        );
        assert!(inventory(dir.path(), None, 0, &root, &mut (10_000, 0, 0)).is_err());
        assert!(inventory(dir.path(), None, 0, &root, &mut (0, 1024 * 1024 * 1024, 0)).is_err());
        assert!(inventory(dir.path(), None, 33, &root, &mut (0, 0, 0)).is_err());
    }

    #[test]
    fn local_path_text_rejects_network_spelling() {
        for local in [r"C:\data", r"D:\state\sub", r"Volume{guid}\mnt"] {
            assert!(local_path_text(local), "{local}");
        }
        for network in [
            r"\\server\share",
            r"UNC\server\share",
            r"unc\server\share",
            r"UnC\server\share",
        ] {
            assert!(!local_path_text(network), "{network}");
        }
    }

    #[test]
    fn guest_report_must_record_every_required_control() {
        let observations = |state| {
            format!(
                r#"{{"observations":[{{"control":"os.process","state":"verified"}},{{"control":"os.fs","state":"{state}"}},{{"control":"os.net.outbound","state":"verified"}}]}}"#
            )
        };
        assert!(validate_controls(&observations("verified")).is_ok());
        // `os.fs` is honestly `unknown` on the default non-LPAC
        // AppContainer — an observation limit, not a weakening; the
        // acceptance gate must still read it as a recorded control.
        assert!(validate_controls(&observations("unknown")).is_ok());
        for state in ["failed", "skipped", "partially_applied"] {
            assert!(validate_controls(&observations(state)).is_err());
        }
        assert!(validate_controls(r#"{"observations":[]}"#).is_err());
        // `unknown` is accepted only for `os.fs` — the capability-based
        // controls are verifiable on the default mechanism and must
        // report verified.
        let process_unknown = r#"{"observations":[{"control":"os.process","state":"unknown"},{"control":"os.fs","state":"verified"},{"control":"os.net.outbound","state":"verified"}]}"#;
        assert!(validate_controls(process_unknown).is_err());
    }

    // -- bound artifact staging (F65/F78) ------------------------------------

    /// Minimal parseable x86-64 PE — DOS header, PE sig, COFF, PE32+
    /// optional header; no imports.
    fn synthetic_pe() -> Vec<u8> {
        let e_lfanew: u32 = 0x80;
        let opt_size: u16 = 0xF0;
        let mut b = vec![0u8; 0x400];
        b[0] = b'M';
        b[1] = b'Z';
        b[0x3C..0x40].copy_from_slice(&e_lfanew.to_le_bytes());
        let coff = e_lfanew as usize + 4;
        b[e_lfanew as usize..coff].copy_from_slice(b"PE\0\0");
        b[coff..coff + 2].copy_from_slice(&0x8664u16.to_le_bytes());
        b[coff + 16..coff + 18].copy_from_slice(&opt_size.to_le_bytes());
        let opt = coff + 20;
        b[opt..opt + 2].copy_from_slice(&0x20Bu16.to_le_bytes());
        b[opt + 108..opt + 112].copy_from_slice(&16u32.to_le_bytes());
        b
    }

    /// F65: the runtime artifact binds its bytes at validation — a
    /// file swapped afterwards cannot desync the staged copy.
    #[test]
    fn artifact_stages_bound_bytes_after_source_swap() {
        let dir = tempfile::tempdir().unwrap();
        let root = crate::fspriv::canonical_root(dir.path()).unwrap();
        let source = dir.path().join("mcp-writ-wsb-relay.exe");
        std::fs::write(&source, synthetic_pe()).unwrap();

        let bound = artifact(
            dir.path(),
            "mcp-writ-wsb-relay.exe",
            &root,
            "MCP_WRIT_TEST_UNSET_PIN",
        )
        .unwrap();
        std::fs::write(&source, b"forged replacement").unwrap();

        let out = tempfile::tempdir().unwrap();
        let dest = out.path().join("mcp-writ-wsb-relay.exe");
        stage_bound(&bound, &dest, &root).unwrap();
        assert_eq!(std::fs::read(&dest).unwrap(), synthetic_pe());
    }

    /// F65/F78: a link at the artifact name is refused at bind — the
    /// object it could point at is never read into the staged copy.
    #[cfg(unix)]
    #[test]
    fn artifact_refuses_symlink() {
        let dir = tempfile::tempdir().unwrap();
        let root = crate::fspriv::canonical_root(dir.path()).unwrap();
        let secret = dir.path().join("secret.exe");
        std::fs::write(&secret, synthetic_pe()).unwrap();
        std::os::unix::fs::symlink(&secret, dir.path().join("mcp-writ-wsb-relay.exe")).unwrap();

        let err = artifact(
            dir.path(),
            "mcp-writ-wsb-relay.exe",
            &root,
            "MCP_WRIT_TEST_UNSET_PIN",
        )
        .unwrap_err();
        assert!(err.contains("link or non-regular"), "got: {err}");
    }

    /// F78: the forgeable-marker hole — a PE carrying valid public
    /// markers but different bytes is refused once the operator pins
    /// the release digest.
    #[test]
    fn artifact_digest_pin_rejects_substituted_bytes() {
        let _env = crate::warden::lock_process_env();
        let dir = tempfile::tempdir().unwrap();
        let root = crate::fspriv::canonical_root(dir.path()).unwrap();
        let source = dir.path().join("mcp-secure-runner.exe");
        std::fs::write(&source, synthetic_pe()).unwrap();

        // A pin naming some other release's bytes refuses this file.
        unsafe {
            std::env::set_var("MCP_WRIT_WSB_RUNNER_SHA256", "f".repeat(64));
        }
        let err = artifact(
            dir.path(),
            "mcp-secure-runner.exe",
            &root,
            "MCP_WRIT_WSB_RUNNER_SHA256",
        )
        .unwrap_err();
        assert!(err.contains("does not match"), "got: {err}");

        // The correct pin passes.
        let digest = crate::container::common::sha256_hex(&synthetic_pe());
        unsafe {
            std::env::set_var("MCP_WRIT_WSB_RUNNER_SHA256", &digest);
        }
        artifact(
            dir.path(),
            "mcp-secure-runner.exe",
            &root,
            "MCP_WRIT_WSB_RUNNER_SHA256",
        )
        .unwrap();
        unsafe {
            std::env::remove_var("MCP_WRIT_WSB_RUNNER_SHA256");
        }
    }

    /// F65: `payload_command` binds the validated exe — a swapped
    /// payload entrypoint never reaches the staged share.
    #[test]
    fn payload_command_binds_validated_exe() {
        let dir = tempfile::tempdir().unwrap();
        let root = crate::fspriv::canonical_root(dir.path()).unwrap();
        std::fs::write(dir.path().join("server.exe"), synthetic_pe()).unwrap();

        let (argv, bound) = payload_command(dir.path(), &root, &["server.exe".into()]).unwrap();
        assert_eq!(argv[0], "C:/mcp-secure/workload/server.exe");
        assert_eq!(bound.bytes[..], synthetic_pe()[..]);

        std::fs::write(dir.path().join("server.exe"), b"swapped").unwrap();
        let out = tempfile::tempdir().unwrap();
        let dest = out.path().join("server.exe");
        stage_bound(&bound, &dest, &root).unwrap();
        assert_eq!(std::fs::read(&dest).unwrap(), synthetic_pe());
    }
}
