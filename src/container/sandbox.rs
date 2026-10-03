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
        ],
    }
}

struct Prepared {
    payload: PathBuf,
    runtime: PathBuf,
    state: PathBuf,
    command: Vec<String>,
    kdl: String,
    policy: crate::audit_log::PolicyAuditContext,
    server: Option<String>,
}

fn local_directory(path: &Path) -> Result<PathBuf, String> {
    let path = path
        .canonicalize()
        .map_err(|e| format!("{}: {e}", path.display()))?;
    let text = path.to_string_lossy();
    let path = PathBuf::from(text.strip_prefix(r"\\?\").unwrap_or(&text));
    if !path.is_dir() || path.to_string_lossy().starts_with(r"\\") {
        return Err("Sandbox directories must be existing local directories".into());
    }
    Ok(path)
}

fn payload_command(payload: &Path, command: &[String]) -> Result<Vec<String>, String> {
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
    let bytes =
        std::fs::read(payload.join(&first)).map_err(|e| format!("payload executable: {e}"))?;
    if pe_magic::pe_arch(&bytes) != Some(TargetArch::X86_64) {
        return Err("payload command must be a Windows x86-64 PE executable; bundle its runtime and dependencies".into());
    }
    let mut argv = command.to_vec();
    argv[0] = format!("C:/mcp-secure/workload/{first}");
    if argv.iter().any(|s| s.contains('\0')) || json_argv(&argv).len() > 64 * 1024 {
        return Err("payload command contains NUL or exceeds 64 KiB".into());
    }
    Ok(argv)
}

fn artifact(runtime: &Path, name: &str) -> Result<Vec<u8>, String> {
    let path = runtime.join(name);
    if std::fs::metadata(&path)
        .map_err(|e| format!("{}: {e}", path.display()))?
        .len()
        > 256 * 1024 * 1024
    {
        return Err(format!("{name} exceeds 256 MiB"));
    }
    let bytes = std::fs::read(path).map_err(|e| e.to_string())?;
    if pe_magic::pe_arch(&bytes) != Some(TargetArch::X86_64) {
        return Err(format!("{name} must be Windows x86-64 PE"));
    }
    Ok(bytes)
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
    let runner = artifact(&runtime, "mcp-secure-runner.exe")?;
    let caps = guest_report::scan_runner_caps(&runner)
        .ok_or("runner lacks guest report capability marker")?;
    if caps.version != env!("CARGO_PKG_VERSION") || !caps.guest_report_capable() {
        return Err(
            "install runner, relay and CLI from the same release (guest-report-1 required)".into(),
        );
    }
    let relay = artifact(&runtime, "mcp-writ-wsb-relay.exe")?;
    let marker = concat!("MCP_WRIT_WSB_RELAY:", env!("CARGO_PKG_VERSION"), ":1\0").as_bytes();
    if !relay.windows(marker.len()).any(|part| part == marker) {
        return Err("relay version/protocol mismatch; install matching artifacts".into());
    }
    inventory(&payload, None, 0, &mut (0, 0))?;
    let command = payload_command(&payload, command)?;
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
        runtime,
        state,
        command,
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
fn inventory(
    source: &Path,
    dest: Option<&Path>,
    depth: usize,
    total: &mut (u64, u64),
) -> Result<(), String> {
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
        total.1 += meta.len();
        if total.0 > 10_000 || total.1 > 1024 * 1024 * 1024 {
            return Err("payload exceeds 10,000 entries or 1 GiB".into());
        }
        let dst = dest.map(|p| p.join(entry.file_name()));
        if meta.is_dir() {
            inventory(&entry.path(), dst.as_deref(), depth + 1, total)?;
        } else if meta.is_file() {
            if let Some(dst) = dst {
                std::fs::copy(entry.path(), &dst).map_err(|e| e.to_string())?;
            }
        } else {
            return Err("payload contains a special file".into());
        }
    }
    Ok(())
}

fn stage_executable(source: &Path, dest: &Path) -> Result<(), String> {
    std::fs::copy(source, dest).map_err(|e| e.to_string())?;
    let bytes = std::fs::read(source).map_err(|e| e.to_string())?;
    for dll in pe_magic::required_redist_dlls(&bytes).ok_or("invalid PE")? {
        if dll.contains(['/', '\\', ':']) {
            return Err("invalid DLL import path".into());
        }
        let local = source
            .parent()
            .ok_or("executable directory missing")?
            .join(&dll);
        let origin = if local.is_file() {
            local
        } else {
            PathBuf::from(std::env::var_os("SystemRoot").ok_or("SystemRoot is missing")?)
                .join("System32")
                .join(&dll)
        };
        let output = dest.parent().ok_or("staging directory missing")?.join(&dll);
        if !output.exists() {
            std::fs::copy(origin, output)
                .map_err(|e| format!("required app-local CRT {dll}: {e}"))?;
        }
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
) -> Result<(), String> {
    let read = guest_report::read_guest_report(
        &rw.join("report"),
        report.launch_id,
        Some(env!("CARGO_PKG_VERSION")),
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
        let verified = observations
            .to_array()
            .map_err(|e| e.to_string())?
            .any(|o| {
                let get = |key| {
                    o.to_member(key)
                        .and_then(|v| v.required())
                        .and_then(|v| v.as_string_str())
                        .ok()
                };
                get("control") == Some(id) && get("state") == Some("verified")
            });
        if !verified {
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
            let _ = collect(&mut report, &dir.join("rw"), false).await;
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
    super::backends::windows_sandbox::prerequisites().await?;
    let prepared = prepare(
        &options.sandbox,
        options.policy.as_deref(),
        options.server.as_deref(),
        &options.command,
    )?;
    report.policy = Some(prepared.policy);
    let dir = prepared.state.join(report.launch_id.to_string());
    std::fs::create_dir(&dir).map_err(|e| e.to_string())?;
    crate::fspriv::restrict_owner_only(&dir).map_err(|e| e.to_string())?;
    *session_dir = Some(dir.clone());
    let ro = dir.join("ro");
    let rw = dir.join("rw");
    std::fs::create_dir(&ro).map_err(|e| e.to_string())?;
    std::fs::create_dir(&rw).map_err(|e| e.to_string())?;
    inventory(
        &prepared.payload,
        Some(&ro.join("workload")),
        0,
        &mut (0, 0),
    )?;
    for name in ["mcp-secure-runner.exe", "mcp-writ-wsb-relay.exe"] {
        stage_executable(&prepared.runtime.join(name), &ro.join(name))?;
    }
    let relative = prepared.command[0]
        .strip_prefix("C:/mcp-secure/workload/")
        .ok_or("invalid staged command")?;
    stage_executable(
        &prepared.payload.join(relative),
        &ro.join("workload").join(relative),
    )?;
    std::fs::write(ro.join("policy.kdl"), prepared.kdl).map_err(|e| e.to_string())?;
    let mut env = vec![
        ("MCP_WRIT_LAUNCH_ID".into(), report.launch_id.to_string()),
        ("MCP_WRIT_FAIL_ON".into(), options.fail_on.as_str().into()),
    ];
    if let Some(server) = prepared.server {
        env.push(("MCP_WRIT_SERVER".into(), server));
    }
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
            },
            ShareMount {
                host: rw.clone(),
                guest: r"C:\relay-rw".into(),
                writable: true,
            },
        ],
        env,
        unit_id_file: Some(dir.join("unit-id")),
    };
    let backend = WindowsSandboxBackend;
    let checked = backend.check(&spec).await.map_err(|e| e.to_string())?;
    backends::ensure_confirmed(&spec, &checked).map_err(|e| e.to_string())?;
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
    let result = match collect(report, &rw, true).await {
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
        for executable in [
            "../server.exe",
            "C:/server.exe",
            r"..\server.exe",
            "/server.exe",
            "x//y.exe",
        ] {
            assert!(
                payload_command(dir.path(), &[executable.into()])
                    .unwrap_err()
                    .contains("relative executable")
            );
        }
        std::fs::write(dir.path().join("data.txt"), "payload").unwrap();
        let dest = tempfile::tempdir().unwrap();
        inventory(dir.path(), Some(dest.path()), 0, &mut (0, 0)).unwrap();
        assert_eq!(
            std::fs::read_to_string(dest.path().join("data.txt")).unwrap(),
            "payload"
        );
        assert!(inventory(dir.path(), None, 0, &mut (10_000, 0)).is_err());
        assert!(inventory(dir.path(), None, 0, &mut (0, 1024 * 1024 * 1024)).is_err());
        assert!(inventory(dir.path(), None, 33, &mut (0, 0)).is_err());
    }

    #[test]
    fn guest_report_must_record_every_required_control() {
        let observations = |state| {
            format!(
                r#"{{"observations":[{{"control":"os.process","state":"verified"}},{{"control":"os.fs","state":"{state}"}},{{"control":"os.net.outbound","state":"verified"}}]}}"#
            )
        };
        assert!(validate_controls(&observations("verified")).is_ok());
        for state in ["unknown", "failed", "skipped", "partially_applied"] {
            assert!(validate_controls(&observations(state)).is_err());
        }
        assert!(validate_controls(r#"{"observations":[]}"#).is_err());
    }
}
