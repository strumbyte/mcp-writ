//! The Apple `container` backend — `IsolationKind::AppleContainer`
//! provided through Apple's `container` CLI on macOS.
//!
//! Scope is deliberately the configuration PR-18 validated on real
//! hardware (`docs/validation/apple-container.md`): a **macOS 26+
//! Apple Silicon host**, Apple's `container` CLI on PATH (the validated
//! line is 1.5.x), the `container-apiserver` service running, and a
//! **Linux/arm64** OCI image workload. `container run` boots one
//! Virtualization.framework VM per unit — the isolation unit is the VM;
//! the recorded unit id is the container id the `--cidfile` captures
//! and the `container-runtime-linux --uuid <id>` process is named
//! after, so the shared `EngineRunHandle`'s `--cidfile`/`rm -f`
//! teardown applies unchanged.
//!
//! Nothing falls back: a missing CLI, a stopped service, an
//! unvalidated version, a non-Linux/foreign-arch image, or a missing
//! guest kernel all refuse before launch — never a silent `runc`
//! container, never a native run. amd64 images are refused rather than
//! launched under Rosetta translation: translation is emulation, not
//! the validated boundary.

use std::process::Command as StdCommand;

use super::oci::EngineRunHandle;
use super::{
    BackendCapabilities, BackendError, IsolationBackend, IsolationCheck, IsolationHandle,
    LaunchSpec,
};
use crate::container::engine::{BoxFuture, ContainerEngine, EngineError};
use crate::execution::{IsolationKind, IsolationUnit, TargetArch, TargetOs};

/// The substrate driver CLI — Apple's `container` tool, a literal
/// `container` binary on PATH. It is not a container *engine*: there is
/// no daemon in the docker sense — `container run` asks
/// `container-apiserver` to boot one Virtualization.framework Linux VM
/// per unit.
pub(crate) const APPLE_CLI: &str = "container";

/// The per-unit runtime process the substrate spawns — one
/// `container-runtime-linux --uuid <id>` process per running VM;
/// recorded in diagnostics as the VM evidence.
const APPLE_RUNTIME_NAME: &str = "container-runtime-linux";

/// The apiserver identity `container system status` must report —
/// proof the CLI on PATH is driving Apple's service and not a
/// lookalike binary of the same name.
const APPLE_SERVER_APP: &str = "container-apiserver";

/// The validated `container` CLI/apiserver line — the 1.5.x series this
/// backend was built and exercised against
/// (docs/validation/apple-container.md). A different major version is
/// unvalidated: it refuses rather than assuming flag/JSON compatibility.
const SUPPORTED_MAJOR: u64 = 1;
const MIN_MINOR: u64 = 5;

/// Minimum macOS major the substrate supports — `container` requires
/// macOS 26 (Tahoe); `system status` reports the host as
/// `"Version 26.x.y (Build …)"`.
const MIN_MACOS_MAJOR: u64 = 26;

/// Bound on each `container system …` probe call — a wedged apiserver
/// must not stall `check`/`plan` indefinitely.
const PROBE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// The apple backend's declared capability set: a macOS host only (the
/// Virtualization.framework substrate is Apple-only), the same Linux
/// guest contract as the OCI path (`mcp-secure-runner` is a Linux ELF),
/// stdio pipes over an attached `container run -i` (the substrate has
/// no detached stdio path — `run -d` closes the workload's stdin), host
/// path shares, termination via `container rm -f`, and the `--cidfile`
/// unit-id record. The guest kernel — and therefore the Landlock/seccomp
/// ABIs the in-guest runner applies — is pinned by the installation's
/// recorded kernel, which the host cannot re-point per launch.
pub(crate) const APPLE_CAPABILITIES: BackendCapabilities = BackendCapabilities {
    host_os: &[TargetOs::MacOs],
    guest_os: &[TargetOs::Linux],
    oci_image: true,
    argv_command: false,
    stdio_pipes: true,
    terminate: true,
    host_shares: true,
    resource_limits: true,
    observations: &[
        "system-status",
        "system-properties",
        "guest-report-mount",
        "unit-id-file",
    ],
};

/// The `container` CLI driver — the apple backend's substrate access.
///
/// This is *not* an OCI engine: `build` is refused (the product
/// contract launches pre-built images — `container build` exists on
/// the CLI but is not wired into this launch contract), `inspect`
/// returns Apple's own record shape (`variants[]` — parsed by
/// `inspect::parse_inspect_json`), and `info` is
/// `container system status --format json`.
pub struct AppleContainerEngine;

/// Resolve the substrate driver — Apple's `container` CLI on PATH, or
/// a `NotAvailable` refusal. Never silently selects another tool: this
/// backend launches through Apple's CLI only.
pub(crate) fn resolve_engine() -> Result<Box<dyn ContainerEngine>, EngineError> {
    crate::container::engine::try_engine(AppleContainerEngine)
}

/// `container run` arguments for a launch, excluding the driver name —
/// the same hardened launch contract as the OCI path (attached stdio,
/// `--rm` self-removal, the fixed runner entrypoint, cleared channel
/// env) rendered for the Apple CLI's own flag set. There is no
/// `--no-healthcheck` here — docker-specific flags are not carried over
/// blindly, and no docker-only hardening flag is silently skipped
/// without reason: Apple's CLI has no healthcheck concept to disable.
pub(crate) fn apple_run_args(options: &[String], image: &str) -> Vec<String> {
    let mut args = vec![
        "run".to_string(),
        "-i".to_string(),
        "--rm".to_string(),
        "--entrypoint".to_string(),
        "/usr/local/bin/mcp-secure-runner".to_string(),
        "-e".to_string(),
        "MCP_WRIT_ENV=".to_string(),
        "-e".to_string(),
        "MCP_WRIT_SKIP_SANDBOX=".to_string(),
        "-e".to_string(),
        "MCP_WRIT_SERVER=".to_string(),
        // Clear an image-baked launch correlation ID: a guest audit event
        // must correlate with the host launch that spawned it, never with
        // a value baked into the image.
        "-e".to_string(),
        "MCP_WRIT_LAUNCH_ID=".to_string(),
        // Clear an image-baked report redirect target: the guest report
        // channel is only the host-mounted directory `options` re-sets.
        "-e".to_string(),
        format!("{}=", crate::container::guest_report::REPORT_OUT_ENV),
        // Clear an image-baked probe flag: an empty value never triggers
        // the guest ABI probe, so this cannot divert a production launch.
        "-e".to_string(),
        format!(
            "{}=",
            crate::container::guest_report::PROBE_LANDLOCK_ABI_ENV
        ),
    ];
    args.extend(options.iter().cloned());
    args.push(image.to_string());
    args
}

/// `container run` options for an apple launch: the `--platform` pin
/// first — it keeps the launched VM on the validated native boundary
/// (an unpinned multi-arch image could otherwise resolve a foreign
/// arch the substrate would boot under Rosetta translation) — then the
/// shared spec options (shares, env, `--cidfile`).
pub(crate) fn run_options(spec: &LaunchSpec) -> Vec<String> {
    let mut options = vec![
        "--platform".to_string(),
        format!("linux/{}", spec.guest_arch.oci_name()),
    ];
    options.extend(super::oci::spec_run_options(spec));
    options
}

/// `IsolationKind::AppleContainer` over the `container` CLI driver —
/// one Virtualization.framework Linux VM per launched unit.
pub struct AppleContainerBackend {
    engine: Box<dyn ContainerEngine>,
}

impl AppleContainerBackend {
    pub fn new(engine: Box<dyn ContainerEngine>) -> Self {
        Self { engine }
    }
}

/// Which validated-configuration prerequisite an apple probe failed
/// on — the stable tags `plan` maps to remediation text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ApplePrereq {
    /// The CLI host OS is not macOS — the substrate is an Apple
    /// Virtualization.framework product.
    HostOs,
    /// The host is not arm64 Apple Silicon — the validated path runs
    /// native arm64 guests only.
    HostArch,
    /// The resolved driver is not Apple's `container` CLI, or `system
    /// status` reports a foreign apiserver identity.
    Driver,
    /// `container system status` / `system property list` failed or
    /// timed out — the substrate cannot be probed.
    SystemProbe,
    /// The apiserver answered but is not `running` — the service needs
    /// `container system start`, which mcp-writ never runs itself.
    SystemStopped,
    /// macOS is older than the substrate's minimum (26), or the host
    /// version could not be determined.
    HostVersion,
    /// CLI or apiserver version is outside the validated 1.5.x line.
    Version,
    /// `system property list` records no guest kernel — the substrate
    /// cannot boot a VM.
    Kernel,
}

/// A refused apple prerequisite: which check failed plus the human
/// detail `check`/`plan` surface.
#[derive(Debug)]
pub(crate) struct ApplePrereqFailure {
    pub prereq: ApplePrereq,
    pub detail: String,
}

impl ApplePrereqFailure {
    fn new(prereq: ApplePrereq, detail: String) -> Self {
        Self { prereq, detail }
    }

    /// Map to the launch-refusal error: a failed substrate probe is a
    /// launch-path failure; an absent prerequisite is an unsuitable
    /// environment, which refuses as `Unsupported` (never a fallback).
    fn into_backend_error(self) -> BackendError {
        match self.prereq {
            ApplePrereq::SystemProbe => BackendError::LaunchFailed(self.detail),
            _ => BackendError::Unsupported(self.detail),
        }
    }
}

/// Remediation text for a refused prerequisite — the host-side fix,
/// which `plan` reports. mcp-writ never repairs the host itself.
pub(crate) fn prereq_remediation(prereq: ApplePrereq) -> String {
    match prereq {
        ApplePrereq::HostOs => "apple-container isolation needs a macOS Apple Silicon \
             host — run from the Mac that hosts the `container` service"
            .to_string(),
        ApplePrereq::HostArch => "the apple `container` substrate runs native arm64 \
             Linux guests — use a Mac on Apple Silicon"
            .to_string(),
        ApplePrereq::Driver => "install Apple's `container` tool so `container` \
             resolves on PATH (macOS 26+: `brew install container`, or the \
             GitHub release — see docs/validation/apple-container.md)"
            .to_string(),
        ApplePrereq::SystemProbe => {
            "repair the `container` installation so `container system status` answers".to_string()
        }
        ApplePrereq::SystemStopped => {
            "run `container system start` to bring container-apiserver up, then re-run".to_string()
        }
        ApplePrereq::HostVersion => {
            "the apple `container` substrate needs macOS 26 or later — upgrade the host OS"
                .to_string()
        }
        ApplePrereq::Version => "validated `container` CLI/apiserver versions are the \
             1.5.x line — install a supported release (see \
             docs/validation/apple-container.md)"
            .to_string(),
        ApplePrereq::Kernel => "reinstall `container` — no guest kernel is recorded in \
             `container system property list`"
            .to_string(),
    }
}

/// `major.minor` of a `container` version string ("1.5.0" — trailing
/// components and suffixes ignored); `None` when unparseable.
fn parse_version(raw: &str) -> Option<(u64, u64)> {
    let mut parts = raw.trim().split(|c: char| !c.is_ascii_digit());
    let major: u64 = parts.next()?.parse().ok()?;
    let minor: u64 = parts.next()?.parse().ok()?;
    Some((major, minor))
}

/// The macOS major version from `system status`'s
/// `host.operatingSystem` ("Version 26.6.2 (Build 25G83)") — the first
/// whitespace-separated token whose leading `.`-segment is fully
/// numeric. `None` when the field carries no numeric version atom.
fn macos_major(host_os: &str) -> Option<u64> {
    host_os
        .split_whitespace()
        .find_map(|token| token.split('.').next()?.parse::<u64>().ok())
}

/// `container system status --format json`, distilled to the members
/// the probe gates on.
#[derive(Debug)]
struct SystemStatus {
    status: Option<String>,
    server_app: Option<String>,
    server_version: Option<String>,
    client_version: Option<String>,
    host_arch: Option<String>,
    host_os: Option<String>,
}

fn member_str(value: &nojson::RawJsonValue<'_, '_>, name: &str) -> Option<String> {
    value
        .to_member(name)
        .ok()
        .and_then(|m| m.optional())
        .and_then(|v| v.to_unquoted_string_str().ok())
        .map(|s| s.into_owned())
}

fn parse_system_status(json_str: &str) -> Result<SystemStatus, ApplePrereqFailure> {
    let json = nojson::RawJson::parse(json_str).map_err(|e| {
        ApplePrereqFailure::new(
            ApplePrereq::SystemProbe,
            format!("`container system status` is not valid JSON: {e}"),
        )
    })?;
    let root = json.value();
    let nested = |obj: &str, name: &str| -> Option<String> {
        root.to_member(obj)
            .ok()
            .and_then(|m| m.optional())
            .and_then(|o| member_str(&o, name))
    };
    Ok(SystemStatus {
        status: member_str(&root, "status"),
        server_app: nested("server", "appName"),
        server_version: nested("server", "version"),
        client_version: nested("client", "version"),
        host_arch: nested("host", "architecture"),
        host_os: nested("host", "operatingSystem"),
    })
}

/// `(binaryPath, digest)` of the guest kernel recorded in
/// `container system property list` — `None` when absent or the JSON
/// is unparseable. The digest is the kernel content hash the
/// installation verified at download; recording it ties the launch to
/// the exact guest kernel.
fn kernel_detail(props_json: &str) -> Option<(String, String)> {
    let json = nojson::RawJson::parse(props_json).ok()?;
    let kernel = json.value().to_member("kernel").ok()?.optional()?;
    let digest = member_str(&kernel, "digest")?;
    let path = member_str(&kernel, "binaryPath").unwrap_or_else(|| "<unrecorded>".to_string());
    Some((path, digest))
}

/// `container system property list --format json` — the substrate's own
/// configuration record (guest kernel, VM defaults).
async fn system_properties() -> Result<String, EngineError> {
    let mut cmd = tokio::process::Command::new(APPLE_CLI);
    cmd.args(["system", "property", "list", "--format", "json"]);
    // A caller timeout drops this future — the spawned CLI must die
    // with it rather than leaking as an orphan.
    cmd.kill_on_drop(true);
    let output = cmd.output().await?;
    if !output.status.success() {
        return Err(EngineError::CommandFailed {
            engine: APPLE_CLI.into(),
            message: String::from_utf8_lossy(&output.stderr).into_owned(),
        });
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

/// Probe the validated-configuration prerequisites shared by `check`
/// and `plan`'s `apple.system` diagnostic. Read-only: two bounded
/// `container system …` calls — nothing is installed, started, or
/// reconfigured.
///
/// `run-image` and `plan` already probe `engine.info()` once for the
/// substrate-OS record; the repeat here is deliberate — the backend's
/// evidence is its own bounded read, not data threaded through a
/// caller whose contract hands over only the spec. Both calls share
/// the [`PROBE_TIMEOUT`] bound.
///
/// On success returns the launch-record detail string (driver/server
/// versions, per-unit runtime, guest kernel). Failure names the
/// refused prerequisite; a launch never proceeds on an unverified
/// apple stack, and never degrades to another backend.
pub(crate) async fn probe(engine: &dyn ContainerEngine) -> Result<String, ApplePrereqFailure> {
    probe_with(engine, Box::pin(system_properties())).await
}

/// [`probe`] with the properties read injected — tests exercise the
/// gating logic without a real apiserver.
async fn probe_with(
    engine: &dyn ContainerEngine,
    properties: BoxFuture<'static, Result<String, EngineError>>,
) -> Result<String, ApplePrereqFailure> {
    let fail = ApplePrereqFailure::new;

    if TargetOs::host() != TargetOs::MacOs {
        return Err(fail(
            ApplePrereq::HostOs,
            format!(
                "apple-container isolation needs a macOS host — the substrate is \
                 Apple's Virtualization.framework; this host is '{}'",
                TargetOs::host().name()
            ),
        ));
    }
    if TargetArch::host() != TargetArch::Aarch64 {
        return Err(fail(
            ApplePrereq::HostArch,
            format!(
                "the apple `container` substrate launches native arm64 Linux guests \
                 — this host is '{}'",
                TargetArch::host().name()
            ),
        ));
    }
    if engine.name() != APPLE_CLI {
        return Err(fail(
            ApplePrereq::Driver,
            format!(
                "the apple container backend launches through Apple's `container` CLI \
                 — driver '{}' is not the substrate CLI",
                engine.name()
            ),
        ));
    }

    let status_json = match tokio::time::timeout(PROBE_TIMEOUT, engine.info()).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            return Err(fail(
                ApplePrereq::SystemProbe,
                format!("`container system status` failed: {e}"),
            ));
        }
        Err(_) => {
            return Err(fail(
                ApplePrereq::SystemProbe,
                format!(
                    "`container system status` did not answer within {}s",
                    PROBE_TIMEOUT.as_secs()
                ),
            ));
        }
    };
    let status = parse_system_status(&status_json)?;
    match status.status.as_deref() {
        Some("running") => {}
        Some(other) => {
            return Err(fail(
                ApplePrereq::SystemStopped,
                format!(
                    "container-apiserver is '{other}' — the substrate is not running \
                     (`container system start` brings it up)"
                ),
            ));
        }
        None => {
            return Err(fail(
                ApplePrereq::SystemProbe,
                "`container system status` JSON carries no `status` field".to_string(),
            ));
        }
    }
    if status.server_app.as_deref() != Some(APPLE_SERVER_APP) {
        return Err(fail(
            ApplePrereq::Driver,
            format!(
                "`container system status` reports server '{}' — not Apple's \
                 {APPLE_SERVER_APP}; the `container` on PATH is not driving the \
                 apple substrate",
                status.server_app.as_deref().unwrap_or("<absent>")
            ),
        ));
    }
    if status.host_arch.as_deref() != Some("arm64") {
        return Err(fail(
            ApplePrereq::HostArch,
            format!(
                "the substrate reports host architecture '{}' — the validated \
                 path is Apple Silicon (arm64)",
                status.host_arch.as_deref().unwrap_or("<absent>")
            ),
        ));
    }
    match status.host_os.as_deref().and_then(macos_major) {
        Some(major) if major >= MIN_MACOS_MAJOR => {}
        Some(major) => {
            return Err(fail(
                ApplePrereq::HostVersion,
                format!(
                    "the apple `container` substrate needs macOS {MIN_MACOS_MAJOR}+ — \
                     this host reports major version {major}"
                ),
            ));
        }
        None => {
            return Err(fail(
                ApplePrereq::HostVersion,
                format!(
                    "the host macOS version could not be determined from `container \
                     system status` ('{}' — need macOS {MIN_MACOS_MAJOR}+)",
                    status.host_os.as_deref().unwrap_or("<absent>")
                ),
            ));
        }
    }
    for (label, raw) in [
        ("CLI", status.client_version.as_deref()),
        ("apiserver", status.server_version.as_deref()),
    ] {
        if !raw
            .and_then(parse_version)
            .is_some_and(|(major, minor)| major == SUPPORTED_MAJOR && minor >= MIN_MINOR)
        {
            return Err(fail(
                ApplePrereq::Version,
                format!(
                    "the `container` {label} version '{}' is outside the validated \
                     {SUPPORTED_MAJOR}.{MIN_MINOR}.x line",
                    raw.unwrap_or("<absent>")
                ),
            ));
        }
    }

    let props_json = match tokio::time::timeout(PROBE_TIMEOUT, properties).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            return Err(fail(
                ApplePrereq::SystemProbe,
                format!("`container system property list` failed: {e}"),
            ));
        }
        Err(_) => {
            return Err(fail(
                ApplePrereq::SystemProbe,
                format!(
                    "`container system property list` did not answer within {}s",
                    PROBE_TIMEOUT.as_secs()
                ),
            ));
        }
    };
    let (kernel_path, kernel_digest) = kernel_detail(&props_json).ok_or_else(|| {
        fail(
            ApplePrereq::Kernel,
            "`container system property list` records no guest kernel — the \
             substrate cannot boot a VM"
                .to_string(),
        )
    })?;

    Ok(format!(
        "driver: {} {} (apiserver {}); runtime: {APPLE_RUNTIME_NAME} — one \
         Virtualization.framework VM per unit; guest kernel: {} ({}); host: {} {}",
        APPLE_CLI,
        status.client_version.as_deref().unwrap_or("?"),
        status.server_version.as_deref().unwrap_or("?"),
        kernel_path,
        kernel_digest,
        status.host_os.as_deref().unwrap_or("macOS ?"),
        status.host_arch.as_deref().unwrap_or("?"),
    ))
}

impl ContainerEngine for AppleContainerEngine {
    fn name(&self) -> &str {
        APPLE_CLI
    }

    /// The apple substrate is a launch runtime, not a builder — the
    /// product contract runs pre-built OCI images. `container build`
    /// exists on the CLI but is deliberately not wired into this
    /// contract, so a build request is an explicit refusal rather than
    /// an untested path.
    fn build<'a>(
        &'a self,
        _dockerfile_path: &'a str,
        _tag: &'a str,
        _context_dir: &'a str,
    ) -> BoxFuture<'a, Result<(), EngineError>> {
        Box::pin(async move {
            Err(EngineError::Unsupported(
                "the apple container backend launches pre-built OCI images — build \
                 with `container build` or an OCI engine, then `run-image`"
                    .to_string(),
            ))
        })
    }

    fn inspect<'a>(&'a self, image: &'a str) -> BoxFuture<'a, Result<String, EngineError>> {
        Box::pin(async move {
            let mut cmd = tokio::process::Command::new(APPLE_CLI);
            cmd.args(["image", "inspect", image]);
            // A caller timeout drops this future — the spawned CLI must
            // die with it rather than leaking as an orphan.
            cmd.kill_on_drop(true);
            let output = cmd.output().await?;
            if !output.status.success() {
                return Err(EngineError::CommandFailed {
                    engine: APPLE_CLI.into(),
                    message: String::from_utf8_lossy(&output.stderr).into_owned(),
                });
            }
            Ok(String::from_utf8_lossy(&output.stdout).into_owned())
        })
    }

    /// `container system status --format json` is this driver's "info"
    /// — the substrate record (`status`, apiserver identity, host) the
    /// probe gates on, and the response shape
    /// `engine_info_os("container", …)` reads.
    fn info<'a>(&'a self) -> BoxFuture<'a, Result<String, EngineError>> {
        Box::pin(async move {
            let mut cmd = tokio::process::Command::new(APPLE_CLI);
            cmd.args(["system", "status", "--format", "json"]);
            // A caller timeout drops this future — the spawned CLI must
            // die with it rather than leaking as an orphan.
            cmd.kill_on_drop(true);
            let output = cmd.output().await?;
            if !output.status.success() {
                return Err(EngineError::CommandFailed {
                    engine: APPLE_CLI.into(),
                    message: String::from_utf8_lossy(&output.stderr).into_owned(),
                });
            }
            Ok(String::from_utf8_lossy(&output.stdout).into_owned())
        })
    }

    /// `container run` with attached, piped stdio — the substrate has
    /// no detached stdio path (`run -d` closes the workload's stdin),
    /// so the session is always the spawned child's pipes.
    fn run<'a>(
        &'a self,
        image: &'a str,
        args: &'a [&'a str],
        stdin_pipe: bool,
    ) -> BoxFuture<'a, Result<tokio::process::Child, EngineError>> {
        Box::pin(async move {
            let option_owned: Vec<String> = args.iter().map(|s| (*s).to_string()).collect();
            let argv = apple_run_args(&option_owned, image);
            let mut cmd = tokio::process::Command::new(APPLE_CLI);
            cmd.args(&argv);
            if stdin_pipe {
                cmd.stdin(std::process::Stdio::piped());
            }
            cmd.stdout(std::process::Stdio::piped());
            // stderr inherits — the CLI's progress/diagnostic lines stay
            // visible and a piped-but-undrained stderr cannot deadlock
            // the guest.
            cmd.stderr(std::process::Stdio::inherit());
            Ok(cmd.spawn()?)
        })
    }

    fn is_available(&self) -> bool {
        StdCommand::new(APPLE_CLI)
            .arg("--version")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }
}

impl IsolationBackend for AppleContainerBackend {
    fn kind(&self) -> IsolationKind {
        IsolationKind::AppleContainer
    }

    fn capabilities(&self) -> BackendCapabilities {
        APPLE_CAPABILITIES
    }

    fn check<'a>(
        &'a self,
        spec: &'a LaunchSpec,
    ) -> BoxFuture<'a, Result<IsolationCheck, BackendError>> {
        Box::pin(async move {
            // The backend confirms exactly the isolation it implements —
            // a spec for another method refuses rather than degrading.
            if spec.isolation != IsolationKind::AppleContainer {
                return Err(BackendError::Unsupported(format!(
                    "the apple container backend cannot provide '{}' isolation",
                    spec.isolation.name()
                )));
            }
            if spec.image.is_none() {
                return Err(BackendError::Unsupported(
                    "the apple container backend requires an image-defined workload".to_string(),
                ));
            }
            if spec.guest_os != TargetOs::Linux {
                return Err(BackendError::Unsupported(format!(
                    "the apple launch contract carries the same Linux guest \
                     entrypoint (/usr/local/bin/mcp-secure-runner) as the \
                     container path — and the substrate runs Linux guests only; \
                     a {} guest needs its own backend",
                    spec.guest_os.name()
                )));
            }
            // The VM boots a native-arch guest kernel. Unlike the OCI
            // substrate — which may negotiate a foreign arch via
            // binfmt/qemu-user — the only foreign-arch path here is
            // Rosetta translation, which is explicitly not the validated
            // boundary: refuse rather than launch into emulation.
            if spec.guest_arch != TargetArch::host() {
                return Err(BackendError::Unsupported(format!(
                    "the apple `container` VM launches native-arch images — image \
                     architecture '{}' on a {} host would run only under Rosetta \
                     translation, which is not the validated isolation boundary",
                    spec.guest_arch.name(),
                    TargetArch::host().name()
                )));
            }
            let detail = probe(&*self.engine)
                .await
                .map_err(ApplePrereqFailure::into_backend_error)?;
            Ok(IsolationCheck {
                verified: IsolationKind::AppleContainer,
                unit: IsolationUnit::Vm,
                detail: Some(detail),
            })
        })
    }

    fn launch<'a>(
        &'a self,
        spec: &'a LaunchSpec,
    ) -> BoxFuture<'a, Result<Box<dyn IsolationHandle>, BackendError>> {
        Box::pin(async move {
            let image = spec.image.as_deref().ok_or_else(|| {
                BackendError::Unsupported(
                    "the apple container backend requires an image-defined workload".to_string(),
                )
            })?;
            let options = run_options(spec);
            let option_refs: Vec<&str> = options.iter().map(String::as_str).collect();
            let child = self.engine.run(image, &option_refs, true).await?;
            Ok(Box::new(
                EngineRunHandle::attach(child, self.engine.name(), spec.unit_id_file.clone()).await,
            ) as Box<dyn IsolationHandle>)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(image: &str) -> LaunchSpec {
        LaunchSpec {
            isolation: IsolationKind::AppleContainer,
            image: Some(image.to_string()),
            guest_os: TargetOs::Linux,
            guest_arch: TargetArch::host(),
            shares: Vec::new(),
            env: Vec::new(),
            unit_id_file: None,
        }
    }

    /// A canned driver for probe tests: a name plus the
    /// `system status` JSON (or error) it returns. Every other engine
    /// method is unreachable — the probe must stay read-only.
    struct StubEngine {
        name: &'static str,
        info: Result<String, EngineError>,
    }

    impl StubEngine {
        fn container(status_json: &str) -> Self {
            Self {
                name: APPLE_CLI,
                info: Ok(status_json.to_string()),
            }
        }
    }

    impl ContainerEngine for StubEngine {
        fn name(&self) -> &str {
            self.name
        }
        fn build<'a>(
            &'a self,
            _d: &'a str,
            _t: &'a str,
            _c: &'a str,
        ) -> BoxFuture<'a, Result<(), EngineError>> {
            unreachable!("the apple probe never builds")
        }
        fn inspect<'a>(&'a self, _i: &'a str) -> BoxFuture<'a, Result<String, EngineError>> {
            unreachable!("the apple probe never inspects")
        }
        fn info<'a>(&'a self) -> BoxFuture<'a, Result<String, EngineError>> {
            let info = match &self.info {
                Ok(s) => Ok(s.clone()),
                Err(_) => Err(EngineError::CommandFailed {
                    engine: self.name.to_string(),
                    message: "stub info failure".to_string(),
                }),
            };
            Box::pin(async move { info })
        }
        fn run<'a>(
            &'a self,
            _i: &'a str,
            _a: &'a [&'a str],
            _s: bool,
        ) -> BoxFuture<'a, Result<tokio::process::Child, EngineError>> {
            unreachable!("check() refusals happen before launch")
        }
        fn is_available(&self) -> bool {
            true
        }
    }

    /// A `container system status` record in the validated shape; each
    /// field is injectable so the probe's gates are exercised one at a
    /// time.
    fn system_status(
        status: &str,
        server_app: &str,
        client_v: &str,
        server_v: &str,
        arch: &str,
        os: &str,
    ) -> String {
        format!(
            r#"{{"client":{{"appName":"container","version":"{client_v}"}},
                 "server":{{"appName":"{server_app}","version":"{server_v}"}},
                 "host":{{"architecture":"{arch}","operatingSystem":"{os}","cpus":8}},
                 "status":"{status}"}}"#
        )
    }

    /// The validated status record — all gates pass.
    fn good_status() -> String {
        system_status(
            "running",
            APPLE_SERVER_APP,
            "1.5.0",
            "1.5.0",
            "arm64",
            "Version 26.6.2 (Build 25G83)",
        )
    }

    /// A `system property list` record with a guest kernel.
    fn props_with_kernel() -> BoxFuture<'static, Result<String, EngineError>> {
        Box::pin(async {
            Ok(r#"{"kernel":{"binaryPath":"opt/kata/share/kata-containers/vmlinux-6.18.35-197-debug","digest":"sha256:8736c054"},"container":{"cpus":4,"memory":"1gb"}}"#.to_string())
        })
    }

    fn props_failed() -> BoxFuture<'static, Result<String, EngineError>> {
        Box::pin(async {
            Err(EngineError::CommandFailed {
                engine: APPLE_CLI.to_string(),
                message: "stub properties failure".to_string(),
            })
        })
    }

    // -- small parsers ---------------------------------------------------

    #[test]
    fn version_parses_dotted_and_rejects_garbage() {
        assert_eq!(parse_version("1.5.0"), Some((1, 5)));
        assert_eq!(parse_version("1.10.2"), Some((1, 10)));
        assert_eq!(parse_version("2.0"), Some((2, 0)));
        assert_eq!(parse_version(""), None);
        assert_eq!(parse_version("release"), None);
        assert_eq!(parse_version("1"), None);
    }

    #[test]
    fn macos_major_reads_version_token() {
        assert_eq!(macos_major("Version 26.6.2 (Build 25G83)"), Some(26));
        assert_eq!(macos_major("Version 15.7 (Build 24G222)"), Some(15));
        // Non-version strings carry no numeric version atom — the gate
        // refuses them as undeterminable rather than guessing.
        assert_eq!(macos_major("unknown"), None);
        // A bare build tag is not a version ("25G83" does not parse).
        assert_eq!(macos_major("Build 25G83"), None);
    }

    #[test]
    fn system_status_parses_nested_members() {
        let status = parse_system_status(&good_status()).expect("parses");
        assert_eq!(status.status.as_deref(), Some("running"));
        assert_eq!(status.server_app.as_deref(), Some(APPLE_SERVER_APP));
        assert_eq!(status.client_version.as_deref(), Some("1.5.0"));
        assert_eq!(status.host_arch.as_deref(), Some("arm64"));
        assert_eq!(
            status.host_os.as_deref(),
            Some("Version 26.6.2 (Build 25G83)")
        );
    }

    #[test]
    fn system_status_rejects_non_json() {
        let err = parse_system_status("not json").unwrap_err();
        assert_eq!(err.prereq, ApplePrereq::SystemProbe);
    }

    #[test]
    fn kernel_detail_reads_path_and_digest() {
        let props = r#"{"kernel":{"binaryPath":"opt/kata/share/vmlinux","digest":"sha256:abc"}}"#;
        let (path, digest) = kernel_detail(props).expect("kernel recorded");
        assert_eq!(path, "opt/kata/share/vmlinux");
        assert_eq!(digest, "sha256:abc");
    }

    #[test]
    fn kernel_detail_missing_or_malformed() {
        assert!(kernel_detail("not json").is_none());
        assert!(kernel_detail("{}").is_none());
        // A kernel entry without a digest is not usable evidence.
        assert!(kernel_detail(r#"{"kernel":{"binaryPath":"vmlinux"}}"#).is_none());
    }

    // -- spec-shape refusals (run before any substrate probe) -------------

    #[tokio::test]
    async fn check_rejects_foreign_isolation() {
        let backend = AppleContainerBackend::new(Box::new(StubEngine::container("")));
        let mut spec = spec("img");
        spec.isolation = IsolationKind::Container;
        let err = backend.check(&spec).await.unwrap_err();
        match err {
            BackendError::Unsupported(msg) => assert!(msg.contains("container"), "got: {msg}"),
            other => panic!("expected Unsupported, got: {other}"),
        }
    }

    #[tokio::test]
    async fn check_rejects_argv_only_workload() {
        let backend = AppleContainerBackend::new(Box::new(StubEngine::container("")));
        let mut spec = spec("img");
        spec.image = None;
        let err = backend.check(&spec).await.unwrap_err();
        assert!(matches!(err, BackendError::Unsupported(_)), "got: {err}");
    }

    #[tokio::test]
    async fn check_rejects_non_linux_guest() {
        let backend = AppleContainerBackend::new(Box::new(StubEngine::container("")));
        let mut spec = spec("img");
        spec.guest_os = TargetOs::Windows;
        let err = backend.check(&spec).await.unwrap_err();
        match err {
            BackendError::Unsupported(msg) => assert!(msg.contains("windows"), "got: {msg}"),
            other => panic!("expected Unsupported, got: {other}"),
        }
    }

    /// The VM's guest kernel is host-arch — a foreign-arch image is
    /// refused (Rosetta translation is not the validated boundary)
    /// rather than launched into emulation.
    #[tokio::test]
    async fn check_rejects_foreign_arch() {
        let backend = AppleContainerBackend::new(Box::new(StubEngine::container("")));
        let mut spec = spec("img");
        spec.guest_arch = match TargetArch::host() {
            TargetArch::Aarch64 => TargetArch::X86_64,
            _ => TargetArch::Aarch64,
        };
        let err = backend.check(&spec).await.unwrap_err();
        match err {
            BackendError::Unsupported(msg) => {
                assert!(msg.contains("Rosetta"), "got: {msg}")
            }
            other => panic!("expected Unsupported, got: {other}"),
        }
    }

    // -- prerequisite probe (stub engine; properties injected) ------------

    /// On a non-macOS (or non-arm64) host every probe refuses at the
    /// host gates — deterministic regardless of driver state.
    #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
    #[tokio::test]
    async fn probe_refuses_non_apple_silicon_host() {
        let stub = StubEngine::container(&good_status());
        let err = probe_with(&stub, props_with_kernel()).await.unwrap_err();
        assert!(
            matches!(err.prereq, ApplePrereq::HostOs | ApplePrereq::HostArch),
            "got: {:?}",
            err.prereq
        );
    }

    /// Probe internals on macOS arm64 only — the host gates precede
    /// them, so these assertions cannot run elsewhere.
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    mod macos_probe {
        use super::*;

        #[tokio::test]
        async fn probe_passes_on_the_validated_shape() {
            let stub = StubEngine::container(&good_status());
            let detail = probe_with(&stub, props_with_kernel())
                .await
                .expect("probe passes");
            assert!(detail.contains("driver: container 1.5.0"), "got: {detail}");
            assert!(
                detail.contains(APPLE_RUNTIME_NAME),
                "the per-VM runtime is part of the evidence: {detail}"
            );
            assert!(detail.contains("sha256:8736c054"), "got: {detail}");
            assert!(detail.contains("vmlinux-6.18.35"), "got: {detail}");
        }

        #[tokio::test]
        async fn probe_refuses_foreign_driver() {
            let stub = StubEngine {
                name: "docker",
                info: Ok(good_status()),
            };
            let err = probe_with(&stub, props_with_kernel()).await.unwrap_err();
            assert_eq!(err.prereq, ApplePrereq::Driver);
            assert!(err.detail.contains("docker"), "got: {}", err.detail);
        }

        #[tokio::test]
        async fn probe_refuses_unprobeable_substrate() {
            let stub = StubEngine {
                name: APPLE_CLI,
                info: Err(EngineError::CommandFailed {
                    engine: APPLE_CLI.to_string(),
                    message: "apiserver unreachable".to_string(),
                }),
            };
            let err = probe_with(&stub, props_with_kernel()).await.unwrap_err();
            assert_eq!(err.prereq, ApplePrereq::SystemProbe);
            // A substrate that cannot be probed is a launch-path
            // failure, not an unsuitable-environment refusal.
            assert!(matches!(
                err.into_backend_error(),
                BackendError::LaunchFailed(_)
            ));
        }

        #[tokio::test]
        async fn probe_refuses_stopped_substrate() {
            let stub = StubEngine::container(&system_status(
                "stopped",
                APPLE_SERVER_APP,
                "1.5.0",
                "1.5.0",
                "arm64",
                "Version 26.6.2 (Build 25G83)",
            ));
            let err = probe_with(&stub, props_with_kernel()).await.unwrap_err();
            assert_eq!(err.prereq, ApplePrereq::SystemStopped);
            assert!(err.detail.contains("stopped"), "got: {}", err.detail);
            // A missing prerequisite is an unsuitable-environment
            // refusal (Unsupported), not a launch failure.
            assert!(matches!(
                err.into_backend_error(),
                BackendError::Unsupported(_)
            ));
        }

        #[tokio::test]
        async fn probe_refuses_foreign_apiserver_identity() {
            let stub = StubEngine::container(&system_status(
                "running",
                "dockerd",
                "1.5.0",
                "1.5.0",
                "arm64",
                "Version 26.6.2 (Build 25G83)",
            ));
            let err = probe_with(&stub, props_with_kernel()).await.unwrap_err();
            assert_eq!(err.prereq, ApplePrereq::Driver);
            assert!(err.detail.contains("dockerd"), "got: {}", err.detail);
        }

        #[tokio::test]
        async fn probe_refuses_foreign_host_arch() {
            let stub = StubEngine::container(&system_status(
                "running",
                APPLE_SERVER_APP,
                "1.5.0",
                "1.5.0",
                "x86_64",
                "Version 26.6.2 (Build 25G83)",
            ));
            let err = probe_with(&stub, props_with_kernel()).await.unwrap_err();
            assert_eq!(err.prereq, ApplePrereq::HostArch);
        }

        #[tokio::test]
        async fn probe_refuses_old_macos() {
            let stub = StubEngine::container(&system_status(
                "running",
                APPLE_SERVER_APP,
                "1.5.0",
                "1.5.0",
                "arm64",
                "Version 15.7 (Build 24G222)",
            ));
            let err = probe_with(&stub, props_with_kernel()).await.unwrap_err();
            assert_eq!(err.prereq, ApplePrereq::HostVersion);
            assert!(err.detail.contains("15"), "got: {}", err.detail);
        }

        #[tokio::test]
        async fn probe_refuses_unsupported_versions() {
            for v in ["0.9.0", "1.4.0", "2.0.0", "garbage"] {
                let stub = StubEngine::container(&system_status(
                    "running",
                    APPLE_SERVER_APP,
                    v,
                    "1.5.0",
                    "arm64",
                    "Version 26.6.2 (Build 25G83)",
                ));
                let err = probe_with(&stub, props_with_kernel()).await.unwrap_err();
                assert_eq!(err.prereq, ApplePrereq::Version, "version {v}");
                assert!(err.detail.contains(v), "got: {}", err.detail);
            }
            // The apiserver's version gates identically.
            let stub = StubEngine::container(&system_status(
                "running",
                APPLE_SERVER_APP,
                "1.5.0",
                "1.4.0",
                "arm64",
                "Version 26.6.2 (Build 25G83)",
            ));
            let err = probe_with(&stub, props_with_kernel()).await.unwrap_err();
            assert_eq!(err.prereq, ApplePrereq::Version);
        }

        #[tokio::test]
        async fn probe_refuses_missing_guest_kernel() {
            let stub = StubEngine::container(&good_status());
            let no_kernel: BoxFuture<'static, Result<String, EngineError>> =
                Box::pin(async { Ok(r#"{"container":{"cpus":4}}"#.to_string()) });
            let err = probe_with(&stub, no_kernel).await.unwrap_err();
            assert_eq!(err.prereq, ApplePrereq::Kernel);
        }

        #[tokio::test]
        async fn probe_refuses_unprobeable_properties() {
            let stub = StubEngine::container(&good_status());
            let err = probe_with(&stub, props_failed()).await.unwrap_err();
            assert_eq!(err.prereq, ApplePrereq::SystemProbe);
        }
    }

    // -- run arguments ----------------------------------------------------

    #[test]
    fn run_args_use_the_apple_flag_set() {
        let args = apple_run_args(&[], "img");
        // The hardened contract is preserved — attached stdio, `--rm`
        // self-removal, the fixed runner entrypoint, cleared channel env.
        assert_eq!(
            &args[..5],
            [
                "run",
                "-i",
                "--rm",
                "--entrypoint",
                "/usr/local/bin/mcp-secure-runner"
            ]
        );
        assert_eq!(args.last().unwrap(), "img");
        assert!(args.iter().any(|a| a == "MCP_WRIT_ENV="));
        assert!(args.iter().any(|a| a == "MCP_WRIT_LAUNCH_ID="));
        assert!(args.iter().any(|a| a == "MCP_WRIT_REPORT_OUT="));
        assert!(args.iter().any(|a| a == "MCP_WRIT_PROBE_LANDLOCK_ABI="));
        // Docker-specific flags are not carried over: Apple's CLI has no
        // `--no-healthcheck`.
        assert!(
            !args.iter().any(|a| a == "--no-healthcheck"),
            "the apple flag set never borrows docker-only flags: {args:?}"
        );
    }

    #[test]
    fn run_options_pin_platform_first() {
        let mut spec = spec("img");
        spec.shares.push(super::super::ShareMount {
            host: std::path::PathBuf::from("/tmp/policy.kdl"),
            guest: "/etc/mcp-secure/policy.kdl".to_string(),
            writable: false,
        });
        spec.unit_id_file = Some(std::path::PathBuf::from("/tmp/u.id"));
        let options = run_options(&spec);
        // `--platform linux/<host-arch>` is the substrate selector — it
        // leads the option list so it can never be lost under the
        // shared spec options.
        assert_eq!(
            options[..2],
            [
                "--platform".to_string(),
                format!("linux/{}", TargetArch::host().oci_name())
            ]
        );
        assert!(
            options
                .iter()
                .any(|a| a.contains("policy.kdl:ro") || a.ends_with(":ro"))
        );
        assert!(options.iter().any(|a| a == "--cidfile"));
    }

    #[test]
    fn apple_capabilities_declared() {
        let caps = AppleContainerBackend::new(Box::new(StubEngine::container(""))).capabilities();
        assert!(caps.oci_image && !caps.argv_command);
        assert!(caps.stdio_pipes && caps.terminate && caps.host_shares);
        assert_eq!(caps.host_os, &[TargetOs::MacOs]);
        assert_eq!(caps.guest_os, &[TargetOs::Linux]);
        assert_eq!(IsolationKind::AppleContainer.unit(), IsolationUnit::Vm);
        assert_eq!(
            IsolationKind::AppleContainer.substrate(),
            crate::execution::ExecutionSubstrate::Vm
        );
    }
}
