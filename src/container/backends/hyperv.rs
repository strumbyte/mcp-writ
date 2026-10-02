//! The Hyper-V isolated Windows container backend —
//! `IsolationKind::HyperV` provided by a Windows docker engine:
//! `docker run --isolation=hyperv` launches the image inside a
//! dedicated Hyper-V utility VM, so the isolation unit is a VM running
//! the image's user-mode OS on a hypervisor-provided kernel — a second
//! kernel boundary, not the shared host kernel a process-isolated
//! container would use. The recorded unit id is the container id
//! (`--cidfile`), so the shared [`EngineRunHandle`]'s `rm -f` teardown
//! applies unchanged.
//!
//! Scope is the single configuration PR-20 validated on real hardware
//! (`docs/validation/windows-hyperv.md`): a **Windows x86-64 host**,
//! the **docker** engine in Windows-containers mode (`OSType=windows`),
//! the Hyper-V compute stack installed (`vmcompute`/`hns` services), and
//! a windows/amd64 image whose recorded `OsVersion` build is not newer
//! than the host's — the documented guest-build rule for Hyper-V
//! isolation. The guest contract is the PR-21 Windows layout
//! (`C:/mcp-secure/mcp-secure-runner.exe` PID 1, `C:`-spelled policy /
//! log / report directory mounts). Everything outside that shape — a
//! non-Windows host or guest, a non-docker engine, a Linux-mode daemon,
//! a foreign or undeterminable arch, a newer-than-host or unversioned
//! image — refuses before launch; nothing falls back to process
//! isolation or a plain container.
//!
//! Requesting Hyper-V is not itself the isolation evidence: the launch
//! passes `--isolation=hyperv` and then reads the unit's recorded
//! `HostConfig.Isolation` back — a daemon that silently substituted
//! `process` isolation is refused and the unit removed before the
//! workload runs. Guest-side OS controls (AppContainer, Job object,
//! DACL grants) are applied by the in-guest `mcp-secure-runner` — the
//! Windows Warden — and reported through the shared guest-report
//! channel; this backend's evidence is the boundary itself, not the
//! in-guest layers.

use std::process::Stdio;

use super::oci::{EngineRunHandle, spec_run_options};
use super::{
    BackendCapabilities, BackendError, IsolationBackend, IsolationCheck, IsolationHandle,
    LaunchSpec,
};
use crate::container::engine::{BoxFuture, ContainerEngine};
use crate::execution::{IsolationKind, IsolationUnit, TargetArch, TargetOs};

/// The engine the validated configuration runs through — `docker` with
/// its daemon in Windows-containers mode. Other engines' Windows paths
/// (podman on Windows, containerd/CRI) exist but are not the validated
/// stack — they are refused, not probed.
const VALIDATED_ENGINE: &str = "docker";

/// The `docker run --isolation` value this backend requests — and the
/// `HostConfig.Isolation` value the launched unit must record.
const HYPERV_ISOLATION: &str = "hyperv";

/// Guest identity the runner launches under: the in-guest PID 1 must
/// create the AppContainer profile, write DACL grants, and build the
/// Job object before the workload child drops into the low-rights
/// AppContainer token — the identity the recorded validation pinned
/// (`ContainerUser` cannot write the grant ACEs). The workload itself
/// never runs as this identity.
const GUEST_USER: &str = "ContainerAdministrator";

/// Host services whose installation evidences the Hyper-V compute
/// stack — `vmcompute` is the VM compute service the launch goes
/// through, `hns` the host networking service the container's network
/// attachment needs. Both are demand-started by the daemon, so presence
/// (not run state) is the gate.
const HYPERV_SERVICES: &[&str] = &["vmcompute", "hns"];

/// Bound on the `docker info` probe — a wedged daemon must not stall
/// `check`/`plan` indefinitely.
const INFO_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// Bound on each `sc query` probe — a wedged service control manager
/// must not stall `check`/`plan` either. A timeout counts the service
/// as unverifiable, which refuses like an absent one.
const SC_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// Bound on the post-spawn `docker inspect` that re-verifies the unit's
/// recorded isolation.
const VERIFY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// The hyperv backend's declared capability set: a Windows host only
/// (the validated dockerd-in-Windows-mode + Hyper-V stack), a Windows
/// guest contract (`mcp-secure-runner.exe` is a Windows PE), stdio
/// pipes, host path shares for the policy/log/report channels,
/// termination via the engine CLI, and a unit id recorded through
/// `--cidfile`. The VM's user-mode OS is the image's — the in-guest
/// Warden's AppContainer/Job/DACL controls apply against the image's
/// Windows build, gated host-build-compatible at `check`.
pub(crate) const HYPERV_CAPABILITIES: BackendCapabilities = BackendCapabilities {
    host_os: &[TargetOs::Windows],
    guest_os: &[TargetOs::Windows],
    oci_image: true,
    argv_command: false,
    stdio_pipes: true,
    terminate: true,
    host_shares: true,
    resource_limits: true,
    observations: &[
        "engine-info",
        "engine-isolation",
        "guest-report-mount",
        "unit-id-file",
    ],
};

/// `IsolationKind::HyperV` over a Windows docker engine.
pub struct HypervBackend {
    engine: Box<dyn ContainerEngine>,
}

impl HypervBackend {
    pub fn new(engine: Box<dyn ContainerEngine>) -> Self {
        Self { engine }
    }
}

/// Which validated-configuration prerequisite a hyperv probe failed on
/// — the stable tags `plan` maps to remediation text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HypervPrereq {
    /// The CLI host OS is not Windows — the validated stack needs a
    /// Windows host running a Windows-mode dockerd.
    HostOs,
    /// The CLI host arch is not x86-64 — the in-guest runner ships
    /// windows/amd64 only (no windows/arm64 contract yet).
    HostArch,
    /// The resolved engine is not docker — only a Windows-mode dockerd
    /// is the validated configuration.
    Engine,
    /// `docker info` failed or timed out — the daemon cannot be probed.
    EngineProbe,
    /// The engine's substrate OS is not windows (or undeterminable) —
    /// the daemon is in Linux-containers mode.
    EngineMode,
    /// The engine did not report a parseable `OSVersion` — the host
    /// side of the guest-build gate cannot be verified.
    HostVersion,
    /// A required host service (`vmcompute`, `hns`) is not installed —
    /// the Hyper-V compute stack is absent.
    HypervStack,
    /// The image's `OsVersion` build is newer than the host's, or the
    /// image does not record one — the documented compat rule cannot be
    /// satisfied.
    ImageVersion,
}

/// A refused hyperv prerequisite: which check failed plus the human
/// detail `check`/`plan` surface.
#[derive(Debug)]
pub(crate) struct HypervPrereqFailure {
    pub prereq: HypervPrereq,
    pub detail: String,
}

impl HypervPrereqFailure {
    fn new(prereq: HypervPrereq, detail: String) -> Self {
        Self { prereq, detail }
    }

    /// Map to the launch-refusal error: a failed daemon probe is a
    /// launch-path failure; an absent prerequisite is an unsuitable
    /// environment, which refuses as `Unsupported` (never a fallback).
    fn into_backend_error(self) -> BackendError {
        match self.prereq {
            HypervPrereq::EngineProbe => BackendError::LaunchFailed(self.detail),
            _ => BackendError::Unsupported(self.detail),
        }
    }
}

/// Remediation text for a refused prerequisite — the host-side fix,
/// which `plan` reports. mcp-writ never repairs the host itself.
pub(crate) fn prereq_remediation(prereq: HypervPrereq) -> String {
    match prereq {
        HypervPrereq::HostOs => "hyperv isolation needs a Windows host — run from the Windows \
             host whose docker engine runs Windows containers"
            .to_string(),
        HypervPrereq::HostArch => "hyperv isolation needs an x86-64 Windows host — there is no \
             windows/arm64 runner contract yet"
            .to_string(),
        HypervPrereq::Engine => "pass --engine docker — only a Windows-mode dockerd is the \
             validated configuration"
            .to_string(),
        HypervPrereq::EngineProbe => {
            "start or repair the docker daemon so `docker info` answers".to_string()
        }
        HypervPrereq::EngineMode => "switch the docker engine to Windows containers \
             (Docker Desktop tray → 'Switch to Windows containers'), or point the CLI at a \
             native Windows dockerd"
            .to_string(),
        HypervPrereq::HostVersion => "the daemon must report its OS version so the guest-build \
             compatibility rule can be verified"
            .to_string(),
        HypervPrereq::HypervStack => "install the Hyper-V and Containers Windows features and \
             reboot — the vmcompute and hns services must exist (demand-started is fine)"
            .to_string(),
        HypervPrereq::ImageVersion => "use a Windows image whose build is not newer than the \
             host's — Hyper-V isolation runs the image's user-mode OS on the host's kernel build"
            .to_string(),
    }
}

/// The probe result a passing `check`/`hyperv.engine` needs: the
/// launch-record detail line plus the engine-reported host OS version
/// — the host side of the guest-build compatibility gate.
#[derive(Debug)]
pub(crate) struct HypervProbe {
    /// Human-readable detail for the launch record / plan check.
    pub detail: String,
    /// Engine-reported host OS version (`10.0.26200`) — compared
    /// against the image's `OsVersion`.
    pub host_os_version: String,
}

/// A `(major, minor, build)` tuple from a Windows OS version string
/// (`10.0.26100.33438` or `10.0.26200`) — the comparison unit the
/// guest-build rule applies; the revision is the image's, the host has
/// none. The revision is the last tolerated component — anything
/// further is not a Windows version.
fn windows_build_triple(version: &str) -> Option<(u64, u64, u64)> {
    let mut it = version.trim().split('.');
    let major = it.next()?.parse().ok()?;
    let minor = it.next()?.parse().ok()?;
    let build = it.next()?.parse().ok()?;
    if let Some(revision) = it.next() {
        revision.parse::<u64>().ok()?;
        if it.next().is_some() {
            return None;
        }
    }
    Some((major, minor, build))
}

/// The documented compatibility rule for Hyper-V-isolated Windows
/// containers: the guest build must not be newer than the host build —
/// the utility VM supplies the host's kernel, and a newer user-mode
/// image is not backward-compatible with it. `Some(detail)` describes
/// the refusal; `None` is the compatible case. An absent or
/// unparseable version on either side is a refusal: a launch cannot
/// proceed on an unverifiable boundary.
pub(crate) fn image_version_check(
    image_os_version: Option<&str>,
    host_os_version: &str,
) -> Option<String> {
    let Some(host) = windows_build_triple(host_os_version) else {
        return Some(format!(
            "the engine's host OS version '{host_os_version}' could not be \
             parsed — the image/host build rule cannot be verified"
        ));
    };
    let Some(image_raw) = image_os_version else {
        return Some(
            "the image records no OsVersion — a Windows guest whose build is \
             undeterminable cannot be proven compatible with the host"
                .to_string(),
        );
    };
    let Some(image) = windows_build_triple(image_raw) else {
        return Some(format!(
            "the image's OsVersion '{image_raw}' could not be parsed — the \
             image/host build rule cannot be verified"
        ));
    };
    if image > host {
        Some(format!(
            "image build {} is newer than the host build {} — Hyper-V \
             isolation requires guest build ≤ host build",
            image_raw, host_os_version
        ))
    } else {
        None
    }
}

/// The service state `sc query <name>` reports: `Some(state)` when the
/// service is installed (demand-started services count — the daemon
/// starts them), `None` when absent, the query failed, or it did not
/// answer within [`SC_TIMEOUT`]. The state word is read best-effort for
/// the detail line only; the exit status — not localized output text —
/// is what decides presence.
async fn service_state(name: &str) -> Option<String> {
    let out = tokio::time::timeout(
        SC_TIMEOUT,
        tokio::process::Command::new("sc")
            .args(["query", name])
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .output(),
    )
    .await
    .ok()?
    .ok()?;
    if !out.status.success() {
        return None;
    }
    Some(
        sc_state_word(&String::from_utf8_lossy(&out.stdout))
            .unwrap_or("installed")
            .to_string(),
    )
}

/// The state word of an `sc query` answer — `running`, `stopped`, … —
/// from the `STATE`/`STATUS` row's numeric code (state names themselves
/// are localized; the code is not).
fn sc_state_word(text: &str) -> Option<&'static str> {
    for line in text.lines() {
        let Some((label, rest)) = line.split_once(':') else {
            continue;
        };
        if !matches!(label.trim(), "STATE" | "STATUS") {
            continue;
        }
        let code = rest.split_whitespace().next()?.parse::<u32>().ok()?;
        return Some(match code {
            1 => "stopped",
            2 => "start_pending",
            3 => "stop_pending",
            4 => "running",
            5 => "continue_pending",
            6 => "pause_pending",
            7 => "paused",
            _ => "installed",
        });
    }
    None
}

/// Probe the validated-configuration prerequisites shared by `check`
/// and `plan`'s `hyperv.engine` diagnostic. Read-only: `docker info`
/// plus an `sc query` on each Hyper-V service — nothing is installed,
/// started, or reconfigured.
///
/// `run-image` and `plan` already probe `engine.info()` once for the
/// substrate-OS record; the repeat here is deliberate — the backend's
/// evidence is its own bounded read, not data threaded through a
/// caller whose contract hands over only the spec.
///
/// On success returns the launch-record detail plus the host OS
/// version the image compat gate compares against. Failure names the
/// refused prerequisite; a launch never proceeds on an unverified
/// Hyper-V stack, and never degrades to process isolation.
pub(crate) async fn probe(
    engine: &dyn ContainerEngine,
) -> Result<HypervProbe, HypervPrereqFailure> {
    probe_with(engine, service_state).await
}

async fn probe_with(
    engine: &dyn ContainerEngine,
    service_state: impl AsyncFn(&str) -> Option<String>,
) -> Result<HypervProbe, HypervPrereqFailure> {
    let fail = HypervPrereqFailure::new;

    if TargetOs::host() != TargetOs::Windows {
        return Err(fail(
            HypervPrereq::HostOs,
            format!(
                "hyperv isolation needs a Windows host — the validated stack is \
                 a Windows-mode dockerd over the Hyper-V compute services; this \
                 host is '{}'",
                TargetOs::host().name()
            ),
        ));
    }
    if TargetArch::host() != TargetArch::X86_64 {
        return Err(fail(
            HypervPrereq::HostArch,
            format!(
                "hyperv isolation needs an x86-64 host — the in-guest runner \
                 ships windows/amd64 only; this host is '{}'",
                TargetArch::host().name()
            ),
        ));
    }
    if engine.name() != VALIDATED_ENGINE {
        return Err(fail(
            HypervPrereq::Engine,
            format!(
                "the hyperv backend drives a Windows-mode dockerd — engine '{}' \
                 is not the validated configuration",
                engine.name()
            ),
        ));
    }
    let info = match tokio::time::timeout(INFO_TIMEOUT, engine.info()).await {
        Ok(Ok(info)) => info,
        Ok(Err(e)) => {
            return Err(fail(
                HypervPrereq::EngineProbe,
                format!("docker info failed: {e}"),
            ));
        }
        Err(_) => {
            return Err(fail(
                HypervPrereq::EngineProbe,
                format!(
                    "docker info did not answer within {}s",
                    INFO_TIMEOUT.as_secs()
                ),
            ));
        }
    };
    match crate::container::engine::engine_info_os("docker", &info) {
        Some(TargetOs::Windows) => {}
        Some(other) => {
            return Err(fail(
                HypervPrereq::EngineMode,
                format!(
                    "the hyperv backend needs the docker engine in \
                     Windows-containers mode — its substrate OS is '{}'",
                    other.name()
                ),
            ));
        }
        None => {
            return Err(fail(
                HypervPrereq::EngineMode,
                "the engine's substrate OS could not be determined from \
                 `docker info` — a Windows-mode daemon reports OSType=windows"
                    .to_string(),
            ));
        }
    }
    let host_os_version = info_string(&info, "OSVersion").ok_or_else(|| {
        fail(
            HypervPrereq::HostVersion,
            "the daemon's `docker info` carries no parseable OSVersion — the \
             host/image build rule cannot be verified"
                .to_string(),
        )
    })?;
    windows_build_triple(&host_os_version).ok_or_else(|| {
        fail(
            HypervPrereq::HostVersion,
            format!(
                "the daemon's OSVersion '{host_os_version}' is not a Windows \
                 build tuple — the host/image build rule cannot be verified"
            ),
        )
    })?;

    let mut service_detail = String::new();
    for svc in HYPERV_SERVICES {
        match service_state(svc).await {
            Some(state) => {
                service_detail.push_str(&format!("; {svc}: {state}"));
            }
            None => {
                return Err(fail(
                    HypervPrereq::HypervStack,
                    format!(
                        "the '{svc}' service is not installed — the Hyper-V \
                         compute stack requires it (enable the Hyper-V and \
                         Containers Windows features)"
                    ),
                ));
            }
        }
    }

    let server_version = info_string(&info, "ServerVersion").unwrap_or_else(|| "?".to_string());
    let default_isolation = info_string(&info, "Isolation")
        .map(|s| format!("default isolation: {s}"))
        .unwrap_or_else(|| "default isolation unreported".to_string());
    Ok(HypervProbe {
        detail: format!(
            "driver: docker {server_version} (OSType=windows, {default_isolation}); \
             host build {host_os_version}{service_detail}; \
             unit: one Hyper-V utility VM per launch"
        ),
        host_os_version,
    })
}

/// A top-level string member of a `docker info` JSON object — `None`
/// when absent, null, or not a string.
fn info_string(info_json: &str, member: &str) -> Option<String> {
    let json = nojson::RawJson::parse(info_json).ok()?;
    json.value()
        .to_member(member)
        .ok()
        .and_then(|m| m.optional())
        .and_then(|v| v.to_unquoted_string_str().ok())
        .map(|s| s.into_owned())
        .filter(|s| !s.is_empty())
}

/// Render `spec` into `docker run` options: the substrate selector
/// (`--isolation hyperv`) plus the in-guest runner identity pin, ahead
/// of the shared spec options (`--entrypoint`, mounts, channel env,
/// `--cidfile`).
pub(crate) fn run_options(spec: &LaunchSpec) -> Vec<String> {
    let mut options = vec![
        "--isolation".to_string(),
        HYPERV_ISOLATION.to_string(),
        // The validated guest identity: the in-guest runner needs the
        // administrator-in-VM token to install DACL grants, register
        // the AppContainer profile, and build the Job — the workload
        // child itself still drops to the low-rights token. An image's
        // own USER is overridden so the contract holds regardless of
        // the wrapped base's choice.
        "--user".to_string(),
        GUEST_USER.to_string(),
    ];
    options.extend(spec_run_options(spec));
    options
}

/// The isolation the unit record says the engine applied —
/// `HostConfig.Isolation` on the launched container.
fn verify_recorded_isolation(recorded: &str, unit_id: &str) -> Result<(), BackendError> {
    match recorded.trim() {
        "hyperv" => Ok(()),
        "" => Err(BackendError::LaunchFailed(format!(
            "unit {unit_id}: the engine recorded no HostConfig.Isolation — the \
             applied boundary is undeterminable, refusing"
        ))),
        other => Err(BackendError::LaunchFailed(format!(
            "unit {unit_id}: the engine applied '{other}' isolation for a \
             --isolation=hyperv launch — the substituted boundary is refused"
        ))),
    }
}

impl IsolationBackend for HypervBackend {
    fn kind(&self) -> IsolationKind {
        IsolationKind::HyperV
    }

    fn capabilities(&self) -> BackendCapabilities {
        HYPERV_CAPABILITIES
    }

    fn check<'a>(
        &'a self,
        spec: &'a LaunchSpec,
    ) -> BoxFuture<'a, Result<IsolationCheck, BackendError>> {
        Box::pin(async move {
            // The backend confirms exactly the isolation it implements —
            // a spec for another method refuses rather than degrading.
            if spec.isolation != IsolationKind::HyperV {
                return Err(BackendError::Unsupported(format!(
                    "the hyperv backend cannot provide '{}' isolation",
                    spec.isolation.name()
                )));
            }
            if spec.image.is_none() {
                return Err(BackendError::Unsupported(
                    "the hyperv backend requires an image-defined workload".to_string(),
                ));
            }
            if spec.guest_os != TargetOs::Windows {
                return Err(BackendError::Unsupported(format!(
                    "the hyperv launch contract carries the Windows guest \
                     entrypoint (C:/mcp-secure/mcp-secure-runner.exe) — a {} \
                     guest needs its own backend",
                    spec.guest_os.name()
                )));
            }
            // The validated image contract is windows/amd64 — the
            // runner ships that arch only, and a foreign arch inside the
            // utility VM is a certain exec failure.
            if spec.guest_arch != TargetArch::X86_64 {
                return Err(BackendError::Unsupported(format!(
                    "the hyperv backend launches windows/amd64 images — image \
                     architecture '{}' is outside the validated contract",
                    spec.guest_arch.name()
                )));
            }
            let probe = probe(&*self.engine)
                .await
                .map_err(HypervPrereqFailure::into_backend_error)?;
            if let Some(detail) =
                image_version_check(spec.image_os_version.as_deref(), &probe.host_os_version)
            {
                return Err(HypervPrereqFailure::new(HypervPrereq::ImageVersion, detail)
                    .into_backend_error());
            }
            Ok(IsolationCheck {
                verified: IsolationKind::HyperV,
                unit: IsolationUnit::Vm,
                detail: Some(format!(
                    "{}; image build {}",
                    probe.detail,
                    spec.image_os_version.as_deref().unwrap_or("<absent>")
                )),
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
                    "the hyperv backend requires an image-defined workload".to_string(),
                )
            })?;
            let options = run_options(spec);
            let option_refs: Vec<&str> = options.iter().map(String::as_str).collect();
            let child = self.engine.run(image, &option_refs, true).await?;
            let mut handle =
                EngineRunHandle::attach(child, self.engine.name(), spec.unit_id_file.clone()).await;
            // The unit id is both the cleanup target and the launch-time
            // proof the daemon applied the requested isolation — a launch
            // that cannot record one is refused rather than left
            // unverifiable.
            let Some(unit_id) = handle.unit_id() else {
                let _ = handle.terminate().await;
                let _ = handle.cleanup().await;
                return Err(BackendError::LaunchFailed(
                    "the launch recorded no unit id — the applied isolation \
                     cannot be verified"
                        .to_string(),
                ));
            };
            // `docker inspect` accepts a unit id too — the unit record's
            // HostConfig.Isolation is the isolation the daemon *applied*,
            // not merely the one the CLI asked for. A substitution (e.g.
            // process isolation on an engine that silently ignored the
            // flag) refuses here, before the workload is trusted.
            let verify = tokio::time::timeout(VERIFY_TIMEOUT, async {
                let mut cmd = tokio::process::Command::new(self.engine.name());
                cmd.args(["inspect", "--format", "{{.HostConfig.Isolation}}", &unit_id]);
                // A dropped future must kill the CLI — an interrupted
                // inspect cannot orphan.
                cmd.kill_on_drop(true);
                cmd.output().await
            })
            .await;
            let applied = match verify {
                Ok(Ok(out)) if out.status.success() => {
                    String::from_utf8_lossy(&out.stdout).into_owned()
                }
                Ok(Ok(out)) => {
                    let _ = handle.terminate().await;
                    let _ = handle.cleanup().await;
                    return Err(BackendError::LaunchFailed(format!(
                        "could not verify unit {unit_id}'s applied isolation — \
                         `docker inspect` failed: {}",
                        String::from_utf8_lossy(&out.stderr).trim()
                    )));
                }
                Ok(Err(e)) => {
                    let _ = handle.terminate().await;
                    let _ = handle.cleanup().await;
                    return Err(BackendError::LaunchFailed(format!(
                        "could not verify unit {unit_id}'s applied isolation — \
                         `docker inspect` failed: {e}"
                    )));
                }
                Err(_) => {
                    let _ = handle.terminate().await;
                    let _ = handle.cleanup().await;
                    return Err(BackendError::LaunchFailed(format!(
                        "could not verify unit {unit_id}'s applied isolation — \
                         `docker inspect` did not answer within {}s",
                        VERIFY_TIMEOUT.as_secs()
                    )));
                }
            };
            if let Err(e) = verify_recorded_isolation(&applied, &unit_id) {
                let _ = handle.terminate().await;
                let _ = handle.cleanup().await;
                return Err(e);
            }
            Ok(Box::new(handle) as Box<dyn IsolationHandle>)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::container::engine::EngineError;

    fn spec(image: &str) -> LaunchSpec {
        LaunchSpec {
            isolation: IsolationKind::HyperV,
            image: Some(image.to_string()),
            guest_os: TargetOs::Windows,
            guest_arch: TargetArch::X86_64,
            image_os_version: Some("10.0.26100.33438".to_string()),
            shares: Vec::new(),
            env: Vec::new(),
            unit_id_file: None,
        }
    }

    /// A canned docker engine for probe tests: a name plus the
    /// `docker info` JSON (or error) it returns. Every other engine
    /// method is unreachable — the probe must stay read-only.
    struct StubEngine {
        name: &'static str,
        info: Result<String, EngineError>,
    }

    impl StubEngine {
        fn docker(info_json: &str) -> Self {
            Self {
                name: "docker",
                info: Ok(info_json.to_string()),
            }
        }
        // Only the Windows-gated probe tests build a non-docker stub.
        #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
        fn named(name: &'static str) -> Self {
            Self {
                name,
                info: Ok(String::new()),
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
            unreachable!("the hyperv probe never builds")
        }
        fn inspect<'a>(&'a self, _i: &'a str) -> BoxFuture<'a, Result<String, EngineError>> {
            unreachable!("the hyperv probe never inspects")
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

    /// The `docker info` record of the validated host — each gated
    /// field injectable.
    fn windows_daemon_info(ostype: &str, os_version: &str, isolation: &str) -> String {
        format!(
            r#"{{"OSType":"{ostype}","OSVersion":"{os_version}","Isolation":"{isolation}","ServerVersion":"29.7.2","Driver":"windowsfilter"}}"#
        )
    }

    fn good_info() -> String {
        windows_daemon_info("windows", "10.0.26200", "hyperv")
    }

    async fn services_installed(name: &str) -> Option<String> {
        Some(format!("installed:{name}"))
    }

    // -- small parsers ---------------------------------------------------

    #[test]
    fn windows_build_triple_parses_and_rejects() {
        assert_eq!(
            windows_build_triple("10.0.26100.33438"),
            Some((10, 0, 26100))
        );
        assert_eq!(windows_build_triple("10.0.26200"), Some((10, 0, 26200)));
        assert_eq!(windows_build_triple("10.0"), None);
        assert_eq!(windows_build_triple("garbage"), None);
        assert_eq!(windows_build_triple(""), None);
        // The UBR/revision is the last tolerated component — a
        // non-numeric revision or a fifth component is not a Windows
        // version.
        assert_eq!(windows_build_triple("10.0.26100.x"), None);
        assert_eq!(windows_build_triple("10.0.26100.33438.7"), None);
    }

    #[test]
    fn sc_state_word_reads_the_state_row() {
        let text = "\nSERVICE_NAME: vmcompute\n        TYPE               : 10  WIN32_OWN_PROCESS  \n        STATE              : 4  RUNNING\n                                (STOPPABLE, NOT_PAUSABLE, IGNORES_SHUTDOWN)\n        WIN32_EXIT_CODE    : 0  (0x0)\n";
        assert_eq!(sc_state_word(text), Some("running"));
        // A localized label (German `STATUS`) still parses — the
        // numeric code is locale-independent.
        let localized = text.replace("STATE", "STATUS");
        assert_eq!(sc_state_word(&localized), Some("running"));
        // A stopped service is still installed.
        let stopped = text.replace(": 4  RUNNING", ": 1  STOPPED");
        assert_eq!(sc_state_word(&stopped), Some("stopped"));
        assert_eq!(sc_state_word("garbage"), None);
    }

    #[test]
    fn info_string_reads_top_level_members() {
        assert_eq!(
            info_string(&good_info(), "OSVersion").as_deref(),
            Some("10.0.26200")
        );
        assert_eq!(
            info_string(&good_info(), "Isolation").as_deref(),
            Some("hyperv")
        );
        assert_eq!(info_string(&good_info(), "Missing"), None);
        assert_eq!(info_string("not json", "OSType"), None);
    }

    // -- spec-shape refusals (run before any engine probe) --------------

    #[tokio::test]
    async fn check_rejects_foreign_isolation() {
        let backend = HypervBackend::new(Box::new(StubEngine::docker("")));
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
        let backend = HypervBackend::new(Box::new(StubEngine::docker("")));
        let mut spec = spec("img");
        spec.image = None;
        let err = backend.check(&spec).await.unwrap_err();
        assert!(matches!(err, BackendError::Unsupported(_)), "got: {err}");
    }

    #[tokio::test]
    async fn check_rejects_non_windows_guest() {
        let backend = HypervBackend::new(Box::new(StubEngine::docker("")));
        let mut spec = spec("img");
        spec.guest_os = TargetOs::Linux;
        let err = backend.check(&spec).await.unwrap_err();
        match err {
            BackendError::Unsupported(msg) => assert!(msg.contains("linux"), "got: {msg}"),
            other => panic!("expected Unsupported, got: {other}"),
        }
    }

    /// The validated image contract is windows/amd64 — a foreign arch
    /// refuses rather than launching into a certain exec failure.
    #[tokio::test]
    async fn check_rejects_foreign_arch() {
        let backend = HypervBackend::new(Box::new(StubEngine::docker("")));
        let mut spec = spec("img");
        spec.guest_arch = TargetArch::Aarch64;
        let err = backend.check(&spec).await.unwrap_err();
        match err {
            BackendError::Unsupported(msg) => assert!(msg.contains("aarch64"), "got: {msg}"),
            other => panic!("expected Unsupported, got: {other}"),
        }
    }

    // -- image build compat ----------------------------------------------

    #[test]
    fn image_version_gate_accepts_older_and_equal_guest_builds() {
        assert!(image_version_check(Some("10.0.26100.33438"), "10.0.26200").is_none());
        assert!(image_version_check(Some("10.0.26200.1"), "10.0.26200").is_none());
        assert!(image_version_check(Some("10.0.20348"), "10.0.26200").is_none());
    }

    #[test]
    fn image_version_gate_refuses_newer_and_undeterminable() {
        // Newer guest build on an older host — the documented refusal.
        let err = image_version_check(Some("10.0.26200.1"), "10.0.26100").unwrap();
        assert!(err.contains("newer"), "got: {err}");
        // Absent / unparseable versions are undeterminable — refuse.
        assert!(image_version_check(None, "10.0.26200").is_some());
        assert!(image_version_check(Some("garbage"), "10.0.26200").is_some());
        assert!(image_version_check(Some("10.0.26100"), "garbage").is_some());
    }

    // -- post-launch verification -----------------------------------------

    #[test]
    fn recorded_isolation_accepts_only_hyperv() {
        assert!(verify_recorded_isolation("hyperv", "u1").is_ok());
        assert!(verify_recorded_isolation("hyperv\n", "u1").is_ok());
        // Process isolation is the substitution the check exists for.
        let err = verify_recorded_isolation("process", "u1").unwrap_err();
        assert!(err.to_string().contains("process"), "got: {err}");
        let err = verify_recorded_isolation("", "u1").unwrap_err();
        assert!(err.to_string().contains("undeterminable"), "got: {err}");
    }

    // -- launch options ----------------------------------------------------

    #[test]
    fn run_options_prepend_isolation_and_user() {
        let spec = spec("img");
        let options = run_options(&spec);
        assert_eq!(
            &options[..4],
            ["--isolation", "hyperv", "--user", "ContainerAdministrator"],
            "the substrate selector and guest user precede the spec options: {options:?}"
        );
        // The shared options still render — entrypoint comes from the
        // windows layout.
        assert!(
            options
                .iter()
                .any(|a| a == "C:/mcp-secure/mcp-secure-runner.exe"),
            "the windows runner path must be the entrypoint: {options:?}"
        );
    }

    // -- prerequisite probe (stub engine; services injected) --------------

    /// On a non-Windows (or non-amd64) host every probe refuses at the
    /// host gates — deterministic regardless of driver state.
    #[cfg(not(all(target_os = "windows", target_arch = "x86_64")))]
    #[tokio::test]
    async fn probe_refuses_non_windows_host() {
        let stub = StubEngine::docker(&good_info());
        let err = probe_with(&stub, services_installed).await.unwrap_err();
        assert!(
            matches!(err.prereq, HypervPrereq::HostOs | HypervPrereq::HostArch),
            "got: {:?}",
            err.prereq
        );
    }

    /// Probe internals on Windows amd64 only — the host gates precede
    /// them, so these assertions cannot run elsewhere.
    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    mod windows_probe {
        use super::*;

        #[tokio::test]
        async fn probe_passes_on_the_validated_shape() {
            let stub = StubEngine::docker(&good_info());
            let p = probe_with(&stub, services_installed)
                .await
                .expect("probe passes");
            assert!(p.detail.contains("OSType=windows"), "got: {}", p.detail);
            assert!(p.detail.contains("vmcompute"), "got: {}", p.detail);
            assert_eq!(p.host_os_version, "10.0.26200");
        }

        #[tokio::test]
        async fn probe_refuses_a_non_docker_engine() {
            let stub = StubEngine::named("podman");
            let err = probe_with(&stub, services_installed).await.unwrap_err();
            assert!(matches!(err.prereq, HypervPrereq::Engine));
        }

        #[tokio::test]
        async fn probe_refuses_a_failed_info() {
            let mut stub = StubEngine::docker("");
            stub.info = Err(EngineError::CommandFailed {
                engine: "docker".to_string(),
                message: "daemon gone".to_string(),
            });
            let err = probe_with(&stub, services_installed).await.unwrap_err();
            assert!(matches!(err.prereq, HypervPrereq::EngineProbe));
        }

        #[tokio::test]
        async fn probe_refuses_a_linux_mode_daemon() {
            let stub = StubEngine::docker(&windows_daemon_info("linux", "", ""));
            let err = probe_with(&stub, services_installed).await.unwrap_err();
            assert!(matches!(err.prereq, HypervPrereq::EngineMode));
            assert!(
                err.detail.contains("Windows-containers"),
                "got: {}",
                err.detail
            );
        }

        #[tokio::test]
        async fn probe_refuses_an_unversioned_host() {
            let stub = StubEngine::docker(&windows_daemon_info("windows", "", "hyperv"));
            let err = probe_with(&stub, services_installed).await.unwrap_err();
            assert!(matches!(err.prereq, HypervPrereq::HostVersion));
        }

        #[tokio::test]
        async fn probe_refuses_a_missing_hyperv_service() {
            let stub = StubEngine::docker(&good_info());
            let err = probe_with(&stub, async |name| {
                if name == "vmcompute" {
                    None
                } else {
                    Some("installed".to_string())
                }
            })
            .await
            .unwrap_err();
            assert!(matches!(err.prereq, HypervPrereq::HypervStack));
            assert!(err.detail.contains("vmcompute"), "got: {}", err.detail);
        }

        /// A failed prerequisite refuses `check` outright — the same
        /// gates `probe_with` exercises — never confirming a weaker
        /// boundary. The non-docker engine fails before any `sc` call,
        /// so this is deterministic on every Windows/amd64 host.
        #[tokio::test]
        async fn check_probe_failure_refuses_without_fallback() {
            let backend = HypervBackend::new(Box::new(StubEngine::named("podman")));
            let err = backend.check(&spec("img")).await.unwrap_err();
            assert!(matches!(err, BackendError::Unsupported(_)), "got: {err}");
        }
    }
}
