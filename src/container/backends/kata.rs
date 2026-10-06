//! The Kata Containers backend — `IsolationKind::Kata` provided through
//! the engine's registered `kata` runtime.
//!
//! Scope is deliberately the single configuration PR-16 validated on
//! real hardware (`docs/validation/kata.md`): a **Linux host**, the
//! **docker** engine, a `kata` runtime registered with dockerd, and the
//! `/dev/kvm` + `/dev/vhost-vsock` device nodes present. `docker run
//! --runtime kata` gives one QEMU-backed VM per launch — the isolation
//! unit is the VM; the recorded unit id is the container id the shim's
//! `sandbox-<id>` VM is named after, so the shared
//! `EngineRunHandle`'s `--cidfile`/``rm -f`` teardown applies
//! unchanged.
//!
//! Nothing falls back to a plain container: a missing runtime
//! registration, a non-docker engine, a non-Linux host/guest, or absent
//! device nodes all refuse before launch — and this backend never
//! installs, registers, or mutates the daemon configuration itself.

use super::oci::EngineRunHandle;
use super::{
    BackendCapabilities, BackendError, IsolationBackend, IsolationCheck, IsolationHandle,
    LaunchSpec,
};
use crate::container::engine::{BoxFuture, ContainerEngine};
use crate::execution::{IsolationKind, IsolationUnit, TargetArch, TargetOs};

/// The dockerd-registered runtime name `docker run --runtime` selects —
/// the name the validated setup (`tests/fixtures/kata/setup-wsl2.sh`)
/// registers for `containerd-shim-kata-v2`.
pub(crate) const KATA_RUNTIME_NAME: &str = "kata";

/// The container engine the validated configuration runs through. The
/// runtime registration is a dockerd concept in this backend — podman /
/// containerd kata setups exist but are not inferred support
/// (docs/validation/kata.md: "Not verified").
const VALIDATED_ENGINE: &str = "docker";

/// Host device nodes the validated QEMU/KVM + vsock path needs. Stock
/// WSL2 lacks `/dev/vhost-vsock` (the validation host needed a locally
/// built module); absent nodes refuse the launch rather than surfacing
/// as an opaque shim failure.
const KATA_REQUIRED_DEVICES: &[&str] = &["/dev/kvm", "/dev/vhost-vsock"];

/// Bound on the `docker info` probe — a wedged daemon must not stall
/// `check`/`plan` indefinitely.
const INFO_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// The kata backend's declared capability set: a Linux host only (the
/// validated dockerd + KVM + vsock stack), the same Linux guest
/// contract as the OCI path (`mcp-secure-runner` is a Linux ELF), stdio
/// pipes, host path shares (virtiofs/9p into the VM), termination via
/// the engine CLI, and the engine-run unit-id record. The guest kernel
/// — and therefore the Landlock/seccomp ABIs the in-guest runner
/// applies — is pinned by the registered runtime's own configuration,
/// which the host cannot re-point per launch.
pub(crate) const KATA_CAPABILITIES: BackendCapabilities = BackendCapabilities {
    host_os: &[TargetOs::Linux],
    guest_os: &[TargetOs::Linux],
    oci_image: true,
    argv_command: false,
    stdio_pipes: true,
    terminate: true,
    host_shares: true,
    resource_limits: true,
    observations: &[
        "engine-info",
        "engine-runtime",
        "guest-report-mount",
        "unit-id-file",
    ],
};

/// `IsolationKind::Kata` over the engine's registered `kata` runtime.
pub struct KataBackend {
    engine: Box<dyn ContainerEngine>,
}

impl KataBackend {
    pub fn new(engine: Box<dyn ContainerEngine>) -> Self {
        Self { engine }
    }
}

/// Which validated-configuration prerequisite a kata probe failed on —
/// the stable tags `plan` maps to remediation text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KataPrereq {
    /// The CLI host OS is not Linux — the validated stack needs dockerd
    /// + KVM + vhost-vsock on a Linux host.
    HostOs,
    /// The resolved engine is not docker — only the dockerd `kata`
    /// runtime registration is the validated configuration.
    Engine,
    /// `docker info` failed or timed out — the daemon cannot be probed.
    EngineProbe,
    /// The engine's substrate OS is not linux (or undeterminable).
    SubstrateOs,
    /// No `kata` runtime is registered with the daemon.
    Runtime,
    /// A required host device node (`/dev/kvm`, `/dev/vhost-vsock`) is
    /// absent.
    DeviceNode,
}

/// A refused kata prerequisite: which check failed plus the human
/// detail `check`/`plan` surface.
#[derive(Debug)]
pub(crate) struct KataPrereqFailure {
    pub prereq: KataPrereq,
    pub detail: String,
}

impl KataPrereqFailure {
    fn new(prereq: KataPrereq, detail: String) -> Self {
        Self { prereq, detail }
    }

    /// Map to the launch-refusal error: a failed daemon probe is a
    /// launch-path failure; an absent prerequisite is an unsuitable
    /// environment, which refuses as `Unsupported` (never a fallback).
    fn into_backend_error(self) -> BackendError {
        match self.prereq {
            KataPrereq::EngineProbe => BackendError::LaunchFailed(self.detail),
            _ => BackendError::Unsupported(self.detail),
        }
    }
}

/// Remediation text for a refused prerequisite — the host-side fix,
/// which `plan` reports. mcp-writ never repairs the host itself.
pub(crate) fn prereq_remediation(prereq: KataPrereq) -> String {
    match prereq {
        KataPrereq::HostOs => "kata isolation needs a Linux host — run from the Linux host or \
             WSL2 distro that hosts dockerd"
            .to_string(),
        KataPrereq::Engine => "pass --engine docker — only the dockerd `kata` runtime is the \
             validated configuration (podman/containerd kata is unverified)"
            .to_string(),
        KataPrereq::EngineProbe => {
            "start or repair the docker daemon so `docker info` answers".to_string()
        }
        KataPrereq::SubstrateOs => {
            "point docker at a Linux daemon — the kata guest VM is Linux".to_string()
        }
        KataPrereq::Runtime => "install Kata Containers and register the `kata` runtime with \
             dockerd, then restart the daemon — see docs/validation/kata.md \
             and tests/fixtures/kata/setup-wsl2.sh"
            .to_string(),
        KataPrereq::DeviceNode => "enable KVM and load vhost_vsock so /dev/kvm and \
             /dev/vhost-vsock exist on this host"
            .to_string(),
    }
}

/// Read the `kata` entry of `docker info`'s `.Runtimes` map — `Some` of
/// the reported `runtimeType`/`path` detail when registered, `None`
/// when absent or the JSON is unparseable. `runtimeType` is the
/// containerd-shim identifier (e.g. the `containerd-shim-kata-v2` path)
/// for shim-registered runtimes; `path` is the OCI runtime binary for
/// runc-style entries — record whichever the daemon reports.
fn kata_runtime_detail(info_json: &str) -> Option<String> {
    let json = nojson::RawJson::parse(info_json).ok()?;
    let runtimes = json.value().to_member("Runtimes").ok()?.optional()?;
    let entry = runtimes.to_member(KATA_RUNTIME_NAME).ok()?.optional()?;
    for field in ["runtimeType", "path"] {
        if let Some(v) = entry
            .to_member(field)
            .ok()
            .and_then(|m| m.optional())
            .and_then(|v| v.to_unquoted_string_str().ok())
        {
            return Some(format!(" ({field}: {v})"));
        }
    }
    Some(String::new())
}

/// First required device node `exists` reports absent — `None` when all
/// are present. The predicate is injected so tests exercise the check
/// on hosts that lack the nodes.
fn missing_required_device(exists: impl Fn(&str) -> bool) -> Option<&'static str> {
    KATA_REQUIRED_DEVICES.iter().copied().find(|d| !exists(d))
}

/// Probe the validated-configuration prerequisites shared by `check`
/// and `plan`'s `kata.runtime` diagnostic. Read-only: `docker info`
/// plus a stat on each device node — nothing is installed, registered,
/// or reconfigured.
///
/// `run-image` and `plan` already probe `engine.info()` once for the
/// substrate-OS record; the repeat here is deliberate — the backend's
/// evidence is its own bounded read, not data threaded through a
/// caller whose contract hands over only the spec. Both calls share
/// the [`INFO_TIMEOUT`] bound.
///
/// On success returns the launch-record detail string (engine +
/// runtime registration). Failure names the refused prerequisite; a
/// launch never proceeds on an unverified kata stack, and never
/// degrades to `runc`.
pub(crate) async fn probe(engine: &dyn ContainerEngine) -> Result<String, KataPrereqFailure> {
    probe_with(engine, |p| std::path::Path::new(p).exists()).await
}

async fn probe_with(
    engine: &dyn ContainerEngine,
    device_exists: impl Fn(&str) -> bool,
) -> Result<String, KataPrereqFailure> {
    let fail = KataPrereqFailure::new;

    if TargetOs::host() != TargetOs::Linux {
        return Err(fail(
            KataPrereq::HostOs,
            format!(
                "kata isolation needs a Linux host — the validated stack is \
                 dockerd + KVM + vhost-vsock; this host is '{}'",
                TargetOs::host().name()
            ),
        ));
    }
    if engine.name() != VALIDATED_ENGINE {
        return Err(fail(
            KataPrereq::Engine,
            format!(
                "the kata backend drives the '{KATA_RUNTIME_NAME}' runtime \
                 registered with dockerd — engine '{}' is not the validated \
                 configuration",
                engine.name()
            ),
        ));
    }
    let info = match tokio::time::timeout(INFO_TIMEOUT, engine.info()).await {
        Ok(Ok(info)) => info,
        Ok(Err(e)) => {
            return Err(fail(
                KataPrereq::EngineProbe,
                format!("docker info failed: {e}"),
            ));
        }
        Err(_) => {
            return Err(fail(
                KataPrereq::EngineProbe,
                format!(
                    "docker info did not answer within {}s",
                    INFO_TIMEOUT.as_secs()
                ),
            ));
        }
    };
    match crate::container::engine::engine_info_os("docker", &info) {
        Some(TargetOs::Linux) => {}
        Some(other) => {
            return Err(fail(
                KataPrereq::SubstrateOs,
                format!(
                    "the kata runtime runs a Linux guest VM — the engine's \
                     substrate OS is '{}'",
                    other.name()
                ),
            ));
        }
        None => {
            return Err(fail(
                KataPrereq::SubstrateOs,
                "the engine's substrate OS could not be determined from \
                 docker info"
                    .to_string(),
            ));
        }
    }
    let runtime_detail = kata_runtime_detail(&info).ok_or_else(|| {
        fail(
            KataPrereq::Runtime,
            format!(
                "no '{KATA_RUNTIME_NAME}' runtime is registered with this \
                 dockerd (docker info .Runtimes lacks it) — a plain runc \
                 container is never a substitute"
            ),
        )
    })?;
    if let Some(dev) = missing_required_device(&device_exists) {
        return Err(fail(
            KataPrereq::DeviceNode,
            format!(
                "{dev} is missing — the validated Kata QEMU/KVM + \
                 vhost-vsock path needs {} on this host",
                KATA_REQUIRED_DEVICES.join(" and ")
            ),
        ));
    }
    // The guest kernel image is whichever vmlinux the registered runtime's
    // configuration names — pinned by the kata installation, identical for
    // every launch, not selectable per workload.
    Ok(format!(
        "engine: docker; runtime: {KATA_RUNTIME_NAME}{runtime_detail}; \
         guest kernel: pinned by the kata installation"
    ))
}

/// `<engine> run` options for a kata launch: the validated runtime
/// selection first (`--runtime kata` is what separates the VM boundary
/// from a namespace container — omitting it would silently run `runc`),
/// then the same spec options the OCI path renders.
pub(crate) fn run_options(spec: &LaunchSpec) -> Vec<String> {
    let mut options = vec!["--runtime".to_string(), KATA_RUNTIME_NAME.to_string()];
    options.extend(super::oci::spec_run_options(spec));
    options
}

impl IsolationBackend for KataBackend {
    fn kind(&self) -> IsolationKind {
        IsolationKind::Kata
    }

    fn capabilities(&self) -> BackendCapabilities {
        KATA_CAPABILITIES
    }

    fn check<'a>(
        &'a self,
        spec: &'a LaunchSpec,
    ) -> BoxFuture<'a, Result<IsolationCheck, BackendError>> {
        Box::pin(async move {
            // The backend confirms exactly the isolation it implements —
            // a spec for another method refuses rather than degrading.
            if spec.isolation != IsolationKind::Kata {
                return Err(BackendError::Unsupported(format!(
                    "the kata backend cannot provide '{}' isolation",
                    spec.isolation.name()
                )));
            }
            if spec.image.is_none() || spec.command.is_some() {
                return Err(BackendError::Unsupported(
                    "the kata backend requires an image-defined workload".to_string(),
                ));
            }
            if spec.guest_os != TargetOs::Linux {
                return Err(BackendError::Unsupported(format!(
                    "the kata launch contract carries the same Linux guest \
                     entrypoint (/usr/local/bin/mcp-secure-runner) as the \
                     container path; a {} guest needs its own backend",
                    spec.guest_os.name()
                )));
            }
            // Unlike the OCI substrate — which may negotiate a foreign
            // arch via binfmt/qemu-user — the kata VM's guest kernel is
            // fixed to the host arch by the installation, so a mismatched
            // image arch is a certain failure: refuse rather than launch
            // a VM that cannot exec the workload.
            if spec.guest_arch != TargetArch::host() {
                return Err(BackendError::Unsupported(format!(
                    "the kata VM boots a {} guest kernel — image architecture \
                     '{}' cannot run on this host",
                    TargetArch::host().name(),
                    spec.guest_arch.name()
                )));
            }
            let detail = probe(&*self.engine)
                .await
                .map_err(KataPrereqFailure::into_backend_error)?;
            Ok(IsolationCheck {
                verified: IsolationKind::Kata,
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
                    "the kata backend requires an image-defined workload".to_string(),
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
    use crate::container::engine::EngineError;

    fn spec(image: &str) -> LaunchSpec {
        LaunchSpec {
            isolation: IsolationKind::Kata,
            image: Some(image.to_string()),
            command: None,
            guest_os: TargetOs::Linux,
            guest_arch: TargetArch::host(),
            image_os_version: None,
            shares: Vec::new(),
            env: Vec::new(),
            unit_id_file: None,
        }
    }

    /// A canned engine for probe tests: a name plus the `docker info`
    /// JSON (or error) it returns. Every other engine method is
    /// unreachable — the probe must stay read-only.
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
            _n: bool,
        ) -> BoxFuture<'a, Result<(), EngineError>> {
            unreachable!("the kata probe never builds")
        }
        fn inspect<'a>(&'a self, _i: &'a str) -> BoxFuture<'a, Result<String, EngineError>> {
            unreachable!("the kata probe never inspects")
        }
        fn tag<'a>(&'a self, _s: &'a str, _t: &'a str) -> BoxFuture<'a, Result<(), EngineError>> {
            unreachable!("the kata probe never tags")
        }
        fn remove_image<'a>(&'a self, _i: &'a str) -> BoxFuture<'a, Result<(), EngineError>> {
            unreachable!("the kata probe never removes images")
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

    /// `docker info` shape with a `Runtimes` map — `Some(entry)` inserts
    /// a `kata` runtime record verbatim.
    fn docker_info(kata_entry: Option<&str>) -> String {
        let kata = kata_entry
            .map(|e| format!(", \"{KATA_RUNTIME_NAME}\": {e}"))
            .unwrap_or_default();
        format!("{{\"OSType\":\"linux\",\"Runtimes\":{{\"runc\":{{\"path\":\"runc\"}}{kata}}}}}")
    }

    // -- docker info runtime parsing -----------------------------------

    #[test]
    fn runtime_detail_reads_shim_type() {
        let info = docker_info(Some("{\"runtimeType\":\"io.containerd.kata.v2\"}"));
        assert_eq!(
            kata_runtime_detail(&info).as_deref(),
            Some(" (runtimeType: io.containerd.kata.v2)")
        );
    }

    #[test]
    fn runtime_detail_reads_path() {
        let info = docker_info(Some("{\"path\":\"/opt/kata/bin/containerd-shim-kata-v2\"}"));
        assert_eq!(
            kata_runtime_detail(&info).as_deref(),
            Some(" (path: /opt/kata/bin/containerd-shim-kata-v2)")
        );
    }

    #[test]
    fn runtime_detail_absent_and_malformed() {
        assert!(kata_runtime_detail(&docker_info(None)).is_none());
        assert!(kata_runtime_detail("not json").is_none());
        // A registered runtime with no reported detail still counts —
        // the name being present is the registration evidence.
        assert_eq!(
            kata_runtime_detail(&docker_info(Some("{}"))),
            Some(String::new())
        );
    }

    #[test]
    fn missing_device_reports_each_absent_node() {
        assert!(missing_required_device(|_| true).is_none());
        assert_eq!(
            missing_required_device(|d| d != "/dev/kvm"),
            Some("/dev/kvm")
        );
        assert_eq!(
            missing_required_device(|d| d != "/dev/vhost-vsock"),
            Some("/dev/vhost-vsock")
        );
    }

    // -- spec-shape refusals (run before any engine probe) --------------

    #[tokio::test]
    async fn check_rejects_foreign_isolation() {
        let backend = KataBackend::new(Box::new(StubEngine::docker("")));
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
        let backend = KataBackend::new(Box::new(StubEngine::docker("")));
        let mut spec = spec("img");
        spec.image = None;
        let err = backend.check(&spec).await.unwrap_err();
        assert!(matches!(err, BackendError::Unsupported(_)), "got: {err}");
    }

    #[tokio::test]
    async fn check_rejects_non_linux_guest() {
        let backend = KataBackend::new(Box::new(StubEngine::docker("")));
        let mut spec = spec("img");
        spec.guest_os = TargetOs::Windows;
        let err = backend.check(&spec).await.unwrap_err();
        match err {
            BackendError::Unsupported(msg) => assert!(msg.contains("windows"), "got: {msg}"),
            other => panic!("expected Unsupported, got: {other}"),
        }
    }

    /// The VM's guest kernel is host-arch — a foreign-arch image is
    /// refused rather than launched into certain exec failure.
    #[tokio::test]
    async fn check_rejects_foreign_arch() {
        let backend = KataBackend::new(Box::new(StubEngine::docker("")));
        let mut spec = spec("img");
        spec.guest_arch = match TargetArch::host() {
            TargetArch::X86_64 => TargetArch::Aarch64,
            _ => TargetArch::X86_64,
        };
        let err = backend.check(&spec).await.unwrap_err();
        match err {
            BackendError::Unsupported(msg) => {
                assert!(msg.contains("architecture"), "got: {msg}")
            }
            other => panic!("expected Unsupported, got: {other}"),
        }
    }

    // -- prerequisite probe (stub engine; devices injected) -------------

    /// On a non-Linux host every probe refuses at the host-OS gate —
    /// deterministic regardless of engine state.
    #[cfg(not(target_os = "linux"))]
    #[tokio::test]
    async fn probe_refuses_non_linux_host() {
        let stub = StubEngine::docker(&docker_info(Some(
            "{\"runtimeType\":\"io.containerd.kata.v2\"}",
        )));
        let err = probe(&stub).await.unwrap_err();
        assert_eq!(err.prereq, KataPrereq::HostOs);
        // The refusal names the actual host OS — capitalized "Linux" in
        // the detail is not a lowercase "linux" hit.
        assert!(
            err.detail.contains(TargetOs::host().name()),
            "got: {}",
            err.detail
        );
    }

    /// Probe internals on Linux only — the host-OS gate precedes them,
    /// so these assertions cannot run elsewhere.
    #[cfg(target_os = "linux")]
    mod linux_probe {
        use super::*;

        const KATA_SHIM: &str =
            "{\"runtimeType\":\"/opt/kata/runtime-rs/bin/containerd-shim-kata-v2\"}";

        #[tokio::test]
        async fn probe_passes_on_the_validated_shape() {
            let stub = StubEngine::docker(&docker_info(Some(KATA_SHIM)));
            let detail = probe_with(&stub, |_| true).await.expect("probe passes");
            assert!(detail.contains("engine: docker"), "got: {detail}");
            assert!(detail.contains("runtime: kata"), "got: {detail}");
            assert!(detail.contains("containerd-shim-kata-v2"), "got: {detail}");
        }

        #[tokio::test]
        async fn probe_refuses_non_docker_engine() {
            let stub = StubEngine {
                name: "podman",
                info: Ok("{}".to_string()),
            };
            let err = probe_with(&stub, |_| true).await.unwrap_err();
            assert_eq!(err.prereq, KataPrereq::Engine);
            assert!(err.detail.contains("podman"), "got: {}", err.detail);
        }

        #[tokio::test]
        async fn probe_refuses_unprobeable_daemon() {
            let stub = StubEngine {
                name: "docker",
                info: Err(EngineError::CommandFailed {
                    engine: "docker".to_string(),
                    message: "daemon down".to_string(),
                }),
            };
            let err = probe_with(&stub, |_| true).await.unwrap_err();
            assert_eq!(err.prereq, KataPrereq::EngineProbe);
            // A daemon that cannot be probed is a launch-path failure,
            // not an unsuitable-environment refusal.
            assert!(matches!(
                err.into_backend_error(),
                BackendError::LaunchFailed(_)
            ));
        }

        #[tokio::test]
        async fn probe_refuses_non_linux_substrate() {
            let stub = StubEngine::docker(
                "{\"OSType\":\"windows\",\"Runtimes\":{\"kata\":{\"runtimeType\":\"x\"}}}",
            );
            let err = probe_with(&stub, |_| true).await.unwrap_err();
            assert_eq!(err.prereq, KataPrereq::SubstrateOs);
            assert!(err.detail.contains("windows"), "got: {}", err.detail);
        }

        /// The fail-closed core: no `kata` runtime registered means the
        /// launch refuses — never silently runc.
        #[tokio::test]
        async fn probe_refuses_unregistered_runtime() {
            let stub = StubEngine::docker(&docker_info(None));
            let err = probe_with(&stub, |_| true).await.unwrap_err();
            assert_eq!(err.prereq, KataPrereq::Runtime);
            assert!(err.detail.contains("kata"), "got: {}", err.detail);
            // A missing prerequisite is an unsuitable-environment
            // refusal (Unsupported), not a launch failure.
            assert!(matches!(
                err.into_backend_error(),
                BackendError::Unsupported(_)
            ));
        }

        #[tokio::test]
        async fn probe_refuses_missing_device_node() {
            let stub = StubEngine::docker(&docker_info(Some(KATA_SHIM)));
            let err = probe_with(&stub, |p| p != "/dev/vhost-vsock")
                .await
                .unwrap_err();
            assert_eq!(err.prereq, KataPrereq::DeviceNode);
            assert!(
                err.detail.contains("/dev/vhost-vsock"),
                "got: {}",
                err.detail
            );
        }
    }

    // -- run options ----------------------------------------------------

    #[test]
    fn run_options_select_kata_runtime_first() {
        let mut spec = spec("img");
        spec.shares.push(super::super::ShareMount {
            host: std::path::PathBuf::from("/tmp/policy.kdl"),
            guest: "/etc/mcp-secure/policy.kdl".to_string(),
            writable: false,
        });
        let options = run_options(&spec);
        assert_eq!(options[..2], ["--runtime", "kata"]);
        assert!(
            options
                .iter()
                .any(|a| a.contains("policy.kdl:ro") || a.ends_with(":ro"))
        );
    }

    #[test]
    fn kata_capabilities_declared() {
        let caps = KataBackend::new(Box::new(StubEngine::docker(""))).capabilities();
        assert!(caps.oci_image && !caps.argv_command);
        assert!(caps.stdio_pipes && caps.terminate && caps.host_shares);
        assert_eq!(caps.host_os, &[TargetOs::Linux]);
        assert_eq!(caps.guest_os, &[TargetOs::Linux]);
        assert_eq!(IsolationKind::Kata.unit(), IsolationUnit::Vm);
    }
}
