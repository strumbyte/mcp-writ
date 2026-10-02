//! The OCI container backend — the existing `run -i --rm` launch
//! expressed through the isolation contract.
//!
//! The container engine keeps owning image build/inspect; this adapter
//! translates a typed [`LaunchSpec`] into `<engine> run` arguments and
//! exposes the spawned CLI child as an [`IsolationHandle`]. The unit it
//! isolates is one container per launch; the substrate-assigned id is
//! recorded through the `--cidfile` the spec carries.

use std::path::PathBuf;

use super::{
    BackendCapabilities, BackendError, IsolationBackend, IsolationCheck, IsolationHandle,
    LaunchSpec, SessionStdio,
};
use crate::container::engine::{BoxFuture, ContainerEngine};
use crate::execution::{IsolationKind, IsolationUnit, TargetOs};

/// The OCI backend's declared capability set: engine-driven `run` on
/// any host OS the engine supports, a Linux guest contract (the
/// embedded `mcp-secure-runner` is a Linux ELF), stdio pipes, host path
/// shares for the policy/log/report channels, termination via the
/// engine CLI, and a unit id recorded through `--cidfile`.
pub(crate) const OCI_CAPABILITIES: BackendCapabilities = BackendCapabilities {
    host_os: &[TargetOs::Linux, TargetOs::MacOs, TargetOs::Windows],
    guest_os: &[TargetOs::Linux],
    oci_image: true,
    argv_command: false,
    stdio_pipes: true,
    terminate: true,
    host_shares: true,
    resource_limits: true,
    observations: &["engine-info", "guest-report-mount", "unit-id-file"],
};

/// `IsolationKind::Container` over a resolved container engine.
pub struct OciBackend {
    engine: Box<dyn ContainerEngine>,
}

impl OciBackend {
    pub fn new(engine: Box<dyn ContainerEngine>) -> Self {
        Self { engine }
    }
}

impl IsolationBackend for OciBackend {
    fn kind(&self) -> IsolationKind {
        IsolationKind::Container
    }

    fn capabilities(&self) -> BackendCapabilities {
        OCI_CAPABILITIES
    }

    fn check<'a>(
        &'a self,
        spec: &'a LaunchSpec,
    ) -> BoxFuture<'a, Result<IsolationCheck, BackendError>> {
        Box::pin(async move {
            // The backend confirms exactly the isolation it implements.
            // A spec for another method — or a combination the OCI runner
            // contract cannot express — refuses rather than degrading.
            if spec.isolation != IsolationKind::Container {
                return Err(BackendError::Unsupported(format!(
                    "the OCI backend cannot provide '{}' isolation",
                    spec.isolation.name()
                )));
            }
            if spec.image.is_none() {
                return Err(BackendError::Unsupported(
                    "the OCI backend requires an image-defined workload".to_string(),
                ));
            }
            if spec.guest_os != TargetOs::Linux {
                return Err(BackendError::Unsupported(format!(
                    "the OCI launch contract carries a Linux guest entrypoint \
                     (/usr/local/bin/mcp-secure-runner); a {} guest needs its own \
                     backend",
                    spec.guest_os.name()
                )));
            }
            Ok(IsolationCheck {
                verified: IsolationKind::Container,
                unit: IsolationUnit::Container,
                detail: Some(format!("engine: {}", self.engine.name())),
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
                    "the OCI backend requires an image-defined workload".to_string(),
                )
            })?;
            let options = spec_run_options(spec);
            let option_refs: Vec<&str> = options.iter().map(String::as_str).collect();
            let child = self.engine.run(image, &option_refs, true).await?;
            Ok(Box::new(
                EngineRunHandle::attach(child, self.engine.name(), spec.unit_id_file.clone()).await,
            ) as Box<dyn IsolationHandle>)
        })
    }
}

/// Render the typed launch spec into `<engine> run` option arguments:
/// one share becomes `-v host:guest[:ro]`, one env pair `-e K=V`, and
/// `unit_id_file` becomes `--cidfile`. The hardened prefix and the
/// trailing image are assembled by
/// [`crate::container::engine::container_run_args`].
///
/// The `--entrypoint` override is part of the spec render, not the
/// prefix: the runner path is the guest contract's
/// ([`crate::container::guest_layout`]) — `/usr/local/bin/…` on Linux,
/// `C:/mcp-secure/…` on Windows — never a literal the launch could
/// point at the wrong guest. A guest OS without a contract renders no
/// override (the backend's `check` already refused it).
/// Render a share's host path for `-v`. The runner canonicalizes share
/// sources, which on Windows yields verbatim `\\?\C:\…` spellings — the
/// engine's volume parser refuses those (`invalid volume
/// specification`), so the mountable form strips the verbatim prefix
/// (`\\?\C:\…` → `C:\…`, `\\?\UNC\s\…` → `\\s\…`). Non-verbatim paths —
/// and every path on non-Windows hosts — pass through unchanged.
fn host_share_path(host: &std::path::Path) -> String {
    let s = host.to_string_lossy();
    if let Some(rest) = s.strip_prefix(r"\\?\UNC\") {
        format!(r"\\{rest}")
    } else if let Some(rest) = s.strip_prefix(r"\\?\") {
        rest.to_string()
    } else {
        s.into_owned()
    }
}

pub(crate) fn spec_run_options(spec: &LaunchSpec) -> Vec<String> {
    let mut options = Vec::new();
    if let Some(layout) = crate::container::guest_layout::for_guest_os(spec.guest_os) {
        options.push("--entrypoint".to_string());
        options.push(layout.runner_path.to_string());
    }
    for share in &spec.shares {
        options.push("-v".to_string());
        let mut mount = format!("{}:{}", host_share_path(&share.host), share.guest);
        if !share.writable {
            mount.push_str(":ro");
        }
        options.push(mount);
    }
    for (key, value) in &spec.env {
        options.push("-e".to_string());
        options.push(format!("{key}={value}"));
    }
    // Record the container id so an interrupted run can still remove
    // the container (`--rm` alone only cleans up on a normal exit).
    if let Some(path) = &spec.unit_id_file {
        options.push("--cidfile".to_string());
        options.push(path.display().to_string());
    }
    options
}

/// Bound on `<engine> rm -f` teardown — the async `cleanup` wait and
/// the last-resort `Drop` give the engine CLI at most this long; a
/// wedged CLI must not stall session teardown or pin the dropping
/// thread.
const RM_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// The launch handle for an engine-driven unit — owns the engine CLI
/// child, the `--cidfile` path, and rm-by-id cleanup. Shared by the
/// backends that drive `<engine> run`: the OCI container path and the
/// kata VM path (`docker run --runtime kata` — the shim names its
/// `sandbox-<id>` VM after the container id the same `--cidfile`
/// records, and `rm -f <id>` tears the VM down identically).
pub(crate) struct EngineRunHandle {
    child: tokio::process::Child,
    engine_name: String,
    cid_path: Option<PathBuf>,
    unit_id: Option<String>,
    cleaned: bool,
}

impl EngineRunHandle {
    /// Wrap a spawned `<engine> run` child and wait briefly for the
    /// substrate to record the unit id — the `--cidfile` appears when
    /// the unit is created, which races the spawn return. A substrate
    /// that never writes one leaves `unit_id` empty rather than
    /// stalling the launch.
    pub(crate) async fn attach(
        child: tokio::process::Child,
        engine_name: &str,
        cid_path: Option<PathBuf>,
    ) -> Self {
        let mut handle = Self {
            child,
            engine_name: engine_name.to_string(),
            cid_path,
            unit_id: None,
            cleaned: false,
        };
        handle.wait_for_unit_id().await;
        handle
    }

    /// Bounded poll for the substrate-written unit id — the `--cidfile`
    /// appears when the container is created, which races the spawn
    /// return. A substrate that never writes one yields `None`.
    async fn wait_for_unit_id(&mut self) {
        let Some(path) = &self.cid_path else {
            return;
        };
        for _ in 0..40 {
            if let Ok(id) = std::fs::read_to_string(path) {
                let id = id.trim().to_string();
                if !id.is_empty() {
                    self.unit_id = Some(id);
                    return;
                }
            }
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }
    }

    /// The recorded unit id, or a fresh read of the id file — used by
    /// cleanup for units whose id only landed after launch returned.
    fn recorded_unit_id(&self) -> Option<String> {
        self.unit_id.clone().or_else(|| {
            self.cid_path.as_ref().and_then(|p| {
                std::fs::read_to_string(p)
                    .ok()
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
            })
        })
    }
}

impl IsolationHandle for EngineRunHandle {
    fn unit_id(&self) -> Option<String> {
        // Read through to the id file — a `--cidfile` that landed after
        // launch's bounded poll still reports the real unit id.
        self.recorded_unit_id()
    }

    fn take_stdio(&mut self) -> Result<SessionStdio, BackendError> {
        let stdin =
            self.child.stdin.take().ok_or_else(|| {
                BackendError::LaunchFailed("container stdin was not captured".into())
            })?;
        let stdout = self.child.stdout.take().ok_or_else(|| {
            BackendError::LaunchFailed("container stdout was not captured".into())
        })?;
        Ok(SessionStdio {
            stdin: Box::new(stdin),
            stdout: Box::new(stdout),
        })
    }

    fn wait_exit(&mut self) -> BoxFuture<'_, Result<i32, BackendError>> {
        Box::pin(async move {
            let status = self.child.wait().await.map_err(|e| {
                BackendError::LaunchFailed(format!("failed to wait for container: {e}"))
            })?;
            Ok(status.code().unwrap_or(1))
        })
    }

    fn terminate(&mut self) -> BoxFuture<'_, Result<(), BackendError>> {
        Box::pin(async move {
            // Killing the engine CLI leaves the container itself running
            // under the daemon — `cleanup` removes it by the recorded id.
            match self.child.kill().await {
                // An already-exited child is not a terminate failure.
                Err(e) if e.kind() == std::io::ErrorKind::InvalidInput => Ok(()),
                other => other.map_err(BackendError::Io),
            }
        })
    }

    fn cleanup(&mut self) -> BoxFuture<'_, Result<(), BackendError>> {
        Box::pin(async move {
            if self.cleaned {
                return Ok(());
            }
            // Terminate the engine CLI first — a launch that failed
            // before a unit id was recorded still leaves the CLI child
            // running. Idempotent when `terminate` already killed it.
            let _ = self.child.start_kill();
            if let Some(id) = self.recorded_unit_id() {
                // Bound the wait on the engine CLI — a timed-out `rm`
                // keeps running detached, so the unit is still released.
                let rm = tokio::process::Command::new(&self.engine_name)
                    .args(["rm", "-f", &id])
                    .output();
                let _ = tokio::time::timeout(RM_TIMEOUT, rm).await;
            }
            // Set only after the attempt: a `cleanup` future cancelled
            // mid-await must let `Drop` retry the removal.
            self.cleaned = true;
            Ok(())
        })
    }
}

/// A dropped live handle still releases the unit — a session future
/// cancelled mid-flight must not leave a container running. Blocking
/// teardown is acceptable here: it is the last resort path, not the
/// normal `cleanup` the driver runs. The wait is bounded by
/// [`RM_TIMEOUT`] so a wedged engine CLI cannot pin the dropping thread.
impl Drop for EngineRunHandle {
    fn drop(&mut self) {
        if self.cleaned {
            return;
        }
        self.cleaned = true;
        let _ = self.child.start_kill();
        if let Some(id) = self.recorded_unit_id() {
            let Ok(mut rm) = std::process::Command::new(&self.engine_name)
                .args(["rm", "-f", &id])
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()
            else {
                return;
            };
            let deadline = std::time::Instant::now() + RM_TIMEOUT;
            loop {
                match rm.try_wait() {
                    Ok(Some(_)) | Err(_) => break,
                    Ok(None) if std::time::Instant::now() >= deadline => {
                        let _ = rm.kill();
                        let _ = rm.wait();
                        break;
                    }
                    Ok(None) => std::thread::sleep(std::time::Duration::from_millis(25)),
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::container::backends::ShareMount;
    use crate::container::engine::{BuildahEngine, container_run_args};
    use crate::execution::{TargetArch, TargetOs};

    fn spec(image: &str) -> LaunchSpec {
        LaunchSpec {
            isolation: IsolationKind::Container,
            image: Some(image.to_string()),
            guest_os: TargetOs::Linux,
            guest_arch: TargetArch::X86_64,
            image_os_version: None,
            shares: Vec::new(),
            env: Vec::new(),
            unit_id_file: None,
        }
    }

    fn oci() -> OciBackend {
        // `check` never spawns the engine CLI — the buildah unit is a
        // convenient stand-in engine.
        OciBackend::new(Box::new(BuildahEngine))
    }

    // -- typed launch conditions → arguments ----------------------------

    fn production_run_args(
        image: &str,
        policy_abs: &std::path::Path,
        log_dir_abs: Option<&std::path::Path>,
    ) -> Vec<String> {
        let mut spec = spec(image);
        spec.shares.push(ShareMount {
            host: policy_abs.to_path_buf(),
            guest: "/etc/mcp-secure/policy.kdl".to_string(),
            writable: false,
        });
        if let Some(dir) = log_dir_abs {
            spec.shares.push(ShareMount {
                host: dir.to_path_buf(),
                guest: "/var/log/mcp-secure".to_string(),
                writable: true,
            });
        }
        let options = spec_run_options(&spec);
        container_run_args(&options, image)
    }

    fn hardening_prefix() -> Vec<&'static str> {
        vec![
            "run",
            "-i",
            "--rm",
            "--no-healthcheck",
            "-e",
            "MCP_WRIT_ENV=",
            "-e",
            "MCP_WRIT_SKIP_SANDBOX=",
            "-e",
            "MCP_WRIT_SERVER=",
            "-e",
            "MCP_WRIT_FAIL_ON=",
            "-e",
            "MCP_WRIT_LAUNCH_ID=",
            "-e",
            "MCP_WRIT_REPORT_OUT=",
            "-e",
            "MCP_WRIT_PROBE_LANDLOCK_ABI=",
            "-e",
            "MCP_WRIT_POLICY_PATH=",
            "-e",
            "MCP_WRIT_AUDIT_DIR=",
            "-e",
            "MCP_WRIT_TEMP_DIR=",
        ]
    }

    /// A canonicalized verbatim `\\?\C:\…` host path must render for
    /// `-v` without the prefix — the engine's volume parser refuses the
    /// verbatim spelling (`invalid volume specification`). Plain and
    /// non-Windows paths pass through unchanged.
    #[test]
    fn share_host_path_strips_the_verbatim_prefix() {
        assert_eq!(
            host_share_path(std::path::Path::new(r"\\?\C:\pol\policydir")),
            r"C:\pol\policydir"
        );
        assert_eq!(
            host_share_path(std::path::Path::new(r"\\?\UNC\srv\share\dir")),
            r"\\srv\share\dir"
        );
        assert_eq!(
            host_share_path(std::path::Path::new(r"C:\pol\policydir")),
            r"C:\pol\policydir"
        );
        assert_eq!(
            host_share_path(std::path::Path::new("/tmp/policy")),
            "/tmp/policy"
        );
    }

    /// The spec-rendered `--entrypoint` pair — the guest contract's
    /// runner path for the spec's Linux guest.
    fn entrypoint_option() -> Vec<String> {
        vec![
            "--entrypoint".to_string(),
            crate::container::guest_layout::LINUX
                .runner_path
                .to_string(),
        ]
    }

    #[test]
    fn spec_args_basic() {
        let spec_args = {
            let mut spec = spec("my-image:latest");
            spec.shares.push(ShareMount {
                host: PathBuf::from("/tmp/policy.kdl"),
                guest: "/etc/mcp-secure/policy.kdl".to_string(),
                writable: false,
            });
            spec
        };
        let args = container_run_args(&spec_run_options(&spec_args), "my-image:latest");
        let mut expected: Vec<String> =
            hardening_prefix().into_iter().map(str::to_string).collect();
        expected.extend(entrypoint_option());
        expected.extend([
            "-v".into(),
            "/tmp/policy.kdl:/etc/mcp-secure/policy.kdl:ro".into(),
            "my-image:latest".into(),
        ]);
        assert_eq!(args, expected);
    }

    #[test]
    fn spec_args_with_log_dir() {
        let policy = PathBuf::from("/etc/mcp/policy.kdl");
        let log_dir = PathBuf::from("/var/log/mcp");
        let args = production_run_args("secure-server:v2", &policy, Some(&log_dir));
        let mut expected: Vec<String> =
            hardening_prefix().into_iter().map(str::to_string).collect();
        expected.extend(entrypoint_option());
        expected.extend([
            "-v".into(),
            "/etc/mcp/policy.kdl:/etc/mcp-secure/policy.kdl:ro".into(),
            "-v".into(),
            "/var/log/mcp:/var/log/mcp-secure".into(),
            "secure-server:v2".into(),
        ]);
        assert_eq!(args, expected);
    }

    #[test]
    fn spec_args_with_report_share_env_and_cidfile() {
        let mut spec = spec("img");
        spec.shares.push(ShareMount {
            host: PathBuf::from("/tmp/policy.kdl"),
            guest: "/etc/mcp-secure/policy.kdl".to_string(),
            writable: false,
        });
        spec.shares.push(ShareMount {
            host: PathBuf::from("/tmp/mcp-report"),
            guest: crate::container::guest_report::GUEST_REPORT_MOUNT_PATH.to_string(),
            writable: true,
        });
        spec.env.push((
            crate::container::guest_report::REPORT_OUT_ENV.to_string(),
            crate::container::guest_report::GUEST_REPORT_MOUNT_PATH.to_string(),
        ));
        spec.env
            .push(("MCP_WRIT_SERVER".to_string(), "srv".to_string()));
        let launch_id = uuid::Uuid::nil();
        spec.env
            .push(("MCP_WRIT_LAUNCH_ID".to_string(), launch_id.to_string()));
        spec.unit_id_file = Some(PathBuf::from("/tmp/launch/container.id"));
        let args = container_run_args(&spec_run_options(&spec), "img");
        assert!(
            args.iter()
                .any(|a| a == "/tmp/mcp-report:/run/mcp-secure/report")
        );
        assert!(
            args.iter()
                .any(|a| a == "MCP_WRIT_REPORT_OUT=/run/mcp-secure/report")
        );
        assert!(args.iter().any(|a| a == "MCP_WRIT_SERVER=srv"));
        assert!(
            args.iter()
                .any(|a| a == &format!("MCP_WRIT_LAUNCH_ID={launch_id}"))
        );
        let cid_pos = args.iter().position(|a| a == "--cidfile").unwrap();
        assert_eq!(args[cid_pos + 1], "/tmp/launch/container.id");
    }

    #[test]
    fn spec_args_policy_share_is_readonly() {
        let policy = PathBuf::from("/tmp/p.kdl");
        let args = production_run_args("img", &policy, None);
        let volume = args
            .iter()
            .find(|a| a.contains("policy.kdl") || a.contains("p.kdl"))
            .expect("policy volume");
        assert!(
            volume.ends_with(":ro"),
            "policy mount should be read-only: {volume}"
        );
    }

    #[test]
    fn spec_args_image_is_last() {
        let policy = PathBuf::from("/tmp/p.kdl");
        let log_dir = PathBuf::from("/tmp/logs");
        let args = production_run_args("my-img", &policy, Some(&log_dir));
        assert_eq!(args.last().unwrap(), "my-img");
    }

    // -- check: spec combinations the OCI contract rejects --------------

    #[tokio::test]
    async fn oci_check_confirms_container() {
        let backend = oci();
        let check = backend.check(&spec("img")).await.expect("check passes");
        assert_eq!(check.verified, IsolationKind::Container);
        assert_eq!(check.unit, IsolationUnit::Container);
        assert_eq!(
            check.detail.as_deref(),
            Some("engine: buildah"),
            "the engine identity is part of the confirmation detail"
        );
    }

    #[tokio::test]
    async fn oci_check_rejects_foreign_isolation() {
        let backend = oci();
        let mut spec = spec("img");
        spec.isolation = IsolationKind::Kata;
        let err = backend.check(&spec).await.unwrap_err();
        match err {
            BackendError::Unsupported(msg) => {
                assert!(msg.contains("kata"), "got: {msg}");
            }
            other => panic!("expected Unsupported, got: {other}"),
        }
    }

    #[tokio::test]
    async fn oci_check_rejects_argv_only_workload() {
        let backend = oci();
        let mut spec = spec("img");
        spec.image = None;
        let err = backend.check(&spec).await.unwrap_err();
        assert!(matches!(err, BackendError::Unsupported(_)), "got: {err}");
    }

    /// The OCI runner contract is a Linux guest — the fixed
    /// `--entrypoint /usr/local/bin/mcp-secure-runner` must never be
    /// reused for a Windows guest.
    #[tokio::test]
    async fn oci_check_rejects_non_linux_guest() {
        let backend = oci();
        let mut spec = spec("img");
        spec.guest_os = TargetOs::Windows;
        let err = backend.check(&spec).await.unwrap_err();
        match err {
            BackendError::Unsupported(msg) => {
                assert!(msg.contains("windows"), "got: {msg}");
                assert!(msg.contains("mcp-secure-runner"), "got: {msg}");
            }
            other => panic!("expected Unsupported, got: {other}"),
        }
    }

    #[test]
    fn oci_capabilities_declared() {
        let caps = oci().capabilities();
        assert!(caps.oci_image);
        assert!(!caps.argv_command);
        assert!(caps.stdio_pipes);
        assert!(caps.terminate);
        assert!(caps.host_shares);
        assert!(caps.guest_os.contains(&TargetOs::Linux));
        assert!(!caps.guest_os.contains(&TargetOs::Windows));
    }
}
