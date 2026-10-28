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
    /// Shared with the launch handle so its `kill`/`rm`/`inspect`
    /// lifecycle commands also spawn through the bound, identity-
    /// re-verified driver — never a bare program spelling.
    engine: std::sync::Arc<dyn ContainerEngine>,
}

impl OciBackend {
    pub fn new(engine: Box<dyn ContainerEngine>) -> Self {
        Self {
            engine: engine.into(),
        }
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
            if spec.image.is_none() || spec.command.is_some() {
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
            if self.engine.name() == "wslc"
                && spec.guest_arch != crate::execution::TargetArch::host()
            {
                // The wslc session VM runs the host's architecture —
                // the validated contract is Windows x86-64 →
                // linux/amd64 with no binfmt bridge, so a foreign-arch
                // image refuses here rather than dying at exec inside
                // the session.
                return Err(BackendError::Unsupported(format!(
                    "the wslc session VM runs the host's {} architecture — \
                     image architecture '{}' has no emulation bridge in the \
                     validated contract",
                    crate::execution::TargetArch::host().name(),
                    spec.guest_arch.name()
                )));
            }
            let detail = if self.engine.name() == "wslc" {
                // The session VM is shared substrate plumbing, not a
                // per-unit boundary — the record says so rather than
                // letting `unit=container` imply a dedicated VM.
                "engine: wslc (shared session VM — substrate plumbing, unit=container)".to_string()
            } else {
                format!("engine: {}", self.engine.name())
            };
            Ok(IsolationCheck {
                verified: IsolationKind::Container,
                unit: IsolationUnit::Container,
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
                    "the OCI backend requires an image-defined workload".to_string(),
                )
            })?;
            // Arm the parent-directory watch before the identity check
            // so the covered window spans verify→mount-resolve entirely
            // — an event on a pinned leaf refuses the launch even when
            // the path itself is back in place by the time a check runs.
            let mut watch = super::begin_share_pin_watch(spec)?;
            // Pinned writable shares (the log mount) are re-opened and
            // identity-checked before their spelling reaches the engine
            // — a replaced path must not be bound into the guest.
            super::verify_share_pins(spec)?;
            let options = spec_run_options(spec);
            let option_refs: Vec<&str> = options.iter().map(String::as_str).collect();
            let child = self.engine.run(image, &option_refs, true).await?;
            let mut handle = EngineRunHandle::attach(
                child,
                self.engine.clone(),
                spec.unit_id_file.clone(),
                spec.unit_name.clone(),
            )
            .await;
            // `attach` can return before the substrate has finished
            // creating the unit, so this drain only covers what already
            // landed; the watch lives on in the handle and drains once
            // more when the session takes stdio — by then the mount has
            // resolved, and a repoint that slipped between the two
            // checks is caught with the same refusal. The second path
            // check here still wins cheaply when a replacement is left
            // in place.
            if let Err(e) = watch.drain().and_then(|()| super::verify_share_pins(spec)) {
                return Err(match handle.cleanup().await {
                    Ok(()) => e,
                    Err(c) => BackendError::CleanupFailed(format!(
                        "{e}; the refused unit could not be proven gone: {c}"
                    )),
                });
            }
            handle.share_watch = Some(watch);
            handle.graceful_signal = self.engine.interrupt_signal();
            Ok(Box::new(handle) as Box<dyn IsolationHandle>)
        })
    }
}

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
    // The caller-known name: the cidfile only lands after the unit is
    // created, so a cancellation inside that gap needs an identity the
    // host already holds for `rm`/`inspect`.
    if let Some(name) = &spec.unit_name {
        options.push("--name".to_string());
        options.push(name.clone());
    }
    options
}

/// Bound on `<engine> rm -f` teardown — the async `cleanup` wait and
/// the last-resort `Drop` give the engine CLI at most this long; a
/// wedged CLI must not stall session teardown or pin the dropping
/// thread.
const RM_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Bound on the graceful-signal unwind — the substrate's preferred
/// unit signal (`wslc kill -s SIGINT <unit>`) gets this long to let the
/// workload's own teardown (the runner's interrupted report) finish
/// before the CLI client is killed. A unit that ignores the signal
/// falls through to the hard stop.
const SIGNAL_GRACE: std::time::Duration = std::time::Duration::from_secs(5);

/// Bound on the post-`rm` removal check — `rm` returning is the engine
/// having *accepted* the delete, not the unit being gone (a timed-out
/// CLI keeps the deletion in flight). `inspect` is polled until it
/// stops resolving the unit; removal is only reported once the id is
/// unresolvable.
const REMOVAL_CONFIRM_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Bound on one `inspect` probe during the removal check — a wedged
/// CLI must not stall teardown, so each probe is killed and retried
/// until [`REMOVAL_CONFIRM_TIMEOUT`] elapses.
const INSPECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3);

/// How long `take_stdio` waits for proof the unit exists — a published
/// cidfile or a successful inspect — before draining the share watch.
/// The mount resolves during unit creation, so ending the watch
/// without that signal would leave a gap where the spelled path could
/// still be repointed unobserved.
const UNIT_READY_WAIT: std::time::Duration = std::time::Duration::from_secs(5);

/// The launch handle for an engine-driven unit — owns the engine CLI
/// child, the `--cidfile` path, and rm-by-id cleanup. Shared by the
/// backends that drive `<engine> run`: the OCI container path, the
/// kata VM path (`docker run --runtime kata` — the shim names its
/// `sandbox-<id>` VM after the container id the same `--cidfile`
/// records, and `rm -f <id>` tears the VM down identically), and the
/// wslc session-VM container path. On wslc the recorded id is a hex
/// container id the lifecycle commands accept directly — verified on
/// wslc 3.0.1.0 (`kill -s SIGKILL`/`rm -f`/`inspect` by the cidfile id
/// all resolve the unit; an unknown id answers
/// `WSLC_E_CONTAINER_NOT_FOUND`).
pub(crate) struct EngineRunHandle {
    child: tokio::process::Child,
    /// The engine the lifecycle commands (`kill`, `rm`, `inspect`)
    /// spawn — an `Arc` so the handle's later teardowns still go
    /// through the bound driver's identity re-verification rather than
    /// reopening a stale program spelling.
    engine: std::sync::Arc<dyn ContainerEngine>,
    cid_path: Option<PathBuf>,
    unit_id: Option<String>,
    /// The caller-generated `--name` — known before launch, so teardown
    /// can name the unit even when the cidfile id was never published
    /// (cancellation inside the create/publish gap).
    unit_name: Option<String>,
    /// The substrate's preferred unit signal for Ctrl-C teardown —
    /// `Some` sends `<engine> kill -s <sig> <unit>` and gives the unit
    /// [`SIGNAL_GRACE`] to unwind before the CLI client is killed;
    /// `None` leaves the client kill + `rm -f` as the whole stop path.
    pub(crate) graceful_signal: Option<&'static str>,
    /// The launch-window repoint detector for pinned shares —
    /// `take_stdio` drains it once more so a swap landing between
    /// `attach` and actual unit creation still refuses the session.
    pub(crate) share_watch: Option<super::SharePinWatch>,
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
        engine: std::sync::Arc<dyn ContainerEngine>,
        cid_path: Option<PathBuf>,
        unit_name: Option<String>,
    ) -> Self {
        let mut handle = Self {
            child,
            engine,
            cid_path,
            unit_id: None,
            unit_name,
            graceful_signal: None,
            share_watch: None,
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

    /// The identity lifecycle commands name the unit by: the recorded
    /// substrate id when known, else the caller-generated `--name`.
    /// `kill`, `rm`, and `inspect` all resolve an owned name the same
    /// as the recorded id on every engine this handle wraps (verified
    /// on wslc 3.0.1.0), so the name is a complete fallback for the
    /// cancel-before-publish gap.
    fn unit_identity(&self) -> Option<String> {
        self.recorded_unit_id().or_else(|| self.unit_name.clone())
    }

    /// `rm` returning is not removal — a timed-out CLI keeps the
    /// deletion in flight, and an engine that accepted the request can
    /// still leave the unit resolvable. Removal is only confirmed once
    /// `inspect` answers that the id does not exist; every engine this
    /// handle wraps prints a not-found marker for an absent unit
    /// (verified on wslc 3.0.1.0, where an unknown id answers
    /// `WSLC_E_CONTAINER_NOT_FOUND`). Any other inspect outcome — the
    /// unit still resolving, or a failure that cannot distinguish
    /// absent from unreachable — leaves removal unconfirmed.
    async fn confirm_removed(&self, id: &str) -> Result<(), BackendError> {
        let deadline = std::time::Instant::now() + REMOVAL_CONFIRM_TIMEOUT;
        loop {
            let unconfirmed = match self.engine.driver_command() {
                // A driver whose identity no longer verifies cannot
                // answer inspect at all — the unit stays unconfirmed.
                Err(e) => Some(format!("inspect failed to run: {e}")),
                Ok(mut cmd) => {
                    cmd.args(["inspect", id]);
                    let inspect = crate::container::engine::bounded_cmd_output(&mut cmd, false);
                    match tokio::time::timeout(INSPECT_TIMEOUT, inspect).await {
                        // Only a not-found answer proves the unit is gone.
                        Ok(Ok(out))
                            if !out.status.success()
                                && crate::container::common::inspect_error_is_absent(
                                    &String::from_utf8_lossy(&out.stderr),
                                ) =>
                        {
                            return Ok(());
                        }
                        Ok(Ok(out)) if !out.status.success() => {
                            let stderr = String::from_utf8_lossy(&out.stderr);
                            let stderr = stderr.trim();
                            Some(if stderr.is_empty() {
                                "inspect exited non-zero".to_string()
                            } else {
                                stderr.to_string()
                            })
                        }
                        // Still resolvable — removal has not landed yet.
                        Ok(Ok(_)) => None,
                        Ok(Err(e)) => Some(format!("inspect failed to run: {e}")),
                        Err(_) => Some("inspect timed out".to_string()),
                    }
                }
            };
            if std::time::Instant::now() >= deadline {
                return Err(BackendError::CleanupFailed(match unconfirmed {
                    Some(msg) => format!(
                        "container unit {id} removal unconfirmed after `rm -f` (inspect: {msg})"
                    ),
                    None => format!("container unit {id} still resolvable after `rm -f`"),
                }));
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
    }

    /// Synchronous existence probe for `take_stdio` — `true` only when
    /// `<cli> inspect <id>` exits 0 within [`INSPECT_TIMEOUT`], meaning
    /// the unit provably exists (created, running, or stopped). A
    /// failed, absent, timed-out, or unspawnable probe answers `false`
    /// so the caller keeps waiting instead of trusting an unanswerable
    /// signal — the opposite polarity of `unit_resolvable_blocking`,
    /// which must assume the unit lives on doubt.
    fn unit_present_blocking(id: &str, engine: &dyn ContainerEngine) -> bool {
        // An unverifiable or unspawnable driver answers `false` — the
        // caller keeps waiting rather than trusting a substitute.
        let Ok(mut cmd) = engine.driver_std_command() else {
            return false;
        };
        let Ok(mut inspect) = cmd
            .args(["inspect", id])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
        else {
            return false;
        };
        let deadline = std::time::Instant::now() + INSPECT_TIMEOUT;
        loop {
            match inspect.try_wait() {
                Ok(Some(status)) => {
                    let _ = inspect.wait();
                    return status.success();
                }
                Ok(None) if std::time::Instant::now() >= deadline => {
                    let _ = inspect.kill();
                    let _ = inspect.wait();
                    return false;
                }
                Ok(None) => std::thread::sleep(std::time::Duration::from_millis(25)),
                Err(_) => return false,
            }
        }
    }

    /// Synchronous single-probe variant for `Drop` — `true` when the
    /// unit still resolves. An unanswerable inspect is treated as
    /// "still present" (conservative — the dropped handle reports the
    /// leak rather than claiming teardown).
    fn unit_resolvable_blocking(id: &str, engine: &dyn ContainerEngine) -> bool {
        // An unverifiable or unspawnable driver proves nothing — the
        // conservative answer is "still present".
        let Ok(mut cmd) = engine.driver_std_command() else {
            return true;
        };
        let Ok(mut inspect) = cmd
            .args(["inspect", id])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped())
            .spawn()
        else {
            return true;
        };
        let deadline = std::time::Instant::now() + INSPECT_TIMEOUT;
        loop {
            match inspect.try_wait() {
                Ok(Some(status)) => {
                    if status.success() {
                        return true;
                    }
                    // Only an explicit not-found answer proves absence —
                    // any other failure leaves the unit's fate unknown.
                    let absent = inspect
                        .wait_with_output()
                        .map(|o| {
                            crate::container::common::inspect_error_is_absent(
                                &String::from_utf8_lossy(&o.stderr),
                            )
                        })
                        .unwrap_or(false);
                    return !absent;
                }
                Ok(None) if std::time::Instant::now() >= deadline => {
                    let _ = inspect.kill();
                    let _ = inspect.wait();
                    return true;
                }
                Ok(None) => std::thread::sleep(std::time::Duration::from_millis(25)),
                Err(_) => return true,
            }
        }
    }
}

impl IsolationHandle for EngineRunHandle {
    fn unit_id(&self) -> Option<String> {
        // Read through to the id file — a `--cidfile` that landed after
        // launch's bounded poll still reports the real unit id.
        self.recorded_unit_id()
    }

    fn take_stdio(&mut self) -> Result<SessionStdio, BackendError> {
        // The mount resolves while the unit is created, which races
        // `attach`'s return — end the launch-window watch only once the
        // unit provably exists (a published cidfile, or an inspect that
        // resolves it), bounded by [`UNIT_READY_WAIT`]. A spec without
        // a unit identity can never produce that signal and is refused
        // outright. Then the final drain runs: a repoint that slipped
        // between `attach` and create still refuses before the first
        // byte flows — the driver's error path runs the usual cleanup.
        // A spec with no unit identity at all can never produce the
        // signal — refuse upfront; a cidfile-only spec still can (the
        // daemon may publish it inside this window), so it polls on.
        if self.cid_path.is_none() && self.unit_name.is_none() {
            return Err(BackendError::LaunchFailed(
                "container unit has no trackable identity — its mount cannot be proven resolved"
                    .into(),
            ));
        }
        let deadline = std::time::Instant::now() + UNIT_READY_WAIT;
        loop {
            if self.recorded_unit_id().is_some() {
                break;
            }
            if let Some(name) = &self.unit_name
                && Self::unit_present_blocking(name, &*self.engine)
            {
                break;
            }
            if std::time::Instant::now() >= deadline {
                return Err(BackendError::LaunchFailed(format!(
                    "container unit was not observable within {}s — the share mount cannot be proven resolved",
                    UNIT_READY_WAIT.as_secs()
                )));
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        if let Some(watch) = &mut self.share_watch {
            watch.drain()?;
        }
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
            // A substrate whose unit survives its CLI client's death —
            // wslc's session-VM units — gets the graceful unit signal
            // first so the workload's own teardown (the runner's
            // interrupted report) still runs; then the usual client
            // kill + rm-by-id hard stop applies. The wslc `kill`
            // accepts the cidfile-recorded id the same as the owned
            // `--name` (verified on wslc 3.0.1.0). Signal or wait
            // failures never gate: the hard stop always follows.
            if let Some(signal) = self.graceful_signal
                && let Some(unit) = self.unit_identity()
                && let Ok(mut cmd) = self.engine.driver_command()
            {
                cmd.args(["kill", "-s", signal, &unit]);
                let sig = crate::container::engine::bounded_cmd_output(&mut cmd, false);
                let _ = tokio::time::timeout(RM_TIMEOUT, sig).await;
                let _ = tokio::time::timeout(SIGNAL_GRACE, self.child.wait()).await;
            }
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
            // Recheck publication once the client is stopped: the
            // cidfile may land only when the daemon finishes creating
            // the unit, which races the client's death. The caller-known
            // `--name` covers a unit whose id never publishes at all.
            self.wait_for_unit_id().await;
            let Some(id) = self.unit_identity() else {
                // No identity at all means nothing to `rm` or `inspect`
                // — removal cannot be proven, so this is an error and
                // `cleaned` stays false for `Drop` to retry.
                return Err(BackendError::CleanupFailed(
                    "no container unit identity recorded (cidfile unpublished, \
                     no --name); a detached unit may still be running"
                        .to_string(),
                ));
            };
            // Bound the wait on the engine CLI — a timed-out `rm`
            // keeps running detached, so the unit is still released.
            // An unverifiable driver cannot run the removal; the
            // confirm below then fails closed rather than trusting a
            // substitute.
            if let Ok(mut cmd) = self.engine.driver_command() {
                cmd.args(["rm", "-f", &id]);
                let rm = crate::container::engine::bounded_cmd_output(&mut cmd, false);
                let _ = tokio::time::timeout(RM_TIMEOUT, rm).await;
            }
            // Removal is only reported once `inspect` stops resolving
            // the unit — a still-resolvable id is a cleanup failure the
            // caller hears about, and `cleaned` stays false so `Drop`
            // retries the teardown rather than leaking the unit.
            match self.confirm_removed(&id).await {
                Ok(()) => {
                    self.cleaned = true;
                    Ok(())
                }
                Err(e) => Err(e),
            }
        })
    }
}

/// A dropped live handle still releases the unit — a session future
/// cancelled mid-flight must not leave a container running. Blocking
/// teardown is acceptable here: it is the last resort path, not the
/// normal `cleanup` the driver runs. The wait is bounded — [`RM_TIMEOUT`]
/// on the `rm` plus four [`INSPECT_TIMEOUT`]-capped probes, ~22s worst
/// case — so a wedged engine CLI cannot pin the dropping thread
/// indefinitely. The bound is still a long stall on an executor thread
/// when a cancelled session future drops the handle inside async
/// context; callers should let `cleanup` run first (it sets `cleaned`,
/// making `Drop` return early) instead of relying on `Drop` there.
impl Drop for EngineRunHandle {
    fn drop(&mut self) {
        if self.cleaned {
            return;
        }
        self.cleaned = true;
        let _ = self.child.start_kill();
        // Recheck the cidfile once the client is stopped — the id can
        // land after launch's bounded poll; the caller-known `--name`
        // remains the fallback identity.
        let id = self.unit_identity();
        if id.is_none() {
            tracing::warn!(
                "container unit identity never recorded (cidfile unpublished, \
                 no --name) — a detached engine unit may be running"
            );
        }
        if let Some(id) = id {
            let mut rm = match self.engine.driver_std_command().and_then(|mut c| {
                c.args(["rm", "-f", &id])
                    .stdin(std::process::Stdio::null())
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null());
                c.spawn()
            }) {
                Ok(rm) => rm,
                // A failed bound-driver verification means the resolved
                // executable no longer names the validated object — the
                // unit leaks, but retrying through an unverified
                // spelling would run a substituted binary instead.
                Err(e) => {
                    tracing::warn!(
                        "container unit {id} teardown skipped — driver \
                         command failed verification or spawn: {e}"
                    );
                    return;
                }
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
            // `Drop` cannot propagate a failure — a still-resolvable
            // unit is the resource leak the caller was trying to avoid,
            // so surface it rather than claiming silent success.
            for _ in 0..4 {
                if !Self::unit_resolvable_blocking(&id, &*self.engine) {
                    return;
                }
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            tracing::warn!(
                "container unit {id} still resolvable after `rm -f` — \
                 teardown may have leaked an isolated unit"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::container::backends::ShareMount;
    use crate::container::engine::{
        BuildahEngine, ContainerEngine, WslcEngine, container_run_args,
    };
    use crate::execution::{TargetArch, TargetOs};

    fn spec(image: &str) -> LaunchSpec {
        LaunchSpec {
            isolation: IsolationKind::Container,
            image: Some(image.to_string()),
            command: None,
            guest_os: TargetOs::Linux,
            guest_arch: TargetArch::X86_64,
            image_os_version: None,
            shares: Vec::new(),
            env: Vec::new(),
            unit_id_file: None,
            unit_name: None,
        }
    }

    fn oci() -> OciBackend {
        // `check` never spawns the engine CLI — the buildah unit is a
        // convenient stand-in engine.
        OciBackend::new(Box::new(BuildahEngine::for_test("buildah")))
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
            pin: None,
        });
        if let Some(dir) = log_dir_abs {
            spec.shares.push(ShareMount {
                host: dir.to_path_buf(),
                guest: "/var/log/mcp-secure".to_string(),
                writable: true,
                pin: None,
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
            "MCP_WRIT_MAX_FRAME_BYTES=",
            "-e",
            "MCP_WRIT_POLICY_PATH=",
            "-e",
            "MCP_WRIT_AUDIT_DIR=",
            "-e",
            "MCP_WRIT_TEMP_DIR=",
            "-e",
            "MCP_WRIT_ALLOW_REPLACEABLE_PATHS=",
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
                pin: None,
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
            pin: None,
        });
        spec.shares.push(ShareMount {
            host: PathBuf::from("/tmp/mcp-report"),
            guest: crate::container::guest_report::GUEST_REPORT_MOUNT_PATH.to_string(),
            writable: true,
            pin: None,
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

    /// A caller-known `--name` is emitted when the spec carries one —
    /// teardown can then name the unit even when the cidfile never
    /// published the substrate id.
    #[test]
    fn spec_args_emit_caller_unit_name() {
        let mut s = spec("img");
        s.unit_name = Some("mcp-writ-deadbeef".to_string());
        let args = container_run_args(&spec_run_options(&s), "img");
        let pos = args.iter().position(|a| a == "--name").unwrap();
        assert_eq!(args[pos + 1], "mcp-writ-deadbeef");
        let without = container_run_args(&spec_run_options(&spec("img")), "img");
        assert!(!without.iter().any(|a| a == "--name"));
    }

    /// A stub engine for the share-swap tests: `run` performs the
    /// attacker's filesystem move — the same instant the real substrate
    /// would resolve the spelled mount source — then spawns a real
    /// child so the launch proceeds to the post-attach checks.
    /// `program` points at a script answering every lifecycle call with
    /// an absent-unit marker so refused-launch teardown stays fast.
    /// `#[allow(dead_code)]`: the enum is used only by the unix
    /// share-swap tests, and `SwapBack`/`AncestorSwap` only by the
    /// Linux launch-window ones.
    #[allow(dead_code)]
    enum SwapMode {
        /// Leave the path untouched — the clean control.
        None,
        /// Move the verified dir away and leave a replacement in place.
        Swap,
        /// Move away, replace, then restore — the path looks untouched
        /// afterwards; only the launch-window watch sees the swap.
        SwapBack,
        /// Repoint an ancestor above the share's parent: rename the
        /// ancestor directory away and rebuild the spelled path inside
        /// a fresh one — a parent-only watch would follow the moved
        /// object and never see it.
        AncestorSwap,
    }

    /// `#[allow(dead_code)]`: constructed only by the unix share-swap
    /// tests — Windows compiles the fixture but never runs one.
    #[allow(dead_code)]
    struct SwapEngine {
        dir: PathBuf,
        backup: PathBuf,
        cli: PathBuf,
        mode: SwapMode,
    }

    /// `#[allow(dead_code)]`: `new` is called only from the unix tests.
    #[allow(dead_code)]
    impl SwapEngine {
        fn new(dir: PathBuf, backup: PathBuf, stage: &std::path::Path, mode: SwapMode) -> Self {
            let cli = stage.join("stub-engine.sh");
            // `inspect` resolves the unit until `rm` records it gone —
            // the take_stdio readiness probe sees an existing unit, and
            // refused-launch teardown confirms removal fast.
            std::fs::write(
                &cli,
                format!(
                    "#!/bin/sh\n\
                     if [ \"$1\" = \"rm\" ]; then touch \"{0}/unit-gone\"; exit 0; fi\n\
                     if [ \"$1\" = \"inspect\" ] && [ ! -f \"{0}/unit-gone\" ]; then exit 0; fi\n\
                     echo 'Error: No such object: fake' >&2\n\
                     exit 1\n",
                    stage.display()
                ),
            )
            .unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&cli, std::fs::Permissions::from_mode(0o755)).unwrap();
            }
            Self {
                dir,
                backup,
                cli,
                mode,
            }
        }
    }

    impl ContainerEngine for SwapEngine {
        fn name(&self) -> &str {
            "docker"
        }
        fn program(&self) -> &str {
            self.cli.to_str().unwrap()
        }
        fn build<'a>(
            &'a self,
            _d: &'a str,
            _t: &'a str,
            _c: &'a str,
            _n: bool,
        ) -> crate::container::engine::BoxFuture<
            'a,
            Result<(), crate::container::engine::EngineError>,
        > {
            unreachable!("the swap engine never builds")
        }
        fn inspect<'a>(
            &'a self,
            _i: &'a str,
        ) -> crate::container::engine::BoxFuture<
            'a,
            Result<String, crate::container::engine::EngineError>,
        > {
            unreachable!("the swap engine never inspects images")
        }
        fn tag<'a>(
            &'a self,
            _s: &'a str,
            _t: &'a str,
        ) -> crate::container::engine::BoxFuture<
            'a,
            Result<(), crate::container::engine::EngineError>,
        > {
            unreachable!("the swap engine never tags")
        }
        fn remove_image<'a>(
            &'a self,
            _i: &'a str,
        ) -> crate::container::engine::BoxFuture<
            'a,
            Result<(), crate::container::engine::EngineError>,
        > {
            unreachable!("the swap engine never removes images")
        }
        fn info<'a>(
            &'a self,
        ) -> crate::container::engine::BoxFuture<
            'a,
            Result<String, crate::container::engine::EngineError>,
        > {
            unreachable!("the swap engine never reports info")
        }
        fn run<'a>(
            &'a self,
            _i: &'a str,
            _a: &'a [&'a str],
            _s: bool,
        ) -> crate::container::engine::BoxFuture<
            'a,
            Result<tokio::process::Child, crate::container::engine::EngineError>,
        > {
            Box::pin(async move {
                // The filesystem move lands exactly where the real
                // daemon would resolve the mount spelling — after the
                // pre-launch verification, before the session proceeds.
                match self.mode {
                    SwapMode::None => {}
                    SwapMode::Swap => {
                        std::fs::rename(&self.dir, &self.backup).unwrap();
                        std::fs::create_dir(&self.dir).unwrap();
                    }
                    SwapMode::SwapBack => {
                        std::fs::rename(&self.dir, &self.backup).unwrap();
                        std::fs::create_dir(&self.dir).unwrap();
                        std::fs::remove_dir(&self.dir).unwrap();
                        std::fs::rename(&self.backup, &self.dir).unwrap();
                    }
                    SwapMode::AncestorSwap => {
                        // `dir` is <ancestor>/<mid>/<leaf>: move the
                        // ancestor away, rebuild the whole spelling
                        // inside a replacement ancestor, then restore
                        // the original — the leaf's parent object is
                        // never touched and the pinned ancestor is back
                        // in place afterwards, so only the component
                        // watch (not the identity re-check) can see it.
                        let leaf = self.dir.file_name().unwrap().to_os_string();
                        let mid_dir = self.dir.parent().unwrap();
                        let mid = mid_dir.file_name().unwrap().to_os_string();
                        let ancestor = mid_dir.parent().unwrap();
                        let escaped = ancestor.parent().unwrap().join(format!(
                            "{}-bak",
                            ancestor.file_name().unwrap().to_string_lossy()
                        ));
                        std::fs::rename(ancestor, &escaped).unwrap();
                        std::fs::create_dir_all(ancestor.join(&mid).join(&leaf)).unwrap();
                        std::fs::remove_dir_all(ancestor).unwrap();
                        std::fs::rename(&escaped, ancestor).unwrap();
                    }
                }
                tokio::process::Command::new("sleep")
                    .arg("30")
                    .stdin(std::process::Stdio::piped())
                    .stdout(std::process::Stdio::piped())
                    .stderr(std::process::Stdio::null())
                    .kill_on_drop(true)
                    .spawn()
                    .map_err(|e| crate::container::engine::EngineError::CommandFailed {
                        engine: "docker".to_string(),
                        message: format!("stub run spawn failed: {e}"),
                    })
            })
        }
        fn is_available(&self) -> bool {
            true
        }
    }

    /// A share path swapped between the pre-launch verification and the
    /// substrate's mount resolution must not be trusted: `run` performs
    /// the replacement mid-launch, and the post-create re-check refuses
    /// the session rather than letting the substituted directory stand
    /// in as the mounted share.
    #[cfg(unix)]
    #[tokio::test]
    async fn launch_refuses_share_replaced_before_mount() {
        let stage = tempfile::tempdir().unwrap();
        let dir = stage.path().join("logs");
        let backup = stage.path().join("logs-backup");
        std::fs::create_dir(&dir).unwrap();
        let (_check, identity) = crate::fspriv::open_dir_pinned(&dir).unwrap();

        let mut s = spec("img");
        s.shares.push(ShareMount {
            host: dir.clone(),
            guest: "/var/log/mcp-secure".to_string(),
            writable: true,
            pin: Some(identity),
        });
        s.unit_name = Some("mcp-writ-test-share-swap".to_string());

        let backend = OciBackend::new(Box::new(SwapEngine::new(
            dir,
            backup,
            stage.path(),
            SwapMode::Swap,
        )));
        let outcome = backend.launch(&s).await;
        assert!(
            outcome.is_err(),
            "a share replaced before the mount resolves must refuse the launch"
        );
    }

    /// The attack the path re-check cannot see: the verified dir is
    /// replaced and then restored inside the launch window, so the
    /// spelled path names the right object again by the time a second
    /// path check runs. The parent-directory watch still recorded the
    /// move/create events — the launch must refuse.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn launch_refuses_share_swapped_back_in_window() {
        let stage = tempfile::tempdir().unwrap();
        let dir = stage.path().join("logs");
        let backup = stage.path().join("logs-backup");
        std::fs::create_dir(&dir).unwrap();
        let (_check, identity) = crate::fspriv::open_dir_pinned(&dir).unwrap();

        let mut s = spec("img");
        s.shares.push(ShareMount {
            host: dir.clone(),
            guest: "/var/log/mcp-secure".to_string(),
            writable: true,
            pin: Some(identity),
        });
        s.unit_name = Some("mcp-writ-test-share-swapback".to_string());

        let backend = OciBackend::new(Box::new(SwapEngine::new(
            dir,
            backup,
            stage.path(),
            SwapMode::SwapBack,
        )));
        let outcome = backend.launch(&s).await;
        assert!(
            outcome.is_err(),
            "a repoint-and-restore inside the launch window must refuse"
        );
    }

    /// An ancestor repoint-and-restore: the directory above the
    /// share's parent is swapped wholesale and then put back, so both
    /// the leaf's own parent object and the pinned ancestor are in
    /// place afterwards — the identity re-check sees the original,
    /// and only the component watch's event stream can catch the
    /// repoint. The launch must refuse.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn launch_refuses_share_ancestor_repoint() {
        let stage = tempfile::tempdir().unwrap();
        let dir = stage.path().join("outer").join("inner").join("logs");
        std::fs::create_dir_all(&dir).unwrap();
        let (_check, identity) = crate::fspriv::open_dir_pinned(&dir).unwrap();

        let mut s = spec("img");
        s.shares.push(ShareMount {
            host: dir.clone(),
            guest: "/var/log/mcp-secure".to_string(),
            writable: true,
            pin: Some(identity),
        });
        s.unit_name = Some("mcp-writ-test-share-ancestor".to_string());

        let backend = OciBackend::new(Box::new(SwapEngine::new(
            dir,
            stage.path().join("unused"),
            stage.path(),
            SwapMode::AncestorSwap,
        )));
        let outcome = backend.launch(&s).await;
        assert!(
            outcome.is_err(),
            "an ancestor repoint inside the launch window must refuse"
        );
    }

    /// A drain that already fired must stay fired: the first failure
    /// is retained so a later drain cannot consume the events and then
    /// report the window clean.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn share_watch_drain_retains_first_failure() {
        let stage = tempfile::tempdir().unwrap();
        let dir = stage.path().join("logs");
        std::fs::create_dir(&dir).unwrap();
        let (_check, identity) = crate::fspriv::open_dir_pinned(&dir).unwrap();

        let mut s = spec("img");
        s.shares.push(ShareMount {
            host: dir.clone(),
            guest: "/var/log/mcp-secure".to_string(),
            writable: true,
            pin: Some(identity),
        });

        let mut watch = crate::container::backends::begin_share_pin_watch(&s).unwrap();
        assert!(watch.drain().is_ok(), "a clean window drains");
        std::fs::rename(&dir, stage.path().join("logs-moved")).unwrap();
        assert!(watch.drain().is_err(), "the repoint must refuse");
        assert!(
            watch.drain().is_err(),
            "the consumed failure must stay refused on the next drain"
        );
    }

    /// The control for the swap tests: with the pinned dir left alone,
    /// the launch proceeds — the arming/verifying/draining pipeline
    /// itself must not refuse a clean window — and the final drain
    /// inside `take_stdio` hands the pipes over.
    #[cfg(unix)]
    #[tokio::test]
    async fn launch_with_stable_pinned_share_proceeds() {
        let stage = tempfile::tempdir().unwrap();
        let dir = stage.path().join("logs");
        let backup = stage.path().join("logs-backup");
        std::fs::create_dir(&dir).unwrap();
        let (_check, identity) = crate::fspriv::open_dir_pinned(&dir).unwrap();

        let mut s = spec("img");
        s.shares.push(ShareMount {
            host: dir.clone(),
            guest: "/var/log/mcp-secure".to_string(),
            writable: true,
            pin: Some(identity),
        });
        s.unit_name = Some("mcp-writ-test-share-stable".to_string());

        let backend = OciBackend::new(Box::new(SwapEngine::new(
            dir,
            backup,
            stage.path(),
            SwapMode::None,
        )));
        let mut handle = backend.launch(&s).await.unwrap();
        handle
            .take_stdio()
            .expect("a clean launch window must hand over stdio");
        handle.cleanup().await.unwrap();
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

    /// The wslc session VM runs the host's architecture — a
    /// foreign-arch spec refuses at `check` (no binfmt bridge in the
    /// validated contract), and a host-arch spec's detail names the
    /// shared session VM rather than implying a dedicated boundary.
    #[tokio::test]
    async fn oci_check_wslc_gates_arch_and_marks_shared_session() {
        let backend = OciBackend::new(Box::new(WslcEngine::for_test("wslc")));
        let mut s = spec("img");
        s.guest_arch = TargetArch::host();
        let check = backend.check(&s).await.expect("host arch passes");
        let detail = check.detail.expect("wslc records a detail");
        assert!(detail.contains("wslc"), "{detail}");
        assert!(
            detail.contains("shared session VM"),
            "unit=container must not imply a dedicated VM: {detail}"
        );
        let foreign = match TargetArch::host() {
            TargetArch::X86_64 => TargetArch::Aarch64,
            _ => TargetArch::X86_64,
        };
        s.guest_arch = foreign.clone();
        let err = backend.check(&s).await.unwrap_err();
        match err {
            BackendError::Unsupported(msg) => {
                assert!(msg.contains("session VM"), "{msg}");
                assert!(msg.contains(foreign.name()), "{msg}");
            }
            other => panic!("expected Unsupported, got: {other}"),
        }
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
