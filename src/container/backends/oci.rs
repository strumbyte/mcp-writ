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
mod tests;
