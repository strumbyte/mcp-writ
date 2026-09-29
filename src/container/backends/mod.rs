//! The additional-isolation backend contract.
//!
//! An isolation *backend* is the concrete way an [`IsolationKind`] is
//! provided on this host: the OCI container path in [`oci`], the Kata
//! Containers VM path in [`kata`], and — in later PRs — Apple
//! `container`, Hyper-V, and Windows Sandbox adapters. The contract is
//! deliberately minimal: a backend declares
//! what it can run and observe ([`BackendCapabilities`]), checks a typed
//! [`LaunchSpec`] against them, and produces an [`IsolationHandle`] the
//! shared session driver owns. Interfaces only some substrates can
//! express — OCI `build`, image inspect — stay on
//! [`crate::container::engine::ContainerEngine`], not on this contract.
//!
//! The lifecycle split is fixed here so every backend shares it:
//! `check` confirms the isolation the launch will actually get (never a
//! different one — [`ensure_confirmed`] refuses a mismatch), `launch`
//! starts the workload, and [`drive_stdio_session`] owns relay / wait /
//! interrupt / cleanup uniformly on top of the handle.

use std::fmt;
use std::future::Future;
use std::path::PathBuf;

use tokio::io::{AsyncRead, AsyncWrite};

use crate::container::engine::{BoxFuture, ContainerEngine, EngineError};
use crate::execution::{IsolationKind, IsolationUnit, TargetArch, TargetOs};

pub mod kata;
pub mod oci;
pub use kata::KataBackend;
pub use oci::OciBackend;

/// What a backend declares it can provide. This is the *declared*
/// capability set — kept distinct from what a particular launch
/// verified; a launch is refused when the spec requires something the
/// declaration does not cover.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BackendCapabilities {
    /// Host OSs the backend can run on.
    pub host_os: &'static [TargetOs],
    /// Workload OSs the backend can launch.
    pub guest_os: &'static [TargetOs],
    /// Accepts an OCI image reference as the workload definition.
    pub oci_image: bool,
    /// Accepts a host command line as the workload definition.
    pub argv_command: bool,
    /// Interactive stdin/stdout pipes — the MCP relay needs both.
    pub stdio_pipes: bool,
    /// The launch can be asked to terminate, not only awaited.
    pub terminate: bool,
    /// Host paths can be shared into the guest — the policy mount, the
    /// log mount, and the guest-report channel all depend on it.
    pub host_shares: bool,
    /// Resource limits can be requested (cpu/memory).
    pub resource_limits: bool,
    /// Observation channels the backend exposes — stable tags like
    /// `"guest-report-mount"` or `"unit-id-file"`.
    pub observations: &'static [&'static str],
}

/// A host→guest shared path in a [`LaunchSpec`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShareMount {
    /// Absolute host path (canonicalized by the caller).
    pub host: PathBuf,
    /// Guest-visible mount point, in the *guest's* path syntax — a Linux
    /// guest mount is a `/`-path regardless of the host OS.
    pub guest: String,
    /// Writable share (`false` mounts read-only).
    pub writable: bool,
}

/// The typed launch conditions handed to a backend. The backend turns
/// it into its own argument shape — and refuses combinations it cannot
/// express (the OCI runner contract is a Linux guest; a Windows guest
/// never inherits the Linux entrypoint).
#[derive(Debug)]
pub struct LaunchSpec {
    /// The isolation method the launch requires — `check` must confirm
    /// exactly this kind or refuse.
    pub isolation: IsolationKind,
    /// OCI image reference, when the workload is defined by an image.
    /// Backends without `oci_image` reject `Some(..)`; image backends
    /// reject `None`.
    pub image: Option<String>,
    /// Workload OS the spec requires in the guest.
    pub guest_os: TargetOs,
    /// Workload CPU architecture. Carried for the launch record, not a
    /// launch condition `check` must verify — the substrate negotiates
    /// platform support at run time (the OCI engine resolves the image's
    /// platform itself), so backends record rather than refuse on it.
    pub guest_arch: TargetArch,
    /// Host→guest path shares (policy read-only, logs/report writable).
    pub shares: Vec<ShareMount>,
    /// Channel env vars the backend must set for the workload.
    pub env: Vec<(String, String)>,
    /// Where the substrate records the unit identifier
    /// (`--cidfile`-equivalent); `None` when the launch does not need to
    /// recover the id for interrupted cleanup.
    pub unit_id_file: Option<PathBuf>,
}

/// What a backend confirmed it can apply for one specific launch — the
/// `check` result, kept distinct from the configured request.
#[derive(Debug)]
pub struct IsolationCheck {
    /// The isolation the backend will actually apply; [`ensure_confirmed`]
    /// requires this to equal `spec.isolation` before launch.
    pub verified: IsolationKind,
    /// The isolation unit granularity the launch gets.
    pub unit: IsolationUnit,
    /// Backend detail (runtime name/version, refusal context).
    pub detail: Option<String>,
}

/// Backend failure modes.
#[derive(Debug)]
pub enum BackendError {
    /// The requested isolation kind or a spec combination is not
    /// supported by this backend — including kinds no backend in this
    /// build implements.
    Unsupported(String),
    /// The backend confirmed a different isolation than the spec
    /// requires — refusal is the only allowed outcome; there is no
    /// degrade to a weaker boundary.
    IsolationMismatch {
        /// The isolation the launch required.
        requested: &'static str,
        /// The isolation the backend confirmed it would apply.
        confirmed: &'static str,
    },
    /// The workload could not be launched or awaited.
    LaunchFailed(String),
    /// IO error talking to the substrate.
    Io(std::io::Error),
}

impl fmt::Display for BackendError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unsupported(msg) => write!(f, "unsupported isolation: {msg}"),
            Self::IsolationMismatch {
                requested,
                confirmed,
            } => write!(
                f,
                "isolation mismatch: requested {requested} but the backend confirmed {confirmed}"
            ),
            Self::LaunchFailed(msg) => write!(f, "isolated launch failed: {msg}"),
            Self::Io(e) => write!(f, "isolation backend IO error: {e}"),
        }
    }
}

impl std::error::Error for BackendError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for BackendError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<EngineError> for BackendError {
    fn from(e: EngineError) -> Self {
        Self::LaunchFailed(e.to_string())
    }
}

/// An isolation backend — the concrete provider of an [`IsolationKind`]
/// on this host. Implementations stay thin: they declare capabilities,
/// check a typed spec against them, and produce a launch handle. The
/// shared session driver owns relay/wait/interrupt semantics on top.
pub trait IsolationBackend: Send + Sync {
    /// The isolation method this backend implements.
    fn kind(&self) -> IsolationKind;

    /// The declared capability set — what the backend can express, not
    /// what a particular launch verified.
    fn capabilities(&self) -> BackendCapabilities;

    /// Check that `spec` can be satisfied on this host; the returned
    /// record is what the launch will actually get. `Err` refuses the
    /// launch before anything starts — a spec the backend cannot
    /// satisfy is never silently degraded.
    fn check<'a>(
        &'a self,
        spec: &'a LaunchSpec,
    ) -> BoxFuture<'a, Result<IsolationCheck, BackendError>>;

    /// Start the workload. A returned handle owns every resource the
    /// launch created; a failed launch leaves nothing running behind.
    fn launch<'a>(
        &'a self,
        spec: &'a LaunchSpec,
    ) -> BoxFuture<'a, Result<Box<dyn IsolationHandle>, BackendError>>;
}

/// The stdio pipes a session relay drives.
pub struct SessionStdio {
    /// Workload stdin (write end) — dropping it signals stdin-EOF.
    pub stdin: Box<dyn AsyncWrite + Send + Unpin>,
    /// Workload stdout (read end).
    pub stdout: Box<dyn AsyncRead + Send + Unpin>,
}

/// A running isolated workload — the launch handle the driver owns.
///
/// `terminate` and `cleanup` must tolerate an already-exited unit, and
/// `cleanup` must be idempotent: every session end — normal exit,
/// interruption, partial launch failure — finishes in `cleanup`.
pub trait IsolationHandle: Send {
    /// The substrate-assigned identifier of the isolation unit
    /// (container id, VM name); `None` when the substrate did not expose
    /// one for this launch.
    fn unit_id(&self) -> Option<String>;

    /// Take the workload's stdio pipes — once.
    fn take_stdio(&mut self) -> Result<SessionStdio, BackendError>;

    /// Wait for the workload to exit; returns the observed exit code.
    fn wait_exit(&mut self) -> BoxFuture<'_, Result<i32, BackendError>>;

    /// Ask the backend to terminate the workload (kill/stop semantics).
    fn terminate(&mut self) -> BoxFuture<'_, Result<(), BackendError>>;

    /// Release every resource the launch holds. Idempotent — safe to
    /// call after `terminate` or a natural exit.
    fn cleanup(&mut self) -> BoxFuture<'_, Result<(), BackendError>>;
}

/// The way a driven session ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionEnd {
    /// The workload exited on its own; carries the observed exit code.
    Exited(i32),
    /// A termination request (Ctrl-C) ended the session — the backend
    /// was asked to terminate and clean up before this was returned.
    Interrupted,
}

/// The isolation kinds a backend in this build implements — the
/// `run-image` pre-engine refusal gate, `plan`'s backend check, and
/// `resolve_backend` share this list so an early refusal can never
/// drift from what resolution would actually provide.
pub(crate) const IMPLEMENTED_KINDS: &[IsolationKind] =
    &[IsolationKind::Container, IsolationKind::Kata];

/// Comma-separated names of the implemented methods, for refusal
/// diagnostics.
pub(crate) fn implemented_names() -> String {
    IMPLEMENTED_KINDS
        .iter()
        .map(|k| k.name())
        .collect::<Vec<_>>()
        .join(", ")
}

/// The declared capabilities of the backend that would serve `kind` —
/// `None` when no backend in this build implements it. Callers inspect
/// the declaration without an engine instance (the pre-engine refusal
/// gate, `plan`'s `isolation.backend` check); `check` still probes the
/// real prerequisites at launch.
pub(crate) fn capabilities_for(kind: IsolationKind) -> Option<BackendCapabilities> {
    match kind {
        IsolationKind::Container => Some(oci::OCI_CAPABILITIES),
        IsolationKind::Kata => Some(kata::KATA_CAPABILITIES),
        _ => None,
    }
}

/// Whether `kind`'s backend drives a host container engine — true for
/// `container` and `kata` (`docker run --runtime kata` is an
/// engine-driven launch). Engine-backed kinds keep the engine identity
/// on the recorded execution target; an engine-less method records none.
pub(crate) fn engine_backed(kind: IsolationKind) -> bool {
    matches!(kind, IsolationKind::Container | IsolationKind::Kata)
}

/// Resolve an isolation kind to its backend on this host.
///
/// `engine` is consumed only by engine-backed kinds (the OCI container
/// path and the Kata VM path — `docker run --runtime kata` is still an
/// engine-driven launch). An unimplemented kind is an explicit refusal —
/// never a fallback to the normal container or native path.
/// `run-image`'s entry gate already refuses kinds no backend implements
/// (and kinds this host OS cannot run) before any engine work; this
/// refusal is deliberately repeated here so the contract holds for any
/// caller that reaches resolution directly.
pub fn resolve_backend(
    kind: IsolationKind,
    engine: Box<dyn ContainerEngine>,
) -> Result<Box<dyn IsolationBackend>, BackendError> {
    match kind {
        IsolationKind::Container => Ok(Box::new(OciBackend::new(engine))),
        IsolationKind::Kata => Ok(Box::new(KataBackend::new(engine))),
        other => Err(BackendError::Unsupported(format!(
            "isolation method '{}' is not implemented in this build \
             (implemented: {})",
            other.name(),
            implemented_names()
        ))),
    }
}

/// The request/observation gate: the backend's confirmed isolation must
/// equal the spec's requirement. A mismatch refuses the launch — a
/// weaker boundary is never applied in place of the requested one.
pub fn ensure_confirmed(spec: &LaunchSpec, check: &IsolationCheck) -> Result<(), BackendError> {
    if check.verified != spec.isolation {
        return Err(BackendError::IsolationMismatch {
            requested: spec.isolation.name(),
            confirmed: check.verified.name(),
        });
    }
    Ok(())
}

/// Drive one isolated session end-to-end on the host's own stdio:
/// relay stdin to the workload and its stdout back, wait for exit or a
/// Ctrl-C interruption, and release the backend's resources on every
/// path — normal exit, interruption, partial launch failure, and wait
/// errors all end in `cleanup`.
pub async fn drive_stdio_session(
    handle: &mut dyn IsolationHandle,
) -> Result<SessionEnd, BackendError> {
    drive_session_io(
        handle,
        tokio::io::stdin(),
        tokio::io::stdout(),
        tokio::signal::ctrl_c(),
    )
    .await
}

/// [`drive_stdio_session`] split for testability: `input`, `output`,
/// and `interrupt` are the host-side endpoints — production passes host
/// stdin/stdout and `tokio::signal::ctrl_c`; tests drive the same code
/// with in-memory channels and a scripted interrupt.
async fn drive_session_io<I, O, F>(
    handle: &mut dyn IsolationHandle,
    input: I,
    output: O,
    interrupt: F,
) -> Result<SessionEnd, BackendError>
where
    I: AsyncRead + Send + Unpin + 'static,
    O: AsyncWrite + Send + Unpin + 'static,
    F: Future,
{
    // Taking the pipes is part of the launch surface: when the backend
    // cannot hand them over the session fails — and still releases the
    // resources the launch created.
    let stdio = match handle.take_stdio() {
        Ok(s) => s,
        Err(e) => {
            let _ = handle.cleanup().await;
            return Err(e);
        }
    };
    let SessionStdio {
        mut stdin,
        mut stdout,
    } = stdio;

    // Host input → workload stdin. When the input ends, the write half
    // drops with the task — that drop is the workload's stdin-EOF.
    let mut input = input;
    let stdin_task = tokio::spawn(async move {
        let _ = tokio::io::copy(&mut input, &mut stdin).await;
    });
    // Workload stdout → host output.
    let mut output = output;
    let stdout_task = tokio::spawn(async move {
        let _ = tokio::io::copy(&mut stdout, &mut output).await;
    });

    enum Outcome {
        Exited(i32),
        Interrupted,
        WaitFailed(BackendError),
    }
    let outcome = tokio::select! {
        res = handle.wait_exit() => match res {
            Ok(code) => Outcome::Exited(code),
            Err(e) => Outcome::WaitFailed(e),
        },
        _ = interrupt => Outcome::Interrupted,
    };
    match outcome {
        Outcome::Exited(code) => {
            stdin_task.abort();
            // Drain whatever the workload emitted before exiting.
            let _ = stdout_task.await;
            let _ = handle.cleanup().await;
            Ok(SessionEnd::Exited(code))
        }
        Outcome::WaitFailed(e) => {
            stdin_task.abort();
            stdout_task.abort();
            let _ = handle.cleanup().await;
            Err(e)
        }
        Outcome::Interrupted => {
            stdin_task.abort();
            stdout_task.abort();
            let _ = handle.terminate().await;
            let _ = handle.cleanup().await;
            Ok(SessionEnd::Interrupted)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
    use tokio::sync::watch;

    /// The lifecycle events a scripted fake records, in order.
    type Events = Arc<Mutex<Vec<&'static str>>>;

    /// A fake backend/handle pair: the "workload" exits with `exit_code`
    /// once its stdin sees EOF (or when `terminate` is asked), writes
    /// `canned_stdout` on the stdout pipe, and records lifecycle events.
    struct FakeBackend {
        kind: IsolationKind,
        /// The isolation `check` reports as confirmed — may differ from
        /// `kind` to script a request/observation mismatch.
        confirms: IsolationKind,
        launches: Arc<AtomicUsize>,
        handle: Mutex<Option<FakeHandle>>,
    }

    struct FakeHandle {
        stdin_end: Option<DuplexStream>,
        stdout_src: Option<DuplexStream>,
        exit_rx: watch::Receiver<Option<i32>>,
        exit_tx: watch::Sender<Option<i32>>,
        events: Events,
        cleanups: Arc<AtomicUsize>,
        unit_id: Option<String>,
        fail_stdio: bool,
        fail_wait: bool,
    }

    struct FakeOpts {
        exit_code: Option<i32>,
        canned_stdout: Vec<u8>,
        unit_id: Option<String>,
        fail_stdio: bool,
        fail_wait: bool,
        /// Where the fake workload stores everything it read from stdin
        /// before exiting — lets tests observe the relayed bytes.
        stdin_sink: Option<Arc<Mutex<Vec<u8>>>>,
    }

    impl Default for FakeOpts {
        fn default() -> Self {
            Self {
                exit_code: Some(0),
                canned_stdout: Vec::new(),
                unit_id: Some("fake-unit-1".to_string()),
                fail_stdio: false,
                fail_wait: false,
                stdin_sink: None,
            }
        }
    }

    fn fake_backend(kind: IsolationKind, opts: FakeOpts) -> (FakeBackend, Events) {
        let events: Events = Arc::new(Mutex::new(Vec::new()));
        let (stdin_end, mut stdin_read) = tokio::io::duplex(1024);
        let (mut stdout_write, stdout_src) = tokio::io::duplex(1024);
        let (exit_tx, exit_rx) = watch::channel::<Option<i32>>(None);
        if let Some(code) = opts.exit_code {
            // The "workload": exits once stdin reaches EOF.
            let tx = exit_tx.clone();
            let sink = opts.stdin_sink.clone();
            tokio::spawn(async move {
                let mut buf = Vec::new();
                let _ = stdin_read.read_to_end(&mut buf).await;
                if let Some(sink) = sink {
                    *sink.lock().unwrap() = buf;
                }
                let _ = tx.send(Some(code));
            });
        }
        if !opts.canned_stdout.is_empty() {
            let canned = opts.canned_stdout.clone();
            tokio::spawn(async move {
                let _ = stdout_write.write_all(&canned).await;
                let _ = stdout_write.shutdown().await;
            });
        }
        (
            FakeBackend {
                kind,
                confirms: kind,
                launches: Arc::new(AtomicUsize::new(0)),
                handle: Mutex::new(Some(FakeHandle {
                    stdin_end: Some(stdin_end),
                    stdout_src: Some(stdout_src),
                    exit_rx,
                    exit_tx,
                    events: events.clone(),
                    cleanups: Arc::new(AtomicUsize::new(0)),
                    unit_id: opts.unit_id,
                    fail_stdio: opts.fail_stdio,
                    fail_wait: opts.fail_wait,
                })),
            },
            events,
        )
    }

    impl FakeBackend {
        fn handle(&self) -> FakeHandle {
            self.handle.lock().unwrap().take().expect("one handle")
        }
    }

    impl IsolationBackend for FakeBackend {
        fn kind(&self) -> IsolationKind {
            self.kind
        }
        fn capabilities(&self) -> BackendCapabilities {
            BackendCapabilities {
                host_os: &[TargetOs::Linux],
                guest_os: &[TargetOs::Linux],
                oci_image: false,
                argv_command: true,
                stdio_pipes: true,
                terminate: true,
                host_shares: false,
                resource_limits: false,
                observations: &["unit-id-file"],
            }
        }
        fn check<'a>(
            &'a self,
            spec: &'a LaunchSpec,
        ) -> BoxFuture<'a, Result<IsolationCheck, BackendError>> {
            Box::pin(async move {
                if spec.isolation != self.kind {
                    return Err(BackendError::Unsupported(format!(
                        "fake backend provides {} only",
                        self.kind.name()
                    )));
                }
                Ok(IsolationCheck {
                    verified: self.confirms,
                    unit: self.confirms.unit(),
                    detail: None,
                })
            })
        }
        fn launch<'a>(
            &'a self,
            _spec: &'a LaunchSpec,
        ) -> BoxFuture<'a, Result<Box<dyn IsolationHandle>, BackendError>> {
            Box::pin(async move {
                self.launches.fetch_add(1, Ordering::SeqCst);
                let handle = self
                    .handle
                    .lock()
                    .unwrap()
                    .take()
                    .expect("fake launched more than once");
                Ok(Box::new(handle) as Box<dyn IsolationHandle>)
            })
        }
    }

    impl IsolationHandle for FakeHandle {
        fn unit_id(&self) -> Option<String> {
            self.unit_id.clone()
        }
        fn take_stdio(&mut self) -> Result<SessionStdio, BackendError> {
            if self.fail_stdio {
                return Err(BackendError::LaunchFailed(
                    "fake stdio capture failed".to_string(),
                ));
            }
            Ok(SessionStdio {
                stdin: Box::new(self.stdin_end.take().expect("stdio taken once")),
                stdout: Box::new(self.stdout_src.take().expect("stdio taken once")),
            })
        }
        fn wait_exit(&mut self) -> BoxFuture<'_, Result<i32, BackendError>> {
            Box::pin(async move {
                self.events.lock().unwrap().push("wait");
                if self.fail_wait {
                    return Err(BackendError::LaunchFailed("fake wait failed".to_string()));
                }
                let mut rx = self.exit_rx.clone();
                let code = rx
                    .wait_for(|v| v.is_some())
                    .await
                    .map(|r| r.unwrap())
                    .map_err(|_| BackendError::LaunchFailed("exit channel closed".to_string()))?;
                Ok(code)
            })
        }
        fn terminate(&mut self) -> BoxFuture<'_, Result<(), BackendError>> {
            Box::pin(async move {
                self.events.lock().unwrap().push("terminate");
                let _ = self.exit_tx.send(Some(137));
                Ok(())
            })
        }
        fn cleanup(&mut self) -> BoxFuture<'_, Result<(), BackendError>> {
            Box::pin(async move {
                self.events.lock().unwrap().push("cleanup");
                self.cleanups.fetch_add(1, Ordering::SeqCst);
                Ok(())
            })
        }
    }

    fn spec_for(kind: IsolationKind) -> LaunchSpec {
        LaunchSpec {
            isolation: kind,
            image: Some("img@sha256:0".to_string()),
            guest_os: TargetOs::Linux,
            guest_arch: TargetArch::X86_64,
            shares: Vec::new(),
            env: Vec::new(),
            unit_id_file: None,
        }
    }

    // -- contract: normal exit, stdin EOF, exit code -------------------

    /// A workload that reads stdin to EOF and exits drives the session
    /// to `Exited` with its code; the driver releases the backend's
    /// resources exactly once.
    #[tokio::test]
    async fn session_exited_code_and_cleanup() {
        let (backend, events) = fake_backend(
            IsolationKind::Container,
            FakeOpts {
                exit_code: Some(42),
                ..Default::default()
            },
        );
        let mut handle = backend.handle();
        let cleanups = handle.cleanups.clone();
        // Empty host input: the relay copies nothing and the write half
        // drops — stdin-EOF is what ends the fake workload.
        let end = drive_session_io(
            &mut handle,
            tokio::io::empty(),
            Vec::new(),
            std::future::pending::<()>(),
        )
        .await
        .expect("session drives to exit");
        assert_eq!(end, SessionEnd::Exited(42));
        assert_eq!(cleanups.load(Ordering::SeqCst), 1, "cleanup runs once");
        let events = events.lock().unwrap().clone();
        assert_eq!(events.last(), Some(&"cleanup"), "events: {events:?}");
        assert_eq!(handle.unit_id().as_deref(), Some("fake-unit-1"));
    }

    /// Bytes on the host input reach the workload's stdin before EOF —
    /// the fake records what it read, and its canned stdout comes back
    /// through the output sink.
    #[tokio::test]
    async fn session_relays_stdin_bytes_and_stdout_back() {
        let stdin_sink = Arc::new(Mutex::new(Vec::new()));
        let (backend, _events) = fake_backend(
            IsolationKind::Container,
            FakeOpts {
                exit_code: Some(0),
                canned_stdout: b"workload-output".to_vec(),
                stdin_sink: Some(stdin_sink.clone()),
                ..Default::default()
            },
        );
        let mut handle = backend.handle();
        // The output sink must outlive the spawned relay task — a duplex
        // pipe stands in for host stdout.
        let (out_w, mut out_r) = tokio::io::duplex(1024);
        let end = drive_session_io(
            &mut handle,
            &b"client-input"[..],
            out_w,
            std::future::pending::<()>(),
        )
        .await
        .expect("session drives to exit");
        assert_eq!(end, SessionEnd::Exited(0));
        let mut buf = Vec::new();
        out_r.read_to_end(&mut buf).await.unwrap();
        assert_eq!(buf, b"workload-output", "stdout relayed to the sink");
        assert_eq!(
            stdin_sink.lock().unwrap().as_slice(),
            b"client-input",
            "stdin bytes reached the workload before EOF"
        );
    }

    // -- contract: interrupt / cancel ----------------------------------

    /// An interruption terminates the workload and cleans up, in that
    /// order, instead of waiting for a natural exit.
    #[tokio::test]
    async fn session_interrupt_terminates_then_cleans_up() {
        let (backend, events) = fake_backend(
            IsolationKind::Container,
            FakeOpts {
                exit_code: None, // the workload never exits on its own
                ..Default::default()
            },
        );
        let mut handle = backend.handle();
        let cleanups = handle.cleanups.clone();
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        let driver = tokio::spawn(async move {
            drive_session_io(&mut handle, tokio::io::empty(), Vec::new(), async move {
                let _ = rx.await;
            })
            .await
        });
        // Let the driver reach the wait, then interrupt.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let _ = tx.send(());
        let end = driver.await.unwrap().expect("interrupted session");
        assert_eq!(end, SessionEnd::Interrupted);
        assert_eq!(cleanups.load(Ordering::SeqCst), 1);
        let events = events.lock().unwrap().clone();
        assert_eq!(
            events,
            vec!["wait", "terminate", "cleanup"],
            "interrupt order: {events:?}"
        );
    }

    // -- contract: partial launch failure ------------------------------

    /// When the backend cannot hand over stdio, the session fails and
    /// the launch's resources are still released.
    #[tokio::test]
    async fn session_stdio_capture_failure_cleans_up() {
        let (backend, events) = fake_backend(
            IsolationKind::Container,
            FakeOpts {
                fail_stdio: true,
                ..Default::default()
            },
        );
        let mut handle = backend.handle();
        let cleanups = handle.cleanups.clone();
        let err = drive_session_io(
            &mut handle,
            tokio::io::empty(),
            Vec::new(),
            std::future::pending::<()>(),
        )
        .await
        .expect_err("stdio failure is an error");
        assert!(err.to_string().contains("stdio capture failed"));
        assert_eq!(cleanups.load(Ordering::SeqCst), 1);
        assert_eq!(events.lock().unwrap().as_slice(), ["cleanup"]);
    }

    /// A wait failure releases resources too — the session never leaves
    /// a launched unit behind.
    #[tokio::test]
    async fn session_wait_failure_cleans_up() {
        let (backend, _events) = fake_backend(
            IsolationKind::Container,
            FakeOpts {
                fail_wait: true,
                ..Default::default()
            },
        );
        let mut handle = backend.handle();
        let cleanups = handle.cleanups.clone();
        let err = drive_session_io(
            &mut handle,
            tokio::io::empty(),
            Vec::new(),
            std::future::pending::<()>(),
        )
        .await
        .expect_err("wait failure is an error");
        assert!(err.to_string().contains("fake wait failed"));
        assert_eq!(cleanups.load(Ordering::SeqCst), 1);
    }

    // -- contract: repeated termination / cleanup is tolerated ---------

    /// `terminate`/`cleanup` after a session already ended must not
    /// error — teardown is idempotent by contract.
    #[tokio::test]
    async fn repeated_cleanup_is_tolerated() {
        let (backend, _events) = fake_backend(IsolationKind::Container, FakeOpts::default());
        let mut handle = backend.handle();
        let cleanups = handle.cleanups.clone();
        let end = drive_session_io(
            &mut handle,
            tokio::io::empty(),
            Vec::new(),
            std::future::pending::<()>(),
        )
        .await
        .unwrap();
        assert_eq!(end, SessionEnd::Exited(0));
        // A second terminate/cleanup pair is a no-op, not an error.
        handle.terminate().await.unwrap();
        handle.cleanup().await.unwrap();
        handle.cleanup().await.unwrap();
        assert_eq!(cleanups.load(Ordering::SeqCst), 3);
    }

    // -- contract: request vs observation mismatch ---------------------

    /// A backend that confirms a different isolation than the spec
    /// requires is refused before launch — no degrade, no launch.
    #[tokio::test]
    async fn mismatched_confirmation_refuses_launch() {
        let (mut backend, _events) = fake_backend(IsolationKind::Container, FakeOpts::default());
        backend.confirms = IsolationKind::Container;
        let spec = spec_for(IsolationKind::Kata);
        // check() refuses a foreign kind outright.
        let err = backend.check(&spec).await.unwrap_err();
        assert!(matches!(err, BackendError::Unsupported(_)), "got: {err}");
        // And a backend that *claims* a different kind fails the gate.
        let check = IsolationCheck {
            verified: IsolationKind::Container,
            unit: IsolationUnit::Container,
            detail: None,
        };
        let err = ensure_confirmed(&spec, &check).unwrap_err();
        match err {
            BackendError::IsolationMismatch {
                requested,
                confirmed,
            } => {
                assert_eq!(requested, "kata");
                assert_eq!(confirmed, "container");
            }
            other => panic!("expected IsolationMismatch, got: {other}"),
        }
        assert_eq!(
            backend.launches.load(Ordering::SeqCst),
            0,
            "a refused check never launches"
        );
    }

    // -- resolution ----------------------------------------------------

    /// `container` and `kata` resolve to their backends; every other
    /// kind is an explicit refusal — never a silent fallback.
    #[test]
    fn resolve_backend_selects_or_refuses() {
        use crate::container::engine::BuildahEngine;
        // The engine-backed backends wrap the resolved engine.
        let backend = resolve_backend(IsolationKind::Container, Box::new(BuildahEngine))
            .expect("container resolves");
        assert_eq!(backend.kind(), IsolationKind::Container);
        let backend =
            resolve_backend(IsolationKind::Kata, Box::new(BuildahEngine)).expect("kata resolves");
        assert_eq!(backend.kind(), IsolationKind::Kata);
        for kind in [
            IsolationKind::AppleContainer,
            IsolationKind::HyperV,
            IsolationKind::WindowsSandbox,
        ] {
            let err = resolve_backend(kind, Box::new(BuildahEngine))
                .err()
                .expect("unimplemented kinds refuse");
            match err {
                BackendError::Unsupported(msg) => {
                    assert!(msg.contains(kind.name()), "got: {msg}");
                    assert!(msg.contains("not implemented"), "got: {msg}");
                }
                other => panic!("expected Unsupported for {kind:?}, got: {other}"),
            }
        }
    }
}
