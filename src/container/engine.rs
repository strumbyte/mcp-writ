use std::fmt;
use std::pin::Pin;
use std::process::Command as StdCommand;
use std::str::FromStr;

mod buildah;
mod docker;
mod podman;
#[cfg(any(test, windows))]
mod wslc;

#[cfg(test)]
mod tests;

pub use buildah::BuildahEngine;
pub use docker::DockerEngine;
pub use podman::PodmanEngine;
#[cfg(any(test, windows))]
pub use wslc::WslcEngine;

/// Type alias for boxed futures, used to support async methods on trait objects.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

// ---------------------------------------------------------------------------
// EngineError
// ---------------------------------------------------------------------------

/// Errors from container engine operations.
#[derive(Debug)]
pub enum EngineError {
    /// Container CLI command exited with a non-zero status.
    CommandFailed { engine: String, message: String },
    /// The requested operation is not supported by this engine.
    Unsupported(String),
    /// No container engine was found on PATH.
    NotFound,
    /// The engine kind string could not be parsed.
    UnknownKind(String),
    /// The specified engine CLI is not available on PATH.
    NotAvailable(String),
    /// An IO error occurred while spawning or communicating with a process.
    Io(std::io::Error),
}

impl fmt::Display for EngineError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CommandFailed { engine, message } => {
                write!(f, "{engine} command failed: {message}")
            }
            Self::Unsupported(msg) => write!(f, "unsupported operation: {msg}"),
            Self::NotFound => write!(f, "no container engine found on PATH"),
            Self::UnknownKind(s) => write!(f, "unknown engine kind: {s}"),
            Self::NotAvailable(name) => write!(f, "engine not available on PATH: {name}"),
            Self::Io(e) => write!(f, "IO error: {e}"),
        }
    }
}

impl std::error::Error for EngineError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for EngineError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

// ---------------------------------------------------------------------------
// ContainerEngine trait
// ---------------------------------------------------------------------------

/// Abstraction over container engines (Docker, Podman, Buildah, and
/// the WSL Containers `wslc` CLI on a Windows host).
///
/// Async methods return [`BoxFuture`] so the trait can be used as a trait object
/// (`Box<dyn ContainerEngine + Send + Sync>`).
pub trait ContainerEngine: Send + Sync {
    /// Human-readable engine name (e.g. `"docker"`, `"podman"`, `"buildah"`,
    /// `"wslc"`).
    fn name(&self) -> &str;

    /// The program subprocesses spawn for this engine's CLI —
    /// `name()` unless the binary resolves by path: a stock
    /// `wslc.exe` lives in the WSL install dir, not on PATH, so the
    /// wslc engine carries its resolved full path while the recorded
    /// identity stays `wslc`.
    fn program(&self) -> &str {
        self.name()
    }

    /// The unit-level signal this substrate prefers for Ctrl-C
    /// teardown before the CLI client is killed —
    /// `<engine> kill -s <signal> <unit>` runs first so the workload's
    /// own teardown (the runner's interrupted report) can still
    /// execute; a bare `rm -f` hard-kills it. `None` leaves the
    /// CLI-client kill plus `rm -f` as the whole stop path.
    fn interrupt_signal(&self) -> Option<&'static str> {
        None
    }

    /// Build a container image from a Dockerfile. `no_cache` adds the
    /// dialect's disable-cache flag (`--no-cache`). The build carries
    /// the engine's own subcommand (`build`, `bud`); the exit-code
    /// contract is each engine's own — a dialect that can exit 0 on
    /// failure (wslc) is caught by the caller's post-build `inspect`,
    /// not by this status alone.
    fn build<'a>(
        &'a self,
        dockerfile_path: &'a str,
        tag: &'a str,
        context_dir: &'a str,
        no_cache: bool,
    ) -> BoxFuture<'a, Result<(), EngineError>>;

    /// Inspect a container image, returning the raw JSON output.
    fn inspect<'a>(&'a self, image: &'a str) -> BoxFuture<'a, Result<String, EngineError>>;

    /// Tag `source` as `target` — an additional reference to the same
    /// image (each engine's `tag`/`image tag` dialect). `build_image`
    /// builds under a unique temporary tag and only associates the
    /// verified product with the requested tag through this call.
    fn tag<'a>(
        &'a self,
        source: &'a str,
        target: &'a str,
    ) -> BoxFuture<'a, Result<(), EngineError>>;

    /// Remove the `image` reference — an untag when other names still
    /// point at the same image (each engine's `rm`/`rmi`/`image rm`
    /// dialect). `build_image` drops its temporary tag through it.
    /// Implementations must confirm the removal fact — see
    /// [`confirm_image_removed`]: an exit-0 `rm` is the engine having
    /// accepted the request, not the reference being gone.
    fn remove_image<'a>(&'a self, image: &'a str) -> BoxFuture<'a, Result<(), EngineError>>;

    /// Engine daemon info as raw JSON (`<cli> info`) — used to record the
    /// substrate OS the container actually runs on and to spot remote
    /// endpoints before host paths are bind-mounted.
    fn info<'a>(&'a self) -> BoxFuture<'a, Result<String, EngineError>>;

    /// Run a container from an image. When `stdin_pipe` is `true`, stdin is piped
    /// so the caller can write to it.
    fn run<'a>(
        &'a self,
        image: &'a str,
        args: &'a [&'a str],
        stdin_pipe: bool,
    ) -> BoxFuture<'a, Result<tokio::process::Child, EngineError>>;

    /// Check whether the engine CLI binary exists on PATH.
    fn is_available(&self) -> bool;
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

/// The removal fact after an `rm` dialect exited 0 — `inspect` no
/// longer resolving the reference. An exit-0 `rm` is the engine having
/// *accepted* the delete, not the reference being gone (the same
/// fake-success dialect `build` already guards against): a reference
/// that still resolves after a reported-success removal is a removal
/// failure, not silent success.
///
/// Only an `inspect` error carrying a not-found marker confirms
/// removal — a CLI launch failure, daemon connection error, or any
/// unanswerable `inspect` propagates because it proves nothing about
/// the reference. A bare-object answer (buildah) resolves; an array
/// answer resolves only when non-empty (wslc answers `[]` for an
/// absent tag at exit 0). An unparseable answer is treated as
/// resolving — an engine whose inspect cannot be understood cannot be
/// trusted to have deleted anything.
pub(crate) async fn confirm_image_removed(
    engine: &dyn ContainerEngine,
    image: &str,
) -> Result<(), EngineError> {
    match engine.inspect(image).await {
        Err(EngineError::CommandFailed { ref message, .. })
            if crate::container::common::inspect_error_is_absent(message) =>
        {
            Ok(())
        }
        Err(e) => Err(e),
        Ok(json) => {
            let resolves = nojson::RawJson::parse(&json)
                .ok()
                .map(|j| match j.value().to_array() {
                    Ok(mut arr) => arr.next().is_some(),
                    Err(_) => true,
                })
                .unwrap_or(true);
            if resolves {
                Err(EngineError::CommandFailed {
                    engine: engine.name().into(),
                    message: format!("image rm reported success but '{image}' still resolves"),
                })
            } else {
                Ok(())
            }
        }
    }
}

/// Arguments passed to `docker`/`podman run`, excluding the engine binary name.
///
/// Production `spawn_container_run` uses this sequence. Tests should call this
/// helper rather than copying the argument list. The `--entrypoint` override
/// is *not* part of this prefix — the guest contract's runner path differs
/// per guest OS, so the spec options carry it (see
/// [`crate::container::backends::oci::spec_run_options`]).
pub(crate) fn container_run_args(options: &[String], image: &str) -> Vec<String> {
    container_run_args_ext(&[], options, image)
}

/// [`container_run_args`] with engine-specific hardening flags spliced
/// into the launch prefix right after `--no-healthcheck` — the way an
/// engine whose `run` dialect needs extra pins expresses them (wslc
/// adds `--pull never` and an owned `--name` there).
pub(crate) fn container_run_args_ext(
    extra_prefix: &[String],
    options: &[String],
    image: &str,
) -> Vec<String> {
    let mut args = vec![
        "run".to_string(),
        "-i".to_string(),
        "--rm".to_string(),
        "--no-healthcheck".to_string(),
    ];
    args.extend(extra_prefix.iter().cloned());
    args.extend([
        "-e".to_string(),
        "MCP_WRIT_ENV=".to_string(),
        "-e".to_string(),
        "MCP_WRIT_SKIP_SANDBOX=".to_string(),
        "-e".to_string(),
        "MCP_WRIT_SERVER=".to_string(),
        // Clear an image-baked fail-on override: the runner resolves its
        // startup-failure policy from the process environment, so a baked
        // `MCP_WRIT_FAIL_ON=none` would silently disable the checks.
        "-e".to_string(),
        "MCP_WRIT_FAIL_ON=".to_string(),
        // Clear an image-baked launch correlation ID: a guest audit event
        // must correlate with the host launch that spawned it, never with
        // a value baked into the image (an explicit `-e` in `options`
        // re-sets it for `--report` launches).
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
    ]);
    // The guest-contract channel paths (policy mount, audit dir, workload
    // temp) are channel vars too — a baked value could redirect the runner
    // to a hostile in-image path, so every launch clears them; `options`
    // re-sets the mount-backed values.
    for var in [
        crate::container::guest_layout::LINUX.policy_path_env,
        crate::container::guest_layout::LINUX.audit_dir_env,
        crate::container::guest_layout::LINUX.temp_dir_env,
    ] {
        args.push("-e".to_string());
        args.push(format!("{var}="));
    }
    args.extend(options.iter().cloned());
    args.push(image.to_string());
    args
}

/// Shared implementation for `ContainerEngine::run` used by Docker and Podman.
fn spawn_container_run<'a>(
    engine_cmd: &'static str,
    image: &'a str,
    options: &'a [&'a str],
    stdin_pipe: bool,
) -> BoxFuture<'a, Result<tokio::process::Child, EngineError>> {
    Box::pin(async move {
        let option_owned: Vec<String> = options.iter().map(|s| (*s).to_string()).collect();
        let args = container_run_args(&option_owned, image);
        let mut cmd = tokio::process::Command::new(engine_cmd);
        cmd.args(&args);
        if stdin_pipe {
            cmd.stdin(std::process::Stdio::piped());
        }
        cmd.stdout(std::process::Stdio::piped());
        cmd.stderr(std::process::Stdio::inherit());
        Ok(cmd.spawn()?)
    })
}

/// `<cli> info` raw JSON shared by the engine implementations.
///
/// `format` selects the JSON output mode where the CLI needs one —
/// docker takes a Go template (`--format '{{json .}}'`), podman accepts
/// the `json` keyword. `None` passes no flag: `buildah info` already
/// emits JSON by default, and its `--format` requires a `{{...}}` Go
/// template — a bare `json` keyword is rejected as "invalid format".
/// Callers parse the result with [`engine_info_os`] or kata's runtime
/// probe, so a plain-text `info` answer is unusable here.
async fn run_info(engine_cmd: &str, format: Option<&str>) -> Result<String, EngineError> {
    let mut cmd = tokio::process::Command::new(engine_cmd);
    cmd.arg("info");
    if let Some(format) = format {
        cmd.args(["--format", format]);
    }
    // A caller timeout drops this future — the spawned CLI must die
    // with it rather than leaking as an orphan.
    cmd.kill_on_drop(true);
    let output = cmd.output().await?;
    let text = String::from_utf8_lossy(&output.stdout).into_owned();
    // The exit code alone is not the success fact — wslc reports CLI
    // errors with a 0 exit — so a non-JSON answer fails here the same
    // way a nonzero exit does, quoting whichever stream complained.
    if !output.status.success() || !text.trim_start().starts_with('{') {
        let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
        return Err(EngineError::CommandFailed {
            engine: engine_cmd.into(),
            message: if stderr.trim().is_empty() {
                text.trim().to_string()
            } else {
                stderr
            },
        });
    }
    Ok(text)
}

/// The `<engine> <subcmd> -f <dockerfile> -t <tag> [--no-cache] <ctx>`
/// argv — the OCI build dialect docker/podman/wslc share; buildah
/// passes `bud` for `subcmd`. `--no-cache` sits after the tag, before
/// the context dir, matching the production build line.
fn image_build_args(
    subcmd: &str,
    dockerfile_path: &str,
    tag: &str,
    context_dir: &str,
    no_cache: bool,
) -> Vec<String> {
    let mut args = vec![
        subcmd.to_string(),
        "-f".to_string(),
        dockerfile_path.to_string(),
        "-t".to_string(),
        tag.to_string(),
    ];
    if no_cache {
        args.push("--no-cache".to_string());
    }
    args.push(context_dir.to_string());
    args
}

/// `<cli> <args…>` shared by the engine `build`/`tag`/`remove_image`
/// implementations — `cli` is the spawned program (a resolved path
/// when the binary is not on PATH), `name` the engine identity error
/// text reports. A nonzero exit is `CommandFailed` quoting stderr;
/// engines whose CLI can exit 0 on a failed command (wslc) are the
/// caller's problem — verify with `inspect`.
async fn run_cli_args<S: AsRef<str>>(cli: &str, name: &str, args: &[S]) -> Result<(), EngineError> {
    let mut cmd = tokio::process::Command::new(cli);
    cmd.args(args.iter().map(|a| a.as_ref()));
    cmd.stdin(std::process::Stdio::null());
    // A caller timeout drops this future — the spawned CLI must die
    // with it rather than leaking as an orphan.
    cmd.kill_on_drop(true);
    let output = cmd.output().await?;
    if !output.status.success() {
        return Err(EngineError::CommandFailed {
            engine: name.into(),
            message: String::from_utf8_lossy(&output.stderr).into_owned(),
        });
    }
    Ok(())
}

/// `<cli> <subcmd> -f <dockerfile> -t <tag> [--no-cache] <ctx>` shared
/// by the engine `build` implementations.
async fn run_image_build(
    cli: &str,
    name: &str,
    subcmd: &str,
    dockerfile_path: &str,
    tag: &str,
    context_dir: &str,
    no_cache: bool,
) -> Result<(), EngineError> {
    run_cli_args(
        cli,
        name,
        &image_build_args(subcmd, dockerfile_path, tag, context_dir, no_cache),
    )
    .await
}

/// Bound on a synchronous engine-CLI probe — `resolve_engine` and
/// `is_available` are sync callers, so the probe polls `try_wait`
/// instead of awaiting; a wedged CLI is killed rather than stalling
/// `run-image`/`plan`/`wrap-image` past the deadline. The budget is
/// the `plan` diagnostics layer's probe timeout.
const CLI_PROBE_TIMEOUT: std::time::Duration = crate::container::windows_probe::PROBE_TIMEOUT;

/// Per-stream output cap for a synchronous probe — a `--version`
/// answer is a line; anything past this is a flood, not a fact.
const CLI_PROBE_OUTPUT_CAP: u64 = 64 * 1024;

/// Drain a piped child stream on a reader thread — the synchronous
/// counterpart of `run_probe`'s joined read futures. The collected
/// bytes arrive on the returned channel once the pipe hits EOF (or the
/// cap); a descendant that inherited and still holds the write end
/// leaves the reader blocked, which is why collection after the
/// child's exit stays deadline-bounded rather than joining.
fn drain_pipe(
    pipe: Option<impl std::io::Read + Send + 'static>,
) -> std::sync::mpsc::Receiver<Vec<u8>> {
    use std::io::Read;
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut buf = Vec::new();
        if let Some(s) = pipe {
            let _ = s.take(CLI_PROBE_OUTPUT_CAP).read_to_end(&mut buf);
        }
        let _ = tx.send(buf);
    });
    rx
}

/// `prog args` with a bounded wait and capped stream reads — the
/// synchronous counterpart of
/// [`crate::container::windows_probe::run_probe`] for the engine
/// resolution paths that cannot await. Both pipes drain concurrently
/// while the child runs; on timeout the child is killed and reaped;
/// on exit the collected output is received within the same deadline —
/// a descendant holding a pipe open can never park the probe.
pub(crate) fn bounded_cli_output(
    prog: &str,
    args: &[&str],
) -> std::io::Result<std::process::Output> {
    let mut cmd = StdCommand::new(prog);
    cmd.args(args)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(0x08000000); // CREATE_NO_WINDOW — a
        // console-attached probe must not pop a window.
    }
    let mut child = cmd.spawn()?;
    let out_rx = drain_pipe(child.stdout.take());
    let err_rx = drain_pipe(child.stderr.take());
    let deadline = std::time::Instant::now() + CLI_PROBE_TIMEOUT;
    let status = loop {
        match child.try_wait()? {
            Some(status) => break status,
            None if std::time::Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    format!("no answer within {}s", CLI_PROBE_TIMEOUT.as_secs()),
                ));
            }
            None => std::thread::sleep(std::time::Duration::from_millis(25)),
        }
    };
    // The child exited; the readers finish on pipe EOF. A descendant
    // still holding a write end must not park collection past the
    // deadline — a pipe that never closes is the same "no answer".
    let collect = |rx: std::sync::mpsc::Receiver<Vec<u8>>| -> std::io::Result<Vec<u8>> {
        match rx.recv_timeout(deadline.saturating_duration_since(std::time::Instant::now())) {
            Ok(buf) => Ok(buf),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                format!(
                    "pipe held open past the {}s deadline",
                    CLI_PROBE_TIMEOUT.as_secs()
                ),
            )),
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                Err(std::io::Error::other("pipe reader died"))
            }
        }
    };
    Ok(std::process::Output {
        status,
        stdout: collect(out_rx)?,
        stderr: collect(err_rx)?,
    })
}

/// The engine host's OS from `<cli> info` JSON: Docker's top-level
/// `OSType`, Podman/Buildah `host.os`. For Apple's `container` CLI the
/// "info" JSON is `container system status --format json` — the
/// substrate is per-unit Linux VMs whenever the response carries the
/// service `status` field (running-state is gated separately by the
/// backend's own probe). `None` when the field is absent or names no
/// known target — never silently claims the CLI host's OS.
pub fn engine_info_os(engine_name: &str, info_json: &str) -> Option<crate::execution::TargetOs> {
    let json = nojson::RawJson::parse(info_json).ok()?;
    let root = json.value();
    let raw = match engine_name {
        "docker" => root
            .to_member("OSType")
            .ok()
            .and_then(|m| m.optional())
            .and_then(|v| v.to_unquoted_string_str().ok())
            .map(|s| s.into_owned()),
        "podman" | "buildah" => root
            .to_member("host")
            .ok()
            .and_then(|m| m.optional())
            .and_then(|h| {
                h.to_member("os")
                    .ok()
                    .and_then(|m| m.optional())
                    .and_then(|v| v.to_unquoted_string_str().ok())
                    .map(|s| s.into_owned())
            }),
        // The `container` substrate runs one Linux VM per unit — the
        // workload OS is Linux by construction; the `status` member is
        // just proof the response is Apple's service record, not an
        // unrelated JSON blob a foreign CLI of the same name produced.
        "container" => root
            .to_member("status")
            .ok()
            .and_then(|m| m.optional())
            .and_then(|v| v.to_unquoted_string_str().ok())
            .map(|_| "linux".to_string()),
        // `wslc info --format json` answers `{Client:{…}, Server:{…}}` —
        // the workload is a Linux container in the shared session VM by
        // construction; `Server.SessionManagerVersion` is proof the
        // answer is the wslc session manager, not a foreign blob.
        "wslc" => root
            .to_member("Server")
            .ok()
            .and_then(|m| m.optional())
            .and_then(|s| {
                s.to_member("SessionManagerVersion")
                    .ok()
                    .and_then(|m| m.optional())
            })
            .map(|_| "linux".to_string()),
        _ => None,
    }?;
    crate::execution::TargetOs::parse(&raw).ok()
}

/// Check that `engine` is available on PATH, returning it boxed or
/// [`EngineError::NotAvailable`] if the CLI cannot be found.
pub(crate) fn try_engine(
    engine: impl ContainerEngine + 'static,
) -> Result<Box<dyn ContainerEngine>, EngineError> {
    if !engine.is_available() {
        return Err(EngineError::NotAvailable(engine.name().to_string()));
    }
    Ok(Box::new(engine))
}

// ---------------------------------------------------------------------------
// EngineKind
// ---------------------------------------------------------------------------

/// Enumeration of supported container engine kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EngineKind {
    Docker,
    Podman,
    Buildah,
    /// WSL Containers (`wslc.exe`) — the WSL-session container driver on
    /// Windows hosts, explicit `--engine wslc` selection only: never in
    /// [`detect_engine`]'s auto-pick order and never a substitute for a
    /// `hyperv` or native request. The validated contract is the wslc
    /// 3.0.x line (≥ 3.0.1) on a Windows x86-64 host running a
    /// linux/amd64 guest in the shared session VM.
    Wslc,
}

impl FromStr for EngineKind {
    type Err = EngineError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "docker" => Ok(Self::Docker),
            "podman" => Ok(Self::Podman),
            "buildah" => Ok(Self::Buildah),
            // The CLI the substrate exposes is `wslc.exe`; its
            // `container.exe` alias is intentionally *not* accepted —
            // that name belongs to Apple's substrate driver, and
            // equating the two by name would mislabel the boundary.
            "wslc" => Ok(Self::Wslc),
            _ => Err(EngineError::UnknownKind(s.to_string())),
        }
    }
}

/// Conversion to the leaf engine identity carried by
/// [`crate::execution::ExecutionTarget`]. Keeping it here is what lets
/// `execution` stay a layer-0 module with no `container` dependency.
impl From<EngineKind> for crate::execution::EngineName {
    fn from(kind: EngineKind) -> Self {
        match kind {
            EngineKind::Docker => Self::Docker,
            EngineKind::Podman => Self::Podman,
            EngineKind::Buildah => Self::Buildah,
            EngineKind::Wslc => Self::Wslc,
        }
    }
}

// ---------------------------------------------------------------------------
// detect_engine / resolve_engine
// ---------------------------------------------------------------------------

/// Detect the first available container engine on PATH.
///
/// Checks in order: docker → podman → buildah. `wslc` is deliberately
/// absent — it is an explicit `--engine wslc` choice on a Windows host
/// (validated line pinned at resolve), never an implicit substitute.
pub fn detect_engine() -> Option<Box<dyn ContainerEngine>> {
    let candidates: [Box<dyn ContainerEngine>; 3] = [
        Box::new(DockerEngine),
        Box::new(PodmanEngine),
        Box::new(BuildahEngine),
    ];
    candidates.into_iter().find(|engine| engine.is_available())
}

/// Resolve a container engine by explicit kind, or auto-detect if `None`.
///
/// When a specific kind is requested, verifies that the CLI is available on PATH
/// before returning the engine. Returns [`EngineError::NotAvailable`] if not found.
pub fn resolve_engine(kind: Option<EngineKind>) -> Result<Box<dyn ContainerEngine>, EngineError> {
    match kind {
        None => detect_engine().ok_or(EngineError::NotFound),
        Some(EngineKind::Docker) => try_engine(DockerEngine),
        Some(EngineKind::Podman) => try_engine(PodmanEngine),
        Some(EngineKind::Buildah) => try_engine(BuildahEngine),
        Some(EngineKind::Wslc) => wslc_engine(),
    }
}

/// The WSL Containers engine — Windows-host only: the Store-WSL CLI
/// runs on Windows. Test builds keep the resolver on every host so
/// fixtures (`MCP_WRIT_WSLC_EXE`) exercise the whole engine; a
/// production non-Windows host gets a clean unsupported refusal —
/// never a different engine substituted.
#[cfg(any(test, windows))]
fn wslc_engine() -> Result<Box<dyn ContainerEngine>, EngineError> {
    WslcEngine::new().map(|e| Box::new(e) as Box<dyn ContainerEngine>)
}

/// See the Windows arm — an off-Windows production host has no wslc
/// launch path at all.
#[cfg(not(any(test, windows)))]
fn wslc_engine() -> Result<Box<dyn ContainerEngine>, EngineError> {
    Err(EngineError::Unsupported(
        "engine 'wslc' (WSL Containers) requires a Windows host".to_string(),
    ))
}
