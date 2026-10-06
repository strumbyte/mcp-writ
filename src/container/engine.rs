use std::fmt;
use std::pin::Pin;
use std::process::Command as StdCommand;
use std::str::FromStr;

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

/// Abstraction over container engines (Docker, Podman, Buildah).
///
/// Async methods return [`BoxFuture`] so the trait can be used as a trait object
/// (`Box<dyn ContainerEngine + Send + Sync>`).
pub trait ContainerEngine: Send + Sync {
    /// Human-readable engine name (e.g. `"docker"`, `"podman"`, `"buildah"`).
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

    /// Build a container image from a Dockerfile.
    fn build<'a>(
        &'a self,
        dockerfile_path: &'a str,
        tag: &'a str,
        context_dir: &'a str,
    ) -> BoxFuture<'a, Result<(), EngineError>>;

    /// Inspect a container image, returning the raw JSON output.
    fn inspect<'a>(&'a self, image: &'a str) -> BoxFuture<'a, Result<String, EngineError>>;

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
// DockerEngine
// ---------------------------------------------------------------------------

pub struct DockerEngine;

impl ContainerEngine for DockerEngine {
    fn name(&self) -> &str {
        "docker"
    }

    fn build<'a>(
        &'a self,
        dockerfile_path: &'a str,
        tag: &'a str,
        context_dir: &'a str,
    ) -> BoxFuture<'a, Result<(), EngineError>> {
        Box::pin(async move {
            let output = tokio::process::Command::new("docker")
                .args(["build", "-f", dockerfile_path, "-t", tag, context_dir])
                .output()
                .await?;
            if !output.status.success() {
                return Err(EngineError::CommandFailed {
                    engine: "docker".into(),
                    message: String::from_utf8_lossy(&output.stderr).into_owned(),
                });
            }
            Ok(())
        })
    }

    fn inspect<'a>(&'a self, image: &'a str) -> BoxFuture<'a, Result<String, EngineError>> {
        Box::pin(async move {
            let mut cmd = tokio::process::Command::new("docker");
            cmd.args(["image", "inspect", image]);
            // A caller timeout drops this future — the spawned CLI must
            // die with it rather than leaking as an orphan.
            cmd.kill_on_drop(true);
            let output = cmd.output().await?;
            if !output.status.success() {
                return Err(EngineError::CommandFailed {
                    engine: "docker".into(),
                    message: String::from_utf8_lossy(&output.stderr).into_owned(),
                });
            }
            Ok(String::from_utf8_lossy(&output.stdout).into_owned())
        })
    }

    fn info<'a>(&'a self) -> BoxFuture<'a, Result<String, EngineError>> {
        Box::pin(async move { run_info("docker", Some("{{json .}}")).await })
    }

    fn run<'a>(
        &'a self,
        image: &'a str,
        args: &'a [&'a str],
        stdin_pipe: bool,
    ) -> BoxFuture<'a, Result<tokio::process::Child, EngineError>> {
        spawn_container_run("docker", image, args, stdin_pipe)
    }

    fn is_available(&self) -> bool {
        StdCommand::new("docker")
            .arg("--version")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }
}

// ---------------------------------------------------------------------------
// PodmanEngine
// ---------------------------------------------------------------------------

pub struct PodmanEngine;

impl ContainerEngine for PodmanEngine {
    fn name(&self) -> &str {
        "podman"
    }

    fn build<'a>(
        &'a self,
        dockerfile_path: &'a str,
        tag: &'a str,
        context_dir: &'a str,
    ) -> BoxFuture<'a, Result<(), EngineError>> {
        Box::pin(async move {
            let output = tokio::process::Command::new("podman")
                .args(["build", "-f", dockerfile_path, "-t", tag, context_dir])
                .output()
                .await?;
            if !output.status.success() {
                return Err(EngineError::CommandFailed {
                    engine: "podman".into(),
                    message: String::from_utf8_lossy(&output.stderr).into_owned(),
                });
            }
            Ok(())
        })
    }

    fn inspect<'a>(&'a self, image: &'a str) -> BoxFuture<'a, Result<String, EngineError>> {
        Box::pin(async move {
            let mut cmd = tokio::process::Command::new("podman");
            cmd.args(["image", "inspect", image]);
            // A caller timeout drops this future — the spawned CLI must
            // die with it rather than leaking as an orphan.
            cmd.kill_on_drop(true);
            let output = cmd.output().await?;
            if !output.status.success() {
                return Err(EngineError::CommandFailed {
                    engine: "podman".into(),
                    message: String::from_utf8_lossy(&output.stderr).into_owned(),
                });
            }
            Ok(String::from_utf8_lossy(&output.stdout).into_owned())
        })
    }

    fn info<'a>(&'a self) -> BoxFuture<'a, Result<String, EngineError>> {
        Box::pin(async move { run_info("podman", Some("json")).await })
    }

    fn run<'a>(
        &'a self,
        image: &'a str,
        args: &'a [&'a str],
        stdin_pipe: bool,
    ) -> BoxFuture<'a, Result<tokio::process::Child, EngineError>> {
        spawn_container_run("podman", image, args, stdin_pipe)
    }

    fn is_available(&self) -> bool {
        StdCommand::new("podman")
            .arg("--version")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }
}

// ---------------------------------------------------------------------------
// BuildahEngine
// ---------------------------------------------------------------------------

pub struct BuildahEngine;

impl ContainerEngine for BuildahEngine {
    fn name(&self) -> &str {
        "buildah"
    }

    fn build<'a>(
        &'a self,
        dockerfile_path: &'a str,
        tag: &'a str,
        context_dir: &'a str,
    ) -> BoxFuture<'a, Result<(), EngineError>> {
        Box::pin(async move {
            let output = tokio::process::Command::new("buildah")
                .args(["bud", "-f", dockerfile_path, "-t", tag, context_dir])
                .output()
                .await?;
            if !output.status.success() {
                return Err(EngineError::CommandFailed {
                    engine: "buildah".into(),
                    message: String::from_utf8_lossy(&output.stderr).into_owned(),
                });
            }
            Ok(())
        })
    }

    fn inspect<'a>(&'a self, image: &'a str) -> BoxFuture<'a, Result<String, EngineError>> {
        Box::pin(async move {
            let output = tokio::process::Command::new("buildah")
                .args(["inspect", "--type=image", image])
                .output()
                .await?;
            if !output.status.success() {
                return Err(EngineError::CommandFailed {
                    engine: "buildah".into(),
                    message: String::from_utf8_lossy(&output.stderr).into_owned(),
                });
            }
            Ok(String::from_utf8_lossy(&output.stdout).into_owned())
        })
    }

    fn info<'a>(&'a self) -> BoxFuture<'a, Result<String, EngineError>> {
        Box::pin(async move { run_info("buildah", None).await })
    }

    fn run<'a>(
        &'a self,
        _image: &'a str,
        _args: &'a [&'a str],
        _stdin_pipe: bool,
    ) -> BoxFuture<'a, Result<tokio::process::Child, EngineError>> {
        Box::pin(async move {
            Err(EngineError::Unsupported(
                "buildah does not support 'run' for container execution".into(),
            ))
        })
    }

    fn is_available(&self) -> bool {
        StdCommand::new("buildah")
            .arg("--version")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }
}

// ---------------------------------------------------------------------------
// WslcEngine — WSL Containers (`wslc.exe`) on a Windows host
// ---------------------------------------------------------------------------

/// The WSL Containers engine — the `wslc.exe` CLI shipped inside Store
/// WSL (the substrate PR-28 validated and PR-29 wires into the launch
/// path). Units are Linux containers inside the shared wslc session
/// VM; the CLI dialect differs from docker's where it matters:
///
/// - A stock install drops `wslc.exe` under `%ProgramFiles%\WSL`
///   without exporting it to PATH, so subprocesses spawn the resolved
///   full path ([`Self::program`]) while the recorded engine identity
///   stays `wslc`.
/// - `run` carries `--pull never` — the launch already inspected the
///   image, a launch never fetches, and pull progress on stdout would
///   corrupt the MCP wire — plus an owned `--name` so `wslc list`
///   shows the unit as ours (an orphaned unit stays attributable).
/// - A `wslc` CLI error can exit 0, so success is read from the
///   answer's shape (`inspect`/`info` must parse as their JSON
///   contract) and the spawned session's behavior — never from the
///   exit code alone.
/// - The first `wslc run` materializes the session VM and can print
///   provisioning progress on stdout; a bounded throwaway warm-up run
///   absorbs that chatter before the real launch's pipe is live.
/// - Ctrl-C teardown signals the unit first (`wslc kill -s SIGINT`) so
///   the runner's interrupted-report unwind executes before the CLI
///   client is killed and the unit `rm -f`'d — the unit outlives its
///   CLI client, so kill-the-client alone is not a stop.
///
/// Resolution is explicit-only: `wslc` never enters
/// [`detect_engine`]'s auto-pick order, never substitutes for a
/// `hyperv` or native request, and the validated line (wslc 3.0.x ≥
/// 3.0.1) is pinned at resolve — anything else refuses.
#[cfg(any(test, windows))]
pub struct WslcEngine {
    /// The resolved `wslc.exe`, spawned by full path.
    exe: String,
}

#[cfg(any(test, windows))]
impl WslcEngine {
    /// Resolve `wslc.exe` (fixture override → PATH → the WSL install
    /// dir) and pin it to the validated 3.0.x line. An absent binary,
    /// an unanswerable `--version`, and a version off the validated
    /// line each refuse distinctly — never a silent substitute for
    /// another engine.
    pub fn new() -> Result<Self, EngineError> {
        use crate::container::windows_probe as probe;
        let exe = probe::find_wslc().ok_or_else(|| {
            EngineError::NotAvailable(
                "wslc (wslc.exe not found — WSL Containers ships inside \
                 Store WSL ≥ 2.9.3; install or update WSL and retry — \
                 mcp-writ never installs or updates it)"
                    .to_string(),
            )
        })?;
        let engine = Self {
            exe: exe.to_string_lossy().into_owned(),
        };
        let version = engine.probe_version()?;
        if !probe::wslc_version_supported(version) {
            let m = probe::WSLC_VALIDATED_MAJOR;
            let n = probe::WSLC_VALIDATED_MINOR;
            let p = probe::WSLC_VALIDATED_PATCH;
            return Err(EngineError::Unsupported(format!(
                "wslc {}.{}.{} is outside the validated {m}.{n}.x line \
                 (≥ {m}.{n}.{p}) — the run/stdio/session contract was \
                 verified on wslc {m}.{n}.{p}; a newer or older CLI \
                 needs its own verification before it launches",
                version.0, version.1, version.2,
            )));
        }
        Ok(engine)
    }

    /// Test constructor — bypasses resolution and the version gate so
    /// backend tests can construct a wslc-shaped engine.
    #[cfg(test)]
    pub(crate) fn for_test(exe: &str) -> Self {
        Self {
            exe: exe.to_string(),
        }
    }

    /// `wslc --version` → `(major, minor, patch)`. A plain sync spawn —
    /// `resolve_engine` is sync, and the answer is a local version
    /// string (no session contact).
    fn probe_version(&self) -> Result<(u64, u64, u64), EngineError> {
        use crate::container::windows_probe as probe;
        let output = StdCommand::new(&self.exe)
            .arg("--version")
            .stdin(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped())
            .output()
            .map_err(|e| EngineError::CommandFailed {
                engine: "wslc".into(),
                message: format!("`--version` spawn failed: {e}"),
            })?;
        if !output.status.success() {
            return Err(EngineError::CommandFailed {
                engine: "wslc".into(),
                message: format!(
                    "`--version` exited {}: {}",
                    output.status,
                    probe::abbreviate(String::from_utf8_lossy(&output.stderr).trim(), 200)
                ),
            });
        }
        let text = probe::decode_cli_text(&output.stdout);
        probe::parse_wslc_version(&text).ok_or_else(|| {
            let m = probe::WSLC_VALIDATED_MAJOR;
            let n = probe::WSLC_VALIDATED_MINOR;
            let p = probe::WSLC_VALIDATED_PATCH;
            EngineError::Unsupported(format!(
                "wslc --version answered an unrecognized format: '{}' — \
                 the validated line is {m}.{n}.x (≥ {m}.{n}.{p})",
                probe::abbreviate(text.trim(), 120)
            ))
        })
    }

    /// Whether `wslc system session list` already shows the CLI-owned
    /// session (`wslc-cli-*`) `wslc run` auto-creates — the bounded
    /// read-only probe; a failed probe reads as absent, since warming
    /// is cheap and hides nothing.
    async fn default_session_listed(&self) -> bool {
        matches!(
            crate::container::windows_probe::run_probe(
                std::path::Path::new(&self.exe),
                &["system", "session", "list"]
            )
            .await,
            crate::container::windows_probe::ProbeOutcome::Answered(text)
                if text.lines().any(|l| l.contains("wslc-cli-"))
        )
    }

    /// The first `wslc run` on a host materializes the default session
    /// VM and can print provisioning progress on **stdout** — the MCP
    /// wire on a real launch. When no CLI session is listed yet, a
    /// bounded throwaway run absorbs that chatter; its streams are
    /// discarded and `--rm` leaves nothing behind. A warm-up failure is
    /// not fatal — the real launch surfaces its own errors.
    async fn warm_session(&self, image: &str) {
        if self.default_session_listed().await {
            return;
        }
        // A UUID name like the launch path's — the same process can warm
        // again after the session VM dropped, and a leftover unit with a
        // reused pid name would collide. A timed-out client is killed by
        // kill_on_drop, but the unit outlives its CLI client (measured):
        // `rm -f` by the recorded name reaps one that materialized.
        let warm_name = format!(
            "mcp-writ-wslc-warm-{}",
            &uuid::Uuid::now_v7().simple().to_string()[..12]
        );
        let warm = tokio::process::Command::new(&self.exe)
            .args([
                "run",
                "--rm",
                "--pull",
                "never",
                "--name",
                &warm_name,
                "--entrypoint",
                "/bin/true",
                image,
            ])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .kill_on_drop(true)
            .output();
        if tokio::time::timeout(std::time::Duration::from_secs(60), warm)
            .await
            .is_err()
        {
            let rm = tokio::process::Command::new(&self.exe)
                .args(["rm", "-f", &warm_name])
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .kill_on_drop(true)
                .output();
            let _ = tokio::time::timeout(std::time::Duration::from_secs(30), rm).await;
        }
    }
}

#[cfg(any(test, windows))]
impl ContainerEngine for WslcEngine {
    fn name(&self) -> &str {
        "wslc"
    }

    fn program(&self) -> &str {
        &self.exe
    }

    fn interrupt_signal(&self) -> Option<&'static str> {
        // The unit outlives its CLI client — Ctrl-C teardown sends
        // `wslc kill -s SIGINT <unit>` first so the runner's
        // interrupted-report unwind runs before the client is killed
        // and the unit removed (verified in PR-28: SIGINT → exit 130,
        // report written, unit reaped).
        Some("SIGINT")
    }

    fn build<'a>(
        &'a self,
        dockerfile_path: &'a str,
        tag: &'a str,
        context_dir: &'a str,
    ) -> BoxFuture<'a, Result<(), EngineError>> {
        Box::pin(async move {
            let output = tokio::process::Command::new(&self.exe)
                .args(["build", "-f", dockerfile_path, "-t", tag, context_dir])
                .output()
                .await?;
            if !output.status.success() {
                return Err(EngineError::CommandFailed {
                    engine: "wslc".into(),
                    message: String::from_utf8_lossy(&output.stderr).into_owned(),
                });
            }
            Ok(())
        })
    }

    fn inspect<'a>(&'a self, image: &'a str) -> BoxFuture<'a, Result<String, EngineError>> {
        Box::pin(async move {
            let mut cmd = tokio::process::Command::new(&self.exe);
            cmd.args(["image", "inspect", image]);
            // A caller timeout drops this future — the spawned CLI must
            // die with it rather than leaking as an orphan.
            cmd.kill_on_drop(true);
            let output = cmd.output().await?;
            let text = String::from_utf8_lossy(&output.stdout).into_owned();
            // wslc can print a CLI error and still exit 0 — the docker-
            // shaped JSON array is the success fact, the exit code is
            // not trusted alone.
            if !output.status.success() || !text.trim_start().starts_with('[') {
                let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
                return Err(EngineError::CommandFailed {
                    engine: "wslc".into(),
                    message: if stderr.trim().is_empty() {
                        text.trim().to_string()
                    } else {
                        stderr
                    },
                });
            }
            Ok(text)
        })
    }

    fn info<'a>(&'a self) -> BoxFuture<'a, Result<String, EngineError>> {
        Box::pin(async move { run_info(&self.exe, Some("json")).await })
    }

    fn run<'a>(
        &'a self,
        image: &'a str,
        args: &'a [&'a str],
        stdin_pipe: bool,
    ) -> BoxFuture<'a, Result<tokio::process::Child, EngineError>> {
        Box::pin(async move {
            self.warm_session(image).await;
            let options: Vec<String> = args.iter().map(|s| s.to_string()).collect();
            let unit = format!(
                "mcp-writ-wslc-{}",
                &uuid::Uuid::now_v7().simple().to_string()[..12]
            );
            let prefix = [
                "--pull".to_string(),
                "never".to_string(),
                "--name".to_string(),
                unit,
            ];
            let run_args = container_run_args_ext(&prefix, &options, image);
            let mut cmd = tokio::process::Command::new(&self.exe);
            cmd.args(&run_args);
            if stdin_pipe {
                cmd.stdin(std::process::Stdio::piped());
            }
            cmd.stdout(std::process::Stdio::piped());
            cmd.stderr(std::process::Stdio::inherit());
            Ok(cmd.spawn()?)
        })
    }

    fn is_available(&self) -> bool {
        // A resolved-and-gated binary is available; re-probe so a CLI
        // that stops answering reports unavailability rather than a
        // stale resolution.
        self.probe_version()
            .map(crate::container::windows_probe::wslc_version_supported)
            .unwrap_or(false)
    }
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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- EngineKind::from_str -------------------------------------------------

    #[test]
    fn engine_kind_from_str_docker() {
        assert_eq!(EngineKind::from_str("docker").unwrap(), EngineKind::Docker);
        assert_eq!(EngineKind::from_str("Docker").unwrap(), EngineKind::Docker);
        assert_eq!(EngineKind::from_str("DOCKER").unwrap(), EngineKind::Docker);
    }

    #[test]
    fn engine_kind_from_str_podman() {
        assert_eq!(EngineKind::from_str("podman").unwrap(), EngineKind::Podman);
        assert_eq!(EngineKind::from_str("Podman").unwrap(), EngineKind::Podman);
    }

    #[test]
    fn engine_kind_from_str_buildah() {
        assert_eq!(
            EngineKind::from_str("buildah").unwrap(),
            EngineKind::Buildah
        );
        assert_eq!(
            EngineKind::from_str("BUILDAH").unwrap(),
            EngineKind::Buildah
        );
    }

    #[test]
    fn engine_kind_from_str_invalid() {
        let err = EngineKind::from_str("containerd").unwrap_err();
        match err {
            EngineError::UnknownKind(s) => assert_eq!(s, "containerd"),
            other => panic!("expected UnknownKind, got: {other}"),
        }
    }

    #[test]
    fn engine_kind_from_str_wslc_recognized_but_not_aliased() {
        // `wslc` parses — the vocabulary knows the candidate. WSLC's
        // `container.exe` alias stays a parse error: it is not the
        // wslc CLI name, and `container` belongs to Apple's driver.
        assert_eq!(EngineKind::from_str("wslc").unwrap(), EngineKind::Wslc);
        assert_eq!(EngineKind::from_str("WSLC").unwrap(), EngineKind::Wslc);
        assert!(matches!(
            EngineKind::from_str("container"),
            Err(EngineError::UnknownKind(_))
        ));
        assert!(matches!(
            EngineKind::from_str("wsl-containers"),
            Err(EngineError::UnknownKind(_))
        ));
    }

    // -- engine_info_os -------------------------------------------------

    #[test]
    fn engine_info_os_recognizes_apple_status_shape() {
        let status = r#"{"status":"running","host":{"architecture":"arm64"}}"#;
        assert_eq!(
            engine_info_os("container", status),
            Some(crate::execution::TargetOs::Linux)
        );
        // A foreign CLI's JSON without Apple's `status` member is not
        // the apple substrate — the OS stays unknown rather than guessed.
        assert_eq!(engine_info_os("container", r#"{"OSType":"linux"}"#), None);
        assert_eq!(engine_info_os("container", "not json"), None);
    }

    // -- Engine names ---------------------------------------------------------

    #[test]
    fn docker_engine_name() {
        assert_eq!(DockerEngine.name(), "docker");
    }

    #[test]
    fn podman_engine_name() {
        assert_eq!(PodmanEngine.name(), "podman");
    }

    #[test]
    fn buildah_engine_name() {
        assert_eq!(BuildahEngine.name(), "buildah");
    }

    // -- BuildahEngine::run returns Unsupported -------------------------------

    #[tokio::test]
    async fn buildah_run_returns_unsupported() {
        let engine = BuildahEngine;
        let result = engine.run("some-image:latest", &["--help"], false).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            EngineError::Unsupported(msg) => {
                assert!(msg.contains("buildah"), "message should mention buildah");
            }
            other => panic!("expected Unsupported, got: {other}"),
        }
    }

    // -- resolve_engine -------------------------------------------------------

    #[test]
    fn resolve_engine_explicit_docker() {
        // With availability check, result depends on environment.
        let result = resolve_engine(Some(EngineKind::Docker));
        match result {
            Ok(engine) => assert_eq!(engine.name(), "docker"),
            Err(EngineError::NotAvailable(name)) => assert_eq!(name, "docker"),
            Err(other) => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn resolve_engine_explicit_podman() {
        let result = resolve_engine(Some(EngineKind::Podman));
        match result {
            Ok(engine) => assert_eq!(engine.name(), "podman"),
            Err(EngineError::NotAvailable(name)) => assert_eq!(name, "podman"),
            Err(other) => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn resolve_engine_explicit_buildah() {
        let result = resolve_engine(Some(EngineKind::Buildah));
        match result {
            Ok(engine) => assert_eq!(engine.name(), "buildah"),
            Err(EngineError::NotAvailable(name)) => assert_eq!(name, "buildah"),
            Err(other) => panic!("unexpected error: {other}"),
        }
    }

    // -- WslcEngine -------------------------------------------------------

    /// A stub `wslc` CLI answering `--version` with `wslc <ver>` —
    /// `.cmd` on Windows (std spawns batch files through cmd.exe), a
    /// shell script elsewhere. The fixture ignores every argument.
    fn wslc_stub(version: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "mcp_writ_wslc_stub_{}",
            uuid::Uuid::now_v7().simple()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        #[cfg(windows)]
        let (name, body) = ("wslc-stub.cmd", format!("@echo wslc {version}\r\n"));
        #[cfg(not(windows))]
        let (name, body) = ("wslc-stub.sh", format!("#!/bin/sh\necho wslc {version}\n"));
        let path = dir.join(name);
        std::fs::write(&path, body).unwrap();
        #[cfg(not(windows))]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&path).unwrap().permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(&path, perms).unwrap();
        }
        path
    }

    /// Explicit-only resolution: the stub answering the validated line
    /// resolves to a wslc engine whose identity is `wslc` while the
    /// spawned program is the resolved path — never an auto-pick.
    #[test]
    fn resolve_engine_wslc_resolves_the_validated_line() {
        let _env = crate::warden::lock_process_env();
        let stub = wslc_stub("3.0.1.0");
        unsafe {
            std::env::set_var(crate::container::windows_probe::WSLC_EXE_ENV, &stub);
        }
        let engine =
            resolve_engine(Some(EngineKind::Wslc)).expect("the validated-line stub resolves");
        unsafe {
            std::env::remove_var(crate::container::windows_probe::WSLC_EXE_ENV);
        }
        assert_eq!(engine.name(), "wslc");
        assert_eq!(engine.program(), stub.to_string_lossy().as_ref());
        assert_eq!(engine.interrupt_signal(), Some("SIGINT"));
        assert!(engine.is_available());
    }

    /// A version off the validated line is an Unsupported refusal —
    /// never a silent launch on an unverified contract.
    #[test]
    fn resolve_engine_wslc_refuses_an_unvalidated_version() {
        let _env = crate::warden::lock_process_env();
        for version in ["2.9.3.0", "3.1.0.0", "4.0.0.0", "3.0.0.0"] {
            let stub = wslc_stub(version);
            unsafe {
                std::env::set_var(crate::container::windows_probe::WSLC_EXE_ENV, &stub);
            }
            let result = resolve_engine(Some(EngineKind::Wslc));
            unsafe {
                std::env::remove_var(crate::container::windows_probe::WSLC_EXE_ENV);
            }
            match result {
                Err(EngineError::Unsupported(msg)) => {
                    assert!(msg.contains("wslc"), "version {version}: {msg}");
                    assert!(msg.contains("3.0"), "names the validated line: {msg}");
                }
                Ok(_) => panic!("version {version} must not resolve"),
                Err(other) => panic!("version {version}: expected Unsupported, got: {other}"),
            }
        }
    }

    /// No resolvable wslc is a distinct NotAvailable — the binary is
    /// absent, not unsupported; the refusal is never a substitute
    /// engine.
    #[test]
    fn resolve_engine_wslc_absent_is_not_available() {
        let _env = crate::warden::lock_process_env();
        // The override naming a missing file reads as absent — and
        // overrides the stock install path, so the refusal is
        // deterministic on every host.
        unsafe {
            std::env::set_var(
                crate::container::windows_probe::WSLC_EXE_ENV,
                r"C:\definitely-not-present\wslc.exe",
            );
        }
        let result = resolve_engine(Some(EngineKind::Wslc));
        unsafe {
            std::env::remove_var(crate::container::windows_probe::WSLC_EXE_ENV);
        }
        match result {
            Err(EngineError::NotAvailable(msg)) => {
                assert!(msg.contains("wslc"), "got: {msg}");
            }
            Ok(_) => panic!("an absent wslc must not resolve"),
            Err(other) => panic!("expected NotAvailable, got: {other}"),
        }
    }

    /// The wslc run-dialect pins: `--pull never` (a launch never
    /// fetches — pull progress on stdout would corrupt the wire) and
    /// an owned `--name`, spliced after `--no-healthcheck` and before
    /// the env-clear list; spec options and the image keep their tail
    /// positions.
    #[test]
    fn wslc_run_prefix_pins_pull_and_name() {
        let prefix = [
            "--pull".to_string(),
            "never".to_string(),
            "--name".to_string(),
            "unit-1".to_string(),
        ];
        let args = container_run_args_ext(&prefix, &["-e".to_string(), "K=V".to_string()], "img");
        assert_eq!(
            &args[..8],
            &[
                "run",
                "-i",
                "--rm",
                "--no-healthcheck",
                "--pull",
                "never",
                "--name",
                "unit-1"
            ]
        );
        assert_eq!(args[8], "-e");
        assert_eq!(args[9], "MCP_WRIT_ENV=");
        assert_eq!(args.last().unwrap(), "img");
        let env_pos = args.iter().position(|a| a == "K=V").unwrap();
        let cid_pos = args.iter().position(|a| a == "--pull").unwrap();
        assert!(env_pos > cid_pos, "spec options stay after the pins");
    }

    /// `wslc info --format json` — the `Server` member is the
    /// session-manager signature; the substrate OS is linux by
    /// construction, and a blob without `Server` claims nothing.
    #[test]
    fn engine_info_os_recognizes_wslc_server_shape() {
        let info = r#"{"Client":{"Version":"3.0.1.0"},"Server":{"SessionManagerVersion":"3.0.1","Sessions":[]}}"#;
        assert_eq!(
            engine_info_os("wslc", info),
            Some(crate::execution::TargetOs::Linux)
        );
        // A foreign CLI's docker-shaped blob is not the wslc answer.
        assert_eq!(engine_info_os("wslc", r#"{"OSType":"linux"}"#), None);
        assert_eq!(engine_info_os("wslc", "not json"), None);
    }

    /// `is_available` re-runs the version probe+gate: a stub on the
    /// line answers true; an old line, a garbage answer, or a missing
    /// binary answers false.
    #[test]
    fn wslc_is_available_reprobes_the_validated_line() {
        let good = wslc_stub("3.0.2.0");
        assert!(WslcEngine::for_test(good.to_str().unwrap()).is_available());
        let old = wslc_stub("2.4.12.0");
        assert!(!WslcEngine::for_test(old.to_str().unwrap()).is_available());
        assert!(!WslcEngine::for_test(r"C:\no\wslc.exe").is_available());
    }

    #[test]
    fn resolve_engine_unavailable_returns_not_available() {
        // At least one of these engines is likely unavailable in the test env.
        // Verify that NotAvailable is returned (not a panic or wrong variant).
        let kinds = [EngineKind::Docker, EngineKind::Podman, EngineKind::Buildah];
        for kind in kinds {
            let result = resolve_engine(Some(kind));
            match &result {
                Ok(engine) => {
                    // Engine is installed; verify it reports available
                    assert!(engine.is_available());
                }
                Err(EngineError::NotAvailable(name)) => {
                    assert!(!name.is_empty(), "engine name in error should not be empty");
                }
                Err(other) => panic!("expected Ok or NotAvailable for {kind:?}, got: {other}"),
            }
        }
    }

    // -- EngineError display --------------------------------------------------

    #[test]
    fn engine_error_display() {
        let err = EngineError::NotFound;
        assert_eq!(err.to_string(), "no container engine found on PATH");

        let err = EngineError::CommandFailed {
            engine: "docker".into(),
            message: "exit code 1".into(),
        };
        assert!(err.to_string().contains("docker"));
        assert!(err.to_string().contains("exit code 1"));

        let err = EngineError::UnknownKind("runc".into());
        assert!(err.to_string().contains("runc"));

        let err = EngineError::Unsupported("not implemented".into());
        assert!(err.to_string().contains("not implemented"));

        let err = EngineError::NotAvailable("podman".into());
        assert!(err.to_string().contains("podman"));
        assert!(err.to_string().contains("not available"));
    }

    // -- is_available does not panic ------------------------------------------

    #[test]
    fn is_available_does_not_panic() {
        // Verify the function runs without panicking, regardless of CLI presence
        let _ = DockerEngine.is_available();
        let _ = PodmanEngine.is_available();
        let _ = BuildahEngine.is_available();
    }
}
