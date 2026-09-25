use std::fmt;
use std::future::Future;
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

    /// Build a container image from a Dockerfile.
    fn build<'a>(
        &'a self,
        dockerfile_path: &'a str,
        tag: &'a str,
        context_dir: &'a str,
    ) -> BoxFuture<'a, Result<(), EngineError>>;

    /// Inspect a container image, returning the raw JSON output.
    fn inspect<'a>(&'a self, image: &'a str) -> BoxFuture<'a, Result<String, EngineError>>;

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
/// helper rather than copying the argument list.
pub(crate) fn container_run_args(options: &[String], image: &str) -> Vec<String> {
    let mut args = vec![
        "run".to_string(),
        "-i".to_string(),
        "--rm".to_string(),
        "--no-healthcheck".to_string(),
        "--entrypoint".to_string(),
        "/usr/local/bin/mcp-secure-runner".to_string(),
        "-e".to_string(),
        "MCP_WRIT_ENV=".to_string(),
        "-e".to_string(),
        "MCP_WRIT_SKIP_SANDBOX=".to_string(),
        "-e".to_string(),
        "MCP_WRIT_SERVER=".to_string(),
    ];
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

/// Check that `engine` is available on PATH, returning it boxed or
/// [`EngineError::NotAvailable`] if the CLI cannot be found.
fn try_engine(
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
            let output = tokio::process::Command::new("docker")
                .args(["image", "inspect", image])
                .output()
                .await?;
            if !output.status.success() {
                return Err(EngineError::CommandFailed {
                    engine: "docker".into(),
                    message: String::from_utf8_lossy(&output.stderr).into_owned(),
                });
            }
            Ok(String::from_utf8_lossy(&output.stdout).into_owned())
        })
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
            let output = tokio::process::Command::new("podman")
                .args(["image", "inspect", image])
                .output()
                .await?;
            if !output.status.success() {
                return Err(EngineError::CommandFailed {
                    engine: "podman".into(),
                    message: String::from_utf8_lossy(&output.stderr).into_owned(),
                });
            }
            Ok(String::from_utf8_lossy(&output.stdout).into_owned())
        })
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
// EngineKind
// ---------------------------------------------------------------------------

/// Enumeration of supported container engine kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EngineKind {
    Docker,
    Podman,
    Buildah,
}

impl FromStr for EngineKind {
    type Err = EngineError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "docker" => Ok(Self::Docker),
            "podman" => Ok(Self::Podman),
            "buildah" => Ok(Self::Buildah),
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
        }
    }
}

// ---------------------------------------------------------------------------
// detect_engine / resolve_engine
// ---------------------------------------------------------------------------

/// Detect the first available container engine on PATH.
///
/// Checks in order: docker → podman → buildah.
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
    }
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
