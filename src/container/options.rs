use std::path::PathBuf;

use crate::container::engine::EngineKind;
use crate::execution::IsolationKind;

/// Execution options for the wrap-image flow.
///
/// Owned by the container layer; the CLI layer converts `WrapImageArgs`
/// into this type so container code does not depend on CLI parsing types.
#[derive(Debug)]
pub struct WrapOptions {
    /// Source container image to wrap.
    pub image: String,
    /// Policy file to embed (defaults to `policy.kdl` at build time).
    pub policy: Option<PathBuf>,
    /// Output image tag (defaults to `<base>-secured:latest`).
    pub tag: Option<String>,
    /// Container engine to use (auto-detect when `None`).
    pub engine: Option<EngineKind>,
    /// Explicit path to the mcp-secure-runner binary.
    pub runner_binary: Option<PathBuf>,
    /// Write the generated Dockerfile here and skip the build.
    pub output_dockerfile: Option<PathBuf>,
    /// Disable the build cache.
    pub no_cache: bool,
    /// Server identity to bind into the image policy.
    pub server: Option<String>,
    /// Extra MSVC redistributable DLLs to ship app-local with a Windows
    /// guest runner (`--crt-dll`, repeatable) — a PE importing
    /// `vcruntime140.dll` fails loader lock on Server Core without one.
    /// The runner's PE import table decides which are *required*; these
    /// paths supply copies the packaged `runners/crt/` drop or System32
    /// did not.
    pub crt_dlls: Vec<PathBuf>,
}

/// Execution options for the run-image flow.
#[derive(Debug)]
pub struct RunImageOptions {
    /// Container engine to use (auto-detect when `None`).
    pub engine: Option<EngineKind>,
    /// The isolation method the launch must be confined by (`--isolation`,
    /// default `container`). Kept separate from `engine`: the engine is
    /// the tooling on the host, isolation is the workload boundary the
    /// resolved backend applies — a non-default method is refused when
    /// no backend implements it, never silently run as a plain container.
    pub isolation: Option<IsolationKind>,
    /// Container image to run (must be digest-pinned unless allowed).
    pub image: String,
    /// Policy file to mount (defaults to `./policy.kdl`).
    pub policy: Option<PathBuf>,
    /// Host directory mounted at `/var/log/mcp-secure`.
    pub log_dir: Option<String>,
    /// Enable verbose stderr output.
    pub verbose: bool,
    /// Permit a tag-only (non-digest-pinned) image reference.
    pub allow_mutable_tag: bool,
    /// Server identity to bind in the mounted policy.
    pub server: Option<String>,
    /// `--report <path>` — the host-side launch report destination (plan,
    /// host-visible observations, final result; JSON to the file, human
    /// summary to stderr, never MCP stdout).
    pub report: Option<PathBuf>,
}

/// Execution options for the containerize flow.
#[derive(Debug)]
pub struct ContainerizeOptions {
    /// MCP server source directory to containerize.
    pub source_dir: PathBuf,
    /// Policy file to embed.
    pub policy: PathBuf,
    /// Output image tag (defaults to `<dir-name>-secured:latest`).
    pub tag: Option<String>,
    /// Base image override (runtime is still inferred from the source).
    pub base_image: Option<String>,
    /// Container engine to use (auto-detect when `None`).
    pub engine: Option<EngineKind>,
    /// Write the generated Dockerfile here and skip the build.
    pub output_dockerfile: Option<PathBuf>,
    /// Server identity to bind into the image policy.
    pub server: Option<String>,
    /// Extra MSVC redistributable DLLs to ship app-local with a Windows
    /// guest runner (`--crt-dll`, repeatable) — same contract as
    /// [`WrapOptions::crt_dlls`].
    pub crt_dlls: Vec<PathBuf>,
}
