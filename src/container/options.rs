use std::path::PathBuf;

use crate::container::engine::EngineKind;

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
}

/// Execution options for the run-image flow.
#[derive(Debug)]
pub struct RunImageOptions {
    /// Container engine to use (auto-detect when `None`).
    pub engine: Option<EngineKind>,
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
}
