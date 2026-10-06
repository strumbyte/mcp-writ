//! The Buildah engine — the `buildah` CLI on PATH (image build/inspect
//! only; `run` is unsupported — a buildah launch has no container
//! execution dialect here).

use super::{
    BoxFuture, ContainerEngine, EngineError, bounded_cli_output, run_cli_args, run_image_build,
    run_info,
};

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
        no_cache: bool,
    ) -> BoxFuture<'a, Result<(), EngineError>> {
        Box::pin(async move {
            run_image_build(
                "buildah",
                "buildah",
                "bud",
                dockerfile_path,
                tag,
                context_dir,
                no_cache,
            )
            .await
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

    fn tag<'a>(
        &'a self,
        source: &'a str,
        target: &'a str,
    ) -> BoxFuture<'a, Result<(), EngineError>> {
        // Buildah's noun-less dialect: `buildah tag`, `buildah rmi`.
        Box::pin(async move { run_cli_args("buildah", "buildah", &["tag", source, target]).await })
    }

    fn remove_image<'a>(&'a self, image: &'a str) -> BoxFuture<'a, Result<(), EngineError>> {
        Box::pin(async move { run_cli_args("buildah", "buildah", &["rmi", image]).await })
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
        bounded_cli_output("buildah", &["--version"])
            .map(|o| o.status.success())
            .unwrap_or(false)
    }
}
