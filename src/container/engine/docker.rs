//! The Docker engine — the `docker` CLI on PATH.

use super::{
    BoxFuture, ContainerEngine, EngineError, bounded_cli_output, run_cli_args, run_image_build,
    run_info, spawn_container_run,
};

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
        no_cache: bool,
    ) -> BoxFuture<'a, Result<(), EngineError>> {
        Box::pin(async move {
            run_image_build(
                "docker",
                "docker",
                "build",
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

    fn tag<'a>(
        &'a self,
        source: &'a str,
        target: &'a str,
    ) -> BoxFuture<'a, Result<(), EngineError>> {
        Box::pin(async move {
            run_cli_args("docker", "docker", &["image", "tag", source, target]).await
        })
    }

    fn remove_image<'a>(&'a self, image: &'a str) -> BoxFuture<'a, Result<(), EngineError>> {
        Box::pin(async move { run_cli_args("docker", "docker", &["image", "rm", image]).await })
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
        bounded_cli_output("docker", &["--version"])
            .map(|o| o.status.success())
            .unwrap_or(false)
    }
}
