//! The Docker engine — the `docker` CLI resolved once to a trusted path.

use super::{
    BoxFuture, ContainerEngine, EngineError, bounded_cli_output, bounded_cmd_output,
    confirm_image_removed, run_cli_args, run_image_build, run_info, spawn_container_run,
};

pub struct DockerEngine {
    /// The validated canonical path bound at [`DockerEngine::resolve`]
    /// — every subprocess this engine spawns names this exact binary so
    /// a mutable-PATH or writable-directory substitution can never slip
    /// a replacement under the resolved identity.
    exe: String,
}

impl DockerEngine {
    /// Resolve `docker` on PATH once to a validated canonical path —
    /// the only moment PATH is consulted. A hit in a location a
    /// different user could rewrite refuses rather than falling
    /// through: the same-name shadow is the substitution this
    /// resolution exists to close.
    pub fn resolve() -> Result<Self, EngineError> {
        let exe = crate::trusted_path::resolve_cli("docker").map_err(EngineError::NotAvailable)?;
        Ok(Self {
            exe: exe.to_string_lossy().into_owned(),
        })
    }

    /// A test stand-in with a caller-chosen program spelling — never
    /// reachable from production resolution.
    #[cfg(test)]
    pub(crate) fn for_test(exe: &str) -> Self {
        Self {
            exe: exe.to_string(),
        }
    }
}

impl ContainerEngine for DockerEngine {
    fn name(&self) -> &str {
        "docker"
    }

    fn program(&self) -> &str {
        &self.exe
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
                &self.exe,
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
            let mut cmd = tokio::process::Command::new(&self.exe);
            cmd.args(["image", "inspect", image]);
            // Bounded drains keep an engine flood from growing
            // memory; kill_on_drop rides inside the helper.
            let output = bounded_cmd_output(&mut cmd, true).await?;
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
            run_cli_args(&self.exe, "docker", &["image", "tag", source, target]).await
        })
    }

    fn remove_image<'a>(&'a self, image: &'a str) -> BoxFuture<'a, Result<(), EngineError>> {
        Box::pin(async move {
            run_cli_args(&self.exe, "docker", &["image", "rm", image]).await?;
            confirm_image_removed(self, image).await
        })
    }

    fn info<'a>(&'a self) -> BoxFuture<'a, Result<String, EngineError>> {
        Box::pin(async move { run_info(&self.exe, Some("{{json .}}")).await })
    }

    fn run<'a>(
        &'a self,
        image: &'a str,
        args: &'a [&'a str],
        stdin_pipe: bool,
    ) -> BoxFuture<'a, Result<tokio::process::Child, EngineError>> {
        spawn_container_run(&self.exe, image, args, stdin_pipe)
    }

    fn is_available(&self) -> bool {
        bounded_cli_output(&self.exe, &["--version"])
            .map(|o| o.status.success() && super::version_answers_as(&o, "docker"))
            .unwrap_or(false)
    }
}
