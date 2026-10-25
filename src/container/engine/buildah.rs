//! The Buildah engine — the `buildah` CLI resolved once to a trusted
//! path (image build/inspect only; `run` is unsupported — a buildah
//! launch has no container execution dialect here).

use super::{
    BoxFuture, ContainerEngine, EngineError, bounded_cmd_output, bounded_driver_output,
    confirm_image_removed, run_cli_args, run_image_build, run_info,
};
use crate::trusted_path::BoundDriver;

pub struct BuildahEngine {
    /// The driver bound at [`BuildahEngine::resolve`] — the validated
    /// canonical path *plus* the pinned file identity. Every
    /// subprocess re-verifies that identity before spawning, so a
    /// binary replaced after resolution fails closed rather than
    /// running under the resolved name.
    exe: BoundDriver,
}

impl BuildahEngine {
    /// Resolve `buildah` to a bound executable — the one moment PATH is
    /// consulted, under the administrator provenance class: a hit in
    /// a caller-managed directory refuses rather than falling
    /// through (the same-name shadow is the substitution this
    /// resolution exists to close), and `MCP_WRIT_BUILDAH_EXE`
    /// supplies an explicit path instead.
    pub fn resolve() -> Result<Self, EngineError> {
        let exe = crate::trusted_path::resolve_cli("buildah").map_err(EngineError::NotAvailable)?;
        Ok(Self { exe })
    }

    /// A test stand-in with a caller-chosen program spelling — never
    /// reachable from production resolution.
    #[cfg(test)]
    pub(crate) fn for_test(exe: &str) -> Self {
        Self {
            exe: BoundDriver::for_test(exe),
        }
    }
}

impl ContainerEngine for BuildahEngine {
    fn name(&self) -> &str {
        "buildah"
    }

    fn program(&self) -> &str {
        self.exe.program()
    }

    fn driver_command(&self) -> std::io::Result<tokio::process::Command> {
        self.exe.tokio_command()
    }

    fn driver_std_command(&self) -> std::io::Result<std::process::Command> {
        self.exe.std_command()
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
            let mut cmd = self.exe.tokio_command()?;
            cmd.args(["inspect", "--type=image", image]);
            let output = bounded_cmd_output(&mut cmd, true).await?;
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
        Box::pin(async move { run_cli_args(&self.exe, "buildah", &["tag", source, target]).await })
    }

    fn remove_image<'a>(&'a self, image: &'a str) -> BoxFuture<'a, Result<(), EngineError>> {
        Box::pin(async move {
            run_cli_args(&self.exe, "buildah", &["rmi", image]).await?;
            confirm_image_removed(self, image).await
        })
    }

    fn info<'a>(&'a self) -> BoxFuture<'a, Result<String, EngineError>> {
        Box::pin(async move { run_info(&self.exe, None).await })
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
        bounded_driver_output(&self.exe, &["--version"])
            .map(|o| o.status.success() && super::version_answers_as(&o, "buildah"))
            .unwrap_or(false)
    }
}
