//! WslcEngine — WSL Containers (`wslc.exe`) on a Windows host.

use super::{
    BoxFuture, ContainerEngine, EngineError, bounded_cli_output, container_run_args_ext,
    run_cli_args, run_image_build, run_info,
};

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
///   provisioning progress on stdout; a bounded `wslc system session
///   run` warm-up materializes the shared session ahead of the launch
///   — no image, no container unit, nothing left to reap. A launch
///   whose warm-up cannot confirm the session refuses rather than
///   letting provisioning chatter corrupt the MCP wire.
/// - Ctrl-C teardown signals the unit first (`wslc kill -s SIGINT`) so
///   the runner's interrupted-report unwind executes before the CLI
///   client is killed and the unit `rm -f`'d — the unit outlives its
///   CLI client, so kill-the-client alone is not a stop. The
///   `kill`/`rm`/`inspect` commands all accept the `--cidfile`-recorded
///   unit id (verified on wslc 3.0.1.0 — SIGKILL/`rm -f` by id reap the
///   unit; whether SIGINT ends it is the init's signal disposition,
///   same as docker).
///
/// Resolution is explicit-only: `wslc` never enters
/// [`detect_engine`][crate::container::engine::detect_engine]'s
/// auto-pick order, never substitutes for a `hyperv` or native
/// request, and the validated line (wslc 3.0.x ≥ 3.0.1) is pinned at
/// resolve — anything else refuses.
pub struct WslcEngine {
    /// The resolved `wslc.exe`, spawned by full path.
    exe: String,
}

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

    /// `wslc --version` → `(major, minor, patch)`. A bounded sync
    /// probe — `resolve_engine`/`is_available` are sync callers, and a
    /// wedged CLI is killed rather than stalling the launch; the
    /// answer is a local version string (no session contact).
    fn probe_version(&self) -> Result<(u64, u64, u64), EngineError> {
        use crate::container::windows_probe as probe;
        let output = bounded_cli_output(&self.exe, &["--version"]).map_err(|e| {
            EngineError::CommandFailed {
                engine: "wslc".into(),
                message: format!("`--version` probe failed: {e}"),
            }
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
    /// bounded `wslc system session run` against the *session VM's own*
    /// userland absorbs that chatter: it needs no image and no
    /// container entrypoint (a distroless or scratch workload image
    /// carries no `/bin/true` to exec), creates no unit, and leaves
    /// nothing to reap. A launch proceeds only after the session is
    /// confirmed — a timed-out, failed, or unverifiable warm-up
    /// refuses rather than racing provisioning output onto the wire.
    async fn warm_session(&self) -> Result<(), EngineError> {
        if self.default_session_listed().await {
            return Ok(());
        }
        // `session run` materializes the `wslc-cli-*` session when none
        // is listed (verified on wslc 3.0.1.0: ~2 s cold, the session
        // lists afterwards) and is a no-op the rest of the time. The
        // command runs in the session VM's own rootfs, where
        // `/bin/true` always exists; a timed-out client is killed by
        // kill_on_drop, and no unit exists to outlive it.
        let warm = tokio::process::Command::new(&self.exe)
            .args(["system", "session", "run", "/bin/true"])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .kill_on_drop(true)
            .output();
        let output = tokio::time::timeout(std::time::Duration::from_secs(60), warm)
            .await
            .map_err(|_| EngineError::CommandFailed {
                engine: "wslc".into(),
                message: "`wslc system session run` warm-up timed out — the \
                          shared session did not materialize"
                    .into(),
            })??;
        if !output.status.success() {
            return Err(EngineError::CommandFailed {
                engine: "wslc".into(),
                message: format!("`wslc system session run` warm-up exited {}", output.status),
            });
        }
        // wslc can exit 0 on a failed command — the session listing is
        // the success fact, the same shape the pre-warm check read.
        if self.default_session_listed().await {
            Ok(())
        } else {
            Err(EngineError::CommandFailed {
                engine: "wslc".into(),
                message: "`wslc system session run` exited 0 but no `wslc-cli-*` \
                          session is listed — refusing to launch without the \
                          shared session"
                    .into(),
            })
        }
    }
}

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
        no_cache: bool,
    ) -> BoxFuture<'a, Result<(), EngineError>> {
        // A wslc build failure can exit 0 — the produced image is the
        // success fact: `common::build_image` verifies it with `image
        // inspect`, so a 0-exit error surfaces there rather than here.
        Box::pin(async move {
            run_image_build(
                &self.exe,
                "wslc",
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

    fn tag<'a>(
        &'a self,
        source: &'a str,
        target: &'a str,
    ) -> BoxFuture<'a, Result<(), EngineError>> {
        // `wslc image tag` — a fake exit-0 is possible; `build_image`
        // confirms the association by comparing inspect `Id`s.
        Box::pin(
            async move { run_cli_args(&self.exe, "wslc", &["image", "tag", source, target]).await },
        )
    }

    fn remove_image<'a>(&'a self, image: &'a str) -> BoxFuture<'a, Result<(), EngineError>> {
        Box::pin(async move {
            run_cli_args(&self.exe, "wslc", &["image", "rm", image]).await?;
            // An exit-0 `image rm` is not the removal fact — the same
            // fake-success dialect as `build`. The image is removed
            // only when `image inspect` answers an empty set.
            super::confirm_image_removed(self, image).await
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
            self.warm_session().await?;
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
