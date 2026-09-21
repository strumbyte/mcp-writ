use std::cell::Cell;
use std::path::{Path, PathBuf};

use crate::error::WardenError;
use crate::policy::Policy;

/// Options for child spawn. `run` uses [`SpawnOptions::default`] (inherit ambient env).
///
/// Self-test (`generate-policy --self-test`) sets `restrict_environment` and a
/// private `tmpdir` so the short-lived child matches live-discovery's restricted
/// environment without using `--unsafe-unsandboxed-discovery`.
#[derive(Debug, Clone, Default)]
pub struct SpawnOptions {
    /// Clear the environment except PATH (and Windows roots) plus TMPDIR.
    pub restrict_environment: bool,
    /// Private temporary directory exported as `TMPDIR` / `TMP` / `TEMP`.
    pub tmpdir: Option<PathBuf>,
}

mod child;
mod env;
#[cfg(target_os = "linux")]
mod landlock_impl;
#[cfg(target_os = "linux")]
mod linux_spawn;
#[cfg(target_os = "macos")]
mod macos_sandbox;
#[cfg(target_os = "linux")]
mod seccomp_impl;
#[cfg(target_os = "windows")]
mod windows_env;
#[cfg(target_os = "windows")]
mod windows_proc;
#[cfg(target_os = "windows")]
mod windows_profile;
#[cfg(target_os = "windows")]
mod windows_sandbox;

pub use child::{ChildProcess, ChildStdin, ChildStdout, RunningChild};

use child::{RunningChildInner, apply_unix_process_group, apply_unix_process_group_tokio};
use env::apply_spawn_env;

pub struct Warden {
    policy: Policy,
    /// When set, `spawn_child*` falls back to the unsandboxed spawn path.
    ///
    /// Sandboxing is applied per child, never to this (parent) process:
    /// Linux runs `no_new_privs` + Landlock + seccomp in the child's `pre_exec`
    /// (see `linux_spawn`), macOS wraps each child in `sandbox-exec`, and
    /// Windows places each child inside an AppContainer profile.
    ///
    /// `apply_sandbox()` is a deprecated no-op and never sets this flag.
    /// Unit tests set it via `mark_sandbox_applied` so `spawn_child*` takes
    /// the unsandboxed path instead of sandboxing test children.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    sandbox_applied: Cell<bool>,
}

impl Warden {
    pub fn new(policy: Policy) -> Self {
        Warden {
            policy,
            sandbox_applied: Cell::new(false),
        }
    }

    /// Deprecated no-op.
    ///
    /// This method does not apply `no_new_privs`, Landlock, or seccomp.
    /// Child-process sandboxing is applied during `spawn_child`.
    #[deprecated(
        note = "sandboxing is applied to the child during spawn_child; this method is a no-op"
    )]
    pub fn apply_sandbox(&self) -> Result<(), WardenError> {
        tracing::debug!(
            "Warden: apply_sandbox is a no-op; child process sandboxing is applied during spawn_child"
        );
        Ok(())
    }

    /// Spawn a child process with the sandbox applied to the child.
    ///
    /// - Linux: Landlock + seccomp applied in `pre_exec` (does not break parent proxy)
    /// - Windows: AppContainer sandbox
    /// - macOS: sandbox-exec
    pub fn spawn_child(&self, command: &str, args: &[String]) -> Result<ChildProcess, WardenError> {
        if self.sandbox_applied.get() {
            return self.spawn_unsandboxed(command, args);
        }

        #[cfg(target_os = "macos")]
        {
            tracing::info!("Warden: macOS sandbox applied (sandbox-exec)");
            macos_sandbox::spawn_sandboxed(&self.policy, command, args).map(ChildProcess::Macos)
        }

        #[cfg(target_os = "windows")]
        {
            tracing::info!("Warden: Windows sandbox applied (AppContainer)");
            windows_sandbox::spawn_sandboxed(
                &self.policy,
                None,
                command,
                args,
                &SpawnOptions::default(),
            )
            .map(ChildProcess::Windows)
        }

        #[cfg(target_os = "linux")]
        {
            tracing::info!("Warden: Linux sandbox applied (Landlock + seccomp via pre_exec)");
            let sandbox_bits = linux_spawn::prepare_linux_child_sandbox(&self.policy)?;
            let mut cmd = std::process::Command::new(command);
            cmd.args(args)
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::inherit());
            apply_unix_process_group(&mut cmd);
            linux_spawn::attach_linux_pre_exec(&mut cmd, sandbox_bits);

            cmd.spawn()
                .map(ChildProcess::Standard)
                .map_err(WardenError::ProcessSpawn)
        }

        #[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
        {
            tracing::warn!(
                "Warden: sandbox not available on this platform. Running unconstrained."
            );
            let mut cmd = std::process::Command::new(command);
            cmd.args(args)
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::inherit());
            apply_unix_process_group(&mut cmd);
            cmd.spawn()
                .map(ChildProcess::Standard)
                .map_err(WardenError::ProcessSpawn)
        }
    }

    /// Spawn a child process without applying any sandbox (dry-run or debug).
    pub fn spawn_unsandboxed(
        &self,
        command: &str,
        args: &[String],
    ) -> Result<ChildProcess, WardenError> {
        tracing::info!("Warden: sandbox skipped (dry-run or skip requested)");
        let mut cmd = std::process::Command::new(command);
        cmd.args(args)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::inherit());
        apply_unix_process_group(&mut cmd);
        cmd.spawn()
            .map(ChildProcess::Standard)
            .map_err(WardenError::ProcessSpawn)
    }

    /// Spawn a sandboxed child process and wrap it for async I/O.
    pub fn spawn_child_async(&self, argv: &[String]) -> Result<RunningChild, WardenError> {
        self.spawn_child_async_with(argv, &SpawnOptions::default())
    }

    /// Same as [`Self::spawn_child_async`] with environment / TMPDIR options.
    pub fn spawn_child_async_with(
        &self,
        argv: &[String],
        opts: &SpawnOptions,
    ) -> Result<RunningChild, WardenError> {
        self.spawn_child_async_impl(None, argv, opts)
    }

    /// Spawn a sandboxed child that execs `program` — the verified
    /// executable — while the child's own `argv[0]` keeps the caller's
    /// spelling (`CommandExt::arg0` semantics: `arg0` on Unix,
    /// `lpApplicationName` on Windows).
    ///
    /// Use this when `argv[0]` names a symlink whose resolved target was
    /// verified: exec runs the hashed file while the child still sees the
    /// link path (a venv `bin/python` locates `pyvenv.cfg` through
    /// `argv[0]`). Where a platform cannot express the separation, the
    /// child sees `program` as its `argv[0]`; on macOS, where CPython
    /// ignores `argv[0]`, the spelled path is also exported as
    /// `PYTHONEXECUTABLE` (see `python_executable_override`).
    pub fn spawn_child_async_exe(
        &self,
        program: &Path,
        argv: &[String],
    ) -> Result<RunningChild, WardenError> {
        self.spawn_child_async_impl(Some(program), argv, &SpawnOptions::default())
    }

    fn spawn_child_async_impl(
        &self,
        program: Option<&Path>,
        argv: &[String],
        opts: &SpawnOptions,
    ) -> Result<RunningChild, WardenError> {
        if argv.is_empty() {
            return Err(WardenError::ProcessSpawn(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "command argv cannot be empty",
            )));
        }
        if self.sandbox_applied.get() {
            return self.spawn_unsandboxed_async_impl(program, argv, opts);
        }
        let command = &argv[0];
        let args = &argv[1..];

        #[cfg(target_os = "windows")]
        {
            tracing::info!("Warden: Windows sandbox applied (AppContainer)");
            let mut win_child =
                windows_sandbox::spawn_sandboxed(&self.policy, program, command, args, opts)?;
            let stdin_file = win_child.stdin.take().ok_or_else(|| {
                WardenError::ProcessSpawn(std::io::Error::other("failed to capture child stdin"))
            })?;
            let stdout_file = win_child.stdout.take().ok_or_else(|| {
                WardenError::ProcessSpawn(std::io::Error::other("failed to capture child stdout"))
            })?;
            let async_stdin = tokio::fs::File::from_std(stdin_file);
            let async_stdout = tokio::fs::File::from_std(stdout_file);
            Ok(RunningChild {
                stdin: Some(Box::new(async_stdin)),
                stdout: Some(Box::new(async_stdout)),
                inner: RunningChildInner::Windows(std::sync::Arc::new(win_child)),
            })
        }

        #[cfg(target_os = "macos")]
        {
            tracing::info!("Warden: macOS sandbox applied (sandbox-exec)");
            let tmpdir = macos_sandbox::create_private_tmpdir()?;
            let sbpl = macos_sandbox::generate_sbpl_with_tmpdir(
                &self.policy,
                tmpdir.path().to_string_lossy().as_ref(),
            )?;
            let mut cmd = tokio::process::Command::new("sandbox-exec");
            cmd.arg("-p").arg(&sbpl).arg("--");
            // sandbox-exec re-execs the given path with argv[0] equal to
            // that path, so a distinct verified executable goes through a
            // shell that re-execs it with the caller's argv[0] (`exec -a`).
            match program {
                Some(p) if p != Path::new(command) => {
                    cmd.arg("/bin/sh")
                        .arg("-c")
                        .arg("exec -a \"$0\" \"$@\"")
                        .arg(command)
                        .arg(p)
                        .args(args);
                }
                _ => {
                    cmd.arg(command).args(args);
                }
            }
            cmd.stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::inherit());
            let mut env_opts = opts.clone();
            if env_opts.tmpdir.is_none() {
                env_opts.tmpdir = Some(tmpdir.path().to_path_buf());
            }
            apply_spawn_env(&mut cmd, &env_opts);
            if let Some(exe) = python_executable_override(command, program) {
                cmd.env("PYTHONEXECUTABLE", exe);
            }
            apply_unix_process_group_tokio(&mut cmd);
            let mut child = cmd.spawn().map_err(WardenError::ProcessSpawn)?;
            let stdin = child.stdin.take().ok_or_else(|| {
                WardenError::ProcessSpawn(std::io::Error::other("failed to capture child stdin"))
            })?;
            let stdout = child.stdout.take().ok_or_else(|| {
                WardenError::ProcessSpawn(std::io::Error::other("failed to capture child stdout"))
            })?;
            Ok(RunningChild {
                stdin: Some(Box::new(stdin)),
                stdout: Some(Box::new(stdout)),
                inner: RunningChildInner::Tokio(Box::new(child)),
                _tmpdir: Some(tmpdir),
            })
        }

        #[cfg(target_os = "linux")]
        {
            tracing::info!("Warden: Linux sandbox applied (Landlock + seccomp via pre_exec)");
            let sandbox_bits = linux_spawn::prepare_linux_child_sandbox(&self.policy)?;
            let mut cmd = match program {
                Some(p) => {
                    let mut c = tokio::process::Command::new(p);
                    // Exec the verified image while the child reads
                    // `command` as its own argv[0].
                    c.arg0(command);
                    c
                }
                None => tokio::process::Command::new(command),
            };
            cmd.args(args)
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::inherit());
            apply_spawn_env(&mut cmd, opts);
            apply_unix_process_group_tokio(&mut cmd);
            linux_spawn::attach_linux_pre_exec_tokio(&mut cmd, sandbox_bits);
            let mut child = cmd.spawn().map_err(WardenError::ProcessSpawn)?;
            let stdin = child.stdin.take().ok_or_else(|| {
                WardenError::ProcessSpawn(std::io::Error::other("failed to capture child stdin"))
            })?;
            let stdout = child.stdout.take().ok_or_else(|| {
                WardenError::ProcessSpawn(std::io::Error::other("failed to capture child stdout"))
            })?;
            Ok(RunningChild {
                stdin: Some(Box::new(stdin)),
                stdout: Some(Box::new(stdout)),
                inner: RunningChildInner::Tokio(Box::new(child)),
            })
        }

        #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
        {
            tracing::warn!(
                "Warden: sandbox not available on this platform. Running unconstrained."
            );
            self.spawn_unsandboxed_async_impl(program, argv, opts)
        }
    }

    /// Spawn an unsandboxed child process and wrap it for async I/O.
    pub fn spawn_unsandboxed_async(&self, argv: &[String]) -> Result<RunningChild, WardenError> {
        self.spawn_unsandboxed_async_with(argv, &SpawnOptions::default())
    }

    /// Same as [`Self::spawn_unsandboxed_async`] with environment / TMPDIR options.
    pub fn spawn_unsandboxed_async_with(
        &self,
        argv: &[String],
        opts: &SpawnOptions,
    ) -> Result<RunningChild, WardenError> {
        self.spawn_unsandboxed_async_impl(None, argv, opts)
    }

    /// Unsandboxed variant of [`Self::spawn_child_async_exe`].
    pub fn spawn_unsandboxed_async_exe(
        &self,
        program: &Path,
        argv: &[String],
    ) -> Result<RunningChild, WardenError> {
        self.spawn_unsandboxed_async_impl(Some(program), argv, &SpawnOptions::default())
    }

    fn spawn_unsandboxed_async_impl(
        &self,
        program: Option<&Path>,
        argv: &[String],
        opts: &SpawnOptions,
    ) -> Result<RunningChild, WardenError> {
        if argv.is_empty() {
            return Err(WardenError::ProcessSpawn(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "command argv cannot be empty",
            )));
        }
        tracing::info!("Warden: sandbox skipped (dry-run or skip requested)");

        // Windows: keep the verified image (lpApplicationName) separate
        // from the caller's argv[0], exactly like the sandboxed path —
        // Command cannot express the split on this platform.
        #[cfg(target_os = "windows")]
        if let Some(p) = program {
            let mut win_child =
                windows_proc::spawn_unsandboxed(Some(p), &argv[0], &argv[1..], opts)?;
            let stdin_file = win_child.stdin.take().ok_or_else(|| {
                WardenError::ProcessSpawn(std::io::Error::other("failed to capture child stdin"))
            })?;
            let stdout_file = win_child.stdout.take().ok_or_else(|| {
                WardenError::ProcessSpawn(std::io::Error::other("failed to capture child stdout"))
            })?;
            let async_stdin = tokio::fs::File::from_std(stdin_file);
            let async_stdout = tokio::fs::File::from_std(stdout_file);
            return Ok(RunningChild {
                stdin: Some(Box::new(async_stdin)),
                stdout: Some(Box::new(async_stdout)),
                inner: RunningChildInner::Windows(std::sync::Arc::new(win_child)),
            });
        }

        let mut cmd = match program {
            Some(p) => {
                #[allow(unused_mut)]
                let mut c = tokio::process::Command::new(p);
                // arg0 is Unix-only; the Windows Some branch returned
                // above, so this arm is unreachable there.
                #[cfg(unix)]
                c.arg0(argv[0].as_str());
                c
            }
            None => tokio::process::Command::new(&argv[0]),
        };
        cmd.args(&argv[1..])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::inherit());
        apply_spawn_env(&mut cmd, opts);
        #[cfg(target_os = "macos")]
        if let Some(exe) = python_executable_override(&argv[0], program) {
            cmd.env("PYTHONEXECUTABLE", exe);
        }
        apply_unix_process_group_tokio(&mut cmd);
        let mut child = cmd.spawn().map_err(WardenError::ProcessSpawn)?;
        let stdin = child.stdin.take().ok_or_else(|| {
            WardenError::ProcessSpawn(std::io::Error::other("failed to capture child stdin"))
        })?;
        let stdout = child.stdout.take().ok_or_else(|| {
            WardenError::ProcessSpawn(std::io::Error::other("failed to capture child stdout"))
        })?;
        Ok(RunningChild {
            stdin: Some(Box::new(stdin)),
            stdout: Some(Box::new(stdout)),
            inner: RunningChildInner::Tokio(Box::new(child)),
            #[cfg(target_os = "macos")]
            _tmpdir: None,
        })
    }

    /// Access the policy associated with this Warden instance.
    pub fn policy(&self) -> &Policy {
        &self.policy
    }
}

/// macOS CPython finds its install prefix from the exec'd image path
/// (`_NSGetExecutablePath`), not `argv[0]`: a venv's `bin/python` exec'd
/// by its resolved base-interpreter path loses `pyvenv.cfg` discovery and
/// runs as the base install. `PYTHONEXECUTABLE` is the getpath hook
/// consulted before the image path, so the child receives the caller's
/// spelled interpreter path whenever the verified image differs from it.
/// A bare `command` (no path separator) has no spelled path: it is
/// resolved through PATH, and the hit is exported only when it
/// canonicalizes to the same `program` that was hash-verified — a
/// mismatch would anchor getpath at an interpreter other than the
/// validated image, so it is left unset.
#[cfg(target_os = "macos")]
fn python_executable_override(command: &str, program: Option<&Path>) -> Option<PathBuf> {
    let program = program?;
    let spelled = Path::new(command);
    if program == spelled {
        return None;
    }
    if crate::legislator::source_bind::interpreter_from_command(command)
        != Some(crate::legislator::source_bind::InterpreterKind::Python)
    {
        return None;
    }
    if command.contains(['/', '\\']) {
        if spelled.is_absolute() {
            Some(spelled.to_path_buf())
        } else {
            std::env::current_dir().ok().map(|d| d.join(spelled))
        }
    } else {
        let hit = crate::verifier::hash::search_path(command)?;
        if crate::verifier::hash::same_file(&hit, program) {
            Some(hit)
        } else {
            tracing::warn!(
                "PYTHONEXECUTABLE not set: PATH resolution of '{command}' ({}) does not match the verified image {}",
                hit.display(),
                program.display()
            );
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::default_policy;

    /// Mark the sandbox as already applied so unit tests do not call
    /// `restrict_self()` / seccomp / native sandbox on the cargo test process.
    fn mark_sandbox_applied(warden: &Warden) {
        warden.sandbox_applied.set(true);
    }

    #[test]
    fn test_warden_new_with_default_policy() {
        let policy = default_policy();
        let warden = Warden::new(policy);
        assert_eq!(warden.policy().version, 1);
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    #[allow(deprecated)]
    fn test_apply_sandbox_noop_on_non_linux() {
        // apply_sandbox is a deprecated no-op on every platform.
        let policy = default_policy();
        let warden = Warden::new(policy);
        assert!(warden.apply_sandbox().is_ok());
    }

    #[test]
    #[allow(deprecated)]
    fn test_apply_sandbox_is_noop() {
        let policy = default_policy();
        let warden = Warden::new(policy);
        assert!(warden.apply_sandbox().is_ok());
        assert!(warden.apply_sandbox().is_ok());
        assert!(
            !warden.sandbox_applied.get(),
            "apply_sandbox must not mark parent sandboxing as applied"
        );
    }

    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    #[test]
    fn test_spawn_child_nonexistent_command() {
        let policy = default_policy();
        let warden = Warden::new(policy);
        #[cfg(target_os = "linux")]
        mark_sandbox_applied(&warden);
        let result = warden.spawn_child("__nonexistent_cmd_9999__", &[]);
        assert!(result.is_err());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn test_spawn_child_nonexistent_command_macos() {
        // On macOS, sandbox-exec is found so spawn() succeeds,
        // but the wrapped nonexistent command exits with failure.
        let policy = default_policy();
        let warden = Warden::new(policy);
        let result = warden.spawn_child("__nonexistent_cmd_9999__", &[]);
        match result {
            Ok(mut child) => {
                let status = child.wait().expect("should be able to wait");
                assert!(!status.success(), "nonexistent command should fail");
            }
            Err(_) => {
                // sandbox-exec not available — acceptable on some environments
            }
        }
    }

    #[test]
    fn test_spawn_child_returns_piped_io() {
        let policy = default_policy();
        let warden = Warden::new(policy);
        mark_sandbox_applied(&warden);
        #[cfg(windows)]
        let (cmd, args) = (
            "cmd",
            vec!["/c".to_string(), "echo".to_string(), "hello".to_string()],
        );
        #[cfg(not(windows))]
        let (cmd, args) = ("echo", vec!["hello".to_string()]);
        let mut child = warden
            .spawn_child(cmd, &args)
            .expect("command should be spawnable");
        assert!(child.has_stdin());
        assert!(child.has_stdout());
        let _ = child.wait();
    }
}
