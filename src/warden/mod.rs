use std::cell::Cell;
use std::path::{Path, PathBuf};

use crate::enforcement::EnforcementPlan;
#[cfg(target_os = "macos")]
use crate::enforcement::{ControlState, GrantSubject};
use crate::error::WardenError;
use crate::policy::Policy;

/// Options for child spawn. `run` builds them from the policy's
/// `defaults.environment` (restriction + allow list); without an
/// `environment` node the child inherits the ambient env unchanged.
///
/// Self-test (`generate-policy --self-test`) sets `restrict_environment` and a
/// private `tmpdir` so the short-lived child matches live-discovery's restricted
/// environment without using `--unsafe-unsandboxed-discovery`.
#[derive(Debug, Clone, Default)]
pub struct SpawnOptions {
    /// Clear the environment except PATH (and Windows roots) plus TMPDIR and
    /// each `allowed_names` entry found in the parent environment.
    pub restrict_environment: bool,
    /// Parent-environment variable names allowed through a restricted child
    /// environment (policy `defaults.environment` allow list). Consulted only
    /// when `restrict_environment` is set; a listed name missing from the
    /// parent stays unset.
    pub allowed_names: Vec<String>,
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
mod plan;
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
pub use plan::{SpawnAttempt, WardenReport};

use child::{RunningChildInner, apply_unix_process_group, apply_unix_process_group_tokio};
use env::{apply_spawn_env, spawn_env_pairs};

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
            // `sandbox-exec` does not expose whether the kernel accepted
            // the profile — this states the spawn mechanism, not kernel
            // confirmation.
            let child = macos_sandbox::spawn_sandboxed(&self.policy, command, args)
                .map(ChildProcess::Macos)?;
            tracing::info!(
                "Warden: child spawned via sandbox-exec; in-kernel profile \
                 acceptance is not observable"
            );
            Ok(child)
        }

        #[cfg(target_os = "windows")]
        {
            let mut grants = Vec::new();
            let child = windows_sandbox::spawn_sandboxed(
                &self.policy,
                None,
                command,
                args,
                &SpawnOptions::default(),
                &mut grants,
            )
            .map(ChildProcess::Windows)?;
            tracing::info!(
                "Warden: child created inside AppContainer (CreateProcessW is \
                 authoritative)"
            );
            Ok(child)
        }

        #[cfg(target_os = "linux")]
        {
            let sandbox_bits = linux_spawn::prepare_linux_child_sandbox(&self.policy)?;
            let mut cmd = std::process::Command::new(command);
            cmd.args(args)
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::inherit());
            apply_unix_process_group(&mut cmd);
            linux_spawn::attach_linux_pre_exec(&mut cmd, sandbox_bits);

            let child = cmd
                .spawn()
                .map(ChildProcess::Standard)
                .map_err(WardenError::ProcessSpawn)?;
            // Spawn returning means the pre_exec hooks ran: no_new_privs,
            // Landlock restrict_self (fail-closed), seccomp apply.
            tracing::info!("Warden: spawned child with Linux sandbox applied in pre_exec");
            Ok(child)
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
        self.spawn_child_async_impl(None, argv, opts, false).outcome
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
        self.spawn_child_async_exe_with(program, argv, &SpawnOptions::default())
    }

    /// [`Self::spawn_child_async_exe`] with environment / TMPDIR options.
    /// The environment restriction is part of the launch contract, so the
    /// caller passes the policy-derived options on every spawn — including
    /// the unsandboxed variants used for dry-run / `MCP_WRIT_SKIP_SANDBOX`.
    pub fn spawn_child_async_exe_with(
        &self,
        program: &Path,
        argv: &[String],
        opts: &SpawnOptions,
    ) -> Result<RunningChild, WardenError> {
        self.spawn_child_async_impl(Some(program), argv, opts, false)
            .outcome
    }

    /// [`Self::spawn_child_async_exe_with`] that also returns the
    /// enforcement report: the plan the spawn was built from plus the
    /// apply observations taken while spawning. `dry_run` only affects the
    /// report's RPC-control notes — the auditor decides whether violations
    /// block.
    pub fn spawn_child_async_exe_with_report(
        &self,
        program: &Path,
        argv: &[String],
        opts: &SpawnOptions,
        dry_run: bool,
    ) -> SpawnAttempt {
        self.spawn_child_async_impl(Some(program), argv, opts, dry_run)
    }

    fn spawn_child_async_impl(
        &self,
        program: Option<&Path>,
        argv: &[String],
        opts: &SpawnOptions,
        dry_run: bool,
    ) -> SpawnAttempt {
        if argv.is_empty() {
            return SpawnAttempt::err(
                WardenReport {
                    plan: plan::build_plan(&self.policy, program, "", opts, None, dry_run),
                    observations: Vec::new(),
                },
                WardenError::ProcessSpawn(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "command argv cannot be empty",
                )),
            );
        }
        if self.sandbox_applied.get() {
            return self.spawn_unsandboxed_async_impl(
                program,
                argv,
                opts,
                "sandbox_applied flag (test hook)",
                dry_run,
            );
        }
        let command = &argv[0];
        let args = &argv[1..];

        #[cfg(target_os = "windows")]
        {
            let mut controls = plan::shared_controls(&self.policy, opts, dry_run, false);
            controls.extend(plan::os_controls(&self.policy));
            let mut limitations = plan::base_limitations();
            plan::os_limitations(&self.policy, &mut limitations);
            let mut grants = Vec::new();
            let spawned = windows_sandbox::spawn_sandboxed(
                &self.policy,
                program,
                command,
                args,
                opts,
                &mut grants,
            )
            .and_then(|mut win_child| {
                let stdin_file = win_child.stdin.take().ok_or_else(|| {
                    WardenError::ProcessSpawn(std::io::Error::other(
                        "failed to capture child stdin",
                    ))
                })?;
                let stdout_file = win_child.stdout.take().ok_or_else(|| {
                    WardenError::ProcessSpawn(std::io::Error::other(
                        "failed to capture child stdout",
                    ))
                })?;
                let async_stdin = tokio::fs::File::from_std(stdin_file);
                let async_stdout = tokio::fs::File::from_std(stdout_file);
                Ok(RunningChild {
                    stdin: Some(Box::new(async_stdin)),
                    stdout: Some(Box::new(async_stdout)),
                    inner: RunningChildInner::Windows(std::sync::Arc::new(win_child)),
                })
            });
            let spawn_err = spawned.as_ref().err().map(|e| e.to_string());
            let mut observations =
                plan::os_spawn_observations(&controls, &grants, spawned.as_ref().err());
            if let Some(o) = plan::env_observation(spawn_env_pairs(opts).is_some(), spawn_err) {
                observations.push(o);
            }
            let report = WardenReport {
                plan: EnforcementPlan {
                    controls,
                    grants,
                    tools: plan::tools_table(&self.policy),
                    limitations,
                },
                observations,
            };
            match spawned {
                Ok(child) => {
                    tracing::info!(
                        "Warden: child created inside AppContainer (CreateProcessW is \
                         authoritative)"
                    );
                    SpawnAttempt::ok(report, child)
                }
                Err(source) => SpawnAttempt::err(report, source),
            }
        }

        #[cfg(target_os = "macos")]
        {
            let mut controls = plan::shared_controls(&self.policy, opts, dry_run, true);
            controls.extend(plan::os_controls(&self.policy));
            let mut limitations = plan::base_limitations();
            plan::os_limitations(&self.policy, &mut limitations);

            // Prepare the profile and private TMPDIR; a failure here is a
            // construction failure — OS controls are marked Failed in the
            // plan and no apply observation exists.
            let prepared = (|| -> Result<(macos_sandbox::PrivateTmpDir, String, Vec<crate::enforcement::ProcessGrant>), WardenError> {
                let tmpdir = macos_sandbox::create_private_tmpdir()?;
                let (sbpl, mut grants) = macos_sandbox::sbpl_profile(
                    &self.policy,
                    tmpdir.path().to_string_lossy().as_ref(),
                )?;
                // The private directory now exists on disk — the creation
                // half of this grant is verified (its sandbox coverage is
                // part of the unobservable profile acceptance).
                for g in &mut grants {
                    if matches!(g.subject, GrantSubject::PrivateTmpdir) {
                        g.state = ControlState::Verified;
                    }
                }
                Ok((tmpdir, sbpl, grants))
            })();
            let (tmpdir, sbpl, grants) = match prepared {
                Ok(v) => v,
                Err(source) => {
                    plan::fail_os_controls(&mut controls, &source);
                    let report = WardenReport {
                        plan: EnforcementPlan {
                            controls,
                            grants: Vec::new(),
                            tools: plan::tools_table(&self.policy),
                            limitations,
                        },
                        observations: Vec::new(),
                    };
                    return SpawnAttempt::err(report, source);
                }
            };
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
            let env_applied = spawn_env_pairs(&env_opts).is_some();
            if let Some(exe) = python_executable_override(command, program) {
                cmd.env("PYTHONEXECUTABLE", exe);
            }
            apply_unix_process_group_tokio(&mut cmd);
            let spawned = cmd.spawn();
            let spawn_err = spawned.as_ref().err().map(|e| e.to_string());
            let mut observations = plan::os_spawn_observations(&controls, spawned.as_ref().err());
            if let Some(o) = plan::env_observation(env_applied, spawn_err) {
                observations.push(o);
            }
            let report = WardenReport {
                plan: EnforcementPlan {
                    controls,
                    grants,
                    tools: plan::tools_table(&self.policy),
                    limitations,
                },
                observations,
            };
            match spawned {
                Ok(mut child) => {
                    tracing::info!(
                        "Warden: child spawned via sandbox-exec; in-kernel profile \
                         acceptance is not observable"
                    );
                    let stdin = child.stdin.take().ok_or_else(|| {
                        WardenError::ProcessSpawn(std::io::Error::other(
                            "failed to capture child stdin",
                        ))
                    });
                    let stdout = child.stdout.take().ok_or_else(|| {
                        WardenError::ProcessSpawn(std::io::Error::other(
                            "failed to capture child stdout",
                        ))
                    });
                    match (stdin, stdout) {
                        (Ok(stdin), Ok(stdout)) => SpawnAttempt::ok(
                            report,
                            RunningChild {
                                stdin: Some(Box::new(stdin)),
                                stdout: Some(Box::new(stdout)),
                                inner: RunningChildInner::Tokio(Box::new(child)),
                                _tmpdir: Some(tmpdir),
                            },
                        ),
                        (Err(e), _) | (_, Err(e)) => SpawnAttempt::err(report, e),
                    }
                }
                Err(e) => SpawnAttempt::err(report, WardenError::ProcessSpawn(e)),
            }
        }

        #[cfg(target_os = "linux")]
        {
            let mut controls = plan::shared_controls(&self.policy, opts, dry_run, false);
            controls.extend(plan::os_controls(&self.policy));
            let mut limitations = plan::base_limitations();
            plan::os_limitations(&self.policy, &mut limitations);

            let mut sandbox_bits = match linux_spawn::prepare_linux_child_sandbox(&self.policy) {
                Ok(bits) => bits,
                Err(source) => {
                    plan::fail_os_controls(&mut controls, &source);
                    let report = WardenReport {
                        plan: EnforcementPlan {
                            controls,
                            grants: Vec::new(),
                            tools: plan::tools_table(&self.policy),
                            limitations,
                        },
                        observations: Vec::new(),
                    };
                    return SpawnAttempt::err(report, source);
                }
            };
            let grants = std::mem::take(&mut sandbox_bits.grants);
            let allow_degraded = sandbox_bits.allow_degraded;
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
            let env_applied = spawn_env_pairs(opts).is_some();
            apply_unix_process_group_tokio(&mut cmd);
            linux_spawn::attach_linux_pre_exec_tokio(&mut cmd, sandbox_bits);
            let spawned = cmd.spawn();
            let spawn_err = spawned.as_ref().err().map(|e| e.to_string());
            let mut observations =
                plan::os_spawn_observations(&controls, allow_degraded, spawned.as_ref().err());
            if let Some(o) = plan::env_observation(env_applied, spawn_err) {
                observations.push(o);
            }
            let report = WardenReport {
                plan: EnforcementPlan {
                    controls,
                    grants,
                    tools: plan::tools_table(&self.policy),
                    limitations,
                },
                observations,
            };
            match spawned {
                Ok(mut child) => {
                    // Spawn returning means the pre_exec hooks ran:
                    // no_new_privs, Landlock restrict_self (fail-closed),
                    // seccomp apply.
                    tracing::info!("Warden: spawned child with Linux sandbox applied in pre_exec");
                    let stdin = child.stdin.take().ok_or_else(|| {
                        WardenError::ProcessSpawn(std::io::Error::other(
                            "failed to capture child stdin",
                        ))
                    });
                    let stdout = child.stdout.take().ok_or_else(|| {
                        WardenError::ProcessSpawn(std::io::Error::other(
                            "failed to capture child stdout",
                        ))
                    });
                    match (stdin, stdout) {
                        (Ok(stdin), Ok(stdout)) => SpawnAttempt::ok(
                            report,
                            RunningChild {
                                stdin: Some(Box::new(stdin)),
                                stdout: Some(Box::new(stdout)),
                                inner: RunningChildInner::Tokio(Box::new(child)),
                            },
                        ),
                        (Err(e), _) | (_, Err(e)) => SpawnAttempt::err(report, e),
                    }
                }
                Err(e) => SpawnAttempt::err(report, WardenError::ProcessSpawn(e)),
            }
        }

        #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
        {
            tracing::warn!(
                "Warden: sandbox not available on this platform. Running unconstrained."
            );
            self.spawn_unsandboxed_async_impl(
                program,
                argv,
                opts,
                "no OS sandbox mechanism on this platform",
                dry_run,
            )
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
        self.spawn_unsandboxed_async_impl(None, argv, opts, "unsandboxed spawn requested", false)
            .outcome
    }

    /// Unsandboxed variant of [`Self::spawn_child_async_exe`].
    pub fn spawn_unsandboxed_async_exe(
        &self,
        program: &Path,
        argv: &[String],
    ) -> Result<RunningChild, WardenError> {
        self.spawn_unsandboxed_async_exe_with(program, argv, &SpawnOptions::default())
    }

    /// Unsandboxed variant of [`Self::spawn_child_async_exe_with`]. The
    /// environment restriction still applies — only the OS sandbox is
    /// skipped.
    pub fn spawn_unsandboxed_async_exe_with(
        &self,
        program: &Path,
        argv: &[String],
        opts: &SpawnOptions,
    ) -> Result<RunningChild, WardenError> {
        self.spawn_unsandboxed_async_impl(
            Some(program),
            argv,
            opts,
            "unsandboxed spawn requested",
            false,
        )
        .outcome
    }

    /// [`Self::spawn_unsandboxed_async_exe_with`] that also returns the
    /// enforcement report — its OS controls are `Skipped` with `reason`
    /// (e.g. `dry-run`, `MCP_WRIT_SKIP_SANDBOX`) and it carries no
    /// sandbox grants.
    pub fn spawn_unsandboxed_async_exe_with_report(
        &self,
        program: &Path,
        argv: &[String],
        opts: &SpawnOptions,
        reason: &'static str,
        dry_run: bool,
    ) -> SpawnAttempt {
        self.spawn_unsandboxed_async_impl(Some(program), argv, opts, reason, dry_run)
    }

    fn spawn_unsandboxed_async_impl(
        &self,
        program: Option<&Path>,
        argv: &[String],
        opts: &SpawnOptions,
        skip_reason: &'static str,
        dry_run: bool,
    ) -> SpawnAttempt {
        let plan_report = || WardenReport {
            plan: plan::build_plan(
                &self.policy,
                program,
                argv.first().map(String::as_str).unwrap_or(""),
                opts,
                Some(skip_reason),
                dry_run,
            ),
            observations: Vec::new(),
        };
        if argv.is_empty() {
            return SpawnAttempt::err(
                plan_report(),
                WardenError::ProcessSpawn(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "command argv cannot be empty",
                )),
            );
        }
        tracing::info!("Warden: sandbox skipped ({skip_reason})");

        // Windows: keep the verified image (lpApplicationName) separate
        // from the caller's argv[0], exactly like the sandboxed path —
        // Command cannot express the split on this platform.
        #[cfg(target_os = "windows")]
        if let Some(p) = program {
            let spawned = windows_proc::spawn_unsandboxed(Some(p), &argv[0], &argv[1..], opts)
                .and_then(|mut win_child| {
                    let stdin_file = win_child.stdin.take().ok_or_else(|| {
                        WardenError::ProcessSpawn(std::io::Error::other(
                            "failed to capture child stdin",
                        ))
                    })?;
                    let stdout_file = win_child.stdout.take().ok_or_else(|| {
                        WardenError::ProcessSpawn(std::io::Error::other(
                            "failed to capture child stdout",
                        ))
                    })?;
                    let async_stdin = tokio::fs::File::from_std(stdin_file);
                    let async_stdout = tokio::fs::File::from_std(stdout_file);
                    Ok(RunningChild {
                        stdin: Some(Box::new(async_stdin)),
                        stdout: Some(Box::new(async_stdout)),
                        inner: RunningChildInner::Windows(std::sync::Arc::new(win_child)),
                    })
                });
            let mut report = plan_report();
            if let Some(o) = plan::env_observation(
                spawn_env_pairs(opts).is_some(),
                spawned.as_ref().err().map(|e| e.to_string()),
            ) {
                report.observations.push(o);
            }
            return match spawned {
                Ok(child) => SpawnAttempt::ok(report, child),
                Err(source) => SpawnAttempt::err(report, source),
            };
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
        let spawned = cmd.spawn();
        let mut report = plan_report();
        if let Some(o) = plan::env_observation(
            spawn_env_pairs(opts).is_some(),
            spawned.as_ref().err().map(|e| e.to_string()),
        ) {
            report.observations.push(o);
        }
        match spawned {
            Ok(mut child) => {
                let stdin = child.stdin.take().ok_or_else(|| {
                    WardenError::ProcessSpawn(std::io::Error::other(
                        "failed to capture child stdin",
                    ))
                });
                let stdout = child.stdout.take().ok_or_else(|| {
                    WardenError::ProcessSpawn(std::io::Error::other(
                        "failed to capture child stdout",
                    ))
                });
                match (stdin, stdout) {
                    (Ok(stdin), Ok(stdout)) => SpawnAttempt::ok(
                        report,
                        RunningChild {
                            stdin: Some(Box::new(stdin)),
                            stdout: Some(Box::new(stdout)),
                            inner: RunningChildInner::Tokio(Box::new(child)),
                            #[cfg(target_os = "macos")]
                            _tmpdir: None,
                        },
                    ),
                    (Err(e), _) | (_, Err(e)) => SpawnAttempt::err(report, e),
                }
            }
            Err(e) => SpawnAttempt::err(report, WardenError::ProcessSpawn(e)),
        }
    }

    /// The enforcement plan for a spawn under `opts` — generated by the
    /// same rule builders the spawn paths use (their artifacts are
    /// discarded). Nothing is applied and no process is spawned.
    ///
    /// `sandbox_skip` describes a deliberately unsandboxed launch
    /// (dry-run / `MCP_WRIT_SKIP_SANDBOX`): OS controls become `Skipped`
    /// and no grants are produced — the plan reflects what that launch
    /// does, which is "no OS sandbox".
    pub fn enforcement_plan(
        &self,
        program: Option<&Path>,
        command: &str,
        opts: &SpawnOptions,
        sandbox_skip: Option<&'static str>,
        dry_run: bool,
    ) -> EnforcementPlan {
        plan::build_plan(&self.policy, program, command, opts, sandbox_skip, dry_run)
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
    if crate::workload::interpreter_from_command(command)
        != Some(crate::workload::InterpreterKind::Python)
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
        let hit = crate::workload::search_path(command)?;
        if crate::workload::same_file(&hit, program) {
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
