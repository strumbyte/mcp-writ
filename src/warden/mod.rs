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
            .map_err(|e| e.source)
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
            let apply_record = linux_spawn::attach_linux_pre_exec(&mut cmd, sandbox_bits);

            let spawned = cmd.spawn();
            // The shared record holds the kernel-reported apply result
            // the pre-exec child wrote. This sync path has no launch
            // report to feed it to (`spawn_child_async_impl` does), so
            // it stays diagnostic — except a failed stage beside a
            // successful spawn, which the record contract says cannot
            // be produced honestly and is surfaced at warn level.
            if let Some(snap) = apply_record.as_ref().map(|r| r.snapshot()) {
                // Same predicate `linux_control_observation` applies: a
                // recorded failure is honest only beside a failed spawn
                // with `stage == failed_stage - 1`.
                let inconsistent = snap.failed_stage != linux_spawn::stage::NONE
                    && (spawned.is_ok() || snap.stage.checked_add(1) != Some(snap.failed_stage));
                if inconsistent {
                    tracing::warn!(
                        stage = snap.stage,
                        failed_stage = snap.failed_stage,
                        landlock = snap.landlock,
                        landlock_abi = snap.landlock_abi,
                        errno = snap.errno,
                        "Warden: inconsistent Linux child apply record \
                         (a recorded failure cannot pair with this spawn result)"
                    );
                } else {
                    tracing::debug!(
                        stage = snap.stage,
                        failed_stage = snap.failed_stage,
                        landlock = snap.landlock,
                        landlock_abi = snap.landlock_abi,
                        errno = snap.errno,
                        "Warden: Linux child apply record"
                    );
                }
            }
            let child = spawned
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
    pub async fn spawn_child_async(&self, argv: &[String]) -> Result<RunningChild, WardenError> {
        self.spawn_child_async_with(argv, &SpawnOptions::default())
            .await
    }

    /// Same as [`Self::spawn_child_async`] with environment / TMPDIR options.
    pub async fn spawn_child_async_with(
        &self,
        argv: &[String],
        opts: &SpawnOptions,
    ) -> Result<RunningChild, WardenError> {
        self.spawn_child_async_impl(None, argv, opts, false)
            .await
            .outcome
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
    pub async fn spawn_child_async_exe(
        &self,
        program: &Path,
        argv: &[String],
    ) -> Result<RunningChild, WardenError> {
        self.spawn_child_async_exe_with(program, argv, &SpawnOptions::default())
            .await
    }

    /// [`Self::spawn_child_async_exe`] with environment / TMPDIR options.
    /// The environment restriction is part of the launch contract, so the
    /// caller passes the policy-derived options on every spawn — including
    /// the unsandboxed variants used for dry-run / `MCP_WRIT_SKIP_SANDBOX`.
    pub async fn spawn_child_async_exe_with(
        &self,
        program: &Path,
        argv: &[String],
        opts: &SpawnOptions,
    ) -> Result<RunningChild, WardenError> {
        self.spawn_child_async_impl(Some(program), argv, opts, false)
            .await
            .outcome
    }

    /// [`Self::spawn_child_async_exe_with`] that also returns the
    /// enforcement report: the plan the spawn was built from plus the
    /// apply observations taken while spawning. `dry_run` only affects the
    /// report's RPC-control notes — the auditor decides whether violations
    /// block.
    pub async fn spawn_child_async_exe_with_report(
        &self,
        program: &Path,
        argv: &[String],
        opts: &SpawnOptions,
        dry_run: bool,
    ) -> SpawnAttempt {
        self.spawn_child_async_impl(Some(program), argv, opts, dry_run)
            .await
    }

    async fn spawn_child_async_impl(
        &self,
        program: Option<&Path>,
        argv: &[String],
        opts: &SpawnOptions,
        dry_run: bool,
    ) -> SpawnAttempt {
        if argv.is_empty() {
            return SpawnAttempt::err(
                WardenReport {
                    // Rejected before any sandbox work: OS controls read
                    // `Skipped`, never `Failed` by an unrelated ruleset
                    // build (on Linux `build_plan` would otherwise run
                    // Landlock/seccomp construction here).
                    plan: plan::build_plan(
                        &self.policy,
                        program,
                        "",
                        opts,
                        Some("launch rejected: empty argv"),
                        dry_run,
                    ),
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
            // Observations are taken from `spawn_sandboxed` alone: it owns
            // the whole OS-control pipeline (profile, capability/ACL
            // grants, CreateProcessW), so its result is the mechanism
            // result. The post-spawn stdio capture below is not part of
            // OS enforcement and must not mark controls Failed.
            let spawned = windows_sandbox::spawn_sandboxed(
                &self.policy,
                program,
                command,
                args,
                opts,
                &mut grants,
            );
            let spawn_err = spawned.as_ref().err().map(|e| e.to_string());
            // `windows_spawn_outcome` generates the observations while
            // the controls are still `Planned` — failing the plan first
            // would leave a setup abort with failed controls and no
            // per-control evidence — and only then marks the plan for a
            // provable pre-`CreateProcessW` (`Policy`/`Prepare` sourced)
            // construction failure. Post-create stages keep their
            // per-control outcomes in the observations alone.
            let mut observations =
                plan::windows_spawn_outcome(&mut controls, &grants, spawned.as_ref().err());
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
                Ok(mut win_child) => {
                    tracing::info!(
                        "Warden: child created inside AppContainer (CreateProcessW is \
                         authoritative)"
                    );
                    // CreateProcessW already ran inside the AppContainer;
                    // only the stdio plumbing can still fail here.
                    let stdin = win_child.stdin.take().ok_or_else(|| {
                        WardenError::ProcessSpawn(std::io::Error::other(
                            "failed to capture child stdin",
                        ))
                    });
                    let stdout = win_child.stdout.take().ok_or_else(|| {
                        WardenError::ProcessSpawn(std::io::Error::other(
                            "failed to capture child stdout",
                        ))
                    });
                    match (stdin, stdout) {
                        (Ok(stdin_file), Ok(stdout_file)) => {
                            let async_stdin = tokio::fs::File::from_std(stdin_file);
                            let async_stdout = tokio::fs::File::from_std(stdout_file);
                            SpawnAttempt::ok(
                                report,
                                RunningChild {
                                    stdin: Some(Box::new(async_stdin)),
                                    stdout: Some(Box::new(async_stdout)),
                                    inner: RunningChildInner::Windows(std::sync::Arc::new(
                                        win_child,
                                    )),
                                },
                            )
                        }
                        (Err(e), _) | (_, Err(e)) => SpawnAttempt::err(report, e),
                    }
                }
                Err(e) => SpawnAttempt::err(report, e.source),
            }
        }

        #[cfg(target_os = "macos")]
        {
            let mut controls = plan::shared_controls(&self.policy, opts, dry_run, true);
            controls.extend(plan::os_controls(&self.policy));
            let mut limitations = plan::base_limitations();
            plan::os_limitations(&self.policy, &mut limitations);
            let mut observations = Vec::new();

            // Prepare the profile and private TMPDIR; a failure here is a
            // construction failure — OS controls are marked Failed in the
            // plan and the build observation carries the stage detail.
            let prepared = (|| -> Result<(macos_sandbox::PrivateTmpDir, String, Vec<crate::enforcement::ProcessGrant>), (&'static str, WardenError)> {
                let tmpdir = macos_sandbox::create_private_tmpdir()
                    .map_err(|e| ("private tmpdir creation failed", e))?;
                let (sbpl, mut grants) = macos_sandbox::sbpl_profile(
                    &self.policy,
                    tmpdir.path().to_string_lossy().as_ref(),
                )
                .map_err(|e| ("profile build failed", e))?;
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
                Ok(v) => {
                    observations.push(plan::macos_prepare_observation(None));
                    v
                }
                Err((stage, source)) => {
                    plan::fail_os_controls(&mut controls, stage, &source);
                    observations.push(plan::macos_prepare_observation(Some((stage, &source))));
                    let report = WardenReport {
                        plan: EnforcementPlan {
                            controls,
                            grants: Vec::new(),
                            tools: plan::tools_table(&self.policy),
                            limitations,
                        },
                        observations,
                    };
                    return SpawnAttempt::err(report, source);
                }
            };
            let mut cmd = tokio::process::Command::new("sandbox-exec");
            cmd.arg("-p").arg(&sbpl).arg("--");
            // sandbox-exec re-execs the given path with argv[0] equal to
            // that path, so a distinct verified executable goes through
            // bash — `exec -a` is a bash builtin, while /bin/sh may
            // resolve (via /var/select/sh) to a shell that lacks it. `-p`
            // keeps the wrapper in privileged mode: $ENV/$BASH_ENV are
            // not read, exported functions are not imported, and
            // SHELLOPTS/BASHOPTS/CDPATH/GLOBIGNORE from the environment
            // are ignored — a hostile spawn environment cannot reshape
            // the launch. `builtin` pins the exec call to the builtin as
            // well, so no inherited function name can intercept it.
            match program {
                Some(p) if p != Path::new(command) => {
                    cmd.arg("/bin/bash")
                        .arg("-p")
                        .arg("-c")
                        .arg("builtin exec -a \"$0\" \"$@\"")
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
            let mut spawned = cmd.spawn();
            // `spawn()` proves only that the sandbox-exec binary ran: a
            // rejected profile or an un-exec'able workload exits the
            // process within milliseconds, so a bounded liveness probe is
            // the only post-spawn evidence available. It is recorded on
            // `os.sandbox`; per-rule kernel acceptance stays unobserved,
            // and an early exit alone cannot be told apart from a
            // workload that finished quickly.
            let liveness = match spawned.as_mut() {
                Ok(child) => Some(macos_sandbox::initial_exit_check(child).await),
                Err(_) => None,
            };
            if let Some(macos_sandbox::SpawnLiveness::Exited(status)) = &liveness {
                tracing::warn!(
                    "Warden: sandbox-exec child exited ({status}) inside the \
                     initial-exit window — profile rejection, exec failure, \
                     or a workload that simply finished quickly all surface \
                     this way"
                );
            }
            let spawn_err = spawned.as_ref().err().map(|e| e.to_string());
            observations.extend(plan::os_spawn_observations(
                &controls,
                spawned.as_ref().err(),
                liveness.as_ref(),
            ));
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
                    plan::fail_os_controls(&mut controls, "rule build failed", &source);
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
            let apply_record = linux_spawn::attach_linux_pre_exec_tokio(&mut cmd, sandbox_bits);
            let spawned = cmd.spawn();
            // The pre-exec child's own apply record — readable now that
            // spawn returned, unforgeable by the exec'd workload.
            let apply_snapshot = apply_record.as_ref().map(|r| r.snapshot());
            let spawn_err = spawned.as_ref().err().map(|e| e.to_string());
            let mut observations = plan::os_spawn_observations(
                &controls,
                apply_snapshot.as_ref(),
                spawned.as_ref().err(),
            );
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
            // The env observation reflects the `CreateProcessW` result
            // alone; post-spawn stdio capture is not part of the env
            // contract and must not mark it unobserved.
            let spawned = windows_proc::spawn_unsandboxed(Some(p), &argv[0], &argv[1..], opts);
            let mut report = plan_report();
            if let Some(o) = plan::env_observation(
                spawn_env_pairs(opts).is_some(),
                spawned.as_ref().err().map(|e| e.to_string()),
            ) {
                report.observations.push(o);
            }
            return match spawned {
                Ok(mut win_child) => {
                    let stdin = win_child.stdin.take().ok_or_else(|| {
                        WardenError::ProcessSpawn(std::io::Error::other(
                            "failed to capture child stdin",
                        ))
                    });
                    let stdout = win_child.stdout.take().ok_or_else(|| {
                        WardenError::ProcessSpawn(std::io::Error::other(
                            "failed to capture child stdout",
                        ))
                    });
                    match (stdin, stdout) {
                        (Ok(stdin_file), Ok(stdout_file)) => {
                            let async_stdin = tokio::fs::File::from_std(stdin_file);
                            let async_stdout = tokio::fs::File::from_std(stdout_file);
                            SpawnAttempt::ok(
                                report,
                                RunningChild {
                                    stdin: Some(Box::new(async_stdin)),
                                    stdout: Some(Box::new(async_stdout)),
                                    inner: RunningChildInner::Windows(std::sync::Arc::new(
                                        win_child,
                                    )),
                                },
                            )
                        }
                        (Err(e), _) | (_, Err(e)) => SpawnAttempt::err(report, e),
                    }
                }
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

    #[tokio::test]
    async fn test_empty_argv_rejects_without_touching_os_controls() {
        let policy = default_policy();
        let warden = Warden::new(policy);
        let attempt = warden
            .spawn_child_async_exe_with_report(
                Path::new("child"),
                &[],
                &SpawnOptions::default(),
                false,
            )
            .await;
        assert!(attempt.outcome.is_err());
        // The launch is rejected before the sandbox stage: OS controls
        // read `Skipped` — never left `Planned`, and never `Failed` by an
        // unrelated ruleset build (`build_plan` must not run the OS
        // grant builders for a rejected launch).
        for c in &attempt.report.plan.controls {
            if c.layer == crate::enforcement::ControlLayer::Os {
                assert!(
                    matches!(
                        c.state,
                        crate::enforcement::ControlState::Skipped
                            | crate::enforcement::ControlState::NotApplicable
                            | crate::enforcement::ControlState::NotApplied
                    ),
                    "{} must not be Planned/Failed, got {:?}",
                    c.id,
                    c.state
                );
            }
        }
        assert!(attempt.report.plan.grants.is_empty());
        assert!(attempt.report.observations.is_empty());
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

    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn test_spawn_report_records_verified_launch_for_running_child() {
        use crate::enforcement::{ControlPhase, ControlState, GrantSubject};

        let policy = default_policy();
        let warden = Warden::new(policy);
        let argv = vec![
            "/bin/sh".to_string(),
            "-c".to_string(),
            "sleep 30".to_string(),
        ];
        let attempt = warden
            .spawn_child_async_exe_with_report(
                Path::new("/bin/sh"),
                &argv,
                &SpawnOptions::default(),
                false,
            )
            .await;
        let mut child = attempt.outcome.expect("sandboxed sh should spawn");
        let obs = &attempt.report.observations;

        // os.sandbox carries the build-phase preparation result and the
        // spawn-phase liveness result — in that order.
        let sandbox: Vec<_> = obs.iter().filter(|o| o.control == "os.sandbox").collect();
        assert_eq!(sandbox.len(), 2);
        assert_eq!(sandbox[0].phase, ControlPhase::Build);
        assert_eq!(sandbox[0].state, ControlState::Verified);
        assert_eq!(sandbox[1].phase, ControlPhase::Spawn);
        assert_eq!(sandbox[1].state, ControlState::Verified);

        // Kernel acceptance of the SBPL rules stays unobserved — a live
        // process is not upgraded into an applied claim.
        for id in ["os.fs", "os.net.outbound", "os.process"] {
            let o = obs.iter().find(|o| o.control == id).unwrap();
            assert_eq!(o.state, ControlState::Unknown, "{id}");
        }

        // The private TMPDIR grant carries its verified creation.
        let tmp = attempt
            .report
            .plan
            .grants
            .iter()
            .find(|g| matches!(g.subject, GrantSubject::PrivateTmpdir))
            .expect("private TMPDIR grant");
        assert_eq!(tmp.state, ControlState::Verified);

        let _ = child.kill().await;
    }

    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn test_spawn_report_flags_immediate_exit() {
        use crate::enforcement::{ControlPhase, ControlState};

        // `exit 3` dies inside the initial-exit window the same way a
        // rejected profile or an un-exec'able workload does: the exit
        // alone cannot distinguish them, so the launch control records
        // the status and reads Unknown, the rule domains stay Unknown,
        // and the spawn outcome itself is unaffected (the caller sees
        // the EOF).
        let policy = default_policy();
        let warden = Warden::new(policy);
        let argv = vec![
            "/bin/sh".to_string(),
            "-c".to_string(),
            "exit 3".to_string(),
        ];
        let attempt = warden
            .spawn_child_async_exe_with_report(
                Path::new("/bin/sh"),
                &argv,
                &SpawnOptions::default(),
                false,
            )
            .await;
        let mut child = attempt.outcome.expect("spawn returns the child handle");
        let obs = &attempt.report.observations;

        let launch = obs
            .iter()
            .filter(|o| o.control == "os.sandbox")
            .find(|o| o.phase == ControlPhase::Spawn)
            .unwrap();
        assert_eq!(launch.state, ControlState::Unknown);
        assert!(
            launch.reason.as_deref().unwrap().contains("exit status: 3"),
            "{:?}",
            launch.reason
        );
        for id in ["os.fs", "os.net.outbound", "os.process"] {
            let o = obs.iter().find(|o| o.control == id).unwrap();
            assert_eq!(o.state, ControlState::Unknown, "{id}");
        }

        let status = child.wait_for_natural_exit().await.unwrap();
        assert!(!status.success());
    }
}
