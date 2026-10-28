use super::*;

impl Warden {
    /// Spawn a child process with the sandbox applied to the child.
    ///
    /// - Linux: Landlock + seccomp applied in `pre_exec` (does not break parent proxy)
    /// - Windows: AppContainer sandbox, or a PSEC security environment
    ///   when `--windows-mechanism psec` was selected
    /// - macOS: sandbox-exec
    ///
    /// A non-default Windows mechanism on a non-Windows host refuses —
    /// the mechanism cannot silently downgrade to the platform default.
    pub fn spawn_child(&self, command: &str, args: &[String]) -> Result<ChildProcess, WardenError> {
        if self.sandbox_applied.get() {
            return self.spawn_unsandboxed(command, args);
        }
        if let Some(reason) = self.mechanism_unavailable_reason() {
            return Err(WardenError::sandbox_setup(
                crate::error::SandboxStage::Prepare,
                reason,
            ));
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
            let spawned = match self.windows_mechanism {
                WindowsNativeMechanism::AppContainer => windows_sandbox::spawn_sandboxed(
                    &self.policy,
                    None,
                    command,
                    args,
                    &SpawnOptions::default(),
                    &mut grants,
                ),
                WindowsNativeMechanism::Psec => windows_psec::spawn_sandboxed(
                    &self.policy,
                    None,
                    command,
                    args,
                    &SpawnOptions::default(),
                    &mut grants,
                ),
            };
            let child = spawned
                .map_err(|e| e.into_warden_error())
                .map(ChildProcess::Windows)?;
            tracing::info!(
                "Warden: child spawned under mechanism={} (CreateProcessW is \
                 authoritative)",
                self.windows_mechanism.name()
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
                // The workload's stderr is attacker-controlled — pipe
                // it through the sanitized relay, never raw to the
                // terminal.
                .stderr(std::process::Stdio::piped());
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
                .map(|mut c| {
                    if let Some(err) = c.stderr.take() {
                        crate::termutil::relay_child_stderr_blocking(err);
                    }
                    ChildProcess::Standard(child::StdChild::spawned(c))
                })
                .map_err(WardenError::ProcessSpawn)?;
            // Spawn returning means the pre_exec hooks ran: no_new_privs,
            // Landlock restrict_self (fail-closed), seccomp apply.
            tracing::info!("Warden: spawned child with Linux sandbox applied in pre_exec");
            Ok(child)
        }

        #[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
        {
            // Fail closed: a `spawn_child` result must mean a sandboxed
            // child. Unconstrained execution on an unsupported platform
            // is only reachable through the explicitly-named
            // `spawn_unsandboxed` API.
            let _ = (command, args);
            Err(WardenError::sandbox_setup(
                crate::error::SandboxStage::Prepare,
                "no OS sandbox mechanism on this platform; refusing to \
                 spawn unconstrained (use spawn_unsandboxed for a \
                 documented unsandboxed launch)",
            ))
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
            // Unsandboxed does not mean trusted — the workload's
            // stderr still crosses to the terminal sanitized.
            .stderr(std::process::Stdio::piped());
        apply_unix_process_group(&mut cmd);
        // No sandbox does not mean the launcher's ambient descriptors
        // should leak — the child seals everything above stdio before
        // exec drops them.
        #[cfg(unix)]
        attach_fd_hygiene(&mut cmd, &[]).map_err(|e| {
            WardenError::sandbox_setup(crate::error::SandboxStage::Prepare, e.to_string())
        })?;
        cmd.spawn()
            .map(|mut c| {
                if let Some(err) = c.stderr.take() {
                    crate::termutil::relay_child_stderr_blocking(err);
                }
                ChildProcess::Standard(child::StdChild::spawned(c))
            })
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
        self.spawn_child_async_impl(None, argv, opts, false, None, None)
            .await
            .outcome
    }

    /// Linux only: like [`Self::spawn_child_async_with`], but also arms
    /// the seccomp user-notification stage for `unotify_nrs` — the
    /// child's `pre_exec` installs the notification filter and hands
    /// the listener fd back. The caller owns answering the
    /// notifications; an unanswered notification leaves the triggering
    /// task suspended, and a dropped listener makes the kernel fail
    /// every watched syscall `ENOSYS`.
    ///
    /// Arming or handoff failure fails the spawn rather than falling
    /// back to an unsupervised child.
    #[cfg(target_os = "linux")]
    pub async fn spawn_child_async_unotify(
        &self,
        argv: &[String],
        opts: &SpawnOptions,
        unotify_nrs: &[u32],
    ) -> Result<(RunningChild, std::fs::File), WardenError> {
        let mut child = self
            .spawn_child_async_impl(None, argv, opts, false, Some(unotify_nrs), None)
            .await
            .outcome?;
        let listener = child.take_unotify_listener().ok_or_else(|| {
            WardenError::sandbox_setup(
                crate::error::SandboxStage::Apply,
                "unotify-armed spawn returned without a listener fd",
            )
        })?;
        Ok((child, listener))
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
        self.spawn_child_async_impl(Some(program), argv, opts, false, None, None)
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
        self.spawn_child_async_impl(Some(program), argv, opts, dry_run, None, None)
            .await
    }

    /// [`Self::spawn_child_async_exe_with_report`] with the namespaced
    /// session context — `ns_ctx` carries the audit sink, correlation
    /// id, and resolved DNS upstream the proxy/gate share. It is read
    /// only when the Linux selection resolved `namespaced`; `None`
    /// there is a dispatch error (fail-closed refusal), and `Some`
    /// under any other selection is ignored.
    pub async fn spawn_child_async_exe_with_report_ctx(
        &self,
        program: &Path,
        argv: &[String],
        opts: &SpawnOptions,
        dry_run: bool,
        ns_ctx: Option<NamespacedLaunchCtx>,
    ) -> SpawnAttempt {
        self.spawn_child_async_impl(Some(program), argv, opts, dry_run, None, ns_ctx)
            .await
    }

    /// The env contract a spawn-side `launch.env` observation reports:
    /// the snapshot bound by [`Self::set_env_contract`] when the launch
    /// captured one *for these options* — the same view the stderr
    /// warnings and `server.connected` details carry — else a fresh
    /// parent-env read, both for callers that never ran the warning
    /// pass and for a spawn whose restriction no longer matches the
    /// bound snapshot's, so the observation always reflects the
    /// allowlist this child is actually filtered with.
    fn env_contract_for(&self, opts: &SpawnOptions) -> Option<env::EnvContractReport> {
        self.env_contract
            .as_ref()
            .filter(|bound| {
                bound.restrict_environment == opts.restrict_environment
                    && bound.allowed_names == opts.allowed_names
            })
            .map(|bound| bound.report.clone())
            .or_else(|| env::env_contract_report(opts))
    }

    async fn spawn_child_async_impl(
        &self,
        program: Option<&Path>,
        argv: &[String],
        opts: &SpawnOptions,
        dry_run: bool,
        unotify_nrs: Option<&[u32]>,
        ns_ctx: Option<NamespacedLaunchCtx>,
    ) -> SpawnAttempt {
        // Consulted only by the Linux arms — the seccomp
        // user-notification stage and the namespaced launch context
        // do not exist elsewhere.
        let _ = unotify_nrs;
        let _ = ns_ctx;
        if argv.is_empty() {
            return SpawnAttempt::err(
                WardenReport {
                    // Rejected before any sandbox work: OS controls read
                    // `Skipped`, never `Failed` by an unrelated ruleset
                    // build (on Linux `build_plan` would otherwise run
                    // Landlock/seccomp construction here). The plan goes
                    // through `enforcement_plan` so the Linux selection
                    // record travels with the refusal.
                    plan: self.enforcement_plan(
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

        // A mechanism that does not exist on this host refuses — it must
        // never silently run the platform default under a different
        // guarantee set.
        if let Some(reason) = self.mechanism_unavailable_reason() {
            let report = WardenReport {
                plan: self.enforcement_plan(program, command, opts, Some(reason), dry_run),
                observations: Vec::new(),
            };
            return SpawnAttempt::err(
                report,
                WardenError::sandbox_setup(crate::error::SandboxStage::Prepare, reason),
            );
        }

        #[cfg(target_os = "windows")]
        {
            let psec_env = self.windows_mechanism == WindowsNativeMechanism::Psec;
            let mut controls = plan::shared_controls(&self.policy, opts, dry_run, false, psec_env);
            controls.extend(plan::os_controls(&self.policy, self.windows_mechanism));
            let mut limitations = plan::base_limitations();
            plan::os_limitations(&self.policy, &mut limitations, self.windows_mechanism);
            let mut grants = Vec::new();
            // Observations are taken from the spawn path alone: it owns
            // the whole OS-control pipeline (capability probe, policy
            // translation, environment/profile, CreateProcessW), so its
            // result is the mechanism result. The post-spawn stdio
            // capture below is not part of OS enforcement and must not
            // mark controls Failed.
            let spawned = match self.windows_mechanism {
                WindowsNativeMechanism::AppContainer => windows_sandbox::spawn_sandboxed(
                    &self.policy,
                    program,
                    command,
                    args,
                    opts,
                    &mut grants,
                ),
                WindowsNativeMechanism::Psec => windows_psec::spawn_sandboxed(
                    &self.policy,
                    program,
                    command,
                    args,
                    opts,
                    &mut grants,
                ),
            };
            let spawn_err = spawned.as_ref().err().map(|e| e.to_string());
            // `windows_spawn_outcome` generates the observations while
            // the controls are still `Planned` — failing the plan first
            // would leave a setup abort with failed controls and no
            // per-control evidence — and only then marks the plan for a
            // provable pre-`CreateProcessW` (`Policy`/`Prepare` sourced)
            // construction failure. Post-create stages keep their
            // per-control outcomes in the observations alone.
            let mut observations = plan::windows_spawn_outcome(
                &mut controls,
                &grants,
                spawned.as_ref().err(),
                self.windows_mechanism,
            );
            // Under PSEC the env block is mechanism-managed — the
            // restriction contract applies by construction; the encoded
            // SpawnOptions block never reaches `lpEnvironment`.
            let env_applied = if psec_env {
                opts.restrict_environment
            } else {
                env_block_applies(opts)
            };
            if let Some(o) =
                plan::env_observation(self.env_contract_for(opts).as_ref(), env_applied, spawn_err)
            {
                observations.push(o);
            }
            let report = WardenReport {
                plan: EnforcementPlan {
                    mechanism: self.mechanism_record(),
                    controls,
                    grants,
                    tools: plan::tools_table(&self.policy),
                    limitations,
                    egress_layers: Some(plan::egress_layers_plan(
                        &self.policy,
                        self.windows_mechanism,
                    )),
                },
                observations,
            };
            match spawned {
                Ok(mut win_child) => {
                    tracing::info!(
                        "Warden: child created under mechanism={} (CreateProcessW is \
                         authoritative)",
                        self.windows_mechanism.name()
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
                                    unotify_listener: None,
                                    inner: RunningChildInner::Windows(std::sync::Arc::new(
                                        win_child,
                                    )),
                                },
                            )
                        }
                        (Err(e), _) | (_, Err(e)) => {
                            // The spawned AppContainer process must not
                            // outlive a stdio-capture failure.
                            let _ = win_child.kill();
                            SpawnAttempt::err(report, e)
                        }
                    }
                }
                Err(e) => SpawnAttempt::err(report, e.into_warden_error()),
            }
        }

        #[cfg(target_os = "macos")]
        {
            let mut controls = plan::shared_controls(&self.policy, opts, dry_run, true, false);
            controls.extend(plan::os_controls(&self.policy, self.windows_mechanism));
            let mut limitations = plan::base_limitations();
            plan::os_limitations(&self.policy, &mut limitations, self.windows_mechanism);
            let mut observations = Vec::new();

            // Prepare the helper path, profile and private TMPDIR; a
            // failure here is a construction failure — OS controls are
            // marked Failed in the plan and the build observation
            // carries the stage detail. `sandbox-exec` is invoked by its
            // validated absolute path only — `PATH` order can never
            // substitute a fake helper that skips the profile.
            type Prepared = Result<
                (
                    PathBuf,
                    macos_sandbox::PrivateTmpDir,
                    String,
                    Vec<crate::enforcement::ProcessGrant>,
                ),
                (&'static str, WardenError),
            >;
            let prepared = (|| -> Prepared {
                let helper = sandbox_exec::sandbox_exec_path()
                    .map_err(|e| ("sandbox-exec helper validation failed", e))?;
                let tmpdir = macos_sandbox::create_private_tmpdir()
                    .map_err(|e| ("private tmpdir creation failed", e))?;
                let (sbpl, mut grants) = macos_sandbox::sbpl_profile(
                    &self.policy,
                    tmpdir.path().to_string_lossy().as_ref(),
                    &opts.exec_map_dirs,
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
                Ok((helper, tmpdir, sbpl, grants))
            })();
            let (helper, tmpdir, sbpl, grants) = match prepared {
                Ok(v) => {
                    observations.push(plan::macos_prepare_observation(None));
                    v
                }
                Err((stage, source)) => {
                    plan::fail_os_controls(&mut controls, stage, &source);
                    observations.push(plan::macos_prepare_observation(Some((stage, &source))));
                    let report = WardenReport {
                        plan: EnforcementPlan {
                            mechanism: self.mechanism_record(),
                            controls,
                            grants: Vec::new(),
                            tools: plan::tools_table(&self.policy),
                            limitations,
                            egress_layers: Some(plan::egress_layers_plan(
                                &self.policy,
                                self.windows_mechanism,
                            )),
                        },
                        observations,
                    };
                    return SpawnAttempt::err(report, source);
                }
            };
            let mut cmd = tokio::process::Command::new(&helper);
            cmd.arg("-p").arg(&sbpl).arg("--");
            // sandbox-exec re-execs the given path with argv[0] equal to
            // that path, so a distinct verified executable goes through
            // bash `exec -a` — `apply_exec_a_wrapper` keeps the wrapper
            // args, ordering, and DYLD fallback re-export identical on
            // every `sandbox-exec` route.
            macos_sandbox::apply_exec_a_wrapper(&mut cmd, program, command, args, opts);
            cmd.stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped())
                // The sandbox-exec helper shares the workload's stderr
                // — attacker-controlled bytes must cross sanitized,
                // never raw to the terminal.
                .stderr(std::process::Stdio::piped());
            let mut env_opts = opts.clone();
            if env_opts.tmpdir.is_none() {
                env_opts.tmpdir = Some(tmpdir.path().to_path_buf());
            }
            apply_spawn_env(&mut cmd, &env_opts);
            let env_applied = env_block_applies(&env_opts);
            if let Some(exe) = python_executable_override(command, program) {
                cmd.env("PYTHONEXECUTABLE", exe);
            }
            apply_unix_process_group_tokio(&mut cmd);
            // fd hygiene + fd-exec handoff: the child's pre_exec seals
            // every ambient descriptor above stdio, then uncloaks the
            // pin's dup'd descriptors so they survive sandbox-exec's
            // re-exec plus the workload exec. The parent-side fd-table
            // snapshot is a prepare stage — a table that cannot be
            // inspected aborts the launch rather than leaking fds the
            // profile never mediated.
            if let Err(e) = attach_fd_hygiene_tokio(&mut cmd, &opts.exec_uncloak_fds) {
                let source =
                    WardenError::sandbox_setup(crate::error::SandboxStage::Prepare, e.to_string());
                plan::fail_os_controls(&mut controls, "ambient fd enumeration failed", &source);
                observations.push(plan::macos_prepare_observation(Some((
                    "ambient fd enumeration failed",
                    &source,
                ))));
                let report = WardenReport {
                    plan: EnforcementPlan {
                        mechanism: self.mechanism_record(),
                        controls,
                        grants,
                        tools: plan::tools_table(&self.policy),
                        limitations,
                        egress_layers: Some(plan::egress_layers_plan(
                            &self.policy,
                            self.windows_mechanism,
                        )),
                    },
                    observations,
                };
                return SpawnAttempt::err(report, source);
            }
            let mut spawned = cmd.spawn();
            // Pin the pid before the liveness probe: the probe reaps a
            // leader that exits inside the window, after which `id()`
            // can no longer resolve — and the pgid (`process_group(0)`
            // ⇒ equal to the pid) must survive for group cleanup.
            #[cfg(unix)]
            let spawned_pid = spawned
                .as_ref()
                .ok()
                .and_then(|child| child.id())
                .unwrap_or(0);
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
            if let Some(o) = plan::env_observation(
                self.env_contract_for(&env_opts).as_ref(),
                env_applied,
                spawn_err,
            ) {
                observations.push(o);
            }
            let report = WardenReport {
                plan: EnforcementPlan {
                    mechanism: self.mechanism_record(),
                    controls,
                    grants,
                    tools: plan::tools_table(&self.policy),
                    limitations,
                    egress_layers: Some(plan::egress_layers_plan(
                        &self.policy,
                        self.windows_mechanism,
                    )),
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
                    if let Some(err) = child.stderr.take() {
                        crate::termutil::relay_child_stderr(err);
                    }
                    match (stdin, stdout) {
                        (Ok(stdin), Ok(stdout)) => SpawnAttempt::ok(
                            report,
                            RunningChild {
                                stdin: Some(Box::new(stdin)),
                                stdout: Some(Box::new(stdout)),
                                unotify_listener: None,
                                #[cfg(unix)]
                                pgid: spawned_pid,
                                #[cfg(unix)]
                                // `initial_exit_check` already reaped a
                                // leader that exited inside its window —
                                // marking it here keeps `kill_descendants`
                                // from ever signaling the freed pgid.
                                reaped: matches!(
                                    liveness,
                                    Some(macos_sandbox::SpawnLiveness::Exited(_))
                                ),
                                inner: RunningChildInner::Tokio(Box::new(child)),
                                _tmpdir: Some(tmpdir),
                            },
                        ),
                        (Err(e), _) | (_, Err(e)) => {
                            // Same contract as the Linux arm: the child
                            // owns its process group; ESRCH on an exited
                            // group is fine. A pid that never
                            // materialized (0) must not reach the calls —
                            // `kill(0)` would signal *this* process's own
                            // group.
                            if spawned_pid > 0 {
                                // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
                                unsafe {
                                    libc::kill(-(spawned_pid as libc::pid_t), libc::SIGKILL);
                                    libc::kill(spawned_pid as libc::pid_t, libc::SIGKILL);
                                }
                            }
                            let _ = child.kill().await;
                            SpawnAttempt::err(report, e)
                        }
                    }
                }
                Err(e) => SpawnAttempt::err(report, WardenError::ProcessSpawn(e)),
            }
        }

        #[cfg(target_os = "linux")]
        {
            // PR-16 dispatch: a `namespaced` selection takes the
            // userns+netns+TUN+proxy route — same fail-closed refusal
            // semantics as every other mechanism (an error is a launch
            // refusal, never a fallback to this native arm).
            if self.linux_selected_mechanism() == Some(LinuxNativeMechanism::Namespaced) {
                let Some(program) = program else {
                    return SpawnAttempt::err(
                        WardenReport {
                            plan: self.enforcement_plan(
                                None,
                                command,
                                opts,
                                Some("namespaced dispatch requires a resolved program"),
                                dry_run,
                            ),
                            observations: Vec::new(),
                        },
                        WardenError::sandbox_setup(
                            crate::error::SandboxStage::Prepare,
                            "namespaced dispatch requires a resolved program",
                        ),
                    );
                };
                let Some(ctx) = ns_ctx else {
                    return SpawnAttempt::err(
                        WardenReport {
                            plan: self.enforcement_plan(
                                Some(program),
                                command,
                                opts,
                                Some("namespaced dispatch requires the launch context"),
                                dry_run,
                            ),
                            observations: Vec::new(),
                        },
                        WardenError::sandbox_setup(
                            crate::error::SandboxStage::Prepare,
                            "namespaced dispatch requires the launch context",
                        ),
                    );
                };
                let env_contract = self.env_contract_for(opts);
                return namespaced::launch::spawn_namespaced_attempt(
                    &self.policy,
                    self.linux_selection
                        .as_ref()
                        .expect("selected mechanism implies a stored selection"),
                    program,
                    argv,
                    opts,
                    dry_run,
                    &ctx,
                    env_contract.as_ref(),
                )
                .await;
            }

            let mut controls = plan::shared_controls(&self.policy, opts, dry_run, false, false);
            controls.extend(plan::os_controls(&self.policy, self.windows_mechanism));
            let mut limitations = plan::base_limitations();
            plan::os_limitations(&self.policy, &mut limitations, self.windows_mechanism);

            let mut sandbox_bits = match linux_spawn::prepare_linux_child_sandbox(&self.policy) {
                Ok(bits) => bits,
                Err(source) => {
                    plan::fail_os_controls(&mut controls, "rule build failed", &source);
                    let report = WardenReport {
                        plan: EnforcementPlan {
                            mechanism: self.mechanism_record(),
                            controls,
                            grants: Vec::new(),
                            tools: plan::tools_table(&self.policy),
                            limitations,
                            egress_layers: Some(plan::egress_layers_plan(
                                &self.policy,
                                self.windows_mechanism,
                            )),
                        },
                        observations: Vec::new(),
                    };
                    return SpawnAttempt::err(report, source);
                }
            };
            // Opt-in: arm the user-notification stage — the filter is
            // installed in `pre_exec` between Landlock and the policy
            // seccomp program, and the listener fd is collected after
            // the spawn below. Arming failure fails the launch rather
            // than silently running unsupervised.
            let unotify_parent = match unotify_nrs {
                Some(nrs) if !nrs.is_empty() => {
                    match unotify::enable_unotify(&mut sandbox_bits, nrs) {
                        Ok(parent) => Some(parent),
                        Err(source) => {
                            plan::fail_os_controls(&mut controls, "unotify arm failed", &source);
                            let report = WardenReport {
                                plan: EnforcementPlan {
                                    mechanism: self.mechanism_record(),
                                    controls,
                                    grants: std::mem::take(&mut sandbox_bits.grants),
                                    tools: plan::tools_table(&self.policy),
                                    limitations,
                                    egress_layers: Some(plan::egress_layers_plan(
                                        &self.policy,
                                        self.windows_mechanism,
                                    )),
                                },
                                observations: Vec::new(),
                            };
                            return SpawnAttempt::err(report, source);
                        }
                    }
                }
                _ => None,
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
                // The workload's stderr is attacker-controlled — pipe
                // it through the sanitized relay, never raw to the
                // terminal.
                .stderr(std::process::Stdio::piped());
            apply_spawn_env(&mut cmd, opts);
            let env_applied = env_block_applies(opts);
            apply_unix_process_group_tokio(&mut cmd);
            // fd-exec handoff: the pin's CLOEXEC dups uncloak inside the
            // child's apply pipeline (before the policy seccomp filter
            // can deny `fcntl`).
            sandbox_bits.exec_uncloak_fds = opts.exec_uncloak_fds.clone();
            // PR-18: the `restrict_self` level alone cannot say which
            // rights were requested — the report lists them.
            let requested_rights = sandbox_bits.requested_rights.clone();
            let apply_record = linux_spawn::attach_linux_pre_exec_tokio(&mut cmd, sandbox_bits);
            let spawned = cmd.spawn();
            // The pre-exec child's own apply record — readable now that
            // spawn returned, unforgeable by the exec'd workload.
            let apply_snapshot = apply_record.as_ref().map(|r| r.snapshot());
            let spawn_err = spawned.as_ref().err().map(|e| e.to_string());
            let mut observations = plan::os_spawn_observations(
                &self.policy,
                &controls,
                apply_snapshot.as_ref(),
                spawned.as_ref().err(),
                Some(requested_rights.as_str()),
            );
            if let Some(o) =
                plan::env_observation(self.env_contract_for(opts).as_ref(), env_applied, spawn_err)
            {
                observations.push(o);
            }
            let mut report = WardenReport {
                plan: EnforcementPlan {
                    mechanism: self.mechanism_record(),
                    controls,
                    grants,
                    tools: plan::tools_table(&self.policy),
                    limitations,
                    egress_layers: Some(plan::egress_layers_plan(
                        &self.policy,
                        self.windows_mechanism,
                    )),
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
                    if let Some(err) = child.stderr.take() {
                        crate::termutil::relay_child_stderr(err);
                    }
                    match (stdin, stdout) {
                        (Ok(stdin), Ok(stdout)) => {
                            // Collect the notification listener the
                            // child's pre_exec handed over. A spawn
                            // that armed the stage but cannot receive
                            // the fd is failed, not left supervised-None.
                            let unotify_listener = match &unotify_parent {
                                Some(parent) => match parent.recv_listener() {
                                    Ok(listener) => Some(listener),
                                    Err(e) => {
                                        let pid = child.id().unwrap_or(0) as libc::pid_t;
                                        // Safety: the child owns its
                                        // process group (set at spawn);
                                        // -ESRCH on an exited group is
                                        // fine. A 0 pid must not reach
                                        // the calls — `kill(0)` would
                                        // signal *this* process's own
                                        // group.
                                        if pid > 0 {
                                            // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
                                            unsafe {
                                                libc::kill(-pid, libc::SIGKILL);
                                                libc::kill(pid, libc::SIGKILL);
                                            }
                                        }
                                        let _ = child.kill().await;
                                        return SpawnAttempt::err(
                                            report,
                                            WardenError::ProcessSpawn(e),
                                        );
                                    }
                                },
                                None => None,
                            };
                            let lifetime_cgroup =
                                cgroup::LifetimeCgroup::try_adopt("run", child.id().unwrap_or(0));
                            report.plan.grants.push(lifetime_grant(&lifetime_cgroup));
                            SpawnAttempt::ok(
                                report,
                                RunningChild {
                                    stdin: Some(Box::new(stdin)),
                                    stdout: Some(Box::new(stdout)),
                                    #[cfg(unix)]
                                    pgid: child.id().unwrap_or(0),
                                    #[cfg(unix)]
                                    reaped: false,
                                    unotify_listener,
                                    lifetime_cgroup,
                                    namespaced: None,
                                    namespaced_report: None,
                                    inner: RunningChildInner::Tokio(Box::new(child)),
                                },
                            )
                        }
                        (Err(e), _) | (_, Err(e)) => {
                            let pid = child.id().unwrap_or(0) as libc::pid_t;
                            // Safety: same contract as the listener-recv
                            // failure arm — the child owns its process
                            // group; ESRCH on an exited group is fine.
                            // A 0 pid must not reach the calls —
                            // `kill(0)` would signal *this* process's
                            // own group. When unotify is armed the child
                            // may already be parked on a watched
                            // syscall, so leaving it running is not an
                            // option either way.
                            if pid > 0 {
                                // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
                                unsafe {
                                    libc::kill(-pid, libc::SIGKILL);
                                    libc::kill(pid, libc::SIGKILL);
                                }
                            }
                            let _ = child.kill().await;
                            SpawnAttempt::err(report, e)
                        }
                    }
                }
                Err(e) => SpawnAttempt::err(report, WardenError::ProcessSpawn(e)),
            }
        }

        #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
        {
            // Fail closed: the sandboxed-spawn API cannot silently
            // downgrade to ambient host authority on an unsupported
            // platform — refuse with a report that states why, and
            // leave unsandboxed execution to the explicitly-named API.
            let reason = "no OS sandbox mechanism on this platform; \
                          refusing to spawn unconstrained (use \
                          spawn_unsandboxed_async for a documented \
                          unsandboxed launch)";
            let report = WardenReport {
                plan: plan::build_plan(
                    &self.policy,
                    program,
                    command,
                    opts,
                    Some(reason),
                    dry_run,
                    self.windows_mechanism,
                ),
                observations: Vec::new(),
            };
            SpawnAttempt::err(
                report,
                WardenError::sandbox_setup(crate::error::SandboxStage::Prepare, reason),
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
                self.windows_mechanism,
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
                self.env_contract_for(opts).as_ref(),
                env_block_applies(opts),
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
                                    unotify_listener: None,
                                    inner: RunningChildInner::Windows(std::sync::Arc::new(
                                        win_child,
                                    )),
                                },
                            )
                        }
                        (Err(e), _) | (_, Err(e)) => {
                            let _ = win_child.kill();
                            SpawnAttempt::err(report, e)
                        }
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
            // Same contract on the unsandboxed arm: attacker-controlled
            // stderr crosses to the terminal sanitized.
            .stderr(std::process::Stdio::piped());
        apply_spawn_env(&mut cmd, opts);
        #[cfg(target_os = "macos")]
        if let Some(exe) = python_executable_override(&argv[0], program) {
            cmd.env("PYTHONEXECUTABLE", exe);
        }
        apply_unix_process_group_tokio(&mut cmd);
        // fd hygiene + fd-exec handoff on the unsandboxed arm: no
        // sandbox does not mean the launcher's ambient descriptors
        // should leak — the child seals everything above stdio except
        // the fd-exec pins, which it uncloaks in the same pre_exec.
        #[cfg(unix)]
        let spawned = match attach_fd_hygiene_tokio(&mut cmd, &opts.exec_uncloak_fds) {
            Ok(()) => cmd.spawn(),
            Err(e) => Err(e),
        };
        #[cfg(not(unix))]
        let spawned = cmd.spawn();
        let mut report = plan_report();
        if let Some(o) = plan::env_observation(
            self.env_contract_for(opts).as_ref(),
            env_block_applies(opts),
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
                if let Some(err) = child.stderr.take() {
                    crate::termutil::relay_child_stderr(err);
                }
                match (stdin, stdout) {
                    (Ok(stdin), Ok(stdout)) => {
                        #[cfg(target_os = "linux")]
                        {
                            let lifetime_cgroup =
                                cgroup::LifetimeCgroup::try_adopt("run", child.id().unwrap_or(0));
                            report.plan.grants.push(lifetime_grant(&lifetime_cgroup));
                            SpawnAttempt::ok(
                                report,
                                RunningChild {
                                    stdin: Some(Box::new(stdin)),
                                    stdout: Some(Box::new(stdout)),
                                    pgid: child.id().unwrap_or(0),
                                    reaped: false,
                                    unotify_listener: None,
                                    lifetime_cgroup,
                                    namespaced: None,
                                    namespaced_report: None,
                                    inner: RunningChildInner::Tokio(Box::new(child)),
                                },
                            )
                        }
                        #[cfg(not(target_os = "linux"))]
                        SpawnAttempt::ok(
                            report,
                            RunningChild {
                                stdin: Some(Box::new(stdin)),
                                stdout: Some(Box::new(stdout)),
                                #[cfg(unix)]
                                pgid: child.id().unwrap_or(0),
                                #[cfg(unix)]
                                reaped: false,
                                unotify_listener: None,
                                inner: RunningChildInner::Tokio(Box::new(child)),
                                #[cfg(target_os = "macos")]
                                _tmpdir: None,
                            },
                        )
                    }
                    (Err(e), _) | (_, Err(e)) => {
                        // A spawned child whose stdio we cannot capture
                        // is still our responsibility — kill it (and its
                        // group, where it owns one) before erroring out.
                        // This path is sync, so `start_kill` delivers
                        // SIGKILL without an async reap.
                        #[cfg(unix)]
                        {
                            let pid = child.id().unwrap_or(0) as libc::pid_t;
                            // A 0 pid must not reach the calls —
                            // `kill(0)` would signal *this* process's
                            // own group.
                            if pid > 0 {
                                // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
                                unsafe {
                                    libc::kill(-pid, libc::SIGKILL);
                                    libc::kill(pid, libc::SIGKILL);
                                }
                            }
                        }
                        let _ = child.start_kill();
                        SpawnAttempt::err(report, e)
                    }
                }
            }
            Err(e) => SpawnAttempt::err(report, WardenError::ProcessSpawn(e)),
        }
    }
}
