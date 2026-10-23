use crate::audit_log::{
    Action, AuditEvent, AuditLogger, EventType, Outcome, PolicyAuditContext, Severity,
    now_iso8601_millis,
};
use crate::auditor::Auditor;
use crate::enforcement::CodeIdentity;
use crate::enforcement::{
    ControlLayer, ControlPhase, ControlState, EnforcementObservation, EnforcementPlan,
    EnforcementSummary, LAUNCH_REPORT_SCHEMA_VERSION, LaunchOutcome, LaunchReport,
    ObservationBasis, PinCheck, SandboxBackend,
};
#[cfg(target_os = "linux")]
use crate::error::SandboxStage;
use crate::error::{AuditorError, WardenError};
use crate::execution::ExecutionTarget;
use crate::policy::Policy;
use crate::verifier::fail_on::FailOn;
use crate::verifier::hash::{self, VerifyError};
use crate::verifier::identity::LaunchIdentity;
use crate::warden::{RunningChild, Warden, WardenReport};

/// Per-binary inputs to [`launch`].
///
/// Callers resolve policy loading, `bind_to_server`, `FailOn`, and audit-log
/// requirements before calling. `skip_sandbox` is also computed by the caller:
/// this function never reads `MCP_WRIT_SKIP_SANDBOX` itself (the container
/// runner strips that variable before launch, and reading it here would break
/// image ENV handling and tests).
pub struct LaunchConfig {
    /// Command argv as the caller spelled it; `argv[0]` is resolved and
    /// verified here but keeps its spelling as the child's `argv[0]` —
    /// the resolved path is exec'd as the process image. Must be non-empty.
    pub argv: Vec<String>,
    pub policy: Policy,
    pub fail_on: FailOn,
    /// Forwarded to `Auditor::with_dry_run` (`mcp-secure-runner` passes false).
    pub dry_run: bool,
    /// Caller-computed sandbox skip (`mcp-writ run --dry-run` or
    /// `MCP_WRIT_SKIP_SANDBOX`; `mcp-secure-runner` always passes false).
    pub skip_sandbox: bool,
    /// Reason interpolated into `sandboxing disabled ({reason})`. Expected to
    /// be set when `skip_sandbox` is true.
    pub skip_reason: Option<&'static str>,
    /// First half of the post-spawn `tracing::info!` — the message names
    /// the executable and argument count only; the full argv is emitted
    /// at debug level solely under explicit `MCP_WRIT_LOG_ARGV` consent.
    pub spawned_log_label: &'static str,
    /// Identity of the enforced (bound) policy — the bound server name (or
    /// `default` for a server-less policy), the declared policy version,
    /// and the hash of its effective `to_kdl` form. Stamped on the launch
    /// report and on the correlated `server.connected`/`server.error`
    /// audit events.
    pub policy_context: Option<PolicyAuditContext>,
    /// Launch correlation ID override. `None` mints a fresh v7 UUID; the
    /// in-guest runner passes the host-supplied `MCP_WRIT_LAUNCH_ID` so
    /// guest audit events correlate with the host's launch report.
    pub launch_id: Option<uuid::Uuid>,
    /// Guest-side directory the workload's TMPDIR/TMP/TEMP are pointed
    /// at — set by the in-guest runner from its contract env. `None`
    /// keeps the inherited variables untouched (the native `run` path).
    pub workload_tmpdir: Option<std::path::PathBuf>,
    /// `--windows-mechanism` — the native Windows sandbox mechanism the
    /// Warden dispatches on (`None` = the platform default,
    /// AppContainer). Recorded on the launch target so the report names
    /// the mechanism actually selected.
    pub windows_mechanism: Option<crate::execution::WindowsNativeMechanism>,
    /// `--linux-mechanism` — the Linux egress-mechanism request
    /// (`auto`/`namespaced`/`native`). `None` keeps the legacy dispatch —
    /// no egress selection runs and the mechanism member stays absent —
    /// for callers the host-side selector does not govern (the in-guest
    /// runner). The legacy route is still gated pre-spawn on what it
    /// cannot honor at all: a UDP-covered allow under deny-all is dead
    /// policy there and refuses the launch
    /// (`warden::select::dead_udp_allows_without_selection`). The host
    /// `run`/`plan` CLI always passes a request, defaulting to
    /// `Some(Auto)`. Only consulted on Linux native launches.
    pub linux_mechanism: Option<crate::execution::LinuxMechanismRequest>,
    /// `--dns-upstream` — the resolver the namespaced route's embedded
    /// DNS gate forwards to. `None` falls back to the first IPv4
    /// `nameserver` in `/etc/resolv.conf`; the selection records what
    /// was resolved.
    pub dns_upstream: Option<std::net::SocketAddr>,
    /// Emitting binary for `guard.*` lifecycle records
    /// (`mcp-writ` on the host, `mcp-secure-runner` in the guest).
    pub component: &'static str,
    /// `--max-frame-bytes` — the JSON-RPC frame cap both relay
    /// directions enforce (`framing::DEFAULT_MAX_FRAME_BYTES` when the
    /// caller did not override). The in-guest runner resolves it from
    /// `MCP_WRIT_MAX_FRAME_BYTES`.
    pub max_frame_bytes: usize,
}

/// A spawned MCP server child plus its running Auditor relay task.
pub struct Launched {
    pub child: RunningChild,
    pub auditor_handle: tokio::task::JoinHandle<Result<(), AuditorError>>,
    /// What this launch intended to enforce and what applying it observably
    /// did (`enforcement` module). Nothing emits it by default — a future
    /// `--report`/diagnostics surface decides where it goes; it never rides
    /// on MCP stdout.
    pub report: LaunchReport,
    /// Audit identity the session-teardown events are stamped with —
    /// passed to `wait_for_shutdown`.
    pub session_audit: crate::runtime::lifecycle::SessionAuditContext,
    /// The verified workload objects (executable + any payload-bound
    /// entrypoint script), held open for the session. On Windows the
    /// `FILE_SHARE_READ`-only share mode is load-bearing for the whole
    /// lifetime: a pinned entrypoint launches by its real path — the
    /// interpreter opens it *after* CreateProcess — so the held pin is
    /// what keeps that path naming the verified object; dropping it at
    /// spawn-return reopens the replace window. On Unix the held
    /// handles remain the identity anchors `verify_spawn_path` checked.
    pub _spawn_pin: Option<hash::SpawnPin>,
    /// Non-Linux Unix: the exec plan's exe spelling is the staged
    /// copy's path — it must resolve at the child's `execve`, which
    /// runs after `spawn()` returns on the fork+pre_exec path, so the
    /// plan rides the session like `_spawn_pin`. Linux needs nothing:
    /// its inherited descriptor names the snapshot, not a path.
    #[cfg(all(unix, not(target_os = "linux")))]
    pub _exec_staging: Option<crate::verifier::hash::FdExecPlan>,
}

/// Failure at one step of [`launch`]. Callers render the message with their
/// own error prefix, shut down the audit logger, and exit.
///
/// Every variant carries `report`: the enforcement plan this launch was
/// built on plus a `result` of `failed`, so a `--report` consumer always
/// gets the same schema for a refused or failed launch — never an empty
/// success and never an unsupported shape.
pub enum LaunchError {
    /// `resolve_command_path` failed; `command` is the unresolved `argv[0]`.
    ResolveCommand {
        command: String,
        source: std::io::Error,
        report: Box<LaunchReport>,
    },
    /// `verify_server_hashes` failed for `server_name`.
    VerifyServerHashes {
        server_name: String,
        source: VerifyError,
        report: Box<LaunchReport>,
    },
    /// `bind_launched_workload` failed.
    BindLaunchedWorkload {
        source: VerifyError,
        report: Box<LaunchReport>,
    },
    /// `reverify_immediately_before_spawn` failed.
    ReverifyBeforeSpawn {
        source: VerifyError,
        report: Box<LaunchReport>,
    },
    /// Warden spawn failed; `argv` is the launch argv. `report` carries the
    /// plan the failed spawn was built from and the failure observations —
    /// a refused launch is still describable.
    Spawn {
        argv: Vec<String>,
        source: WardenError,
        report: Box<LaunchReport>,
    },
    /// `take_io` failed; ownership of the child is returned so the caller can
    /// kill/wait/drop in the usual order. `report` describes the launch the
    /// child was spawned under.
    TakeIo {
        child: Box<RunningChild>,
        report: Box<LaunchReport>,
    },
}

/// Shared sequence: resolve argv0 → verify hashes → bind → reverify →
/// Warden spawn (exec'ing the verified path while the child keeps the
/// caller's `argv[0]`) → `take_io` → `Auditor` relay on a spawned task.
///
/// Ordering is fixed: verify → bind → reverify reruns the binding —
/// including the content re-hash — immediately before spawn, narrowing
/// but not closing the hash-to-exec window. `code_identity` in the
/// report records which check points each pin passed.
/// Signal waiting and shutdown are NOT part of this function.
///
/// A [`LaunchReport`] is assembled for every outcome of [`launch`]: it is
/// returned inside [`Launched`] with `result = running` (the caller
/// finalizes it at session end) and inside every [`LaunchError`] variant
/// with `result = failed`, so a refused or failed launch stays
/// describable in the same schema. The plan comes from the same
/// normalized rule data the spawn used, the observations from the
/// spawn's own outcome, and `launch_id` correlates them with the audit
/// events emitted here — including a `server.error` event on every
/// failure path, so a failed launch is auditable under the same id.
pub async fn launch(
    config: LaunchConfig,
    audit_logger: &AuditLogger,
) -> Result<Launched, LaunchError> {
    let LaunchConfig {
        argv,
        policy,
        fail_on,
        dry_run,
        skip_sandbox,
        skip_reason,
        spawned_log_label,
        policy_context,
        launch_id,
        workload_tmpdir,
        windows_mechanism,
        linux_mechanism,
        dns_upstream,
        component,
        max_frame_bytes,
    } = config;

    let launch_id = launch_id.unwrap_or_else(uuid::Uuid::now_v7);
    #[allow(unused_mut)] // only the Linux mechanism stamp below mutates it
    let mut target = match windows_mechanism {
        Some(m) => ExecutionTarget::native().with_native_windows_mechanism(m),
        None => ExecutionTarget::native(),
    };
    let hash_entry_count = policy.hash_entries.len();
    let has_hashes = hash_entry_count > 0;
    let argv0 = argv.first().map(String::as_str).unwrap_or("");

    // The selected mechanism is fail-closed in the Warden: an explicit
    // non-default mechanism that cannot run refuses — it never silently
    // becomes AppContainer.
    let mut warden =
        Warden::with_windows_mechanism(policy.clone(), windows_mechanism.unwrap_or_default());
    let sandbox_skip_reason: Option<&'static str> = if skip_sandbox {
        Some(skip_reason.unwrap_or("unspecified"))
    } else {
        None
    };

    // PR-16 — resolve the Linux egress selection once, before any
    // launch work, so the dispatch, the plan, and the audit digest all
    // read the same evidence. A deliberately unsandboxed launch
    // (`--dry-run`/`MCP_WRIT_SKIP_SANDBOX`) applies no OS mechanism, so
    // no selection runs and the mechanism member stays absent. A `None`
    // request keeps the legacy dispatch with no selection at all — the
    // in-guest runner's contract; the host `run`/`plan` path always
    // passes an explicit request (`auto` by default).
    #[cfg(target_os = "linux")]
    let linux_selection = if sandbox_skip_reason.is_some() {
        None
    } else {
        linux_mechanism.map(|request| {
            crate::warden::select::select_linux_mechanism(request, &policy, dns_upstream)
        })
    };
    // `target` records the bound mechanism — or, on a refused
    // selection, the refused marker so `sandbox_mechanism` reports
    // null rather than claiming a mechanism that never ran.
    #[cfg(target_os = "linux")]
    if let Some(sel) = &linux_selection {
        target = match sel.selected {
            Some(m) => target.with_native_linux_mechanism(m),
            None => target.with_linux_selection_refused(),
        };
    }
    #[cfg(target_os = "linux")]
    let linux_refusal: Option<String> = linux_selection
        .as_ref()
        .filter(|s| s.selected.is_none())
        .map(|s| s.reason.clone());
    #[cfg(target_os = "linux")]
    if let Some(sel) = linux_selection {
        warden.set_linux_selection(sel);
    }
    #[cfg(not(target_os = "linux"))]
    let _ = (linux_mechanism, dns_upstream, &mut warden);
    // The backend the `enforcement` member reports — the mechanism the
    // launch's sandboxed dispatch is bound to (`Warden::sandbox_backend`),
    // or `none` when the launch skips the OS sandbox entirely. A
    // mechanism absent on this host binds to nothing and reports `none`
    // too — the dispatch refuses rather than run under another name.
    let backend = if sandbox_skip_reason.is_some() {
        SandboxBackend::None
    } else {
        warden.sandbox_backend()
    };
    // The environment restriction is part of the launch contract, not the OS
    // sandbox: it applies identically on the sandboxed path and when
    // `skip_sandbox` (`--dry-run` / `MCP_WRIT_SKIP_SANDBOX`) is set.
    #[allow(unused_mut)] // only the unix fd-exec arm mutates it below
    let mut spawn_opts = crate::warden::SpawnOptions {
        restrict_environment: policy.environment.restrict,
        allowed_names: policy.environment.allowed.clone(),
        tmpdir: workload_tmpdir,
        ..Default::default()
    };
    // `policy` moves into `Auditor::new` below; the ambient-inheritance
    // flag is needed on the `server.connected` record afterwards.
    let env_inherit_parent = policy.environment.inherit_parent;

    // The verified executable/entrypoint handles, when the policy pins
    // hashes — held open across the spawn so the checked object is the
    // executed object (Windows: replacement-preventing share mode;
    // Unix: the final path-identity re-check anchor).
    let mut spawn_pin: Option<hash::SpawnPin> = None;

    // The plan a report describes: for a failed launch the same builders
    // still run (nothing is applied), so the report shows what the launch
    // intended to enforce, not an empty result.
    let launch_plan = |program: Option<&std::path::Path>| -> EnforcementPlan {
        warden.enforcement_plan(program, argv0, &spawn_opts, sandbox_skip_reason, dry_run)
    };
    let fail = |report: Box<LaunchReport>| {
        let mut event = AuditEvent::new(
            launch_id,
            EventType::ServerError,
            Severity::High,
            Outcome::Failure,
            Action::Observed,
        );
        event.policy_context = policy_context.clone();
        // The bound server name only — never the "default" label a
        // server-less policy reports.
        if let Some(ctx) = &policy_context
            && ctx.id != "default"
        {
            event.target_server = Some(ctx.id.clone());
        }
        // `session_id` keeps the record attributable when the host's
        // and the guest runner's JSONL streams merge under one launch
        // id; the failure detail follows verbatim.
        let mut details = format!("session_id={}", audit_logger.session_id());
        if let Some(detail) = report.result.as_ref().and_then(|r| r.detail.as_deref()) {
            details.push_str(&format!(" {detail}"));
        }
        event.details = Some(details);
        // The same plan/observations the `--report` file carries, as the
        // record's structured `enforcement` member — a failed launch
        // states what it attempted, not just the error string.
        event.enforcement = Some(
            EnforcementSummary::build(&report.plan, &report.observations, backend, report.dry_run)
                .to_json(),
        );
        audit_logger.log(event);
        report
    };

    // PR-16 — a refused Linux egress selection stops the launch here:
    // nothing was spawned and nothing falls back to the other
    // mechanism. The report still carries the selection record via
    // `launch_plan` (the Warden already holds the refused selection).
    #[cfg(target_os = "linux")]
    if let Some(reason) = linux_refusal {
        let detail = format!("linux egress mechanism selection refused: {reason}");
        let report = fail(failure_report(
            launch_id,
            target,
            &policy_context,
            dry_run,
            launch_plan(None),
            Vec::new(),
            LaunchIdentity::for_launch(&argv, &policy.hash_entries).finish(),
            detail,
        ));
        return Err(LaunchError::Spawn {
            argv: argv.clone(),
            source: WardenError::sandbox_setup(SandboxStage::Policy, reason),
            report,
        });
    }

    // PR-26 — the legacy dispatch (`linux_mechanism == None`, the
    // in-guest runner's contract) lands on the same native route the
    // selection calls unenforceable, with no verdict in the middle:
    // a UDP-covering allow under deny-all would be dead policy there
    // (the seccomp pin denies datagram socket creation outright), and
    // an fs grant rooted on a filesystem Landlock cannot mediate is
    // dead the same way. Refuse both pre-spawn — the same predicates
    // the selection reports — rather than run a workload whose
    // declared grant never applies.
    #[cfg(target_os = "linux")]
    if linux_mechanism.is_none() && sandbox_skip_reason.is_none() {
        let mut dead = crate::warden::select::dead_udp_allows_without_selection(&policy);
        dead.extend(crate::warden::select::dead_fs_grants_without_selection(
            &policy,
        ));
        if !dead.is_empty() {
            let reason = dead.join("; ");
            let detail = format!("linux egress policy refused: {reason}");
            let report = fail(failure_report(
                launch_id,
                target,
                &policy_context,
                dry_run,
                launch_plan(None),
                Vec::new(),
                LaunchIdentity::for_launch(&argv, &policy.hash_entries).finish(),
                detail,
            ));
            return Err(LaunchError::Spawn {
                argv: argv.clone(),
                source: WardenError::sandbox_setup(SandboxStage::Policy, reason),
                report,
            });
        }
    }

    // Resolve `argv[0]` to the exec image. When the policy pins
    // workload identity (`has_hashes`), a `#!` script expands to the
    // interpreter-plus-script launch the kernel would perform: the
    // interpreter becomes the resolved executable `binary-hash` binds,
    // and the script the payload `entrypoint-hash` binds — no
    // kernel-selected interpreter runs unpinned. Unpinned launches keep
    // the historical direct-exec contract.
    let (argv, resolved_exe) = match crate::workload::resolve_launch(argv0, has_hashes) {
        Ok(resolution) => (resolution.into_argv(&argv), resolution.exe),
        Err(source) => {
            let detail = format!("cannot resolve command '{argv0}': {source}");
            let identity = LaunchIdentity::for_launch(&argv, &policy.hash_entries);
            let report = fail(failure_report(
                launch_id,
                target,
                &policy_context,
                dry_run,
                launch_plan(None),
                Vec::new(),
                identity.finish(),
                detail,
            ));
            return Err(LaunchError::ResolveCommand {
                command: argv0.to_string(),
                source,
                report,
            });
        }
    };
    // The code-identity record accumulates which check points each hash
    // pin passed — built over the effective launch argv so an expanded
    // shebang launch reports as the interpreted shape it is.
    let mut identity = LaunchIdentity::for_launch(&argv, &policy.hash_entries);
    identity.set_resolved(&resolved_exe);
    if has_hashes {
        let identity_fail = |detail: String| -> Vec<EnforcementObservation> {
            vec![identity_observation_failed(&detail)]
        };
        let server_names: std::collections::HashSet<_> = policy
            .hash_entries
            .iter()
            .map(|e| e.server_name.as_str())
            .collect();
        for s_name in server_names {
            match hash::verify_server_hashes(s_name, &policy.hash_entries, audit_logger) {
                Ok(_) => identity.mark_server_verified(s_name),
                Err(source) => {
                    identity.mark_server_failed(s_name, &source);
                    let detail =
                        format!("supply chain verification failed for '{s_name}': {source}");
                    let report = fail(failure_report(
                        launch_id,
                        target,
                        &policy_context,
                        dry_run,
                        launch_plan(Some(&resolved_exe)),
                        identity_fail(detail.clone()),
                        identity.finish(),
                        detail,
                    ));
                    return Err(LaunchError::VerifyServerHashes {
                        server_name: s_name.to_string(),
                        source,
                        report,
                    });
                }
            }
        }
        if let Err(source) =
            hash::bind_launched_workload(&argv, &resolved_exe, &policy.hash_entries, audit_logger)
        {
            let detail = format!("supply chain verification failed: {source}");
            let report = fail(failure_report(
                launch_id,
                target,
                &policy_context,
                dry_run,
                launch_plan(Some(&resolved_exe)),
                identity_fail(detail.clone()),
                identity.finish(),
                detail,
            ));
            return Err(LaunchError::BindLaunchedWorkload { source, report });
        }
        identity.mark_bound();
        match hash::reverify_immediately_before_spawn(
            &argv,
            &resolved_exe,
            &policy.hash_entries,
            audit_logger,
        ) {
            Ok(pin) => spawn_pin = Some(pin),
            Err(source) => {
                let detail = format!("supply chain verification failed at spawn: {source}");
                let report = fail(failure_report(
                    launch_id,
                    target,
                    &policy_context,
                    dry_run,
                    launch_plan(Some(&resolved_exe)),
                    identity_fail(detail.clone()),
                    identity.finish(),
                    detail,
                ));
                return Err(LaunchError::ReverifyBeforeSpawn { source, report });
            }
        }
        identity.mark_reverified();
        // Hash verification, binding, and the pre-spawn reverify all ran
        // to completion — the identity control is verified for this launch.
    }
    // Snapshot the record now — `identity` borrows `argv` and `policy`,
    // which move into the spawn and the Auditor below.
    let code_identity = identity.finish();

    // The child execs `resolved_exe` — the canonicalized, hash-verified
    // image — while `argv` keeps the caller's spelling as the child's
    // argv[0]: a venv `bin/python` locates `pyvenv.cfg` relative to it
    // (on macOS, where CPython ignores argv[0], the Warden passes the
    // spelling via PYTHONEXECUTABLE). Passing the symlink itself to
    // spawn would exec the unverified link.
    if let Some(reason) = sandbox_skip_reason {
        tracing::warn!("sandboxing disabled ({reason})");
    }
    // Unix: the executable execs the pinned object's snapshot — a
    // `/proc/self/fd` descriptor spelling on Linux, the staged copy's
    // owner-only path on Unixes without an exec'able fd directory. A
    // pinned entrypoint script keeps its *real path* instead: the
    // interpreter opens it by name, realpaths it, and resolves sibling
    // and relative imports from its directory, which neither the memfd
    // pseudo-path nor a staged copy in an empty dir can carry. The
    // plan holds the snapshot backing and must stay alive until the
    // child has exec'd (Linux: spawn return; path-exec: the session —
    // it lands in `Launched`).
    #[cfg(unix)]
    let fd_exec_plan = match &spawn_pin {
        Some(pin) => match pin.fd_exec_plan(&argv, &resolved_exe) {
            Ok(plan) => Some(plan),
            Err(source) => {
                let detail = format!("supply chain verification failed at spawn: {source}");
                let report = fail(failure_report(
                    launch_id,
                    target,
                    &policy_context,
                    dry_run,
                    launch_plan(Some(&resolved_exe)),
                    vec![identity_observation_failed(&detail)],
                    code_identity.clone(),
                    detail,
                ));
                return Err(LaunchError::ReverifyBeforeSpawn { source, report });
            }
        },
        None => None,
    };
    #[cfg(unix)]
    let (spawn_exe, spawn_argv_storage) = match &fd_exec_plan {
        Some(plan) => {
            // The dup'd pin descriptors stay CLOEXEC in the parent; the
            // spawn clears the flag inside the child's pre_exec. The
            // staged dirs name the paths a sandboxed child must be
            // granted to exec/read the snapshots (no fd spelling on
            // macOS); empty on Linux.
            spawn_opts.exec_uncloak_fds = plan.uncloak_fds();
            spawn_opts.exec_map_dirs = plan.staged_dirs().to_vec();
            (plan.exe_path().to_path_buf(), plan.exec_argv(&argv))
        }
        None => (resolved_exe.clone(), argv.clone()),
    };
    // macOS: dyld needs file-map-executable on every non-system library
    // it loads — derive the dirs the workload legitimately maps code
    // from (runtime prefix, linked-dylib package dirs, payload package
    // dir) so the sandboxed child can actually start. Independent of
    // pinning: an unpinned Homebrew interpreter needs the same grants.
    #[cfg(target_os = "macos")]
    spawn_opts
        .exec_map_dirs
        .extend(crate::warden::macos_sandbox::code_map_dirs(
            &resolved_exe,
            &argv,
        ));
    // Windows: a payload-bound entrypoint launches through its real
    // path — the interpreter opens it by name *after* CreateProcess and
    // resolves sibling/relative imports from its directory, so a staged
    // copy cannot carry the launch. `entrypoint_exec_argv` re-spells
    // the payload arg to the resolved path the pin verified; the
    // share-mode pin rides `Launched` for the session so the path the
    // interpreter re-opens still names the verified object.
    #[cfg(windows)]
    let spawn_argv_storage = match &spawn_pin {
        Some(pin) => match pin.entrypoint_exec_argv(&argv, &resolved_exe) {
            Ok(argv) => argv,
            Err(source) => {
                let detail = format!("supply chain verification failed at spawn: {source}");
                let report = fail(failure_report(
                    launch_id,
                    target,
                    &policy_context,
                    dry_run,
                    launch_plan(Some(&resolved_exe)),
                    vec![identity_observation_failed(&detail)],
                    code_identity.clone(),
                    detail,
                ));
                return Err(LaunchError::ReverifyBeforeSpawn { source, report });
            }
        },
        None => argv.clone(),
    };
    #[cfg(windows)]
    let spawn_exe = resolved_exe.clone();
    #[cfg(all(not(unix), not(windows)))]
    let (spawn_exe, spawn_argv_storage) = (resolved_exe.clone(), argv.clone());
    let spawn_argv: &[String] = &spawn_argv_storage;
    // PR-16 — the namespaced route's session context (audit sink,
    // correlation id, resolved upstream). `Some` only when the Linux
    // selection resolved `namespaced`; the Warden dispatch routes on
    // its stored selection, so this block only feeds the context.
    #[cfg(target_os = "linux")]
    let ns_ctx = (warden.linux_selected_mechanism()
        == Some(crate::execution::LinuxNativeMechanism::Namespaced))
    .then(|| crate::warden::NamespacedLaunchCtx {
        launch_id,
        upstream: warden.linux_selection().and_then(|s| s.dns_upstream),
        audit: audit_logger.clone(),
        policy_ctx: policy_context.clone(),
    });
    #[cfg(not(target_os = "linux"))]
    let ns_ctx = None;
    // The last identity check before the spawn — kept after the exec
    // plan/argv are built so it sits immediately against `spawn()`.
    // For a payload-bound entrypoint (which the child interpreter
    // opens by real path) this same-object + stamp re-check *is* the
    // exec-time guarantee; for the exe it pins the *decision* — a
    // retargeted path still fails the launch — while the snapshot
    // exec (or, on Windows, the share-mode pin) binds the *object*.
    // `launch_plan` cannot be consulted here — its `&spawn_opts`
    // borrow is dead once `exec_uncloak_fds`/`exec_map_dirs` were
    // assigned — so the failure report describes the spawn-time plan
    // via a direct call.
    if let Some(pin) = &spawn_pin
        && let Err(source) = pin.verify_spawn_path(&resolved_exe)
    {
        let detail = format!("supply chain verification failed at spawn: {source}");
        let report = fail(failure_report(
            launch_id,
            target,
            &policy_context,
            dry_run,
            warden.enforcement_plan(
                Some(&resolved_exe),
                argv0,
                &spawn_opts,
                sandbox_skip_reason,
                dry_run,
            ),
            vec![identity_observation_failed(&detail)],
            code_identity.clone(),
            detail,
        ));
        return Err(LaunchError::ReverifyBeforeSpawn { source, report });
    }
    let attempt = match sandbox_skip_reason {
        Some(reason) => warden.spawn_unsandboxed_async_exe_with_report(
            &spawn_exe,
            spawn_argv,
            &spawn_opts,
            reason,
            dry_run,
        ),
        None => {
            warden
                .spawn_child_async_exe_with_report_ctx(
                    &spawn_exe,
                    spawn_argv,
                    &spawn_opts,
                    dry_run,
                    ns_ctx,
                )
                .await
        }
    };
    let WardenReport {
        plan,
        mut observations,
    } = attempt.report;
    let mut child = match attempt.outcome {
        Ok(child) => child,
        Err(source) => {
            // Hash verification ran before the spawn attempt — record it
            // even though the launch fails here. It is a Build-phase
            // observation, so it precedes the spawn-phase ones.
            if has_hashes {
                observations.insert(0, identity_observation(&code_identity));
            }
            // The responsible component (Warden) and stage are inside
            // `source`; the `fail` helper records a `server.error` audit
            // event under the same launch_id so the JSONL log carries the
            // same fact the report does.
            let report = fail(failure_report(
                launch_id,
                target,
                &policy_context,
                dry_run,
                plan,
                observations,
                code_identity.clone(),
                format!("server spawn failed: {source}"),
            ));
            return Err(LaunchError::Spawn {
                argv,
                source,
                report,
            });
        }
    };
    // Workload argv can carry credentials (tokens, passwords, inline
    // eval strings) — INFO logs the executable identity and argument
    // count only. The complete argv stays behind explicit unsafe
    // debug consent (`MCP_WRIT_LOG_ARGV=1`) so a default deployment
    // never writes it to a log stream.
    let exe_name = argv.first().map(String::as_str).unwrap_or("(empty)");
    tracing::info!("{spawned_log_label}: {exe_name} ({} args)", argv.len());
    if std::env::var_os("MCP_WRIT_LOG_ARGV").is_some_and(|v| v == "1") {
        tracing::debug!("{spawned_log_label} argv: {argv:?}");
    }

    let (child_stdin, child_stdout) = match child.take_io() {
        Some(io) => io,
        None => {
            if has_hashes {
                observations.insert(0, identity_observation(&code_identity));
            }
            let report = fail(failure_report(
                launch_id,
                target,
                &policy_context,
                dry_run,
                plan,
                observations,
                code_identity.clone(),
                "failed to capture child process stdin/stdout".to_string(),
            ));
            return Err(LaunchError::TakeIo {
                child: Box::new(child),
                report,
            });
        }
    };

    let auditor = Auditor::new(policy, audit_logger.clone())
        .with_dry_run(dry_run)
        .with_fail_on(fail_on)
        .with_max_frame_bytes(max_frame_bytes);
    let auditor_handle = tokio::spawn(async move { auditor.run(child_stdin, child_stdout).await });

    // Observations only the launch path can take: the pre-spawn identity
    // checks (Build phase — inserted ahead of the spawn-phase entries)
    // and placeholders for the session checks the running Auditor
    // performs — spawning the relay is not itself evidence they ran.
    if has_hashes {
        observations.insert(0, identity_observation(&code_identity));
    }
    let rpc_reason = if dry_run {
        Some("dry-run: observable tools/call denials are forwarded and logged; other violations stay blocked".to_string())
    } else {
        Some("auditor relay running".to_string())
    };
    for ctrl in plan.controls.iter() {
        if ctrl.layer == ControlLayer::Rpc && ctrl.state == ControlState::Planned {
            observations.push(EnforcementObservation {
                control: ctrl.id,
                state: ControlState::Unknown,
                basis: ObservationBasis::NotObserved,
                phase: ControlPhase::Session,
                reason: rpc_reason.clone(),
            });
        }
    }

    let report = LaunchReport {
        schema_version: LAUNCH_REPORT_SCHEMA_VERSION,
        launch_id,
        created_at: now_iso8601_millis(),
        target,
        policy: policy_context.clone(),
        dry_run,
        plan,
        observations,
        // The session is now running; the caller rewrites this with the
        // observed outcome at exit.
        result: Some(LaunchOutcome {
            status: "running",
            detail: None,
            exit_code: None,
        }),
        code_identity: Some(code_identity),
        // `mcp-secure-runner` fills this in when it re-emits the report
        // as its own guest-side record.
        guest_runner: None,
        guest: None,
        // A native launch involves no isolation backend.
        isolation: None,
    };
    tracing::debug!("launch report: {}", report.to_json());

    let session_audit = crate::runtime::lifecycle::SessionAuditContext {
        launch_id,
        policy: policy_context.clone(),
        component,
    };
    // The audited session opens: `session.started` brackets the relay's
    // lifetime, `server.connected` records the spawn inside it. Both
    // share the launch_id correlation the report carries.
    crate::runtime::lifecycle::session_started(audit_logger, &session_audit);
    let mut event = AuditEvent::new(
        launch_id,
        EventType::ServerConnected,
        Severity::Info,
        Outcome::Success,
        Action::Observed,
    );
    if let Some(ctx) = &policy_context
        && ctx.id != "default"
    {
        event.target_server = Some(ctx.id.clone());
    }
    event.policy_context = policy_context;
    let mut details = format!(
        "spawned {} backend={}",
        resolved_exe.display(),
        backend.as_str()
    );
    if dry_run {
        details.push_str(" (dry-run)");
    }
    if sandbox_skip_reason.is_some() {
        // A skipped OS sandbox is stated on the spawn record itself —
        // `guard.started` carries the cause, this event the effect.
        details.push_str(" sandbox=skipped");
    }
    if env_inherit_parent {
        // Ambient environment inheritance is an explicit downgrade —
        // the spawn record names it rather than reading as neutral.
        details.push_str(" env=inherit-parent");
    }
    // The exec method a hash pin produced is part of the launch's
    // security surface: the exe image is snapshot-exec'd (`fd` on
    // Linux, `staged` on other Unix, the share-mode-pinned path on
    // Windows); a payload-bound entrypoint launches by `path` — an
    // interpreter resolves its module and imports from that path,
    // which a snapshot spelling cannot carry.
    #[cfg(unix)]
    if let Some(plan) = &fd_exec_plan {
        details.push_str(&format!(" exe_exec={}", plan.exe_exec_mode()));
        if plan.entrypoint_exec_mode().is_some() {
            details.push_str(" entrypoint_exec=path");
        }
    }
    #[cfg(windows)]
    if spawn_pin
        .as_ref()
        .is_some_and(|pin| pin.has_pinned_entrypoint())
    {
        details.push_str(" entrypoint_exec=path");
    }
    // OS controls the launch tolerated below full enforcement ride the
    // same observations the report carries — not a separate computation.
    details.push_str(&weakened_os_tokens(&report.observations));
    details.push_str(&format!(" session_id={}", audit_logger.session_id()));
    event.details = Some(details);
    // The machine-readable mirror of `details`: backend, effective
    // control states, grant counts, and the PSEC digest — built from the
    // same `plan`/`observations` the report file carries.
    event.enforcement = Some(
        EnforcementSummary::build(&report.plan, &report.observations, backend, dry_run).to_json(),
    );
    audit_logger.log(event);

    Ok(Launched {
        child,
        auditor_handle,
        report,
        session_audit,
        _spawn_pin: spawn_pin,
        #[cfg(all(unix, not(target_os = "linux")))]
        _exec_staging: fd_exec_plan,
    })
}

/// `launch.identity` observation: hash verification, workload binding, and
/// the pre-spawn reverify all ran to completion — a failed verification
/// never reaches this point (it aborts the launch earlier). The reason
/// keeps binding distinct from content-only verification: only pins that
/// earned the `bind_path` check bind the process, and re-verification
/// narrows the hash-to-exec window without closing it.
fn identity_observation(identity: &CodeIdentity) -> EnforcementObservation {
    let total = identity.pins.len();
    // A pin binds the process only when its bind-path check actually
    // passed — role alone overstates it (`binary-hash` whose target is
    // not the resolved exe verifies content but binds nothing).
    let binding = identity
        .pins
        .iter()
        .filter(|p| p.checks.contains(&PinCheck::BindPath))
        .count();
    let content_only = total - binding;
    let reason = if content_only == 0 {
        format!(
            "{total} hash entries verified and bound to the launch; \
             re-verified immediately before spawn (the hash-to-exec window \
             narrows but is not closed)"
        )
    } else {
        let rest = if content_only == 1 {
            "1 entry verifies content only and does not bind the process".to_string()
        } else {
            format!("{content_only} entries verify content only and do not bind the process")
        };
        format!(
            "{binding} of {total} hash entries bind the launched process and \
             were re-verified before spawn; {rest}"
        )
    };
    EnforcementObservation {
        control: "launch.identity",
        state: ControlState::Verified,
        basis: ObservationBasis::VerificationRun,
        phase: ControlPhase::Build,
        reason: Some(reason),
    }
}

/// `launch.identity` observation for a verification that ran and failed:
/// the check did execute (`VerificationRun`), its outcome is `Failed`,
/// and `reason` carries the refused detail.
fn identity_observation_failed(detail: &str) -> EnforcementObservation {
    EnforcementObservation {
        control: "launch.identity",
        state: ControlState::Failed,
        basis: ObservationBasis::VerificationRun,
        phase: ControlPhase::Build,
        reason: Some(detail.to_string()),
    }
}

/// `server.connected` detail tokens for OS-layer controls the launch
/// tolerated below full enforcement — one `<control>=<state>` pair per
/// `os.*` observation that came back `partially_applied`, `not_applied`,
/// or `failed` (a tolerated `allow_degraded` outcome, an unenforceable
/// rule set, a failed grant on a spawn that still completed).
/// `launch.*`/`rpc.*` observations never express kernel enforcement and
/// are filtered by the `os.` prefix; `unknown` is deliberately absent —
/// it records an observation limit (e.g. in-kernel profile acceptance),
/// not a weakening the launch accepted. Token-free therefore means only
/// *no accepted weakening was observed* — `skipped` and `not_applicable`
/// controls emit no token either, so whether a control actually
/// enforced is answered by the report's `observations`, never inferred
/// from token absence. A skipped OS sandbox is the one absence that
/// names itself: `sandbox=skipped`.
fn weakened_os_tokens(observations: &[EnforcementObservation]) -> String {
    let mut out = String::new();
    for o in observations {
        if o.control.starts_with("os.")
            && matches!(
                o.state,
                ControlState::PartiallyApplied | ControlState::NotApplied | ControlState::Failed
            )
        {
            out.push_str(&format!(" {}={}", o.control, o.state.as_str()));
        }
    }
    out
}

/// A report for a launch that never reached a running session: the plan
/// the launch was built on plus whatever observations the failed stage
/// produced, and `result = failed` so a `--report` write is never an
/// empty success.
#[expect(clippy::too_many_arguments)]
fn failure_report(
    launch_id: uuid::Uuid,
    target: ExecutionTarget,
    policy_context: &Option<PolicyAuditContext>,
    dry_run: bool,
    plan: EnforcementPlan,
    observations: Vec<EnforcementObservation>,
    code_identity: CodeIdentity,
    detail: String,
) -> Box<LaunchReport> {
    Box::new(LaunchReport {
        schema_version: LAUNCH_REPORT_SCHEMA_VERSION,
        launch_id,
        created_at: now_iso8601_millis(),
        target,
        policy: policy_context.clone(),
        dry_run,
        plan,
        observations,
        result: Some(LaunchOutcome {
            status: "failed",
            detail: Some(detail),
            exit_code: Some(1),
        }),
        code_identity: Some(code_identity),
        guest_runner: None,
        guest: None,
        isolation: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn obs(control: &'static str, state: ControlState) -> EnforcementObservation {
        EnforcementObservation {
            control,
            state,
            basis: ObservationBasis::MechanismResult,
            phase: ControlPhase::Spawn,
            reason: None,
        }
    }

    /// Every OS control verified — no weakening tokens on the record.
    #[test]
    fn weakened_os_tokens_silent_on_full_enforcement() {
        let observations = vec![
            obs("os.privileges", ControlState::Verified),
            obs("os.fs", ControlState::Verified),
            obs("os.net.outbound", ControlState::Verified),
            obs("launch.identity", ControlState::Verified),
            obs("rpc.tools", ControlState::Unknown),
        ];
        assert_eq!(weakened_os_tokens(&observations), "");
    }

    /// A tolerated partial/absent application names the affected
    /// controls with the same state vocabulary the report uses.
    #[test]
    fn weakened_os_tokens_names_degraded_controls() {
        let observations = vec![
            obs("os.fs", ControlState::PartiallyApplied),
            obs("os.net.outbound", ControlState::NotApplied),
            obs("os.syscalls", ControlState::Verified),
        ];
        assert_eq!(
            weakened_os_tokens(&observations),
            " os.fs=partially_applied os.net.outbound=not_applied"
        );
    }

    /// Non-OS observations never leak into the token list, and `unknown`
    /// stays silent — an observation limit is not a tolerated weakening.
    #[test]
    fn weakened_os_tokens_excludes_non_os_and_unknown() {
        let observations = vec![
            obs("os.sandbox", ControlState::Unknown),
            obs("os.fs", ControlState::Unknown),
            obs("launch.env", ControlState::Failed),
            obs("launch.identity", ControlState::Failed),
            obs("rpc.tools", ControlState::Failed),
        ];
        assert_eq!(weakened_os_tokens(&observations), "");
    }

    /// An OS control whose apply failed beside a completed spawn is a
    /// weakening too — it must not read as full enforcement.
    #[test]
    fn weakened_os_tokens_records_failed_os_control() {
        let observations = vec![
            obs("os.fs", ControlState::Failed),
            obs("os.privileges", ControlState::Verified),
        ];
        assert_eq!(weakened_os_tokens(&observations), " os.fs=failed");
    }

    /// `Warden::sandbox_backend` names the mechanism this host's
    /// sandboxed dispatch is bound to — the value `enforcement.backend`
    /// and the `backend=` detail token report. A caller-side sandbox
    /// skip maps to `SandboxBackend::None` at the call site, not here;
    /// a mechanism absent on this host binds to no backend and reports
    /// `None` instead.
    #[test]
    fn sandbox_backend_matches_platform_dispatch() {
        let warden = Warden::new(Policy::default());
        #[cfg(target_os = "linux")]
        assert_eq!(warden.sandbox_backend(), SandboxBackend::LandlockSeccomp);
        #[cfg(target_os = "macos")]
        assert_eq!(warden.sandbox_backend(), SandboxBackend::SandboxExec);
        #[cfg(target_os = "windows")]
        assert_eq!(warden.sandbox_backend(), SandboxBackend::AppContainer);
        #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
        assert_eq!(warden.sandbox_backend(), SandboxBackend::None);

        #[cfg(target_os = "windows")]
        {
            let psec = Warden::with_windows_mechanism(
                Policy::default(),
                crate::execution::WindowsNativeMechanism::Psec,
            );
            assert_eq!(psec.sandbox_backend(), SandboxBackend::Psec);
        }

        // A requested mechanism that does not exist on this host binds
        // to no backend — the launch refuses rather than report a
        // mechanism the dispatch can never run under.
        #[cfg(not(target_os = "windows"))]
        {
            let psec = Warden::with_windows_mechanism(
                Policy::default(),
                crate::execution::WindowsNativeMechanism::Psec,
            );
            assert_eq!(psec.sandbox_backend(), SandboxBackend::None);
        }
    }

    /// PR-26 — the legacy dispatch (`linux_mechanism: None`, the
    /// in-guest runner's contract) must refuse a UDP-covered allow
    /// under deny-all before spawn: the native route's socket pin
    /// would make the grant dead policy. The refusal rides
    /// `LaunchError::Spawn` carrying the "dead policy" evidence the
    /// selection verdict produces.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn legacy_dispatch_refuses_udp_allow_under_deny_all() {
        let mut policy = Policy::default();
        policy.network.outbound.egress_rules = vec![crate::policy::EgressRule {
            allow: true,
            dest: crate::policy::EgressDest::Host("203.0.113.5".to_string()),
            proto: crate::policy::EgressProto::Udp,
            port: Some(53),
        }];
        let logger = AuditLogger::to_tracing();
        let err = launch(
            LaunchConfig {
                argv: vec!["/bin/true".to_string()],
                policy,
                fail_on: FailOn::None,
                dry_run: false,
                skip_sandbox: false,
                skip_reason: None,
                spawned_log_label: "test",
                policy_context: None,
                launch_id: None,
                workload_tmpdir: None,
                windows_mechanism: None,
                linux_mechanism: None,
                dns_upstream: None,
                component: "test",
                max_frame_bytes: crate::framing::DEFAULT_MAX_FRAME_BYTES,
            },
            &logger,
        )
        .await
        .err()
        .expect("a UDP allow under deny-all must refuse on the legacy dispatch");
        let LaunchError::Spawn { source, report, .. } = err else {
            panic!("expected LaunchError::Spawn");
        };
        assert!(
            source.to_string().contains("dead policy"),
            "source: {source}"
        );
        let detail = report
            .result
            .as_ref()
            .and_then(|r| r.detail.as_deref())
            .unwrap_or("");
        assert!(
            detail.contains("linux egress policy refused"),
            "detail: {detail}"
        );
        // The target must not claim a mechanism — nothing was bound.
        assert!(
            report.target.native_linux_mechanism.is_none(),
            "refused launch must not record a bound mechanism: {:?}",
            report.target
        );
    }

    /// A `Some(_)` request reaches selection instead — a policy both
    /// routes refuse (an IPv6 + UDP-covering allow: v6 is dropped on
    /// the namespaced route and the rule is dead on the native one)
    /// surfaces the selection's verdict on every host, never the
    /// legacy-only gate's `linux egress policy refused` detail.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn explicit_request_uses_selection_not_the_legacy_gate() {
        let mut policy = Policy::default();
        policy.network.outbound.egress_rules = vec![crate::policy::EgressRule {
            allow: true,
            dest: crate::policy::EgressDest::Cidr("2001:db8::/32".to_string()),
            proto: crate::policy::EgressProto::Any,
            port: None,
        }];
        let logger = AuditLogger::to_tracing();
        let err = launch(
            LaunchConfig {
                argv: vec!["/bin/true".to_string()],
                policy,
                fail_on: FailOn::None,
                dry_run: false,
                skip_sandbox: false,
                skip_reason: None,
                spawned_log_label: "test",
                policy_context: None,
                launch_id: None,
                workload_tmpdir: None,
                windows_mechanism: None,
                linux_mechanism: Some(crate::execution::LinuxMechanismRequest::Auto),
                dns_upstream: None,
                component: "test",
                max_frame_bytes: crate::framing::DEFAULT_MAX_FRAME_BYTES,
            },
            &logger,
        )
        .await
        .err()
        .expect("a policy no route satisfies must refuse pre-spawn");
        let LaunchError::Spawn { report, .. } = err else {
            panic!("expected LaunchError::Spawn");
        };
        let detail = report
            .result
            .as_ref()
            .and_then(|r| r.detail.as_deref())
            .unwrap_or("");
        assert!(
            detail.contains("linux egress mechanism selection refused"),
            "detail: {detail}"
        );
        assert!(
            !detail.contains("linux egress policy refused"),
            "detail: {detail}"
        );
    }
}
