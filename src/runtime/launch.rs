use std::path::{Path, PathBuf};

use crate::audit_log::{
    Action, AuditEvent, AuditLogger, EventType, Outcome, PolicyAuditContext, Severity,
    encode_audit_field_value, now_iso8601_millis,
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

/// The binary a launch's records are emitted by. Selects both the
/// `guard.*` audit stamp and the stderr wording
/// [`LaunchError::describe`] renders, so the wording can never silently
/// follow a renamed component string.
#[derive(Clone, Copy, Debug)]
pub enum Emitter {
    /// The host `mcp-writ` CLI.
    Host,
    /// The in-guest `mcp-secure-runner`.
    Guest,
}

impl Emitter {
    /// The component name stamped onto `guard.*` lifecycle records.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Host => "mcp-writ",
            Self::Guest => "mcp-secure-runner",
        }
    }
}

/// Per-binary inputs to [`launch`].
///
/// Callers resolve policy loading, `bind_to_server`, `FailOn`, and audit-log
/// requirements before calling. `skip_sandbox` is also computed by the caller:
/// this function never reads `MCP_WRIT_SKIP_SANDBOX` itself (the container
/// runner strips that variable before launch, and reading it here would break
/// image ENV handling and tests).
pub struct LaunchConfig {
    /// Command argv as the caller spelled it; `argv[0]` is resolved and
    /// verified here. The child keeps its spelling as `argv[0]` — except
    /// under a pinned Unix `#!` expansion, which heads argv with the
    /// interpreter instead — while the resolved path is exec'd as the
    /// process image. That expansion's script argument holds the
    /// caller's spelling only while the script stays unpinned; a
    /// payload-bound entrypoint is re-spelled to its resolved real
    /// path. Must be non-empty.
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
    /// Emitting binary for `guard.*` lifecycle records — also selects
    /// the stderr wording [`LaunchError::describe`] renders.
    pub component: Emitter,
    /// `--max-frame-bytes` — the JSON-RPC frame cap both relay
    /// directions enforce (`framing::DEFAULT_MAX_FRAME_BYTES` when the
    /// caller did not override). The in-guest runner resolves it from
    /// `MCP_WRIT_MAX_FRAME_BYTES`.
    pub max_frame_bytes: usize,
}

/// The reap budget [`Launched::abort`] gives `kill → wait` — the same
/// 5-second grace `forward_signal_with_grace` uses for signal handling.
/// Past it the abort proceeds without the reap and the audit bracket
/// records `kill_unconfirmed` rather than `killed`.
const ABORT_REAP_GRACE: std::time::Duration = std::time::Duration::from_secs(5);

/// Kill → wait a spawned child under [`ABORT_REAP_GRACE`], reporting
/// whether the reap was confirmed. `kill()` already sweeps descendants
/// and reaps on Unix, and the Windows Job terminate is synchronous —
/// but an unkillable or driver-wedged child must not hang the calling
/// teardown. A timed-out or failed kill still reaches `Drop`'s
/// best-effort `start_kill`. Shared by [`Launched::abort`], whose audit
/// reason depends on the outcome, and [`LaunchError::into_report`],
/// which must not let a wedged child hold the failure path forever.
async fn reaped_within_grace(child: &mut RunningChild) -> bool {
    matches!(
        tokio::time::timeout(ABORT_REAP_GRACE, async {
            child.kill().await.ok()?;
            child.wait().await.ok()
        })
        .await,
        Ok(Some(_))
    )
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
    /// Post-spawn resources the session owns for its whole lifetime —
    /// see [`SessionKeeps`].
    pub keeps: SessionKeeps,
    /// The Auditor's session call tally — read back at session end
    /// to compute the report's correction candidates.
    pub call_tally: crate::auditor::proxy_state::SharedCallTally,
    /// Tool names the bound policy declares (`allowed`), in policy
    /// order — the population the candidates' unused set is drawn from.
    pub declared_tools: Vec<String>,
}

/// Post-spawn resources a session holds but never reads: dropping them
/// releases the guarantee they carry, so they live exactly as long as
/// `Launched` and are reclaimed with it. The single owner of the
/// spawn-boundary pins — no other handle may outlive the session.
pub struct SessionKeeps {
    /// The verified workload objects (executable + any payload-bound
    /// entrypoint script), held open for the session. On Windows the
    /// `FILE_SHARE_READ`-only share mode is load-bearing for the whole
    /// lifetime: a pinned entrypoint launches by its real path — the
    /// interpreter opens it *after* CreateProcess — so the held pin is
    /// what keeps that path naming the verified object; dropping it at
    /// spawn-return reopens the replace window. On Unix the held
    /// handles remain the identity anchors `verify_spawn_path` checked.
    _spawn_pin: Option<hash::SpawnPin>,
    /// Non-Linux Unix: the exec plan's exe spelling is the staged
    /// copy's path — it must resolve at the child's `execve`, which
    /// runs after `spawn()` returns on the fork+pre_exec path, so the
    /// plan rides the session like `_spawn_pin`. Linux needs nothing:
    /// its inherited descriptor names the snapshot, not a path.
    #[cfg(all(unix, not(target_os = "linux")))]
    _exec_staging: Option<crate::verifier::hash::FdExecPlan>,
}

impl Launched {
    /// Kill the running child, abort the Auditor relay, and close the
    /// audit bracket under `outcome` — the shared post-launch abort for
    /// a caller-side failure (e.g. an unwritable `--report`) that must
    /// not leave the workload running behind a `failed` result. The
    /// child is reaped before the relay is aborted and the bracket is
    /// closed, so nothing is waited on twice and nothing is left
    /// running. Returns once the teardown has run; the caller exits
    /// nonzero.
    pub async fn abort(self, audit_logger: &AuditLogger, outcome: LaunchOutcome) {
        let mut child = self.child;
        // `reason` records `killed` only once the reap is confirmed — a
        // timed-out or failed kill leaves Drop's best-effort `start_kill`
        // and the bracket cannot claim a dead workload that may still
        // run.
        let reaped = reaped_within_grace(&mut child).await;
        drop(child);
        self.auditor_handle.abort();
        // Await the aborted task — `abort()` only schedules the stop,
        // and the audit bracket below must not close while the relay
        // could still emit session events into it. An already-finished
        // task resolves immediately with its own result.
        let _ = self.auditor_handle.await;
        let _ = crate::runtime::lifecycle::teardown(
            audit_logger,
            &self.session_audit,
            if reaped { "killed" } else { "kill_unconfirmed" },
            &outcome,
        )
        .await;
    }
}

/// Which stage of [`launch`] failed, with that stage's payload.
pub enum LaunchErrorKind {
    /// `resolve_launch` failed; `command` is the unresolved `argv[0]`.
    ResolveCommand {
        command: String,
        source: std::io::Error,
    },
    /// `verify_server_hashes` failed for `server_name`.
    VerifyServerHashes {
        server_name: String,
        source: VerifyError,
    },
    /// `bind_launched_workload` failed.
    BindLaunchedWorkload { source: VerifyError },
    /// `reverify_immediately_before_spawn` failed — or a spawn-side gate
    /// that re-proves the pin (`fd_exec_plan`, the Windows argv respell,
    /// the final `verify_spawn_path` check) did.
    ReverifyBeforeSpawn { source: VerifyError },
    /// The launch refused before spawn (Linux selection/dead-policy
    /// gates carry the caller's argv) or the Warden spawn itself failed
    /// (the effective argv). The `report` carries the plan the failed
    /// spawn was built from and the failure observations — a refused
    /// launch is still describable.
    Spawn {
        argv: Vec<String>,
        source: WardenError,
    },
    /// `take_io` failed; ownership of the child is returned — the
    /// already-spawned child must be reaped, which
    /// [`LaunchError::into_report`] performs in the usual kill → wait →
    /// drop order. `keeps` moves the session-boundary pins into the
    /// error so they drop *after* the reap: releasing the share-mode
    /// pin or the staged-exec dir first would reopen the replace
    /// window while the child is still being killed.
    TakeIo {
        child: Box<RunningChild>,
        keeps: SessionKeeps,
    },
}

/// Failure at one step of [`launch`]. Callers print [`Self::describe`],
/// take the report with [`Self::into_report`], and close the audit
/// bracket — the per-stage wording and the `TakeIo` reap live here so
/// no caller re-implements them.
///
/// `report` is the enforcement plan this launch was built on plus a
/// `result` of `failed`, so a `--report` consumer always gets the same
/// schema for a refused or failed launch — never an empty success and
/// never an unsupported shape.
pub struct LaunchError {
    /// The failed stage and its payload.
    pub kind: LaunchErrorKind,
    /// The stage's failure report — carried by every kind uniformly, so
    /// the caller never matches variants just to reach it.
    pub report: Box<LaunchReport>,
    /// The emitting binary — `describe` renders its stderr wording.
    component: Emitter,
}

impl LaunchError {
    /// The stderr line for this failure, rendered in the emitting
    /// binary's wording. [`Emitter::Guest`] prefixes every line with
    /// its component name and uses lowercase stage text; the host `run`
    /// prefixes non-hash stages `Error: ` while the hash stages keep
    /// their standalone `Supply chain verification failed…` form.
    pub fn describe(&self) -> String {
        let guest = matches!(self.component, Emitter::Guest);
        match &self.kind {
            LaunchErrorKind::ResolveCommand { command, source } => {
                if guest {
                    format!(
                        "{}: cannot resolve command '{command}': {source}",
                        self.component.as_str()
                    )
                } else {
                    format!("Error: cannot resolve command '{command}': {source}")
                }
            }
            LaunchErrorKind::VerifyServerHashes {
                server_name,
                source,
            } => {
                if guest {
                    format!(
                        "{}: supply chain verification failed for '{server_name}': {source}",
                        self.component.as_str()
                    )
                } else {
                    format!("Supply chain verification failed for '{server_name}': {source}")
                }
            }
            LaunchErrorKind::BindLaunchedWorkload { source } => {
                if guest {
                    format!(
                        "{}: supply chain verification failed: {source}",
                        self.component.as_str()
                    )
                } else {
                    format!("Supply chain verification failed: {source}")
                }
            }
            LaunchErrorKind::ReverifyBeforeSpawn { source } => {
                if guest {
                    format!(
                        "{}: supply chain verification failed at spawn: {source}",
                        self.component.as_str()
                    )
                } else {
                    format!("Supply chain verification failed at spawn: {source}")
                }
            }
            LaunchErrorKind::Spawn { argv, source } => {
                let command_name = argv.first().map(String::as_str).unwrap_or("(empty)");
                if guest {
                    format!(
                        "{}: failed to spawn child process '{command_name}' ({} args): {source}",
                        self.component.as_str(),
                        argv.len()
                    )
                } else {
                    format!("Error: failed to spawn MCP server '{command_name}': {source}")
                }
            }
            LaunchErrorKind::TakeIo { .. } => {
                if guest {
                    format!(
                        "{}: failed to capture child stdin/stdout",
                        self.component.as_str()
                    )
                } else {
                    "Error: failed to capture child process stdin/stdout".to_string()
                }
            }
        }
    }

    /// Consume the error into its failure report, reaping the child a
    /// `TakeIo` stage carries — kill → wait → drop in the order every
    /// teardown follows, so a spawned child is never left running
    /// behind a `failed` report and is never waited on twice. The
    /// variant's `keeps` stays inside `self` until it drops — after the
    /// reap — so the pins still name the verified object while the
    /// child is killed.
    pub async fn into_report(self) -> Box<LaunchReport> {
        if let LaunchErrorKind::TakeIo { mut child, .. } = self.kind {
            // Bounded like `Launched::abort` — a child that refuses to
            // die cannot hold the failure path forever, and `Drop`
            // still issues its best-effort kill when we walk away.
            let _ = reaped_within_grace(&mut child).await;
            drop(child);
        }
        self.report
    }
}

/// Everything a launch failure describes itself with: the correlation
/// id, execution target, bound-policy identity, run flags, backend, the
/// emitting binary, and the audit sink the `server.error` record goes
/// to. Every stage reports through this single context, so a failure
/// report and its audit record are built identically whoever fails —
/// the report and the `server.error` event can never drift apart. The
/// session-start stage also reads it: the same id and policy identity
/// stamp `session.started`/`server.connected`.
struct FailCtx<'a> {
    audit_logger: &'a AuditLogger,
    launch_id: uuid::Uuid,
    target: ExecutionTarget,
    policy_context: Option<PolicyAuditContext>,
    dry_run: bool,
    backend: SandboxBackend,
    component: Emitter,
}

impl FailCtx<'_> {
    /// A report for a launch that never reached a running session — the
    /// plan the launch was built on plus whatever observations the
    /// failed stage produced, and `result = failed` so a `--report`
    /// write is never an empty success — plus the `server.error` audit
    /// event correlated under the same launch id, so a failed launch is
    /// auditable under the same id and the record carries the same
    /// plan/observations the `--report` file does.
    fn fail(
        &self,
        plan: EnforcementPlan,
        observations: Vec<EnforcementObservation>,
        code_identity: CodeIdentity,
        detail: String,
    ) -> Box<LaunchReport> {
        let report = Box::new(LaunchReport {
            schema_version: LAUNCH_REPORT_SCHEMA_VERSION,
            launch_id: self.launch_id,
            created_at: now_iso8601_millis(),
            target: self.target.clone(),
            policy: self.policy_context.clone(),
            dry_run: self.dry_run,
            allow_replaceable_paths: crate::fspriv::replaceable_paths_permitted(),
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
            correction_candidates: None,
        });
        let mut event = AuditEvent::new(
            self.launch_id,
            EventType::ServerError,
            Severity::High,
            Outcome::Failure,
            Action::Observed,
        );
        event.policy_context = self.policy_context.clone();
        // The bound server name only — never the "default" label a
        // server-less policy reports.
        if let Some(ctx) = &self.policy_context
            && ctx.id != "default"
        {
            event.target_server = Some(ctx.id.clone());
        }
        // `session_id` keeps the record attributable when the host's
        // and the guest runner's JSONL streams merge under one launch
        // id; the failure detail follows verbatim.
        let mut details = format!("session_id={}", self.audit_logger.session_id());
        if let Some(detail) = report.result.as_ref().and_then(|r| r.detail.as_deref()) {
            details.push_str(&format!(" {detail}"));
        }
        event.details = Some(details);
        // The same plan/observations the `--report` file carries, as the
        // record's structured `enforcement` member — a failed launch
        // states what it attempted, not just the error string.
        event.enforcement = Some(
            EnforcementSummary::build(
                &report.plan,
                &report.observations,
                self.backend,
                self.dry_run,
            )
            .to_json(),
        );
        self.audit_logger.log(event);
        report
    }

    /// Wrap a stage's payload and its failure report into the public
    /// error — `component` stamps whose stderr wording `describe`
    /// renders.
    fn err(&self, kind: LaunchErrorKind, report: Box<LaunchReport>) -> LaunchError {
        LaunchError {
            kind,
            report,
            component: self.component,
        }
    }
}

/// What the spawn execs and the argv it sees — `exec_spelling`'s output.
/// The fd-exec plan (Unix) stays alive through spawn and, where its
/// staged copy must resolve at `execve`, into the session keeps.
struct ExecSpelling {
    /// The executable image the child execs — the pinned snapshot's
    /// spelling where `fd_exec` applies, else the resolved real path.
    exe: PathBuf,
    /// The argv the child sees — the caller's spelling, a pinned `#!`
    /// expansion, or a payload-bound entrypoint re-spelled to its
    /// resolved real path.
    argv: Vec<String>,
    /// The snapshot-exec plan — Linux execs through an inherited
    /// descriptor and needs no retention; other Unixes exec the staged
    /// copy's path, which must resolve at execve, so the plan moves
    /// into the session keeps.
    #[cfg(unix)]
    fd_exec: Option<hash::FdExecPlan>,
}

/// The spawn stage's output: the running child plus the report inputs
/// the spawn produced — `into_session` consumes it.
struct Spawned {
    child: RunningChild,
    plan: EnforcementPlan,
    observations: Vec<EnforcementObservation>,
    /// The allowlist snapshot `warn_env_allowlist_gaps` captured and
    /// `set_env_contract` bound onto the Warden — the `server.connected`
    /// details report its gaps verbatim.
    env_contract: Option<crate::warden::EnvContractReport>,
}

/// The launch pipeline's prepared state — everything decided from
/// `LaunchConfig` before the workload pipeline runs: the bound Warden
/// (policy + mechanism selection + env contract), the spawn options,
/// the failure context every stage reports through, and the flags the
/// stage methods need. `launch` drives the stage methods in order;
/// each produces exactly what the next consumes, so ownership of the
/// prepared policy, the verified pins, the spawned child, and the
/// session is spelled out per stage.
struct PreparedLaunch<'a> {
    /// The failure-report and `server.error` context.
    fail: FailCtx<'a>,
    /// Caller-spelled argv (pre-resolution).
    argv: Vec<String>,
    /// `argv[0]` as spelled — `resolve_command` resolves it.
    argv0: String,
    /// `!policy.hash_entries.is_empty()` — whether identity pinning runs.
    has_hashes: bool,
    /// The bound policy — cloned into the Warden; moved into the Auditor
    /// at session start.
    policy: Policy,
    /// The bound Warden — owns the mechanism selection, the env
    /// contract, and the sandbox dispatch.
    warden: Warden,
    /// The spawn contract — env restriction plus the exec grants the
    /// `exec_spelling` stage fills in.
    spawn_opts: crate::warden::SpawnOptions,
    /// `Some` on a deliberately unsandboxed launch, with the reason.
    sandbox_skip_reason: Option<&'static str>,
    /// Ambient-inheritance flag — read before `policy` moves into the
    /// Auditor; the `server.connected` detail reports it.
    env_inherit_parent: bool,
    /// The Auditor's failure dial.
    fail_on: FailOn,
    /// First half of the post-spawn `tracing::info!`.
    spawned_log_label: &'static str,
    /// JSON-RPC frame cap for the Auditor.
    max_frame_bytes: usize,
    /// The reverify stage's held pins — `Some` once `verify_and_bind`
    /// mints them; moved into `SessionKeeps` at session start.
    spawn_pin: Option<hash::SpawnPin>,
    /// `--linux-mechanism` request — kept for the legacy dead-policy
    /// gate; the selection itself lives on the Warden.
    #[cfg(target_os = "linux")]
    linux_mechanism: Option<crate::execution::LinuxMechanismRequest>,
    /// A refused selection's reason — `refuse_unenforceable_linux`
    /// turns it into the launch refusal.
    #[cfg(target_os = "linux")]
    linux_refusal: Option<String>,
}

// The error path runs once per process — the struct stays whole rather
// than boxed.
#[allow(clippy::result_large_err)]
impl<'a> PreparedLaunch<'a> {
    /// Prepare the launch: mint the target and Warden, run the Linux
    /// egress selection (Linux only), and derive the spawn options and
    /// failure context. No workload work runs yet — argv resolution and
    /// every pin are later stages.
    fn new(config: LaunchConfig, audit_logger: &'a AuditLogger) -> Self {
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
        let has_hashes = !policy.hash_entries.is_empty();
        let argv0 = argv.first().cloned().unwrap_or_default();

        // The selected mechanism is fail-closed in the Warden: an explicit
        // non-default mechanism that cannot run refuses — it never silently
        // becomes AppContainer.
        #[allow(unused_mut)] // only the Linux `set_linux_selection` below mutates it
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
                // PR-05 — the masked-tree screen judges the same paths the
                // launch resolves below: the resolved executable and the
                // first payload arg must still resolve inside init's mount
                // namespace. A payload-bound entrypoint pin needs no
                // separate input — its path is the same normalized
                // spelling the payload arg screens, and an exe-bound pin
                // execs through `/proc/self/fd/N`. Best-effort: an
                // unresolvable argv[0] carries no visibility and the
                // launch's own resolve step reports that error instead.
                let visibility = crate::workload::resolve_launch(&argv0, has_hashes)
                    .map(|resolution| {
                        let eff_argv = resolution.into_argv(&argv);
                        // An exe a hash entry pins execs the verified
                        // snapshot through `/proc/self/fd/N` inside the
                        // namespace — its *path* is never what init opens,
                        // so the masked screen must not count it.
                        crate::warden::select::workload_visibility(
                            &eff_argv,
                            &resolution.exe,
                            None,
                            crate::warden::select::exe_pin_fd_exec(
                                &policy.hash_entries,
                                &resolution.exe,
                            ),
                        )
                    })
                    .unwrap_or_default();
                crate::warden::select::select_linux_mechanism(
                    request,
                    &policy,
                    dns_upstream,
                    visibility,
                )
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
        let _ = (linux_mechanism, dns_upstream);

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
        let spawn_opts = crate::warden::SpawnOptions {
            restrict_environment: policy.environment.restrict,
            allowed_names: policy.environment.allowed.clone(),
            tmpdir: workload_tmpdir,
            ..Default::default()
        };
        // `policy` moves into `Auditor::new` at session start; the
        // ambient-inheritance flag is needed on the `server.connected`
        // record afterwards.
        let env_inherit_parent = policy.environment.inherit_parent;

        Self {
            fail: FailCtx {
                audit_logger,
                launch_id,
                target,
                policy_context,
                dry_run,
                backend,
                component,
            },
            argv,
            argv0,
            has_hashes,
            policy,
            warden,
            spawn_opts,
            sandbox_skip_reason,
            env_inherit_parent,
            fail_on,
            spawned_log_label,
            max_frame_bytes,
            spawn_pin: None,
            #[cfg(target_os = "linux")]
            linux_mechanism,
            #[cfg(target_os = "linux")]
            linux_refusal,
        }
    }

    /// The plan a report describes: for a failed launch the same builders
    /// still run (nothing is applied), so the report shows what the launch
    /// intended to enforce, not an empty result.
    fn launch_plan(&self, program: Option<&Path>) -> EnforcementPlan {
        self.warden.enforcement_plan(
            program,
            &self.argv0,
            &self.spawn_opts,
            self.sandbox_skip_reason,
            self.fail.dry_run,
        )
    }

    /// Linux only — the two pre-resolve refusals. A refused egress
    /// selection stops the launch here: nothing is spawned and nothing
    /// falls back to the other mechanism; the report still carries the
    /// selection record via `launch_plan` (the Warden already holds the
    /// refused selection). The legacy dispatch (`linux_mechanism ==
    /// None`, the in-guest runner's contract) lands on the same native
    /// route the selection calls unenforceable, with no verdict in the
    /// middle: a UDP-covering allow under deny-all would be dead policy
    /// there (the seccomp pin denies datagram socket creation
    /// outright), and an fs grant rooted on a filesystem Landlock
    /// cannot mediate is dead the same way — as is a mandatory Landlock
    /// control the kernel ABI cannot apply at all (a declared fs grant
    /// or TCP allow on an ABI 0 kernel, a TCP allow under ABI v1-v3).
    /// Both refuse pre-spawn on the same predicates the selection
    /// reports, rather than run a workload whose declared grant never
    /// applies.
    #[cfg(target_os = "linux")]
    fn refuse_unenforceable_linux(&self) -> Result<(), LaunchError> {
        if let Some(reason) = &self.linux_refusal {
            let detail = format!("linux egress mechanism selection refused: {reason}");
            let report = self.fail.fail(
                self.launch_plan(None),
                Vec::new(),
                LaunchIdentity::for_launch(&self.argv, &self.policy.hash_entries).finish(),
                detail,
            );
            return Err(self.fail.err(
                LaunchErrorKind::Spawn {
                    argv: self.argv.clone(),
                    source: WardenError::sandbox_setup(SandboxStage::Policy, reason.clone()),
                },
                report,
            ));
        }
        if self.linux_mechanism.is_none() && self.sandbox_skip_reason.is_none() {
            let mut dead = crate::warden::select::dead_udp_allows_without_selection(&self.policy);
            dead.extend(crate::warden::select::dead_fs_grants_without_selection(
                &self.policy,
            ));
            dead.extend(
                crate::warden::select::dropped_landlock_controls_without_selection(&self.policy),
            );
            if !dead.is_empty() {
                let reason = dead.join("; ");
                let detail = format!("linux egress policy refused: {reason}");
                let report = self.fail.fail(
                    self.launch_plan(None),
                    Vec::new(),
                    LaunchIdentity::for_launch(&self.argv, &self.policy.hash_entries).finish(),
                    detail,
                );
                return Err(self.fail.err(
                    LaunchErrorKind::Spawn {
                        argv: self.argv.clone(),
                        source: WardenError::sandbox_setup(SandboxStage::Policy, reason),
                    },
                    report,
                ));
            }
        }
        Ok(())
    }

    /// Resolve `argv[0]` to the exec image. When the policy pins
    /// workload identity (`has_hashes`), a `#!` script expands to the
    /// interpreter-plus-script launch the kernel would perform: the
    /// interpreter becomes the resolved executable `binary-hash` binds,
    /// and the script the payload `entrypoint-hash` binds — no
    /// kernel-selected interpreter runs unpinned. Unpinned launches
    /// keep the historical direct-exec contract.
    fn resolve_command(&self) -> Result<(Vec<String>, PathBuf), LaunchError> {
        match crate::workload::resolve_launch(&self.argv0, self.has_hashes) {
            Ok(resolution) => Ok((resolution.into_argv(&self.argv), resolution.exe)),
            Err(source) => {
                let detail = format!("cannot resolve command '{}': {source}", self.argv0);
                let report = self.fail.fail(
                    self.launch_plan(None),
                    Vec::new(),
                    LaunchIdentity::for_launch(&self.argv, &self.policy.hash_entries).finish(),
                    detail,
                );
                Err(self.fail.err(
                    LaunchErrorKind::ResolveCommand {
                        command: self.argv0.clone(),
                        source,
                    },
                    report,
                ))
            }
        }
    }

    /// verify → bind → reverify: the held-pin workload is minted per
    /// server name, bound to the launch argv, and re-proved immediately
    /// before spawn — minting the `SpawnPin` `exec_spelling` and
    /// `verify_spawn_path` consume and the session keeps. Returns the
    /// code-identity record (including on the no-hashes path, where it
    /// only marks the resolved executable).
    fn verify_and_bind(
        &mut self,
        argv: &[String],
        resolved_exe: &Path,
    ) -> Result<CodeIdentity, LaunchError> {
        // The code-identity record accumulates which check points each
        // hash pin passed — built over the effective launch argv so an
        // expanded shebang launch reports as the interpreted shape it is.
        let mut identity = LaunchIdentity::for_launch(argv, &self.policy.hash_entries);
        identity.set_resolved(resolved_exe);
        if !self.has_hashes {
            return Ok(identity.finish());
        }
        let server_names: std::collections::HashSet<_> = self
            .policy
            .hash_entries
            .iter()
            .map(|e| e.server_name.as_str())
            .collect();
        // The verify stage mints a held pin per binary/entrypoint
        // target; bind and reverify consume the workload's pins
        // instead of re-reading the targets by path.
        let mut verified = hash::VerifiedWorkload::new();
        for s_name in server_names {
            match verified.verify_server_hashes(
                s_name,
                &self.policy.hash_entries,
                self.fail.audit_logger,
            ) {
                Ok(_) => identity.mark_server_verified(s_name),
                Err(source) => {
                    identity.mark_server_failed(s_name, &source);
                    let detail =
                        format!("supply chain verification failed for '{s_name}': {source}");
                    let report = self.fail.fail(
                        self.launch_plan(Some(resolved_exe)),
                        vec![identity_observation_failed(&detail)],
                        identity.finish(),
                        detail,
                    );
                    return Err(self.fail.err(
                        LaunchErrorKind::VerifyServerHashes {
                            server_name: s_name.to_string(),
                            source,
                        },
                        report,
                    ));
                }
            }
        }
        if let Err(source) = hash::bind_launched_workload(
            argv,
            resolved_exe,
            &self.policy.hash_entries,
            self.fail.audit_logger,
            Some(&mut verified),
        ) {
            let detail = format!("supply chain verification failed: {source}");
            let report = self.fail.fail(
                self.launch_plan(Some(resolved_exe)),
                vec![identity_observation_failed(&detail)],
                identity.finish(),
                detail,
            );
            return Err(self
                .fail
                .err(LaunchErrorKind::BindLaunchedWorkload { source }, report));
        }
        identity.mark_bound();
        // The namespaced route mounts the verified entrypoint bytes
        // over the script's path inside init's mount namespace — the
        // trusted-source gate is skipped only on that route, where the
        // handoff carries the guarantee instead.
        #[cfg(target_os = "linux")]
        let entrypoint_mount_handoff = self.warden.linux_selected_mechanism()
            == Some(crate::execution::LinuxNativeMechanism::Namespaced);
        #[cfg(not(target_os = "linux"))]
        let entrypoint_mount_handoff = false;
        match hash::reverify_immediately_before_spawn(
            argv,
            resolved_exe,
            &self.policy.hash_entries,
            self.fail.audit_logger,
            entrypoint_mount_handoff,
            Some(&mut verified),
        ) {
            Ok(pin) => self.spawn_pin = Some(pin),
            Err(source) => {
                let detail = format!("supply chain verification failed at spawn: {source}");
                let report = self.fail.fail(
                    self.launch_plan(Some(resolved_exe)),
                    vec![identity_observation_failed(&detail)],
                    identity.finish(),
                    detail,
                );
                return Err(self
                    .fail
                    .err(LaunchErrorKind::ReverifyBeforeSpawn { source }, report));
            }
        }
        identity.mark_reverified();
        // Hash verification, binding, and the pre-spawn reverify all ran
        // to completion — the identity control is verified for this launch.
        Ok(identity.finish())
    }

    /// What the spawn execs and how argv reaches it: the executable
    /// execs the pinned snapshot on Unix (a `/proc/self/fd` descriptor
    /// spelling on Linux, an owner-only staged copy elsewhere), a
    /// payload-bound entrypoint launches by its real path — re-spelled
    /// into argv on Windows — and macOS derives the code-map dirs dyld
    /// needs. `spawn_opts` gains the fd/dir grants the plan requires.
    fn exec_spelling(
        &mut self,
        argv: &[String],
        resolved_exe: &Path,
        code_identity: &CodeIdentity,
    ) -> Result<ExecSpelling, LaunchError> {
        if let Some(reason) = self.sandbox_skip_reason {
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
        // it lands in `SessionKeeps`).
        #[cfg(unix)]
        let fd_exec_plan = match &self.spawn_pin {
            Some(pin) => match pin.fd_exec_plan(argv, resolved_exe) {
                Ok(plan) => Some(plan),
                Err(source) => {
                    let detail = format!("supply chain verification failed at spawn: {source}");
                    let report = self.fail.fail(
                        self.launch_plan(Some(resolved_exe)),
                        vec![identity_observation_failed(&detail)],
                        code_identity.clone(),
                        detail,
                    );
                    return Err(self
                        .fail
                        .err(LaunchErrorKind::ReverifyBeforeSpawn { source }, report));
                }
            },
            None => None,
        };
        #[cfg(unix)]
        let (exe, spawn_argv) = match &fd_exec_plan {
            Some(plan) => {
                // The dup'd pin descriptors stay CLOEXEC in the parent; the
                // spawn clears the flag inside the child's pre_exec. The
                // staged dirs name the paths a sandboxed child must be
                // granted to exec/read the snapshots (no fd spelling on
                // macOS); empty on Linux. The entrypoint pin's fd+path ride
                // `exec_entry_pin` so the namespaced dispatch can hand init
                // the descriptor it bind-mounts over the payload path —
                // inert on every other route.
                self.spawn_opts.exec_uncloak_fds = plan.uncloak_fds();
                self.spawn_opts.exec_map_dirs = plan.staged_dirs().to_vec();
                self.spawn_opts.exec_entry_pin = plan
                    .entrypoint_bind_pin()
                    .map(|(fd, p, sha)| (fd, p.to_path_buf(), sha.to_string()));
                (plan.exe_path().to_path_buf(), plan.exec_argv(argv))
            }
            None => (resolved_exe.to_path_buf(), argv.to_vec()),
        };
        // macOS: dyld needs file-map-executable on every non-system library
        // it loads — derive the dirs the workload legitimately maps code
        // from (runtime prefix, linked-dylib package dirs, payload package
        // dir) so the sandboxed child can actually start. Independent of
        // pinning: an unpinned Homebrew interpreter needs the same grants.
        #[cfg(target_os = "macos")]
        {
            self.spawn_opts
                .exec_map_dirs
                .extend(crate::warden::macos_sandbox::code_map_dirs(
                    resolved_exe,
                    argv,
                ));
            // The staged exe relocates `@executable_path`-relative rpaths
            // to the staging dir; the derived dirs restore the real install
            // prefix as dyld's fallback so a shared build (`libnode.dylib`)
            // still links. Deps resolve from their real locations — runtime
            // code is unpinned, same as interpreter imports.
            if let Some(plan) = &fd_exec_plan {
                self.spawn_opts.exec_dyld_fallback =
                    crate::warden::macos_sandbox::staged_exec_dyld_fallback_dirs(
                        plan.exe_path(),
                        resolved_exe,
                    );
            }
        }
        // Windows: a payload-bound entrypoint launches through its real
        // path — the interpreter opens it by name *after* CreateProcess and
        // resolves sibling/relative imports from its directory, so a staged
        // copy cannot carry the launch. `entrypoint_exec_argv` re-spells
        // the payload arg to the resolved path the pin verified; the
        // share-mode pin rides `SessionKeeps` for the session so the path
        // the interpreter re-opens still names the verified object.
        #[cfg(windows)]
        let spawn_argv = match &self.spawn_pin {
            Some(pin) => match pin.entrypoint_exec_argv(argv, resolved_exe) {
                Ok(argv) => argv,
                Err(source) => {
                    let detail = format!("supply chain verification failed at spawn: {source}");
                    let report = self.fail.fail(
                        self.launch_plan(Some(resolved_exe)),
                        vec![identity_observation_failed(&detail)],
                        code_identity.clone(),
                        detail,
                    );
                    return Err(self
                        .fail
                        .err(LaunchErrorKind::ReverifyBeforeSpawn { source }, report));
                }
            },
            None => argv.to_vec(),
        };
        #[cfg(windows)]
        let exe = resolved_exe.to_path_buf();
        #[cfg(all(not(unix), not(windows)))]
        let (exe, spawn_argv) = (resolved_exe.to_path_buf(), argv.to_vec());
        Ok(ExecSpelling {
            exe,
            argv: spawn_argv,
            #[cfg(unix)]
            fd_exec: fd_exec_plan,
        })
    }

    /// The last pre-spawn gates and the spawn itself: the namespaced
    /// session context (Linux), the env allowlist contract — one
    /// snapshot shared by the stderr warnings, the `server.connected`
    /// details, and the spawn's `launch.env` observation — the pin's
    /// final path-identity re-check ordered immediately against the
    /// spawn, then the Warden dispatch. Returns the running child plus
    /// the plan/observations the spawn produced.
    async fn spawn(
        &mut self,
        argv: &[String],
        resolved_exe: &Path,
        exec: &ExecSpelling,
        code_identity: &CodeIdentity,
    ) -> Result<Spawned, LaunchError> {
        // PR-16 — the namespaced route's session context (audit sink,
        // correlation id, resolved upstream). `Some` only when the Linux
        // selection resolved `namespaced`; the Warden dispatch routes on
        // its stored selection, so this block only feeds the context.
        #[cfg(target_os = "linux")]
        let ns_ctx = (self.warden.linux_selected_mechanism()
            == Some(crate::execution::LinuxNativeMechanism::Namespaced))
        .then(|| crate::warden::NamespacedLaunchCtx {
            launch_id: self.fail.launch_id,
            upstream: self.warden.linux_selection().and_then(|s| s.dns_upstream),
            audit: self.fail.audit_logger.clone(),
            policy_ctx: self.fail.policy_context.clone(),
        });
        #[cfg(not(target_os = "linux"))]
        let ns_ctx = None;
        // The allowlist diagnosis for this launch — `Some` only when the
        // environment restriction consults a list — is a names-only
        // snapshot of this process's parent environment, re-read through
        // the same allowlist pass the restricted env block will be built
        // from. A missing name is recorded, never a launch refusal: it
        // lands on the `launch.env` observation, the `server.connected`
        // details, and one stderr warning per gap class (emitted by
        // warn_env_allowlist_gaps, which returns the same snapshot).
        let env_contract = crate::warden::warn_env_allowlist_gaps(&self.spawn_opts);
        // Bind that snapshot onto the warden so the `launch.env`
        // observation the spawn produces describes it verbatim — every
        // reported diagnostic then reflects the one environment read the
        // warnings and audit details already carry, never a second
        // parent-env sample that could diverge from them. The binding
        // keys on the restriction `spawn_opts` carries: a spawn whose
        // options diverged would re-read rather than misreport.
        self.warden
            .set_env_contract(&self.spawn_opts, env_contract.clone());
        // The last identity check before the spawn — run after the exec
        // plan/argv are built *and* after the env contract is bound, so
        // nothing remains between it and the dispatch: a retarget while
        // the warnings and contract above were computed is still caught
        // here. For a payload-bound entrypoint (which the child
        // interpreter opens by real path) this same-object + stamp
        // re-check *is* the exec-time guarantee; for the exe it pins the
        // *decision* — a retargeted path still fails the launch — while
        // the snapshot exec (or, on Windows, the share-mode pin) binds
        // the *object*.
        if let Some(pin) = &self.spawn_pin
            && let Err(source) = pin.verify_spawn_path(resolved_exe)
        {
            let detail = format!("supply chain verification failed at spawn: {source}");
            let report = self.fail.fail(
                self.launch_plan(Some(resolved_exe)),
                vec![identity_observation_failed(&detail)],
                code_identity.clone(),
                detail,
            );
            return Err(self
                .fail
                .err(LaunchErrorKind::ReverifyBeforeSpawn { source }, report));
        }
        let attempt = match self.sandbox_skip_reason {
            Some(reason) => self.warden.spawn_unsandboxed_async_exe_with_report(
                &exec.exe,
                &exec.argv,
                &self.spawn_opts,
                reason,
                self.fail.dry_run,
            ),
            None => {
                self.warden
                    .spawn_child_async_exe_with_report_ctx(
                        &exec.exe,
                        &exec.argv,
                        &self.spawn_opts,
                        self.fail.dry_run,
                        ns_ctx,
                    )
                    .await
            }
        };
        let WardenReport {
            plan,
            mut observations,
        } = attempt.report;
        let child = match attempt.outcome {
            Ok(child) => child,
            Err(source) => {
                // Hash verification ran before the spawn attempt — record it
                // even though the launch fails here. It is a Build-phase
                // observation, so it precedes the spawn-phase ones.
                if self.has_hashes {
                    observations.insert(0, identity_observation(code_identity));
                }
                // The responsible component (Warden) and stage are inside
                // `source`; the failure helper records a `server.error`
                // audit event under the same launch_id so the JSONL log
                // carries the same fact the report does.
                let report = self.fail.fail(
                    plan,
                    observations,
                    code_identity.clone(),
                    format!("server spawn failed: {source}"),
                );
                return Err(self.fail.err(
                    LaunchErrorKind::Spawn {
                        argv: argv.to_vec(),
                        source,
                    },
                    report,
                ));
            }
        };
        // Workload argv can carry credentials (tokens, passwords, inline
        // eval strings) — INFO logs the executable identity and argument
        // count only. The complete argv stays behind explicit unsafe
        // debug consent (`MCP_WRIT_LOG_ARGV=1`) so a default deployment
        // never writes it to a log stream.
        let exe_name = argv.first().map(String::as_str).unwrap_or("(empty)");
        tracing::info!(
            "{}: {exe_name} ({} args)",
            self.spawned_log_label,
            argv.len()
        );
        if std::env::var_os("MCP_WRIT_LOG_ARGV").is_some_and(|v| v == "1") {
            tracing::debug!("{} argv: {argv:?}", self.spawned_log_label);
        }
        Ok(Spawned {
            child,
            plan,
            observations,
            env_contract,
        })
    }

    /// stdio acquisition and session start: take the child's pipes, spawn
    /// the Auditor relay (the prepared policy moves into it), build the
    /// running report, and open the session bracket — `session.started`
    /// plus the `server.connected` spawn record. The only remaining
    /// failure is `take_io`, which hands the child back through the
    /// error for the caller to reap.
    fn into_session(
        self,
        resolved_exe: &Path,
        #[cfg_attr(not(unix), allow(unused_variables))] exec: ExecSpelling,
        spawned: Spawned,
        code_identity: CodeIdentity,
    ) -> Result<Launched, LaunchError> {
        let Spawned {
            mut child,
            plan,
            mut observations,
            env_contract,
        } = spawned;
        let (child_stdin, child_stdout) = match child.take_io() {
            Some(io) => io,
            None => {
                if self.has_hashes {
                    observations.insert(0, identity_observation(&code_identity));
                }
                let report = self.fail.fail(
                    plan,
                    observations,
                    code_identity,
                    "failed to capture child process stdin/stdout".to_string(),
                );
                return Err(self.fail.err(
                    LaunchErrorKind::TakeIo {
                        child: Box::new(child),
                        keeps: SessionKeeps {
                            _spawn_pin: self.spawn_pin,
                            #[cfg(all(unix, not(target_os = "linux")))]
                            _exec_staging: exec.fd_exec,
                        },
                    },
                    report,
                ));
            }
        };

        // The bound policy's declared tools, for the report's
        // correction candidates: what this session could have called.
        let declared_tools: Vec<String> = self
            .policy
            .tools
            .iter()
            .filter(|t| t.allowed)
            .map(|t| t.name.clone())
            .collect();
        let auditor = Auditor::new(self.policy, self.fail.audit_logger.clone())
            .with_dry_run(self.fail.dry_run)
            .with_fail_on(self.fail_on)
            .with_max_frame_bytes(self.max_frame_bytes);
        let call_tally = auditor.call_tally();
        let auditor_handle =
            tokio::spawn(async move { auditor.run(child_stdin, child_stdout).await });

        // Observations only the launch path can take: the pre-spawn identity
        // checks (Build phase — inserted ahead of the spawn-phase entries)
        // and placeholders for the session checks the running Auditor
        // performs — spawning the relay is not itself evidence they ran.
        if self.has_hashes {
            observations.insert(0, identity_observation(&code_identity));
        }
        let rpc_reason = if self.fail.dry_run {
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
                    restriction: None,
                    reason: rpc_reason.clone(),
                });
            }
        }

        let report = LaunchReport {
            schema_version: LAUNCH_REPORT_SCHEMA_VERSION,
            launch_id: self.fail.launch_id,
            created_at: now_iso8601_millis(),
            target: self.fail.target.clone(),
            policy: self.fail.policy_context.clone(),
            dry_run: self.fail.dry_run,
            allow_replaceable_paths: crate::fspriv::replaceable_paths_permitted(),
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
            correction_candidates: None,
        };
        tracing::debug!("launch report: {}", report.to_json());

        let session_audit = crate::runtime::lifecycle::SessionAuditContext {
            launch_id: self.fail.launch_id,
            policy: self.fail.policy_context.clone(),
            component: self.fail.component.as_str(),
        };
        // The audited session opens: `session.started` brackets the relay's
        // lifetime, `server.connected` records the spawn inside it. Both
        // share the launch_id correlation the report carries.
        crate::runtime::lifecycle::session_started(self.fail.audit_logger, &session_audit);
        let mut event = AuditEvent::new(
            self.fail.launch_id,
            EventType::ServerConnected,
            Severity::Info,
            Outcome::Success,
            Action::Observed,
        );
        if let Some(ctx) = &self.fail.policy_context
            && ctx.id != "default"
        {
            event.target_server = Some(ctx.id.clone());
        }
        event.policy_context = self.fail.policy_context;
        let mut details = format!(
            "spawned {} backend={}",
            resolved_exe.display(),
            self.fail.backend.as_str()
        );
        if self.fail.dry_run {
            details.push_str(" (dry-run)");
        }
        if self.sandbox_skip_reason.is_some() {
            // A skipped OS sandbox is stated on the spawn record itself —
            // `guard.started` carries the cause, this event the effect.
            details.push_str(" sandbox=skipped");
        }
        if self.env_inherit_parent {
            // Ambient environment inheritance is an explicit downgrade —
            // the spawn record names it rather than reading as neutral.
            details.push_str(" env=inherit-parent");
        }
        // The allowlist's launch-time gaps ride the same spawn record —
        // names only (the observation already carries the same list on the
        // `--report` side). Values are percent-encoded per the details
        // `k=v` convention: the validator only forbids `=`/NUL in names, so
        // an exotic-but-legal name cannot forge additional members.
        if let Some(contract) = &env_contract {
            if !contract.missing.is_empty() {
                details.push_str(&format!(
                    " env_missing={}",
                    contract
                        .missing
                        .iter()
                        .map(|n| encode_audit_field_value(n))
                        .collect::<Vec<_>>()
                        .join(",")
                ));
            }
            if !contract.path_missing.is_empty() {
                details.push_str(&format!(
                    " env_path_missing={}",
                    contract
                        .path_missing
                        .iter()
                        .map(|n| encode_audit_field_value(n))
                        .collect::<Vec<_>>()
                        .join(",")
                ));
            }
        }
        // The replaceable-paths opt-out waives a fail-closed ancestry
        // check, so an activation rides the spawn record like the other
        // launch waivers — its absence means the check stood.
        if crate::fspriv::replaceable_paths_permitted() {
            details.push_str(" allow_replaceable_paths=true");
        }
        // The exec method a hash pin produced is part of the launch's
        // security surface: the exe image is snapshot-exec'd (`fd` on
        // Linux, `staged` on other Unix) or path-launched under the
        // share-mode pin (`path` on Windows); a payload-bound entrypoint
        // launches by `path` — an interpreter resolves its module and
        // imports from that path, which a snapshot spelling cannot carry.
        #[cfg(unix)]
        if let Some(plan) = &exec.fd_exec {
            details.push_str(&format!(" exe_exec={}", plan.exe_exec_mode()));
            if plan.entrypoint_exec_mode().is_some() {
                details.push_str(" entrypoint_exec=path");
            }
        }
        // PR-05 — a selection that fell back to native because the
        // workload resolves under a tree init masks names the blocked
        // root on the spawn record too, like the other launch waivers;
        // the plan/report `mechanism.missing` member carries the full
        // evidence list. An explicit `native` request keeps the token in
        // `missing` but not here — namespaced was never a candidate for
        // this launch, so the spawn record has no waiver to describe.
        #[cfg(target_os = "linux")]
        if let Some(sel) = self.warden.linux_selection()
            && sel.requested != crate::execution::LinuxMechanismRequest::Native
        {
            for token in &sel.missing {
                if token.starts_with("workload_masked:") {
                    details.push_str(&format!(" {token}"));
                }
            }
        }
        #[cfg(windows)]
        if let Some(pin) = &self.spawn_pin {
            // The exe launches by its real path too — the session-held
            // share-mode pin is the object binding there.
            details.push_str(" exe_exec=path");
            if pin.has_pinned_entrypoint() {
                details.push_str(" entrypoint_exec=path");
            }
        }
        // OS controls the launch tolerated below full enforcement ride the
        // same observations the report carries — not a separate computation.
        details.push_str(&weakened_os_tokens(&report.observations));
        details.push_str(&format!(
            " session_id={}",
            self.fail.audit_logger.session_id()
        ));
        event.details = Some(details);
        // The machine-readable mirror of `details`: backend, effective
        // control states, grant counts, and the PSEC digest — built from the
        // same `plan`/`observations` the report file carries.
        event.enforcement = Some(
            EnforcementSummary::build(
                &report.plan,
                &report.observations,
                self.fail.backend,
                self.fail.dry_run,
            )
            .to_json(),
        );
        self.fail.audit_logger.log(event);

        Ok(Launched {
            child,
            auditor_handle,
            report,
            session_audit,
            keeps: SessionKeeps {
                _spawn_pin: self.spawn_pin,
                #[cfg(all(unix, not(target_os = "linux")))]
                _exec_staging: exec.fd_exec,
            },
            call_tally,
            declared_tools,
        })
    }
}

/// Shared sequence — each stage a [`PreparedLaunch`] method, in order:
/// `new` (Warden, mechanism selection, spawn options) →
/// `refuse_unenforceable_linux` (Linux only: refused selection or dead
/// legacy policy) → `resolve_command` → `verify_and_bind` (verify →
/// bind → reverify, minting the spawn pin) → `exec_spelling` (the
/// fd/staged exec plan and the spawn's exe/argv) → `spawn` (env
/// contract, the pin's last path re-check, the Warden dispatch) →
/// `into_session` (stdio acquisition, the Auditor relay, the running
/// report, the session bracket).
///
/// A non-expanded launch keeps the caller's `argv[0]`; a pinned Unix `#!`
/// launch expands to the interpreter launch the kernel would perform, so
/// the child's `argv[0]` is the interpreter and the caller's spelling
/// moves to the script argument — preserved there only while the script
/// stays unpinned; a payload-bound entrypoint is re-spelled to its
/// resolved real path instead.
///
/// What the spawn execs splits three ways: a pinned executable image
/// runs the pinned object itself — an inherited `/proc/self/fd`
/// descriptor on Linux, an owner-only staged copy on other Unixes, the
/// real path under the share-mode pin held for the session on Windows;
/// an unpinned executable launches through its resolved path; and a
/// payload-bound entrypoint script launches through its real path so
/// the interpreter can resolve sibling/relative imports (and Node's
/// `node_modules` ancestor walk), protected on native Unix by the
/// `fspriv` trusted-source gate and on the namespaced route by init's
/// verified bind mount.
///
/// Ordering is fixed: verify → bind → reverify reruns the binding
/// immediately before spawn, narrowing but not closing the
/// hash-to-exec window. The verify stage mints one held pin per
/// launch-identity target; bind and reverify re-prove those pins by
/// object identity and stamp — re-hashing only when an object provably
/// changed — so the fixed pipeline's content guarantee is the digest
/// computed through the held handle rather than repeated pathname
/// reads. `code_identity` in the report records which check points
/// each pin passed.
/// Signal waiting and shutdown are NOT part of this function.
///
/// A [`LaunchReport`] is assembled for every outcome of [`launch`]: it is
/// returned inside [`Launched`] with `result = running` (the caller
/// finalizes it at session end) and inside every [`LaunchError`] with
/// `result = failed`, so a refused or failed launch stays
/// describable in the same schema. The plan comes from the same
/// normalized rule data the spawn used, the observations from the
/// spawn's own outcome, and `launch_id` correlates them with the audit
/// events emitted here — including a `server.error` event on every
/// failure path, so a failed launch is auditable under the same id.
// The error path runs once per process — the struct stays whole rather
// than boxed.
#[allow(clippy::result_large_err)]
pub async fn launch(
    config: LaunchConfig,
    audit_logger: &AuditLogger,
) -> Result<Launched, LaunchError> {
    let mut launch = PreparedLaunch::new(config, audit_logger);
    #[cfg(target_os = "linux")]
    launch.refuse_unenforceable_linux()?;
    let (argv, resolved_exe) = launch.resolve_command()?;
    let code_identity = launch.verify_and_bind(&argv, &resolved_exe)?;
    let exec = launch.exec_spelling(&argv, &resolved_exe, &code_identity)?;
    let spawned = launch
        .spawn(&argv, &resolved_exe, &exec, &code_identity)
        .await?;
    launch.into_session(&resolved_exe, exec, spawned, code_identity)
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
        restriction: None,
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
        restriction: None,
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

#[cfg(test)]
mod tests;
