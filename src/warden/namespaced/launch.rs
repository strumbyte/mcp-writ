//! PR-16 — the `run`-route namespaced launch: the productized path of
//! the PR-09 PoC, dispatched from `Warden::spawn_child_async_impl`
//! when the egress selection resolved `namespaced`.
//!
//! The sequence mirrors `namespaced-run`'s fail-closed ordering but
//! produces the shared [`SpawnAttempt`]/[`RunningChild`] shapes so the
//! rest of `run` (MCP stdio proxying, auditor, wait loop, launch
//! report) treats it like any other sandboxed spawn:
//!
//! ```text
//!   evaluator build → in-ns rule build (grants) → policy memfd →
//!   spawn namespaced-init (piped stdio, tokio child) → READY+TUN →
//!   DNS gate + TUN proxy tasks → GO → SANDBOXED → exec epoch (EOF)
//! ```
//!
//! Every failure before `RunningChild` exists kills the half-spawned
//! process group and refuses the launch — there is no path from a
//! failed namespaced launch to the native or unsandboxed routes.

use std::path::Path;
use std::sync::Arc;

use crate::enforcement::EnforcementPlan;
use crate::error::WardenError;
use crate::policy::Policy;

use super::super::child::{NamespacedRuntime, RunningChildInner};
use super::super::linux_spawn;
use super::super::plan::{self, SpawnAttempt, WardenReport};
use super::super::select::LinuxSelection;
use super::super::{NamespacedLaunchCtx, RunningChild, SpawnOptions, spawn_env_pairs};
use super::{SpawnConfig, policy_memfd, spawn_namespaced_child_tokio};

/// Dispatch a namespaced launch from the warden's spawn path.
///
/// `program`/`argv`/`opts` are exactly what the native arm would have
/// spawned — the resolved (possibly fd-exec) image, the caller-spelled
/// argv, and the policy-derived spawn options — so the hash-pin and
/// env-restriction contracts are identical. `selection` provides the
/// mechanism evidence the plan/report carry.
///
/// Failure at any stage returns `SpawnAttempt::err` — the launch layer
/// turns it into a refusal report; nothing here ever re-dispatches a
/// weaker mechanism.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn spawn_namespaced_attempt(
    policy: &Policy,
    selection: &LinuxSelection,
    program: &Path,
    argv: &[String],
    opts: &SpawnOptions,
    dry_run: bool,
    ctx: &NamespacedLaunchCtx,
) -> SpawnAttempt {
    let mut controls = plan::shared_controls(policy, opts, dry_run, false, false);
    // The DNS gate exists only when an upstream resolver was resolved —
    // the control is planned as NotApplicable rather than promised.
    controls.extend(plan::os_controls_namespaced(policy, ctx.upstream.is_some()));
    let mut limitations = plan::base_limitations();
    if policy.environment.inherit_parent {
        limitations.push(
            "Ambient environment inheritance is enabled (`environment { inherit-parent \
             #true }`): the child receives every launcher variable — secrets in the \
             launcher's environment reach the workload."
                .to_string(),
        );
    }
    plan::os_limitations_namespaced(policy, &mut limitations);

    let plan_of = |controls: Vec<crate::enforcement::PlannedControl>,
                   grants: Vec<crate::enforcement::ProcessGrant>| {
        EnforcementPlan {
            controls,
            grants,
            tools: plan::tools_table(policy),
            limitations: limitations.clone(),
            egress_layers: Some(plan::egress_layers_namespaced_plan(policy)),
            mechanism: Some(selection.to_record()),
        }
    };
    macro_rules! refuse {
        ($controls:expr, $grants:expr, $source:expr) => {
            return SpawnAttempt::err(
                WardenReport {
                    plan: plan_of($controls, $grants),
                    observations: Vec::new(),
                },
                $source,
            )
        };
    }

    // 1 — the namespaced egress evaluator: every destination rule the
    // proxy evaluates lives here; a build failure means the route
    // cannot express the policy (already screened by selection, but
    // re-checked at the point of use — never trust a stale screen).
    let evaluator =
        match super::super::unotify::IpLayerEvaluator::new_namespaced(&policy.network.outbound) {
            Ok(e) => e,
            Err(detail) => {
                let mut c = controls;
                plan::fail_os_controls(&mut c, "evaluator build failed", &eval_err(&detail));
                refuse!(c, Vec::new(), eval_err(&detail));
            }
        };

    // 2 — the in-namespace sandbox bits: Landlock fs rules + exact
    // port narrowing + seccomp. Their grant entries are the launch's
    // kernel grants; the proxy's destination rules are evaluator
    // config and live in the egress-layers table.
    let sandbox_bits = match linux_spawn::prepare_linux_child_sandbox_namespaced(policy) {
        Ok(bits) => bits,
        Err(source) => {
            let mut c = controls;
            plan::fail_os_controls(&mut c, "rule build failed", &source);
            refuse!(c, Vec::new(), source);
        }
    };
    let grants = sandbox_bits.grants;

    // 3 — the effective policy as a sealed read-only memfd init
    // re-loads, so its Landlock/seccomp bits build from the identical
    // bytes the parent bound.
    let policy_kdl_fd = match policy_memfd(policy) {
        Ok(f) => f,
        Err(e) => {
            let mut c = controls;
            plan::fail_os_controls(&mut c, "policy serialization failed", &spawn_err(&e));
            refuse!(
                c,
                Vec::new(),
                spawn_err(&std::io::Error::new(
                    e.kind(),
                    format!("policy serialization for init failed: {e}")
                ))
            );
        }
    };

    // 4 — spawn namespaced-init; complete the READY handshake. The
    // filtered env block is built by the same `spawn_env_pairs` the
    // native arm uses — `MCP_WRIT_NS_*` control vars are stripped by
    // the spawn builder itself.
    let env = spawn_env_pairs(opts);
    let cfg = SpawnConfig {
        argv: argv.to_vec(),
        resolved_exe: program.to_path_buf(),
        policy_kdl_fd,
        env,
        exec_uncloak_fds: opts.exec_uncloak_fds.clone(),
    };
    // The spawn + READY handshake is blocking socket work — run it on
    // the blocking pool rather than stall the async worker.
    let spawn_res = tokio::task::spawn_blocking(move || spawn_namespaced_child_tokio(&cfg)).await;
    let mut launched = match spawn_res {
        Ok(Ok(c)) => c,
        Ok(Err(detail)) => {
            refuse!(controls, grants, spawn_err_msg(&detail));
        }
        Err(e) => {
            refuse!(
                controls,
                grants,
                spawn_err_msg(&format!("namespaced spawn task failed: {e}"))
            );
        }
    };
    let child_pid = launched.pid();
    // Non-escapable descendant boundary — same contract as the native
    // arm's "run" cgroup.
    let lifetime_cgroup = super::super::cgroup::LifetimeCgroup::try_adopt("run", child_pid as u32);

    // 5 — the embedded DNS gate + the shared grant table. No upstream
    // → no gate: port-53 flows then fall to the ordinary evaluator,
    // which deny-all refuses (the selection has already flagged any
    // name-bound rule as unsatisfiable without a resolver).
    let allowlist = Arc::new(crate::dnsgate::DynamicAllowList::new(
        crate::dnsgate::server::DEFAULT_MAX_GRANTS,
    ));
    let gate_core = ctx.upstream.map(|upstream| {
        Arc::new(crate::dnsgate::server::QueryCore::new(
            crate::dnsgate::GateConfig {
                upstream,
                refusal: crate::dnsgate::Refusal::Refused,
                allowlist_export: None,
                ..Default::default()
            },
            Arc::new(policy.network.outbound.clone()),
            allowlist.clone(),
            ctx.audit.clone(),
            ctx.launch_id,
            ctx.policy_ctx.clone(),
        ))
    });

    // 6 — start the proxy before GO. A TUN clone failure is a launch
    // failure, not a panic: kill the group exactly like every other
    // refused stage.
    let proxy_tun = match launched.tun.try_clone() {
        Ok(f) => f,
        Err(e) => {
            kill_init_group(child_pid, &lifetime_cgroup);
            let _ = launched.child.start_kill();
            refuse!(
                controls,
                grants,
                spawn_err_msg(&format!("tun clone for the proxy failed: {e}"))
            );
        }
    };
    let stats = super::ProxyStats::default();
    let proxy_task = tokio::spawn({
        let stats = stats.clone();
        let logger = ctx.audit.clone();
        let policy_ctx = ctx.policy_ctx.clone();
        let launch_id = ctx.launch_id;
        async move {
            super::run_proxy(
                super::ProxyConfig {
                    tun: proxy_tun,
                    evaluator,
                    allowlist,
                    gate: gate_core,
                    logger,
                    launch_id,
                    policy_ctx,
                },
                stats,
            )
            .await;
        }
    });

    // 7 — GO: init applies the sandbox and execs. The handshake read
    // is bounded by `go()`'s socket timeout; run it on the blocking
    // pool and get `launched` back either way so the refusal path can
    // still kill the group.
    let go_res = tokio::task::spawn_blocking(move || {
        let mut l = launched;
        match l.go() {
            Ok(()) => Ok(l),
            // Boxed: `NamespacedChildTokio` outweighs the happy-path
            // payload this closure returns it alongside.
            Err(e) => Err((e, Box::new(l))),
        }
    })
    .await;
    let mut launched = match go_res {
        Ok(Ok(l)) => l,
        Ok(Err((detail, mut l))) => {
            kill_init_group(l.pid(), &lifetime_cgroup);
            let _ = l.child.start_kill();
            proxy_task.abort();
            refuse!(controls, grants, spawn_err_msg(&detail));
        }
        Err(e) => {
            refuse!(
                controls,
                grants,
                spawn_err_msg(&format!("namespaced GO handshake failed: {e}"))
            );
        }
    };
    let sandbox_applied = launched.sandbox_applied.get();

    // 8 — observations: the in-namespace sandbox verdict comes from
    // the handshake, the proxy/gate controls from their task starts.
    // The gate only exists when an upstream resolver was configured —
    // without one there is no task to mark started.
    let mut observations = plan::os_spawn_observations_namespaced(
        &controls,
        sandbox_applied,
        true,
        ctx.upstream.is_some(),
        None,
    );
    if let Some(o) = plan::env_observation(spawn_env_pairs(opts).is_some(), None) {
        observations.push(o);
    }

    let stdin = launched.child.stdin.take();
    let stdout = launched.child.stdout.take();
    let (stdin, stdout) = match (stdin, stdout) {
        (Some(s), Some(o)) => (s, o),
        _ => {
            kill_init_group(child_pid, &lifetime_cgroup);
            let _ = launched.child.start_kill();
            proxy_task.abort();
            refuse!(
                controls,
                grants,
                spawn_err_msg("failed to capture namespaced child stdin/stdout")
            );
        }
    };

    let report = WardenReport {
        plan: plan_of(controls, grants),
        observations,
    };
    // One flag shared by the runtime (wait-loop/kill) and the report
    // source — a supervision loss observed on either side lands in the
    // finalized `mechanism.namespaced` member.
    let proxy_lost = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    SpawnAttempt::ok(
        report,
        RunningChild {
            stdin: Some(Box::new(stdin)),
            stdout: Some(Box::new(stdout)),
            pgid: child_pid as u32,
            reaped: false,
            unotify_listener: None,
            lifetime_cgroup,
            namespaced: Some(Box::new(NamespacedRuntime {
                proxy: proxy_task,
                tun: launched.tun,
                proxy_lost: proxy_lost.clone(),
            })),
            namespaced_report: Some(super::super::child::NamespacedReportSource {
                stats,
                sandbox_applied,
                proxy_lost,
            }),
            inner: RunningChildInner::Tokio(Box::new(launched.child)),
        },
    )
}

/// SIGKILL the init child's process group and sweep the lifetime
/// cgroup — the same group-kill contract every refused namespaced
/// stage uses.
fn kill_init_group(pid: i32, cg: &Option<super::super::cgroup::LifetimeCgroup>) {
    // `kill(0)` signals *this* process's own group — a pid that never
    // materialized must not reach the group call.
    if pid > 0 {
        unsafe { libc::kill(-pid, libc::SIGKILL) };
    }
    if let Some(cg) = cg
        && cg.kill_members() > 0
    {
        tracing::warn!(
            "namespaced lifetime cgroup still lists members after the kill \
             sweep — orphaned descendants may outlive this teardown"
        );
    }
}

fn spawn_err(e: &std::io::Error) -> WardenError {
    WardenError::ProcessSpawn(std::io::Error::new(e.kind(), e.to_string()))
}

fn spawn_err_msg(detail: &str) -> WardenError {
    WardenError::ProcessSpawn(std::io::Error::other(detail.to_string()))
}

fn eval_err(detail: &str) -> WardenError {
    WardenError::sandbox_setup(crate::error::SandboxStage::Prepare, detail.to_string())
}
