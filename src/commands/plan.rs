//! `mcp-writ plan` — pre-launch diagnostics.
//!
//! Computes the enforcement plan and inspects launch prerequisites
//! *without* starting the workload, running live discovery, pulling an
//! image, or mutating any host/daemon configuration. Two modes:
//!
//!   native: `mcp-writ plan --policy <path> -- <command>`
//!   image:  `mcp-writ plan --engine <engine> --image <ref> --policy <path>`
//!
//! The machine-readable [`PlanReport`] goes to stdout, the human summary
//! and remediation steps to stderr, and the process exits with the fixed
//! status code (`ready` 0 / `blocked` 1 / `invalid` 2 / `error` 1).
//! `plan` never runs unsandboxed-live probes: a missing prerequisite is
//! reported as `blocked`, not worked around.

use std::path::Path;

use crate::audit_log::now_iso8601_millis;
use crate::cli::PlanArgs;
use crate::enforcement::{
    ControlLayer, ControlState, EnforcementPlan, PLAN_REPORT_SCHEMA_VERSION, PlanCheck,
    PlanCheckStatus, PlanReport, PlanStatus, PlannedControl, ToolDisposition,
};
use crate::error::PolicyError;
use crate::execution::{EngineName, ExecutionTarget, IsolationKind, TargetArch, TargetOs};
use crate::policy::Policy;
use crate::policy::loader::load_policy_or_default_for_target;
use crate::workload::resolve_command_path;

/// Run `plan` and exit the process with the status-mapped code.
pub async fn run_plan(args: PlanArgs) -> ! {
    let report_path = args.report.clone();
    let report = diagnose(args).await;
    emit_and_exit(&report, report_path.as_deref());
}

/// Human summary + remediation on stderr.
fn print_summary(report: &PlanReport) {
    match report.status {
        PlanStatus::Ready => {
            eprintln!("plan: ready — enforcement plan computed; prerequisites satisfied");
        }
        status => {
            let reason = report.reason.as_deref().unwrap_or("(no detail)");
            eprintln!("plan: {status} — {reason}", status = status.as_str());
        }
    }
    for (i, step) in report.remediation.iter().enumerate() {
        eprintln!("  {}. {step}", i + 1);
    }
}

/// Emit `report` and exit with [`PlanStatus::exit_code`].
///
/// Without `--report` the JSON result goes to stdout — `plan` owns
/// stdout outright, no MCP child relays through it. With `--report`
/// the JSON goes to the file; a write failure is itself a result:
/// status `error` (exit 1), machine-readable on stdout.
fn emit_and_exit(report: &PlanReport, report_path: Option<&Path>) -> ! {
    let Some(path) = report_path else {
        println!("{}", report.to_json());
        print_summary(report);
        std::process::exit(report.status.exit_code());
    };

    match std::fs::write(path, report.to_json()) {
        Ok(()) => {
            eprintln!("plan report written to {}", path.display());
            print_summary(report);
            std::process::exit(report.status.exit_code());
        }
        Err(e) => {
            let err = PlanReport {
                schema_version: PLAN_REPORT_SCHEMA_VERSION,
                created_at: now_iso8601_millis(),
                status: PlanStatus::Error,
                reason_code: Some("report_write_failed"),
                reason: Some(format!(
                    "failed to write plan report to '{}': {e}",
                    path.display()
                )),
                target: report.target.clone(),
                policy: report.policy.clone(),
                checks: report.checks.clone(),
                remediation: vec![format!(
                    "fix the --report destination '{}': {e}",
                    path.display()
                )],
                plan: report.plan.clone(),
            };
            // The requested destination failed; stdout remains as the
            // fallback machine channel.
            println!("{}", err.to_json());
            eprintln!(
                "Error: failed to write plan report to '{}': {e}",
                path.display()
            );
            std::process::exit(PlanStatus::Error.exit_code());
        }
    }
}

fn check(id: &'static str, status: PlanCheckStatus, detail: Option<String>) -> PlanCheck {
    PlanCheck {
        id,
        status,
        detail,
        remediation: None,
    }
}

fn failing_check(id: &'static str, detail: String, remediation: String) -> PlanCheck {
    PlanCheck {
        id,
        status: PlanCheckStatus::Fail,
        detail: Some(detail),
        remediation: Some(remediation),
    }
}

fn base_report(target: ExecutionTarget) -> PlanReport {
    PlanReport {
        schema_version: PLAN_REPORT_SCHEMA_VERSION,
        created_at: now_iso8601_millis(),
        status: PlanStatus::Ready,
        reason_code: None,
        reason: None,
        target,
        policy: None,
        checks: Vec::new(),
        remediation: Vec::new(),
        plan: None,
    }
}

/// True when `MCP_WRIT_SKIP_SANDBOX` is set truthy — the same rule
/// `run` applies, so `plan` warns about the same launch the user gets.
fn env_skip_sandbox() -> bool {
    std::env::var("MCP_WRIT_SKIP_SANDBOX")
        .map(|v| {
            let v = v.trim().to_lowercase();
            v == "1" || v == "true"
        })
        .unwrap_or(false)
}

/// Finalize `report`: any `Fail` check downgrades `ready` to `blocked`,
/// sets `reason`/`reason_code` from the first failing check when unset,
/// and collects human remediation from every Fail/Warn check (warnings
/// are shown even for a `ready` result — optional features and omitted
/// controls stay visible in the summary).
fn finalize(mut report: PlanReport) -> PlanReport {
    let first_fail = report
        .checks
        .iter()
        .find(|c| c.status == PlanCheckStatus::Fail);
    if let Some(f) = first_fail {
        if report.status == PlanStatus::Ready {
            report.status = PlanStatus::Blocked;
        }
        if report.reason_code.is_none() {
            report.reason_code = Some(reason_code_for(f.id));
        }
        if report.reason.is_none() {
            report.reason = f.detail.clone();
        }
    }
    for c in &report.checks {
        if let Some(r) = &c.remediation
            && matches!(c.status, PlanCheckStatus::Fail | PlanCheckStatus::Warn)
        {
            report.remediation.push(r.clone());
        }
    }
    // A blocked result must name the fix even when no check carried a
    // remediation string.
    if report.status == PlanStatus::Blocked && report.remediation.is_empty() {
        report
            .remediation
            .push("resolve the failing checks above and re-run `mcp-writ plan`".to_string());
    }
    report
}

/// Stable reason code for a failing check id — the machine contract of
/// `reason.code` in the emitted result.
fn reason_code_for(check_id: &str) -> &'static str {
    match check_id {
        "input.cli" => "invalid_input",
        "policy.load" => "policy_not_found",
        "policy.bind" => "policy_bind_failed",
        "command.resolve" => "command_not_found",
        "sandbox.mechanism" => "sandbox_plan_failed",
        "engine.resolve" => "engine_not_found",
        "engine.locality" => "remote_daemon",
        "isolation.backend" | "kata.runtime" | "apple.system" => "isolation_unsupported",
        "hyperv.engine" | "hyperv.image" => "isolation_unsupported",
        "image.reference" => "image_not_pinned",
        "image.inspect" => "image_not_available",
        "image.os" => "unsupported_guest_os",
        "image.arch" => "unsupported_guest_arch",
        "runner.entrypoint" => "runner_missing",
        "runner.caps" => "runner_incapable",
        "image.digest_match" => "digest_mismatch",
        _ => "prerequisite_failed",
    }
}

/// Load + bind the policy for `target`, recording the outcome in
/// `report.checks`. `None` means no policy could be bound: `report` is
/// already set to `blocked`/`invalid` accordingly.
fn load_policy_check(
    report: &mut PlanReport,
    policy_path: Option<&Path>,
    server: Option<&str>,
    target: &ExecutionTarget,
) -> Option<Policy> {
    let policy = match load_policy_or_default_for_target(policy_path, target) {
        Ok(p) => p,
        Err(e) => {
            let remediation = match &e {
                PolicyError::FileRead(_) => {
                    "create the policy file or pass a valid --policy path (missing files may be generated with `mcp-writ generate-policy`)"
                        .to_string()
                }
                _ => "fix the policy KDL at the reported location".to_string(),
            };
            let code = match &e {
                PolicyError::FileRead(_) => "policy_not_found",
                _ => "policy_invalid",
            };
            // A missing policy keeps an earlier failure's reason fields —
            // finalize derives them from the first failing check. An
            // Invalid status instead owns the reason fields: the
            // machine-readable reason must name the same cause as the
            // status, so it always follows the policy error.
            let has_prior_fail = report
                .checks
                .iter()
                .any(|c| c.status == PlanCheckStatus::Fail);
            report
                .checks
                .push(failing_check("policy.load", e.to_string(), remediation));
            // A missing policy is a blocked prerequisite — but it must
            // not upgrade a status an earlier failure already recorded
            // (only a Ready report becomes Blocked). Other load errors
            // always promote to Invalid.
            match code {
                "policy_not_found" => {
                    if report.status == PlanStatus::Ready {
                        report.status = PlanStatus::Blocked;
                    }
                    if !has_prior_fail {
                        if report.reason_code.is_none() {
                            report.reason_code = Some(code);
                        }
                        if report.reason.is_none() {
                            report.reason = Some(e.to_string());
                        }
                    }
                }
                _ => {
                    report.status = PlanStatus::Invalid;
                    report.reason_code = Some(code);
                    report.reason = Some(e.to_string());
                }
            }
            return None;
        }
    };

    let bound = match policy.bind_to_server(server) {
        Ok(b) => b,
        Err(e) => {
            report.checks.push(failing_check(
                "policy.bind",
                e.to_string(),
                "pass --server <name> matching an identity declared in the policy".to_string(),
            ));
            // A bind failure makes the plan invalid — the reason fields
            // name this cause even when an earlier check already failed.
            report.status = PlanStatus::Invalid;
            report.reason_code = Some("policy_bind_failed");
            report.reason = Some(e.to_string());
            return None;
        }
    };
    report.checks.push(check(
        "policy.load",
        PlanCheckStatus::Pass,
        Some(format!("policy version {} bound", bound.version)),
    ));
    report.policy = bound.audit_context().ok();
    Some(bound)
}

/// Diagnose the parsed `plan` arguments into a [`PlanReport`].
async fn diagnose(args: PlanArgs) -> PlanReport {
    // Parse/semantic errors are already a result: status invalid.
    if let Some(msg) = args.invalid_input {
        let mut report = base_report(ExecutionTarget::native());
        report.status = PlanStatus::Invalid;
        report.reason_code = Some("invalid_input");
        report.reason = Some(msg.clone());
        report.checks.push(failing_check(
            "input.cli",
            msg.clone(),
            format!("fix the invocation: {msg}"),
        ));
        return finalize(report);
    }

    match &args.image {
        Some(image) => diagnose_image(&args, image).await,
        None => diagnose_native(&args),
    }
}

/// Native mode: `mcp-writ plan --policy <path> -- <command>`.
fn diagnose_native(args: &PlanArgs) -> PlanReport {
    let target = ExecutionTarget::native();
    let mut report = base_report(target.clone());
    let argv0 = args.command.first().cloned().unwrap_or_default();

    // policy.load
    let Some(policy) = load_policy_check(
        &mut report,
        args.policy.as_deref(),
        args.server.as_deref(),
        &target,
    ) else {
        return finalize(report);
    };

    // command.resolve — a missing executable blocks the launch, so it
    // blocks the plan's `ready`.
    let resolved = match resolve_command_path(&argv0) {
        Ok(p) => {
            report.checks.push(check(
                "command.resolve",
                PlanCheckStatus::Pass,
                Some(format!("{argv0} resolved to {}", p.display())),
            ));
            Some(p)
        }
        Err(e) => {
            report.checks.push(failing_check(
                "command.resolve",
                format!("cannot resolve command '{argv0}': {e}"),
                "install the program, fix PATH, or correct the command name".to_string(),
            ));
            None
        }
    };

    // env.skip_sandbox — the same env var `run` honors.
    let skip_reason = if env_skip_sandbox() {
        report.checks.push(PlanCheck {
            id: "env.skip_sandbox",
            status: PlanCheckStatus::Warn,
            detail: Some(
                "MCP_WRIT_SKIP_SANDBOX is set: a launch would run without the OS sandbox"
                    .to_string(),
            ),
            remediation: Some(
                "unset MCP_WRIT_SKIP_SANDBOX to launch under the OS sandbox".to_string(),
            ),
        });
        Some("MCP_WRIT_SKIP_SANDBOX")
    } else {
        report
            .checks
            .push(check("env.skip_sandbox", PlanCheckStatus::Pass, None));
        None
    };

    // audit.config — fail-closed logging requires --audit-log at `run`
    // time. `plan` cannot verify whether a later `run` invocation
    // receives it, so the requirement is a warning that stays visible in
    // the result's remediation — `run` itself enforces it at launch.
    if policy.logging.fail_closed {
        report.checks.push(PlanCheck {
            id: "audit.config",
            status: PlanCheckStatus::Warn,
            detail: Some(
                "policy logging.fail_closed is on: `run` requires --audit-log <path>, which `plan` cannot verify".to_string(),
            ),
            remediation: Some("pass --audit-log <path> to `run`".to_string()),
        });
    } else {
        report.checks.push(check(
            "audit.config",
            PlanCheckStatus::Pass,
            Some("logging.fail_closed is off; audit events may go to tracing".to_string()),
        ));
    }

    // hash.identity — launch-target pinning coverage. The entry roles
    // stay distinct: binary-hash/entrypoint-hash bind the launched
    // process; lockfile-hash/docker-manifest-hash verify content only —
    // a policy that has only content entries would fail closed at `run`
    // (`bind_launched_workload` refuses when no identity entry exists).
    if policy.hash_entries.is_empty() {
        report.checks.push(PlanCheck {
            id: "hash.identity",
            status: PlanCheckStatus::Warn,
            detail: Some(
                "policy has no hash entries: server binaries are not integrity-pinned".to_string(),
            ),
            remediation: Some(
                "add hash entries (e.g. via `mcp-writ generate-policy`) to pin server binaries"
                    .to_string(),
            ),
        });
    } else {
        let identity_count = policy
            .hash_entries
            .iter()
            .filter(|e| {
                matches!(
                    e.hash_type,
                    crate::policy::HashType::Binary | crate::policy::HashType::Entrypoint
                )
            })
            .count();
        let content_count = policy.hash_entries.len() - identity_count;
        if identity_count == 0 {
            report.checks.push(failing_check(
                "hash.identity",
                format!(
                    "{} hash entries but no binary-hash/entrypoint-hash — \
                     lockfile-hash/docker-manifest-hash entries verify file content \
                     only and cannot bind the launched process; `run` fails closed",
                    policy.hash_entries.len()
                ),
                "add a binary-hash (plus entrypoint-hash for an interpreted workload) \
                 pinning the launch target, e.g. via `mcp-writ generate-policy`"
                    .to_string(),
            ));
        } else {
            report.checks.push(check(
                "hash.identity",
                PlanCheckStatus::Pass,
                Some(format!(
                    "{identity_count} launch-target entries (binary-hash/entrypoint-hash) \
                     bind the process{}",
                    if content_count > 0 {
                        format!(
                            "; {content_count} content-only entries \
                             (lockfile-hash/docker-manifest-hash) verify file content \
                             without binding the process"
                        )
                    } else {
                        String::new()
                    }
                )),
            ));
        }
    }

    // Compute the enforcement plan — the same builders the spawn path
    // uses, so its Failed controls are exactly what a launch would fail
    // on. Nothing is applied and no process is spawned.
    let warden = crate::warden::Warden::new(policy.clone());
    let spawn_opts = crate::warden::SpawnOptions {
        restrict_environment: policy.environment.restrict,
        allowed_names: policy.environment.allowed.clone(),
        tmpdir: None,
    };
    let plan =
        warden.enforcement_plan(resolved.as_deref(), &argv0, &spawn_opts, skip_reason, false);

    // sandbox.mechanism — the OS controls' build outcome.
    let failed_os: Vec<&PlannedControl> = plan
        .controls
        .iter()
        .filter(|c| c.layer == ControlLayer::Os && c.state == ControlState::Failed)
        .collect();
    if !failed_os.is_empty() {
        let detail = failed_os
            .iter()
            .map(|c| format!("{}: {}", c.id, c.reason.as_deref().unwrap_or("(no detail)")))
            .collect::<Vec<_>>()
            .join("; ");
        report.checks.push(failing_check(
            "sandbox.mechanism",
            detail.clone(),
            sandbox_remediation(&detail),
        ));
    } else {
        report.checks.push(check(
            "sandbox.mechanism",
            PlanCheckStatus::Pass,
            Some(sandbox_mechanism_detail()),
        ));
    }

    // A failed Landlock ruleset build is reported above; a *tolerated*
    // degraded sandbox is a warning, not a block.
    if policy.sandbox.allow_degraded {
        report.checks.push(PlanCheck {
            id: "sandbox.degraded",
            status: PlanCheckStatus::Warn,
            detail: Some(
                "sandbox.allow_degraded is on: partial enforcement is tolerated".to_string(),
            ),
            remediation: Some(
                "disable sandbox.allow_degraded to refuse degraded enforcement".to_string(),
            ),
        });
    }

    report.plan = Some(plan);
    finalize(report)
}

/// Remediation hint for a failed sandbox-mechanism check.
fn sandbox_remediation(detail: &str) -> String {
    if cfg!(target_os = "linux") {
        if detail.contains("Landlock") {
            "kernel Landlock support is required (5.13+ for filesystem rules, \
             6.7+ for network rules); upgrade the kernel, or set \
             sandbox.allow_degraded to accept weaker enforcement"
                .to_string()
        } else {
            "fix the sandbox rule build error shown in the check detail".to_string()
        }
    } else if cfg!(target_os = "macos") {
        "ensure `sandbox-exec` is available on PATH and the SBPL profile builds".to_string()
    } else {
        "resolve the OS sandbox error shown in the check detail".to_string()
    }
}

/// Human detail for a passing sandbox-mechanism check.
fn sandbox_mechanism_detail() -> String {
    if cfg!(target_os = "linux") {
        "kernel Landlock + seccomp rulesets build successfully".to_string()
    } else if cfg!(target_os = "macos") {
        "SBPL profile builds; kernel acceptance is verified at launch".to_string()
    } else if cfg!(target_os = "windows") {
        "AppContainer grant intents compute successfully".to_string()
    } else {
        "no OS sandbox on this platform".to_string()
    }
}

/// The launch target an `--image` plan records: substrate and workload
/// OS follow the isolation method (a VM-boundary method is not the
/// Linux container contract), and `engine` — which names a container
/// engine — is recorded when the backend is engine-driven (`container`,
/// and `kata` whose VM is launched by `docker run --runtime kata`); an
/// engine-less method records none.
fn image_target(engine: Option<EngineName>, isolation: IsolationKind) -> ExecutionTarget {
    let mut target = ExecutionTarget::linux_container(engine, None);
    target.substrate = isolation.substrate();
    target.workload_os = isolation.guest_os();
    if !crate::container::backends::engine_backed(isolation) {
        target.engine = None;
    }
    target
}

/// Image mode: `mcp-writ plan --engine <e> --image <ref> --policy <path>`.
///
/// Inspects the *local* image only — no pull, no container start, no
/// daemon configuration change.
async fn diagnose_image(args: &PlanArgs, image: &str) -> PlanReport {
    // The isolation method is a separate selection from the engine —
    // it decides which backend would launch the workload and which
    // substrate the target records.
    let isolation = args.isolation.unwrap_or(IsolationKind::Container);
    let mut report = base_report(image_target(args.engine.map(EngineName::from), isolation));
    let launch_control = |id: &'static str| PlannedControl {
        id,
        layer: ControlLayer::Launch,
        mechanism: "container launch",
        state: ControlState::Planned,
        reason: None,
    };
    let mut plan_controls = vec![
        PlannedControl {
            id: "launch.isolation",
            layer: ControlLayer::Launch,
            mechanism: "isolation backend",
            state: ControlState::Planned,
            reason: Some(
                "the workload boundary the launch is confined to; \
                 --isolation selects it, the backend confirms it"
                    .to_string(),
            ),
        },
        launch_control("launch.engine"),
        launch_control("launch.image"),
        launch_control("launch.runner"),
        launch_control("launch.policy"),
        launch_control("launch.container"),
        PlannedControl {
            id: "launch.guest_report",
            layer: ControlLayer::Launch,
            mechanism: "dedicated report mount",
            state: ControlState::Planned,
            reason: Some(
                "the in-guest runner writes its own launch report into the \
                 dedicated mount when --report is requested"
                    .to_string(),
            ),
        },
        PlannedControl {
            id: "rpc.guest",
            layer: ControlLayer::Rpc,
            mechanism: "mcp-secure-runner (guest)",
            state: ControlState::Planned,
            reason: Some(
                "the in-guest auditor enforces tool policy; the host does not observe it"
                    .to_string(),
            ),
        },
    ];

    // isolation.backend — the selection contract. An unimplemented
    // method, or an implemented one this host OS is out of scope for,
    // blocks the plan exactly as run-image refuses it: no silent
    // fallback to a normal container.
    let backend_caps = crate::container::backends::capabilities_for(isolation);
    let backend_available = backend_caps
        .map(|c| c.host_os.contains(&TargetOs::host()))
        .unwrap_or(false);
    match backend_caps {
        Some(caps) if !caps.host_os.contains(&TargetOs::host()) => {
            report.checks.push(failing_check(
                "isolation.backend",
                format!(
                    "isolation method '{}' is not supported on this host OS \
                     ({}) — declared host OSs: {}",
                    isolation.name(),
                    TargetOs::host().name(),
                    caps.host_os
                        .iter()
                        .map(|o| o.name())
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
                "run on a supported host OS, or select an implemented method".to_string(),
            ));
        }
        Some(_) => {
            let detail = match isolation {
                IsolationKind::Kata => "kata VM isolation via docker's registered `kata` runtime \
                     (prerequisites checked under `kata.runtime`)"
                    .to_string(),
                IsolationKind::AppleContainer => "apple `container` per-unit VM isolation via \
                     the `container` CLI (prerequisites checked under `apple.system`)"
                    .to_string(),
                IsolationKind::HyperV => "Hyper-V utility-VM isolation via docker's \
                     `--isolation=hyperv` (prerequisites checked under `hyperv.engine`, \
                     image compatibility under `hyperv.image`)"
                    .to_string(),
                _ => "container isolation over the resolved engine (default)".to_string(),
            };
            report.checks.push(check(
                "isolation.backend",
                PlanCheckStatus::Pass,
                Some(detail),
            ));
        }
        None => {
            report.checks.push(failing_check(
                "isolation.backend",
                format!(
                    "isolation method '{}' is not implemented in this build \
                     (implemented: {})",
                    isolation.name(),
                    crate::container::backends::implemented_names()
                ),
                "use an implemented isolation method, or upgrade to a build \
                 that implements this one"
                    .to_string(),
            ));
        }
    }

    // image.reference — digest pinning (mirrors run-image's refusal).
    if !args.allow_mutable_tag && !crate::container::runner::image_ref_is_digest_pinned(image) {
        report.checks.push(failing_check(
            "image.reference",
            format!("image reference '{image}' is not digest-pinned"),
            "pin the image with @sha256:<digest>, or pass --allow-mutable-tag".to_string(),
        ));
    } else if args.allow_mutable_tag && !crate::container::runner::image_ref_is_digest_pinned(image)
    {
        report.checks.push(PlanCheck {
            id: "image.reference",
            status: PlanCheckStatus::Warn,
            detail: Some(format!(
                "image reference '{image}' is tag-only; --allow-mutable-tag accepts it"
            )),
            remediation: Some(
                "pin the image with @sha256:<digest> for a reproducible launch".to_string(),
            ),
        });
    } else {
        report.checks.push(check(
            "image.reference",
            PlanCheckStatus::Pass,
            Some("image reference is digest-pinned".to_string()),
        ));
    }

    // engine.resolve — read-only resolution; no daemon mutation. A
    // resolved buildah is still not a usable `run-image` engine: it
    // builds and inspects images but cannot `run` a container. The
    // engine contract exists for the engine-driven backends (`container`
    // and `kata`) — a substrate-driven backend (`apple-container`)
    // resolves its own CLI instead: `--engine` does not apply to it and
    // is refused rather than silently ignored. An unavailable or
    // host-unsupported backend has nothing to probe.
    let engine = if !backend_available {
        report.checks.push(check(
            "engine.resolve",
            PlanCheckStatus::Skipped,
            Some("the selected isolation backend is unavailable".to_string()),
        ));
        None
    } else if !crate::container::backends::engine_backed(isolation) {
        if args.engine.is_some() {
            report.checks.push(failing_check(
                "engine.resolve",
                format!(
                    "--engine does not apply to --isolation {} — the launch is \
                     driven by the substrate's own CLI",
                    isolation.name()
                ),
                "drop --engine, or select an engine-driven isolation method".to_string(),
            ));
            None
        } else {
            match crate::container::backends::substrate_engine(isolation) {
                Some(Ok(e)) => {
                    report.checks.push(check(
                        "engine.resolve",
                        PlanCheckStatus::Pass,
                        Some(format!("substrate driver: {}", e.name())),
                    ));
                    Some(e)
                }
                Some(Err(e)) => {
                    report.checks.push(failing_check(
                        "engine.resolve",
                        format!("substrate driver unavailable: {e}"),
                        "install Apple's `container` tool so `container` resolves on \
                         PATH, then re-run"
                            .to_string(),
                    ));
                    None
                }
                // An implemented non-engine kind always has a driver
                // today — this arm is the contract fallback, not a
                // reachable state.
                None => {
                    report.checks.push(check(
                        "engine.resolve",
                        PlanCheckStatus::Skipped,
                        Some("the backend has no substrate driver".to_string()),
                    ));
                    None
                }
            }
        }
    } else {
        match crate::container::engine::resolve_engine(args.engine) {
            Ok(e) if e.name() == "buildah" => {
                report.checks.push(failing_check(
                    "engine.resolve",
                    "buildah does not support 'run' for container execution".to_string(),
                    "install docker or podman and ensure it is on PATH, or pass \
                     --engine docker|podman"
                        .to_string(),
                ));
                None
            }
            Ok(e) => {
                report.checks.push(check(
                    "engine.resolve",
                    PlanCheckStatus::Pass,
                    Some(format!("engine: {}", e.name())),
                ));
                Some(e)
            }
            Err(e) => {
                report.checks.push(failing_check(
                    "engine.resolve",
                    format!("no usable container engine: {e}"),
                    "install docker or podman and ensure it is on PATH, or pass \
                     --engine docker|podman"
                        .to_string(),
                ));
                None
            }
        }
    };

    // The report target names the resolved engine, not just the CLI hint.
    if let Some(e) = engine.as_ref() {
        report.target.engine = EngineName::from_name(e.name());
    }

    // engine.locality — host bind mounts only reach a local daemon; the
    // same env-var hint run-image refuses on is diagnosed here. The
    // substrate OS comes from `<cli> info` (read-only): an unprobeable
    // OS stays `unknown` rather than borrowing the CLI host's.
    if let Some(e) = engine.as_ref() {
        if let Some(reason) = crate::container::guest_report::remote_daemon_hint(e.name()) {
            report.checks.push(failing_check(
                "engine.locality",
                reason,
                "point the engine at a local daemon, or unset the remote \
                 endpoint env var (DOCKER_HOST / CONTAINER_HOST)"
                    .to_string(),
            ));
        } else {
            match tokio::time::timeout(std::time::Duration::from_secs(5), e.info()).await {
                Ok(Ok(info)) => {
                    if let Some(os) = crate::container::engine::engine_info_os(e.name(), &info) {
                        report.target.substrate_os = os;
                    }
                    report.checks.push(check(
                        "engine.locality",
                        PlanCheckStatus::Pass,
                        Some(format!(
                            "local engine endpoint (substrate {})",
                            report.target.substrate_os.name()
                        )),
                    ));
                }
                _ => {
                    report.checks.push(PlanCheck {
                        id: "engine.locality",
                        status: PlanCheckStatus::Warn,
                        detail: Some(
                            "engine substrate OS could not be probed; recorded as unknown"
                                .to_string(),
                        ),
                        remediation: None,
                    });
                }
            }
        }
    } else {
        let reason = if !backend_available {
            "the selected isolation backend is unavailable"
        } else if crate::container::backends::engine_backed(isolation) {
            "container engine unavailable"
        } else {
            "substrate driver unavailable"
        };
        report.checks.push(check(
            "engine.locality",
            PlanCheckStatus::Skipped,
            Some(reason.to_string()),
        ));
    }

    // kata.runtime — when kata isolation is selected, the validated
    // configuration's prerequisites are probed read-only (`docker info`
    // runtime registration + stat on the host device nodes; nothing is
    // installed or reconfigured). A missing piece blocks the plan —
    // run-image refuses the same way at check time.
    if isolation == IsolationKind::Kata {
        let entry = if !backend_available {
            check(
                "kata.runtime",
                PlanCheckStatus::Skipped,
                Some("the kata backend is unavailable on this host OS".to_string()),
            )
        } else {
            match engine.as_ref() {
                Some(e) => match crate::container::backends::kata::probe(e.as_ref()).await {
                    Ok(detail) => check("kata.runtime", PlanCheckStatus::Pass, Some(detail)),
                    Err(f) => failing_check(
                        "kata.runtime",
                        f.detail,
                        crate::container::backends::kata::prereq_remediation(f.prereq),
                    ),
                },
                None => check(
                    "kata.runtime",
                    PlanCheckStatus::Skipped,
                    Some("container engine unavailable".to_string()),
                ),
            }
        };
        report.checks.push(entry);
    }

    // apple.system — when apple-container isolation is selected, the
    // validated configuration's prerequisites are probed read-only
    // (`system status` + `system property list`; nothing is started or
    // reconfigured). A missing piece blocks the plan — run-image
    // refuses the same way at check time.
    if isolation == IsolationKind::AppleContainer {
        let entry = if !backend_available {
            check(
                "apple.system",
                PlanCheckStatus::Skipped,
                Some("the apple container backend is unavailable on this host OS".to_string()),
            )
        } else {
            match engine.as_ref() {
                Some(e) => match crate::container::backends::apple::probe(e.as_ref()).await {
                    Ok(detail) => check("apple.system", PlanCheckStatus::Pass, Some(detail)),
                    Err(f) => failing_check(
                        "apple.system",
                        f.detail,
                        crate::container::backends::apple::prereq_remediation(f.prereq),
                    ),
                },
                None => check(
                    "apple.system",
                    PlanCheckStatus::Skipped,
                    Some("substrate driver unavailable".to_string()),
                ),
            }
        };
        report.checks.push(entry);
    }

    // hyperv.engine — when hyperv isolation is selected, the validated
    // configuration's prerequisites are probed read-only (`docker info`
    // OSType/OSVersion plus an `sc query` on the Hyper-V services;
    // nothing is started or reconfigured). A missing piece blocks the
    // plan — run-image refuses the same way at check time. The probed
    // host build is kept for the image-compat check below.
    let mut hyperv_host_build: Option<String> = None;
    if isolation == IsolationKind::HyperV {
        let entry = if !backend_available {
            check(
                "hyperv.engine",
                PlanCheckStatus::Skipped,
                Some("the hyperv backend is unavailable on this host OS".to_string()),
            )
        } else {
            match engine.as_ref() {
                Some(e) => match crate::container::backends::hyperv::probe(e.as_ref()).await {
                    Ok(probe) => {
                        hyperv_host_build = Some(probe.host_os_version.clone());
                        check("hyperv.engine", PlanCheckStatus::Pass, Some(probe.detail))
                    }
                    Err(f) => failing_check(
                        "hyperv.engine",
                        f.detail,
                        crate::container::backends::hyperv::prereq_remediation(f.prereq),
                    ),
                },
                None => check(
                    "hyperv.engine",
                    PlanCheckStatus::Skipped,
                    Some("container engine unavailable".to_string()),
                ),
            }
        };
        report.checks.push(entry);
    }

    // policy.load — validated against the guest contract the selected
    // isolation method would carry, not always the Linux container one.
    let guest_target = image_target(
        engine
            .as_ref()
            .and_then(|e| EngineName::from_name(e.name())),
        isolation,
    );
    // run-image mounts ./policy.kdl when --policy is omitted — the plan
    // evaluates the file the launch would actually carry.
    let policy_path = args.policy.as_deref().unwrap_or(Path::new("./policy.kdl"));
    let policy = load_policy_check(
        &mut report,
        Some(policy_path),
        args.server.as_deref(),
        &guest_target,
    );

    // image.inspect — local inspect only; a missing image is a blocked
    // prerequisite, never an implicit pull. Bounded like `engine.locality`:
    // a wedged daemon turns inspect into a failed prerequisite rather than
    // a hung plan.
    if let Some(engine) = engine.as_ref() {
        let inspected = match tokio::time::timeout(
            std::time::Duration::from_secs(5),
            crate::container::inspect::inspect_image(engine.as_ref(), image),
        )
        .await
        {
            Ok(res) => res,
            Err(_) => Err(crate::error::ContainerError::InspectExec(format!(
                "{} image inspect timed out after 5s",
                engine.name()
            ))),
        };
        match inspected {
            Ok(meta) => {
                report.checks.push(check(
                    "image.inspect",
                    PlanCheckStatus::Pass,
                    Some("image metadata inspected locally".to_string()),
                ));

                // image.os — the workload's OS is the image's guest OS,
                // never the CLI host's. Both defined guest contracts
                // (linux, windows) pass; whether the selected isolation
                // backend can actually launch that guest is a separate
                // check below. An unknown OS is refused rather than
                // assumed Linux.
                match crate::container::guest_report::check_guest_image_os(meta.os.as_deref()) {
                    Ok(os) => {
                        report.target.workload_os = os;
                        report.checks.push(check(
                            "image.os",
                            PlanCheckStatus::Pass,
                            Some(format!(
                                "image OS '{}' matches the {} guest contract",
                                meta.os.as_deref().unwrap_or(os.name()),
                                os.name()
                            )),
                        ));
                    }
                    Err(e) => {
                        report.checks.push(failing_check(
                            "image.os",
                            e,
                            "wrap a Linux or Windows image — the embedded \
                             mcp-secure-runner must match the guest OS"
                                .to_string(),
                        ));
                    }
                }
                report.target.workload_arch =
                    crate::container::guest_report::image_target_arch(meta.architecture.as_deref());

                // image.arch — the OCI substrate can bridge a foreign
                // image arch via binfmt/qemu-user; a VM substrate cannot:
                // the kata VM boots a host-arch guest kernel, the apple
                // VM's only foreign-arch path is Rosetta translation,
                // and the hyperv contract ships windows/amd64 only —
                // none is the validated boundary for a foreign arch. A
                // mismatched image is the same refusal run-image applies.
                if matches!(
                    isolation,
                    IsolationKind::Kata | IsolationKind::AppleContainer | IsolationKind::HyperV
                ) && report.target.workload_arch != TargetArch::host()
                {
                    let detail = if isolation == IsolationKind::Kata {
                        format!(
                            "the kata VM boots a {} guest kernel — image architecture \
                             '{}' cannot run on this host",
                            TargetArch::host().name(),
                            report.target.workload_arch.name()
                        )
                    } else if isolation == IsolationKind::HyperV {
                        format!(
                            "the hyperv backend launches windows/amd64 images — image \
                             architecture '{}' is outside the validated contract",
                            report.target.workload_arch.name()
                        )
                    } else {
                        format!(
                            "the apple `container` VM launches native-arch images — image \
                             architecture '{}' on this {} host would run only under \
                             Rosetta translation, which is not the validated isolation \
                             boundary",
                            report.target.workload_arch.name(),
                            TargetArch::host().name()
                        )
                    };
                    report.checks.push(failing_check(
                        "image.arch",
                        detail,
                        "use an image built for the host architecture, or select \
                         container isolation"
                            .to_string(),
                    ));
                }

                // runner.entrypoint — the guest contract's runner path,
                // per the image's guest OS (never a hardcoded literal).
                let entrypoint = meta.entrypoint.as_deref().unwrap_or(&[]);
                let runner_path =
                    crate::container::guest_layout::for_guest_os(report.target.workload_os)
                        .map(|l| l.runner_path);
                match runner_path {
                    Some(path) if entrypoint.first().map(String::as_str) == Some(path) => {
                        report.checks.push(check(
                            "runner.entrypoint",
                            PlanCheckStatus::Pass,
                            Some(format!("image ENTRYPOINT[0] is {path}")),
                        ));
                    }
                    Some(path) => {
                        report.checks.push(failing_check(
                            "runner.entrypoint",
                            format!("image ENTRYPOINT[0] is not {path}"),
                            "wrap or containerize the image first \
                             (`mcp-writ wrap-image` / `mcp-writ containerize`)"
                                .to_string(),
                        ));
                    }
                    None => {
                        report.checks.push(failing_check(
                            "runner.entrypoint",
                            format!(
                                "no guest contract for image OS '{}'",
                                report.target.workload_os.name()
                            ),
                            "wrap a Linux or Windows image".to_string(),
                        ));
                    }
                }

                // isolation.guest_os — the backend must declare the
                // image's guest OS. A Windows image is a defined guest
                // contract, but no backend launches it yet (the Hyper-V
                // backend is PR-22) — surface that as a plan failure
                // rather than a launch-time surprise.
                if let Some(caps) = crate::container::backends::capabilities_for(isolation)
                    && !caps.guest_os.contains(&report.target.workload_os)
                {
                    report.checks.push(failing_check(
                        "isolation.guest_os",
                        format!(
                            "isolation method '{}' does not launch {} guests \
                             (declared guest OSs: {})",
                            isolation.name(),
                            report.target.workload_os.name(),
                            caps.guest_os
                                .iter()
                                .map(|o| o.name())
                                .collect::<Vec<_>>()
                                .join(", ")
                        ),
                        "use an isolation backend that supports the image's \
                         guest OS"
                            .to_string(),
                    ));
                }

                // hyperv.image — the guest-build compatibility rule:
                // the image's recorded `OsVersion` build may not be
                // newer than the host's. The host side comes from the
                // `hyperv.engine` probe; when it never ran (backend or
                // engine unavailable) the check is skipped rather than
                // guessed. A windows guest on the wrong substrate is
                // refused by `isolation.guest_os` below — this check
                // runs only for the hyperv selection.
                if isolation == IsolationKind::HyperV {
                    let entry = match hyperv_host_build.as_deref() {
                        Some(host_build) if report.target.workload_os == TargetOs::Windows => {
                            match crate::container::backends::hyperv::image_version_check(
                                meta.os_version.as_deref(),
                                host_build,
                            ) {
                                None => check(
                                    "hyperv.image",
                                    PlanCheckStatus::Pass,
                                    Some(format!(
                                        "image build {} ≤ host build {host_build}",
                                        meta.os_version.as_deref().unwrap_or("<absent>")
                                    )),
                                ),
                                Some(detail) => failing_check(
                                    "hyperv.image",
                                    detail,
                                    crate::container::backends::hyperv::prereq_remediation(
                                        crate::container::backends::hyperv::HypervPrereq::ImageVersion,
                                    ),
                                ),
                            }
                        }
                        Some(_) => check(
                            "hyperv.image",
                            PlanCheckStatus::Skipped,
                            Some("the image's guest is not windows".to_string()),
                        ),
                        None => check(
                            "hyperv.image",
                            PlanCheckStatus::Skipped,
                            Some("the hyperv.engine probe did not produce a host build".to_string()),
                        ),
                    };
                    report.checks.push(entry);
                }

                // runner.caps — the capability marker env recorded at
                // build time. An absent marker is a legacy runner: it
                // still launches, but `run-image --report` refuses it —
                // a warning here, not a block.
                match crate::container::guest_report::caps_from_image_env(&meta.env) {
                    Some(caps) if caps.guest_report_capable() => {
                        report.checks.push(check(
                            "runner.caps",
                            PlanCheckStatus::Pass,
                            Some(format!(
                                "runner v{} claims the guest report capability",
                                caps.version
                            )),
                        ));
                    }
                    Some(caps) => {
                        report.checks.push(PlanCheck {
                            id: "runner.caps",
                            status: PlanCheckStatus::Warn,
                            detail: Some(format!(
                                "runner v{} does not claim the guest report capability",
                                caps.version
                            )),
                            remediation: Some(
                                "rebuild the image with a current mcp-secure-runner to \
                                 enable `run-image --report` guest reports"
                                    .to_string(),
                            ),
                        });
                    }
                    None => {
                        report.checks.push(PlanCheck {
                            id: "runner.caps",
                            status: PlanCheckStatus::Warn,
                            detail: Some(
                                "no runner capability marker on the image (legacy build); \
                                 `run-image --report` refuses this image"
                                    .to_string(),
                            ),
                            remediation: Some(
                                "rebuild the image with a current mcp-secure-runner via \
                                 wrap-image or containerize"
                                    .to_string(),
                            ),
                        });
                    }
                }

                // image.digest_match — policy docker-manifest-hash entries.
                if let Some(policy) = policy.as_ref() {
                    // Workload pins are not host-checkable on an image
                    // launch — `mcp-secure-runner` verifies them inside the
                    // guest at workload launch. `skipped`, not `pass`:
                    // nothing ran here.
                    let guest_pins = policy
                        .hash_entries
                        .iter()
                        .filter(|e| !matches!(e.hash_type, crate::policy::HashType::DockerManifest))
                        .count();
                    if guest_pins > 0 {
                        report.checks.push(check(
                            "guest.hash",
                            PlanCheckStatus::Skipped,
                            Some(format!(
                                "{guest_pins} workload hash entries \
                                 (binary-hash/entrypoint-hash/lockfile-hash) verify inside \
                                 the guest at launch — not by this host-side plan; see the \
                                 guest report's code_identity"
                            )),
                        ));
                    }
                    let docker_hashes: Vec<_> = policy
                        .hash_entries
                        .iter()
                        .filter(|e| e.hash_type == crate::policy::HashType::DockerManifest)
                        .collect();
                    if !docker_hashes.is_empty() {
                        let actual = meta.digest.as_deref().unwrap_or("");
                        if docker_hashes.iter().any(|e| e.hash_value == actual) {
                            report.checks.push(check(
                                "image.digest_match",
                                PlanCheckStatus::Pass,
                                Some(
                                    "image digest matches the policy's docker-manifest-hash"
                                        .to_string(),
                                ),
                            ));
                        } else {
                            report.checks.push(failing_check(
                                "image.digest_match",
                                format!(
                                    "image digest '{}' does not match any docker-manifest-hash in the policy",
                                    if actual.is_empty() { "(missing)" } else { actual }
                                ),
                                "rebuild or re-pull the pinned image, or update the policy's \
                                 docker-manifest-hash entries"
                                    .to_string(),
                            ));
                        }
                    }
                }
            }
            Err(e) => {
                report.checks.push(failing_check(
                    "image.inspect",
                    format!("failed to inspect image '{image}': {e}"),
                    "build or pull the image locally first — `plan` never pulls".to_string(),
                ));
            }
        }
    } else {
        // Driver resolution failed or the selected isolation backend is
        // unavailable — image checks cannot run.
        let reason = if !backend_available {
            "the selected isolation backend is unavailable"
        } else if crate::container::backends::engine_backed(isolation) {
            "container engine unavailable"
        } else {
            "substrate driver unavailable"
        };
        report.checks.push(check(
            "image.inspect",
            PlanCheckStatus::Skipped,
            Some(reason.to_string()),
        ));
        report.checks.push(check(
            "image.os",
            PlanCheckStatus::Skipped,
            Some(reason.to_string()),
        ));
        report.checks.push(check(
            "runner.entrypoint",
            PlanCheckStatus::Skipped,
            Some(reason.to_string()),
        ));
        report.checks.push(check(
            "runner.caps",
            PlanCheckStatus::Skipped,
            Some(reason.to_string()),
        ));
    }

    // audit.config — fail-closed logging requires a mounted
    // /var/log/mcp-secure inside the guest (`run-image --log-dir`);
    // mcp-secure-runner exits when it is absent. `plan` cannot verify a
    // later invocation's flags, so this is a warning, not a block — the
    // same treatment the native `audit.config` check gets.
    match policy.as_ref() {
        Some(p) if p.logging.fail_closed => {
            report.checks.push(PlanCheck {
                id: "audit.config",
                status: PlanCheckStatus::Warn,
                detail: Some(
                    "policy logging.fail_closed is on: `run-image` requires \
                     --log-dir <dir> mounted at /var/log/mcp-secure, which \
                     `plan` cannot verify"
                        .to_string(),
                ),
                remediation: Some("pass --log-dir <dir> to `run-image`".to_string()),
            });
        }
        Some(_) => {
            report.checks.push(check(
                "audit.config",
                PlanCheckStatus::Pass,
                Some(
                    "logging.fail_closed is off; guest audit events may go to tracing".to_string(),
                ),
            ));
        }
        None => {
            report.checks.push(check(
                "audit.config",
                PlanCheckStatus::Skipped,
                Some("policy unavailable".to_string()),
            ));
        }
    }

    // guest.contract — the in-guest sandbox/audit cannot be probed from
    // the host without launching; recorded as not-inspected rather than
    // assumed.
    report.checks.push(check(
        "guest.contract",
        PlanCheckStatus::Skipped,
        Some(
            "guest-side enforcement (Landlock/seccomp, auditor) is applied by \
             mcp-secure-runner inside the guest and is not probed here"
                .to_string(),
        ),
    ));

    // Host-side launch plan: what `run-image` sets up. The guest's own
    // enforcement plan is computed by mcp-secure-runner at container
    // start and is not observable here.
    let tools: Vec<ToolDisposition> = policy
        .as_ref()
        .map(|p| {
            p.tools
                .iter()
                .map(|t| ToolDisposition {
                    name: t.name.clone(),
                    server: t.server.clone(),
                    allowed: t.allowed,
                    side_effect: t.side_effect.clone(),
                })
                .collect()
        })
        .unwrap_or_default();
    // Mark plan controls whose prerequisite check failed.
    for c in plan_controls.iter_mut() {
        let blocked = match c.id {
            "launch.isolation" => {
                !backend_available
                    || report.checks.iter().any(|k| {
                        matches!(
                            k.id,
                            "kata.runtime" | "apple.system" | "hyperv.engine" | "hyperv.image"
                        ) && k.status == PlanCheckStatus::Fail
                    })
            }
            "launch.engine" => {
                engine.is_none()
                    || report
                        .checks
                        .iter()
                        .any(|k| k.id == "engine.locality" && k.status == PlanCheckStatus::Fail)
            }
            // The image control covers reference pinning, local presence,
            // the guest-OS contract, and digest-vs-policy matching — a
            // failed entrypoint check is the runner control's concern.
            "launch.image" => report.checks.iter().any(|k| {
                matches!(
                    k.id,
                    "image.reference"
                        | "image.inspect"
                        | "image.os"
                        | "image.arch"
                        | "image.digest_match"
                ) && k.status == PlanCheckStatus::Fail
            }),
            "launch.runner" => report.checks.iter().any(|k| {
                matches!(k.id, "image.inspect" | "runner.entrypoint")
                    && k.status == PlanCheckStatus::Fail
            }),
            "launch.policy" => policy.is_none(),
            _ => false,
        };
        if blocked {
            c.state = ControlState::Failed;
            c.reason = Some("prerequisite check failed".to_string());
        }
    }
    report.plan = Some(EnforcementPlan {
        controls: plan_controls,
        grants: Vec::new(),
        tools,
        limitations: vec![
            "host-side launch plan only: guest-side grants and sandbox observations \
             are produced by mcp-secure-runner inside the guest and are not \
             enumerated here"
                .to_string(),
        ],
    });
    finalize(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn image_plan_args(isolation: Option<IsolationKind>) -> PlanArgs {
        PlanArgs {
            image: Some(
                "app@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                    .to_string(),
            ),
            isolation,
            // Image mode defaults --policy to ./policy.kdl (run-image
            // parity); pin a real file so policy.load passes and the
            // asserted failure stays the test's own subject.
            policy: Some(Path::new(env!("CARGO_MANIFEST_DIR")).join("policy.example.kdl")),
            ..Default::default()
        }
    }

    /// An unimplemented isolation method blocks the plan before any
    /// engine or image probing — the same refusal `run-image` gives,
    /// reported as a check rather than a silent fallback.
    #[tokio::test]
    async fn unimplemented_isolation_blocks_the_plan() {
        let report = diagnose(image_plan_args(Some(IsolationKind::WindowsSandbox))).await;
        assert_eq!(report.status, PlanStatus::Blocked);
        assert_eq!(report.reason_code, Some("isolation_unsupported"));
        let c = report
            .checks
            .iter()
            .find(|c| c.id == "isolation.backend")
            .expect("isolation.backend check");
        assert_eq!(c.status, PlanCheckStatus::Fail);
        assert!(
            c.detail
                .as_deref()
                .unwrap_or_default()
                .contains("not implemented"),
            "got: {:?}",
            c.detail
        );
        // No engine probe ran — an unimplemented backend has no engine
        // contract; engine/image checks are skipped, not failed.
        let engine = report
            .checks
            .iter()
            .find(|c| c.id == "engine.resolve")
            .expect("engine.resolve check");
        assert_eq!(engine.status, PlanCheckStatus::Skipped);
        // The recorded substrate is the VM boundary the method would
        // give, not the container substrate — and a method not driven
        // through the resolved engine carries no container-engine
        // identity.
        assert_eq!(report.target.substrate.name(), "vm");
        assert_eq!(report.target.engine, None);
        // The launch plan marks the isolation control failed.
        let plan = report.plan.as_ref().expect("plan present");
        let iso = plan
            .controls
            .iter()
            .find(|c| c.id == "launch.isolation")
            .expect("launch.isolation control");
        assert_eq!(iso.state, ControlState::Failed);
    }

    /// The remaining unimplemented kind fails the same check — never a
    /// selectably-successful path.
    #[tokio::test]
    async fn every_unimplemented_isolation_blocks() {
        let kind = IsolationKind::WindowsSandbox;
        let report = diagnose(image_plan_args(Some(kind))).await;
        assert_eq!(report.status, PlanStatus::Blocked, "kind {}", kind.name());
        let c = report
            .checks
            .iter()
            .find(|c| c.id == "isolation.backend")
            .expect("isolation.backend check");
        assert_eq!(c.status, PlanCheckStatus::Fail, "kind {}", kind.name());
        assert!(
            c.detail.as_deref().unwrap().contains(kind.name()),
            "kind {}: {:?}",
            kind.name(),
            c.detail
        );
    }

    /// The default (`container`) isolation reports the backend check as
    /// pass and keeps the container substrate — existing behavior is
    /// preserved.
    #[tokio::test]
    async fn container_isolation_passes_the_backend_check() {
        let report = diagnose(image_plan_args(None)).await;
        let c = report
            .checks
            .iter()
            .find(|c| c.id == "isolation.backend")
            .expect("isolation.backend check");
        assert_eq!(c.status, PlanCheckStatus::Pass);
        assert_eq!(report.target.substrate.name(), "container");
        // engine.resolve still ran — the container path is unchanged.
        let engine = report
            .checks
            .iter()
            .find(|c| c.id == "engine.resolve")
            .expect("engine.resolve check");
        assert_ne!(
            engine.status,
            PlanCheckStatus::Skipped,
            "container isolation must not skip the engine probe"
        );
        let plan = report.plan.as_ref().expect("plan present");
        let iso = plan
            .controls
            .iter()
            .find(|c| c.id == "launch.isolation")
            .expect("launch.isolation control");
        assert_eq!(iso.state, ControlState::Planned);
    }

    /// `--isolation kata` is implemented, so plan diagnoses it instead
    /// of refusing as unimplemented: `isolation.backend` is host-OS
    /// gated (fail only off-Linux, where the validated dockerd+KVM stack
    /// cannot exist), `kata.runtime` probes docker's runtime
    /// registration and the KVM/vsock device nodes, and the recorded
    /// target keeps the engine name because the launch is engine-driven.
    #[tokio::test]
    async fn kata_isolation_is_diagnosed_not_refused() {
        let report = diagnose(image_plan_args(Some(IsolationKind::Kata))).await;
        let backend = report
            .checks
            .iter()
            .find(|c| c.id == "isolation.backend")
            .expect("isolation.backend check");
        // Implemented, always — the detail never claims otherwise.
        assert!(
            !backend
                .detail
                .as_deref()
                .unwrap_or_default()
                .contains("not implemented"),
            "kata is implemented: {:?}",
            backend.detail
        );
        let kata_runtime = report
            .checks
            .iter()
            .find(|c| c.id == "kata.runtime")
            .expect("kata.runtime check recorded for --isolation kata");
        if cfg!(target_os = "linux") {
            assert_eq!(backend.status, PlanCheckStatus::Pass);
            // The runtime probe answers pass/fail when an engine is
            // resolvable, skipped only when there is no engine to ask.
            // A fail blocks the plan and the isolation control — never
            // a silent downgrade to a normal container.
            if kata_runtime.status == PlanCheckStatus::Fail {
                assert_eq!(report.status, PlanStatus::Blocked);
                assert_eq!(report.reason_code, Some("isolation_unsupported"));
                let plan = report.plan.as_ref().expect("plan present");
                let iso = plan
                    .controls
                    .iter()
                    .find(|c| c.id == "launch.isolation")
                    .expect("launch.isolation control");
                assert_eq!(iso.state, ControlState::Failed);
            }
        } else {
            // Off-Linux the declared-capability gate fails the backend
            // check before any engine work, and the runtime probe is
            // recorded skipped — never silently absent.
            assert_eq!(backend.status, PlanCheckStatus::Fail);
            assert!(
                backend
                    .detail
                    .as_deref()
                    .unwrap_or_default()
                    .contains("not supported on this host OS"),
                "got: {:?}",
                backend.detail
            );
            assert_eq!(kata_runtime.status, PlanCheckStatus::Skipped);
            assert_eq!(report.status, PlanStatus::Blocked);
            assert_eq!(report.reason_code, Some("isolation_unsupported"));
        }
        // The recorded target is the VM substrate with a Linux guest —
        // and `engine` stays recorded: `docker run --runtime kata` is
        // an engine-driven launch.
        assert_eq!(report.target.substrate.name(), "vm");
        assert_eq!(report.target.workload_os.name(), "linux");
        let _ = report.target.engine;
    }

    /// `--isolation apple-container` is implemented, so plan diagnoses
    /// it instead of refusing as unimplemented: `isolation.backend` is
    /// host-OS gated (fail only off-macOS, where the Virtualization.
    /// framework substrate cannot exist), `apple.system` probes the
    /// `container` service and guest kernel, and a resolved `container`
    /// CLI driver is recorded as the launch's substrate identity.
    #[tokio::test]
    async fn apple_isolation_is_diagnosed_not_refused() {
        let report = diagnose(image_plan_args(Some(IsolationKind::AppleContainer))).await;
        let backend = report
            .checks
            .iter()
            .find(|c| c.id == "isolation.backend")
            .expect("isolation.backend check");
        // Implemented, always — the detail never claims otherwise.
        assert!(
            !backend
                .detail
                .as_deref()
                .unwrap_or_default()
                .contains("not implemented"),
            "apple-container is implemented: {:?}",
            backend.detail
        );
        let apple_system = report
            .checks
            .iter()
            .find(|c| c.id == "apple.system")
            .expect("apple.system check recorded for --isolation apple-container");
        if cfg!(target_os = "macos") {
            // The backend's declared host scope is macOS itself — it
            // passes on Intel too. The Apple-Silicon restriction is
            // enforced one level down, by the `apple.system` probe.
            assert_eq!(backend.status, PlanCheckStatus::Pass);
            // The system probe answers pass/fail when the driver is
            // resolvable, skipped only when there is no driver to ask.
            // A fail blocks the plan and the isolation control — never
            // a silent downgrade to a normal container.
            if apple_system.status == PlanCheckStatus::Fail {
                assert_eq!(report.status, PlanStatus::Blocked);
                assert_eq!(report.reason_code, Some("isolation_unsupported"));
                let plan = report.plan.as_ref().expect("plan present");
                let iso = plan
                    .controls
                    .iter()
                    .find(|c| c.id == "launch.isolation")
                    .expect("launch.isolation control");
                assert_eq!(iso.state, ControlState::Failed);
            }
            if cfg!(target_arch = "aarch64") {
                // When the `container` CLI resolved, its substrate-driver
                // identity is recorded on the target.
                let engine = report
                    .checks
                    .iter()
                    .find(|c| c.id == "engine.resolve")
                    .expect("engine.resolve check");
                if engine.status == PlanCheckStatus::Pass {
                    assert_eq!(
                        report.target.engine,
                        Some(crate::execution::EngineName::AppleContainer),
                        "the container CLI is the substrate driver identity"
                    );
                }
            } else {
                // Intel macOS: the probe refuses a non-aarch64 host —
                // Fail when the `container` driver resolved, Skipped
                // when engine.resolve's own failure already blocked the
                // plan. It can never pass.
                assert_ne!(apple_system.status, PlanCheckStatus::Pass);
                assert_eq!(report.status, PlanStatus::Blocked);
            }
        } else {
            // Off-Apple-Silicon the declared-capability gate fails the
            // backend check before any driver work, and the system probe
            // is recorded skipped — never silently absent.
            assert_eq!(backend.status, PlanCheckStatus::Fail);
            assert!(
                backend
                    .detail
                    .as_deref()
                    .unwrap_or_default()
                    .contains("not supported on this host OS"),
                "got: {:?}",
                backend.detail
            );
            assert_eq!(apple_system.status, PlanCheckStatus::Skipped);
            assert_eq!(report.status, PlanStatus::Blocked);
            assert_eq!(report.reason_code, Some("isolation_unsupported"));
        }
        // The recorded target is the VM substrate with a Linux guest.
        assert_eq!(report.target.substrate.name(), "vm");
        assert_eq!(report.target.workload_os.name(), "linux");
    }

    /// `--engine` does not apply to a substrate-driven isolation — the
    /// flag is refused as an engine.resolve failure rather than ignored.
    /// (On non-macOS hosts the host-OS gate blocks the plan first.)
    #[tokio::test]
    async fn apple_isolation_refuses_an_engine_flag_in_plan() {
        let mut args = image_plan_args(Some(IsolationKind::AppleContainer));
        args.engine = Some(crate::container::engine::EngineKind::Docker);
        let report = diagnose(args).await;
        if cfg!(target_os = "macos") {
            let engine = report
                .checks
                .iter()
                .find(|c| c.id == "engine.resolve")
                .expect("engine.resolve check");
            assert_eq!(engine.status, PlanCheckStatus::Fail);
            assert!(
                engine
                    .detail
                    .as_deref()
                    .unwrap_or_default()
                    .contains("--engine"),
                "got: {:?}",
                engine.detail
            );
        } else {
            assert_eq!(report.status, PlanStatus::Blocked);
        }
    }

    /// A VM-substrate method's recorded target follows the method's
    /// guest contract — `--isolation windows-sandbox --engine docker`
    /// reports a Windows workload and drops the engine identity rather
    /// than pairing a VM substrate with a container engine.
    #[tokio::test]
    async fn vm_isolation_target_records_its_own_contract() {
        let mut args = image_plan_args(Some(IsolationKind::WindowsSandbox));
        args.engine = Some(crate::container::engine::EngineKind::Docker);
        let report = diagnose(args).await;
        assert_eq!(report.status, PlanStatus::Blocked);
        assert_eq!(report.target.substrate.name(), "vm");
        assert_eq!(
            report.target.engine, None,
            "a VM substrate records no container engine"
        );
        assert_eq!(
            report.target.workload_os,
            crate::execution::TargetOs::Windows,
            "a Windows-scoped method records a Windows workload"
        );
    }
}
