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
use crate::execution::{EngineName, ExecutionTarget};
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
        "image.reference" => "image_not_pinned",
        "image.inspect" => "image_not_available",
        "image.os" => "unsupported_guest_os",
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
            report
                .checks
                .push(failing_check("policy.load", e.to_string(), remediation));
            report.status = match code {
                "policy_not_found" => PlanStatus::Blocked,
                _ => PlanStatus::Invalid,
            };
            report.reason_code = Some(code);
            report.reason = Some(e.to_string());
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

    // hash.entries — supply-chain pinning coverage.
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
        report.checks.push(check(
            "hash.identity",
            PlanCheckStatus::Pass,
            Some(format!(
                "{} hash entries will verify binaries before spawn",
                policy.hash_entries.len()
            )),
        ));
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

/// Image mode: `mcp-writ plan --engine <e> --image <ref> --policy <path>`.
///
/// Inspects the *local* image only — no pull, no container start, no
/// daemon configuration change.
async fn diagnose_image(args: &PlanArgs, image: &str) -> PlanReport {
    let target = ExecutionTarget::linux_container(args.engine.map(EngineName::from), None);
    let mut report = base_report(target);
    let launch_control = |id: &'static str| PlannedControl {
        id,
        layer: ControlLayer::Launch,
        mechanism: "container launch",
        state: ControlState::Planned,
        reason: None,
    };
    let mut plan_controls = vec![
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
    // builds and inspects images but cannot `run` a container.
    let engine = match crate::container::engine::resolve_engine(args.engine) {
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
                "install docker, podman, or buildah and ensure it is on PATH".to_string(),
            ));
            None
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
        report.checks.push(check(
            "engine.locality",
            PlanCheckStatus::Skipped,
            Some("container engine unavailable".to_string()),
        ));
    }

    // policy.load — validated against the Linux guest contract.
    let guest_target = ExecutionTarget::linux_container(
        engine
            .as_ref()
            .and_then(|e| EngineName::from_name(e.name())),
        None,
    );
    let policy = load_policy_check(
        &mut report,
        args.policy.as_deref(),
        args.server.as_deref(),
        &guest_target,
    );

    // image.inspect — local inspect only; a missing image is a blocked
    // prerequisite, never an implicit pull.
    if let Some(engine) = engine.as_ref() {
        match crate::container::inspect::inspect_image(engine.as_ref(), image).await {
            Ok(meta) => {
                report.checks.push(check(
                    "image.inspect",
                    PlanCheckStatus::Pass,
                    Some("image metadata inspected locally".to_string()),
                ));

                // image.os — the workload's OS is the image's guest OS,
                // never the CLI host's. run-image refuses a non-Linux
                // image outright, so it blocks the plan's `ready`.
                match crate::container::guest_report::check_guest_image_os(meta.os.as_deref()) {
                    Ok(os) => {
                        report.target.workload_os = os;
                        report.checks.push(check(
                            "image.os",
                            PlanCheckStatus::Pass,
                            Some(format!(
                                "image OS '{}' satisfies the Linux guest contract",
                                meta.os.as_deref().unwrap_or("linux")
                            )),
                        ));
                    }
                    Err(e) => {
                        report.checks.push(failing_check(
                            "image.os",
                            e,
                            "wrap a Linux image — the embedded mcp-secure-runner \
                             is a Linux ELF"
                                .to_string(),
                        ));
                    }
                }
                report.target.workload_arch =
                    crate::container::guest_report::image_target_arch(meta.architecture.as_deref());

                // runner.entrypoint — the guest contract.
                let entrypoint = meta.entrypoint.as_deref().unwrap_or(&[]);
                if entrypoint.first().map(String::as_str)
                    == Some("/usr/local/bin/mcp-secure-runner")
                {
                    report.checks.push(check(
                        "runner.entrypoint",
                        PlanCheckStatus::Pass,
                        Some("image ENTRYPOINT[0] is /usr/local/bin/mcp-secure-runner".to_string()),
                    ));
                } else {
                    report.checks.push(failing_check(
                        "runner.entrypoint",
                        "image ENTRYPOINT[0] is not /usr/local/bin/mcp-secure-runner".to_string(),
                        "wrap or containerize the image first \
                         (`mcp-writ wrap-image` / `mcp-writ containerize`)"
                            .to_string(),
                    ));
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
        // Engine resolution failed — image checks cannot run.
        report.checks.push(check(
            "image.inspect",
            PlanCheckStatus::Skipped,
            Some("container engine unavailable".to_string()),
        ));
        report.checks.push(check(
            "image.os",
            PlanCheckStatus::Skipped,
            Some("container engine unavailable".to_string()),
        ));
        report.checks.push(check(
            "runner.entrypoint",
            PlanCheckStatus::Skipped,
            Some("container engine unavailable".to_string()),
        ));
        report.checks.push(check(
            "runner.caps",
            PlanCheckStatus::Skipped,
            Some("container engine unavailable".to_string()),
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
             mcp-secure-runner inside the container and is not probed here"
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
                    "image.reference" | "image.inspect" | "image.os" | "image.digest_match"
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
             are produced by mcp-secure-runner inside the container and are not \
             enumerated here"
                .to_string(),
        ],
    });
    finalize(report)
}
