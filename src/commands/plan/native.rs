//! Native mode: `mcp-writ plan --policy <path> -- <command>` — the
//! host-side launch the warden would enforce, diagnosed without a spawn.

use crate::cli::PlanArgs;
use crate::enforcement::{
    ControlLayer, ControlState, PlanCheck, PlanCheckStatus, PlanReport, PlannedControl,
};
use crate::execution::ExecutionTarget;
use crate::verifier::fail_on::{FAIL_ON_ENV, FailOn};
use crate::workload::resolve_command_path;

use super::host::host_os_check;
use super::report::{base_report, check, failing_check, finalize, load_policy_check};

/// Native mode: `mcp-writ plan --policy <path> -- <command>`.
pub(super) async fn diagnose_native(args: &PlanArgs) -> PlanReport {
    let target = match args.windows_mechanism {
        Some(m) => ExecutionTarget::native().with_native_windows_mechanism(m),
        None => ExecutionTarget::native(),
    };
    let mut report = base_report(target.clone());
    // host.os first — the report always carries which host it
    // diagnosed. Native plans never probe WSL: the diagnostic does not
    // require it, and on non-Windows hosts no Windows tool spawns.
    report.checks.push(host_os_check().await);
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

    // env.fail_on — the finding-abort dial `run` resolves
    // (--fail-on > MCP_WRIT_FAIL_ON > high) and records on
    // `policy.loaded`. `plan` cannot see a later invocation's CLI flag,
    // so it reports the env/default half: a below-default dial is a
    // warning (a launch would weaken enforcement), an invalid value is
    // a failure (a launch would refuse before spawning).
    match FailOn::resolve_from_process_env(None) {
        Err(e) => report.checks.push(failing_check(
            "env.fail_on",
            format!("MCP_WRIT_FAIL_ON is invalid: {e}"),
            "set MCP_WRIT_FAIL_ON to high, critical, or none (or unset it) — \
             `run` refuses an invalid value before launch"
                .to_string(),
        )),
        Ok(FailOn::None) => report.checks.push(PlanCheck {
            id: "env.fail_on",
            status: PlanCheckStatus::Warn,
            detail: Some(
                "MCP_WRIT_FAIL_ON=none: findings never abort the launch — \
                 `run` warns and records the dial on policy.loaded"
                    .to_string(),
            ),
            remediation: Some(
                "set MCP_WRIT_FAIL_ON to high or critical, or pass --fail-on to `run`".to_string(),
            ),
        }),
        Ok(FailOn::Critical) => report.checks.push(PlanCheck {
            id: "env.fail_on",
            status: PlanCheckStatus::Warn,
            detail: Some(
                "MCP_WRIT_FAIL_ON=critical: High findings no longer abort — \
                 weaker than the default 'high' (`run` records the dial on \
                 policy.loaded)"
                    .to_string(),
            ),
            remediation: Some(
                "set MCP_WRIT_FAIL_ON to high to restore the default, or pass \
                 --fail-on to `run`"
                    .to_string(),
            ),
        }),
        Ok(FailOn::High) => {
            let origin = match std::env::var(FAIL_ON_ENV) {
                Ok(v) if !v.is_empty() => "from MCP_WRIT_FAIL_ON; --fail-on overrides at run",
                _ => "default — MCP_WRIT_FAIL_ON unset",
            };
            report.checks.push(check(
                "env.fail_on",
                PlanCheckStatus::Pass,
                Some(format!("fail-on resolves to 'high' ({origin})")),
            ));
        }
    }

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

    // windows.mechanism — an explicit selection is surfaced as its own
    // check. `psec` runs the real capability probe now (the same gate a
    // launch runs first): a host without the contract reports blocked
    // with the probe's reason, never a plan that would silently run the
    // default mechanism.
    if let Some(mechanism) = args.windows_mechanism {
        use crate::execution::WindowsNativeMechanism as M;
        match mechanism {
            M::AppContainer => report.checks.push(check(
                "windows.mechanism",
                PlanCheckStatus::Pass,
                Some(if cfg!(windows) {
                    "appcontainer — the platform default mechanism".to_string()
                } else {
                    "appcontainer — a native-Windows mechanism selection; this \
                     host's default sandbox is a different mechanism"
                        .to_string()
                }),
            )),
            M::Psec => match crate::warden::psec_capability_probe() {
                Ok(detail) => report.checks.push(check(
                    "windows.mechanism",
                    PlanCheckStatus::Pass,
                    Some(format!("psec — capability probe passed: {detail}")),
                )),
                Err(e) => report.checks.push(failing_check(
                    "windows.mechanism",
                    format!("psec capability probe failed: {e}"),
                    "select appcontainer (the default) or run on a host whose \
                     PSEC contract answers the probe — a psec launch refuses \
                     this host, it never falls back"
                        .to_string(),
                )),
            },
        }
    }

    // Compute the enforcement plan — the same builders the spawn path
    // uses, so its Failed controls are exactly what a launch would fail
    // on. Nothing is applied and no process is spawned.
    let warden = crate::warden::Warden::with_windows_mechanism(
        policy.clone(),
        args.windows_mechanism.unwrap_or_default(),
    );
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
            Some(sandbox_mechanism_detail(args.windows_mechanism)),
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
fn sandbox_mechanism_detail(mechanism: Option<crate::execution::WindowsNativeMechanism>) -> String {
    if cfg!(target_os = "linux") {
        "kernel Landlock + seccomp rulesets build successfully".to_string()
    } else if cfg!(target_os = "macos") {
        "SBPL profile builds; kernel acceptance is verified at launch".to_string()
    } else if cfg!(target_os = "windows") {
        match mechanism {
            Some(crate::execution::WindowsNativeMechanism::Psec) => {
                "PSEC policy-to-spec translation succeeds; the security \
                 environment itself is created at launch"
                    .to_string()
            }
            _ => "AppContainer grant intents compute successfully".to_string(),
        }
    } else {
        "no OS sandbox on this platform".to_string()
    }
}
