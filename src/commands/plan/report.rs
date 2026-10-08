//! The [`PlanReport`] contract shared by every `plan` mode: check
//! builders, the policy-load check, finalization (status downgrade +
//! remediation collection), and the stdout/`--report` emission path.

use std::path::Path;

use crate::audit_log::now_iso8601_millis;
use crate::enforcement::{
    PLAN_REPORT_SCHEMA_VERSION, PlanCheck, PlanCheckStatus, PlanReport, PlanStatus,
};
use crate::error::PolicyError;
use crate::execution::ExecutionTarget;
use crate::policy::Policy;
use crate::policy::loader::load_policy_or_default_for_target;

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
pub(super) fn emit_and_exit(report: &PlanReport, report_path: Option<&Path>) -> ! {
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

pub(super) fn check(
    id: &'static str,
    status: PlanCheckStatus,
    detail: Option<String>,
) -> PlanCheck {
    PlanCheck {
        id,
        status,
        detail,
        remediation: None,
    }
}

pub(super) fn failing_check(id: &'static str, detail: String, remediation: String) -> PlanCheck {
    PlanCheck {
        id,
        status: PlanCheckStatus::Fail,
        detail: Some(detail),
        remediation: Some(remediation),
    }
}

pub(super) fn base_report(target: ExecutionTarget) -> PlanReport {
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

/// Finalize `report`: any `Fail` check downgrades `ready` to `blocked`,
/// sets `reason`/`reason_code` from the first failing check when unset,
/// and collects human remediation from every Fail/Warn check (warnings
/// are shown even for a `ready` result — optional features and omitted
/// controls stay visible in the summary).
pub(super) fn finalize(mut report: PlanReport) -> PlanReport {
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
pub(super) fn load_policy_check(
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
