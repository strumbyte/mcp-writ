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

use crate::cli::PlanArgs;
use crate::enforcement::{PlanCheckStatus, PlanReport, PlanStatus};
use crate::execution::{ExecutionTarget, IsolationKind};

mod host;
mod image;
mod native;
mod report;
#[cfg(test)]
mod tests;

use host::{env_fail_on_check, host_os_check, wsb_store_check};
use image::diagnose_image;
use native::diagnose_native;
use report::{base_report, check, emit_and_exit, failing_check, finalize};

/// Run `plan` and exit the process with the status-mapped code.
pub async fn run_plan(args: PlanArgs) -> ! {
    let report_path = args.report.clone();
    let report = diagnose(args).await;
    emit_and_exit(&report, report_path.as_deref());
}

/// Diagnose the parsed `plan` arguments into a [`PlanReport`].
async fn diagnose(args: PlanArgs) -> PlanReport {
    // Parse/semantic errors are already a result: status invalid.
    if let Some(msg) = args.invalid_input {
        let mut report = base_report(ExecutionTarget::native());
        // Even an undiagnosed result names the host it was produced on —
        // every plan report carries the host.os record.
        report.checks.push(host_os_check().await);
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

    if args.isolation == Some(IsolationKind::WindowsSandbox) && args.image.is_none() {
        let mut report = base_report(crate::container::sandbox::target());
        report.checks.push(host_os_check().await);
        report.plan = Some(crate::container::sandbox::plan());
        let result = crate::container::sandbox::check_configuration(
            &args.sandbox,
            args.policy.as_deref(),
            args.server.as_deref(),
            &args.command,
        );
        match result {
            Ok(()) => report.checks.push(check("sandbox.payload", PlanCheckStatus::Pass, None)),
            Err(e) => report.checks.push(failing_check("sandbox.payload", e,
                "provide a Windows x86-64 payload, matching runner/relay, explicit policy and local state directory".into())),
        }
        // env.fail_on — `run --isolation windows-sandbox` resolves the
        // dial on the host (an invalid value refuses before the guest
        // spec is built) and forwards it into the sandbox, so the plan
        // reports the same env/default half native does.
        report.checks.push(env_fail_on_check());
        match crate::container::backends::windows_sandbox::prerequisites().await {
            Ok(_) => report.checks.push(check("isolation.backend", PlanCheckStatus::Pass, Some("interactive Windows Sandbox prerequisites available; guest controls checked at launch".into()))),
            Err(e) => report.checks.push(failing_check("isolation.backend", e,
                "enable Windows Sandbox and reboot; update the Store client; use an interactive Windows x86-64 session with no existing Sandbox".into())),
        }
        report.checks.push(wsb_store_check().await);
        return finalize(report);
    }
    match &args.image {
        Some(image) => diagnose_image(&args, image).await,
        None => diagnose_native(&args).await,
    }
}
