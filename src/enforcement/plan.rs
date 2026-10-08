//! `plan` command diagnostics: the machine-readable [`PlanReport`]
//! result contract and its check vocabulary.

use crate::audit_log::PolicyAuditContext;
use crate::execution::ExecutionTarget;

use super::model::EnforcementPlan;

// ---------------------------------------------------------------------------
// `plan` diagnostics
// ---------------------------------------------------------------------------

/// Schema version of the JSON produced by [`PlanReport::to_json`].
pub const PLAN_REPORT_SCHEMA_VERSION: &str = "1";

/// Machine-readable outcome of a `plan` run — paired with the fixed exit
/// code in [`PlanStatus::exit_code`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PlanStatus {
    /// The plan computed and every inspected prerequisite passed. Actual
    /// control application stays unobserved until a real launch.
    Ready,
    /// A required prerequisite is missing, unsupported, or could not be
    /// confirmed — the result names what is missing.
    Blocked,
    /// The CLI input or the policy's syntax/semantics are invalid — the
    /// result names the fix location.
    Invalid,
    /// The diagnostic itself failed (e.g. the result could not be saved).
    Error,
}

impl PlanStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ready => "ready",
            Self::Blocked => "blocked",
            Self::Invalid => "invalid",
            Self::Error => "error",
        }
    }

    /// The exit code this status maps to: ready `0`, blocked `1`,
    /// invalid `2`, error `1`. `blocked` and `error` share code `1` and
    /// are told apart by `status`/`reason` in the result itself.
    pub fn exit_code(self) -> i32 {
        match self {
            Self::Ready => 0,
            Self::Blocked | Self::Error => 1,
            Self::Invalid => 2,
        }
    }
}

/// Outcome of one [`PlanCheck`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PlanCheckStatus {
    /// The inspected prerequisite was confirmed.
    Pass,
    /// Not blocking, but weakens what a launch would enforce or need
    /// (e.g. `MCP_WRIT_SKIP_SANDBOX` set, `allow_degraded` policy).
    Warn,
    /// A required prerequisite failed.
    Fail,
    /// The check does not apply to this target/policy.
    Skipped,
}

impl PlanCheckStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Warn => "warn",
            Self::Fail => "fail",
            Self::Skipped => "skipped",
        }
    }
}

/// One prerequisite check in a [`PlanReport`]: a stable `id`, its
/// outcome, an optional detail string, and the concrete next step the
/// user should take when it did not pass.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanCheck {
    /// Stable dotted identifier (`command.resolve`, `sandbox.mechanism`,
    /// `engine.resolve`, `image.inspect`, ...).
    pub id: &'static str,
    pub status: PlanCheckStatus,
    pub detail: Option<String>,
    /// Human remediation for warn/fail outcomes.
    pub remediation: Option<String>,
}

/// The `plan` command's machine-readable result.
///
/// `status` + `reason` are the machine contract; `remediation` and the
/// human summary on stderr are for the operator. `plan` carries the
/// computed [`EnforcementPlan`] in the same member shape as
/// [`LaunchReport::plan`](crate::enforcement::LaunchReport::plan) —
/// `None` when the inputs were too invalid to
/// compute one.
#[derive(Debug, Clone)]
pub struct PlanReport {
    /// Always [`PLAN_REPORT_SCHEMA_VERSION`].
    pub schema_version: &'static str,
    pub created_at: String,
    pub status: PlanStatus,
    /// Stable reason code for non-ready results (`command_not_found`,
    /// `engine_not_found`, `policy_invalid`, `sandbox_plan_failed`, ...).
    pub reason_code: Option<&'static str>,
    /// Detail string for `reason_code`.
    pub reason: Option<String>,
    /// The execution target the plan was computed for.
    pub target: ExecutionTarget,
    /// Identity of the bound policy, when one loaded.
    pub policy: Option<PolicyAuditContext>,
    /// Per-prerequisite diagnostic findings, in check order.
    pub checks: Vec<PlanCheck>,
    /// Ordered human next-steps for non-ready results.
    pub remediation: Vec<String>,
    /// The enforcement plan when it could be computed — the same shape
    /// [`LaunchReport::plan`](crate::enforcement::LaunchReport::plan)
    /// serializes to.
    pub plan: Option<EnforcementPlan>,
}
