//! Shared leaf model for launch-time enforcement reporting.
//!
//! Three representations stay distinct by construction:
//!
//! - [`EnforcementPlan`] — the controls and permission entries a launch
//!   *intends* to enforce, generated from the same normalized rule data the
//!   sandbox builders consume.
//! - [`EnforcementObservation`] — what applying one control *observably*
//!   did, recorded by the Warden (spawn/prepare) or the runtime (session
//!   checks). A control that has no observation channel is reported
//!   [`ControlState::Unknown`], never guessed.
//! - [`LaunchReport`] — the assembled per-launch record (target, plan,
//!   observations, policy identity), serialized as JSON.
//! - [`EnforcementSummary`] — the structured digest of plan +
//!   observations written to the `enforcement` member of the
//!   `server.connected`/`server.error` JSONL audit records, so the audit
//!   stream alone states which mechanism enforced what.
//!
//! Process semantics: every entry in `plan.grants` is a *process-wide*
//! permission. Entries record which policy element contributed them
//! ([`GrantOrigin`]) so the report shows the provenance — but at kernel
//! level they apply to the whole spawned process, not to individual tools.
//! Per-tool restrictions live in the RPC layer (`plan.tools` and the
//! `rpc.*` controls), which is a separate enforcement surface.
//!
//! This is a leaf/value module: it must not depend on `policy`, `runtime`,
//! `warden`, or `container`. Conversions from `Policy` into these types are
//! owned by `warden::plan` / `runtime::launch`.

mod json;
mod model;
mod plan;
mod summary;

pub use model::{
    CodeIdentity, ControlLayer, ControlPhase, ControlState, EgressLayerStatus, EgressLayersPlan,
    EgressRuleReport, EnforcementObservation, EnforcementPlan, FsAccess, GrantOrigin, GrantSubject,
    GuestReportLink, GuestReportState, GuestRunnerIdentity, IdentityKind, IdentityPin,
    IsolationRecord, LAUNCH_REPORT_SCHEMA_VERSION, LaunchOutcome, LaunchReport, ObservationBasis,
    PinCheck, PinRole, PlannedControl, ProcessGrant, ToolDisposition,
};
pub use plan::{PLAN_REPORT_SCHEMA_VERSION, PlanCheck, PlanCheckStatus, PlanReport, PlanStatus};
pub use summary::{
    ControlOutcome, EnforcementSummary, GrantStateCounts, PSEC_SPEC_SCHEMA_VERSION, PsecSummary,
    SKIPPED_GRANT_SUMMARY_CAP, SandboxBackend,
};

/// Marker prefix `warden::plan::linux` writes into Landlock-backed
/// control observation reasons — `restrict_self reported <level>` —
/// followed by the kernel-reported `RulesetStatus` name. The summary
/// scanner reads the same prefix back: the wording is a producer/consumer
/// contract, so the constants below are the only spellings.
pub(crate) const RESTRICT_SELF_REPORTED: &str = "restrict_self reported ";

/// `RulesetStatus` level names as they appear after
/// [`RESTRICT_SELF_REPORTED`] in an observation reason.
pub(crate) const LANDLOCK_FULLY_ENFORCED: &str = "FullyEnforced";
pub(crate) const LANDLOCK_PARTIALLY_ENFORCED: &str = "PartiallyEnforced";
pub(crate) const LANDLOCK_NOT_ENFORCED: &str = "NotEnforced";

#[cfg(test)]
mod tests;
