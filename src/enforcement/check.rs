//! `check` command contract: the machine-readable [`CheckReport`] a
//! policy drift check emits — status, per-pin outcomes, and unresolved
//! `// REVIEW` markers.

use crate::audit_log::PolicyAuditContext;
use crate::execution::ExecutionTarget;

/// Schema version of the JSON produced by [`CheckReport::to_json`].
pub const CHECK_REPORT_SCHEMA_VERSION: &str = "1";

/// Machine-readable outcome of a `check` run — paired with the fixed
/// exit code in [`CheckStatus::exit_code`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CheckStatus {
    /// The policy loaded and every declared integrity pin re-verified
    /// against the current artifacts; no unresolved `REVIEW` markers.
    Clean,
    /// At least one pin mismatched, was unreadable, or could not be
    /// re-verified, or unresolved `REVIEW` markers remain — the result
    /// names which.
    Drifted,
    /// The CLI input or the policy itself is invalid — the result names
    /// the fix location. Drift detection never ran on a policy that
    /// could not load.
    Invalid,
    /// The check itself failed (e.g. the report could not be saved).
    Error,
}

impl CheckStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Clean => "clean",
            Self::Drifted => "drifted",
            Self::Invalid => "invalid",
            Self::Error => "error",
        }
    }

    /// The exit code this status maps to: clean `0`, drifted `1`,
    /// invalid `2`, error `1` — the `plan` convention, so CI treats a
    /// drifted policy the same as a blocked launch. `drifted` and
    /// `error` share code `1` and are told apart by `status`/`reason`.
    pub fn exit_code(self) -> i32 {
        match self {
            Self::Clean => 0,
            Self::Drifted | Self::Error => 1,
            Self::Invalid => 2,
        }
    }
}

/// Outcome of re-verifying one integrity pin.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PinStatus {
    /// The current artifact's digest equals the pinned value.
    Verified,
    /// The pinned content no longer holds — the artifact was read and
    /// its digest differs, or (with `-- <command>`) the pin's `target=`
    /// fails the launch-binding correspondence `bind_launched_workload`
    /// enforces at `run`. Either way: drift.
    Mismatch,
    /// The artifact could not be read at all (missing file, engine
    /// answered "no such image").
    Unreadable,
    /// The pin could not be evaluated — `tools-list-hash` with no
    /// `-- <command>` to fetch from, `docker-manifest-hash` with no
    /// resolvable engine or an image carrying no repo digest, a
    /// tools-list fetch that failed. A pin that was not exercised is
    /// drift: the check cannot attest to the pinned state.
    Unverified,
}

impl PinStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Verified => "verified",
            Self::Mismatch => "mismatch",
            Self::Unreadable => "unreadable",
            Self::Unverified => "unverified",
        }
    }
}

/// One re-verified integrity pin in a [`CheckReport`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PinResult {
    /// Server identity the pin is bound to (`""` for an unbound
    /// single-server policy entry).
    pub server: String,
    /// `binary-hash` / `entrypoint-hash` / `lockfile-hash` /
    /// `docker-manifest-hash` / `tools-list-hash`.
    pub pin_type: &'static str,
    /// What was hashed: a file path, an image reference, or
    /// `"tools/list"`.
    pub target: String,
    pub status: PinStatus,
    /// The digest the policy pins (`sha256:…`).
    pub expected: String,
    /// The digest observed now — `None` unless the artifact was read.
    pub actual: Option<String>,
    /// I/O error, inspect failure, the binding rule a `-- <command>`
    /// launch argv made the pin fail, or the reason the pin went
    /// unverified.
    pub detail: Option<String>,
}

/// One unresolved `// REVIEW` comment found while loading the policy —
/// serialized from `policy::review::ReviewMarker` so `check` reports
/// drift in-band regardless of `MCP_WRIT_REVIEW_MODE`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReviewMarkerRecord {
    /// File the marker lives in (the entry file or an
    /// `extends`/`include` ancestor).
    pub file: String,
    /// 1-based line the marker's comment starts on.
    pub line: u32,
    /// The marker text (`REVIEW: …` / `REVIEW all entries …`).
    pub text: String,
}

/// The `check` command's machine-readable result.
///
/// `status` + `reason` are the machine contract; `pins`,
/// `review_markers`, `remediation`, and the human summary on stderr are
/// the detail. The JSON goes to stdout — or to `--report`, leaving
/// stdout untouched — matching `plan`.
#[derive(Debug, Clone)]
pub struct CheckReport {
    /// Always [`CHECK_REPORT_SCHEMA_VERSION`].
    pub schema_version: &'static str,
    pub created_at: String,
    pub status: CheckStatus,
    /// Stable reason code for non-clean results (`hash_mismatch`,
    /// `target_unreadable`, `pin_unverified`, `unresolved_review`,
    /// `policy_not_found`, `policy_invalid`, `invalid_input`,
    /// `report_write_failed`, ...).
    pub reason_code: Option<&'static str>,
    /// Detail string for `reason_code`.
    pub reason: Option<String>,
    /// The execution target the check ran for (native — `check`
    /// inspects host-visible artifacts).
    pub target: ExecutionTarget,
    /// Identity of the checked policy, when one loaded.
    pub policy: Option<PolicyAuditContext>,
    /// Per-pin re-verification outcomes — the `hash_entries` pins
    /// (`binary-hash` / `entrypoint-hash` / `lockfile-hash` /
    /// `docker-manifest-hash`) in policy order, then the
    /// `tools-list-hash` pins.
    pub pins: Vec<PinResult>,
    /// Unresolved `// REVIEW` markers from the loaded file set.
    pub review_markers: Vec<ReviewMarkerRecord>,
    /// Ordered human next-steps for non-clean results.
    pub remediation: Vec<String>,
}
