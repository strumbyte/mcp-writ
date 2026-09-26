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

use crate::audit_log::PolicyAuditContext;
use crate::execution::ExecutionTarget;
use uuid::Uuid;

/// Schema version of the JSON produced by [`LaunchReport::to_json`].
pub const LAUNCH_REPORT_SCHEMA_VERSION: &str = "1";

// ---------------------------------------------------------------------------
// Enumerations
// ---------------------------------------------------------------------------

/// Which enforcement surface a control or observation belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ControlLayer {
    /// OS-level control applied to the spawned process (kernel-enforced).
    Os,
    /// RPC-level control enforced by the proxy/auditor while forwarding
    /// MCP traffic (per-tool gating, overlays, server-origin checks).
    Rpc,
    /// Launch-time contract that is neither kernel nor RPC: environment
    /// restriction, hash verification, identity binding.
    Launch,
}

impl ControlLayer {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Os => "os",
            Self::Rpc => "rpc",
            Self::Launch => "launch",
        }
    }
}

/// Planned or observed state of one control or grant entry.
///
/// In `plan.controls` / `plan.grants` the state describes the *construction*
/// outcome (`Planned`, `Skipped`, `NotApplicable`, `NotApplied`, `Failed`).
/// In `observations` the same vocabulary describes the *apply* outcome
/// (`Verified`, `PartiallyApplied`, `Unknown`, `Failed`, `Skipped`,
/// `NotApplied`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ControlState {
    /// The launch intends to apply this; construction succeeded or is
    /// expected to succeed.
    Planned,
    /// The mechanism reported that the control was applied (e.g. a spawn
    /// that carries in-child apply hooks succeeded, an ACL write returned
    /// success, a verification ran to completion).
    Verified,
    /// Some intended elements applied while others could not.
    PartiallyApplied,
    /// The element was requested but the mechanism cannot express it
    /// (e.g. Landlock cannot grant TCP bind).
    NotApplied,
    /// Deliberately omitted (sandbox skip, optional check disabled).
    Skipped,
    /// The state cannot be observed; nothing was or could be confirmed.
    /// Never used to claim enforcement.
    Unknown,
    /// Applying or verifying the control returned an error.
    Failed,
    /// The mechanism is irrelevant to this target (e.g. a syscall
    /// allowlist control on macOS).
    NotApplicable,
}

impl ControlState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Planned => "planned",
            Self::Verified => "verified",
            Self::PartiallyApplied => "partially_applied",
            Self::NotApplied => "not_applied",
            Self::Skipped => "skipped",
            Self::Unknown => "unknown",
            Self::Failed => "failed",
            Self::NotApplicable => "not_applicable",
        }
    }
}

/// Where in the launch sequence an observation was taken.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ControlPhase {
    /// While building rules/artifacts, before spawn (e.g. policy hash
    /// verification, ruleset/profile construction).
    Build,
    /// At process-spawn time (pre-exec hooks, security attributes).
    Spawn,
    /// While the session runs (relay/auditor checks).
    Session,
}

impl ControlPhase {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Build => "build",
            Self::Spawn => "spawn",
            Self::Session => "session",
        }
    }
}

/// What evidence backs an observation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ObservationBasis {
    /// Placeholder for controls that have no observation channel; the
    /// state is `Unknown` (or a build-time decision such as `Skipped`).
    NotObserved,
    /// The apply mechanism itself returned a definitive result
    /// (`CreateProcessW` inside an AppContainer, an ACL write, `env` setup).
    MechanismResult,
    /// `spawn()` returning is the evidence that in-child apply hooks ran.
    SpawnResult,
    /// A dedicated verification ran to completion (hash check, ruleset or
    /// profile build, `tools/list` baseline).
    VerificationRun,
}

impl ObservationBasis {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NotObserved => "not_observed",
            Self::MechanismResult => "mechanism_result",
            Self::SpawnResult => "spawn_result",
            Self::VerificationRun => "verification_run",
        }
    }
}

/// Which policy element (or the runtime/OS implementation) contributed a
/// process-wide grant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GrantOrigin {
    /// A `defaults.*` rule (`fs.read_only`, `network.outbound.allowed`,
    /// `syscalls.allowed`, ...).
    Policy,
    /// An allowed tool's `allowed_paths`/`allowed_ports` — the grant is
    /// still process-wide; the tool name is provenance, not isolation.
    Tool(String),
    /// The launch itself needs it (the verified executable, a private
    /// temp dir, the startup `execve` syscall, ancestor traversal).
    Runtime,
    /// The OS sandbox implementation's fixed baseline (e.g. the SBPL
    /// fixed set: system libraries, devices, Mach services).
    OsImplementation,
}

impl GrantOrigin {
    /// Stable tag used in JSON.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Policy => "policy",
            Self::Tool(_) => "tool",
            Self::Runtime => "runtime",
            Self::OsImplementation => "os_implementation",
        }
    }
}

/// What a [`ProcessGrant`] entry grants. One rule of the mechanism may map
/// to one entry; the `kind` string is stable vocabulary for consumers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GrantSubject {
    /// A filesystem path (or glob/ancestor spelling) with an access class.
    FsPath { path: String, access: FsAccess },
    /// TCP connect permission. The mechanisms grant *ports*, not
    /// destinations — per-destination rules are RPC-layer enforcement.
    TcpConnect { port: u16 },
    /// An OS capability token (e.g. a Windows well-known capability).
    Capability { name: String },
    /// A syscall name in the seccomp allowlist.
    Syscall { name: String },
    /// The private temporary directory created for this launch.
    PrivateTmpdir,
    /// Any other mechanism-specific grant (`kind` names it; `name`
    /// carries the target: a Mach service name, a network scope, ...).
    Rule { kind: &'static str, name: String },
}

/// Access class on a [`GrantSubject::FsPath`] entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FsAccess {
    Read,
    ReadWrite,
    /// Metadata/traversal only (ancestor directories, directory listing
    /// without content access).
    Traverse,
}

impl FsAccess {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::ReadWrite => "read_write",
            Self::Traverse => "traverse",
        }
    }
}

// ---------------------------------------------------------------------------
// Plan entries
// ---------------------------------------------------------------------------

/// One enforcement control in the plan: a fixed-id capability of the
/// launch with the layer it belongs to and its construction state.
///
/// `id` is a stable, dotted identifier (`os.fs`, `rpc.tools`,
/// `launch.identity`, ...). `mechanism` names the enforcing mechanism
/// (`landlock`, `seccomp`, `sbpl`, `appcontainer`, `auditor`, ...).
/// `reason` carries skips, not-applicable decisions, qualifiers
/// (`allow_degraded`), and construction failures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedControl {
    pub id: &'static str,
    pub layer: ControlLayer,
    pub mechanism: &'static str,
    pub state: ControlState,
    pub reason: Option<String>,
}

/// One process-wide permission entry contributed to the spawned child.
///
/// The grant describes the *rule object* the sandbox builder produced —
/// never the child's full kernel permission set. `state` is the entry's
/// own disposition: `Planned` (added to the ruleset/profile being built),
/// `Skipped` (excluded during normalization, `reason` says why),
/// `Verified` (the apply call for this entry returned success), or
/// `Failed`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessGrant {
    pub subject: GrantSubject,
    pub origin: GrantOrigin,
    pub state: ControlState,
    pub reason: Option<String>,
}

/// One declared tool's disposition in the RPC layer. `allowed=false`
/// marks a denied tool; `side_effect`/`server` carry the policy labels
/// the auditor enforces. This is RPC-layer gating — it does not imply
/// kernel-level per-tool isolation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolDisposition {
    pub name: String,
    pub server: Option<String>,
    pub allowed: bool,
    pub side_effect: Option<String>,
}

// ---------------------------------------------------------------------------
// Aggregates
// ---------------------------------------------------------------------------

/// The normalized enforcement plan for one launch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnforcementPlan {
    /// Controls the launch intends to enforce, grouped by `layer`.
    pub controls: Vec<PlannedControl>,
    /// Process-wide permission entries the sandbox rules grant.
    pub grants: Vec<ProcessGrant>,
    /// Declared tools and their RPC-layer dispositions.
    pub tools: Vec<ToolDisposition>,
    /// Honest scope notes: process-wide grants, unenumerated ambient
    /// permissions, deny-rule enforcement, unobservable mechanisms.
    pub limitations: Vec<String>,
}

impl EnforcementPlan {
    /// The declared tool entries whose `allowed` flag is set.
    pub fn allowed_tools(&self) -> impl Iterator<Item = &ToolDisposition> {
        self.tools.iter().filter(|t| t.allowed)
    }
}

/// The observed outcome of applying one control — where it was taken and
/// on what evidence. Observations exist only for outcomes that required a
/// runtime check; construction-time decisions (`NotApplicable`,
/// `NotApplied`, `Skipped` at build) live entirely in the plan entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnforcementObservation {
    /// `id` of the [`PlannedControl`] this observation belongs to.
    pub control: &'static str,
    pub state: ControlState,
    pub basis: ObservationBasis,
    pub phase: ControlPhase,
    pub reason: Option<String>,
}

/// The final disposition of the launch a [`LaunchReport`] describes.
///
/// `status` is a stable vocabulary, never a guess:
///
/// - `"running"` — the report was written while the session was still up
///   (the launch-time write; `created_at` timestamps it).
/// - `"exited"` — the session ended (child exit or auditor finish);
///   `exit_code` is the observed code (a signal death reads `128 + sig`).
/// - `"failed"` — a launch, spawn, auditor, or wait failure aborted the
///   session; `detail` names the failed stage.
/// - `"interrupted"` — a termination signal ended the session
///   (`exit_code` 130/143 or the forwarded child's code).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LaunchOutcome {
    pub status: &'static str,
    pub detail: Option<String>,
    pub exit_code: Option<i32>,
}

/// Identity of the `mcp-secure-runner` that wrote a report inside a
/// container guest — the writer's self-declaration, matching the
/// capability marker compiled into the runner binary and recorded on the
/// image by `wrap-image`/`containerize`. Serialized on guest-written
/// reports as `"guest_runner"`.
#[derive(Debug, Clone, PartialEq)]
pub struct GuestRunnerIdentity {
    /// Crate version of the runner binary.
    pub version: String,
    /// Capability tokens the runner claims (e.g. `"guest-report-1"`).
    pub capabilities: Vec<String>,
}

/// How the transfer of the in-guest launch report ended for a container
/// run (`guest.state`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuestReportState {
    /// No `--report` was requested, so no guest report was collected.
    NotRequested,
    /// The image's runner does not claim the report capability.
    UnsupportedRunner,
    /// A well-formed guest report arrived via the dedicated channel.
    Received,
    /// The runner claimed the capability but no report file appeared.
    Missing,
    /// A file appeared but failed validation (id, version, format).
    Invalid,
}

impl GuestReportState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NotRequested => "not_requested",
            Self::UnsupportedRunner => "unsupported_runner",
            Self::Received => "received",
            Self::Missing => "missing",
            Self::Invalid => "invalid",
        }
    }
}

/// Host-side record of the guest report handoff for a container launch.
/// The embedded `report_json` is guest-self-reported data transported
/// through the dedicated mount — validated for transfer integrity
/// (launch id, runner identity, size, format) but never promoted to
/// host-independent proof of guest-side enforcement.
#[derive(Debug, Clone)]
pub struct GuestReportLink {
    pub state: GuestReportState,
    /// Why the state is not `Received` (or extra context when it is).
    pub detail: Option<String>,
    /// Runner identity declared on the image (capability marker env).
    pub runner: Option<GuestRunnerIdentity>,
    /// Verbatim validated report JSON written by the guest runner.
    pub report_json: Option<String>,
}

/// The assembled per-launch enforcement record. `launch_id` correlates
/// the plan, every observation, and the audit events emitted for the same
/// launch (`server.connected`, `server.error`).
#[derive(Debug, Clone)]
pub struct LaunchReport {
    /// Always [`LAUNCH_REPORT_SCHEMA_VERSION`].
    pub schema_version: &'static str,
    pub launch_id: Uuid,
    pub created_at: String,
    /// The execution target this launch ran on — host, substrate, and
    /// workload identities stay distinct.
    pub target: ExecutionTarget,
    /// Identity of the enforced (bound) policy: the bound server name (or
    /// `default` for a server-less policy), the declared policy version,
    /// and the hash of the effective `to_kdl` form.
    pub policy: Option<PolicyAuditContext>,
    pub dry_run: bool,
    pub plan: EnforcementPlan,
    pub observations: Vec<EnforcementObservation>,
    /// Final result of the launch; `None` only while the outcome has not
    /// been decided (a report built before the session's end is known).
    pub result: Option<LaunchOutcome>,
    /// Set only on a report *written by* `mcp-secure-runner` inside a
    /// container guest — the writer's identity self-declaration.
    /// `None` on host-side reports.
    pub guest_runner: Option<GuestRunnerIdentity>,
    /// Set only on a *host-side* container run report: the outcome of
    /// collecting the guest's own launch report. `None` on native and
    /// guest-side reports.
    pub guest: Option<GuestReportLink>,
}

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
/// [`LaunchReport::plan`] — `None` when the inputs were too invalid to
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
    /// [`LaunchReport::plan`] serializes to.
    pub plan: Option<EnforcementPlan>,
}

// ---------------------------------------------------------------------------
// JSON serialization (nojson — same style as audit_log.rs)
// ---------------------------------------------------------------------------

/// Outputs the JSON literal `null`.
struct JsonNull;

impl nojson::DisplayJson for JsonNull {
    fn fmt(&self, f: &mut nojson::JsonFormatter<'_, '_>) -> std::fmt::Result {
        write!(f.inner_mut(), "null")
    }
}

/// Emits already-validated JSON text verbatim. Used to embed the guest
/// report inside the host report without re-interpreting its content —
/// the caller must have parsed the text before reaching for this.
struct JsonRaw<'a>(&'a str);

impl nojson::DisplayJson for JsonRaw<'_> {
    fn fmt(&self, f: &mut nojson::JsonFormatter<'_, '_>) -> std::fmt::Result {
        write!(f.inner_mut(), "{}", self.0)
    }
}

fn write_runner_identity(
    f: &mut nojson::JsonObjectFormatter<'_, '_, '_>,
    r: &GuestRunnerIdentity,
) -> std::fmt::Result {
    f.member("version", r.version.as_str())?;
    f.member(
        "capabilities",
        nojson::array(|f| {
            for c in &r.capabilities {
                f.element(c.as_str())?;
            }
            Ok(())
        }),
    )
}

fn write_guest_link(
    f: &mut nojson::JsonObjectFormatter<'_, '_, '_>,
    g: &GuestReportLink,
) -> std::fmt::Result {
    f.member("state", g.state.as_str())?;
    match &g.detail {
        Some(d) => f.member("detail", d.as_str()),
        None => f.member("detail", JsonNull),
    }?;
    match &g.runner {
        Some(r) => f.member("runner", nojson::object(|f| write_runner_identity(f, r))),
        None => f.member("runner", JsonNull),
    }?;
    match &g.report_json {
        Some(j) => f.member("report", JsonRaw(j.as_str())),
        None => f.member("report", JsonNull),
    }
}

fn write_control(
    f: &mut nojson::JsonObjectFormatter<'_, '_, '_>,
    c: &PlannedControl,
) -> std::fmt::Result {
    f.member("id", c.id)?;
    f.member("layer", c.layer.as_str())?;
    f.member("mechanism", c.mechanism)?;
    f.member("state", c.state.as_str())?;
    match &c.reason {
        Some(r) => f.member("reason", r.as_str()),
        None => f.member("reason", JsonNull),
    }
}

fn write_subject(
    f: &mut nojson::JsonObjectFormatter<'_, '_, '_>,
    s: &GrantSubject,
) -> std::fmt::Result {
    match s {
        GrantSubject::FsPath { path, access } => {
            f.member("kind", "fs_path")?;
            f.member("path", path.as_str())?;
            f.member("access", access.as_str())
        }
        GrantSubject::TcpConnect { port } => {
            f.member("kind", "tcp_connect")?;
            f.member("port", *port)
        }
        GrantSubject::Capability { name } => {
            f.member("kind", "capability")?;
            f.member("name", name.as_str())
        }
        GrantSubject::Syscall { name } => {
            f.member("kind", "syscall")?;
            f.member("name", name.as_str())
        }
        GrantSubject::PrivateTmpdir => f.member("kind", "private_tmpdir"),
        GrantSubject::Rule { kind, name } => {
            f.member("kind", *kind)?;
            f.member("name", name.as_str())
        }
    }
}

fn write_grant(
    f: &mut nojson::JsonObjectFormatter<'_, '_, '_>,
    g: &ProcessGrant,
) -> std::fmt::Result {
    f.member("subject", nojson::object(|o| write_subject(o, &g.subject)))?;
    match &g.origin {
        GrantOrigin::Tool(name) => {
            f.member(
                "origin",
                nojson::object(|o| {
                    o.member("kind", "tool")?;
                    o.member("name", name.as_str())
                }),
            )?;
        }
        origin => f.member("origin", origin.kind())?,
    }
    f.member("state", g.state.as_str())?;
    match &g.reason {
        Some(r) => f.member("reason", r.as_str()),
        None => f.member("reason", JsonNull),
    }
}

fn write_tool(
    f: &mut nojson::JsonObjectFormatter<'_, '_, '_>,
    t: &ToolDisposition,
) -> std::fmt::Result {
    f.member("name", t.name.as_str())?;
    match &t.server {
        Some(s) => f.member("server", s.as_str()),
        None => f.member("server", JsonNull),
    }?;
    f.member("allowed", t.allowed)?;
    match &t.side_effect {
        Some(s) => f.member("side_effect", s.as_str()),
        None => f.member("side_effect", JsonNull),
    }
}

fn write_observation(
    f: &mut nojson::JsonObjectFormatter<'_, '_, '_>,
    o: &EnforcementObservation,
) -> std::fmt::Result {
    f.member("control", o.control)?;
    f.member("state", o.state.as_str())?;
    f.member("basis", o.basis.as_str())?;
    f.member("phase", o.phase.as_str())?;
    match &o.reason {
        Some(r) => f.member("reason", r.as_str()),
        None => f.member("reason", JsonNull),
    }
}

impl EnforcementPlan {
    fn write_json(&self, f: &mut nojson::JsonObjectFormatter<'_, '_, '_>) -> std::fmt::Result {
        f.member(
            "controls",
            nojson::array(|f| {
                for c in &self.controls {
                    f.element(nojson::object(|o| write_control(o, c)))?;
                }
                Ok(())
            }),
        )?;
        f.member(
            "grants",
            nojson::array(|f| {
                for g in &self.grants {
                    f.element(nojson::object(|o| write_grant(o, g)))?;
                }
                Ok(())
            }),
        )?;
        f.member(
            "tools",
            nojson::array(|f| {
                for t in &self.tools {
                    f.element(nojson::object(|o| write_tool(o, t)))?;
                }
                Ok(())
            }),
        )?;
        f.member(
            "limitations",
            nojson::array(|f| {
                for l in &self.limitations {
                    f.element(l.as_str())?;
                }
                Ok(())
            }),
        )
    }
}

impl LaunchReport {
    /// Serialize the report as one JSON object (schema version
    /// [`LAUNCH_REPORT_SCHEMA_VERSION`]).
    pub fn to_json(&self) -> String {
        let report = self;
        let launch_id = report.launch_id.to_string();
        nojson::object(|f| {
            f.member("schema_version", report.schema_version)?;
            f.member("launch_id", launch_id.as_str())?;
            f.member("created_at", report.created_at.as_str())?;
            f.member(
                "target",
                nojson::object(|f| {
                    f.member("host_os", report.target.host_os.name())?;
                    f.member("substrate_os", report.target.substrate_os.name())?;
                    f.member("workload_os", report.target.workload_os.name())?;
                    f.member("workload_arch", report.target.workload_arch.name())?;
                    f.member("substrate", report.target.substrate.name())?;
                    match report.target.engine {
                        Some(engine) => f.member("engine", engine.name()),
                        None => f.member("engine", JsonNull),
                    }
                }),
            )?;
            match &report.policy {
                Some(p) => f.member(
                    "policy",
                    nojson::object(|f| {
                        f.member("id", p.id.as_str())?;
                        f.member("version", p.version.as_str())?;
                        f.member("hash", p.hash.as_str())
                    }),
                )?,
                None => f.member("policy", JsonNull)?,
            }
            f.member("dry_run", report.dry_run)?;
            f.member("plan", nojson::object(|f| report.plan.write_json(f)))?;
            f.member(
                "observations",
                nojson::array(|f| {
                    for o in &report.observations {
                        f.element(nojson::object(|o2| write_observation(o2, o)))?;
                    }
                    Ok(())
                }),
            )?;
            match &report.result {
                Some(r) => f.member(
                    "result",
                    nojson::object(|f| {
                        f.member("status", r.status)?;
                        match &r.detail {
                            Some(d) => f.member("detail", d.as_str()),
                            None => f.member("detail", JsonNull),
                        }?;
                        match r.exit_code {
                            Some(c) => f.member("exit_code", c),
                            None => f.member("exit_code", JsonNull),
                        }
                    }),
                ),
                None => f.member("result", JsonNull),
            }?;
            match &report.guest_runner {
                Some(r) => f.member(
                    "guest_runner",
                    nojson::object(|f| write_runner_identity(f, r)),
                ),
                None => f.member("guest_runner", JsonNull),
            }?;
            match &report.guest {
                Some(g) => f.member("guest", nojson::object(|f| write_guest_link(f, g))),
                None => f.member("guest", JsonNull),
            }
        })
        .to_string()
    }

    /// Serialize and write to `path`, replacing an existing file.
    ///
    /// `--report` semantics: every launch attempt overwrites the report
    /// path — the file always describes the most recent launch. The
    /// caller decides the exit code; a write error is never success.
    pub fn write_to(&self, path: &std::path::Path) -> std::io::Result<()> {
        std::fs::write(path, self.to_json())
    }
}

fn write_check(f: &mut nojson::JsonObjectFormatter<'_, '_, '_>, c: &PlanCheck) -> std::fmt::Result {
    f.member("id", c.id)?;
    f.member("status", c.status.as_str())?;
    match &c.detail {
        Some(d) => f.member("detail", d.as_str()),
        None => f.member("detail", JsonNull),
    }?;
    match &c.remediation {
        Some(r) => f.member("remediation", r.as_str()),
        None => f.member("remediation", JsonNull),
    }
}

impl PlanReport {
    /// Serialize the plan result as one JSON object (schema version
    /// [`PLAN_REPORT_SCHEMA_VERSION`]). `reason` serializes as
    /// `{code, detail}` — both parts stay machine-readable.
    pub fn to_json(&self) -> String {
        let report = self;
        nojson::object(|f| {
            f.member("schema_version", report.schema_version)?;
            f.member("created_at", report.created_at.as_str())?;
            f.member("status", report.status.as_str())?;
            match (&report.reason_code, &report.reason) {
                (Some(code), detail) => f.member(
                    "reason",
                    nojson::object(|f| {
                        f.member("code", *code)?;
                        match detail {
                            Some(d) => f.member("detail", d.as_str()),
                            None => f.member("detail", JsonNull),
                        }
                    }),
                ),
                _ => f.member("reason", JsonNull),
            }?;
            f.member(
                "target",
                nojson::object(|f| {
                    f.member("host_os", report.target.host_os.name())?;
                    f.member("substrate_os", report.target.substrate_os.name())?;
                    f.member("workload_os", report.target.workload_os.name())?;
                    f.member("workload_arch", report.target.workload_arch.name())?;
                    f.member("substrate", report.target.substrate.name())?;
                    match report.target.engine {
                        Some(engine) => f.member("engine", engine.name()),
                        None => f.member("engine", JsonNull),
                    }
                }),
            )?;
            match &report.policy {
                Some(p) => f.member(
                    "policy",
                    nojson::object(|f| {
                        f.member("id", p.id.as_str())?;
                        f.member("version", p.version.as_str())?;
                        f.member("hash", p.hash.as_str())
                    }),
                )?,
                None => f.member("policy", JsonNull)?,
            }
            f.member(
                "checks",
                nojson::array(|f| {
                    for c in &report.checks {
                        f.element(nojson::object(|o| write_check(o, c)))?;
                    }
                    Ok(())
                }),
            )?;
            f.member(
                "remediation",
                nojson::array(|f| {
                    for r in &report.remediation {
                        f.element(r.as_str())?;
                    }
                    Ok(())
                }),
            )?;
            match &report.plan {
                Some(p) => f.member("plan", nojson::object(|f| p.write_json(f))),
                None => f.member("plan", JsonNull),
            }
        })
        .to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::execution::{ExecutionSubstrate, TargetArch, TargetOs};

    fn sample_report() -> LaunchReport {
        LaunchReport {
            schema_version: LAUNCH_REPORT_SCHEMA_VERSION,
            launch_id: Uuid::nil(),
            created_at: "2026-01-01T00:00:00.000Z".to_string(),
            target: ExecutionTarget {
                host_os: TargetOs::Windows,
                substrate_os: TargetOs::Linux,
                workload_os: TargetOs::Linux,
                workload_arch: TargetArch::Aarch64,
                substrate: ExecutionSubstrate::Container,
                engine: Some(crate::execution::EngineName::Docker),
            },
            policy: Some(PolicyAuditContext {
                id: "policy.kdl".to_string(),
                version: "1".to_string(),
                hash: "sha256:abc".to_string(),
            }),
            dry_run: false,
            plan: EnforcementPlan {
                controls: vec![
                    PlannedControl {
                        id: "os.fs",
                        layer: ControlLayer::Os,
                        mechanism: "landlock",
                        state: ControlState::Planned,
                        reason: None,
                    },
                    PlannedControl {
                        id: "rpc.tools",
                        layer: ControlLayer::Rpc,
                        mechanism: "auditor",
                        state: ControlState::Planned,
                        reason: None,
                    },
                ],
                grants: vec![
                    ProcessGrant {
                        subject: GrantSubject::FsPath {
                            path: "/data".to_string(),
                            access: FsAccess::Read,
                        },
                        origin: GrantOrigin::Policy,
                        state: ControlState::Planned,
                        reason: None,
                    },
                    ProcessGrant {
                        subject: GrantSubject::FsPath {
                            path: "/tool/x".to_string(),
                            access: FsAccess::ReadWrite,
                        },
                        origin: GrantOrigin::Tool("read_files".to_string()),
                        state: ControlState::Skipped,
                        reason: Some("path does not exist".to_string()),
                    },
                ],
                tools: vec![
                    ToolDisposition {
                        name: "read_files".to_string(),
                        server: Some("fs".to_string()),
                        allowed: true,
                        side_effect: Some("low".to_string()),
                    },
                    ToolDisposition {
                        name: "delete_all".to_string(),
                        server: Some("fs".to_string()),
                        allowed: false,
                        side_effect: Some("high".to_string()),
                    },
                ],
                limitations: vec!["grants are process-wide".to_string()],
            },
            observations: vec![EnforcementObservation {
                control: "os.fs",
                state: ControlState::Verified,
                basis: ObservationBasis::SpawnResult,
                phase: ControlPhase::Spawn,
                reason: None,
            }],
            result: Some(LaunchOutcome {
                status: "exited",
                detail: Some("MCP server exited".to_string()),
                exit_code: Some(0),
            }),
            guest_runner: None,
            guest: None,
        }
    }

    #[test]
    fn control_states_have_distinct_strings() {
        let states = [
            ControlState::Planned,
            ControlState::Verified,
            ControlState::PartiallyApplied,
            ControlState::NotApplied,
            ControlState::Skipped,
            ControlState::Unknown,
            ControlState::Failed,
            ControlState::NotApplicable,
        ];
        let mut seen = std::collections::HashSet::new();
        for s in states {
            assert!(seen.insert(s.as_str()), "duplicate as_str: {}", s.as_str());
        }
        // The states that must not be conflated serialize distinctly.
        assert_ne!(
            ControlState::Planned.as_str(),
            ControlState::Verified.as_str()
        );
        assert_ne!(
            ControlState::Verified.as_str(),
            ControlState::Unknown.as_str()
        );
        assert_ne!(
            ControlState::Skipped.as_str(),
            ControlState::Failed.as_str()
        );
        assert_ne!(
            ControlState::PartiallyApplied.as_str(),
            ControlState::Failed.as_str()
        );
    }

    #[test]
    fn layers_phases_bases_have_distinct_strings() {
        for (a, b) in [
            (ControlLayer::Os, ControlLayer::Rpc),
            (ControlLayer::Os, ControlLayer::Launch),
            (ControlLayer::Rpc, ControlLayer::Launch),
        ] {
            assert_ne!(a.as_str(), b.as_str());
        }
        assert_eq!(ControlPhase::Build.as_str(), "build");
        assert_eq!(ControlPhase::Spawn.as_str(), "spawn");
        assert_eq!(ControlPhase::Session.as_str(), "session");
        assert_eq!(ObservationBasis::NotObserved.as_str(), "not_observed");
        assert_ne!(
            ObservationBasis::MechanismResult.as_str(),
            ObservationBasis::SpawnResult.as_str()
        );
    }

    fn member<'text, 'raw>(
        v: nojson::RawJsonValue<'text, 'raw>,
        name: &str,
    ) -> nojson::RawJsonValue<'text, 'raw> {
        v.to_member(name).unwrap().required().unwrap()
    }

    #[test]
    fn launch_report_serializes_all_sections() {
        let json = sample_report().to_json();
        let parsed = nojson::RawJson::parse(&json).expect("valid json");
        let root = parsed.value();
        assert_eq!(member(root, "schema_version").as_string_str().unwrap(), "1");
        assert_eq!(
            member(root, "launch_id").as_string_str().unwrap(),
            Uuid::nil().to_string()
        );
        // Target keeps host/substrate/workload distinct.
        let target = member(root, "target");
        assert_eq!(
            member(target, "host_os").as_string_str().unwrap(),
            "windows"
        );
        assert_eq!(
            member(target, "substrate_os").as_string_str().unwrap(),
            "linux"
        );
        assert_eq!(
            member(target, "workload_os").as_string_str().unwrap(),
            "linux"
        );
        assert_eq!(
            member(target, "workload_arch").as_string_str().unwrap(),
            "aarch64"
        );
        assert_eq!(
            member(target, "substrate").as_string_str().unwrap(),
            "container"
        );
        assert_eq!(member(target, "engine").as_string_str().unwrap(), "docker");
        // Plan sections.
        let plan = member(root, "plan");
        assert_eq!(member(plan, "controls").to_array().unwrap().count(), 2);
        assert_eq!(member(plan, "grants").to_array().unwrap().count(), 2);
        assert_eq!(member(plan, "tools").to_array().unwrap().count(), 2);
        // Observations reference controls by id.
        let obs = member(root, "observations");
        let first = obs.to_array().unwrap().next().unwrap();
        assert_eq!(member(first, "control").as_string_str().unwrap(), "os.fs");
        assert_eq!(member(first, "state").as_string_str().unwrap(), "verified");
        // Final result is part of the same schema.
        let result = member(root, "result");
        assert_eq!(member(result, "status").as_string_str().unwrap(), "exited");
        assert_eq!(member(result, "exit_code").as_integer_str().unwrap(), "0");
    }

    #[test]
    fn plan_report_serializes_status_reason_and_plan() {
        let report = PlanReport {
            schema_version: PLAN_REPORT_SCHEMA_VERSION,
            created_at: "2026-01-01T00:00:00.000Z".to_string(),
            status: PlanStatus::Blocked,
            reason_code: Some("command_not_found"),
            reason: Some("cannot resolve 'missing-cmd'".to_string()),
            target: ExecutionTarget::native(),
            policy: None,
            checks: vec![PlanCheck {
                id: "command.resolve",
                status: PlanCheckStatus::Fail,
                detail: Some("command 'missing-cmd' not found on PATH".to_string()),
                remediation: Some("install it or pass an absolute path".to_string()),
            }],
            remediation: vec!["install 'missing-cmd' or pass an absolute path".to_string()],
            plan: None,
        };
        let json = report.to_json();
        let parsed = nojson::RawJson::parse(&json).expect("valid json");
        let root = parsed.value();
        assert_eq!(member(root, "schema_version").as_string_str().unwrap(), "1");
        assert_eq!(member(root, "status").as_string_str().unwrap(), "blocked");
        let reason = member(root, "reason");
        assert_eq!(
            member(reason, "code").as_string_str().unwrap(),
            "command_not_found"
        );
        let checks = member(root, "checks");
        let first = checks.to_array().unwrap().next().unwrap();
        assert_eq!(member(first, "status").as_string_str().unwrap(), "fail");
        assert_eq!(member(root, "plan").as_string_str().ok(), None);
    }

    #[test]
    fn plan_status_exit_codes_match_the_contract() {
        assert_eq!(PlanStatus::Ready.exit_code(), 0);
        assert_eq!(PlanStatus::Blocked.exit_code(), 1);
        assert_eq!(PlanStatus::Invalid.exit_code(), 2);
        assert_eq!(PlanStatus::Error.exit_code(), 1);
        assert_eq!(PlanStatus::Ready.as_str(), "ready");
        assert_eq!(PlanStatus::Blocked.as_str(), "blocked");
        assert_eq!(PlanStatus::Invalid.as_str(), "invalid");
        assert_eq!(PlanStatus::Error.as_str(), "error");
    }

    #[test]
    fn grant_origin_tool_serializes_with_name() {
        let json = sample_report().to_json();
        assert!(json.contains(r#""origin":{"kind":"tool","name":"read_files"}"#));
        assert!(json.contains(r#""origin":"policy""#));
    }

    #[test]
    fn allowed_tools_filters_denied() {
        let report = sample_report();
        let names: Vec<_> = report
            .plan
            .allowed_tools()
            .map(|t| t.name.as_str())
            .collect();
        assert_eq!(names, ["read_files"]);
    }

    #[test]
    fn guest_runner_identity_serializes_on_guest_report() {
        // The runner's own report carries its identity as `guest_runner`;
        // `guest` stays null — that member is the host-side link only.
        let mut report = sample_report();
        report.guest_runner = Some(GuestRunnerIdentity {
            version: "0.5.0".to_string(),
            capabilities: vec!["guest-report-1".to_string()],
        });
        let json = report.to_json();
        let parsed = nojson::RawJson::parse(&json).expect("valid json");
        let root = parsed.value();
        let runner = member(root, "guest_runner");
        assert_eq!(member(runner, "version").as_string_str().unwrap(), "0.5.0");
        let caps = member(runner, "capabilities");
        assert_eq!(
            caps.to_array()
                .unwrap()
                .next()
                .unwrap()
                .as_string_str()
                .unwrap(),
            "guest-report-1"
        );
        assert!(
            root.to_member("guest")
                .unwrap()
                .required()
                .unwrap()
                .kind()
                .is_null()
        );
    }

    #[test]
    fn guest_link_serializes_state_runner_and_embedded_report() {
        // The host report's `guest` member carries the handoff outcome:
        // the declared runner identity plus the verbatim guest report as
        // an embedded JSON object (not a string).
        let mut report = sample_report();
        let inner = r#"{"schema_version":"1","launch_id":"00000000-0000-0000-0000-000000000000","guest_runner":{"version":"0.5.0","capabilities":["guest-report-1"]}}"#;
        report.guest = Some(GuestReportLink {
            state: GuestReportState::Received,
            detail: None,
            runner: Some(GuestRunnerIdentity {
                version: "0.5.0".to_string(),
                capabilities: vec!["guest-report-1".to_string()],
            }),
            report_json: Some(inner.to_string()),
        });
        let json = report.to_json();
        let parsed = nojson::RawJson::parse(&json).expect("valid json");
        let root = parsed.value();
        let guest = member(root, "guest");
        assert_eq!(member(guest, "state").as_string_str().unwrap(), "received");
        let runner = member(guest, "runner");
        assert_eq!(member(runner, "version").as_string_str().unwrap(), "0.5.0");
        let embedded = member(guest, "report");
        assert_eq!(embedded.kind(), nojson::JsonValueKind::Object);
        assert_eq!(
            member(embedded, "schema_version").as_string_str().unwrap(),
            "1"
        );
    }

    #[test]
    fn guest_report_states_serialize_distinctly() {
        assert_eq!(GuestReportState::NotRequested.as_str(), "not_requested");
        assert_eq!(
            GuestReportState::UnsupportedRunner.as_str(),
            "unsupported_runner"
        );
        assert_eq!(GuestReportState::Received.as_str(), "received");
        assert_eq!(GuestReportState::Missing.as_str(), "missing");
        assert_eq!(GuestReportState::Invalid.as_str(), "invalid");
    }
}
