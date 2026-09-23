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
            )
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
}
