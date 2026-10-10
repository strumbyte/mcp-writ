//! The launch-reporting data model: control/grant vocabulary, the
//! normalized [`EnforcementPlan`], and the assembled [`LaunchReport`].

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
// Two-layer egress model — the host-rule/CIDR-rule correspondence table
// ---------------------------------------------------------------------------

/// One outbound policy rule and the egress layer(s) it is evaluated at —
/// one row of the name-layer/IP-layer correspondence table in `plan`
/// and `--report` output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EgressRuleReport {
    /// `allow` or `deny`.
    pub effect: &'static str,
    /// `host` or `cidr` — the policy attribute the rule was declared
    /// with (`allow host=`, `allow cidr=`, ...).
    pub kind: &'static str,
    /// The normalized rule value as stored on the policy.
    pub rule: String,
    /// Evaluated at the name layer — a `host=` rule carries an FQDN or
    /// wildcard identity the DNS-gate name policy / Auditor hostname
    /// argument checks evaluate.
    pub name_layer: bool,
    /// Evaluated at the IP layer — `cidr=` rules, and `host=` entries
    /// that are IP literals: a literal needs no resolution, so it
    /// stands as a static IP-layer rule (`/32` or `/128`) as well.
    pub ip_layer: bool,
    /// The `proto=` qualifier (`"tcp"`/`"udp"`/`"any"`) — `None` means
    /// the declaration carried no transport scope (defaults `tcp` on
    /// allow rules; deny rules are always transport-blind).
    pub proto: Option<&'static str>,
    /// The `port=` qualifier — `None` means every destination port.
    pub port: Option<u16>,
}

/// Which surfaces evaluate one egress policy layer on the planned
/// path — where a layer that reaches nothing says so explicitly
/// instead of being implied effective.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EgressLayerStatus {
    /// `name` (FQDN rules) or `ip` (CIDR / literal-IP rules).
    pub layer: &'static str,
    /// RPC-surface enforcement of this layer — the Auditor's argument
    /// checks, present wherever MCP traffic is proxied.
    pub rpc: &'static str,
    /// OS-level mechanism evaluating this layer on the planned path.
    /// `None` means no mechanism here can reach the layer — `note`
    /// carries the honest reason (Landlock binds ports only,
    /// AppContainer capabilities are all-or-none, ...).
    pub os: Option<String>,
    /// Why the layer is not — or only partially — covered on this
    /// path.
    pub note: Option<String>,
}

/// The egress `default_action` plus the per-rule layer table.
/// `None` on `EnforcementPlan` where no policy was available to
/// evaluate (pre-plan failure reports, host-side container reports).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EgressLayersPlan {
    /// Posture for destinations with no matching rule:
    /// `deny_all` | `allow_all`.
    pub default_action: &'static str,
    /// The host-rule (name layer) / cidr-rule (IP layer)
    /// correspondence — every `allowed`, `allowed_cidrs`,
    /// `denied_hosts`, `denied_cidrs` entry once.
    pub rules: Vec<EgressRuleReport>,
    /// Per-layer disposition — one `name` and one `ip` entry.
    pub layers: Vec<EgressLayerStatus>,
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
    /// The two-layer egress correspondence table — which policy rules
    /// land on the name layer vs. the IP layer and which mechanisms
    /// evaluate each on this path. `None` where no policy was
    /// available to evaluate.
    pub egress_layers: Option<EgressLayersPlan>,
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

/// `LaunchReport.isolation` — the configured vs. observed isolation
/// boundary of the launch. `configured` is the request (`--isolation`
/// or the mode default); `verified` is what the backend confirmed it
/// applied — kept separate so a weakened boundary can never pass as
/// the requested one. `unit_id` correlates the launch (via
/// `launch_id`) with the substrate's own identifier (container id, VM
/// name). `None` on the report means no isolation backend was involved
/// (native run, guest-side report).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IsolationRecord {
    /// The isolation method the launch was configured with.
    pub configured: crate::execution::IsolationKind,
    /// The isolation the backend/engine confirmed for this launch;
    /// `None` until the backend's pre-launch check reports it.
    pub verified: Option<crate::execution::IsolationKind>,
    /// Granularity of the isolation unit the backend confirmed.
    pub unit: Option<crate::execution::IsolationUnit>,
    /// The substrate-assigned identifier of the concrete isolation
    /// unit (container id, VM name).
    pub unit_id: Option<String>,
    /// Free-form detail — runtime name, refusal reason, …
    pub detail: Option<String>,
}

/// The launch shape a [`CodeIdentity`] record describes — the
/// distinctions that keep "the workload is hash-bound" from reading as
/// "every byte of code it will run is fixed".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IdentityKind {
    /// A single file is the spawned image; `binary-hash` (or an
    /// `entrypoint-hash` on the same file) pins that image.
    NativeFile,
    /// An interpreter image plus a separate payload script —
    /// `binary-hash` pins the interpreter image, `entrypoint-hash` the
    /// script file.
    InterpretedScript,
    /// A launcher-, module-, or stdin-selected form (`env`, `sudo`,
    /// `py`, `npx`, `python -m`, a bare interpreter): the pinned image
    /// runs a workload selected at run time that no file pin binds.
    LauncherOrModule,
    /// Inline evaluation (`-c`, `-e`, `--eval`, …): the payload is an
    /// argv string, never a hash-bindable file; a policy with hash
    /// entries refuses the launch at binding.
    InlineEval,
    /// A container image named by a digest-pinned reference or bound by
    /// `docker-manifest-hash` — every file inside the image is in the
    /// pinned scope.
    ImageDigest,
    /// A mutable image tag accepted via `--allow-mutable-tag` — the
    /// inspected digest is recorded, but the tag may be re-pointed
    /// between inspect and run.
    ImageTag,
}

impl IdentityKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NativeFile => "native_file",
            Self::InterpretedScript => "interpreted_script",
            Self::LauncherOrModule => "launcher_or_module",
            Self::InlineEval => "inline_eval",
            Self::ImageDigest => "image_digest",
            Self::ImageTag => "image_tag",
        }
    }
}

/// Which part of a launch a hash entry's pin attaches to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PinRole {
    /// `binary-hash` — the spawned process image (the resolved
    /// `argv[0]`; for an interpreter launch that is the interpreter
    /// itself, not the script it runs).
    ExecImage,
    /// `entrypoint-hash` — a payload file (the script an interpreter
    /// runs; when it is also the exec'd file the roles coincide).
    PayloadFile,
    /// `lockfile-hash` — a dependency manifest's own content. It does
    /// not bind the launched process and does not verify the
    /// dependencies it names.
    DependencyList,
    /// `docker-manifest-hash` — a container image manifest digest.
    ImageManifest,
}

impl PinRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ExecImage => "exec_image",
            Self::PayloadFile => "payload_file",
            Self::DependencyList => "dependency_list",
            Self::ImageManifest => "image_manifest",
        }
    }
}

/// A point in the launch sequence where a pin's check ran and passed.
/// `pins[].checks` lists the points in launch order — a point absent
/// from the list did not run or did not pass, and `result` plus the
/// `launch.identity` observation name the failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PinCheck {
    /// The initial content check: the configured target's content
    /// matched its pinned digest.
    Initial,
    /// The binding pass confirmed the configured target canonicalizes
    /// to the launched executable or its first payload argument — a
    /// path correspondence, not a content check.
    BindPath,
    /// The binding pass also re-hashed the target's content — applies
    /// to the executable and to a payload-matched script.
    BindContent,
    /// The pre-spawn pass re-confirmed the path correspondence
    /// immediately before spawn.
    PreSpawnPath,
    /// The pre-spawn pass re-hashed the content. Nothing holds the file
    /// immutable between this last check and `exec` — that residual
    /// window is the launch's acknowledged hash-to-exec gap.
    PreSpawnContent,
    /// `run-image`/`plan` image check: the inspected image's manifest
    /// digest matched the pin.
    ImageInspect,
}

impl PinCheck {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Initial => "initial",
            Self::BindPath => "bind_path",
            Self::BindContent => "bind_content",
            Self::PreSpawnPath => "pre_spawn_path",
            Self::PreSpawnContent => "pre_spawn_content",
            Self::ImageInspect => "image_inspect",
        }
    }
}

/// One hash entry's pin as it applied to this launch — the configured
/// target, the part of the launch it attaches to, and the check points
/// it passed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityPin {
    /// Entry type as spelled in the policy (`binary-hash`, …).
    pub hash_type: &'static str,
    /// The configured `target=` spelling.
    pub target: String,
    /// The pinned digest (`sha256:…`).
    pub hash: String,
    /// What the entry pins in this launch shape.
    pub role: PinRole,
    /// Check points passed, in launch order (see [`PinCheck`]).
    pub checks: Vec<PinCheck>,
}

/// `LaunchReport.code_identity` — what the launch's hash pins actually
/// fixed: which part of the launch each pin attaches to, the points in
/// the launch sequence where each check ran, and what stays mutable
/// afterward. It deliberately keeps "hash-bound" from reading as "every
/// byte of code the workload will run is fixed".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodeIdentity {
    /// The launch shape the pins apply to.
    pub kind: IdentityKind,
    /// The resolved launch target — the canonical `argv[0]` path on a
    /// native launch, the image reference on a container launch.
    /// `None` when `argv[0]` never resolved.
    pub resolved: Option<String>,
    /// Per hash-entry pin records.
    pub pins: Vec<IdentityPin>,
    /// What the pins fix, stated as quotable facts (e.g. every file
    /// inside a digest-pinned image is in the pinned scope).
    pub pinned: Vec<String>,
    /// What stays changeable or unverified — the residual
    /// hash-to-`exec` window, unpinned runtime-loaded code, host
    /// mounts, mutable tags.
    pub mutable: Vec<String>,
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
    /// What the launch's hash pins actually fixed — launch shape,
    /// resolved target, per-entry check points, and what stays mutable
    /// afterward. `None` when the launch never reached identity
    /// assessment (e.g. a report written for a pre-policy failure).
    pub code_identity: Option<CodeIdentity>,
    /// Set only on a report *written by* `mcp-secure-runner` inside a
    /// container guest — the writer's identity self-declaration.
    /// `None` on host-side reports.
    pub guest_runner: Option<GuestRunnerIdentity>,
    /// Set only on a *host-side* container run report: the outcome of
    /// collecting the guest's own launch report. `None` on native and
    /// guest-side reports.
    pub guest: Option<GuestReportLink>,
    /// Set only on a host-side report whose launch went through an
    /// isolation backend: the configured vs. confirmed boundary and the
    /// unit identifier. `None` on native and guest-side reports.
    pub isolation: Option<IsolationRecord>,
}
