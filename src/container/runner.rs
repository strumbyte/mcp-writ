use std::path::PathBuf;

use crate::container::backends::{self, LaunchSpec, ShareMount};
use crate::container::engine::resolve_engine;
use crate::container::guest_report::{self, GuestReportRead};
use crate::container::options::RunImageOptions;
use crate::container::policy_export::{self, PolicyBindError};
use crate::enforcement::{
    ControlLayer, ControlPhase, ControlState, EnforcementObservation, EnforcementPlan,
    GuestReportLink, GuestReportState, GuestRunnerIdentity, IsolationRecord,
    LAUNCH_REPORT_SCHEMA_VERSION, LaunchOutcome, LaunchReport, ObservationBasis, PlannedControl,
    ToolDisposition,
};
use crate::execution::{ExecutionTarget, IsolationKind, TargetOs};

/// True when the image reference is pinned to an immutable digest.
pub fn image_ref_is_digest_pinned(image: &str) -> bool {
    image.contains("@sha256:")
}

/// Private temp dir carrying every host-side handoff artifact for one
/// launch — the exported policy, the guest report mount, and the
/// container id file. `Drop` removes the whole tree on every path.
struct TempLaunchDir {
    dir: PathBuf,
}

impl TempLaunchDir {
    fn new() -> Result<Self, std::io::Error> {
        let dir = crate::fspriv::create_private_tempdir("run-launch")?;
        Ok(Self { dir })
    }

    fn policy_path(&self) -> PathBuf {
        self.dir.join("policy.kdl")
    }

    /// Mount point source for the guest report channel (created on
    /// demand — only when the runner can produce a report).
    fn report_dir(&self) -> PathBuf {
        self.dir.join("report")
    }

    /// File the engine records the container id in (`--cidfile`), used
    /// to remove the container when the launch is interrupted.
    fn cid_path(&self) -> PathBuf {
        self.dir.join("container.id")
    }
}

impl Drop for TempLaunchDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// Host-side record of a `run-image` launch: the launch-layer controls
/// the host sets up, the observations it can honestly take, the bound
/// policy's tool table (enforced in the guest), and the guest report
/// handoff outcome.
struct HostRunRec {
    launch_id: uuid::Uuid,
    target: ExecutionTarget,
    policy: Option<crate::audit_log::PolicyAuditContext>,
    controls: Vec<PlannedControl>,
    tools: Vec<ToolDisposition>,
    observations: Vec<EnforcementObservation>,
    /// The stage currently in flight — named in the failed result.
    stage: &'static str,
    /// Runner identity declared on the image's capability marker env.
    guest_runner: Option<GuestRunnerIdentity>,
    guest_state: GuestReportState,
    guest_detail: Option<String>,
    /// Verbatim validated guest report JSON.
    guest_report_json: Option<String>,
    /// Set when SIGINT ended the wait — reported as `interrupted`.
    interrupted: bool,
    /// What the launch's hash pins bound — the image identity record is
    /// assembled at the image-reference stage and completed once the
    /// bound policy's `docker-manifest-hash` pins are known.
    identity: Option<crate::enforcement::CodeIdentity>,
    /// The configured vs. backend-confirmed isolation boundary — kept
    /// distinct from the engine record and the guest report so the
    /// report shows the request, the applied boundary, and the guest's
    /// own claims as separate facts.
    isolation: IsolationRecord,
}

impl HostRunRec {
    fn new(engine_name: Option<crate::execution::EngineName>, isolation: IsolationKind) -> Self {
        let launch_control = |id: &'static str| PlannedControl {
            id,
            layer: ControlLayer::Launch,
            mechanism: "container launch",
            state: ControlState::Planned,
            reason: None,
        };
        let mut target = ExecutionTarget::linux_container(engine_name, None);
        // Substrate and workload OS follow the isolation method — the
        // same contract `plan --image`'s `image_target` records (a
        // Windows-scoped method is not the Linux container contract);
        // the image metadata re-stamps the OS once it is inspected.
        target.substrate = isolation.substrate();
        target.workload_os = isolation.guest_os();
        if !backends::engine_backed(isolation) {
            // A substrate not driven through a container engine records
            // no engine identity (same contract `plan --image` uses).
            target.engine = None;
        }
        Self {
            launch_id: uuid::Uuid::now_v7(),
            target,
            policy: None,
            controls: vec![
                PlannedControl {
                    id: "launch.isolation",
                    layer: ControlLayer::Launch,
                    mechanism: "isolation backend",
                    state: ControlState::Planned,
                    reason: Some(
                        "the workload boundary the launch is confined to; \
                         --isolation selects it, the backend confirms it"
                            .to_string(),
                    ),
                },
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
            ],
            tools: Vec::new(),
            observations: Vec::new(),
            stage: "startup",
            guest_runner: None,
            guest_state: GuestReportState::NotRequested,
            guest_detail: None,
            guest_report_json: None,
            interrupted: false,
            identity: None,
            isolation: IsolationRecord {
                configured: isolation,
                verified: None,
                unit: None,
                unit_id: None,
                detail: None,
            },
        }
    }

    fn observe(
        &mut self,
        control: &'static str,
        state: ControlState,
        basis: ObservationBasis,
        phase: ControlPhase,
        reason: Option<String>,
    ) {
        if state == ControlState::Failed {
            for c in self.controls.iter_mut() {
                if c.id == control {
                    c.state = ControlState::Failed;
                    c.reason = reason.clone();
                }
            }
        }
        self.observations.push(EnforcementObservation {
            control,
            state,
            basis,
            phase,
            reason,
        });
    }

    /// Assemble the final report — plan, host observations, and the
    /// session result in the same schema a native `run --report` emits.
    fn into_report(self, outcome: LaunchOutcome) -> LaunchReport {
        LaunchReport {
            schema_version: LAUNCH_REPORT_SCHEMA_VERSION,
            launch_id: self.launch_id,
            created_at: crate::audit_log::now_iso8601_millis(),
            target: self.target,
            policy: self.policy,
            dry_run: false,
            plan: EnforcementPlan {
                controls: self.controls,
                grants: Vec::new(),
                tools: self.tools,
                limitations: vec![
                    "host-side launch report: guest-side grants and sandbox \
                     observations are produced by mcp-secure-runner inside the \
                     guest (a container, or a VM under --isolation kata); \
                     rpc.guest stays unobserved from the host"
                        .to_string(),
                ],
            },
            observations: self.observations,
            result: Some(outcome),
            code_identity: self.identity,
            // The host writes this report — `guest_runner` stays empty;
            // the guest's own writer identity lives inside the attached
            // guest report.
            guest_runner: None,
            guest: Some(GuestReportLink {
                state: self.guest_state,
                detail: self.guest_detail,
                runner: self.guest_runner,
                report_json: self.guest_report_json,
            }),
            isolation: Some(self.isolation),
        }
    }
}

/// Run a container image with policy and log volume mounts.
///
/// The launch goes through the isolation-backend contract
/// ([`crate::container::backends`]): the `--isolation` method resolves to
/// a backend — `container` (default) is the OCI engine path, `kata` the
/// engine-driven Kata VM boundary — which confirms the spec, spawns the
/// workload, and hands its handle to the shared session driver that
/// relays stdin/stdout between the host and the workload. On workload
/// exit, the process exits with its exit code.
///
/// With `options.report` set, a host-side [`LaunchReport`] is written at
/// every outcome — including failures — in the same schema `run --report`
/// uses. A report that cannot be written makes the run fail: an
/// explicitly requested report never exits successfully without it.
pub async fn run_image(options: &RunImageOptions) -> Result<(), Box<dyn std::error::Error>> {
    // Validate the report destination before any engine/daemon work: an
    // explicitly requested report that cannot be saved must never end
    // successfully, and must not surface only after the container ran.
    // The file is created/truncated up front — the same rule `run`
    // applies — so a crashed launch never leaves a stale success report
    // behind to be misread as the latest outcome.
    if let Some(path) = &options.report
        && let Err(e) = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)
    {
        return Err(format!("cannot write launch report to '{}': {e}", path.display()).into());
    }

    // The isolation method is selected separately from the engine —
    // `container` (default) is the existing OCI path; a method no
    // backend implements is refused inside the run, never aliased to a
    // normal container or a native run.
    let isolation = options.isolation.unwrap_or(IsolationKind::Container);
    let mut rec = HostRunRec::new(
        options.engine.map(crate::execution::EngineName::from),
        isolation,
    );
    let outcome = run_image_inner(options, &mut rec).await;

    let outcome = match outcome {
        Ok(code) => LaunchOutcome {
            status: "exited",
            detail: None,
            exit_code: Some(code),
        },
        Err(e) if rec.interrupted => LaunchOutcome {
            status: "interrupted",
            detail: Some(format!("{}: {e}", rec.stage)),
            exit_code: Some(130),
        },
        Err(e) => LaunchOutcome {
            status: "failed",
            detail: Some(format!("{}: {e}", rec.stage)),
            exit_code: Some(1),
        },
    };
    let result = match outcome.status {
        "exited" => {
            let code = outcome.exit_code.unwrap_or(0);
            if code == 0 {
                Ok(())
            } else {
                Err(format!("container exited with code {code}").into())
            }
        }
        _ => Err(outcome.detail.clone().unwrap_or_default().into()),
    };

    if let Some(path) = &options.report {
        let status = outcome.status;
        match rec.into_report(outcome).write_to(path) {
            Ok(()) => eprintln!("launch report ({status}) written to {}", path.display()),
            Err(e) => {
                eprintln!("failed to write launch report to '{}': {e}", path.display());
                // The report was explicitly requested — do not let a
                // write failure pass as success.
                return Err(format!("failed to write launch report: {e}").into());
            }
        }
    }
    result
}

/// The `run-image` flow; `rec` accumulates the plan/observations the
/// driver serializes on both success and failure.
async fn run_image_inner(
    options: &RunImageOptions,
    rec: &mut HostRunRec,
) -> Result<i32, Box<dyn std::error::Error>> {
    // 0. The isolation method is a separate selection from the engine.
    //    A method no backend implements — or one whose declared host-OS
    //    scope excludes this host — is refused before any engine work;
    //    an unusable isolation is never an implicit fallback to a normal
    //    container or a native run.
    rec.stage = "resolve isolation";
    let refusal = match backends::capabilities_for(rec.isolation.configured) {
        None => Some(format!(
            "isolation method '{}' is not implemented in this build \
             (implemented: {})",
            rec.isolation.configured.name(),
            backends::implemented_names()
        )),
        Some(caps) if !caps.host_os.contains(&TargetOs::host()) => Some(format!(
            "isolation method '{}' is not supported on this host OS ({}) — \
             declared host OSs: {}",
            rec.isolation.configured.name(),
            TargetOs::host().name(),
            caps.host_os
                .iter()
                .map(|o| o.name())
                .collect::<Vec<_>>()
                .join(", ")
        )),
        Some(_) => None,
    };
    if let Some(detail) = refusal {
        rec.isolation.detail = Some(detail.clone());
        rec.observe(
            "launch.isolation",
            ControlState::Failed,
            ObservationBasis::MechanismResult,
            ControlPhase::Build,
            Some(detail.clone()),
        );
        return Err(detail.into());
    }

    // 1. Resolve container engine and probe the substrate it runs on —
    // the engine host (Docker Desktop VM, remote daemon, …) is not the
    // CLI host, and an unprobeable OS stays `unknown` rather than
    // borrowing the host's.
    rec.stage = "resolve engine";
    let engine = resolve_engine(options.engine).inspect_err(|_| {
        rec.observe(
            "launch.engine",
            ControlState::Failed,
            ObservationBasis::MechanismResult,
            ControlPhase::Build,
            Some("no usable container engine".to_string()),
        );
    })?;
    let engine_name = engine.name().to_string();
    rec.target.engine = crate::execution::EngineName::from_name(&engine_name);
    if let Ok(Ok(info)) =
        tokio::time::timeout(std::time::Duration::from_secs(5), engine.info()).await
        && let Some(os) = crate::container::engine::engine_info_os(&engine_name, &info)
    {
        rec.target.substrate_os = os;
    }
    rec.observe(
        "launch.engine",
        ControlState::Verified,
        ObservationBasis::MechanismResult,
        ControlPhase::Build,
        Some(format!(
            "resolved to {engine_name} (substrate {})",
            rec.target.substrate_os.name()
        )),
    );

    // Host bind mounts (policy, logs, report area) can only reach a
    // daemon on this machine — a remote endpoint would silently mount
    // the wrong host's paths, so refuse up front.
    rec.stage = "check engine locality";
    if let Some(reason) = guest_report::remote_daemon_hint(&engine_name) {
        rec.observe(
            "launch.engine",
            ControlState::Failed,
            ObservationBasis::MechanismResult,
            ControlPhase::Build,
            Some(reason.clone()),
        );
        return Err(format!("refusing to launch: {reason}").into());
    }

    if options.verbose {
        eprintln!("[run-image] engine: {}", engine_name);
    }

    rec.stage = "validate image reference";
    // The image-reference shape is knowable before the policy loads —
    // record the kind now; the pins fill in once the bound policy and
    // the digest check are in.
    let digest_pinned = image_ref_is_digest_pinned(&options.image);
    // `None`: the policy's pins are not bound yet — the record must not
    // claim "no pins" before the policy is seen.
    rec.identity = Some(crate::verifier::identity::for_image(
        &options.image,
        digest_pinned,
        None,
        None,
        options.allow_mutable_tag,
    ));
    if !options.allow_mutable_tag && !digest_pinned {
        rec.observe(
            "launch.image",
            ControlState::Failed,
            ObservationBasis::MechanismResult,
            ControlPhase::Build,
            Some("image reference is not digest-pinned".to_string()),
        );
        return Err(
            "refusing tag-only image reference; pin with @sha256:<digest> or pass --allow-mutable-tag"
                .into(),
        );
    }

    rec.stage = "inspect image";
    let meta = crate::container::inspect::inspect_image(engine.as_ref(), &options.image)
        .await
        .map_err(|e| {
            rec.observe(
                "launch.image",
                ControlState::Failed,
                ObservationBasis::MechanismResult,
                ControlPhase::Build,
                Some(format!("inspect failed: {e}")),
            );
            format!("failed to inspect image: {e}")
        })?;

    // The workload's OS is the image's guest OS — never the CLI host's.
    // Windows-target images are an explicit refusal at this stage, and
    // an undeterminable OS is refused rather than assumed Linux.
    rec.stage = "check guest OS";
    match guest_report::check_guest_image_os(meta.os.as_deref()) {
        Ok(os) => rec.target.workload_os = os,
        Err(e) => {
            rec.observe(
                "launch.image",
                ControlState::Failed,
                ObservationBasis::MechanismResult,
                ControlPhase::Build,
                Some(e.clone()),
            );
            return Err(e.into());
        }
    }
    rec.target.workload_arch = guest_report::image_target_arch(meta.architecture.as_deref());
    rec.observe(
        "launch.image",
        ControlState::Verified,
        ObservationBasis::MechanismResult,
        ControlPhase::Build,
        Some(format!(
            "image metadata inspected (os {}, arch {})",
            meta.os.as_deref().unwrap_or("unknown"),
            meta.architecture.as_deref().unwrap_or("unknown"),
        )),
    );

    rec.stage = "check runner entrypoint";
    let entrypoint = meta.entrypoint.as_deref().unwrap_or(&[]);
    if entrypoint.first().map(String::as_str) != Some("/usr/local/bin/mcp-secure-runner") {
        rec.observe(
            "launch.runner",
            ControlState::Failed,
            ObservationBasis::MechanismResult,
            ControlPhase::Build,
            Some("ENTRYPOINT[0] is not /usr/local/bin/mcp-secure-runner".to_string()),
        );
        return Err(
            "image ENTRYPOINT[0] must be /usr/local/bin/mcp-secure-runner (wrap or containerize the image first)"
                .into(),
        );
    }
    rec.observe(
        "launch.runner",
        ControlState::Verified,
        ObservationBasis::MechanismResult,
        ControlPhase::Build,
        None,
    );

    // Runner capability decides the report channel: the image env's
    // recorded marker separates report-capable builds from legacy ones.
    // `--report` on a runner that cannot produce a guest report is
    // refused before the container launches — a missing capability is
    // a missing record, never silently the old behavior.
    rec.stage = "check runner capability";
    let runner_caps = guest_report::caps_from_image_env(&meta.env);
    rec.guest_runner = runner_caps.as_ref().map(|c| c.identity());
    let report_capable = runner_caps
        .as_ref()
        .map(|c| c.guest_report_capable())
        .unwrap_or(false);
    if options.report.is_some() && !report_capable {
        let detail = "the image's mcp-secure-runner cannot produce a guest launch report; \
             rebuild it with a current runner via wrap-image or containerize"
            .to_string();
        rec.guest_state = GuestReportState::UnsupportedRunner;
        rec.guest_detail = Some(detail.clone());
        rec.observe(
            "launch.guest_report",
            ControlState::Failed,
            ObservationBasis::MechanismResult,
            ControlPhase::Build,
            Some(detail.clone()),
        );
        return Err(detail.into());
    }
    let want_guest_report = options.report.is_some() && report_capable;
    // A legacy runner launches as before — the run is allowed, but the
    // guest-side record stays unobserved rather than assumed.
    if !report_capable {
        eprintln!(
            "[run-image] note: {}",
            crate::container::wrap::runner_capability_note(&runner_caps)
        );
    }

    // 2. Resolve policy file and generate self-contained KDL.
    //
    // The guest contract is a Linux workload: `mcp-secure-runner` is a
    // static ELF and the in-guest OS is Linux regardless of the CLI host,
    // so the policy is accepted against a Linux target here — never against
    // the host OS — and re-validated inside the guest by the runner.
    let guest_target = crate::execution::ExecutionTarget::linux_container(
        crate::execution::EngineName::from_name(&engine_name),
        // The substrate OS is not consulted for policy validation — the
        // guest contract is Linux regardless — so skip the `<cli> info`
        // probe and record it as unknown.
        None,
    );
    rec.stage = "load policy";
    let policy_path = options
        .policy
        .as_deref()
        .unwrap_or_else(|| std::path::Path::new("./policy.kdl"));
    let policy_canonical = std::fs::canonicalize(policy_path)
        .map_err(|e| format!("policy file '{}': {e}", policy_path.display()))?;
    let base_dir = policy_canonical
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."));
    let bound = policy_export::load_and_bind_policy(
        &policy_canonical,
        options.server.as_deref(),
        &guest_target,
    )
    .map_err(|e| {
        rec.observe(
            "launch.policy",
            ControlState::Failed,
            ObservationBasis::MechanismResult,
            ControlPhase::Build,
            Some(e.to_string()),
        );
        match e {
            PolicyBindError::Load(m) => {
                format!("failed to load policy '{}': {m}", policy_path.display())
            }
            PolicyBindError::Bind(m) => format!("failed to bind policy to server: {m}"),
        }
    })?;
    rec.policy = bound.audit_context().ok();
    rec.tools = bound
        .tools
        .iter()
        .map(|t| ToolDisposition {
            name: t.name.clone(),
            server: t.server.clone(),
            allowed: t.allowed,
            side_effect: t.side_effect.clone(),
        })
        .collect();
    rec.observe(
        "launch.policy",
        ControlState::Verified,
        ObservationBasis::MechanismResult,
        ControlPhase::Build,
        Some("policy bound and exported self-contained".to_string()),
    );

    let docker_hashes: Vec<_> = bound
        .hash_entries
        .iter()
        .filter(|e| e.hash_type == crate::policy::HashType::DockerManifest)
        .collect();
    let digest_matched = meta
        .digest
        .as_deref()
        .is_some_and(|actual| docker_hashes.iter().any(|e| e.hash_value == actual));
    // The image pins join the record once the bound policy exists —
    // `image_inspect` marks the pins whose own digest matched.
    rec.identity = Some(crate::verifier::identity::for_image(
        &options.image,
        digest_pinned,
        Some(&bound.hash_entries),
        meta.digest.as_deref(),
        options.allow_mutable_tag,
    ));
    if !docker_hashes.is_empty() {
        let actual = meta.digest.as_deref().unwrap_or("");
        if !digest_matched {
            rec.observe(
                "launch.image",
                ControlState::Failed,
                ObservationBasis::VerificationRun,
                ControlPhase::Build,
                Some("image digest does not match the policy's docker-manifest-hash".to_string()),
            );
            return Err(format!(
                "image digest '{}' does not match any docker-manifest-hash in the policy",
                if actual.is_empty() {
                    "(missing)"
                } else {
                    actual
                }
            )
            .into());
        }
    }
    let self_contained_kdl = policy_export::inline_policy_to_kdl(&bound, base_dir, &guest_target)
        .map_err(|e| e.to_string())?;

    // One private temp dir carries the exported policy, the guest
    // report mount, and the container id file — dropped on every path.
    let temp_dir =
        TempLaunchDir::new().map_err(|e| format!("failed to create temp dir for policy: {e}"))?;
    let temp_policy_path = temp_dir.policy_path();
    std::fs::write(&temp_policy_path, self_contained_kdl)
        .map_err(|e| format!("failed to write self-contained policy: {e}"))?;
    let policy_abs = std::fs::canonicalize(&temp_policy_path)
        .map_err(|e| format!("failed to canonicalize temp policy path: {e}"))?;

    // The report handoff directory is only created when the runner can
    // fill it — an empty mount would look like a report channel that
    // silently produced nothing.
    let report_dir_abs = if want_guest_report {
        let dir = temp_dir.report_dir();
        std::fs::create_dir(&dir).map_err(|e| format!("failed to create guest report dir: {e}"))?;
        Some(dir)
    } else {
        None
    };
    // A mounted channel that produced nothing is `missing`, not
    // `received` — set the pending state now and let collection prove it.
    if want_guest_report {
        rec.guest_state = GuestReportState::Missing;
    }

    // 3. Resolve optional log directory
    let log_dir_abs = match &options.log_dir {
        Some(dir) => {
            let log_path = PathBuf::from(dir);
            if !log_path.exists() {
                std::fs::create_dir_all(&log_path)
                    .map_err(|e| format!("failed to create log dir '{}': {e}", dir))?;
            }
            Some(
                std::fs::canonicalize(&log_path)
                    .map_err(|e| format!("log directory '{}': {e}", dir))?,
            )
        }
        None => None,
    };

    // 4. The typed launch spec the backend translates into its own
    //    argument shape — shares, channel env vars, and the unit-id
    //    record — never a string list assembled by the caller.
    let mut spec = LaunchSpec {
        isolation: rec.isolation.configured,
        image: Some(options.image.clone()),
        guest_os: rec.target.workload_os,
        guest_arch: rec.target.workload_arch.clone(),
        shares: vec![ShareMount {
            host: policy_abs.clone(),
            guest: "/etc/mcp-secure/policy.kdl".to_string(),
            writable: false,
        }],
        env: Vec::new(),
        unit_id_file: Some(temp_dir.cid_path()),
    };
    if let Some(log_dir) = &log_dir_abs {
        spec.shares.push(ShareMount {
            host: log_dir.clone(),
            guest: "/var/log/mcp-secure".to_string(),
            writable: true,
        });
    }
    // The dedicated guest-report handoff area: a private host directory
    // mounted at a fixed guest path — the runner writes report.json
    // there, the host reads it back after the container exits. Kept
    // separate from the read-only policy mount and the log mount.
    if let Some(report_dir) = &report_dir_abs {
        spec.shares.push(ShareMount {
            host: report_dir.clone(),
            guest: guest_report::GUEST_REPORT_MOUNT_PATH.to_string(),
            writable: true,
        });
        spec.env.push((
            guest_report::REPORT_OUT_ENV.to_string(),
            guest_report::GUEST_REPORT_MOUNT_PATH.to_string(),
        ));
    }
    if let Some(name) = &options.server {
        spec.env.push(("MCP_WRIT_SERVER".to_string(), name.clone()));
    }
    // Correlate the guest runner's launch/audit records with this host's
    // report — the runner reads it before stripping the variable from the
    // workload environment.
    if options.report.is_some() {
        spec.env
            .push(("MCP_WRIT_LAUNCH_ID".to_string(), rec.launch_id.to_string()));
    }

    if options.verbose {
        // The rendered options come from the backend that will launch —
        // kata prepends its runtime selection to the shared spec options.
        let rendered = match spec.isolation {
            IsolationKind::Kata => backends::kata::run_options(&spec),
            _ => backends::oci::spec_run_options(&spec),
        };
        eprintln!(
            "[run-image] {} run -i --rm {} {}",
            engine_name,
            rendered.join(" "),
            options.image
        );
    }

    // 5. Resolve the isolation backend and confirm it applies exactly the
    //    requested boundary for this spec — a refusal or a mismatched
    //    confirmation leaves nothing running and never degrades to a
    //    weaker isolation.
    rec.stage = "check isolation backend";
    let backend = match backends::resolve_backend(rec.isolation.configured, engine) {
        Ok(b) => b,
        Err(e) => {
            let detail = e.to_string();
            rec.isolation.detail = Some(detail.clone());
            rec.observe(
                "launch.isolation",
                ControlState::Failed,
                ObservationBasis::MechanismResult,
                ControlPhase::Build,
                Some(detail.clone()),
            );
            return Err(detail.into());
        }
    };
    let confirmed = match backend.check(&spec).await {
        Ok(c) => c,
        Err(e) => {
            let detail = e.to_string();
            rec.isolation.detail = Some(detail.clone());
            rec.observe(
                "launch.isolation",
                ControlState::Failed,
                ObservationBasis::MechanismResult,
                ControlPhase::Build,
                Some(detail.clone()),
            );
            return Err(detail.into());
        }
    };
    if let Err(e) = backends::ensure_confirmed(&spec, &confirmed) {
        let detail = e.to_string();
        rec.isolation.detail = Some(detail.clone());
        rec.observe(
            "launch.isolation",
            ControlState::Failed,
            ObservationBasis::MechanismResult,
            ControlPhase::Build,
            Some(detail.clone()),
        );
        return Err(detail.into());
    }
    // What the record reports is the *confirmed* isolation — distinct
    // from the configured request it was checked against.
    rec.isolation.verified = Some(confirmed.verified);
    rec.isolation.unit = Some(confirmed.unit);
    rec.isolation.detail = confirmed.detail.clone();
    rec.observe(
        "launch.isolation",
        ControlState::Verified,
        ObservationBasis::MechanismResult,
        ControlPhase::Build,
        Some(format!(
            "{} isolation confirmed (unit: {})",
            confirmed.verified.name(),
            confirmed.unit.name()
        )),
    );

    rec.stage = "spawn container";
    let mut handle = backend.launch(&spec).await.map_err(|e| {
        rec.observe(
            "launch.container",
            ControlState::Failed,
            ObservationBasis::SpawnResult,
            ControlPhase::Spawn,
            Some(format!("container spawn failed: {e}")),
        );
        format!("failed to run container with {engine_name}: {e}")
    })?;
    // The substrate-assigned unit identifier (container id) is recorded
    // alongside the launch id so the boundary is traceable.
    rec.isolation.unit_id = handle.unit_id();
    rec.observe(
        "launch.container",
        ControlState::Verified,
        ObservationBasis::SpawnResult,
        ControlPhase::Spawn,
        Some("container spawned".to_string()),
    );
    // Guest-side enforcement cannot be observed from the host: the record
    // stays honest — not applied, not absent, unknown. A collected guest
    // report is self-reported data attached under `guest`, never a
    // host-verified `rpc.guest` observation.
    rec.observations.push(EnforcementObservation {
        control: "rpc.guest",
        state: ControlState::Unknown,
        basis: ObservationBasis::NotObserved,
        phase: ControlPhase::Session,
        reason: Some(
            "guest-side enforcement runs inside the guest (a container, or a \
             VM under --isolation kata); the host does not observe it (the \
             mounted audit log and, for report-capable runners, the guest \
             report attachment carry the guest's own record under the same \
             launch_id)"
                .to_string(),
        ),
    });

    // 6. The shared session driver owns the stdin/stdout relay, the wait,
    //    the interrupt path, and resource cleanup — identical across
    //    backends. An interrupt asks the backend to terminate, removes the
    //    unit by its recorded id, and reports `interrupted`; a partial
    //    failure still releases what the launch created.
    rec.stage = "wait for container";
    let session_end = backends::drive_stdio_session(handle.as_mut()).await;
    // The substrate may have written the unit id after launch's bounded
    // poll — refresh the record now that the session has settled so a
    // late id is still reported on every end path.
    if rec.isolation.unit_id.is_none() {
        rec.isolation.unit_id = handle.unit_id();
    }
    let code = match session_end {
        Ok(backends::SessionEnd::Exited(code)) => code,
        Ok(backends::SessionEnd::Interrupted) => {
            rec.interrupted = true;
            return Err("interrupted by SIGINT".into());
        }
        Err(e) => return Err(format!("container session failed: {e}").into()),
    };

    // 7. Collect the guest's own launch report through the dedicated
    // mount. A missing or unvalidatable file is a failed channel — the
    // run cannot succeed while a required report is absent.
    if let Some(report_dir) = &report_dir_abs {
        rec.stage = "collect guest report";
        let expected_version = runner_caps.as_ref().map(|c| c.version.as_str());
        let read =
            guest_report::read_guest_report(report_dir, rec.launch_id, expected_version).await;
        match read {
            GuestReportRead::Received(text) => {
                rec.guest_state = GuestReportState::Received;
                rec.guest_report_json = Some(text);
                rec.observe(
                    "launch.guest_report",
                    ControlState::Verified,
                    ObservationBasis::VerificationRun,
                    ControlPhase::Session,
                    Some("guest report received via the dedicated mount and validated".to_string()),
                );
            }
            GuestReportRead::Missing(detail) => {
                rec.guest_state = GuestReportState::Missing;
                rec.guest_detail = Some(detail.clone());
                rec.observe(
                    "launch.guest_report",
                    ControlState::Failed,
                    ObservationBasis::VerificationRun,
                    ControlPhase::Session,
                    Some(detail.clone()),
                );
                return Err(detail.into());
            }
            GuestReportRead::Invalid(detail) => {
                rec.guest_state = GuestReportState::Invalid;
                rec.guest_detail = Some(detail.clone());
                rec.observe(
                    "launch.guest_report",
                    ControlState::Failed,
                    ObservationBasis::VerificationRun,
                    ControlPhase::Session,
                    Some(detail.clone()),
                );
                return Err(detail.into());
            }
        }
    }

    Ok(code)
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::container::engine::EngineKind;

    /// Resolve a path to an absolute path, using the current directory as base.
    fn resolve_path(path: &str) -> std::io::Result<PathBuf> {
        let p = PathBuf::from(path);
        if p.is_absolute() {
            Ok(p)
        } else {
            Ok(std::env::current_dir()?.join(p))
        }
    }

    fn member<'text, 'raw>(
        v: nojson::RawJsonValue<'text, 'raw>,
        name: &str,
    ) -> nojson::RawJsonValue<'text, 'raw> {
        v.to_member(name).unwrap().required().unwrap()
    }

    fn pinned_image_options() -> RunImageOptions {
        RunImageOptions {
            engine: Some(EngineKind::Docker),
            isolation: None,
            image: "img@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                .to_string(),
            policy: None,
            log_dir: None,
            verbose: false,
            allow_mutable_tag: false,
            server: None,
            report: None,
        }
    }

    /// An unimplemented isolation is refused before any engine or image
    /// work — never an implicit fallback to a normal container, and the
    /// refusal records itself on the report.
    #[tokio::test]
    async fn unimplemented_isolation_refuses_before_engine_work() {
        let temp_dir = tempfile::tempdir().unwrap();
        let report_path = temp_dir.path().join("report.json");
        let options = RunImageOptions {
            isolation: Some(IsolationKind::AppleContainer),
            report: Some(report_path.clone()),
            ..pinned_image_options()
        };
        let err = run_image(&options)
            .await
            .expect_err("apple-container is refused");
        assert!(err.to_string().contains("apple-container"), "got: {err}");
        assert!(err.to_string().contains("not implemented"), "got: {err}");

        // The failed report still carries the configured isolation and
        // shows the backend never confirmed it.
        let json = std::fs::read_to_string(&report_path).unwrap();
        let parsed = nojson::RawJson::parse(&json).unwrap();
        let root = parsed.value();
        let isolation = member(root, "isolation");
        assert_eq!(
            member(isolation, "configured").as_string_str().unwrap(),
            "apple-container"
        );
        assert!(member(isolation, "verified").kind().is_null());
        assert!(member(isolation, "unit").kind().is_null());
        assert_eq!(
            member(root, "result").to_object().unwrap().count(),
            3,
            "status/detail/exit_code"
        );
    }

    /// Every recognized-but-unimplemented kind refuses the same way —
    /// none is silently launched as a normal container.
    #[tokio::test]
    async fn every_unimplemented_isolation_refuses() {
        for kind in [
            IsolationKind::AppleContainer,
            IsolationKind::HyperV,
            IsolationKind::WindowsSandbox,
        ] {
            let options = RunImageOptions {
                isolation: Some(kind),
                ..pinned_image_options()
            };
            let err = run_image(&options).await.expect_err("refuses");
            assert!(
                err.to_string().contains(kind.name()),
                "kind {}: {err}",
                kind.name()
            );
        }
    }

    /// `kata` is implemented — it passes the "not implemented" gate. On
    /// a non-Linux host the declared-capability gate refuses it before
    /// any engine work (the validated stack needs dockerd + KVM); on
    /// Linux it proceeds to engine resolution, so the failure — if any —
    /// is downstream of the isolation gate (engine missing, image
    /// absent, or the kata runtime unregistered).
    #[tokio::test]
    async fn kata_isolation_passes_the_implemented_gate() {
        let temp_dir = tempfile::tempdir().unwrap();
        let report_path = temp_dir.path().join("report.json");
        let options = RunImageOptions {
            isolation: Some(IsolationKind::Kata),
            engine: Some(EngineKind::Docker),
            report: Some(report_path.clone()),
            ..pinned_image_options()
        };
        let err = run_image(&options).await.expect_err(
            "this test does not supply a launchable kata environment — the \
             run must fail somewhere after the implemented gate",
        );
        assert!(
            !err.to_string().contains("not implemented in this build"),
            "kata is implemented — it must not refuse as unimplemented: {err}"
        );
        if cfg!(target_os = "linux") {
            // Past the gate the run proceeds to engine resolution and
            // image/policy work — whatever fails there is a real
            // prerequisite, not an alias to container.
            assert!(
                !err.to_string().contains("not supported on this host OS"),
                "the declared-capability gate only refuses off-Linux: {err}"
            );
        } else {
            assert!(
                err.to_string().contains("not supported on this host OS"),
                "kata needs a Linux host: {err}"
            );
        }
        // Either way the refusal is recorded: configured kata, never
        // verified (the backend never got to confirm).
        let json = std::fs::read_to_string(&report_path).unwrap();
        let parsed = nojson::RawJson::parse(&json).unwrap();
        let isolation = member(parsed.value(), "isolation");
        assert_eq!(
            member(isolation, "configured").as_string_str().unwrap(),
            "kata"
        );
        assert!(member(isolation, "verified").kind().is_null());
    }

    /// `container` (the default) does not refuse at the isolation gate —
    /// the run proceeds to engine resolution and fails there on a host
    /// without docker, which proves the isolation check passed it
    /// through rather than rejecting it.
    #[tokio::test]
    async fn default_container_isolation_passes_the_gate() {
        let options = RunImageOptions {
            engine: Some(EngineKind::Buildah),
            ..pinned_image_options()
        };
        let err = run_image(&options).await.expect_err("buildah cannot run");
        // The refusal is the engine's, not the isolation gate's.
        assert!(
            !err.to_string().contains("not implemented in this build"),
            "isolation gate must pass container through, got: {err}"
        );
    }

    #[test]
    fn test_image_ref_is_digest_pinned() {
        assert!(image_ref_is_digest_pinned(
            "example.com/app@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        ));
        assert!(!image_ref_is_digest_pinned("example.com/app:latest"));
        assert!(!image_ref_is_digest_pinned("example.com/app"));
    }

    #[test]
    fn test_resolve_path_absolute() {
        #[cfg(windows)]
        let abs_str = "C:\\absolute\\path";
        #[cfg(not(windows))]
        let abs_str = "/absolute/path";

        let result = resolve_path(abs_str);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), PathBuf::from(abs_str));
    }

    #[test]
    fn test_resolve_path_relative() {
        let result = resolve_path("relative/path");
        assert!(result.is_ok());
        let resolved = result.unwrap();
        assert!(resolved.is_absolute());
        assert!(resolved.ends_with("relative/path"));
    }
}
