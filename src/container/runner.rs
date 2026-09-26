use std::path::PathBuf;

use crate::container::engine::resolve_engine;
use crate::container::options::RunImageOptions;
use crate::container::policy_export::{self, PolicyBindError};
use crate::enforcement::{
    ControlLayer, ControlPhase, ControlState, EnforcementObservation, EnforcementPlan,
    LAUNCH_REPORT_SCHEMA_VERSION, LaunchOutcome, LaunchReport, ObservationBasis, PlannedControl,
    ToolDisposition,
};
use crate::execution::ExecutionTarget;

/// Build the container run options (volume mounts).
fn build_run_options(
    policy_abs: &std::path::Path,
    log_dir_abs: Option<&std::path::Path>,
    server: Option<&str>,
    launch_id: Option<uuid::Uuid>,
) -> Vec<String> {
    let mut options = vec![
        "-v".to_string(),
        format!("{}:/etc/mcp-secure/policy.kdl:ro", policy_abs.display()),
    ];

    if let Some(log_dir) = log_dir_abs {
        options.push("-v".to_string());
        options.push(format!("{}:/var/log/mcp-secure", log_dir.display()));
    }

    if let Some(name) = server {
        options.push("-e".to_string());
        options.push(format!("MCP_WRIT_SERVER={name}"));
    }

    // Correlate the guest runner's launch/audit records with this host's
    // report — the runner reads it before stripping the variable from the
    // workload environment.
    if let Some(id) = launch_id {
        options.push("-e".to_string());
        options.push(format!("MCP_WRIT_LAUNCH_ID={id}"));
    }

    options
}

/// True when the image reference is pinned to an immutable digest.
pub fn image_ref_is_digest_pinned(image: &str) -> bool {
    image.contains("@sha256:")
}

struct TempPolicyDir {
    dir: PathBuf,
}

impl TempPolicyDir {
    fn new() -> Result<Self, std::io::Error> {
        let dir = crate::fspriv::create_private_tempdir("run-policy")?;
        Ok(Self { dir })
    }

    fn path(&self) -> &std::path::Path {
        &self.dir
    }
}

impl Drop for TempPolicyDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// Host-side record of a `run-image` launch: the launch-layer controls
/// the host sets up, the observations it can honestly take, and the
/// bound policy's tool table (enforced in the guest).
struct HostRunRec {
    launch_id: uuid::Uuid,
    target: ExecutionTarget,
    policy: Option<crate::audit_log::PolicyAuditContext>,
    controls: Vec<PlannedControl>,
    tools: Vec<ToolDisposition>,
    observations: Vec<EnforcementObservation>,
    /// The stage currently in flight — named in the failed result.
    stage: &'static str,
}

impl HostRunRec {
    fn new(engine_name: Option<crate::execution::EngineName>) -> Self {
        let launch_control = |id: &'static str| PlannedControl {
            id,
            layer: ControlLayer::Launch,
            mechanism: "container launch",
            state: ControlState::Planned,
            reason: None,
        };
        Self {
            launch_id: uuid::Uuid::now_v7(),
            target: ExecutionTarget::linux_container(engine_name, None),
            policy: None,
            controls: vec![
                launch_control("launch.engine"),
                launch_control("launch.image"),
                launch_control("launch.runner"),
                launch_control("launch.policy"),
                launch_control("launch.container"),
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
                     container; rpc.guest stays unobserved from the host"
                        .to_string(),
                ],
            },
            observations: self.observations,
            result: Some(outcome),
        }
    }
}

/// Run a container image with policy and log volume mounts.
///
/// This function spawns a container using the resolved engine, mounts the policy
/// file and optional log directory, and transparently relays stdin/stdout between
/// the host and the container. On container exit, the process exits with the
/// container's exit code.
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

    let mut rec = HostRunRec::new(options.engine.map(crate::execution::EngineName::from));
    let outcome = run_image_inner(options, &mut rec).await;

    let outcome = match outcome {
        Ok(code) => LaunchOutcome {
            status: "exited",
            detail: None,
            exit_code: Some(code),
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
    // 1. Resolve container engine
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
    rec.observe(
        "launch.engine",
        ControlState::Verified,
        ObservationBasis::MechanismResult,
        ControlPhase::Build,
        Some(format!("resolved to {engine_name}")),
    );

    if options.verbose {
        eprintln!("[run-image] engine: {}", engine_name);
    }

    rec.stage = "validate image reference";
    if !options.allow_mutable_tag && !image_ref_is_digest_pinned(&options.image) {
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
    rec.observe(
        "launch.image",
        ControlState::Verified,
        ObservationBasis::MechanismResult,
        ControlPhase::Build,
        Some("image metadata inspected".to_string()),
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
    if !docker_hashes.is_empty() {
        let actual = meta.digest.as_deref().unwrap_or("");
        if !docker_hashes.iter().any(|e| e.hash_value == actual) {
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

    let temp_policy_dir =
        TempPolicyDir::new().map_err(|e| format!("failed to create temp dir for policy: {e}"))?;
    let temp_policy_path = temp_policy_dir.path().join("policy.kdl");
    std::fs::write(&temp_policy_path, self_contained_kdl)
        .map_err(|e| format!("failed to write self-contained policy: {e}"))?;
    let policy_abs = std::fs::canonicalize(&temp_policy_path)
        .map_err(|e| format!("failed to canonicalize temp policy path: {e}"))?;

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

    // 4. Build run options
    let run_options = build_run_options(
        &policy_abs,
        log_dir_abs.as_deref(),
        options.server.as_deref(),
        // Correlate guest audit events with this host report.
        options.report.as_ref().map(|_| rec.launch_id),
    );
    let options_refs: Vec<&str> = run_options.iter().map(|s| s.as_str()).collect();

    if options.verbose {
        eprintln!(
            "[run-image] {} run -i --rm {} {}",
            engine_name,
            run_options.join(" "),
            options.image
        );
    }

    // 5. Spawn container using engine.run abstraction
    rec.stage = "spawn container";
    let mut child = engine
        .run(&options.image, &options_refs, true)
        .await
        .map_err(|e| {
            rec.observe(
                "launch.container",
                ControlState::Failed,
                ObservationBasis::SpawnResult,
                ControlPhase::Spawn,
                Some(format!("container spawn failed: {e}")),
            );
            format!("failed to run container with {engine_name}: {e}")
        })?;
    rec.observe(
        "launch.container",
        ControlState::Verified,
        ObservationBasis::SpawnResult,
        ControlPhase::Spawn,
        Some("container spawned".to_string()),
    );
    // Guest-side enforcement cannot be observed from the host: the record
    // stays honest — not applied, not absent, unknown.
    rec.observations.push(EnforcementObservation {
        control: "rpc.guest",
        state: ControlState::Unknown,
        basis: ObservationBasis::NotObserved,
        phase: ControlPhase::Session,
        reason: Some(
            "guest-side enforcement runs inside the container; the host does \
             not observe it (the mounted audit log carries the guest's own \
             launch record under the same launch_id)"
                .to_string(),
        ),
    });

    // 6. Transparent stdin/stdout relay
    let child_stdin = child
        .stdin
        .take()
        .ok_or("failed to capture container stdin")?;
    let child_stdout = child
        .stdout
        .take()
        .ok_or("failed to capture container stdout")?;

    // Relay host stdin → container stdin
    let stdin_handle = tokio::spawn(async move {
        let mut host_stdin = tokio::io::stdin();
        let mut sink = child_stdin;
        let _ = tokio::io::copy(&mut host_stdin, &mut sink).await;
    });

    // Relay container stdout → host stdout
    let stdout_handle = tokio::spawn(async move {
        let mut source = child_stdout;
        let mut host_stdout = tokio::io::stdout();
        let _ = tokio::io::copy(&mut source, &mut host_stdout).await;
    });

    // 7. Wait for container to exit
    rec.stage = "wait for container";
    let status = child
        .wait()
        .await
        .map_err(|e| format!("failed to wait for container: {e}"))?;

    // Clean up relay tasks
    stdin_handle.abort();
    let _ = stdout_handle.await;

    let code = status.code().unwrap_or(1);
    Ok(code)
}
#[cfg(test)]
mod tests {
    use super::*;

    /// Resolve a path to an absolute path, using the current directory as base.
    fn resolve_path(path: &str) -> std::io::Result<PathBuf> {
        let p = PathBuf::from(path);
        if p.is_absolute() {
            Ok(p)
        } else {
            Ok(std::env::current_dir()?.join(p))
        }
    }

    fn production_run_args(
        image: &str,
        policy_abs: &std::path::Path,
        log_dir_abs: Option<&std::path::Path>,
    ) -> Vec<String> {
        let options = super::build_run_options(policy_abs, log_dir_abs, None, None);
        crate::container::engine::container_run_args(&options, image)
    }

    fn hardening_prefix() -> Vec<&'static str> {
        vec![
            "run",
            "-i",
            "--rm",
            "--no-healthcheck",
            "--entrypoint",
            "/usr/local/bin/mcp-secure-runner",
            "-e",
            "MCP_WRIT_ENV=",
            "-e",
            "MCP_WRIT_SKIP_SANDBOX=",
            "-e",
            "MCP_WRIT_SERVER=",
            "-e",
            "MCP_WRIT_LAUNCH_ID=",
        ]
    }

    #[test]
    fn test_build_run_args_basic() {
        let policy = PathBuf::from("/tmp/policy.kdl");
        let args = production_run_args("my-image:latest", &policy, None);
        let mut expected: Vec<String> =
            hardening_prefix().into_iter().map(str::to_string).collect();
        expected.extend([
            "-v".into(),
            "/tmp/policy.kdl:/etc/mcp-secure/policy.kdl:ro".into(),
            "my-image:latest".into(),
        ]);
        assert_eq!(args, expected);
    }

    #[test]
    fn test_build_run_args_with_log_dir() {
        let policy = PathBuf::from("/etc/mcp/policy.kdl");
        let log_dir = PathBuf::from("/var/log/mcp");
        let args = production_run_args("secure-server:v2", &policy, Some(&log_dir));
        let mut expected: Vec<String> =
            hardening_prefix().into_iter().map(str::to_string).collect();
        expected.extend([
            "-v".into(),
            "/etc/mcp/policy.kdl:/etc/mcp-secure/policy.kdl:ro".into(),
            "-v".into(),
            "/var/log/mcp:/var/log/mcp-secure".into(),
            "secure-server:v2".into(),
        ]);
        assert_eq!(args, expected);
    }

    #[test]
    fn test_build_run_args_policy_mount_is_readonly() {
        let policy = PathBuf::from("/tmp/p.kdl");
        let args = production_run_args("img", &policy, None);
        let volume = args
            .iter()
            .find(|a| a.contains("policy.kdl") || a.contains("p.kdl"))
            .expect("policy volume");
        assert!(
            volume.ends_with(":ro"),
            "policy mount should be read-only: {volume}"
        );
    }

    #[test]
    fn test_build_run_args_image_is_last() {
        let policy = PathBuf::from("/tmp/p.kdl");
        let log_dir = PathBuf::from("/tmp/logs");
        let args = production_run_args("my-img", &policy, Some(&log_dir));
        assert_eq!(args.last().unwrap(), "my-img");
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
