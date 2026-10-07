use super::*;
#[cfg(any(target_os = "linux", target_os = "windows"))]
use crate::enforcement::{FsAccess, GrantOrigin, GrantSubject};
use crate::policy::{FsToolPolicy, ToolPolicy};
#[cfg(target_os = "windows")]
use crate::enforcement::ProcessGrant;
#[cfg(target_os = "windows")]
use crate::policy::TransportType;
#[cfg(target_os = "windows")]
use crate::warden::windows_sandbox::{WinSpawnError, WinStage};

/// A policy with an allowed read tool, an allowed write tool, and a
/// denied tool — the "read/write tools coexist + denied tool" case
/// the PR-03 verification list calls for.
fn policy_with_tools() -> Policy {
    let mut policy = Policy::default();
    // The Linux spawn path refuses policies without an execve
    // allowance; every test here declares it.
    policy.syscalls.allowed = vec!["execve".to_string()];

    let mut read = ToolPolicy::named("read_file", true);
    read.server = Some("fs".to_string());
    read.side_effect = Some("read_only".to_string());
    // allowed_paths=[/usr] is the tool grant; read_only_paths adds
    // /deny-me which the global deny list overrides — an exact-match
    // deny produces a Skipped grant (a deny *subpath* of an allowed
    // path is rejected by validation before the build).
    let mut fs = FsToolPolicy::new(vec!["/usr".to_string()], vec![]);
    fs.read_only_paths = vec!["/usr".to_string(), "/deny-me".to_string()];
    read.fs = Some(fs);

    let mut write = ToolPolicy::named("write_file", true);
    write.side_effect = Some("write".to_string());

    let denied = ToolPolicy::named("rm_rf", false);

    policy.tools = vec![read, write, denied];
    policy
}

fn control_state<'a>(plan: &'a EnforcementPlan, id: &str) -> (ControlState, &'a str) {
    let c = plan
        .controls
        .iter()
        .find(|c| c.id == id)
        .unwrap_or_else(|| panic!("control {id} missing"));
    (c.state, c.reason.as_deref().unwrap_or(""))
}

#[test]
fn tools_table_keeps_read_write_and_denied_tools() {
    let tools = tools_table(&policy_with_tools());
    assert_eq!(tools.len(), 3);
    let read = tools.iter().find(|t| t.name == "read_file").unwrap();
    assert!(read.allowed);
    assert_eq!(read.server.as_deref(), Some("fs"));
    assert_eq!(read.side_effect.as_deref(), Some("read_only"));
    let write = tools.iter().find(|t| t.name == "write_file").unwrap();
    assert!(write.allowed);
    assert_eq!(write.side_effect.as_deref(), Some("write"));
    let denied = tools.iter().find(|t| t.name == "rm_rf").unwrap();
    assert!(!denied.allowed);
}

#[test]
fn shared_controls_distinguish_optional_features() {
    let policy = policy_with_tools();
    let opts = SpawnOptions {
        restrict_environment: true,
        allowed_names: vec!["FOO".to_string()],
        tmpdir: None,
    };
    let controls = shared_controls(&policy, &opts, false, false, false);
    let by_id = |id: &str| controls.iter().find(|c| c.id == id).unwrap();

    // Identity planned? default policy has no hash entries.
    assert_eq!(by_id("launch.identity").state, ControlState::Skipped);
    assert_eq!(by_id("launch.env").state, ControlState::Planned);
    // RPC controls are always planned (the auditor runs them).
    for id in ["rpc.tools", "rpc.tools_list"] {
        assert_eq!(by_id(id).state, ControlState::Planned);
        assert_eq!(by_id(id).layer, ControlLayer::Rpc);
    }
    // secret_overlay defaults on; trajectory / confused_deputy are opt-in.
    assert_eq!(by_id("rpc.secret_overlay").state, ControlState::Planned);
    assert_eq!(by_id("rpc.trajectory").state, ControlState::Skipped);
    assert_eq!(by_id("rpc.confused_deputy").state, ControlState::Skipped);

    // Opt-ins flip to Planned.
    let mut on = policy.clone();
    on.trajectory = true;
    on.confused_deputy_protection = true;
    on.fs.secret_overlay = false;
    let controls = shared_controls(&on, &opts, false, false, false);
    let by_id = |id: &str| controls.iter().find(|c| c.id == id).unwrap();
    assert_eq!(by_id("rpc.trajectory").state, ControlState::Planned);
    assert_eq!(by_id("rpc.confused_deputy").state, ControlState::Planned);
    assert_eq!(by_id("rpc.secret_overlay").state, ControlState::Skipped);
}

#[test]
fn env_observation_only_exists_when_the_contract_applies() {
    assert!(env_observation(false, None).is_none());
    let ok = env_observation(true, None).unwrap();
    assert_eq!(ok.state, ControlState::Verified);
    assert_eq!(ok.phase, ControlPhase::Spawn);
    let err = env_observation(true, Some("boom".to_string())).unwrap();
    assert_eq!(err.state, ControlState::Unknown);
}

#[cfg(target_os = "linux")]
#[test]
fn linux_plan_grants_come_from_the_same_build() {
    let mut policy = policy_with_tools();
    policy.fs.read_only = vec!["/tmp".to_string()];
    policy.fs.read_write = vec!["/definitely/missing/mcp-writ".to_string()];
    policy.fs.denied_paths = vec!["/deny-me".to_string()];
    policy.network.outbound.allowed = vec!["443".to_string(), "api.example.com".to_string()];
    policy.network.inbound.allow_listen = true;

    let plan = build_plan(
        &policy,
        None,
        "child",
        &SpawnOptions::default(),
        None,
        false,
        WindowsNativeMechanism::AppContainer,
    );

    // The plan's grants are exactly what the spawn-path builder
    // produced — the two cannot diverge.
    let direct = super::super::linux_spawn::prepare_linux_child_sandbox(&policy)
        .expect("sandbox build")
        .grants;
    assert_eq!(plan.grants, direct);

    let fs = |path: &str| {
        plan.grants
            .iter()
            .find(|g| matches!(&g.subject, GrantSubject::FsPath { path: p, .. } if p == path))
            .unwrap_or_else(|| panic!("no fs grant for {path}"))
    };
    // Default (policy-level) permissions.
    let tmp = fs("/tmp");
    assert_eq!(tmp.state, ControlState::Planned);
    assert_eq!(tmp.origin, GrantOrigin::Policy);
    assert!(matches!(
        tmp.subject,
        GrantSubject::FsPath {
            access: FsAccess::Read,
            ..
        }
    ));
    // Deny rule wins over the tool's read listing.
    let denied = fs("/deny-me");
    assert_eq!(denied.state, ControlState::Skipped);
    assert_eq!(denied.origin, GrantOrigin::Tool("read_file".to_string()));
    // Missing path: the rule could not be constructed.
    let missing = fs("/definitely/missing/mcp-writ");
    assert_eq!(missing.state, ControlState::Skipped);
    assert!(missing.reason.as_deref().unwrap().contains("cannot open"));
    // Tool-contributed grant: process-wide, but provenance is the tool.
    let tool_grant = fs("/usr");
    assert_eq!(
        tool_grant.origin,
        GrantOrigin::Tool("read_file".to_string())
    );
    assert_eq!(tool_grant.state, ControlState::Planned);
    // Numeric port is a real Landlock rule; the hostname is not
    // expressible and stays RPC-layer only.
    let port = plan
        .grants
        .iter()
        .find(|g| matches!(g.subject, GrantSubject::TcpConnect { port: 443 }))
        .unwrap();
    assert_eq!(port.state, ControlState::Planned);
    let host = plan
        .grants
        .iter()
        .find(|g| matches!(&g.subject, GrantSubject::Rule { name, .. } if name == "api.example.com"))
        .unwrap();
    assert_eq!(host.state, ControlState::Skipped);
    // The execve allowance the policy declares is a Policy grant.
    let execve = plan
        .grants
        .iter()
        .find(|g| matches!(&g.subject, GrantSubject::Syscall { name } if name == "execve"))
        .unwrap();
    assert_eq!(execve.origin, GrantOrigin::Policy);
    assert_eq!(execve.state, ControlState::Planned);

    // Landlock cannot grant TCP bind — an accepted inbound rule is
    // reported NotApplied, never as success.
    assert_eq!(
        control_state(&plan, "os.net.inbound").0,
        ControlState::NotApplied
    );
    assert!(
        control_state(&plan, "os.net.inbound")
            .1
            .contains("Landlock")
    );
}

// -- Linux apply-record → observation mapping --------------------------
// The record written by the pre-exec child is the only evidence; the
// mapping below must never upgrade a missing/truncated record to an
// applied state.

#[cfg(target_os = "linux")]
mod linux_observations {
    use super::*;
    use crate::warden::linux_spawn::{ApplySnapshot, landlock_level, stage};

    fn full_record() -> ApplySnapshot {
        ApplySnapshot {
            stage: stage::SECCOMP,
            landlock: landlock_level::FULL,
            landlock_abi: 4,
            failed_stage: 0,
            errno: 0,
        }
    }

    fn controls() -> Vec<PlannedControl> {
        let mut policy = policy_with_tools();
        policy.sandbox.allow_degraded = true;
        os_controls(&policy, WindowsNativeMechanism::AppContainer)
    }

    fn state_of(obs: &[EnforcementObservation], id: &str) -> ControlState {
        obs.iter().find(|o| o.control == id).unwrap().state
    }

    #[test]
    fn full_apply_reads_verified_even_with_allow_degraded() {
        // allow_degraded tolerates degradation; a kernel-reported
        // FullyEnforced must still read Verified — the flag never
        // decides the observed state on its own.
        let obs = os_spawn_observations(&controls(), Some(&full_record()), None);
        for id in ["os.privileges", "os.fs", "os.net.outbound", "os.syscalls"] {
            assert_eq!(state_of(&obs, id), ControlState::Verified, "{id}");
        }
    }

    #[test]
    fn partial_apply_is_reported_not_flattened() {
        // allow_degraded permits a partially enforced ruleset; the
        // record still reports PARTIAL, so fs reads PartiallyApplied.
        let snap = ApplySnapshot {
            landlock: landlock_level::PARTIAL,
            ..full_record()
        };
        let obs = os_spawn_observations(&controls(), Some(&snap), None);
        assert_eq!(state_of(&obs, "os.fs"), ControlState::PartiallyApplied);
        assert_eq!(state_of(&obs, "os.privileges"), ControlState::Verified);
        assert_eq!(state_of(&obs, "os.syscalls"), ControlState::Verified);
    }

    #[test]
    fn pre_v4_kernel_network_rules_read_not_applied() {
        // Landlock network rules exist since ABI v4: on an older
        // kernel the port rules were never enforceable, so the net
        // control reads NotApplied while fs is PartiallyApplied.
        let snap = ApplySnapshot {
            landlock: landlock_level::PARTIAL,
            landlock_abi: 1,
            ..full_record()
        };
        let obs = os_spawn_observations(&controls(), Some(&snap), None);
        assert_eq!(state_of(&obs, "os.net.outbound"), ControlState::NotApplied);
        assert_eq!(state_of(&obs, "os.fs"), ControlState::PartiallyApplied);
    }

    #[test]
    fn not_enforced_is_not_applied_not_unknown() {
        let snap = ApplySnapshot {
            landlock: landlock_level::NOT_ENFORCED,
            landlock_abi: 0,
            ..full_record()
        };
        let obs = os_spawn_observations(&controls(), Some(&snap), None);
        assert_eq!(state_of(&obs, "os.fs"), ControlState::NotApplied);
        assert_eq!(state_of(&obs, "os.net.outbound"), ControlState::NotApplied);
        assert_eq!(state_of(&obs, "os.syscalls"), ControlState::Verified);
    }

    #[test]
    fn failed_stage_marks_that_control_failed_and_later_unreached() {
        // The Landlock gate refused a partial ruleset: nnp completed,
        // the Landlock stage failed, seccomp never ran.
        let snap = ApplySnapshot {
            stage: stage::NO_NEW_PRIVS,
            landlock: landlock_level::PARTIAL,
            landlock_abi: 1,
            failed_stage: stage::LANDLOCK,
            errno: libc::EACCES,
        };
        let err = std::io::Error::from_raw_os_error(libc::EACCES);
        let obs = os_spawn_observations(&controls(), Some(&snap), Some(&err));
        assert_eq!(state_of(&obs, "os.privileges"), ControlState::Verified);
        assert_eq!(state_of(&obs, "os.fs"), ControlState::Failed);
        assert_eq!(state_of(&obs, "os.net.outbound"), ControlState::Failed);
        assert_eq!(state_of(&obs, "os.syscalls"), ControlState::Failed);
        let reason = &obs.iter().find(|o| o.control == "os.fs").unwrap().reason;
        assert!(reason.as_deref().unwrap().contains("PartiallyEnforced"));
    }

    #[test]
    fn exec_failure_after_apply_keeps_stages_but_notes_failure() {
        // execve failed after the whole pipeline ran (e.g. ENOENT):
        // the applies did happen; the reason names the spawn failure
        // so a verified stage is never read as a live launch.
        let err = std::io::Error::from_raw_os_error(libc::ENOENT);
        let obs = os_spawn_observations(&controls(), Some(&full_record()), Some(&err));
        assert_eq!(state_of(&obs, "os.fs"), ControlState::Verified);
        let reason = obs
            .iter()
            .find(|o| o.control == "os.fs")
            .unwrap()
            .reason
            .clone()
            .unwrap();
        assert!(reason.contains("spawn"));
    }

    #[test]
    fn missing_or_truncated_record_reads_unknown() {
        let controls = controls();
        // No shared page at all.
        let obs = os_spawn_observations(&controls, None, None);
        for id in ["os.privileges", "os.fs", "os.net.outbound", "os.syscalls"] {
            assert_eq!(state_of(&obs, id), ControlState::Unknown, "{id}");
        }
        // Page present but never written past stage 0 — the spawn
        // somehow returned anyway (child killed mid-pipeline).
        let snap = ApplySnapshot {
            stage: stage::NONE,
            ..full_record()
        };
        let obs = os_spawn_observations(&controls, Some(&snap), None);
        for id in ["os.fs", "os.net.outbound", "os.syscalls"] {
            assert_eq!(state_of(&obs, id), ControlState::Unknown, "{id}");
        }
    }

    #[test]
    fn inconsistent_record_reads_unknown() {
        // failed_stage is written only before pre_exec returns Err —
        // a success result beside it cannot be produced honestly.
        let snap = ApplySnapshot {
            failed_stage: stage::SECCOMP,
            errno: libc::EPERM,
            ..full_record()
        };
        let obs = os_spawn_observations(&controls(), Some(&snap), None);
        for id in ["os.privileges", "os.fs", "os.net.outbound", "os.syscalls"] {
            assert_eq!(state_of(&obs, id), ControlState::Unknown, "{id}");
        }

        // An honest record always has stage == failed_stage - 1: a
        // `stage` that does not sit exactly one below `failed_stage`
        // is corrupt too — even beside the expected spawn error.
        let snap = ApplySnapshot {
            stage: stage::NONE,
            landlock: landlock_level::NOT_RUN,
            failed_stage: stage::SECCOMP,
            errno: libc::EPERM,
            ..full_record()
        };
        let err = std::io::Error::from_raw_os_error(libc::EPERM);
        let obs = os_spawn_observations(&controls(), Some(&snap), Some(&err));
        for id in ["os.privileges", "os.fs", "os.net.outbound", "os.syscalls"] {
            assert_eq!(state_of(&obs, id), ControlState::Unknown, "{id}");
        }
    }
}

#[cfg(target_os = "linux")]
#[test]
fn linux_allow_degraded_does_not_decide_plan_state() {
    // allow_degraded tolerates partial enforcement at apply time; it
    // must not change what the plan claims was requested — the state
    // stays Planned (with a qualifier), not PartiallyApplied.
    let mut policy = policy_with_tools();
    policy.sandbox.allow_degraded = true;
    let plan = build_plan(
        &policy,
        None,
        "child",
        &SpawnOptions::default(),
        None,
        false,
        WindowsNativeMechanism::AppContainer,
    );
    for id in ["os.fs", "os.net.outbound"] {
        let (state, reason) = control_state(&plan, id);
        assert_eq!(state, ControlState::Planned, "{id}");
        assert!(reason.contains("allow_degraded"), "{id}");
    }
}

#[cfg(target_os = "windows")]
#[test]
fn failed_fs_grant_marks_os_fs_partially_applied() {
    let controls = os_controls(&policy_with_tools(), WindowsNativeMechanism::AppContainer);
    let failed = ProcessGrant {
        subject: GrantSubject::FsPath {
            path: "C:\\deny".to_string(),
            access: FsAccess::Read,
        },
        origin: GrantOrigin::Policy,
        state: ControlState::Failed,
        reason: Some("ACL write denied".to_string()),
    };
    let obs = os_spawn_observations(
        &controls,
        &[failed],
        None,
        WindowsNativeMechanism::AppContainer,
    );
    let get = |id: &str| obs.iter().find(|o| o.control == id).unwrap().state;
    assert_eq!(get("os.fs"), ControlState::PartiallyApplied);
    assert_eq!(get("os.process"), ControlState::Verified);

    // All fs grants applied (or none attempted) keeps the Verified result.
    let obs = os_spawn_observations(&controls, &[], None, WindowsNativeMechanism::AppContainer);
    assert_eq!(
        obs.iter().find(|o| o.control == "os.fs").unwrap().state,
        ControlState::Verified
    );
}

#[cfg(target_os = "windows")]
#[test]
fn failed_runtime_fs_grant_does_not_mark_os_fs_partial() {
    // Runtime grants (private TMPDIR, executable image, ancestors) are
    // best-effort: a failure stays on the grant's own entry but does
    // not mark the policy fs control partially applied.
    let controls = os_controls(&policy_with_tools(), WindowsNativeMechanism::AppContainer);
    let failed = ProcessGrant {
        subject: GrantSubject::FsPath {
            path: "C:\\tmp".to_string(),
            access: FsAccess::ReadWrite,
        },
        origin: GrantOrigin::Runtime,
        state: ControlState::Failed,
        reason: Some("ACL write denied".to_string()),
    };
    let obs = os_spawn_observations(
        &controls,
        &[failed],
        None,
        WindowsNativeMechanism::AppContainer,
    );
    let os_fs = obs.iter().find(|o| o.control == "os.fs").unwrap();
    assert_eq!(os_fs.state, ControlState::Verified);
}

#[cfg(target_os = "windows")]
#[test]
fn sandbox_setup_error_fails_planned_controls() {
    // A provable pre-`CreateProcessW` failure (profile, capability,
    // loopback, pipes) means nothing ever ran inside a container:
    // every still-planned control reads Failed and names the stage.
    let controls = os_controls(&policy_with_tools(), WindowsNativeMechanism::AppContainer);
    let err = WinSpawnError {
        stage: WinStage::Grants,
        source: WardenError::sandbox_setup(
            crate::error::SandboxStage::Apply,
            "enable_loopback".to_string(),
        ),
    };
    let obs = os_spawn_observations(
        &controls,
        &[],
        Some(&err),
        WindowsNativeMechanism::AppContainer,
    );
    assert!(!obs.is_empty());
    for o in &obs {
        assert_eq!(o.state, ControlState::Failed, "{}", o.control);
        assert!(
            o.reason
                .as_deref()
                .unwrap_or_default()
                .contains("grant-application"),
            "{}",
            o.control
        );
    }
}

#[cfg(target_os = "windows")]
#[test]
fn prepare_source_failure_through_spawn_outcome_assembly() {
    // `windows_spawn_outcome` is the outcome assembly
    // `spawn_child_async_impl` runs for a Windows launch: the
    // observations are produced while the controls are still
    // `Planned`, so a `Prepare`-sourced setup abort yields
    // per-control evidence (never an empty result), and only then
    // does the plan agree by failing the same controls — with the
    // pipeline stage named in the reason.
    let mut controls = os_controls(&policy_with_tools(), WindowsNativeMechanism::AppContainer);
    let planned_ids: Vec<&'static str> = controls
        .iter()
        .filter(|c| c.layer == ControlLayer::Os && c.state == ControlState::Planned)
        .map(|c| c.id)
        .collect();
    assert!(!planned_ids.is_empty());
    let err = WinSpawnError {
        stage: WinStage::ProcessSetup,
        source: WardenError::sandbox_setup(
            crate::error::SandboxStage::Prepare,
            "CreatePipe".to_string(),
        ),
    };
    let obs = windows_spawn_outcome(
        &mut controls,
        &[],
        Some(&err),
        WindowsNativeMechanism::AppContainer,
    );
    assert_eq!(obs.len(), planned_ids.len());
    for o in &obs {
        assert_eq!(o.state, ControlState::Failed, "{}", o.control);
        assert!(
            o.reason
                .as_deref()
                .unwrap_or_default()
                .contains("process-setup"),
            "{}",
            o.control
        );
    }
    for c in controls
        .iter()
        .filter(|c| c.layer == ControlLayer::Os && planned_ids.contains(&c.id))
    {
        assert_eq!(c.state, ControlState::Failed, "{}", c.id);
        assert!(
            c.reason
                .as_deref()
                .unwrap_or_default()
                .contains("process-setup"),
            "{}",
            c.id
        );
    }
    for c in controls
        .iter()
        .filter(|c| c.layer == ControlLayer::Os && !planned_ids.contains(&c.id))
    {
        assert_ne!(c.state, ControlState::Failed, "{}", c.id);
    }

    // A `Prepare`-sourced failure at a *post-create* stage — e.g.
    // `CreateJobObjectW` failing inside `job-setup` — does not
    // collapse the plan: a real container process existed, so the
    // observations carry `os.process` as `Failed` while controls
    // whose apply work completed keep their mechanism outcomes.
    let mut controls = os_controls(&policy_with_tools(), WindowsNativeMechanism::AppContainer);
    let before: Vec<(&'static str, ControlState)> = controls
        .iter()
        .filter(|c| c.layer == ControlLayer::Os)
        .map(|c| (c.id, c.state))
        .collect();
    let err = WinSpawnError {
        stage: WinStage::JobSetup,
        source: WardenError::sandbox_setup(
            crate::error::SandboxStage::Prepare,
            "CreateJobObjectW".to_string(),
        ),
    };
    let obs = windows_spawn_outcome(
        &mut controls,
        &[],
        Some(&err),
        WindowsNativeMechanism::AppContainer,
    );
    for (id, state) in before {
        let c = controls.iter().find(|c| c.id == id).unwrap();
        assert_eq!(
            c.state, state,
            "post-create failure must not change plan state: {id}"
        );
    }
    let get = |id: &str| obs.iter().find(|o| o.control == id).unwrap();
    assert_eq!(get("os.process").state, ControlState::Failed);
    assert_eq!(get("os.fs").state, ControlState::Verified);
    assert!(
        get("os.fs")
            .reason
            .as_deref()
            .unwrap_or_default()
            .contains("job-setup"),
        "applied controls must name the abort stage"
    );
}

#[cfg(target_os = "windows")]
#[test]
fn process_spawn_error_leaves_controls_unknown() {
    // CreateProcessW fuses the attribute and image checks — the
    // failing stage is undetermined, so the controls read Unknown
    // (SpawnResult), not Failed.
    let controls = os_controls(&policy_with_tools(), WindowsNativeMechanism::AppContainer);
    let err = WinSpawnError {
        stage: WinStage::CreateProcess,
        source: WardenError::ProcessSpawn(std::io::Error::from_raw_os_error(2)),
    };
    let obs = os_spawn_observations(
        &controls,
        &[],
        Some(&err),
        WindowsNativeMechanism::AppContainer,
    );
    assert!(!obs.is_empty());
    for o in &obs {
        assert_eq!(o.state, ControlState::Unknown, "{}", o.control);
        assert_eq!(o.basis, ObservationBasis::SpawnResult, "{}", o.control);
    }
}

#[cfg(target_os = "windows")]
#[test]
fn post_create_abort_fails_os_process_but_keeps_apply_outcomes() {
    // A Job/execution-start failure ran against a real suspended
    // container process: os.process reads Failed while controls
    // whose apply work provably completed keep their mechanism
    // outcomes — with the abort named in the reason.
    let controls = os_controls(&policy_with_tools(), WindowsNativeMechanism::AppContainer);
    let err = WinSpawnError {
        stage: WinStage::Job,
        source: WardenError::sandbox_setup(
            crate::error::SandboxStage::Apply,
            "AssignProcessToJobObject".to_string(),
        ),
    };
    let obs = os_spawn_observations(
        &controls,
        &[],
        Some(&err),
        WindowsNativeMechanism::AppContainer,
    );
    let get = |id: &str| obs.iter().find(|o| o.control == id).unwrap();
    assert_eq!(get("os.process").state, ControlState::Failed);
    assert!(
        get("os.process")
            .reason
            .as_deref()
            .unwrap_or_default()
            .contains("job-assignment")
    );
    let fs = get("os.fs");
    assert_eq!(fs.state, ControlState::Verified);
    assert!(
        fs.reason
            .as_deref()
            .unwrap_or_default()
            .contains("job-assignment")
    );
}

#[cfg(target_os = "windows")]
#[test]
fn post_create_abort_os_process_names_the_mechanisms_location() {
    // The os.process failure names where the suspended process lived:
    // the AppContainer container, or the PSEC security environment.
    let err = WinSpawnError {
        stage: WinStage::Job,
        source: WardenError::sandbox_setup(
            crate::error::SandboxStage::Apply,
            "AssignProcessToJobObject".to_string(),
        ),
    };
    let reason_of = |mechanism: WindowsNativeMechanism| {
        let controls = os_controls(&policy_with_tools(), mechanism);
        os_spawn_observations(&controls, &[], Some(&err), mechanism)
            .into_iter()
            .find(|o| o.control == "os.process")
            .unwrap()
            .reason
            .unwrap()
    };
    assert!(
        reason_of(WindowsNativeMechanism::AppContainer).contains("inside the container"),
        "appcontainer reason should name the container"
    );
    assert!(
        reason_of(WindowsNativeMechanism::Psec).contains("inside the security environment"),
        "psec reason should name the security environment"
    );
}

#[cfg(target_os = "windows")]
#[test]
fn psec_outbound_observation_counts_applied_allow_rules() {
    // The spawn path promotes spec grants Planned → Verified once the
    // environment exists — the observation must read either state or
    // every successful launch would report zero allow rules.
    let mut policy = policy_with_tools();
    policy.network.outbound.allowed = vec!["10.0.0.1".to_string(), "10.0.0.2".to_string()];
    let controls = os_controls(&policy, WindowsNativeMechanism::Psec);
    assert!(controls.iter().any(
        |c| c.id == "os.net.outbound" && c.state == ControlState::Planned
    ));
    let grant = |name: &str, state: ControlState| ProcessGrant {
        subject: GrantSubject::Rule {
            kind: "net_destination",
            name: name.to_string(),
        },
        origin: GrantOrigin::Policy,
        state,
        reason: None,
    };
    let find = |grants: &[ProcessGrant]| {
        os_spawn_observations(&controls, grants, None, WindowsNativeMechanism::Psec)
            .into_iter()
            .find(|o| o.control == "os.net.outbound")
            .unwrap()
    };
    let verified = find(&[
        grant("10.0.0.1", ControlState::Verified),
        grant("10.0.0.2", ControlState::Verified),
    ]);
    assert_eq!(verified.state, ControlState::Verified);
    assert!(
        verified
            .reason
            .as_deref()
            .unwrap_or_default()
            .contains("2 IPv4"),
        "{verified:?}"
    );
    // Entries a failed env-create left Skipped are not counted.
    let mixed = find(&[
        grant("10.0.0.1", ControlState::Verified),
        grant("10.0.0.2", ControlState::Skipped),
    ]);
    assert!(
        mixed
            .reason
            .as_deref()
            .unwrap_or_default()
            .contains("1 IPv4"),
        "{mixed:?}"
    );
}

#[cfg(target_os = "windows")]
#[test]
fn loopback_observation_reflects_exemption_outcome() {
    // HTTP transport plans the loopback exemption as its own control;
    // the observation mirrors the recorded grant result.
    let policy = {
        let mut p = policy_with_tools();
        p.transport.type_ = TransportType::Http;
        p
    };
    let controls = os_controls(&policy, WindowsNativeMechanism::AppContainer);
    assert!(
        controls
            .iter()
            .any(|c| c.id == "os.net.loopback" && c.state == ControlState::Planned)
    );

    let grant = |state: ControlState| ProcessGrant {
        subject: GrantSubject::Rule {
            kind: "loopback_exemption",
            name: "localhost".to_string(),
        },
        origin: GrantOrigin::Runtime,
        state,
        reason: None,
    };
    let find = |grants: &[ProcessGrant]| {
        os_spawn_observations(
            &controls,
            grants,
            None,
            WindowsNativeMechanism::AppContainer,
        )
        .into_iter()
        .find(|o| o.control == "os.net.loopback")
        .unwrap()
    };
    assert_eq!(
        find(&[grant(ControlState::Verified)]).state,
        ControlState::Verified
    );
    assert_eq!(
        find(&[grant(ControlState::Unknown)]).state,
        ControlState::Unknown
    );

    // Non-HTTP policy leaves the control NotApplicable — no
    // observation is emitted for it.
    let controls = os_controls(&policy_with_tools(), WindowsNativeMechanism::AppContainer);
    let obs = os_spawn_observations(&controls, &[], None, WindowsNativeMechanism::AppContainer);
    assert!(obs.iter().all(|o| o.control != "os.net.loopback"));
}

#[test]
fn sandbox_skip_marks_os_controls_and_grants_nothing() {
    let policy = policy_with_tools();
    let sandboxed = build_plan(
        &policy,
        None,
        "child",
        &SpawnOptions::default(),
        None,
        false,
        WindowsNativeMechanism::AppContainer,
    );
    let plan = build_plan(
        &policy,
        None,
        "child",
        &SpawnOptions::default(),
        Some("dry-run"),
        true,
        WindowsNativeMechanism::AppContainer,
    );
    // Every OS control that was Planned in the sandboxed plan is
    // Skipped here; build-time states (NotApplicable / NotApplied)
    // survive — they would not have applied anyway.
    for normal in sandboxed
        .controls
        .iter()
        .filter(|c| c.layer == ControlLayer::Os)
    {
        let skipped = plan.controls.iter().find(|c| c.id == normal.id).unwrap();
        match normal.state {
            ControlState::Planned => assert_eq!(
                skipped.state,
                ControlState::Skipped,
                "{} should be skipped",
                normal.id
            ),
            other => assert_eq!(skipped.state, other, "{} should keep its state", normal.id),
        }
    }
    assert!(plan.grants.is_empty());
    // RPC-layer enforcement is not part of the OS sandbox and stays
    // planned, carrying the dry-run qualifier.
    assert_eq!(control_state(&plan, "rpc.tools").0, ControlState::Planned);
    assert!(control_state(&plan, "rpc.tools").1.contains("dry-run"));
}

// -- macOS spawn-fact → observation mapping ------------------------
// sandbox-exec exposes no kernel-acceptance query: the domain
// controls must stay Unknown, while the launch itself (`os.sandbox`)
// records the facts the mechanism does produce.

#[cfg(target_os = "macos")]
mod macos_observations {
    use super::*;
    use crate::warden::macos_sandbox::SpawnLiveness;
    use std::os::unix::process::ExitStatusExt;

    fn controls() -> Vec<PlannedControl> {
        os_controls(&policy_with_tools(), WindowsNativeMechanism::AppContainer)
    }

    fn state_of(obs: &[EnforcementObservation], id: &str) -> ControlState {
        obs.iter().find(|o| o.control == id).unwrap().state
    }

    fn exited() -> SpawnLiveness {
        SpawnLiveness::Exited(std::process::ExitStatus::from_raw(3 << 8))
    }

    #[test]
    fn os_sandbox_is_a_planned_sandbox_exec_control() {
        let c = controls()
            .into_iter()
            .find(|c| c.id == "os.sandbox")
            .expect("os.sandbox control must exist");
        assert_eq!(c.state, ControlState::Planned);
        assert_eq!(c.mechanism, "sandbox-exec");
    }

    #[test]
    fn surviving_child_verifies_the_launch_only() {
        let obs = os_spawn_observations(&controls(), None, Some(&SpawnLiveness::Running));
        let launch = obs.iter().find(|o| o.control == "os.sandbox").unwrap();
        assert_eq!(launch.state, ControlState::Verified);
        assert_eq!(launch.basis, ObservationBasis::SpawnResult);
        // A live process is not kernel acceptance: every SBPL domain
        // stays Unknown rather than being upgraded on inference.
        for id in ["os.fs", "os.net.outbound", "os.process"] {
            assert_eq!(state_of(&obs, id), ControlState::Unknown, "{id}");
        }
        let fs = obs.iter().find(|o| o.control == "os.fs").unwrap();
        assert!(fs.reason.as_deref().unwrap().contains("not observable"));
    }

    #[test]
    fn spawn_error_fails_every_planned_control() {
        // A spawn() error means sandbox-exec never ran — nothing was
        // applied, so the controls read Failed, not Unknown.
        let err = std::io::Error::from_raw_os_error(libc::ENOENT);
        let obs = os_spawn_observations(&controls(), Some(&err), None);
        for id in ["os.sandbox", "os.fs", "os.net.outbound", "os.process"] {
            assert_eq!(state_of(&obs, id), ControlState::Failed, "{id}");
        }
    }

    #[test]
    fn early_exit_leaves_launch_and_rules_unknown() {
        // The process died inside the window: the exit status is the
        // child's recorded termination state, but a short-lived
        // workload ends the same way — the exit alone is not evidence
        // the kernel rejected the profile, so the launch stays
        // Unknown (basis SpawnResult) and the domains stay Unknown.
        let obs = os_spawn_observations(&controls(), None, Some(&exited()));
        let launch = obs.iter().find(|o| o.control == "os.sandbox").unwrap();
        assert_eq!(launch.state, ControlState::Unknown);
        assert_eq!(launch.basis, ObservationBasis::SpawnResult);
        assert!(launch.reason.as_deref().unwrap().contains("exit status: 3"));
        for id in ["os.fs", "os.net.outbound", "os.process"] {
            assert_eq!(state_of(&obs, id), ControlState::Unknown, "{id}");
            let reason = obs
                .iter()
                .find(|o| o.control == id)
                .unwrap()
                .reason
                .clone()
                .unwrap();
            assert!(reason.contains("exited"), "{id}: {reason}");
        }
    }

    #[test]
    fn failed_liveness_probe_stays_unknown() {
        let obs = os_spawn_observations(&controls(), None, Some(&SpawnLiveness::PollFailed));
        assert_eq!(state_of(&obs, "os.sandbox"), ControlState::Unknown);
        assert_eq!(state_of(&obs, "os.fs"), ControlState::Unknown);
    }

    #[test]
    fn build_observation_covers_generation_not_acceptance() {
        let ok = macos_prepare_observation(None);
        assert_eq!(ok.control, "os.sandbox");
        assert_eq!(ok.state, ControlState::Verified);
        assert_eq!(ok.phase, ControlPhase::Build);
        assert_eq!(ok.basis, ObservationBasis::VerificationRun);

        let err =
            WardenError::sandbox_setup(crate::error::SandboxStage::Policy, "boom".to_string());
        let bad = macos_prepare_observation(Some(("profile build failed", &err)));
        assert_eq!(bad.state, ControlState::Failed);
        assert_eq!(bad.phase, ControlPhase::Build);
        assert!(
            bad.reason
                .as_deref()
                .unwrap()
                .contains("profile build failed")
        );
    }
}
