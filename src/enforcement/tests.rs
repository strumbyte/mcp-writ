use super::*;
use crate::audit_log::PolicyAuditContext;
use crate::execution::{ExecutionSubstrate, ExecutionTarget, TargetArch, TargetOs};
use uuid::Uuid;

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
            native_windows_mechanism: None,
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
            egress_layers: None,
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
        code_identity: Some(CodeIdentity {
            kind: IdentityKind::InterpretedScript,
            resolved: Some("/usr/bin/python3".to_string()),
            pins: vec![
                IdentityPin {
                    hash_type: "binary-hash",
                    target: "/usr/bin/python3".to_string(),
                    hash: "sha256:aaa".to_string(),
                    role: PinRole::ExecImage,
                    checks: vec![
                        PinCheck::Initial,
                        PinCheck::BindPath,
                        PinCheck::BindContent,
                        PinCheck::PreSpawnPath,
                        PinCheck::PreSpawnContent,
                    ],
                },
                IdentityPin {
                    hash_type: "entrypoint-hash",
                    target: "/srv/server.py".to_string(),
                    hash: "sha256:bbb".to_string(),
                    role: PinRole::PayloadFile,
                    checks: vec![
                        PinCheck::Initial,
                        PinCheck::BindPath,
                        PinCheck::BindContent,
                        PinCheck::PreSpawnPath,
                        PinCheck::PreSpawnContent,
                    ],
                },
                IdentityPin {
                    hash_type: "lockfile-hash",
                    target: "/srv/requirements.txt".to_string(),
                    hash: "sha256:ccc".to_string(),
                    role: PinRole::DependencyList,
                    checks: vec![PinCheck::Initial],
                },
            ],
            pinned: vec!["the interpreter image and the script content".to_string()],
            mutable: vec![
                "nothing holds the pinned files immutable between the last check and exec"
                    .to_string(),
            ],
        }),
        guest_runner: None,
        guest: None,
        isolation: Some(IsolationRecord {
            configured: crate::execution::IsolationKind::Container,
            verified: Some(crate::execution::IsolationKind::Container),
            unit: Some(crate::execution::IsolationUnit::Container),
            unit_id: Some("9f1c3ab2".to_string()),
            detail: None,
        }),
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
    // Code identity keeps the launch shape, the per-pin roles, and
    // the check points distinct.
    let identity = member(root, "code_identity");
    assert_eq!(
        member(identity, "kind").as_string_str().unwrap(),
        "interpreted_script"
    );
    assert_eq!(
        member(identity, "resolved").as_string_str().unwrap(),
        "/usr/bin/python3"
    );
    let pins: Vec<_> = member(identity, "pins").to_array().unwrap().collect();
    assert_eq!(pins.len(), 3);
    assert_eq!(
        member(pins[0], "type").as_string_str().unwrap(),
        "binary-hash"
    );
    assert_eq!(
        member(pins[0], "role").as_string_str().unwrap(),
        "exec_image"
    );
    assert_eq!(
        member(pins[1], "role").as_string_str().unwrap(),
        "payload_file"
    );
    assert_eq!(
        member(pins[2], "role").as_string_str().unwrap(),
        "dependency_list"
    );
    let checks: Vec<_> = member(pins[0], "checks")
        .to_array()
        .unwrap()
        .map(|c| c.as_string_str().unwrap().to_string())
        .collect();
    assert_eq!(
        checks,
        [
            "initial",
            "bind_path",
            "bind_content",
            "pre_spawn_path",
            "pre_spawn_content"
        ]
    );
    assert_eq!(
        member(pins[2], "checks")
            .to_array()
            .unwrap()
            .map(|c| c.as_string_str().unwrap().to_string())
            .collect::<Vec<_>>(),
        ["initial"]
    );
    assert_eq!(member(identity, "pinned").to_array().unwrap().count(), 1);
    assert_eq!(member(identity, "mutable").to_array().unwrap().count(), 1);
    // The isolation record keeps the configured request, the
    // backend-confirmed kind, the unit granularity, and the unit
    // identifier as separate members.
    let isolation = member(root, "isolation");
    assert_eq!(
        member(isolation, "configured").as_string_str().unwrap(),
        "container"
    );
    assert_eq!(
        member(isolation, "verified").as_string_str().unwrap(),
        "container"
    );
    assert_eq!(
        member(isolation, "unit").as_string_str().unwrap(),
        "container"
    );
    assert_eq!(
        member(isolation, "unit_id").as_string_str().unwrap(),
        "9f1c3ab2"
    );
}

#[test]
fn egress_layers_serializes_the_correspondence_table() {
    // `plan.egress_layers` carries the name-layer/IP-layer rule table
    // and the per-layer disposition — the shape `plan` output and
    // `--report` consumers read.
    let mut report = sample_report();
    report.plan.egress_layers = Some(EgressLayersPlan {
        default_action: "deny_all",
        rules: vec![
            EgressRuleReport {
                effect: "allow",
                kind: "host",
                rule: "api.example.com".to_string(),
                name_layer: true,
                ip_layer: false,
                proto: Some("tcp"),
                port: None,
            },
            EgressRuleReport {
                effect: "allow",
                kind: "host",
                rule: "192.0.2.10".to_string(),
                name_layer: true,
                ip_layer: true,
                proto: Some("tcp"),
                port: None,
            },
            EgressRuleReport {
                effect: "deny",
                kind: "cidr",
                rule: "169.254.0.0/16".to_string(),
                name_layer: false,
                ip_layer: true,
                proto: None,
                port: None,
            },
        ],
        layers: vec![
            EgressLayerStatus {
                layer: "name",
                rpc: "auditor",
                os: None,
                note: Some("no destination-name mechanism on this path".to_string()),
            },
            EgressLayerStatus {
                layer: "ip",
                rpc: "auditor",
                os: Some("psec".to_string()),
                note: None,
            },
        ],
    });
    let json = report.to_json();
    let parsed = nojson::RawJson::parse(&json).expect("valid json");
    let egress = member(member(parsed.value(), "plan"), "egress_layers");
    assert_eq!(
        member(egress, "default_action").as_string_str().unwrap(),
        "deny_all"
    );
    let rules: Vec<_> = member(egress, "rules").to_array().unwrap().collect();
    assert_eq!(rules.len(), 3);
    assert_eq!(member(rules[0], "kind").as_string_str().unwrap(), "host");
    assert_eq!(
        member(rules[0], "rule").as_string_str().unwrap(),
        "api.example.com"
    );
    assert_eq!(
        member(rules[0], "name_layer").as_boolean_str().unwrap(),
        "true"
    );
    // The literal-IP host row lands on both layers; the cidr row on
    // the IP layer only.
    assert_eq!(
        member(rules[1], "ip_layer").as_boolean_str().unwrap(),
        "true"
    );
    assert_eq!(
        member(rules[2], "name_layer").as_boolean_str().unwrap(),
        "false"
    );
    let layers: Vec<_> = member(egress, "layers").to_array().unwrap().collect();
    assert_eq!(layers.len(), 2);
    assert_eq!(member(layers[1], "os").as_string_str().unwrap(), "psec");
    assert!(member(layers[0], "os").kind().is_null());
    assert_eq!(member(layers[0], "rpc").as_string_str().unwrap(), "auditor");
}

#[test]
fn isolation_record_serializes_configured_vs_verified() {
    // A launch refused before the backend confirmed anything:
    // `configured` records the request, `verified`/`unit`/`unit_id`
    // stay null rather than claiming an applied boundary.
    let mut report = sample_report();
    report.isolation = Some(IsolationRecord {
        configured: crate::execution::IsolationKind::Kata,
        verified: None,
        unit: None,
        unit_id: None,
        detail: Some("isolation method 'kata' is not implemented".to_string()),
    });
    let json = report.to_json();
    let parsed = nojson::RawJson::parse(&json).expect("valid json");
    let isolation = member(parsed.value(), "isolation");
    assert_eq!(
        member(isolation, "configured").as_string_str().unwrap(),
        "kata"
    );
    assert!(member(isolation, "verified").kind().is_null());
    assert!(member(isolation, "unit").kind().is_null());
    assert!(member(isolation, "unit_id").kind().is_null());
    assert!(
        member(isolation, "detail")
            .as_string_str()
            .unwrap()
            .contains("not implemented")
    );

    // No isolation backend involved → the member is JSON null.
    let mut report = sample_report();
    report.isolation = None;
    let json = report.to_json();
    let parsed = nojson::RawJson::parse(&json).expect("valid json");
    assert!(member(parsed.value(), "isolation").kind().is_null());
}

#[test]
fn identity_kinds_roles_and_checks_serialize_distinctly() {
    let mut seen = std::collections::HashSet::new();
    for k in [
        IdentityKind::NativeFile,
        IdentityKind::InterpretedScript,
        IdentityKind::LauncherOrModule,
        IdentityKind::InlineEval,
        IdentityKind::ImageDigest,
        IdentityKind::ImageTag,
    ] {
        assert!(seen.insert(k.as_str()), "duplicate kind: {}", k.as_str());
    }
    let mut seen = std::collections::HashSet::new();
    for r in [
        PinRole::ExecImage,
        PinRole::PayloadFile,
        PinRole::DependencyList,
        PinRole::ImageManifest,
    ] {
        assert!(seen.insert(r.as_str()), "duplicate role: {}", r.as_str());
    }
    let mut seen = std::collections::HashSet::new();
    for c in [
        PinCheck::Initial,
        PinCheck::BindPath,
        PinCheck::BindContent,
        PinCheck::PreSpawnPath,
        PinCheck::PreSpawnContent,
        PinCheck::ImageInspect,
    ] {
        assert!(seen.insert(c.as_str()), "duplicate check: {}", c.as_str());
    }
}

#[test]
fn code_identity_absent_serializes_null() {
    let mut report = sample_report();
    report.code_identity = None;
    let json = report.to_json();
    let parsed = nojson::RawJson::parse(&json).expect("valid json");
    let root = parsed.value();
    assert!(
        member(root, "code_identity").kind().is_null(),
        "unassessed identity must serialize null"
    );
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
    assert!(
        member(root, "plan").kind().is_null(),
        "uncomputed plan must serialize null"
    );
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

// ─── EnforcementSummary (`enforcement` JSONL member) ──────────────

fn sctrl(id: &'static str, mechanism: &'static str, state: ControlState) -> PlannedControl {
    PlannedControl {
        id,
        layer: ControlLayer::Os,
        mechanism,
        state,
        reason: None,
    }
}

fn sgrant(subject: GrantSubject, state: ControlState, reason: Option<&str>) -> ProcessGrant {
    ProcessGrant {
        subject,
        origin: GrantOrigin::Policy,
        state,
        reason: reason.map(str::to_string),
    }
}

fn sobs(
    control: &'static str,
    state: ControlState,
    reason: Option<String>,
) -> EnforcementObservation {
    EnforcementObservation {
        control,
        state,
        basis: ObservationBasis::MechanismResult,
        phase: ControlPhase::Spawn,
        reason,
    }
}

fn net_rule(name: &str) -> GrantSubject {
    GrantSubject::Rule {
        kind: "net_destination",
        name: name.to_string(),
    }
}

#[test]
fn backend_names_are_stable() {
    assert_eq!(SandboxBackend::LandlockSeccomp.as_str(), "landlock+seccomp");
    assert_eq!(SandboxBackend::AppContainer.as_str(), "appcontainer");
    assert_eq!(SandboxBackend::Psec.as_str(), "psec");
    assert_eq!(SandboxBackend::SandboxExec.as_str(), "sandbox-exec");
    assert_eq!(SandboxBackend::None.as_str(), "none");
}

/// Effective control state = the observation where one exists, else
/// the plan state — the audit reader never reconciles the lists.
#[test]
fn summary_controls_take_observation_over_plan_state() {
    let plan = EnforcementPlan {
        controls: vec![
            sctrl("os.fs", "landlock", ControlState::Planned),
            sctrl("os.privileges", "no_new_privs", ControlState::Planned),
        ],
        grants: vec![],
        tools: vec![],
        limitations: vec![],
        egress_layers: None,
    };
    let observations = vec![sobs("os.fs", ControlState::Verified, None)];
    let s = EnforcementSummary::build(&plan, &observations, SandboxBackend::LandlockSeccomp, false);
    assert_eq!(s.controls.len(), 2);
    assert_eq!(s.controls[0].state, ControlState::Verified);
    assert_eq!(s.controls[1].state, ControlState::Planned);
    assert_eq!(s.controls_applied, 1);
}

/// The Landlock `restrict_self reported <level>` marker in an
/// observation reason parses back to `restriction` — the same
/// vocabulary the report reason carries, not a second judgment.
#[test]
fn summary_restriction_reads_landlock_marker() {
    let plan = EnforcementPlan {
        controls: vec![],
        grants: vec![],
        tools: vec![],
        limitations: vec![],
        egress_layers: None,
    };
    for (reason, want) in [
        (
            "restrict_self reported FullyEnforced (kernel Landlock ABI v3)",
            Some("fully_enforced"),
        ),
        (
            "restrict_self reported PartiallyEnforced; tolerated by sandbox.allow_degraded",
            Some("partially_enforced"),
        ),
        (
            "restrict_self reported NotEnforced; tolerated by sandbox.allow_degraded",
            Some("not_enforced"),
        ),
        ("no marker here", None),
    ] {
        let obs = vec![sobs(
            "os.fs",
            ControlState::Verified,
            Some(reason.to_string()),
        )];
        let s = EnforcementSummary::build(&plan, &obs, SandboxBackend::LandlockSeccomp, false);
        assert_eq!(s.restriction, want, "reason: {reason}");
    }
}

/// Grant counts split per state; `skipped` entries get bounded
/// human labels (`fs_path:<path> (<access>) — <reason>`).
#[test]
fn summary_grants_count_and_skipped_labels() {
    let plan = EnforcementPlan {
        controls: vec![],
        grants: vec![
            sgrant(
                GrantSubject::FsPath {
                    path: "/data".to_string(),
                    access: FsAccess::Read,
                },
                ControlState::Verified,
                None,
            ),
            sgrant(
                GrantSubject::FsPath {
                    path: "/gone".to_string(),
                    access: FsAccess::Read,
                },
                ControlState::Skipped,
                Some("path does not exist"),
            ),
            sgrant(
                GrantSubject::TcpConnect { port: 443 },
                ControlState::Failed,
                Some("ruleset refused"),
            ),
        ],
        tools: vec![],
        limitations: vec![],
        egress_layers: None,
    };
    let s = EnforcementSummary::build(&plan, &[], SandboxBackend::None, true);
    assert_eq!(s.grants.verified, 1);
    assert_eq!(s.grants.skipped, 1);
    assert_eq!(s.grants.failed, 1);
    assert_eq!(s.skipped_grants.len(), 1);
    assert!(s.skipped_grants[0].contains("fs_path:/gone (read)"));
    assert!(s.skipped_grants[0].contains("path does not exist"));
}

/// Beyond `SKIPPED_GRANT_SUMMARY_CAP` the list folds into a
/// `"(+N more)"` tail — the line stays bounded.
#[test]
fn summary_skipped_grants_cap() {
    let grants: Vec<ProcessGrant> = (0..10)
        .map(|i| {
            sgrant(
                GrantSubject::Syscall {
                    name: format!("sc_{i}"),
                },
                ControlState::Skipped,
                None,
            )
        })
        .collect();
    let plan = EnforcementPlan {
        controls: vec![],
        grants,
        tools: vec![],
        limitations: vec![],
        egress_layers: None,
    };
    let s = EnforcementSummary::build(&plan, &[], SandboxBackend::None, false);
    assert_eq!(s.grants.skipped, 10);
    assert_eq!(s.skipped_grants.len(), SKIPPED_GRANT_SUMMARY_CAP + 1);
    assert_eq!(s.skipped_grants.last().unwrap().as_str(), "(+2 more)");
}

/// The `psec` member exists only on a PSEC launch; the egress counts
/// come from the plan's `net_destination` grants (accepted vs
/// refused), and the deny-by-default posture from the
/// `os.net.outbound` control.
#[test]
fn summary_psec_member_counts_egress() {
    let plan = EnforcementPlan {
        controls: vec![sctrl("os.net.outbound", "psec", ControlState::Planned)],
        grants: vec![
            sgrant(net_rule("10.0.0.1"), ControlState::Planned, None),
            sgrant(net_rule("10.0.0.2"), ControlState::Verified, None),
            sgrant(
                net_rule("0.0.0.0"),
                ControlState::NotApplied,
                Some("unrestricted egress is not expressible"),
            ),
            sgrant(
                GrantSubject::FsPath {
                    path: "C:\\x".to_string(),
                    access: FsAccess::Read,
                },
                ControlState::NotApplied,
                Some("unrelated refusal"),
            ),
        ],
        tools: vec![],
        limitations: vec![],
        egress_layers: None,
    };
    let s = EnforcementSummary::build(&plan, &[], SandboxBackend::Psec, false);
    let p = s.psec.expect("psec member must exist for backend=psec");
    assert_eq!(p.schema_version, "1.0");
    assert!(p.egress_default_deny);
    assert_eq!(p.egress_allow_rules, 2);
    assert_eq!(p.egress_rules_refused, 1);
    // Non-PSEC backends never carry the member.
    let s = EnforcementSummary::build(&plan, &[], SandboxBackend::AppContainer, false);
    assert!(s.psec.is_none());
}

/// `os.net.outbound` refused or failed → no deny-by-default claim;
/// the flag reads the *effective* state (observation over plan), so
/// a `planned` control the apply recorded `failed` still reads false.
#[test]
fn summary_psec_egress_deny_reflects_control_state() {
    let plan = EnforcementPlan {
        controls: vec![sctrl("os.net.outbound", "psec", ControlState::NotApplied)],
        grants: vec![],
        tools: vec![],
        limitations: vec![],
        egress_layers: None,
    };
    let s = EnforcementSummary::build(&plan, &[], SandboxBackend::Psec, false);
    assert!(!s.psec.unwrap().egress_default_deny);

    let plan = EnforcementPlan {
        controls: vec![sctrl("os.net.outbound", "psec", ControlState::Planned)],
        grants: vec![],
        tools: vec![],
        limitations: vec![],
        egress_layers: None,
    };
    let observations = vec![sobs("os.net.outbound", ControlState::Failed, None)];
    let s = EnforcementSummary::build(&plan, &observations, SandboxBackend::Psec, false);
    assert!(!s.psec.unwrap().egress_default_deny);
}

/// The serialized member is a JSON object with the stable member
/// names audit consumers parse.
#[test]
fn summary_to_json_shape() {
    let plan = EnforcementPlan {
        controls: vec![sctrl("os.fs", "landlock", ControlState::Planned)],
        grants: vec![sgrant(
            GrantSubject::FsPath {
                path: "/data".to_string(),
                access: FsAccess::Read,
            },
            ControlState::Skipped,
            Some("gone"),
        )],
        tools: vec![],
        limitations: vec![],
        egress_layers: None,
    };
    let observations = vec![sobs(
        "os.fs",
        ControlState::Verified,
        Some("restrict_self reported FullyEnforced".to_string()),
    )];
    let s = EnforcementSummary::build(&plan, &observations, SandboxBackend::LandlockSeccomp, false);
    let json = s.to_json();
    let parsed = nojson::RawJson::parse(json.as_str()).expect("valid json");
    let root = parsed.value();
    assert_eq!(
        member(root, "backend").as_string_str().unwrap(),
        "landlock+seccomp"
    );
    assert_eq!(
        member(root, "restriction").as_string_str().unwrap(),
        "fully_enforced"
    );
    assert_eq!(member(root, "controls_applied").as_raw_str(), "1");
    let controls = member(root, "controls");
    assert_eq!(controls.kind(), nojson::JsonValueKind::Array);
    let grants = member(root, "grants");
    assert_eq!(member(grants, "skipped").as_raw_str(), "1");
    let skipped = member(root, "skipped_grants");
    assert_eq!(skipped.kind(), nojson::JsonValueKind::Array);
    assert!(
        member(root, "psec").kind().is_null(),
        "psec must serialize null"
    );
    assert_eq!(member(root, "dry_run").as_raw_str(), "false");
}
