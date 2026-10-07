//! Windows controls and spawn observations — the AppContainer + Job
//! pipeline or the opt-in PSEC security environment selected by
//! `--windows-mechanism`; per-control evidence comes from the
//! `WinSpawnError` stage and the recorded grant outcomes.

use std::path::Path;

use crate::enforcement::{
    ControlLayer, ControlPhase, ControlState, EnforcementObservation, GrantOrigin, GrantSubject,
    ObservationBasis, PlannedControl, ProcessGrant,
};
use crate::error::WardenError;
use crate::execution::WindowsNativeMechanism;
use crate::policy::{Policy, TransportType};

use super::super::SpawnOptions;
use super::super::windows_sandbox::{WinSpawnError, WinStage};
use super::{control, fail_os_controls, observation, planned};

pub(crate) fn os_controls(
    policy: &Policy,
    mechanism: WindowsNativeMechanism,
) -> Vec<PlannedControl> {
    if mechanism == WindowsNativeMechanism::Psec {
        return psec_controls(policy);
    }
    let lpac = super::super::windows_profile::lpac_enabled();
    let v = vec![
        control(
            "os.process",
            ControlLayer::Os,
            "appcontainer + job",
            ControlState::Planned,
            Some(
                if lpac {
                    "AppContainer profile + kill-on-close Job Object (LPAC mode via \
                 MCP_WRIT_WINDOWS_LPAC)"
                } else {
                    "AppContainer profile + kill-on-close Job Object"
                }
                .to_string(),
            ),
        ),
        planned("os.fs", ControlLayer::Os, "appcontainer + dacl"),
        if policy.network.outbound.deny_all_others {
            control(
                "os.net.outbound",
                ControlLayer::Os,
                "appcontainer capabilities",
                ControlState::Planned,
                Some("default-deny: no network capabilities are granted".to_string()),
            )
        } else {
            control(
                "os.net.outbound",
                ControlLayer::Os,
                "appcontainer capabilities",
                ControlState::Planned,
                Some(
                    "internetClient + privateNetworkClientServer (all-or-none; \
                     per-destination rules stay RPC-layer)"
                        .to_string(),
                ),
            )
        },
        if !policy.network.inbound.allow_listen {
            control(
                "os.net.inbound",
                ControlLayer::Os,
                "appcontainer capabilities",
                ControlState::NotApplicable,
                Some("no inbound listen requested".to_string()),
            )
        } else if policy.network.outbound.deny_all_others {
            control(
                "os.net.inbound",
                ControlLayer::Os,
                "appcontainer capabilities",
                ControlState::NotApplied,
                Some(
                    "inbound requires internet capabilities that outbound \
                     deny-all withholds"
                        .to_string(),
                ),
            )
        } else {
            control(
                "os.net.inbound",
                ControlLayer::Os,
                "appcontainer capabilities",
                ControlState::Planned,
                Some("internetClientServer".to_string()),
            )
        },
        if matches!(policy.transport.type_, TransportType::Http) {
            // A deliberate isolation *opening*: HTTP transport needs
            // loopback to the container, so the exemption is a mandatory
            // pipeline stage and gets its own control — an unconfirmed
            // exemption must not hide inside the capability grants.
            control(
                "os.net.loopback",
                ControlLayer::Os,
                "CheckNetIsolation loopback exemption",
                ControlState::Planned,
                Some("HTTP transport requires loopback to the container".to_string()),
            )
        } else {
            control(
                "os.net.loopback",
                ControlLayer::Os,
                "CheckNetIsolation loopback exemption",
                ControlState::NotApplicable,
                Some("no HTTP transport; loopback stays denied".to_string()),
            )
        },
        control(
            "os.syscalls",
            ControlLayer::Os,
            "seccomp",
            ControlState::NotApplicable,
            Some("no syscall allowlist mechanism on Windows".to_string()),
        ),
    ];
    v
}

/// OS controls for the `--windows-mechanism psec` path — a PSEC v1.0
/// security environment supplies the token, the fs lists and the egress
/// posture; the Job and pipes are the shared pipeline's. Controls that
/// the policy makes unexpressible stay `NotApplied` with the refusal
/// reason — the launch would abort at `policy-check`, so the plan names
/// it rather than planning enforcement that cannot exist.
fn psec_controls(policy: &Policy) -> Vec<PlannedControl> {
    vec![
        control(
            "os.process",
            ControlLayer::Os,
            "psec security-environment + job",
            ControlState::Planned,
            Some(
                "PSEC environment (schema v1.0) attached via \
                 PROC_THREAD_ATTRIBUTE_SECURITY_ENVIRONMENT; kill-on-close \
                 Job Object — conditional status, see \
                 docs/validation/windows-isolation.md"
                    .to_string(),
            ),
        ),
        planned("os.fs", ControlLayer::Os, "psec fs rules"),
        if policy.network.outbound.deny_all_others {
            let n = policy
                .network
                .outbound
                .allowed
                .iter()
                .filter(|e| crate::policy::validator::psec_ipv4_expressible(e))
                .count();
            control(
                "os.net.outbound",
                ControlLayer::Os,
                "psec egress policy",
                ControlState::Planned,
                Some(if n == 0 {
                    "egress default-deny".to_string()
                } else {
                    format!(
                        "egress default-deny + {n} IPv4 destination allow \
                         rule(s) — ports are not part of the policy model"
                    )
                }),
            )
        } else {
            control(
                "os.net.outbound",
                ControlLayer::Os,
                "psec egress policy",
                ControlState::NotApplied,
                Some(
                    "unrestricted egress is not expressible — the launch \
                     refuses"
                        .to_string(),
                ),
            )
        },
        if policy.network.inbound.allow_listen {
            control(
                "os.net.inbound",
                ControlLayer::Os,
                "psec egress policy",
                ControlState::NotApplied,
                Some("PSEC v1.0 has no ingress section — the launch refuses".to_string()),
            )
        } else {
            control(
                "os.net.inbound",
                ControlLayer::Os,
                "psec egress policy",
                ControlState::NotApplicable,
                Some("no inbound listen requested".to_string()),
            )
        },
        if matches!(policy.transport.type_, TransportType::Http) {
            control(
                "os.net.loopback",
                ControlLayer::Os,
                "none",
                ControlState::NotApplied,
                Some(
                    "egress rules do not exempt loopback and no exemption \
                     exists for a security environment — the launch refuses"
                        .to_string(),
                ),
            )
        } else {
            control(
                "os.net.loopback",
                ControlLayer::Os,
                "none",
                ControlState::NotApplicable,
                Some("no HTTP transport; loopback stays denied".to_string()),
            )
        },
        control(
            "os.syscalls",
            ControlLayer::Os,
            "seccomp",
            ControlState::NotApplicable,
            Some("no syscall allowlist mechanism on Windows".to_string()),
        ),
    ]
}

/// The Windows pipeline applies controls in the parent before and after
/// `CreateProcessW`; the call itself is authoritative for the container
/// token. The evidence is the [`WinSpawnError`] stage tag (plus the
/// per-grant record `spawn_sandboxed` fills as it applies):
///
/// - a *setup* abort (stages before `CreateProcessW`) means no container
///   process ever existed, so every still-planned control is `Failed`
///   with the stage named;
/// - a `CreateProcessW` failure fuses attribute and image checks —
///   undetermined, so controls read `Unknown`;
/// - a *post-create* abort (Job setup, Job assignment, or execution
///   start) ran against a real suspended container process: `os.process`
///   is `Failed`, while controls whose apply work had provably completed
///   keep that outcome with the abort appended to their reason — the
///   same convention as the Linux exec-failure path;
/// - a spawned child gives each control its mechanism result — the
///   container token for `os.process`, the ACL API results for `os.fs`,
///   the token capabilities for the net controls.
pub(crate) fn os_spawn_observations(
    controls: &[PlannedControl],
    grants: &[ProcessGrant],
    outcome: Option<&WinSpawnError>,
    mechanism: WindowsNativeMechanism,
) -> Vec<EnforcementObservation> {
    controls
        .iter()
        .filter(|c| c.layer == ControlLayer::Os && c.state == ControlState::Planned)
        .map(|c| match outcome {
            None => windows_success_observation(c, grants, None, mechanism),
            Some(err) => windows_abort_observation(c, grants, err, mechanism),
        })
        .collect()
}

/// Per-control outcome after a completed or post-create-aborted spawn.
/// `abort` is the post-`CreateProcessW` failure, when the spawn died
/// during Job setup, Job assignment, or execution start; it is appended
/// to the reason so the observation can never read as a live launch.
fn windows_success_observation(
    c: &PlannedControl,
    grants: &[ProcessGrant],
    abort: Option<&WinSpawnError>,
    mechanism: WindowsNativeMechanism,
) -> EnforcementObservation {
    let mut o = match c.id {
        "os.process" if mechanism == WindowsNativeMechanism::Psec => observation(
            c.id,
            ControlState::Verified,
            ObservationBasis::MechanismResult,
            ControlPhase::Spawn,
            Some(
                "PSEC capability probe passed and the v1.0 security \
                 environment was created and attached via \
                 PROC_THREAD_ATTRIBUTE_SECURITY_ENVIRONMENT; the process \
                 was created suspended under the environment, assigned to \
                 a kill-on-close Job, and execution resumed"
                    .to_string(),
            ),
        ),
        "os.fs" if mechanism == WindowsNativeMechanism::Psec => observation(
            c.id,
            ControlState::Verified,
            ObservationBasis::MechanismResult,
            ControlPhase::Spawn,
            Some(
                "filesystem rules were encoded into the PSEC spec and \
                 CreateProcessSecurityEnvironment accepted them — the \
                 environment token carries the fs lists"
                    .to_string(),
            ),
        ),
        "os.net.outbound" if mechanism == WindowsNativeMechanism::Psec => {
            // The spawn path promotes spec grants Planned → Verified
            // once the environment exists — the count must read both or
            // every successful launch would report zero allow rules.
            let n = grants
                .iter()
                .filter(|g| {
                    matches!(&g.subject, GrantSubject::Rule { kind, .. }
                        if *kind == "net_destination")
                        && matches!(g.state, ControlState::Planned | ControlState::Verified)
                })
                .count();
            observation(
                c.id,
                ControlState::Verified,
                ObservationBasis::MechanismResult,
                ControlPhase::Spawn,
                Some(if n == 0 {
                    "egress default-deny encoded in the PSEC spec".to_string()
                } else {
                    format!(
                        "egress default-deny + {n} IPv4 destination rule(s) \
                         encoded in the PSEC spec"
                    )
                }),
            )
        }
        "os.process" => {
            let lpac = if super::super::windows_profile::lpac_enabled() {
                " (LPAC)"
            } else {
                ""
            };
            observation(
                c.id,
                ControlState::Verified,
                ObservationBasis::MechanismResult,
                ControlPhase::Spawn,
                Some(format!(
                    "AppContainer{lpac} profile created; the process was \
                     created suspended inside the container, assigned to a \
                     kill-on-close Job, and execution resumed — \
                     CreateProcessW is authoritative for the container token"
                )),
            )
        }
        "os.fs" => {
            let failed = grants
                .iter()
                .filter(|g| matches!(g.subject, GrantSubject::FsPath { .. }))
                .filter(|g| g.origin == GrantOrigin::Policy)
                .filter(|g| g.state == ControlState::Failed)
                .count();
            if failed > 0 {
                observation(
                    c.id,
                    ControlState::PartiallyApplied,
                    ObservationBasis::MechanismResult,
                    ControlPhase::Spawn,
                    Some(format!(
                        "{failed} filesystem ACL grant(s) failed; \
                         effective access is unverified"
                    )),
                )
            } else {
                observation(
                    c.id,
                    ControlState::Verified,
                    ObservationBasis::MechanismResult,
                    ControlPhase::Spawn,
                    Some(
                        "all path DACL writes returned success \
                         (SetNamedSecurityInfoW); the child was created \
                         inside the container"
                            .to_string(),
                    ),
                )
            }
        }
        "os.net.outbound" => {
            let caps = grants
                .iter()
                .filter(|g| {
                    matches!(g.subject, GrantSubject::Capability { .. })
                        && g.state == ControlState::Verified
                })
                .map(|g| match &g.subject {
                    GrantSubject::Capability { name } => name.clone(),
                    _ => String::new(),
                })
                .collect::<Vec<_>>();
            let reason = if caps.is_empty() {
                "no network capability SIDs in the container token — \
                 outbound stays default-deny"
                    .to_string()
            } else {
                format!(
                    "capability SIDs in the container token: {} \
                     (all-or-none; per-destination rules stay RPC-layer)",
                    caps.join(", ")
                )
            };
            observation(
                c.id,
                ControlState::Verified,
                ObservationBasis::MechanismResult,
                ControlPhase::Spawn,
                Some(reason),
            )
        }
        "os.net.inbound" => observation(
            c.id,
            ControlState::Verified,
            ObservationBasis::MechanismResult,
            ControlPhase::Spawn,
            Some(
                "internetClientServer capability SID is in the container \
                 token"
                    .to_string(),
            ),
        ),
        "os.net.loopback" => {
            let exempt = grants.iter().find(|g| {
                matches!(&g.subject, GrantSubject::Rule { kind, .. }
                    if *kind == "loopback_exemption")
            });
            match exempt.map(|g| g.state) {
                Some(ControlState::Verified) => observation(
                    c.id,
                    ControlState::Verified,
                    ObservationBasis::MechanismResult,
                    ControlPhase::Spawn,
                    Some(
                        "CheckNetIsolation reported the loopback exemption \
                         applied"
                            .to_string(),
                    ),
                ),
                Some(ControlState::Unknown) => observation(
                    c.id,
                    ControlState::Unknown,
                    ObservationBasis::MechanismResult,
                    ControlPhase::Spawn,
                    Some(
                        "CheckNetIsolation exited nonzero; the exemption \
                         was not confirmed"
                            .to_string(),
                    ),
                ),
                _ => observation(
                    c.id,
                    ControlState::Unknown,
                    ObservationBasis::NotObserved,
                    ControlPhase::Spawn,
                    Some("no loopback exemption record".to_string()),
                ),
            }
        }
        _ => observation(
            c.id,
            ControlState::Unknown,
            ObservationBasis::NotObserved,
            ControlPhase::Spawn,
            Some("no outcome mapping for this control".to_string()),
        ),
    };
    if let Some(err) = abort {
        let note = format!(
            "the launch then aborted at the {} stage: {}; the suspended \
             process was terminated and the created handles/Job were \
             cleaned up",
            err.stage.label(),
            err.source
        );
        o.reason = Some(match o.reason {
            Some(r) => format!("{r}; {note}"),
            None => note,
        });
    }
    o
}

/// Every still-planned control after an aborted Windows spawn.
fn windows_abort_observation(
    c: &PlannedControl,
    grants: &[ProcessGrant],
    err: &WinSpawnError,
    mechanism: WindowsNativeMechanism,
) -> EnforcementObservation {
    match err.stage {
        // CreateProcessW fuses the attribute and image checks — an
        // undetermined failure, not a sandbox-apply failure.
        WinStage::CreateProcess => observation(
            c.id,
            ControlState::Unknown,
            ObservationBasis::SpawnResult,
            ControlPhase::Spawn,
            Some(format!(
                "spawn failed; sandbox application undetermined: {}",
                err.source
            )),
        ),
        // After CreateProcessW a real sandboxed process existed and had
        // to be torn down — that is an explicit failure for os.process.
        WinStage::JobSetup | WinStage::Job | WinStage::Resume if c.id == "os.process" => {
            let location = if mechanism == WindowsNativeMechanism::Psec {
                "the security environment"
            } else {
                "the container"
            };
            observation(
                c.id,
                ControlState::Failed,
                ObservationBasis::MechanismResult,
                ControlPhase::Spawn,
                Some(format!(
                    "the {} stage failed: {}; the suspended process inside \
                 {location} was terminated and the created handles/Job \
                 were cleaned up",
                    err.stage.label(),
                    err.source
                )),
            )
        }
        // Other controls' apply work had provably completed — keep their
        // mechanism outcomes, with the abort appended to the reason.
        WinStage::JobSetup | WinStage::Job | WinStage::Resume => {
            windows_success_observation(c, grants, Some(err), mechanism)
        }
        // Any earlier stage died before process creation: nothing ever
        // went live, so every planned control is an explicit failure
        // that names the stage.
        _ => observation(
            c.id,
            ControlState::Failed,
            ObservationBasis::MechanismResult,
            ControlPhase::Spawn,
            Some(format!(
                "the {} stage failed: {}; the launch aborted before \
                 process creation and created objects were cleaned up",
                err.stage.label(),
                err.source
            )),
        ),
    }
}

/// Windows spawn outcome → per-control observations, plus the plan
/// update a provable construction failure calls for. This is the
/// assembly `spawn_child_async_impl` runs for every Windows launch.
///
/// The observations are generated *before* the plan is touched:
/// [`os_spawn_observations`] reports only controls still `Planned`, so
/// failing the plan first would leave a setup abort with failed
/// controls and no per-control evidence at all. Only then does a
/// *pre-`CreateProcessW`* failure (`profile-creation`,
/// `grant-application`, `process-setup`, plus the PSEC `probe`,
/// `policy-check` and `env-create` stages) whose source is a provable
/// `Policy`/`Prepare` setup error mark the planned controls `Failed` —
/// the same convention as the Linux/macOS build-failure paths. Later
/// stages never collapse the plan: `CreateProcessW` fuses its inputs so
/// the failing one is undetermined, and a job-setup/assignment or
/// execution-start abort ran against a real container process whose
/// per-control outcomes the observations already carry.
pub(crate) fn windows_spawn_outcome(
    controls: &mut [PlannedControl],
    grants: &[ProcessGrant],
    outcome: Option<&WinSpawnError>,
    mechanism: WindowsNativeMechanism,
) -> Vec<EnforcementObservation> {
    let observations = os_spawn_observations(controls, grants, outcome, mechanism);
    if let Some(e) = outcome
        && matches!(
            e.stage,
            WinStage::Profile
                | WinStage::Grants
                | WinStage::ProcessSetup
                | WinStage::Probe
                | WinStage::PolicyCheck
                | WinStage::EnvironmentCreate
        )
        && matches!(
            &e.source,
            WardenError::SandboxSetup { stage, .. }
                if matches!(
                    stage,
                    crate::error::SandboxStage::Policy | crate::error::SandboxStage::Prepare
                )
        )
    {
        fail_os_controls(
            controls,
            &format!("sandbox pipeline failed at the {} stage", e.stage.label()),
            &e.source,
        );
    }
    observations
}

pub(crate) fn os_plan_grants(
    policy: &Policy,
    program: Option<&Path>,
    command: &str,
    opts: &SpawnOptions,
    controls: &mut [PlannedControl],
    mechanism: WindowsNativeMechanism,
) -> Vec<ProcessGrant> {
    if mechanism == WindowsNativeMechanism::Psec {
        // Spec build only — nothing is applied, no environment created.
        // A refusal carries the per-requirement reasons and marks the OS
        // controls Failed: the same launch would refuse at policy-check.
        return match super::super::psec_spec::build_launch_spec(policy, program, command, opts) {
            Ok(build) => build.grants,
            Err(refusal) => {
                let source = WardenError::sandbox_setup(
                    crate::error::SandboxStage::Policy,
                    format!(
                        "policy is not expressible as a PSEC security \
                         environment: {}",
                        refusal.problems.join("; ")
                    ),
                );
                fail_os_controls(controls, "PSEC policy translation failed", &source);
                refusal.grants
            }
        };
    }
    // Intents only — no profile is created and nothing is applied.
    super::super::windows_sandbox::grant_intents(policy, program, command, opts.tmpdir.as_deref())
        .into_iter()
        .map(|(grant, _)| grant)
        .collect()
}

pub(crate) fn os_limitations(
    _policy: &Policy,
    out: &mut Vec<String>,
    mechanism: WindowsNativeMechanism,
) {
    if mechanism == WindowsNativeMechanism::Psec {
        out.push(
            "PSEC is a conditional mechanism (contract validated on a \
             measured build; the capability probe runs per launch and a \
             failure refuses the launch) — see \
             docs/validation/windows-isolation.md."
                .to_string(),
        );
        out.push(
            "A PSEC child's environment is mechanism-managed: no parent \
             variable propagates and no named allow list or TMPDIR \
             override can be delivered — such policies refuse rather than \
             degrade."
                .to_string(),
        );
        out.push(
            "PSEC egress supports deny-all plus IPv4 destination allow \
             rules only; there is no ingress section and no loopback \
             exemption."
                .to_string(),
        );
        out.push(
            "PSEC fs lists are literal absolute paths; a recorded grant \
             means the spec entry was accepted by \
             CreateProcessSecurityEnvironment — effective access still \
             follows each object's own ACL."
                .to_string(),
        );
        return;
    }
    out.push(
        "AppContainer inherits ambient read access via ALL_APPLICATION_PACKAGES \
         (program files, registry keys); only explicit ACL grants are enumerated."
            .to_string(),
    );
    out.push(
        "A 'verified' ACL grant records the SetNamedSecurityInfoW API result \
         (the ACE was written); whether access is actually allowed or denied \
         follows each object's resulting ACL — deny coverage is exercised by \
         the warden tests, not by this report."
            .to_string(),
    );
    out.push(
        "AppContainer network capabilities are all-or-none; per-destination \
         outbound rules are not expressible and stay RPC-layer checks."
            .to_string(),
    );
}
