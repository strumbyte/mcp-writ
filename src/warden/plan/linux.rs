//! Linux controls and apply observations — the Landlock/seccomp
//! pipeline reports through the apply record the pre-exec child
//! writes ([`linux_spawn::ApplySnapshot`]).

use std::path::Path;

use crate::enforcement::{
    ControlLayer, ControlPhase, ControlState, EgressLayerStatus, EnforcementObservation,
    LANDLOCK_FULLY_ENFORCED, LANDLOCK_NOT_ENFORCED, LANDLOCK_PARTIALLY_ENFORCED, ObservationBasis,
    PlannedControl, ProcessGrant, RESTRICT_SELF_REPORTED,
};
use crate::execution::WindowsNativeMechanism;
use crate::policy::Policy;

use super::super::SpawnOptions;
use super::super::linux_spawn;
use super::{control, fail_os_controls, observation, planned};

pub(crate) fn os_controls(
    policy: &Policy,
    _mechanism: WindowsNativeMechanism,
) -> Vec<PlannedControl> {
    let degraded_note =
        || Some("sandbox.allow_degraded=#true: partial enforcement is tolerated".to_string());
    let v = vec![
        planned("os.privileges", ControlLayer::Os, "no_new_privs"),
        control(
            "os.fs",
            ControlLayer::Os,
            "landlock",
            ControlState::Planned,
            if policy.sandbox.allow_degraded {
                degraded_note()
            } else {
                None
            },
        ),
        control(
            "os.net.outbound",
            ControlLayer::Os,
            "landlock",
            ControlState::Planned,
            if policy.sandbox.allow_degraded {
                degraded_note()
            } else {
                None
            },
        ),
        if policy.network.inbound.allow_listen {
            control(
                "os.net.inbound",
                ControlLayer::Os,
                "landlock",
                ControlState::NotApplied,
                Some("Landlock does not grant TCP bind; inbound listen stays denied".to_string()),
            )
        } else {
            control(
                "os.net.inbound",
                ControlLayer::Os,
                "landlock",
                ControlState::NotApplicable,
                Some("no inbound listen requested".to_string()),
            )
        },
        {
            // The plan models the same gate `run` applies at spawn
            // (`require_execve_allowance`): an effective `syscalls.allowed`
            // without execve/execveat fails the launch — so a `plan`
            // that said `ready` for a launch `run` would refuse is
            // reported `failed`, with the file that wrote the list.
            let mut c = planned("os.syscalls", ControlLayer::Os, "seccomp");
            if !super::super::seccomp_impl::policy_allows_execve(policy) {
                if policy.sandbox.allow_degraded {
                    c.reason = Some(
                        "sandbox.allow_degraded=#true: leftover execve stays available \
                         after spawn"
                            .to_string(),
                    );
                } else {
                    c.state = ControlState::Failed;
                    let mut reason = String::from(
                        "syscalls.allowed must include execve (or execveat) to spawn a \
                         child process, or set sandbox.allow_degraded=#true",
                    );
                    if let Some(detail) =
                        super::super::seccomp_impl::execve_provenance_detail(policy)
                    {
                        reason.push_str(&detail);
                    }
                    c.reason = Some(reason);
                }
            }
            c
        },
        {
            // PR-18: AF_UNIX containment. Under deny-all the seccomp
            // family pin closes the family (socketpair's datagram route
            // too); the Landlock scope adds the abstract-socket check on
            // ABI v6+. Under an open posture the pin does not exist and
            // the scope is all there is — below v6 there is nothing.
            let abi = super::super::landlock_impl::kernel_abi();
            let deny_all = policy.network.outbound.deny_all_others;
            if deny_all {
                planned("os.ipc.unix", ControlLayer::Os, "seccomp+landlock-scope")
            } else if abi >= 6 {
                let mut c = planned("os.ipc.unix", ControlLayer::Os, "landlock-scope");
                c.reason = Some(
                    "open posture: the socket() family pin does not apply — \
                     only abstract-socket scoping (Landlock ABI v6) is \
                     enforced; pathname unix sockets stay unrestricted"
                        .to_string(),
                );
                c
            } else {
                control(
                    "os.ipc.unix",
                    ControlLayer::Os,
                    "seccomp+landlock-scope",
                    ControlState::NotApplied,
                    Some(format!(
                        "open posture leaves socket() unrestricted and kernel \
                         Landlock ABI v{abi} predates scoped restrictions (v6, \
                         kernel 6.12) — pathname and abstract unix sockets \
                         are uncontained"
                    )),
                )
            }
        },
        {
            // PR-18: signal containment is a Landlock scope right — on
            // ABI<6 kernels there is no mediation and the control must
            // say so rather than ride the deny-all posture.
            let abi = super::super::landlock_impl::kernel_abi();
            if abi >= 6 {
                planned("os.ipc.signal", ControlLayer::Os, "landlock-scope")
            } else {
                control(
                    "os.ipc.signal",
                    ControlLayer::Os,
                    "landlock-scope",
                    ControlState::NotApplied,
                    Some(format!(
                        "kernel Landlock ABI v{abi} predates scoped \
                         restrictions (v6, kernel 6.12) — kill/tgkill/\
                         pidfd_send_signal to outside processes are \
                         unmediated"
                    )),
                )
            }
        },
    ];
    v
}

/// Spawn-result observations for the Linux controls. The evidence is the
/// shared apply record the pre-exec child filled
/// ([`linux_spawn::ApplySnapshot`]) — a mechanism result per apply stage,
/// not just "spawn returned". The `no_new_privs` → Landlock → seccomp
/// order is fixed, so a completed stage proves the earlier ones ran too;
/// a failed or truncated stage is never reported as applied.
pub(crate) fn os_spawn_observations(
    policy: &Policy,
    controls: &[PlannedControl],
    apply: Option<&linux_spawn::ApplySnapshot>,
    spawn_err: Option<&std::io::Error>,
    requested_rights: Option<&str>,
) -> Vec<EnforcementObservation> {
    controls
        .iter()
        .filter(|c| c.layer == ControlLayer::Os && c.state == ControlState::Planned)
        .map(|c| linux_control_observation(policy, c, apply, spawn_err, requested_rights))
        .collect()
}

/// The fixed pipeline stage a control's mechanism occupies — same order
/// as `linux_spawn::apply_in_child`. Controls with no stage mapping get
/// an `Unknown` observation rather than a guessed success.
fn linux_control_stage(id: &str) -> Option<u8> {
    use super::super::linux_spawn::stage;
    match id {
        "os.privileges" => Some(stage::NO_NEW_PRIVS),
        "os.fs" | "os.net.outbound" | "os.ipc.signal" => Some(stage::LANDLOCK),
        "os.syscalls" | "os.ipc.unix" => Some(stage::SECCOMP),
        _ => None,
    }
}

fn linux_control_observation(
    policy: &Policy,
    c: &PlannedControl,
    apply: Option<&linux_spawn::ApplySnapshot>,
    spawn_err: Option<&std::io::Error>,
    requested_rights: Option<&str>,
) -> EnforcementObservation {
    let Some(my_stage) = linux_control_stage(c.id) else {
        return observation(
            c.id,
            ControlState::Unknown,
            ObservationBasis::NotObserved,
            ControlPhase::Spawn,
            Some("no apply stage is bound to this control".to_string()),
        );
    };

    let Some(snap) = apply else {
        return observation(
            c.id,
            ControlState::Unknown,
            ObservationBasis::NotObserved,
            ControlPhase::Spawn,
            Some(match spawn_err {
                Some(e) => format!("spawn failed ({e}); no apply record was collected"),
                None => "apply record unavailable (shared page was not mapped)".to_string(),
            }),
        );
    };

    // A recorded failure implies the spawn failed: `failed_stage` is
    // written only on the `pre_exec` error path, and an honest record
    // then has `stage == failed_stage - 1` (the stage right before the
    // failed one completed, nothing after it did). A success alongside
    // a recorded failure, or any other `stage`/`failed_stage` pairing,
    // is corrupt — report Unknown, never applied.
    let record_inconsistent = snap.failed_stage != linux_spawn::stage::NONE
        && (spawn_err.is_none() || snap.stage.checked_add(1) != Some(snap.failed_stage));
    if record_inconsistent {
        return observation(
            c.id,
            ControlState::Unknown,
            ObservationBasis::MechanismResult,
            ControlPhase::Spawn,
            Some(
                "apply record is inconsistent (a recorded failure cannot pair \
                 with the recorded stages)"
                    .to_string(),
            ),
        );
    }

    if snap.failed_stage == my_stage {
        return observation(
            c.id,
            ControlState::Failed,
            ObservationBasis::MechanismResult,
            ControlPhase::Spawn,
            Some(linux_stage_failure_reason(snap)),
        );
    }

    if snap.stage >= my_stage {
        // This stage verifiably completed. A spawn error afterwards
        // (e.g. execve ENOENT) does not undo the apply — the reason
        // names it so a verified control is never read as a live launch.
        let (state, mut reason) = linux_stage_outcome(policy, c.id, snap, requested_rights);
        if let Some(e) = spawn_err {
            reason.push_str(&format!("; the spawn itself then failed: {e}"));
        }
        return observation(
            c.id,
            state,
            ObservationBasis::MechanismResult,
            ControlPhase::Spawn,
            Some(reason),
        );
    }

    if snap.failed_stage != linux_spawn::stage::NONE {
        return observation(
            c.id,
            ControlState::Failed,
            ObservationBasis::MechanismResult,
            ControlPhase::Spawn,
            Some(format!(
                "the apply pipeline aborted at an earlier stage (os error {})",
                snap.errno
            )),
        );
    }

    observation(
        c.id,
        ControlState::Unknown,
        ObservationBasis::MechanismResult,
        ControlPhase::Spawn,
        Some(match spawn_err {
            Some(e) => {
                format!("spawn failed ({e}) and the apply record stops before this stage")
            }
            None => "apply record stops before this stage although spawn succeeded".to_string(),
        }),
    )
}

/// Reason for the stage that returned `Err` to `pre_exec`. For Landlock
/// the kernel-reported level is included — a refusal because the ruleset
/// was only partially enforced reads differently from a syscall error.
fn linux_stage_failure_reason(snap: &linux_spawn::ApplySnapshot) -> String {
    use super::super::linux_spawn::{landlock_level, stage};
    let base = match snap.failed_stage {
        stage::NO_NEW_PRIVS => "no_new_privs prctl failed in the child",
        stage::LANDLOCK => "Landlock apply stage failed in the child",
        stage::UNOTIFY => {
            "seccomp user-notification setup failed in the child \
             (filter install or listener-fd handoff)"
        }
        stage::CGROUP => {
            "cgroup join failed in the child (cgroup.procs write for the \
             private cgroup)"
        }
        stage::DEMOTE => {
            "workload credential demotion failed in the child (privilege \
             split could not be proven — the launch refuses rather than \
             run the image with setup privileges)"
        }
        stage::SECCOMP => "seccomp apply failed in the child",
        _ => "an apply stage failed in the child",
    };
    let mut reason = format!("{base} (os error {})", snap.errno);
    if snap.failed_stage == stage::LANDLOCK {
        match snap.landlock {
            landlock_level::PARTIAL => reason.push_str(&format!(
                "; {RESTRICT_SELF_REPORTED}{LANDLOCK_PARTIALLY_ENFORCED} and \
                 sandbox.allow_degraded is off"
            )),
            landlock_level::NOT_ENFORCED => reason.push_str(&format!(
                "; {RESTRICT_SELF_REPORTED}{LANDLOCK_NOT_ENFORCED} and \
                 sandbox.allow_degraded is off"
            )),
            _ => {}
        }
    }
    reason
}

/// Observation for a control whose stage the record marks complete.
/// For Landlock-backed controls this maps the kernel-reported
/// enforcement level; `os.net.outbound` additionally splits on the
/// kernel ABI — Landlock network rules exist only since ABI v4.
/// `os.ipc.*` splits on the policy posture (the seccomp family pin
/// only exists under deny-all) and the ABI the scope rights need (v6).
fn linux_stage_outcome(
    policy: &Policy,
    id: &str,
    snap: &linux_spawn::ApplySnapshot,
    requested_rights: Option<&str>,
) -> (ControlState, String) {
    use super::super::linux_spawn::landlock_level;
    let requested = |base: String| match requested_rights {
        Some(r) => format!("{base}; requested: {r}"),
        None => base,
    };
    match id {
        "os.privileges" => (
            ControlState::Verified,
            "no_new_privs confirmed set in the child's pre_exec".to_string(),
        ),
        "os.syscalls" => (
            ControlState::Verified,
            "seccomp program confirmed installed in the child's pre_exec".to_string(),
        ),
        // PR-18: pathname AF_UNIX is the seccomp family pin (deny-all
        // only) plus the ResolveUnix opt-in rules; abstract sockets add
        // the ABI v6 scope. The stage verifies the seccomp apply; the
        // Landlock level carries the scope half.
        "os.ipc.unix" => {
            let deny_all = policy.network.outbound.deny_all_others;
            let pin = if deny_all {
                "the socket()/socketpair() family pins are verified"
            } else {
                "the open posture leaves socket() unrestricted"
            };
            // `unix="*"` deliberately leaves `Scope::AbstractUnixSocket`
            // unrequested (landlock_impl.rs) — the observation must not
            // claim a scoping the opt-in waived. Path scoping exists only
            // where `ResolveUnix` rules were handled: a path-bound
            // `unix=` opt-in under deny-all on ABI v9 (the build refuses
            // the combination below v9 and `"*"` supersedes path rules).
            let unix_allows = policy.network.outbound.unix_allows();
            let unix_star = unix_allows.iter().any(|u| u == "*");
            let unix_path = unix_allows.iter().any(|u| u != "*");
            let abstract_scoped = !(deny_all && unix_star);
            let path_scoped = deny_all && unix_path && !unix_star && snap.landlock_abi >= 9;
            let scoped_text = if !abstract_scoped {
                "unix=\"*\" waived abstract-socket scoping by opt-in"
            } else if path_scoped {
                "abstract-socket and unix-path scoping applied"
            } else {
                "abstract-socket scoping applied"
            };
            match snap.landlock {
                landlock_level::FULL => {
                    if snap.landlock_abi >= 6 {
                        (
                            ControlState::Verified,
                            requested(format!(
                                "{pin}; {scoped_text} \
                                 ({RESTRICT_SELF_REPORTED}{LANDLOCK_FULLY_ENFORCED}, \
                                 kernel Landlock ABI v{})",
                                snap.landlock_abi
                            )),
                        )
                    } else {
                        (
                            ControlState::PartiallyApplied,
                            format!(
                                "{pin}; kernel Landlock ABI v{} predates scoped \
                                 restrictions (v6) — abstract unix sockets are \
                                 unmediated",
                                snap.landlock_abi
                            ),
                        )
                    }
                }
                landlock_level::PARTIAL => {
                    if snap.landlock_abi >= 6 {
                        (
                            ControlState::Verified,
                            requested(format!(
                                "{pin}; {scoped_text} — the scope request \
                                 landed ({RESTRICT_SELF_REPORTED}{LANDLOCK_PARTIALLY_ENFORCED}, \
                                 kernel Landlock ABI v{}); the dropped piece is \
                                 elsewhere in the ruleset",
                                snap.landlock_abi
                            )),
                        )
                    } else {
                        (
                            ControlState::PartiallyApplied,
                            format!(
                                "{pin}; kernel Landlock ABI v{} predates scoped \
                                 restrictions (v6) — abstract unix sockets are \
                                 unmediated",
                                snap.landlock_abi
                            ),
                        )
                    }
                }
                landlock_level::NOT_ENFORCED => (
                    if deny_all {
                        ControlState::PartiallyApplied
                    } else {
                        ControlState::NotApplied
                    },
                    format!(
                        "{pin}; {RESTRICT_SELF_REPORTED}{LANDLOCK_NOT_ENFORCED} — \
                         no abstract-socket or unix-path scoping is in effect"
                    ),
                ),
                landlock_level::NO_RULESET => (
                    ControlState::NotApplied,
                    "no Landlock ruleset was applied".to_string(),
                ),
                _ => (
                    ControlState::Unknown,
                    "the apply record carries no Landlock result".to_string(),
                ),
            }
        }
        // PR-18: `Scope::Signal` is an ABI v6 right — a lower kernel
        // cannot scope kill/tgkill/pidfd_send_signal, and the plan
        // state already reported `not_applied` (this arm only sees the
        // control when it was planned).
        "os.ipc.signal" => match snap.landlock {
            landlock_level::FULL | landlock_level::PARTIAL if snap.landlock_abi >= 6 => (
                ControlState::Verified,
                requested(format!(
                    "Scope::Signal applied ({RESTRICT_SELF_REPORTED}{}, kernel \
                     Landlock ABI v{}) — kill-family syscalls cannot reach \
                     outside the sandbox",
                    if snap.landlock == landlock_level::FULL {
                        LANDLOCK_FULLY_ENFORCED
                    } else {
                        LANDLOCK_PARTIALLY_ENFORCED
                    },
                    snap.landlock_abi
                )),
            ),
            landlock_level::NOT_ENFORCED => (
                ControlState::NotApplied,
                format!(
                    "{RESTRICT_SELF_REPORTED}{LANDLOCK_NOT_ENFORCED} — no signal \
                     scoping is in effect"
                ),
            ),
            landlock_level::NO_RULESET => (
                ControlState::NotApplied,
                "no Landlock ruleset was applied".to_string(),
            ),
            _ if snap.landlock_abi < 6 => (
                ControlState::NotApplied,
                format!(
                    "kernel Landlock ABI v{} predates scoped restrictions (v6) \
                     — kill-family syscalls to outside processes are unmediated",
                    snap.landlock_abi
                ),
            ),
            _ => (
                ControlState::Unknown,
                "the apply record carries no Landlock result".to_string(),
            ),
        },
        "os.fs" | "os.net.outbound" => {
            let abi = if snap.landlock_abi > 0 {
                format!(" (kernel Landlock ABI v{})", snap.landlock_abi)
            } else {
                String::new()
            };
            match snap.landlock {
                landlock_level::FULL => (
                    ControlState::Verified,
                    requested(format!(
                        "{RESTRICT_SELF_REPORTED}{LANDLOCK_FULLY_ENFORCED}{abi}"
                    )),
                ),
                landlock_level::PARTIAL => {
                    if id == "os.net.outbound" && (1..4).contains(&snap.landlock_abi) {
                        (
                            ControlState::NotApplied,
                            format!(
                                "kernel Landlock ABI v{} predates network rules (v4); \
                                 outbound port rules were not enforceable",
                                snap.landlock_abi
                            ),
                        )
                    } else {
                        (
                            ControlState::PartiallyApplied,
                            requested(format!(
                                "{RESTRICT_SELF_REPORTED}{LANDLOCK_PARTIALLY_ENFORCED}{abi}; \
                                 tolerated by sandbox.allow_degraded — which rules were \
                                 dropped is not decomposed per control"
                            )),
                        )
                    }
                }
                landlock_level::NOT_ENFORCED => (
                    ControlState::NotApplied,
                    requested(format!(
                        "{RESTRICT_SELF_REPORTED}{LANDLOCK_NOT_ENFORCED}{abi}; tolerated by \
                         sandbox.allow_degraded — no Landlock enforcement is in effect"
                    )),
                ),
                // Currently unreachable: `prepare_linux_child_sandbox`
                // always installs a ruleset, so the child never records
                // NO_RULESET today. Kept so the mapping stays honest if
                // a "policy without Landlock" path is ever added.
                landlock_level::NO_RULESET => (
                    ControlState::NotApplied,
                    "no Landlock ruleset was applied".to_string(),
                ),
                landlock_level::NOT_RUN => (
                    ControlState::Unknown,
                    "the record shows the Landlock stage ran but stored no status".to_string(),
                ),
                _ => (
                    ControlState::Unknown,
                    "the apply record carries no Landlock result".to_string(),
                ),
            }
        }
        _ => (
            ControlState::Unknown,
            "no outcome mapping for this control".to_string(),
        ),
    }
}

/// Plan-mode grants for the sandboxed case: runs the same rule builders
/// as the spawn path (their artifacts are discarded — nothing is applied)
/// and marks OS controls `Failed` when the build itself fails.
pub(crate) fn os_plan_grants(
    policy: &Policy,
    _program: Option<&Path>,
    _command: &str,
    _opts: &SpawnOptions,
    controls: &mut [PlannedControl],
    _mechanism: WindowsNativeMechanism,
) -> Vec<ProcessGrant> {
    match super::super::linux_spawn::prepare_linux_child_sandbox(policy) {
        Ok(bits) => bits.grants,
        Err(e) => {
            fail_os_controls(controls, "rule build failed", &e);
            Vec::new()
        }
    }
}

pub(crate) fn os_limitations(
    policy: &Policy,
    out: &mut Vec<String>,
    _mechanism: WindowsNativeMechanism,
) {
    if policy.sandbox.allow_degraded {
        out.push(
            "sandbox.allow_degraded=#true: partial or absent Landlock enforcement \
             is tolerated instead of aborting the launch; the kernel-reported \
             level is collected from the child and shown per control."
                .to_string(),
        );
    }

    // PR-18: ABI-dependent containment must be disclosed where it
    // cannot be enforced — the same text the capability matrix's
    // deficiency rows carry.
    let abi = super::super::landlock_impl::kernel_abi();
    if abi < 6 {
        out.push(format!(
            "kernel Landlock ABI v{abi} predates scoped restrictions (v6, \
             kernel 6.12): kill/tgkill/pidfd_send_signal to outside processes \
             and abstract-AF_UNIX connects are unmediated — the os.ipc.* \
             controls report their state"
        ));
    }
    for u in policy.network.outbound.unix_allows() {
        if u == "*" {
            out.push(
                "'allow unix=\"*\"' opens the AF_UNIX family without path \
                 scoping — pathname and abstract unix sockets are unrestricted"
                    .to_string(),
            );
        } else if abi >= 9 {
            let parent = Path::new(&u)
                .parent()
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_else(|| u.to_string());
            out.push(format!(
                "'allow unix={u}' grants AF_UNIX connect/sendto beneath \
                 '{parent}' via Landlock ResolveUnix — a socket inode cannot \
                 be pinned, so the parent directory carries the grant"
            ));
        }
        // abi<9 + path opt-in is refused at selection — no limitation row.
    }
}

/// Per-layer egress disposition on native Linux — the strings live in
/// the `linux-native` row of [`crate::enforcement::capability`] so the
/// plan, the launch report, and the capability matrix can never diverge.
pub(crate) fn os_egress_layer_status(
    _mechanism: WindowsNativeMechanism,
) -> (EgressLayerStatus, EgressLayerStatus) {
    crate::enforcement::capability::LINUX_NATIVE.egress_status()
}

// ---------------------------------------------------------------------------
// PR-16 — the namespaced route's plan pieces
// ---------------------------------------------------------------------------

/// The OS controls a namespaced launch declares — the Landlock/seccomp
/// control ids are unchanged (those bits still apply inside the
/// namespace), but `os.net.outbound`'s enforcing mechanism is the TUN
/// proxy rather than netport narrowing, and this route adds the two
/// supervision controls only it has. `dns_gate` is true only when an
/// upstream resolver was resolved — without one there is no gate task
/// to plan, so the control reports NotApplicable instead of claiming
/// an interception point that will never exist.
pub(crate) fn os_controls_namespaced(policy: &Policy, dns_gate: bool) -> Vec<PlannedControl> {
    let mut v = os_controls(policy, WindowsNativeMechanism::AppContainer);
    for c in &mut v {
        match c.id {
            "os.net.outbound" => {
                c.mechanism = "tun-proxy";
                c.reason = Some(
                    "all egress dead-ends at the TUN-fed proxy — TCP/UDP is \
                     evaluated per destination+port there; in-namespace \
                     Landlock narrows ports only where a rule is exactly \
                     expressible"
                        .to_string(),
                );
            }
            "os.net.inbound" => {
                // The selection refuses `allow_listen` before this plan
                // exists — mark the honest state rather than inherit
                // native's Landlock note.
                c.state = ControlState::NotApplicable;
                c.reason = Some(
                    "the namespaced netns has no inbound path (all egress \
                     dead-ends at the TUN proxy)"
                        .to_string(),
                );
            }
            "os.ipc.unix" => {
                // On this route the family pin is unconditional — it is
                // not tied to the egress posture — and init masks /run.
                c.state = ControlState::Planned;
                c.mechanism = "seccomp+mountns";
                c.reason = Some(
                    "socket() families are pinned to AF_INET/AF_INET6 — \
                     AF_UNIX is unreachable — and a private /run hides host \
                     socket paths; Landlock adds abstract-socket scoping on \
                     ABI v6+"
                        .to_string(),
                );
            }
            "os.ipc.signal" => {
                // The dedicated pid namespace confines signals to
                // in-namespace pids regardless of the Landlock ABI.
                c.state = ControlState::Planned;
                c.mechanism = "pidns+landlock-scope";
                c.reason = Some(
                    "CLONE_NEWPID confines signals to in-namespace pids; \
                     Landlock adds Scope::Signal on ABI v6+"
                        .to_string(),
                );
            }
            _ => {}
        }
    }
    v.push(planned("os.net.proxy", ControlLayer::Os, "tun-proxy"));
    if dns_gate {
        v.push(planned(
            "os.net.dns-gate",
            ControlLayer::Os,
            "embedded-dns-gate",
        ));
    } else {
        let mut c = planned("os.net.dns-gate", ControlLayer::Os, "embedded-dns-gate");
        c.state = ControlState::NotApplicable;
        c.reason = Some(
            "no DNS upstream is configured — the embedded gate does not \
             exist for this launch; port-53 flows fall to the ordinary \
             per-destination evaluator"
                .to_string(),
        );
        v.push(c);
    }
    v
}

/// Namespaced-route spawn observations. The evidence differs from the
/// native apply record: init's handshake reports the in-namespace
/// sandbox verdict (`sandbox_applied`), the proxy/gate controls report
/// their task starts, and `os.net.outbound` verifies on the proxy —
/// never a claimed Landlock level it did not reach.
pub(crate) fn os_spawn_observations_namespaced(
    controls: &[PlannedControl],
    sandbox_applied: Option<bool>,
    proxy_started: bool,
    gate_started: bool,
    spawn_err: Option<&str>,
) -> Vec<EnforcementObservation> {
    controls
        .iter()
        .filter(|c| c.layer == ControlLayer::Os && c.state == ControlState::Planned)
        .map(|c| {
            let fail_or_unknown = |default: &str| {
                observation(
                    c.id,
                    if spawn_err.is_some() {
                        ControlState::Failed
                    } else {
                        ControlState::Unknown
                    },
                    ObservationBasis::MechanismResult,
                    ControlPhase::Spawn,
                    Some(match spawn_err {
                        Some(e) => format!("{default}: {e}"),
                        None => default.to_string(),
                    }),
                )
            };
            match c.id {
                "os.privileges" | "os.fs" | "os.syscalls" | "os.ipc.unix" | "os.ipc.signal" => {
                    match sandbox_applied {
                        Some(true) => observation(
                            c.id,
                            ControlState::Verified,
                            ObservationBasis::MechanismResult,
                            ControlPhase::Spawn,
                            Some(
                                "init reported SANDBOXED — no_new_privs, Landlock, and \
                             seccomp applied inside the namespace before exec"
                                    .to_string(),
                            ),
                        ),
                        Some(false) => observation(
                            c.id,
                            ControlState::Skipped,
                            ObservationBasis::MechanismResult,
                            ControlPhase::Spawn,
                            Some(
                                "init reported SANDBOX-SKIPPED — the debug hatch left \
                             the workload without Landlock/seccomp inside the \
                             namespace"
                                    .to_string(),
                            ),
                        ),
                        None => fail_or_unknown(
                            "init's post-GO reply arrived without a sandbox verdict",
                        ),
                    }
                }
                "os.net.outbound" | "os.net.proxy" => {
                    if proxy_started {
                        observation(
                            c.id,
                            ControlState::Verified,
                            ObservationBasis::MechanismResult,
                            ControlPhase::Spawn,
                            Some(
                                "the TUN-fed egress proxy task is running — the \
                                 workload's only egress path is the policy-checked \
                                 device"
                                    .to_string(),
                            ),
                        )
                    } else {
                        fail_or_unknown("the egress proxy did not start")
                    }
                }
                "os.net.dns-gate" => {
                    if gate_started {
                        observation(
                            c.id,
                            ControlState::Verified,
                            ObservationBasis::MechanismResult,
                            ControlPhase::Spawn,
                            Some(
                                "the embedded DNS gate is running — UDP/TCP \
                                 port-53 traffic is intercepted inside the netns"
                                    .to_string(),
                            ),
                        )
                    } else {
                        fail_or_unknown("the embedded DNS gate did not start")
                    }
                }
                _ => observation(
                    c.id,
                    ControlState::Unknown,
                    ObservationBasis::NotObserved,
                    ControlPhase::Spawn,
                    Some("no observation mapping for this control".to_string()),
                ),
            }
        })
        .collect()
}

/// Namespaced-route limitations — appended to `base_limitations` so the
/// report's honest scope notes name what this mechanism cannot see.
pub(crate) fn os_limitations_namespaced(_policy: &Policy, out: &mut Vec<String>) {
    for l in [
        "v6 elements the classifier cannot inspect stay dropped — extension-\
         header chains, fragments, and ICMPv6 (incl. Packet-Too-Big, unneeded \
         since the proxy re-originates every flow on host sockets); a v6 \
         destination the host cannot dial fails closed per flow",
        "no IP-fragment reassembly and no non-TCP/UDP protocols — ICMP, GRE, \
         raw sockets, and unknown protocols are dropped at the TUN",
        "DoT/DoH and resolver bypass are outside the name layer — the embedded \
         gate intercepts UDP/TCP port-53 only; encrypted resolvers are subject \
         to IP-layer rules alone",
        "shared-IP/CDN answers carry destination ambiguity — a DNS grant names \
         the literal resolved address, not the logical service",
        "the egress proxy and embedded DNS gate are hard supervision \
         dependencies — their loss kills the workload rather than leave it \
         without an enforcement point",
    ] {
        out.push(l.to_string());
    }
}

/// Per-layer egress disposition on the namespaced route — the strings
/// live in the `linux-namespaced` row of
/// [`crate::enforcement::capability`], same contract as
/// [`os_egress_layer_status`].
pub(crate) fn os_egress_layer_status_namespaced() -> (EgressLayerStatus, EgressLayerStatus) {
    crate::enforcement::capability::LINUX_NAMESPACED.egress_status()
}

/// The namespaced route's egress correspondence table — same rule rows
/// as every Linux plan, with the namespaced layer dispositions.
pub(crate) fn egress_layers_namespaced_plan(
    policy: &Policy,
) -> crate::enforcement::EgressLayersPlan {
    let (name, ip) = os_egress_layer_status_namespaced();
    crate::enforcement::EgressLayersPlan {
        default_action: if policy.network.outbound.deny_all_others {
            "deny_all"
        } else {
            "allow_all"
        },
        rules: super::egress_rule_table(policy),
        layers: vec![name, ip],
    }
}

/// Plan-mode grants for a namespaced spawn — the same in-namespace
/// rule builders the spawn runs (Landlock fs + exact port narrowing +
/// seccomp); the proxy's destination rules are policy data the
/// evaluator consumes, not kernel grants, so they live in the
/// egress-layers table instead.
pub(crate) fn os_plan_grants_namespaced(
    policy: &Policy,
    controls: &mut [PlannedControl],
) -> Vec<ProcessGrant> {
    match super::super::linux_spawn::prepare_linux_child_sandbox_namespaced(policy) {
        Ok(bits) => bits.grants,
        Err(e) => {
            fail_os_controls(controls, "rule build failed", &e);
            Vec::new()
        }
    }
}
