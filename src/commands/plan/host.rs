//! Host-environment evidence checks shared by the `plan` modes: the
//! `host.os` record every report carries, the `env.fail_on` dial the
//! host-resolved launch modes share, the `wsb.store` package record
//! for Windows Sandbox plans, and the WSL/WSLC environment tiers the
//! `wslc` engine selection adds. Every probe here is read-only — `plan`
//! never installs, updates, starts, or reconfigures what it inspects.

use crate::enforcement::{PlanCheck, PlanCheckStatus};
use crate::execution::{TargetArch, TargetOs};
use crate::verifier::fail_on::{FAIL_ON_ENV, FailOn};

use super::report::{check, failing_check};

/// The `host.os` record — the host environment every `plan` report
/// carries. A Windows host reads edition/display/build from one bounded
/// `reg query` of the CurrentVersion key; other hosts record the
/// compile-time os/arch with no spawn at all. Facts only — never a
/// capability claim.
pub(super) async fn host_os_check() -> PlanCheck {
    use crate::container::windows_probe::{self, ProbeOutcome};
    let mut detail = format!("{} {}", TargetOs::host().name(), TargetArch::host().name());
    // On a non-Windows host the record is compile-time only — no Windows
    // tool ever spawns there, even under the fixture env overrides the
    // probe layer exposes (those select *probe* binaries for targets the
    // operator asked about, never host facts on a non-Windows host).
    let edition_probe = if TargetOs::host() == TargetOs::Windows {
        windows_probe::host_edition().await
    } else {
        ProbeOutcome::Absent
    };
    match edition_probe {
        ProbeOutcome::Answered(text) => {
            let edition = windows_probe::parse_current_version_key(&text);
            if let Some(name) = &edition.product_name {
                detail.push_str(&format!(" product=\"{name}\""));
            }
            if let Some(id) = &edition.edition_id {
                detail.push_str(&format!(" edition={id}"));
            }
            if let Some(display) = &edition.display_version {
                detail.push_str(&format!(" display={display}"));
            }
            match edition.build() {
                Some(build) => detail.push_str(&format!(" build={build}")),
                None => detail.push_str(" build=unknown"),
            }
            check("host.os", PlanCheckStatus::Pass, Some(detail))
        }
        // Non-Windows hosts resolve no `reg` probe — the compile-time
        // os/arch is the whole record, and no Windows tool spawned.
        ProbeOutcome::Absent if TargetOs::host() != TargetOs::Windows => {
            check("host.os", PlanCheckStatus::Pass, Some(detail))
        }
        ProbeOutcome::Absent => PlanCheck {
            id: "host.os",
            status: PlanCheckStatus::Warn,
            detail: Some(format!(
                "{detail} — reg.exe did not resolve: host edition/build unreadable"
            )),
            remediation: Some(
                "reg.exe should exist on every Windows host; check PATH/System32".to_string(),
            ),
        },
        ProbeOutcome::Failed(error) => PlanCheck {
            id: "host.os",
            status: PlanCheckStatus::Warn,
            detail: Some(format!("{detail} — host edition/build unreadable: {error}")),
            remediation: None,
        },
    }
}

/// The `env.fail_on` record — the finding-abort dial `run` resolves
/// (--fail-on > MCP_WRIT_FAIL_ON > high) and records on
/// `policy.loaded`. `plan` cannot see a later invocation's CLI flag,
/// so it reports the env/default half: a below-default dial is a
/// warning (a launch would weaken enforcement), an invalid value is
/// a failure (a launch would refuse before spawning). Shared by the
/// modes whose launches resolve the dial on the host — native `run`
/// and `run --isolation windows-sandbox`, which refuses an invalid
/// value before building the guest spec.
pub(super) fn env_fail_on_check() -> PlanCheck {
    match FailOn::resolve_from_process_env(None) {
        Err(e) => failing_check(
            "env.fail_on",
            format!("MCP_WRIT_FAIL_ON is invalid: {e}"),
            "set MCP_WRIT_FAIL_ON to high, critical, or none (or unset it) — \
             `run` refuses an invalid value before launch"
                .to_string(),
        ),
        Ok(FailOn::None) => PlanCheck {
            id: "env.fail_on",
            status: PlanCheckStatus::Warn,
            detail: Some(
                "MCP_WRIT_FAIL_ON=none: findings never abort the launch — \
                 `run` warns and records the dial on policy.loaded"
                    .to_string(),
            ),
            remediation: Some(
                "set MCP_WRIT_FAIL_ON to high or critical, or pass --fail-on to `run`".to_string(),
            ),
        },
        Ok(FailOn::Critical) => PlanCheck {
            id: "env.fail_on",
            status: PlanCheckStatus::Warn,
            detail: Some(
                "MCP_WRIT_FAIL_ON=critical: High findings no longer abort — \
                 weaker than the default 'high' (`run` records the dial on \
                 policy.loaded)"
                    .to_string(),
            ),
            remediation: Some(
                "set MCP_WRIT_FAIL_ON to high to restore the default, or pass \
                 --fail-on to `run`"
                    .to_string(),
            ),
        },
        Ok(FailOn::High) => {
            let origin = match std::env::var(FAIL_ON_ENV) {
                Ok(v) if !v.is_empty() => "from MCP_WRIT_FAIL_ON; --fail-on overrides at run",
                _ => "default — MCP_WRIT_FAIL_ON unset",
            };
            check(
                "env.fail_on",
                PlanCheckStatus::Pass,
                Some(format!("fail-on resolves to 'high' ({origin})")),
            )
        }
    }
}

/// The `wsb.store` record — the Windows Sandbox *Store package* version
/// (`Get-AppxPackage`), kept separate from the `wsb.exe` client string
/// the `isolation.backend` prerequisite validates. Presence of the
/// package is recorded, not proof the runtime contract works — that is
/// what `isolation.backend` and launch-time checks are for.
pub(super) async fn wsb_store_check() -> PlanCheck {
    use crate::container::windows_probe::{self, ProbeOutcome};
    match windows_probe::wsb_store_version().await {
        ProbeOutcome::Answered(text) => {
            let first = text.lines().next().map(str::trim).unwrap_or("");
            if first.is_empty() {
                PlanCheck {
                    id: "wsb.store",
                    status: PlanCheckStatus::Warn,
                    detail: Some(
                        "no 'Microsoft.WindowsSandbox' Store package registered for \
                         this user — the wsb.exe client version remains the backend \
                         gate (isolation.backend)"
                            .to_string(),
                    ),
                    remediation: None,
                }
            } else {
                check(
                    "wsb.store",
                    PlanCheckStatus::Pass,
                    Some(format!("store package: {first}")),
                )
            }
        }
        ProbeOutcome::Absent => check(
            "wsb.store",
            PlanCheckStatus::Skipped,
            Some("requires a Windows host (powershell.exe not resolved)".to_string()),
        ),
        ProbeOutcome::Failed(error) => PlanCheck {
            id: "wsb.store",
            status: PlanCheckStatus::Warn,
            detail: Some(format!("Store package version unreadable: {error}")),
            remediation: None,
        },
    }
}

/// The WSL/WSLC environment checks emitted when `--engine wslc` is
/// selected — the evidence tiers stay distinct: presence (`wsl.exe` /
/// `wslc.exe` resolving), version facts (`--version` answers, per-distro
/// WSL-1/2 modes), and the runtime contract, which `plan` never
/// exercises because starting a WSLC session is itself a side effect.
/// Nothing here runs `wsl --update`, enables a feature, starts a
/// distro/VM, pulls an image, or elevates.
pub(super) async fn wslc_environment_checks() -> Vec<PlanCheck> {
    use crate::container::windows_probe::{self, ProbeOutcome};
    let mut checks = Vec::new();

    // wsl.cli — presence tier.
    let wsl = windows_probe::find_wsl();
    match &wsl {
        Some(path) => checks.push(check(
            "wsl.cli",
            PlanCheckStatus::Pass,
            Some(format!("wsl.exe resolved at {}", path.display())),
        )),
        None => checks.push(failing_check(
            "wsl.cli",
            "wsl.exe not found — WSL is not installed on this host".to_string(),
            "install Store WSL (wsl --install / winget) — mcp-writ never installs \
             or updates WSL itself"
                .to_string(),
        )),
    }

    // wsl.product — the product version + packaged guest kernel from
    // `wsl --version`. A distro's WSL-1/2 mode is recorded separately in
    // wsl.distro; the two are never conflated.
    match &wsl {
        None => checks.push(check(
            "wsl.product",
            PlanCheckStatus::Skipped,
            Some("wsl.exe absent — no product version to read".to_string()),
        )),
        Some(exe) => match windows_probe::wsl_version(exe).await {
            ProbeOutcome::Answered(text) => {
                let parsed = windows_probe::parse_wsl_version(&text);
                let mut detail = String::new();
                if let Some(product) = &parsed.product {
                    detail.push_str(&format!("wsl product={product}"));
                }
                if let Some(kernel) = &parsed.kernel {
                    detail.push_str(&format!(" kernel={kernel}"));
                }
                if let Some(windows) = &parsed.windows {
                    detail.push_str(&format!(" windows={windows}"));
                }
                match parsed.product.as_deref() {
                    Some(product) => {
                        match windows_probe::version_at_least(product, windows_probe::WSLC_MIN_WSL)
                        {
                            Some(true) => checks.push(check(
                                "wsl.product",
                                PlanCheckStatus::Pass,
                                Some(detail),
                            )),
                            Some(false) => checks.push(failing_check(
                                "wsl.product",
                                format!(
                                    "{detail} — below the WSL Containers minimum \
                                     (WSL {}.{}.{}+)",
                                    windows_probe::WSLC_MIN_WSL.0,
                                    windows_probe::WSLC_MIN_WSL.1,
                                    windows_probe::WSLC_MIN_WSL.2
                                ),
                                "update WSL via the Store/winget — mcp-writ never \
                                 runs `wsl --update` itself"
                                    .to_string(),
                            )),
                            None => checks.push(failing_check(
                                "wsl.product",
                                format!("{detail} — product version is not a numeric tuple"),
                                "verify `wsl --version` reports a numeric product version"
                                    .to_string(),
                            )),
                        }
                    }
                    None => checks.push(failing_check(
                        "wsl.product",
                        "wsl --version answered but no product version line was \
                         parseable — an unrecognized format is unverified, not \
                         assumed"
                            .to_string(),
                        "inspect `wsl --version` output manually".to_string(),
                    )),
                }
            }
            ProbeOutcome::Failed(error) => {
                // A non-zero exit is the inbox/legacy signature — that WSL
                // does not implement `--version` at all. A transport
                // failure (spawn, deadline, output cap — the probe layer's
                // "exited" prefix marks the exit case) names its own cause
                // and must not be pinned on the legacy-WSL explanation.
                let (cause, remediation) = if error.starts_with("exited") {
                    (
                        " — inbox/legacy WSL reports no product version",
                        format!(
                            "install or update to Store WSL ≥ {}.{}.{} for WSL Containers \
                             — mcp-writ never runs `wsl --update` itself",
                            windows_probe::WSLC_MIN_WSL.0,
                            windows_probe::WSLC_MIN_WSL.1,
                            windows_probe::WSLC_MIN_WSL.2
                        ),
                    )
                } else {
                    (
                        "",
                        "inspect `wsl --version` manually — the bounded probe must \
                         answer within the time and output limits"
                            .to_string(),
                    )
                };
                checks.push(failing_check(
                    "wsl.product",
                    format!("`wsl --version` failed: {error}{cause}"),
                    remediation,
                ));
            }
            ProbeOutcome::Absent => checks.push(check(
                "wsl.product",
                PlanCheckStatus::Skipped,
                Some("probe did not run — executable unresolved".to_string()),
            )),
        },
    }

    // wsl.distro — registered distros and each one's mode. Informational:
    // a WSL-2 distro mode is not the product version, and a WSL install
    // alone is not a host-boundary guarantee.
    match &wsl {
        None => checks.push(check(
            "wsl.distro",
            PlanCheckStatus::Skipped,
            Some("wsl.exe absent — no distro list".to_string()),
        )),
        Some(exe) => match windows_probe::wsl_distros(exe).await {
            ProbeOutcome::Answered(text) => {
                let distros = windows_probe::parse_wsl_distros(&text);
                if distros.is_empty() {
                    // Prose with no row-shaped lines — the localized "no
                    // installed distributions" guidance wsl prints when
                    // nothing is registered — is a zero-distro answer, not
                    // an unrecognized format.
                    if text.trim().is_empty() || !windows_probe::has_row_like_lines(&text) {
                        checks.push(check(
                            "wsl.distro",
                            PlanCheckStatus::Pass,
                            Some("no distros registered".to_string()),
                        ));
                    } else {
                        checks.push(PlanCheck {
                            id: "wsl.distro",
                            status: PlanCheckStatus::Warn,
                            detail: Some(
                                "`wsl -l -v` answered but no distro rows were \
                                 parseable — an unrecognized format is recorded, \
                                 not assumed"
                                    .to_string(),
                            ),
                            remediation: None,
                        });
                    }
                } else {
                    let mut detail = format!("{} distro(s): ", distros.len());
                    detail.push_str(
                        &distros
                            .iter()
                            .take(8)
                            .map(|d| {
                                let mode =
                                    d.mode.map(|m| m.to_string()).unwrap_or_else(|| "?".into());
                                if d.is_default {
                                    format!("{}(WSL {mode}, default)", d.name)
                                } else {
                                    format!("{}(WSL {mode})", d.name)
                                }
                            })
                            .collect::<Vec<_>>()
                            .join(", "),
                    );
                    if distros.len() > 8 {
                        detail.push_str(&format!(", … +{} more", distros.len() - 8));
                    }
                    checks.push(check("wsl.distro", PlanCheckStatus::Pass, Some(detail)));
                }
            }
            ProbeOutcome::Failed(error) => checks.push(PlanCheck {
                id: "wsl.distro",
                status: PlanCheckStatus::Warn,
                detail: Some(format!("`wsl -l -v` failed: {error}")),
                remediation: None,
            }),
            ProbeOutcome::Absent => checks.push(check(
                "wsl.distro",
                PlanCheckStatus::Skipped,
                Some("probe did not run — executable unresolved".to_string()),
            )),
        },
    }

    // wslc.cli — the WSL Containers CLI's entity (resolved path) and
    // self-reported version. An answered --version is the presence +
    // version tier, not the runtime contract.
    match windows_probe::find_wslc() {
        None => checks.push(failing_check(
            "wslc.cli",
            format!(
                "wslc.exe not found — WSL Containers requires Store WSL ≥ {}.{}.{}",
                windows_probe::WSLC_MIN_WSL.0,
                windows_probe::WSLC_MIN_WSL.1,
                windows_probe::WSLC_MIN_WSL.2
            ),
            "update WSL via the Store/winget — mcp-writ never installs or updates \
             WSL itself"
                .to_string(),
        )),
        Some(exe) => match windows_probe::wslc_version(&exe).await {
            ProbeOutcome::Answered(text) => {
                let first = text.lines().next().map(str::trim).unwrap_or("");
                if first.is_empty() {
                    checks.push(failing_check(
                        "wslc.cli",
                        format!(
                            "wslc.exe resolved at {} but `--version` produced no \
                             output — the entity is present but unverified",
                            exe.display()
                        ),
                        "verify the wslc.exe install answers --version".to_string(),
                    ));
                } else {
                    let detail = format!(
                        "wslc.exe resolved at {} — version: {}",
                        exe.display(),
                        crate::container::windows_probe::abbreviate(first, 120)
                    );
                    // The launch path pins the validated 3.0.x line — an
                    // answered version off the line or in an unrecognized
                    // layout is a Warn here and a refusal at engine
                    // resolve, not a silent launch.
                    match crate::container::windows_probe::parse_wslc_version(&text) {
                        Some(v) if crate::container::windows_probe::wslc_version_supported(v) => {
                            checks.push(check("wslc.cli", PlanCheckStatus::Pass, Some(detail)))
                        }
                        Some(_) => checks.push(PlanCheck {
                            id: "wslc.cli",
                            status: PlanCheckStatus::Warn,
                            detail: Some(format!(
                                "{detail} — off the validated wslc 3.0.x line \
                                 (≥ 3.0.1); run-image refuses this version"
                            )),
                            remediation: Some(
                                "update WSL to a wslc 3.0.x release — mcp-writ \
                                 never installs or updates it"
                                    .to_string(),
                            ),
                        }),
                        None => checks.push(PlanCheck {
                            id: "wslc.cli",
                            status: PlanCheckStatus::Warn,
                            detail: Some(format!(
                                "{detail} — the version answer is not in the \
                                 validated wslc format; run-image refuses an \
                                 unverified version"
                            )),
                            remediation: Some(
                                "update WSL to a wslc 3.0.x release — mcp-writ \
                                 never installs or updates it"
                                    .to_string(),
                            ),
                        }),
                    }
                }
            }
            ProbeOutcome::Failed(error) => checks.push(failing_check(
                "wslc.cli",
                format!(
                    "wslc.exe resolved at {} but `--version` failed: {error}",
                    exe.display()
                ),
                "verify the wslc.exe install — a binary that cannot report its \
                 version is not a usable contract"
                    .to_string(),
            )),
            ProbeOutcome::Absent => checks.push(check(
                "wslc.cli",
                PlanCheckStatus::Skipped,
                Some("probe did not run — executable unresolved".to_string()),
            )),
        },
    }

    // wslc.runtime — the runtime/API contract is *not* probed: starting a
    // WSLC session is a side effect `plan` never performs. The adopted
    // identity model a wslc launch records: engine=wslc,
    // substrate=container, unit=container — the shared session VHD is
    // substrate plumbing, never unit=vm.
    checks.push(check(
        "wslc.runtime",
        PlanCheckStatus::Skipped,
        Some(
            "runtime contract unverified — probing it would start the WSLC \
             session, which plan never does; a launch records unit=container \
             (the shared session is substrate plumbing), never unit=vm"
                .to_string(),
        ),
    ));

    checks
}
