//! Image mode: `mcp-writ plan --engine <e> --image <ref> --policy <path>`
//! — the isolation backend, engine, image, and guest-runner prerequisites
//! a `run-image` launch would enforce, diagnosed read-only.

use std::path::Path;

use crate::cli::PlanArgs;
use crate::enforcement::{
    ControlLayer, ControlState, EnforcementPlan, PlanCheck, PlanCheckStatus, PlanReport,
    PlannedControl, ToolDisposition,
};
use crate::execution::{EngineName, ExecutionTarget, IsolationKind, TargetArch, TargetOs};

use super::host::{host_os_check, wslc_environment_checks};
use super::report::{base_report, check, failing_check, finalize, load_policy_check};

/// The launch target an `--image` plan records: substrate and workload
/// OS follow the isolation method (a VM-boundary method is not the
/// Linux container contract), and `engine` — which names a container
/// engine — is recorded when the backend is engine-driven (`container`,
/// and `kata` whose VM is launched by `docker run --runtime kata`); an
/// engine-less method records none.
fn image_target(engine: Option<EngineName>, isolation: IsolationKind) -> ExecutionTarget {
    let mut target = ExecutionTarget::linux_container(engine, None);
    target.substrate = isolation.substrate();
    target.workload_os = isolation.guest_os();
    if !crate::container::backends::engine_backed(isolation) {
        target.engine = None;
    }
    target
}

/// Image mode: `mcp-writ plan --engine <e> --image <ref> --policy <path>`.
///
/// Inspects the *local* image only — no pull, no container start, no
/// daemon configuration change.
pub(super) async fn diagnose_image(args: &PlanArgs, image: &str) -> PlanReport {
    // The isolation method is a separate selection from the engine —
    // it decides which backend would launch the workload and which
    // substrate the target records.
    let isolation = args.isolation.unwrap_or(IsolationKind::Container);
    let mut report = base_report(image_target(args.engine.map(EngineName::from), isolation));
    // host.os first — every image plan records the diagnosed host
    // environment before the method/engine checks.
    report.checks.push(host_os_check().await);
    let launch_control = |id: &'static str| PlannedControl {
        id,
        layer: ControlLayer::Launch,
        mechanism: "container launch",
        state: ControlState::Planned,
        reason: None,
    };
    let mut plan_controls = vec![
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
    ];

    // isolation.backend — the selection contract. An unimplemented
    // method, or an implemented one this host OS is out of scope for,
    // blocks the plan exactly as run-image refuses it: no silent
    // fallback to a normal container.
    let backend_caps = crate::container::backends::capabilities_for(isolation);
    let backend_available = backend_caps
        .map(|c| c.oci_image && c.host_os.contains(&TargetOs::host()))
        .unwrap_or(false);
    match backend_caps {
        Some(caps) if !caps.oci_image => {
            report.checks.push(failing_check("isolation.backend",
                "windows-sandbox requires a command payload".into(),
                "use plan --isolation windows-sandbox --sandbox-payload <dir> --sandbox-state <dir> --policy <file> -- <relative.exe>".into()));
        }
        Some(caps) if !caps.host_os.contains(&TargetOs::host()) => {
            report.checks.push(failing_check(
                "isolation.backend",
                format!(
                    "isolation method '{}' is not supported on this host OS \
                     ({}) — declared host OSs: {}",
                    isolation.name(),
                    TargetOs::host().name(),
                    caps.host_os
                        .iter()
                        .map(|o| o.name())
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
                "run on a supported host OS, or select an implemented method".to_string(),
            ));
        }
        Some(_) => {
            let detail = match isolation {
                IsolationKind::Kata => "kata VM isolation via docker's registered `kata` runtime \
                     (prerequisites checked under `kata.runtime`)"
                    .to_string(),
                IsolationKind::AppleContainer => "apple `container` per-unit VM isolation via \
                     the `container` CLI (prerequisites checked under `apple.system`)"
                    .to_string(),
                IsolationKind::HyperV => "Hyper-V utility-VM isolation via docker's \
                     `--isolation=hyperv` (prerequisites checked under `hyperv.engine`, \
                     image compatibility under `hyperv.image`)"
                    .to_string(),
                _ => "container isolation over the resolved engine (default)".to_string(),
            };
            report.checks.push(check(
                "isolation.backend",
                PlanCheckStatus::Pass,
                Some(detail),
            ));
        }
        None => {
            report.checks.push(failing_check(
                "isolation.backend",
                format!(
                    "isolation method '{}' is not implemented in this build \
                     (implemented: {})",
                    isolation.name(),
                    crate::container::backends::implemented_names()
                ),
                "use an implemented isolation method, or upgrade to a build \
                 that implements this one"
                    .to_string(),
            ));
        }
    }

    // image.reference — digest pinning (mirrors run-image's refusal).
    if !args.allow_mutable_tag && !crate::container::runner::image_ref_is_digest_pinned(image) {
        report.checks.push(failing_check(
            "image.reference",
            format!("image reference '{image}' is not digest-pinned"),
            "pin the image with @sha256:<digest>, or pass --allow-mutable-tag".to_string(),
        ));
    } else if args.allow_mutable_tag && !crate::container::runner::image_ref_is_digest_pinned(image)
    {
        report.checks.push(PlanCheck {
            id: "image.reference",
            status: PlanCheckStatus::Warn,
            detail: Some(format!(
                "image reference '{image}' is tag-only; --allow-mutable-tag accepts it"
            )),
            remediation: Some(
                "pin the image with @sha256:<digest> for a reproducible launch".to_string(),
            ),
        });
    } else {
        report.checks.push(check(
            "image.reference",
            PlanCheckStatus::Pass,
            Some("image reference is digest-pinned".to_string()),
        ));
    }

    // engine.resolve — read-only resolution; no daemon mutation. A
    // resolved buildah is still not a usable `run-image` engine: it
    // builds and inspects images but cannot `run` a container. The
    // engine contract exists for the engine-driven backends (`container`
    // and `kata`) — a substrate-driven backend (`apple-container`)
    // resolves its own CLI instead: `--engine` does not apply to it and
    // is refused rather than silently ignored. An unavailable or
    // host-unsupported backend has nothing to probe.
    let engine = if !backend_available {
        report.checks.push(check(
            "engine.resolve",
            PlanCheckStatus::Skipped,
            Some("the selected isolation backend is unavailable".to_string()),
        ));
        None
    } else if !crate::container::backends::engine_backed(isolation) {
        if args.engine.is_some() {
            report.checks.push(failing_check(
                "engine.resolve",
                format!(
                    "--engine does not apply to --isolation {} — the launch is \
                     driven by the substrate's own CLI",
                    isolation.name()
                ),
                "drop --engine, or select an engine-driven isolation method".to_string(),
            ));
            None
        } else {
            match crate::container::backends::substrate_engine(isolation) {
                Some(Ok(e)) => {
                    report.checks.push(check(
                        "engine.resolve",
                        PlanCheckStatus::Pass,
                        Some(format!("substrate driver: {}", e.name())),
                    ));
                    Some(e)
                }
                Some(Err(e)) => {
                    report.checks.push(failing_check(
                        "engine.resolve",
                        format!("substrate driver unavailable: {e}"),
                        "install Apple's `container` tool so `container` resolves on \
                         PATH, then re-run"
                            .to_string(),
                    ));
                    None
                }
                // An implemented non-engine kind always has a driver
                // today — this arm is the contract fallback, not a
                // reachable state.
                None => {
                    report.checks.push(check(
                        "engine.resolve",
                        PlanCheckStatus::Skipped,
                        Some("the backend has no substrate driver".to_string()),
                    ));
                    None
                }
            }
        }
    } else if let Some(kind) = args.engine
        && !crate::container::backends::engine_kind_applies(kind, isolation)
    {
        // The engine resolved fine is not the same as the engine this
        // backend can be driven by — an explicit `--engine wslc` paired
        // with a VM method would otherwise report a successful resolve
        // and fail one check later (`kata.runtime`/`hyperv.engine`
        // naming "engine 'wslc' is not the validated ..."). Refuse the
        // combination here, at the selection check.
        report.checks.push(failing_check(
            "engine.resolve",
            format!(
                "--engine {} does not apply to --isolation {} — wslc (WSL \
                 Containers) only drives --isolation container on a Windows \
                 host; this method's validated engine contract is docker",
                crate::execution::EngineName::from(kind).name(),
                isolation.name()
            ),
            "drop --engine wslc, or select --isolation container".to_string(),
        ));
        None
    } else {
        match crate::container::engine::resolve_engine(args.engine) {
            Ok(e) if e.name() == "buildah" => {
                report.checks.push(failing_check(
                    "engine.resolve",
                    "buildah does not support 'run' for container execution".to_string(),
                    "install docker or podman and ensure it is on PATH, or pass \
                     --engine docker|podman"
                        .to_string(),
                ));
                None
            }
            Ok(e) => {
                report.checks.push(check(
                    "engine.resolve",
                    PlanCheckStatus::Pass,
                    Some(format!("engine: {}", e.name())),
                ));
                Some(e)
            }
            Err(e) => {
                // The non-container pairing was refused above — a wslc
                // resolve failure here is on `container`, the only
                // engine-driven method wslc applies to.
                let remediation = if args.engine == Some(crate::container::engine::EngineKind::Wslc)
                {
                    "the wsl.* and wslc.* checks record what failed — the wslc \
                     engine needs Store WSL with a wslc.exe on the validated \
                     3.0.x line (≥ 3.0.1); WSL is never installed or updated \
                     by mcp-writ"
                        .to_string()
                } else {
                    "install docker or podman and ensure it is on PATH, or pass \
                     --engine docker|podman"
                        .to_string()
                };
                report.checks.push(failing_check(
                    "engine.resolve",
                    format!("no usable container engine: {e}"),
                    remediation,
                ));
                None
            }
        }
    };

    // WSL/WSLC environment diagnostics — only when the wslc engine was
    // selected for the `container` substrate it drives. Another
    // isolation method owns its own engine contract (kata/hyperv
    // resolve through docker; a substrate-driven backend refuses
    // --engine outright), so WSL evidence there is noise on top of an
    // already-refused selection. Three tiers stay distinct: presence
    // (PATH/install-dir resolution), `--version` facts, and the runtime
    // contract (never probed — a session/container start is a side
    // effect plan does not perform).
    if args.engine == Some(crate::container::engine::EngineKind::Wslc)
        && isolation == IsolationKind::Container
    {
        report.checks.extend(wslc_environment_checks().await);
    }

    // The report target names the resolved engine, not just the CLI hint.
    if let Some(e) = engine.as_ref() {
        report.target.engine = EngineName::from_name(e.name());
    }

    // engine.locality — host bind mounts only reach a local daemon; the
    // same env-var hint run-image refuses on is diagnosed here. The
    // substrate OS comes from `<cli> info` (read-only): an unprobeable
    // OS stays `unknown` rather than borrowing the CLI host's.
    if let Some(e) = engine.as_ref() {
        if let Some(reason) = crate::container::guest_report::remote_daemon_hint(e.name()) {
            report.checks.push(failing_check(
                "engine.locality",
                reason,
                "point the engine at a local daemon, or unset the remote \
                 endpoint env var (DOCKER_HOST / CONTAINER_HOST)"
                    .to_string(),
            ));
        } else {
            match tokio::time::timeout(std::time::Duration::from_secs(5), e.info()).await {
                Ok(Ok(info)) => {
                    if let Some(os) = crate::container::engine::engine_info_os(e.name(), &info) {
                        report.target.substrate_os = os;
                    }
                    report.checks.push(check(
                        "engine.locality",
                        PlanCheckStatus::Pass,
                        Some(format!(
                            "local engine endpoint (substrate {})",
                            report.target.substrate_os.name()
                        )),
                    ));
                }
                _ => {
                    report.checks.push(PlanCheck {
                        id: "engine.locality",
                        status: PlanCheckStatus::Warn,
                        detail: Some(
                            "engine substrate OS could not be probed; recorded as unknown"
                                .to_string(),
                        ),
                        remediation: None,
                    });
                }
            }
        }
    } else {
        let reason = if !backend_available {
            "the selected isolation backend is unavailable"
        } else if crate::container::backends::engine_backed(isolation) {
            "container engine unavailable"
        } else {
            "substrate driver unavailable"
        };
        report.checks.push(check(
            "engine.locality",
            PlanCheckStatus::Skipped,
            Some(reason.to_string()),
        ));
    }

    // kata.runtime — when kata isolation is selected, the validated
    // configuration's prerequisites are probed read-only (`docker info`
    // runtime registration + stat on the host device nodes; nothing is
    // installed or reconfigured). A missing piece blocks the plan —
    // run-image refuses the same way at check time.
    if isolation == IsolationKind::Kata {
        let entry = if !backend_available {
            check(
                "kata.runtime",
                PlanCheckStatus::Skipped,
                Some("the kata backend is unavailable on this host OS".to_string()),
            )
        } else {
            match engine.as_ref() {
                Some(e) => match crate::container::backends::kata::probe(e.as_ref()).await {
                    Ok(detail) => check("kata.runtime", PlanCheckStatus::Pass, Some(detail)),
                    Err(f) => failing_check(
                        "kata.runtime",
                        f.detail,
                        crate::container::backends::kata::prereq_remediation(f.prereq),
                    ),
                },
                None => check(
                    "kata.runtime",
                    PlanCheckStatus::Skipped,
                    Some("container engine unavailable".to_string()),
                ),
            }
        };
        report.checks.push(entry);
    }

    // apple.system — when apple-container isolation is selected, the
    // validated configuration's prerequisites are probed read-only
    // (`system status` + `system property list`; nothing is started or
    // reconfigured). A missing piece blocks the plan — run-image
    // refuses the same way at check time.
    if isolation == IsolationKind::AppleContainer {
        let entry = if !backend_available {
            check(
                "apple.system",
                PlanCheckStatus::Skipped,
                Some("the apple container backend is unavailable on this host OS".to_string()),
            )
        } else {
            match engine.as_ref() {
                Some(e) => match crate::container::backends::apple::probe(e.as_ref()).await {
                    Ok(detail) => check("apple.system", PlanCheckStatus::Pass, Some(detail)),
                    Err(f) => failing_check(
                        "apple.system",
                        f.detail,
                        crate::container::backends::apple::prereq_remediation(f.prereq),
                    ),
                },
                None => check(
                    "apple.system",
                    PlanCheckStatus::Skipped,
                    Some("substrate driver unavailable".to_string()),
                ),
            }
        };
        report.checks.push(entry);
    }

    // hyperv.engine — when hyperv isolation is selected, the validated
    // configuration's prerequisites are probed read-only (`docker info`
    // OSType/OSVersion plus an `sc query` on the Hyper-V services;
    // nothing is started or reconfigured). A missing piece blocks the
    // plan — run-image refuses the same way at check time. The probed
    // host build is kept for the image-compat check below.
    let mut hyperv_host_build: Option<String> = None;
    if isolation == IsolationKind::HyperV {
        let entry = if !backend_available {
            check(
                "hyperv.engine",
                PlanCheckStatus::Skipped,
                Some("the hyperv backend is unavailable on this host OS".to_string()),
            )
        } else {
            match engine.as_ref() {
                Some(e) => match crate::container::backends::hyperv::probe(e.as_ref()).await {
                    Ok(probe) => {
                        hyperv_host_build = Some(probe.host_os_version.clone());
                        check("hyperv.engine", PlanCheckStatus::Pass, Some(probe.detail))
                    }
                    Err(f) => failing_check(
                        "hyperv.engine",
                        f.detail,
                        crate::container::backends::hyperv::prereq_remediation(f.prereq),
                    ),
                },
                None => check(
                    "hyperv.engine",
                    PlanCheckStatus::Skipped,
                    Some("container engine unavailable".to_string()),
                ),
            }
        };
        report.checks.push(entry);
    }

    // policy.load — validated against the guest contract the selected
    // isolation method would carry, not always the Linux container one.
    let guest_target = image_target(
        engine
            .as_ref()
            .and_then(|e| EngineName::from_name(e.name())),
        isolation,
    );
    // run-image mounts ./policy.kdl when --policy is omitted — the plan
    // evaluates the file the launch would actually carry.
    let policy_path = args.policy.as_deref().unwrap_or(Path::new("./policy.kdl"));
    let policy = load_policy_check(
        &mut report,
        Some(policy_path),
        args.server.as_deref(),
        &guest_target,
    );

    // image.inspect — local inspect only; a missing image is a blocked
    // prerequisite, never an implicit pull. Bounded like `engine.locality`:
    // a wedged daemon turns inspect into a failed prerequisite rather than
    // a hung plan.
    if let Some(engine) = engine.as_ref() {
        let inspected = match tokio::time::timeout(
            std::time::Duration::from_secs(5),
            crate::container::inspect::inspect_image(engine.as_ref(), image),
        )
        .await
        {
            Ok(res) => res,
            Err(_) => Err(crate::error::ContainerError::InspectExec(format!(
                "{} image inspect timed out after 5s",
                engine.name()
            ))),
        };
        match inspected {
            Ok(meta) => {
                report.checks.push(check(
                    "image.inspect",
                    PlanCheckStatus::Pass,
                    Some("image metadata inspected locally".to_string()),
                ));

                // image.os — the workload's OS is the image's guest OS,
                // never the CLI host's. Both defined guest contracts
                // (linux, windows) pass; whether the selected isolation
                // backend can actually launch that guest is a separate
                // check below. An unknown OS is refused rather than
                // assumed Linux.
                match crate::container::guest_report::check_guest_image_os(meta.os.as_deref()) {
                    Ok(os) => {
                        report.target.workload_os = os;
                        report.checks.push(check(
                            "image.os",
                            PlanCheckStatus::Pass,
                            Some(format!(
                                "image OS '{}' matches the {} guest contract",
                                meta.os.as_deref().unwrap_or(os.name()),
                                os.name()
                            )),
                        ));
                    }
                    Err(e) => {
                        report.checks.push(failing_check(
                            "image.os",
                            e,
                            "wrap a Linux or Windows image — the embedded \
                             mcp-secure-runner must match the guest OS"
                                .to_string(),
                        ));
                    }
                }
                report.target.workload_arch =
                    crate::container::guest_report::image_target_arch(meta.architecture.as_deref());

                // image.arch — the OCI substrate can bridge a foreign
                // image arch via binfmt/qemu-user; a VM substrate cannot:
                // the kata VM boots a host-arch guest kernel, the apple
                // VM's only foreign-arch path is Rosetta translation,
                // the hyperv contract ships windows/amd64 only, and the
                // wslc session VM runs the host's architecture — none is
                // the validated boundary for a foreign arch. A
                // mismatched image is the same refusal run-image applies.
                let foreign_arch = report.target.workload_arch != TargetArch::host();
                let wslc_container = isolation == IsolationKind::Container
                    && args.engine == Some(crate::container::engine::EngineKind::Wslc);
                if (matches!(
                    isolation,
                    IsolationKind::Kata | IsolationKind::AppleContainer | IsolationKind::HyperV
                ) || wslc_container)
                    && foreign_arch
                {
                    let detail = if wslc_container {
                        format!(
                            "the wslc session VM runs the host's {} architecture — \
                             image architecture '{}' has no emulation bridge in the \
                             validated contract",
                            TargetArch::host().name(),
                            report.target.workload_arch.name()
                        )
                    } else if isolation == IsolationKind::Kata {
                        format!(
                            "the kata VM boots a {} guest kernel — image architecture \
                             '{}' cannot run on this host",
                            TargetArch::host().name(),
                            report.target.workload_arch.name()
                        )
                    } else if isolation == IsolationKind::HyperV {
                        format!(
                            "the hyperv backend launches windows/amd64 images — image \
                             architecture '{}' is outside the validated contract",
                            report.target.workload_arch.name()
                        )
                    } else {
                        format!(
                            "the apple `container` VM launches native-arch images — image \
                             architecture '{}' on this {} host would run only under \
                             Rosetta translation, which is not the validated isolation \
                             boundary",
                            report.target.workload_arch.name(),
                            TargetArch::host().name()
                        )
                    };
                    report.checks.push(failing_check(
                        "image.arch",
                        detail,
                        "use an image built for the host architecture, or select \
                         container isolation"
                            .to_string(),
                    ));
                }

                // runner.entrypoint — the guest contract's runner path,
                // per the image's guest OS (never a hardcoded literal).
                let entrypoint = meta.entrypoint.as_deref().unwrap_or(&[]);
                let runner_path =
                    crate::container::guest_layout::for_guest_os(report.target.workload_os)
                        .map(|l| l.runner_path);
                match runner_path {
                    Some(path) if entrypoint.first().map(String::as_str) == Some(path) => {
                        report.checks.push(check(
                            "runner.entrypoint",
                            PlanCheckStatus::Pass,
                            Some(format!("image ENTRYPOINT[0] is {path}")),
                        ));
                    }
                    Some(path) => {
                        report.checks.push(failing_check(
                            "runner.entrypoint",
                            format!("image ENTRYPOINT[0] is not {path}"),
                            "wrap or containerize the image first \
                             (`mcp-writ wrap-image` / `mcp-writ containerize`)"
                                .to_string(),
                        ));
                    }
                    None => {
                        report.checks.push(failing_check(
                            "runner.entrypoint",
                            format!(
                                "no guest contract for image OS '{}'",
                                report.target.workload_os.name()
                            ),
                            "wrap a Linux or Windows image".to_string(),
                        ));
                    }
                }

                // isolation.guest_os — the backend must declare the
                // image's guest OS. A Windows image is a defined guest
                // contract, but no backend launches it yet (the Hyper-V
                // backend is PR-22) — surface that as a plan failure
                // rather than a launch-time surprise.
                if let Some(caps) = crate::container::backends::capabilities_for(isolation)
                    && !caps.guest_os.contains(&report.target.workload_os)
                {
                    report.checks.push(failing_check(
                        "isolation.guest_os",
                        format!(
                            "isolation method '{}' does not launch {} guests \
                             (declared guest OSs: {})",
                            isolation.name(),
                            report.target.workload_os.name(),
                            caps.guest_os
                                .iter()
                                .map(|o| o.name())
                                .collect::<Vec<_>>()
                                .join(", ")
                        ),
                        "use an isolation backend that supports the image's \
                         guest OS"
                            .to_string(),
                    ));
                }

                // hyperv.image — the guest-build compatibility rule:
                // the image's recorded `OsVersion` build may not be
                // newer than the host's. The host side comes from the
                // `hyperv.engine` probe; when it never ran (backend or
                // engine unavailable) the check is skipped rather than
                // guessed. A windows guest on the wrong substrate is
                // refused by `isolation.guest_os` below — this check
                // runs only for the hyperv selection.
                if isolation == IsolationKind::HyperV {
                    let entry = match hyperv_host_build.as_deref() {
                        Some(host_build) if report.target.workload_os == TargetOs::Windows => {
                            match crate::container::backends::hyperv::image_version_check(
                                meta.os_version.as_deref(),
                                host_build,
                            ) {
                                None => check(
                                    "hyperv.image",
                                    PlanCheckStatus::Pass,
                                    Some(format!(
                                        "image build {} ≤ host build {host_build}",
                                        meta.os_version.as_deref().unwrap_or("<absent>")
                                    )),
                                ),
                                Some(detail) => failing_check(
                                    "hyperv.image",
                                    detail,
                                    crate::container::backends::hyperv::prereq_remediation(
                                        crate::container::backends::hyperv::HypervPrereq::ImageVersion,
                                    ),
                                ),
                            }
                        }
                        Some(_) => check(
                            "hyperv.image",
                            PlanCheckStatus::Skipped,
                            Some("the image's guest is not windows".to_string()),
                        ),
                        None => check(
                            "hyperv.image",
                            PlanCheckStatus::Skipped,
                            Some("the hyperv.engine probe did not produce a host build".to_string()),
                        ),
                    };
                    report.checks.push(entry);
                }

                // runner.caps — the capability marker env recorded at
                // build time. An absent marker is a legacy runner: it
                // still launches, but `run-image --report` refuses it —
                // a warning here, not a block.
                match crate::container::guest_report::caps_from_image_env(&meta.env) {
                    Some(caps) if caps.guest_report_capable() => {
                        report.checks.push(check(
                            "runner.caps",
                            PlanCheckStatus::Pass,
                            Some(format!(
                                "runner v{} claims the guest report capability",
                                caps.version
                            )),
                        ));
                    }
                    Some(caps) => {
                        report.checks.push(PlanCheck {
                            id: "runner.caps",
                            status: PlanCheckStatus::Warn,
                            detail: Some(format!(
                                "runner v{} does not claim the guest report capability",
                                caps.version
                            )),
                            remediation: Some(
                                "rebuild the image with a current mcp-secure-runner to \
                                 enable `run-image --report` guest reports"
                                    .to_string(),
                            ),
                        });
                    }
                    None => {
                        report.checks.push(PlanCheck {
                            id: "runner.caps",
                            status: PlanCheckStatus::Warn,
                            detail: Some(
                                "no runner capability marker on the image (legacy build); \
                                 `run-image --report` refuses this image"
                                    .to_string(),
                            ),
                            remediation: Some(
                                "rebuild the image with a current mcp-secure-runner via \
                                 wrap-image or containerize"
                                    .to_string(),
                            ),
                        });
                    }
                }

                // image.digest_match — policy docker-manifest-hash entries.
                if let Some(policy) = policy.as_ref() {
                    // Workload pins are not host-checkable on an image
                    // launch — `mcp-secure-runner` verifies them inside the
                    // guest at workload launch. `skipped`, not `pass`:
                    // nothing ran here.
                    let guest_pins = policy
                        .hash_entries
                        .iter()
                        .filter(|e| !matches!(e.hash_type, crate::policy::HashType::DockerManifest))
                        .count();
                    if guest_pins > 0 {
                        report.checks.push(check(
                            "guest.hash",
                            PlanCheckStatus::Skipped,
                            Some(format!(
                                "{guest_pins} workload hash entries \
                                 (binary-hash/entrypoint-hash/lockfile-hash) verify inside \
                                 the guest at launch — not by this host-side plan; see the \
                                 guest report's code_identity"
                            )),
                        ));
                    }
                    let docker_hashes: Vec<_> = policy
                        .hash_entries
                        .iter()
                        .filter(|e| e.hash_type == crate::policy::HashType::DockerManifest)
                        .collect();
                    if !docker_hashes.is_empty() {
                        let actual = meta.digest.as_deref().unwrap_or("");
                        if docker_hashes.iter().any(|e| e.hash_value == actual) {
                            report.checks.push(check(
                                "image.digest_match",
                                PlanCheckStatus::Pass,
                                Some(
                                    "image digest matches the policy's docker-manifest-hash"
                                        .to_string(),
                                ),
                            ));
                        } else {
                            report.checks.push(failing_check(
                                "image.digest_match",
                                format!(
                                    "image digest '{}' does not match any docker-manifest-hash in the policy",
                                    if actual.is_empty() { "(missing)" } else { actual }
                                ),
                                "rebuild or re-pull the pinned image, or update the policy's \
                                 docker-manifest-hash entries"
                                    .to_string(),
                            ));
                        }
                    }
                }
            }
            Err(e) => {
                report.checks.push(failing_check(
                    "image.inspect",
                    format!("failed to inspect image '{image}': {e}"),
                    "build or pull the image locally first — `plan` never pulls".to_string(),
                ));
            }
        }
    } else {
        // Driver resolution failed or the selected isolation backend is
        // unavailable — image checks cannot run.
        let reason = if !backend_available {
            "the selected isolation backend is unavailable"
        } else if crate::container::backends::engine_backed(isolation) {
            "container engine unavailable"
        } else {
            "substrate driver unavailable"
        };
        report.checks.push(check(
            "image.inspect",
            PlanCheckStatus::Skipped,
            Some(reason.to_string()),
        ));
        report.checks.push(check(
            "image.os",
            PlanCheckStatus::Skipped,
            Some(reason.to_string()),
        ));
        report.checks.push(check(
            "runner.entrypoint",
            PlanCheckStatus::Skipped,
            Some(reason.to_string()),
        ));
        report.checks.push(check(
            "runner.caps",
            PlanCheckStatus::Skipped,
            Some(reason.to_string()),
        ));
    }

    // audit.config — fail-closed logging requires a mounted
    // /var/log/mcp-secure inside the guest (`run-image --log-dir`);
    // mcp-secure-runner exits when it is absent. `plan` cannot verify a
    // later invocation's flags, so this is a warning, not a block — the
    // same treatment the native `audit.config` check gets.
    match policy.as_ref() {
        Some(p) if p.logging.fail_closed => {
            report.checks.push(PlanCheck {
                id: "audit.config",
                status: PlanCheckStatus::Warn,
                detail: Some(
                    "policy logging.fail_closed is on: `run-image` requires \
                     --log-dir <dir> mounted at /var/log/mcp-secure, which \
                     `plan` cannot verify"
                        .to_string(),
                ),
                remediation: Some("pass --log-dir <dir> to `run-image`".to_string()),
            });
        }
        Some(_) => {
            report.checks.push(check(
                "audit.config",
                PlanCheckStatus::Pass,
                Some(
                    "logging.fail_closed is off; guest audit events may go to tracing".to_string(),
                ),
            ));
        }
        None => {
            report.checks.push(check(
                "audit.config",
                PlanCheckStatus::Skipped,
                Some("policy unavailable".to_string()),
            ));
        }
    }

    // guest.contract — the in-guest sandbox/audit cannot be probed from
    // the host without launching; recorded as not-inspected rather than
    // assumed.
    report.checks.push(check(
        "guest.contract",
        PlanCheckStatus::Skipped,
        Some(
            "guest-side enforcement (Landlock/seccomp, auditor) is applied by \
             mcp-secure-runner inside the guest and is not probed here"
                .to_string(),
        ),
    ));

    // Host-side launch plan: what `run-image` sets up. The guest's own
    // enforcement plan is computed by mcp-secure-runner at container
    // start and is not observable here.
    let tools: Vec<ToolDisposition> = policy
        .as_ref()
        .map(|p| {
            p.tools
                .iter()
                .map(|t| ToolDisposition {
                    name: t.name.clone(),
                    server: t.server.clone(),
                    allowed: t.allowed,
                    side_effect: t.side_effect.clone(),
                })
                .collect()
        })
        .unwrap_or_default();
    // Mark plan controls whose prerequisite check failed.
    for c in plan_controls.iter_mut() {
        let blocked = match c.id {
            "launch.isolation" => {
                !backend_available
                    || report.checks.iter().any(|k| {
                        matches!(
                            k.id,
                            "kata.runtime" | "apple.system" | "hyperv.engine" | "hyperv.image"
                        ) && k.status == PlanCheckStatus::Fail
                    })
            }
            "launch.engine" => {
                engine.is_none()
                    || report
                        .checks
                        .iter()
                        .any(|k| k.id == "engine.locality" && k.status == PlanCheckStatus::Fail)
            }
            // The image control covers reference pinning, local presence,
            // the guest-OS contract, and digest-vs-policy matching — a
            // failed entrypoint check is the runner control's concern.
            "launch.image" => report.checks.iter().any(|k| {
                matches!(
                    k.id,
                    "image.reference"
                        | "image.inspect"
                        | "image.os"
                        | "image.arch"
                        | "image.digest_match"
                ) && k.status == PlanCheckStatus::Fail
            }),
            "launch.runner" => report.checks.iter().any(|k| {
                matches!(k.id, "image.inspect" | "runner.entrypoint")
                    && k.status == PlanCheckStatus::Fail
            }),
            "launch.policy" => policy.is_none(),
            _ => false,
        };
        if blocked {
            c.state = ControlState::Failed;
            c.reason = Some("prerequisite check failed".to_string());
        }
    }
    report.plan = Some(EnforcementPlan {
        controls: plan_controls,
        grants: Vec::new(),
        tools,
        limitations: vec![
            "host-side launch plan only: guest-side grants and sandbox observations \
             are produced by mcp-secure-runner inside the guest and are not \
             enumerated here"
                .to_string(),
        ],
    });
    finalize(report)
}
