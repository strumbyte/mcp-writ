//! Tests for `plan` dispatch and the per-isolation diagnostic contract
//! the image mode reports.

use std::path::Path;

use super::*;
use crate::enforcement::ControlState;

fn image_plan_args(isolation: Option<IsolationKind>) -> PlanArgs {
    PlanArgs {
        image: Some(
            "app@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                .to_string(),
        ),
        isolation,
        // Image mode defaults --policy to ./policy.kdl (run-image
        // parity); pin a real file so policy.load passes and the
        // asserted failure stays the test's own subject.
        policy: Some(Path::new(env!("CARGO_MANIFEST_DIR")).join("policy.example.kdl")),
        ..Default::default()
    }
}

/// A command-only isolation method blocks the image plan before any
/// engine or image probing — the same refusal `run-image` gives,
/// reported as a check rather than a silent fallback.
#[tokio::test]
async fn command_backend_blocks_image_plan() {
    let report = diagnose(image_plan_args(Some(IsolationKind::WindowsSandbox))).await;
    assert_eq!(report.status, PlanStatus::Blocked);
    assert_eq!(report.reason_code, Some("isolation_unsupported"));
    let c = report
        .checks
        .iter()
        .find(|c| c.id == "isolation.backend")
        .expect("isolation.backend check");
    assert_eq!(c.status, PlanCheckStatus::Fail);
    assert!(
        c.detail
            .as_deref()
            .unwrap_or_default()
            .contains("requires a command payload"),
        "got: {:?}",
        c.detail
    );
    // No engine probe ran — this command backend has no engine
    // contract; engine/image checks are skipped, not failed.
    let engine = report
        .checks
        .iter()
        .find(|c| c.id == "engine.resolve")
        .expect("engine.resolve check");
    assert_eq!(engine.status, PlanCheckStatus::Skipped);
    // The recorded substrate is the VM boundary the method would
    // give, not the container substrate — and a method not driven
    // through the resolved engine carries no container-engine
    // identity.
    assert_eq!(report.target.substrate.name(), "vm");
    assert_eq!(report.target.engine, None);
    // The launch plan marks the isolation control failed.
    let plan = report.plan.as_ref().expect("plan present");
    let iso = plan
        .controls
        .iter()
        .find(|c| c.id == "launch.isolation")
        .expect("launch.isolation control");
    assert_eq!(iso.state, ControlState::Failed);
}

/// The image-plan refusal identifies the command-only backend.
#[tokio::test]
async fn command_backend_image_plan_refusal_identifies_backend() {
    let kind = IsolationKind::WindowsSandbox;
    let report = diagnose(image_plan_args(Some(kind))).await;
    assert_eq!(report.status, PlanStatus::Blocked, "kind {}", kind.name());
    let c = report
        .checks
        .iter()
        .find(|c| c.id == "isolation.backend")
        .expect("isolation.backend check");
    assert_eq!(c.status, PlanCheckStatus::Fail, "kind {}", kind.name());
    assert!(
        c.detail.as_deref().unwrap().contains(kind.name()),
        "kind {}: {:?}",
        kind.name(),
        c.detail
    );
}

/// The default (`container`) isolation reports the backend check as
/// pass and keeps the container substrate — existing behavior is
/// preserved.
#[tokio::test]
async fn container_isolation_passes_the_backend_check() {
    let report = diagnose(image_plan_args(None)).await;
    let c = report
        .checks
        .iter()
        .find(|c| c.id == "isolation.backend")
        .expect("isolation.backend check");
    assert_eq!(c.status, PlanCheckStatus::Pass);
    assert_eq!(report.target.substrate.name(), "container");
    // engine.resolve still ran — the container path is unchanged.
    let engine = report
        .checks
        .iter()
        .find(|c| c.id == "engine.resolve")
        .expect("engine.resolve check");
    assert_ne!(
        engine.status,
        PlanCheckStatus::Skipped,
        "container isolation must not skip the engine probe"
    );
    let plan = report.plan.as_ref().expect("plan present");
    let iso = plan
        .controls
        .iter()
        .find(|c| c.id == "launch.isolation")
        .expect("launch.isolation control");
    assert_eq!(iso.state, ControlState::Planned);
}

/// `--isolation kata` is implemented, so plan diagnoses it instead
/// of refusing as unimplemented: `isolation.backend` is host-OS
/// gated (fail only off-Linux, where the validated dockerd+KVM stack
/// cannot exist), `kata.runtime` probes docker's runtime
/// registration and the KVM/vsock device nodes, and the recorded
/// target keeps the engine name because the launch is engine-driven.
#[tokio::test]
async fn kata_isolation_is_diagnosed_not_refused() {
    let report = diagnose(image_plan_args(Some(IsolationKind::Kata))).await;
    let backend = report
        .checks
        .iter()
        .find(|c| c.id == "isolation.backend")
        .expect("isolation.backend check");
    // Implemented, always — the detail never claims otherwise.
    assert!(
        !backend
            .detail
            .as_deref()
            .unwrap_or_default()
            .contains("not implemented"),
        "kata is implemented: {:?}",
        backend.detail
    );
    let kata_runtime = report
        .checks
        .iter()
        .find(|c| c.id == "kata.runtime")
        .expect("kata.runtime check recorded for --isolation kata");
    if cfg!(target_os = "linux") {
        assert_eq!(backend.status, PlanCheckStatus::Pass);
        // The runtime probe answers pass/fail when an engine is
        // resolvable, skipped only when there is no engine to ask.
        // A fail blocks the plan and the isolation control — never
        // a silent downgrade to a normal container.
        if kata_runtime.status == PlanCheckStatus::Fail {
            assert_eq!(report.status, PlanStatus::Blocked);
            assert_eq!(report.reason_code, Some("isolation_unsupported"));
            let plan = report.plan.as_ref().expect("plan present");
            let iso = plan
                .controls
                .iter()
                .find(|c| c.id == "launch.isolation")
                .expect("launch.isolation control");
            assert_eq!(iso.state, ControlState::Failed);
        }
    } else {
        // Off-Linux the declared-capability gate fails the backend
        // check before any engine work, and the runtime probe is
        // recorded skipped — never silently absent.
        assert_eq!(backend.status, PlanCheckStatus::Fail);
        assert!(
            backend
                .detail
                .as_deref()
                .unwrap_or_default()
                .contains("not supported on this host OS"),
            "got: {:?}",
            backend.detail
        );
        assert_eq!(kata_runtime.status, PlanCheckStatus::Skipped);
        assert_eq!(report.status, PlanStatus::Blocked);
        assert_eq!(report.reason_code, Some("isolation_unsupported"));
    }
    // The recorded target is the VM substrate with a Linux guest —
    // and `engine` stays recorded: `docker run --runtime kata` is
    // an engine-driven launch.
    assert_eq!(report.target.substrate.name(), "vm");
    assert_eq!(report.target.workload_os.name(), "linux");
    let _ = report.target.engine;
}

/// `--isolation apple-container` is implemented, so plan diagnoses
/// it instead of refusing as unimplemented: `isolation.backend` is
/// host-OS gated (fail only off-macOS, where the Virtualization.
/// framework substrate cannot exist), `apple.system` probes the
/// `container` service and guest kernel, and a resolved `container`
/// CLI driver is recorded as the launch's substrate identity.
#[tokio::test]
async fn apple_isolation_is_diagnosed_not_refused() {
    let report = diagnose(image_plan_args(Some(IsolationKind::AppleContainer))).await;
    let backend = report
        .checks
        .iter()
        .find(|c| c.id == "isolation.backend")
        .expect("isolation.backend check");
    // Implemented, always — the detail never claims otherwise.
    assert!(
        !backend
            .detail
            .as_deref()
            .unwrap_or_default()
            .contains("not implemented"),
        "apple-container is implemented: {:?}",
        backend.detail
    );
    let apple_system = report
        .checks
        .iter()
        .find(|c| c.id == "apple.system")
        .expect("apple.system check recorded for --isolation apple-container");
    if cfg!(target_os = "macos") {
        // The backend's declared host scope is macOS itself — it
        // passes on Intel too. The Apple-Silicon restriction is
        // enforced one level down, by the `apple.system` probe.
        assert_eq!(backend.status, PlanCheckStatus::Pass);
        // The system probe answers pass/fail when the driver is
        // resolvable, skipped only when there is no driver to ask.
        // A fail blocks the plan and the isolation control — never
        // a silent downgrade to a normal container.
        if apple_system.status == PlanCheckStatus::Fail {
            assert_eq!(report.status, PlanStatus::Blocked);
            assert_eq!(report.reason_code, Some("isolation_unsupported"));
            let plan = report.plan.as_ref().expect("plan present");
            let iso = plan
                .controls
                .iter()
                .find(|c| c.id == "launch.isolation")
                .expect("launch.isolation control");
            assert_eq!(iso.state, ControlState::Failed);
        }
        if cfg!(target_arch = "aarch64") {
            // When the `container` CLI resolved, its substrate-driver
            // identity is recorded on the target.
            let engine = report
                .checks
                .iter()
                .find(|c| c.id == "engine.resolve")
                .expect("engine.resolve check");
            if engine.status == PlanCheckStatus::Pass {
                assert_eq!(
                    report.target.engine,
                    Some(crate::execution::EngineName::AppleContainer),
                    "the container CLI is the substrate driver identity"
                );
            }
        } else {
            // Intel macOS: the probe refuses a non-aarch64 host —
            // Fail when the `container` driver resolved, Skipped
            // when engine.resolve's own failure already blocked the
            // plan. It can never pass.
            assert_ne!(apple_system.status, PlanCheckStatus::Pass);
            assert_eq!(report.status, PlanStatus::Blocked);
        }
    } else {
        // Off-Apple-Silicon the declared-capability gate fails the
        // backend check before any driver work, and the system probe
        // is recorded skipped — never silently absent.
        assert_eq!(backend.status, PlanCheckStatus::Fail);
        assert!(
            backend
                .detail
                .as_deref()
                .unwrap_or_default()
                .contains("not supported on this host OS"),
            "got: {:?}",
            backend.detail
        );
        assert_eq!(apple_system.status, PlanCheckStatus::Skipped);
        assert_eq!(report.status, PlanStatus::Blocked);
        assert_eq!(report.reason_code, Some("isolation_unsupported"));
    }
    // The recorded target is the VM substrate with a Linux guest.
    assert_eq!(report.target.substrate.name(), "vm");
    assert_eq!(report.target.workload_os.name(), "linux");
}

/// `--engine` does not apply to a substrate-driven isolation — the
/// flag is refused as an engine.resolve failure rather than ignored.
/// (On non-macOS hosts the host-OS gate blocks the plan first.)
#[tokio::test]
async fn apple_isolation_refuses_an_engine_flag_in_plan() {
    let mut args = image_plan_args(Some(IsolationKind::AppleContainer));
    args.engine = Some(crate::container::engine::EngineKind::Docker);
    let report = diagnose(args).await;
    if cfg!(target_os = "macos") {
        let engine = report
            .checks
            .iter()
            .find(|c| c.id == "engine.resolve")
            .expect("engine.resolve check");
        assert_eq!(engine.status, PlanCheckStatus::Fail);
        assert!(
            engine
                .detail
                .as_deref()
                .unwrap_or_default()
                .contains("--engine"),
            "got: {:?}",
            engine.detail
        );
    } else {
        assert_eq!(report.status, PlanStatus::Blocked);
    }
}

/// A VM-substrate method's recorded target follows the method's
/// guest contract — `--isolation windows-sandbox --engine docker`
/// reports a Windows workload and drops the engine identity rather
/// than pairing a VM substrate with a container engine.
#[tokio::test]
async fn vm_isolation_target_records_its_own_contract() {
    let mut args = image_plan_args(Some(IsolationKind::WindowsSandbox));
    args.engine = Some(crate::container::engine::EngineKind::Docker);
    let report = diagnose(args).await;
    assert_eq!(report.status, PlanStatus::Blocked);
    assert_eq!(report.target.substrate.name(), "vm");
    assert_eq!(
        report.target.engine, None,
        "a VM substrate records no container engine"
    );
    assert_eq!(
        report.target.workload_os,
        crate::execution::TargetOs::Windows,
        "a Windows-scoped method records a Windows workload"
    );
}

/// `--engine wslc` under a non-`container` isolation does not emit
/// the WSL environment diagnostics — those describe the WSL
/// Containers candidate for the container substrate only; another
/// method owns its own engine contract and WSL evidence there is
/// noise on top of an already-refused selection.
#[tokio::test]
async fn wslc_engine_checks_apply_to_container_isolation_only() {
    for kind in [
        IsolationKind::Kata,
        IsolationKind::AppleContainer,
        IsolationKind::HyperV,
    ] {
        let mut args = image_plan_args(Some(kind));
        args.engine = Some(crate::container::engine::EngineKind::Wslc);
        let report = diagnose(args).await;
        assert!(
            report.checks.iter().all(|c| !c.id.starts_with("wsl")),
            "kind {}: no wsl.*/wslc.* checks — got {:?}",
            kind.name(),
            report.checks.iter().map(|c| c.id).collect::<Vec<_>>()
        );
    }
    // The default container isolation keeps emitting every tier.
    let mut args = image_plan_args(None);
    args.engine = Some(crate::container::engine::EngineKind::Wslc);
    let report = diagnose(args).await;
    for id in [
        "wsl.cli",
        "wsl.product",
        "wsl.distro",
        "wslc.cli",
        "wslc.runtime",
    ] {
        assert!(
            report.checks.iter().any(|c| c.id == id),
            "missing check {id} under container isolation"
        );
    }
}

/// An `invalid` result still names the host it was produced on —
/// every plan report carries the `host.os` record.
#[tokio::test]
async fn invalid_plan_records_host_os() {
    let mut args = image_plan_args(None);
    args.invalid_input = Some("test invalid input".to_string());
    let report = diagnose(args).await;
    assert_eq!(report.status, PlanStatus::Invalid);
    assert!(
        report.checks.iter().any(|c| c.id == "host.os"),
        "invalid results must record host.os"
    );
}
