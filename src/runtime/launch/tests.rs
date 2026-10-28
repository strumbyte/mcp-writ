use super::*;

fn obs(control: &'static str, state: ControlState) -> EnforcementObservation {
    EnforcementObservation {
        control,
        state,
        basis: ObservationBasis::MechanismResult,
        phase: ControlPhase::Spawn,
        reason: None,
    }
}

/// Every OS control verified — no weakening tokens on the record.
#[test]
fn weakened_os_tokens_silent_on_full_enforcement() {
    let observations = vec![
        obs("os.privileges", ControlState::Verified),
        obs("os.fs", ControlState::Verified),
        obs("os.net.outbound", ControlState::Verified),
        obs("launch.identity", ControlState::Verified),
        obs("rpc.tools", ControlState::Unknown),
    ];
    assert_eq!(weakened_os_tokens(&observations), "");
}

/// A tolerated partial/absent application names the affected
/// controls with the same state vocabulary the report uses.
#[test]
fn weakened_os_tokens_names_degraded_controls() {
    let observations = vec![
        obs("os.fs", ControlState::PartiallyApplied),
        obs("os.net.outbound", ControlState::NotApplied),
        obs("os.syscalls", ControlState::Verified),
    ];
    assert_eq!(
        weakened_os_tokens(&observations),
        " os.fs=partially_applied os.net.outbound=not_applied"
    );
}

/// Non-OS observations never leak into the token list, and `unknown`
/// stays silent — an observation limit is not a tolerated weakening.
#[test]
fn weakened_os_tokens_excludes_non_os_and_unknown() {
    let observations = vec![
        obs("os.sandbox", ControlState::Unknown),
        obs("os.fs", ControlState::Unknown),
        obs("launch.env", ControlState::Failed),
        obs("launch.identity", ControlState::Failed),
        obs("rpc.tools", ControlState::Failed),
    ];
    assert_eq!(weakened_os_tokens(&observations), "");
}

/// An OS control whose apply failed beside a completed spawn is a
/// weakening too — it must not read as full enforcement.
#[test]
fn weakened_os_tokens_records_failed_os_control() {
    let observations = vec![
        obs("os.fs", ControlState::Failed),
        obs("os.privileges", ControlState::Verified),
    ];
    assert_eq!(weakened_os_tokens(&observations), " os.fs=failed");
}

/// `Warden::sandbox_backend` names the mechanism this host's
/// sandboxed dispatch is bound to — the value `enforcement.backend`
/// and the `backend=` detail token report. A caller-side sandbox
/// skip maps to `SandboxBackend::None` at the call site, not here;
/// a mechanism absent on this host binds to no backend and reports
/// `None` instead.
#[test]
fn sandbox_backend_matches_platform_dispatch() {
    let warden = Warden::new(Policy::default());
    #[cfg(target_os = "linux")]
    assert_eq!(warden.sandbox_backend(), SandboxBackend::LandlockSeccomp);
    #[cfg(target_os = "macos")]
    assert_eq!(warden.sandbox_backend(), SandboxBackend::SandboxExec);
    #[cfg(target_os = "windows")]
    assert_eq!(warden.sandbox_backend(), SandboxBackend::AppContainer);
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    assert_eq!(warden.sandbox_backend(), SandboxBackend::None);

    #[cfg(target_os = "windows")]
    {
        let psec = Warden::with_windows_mechanism(
            Policy::default(),
            crate::execution::WindowsNativeMechanism::Psec,
        );
        assert_eq!(psec.sandbox_backend(), SandboxBackend::Psec);
    }

    // A requested mechanism that does not exist on this host binds
    // to no backend — the launch refuses rather than report a
    // mechanism the dispatch can never run under.
    #[cfg(not(target_os = "windows"))]
    {
        let psec = Warden::with_windows_mechanism(
            Policy::default(),
            crate::execution::WindowsNativeMechanism::Psec,
        );
        assert_eq!(psec.sandbox_backend(), SandboxBackend::None);
    }
}

/// PR-26 — the legacy dispatch (`linux_mechanism: None`, the
/// in-guest runner's contract) must refuse a UDP-covered allow
/// under deny-all before spawn: the native route's socket pin
/// would make the grant dead policy. The refusal rides
/// `LaunchError::Spawn` carrying the "dead policy" evidence the
/// selection verdict produces.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn legacy_dispatch_refuses_udp_allow_under_deny_all() {
    let mut policy = Policy::default();
    policy.network.outbound.egress_rules = vec![crate::policy::EgressRule {
        allow: true,
        dest: crate::policy::EgressDest::Host("203.0.113.5".to_string()),
        proto: crate::policy::EgressProto::Udp,
        port: Some(53),
    }];
    let logger = AuditLogger::to_tracing();
    let err = launch(
        LaunchConfig {
            argv: vec!["/bin/true".to_string()],
            policy,
            fail_on: FailOn::None,
            dry_run: false,
            skip_sandbox: false,
            skip_reason: None,
            spawned_log_label: "test",
            policy_context: None,
            launch_id: None,
            workload_tmpdir: None,
            windows_mechanism: None,
            linux_mechanism: None,
            dns_upstream: None,
            component: "test",
            max_frame_bytes: crate::framing::DEFAULT_MAX_FRAME_BYTES,
        },
        &logger,
    )
    .await
    .err()
    .expect("a UDP allow under deny-all must refuse on the legacy dispatch");
    let LaunchError::Spawn { source, report, .. } = err else {
        panic!("expected LaunchError::Spawn");
    };
    assert!(
        source.to_string().contains("dead policy"),
        "source: {source}"
    );
    let detail = report
        .result
        .as_ref()
        .and_then(|r| r.detail.as_deref())
        .unwrap_or("");
    assert!(
        detail.contains("linux egress policy refused"),
        "detail: {detail}"
    );
    // The target must not claim a mechanism — nothing was bound.
    assert!(
        report.target.native_linux_mechanism.is_none(),
        "refused launch must not record a bound mechanism: {:?}",
        report.target
    );
}

/// A `Some(_)` request reaches selection instead — a policy both
/// routes refuse (an IPv6 + UDP-covering allow: v6 is dropped on
/// the namespaced route and the rule is dead on the native one)
/// surfaces the selection's verdict on every host, never the
/// legacy-only gate's `linux egress policy refused` detail.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn explicit_request_uses_selection_not_the_legacy_gate() {
    let mut policy = Policy::default();
    policy.network.outbound.egress_rules = vec![crate::policy::EgressRule {
        allow: true,
        dest: crate::policy::EgressDest::Cidr("2001:db8::/32".to_string()),
        proto: crate::policy::EgressProto::Any,
        port: None,
    }];
    let logger = AuditLogger::to_tracing();
    let err = launch(
        LaunchConfig {
            argv: vec!["/bin/true".to_string()],
            policy,
            fail_on: FailOn::None,
            dry_run: false,
            skip_sandbox: false,
            skip_reason: None,
            spawned_log_label: "test",
            policy_context: None,
            launch_id: None,
            workload_tmpdir: None,
            windows_mechanism: None,
            linux_mechanism: Some(crate::execution::LinuxMechanismRequest::Auto),
            dns_upstream: None,
            component: "test",
            max_frame_bytes: crate::framing::DEFAULT_MAX_FRAME_BYTES,
        },
        &logger,
    )
    .await
    .err()
    .expect("a policy no route satisfies must refuse pre-spawn");
    let LaunchError::Spawn { report, .. } = err else {
        panic!("expected LaunchError::Spawn");
    };
    let detail = report
        .result
        .as_ref()
        .and_then(|r| r.detail.as_deref())
        .unwrap_or("");
    assert!(
        detail.contains("linux egress mechanism selection refused"),
        "detail: {detail}"
    );
    assert!(
        !detail.contains("linux egress policy refused"),
        "detail: {detail}"
    );
}
