use super::*;

fn obs(control: &'static str, state: ControlState) -> EnforcementObservation {
    EnforcementObservation {
        control,
        state,
        basis: ObservationBasis::MechanismResult,
        phase: ControlPhase::Spawn,
        restriction: None,
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
            component: Emitter::Host,
            max_frame_bytes: crate::framing::DEFAULT_MAX_FRAME_BYTES,
        },
        &logger,
    )
    .await
    .err()
    .expect("a UDP allow under deny-all must refuse on the legacy dispatch");
    let LaunchError {
        kind: LaunchErrorKind::Spawn { source, .. },
        report,
        ..
    } = err
    else {
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
            component: Emitter::Host,
            max_frame_bytes: crate::framing::DEFAULT_MAX_FRAME_BYTES,
        },
        &logger,
    )
    .await
    .err()
    .expect("a policy no route satisfies must refuse pre-spawn");
    let LaunchError {
        kind: LaunchErrorKind::Spawn { .. },
        report,
        ..
    } = err
    else {
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

/// `TakeIo` carries the already-spawned child — `into_report` must run
/// the kill → wait → drop sequence exactly once, so a stdio failure
/// can never leave the workload running behind a `failed` report.
#[tokio::test]
async fn into_report_reaps_the_take_io_child() {
    let warden = Warden::new(Policy::default());
    // A sleeper that stays alive until killed: `cmd /q` blocks reading
    // our stdin pipe on Windows, `cat` does the same on Unix. The exe
    // is spelled absolute — this spawn API takes a resolved program,
    // not a PATH lookup.
    // The spawn API takes an argv[0]-inclusive vector — `argv[0]` is
    // the process name, `argv[1..]` the real arguments (`argv[0]` alone
    // is used verbatim as the command line's first token; an empty
    // vector is refused outright).
    #[cfg(windows)]
    let (exe, argv) = (
        crate::trusted_path::system32_path("cmd.exe")
            .expect("cmd.exe must resolve from the system directory"),
        // `/d` disables cmd's AutoRun commands — a registered AutoRun
        // could otherwise change how the fixture reads stdin — and
        // `/q` turns echo off. With no command to run, cmd then blocks
        // on our stdin pipe.
        vec!["cmd.exe".to_string(), "/d".to_string(), "/q".to_string()],
    );
    #[cfg(unix)]
    let (exe, argv) = (
        std::path::PathBuf::from("/bin/cat"),
        vec!["cat".to_string()],
    );
    let attempt = warden.spawn_unsandboxed_async_exe_with_report(
        &exe,
        &argv,
        &crate::warden::SpawnOptions::default(),
        "test",
        false,
    );
    let child = attempt.outcome.expect("unsandboxed spawn must succeed");
    let pid = child.id().expect("spawned child must carry a pid");
    // A `SYNCHRONIZE`-only handle to the *original* process object,
    // opened before cleanup hands the child to the error — after
    // `into_report` its signaled state tells whether that process
    // exited, which reopen-by-pid can never prove (a reused pid or a
    // surviving stray handle would still open).
    #[cfg(windows)]
    let exit_probe = take_io_test_exit_probe(pid);
    // The fixture must be alive *and* blocked before cleanup — a child
    // that already exited would let `into_report` pass without proving
    // anything about a live workload's reap.
    #[cfg(unix)]
    assert!(
        take_io_test_process_alive(pid),
        "the fixture child must be alive before into_report"
    );
    #[cfg(windows)]
    assert!(
        !exit_probe.exited(),
        "the fixture child must be running (unsignaled) before into_report"
    );

    let logger = AuditLogger::to_tracing();
    let fail = FailCtx {
        audit_logger: &logger,
        launch_id: uuid::Uuid::new_v4(),
        target: ExecutionTarget::native(),
        policy_context: None,
        dry_run: false,
        backend: warden.sandbox_backend(),
        component: Emitter::Host,
    };
    let report = fail.fail(
        warden.enforcement_plan(
            None,
            "",
            &crate::warden::SpawnOptions::default(),
            Some("test"),
            false,
        ),
        Vec::new(),
        LaunchIdentity::for_launch(&argv, &[]).finish(),
        "stdio capture failed".to_string(),
    );
    let err = fail.err(
        LaunchErrorKind::TakeIo {
            child: Box::new(child),
            keeps: SessionKeeps {
                _spawn_pin: None,
                #[cfg(all(unix, not(target_os = "linux")))]
                _exec_staging: None,
            },
        },
        report,
    );
    // Bound the cleanup itself: the TakeIo child blocks on stdin, so a
    // broken reap would hang here rather than fail. On timeout the
    // fixture is terminated through a fresh pid-level handle —
    // independent of whatever `into_report` left behind — so the test
    // fails without leaving a stray child running.
    let report =
        match tokio::time::timeout(std::time::Duration::from_secs(30), err.into_report()).await {
            Ok(report) => report,
            Err(_) => {
                take_io_test_force_kill(pid);
                panic!("into_report did not reap the TakeIo child within 30s");
            }
        };
    assert_eq!(
        report.result.as_ref().map(|r| r.status),
        Some("failed"),
        "the TakeIo report must still record the launch as failed"
    );

    // `into_report` ran kill → wait → drop — the original process object
    // must already be signaled *now*. Checking the pre-cleanup probe
    // immediately proves the reap happened inside cleanup; an exit that
    // lands afterwards must not satisfy the assertion.
    #[cfg(unix)]
    assert!(
        !take_io_test_process_alive(pid),
        "the TakeIo child (pid {pid}) is still running after into_report"
    );
    #[cfg(windows)]
    assert!(
        exit_probe.exited(),
        "the TakeIo child (pid {pid}) is still running after into_report"
    );
}

/// Whether `pid` still names a live process: signal-0 probe — a reaped
/// child fails it.
#[cfg(unix)]
fn take_io_test_process_alive(pid: u32) -> bool {
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    unsafe { libc::kill(pid as libc::pid_t, 0) == 0 }
}

/// Pid-level termination independent of the child object — the escape
/// hatch when the bounded `into_report` times out, so a wedged fixture
/// can never outlive the failing test.
#[cfg(unix)]
fn take_io_test_force_kill(pid: u32) {
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    unsafe {
        libc::kill(pid as libc::pid_t, libc::SIGKILL);
    }
}

/// Windows counterpart — a fresh `PROCESS_TERMINATE` handle on the pid,
/// not any handle the child object or the probe owns.
#[cfg(windows)]
fn take_io_test_force_kill(pid: u32) {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Threading::{OpenProcess, PROCESS_TERMINATE, TerminateProcess};
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    let Ok(handle) = (unsafe { OpenProcess(PROCESS_TERMINATE, false, pid) }) else {
        return;
    };
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    unsafe {
        let _ = TerminateProcess(handle, 1);
        let _ = CloseHandle(handle);
    }
}

/// A `SYNCHRONIZE` handle opened on the child *before* cleanup — its
/// signaled state afterwards is the exit verdict, which reopen-by-pid
/// can never prove (a reused pid or a surviving stray handle would
/// still open).
#[cfg(windows)]
struct TakeIoExitProbe(windows::Win32::Foundation::HANDLE);

#[cfg(windows)]
fn take_io_test_exit_probe(pid: u32) -> TakeIoExitProbe {
    use windows::Win32::System::Threading::{OpenProcess, PROCESS_SYNCHRONIZE};
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    let handle = unsafe { OpenProcess(PROCESS_SYNCHRONIZE, false, pid) }
        .expect("the just-spawned child must open with SYNCHRONIZE access");
    TakeIoExitProbe(handle)
}

#[cfg(windows)]
impl TakeIoExitProbe {
    /// `true` once the original process object is signaled — i.e. the
    /// child actually terminated. Independent of pid reuse and of any
    /// handle the warden itself still holds.
    fn exited(&self) -> bool {
        use windows::Win32::Foundation::WAIT_OBJECT_0;
        use windows::Win32::System::Threading::WaitForSingleObject;
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe { WaitForSingleObject(self.0, 0) == WAIT_OBJECT_0 }
    }
}

#[cfg(windows)]
impl Drop for TakeIoExitProbe {
    fn drop(&mut self) {
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        let _ = unsafe { windows::Win32::Foundation::CloseHandle(self.0) };
    }
}
