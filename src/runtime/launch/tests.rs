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
    let descendant_dir = tempfile::tempdir().expect("create descendant fixture directory");
    #[cfg(unix)]
    let descendant_pidfile = descendant_dir.path().join("descendant.pid");
    // Unix: make the direct child exit immediately after spawning a
    // descendant. Cleanup must not treat the leader's own exit as proof
    // that the descendant tree is gone.
    #[cfg(unix)]
    let (exe, argv) = (
        std::path::PathBuf::from("/bin/sh"),
        vec![
            "sh".to_string(),
            "-c".to_string(),
            "sleep 120 & echo $! > \"$1\"; exit 0".to_string(),
            "sh".to_string(),
            descendant_pidfile.display().to_string(),
        ],
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
    #[cfg(unix)]
    {
        // Let the fixture reach its descendant-spawn/leader-exit point
        // before cleanup starts; otherwise the test would only repeat the
        // live-leader case.
        for _ in 0..20 {
            if descendant_pidfile.exists() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        assert!(
            descendant_pidfile.exists(),
            "the fixture did not spawn/publish its descendant before cleanup"
        );
        for _ in 0..20 {
            if unix_leader_exited_unreaped(pid) {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        assert!(
            unix_leader_exited_unreaped(pid),
            "the fixture leader did not exit before cleanup"
        );
    }
    #[cfg(unix)]
    let descendant: u32 = std::fs::read_to_string(&descendant_pidfile)
        .expect("the fixture must publish its descendant pid")
        .trim()
        .parse()
        .expect("descendant pid must be numeric");
    #[cfg(target_os = "linux")]
    let descendant_pidfd = linux_pidfd(descendant);
    #[cfg(all(unix, not(target_os = "linux")))]
    let descendant_pidfd = None::<std::os::fd::OwnedFd>;
    #[cfg(unix)]
    assert!(
        !descendant_exited(descendant, descendant_pidfd.as_ref()),
        "the descendant must be alive before cleanup"
    );
    #[cfg(unix)]
    let mut descendant_guard = DescendantCleanupGuard {
        pid: descendant,
        #[cfg(target_os = "linux")]
        pidfd: descendant_pidfd.as_ref().map(|fd| {
            use std::os::fd::AsRawFd;
            fd.as_raw_fd()
        }),
    };
    // A `SYNCHRONIZE`-only handle to the *original* process object,
    // opened before cleanup hands the child to the error — after
    // `into_report` its signaled state tells whether that process
    // exited, which reopen-by-pid can never prove (a reused pid or a
    // surviving stray handle would still open).
    #[cfg(windows)]
    let mut exit_probe = take_io_test_exit_probe(pid);
    #[cfg(unix)]
    let mut cleanup_guard = TakeIoCleanupGuard::new(pid);
    // The fixture must be alive *and* blocked before cleanup — a child
    // that already exited would let `into_report` pass without proving
    // anything about a live workload's reap.
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
            keeps: Box::new(SessionKeeps {
                _spawn_pin: None,
                #[cfg(all(unix, not(target_os = "linux")))]
                _exec_staging: None,
            }),
        },
        report,
    );
    // Bound the cleanup itself: the TakeIo child blocks on stdin, so a
    // broken reap would hang here rather than fail. On timeout the
    // fixture is terminated through a fresh pid-level handle —
    // independent of whatever `into_report` left behind — so the test
    // fails without leaving a stray child running.
    let mut cleanup = Box::pin(err.into_report());
    let report = match tokio::time::timeout(std::time::Duration::from_secs(30), &mut cleanup).await
    {
        Ok(report) => report,
        Err(_) => {
            // Dropping the timed-out future drops the RunningChild it owns:
            // Unix start_kill does not reap, so the pid still names this
            // fixture when the guard unwinds; Windows cleanup uses the
            // original object handle, never a reopened pid.
            drop(cleanup);
            panic!("into_report did not reap the TakeIo child within 30s");
        }
    };

    // The guard stays armed across exactly the liveness assertion, then is
    // disarmed before later report assertions where the child is known dead.
    #[cfg(unix)]
    assert!(
        !take_io_test_process_alive(pid),
        "the TakeIo child (pid {pid}) is still running after into_report"
    );
    #[cfg(unix)]
    cleanup_guard.disarm();
    #[cfg(unix)]
    {
        let mut gone = descendant_exited(descendant, descendant_pidfd.as_ref());
        for _ in 0..20 {
            if gone {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
            gone = descendant_exited(descendant, descendant_pidfd.as_ref());
        }
        assert!(
            gone,
            "the descendant (pid {descendant}) survived direct-child cleanup"
        );
        descendant_guard.disarm();
    }
    #[cfg(windows)]
    assert!(
        exit_probe.exited(),
        "the TakeIo child (pid {pid}) is still running after into_report"
    );
    #[cfg(windows)]
    exit_probe.disarm();
    assert_eq!(
        report.result.as_ref().map(|r| r.status),
        Some("failed"),
        "the TakeIo report must still record the launch as failed"
    );
}

#[cfg(unix)]
struct DescendantCleanupGuard {
    pid: u32,
    #[cfg(target_os = "linux")]
    pidfd: Option<i32>,
}

#[cfg(unix)]
impl DescendantCleanupGuard {
    fn disarm(&mut self) {
        self.pid = 0;
    }
}

#[cfg(unix)]
impl Drop for DescendantCleanupGuard {
    fn drop(&mut self) {
        if self.pid == 0 {
            return;
        }
        #[cfg(target_os = "linux")]
        if let Some(fd) = self.pidfd {
            // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
            unsafe {
                libc::syscall(
                    libc::SYS_pidfd_send_signal,
                    fd,
                    libc::SIGKILL,
                    std::ptr::null_mut::<libc::siginfo_t>(),
                    0,
                )
            };
            return;
        }
        // Without a pidfd there is no process-bound handle here. A raw
        // pid becomes unsafe as soon as the descendant exits and the
        // integer can be recycled, so — as in `TakeIoCleanupGuard` —
        // the guard is deliberately inert rather than risking an
        // unrelated process. The fixture's bounded 120 s sleep is the
        // fallback cleanup in that case.
        let _ = self.pid;
    }
}

/// Non-consuming exit notification for a direct child: WNOWAIT leaves
/// the zombie for the product's owner to reap.
#[cfg(unix)]
fn unix_leader_exited_unreaped(pid: u32) -> bool {
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    unsafe {
        libc::waitid(
            libc::P_PID,
            pid as libc::id_t,
            &mut info,
            libc::WEXITED | libc::WNOWAIT | libc::WNOHANG,
        ) == 0
            && info.si_pid() == pid as libc::pid_t
    }
}

#[cfg(target_os = "linux")]
fn linux_pidfd(pid: u32) -> Option<std::os::fd::OwnedFd> {
    use std::os::fd::FromRawFd;
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid as libc::pid_t, 0) };
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    (fd >= 0).then(|| unsafe { std::os::fd::OwnedFd::from_raw_fd(fd as i32) })
}

#[cfg(target_os = "linux")]
fn descendant_exited(pid: u32, pidfd: Option<&std::os::fd::OwnedFd>) -> bool {
    use std::os::fd::AsRawFd;
    // pidfd is the precise probe, but supported test hosts can deny or
    // lack pidfd_open. The descendant outlives the whole test deadline,
    // so the kill-0 fallback still distinguishes cleanup termination
    // from the fixture's natural exit.
    let Some(fd) = pidfd else {
        return !take_io_test_process_alive(pid);
    };
    let mut pfd = libc::pollfd {
        fd: fd.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    unsafe { libc::poll(&mut pfd, 1, 0) == 1 && pfd.revents & libc::POLLIN != 0 }
}

#[cfg(all(unix, not(target_os = "linux")))]
fn descendant_exited(pid: u32, _pidfd: Option<&std::os::fd::OwnedFd>) -> bool {
    !take_io_test_process_alive(pid)
}

/// Whether `pid` still names a live process: signal-0 probe — a reaped
/// child fails it.
#[cfg(unix)]
fn take_io_test_process_alive(pid: u32) -> bool {
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    unsafe { libc::kill(pid as libc::pid_t, 0) == 0 }
}

/// Unix cleanup owner for the fixture child. Once the child is moved into
/// `LaunchErrorKind::TakeIo`, the fixture no longer owns reap/termination.
/// A raw pid is therefore never signalled on platforms without a stable
/// process handle: after the product reaps the child, that integer can name
/// an unrelated reused process. Linux uses a pidfd, which remains bound to
/// the original process even after it is reaped; other Unix platforms rely
/// on the process-bound `RunningChild`/product cleanup and the guard is
/// intentionally inert rather than unsafe.
#[cfg(unix)]
struct TakeIoCleanupGuard {
    #[cfg(target_os = "linux")]
    pidfd: Option<std::os::fd::OwnedFd>,
    #[cfg(not(target_os = "linux"))]
    armed: bool,
}

#[cfg(unix)]
impl TakeIoCleanupGuard {
    fn new(pid: u32) -> Self {
        #[cfg(target_os = "linux")]
        {
            use std::os::fd::FromRawFd;
            // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
            // libc exposes the pidfd wrappers only on some libcs/targets;
            // the syscall numbers are part of the stable Linux ABI everywhere
            // this test builds.
            let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid as libc::pid_t, 0) };
            // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
            let pidfd = (fd >= 0).then(|| unsafe { std::os::fd::OwnedFd::from_raw_fd(fd as i32) });
            Self { pidfd }
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = pid;
            Self { armed: true }
        }
    }
    fn disarm(&mut self) {
        #[cfg(target_os = "linux")]
        {
            self.pidfd = None;
        }
        #[cfg(not(target_os = "linux"))]
        {
            self.armed = false;
        }
    }
}

#[cfg(unix)]
impl Drop for TakeIoCleanupGuard {
    fn drop(&mut self) {
        #[cfg(target_os = "linux")]
        if let Some(fd) = self.pidfd.take() {
            use std::os::fd::AsRawFd;
            // pidfd_send_signal is process-bound: signalling after another
            // owner reaps the child is harmless and cannot hit a reused pid.
            // The fixture does not waitpid here because reaping ownership
            // belongs to the product cleanup path.
            // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
            unsafe {
                libc::syscall(
                    libc::SYS_pidfd_send_signal,
                    fd.as_raw_fd(),
                    libc::SIGKILL,
                    std::ptr::null_mut::<libc::siginfo_t>(),
                    0,
                );
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            // No stable process handle exists here. Do not signal the raw
            // pid: if `into_report` reaped the fixture, that integer may
            // already have been recycled by an unrelated process.
            let _ = self.armed;
        }
    }
}

/// A `SYNCHRONIZE` handle opened on the child *before* cleanup — its
/// signaled state afterwards is the exit verdict, which reopen-by-pid
/// can never prove (a reused pid or a surviving stray handle would
/// still open).
#[cfg(windows)]
struct TakeIoExitProbe {
    handle: windows::Win32::Foundation::HANDLE,
    armed: bool,
}

#[cfg(windows)]
fn take_io_test_exit_probe(pid: u32) -> TakeIoExitProbe {
    use windows::Win32::System::Threading::{OpenProcess, PROCESS_SYNCHRONIZE, PROCESS_TERMINATE};
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    let handle = unsafe { OpenProcess(PROCESS_SYNCHRONIZE | PROCESS_TERMINATE, false, pid) }
        .expect("the just-spawned child must open with SYNCHRONIZE|TERMINATE access");
    TakeIoExitProbe {
        handle,
        armed: true,
    }
}

#[cfg(windows)]
impl TakeIoExitProbe {
    fn disarm(&mut self) {
        self.armed = false;
    }
    /// `true` once the original process object is signaled — i.e. the
    /// child actually terminated. Independent of pid reuse and of any
    /// handle the warden itself still holds.
    fn exited(&self) -> bool {
        use windows::Win32::Foundation::WAIT_OBJECT_0;
        use windows::Win32::System::Threading::WaitForSingleObject;
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe { WaitForSingleObject(self.handle, 0) == WAIT_OBJECT_0 }
    }
}

#[cfg(windows)]
impl Drop for TakeIoExitProbe {
    fn drop(&mut self) {
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        if self.armed {
            // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
            let _ = unsafe { windows::Win32::System::Threading::TerminateProcess(self.handle, 1) };
        }
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        let _ = unsafe { windows::Win32::Foundation::CloseHandle(self.handle) };
    }
}
