use super::*;

fn spawn_sh(script: &str) -> RunningChild {
    let mut cmd = tokio::process::Command::new("sh");
    cmd.arg("-c").arg(script);
    apply_unix_process_group_tokio(&mut cmd);
    let child = cmd.spawn().expect("spawn sh");
    let pgid = child.id().unwrap_or(0);
    RunningChild {
        stdin: None,
        stdout: None,
        unotify_listener: None,
        inner: RunningChildInner::Tokio(Box::new(child)),
        pgid,
        reaped: false,
        #[cfg(target_os = "linux")]
        lifetime_cgroup: LifetimeCgroup::try_adopt("test", pgid),
        #[cfg(target_os = "linux")]
        namespaced: None,
        #[cfg(target_os = "linux")]
        namespaced_report: None,
        #[cfg(target_os = "macos")]
        _tmpdir: None,
    }
}

/// `wait_for_natural_exit` → the leader's own status; a supervision
/// loss fails the test (these children are never namespaced).
async fn natural_exit(child: &mut RunningChild) -> std::process::ExitStatus {
    match child.wait_for_natural_exit().await {
        NaturalExit::Exited(status) => status.expect("natural exit status"),
        #[cfg(target_os = "linux")]
        NaturalExit::SupervisionLost(detail) => {
            panic!("unexpected supervision loss: {detail}")
        }
    }
}

/// A reaped leader frees its pid — the recorded pgid could belong
/// to a recycled group, so `signal` and the descendant sweep must
/// no longer target it.
#[tokio::test]
async fn group_signaling_stops_after_natural_exit() {
    let mut child = spawn_sh("exit 0");
    natural_exit(&mut child).await;
    assert!(child.process_group_id().is_none());
    assert_eq!(
        child.signal(libc::SIGTERM).unwrap_err().kind(),
        std::io::ErrorKind::NotFound
    );
}

/// `try_wait` reaps too — the same guard must engage.
#[tokio::test]
async fn group_signaling_stops_after_try_wait() {
    let mut child = spawn_sh("exit 0");
    let status = loop {
        if let Some(s) = child.try_wait().expect("try_wait") {
            break s;
        }
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    };
    assert!(status.success());
    assert!(child.process_group_id().is_none());
    assert_eq!(
        child.signal(libc::SIGTERM).unwrap_err().kind(),
        std::io::ErrorKind::NotFound
    );
}

/// While the leader is still alive the group must stay signalable —
/// the reaped guard must not regress descendant cleanup.
#[tokio::test]
async fn group_is_signaled_while_leader_lives() {
    let mut child = spawn_sh("sleep 30");
    assert!(child.process_group_id().is_some());
    child.signal(libc::SIGKILL).expect("signal group");
    let status = natural_exit(&mut child).await;
    assert!(status.code().is_none(), "SIGKILL leaves no exit code");
}

/// A `waitid` probe failure must surface from `try_wait`, not read
/// as "still running" forever. `SA_NOCLDWAIT` makes children exit
/// without ever becoming waitable, so the probe fails `ECHILD`
/// once the leader is gone — the exact unanswerable-probe shape
/// the guard now propagates. The disposition is process-global, so
/// the scenario runs in a re-executed copy of this test binary
/// (`MCP_WRIT_TEST_NOCLDWAIT_INNER`) and never mutates the host
/// test process. Exit codes: 0 = probe error surfaced, 2 = the
/// host did not honor SA_NOCLDWAIT (outer skips), anything else =
/// failure.
const NOCLDWAIT_INNER_ENV: &str = "MCP_WRIT_TEST_NOCLDWAIT_INNER";
const NOCLDWAIT_RC_UNSUPPORTED: i32 = 2;

#[tokio::test]
async fn try_wait_surfaces_unanswerable_waitid_probe() {
    if std::env::var_os(NOCLDWAIT_INNER_ENV).is_some() {
        noclwait_inner().await;
    }
    let exe = std::env::current_exe().expect("current test binary"); // nosemgrep: rust.lang.security.current-exe.current-exe
    let out = std::process::Command::new(exe)
        .args([
            "--exact",
            "warden::child::tests::try_wait_surfaces_unanswerable_waitid_probe",
            "--test-threads=1",
        ])
        .env(NOCLDWAIT_INNER_ENV, "1")
        .output()
        .expect("spawn inner probe");
    match out.status.code() {
        Some(0) => {}
        Some(c) if c == NOCLDWAIT_RC_UNSUPPORTED => {
            eprintln!("skipping: host does not honor SA_NOCLDWAIT")
        }
        other => panic!(
            "inner probe exited {other:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        ),
    }
}

/// Inner leg of [`try_wait_surfaces_unanswerable_waitid_probe`] —
/// runs inside the re-executed binary only. Never returns: each
/// outcome is reported by process exit.
async fn noclwait_inner() -> ! {
    // SIGCHLD disposition with SA_NOCLDWAIT: children exit without
    // becoming waitable zombies.
    // SAFETY: `sigaction` is a POD struct — all-zero then the three
    // public fields assigned below names a valid disposition; the
    // handler is SIG_DFL, which is always sound.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    let mut sa: libc::sigaction = unsafe { std::mem::zeroed() };
    sa.sa_flags = libc::SA_NOCLDWAIT;
    sa.sa_sigaction = libc::SIG_DFL;
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    unsafe {
        libc::sigemptyset(&mut sa.sa_mask);
        if libc::sigaction(libc::SIGCHLD, &sa, std::ptr::null_mut()) != 0 {
            std::process::exit(NOCLDWAIT_RC_UNSUPPORTED);
        }
    }
    let mut child = spawn_sh("exit 0");
    for _ in 0..500 {
        match child.try_wait() {
            // The unanswerable probe surfaced — the fixed behavior.
            Err(e) if e.raw_os_error() == Some(libc::ECHILD) => std::process::exit(0),
            // A different probe failure is still a surfaced error —
            // fail rather than accept a wrong errno silently.
            Err(_) => std::process::exit(4),
            // The exited child stayed waitable — SA_NOCLDWAIT was
            // not honored on this host; outer skips.
            Ok(Some(_)) => std::process::exit(NOCLDWAIT_RC_UNSUPPORTED),
            Ok(None) => tokio::time::sleep(std::time::Duration::from_millis(10)).await,
        }
    }
    // Timed out with only "still running" answers — no verdict.
    std::process::exit(3)
}
