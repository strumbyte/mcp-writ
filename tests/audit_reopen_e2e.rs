//! PR-27 (improvement plan F-11) fixtures — Unix only: file rotation
//! and its signal are POSIX semantics, and the Windows append handle
//! grants no delete sharing for a rotator to move anyway.
//!
//! - `rotate` leg: a re-exec'd child opens the file audit sink,
//!   registers the production SIGUSR1 listener (the same
//!   `spawn_audit_reopen_listener` call `run` and `mcp-secure-runner`
//!   make ahead of `wait_for_shutdown`), and proves the stream
//!   continues into the *new* file after the parent renames the old
//!   one away and signals.
//! - `enospc` leg: `RLIMIT_FSIZE` stands in for a full filesystem —
//!   writes past the limit fail `EFBIG` through the identical writer
//!   fault path an `ENOSPC` takes — proving the fail-closed latch and
//!   that freeing room afterwards does *not* revive the sink.

#![cfg(unix)]

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

use mcp_writ::audit_log::{
    Action, AuditEvent, AuditLogger, AuditSyncMode, EventType, Outcome, Severity,
};
use mcp_writ::runtime::lifecycle::SessionAuditContext;
use uuid::Uuid;

const CHILD_FLAG: &str = "MCP_WRIT_REOPEN_FIXTURE_CHILD";
const CHILD_LOG: &str = "MCP_WRIT_REOPEN_FIXTURE_LOG";
const CHILD_ROLE: &str = "MCP_WRIT_REOPEN_FIXTURE_ROLE";

fn fixture_event(cid: Uuid, tag: &str) -> AuditEvent {
    let mut event = AuditEvent::new(
        cid,
        EventType::ToolCallAllowed,
        Severity::Info,
        Outcome::Success,
        Action::Allowed,
    );
    event.details = Some(format!("tag={tag}"));
    event
}

/// Re-exec entry — the parent legs spawn this same test binary with
/// `CHILD_FLAG` set. Without the flag it returns immediately so an
/// ordinary `cargo test` run passes trivially.
#[tokio::test]
async fn audit_reopen_child() {
    if std::env::var(CHILD_FLAG).as_deref() != Ok("1") {
        return;
    }
    let path = PathBuf::from(std::env::var(CHILD_LOG).expect("child log path"));
    match std::env::var(CHILD_ROLE).expect("child role").as_str() {
        "rotate" => run_rotate_leg(&path).await,
        "enospc" => run_enospc_leg(&path).await,
        other => panic!("unknown fixture role {other}"),
    }
}

/// The rotate leg: one committed record anchors the old file, then the
/// production listener — `spawn_audit_reopen_listener`, the same call
/// `run` and `mcp-secure-runner` make ahead of `wait_for_shutdown` —
/// turns the parent's SIGUSR1 into a `reopen()` with the
/// `audit.reopened` marker emitted in-band, and a second committed
/// record proves the stream resumed on the new file.
async fn run_rotate_leg(path: &Path) {
    let logger = AuditLogger::to_file_with_options(path, true, AuditSyncMode::EveryEvent)
        .expect("child logger");
    let ctx = SessionAuditContext::pre_policy(Uuid::now_v7(), "test-reopen");
    let cid = ctx.launch_id;

    logger
        .log_committed(fixture_event(cid, "pre-rotation"))
        .await
        .expect("pre-rotation record");
    mcp_writ::runtime::wait::spawn_audit_reopen_listener(&logger, &ctx);
    println!("READY");
    std::io::stdout().flush().unwrap();

    // Wait out the listener's reopen: the marker is written in-band as
    // the new file's first record before `reopen()` acknowledges, so
    // seeing it here means the handle swap already completed.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while !read_lines(path)
        .iter()
        .any(|line| line.contains("\"event_type\":\"audit.reopened\""))
    {
        assert!(
            std::time::Instant::now() < deadline,
            "SIGUSR1 listener did not complete the reopen"
        );
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    }

    logger
        .log_committed(fixture_event(cid, "post-rotation"))
        .await
        .expect("post-rotation record");
    logger.shutdown().await.expect("clean shutdown");
    println!("ROTATED");
    std::io::stdout().flush().unwrap();
}

/// The enospc leg: a small `RLIMIT_FSIZE` makes the sink's writes fail
/// the way a full filesystem would. SIGXFSZ must be ignored — its
/// default disposition kills the process on the first over-limit
/// write. After the latch, the limit is lifted to prove the sink does
/// not recover: the fail-closed contract is terminal, not transient.
async fn run_enospc_leg(path: &Path) {
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    unsafe {
        assert_ne!(
            libc::signal(libc::SIGXFSZ, libc::SIG_IGN),
            libc::SIG_ERR,
            "SIGXFSZ ignore"
        );
        let lim = libc::rlimit {
            rlim_cur: 48 * 1024,
            rlim_max: libc::RLIM_INFINITY,
        };
        assert_eq!(
            libc::setrlimit(libc::RLIMIT_FSIZE, &lim),
            0,
            "setrlimit RLIMIT_FSIZE"
        );
    }

    let logger = AuditLogger::to_file_with_options(path, true, AuditSyncMode::EveryEvent)
        .expect("child logger");
    let cid = Uuid::now_v7();

    // ~600-byte records against a 48 KiB file ceiling — the refusal
    // arrives within a few hundred committed records.
    let mut refused = false;
    for i in 0..400 {
        if logger
            .log_committed(fixture_event(cid, &format!("seq-{i}")))
            .await
            .is_err()
        {
            refused = true;
            break;
        }
    }
    assert!(refused, "the size limit must refuse a write");
    assert!(
        logger.is_failed(),
        "a failed write must latch the fail-closed fault"
    );

    // Lift the limit — the sink stays latched: room made after the
    // fault does not resume the session's audit stream.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    unsafe {
        let lim = libc::rlimit {
            rlim_cur: libc::RLIM_INFINITY,
            rlim_max: libc::RLIM_INFINITY,
        };
        assert_eq!(libc::setrlimit(libc::RLIMIT_FSIZE, &lim), 0);
    }
    let err = logger
        .log_committed(fixture_event(cid, "after-room"))
        .await
        .unwrap_err();
    assert!(
        logger.is_failed(),
        "a made-room write must still report the latched fault"
    );
    println!("ENOSPC-LATCHED {err}");
    std::io::stdout().flush().unwrap();
}

fn spawn_fixture(role: &str, log: &Path) -> (Child, BufReader<std::process::ChildStdout>) {
    let exe = std::env::current_exe().expect("current test binary"); // nosemgrep: rust.lang.security.current-exe.current-exe
    let mut child = Command::new(exe)
        .args(["audit_reopen_child", "--exact", "--nocapture"])
        .env(CHILD_FLAG, "1")
        .env(CHILD_LOG, log)
        .env(CHILD_ROLE, role)
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("re-exec fixture child");
    let stdout = BufReader::new(child.stdout.take().expect("child stdout"));
    (child, stdout)
}

fn await_ready(stdout: &mut BufReader<std::process::ChildStdout>) {
    let mut line = String::new();
    loop {
        line.clear();
        let n = stdout.read_line(&mut line).expect("read child readiness");
        assert!(n > 0, "child exited before READY");
        if line.starts_with("READY") {
            return;
        }
    }
}

fn read_lines(path: &Path) -> Vec<String> {
    std::fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .map(String::from)
        .collect()
}

/// The logrotate contract, end to end through a real SIGUSR1: after
/// the old file is renamed away, the marker and every later record
/// continue into a freshly created file at the audit path — nothing
/// lands back in the rotated file.
#[test]
fn sigusr1_reopen_continues_in_new_file() {
    let dir = tempfile::tempdir().expect("fixture dir");
    // Real spelling: $TMPDIR may traverse a platform link (macOS
    // `/var` → `/private/var`) that the audit sink's strict ancestor
    // walk refuses.
    let log = dir.path().canonicalize().unwrap().join("audit.jsonl");
    let rotated = dir.path().join("audit.jsonl.1");

    let (mut child, mut stdout) = spawn_fixture("rotate", &log);
    await_ready(&mut stdout);

    // What a rotator does: move the live file aside, then signal. The
    // pre-rotation record is already committed — durable in the file
    // being moved.
    std::fs::rename(&log, &rotated).expect("rotate the live log aside");
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    let rc = unsafe { libc::kill(child.id() as i32, libc::SIGUSR1) };
    assert_eq!(rc, 0, "SIGUSR1 delivery");

    let status = child.wait().expect("reap child");
    let mut rest = String::new();
    let _ = stdout.read_line(&mut rest);
    assert!(
        status.success(),
        "rotate child failed ({status:?}); trailing output: {rest}"
    );

    let old = read_lines(&rotated);
    assert_eq!(
        old.len(),
        1,
        "rotated file holds only the pre records: {old:?}"
    );
    assert!(old[0].contains("pre-rotation"));

    let new = read_lines(&log);
    assert_eq!(
        new.len(),
        2,
        "new file holds the marker plus the post record: {new:?}"
    );
    assert!(
        new[0].contains("\"event_type\":\"audit.reopened\""),
        "first record in the new file must be the marker: {}",
        new[0]
    );
    assert!(new[0].contains("signal=sigusr1"));
    assert!(new[1].contains("post-rotation"));

    let _ = std::fs::remove_dir_all(dir.path());
}

/// A full filesystem (simulated via `RLIMIT_FSIZE`) interrupts the
/// fail-closed stream — and freeing room afterwards does not revive
/// it. The child's own asserts encode both halves; the parent only
/// checks the verdict line and exit status.
#[test]
fn full_disk_latches_and_does_not_recover() {
    let dir = tempfile::tempdir().expect("fixture dir");
    let log = dir.path().canonicalize().unwrap().join("audit.jsonl");

    let (mut child, stdout) = spawn_fixture("enospc", &log);
    let status = child.wait().expect("reap child");
    let mut out = String::new();
    for line in stdout.lines() {
        let line = line.expect("child stdout");
        out.push_str(&line);
        out.push('\n');
    }
    assert!(
        status.success(),
        "enospc child failed ({status:?}); output: {out}"
    );
    assert!(
        out.contains("ENOSPC-LATCHED"),
        "child must report the latched verdict: {out}"
    );

    // The file is truncated at the size limit — the last line may be
    // a partial record; readers must tolerate a non-JSON tail.
    let body = std::fs::read_to_string(&log).unwrap();
    assert!(!body.is_empty(), "partial stream must exist");
    let _ = std::fs::remove_dir_all(dir.path());
}
