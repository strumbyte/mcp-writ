//! SIGKILL audit-tail-loss fixture (improvement plan §2.4 / §5.4): a
//! re-exec'd copy of this test binary opens a file audit sink, emits a
//! fixed event mix, and is then force-killed by the parent leg. The
//! surviving records are counted — the measured bound on what a killed
//! guard can lose — against both the default buffered mode and
//! `--audit-sync`'s every-record syncing, plus a drain-latency
//! measurement that prices the per-record fsync trade-off.

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use mcp_writ::audit_log::{
    Action, AuditEvent, AuditLogger, AuditSyncMode, EventType, Outcome, Severity,
};
use uuid::Uuid;

const CHILD_FLAG: &str = "MCP_WRIT_AUDIT_FIXTURE_CHILD";
const CHILD_LOG: &str = "MCP_WRIT_AUDIT_FIXTURE_LOG";
const CHILD_MODE: &str = "MCP_WRIT_AUDIT_FIXTURE_MODE";
const CHILD_BEHAVIOR: &str = "MCP_WRIT_AUDIT_FIXTURE_BEHAVIOR";

const HIGH_EVENTS: usize = 3;
const INFO_EVENTS: usize = 50;

/// Emits the durable prefix (High) then the volatile tail (Info) —
/// under the buffered policy only the prefix is expected to survive a
/// kill that lands inside the 1s periodic-flush window.
const fn emitted_total() -> usize {
    HIGH_EVENTS + INFO_EVENTS + 1 // + the commit-marker record
}

fn fixture_event(cid: Uuid, severity: Severity, seq: usize) -> AuditEvent {
    let mut event = AuditEvent::new(
        cid,
        EventType::ToolCallAllowed,
        severity,
        Outcome::Success,
        Action::Allowed,
    );
    event.details = Some(format!("seq={seq}"));
    event
}

/// Re-exec entry: plays the emitter child when `CHILD_FLAG` is set —
/// the parent legs spawn this same test binary filtered to this test.
/// Without the flag it returns immediately, so an ordinary
/// `cargo test` run passes trivially.
#[tokio::test]
async fn audit_emit_child() {
    if std::env::var(CHILD_FLAG).as_deref() != Ok("1") {
        return;
    }
    let path = PathBuf::from(std::env::var(CHILD_LOG).expect("child log path"));
    let mode = match std::env::var(CHILD_MODE).expect("child mode").as_str() {
        "sync" => AuditSyncMode::EveryEvent,
        _ => AuditSyncMode::Buffered,
    };
    let behavior = std::env::var(CHILD_BEHAVIOR).expect("child behavior");
    let logger = AuditLogger::to_file_with_options(&path, true, mode).expect("child logger");

    let cid = Uuid::now_v7();
    let t0 = Instant::now();
    for seq in 0..HIGH_EVENTS {
        logger.log(fixture_event(cid, Severity::High, seq));
    }
    for seq in HIGH_EVENTS..(HIGH_EVENTS + INFO_EVENTS) {
        logger.log(fixture_event(cid, Severity::Info, seq));
    }
    // The commit marker is acknowledged only after every record queued
    // ahead of it is flushed and fsync'd — waiting on it turns "the
    // writer reached the tail" from a timing guess into a fact. Only
    // the normal-exit legs use it: the buffered kill leg needs the tail
    // uncommitted (it is the loss being measured), and the sync kill
    // leg must not let a commit waiter's forced flush stand in for
    // EveryEvent's per-record sync — it waits on the file itself.
    let drain_ms = if behavior == "exit" {
        let mut marker = fixture_event(cid, Severity::Info, emitted_total() - 1);
        marker.details = Some("commit-marker".to_string());
        logger
            .log_committed(marker)
            .await
            .expect("committed marker");
        Some(t0.elapsed())
    } else {
        // The sync kill leg still emits the trailing record so its log
        // carries emitted_total() lines like the exit legs — queued
        // plainly, so only the mode's own per-record sync persists it.
        if mode == AuditSyncMode::EveryEvent {
            logger.log(fixture_event(cid, Severity::Info, emitted_total() - 1));
            wait_for_durable_records(&path, emitted_total()).await;
        }
        None
    };
    match drain_ms {
        Some(d) => println!("READY drain_ms={}", d.as_millis()),
        // The kill legs report the writer's age instead — the buffered
        // leg's parent must land its kill inside the 1s periodic-flush
        // window measured on the *child's* clock, and a slow spawn or
        // harness start shrinks that window by an amount only the child
        // knows.
        None => println!("READY age_ms={}", t0.elapsed().as_millis()),
    }
    std::io::stdout().flush().unwrap();
    if behavior == "exit" {
        logger.shutdown().await;
        return;
    }
    tokio::time::sleep(Duration::from_secs(60)).await;
}

/// The child's stdout stream is returned alongside the process handle
/// and must outlive it: dropping the read end early would make the
/// child's trailing harness output hit a closed pipe (EPIPE/SIGPIPE on
/// Unix) and turn a clean `exit` leg into a signal death.
fn spawn_fixture(
    mode: &str,
    behavior: &str,
    log: &Path,
) -> (Child, BufReader<std::process::ChildStdout>) {
    let exe = std::env::current_exe().expect("current test binary");
    let mut child = Command::new(exe)
        // `--nocapture` puts the child's READY print on the real stdout
        // pipe; the filter keeps the re-exec'd binary to this one test.
        .args(["audit_emit_child", "--exact", "--nocapture"])
        .env(CHILD_FLAG, "1")
        .env(CHILD_LOG, log)
        .env(CHILD_MODE, mode)
        .env(CHILD_BEHAVIOR, behavior)
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("re-exec fixture child");
    let stdout = BufReader::new(child.stdout.take().expect("child stdout"));
    (child, stdout)
}

/// Read the child's stdout until its READY line (the test harness's own
/// banner comes first); the returned line carries `drain_ms` when the
/// child measured a committed drain.
fn await_ready(stdout: &mut BufReader<std::process::ChildStdout>) -> String {
    let mut line = String::new();
    loop {
        line.clear();
        let n = stdout.read_line(&mut line).expect("read child readiness");
        assert!(n > 0, "child exited before READY");
        if let Some(ready) = line.strip_prefix("READY") {
            return ready.trim().to_string();
        }
    }
}

fn surviving_lines(log: &Path) -> Vec<String> {
    std::fs::read_to_string(log)
        .unwrap_or_default()
        .lines()
        .map(String::from)
        .collect()
}

/// Waits until the audit file holds `want` records — the sync kill
/// leg's proof that the writer reached the tail. Unlike a commit
/// marker this leans only on EveryEvent's own mechanics: under
/// per-record sync a record appears in the file solely because its
/// dequeue-time flush+fsync ran. A stalled file means the mode is not
/// syncing, which must fail the leg rather than hang it.
async fn wait_for_durable_records(log: &Path, want: usize) {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let seen = surviving_lines(log).len();
        if seen >= want {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "writer stalled at {seen}/{want} durable records — \
             per-record sync did not settle the tail"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

fn count_severity(lines: &[String], severity: &str) -> usize {
    let needle = format!("\"severity\":\"{severity}\"");
    lines.iter().filter(|l| l.contains(&needle)).count()
}

/// Buffered mode, force-killed inside the 1s flush window: the High
/// prefix survives on the immediate flush+fsync path, the buffered
/// Info tail is shed. The measured numbers are the tail-loss bound a
/// SIGKILL'd guard leaves behind.
///
/// `log()` only queues — a High record becomes durable when the writer
/// task dequeues it and runs its immediate flush+fsync, which is the
/// path under test here. The kill is therefore gated on the records
/// actually landing in the file, not on a fixed delay: on a slow disk
/// (observed on ARM CI) a few hundred milliseconds of writer progress
/// is not guaranteed, and killing mid-queue would lose High records
/// that were never the writer's to sync yet.
#[test]
fn sigkill_loses_buffered_tail_but_keeps_high_records() {
    let dir = tempfile::tempdir().expect("fixture dir");
    let log = dir.path().join("audit.jsonl");
    let (mut child, mut stdout) = spawn_fixture("buffered", "sleep", &log);
    let ready = await_ready(&mut stdout);
    // READY carries the writer's age at emit-loop end — the clock the
    // 1s periodic flush ticks on, and the only baseline that survives
    // a slow spawn or harness start.
    let writer_age_ms: u64 = ready
        .strip_prefix("age_ms=")
        .and_then(|s| s.parse().ok())
        .expect("buffered leg must report writer age");
    const FLUSH_PERIOD_MS: u64 = 1000;
    let ready_at = Instant::now();

    // Wait until the file actually holds the High records. On a fast
    // host the three immediate fsyncs take milliseconds; on a slow
    // disk each can cost far longer, so a deadline — not a delay — is
    // what separates "writer reached them" from "still queued".
    // Absence by the deadline is a real contract failure: the
    // immediate-sync path did not run.
    let deadline = Instant::now() + Duration::from_secs(15);
    let high_drain_ms = loop {
        if count_severity(&surviving_lines(&log), "high") == HIGH_EVENTS {
            break ready_at.elapsed().as_millis() as u64;
        }
        assert!(
            Instant::now() < deadline,
            "high-severity records never became durable — \
             the immediate flush+fsync path did not reach them"
        );
        std::thread::sleep(Duration::from_millis(5));
    };

    // Kill at once, before the next periodic flush can commit the
    // tail. The Info records sit FIFO-queued behind the Highs, so they
    // reach the BufWriter only after the last High's fsync; the tail
    // is provably volatile iff no 1s tick boundary on the writer's
    // clock falls between emit-loop end and the kill.
    child.kill().expect("kill child");
    child.wait().expect("reap child");
    let writer_age_at_kill_ms = writer_age_ms + ready_at.elapsed().as_millis() as u64;
    let tail_volatile = writer_age_ms / FLUSH_PERIOD_MS == writer_age_at_kill_ms / FLUSH_PERIOD_MS;

    let lines = surviving_lines(&log);
    let high = count_severity(&lines, "high");
    let info = count_severity(&lines, "info");
    eprintln!(
        "MEASURE buffered-sigkill emitted={} survived={} high={} info={} lost_info={} \
         writer_age_ms={writer_age_ms} high_drain_ms={} writer_age_at_kill_ms={writer_age_at_kill_ms}",
        HIGH_EVENTS + INFO_EVENTS,
        lines.len(),
        high,
        info,
        INFO_EVENTS.saturating_sub(info),
        high_drain_ms,
    );
    assert_eq!(
        high, HIGH_EVENTS,
        "high-severity records must survive a force-kill"
    );
    if tail_volatile {
        assert!(
            info < INFO_EVENTS,
            "the buffered tail must be observably lost, got {info}/{INFO_EVENTS}"
        );
    } else {
        // A periodic-flush tick could have landed between the tail's
        // buffering and the kill — the measurement is indeterminate on
        // a host this slow; say so instead of flaking.
        eprintln!(
            "SKIP tail-loss bound: a 1s flush tick could have committed the tail \
             before the kill (writer age {writer_age_ms}ms -> {writer_age_at_kill_ms}ms)"
        );
    }
}

/// `--audit-sync` mode: every record is fsync'd as written. The leg
/// deliberately carries no commit marker — the marker's forced flush
/// would prove the tail durable even if EveryEvent's per-record sync
/// never ran — so the child's READY is gated on the file itself
/// holding the complete stream, and the kill must find it durable.
#[test]
fn audit_sync_loses_nothing_on_sigkill() {
    let dir = tempfile::tempdir().expect("fixture dir");
    let log = dir.path().join("audit.jsonl");
    let (mut child, mut stdout) = spawn_fixture("sync", "sleep", &log);
    await_ready(&mut stdout);
    std::thread::sleep(Duration::from_millis(50));
    child.kill().expect("kill child");
    child.wait().expect("reap child");

    let lines = surviving_lines(&log);
    eprintln!(
        "MEASURE sync-sigkill emitted={} survived={}",
        emitted_total(),
        lines.len(),
    );
    assert_eq!(
        lines.len(),
        emitted_total(),
        "every emitted record must be durable under audit-sync"
    );
}

/// Prices the durability modes: the same event mix is drained through a
/// committed marker in buffered vs every-event mode — the wall time the
/// commit waits on is the per-mode cost of reaching durable storage.
#[test]
fn drain_latency_of_each_sync_mode_is_measured() {
    for mode in ["buffered", "sync"] {
        let dir = tempfile::tempdir().expect("fixture dir");
        let log = dir.path().join("audit.jsonl");
        let (mut child, mut stdout) = spawn_fixture(mode, "exit", &log);
        let ready = await_ready(&mut stdout);
        let status = child.wait().expect("reap child");
        assert!(status.success(), "{mode} fixture child failed");

        let drain_ms = ready
            .strip_prefix("drain_ms=")
            .and_then(|s| s.parse::<u128>().ok())
            .expect("exit leg must report drain_ms");
        let lines = surviving_lines(&log);
        eprintln!(
            "MEASURE drain mode={mode} events={} drain_ms={drain_ms} lines={}",
            emitted_total(),
            lines.len(),
        );
        assert_eq!(lines.len(), emitted_total(), "{mode} clean drain");
    }
}
