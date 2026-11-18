//! RF03 ordering/fairness regression tests: a manual clock and a
//! scripted sink reproduce sustained input, queue saturation, multiple
//! rotations, and a shutdown landing mid-rotation — deterministically,
//! without wall-clock sleeps or `tokio::time` control. Both
//! abstractions are the injected traits the production writer runs on
//! (`AuditClock`, `AuditSink`), so the same fixtures keep working if
//! the driver later moves to a blocking thread.

use std::cell::RefCell;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};

use super::super::writer::{
    AuditClock, AuditSink, CLOCK_CHECK_RECORDS, FLUSH_PERIOD, FSYNC_PERIOD, WriterCore,
    file_writer_task,
};
use super::super::*;
use super::make_test_event;
use uuid::Uuid;

// ─── ManualClock ────────────────────────────────────────────────────────

/// A test clock the test itself advances — `now()` only moves on
/// `advance`, and `sleep_until` futures complete the moment an advance
/// reaches their deadline. No executor and no wall time is involved in
/// the writer's deadline decisions.
#[derive(Clone)]
struct ManualClock {
    inner: Arc<Mutex<ManualClockState>>,
}

struct ManualClockState {
    now: Instant,
    sleepers: Vec<(Instant, Waker)>,
}

impl ManualClock {
    fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(ManualClockState {
                now: Instant::now(),
                sleepers: Vec::new(),
            })),
        }
    }

    /// Move the clock forward — sleepers whose deadline is now past
    /// are woken.
    fn advance(&self, delta: Duration) {
        let due = {
            let mut state = self.inner.lock().unwrap();
            state.now += delta;
            let now = state.now;
            let (due, pending): (Vec<_>, Vec<_>) = state
                .sleepers
                .drain(..)
                .partition(|(deadline, _)| *deadline <= now);
            state.sleepers = pending;
            due
        };
        for (_, waker) in due {
            waker.wake();
        }
    }
}

struct ManualSleep {
    inner: Arc<Mutex<ManualClockState>>,
    deadline: Instant,
}

impl Future for ManualSleep {
    type Output = ();
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        let mut state = self.inner.lock().unwrap();
        if state.now >= self.deadline {
            return Poll::Ready(());
        }
        if !state.sleepers.iter().any(|(_, w)| w.will_wake(cx.waker())) {
            state.sleepers.push((self.deadline, cx.waker().clone()));
        }
        Poll::Pending
    }
}

impl AuditClock for ManualClock {
    fn now(&self) -> Instant {
        self.inner.lock().unwrap().now
    }

    fn sleep_until(&self, deadline: Instant) -> Pin<Box<dyn Future<Output = ()> + Send>> {
        Box::pin(ManualSleep {
            inner: self.inner.clone(),
            deadline,
        })
    }
}

// ─── FakeSink ───────────────────────────────────────────────────────────

/// One sink-side step the core asks for, tagged with the generation it
/// ran on. `Reopen` is the barrier: ops before it belong to the
/// generation being retired, ops after it to the new one. `Write`
/// carries the record's serialized line so tests can tell the
/// `audit.reopened` marker from a normal record.
#[derive(Clone, Debug, PartialEq, Eq)]
enum SinkOp {
    Write(String),
    Flush,
    SyncFile,
    SyncDir,
    EntryVisible,
    Reopen,
}

/// What a scripted `reopen` does at the swap point — mirroring
/// `FileSink::reopen`'s partial-failure semantics.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
enum ReopenPlan {
    /// Swap succeeds and the new generation's entry sync succeeds.
    #[default]
    Ok,
    /// The re-open itself fails — no swap; the old generation lives
    /// on.
    ErrBeforeSwap,
    /// The swap happened but the new entry's sync failed — `Err`
    /// reported while the new generation is live.
    ErrAfterSwap,
}

/// The scripted sink: every durable step lands in `ops` tagged with
/// the generation it ran on — `RefCell` so `entry_visible`'s `&self`
/// can record too. Faults are per-kind flags plus a one-shot write
/// index; the optional single-use gates park the first `write_record`,
/// `sync_file`, `reopen`, or `entry_visible` mid-call so a test can
/// close the queue during a write, an fsync, a rotation, or the
/// visible-entry proof. `mirror` streams ops to a task-level test
/// that cannot reach `ops` while the task owns the sink.
struct FakeSink {
    ops: RefCell<Vec<(usize, SinkOp)>>,
    mirror: Option<std::sync::mpsc::Sender<(usize, SinkOp)>>,
    generation: usize,
    needs_dir: bool,
    visible: bool,
    fail_write: bool,
    fail_write_at: Option<usize>,
    writes_seen: usize,
    fail_flush: bool,
    fail_flush_at: Option<usize>,
    flushes_seen: usize,
    fail_sync: bool,
    fail_dir_sync: bool,
    reopen_plan: ReopenPlan,
    reopen_gate: Option<(std::sync::mpsc::Sender<()>, std::sync::mpsc::Receiver<()>)>,
    write_gate: Option<(std::sync::mpsc::Sender<()>, std::sync::mpsc::Receiver<()>)>,
    sync_gate: Option<(std::sync::mpsc::Sender<()>, std::sync::mpsc::Receiver<()>)>,
    /// `entry_visible` is a `&self` call — its single-use gate lives
    /// behind interior mutability like `ops`.
    visible_gate: RefCell<Option<(std::sync::mpsc::Sender<()>, std::sync::mpsc::Receiver<()>)>>,
}

impl Default for FakeSink {
    /// The healthy default: a pre-existing file whose entry is durable
    /// (`needs_dir == false`) and still names the opened object
    /// (`visible == true`). Tests needing a freshly created file's
    /// owed entry fsync or a swapped-out entry set the flags.
    fn default() -> Self {
        Self {
            ops: RefCell::new(Vec::new()),
            mirror: None,
            generation: 0,
            needs_dir: false,
            visible: true,
            fail_write: false,
            fail_write_at: None,
            writes_seen: 0,
            fail_flush: false,
            fail_flush_at: None,
            flushes_seen: 0,
            fail_sync: false,
            fail_dir_sync: false,
            reopen_plan: ReopenPlan::Ok,
            reopen_gate: None,
            write_gate: None,
            sync_gate: None,
            visible_gate: RefCell::new(None),
        }
    }
}

impl FakeSink {
    fn mirrored(mirror: std::sync::mpsc::Sender<(usize, SinkOp)>) -> Self {
        Self {
            mirror: Some(mirror),
            ..Self::default()
        }
    }

    fn record(&self, op: SinkOp) {
        self.ops.borrow_mut().push((self.generation, op.clone()));
        if let Some(tx) = &self.mirror {
            let _ = tx.send((self.generation, op));
        }
    }

    fn err(msg: &str) -> std::io::Error {
        std::io::Error::other(msg.to_owned())
    }
}

impl AuditSink for FakeSink {
    fn write_record(&mut self, line: &[u8]) -> std::io::Result<()> {
        if let Some((entered, proceed)) = self.write_gate.take() {
            let _ = entered.send(());
            let _ = proceed.recv();
        }
        self.writes_seen += 1;
        if self.fail_write || self.fail_write_at == Some(self.writes_seen) {
            return Err(Self::err("write failed"));
        }
        self.record(SinkOp::Write(String::from_utf8_lossy(line).into_owned()));
        Ok(())
    }

    fn flush_buffer(&mut self) -> std::io::Result<()> {
        self.flushes_seen += 1;
        self.record(SinkOp::Flush);
        if self.fail_flush || self.fail_flush_at == Some(self.flushes_seen) {
            return Err(Self::err("flush failed"));
        }
        Ok(())
    }

    fn sync_file(&mut self) -> std::io::Result<()> {
        if let Some((entered, proceed)) = self.sync_gate.take() {
            let _ = entered.send(());
            let _ = proceed.recv();
        }
        self.record(SinkOp::SyncFile);
        if self.fail_sync {
            return Err(Self::err("sync failed"));
        }
        Ok(())
    }

    fn needs_dir_sync(&self) -> bool {
        self.needs_dir
    }

    fn sync_dir(&mut self) -> std::io::Result<()> {
        self.record(SinkOp::SyncDir);
        if self.fail_dir_sync {
            return Err(Self::err("dir sync failed"));
        }
        self.needs_dir = false;
        Ok(())
    }

    fn entry_visible(&self, _path: &Path) -> bool {
        if let Some((entered, proceed)) = self.visible_gate.borrow_mut().take() {
            let _ = entered.send(());
            let _ = proceed.recv();
        }
        self.record(SinkOp::EntryVisible);
        self.visible
    }

    /// Mirrors `FileSink::reopen`'s internal sequence — old-generation
    /// flush + fsync (+ owed dir fsync), the swap point, then the new
    /// generation's entry sync — so generation accounting in the op
    /// log stays faithful. The pre-swap steps run through the same
    /// fallible methods the writer calls, so a configured flush/fsync/
    /// dir failure stops the rotation before the swap — exactly like
    /// the real sink. The single-use gate parks the call before the
    /// sequence runs: a mid-rotation test window.
    fn reopen(&mut self, _path: &Path) -> std::io::Result<()> {
        if let Some((entered, proceed)) = self.reopen_gate.take() {
            let _ = entered.send(());
            let _ = proceed.recv();
        }
        self.flush_buffer()?;
        self.sync_file()?;
        if self.needs_dir {
            self.sync_dir()?;
        }
        self.record(SinkOp::Reopen);
        match self.reopen_plan {
            ReopenPlan::ErrBeforeSwap => Err(Self::err("reopen refused")),
            ReopenPlan::ErrAfterSwap => {
                self.generation += 1;
                self.record(SinkOp::SyncDir);
                self.needs_dir = true;
                Err(Self::err("post-swap dir sync failed"))
            }
            ReopenPlan::Ok => {
                self.generation += 1;
                self.record(SinkOp::SyncDir);
                self.needs_dir = false;
                Ok(())
            }
        }
    }
}

// ─── Fixtures ───────────────────────────────────────────────────────────

const TEST_SESSION: &str = "test-session";
const TEST_PATH: &str = "audit.jsonl";

/// The in-band rotation marker a reopen carries — same shape as
/// `lifecycle::audit_reopened_event`, kept local so writer-level tests
/// stay in this module.
fn marker_ok() -> ReopenMarker {
    marker_with_details("signal=sigusr1")
}

/// A marker tagged with its request's sequence id — FIFO tests give
/// each reopen request a distinct marker so the emitted marker order
/// proves the queue's service order, not just the rotation count.
fn marker_seq(id: usize) -> ReopenMarker {
    marker_with_details(&format!("signal=sigusr1 seq={id}"))
}

fn marker_with_details(details: &str) -> ReopenMarker {
    let details = details.to_owned();
    Box::new(move |err| {
        let mut evt = AuditEvent::new(
            Uuid::now_v7(),
            EventType::AuditReopened,
            Severity::Info,
            if err.is_some() {
                Outcome::Failure
            } else {
                Outcome::Success
            },
            Action::Observed,
        );
        evt.details = Some(match err {
            Some(e) => format!("{details} error={e}"),
            None => details.clone(),
        });
        evt
    })
}

/// An `AuditItem` for direct core calls — its permits come from
/// throwaway semaphores, like the queue-side accounting they stand
/// in for.
fn test_item(evt: AuditEvent, ack: Option<tokio::sync::oneshot::Sender<()>>) -> AuditItem {
    AuditItem {
        event: evt,
        ack,
        bytes_permit: std::sync::Arc::new(tokio::sync::Semaphore::new(1 << 20))
            .try_acquire_many_owned(256)
            .unwrap(),
        slot_permit: std::sync::Arc::new(tokio::sync::Semaphore::new(64))
            .try_acquire_owned()
            .unwrap(),
    }
}

/// Poll `cond` once per yield until it holds — scheduler-timing waits
/// (a spawned producer reaching its permit acquire) get a bounded,
/// honest timeout instead of a bare sleep.
async fn wait_until(cond: impl Fn() -> bool, what: &str) {
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        while !cond() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("timed out waiting for {what}"));
}

/// Wait for a FakeSink gate's entered signal on the blocking pool —
/// bounded, so a writer that never reaches the gate fails the test
/// instead of hanging it.
async fn gate_entered(rx: std::sync::mpsc::Receiver<()>) {
    tokio::task::spawn_blocking(move || {
        rx.recv_timeout(Duration::from_secs(10))
            .expect("the writer must enter the FakeSink gate")
    })
    .await
    .unwrap();
}

/// Free space in the writer's intake queue — one fewer free slot is
/// how a test observes a control item's *admission* without waiting
/// on the request's reply.
fn queue_free(logger: &AuditLogger) -> usize {
    logger
        .inner
        .tx
        .lock()
        .unwrap()
        .as_ref()
        .expect("the writer sender is live")
        .capacity()
}

fn test_core(sink: FakeSink, clock: ManualClock) -> WriterCore<FakeSink, ManualClock> {
    WriterCore::new(
        sink,
        clock,
        FailureFlag::new(),
        AuditSyncMode::Buffered,
        TEST_SESSION.to_string(),
        PathBuf::from(TEST_PATH),
    )
}

/// A file-sink logger whose writer runs `sink`/`clock` — the full
/// queue-side API (`log`/`log_ordered`/`log_committed`/`reopen`/
/// `shutdown`) against scripted parts.
fn fake_logger(
    sink: FakeSink,
    clock: ManualClock,
    event_capacity: usize,
    fail_closed: bool,
) -> AuditLogger {
    let (tx, rx) = mpsc::channel(event_capacity + CONTROL_QUEUE_CAPACITY);
    let writer_failed = FailureFlag::new();
    let core = WriterCore::new(
        sink,
        clock,
        writer_failed.clone(),
        AuditSyncMode::Buffered,
        TEST_SESSION.to_string(),
        PathBuf::from(TEST_PATH),
    );
    let writer_handle = tokio::spawn(file_writer_task(rx, core));
    super::assemble_logger(
        tx,
        writer_handle,
        fail_closed,
        event_capacity,
        QUEUE_BYTE_BUDGET,
        true,
        writer_failed,
        TEST_SESSION.to_string(),
    )
}

// ─── Periodic-sync fairness ─────────────────────────────────────────────

/// The core of the starvation fix: a passed deadline is serviced at
/// the next bounded processing boundary — `CLOCK_CHECK_RECORDS`
/// records — not when the queue happens to drain. The op stream shows
/// the sync interleaved mid-stream with records still behind it.
#[test]
fn test_due_deadline_services_at_record_boundary() {
    let clock = ManualClock::new();
    let mut core = test_core(FakeSink::default(), clock.clone());
    // A partial processing chunk buffered but not yet due — the
    // boundary lands mid-stream once the deadline passes.
    for _ in 0..CLOCK_CHECK_RECORDS - 4 {
        core.handle_record(test_item(make_test_event(), None));
    }
    assert!(
        core.sink()
            .ops
            .borrow()
            .iter()
            .all(|(_, op)| matches!(op, SinkOp::Write(_))),
        "no sync may run before a deadline passes"
    );
    // The fsync deadline passes while records keep arriving.
    clock.advance(FSYNC_PERIOD + Duration::from_secs(1));
    for _ in 0..8 {
        core.handle_record(test_item(make_test_event(), None));
    }
    let ops = core.sink().ops.borrow();
    let boundary = CLOCK_CHECK_RECORDS as usize;
    // The boundary check after record CLOCK_CHECK_RECORDS services the
    // due flush (buffered tail non-empty) and the due fsync — in that
    // order — while later records continue behind them.
    assert_eq!(ops[boundary].1, SinkOp::Flush);
    assert_eq!(ops[boundary + 1].1, SinkOp::SyncFile);
    assert!(matches!(ops[boundary + 2].1, SinkOp::Write(_)));
    assert_eq!(
        ops.iter()
            .filter(|(_, op)| matches!(op, SinkOp::SyncFile))
            .count(),
        1,
        "exactly one periodic fsync for the passed 5s deadline: {ops:?}"
    );
}

/// An idle queue still wakes on the deadline itself: the driver's
/// `sleep_until` arm completes when the manual clock advances past it
/// — no records needed. (Multi-threaded: the test thread blocks on
/// `recv_timeout` while the writer task lives on another worker.)
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_idle_writer_services_deadline() {
    let (op_tx, op_rx) = std::sync::mpsc::channel();
    let clock = ManualClock::new();
    let logger = fake_logger(FakeSink::mirrored(op_tx), clock.clone(), 8, true);
    // Past both deadlines: the flush finds an empty tail (skipped,
    // like the old arm), the fsync runs.
    clock.advance(FSYNC_PERIOD + Duration::from_secs(1));
    let (_, op) = op_rx
        .recv_timeout(Duration::from_secs(10))
        .expect("idle writer must service the due fsync");
    assert_eq!(op, SinkOp::SyncFile);
    // The next period fires too — deadlines keep their schedule.
    clock.advance(FSYNC_PERIOD);
    let (_, op) = op_rx
        .recv_timeout(Duration::from_secs(10))
        .expect("the following period must sync too");
    assert_eq!(op, SinkOp::SyncFile);
    let _ = logger.shutdown().await;
}

/// Missed periods are settled per deadline — the Burst semantics the
/// interval arm had: a stall owes one sync per owed period, not a
/// collapsed single one.
#[test]
fn test_missed_periods_each_service() {
    let clock = ManualClock::new();
    let mut core = test_core(FakeSink::default(), clock.clone());
    // Two full fsync periods pass before the core gets to check.
    clock.advance(FSYNC_PERIOD * 2 + Duration::from_secs(1));
    core.service_due_deadlines();
    let ops = core.sink().ops.borrow();
    let syncs = ops
        .iter()
        .filter(|(_, op)| matches!(op, SinkOp::SyncFile))
        .count();
    assert_eq!(syncs, 2, "each owed period is settled: {ops:?}");
}

/// A failed flush keeps the tail pending — the next due deadline
/// retries it even though no new records arrived, and once the retry
/// succeeds the pending state is really cleared.
#[test]
fn test_failed_flush_retries_at_next_deadline() {
    let clock = ManualClock::new();
    let mut core = test_core(
        FakeSink {
            // The first flush attempt fails; later ones recover.
            fail_flush_at: Some(1),
            ..FakeSink::default()
        },
        clock.clone(),
    );
    core.handle_record(test_item(make_test_event(), None));
    clock.advance(FLUSH_PERIOD + Duration::from_secs(1));
    core.service_due_deadlines();
    assert_eq!(
        core.sink()
            .ops
            .borrow()
            .iter()
            .filter(|(_, op)| *op == SinkOp::Flush)
            .count(),
        1,
        "the due flush ran once and failed"
    );
    // No new records — the retained pending state must still make the
    // next deadline flush again.
    clock.advance(FLUSH_PERIOD);
    core.service_due_deadlines();
    assert_eq!(
        core.sink()
            .ops
            .borrow()
            .iter()
            .filter(|(_, op)| *op == SinkOp::Flush)
            .count(),
        2,
        "the next deadline retries the pending tail"
    );
    // The retry succeeded — a further due deadline flushes nothing.
    clock.advance(FLUSH_PERIOD);
    core.service_due_deadlines();
    assert_eq!(
        core.sink()
            .ops
            .borrow()
            .iter()
            .filter(|(_, op)| *op == SinkOp::Flush)
            .count(),
        2,
        "a successful retry clears the pending state"
    );
}

// ─── Rotation barrier ───────────────────────────────────────────────────

/// The queue position is the barrier: records dequeued ahead of the
/// control item are committed to generation 0; the marker is the first
/// record of generation 1, ahead of every record that follows.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_reopen_barrier_orders_generations() {
    let (entered_tx, entered_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let (op_tx, op_rx) = std::sync::mpsc::channel();
    let sink = FakeSink {
        mirror: Some(op_tx),
        reopen_gate: Some((entered_tx, release_rx)),
        ..FakeSink::default()
    };
    let logger = fake_logger(sink, ManualClock::new(), 8, true);
    for _ in 0..4 {
        logger.log(make_test_event());
    }
    let l = logger.clone();
    let reopened = tokio::spawn(async move { l.reopen(marker_ok()).await });
    // Park the writer inside the rotation — the barrier's queue
    // position is consumed and fixed, so what follows is post-barrier
    // by construction.
    gate_entered(entered_rx).await;
    // These land behind the control item — post-barrier records.
    for _ in 0..2 {
        logger.log(make_test_event());
    }
    release_tx.send(()).unwrap();
    assert!(reopened.await.unwrap().unwrap());
    let _ = logger.shutdown().await;

    let ops: Vec<(usize, SinkOp)> = op_rx.iter().collect();
    let barrier = ops
        .iter()
        .position(|(_, op)| *op == SinkOp::Reopen)
        .expect("the rotation must run");
    // Pre-barrier: all four records' writes on generation 0.
    let writes_before = ops[..barrier]
        .iter()
        .filter(|(_, op)| matches!(op, SinkOp::Write(_)))
        .count();
    assert_eq!(writes_before, 4, "pre-barrier records: {ops:?}");
    assert!(
        ops[..barrier].iter().all(|(g, _)| *g == 0),
        "pre-barrier work belongs to generation 0: {ops:?}"
    );
    // The first write after the barrier is the marker, on generation
    // 1, followed only by generation-1 records.
    let after = &ops[barrier + 1..];
    let first_write = after
        .iter()
        .find(|(_, op)| matches!(op, SinkOp::Write(_)))
        .expect("the marker must be written");
    assert_eq!(first_write.0, 1, "marker belongs to generation 1: {ops:?}");
    let SinkOp::Write(line) = &first_write.1 else {
        unreachable!()
    };
    assert!(
        line.contains("audit.reopened"),
        "first post-barrier write is the marker: {line}"
    );
    let record_writes_after = after
        .iter()
        .filter(|(_, op)| matches!(op, SinkOp::Write(l) if !l.contains("audit.reopened")))
        .count();
    assert_eq!(record_writes_after, 2, "post-barrier records: {ops:?}");
    assert!(
        after.iter().all(|(g, _)| *g == 1),
        "everything behind the barrier lands on generation 1: {ops:?}"
    );
}

/// A saturated record stream cannot starve a control request of
/// submission space: records fill their own bounded share, one drops
/// (the counted drop), and the rotation still submits, is serviced in
/// FIFO order, and is acknowledged. The receiver stays parked inside
/// the first record's write until the control item is provably *in*
/// the queue — admission ahead of any dequeue is what the control
/// reserve exists to guarantee.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_control_accepted_while_record_share_full() {
    let (entered_tx, entered_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let (op_tx, op_rx) = std::sync::mpsc::channel();
    let sink = FakeSink {
        mirror: Some(op_tx),
        // The writer parks inside the first record's write, holding
        // that record's slot in-flight — so all eight record slots
        // fill while the receiver cannot dequeue anything.
        write_gate: Some((entered_tx, release_rx)),
        ..FakeSink::default()
    };
    let logger = fake_logger(sink, ManualClock::new(), 8, false);
    logger.log(make_test_event());
    gate_entered(entered_rx).await;
    // Seven more records fill the remaining record slots — one
    // in-flight plus seven queued.
    for _ in 0..7 {
        logger.log(make_test_event());
    }
    // The ninth record finds no record slot — a counted drop, not a
    // control-space problem.
    logger.log(make_test_event());
    assert_eq!(logger.dropped_count(), 1);
    // The control request still submits — its own bounded capacity.
    // One fewer free queue slot is its admission proof: the item is
    // in the queue before the receiver is allowed to dequeue again.
    let free = queue_free(&logger);
    let l = logger.clone();
    let reopened = tokio::spawn(async move { l.reopen(marker_ok()).await });
    wait_until(
        || queue_free(&logger) == free - 1,
        "the control item's admission behind the saturated record share",
    )
    .await;
    release_tx.send(()).unwrap();
    assert!(
        reopened.await.unwrap().unwrap(),
        "the rotation must be accepted and serviced behind the saturated stream"
    );
    let _ = logger.shutdown().await;

    let ops: Vec<(usize, SinkOp)> = op_rx.iter().collect();
    let barrier = ops
        .iter()
        .position(|(_, op)| *op == SinkOp::Reopen)
        .unwrap();
    let writes_before = ops[..barrier]
        .iter()
        .filter(|(_, op)| matches!(op, SinkOp::Write(_)))
        .count();
    assert_eq!(
        writes_before, 8,
        "the barrier commits exactly the accepted records — the dropped ninth was never accepted: {ops:?}"
    );
}

/// Bounded control capacity: `CONTROL_QUEUE_CAPACITY` requests fill
/// the control reserve; the next waits for a dequeue — a bounded wait
/// on the writer, never on record space.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_control_capacity_is_bounded_and_fifo() {
    let (entered_tx, entered_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let (op_tx, op_rx) = std::sync::mpsc::channel();
    let sink = FakeSink {
        mirror: Some(op_tx),
        reopen_gate: Some((entered_tx, release_rx)),
        ..FakeSink::default()
    };
    let logger = fake_logger(sink, ManualClock::new(), 8, false);
    for _ in 0..2 {
        logger.log(make_test_event());
    }
    // The first reopen parks the writer inside the rotation — the
    // queue behind it still accepts control requests.
    let l = logger.clone();
    let first = tokio::spawn(async move { l.reopen(marker_seq(1)).await });
    gate_entered(entered_rx).await;
    // The remaining control capacity accepts three more requests.
    // Each request's marker carries its id, and each spawn waits for
    // the previous request's queue position to exist — one fewer free
    // slot — so the ids give the requests a known admission order
    // while the writer is still gated.
    let mut pending = Vec::new();
    for id in 2..=4usize {
        let free = queue_free(&logger);
        let l = logger.clone();
        pending.push(tokio::spawn(async move { l.reopen(marker_seq(id)).await }));
        wait_until(
            || queue_free(&logger) == free - 1,
            "a queued control request's queue position",
        )
        .await;
    }
    // Each request holds its permit from submission through service,
    // so the reserve is exhausted once all three have queued.
    assert_eq!(logger.inner.control_slots.available_permits(), 0);
    // The fifth must wait for a dequeue — bounded control capacity —
    // never for record space. The parked signal fires only after the
    // request's first poll suspended — with the reserve exhausted the
    // only pending point is the control-slot acquire — so
    // `!is_finished` and the unchanged queue occupancy read as
    // "parked on the full reserve", never "never polled" or "queued".
    let free = queue_free(&logger);
    let (parked_tx, parked_rx) = tokio::sync::oneshot::channel();
    let l = logger.clone();
    let fifth = tokio::spawn(async move {
        let mut fut = std::pin::pin!(l.reopen(marker_seq(5)));
        std::future::poll_fn(|cx| {
            assert!(
                fut.as_mut().poll(cx).is_pending(),
                "the fifth request must park on the full control reserve"
            );
            Poll::Ready(())
        })
        .await;
        let _ = parked_tx.send(());
        fut.await
    });
    parked_rx.await.unwrap();
    assert!(
        !fifth.is_finished(),
        "control capacity is bounded — the fifth waits"
    );
    assert_eq!(
        queue_free(&logger),
        free,
        "the fifth request is parked on the reserve — it never entered the queue"
    );
    release_tx.send(()).unwrap();
    assert!(first.await.unwrap().unwrap());
    for h in pending {
        assert!(h.await.unwrap().unwrap());
    }
    assert!(fifth.await.unwrap().unwrap());
    let _ = logger.shutdown().await;

    let ops: Vec<(usize, SinkOp)> = op_rx.iter().collect();
    let reopens = ops.iter().filter(|(_, op)| *op == SinkOp::Reopen).count();
    assert_eq!(
        reopens, 5,
        "every accepted rotation runs, in order: {ops:?}"
    );
    // Each rotation's marker is the first write of its new generation
    // — and carries its request's id, so the marker sequence across
    // generations is the queue's service order: it must equal the
    // admission order established above.
    for g in 1..=5usize {
        let first_write = ops
            .iter()
            .find(|(gg, op)| *gg == g && matches!(op, SinkOp::Write(_)));
        assert!(
            matches!(first_write, Some((_, SinkOp::Write(l))) if l.contains("audit.reopened") && l.contains(&format!("seq={g}"))),
            "generation {g}'s first record must be request {g}'s marker — the queue serves control items FIFO: {ops:?}"
        );
    }
}

/// A rotation request whose caller went away still occupies its
/// barrier position — an accepted request leaves no hole in the order,
/// and a dropped reply is not a writer fault.
#[tokio::test]
async fn test_accepted_control_processed_after_caller_cancel() {
    let (op_tx, op_rx) = std::sync::mpsc::channel();
    let (tx, rx) = mpsc::channel::<WriterItem>(4 + CONTROL_QUEUE_CAPACITY);
    let writer_failed = FailureFlag::new();
    let core = WriterCore::new(
        FakeSink::mirrored(op_tx),
        ManualClock::new(),
        writer_failed.clone(),
        AuditSyncMode::Buffered,
        TEST_SESSION.to_string(),
        PathBuf::from(TEST_PATH),
    );
    let writer = tokio::spawn(file_writer_task(rx, core));
    // Queue the control item directly, then drop its reply receiver —
    // the caller is gone before the writer reaches it.
    let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
    tx.send(WriterItem::Control(ControlRequest::Reopen(ReopenRequest {
        reply: reply_tx,
        marker: marker_ok(),
        queued_at: Instant::now(),
        slot: std::sync::Arc::new(tokio::sync::Semaphore::new(4))
            .try_acquire_owned()
            .unwrap(),
    })))
    .await
    .unwrap();
    drop(reply_rx);
    drop(tx);
    writer.await.unwrap();
    let ops: Vec<(usize, SinkOp)> = op_rx.iter().collect();
    assert!(
        ops.iter()
            .any(|(_, op)| matches!(op, SinkOp::Write(l) if l.contains("audit.reopened"))),
        "the barrier position is still honored: {ops:?}"
    );
    assert!(
        !writer_failed.get(),
        "a dropped reply is not a writer fault"
    );
}

/// The shutdown request's position is the channel's end: everything
/// already queued — records and the rotation — drains in acceptance
/// order before the final durable commit.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_shutdown_drains_in_acceptance_order() {
    let (entered_tx, entered_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let (op_tx, op_rx) = std::sync::mpsc::channel();
    let sink = FakeSink {
        mirror: Some(op_tx),
        reopen_gate: Some((entered_tx, release_rx)),
        ..FakeSink::default()
    };
    let logger = fake_logger(sink, ManualClock::new(), 8, true);
    for _ in 0..2 {
        logger.log(make_test_event());
    }
    let l = logger.clone();
    let reopened = tokio::spawn(async move { l.reopen(marker_ok()).await });
    // Park the writer inside the rotation — the two records below are
    // post-barrier by construction, and the shutdown's queue-end
    // position lands behind them all.
    gate_entered(entered_rx).await;
    for _ in 0..2 {
        logger.log(make_test_event());
    }
    release_tx.send(()).unwrap();
    assert!(reopened.await.unwrap().unwrap());
    assert!(logger.shutdown().await.is_ok());

    let ops: Vec<(usize, SinkOp)> = op_rx.iter().collect();
    let barrier = ops
        .iter()
        .position(|(_, op)| *op == SinkOp::Reopen)
        .unwrap();
    // Everything the rotation's own sequence did not emit still
    // surrounds it in acceptance order.
    assert!(
        matches!(ops[0].1, SinkOp::Write(_)) && matches!(ops[1].1, SinkOp::Write(_)),
        "pre-barrier records first: {ops:?}"
    );
    assert_eq!(
        ops[barrier].1,
        SinkOp::Reopen,
        "the barrier lands after the pre-barrier records: {ops:?}"
    );
    // The final durable commit — flush, fsync, visibility proof — is
    // the drain's tail.
    let tail = &ops[ops.len() - 3..];
    assert_eq!(
        tail.iter().map(|(_, op)| op).collect::<Vec<_>>(),
        vec![&SinkOp::Flush, &SinkOp::SyncFile, &SinkOp::EntryVisible],
        "the drain ends with the final durable commit: {ops:?}"
    );
}

/// A shutdown landing while a rotation is in flight does not reorder
/// anything: the rotation completes, the record queued behind it
/// lands on the new generation, and only then does the final commit
/// run.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_shutdown_while_rotation_in_flight() {
    let (entered_tx, entered_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let (op_tx, op_rx) = std::sync::mpsc::channel();
    let sink = FakeSink {
        mirror: Some(op_tx),
        reopen_gate: Some((entered_tx, release_rx)),
        ..FakeSink::default()
    };
    let logger = fake_logger(sink, ManualClock::new(), 8, true);
    logger.log(make_test_event());
    let l = logger.clone();
    let reopened = tokio::spawn(async move { l.reopen(marker_ok()).await });
    // Park the writer inside the rotation — deterministically.
    gate_entered(entered_rx).await;
    // The post-barrier record and the shutdown both land while the
    // rotation is mid-flight.
    logger.log(make_test_event());
    let l = logger.clone();
    let shutdown = tokio::spawn(async move { l.shutdown().await });
    // The shutdown's position is the channel close — confirm the
    // sender was taken while the rotation is still parked, or the
    // scenario tested is merely "shutdown after rotation".
    wait_until(
        || logger.inner.tx.lock().unwrap().is_none(),
        "shutdown to take the sender while the rotation is parked",
    )
    .await;
    release_tx.send(()).unwrap();
    assert!(reopened.await.unwrap().unwrap());
    shutdown.await.unwrap().unwrap();

    let ops: Vec<(usize, SinkOp)> = op_rx.iter().collect();
    let barrier = ops
        .iter()
        .position(|(_, op)| *op == SinkOp::Reopen)
        .unwrap();
    assert_eq!(
        ops[..barrier]
            .iter()
            .filter(|(_, op)| matches!(op, SinkOp::Write(_)))
            .count(),
        1,
        "the pre-barrier record committed to generation 0: {ops:?}"
    );
    let after = &ops[barrier + 1..];
    let writes_after = after
        .iter()
        .filter(|(_, op)| matches!(op, SinkOp::Write(_)))
        .count();
    assert_eq!(
        writes_after, 2,
        "marker plus post-barrier record on generation 1: {ops:?}"
    );
    assert!(
        after.iter().all(|(g, _)| *g == 1),
        "post-barrier work lands on generation 1: {ops:?}"
    );
    assert_eq!(
        ops[ops.len() - 3..]
            .iter()
            .map(|(_, op)| op)
            .collect::<Vec<_>>(),
        vec![&SinkOp::Flush, &SinkOp::SyncFile, &SinkOp::EntryVisible],
        "the drain's final commit follows the rotation: {ops:?}"
    );
}

// ─── Durable ack and failure paths ──────────────────────────────────────

/// The committed record's ack fires only after the whole durable path
/// — write, buffer flush, file fsync, and the visible-entry proof.
/// Parked mid-fsync, then again inside the visibility proof, the
/// acknowledgment is still pending; a failed durability step closes
/// the sender without a value.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_commit_ack_after_full_durable_path() {
    let (sync_entered_tx, sync_entered_rx) = std::sync::mpsc::channel();
    let (sync_release_tx, sync_release_rx) = std::sync::mpsc::channel();
    let (vis_entered_tx, vis_entered_rx) = std::sync::mpsc::channel();
    let (vis_release_tx, vis_release_rx) = std::sync::mpsc::channel();
    let (op_tx, op_rx) = std::sync::mpsc::channel();
    let logger = fake_logger(
        FakeSink {
            mirror: Some(op_tx),
            // Two mid-path windows: the fsync, then the visible-entry
            // proof — each is its own acknowledgment boundary.
            sync_gate: Some((sync_entered_tx, sync_release_rx)),
            visible_gate: RefCell::new(Some((vis_entered_tx, vis_release_rx))),
            ..FakeSink::default()
        },
        ManualClock::new(),
        8,
        true,
    );
    let (ack_tx, mut ack_rx) = tokio::sync::oneshot::channel();
    // The cloned sender is dropped right after the send — the
    // shutdown below must still see the channel close.
    let tx = logger.inner.tx.lock().unwrap().clone().unwrap();
    tx.send(WriterItem::Record(Box::new(test_item(
        make_test_event(),
        Some(ack_tx),
    ))))
    .await
    .unwrap();
    drop(tx);
    gate_entered(sync_entered_rx).await;
    assert!(
        matches!(
            ack_rx.try_recv(),
            Err(tokio::sync::oneshot::error::TryRecvError::Empty)
        ),
        "the acknowledgment stays pending mid-durable-path"
    );
    sync_release_tx.send(()).unwrap();
    // The fsync completed — the writer is now parked inside the
    // visibility proof — and the acknowledgment is still pending.
    gate_entered(vis_entered_rx).await;
    assert!(
        matches!(
            ack_rx.try_recv(),
            Err(tokio::sync::oneshot::error::TryRecvError::Empty)
        ),
        "the fsync alone never acknowledges — the proof must still run"
    );
    vis_release_tx.send(()).unwrap();
    // A retained sender would hang the waiter — a timeout here is a
    // test failure, not an outcome.
    tokio::time::timeout(Duration::from_secs(10), ack_rx)
        .await
        .expect("the ack must arrive promptly once the proof passes")
        .expect("the durable path completes — the ack fires");
    // The await resolving means every step below already ran.
    let ops: Vec<(usize, SinkOp)> = op_rx.try_iter().collect();
    assert_eq!(
        ops.len(),
        4,
        "write → flush → fsync → visible-proof: {ops:?}"
    );
    assert!(matches!(ops[0].1, SinkOp::Write(_)));
    assert_eq!(ops[1].1, SinkOp::Flush);
    assert_eq!(ops[2].1, SinkOp::SyncFile);
    assert_eq!(ops[3].1, SinkOp::EntryVisible);
    let _ = logger.shutdown().await;

    // The same gate with the fsync failing: the sender closes without
    // a value — the durable path never reports an acknowledgment.
    let (entered_tx, entered_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let (op_tx, op_rx) = std::sync::mpsc::channel();
    let logger = fake_logger(
        FakeSink {
            mirror: Some(op_tx),
            fail_sync: true,
            sync_gate: Some((entered_tx, release_rx)),
            ..FakeSink::default()
        },
        ManualClock::new(),
        8,
        true,
    );
    let (ack_tx, mut ack_rx) = tokio::sync::oneshot::channel();
    // The cloned sender is dropped right after the send — the
    // shutdown below must still see the channel close.
    let tx = logger.inner.tx.lock().unwrap().clone().unwrap();
    tx.send(WriterItem::Record(Box::new(test_item(
        make_test_event(),
        Some(ack_tx),
    ))))
    .await
    .unwrap();
    drop(tx);
    gate_entered(entered_rx).await;
    assert!(
        matches!(
            ack_rx.try_recv(),
            Err(tokio::sync::oneshot::error::TryRecvError::Empty)
        ),
        "the acknowledgment stays pending mid-durable-path"
    );
    release_tx.send(()).unwrap();
    // A retained (never-sent, never-dropped) sender would hang this
    // await — a timeout is a test failure, not evidence of a close.
    let closed = tokio::time::timeout(Duration::from_secs(10), ack_rx)
        .await
        .expect("the sender must close promptly");
    assert!(
        closed.is_err(),
        "a failed durability step closes the sender without a value"
    );
    let ops: Vec<(usize, SinkOp)> = op_rx.try_iter().collect();
    assert!(
        ops.iter().any(|(_, op)| *op == SinkOp::SyncFile)
            && !ops.iter().any(|(_, op)| *op == SinkOp::EntryVisible),
        "the fsync ran and failed — the visibility proof never did: {ops:?}"
    );
    let _ = logger.shutdown().await;
}

/// A directory entry that no longer names the sink is an audit fault,
/// not an ack — the commit waiter fails closed and the latch sets.
/// The error is the dropped-sender report ("before durable write"),
/// not `ensure_available`'s latched-failure refusal — the two failure
/// surfaces are never conflated.
#[tokio::test]
async fn test_commit_fails_when_entry_hidden() {
    let (op_tx, _op_rx) = std::sync::mpsc::channel();
    let logger = fake_logger(
        FakeSink {
            mirror: Some(op_tx),
            visible: false,
            ..FakeSink::default()
        },
        ManualClock::new(),
        8,
        true,
    );
    let err = logger.log_committed(make_test_event()).await.unwrap_err();
    match &err {
        crate::error::AuditorError::AuditUnavailable(msg) => assert!(
            msg.contains("before durable write"),
            "the withheld ack surfaces as the dropped-sender report, \
             not a failure-latch refusal: {err:?}"
        ),
        e => panic!("expected AuditUnavailable, got {e:?}"),
    }
    assert!(logger.is_failed(), "a hidden entry must latch the fault");
    let _ = logger.shutdown().await;
}

/// Write-side and sync-side failures — the disk-full shape — latch the
/// writer fault and refuse the commit ack.
#[tokio::test]
async fn test_write_and_sync_failures_latch() {
    // The record never reaches the sink: no durable step may follow.
    let (op_tx, op_rx) = std::sync::mpsc::channel();
    let logger = fake_logger(
        FakeSink {
            mirror: Some(op_tx),
            fail_write: true,
            ..FakeSink::default()
        },
        ManualClock::new(),
        8,
        true,
    );
    let err = logger.log_committed(make_test_event()).await.unwrap_err();
    assert!(matches!(
        err,
        crate::error::AuditorError::AuditUnavailable(_)
    ));
    assert!(logger.is_failed());
    let ops: Vec<(usize, SinkOp)> = op_rx.try_iter().collect();
    assert!(
        ops.is_empty(),
        "a failed write gates every later durable step: {ops:?}"
    );
    let _ = logger.shutdown().await;

    // The fsync failing is the disk-full shape: flushed but not
    // durable → no ack.
    let (op_tx, op_rx) = std::sync::mpsc::channel();
    let logger = fake_logger(
        FakeSink {
            mirror: Some(op_tx),
            fail_sync: true,
            ..FakeSink::default()
        },
        ManualClock::new(),
        8,
        true,
    );
    let err = logger.log_committed(make_test_event()).await.unwrap_err();
    assert!(matches!(
        err,
        crate::error::AuditorError::AuditUnavailable(_)
    ));
    assert!(logger.is_failed());
    let ops: Vec<(usize, SinkOp)> = op_rx.try_iter().collect();
    assert!(
        ops.iter().any(|(_, op)| *op == SinkOp::SyncFile)
            && !ops.iter().any(|(_, op)| *op == SinkOp::EntryVisible),
        "the fsync ran and failed — the visibility proof never did: {ops:?}"
    );
    let _ = logger.shutdown().await;
}

// ─── Reopen failure distinctions ────────────────────────────────────────

/// An old-generation fsync failure stops the rotation before the
/// swap: no `Reopen` op is recorded, every op stays on generation 0,
/// and the failure marker still lands on the surviving handle.
#[tokio::test]
async fn test_preswap_sync_failure_stops_rotation() {
    let (op_tx, op_rx) = std::sync::mpsc::channel();
    let logger = fake_logger(
        FakeSink {
            mirror: Some(op_tx),
            fail_sync: true,
            ..FakeSink::default()
        },
        ManualClock::new(),
        8,
        true,
    );
    let err = logger.reopen(marker_ok()).await.unwrap_err();
    assert!(matches!(
        err,
        crate::error::AuditorError::AuditUnavailable(_)
    ));
    assert!(
        logger.is_failed(),
        "a failed reopen latches the writer fault"
    );
    let _ = logger.shutdown().await;

    let ops: Vec<(usize, SinkOp)> = op_rx.iter().collect();
    assert!(
        !ops.iter().any(|(_, op)| *op == SinkOp::Reopen),
        "a pre-swap sync failure must stop the rotation before the swap: {ops:?}"
    );
    assert!(
        ops.iter().all(|(g, _)| *g == 0),
        "no swap — every op stays on generation 0: {ops:?}"
    );
    // The outcome=failure marker still records the refusal in-band.
    let marker = ops
        .iter()
        .find(|(_, op)| matches!(op, SinkOp::Write(l) if l.contains("audit.reopened")))
        .expect("the failure marker is still written");
    let SinkOp::Write(line) = &marker.1 else {
        unreachable!()
    };
    assert!(
        line.contains("\"outcome\":\"failure\""),
        "the marker records the failure: {line}"
    );
}

/// A refused reopen leaves the old generation live: the failure marker
/// lands on generation 0, later records keep appending there, and the
/// latch sets.
#[tokio::test]
async fn test_reopen_refused_keeps_old_generation() {
    let (op_tx, op_rx) = std::sync::mpsc::channel();
    let logger = fake_logger(
        FakeSink {
            mirror: Some(op_tx),
            reopen_plan: ReopenPlan::ErrBeforeSwap,
            ..FakeSink::default()
        },
        ManualClock::new(),
        8,
        true,
    );
    let err = logger.reopen(marker_ok()).await.unwrap_err();
    assert!(matches!(
        err,
        crate::error::AuditorError::AuditUnavailable(_)
    ));
    assert!(
        logger.is_failed(),
        "a failed reopen latches the writer fault"
    );
    logger.log(make_test_event());
    let _ = logger.shutdown().await;

    let ops: Vec<(usize, SinkOp)> = op_rx.iter().collect();
    assert!(
        ops.iter().all(|(g, _)| *g == 0),
        "a refused reopen swaps nothing: {ops:?}"
    );
    // The outcome=failure marker lands on the surviving (old) handle.
    let marker = ops
        .iter()
        .find(|(_, op)| matches!(op, SinkOp::Write(l) if l.contains("audit.reopened")))
        .expect("the failure marker is still written");
    let SinkOp::Write(line) = &marker.1 else {
        unreachable!()
    };
    assert!(
        line.contains("\"outcome\":\"failure\""),
        "the marker records the failure: {line}"
    );
}

/// A post-swap sync failure reports `Err` while the new generation is
/// live — the distinction a plain refusal never makes: the marker and
/// later records land on generation 1.
#[tokio::test]
async fn test_post_swap_failure_keeps_new_generation() {
    let (op_tx, op_rx) = std::sync::mpsc::channel();
    let logger = fake_logger(
        FakeSink {
            mirror: Some(op_tx),
            reopen_plan: ReopenPlan::ErrAfterSwap,
            ..FakeSink::default()
        },
        ManualClock::new(),
        8,
        true,
    );
    let err = logger.reopen(marker_ok()).await.unwrap_err();
    assert!(matches!(
        err,
        crate::error::AuditorError::AuditUnavailable(_)
    ));

    // The reply resolves only after the marker's durable path
    // completes — snapshot now, before another record or the shutdown
    // drain can contribute ops, so the dir-sync count below is the
    // marker path's own retry.
    let ops: Vec<(usize, SinkOp)> = op_rx.try_iter().collect();
    let barrier = ops
        .iter()
        .position(|(_, op)| *op == SinkOp::Reopen)
        .unwrap();
    assert!(
        ops[barrier + 1..].iter().all(|(g, _)| *g == 1),
        "the swap already happened — post-barrier work is generation 1: {ops:?}"
    );
    // The marker's durable path retries the owed entry sync on the new
    // generation.
    let dir_syncs_after = ops[barrier + 1..]
        .iter()
        .filter(|(_, op)| *op == SinkOp::SyncDir)
        .count();
    assert!(
        dir_syncs_after >= 2,
        "post-swap dir sync attempt plus the marker path's retry: {ops:?}"
    );

    // A record logged after the failed rotation still lands on the
    // live new generation — the swap survived the post-swap failure.
    logger.log(make_test_event());
    let _ = logger.shutdown().await;
    let ops: Vec<(usize, SinkOp)> = op_rx.iter().collect();
    assert!(
        ops.iter().any(|(g, op)| *g == 1
            && matches!(op, SinkOp::Write(l) if !l.contains("audit.reopened"))),
        "the post-rotation record lands on generation 1: {ops:?}"
    );
}

/// A marker write that fails after a successful swap reports `Err` —
/// distinct from the reopen refusal — and leaves the new generation
/// live.
#[tokio::test]
async fn test_marker_write_failure_is_distinct() {
    let (op_tx, op_rx) = std::sync::mpsc::channel();
    let logger = fake_logger(
        FakeSink {
            mirror: Some(op_tx),
            // The marker is the first write the rotation produces.
            fail_write_at: Some(1),
            ..FakeSink::default()
        },
        ManualClock::new(),
        8,
        true,
    );
    let err = logger.reopen(marker_ok()).await.unwrap_err();
    assert!(matches!(
        err,
        crate::error::AuditorError::AuditUnavailable(_)
    ));
    assert!(logger.is_failed());
    logger.log(make_test_event());
    let _ = logger.shutdown().await;

    let ops: Vec<(usize, SinkOp)> = op_rx.iter().collect();
    let barrier = ops
        .iter()
        .position(|(_, op)| *op == SinkOp::Reopen)
        .unwrap();
    let gen1_write = ops[barrier + 1..]
        .iter()
        .find(|(_, op)| matches!(op, SinkOp::Write(_)));
    assert!(
        gen1_write.is_some_and(|(g, _)| *g == 1),
        "the post-barrier record still lands on generation 1: {ops:?}"
    );
}

// ─── Permit release on cancel / send failure ────────────────────────────

/// A producer cancelled while waiting on queue space drops its held
/// permits — the byte budget comes back and no hole appears in the
/// order: the item was never in the queue.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_cancelled_wait_releases_its_permits() {
    let (entered_tx, entered_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let (op_tx, op_rx) = std::sync::mpsc::channel();
    let sink = FakeSink {
        mirror: Some(op_tx),
        // The writer parks inside the first record's write, holding
        // its queue slot for the whole gate window.
        write_gate: Some((entered_tx, release_rx)),
        ..FakeSink::default()
    };
    // A single record slot — the in-flight record occupies it.
    let logger = fake_logger(sink, ManualClock::new(), 1, true);
    logger.log_ordered(make_test_event()).await.unwrap();
    gate_entered(entered_rx).await;
    // A second ordered record waits on the record slot — bounded
    // backpressure, not a drop.
    let l = logger.clone();
    let waiter = tokio::spawn(async move { l.log_ordered(make_test_event()).await });
    // Prove the waiter acquired its byte permit and is parked on the
    // record slot before the abort — an abort landing before the
    // acquire would pass the assertions without exercising the
    // cancel-while-holding path.
    wait_until(
        || {
            logger.inner.bytes_budget.available_permits() < QUEUE_BYTE_BUDGET
                && logger.inner.event_slots.available_permits() == 0
        },
        "the waiter to hold its byte permit on the full record slot",
    )
    .await;
    assert!(
        !waiter.is_finished(),
        "the slot wait is bounded backpressure"
    );
    waiter.abort();
    // The aborted waiter held its byte permit while parking — its drop
    // restores the budget in full; the record slot it never got is
    // still pinned by the in-flight record.
    waiter.await.unwrap_err();
    assert_eq!(
        logger.inner.bytes_budget.available_permits(),
        QUEUE_BYTE_BUDGET,
        "the cancelled waiter's byte permit is back"
    );
    assert_eq!(logger.inner.event_slots.available_permits(), 0);
    // Release the gate: the in-flight record commits and its slot frees.
    release_tx.send(()).unwrap();
    logger.log_ordered(make_test_event()).await.unwrap();
    let _ = logger.shutdown().await;
    let ops: Vec<(usize, SinkOp)> = op_rx.iter().collect();
    assert_eq!(
        ops.iter()
            .filter(|(_, op)| matches!(op, SinkOp::Write(_)))
            .count(),
        2,
        "exactly the two accepted records — the cancelled send left no hole: {ops:?}"
    );
}

/// A send that fails outright (receiver already closed) drops the item
/// — both permits release.
#[tokio::test]
async fn test_failed_send_releases_its_permits() {
    let (tx, rx) = mpsc::channel::<WriterItem>(4 + CONTROL_QUEUE_CAPACITY);
    let logger = super::assemble_logger(
        tx,
        tokio::spawn(std::future::pending()),
        true,
        4,
        QUEUE_BYTE_BUDGET,
        true,
        FailureFlag::new(),
        TEST_SESSION.to_string(),
    );
    drop(rx);
    let err = logger.log_ordered(make_test_event()).await.unwrap_err();
    assert!(matches!(
        err,
        crate::error::AuditorError::AuditUnavailable(_)
    ));
    assert_eq!(
        logger.inner.event_slots.available_permits(),
        4,
        "the record slot releases on send failure"
    );
    assert_eq!(
        logger.inner.bytes_budget.available_permits(),
        QUEUE_BYTE_BUDGET,
        "the byte budget releases on send failure"
    );
}
