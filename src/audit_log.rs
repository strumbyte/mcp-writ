use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use tokio::sync::mpsc;

mod emit;
mod event;
mod sink_guard;
mod sink_open;
mod writer;

use emit::generate_session_id;
pub use emit::{now_iso8601, now_iso8601_millis, write_event_jsonl};
pub use event::{
    AUDIT_SCHEMA_VERSION, Action, AuditEvent, EmbeddedJson, EventType, Outcome, PolicyAuditContext,
    Severity,
};
pub use event::{MAX_AUDIT_FIELD_BYTES, bound_audit_field, encode_audit_field_value};
pub use sink_guard::{
    audit_sink_write_conflict, policy_source_write_conflict, report_write_conflict,
    snapshot_write_conflict,
};
use writer::{
    FileSink, FileWriterSpawn, SinkAnchor, TokioClock, WriterCore, spawn_file_writer,
    tracing_writer_task,
};

// ═══════════════════════════════════════════════════════════════════════════════
// AuditLogger (mpsc channel + dedicated writer thread)
// ═══════════════════════════════════════════════════════════════════════════════

/// Record slots in the writer's bounded queue — enforced by the
/// `event_slots` semaphore instead of the channel bound itself, so
/// control requests get their own reserve on the same queue.
const EVENT_QUEUE_CAPACITY: usize = 4096;
const BUF_WRITER_CAPACITY: usize = 65536; // 64KB
const FLUSH_EVENT_THRESHOLD: u32 = 100;

/// Aggregate byte ceiling for records sitting in the queue. The count
/// bound (`EVENT_QUEUE_CAPACITY`) alone cannot hold memory: each queued
/// event's size is whatever the wire offered — a denied `tools/call`
/// can carry megabytes of attacker arguments. A producer hitting the
/// byte budget is treated exactly like a full channel: counted drop in
/// best-effort mode, writer-fault latch under fail-closed, and bounded
/// backpressure for `log_ordered`/`log_committed`.
const QUEUE_BYTE_BUDGET: usize = 32 * 1024 * 1024;

/// A record at or above this severity skips the buffered tail: the
/// writer flushes *and* fsyncs it as soon as it is dequeued — a sync
/// that also carries any earlier records still sitting in the buffer —
/// so a SIGKILL cannot shed it once the writer has reached it. `High` is
/// the floor — a denial or failure record is exactly the evidence a
/// forced kill most wants to lose. The threshold is a fixed contract
/// documented in the guide, not a dial: making it configurable would
/// let an operator silently weaken the durability this path exists to
/// guarantee.
const IMMEDIATE_SYNC_SEVERITY: Severity = Severity::High;

/// How aggressively the file writer pushes queued records to stable
/// storage. The mode changes only *when* records sync, never what is
/// recorded — the JSONL schema is identical under either mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AuditSyncMode {
    /// Buffered tail (default): records flush on a 1s interval or every
    /// 100 queued events and fsync every 5s; a record at
    /// `IMMEDIATE_SYNC_SEVERITY` or with a commit waiter syncs at
    /// once. A force-kill loses at most the buffered tail since the
    /// last sync point.
    #[default]
    Buffered,
    /// `--audit-sync`: every record is flushed and fsync'd before the
    /// writer dequeues the next one — a storage round-trip per record
    /// in exchange for the emitted stream being durable up to the last
    /// record the writer reached. Trades sustained fsync latency for
    /// the smallest possible force-kill loss window.
    EveryEvent,
}

/// Control requests — reopen today — own this many slots of the
/// unified queue: the same 4 the dedicated reopen channel held.
/// Because records are separately capped by `event_slots`, a saturated
/// record stream can never starve control submission of queue space.
const CONTROL_QUEUE_CAPACITY: usize = 4;

/// Headroom above the permit-accounted capacity for the writer's own
/// wake items: a [`WriterItem::Tick`] carries no permit, so without
/// headroom a saturated queue could bounce the deadline wake — and a
/// queued tick must never push a permit-holding `try_send` into
/// `Full`. At most one tick is outstanding at a time, so two slots
/// bound it with margin.
const TICK_QUEUE_RESERVE: usize = 2;

/// Total bounded capacity of the writer's intake queue — records plus
/// the control reserve plus the tick headroom.
const QUEUE_CAPACITY: usize = EVENT_QUEUE_CAPACITY + CONTROL_QUEUE_CAPACITY + TICK_QUEUE_RESERVE;

/// One queued audit record. The oneshot half is set only by
/// [`AuditLogger::log_committed`]: the writer signals it after the
/// record is durably persisted — flushed through the `BufWriter` and
/// `sync_all`'d to storage — so a fail-closed path forwards protected
/// traffic only after the record exists on disk, not merely after the
/// queue accepted it. The permits pin the record's byte share of
/// [`QUEUE_BYTE_BUDGET`] and one of [`EVENT_QUEUE_CAPACITY`] record
/// slots until the writer consumes the item — dropping the item (a
/// failed or cancelled send) releases both.
struct AuditItem {
    event: AuditEvent,
    ack: Option<tokio::sync::oneshot::Sender<()>>,
    bytes_permit: tokio::sync::OwnedSemaphorePermit,
    slot_permit: tokio::sync::OwnedSemaphorePermit,
}

/// Everything the writer consumes, on one FIFO — the single place the
/// acceptance order of records and control requests is fixed. A
/// `Control` item's queue position is an ordering barrier: a reopen
/// commits every record dequeued ahead of it to the still-live sink
/// before swapping, then writes its marker ahead of all records that
/// follow. Channel close — every sender dropped — is the shutdown
/// request's position in the same order: the writer drains what is
/// queued and performs its final durable commit.
enum WriterItem {
    // `AuditItem` is the wire event plus its permits — boxing keeps
    // `WriterItem` small enough that a queued `Control` never pays for
    // the record variant's size.
    Record(Box<AuditItem>),
    Control(ControlRequest),
    /// The deadline wake the writer's ticker companion posts when the
    /// earliest periodic deadline passes — payloadless, in queue
    /// order, serviced by running whatever deadlines are due. It
    /// holds no permit and occupies a [`TICK_QUEUE_RESERVE`] slot, so
    /// it can never displace a record or control item.
    Tick,
}

enum ControlRequest {
    Reopen(ReopenRequest),
}

/// Builds the `audit.reopened` record inside the writer — the
/// argument is `Some(error)` on a failed reopen and `None` on success,
/// so the same factory produces both the success and the failure
/// marker. Running it in-band keeps the marker ahead of every
/// concurrently queued record and out of the bounded channel's drop
/// accounting entirely.
pub type ReopenMarker = Box<dyn FnOnce(Option<String>) -> AuditEvent + Send>;

/// A reopen request pairs the oneshot its result is reported through
/// with the rotation-marker factory: the writer flushes + fsyncs the
/// live sink, re-resolves the audit path through `open_audit_sink`,
/// swaps handles, and records the marker before acknowledging.
/// `queued_at` feeds the `audit.control_wait.ns` measure — the
/// submission-to-service wait; `slot` is the request's
/// [`CONTROL_QUEUE_CAPACITY`] share, released when the writer dequeues
/// it.
struct ReopenRequest {
    reply: tokio::sync::oneshot::Sender<std::io::Result<()>>,
    marker: ReopenMarker,
    queued_at: std::time::Instant,
    slot: tokio::sync::OwnedSemaphorePermit,
}

/// Writer-failure flag fused with its wake notification: setting the
/// flag is impossible without also waking fail-closed waiters — an
/// idle relay parked on `failure_watch` learns about a dead writer or
/// saturated channel immediately instead of discovering it only when
/// the next frame's `log` happens to trip the same code path.
/// `send` on a watch channel fails only when no receivers exist —
/// that is exactly the "nobody left to wake" case.
#[derive(Clone)]
struct FailureFlag {
    flag: std::sync::Arc<AtomicBool>,
    notify: tokio::sync::watch::Sender<bool>,
}

impl FailureFlag {
    fn new() -> Self {
        let (notify, _) = tokio::sync::watch::channel(false);
        Self {
            flag: std::sync::Arc::new(AtomicBool::new(false)),
            notify,
        }
    }

    fn get(&self) -> bool {
        self.flag.load(Ordering::SeqCst)
    }

    fn set(&self) {
        self.flag.store(true, Ordering::SeqCst);
        let _ = self.notify.send(true);
    }

    fn watch(&self) -> tokio::sync::watch::Receiver<bool> {
        self.notify.subscribe()
    }
}

#[derive(Clone)]
pub struct AuditLogger {
    inner: std::sync::Arc<AuditLoggerInner>,
}

/// What `shutdown()` waits on once the intake closes — the writer's
/// end-of-life notice. The file sink runs on a dedicated OS thread:
/// its completion arrives over a oneshot the async side awaits, never
/// a synchronous thread join on a runtime worker. The tracing sink
/// stays an ordinary task — stderr delivery carries none of the
/// durable-sink guarantees the file writer is isolated for.
enum WriterEnd {
    /// The dedicated file-writer thread's spawn set: the completion
    /// oneshot, the join handle (ownership token — the oneshot is the
    /// completion channel, so the handle is released by detach, never
    /// joined), and the idle-wake ticker retired with the writer.
    Thread(FileWriterSpawn),
    /// The tracing writer's ordinary task.
    Task(tokio::task::JoinHandle<()>),
}

struct AuditLoggerInner {
    tx: std::sync::Mutex<Option<mpsc::Sender<WriterItem>>>,
    /// `true` while this logger drives a live file sink — the only
    /// sink [`AuditLogger::reopen`] can act on. `false` for the
    /// tracing sink; combined with a taken `tx` (post-shutdown) a
    /// reopen finds no live sink, matching the old dedicated-channel
    /// `None`.
    file_sink: bool,
    session_id: String,
    writer_end: tokio::sync::Mutex<Option<WriterEnd>>,
    fail_closed: bool,
    dropped: AtomicU64,
    writer_failed: FailureFlag,
    /// Byte-level queue bound — one permit per queued wire byte. Held
    /// inside the `AuditItem`, so the writer consuming a record frees
    /// its share automatically.
    bytes_budget: std::sync::Arc<tokio::sync::Semaphore>,
    /// Record slots — the [`EVENT_QUEUE_CAPACITY`] bound on the record
    /// share of the unified queue. Held inside each `AuditItem` until
    /// the writer dequeues it.
    event_slots: std::sync::Arc<tokio::sync::Semaphore>,
    /// Control slots — the [`CONTROL_QUEUE_CAPACITY`] reserve keeping
    /// control submission bounded and unblocked under record
    /// saturation.
    control_slots: std::sync::Arc<tokio::sync::Semaphore>,
}

impl AuditLogger {
    /// Create a logger that appends JSONL to a file.
    /// Spawns the dedicated writer thread the sink lives on.
    ///
    /// Must be called within a Tokio runtime context — the writer's
    /// idle-wake ticker is a task on the calling runtime — and the
    /// runtime's time driver must be enabled (`Builder::enable_all`
    /// or `enable_time`): startup arms the ticker's timer before
    /// returning and refuses a runtime that cannot run it. Keep the
    /// logger within that runtime's lifetime: if the runtime shuts
    /// down first, records still drain on the writer's thread but the
    /// periodic idle sync stops being woken.
    pub fn to_file(path: &Path) -> Result<Self, std::io::Error> {
        Self::to_file_with_fail_closed(path, true)
    }

    /// Create a file logger. When `fail_closed` is true, enqueue or write
    /// failures mark the logger unavailable so enforcement can stop.
    pub fn to_file_with_fail_closed(
        path: &Path,
        fail_closed: bool,
    ) -> Result<Self, std::io::Error> {
        Self::to_file_with_options(path, fail_closed, AuditSyncMode::Buffered)
    }

    /// Create a file logger with an explicit sync mode —
    /// [`AuditSyncMode::EveryEvent`] is the `--audit-sync` path, syncing
    /// every record as it is written instead of buffering a tail.
    ///
    /// Like [`AuditLogger::to_file`], this must be called within a
    /// Tokio runtime context whose lifetime covers the logger's and
    /// whose time driver is enabled (`enable_all`/`enable_time`).
    /// Returns `Err` if the OS refuses the writer's thread spawn or
    /// the calling runtime cannot arm the ticker's timer; the
    /// already-opened log file is left behind — possibly empty —
    /// because it may pre-date this call and removing it could delete
    /// a log the caller still owns. Dropping every clone of the logger
    /// without `shutdown()` closes the intake and lets the writer
    /// drain on its own thread; a leaked logger leaks that thread.
    pub fn to_file_with_options(
        path: &Path,
        fail_closed: bool,
        sync_mode: AuditSyncMode,
    ) -> Result<Self, std::io::Error> {
        // The sink open is part of the trust boundary: `open_audit_sink`
        // resolves ancestors without following links, refuses a link or
        // non-regular leaf, verifies the opened handle, and tightens it
        // to owner-only access. For a file this call creates, the
        // returned parent-directory handle is the fsync anchor — the
        // directory entry must be durable before the first completion
        // notification or a crash could lose the whole log — and the
        // leaf name lets the writer re-verify the entry still names
        // the opened object before committing acknowledgments.
        let sink_open::OpenedSink { file, dir, leaf } = sink_open::open_audit_sink(path)?;
        let writer = std::io::BufWriter::with_capacity(BUF_WRITER_CAPACITY, file);
        let (tx, rx) = mpsc::channel(QUEUE_CAPACITY);
        let session_id = generate_session_id();
        let writer_failed = FailureFlag::new();
        let sink = FileSink::new(writer, SinkAnchor { dir, leaf });
        let core = WriterCore::new(
            sink,
            TokioClock,
            writer_failed.clone(),
            sync_mode,
            session_id.clone(),
            path.to_path_buf(),
        );
        let writer_end = WriterEnd::Thread(spawn_file_writer(&tx, rx, core)?);
        let bytes_budget = std::sync::Arc::new(tokio::sync::Semaphore::new(QUEUE_BYTE_BUDGET));
        #[cfg(feature = "measure")]
        crate::measure::register_queue_budget(QUEUE_BYTE_BUDGET as u64, &bytes_budget);
        Ok(Self {
            inner: std::sync::Arc::new(AuditLoggerInner {
                tx: std::sync::Mutex::new(Some(tx)),
                file_sink: true,
                session_id,
                writer_end: tokio::sync::Mutex::new(Some(writer_end)),
                fail_closed,
                dropped: AtomicU64::new(0),
                writer_failed,
                bytes_budget,
                event_slots: std::sync::Arc::new(tokio::sync::Semaphore::new(EVENT_QUEUE_CAPACITY)),
                control_slots: std::sync::Arc::new(tokio::sync::Semaphore::new(
                    CONTROL_QUEUE_CAPACITY,
                )),
            }),
        })
    }

    /// Create a logger that outputs via tracing (stderr).
    /// Spawns a dedicated writer task on the tokio runtime.
    pub fn to_tracing() -> Self {
        Self::to_tracing_with_fail_closed(false)
    }

    /// Tracing/stderr logger. `fail_closed` makes a full channel abort the session.
    pub fn to_tracing_with_fail_closed(fail_closed: bool) -> Self {
        let (tx, rx) = mpsc::channel(QUEUE_CAPACITY);
        let session_id = generate_session_id();
        let writer_failed = FailureFlag::new();
        // stderr delivery cannot prove a durable write — a fail-closed
        // logger's completion waiters must not be acknowledged here.
        let writer_end = WriterEnd::Task(tokio::spawn(tracing_writer_task(
            rx,
            !fail_closed,
            session_id.clone(),
        )));
        let bytes_budget = std::sync::Arc::new(tokio::sync::Semaphore::new(QUEUE_BYTE_BUDGET));
        #[cfg(feature = "measure")]
        crate::measure::register_queue_budget(QUEUE_BYTE_BUDGET as u64, &bytes_budget);
        Self {
            inner: std::sync::Arc::new(AuditLoggerInner {
                tx: std::sync::Mutex::new(Some(tx)),
                file_sink: false,
                session_id,
                writer_end: tokio::sync::Mutex::new(Some(writer_end)),
                fail_closed,
                dropped: AtomicU64::new(0),
                writer_failed,
                bytes_budget,
                event_slots: std::sync::Arc::new(tokio::sync::Semaphore::new(EVENT_QUEUE_CAPACITY)),
                control_slots: std::sync::Arc::new(tokio::sync::Semaphore::new(
                    CONTROL_QUEUE_CAPACITY,
                )),
            }),
        }
    }

    /// Get the session ID for this logger instance.
    pub fn session_id(&self) -> &str {
        &self.inner.session_id
    }

    /// Bound the wire-derived string members of `event` to
    /// [`MAX_AUDIT_FIELD_BYTES`] and return the record's byte-budget
    /// share — capped at the whole budget so a single oversized record
    /// can always proceed once the queue drains. The session id is no
    /// longer stored on the event; the writer attaches its own
    /// logger's id at serialization time, so this function only
    /// accounts for the id's length in the byte-budget share.
    fn prepare(event: &mut AuditEvent, session_id: &str) -> u32 {
        event.bound_wire_fields();
        (event.wire_size() + session_id.len()).min(QUEUE_BYTE_BUDGET) as u32
    }

    /// Log an audit event. Non-blocking.
    ///
    /// When `fail_closed` is set, a full or closed channel — or an
    /// exhausted byte budget — marks the logger unavailable instead of
    /// silently discarding the event.
    pub fn log(&self, mut event: AuditEvent) {
        let need = Self::prepare(&mut event, &self.inner.session_id);
        let bytes_permit = match self.inner.bytes_budget.clone().try_acquire_many_owned(need) {
            Ok(p) => p,
            Err(_) => {
                self.inner.dropped.fetch_add(1, Ordering::Relaxed);
                if self.inner.fail_closed {
                    self.inner.writer_failed.set();
                }
                tracing::error!(
                    event_type = event.event_type.as_str(),
                    fail_closed = self.inner.fail_closed,
                    bytes = need,
                    "Audit queue byte budget exhausted"
                );
                return;
            }
        };
        let slot_permit = match self.inner.event_slots.clone().try_acquire_owned() {
            Ok(p) => p,
            Err(_) => {
                self.inner.dropped.fetch_add(1, Ordering::Relaxed);
                // Saturation is a counted drop in best-effort mode —
                // the writer itself is still healthy, so only a
                // fail-closed session treats a full channel as a
                // writer fault.
                if self.inner.fail_closed {
                    self.inner.writer_failed.set();
                }
                tracing::error!(
                    event_type = event.event_type.as_str(),
                    fail_closed = self.inner.fail_closed,
                    "Audit log channel full"
                );
                return;
            }
        };
        let tx_opt = self.inner.tx.lock().unwrap();
        if let Some(tx) = tx_opt.as_ref() {
            if let Err(e) = tx.try_send(WriterItem::Record(Box::new(AuditItem {
                event,
                ack: None,
                bytes_permit,
                slot_permit,
            }))) {
                match e {
                    // A record holding a slot permit always fits the
                    // queue's record share — unreachable while the
                    // accounting holds; keep the counted-drop/latch
                    // parity regardless.
                    mpsc::error::TrySendError::Full(WriterItem::Record(item)) => {
                        self.inner.dropped.fetch_add(1, Ordering::Relaxed);
                        if self.inner.fail_closed {
                            self.inner.writer_failed.set();
                        }
                        tracing::error!(
                            event_type = item.event.event_type.as_str(),
                            fail_closed = self.inner.fail_closed,
                            "Audit log channel full"
                        );
                    }
                    mpsc::error::TrySendError::Closed(WriterItem::Record(item)) => {
                        self.inner.writer_failed.set();
                        tracing::error!(
                            event_type = item.event.event_type.as_str(),
                            "Audit log channel closed"
                        );
                    }
                    _ => {}
                }
            }
        } else {
            self.inner.writer_failed.set();
            tracing::error!(
                event_type = event.event_type.as_str(),
                "Audit log channel unavailable after shutdown"
            );
        }
    }

    /// Enqueue a record that must precede the protected action it
    /// authorizes: under fail-closed this waits on `send().await` so
    /// saturation is backpressure rather than a silently dropped
    /// authorization record, and a closed channel refuses the forward
    /// with `AuditUnavailable`. The record is FIFO-ordered ahead of the
    /// action, so no frame crosses ahead of its own decision record.
    /// Durability stays governed by [`AuditSyncMode`] — deployments
    /// needing durable-before-forward ordering per record use
    /// `EveryEvent` or [`AuditLogger::log_committed`].
    ///
    /// Best-effort mode keeps [`AuditLogger::log`]'s counted try_send:
    /// an unenqueued record is only acceptable where the session is
    /// allowed to continue.
    pub async fn log_ordered(
        &self,
        mut event: AuditEvent,
    ) -> Result<(), crate::error::AuditorError> {
        if !self.inner.fail_closed {
            self.log(event);
            return Ok(());
        }
        let need = Self::prepare(&mut event, &self.inner.session_id);
        // Bounded backpressure: wait for byte budget, then a record
        // slot, before queueing — saturation slows the producer instead
        // of dropping the record. Cancelling the wait drops the
        // permits and leaves no hole in the queue order: an item
        // exists only once its send lands.
        let bytes_permit = match self
            .inner
            .bytes_budget
            .clone()
            .acquire_many_owned(need)
            .await
        {
            Ok(p) => p,
            Err(_) => {
                self.inner.writer_failed.set();
                return Err(crate::error::AuditorError::AuditUnavailable(
                    "audit queue closed".into(),
                ));
            }
        };
        let slot_permit = match self.inner.event_slots.clone().acquire_owned().await {
            Ok(p) => p,
            Err(_) => {
                self.inner.writer_failed.set();
                return Err(crate::error::AuditorError::AuditUnavailable(
                    "audit queue closed".into(),
                ));
            }
        };
        let tx = {
            let guard = self.inner.tx.lock().unwrap();
            guard.as_ref().cloned()
        };
        match tx {
            Some(tx) => {
                if tx
                    .send(WriterItem::Record(Box::new(AuditItem {
                        event,
                        ack: None,
                        bytes_permit,
                        slot_permit,
                    })))
                    .await
                    .is_err()
                {
                    self.inner.writer_failed.set();
                    return Err(crate::error::AuditorError::AuditUnavailable(
                        "audit log channel closed".into(),
                    ));
                }
            }
            None => {
                self.inner.writer_failed.set();
                return Err(crate::error::AuditorError::AuditUnavailable(
                    "audit log channel unavailable".into(),
                ));
            }
        }
        self.ensure_available()
    }

    /// Enqueue an event and, in fail-closed mode, wait until the writer
    /// has durably persisted it — buffer flush plus `sync_all` — before
    /// returning. Merely being accepted by the channel is not enough:
    /// the protected traffic this call precedes must not forward until
    /// the record actually exists on disk.
    ///
    /// Each call costs a storage round-trip — a `BufWriter` flush plus
    /// `sync_all`, and a one-time parent-directory fsync on a freshly
    /// created log — so a fail-closed gate on a hot path (e.g. every
    /// allowed `tools/call`) serializes on disk latency. That is the
    /// deliberate price of durable-before-forward ordering: batching or
    /// weakening the ack would reopen the gap this call exists to close.
    pub async fn log_committed(
        &self,
        mut event: AuditEvent,
    ) -> Result<(), crate::error::AuditorError> {
        if !self.inner.fail_closed {
            self.log(event);
            return self.ensure_available();
        }
        let need = Self::prepare(&mut event, &self.inner.session_id);
        let bytes_permit = match self
            .inner
            .bytes_budget
            .clone()
            .acquire_many_owned(need)
            .await
        {
            Ok(p) => p,
            Err(_) => {
                self.inner.writer_failed.set();
                return Err(crate::error::AuditorError::AuditUnavailable(
                    "audit queue closed".into(),
                ));
            }
        };
        let slot_permit = match self.inner.event_slots.clone().acquire_owned().await {
            Ok(p) => p,
            Err(_) => {
                self.inner.writer_failed.set();
                return Err(crate::error::AuditorError::AuditUnavailable(
                    "audit queue closed".into(),
                ));
            }
        };
        let tx = {
            let guard = self.inner.tx.lock().unwrap();
            guard.as_ref().cloned()
        };
        match tx {
            Some(tx) => {
                let (ack_tx, ack_rx) = tokio::sync::oneshot::channel();
                if tx
                    .send(WriterItem::Record(Box::new(AuditItem {
                        event,
                        ack: Some(ack_tx),
                        bytes_permit,
                        slot_permit,
                    })))
                    .await
                    .is_err()
                {
                    self.inner.writer_failed.set();
                    return Err(crate::error::AuditorError::AuditUnavailable(
                        "audit log channel closed".into(),
                    ));
                }
                // A dropped sender (writer dead) fails the wait —
                // fail closed rather than forward unaudited traffic.
                if ack_rx.await.is_err() {
                    self.inner.writer_failed.set();
                    return Err(crate::error::AuditorError::AuditUnavailable(
                        "audit writer stopped before durable write".into(),
                    ));
                }
            }
            None => {
                self.inner.writer_failed.set();
                return Err(crate::error::AuditorError::AuditUnavailable(
                    "audit log channel unavailable".into(),
                ));
            }
        }
        self.ensure_available()
    }

    /// Re-resolve and swap the file sink at the launch's audit path —
    /// the logrotate coexistence path driven by SIGUSR1 on Unix. The
    /// request enters the same queue the records use, so its position
    /// is the ordering barrier: every record accepted ahead of it is
    /// committed to the *old* file first — the writer flushes and
    /// fsyncs that file before the handle is swapped — and every record
    /// behind it lands in the new file after the marker. The path is
    /// re-opened through the same trust-boundary checks the launch
    /// used, so a link planted by a co-located actor — or a file a
    /// rotator recreated under a foreign uid — fails the reopen
    /// exactly as it would have failed the launch.
    ///
    /// The writer emits the `marker` record in-band before replying —
    /// the new file's first record on success, an `outcome=failure`
    /// record on the surviving handle on error — so the operation's
    /// audit evidence is durable by the time the call resolves and can
    /// neither be overtaken by a queued record nor shed by a saturated
    /// channel. The request's bounded wait is its queue position — a
    /// saturated record stream slows the service, never the
    /// submission: control requests hold slots records cannot take.
    ///
    /// `Ok(true)` means the sink now appends to a freshly opened handle
    /// at the path. `Ok(false)` means this logger has no live file sink
    /// (a tracing sink, or one already shut down) — nothing was
    /// reopened and the marker factory is dropped unused. `Err` means
    /// the reopen failed or its marker could not be persisted;
    /// `writer_failed` latches either way, so a fail-closed session
    /// still aborts rather than silently append to a path the operator
    /// believes rotated — and whether records continue into the old
    /// handle or the just-swapped one depends on which step failed (a
    /// marker-persistence `Err` after a completed swap leaves the new
    /// handle live). When both fail, the reported error is the reopen's
    /// — it names why the path could not be re-opened.
    pub async fn reopen(&self, marker: ReopenMarker) -> Result<bool, crate::error::AuditorError> {
        if !self.inner.file_sink {
            return Ok(false);
        }
        let queued_at = std::time::Instant::now();
        // The control share of the queue — the request always finds
        // submission space ahead of its service, no matter how
        // saturated the record stream is. Acquired before the sender
        // check so a request parked here holds no sender clone that
        // would keep the channel — and a rotation — alive across a
        // shutdown.
        let slot = match self.inner.control_slots.clone().acquire_owned().await {
            Ok(s) => s,
            // The reserve closes only from `shutdown()` — a failed
            // acquire is a post-shutdown request finding no live
            // sink, not a writer fault.
            Err(_) => return Ok(false),
        };
        let (ack_tx, ack_rx) = tokio::sync::oneshot::channel();
        // The sender check and the enqueue run under the same lock
        // `shutdown()` takes the sender through: a shutdown that
        // already began means no live sink, so the request answers
        // `false` instead of queueing a rotation the drain would
        // service afterwards. `try_send` suffices — a request holding
        // its control permit always fits the queue's control share —
        // and keeps the check-and-enqueue atomic under the lock.
        let send = {
            let guard = self.inner.tx.lock().unwrap();
            match guard.as_ref() {
                Some(tx) => {
                    tx.try_send(WriterItem::Control(ControlRequest::Reopen(ReopenRequest {
                        reply: ack_tx,
                        marker,
                        queued_at,
                        slot,
                    })))
                }
                None => return Ok(false),
            }
        };
        match send {
            Ok(()) => {}
            // A control item holding its slot permit always fits the
            // queue's control share — unreachable while the accounting
            // holds; keep the latch parity with a closed channel
            // regardless.
            Err(mpsc::error::TrySendError::Full(_)) => {
                self.inner.writer_failed.set();
                return Err(crate::error::AuditorError::AuditUnavailable(
                    "audit queue full".into(),
                ));
            }
            // A dead writer can neither take the request nor hold the
            // sink — the same unavailability a closed record channel
            // reports.
            Err(mpsc::error::TrySendError::Closed(_)) => {
                self.inner.writer_failed.set();
                return Err(crate::error::AuditorError::AuditUnavailable(
                    "audit writer stopped".into(),
                ));
            }
        }
        match ack_rx.await {
            Ok(Ok(())) => Ok(true),
            Ok(Err(e)) => Err(crate::error::AuditorError::AuditUnavailable(format!(
                "audit reopen failed: {e}"
            ))),
            // A dropped reply sender means the writer died mid-reopen.
            Err(_) => {
                self.inner.writer_failed.set();
                Err(crate::error::AuditorError::AuditUnavailable(
                    "audit writer stopped before reopen".into(),
                ))
            }
        }
    }

    /// True when durable audit recording has failed.
    pub fn is_failed(&self) -> bool {
        self.inner.fail_closed && self.inner.writer_failed.get()
    }

    /// The raw writer-fault flag, without the `fail_closed` gate
    /// [`AuditLogger::is_failed`] applies. A best-effort logger still
    /// reports it: `guard.stopped` records this value so a log whose
    /// tail may be incomplete says so instead of implying completeness.
    pub fn writer_failed(&self) -> bool {
        self.inner.writer_failed.get()
    }

    /// True while this logger drives a live file sink — the only sink
    /// [`AuditLogger::reopen`] can act on. Signal plumbing checks this
    /// before registering a reopen handler so a tracing-only session
    /// keeps the signal's default disposition instead of binding a
    /// listener that can only no-op. `false` after `shutdown()`,
    /// matching `reopen()`'s no-live-sink result.
    pub fn has_file_sink(&self) -> bool {
        self.inner.file_sink && self.inner.tx.lock().unwrap().is_some()
    }

    /// Events dropped because the writer channel was full. A
    /// best-effort (fail-open) logger counts saturation here instead of
    /// failing — this counter is the only observable trace of it.
    pub fn dropped_count(&self) -> u64 {
        self.inner.dropped.load(Ordering::Relaxed)
    }

    /// Subscribe to writer-failure transitions. The receiver completes
    /// `changed()` on every `FailureFlag::set()` — including failures
    /// that happen while a relay is idle waiting on input — so a
    /// fail-closed session can abort mid-wait rather than discovering
    /// the dead sink only when the next record is attempted. Consumers
    /// must still re-check [`AuditLogger::is_failed`]: the flag is raw
    /// and ungated by `fail_closed`.
    pub fn failure_watch(&self) -> tokio::sync::watch::Receiver<bool> {
        self.inner.writer_failed.watch()
    }

    /// Fail-closed check for the proxy: returns an error when audit is required
    /// and unavailable.
    pub fn ensure_available(&self) -> Result<(), crate::error::AuditorError> {
        // `shutdown()` drops the sender without setting `writer_failed`,
        // so a clean shutdown leaves `is_failed` clear even though no
        // record can ever reach the sink again. For a fail-closed
        // logger a closed channel is just as unavailable — checking it
        // here keeps an enforcement gate from forwarding one unaudited
        // request before the next `log()` would set the flag.
        let channel_closed = self.inner.fail_closed && self.inner.tx.lock().unwrap().is_none();
        if self.is_failed() || channel_closed {
            Err(crate::error::AuditorError::AuditUnavailable(format!(
                "dropped={} writer_failed={} channel_closed={}",
                self.inner.dropped.load(Ordering::Relaxed),
                self.inner.writer_failed.get(),
                channel_closed,
            )))
        } else {
            Ok(())
        }
    }

    /// Gracefully shutdown the logger.
    /// Closes the channel and waits for the writer's end-of-life
    /// notice — for the file sink, the dedicated thread's drain,
    /// terminal sync, and handle release. In-flight OS I/O cannot be
    /// interrupted: the wait has no timeout, so a slow sink delays
    /// this call rather than being cut off and misreported.
    ///
    /// Returns `Err` when the terminal flush failed *and* this logger is
    /// fail-closed: the writer never reported its end-of-life notice
    /// (a dead thread's dropped completion sender, a join error on the
    /// tracing task) or `writer_failed` was latched anywhere in the
    /// sink's life (a
    /// write/sync fault, a dropped commit waiter, a saturated
    /// fail-closed channel). A best-effort sink reports `Ok` for the
    /// same state — its failures stay latched on `writer_failed` for
    /// observability but never convert the session's exit result.
    /// Callers must not pair a failed shutdown with a success result —
    /// the session's audit stream cannot be shown durable, so
    /// fail-closed run paths fold the error into the command's
    /// outcome/exit status.
    pub async fn shutdown(&self) -> Result<(), crate::error::AuditorError> {
        // The end state is locked ahead of the intake close so the
        // drain's start can be stamped in the same critical section
        // the sender is taken in — the writer measures `audit.drain.ns`
        // from that stamp, not from its own later `is_closed()`
        // observation which trails whatever in-flight write kept the
        // channel open.
        let mut end_lock = self.inner.writer_end.lock().await;
        // Drop the sender to close the queue — the shutdown request's
        // position in the same acceptance order: everything already
        // queued, records and control alike, is drained before the
        // writer's final durable commit. A post-shutdown `reopen()`
        // finds no live sink and never revives the writer.
        {
            let mut tx_lock = self.inner.tx.lock().unwrap();
            if tx_lock.is_some() {
                // The first close stamps the drain's start; a retried
                // shutdown finds no sender here and leaves the first
                // stamp untouched.
                #[cfg(feature = "measure")]
                if let Some(WriterEnd::Thread(spawn)) = end_lock.as_ref() {
                    spawn
                        .drain_started
                        .lock()
                        .unwrap()
                        .get_or_insert_with(std::time::Instant::now);
                }
                tx_lock.take();
            }
        }
        // Reopen calls parked on the control reserve wake to a failed
        // acquire — `reopen()` reports it as no live sink (`Ok(false)`),
        // the same answer the locked sender check gives requests that
        // already hold a permit.
        self.inner.control_slots.close();

        // Wait for the writer's end-of-life notice. The file writer's
        // oneshot resolves only after its drain, terminal sync, and
        // handle release — the async side awaits it rather than
        // joining the thread synchronously, so an uninterruptible
        // in-flight OS I/O is waited out, never cut off and reported.
        // A dropped sender is a dead writer: a fault, not a clean end.
        // The end state stays in the mutex while the wait runs —
        // cancelling this future leaves it for the next shutdown()
        // call to resume; only a completed wait removes it.
        let mut join_err = false;
        if let Some(end) = end_lock.as_mut() {
            match end {
                WriterEnd::Thread(spawn) => {
                    spawn.ticker.abort();
                    if (&mut spawn.done).await.is_err() {
                        self.inner.writer_failed.set();
                        join_err = true;
                        tracing::error!("Audit writer thread stopped before signaling completion");
                    }
                }
                WriterEnd::Task(handle) => {
                    if let Err(e) = handle.await {
                        self.inner.writer_failed.set();
                        join_err = true;
                        tracing::error!("Writer task join error: {e}");
                    }
                }
            }
            end_lock.take();
        }
        if self.inner.fail_closed && (self.inner.writer_failed.get() || join_err) {
            Err(crate::error::AuditorError::AuditUnavailable(format!(
                "audit shutdown failed (writer_failed={} join_error={})",
                self.inner.writer_failed.get(),
                join_err,
            )))
        } else {
            Ok(())
        }
    }
}

impl Drop for AuditLoggerInner {
    fn drop(&mut self) {
        // This means shutdown() was not called. Closing the intake is
        // the writer's stop request — the same "all senders gone"
        // queue-end position as shutdown(): the file-writer thread
        // drains the queue and exits on its own. In-flight OS I/O
        // cannot be interrupted, so the drain continues in the
        // background; anything still buffered if the process exits
        // first is lost.
        if let Ok(mut tx_lock) = self.tx.lock() {
            tx_lock.take();
        }
        // Wake every waiter the drain itself cannot reach: a reopen
        // parked on the control reserve resolves to "no live sink",
        // and producers parked on record slots or the byte budget
        // fail the acquire instead of hanging on a dead logger.
        self.control_slots.close();
        self.event_slots.close();
        self.bytes_budget.close();
        if let Ok(mut end_lock) = self.writer_end.try_lock()
            && let Some(end) = end_lock.take()
        {
            tracing::warn!(
                "AuditLogger dropped without shutdown(); \
                 the writer's drain continues on its own thread — \
                 buffered events may be lost if the process exits first. \
                 Call AuditLogger::shutdown().await for graceful flush."
            );
            self.writer_failed.set();
            match end {
                WriterEnd::Thread(spawn) => {
                    // The drop-side close is a drain start too — the
                    // same stamp `shutdown()` writes, skipped when one
                    // is already recorded.
                    #[cfg(feature = "measure")]
                    spawn
                        .drain_started
                        .lock()
                        .unwrap()
                        .get_or_insert_with(std::time::Instant::now);
                    spawn.ticker.abort();
                    // Detach, never join: the thread may be parked in
                    // an uninterruptible OS I/O, and a synchronous
                    // join inside a drop could stall a runtime worker.
                    drop(spawn.join);
                    drop(spawn.done);
                }
                // The tracing task has no drain contract — abort is
                // the same end the pre-thread writer had.
                WriterEnd::Task(handle) => handle.abort(),
            }
        }
    }
}
#[cfg(test)]
mod tests;
