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
use writer::{SinkAnchor, file_writer_task, tracing_writer_task};

// ═══════════════════════════════════════════════════════════════════════════════
// AuditLogger (mpsc channel + dedicated writer task)
// ═══════════════════════════════════════════════════════════════════════════════

const CHANNEL_CAPACITY: usize = 4096;
const BUF_WRITER_CAPACITY: usize = 65536; // 64KB
const FLUSH_EVENT_THRESHOLD: u32 = 100;

/// Aggregate byte ceiling for records sitting in the queue. The count
/// bound (`CHANNEL_CAPACITY`) alone cannot hold memory: each queued
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

/// One queued audit record. The oneshot half is set only by
/// [`AuditLogger::log_committed`]: the writer signals it after the
/// record is durably persisted — flushed through the `BufWriter` and
/// `sync_all`'d to storage — so a fail-closed path forwards protected
/// traffic only after the record exists on disk, not merely after the
/// queue accepted it. The semaphore permit pins the record's byte
/// share of [`QUEUE_BYTE_BUDGET`] until the writer consumes it —
/// dropping the item releases the budget.
type AuditItem = (
    AuditEvent,
    Option<tokio::sync::oneshot::Sender<()>>,
    Option<tokio::sync::OwnedSemaphorePermit>,
);

/// Builds the `audit.reopened` record inside the writer task — the
/// argument is `Some(error)` on a failed reopen and `None` on success,
/// so the same factory produces both the success and the failure
/// marker. Running it in-band keeps the marker ahead of every
/// concurrently queued record and out of the bounded channel's drop
/// accounting entirely.
pub type ReopenMarker = Box<dyn FnOnce(Option<String>) -> AuditEvent + Send>;

/// A reopen request pairs the oneshot its result is reported through
/// with the rotation-marker factory: the writer flushes + fsyncs the
/// live sink, re-resolves the audit path through `open_audit_sink`,
/// swaps handles, and records the marker before acknowledging. The
/// queue is deliberately tiny: a pending request already holds the
/// whole reopen intent — coalescing further signals would produce the
/// same single flush+open sequence.
const REOPEN_QUEUE_CAPACITY: usize = 4;
struct ReopenRequest {
    reply: tokio::sync::oneshot::Sender<std::io::Result<()>>,
    marker: ReopenMarker,
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

struct AuditLoggerInner {
    tx: std::sync::Mutex<Option<mpsc::Sender<AuditItem>>>,
    /// Reopen channel into the file writer — `None` for a non-file
    /// sink, and taken on `shutdown()` like `tx` so a post-shutdown
    /// [`AuditLogger::reopen`] finds no live sink.
    reopen_tx: std::sync::Mutex<Option<mpsc::Sender<ReopenRequest>>>,
    session_id: String,
    writer_handle: tokio::sync::Mutex<Option<tokio::task::JoinHandle<()>>>,
    fail_closed: bool,
    dropped: AtomicU64,
    writer_failed: FailureFlag,
    /// Byte-level queue bound — one permit per queued wire byte. Held
    /// inside the `AuditItem`, so the writer consuming a record frees
    /// its share automatically.
    bytes_budget: std::sync::Arc<tokio::sync::Semaphore>,
}

impl AuditLogger {
    /// Create a logger that appends JSONL to a file.
    /// Spawns a dedicated writer task on the tokio runtime.
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
        let (tx, rx) = mpsc::channel(CHANNEL_CAPACITY);
        let (reopen_tx, reopen_rx) = mpsc::channel(REOPEN_QUEUE_CAPACITY);
        let session_id = generate_session_id();
        let writer_failed = FailureFlag::new();
        let writer_handle = tokio::spawn(file_writer_task(
            rx,
            writer,
            writer_failed.clone(),
            SinkAnchor { dir, leaf },
            sync_mode,
            path.to_path_buf(),
            reopen_rx,
        ));
        Ok(Self {
            inner: std::sync::Arc::new(AuditLoggerInner {
                tx: std::sync::Mutex::new(Some(tx)),
                reopen_tx: std::sync::Mutex::new(Some(reopen_tx)),
                session_id,
                writer_handle: tokio::sync::Mutex::new(Some(writer_handle)),
                fail_closed,
                dropped: AtomicU64::new(0),
                writer_failed,
                bytes_budget: std::sync::Arc::new(tokio::sync::Semaphore::new(QUEUE_BYTE_BUDGET)),
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
        let (tx, rx) = mpsc::channel(CHANNEL_CAPACITY);
        let session_id = generate_session_id();
        let writer_failed = FailureFlag::new();
        // stderr delivery cannot prove a durable write — a fail-closed
        // logger's completion waiters must not be acknowledged here.
        let writer_handle = tokio::spawn(tracing_writer_task(rx, !fail_closed));
        Self {
            inner: std::sync::Arc::new(AuditLoggerInner {
                tx: std::sync::Mutex::new(Some(tx)),
                reopen_tx: std::sync::Mutex::new(None),
                session_id,
                writer_handle: tokio::sync::Mutex::new(Some(writer_handle)),
                fail_closed,
                dropped: AtomicU64::new(0),
                writer_failed,
                bytes_budget: std::sync::Arc::new(tokio::sync::Semaphore::new(QUEUE_BYTE_BUDGET)),
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
    /// can always proceed once the queue drains.
    fn prepare(event: &mut AuditEvent) -> u32 {
        event.bound_wire_fields();
        event.wire_size().min(QUEUE_BYTE_BUDGET) as u32
    }

    /// Log an audit event. Non-blocking.
    ///
    /// When `fail_closed` is set, a full or closed channel — or an
    /// exhausted byte budget — marks the logger unavailable instead of
    /// silently discarding the event.
    pub fn log(&self, mut event: AuditEvent) {
        let need = Self::prepare(&mut event);
        let permit = match self.inner.bytes_budget.clone().try_acquire_many_owned(need) {
            Ok(p) => Some(p),
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
        let tx_opt = self.inner.tx.lock().unwrap();
        if let Some(tx) = tx_opt.as_ref() {
            if let Err(e) = tx.try_send((event, None, permit)) {
                match e {
                    mpsc::error::TrySendError::Full((evt, _, _)) => {
                        self.inner.dropped.fetch_add(1, Ordering::Relaxed);
                        // Saturation is a counted drop in best-effort
                        // mode — the writer itself is still healthy, so
                        // only a fail-closed session treats a full
                        // channel as a writer fault.
                        if self.inner.fail_closed {
                            self.inner.writer_failed.set();
                        }
                        tracing::error!(
                            event_type = evt.event_type.as_str(),
                            fail_closed = self.inner.fail_closed,
                            "Audit log channel full"
                        );
                    }
                    mpsc::error::TrySendError::Closed((evt, _, _)) => {
                        self.inner.writer_failed.set();
                        tracing::error!(
                            event_type = evt.event_type.as_str(),
                            "Audit log channel closed"
                        );
                    }
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
        let need = Self::prepare(&mut event);
        // Bounded backpressure: wait for byte budget before queueing —
        // saturation slows the producer instead of dropping the record.
        let permit = match self
            .inner
            .bytes_budget
            .clone()
            .acquire_many_owned(need)
            .await
        {
            Ok(p) => Some(p),
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
                if tx.send((event, None, permit)).await.is_err() {
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
        let need = Self::prepare(&mut event);
        let permit = match self
            .inner
            .bytes_budget
            .clone()
            .acquire_many_owned(need)
            .await
        {
            Ok(p) => Some(p),
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
                if tx.send((event, Some(ack_tx), permit)).await.is_err() {
                    self.inner.writer_failed.set();
                    return Err(crate::error::AuditorError::AuditUnavailable(
                        "audit log channel closed".into(),
                    ));
                }
                // A dropped sender (writer task dead) fails the wait —
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
    /// writer drains every record already queued to the *old* file
    /// first (the channel arm is polled ahead of the reopen arm), then
    /// flushes and fsyncs it before the handle is swapped; the path is
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
    /// channel.
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
        let tx = self.inner.reopen_tx.lock().unwrap().clone();
        let Some(tx) = tx else { return Ok(false) };
        let (ack_tx, ack_rx) = tokio::sync::oneshot::channel();
        // A dead writer can neither take the request nor hold the sink
        // — the same unavailability a closed record channel reports.
        if tx
            .send(ReopenRequest {
                reply: ack_tx,
                marker,
            })
            .await
            .is_err()
        {
            self.inner.writer_failed.set();
            return Err(crate::error::AuditorError::AuditUnavailable(
                "audit writer stopped".into(),
            ));
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
        self.inner.reopen_tx.lock().unwrap().is_some()
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
    /// Closes the channel and waits for the writer task to complete.
    ///
    /// Returns `Err` when the terminal flush failed *and* this logger is
    /// fail-closed: the writer task did not join cleanly or
    /// `writer_failed` was latched anywhere in the sink's life (a
    /// write/sync fault, a dropped commit waiter, a saturated
    /// fail-closed channel). A best-effort sink reports `Ok` for the
    /// same state — its failures stay latched on `writer_failed` for
    /// observability but never convert the session's exit result.
    /// Callers must not pair a failed shutdown with a success result —
    /// the session's audit stream cannot be shown durable, so
    /// fail-closed run paths fold the error into the command's
    /// outcome/exit status.
    pub async fn shutdown(&self) -> Result<(), crate::error::AuditorError> {
        // Drop the sender to close the channel, signaling the writer task to flush and exit
        {
            let mut tx_lock = self.inner.tx.lock().unwrap();
            tx_lock.take();
        }
        // The reopen channel closes with it — a post-shutdown
        // `reopen()` must find no live sink, never revive the writer.
        {
            let mut reopen_lock = self.inner.reopen_tx.lock().unwrap();
            reopen_lock.take();
        }

        // Wait for the writer task to complete
        let mut join_err = false;
        let mut handle_lock = self.inner.writer_handle.lock().await;
        if let Some(handle) = handle_lock.take()
            && let Err(e) = handle.await
        {
            self.inner.writer_failed.set();
            join_err = true;
            tracing::error!("Writer task join error: {e}");
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
        // Abort the writer task if it's still running.
        // This means shutdown() was not called — buffered events may be lost.
        if let Ok(mut handle_lock) = self.writer_handle.try_lock()
            && let Some(handle) = handle_lock.take()
        {
            tracing::warn!(
                "AuditLogger dropped without shutdown(); \
                 aborting writer task — buffered events may be lost. \
                 Call AuditLogger::shutdown().await for graceful flush."
            );
            self.writer_failed.set();
            handle.abort();
        }
    }
}
#[cfg(test)]
mod tests;
