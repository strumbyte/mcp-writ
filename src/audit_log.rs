use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use tokio::sync::mpsc;

mod emit;
mod event;

use emit::generate_session_id;
pub use emit::{now_iso8601, now_iso8601_millis, write_event_jsonl};
pub use event::{
    AUDIT_SCHEMA_VERSION, Action, AuditEvent, EmbeddedJson, EventType, Outcome, PolicyAuditContext,
    Severity,
};

// ═══════════════════════════════════════════════════════════════════════════════
// AuditLogger (mpsc channel + dedicated writer task)
// ═══════════════════════════════════════════════════════════════════════════════

const CHANNEL_CAPACITY: usize = 4096;
const BUF_WRITER_CAPACITY: usize = 65536; // 64KB
const FLUSH_EVENT_THRESHOLD: u32 = 100;

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
/// queue accepted it.
type AuditItem = (AuditEvent, Option<tokio::sync::oneshot::Sender<()>>);

#[derive(Clone)]
pub struct AuditLogger {
    inner: std::sync::Arc<AuditLoggerInner>,
}

struct AuditLoggerInner {
    tx: std::sync::Mutex<Option<mpsc::Sender<AuditItem>>>,
    session_id: String,
    writer_handle: tokio::sync::Mutex<Option<tokio::task::JoinHandle<()>>>,
    fail_closed: bool,
    dropped: AtomicU64,
    writer_failed: std::sync::Arc<AtomicBool>,
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
        // A file this call creates has no durable directory entry yet —
        // the writer must fsync the parent before its first completion
        // notification or a crash could lose the whole log.
        let file_was_new = !path.exists();
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)?;
        let writer = std::io::BufWriter::with_capacity(BUF_WRITER_CAPACITY, file);
        let (tx, rx) = mpsc::channel(CHANNEL_CAPACITY);
        let session_id = generate_session_id();
        let writer_failed = std::sync::Arc::new(AtomicBool::new(false));
        // A bare filename has parent "" — syncing "" fails or lands on
        // the wrong entry, so the empty parent means the current dir.
        let new_file_dir = file_was_new.then(|| match path.parent() {
            Some(parent) if !parent.as_os_str().is_empty() => parent.to_path_buf(),
            _ => Path::new(".").into(),
        });
        let writer_handle = tokio::spawn(file_writer_task(
            rx,
            writer,
            writer_failed.clone(),
            new_file_dir,
            sync_mode,
        ));
        Ok(Self {
            inner: std::sync::Arc::new(AuditLoggerInner {
                tx: std::sync::Mutex::new(Some(tx)),
                session_id,
                writer_handle: tokio::sync::Mutex::new(Some(writer_handle)),
                fail_closed,
                dropped: AtomicU64::new(0),
                writer_failed,
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
        let writer_failed = std::sync::Arc::new(AtomicBool::new(false));
        // stderr delivery cannot prove a durable write — a fail-closed
        // logger's completion waiters must not be acknowledged here.
        let writer_handle = tokio::spawn(tracing_writer_task(rx, !fail_closed));
        Self {
            inner: std::sync::Arc::new(AuditLoggerInner {
                tx: std::sync::Mutex::new(Some(tx)),
                session_id,
                writer_handle: tokio::sync::Mutex::new(Some(writer_handle)),
                fail_closed,
                dropped: AtomicU64::new(0),
                writer_failed,
            }),
        }
    }

    /// Get the session ID for this logger instance.
    pub fn session_id(&self) -> &str {
        &self.inner.session_id
    }

    /// Log an audit event. Non-blocking.
    ///
    /// When `fail_closed` is set, a full or closed channel marks the logger
    /// unavailable instead of silently discarding the event.
    pub fn log(&self, event: AuditEvent) {
        let tx_opt = self.inner.tx.lock().unwrap();
        if let Some(tx) = tx_opt.as_ref() {
            if let Err(e) = tx.try_send((event, None)) {
                match e {
                    mpsc::error::TrySendError::Full((evt, _)) => {
                        self.inner.dropped.fetch_add(1, Ordering::Relaxed);
                        // Saturation is a counted drop in best-effort
                        // mode — the writer itself is still healthy, so
                        // only a fail-closed session treats a full
                        // channel as a writer fault.
                        if self.inner.fail_closed {
                            self.inner.writer_failed.store(true, Ordering::SeqCst);
                        }
                        tracing::error!(
                            event_type = evt.event_type.as_str(),
                            fail_closed = self.inner.fail_closed,
                            "Audit log channel full"
                        );
                    }
                    mpsc::error::TrySendError::Closed((evt, _)) => {
                        self.inner.writer_failed.store(true, Ordering::SeqCst);
                        tracing::error!(
                            event_type = evt.event_type.as_str(),
                            "Audit log channel closed"
                        );
                    }
                }
            }
        } else {
            self.inner.writer_failed.store(true, Ordering::SeqCst);
            tracing::error!(
                event_type = event.event_type.as_str(),
                "Audit log channel unavailable after shutdown"
            );
        }
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
    pub async fn log_committed(&self, event: AuditEvent) -> Result<(), crate::error::AuditorError> {
        if !self.inner.fail_closed {
            self.log(event);
            return self.ensure_available();
        }
        let tx = {
            let guard = self.inner.tx.lock().unwrap();
            guard.as_ref().cloned()
        };
        match tx {
            Some(tx) => {
                let (ack_tx, ack_rx) = tokio::sync::oneshot::channel();
                if tx.send((event, Some(ack_tx))).await.is_err() {
                    self.inner.writer_failed.store(true, Ordering::SeqCst);
                    return Err(crate::error::AuditorError::AuditUnavailable(
                        "audit log channel closed".into(),
                    ));
                }
                // A dropped sender (writer task dead) fails the wait —
                // fail closed rather than forward unaudited traffic.
                if ack_rx.await.is_err() {
                    self.inner.writer_failed.store(true, Ordering::SeqCst);
                    return Err(crate::error::AuditorError::AuditUnavailable(
                        "audit writer stopped before durable write".into(),
                    ));
                }
            }
            None => {
                self.inner.writer_failed.store(true, Ordering::SeqCst);
                return Err(crate::error::AuditorError::AuditUnavailable(
                    "audit log channel unavailable".into(),
                ));
            }
        }
        self.ensure_available()
    }

    /// True when durable audit recording has failed.
    pub fn is_failed(&self) -> bool {
        self.inner.fail_closed && self.inner.writer_failed.load(Ordering::SeqCst)
    }

    /// The raw writer-fault flag, without the `fail_closed` gate
    /// [`AuditLogger::is_failed`] applies. A best-effort logger still
    /// reports it: `guard.stopped` records this value so a log whose
    /// tail may be incomplete says so instead of implying completeness.
    pub fn writer_failed(&self) -> bool {
        self.inner.writer_failed.load(Ordering::SeqCst)
    }

    /// Events dropped because the writer channel was full. A
    /// best-effort (fail-open) logger counts saturation here instead of
    /// failing — this counter is the only observable trace of it.
    pub fn dropped_count(&self) -> u64 {
        self.inner.dropped.load(Ordering::Relaxed)
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
                self.inner.writer_failed.load(Ordering::SeqCst),
                channel_closed,
            )))
        } else {
            Ok(())
        }
    }

    /// Gracefully shutdown the logger.
    /// Closes the channel and waits for the writer task to complete.
    pub async fn shutdown(&self) {
        // Drop the sender to close the channel, signaling the writer task to flush and exit
        {
            let mut tx_lock = self.inner.tx.lock().unwrap();
            tx_lock.take();
        }

        // Wait for the writer task to complete
        let mut handle_lock = self.inner.writer_handle.lock().await;
        if let Some(handle) = handle_lock.take()
            && let Err(e) = handle.await
        {
            tracing::error!("Writer task join error: {e}");
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
            self.writer_failed.store(true, Ordering::SeqCst);
            handle.abort();
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Writer Tasks
// ═══════════════════════════════════════════════════════════════════════════════

/// fsync the directory holding a freshly created log file — the file's
/// own `sync_all` commits its data but not the directory entry naming
/// it, so a crash between create and commit could lose the whole file.
/// `None` (an existing file) needs no directory sync: its entry is
/// already durable.
#[cfg(unix)]
fn sync_audit_dir(dir: Option<&Path>) -> std::io::Result<()> {
    let Some(dir) = dir else { return Ok(()) };
    std::fs::File::open(dir)?.sync_all()
}

/// Windows has no directory-fsync primitive — `FlushFileBuffers`
/// rejects directory handles. NTFS journals directory entries in
/// `$LogFile` and commits them through the file's own flush, so the
/// `sync_all` on the log file above is the durability boundary.
#[cfg(not(unix))]
fn sync_audit_dir(_dir: Option<&Path>) -> std::io::Result<()> {
    Ok(())
}

async fn file_writer_task(
    mut rx: mpsc::Receiver<AuditItem>,
    mut writer: std::io::BufWriter<std::fs::File>,
    writer_failed: std::sync::Arc<AtomicBool>,
    new_file_dir: Option<PathBuf>,
    sync_mode: AuditSyncMode,
) {
    // Only a newly created file needs its directory entry fsynced —
    // once, before the first completion notification.
    let mut dir_synced = new_file_dir.is_none();
    let mut events_since_flush: u32 = 0;
    let mut flush_interval = tokio::time::interval(std::time::Duration::from_secs(1));
    let mut fsync_interval = tokio::time::interval(std::time::Duration::from_secs(5));

    // Consume initial ticks (tokio intervals fire immediately on first tick)
    flush_interval.tick().await;
    fsync_interval.tick().await;

    loop {
        tokio::select! {
            biased;

            event = rx.recv() => {
                match event {
                    Some((evt, ack)) => {
                        // A record skips the buffered tail when a caller
                        // waits on its durability (the fail-closed ack),
                        // when `--audit-sync` syncs every record, or when
                        // its severity reaches IMMEDIATE_SYNC_SEVERITY —
                        // a denial or failure is exactly the evidence a
                        // forced kill most wants to shed.
                        let must_sync = ack.is_some()
                            || matches!(sync_mode, AuditSyncMode::EveryEvent)
                            || evt.severity >= IMMEDIATE_SYNC_SEVERITY;
                        let json = write_event_jsonl(&evt);
                        // A failed write gates the durable path below:
                        // the record may never have reached the buffer,
                        // so a later successful flush must not be
                        // reported as its ack.
                        let mut ok = true;
                        if let Err(e) = writeln!(writer, "{}", json) {
                            tracing::error!("Audit log write failed: {e}");
                            writer_failed.store(true, Ordering::SeqCst);
                            ok = false;
                        }
                        events_since_flush += 1;

                        if must_sync {
                            // The durable path: flush the buffer, fsync
                            // the file, then — for a freshly created log
                            // — fsync the parent so the directory entry
                            // survives a crash too.
                            if let Err(e) = writer.flush() {
                                tracing::error!("Audit log sync flush failed: {e}");
                                writer_failed.store(true, Ordering::SeqCst);
                                ok = false;
                            }
                            events_since_flush = 0;
                            if ok && let Err(e) = writer.get_ref().sync_all() {
                                tracing::error!("Audit log sync fsync failed: {e}");
                                writer_failed.store(true, Ordering::SeqCst);
                                ok = false;
                            }
                            // The record is durable only once the parent
                            // directory entry is too — a failure is an
                            // audit error, not an ack.
                            if ok && !dir_synced {
                                match sync_audit_dir(new_file_dir.as_deref()) {
                                    Ok(()) => dir_synced = true,
                                    Err(e) => {
                                        tracing::error!(
                                            "Audit log directory sync failed: {e}"
                                        );
                                        writer_failed.store(true, Ordering::SeqCst);
                                        ok = false;
                                    }
                                }
                            }
                            // A dropped receiver is the ack for failure —
                            // never signal success on a failed write.
                            if ok && let Some(ack) = ack {
                                let _ = ack.send(());
                            }
                        } else if events_since_flush >= FLUSH_EVENT_THRESHOLD {
                            if let Err(e) = writer.flush() {
                                tracing::error!("Audit log flush failed: {e}");
                                writer_failed.store(true, Ordering::SeqCst);
                            }
                            events_since_flush = 0;
                        }
                    }
                    None => {
                        if let Err(e) = writer.flush() {
                            tracing::error!("Audit log final flush failed: {e}");
                            writer_failed.store(true, Ordering::SeqCst);
                        }
                        if let Err(e) = writer.get_ref().sync_all() {
                            tracing::error!("Audit log final sync failed: {e}");
                            writer_failed.store(true, Ordering::SeqCst);
                        }
                        if !dir_synced
                            && let Err(e) = sync_audit_dir(new_file_dir.as_deref())
                        {
                            tracing::error!("Audit log directory sync failed: {e}");
                            writer_failed.store(true, Ordering::SeqCst);
                        }
                        return;
                    }
                }
            }
            _ = flush_interval.tick() => {
                if events_since_flush > 0 {
                    if let Err(e) = writer.flush() {
                        tracing::error!("Audit log periodic flush failed: {e}");
                        writer_failed.store(true, Ordering::SeqCst);
                    }
                    events_since_flush = 0;
                }
            }
            _ = fsync_interval.tick() => {
                if let Err(e) = writer.get_ref().sync_all() {
                    tracing::error!("Audit log fsync failed: {e}");
                    writer_failed.store(true, Ordering::SeqCst);
                }
                if !dir_synced {
                    match sync_audit_dir(new_file_dir.as_deref()) {
                        Ok(()) => dir_synced = true,
                        Err(e) => {
                            tracing::error!("Audit log directory sync failed: {e}");
                            writer_failed.store(true, Ordering::SeqCst);
                        }
                    }
                }
            }
        }
    }
}

async fn tracing_writer_task(mut rx: mpsc::Receiver<AuditItem>, sink_durable: bool) {
    while let Some((evt, ack)) = rx.recv().await {
        let json = write_event_jsonl(&evt);
        match evt.severity {
            Severity::Critical | Severity::High => {
                tracing::error!(target: "audit", "{}", json);
            }
            Severity::Medium => {
                tracing::warn!(target: "audit", "{}", json);
            }
            Severity::Low | Severity::Info => {
                tracing::info!(target: "audit", "{}", json);
            }
        }
        // stderr delivery is no durability proof — a fail-closed sink
        // (`sink_durable == false`) drops the completion instead of
        // acknowledging it, so the waiter fails closed.
        if sink_durable && let Some(ack) = ack {
            let _ = ack.send(());
        }
    }
}

#[cfg(test)]
mod tests;
