//! The dedicated writer behind [`AuditLogger`](super::AuditLogger).
//!
//! ## Ordering and fairness
//!
//! One bounded queue carries records *and* control requests, so a
//! single FIFO fixes the acceptance order of both — no second channel
//! exists whose arm order could reorder them. A control item's queue
//! position is an ordering barrier: every record dequeued ahead of it
//! is committed to the sink generation live at the barrier — for a
//! reopen, the old file — and every record behind it lands on the next
//! generation after the rotation marker. Channel close (all senders
//! dropped) is the shutdown request's position in the same order: the
//! writer drains what is queued, then performs its final durable
//! commit.
//!
//! Records occupy `EVENT_QUEUE_CAPACITY` slots of the queue; control
//! requests hold `CONTROL_QUEUE_CAPACITY` slots of their own — a
//! saturated record stream can never starve a control request of
//! submission space. A producer cancelled or refused while waiting
//! leaves no hole in the order: items enter the queue only through a
//! completed send, and the permits riding in each item release on
//! drop.
//!
//! ## Dedicated thread
//!
//! The file writer owns its sink, buffer, and deadlines on a single
//! dedicated OS thread — never a per-event thread or blocking task —
//! so synchronous writes and `sync_all` cannot occupy a runtime
//! worker and stall audit-unrelated tasks. The thread drains the same
//! queue through `blocking_recv`: admission order, bounded
//! backpressure, and permit release are exactly the async driver's
//! semantics, because the queue itself is unchanged. Completion is a
//! oneshot notice the async side awaits — never a synchronous thread
//! join on a runtime worker.
//!
//! ## Periodic sync
//!
//! The periodic flush/fsync deadlines are serviced inside the item
//! path, not by receiver-side waits that only run while the queue is
//! idle: after every [`CLOCK_CHECK_RECORDS`] processed records — and
//! after each control item — the writer consults its [`AuditClock`]
//! and runs whatever deadlines have passed. Starting a sync is
//! therefore never conditioned on the queue draining — under
//! sustained input the next bounded processing boundary is at most
//! `CLOCK_CHECK_RECORDS` writes away. The idle wake is the only piece
//! that cannot live on the blocking thread — `blocking_recv` has no
//! deadline — so a lightweight *ticker* task on the runtime armed on
//! the writer's posted earliest deadline lands a
//! [`WriterItem::Tick`] in the same queue when the instant passes.
//! The tick carries no payload and occupies a small headroom reserve
//! above the permit-accounted capacity, so it can never bounce a
//! permit-holding send; a dropped tick costs nothing because a busy
//! queue services deadlines at its own boundaries.
//!
//! The sink ([`AuditSink`]) and the clock are injected traits: the
//! production pairing is `BufWriter<File>` plus [`TokioClock`];
//! regression tests drive a scripted sink and a manual clock so
//! sustained input, saturation, multiple rotations and mid-rotation
//! shutdown are deterministic — the same fixtures the async driver
//! ran under now run on the dedicated thread unchanged.

use std::future::Future;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use tokio::sync::mpsc;

use super::{
    AuditItem, AuditSyncMode, BUF_WRITER_CAPACITY, ControlRequest, FLUSH_EVENT_THRESHOLD,
    FailureFlag, IMMEDIATE_SYNC_SEVERITY, ReopenRequest, Severity, WriterItem, sink_open,
    write_event_jsonl,
};

/// Periodic `BufWriter` flush cadence — the 1 s period the old
/// `tokio::time::interval` arm ran on.
pub(super) const FLUSH_PERIOD: Duration = Duration::from_secs(1);

/// Periodic `fsync` cadence — the 5 s period the old interval arm ran
/// on. Missed periods are settled individually (the Burst semantics
/// this replaces), never collapsed.
pub(super) const FSYNC_PERIOD: Duration = Duration::from_secs(5);

/// The bounded processing chunk: the writer consults its clock after
/// this many processed records, so a passed deadline is serviced at
/// the next processing boundary instead of whenever the receive queue
/// happens to empty. This constant *is* the fairness bound on
/// sync-start delay under sustained input — at most this many
/// records' write time past the deadline.
pub(super) const CLOCK_CHECK_RECORDS: u32 = 32;

/// The deadline source for the periodic flush/fsync schedule. The
/// production clock is [`TokioClock`]; tests drive a manual clock so a
/// deadline's passing is a deliberate test action, never a wall-clock
/// wait — and the writer core stays usable on a blocking driver where
/// `tokio::time` does not exist.
pub(super) trait AuditClock: Clone + Send + 'static {
    /// The clock's current instant. Only ordering matters — deadlines
    /// are taken from and compared against this clock alone.
    fn now(&self) -> Instant;
    /// A future that resolves once `deadline` is reached on this
    /// clock. Must resolve immediately when `deadline <= now()` — the
    /// idle arm relies on it for punctual service; the busy path does
    /// not rely on it at all.
    fn sleep_until(&self, deadline: Instant) -> Pin<Box<dyn Future<Output = ()> + Send>>;
}

/// The runtime clock: `Instant::now()` for `now`, a tokio sleep for
/// the idle wake. Deadline arithmetic stays in `std::time` so
/// non-tokio clocks compare correctly.
#[derive(Clone)]
pub(super) struct TokioClock;

impl AuditClock for TokioClock {
    fn now(&self) -> Instant {
        Instant::now()
    }

    fn sleep_until(&self, deadline: Instant) -> Pin<Box<dyn Future<Output = ()> + Send>> {
        Box::pin(tokio::time::sleep_until(tokio::time::Instant::from_std(
            deadline,
        )))
    }
}

/// The writable end of the audit stream: one ordered record at a
/// time, a buffer-boundary push, a durable sync, the parent-entry
/// fsync a freshly created file's name needs once, the visible-entry
/// proof, and the rotation swap. [`FileSink`] implements it over
/// `BufWriter<File>`; tests implement it over a scripted op log.
///
/// `reopen` owns the whole rotation sequence — the pre-swap durable
/// commit of the old generation through the handle swap and the new
/// generation's entry sync — because only the sink knows which steps
/// its medium needs. An `Err` after a partial swap is reported while
/// the sink remains on the new generation: the writer distinguishes
/// "rotation refused" from "post-swap sync failed" purely by which
/// side effects already happened.
pub(super) trait AuditSink: Send {
    /// Append one serialized record — the trailing newline included.
    fn write_record(&mut self, line: &[u8]) -> std::io::Result<()>;
    /// Push the buffered tail across the OS boundary.
    fn flush_buffer(&mut self) -> std::io::Result<()>;
    /// Durably commit what was pushed — the file's own `sync_all`.
    fn sync_file(&mut self) -> std::io::Result<()>;
    /// `true` while the current generation's directory entry still
    /// needs its one-time durability fsync.
    fn needs_dir_sync(&self) -> bool;
    /// The one-time parent-directory fsync that makes a freshly
    /// created file's name durable.
    fn sync_dir(&mut self) -> std::io::Result<()>;
    /// The sink's directory entry still names the open object — a
    /// committed record behind a swapped-out entry is hidden from the
    /// reader the operator named, so `false` is an audit fault.
    fn entry_visible(&self, path: &Path) -> bool;
    /// Rotate: commit the current generation durably, swap to a
    /// freshly opened handle at `path`, make the new generation's
    /// entry durable. See the type docs for partial-failure
    /// semantics.
    fn reopen(&mut self, path: &Path) -> std::io::Result<()>;
}

/// fsync the directory handle a freshly created log's entry lives in —
/// the file's own `sync_all` commits its data but not the directory
/// entry naming it, so a crash between create and commit could lose
/// the whole file. `None` means either a pre-existing file (its entry
/// is already durable) or a platform with no directory-fsync boundary —
/// Windows commits the entry through the file's own flush, so the
/// sink open hands no handle over.
fn sync_audit_dir(dir: Option<&std::fs::File>) -> std::io::Result<()> {
    let Some(dir) = dir else { return Ok(()) };
    dir.sync_all()
}

/// `file.sync_all()` with the `measure` feature's count / duration
/// sampling — plain `sync_all` when the feature is off.
fn file_sync_all(file: &std::fs::File) -> std::io::Result<()> {
    #[cfg(feature = "measure")]
    {
        let now = std::time::Instant::now();
        crate::measure::incr(&crate::measure::AUDIT_SYNC_COUNT, 1);
        let result = file.sync_all();
        crate::measure::observe(
            &crate::measure::AUDIT_SYNC_NS,
            now.elapsed().as_nanos().min(u64::MAX as u128) as u64,
        );
        result
    }
    #[cfg(not(feature = "measure"))]
    file.sync_all()
}

/// `writer.flush()` with the `measure` feature's count / duration
/// sampling — plain `flush` when the feature is off.
fn buf_flush(writer: &mut std::io::BufWriter<std::fs::File>) -> std::io::Result<()> {
    #[cfg(feature = "measure")]
    {
        crate::measure::incr(&crate::measure::AUDIT_FLUSH_COUNT, 1);
        let start = std::time::Instant::now();
        let result = writer.flush();
        crate::measure::observe(
            &crate::measure::AUDIT_FLUSH_NS,
            start.elapsed().as_nanos().min(u64::MAX as u128) as u64,
        );
        result
    }
    #[cfg(not(feature = "measure"))]
    writer.flush()
}

/// The pinned parent handle + leaf name the sink's visible-entry
/// proof re-resolves under — carried alongside the writer so commit
/// acknowledgments and shutdown can still verify the entry names the
/// opened object, and the parent stays live for entry fsyncs.
pub(super) struct SinkAnchor {
    pub(super) dir: Option<std::fs::File>,
    pub(super) leaf: Option<std::ffi::OsString>,
}

/// The production [`AuditSink`]: `BufWriter<File>` plus the pinned
/// parent handle + leaf name its visible-entry proof re-resolves
/// under, and the flag tracking whether the current generation's
/// directory entry ever got its one-time durability fsync.
pub(super) struct FileSink {
    writer: std::io::BufWriter<std::fs::File>,
    anchor: SinkAnchor,
    dir_synced: bool,
}

impl FileSink {
    /// The parent handle is retained for every open so the entry can
    /// be re-verified at commit-ack time; its fsync runs once before
    /// the first completion notification — required for a freshly
    /// created file's entry, redundant for a durable existing one.
    /// `None` (Windows, which carries no parent capability) counts as
    /// synced.
    pub(super) fn new(writer: std::io::BufWriter<std::fs::File>, anchor: SinkAnchor) -> Self {
        let dir_synced = anchor.dir.is_none();
        Self {
            writer,
            anchor,
            dir_synced,
        }
    }
}

impl AuditSink for FileSink {
    fn write_record(&mut self, line: &[u8]) -> std::io::Result<()> {
        self.writer.write_all(line)
    }

    fn flush_buffer(&mut self) -> std::io::Result<()> {
        buf_flush(&mut self.writer)
    }

    fn sync_file(&mut self) -> std::io::Result<()> {
        file_sync_all(self.writer.get_ref())
    }

    fn needs_dir_sync(&self) -> bool {
        !self.dir_synced
    }

    fn sync_dir(&mut self) -> std::io::Result<()> {
        match sync_audit_dir(self.anchor.dir.as_ref()) {
            Ok(()) => {
                self.dir_synced = true;
                Ok(())
            }
            Err(e) => Err(e),
        }
    }

    fn entry_visible(&self, path: &Path) -> bool {
        match sink_open::entry_names_opened_file(
            self.anchor.dir.as_ref(),
            path,
            self.anchor.leaf.as_deref(),
            self.writer.get_ref(),
        ) {
            Ok(visible) => visible,
            Err(e) => {
                tracing::error!("Audit log entry verification failed: {e}");
                false
            }
        }
    }

    /// The reopen sequence behind signal-driven rotation: the
    /// buffered tail must be durable in the *old* file before the
    /// handle is swapped, so the flush and fsync run while `writer`
    /// still names the previous object. The path is then re-opened
    /// through the same trust-boundary `open_audit_sink` the launch
    /// used — a link planted since launch, a non-regular leaf, or a
    /// file a rotator recreated under another uid fails the reopen
    /// exactly as it would have failed the launch. The swap itself
    /// happens as soon as the new handle is verified — a failed
    /// directory-entry fsync afterwards still reports `Err`, but
    /// records keep reaching the correctly named file.
    fn reopen(&mut self, path: &Path) -> std::io::Result<()> {
        self.flush_buffer()?;
        // Each sync error carries the phase it failed in: a pre-swap
        // fsync refusal and a post-swap entry-sync failure both report
        // `Err` but leave different generations live — the tag lets
        // the caller, and the in-band failure marker that embeds this
        // message, tell which side of the swap failed.
        self.sync_file()
            .map_err(|e| std::io::Error::new(e.kind(), format!("pre-swap file sync: {e}")))?;
        // A launch-created log whose directory entry is still unsynced
        // is synced before the swap — after the handle is released the
        // entry must already be durable, or a crash could lose the
        // rotated file the reopen was meant to preserve.
        if !self.dir_synced {
            self.sync_dir().map_err(|e| {
                std::io::Error::new(e.kind(), format!("pre-swap directory sync: {e}"))
            })?;
        }
        let sink_open::OpenedSink { file, dir, leaf } = sink_open::open_audit_sink(path)?;
        self.writer = std::io::BufWriter::with_capacity(BUF_WRITER_CAPACITY, file);
        // A freshly created rotated file's directory entry needs the
        // same one-time fsync a launch-time create does — done here,
        // in the reopen path, so the `audit.reopened` marker that
        // follows can never outrun its own entry. The handle replaces
        // the retired anchor so a failed sync can still be retried by
        // the periodic service — `dir_synced` now tracks the *new*
        // entry's durability, and the leaf tracks the name its
        // visible-entry proof re-resolves.
        self.anchor.dir = dir;
        self.anchor.leaf = leaf;
        match sync_audit_dir(self.anchor.dir.as_ref()) {
            Ok(()) => {
                self.dir_synced = true;
                Ok(())
            }
            Err(e) => {
                self.dir_synced = false;
                Err(std::io::Error::new(
                    e.kind(),
                    format!("post-swap directory sync: {e}"),
                ))
            }
        }
    }
}

/// The sink- and clock-agnostic writer core: one dequeued item at a
/// time, the durability ladder each kind requires, and the periodic
/// deadline service a bounded processing chunk guarantees. The
/// dedicated-thread driver supplies the queue; every ordering and
/// durability decision lives here so the core is identical no matter
/// which driver drains it.
pub(super) struct WriterCore<S: AuditSink, C: AuditClock> {
    /// The sink generation currently live — tests reach it through
    /// [`WriterCore::sink`] for scripted-sink assertions.
    sink: S,
    clock: C,
    writer_failed: FailureFlag,
    sync_mode: AuditSyncMode,
    session_id: String,
    /// The path the sink re-resolves under and the visible-entry
    /// proof verifies against — the launch's configured audit path.
    audit_path: PathBuf,
    events_since_flush: u32,
    records_since_clock_check: u32,
    next_flush_at: Instant,
    next_fsync_at: Instant,
}

impl<S: AuditSink, C: AuditClock> WriterCore<S, C> {
    pub(super) fn new(
        sink: S,
        clock: C,
        writer_failed: FailureFlag,
        sync_mode: AuditSyncMode,
        session_id: String,
        audit_path: PathBuf,
    ) -> Self {
        // Periodic deadlines anchor to the core's birth, like the old
        // intervals' first ticks.
        let now = clock.now();
        Self {
            sink,
            clock,
            writer_failed,
            sync_mode,
            session_id,
            audit_path,
            events_since_flush: 0,
            records_since_clock_check: 0,
            next_flush_at: now + FLUSH_PERIOD,
            next_fsync_at: now + FSYNC_PERIOD,
        }
    }

    /// The sink, for scripted-sink assertions in tests.
    #[cfg(test)]
    pub(super) fn sink(&self) -> &S {
        &self.sink
    }

    /// The earliest deadline the idle arm should wait on.
    pub(super) fn next_deadline(&self) -> Instant {
        self.next_flush_at.min(self.next_fsync_at)
    }

    /// One dequeued record: serialize, append, run whichever sync
    /// path the record's own contract demands — then, every
    /// [`CLOCK_CHECK_RECORDS`], consult the clock and service anything
    /// due. That check is what keeps periodic sync starts out of
    /// starvation: it runs after a bounded chunk whether or not the
    /// queue behind it is empty.
    pub(super) fn handle_record(&mut self, item: AuditItem) {
        let AuditItem {
            event: evt,
            ack,
            bytes_permit,
            slot_permit: _slot_permit,
        } = item;
        // The record left the queue — its byte share of the queue's
        // memory budget returns now, ahead of the write. The slot
        // permit stays pinned for the whole processing window: it
        // bounds records-in-flight, not just queue occupancy.
        drop(bytes_permit);
        #[cfg(feature = "measure")]
        crate::measure::incr(&crate::measure::AUDIT_EVENTS_DEQUEUED, 1);
        // A record skips the buffered tail when a caller waits on its
        // durability (the fail-closed ack), when `--audit-sync` syncs
        // every record, or when its severity reaches
        // IMMEDIATE_SYNC_SEVERITY — a denial or failure is exactly the
        // evidence a forced kill most wants to shed.
        let must_sync = ack.is_some()
            || matches!(self.sync_mode, AuditSyncMode::EveryEvent)
            || evt.severity >= IMMEDIATE_SYNC_SEVERITY;
        let json = write_event_jsonl(&self.session_id, &evt);
        // A failed write gates the durable path below: the record may
        // never have reached the buffer, so a later successful flush
        // must not be reported as its ack.
        // One `write_all` per record: `writeln!`'s multi-`write_str`
        // calls could straddle a buffer flush boundary and leave a
        // partial line in the file — a concurrent reader must only
        // ever see whole records.
        let mut ok = true;
        let mut line = json;
        line.push('\n');
        if let Err(e) = self.sink.write_record(line.as_bytes()) {
            tracing::error!("Audit log write failed: {e}");
            self.writer_failed.set();
            ok = false;
        }
        self.events_since_flush += 1;

        if must_sync {
            // The durable path: flush the buffer, fsync the file,
            // then — for a freshly created log — fsync the parent so
            // the directory entry survives a crash too. A failed write
            // gates *every* step, the flush included: the record may
            // never have reached the buffer, so a later successful
            // flush must not be reported as its ack — and retrying IO
            // on a sink that just faulted buys the buffered tail
            // nothing the periodic path won't retry anyway. (This
            // tightens the pre-RF03 writer, which flushed
            // unconditionally.)
            if ok && let Err(e) = self.sink.flush_buffer() {
                tracing::error!("Audit log sync flush failed: {e}");
                self.writer_failed.set();
                ok = false;
            }
            if ok {
                self.events_since_flush = 0;
            }
            if ok && let Err(e) = self.sink.sync_file() {
                tracing::error!("Audit log sync fsync failed: {e}");
                self.writer_failed.set();
                ok = false;
            }
            // The record is durable only once the parent directory
            // entry is too — a failure is an audit error, not an ack.
            if ok && self.sink.needs_dir_sync() {
                match self.sink.sync_dir() {
                    Ok(()) => {}
                    Err(e) => {
                        tracing::error!("Audit log directory sync failed: {e}");
                        self.writer_failed.set();
                        ok = false;
                    }
                }
            }
            // An acknowledged record must still be reachable under the
            // name the operator opened — a swapped-out directory entry
            // would hide the evidence behind a substitute, so a hidden
            // entry is an audit failure, not an ack.
            if ok && !self.sink.entry_visible(&self.audit_path) {
                tracing::error!("Audit log entry no longer names the opened file");
                self.writer_failed.set();
                ok = false;
            }
            // A dropped receiver is the ack for failure — never signal
            // success on a failed write.
            if ok && let Some(ack) = ack {
                let _ = ack.send(());
            }
        } else if self.events_since_flush >= FLUSH_EVENT_THRESHOLD {
            if let Err(e) = self.sink.flush_buffer() {
                tracing::error!("Audit log flush failed: {e}");
                self.writer_failed.set();
            } else {
                self.events_since_flush = 0;
            }
        }

        self.records_since_clock_check += 1;
        if self.records_since_clock_check >= CLOCK_CHECK_RECORDS {
            self.records_since_clock_check = 0;
            self.service_due_deadlines();
        }
    }

    /// A control request is a barrier: all records dequeued before it
    /// belong to the sink generation still live here and get their
    /// durable commit before the swap; records dequeued after belong
    /// to the next generation — they appear after the marker in the
    /// new file. Its dequeue is also a processing boundary — owed
    /// periodic deadlines are settled once the request is serviced.
    pub(super) fn handle_control(&mut self, req: ControlRequest) {
        match req {
            ControlRequest::Reopen(ReopenRequest {
                reply,
                marker,
                queued_at,
                slot: _slot,
            }) => {
                let _queued_at = queued_at;
                #[cfg(feature = "measure")]
                crate::measure::observe(
                    &crate::measure::AUDIT_CONTROL_WAIT_NS,
                    _queued_at.elapsed().as_nanos().min(u64::MAX as u128) as u64,
                );
                // The timer lives in the arm's scope — its drop at the
                // end of reopen processing is what `audit.reopen.ns`
                // records as the control request's service time.
                #[cfg(feature = "measure")]
                let _reopen_timer = crate::measure::Timer::new(&crate::measure::AUDIT_REOPEN_NS);
                let result = self.sink.reopen(&self.audit_path);
                if let Err(e) = &result {
                    tracing::error!("Audit log reopen failed: {e}");
                    self.writer_failed.set();
                } else {
                    tracing::info!("Audit log reopened at {}", self.audit_path.display());
                }
                // The rotation marker is written in-band, ahead of any
                // record a relay may have queued while the reopen ran —
                // on success it is the first record of the new file; on
                // failure it lands on whatever handle survived (the old
                // sink, or the swapped-in one when the dir fsync failed
                // post-swap). Synced before the reply so an
                // acknowledged reopen means the evidence is durable,
                // not merely buffered — a marker that cannot be
                // persisted fails the reply too.
                let mut evt = marker(result.as_ref().err().map(|e| e.to_string()));
                evt.bound_wire_fields();
                // Serialized with the writer's own session id here,
                // like every other record — this guarantees the
                // rotation marker carries the structured id.
                let mut line = write_event_jsonl(&self.session_id, &evt);
                line.push('\n');
                let mut marker_result = Ok(());
                // The marker joins the pending tail like any other
                // record — count it before the write so a failed
                // flush below leaves the tail pending for the
                // periodic retry instead of clearing the state.
                self.events_since_flush += 1;
                if let Err(e) = self.sink.write_record(line.as_bytes()) {
                    tracing::error!("Audit log reopen marker write failed: {e}");
                    self.writer_failed.set();
                    marker_result = Err(e);
                }
                if marker_result.is_ok()
                    && let Err(e) = self.sink.flush_buffer()
                {
                    tracing::error!("Audit log reopen marker flush failed: {e}");
                    self.writer_failed.set();
                    marker_result = Err(e);
                }
                // Cleared only once the marker actually crossed the
                // buffer boundary — a failed flush keeps the pending
                // count so the next deadline retries the tail.
                if marker_result.is_ok() {
                    self.events_since_flush = 0;
                }
                if marker_result.is_ok()
                    && let Err(e) = self.sink.sync_file()
                {
                    tracing::error!("Audit log reopen marker fsync failed: {e}");
                    self.writer_failed.set();
                    marker_result = Err(e);
                }
                if marker_result.is_ok() && self.sink.needs_dir_sync() {
                    match self.sink.sync_dir() {
                        Ok(()) => {}
                        Err(e) => {
                            tracing::error!("Audit log directory sync failed: {e}");
                            self.writer_failed.set();
                            marker_result = Err(e);
                        }
                    }
                }
                // An acknowledged reopen means the new sink is durable
                // *and* still reachable under the audit path — a
                // rotator or co-located actor that swapped the entry
                // mid-rotation hides the reopened file from the
                // operator's reader.
                if marker_result.is_ok() && !self.sink.entry_visible(&self.audit_path) {
                    tracing::error!("Audit log entry no longer names the reopened file");
                    self.writer_failed.set();
                    marker_result = Err(std::io::Error::other(
                        "audit log entry no longer names the opened file",
                    ));
                }
                // `and` keeps the reopen's error primary — when both
                // fail, the caller hears why the path could not be
                // re-opened, not the secondary marker fault on the
                // surviving handle.
                let _ = reply.send(result.and(marker_result));
            }
        }
        // A control item is a processing boundary too — a long
        // rotation's own syncs do not discharge the periodic
        // schedule. Settle what is owed here so a passed deadline
        // never waits on the next record or an empty queue.
        self.records_since_clock_check = 0;
        self.service_due_deadlines();
    }

    /// Channel closed: everything accepted has already dequeued —
    /// final durable commit plus the last visible-entry proof, then
    /// the driver exits.
    pub(super) fn drain_finish(&mut self) {
        if let Err(e) = self.sink.flush_buffer() {
            tracing::error!("Audit log final flush failed: {e}");
            self.writer_failed.set();
        }
        if let Err(e) = self.sink.sync_file() {
            tracing::error!("Audit log final sync failed: {e}");
            self.writer_failed.set();
        }
        if self.sink.needs_dir_sync()
            && let Err(e) = self.sink.sync_dir()
        {
            tracing::error!("Audit log directory sync failed: {e}");
            self.writer_failed.set();
        }
        // Shutdown is the last place a hidden entry can be reported —
        // committed records behind a swapped-out entry fail the
        // session flag.
        if !self.sink.entry_visible(&self.audit_path) {
            tracing::error!("Audit log entry no longer names the opened file at shutdown");
            self.writer_failed.set();
        }
    }

    /// Run any deadline whose scheduled instant has passed — at a
    /// bounded processing boundary inside [`handle_record`] and on
    /// the driver's idle wake.
    ///
    /// [`handle_record`]: WriterCore::handle_record
    pub(super) fn service_due_deadlines(&mut self) {
        let now = self.clock.now();
        // The periodic flush's schedule: each due 1 s tick flushes a
        // non-empty tail. Collapsing missed ticks into one check is
        // identical to the Burst interval firing them — the first
        // serviced tick empties the counter the later ones would
        // test.
        let flush_due = self.next_flush_at <= now && self.events_since_flush > 0;
        while self.next_flush_at <= now {
            self.next_flush_at += FLUSH_PERIOD;
        }
        if flush_due {
            if let Err(e) = self.sink.flush_buffer() {
                tracing::error!("Audit log periodic flush failed: {e}");
                self.writer_failed.set();
            } else {
                self.events_since_flush = 0;
            }
        }
        // The periodic fsync's schedule: every due 5 s tick gets its
        // own sync — a stall settles each owed period individually
        // (the Burst semantics this replaces), never collapsing them.
        while self.next_fsync_at <= now {
            // `_scheduled` is the instant this sync was *meant* to
            // start — the difference to `now` is the periodic-sync
            // start delay RF03 tracks. Recorded only here, so syncs
            // caused by a reopen, a shutdown drain, or a record's own
            // durable path never count as an overdue deadline.
            let _scheduled = self.next_fsync_at;
            self.next_fsync_at += FSYNC_PERIOD;
            // Sample the clock at the sync's actual start — the entry
            // `now` predates the flush phase and any earlier owed
            // ticks, so a stale sample would overstate this tick's
            // start delay. The `while` cutoff still uses `now`.
            #[cfg(feature = "measure")]
            crate::measure::observe(
                &crate::measure::AUDIT_SYNC_START_DELAY_NS,
                self.clock
                    .now()
                    .saturating_duration_since(_scheduled)
                    .as_nanos()
                    .min(u64::MAX as u128) as u64,
            );
            if let Err(e) = self.sink.sync_file() {
                tracing::error!("Audit log fsync failed: {e}");
                self.writer_failed.set();
            }
            if self.sink.needs_dir_sync()
                && let Err(e) = self.sink.sync_dir()
            {
                tracing::error!("Audit log directory sync failed: {e}");
                self.writer_failed.set();
            }
        }
    }
}

/// The spawned pieces of a file writer: the dedicated thread's join
/// handle, the idle-wake ticker task, and the completion notice the
/// shutdown side awaits. `join` is never waited on — it exists to own
/// the thread's lifetime token, released by detach once `done`
/// proves the work finished; `ticker` is a companion the retire path
/// aborts, not an input the drain depends on.
pub(super) struct FileWriterSpawn {
    pub(super) join: std::thread::JoinHandle<()>,
    pub(super) ticker: tokio::task::JoinHandle<()>,
    pub(super) done: tokio::sync::oneshot::Receiver<()>,
}

/// Spawn the dedicated file-writer thread plus its idle-wake ticker.
/// The thread owns the sink and the intake receiver — one thread per
/// logger for the logger's whole life, never a thread or blocking
/// task per event. Fails only if the OS refuses the thread spawn; the
/// opened sink is then dropped by the caller with the writer never
/// having existed.
pub(super) fn spawn_file_writer<S, C>(
    tx: &mpsc::Sender<WriterItem>,
    rx: mpsc::Receiver<WriterItem>,
    core: WriterCore<S, C>,
) -> std::io::Result<FileWriterSpawn>
where
    S: AuditSink + 'static,
    C: AuditClock,
{
    let clock = core.clock.clone();
    // The writer's earliest deadline, reposted after every processed
    // item — the ticker re-arms on it so an idle queue's deadline is
    // serviced on the clock's own schedule.
    let (deadline_tx, deadline_rx) = tokio::sync::watch::channel(core.next_deadline());
    // At most one tick outstanding: the flag is claimed before the
    // send and cleared when the writer dequeues the tick, so wake
    // traffic can never pile up inside the bounded queue.
    let tick_pending = std::sync::Arc::new(AtomicBool::new(false));
    let ticker = tokio::spawn(deadline_ticker(
        clock,
        deadline_rx,
        tx.downgrade(),
        tick_pending.clone(),
    ));
    let (done_tx, done) = tokio::sync::oneshot::channel();
    let join = match std::thread::Builder::new()
        .name("mcp-writ-audit".to_string())
        .spawn(move || {
            file_writer_thread(rx, core, deadline_tx, tick_pending, done_tx);
        }) {
        Ok(join) => join,
        Err(e) => {
            ticker.abort();
            return Err(e);
        }
    };
    Ok(FileWriterSpawn { join, ticker, done })
}

/// Latches the writer's failure flag if the thread dies without
/// reaching its disarm point — a panic unwinding out of the driver
/// must still notify every `failure_watch` subscriber, not just the
/// `done` waiter: an abnormal exit is a fault whether or not anyone
/// is currently awaiting the completion notice.
struct WriterFaultGuard {
    flag: FailureFlag,
    armed: bool,
}

impl Drop for WriterFaultGuard {
    fn drop(&mut self) {
        if self.armed {
            self.flag.set();
        }
    }
}

/// The blocking driver over [`WriterCore`], running on the writer's
/// dedicated thread: the queue supplies the order through
/// `blocking_recv`; the core supplies every durability decision.
/// Channel close — all senders dropped — is the shutdown request's
/// position: the queue drains, the terminal durable commit and
/// visible-entry proof run, the sink handles release, and only then
/// does `done` report the end of life. In-flight OS I/O cannot be
/// interrupted, so nothing here is on a timeout: an incomplete drain
/// is never reported as a completion.
fn file_writer_thread<S: AuditSink, C: AuditClock>(
    mut rx: mpsc::Receiver<WriterItem>,
    mut core: WriterCore<S, C>,
    deadline_tx: tokio::sync::watch::Sender<Instant>,
    tick_pending: std::sync::Arc<AtomicBool>,
    done_tx: tokio::sync::oneshot::Sender<()>,
) {
    // Armed until the driver finishes normally — unwinding past it
    // means the writer died without its completion notice, and the
    // fault must latch before the thread does.
    let mut fault = WriterFaultGuard {
        flag: core.writer_failed.clone(),
        armed: true,
    };
    let mut posted = core.next_deadline();
    // The stop delay a shutdown waits out starts at intake closure —
    // the queued commits and the final sync all ride the window, not
    // just `drain_finish`'s tail.
    #[cfg(feature = "measure")]
    let mut drain_start: Option<Instant> = None;
    while let Some(item) = rx.blocking_recv() {
        #[cfg(feature = "measure")]
        if drain_start.is_none() && rx.is_closed() {
            drain_start = Some(core.clock.now());
        }
        match item {
            WriterItem::Record(item) => core.handle_record(*item),
            WriterItem::Control(req) => core.handle_control(req),
            // The idle wake lands here, in queue order like every
            // other item — it carries no payload, so servicing due
            // deadlines at its position reorders nothing.
            WriterItem::Tick => {
                tick_pending.store(false, Ordering::SeqCst);
                core.service_due_deadlines();
            }
        }
        // Repost the earliest deadline whenever the last service
        // moved it — the ticker re-arms on each new value, so one
        // posted instant maps to at most the pending tick's own wait.
        let deadline = core.next_deadline();
        if deadline != posted {
            posted = deadline;
            let _ = deadline_tx.send(deadline);
        }
    }
    // A close observed with an empty queue never entered the loop —
    // the drain window is only the terminal commit then.
    #[cfg(feature = "measure")]
    let drain_start = drain_start.unwrap_or_else(|| core.clock.now());
    core.drain_finish();
    #[cfg(feature = "measure")]
    let drain_clock = core.clock.clone();
    // The sink's file and directory handles release ahead of the
    // completion notice — shutdown's `done` wait observes the end
    // result only after the drain, the final sync, and the handle
    // release all happened.
    drop(core);
    drop(rx);
    #[cfg(feature = "measure")]
    crate::measure::observe(
        &crate::measure::AUDIT_DRAIN_NS,
        drain_clock
            .now()
            .saturating_duration_since(drain_start)
            .as_nanos()
            .min(u64::MAX as u128) as u64,
    );
    let _ = done_tx.send(());
    // The completion notice is out — reaching here is a normal end,
    // not a fault the flag should remember.
    fault.armed = false;
}

/// The idle-wake companion for [`file_writer_thread`]: the writer
/// posts its earliest deadline; when the injected clock reaches it,
/// the ticker lands a [`WriterItem::Tick`] in the same queue so the
/// blocking thread wakes for deadline service. The weak sender keeps
/// the ticker from holding the channel open — the writer's drain
/// still keys on the last real sender dropping — and upgrade failing
/// is the all-senders-gone case, where no tick is needed anyway.
/// Runs until the deadline watch closes (writer exit) or the task is
/// aborted (explicit retire).
async fn deadline_ticker<C: AuditClock>(
    clock: C,
    mut deadline_rx: tokio::sync::watch::Receiver<Instant>,
    weak_tx: mpsc::WeakSender<WriterItem>,
    tick_pending: std::sync::Arc<AtomicBool>,
) {
    loop {
        let deadline = *deadline_rx.borrow_and_update();
        tokio::select! {
            _ = clock.sleep_until(deadline) => {
                // Claim the single outstanding-tick slot before
                // sending; a failed claim means a tick is already in
                // flight, a failed send means the queue cannot take
                // it — either way the flag returns to clear.
                if !tick_pending.swap(true, Ordering::SeqCst) {
                    let sent = weak_tx
                        .upgrade()
                        .is_some_and(|tx| tx.try_send(WriterItem::Tick).is_ok());
                    if !sent {
                        tick_pending.store(false, Ordering::SeqCst);
                    }
                }
                // Re-arm only once the writer's service moved the
                // deadline — re-ticking the same instant would spin,
                // and a dropped tick already implies the busy path
                // carries the due service.
                if deadline_rx.changed().await.is_err() {
                    return;
                }
            }
            changed = deadline_rx.changed() => {
                if changed.is_err() {
                    return;
                }
            }
        }
    }
}

pub(super) async fn tracing_writer_task(
    mut rx: mpsc::Receiver<WriterItem>,
    sink_durable: bool,
    session_id: String,
) {
    while let Some(item) = rx.recv().await {
        let WriterItem::Record(item) = item else {
            // Non-record items never reach this task — `reopen()`
            // answers `false` before queueing on a non-file sink, and
            // only the file writer's ticker posts ticks. A stray
            // control item must drop its reply anyway: acknowledging
            // it would mean reporting a rotation nothing performed.
            continue;
        };
        let AuditItem {
            event: evt,
            ack,
            bytes_permit: _bytes_permit,
            slot_permit: _slot_permit,
        } = *item;
        let json = write_event_jsonl(&session_id, &evt);
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
