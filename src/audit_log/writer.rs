//! The dedicated writer tasks behind [`AuditLogger`](super::AuditLogger):
//! the file task drains the bounded record channel into a `BufWriter`,
//! applies the flush/fsync schedule (and the reopen rotation arm), and
//! re-verifies the sink's directory entry before acknowledging durable
//! records; the tracing task mirrors records to stderr where a
//! completion can never prove durability.

use std::io::Write;
use std::path::{Path, PathBuf};

use tokio::sync::mpsc;

use super::{
    AuditItem, AuditSyncMode, BUF_WRITER_CAPACITY, FLUSH_EVENT_THRESHOLD, FailureFlag,
    IMMEDIATE_SYNC_SEVERITY, ReopenRequest, Severity, sink_open, write_event_jsonl,
};

/// fsync the directory handle a freshly created log's entry lives in —
/// the file's own `sync_all` commits its data but not the directory
/// entry naming it, so a crash between create and commit could lose the
/// whole file. `None` means either a pre-existing file (its entry is
/// already durable) or a platform with no directory-fsync boundary —
/// Windows commits the entry through the file's own flush, so the sink
/// open hands no handle over.
fn sync_audit_dir(dir: Option<&std::fs::File>) -> std::io::Result<()> {
    let Some(dir) = dir else { return Ok(()) };
    dir.sync_all()
}

/// The pinned parent handle + leaf name the sink's visible-entry
/// proof re-resolves under — carried alongside the writer so commit
/// acknowledgments and shutdown can still verify the entry names the
/// opened object, and the parent stays live for entry fsyncs.
pub(super) struct SinkAnchor {
    pub(super) dir: Option<std::fs::File>,
    pub(super) leaf: Option<std::ffi::OsString>,
}

/// `true` while the sink's leaf under its pinned parent still names
/// the open file — a committed record behind a swapped-out entry is
/// hidden from the reader the operator named, so a `false` here is an
/// audit failure, not an acknowledgment.
fn sink_entry_visible(
    writer: &std::io::BufWriter<std::fs::File>,
    dir: Option<&std::fs::File>,
    leaf: Option<&std::ffi::OsStr>,
    path: &Path,
) -> bool {
    match sink_open::entry_names_opened_file(dir, path, leaf, writer.get_ref()) {
        Ok(visible) => visible,
        Err(e) => {
            tracing::error!("Audit log entry verification failed: {e}");
            false
        }
    }
}

/// The reopen sequence behind signal-driven rotation: the buffered
/// tail must be durable in the *old* file before the handle is
/// swapped, so the flush and fsync run while `writer` still names the
/// previous object. The path is then re-opened through the same
/// trust-boundary `open_audit_sink` the launch used — a link planted
/// since launch, a non-regular leaf, or a file a rotator recreated
/// under another uid fails the reopen exactly as it would have failed
/// the launch. The swap itself happens as soon as the new handle is
/// verified — a failed directory-entry fsync afterwards still reports
/// `Err`, but records keep reaching the correctly named file.
fn reopen_sink(
    writer: &mut std::io::BufWriter<std::fs::File>,
    path: &Path,
    anchor: &mut SinkAnchor,
    dir_synced: &mut bool,
) -> std::io::Result<()> {
    writer.flush()?;
    writer.get_ref().sync_all()?;
    // A launch-created log whose directory entry is still unsynced is
    // synced before the swap — after the handle is released the entry
    // must already be durable, or a crash could lose the rotated file
    // the reopen was meant to preserve.
    if !*dir_synced {
        sync_audit_dir(anchor.dir.as_ref())?;
        *dir_synced = true;
    }
    let sink_open::OpenedSink { file, dir, leaf } = sink_open::open_audit_sink(path)?;
    *writer = std::io::BufWriter::with_capacity(BUF_WRITER_CAPACITY, file);
    // A freshly created rotated file's directory entry needs the same
    // one-time fsync a launch-time create does — done here, in the
    // reopen path, so the `audit.reopened` marker that follows can
    // never outrun its own entry. The handle replaces the retired
    // anchor so a failed sync can still be retried by the periodic
    // arm — `dir_synced` now tracks the *new* entry's durability, and
    // the leaf tracks the name its visible-entry proof re-resolves.
    anchor.dir = dir;
    anchor.leaf = leaf;
    match sync_audit_dir(anchor.dir.as_ref()) {
        Ok(()) => {
            *dir_synced = true;
            Ok(())
        }
        Err(e) => {
            *dir_synced = false;
            Err(e)
        }
    }
}

pub(super) async fn file_writer_task(
    mut rx: mpsc::Receiver<AuditItem>,
    mut writer: std::io::BufWriter<std::fs::File>,
    writer_failed: FailureFlag,
    mut anchor: SinkAnchor,
    sync_mode: AuditSyncMode,
    audit_path: PathBuf,
    mut reopen_rx: mpsc::Receiver<ReopenRequest>,
) {
    // The parent handle is retained for every open so the entry can be
    // re-verified at commit-ack time; its fsync runs once before the
    // first completion notification — required for a freshly created
    // file's entry, redundant for a durable existing one. `None`
    // (Windows, which carries no parent capability) counts as synced.
    let mut dir_synced = anchor.dir.is_none();
    // A closed reopen channel (every sender gone) parks the arm — a
    // `None` recv must not spin the loop.
    let mut reopen_open = true;
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
                    Some((evt, ack, _permit)) => {
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
                        // One `write_all` per record: `writeln!`'s
                        // multi-`write_str` calls could straddle a
                        // buffer flush boundary and leave a partial
                        // line in the file — a concurrent reader must
                        // only ever see whole records.
                        let mut ok = true;
                        let mut line = json;
                        line.push('\n');
                        if let Err(e) = writer.write_all(line.as_bytes()) {
                            tracing::error!("Audit log write failed: {e}");
                            writer_failed.set();
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
                                writer_failed.set();
                                ok = false;
                            }
                            events_since_flush = 0;
                            if ok && let Err(e) = writer.get_ref().sync_all() {
                                tracing::error!("Audit log sync fsync failed: {e}");
                                writer_failed.set();
                                ok = false;
                            }
                            // The record is durable only once the parent
                            // directory entry is too — a failure is an
                            // audit error, not an ack.
                            if ok && !dir_synced {
                                match sync_audit_dir(anchor.dir.as_ref()) {
                                    Ok(()) => dir_synced = true,
                                    Err(e) => {
                                        tracing::error!(
                                            "Audit log directory sync failed: {e}"
                                        );
                                        writer_failed.set();
                                        ok = false;
                                    }
                                }
                            }
                            // An acknowledged record must still be
                            // reachable under the name the operator
                            // opened — a swapped-out directory entry
                            // would hide the evidence behind a
                            // substitute, so a hidden entry is an
                            // audit failure, not an ack.
                            if ok
                                && !sink_entry_visible(
                                    &writer,
                                    anchor.dir.as_ref(),
                                    anchor.leaf.as_deref(),
                                    &audit_path,
                                )
                            {
                                tracing::error!(
                                    "Audit log entry no longer names the opened file"
                                );
                                writer_failed.set();
                                ok = false;
                            }
                            // A dropped receiver is the ack for failure —
                            // never signal success on a failed write.
                            if ok && let Some(ack) = ack {
                                let _ = ack.send(());
                            }
                        } else if events_since_flush >= FLUSH_EVENT_THRESHOLD {
                            if let Err(e) = writer.flush() {
                                tracing::error!("Audit log flush failed: {e}");
                                writer_failed.set();
                            }
                            events_since_flush = 0;
                        }
                    }
                    None => {
                        if let Err(e) = writer.flush() {
                            tracing::error!("Audit log final flush failed: {e}");
                            writer_failed.set();
                        }
                        if let Err(e) = writer.get_ref().sync_all() {
                            tracing::error!("Audit log final sync failed: {e}");
                            writer_failed.set();
                        }
                        if !dir_synced
                            && let Err(e) = sync_audit_dir(anchor.dir.as_ref())
                        {
                            tracing::error!("Audit log directory sync failed: {e}");
                            writer_failed.set();
                        }
                        // Shutdown is the last place a hidden entry can
                        // be reported — committed records behind a
                        // swapped-out entry fail the session flag.
                        if !sink_entry_visible(
                            &writer,
                            anchor.dir.as_ref(),
                            anchor.leaf.as_deref(),
                            &audit_path,
                        ) {
                            tracing::error!(
                                "Audit log entry no longer names the opened file at shutdown"
                            );
                            writer_failed.set();
                        }
                        return;
                    }
                }
            }
            // The record arm is polled first under `biased`, so every
            // event queued ahead of a pending request is already
            // written to the old file — rotation can never interleave
            // a pre-signal record into the new file.
            req = reopen_rx.recv(), if reopen_open => {
                match req {
                    Some(ReopenRequest { reply, marker }) => {
                        let result = reopen_sink(
                            &mut writer,
                            &audit_path,
                            &mut anchor,
                            &mut dir_synced,
                        );
                        if let Err(e) = &result {
                            tracing::error!("Audit log reopen failed: {e}");
                            writer_failed.set();
                        } else {
                            tracing::info!("Audit log reopened at {}", audit_path.display());
                        }
                        // The rotation marker is written in-band, ahead
                        // of any record a relay may have queued while
                        // the reopen ran — on success it is the first
                        // record of the new file; on failure it lands
                        // on whatever handle survived (the old sink, or
                        // the swapped-in one when the dir fsync failed
                        // post-swap). Synced before the reply so an
                        // acknowledged reopen means the evidence is
                        // durable, not merely buffered — a marker that
                        // cannot be persisted fails the reply too.
                        let mut evt =
                            marker(result.as_ref().err().map(|e| e.to_string()));
                        evt.bound_wire_fields();
                        let mut line = write_event_jsonl(&evt);
                        line.push('\n');
                        let mut marker_result = Ok(());
                        if let Err(e) = writer.write_all(line.as_bytes()) {
                            tracing::error!("Audit log reopen marker write failed: {e}");
                            writer_failed.set();
                            marker_result = Err(e);
                        }
                        events_since_flush = 0;
                        if marker_result.is_ok()
                            && let Err(e) = writer.flush()
                        {
                            tracing::error!("Audit log reopen marker flush failed: {e}");
                            writer_failed.set();
                            marker_result = Err(e);
                        }
                        if marker_result.is_ok()
                            && let Err(e) = writer.get_ref().sync_all()
                        {
                            tracing::error!("Audit log reopen marker fsync failed: {e}");
                            writer_failed.set();
                            marker_result = Err(e);
                        }
                        if marker_result.is_ok() && !dir_synced {
                            match sync_audit_dir(anchor.dir.as_ref()) {
                                Ok(()) => dir_synced = true,
                                Err(e) => {
                                    tracing::error!(
                                        "Audit log directory sync failed: {e}"
                                    );
                                    writer_failed.set();
                                    marker_result = Err(e);
                                }
                            }
                        }
                        // An acknowledged reopen means the new sink is
                        // durable *and* still reachable under the audit
                        // path — a rotator or co-located actor that
                        // swapped the entry mid-rotation hides the
                        // reopened file from the operator's reader.
                        if marker_result.is_ok()
                            && !sink_entry_visible(
                                &writer,
                                anchor.dir.as_ref(),
                                anchor.leaf.as_deref(),
                                &audit_path,
                            )
                        {
                            tracing::error!(
                                "Audit log entry no longer names the reopened file"
                            );
                            writer_failed.set();
                            marker_result = Err(std::io::Error::other(
                                "audit log entry no longer names the opened file",
                            ));
                        }
                        // `and` keeps the reopen_sink error primary —
                        // when both fail, the caller hears why the path
                        // could not be re-opened, not the secondary
                        // marker fault on the surviving handle.
                        let _ = reply.send(result.and(marker_result));
                    }
                    None => reopen_open = false,
                }
            }
            _ = flush_interval.tick() => {
                if events_since_flush > 0 {
                    if let Err(e) = writer.flush() {
                        tracing::error!("Audit log periodic flush failed: {e}");
                        writer_failed.set();
                    }
                    events_since_flush = 0;
                }
            }
            _ = fsync_interval.tick() => {
                if let Err(e) = writer.get_ref().sync_all() {
                    tracing::error!("Audit log fsync failed: {e}");
                    writer_failed.set();
                }
                if !dir_synced {
                    match sync_audit_dir(anchor.dir.as_ref()) {
                        Ok(()) => dir_synced = true,
                        Err(e) => {
                            tracing::error!("Audit log directory sync failed: {e}");
                            writer_failed.set();
                        }
                    }
                }
            }
        }
    }
}

pub(super) async fn tracing_writer_task(mut rx: mpsc::Receiver<AuditItem>, sink_durable: bool) {
    while let Some((evt, ack, _permit)) = rx.recv().await {
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
