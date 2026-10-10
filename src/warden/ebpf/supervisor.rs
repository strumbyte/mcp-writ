//! Drain supervisor — consumes kernel-side deny events from the ring
//! buffer, resyncs the dynamic-grant maps from the dns-gate snapshot,
//! and emits `sandbox.network_denied` under the launch's correlation.
//!
//! Unlike `unotify`'s supervisor this loop *observes* denials the
//! kernel already enforced — the verdict is never in flight here, so
//! a slow drain loses audit records (counted via `stats.dropped`) but
//! never enforcement.

use std::fs::File;
use std::io;
use std::os::unix::io::{AsRawFd, FromRawFd};
use std::path::PathBuf;

use crate::audit_log::{
    Action, AuditEvent, AuditLogger, EventType, Outcome, PolicyAuditContext, Severity,
};

use super::events::{DenyEvent, Pop, RingBuf, poll_ready};
use super::rules::{Family, RULE_ENTRY_SIZE, RULE_IDX_NONE};
use super::runtime::Runtime;
use super::sys;

/// How often the grant maps are checked for snapshot changes and
/// expired entries are swept (independent of event traffic).
const RESYNC_INTERVAL: std::time::Duration = std::time::Duration::from_millis(500);

/// What the drain needs: the runtime's event/grant fds, the grant
/// snapshot source, the audit sink and correlation context.
pub struct DrainConfig {
    pub allowlist: Option<PathBuf>,
    pub logger: AuditLogger,
    pub launch_id: uuid::Uuid,
    pub policy_context: Option<PolicyAuditContext>,
}

/// Counters the report carries.
#[derive(Debug, Default, Clone)]
pub struct DrainStats {
    /// Well-formed deny events drained — including any whose
    /// committed audit write itself failed (an `audit_errors`
    /// increment does not exclude the record from this count).
    pub denied: u64,
    /// Kernel-side denied connects the ring buffer lost (events map
    /// `denied_dropped` counter snapshot at drain end).
    pub dropped: u64,
    /// Malformed/oversized ring-buffer records skipped.
    pub malformed: u64,
    /// Head records found mid-submit (`BUSY` flag set) — the drain
    /// paused and retried rather than consuming them early or
    /// spinning on the position.
    pub busy: u64,
    /// Grant-map resyncs performed.
    pub grant_syncs: u64,
    /// Grant entries written at the last resync.
    pub grant_entries: u64,
    /// Flattened grant entries dropped across resyncs because the
    /// grant maps' `GRANT_SLOTS` bound was exceeded — fail-closed
    /// (a dropped grant is denied by default), counted here.
    pub grants_dropped: u64,
    /// Audit-commit failures on deny records.
    pub audit_errors: u64,
}

/// Why the drain loop exited.
#[derive(Debug)]
pub enum DrainExit {
    /// The stop fd was signalled (command-initiated shutdown).
    Shutdown,
    /// The ring buffer/poll failed — observation is gone; enforcement
    /// continues in-kernel but the launch treats lost observability as
    /// fatal rather than silently auditing nothing.
    Lost(String),
}

/// Exit record: reason plus counters.
pub struct DrainEnd {
    pub reason: DrainExit,
    pub stats: DrainStats,
}

/// A running drain — the blocking loop on a `spawn_blocking` task plus
/// the eventfd the stop side writes.
pub struct Drain {
    task: tokio::task::JoinHandle<DrainEnd>,
    stop: File,
}

impl Drain {
    /// Start draining `rt`'s ring buffer. `rt` must outlive the drain —
    /// the caller stops the drain before dropping the runtime.
    pub fn start(rt: &Runtime, cfg: DrainConfig) -> io::Result<Self> {
        let stop_raw = unsafe { libc::eventfd(0, libc::EFD_CLOEXEC) };
        if stop_raw < 0 {
            return Err(io::Error::last_os_error());
        }
        let stop = unsafe { File::from_raw_fd(stop_raw) };
        let loop_stop = stop.try_clone()?;
        let ring = RingBuf::open(rt.events_fd(), super::runtime::RINGBUF_DATA_SIZE)?;
        let events_fd = rt.events_fd();
        let grants = (rt.grant_map(Family::V4), rt.grant_map(Family::V6));
        let stats_map = rt.stats_fd();
        let meta4 = rt.meta4.clone();
        let meta6 = rt.meta6.clone();
        let task = tokio::task::spawn_blocking(move || {
            let mut l = Loop {
                ring,
                events_fd,
                stop: loop_stop,
                grants,
                stats_map,
                meta4,
                meta6,
                allowlist: cfg.allowlist,
                allow_sig: None,
                logger: cfg.logger,
                launch_id: cfg.launch_id,
                policy_ctx: cfg.policy_context,
                stats: DrainStats::default(),
            };
            l.run()
        });
        Ok(Self { task, stop })
    }

    /// The drain's exit future for `tokio::select!`.
    pub fn exited(&mut self) -> &mut tokio::task::JoinHandle<DrainEnd> {
        &mut self.task
    }

    /// Signal the loop to stop and await its exit record.
    pub async fn shutdown(self) -> DrainEnd {
        let byte = 1u64.to_ne_bytes();
        unsafe {
            libc::write(
                self.stop.as_raw_fd(),
                byte.as_ptr().cast::<std::ffi::c_void>(),
                8,
            )
        };
        match self.task.await {
            Ok(end) => end,
            Err(e) => DrainEnd {
                reason: DrainExit::Lost(format!("drain task join failed: {e}")),
                stats: DrainStats::default(),
            },
        }
    }
}

/// Flatten grants to per-family entry lists bounded by `GRANT_SLOTS`
/// — overflow entries are counted, not written (a dropped grant stays
/// denied: fail-closed). `pub(super)` for the unit test.
pub(super) fn flatten_grants(
    grants: &[crate::warden::unotify::SnapshotGrant],
) -> (
    Vec<super::rules::RuleEntry>,
    Vec<super::rules::RuleEntry>,
    u64,
) {
    let mut e4 = Vec::new();
    let mut e6 = Vec::new();
    let mut dropped = 0u64;
    for g in grants {
        for (fam, entry) in super::rules::grant_entries(g.addr, &g.quals, g.expires_at_unix_secs) {
            match fam {
                Family::V4 if e4.len() < super::rules::GRANT_SLOTS => e4.push(entry),
                Family::V6 if e6.len() < super::rules::GRANT_SLOTS => e6.push(entry),
                _ => dropped += 1,
            }
        }
    }
    (e4, e6, dropped)
}

/// Flatten parsed grants to per-family entries and rewrite both grant
/// maps — used slots filled, the rest sentinel'd. Returns
/// `(written, dropped)` totals, or `None` on a map-update failure.
fn write_grant_maps(
    maps: (i32, i32),
    grants: &[crate::warden::unotify::SnapshotGrant],
) -> Option<(usize, u64)> {
    let (e4, e6, dropped) = flatten_grants(grants);
    let sentinel = super::rules::grant_sentinel();
    let write_all = |map: i32, entries: &[super::rules::RuleEntry]| {
        for i in 0..super::rules::GRANT_SLOTS {
            let e = entries.get(i).copied().unwrap_or(sentinel);
            let b = unsafe {
                std::slice::from_raw_parts(
                    &e as *const super::rules::RuleEntry as *const u8,
                    RULE_ENTRY_SIZE,
                )
            };
            if sys::map_update(map, &(i as u32).to_ne_bytes(), b).is_err() {
                return false;
            }
        }
        true
    };
    if write_all(maps.0, &e4) && write_all(maps.1, &e6) {
        if dropped > 0 {
            tracing::warn!(
                dropped,
                slots = super::rules::GRANT_SLOTS,
                "grant entries exceed the eBPF grant-map capacity — \
                 dropped grants are denied by default"
            );
        }
        Some((e4.len() + e6.len(), dropped))
    } else {
        None
    }
}

/// Synchronous grant-map load for the pre-spawn window: the drain's
/// 500ms resync cadence is correct for *updates*, but the child's
/// first connect can land before it — a granted destination must be
/// authorized from exec onward. `None` allowlist leaves the prepared
/// sentinel state (maps are already all-sentinel from
/// `Runtime::prepare`). A missing/unparsable snapshot writes an empty
/// grant set — fail closed, same as the loop. A map-write failure is
/// reported so the launch can refuse rather than run with silently
/// absent grants.
pub fn sync_grants_once(rt: &Runtime, allowlist: Option<&std::path::Path>) -> bool {
    let Some(path) = allowlist else { return true };
    let grants = crate::warden::unotify::load_snapshot(path);
    write_grant_maps(
        (rt.grant_map(Family::V4), rt.grant_map(Family::V6)),
        &grants,
    )
    .is_some()
}

struct Loop {
    ring: RingBuf,
    events_fd: i32,
    stop: File,
    grants: (i32, i32),
    stats_map: i32,
    meta4: Vec<super::rules::RuleMeta>,
    meta6: Vec<super::rules::RuleMeta>,
    allowlist: Option<PathBuf>,
    allow_sig: Option<(std::time::SystemTime, u64)>,
    logger: AuditLogger,
    launch_id: uuid::Uuid,
    policy_ctx: Option<PolicyAuditContext>,
    stats: DrainStats,
}

impl Loop {
    fn run(&mut self) -> DrainEnd {
        let stop_fd = self.stop.as_raw_fd();
        loop {
            // A pending record short-circuits the poll so a burst is
            // drained without a timeout between records.
            if !self.ring.has_pending() {
                match poll_ready(self.events_fd, RESYNC_INTERVAL) {
                    Ok(_) => {}
                    Err(e) if e.raw_os_error() == Some(libc::EINTR) => continue,
                    Err(e) => {
                        return self.end(DrainExit::Lost(format!("ringbuf poll failed: {e}")));
                    }
                }
            }
            let mut pfd = libc::pollfd {
                fd: stop_fd,
                events: libc::POLLIN,
                revents: 0,
            };
            // Safety: `pfd` is live for the zero-timeout poll.
            if unsafe { libc::poll(&mut pfd, 1, 0) } > 0 && pfd.revents & libc::POLLIN != 0 {
                // Flush what the kernel already wrote — a stop must
                // not shed audited denials still sitting in the ring.
                // A BUSY head gets a short bounded wait for the
                // producer to finish its submit.
                for _ in 0..50 {
                    if self.drain_pending() {
                        break;
                    }
                    std::thread::sleep(std::time::Duration::from_millis(1));
                }
                return self.end(DrainExit::Shutdown);
            }
            if !self.drain_pending() {
                // Head record mid-submit (`BUSY`): the producer's
                // submit lands momentarily — pace the retry so the
                // pending-but-unconsumable head cannot spin the loop.
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
            self.maybe_resync_grants();
        }
    }

    /// Pop every pending record: valid events are audited, malformed
    /// ones fold into the counter + warning path. `false` when the
    /// head record is still mid-submit (`BUSY`) — the caller paces
    /// the retry so a stuck reservation cannot spin the drain.
    fn drain_pending(&mut self) -> bool {
        loop {
            match self.ring.pop() {
                Pop::Empty => return true,
                Pop::Busy => {
                    self.stats.busy += 1;
                    return false;
                }
                Pop::Record(Ok(ev)) => self.emit_deny(&ev),
                Pop::Record(Err(e)) => {
                    self.stats.malformed += 1;
                    tracing::warn!("ebpf drain: {e}");
                }
            }
        }
    }

    fn end(&mut self, reason: DrainExit) -> DrainEnd {
        // Fold the kernel-side drop counter into the reportable stats.
        let mut b = [0u8; 16];
        if sys::map_lookup(self.stats_map, &0u32.to_ne_bytes(), &mut b).is_ok() {
            self.stats.dropped = u64::from_ne_bytes(b[8..16].try_into().unwrap());
        }
        DrainEnd {
            reason,
            stats: std::mem::take(&mut self.stats),
        }
    }

    /// Re-read the allowlist snapshot when it changed; rewrite both
    /// grant maps (fill used slots, sentinel the rest). A missing file
    /// is an empty grant set — same fail-closed contract the unotify
    /// `Grants` applies.
    fn maybe_resync_grants(&mut self) {
        let Some(path) = &self.allowlist else { return };
        let sig = std::fs::metadata(path)
            .ok()
            .and_then(|m| m.modified().ok().map(|t| (t, m.len())));
        if sig == self.allow_sig {
            return;
        }
        self.allow_sig = sig;
        let grants = match sig {
            Some(_) => crate::warden::unotify::load_snapshot(path),
            None => Vec::new(),
        };
        match write_grant_maps(self.grants, &grants) {
            Some((n, dropped)) => {
                self.stats.grant_syncs += 1;
                self.stats.grant_entries = n as u64;
                self.stats.grants_dropped += dropped;
            }
            None => {
                tracing::warn!("ebpf grant resync: map update failed — grants left stale");
            }
        }
    }

    /// One drained deny event → `sandbox.network_denied` (committed —
    /// the kernel already enforced it; the audit must still be durable).
    fn emit_deny(&mut self, ev: &DenyEvent) {
        // Grants never deny — the GRANT bit arriving here is
        // defensive decode, same as an unindexed default verdict.
        let meta =
            if ev.rule_idx == RULE_IDX_NONE || ev.rule_idx & super::rules::RULE_IDX_GRANT != 0 {
                None
            } else {
                let idx = ev.rule_idx as usize;
                match ev.family as i32 {
                    f if f == libc::AF_INET => self.meta4.get(idx),
                    f if f == libc::AF_INET6 => self.meta6.get(idx),
                    _ => None,
                }
            };
        let (decision, rule) = match meta {
            Some(m) => (m.decision, Some(m.rule.as_str())),
            None => ("not-allowed", None),
        };
        let proto = match ev.proto as i32 {
            p if p == libc::IPPROTO_TCP => "tcp",
            p if p == libc::IPPROTO_UDP => "udp",
            _ => "unknown",
        };
        let dest = ev
            .dest()
            .map(|d| d.to_string())
            .unwrap_or_else(|| "?".to_string());
        let mut event = AuditEvent::new(
            self.launch_id,
            EventType::SandboxNetworkDenied,
            Severity::High,
            Outcome::Failure,
            Action::Denied,
        );
        event.policy_context = self.policy_ctx.clone();
        if let Some(p) = &self.policy_ctx
            && p.id != "default"
        {
            event.target_server = Some(p.id.clone());
        }
        let mut details = format!(
            "layer=ip proto={proto} dest={dest} port={} pid={} decision={decision} session_id={}",
            ev.port(),
            ev.pid(),
            self.logger.session_id()
        );
        if let Some(r) = rule {
            details.push_str(&format!(" rule={r}"));
        }
        event.details = Some(details);
        let res = tokio::runtime::Handle::current().block_on(self.logger.log_committed(event));
        if let Err(e) = res {
            self.stats.audit_errors += 1;
            tracing::error!("audit commit for kernel-denied connect failed: {e}");
        }
        // `denied` counts every well-formed deny record drained —
        // audited or audit-failed.
        self.stats.denied += 1;
    }
}
