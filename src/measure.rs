//! Internal counters for the sibling `bench/` crate — the measurement
//! façade behind the non-default `measure` feature.
//!
//! Compiled only when `measure` is enabled (the `bench/` workspace
//! package enables it through its `mcp-writ` dependency). The feature is
//! off in shipped builds: every instrumented site is `#[cfg(feature =
//! "measure")]`-gated, so the default build's public API, behavior, and
//! performance are untouched — same shape as the `fuzzing` feature's
//! `fuzz` façade. Hidden from the documented API for the same reason.
//!
//! A counter's value is only meaningful against the list of sites that
//! feed it; each constant documents its sites so a reading is never
//! mistaken for coverage it does not have. Sites are chosen on the
//! request/audit/DNS paths the 2026-11 refactoring PRs compare — an RF
//! that needs a site not yet instrumented adds it in its own PR.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

/// A monotonic event counter — relaxed atomic adds.
pub struct Counter {
    pub name: &'static str,
    value: AtomicU64,
}

impl Counter {
    pub const fn new(name: &'static str) -> Self {
        Self {
            name,
            value: AtomicU64::new(0),
        }
    }
}

/// A sampled duration distribution — count / sum / max in nanoseconds.
pub struct Timing {
    pub name: &'static str,
    count: AtomicU64,
    sum_ns: AtomicU64,
    max_ns: AtomicU64,
}

impl Timing {
    pub const fn new(name: &'static str) -> Self {
        Self {
            name,
            count: AtomicU64::new(0),
            sum_ns: AtomicU64::new(0),
            max_ns: AtomicU64::new(0),
        }
    }

    fn observe(&self, ns: u64) {
        self.count.fetch_add(1, Ordering::Relaxed);
        self.sum_ns.fetch_add(ns, Ordering::Relaxed);
        self.max_ns.fetch_max(ns, Ordering::Relaxed);
    }
}

/// The latest value of an instantaneous quantity (queue depth, …).
pub struct Gauge {
    pub name: &'static str,
    value: AtomicU64,
}

impl Gauge {
    pub const fn new(name: &'static str) -> Self {
        Self {
            name,
            value: AtomicU64::new(0),
        }
    }
}

/// Add `n` to `c`.
pub fn incr(c: &'static Counter, n: u64) {
    c.value.fetch_add(n, Ordering::Relaxed);
}

/// Record one duration sample in `t`.
pub fn observe(t: &'static Timing, ns: u64) {
    t.observe(ns);
}

/// Set `g` to the current reading.
pub fn set(g: &'static Gauge, v: u64) {
    g.value.store(v, Ordering::Relaxed);
}

/// RAII duration sample — `Timer::new(&T)` at the top of a scope records
/// the scope's wall time on drop.
pub struct Timer {
    stat: &'static Timing,
    start: Instant,
}

impl Timer {
    pub fn new(stat: &'static Timing) -> Self {
        Self {
            stat,
            start: Instant::now(),
        }
    }
}

impl Drop for Timer {
    fn drop(&mut self) {
        self.stat
            .observe(self.start.elapsed().as_nanos().min(u64::MAX as u128) as u64);
    }
}

// ---------------------------------------------------------------------
// Counters
// ---------------------------------------------------------------------

/// `nojson::RawJson::parse` calls on the request path.
/// Sites: `auditor::proxy_c2s` structural gate,
/// `checker::check_request`, `checker::check_trajectory`,
/// `checker::classify_request_protocol_version`,
/// `checker::request_state_over_cap`, `session::rpc_id::RpcId::from_line`,
/// `checker::targets::{extract_fs_targets, extract_deputy_use_targets_as,
/// request_has_host_or_url}`.
pub static JSON_PARSE_CALLS: Counter = Counter::new("json.parse.calls");

/// `check_duplicate_keys_recursively` invocations (any caller).
pub static DUPKEY_SCAN_CALLS: Counter = Counter::new("json.dupkey.scan.calls");

/// Object nodes visited inside the duplicate-key walk.
pub static DUPKEY_OBJECT_NODES: Counter = Counter::new("json.dupkey.object_nodes");

/// `schema_validator::validate_arguments` schema parses — the per-request
/// `RawJson::parse(schema_str)` RF05b removes.
pub static SCHEMA_PARSE_CALLS: Counter = Counter::new("schema.parse.calls");

/// `regex_lite::Regex::new` compilations inside `pattern` evaluation —
/// the per-request regex builds RF05b removes.
pub static SCHEMA_REGEX_BUILDS: Counter = Counter::new("schema.regex.builds");

/// Grant entries visited by `DynamicAllowList` lookup/name/qual scans —
/// the full-set walks RF07 indexes away.
pub static DNS_SCAN_ENTRIES: Counter = Counter::new("dns.scan.entries");

/// Staged entries walked by `register_staged_at`'s capacity re-check —
/// the staged-set rebuild RF07 replaces with per-key counts.
pub static DNS_STAGED_SCAN_ENTRIES: Counter = Counter::new("dns.staged.scan.entries");

/// Records dequeued by the audit file writer task.
pub static AUDIT_EVENTS_DEQUEUED: Counter = Counter::new("audit.events.dequeued");

/// `sync_all` calls on the audit file sink (any cause).
pub static AUDIT_SYNC_COUNT: Counter = Counter::new("audit.sync.count");

/// `BufWriter::flush` calls on the audit file sink (any cause).
pub static AUDIT_FLUSH_COUNT: Counter = Counter::new("audit.flush.count");

/// All counters, for [`snapshot`].
static COUNTERS: &[&Counter] = &[
    &JSON_PARSE_CALLS,
    &DUPKEY_SCAN_CALLS,
    &DUPKEY_OBJECT_NODES,
    &SCHEMA_PARSE_CALLS,
    &SCHEMA_REGEX_BUILDS,
    &DNS_SCAN_ENTRIES,
    &DNS_STAGED_SCAN_ENTRIES,
    &AUDIT_EVENTS_DEQUEUED,
    &AUDIT_SYNC_COUNT,
    &AUDIT_FLUSH_COUNT,
];

// ---------------------------------------------------------------------
// Timings
// ---------------------------------------------------------------------

/// `DynamicAllowList::inner` critical-section hold time — the lock
/// window RF07's indexed lookups shrink.
pub static DNS_LOCK_NS: Timing = Timing::new("dns.lock.hold.ns");

/// `sync_all` duration on the audit file sink.
pub static AUDIT_SYNC_NS: Timing = Timing::new("audit.sync.ns");

/// Delay between the audit writer's periodic fsync tick's scheduled
/// instant and when the `fsync_interval` arm actually runs — the
/// sync-start starvation signal RF03 fixes (~0 when punctual; seconds
/// when a busy event channel starves the 5 s timer under `biased`).
/// Fed only by that arm, so syncs caused by a reopen, a shutdown
/// drain, or a record's durable path never count as an overdue timer.
pub static AUDIT_SYNC_START_DELAY_NS: Timing = Timing::new("audit.sync.start_delay.ns");

/// `BufWriter::flush` duration on the audit file sink.
pub static AUDIT_FLUSH_NS: Timing = Timing::new("audit.flush.ns");

/// Audit reopen request handling time inside the writer task — the
/// rotation wait the requesting side sees as `reopen()` latency.
pub static AUDIT_REOPEN_NS: Timing = Timing::new("audit.reopen.ns");

/// Wait between a control request's queue admission and the writer
/// starting its service — M3's control-wait figure, kept separate
/// from the service time `audit.reopen.ns` measures.
pub static AUDIT_CONTROL_WAIT_NS: Timing = Timing::new("audit.control_wait.ns");

/// All timings, for [`snapshot`].
static TIMINGS: &[&Timing] = &[
    &DNS_LOCK_NS,
    &AUDIT_SYNC_NS,
    &AUDIT_SYNC_START_DELAY_NS,
    &AUDIT_FLUSH_NS,
    &AUDIT_REOPEN_NS,
    &AUDIT_CONTROL_WAIT_NS,
];

// ---------------------------------------------------------------------
// Gauges
// ---------------------------------------------------------------------

/// Queued audit byte budget in use — Σ(capacity − available permits)
/// over every live logger's registered `bytes_budget`, derived at
/// [`snapshot`] time so the reading reflects releases (writer drains,
/// failed sends, cancelled producers) rather than only enqueue edges.
pub static AUDIT_QUEUE_BYTES: Gauge = Gauge::new("audit.queue.bytes");

/// All gauges, for [`snapshot`].
static GAUGES: &[&Gauge] = &[&AUDIT_QUEUE_BYTES];

/// Registered audit byte-budget semaphores — `(capacity, weak ref)`
/// per live logger. [`AUDIT_QUEUE_BYTES`] is derived from these at
/// snapshot time; weak refs keep a dropped logger's budget out of the
/// sum without an unregister call on the drop path.
static QUEUE_BUDGETS: std::sync::Mutex<Vec<(u64, std::sync::Weak<tokio::sync::Semaphore>)>> =
    std::sync::Mutex::new(Vec::new());

/// Register a queue byte-budget source for [`AUDIT_QUEUE_BYTES`] —
/// called once per constructed `AuditLogger`, which owns the strong
/// `Arc<Semaphore>` for the logger's lifetime.
pub fn register_queue_budget(capacity: u64, sem: &std::sync::Arc<tokio::sync::Semaphore>) {
    let mut budgets = QUEUE_BUDGETS.lock().unwrap();
    budgets.retain(|(_, w)| w.strong_count() > 0);
    budgets.push((capacity, std::sync::Arc::downgrade(sem)));
}

// ---------------------------------------------------------------------
// Snapshot / reset
// ---------------------------------------------------------------------

/// One timing's aggregate at snapshot time.
#[derive(Debug)]
pub struct TimingStat {
    pub count: u64,
    pub sum_ns: u64,
    pub max_ns: u64,
}

/// Point-in-time copy of every counter, timing, and gauge.
#[derive(Debug)]
pub struct Snapshot {
    pub counters: Vec<(&'static str, u64)>,
    pub timings: Vec<(&'static str, TimingStat)>,
    pub gauges: Vec<(&'static str, u64)>,
}

/// Read all registered counters, timings, and gauges.
pub fn snapshot() -> Snapshot {
    // `audit.queue.bytes` derives from live permit availability so the
    // gauge is exact at every release edge — a writer drain, a failed
    // send, or a cancelled producer frees budget without a sampled
    // update site.
    let queue_bytes: u64 = QUEUE_BUDGETS
        .lock()
        .unwrap()
        .iter()
        .filter_map(|(cap, w)| {
            w.upgrade()
                .map(|s| cap.saturating_sub(s.available_permits() as u64))
        })
        .sum();
    AUDIT_QUEUE_BYTES
        .value
        .store(queue_bytes, Ordering::Relaxed);
    Snapshot {
        counters: COUNTERS
            .iter()
            .map(|c| (c.name, c.value.load(Ordering::Relaxed)))
            .collect(),
        timings: TIMINGS
            .iter()
            .map(|t| {
                (
                    t.name,
                    TimingStat {
                        count: t.count.load(Ordering::Relaxed),
                        sum_ns: t.sum_ns.load(Ordering::Relaxed),
                        max_ns: t.max_ns.load(Ordering::Relaxed),
                    },
                )
            })
            .collect(),
        gauges: GAUGES
            .iter()
            .map(|g| (g.name, g.value.load(Ordering::Relaxed)))
            .collect(),
    }
}

/// Zero every counter, timing, and gauge — measurement iteration setup,
/// not a product-path operation.
pub fn reset() {
    for c in COUNTERS {
        c.value.store(0, Ordering::Relaxed);
    }
    for t in TIMINGS {
        t.count.store(0, Ordering::Relaxed);
        t.sum_ns.store(0, Ordering::Relaxed);
        t.max_ns.store(0, Ordering::Relaxed);
    }
    for g in GAUGES {
        g.value.store(0, Ordering::Relaxed);
    }
}
