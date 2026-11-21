//! TTL-scoped dynamic IP allow list — the name→address grants the gate
//! mints from upstream answers.
//!
//! This table is the contract between the name layer and the IP layer:
//! every A/AAAA the gate relays is registered under the response's
//! chain-minimum TTL, and an IP-layer enforcement point (PR-07
//! supervisor / PR-09 namespaced proxy — separate components, not this
//! one) consults `is_allowed` to decide whether a connection attempt
//! lands on an address the resolver actually vended. An address with a
//! live grant is allowed; expiry closes it again — the grant lifetime
//! is bounded by the DNS answer, not by the gate's uptime.
//!
//! `snapshot_json` / `export_to` serialize the live grants for a
//! consumer in another process (a netns-resident proxy cannot share
//! this map). Consumers MUST honor `expires_at_unix_secs` themselves —
//! a snapshot goes stale the moment it is written, and re-checking
//! expiry is what keeps the TTL contract intact.

use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// One name→address grant keyed separately so a name's re-resolution
/// refreshes only its own grants and two names can share an address
/// without merging each other's expiries.
#[derive(Clone, PartialEq, Eq, Hash)]
struct GrantKey {
    addr: IpAddr,
    name: String,
}

struct GrantEntry {
    expires: Instant,
    /// Deadline-heap generation — bumped on every expiry write so a
    /// heap entry superseded by a refresh can never remove the
    /// updated grant. Staged entries carry 0; a real generation is
    /// assigned when they land live.
    generation: u64,
    /// The proto/port qualifiers under which the grant was minted —
    /// the allow rules that covered the name decide what the resolved
    /// address may carry (a `proto=udp` name rule authorizes only UDP
    /// flows to it). An empty set is never stored — `register` treats
    /// it as a refusal, since a qualifier-less grant would authorize
    /// nothing.
    quals: Vec<crate::policy::GrantQual>,
}

struct Inner {
    /// Live grants indexed by address then name — the IP-layer lookup
    /// walks only the judged endpoint's own names instead of the
    /// whole table. The (address, name) pair stays the grant key and
    /// keeps its own TTL: two names on one address remain separate
    /// entries with separate expiries, and the audit trail can still
    /// say which policy name covered an address.
    by_addr: HashMap<IpAddr, HashMap<String, GrantEntry>>,
    /// Entries in `by_addr`, unreaped expired ones included — the
    /// live figure `max_grants` bounds (the old `grants.len()`).
    live_total: usize,
    /// Grants minted by in-flight resolutions whose audit record has
    /// not committed yet — one bucket per staging token so concurrent
    /// resolutions never share visibility. Staged entries occupy
    /// capacity but are invisible to `is_allowed`, `names_for`,
    /// `quals_for`, `live_len`, snapshots and exports until
    /// `commit_staged` moves them live. Keyed by grant key so a
    /// re-registration inside the same token refreshes in place.
    staged: HashMap<u64, HashMap<GrantKey, GrantEntry>>,
    /// Tokens holding a staged copy of each key. Keys stay tracked
    /// while live too: if the live grant is later reaped or revoked,
    /// its remaining staged copies resume counting as new-key
    /// reservations — the same accounting the per-call `staged_new`
    /// rebuild produced.
    staged_counts: HashMap<GrantKey, usize>,
    /// Count of `staged_counts` keys that are not live — the unique
    /// new-key reservations the staged capacity check adds to
    /// `live_total`. Incrementally maintained on every stage,
    /// commit, drop, reap, or revoke transition.
    staged_new: usize,
    /// Live-grant expiry deadlines, earliest first. Refreshing a
    /// grant pushes a new entry with a bumped generation; stale
    /// entries are skipped on pop, and the heap is rebuilt once it
    /// outgrows the live set so update churn cannot grow it
    /// unboundedly.
    deadlines: DeadlineHeap,
    /// Generation source for `deadlines` staleness checks.
    next_deadline_gen: u64,
}

/// Stale-deadline slack the heap tolerates before `reap_expired`
/// rebuilds it — rebuilds are O(live) so a floor keeps churn on
/// small tables from rebuilding on every other write.
const DEADLINE_REBUILD_FLOOR: usize = 256;

/// The deadline queue's element: a grant's expiry, the generation it
/// was pushed under, and the key it reaps. `Reverse` orders the heap
/// earliest-deadline-first.
type DeadlineHeap = BinaryHeap<Reverse<(Instant, u64, IpAddr, Box<str>)>>;

impl Inner {
    /// Whether `key` names a live grant — the raw map check the
    /// capacity semantics use (unexpired entries count too).
    fn live_has(&self, key: &GrantKey) -> bool {
        self.by_addr
            .get(&key.addr)
            .is_some_and(|m| m.contains_key(&key.name))
    }

    /// `key` became live — bumps `live_total` and, while staged holds
    /// of it remain, drops the key from the new-key reservation count.
    fn note_live_inserted(&mut self, key: &GrantKey) {
        self.live_total += 1;
        if self.staged_counts.contains_key(key) {
            self.staged_new -= 1;
        }
    }

    /// `key` stopped being live — any staged holds it still has
    /// resume counting as a new-key reservation.
    fn note_live_removed(&mut self, key: &GrantKey) {
        self.live_total -= 1;
        if self.staged_counts.contains_key(key) {
            self.staged_new += 1;
        }
    }

    /// One staged hold of `key` released (commit or drop). When the
    /// last hold of a not-live key goes, the key stops counting
    /// against capacity.
    fn release_staged_hold(&mut self, key: &GrantKey) {
        let Some(c) = self.staged_counts.get_mut(key) else {
            return;
        };
        *c -= 1;
        if *c == 0 {
            self.staged_counts.remove(key);
            if !self.live_has(key) {
                self.staged_new -= 1;
            }
        }
    }
}

/// Queue the grant's next deadline under the heap's freshest
/// generation — the stale check an older queued entry fails.
/// Field-split so a live entry's mutable borrow can stay open
/// alongside the heap write.
fn push_deadline(
    deadlines: &mut DeadlineHeap,
    next_deadline_gen: &mut u64,
    expires: Instant,
    addr: IpAddr,
    name: &str,
) -> u64 {
    let generation = *next_deadline_gen;
    *next_deadline_gen += 1;
    deadlines.push(Reverse((expires, generation, addr, name.into())));
    generation
}

/// Reap every live grant whose deadline passed — the lazy expiry the
/// per-write `retain` scan did, now driven by the deadline heap.
/// Stale heap entries (superseded by a refresh, or their key already
/// gone) skip on pop via the generation check; the heap is rebuilt
/// once stale mass outgrows the live set so update churn cannot grow
/// it unboundedly.
fn reap_expired(inner: &mut Inner, now: Instant) {
    while inner
        .deadlines
        .peek()
        .is_some_and(|Reverse((expires, ..))| *expires <= now)
    {
        let Reverse((_, generation, addr, name)) = inner.deadlines.pop().unwrap();
        let stale = inner
            .by_addr
            .get(&addr)
            .and_then(|m| m.get(&*name))
            .is_none_or(|e| e.generation != generation);
        if stale {
            continue;
        }
        let empty = {
            let m = inner.by_addr.get_mut(&addr).unwrap();
            m.remove(&*name);
            m.is_empty()
        };
        if empty {
            inner.by_addr.remove(&addr);
        }
        inner.note_live_removed(&GrantKey {
            addr,
            name: name.into_string(),
        });
    }
    compact_deadlines(inner);
}

/// Drop heap entries whose generation no longer matches their live
/// grant once the heap outgrows the live set — the bound that keeps
/// update churn, bulk commits, and revocations from retaining stale
/// deadlines in proportion to operation count. Entries whose
/// generation still matches their key's live grant stay queued, so
/// a refreshed deadline is never compacted away.
fn compact_deadlines(inner: &mut Inner) {
    if inner.deadlines.len()
        > inner
            .live_total
            .saturating_mul(2)
            .max(DEADLINE_REBUILD_FLOOR)
    {
        let old = std::mem::take(&mut inner.deadlines);
        inner.deadlines = old
            .into_iter()
            .filter(|Reverse((_, generation, addr, name))| {
                inner
                    .by_addr
                    .get(addr)
                    .and_then(|m| m.get(&**name))
                    .is_some_and(|e| e.generation == *generation)
            })
            .collect();
    }
    #[cfg(feature = "measure")]
    crate::measure::set(
        &crate::measure::DNS_DEADLINE_ENTRIES,
        inner.deadlines.len() as u64,
    );
}

/// Release the token's whole staged bucket — the drop half shared by
/// `drop_staged` and its unwind-safe variant.
fn drop_staged_bucket(inner: &mut Inner, staging: &GrantStaging) {
    if let Some(entries) = inner.staged.remove(&staging.0) {
        for key in entries.into_keys() {
            inner.release_staged_hold(&key);
        }
    }
}

/// Staging token for one resolution's not-yet-committed grants — see
/// [`DynamicAllowList::begin_staging`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct GrantStaging(u64);

/// One endpoint's grant state taken under a single lock — see
/// [`DynamicAllowList::grant_view`].
#[derive(Debug, Default)]
#[allow(dead_code)] // consumed by the Linux/macOS flow consumers
pub(crate) struct GrantView {
    /// Names with a live grant on the endpoint, sorted.
    pub names: Vec<String>,
    /// Any live grant's qualifiers cover the asked-for flow.
    pub covered: bool,
}

/// The `grant_view*` body — names and coverage computed from the
/// locked table at `now`.
fn grant_view_of(
    inner: &Inner,
    addr: &IpAddr,
    proto: crate::policy::EgressProto,
    port: u16,
    now: Instant,
) -> GrantView {
    let mut view = GrantView::default();
    if let Some(m) = inner.by_addr.get(addr) {
        for (name, e) in m {
            #[cfg(feature = "measure")]
            crate::measure::incr(&crate::measure::DNS_SCAN_ENTRIES, 1);
            if e.expires > now {
                view.names.push(name.clone());
                if !view.covered {
                    view.covered = e.quals.iter().any(|q| q.covers(proto, port));
                }
            }
        }
    }
    view.names.sort();
    view
}

/// Dynamic allow list for DNS-gate answers. Thread-safe; reaping of
/// expired grants runs lazily inside the mutating calls, so the table
/// stays bounded without a sweeper task.
pub struct DynamicAllowList {
    inner: Mutex<Inner>,
    /// Serializes `export_to`'s serialize+write+rename — two exports on
    /// the same destination must not interleave tmp writes or let a
    /// slower snapshot rename over a newer one.
    export_lock: Mutex<()>,
    /// Live-grant ceiling — a bound on memory growth from churning
    /// answers. Registration past the cap refuses; the refusal is a
    /// capacity signal (`guard` details mark it), never a verdict.
    max_grants: usize,
    /// Staging-token allocator for [`Self::begin_staging`].
    next_staging: AtomicU64,
}

impl DynamicAllowList {
    pub fn new(max_grants: usize) -> Self {
        Self {
            inner: Mutex::new(Inner {
                by_addr: HashMap::new(),
                live_total: 0,
                staged: HashMap::new(),
                staged_counts: HashMap::new(),
                staged_new: 0,
                deadlines: BinaryHeap::new(),
                next_deadline_gen: 1,
            }),
            export_lock: Mutex::new(()),
            max_grants,
            next_staging: AtomicU64::new(1),
        }
    }

    /// Register or refresh a `name → addr` grant for `ttl`, minted
    /// under `quals` — the covering allow rules' proto/port scope.
    /// Returns `false` when the table is full of live grants, `ttl`
    /// is zero, or `quals` is empty — a zero-TTL grant expires before
    /// it can be used and a qualifier-less grant authorizes nothing,
    /// so neither is recorded (and the response is still relayed).
    ///
    /// Capacity counts live grants only; a direct registration never
    /// consults the staged set. Callers must not mix the two modes on
    /// one list — the gate mints only through `*_staged`, while the
    /// macOS CONNECT proxy registers directly on its own table.
    pub fn register(
        &self,
        name: &str,
        addr: IpAddr,
        quals: &[crate::policy::GrantQual],
        ttl: Duration,
    ) -> bool {
        self.register_at(name, addr, quals, Instant::now() + ttl)
    }

    /// Register with an absolute expiry — the testable core of
    /// [`Self::register`].
    pub(crate) fn register_at(
        &self,
        name: &str,
        addr: IpAddr,
        quals: &[crate::policy::GrantQual],
        expires: Instant,
    ) -> bool {
        if expires <= Instant::now() || quals.is_empty() {
            return false;
        }
        let mut inner = self.inner.lock().unwrap();
        #[cfg(feature = "measure")]
        let _lock_hold = crate::measure::Timer::new(&crate::measure::DNS_LOCK_NS);
        // Reborrow through the guard once — field-split borrows on a
        // plain `&mut Inner` let the refresh path hold its entry while
        // the deadline heap is written alongside.
        let inner = &mut *inner;
        reap_expired(inner, Instant::now());
        let key = GrantKey {
            addr,
            name: name.to_string(),
        };
        if let Some(e) = inner.by_addr.get_mut(&addr).and_then(|m| m.get_mut(name)) {
            // A fresh answer for the same name→addr replaces the
            // grant's expiry and scope — a longer-lived answer renews
            // it, a shorter one is the resolver's newer truth and
            // wins too. The bumped generation strands the old
            // deadline in the heap as a skip-on-pop stale entry.
            e.expires = expires;
            e.quals = quals.to_vec();
            e.generation = push_deadline(
                &mut inner.deadlines,
                &mut inner.next_deadline_gen,
                expires,
                addr,
                name,
            );
            return true;
        }
        if inner.live_total >= self.max_grants {
            return false;
        }
        let generation = push_deadline(
            &mut inner.deadlines,
            &mut inner.next_deadline_gen,
            expires,
            addr,
            name,
        );
        inner.by_addr.entry(addr).or_default().insert(
            key.name.clone(),
            GrantEntry {
                expires,
                generation,
                quals: quals.to_vec(),
            },
        );
        inner.note_live_inserted(&key);
        true
    }

    /// Begin a staging token for one resolution's mint. Grants
    /// registered under it occupy capacity immediately but stay
    /// invisible to every consumer until [`Self::commit_staged`] —
    /// the mint→commit ordering contract: name→address authority must
    /// not be usable by an IP-layer consumer before the resolution's
    /// audit record is durable. On commit failure [`Self::drop_staged`]
    /// discards the staged set without touching live grants.
    ///
    /// Outstanding tokens are the caller's bound — the gate holds one
    /// per in-flight query under its `MAX_INFLIGHT_QUERIES` semaphore —
    /// and each staged entry keeps its reservation until commit or
    /// drop; nothing reaps staged entries, so a cancelled query still
    /// settles its token (the gate's `StagingGuard`). Capacity counts
    /// *unique* keys only, so reservations another token already holds
    /// never widen the staged footprint.
    pub fn begin_staging(&self) -> GrantStaging {
        GrantStaging(self.next_staging.fetch_add(1, Ordering::Relaxed))
    }

    /// [`Self::register`] semantics for a not-yet-live grant under
    /// `staging` — same refusals (zero TTL, empty quals, capacity), but
    /// the grant lands in the staged set instead of the live table.
    pub fn register_staged(
        &self,
        staging: GrantStaging,
        name: &str,
        addr: IpAddr,
        quals: &[crate::policy::GrantQual],
        ttl: Duration,
    ) -> bool {
        self.register_staged_at(staging, name, addr, quals, Instant::now() + ttl)
    }

    /// [`Self::register_staged`] with an absolute expiry — the testable
    /// core, mirroring `register_at`.
    pub(crate) fn register_staged_at(
        &self,
        staging: GrantStaging,
        name: &str,
        addr: IpAddr,
        quals: &[crate::policy::GrantQual],
        expires: Instant,
    ) -> bool {
        if expires <= Instant::now() || quals.is_empty() {
            return false;
        }
        let mut inner = self.inner.lock().unwrap();
        #[cfg(feature = "measure")]
        let _lock_hold = crate::measure::Timer::new(&crate::measure::DNS_LOCK_NS);
        reap_expired(&mut inner, Instant::now());
        let key = GrantKey {
            addr,
            name: name.to_string(),
        };
        // A re-registration inside the same token refreshes in place —
        // still invisible until commit.
        if let Some(e) = inner
            .staged
            .get_mut(&staging.0)
            .and_then(|entries| entries.get_mut(&key))
        {
            e.expires = expires;
            e.quals = quals.to_vec();
            return true;
        }
        // Capacity counts live grants plus staged keys that would add
        // a *new* key on commit — a staged refresh of a live key adds
        // nothing, and two tokens staging the same key share one
        // reservation: re-staging a key another token already holds
        // merges into that reservation on commit, so it consumes no
        // further headroom and must not be refused by a full table.
        // `staged_new` tracks that unique-set count incrementally —
        // the per-call staged-set rebuild it replaced.
        if let Some(c) = inner.staged_counts.get_mut(&key) {
            *c += 1;
        } else if !inner.live_has(&key) {
            if inner.live_total + inner.staged_new >= self.max_grants {
                return false;
            }
            inner.staged_new += 1;
            inner.staged_counts.insert(key.clone(), 1);
        } else {
            // First staged hold of a live key — tracked so reaping or
            // revoking the live grant restores the reservation.
            inner.staged_counts.insert(key.clone(), 1);
        }
        inner.staged.entry(staging.0).or_default().insert(
            key,
            GrantEntry {
                expires,
                generation: 0,
                quals: quals.to_vec(),
            },
        );
        true
    }

    /// Activate every grant staged under `staging` — the audit record
    /// is durable, so the authority it described may now serve flows.
    /// A staged key landing on a live grant replaces expiry and scope:
    /// the refresh becomes visible atomically with the record that
    /// vended it.
    pub fn commit_staged(&self, staging: GrantStaging) {
        let mut inner = self.inner.lock().unwrap();
        #[cfg(feature = "measure")]
        let _lock_hold = crate::measure::Timer::new(&crate::measure::DNS_LOCK_NS);
        let inner = &mut *inner;
        if let Some(entries) = inner.staged.remove(&staging.0) {
            for (key, mut entry) in entries {
                inner.release_staged_hold(&key);
                entry.generation = push_deadline(
                    &mut inner.deadlines,
                    &mut inner.next_deadline_gen,
                    entry.expires,
                    key.addr,
                    &key.name,
                );
                if inner
                    .by_addr
                    .entry(key.addr)
                    .or_default()
                    .insert(key.name.clone(), entry)
                    .is_none()
                {
                    // A staged key staying held by other tokens stops
                    // counting as a new-key reservation once it lands
                    // live — `note_live_inserted` folds that in.
                    inner.note_live_inserted(&key);
                }
            }
            // The batch pushed one deadline per key, stranding the
            // superseded ones — check the heap bound once here
            // rather than leaving it for the next register.
            compact_deadlines(inner);
        }
    }

    /// Discard every grant staged under `staging` — the audit commit
    /// failed, so nothing it minted may stay reachable. A live grant on
    /// the same key survives untouched: an earlier, recorded resolution
    /// committed it.
    pub fn drop_staged(&self, staging: GrantStaging) {
        let mut inner = self.inner.lock().unwrap();
        #[cfg(feature = "measure")]
        let _lock_hold = crate::measure::Timer::new(&crate::measure::DNS_LOCK_NS);
        drop_staged_bucket(&mut inner, &staging);
    }

    /// [`Self::drop_staged`] for unwinding paths — the same removal,
    /// but proceeds through a poisoned lock instead of panicking:
    /// discarding a bucket is memory-safe on any state, and a `Drop`
    /// running during unwind must not introduce a second panic (that
    /// aborts the process). Only the gate's `StagingGuard` calls this.
    pub(crate) fn drop_staged_unwind_safe(&self, staging: GrantStaging) {
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        #[cfg(feature = "measure")]
        let _lock_hold = crate::measure::Timer::new(&crate::measure::DNS_LOCK_NS);
        drop_staged_bucket(&mut inner, &staging);
    }

    /// Remove the grant for exactly `(name, addr)` — the rollback half
    /// of register→commit ordering: an answer whose audit record could
    /// not be accepted must not leave name→address authority behind.
    /// Revoking also deletes a refreshed entry (an earlier answer's
    /// grant on the same key); on a failed audit sink that is the safe
    /// direction — every consumer denies while `is_failed` stands.
    pub fn revoke(&self, name: &str, addr: IpAddr) {
        let mut inner = self.inner.lock().unwrap();
        #[cfg(feature = "measure")]
        let _lock_hold = crate::measure::Timer::new(&crate::measure::DNS_LOCK_NS);
        let removed = if let Some(m) = inner.by_addr.get_mut(&addr) {
            let removed = m.remove(name).is_some();
            if m.is_empty() {
                inner.by_addr.remove(&addr);
            }
            removed
        } else {
            false
        };
        if removed {
            inner.note_live_removed(&GrantKey {
                addr,
                name: name.to_string(),
            });
            // The live count the heap bound derives from just
            // shrank — a stranded deadline leaves with its grant.
            compact_deadlines(&mut inner);
        }
    }

    /// Whether a live grant authorizes a flow of `proto` to
    /// `addr`:`port` — the IP-layer question, qualifier-aware: a grant
    /// minted under a `proto=udp` name rule never authorizes TCP.
    pub fn is_allowed(&self, addr: &IpAddr, proto: crate::policy::EgressProto, port: u16) -> bool {
        self.is_allowed_at(addr, proto, port, Instant::now())
    }

    pub(crate) fn is_allowed_at(
        &self,
        addr: &IpAddr,
        proto: crate::policy::EgressProto,
        port: u16,
        now: Instant,
    ) -> bool {
        let inner = self.inner.lock().unwrap();
        #[cfg(feature = "measure")]
        let _lock_hold = crate::measure::Timer::new(&crate::measure::DNS_LOCK_NS);
        inner.by_addr.get(addr).is_some_and(|m| {
            m.values().any(|e| {
                #[cfg(feature = "measure")]
                crate::measure::incr(&crate::measure::DNS_SCAN_ENTRIES, 1);
                e.expires > now && e.quals.iter().any(|q| q.covers(proto, port))
            })
        })
    }

    /// One endpoint's grant state under a single lock acquisition —
    /// the live names that vended it (audit detail) and whether any
    /// of their qualifiers cover the `proto`/`port` flow. Both halves
    /// come from the same snapshot, so a commit cannot interleave
    /// between a verdict's answer and its audit names. `names` is
    /// sorted — the same order [`Self::names_for`] returns — and
    /// `covered` is the same answer [`Self::is_allowed`] gives.
    #[allow(dead_code)] // consumed by FlowGate and unotify on Linux/macOS
    pub(crate) fn grant_view(
        &self,
        addr: &IpAddr,
        proto: crate::policy::EgressProto,
        port: u16,
    ) -> GrantView {
        // The reference instant is sampled under the lock so the
        // expiry check runs against the same state the verdict reads
        // — a grant that lapses between sample and acquisition must
        // not be reported live.
        let inner = self.inner.lock().unwrap();
        #[cfg(feature = "measure")]
        let _lock_hold = crate::measure::Timer::new(&crate::measure::DNS_LOCK_NS);
        grant_view_of(&inner, addr, proto, port, Instant::now())
    }

    /// [`Self::grant_view`] at a caller-chosen instant — the testable
    /// core, and the lookup-side expiry check kept independent of
    /// reaper timing.
    #[allow(dead_code)] // used by `grant_view` and the RF07 tests
    pub(crate) fn grant_view_at(
        &self,
        addr: &IpAddr,
        proto: crate::policy::EgressProto,
        port: u16,
        now: Instant,
    ) -> GrantView {
        let inner = self.inner.lock().unwrap();
        #[cfg(feature = "measure")]
        let _lock_hold = crate::measure::Timer::new(&crate::measure::DNS_LOCK_NS);
        grant_view_of(&inner, addr, proto, port, now)
    }

    /// Live grants on `addr` — the names that vended it, for
    /// diagnostics and reporting.
    pub fn names_for(&self, addr: &IpAddr) -> Vec<String> {
        let now = Instant::now();
        let inner = self.inner.lock().unwrap();
        #[cfg(feature = "measure")]
        let _lock_hold = crate::measure::Timer::new(&crate::measure::DNS_LOCK_NS);
        let mut names = Vec::new();
        if let Some(m) = inner.by_addr.get(addr) {
            for (name, e) in m {
                #[cfg(feature = "measure")]
                crate::measure::incr(&crate::measure::DNS_SCAN_ENTRIES, 1);
                if e.expires > now {
                    names.push(name.clone());
                }
            }
        }
        names.sort();
        names
    }

    /// The live qualifiers covering `addr` — every grant's scope,
    /// unioned, for consumers that evaluate flows themselves (the
    /// namespaced proxy's per-datagram check).
    pub fn quals_for(&self, addr: &IpAddr) -> Vec<crate::policy::GrantQual> {
        let now = Instant::now();
        let inner = self.inner.lock().unwrap();
        #[cfg(feature = "measure")]
        let _lock_hold = crate::measure::Timer::new(&crate::measure::DNS_LOCK_NS);
        let mut quals = Vec::new();
        if let Some(m) = inner.by_addr.get(addr) {
            for e in m.values() {
                #[cfg(feature = "measure")]
                crate::measure::incr(&crate::measure::DNS_SCAN_ENTRIES, 1);
                if e.expires > now {
                    quals.extend_from_slice(&e.quals);
                }
            }
        }
        quals.sort();
        quals.dedup();
        quals
    }

    /// Number of live (unexpired) grants.
    pub fn live_len(&self) -> usize {
        let now = Instant::now();
        let inner = self.inner.lock().unwrap();
        #[cfg(feature = "measure")]
        let _lock_hold = crate::measure::Timer::new(&crate::measure::DNS_LOCK_NS);
        inner
            .by_addr
            .values()
            .flat_map(|m| m.values())
            .filter(|e| {
                #[cfg(feature = "measure")]
                crate::measure::incr(&crate::measure::DNS_SCAN_ENTRIES, 1);
                e.expires > now
            })
            .count()
    }

    /// Serialize the live grants to the JSON snapshot contract:
    /// `{"schema_version":"1.1","generated_at_unix_secs":N,"entries":
    /// [{"name","addr","expires_at_unix_secs","quals":[{"proto",
    /// "port"}]}]}` — expiry as epoch seconds so a consumer compares
    /// it against its own clock; `quals` are the proto/port scope the
    /// grant was minted under (`port: null` = any port). A `1.0`
    /// snapshot without `quals` decodes as the pre-schema semantics
    /// (`tcp`, any port) — exactly what those gates minted.
    pub fn snapshot_json(&self) -> String {
        let now = Instant::now();
        let now_wall = SystemTime::now();
        let inner = self.inner.lock().unwrap();
        #[cfg(feature = "measure")]
        let _lock_hold = crate::measure::Timer::new(&crate::measure::DNS_LOCK_NS);
        nojson::object(|o| -> std::fmt::Result {
            o.member("schema_version", "1.1")?;
            o.member("generated_at_unix_secs", unix_secs(now_wall))?;
            o.member(
                "entries",
                nojson::array(|a| {
                    for (addr, names) in &inner.by_addr {
                        for (name, e) in names {
                            if e.expires <= now {
                                continue;
                            }
                            let expires_wall = now_wall + e.expires.saturating_duration_since(now);
                            let addr = addr.to_string();
                            a.element(nojson::object(|e2| {
                                e2.member("name", name.as_str())?;
                                e2.member("addr", addr.as_str())?;
                                e2.member("expires_at_unix_secs", unix_secs(expires_wall))?;
                                e2.member(
                                    "quals",
                                    nojson::array(|qa| {
                                        for q in &e.quals {
                                            qa.element(nojson::object(|qo| {
                                                qo.member("proto", q.proto.as_str())?;
                                                qo.member("port", q.port)
                                            }))?;
                                        }
                                        Ok(())
                                    }),
                                )
                            }))?;
                        }
                    }
                    Ok(())
                }),
            )
        })
        .to_string()
    }

    /// Atomically write the snapshot to `path` (temp file + rename), so
    /// a consumer never reads a half-written table. Exports are
    /// serialized under `export_lock`.
    ///
    /// The temp name carries an unpredictable suffix and is opened with
    /// `create_new`: a predictable sibling path would let a co-located
    /// writer squat a symlink at `<path>.tmp` and have the write land
    /// (and then be renamed from) an attacker-chosen target.
    pub fn export_to(&self, path: &Path) -> std::io::Result<()> {
        let _guard = self.export_lock.lock().unwrap();
        let tmp = export_temp_path(path);
        // `create_new` failing means the temp name is already taken
        // (e.g. planted) — that file is not ours to delete, so cleanup
        // only runs once the create succeeded.
        let mut file = create_temp_file(&tmp)?;
        let result = write_temp_file(&mut file, self.snapshot_json().as_bytes())
            .and_then(|()| std::fs::rename(&tmp, path));
        if result.is_err() {
            let _ = std::fs::remove_file(&tmp);
        }
        result
    }
}

fn export_temp_path(path: &Path) -> PathBuf {
    let mut tmp_os = path.as_os_str().to_os_string();
    tmp_os.push(format!(".tmp-{}", crate::fspriv::unique_suffix()));
    PathBuf::from(tmp_os)
}

fn create_temp_file(tmp: &Path) -> std::io::Result<std::fs::File> {
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    opts.open(tmp)
}

fn write_temp_file(file: &mut std::fs::File, contents: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    file.write_all(contents)?;
    file.sync_data()
}

fn unix_secs(t: SystemTime) -> u64 {
    t.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    const TCP_ANY: crate::policy::GrantQual = crate::policy::GrantQual::TCP_ANY;

    #[test]
    fn register_and_query() {
        let al = DynamicAllowList::new(16);
        let addr = IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34));
        assert!(al.register("www.example.com", addr, &[TCP_ANY], Duration::from_secs(60)));
        assert!(al.is_allowed(&addr, crate::policy::EgressProto::Tcp, 443));
        // A TCP_ANY grant never authorizes UDP.
        assert!(!al.is_allowed(&addr, crate::policy::EgressProto::Udp, 53));
        assert!(!al.is_allowed(
            &IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            crate::policy::EgressProto::Tcp,
            443
        ));
        assert_eq!(al.names_for(&addr), vec!["www.example.com"]);
        assert_eq!(al.live_len(), 1);
    }

    /// Staged grants carry the mint→commit ordering: invisible to every
    /// consumer until `commit_staged`, discarded by `drop_staged`.
    #[test]
    fn staged_grants_are_invisible_until_commit() {
        let al = DynamicAllowList::new(16);
        let a = IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34));
        let s = al.begin_staging();
        assert!(al.register_staged(s, "x.example", a, &[TCP_ANY], Duration::from_secs(60)));
        // Not yet committed: no consumer may see the authority.
        assert!(!al.is_allowed(&a, crate::policy::EgressProto::Tcp, 443));
        assert!(al.names_for(&a).is_empty());
        assert!(al.quals_for(&a).is_empty());
        assert_eq!(al.live_len(), 0);
        assert!(!al.snapshot_json().contains("x.example"));

        al.commit_staged(s);
        assert!(al.is_allowed(&a, crate::policy::EgressProto::Tcp, 443));
        assert_eq!(al.names_for(&a), vec!["x.example"]);
        assert_eq!(al.live_len(), 1);
    }

    /// Commit failure path: `drop_staged` removes only the staged set —
    /// a live grant an earlier committed resolution vended stays.
    #[test]
    fn drop_staged_leaves_committed_grants() {
        let al = DynamicAllowList::new(16);
        let a = IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34));
        assert!(al.register("y.example", a, &[TCP_ANY], Duration::from_secs(60)));

        let s = al.begin_staging();
        // A staged refresh of the live key does not disturb it...
        assert!(al.register_staged(s, "y.example", a, &[TCP_ANY], Duration::from_secs(120)));
        // ...and a new staged key stays invisible.
        let b = IpAddr::V4(Ipv4Addr::new(93, 184, 216, 35));
        assert!(al.register_staged(s, "y.example", b, &[TCP_ANY], Duration::from_secs(60)));
        assert!(!al.is_allowed(&b, crate::policy::EgressProto::Tcp, 443));

        al.drop_staged(s);
        assert!(al.is_allowed(&a, crate::policy::EgressProto::Tcp, 443));
        assert!(!al.is_allowed(&b, crate::policy::EgressProto::Tcp, 443));
        assert_eq!(al.live_len(), 1);
    }

    /// Two resolutions for the same name stage independently: one
    /// commit must not activate the other's still-pending grants.
    #[test]
    fn staging_tokens_are_isolated() {
        let al = DynamicAllowList::new(16);
        let a = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
        let s1 = al.begin_staging();
        let s2 = al.begin_staging();
        assert!(al.register_staged(s1, "n.example", a, &[TCP_ANY], Duration::from_secs(60)));
        assert!(al.register_staged(s2, "n.example", a, &[TCP_ANY], Duration::from_secs(90)));

        al.commit_staged(s2);
        assert!(al.is_allowed(&a, crate::policy::EgressProto::Tcp, 443));
        // s1's drop removes its own staged copy only.
        al.drop_staged(s1);
        assert!(al.is_allowed(&a, crate::policy::EgressProto::Tcp, 443));
    }

    /// Two resolutions racing the same name→addr under a full table
    /// must both stage: the second token re-reserves the key the first
    /// already holds — the reservation merges into one live grant on
    /// commit, so it consumes no new capacity.
    #[test]
    fn staged_same_key_two_tokens_at_capacity() {
        let al = DynamicAllowList::new(1);
        let a = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10));
        let s1 = al.begin_staging();
        let s2 = al.begin_staging();
        assert!(al.register_staged_at(
            s1,
            "dup.example",
            a,
            &[TCP_ANY],
            Instant::now() + Duration::from_secs(60)
        ));
        assert!(al.register_staged_at(
            s2,
            "dup.example",
            a,
            &[TCP_ANY],
            Instant::now() + Duration::from_secs(90)
        ));
        // Neither reservation is visible before commit.
        assert!(!al.is_allowed(&a, crate::policy::EgressProto::Tcp, 443));
        assert!(al.names_for(&a).is_empty());
        assert_eq!(al.live_len(), 0);
        assert!(!al.snapshot_json().contains("dup.example"));

        al.commit_staged(s1);
        assert!(al.is_allowed(&a, crate::policy::EgressProto::Tcp, 443));
        assert_eq!(al.live_len(), 1);
        // s2's leftover staged copy drops without touching the grant
        // s1 committed.
        al.drop_staged(s2);
        assert!(al.is_allowed(&a, crate::policy::EgressProto::Tcp, 443));
        assert_eq!(al.live_len(), 1);
    }

    /// The stored RF02 reproducer's shape — capacity 2 holding one
    /// live grant: both tokens reserve the shared key, `commit:s1`
    /// publishes it once, `drop:s2` removes only s2's hold
    /// (tests/fixtures/refactoring/rf02/capacity1_duplicate.json).
    #[test]
    fn staged_same_key_two_tokens_one_live() {
        let al = DynamicAllowList::new(2);
        let live = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
        let staged_addr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2));
        assert!(al.register("live.example", live, &[TCP_ANY], Duration::from_secs(60)));
        let s1 = al.begin_staging();
        let s2 = al.begin_staging();
        assert!(al.register_staged(
            s1,
            "x.example",
            staged_addr,
            &[TCP_ANY],
            Duration::from_secs(60)
        ));
        assert!(al.register_staged(
            s2,
            "x.example",
            staged_addr,
            &[TCP_ANY],
            Duration::from_secs(60)
        ));
        assert_eq!(al.live_len(), 1);
        al.commit_staged(s1);
        assert_eq!(al.live_len(), 2);
        assert!(al.is_allowed(&staged_addr, crate::policy::EgressProto::Tcp, 443));
        al.drop_staged(s2);
        assert_eq!(al.live_len(), 2);
        assert!(al.is_allowed(&staged_addr, crate::policy::EgressProto::Tcp, 443));
    }

    /// Either drop/commit order publishes the shared key once — a
    /// token's cancellation never removes a reservation another token
    /// still holds, and a second commit on the same key is a refresh.
    #[test]
    fn staged_same_key_drop_then_commit_and_reverse_commit() {
        // Drop the first stager, then commit the second.
        let al = DynamicAllowList::new(1);
        let a = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 11));
        let s1 = al.begin_staging();
        let s2 = al.begin_staging();
        assert!(al.register_staged(s1, "ord.example", a, &[TCP_ANY], Duration::from_secs(60)));
        assert!(al.register_staged(s2, "ord.example", a, &[TCP_ANY], Duration::from_secs(90)));
        al.drop_staged(s1);
        al.commit_staged(s2);
        assert!(al.is_allowed(&a, crate::policy::EgressProto::Tcp, 443));
        assert_eq!(al.live_len(), 1);

        // Commit in reverse registration order — the second commit
        // refreshes the same key (TTL/scope update), still one grant.
        let al = DynamicAllowList::new(1);
        let a = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 12));
        let s1 = al.begin_staging();
        let s2 = al.begin_staging();
        assert!(al.register_staged(s1, "ord.example", a, &[TCP_ANY], Duration::from_secs(60)));
        assert!(al.register_staged(s2, "ord.example", a, &[TCP_ANY], Duration::from_secs(90)));
        al.commit_staged(s2);
        al.commit_staged(s1);
        assert!(al.is_allowed(&a, crate::policy::EgressProto::Tcp, 443));
        assert_eq!(al.live_len(), 1);
    }

    /// A staged refresh of a *live* key never needs headroom — at
    /// capacity 1 the refresh stages and its commit replaces expiry
    /// and scope, the same update `register` performs in place.
    #[test]
    fn staged_refresh_of_live_key_at_capacity() {
        let al = DynamicAllowList::new(1);
        let a = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 20));
        let udp53 = crate::policy::GrantQual {
            proto: crate::policy::EgressProto::Udp,
            port: Some(53),
        };
        assert!(al.register("svc.example", a, &[TCP_ANY], Duration::from_secs(60)));
        let s = al.begin_staging();
        assert!(al.register_staged(s, "svc.example", a, &[udp53], Duration::from_secs(120)));
        // The refresh is invisible until commit — the live grant still
        // carries its original scope.
        assert!(al.is_allowed(&a, crate::policy::EgressProto::Tcp, 443));
        assert!(!al.is_allowed(&a, crate::policy::EgressProto::Udp, 53));
        al.commit_staged(s);
        assert!(!al.is_allowed(&a, crate::policy::EgressProto::Tcp, 443));
        assert!(al.is_allowed(&a, crate::policy::EgressProto::Udp, 53));
        assert_eq!(al.quals_for(&a), vec![udp53]);
        assert_eq!(al.live_len(), 1);
    }

    /// Move every entry staged under `token` into the past — the
    /// resolution's answer aged out between mint and audit commit.
    /// Registration still needs a future deadline (`register_staged_at`
    /// refuses an already-lapsed one), so the expiry is rewound after
    /// the fact instead of racing the real clock.
    fn expire_staged(al: &DynamicAllowList, token: GrantStaging) {
        let mut inner = al.inner.lock().unwrap();
        let past = Instant::now()
            .checked_sub(Duration::from_secs(60))
            .unwrap_or_else(Instant::now);
        for e in inner.staged.get_mut(&token.0).unwrap().values_mut() {
            e.expires = past;
        }
    }

    /// A reservation that expires while staged commits as the
    /// resolver's newer truth — landing the lapsed expiry closes the
    /// key rather than letting stale authority linger.
    #[test]
    fn staged_entry_expiring_before_commit() {
        let al = DynamicAllowList::new(16);
        let a = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 30));
        // An unexpired reservation commits normally.
        let s = al.begin_staging();
        assert!(al.register_staged_at(
            s,
            "ttl.example",
            a,
            &[TCP_ANY],
            Instant::now() + Duration::from_secs(60)
        ));
        al.commit_staged(s);
        assert!(al.is_allowed(&a, crate::policy::EgressProto::Tcp, 443));
        // A reservation whose answer lapsed before commit lands the
        // newer truth — the expired entry overwrites the live grant.
        let s = al.begin_staging();
        assert!(al.register_staged_at(
            s,
            "ttl.example",
            a,
            &[TCP_ANY],
            Instant::now() + Duration::from_secs(60)
        ));
        expire_staged(&al, s);
        al.commit_staged(s);
        assert!(!al.is_allowed(&a, crate::policy::EgressProto::Tcp, 443));
        assert_eq!(al.live_len(), 0);

        // The same overwrite applies to a staged refresh of a live
        // key: an unexpired refresh renews the grant, an expired one
        // closes it.
        let b = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 31));
        assert!(al.register("live.example", b, &[TCP_ANY], Duration::from_secs(300)));
        let s = al.begin_staging();
        assert!(al.register_staged_at(
            s,
            "live.example",
            b,
            &[TCP_ANY],
            Instant::now() + Duration::from_secs(120)
        ));
        al.commit_staged(s);
        assert!(al.is_allowed(&b, crate::policy::EgressProto::Tcp, 443));
        let s = al.begin_staging();
        assert!(al.register_staged_at(
            s,
            "live.example",
            b,
            &[TCP_ANY],
            Instant::now() + Duration::from_secs(120)
        ));
        expire_staged(&al, s);
        al.commit_staged(s);
        assert!(!al.is_allowed(&b, crate::policy::EgressProto::Tcp, 443));
        assert_eq!(al.live_len(), 0);
    }

    /// Shared-key reservations share one reservation; *distinct* keys
    /// still count separately — a different name on the same address
    /// or a different address under the same name must be refused
    /// once every unique key is spoken for.
    #[test]
    fn staged_distinct_key_at_capacity_refused() {
        let al = DynamicAllowList::new(1);
        let a = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 40));
        let b = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 41));
        let s1 = al.begin_staging();
        let s2 = al.begin_staging();
        assert!(al.register_staged(s1, "n.example", a, &[TCP_ANY], Duration::from_secs(60)));
        // Same key again from s2 — shares s1's reservation.
        assert!(al.register_staged(s2, "n.example", a, &[TCP_ANY], Duration::from_secs(60)));
        // A different name on the same address is a different key.
        assert!(!al.register_staged(s2, "m.example", a, &[TCP_ANY], Duration::from_secs(60)));
        // A different address under the same name is a different key.
        assert!(!al.register_staged(s2, "n.example", b, &[TCP_ANY], Duration::from_secs(60)));
        // The refusals stage nothing: s2 commits only its shared copy.
        al.commit_staged(s2);
        assert_eq!(al.live_len(), 1);
        assert_eq!(al.names_for(&a), vec!["n.example"]);
        al.drop_staged(s1);
    }

    /// Uncommitted reservations stay invisible to the exported
    /// snapshot too — `export_to` serializes the same live-only view
    /// `snapshot_json` produces.
    #[test]
    fn staged_grants_absent_from_export() {
        let dir = std::env::temp_dir() // nosemgrep: rust.lang.security.temp-dir.temp-dir
            .join("mcp_writ_test")
            .join(format!("export_staged_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let dest = dir.join("allowlist.json");
        let al = DynamicAllowList::new(16);
        let a = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 50));
        al.register("live.example", a, &[TCP_ANY], Duration::from_secs(60));
        let s = al.begin_staging();
        assert!(al.register_staged(
            s,
            "pending.example",
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 51)),
            &[TCP_ANY],
            Duration::from_secs(60)
        ));
        al.export_to(&dest).unwrap();
        let body = std::fs::read_to_string(&dest).unwrap();
        assert!(body.contains("live.example"));
        assert!(!body.contains("pending.example"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Direct registration counts live grants only — it never
    /// consults the staged set. Callers do not mix the two modes on
    /// one list (the gate stages, the CONNECT proxy registers), so
    /// this overlap is a contract pin, not a production path.
    #[test]
    fn register_ignores_staged_capacity() {
        let al = DynamicAllowList::new(1);
        let a = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 60));
        let b = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 61));
        let s = al.begin_staging();
        assert!(al.register_staged(s, "staged.example", a, &[TCP_ANY], Duration::from_secs(60)));
        assert!(al.register("direct.example", b, &[TCP_ANY], Duration::from_secs(60)));
        assert_eq!(al.live_len(), 1);
        al.drop_staged(s);
    }

    /// `drop_staged_unwind_safe` must not panic on a poisoned lock —
    /// `StagingGuard` runs it inside `Drop`, where a second panic
    /// during unwind would abort the process. The bucket discard is
    /// memory-safe even on possibly-inconsistent state.
    #[test]
    fn drop_staged_unwind_safe_tolerates_a_poisoned_lock() {
        let al = std::sync::Arc::new(DynamicAllowList::new(4));
        let a = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 70));
        let s = al.begin_staging();
        assert!(al.register_staged(s, "p.example", a, &[TCP_ANY], Duration::from_secs(60)));
        // Poison the lock: a thread panics while holding it.
        let al2 = al.clone();
        let _ = std::thread::spawn(move || {
            let _guard = al2.inner.lock().unwrap();
            panic!("intentional poison");
        })
        .join();
        assert!(al.inner.lock().is_err(), "lock must be poisoned");
        // No panic — and the stranded bucket is still discarded.
        al.drop_staged_unwind_safe(s);
        let inner = al.inner.lock().unwrap_or_else(|e| e.into_inner());
        assert!(inner.staged.is_empty());
    }

    /// Rollback for the fail-closed ordering contract: a grant minted
    /// before its audit record committed is revoked when the commit
    /// fails — the revoked key no longer authorizes.
    #[test]
    fn revoke_removes_only_the_named_grant() {
        let al = DynamicAllowList::new(16);
        let a = IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34));
        let b = IpAddr::V4(Ipv4Addr::new(93, 184, 216, 35));
        assert!(al.register("x.example", a, &[TCP_ANY], Duration::from_secs(60)));
        assert!(al.register("x.example", b, &[TCP_ANY], Duration::from_secs(60)));
        assert!(al.register("y.example", a, &[TCP_ANY], Duration::from_secs(60)));

        al.revoke("x.example", a);
        // The address stays authorized: `y.example` independently vended
        // it, and that grant carries its own committed audit record.
        assert!(al.is_allowed(&a, crate::policy::EgressProto::Tcp, 443));
        assert_eq!(al.names_for(&a), vec!["y.example"]);
        // The other addr under the revoked name survives — the key is
        // (name, addr).
        assert!(al.is_allowed(&b, crate::policy::EgressProto::Tcp, 443));
        // Once every name→a grant is revoked the address no longer
        // authorizes — the rollback property the DNS gate relies on.
        al.revoke("y.example", a);
        assert!(
            !al.is_allowed(&a, crate::policy::EgressProto::Tcp, 443),
            "last grant for an addr must close it"
        );
        // Revoking an absent key is a no-op.
        al.revoke("x.example", a);
        al.revoke("absent.example", a);
        assert_eq!(al.live_len(), 1);
    }

    #[test]
    fn qualifier_scopes_the_grant() {
        let al = DynamicAllowList::new(16);
        let addr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9));
        let udp53 = crate::policy::GrantQual {
            proto: crate::policy::EgressProto::Udp,
            port: Some(53),
        };
        assert!(al.register("ns.example", addr, &[udp53], Duration::from_secs(60)));
        assert!(al.is_allowed(&addr, crate::policy::EgressProto::Udp, 53));
        assert!(!al.is_allowed(&addr, crate::policy::EgressProto::Udp, 5353));
        assert!(!al.is_allowed(&addr, crate::policy::EgressProto::Tcp, 53));
        // A grant with no quals is never recorded.
        assert!(!al.register("none.example", addr, &[], Duration::from_secs(60)));
        assert_eq!(al.quals_for(&addr), vec![udp53]);
    }

    #[test]
    fn expiry_closes_the_grant() {
        let al = DynamicAllowList::new(16);
        let addr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
        let now = Instant::now();
        assert!(al.register_at("a.example", addr, &[TCP_ANY], now + Duration::from_secs(5)));
        assert!(al.is_allowed_at(
            &addr,
            crate::policy::EgressProto::Tcp,
            443,
            now + Duration::from_secs(4)
        ));
        assert!(!al.is_allowed_at(
            &addr,
            crate::policy::EgressProto::Tcp,
            443,
            now + Duration::from_secs(6)
        ));
        assert_eq!(al.live_len(), 1); // lazily reaped, not eagerly
    }

    #[test]
    fn zero_ttl_is_never_recorded() {
        let al = DynamicAllowList::new(16);
        let addr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 9));
        assert!(!al.register("a.example", addr, &[TCP_ANY], Duration::ZERO));
        assert!(!al.is_allowed(&addr, crate::policy::EgressProto::Tcp, 443));
    }

    #[test]
    fn capacity_refuses_grants() {
        let al = DynamicAllowList::new(1);
        let a1 = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
        let a2 = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2));
        assert!(al.register("a.example", a1, &[TCP_ANY], Duration::from_secs(60)));
        assert!(!al.register("b.example", a2, &[TCP_ANY], Duration::from_secs(60)));
        // The same name→addr pair still refreshes under a full table.
        assert!(al.register("a.example", a1, &[TCP_ANY], Duration::from_secs(120)));
        assert!(al.is_allowed(&a1, crate::policy::EgressProto::Tcp, 443));
        assert!(!al.is_allowed(&a2, crate::policy::EgressProto::Tcp, 443));
    }

    #[test]
    fn snapshot_serializes_live_entries() {
        let al = DynamicAllowList::new(16);
        let addr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7));
        al.register("svc.example", addr, &[TCP_ANY], Duration::from_secs(300));
        let json = al.snapshot_json();
        let parsed = nojson::RawJson::parse(&json).unwrap();
        let entries_member = parsed.value().to_member("entries").unwrap();
        let entries: Vec<_> = entries_member
            .required()
            .unwrap()
            .to_array()
            .unwrap()
            .collect();
        assert_eq!(entries.len(), 1);
        let entry = entries[0];
        assert_eq!(
            entry
                .to_member("name")
                .unwrap()
                .required()
                .unwrap()
                .to_unquoted_string_str()
                .unwrap(),
            "svc.example"
        );
        assert_eq!(
            entry
                .to_member("addr")
                .unwrap()
                .required()
                .unwrap()
                .to_unquoted_string_str()
                .unwrap(),
            "203.0.113.7"
        );
        let exp: u64 = entry
            .to_member("expires_at_unix_secs")
            .unwrap()
            .required()
            .unwrap()
            .as_number_str()
            .unwrap()
            .parse()
            .unwrap();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        assert!(exp > now && exp <= now + 300);
    }

    #[test]
    fn two_names_can_share_one_address() {
        let al = DynamicAllowList::new(16);
        let addr = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 10));
        al.register("a.example", addr, &[TCP_ANY], Duration::from_secs(60));
        al.register("b.example", addr, &[TCP_ANY], Duration::from_secs(30));
        let mut names = al.names_for(&addr);
        names.sort();
        assert_eq!(names, vec!["a.example", "b.example"]);
    }

    #[test]
    fn export_to_tmp_suffixed_destination_stays_atomic() {
        // A destination already spelled `x.tmp` must not collide with
        // its own temp path — the temp name is a suffix on the whole
        // name (`x.tmp.tmp`), never a replacement extension.
        let dir = std::env::temp_dir() // nosemgrep: rust.lang.security.temp-dir.temp-dir
            .join("mcp_writ_test")
            .join(format!("export_tmp_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let dest = dir.join("allowlist.tmp");
        let al = DynamicAllowList::new(16);
        al.register(
            "a.example",
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 5)),
            &[TCP_ANY],
            Duration::from_secs(60),
        );
        al.export_to(&dest).unwrap();
        let body = std::fs::read_to_string(&dest).unwrap();
        assert!(body.contains("a.example"));
        // The temp file was consumed by the rename — the destination
        // (itself spelled `.tmp`) is the only entry left.
        let names: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(
            names,
            vec![dest.file_name().unwrap().to_os_string()],
            "no temp residue expected"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn export_to_symlink_destination_does_not_write_through() {
        // A symlink planted at the destination must be replaced by the
        // rename, never followed: the link target keeps its contents.
        let dir = std::env::temp_dir()
            .join("mcp_writ_test")
            .join(format!("export_link_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let victim = dir.join("victim");
        std::fs::write(&victim, "keep-me").unwrap();
        let dest = dir.join("allowlist.json");
        std::os::unix::fs::symlink(&victim, &dest).unwrap();

        let al = DynamicAllowList::new(16);
        al.register(
            "a.example",
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 5)),
            &[TCP_ANY],
            Duration::from_secs(60),
        );
        al.export_to(&dest).unwrap();

        assert_eq!(std::fs::read_to_string(&victim).unwrap(), "keep-me");
        let meta = std::fs::symlink_metadata(&dest).unwrap();
        assert!(meta.is_file(), "dest must be a regular file, not a link");
        assert!(
            std::fs::read_to_string(&dest)
                .unwrap()
                .contains("a.example")
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// When the temp create itself fails (unwritable directory), the
    /// destination and siblings must be left untouched — cleanup only
    /// runs on a file this call created.
    #[cfg(unix)]
    #[test]
    fn export_to_failed_create_touches_nothing() {
        use std::os::unix::fs::PermissionsExt;
        if crate::fspriv::running_as_root() {
            eprintln!("SKIP: root bypasses the 0o555 mode — cannot exercise EACCES");
            return;
        }
        let dir = std::env::temp_dir()
            .join("mcp_writ_test")
            .join(format!("export_ro_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let dest = dir.join("allowlist.json");
        std::fs::write(&dest, "pre-existing").unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o555)).unwrap();

        let al = DynamicAllowList::new(16);
        al.register(
            "a.example",
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 5)),
            &[TCP_ANY],
            Duration::from_secs(60),
        );
        assert!(al.export_to(&dest).is_err());
        assert_eq!(std::fs::read_to_string(&dest).unwrap(), "pre-existing");
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 1);

        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The exported file must not inherit an over-permissive umask —
    /// an allowlist snapshot is a security artifact.
    #[cfg(unix)]
    #[test]
    fn export_to_uses_restrictive_mode() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir()
            .join("mcp_writ_test")
            .join(format!("export_mode_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let dest = dir.join("allowlist.json");
        let al = DynamicAllowList::new(16);
        al.register(
            "a.example",
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 5)),
            &[TCP_ANY],
            Duration::from_secs(60),
        );
        al.export_to(&dest).unwrap();
        let mode = std::fs::metadata(&dest).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "export mode was {mode:o}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ---- RF07: indexed layout, staged refcounts, deadline heap ------

    /// xorshift64* — a tiny deterministic stream so the reference-
    /// model trace replays identically run to run.
    struct Xor64(u64);

    impl Xor64 {
        fn next(&mut self) -> u64 {
            let mut x = self.0;
            x ^= x >> 12;
            x ^= x << 25;
            x ^= x >> 27;
            self.0 = x;
            x.wrapping_mul(0x2545_F491_4F6C_DD1D)
        }

        fn pick(&mut self, n: usize) -> usize {
            (self.next() % n as u64) as usize
        }
    }

    /// The flat, full-scan semantics the indexed layout replaced —
    /// the reference the seeded op trace validates every state
    /// transition against. Test-only; never part of the shipped
    /// table.
    struct RefEntry {
        expires: Instant,
        quals: Vec<crate::policy::GrantQual>,
    }

    struct RefList {
        max: usize,
        live: HashMap<(IpAddr, String), RefEntry>,
        staged: HashMap<u64, HashMap<(IpAddr, String), RefEntry>>,
        next_token: u64,
    }

    impl RefList {
        fn new(max: usize) -> Self {
            Self {
                max,
                live: HashMap::new(),
                staged: HashMap::new(),
                next_token: 1,
            }
        }

        fn begin_staging(&mut self) -> u64 {
            let t = self.next_token;
            self.next_token += 1;
            t
        }

        /// The `retain` sweep the flat table ran on every register.
        fn reap(&mut self, now: Instant) {
            self.live.retain(|_, e| e.expires > now);
        }

        fn register_at(
            &mut self,
            name: &str,
            addr: IpAddr,
            quals: &[crate::policy::GrantQual],
            expires: Instant,
            now: Instant,
        ) -> bool {
            if expires <= now || quals.is_empty() {
                return false;
            }
            self.reap(now);
            let k = (addr, name.to_string());
            if let Some(e) = self.live.get_mut(&k) {
                e.expires = expires;
                e.quals = quals.to_vec();
                return true;
            }
            if self.live.len() >= self.max {
                return false;
            }
            self.live.insert(
                k,
                RefEntry {
                    expires,
                    quals: quals.to_vec(),
                },
            );
            true
        }

        /// Unique staged keys that would land as new live grants —
        /// the `staged_new` set the flat code rebuilt per call.
        fn staged_new_len(&self) -> usize {
            let mut keys = std::collections::HashSet::new();
            for entries in self.staged.values() {
                for k in entries.keys() {
                    if !self.live.contains_key(k) {
                        keys.insert(k);
                    }
                }
            }
            keys.len()
        }

        fn register_staged_at(
            &mut self,
            staging: u64,
            name: &str,
            addr: IpAddr,
            quals: &[crate::policy::GrantQual],
            expires: Instant,
            now: Instant,
        ) -> bool {
            if expires <= now || quals.is_empty() {
                return false;
            }
            self.reap(now);
            let k = (addr, name.to_string());
            if let Some(e) = self.staged.get_mut(&staging).and_then(|m| m.get_mut(&k)) {
                e.expires = expires;
                e.quals = quals.to_vec();
                return true;
            }
            if !self.live.contains_key(&k) {
                let already_staged = self.staged.values().any(|m| m.contains_key(&k));
                if !already_staged && self.live.len() + self.staged_new_len() >= self.max {
                    return false;
                }
            }
            self.staged.entry(staging).or_default().insert(
                k,
                RefEntry {
                    expires,
                    quals: quals.to_vec(),
                },
            );
            true
        }

        fn commit_staged(&mut self, staging: u64) {
            if let Some(entries) = self.staged.remove(&staging) {
                for (k, e) in entries {
                    self.live.insert(k, e);
                }
            }
        }

        fn drop_staged(&mut self, staging: u64) {
            self.staged.remove(&staging);
        }

        fn revoke(&mut self, name: &str, addr: IpAddr) {
            self.live.remove(&(addr, name.to_string()));
        }

        /// The same question `grant_view_at` answers, asked of the
        /// flat map: live names on `addr` (sorted) plus coverage.
        fn view_at(
            &self,
            addr: IpAddr,
            proto: crate::policy::EgressProto,
            port: u16,
            now: Instant,
        ) -> (Vec<String>, bool) {
            let mut names = Vec::new();
            let mut covered = false;
            for ((a, name), e) in &self.live {
                if *a == addr && e.expires > now {
                    names.push(name.clone());
                    if !covered {
                        covered = e.quals.iter().any(|q| q.covers(proto, port));
                    }
                }
            }
            names.sort();
            (names, covered)
        }
    }

    /// Structural invariants tying the derived counters back to the
    /// maps they summarize — checked after every traced op.
    fn assert_bookkeeping(al: &DynamicAllowList, rf: &RefList) {
        let inner = al.inner.lock().unwrap();
        let live: usize = inner.by_addr.values().map(|m| m.len()).sum();
        assert_eq!(inner.live_total, live);
        assert_eq!(live, rf.live.len());
        assert_eq!(inner.staged_new, rf.staged_new_len());
        // staged_counts == the multiset of staged keys across tokens.
        let mut holds: HashMap<&GrantKey, usize> = HashMap::new();
        for entries in inner.staged.values() {
            for k in entries.keys() {
                *holds.entry(k).or_default() += 1;
            }
        }
        assert_eq!(inner.staged_counts.len(), holds.len());
        for (k, c) in &inner.staged_counts {
            assert_eq!(holds.get(k), Some(c));
        }
        // staged_new == the staged keys that are not live — the set
        // the reference computes outright.
        let new_keys = holds.keys().filter(|k| !inner.live_has(k)).count();
        assert_eq!(inner.staged_new, new_keys);
        // Every live entry's current generation sits in the heap —
        // reaping relies on that pairing.
        for (addr, names) in &inner.by_addr {
            for (name, e) in names {
                assert!(
                    inner
                        .deadlines
                        .iter()
                        .any(|Reverse((_, g, a, n))| *g == e.generation
                            && *a == *addr
                            && n.as_ref() == name.as_str()),
                    "live entry {name}@{addr} lost its deadline"
                );
            }
        }
    }

    /// Drive identical register / stage / commit / drop / revoke /
    /// reap / check sequences through the indexed table and the flat
    /// reference model — same-key updates, exact expiry boundaries,
    /// TTL shortening, and capacity recovery all fall out of the
    /// seeded trace.
    #[test]
    fn indexed_state_matches_flat_reference_model() {
        use crate::policy::{EgressProto, GrantQual};
        let names = [
            "a.example",
            "b.example",
            "c.example",
            "d.example",
            "e.example",
            "f.example",
        ];
        // Several names pile onto one address — the concentrated-IP
        // shape the index is built for.
        let hot = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10));
        let addrs = [
            hot,
            hot,
            IpAddr::V4(Ipv4Addr::new(198, 51, 100, 20)),
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 30)),
            "2001:db8::40".parse().unwrap(),
            "2001:db8::41".parse().unwrap(),
        ];
        let never_addr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 200));
        let quals_pool: [&[GrantQual]; 4] = [
            &[GrantQual::TCP_ANY],
            &[GrantQual {
                proto: EgressProto::Any,
                port: None,
            }],
            &[GrantQual {
                proto: EgressProto::Udp,
                port: Some(53),
            }],
            &[
                GrantQual {
                    proto: EgressProto::Tcp,
                    port: Some(443),
                },
                GrantQual {
                    proto: EgressProto::Udp,
                    port: Some(443),
                },
            ],
        ];
        let flows: [(EgressProto, u16); 6] = [
            (EgressProto::Tcp, 443),
            (EgressProto::Tcp, 53),
            (EgressProto::Udp, 53),
            (EgressProto::Udp, 443),
            (EgressProto::Any, 80),
            (EgressProto::Tcp, 80),
        ];
        let base = Instant::now();
        // The grid hits every generated expiry exactly — the strict
        // `expires > now` boundary must agree on both sides at the
        // deadline instant.
        let grid: Vec<Instant> = [
            -1i64, 5, 20, 29, 30, 31, 44, 45, 60, 61, 74, 75, 76, 89, 90, 91, 120,
        ]
        .iter()
        .map(|s| {
            if *s < 0 {
                base.checked_sub(Duration::from_secs(1)).unwrap()
            } else {
                base + Duration::from_secs(*s as u64)
            }
        })
        .collect();
        let mut rng = Xor64(0x9E37_79B9_7F4A_7C15);
        let al = DynamicAllowList::new(24);
        let mut rf = RefList::new(24);
        let mut tokens: Vec<(GrantStaging, u64)> = Vec::new();

        // Expiries are either clearly past (refused identically on
        // both sides no matter whose clock reads `now`) or well into
        // the future — nothing sits within a millisecond of the
        // caller's instant, so the trace stays deterministic.
        let expiry_for = |rng: &mut Xor64| -> Instant {
            match rng.pick(8) {
                0 => base.checked_sub(Duration::from_secs(1)).unwrap(),
                n => base + Duration::from_secs([30, 45, 60, 60, 75, 75, 90][n - 1]),
            }
        };

        for step in 0..600 {
            let op = rng.pick(100);
            if op < 12 && tokens.len() < 8 {
                tokens.push((al.begin_staging(), rf.begin_staging()));
            } else if !tokens.is_empty() || op >= 75 {
                let name = names[rng.pick(names.len())];
                let addr = addrs[rng.pick(addrs.len())];
                match op {
                    // Stage a grant under a live token — the same key
                    // from a second token shares its reservation.
                    12..=36 => {
                        let i = rng.pick(tokens.len());
                        let (tok, rtok) = tokens[i];
                        let quals = quals_pool[rng.pick(quals_pool.len())];
                        let exp = expiry_for(&mut rng);
                        assert_eq!(
                            al.register_staged_at(tok, name, addr, quals, exp),
                            rf.register_staged_at(rtok, name, addr, quals, exp, Instant::now()),
                            "register_staged diverged at step {step}"
                        );
                    }
                    // Direct refresh/insert — same-key TTL updates
                    // (including shortenings) land here.
                    37..=52 => {
                        let quals = quals_pool[rng.pick(quals_pool.len())];
                        let exp = expiry_for(&mut rng);
                        assert_eq!(
                            al.register_at(name, addr, quals, exp),
                            rf.register_at(name, addr, quals, exp, Instant::now()),
                            "register diverged at step {step}"
                        );
                    }
                    53..=64 => {
                        let i = rng.pick(tokens.len());
                        let (tok, rtok) = tokens.swap_remove(i);
                        al.commit_staged(tok);
                        rf.commit_staged(rtok);
                    }
                    65..=74 => {
                        let i = rng.pick(tokens.len());
                        let (tok, rtok) = tokens.swap_remove(i);
                        al.drop_staged(tok);
                        rf.drop_staged(rtok);
                    }
                    75..=79 => {
                        al.revoke(name, addr);
                        rf.revoke(name, addr);
                    }
                    // A lazy reap at a grid instant — expiry-driven
                    // capacity recovery, run identically on both.
                    80..=89 => {
                        let at = grid[rng.pick(grid.len())];
                        reap_expired(&mut al.inner.lock().unwrap(), at);
                        rf.reap(at);
                    }
                    _ => {}
                }
            }
            assert_bookkeeping(&al, &rf);
            let at = grid[rng.pick(grid.len())];
            for &addr in addrs.iter().chain(std::iter::once(&never_addr)) {
                for &(proto, port) in &flows {
                    let v = al.grant_view_at(&addr, proto, port, at);
                    let (rn, rc) = rf.view_at(addr, proto, port, at);
                    assert_eq!(
                        (v.names.as_slice(), v.covered),
                        (rn.as_slice(), rc),
                        "view diverged at step {step}: {addr} {proto:?}:{port} @{at:?}"
                    );
                    assert_eq!(al.is_allowed_at(&addr, proto, port, at), v.covered);
                }
            }
        }
    }

    /// One lock's worth of state: the verdict's `covered` flag and the
    /// audit's name list come from the same read — and `names` keeps
    /// the sorted order `names_for` has always returned.
    #[test]
    fn grant_view_names_and_coverage_from_one_snapshot() {
        use crate::policy::{EgressProto, GrantQual};
        let al = DynamicAllowList::new(16);
        let a = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 60));
        let udp53 = GrantQual {
            proto: EgressProto::Udp,
            port: Some(53),
        };
        al.register("b.example", a, &[TCP_ANY], Duration::from_secs(60));
        al.register("a.example", a, &[udp53], Duration::from_secs(60));
        let v = al.grant_view(&a, EgressProto::Tcp, 8443);
        assert_eq!(v.names, vec!["a.example", "b.example"]);
        assert!(v.covered);
        let v = al.grant_view(&a, EgressProto::Udp, 443);
        assert_eq!(v.names, vec!["a.example", "b.example"]);
        assert!(!v.covered);
        let v = al.grant_view(&a, EgressProto::Udp, 53);
        assert!(v.covered);
        // An expired name leaves both halves of the view.
        let v = al.grant_view_at(
            &a,
            EgressProto::Tcp,
            443,
            Instant::now() + Duration::from_secs(90),
        );
        assert!(v.names.is_empty() && !v.covered);
    }

    /// Two names sharing one address keep independent expiries — the
    /// index must not merge them into a single TTL.
    #[test]
    fn same_addr_names_expire_independently() {
        let al = DynamicAllowList::new(16);
        let a = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 61));
        let t0 = Instant::now();
        al.register_at("short.example", a, &[TCP_ANY], t0 + Duration::from_secs(30));
        al.register_at("long.example", a, &[TCP_ANY], t0 + Duration::from_secs(120));
        let at = |s: u64| t0 + Duration::from_secs(s);
        assert_eq!(
            al.grant_view_at(&a, crate::policy::EgressProto::Tcp, 443, at(20))
                .names,
            vec!["long.example", "short.example"]
        );
        reap_expired(&mut al.inner.lock().unwrap(), at(60));
        assert_eq!(
            al.grant_view_at(&a, crate::policy::EgressProto::Tcp, 443, at(61))
                .names,
            vec!["long.example"]
        );
        assert_eq!(al.live_len(), 1);
        assert_eq!(al.names_for(&a), vec!["long.example"]);
    }

    /// Re-staging a key that is already live reserves nothing — but
    /// once that live grant is reaped or revoked, the still-held
    /// staged copy resumes counting as a new-key reservation.
    #[test]
    fn staged_hold_resumes_reservation_when_live_key_reaps() {
        let al = DynamicAllowList::new(2);
        let a = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 62));
        let t0 = Instant::now();
        al.register_at("n.example", a, &[TCP_ANY], t0 + Duration::from_secs(30));
        let s = al.begin_staging();
        // Staging the live key needs no headroom.
        assert!(al.register_staged_at(
            s,
            "n.example",
            a,
            &[TCP_ANY],
            t0 + Duration::from_secs(120)
        ));
        // A second live grant fills the remaining slot.
        assert!(al.register_at("m.example", a, &[TCP_ANY], t0 + Duration::from_secs(120)));
        // n's live grant reaps out from under the staged copy — the
        // hold is a new-key reservation again, and the table is full:
        // live(m)=1 + staged_new(n)=1 == max 2.
        reap_expired(&mut al.inner.lock().unwrap(), t0 + Duration::from_secs(60));
        assert_eq!(al.live_len(), 1);
        let s2 = al.begin_staging();
        assert!(!al.register_staged_at(
            s2,
            "p.example",
            a,
            &[TCP_ANY],
            t0 + Duration::from_secs(120)
        ));
        // Committing s lands n against the reservation it resumed.
        al.commit_staged(s);
        assert_eq!(al.live_len(), 2);
        assert!(al.is_allowed_at(
            &a,
            crate::policy::EgressProto::Tcp,
            443,
            t0 + Duration::from_secs(70)
        ));
    }

    /// A refreshed expiry pushes a new deadline under a bumped
    /// generation; the superseded heap entry must never reap the
    /// refreshed grant — TTL shortenings included.
    #[test]
    fn stale_deadline_never_reaps_refreshed_grant() {
        let al = DynamicAllowList::new(16);
        let a = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 63));
        let t0 = Instant::now();
        // Shortening refresh: the resolver's newer truth (30s) wins,
        // and the superseded 120s deadline reaps nothing it shouldn't.
        al.register_at("n.example", a, &[TCP_ANY], t0 + Duration::from_secs(120));
        al.register_at("n.example", a, &[TCP_ANY], t0 + Duration::from_secs(30));
        reap_expired(&mut al.inner.lock().unwrap(), t0 + Duration::from_secs(45));
        assert_eq!(al.live_len(), 0);
        // Lengthening refresh: the stale 30s deadline pops first and
        // must skip — the grant lives to its 120s truth.
        al.register_at("n.example", a, &[TCP_ANY], t0 + Duration::from_secs(30));
        al.register_at("n.example", a, &[TCP_ANY], t0 + Duration::from_secs(120));
        reap_expired(&mut al.inner.lock().unwrap(), t0 + Duration::from_secs(60));
        assert!(al.is_allowed_at(
            &a,
            crate::policy::EgressProto::Tcp,
            443,
            t0 + Duration::from_secs(90)
        ));
    }

    /// Every refresh strands one stale heap entry — the rebuild bound
    /// keeps the heap proportional to live count, not update count.
    #[test]
    fn deadline_heap_stays_bounded_under_update_churn() {
        let al = DynamicAllowList::new(16);
        let a = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 64));
        for _ in 0..600 {
            assert!(al.register("n.example", a, &[TCP_ANY], Duration::from_secs(60)));
        }
        let inner = al.inner.lock().unwrap();
        assert!(
            inner.deadlines.len() <= usize::max(2 * inner.live_total, DEADLINE_REBUILD_FLOOR) + 1,
            "heap {} vs live {}",
            inner.deadlines.len(),
            inner.live_total
        );
        drop(inner);
        // Churn across many keys tells the same story.
        for i in 0..300u32 {
            let a2 = IpAddr::V4(Ipv4Addr::new(192, 0, 3, (i % 200) as u8));
            al.register("n.example", a2, &[TCP_ANY], Duration::from_secs(60));
        }
        let inner = al.inner.lock().unwrap();
        assert!(
            inner.deadlines.len() <= usize::max(2 * inner.live_total, DEADLINE_REBUILD_FLOOR) + 1,
            "heap {} vs live {}",
            inner.deadlines.len(),
            inner.live_total
        );
    }

    /// Commit batches and revocations strand stale deadlines the
    /// same way refreshes do — both paths compact against the bound
    /// on their own, without a register having to trigger it first.
    #[test]
    fn deadline_heap_compacts_on_commit_and_revoke() {
        let al = DynamicAllowList::new(400);
        let t0 = Instant::now();
        let addr_of =
            |i: u32| IpAddr::V4(Ipv4Addr::new(192, 0, 5 + (i / 256) as u8, (i % 256) as u8));
        for i in 0..300u32 {
            assert!(al.register_at(
                &format!("n{i}.example"),
                addr_of(i),
                &[TCP_ANY],
                t0 + Duration::from_secs(300)
            ));
        }
        // Refresh-commit rounds strand the previous generation per
        // key; the commit-side compaction must hold the bound
        // between rounds — no register intervenes.
        for round in 0..3u32 {
            let s = al.begin_staging();
            for i in 0..300u32 {
                assert!(al.register_staged_at(
                    s,
                    &format!("n{i}.example"),
                    addr_of(i),
                    &[TCP_ANY],
                    t0 + Duration::from_secs(300)
                ));
            }
            al.commit_staged(s);
            let inner = al.inner.lock().unwrap();
            assert!(
                inner.deadlines.len() <= usize::max(2 * inner.live_total, DEADLINE_REBUILD_FLOOR),
                "commit round {round} left {} deadlines over the bound (live {})",
                inner.deadlines.len(),
                inner.live_total
            );
        }
        // Mass-revoke shrinks `live_total` out from under the heap —
        // each successful revoke compacts, so stranded deadlines
        // leave with their grants instead of waiting for a write.
        for i in 0..280u32 {
            al.revoke(&format!("n{i}.example"), addr_of(i));
        }
        let inner = al.inner.lock().unwrap();
        assert_eq!(inner.live_total, 20);
        assert!(
            inner.deadlines.len() <= usize::max(2 * inner.live_total, DEADLINE_REBUILD_FLOOR),
            "revoke left {} deadlines over the bound (live {})",
            inner.deadlines.len(),
            inner.live_total
        );
    }

    /// `expires > now` is strict: at the exact deadline instant the
    /// grant is already closed — the lookup-side check never waits
    /// for the reaper to catch up.
    #[test]
    fn grant_expires_at_its_exact_deadline() {
        let al = DynamicAllowList::new(16);
        let a = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 65));
        let t0 = Instant::now();
        let exp = t0 + Duration::from_secs(30);
        al.register_at("n.example", a, &[TCP_ANY], exp);
        assert!(al.is_allowed_at(
            &a,
            crate::policy::EgressProto::Tcp,
            443,
            exp - Duration::from_millis(1)
        ));
        assert!(!al.is_allowed_at(&a, crate::policy::EgressProto::Tcp, 443, exp));
        let v = al.grant_view_at(&a, crate::policy::EgressProto::Tcp, 443, exp);
        assert!(v.names.is_empty() && !v.covered);
        // And the not-yet-reaped entry denies exactly like a reaped
        // one would.
        assert!(!al.is_allowed_at(
            &a,
            crate::policy::EgressProto::Tcp,
            443,
            t0 + Duration::from_secs(31)
        ));
    }
}
