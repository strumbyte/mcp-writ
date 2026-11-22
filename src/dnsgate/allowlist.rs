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

/// Sparse-bucket bound shared by the reap and revoke removals: a
/// kept inner map shrinks once its allocation exceeds this multiple
/// of its population — the bucket stays, but not an allocation still
/// sized for names already gone.
const BUCKET_SHRINK_FACTOR: usize = 4;

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
        remove_from_bucket(inner, addr, &name);
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

/// Remove `name` from `addr`'s bucket — `true` when a grant left.
/// The empty bucket drops out of `by_addr` entirely; a kept one
/// shrinks once its capacity outgrows `BUCKET_SHRINK_FACTOR`, the
/// same policy on both removal paths so a concentrated address's
/// map cannot retain an allocation sized for names already gone.
fn remove_from_bucket(inner: &mut Inner, addr: IpAddr, name: &str) -> bool {
    let Some(m) = inner.by_addr.get_mut(&addr) else {
        return false;
    };
    if m.remove(name).is_none() {
        return false;
    }
    if m.is_empty() {
        inner.by_addr.remove(&addr);
    } else if m.capacity() > m.len().saturating_mul(BUCKET_SHRINK_FACTOR) {
        m.shrink_to_fit();
    }
    true
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
pub struct GrantView {
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

/// The `is_allowed*` body — the per-address qualifier scan shared by
/// the under-lock `is_allowed` and its caller-clocked variant.
fn is_allowed_of(
    inner: &Inner,
    addr: &IpAddr,
    proto: crate::policy::EgressProto,
    port: u16,
    now: Instant,
) -> bool {
    inner.by_addr.get(addr).is_some_and(|m| {
        m.values().any(|e| {
            #[cfg(feature = "measure")]
            crate::measure::incr(&crate::measure::DNS_SCAN_ENTRIES, 1);
            e.expires > now && e.quals.iter().any(|q| q.covers(proto, port))
        })
    })
}

/// The `register_at*` body run under the table lock — refusal, lazy
/// reap, and the refresh-or-insert all at `now`, the instant the
/// caller chose: sampled under the lock by `register_at`, injected by
/// `register_at_clock`.
fn register_at_of(
    inner: &mut Inner,
    max_grants: usize,
    name: &str,
    addr: IpAddr,
    quals: &[crate::policy::GrantQual],
    expires: Instant,
    now: Instant,
) -> bool {
    if expires <= now || quals.is_empty() {
        return false;
    }
    // Reborrow the `&mut Inner` once — field-split borrows let the
    // refresh path hold its entry while the deadline heap is written
    // alongside.
    let inner = &mut *inner;
    reap_expired(inner, now);
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
        compact_deadlines(inner);
        return true;
    }
    if inner.live_total >= max_grants {
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
    compact_deadlines(inner);
    true
}

/// The `register_staged_at*` body run under the table lock — same
/// refusals and lazy reap as `register_at_of`, at the caller's `now`,
/// but the grant lands in the staged set instead of the live table.
#[expect(clippy::too_many_arguments)] // mirrors the method's parameter list
fn register_staged_at_of(
    inner: &mut Inner,
    max_grants: usize,
    staging: GrantStaging,
    name: &str,
    addr: IpAddr,
    quals: &[crate::policy::GrantQual],
    expires: Instant,
    now: Instant,
) -> bool {
    if expires <= now || quals.is_empty() {
        return false;
    }
    reap_expired(inner, now);
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
        if inner.live_total + inner.staged_new >= max_grants {
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
    /// [`Self::register`]. The reference instant is sampled under the
    /// lock, as in `is_allowed` — the refusal check and the lazy reap
    /// run at the instant the table is actually examined.
    pub(crate) fn register_at(
        &self,
        name: &str,
        addr: IpAddr,
        quals: &[crate::policy::GrantQual],
        expires: Instant,
    ) -> bool {
        let mut inner = self.inner.lock().unwrap();
        #[cfg(feature = "measure")]
        let _lock_hold = crate::measure::Timer::new(&crate::measure::DNS_LOCK_NS);
        register_at_of(
            &mut inner,
            self.max_grants,
            name,
            addr,
            quals,
            expires,
            Instant::now(),
        )
    }

    /// [`Self::register_at`] against a caller-chosen instant — the
    /// refusal check and the lazy reap share one clock, letting the
    /// reference-model trace drive a monotone logical time.
    #[allow(dead_code)] // used by the RF07 tests
    pub(crate) fn register_at_clock(
        &self,
        name: &str,
        addr: IpAddr,
        quals: &[crate::policy::GrantQual],
        expires: Instant,
        now: Instant,
    ) -> bool {
        if expires <= now || quals.is_empty() {
            return false;
        }
        let mut inner = self.inner.lock().unwrap();
        #[cfg(feature = "measure")]
        let _lock_hold = crate::measure::Timer::new(&crate::measure::DNS_LOCK_NS);
        register_at_of(&mut inner, self.max_grants, name, addr, quals, expires, now)
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
    /// core, mirroring `register_at`: the reference instant is sampled
    /// under the lock so the refusal check and the lazy reap share the
    /// instant the table is examined at.
    pub(crate) fn register_staged_at(
        &self,
        staging: GrantStaging,
        name: &str,
        addr: IpAddr,
        quals: &[crate::policy::GrantQual],
        expires: Instant,
    ) -> bool {
        let mut inner = self.inner.lock().unwrap();
        #[cfg(feature = "measure")]
        let _lock_hold = crate::measure::Timer::new(&crate::measure::DNS_LOCK_NS);
        register_staged_at_of(
            &mut inner,
            self.max_grants,
            staging,
            name,
            addr,
            quals,
            expires,
            Instant::now(),
        )
    }

    /// [`Self::register_staged_at`] against a caller-chosen instant —
    /// mirrors `register_at_clock` for the staged path.
    #[allow(dead_code)] // used by the RF07 tests
    pub(crate) fn register_staged_at_clock(
        &self,
        staging: GrantStaging,
        name: &str,
        addr: IpAddr,
        quals: &[crate::policy::GrantQual],
        expires: Instant,
        now: Instant,
    ) -> bool {
        if expires <= now || quals.is_empty() {
            return false;
        }
        let mut inner = self.inner.lock().unwrap();
        #[cfg(feature = "measure")]
        let _lock_hold = crate::measure::Timer::new(&crate::measure::DNS_LOCK_NS);
        register_staged_at_of(
            &mut inner,
            self.max_grants,
            staging,
            name,
            addr,
            quals,
            expires,
            now,
        )
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
        let removed = remove_from_bucket(&mut inner, addr, name);
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
        // The reference instant is sampled under the lock, as in
        // `grant_view` — a grant that lapses between sample and
        // acquisition must not be reported live.
        let inner = self.inner.lock().unwrap();
        #[cfg(feature = "measure")]
        let _lock_hold = crate::measure::Timer::new(&crate::measure::DNS_LOCK_NS);
        is_allowed_of(&inner, addr, proto, port, Instant::now())
    }

    /// [`Self::is_allowed`] at a caller-chosen instant — the testable
    /// core, keeping the lookup-side expiry check independent of
    /// reaper timing.
    #[allow(dead_code)] // used by the RF07 tests
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
        is_allowed_of(&inner, addr, proto, port, now)
    }

    /// One endpoint's grant state under a single lock acquisition —
    /// the live names that vended it (audit detail) and whether any
    /// of their qualifiers cover the `proto`/`port` flow. Both halves
    /// come from the same snapshot, so a commit cannot interleave
    /// between a verdict's answer and its audit names. `names` is
    /// sorted — the same order [`Self::names_for`] returns — and
    /// `covered` is the same answer [`Self::is_allowed`] gives.
    pub fn grant_view(
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
        let inner = self.inner.lock().unwrap();
        #[cfg(feature = "measure")]
        let _lock_hold = crate::measure::Timer::new(&crate::measure::DNS_LOCK_NS);
        let now = Instant::now();
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
        let inner = self.inner.lock().unwrap();
        #[cfg(feature = "measure")]
        let _lock_hold = crate::measure::Timer::new(&crate::measure::DNS_LOCK_NS);
        let now = Instant::now();
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
        let inner = self.inner.lock().unwrap();
        #[cfg(feature = "measure")]
        let _lock_hold = crate::measure::Timer::new(&crate::measure::DNS_LOCK_NS);
        let now = Instant::now();
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
        let inner = self.inner.lock().unwrap();
        #[cfg(feature = "measure")]
        let _lock_hold = crate::measure::Timer::new(&crate::measure::DNS_LOCK_NS);
        // The reference instant is sampled under the lock like the
        // lookups — grants that lapse before acquisition are left
        // out of the snapshot entirely.
        let now = Instant::now();
        let now_wall = SystemTime::now();
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
mod tests;
