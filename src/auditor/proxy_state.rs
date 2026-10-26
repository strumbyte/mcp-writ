//! Shared state between the client→server and server→client relay halves of
//! `run_proxy`, plus the bounded set of in-flight tools/list request ids.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64};

use tokio::sync::{Mutex, watch};

use super::proxy_rpc::WireState;
use super::session::{RpcId, SessionState};
use crate::audit_log::AuditLogger;
use crate::policy::Policy;
use crate::verifier::fail_on::FailOn;

/// Bounded set of in-flight tools/list request ids.
///
/// Entries are removed only when the matching response arrives. At capacity,
/// new ids are rejected so unanswered ids are never discarded.
pub(crate) const MAX_PENDING_TOOLS_LIST: usize = 128;

/// Aggregate byte budget for `original_tools_list`: each retained value
/// is a full client request frame, so the cap bounds what outstanding
/// listings (and any leaked entries) can hold.
pub(crate) const MAX_ORIGINAL_TOOLS_LIST_BYTES: usize = 8 * 1024 * 1024;

/// True when tools/list verification is enforced for this session — a
/// pinned `tools-list-hash` entry or manifest scanning (`fail-on`
/// stricter than `none`). While active, `tools/call` fails closed
/// until the first verified listing publishes `list_generation > 0`.
pub(crate) fn list_verification_required(policy: &Policy, fail_on: FailOn) -> bool {
    !policy.tools_list_hashes.is_empty() || fail_on != FailOn::None
}

/// The tool-name set the last verified `tools/list` advertised to the
/// client — paired with the generation it published under.
///
/// `names` holds exactly what the client-facing response emitted: the
/// policy-visible subset in enforce mode, the full advertised set in
/// dry-run. `tools/call` is admitted only when the called name is a
/// member — a statically allowed tool the verified listing omitted is
/// refused, because the client could never have learned it was offered.
pub(crate) struct VerifiedToolSet {
    /// Same counter as `list_generation`: bumped once per verified
    /// manifest, so `generation` and `names` always move together.
    pub(crate) generation: u64,
    pub(crate) names: std::collections::HashSet<String>,
}

pub(crate) struct PendingToolsList {
    ids: std::collections::VecDeque<RpcId>,
}

impl PendingToolsList {
    pub(crate) fn new() -> Self {
        Self {
            ids: std::collections::VecDeque::new(),
        }
    }

    /// Record `id` until its response arrives.
    ///
    /// Returns `false` when the set is full or `id` is already in flight.
    pub(crate) fn try_insert(&mut self, id: RpcId) -> bool {
        if matches!(id, RpcId::Null) {
            return false;
        }
        if self.ids.iter().any(|existing| existing == &id) {
            return false;
        }
        if self.ids.len() >= MAX_PENDING_TOOLS_LIST {
            return false;
        }
        self.ids.push_back(id);
        true
    }

    pub(crate) fn remove(&mut self, id: &RpcId) -> bool {
        if let Some(index) = self.ids.iter().position(|existing| existing == id) {
            self.ids.remove(index);
            true
        } else {
            false
        }
    }

    /// Check membership without consuming the entry.
    pub(crate) fn contains(&self, id: &RpcId) -> bool {
        self.ids.iter().any(|existing| existing == id)
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.ids.is_empty()
    }
}

/// State shared by the two relay directions of `run_proxy`.
///
/// One instance is built per proxy session; each direction holds a clone of
/// the `Arc` fields so `list_busy`, the pending list set, and the abort
/// channel observe the same underlying state.
pub(crate) struct ProxyShared<W> {
    pub(crate) policy: Policy,
    pub(crate) dry_run: bool,
    pub(crate) fail_on: FailOn,
    /// Configured JSON-RPC frame cap (`--max-frame-bytes`) applied by
    /// both relay directions' readers.
    pub(crate) max_frame_bytes: usize,
    pub(crate) audit: Arc<AuditLogger>,
    /// Process-local session: Confused Deputy and/or trajectory (never requestState).
    pub(crate) session: Option<Arc<Mutex<SessionState>>>,
    /// Bidirectional MCP correlation: established revision, 2025
    /// lifecycle, negotiated capabilities, and the bounded table of
    /// in-flight requests in both directions.
    pub(crate) wire: Arc<Mutex<WireState>>,
    pub(crate) pending_tools_list: Arc<Mutex<PendingToolsList>>,
    pub(crate) client_out: Arc<Mutex<tokio::io::Stdout>>,
    /// Both relay directions can write (internal tools/list requests use S2C).
    /// `Option` lets client EOF close the actual pipe even while the other
    /// direction holds an `Arc`.
    pub(crate) child_stdin: Arc<Mutex<Option<W>>>,
    /// Retained `tools/list` request frames keyed by the request's
    /// canonical [`RpcId`] — a canonically-equal-but-differently-spelled
    /// response/cancel (`1` vs `1.0`) resolves the same entry, so no
    /// raw-keyed copy can leak. Values stay bounded by
    /// [`MAX_ORIGINAL_TOOLS_LIST_BYTES`].
    pub(crate) original_tools_list: Arc<Mutex<HashMap<RpcId, String>>>,
    /// Busy gate for the tools/list path: C2S raises it when a client
    /// `tools/list` registers. Only the S2C side ever clears it — when
    /// the verified emit completes, or when `resume_queued_revalidation`
    /// finds nothing queued after checking `st.idle()` and
    /// `pending_tools_list` (a gate owned by a newer listing is never
    /// lowered underneath it). C2S unwinds via `list_kick`, never a
    /// `store(false)` of its own.
    pub(crate) list_busy: Arc<AtomicBool>,
    /// C2S→S2C kick: wakes the S2C loop to drive a queued revalidation
    /// after a client `tools/list` was cancelled mid-flight.
    ///
    /// Invariant for future kick sources: a kick only *wakes* — it must
    /// never carry authority to release `list_busy`. The gate is dropped
    /// solely by `resume_queued_revalidation` after inspecting what is
    /// actually queued and which client listings are still pending, and
    /// every current kick origin (a cancelled client listing, a refused
    /// registration / failed write, a registration that lost the
    /// busy-gate CAS) either names the dead request or happens while
    /// the session is already unwinding — so a stale kick can never
    /// lower the gate underneath an unbound listing. Keep that property
    /// when adding sources: a kick that can outlive the request it was
    /// sent for needs the `cancelled_list_id` slot (or an equivalent
    /// binding) to stay safe.
    pub(crate) list_kick: Arc<tokio::sync::Notify>,
    /// Canonical id of the most recently cancelled client `tools/list`,
    /// handed to the S2C loop so it can release the half-collected state
    /// bound to that request (at most one client listing can be in
    /// flight, so a single slot suffices).
    pub(crate) cancelled_list_id: Arc<Mutex<Option<RpcId>>>,
    /// A client `tools/list` that lost the busy-gate CAS to an internal
    /// listing — the post-`initialize` probe or a `list_changed`
    /// revalidation — held rather than refused. It is never forwarded on
    /// its own: the S2C side answers it from the verified emit when the
    /// in-flight listing settles, or with an error when that listing
    /// unwinds — including the abort drain on the C2S side, which reads
    /// this slot when `internal_list_failure` is set. Single slot — a
    /// second racing listing is refused. The tuple is `(canonical id,
    /// raw id)`; the request line is not kept because the answer is
    /// rebuilt, never replayed.
    pub(crate) held_client_list: Arc<Mutex<Option<(RpcId, String)>>>,
    /// The failure detail of an internally-owned listing whose failure
    /// is aborting the session — set by the S2C side before `abort_tx`
    /// fires so the C2S abort drain can answer a coalesced client
    /// `tools/list` (held, or still in transit in the stdin pipe) under
    /// its own id instead of leaving it to EOF. The bool records
    /// whether the failing path already emitted a client-visible reply
    /// on a real request id — the drain then skips its `id: null`
    /// fallback, the abort being observable already.
    pub(crate) internal_list_failure: Arc<Mutex<Option<(String, bool)>>>,
    /// Verified tools/list generation: `0` while no verified manifest has
    /// been published, bumped once per successful verification — after
    /// the committed `tools_list.verified` record and before `list_busy`
    /// drops. When [`list_verification_required`] holds, `tools/call`
    /// captures this at admission and re-checks it (together with the
    /// busy gate, which a revalidation raises *before* it starts) right
    /// before the child write — a mismatch unwinds and denies the call.
    /// The atomic mirrors `verified_tools`'s generation for readers that
    /// only need the number; the mutexed pair is authoritative.
    pub(crate) list_generation: Arc<AtomicU64>,
    /// The (generation, advertised-name-set) pair `tools/call`
    /// authorization is bound to — updated under one lock at verified
    /// publish so an admission captures both atomically and the
    /// pre-write recheck observes the identical pair. A server cannot
    /// keep an authorized channel to a tool it omitted from the
    /// verified listing: membership in the emitted set is checked at
    /// admission, not just the generation number.
    pub(crate) verified_tools: Arc<std::sync::Mutex<VerifiedToolSet>>,
    pub(crate) last_list_template: Arc<Mutex<String>>,
    pub(crate) next_internal_id: Arc<AtomicU64>,
    /// Whether the once-per-session `init-order` stderr diagnostic was
    /// already emitted — per-request warns would flood stderr on a
    /// mis-ordering client, so only the first denial in either
    /// direction logs (the wire error repeats on every denial).
    pub(crate) init_order_warned: Arc<AtomicBool>,
    /// Cancellation signal shared between S2C and C2S to immediately abort session.
    pub(crate) abort_tx: watch::Sender<bool>,
}

// Manual impl: `W` lives behind `Arc<Mutex<Option<W>>>`, so cloning a
// direction handle must not require `W: Clone`.
impl<W> Clone for ProxyShared<W> {
    fn clone(&self) -> Self {
        Self {
            policy: self.policy.clone(),
            dry_run: self.dry_run,
            fail_on: self.fail_on,
            max_frame_bytes: self.max_frame_bytes,
            audit: self.audit.clone(),
            session: self.session.clone(),
            wire: self.wire.clone(),
            pending_tools_list: self.pending_tools_list.clone(),
            client_out: self.client_out.clone(),
            child_stdin: self.child_stdin.clone(),
            original_tools_list: self.original_tools_list.clone(),
            list_busy: self.list_busy.clone(),
            list_kick: self.list_kick.clone(),
            cancelled_list_id: self.cancelled_list_id.clone(),
            held_client_list: self.held_client_list.clone(),
            internal_list_failure: self.internal_list_failure.clone(),
            list_generation: self.list_generation.clone(),
            verified_tools: self.verified_tools.clone(),
            last_list_template: self.last_list_template.clone(),
            next_internal_id: self.next_internal_id.clone(),
            init_order_warned: self.init_order_warned.clone(),
            abort_tx: self.abort_tx.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pending_tools_list_does_not_drop_unanswered_ids() {
        let mut pending = PendingToolsList::new();
        for i in 0..MAX_PENDING_TOOLS_LIST {
            assert!(pending.try_insert(RpcId::Number(i.to_string())));
        }
        assert!(!pending.try_insert(RpcId::String("overflow".into())));
        assert!(pending.remove(&RpcId::Number("0".into())));
        assert!(!pending.remove(&RpcId::String("overflow".into())));
        assert!(pending.try_insert(RpcId::String("overflow".into())));
        assert!(!pending.try_insert(RpcId::String("overflow".into())));
    }

    #[test]
    fn test_pending_tools_list_rejects_null_id() {
        let mut pending = PendingToolsList::new();
        assert!(!pending.try_insert(RpcId::Null));
        assert!(!pending.remove(&RpcId::Null));
        assert!(pending.try_insert(RpcId::Number("1".into())));
    }

    #[test]
    fn test_pending_tools_list_contains_does_not_consume() {
        let mut pending = PendingToolsList::new();
        assert!(pending.try_insert(RpcId::Number("7".into())));
        assert!(pending.contains(&RpcId::Number("7".into())));
        assert!(!pending.contains(&RpcId::Number("8".into())));
        assert!(pending.contains(&RpcId::Number("7".into())));
        assert!(pending.remove(&RpcId::Number("7".into())));
        assert!(!pending.contains(&RpcId::Number("7".into())));
    }
}
