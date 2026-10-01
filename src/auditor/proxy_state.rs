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
    pub(crate) original_tools_list: Arc<Mutex<HashMap<String, String>>>,
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
    pub(crate) last_list_template: Arc<Mutex<String>>,
    pub(crate) next_internal_id: Arc<AtomicU64>,
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
            last_list_template: self.last_list_template.clone(),
            next_internal_id: self.next_internal_id.clone(),
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
