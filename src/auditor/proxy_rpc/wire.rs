use super::*;

/// What [`WireState::on_request_forwarded`] overwrote — handed back to
/// the caller so a failed forward write can restore the exact prior
/// state together with the registration.
#[derive(Debug)]
pub(crate) struct RequestForwardUndo {
    direction: MessageDirection,
    id: RpcId,
    version: Option<SupportedProtocolVersion>,
    pending_init_capabilities: Option<Vec<String>>,
    /// `elicitationId` this forward newly registered — rollback removes
    /// exactly it, leaving ids other forwards added alone.
    elicitation_inserted: Option<String>,
}

/// Session-wide wire state shared by both relay directions.
///
/// Every fact handed to `decide` is resolved here from forwarded traffic —
/// a message can only reference state the Auditor already recorded, never
/// its own claims.
#[derive(Debug, Default)]
pub(crate) struct WireState {
    /// Established revision — set when the first request forwards. Before
    /// that, unknown envelopes default to 2025-11-25 handling.
    version: Option<SupportedProtocolVersion>,
    /// 2025-11-25 lifecycle stage.
    init: InitStage,
    /// Client capabilities of an in-flight `initialize` request, committed
    /// when its response forwards.
    pending_init_capabilities: Option<Vec<String>>,
    client_capabilities: Vec<String>,
    server_capabilities: Vec<String>,
    /// Active `resources/subscribe` URIs (2025).
    resource_subscriptions: Vec<String>,
    /// URL-mode `elicitationId`s awaiting
    /// `notifications/elicitation/complete` — registered by a forwarded
    /// `elicitation/create` request or a `-32042` error, consumed by the
    /// matching completion notification. Bounded, deduplicated.
    pending_elicitations: Vec<String>,
    /// Session log threshold (`logging/setLevel`, 2025).
    log_level: Option<String>,
    /// In-flight requests keyed by (direction, id). Opposite-direction
    /// same-id requests are distinct keys — a response only ever matches
    /// the opposing-direction entry.
    requests: HashMap<(MessageDirection, RpcId), TrackedRequest>,
    /// Ids of cancelled requests evicted under capacity pressure. The
    /// tracking entry is gone but the id stays retired while held here:
    /// `register` refuses its reuse so a late response can never
    /// correlate to a different request carrying the same id. Retired
    /// ids are NEVER evicted — the peer may still answer them — so a
    /// full set simply makes further reclaim-dependent registrations
    /// fail closed.
    retired_ids: HashSet<(MessageDirection, RpcId)>,
    /// Aggregate serialized bytes retained across all collections.
    wire_bytes: usize,
}

impl WireState {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Serialized bytes a `(direction, id)` map key retains.
    fn key_bytes(id: &RpcId) -> usize {
        size_of::<MessageDirection>() + rpc_id_bytes(id)
    }

    /// Serialized bytes a `requests` entry retains: key + every
    /// peer-controlled string in `TrackedRequest` (method, progress
    /// token, log level, capability names, subscription URIs).
    fn request_bytes(id: &RpcId, entry: &TrackedRequest) -> usize {
        let mut n = Self::key_bytes(id) + entry.method.len();
        if let Some(token) = &entry.progress_token {
            n += rpc_id_bytes(token);
        }
        if let Some(level) = &entry.log_level {
            n += level.len();
        }
        n += entry
            .client_capabilities
            .iter()
            .map(|name| name.len())
            .sum::<usize>();
        if let Some(uri) = &entry.uri {
            n += uri.len();
        }
        if let Some(level) = &entry.level {
            n += level.len();
        }
        if let Some(sub) = &entry.subscription {
            n += sub.acked_uris.iter().map(|uri| uri.len()).sum::<usize>();
            if let Some(uris) = &sub.requested.resource_subscriptions {
                n += uris.iter().map(|uri| uri.len()).sum::<usize>();
            }
        }
        n
    }

    /// True when the entry retains a peer string over the per-value
    /// cap — registration denies such requests outright.
    fn entry_oversized(id: &RpcId, entry: &TrackedRequest) -> bool {
        rpc_id_bytes(id) > MAX_RPC_ID_BYTES
            || entry.method.len() > MAX_RETAINED_VALUE_BYTES
            || entry
                .progress_token
                .as_ref()
                .is_some_and(|token| rpc_id_bytes(token) > MAX_RPC_ID_BYTES)
            || entry
                .log_level
                .as_deref()
                .is_some_and(|v| v.len() > MAX_RETAINED_VALUE_BYTES)
            || entry
                .uri
                .as_deref()
                .is_some_and(|v| v.len() > MAX_RETAINED_VALUE_BYTES)
            || entry
                .level
                .as_deref()
                .is_some_and(|v| v.len() > MAX_RETAINED_VALUE_BYTES)
            || entry
                .client_capabilities
                .iter()
                .any(|v| v.len() > MAX_RETAINED_VALUE_BYTES)
            || entry.subscription.as_ref().is_some_and(|sub| {
                sub.acked_uris
                    .iter()
                    .chain(sub.requested.resource_subscriptions.iter().flatten())
                    .any(|v| v.len() > MAX_RETAINED_VALUE_BYTES)
            })
    }

    /// Charge `n` retained bytes; false without mutation when the
    /// aggregate budget is exhausted (caller fails closed).
    fn charge_bytes(&mut self, n: usize) -> bool {
        if self.wire_bytes.saturating_add(n) > MAX_WIRE_STATE_BYTES {
            return false;
        }
        self.wire_bytes += n;
        true
    }

    /// Refund bytes released by a removal.
    fn refund_bytes(&mut self, n: usize) {
        self.wire_bytes = self.wire_bytes.saturating_sub(n);
    }

    /// Refund the ledger for a request entry that is about to be
    /// removed. `retired` marks the id as retired instead of freed —
    /// the key bytes stay charged because the retired set retains them.
    fn remove_request(
        &mut self,
        key: &(MessageDirection, RpcId),
        retired: bool,
    ) -> Option<TrackedRequest> {
        let entry = self.requests.remove(key)?;
        if retired {
            // Entry strings are released; the id bytes transfer to
            // `retired_ids` (permanent while the peer may still answer).
            self.refund_bytes(Self::request_bytes(&key.1, &entry) - Self::key_bytes(&key.1));
        } else {
            self.refund_bytes(Self::request_bytes(&key.1, &entry));
        }
        Some(entry)
    }

    /// The established wire revision, once any request has forwarded.
    pub(crate) fn wire_version(&self) -> Option<SupportedProtocolVersion> {
        self.version
    }

    /// Revision for frames without a tracked request (notifications,
    /// server requests, uncorrelated responses): the established wire,
    /// defaulting to 2025-11-25 before anything forwards.
    pub(crate) fn passive_version(&self) -> SupportedProtocolVersion {
        self.version.unwrap_or(V25)
    }

    /// Select the revision an incoming C2S request is judged under.
    ///
    /// - An established 2026 wire keeps every frame at 2026.
    /// - `initialize` is 2025-only.
    /// - A `params._meta` `protocolVersion` member claims 2026; on an
    ///   established 2025 wire that is a mid-session switch → denied.
    /// - Otherwise the frame is 2025-11-25.
    pub(crate) fn request_version(
        &self,
        method: &str,
        meta_declares_version: bool,
    ) -> Result<SupportedProtocolVersion, DenyReason> {
        if self.version == Some(V26) {
            return Ok(V26);
        }
        if method == "initialize" {
            return Ok(V25);
        }
        if meta_declares_version {
            return match self.version {
                Some(V25) => Err(DenyReason::MetaVersion),
                _ => Ok(V26),
            };
        }
        Ok(V25)
    }

    pub(crate) fn session_facts(&self) -> SessionFacts<'_> {
        SessionFacts {
            init: self.init,
            client_capabilities: &self.client_capabilities,
            server_capabilities: &self.server_capabilities,
            resource_subscriptions: &self.resource_subscriptions,
            pending_elicitations: &self.pending_elicitations,
            log_level: self.log_level.as_deref(),
        }
    }

    /// Register a request that is about to be forwarded. Errors (null id,
    /// same direction+id collision, capacity) keep the table unchanged —
    /// the caller must deny the request instead of evicting an unanswered
    /// one. At capacity a cancelled, non-subscription entry is reclaimed;
    /// its id moves to `retired_ids` so a late response can never
    /// correlate to a later request that reuses the id.
    pub(crate) fn register(
        &mut self,
        direction: MessageDirection,
        id: RpcId,
        entry: TrackedRequest,
    ) -> Result<(), &'static str> {
        if matches!(id, RpcId::Null) {
            return Err("request id must not be null");
        }
        let key = (direction, id);
        if self.requests.contains_key(&key) {
            return Err("duplicate in-flight request id");
        }
        if self.retired_ids.contains(&key) {
            return Err("request id retired after cancelled-entry reclaim");
        }
        if Self::entry_oversized(&key.1, &entry) {
            return Err("request retains an oversized peer-controlled value");
        }
        // Reclaim selection is side-effect-free: the victim is only
        // removed once every check below has passed, so a failed
        // registration leaves the table and `retired_ids` untouched.
        let reclaim = if self.requests.len() >= MAX_IN_FLIGHT_REQUESTS {
            // Reclaim a cancelled, non-subscription entry — a forwarded
            // cancel must not permanently consume capacity. Its late
            // response loses correlation; a cancelled subscription entry
            // stays because it still resolves ack/notification traffic.
            // The retired set is NEVER evicted: the peer may still
            // answer a retired id, so evicting it would let a stale
            // response complete a later request reusing that id. When
            // the retirement budget is also exhausted the registration
            // fails closed.
            let victim = self
                .requests
                .iter()
                .find(|(_, e)| e.cancelled && e.subscription.is_none())
                .map(|(k, _)| k.clone());
            let Some(victim) = victim else {
                return Err("in-flight request limit reached");
            };
            if self.retired_ids.len() >= MAX_RETIRED_REQUEST_IDS {
                return Err("retired request id budget exhausted");
            }
            Some(victim)
        } else {
            None
        };
        let charge = Self::request_bytes(&key.1, &entry);
        // Judge the ledger against the post-reclaim balance: the
        // victim's entry bytes come back (its id bytes stay charged
        // under `retired_ids`), so the budget check must see the
        // anticipated total rather than the pre-reclaim one.
        let refunded = reclaim
            .as_ref()
            .and_then(|victim| {
                self.requests
                    .get(victim)
                    .map(|e| Self::request_bytes(&victim.1, e) - Self::key_bytes(&victim.1))
            })
            .unwrap_or(0);
        if self
            .wire_bytes
            .saturating_sub(refunded)
            .saturating_add(charge)
            > MAX_WIRE_STATE_BYTES
        {
            return Err("wire ledger byte budget exhausted");
        }
        if let Some(victim) = reclaim {
            // Entry bytes are refunded but the id bytes stay charged —
            // `retired_ids` retains them permanently.
            self.remove_request(&victim, true);
            self.retired_ids.insert(victim);
        }
        // Proven to fit by the anticipated check above — the reclaim
        // refund is already applied, so this cannot hit the cap.
        self.charge_bytes(charge);
        self.requests.insert(key, entry);
        Ok(())
    }

    /// Side-effect-free mirror of [`register`](Self::register)'s
    /// eligibility checks — a caller can deny an unregisterable request
    /// before committing forward-time bookkeeping instead of unwinding
    /// afterwards. `register` stays authoritative: the table may change
    /// between this check and the real registration under the lock.
    pub(crate) fn can_register(
        &self,
        direction: MessageDirection,
        id: &RpcId,
    ) -> Result<(), &'static str> {
        if matches!(id, RpcId::Null) {
            return Err("request id must not be null");
        }
        let key = (direction, id.clone());
        if self.requests.contains_key(&key) {
            return Err("duplicate in-flight request id");
        }
        if self.retired_ids.contains(&key) {
            return Err("request id retired after cancelled-entry reclaim");
        }
        if self.requests.len() >= MAX_IN_FLIGHT_REQUESTS {
            if !self
                .requests
                .iter()
                .any(|(_, e)| e.cancelled && e.subscription.is_none())
            {
                return Err("in-flight request limit reached");
            }
            if self.retired_ids.len() >= MAX_RETIRED_REQUEST_IDS {
                return Err("retired request id budget exhausted");
            }
        }
        if self
            .wire_bytes
            .saturating_add(Self::key_bytes(id))
            .gt(&MAX_WIRE_STATE_BYTES)
        {
            return Err("wire ledger byte budget exhausted");
        }
        Ok(())
    }

    /// Drop a registration (e.g. the forward write failed).
    pub(crate) fn unregister(&mut self, direction: MessageDirection, id: &RpcId) {
        self.remove_request(&(direction, id.clone()), false);
    }

    /// Inspect a tracked request without consuming it.
    pub(crate) fn get(&self, direction: MessageDirection, id: &RpcId) -> Option<&TrackedRequest> {
        self.requests.get(&(direction, id.clone()))
    }

    /// Consume the tracked request a response answers.
    pub(crate) fn take(
        &mut self,
        direction: MessageDirection,
        id: &RpcId,
    ) -> Option<TrackedRequest> {
        self.remove_request(&(direction, id.clone()), false)
    }

    /// Look up the request a response answers without consuming it.
    /// Entries whose response already correlated (`responded` — the
    /// 2026 `subscriptions/listen` case) cannot be answered twice.
    pub(crate) fn answered(
        &self,
        response_direction: MessageDirection,
        id: &RpcId,
    ) -> Option<AnsweredRequest> {
        self.requests
            .get(&(opposite(response_direction), id.clone()))
            .filter(|e| !e.responded)
            .map(|e| AnsweredRequest {
                request_direction: opposite(response_direction),
                method: e.method.clone(),
                // Correlation asks "did this request genuinely reach the
                // peer": a dry-run forward did, even when policy denied
                // it. The raw `allowed` verdict stays on `TrackedRequest`
                // for PR-11's `input_required` gate.
                reached_peer: e.allowed || e.dry_run,
                internal: e.internal,
            })
    }

    /// `notifications/cancelled` correlation: in-flight request travelling
    /// in the notification's own direction; for 2026 S2C cancels, a live
    /// `subscriptions/listen` the subscription id resolved from.
    pub(crate) fn cancel_facts(
        &self,
        direction: MessageDirection,
        id: &RpcId,
        version: SupportedProtocolVersion,
    ) -> CancelFacts {
        if version == V26 && direction == S2C {
            return match self
                .requests
                .get(&(C2S, id.clone()))
                .and_then(|e| e.subscription.as_ref().map(|s| s.state))
            {
                Some(SubscriptionState::PendingAck | SubscriptionState::Active) => {
                    CancelFacts::Subscription
                }
                _ => CancelFacts::Unrelated,
            };
        }
        match self.requests.get(&(direction, id.clone())) {
            Some(_) => CancelFacts::OwnedRequest,
            None => CancelFacts::Unrelated,
        }
    }

    /// `notifications/progress` correlation: the token must belong to an
    /// in-flight request travelling **opposite** the notification — the
    /// responder reports progress to the requester.
    pub(crate) fn progress(
        &self,
        direction: MessageDirection,
        token: &RpcId,
    ) -> ProgressCorrelation {
        let requester = opposite(direction);
        let matched = self
            .requests
            .iter()
            .any(|((d, _), e)| *d == requester && e.progress_token.as_ref() == Some(token));
        if matched {
            ProgressCorrelation::Matched
        } else {
            ProgressCorrelation::Unmatched
        }
    }

    /// 2026 `notifications/message` correlation. stdio has no response
    /// stream to lean on, so resolution order is: `subscriptionId` → the
    /// listen request; `progressToken` → the request carrying it; finally
    /// exactly one in-flight C2S request that declared a `logLevel`.
    /// Anything ambiguous yields `None` — the notification drops.
    pub(crate) fn message_correlation(
        &self,
        subscription_id: Option<&RpcId>,
        progress_token: Option<&RpcId>,
    ) -> Option<MessageCorrelation<'_>> {
        if let Some(id) = subscription_id
            && let Some(entry) = self.requests.get(&(C2S, id.clone()))
            && entry.subscription.is_some()
        {
            return Some(MessageCorrelation {
                log_level: entry.log_level.as_deref(),
            });
        }
        if let Some(token) = progress_token
            && let Some(entry) = self
                .requests
                .iter()
                .find(|((d, _), e)| *d == C2S && e.progress_token.as_ref() == Some(token))
                .map(|(_, e)| e)
        {
            return Some(MessageCorrelation {
                log_level: entry.log_level.as_deref(),
            });
        }
        let mut candidates = self
            .requests
            .iter()
            .filter(|((d, _), e)| *d == C2S && e.log_level.is_some());
        match (candidates.next(), candidates.next()) {
            (Some((_, entry)), None) => Some(MessageCorrelation {
                log_level: entry.log_level.as_deref(),
            }),
            _ => None,
        }
    }

    /// Resolved subscription for a 2026 subscription notification /
    /// ack / cancel.
    pub(crate) fn subscription_facts(&self, id: &RpcId) -> Option<SubscriptionFacts<'_>> {
        let entry = self.requests.get(&(C2S, id.clone()))?;
        let sub = entry.subscription.as_ref()?;
        Some(SubscriptionFacts {
            state: sub.state,
            requested: &sub.requested,
            acked: &sub.acked,
            acked_uris: &sub.acked_uris,
        })
    }

    /// Side effects of a request about to be forwarded, applied under the
    /// same lock as [`register`](Self::register) so a response that lands
    /// the instant the write completes already sees them: establishes the
    /// wire revision on the first C2S request, stashes `initialize`
    /// client capabilities until the response commits them, and registers
    /// a forwarded server `elicitation/create`'s URL-mode `elicitationId`
    /// as pending. The returned token lets
    /// [`rollback_forwarded_request`](Self::rollback_forwarded_request)
    /// restore everything when the write fails.
    pub(crate) fn on_request_forwarded(
        &mut self,
        direction: MessageDirection,
        id: &RpcId,
        method: &str,
        version: SupportedProtocolVersion,
        ext: &ExtractedRequest,
    ) -> RequestForwardUndo {
        let mut undo = RequestForwardUndo {
            direction,
            id: id.clone(),
            version: self.version,
            pending_init_capabilities: self.pending_init_capabilities.clone(),
            elicitation_inserted: None,
        };
        if direction == C2S {
            if self.version.is_none() {
                self.version = Some(version);
            }
            if method == "initialize" {
                self.set_pending_init(Some(ext.initialize_client_capabilities.clone()));
            }
        } else if method == "elicitation/create"
            && let Some(el_id) = &ext.elicitation_id
            && self.track_elicitation(el_id)
        {
            undo.elicitation_inserted = Some(el_id.clone());
        }
        undo
    }

    /// Roll back a request whose forward write failed: drop the
    /// registration and restore the side-effect state the token captured.
    pub(crate) fn rollback_forwarded_request(&mut self, undo: RequestForwardUndo) {
        self.unregister(undo.direction, &undo.id);
        self.version = undo.version;
        self.set_pending_init(undo.pending_init_capabilities);
        if let Some(el_id) = undo.elicitation_inserted {
            self.drop_elicitation(&el_id);
        }
    }

    /// Replace `pending_init_capabilities` under the byte ledger —
    /// oversized names are dropped (never retained) and a full ledger
    /// leaves the slot empty so dependent checks fail closed.
    fn set_pending_init(&mut self, caps: Option<Vec<String>>) {
        if let Some(old) = &self.pending_init_capabilities {
            self.refund_bytes(old.iter().map(|name| name.len()).sum());
        }
        let caps = caps.map(bounded_names);
        if let Some(new) = &caps
            && !self.charge_bytes(new.iter().map(|name| name.len()).sum())
        {
            self.pending_init_capabilities = Some(Vec::new());
            return;
        }
        self.pending_init_capabilities = caps;
    }

    /// Remove `el_id` from `pending_elicitations`, refunding its bytes.
    fn drop_elicitation(&mut self, el_id: &str) {
        let refunded: usize = self
            .pending_elicitations
            .iter()
            .filter(|e| e.as_str() == el_id)
            .map(|e| e.len())
            .sum();
        self.refund_bytes(refunded);
        self.pending_elicitations.retain(|e| e != el_id);
    }

    /// Side effects of a forwarded notification.
    pub(crate) fn on_notification_forwarded(
        &mut self,
        direction: MessageDirection,
        version: SupportedProtocolVersion,
        method: &str,
        ext: &ExtractedNotification,
    ) {
        match (direction, method) {
            (C2S, "notifications/initialized") => {
                self.init = InitStage::Operational;
            }
            (_, "notifications/cancelled") => {
                if let Some(id) = &ext.cancel_id {
                    if version == V26 && direction == S2C {
                        self.end_subscription(id);
                    } else {
                        // Cancelling a completed (`responded`) request —
                        // the subscription-cancel case for a 2026 listen —
                        // retires the entry outright; an in-flight request
                        // keeps its entry so a late response correlates.
                        let responded = self
                            .requests
                            .get(&(direction, id.clone()))
                            .is_some_and(|e| e.responded);
                        if responded {
                            self.remove_request(&(direction, id.clone()), false);
                        } else if let Some(entry) = self.requests.get_mut(&(direction, id.clone()))
                        {
                            entry.cancelled = true;
                            if let Some(sub) = entry.subscription.as_mut() {
                                sub.state = SubscriptionState::Ended;
                            }
                        }
                    }
                }
            }
            (S2C, "notifications/subscriptions/acknowledged") => {
                if let Some(id) = &ext.subscription_id {
                    let key = (C2S, id.clone());
                    // Bound the replacement set before mutating: oversized
                    // URIs drop, and a full ledger keeps the prior ack set.
                    let bounded: Vec<String> = ext
                        .ack_filters
                        .as_ref()
                        .and_then(|f| f.resource_subscriptions.clone())
                        .map(bounded_names)
                        .unwrap_or_default();
                    let new_sum: usize = bounded.iter().map(|u| u.len()).sum();
                    let old_sum: usize = self
                        .requests
                        .get(&key)
                        .and_then(|e| e.subscription.as_ref())
                        .map(|s| s.acked_uris.iter().map(|u| u.len()).sum())
                        .unwrap_or(0);
                    // Charge only the growth delta; a full ledger keeps
                    // the prior ack set (fail closed). Shrinks refund.
                    let chargeable = new_sum <= old_sum || self.charge_bytes(new_sum - old_sum);
                    if let Some(sub) = self
                        .requests
                        .get_mut(&key)
                        .and_then(|e| e.subscription.as_mut())
                    {
                        sub.state = SubscriptionState::Active;
                        if let Some(filters) = &ext.ack_filters {
                            sub.acked = filters.enabled();
                            if chargeable {
                                sub.acked_uris = bounded;
                            }
                        }
                    }
                    if chargeable && new_sum < old_sum {
                        self.refund_bytes(old_sum - new_sum);
                    }
                }
            }
            (S2C, "notifications/elicitation/complete") => {
                // Forwarded completion consumes the pending id it names —
                // the notification's decide already matched it against
                // `pending_elicitations`.
                if let Some(el_id) = &ext.elicitation_id {
                    self.drop_elicitation(el_id);
                }
            }
            _ => {}
        }
    }

    /// Register a URL-mode `elicitationId` as awaiting its
    /// `notifications/elicitation/complete`. Returns `false` when the id
    /// is already tracked or the bound is full — an untracked id simply
    /// fails the notification's correlation check.
    fn track_elicitation(&mut self, elicitation_id: &str) -> bool {
        if elicitation_id.len() > MAX_RETAINED_VALUE_BYTES
            || self
                .pending_elicitations
                .iter()
                .any(|e| e == elicitation_id)
            || self.pending_elicitations.len() >= MAX_PENDING_ELICITATIONS
            || !self.charge_bytes(elicitation_id.len())
        {
            return false;
        }
        self.pending_elicitations.push(elicitation_id.to_string());
        true
    }

    /// Side effects of a forwarded response: commits negotiated
    /// capabilities, the 2025 lifecycle stage, URI subscriptions, and the
    /// log threshold.
    ///
    /// `entry` is the tracked request the response answered (already
    /// consumed by [`take`](Self::take)). `is_result` marks a
    /// non-error completion.
    pub(crate) fn on_response_forwarded(
        &mut self,
        response_direction: MessageDirection,
        entry: &TrackedRequest,
        ext: &ExtractedResponse,
        is_result: bool,
    ) {
        if response_direction == C2S {
            return;
        }
        // A `-32042` URL_ELICITATION_REQUIRED error names the URL-mode
        // elicitations the retry is blocked on; each completes via a
        // `notifications/elicitation/complete` naming its `elicitationId`.
        for el_id in &ext.elicitation_ids {
            self.track_elicitation(el_id);
        }
        if !is_result {
            return;
        }
        match entry.method.as_str() {
            "initialize" => {
                // Client caps were charged when `pending_init_capabilities`
                // was set — the move transfers ownership without a new
                // charge; a re-initialize refunds the displaced list.
                self.refund_bytes(self.client_capabilities.iter().map(|name| name.len()).sum());
                self.client_capabilities =
                    self.pending_init_capabilities.take().unwrap_or_default();
                let server = bounded_names(ext.initialize_server_capabilities.clone());
                self.refund_bytes(self.server_capabilities.iter().map(|name| name.len()).sum());
                self.server_capabilities = Vec::new();
                if self.charge_bytes(server.iter().map(|name| name.len()).sum()) {
                    self.server_capabilities = server;
                }
                self.init = InitStage::AwaitingInitialized;
            }
            "resources/subscribe" => {
                if let Some(uri) = &entry.uri
                    && !self.resource_subscriptions.contains(uri)
                    && self.resource_subscriptions.len() < MAX_RESOURCE_SUBSCRIPTIONS
                    && uri.len() <= MAX_RETAINED_VALUE_BYTES
                    && self.charge_bytes(uri.len())
                {
                    self.resource_subscriptions.push(uri.clone());
                }
            }
            "resources/unsubscribe" => {
                if let Some(uri) = &entry.uri {
                    let refunded: usize = self
                        .resource_subscriptions
                        .iter()
                        .filter(|u| *u == uri)
                        .map(|u| u.len())
                        .sum();
                    self.refund_bytes(refunded);
                    self.resource_subscriptions.retain(|u| u != uri);
                }
            }
            "logging/setLevel" => {
                if let Some(level) = &entry.level {
                    if let Some(old) = &self.log_level {
                        self.refund_bytes(old.len());
                    }
                    self.log_level = None;
                    if level.len() <= MAX_RETAINED_VALUE_BYTES && self.charge_bytes(level.len()) {
                        self.log_level = Some(level.clone());
                    }
                }
            }
            _ => {}
        }
    }

    /// Mark a 2026 subscription ended (a forwarded
    /// `notifications/cancelled` carrying the subscription id). When the
    /// listen request already completed the entry is removed; when it is
    /// still in flight the `Ended` state lets its late response correlate
    /// while new subscription traffic drops.
    fn end_subscription(&mut self, id: &RpcId) {
        let key = (C2S, id.clone());
        let responded = self.requests.get(&key).is_some_and(|e| e.responded);
        if responded {
            self.remove_request(&key, false);
            return;
        }
        if let Some(sub) = self
            .requests
            .get_mut(&key)
            .and_then(|e| e.subscription.as_mut())
        {
            sub.state = SubscriptionState::Ended;
        }
    }

    /// A response to a `subscriptions/listen` request correlated and is
    /// about to forward: the request completes but the subscription —
    /// keyed by the same id — keeps the entry for ack / notification /
    /// cancel resolution. A second response no longer correlates.
    /// A subscription already `Ended` (cancel forwarded first) frees the
    /// entry, which is returned for the caller's audit bookkeeping.
    pub(crate) fn mark_responded(
        &mut self,
        direction: MessageDirection,
        id: &RpcId,
    ) -> Option<TrackedRequest> {
        let key = (direction, id.clone());
        let entry = self.requests.get_mut(&key)?;
        entry.responded = true;
        let ended = entry
            .subscription
            .as_ref()
            .is_some_and(|s| s.state == SubscriptionState::Ended);
        if ended || entry.cancelled {
            return self.remove_request(&key, false);
        }
        None
    }

    /// `initialize` result check the decision model cannot express: the
    /// negotiated `protocolVersion` must be in
    /// [`SUPPORTED_INITIALIZE_VERSIONS`] — `2025-11-25` only; a
    /// `2026-07-28` answer is rejected like any unimplemented revision.
    pub(crate) fn initialize_result_version_ok(ext: &ExtractedResponse) -> bool {
        ext.initialize_protocol_version
            .as_deref()
            .is_some_and(|v| SUPPORTED_INITIALIZE_VERSIONS.contains(&v))
    }
}

#[cfg(test)]
mod tests;
