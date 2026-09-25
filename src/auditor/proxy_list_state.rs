//! State transitions for one server-to-client tools/list collection.
//! Fields stay private so pagination, client correlation and queued
//! revalidation are updated together. I/O and the shared busy flag belong
//! to the relay, which must keep calls blocked until verification finishes.

use std::collections::HashSet;

use crate::protocol::tools_list::MAX_PAGES;
use crate::tool_def::ToolDefinition;

#[derive(Default)]
pub(crate) struct S2cListState {
    accumulated_tools: Vec<ToolDefinition>,
    result_extras: Vec<(String, String)>,
    collecting_client_id: Option<String>,
    collecting_original: String,
    waiting_internal_id: Option<String>,
    seen_cursors: HashSet<String>,
    page_count: usize,
    held_list_changed: Option<String>,
    pending_revalidate: bool,
    internal_revalidation: bool,
    last_verified: Option<String>,
}

impl S2cListState {
    pub(super) fn new() -> Self {
        Self::default()
    }

    /// Hold the latest notification and report whether a listing already
    /// in flight must finish before the queued revalidation can start.
    pub(super) fn hold_list_changed(&mut self, line: &str, already_busy: bool) -> bool {
        self.held_list_changed = Some(line.to_owned());
        let in_flight = already_busy
            || self.collecting_client_id.is_some()
            || self.waiting_internal_id.is_some()
            || !self.accumulated_tools.is_empty();
        if in_flight {
            self.pending_revalidate = true;
        }
        in_flight
    }

    pub(super) fn begin_revalidation(&mut self, template: String, internal_id: u64) {
        self.internal_revalidation = true;
        self.discard_pages();
        self.collecting_original = template;
        self.expect_internal_response(internal_id);
    }

    pub(super) fn needs_client_binding(&self) -> bool {
        self.collecting_client_id.is_none() && !self.internal_revalidation
    }

    pub(super) fn bind_client(&mut self, id: String, original: String) {
        self.collecting_client_id = Some(id);
        self.collecting_original = original;
    }

    pub(super) fn client_id(&self) -> Option<&str> {
        self.collecting_client_id.as_deref()
    }

    pub(super) fn take_client_id(&mut self) -> Option<String> {
        self.collecting_client_id.take()
    }

    pub(super) fn original_request(&self) -> &str {
        &self.collecting_original
    }

    pub(super) fn is_internal_response(&self, raw_id: Option<&str>) -> bool {
        self.waiting_internal_id.is_some() && self.waiting_internal_id.as_deref() == raw_id
    }

    pub(super) fn expect_internal_response(&mut self, internal_id: u64) {
        self.waiting_internal_id = Some(internal_id.to_string());
    }

    pub(super) fn append_page(&mut self, tools: Vec<ToolDefinition>) -> Result<(), String> {
        self.accumulated_tools.extend(tools);
        self.page_count += 1;
        if self.page_count > MAX_PAGES {
            return Err("tools/list exceeded max page limit".to_owned());
        }
        Ok(())
    }

    pub(super) fn record_cursor(&mut self, cursor: &str) -> Result<(), String> {
        if !self.seen_cursors.insert(cursor.to_owned()) {
            return Err(format!("repeated tools/list cursor '{cursor}'"));
        }
        Ok(())
    }

    /// Result-level members (`resultType`, `ttlMs`, `cacheScope`, `_meta`,
    /// vendor keys) travel beside the accumulated tools — the client-facing
    /// response is rebuilt and must forward them verbatim. Merged per key
    /// across pages: the latest page carrying a name wins.
    pub(super) fn record_result_extras(&mut self, extras: Vec<(String, String)>) {
        for (name, raw) in extras {
            self.result_extras.retain(|(k, _)| *k != name);
            self.result_extras.push((name, raw));
        }
    }

    /// Completing pagination does not complete verification. Keep held
    /// notifications and revalidation state until the verified result is emitted.
    #[allow(clippy::type_complexity)]
    pub(super) fn take_completed_pages(
        &mut self,
    ) -> (Vec<ToolDefinition>, Option<String>, Vec<(String, String)>) {
        let tools = std::mem::take(&mut self.accumulated_tools);
        let client_id = self.take_client_id();
        let extras = std::mem::take(&mut self.result_extras);
        self.discard_pages();
        (tools, client_id, extras)
    }

    /// An error discards the page buffer but preserves the client ID and
    /// revalidation context needed to correlate the error and abort safely.
    pub(super) fn discard_pages(&mut self) {
        self.accumulated_tools.clear();
        self.result_extras.clear();
        self.page_count = 0;
        self.seen_cursors.clear();
        self.waiting_internal_id = None;
    }

    pub(super) fn is_revalidating(&self) -> bool {
        self.internal_revalidation
    }

    pub(super) fn requires_abort_on_error(&self) -> bool {
        self.internal_revalidation || self.held_list_changed.is_some()
    }

    pub(super) fn has_incomplete_listing(&self) -> bool {
        self.collecting_client_id.is_some() || self.requires_abort_on_error()
    }

    /// Record the digest of a successfully verified listing. Returns the
    /// recorded digest and whether it differs from the previously recorded
    /// one — an unchanged digest means the advertised set is identical.
    pub(super) fn record_verified_digest(&mut self, digest: String) -> (&str, bool) {
        let changed = self.last_verified.as_deref() != Some(digest.as_str());
        if changed {
            self.last_verified = Some(digest);
        }
        (self.last_verified.as_deref().unwrap_or(""), changed)
    }

    pub(super) fn take_queued_revalidation(&mut self) -> bool {
        std::mem::take(&mut self.pending_revalidate)
    }

    pub(super) fn take_verified_notification(&mut self) -> Option<String> {
        self.held_list_changed.take()
    }

    pub(super) fn finish_verification(&mut self) {
        self.internal_revalidation = false;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_pagination_preserves_correlation_and_resets_page_limits() {
        let mut state = S2cListState::new();
        state.bind_client("\"client\"".into(), "original request".into());
        state
            .append_page(vec![ToolDefinition::new("first", "")])
            .unwrap();
        state.record_cursor("next").unwrap();
        state.expect_internal_response(910_001);
        assert!(state.is_internal_response(Some("910001")));
        assert!(!state.is_internal_response(None));
        state
            .append_page(vec![ToolDefinition::new("second", "")])
            .unwrap();

        let (tools, client_id, _) = state.take_completed_pages();
        assert_eq!(client_id.as_deref(), Some("\"client\""));
        assert_eq!(
            tools
                .iter()
                .map(|tool| tool.name.as_str())
                .collect::<Vec<_>>(),
            ["first", "second"]
        );
        assert!(!state.is_internal_response(Some("910001")));
        assert!(state.needs_client_binding());
        state
            .record_cursor("next")
            .expect("cursor belongs to a new listing");
        for _ in 0..MAX_PAGES {
            state.append_page(Vec::new()).unwrap();
        }
        assert!(state.append_page(Vec::new()).is_err());
    }

    #[test]
    fn notification_before_first_client_page_requires_a_later_revalidation() {
        let mut state = S2cListState::new();
        assert!(state.hold_list_changed("first notification", true));
        state.bind_client("7".into(), "request".into());
        state.append_page(Vec::new()).unwrap();
        assert_eq!(state.take_completed_pages().1.as_deref(), Some("7"));
        assert!(state.has_incomplete_listing());
        assert!(state.take_queued_revalidation());
        assert!(!state.take_queued_revalidation());

        state.begin_revalidation("request".into(), 910_001);
        assert!(state.hold_list_changed("latest notification", true));
        state.append_page(Vec::new()).unwrap();
        assert!(state.take_completed_pages().1.is_none());
        assert!(state.take_queued_revalidation());
        state.begin_revalidation("request".into(), 910_002);
        state.append_page(Vec::new()).unwrap();
        state.take_completed_pages();
        assert!(state.is_revalidating());
        assert!(!state.take_queued_revalidation());
        assert_eq!(
            state.take_verified_notification().as_deref(),
            Some("latest notification")
        );
        assert!(state.has_incomplete_listing());
        state.finish_verification();
        assert!(!state.has_incomplete_listing());
    }

    #[test]
    fn discard_preserves_the_context_needed_to_abort_revalidation() {
        let mut state = S2cListState::new();
        assert!(!state.hold_list_changed("notification", false));
        state.begin_revalidation("request".into(), 910_001);
        state
            .append_page(vec![ToolDefinition::new("unverified", "")])
            .unwrap();
        state.record_cursor("next").unwrap();
        assert!(state.record_cursor("next").is_err());
        state.discard_pages();
        assert!(!state.is_internal_response(Some("910001")));
        assert!(state.requires_abort_on_error());
        assert!(state.has_incomplete_listing());
        assert!(state.take_completed_pages().0.is_empty());
    }
}
