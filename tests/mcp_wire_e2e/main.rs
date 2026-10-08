//! PR-10 wire-level enforcement end-to-end tests.
//!
//! These exercise the bidirectional JSON-RPC contract the Auditor proxy
//! enforces in front of `tests/fixtures/mcp_servers/scripted_stdio.py`:
//! direction-keyed request/response correlation, orphan and duplicate
//! responses, notifications that never get answers, cancellation and
//! progress correlation, the bounded in-flight request table, the 2026
//! subscription lifecycle, and dry-run forwarding of denied requests.
//!
//! Suite layout — this `main.rs` is only the crate root (cargo maps
//! `tests/mcp_wire_e2e/main.rs` to the `mcp_wire_e2e` target). The shared
//! harness lives in `support.rs`; the tests live in `correlation.rs`
//! (S2C correlation, envelope integrity, dry-run forwarding),
//! `inflight.rs` (cancellation/progress correlation, the bounded pending
//! table, tools/list busy gating), `v26.rs` (the 2026-07-28 revision:
//! `_meta`, pre-init gating, subscriptions, the `requestState` cap),
//! `input_required.rs` (MRTR `input_required`/`inputResponses` gating),
//! and `deputy.rs` (confused-deputy roles, extraction, denial audits).

// The repo-wide test helpers stay in `tests/common/mod.rs`; from this
// nested root they are reached by path.
#[path = "../common/mod.rs"]
mod common;
mod support;

mod correlation;
mod deputy;
mod inflight;
mod input_required;
mod v26;
