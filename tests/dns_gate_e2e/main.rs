//! Integration tests for `dnsgate` — the policy-evaluating DNS
//! resolver (PR-06, improvement plan §1.2/§1.6).
//!
//! A real gate task is served on loopback against a scripted mock
//! upstream; clients are raw UDP/TCP sockets, so the whole exchange is
//! exercised on the wire. Assertions cover: name-layer evaluation
//! parity with the Auditor (`host_matches` semantics), refusal RCODEs,
//! the deny-all posture (an empty allow list refuses every name — only
//! `allow host="*"` opens the gate), `sandbox.network_denied` /
//! `sandbox.network_resolved` emission with `name`/`qtype`/`session_id`,
//! alias-chain re-judgement (CNAME and DNAME targets receive the same
//! deny-precedence evaluation as the queried name), fail-closed
//! refusal of undecodable answers and overlong chains, explicit
//! address denies on resolved endpoints, protected-address grant
//! refusal with literal/CIDR opt-in, chain-minimum-TTL grants into
//! the dynamic allow list, upstream timeout/mismatch handling, TCP
//! connection capacity, and fail-closed behavior when the audit sink
//! is unavailable.
//!
//! Suite layout — this `main.rs` is only the crate root (cargo maps
//! `tests/dns_gate_e2e/main.rs` to the `dns_gate_e2e` target). The
//! shared wire codec helpers, mock upstream, gate harness, and client
//! helpers live in `support.rs`; the tests live in `names.rs`
//! (name-layer policy), `chains.rs` (alias chains), `addresses.rs`
//! (resolved/protected addresses), `transport.rs` (UDP/TCP transport),
//! and `audit.rs` (audit sink + allow-list export).

// The repo-wide test helpers stay in `tests/common/mod.rs`; from this
// nested root they are reached by path.
#[path = "../common/mod.rs"]
mod common;
mod support;

mod addresses;
mod audit;
mod chains;
mod names;
mod transport;
