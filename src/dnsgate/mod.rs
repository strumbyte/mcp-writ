//! DNS gate — the name-layer enforcement component: a
//! policy-evaluating DNS resolver.
//!
//! A workload whose resolver points at this gate gets answers only for
//! names the policy's name layer (`allow host=` / `deny host=`) allows;
//! every other name is refused NXDOMAIN/REFUSED and recorded as
//! `sandbox.network_denied` with `name`/`qtype`/`session_id`. Allowed
//! answers are relayed verbatim; their CNAME chain and A/AAAA records
//! are observed for the audit record and mint TTL-scoped entries in the
//! dynamic IP allow list (chain-minimum TTL) — the contract an IP-layer
//! enforcement point (PR-07/PR-09) consumes to extend name-layer
//! control to connections, on paths that provide one.
//!
//! Honest boundary, per the improvement plan: this gate only covers
//! traffic that resolves through it. DoH, hardcoded resolvers, and
//! direct-IP connections bypass the name layer entirely — containing
//! those is the IP layer's and the namespaced launch's job, and no
//! plan/report presents them as name-controlled.

pub(crate) mod allowlist;
pub(crate) mod name_policy;
pub(crate) mod server;
pub(crate) mod upstream;
pub(crate) mod wire;

pub use allowlist::DynamicAllowList;
pub use server::{GateConfig, Refusal, serve};

/// Canonicalize a DNS wire name (decoded dotted text) or a host
/// spelling through the same pipeline the Auditor applies to argument
/// hosts: `normalize_policy_host` then `canonicalize_policy_host`
/// (trim → UTS-46/IDNA → URL-grammar fold). The result is the identity
/// the name layer evaluates, forwards, and records.
pub(crate) fn canonical_name(name: &str) -> String {
    crate::policy::canonicalize_policy_host(&crate::policy::host::normalize_policy_host(name))
}
