//! PR-07 e2e: `plan` diagnostics (4 statuses / fixed exit codes, no
//! workload launch) and `run --report` (same-schema plan+observations+
//! result; JSON off stdout; failures recorded, never empty success).
//!
//! Suite layout — this `main.rs` is only the crate root (cargo maps
//! `tests/plan_report_e2e/main.rs` to the `plan_report_e2e` target).
//! The shared harness lives in `support.rs`; the tests live in
//! `plan.rs` (the `plan` command), `report.rs` (the `run --report`
//! document), and `lifecycle.rs` (launch lifecycle audit records).

// The repo-wide test helpers stay in `tests/common/mod.rs`; from this
// nested root they are reached by path.
#[path = "../common/mod.rs"]
mod common;
mod support;

mod lifecycle;
mod plan;
mod report;
