//! `capability-matrix` — print the machine-readable per-OS capability
//! catalog as one JSON object on stdout.
//!
//! The document is generated from [`crate::enforcement::capability`] — the same
//! model `plan`/`--report` and the PoC reports draw their mechanism
//! strings and requirement ids from — so what the matrix claims is what
//! the launch paths report. `docs/capability-matrix.json` commits this
//! output; `tests/capability_matrix.rs` fails when the two diverge.
//!
//! The matrix describes the product, never this machine: no probing
//! runs here. Per-launch evidence stays in `plan`/`--report`; a
//! mechanism marked `adopted-conditional` still probes per launch and
//! refuses when its requirements are unmet.

/// Print the capability matrix JSON to stdout.
pub fn run_capability_matrix() {
    println!("{}", crate::enforcement::capability_matrix_json());
}
