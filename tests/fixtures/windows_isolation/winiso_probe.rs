//! PR-30 Windows isolation candidate probe — one std-only binary that
//! measures the new Windows isolation mechanisms (PSEC / BaseContainer,
//! IsolationSession, Win32 app isolation packaging signals) against the
//! existing AppContainer baseline. Never wired into the product launch
//! path; compiled on demand by `tests/windows_isolation_e2e.rs` and by
//! `scripts/validate-windows-isolation.ps1`.
//!
//! Evidence-tier discipline (same contract as `src/container/windows_probe.rs`):
//!
//! - **presence** — file/service/registry artifacts exist (`facts`)
//! - **contract answers** — API-set implementation, export resolution,
//!   version/support queries, WinRT activation (`contracts`). An answer
//!   is never promoted to "the runtime contract works".
//! - **runtime** — real environment creation + a spawned child running
//!   the `attempts` battery (`ac-run`, `psec-run`). Denials are the
//!   data: each attempt records what the OS actually did.
//!
//! Bounded and owned: no elevation, no service control, no Windows
//! feature changes, no store/package installs, no registry writes
//! outside a test-owned HKCU key (attempt leg), no ACL changes outside
//! paths the caller created and restores (`ac-run`). `psec-run` creates
//! a server-side security environment for a single child and closes it;
//! IsolationSession's session/user mutating legs are NOT here — they
//! belong to the dedicated Insider lab (`-Lab` script legs) since they
//! create local users and sessions.
//!
//! Modes: `facts` | `contracts` | `attempts` | `ac-run` | `psec-run` |
//! `sleep <ms>` | `spec-file <out>` (write the PSEC spec bytes for
//! offline inspection). All machine output is one JSON object on
//! stdout; diagnostics go to stderr.
//!
//! Layout: this file is the crate root for the single `rustc -O` build;
//! sibling modules resolve next to it — `ffi` (raw-dylib imports),
//! `helpers` (JSON/registry/token/DLL plumbing), `spawn` (child-process
//! plumbing shared by the run modes), `psec_spec` (FlatBuffers writer),
//! and one file per mode (`facts`, `contracts`, `attempts`, `ac_run`,
//! `psec_run`).

#![cfg(windows)]

mod ac_run;
mod attempts;
mod contracts;
mod facts;
mod ffi;
mod helpers;
mod psec_run;
mod psec_spec;
mod spawn;

use std::io::Write;

use crate::ffi::Sleep;
use crate::helpers::js;
use crate::psec_spec::{psec_spec, NetSpec};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("facts") => println!("{}", facts::mode_facts()),
        Some("contracts") => println!("{}", contracts::mode_contracts()),
        Some("attempts") => println!("{}", attempts::mode_attempts(&args[1..])),
        Some("ac-run") => println!("{}", ac_run::mode_ac_run(&args[1..])),
        Some("psec-run") => println!("{}", psec_run::mode_psec_run(&args[1..])),
        Some("sleep") => {
            let ms: u32 = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(1000);
            unsafe { Sleep(ms) };
        }
        Some("psec-spec-test") => {
            // Bounded create-attempt ladder to isolate what the schema
            // check accepts — each HRESULT is recorded, never retried
            // as a guess. No environment is left open: every successful
            // create is closed immediately.
            println!("{}", psec_run::mode_psec_spec_test());
        }
        Some("spec-file") => {
            // Write the minimal spec for offline inspection/debugging.
            let out = args
                .get(1)
                .cloned()
                .unwrap_or_else(|| "psec-spec.bin".into());
            let spec = psec_spec(
                &["C:\\ro".to_string()],
                &["C:\\rw".to_string()],
                &["C:\\deny".to_string()],
                &NetSpec::DenyAll,
                true,
            );
            let mut f = std::fs::File::create(&out).expect("create spec file");
            f.write_all(&spec).expect("write spec");
            println!(
                "{{\"mode\":\"spec-file\",\"path\":{},\"len\":{}}}",
                js(&out),
                spec.len()
            );
        }
        _ => {
            eprintln!("usage: winiso_probe facts|contracts|attempts [flags]|ac-run [--lpac] [--net]|psec-run [--ro D --rw D --deny P]|psec-spec-test|sleep <ms>|spec-file <out>");
            std::process::exit(2);
        }
    }
}
