//! `denial_audit_e2e` workload — attempts one kernel-enforced operation
//! and reports the outcome on **stderr** (stdout stays silent: under
//! `mcp-writ run` it is the Auditor's JSON-RPC channel, so a stray line
//! would be audited as a malformed frame and is never where this probe
//! reports).
//!
//! Compiled with plain `rustc` by `tests/denial_audit_e2e.rs` (no crate
//! deps — the fixture must not assume the workspace). Modes:
//!
//! - `open <path>` — opens the file read-only,
//! - `connect <ip:port>` — a single blocking TCP `connect(2)`.
//!
//! Exit contract (both modes print `KDP <mode>=errno=<n>|ok` first):
//!
//! - exit 10 — the operation was denied by the OS (EACCES or EPERM),
//! - exit 0  — the operation ran (opened / reached the kernel — for a
//!   connect that includes a real `ECONNREFUSED`, which still proves the
//!   syscall passed the sandbox),
//! - exit 1  — any other error,
//! - exit 2  — usage.
//!
//! Exit 10 is the leg the spec test needs: the denial provably happened
//! in-kernel, so the audit log's silence on it is the observable claim —
//! "unobservable", never "did not happen".

fn report(mode: &str, outcome: Result<i32, i32>) -> ! {
    match outcome {
        Ok(_) => {
            eprintln!("KDP {mode}=ok");
            std::process::exit(0);
        }
        Err(errno) => {
            eprintln!("KDP {mode}=errno={errno}");
            match errno {
                EACCES | EPERM => std::process::exit(10),
                _ => std::process::exit(1),
            }
        }
    }
}

fn main() {
    let mut args = std::env::args().skip(1);
    let (Some(mode), Some(arg)) = (args.next(), args.next()) else {
        eprintln!("usage: kernel_deny_probe open <path> | connect <ip:port>");
        std::process::exit(2);
    };
    match mode.as_str() {
        "open" => report(
            "open",
            std::fs::File::open(&arg)
                .map(|_| 0)
                .map_err(|e| e.raw_os_error().unwrap_or(-1)),
        ),
        "connect" => report(
            "connect",
            std::net::TcpStream::connect(arg.as_str())
                .map(|_| 0)
                .map_err(|e| e.raw_os_error().unwrap_or(-1)),
        ),
        _ => {
            eprintln!("unknown mode: {mode}");
            std::process::exit(2);
        }
    }
}

// The fixture compiles without Cargo deps — spell the errno values the
// test discriminates on directly (Linux numbers; the test target is
// Linux-gated).
const EACCES: i32 = 13;
const EPERM: i32 = 1;
