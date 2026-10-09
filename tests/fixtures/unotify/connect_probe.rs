//! `unotify-run` e2e workload — a single `connect(2)` to a literal
//! `IP:PORT` given as argv[1]. TCP only: `deny_all_others` policies
//! pin `socket(2)` to SOCK_STREAM (UDP/RAW fail closed) and Landlock
//! `ConnectTcp` independently re-checks an allowed connect, so the
//! kernel outcome after a supervisor CONTINUE is ABI-dependent.
//!
//! Compiled with plain `rustc` by `tests/unotify_e2e.rs` (no crate
//! deps — the fixture must not assume the workspace). Outcomes:
//!
//! - exit 0 — the kernel ran the connect (`connected`, or TCP refused
//!   `ECONNREFUSED`), i.e. the supervisor answered CONTINUE and no
//!   later kernel layer denied it,
//! - exit 10 — `EACCES`: denied — by the supervisor, or by Landlock
//!   net enforcement after a CONTINUE; the audit record disambiguates,
//! - exit 11 — `ENOSYS`: the notification channel went dead (fail
//!   closed at the kernel),
//! - exit 1 — any other connect error,
//! - exit 2 — usage.

use std::net::TcpStream;

fn main() {
    let Some(addr) = std::env::args().nth(1) else {
        eprintln!("usage: connect_probe <ip:port>");
        std::process::exit(2);
    };
    match TcpStream::connect(addr.as_str()) {
        Ok(_) => {
            println!("connected");
            std::process::exit(0);
        }
        Err(e) => {
            let errno = e.raw_os_error().unwrap_or(-1);
            println!("connect-error errno={errno}");
            match errno {
                libc::EACCES => std::process::exit(10),
                libc::ECONNREFUSED => std::process::exit(0),
                libc::ENOSYS => std::process::exit(11),
                _ => std::process::exit(1),
            }
        }
    }
}

// The fixture compiles without Cargo deps — spell the three errno
// values the test discriminates on directly.
mod libc {
    pub const EACCES: i32 = 13;
    pub const ECONNREFUSED: i32 = 111;
    pub const ENOSYS: i32 = 38;
}
