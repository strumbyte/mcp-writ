//! `unotify-run` e2e workload — a single blocking TCP `connect(2)` to
//! a literal `IP:PORT` given as argv[1].
//!
//! Compiled with plain `rustc` by `tests/unotify_e2e.rs` (no crate
//! deps — the fixture must not assume the workspace). Outcomes:
//!
//! - exit 0 — the kernel ran the connect (`connected` or refused
//!   `ECONNREFUSED`), i.e. the supervisor answered CONTINUE,
//! - exit 10 — `EACCES`: the supervisor denied the destination,
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
