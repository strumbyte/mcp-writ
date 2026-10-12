//! Sandboxed workload for `proxy_sigterm_reaches_the_sandboxed_workload`.
//! Prints READY, parks in `pause()`, and its SIGTERM handler writes
//! GOT_TERM to stdout then _exit(0)s. Single process — the handler runs
//! on whichever thread the kernel interrupts — so signal delivery is
//! observable deterministically.
//!
//! A `sh` wait-and-trap form is NOT dependable as this oracle: a
//! group-wide TERM that also kills the child `sh` is `wait`ing on can
//! reap the child first, completing `wait` normally while `sh`'s own
//! pending trap is dropped on the EOF path (sh exits 0 without
//! echoing) or deferred indefinitely (a loop form survived past the
//! supervisor's 5s teardown grace until SIGKILL).
//!
//! Compiled with `rustc -O` at test time — no external crates — the
//! same convention as `tests/fixtures/mcp_servers/open_path_server.rs`.

use std::io::Write;

extern "C" {
    fn signal(signum: i32, handler: extern "C" fn(i32)) -> isize;
    fn write(fd: i32, buf: *const u8, count: usize) -> isize;
    fn pause() -> i32;
    fn _exit(status: i32) -> !;
}

// SIGTERM is 15 on macOS (the only platform this fixture targets).
const SIGTERM: i32 = 15;

extern "C" fn on_term(_signum: i32) {
    // Handler context — only async-signal-safe calls: write(2) and
    // _exit(2). println!/malloc/locks are not permitted here.
    unsafe {
        write(1, b"GOT_TERM\n".as_ptr(), 9);
        _exit(0);
    }
}

fn main() {
    unsafe {
        signal(SIGTERM, on_term);
    }
    println!("READY");
    std::io::stdout().flush().expect("flush READY");
    loop {
        unsafe {
            pause();
        }
    }
}
