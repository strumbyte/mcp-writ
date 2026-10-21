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
//! - `connect <ip:port>` — a single blocking TCP `connect(2)`,
//! - `unix-connect <path>` — `connect(2)` to a pathname AF_UNIX socket
//!   (PR-18 escape leg),
//! - `abstract-connect <name>` — `connect(2)` to an abstract AF_UNIX
//!   socket (PR-18 escape leg),
//! - `dgram-sendto <path>` — unbound `SOCK_DGRAM` AF_UNIX `sendto(2)` to
//!   a pathname socket (PR-18 escape leg),
//! - `kill <pid>` — `kill(pid, 0)` reachability probe: signal 0 runs
//!   the same permission/scoping checks without delivering a signal,
//!   so a same-uid target distinguishes Landlock `Scope::Signal` from
//!   an ordinary credential refusal (PR-18 escape leg).
//!
//! Exit contract (every mode prints `KDP <mode>=errno=<n>|ok` first):
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
    use std::io::Write as _;
    match outcome {
        Ok(_) => {
            // One write(2) for the whole marker: the launcher shares this
            // stderr pipe with its own tracing, and eprintln! emits each
            // format piece as a separate write — an interleaved INFO line
            // between them splits "KDP <mode>=" and the leg reads as a
            // missing marker instead of a denied escape.
            let _ = std::io::stderr().write_all(format!("KDP {mode}=ok\n").as_bytes());
            std::process::exit(0);
        }
        Err(errno) => {
            let _ = std::io::stderr()
                .write_all(format!("KDP {mode}=errno={errno}\n").as_bytes());
            match errno {
                EACCES | EPERM => std::process::exit(10),
                _ => std::process::exit(1),
            }
        }
    }
}

/// `kill(pid, 0)` via a raw syscall — the fixture has no libc dep, and
/// `std` exposes no signal API. Signal 0 exercises the same
/// `task_kill` hook (Landlock `Scope::Signal` and the ordinary
/// permission checks) without delivering a signal: a same-uid target
/// answers `0` on an unscoped kernel and `EPERM` under the scope.
#[cfg(target_arch = "x86_64")]
fn kill0(pid: i64) -> Result<i32, i32> {
    const SYS_KILL: usize = 62;
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "syscall",
            inlateout("rax") SYS_KILL as i64 => ret,
            in("rdi") pid,
            in("rsi") 0i64,
            lateout("rcx") _,
            lateout("r11") _,
            options(nomem, nostack),
        );
    }
    if ret < 0 {
        Err((-ret) as i32)
    } else {
        Ok(0)
    }
}

#[cfg(target_arch = "aarch64")]
fn kill0(pid: i64) -> Result<i32, i32> {
    const SYS_KILL: usize = 129;
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") SYS_KILL as i64,
            inlateout("x0") pid => ret,
            in("x1") 0i64,
            options(nomem, nostack),
        );
    }
    if ret < 0 {
        Err((-ret) as i32)
    } else {
        Ok(0)
    }
}

fn main() {
    let mut args = std::env::args().skip(1);
    let (Some(mode), Some(arg)) = (args.next(), args.next()) else {
        eprintln!(
            "usage: kernel_deny_probe open <path> | connect <ip:port> | \
             unix-connect <path> | abstract-connect <name> | \
             dgram-sendto <path> | kill <pid>"
        );
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
        "unix-connect" => report(
            "unix-connect",
            std::os::unix::net::UnixStream::connect(&arg)
                .map(|_| 0)
                .map_err(|e| e.raw_os_error().unwrap_or(-1)),
        ),
        "abstract-connect" => {
            use std::os::linux::net::SocketAddrExt;
            let outcome = match std::os::unix::net::SocketAddr::from_abstract_name(&arg) {
                Ok(addr) => std::os::unix::net::UnixStream::connect_addr(&addr)
                    .map(|_| 0)
                    .map_err(|e| e.raw_os_error().unwrap_or(-1)),
                Err(e) => Err(e.raw_os_error().unwrap_or(-1)),
            };
            report("abstract-connect", outcome);
        }
        "dgram-sendto" => {
            let outcome = std::os::unix::net::UnixDatagram::unbound()
                .and_then(|s| s.send_to(b"x", &arg))
                .map(|_| 0)
                .map_err(|e| e.raw_os_error().unwrap_or(-1));
            report("dgram-sendto", outcome);
        }
        "kill" => {
            let pid = arg.parse::<i64>().unwrap_or(-1);
            report("kill", kill0(pid));
        }
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
