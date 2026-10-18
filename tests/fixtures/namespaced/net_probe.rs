//! `net_probe` — workload fixture for `tests/linux_mechanism_e2e.rs`.
//!
//! Compiled with plain `rustc` (no crates — the same contract the
//! `unotify` fixture keeps). Every destination is an IP literal:
//! resolution is never exercised, so a name-layer grant can never
//! smuggle coverage the test did not declare.
//!
//! Modes:
//!   udp-echo <ip:port>        send one datagram and await its echo —
//!                             exit 0 on reply ("UDP-ECHO-OK"), 11 on
//!                             timeout (dropped = denied), 10 on a
//!                             local socket error (e.g. EPERM socket)
//!   udp-two <ok> <deny>       first datagram must be echoed
//!                             ("UDP-ALLOWED-OK"), second must be
//!                             dropped ("UDP-DENIED-OK") — exit 0 when
//!                             both behave, 3/4 when the expectation
//!                             flips
//!   udp-loop <ip:port> <tag>  one datagram every ~60ms forever, with a
//!                             `NETPROBE-HB <tag> seq=N replies=M`
//!                             heartbeat on stderr every 20 sends —
//!                             for the supervisor-kill leg (killed by
//!                             the pdeathsig cascade, never exits 0)
//!   tcp-two <ok> <deny>       first leg must complete a connect+echo
//!                             round-trip ("TCP-ALLOWED-OK"); the
//!                             second must fail at connect OR echo
//!                             ("TCP-DENIED-OK") — a DNAT accept makes
//!                             connect() succeed for every flow, so
//!                             only a completed round-trip proves the
//!                             flow was really allowed. Exit 0 when
//!                             both behave, 3 when the denied leg
//!                             echoes back
//!   tcp-echo <ip:port>        connect + echo round-trip — exit 0 on
//!                             "TCP-ECHO-OK", 1 on refused, 2 on other
//!                             I/O error

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs, UdpSocket};
use std::process::exit;
use std::time::Duration;

fn sock_addr(s: &str) -> SocketAddr {
    s.to_socket_addrs()
        .expect("resolve dest")
        .next()
        .expect("no addr")
}

/// `Some(errno)` when `e` is a hard OS refusal the caller treats as a
/// sandbox denial (EACCES/EPERM), `None` otherwise.
fn sandbox_errno(e: &std::io::Error) -> Option<i32> {
    match e.raw_os_error() {
        Some(libc::EACCES) | Some(libc::EPERM) => e.raw_os_error(),
        _ => None,
    }
}

// The fixture links libc through the platform prelude — declare the
// handful of constants used rather than taking a crate dependency.
#[allow(non_camel_case_types)]
mod libc {
    pub const EACCES: i32 = 13;
    pub const EPERM: i32 = 1;
    pub const ECONNREFUSED: i32 = 111;
    pub const ETIMEDOUT: i32 = 110;
}

fn udp_echo(dest: &str) -> ! {
    let target = sock_addr(dest);
    let sock = match UdpSocket::bind("0.0.0.0:0") {
        Ok(s) => s,
        Err(e) => {
            eprintln!("net_probe: udp bind failed: {e}");
            exit(if sandbox_errno(&e).is_some() { 10 } else { 2 });
        }
    };
    if let Err(e) = sock.send_to(b"ping", target) {
        eprintln!("net_probe: udp send_to failed: {e}");
        exit(if sandbox_errno(&e).is_some() { 10 } else { 2 });
    }
    // A denied datagram is dropped at the proxy — the echo simply
    // never returns; the read deadline is the tell.
    let _ = sock.set_read_timeout(Some(Duration::from_secs(5)));
    let mut buf = [0u8; 512];
    match sock.recv_from(&mut buf) {
        Ok(_) => {
            println!("UDP-ECHO-OK");
            exit(0);
        }
        Err(e)
            if e.kind() == std::io::ErrorKind::WouldBlock
                || e.kind() == std::io::ErrorKind::TimedOut
                || e.raw_os_error() == Some(libc::ETIMEDOUT) =>
        {
            eprintln!("net_probe: udp echo timed out (datagram dropped)");
            exit(11);
        }
        Err(e) => {
            eprintln!("net_probe: udp recv failed: {e}");
            exit(if sandbox_errno(&e).is_some() { 10 } else { 2 });
        }
    }
}

/// One UDP `send_to`/`recv_from` round-trip against `dest` on `sock`.
/// `Ok(())` on a reply within the deadline; `Err(11)` on timeout
/// (dropped = denied at the relay), `Err(2|10)` on a socket error.
fn udp_probe_once(sock: &UdpSocket, dest: &SocketAddr, payload: &[u8]) -> Result<(), i32> {
    if let Err(e) = sock.send_to(payload, dest) {
        eprintln!("net_probe: udp send_to {dest} failed: {e}");
        return Err(if sandbox_errno(&e).is_some() { 10 } else { 2 });
    }
    let _ = sock.set_read_timeout(Some(Duration::from_secs(5)));
    let mut buf = [0u8; 512];
    match sock.recv_from(&mut buf) {
        Ok(_) => Ok(()),
        Err(e)
            if e.kind() == std::io::ErrorKind::WouldBlock
                || e.kind() == std::io::ErrorKind::TimedOut
                || e.raw_os_error() == Some(libc::ETIMEDOUT) =>
        {
            Err(11)
        }
        Err(e) => {
            eprintln!("net_probe: udp recv from {dest} failed: {e}");
            Err(if sandbox_errno(&e).is_some() { 10 } else { 2 })
        }
    }
}

fn udp_two(ok: &str, deny: &str) -> ! {
    let ok_addr = sock_addr(ok);
    let deny_addr = sock_addr(deny);
    let sock = match UdpSocket::bind("0.0.0.0:0") {
        Ok(s) => s,
        Err(e) => {
            eprintln!("net_probe: udp bind failed: {e}");
            exit(if sandbox_errno(&e).is_some() { 10 } else { 2 });
        }
    };
    match udp_probe_once(&sock, &ok_addr, b"ping-ok") {
        Ok(()) => println!("UDP-ALLOWED-OK"),
        Err(c) => {
            eprintln!("net_probe: expected-allowed datagram failed ({c})");
            exit(c);
        }
    }
    match udp_probe_once(&sock, &deny_addr, b"ping-deny") {
        Err(11) => println!("UDP-DENIED-OK"),
        Ok(()) => {
            eprintln!("net_probe: expected-denied datagram was ECHOED");
            exit(3);
        }
        Err(c) => {
            eprintln!("net_probe: denied leg hit a socket error, not a drop");
            exit(c);
        }
    }
    exit(0);
}

fn udp_loop(dest: &str, tag: &str) -> ! {
    let target = sock_addr(dest);
    let sock = match UdpSocket::bind("0.0.0.0:0") {
        Ok(s) => s,
        Err(e) => {
            eprintln!("net_probe: udp bind failed: {e}");
            exit(if sandbox_errno(&e).is_some() { 10 } else { 2 });
        }
    };
    let _ = sock.set_read_timeout(Some(Duration::from_millis(10)));
    let payload = format!("hb:{tag}").into_bytes();
    let mut seq: u64 = 0;
    let mut replies: u64 = 0;
    let mut buf = [0u8; 512];
    loop {
        seq += 1;
        let _ = sock.send_to(&payload, target);
        if sock.recv_from(&mut buf).is_ok() {
            replies += 1;
        }
        if seq % 20 == 0 {
            eprintln!("NETPROBE-HB {tag} seq={seq} replies={replies}");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn tcp_connect(addr: &SocketAddr) -> Result<TcpStream, i32> {
    match TcpStream::connect_timeout(addr, Duration::from_secs(5)) {
        Ok(s) => Ok(s),
        Err(e) => {
            eprintln!("net_probe: tcp connect to {addr} failed: {e}");
            Err(match e.raw_os_error() {
                Some(libc::ECONNREFUSED) | Some(libc::ETIMEDOUT) => 1,
                _ if sandbox_errno(&e).is_some() => 10,
                _ => 1,
            })
        }
    }
}

/// connect + echo round-trip against `addr`. `Ok(())` only when the
/// echo actually returns — behind the namespaced DNAT the workload's
/// `connect` answers at the in-namespace smoltcp listener before the
/// evaluator's verdict lands, so handshake success alone cannot tell
/// an allowed flow from a denied one (the deny RST arrives just
/// after). A connect refusal (in-kernel deny) or any echo failure
/// counts as `Err(1|10)` — a real denial either way.
fn tcp_probe(addr: &SocketAddr) -> Result<(), i32> {
    let mut s = tcp_connect(addr)?;
    let _ = s.set_read_timeout(Some(Duration::from_secs(5)));
    let _ = s.set_write_timeout(Some(Duration::from_secs(5)));
    if let Err(e) = s.write_all(b"ping") {
        eprintln!("net_probe: tcp write to {addr} failed: {e}");
        return Err(1);
    }
    let mut buf = [0u8; 64];
    match s.read(&mut buf) {
        Ok(n) if n > 0 => Ok(()),
        Ok(_) | Err(_) => Err(1),
    }
}

fn tcp_two(ok: &str, deny: &str) -> ! {
    let ok_addr = sock_addr(ok);
    let deny_addr = sock_addr(deny);
    match tcp_probe(&ok_addr) {
        Ok(()) => println!("TCP-ALLOWED-OK"),
        Err(c) => {
            eprintln!("net_probe: expected-allowed flow failed ({c})");
            exit(c);
        }
    }
    match tcp_probe(&deny_addr) {
        Err(_) => println!("TCP-DENIED-OK"),
        Ok(()) => {
            eprintln!("net_probe: expected-denied flow echoed back");
            exit(3);
        }
    }
    exit(0);
}

fn tcp_echo(dest: &str) -> ! {
    let addr = sock_addr(dest);
    let mut s = match tcp_connect(&addr) {
        Ok(s) => s,
        Err(c) => exit(c),
    };
    let _ = s.set_read_timeout(Some(Duration::from_secs(5)));
    let _ = s.set_write_timeout(Some(Duration::from_secs(5)));
    if let Err(e) = s.write_all(b"ping") {
        eprintln!("net_probe: tcp write failed: {e}");
        exit(2);
    }
    let mut buf = [0u8; 64];
    match s.read(&mut buf) {
        Ok(n) if n > 0 => {
            println!("TCP-ECHO-OK");
            exit(0);
        }
        Ok(_) | Err(_) => {
            eprintln!("net_probe: tcp echo failed");
            exit(2);
        }
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        eprintln!("usage: net_probe <mode> <args...>");
        exit(2);
    }
    match args[1].as_str() {
        "udp-echo" => udp_echo(&args[2]),
        "udp-two" => udp_two(&args[2], args.get(3).map(String::as_str).unwrap_or("")),
        "udp-loop" => udp_loop(&args[2], args.get(3).map(String::as_str).unwrap_or("t")),
        "tcp-two" => tcp_two(&args[2], args.get(3).map(String::as_str).unwrap_or("")),
        "tcp-echo" => tcp_echo(&args[2]),
        other => {
            eprintln!("net_probe: unknown mode '{other}'");
            exit(2);
        }
    }
}
