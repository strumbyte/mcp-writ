//! `net_probe` — workload fixture for `tests/linux_mechanism_e2e.rs`.
//!
//! Compiled with plain `rustc` (no crates — the same contract the
//! `unotify` fixture keeps). Destinations are parsed as `SocketAddr`
//! literals only — a hostname is rejected, never resolved — so a
//! name-layer grant can never smuggle coverage the test did not
//! declare, and a malformed argv fails deterministically on the
//! usage exit instead of panicking mid-run.
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
//!   udp6-echo / udp6-two /    the IPv6 spellings of the same modes —
//!   udp6-loop / tcp6-two /    destinations are `[v6]:port` literals
//!   tcp6-echo                 (a `::ffff:<v4>` mapped spelling is a
//!                             genuine v6 packet to the proxy — the
//!                             fold to v4 is the evaluator's call)
//!   dns-aaaa <name>           resolve `name` through the workload
//!                             resolver and print `RESOLVED <ip>` per
//!                             answer — exit 0 when at least one v6
//!                             (incl. mapped) answer arrives
//!                             ("DNS-AAAA-OK"), 12 when none does, 11
//!                             on resolution failure
//!   dns6-flow <name>:<port>   resolve `name` like dns-aaaa, then
//!                             connect+echo to the first v6 answer —
//!                             proves the minted grant reaches the
//!                             evaluator. Exit 0 on "TCP-ECHO-OK",
//!                             1 on refused, 12 on no v6 answer

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, UdpSocket};
use std::process::exit;
use std::time::Duration;

/// Parse an `ip:port` destination. `SocketAddr`'s parser accepts IP
/// literals only — it never consults the resolver — so a hostname (or
/// any malformed spelling) is a deterministic usage failure, not a
/// DNS lookup inside the sandboxed run.
fn sock_addr(s: &str) -> SocketAddr {
    match s.parse() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("net_probe: '{s}' is not an IP-literal socket address: {e}");
            exit(2);
        }
    }
}

/// `Some(errno)` when `e` is a hard OS refusal the caller treats as a
/// sandbox denial (EACCES/EPERM), `None` otherwise.
fn sandbox_errno(e: &std::io::Error) -> Option<i32> {
    match e.raw_os_error() {
        Some(libc::EACCES) | Some(libc::EPERM) => e.raw_os_error(),
        _ => None,
    }
}

// The fixture builds with plain `rustc` and no crate dependencies —
// declare the handful of errno constants used rather than pulling in
// the `libc` crate.
#[allow(non_camel_case_types)]
mod libc {
    pub const EACCES: i32 = 13;
    pub const EPERM: i32 = 1;
    pub const ECONNREFUSED: i32 = 111;
    pub const ETIMEDOUT: i32 = 110;
}

/// UDP bind address matching `dest`'s family — `0.0.0.0` cannot send
/// to a v6 peer and `[::]` dual-stack-binds on Linux, but pinning the
/// family keeps an accidental spelling flip from passing silently.
fn udp_bind_for(dest: &SocketAddr) -> &'static str {
    if dest.is_ipv6() { "[::]:0" } else { "0.0.0.0:0" }
}

fn udp_echo(dest: &str) -> ! {
    let target = sock_addr(dest);
    let sock = match UdpSocket::bind(udp_bind_for(&target)) {
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
    let sock = match UdpSocket::bind(udp_bind_for(&ok_addr)) {
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
    let sock = match UdpSocket::bind(udp_bind_for(&target)) {
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

/// Resolve `name` through the workload's ordinary resolver (the
/// redirected `resolv.conf` → port-53 gate intercept) and print each
/// answer address. Exit 0 when at least one v6 (incl. v4-mapped)
/// answer arrived — the e2e leg then asserts the minted grant lets
/// the flow through.
fn dns_aaaa(name: &str) -> ! {
    use std::net::ToSocketAddrs;
    let answers = match (name, 443).to_socket_addrs() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("net_probe: resolve '{name}' failed: {e}");
            exit(11);
        }
    };
    let mut saw_v6 = false;
    for a in answers {
        eprintln!("RESOLVED {}", a.ip());
        if a.is_ipv6() {
            saw_v6 = true;
        }
    }
    if saw_v6 {
        eprintln!("DNS-AAAA-OK");
        exit(0);
    }
    eprintln!("net_probe: '{name}' resolved without a v6 answer");
    exit(12);
}

/// The dns-aaaa leg's second half: resolve `name`, then open a
/// connect+echo to its first v6 answer on `port`. The minted grant —
/// not a static rule — is the only authority for that destination, so
/// reaching the dial proves AAAA→grant→verdict end to end. On a host
/// without v6 reachability the grant still authorizes the flow and
/// the dial itself fails closed (exit 1) — the audit record, not the
/// exit code, is the assertion point.
fn dns6_flow(name_port: &str) -> ! {
    use std::net::ToSocketAddrs;
    let Some((name, port)) = name_port.rsplit_once(':') else {
        eprintln!("net_probe: '{name_port}' is not <name>:<port>");
        exit(2);
    };
    let answers = match (name, 443).to_socket_addrs() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("net_probe: resolve '{name}' failed: {e}");
            exit(11);
        }
    };
    let mut first_v6: Option<SocketAddr> = None;
    for a in answers {
        eprintln!("RESOLVED {}", a.ip());
        if first_v6.is_none() && a.is_ipv6() {
            first_v6 = Some(a);
        }
    }
    let Some(target) = first_v6 else {
        eprintln!("net_probe: '{name}' resolved without a v6 answer");
        exit(12);
    };
    let port: u16 = match port.parse() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("net_probe: '{port}' is not a port: {e}");
            exit(2);
        }
    };
    let target = SocketAddr::new(target.ip(), port);
    match tcp_probe(&target) {
        Ok(()) => {
            println!("TCP-ECHO-OK");
            exit(0);
        }
        Err(c) => exit(c),
    }
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
    // argv is this fixture's contract with the harness, not a security
    // boundary: the fixed mode table and `SocketAddr`-literal parsing
    // are the only sinks arguments can reach, and the egress verdict is
    // enforced by the proxy/evaluator — never decided here. `args_os` +
    // a hard UTF-8 check puts even non-Unicode input on the usage exit
    // instead of the `args()` panic — the `nosemgrep` waiver is scoped
    // to this one read since replacing it with `args()` would weaken
    // the validation, not the risk.
    let args: Vec<String> = std::env::args_os() // nosemgrep — argv is the fixture's test contract; every malformed input below exits 2 deterministically
        .map(|a| match a.into_string() {
            Ok(s) => s,
            Err(_) => {
                eprintln!("net_probe: argument is not valid UTF-8");
                exit(2);
            }
        })
        .collect();
    let usage = |args: &[String]| -> ! {
        eprintln!(
            "usage: {} <udp-echo|udp6-echo|tcp-echo|tcp6-echo|dns-aaaa|dns6-flow> <ip:port|name[:port]> | \
             <udp-two|udp6-two|tcp-two|tcp6-two> <ok-ip:port> <deny-ip:port> | \
             <udp-loop|udp6-loop> <ip:port> <tag>",
            args.first().map(String::as_str).unwrap_or("net_probe")
        );
        exit(2);
    };
    // Strict contract: a known mode carrying exactly its declared
    // arity — anything else is a harness bug, named on stderr and
    // refused on the usage exit rather than silently defaulted.
    let Some(mode) = args.get(1).map(String::as_str) else {
        usage(&args)
    };
    let need = match mode {
        "udp-echo" | "udp6-echo" | "tcp-echo" | "tcp6-echo" | "dns-aaaa" | "dns6-flow" => 1,
        "udp-two" | "udp6-two" | "tcp-two" | "tcp6-two" | "udp-loop" | "udp6-loop" => 2,
        other => {
            eprintln!("net_probe: unknown mode '{other}'");
            usage(&args)
        }
    };
    let rest = &args[2..];
    if rest.len() != need {
        eprintln!(
            "net_probe: mode '{mode}' takes {need} arg(s), got {}",
            rest.len()
        );
        usage(&args);
    }
    match mode {
        "udp-echo" | "udp6-echo" => udp_echo(&rest[0]),
        "udp-two" | "udp6-two" => udp_two(&rest[0], &rest[1]),
        "udp-loop" | "udp6-loop" => udp_loop(&rest[0], &rest[1]),
        "tcp-two" | "tcp6-two" => tcp_two(&rest[0], &rest[1]),
        "tcp-echo" | "tcp6-echo" => tcp_echo(&rest[0]),
        "dns-aaaa" => dns_aaaa(&rest[0]),
        "dns6-flow" => dns6_flow(&rest[0]),
        _ => unreachable!("mode and arity checked above"),
    }
}
