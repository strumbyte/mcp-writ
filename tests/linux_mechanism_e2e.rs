//! End-to-end tests for the PR-16 Linux egress mechanism selection
//! (improvement plan PR-16 task 6, landed under PR-26): `run`'s
//! `--linux-mechanism` matrix on a real kernel.
//!
//! Each leg spawns the real `mcp-writ` binary — policy load →
//! mechanism selection → namespaced/native dispatch → the in-process
//! TUN proxy → audit/report assertions. The workload is
//! `tests/fixtures/namespaced/net_probe.rs`, compiled once here with
//! plain `rustc` — no extra dependencies.
//!
//! Coverage:
//!
//! - `auto` selects `linux-namespaced` when only the namespaced route
//!   can satisfy the policy (a destination-scoped UDP allow), and also
//!   when the native route could satisfy it (a port-scoped TCP allow)
//!   — namespaced is the preferred route on a capable host. Omitting
//!   the flag requests `auto` (the `run` default).
//! - `namespaced` honors the UDP allow/deny split per datagram and the
//!   TCP allow/deny split per flow; proxy stats and the audit JSONL
//!   carry both halves of the verdict.
//! - `native` refuses a UDP-covered allow under deny-all before spawn
//!   (dead policy on the native route) — the workload never runs and
//!   no `server.connected` record exists.
//! - `namespaced` refuses a policy it cannot satisfy (an fs grant
//!   rooted under the `/run` private-tmpfs mask) instead of falling
//!   back to native.
//! - Forcing the egress proxy to end while UDP traffic is in flight is
//!   a supervision loss: the workload is killed fail-closed, `run`
//!   exits nonzero, the report records `proxy_lost`, and the audit
//!   carries `reason=supervision_lost` — the previously unverified
//!   "proxy 強制終了" item in `docs/validation/linux-namespaced-proxy.md`.
//!
//! Every test skips via `common::skip_e2e_test` when a prerequisite is
//! missing (rustc, a non-loopback IPv4, or the `namespaced-probe`
//! capability verdict — the same probe the launcher refuses on).
//! `MCP_WRIT_REQUIRE_E2E_TESTS=1` turns the skip into a failure, so a
//! mandatory run can never pass unexecuted.

#![cfg(target_os = "linux")]

use std::io::Read;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::OnceLock;
use std::time::Duration;

mod common;

/// Per-leg budget — a wedged supervisor/proxy must fail, never hang.
/// The denied UDP leg's read deadline (5 s) and the denied TCP leg's
/// connect timeout (5 s) both fit comfortably inside it.
const TEST_TIMEOUT: Duration = Duration::from_secs(60);
/// Parent-side fault-injection hook the launch checks on its own
/// environment (`warden::namespaced::init_env::PROXY_KILL_AFTER_MS`).
/// Listing the name here keeps the assertion next to the leg that sets
/// it — the value ends the egress proxy task that many ms after start.
/// The hook is compiled in only under `debug_assertions` (`#[cfg]` in
/// the launch); this target drives the dev-profile
/// `CARGO_BIN_EXE_mcp-writ`, which carries it.
const PROXY_KILL_ENV: &str = "MCP_WRIT_NS_PROXY_KILL_AFTER_MS";

// ─── fixture / environment prerequisites ─────────────────────────────

/// Compile `tests/fixtures/namespaced/net_probe.rs` once per test
/// binary — the output lands under `target/linux-mechanism-e2e/`,
/// *outside* `/tmp` and `/run`: the namespaced init covers those trees
/// with private tmpfs mounts, so a workload image under them is
/// unreachable inside the namespace (and an fs grant naming them is a
/// selection violation by design).
fn fixture() -> Option<PathBuf> {
    static BIN: OnceLock<Option<PathBuf>> = OnceLock::new();
    BIN.get_or_init(|| {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("target/linux-mechanism-e2e");
        if let Err(e) = std::fs::create_dir_all(&dir) {
            common::skip_e2e_test(&format!("fixture dir create failed: {e}"));
            return None;
        }
        let bin = dir.join("net_probe");
        let src = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/namespaced/net_probe.rs");
        let need = !bin.exists()
            || std::fs::metadata(&src).and_then(|m| m.modified()).ok()
                > std::fs::metadata(&bin).and_then(|m| m.modified()).ok();
        if need {
            match Command::new("rustc")
                .args(["-O", "-o"])
                .arg(&bin)
                .arg(&src)
                .status()
            {
                Ok(s) if s.success() => {}
                Ok(s) => {
                    common::skip_e2e_test(&format!("rustc -O net_probe.rs failed: {s}"));
                    return None;
                }
                Err(e) => {
                    common::skip_e2e_test(&format!("rustc unavailable: {e}"));
                    return None;
                }
            }
        }
        Some(bin)
    })
    .clone()
}

/// The launcher's own capability probe: `namespaced-probe` exits 0
/// exactly when every stage `namespaced` needs (userns/netns/mountns,
/// uid map, TUN, loopback, route) succeeds — the same verdict the
/// selection consults, so a skip mirrors a refused launch.
fn namespaced_capable() -> bool {
    match Command::new(env!("CARGO_BIN_EXE_mcp-writ"))
        .arg("namespaced-probe")
        .stdin(Stdio::null())
        .output()
    {
        Ok(out) if out.status.success() => true,
        Ok(out) => {
            common::skip_e2e_test(&format!(
                "host lacks namespaced capability (probe exit {:?}): {}",
                out.status.code(),
                String::from_utf8_lossy(&out.stdout)
            ));
            false
        }
        Err(e) => {
            common::skip_e2e_test(&format!("namespaced-probe spawn failed: {e}"));
            false
        }
    }
}

/// The host's primary IPv4 — the workload reaches the test's echo
/// servers through the TUN proxy's host sockets, so the destination
/// must be an address the host itself owns. `connect` on a UDP socket
/// only resolves the route; no datagram is sent.
fn host_ipv4() -> Option<Ipv4Addr> {
    let s = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).ok()?;
    s.connect((Ipv4Addr::new(203, 0, 113, 1), 53)).ok()?;
    match s.local_addr().ok()?.ip() {
        std::net::IpAddr::V4(v4) if !v4.is_loopback() => Some(v4),
        _ => {
            common::skip_e2e_test("no non-loopback IPv4 for the echo servers");
            None
        }
    }
}

/// Whether the host can route a global-v6 destination — the same
/// judgment `select`'s `host_v6_reach` makes (a UDP `connect` does
/// the route lookup without sending anything). Drives the
/// environment-dependent v6 legs: legs that need a real v6 dial
/// skip when this is false, and the refusal leg only runs when it is.
fn v6_globally_routable() -> bool {
    let Ok(s) = UdpSocket::bind((Ipv6Addr::UNSPECIFIED, 0)) else {
        return false;
    };
    s.connect(("2001:4860:4860::8888".parse::<Ipv6Addr>().unwrap(), 53))
        .is_ok()
}

/// The host's first routable v6 address (global or ULA — anything a
/// host-side connect could reach), read straight from
/// `/proc/net/if_inet6` so the test needs no privileges. `None` on a
/// v6-less host — the environment-dependent legs skip there.
fn host_ipv6() -> Option<Ipv6Addr> {
    let body = std::fs::read_to_string("/proc/net/if_inet6").ok()?;
    for line in body.lines() {
        let Some(hex) = line.get(..32) else {
            continue;
        };
        let Ok(raw) = u128::from_str_radix(hex, 16) else {
            continue;
        };
        let a = Ipv6Addr::from(raw);
        if !a.is_loopback() && !a.is_unicast_link_local() {
            return Some(a);
        }
    }
    None
}

/// Ephemeral UDP+TCP echo servers bound on the host's wildcard
/// address — the proxy relays the allowed datagrams/flows to them via
/// real host sockets.
struct EchoServers {
    udp_port: u16,
    tcp_port: u16,
}

fn start_echo_servers() -> Option<EchoServers> {
    let udp = match UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)) {
        Ok(s) => s,
        Err(e) => {
            common::skip_e2e_test(&format!("udp echo bind failed: {e}"));
            return None;
        }
    };
    let tcp = match TcpListener::bind((Ipv4Addr::UNSPECIFIED, 0)) {
        Ok(l) => l,
        Err(e) => {
            common::skip_e2e_test(&format!("tcp echo bind failed: {e}"));
            return None;
        }
    };
    let servers = EchoServers {
        udp_port: udp.local_addr().ok()?.port(),
        tcp_port: tcp.local_addr().ok()?.port(),
    };
    std::thread::spawn(move || {
        let mut buf = [0u8; 2048];
        while let Ok((n, from)) = udp.recv_from(&mut buf) {
            let _ = udp.send_to(&buf[..n], from);
        }
    });
    std::thread::spawn(move || {
        for stream in tcp.incoming().flatten() {
            std::thread::spawn(move || {
                let mut s = stream;
                let mut peer = match s.try_clone() {
                    Ok(p) => p,
                    Err(_) => return,
                };
                let _ = std::io::copy(&mut peer, &mut s);
            });
        }
    });
    Some(servers)
}

/// A minimal DNS responder for the v6 upstream legs — bound on the
/// host's `::1` so the *upstream side* of the gate forwards over a
/// real v6 socket without external v6 reachability. Answers A with
/// `A_ADDR` and AAAA with `AAAA_ADDR`; anything else gets an empty
/// NOERROR so a glibc retry still terminates.
struct MockDns {
    addr: SocketAddr,
}

const MOCK_DNS_A: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);
const MOCK_DNS_AAAA: Ipv6Addr = Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 5);

/// Build a DNS response for `query`: header + echoed question + one
/// answer — the gate validates id/name echo before relaying, so the
/// question bytes are copied verbatim.
fn mock_dns_response(query: &[u8]) -> Option<Vec<u8>> {
    if query.len() < 12 {
        return None;
    }
    // Skip header to find the question end: labels until 0, then
    // qtype+qclass. (No compression in a question's first pass.)
    let mut i = 12usize;
    loop {
        let len = *query.get(i)? as usize;
        if len == 0 {
            i += 1;
            break;
        }
        i += 1 + len;
    }
    let question_end = i.checked_add(4)?;
    let question = &query[12..question_end];
    let qtype = u16::from_be_bytes([*query.get(i)?, *query.get(i + 1)?]);
    let mut resp = Vec::with_capacity(question_end + 32);
    resp.extend_from_slice(&query[..2]); // id
    resp.extend_from_slice(&[0x81, 0x80]); // QR | RD | RA
    resp.extend_from_slice(&query[4..6]); // qdcount
    resp.extend_from_slice(&1u16.to_be_bytes()); // ancount
    resp.extend_from_slice(&[0, 0, 0, 0]); // nscount, arcount
    resp.extend_from_slice(question);
    // Compressed name pointer to the question name, then type A/AAAA,
    // class IN, TTL 300.
    resp.extend_from_slice(&[0xC0, 0x0C]);
    match qtype {
        1 => {
            resp.extend_from_slice(&1u16.to_be_bytes());
            resp.extend_from_slice(&1u16.to_be_bytes());
            resp.extend_from_slice(&300u32.to_be_bytes());
            resp.extend_from_slice(&4u16.to_be_bytes());
            resp.extend_from_slice(&MOCK_DNS_A.octets());
        }
        28 => {
            resp.extend_from_slice(&28u16.to_be_bytes());
            resp.extend_from_slice(&1u16.to_be_bytes());
            resp.extend_from_slice(&300u32.to_be_bytes());
            resp.extend_from_slice(&16u16.to_be_bytes());
            resp.extend_from_slice(&MOCK_DNS_AAAA.octets());
        }
        _ => {
            // No answer for other qtypes — the gate relays a NOERROR
            // empty answer and the resolver moves on.
            resp.truncate(6);
            resp.extend_from_slice(&0u16.to_be_bytes());
            resp.extend_from_slice(&[0, 0, 0, 0]);
            resp.extend_from_slice(question);
            return Some(resp);
        }
    }
    Some(resp)
}

fn start_mock_dns() -> Option<MockDns> {
    let sock = match UdpSocket::bind((Ipv6Addr::LOCALHOST, 0)) {
        Ok(s) => s,
        Err(e) => {
            common::skip_e2e_test(&format!("mock dns bind on [::1] failed: {e}"));
            return None;
        }
    };
    let addr = SocketAddr::new(
        IpAddr::V6(Ipv6Addr::LOCALHOST),
        sock.local_addr().ok()?.port(),
    );
    std::thread::spawn(move || {
        let mut buf = [0u8; 2048];
        while let Ok((n, from)) = sock.recv_from(&mut buf) {
            if let Some(resp) = mock_dns_response(&buf[..n]) {
                let _ = sock.send_to(&resp, from);
            }
        }
    });
    Some(MockDns { addr })
}

// ─── policy / run helpers ────────────────────────────────────────────

/// The fixture's syscall surface: the shared baseline plus the socket
/// ops `net_probe` needs (`sendto`/`recvfrom`/`recvmsg`/`sendmsg` are
/// the datagram verbs the namespaced route exists to cover). `socket`
/// is allow-listed so the policy seccomp lets the family pin — not the
/// filter — decide what a datagram socket may do.
const NET_PROBE_SYSCALLS: &str = concat!(
    "    syscalls {\n",
    "        allow \"read\" \"write\" \"close\" \"openat\" \"open\" \"newfstatat\" \"stat\" ",
    "\"fstat\" \"lstat\" \"lseek\" \"mmap\" \"mprotect\" \"munmap\" \"brk\" ",
    "\"rt_sigaction\" \"rt_sigprocmask\" \"rt_sigreturn\" \"ioctl\" \"pread64\" ",
    "\"pwrite64\" \"readv\" \"writev\" \"getcwd\" \"chdir\" \"fcntl\" \"flock\" ",
    "\"fsync\" \"dup\" \"dup2\" \"dup3\" \"pipe\" \"pipe2\" \"clone\" \"clone3\" ",
    "\"execve\" \"exit\" \"exit_group\" \"wait4\" \"kill\" \"getpid\" \"getppid\" ",
    "\"getuid\" \"getgid\" \"geteuid\" \"getegid\" \"setsid\" \"sigaltstack\" ",
    "\"futex\" \"nanosleep\" \"clock_gettime\" \"clock_nanosleep\" \"getrandom\" ",
    "\"prctl\" \"arch_prctl\" \"set_tid_address\" \"set_robust_list\" ",
    "\"sched_getaffinity\" \"sched_yield\" \"madvise\" \"prlimit64\" \"rseq\" ",
    "\"getdents64\" \"access\" \"readlink\" \"readlinkat\" \"epoll_create1\" \"epoll_ctl\" ",
    "\"epoll_pwait\" \"epoll_wait\" \"poll\" \"select\" \"pselect6\" \"ppoll\" ",
    "\"socket\" \"bind\" \"connect\" \"sendto\" \"sendmsg\" \"sendmmsg\" \"recvfrom\" \"recvmsg\" ",
    "\"getsockname\" \"getpeername\" \"getsockopt\" \"setsockopt\" \"gettid\"\n",
    "    }\n",
);

/// Policy for one leg: `allow "/" mode="read"` covers the fixture
/// image and loader without naming a masked tree; `net_rules` are the
/// leg's egress rules verbatim inside `network { }`; `fs_extra` adds
/// fs allow lines for the refusal leg.
fn write_policy(dir: &Path, fs_extra: &str, net_rules: &str) -> PathBuf {
    let policy = dir.join("policy.kdl");
    let body = format!(
        "policy version=1\n\ndefaults {{\n    filesystem {{\n        allow \"/\" mode=\"read\"\n{fs_extra}    }}\n{NET_PROBE_SYSCALLS}    network {{\n{net_rules}    }}\n}}\n\nlogging fail_closed=#false\n\nserver \"probe\" {{\n    tool \"probe\"\n}}\n"
    );
    std::fs::write(&policy, body).expect("write policy");
    policy
}

/// `allow host=<ip> proto=<proto> port=<ok>` + `deny host="*"` — the
/// allowed leg pins the echo server's destination and port; the
/// denied leg is the same host on a port no rule grants.
fn allow_deny_rules(ip: Ipv4Addr, proto: &str, ok_port: u16) -> String {
    format!(
        "        allow host=\"{ip}\" proto=\"{proto}\" port={ok_port}\n        deny host=\"*\"\n"
    )
}

/// The port the denied leg probes: adjacent to the allowed one, so no
/// listener or rule can collide with the test's own servers.
fn denied_port(ok_port: u16) -> u16 {
    if ok_port == u16::MAX {
        ok_port - 1
    } else {
        ok_port + 1
    }
}

struct Run {
    code: i32,
    #[allow(dead_code)]
    stdout: String,
    stderr: String,
}

/// Run `mcp-writ run` against `policy` with the fixture workload.
/// `mechanism` is the `--linux-mechanism` value (`None` = flag absent,
/// i.e. the `run` default); `kill_after_ms` arms the proxy-loss fault
/// injection on the supervisor's environment; `dns_upstream` is passed
/// to `--dns-upstream` verbatim (an `ip[:port]` literal — a `[v6]:port`
/// spelling forwards the gate's upstream side over a real v6 socket).
///
/// The child's stdin pipe stays open (owned, never read) so the
/// auditor relay outlives the workload — a premature EOF would let the
/// "relay finished" arm win the wait loop and mask the exit path the
/// leg is testing.
fn launch(
    dir: &Path,
    policy: &Path,
    mechanism: Option<&str>,
    kill_after_ms: Option<u64>,
    dns_upstream: Option<String>,
    workload_args: &[String],
) -> Run {
    let audit = dir.join("audit.jsonl");
    let report = dir.join("report.json");
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_mcp-writ"));
    cmd.args(["run", "--policy"])
        .arg(policy)
        .args(["--server", "probe"])
        .args(["--audit-log"])
        .arg(&audit)
        .args(["--report"])
        .arg(&report);
    if let Some(m) = mechanism {
        cmd.args(["--linux-mechanism", m]);
    }
    if let Some(u) = dns_upstream {
        cmd.args(["--dns-upstream", &u]);
    }
    cmd.arg("--")
        .arg(fixture().expect("fixture checked"))
        .args(workload_args);
    cmd.env_remove("MCP_WRIT_SKIP_SANDBOX")
        .env_remove(PROXY_KILL_ENV);
    if let Some(ms) = kill_after_ms {
        cmd.env(PROXY_KILL_ENV, ms.to_string());
    }
    cmd.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .current_dir(dir);
    run_with_timeout(&mut cmd, TEST_TIMEOUT)
}

fn run_with_timeout(cmd: &mut Command, timeout: Duration) -> Run {
    fn drain(mut pipe: impl Read + Send + 'static) -> std::thread::JoinHandle<String> {
        std::thread::spawn(move || {
            let mut s = String::new();
            pipe.read_to_string(&mut s).ok();
            s
        })
    }
    let mut child = cmd.spawn().expect("spawn mcp-writ");
    // Keep the stdin pipe open for the run's whole life — see `launch`.
    let _stdin = child.stdin.take();
    // Drain stdout/stderr on threads — a full pipe would block the
    // child's next write, wedge it alive, and trip a false timeout.
    let stdout_thr = drain(child.stdout.take().unwrap());
    let stderr_thr = drain(child.stderr.take().unwrap());
    let start = std::time::Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait().expect("try_wait") {
            break status;
        }
        if start.elapsed() >= timeout {
            // Reap before panicking — an orphaned child keeps the
            // listener/pipe fds alive and can outlive the test.
            let _ = child.kill();
            let _ = child.wait();
            let _ = stdout_thr.join();
            let _ = stderr_thr.join();
            panic!("mcp-writ run exceeded {timeout:?}");
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    Run {
        code: status.code().unwrap_or(-1),
        stdout: stdout_thr.join().unwrap_or_default(),
        stderr: stderr_thr.join().unwrap_or_default(),
    }
}

// ─── report / audit assertions ───────────────────────────────────────

fn member<'a>(
    v: &nojson::RawJsonValue<'a, 'a>,
    name: &str,
) -> Option<nojson::RawJsonValue<'a, 'a>> {
    v.to_member(name).ok().and_then(|m| m.optional())
}

fn member_str<'a>(v: &nojson::RawJsonValue<'a, 'a>, name: &str) -> Option<String> {
    member(v, name).and_then(|m| m.to_unquoted_string_str().ok().map(|s| s.into_owned()))
}

fn member_u64(v: &nojson::RawJsonValue<'_, '_>, name: &str) -> Option<u64> {
    member(v, name).and_then(|m| m.as_number_str().ok()?.parse().ok())
}

fn member_bool(v: &nojson::RawJsonValue<'_, '_>, name: &str) -> Option<bool> {
    member(v, name).and_then(|m| m.as_boolean_str().ok().map(|s| s == "true"))
}

/// The `mechanism.namespaced` object, flattened — `None` when the
/// launch never bound the namespaced route (refusal, native pick).
struct NsReport {
    sandbox_applied: Option<bool>,
    proxy_lost: Option<bool>,
    udp_datagrams: u64,
    udp_denied: u64,
    tcp_accepted: u64,
    tcp_denied: u64,
    dns_queries: u64,
    /// Extension-header/fragment v6 drops — parsed so the report's
    /// fail-closed surface stays pinned; no e2e leg emits one
    /// (std sockets cannot set IPV6_HOPOPTS, and the in-namespace
    /// seccomp denies raw sockets). `stack`'s unit tests exercise
    /// the counter itself.
    #[allow(dead_code)]
    dropped_v6_ext: u64,
}

struct Report {
    requested: Option<String>,
    selected: Option<String>,
    status: Option<String>,
    detail: Option<String>,
    violations: Vec<String>,
    ns: Option<NsReport>,
}

/// Read the `--report` file's selection + result members — the
/// machine-readable evidence of which mechanism the launch picked
/// (or why it refused).
fn read_report(dir: &Path) -> Report {
    let body = std::fs::read_to_string(dir.join("report.json")).expect("report file");
    let parsed = nojson::RawJson::parse(&body).expect("report must parse");
    let root = parsed.value();
    let plan = member(&root, "plan").expect("report.plan");
    let mech = member(&plan, "mechanism").expect("report.plan.mechanism");
    let result = member(&root, "result").expect("report.result");
    let ns = member(&mech, "namespaced").and_then(|n| {
        if n.kind().is_null() {
            return None;
        }
        let stats = member(&n, "stats");
        let num = |name: &str| stats.and_then(|s| member_u64(&s, name)).unwrap_or(0);
        Some(NsReport {
            sandbox_applied: member_bool(&n, "sandbox_applied"),
            proxy_lost: member_bool(&n, "proxy_lost"),
            udp_datagrams: num("udp_datagrams"),
            udp_denied: num("udp_denied"),
            tcp_accepted: num("tcp_accepted"),
            tcp_denied: num("tcp_denied"),
            dns_queries: num("dns_queries"),
            dropped_v6_ext: num("dropped_v6_ext"),
        })
    });
    let violations = member(&mech, "violations")
        .and_then(|arr| arr.to_array().ok())
        .map(|els| {
            els.filter_map(|e| e.to_unquoted_string_str().ok().map(|s| s.into_owned()))
                .collect()
        })
        .unwrap_or_default();
    Report {
        requested: member_str(&mech, "requested"),
        selected: member_str(&mech, "selected"),
        status: member_str(&result, "status"),
        detail: member_str(&result, "detail"),
        violations,
        ns,
    }
}

/// The namespaced member for a leg that must have selected the route.
fn ns_of(report: &Report) -> &NsReport {
    report
        .ns
        .as_ref()
        .expect("mechanism.namespaced is null — the namespaced route was not selected")
}

fn audit_lines(dir: &Path) -> Vec<String> {
    std::fs::read_to_string(dir.join("audit.jsonl"))
        .unwrap_or_default()
        .lines()
        .map(|l| l.to_string())
        .collect()
}

/// Audit records of one event type containing `needle` — both the
/// allow and deny halves of the egress verdict contract.
fn audit_matching(dir: &Path, event: &str, needle: &str) -> Vec<String> {
    audit_lines(dir)
        .into_iter()
        .filter(|l| l.contains(event) && l.contains(needle))
        .collect()
}

// ─── tests ───────────────────────────────────────────────────────────

/// `auto` + a destination-scoped UDP allow: only the namespaced route
/// can express it (native Landlock net rules bind a port, never a
/// destination or the datagram family), so selection must land there.
/// `udp-two` exercises both halves of the rule — the allowed echo and
/// the dropped denied datagram.
#[test]
fn auto_selects_namespaced_for_udp_policy() {
    if !namespaced_capable() {
        return;
    }
    let Some(ip) = host_ipv4() else { return };
    let Some(srv) = start_echo_servers() else {
        return;
    };
    if fixture().is_none() {
        return;
    }
    let dir = common::real_tempdir();
    let deny = denied_port(srv.udp_port);
    let policy = write_policy(dir.path(), "", &allow_deny_rules(ip, "udp", srv.udp_port));
    let run = launch(
        dir.path(),
        &policy,
        Some("auto"),
        None,
        None,
        &[
            "udp-two".to_string(),
            format!("{ip}:{}", srv.udp_port),
            format!("{ip}:{deny}"),
        ],
    );
    assert_eq!(run.code, 0, "stderr: {}", run.stderr);
    let report = read_report(dir.path());
    assert_eq!(report.requested.as_deref(), Some("auto"));
    assert_eq!(report.selected.as_deref(), Some("linux-namespaced"));
    let ns = ns_of(&report);
    assert_eq!(ns.sandbox_applied, Some(true));
    assert_eq!(ns.proxy_lost, Some(false));
    assert!(
        ns.udp_datagrams >= 1,
        "allowed leg must relay at least one datagram"
    );
    assert!(
        ns.udp_denied >= 1,
        "denied leg must be counted at the evaluator"
    );
    assert!(
        !audit_matching(
            dir.path(),
            "sandbox.network_allowed",
            &format!("port={}", srv.udp_port)
        )
        .is_empty(),
        "audit must carry the allowed UDP verdict"
    );
    assert!(
        !audit_matching(
            dir.path(),
            "sandbox.network_denied",
            &format!("port={deny}")
        )
        .is_empty(),
        "audit must carry the denied UDP verdict"
    );
}

/// Explicit `--linux-mechanism namespaced` + a destination-scoped TCP
/// allow: `tcp-two` must see the allowed connect spliced to the host
/// echo server and a connect to a *different host on the same port*
/// refused. The denied leg deliberately keeps the granted port: the
/// in-namespace Landlock netport rule lets it through (it binds a
/// port, not a destination), so the refusal happens at the proxy
/// evaluator — destination narrowing is the namespaced route's whole
/// reason to exist, and `tcp_denied` + the audit record are its proof.
#[test]
fn namespaced_tcp_allow_and_deny() {
    if !namespaced_capable() {
        return;
    }
    let Some(ip) = host_ipv4() else { return };
    let Some(srv) = start_echo_servers() else {
        return;
    };
    if fixture().is_none() {
        return;
    }
    let dir = common::real_tempdir();
    // TEST-NET-3: a public spelling no `allow` rule names — the flow
    // passes the in-ns port rule and dies at the proxy's `deny host="*"`.
    let denied_dest = Ipv4Addr::new(203, 0, 113, 9);
    let policy = write_policy(dir.path(), "", &allow_deny_rules(ip, "tcp", srv.tcp_port));
    let run = launch(
        dir.path(),
        &policy,
        Some("namespaced"),
        None,
        None,
        &[
            "tcp-two".to_string(),
            format!("{ip}:{}", srv.tcp_port),
            format!("{denied_dest}:{}", srv.tcp_port),
        ],
    );
    assert_eq!(run.code, 0, "stderr: {}", run.stderr);
    let report = read_report(dir.path());
    assert_eq!(report.requested.as_deref(), Some("namespaced"));
    assert_eq!(report.selected.as_deref(), Some("linux-namespaced"));
    assert_eq!(report.status.as_deref(), Some("exited"));
    let ns = ns_of(&report);
    assert!(ns.tcp_accepted >= 1, "allowed connect must be spliced");
    assert!(
        ns.tcp_denied >= 1,
        "denied connect must be refused at the evaluator"
    );
    assert!(
        !audit_matching(
            dir.path(),
            "sandbox.network_denied",
            &format!("dest={denied_dest}")
        )
        .is_empty(),
        "audit must carry the denied TCP verdict"
    );
}

/// `run` with no `--linux-mechanism` flag requests `auto` — and `auto`
/// prefers `linux-namespaced` even when the native route *could*
/// satisfy the policy (a port-scoped `host="*"` TCP allow fits
/// Landlock netport rules). The selection must not collapse to native
/// just because native is sufficient.
#[test]
fn run_default_is_auto_and_prefers_namespaced() {
    if !namespaced_capable() {
        return;
    }
    let Some(ip) = host_ipv4() else { return };
    let Some(srv) = start_echo_servers() else {
        return;
    };
    if fixture().is_none() {
        return;
    }
    let dir = common::real_tempdir();
    // `host="*"` + port is the shape the native netport rules express
    // — a satisfiable-but-less-preferred policy for the auto choice.
    let policy = write_policy(
        dir.path(),
        "",
        &format!(
            "        allow host=\"*\" proto=\"tcp\" port={}\n        deny host=\"*\"\n",
            srv.tcp_port
        ),
    );
    let run = launch(
        dir.path(),
        &policy,
        None,
        None,
        None,
        &["tcp-echo".to_string(), format!("{ip}:{}", srv.tcp_port)],
    );
    assert_eq!(run.code, 0, "stderr: {}", run.stderr);
    let report = read_report(dir.path());
    assert_eq!(
        report.requested.as_deref(),
        Some("auto"),
        "a run with no --linux-mechanism must record the auto request"
    );
    assert_eq!(
        report.selected.as_deref(),
        Some("linux-namespaced"),
        "auto must prefer namespaced on a capable host even when native satisfies"
    );
}

/// `--linux-mechanism native` + a UDP-covered allow under deny-all:
/// the native route's datagram socket pin makes the grant dead
/// policy, so selection refuses *before spawn* — the workload never
/// runs and the audit carries no `server.connected`. An explicit
/// `native` request skips the capability probe, so this leg runs on
/// hosts without userns/netns support.
#[test]
fn native_refuses_udp_allow_before_spawn() {
    let Some(ip) = host_ipv4() else { return };
    let Some(srv) = start_echo_servers() else {
        return;
    };
    if fixture().is_none() {
        return;
    }
    let dir = common::real_tempdir();
    let policy = write_policy(dir.path(), "", &allow_deny_rules(ip, "udp", srv.udp_port));
    let run = launch(
        dir.path(),
        &policy,
        Some("native"),
        None,
        None,
        &["udp-echo".to_string(), format!("{ip}:{}", srv.udp_port)],
    );
    assert_ne!(run.code, 0, "native must refuse; stderr: {}", run.stderr);
    assert!(
        run.stderr.contains("launch refused"),
        "refusal reason must reach stderr: {}",
        run.stderr
    );
    let report = read_report(dir.path());
    assert_eq!(report.requested.as_deref(), Some("native"));
    assert_eq!(
        report.selected.as_deref(),
        None,
        "a refused selection binds no mechanism"
    );
    assert_eq!(report.status.as_deref(), Some("failed"));
    assert!(
        report
            .detail
            .as_deref()
            .unwrap_or("")
            .contains("launch refused"),
        "result.detail must name the refusal: {:?}",
        report.detail
    );
    assert!(
        audit_lines(dir.path())
            .iter()
            .all(|l| !l.contains("server.connected")),
        "a refused launch must never spawn the workload"
    );
}

/// `--linux-mechanism namespaced` + a policy the route cannot satisfy
/// (an fs grant rooted under `/run`, which init covers with a private
/// tmpfs): the launch refuses — explicit mechanism requests never fall
/// back to another mechanism.
#[test]
fn namespaced_refuses_unsatisfiable_policy_without_fallback() {
    if !namespaced_capable() {
        return;
    }
    let Some(ip) = host_ipv4() else { return };
    let Some(srv) = start_echo_servers() else {
        return;
    };
    if fixture().is_none() {
        return;
    }
    let dir = common::real_tempdir();
    // `/run` is masked unconditionally (unlike `/tmp`, whose mask
    // depends on the resolv.conf redirect) — the violation fires on
    // every host, container or not.
    let policy = write_policy(
        dir.path(),
        "        allow \"/run/mcp-writ-e2e-masked\" mode=\"read\"\n",
        &allow_deny_rules(ip, "udp", srv.udp_port),
    );
    let run = launch(
        dir.path(),
        &policy,
        Some("namespaced"),
        None,
        None,
        &["udp-echo".to_string(), format!("{ip}:{}", srv.udp_port)],
    );
    assert_ne!(
        run.code, 0,
        "namespaced must refuse a masked-tree grant; stderr: {}",
        run.stderr
    );
    assert!(
        run.stderr.contains("launch refused") && run.stderr.contains("masked tree"),
        "refusal detail must name the masked-tree violation: {}",
        run.stderr
    );
    let report = read_report(dir.path());
    assert_eq!(report.requested.as_deref(), Some("namespaced"));
    assert_eq!(report.selected.as_deref(), None);
    assert_eq!(report.status.as_deref(), Some("failed"));
    assert!(
        audit_lines(dir.path())
            .iter()
            .all(|l| !l.contains("server.connected")),
        "a refused launch must never spawn the workload"
    );
}

/// The previously unverified leg from
/// `docs/validation/linux-namespaced-proxy.md`: force the egress proxy
/// task to end while a `udp-loop` flow is active. The supervision loss
/// is fail-closed — the workload is killed, `run` exits nonzero, the
/// report records `proxy_lost`, and the audit closes with
/// `reason=supervision_lost`. There is no degraded/native continuation.
#[test]
fn proxy_loss_during_active_udp_traffic_kills_workload() {
    if !namespaced_capable() {
        return;
    }
    let Some(ip) = host_ipv4() else { return };
    let Some(srv) = start_echo_servers() else {
        return;
    };
    if fixture().is_none() {
        return;
    }
    let dir = common::real_tempdir();
    let policy = write_policy(dir.path(), "", &allow_deny_rules(ip, "udp", srv.udp_port));
    // 3000 ms: the kill timer counts from proxy-task spawn — *before*
    // the GO handshake, init re-exec, and workload exec — while the
    // first `NETPROBE-HB` lands ~1 s into the loop (20 sends at 50 ms).
    // The wider margin absorbs slow CI startup and still ends the proxy
    // mid-traffic: the run fails on the proxy arm, not on a workload
    // that had already finished.
    let run = launch(
        dir.path(),
        &policy,
        Some("namespaced"),
        Some(3000),
        None,
        &[
            "udp-loop".to_string(),
            format!("{ip}:{}", srv.udp_port),
            "e2e".to_string(),
        ],
    );
    assert_ne!(
        run.code, 0,
        "supervision loss must fail the run, not degrade: stderr {}",
        run.stderr
    );
    assert!(
        run.stderr.contains("NETPROBE-HB"),
        "the workload must have been mid-traffic when the proxy died: {}",
        run.stderr
    );
    let report = read_report(dir.path());
    assert_eq!(report.selected.as_deref(), Some("linux-namespaced"));
    assert_eq!(report.status.as_deref(), Some("failed"));
    let ns = ns_of(&report);
    assert_eq!(
        ns.proxy_lost,
        Some(true),
        "the report must record the supervision loss"
    );
    assert!(
        ns.udp_datagrams >= 1,
        "datagrams must have flowed before the proxy ended"
    );
    assert!(
        !audit_matching(dir.path(), "server.disconnected", "reason=supervision_lost").is_empty(),
        "audit must close the session as a supervision loss"
    );
}

// ─── PR-26a: IPv6 dual-stack legs ────────────────────────────────────
//
// A host without global v6 still runs every leg except
// `namespaced_ipv6_flows_allowed_on_v6_host`: the DNS leg terminates
// inside the gate (v6 packets both ways, no host v6 route needed),
// the denied legs exercise classify+verdict, and the open-posture
// allow legs prove the *verdict* is family-generic — the subsequent
// host-side dial fails closed per flow, which is exactly the spec's
// "v6 到達性が無い宛先は当該フローのみ拒否".

/// AAAA resolution → TTL-scoped v6 grant → grant-authorized v6 flow.
/// The workload resolves `v6ok.example` through the in-netns
/// `resolv.conf` (its v6 nameserver spelling reaches the same port-53
/// intercept), the gate forwards over a real v6 upstream socket to
/// the mock resolver on `[::1]`, and the minted `2001:db8::5` grant
/// is the flow's only authority — the audit `network_allowed` with
/// `basis=allowlist-grant` is the proof the grant reached the
/// evaluator. The parent-side dial to the doc-net v6 fails closed
/// (RST) on a host without a v6 route to it — per-flow refusal, not
/// a launch failure.
#[test]
fn namespaced_ipv6_dns_aaaa_mints_and_consumes_grant() {
    if !namespaced_capable() {
        return;
    }
    let Some(dns) = start_mock_dns() else {
        return;
    };
    if fixture().is_none() {
        return;
    }
    let dir = common::real_tempdir();
    let policy = write_policy(
        dir.path(),
        "",
        "        allow host=\"v6ok.example\"\n        deny host=\"*\"\n",
    );
    let run = launch(
        dir.path(),
        &policy,
        Some("namespaced"),
        None,
        Some(dns.addr.to_string()),
        &["dns6-flow".to_string(), "v6ok.example:443".to_string()],
    );
    assert_eq!(
        run.code, 1,
        "the allowed-but-unreachable v6 dial must fail closed; stderr: {}",
        run.stderr
    );
    assert!(
        run.stderr.contains(&format!("RESOLVED {MOCK_DNS_AAAA}")),
        "the workload must log the AAAA answer it received: {}",
        run.stderr
    );
    let report = read_report(dir.path());
    assert_eq!(report.selected.as_deref(), Some("linux-namespaced"));
    let ns = ns_of(&report);
    assert!(ns.dns_queries >= 1, "the intercepted query must be counted");
    assert!(
        !audit_matching(dir.path(), "sandbox.network_resolved", "name=v6ok.example").is_empty(),
        "audit must carry the gate's resolution record"
    );
    assert!(
        !audit_matching(
            dir.path(),
            "sandbox.network_resolved",
            &format!("addrs=[{MOCK_DNS_AAAA}")
        )
        .is_empty(),
        "the resolution record must name the AAAA answer"
    );
    let allowed = audit_matching(
        dir.path(),
        "sandbox.network_allowed",
        &format!("dest={MOCK_DNS_AAAA}"),
    );
    assert!(
        !allowed.is_empty() && allowed.iter().any(|l| l.contains("basis=allowlist-grant")),
        "the minted v6 grant must authorize the flow: {allowed:?}"
    );
}

/// `deny host=<v6>` on a UDP datagram — the v6 packet is classified,
/// the verdict refuses it, and the drop is counted; the audit names
/// the v6 spelling the workload dialed.
#[test]
fn namespaced_ipv6_udp_deny_drops_and_audits() {
    if !namespaced_capable() {
        return;
    }
    if fixture().is_none() {
        return;
    }
    let dir = common::real_tempdir();
    let denied6 = "2001:db8::9".parse::<Ipv6Addr>().unwrap();
    let policy = write_policy(
        dir.path(),
        "",
        "        allow host=\"*\"\n        deny host=\"2001:db8::9\"\n",
    );
    // Port 9 (discard), not 53 — while a DNS upstream exists on the
    // host the gate intercepts :53 before the destination evaluator
    // ever sees the datagram; any other port keeps the flow on the
    // per-datagram verdict this leg asserts.
    let run = launch(
        dir.path(),
        &policy,
        Some("namespaced"),
        None,
        None,
        &["udp6-echo".to_string(), format!("[{denied6}]:9")],
    );
    assert_eq!(
        run.code, 11,
        "a denied datagram drops silently — the workload sees a timeout: {}",
        run.stderr
    );
    let report = read_report(dir.path());
    let ns = ns_of(&report);
    assert!(ns.udp_datagrams >= 1, "the v6 datagram must be classified");
    assert!(ns.udp_denied >= 1, "the v6 deny must be counted");
    assert!(
        !audit_matching(
            dir.path(),
            "sandbox.network_denied",
            &format!("dest={denied6}")
        )
        .is_empty(),
        "audit must carry the v6 deny verdict"
    );
}

/// Open-posture `allow host="*"` covers a pure-v6 destination: the
/// verdict is `open`-basis allow, the authorize record is durable,
/// and only the host-side dial fails — fail-closed *per flow*, with
/// v4 traffic unaffected. On a v6-less host this is the spec's
/// "当該フローのみ拒否"; on a v6-capable host the dial still fails
/// because `2001:db8::5` is a doc-net spelling nobody answers.
#[test]
fn namespaced_ipv6_allow_verdict_dial_fails_closed() {
    if !namespaced_capable() {
        return;
    }
    if fixture().is_none() {
        return;
    }
    let dir = common::real_tempdir();
    let dest6 = "2001:db8::5".parse::<Ipv6Addr>().unwrap();
    let policy = write_policy(dir.path(), "", "        allow host=\"*\"\n");
    let run = launch(
        dir.path(),
        &policy,
        Some("namespaced"),
        None,
        None,
        &["tcp6-echo".to_string(), format!("[{dest6}]:443")],
    );
    // Exit 1 or 2 — the race is timing: the DNAT listener completes
    // the handshake eagerly, then the failed host-side dial resets the
    // flow; whether the RST lands inside connect() (1) or at the
    // write/echo (2) depends on scheduling. Both prove the flow died.
    assert!(
        run.code == 1 || run.code == 2,
        "the flow's verdict is allow; the v6-less dial fails closed: {}",
        run.stderr
    );
    let report = read_report(dir.path());
    let ns = ns_of(&report);
    assert!(
        ns.tcp_accepted >= 1,
        "the v6 SYN must be DNAT'd, accepted, and verdict-allowed"
    );
    assert!(
        !audit_matching(
            dir.path(),
            "sandbox.network_allowed",
            &format!("dest={dest6}")
        )
        .is_empty(),
        "audit must carry the v6 allow verdict"
    );
}

/// A destination-scoped v6 *allow* on a host with no route to it is
/// dead policy: the flow would fail at every dial, so selection must
/// refuse with a named reason — never launch and silently blackhole.
/// Only meaningful on a host that truly lacks v6 reachability; skips
/// where a global-v6 route exists (there the same policy selects).
#[test]
fn namespaced_refuses_v6_allow_when_host_cannot_route_it() {
    // Same env-scope gate: on a v6-capable host the policy below is
    // satisfiable, so there is nothing to refuse — skip silently.
    if v6_globally_routable() {
        eprintln!("skip: host has a global-v6 route — unreachable-v6 refusal leg does not apply");
        return;
    }
    if !namespaced_capable() {
        return;
    }
    if fixture().is_none() {
        return;
    }
    let dir = common::real_tempdir();
    let policy = write_policy(
        dir.path(),
        "",
        "        allow host=\"2001:db8::5\" proto=\"tcp\" port=443\n        deny host=\"*\"\n",
    );
    let run = launch(
        dir.path(),
        &policy,
        Some("namespaced"),
        None,
        None,
        &["tcp6-echo".to_string(), "[2001:db8::5]:443".to_string()],
    );
    assert_ne!(
        run.code, 0,
        "a v6 allow on a v6-less host must refuse the launch: stderr {}",
        run.stderr
    );
    assert!(
        run.stderr.contains("launch refused"),
        "refusal must reach stderr: {}",
        run.stderr
    );
    let report = read_report(dir.path());
    assert!(
        report.violations.iter().any(|v| v.contains("IPv6")),
        "the refusal must name the unroutable v6 destination: {:?}",
        report.violations
    );
    assert_eq!(report.selected.as_deref(), None);
    assert_eq!(report.status.as_deref(), Some("failed"));
    assert!(
        audit_lines(dir.path())
            .iter()
            .all(|l| !l.contains("server.connected")),
        "a refused launch must never spawn the workload"
    );
}

/// Environment-dependent leg (spec: 外部 v6 宛は環境依存レグとして分
/// 離): a real v6 allowed flow needs a host-owned v6 address — the
/// workload dials the host's own routable v6, the proxy splices the
/// flow to the echo server over the host's real v6 stack. Skips on a
/// v6-less host (WSL2 default); `MCP_WRIT_REQUIRE_E2E_TESTS` still
/// forces the *prerequisite* failures to be loud, not the env shape.
#[test]
fn namespaced_ipv6_flows_allowed_on_v6_host() {
    if !namespaced_capable() {
        return;
    }
    // These two gates skip silently rather than via
    // `common::skip_e2e_test`: an absent host v6 is this leg's declared
    // environment scope, not a missing prerequisite — REQUIRE_E2E
    // must not turn "the host genuinely has no v6" into a failure.
    let Some(v6) = host_ipv6() else {
        eprintln!("skip: no host-owned global/ULA IPv6 — external-v6 leg");
        return;
    };
    if !v6_globally_routable() {
        eprintln!("skip: host v6 address exists but no v6 route — external-v6 leg");
        return;
    }
    if fixture().is_none() {
        return;
    }
    // v6-wildcard echo servers: the proxy's parent-side relay connects
    // to this host's own v6 address, exercising the real v6 data path.
    let udp = match UdpSocket::bind((Ipv6Addr::UNSPECIFIED, 0)) {
        Ok(s) => s,
        Err(e) => {
            common::skip_e2e_test(&format!("v6 udp echo bind failed: {e}"));
            return;
        }
    };
    let tcp = match TcpListener::bind((Ipv6Addr::UNSPECIFIED, 0)) {
        Ok(l) => l,
        Err(e) => {
            common::skip_e2e_test(&format!("v6 tcp echo bind failed: {e}"));
            return;
        }
    };
    let udp_port = udp.local_addr().unwrap().port();
    let tcp_port = tcp.local_addr().unwrap().port();
    std::thread::spawn(move || {
        let mut buf = [0u8; 2048];
        while let Ok((n, from)) = udp.recv_from(&mut buf) {
            let _ = udp.send_to(&buf[..n], from);
        }
    });
    std::thread::spawn(move || {
        for stream in tcp.incoming().flatten() {
            std::thread::spawn(move || {
                let mut s = stream;
                let mut peer = match s.try_clone() {
                    Ok(p) => p,
                    Err(_) => return,
                };
                let _ = std::io::copy(&mut peer, &mut s);
            });
        }
    });
    let dir = common::real_tempdir();
    let policy = write_policy(
        dir.path(),
        "",
        &format!("        allow host=\"{v6}\" proto=\"any\"\n        deny host=\"*\"\n"),
    );
    // UDP allow+deny: the allowed datagram echoes over the real v6
    // path; a denied v6 spelling drops.
    let denied6 = "2001:db8::9";
    let run = launch(
        dir.path(),
        &policy,
        Some("namespaced"),
        None,
        None,
        &[
            "udp6-two".to_string(),
            format!("[{v6}]:{udp_port}"),
            format!("[{denied6}]:{udp_port}"),
        ],
    );
    assert_eq!(run.code, 0, "v6 udp allow+deny legs: {}", run.stderr);
    let report = read_report(dir.path());
    let ns = ns_of(&report);
    assert!(ns.udp_datagrams >= 2, "both v6 datagrams must classify");
    assert!(ns.udp_denied >= 1, "the denied v6 datagram must count");
    assert!(
        !audit_matching(
            dir.path(),
            "sandbox.network_denied",
            &format!("dest={denied6}")
        )
        .is_empty(),
        "audit must carry the denied v6 verdict"
    );
    // TCP allow: the v6 SYN splices to the echo server.
    let dir = common::real_tempdir();
    let policy = write_policy(
        dir.path(),
        "",
        &format!(
            "        allow host=\"{v6}\" proto=\"tcp\" port={tcp_port}\n        deny host=\"*\"\n"
        ),
    );
    let run = launch(
        dir.path(),
        &policy,
        Some("namespaced"),
        None,
        None,
        &["tcp6-echo".to_string(), format!("[{v6}]:{tcp_port}")],
    );
    assert_eq!(run.code, 0, "v6 tcp allow leg: {}", run.stderr);
    let report = read_report(dir.path());
    let ns = ns_of(&report);
    assert!(
        ns.tcp_accepted >= 1,
        "the v6 connect must be spliced over the host's v6 stack"
    );
    assert!(
        !audit_matching(dir.path(), "sandbox.network_allowed", &format!("dest={v6}")).is_empty(),
        "audit must carry the allowed v6 flow"
    );
}
