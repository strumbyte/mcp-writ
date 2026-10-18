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
use std::net::{Ipv4Addr, TcpListener, UdpSocket};
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
/// The hook only exists under `debug_assertions`; this target drives
/// the dev-profile `CARGO_BIN_EXE_mcp-writ`, which carries it.
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
    "\"epoll_pwait\" \"epoll_wait\" \"poll\" \"select\" \"pselect6\" ",
    "\"socket\" \"bind\" \"connect\" \"sendto\" \"sendmsg\" \"recvfrom\" \"recvmsg\" ",
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
/// injection on the supervisor's environment.
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
}

struct Report {
    requested: Option<String>,
    selected: Option<String>,
    status: Option<String>,
    detail: Option<String>,
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
        })
    });
    Report {
        requested: member_str(&mech, "requested"),
        selected: member_str(&mech, "selected"),
        status: member_str(&result, "status"),
        detail: member_str(&result, "detail"),
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
