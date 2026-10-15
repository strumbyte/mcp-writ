//! End-to-end tests for `macos-proxy-run` — the PR-11 macOS opt-in
//! (improvement plan §1.5): `sandbox-exec` pins the workload's outbound
//! TCP to a loopback CONNECT proxy that evaluates name/IP destination
//! rules and dials outward.
//!
//! Each test spawns the real `mcp-writ` binary and a real workload
//! (`/usr/bin/python3` connect probe — the only Python use — `nc`/`sh`
//! one-liners, or the rustc-compiled `sigterm_probe` fixture; the probe
//! honors the injected `https_proxy` env, which is exactly how a proxied
//! client behaves). The CONNECT target is the host's own non-loopback
//! interface address, so a proxy-mediated "external" dial is real
//! without depending on internet reachability.
//!
//! Assertions cover: proxy-mediated allowed egress (+ splice),
//! policy-refused egress with `sandbox.network_denied` at both the IP
//! and name layers, the protected-destination (SSRF) guard, missing
//! credentials, the loopback pin (direct connect + loopback bypass
//! both kernel-denied), UDP denial, the in-sandbox resolver being
//! unreachable, a name that fails resolution (`resolve-error`), an
//! oversized request head getting a `431`, the `--listen` port
//! appearing in the report, an allowed-but-refused name flow leaving
//! no `sandbox.network_allowed` (the event means "established"), a
//! WHATWG-number authority judged as its folded IP literal, SIGTERM
//! forwarding to the sandboxed workload, the capability report shape,
//! and the native `run` path staying unregressed.
//!
//! Every test skips via `common::skip_e2e_test` when a prerequisite
//! (sandbox-exec helper, python3 or rustc for fixtures, a usable host
//! interface address) is unavailable — `MCP_WRIT_REQUIRE_E2E_TESTS=1`
//! turns a skip into a failure so a mandatory run can never pass
//! unexecuted.

#![cfg(target_os = "macos")]

use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream, ToSocketAddrs, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

mod common;

const TEST_TIMEOUT: Duration = Duration::from_secs(30);

// ─── fixture / policy helpers ────────────────────────────────────────

/// The CONNECT probe script — runs sandboxed, honors `https_proxy`.
fn probe_script() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/macos_proxy/connect_probe.py")
}

/// `/usr/bin/python3` — the system interpreter (the SBPL base profile
/// only covers system paths; a Homebrew python would not exec inside
/// the sandbox).
fn sys_python() -> Option<String> {
    let p = "/usr/bin/python3";
    match Command::new(p)
        .arg("-c")
        .arg("pass")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
    {
        Ok(s) if s.success() => Some(p.to_string()),
        _ => {
            common::skip_e2e_test("/usr/bin/python3 unavailable");
            None
        }
    }
}

/// Compile the sigterm-probe fixture once per test binary — the same
/// `rustc -O`-at-test-time convention as `common::compiled_open_path_fixture`.
fn compiled_sigterm_probe() -> Option<PathBuf> {
    static FIXTURE: std::sync::OnceLock<Option<PathBuf>> = std::sync::OnceLock::new();
    FIXTURE
        .get_or_init(|| {
            let src = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/macos_proxy/sigterm_probe.rs");
            let dir = match tempfile::Builder::new()
                .prefix("mcp_writ_sigterm_probe_")
                .tempdir()
            {
                Ok(d) => d,
                Err(e) => {
                    common::skip_e2e_test(&format!("sigterm probe tempdir failed: {e}"));
                    return None;
                }
            };
            let out = dir.path().join("sigterm_probe");
            let status = Command::new("rustc")
                .arg("-O")
                .arg("-o")
                .arg(&out)
                .arg(&src)
                .stdout(Stdio::null())
                .stderr(Stdio::inherit())
                .status();
            match status {
                Ok(s) if s.success() && out.exists() => {
                    let kept = dir.keep();
                    Some(kept.join("sigterm_probe"))
                }
                Ok(s) => {
                    common::skip_e2e_test(&format!("rustc -O sigterm_probe.rs failed: {s}"));
                    None
                }
                Err(e) => {
                    common::skip_e2e_test(&format!("rustc unavailable: {e}"));
                    None
                }
            }
        })
        .clone()
}

/// The host's non-loopback outbound address — the CONNECT target every
/// "external" dial test uses (private/global, never the protected
/// loopback set). `UdpSocket::connect` sends nothing; `local_addr`
/// just names the interface the kernel would route through.
fn host_ip() -> Option<std::net::IpAddr> {
    let sock = match UdpSocket::bind("0.0.0.0:0") {
        Ok(s) => s,
        Err(e) => {
            common::skip_e2e_test(&format!("probe socket failed: {e}"));
            return None;
        }
    };
    if let Err(e) = sock.connect("192.0.2.1:53") {
        common::skip_e2e_test(&format!("no outbound interface: {e}"));
        return None;
    }
    match sock.local_addr() {
        Ok(a) if !a.ip().is_loopback() => Some(a.ip()),
        _ => {
            common::skip_e2e_test("no non-loopback interface address");
            None
        }
    }
}

/// A line-echo listener on `ip:0` — the "external" service the proxy
/// dials. Returns the port plus a handle that ends on drop.
struct Echo {
    port: u16,
    stop: Option<mpsc::Sender<()>>,
    join: Option<std::thread::JoinHandle<()>>,
}

impl Echo {
    fn bind(ip: std::net::IpAddr) -> Self {
        let listener = match TcpListener::bind((ip, 0)) {
            Ok(l) => l,
            Err(e) => panic!("echo listener on {ip} failed: {e}"),
        };
        let port = listener.local_addr().unwrap().port();
        let (tx, rx) = mpsc::channel::<()>();
        let join = std::thread::spawn(move || {
            // Nonblocking accept loop: echo each accepted stream line
            // for line until the client closes.
            listener.set_nonblocking(true).ok();
            loop {
                if rx.try_recv().is_ok() {
                    return;
                }
                match listener.accept() {
                    Ok((stream, _)) => {
                        std::thread::spawn(move || echo_conn(stream));
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(20));
                    }
                    Err(_) => return,
                }
            }
        });
        Self {
            port,
            stop: Some(tx),
            join: Some(join),
        }
    }
}

fn echo_conn(stream: TcpStream) {
    let mut read = BufReader::new(match stream.try_clone() {
        Ok(s) => s,
        Err(_) => return,
    });
    let mut write = stream;
    let mut line = String::new();
    loop {
        line.clear();
        match read.read_line(&mut line) {
            Ok(0) | Err(_) => return,
            Ok(_) => {
                if write.write_all(line.as_bytes()).is_err() {
                    return;
                }
            }
        }
    }
}

impl Drop for Echo {
    fn drop(&mut self) {
        if let Some(tx) = self.stop.take() {
            let _ = tx.send(());
        }
        if let Some(j) = self.join.take() {
            let _ = j.join();
        }
    }
}

/// A workspace-private temp dir that survives a failed run for
/// inspection (next run truncates it).
fn workdir(tag: &str) -> PathBuf {
    // Real spelling: `$TMPDIR` traverses the `/var` → `/private/var`
    // link on macOS, which the audit sink's strict ancestor walk
    // refuses — spell the workdir the way the filesystem lays it out.
    let dir = common::real_temp_base().join(format!(
        "mcp-writ-macos-proxy-e2e-{}-{}",
        std::process::id(),
        tag
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// Fixture policy — mirror of the unotify fixture shape (the workload
/// is not an MCP server; the `server "probe"` block only exists so
/// `--server probe` binds). `rules` is the egress rule set under test.
fn write_policy(dir: &Path, rules: &str) -> PathBuf {
    let policy = dir.join("policy.kdl");
    let body = format!(
        r#"policy version=1

defaults {{
    filesystem {{
        allow "/" mode="read"
    }}
    network {{
{rules}    }}
    logging {{
        fail_closed #false
    }}
}}

server "probe" {{
    tool "probe"
}}
"#
    );
    std::fs::write(&policy, body).unwrap();
    policy
}

struct Run {
    code: i32,
    stdout: String,
    stderr: String,
}

fn run_with_timeout(cmd: &mut Command) -> Run {
    fn drain(mut pipe: impl std::io::Read + Send + 'static) -> std::thread::JoinHandle<String> {
        std::thread::spawn(move || {
            let mut s = String::new();
            std::io::Read::read_to_string(&mut pipe, &mut s).ok();
            s
        })
    }
    let mut child = cmd.spawn().expect("spawn mcp-writ");
    let stdout_thr = drain(child.stdout.take().unwrap());
    let stderr_thr = drain(child.stderr.take().unwrap());
    let start = std::time::Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait().expect("try_wait") {
            break status;
        }
        if start.elapsed() >= TEST_TIMEOUT {
            let _ = child.kill();
            let _ = child.wait();
            let _ = stdout_thr.join();
            let _ = stderr_thr.join();
            panic!("macos-proxy-run exceeded {TEST_TIMEOUT:?}");
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    Run {
        code: status.code().unwrap_or(-1),
        stdout: stdout_thr.join().unwrap_or_default(),
        stderr: stderr_thr.join().unwrap_or_default(),
    }
}

/// `mcp-writ macos-proxy-run --policy <p> --server probe --audit-log <a>
/// --report <r> -- <argv…>` — returns (run, audit path, report path).
fn proxy_run(dir: &Path, policy: &Path, argv: &[String]) -> (Run, PathBuf, PathBuf) {
    proxy_run_opts(dir, policy, argv, &[])
}

/// `proxy_run` with extra options spliced in before the `--` separator.
fn proxy_run_opts(
    dir: &Path,
    policy: &Path,
    argv: &[String],
    extra: &[String],
) -> (Run, PathBuf, PathBuf) {
    let audit = dir.join("audit.jsonl");
    let report = dir.join("report.json");
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_mcp-writ"));
    cmd.args(["macos-proxy-run", "--policy"])
        .arg(policy)
        .args(["--server", "probe"])
        .args(["--audit-log"])
        .arg(&audit)
        .args(["--report"])
        .arg(&report)
        .args(extra)
        .arg("--")
        .args(argv)
        .current_dir(dir)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    (run_with_timeout(&mut cmd), audit, report)
}

/// `connect_probe.py <target>` argv — the proxy-aware workload.
fn probe_argv(target: &str, extra: &[&str]) -> Vec<String> {
    let mut v = vec![
        sys_python().expect("checked by caller"),
        probe_script().to_string_lossy().into_owned(),
    ];
    v.extend(extra.iter().map(|s| s.to_string()));
    v.push(target.to_string());
    v
}

fn audit_lines(audit: &Path) -> Vec<String> {
    std::fs::read_to_string(audit)
        .unwrap_or_default()
        .lines()
        .map(|l| l.to_string())
        .collect()
}

fn denied_records(audit: &Path) -> Vec<String> {
    audit_lines(audit)
        .into_iter()
        .filter(|l| l.contains("sandbox.network_denied"))
        .collect()
}

fn allowed_records(audit: &Path) -> Vec<String> {
    audit_lines(audit)
        .into_iter()
        .filter(|l| l.contains("sandbox.network_allowed"))
        .collect()
}

fn report_body(report: &Path) -> String {
    std::fs::read_to_string(report).unwrap_or_default()
}

/// Whether `sandbox-exec` itself is present — the mechanism's single
/// hard prerequisite.
fn sandbox_exec_available() -> bool {
    Path::new("/usr/bin/sandbox-exec").exists()
}

// ─── tests ───────────────────────────────────────────────────────────

/// Allowed IP-literal CONNECT: proxy dials the host interface listener,
/// the splice relays bytes, `sandbox.network_allowed` lands, and the
/// report shows the live stats and the layered egress table.
#[test]
fn proxy_allowed_connect_relays_and_audits() {
    if !sandbox_exec_available() {
        common::skip_e2e_test("sandbox-exec absent");
        return;
    }
    let Some(ip) = host_ip() else { return };
    if sys_python().is_none() {
        return;
    }
    let echo = Echo::bind(ip);
    let dir = workdir("allow");
    let policy = write_policy(
        &dir,
        &format!("        allow cidr=\"{ip}/32\"\n        deny host=\"*\"\n"),
    );
    let (run, audit, report) = proxy_run(
        &dir,
        &policy,
        &probe_argv(&format!("{ip}:{}", echo.port), &[]),
    );
    assert_eq!(run.code, 0, "stderr: {}", run.stderr);
    let out = run.stdout;
    assert!(out.contains("200"), "expected 200 CONNECT, got: {out}");
    assert!(
        out.contains("PING-BACK:PING"),
        "splice must relay the echo line, got: {out}"
    );
    let allowed = allowed_records(&audit);
    assert!(
        allowed
            .iter()
            .any(|l| l.contains(&format!("dest={ip}")) && l.contains("layer=ip")),
        "expected layer=ip allowed record for {ip}: {allowed:?}"
    );
    let body = report_body(&report);
    assert!(body.contains("\"component\":\"macos-proxy-run\""));
    assert!(body.contains("\"mechanism\":\"sbpl-loopback-connect-proxy\""));
    assert!(body.contains("\"state\":\"stopped\""));
    assert!(body.contains("\"accepted\":1"), "report stats: {body}");
    assert!(body.contains("\"layer\":\"ip\"") && body.contains("connect-proxy"));
}

/// Deny-by-CIDR: the proxy refuses with 403 and commits
/// `sandbox.network_denied` (layer=ip, decision=deny-cidr) before the
/// refusal reaches the workload.
#[test]
fn proxy_denied_cidr_audits_network_denied() {
    if !sandbox_exec_available() {
        common::skip_e2e_test("sandbox-exec absent");
        return;
    }
    let Some(ip) = host_ip() else { return };
    if sys_python().is_none() {
        return;
    }
    let echo = Echo::bind(ip);
    let dir = workdir("deny-cidr");
    let policy = write_policy(
        &dir,
        &format!("        deny cidr=\"{ip}/32\"\n        deny host=\"*\"\n"),
    );
    let (run, audit, report) = proxy_run(
        &dir,
        &policy,
        &probe_argv(&format!("{ip}:{}", echo.port), &[]),
    );
    assert_eq!(run.code, 0, "stderr: {}", run.stderr);
    assert!(
        run.stdout.contains("403"),
        "expected 403, got: {}",
        run.stdout
    );
    let denied = denied_records(&audit);
    assert!(
        denied.iter().any(|l| {
            l.contains("layer=ip")
                && l.contains(&format!("dest={ip}"))
                && l.contains("decision=deny-cidr")
                && l.contains(&format!("port={}", echo.port))
        }),
        "expected layer=ip deny-cidr record: {denied:?}"
    );
    assert!(
        report_body(&report).contains("\"denied_ip\":1"),
        "report should count the ip-layer denial"
    );
}

/// The SSRF guard: even with `allow cidr=127.0.0.0/8`, CONNECT to a
/// loopback address is refused — the proxy must never relay into host
/// services on the loopback interface.
#[test]
fn proxy_loopback_target_is_protected_denied() {
    if !sandbox_exec_available() {
        common::skip_e2e_test("sandbox-exec absent");
        return;
    }
    if sys_python().is_none() {
        return;
    }
    let echo = Echo::bind(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST));
    let dir = workdir("protected");
    let policy = write_policy(
        &dir,
        "        allow cidr=\"127.0.0.0/8\"\n        deny host=\"*\"\n",
    );
    let (run, audit, report) = proxy_run(
        &dir,
        &policy,
        &probe_argv(&format!("127.0.0.1:{}", echo.port), &[]),
    );
    assert_eq!(run.code, 0, "stderr: {}", run.stderr);
    assert!(
        run.stdout.contains("403"),
        "expected 403, got: {}",
        run.stdout
    );
    let denied = denied_records(&audit);
    assert!(
        denied
            .iter()
            .any(|l| l.contains("decision=protected-dest") && l.contains("dest=127.0.0.1")),
        "expected protected-dest denial: {denied:?}"
    );
    assert!(
        report_body(&report).contains("\"denied_protected\":1"),
        "report should count the protected-dest refusal"
    );
}

/// A denied CONNECT authority name is refused at the name layer —
/// `layer=name` with the matching deny rule — before any resolution
/// or dial is attempted.
#[test]
fn proxy_denied_name_audits_name_layer() {
    if !sandbox_exec_available() {
        common::skip_e2e_test("sandbox-exec absent");
        return;
    }
    if sys_python().is_none() {
        return;
    }
    let dir = workdir("deny-name");
    let policy = write_policy(
        &dir,
        "        deny host=\"example.com\"\n        deny host=\"*\"\n",
    );
    let (run, audit, report) = proxy_run(&dir, &policy, &probe_argv("example.com:443", &[]));
    assert_eq!(run.code, 0, "stderr: {}", run.stderr);
    assert!(
        run.stdout.contains("403"),
        "expected 403, got: {}",
        run.stdout
    );
    let denied = denied_records(&audit);
    assert!(
        denied.iter().any(|l| {
            l.contains("layer=name")
                && l.contains("name=example.com")
                && l.contains("decision=deny-host")
        }),
        "expected layer=name deny-host record: {denied:?}"
    );
    assert!(
        report_body(&report).contains("\"denied_name\":1"),
        "report should count the name-layer denial"
    );
}

/// A CONNECT without the per-launch credential gets 407 — a sibling
/// loopback client cannot piggyback the listener.
#[test]
fn proxy_missing_credential_gets_407() {
    if !sandbox_exec_available() {
        common::skip_e2e_test("sandbox-exec absent");
        return;
    }
    if sys_python().is_none() {
        return;
    }
    let dir = workdir("noauth");
    let policy = write_policy(&dir, "        deny host=\"*\"\n");
    let (run, _audit, _report) =
        proxy_run(&dir, &policy, &probe_argv("example.com:443", &["--noauth"]));
    assert_eq!(run.code, 0, "stderr: {}", run.stderr);
    assert!(
        run.stdout.contains("407"),
        "expected 407, got: {}",
        run.stdout
    );
}

/// The loopback pin is the bypass boundary: a workload-side direct
/// connect — to the host interface or to another loopback port — is
/// kernel-denied; only the proxy port is reachable.
#[test]
fn workload_direct_and_loopback_egress_is_kernel_denied() {
    if !sandbox_exec_available() {
        common::skip_e2e_test("sandbox-exec absent");
        return;
    }
    let Some(ip) = host_ip() else { return };
    let echo = Echo::bind(ip);
    let loop_echo = Echo::bind(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST));
    let dir = workdir("bypass");
    // allow_listen is off and no localhost rules exist — the ONLY
    // reachable TCP endpoint is the proxy itself.
    let policy = write_policy(&dir, "        deny host=\"*\"\n");
    let script = format!(
        "nc -z -G2 -w2 {ip} {ext} 2>/dev/null && echo EXT_REACHED || echo EXT_BLOCKED; \
         nc -z -G2 -w2 127.0.0.1 {lo} 2>/dev/null && echo LO_REACHED || echo LO_BLOCKED",
        ext = echo.port,
        lo = loop_echo.port,
    );
    let argv = vec!["/bin/sh".to_string(), "-c".to_string(), script];
    let (run, _audit, _report) = proxy_run(&dir, &policy, &argv);
    assert_eq!(run.code, 0, "stderr: {}", run.stderr);
    assert!(
        run.stdout.contains("EXT_BLOCKED"),
        "direct connect must be kernel-denied: {}",
        run.stdout
    );
    assert!(
        run.stdout.contains("LO_BLOCKED"),
        "loopback connect to a non-proxy port must be kernel-denied: {}",
        run.stdout
    );
    assert!(
        !run.stdout.contains("_REACHED"),
        "a bypass succeeded — the pin leaked: {}",
        run.stdout
    );
}

/// UDP has no CONNECT path — `sendto` inside the sandbox is denied,
/// and the in-sandbox resolver is unreachable (no mDNSResponder grant),
/// so `getaddrinfo` fails rather than leaking a query the policy never
/// judged. An in-sandbox `OSError` only proves the profile denied the
/// operation when the same operation would have succeeded unsandboxed —
/// controls run first (loopback UDP delivery, a sendto to the probe
/// destination, and resolving the probe name); a failed control skips
/// the test rather than reading a sandbox denial into a broken
/// environment.
#[test]
fn workload_udp_and_dns_are_denied() {
    if !sandbox_exec_available() {
        common::skip_e2e_test("sandbox-exec absent");
        return;
    }
    if sys_python().is_none() {
        return;
    }

    // Controls OUTSIDE the sandbox: UDP must actually deliver locally,
    // a sendto to the probe destination must not error (route exists),
    // and the probe name must resolve.
    let udp_local_ok = (|| {
        let listener = UdpSocket::bind(("127.0.0.1", 0)).ok()?;
        listener
            .set_read_timeout(Some(Duration::from_secs(2)))
            .ok()?;
        let sender = UdpSocket::bind(("127.0.0.1", 0)).ok()?;
        sender.send_to(b"x", listener.local_addr().ok()?).ok()?;
        let mut buf = [0u8; 8];
        listener.recv_from(&mut buf).ok().map(|(n, _)| n > 0)
    })()
    .unwrap_or(false);
    let udp_dest_ok = UdpSocket::bind(("0.0.0.0", 0))
        .and_then(|s| s.send_to(b"x", "192.0.2.1:53").map(|_| ()))
        .is_ok();
    let dns_ok = ("example.com", 443)
        .to_socket_addrs()
        .map(|mut it| it.next().is_some())
        .unwrap_or(false);
    if !(udp_local_ok && udp_dest_ok && dns_ok) {
        common::skip_e2e_test(&format!(
            "unsandboxed controls failed (udp_local={udp_local_ok}, \
             udp_dest={udp_dest_ok}, dns={dns_ok}) — an in-sandbox \
             OSError would not prove denial"
        ));
        return;
    }

    let dir = workdir("udp-dns");
    let policy = write_policy(&dir, "        deny host=\"*\"\n");
    let script = r#"
import socket
try:
    socket.socket(socket.AF_INET, socket.SOCK_DGRAM).sendto(b"x", ("192.0.2.1", 53))
    print("UDP_REACHED")
except OSError as e:
    print(f"UDP_BLOCKED:{e.errno}")
try:
    socket.getaddrinfo("example.com", 443)
    print("DNS_RESOLVED")
except OSError as e:
    print(f"DNS_BLOCKED:{e.errno}")
"#;
    let argv = vec![sys_python().unwrap(), "-c".to_string(), script.to_string()];
    let (run, _audit, _report) = proxy_run(&dir, &policy, &argv);
    assert_eq!(run.code, 0, "stderr: {}", run.stderr);
    assert!(
        run.stdout.contains("UDP_BLOCKED"),
        "UDP sendto must be denied: {}",
        run.stdout
    );
    assert!(
        run.stdout.contains("DNS_BLOCKED"),
        "in-sandbox getaddrinfo must fail: {}",
        run.stdout
    );
}

/// Pipelined bytes: a client that sends CONNECT + payload in one
/// flight still gets its early bytes relayed after the 200.
#[test]
fn proxy_relays_pipelined_bytes() {
    if !sandbox_exec_available() {
        common::skip_e2e_test("sandbox-exec absent");
        return;
    }
    let Some(ip) = host_ip() else { return };
    if sys_python().is_none() {
        return;
    }
    let echo = Echo::bind(ip);
    let dir = workdir("early");
    let policy = write_policy(
        &dir,
        &format!("        allow cidr=\"{ip}/32\"\n        deny host=\"*\"\n"),
    );
    let (run, _audit, _report) = proxy_run(
        &dir,
        &policy,
        &probe_argv(&format!("{ip}:{}", echo.port), &["--early"]),
    );
    assert_eq!(run.code, 0, "stderr: {}", run.stderr);
    assert!(
        run.stdout.contains("200"),
        "expected 200, got: {}",
        run.stdout
    );
    // The echoed line is either the pipelined EARLY or the PING —
    // either proves bytes after the head reached the peer. Assert
    // EARLY explicitly: the pipelined bytes themselves must have been
    // relayed, not just the later PING.
    assert!(
        run.stdout.contains("PING-BACK:"),
        "early bytes must relay: {}",
        run.stdout
    );
    assert!(
        run.stdout.contains("PING-BACK:EARLY"),
        "the pipelined EARLY payload must be echoed through the splice: {}",
        run.stdout
    );
}

/// An oversized request head (past the proxy's `MAX_HEAD_BYTES` cap)
/// is answered with `431` — refused, but diagnosed, not just a
/// silent close. The target never matters: the head is refused before
/// any policy evaluation.
#[test]
fn proxy_answers_oversized_head_with_431() {
    if !sandbox_exec_available() {
        common::skip_e2e_test("sandbox-exec absent");
        return;
    }
    if sys_python().is_none() {
        return;
    }
    let dir = workdir("bighead");
    let policy = write_policy(&dir, "        deny host=\"*\"\n");
    // --pad=9000 pushes the head past the 8192-byte cap; the probe's
    // printed status is the proxy's refusal.
    let (run, _audit, _report) = proxy_run(
        &dir,
        &policy,
        &probe_argv("example.com:443", &["--pad=9000"]),
    );
    assert_eq!(run.code, 0, "stderr: {}", run.stderr);
    assert!(
        run.stdout.contains("431"),
        "expected 431 for an oversized head, got: {}",
        run.stdout
    );
}

/// `--listen <port>` pins the CONNECT proxy to a chosen loopback port —
/// the report's `proxy.listen` records the requested endpoint, not a
/// kernel-assigned one.
#[test]
fn proxy_explicit_listen_port_is_reported() {
    if !sandbox_exec_available() {
        common::skip_e2e_test("sandbox-exec absent");
        return;
    }
    let Some(ip) = host_ip() else { return };
    if sys_python().is_none() {
        return;
    }
    // Reserve then release an ephemeral port — small TOCTOU window, and
    // a loss still fails visibly rather than asserting a wrong port.
    let port = TcpListener::bind(("127.0.0.1", 0))
        .expect("bind ephemeral")
        .local_addr()
        .unwrap()
        .port();
    let echo = Echo::bind(ip);
    let dir = workdir("listen");
    let policy = write_policy(
        &dir,
        &format!("        allow cidr=\"{ip}/32\"\n        deny host=\"*\"\n"),
    );
    let (run, _audit, report) = proxy_run_opts(
        &dir,
        &policy,
        &probe_argv(&format!("{ip}:{}", echo.port), &[]),
        &["--listen".to_string(), port.to_string()],
    );
    assert_eq!(run.code, 0, "stderr: {}", run.stderr);
    let body = report_body(&report);
    assert!(
        body.contains(&format!("\"listen\":\"127.0.0.1:{port}\"")),
        "report must record the explicit listen port: {body}"
    );
    assert!(
        body.contains("\"accepted\":1"),
        "the CONNECT must still succeed on the explicit port: {body}"
    );
}

/// An allowed name whose resolution fails is refused at the name layer
/// with `decision=resolve-error` and a 502 — the record marks a
/// resolver failure, not a policy verdict.
#[test]
fn proxy_unresolvable_name_audits_resolve_error() {
    if !sandbox_exec_available() {
        common::skip_e2e_test("sandbox-exec absent");
        return;
    }
    if sys_python().is_none() {
        return;
    }
    let dir = workdir("resolve");
    // `.invalid` is reserved (RFC 2606) — no resolver should answer it.
    let policy = write_policy(
        &dir,
        "        allow host=\"nonexistent.invalid\"\n        deny host=\"*\"\n",
    );
    let (run, audit, report) =
        proxy_run(&dir, &policy, &probe_argv("nonexistent.invalid:443", &[]));
    assert_eq!(run.code, 0, "stderr: {}", run.stderr);
    assert!(
        run.stdout.contains("502"),
        "expected 502, got: {}",
        run.stdout
    );
    let denied = denied_records(&audit);
    assert!(
        denied.iter().any(|l| {
            l.contains("layer=name")
                && l.contains("name=nonexistent.invalid")
                && l.contains("decision=resolve-error")
        }),
        "expected layer=name resolve-error record: {denied:?}"
    );
    assert!(
        report_body(&report).contains("\"resolve_failed\":1"),
        "report should count the resolution failure"
    );
}

/// A name the policy allows but whose resolved destinations all refuse
/// must leave NO `sandbox.network_allowed` record — the event means
/// "flow established", so recording it at the name-layer verdict would
/// mark refused flows as allowed (`localhost` resolves only to
/// protected loopbacks here).
#[test]
fn proxy_refused_name_flow_emits_no_allowed_record() {
    if !sandbox_exec_available() {
        common::skip_e2e_test("sandbox-exec absent");
        return;
    }
    if sys_python().is_none() {
        return;
    }
    let dir = workdir("refused-name");
    // `localhost` clears the name layer; every address it resolves to
    // is a protected loopback — refused at the IP layer.
    let policy = write_policy(
        &dir,
        "        allow host=\"localhost\"\n        deny host=\"*\"\n",
    );
    let (run, audit, report) = proxy_run(&dir, &policy, &probe_argv("localhost:443", &[]));
    assert_eq!(run.code, 0, "stderr: {}", run.stderr);
    assert!(
        run.stdout.contains("403"),
        "expected 403, got: {}",
        run.stdout
    );
    let denied = denied_records(&audit);
    assert!(
        denied.iter().any(|l| l.contains("decision=protected-dest")),
        "expected a protected-dest denial for the loopback answers: {denied:?}"
    );
    assert!(
        allowed_records(&audit).is_empty(),
        "a refused CONNECT must leave no sandbox.network_allowed record: {denied:?}"
    );
    let body = report_body(&report);
    assert!(
        body.contains("\"accepted\":0"),
        "the report must count no established flow: {body}"
    );
}

/// A WHATWG IPv4-number authority (`2130706433` = 127.0.0.1) is not a
/// dotted literal, so it enters the name layer — whose canonical form
/// is the folded address. The resolver must treat it as that literal,
/// never a name query, so the protected-destination guard refuses it
/// exactly like the `127.0.0.1` spelling.
#[test]
fn proxy_whatwg_number_target_is_judged_as_its_ip() {
    if !sandbox_exec_available() {
        common::skip_e2e_test("sandbox-exec absent");
        return;
    }
    if sys_python().is_none() {
        return;
    }
    let echo = Echo::bind(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST));
    let dir = workdir("whatwg");
    let policy = write_policy(&dir, "        allow host=\"*\"\n");
    let (run, audit, report) = proxy_run(
        &dir,
        &policy,
        &probe_argv(&format!("2130706433:{}", echo.port), &[]),
    );
    assert_eq!(run.code, 0, "stderr: {}", run.stderr);
    assert!(
        run.stdout.contains("403"),
        "expected 403, got: {}",
        run.stdout
    );
    let denied = denied_records(&audit);
    assert!(
        denied
            .iter()
            .any(|l| { l.contains("decision=protected-dest") && l.contains("dest=127.0.0.1") }),
        "expected a protected-dest denial for 127.0.0.1: {denied:?}"
    );
    let body = report_body(&report);
    assert!(
        body.contains("\"denied_protected\":1"),
        "exactly one folded literal must hit the guard: {body}"
    );
}

/// SIGTERM to the supervisor is forwarded to the sandboxed workload's
/// process group — the workload observes the signal, the run exits 143,
/// and the report records the forward.
#[test]
fn proxy_sigterm_reaches_the_sandboxed_workload() {
    if !sandbox_exec_available() {
        common::skip_e2e_test("sandbox-exec absent");
        return;
    }
    let dir = workdir("signal");
    let policy = write_policy(&dir, "        deny host=\"*\"\n");
    let audit = dir.join("audit.jsonl");
    let report = dir.join("report.json");
    // A single-process compiled workload is the forwarding oracle: its
    // SIGTERM handler writes GOT_TERM from whichever thread the kernel
    // interrupts — deterministic. A `sh` trap is NOT dependable here:
    // when the group-wide TERM kills the child `sh` is `wait`ing on,
    // sh's `wait` can complete normally (child reaped first) while its
    // pending trap is dropped at EOF or deferred indefinitely —
    // observed under parallel load as `sh` exiting 0 without echoing,
    // or surviving past the supervisor's 5s grace until SIGKILL. Python
    // is reserved for the connect-probe MCP fixture only. READY proves
    // the handler is installed before we signal.
    let Some(probe) = compiled_sigterm_probe() else {
        return;
    };
    let argv = vec![probe.to_string_lossy().into_owned()];
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_mcp-writ"));
    cmd.args(["macos-proxy-run", "--policy"])
        .arg(&policy)
        .args(["--server", "probe"])
        .args(["--audit-log"])
        .arg(&audit)
        .args(["--report"])
        .arg(&report)
        .arg("--")
        .args(&argv)
        .current_dir(&dir)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cmd.spawn().expect("spawn mcp-writ");
    let out_buf = std::sync::Arc::new(std::sync::Mutex::new(String::new()));
    let stdout_thr = {
        let mut pipe = child.stdout.take().unwrap();
        let buf = out_buf.clone();
        std::thread::spawn(move || {
            let mut chunk = [0u8; 8192];
            loop {
                match std::io::Read::read(&mut pipe, &mut chunk) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => buf
                        .lock()
                        .unwrap()
                        .push_str(&String::from_utf8_lossy(&chunk[..n])),
                }
            }
        })
    };
    let stderr_thr = {
        let mut pipe = child.stderr.take().unwrap();
        std::thread::spawn(move || {
            let mut s = String::new();
            std::io::Read::read_to_string(&mut pipe, &mut s).ok();
            s
        })
    };
    // READY proves the sandboxed workload installed its handler —
    // signal only after that or TERM could land before it exists.
    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    while !out_buf.lock().unwrap().contains("READY") {
        if std::time::Instant::now() >= deadline || child.try_wait().unwrap().is_some() {
            let _ = child.kill();
            let _ = child.wait();
            panic!("workload never became READY: {}", out_buf.lock().unwrap());
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let sig = Command::new("kill")
        .args(["-TERM", &child.id().to_string()])
        .status()
        .expect("kill binary");
    assert!(sig.success(), "kill -TERM failed");
    let start = std::time::Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait().expect("try_wait") {
            break status;
        }
        if start.elapsed() >= TEST_TIMEOUT {
            let _ = child.kill();
            let _ = child.wait();
            panic!("supervisor did not exit after SIGTERM");
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    let _ = stdout_thr.join();
    let stdout = out_buf.lock().unwrap().clone();
    let stderr = stderr_thr.join().unwrap_or_default();
    assert_eq!(
        status.code().unwrap_or(-1),
        143,
        "supervisor must exit 143 after forwarding TERM: {stderr}"
    );
    assert!(
        stdout.contains("GOT_TERM"),
        "the forwarded TERM must reach the sandboxed workload: {stdout}"
    );
    let body = report_body(&report);
    assert!(
        body.contains("\"state\":\"stopped\"") && body.contains("signal 15 forwarded"),
        "report must record the forwarded signal: {body}"
    );
}

/// The native `run` path is untouched by the opt-in: same policy, same
/// plan semantics — `run --dry-run` still builds and reports the
/// sandbox-exec mechanism without the proxy in sight.
#[test]
fn native_run_path_unaffected_by_proxy_opt_in() {
    if !sandbox_exec_available() {
        common::skip_e2e_test("sandbox-exec absent");
        return;
    }
    let dir = workdir("native");
    let policy = write_policy(&dir, "        deny host=\"*\"\n");
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_mcp-writ"));
    cmd.args(["run", "--policy"])
        .arg(&policy)
        .args(["--server", "probe"])
        .args(["--dry-run"])
        .args(["--audit-log"])
        .arg(dir.join("native-audit.jsonl"))
        .arg("--")
        .arg("/usr/bin/true")
        .current_dir(&dir)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let run = run_with_timeout(&mut cmd);
    assert_eq!(
        run.code, 0,
        "native run --dry-run must still work: {}",
        run.stderr
    );
    // The native mechanism vocabulary — the proxy pin must not leak
    // into the default plan.
    let combined = format!("{}{}", run.stdout, run.stderr);
    assert!(
        !combined.contains("connect_proxy"),
        "native path must not emit the proxy pin: {combined}"
    );
}
