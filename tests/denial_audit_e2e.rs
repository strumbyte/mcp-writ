//! Denial-audit scenario regression (improvement plan PR-08, §1.6/§5.4).
//!
//! The v0.3 audit-completeness claim is end-to-end: a *denied* operation
//! must be visible in the JSONL audit stream, and the paths where a
//! denial cannot be observed must be pinned as a specification — never
//! read as proof nothing was denied.
//!
//! - **Scenario A** (injection → RPC-layer denial → JSONL): a denied
//!   `tools/call` emits `tool_call.denied`, a denied non-tool request
//!   emits `mcp_message.denied`, and the client receives the refusal.
//! - **Scenario B** (direct `:443` IP egress): the `unotify-run` IP
//!   layer (PR-07) refuses the `connect(2)` and emits
//!   `sandbox.network_denied` with `layer=ip`.
//! - **Name layer**: the real `dns-gate` binary (PR-06) refuses an
//!   unlisted name (REFUSED by default, NXDOMAIN under
//!   `--refuse-rcode nxdomain`) and emits `sandbox.network_denied` with
//!   `layer=name`.
//! - **Kernel-internal denials** (Landlock + policy seccomp under a
//!   plain `run`): the workload observes EACCES/EPERM, the audit log
//!   records the launch lifecycle, and no `sandbox.*_denied` record is
//!   emitted — kernel-internal denials have no userspace observation
//!   path, so their absence is the specification under test.
//!
//! Skips route through `common::skip_e2e_test` so a mandatory run
//! (`MCP_WRIT_REQUIRE_E2E_TESTS=1`) fails rather than passing
//! unexecuted.

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, Instant};

mod common;

#[cfg(target_os = "linux")]
const TEST_TIMEOUT: Duration = Duration::from_secs(30);

// ─── shared helpers ──────────────────────────────────────────────────

/// A workspace-private temp dir that survives a failed run for
/// inspection (next run truncates it) — same convention as
/// `unotify_e2e`. Rooted at the real temp spelling: `$TMPDIR`
/// traverses a platform link on macOS (`/var` → `/private/var`) that
/// the spawned binary's strict `O_NOFOLLOW` ancestor walk refuses.
fn workdir(tag: &str) -> PathBuf {
    let dir = common::real_temp_base().join(format!(
        "mcp-writ-denial-audit-e2e-{}-{}",
        std::process::id(),
        tag
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// Compile a `tests/fixtures/…` rustc fixture once per test binary —
/// parallel tests must not compile to the same output path
/// concurrently, so each name builds under one mutex.
#[cfg(target_os = "linux")]
fn compile_fixture(src_rel: &str, name: &'static str) -> PathBuf {
    use std::collections::HashMap;
    use std::sync::{Mutex, OnceLock};
    static BINS: OnceLock<Mutex<HashMap<&'static str, PathBuf>>> = OnceLock::new();
    let mut bins = BINS
        .get_or_init(|| Mutex::new(HashMap::new()))
        .lock()
        .unwrap();
    if let Some(bin) = bins.get(name) {
        return bin.clone();
    }
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("target/denial-audit-e2e");
    std::fs::create_dir_all(&dir).unwrap();
    let bin = dir.join(name);
    let src = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(src_rel);
    let need = !bin.exists()
        || std::fs::metadata(&src).unwrap().modified().unwrap()
            > std::fs::metadata(&bin).unwrap().modified().unwrap();
    if need {
        let status = std::process::Command::new("rustc")
            .args(["-O", "-o"])
            .arg(&bin)
            .arg(&src)
            .status()
            .expect("rustc must exist — cargo test ran under a toolchain");
        assert!(status.success(), "fixture compile failed for {src_rel}");
    }
    bins.insert(name, bin.clone());
    bin
}

#[cfg(target_os = "linux")]
struct Run {
    code: i32,
    stdout: String,
    stderr: String,
}

/// Run a `mcp-writ` invocation with a hard timeout — a wedged child
/// must surface as a failure, not a hang. Stdout/stderr drain on
/// threads so a full pipe cannot block the child.
#[cfg(target_os = "linux")]
fn run_with_timeout(cmd: &mut std::process::Command) -> Run {
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
    let start = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait().expect("try_wait") {
            break status;
        }
        if start.elapsed() >= TEST_TIMEOUT {
            let _ = child.kill();
            let _ = child.wait();
            let _ = stdout_thr.join();
            let _ = stderr_thr.join();
            panic!("mcp-writ invocation exceeded {TEST_TIMEOUT:?}");
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    Run {
        code: status.code().unwrap_or(-1),
        stdout: stdout_thr.join().unwrap_or_default(),
        stderr: stderr_thr.join().unwrap_or_default(),
    }
}

fn read_audit(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap_or_default()
}

/// Every audit record whose parsed `event_type` equals `event_type`.
/// Matching is parse-based rather than a `"event_type":"..."` substring
/// — a serialization layout change would silently match nothing under
/// the substring shape, turning an absence assertion into a vacuous
/// pass. Unparseable lines fail the leg via `audit_json`.
fn audit_lines<'a>(audit: &'a str, event_type: &str) -> Vec<&'a str> {
    audit
        .lines()
        .filter(|l| !l.trim().is_empty())
        .filter(|l| audit_event_type(l).as_deref() == Some(event_type))
        .collect()
}

/// Parse one audit line — every non-empty JSONL line is a JSON event,
/// and a line that will not parse must fail the leg rather than slip an
/// event past a substring filter.
fn audit_json(line: &str) -> nojson::RawJson<'static> {
    nojson::RawJson::parse(Box::leak(line.trim().to_string().into_boxed_str()))
        .unwrap_or_else(|e| panic!("audit line must parse as JSON: {e}\n{line}"))
}

/// The parsed `event_type` member — a whitespace-sensitive substring
/// match would silently match nothing under a different serialization
/// layout, turning an absence assertion into a vacuous pass.
fn audit_event_type(line: &str) -> Option<String> {
    audit_json(line)
        .value()
        .to_member("event_type")
        .ok()?
        .optional()?
        .to_unquoted_string_str()
        .ok()
        .map(|s| s.into_owned())
}

// ─── Scenario A: injection → RPC-layer denial → JSONL ────────────────
//
// `run` over a scripted fixture server (OS sandbox bypassed — the RPC
// layer is what this scenario measures; `MCP_WRIT_SKIP_SANDBOX` runs
// never count as OS-enforcement evidence). A policy-listed call answers
// normally (positive control); a call naming a tool the policy never
// heard of is refused with `tool_call.denied`; a request for a method
// with no `mcp` rule is refused with `mcp_message.denied` (`no-rule`).

/// Tools the fixture advertises under `tools_call_ok`; the policy
/// allows all three plus `write_file`, so tools/list filtering never
/// rewrites the verified result. No `mcp` block: every non-tool method
/// decides `no-rule`.
const SCENARIO_A_POLICY: &str = r#"
policy version=1
logging level="info" fail_closed=#false
server "wire" {
    tool "read_file"
    tool "write_file"
    tool "fail_write"
    tool "fetch_url"
}
"#;

#[tokio::test]
async fn scenario_a_denied_rpc_requests_are_audited() {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::time::timeout;

    // The workload is the Python scripted fixture — resolve the
    // interpreter first so a host without it records a skip, not a
    // launch failure misread as a denial.
    let interpreter = if cfg!(windows) { "py" } else { "python3" };
    if mcp_writ::workload::resolve_command_path(interpreter).is_err() {
        common::skip_e2e_test(&format!("{interpreter} not on PATH"));
        return;
    }

    let dir = workdir("scenario-a");
    let policy = dir.join("policy.kdl");
    std::fs::write(&policy, SCENARIO_A_POLICY).unwrap();
    let audit = dir.join("audit.jsonl");

    let mut child = tokio::process::Command::new(env!("CARGO_BIN_EXE_mcp-writ"))
        .args([
            "run",
            "--transport",
            "stdio",
            "--policy",
            policy.to_str().expect("policy path utf-8"),
            "--audit-log",
            audit.to_str().expect("audit path utf-8"),
            "--",
        ])
        .args(common::scripted_stdio_argv("tools_call_ok"))
        .env("MCP_WRIT_SKIP_SANDBOX", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn mcp-writ binary");
    let mut stdin = child.stdin.take().expect("stdin");
    let stdout = child.stdout.take().expect("stdout");
    let mut reader = BufReader::new(stdout).lines();

    async fn exchange(
        stdin: &mut tokio::process::ChildStdin,
        reader: &mut tokio::io::Lines<BufReader<tokio::process::ChildStdout>>,
        request: &str,
    ) -> String {
        stdin
            .write_all(format!("{request}\n").as_bytes())
            .await
            .expect("write request");
        stdin.flush().await.expect("flush request");
        timeout(Duration::from_secs(15), async {
            loop {
                let line = reader
                    .next_line()
                    .await
                    .expect("IO error reading mcp-writ stdout")
                    .expect("unexpected EOF on mcp-writ stdout");
                if line.starts_with("{\"jsonrpc\"") {
                    return line;
                }
            }
        })
        .await
        .expect("timeout waiting for JSON-RPC frame")
    }

    // 2025-11-25 handshake.
    let init = exchange(&mut stdin, &mut reader, common::INIT_REQUEST).await;
    assert!(
        init.contains("\"protocolVersion\":\"2025-11-25\""),
        "initialize must complete: {init}"
    );
    stdin
        .write_all(format!("{}\n", common::INITIALIZED_NOTIF).as_bytes())
        .await
        .expect("write initialized");
    stdin.flush().await.expect("flush initialized");

    // Publish the verified listing — the generation gate denies
    // `tools/call` until a client `tools/list` has completed.
    let list = exchange(
        &mut stdin,
        &mut reader,
        r#"{"jsonrpc":"2.0","id":9,"method":"tools/list","params":{}}"#,
    )
    .await;
    assert!(
        list.contains("\"result\""),
        "tools/list must verify and emit: {list}"
    );

    // Positive control: a policy-listed call forwards and answers.
    let ok = exchange(
        &mut stdin,
        &mut reader,
        r#"{"jsonrpc":"2.0","id":10,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/workspace/notes.txt"}}}"#,
    )
    .await;
    assert!(
        ok.contains("\"id\":10") && ok.contains("\"result\""),
        "allowed call must return a result: {ok}"
    );

    // Injection leg 1 — a call naming a tool the policy never heard of.
    let denied_tool = exchange(
        &mut stdin,
        &mut reader,
        r#"{"jsonrpc":"2.0","id":11,"method":"tools/call","params":{"name":"exec_shell","arguments":{"command":"id"}}}"#,
    )
    .await;
    assert!(
        denied_tool.contains("\"id\":11") && denied_tool.contains("\"error\""),
        "denied call must surface an error with the request id: {denied_tool}"
    );
    assert!(
        denied_tool.contains("exec_shell"),
        "the error must name the refused tool: {denied_tool}"
    );

    // Injection leg 2 — a request for a method with no `mcp` rule.
    let denied_method = exchange(
        &mut stdin,
        &mut reader,
        r#"{"jsonrpc":"2.0","id":12,"method":"resources/read","params":{"uri":"file:///etc/passwd"}}"#,
    )
    .await;
    assert!(
        denied_method.contains("\"id\":12") && denied_method.contains("\"error\""),
        "no-rule request must surface an error with the request id: {denied_method}"
    );
    assert!(
        denied_method.contains("no-rule"),
        "expected the no-rule reason on the wire: {denied_method}"
    );

    drop(stdin);
    let status = timeout(Duration::from_secs(15), child.wait())
        .await
        .expect("guard did not exit after stdin EOF")
        .expect("guard wait failed");
    assert!(
        status.success(),
        "a session containing denials must still exit cleanly: {status}"
    );

    let body = read_audit(&audit);

    // The allowed control call is auditable too — allow and deny share
    // one record surface, so a denial cannot hide among silence.
    assert!(
        audit_lines(&body, "tool_call.allowed")
            .iter()
            .any(|l| l.contains("\"target_tool\":\"read_file\"")),
        "the allowed control call must be audited: {body}"
    );

    // Leg 1: the injected tool call is a high-severity denial tied to
    // its request id and the refused tool.
    let tool_denied = audit_lines(&body, "tool_call.denied");
    assert!(
        tool_denied.iter().any(|l| {
            l.contains("\"target_tool\":\"exec_shell\"")
                && l.contains("\"request_id\":\"11\"")
                && l.contains("\"severity\":\"high\"")
                && l.contains("\"outcome\":\"failure\"")
                && l.contains("\"action\":\"denied\"")
                && l.contains("not found in policy")
        }),
        "tool_call.denied must name exec_shell, request 11, action=denied: {tool_denied:?}"
    );

    // Leg 2: the unruled method is an `mcp_message.denied` with the
    // stable no-rule reason — the wire-layer refusal record.
    let msg_denied = audit_lines(&body, "mcp_message.denied");
    assert!(
        msg_denied.iter().any(|l| {
            l.contains("\"target_tool\":\"resources/read\"")
                && l.contains("\"request_id\":\"12\"")
                && l.contains("\"action\":\"denied\"")
                && l.contains("reason=no-rule")
                && l.contains("forwarded=false")
        }),
        "mcp_message.denied must record the no-rule resources/read denial: {msg_denied:?}"
    );

    // The denial records live inside a normal session bracket — a burst
    // of refused traffic does not break the lifecycle contract.
    for ty in [
        "guard.started",
        "policy.loaded",
        "server.connected",
        "server.disconnected",
        "session.ended",
        "guard.stopped",
    ] {
        assert!(
            !audit_lines(&body, ty).is_empty(),
            "lifecycle record {ty} missing: {body}"
        );
    }
}

// ─── Scenario B: direct :443 egress refused at the IP layer ─────────
//
// The `unotify-run` PoC (PR-07) supervises `connect(2)` under seccomp
// user notification; the workload is the same `connect_probe` fixture
// that suite compiles. A connect straight to a literal IP on port 443 —
// the DNS-bypass egress the name layer cannot see — must be refused by
// the IP layer and recorded as `sandbox.network_denied` (`layer=ip`).

/// Deny-all posture plus an explicit `deny cidr` covering the probe
/// destination: `192.0.2.0/24` is TEST-NET-1 documentation space, so
/// the attempt is never a real escape even where the supervisor is not
/// enforcing. `socket`/`connect` must be syscall-allowed — an ERRNO
/// verdict from the policy filter wins over USER_NOTIF and the
/// notification would never fire.
#[cfg(target_os = "linux")]
fn scenario_b_policy(dir: &Path) -> PathBuf {
    // The fixture syscall baseline is shared with the Landlock-era
    // suites (`common::FIXTURE_SYSCALLS_KDL` — proven for rustc-built
    // fixtures); `socket`/`connect`/`setsockopt`/`getsockopt` are the
    // networking calls `connect_probe` exercises.
    let baseline = common::FIXTURE_SYSCALLS_KDL
        .trim_end()
        .strip_suffix('}')
        .expect("fixture syscall block ends with }");
    let policy = dir.join("policy.kdl");
    std::fs::write(
        &policy,
        format!(
            r#"policy version=1

defaults {{
    filesystem {{
        allow "/" mode="read"
    }}
{baseline}        allow "socket" "connect" "setsockopt" "getsockopt"
    }}
    network {{
        deny cidr="192.0.2.0/24"
        deny host="*"
    }}
    logging {{
        fail_closed #false
    }}
}}

server "probe" {{
    // Declares the 'probe' server identity so `--server probe` binds —
    // an empty named block registers nothing, and the workload is not
    // an MCP server so no tool is ever invoked.
    tool "probe"
}}
"#
        ),
    )
    .unwrap();
    policy
}

#[cfg(target_os = "linux")]
#[test]
fn scenario_b_direct_443_egress_denied_and_audited() {
    if let Err(e) = mcp_writ::warden::unotify::check_support() {
        common::skip_e2e_test(&format!("kernel lacks unotify support: {e}"));
        return;
    }
    let dir = workdir("scenario-b");
    let policy = scenario_b_policy(&dir);
    let audit = dir.join("audit.jsonl");
    let audit_arg = audit.display().to_string();
    let probe = compile_fixture("tests/fixtures/unotify/connect_probe.rs", "connect_probe");

    let mut cmd = std::process::Command::new(env!("CARGO_BIN_EXE_mcp-writ"));
    cmd.args(["unotify-run", "--policy"])
        .arg(&policy)
        .args(["--server", "probe"])
        .args(["--audit-log", audit_arg.as_str()])
        .arg("--")
        .arg(&probe)
        .arg("192.0.2.1:443")
        .current_dir(&dir)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let run = run_with_timeout(&mut cmd);

    // Exit 10 = the workload received EACCES — the supervisor denied the
    // destination before the kernel ever ran the connect.
    assert_eq!(run.code, 10, "stderr: {}", run.stderr);
    assert!(
        run.stdout.contains("errno=13"),
        "expected EACCES at the workload, got: {}",
        run.stdout
    );
    let body = read_audit(&audit);
    let denied = audit_lines(&body, "sandbox.network_denied");
    assert!(
        denied.iter().any(|l| {
            l.contains("layer=ip")
                && l.contains("dest=192.0.2.1")
                && l.contains("port=443")
                && l.contains("decision=deny-cidr")
        }),
        "scenario B must leave a layer=ip denial for 192.0.2.1:443; got {denied:?}"
    );
    assert!(
        denied.iter().all(|l| l.contains(r#""action":"denied""#)),
        "denial records must use action=denied: {denied:?}"
    );
}

// ─── Name layer: real `dns-gate` binary refusal → JSONL ─────────────
//
// The in-process `dns_gate_e2e` suite covers wire semantics; this leg
// drives the shipped `dns-gate` subcommand end to end — policy load →
// gate serve → real UDP answers → audit file — so the *command's* denial
// path is the one under test.

fn dns_name_wire(name: &str) -> Vec<u8> {
    let mut out = Vec::new();
    for label in name.split('.').filter(|l| !l.is_empty()) {
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    out
}

fn dns_query(id: u16, name: &str, qtype: u16) -> Vec<u8> {
    let mut pkt = Vec::new();
    pkt.extend_from_slice(&id.to_be_bytes());
    pkt.extend_from_slice(&0x0100u16.to_be_bytes()); // RD
    pkt.extend_from_slice(&1u16.to_be_bytes()); // qd
    pkt.extend_from_slice(&0u16.to_be_bytes()); // an
    pkt.extend_from_slice(&0u16.to_be_bytes()); // ns
    pkt.extend_from_slice(&0u16.to_be_bytes()); // ar
    pkt.extend_from_slice(&dns_name_wire(name));
    pkt.extend_from_slice(&qtype.to_be_bytes());
    pkt.extend_from_slice(&1u16.to_be_bytes()); // IN
    pkt
}

fn dns_rcode(resp: &[u8]) -> u8 {
    resp[3] & 0x0F
}

/// A mock upstream resolver: answers every forwarded query with a fixed
/// A record. Runs on a thread — a blocked `recv_from` simply dies with
/// the test process.
fn spawn_mock_upstream() -> std::net::SocketAddr {
    let sock = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind mock upstream");
    let addr = sock.local_addr().unwrap();
    std::thread::spawn(move || {
        let mut buf = [0u8; 4096];
        while let Ok((n, peer)) = sock.recv_from(&mut buf) {
            let req = &buf[..n];
            if n < 12 {
                continue;
            }
            // Echo the question section: walk labels to the terminator,
            // then qtype+qclass. A malformed name leaves `qend` short —
            // the answer still echoes what was received.
            let qend = {
                let mut pos = 12;
                loop {
                    match buf.get(pos) {
                        Some(0) => break pos + 5,
                        Some(&len) if len & 0xC0 == 0 => pos += 1 + len as usize,
                        _ => break pos,
                    }
                }
            };
            let mut resp = req[..qend.min(n)].to_vec();
            // flags: QR + RD (echo) + RA — rcode NOERROR; ancount 1.
            if resp.len() >= 8 {
                resp[2] = 0x81;
                resp[3] = 0x80;
                resp[6] = 0;
                resp[7] = 1;
            }
            // Answer RR: name = pointer to qname (0xC00C), A/IN, ttl 60.
            resp.extend_from_slice(&[0xC0, 0x0C]);
            resp.extend_from_slice(&1u16.to_be_bytes());
            resp.extend_from_slice(&1u16.to_be_bytes());
            resp.extend_from_slice(&60u32.to_be_bytes());
            resp.extend_from_slice(&4u16.to_be_bytes());
            resp.extend_from_slice(&[1, 2, 3, 4]);
            let _ = sock.send_to(&resp, peer);
        }
    });
    addr
}

/// One UDP query with id matching — a connected socket so a recycled
/// datagram cannot be mistaken for the answer.
fn udp_query(listen: std::net::SocketAddr, pkt: &[u8]) -> Option<Vec<u8>> {
    let sock = std::net::UdpSocket::bind("127.0.0.1:0").ok()?;
    sock.set_read_timeout(Some(Duration::from_secs(1))).ok()?;
    sock.connect(listen).ok()?;
    sock.send(pkt).ok()?;
    let want_id = u16::from_be_bytes([pkt[0], pkt[1]]);
    let deadline = Instant::now() + Duration::from_secs(4);
    let mut buf = [0u8; 4096];
    loop {
        match sock.recv(&mut buf) {
            Ok(n) if n >= 2 && u16::from_be_bytes([buf[0], buf[1]]) == want_id => {
                return Some(buf[..n].to_vec());
            }
            _ => {}
        }
        if Instant::now() >= deadline {
            return None;
        }
    }
}

/// Spawn the real `dns-gate` command and wait until its UDP listener
/// answers (a header-only packet earns a FORMERR — any response proves
/// the socket is serving). The returned stderr receiver carries the
/// gate's diagnostics for a failure message.
fn spawn_dns_gate(
    dir: &Path,
    policy: &Path,
    upstream: std::net::SocketAddr,
    refuse_rcode: Option<&str>,
) -> (
    std::process::Child,
    std::net::SocketAddr,
    PathBuf,
    std::sync::mpsc::Receiver<String>,
) {
    let audit = dir.join("audit.jsonl");
    // Ephemeral probe for the listen port — the same release-then-bind
    // race the in-process suite accepts; a lost race surfaces as the
    // readiness deadline expiring below.
    let probe = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let listen = probe.local_addr().unwrap();
    drop(probe);

    let mut cmd = std::process::Command::new(env!("CARGO_BIN_EXE_mcp-writ"));
    cmd.args(["dns-gate", "--policy"])
        .arg(policy)
        .args(["--upstream", &upstream.to_string()])
        .args(["--listen", &listen.to_string()])
        .args(["--audit-log", audit.to_str().expect("audit path utf-8")])
        .arg("--audit-sync");
    if let Some(rc) = refuse_rcode {
        cmd.args(["--refuse-rcode", rc]);
    }
    let mut child = cmd
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn mcp-writ dns-gate");
    // Drain both pipes on threads — a full pipe would wedge the gate.
    fn drain(mut pipe: impl std::io::Read + Send + 'static) -> std::sync::mpsc::Receiver<String> {
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let mut s = String::new();
            std::io::Read::read_to_string(&mut pipe, &mut s).ok();
            let _ = tx.send(s);
        });
        rx
    }
    let _stdout_rx = drain(child.stdout.take().unwrap());
    let stderr_rx = drain(child.stderr.take().unwrap());

    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(status) = child.try_wait().expect("try_wait") {
            let stderr = stderr_rx
                .recv_timeout(Duration::from_secs(2))
                .unwrap_or_default();
            panic!("dns-gate exited before serving ({status}): {stderr}");
        }
        // Readiness probe: the gate answers even a header-only packet.
        let mut pkt = Vec::new();
        pkt.extend_from_slice(&0xEEu16.to_be_bytes());
        pkt.extend_from_slice(&0x0100u16.to_be_bytes());
        pkt.extend_from_slice(&[0u8; 8]);
        if let Some(resp) = udp_query(listen, &pkt)
            && resp.len() >= 4
        {
            return (child, listen, audit, stderr_rx);
        }
        assert!(
            Instant::now() < deadline,
            "dns-gate did not answer within 10s"
        );
    }
}

fn dns_gate_policy(dir: &Path) -> PathBuf {
    let policy = dir.join("policy.kdl");
    std::fs::write(
        &policy,
        r#"policy version=1
defaults {
    network {
        allow host="allowed.example"
        deny host="blocked.example"
        deny host="*"
    }
    logging {
        fail_closed #false
    }
}

server "probe" {
    // No tools or grants: dns-gate evaluates `defaults.network` only,
    // so no server identity is required. The empty named block keeps
    // the policy shape parallel with the unotify-run legs — and proves
    // an empty block still loads and binds cleanly.
}
"#,
    )
    .unwrap();
    policy
}

fn dns_gate_denial_leg(refuse_rcode: Option<&str>, want_rcode: u8, rcode_name: &str) {
    let dir = workdir(&format!("dns-gate-{rcode_name}"));
    let policy = dns_gate_policy(&dir);
    let upstream = spawn_mock_upstream();
    let (mut gate, listen, audit, _stderr_rx) =
        spawn_dns_gate(&dir, &policy, upstream, refuse_rcode);

    // Denied names refuse before any upstream contact — two denial
    // classes: an explicit `deny host=` rule, and the deny-all-others
    // posture for an unlisted name.
    let denied_explicit = udp_query(listen, &dns_query(0xA001, "blocked.example", 1))
        .expect("denied query must be answered");
    assert_eq!(
        dns_rcode(&denied_explicit),
        want_rcode,
        "explicit deny must answer {rcode_name}"
    );
    let denied_default = udp_query(listen, &dns_query(0xA002, "denied.example", 1))
        .expect("unlisted-name query must be answered");
    assert_eq!(
        dns_rcode(&denied_default),
        want_rcode,
        "deny-all-others must answer {rcode_name}"
    );

    // The allowed name resolves through the mock upstream — proof the
    // gate really forwarded, so a refusal is policy, not a dead gate.
    let resolved = udp_query(listen, &dns_query(0xA003, "allowed.example", 1))
        .expect("allowed query must be answered");
    assert_eq!(dns_rcode(&resolved), 0, "allowed name must resolve");

    // The resolved record is a *buffered* emit (unlike the committed
    // denials): --audit-sync makes it durable once the writer dequeues
    // it, but the emit→dequeue hop races the kill below. Wait for the
    // record to land before stopping the gate — the assertion is about
    // the record existing, not about a lucky drain order.
    let resolve_deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let body = read_audit(&audit);
        if audit_lines(&body, "sandbox.network_resolved")
            .iter()
            .any(|l| l.contains("name=allowed.example"))
        {
            break;
        }
        assert!(
            Instant::now() < resolve_deadline,
            "sandbox.network_resolved for allowed.example did not reach the audit log: {body}"
        );
        std::thread::sleep(Duration::from_millis(25));
    }

    // --audit-sync makes every emitted record durable before the kill;
    // the denied record is additionally log_committed — durable before
    // the answer ever went out.
    let _ = gate.kill();
    let _ = gate.wait();

    let body = read_audit(&audit);
    let denied = audit_lines(&body, "sandbox.network_denied");
    assert!(
        denied.iter().any(|l| {
            l.contains("layer=name")
                && l.contains("name=blocked.example")
                && l.contains("decision=deny-host")
                && l.contains("rule=")
                && l.contains(&format!("rcode={rcode_name}"))
        }),
        "explicit deny must audit deny-host with the matched rule: {denied:?}"
    );
    assert!(
        denied.iter().any(|l| {
            l.contains("layer=name")
                && l.contains("name=denied.example")
                && l.contains("decision=not-allowed")
                && l.contains(&format!("rcode={rcode_name}"))
        }),
        "unlisted name must audit not-allowed: {denied:?}"
    );
    assert!(
        denied.iter().all(|l| {
            l.contains("\"severity\":\"high\"")
                && l.contains("\"outcome\":\"failure\"")
                && l.contains("\"action\":\"denied\"")
        }),
        "name-layer denials must be high/failure/denied: {denied:?}"
    );

    let resolved = audit_lines(&body, "sandbox.network_resolved");
    assert!(
        resolved
            .iter()
            .any(|l| l.contains("layer=name") && l.contains("name=allowed.example")),
        "the allowed query must be audited as resolved: {resolved:?}"
    );
    for ty in ["guard.started", "policy.loaded"] {
        assert!(
            !audit_lines(&body, ty).is_empty(),
            "lifecycle record {ty} missing: {body}"
        );
    }
}

#[test]
fn dns_gate_denied_names_are_refused_and_audited() {
    // REFUSED is the default refusal; NXDOMAIN is the alternate shape —
    // both must carry the denial into the audit trail.
    dns_gate_denial_leg(None, 5, "refused");
    dns_gate_denial_leg(Some("nxdomain"), 3, "nxdomain");
}

// ─── Kernel-internal denials: unobservable by specification ─────────
//
// Under a plain `run` the Landlock + seccomp layer denies in-kernel and
// produces no userspace notification — there is no observation path, so
// no `sandbox.*_denied` record may be emitted. This test pins that
// contract: the workload *provably* hits the denial (the stderr errno
// report and the propagated exit code), the audit log proves the
// session ran under the Landlock+seccomp backend
// (`server.connected.enforcement.backend`), and yet no denial record
// exists. Absence is the spec — never read as "the denial did not
// happen".

#[cfg(target_os = "linux")]
fn kernel_probe_policy(dir: &Path, probe: &Path) -> PathBuf {
    // Grant the fixture's own directory so the image loads; the probe's
    // target paths deliberately sit outside every grant.
    let fs_allows = common::sandbox_fs_allows(&[dir], &[], probe);
    let mut text = common::sandboxed_policy(&fs_allows, "server \"probe\" {\n}\n");
    if common::linux_below_landlock_v4() {
        // Kernel < 6.7 (e.g. WSL2's 5.15) enforces Landlock ABI V1
        // partially; a fail-closed spawn would refuse. The denials this
        // test needs — fs rules and the syscall baseline — exist in V1.
        text.push_str("sandbox allow_degraded=#true\n");
    }
    let policy = dir.join("policy.kdl");
    std::fs::write(&policy, text).unwrap();
    policy
}

#[cfg(target_os = "linux")]
fn run_kernel_probe(probe: &Path, args: &[&str], dir: &Path) -> Run {
    let policy = kernel_probe_policy(dir, probe);
    let audit = dir.join("audit.jsonl");
    let mut cmd = std::process::Command::new(env!("CARGO_BIN_EXE_mcp-writ"));
    cmd.args(["run", "--transport", "stdio", "--policy"])
        .arg(&policy)
        // PR-18: the kernel-internal denial evidence is pinned to the
        // native Landlock+seccomp route — `auto` could resolve to the
        // namespaced route, which enforces through different machinery
        // than the legs assert on.
        .args(["--linux-mechanism", "native"])
        .args(["--audit-log", audit.to_str().expect("audit path utf-8")])
        .arg("--")
        .arg(probe)
        .args(args)
        .current_dir(dir)
        // A parent-level skip var must not leak into the evidence run.
        .env_remove("MCP_WRIT_SKIP_SANDBOX")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    run_with_timeout(&mut cmd)
}

/// Shared assertions for the unobservable legs. `exit 10` from the
/// fixture means the kernel denied the operation (EACCES/EPERM — the
/// stderr `KDP` marker carries the errno); the audit must then show the
/// session ran under the Landlock+seccomp backend while holding no
/// `sandbox.*_denied` record. A run where the probe never executed (no
/// marker) or where nothing denied the operation is an environment gap
/// — a skip, not a pass-by-absence.
#[cfg(target_os = "linux")]
fn assert_unobservable_denial(run: &Run, dir: &Path, leg: &str) {
    let marker = format!("KDP {leg}=errno=");
    if !run.stderr.contains(&marker) {
        common::skip_e2e_test(&format!(
            "sandboxed spawn unavailable ({leg} leg); stderr: {}",
            run.stderr
        ));
        return;
    }
    let audit = read_audit(&dir.join("audit.jsonl"));
    let backend = audit
        .lines()
        .filter(|l| !l.trim().is_empty())
        .filter(|l| audit_event_type(l).as_deref() == Some("server.connected"))
        .find_map(|l| {
            audit_json(l)
                .value()
                .to_member("enforcement")
                .ok()?
                .optional()?
                .to_member("backend")
                .ok()?
                .optional()?
                .to_unquoted_string_str()
                .ok()
                .map(|s| s.into_owned())
        });
    if run.code != 10 {
        // The probe ran but reported no denial. If enforcement claims it
        // applied, an undenied operation is a real gap; if it never did,
        // the leg exercised nothing and the host reports unavailable.
        assert!(
            backend.as_deref() != Some("landlock+seccomp"),
            "{leg}: enforcement claims landlock+seccomp but the kernel did not deny \
             (exit {}; stderr: {})",
            run.code,
            run.stderr
        );
        common::skip_e2e_test(&format!(
            "{leg}: operation was not denied (exit {}; stderr: {})",
            run.code, run.stderr
        ));
        return;
    }
    assert!(
        backend.as_deref() == Some("landlock+seccomp"),
        "{leg}: a kernel denial under `run` must come from the landlock+seccomp \
         backend (got {backend:?} — the workload may have run unsandboxed): {audit}"
    );

    // The launch happened and the workload lived inside it.
    for ty in ["server.connected", "server.disconnected", "guard.stopped"] {
        assert!(
            !audit_lines(&audit, ty).is_empty(),
            "{leg}: lifecycle record {ty} missing: {audit}"
        );
    }

    // The specification under test: kernel-internal denials produce no
    // userspace observation, so *no* `sandbox.*_denied` record may
    // exist — not because nothing was denied, but because nothing could
    // have observed it.
    let sandbox_denials: Vec<&str> = audit
        .lines()
        .filter(|l| !l.trim().is_empty())
        .filter(|l| {
            audit_event_type(l)
                .map(|t| t.starts_with("sandbox.") && t.ends_with("_denied"))
                .unwrap_or(false)
        })
        .collect();
    assert!(
        sandbox_denials.is_empty(),
        "{leg}: kernel-internal denials must leave no sandbox.*_denied record — \
         found {sandbox_denials:?} in {audit}"
    );
    // The reserved event names stay reserved.
    for reserved in ["sandbox.file_denied", "sandbox.process_denied"] {
        assert!(
            !audit.contains(reserved),
            "{leg}: {reserved} is reserved — it must never be emitted"
        );
    }
    eprintln!(
        "UNOBSERVABLE {leg}: exit=10 (kernel denied) backend={} — no sandbox.*_denied record, per spec",
        backend.unwrap_or_default()
    );
}

#[cfg(target_os = "linux")]
#[test]
fn landlock_fs_denial_is_unobservable_by_spec() {
    let dir = workdir("unobservable-fs");
    let probe_src = compile_fixture(
        "tests/fixtures/denial_audit/kernel_deny_probe.rs",
        "kernel_deny_probe",
    );
    // Stage the fixture into the granted dir — like the sandboxed
    // environment e2e, a binary living on a filesystem Landlock cannot
    // govern (a DrvFs checkout) is not a valid fixture image.
    let probe = dir.join("kernel_deny_probe");
    std::fs::copy(&probe_src, &probe).unwrap();

    // The secret exists but is outside every filesystem grant — the
    // denial is Landlock's, not a missing-file error.
    let secret_dir = workdir("unobservable-fs-secret");
    let secret = secret_dir.join("secret.txt");
    std::fs::write(&secret, "not granted\n").unwrap();

    let run = run_kernel_probe(&probe, &["open", secret.to_str().unwrap()], &dir);
    assert_unobservable_denial(&run, &dir, "open");
}

#[cfg(target_os = "linux")]
#[test]
fn seccomp_connect_denial_is_unobservable_by_spec() {
    let dir = workdir("unobservable-net");
    let probe_src = compile_fixture(
        "tests/fixtures/denial_audit/kernel_deny_probe.rs",
        "kernel_deny_probe",
    );
    let probe = dir.join("kernel_deny_probe");
    std::fs::copy(&probe_src, &probe).unwrap();

    // `socket`/`connect` are absent from the fixture syscall baseline —
    // the connect dies in-kernel (EPERM) without ever naming a
    // destination the audit could have recorded. The literal is
    // TEST-NET-1 documentation space: even an unsandboxed run cannot
    // escape anywhere real.
    let run = run_kernel_probe(&probe, &["connect", "192.0.2.1:443"], &dir);
    assert_unobservable_denial(&run, &dir, "connect");
}

// ─── PR-18: native-route IPC escape legs ─────────────────────────────
//
// The native route's AF_UNIX/signal containment (PR-18) pins
// `socket()`/`socketpair()` to the IP families under deny-all and adds
// the Landlock scope rights (abstract sockets + signals, ABI v6). The
// four legs below run the fixture's escape modes under a pinned
// `--linux-mechanism native` and assert the kernel outcome matches the
// enforcement report's own claim — a denial that never lands, or a
// disclosure that never happened, are both failures.
//
// The socket legs must be denied on every kernel: the family pin is a
// seccomp rule, not a Landlock right, so it is ABI-independent. The
// signal leg is honest per-kernel — `Scope::Signal` exists only on
// Landlock ABI v6+ (kernel 6.12), so below v6 the plan must carry
// `os.ipc.signal` as `not_applied` and the kill is expected to reach
// the outside process.

/// Unix-socket/signal syscalls the probe needs joined onto the fixture
/// baseline — under the bare baseline the syscall allowlist would kill
/// the legs before the family pin or scope is ever exercised, which
/// proves nothing about the PR-18 machinery. `network_rules` is spliced
/// verbatim into `defaults.network` so legs can vary the posture/opt-ins.
#[cfg(target_os = "linux")]
fn pr18_probe_policy(dir: &Path, probe: &Path, version: u8, network_rules: &str) -> PathBuf {
    let fs_allows = common::sandbox_fs_allows(&[dir], &[], probe);
    let baseline = common::FIXTURE_SYSCALLS_KDL
        .trim_end()
        .strip_suffix('}')
        .expect("fixture syscall block ends with }");
    let mut text = format!(
        "policy version={version}\ndefaults {{\n    filesystem {{\n        secret-overlay #true\n{fs_allows}    }}\n{baseline}        allow \"socket\" \"socketpair\" \"connect\" \"sendto\" \"sendmsg\" \"bind\" \"getsockname\" \"getpeername\" \"listen\" \"accept\" \"accept4\" \"tgkill\" \"pidfd_send_signal\" \"pidfd_open\"\n    }}\n    network {{\n        {network_rules}\n    }}\n    logging {{\n        fail_closed #false\n    }}\n}}\n\nserver \"probe\" {{\n    tool \"probe\"\n}}\n"
    );
    if common::linux_below_landlock_v4() {
        // Kernel < 6.7 enforces Landlock ABI V1 partially; a
        // fail-closed spawn would refuse. The denials the socket legs
        // need are seccomp's, which never depended on the Landlock ABI.
        text.push_str("sandbox allow_degraded=#true\n");
    }
    let policy = dir.join(format!("policy-{version}-{}.kdl", network_rules.len()));
    std::fs::write(&policy, text).unwrap();
    policy
}

/// Run one probe leg under a pinned native route; returns the run and
/// the launch report JSON the `--report` flag wrote (empty when the
/// run never produced one).
#[cfg(target_os = "linux")]
fn run_pr18_probe(
    probe: &Path,
    args: &[&str],
    dir: &Path,
    leg: &str,
    version: u8,
    network_rules: &str,
) -> (Run, String) {
    let policy = pr18_probe_policy(dir, probe, version, network_rules);
    let audit = dir.join(format!("audit-{leg}.jsonl"));
    let report = dir.join(format!("report-{leg}.json"));
    let mut cmd = std::process::Command::new(env!("CARGO_BIN_EXE_mcp-writ"));
    cmd.args(["run", "--transport", "stdio", "--policy"])
        .arg(&policy)
        .args(["--linux-mechanism", "native"])
        .args(["--audit-log", audit.to_str().expect("audit path utf-8")])
        .args(["--report", report.to_str().expect("report path utf-8")])
        .arg("--")
        .arg(probe)
        .args(args)
        .current_dir(dir)
        .env_remove("MCP_WRIT_SKIP_SANDBOX")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    (run_with_timeout(&mut cmd), read_audit(&report))
}

/// The `state` member of the planned control `id` in a launch report,
/// or `None` when the control is absent (a control the plan never
/// declared has no observation either).
#[cfg(target_os = "linux")]
fn plan_control_state(report: &str, id: &str) -> Option<String> {
    fn member<'a>(
        v: &nojson::RawJsonValue<'a, 'a>,
        name: &str,
    ) -> Option<nojson::RawJsonValue<'a, 'a>> {
        v.to_member(name).ok().and_then(|m| m.optional())
    }
    if report.trim().is_empty() {
        return None;
    }
    let json = nojson::RawJson::parse(report.trim())
        .unwrap_or_else(|e| panic!("launch report must parse as JSON: {e}\n{report}"));
    let root = json.value();
    let plan = member(&root, "plan")?;
    let controls = member(&plan, "controls")?;
    let mut arr = controls.to_array().ok()?;
    arr.find_map(|c| {
        let cid = member(&c, "id").and_then(|m| m.to_unquoted_string_str().ok())?;
        if cid.as_ref() != id {
            return None;
        }
        member(&c, "state")
            .and_then(|m| m.to_unquoted_string_str().ok())
            .map(|s| s.into_owned())
    })
}

/// A kernel-denied escape leg: the probe reported an errno and exited
/// 10. `leg` names the fixture mode for messages.
#[cfg(target_os = "linux")]
fn assert_escape_denied(run: &Run, leg: &str) {
    let marker = format!("KDP {leg}=");
    if !run.stderr.contains(&marker) {
        common::skip_e2e_test(&format!(
            "sandboxed spawn unavailable ({leg} leg); stderr: {}",
            run.stderr
        ));
        return;
    }
    assert_eq!(
        run.code, 10,
        "{leg}: the escape must be kernel-denied under the native route \
         (exit {}; stderr: {})",
        run.code, run.stderr
    );
}

#[cfg(target_os = "linux")]
#[test]
fn pr18_native_ipc_escape_legs() {
    let dir = workdir("pr18-ipc");
    let probe_src = compile_fixture(
        "tests/fixtures/denial_audit/kernel_deny_probe.rs",
        "kernel_deny_probe",
    );
    let probe = dir.join("kernel_deny_probe");
    std::fs::copy(&probe_src, &probe).unwrap();

    const DENY_ALL: &str = "deny host=\"*\"";

    // Leg 1 — pathname AF_UNIX connect. A live host-side listener makes
    // the leg real: without the pin the connect would succeed.
    let sock_path = dir.join("svc.sock");
    let _listener =
        std::os::unix::net::UnixListener::bind(&sock_path).expect("bind pathname unix listener");
    let (run, _report) = run_pr18_probe(
        &probe,
        &["unix-connect", sock_path.to_str().unwrap()],
        &dir,
        "unix-connect",
        1,
        DENY_ALL,
    );
    assert_escape_denied(&run, "unix-connect");

    // Leg 2 — abstract AF_UNIX connect. Path grants cannot cover an
    // abstract name; the family pin still denies the socket() creation.
    let abstract_name = format!("mcp-writ-pr18-{}", std::process::id());
    let _abstract = {
        use std::os::linux::net::SocketAddrExt;
        let addr = std::os::unix::net::SocketAddr::from_abstract_name(&abstract_name)
            .expect("abstract addr");
        std::os::unix::net::UnixListener::bind_addr(&addr).expect("bind abstract listener")
    };
    let (run, _report) = run_pr18_probe(
        &probe,
        &["abstract-connect", &abstract_name],
        &dir,
        "abstract-connect",
        1,
        DENY_ALL,
    );
    assert_escape_denied(&run, "abstract-connect");

    // Leg 3 — datagram sendto to a unix pathname. The dgram socket
    // never passes the family pin (and socketpair's dgram route is
    // denied outright).
    let dgram_path = dir.join("dgram.sock");
    let _dgram =
        std::os::unix::net::UnixDatagram::bind(&dgram_path).expect("bind unix datagram socket");
    let (run, _report) = run_pr18_probe(
        &probe,
        &["dgram-sendto", dgram_path.to_str().unwrap()],
        &dir,
        "dgram-sendto",
        1,
        DENY_ALL,
    );
    assert_escape_denied(&run, "dgram-sendto");

    // Positive control — an allowed TCP connect still passes. The
    // deny-all posture stands; `allow host="*" port=N` mints a netport
    // grant, so the loopback connect proves native TCP enforcement did
    // not regress beside the new pins.
    let tcp_listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind tcp listener");
    let tcp_port = tcp_listener.local_addr().unwrap().port();
    let net = format!("{DENY_ALL}\n        allow host=\"*\" port={tcp_port}");
    let (run, _report) = run_pr18_probe(
        &probe,
        &["connect", &format!("127.0.0.1:{tcp_port}")],
        &dir,
        "tcp-allow",
        1,
        &net,
    );
    if common::linux_below_landlock_v4() || !run.stderr.contains("KDP connect=") {
        common::skip_e2e_test(&format!(
            "sandboxed spawn unavailable or the kernel cannot express the \
             netport grant (tcp leg); stderr: {}",
            run.stderr
        ));
        return;
    }
    assert_eq!(
        run.code, 0,
        "allowed TCP connect must still pass under the pins (exit {}; stderr: {})",
        run.code, run.stderr
    );
    assert!(
        run.stderr.contains("KDP connect=ok"),
        "the TCP control leg must report ok: {}",
        run.stderr
    );

    // Leg 4 — signal escape. The probe signals this test process
    // (outside the sandbox domain, same uid) with signal 0: the cred
    // check passes, so only `Scope::Signal` can deny it. Below Landlock
    // ABI v6 there is no scope to apply — the plan must already say
    // `not_applied` and the escape is expected to succeed, which is the
    // disclosure the spec requires rather than a denial that never
    // lands.
    let parent_pid = std::process::id().to_string();
    let (run, report) = run_pr18_probe(&probe, &["kill", &parent_pid], &dir, "kill", 1, DENY_ALL);
    if !run.stderr.contains("KDP kill=") {
        common::skip_e2e_test(&format!(
            "sandboxed spawn unavailable (kill leg); stderr: {}",
            run.stderr
        ));
        return;
    }
    let signal_state = plan_control_state(&report, "os.ipc.signal");
    match signal_state.as_deref() {
        Some("planned") => {
            // ABI v6+: the scope is planned, so the kernel must deny.
            assert_eq!(
                run.code, 10,
                "kill: Scope::Signal is planned but the kill reached outside \
                 (exit {}; stderr: {})",
                run.code, run.stderr
            );
        }
        Some("not_applied") => {
            // ABI < 6: no scope can exist — the disclosed gap, and the
            // escape succeeding is the honest outcome.
            assert_eq!(
                run.code, 0,
                "kill: os.ipc.signal is disclosed not_applied (ABI < 6) yet the \
                 escape was denied — the disclosure and the kernel disagree \
                 (exit {}; stderr: {})",
                run.code, run.stderr
            );
            assert!(
                report.contains("Landlock ABI"),
                "the not_applied reason must name the kernel Landlock ABI \
                 that cannot express the scope: {report}"
            );
        }
        other => panic!(
            "kill: unexpected os.ipc.signal plan state {other:?} — the leg \
             cannot check a control it cannot read (report: {report})"
        ),
    }
    eprintln!(
        "PR-18 legs: unix-connect/abstract-connect/dgram-sendto denied by the \
         family pin; kill leg plan state {signal_state:?} → exit {}",
        run.code
    );
}

/// The `allow unix=` opt-in legs: `"*"` re-admits the whole family on
/// any kernel, while a path-bound opt-in must reopen exactly its
/// scope — connects beneath the socket's parent directory pass, and
/// everything the pins close stays closed (other directories, datagram
/// sockets, abstract names).
#[cfg(target_os = "linux")]
#[test]
fn pr18_native_unix_optin_legs() {
    let dir = workdir("pr18-unix-optin");
    let probe_src = compile_fixture(
        "tests/fixtures/denial_audit/kernel_deny_probe.rs",
        "kernel_deny_probe",
    );
    let probe = dir.join("kernel_deny_probe");
    std::fs::copy(&probe_src, &probe).unwrap();

    const DENY_ALL: &str = "deny host=\"*\"";
    let star_net = format!("{DENY_ALL}\n        allow unix=\"*\"");

    // Leg 1 — `unix="*"` lets a pathname connect through: the seccomp
    // pin admits the family and no Landlock right is needed, so this
    // leg runs on every kernel.
    let sock_path = dir.join("star.sock");
    let _listener =
        std::os::unix::net::UnixListener::bind(&sock_path).expect("bind pathname unix listener");
    let (run, _report) = run_pr18_probe(
        &probe,
        &["unix-connect", sock_path.to_str().unwrap()],
        &dir,
        "unix-star",
        2,
        &star_net,
    );
    if !run.stderr.contains("KDP unix-connect=") {
        common::skip_e2e_test(&format!(
            "sandboxed spawn unavailable (unix-star leg); stderr: {}",
            run.stderr
        ));
        return;
    }
    assert_eq!(
        run.code, 0,
        "unix=\"*\" must re-admit a pathname connect (exit {}; stderr: {})",
        run.code, run.stderr
    );
    assert!(
        run.stderr.contains("KDP unix-connect=ok"),
        "the '*' opt-in leg must report ok: {}",
        run.stderr
    );

    // Leg 2 — under `unix="*"` the abstract-socket scope is deliberately
    // waived, so the abstract connect reaches the listener too.
    let star_abstract = format!("mcp-writ-pr18-star-{}", std::process::id());
    let _star_listener = {
        use std::os::linux::net::SocketAddrExt;
        let addr = std::os::unix::net::SocketAddr::from_abstract_name(&star_abstract)
            .expect("abstract addr");
        std::os::unix::net::UnixListener::bind_addr(&addr).expect("bind abstract listener")
    };
    let (run, _report) = run_pr18_probe(
        &probe,
        &["abstract-connect", &star_abstract],
        &dir,
        "unix-star-abstract",
        2,
        &star_net,
    );
    if !run.stderr.contains("KDP abstract-connect=") {
        common::skip_e2e_test(&format!(
            "sandboxed spawn unavailable (unix-star-abstract leg); stderr: {}",
            run.stderr
        ));
        return;
    }
    assert_eq!(
        run.code, 0,
        "unix=\"*\" waives abstract-socket scoping — the connect must pass \
         (exit {}; stderr: {})",
        run.code, run.stderr
    );

    // Legs 3–6 — a path-bound opt-in needs Landlock ABI v9
    // (`ResolveUnix`): below it selection refuses the launch, the probe
    // never runs, and the missing KDP marker skips the legs rather than
    // failing them.
    let optin_sock = dir.join("optin.sock");
    let _optin_listener =
        std::os::unix::net::UnixListener::bind(&optin_sock).expect("bind opt-in socket");
    let outside_dir = workdir("pr18-unix-outside");
    let outside_sock = outside_dir.join("outside.sock");
    let _outside_listener =
        std::os::unix::net::UnixListener::bind(&outside_sock).expect("bind outside socket");
    let dgram_sock = dir.join("optin-dgram.sock");
    let _dgram =
        std::os::unix::net::UnixDatagram::bind(&dgram_sock).expect("bind unix datagram socket");
    let path_net = format!(
        "{DENY_ALL}\n        allow unix=\"{}\"",
        optin_sock.display()
    );

    // Leg 3 — connect to the opted-in socket beneath its granted parent.
    let (run, _report) = run_pr18_probe(
        &probe,
        &["unix-connect", optin_sock.to_str().unwrap()],
        &dir,
        "unix-path-allow",
        2,
        &path_net,
    );
    if !run.stderr.contains("KDP unix-connect=") {
        common::skip_e2e_test(&format!(
            "path opt-in legs need Landlock ABI v9 — stderr: {}",
            run.stderr
        ));
        return;
    }
    assert_eq!(
        run.code, 0,
        "unix=<path> must allow connects beneath the socket's parent \
         directory (exit {}; stderr: {})",
        run.code, run.stderr
    );
    assert!(
        run.stderr.contains("KDP unix-connect=ok"),
        "the path opt-in leg must report ok: {}",
        run.stderr
    );

    // Leg 4 — a pathname connect outside the granted parent stays denied.
    let (run, _report) = run_pr18_probe(
        &probe,
        &["unix-connect", outside_sock.to_str().unwrap()],
        &dir,
        "unix-path-outside",
        2,
        &path_net,
    );
    assert_escape_denied(&run, "unix-path-outside");

    // Leg 5 — a datagram sendto stays denied: the opt-in re-admits
    // SOCK_STREAM only, so the dgram socket() call never happens.
    let (run, _report) = run_pr18_probe(
        &probe,
        &["dgram-sendto", dgram_sock.to_str().unwrap()],
        &dir,
        "unix-path-dgram",
        2,
        &path_net,
    );
    assert_escape_denied(&run, "unix-path-dgram");

    // Leg 6 — abstract sockets stay scoped: a path opt-in does not waive
    // `Scope::AbstractUnixSocket` the way `"*"` does.
    let path_abstract = format!("mcp-writ-pr18-path-{}", std::process::id());
    let _path_listener = {
        use std::os::linux::net::SocketAddrExt;
        let addr = std::os::unix::net::SocketAddr::from_abstract_name(&path_abstract)
            .expect("abstract addr");
        std::os::unix::net::UnixListener::bind_addr(&addr).expect("bind abstract listener")
    };
    let (run, _report) = run_pr18_probe(
        &probe,
        &["abstract-connect", &path_abstract],
        &dir,
        "unix-path-abstract",
        2,
        &path_net,
    );
    assert_escape_denied(&run, "unix-path-abstract");

    eprintln!(
        "PR-18 opt-in legs: '*' admitted pathname+abstract connects; the \
         path opt-in allowed beneath its parent dir and denied \
         outside/dgram/abstract"
    );
}
