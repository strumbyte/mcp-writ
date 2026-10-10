//! Integration tests for `dnsgate` — the policy-evaluating DNS
//! resolver (PR-06, improvement plan §1.2/§1.6).
//!
//! A real gate task is served on loopback against a scripted mock
//! upstream; clients are raw UDP/TCP sockets, so the whole exchange is
//! exercised on the wire. Assertions cover: name-layer evaluation
//! parity with the Auditor (`host_matches` semantics), refusal RCODEs,
//! the deny-all posture (an empty allow list refuses every name — only
//! `allow host="*"` opens the gate), `sandbox.network_denied` /
//! `sandbox.network_resolved` emission with `name`/`qtype`/`session_id`,
//! CNAME-chain observation without re-judgement, chain-minimum-TTL
//! grants into the dynamic allow list, upstream timeout/mismatch
//! handling, TCP connection capacity, and fail-closed behavior when
//! the audit sink is unavailable.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use tokio::time::timeout;

use mcp_writ::audit_log::{AuditLogger, AuditSyncMode};
use mcp_writ::dnsgate::{DynamicAllowList, GateConfig, Refusal};
use mcp_writ::policy::{OutboundPolicy, Policy};

const TEST_TIMEOUT: Duration = Duration::from_secs(10);

// ─── Wire helpers (test-local; the crate's codec is crate-internal) ──

fn name_wire(name: &str) -> Vec<u8> {
    let mut out = Vec::new();
    // Empty labels are skipped so a trailing dot encodes as the root
    // terminator it already denotes, not a malformed extra byte.
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
    pkt.extend_from_slice(&name_wire(name));
    pkt.extend_from_slice(&qtype.to_be_bytes());
    pkt.extend_from_slice(&1u16.to_be_bytes()); // IN
    pkt
}

/// Decode an uncompressed dotted name at `off` (test messages never
/// compress; the decoder rejects pointers deliberately — a compressed
/// test name is a bug, not an input).
fn decode_name_uncompressed(buf: &[u8], off: usize) -> Option<(String, usize)> {
    let mut labels = Vec::new();
    let mut pos = off;
    loop {
        let b = *buf.get(pos)?;
        if b == 0 {
            return Some((labels.join("."), pos + 1));
        }
        assert_eq!(b & 0xC0, 0, "test decoder: compression pointer");
        let len = b as usize;
        labels.push(
            std::str::from_utf8(buf.get(pos + 1..pos + 1 + len)?)
                .ok()?
                .to_string(),
        );
        pos += 1 + len;
    }
}

fn question_end(buf: &[u8]) -> usize {
    let (_name, end) = decode_name_uncompressed(buf, 12).expect("question name");
    end + 4
}

fn rcode(resp: &[u8]) -> u8 {
    resp[3] & 0x0F
}

fn ancount(resp: &[u8]) -> u16 {
    u16::from_be_bytes([resp[6], resp[7]])
}

/// IPv4 addresses from answer-section A records (walks compression
/// pointers — upstream answers may compress owners).
fn answer_a_records(resp: &[u8]) -> Vec<Ipv4Addr> {
    fn skip_name(buf: &[u8], off: usize) -> Option<usize> {
        let mut pos = off;
        loop {
            let b = *buf.get(pos)?;
            if b & 0xC0 == 0xC0 {
                return Some(pos + 2);
            }
            if b == 0 {
                return Some(pos + 1);
            }
            pos += 1 + b as usize;
        }
    }
    let an = ancount(resp) as usize;
    let mut pos = question_end(resp);
    let mut out = Vec::new();
    for _ in 0..an {
        let Some(p) = skip_name(resp, pos) else { break };
        pos = p;
        if pos + 10 > resp.len() {
            break;
        }
        let rtype = u16::from_be_bytes([resp[pos], resp[pos + 1]]);
        let rdlen = u16::from_be_bytes([resp[pos + 8], resp[pos + 9]]) as usize;
        pos += 10;
        if pos + rdlen > resp.len() {
            break;
        }
        if rtype == 1 && rdlen == 4 {
            out.push(Ipv4Addr::new(
                resp[pos],
                resp[pos + 1],
                resp[pos + 2],
                resp[pos + 3],
            ));
        }
        pos += rdlen;
    }
    out
}

// ─── Mock upstream ──────────────────────────────────────────────────

enum Answ {
    Cname {
        owner: String,
        target: String,
        ttl: u32,
    },
    A {
        owner: String,
        ip: Ipv4Addr,
        ttl: u32,
    },
}

struct MockAnswer {
    rcode: u8,
    /// Respond truncated over UDP (drives the gate's own TCP retry).
    tc_on_udp: bool,
    answers: Vec<Answ>,
    /// Never answer — drives the upstream-timeout path.
    silent: bool,
    /// Echo a wrong query ID — drives the upstream-mismatch path.
    corrupt_id: bool,
}

fn push_rr(out: &mut Vec<u8>, owner: &str, rtype: u16, ttl: u32, rdata: &[u8]) {
    out.extend_from_slice(&name_wire(owner));
    out.extend_from_slice(&rtype.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes()); // IN
    out.extend_from_slice(&ttl.to_be_bytes());
    out.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
    out.extend_from_slice(rdata);
}

fn mock_response(req: &[u8], spec: &MockAnswer, tcp: bool) -> Vec<u8> {
    let qend = question_end(req);
    let tc = spec.tc_on_udp && !tcp;
    let answers: &[Answ] = if tc { &[] } else { &spec.answers };
    let mut out = Vec::new();
    if spec.corrupt_id {
        out.extend_from_slice(&[req[0] ^ 0xFF, req[1]]);
    } else {
        out.extend_from_slice(&req[0..2]);
    }
    out.push(0x81 | if tc { 0x02 } else { 0 }); // QR|RD(+TC)
    out.push(0x80 | spec.rcode); // RA|rcode
    out.extend_from_slice(&1u16.to_be_bytes());
    out.extend_from_slice(&(answers.len() as u16).to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&req[12..qend]);
    for a in answers {
        match a {
            Answ::Cname { owner, target, ttl } => {
                push_rr(&mut out, owner, 5, *ttl, &name_wire(target));
            }
            Answ::A { owner, ip, ttl } => {
                push_rr(&mut out, owner, 1, *ttl, &ip.octets());
            }
        }
    }
    out
}

fn answer_for(table: &HashMap<String, MockAnswer>, req: &[u8], tcp: bool) -> Option<Vec<u8>> {
    let (name, _end) = decode_name_uncompressed(req, 12)?;
    match table.get(&name.to_ascii_lowercase()) {
        Some(spec) if spec.silent => None,
        Some(spec) => Some(mock_response(req, spec, tcp)),
        // Default upstream answer for an unknown name: NXDOMAIN.
        None => Some(mock_response(
            req,
            &MockAnswer {
                rcode: 3,
                tc_on_udp: false,
                answers: Vec::new(),
                silent: false,
                corrupt_id: false,
            },
            tcp,
        )),
    }
}

struct MockUpstream {
    addr: SocketAddr,
    _udp: JoinHandle<()>,
    _tcp: JoinHandle<()>,
}

async fn spawn_mock_upstream(table: HashMap<String, MockAnswer>) -> MockUpstream {
    let table = Arc::new(table);
    // The UDP socket picks a port the TCP listener then shares — a
    // concurrent test may claim it in between, so retry on TCP bind
    // failure rather than assume the port stayed free.
    let (udp, tcp, port) = 'bind: {
        for _ in 0..32 {
            let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let port = udp.local_addr().unwrap().port();
            if let Ok(tcp) = TcpListener::bind(("127.0.0.1", port)).await {
                break 'bind (udp, tcp, port);
            }
        }
        panic!("mock upstream could not claim a shared udp+tcp port");
    };
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);

    let udp_task = {
        let table = table.clone();
        tokio::spawn(async move {
            let mut buf = [0u8; 4096];
            while let Ok((n, peer)) = udp.recv_from(&mut buf).await {
                if let Some(resp) = answer_for(&table, &buf[..n], false) {
                    let _ = udp.send_to(&resp, peer).await;
                }
            }
        })
    };
    let tcp_task = tokio::spawn(async move {
        while let Ok((mut stream, _peer)) = tcp.accept().await {
            let table = table.clone();
            tokio::spawn(async move {
                let mut len_buf = [0u8; 2];
                while stream.read_exact(&mut len_buf).await.is_ok() {
                    let len = u16::from_be_bytes(len_buf) as usize;
                    if len == 0 || len > 4096 {
                        return;
                    }
                    let mut req = vec![0u8; len];
                    if stream.read_exact(&mut req).await.is_err() {
                        return;
                    }
                    let Some(resp) = answer_for(&table, &req, true) else {
                        return;
                    };
                    let out_len = (resp.len() as u16).to_be_bytes();
                    if stream.write_all(&out_len).await.is_err()
                        || stream.write_all(&resp).await.is_err()
                    {
                        return;
                    }
                }
            });
        }
    });
    MockUpstream {
        addr,
        _udp: udp_task,
        _tcp: tcp_task,
    }
}

// ─── Gate harness ───────────────────────────────────────────────────

struct GateHandle {
    listen: SocketAddr,
    allowlist: Arc<DynamicAllowList>,
    shutdown: oneshot::Sender<()>,
    task: JoinHandle<std::io::Result<()>>,
    logger: AuditLogger,
    audit_path: PathBuf,
    _tmp: tempfile::TempDir,
    _upstream: MockUpstream,
}

fn outbound(
    allowed: &[&str],
    denied: &[&str],
    allowed_cidrs: &[&str],
    denied_cidrs: &[&str],
    deny_all: bool,
) -> OutboundPolicy {
    OutboundPolicy {
        allowed: allowed.iter().map(|s| s.to_string()).collect(),
        allowed_port_qualified: Vec::new(),
        allowed_cidrs: allowed_cidrs.iter().map(|s| s.to_string()).collect(),
        allowed_cidrs_port_qualified: Vec::new(),
        denied_hosts: denied.iter().map(|s| s.to_string()).collect(),
        denied_cidrs: denied_cidrs.iter().map(|s| s.to_string()).collect(),
        deny_all_others: deny_all,
        egress_rules: Vec::new(),
    }
}

fn policy_with(outbound: OutboundPolicy) -> Policy {
    let mut p = Policy::default();
    p.network.outbound = outbound;
    p
}

/// Bind an ephemeral loopback port for the gate's listeners (the port
/// is released before the gate binds — the standard ephemeral-probe
/// trick; on loopback the race window is harmless for a test).
async fn free_port() -> u16 {
    let probe = TcpListener::bind("127.0.0.1:0").await.unwrap();
    probe.local_addr().unwrap().port()
}

async fn start_gate(
    policy: Policy,
    upstream_table: HashMap<String, MockAnswer>,
    refusal: Refusal,
    allowlist_export: Option<PathBuf>,
    fail_closed: bool,
) -> GateHandle {
    let upstream = spawn_mock_upstream(upstream_table).await;

    let tmp = tempfile::tempdir().unwrap();
    let audit_path = tmp.path().join("audit.jsonl");
    let logger =
        AuditLogger::to_file_with_options(&audit_path, fail_closed, AuditSyncMode::Buffered)
            .expect("audit log");
    let allowlist = Arc::new(DynamicAllowList::new(1024));

    // Port race: the probed-free port can be claimed by a concurrent
    // test between release and bind, which fails `serve` immediately.
    // A dead task is the tell — retry on a fresh port until ours stays
    // alive AND answers the probe (a probe answered by a stranger's
    // gate while ours died is caught by the final is_finished check).
    let (listen, tx, task) = 'outer: {
        for _ in 0..32 {
            let listen = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), free_port().await);
            let config = GateConfig {
                listen,
                upstream: upstream.addr,
                refusal,
                allowlist_export: allowlist_export.clone(),
                max_grants: 1024,
            };
            let (tx, rx) = oneshot::channel::<()>();
            let al = allowlist.clone();
            let lg = logger.clone();
            let policy = policy.clone();
            let task = tokio::spawn(async move {
                mcp_writ::dnsgate::serve(
                    config,
                    policy,
                    al,
                    lg,
                    uuid::Uuid::now_v7(),
                    None,
                    async move {
                        let _ = rx.await;
                    },
                )
                .await
            });
            // Wait until the gate's UDP listener is actually bound: a
            // header-only packet earns a FORMERR once the socket
            // answers.
            let probe_deadline = tokio::time::Instant::now() + Duration::from_secs(5);
            loop {
                if task.is_finished() {
                    break; // bind lost the race — retry on a new port
                }
                if udp_probe(listen).await {
                    if !task.is_finished() {
                        break 'outer (listen, tx, task);
                    }
                    break;
                }
                assert!(
                    tokio::time::Instant::now() < probe_deadline,
                    "dns gate did not bind within 5s"
                );
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        }
        panic!("dns gate could not claim a port after 32 tries");
    };

    GateHandle {
        listen,
        allowlist,
        shutdown: tx,
        task,
        logger,
        audit_path,
        _tmp: tmp,
        _upstream: upstream,
    }
}

/// Probe that the gate's UDP socket is bound — a 12-byte header with
/// qdcount=0 is malformed but answerable (FORMERR), so any response
/// proves the listener is serving.
async fn udp_probe(listen: SocketAddr) -> bool {
    let Ok(sock) = UdpSocket::bind("127.0.0.1:0").await else {
        return false;
    };
    if sock.connect(listen).await.is_err() {
        return false;
    }
    let mut probe = Vec::new();
    probe.extend_from_slice(&0xEEu16.to_be_bytes());
    probe.extend_from_slice(&0x0100u16.to_be_bytes());
    probe.extend_from_slice(&[0u8; 8]); // all counts zero
    if sock.send(&probe).await.is_err() {
        return false;
    }
    let mut buf = [0u8; 64];
    match timeout(Duration::from_millis(100), sock.recv(&mut buf)).await {
        Ok(Ok(n)) => n >= 2 && buf[0] == 0 && buf[1] == 0xEE,
        _ => false,
    }
}

async fn stop_gate(gate: GateHandle) -> Vec<String> {
    let _ = gate.shutdown.send(());
    let res = timeout(TEST_TIMEOUT, gate.task).await.unwrap();
    res.unwrap().unwrap();
    gate.logger.shutdown().await;
    std::fs::read_to_string(&gate.audit_path)
        .unwrap_or_default()
        .lines()
        .map(|l| l.to_string())
        .collect()
}

/// Event details for every emitted record of .
fn details_for(lines: &[String], event_type: &str) -> Vec<String> {
    lines
        .iter()
        .filter_map(|l| {
            let j = nojson::RawJson::parse(l).ok()?;
            let ty = j
                .value()
                .to_member("event_type")
                .ok()?
                .optional()?
                .to_unquoted_string_str()
                .ok()?
                .into_owned();
            if ty != event_type {
                return None;
            }
            j.value()
                .to_member("details")
                .ok()?
                .optional()
                .and_then(|d| d.to_unquoted_string_str().ok())
                .map(|d| d.into_owned())
        })
        .collect()
}

// ─── Client helpers ─────────────────────────────────────────────────

async fn udp_query(listen: SocketAddr, pkt: &[u8]) -> Option<Vec<u8>> {
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    // connect() pins the peer so a stray datagram recycled onto this
    // ephemeral port cannot be mistaken for our answer; matching the
    // query id discards a late duplicate from the same gate.
    sock.connect(listen).await.unwrap();
    sock.send(pkt).await.unwrap();
    let want_id = u16::from_be_bytes([pkt[0], pkt[1]]);
    let mut buf = [0u8; 4096];
    let deadline = tokio::time::Instant::now() + TEST_TIMEOUT;
    loop {
        let n = timeout(deadline - tokio::time::Instant::now(), sock.recv(&mut buf))
            .await
            .ok()?
            .ok()?;
        if n >= 2 && u16::from_be_bytes([buf[0], buf[1]]) == want_id {
            return Some(buf[..n].to_vec());
        }
    }
}

async fn tcp_query(listen: SocketAddr, pkt: &[u8]) -> Option<Vec<u8>> {
    let mut s = TcpStream::connect(listen).await.ok()?;
    s.write_all(&(pkt.len() as u16).to_be_bytes()).await.ok()?;
    s.write_all(pkt).await.ok()?;
    let mut len_buf = [0u8; 2];
    timeout(TEST_TIMEOUT, s.read_exact(&mut len_buf))
        .await
        .ok()?
        .ok()?;
    let len = u16::from_be_bytes(len_buf) as usize;
    let mut resp = vec![0u8; len];
    timeout(TEST_TIMEOUT, s.read_exact(&mut resp))
        .await
        .ok()?
        .ok()?;
    Some(resp)
}

// ─── Tests ──────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn denied_name_is_refused_and_audited() {
    let mut table = HashMap::new();
    table.insert(
        "allowed.example".to_string(),
        MockAnswer {
            rcode: 0,
            tc_on_udp: false,
            answers: vec![Answ::A {
                owner: "allowed.example".into(),
                ip: Ipv4Addr::new(93, 184, 216, 34),
                ttl: 60,
            }],
            silent: false,
            corrupt_id: false,
        },
    );
    let gate = start_gate(
        policy_with(outbound(&["allowed.example"], &[], &[], &[], true)),
        table,
        Refusal::Refused,
        None,
        false,
    )
    .await;

    // Denied: not on the allow list under deny-all-others → REFUSED,
    // and upstream is never contacted (mock would answer NXDOMAIN for
    // an unknown name, but a refusal must not even forward).
    let resp = udp_query(gate.listen, &dns_query(1, "denied.example", 1))
        .await
        .expect("refusal answer");
    assert_eq!(rcode(&resp), 5, "denied name must be REFUSED");
    assert_eq!(resp[0..2], 1u16.to_be_bytes(), "same query id echoed");

    // Allowed: relays the upstream A record.
    let resp = udp_query(gate.listen, &dns_query(2, "allowed.example", 1))
        .await
        .expect("upstream answer");
    assert_eq!(rcode(&resp), 0);
    assert_eq!(
        answer_a_records(&resp),
        vec![Ipv4Addr::new(93, 184, 216, 34)]
    );

    let lines = stop_gate(gate).await;
    // The startup probe also earns a `protocol-error` denial record —
    // match on the queried name rather than the raw record count.
    let denied = details_for(&lines, "sandbox.network_denied");
    let denied: Vec<&String> = denied
        .iter()
        .filter(|d| d.contains("name=denied.example"))
        .collect();
    assert_eq!(denied.len(), 1, "one denial record: {denied:?}");
    let d = denied[0];
    assert!(d.contains("layer=name"), "{d}");
    assert!(d.contains("name=denied.example"), "{d}");
    assert!(d.contains("qtype=A"), "{d}");
    assert!(d.contains("decision=not-allowed"), "{d}");
    assert!(d.contains("session_id="), "{d}");

    let resolved = details_for(&lines, "sandbox.network_resolved");
    assert_eq!(resolved.len(), 1, "one resolution record: {resolved:?}");
    let r = &resolved[0];
    assert!(r.contains("name=allowed.example"), "{r}");
    assert!(r.contains("addrs=[93.184.216.34]"), "{r}");
    assert!(r.contains("ttl_min=60"), "{r}");
    assert!(r.contains("session_id="), "{r}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn deny_host_rule_wins_over_allow() {
    // deny wins even when an allow also covers the name — the same
    // precedence the Auditor applies to argument hosts.
    let gate = start_gate(
        policy_with(outbound(&["*"], &["bad.example"], &[], &[], false)),
        HashMap::new(),
        Refusal::Refused,
        None,
        false,
    )
    .await;
    let resp = udp_query(gate.listen, &dns_query(1, "bad.example", 1))
        .await
        .unwrap();
    assert_eq!(rcode(&resp), 5);
    let lines = stop_gate(gate).await;
    let denied = details_for(&lines, "sandbox.network_denied");
    assert!(denied.iter().any(|d| d.contains("name=bad.example")
        && d.contains("decision=deny-host")
        && d.contains("rule=bad.example")));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wildcard_covers_subdomain_not_bare() {
    //  covers sub.example.com but NOT bare example.com —
    // the same wildcard semantics as the Auditor.
    let mut table = HashMap::new();
    table.insert(
        "sub.example.com".to_string(),
        MockAnswer {
            rcode: 0,
            tc_on_udp: false,
            answers: vec![Answ::A {
                owner: "sub.example.com".into(),
                ip: Ipv4Addr::new(192, 0, 2, 10),
                ttl: 30,
            }],
            silent: false,
            corrupt_id: false,
        },
    );
    let gate = start_gate(
        policy_with(outbound(&["*.example.com"], &[], &[], &[], true)),
        table,
        Refusal::Refused,
        None,
        false,
    )
    .await;
    let resp = udp_query(gate.listen, &dns_query(1, "sub.example.com", 1))
        .await
        .unwrap();
    assert_eq!(rcode(&resp), 0);
    let resp = udp_query(gate.listen, &dns_query(2, "example.com", 1))
        .await
        .unwrap();
    assert_eq!(rcode(&resp), 5, "bare domain must not match wildcard");
    let resp = udp_query(gate.listen, &dns_query(3, "evilexample.com", 1))
        .await
        .unwrap();
    assert_eq!(rcode(&resp), 5, "suffix lookalike must not match");
    stop_gate(gate).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn nxdomain_refusal_rcode() {
    let gate = start_gate(
        policy_with(outbound(&["allowed.example"], &[], &[], &[], true)),
        HashMap::new(),
        Refusal::Nxdomain,
        None,
        false,
    )
    .await;
    let resp = udp_query(gate.listen, &dns_query(1, "denied.example", 1))
        .await
        .unwrap();
    assert_eq!(rcode(&resp), 3, "configured NXDOMAIN refusal");
    stop_gate(gate).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cname_chain_recorded_not_rejudged() {
    // The CNAME target is deliberately *denied* by policy — a correct
    // gate evaluates only the queried name, observes the chain for
    // audit, and still relays the answer.
    let mut table = HashMap::new();
    table.insert(
        "www.allowed.example".to_string(),
        MockAnswer {
            rcode: 0,
            tc_on_udp: false,
            answers: vec![
                Answ::Cname {
                    owner: "www.allowed.example".into(),
                    target: "edge.denied.example".into(),
                    // Shorter than the A record's TTL — the grant must
                    // not outlive the alias that vended it.
                    ttl: 20,
                },
                Answ::A {
                    owner: "edge.denied.example".into(),
                    ip: Ipv4Addr::new(203, 0, 113, 5),
                    ttl: 45,
                },
            ],
            silent: false,
            corrupt_id: false,
        },
    );
    let gate = start_gate(
        policy_with(outbound(
            &["allowed.example", "*.allowed.example"],
            &["*.denied.example"],
            &[],
            &[],
            true,
        )),
        table,
        Refusal::Refused,
        None,
        false,
    )
    .await;
    let resp = udp_query(gate.listen, &dns_query(1, "www.allowed.example", 1))
        .await
        .expect("chain answer");
    assert_eq!(
        rcode(&resp),
        0,
        "denied CNAME target must not refuse the allowed query"
    );
    assert_eq!(answer_a_records(&resp), vec![Ipv4Addr::new(203, 0, 113, 5)]);

    // The A record minted a grant under the queried name — chain-min
    // TTL (min(20,45)=20), so the grant expires near now+20, well
    // inside the address record's own 45s.
    let addr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5));
    assert!(
        gate.allowlist
            .is_allowed(&addr, mcp_writ::policy::EgressProto::Tcp, 443),
        "answer IP must be allow-listed"
    );
    assert_eq!(
        gate.allowlist.names_for(&addr),
        vec!["www.allowed.example".to_string()]
    );
    let snapshot = gate.allowlist.snapshot_json();
    let json = nojson::RawJson::parse(&snapshot).unwrap();
    let exp: u64 = json
        .value()
        .to_member("entries")
        .unwrap()
        .required()
        .unwrap()
        .to_array()
        .unwrap()
        .next()
        .unwrap()
        .to_member("expires_at_unix_secs")
        .unwrap()
        .required()
        .unwrap()
        .as_number_str()
        .unwrap()
        .parse()
        .unwrap();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    assert!(
        exp > now && exp <= now + 21,
        "grant expiry must be chain-min TTL, not the A record's 45s: exp={exp} now={now}"
    );

    let lines = stop_gate(gate).await;
    let resolved = details_for(&lines, "sandbox.network_resolved");
    assert_eq!(resolved.len(), 1);
    let r = &resolved[0];
    assert!(r.contains("chain=edge.denied.example"), "{r}");
    assert!(r.contains("ttl_min=20"), "{r}");
    assert!(r.contains("grants=1"), "{r}");
    // And no denial record exists for the chain target.
    let denied = details_for(&lines, "sandbox.network_denied");
    assert!(
        denied.iter().all(|d| !d.contains("denied.example")),
        "chain target must not be denied: {denied:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn idna_and_trailing_dot_normalize() {
    // Full-width spelling and a trailing root dot fold to the same
    // canonical identity — a Unicode variant cannot evade or bypass
    // the rule either way.
    let mut table = HashMap::new();
    table.insert(
        "example.com".to_string(),
        MockAnswer {
            rcode: 0,
            tc_on_udp: false,
            answers: vec![Answ::A {
                owner: "example.com".into(),
                ip: Ipv4Addr::new(93, 184, 216, 34),
                ttl: 300,
            }],
            silent: false,
            corrupt_id: false,
        },
    );
    let gate = start_gate(
        policy_with(outbound(&["example.com"], &[], &[], &[], true)),
        table,
        Refusal::Refused,
        None,
        false,
    )
    .await;
    let resp = udp_query(gate.listen, &dns_query(1, "EXAMPLE.com.", 1))
        .await
        .unwrap();
    assert_eq!(rcode(&resp), 0, "case + trailing dot fold to the allow");
    let resp = udp_query(
        gate.listen,
        &dns_query(2, "ｅｘａｍｐｌｅ.com", 1), // full-width letters
    )
    .await
    .unwrap();
    assert_eq!(rcode(&resp), 0, "UTS-46 folds full-width to example.com");
    stop_gate(gate).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tcp_transport_round_trip() {
    let mut table = HashMap::new();
    table.insert(
        "allowed.example".to_string(),
        MockAnswer {
            rcode: 0,
            tc_on_udp: false,
            answers: vec![Answ::A {
                owner: "allowed.example".into(),
                ip: Ipv4Addr::new(93, 184, 216, 34),
                ttl: 60,
            }],
            silent: false,
            corrupt_id: false,
        },
    );
    let gate = start_gate(
        policy_with(outbound(&["allowed.example"], &[], &[], &[], true)),
        table,
        Refusal::Refused,
        None,
        false,
    )
    .await;
    let resp = tcp_query(gate.listen, &dns_query(1, "allowed.example", 1))
        .await
        .expect("tcp answer");
    assert_eq!(rcode(&resp), 0);
    assert_eq!(
        answer_a_records(&resp),
        vec![Ipv4Addr::new(93, 184, 216, 34)]
    );
    let resp = tcp_query(gate.listen, &dns_query(2, "denied.example", 1))
        .await
        .expect("tcp refusal");
    assert_eq!(rcode(&resp), 5);
    stop_gate(gate).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tc_answer_retries_over_tcp() {
    // The upstream answers UDP with TC — the gate performs the retry
    // itself so a UDP-only client still gets the full answer.
    let mut table = HashMap::new();
    table.insert(
        "big.allowed.example".to_string(),
        MockAnswer {
            rcode: 0,
            tc_on_udp: true,
            answers: vec![Answ::A {
                owner: "big.allowed.example".into(),
                ip: Ipv4Addr::new(192, 0, 2, 99),
                ttl: 10,
            }],
            silent: false,
            corrupt_id: false,
        },
    );
    let gate = start_gate(
        policy_with(outbound(&["*.allowed.example"], &[], &[], &[], true)),
        table,
        Refusal::Refused,
        None,
        false,
    )
    .await;
    let resp = udp_query(gate.listen, &dns_query(1, "big.allowed.example", 1))
        .await
        .expect("full answer after TCP retry");
    assert_eq!(resp[2] & 0x02, 0, "relay answer is not truncated");
    assert_eq!(answer_a_records(&resp), vec![Ipv4Addr::new(192, 0, 2, 99)]);
    stop_gate(gate).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn upstream_timeout_is_servfail() {
    let mut table = HashMap::new();
    table.insert(
        "slow.allowed.example".to_string(),
        MockAnswer {
            rcode: 0,
            tc_on_udp: false,
            answers: Vec::new(),
            silent: true, // upstream never answers
            corrupt_id: false,
        },
    );
    let gate = start_gate(
        policy_with(outbound(&["*.allowed.example"], &[], &[], &[], true)),
        table,
        Refusal::Refused,
        None,
        false,
    )
    .await;
    let resp = udp_query(gate.listen, &dns_query(1, "slow.allowed.example", 1))
        .await
        .expect("servfail");
    assert_eq!(rcode(&resp), 2, "upstream timeout → SERVFAIL");
    let lines = stop_gate(gate).await;
    let resolved = details_for(&lines, "sandbox.network_resolved");
    assert!(
        resolved
            .iter()
            .any(|r| r.contains("result=upstream-timeout")),
        "timeout must be audited: {resolved:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn malformed_query_is_formerr() {
    let gate = start_gate(
        policy_with(outbound(&["*"], &[], &[], &[], false)),
        HashMap::new(),
        Refusal::Refused,
        None,
        false,
    )
    .await;
    // Opcode IQUERY (1) — not a standard query → NOTIMP.
    let mut pkt = dns_query(1, "x.example", 1);
    pkt[2] = 0x08 | (pkt[2] & 0x01); // opcode 1, keep RD
    let resp = udp_query(gate.listen, &pkt).await.expect("notimp");
    assert_eq!(rcode(&resp), 4);
    // qdcount 0 → FORMERR.
    let mut pkt = dns_query(2, "x.example", 1);
    pkt[5] = 0;
    let resp = udp_query(gate.listen, &pkt).await.expect("formerr");
    assert_eq!(rcode(&resp), 1);
    // A packet too short to even parse is dropped (no answer).
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    sock.connect(gate.listen).await.unwrap();
    sock.send(&[0u8; 5]).await.unwrap();
    let mut buf = [0u8; 128];
    let res = timeout(Duration::from_millis(500), sock.recv(&mut buf)).await;
    assert!(res.is_err(), "sub-header packet must be dropped");
    stop_gate(gate).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn fail_closed_audit_unavailable_refuses_allowed() {
    // With fail_closed audit, a dead writer turns an *allowed* query
    // into SERVFAIL — resolution must not proceed unaudited.
    let mut table = HashMap::new();
    table.insert(
        "allowed.example".to_string(),
        MockAnswer {
            rcode: 0,
            tc_on_udp: false,
            answers: vec![Answ::A {
                owner: "allowed.example".into(),
                ip: Ipv4Addr::new(93, 184, 216, 34),
                ttl: 60,
            }],
            silent: false,
            corrupt_id: false,
        },
    );
    let gate = start_gate(
        policy_with(outbound(&["allowed.example"], &[], &[], &[], true)),
        table,
        Refusal::Refused,
        None,
        true, // fail_closed
    )
    .await;
    // Kill the sink: shutting the logger down makes the channel
    // unavailable; the next allowed query must fail closed.
    gate.logger.shutdown().await;
    let resp = udp_query(gate.listen, &dns_query(1, "allowed.example", 1))
        .await
        .expect("servfail on dead audit sink");
    assert_eq!(
        rcode(&resp),
        2,
        "audit-unavailable → SERVFAIL, never resolve unaudited"
    );
    // Denied queries still refuse — the denial does not depend on the sink.
    let resp = udp_query(gate.listen, &dns_query(2, "denied.example", 1))
        .await
        .expect("refusal on dead audit sink");
    assert_eq!(rcode(&resp), 5);
    let _ = gate.shutdown.send(());
    let _ = timeout(TEST_TIMEOUT, gate.task).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ip_literal_query_evaluates_cidr_rules() {
    //  constrains IP-literal query names; a denied CIDR
    // refuses the literal even when the name isn't a host rule.
    let mut table = HashMap::new();
    table.insert(
        "10.1.2.3".to_string(),
        MockAnswer {
            rcode: 0,
            tc_on_udp: false,
            answers: vec![Answ::A {
                owner: "10.1.2.3".into(),
                ip: Ipv4Addr::new(10, 1, 2, 3),
                ttl: 30,
            }],
            silent: false,
            corrupt_id: false,
        },
    );
    let gate = start_gate(
        policy_with(outbound(&[], &[], &["10.0.0.0/8"], &["10.9.0.0/16"], true)),
        table,
        Refusal::Refused,
        None,
        false,
    )
    .await;
    let resp = udp_query(gate.listen, &dns_query(1, "10.1.2.3", 1))
        .await
        .unwrap();
    assert_eq!(rcode(&resp), 0, "allowed cidr covers the literal");
    let resp = udp_query(gate.listen, &dns_query(2, "10.9.1.1", 1))
        .await
        .unwrap();
    assert_eq!(rcode(&resp), 5, "denied cidr refuses the literal");
    let resp = udp_query(gate.listen, &dns_query(3, "172.16.0.1", 1))
        .await
        .unwrap();
    assert_eq!(rcode(&resp), 5, "uncovered literal refused under deny-all");
    let lines = stop_gate(gate).await;
    let denied = details_for(&lines, "sandbox.network_denied");
    assert!(
        denied
            .iter()
            .any(|d| d.contains("decision=deny-cidr") && d.contains("rule=10.9.0.0/16")),
        "cidr deny must name the rule: {denied:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn allowlist_export_writes_snapshot() {
    let mut table = HashMap::new();
    table.insert(
        "allowed.example".to_string(),
        MockAnswer {
            rcode: 0,
            tc_on_udp: false,
            answers: vec![Answ::A {
                owner: "allowed.example".into(),
                ip: Ipv4Addr::new(93, 184, 216, 34),
                ttl: 60,
            }],
            silent: false,
            corrupt_id: false,
        },
    );
    let tmp = tempfile::tempdir().unwrap();
    let export_path = tmp.path().join("allowlist.json");
    let gate = start_gate(
        policy_with(outbound(&["allowed.example"], &[], &[], &[], true)),
        table,
        Refusal::Refused,
        Some(export_path.clone()),
        false,
    )
    .await;
    let resp = udp_query(gate.listen, &dns_query(1, "allowed.example", 1))
        .await
        .unwrap();
    assert_eq!(rcode(&resp), 0);
    // The export lands after the registration batch — poll briefly.
    let mut snapshot = String::new();
    for _ in 0..50 {
        if export_path.exists() {
            snapshot = std::fs::read_to_string(&export_path).unwrap();
            if !snapshot.is_empty() {
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let json = nojson::RawJson::parse(&snapshot).expect("export is valid JSON");
    let entries: Vec<_> = json
        .value()
        .to_member("entries")
        .unwrap()
        .required()
        .unwrap()
        .to_array()
        .unwrap()
        .collect();
    assert_eq!(entries.len(), 1);
    assert_eq!(
        entries[0]
            .to_member("name")
            .unwrap()
            .required()
            .unwrap()
            .to_unquoted_string_str()
            .unwrap(),
        "allowed.example"
    );
    assert_eq!(
        entries[0]
            .to_member("addr")
            .unwrap()
            .required()
            .unwrap()
            .to_unquoted_string_str()
            .unwrap(),
        "93.184.216.34"
    );
    stop_gate(gate).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn deny_all_empty_allow_list_refuses_all_names() {
    // `deny_all_others` with no allow rules — `deny host="*"` alone, an
    // empty `network` block, or a policy with no `network` block at all
    // (all three load to this shape). The gate is the terminal
    // name-layer enforcement point: the Auditor's empty-allow
    // fall-through relies on the OS sandbox behind it, and there is
    // nothing behind the gate — that carve-out would leave an open
    // resolver.
    let gate = start_gate(
        policy_with(outbound(&[], &[], &[], &[], true)),
        HashMap::new(),
        Refusal::Refused,
        None,
        false,
    )
    .await;
    let resp = udp_query(gate.listen, &dns_query(1, "anything.example", 1))
        .await
        .expect("deny-all refusal");
    assert_eq!(rcode(&resp), 5, "deny-all + empty allow must refuse");
    let resp = udp_query(gate.listen, &dns_query(2, "192.0.2.1", 1))
        .await
        .expect("deny-all refusal");
    assert_eq!(rcode(&resp), 5, "IP literal under deny-all must refuse");
    let lines = stop_gate(gate).await;
    let denied = details_for(&lines, "sandbox.network_denied");
    assert!(
        denied
            .iter()
            .any(|d| d.contains("name=anything.example") && d.contains("decision=not-allowed")),
        "deny-all-empty must audit not-allowed: {denied:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn open_posture_resolves_unlisted_names() {
    // `allow host="*"` (deny_all_others = false) is the only open
    // posture — names with no covering rule still forward upstream.
    let mut table = HashMap::new();
    table.insert(
        "free.example".to_string(),
        MockAnswer {
            rcode: 0,
            tc_on_udp: false,
            answers: vec![Answ::A {
                owner: "free.example".into(),
                ip: Ipv4Addr::new(192, 0, 2, 55),
                ttl: 60,
            }],
            silent: false,
            corrupt_id: false,
        },
    );
    let gate = start_gate(
        policy_with(outbound(&[], &[], &[], &[], false)),
        table,
        Refusal::Refused,
        None,
        false,
    )
    .await;
    let resp = udp_query(gate.listen, &dns_query(1, "free.example", 1))
        .await
        .expect("open-posture answer");
    assert_eq!(rcode(&resp), 0, "open posture forwards unlisted names");
    assert_eq!(answer_a_records(&resp), vec![Ipv4Addr::new(192, 0, 2, 55)]);
    stop_gate(gate).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn upstream_mismatch_is_servfail() {
    // An upstream TCP answer that does not echo our query (here a
    // wrong ID) is not ours to relay — SERVFAIL, and the audit record
    // names the mismatch. (Over UDP a mismatched datagram is dropped
    // and the wait continues, so the wire-visible outcome there is the
    // fixed timeout budget, not an immediate mismatch.)
    let mut table = HashMap::new();
    table.insert(
        "mismatch.allowed.example".to_string(),
        MockAnswer {
            rcode: 0,
            tc_on_udp: false,
            answers: vec![Answ::A {
                owner: "mismatch.allowed.example".into(),
                ip: Ipv4Addr::new(192, 0, 2, 77),
                ttl: 60,
            }],
            silent: false,
            corrupt_id: true,
        },
    );
    let gate = start_gate(
        policy_with(outbound(&["*.allowed.example"], &[], &[], &[], true)),
        table,
        Refusal::Refused,
        None,
        false,
    )
    .await;
    let resp = tcp_query(gate.listen, &dns_query(1, "mismatch.allowed.example", 1))
        .await
        .expect("servfail on mismatched upstream");
    assert_eq!(rcode(&resp), 2, "upstream mismatch → SERVFAIL");
    let lines = stop_gate(gate).await;
    let resolved = details_for(&lines, "sandbox.network_resolved");
    assert!(
        resolved
            .iter()
            .any(|r| r.contains("result=upstream-mismatch")),
        "mismatch must be audited: {resolved:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tcp_connection_capacity_refuses_overflow() {
    // MAX_TCP_CONNECTIONS (64) bounds simultaneous client connections —
    // a connection accepted past capacity is dropped immediately, not
    // served, and the gate itself keeps answering over UDP.
    let gate = start_gate(
        policy_with(outbound(&["*"], &[], &[], &[], false)),
        HashMap::new(),
        Refusal::Refused,
        None,
        false,
    )
    .await;
    let mut held = Vec::new();
    for _ in 0..64 {
        held.push(
            TcpStream::connect(gate.listen)
                .await
                .expect("connection within capacity"),
        );
    }
    // Let the accept loop drain the backlog so every held connection
    // actually occupies its slot before the overflow attempt.
    tokio::time::sleep(Duration::from_millis(500)).await;
    let mut extra = TcpStream::connect(gate.listen)
        .await
        .expect("overflow connection still completes the handshake");
    let pkt = dns_query(1, "x.example", 1);
    extra
        .write_all(&(pkt.len() as u16).to_be_bytes())
        .await
        .ok();
    extra.write_all(&pkt).await.ok();
    let mut len_buf = [0u8; 2];
    match timeout(TEST_TIMEOUT, extra.read_exact(&mut len_buf)).await {
        // Dropped by the gate — EOF on unix-y stacks, an abort/reset
        // error on Windows; either way it was not served.
        Ok(Err(e)) => assert!(
            matches!(
                e.kind(),
                std::io::ErrorKind::UnexpectedEof
                    | std::io::ErrorKind::ConnectionAborted
                    | std::io::ErrorKind::ConnectionReset
            ),
            "overflow connection must be dropped, got {e}"
        ),
        Ok(Ok(n)) => panic!("overflow connection must not be served (read {n} bytes)"),
        Err(_) => panic!("overflow connection must close promptly, not hang"),
    }
    // The gate is not wedged — an unrelated UDP query still resolves
    // (empty mock table → upstream NXDOMAIN relayed).
    let resp = udp_query(gate.listen, &dns_query(2, "x.example", 1))
        .await
        .expect("gate still answers over UDP");
    assert_eq!(rcode(&resp), 3, "upstream NXDOMAIN relayed — gate alive");
    drop(held);
    stop_gate(gate).await;
}
