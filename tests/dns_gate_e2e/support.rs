//! Shared harness for the dns_gate e2e suite: wire codec helpers,
//! the scripted mock upstream, the gate spawn/stop driver, and the
//! raw UDP/TCP client helpers used by every submodule.

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

use crate::common;

pub const TEST_TIMEOUT: Duration = Duration::from_secs(10);

// ─── Wire helpers (test-local; the crate's codec is crate-internal) ──

pub fn name_wire(name: &str) -> Vec<u8> {
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

pub fn dns_query(id: u16, name: &str, qtype: u16) -> Vec<u8> {
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
pub fn decode_name_uncompressed(buf: &[u8], off: usize) -> Option<(String, usize)> {
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

pub fn question_end(buf: &[u8]) -> usize {
    let (_name, end) = decode_name_uncompressed(buf, 12).expect("question name");
    end + 4
}

pub fn rcode(resp: &[u8]) -> u8 {
    resp[3] & 0x0F
}

pub fn ancount(resp: &[u8]) -> u16 {
    u16::from_be_bytes([resp[6], resp[7]])
}

/// IPv4 addresses from answer-section A records (walks compression
/// pointers — upstream answers may compress owners).
pub fn answer_a_records(resp: &[u8]) -> Vec<Ipv4Addr> {
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

pub enum Answ {
    Cname {
        owner: String,
        target: String,
        ttl: u32,
    },
    Dname {
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

pub struct MockAnswer {
    pub rcode: u8,
    /// Respond truncated over UDP (drives the gate's own TCP retry).
    pub tc_on_udp: bool,
    pub answers: Vec<Answ>,
    /// Never answer — drives the upstream-timeout path.
    pub silent: bool,
    /// Echo a wrong query ID — drives the upstream-mismatch path.
    pub corrupt_id: bool,
}

pub fn push_rr(out: &mut Vec<u8>, owner: &str, rtype: u16, ttl: u32, rdata: &[u8]) {
    out.extend_from_slice(&name_wire(owner));
    out.extend_from_slice(&rtype.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes()); // IN
    out.extend_from_slice(&ttl.to_be_bytes());
    out.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
    out.extend_from_slice(rdata);
}

pub fn mock_response(req: &[u8], spec: &MockAnswer, tcp: bool) -> Vec<u8> {
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
            Answ::Dname { owner, target, ttl } => {
                push_rr(&mut out, owner, 39, *ttl, &name_wire(target));
            }
            Answ::A { owner, ip, ttl } => {
                push_rr(&mut out, owner, 1, *ttl, &ip.octets());
            }
        }
    }
    out
}

pub fn answer_for(table: &HashMap<String, MockAnswer>, req: &[u8], tcp: bool) -> Option<Vec<u8>> {
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

pub struct MockUpstream {
    pub addr: SocketAddr,
    pub _udp: JoinHandle<()>,
    pub _tcp: JoinHandle<()>,
}

pub async fn spawn_mock_upstream(table: HashMap<String, MockAnswer>) -> MockUpstream {
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

pub struct GateHandle {
    pub listen: SocketAddr,
    pub allowlist: Arc<DynamicAllowList>,
    pub shutdown: oneshot::Sender<()>,
    pub task: JoinHandle<std::io::Result<()>>,
    pub logger: AuditLogger,
    pub audit_path: PathBuf,
    pub _tmp: tempfile::TempDir,
    pub _upstream: MockUpstream,
}

pub fn outbound(
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

pub fn policy_with(outbound: OutboundPolicy) -> Policy {
    let mut p = Policy::default();
    p.network.outbound = outbound;
    p
}

/// Bind an ephemeral loopback port for the gate's listeners (the port
/// is released before the gate binds — the standard ephemeral-probe
/// trick; on loopback the race window is harmless for a test).
pub async fn free_port() -> u16 {
    let probe = TcpListener::bind("127.0.0.1:0").await.unwrap();
    probe.local_addr().unwrap().port()
}

pub async fn start_gate(
    policy: Policy,
    upstream_table: HashMap<String, MockAnswer>,
    refusal: Refusal,
    allowlist_export: Option<PathBuf>,
    fail_closed: bool,
) -> Option<GateHandle> {
    let upstream = spawn_mock_upstream(upstream_table).await;

    // The in-process audit sink refuses replaceable ancestors — a
    // shared %TEMP% root whose ACL grants another principal replace
    // access fails the strict walk outright, so root the sink under a
    // write-restricted base. `None` when the host has none (callers
    // take the e2e skip path).
    let tmp = common::restricted_tempdir()?;
    let audit_path = tmp.path().canonicalize().unwrap().join("audit.jsonl");
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

    Some(GateHandle {
        listen,
        allowlist,
        shutdown: tx,
        task,
        logger,
        audit_path,
        _tmp: tmp,
        _upstream: upstream,
    })
}

/// Probe that the gate's UDP socket is bound — a 12-byte header with
/// qdcount=0 is malformed but answerable (FORMERR), so any response
/// proves the listener is serving.
pub async fn udp_probe(listen: SocketAddr) -> bool {
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

pub async fn stop_gate(gate: GateHandle) -> Vec<String> {
    let _ = gate.shutdown.send(());
    let res = timeout(TEST_TIMEOUT, gate.task).await.unwrap();
    res.unwrap().unwrap();
    let _ = gate.logger.shutdown().await;
    std::fs::read_to_string(&gate.audit_path)
        .unwrap_or_default()
        .lines()
        .map(|l| l.to_string())
        .collect()
}

/// Event details for every emitted record of .
pub fn details_for(lines: &[String], event_type: &str) -> Vec<String> {
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

pub async fn udp_query(listen: SocketAddr, pkt: &[u8]) -> Option<Vec<u8>> {
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

pub async fn tcp_query(listen: SocketAddr, pkt: &[u8]) -> Option<Vec<u8>> {
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
