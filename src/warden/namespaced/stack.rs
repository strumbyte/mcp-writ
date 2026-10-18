//! The namespaced egress proxy: TUN fd → packet classifier →
//! per-protocol enforcement → host sockets.
//!
//! Task topology (all in-process, one tokio runtime):
//!
//! ```text
//!   workload ──tun──▶ reader ──TCP──▶ DNAT ──▶ smoltcp stack ──▶ splice
//!                    task              │         task              task
//!                       │               │     (accept/eval)      (real
//!                       ├──UDP:53──▶ gate task  (dnsgate::QueryCore)  sockets)
//!                       ├──UDP ───▶ udp task   (per-datagram eval)
//!                       └──other──▶ drop counter (fail-closed)
//!
//!   splice/gate/udp replies ──▶ writer task ──tun──▶ workload
//! ```
//!
//! The TUN fd itself is the boundary: if this task tree dies the fd
//! closes and the workload's packets have nowhere to go — proxy loss
//! is fail-closed by construction.
//!
//! Deliberate drops (documented in `report::LIMITATIONS`): IP
//! fragments (no reassembly — UDP cannot be per-datagram checked
//! without ports; TCP keeps working because smoltcp's own
//! fragmentation feature is off and the TUN MTU is 1500), IPv6
//! extension-header chains (the classifier reads a bare next-header
//! only — anything it cannot inspect stays dropped, fail-closed),
//! ICMPv4/v6 and other non-TCP/UDP protocols, and frames that are
//! neither IP version.

use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::os::unix::io::AsRawFd;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use smoltcp::iface::{Config as IfaceConfig, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium};
use smoltcp::socket::tcp::{Socket as TcpSock, SocketBuffer, State as TcpState};
use smoltcp::time::Instant as SmolInstant;
use smoltcp::wire::{HardwareAddress, IpCidr, IpListenEndpoint};

use tokio::io::unix::AsyncFd;
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::mpsc;

use crate::dnsgate::allowlist::DynamicAllowList;
use crate::dnsgate::server::QueryCore;
use crate::policy::EgressProto;
use crate::warden::flow_gate::FlowGate;
use crate::warden::unotify::IpVerdict;

use super::nat::NatTable;

/// Cap on buffered-but-undrained frames between reader and stack.
const TCP_RX_CHANNEL: usize = 256;
/// Bound on workload-bound frames queued for the TUN writer — a full
/// queue drops the packet (TCP retransmits; UDP/DNS loss is normal
/// semantics) rather than letting reply traffic grow memory without
/// limit against a slow or stalled workload-side drain.
const TUN_TX_CHANNEL: usize = 512;
/// Bound on classified UDP datagrams waiting for the relay task —
/// excess is dropped at the reader, matching UDP loss semantics.
const UDP_RX_CHANNEL: usize = 256;
/// Bound on intercepted DNS queries waiting for the gate task —
/// excess is dropped; the workload's resolver retries or times out.
const GATE_RX_CHANNEL: usize = 256;
/// Pre-listened sockets per listener — one becomes the connection.
const LISTEN_POOL: usize = 8;
/// Per-connection socket buffers.
const SOCK_BUF: usize = 16 * 1024;
/// Channel bound for workload→backend bytes; socket-level backpressure
/// engages when it fills.
const BACKEND_CHANNEL: usize = 64;
/// Channel bound for backend→stack events — backends pause their reads
/// when it fills, bounding `pending` growth per live connection.
const EVENTS_CHANNEL: usize = 256;
/// Per-connection ceiling on backend→workload bytes sitting in
/// `Conn::pending` — a conn at the cap stops its backend reads until
/// the stack drains the backlog, so one slow consumer cannot grow
/// queue memory against the shared channel bound alone.
const CONN_PENDING_CAP: usize = 4 * SOCK_BUF;
/// Concurrent upstream-bound DNS answers the gate task may run.
const GATE_INFLIGHT: usize = 64;
/// Live UDP flow ceiling — excess flows evict oldest.
const UDP_FLOW_CAP: usize = 256;
/// Global cap on admitted TCP data flows. Every accepted flow owns a
/// socket pair, a backend task, channels, and a NAT mapping — all
/// workload-paceable, so a connect flood must hit a hard refusal
/// (RST) rather than grow the connection map unboundedly.
const MAX_TCP_FLOWS: usize = 1024;
/// Stricter sub-limit for DNS-over-TCP intercept flows — they are
/// answered by the embedded gate, so their legitimate concurrency is
/// far below bulk TCP.
const MAX_DNS_TCP_FLOWS: usize = 64;
/// UDP flow idle reaper.
const UDP_IDLE: std::time::Duration = std::time::Duration::from_secs(60);
/// UDP audit emission budget — `UDP_AUDIT_BURST` events per window;
/// anything beyond it is counted in `udp_audit_suppressed`, never
/// queued, so a datagram flood cannot become a sink flood.
const UDP_AUDIT_BURST: usize = 32;
const UDP_AUDIT_WINDOW: std::time::Duration = std::time::Duration::from_secs(1);
/// A denied datagram with no flow repeats one audit subject — collapse
/// repeats per destination inside this window; the map is bounded and
/// evicts its oldest entry at the cap.
const UDP_DENY_AUDIT_WINDOW: std::time::Duration = std::time::Duration::from_secs(60);
const UDP_DENY_AUDIT_CAP: usize = 1024;

/// Inputs the command layer assembles once policy + audit exist.
pub struct ProxyConfig {
    pub tun: std::fs::File,
    pub evaluator: crate::warden::unotify::IpLayerEvaluator,
    pub allowlist: Arc<DynamicAllowList>,
    pub gate: Option<Arc<QueryCore>>,
    pub logger: crate::audit_log::AuditLogger,
    pub launch_id: uuid::Uuid,
    pub policy_ctx: Option<crate::audit_log::PolicyAuditContext>,
}

/// Report counters — `AtomicU64` because reader/writer tasks share
/// them with the stack task.
#[derive(Default, Clone)]
pub struct ProxyStats {
    pub tcp_accepted: Arc<AtomicU64>,
    pub tcp_denied: Arc<AtomicU64>,
    /// Flows refused at the global TCP/DNS-over-TCP admission caps —
    /// counted separately from policy denials so saturation is visible
    /// in the launch report.
    pub tcp_saturated: Arc<AtomicU64>,
    pub udp_flows: Arc<AtomicU64>,
    pub udp_datagrams: Arc<AtomicU64>,
    pub udp_denied: Arc<AtomicU64>,
    /// Audit events the UDP path suppressed under its emission budget
    /// — the datagrams themselves are still counted in
    /// `udp_datagrams`/`udp_denied`; this keeps the suppression honest.
    pub udp_audit_suppressed: Arc<AtomicU64>,
    pub dns_queries: Arc<AtomicU64>,
    pub dropped_packets: Arc<AtomicU64>,
    /// Frames whose version nibble is neither IPv4 nor IPv6.
    pub dropped_non_v4: Arc<AtomicU64>,
    /// IPv6 frames the classifier cannot inspect — extension-header
    /// chains, ICMPv6, and non-TCP/UDP next-headers (fragments count
    /// under `dropped_fragment`).
    pub dropped_v6_ext: Arc<AtomicU64>,
    pub dropped_fragment: Arc<AtomicU64>,
    pub dropped_proto: Arc<AtomicU64>,
    pub bytes_to_workload: Arc<AtomicU64>,
    pub bytes_from_workload: Arc<AtomicU64>,
}

impl ProxyStats {
    /// Plain-value snapshot for the launch report's mechanism record —
    /// reads each shared counter once at finalize time.
    pub fn snapshot(&self) -> crate::execution::NamespacedProxyStats {
        let get = |a: &Arc<AtomicU64>| a.load(Ordering::Relaxed);
        crate::execution::NamespacedProxyStats {
            tcp_accepted: get(&self.tcp_accepted),
            tcp_denied: get(&self.tcp_denied),
            tcp_saturated: get(&self.tcp_saturated),
            udp_flows: get(&self.udp_flows),
            udp_datagrams: get(&self.udp_datagrams),
            udp_denied: get(&self.udp_denied),
            udp_audit_suppressed: get(&self.udp_audit_suppressed),
            dns_queries: get(&self.dns_queries),
            dropped_packets: get(&self.dropped_packets),
            dropped_non_v4: get(&self.dropped_non_v4),
            dropped_v6_ext: get(&self.dropped_v6_ext),
            dropped_fragment: get(&self.dropped_fragment),
            dropped_proto: get(&self.dropped_proto),
            bytes_to_workload: get(&self.bytes_to_workload),
            bytes_from_workload: get(&self.bytes_from_workload),
        }
    }
}

// ---------------------------------------------------------------------------
// smoltcp device: inbound frames arrive pre-DNAT'd via `rx`; outbound
// frames leave via `tx` after reverse-NAT.
// ---------------------------------------------------------------------------

struct TunDev {
    rx: VecDeque<Vec<u8>>,
    tx: mpsc::Sender<Vec<u8>>,
    nat: std::sync::Arc<std::sync::Mutex<NatTable>>,
    stats: ProxyStats,
}

struct TunRx {
    frame: Vec<u8>,
}
struct TunTx {
    tx: mpsc::Sender<Vec<u8>>,
    nat: std::sync::Arc<std::sync::Mutex<NatTable>>,
    stats: ProxyStats,
}

impl smoltcp::phy::RxToken for TunRx {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.frame)
    }
}

impl smoltcp::phy::TxToken for TunTx {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buf = vec![0u8; len];
        let r = f(&mut buf);
        if self.nat.lock().unwrap().rev_nat_out(&mut buf) && self.tx.try_send(buf).is_err() {
            // A full writer queue drops instead of growing — TCP
            // retransmits and UDP/DNS loss is ordinary semantics.
            self.stats.dropped_packets.fetch_add(1, Ordering::Relaxed);
        }
        // Untracked outbound frames (e.g. a stray RST) are dropped —
        // the workload never sees a peer it did not dial.
        r
    }
}

impl Device for TunDev {
    type RxToken<'a>
        = TunRx
    where
        Self: 'a;
    type TxToken<'a>
        = TunTx
    where
        Self: 'a;

    fn receive(&mut self, _ts: SmolInstant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let frame = self.rx.pop_front()?;
        Some((
            TunRx { frame },
            TunTx {
                tx: self.tx.clone(),
                nat: self.nat.clone(),
                stats: self.stats.clone(),
            },
        ))
    }

    fn transmit(&mut self, _ts: SmolInstant) -> Option<Self::TxToken<'_>> {
        Some(TunTx {
            tx: self.tx.clone(),
            nat: self.nat.clone(),
            stats: self.stats.clone(),
        })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = 1500;
        caps.max_burst_size = Some(1);
        caps
    }
}

// ---------------------------------------------------------------------------
// Connection bookkeeping — one accepted smoltcp socket per flow, with
// a backend task moving bytes between the socket and the real world.
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
struct ConnKey {
    ip: IpAddr,
    port: u16,
}

enum ConnEvent {
    /// Backend produced bytes for the workload.
    Data { key: ConnKey, bytes: Vec<u8> },
    /// Backend is done — FIN the workload once pending sends drain.
    Eof { key: ConnKey },
    /// Backend failed (connect refused, io error) — RST the flow.
    Fail { key: ConnKey },
}

enum ToBackend {
    Data(Vec<u8>),
    /// Workload sent FIN — backend should half-close its write side.
    Fin,
}

/// Per-connection backend→workload backlog accounting. The backend
/// task adds bytes as it forwards them, the stack subtracts as
/// `send_slice` moves them into the smoltcp socket, and `drained`
/// wakes the backend once it may resume reading.
struct FlowCredit {
    bytes: std::sync::atomic::AtomicUsize,
    drained: tokio::sync::Notify,
}

struct Conn {
    handle: SocketHandle,
    to_backend: mpsc::Sender<ToBackend>,
    /// Backend→workload bytes not yet pushed into the socket.
    pending: VecDeque<Vec<u8>>,
    credit: Arc<FlowCredit>,
    backend_eof: bool,
    fin_sent_to_backend: bool,
    /// DNS-over-TCP intercept flow — counted against the stricter
    /// `MAX_DNS_TCP_FLOWS` sub-limit rather than the data-flow cap.
    dns_tcp: bool,
}

// ---------------------------------------------------------------------------
// Packet classification (reader task)
// ---------------------------------------------------------------------------

struct UdpDgram {
    src: IpAddr,
    src_port: u16,
    dst: IpAddr,
    dst_port: u16,
    payload: Vec<u8>,
}

enum GateCtx {
    /// UDP DNS: reply packet is crafted dst→src, same family as the
    /// query arrived on.
    Udp {
        src: IpAddr,
        src_port: u16,
        dst: IpAddr,
        dst_port: u16,
    },
}

struct GateReq {
    pkt: Vec<u8>,
    peer: SocketAddr,
    ctx: GateCtx,
}

enum Classified {
    Tcp(Vec<u8>),
    UdpDns(GateReq),
    Udp(UdpDgram),
    /// Frame whose version nibble is neither IPv4 nor IPv6.
    DropNonIp,
    /// IPv6 frame whose next-header is not bare TCP/UDP — extension
    /// chains (hop-by-hop, routing, destination options, AH/ESP),
    /// ICMPv6, and unknown protocols all land here: uninspectable v6
    /// elements stay default-dropped (fragments carry their own
    /// counter below).
    DropV6Ext,
    DropFragment,
    DropProto,
    DropMalformed,
}

/// `dns_intercept` is the gate's existence: with no configured
/// upstream there is no gate task to answer `UdpDns` work, so port-53
/// datagrams must take the ordinary per-datagram evaluator path —
/// classifying them as gate work would dead-letter them into a
/// channel nobody drains (no verdict, no audit record, silent loss).
fn classify(frame: &[u8], dns_intercept: bool) -> Classified {
    if frame.len() < 20 {
        return Classified::DropMalformed;
    }
    if frame[0] >> 4 == 6 {
        return classify_v6(frame, dns_intercept);
    }
    if frame[0] >> 4 != 4 {
        return Classified::DropNonIp;
    }
    let ihl = usize::from(frame[0] & 0x0f) * 4;
    let total = u16::from_be_bytes([frame[2], frame[3]]) as usize;
    if ihl < 20 || total < ihl || frame.len() < total {
        return Classified::DropMalformed;
    }
    // IP fragments are dropped entirely — see module docs.
    let frag = u16::from_be_bytes([frame[6], frame[7]]);
    if frag & 0x3fff != 0 {
        return Classified::DropFragment;
    }
    match frame[9] {
        6 => {
            if total < ihl + 20 {
                return Classified::DropMalformed;
            }
            Classified::Tcp(frame[..total].to_vec())
        }
        17 => {
            if total < ihl + 8 {
                return Classified::DropMalformed;
            }
            let sp = u16::from_be_bytes([frame[ihl], frame[ihl + 1]]);
            let dp = u16::from_be_bytes([frame[ihl + 2], frame[ihl + 3]]);
            let ulen = u16::from_be_bytes([frame[ihl + 4], frame[ihl + 5]]) as usize;
            if ulen < 8 || ihl + ulen > total {
                return Classified::DropMalformed;
            }
            let src = Ipv4Addr::new(frame[12], frame[13], frame[14], frame[15]);
            let dst = Ipv4Addr::new(frame[16], frame[17], frame[18], frame[19]);
            let payload = frame[ihl + 8..ihl + ulen].to_vec();
            classify_udp(src.into(), dst.into(), sp, dp, payload, dns_intercept)
        }
        _ => Classified::DropProto,
    }
}

/// IPv6 twin of [`classify`]: the fixed 40-byte header carries a bare
/// `next_header` field — only TCP (6) and UDP (17) are relayed, and
/// only as extension-free packets. A next-header naming an extension
/// type (hop-by-hop 0, routing 43, destination options 60, AH/ESP…),
/// the fragment header (44), ICMPv6 (58), or anything else cannot be
/// evaluated at the transport layer and is dropped — the same
/// fail-closed boundary the v4 fragment/proto drops draw.
fn classify_v6(frame: &[u8], dns_intercept: bool) -> Classified {
    if frame.len() < 40 {
        return Classified::DropMalformed;
    }
    let payload_len = u16::from_be_bytes([frame[4], frame[5]]) as usize;
    if frame.len() < 40 + payload_len {
        return Classified::DropMalformed;
    }
    match frame[6] {
        6 => {
            if payload_len < 20 {
                return Classified::DropMalformed;
            }
            Classified::Tcp(frame[..40 + payload_len].to_vec())
        }
        17 => {
            if payload_len < 8 {
                return Classified::DropMalformed;
            }
            let sp = u16::from_be_bytes([frame[40], frame[41]]);
            let dp = u16::from_be_bytes([frame[42], frame[43]]);
            let ulen = u16::from_be_bytes([frame[44], frame[45]]) as usize;
            if ulen < 8 || ulen > payload_len {
                return Classified::DropMalformed;
            }
            let src = std::net::Ipv6Addr::from(<[u8; 16]>::try_from(&frame[8..24]).unwrap());
            let dst = std::net::Ipv6Addr::from(<[u8; 16]>::try_from(&frame[24..40]).unwrap());
            let payload = frame[48..40 + ulen].to_vec();
            classify_udp(src.into(), dst.into(), sp, dp, payload, dns_intercept)
        }
        44 => Classified::DropFragment,
        _ => Classified::DropV6Ext,
    }
}

/// Shared UDP outcome for both families — the DNS intercept binds
/// the destination port regardless of family, so a query sent to
/// any v6 resolver spelling is answered by the same gate.
fn classify_udp(
    src: IpAddr,
    dst: IpAddr,
    sp: u16,
    dp: u16,
    payload: Vec<u8>,
    dns_intercept: bool,
) -> Classified {
    if dns_intercept && dp == 53 {
        // DNS intercept — regardless of the queried address
        // the embedded gate answers, so a raw-resolver bypass
        // cannot mint unlisted destinations.
        Classified::UdpDns(GateReq {
            pkt: payload,
            peer: SocketAddr::new(src, sp),
            ctx: GateCtx::Udp {
                src,
                src_port: sp,
                dst,
                dst_port: dp,
            },
        })
    } else {
        Classified::Udp(UdpDgram {
            src,
            src_port: sp,
            dst,
            dst_port: dp,
            payload,
        })
    }
}

/// Encapsulate a UDP reply into an IP packet of the addrs' family
/// (reply src = the original destination the workload addressed).
/// `src`/`dst` always share a family — replies are built from the
/// request's own tuple — so the version comes from `dst`.
fn craft_udp_packet(
    src: IpAddr,
    src_port: u16,
    dst: IpAddr,
    dst_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let udp_len = 8 + payload.len();
    match (src, dst) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => {
            let total = 20 + udp_len;
            let mut f = vec![0u8; total];
            f[0] = 0x45;
            f[2..4].copy_from_slice(&(total as u16).to_be_bytes());
            f[8] = 64;
            f[9] = 17;
            f[12..16].copy_from_slice(&src.octets());
            f[16..20].copy_from_slice(&dst.octets());
            // IPv4 header checksum.
            let mut acc = 0u32;
            for pair in f[..20].as_chunks::<2>().0 {
                acc += u16::from_be_bytes(*pair) as u32;
            }
            while acc >> 16 != 0 {
                acc = (acc & 0xffff) + (acc >> 16);
            }
            let ip_sum = !(acc as u16);
            f[10..12].copy_from_slice(&ip_sum.to_be_bytes());
            f[20..22].copy_from_slice(&src_port.to_be_bytes());
            f[22..24].copy_from_slice(&dst_port.to_be_bytes());
            f[24..26].copy_from_slice(&(udp_len as u16).to_be_bytes());
            f[28..].copy_from_slice(payload);
            let sum = udp_checksum(&f[12..20], &f[20..]);
            f[26..28].copy_from_slice(&sum.to_be_bytes());
            f
        }
        (IpAddr::V6(src), IpAddr::V6(dst)) => {
            let total = 40 + udp_len;
            let mut f = vec![0u8; total];
            f[0] = 0x60;
            f[4..6].copy_from_slice(&(udp_len as u16).to_be_bytes());
            f[6] = 17;
            f[7] = 64; // hop limit
            f[8..24].copy_from_slice(&src.octets());
            f[24..40].copy_from_slice(&dst.octets());
            f[40..42].copy_from_slice(&src_port.to_be_bytes());
            f[42..44].copy_from_slice(&dst_port.to_be_bytes());
            f[44..46].copy_from_slice(&(udp_len as u16).to_be_bytes());
            f[48..].copy_from_slice(payload);
            let sum = udp_checksum(&f[8..40], &f[40..]);
            f[46..48].copy_from_slice(&sum.to_be_bytes());
            f
        }
        // Unreachable by construction: reply tuples are built from one
        // classified packet, which is a single family.
        _ => Vec::new(),
    }
}

/// UDP checksum over the pseudo-header (the 8 or 32 address bytes)
/// plus the UDP datagram — mandatory on v6, computed on v4 too so
/// strict parsers see a real checksum.
fn udp_checksum(addr_bytes: &[u8], udp: &[u8]) -> u16 {
    let mut acc = 0u32;
    for pair in addr_bytes.as_chunks::<2>().0 {
        acc += u16::from_be_bytes(*pair) as u32;
    }
    acc += 17u32 + udp.len() as u32;
    let mut tail = udp.to_vec();
    if tail.len() % 2 == 1 {
        tail.push(0);
    }
    for pair in tail.as_chunks::<2>().0 {
        acc += u16::from_be_bytes(*pair) as u32;
    }
    while acc >> 16 != 0 {
        acc = (acc & 0xffff) + (acc >> 16);
    }
    let sum = !(acc as u16);
    if sum == 0 { 0xffff } else { sum }
}

// ---------------------------------------------------------------------------
// Backend tasks
// ---------------------------------------------------------------------------

/// Real-TCP splice: connect to the original destination, then relay
/// until either side closes.
async fn tcp_backend(
    key: ConnKey,
    orig: super::nat::OrigDst,
    events: mpsc::Sender<ConnEvent>,
    mut from_stack: mpsc::Receiver<ToBackend>,
    credit: Arc<FlowCredit>,
) {
    let target = SocketAddr::new(orig.addr, orig.port);
    let mut stream = match TcpStream::connect(target).await {
        Ok(s) => s,
        Err(e) => {
            tracing::debug!("namespaced tcp connect {target} failed: {e}");
            let _ = events.send(ConnEvent::Fail { key }).await;
            return;
        }
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut buf = vec![0u8; SOCK_BUF];
    loop {
        // Per-conn backlog cap: while this flow's unwritten queue sits
        // at the ceiling the backend stops reading — the TCP window
        // then throttles the remote instead of growing `pending`.
        // Each pass builds a fresh `Notified` (`enable()` before the
        // re-check avoids a missed wake); a `Notified` is one-shot, so
        // re-awaiting a spent one would spin instead of sleeping.
        loop {
            // A dropped conn drops its sender too — stop waiting.
            if from_stack.is_closed() {
                return;
            }
            if credit.bytes.load(Ordering::Acquire) < CONN_PENDING_CAP {
                break;
            }
            let wait = credit.drained.notified();
            tokio::pin!(wait);
            wait.as_mut().enable();
            if credit.bytes.load(Ordering::Acquire) < CONN_PENDING_CAP {
                break;
            }
            wait.await;
        }
        tokio::select! {
            read = stream.read(&mut buf) => {
                match read {
                    Ok(0) => {
                        let _ = events.send(ConnEvent::Eof { key }).await;
                        return;
                    }
                    Ok(n) => {
                        // Blocking on the bounded channel is the
                        // backpressure: a workload not draining stops
                        // our backend reads instead of growing pending.
                        credit.bytes.fetch_add(n, Ordering::Release);
                        if events.send(ConnEvent::Data {
                            key,
                            bytes: buf[..n].to_vec(),
                        }).await.is_err() {
                            return;
                        }
                    }
                    Err(_) => {
                        let _ = events.send(ConnEvent::Fail { key }).await;
                        return;
                    }
                }
            }
            msg = from_stack.recv() => match msg {
                Some(ToBackend::Data(b)) => {
                    if stream.write_all(&b).await.is_err() {
                        let _ = events.send(ConnEvent::Fail { key }).await;
                        return;
                    }
                }
                Some(ToBackend::Fin) => {
                    let _ = stream.shutdown().await;
                }
                None => {
                    // Stack dropped the channel — conn torn down.
                    return;
                }
            },
        }
    }
}

/// DNS-over-TCP intercept backend: RFC 7766 framing in, gate pipeline
/// out — no real socket exists behind this conn. Replies share the
/// conn's `FlowCredit` backlog cap with the splice backend, so a
/// workload that floods queries without reading answers stalls at
/// `from_stack` instead of growing `Conn::pending` unboundedly.
async fn dns_tcp_backend(
    key: ConnKey,
    gate: Arc<QueryCore>,
    peer: SocketAddr,
    events: mpsc::Sender<ConnEvent>,
    mut from_stack: mpsc::Receiver<ToBackend>,
    credit: Arc<FlowCredit>,
) {
    let mut buf: Vec<u8> = Vec::new();
    while let Some(msg) = from_stack.recv().await {
        match msg {
            ToBackend::Data(b) => buf.extend_from_slice(&b),
            ToBackend::Fin => {
                let _ = events.send(ConnEvent::Eof { key }).await;
                return;
            }
        }
        loop {
            if buf.len() < 2 {
                break;
            }
            let len = u16::from_be_bytes([buf[0], buf[1]]) as usize;
            if buf.len() < 2 + len {
                break;
            }
            let pkt: Vec<u8> = buf.drain(..2 + len).skip(2).collect();
            if let Some(resp) = gate.answer(&pkt, peer, true).await {
                credit.bytes.fetch_add(resp.len(), Ordering::Release);
                if events
                    .send(ConnEvent::Data { key, bytes: resp })
                    .await
                    .is_err()
                {
                    return;
                }
                // Same throttle as `tcp_backend`: while the conn's
                // unwritten queue sits at the ceiling, stop answering
                // further queries — the `from_stack` channel fills and
                // TCP backpressure, not `pending`, absorbs the flood.
                // Each pass builds a fresh `Notified` (`enable()` before
                // the re-check avoids a missed wake).
                loop {
                    // A dropped conn drops its sender too — stop waiting.
                    if from_stack.is_closed() {
                        return;
                    }
                    if credit.bytes.load(Ordering::Acquire) < CONN_PENDING_CAP {
                        break;
                    }
                    let wait = credit.drained.notified();
                    tokio::pin!(wait);
                    wait.as_mut().enable();
                    if credit.bytes.load(Ordering::Acquire) < CONN_PENDING_CAP {
                        break;
                    }
                    wait.await;
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// The proxy
// ---------------------------------------------------------------------------

/// Run the proxy until the workload child exits (or the caller aborts
/// the task). Returns the counters for the report.
/// Runs the proxy until the TUN fd goes away or the task is aborted.
/// `stats` is shared by `Arc` — the caller keeps a handle so an abort
/// still leaves every counter readable for the final report (waiting
/// for a return value would lose them).
pub async fn run_proxy(cfg: ProxyConfig, stats: ProxyStats) {
    let gate = FlowGate::new(
        cfg.evaluator,
        cfg.allowlist,
        cfg.logger,
        cfg.launch_id,
        cfg.policy_ctx,
    );
    let gate = Arc::new(gate);
    // Port-53 interception exists only while a gate does — with no
    // upstream there is nobody to answer `UdpDns` work or DNS-over-TCP
    // flows, so the classifier and NAT table must leave :53 on the
    // ordinary evaluator path (the selection layer already flagged
    // name-bound rules as unsatisfiable in that configuration).
    let dns_intercept = cfg.gate.is_some();

    // Channels — all bounded. A producer that outruns its consumer
    // drops at `try_send` (counted) instead of growing queue memory:
    // the workload only ever sees ordinary packet loss.
    let (to_stack_tx, to_stack_rx) = mpsc::channel::<Vec<u8>>(TCP_RX_CHANNEL);
    let (tun_tx, tun_rx) = mpsc::channel::<Vec<u8>>(TUN_TX_CHANNEL);
    let (events_tx, events_rx) = mpsc::channel::<ConnEvent>(EVENTS_CHANNEL);
    let (udp_tx, udp_rx) = mpsc::channel::<UdpDgram>(UDP_RX_CHANNEL);
    let (gate_tx, gate_rx) = mpsc::channel::<GateReq>(GATE_RX_CHANNEL);

    let tun_fd = cfg.tun;
    set_nonblocking(tun_fd.as_raw_fd());
    let tun_reader_fd = match tun_fd.try_clone() {
        Ok(f) => f,
        Err(e) => {
            tracing::error!("tun clone for reader failed: {e}");
            return;
        }
    };
    let tun_writer_fd = tun_fd;

    // Structured teardown: every long-lived sub-task is owned by this
    // JoinSet. `run_proxy` returning — or the task being aborted — drops
    // the set, which aborts every member; their frames in turn drop
    // *their* inner task sets (gate queries, UDP reply pumps, TCP
    // backends) and the owned TUN descriptors, so a proxy teardown can
    // never strand a detached task holding a netns-pinning fd.
    let mut tasks = tokio::task::JoinSet::new();

    // ---- tun reader: classify + route -----------------------------
    {
        let stats = stats.clone();
        let gate_tx = gate_tx.clone();
        tasks.spawn(async move {
            let afd = match AsyncFd::new(tun_reader_fd) {
                Ok(a) => a,
                Err(e) => {
                    tracing::error!("tun reader AsyncFd failed: {e}");
                    return;
                }
            };
            let mut buf = vec![0u8; 65536];
            loop {
                let mut guard = match afd.readable().await {
                    Ok(g) => g,
                    Err(e) => {
                        tracing::error!("tun readable failed: {e}");
                        return;
                    }
                };
                match guard.try_io(|fd| {
                    use std::os::unix::io::AsRawFd;
                    let n = unsafe {
                        libc::read(
                            fd.as_raw_fd(),
                            buf.as_mut_ptr() as *mut libc::c_void,
                            buf.len(),
                        )
                    };
                    if n < 0 {
                        Err(std::io::Error::last_os_error())
                    } else {
                        Ok(n as usize)
                    }
                }) {
                    Ok(Ok(0)) => continue,
                    Ok(Ok(n)) => {
                        stats
                            .bytes_from_workload
                            .fetch_add(n as u64, Ordering::Relaxed);
                        match classify(&buf[..n], dns_intercept) {
                            Classified::Tcp(mut f) => {
                                if to_stack_tx.try_send(std::mem::take(&mut f)).is_err() {
                                    stats.dropped_packets.fetch_add(1, Ordering::Relaxed);
                                }
                            }
                            Classified::UdpDns(req) => {
                                stats.dns_queries.fetch_add(1, Ordering::Relaxed);
                                if gate_tx.try_send(req).is_err() {
                                    stats.dropped_packets.fetch_add(1, Ordering::Relaxed);
                                }
                            }
                            Classified::Udp(d) => {
                                stats.udp_datagrams.fetch_add(1, Ordering::Relaxed);
                                if udp_tx.try_send(d).is_err() {
                                    stats.dropped_packets.fetch_add(1, Ordering::Relaxed);
                                }
                            }
                            Classified::DropNonIp => {
                                stats.dropped_non_v4.fetch_add(1, Ordering::Relaxed);
                            }
                            Classified::DropV6Ext => {
                                stats.dropped_v6_ext.fetch_add(1, Ordering::Relaxed);
                            }
                            Classified::DropFragment => {
                                stats.dropped_fragment.fetch_add(1, Ordering::Relaxed);
                            }
                            Classified::DropProto | Classified::DropMalformed => {
                                stats.dropped_proto.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                    }
                    Ok(Err(e)) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
                    Ok(Err(_)) => return, // tun gone — proxy over
                    Err(_) => continue,   // guard consumed, still readable
                }
            }
        });
    }

    // ---- tun writer ------------------------------------------------
    {
        let stats = stats.clone();
        let mut tun_rx = tun_rx;
        tasks.spawn(async move {
            let afd = match AsyncFd::new(tun_writer_fd) {
                Ok(a) => a,
                Err(e) => {
                    tracing::error!("tun writer AsyncFd failed: {e}");
                    return;
                }
            };
            while let Some(frame) = tun_rx.recv().await {
                stats
                    .bytes_to_workload
                    .fetch_add(frame.len() as u64, Ordering::Relaxed);
                let mut written = 0usize;
                while written < frame.len() {
                    let mut guard = match afd.writable().await {
                        Ok(g) => g,
                        Err(e) => {
                            tracing::error!("tun writable failed: {e}");
                            return;
                        }
                    };
                    match guard.try_io(|fd| {
                        use std::os::unix::io::AsRawFd;
                        let n = unsafe {
                            libc::write(
                                fd.as_raw_fd(),
                                frame[written..].as_ptr() as *const libc::c_void,
                                frame.len() - written,
                            )
                        };
                        if n < 0 {
                            Err(std::io::Error::last_os_error())
                        } else {
                            Ok(n as usize)
                        }
                    }) {
                        Ok(Ok(n)) => written += n,
                        Ok(Err(e)) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
                        Ok(Err(e)) => {
                            tracing::debug!("tun write failed: {e}");
                            return;
                        }
                        Err(_) => continue,
                    }
                }
            }
        });
    }

    // ---- gate task: intercepted DNS --------------------------------
    if let Some(gate_core) = &cfg.gate {
        let gate_core = gate_core.clone();
        let tun_tx = tun_tx.clone();
        let stats = stats.clone();
        let mut gate_rx = gate_rx;
        tasks.spawn(async move {
            // Each query answers on its own task — awaiting upstream
            // inline serializes the gate and lets pending queries pile
            // up behind a slow resolver. The semaphore caps that
            // concurrency; at the ceiling a query is dropped (the
            // workload's resolver retries or times out — never a
            // silent pass). The JoinSet owns every in-flight query, so
            // this task's teardown (channel close or proxy abort)
            // cannot strand one holding a `tun_tx` clone.
            let inflight = std::sync::Arc::new(tokio::sync::Semaphore::new(GATE_INFLIGHT));
            let mut queries = tokio::task::JoinSet::new();
            while let Some(req) = gate_rx.recv().await {
                let Ok(permit) = inflight.clone().try_acquire_owned() else {
                    continue;
                };
                let gate_core = gate_core.clone();
                let tun_tx = tun_tx.clone();
                let stats = stats.clone();
                queries.spawn(async move {
                    let _permit = permit;
                    match req.ctx {
                        GateCtx::Udp {
                            src,
                            src_port,
                            dst,
                            dst_port,
                        } => {
                            if let Some(resp) = gate_core.answer(&req.pkt, req.peer, false).await {
                                let pkt = craft_udp_packet(dst, dst_port, src, src_port, &resp);
                                if tun_tx.try_send(pkt).is_err() {
                                    stats.dropped_packets.fetch_add(1, Ordering::Relaxed);
                                }
                            }
                        }
                    }
                });
            }
        });
    }

    // ---- udp relay task ---------------------------------------------
    {
        let gate = gate.clone();
        let tun_tx = tun_tx.clone();
        let stats = stats.clone();
        tasks.spawn(async move {
            udp_task(udp_rx, gate, tun_tx, stats).await;
        });
    }

    // ---- stack task (this fn's body continues) ----------------------
    stack_loop(
        to_stack_rx,
        events_rx,
        events_tx,
        tun_tx,
        gate,
        cfg.gate.clone(),
        dns_intercept,
        stats.clone(),
    )
    .await;
}

// ---------------------------------------------------------------------------

struct UdpFlow {
    socket: Arc<UdpSocket>,
    last_seen: std::time::Instant,
    /// Last verdict direction this flow emitted an audit record for —
    /// repeats are suppressed; a direction flip re-logs (the
    /// transition, not each packet, is the audit-worthy event).
    audit: FlowAudit,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum FlowAudit {
    Allowed,
    Denied,
}

/// Windowed emission budget for the UDP audit path — bounds the
/// aggregate event rate regardless of how many distinct flows or
/// destinations a datagram flood invents.
struct AuditBudget {
    window_start: std::time::Instant,
    used: usize,
}

impl AuditBudget {
    fn new() -> Self {
        Self {
            window_start: std::time::Instant::now(),
            used: 0,
        }
    }

    /// `true` when an event may be emitted this window.
    fn take(&mut self) -> bool {
        if self.window_start.elapsed() >= UDP_AUDIT_WINDOW {
            self.window_start = std::time::Instant::now();
            self.used = 0;
        }
        if self.used >= UDP_AUDIT_BURST {
            return false;
        }
        self.used += 1;
        true
    }
}

async fn udp_task(
    mut rx: mpsc::Receiver<UdpDgram>,
    gate: Arc<FlowGate>,
    tun_tx: mpsc::Sender<Vec<u8>>,
    stats: ProxyStats,
) {
    type FlowKey = (IpAddr, u16, IpAddr, u16);
    // Per-flow reply pumps live in this JoinSet: the map only stores
    // their AbortHandles for eviction, so this task ending — channel
    // close or proxy abort — drops the set and kills every pump (each
    // holds a `tun_tx` clone that would otherwise keep a dead channel
    // open while it parked on `recv` forever).
    let mut pumps = tokio::task::JoinSet::new();
    let mut flows: HashMap<FlowKey, (UdpFlow, tokio::task::AbortHandle)> = HashMap::new();
    // Denied datagrams never mint a flow, so a per-key window map does
    // the dedup the flow's `audit` field does for allowed traffic —
    // without it a single-target flood would spend the whole budget.
    let mut deny_audit: HashMap<(IpAddr, u16), std::time::Instant> = HashMap::new();
    let mut budget = AuditBudget::new();
    let mut reaper = tokio::time::interval(UDP_IDLE / 2);
    reaper.tick().await; // immediate first tick is free
    loop {
        tokio::select! {
            Some(d) = rx.recv() => {
                let key = (d.src, d.src_port, d.dst, d.dst_port);
                // Per-datagram verdict — a TTL-scoped grant can expire
                // mid-flow and must stop taking effect immediately.
                let verdict = gate.verdict(d.dst, EgressProto::Udp, d.dst_port);
                match verdict {
                    IpVerdict::Allow { basis, rule } => {
                        let fresh = !matches!(
                            flows.get(&key),
                            Some((f, _)) if f.audit == FlowAudit::Allowed
                        );
                        if fresh {
                            if !budget.take() {
                                stats.udp_audit_suppressed.fetch_add(1, Ordering::Relaxed);
                            } else if gate
                                .authorize(
                                    EgressProto::Udp,
                                    d.dst,
                                    d.dst_port,
                                    basis,
                                    rule.as_deref(),
                                )
                                .await
                                .is_err()
                            {
                                // Audit admission failed — fail closed:
                                // drop the datagram rather than relay
                                // it unaudited. `writer_failed` latches,
                                // so later verdicts deny outright.
                                stats.udp_denied.fetch_add(1, Ordering::Relaxed);
                                continue;
                            }
                        }
                    }
                    IpVerdict::Deny { decision, rule } => {
                        stats.udp_denied.fetch_add(1, Ordering::Relaxed);
                        let fresh = if let Some((f, _)) = flows.get_mut(&key) {
                            std::mem::replace(&mut f.audit, FlowAudit::Denied)
                                != FlowAudit::Denied
                        } else {
                            let k = (d.dst, d.dst_port);
                            let due = match deny_audit.get(&k) {
                                Some(t) => t.elapsed() >= UDP_DENY_AUDIT_WINDOW,
                                None => true,
                            };
                            if due {
                                if deny_audit.len() >= UDP_DENY_AUDIT_CAP
                                    && let Some((&old, _)) =
                                        deny_audit.iter().min_by_key(|(_, t)| *t)
                                {
                                    deny_audit.remove(&old);
                                }
                                deny_audit.insert(k, std::time::Instant::now());
                            }
                            due
                        };
                        if fresh {
                            if budget.take() {
                                gate.denied(
                                    EgressProto::Udp,
                                    d.dst,
                                    d.dst_port,
                                    decision,
                                    rule.as_deref(),
                                )
                                .await;
                            } else {
                                stats.udp_audit_suppressed.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                        continue;
                    }
                }
                if !flows.contains_key(&key) && flows.len() >= UDP_FLOW_CAP {
                    // Evict the idlest entry.
                    if let Some((&k, _)) =
                        flows.iter().min_by_key(|(_, (f, _))| f.last_seen)
                        && let Some((_, j)) = flows.remove(&k)
                    {
                        j.abort();
                    }
                }
                if let std::collections::hash_map::Entry::Vacant(e) = flows.entry(key) {
                    // The relay socket's family follows the datagram's
                    // spelled destination — a `::ffff:<v4>` target
                    // binds v6 and lets the kernel fold, exactly the
                    // endpoint the verdict judged.
                    let bind_addr: &str = if d.dst.is_ipv4() {
                        "0.0.0.0:0"
                    } else {
                        "[::]:0"
                    };
                    let sock = match UdpSocket::bind(bind_addr).await {
                        Ok(s) => s,
                        Err(err) => {
                            // No stack for this family → the flow is
                            // refused (datagram dropped), never routed
                            // around the boundary.
                            tracing::warn!("udp relay socket bind failed: {err}");
                            continue;
                        }
                    };
                    // A bound-but-unconnected socket accepts datagrams
                    // from any source — connect pins the peer so a
                    // stray or spoofed packet cannot be relayed to the
                    // workload as if it came from this flow's peer.
                    if let Err(err) = sock
                        .connect(SocketAddr::new(d.dst, d.dst_port))
                        .await
                    {
                        tracing::warn!("udp relay socket connect failed: {err}");
                        continue;
                    }
                    let sock = Arc::new(sock);
                    stats.udp_flows.fetch_add(1, Ordering::Relaxed);
                    // Reply pump for this flow.
                    let reply_sock = sock.clone();
                    let tun_tx = tun_tx.clone();
                    let stats = stats.clone();
                    let (wsrc, wsport, rdst, rdport) = key;
                    let j = pumps.spawn(async move {
                        let mut buf = vec![0u8; 65536];
                        loop {
                            let n = match reply_sock.recv(&mut buf).await {
                                Ok(n) => n,
                                Err(_) => return,
                            };
                            let pkt = craft_udp_packet(rdst, rdport, wsrc, wsport, &buf[..n]);
                            match tun_tx.try_send(pkt) {
                                Ok(()) => {}
                                // A full writer queue drops the reply —
                                // ordinary UDP loss; the workload's
                                // own stack retries if it wants to.
                                Err(mpsc::error::TrySendError::Full(_)) => {
                                    stats.dropped_packets.fetch_add(1, Ordering::Relaxed);
                                }
                                Err(mpsc::error::TrySendError::Closed(_)) => return,
                            }
                        }
                    });
                    e.insert((
                        UdpFlow {
                            socket: sock,
                            last_seen: std::time::Instant::now(),
                            audit: FlowAudit::Allowed,
                        },
                        j,
                    ));
                }
                let (flow, _) = flows.get_mut(&key).unwrap();
                flow.last_seen = std::time::Instant::now();
                flow.audit = FlowAudit::Allowed;
                if let Err(e) = flow.socket.send(&d.payload).await {
                    tracing::debug!("udp relay send failed: {e}");
                }
            }
            _ = reaper.tick() => {
                flows.retain(|_, (f, j)| {
                    let live = f.last_seen.elapsed() < UDP_IDLE;
                    if !live { j.abort(); }
                    live
                });
            }
            else => return,
        }
    }
}

// ---------------------------------------------------------------------------

/// The smoltcp-side loop. Owns iface/sockets/NAT; accepts connections,
/// evaluates policy, drives splicing. Runs until `to_stack_rx` closes
/// (reader gone = tun gone = proxy over).
#[allow(clippy::too_many_arguments)]
async fn stack_loop(
    mut to_stack_rx: mpsc::Receiver<Vec<u8>>,
    mut events_rx: mpsc::Receiver<ConnEvent>,
    events_tx: mpsc::Sender<ConnEvent>,
    tun_tx: mpsc::Sender<Vec<u8>>,
    gate: Arc<FlowGate>,
    gate_core: Option<Arc<QueryCore>>,
    dns_intercept: bool,
    stats: ProxyStats,
) {
    // Per-connection backend tasks (tcp_backend / dns_tcp_backend)
    // live in this set — an abort of the stack loop drops it and
    // kills every backend, so no splicing task can outlive the proxy
    // holding a `tun_tx`/events handle.
    let mut backends = tokio::task::JoinSet::new();
    let nat = std::sync::Arc::new(std::sync::Mutex::new(NatTable::new(dns_intercept)));
    let mut dev = TunDev {
        rx: VecDeque::new(),
        tx: tun_tx.clone(),
        nat: nat.clone(),
        stats: stats.clone(),
    };

    let mut iface = Interface::new(
        IfaceConfig::new(HardwareAddress::Ip),
        &mut dev,
        SmolInstant::now(),
    );
    iface.set_any_ip(true);
    iface.update_ip_addrs(|addrs| {
        addrs
            .push(IpCidr::new(super::GATEWAY_V4.into(), 24))
            .expect("iface addr capacity");
        addrs
            .push(IpCidr::new(super::GATEWAY_V6.into(), 64))
            .expect("iface addr capacity");
    });
    let mut sockets = SocketSet::new(Vec::new());
    let mut conns: HashMap<ConnKey, Conn> = HashMap::new();

    // Listener top-up: keep `LISTEN_POOL` sockets in Listen on each
    // intercept port; one becomes the connection on each SYN. The DNS
    // listener only exists while interception is armed — without a
    // gate no NAT rewrite ever targets it, so the pool would sit
    // idle forever.
    let ensure_listeners = |sockets: &mut SocketSet| {
        let ports: &[u16] = if dns_intercept {
            &[super::TCP_NAT_PORT, super::DNS_TCP_NAT_PORT]
        } else {
            &[super::TCP_NAT_PORT]
        };
        for &port in ports {
            let listening = sockets
                .iter()
                .filter(|(_, s)| {
                    matches!(s, smoltcp::socket::Socket::Tcp(t)
                        if t.state() == TcpState::Listen
                            && t.listen_endpoint().port == port)
                })
                .count();
            for _ in listening..LISTEN_POOL {
                let mut s = TcpSock::new(
                    SocketBuffer::new(vec![0u8; SOCK_BUF]),
                    SocketBuffer::new(vec![0u8; SOCK_BUF]),
                );
                if s.listen(IpListenEndpoint { addr: None, port }).is_err() {
                    return;
                }
                sockets.add(s);
            }
        }
    };

    loop {
        // Drain inbound work before polling.
        while let Ok(frame) = to_stack_rx.try_recv() {
            // Frames arrive here NOT yet DNAT'd — reader pushed raw
            // TCP; the NAT table lives on the device for tx, so do
            // the inbound rewrite here against the same table.
            let mut f = frame;
            if nat.lock().unwrap().dnat_in(&mut f).is_some() {
                dev.rx.push_back(f);
            } else {
                stats.dropped_packets.fetch_add(1, Ordering::Relaxed);
            }
        }
        while let Ok(ev) = events_rx.try_recv() {
            match ev {
                ConnEvent::Data { key, bytes } => {
                    if let Some(c) = conns.get_mut(&key) {
                        c.pending.push_back(bytes);
                    }
                }
                ConnEvent::Eof { key } => {
                    if let Some(c) = conns.get_mut(&key) {
                        c.backend_eof = true;
                    }
                }
                ConnEvent::Fail { key } => {
                    if let Some(c) = conns.remove(&key) {
                        let s: &mut TcpSock = sockets.get_mut(c.handle);
                        s.abort();
                        // Flush the queued RST while the NAT mapping
                        // still stands — removing it first would drop
                        // the RST at rev-NAT and leave the workload
                        // hanging on a "connected" socket.
                        iface.poll(SmolInstant::now(), &mut dev, &mut sockets);
                        sockets.remove(c.handle);
                        nat.lock().unwrap().remove(key.ip, key.port);
                    }
                }
            }
        }

        let now = SmolInstant::now();
        iface.poll(now, &mut dev, &mut sockets);
        ensure_listeners(&mut sockets);
        // Reap SYN-minted mappings that never associated — a workload
        // that fires SYNs and abandons them must not retain NAT state.
        // Internally throttled to once per second.
        nat.lock().unwrap().reap_if_due(std::time::Instant::now());

        // Post-poll: accept newly-established sockets, pump data.
        let mut new_conns: Vec<(SocketHandle, ConnKey)> = Vec::new();
        let mut dead: Vec<SocketHandle> = Vec::new();
        for (handle, sock) in sockets.iter_mut() {
            let smoltcp::socket::Socket::Tcp(t) = sock;
            if t.state() == TcpState::Listen {
                continue;
            }
            let Some(remote) = t.remote_endpoint() else {
                continue;
            };
            let key = ConnKey {
                ip: match remote.addr {
                    smoltcp::wire::IpAddress::Ipv4(v4) => v4.into(),
                    smoltcp::wire::IpAddress::Ipv6(v6) => v6.into(),
                },
                port: remote.port,
            };
            if !conns.contains_key(&key)
                && matches!(t.state(), TcpState::SynReceived | TcpState::Established)
            {
                new_conns.push((handle, key));
            }
        }
        for (handle, key) in new_conns {
            // Look up the original destination recorded at DNAT time.
            let orig = nat.lock().unwrap().orig_for(key.ip, key.port);
            let Some(orig) = orig else {
                sockets.get_mut::<TcpSock>(handle).abort();
                // Emit the RST, then free the slot — an aborted socket
                // left in the set keeps its buffers forever.
                iface.poll(SmolInstant::now(), &mut dev, &mut sockets);
                sockets.remove(handle);
                continue;
            };
            // Global admission: the flow owns a socket pair, backend
            // task, and channels — refuse before any of it is retained.
            // Saturation answers RST exactly like a policy deny, but
            // counts under `tcp_saturated`, not `tcp_denied`.
            let dns_tcp_conns = conns.values().filter(|c| c.dns_tcp).count();
            let data_conns = conns.len() - dns_tcp_conns;
            if (orig.dns_tcp && dns_tcp_conns >= MAX_DNS_TCP_FLOWS)
                || (!orig.dns_tcp && data_conns >= MAX_TCP_FLOWS)
            {
                stats.tcp_saturated.fetch_add(1, Ordering::Relaxed);
                sockets.get_mut::<TcpSock>(handle).abort();
                iface.poll(SmolInstant::now(), &mut dev, &mut sockets);
                sockets.remove(handle);
                nat.lock().unwrap().remove(key.ip, key.port);
                continue;
            }
            nat.lock().unwrap().mark_associated(key.ip, key.port);
            if orig.dns_tcp {
                // DNS-over-TCP intercept — answer through the gate.
                if let Some(gate_core) = &gate_core {
                    let (tx, rx) = mpsc::channel(BACKEND_CHANNEL);
                    let credit = Arc::new(FlowCredit {
                        bytes: std::sync::atomic::AtomicUsize::new(0),
                        drained: tokio::sync::Notify::new(),
                    });
                    backends.spawn(dns_tcp_backend(
                        key,
                        gate_core.clone(),
                        SocketAddr::new(key.ip, key.port),
                        events_tx.clone(),
                        rx,
                        credit.clone(),
                    ));
                    conns.insert(
                        key,
                        Conn {
                            handle,
                            to_backend: tx,
                            pending: VecDeque::new(),
                            credit,
                            backend_eof: false,
                            fin_sent_to_backend: false,
                            dns_tcp: true,
                        },
                    );
                } else {
                    sockets.get_mut::<TcpSock>(handle).abort();
                    iface.poll(SmolInstant::now(), &mut dev, &mut sockets);
                    sockets.remove(handle);
                    nat.lock().unwrap().remove(key.ip, key.port);
                }
                continue;
            }
            let verdict = gate.verdict(orig.addr, EgressProto::Tcp, orig.port);
            match verdict {
                IpVerdict::Allow { basis, rule } => {
                    // Durable-before-side-effect: the `authorize` record
                    // must be committed before the host-side backend
                    // spawns and flow state installs. A dead sink fails
                    // closed — the socket aborts and answers RST like a
                    // policy deny.
                    if let Err(e) = gate
                        .authorize(
                            EgressProto::Tcp,
                            orig.addr,
                            orig.port,
                            basis,
                            rule.as_deref(),
                        )
                        .await
                    {
                        tracing::error!("flow audit authorization failed (fail-closed): {e}");
                        stats.tcp_denied.fetch_add(1, Ordering::Relaxed);
                        sockets.get_mut::<TcpSock>(handle).abort();
                        iface.poll(SmolInstant::now(), &mut dev, &mut sockets);
                        sockets.remove(handle);
                        nat.lock().unwrap().remove(key.ip, key.port);
                        continue;
                    }
                    stats.tcp_accepted.fetch_add(1, Ordering::Relaxed);
                    let (tx, rx) = mpsc::channel(BACKEND_CHANNEL);
                    let credit = Arc::new(FlowCredit {
                        bytes: std::sync::atomic::AtomicUsize::new(0),
                        drained: tokio::sync::Notify::new(),
                    });
                    backends.spawn(tcp_backend(
                        key,
                        orig,
                        events_tx.clone(),
                        rx,
                        credit.clone(),
                    ));
                    conns.insert(
                        key,
                        Conn {
                            handle,
                            to_backend: tx,
                            pending: VecDeque::new(),
                            credit,
                            backend_eof: false,
                            fin_sent_to_backend: false,
                            dns_tcp: false,
                        },
                    );
                }
                IpVerdict::Deny { decision, rule } => {
                    stats.tcp_denied.fetch_add(1, Ordering::Relaxed);
                    gate.denied(
                        EgressProto::Tcp,
                        orig.addr,
                        orig.port,
                        decision,
                        rule.as_deref(),
                    )
                    .await;
                    sockets.get_mut::<TcpSock>(handle).abort();
                    // Same RST-before-map-removal ordering as the Fail
                    // path — a denied flow must answer the workload
                    // with RST, not silence.
                    iface.poll(SmolInstant::now(), &mut dev, &mut sockets);
                    // Free the slot once the RST is on the wire — an
                    // aborted socket left behind would accumulate
                    // buffers for every denied SYN.
                    sockets.remove(handle);
                    nat.lock().unwrap().remove(key.ip, key.port);
                }
            }
        }

        // Per-conn socket pump.
        let mut remove_keys: Vec<ConnKey> = Vec::new();
        for (key, conn) in conns.iter_mut() {
            let t: &mut TcpSock = sockets.get_mut(conn.handle);
            // workload → backend: pull only while a backend channel
            // slot is reserved. A full channel leaves the bytes in the
            // smoltcp buffer so the TCP window applies the
            // backpressure; only a closed channel means the backend
            // died and the flow aborts.
            //
            // `can_recv` (rx buffer non-empty), not `may_recv` (state
            // allows receiving): `may_recv` stays true for the whole
            // ESTABLISHED lifetime, so probing `try_reserve` against a
            // channel whose backend task already exited on EOF would
            // abort healthy idle connections before their pending
            // reply was flushed.
            while t.can_recv() {
                use tokio::sync::mpsc::error::TrySendError;
                let permit = match conn.to_backend.try_reserve() {
                    Ok(p) => p,
                    Err(TrySendError::Full(())) => break,
                    Err(TrySendError::Closed(())) => {
                        t.abort();
                        break;
                    }
                };
                let mut chunk = Vec::new();
                let _ = t.recv(|b| {
                    let n = b.len().min(SOCK_BUF);
                    chunk.extend_from_slice(&b[..n]);
                    (n, ())
                });
                if chunk.is_empty() {
                    break;
                }
                permit.send(ToBackend::Data(chunk));
            }
            // Forward the workload's FIN to the backend exactly once —
            // `may_recv()` is false throughout SynReceived too (not a
            // half-close), so the gate is the explicit CloseWait state:
            // remote FIN received, our send side still open.
            if t.state() == TcpState::CloseWait && !conn.fin_sent_to_backend {
                let _ = conn.to_backend.try_send(ToBackend::Fin);
                conn.fin_sent_to_backend = true;
            }
            // backend → workload: drain pending into the socket, then
            // release the backend's read throttle for what moved.
            let mut moved = 0usize;
            while t.may_send() && !conn.pending.is_empty() {
                let n = match t.send_slice(&conn.pending[0]) {
                    Ok(n) => n,
                    Err(_) => break,
                };
                if n == 0 {
                    break;
                }
                moved += n;
                if n == conn.pending[0].len() {
                    conn.pending.pop_front();
                } else {
                    conn.pending[0].drain(..n);
                }
            }
            if moved > 0 {
                conn.credit.bytes.fetch_sub(moved, Ordering::Release);
                conn.credit.drained.notify_one();
            }
            if conn.backend_eof && conn.pending.is_empty() && t.may_send() {
                t.close();
            }
            if matches!(t.state(), TcpState::Closed) || !t.is_open() {
                remove_keys.push(*key);
            }
        }
        for key in remove_keys {
            if let Some(c) = conns.remove(&key) {
                // A backend parked on the backlog cap only rechecks
                // `is_closed` when woken — release it.
                c.credit.drained.notify_waiters();
                dead.push(c.handle);
                nat.lock().unwrap().remove(key.ip, key.port);
            }
        }
        for h in dead {
            sockets.remove(h);
        }

        // Wait for the next wakeup: inbound frame, conn event, or the
        // stack's own timer (retransmit/ACK/delayed work).
        let delay = iface
            .poll_delay(SmolInstant::now(), &sockets)
            .map(|d| std::time::Duration::from_micros(d.total_micros().min(1_000_000)))
            .unwrap_or(std::time::Duration::from_millis(10));
        tokio::select! {
            frame = to_stack_rx.recv() => {
                match frame {
                    Some(mut f) => {
                        if nat.lock().unwrap().dnat_in(&mut f).is_some() {
                            dev.rx.push_back(f);
                        } else {
                            stats.dropped_packets.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                    None => return, // reader gone → proxy over
                }
            }
            ev = events_rx.recv() => {
                match ev {
                    Some(ConnEvent::Data { key, bytes }) => {
                        if let Some(c) = conns.get_mut(&key) {
                            c.pending.push_back(bytes);
                        }
                    }
                    Some(ConnEvent::Eof { key }) => {
                        if let Some(c) = conns.get_mut(&key) {
                            c.backend_eof = true;
                        }
                    }
                    Some(ConnEvent::Fail { key }) => {
                        if let Some(c) = conns.remove(&key) {
                            let s: &mut TcpSock = sockets.get_mut(c.handle);
                            s.abort();
                            // Same ordering as the drain branch: emit
                            // the RST before the mapping goes away.
                            iface.poll(SmolInstant::now(), &mut dev, &mut sockets);
                            sockets.remove(c.handle);
                            nat.lock().unwrap().remove(key.ip, key.port);
                        }
                    }
                    None => return,
                }
            }
            () = tokio::time::sleep(delay) => {}
        }
    }
}

fn set_nonblocking(fd: i32) {
    unsafe {
        let flags = libc::fcntl(fd, libc::F_GETFL);
        if flags >= 0 {
            libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
        }
    }
}
