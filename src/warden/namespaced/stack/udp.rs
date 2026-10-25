//! The UDP relay task: per-datagram policy verdicts, per-flow
//! connected sockets, and reply pumps back onto the TUN.
//!
//! Denied datagrams never mint a flow; allowed ones get a real
//! `UdpSocket` bound-and-connected to the spelled destination, with a
//! reply pump re-encapsulating answers for the workload. Audit
//! emission runs under windowed budgets (`AuditBudget`) so a datagram
//! flood degrades telemetry rate, never the fail-closed boundary.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::Ordering;

use tokio::net::UdpSocket;
use tokio::sync::mpsc;

use crate::policy::EgressProto;
use crate::warden::flow_gate::FlowGate;
use crate::warden::unotify::IpVerdict;

use super::ProxyStats;
use super::backend::unspecified_target;
use super::packet::{UdpDgram, craft_udp_packet};

/// Live UDP flow ceiling — excess flows evict oldest.
const UDP_FLOW_CAP: usize = 256;
/// UDP flow idle reaper.
const UDP_IDLE: std::time::Duration = std::time::Duration::from_secs(60);
/// UDP audit emission budget — `UDP_AUDIT_BURST` events per window;
/// anything beyond it is counted in `udp_audit_suppressed`, never
/// queued, so a datagram flood cannot become a sink flood.
const UDP_AUDIT_BURST: usize = 32;
/// Sub-cap on denied-datagram records *within* the same per-second
/// aggregate: a flood of fresh denied destinations is telemetry and
/// must never starve the allow path's required `authorize` records —
/// at least `UDP_AUDIT_BURST - UDP_DENY_AUDIT_BURST` slots per window
/// remain available to them.
const UDP_DENY_AUDIT_BURST: usize = 8;
const UDP_AUDIT_WINDOW: std::time::Duration = std::time::Duration::from_secs(1);
/// A denied datagram with no flow repeats one audit subject — collapse
/// repeats per destination inside this window; the map is bounded and
/// evicts its oldest entry at the cap.
const UDP_DENY_AUDIT_WINDOW: std::time::Duration = std::time::Duration::from_secs(60);
const UDP_DENY_AUDIT_CAP: usize = 1024;

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
    limit: usize,
}

impl AuditBudget {
    fn new(limit: usize) -> Self {
        Self {
            window_start: std::time::Instant::now(),
            used: 0,
            limit,
        }
    }

    /// `true` when an event may be emitted this window.
    fn take(&mut self) -> bool {
        if self.window_start.elapsed() >= UDP_AUDIT_WINDOW {
            self.window_start = std::time::Instant::now();
            self.used = 0;
        }
        if self.used >= self.limit {
            return false;
        }
        self.used += 1;
        true
    }

    /// `true` when a slot is free this window — consumes nothing; the
    /// caller charges with `take` only once every budget is known to
    /// admit the event.
    fn available(&self) -> bool {
        self.window_start.elapsed() >= UDP_AUDIT_WINDOW || self.used < self.limit
    }
}

pub(super) async fn udp_task(
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
    let mut budget = AuditBudget::new(UDP_AUDIT_BURST);
    let mut deny_budget = AuditBudget::new(UDP_DENY_AUDIT_BURST);
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
                                // The budget throttles telemetry, never
                                // authorization: a fresh tuple whose
                                // `authorize` record cannot be emitted
                                // must not relay unaudited. Drop the
                                // datagram — the workload's retransmit
                                // lands in a replenished window.
                                stats.udp_audit_suppressed.fetch_add(1, Ordering::Relaxed);
                                continue;
                            }
                            if gate
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
                            // Charge neither budget until both admit
                            // the record — a shared-cap rejection must
                            // not spend the deny sub-budget on an event
                            // that was never emitted.
                            if deny_budget.available() && budget.available() {
                                deny_budget.take();
                                budget.take();
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
                    // Same unspecified-destination guard as the TCP
                    // backend — `connect` would fold it to host
                    // loopback while the verdict named the spelled
                    // address. The datagram drops; no flow is minted.
                    if unspecified_target(d.dst) {
                        tracing::debug!(
                            "namespaced udp relay refused unspecified destination {}",
                            d.dst
                        );
                        continue;
                    }
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
                                // ICMP port-unreachable for a sent
                                // datagram surfaces as ECONNREFUSED on
                                // the connected socket — ordinary UDP
                                // loss, not a dead socket. Keep the
                                // pump alive for replies that arrive
                                // after the refusal.
                                Err(e) if e.kind() == std::io::ErrorKind::ConnectionRefused => {
                                    continue;
                                }
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
                // Reap pump entries — abort() only *signals* the task;
                // its JoinSet entry (with the tun_tx clone it held)
                // stays until a join clears it, so finished and evicted
                // pumps alike are drained here rather than retained
                // for the session's lifetime.
                while pumps.try_join_next().is_some() {}
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
