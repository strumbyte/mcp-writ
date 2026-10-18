//! DNAT interception for the transparent TCP path.
//!
//! smoltcp cannot listen on a wildcard port, so inbound TCP packets
//! are rewritten before they reach the stack: `dst` becomes the
//! proxy's own gateway address and a fixed listener port
//! (`TCP_NAT_PORT` for data flows, `DNS_TCP_NAT_PORT` when the
//! original destination port was 53 — DNS-over-TCP interception,
//! matching the UDP intercept — and only while `dns_intercept` is
//! armed, i.e. an embedded DNS gate actually exists to answer it;
//! with no gate a :53 flow is an ordinary evaluated TCP flow).
//!
//! Each flow also gets its own *translated source port*: the workload
//! is root inside its own netns and can emit raw packets, so two SYNs
//! may legitimately arrive sharing (src_ip, src_port) toward different
//! destinations. Rewriting the source port to a per-flow allocation
//! keeps the stack-side remote endpoint unique — smoltcp tells the
//! connections apart and the reverse path is unambiguous.
//!
//! Outbound packets take the reverse rewrite: the stack's reply source
//! is replaced with the recorded original destination and the reply's
//! destination port restored to the workload's real source port, so
//! the workload sees answers from the peer it dialed.
//!
//! Both IP families share the one table (PR-26a): a v6 flow keys and
//! rewrites exactly like v4, with the v6 pseudo-header checksum in
//! place of the header+segment pair. Both directions recompute the
//! checksums — no incremental fixups; correctness over cleverness
//! for a PoC.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::{Duration, Instant};

/// First translated source port — stack-side only, so the ordinary
/// ephemeral range is free (collisions are resolved by scanning).
const ALLOC_BASE: u16 = 49152;

/// Hard cap on live NAT mappings. Every SYN that mints a flow is
/// workload-controlled; without a ceiling a SYN flood exhausts the
/// translated-port space and grows the table unboundedly. Saturation
/// refuses O(1) — the SYN is dropped and the workload retransmits.
pub(crate) const MAX_NAT_MAPPINGS: usize = 4096;

/// A minted mapping that never associates with an accepted socket —
/// the workload sent a SYN but never completed the handshake, or the
/// stack dropped the socket before it reached SynReceived — is reaped
/// after this deadline. Legitimate associations complete within
/// milliseconds.
const NAT_ASSOCIATE_DEADLINE: Duration = Duration::from_secs(5);

/// Reap scans are throttled to this period — `dnat_in` is a per-packet
/// path and must not pay an O(table) sweep per SYN.
const NAT_REAP_INTERVAL: Duration = Duration::from_secs(1);

/// A recovered original destination for one intercepted flow.
#[derive(Debug, Clone, Copy)]
pub struct OrigDst {
    pub addr: IpAddr,
    pub port: u16,
    /// The original destination port was 53 — this flow is a
    /// DNS-over-TCP intercept, answered by the embedded gate rather
    /// than a real socket.
    pub dns_tcp: bool,
}

/// Everything needed to reverse one flow, keyed stack-side.
#[derive(Debug, Clone, Copy)]
struct FlowOrig {
    dst_addr: IpAddr,
    dst_port: u16,
    /// The workload's real source port — restored on the reverse path.
    src_port: u16,
    dns_tcp: bool,
    /// When the mapping was minted by the inbound SYN.
    minted: Instant,
    /// The stack accepted the translated SYN into a live connection.
    /// Unassociated mappings expire at `NAT_ASSOCIATE_DEADLINE`;
    /// associated ones live until `remove`.
    associated: bool,
}

/// Workload-side 4-tuple → allocated stack-side source port.
type FlowKey = (IpAddr, u16, IpAddr, u16);
/// Stack-side remote endpoint (workload_ip, alloc_port).
type AllocKey = (IpAddr, u16);

pub struct NatTable {
    by_flow: HashMap<FlowKey, u16>,
    by_alloc: HashMap<AllocKey, FlowOrig>,
    next_alloc: u16,
    /// Throttle for the periodic expired-mapping sweep.
    next_reap: Instant,
    /// Whether port-53 flows DNAT to the DNS-over-TCP intercept
    /// listener. Armed only when the embedded gate exists — without a
    /// gate the intercept has no answerer, so :53 must stay on the
    /// ordinary evaluated path where the policy can decide it.
    dns_intercept: bool,
}

impl NatTable {
    pub fn new(dns_intercept: bool) -> Self {
        Self {
            by_flow: HashMap::new(),
            by_alloc: HashMap::new(),
            next_alloc: ALLOC_BASE,
            next_reap: Instant::now() + NAT_REAP_INTERVAL,
            dns_intercept,
        }
    }

    /// Drop minted-but-never-associated mappings past their deadline.
    /// Associated flows are untouched — they are owned by the stack's
    /// connection map and leave via `remove`.
    fn reap_expired(&mut self, now: Instant) {
        self.by_alloc.retain(|(src, _alloc), orig| {
            if orig.associated || now.duration_since(orig.minted) <= NAT_ASSOCIATE_DEADLINE {
                return true;
            }
            self.by_flow
                .remove(&(*src, orig.src_port, orig.dst_addr, orig.dst_port));
            false
        });
    }

    /// Periodic expired-mapping sweep, throttled to `NAT_REAP_INTERVAL`
    /// — the per-packet caller must not pay an O(table) scan each SYN.
    pub fn reap_if_due(&mut self, now: Instant) {
        if now < self.next_reap {
            return;
        }
        self.next_reap = now + NAT_REAP_INTERVAL;
        self.reap_expired(now);
    }

    /// The stack accepted the translated SYN for `(workload, port)`
    /// into a live connection — the mapping leaves the reaper's reach
    /// and is owned by the connection lifecycle (`remove`).
    pub fn mark_associated(&mut self, workload: IpAddr, port: u16) {
        if let Some(orig) = self.by_alloc.get_mut(&(workload, port)) {
            orig.associated = true;
        }
    }

    /// Allocate a stack-side source port for `src`'s new flow.
    fn alloc_port(&mut self, src: IpAddr) -> Option<u16> {
        for _ in 0..=u16::MAX {
            let p = self.next_alloc;
            self.next_alloc = if self.next_alloc == u16::MAX {
                ALLOC_BASE
            } else {
                self.next_alloc + 1
            };
            if !self.by_alloc.contains_key(&(src, p)) {
                return Some(p);
            }
        }
        None
    }

    /// Rewrite an inbound IPv4/IPv6 TCP packet toward the fixed
    /// listener. Returns the recovered [`OrigDst`] (also stored for
    /// the reverse path), or `None` when the packet is not TCP, is
    /// malformed, or has no flow behind it — callers drop those.
    /// Only a SYN (without ACK) mints a mapping: anything else may
    /// rewrite only against an existing entry — a stray or crafted
    /// segment must not mint or overwrite flow state. A SYN on an
    /// already-recorded 4-tuple reuses its translation (retransmit),
    /// while a SYN colliding on (src_ip, src_port) toward a different
    /// destination becomes a *separate* flow — never an overwrite.
    pub fn dnat_in(&mut self, frame: &mut [u8]) -> Option<OrigDst> {
        let (src, dst, src_port, dst_port) = parse_tcp_tuple(frame)?;
        let flags = frame[l4_offset(frame) + 13];
        let flow_key = (src, src_port, dst, dst_port);
        let alloc = if is_workload_src(src) && flags & 0x12 == 0x02 {
            match self.by_flow.get(&flow_key) {
                Some(&p) => p,
                None => {
                    // Admit before minting: a saturated table refuses
                    // O(1) — the SYN is dropped, the workload's stack
                    // retransmits, and no durable state is retained.
                    // Reap once first so a stale half-open buildup
                    // cannot hold the cap hostage.
                    if self.by_alloc.len() >= MAX_NAT_MAPPINGS {
                        let now = Instant::now();
                        self.reap_expired(now);
                        self.next_reap = now + NAT_REAP_INTERVAL;
                        if self.by_alloc.len() >= MAX_NAT_MAPPINGS {
                            return None;
                        }
                    }
                    let p = self.alloc_port(src)?;
                    self.by_flow.insert(flow_key, p);
                    self.by_alloc.insert(
                        (src, p),
                        FlowOrig {
                            dst_addr: dst,
                            dst_port,
                            src_port,
                            dns_tcp: self.dns_intercept && dst_port == 53,
                            minted: Instant::now(),
                            associated: false,
                        },
                    );
                    p
                }
            }
        } else {
            *self.by_flow.get(&flow_key)?
        };
        let orig = *self.by_alloc.get(&(src, alloc))?;
        let nat_port = if orig.dns_tcp {
            super::DNS_TCP_NAT_PORT
        } else {
            super::TCP_NAT_PORT
        };
        set_ip_dst(frame, gateway_for(src));
        set_tcp_dst_port(frame, nat_port);
        set_tcp_src_port(frame, alloc);
        fix_checksums(frame);
        Some(OrigDst {
            addr: orig.dst_addr,
            port: orig.dst_port,
            dns_tcp: orig.dns_tcp,
        })
    }

    /// Rewrite an outbound (stack→workload) packet's source back to
    /// the recorded original destination and its destination port back
    /// to the workload's real source port. `false` when no mapping
    /// exists — the packet is dropped (an untracked RST/reply from the
    /// stack is not evidence of a flow).
    pub fn rev_nat_out(&mut self, frame: &mut [u8]) -> bool {
        // The reply's destination is the stack-side remote endpoint:
        // (workload_ip, allocated_port).
        let (_, dst_ip, _, dst_port) = match parse_tcp_tuple(frame) {
            Some(t) => t,
            None => return false,
        };
        let Some(orig) = self.by_alloc.get(&(dst_ip, dst_port)).copied() else {
            return false;
        };
        set_ip_src(frame, orig.dst_addr);
        set_tcp_src_port(frame, orig.dst_port);
        set_tcp_dst_port(frame, orig.src_port);
        fix_checksums(frame);
        true
    }

    /// The recorded original destination for a post-NAT connection —
    /// the tuple the accepted smoltcp socket reports as its remote
    /// (workload_ip, allocated_port).
    pub fn orig_for(&self, workload: IpAddr, port: u16) -> Option<OrigDst> {
        self.by_alloc.get(&(workload, port)).map(|o| OrigDst {
            addr: o.dst_addr,
            port: o.dst_port,
            dns_tcp: o.dns_tcp,
        })
    }

    /// Forget a closed connection — `port` is the stack-side
    /// (allocated) source port the smoltcp socket reported.
    pub fn remove(&mut self, workload: IpAddr, port: u16) {
        if let Some(orig) = self.by_alloc.remove(&(workload, port)) {
            self.by_flow
                .remove(&(workload, orig.src_port, orig.dst_addr, orig.dst_port));
        }
    }
}

// ---- packet surgery ------------------------------------------------

/// Parse `frame` as IPv4/TCP or IPv6/TCP; return (src, dst, src_port,
/// dst_port). `None` when the packet is too short, not bare TCP (v6
/// extension chains never reach here — the classifier drops them
/// first, and this refuses the same way), or inconsistent — callers
/// treat it as undeliverable.
fn parse_tcp_tuple(frame: &[u8]) -> Option<(IpAddr, IpAddr, u16, u16)> {
    if frame.len() < 20 {
        return None;
    }
    match frame[0] >> 4 {
        4 => {
            let ihl = usize::from(frame[0] & 0x0f) * 4;
            if ihl < 20 || frame.len() < ihl + 20 {
                return None;
            }
            if frame[9] != 6 {
                return None;
            }
            let total_len = u16::from_be_bytes([frame[2], frame[3]]) as usize;
            if total_len < ihl + 20 || frame.len() < total_len {
                return None;
            }
            let src = Ipv4Addr::new(frame[12], frame[13], frame[14], frame[15]);
            let dst = Ipv4Addr::new(frame[16], frame[17], frame[18], frame[19]);
            let sp = u16::from_be_bytes([frame[ihl], frame[ihl + 1]]);
            let dp = u16::from_be_bytes([frame[ihl + 2], frame[ihl + 3]]);
            Some((src.into(), dst.into(), sp, dp))
        }
        6 => {
            if frame.len() < 40 + 20 {
                return None;
            }
            // Only a bare TCP next-header is relayed — extension
            // chains are the classifier's drop list, and a packet that
            // slipped through here fails the same check.
            if frame[6] != 6 {
                return None;
            }
            let payload_len = u16::from_be_bytes([frame[4], frame[5]]) as usize;
            if payload_len < 20 || frame.len() < 40 + payload_len {
                return None;
            }
            let src = Ipv6Addr::from(<[u8; 16]>::try_from(&frame[8..24]).unwrap());
            let dst = Ipv6Addr::from(<[u8; 16]>::try_from(&frame[24..40]).unwrap());
            let sp = u16::from_be_bytes([frame[40], frame[41]]);
            let dp = u16::from_be_bytes([frame[42], frame[43]]);
            Some((src.into(), dst.into(), sp, dp))
        }
        _ => None,
    }
}

/// The byte offset of the TCP header — IHL for v4, the fixed 40 for
/// v6 (extension chains never reach this path).
fn l4_offset(frame: &[u8]) -> usize {
    if frame[0] >> 4 == 6 {
        40
    } else {
        usize::from(frame[0] & 0x0f) * 4
    }
}

/// The source addresses the workload legitimately emits from its side
/// of the TUN: its fixed v4 address, its fixed v6 address, and the
/// v4-mapped form a v6 socket uses when it talks to `::ffff:<v4>`.
/// Anything else is a spoofed source — the packet may rewrite against
/// an existing flow but never mints one.
fn is_workload_src(src: IpAddr) -> bool {
    match src {
        IpAddr::V4(v4) => v4 == super::WORKLOAD_V4,
        IpAddr::V6(v6) => {
            v6 == super::WORKLOAD_V6 || v6.to_ipv4_mapped() == Some(super::WORKLOAD_V4)
        }
    }
}

/// The DNAT target gateway in the packet's own family.
fn gateway_for(addr: IpAddr) -> IpAddr {
    match addr {
        IpAddr::V4(_) => super::GATEWAY_V4.into(),
        IpAddr::V6(_) => super::GATEWAY_V6.into(),
    }
}

fn set_ip_dst(frame: &mut [u8], addr: IpAddr) {
    match addr {
        IpAddr::V4(v4) => frame[16..20].copy_from_slice(&v4.octets()),
        IpAddr::V6(v6) => frame[24..40].copy_from_slice(&v6.octets()),
    }
}
fn set_ip_src(frame: &mut [u8], addr: IpAddr) {
    match addr {
        IpAddr::V4(v4) => frame[12..16].copy_from_slice(&v4.octets()),
        IpAddr::V6(v6) => frame[8..24].copy_from_slice(&v6.octets()),
    }
}
fn set_tcp_dst_port(frame: &mut [u8], port: u16) {
    let l4 = l4_offset(frame);
    frame[l4 + 2..l4 + 4].copy_from_slice(&port.to_be_bytes());
}
fn set_tcp_src_port(frame: &mut [u8], port: u16) {
    let l4 = l4_offset(frame);
    frame[l4..l4 + 2].copy_from_slice(&port.to_be_bytes());
}

/// Recompute the checksums the rewrites invalidated — the v4 header
/// checksum has no v6 counterpart (v6 headers carry none).
fn fix_checksums(frame: &mut [u8]) {
    if frame[0] >> 4 == 4 {
        fix_ipv4_checksum(frame);
    }
    fix_tcp_checksum(frame);
}

/// RFC 791 header checksum over the first `ihl` bytes.
fn fix_ipv4_checksum(frame: &mut [u8]) {
    frame[10] = 0;
    frame[11] = 0;
    let ihl = usize::from(frame[0] & 0x0f) * 4;
    let sum = checksum(&frame[..ihl], 0);
    frame[10..12].copy_from_slice(&sum.to_be_bytes());
}

/// RFC 793 / RFC 8200 checksum over pseudo-header + segment.
fn fix_tcp_checksum(frame: &mut [u8]) {
    let l4 = l4_offset(frame);
    // Pseudo-header accumulation: v6 sums the 32 address bytes plus
    // the upper-layer packet length and next-header; v4 sums the 8
    // address bytes plus protocol and TCP length — the same two
    // trailing fields once the leading-zero padding folds away.
    let mut acc: u32 = 0;
    let (seg_len, end) = if frame[0] >> 4 == 6 {
        for pair in frame[8..40].as_chunks::<2>().0 {
            acc += u16::from_be_bytes(*pair) as u32;
        }
        let payload_len = u16::from_be_bytes([frame[4], frame[5]]) as usize;
        (payload_len, 40 + payload_len)
    } else {
        for pair in frame[12..20].as_chunks::<2>().0 {
            acc += u16::from_be_bytes(*pair) as u32;
        }
        let total = u16::from_be_bytes([frame[2], frame[3]]) as usize;
        (total - l4, total)
    };
    frame[l4 + 16] = 0;
    frame[l4 + 17] = 0;
    acc += 6u32; // proto TCP
    acc += seg_len as u32;
    let sum = checksum(&frame[l4..end], acc);
    frame[l4 + 16..l4 + 18].copy_from_slice(&sum.to_be_bytes());
}

/// Internet checksum of `data` seeded with `acc` (pseudo-header sum).
fn checksum(data: &[u8], mut acc: u32) -> u16 {
    let (chunks, remainder) = data.as_chunks::<2>();
    for pair in chunks {
        acc = acc.wrapping_add(u16::from_be_bytes(*pair) as u32);
    }
    if let Some(&last) = remainder.first() {
        acc = acc.wrapping_add((last as u32) << 8);
    }
    while acc >> 16 != 0 {
        acc = (acc & 0xffff) + (acc >> 16);
    }
    !(acc as u16)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal IPv4+TCP SYN: 20B IP + 20B TCP, checksums zeroed —
    /// the DNAT path recomputes both.
    fn syn_packet() -> Vec<u8> {
        let mut f = vec![0u8; 40];
        f[0] = 0x45; // v4, ihl 20
        f[2..4].copy_from_slice(&40u16.to_be_bytes());
        f[8] = 64; // ttl
        f[9] = 6; // tcp
        f[12..16].copy_from_slice(&[10, 250, 0, 2]);
        f[16..20].copy_from_slice(&[93, 184, 216, 34]);
        f[20..22].copy_from_slice(&[0x12, 0x34]); // sport 4660
        f[22..24].copy_from_slice(&[0x01, 0xBB]); // dport 443
        f[33] = 0x02; // flags: SYN (TCP offset 13)
        f[34] = 0x40; // window 0x4000
        f
    }

    /// A minimal IPv6+TCP SYN toward `2001:db8::443:443`: 40B fixed
    /// header + 20B TCP, no extension headers.
    fn syn6_packet() -> Vec<u8> {
        let mut f = vec![0u8; 60];
        f[0] = 0x60; // v6
        f[4..6].copy_from_slice(&20u16.to_be_bytes()); // payload len
        f[6] = 6; // next header: tcp
        f[7] = 64; // hop limit
        f[8..24].copy_from_slice(&super::super::WORKLOAD_V6.octets());
        f[24..40].copy_from_slice(&"2001:db8::443:443".parse::<Ipv6Addr>().unwrap().octets());
        f[40..42].copy_from_slice(&[0x12, 0x34]); // sport 4660
        f[42..44].copy_from_slice(&[0x01, 0xBB]); // dport 443
        f[53] = 0x02; // flags: SYN (TCP offset 13)
        f[54] = 0x40; // window
        f
    }

    #[test]
    fn dnat_records_and_reverses() {
        let mut nat = NatTable::new(true);
        let mut f = syn_packet();
        let orig = nat.dnat_in(&mut f).unwrap();
        assert_eq!(orig.addr, IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)));
        assert_eq!(orig.port, 443);
        assert!(!orig.dns_tcp);
        // Now dst = gateway:nat_port, src = workload:allocated_port.
        let (s, d, sp, dp) = parse_tcp_tuple(&f).unwrap();
        assert_eq!(d, IpAddr::V4(super::super::GATEWAY_V4));
        assert_eq!(dp, super::super::TCP_NAT_PORT);
        assert_eq!((s, sp), (IpAddr::V4(super::super::WORKLOAD_V4), ALLOC_BASE));
        // Reply path: flip src/dst like a stack reply would.
        let mut r = f.clone();
        r[12..16].copy_from_slice(&[10, 250, 0, 1]);
        r[16..20].copy_from_slice(&[10, 250, 0, 2]);
        r[20..22].copy_from_slice(&super::super::TCP_NAT_PORT.to_be_bytes());
        r[22..24].copy_from_slice(&ALLOC_BASE.to_be_bytes());
        assert!(nat.rev_nat_out(&mut r));
        let (rs, rd, rsp, rdp) = parse_tcp_tuple(&r).unwrap();
        assert_eq!(rs, IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)));
        assert_eq!(rsp, 443);
        // The workload's real source port is restored.
        assert_eq!((rd, rdp), (IpAddr::V4(super::super::WORKLOAD_V4), 0x1234));
    }

    #[test]
    fn same_source_port_different_dst_gets_distinct_flows() {
        let mut nat = NatTable::new(true);
        // Raw-packet workload reuses (src,sport) toward two dests.
        let mut f1 = syn_packet();
        let mut f2 = syn_packet();
        f2[16..20].copy_from_slice(&[9, 9, 9, 9]);
        let o1 = nat.dnat_in(&mut f1).unwrap();
        let o2 = nat.dnat_in(&mut f2).unwrap();
        assert_eq!(o1.addr, IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)));
        assert_eq!(o2.addr, IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)));
        // Distinct stack-side remotes — smoltcp tells the conns apart.
        let (_, _, p1, _) = parse_tcp_tuple(&f1).unwrap();
        let (_, _, p2, _) = parse_tcp_tuple(&f2).unwrap();
        assert_ne!(p1, p2);
        // Reverse path resolves each flow to its own destination.
        let mut r = f2.clone();
        r[12..16].copy_from_slice(&[10, 250, 0, 1]);
        r[16..20].copy_from_slice(&[10, 250, 0, 2]);
        r[20..22].copy_from_slice(&super::super::TCP_NAT_PORT.to_be_bytes());
        r[22..24].copy_from_slice(&p2.to_be_bytes());
        assert!(nat.rev_nat_out(&mut r));
        let (rs, _, _, rdp) = parse_tcp_tuple(&r).unwrap();
        assert_eq!(rs, IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)));
        assert_eq!(rdp, 0x1234);
        // Removing one flow leaves the other intact.
        nat.remove(super::super::WORKLOAD_V4.into(), p2);
        let mut r2 = f1.clone();
        r2[12..16].copy_from_slice(&[10, 250, 0, 1]);
        r2[16..20].copy_from_slice(&[10, 250, 0, 2]);
        r2[20..22].copy_from_slice(&super::super::TCP_NAT_PORT.to_be_bytes());
        r2[22..24].copy_from_slice(&p1.to_be_bytes());
        assert!(nat.rev_nat_out(&mut r2));
    }

    #[test]
    fn dns_port_redirects_to_dns_listener() {
        let mut nat = NatTable::new(true);
        let mut f = syn_packet();
        f[22..24].copy_from_slice(&53u16.to_be_bytes());
        let orig = nat.dnat_in(&mut f).unwrap();
        assert!(orig.dns_tcp);
        let (_, _, _, dp) = parse_tcp_tuple(&f).unwrap();
        assert_eq!(dp, super::super::DNS_TCP_NAT_PORT);
    }

    #[test]
    fn dns_port_is_ordinary_tcp_without_a_gate() {
        // No upstream → no gate → nothing answers the DNS-over-TCP
        // listener. Port-53 flows must stay on the evaluated data
        // path so `allow <ip>:53` rules can reach a verdict.
        let mut nat = NatTable::new(false);
        let mut f = syn_packet();
        f[22..24].copy_from_slice(&53u16.to_be_bytes());
        let orig = nat.dnat_in(&mut f).unwrap();
        assert!(!orig.dns_tcp);
        let (_, _, _, dp) = parse_tcp_tuple(&f).unwrap();
        assert_eq!(dp, super::super::TCP_NAT_PORT);
    }

    #[test]
    fn non_syn_never_mints_a_mapping() {
        let mut nat = NatTable::new(true);
        // A lone ACK from the workload address is dropped — it cannot
        // create or overwrite flow state.
        let mut ack = syn_packet();
        ack[33] = 0x10; // ACK
        assert!(nat.dnat_in(&mut ack).is_none());
        assert!(nat.by_flow.is_empty() && nat.by_alloc.is_empty());
        // SYN+ACK is not an opening SYN either.
        let mut synack = syn_packet();
        synack[33] = 0x12;
        assert!(nat.dnat_in(&mut synack).is_none());
        // After a real SYN the same ACK tuple rewrites fine.
        let mut f = syn_packet();
        nat.dnat_in(&mut f).unwrap();
        let mut ack = syn_packet();
        ack[33] = 0x10;
        assert!(nat.dnat_in(&mut ack).is_some());
        // A non-workload source cannot mint even with SYN.
        let mut foreign = syn_packet();
        foreign[12..16].copy_from_slice(&[192, 0, 2, 99]);
        assert!(nat.dnat_in(&mut foreign).is_none());
    }

    #[test]
    fn saturated_table_refuses_new_flows() {
        let mut nat = NatTable::new(true);
        let mut f = syn_packet();
        // Mint MAX_NAT_MAPPINGS distinct flows via the source port.
        for i in 0..MAX_NAT_MAPPINGS {
            f[20..22].copy_from_slice(&(i as u16).to_be_bytes());
            assert!(nat.dnat_in(&mut f).is_some(), "flow {i} refused early");
        }
        // Next new flow is refused O(1) — no port scan, no state.
        f[20..22].copy_from_slice(&0xFFFFu16.to_be_bytes());
        assert!(nat.dnat_in(&mut f).is_none());
        assert_eq!(nat.by_alloc.len(), MAX_NAT_MAPPINGS);
        // A retired mapping frees one slot for the next SYN.
        nat.remove(super::super::WORKLOAD_V4.into(), ALLOC_BASE);
        assert!(nat.dnat_in(&mut f).is_some());
    }

    #[test]
    fn unassociated_mappings_expire() {
        let mut nat = NatTable::new(true);
        let mut f = syn_packet();
        nat.dnat_in(&mut f).unwrap();
        // Backdate the mint past the association deadline — a SYN the
        // workload never completed cannot hold state forever.
        let stale = Instant::now() - NAT_ASSOCIATE_DEADLINE - Duration::from_secs(1);
        for orig in nat.by_alloc.values_mut() {
            orig.minted = stale;
        }
        nat.reap_expired(Instant::now());
        assert!(nat.by_alloc.is_empty() && nat.by_flow.is_empty());
        // The freed capacity admits the next SYN.
        assert!(nat.dnat_in(&mut f).is_some());
    }

    #[test]
    fn associated_mappings_survive_reaping() {
        let mut nat = NatTable::new(true);
        let mut f = syn_packet();
        nat.dnat_in(&mut f).unwrap();
        let (_, _, alloc, _) = parse_tcp_tuple(&f).unwrap();
        nat.mark_associated(super::super::WORKLOAD_V4.into(), alloc);
        let stale = Instant::now() - NAT_ASSOCIATE_DEADLINE - Duration::from_secs(1);
        for orig in nat.by_alloc.values_mut() {
            orig.minted = stale;
        }
        nat.reap_expired(Instant::now());
        assert_eq!(nat.by_alloc.len(), 1);
        // Reverse path still resolves the live flow.
        let mut r = f.clone();
        r[12..16].copy_from_slice(&[10, 250, 0, 1]);
        r[16..20].copy_from_slice(&[10, 250, 0, 2]);
        r[20..22].copy_from_slice(&super::super::TCP_NAT_PORT.to_be_bytes());
        r[22..24].copy_from_slice(&alloc.to_be_bytes());
        assert!(nat.rev_nat_out(&mut r));
    }

    #[test]
    fn dnat_v6_records_and_reverses() {
        let mut nat = NatTable::new(true);
        let mut f = syn6_packet();
        let orig = nat.dnat_in(&mut f).unwrap();
        assert_eq!(
            orig.addr,
            IpAddr::V6("2001:db8::443:443".parse::<Ipv6Addr>().unwrap())
        );
        assert_eq!(orig.port, 443);
        assert!(!orig.dns_tcp);
        let (s, d, sp, dp) = parse_tcp_tuple(&f).unwrap();
        assert_eq!(d, IpAddr::V6(super::super::GATEWAY_V6));
        assert_eq!(dp, super::super::TCP_NAT_PORT);
        assert_eq!((s, sp), (IpAddr::V6(super::super::WORKLOAD_V6), ALLOC_BASE));
        // Reply path: the stack answers from gateway:nat_port to the
        // allocated source port.
        let mut r = f.clone();
        r[8..24].copy_from_slice(&super::super::GATEWAY_V6.octets());
        r[24..40].copy_from_slice(&super::super::WORKLOAD_V6.octets());
        r[40..42].copy_from_slice(&super::super::TCP_NAT_PORT.to_be_bytes());
        r[42..44].copy_from_slice(&ALLOC_BASE.to_be_bytes());
        assert!(nat.rev_nat_out(&mut r));
        let (rs, rd, rsp, rdp) = parse_tcp_tuple(&r).unwrap();
        assert_eq!(
            rs,
            IpAddr::V6("2001:db8::443:443".parse::<Ipv6Addr>().unwrap())
        );
        assert_eq!(rsp, 443);
        assert_eq!((rd, rdp), (IpAddr::V6(super::super::WORKLOAD_V6), 0x1234));
        // The v6 TCP checksum must be a valid one's-complement sum
        // over pseudo-header + segment.
        let mut acc = 0u32;
        for pair in r[8..40].as_chunks::<2>().0 {
            acc += u16::from_be_bytes(*pair) as u32;
        }
        acc += 6u32 + 20u32;
        for pair in r[40..60].as_chunks::<2>().0 {
            acc += u16::from_be_bytes(*pair) as u32;
        }
        while acc >> 16 != 0 {
            acc = (acc & 0xffff) + (acc >> 16);
        }
        assert_eq!(acc as u16, 0xffff, "v6 TCP checksum does not verify");
    }

    #[test]
    fn v4_mapped_syn_mints_under_the_mapped_source() {
        // A v6 socket dialing `::ffff:<v4>` emits src
        // `::ffff:10.250.0.2` — the mapped form of the workload's v4.
        // That spelling is a legitimate workload source and must mint.
        let mut nat = NatTable::new(true);
        let mut f = syn6_packet();
        let mapped_src = super::super::WORKLOAD_V4.to_ipv6_mapped();
        let mapped_dst = Ipv4Addr::new(93, 184, 216, 34).to_ipv6_mapped();
        f[8..24].copy_from_slice(&mapped_src.octets());
        f[24..40].copy_from_slice(&mapped_dst.octets());
        let orig = nat.dnat_in(&mut f).unwrap();
        assert_eq!(orig.addr, IpAddr::V6(mapped_dst));
    }

    #[test]
    fn extension_header_chain_is_not_tcp() {
        // A v6 frame whose next-header is an extension type (e.g. the
        // fragment header, 44) must not parse — the classifier drops
        // it earlier, and the NAT layer agrees independently.
        let mut nat = NatTable::new(true);
        let mut f = syn6_packet();
        f[6] = 44;
        assert!(parse_tcp_tuple(&f).is_none());
        assert!(nat.dnat_in(&mut f).is_none());
    }

    #[test]
    fn checksums_verify() {
        let mut nat = NatTable::new(true);
        let mut f = syn_packet();
        nat.dnat_in(&mut f).unwrap();
        // IPv4 checksum: stored value makes the header sum 0xffff.
        let mut acc = 0u32;
        for pair in f[..20].as_chunks::<2>().0 {
            acc += u16::from_be_bytes(*pair) as u32;
        }
        while acc >> 16 != 0 {
            acc = (acc & 0xffff) + (acc >> 16);
        }
        assert_eq!(acc as u16, 0xffff);
    }
}
