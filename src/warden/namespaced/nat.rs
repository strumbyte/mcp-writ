//! DNAT interception for the transparent TCP path.
//!
//! smoltcp cannot listen on a wildcard port, so inbound TCP packets
//! are rewritten before they reach the stack: `dst` becomes the
//! proxy's own gateway address and a fixed listener port
//! (`TCP_NAT_PORT` for data flows, `DNS_TCP_NAT_PORT` when the
//! original destination port was 53 — DNS-over-TCP interception,
//! matching the UDP intercept).
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
//! Both directions recompute the IPv4 and TCP checksums — no
//! incremental fixups; correctness over cleverness for a PoC.

use std::collections::HashMap;
use std::net::Ipv4Addr;

/// First translated source port — stack-side only, so the ordinary
/// ephemeral range is free (collisions are resolved by scanning).
const ALLOC_BASE: u16 = 49152;

/// A recovered original destination for one intercepted flow.
#[derive(Debug, Clone, Copy)]
pub struct OrigDst {
    pub addr: Ipv4Addr,
    pub port: u16,
    /// The original destination port was 53 — this flow is a
    /// DNS-over-TCP intercept, answered by the embedded gate rather
    /// than a real socket.
    pub dns_tcp: bool,
}

/// Everything needed to reverse one flow, keyed stack-side.
#[derive(Debug, Clone, Copy)]
struct FlowOrig {
    dst_addr: Ipv4Addr,
    dst_port: u16,
    /// The workload's real source port — restored on the reverse path.
    src_port: u16,
    dns_tcp: bool,
}

/// Workload-side 4-tuple → allocated stack-side source port.
type FlowKey = (Ipv4Addr, u16, Ipv4Addr, u16);
/// Stack-side remote endpoint (workload_ip, alloc_port).
type AllocKey = (Ipv4Addr, u16);

pub struct NatTable {
    by_flow: HashMap<FlowKey, u16>,
    by_alloc: HashMap<AllocKey, FlowOrig>,
    next_alloc: u16,
}

impl NatTable {
    pub fn new() -> Self {
        Self {
            by_flow: HashMap::new(),
            by_alloc: HashMap::new(),
            next_alloc: ALLOC_BASE,
        }
    }

    /// Allocate a stack-side source port for `src`'s new flow.
    fn alloc_port(&mut self, src: Ipv4Addr) -> Option<u16> {
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

    /// Rewrite an inbound IPv4/TCP packet toward the fixed listener.
    /// Returns the recovered [`OrigDst`] (also stored for the reverse
    /// path), or `None` when the packet is not IPv4/TCP, is malformed,
    /// or has no flow behind it — callers drop those. Only a SYN
    /// (without ACK) mints a mapping: anything else may rewrite only
    /// against an existing entry — a stray or crafted segment must not
    /// mint or overwrite flow state. A SYN on an already-recorded
    /// 4-tuple reuses its translation (retransmit), while a SYN
    /// colliding on (src_ip, src_port) toward a different destination
    /// becomes a *separate* flow — never an overwrite.
    pub fn dnat_in(&mut self, frame: &mut [u8]) -> Option<OrigDst> {
        let (src, dst, src_port, dst_port) = parse_tcp_tuple(frame)?;
        let flags = frame[ihl_of(frame) + 13];
        let flow_key = (src, src_port, dst, dst_port);
        let alloc = if src == super::WORKLOAD_V4 && flags & 0x12 == 0x02 {
            match self.by_flow.get(&flow_key) {
                Some(&p) => p,
                None => {
                    let p = self.alloc_port(src)?;
                    self.by_flow.insert(flow_key, p);
                    self.by_alloc.insert(
                        (src, p),
                        FlowOrig {
                            dst_addr: dst,
                            dst_port,
                            src_port,
                            dns_tcp: dst_port == 53,
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
        set_ipv4_dst(frame, super::GATEWAY_V4);
        set_tcp_dst_port(frame, nat_port);
        set_tcp_src_port(frame, alloc);
        fix_ipv4_checksum(frame);
        fix_tcp_checksum(frame);
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
        set_ipv4_src(frame, orig.dst_addr);
        set_tcp_src_port(frame, orig.dst_port);
        set_tcp_dst_port(frame, orig.src_port);
        fix_ipv4_checksum(frame);
        fix_tcp_checksum(frame);
        true
    }

    /// The recorded original destination for a post-NAT connection —
    /// the tuple the accepted smoltcp socket reports as its remote
    /// (workload_ip, allocated_port).
    pub fn orig_for(&self, workload: Ipv4Addr, port: u16) -> Option<OrigDst> {
        self.by_alloc.get(&(workload, port)).map(|o| OrigDst {
            addr: o.dst_addr,
            port: o.dst_port,
            dns_tcp: o.dns_tcp,
        })
    }

    /// Forget a closed connection — `port` is the stack-side
    /// (allocated) source port the smoltcp socket reported.
    pub fn remove(&mut self, workload: Ipv4Addr, port: u16) {
        if let Some(orig) = self.by_alloc.remove(&(workload, port)) {
            self.by_flow
                .remove(&(workload, orig.src_port, orig.dst_addr, orig.dst_port));
        }
    }
}

// ---- packet surgery ------------------------------------------------

/// Parse `frame` as IPv4/TCP; return (src, dst, src_port, dst_port).
/// `None` when the packet is too short, not TCP, or the IHL is
/// inconsistent — callers treat it as undeliverable.
fn parse_tcp_tuple(frame: &[u8]) -> Option<(Ipv4Addr, Ipv4Addr, u16, u16)> {
    if frame.len() < 20 || frame[0] >> 4 != 4 {
        return None;
    }
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
    Some((src, dst, sp, dp))
}

fn ihl_of(frame: &[u8]) -> usize {
    usize::from(frame[0] & 0x0f) * 4
}

fn set_ipv4_dst(frame: &mut [u8], addr: Ipv4Addr) {
    frame[16..20].copy_from_slice(&addr.octets());
}
fn set_ipv4_src(frame: &mut [u8], addr: Ipv4Addr) {
    frame[12..16].copy_from_slice(&addr.octets());
}
fn set_tcp_dst_port(frame: &mut [u8], port: u16) {
    let ihl = ihl_of(frame);
    frame[ihl + 2..ihl + 4].copy_from_slice(&port.to_be_bytes());
}
fn set_tcp_src_port(frame: &mut [u8], port: u16) {
    let ihl = ihl_of(frame);
    frame[ihl..ihl + 2].copy_from_slice(&port.to_be_bytes());
}

/// RFC 791 header checksum over the first `ihl` bytes.
fn fix_ipv4_checksum(frame: &mut [u8]) {
    frame[10] = 0;
    frame[11] = 0;
    let ihl = ihl_of(frame);
    let sum = checksum(&frame[..ihl], 0);
    frame[10..12].copy_from_slice(&sum.to_be_bytes());
}

/// RFC 793 checksum over pseudo-header + segment.
fn fix_tcp_checksum(frame: &mut [u8]) {
    let ihl = ihl_of(frame);
    let total = u16::from_be_bytes([frame[2], frame[3]]) as usize;
    let seg_len = total - ihl;
    frame[ihl + 16] = 0;
    frame[ihl + 17] = 0;
    // Pseudo-header accumulation.
    let mut acc: u32 = 0;
    for pair in frame[12..20].as_chunks::<2>().0 {
        acc += u16::from_be_bytes(*pair) as u32;
    }
    acc += 6u32; // proto TCP
    acc += seg_len as u32;
    let sum = checksum(&frame[ihl..total], acc);
    frame[ihl + 16..ihl + 18].copy_from_slice(&sum.to_be_bytes());
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

    #[test]
    fn dnat_records_and_reverses() {
        let mut nat = NatTable::new();
        let mut f = syn_packet();
        let orig = nat.dnat_in(&mut f).unwrap();
        assert_eq!(orig.addr, Ipv4Addr::new(93, 184, 216, 34));
        assert_eq!(orig.port, 443);
        assert!(!orig.dns_tcp);
        // Now dst = gateway:nat_port, src = workload:allocated_port.
        let (s, d, sp, dp) = parse_tcp_tuple(&f).unwrap();
        assert_eq!(d, super::super::GATEWAY_V4);
        assert_eq!(dp, super::super::TCP_NAT_PORT);
        assert_eq!((s, sp), (super::super::WORKLOAD_V4, ALLOC_BASE));
        // Reply path: flip src/dst like a stack reply would.
        let mut r = f.clone();
        r[12..16].copy_from_slice(&[10, 250, 0, 1]);
        r[16..20].copy_from_slice(&[10, 250, 0, 2]);
        r[20..22].copy_from_slice(&super::super::TCP_NAT_PORT.to_be_bytes());
        r[22..24].copy_from_slice(&ALLOC_BASE.to_be_bytes());
        assert!(nat.rev_nat_out(&mut r));
        let (rs, rd, rsp, rdp) = parse_tcp_tuple(&r).unwrap();
        assert_eq!(rs, Ipv4Addr::new(93, 184, 216, 34));
        assert_eq!(rsp, 443);
        // The workload's real source port is restored.
        assert_eq!((rd, rdp), (super::super::WORKLOAD_V4, 0x1234));
    }

    #[test]
    fn same_source_port_different_dst_gets_distinct_flows() {
        let mut nat = NatTable::new();
        // Raw-packet workload reuses (src,sport) toward two dests.
        let mut f1 = syn_packet();
        let mut f2 = syn_packet();
        f2[16..20].copy_from_slice(&[9, 9, 9, 9]);
        let o1 = nat.dnat_in(&mut f1).unwrap();
        let o2 = nat.dnat_in(&mut f2).unwrap();
        assert_eq!(o1.addr, Ipv4Addr::new(93, 184, 216, 34));
        assert_eq!(o2.addr, Ipv4Addr::new(9, 9, 9, 9));
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
        assert_eq!(rs, Ipv4Addr::new(9, 9, 9, 9));
        assert_eq!(rdp, 0x1234);
        // Removing one flow leaves the other intact.
        nat.remove(super::super::WORKLOAD_V4, p2);
        let mut r2 = f1.clone();
        r2[12..16].copy_from_slice(&[10, 250, 0, 1]);
        r2[16..20].copy_from_slice(&[10, 250, 0, 2]);
        r2[20..22].copy_from_slice(&super::super::TCP_NAT_PORT.to_be_bytes());
        r2[22..24].copy_from_slice(&p1.to_be_bytes());
        assert!(nat.rev_nat_out(&mut r2));
    }

    #[test]
    fn dns_port_redirects_to_dns_listener() {
        let mut nat = NatTable::new();
        let mut f = syn_packet();
        f[22..24].copy_from_slice(&53u16.to_be_bytes());
        let orig = nat.dnat_in(&mut f).unwrap();
        assert!(orig.dns_tcp);
        let (_, _, _, dp) = parse_tcp_tuple(&f).unwrap();
        assert_eq!(dp, super::super::DNS_TCP_NAT_PORT);
    }

    #[test]
    fn non_syn_never_mints_a_mapping() {
        let mut nat = NatTable::new();
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
    fn checksums_verify() {
        let mut nat = NatTable::new();
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
