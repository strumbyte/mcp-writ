//! Wire-format layer for the proxy: inbound frame classification and
//! outbound reply construction.
//!
//! [`classify`] decides each TUN frame's fate — TCP frames pass to the
//! smoltcp stack, UDP/53 datagrams to the DNS gate, other UDP to the
//! per-datagram relay, and everything uninspectable to a counted drop
//! (the fail-closed drop list is documented in the parent `stack`
//! module docs). [`craft_udp_packet`] builds the
//! reverse-direction replies the gate and UDP relay emit toward the
//! workload. Keeping parse and build in one file keeps every
//! byte-level IP/UDP assumption — header layout, checksums, which
//! elements are dropped — next to its mirror.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

// ---------------------------------------------------------------------------
// Packet classification (reader task)
// ---------------------------------------------------------------------------

pub(super) struct UdpDgram {
    pub(super) src: IpAddr,
    pub(super) src_port: u16,
    pub(super) dst: IpAddr,
    pub(super) dst_port: u16,
    pub(super) payload: Vec<u8>,
}

pub(super) enum GateCtx {
    /// UDP DNS: reply packet is crafted dst→src, same family as the
    /// query arrived on.
    Udp {
        src: IpAddr,
        src_port: u16,
        dst: IpAddr,
        dst_port: u16,
    },
}

pub(super) struct GateReq {
    pub(super) pkt: Vec<u8>,
    pub(super) peer: SocketAddr,
    pub(super) ctx: GateCtx,
}

pub(super) enum Classified {
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
pub(super) fn classify(frame: &[u8], dns_intercept: bool) -> Classified {
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
pub(super) fn craft_udp_packet(
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
