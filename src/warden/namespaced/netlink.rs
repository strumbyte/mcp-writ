//! Minimal rtnetlink for the init helper — just enough to bring up
//! `lo`, address the TUN interface, and install the default route that
//! pushes every workload packet onto the TUN fd.
//!
//! Implemented directly on `NETLINK_ROUTE` rather than pulling a
//! crate: the PoC needs three fixed requests and a dependency for
//! them would outweigh the ~200 lines of byte packing below.

use std::io;

use libc::{
    AF_INET, AF_NETLINK, IFF_RUNNING, IFF_UP, NETLINK_ROUTE, NLM_F_ACK, NLM_F_CREATE, NLM_F_EXCL,
    NLM_F_REQUEST, NLMSG_ERROR, RT_SCOPE_HOST, RT_SCOPE_UNIVERSE, RTA_DST, RTA_GATEWAY, RTA_OIF,
    RTM_NEWADDR, RTM_NEWLINK, RTM_NEWROUTE, RTPROT_STATIC, SOCK_RAW,
};

// The libc crate does not expose every <linux/if_addr.h> /
// <linux/rtnetlink.h> constant; these match the kernel headers.
const IFA_ADDRESS: u16 = 1;
const IFA_LOCAL: u16 = 2;
const RT_SCOPE_GLOBAL: u8 = 0;

const NLMSG_ALIGNTO: usize = 4;
const RTA_ALIGNTO: usize = 4;

fn nlmsg_align(len: usize) -> usize {
    (len + NLMSG_ALIGNTO - 1) & !(NLMSG_ALIGNTO - 1)
}
fn rta_align(len: usize) -> usize {
    (len + RTA_ALIGNTO - 1) & !(RTA_ALIGNTO - 1)
}

struct Msg {
    buf: Vec<u8>,
}

impl Msg {
    fn new(msg_type: u16, flags: u16, seq: u32, payload_len: usize) -> Self {
        let mut buf = vec![0u8; 16 + payload_len];
        let hdr = nlmsg_align(16 + payload_len) as u32;
        buf[0..4].copy_from_slice(&hdr.to_ne_bytes()); // nlmsg_len
        buf[4..6].copy_from_slice(&msg_type.to_ne_bytes());
        buf[6..8].copy_from_slice(&flags.to_ne_bytes());
        buf[8..12].copy_from_slice(&seq.to_ne_bytes());
        buf[12..16].copy_from_slice(&0u32.to_ne_bytes()); // pid
        Self { buf }
    }

    fn put_u8(&mut self, off: usize, v: u8) {
        self.buf[16 + off] = v;
    }
    fn put_u32(&mut self, off: usize, v: u32) {
        self.buf[16 + off..20 + off].copy_from_slice(&v.to_ne_bytes());
    }

    fn rta(&mut self, rta_type: u16, payload: &[u8]) {
        let len = (4 + payload.len()) as u16;
        let mut attr = Vec::with_capacity(rta_align(payload.len()) + 4);
        attr.extend_from_slice(&len.to_ne_bytes());
        attr.extend_from_slice(&rta_type.to_ne_bytes());
        attr.extend_from_slice(payload);
        attr.resize(rta_align(payload.len()) + 4 - 4 + 4, 0);
        // fix len after resize bookkeeping: attr = header + aligned payload
        attr.truncate(4 + rta_align(payload.len()));
        self.buf.extend_from_slice(&attr);
        let total = self.buf.len() as u32;
        self.buf[0..4].copy_from_slice(&total.to_ne_bytes());
    }
}

fn nl_send(req: &[u8]) -> io::Result<()> {
    let fd = unsafe { libc::socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let res = (|| {
        let mut addr: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        addr.nl_family = AF_NETLINK as u16;
        if unsafe {
            libc::sendto(
                fd,
                req.as_ptr() as *const libc::c_void,
                req.len(),
                0,
                &addr as *const libc::sockaddr_nl as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_nl>() as u32,
            )
        } < 0
        {
            return Err(io::Error::last_os_error());
        }
        // Await the ACK: NLMSG_ERROR with error==0 is success; a
        // negative error is the kernel's errno for the request.
        let mut buf = [0u8; 4096];
        let n = unsafe { libc::recv(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0) };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        let n = n as usize;
        if n < 20 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "short nlmsg"));
        }
        let msg_type = u16::from_ne_bytes([buf[4], buf[5]]);
        if msg_type as i32 == NLMSG_ERROR {
            let err = i32::from_ne_bytes([buf[16], buf[17], buf[18], buf[19]]);
            if err != 0 {
                return Err(io::Error::from_raw_os_error(-err));
            }
        }
        Ok(())
    })();
    unsafe { libc::close(fd) };
    res
}

fn if_nametoindex(name: &str) -> io::Result<u32> {
    let c = std::ffi::CString::new(name)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "interface name contains NUL"))?;
    let idx = unsafe { libc::if_nametoindex(c.as_ptr()) };
    if idx == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(idx)
    }
}

fn link_set_up(name: &str) -> io::Result<()> {
    let index = if_nametoindex(name)? as i32;
    // ifinfomsg: family u8, pad u8, type u16, index i32, flags u32, change u32 = 16B
    let mut m = Msg::new(RTM_NEWLINK, (NLM_F_REQUEST | NLM_F_ACK) as u16, 1, 16);
    m.put_u8(0, AF_INET as u8);
    m.put_u32(8, (IFF_UP | IFF_RUNNING) as u32);
    m.put_u32(12, (IFF_UP | IFF_RUNNING) as u32); // change mask
    m.buf[16 + 4..16 + 8].copy_from_slice(&index.to_ne_bytes());
    nl_send(&m.buf)
}

/// `lo` up — the workload's localhost traffic stays inside the netns.
pub fn bring_loopback_up() -> io::Result<()> {
    link_set_up("lo")
}

/// `ip addr add <addr>/<prefix> dev <ifname>` + link up.
pub fn addr_add(ifname: &str, addr: std::net::Ipv4Addr, prefix: u8) -> io::Result<()> {
    let index = if_nametoindex(ifname)? as i32;
    // ifaddrmsg: family u8, prefix u8, flags u8, scope u8, index u32 = 8B
    let mut m = Msg::new(
        RTM_NEWADDR,
        (NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL) as u16,
        2,
        8,
    );
    m.put_u8(0, AF_INET as u8);
    m.put_u8(1, prefix);
    m.put_u8(2, 0);
    // RT_SCOPE_UNIVERSE: a link-scoped address is never selected as the
    // source of routed traffic — sockets would emit src 0.0.0.0 and the
    // proxy's reply path could not reach them.
    m.put_u8(3, RT_SCOPE_UNIVERSE);
    m.put_u32(4, index as u32);
    let octets = addr.octets();
    m.rta(IFA_LOCAL, &octets);
    m.rta(IFA_ADDRESS, &octets);
    nl_send(&m.buf)?;
    link_set_up(ifname)
}

/// `ip route add default dev <ifname>` — point-to-point TUN needs no
/// gateway: every routed packet lands on our fd.
pub fn default_route_dev(ifname: &str) -> io::Result<()> {
    let index = if_nametoindex(ifname)? as i32;
    // rtmsg: family, dst_len, src_len, tos, table, protocol, scope, type, flags = 12B
    let mut m = Msg::new(
        RTM_NEWROUTE,
        (NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL) as u16,
        3,
        12,
    );
    m.put_u8(0, AF_INET as u8);
    m.put_u8(1, 0); // dst_len = default
    m.put_u8(2, 0);
    m.put_u8(3, 0);
    m.put_u8(4, libc::RT_TABLE_MAIN);
    m.put_u8(5, RTPROT_STATIC);
    m.put_u8(6, RT_SCOPE_UNIVERSE);
    m.put_u8(7, libc::RTN_UNICAST);
    m.put_u32(8, 0);
    m.rta(RTA_OIF, &index.to_ne_bytes());
    nl_send(&m.buf)
}

// Keep the referenced constants visibly used for readers checking the
// packing against <linux/rtnetlink.h>.
#[allow(dead_code)]
const _: () = {
    let _ = (
        RTA_DST,
        RTA_GATEWAY,
        RT_SCOPE_GLOBAL,
        RT_SCOPE_HOST,
        RT_SCOPE_UNIVERSE,
        IFA_ADDRESS,
        IFA_LOCAL,
    );
};
