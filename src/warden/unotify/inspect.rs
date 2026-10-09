//! `sockaddr` decode and `SO_TYPE` detection — what one `connect`
//! notification's destination is.

use std::mem::size_of;
use std::net::IpAddr;

use super::notif::read_remote;

/// What one `connect` notification's destination decoded to.
#[derive(Debug)]
pub(super) enum SockTarget {
    /// `AF_INET`/`AF_INET6` — destination address + port. IPv4-mapped
    /// IPv6 spellings fold to the IPv4 destination they name (the same
    /// fold `analyze_policy_cidr` applies to policy rules); a
    /// deprecated IPv4-*compatible* spelling (`::a.b.c.d`) stays v6 —
    /// the policy layer never folds it either.
    Inet { dest: IpAddr, port: u16 },
    /// A non-INET family (`AF_UNIX`, …) — out of this layer's scope;
    /// continued unsupervised, counted, documented.
    OtherFamily { family: u16 },
    /// The `sockaddr` could not be read or decoded — fail closed.
    Unreadable { detail: &'static str },
}

pub(super) fn parse_sockaddr(bytes: &[u8], addrlen: u64) -> SockTarget {
    if addrlen < 2 || bytes.len() < 2 {
        return SockTarget::Unreadable {
            detail: "sockaddr too short for a family",
        };
    }
    let family = u16::from_ne_bytes([bytes[0], bytes[1]]);
    match family as i32 {
        libc::AF_INET => {
            if bytes.len() < 16 || addrlen < 16 {
                return SockTarget::Unreadable {
                    detail: "sockaddr_in shorter than 16 bytes",
                };
            }
            let port = u16::from_be_bytes([bytes[2], bytes[3]]);
            let dest = IpAddr::V4(std::net::Ipv4Addr::new(
                bytes[4], bytes[5], bytes[6], bytes[7],
            ));
            SockTarget::Inet { dest, port }
        }
        libc::AF_INET6 => {
            if bytes.len() < 28 || addrlen < 28 {
                return SockTarget::Unreadable {
                    detail: "sockaddr_in6 shorter than 28 bytes",
                };
            }
            let port = u16::from_be_bytes([bytes[2], bytes[3]]);
            let mut raw = [0u8; 16];
            raw.copy_from_slice(&bytes[8..24]);
            let v6 = std::net::Ipv6Addr::from(raw);
            // Fold IPv4-mapped IPv6 (`::ffff:a.b.c.d`) to the v4
            // destination — the kernel routes it as IPv4 and the
            // policy's v4 rules must reach it. `to_ipv4_mapped` only:
            // the policy layer (`analyze_policy_cidr`,
            // `canonicalize_url_host`) folds mapped spellings and leaves
            // the deprecated compatible form (`::a.b.c.d`) in v6 space —
            // folding it here would let a v6-spelled destination slip
            // into a v4 allow rule the policy never granted it.
            let dest = v6
                .to_ipv4_mapped()
                .map(IpAddr::V4)
                .unwrap_or(IpAddr::V6(v6));
            SockTarget::Inet { dest, port }
        }
        _ => SockTarget::OtherFamily { family },
    }
}

/// Read and decode the `sockaddr` a `connect` notification carries:
/// `args[1]` is the user pointer, `args[2]` the length. The child may
/// rewrite the buffer after we read it — the read pins the *decision
/// input*, not the bytes the kernel finally uses
/// ([`LIMITATIONS`](super::LIMITATIONS)).
pub(super) fn inspect_sockaddr(pid: u32, addr: u64, addrlen: u64) -> SockTarget {
    let mut buf = [0u8; 128];
    let want = addrlen.min(buf.len() as u64);
    if addrlen == 0 || addr == 0 {
        return SockTarget::Unreadable {
            detail: "null/empty sockaddr argument",
        };
    }
    match read_remote(pid, addr, &mut buf[..want as usize]) {
        Ok(()) => parse_sockaddr(&buf[..want as usize], addrlen),
        Err(_) => SockTarget::Unreadable {
            detail: "process_vm_readv failed",
        },
    }
}

/// `SO_TYPE` of the fd the connect ran on — `pidfd_getfd` duplicates
/// the child's fd so `getsockopt` reports the real socket type.
/// `Unknown` degrades only the `proto` audit field, never the verdict.
pub(super) enum SockProto {
    Stream,
    Datagram,
    Other,
    Unknown,
}

impl SockProto {
    pub(super) fn label(&self) -> &'static str {
        match self {
            Self::Stream => "tcp",
            Self::Datagram => "udp",
            Self::Other => "other",
            Self::Unknown => "unknown",
        }
    }
}

pub(super) fn socket_proto(pid: u32, fd: u64) -> SockProto {
    // Safety: syscall args are scalars.
    let pidfd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid as libc::pid_t, 0) };
    if pidfd < 0 {
        return SockProto::Unknown;
    }
    let dup = unsafe { libc::syscall(libc::SYS_pidfd_getfd, pidfd, fd as libc::c_int, 0) };
    unsafe { libc::close(pidfd as libc::c_int) };
    if dup < 0 {
        return SockProto::Unknown;
    }
    let mut ty = 0 as libc::c_int;
    let mut len = size_of::<libc::c_int>() as libc::socklen_t;
    // Safety: `ty`/`len` are live out-buffers for getsockopt.
    let rc = unsafe {
        libc::getsockopt(
            dup as libc::c_int,
            libc::SOL_SOCKET,
            libc::SO_TYPE,
            (&mut ty as *mut libc::c_int).cast(),
            &mut len,
        )
    };
    unsafe { libc::close(dup as libc::c_int) };
    if rc != 0 {
        return SockProto::Unknown;
    }
    match ty {
        libc::SOCK_STREAM => SockProto::Stream,
        libc::SOCK_DGRAM => SockProto::Datagram,
        _ => SockProto::Other,
    }
}
