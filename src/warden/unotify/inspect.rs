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
    ///
    /// `raw` carries the pinned sockaddr bytes the supervisor read —
    /// an *allowed* connect is emulated on exactly these bytes (see
    /// `supervisor`), so a child rewrite after the read cannot reach
    /// the kernel. Folded destinations keep the original family and
    /// aux fields in `raw`: the verdict evaluates `dest` (v4 for a
    /// mapped spelling) while the emulation replays the child's own
    /// sockaddr, preserving `sin6_scope_id`/`sin6_flowinfo` semantics
    /// an `AF_INET6` socket expects.
    Inet {
        dest: IpAddr,
        port: u16,
        raw: Box<[u8]>,
    },
    /// A non-INET family (`AF_UNIX`, …) — out of this layer's
    /// destination-gating scope. `raw` still carries the pinned
    /// sockaddr bytes: a `CONTINUE` answer would re-resolve the child's
    /// *fd number* at resume time, and a sibling could `dup2` an INET
    /// socket into the slot between the `SO_DOMAIN` check and the
    /// resumed connect — so the connect is emulated on the dup'd
    /// object exactly like an allowed INET one, never continued.
    OtherFamily { family: u16, raw: Box<[u8]> },
    /// The `sockaddr` could not be read or decoded — fail closed.
    Unreadable { detail: &'static str },
}

/// Decode a sockaddr into `(dest, port)` — the pinned bytes go into
/// `SockTarget::Inet::raw` unchanged so the supervisor can emulate the
/// connect on the same sockaddr it evaluated.
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
            SockTarget::Inet {
                dest,
                port,
                raw: bytes.into(),
            }
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
            SockTarget::Inet {
                dest,
                port,
                raw: bytes.into(),
            }
        }
        _ => SockTarget::OtherFamily {
            family,
            raw: bytes.into(),
        },
    }
}

/// Read and decode the `sockaddr` a `connect` notification carries:
/// `args[1]` is the user pointer, `args[2]` the length. The read pins
/// the sockaddr — the bytes the verdict sees *are* the bytes an
/// emulated connect uses, so the TOCTOU window a `CONTINUE` answer
/// would leave (child rewrites the buffer, the kernel re-reads it)
/// does not exist on this route.
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

/// `SO_DOMAIN` of the fd the connect ran on. A socket's domain is
/// fixed at `socket(2)` — unlike the child's mutable sockaddr buffer
/// it cannot be rewritten between inspection and `CONTINUE`, so it is
/// the authoritative check that a "non-INET sockaddr" really sits on a
/// non-INET socket. `Unknown` is fail-closed (an unverifiable INET fd
/// must not be continued).
pub(super) enum SockDomain {
    Inet,
    Other,
    Unknown,
}

pub(super) fn socket_domain(pid: u32, fd: u64) -> SockDomain {
    let Some(dup) = dup_child_fd(pid, fd) else {
        return SockDomain::Unknown;
    };
    let mut dom = 0 as libc::c_int;
    let mut len = size_of::<libc::c_int>() as libc::socklen_t;
    // Safety: `dom`/`len` are live out-buffers for getsockopt.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    let rc = unsafe {
        libc::getsockopt(
            dup,
            libc::SOL_SOCKET,
            libc::SO_DOMAIN,
            (&mut dom as *mut libc::c_int).cast(),
            &mut len,
        )
    };
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    unsafe { libc::close(dup) };
    if rc != 0 {
        return SockDomain::Unknown;
    }
    match dom {
        libc::AF_INET | libc::AF_INET6 => SockDomain::Inet,
        _ => SockDomain::Other,
    }
}

/// True when `raw` pins an `AF_UNIX` sockaddr carrying a filesystem
/// pathname — `sun_path[0] != 0` (the byte after `sa_family`). A
/// pathname resolves in the *caller's* mount namespace, so emulating
/// the connect on a dup'd fd would bind the supervisor's view of that
/// path, not the child's. Abstract (`sun_path[0] == 0`) and unnamed
/// unix addresses resolve in the socket's own network namespace —
/// carried by the dup'd object — and stay emulation-safe.
pub(super) fn unix_sockaddr_is_pathname(family: u16, raw: &[u8]) -> bool {
    family as i32 == libc::AF_UNIX && raw.get(2).is_some_and(|b| *b != 0)
}

/// `pidfd_open` + `pidfd_getfd` duplicate of the child's fd — the dup
/// refers to the same file description, so its getsockopt answers the
/// child's socket's real attributes.
fn dup_child_fd(pid: u32, fd: u64) -> Option<libc::c_int> {
    // Safety: syscall args are scalars.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    let pidfd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid as libc::pid_t, 0) };
    if pidfd < 0 {
        return None;
    }
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    let dup = unsafe { libc::syscall(libc::SYS_pidfd_getfd, pidfd, fd as libc::c_int, 0) };
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    unsafe { libc::close(pidfd as libc::c_int) };
    (dup >= 0).then_some(dup as libc::c_int)
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
    let Some(dup) = dup_child_fd(pid, fd) else {
        return SockProto::Unknown;
    };
    let mut ty = 0 as libc::c_int;
    let mut len = size_of::<libc::c_int>() as libc::socklen_t;
    // Safety: `ty`/`len` are live out-buffers for getsockopt.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    let rc = unsafe {
        libc::getsockopt(
            dup,
            libc::SOL_SOCKET,
            libc::SO_TYPE,
            (&mut ty as *mut libc::c_int).cast(),
            &mut len,
        )
    };
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    unsafe { libc::close(dup) };
    if rc != 0 {
        return SockProto::Unknown;
    }
    match ty {
        libc::SOCK_STREAM => SockProto::Stream,
        libc::SOCK_DGRAM => SockProto::Datagram,
        _ => SockProto::Other,
    }
}
