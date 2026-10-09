//! Linux IP-layer PoC — a seccomp user-notification supervisor for
//! `connect(2)` (improvement plan PR-07).
//!
//! An opted-in launch (`mcp-writ unotify-run …`) runs the ordinary Linux
//! sandbox pipeline in the child's `pre_exec` — `no_new_privs` →
//! Landlock → *this module's notification filter* → the policy seccomp
//! program — with the notification stage inserted before the policy
//! filter on purpose: installing it needs `seccomp(2)` plus
//! `sendmsg(2)`/`close(2)` for the listener-fd handoff, syscalls the
//! policy allowlist may not grant the workload. Return-action
//! precedence is fixed by the kernel regardless of install order
//! (`ERRNO` still beats `USER_NOTIF`, `USER_NOTIF` beats `ALLOW`), so
//! the insertion changes nothing about which verdict a syscall gets.
//!
//! The child installs a filter that returns `SECCOMP_RET_USER_NOTIF`
//! for `connect`, `SECCOMP_RET_ALLOW` for everything else on the
//! native architecture, and `SECCOMP_RET_KILL_PROCESS` for a foreign
//! arch or an x32-ABI syscall number (both carry a syscall table this
//! filter's numbers do not line up with — an x32 task even reports the
//! native `arch` word, so the `nr >= 0x4000_0000` bound is what closes
//! that hole; killing it is the fail-closed answer). The kernel
//! hands the filter's listener fd to the child; the child passes it to
//! the supervisor over an `SCM_RIGHTS` socketpair before `exec`, and the
//! parent polls that fd.
//!
//! For each notification the supervisor:
//!
//! 1. reads the child's `sockaddr` with `process_vm_readv` (the
//!    documented alternative `/proc/<pid>/mem` needs the same
//!    ptrace-read capability; the PoC uses `process_vm_readv` only),
//! 2. revalidates the notification id
//!    (`SECCOMP_IOCTL_NOTIF_ID_VALID` — checked after the memory read
//!    so a task that died mid-handling is never answered or audited;
//!    a dead id means the triggering task was killed and needs no
//!    answer),
//! 3. decodes IPv4/IPv6 destination + port (a non-`AF_INET`/`AF_INET6`
//!    family is *not* an IP destination — it is continued unsupervised
//!    and counted, see [`LIMITATIONS`]),
//! 4. detects the socket's `SOCK_STREAM`/`SOCK_DGRAM` type through
//!    `pidfd_open` + `pidfd_getfd` + `getsockopt(SO_TYPE)` for the
//!    audit `proto` field (`"unknown"` when the fd cannot be resolved),
//! 5. evaluates the destination against the policy's IP-layer rules
//!    ([`IpLayerEvaluator`]) and the TTL-scoped dynamic grants
//!    ([`GrantSource`]),
//! 6. answers `SECCOMP_USER_NOTIF_FLAG_CONTINUE` for an allowed
//!    connect (kernel ≥ 5.5 — the syscall then runs exactly once,
//!    still through every other installed filter) after emitting a
//!    buffered `sandbox.network_allowed`, or an `EACCES` error for a
//!    denied one after committing `sandbox.network_denied` through the
//!    launch's fail-closed audit path.
//!
//! Fail-closed contract:
//!
//! - `check_support` refuses at startup when the kernel lacks user
//!   notification / `CONTINUE` — never silently degrades, regardless of
//!   `sandbox.allow_degraded` (that dial covers *Landlock* level, not
//!   this feature).
//! - Listener install or fd handoff failure aborts the spawn
//!   (`SandboxStage::Apply`/`ProcessSpawn`), not a degraded run.
//! - Supervisor death fails closed at the kernel itself: a released
//!   listener fd makes pending and future `connect` calls return
//!   `ENOSYS`; the command additionally kills the supervised child.
//! - A fail-closed audit sink that has failed flips *allowed* connects
//!   to denied — protected traffic never passes unaudited. Allowed
//!   connects are themselves recorded (`sandbox.network_allowed`,
//!   buffered like the dns-gate's allow-side records).
//! - The `sockaddr` read is a TOCTOU window: the child may rewrite the
//!   buffer between inspection and use — see [`LIMITATIONS`].
//!
//! `connect` needs to be present in `syscalls.allowed` for this layer
//! to ever see it: a policy filter that denies `connect` at `ERRNO`
//! wins over the notification (the deny stays denied — it is enforced
//! one layer lower, just unaudited here).

use std::fs::File;
use std::io;
use std::mem::size_of;
use std::net::IpAddr;
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
use std::path::{Path, PathBuf};

use crate::audit_log::{
    Action, AuditEvent, AuditLogger, EventType, Outcome, PolicyAuditContext, Severity,
};
use crate::error::{SandboxStage, WardenError};
use crate::policy::OutboundPolicy;
use crate::policy::host;

/// The syscall number watched for `connect` on this architecture.
const CONNECT_NR: u32 = libc::SYS_connect as u32;

/// `seccomp_data.arch` value for the build's own architecture — a
/// foreign-arch task's syscall table is a different table, so its
/// `connect` number is not this filter's number.
#[cfg(target_arch = "x86_64")]
const AUDIT_ARCH_NATIVE: u32 = 0xC000_003E; // AUDIT_ARCH_X86_64
#[cfg(target_arch = "aarch64")]
const AUDIT_ARCH_NATIVE: u32 = 0xC000_00B7; // AUDIT_ARCH_AARCH64
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
const AUDIT_ARCH_NATIVE: u32 = 0; // never matches — see check_support

// BPF instruction fields the kernel's `sock_filter` carries.
const BPF_LD: u16 = 0x00;
const BPF_W: u16 = 0x00;
const BPF_ABS: u16 = 0x20;
const BPF_JMP: u16 = 0x05;
const BPF_JEQ: u16 = 0x10;
const BPF_JGE: u16 = 0x30;
const BPF_K: u16 = 0x00;
const BPF_RET: u16 = 0x06;

/// `__X32_SYSCALL_BIT` — syscall numbers at or above this value belong
/// to the x32 ABI's own table, not the native table this filter was
/// written against. An x32 task reports the same `AUDIT_ARCH_X86_64`
/// `arch` word as a native one, so without this bound an x32 `connect`
/// would fail the `watched_nr` compare and land on `ALLOW`
/// unsupervised. No native nr reaches the bound on any arch we build
/// for, so the check is unconditional.
const X32_SYSCALL_BIT: u32 = 0x4000_0000;

fn stmt(code: u16, k: u32) -> libc::sock_filter {
    libc::sock_filter {
        code,
        jt: 0,
        jf: 0,
        k,
    }
}

fn jump(code: u16, k: u32, jt: u8, jf: u8) -> libc::sock_filter {
    libc::sock_filter { code, jt, jf, k }
}

/// The notification filter: `connect` → `USER_NOTIF`, anything else on
/// the native arch → `ALLOW`, a foreign arch or an x32-ABI syscall
/// number → `KILL_PROCESS` (fail-closed — both carry a syscall table
/// this program was not written against).
///
/// ```text
/// 0: ld  arch          (seccomp_data.arch)
/// 1: jeq AUDIT_ARCH_NATIVE → 2 ; else → 7
/// 2: ld  nr            (seccomp_data.nr)
/// 3: jge X32_SYSCALL_BIT   → 7 ; else → 4
/// 4: jeq connect_nr    → 5 ; else → 6
/// 5: ret USER_NOTIF
/// 6: ret ALLOW
/// 7: ret KILL_PROCESS
/// ```
fn notify_program(watched_nr: u32) -> [libc::sock_filter; 8] {
    let arch_off = std::mem::offset_of!(libc::seccomp_data, arch) as u32;
    let nr_off = std::mem::offset_of!(libc::seccomp_data, nr) as u32;
    [
        stmt(BPF_LD | BPF_W | BPF_ABS, arch_off),
        jump(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_NATIVE, 0, 5),
        stmt(BPF_LD | BPF_W | BPF_ABS, nr_off),
        jump(BPF_JMP | BPF_JGE | BPF_K, X32_SYSCALL_BIT, 3, 0),
        jump(BPF_JMP | BPF_JEQ | BPF_K, watched_nr, 0, 1),
        stmt(BPF_RET | BPF_K, libc::SECCOMP_RET_USER_NOTIF),
        stmt(BPF_RET | BPF_K, libc::SECCOMP_RET_ALLOW),
        stmt(BPF_RET | BPF_K, libc::SECCOMP_RET_KILL_PROCESS),
    ]
}

// ---------------------------------------------------------------------------
// Child-side apply (pre_exec — no allocation, syscalls only)
// ---------------------------------------------------------------------------

/// What the `pre_exec` child installs: the notification filter plus the
/// socketpair end the listener fd is handed to the parent through.
/// `program` was allocated in the parent — the child only reads it.
pub(super) struct UnotifyChild {
    program: Vec<libc::sock_filter>,
    handoff: RawFd,
}

/// Parent side of the listener handoff — the other end of the
/// socketpair. `recv_listener` collects the fd the child sent once
/// `spawn()` has returned.
pub(super) struct UnotifyParent {
    sock: File,
}

/// `seccomp(SECCOMP_SET_MODE_FILTER, NEW_LISTENER, prog)` — returns the
/// notification listener fd. Syscall-only; safe in `pre_exec`.
fn install_listener(program: &[libc::sock_filter]) -> io::Result<RawFd> {
    let fprog = libc::sock_fprog {
        len: program.len() as libc::c_ushort,
        filter: program.as_ptr() as *mut libc::sock_filter,
    };
    // Safety: `fprog` points at `program`, live for the call; the
    // returned fd is owned by the caller.
    let fd = unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            libc::SECCOMP_SET_MODE_FILTER,
            libc::SECCOMP_FILTER_FLAG_NEW_LISTENER,
            &fprog,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(fd as RawFd)
}

/// Send `listener` over `sock` as `SCM_RIGHTS` ancillary data (one
/// dummy byte of payload). No allocation; `pre_exec`-safe.
fn send_listener(sock: RawFd, listener: RawFd) -> io::Result<()> {
    let mut byte = [0u8; 1];
    let iov = libc::iovec {
        iov_base: byte.as_mut_ptr().cast(),
        iov_len: 1,
    };
    let mut control = [0u8; 64];
    // Safety: `msg` points at live locals; `control` is large enough
    // for one SCM_RIGHTS fd (CMSG_SPACE(4) == 24 on LP64).
    unsafe {
        let mut msg: libc::msghdr = std::mem::zeroed();
        msg.msg_iov = &iov as *const _ as *mut _;
        msg.msg_iovlen = 1;
        msg.msg_control = control.as_mut_ptr().cast();
        msg.msg_controllen = control.len();
        let cmsg = libc::CMSG_FIRSTHDR(&msg);
        if cmsg.is_null() {
            return Err(io::Error::from_raw_os_error(libc::EINVAL));
        }
        (*cmsg).cmsg_level = libc::SOL_SOCKET;
        (*cmsg).cmsg_type = libc::SCM_RIGHTS;
        (*cmsg).cmsg_len = libc::CMSG_LEN(size_of::<RawFd>() as u32) as usize;
        std::ptr::write(libc::CMSG_DATA(cmsg).cast::<RawFd>(), listener);
        msg.msg_controllen = libc::CMSG_SPACE(size_of::<RawFd>() as u32) as usize;
        if libc::sendmsg(sock, &msg, libc::MSG_NOSIGNAL) < 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

impl UnotifyChild {
    /// The `pre_exec` step: install the notification filter (listener
    /// fd returned by the kernel), hand it to the parent, close the
    /// child's copy — the fd survives in the parent, and the filter's
    /// notification state survives `exec`.
    pub(super) fn apply(&self) -> io::Result<()> {
        let listener = install_listener(&self.program)?;
        let sent = send_listener(self.handoff, listener);
        // Closing our copy is safe: the parent holds a reference from
        // SCM_RIGHTS and the kernel keeps the notification object
        // alive for the filter. A send failure still reports below.
        unsafe { libc::close(listener) };
        sent
    }
}

/// Arm the PoC stage on a prepared sandbox: build the handoff
/// socketpair and stage the child-side artifacts. Parent-side,
/// allocation-ful — call before `attach_linux_pre_exec*`.
pub(super) fn enable_unotify(
    bits: &mut super::linux_spawn::LinuxSandboxBits,
) -> Result<UnotifyParent, WardenError> {
    if AUDIT_ARCH_NATIVE == 0 {
        return Err(WardenError::sandbox_setup(
            SandboxStage::Prepare,
            "seccomp user-notification PoC is built only for x86_64/aarch64",
        ));
    }
    let mut pair = [0 as RawFd; 2];
    // Safety: standard socketpair; `pair` receives two owned fds.
    let rc = unsafe {
        libc::socketpair(
            libc::AF_UNIX,
            libc::SOCK_DGRAM | libc::SOCK_CLOEXEC,
            0,
            pair.as_mut_ptr(),
        )
    };
    if rc < 0 {
        return Err(WardenError::sandbox_setup(
            SandboxStage::Prepare,
            format!(
                "seccomp user-notification socketpair failed: {}",
                io::Error::last_os_error()
            ),
        ));
    }
    bits.unotify = Some(UnotifyChild {
        program: notify_program(CONNECT_NR).to_vec(),
        handoff: pair[0],
    });
    // Safety: `pair[1]` is a live fd owned by this call.
    let sock = unsafe { File::from_raw_fd(pair[1]) };
    Ok(UnotifyParent { sock })
}

impl UnotifyParent {
    /// Receive the listener fd the child's `pre_exec` sent. Bounded by
    /// a poll timeout — a spawn that succeeded without handing the fd
    /// over is a bug, but the error must surface rather than hang.
    pub(super) fn recv_listener(&self) -> io::Result<File> {
        let fd = self.sock.as_raw_fd();
        let mut pfd = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        // Safety: `pfd` lives for the call.
        let rc = unsafe { libc::poll(&mut pfd, 1, 10_000) };
        if rc <= 0 {
            return Err(if rc == 0 {
                io::Error::new(io::ErrorKind::TimedOut, "listener handoff timed out")
            } else {
                io::Error::last_os_error()
            });
        }
        let mut byte = [0u8; 1];
        let mut iov = libc::iovec {
            iov_base: byte.as_mut_ptr().cast(),
            iov_len: 1,
        };
        let mut control = [0u8; 64];
        // Safety: same layout the child wrote; `control` fits one fd.
        unsafe {
            let mut msg: libc::msghdr = std::mem::zeroed();
            msg.msg_iov = &mut iov as *mut _;
            msg.msg_iovlen = 1;
            msg.msg_control = control.as_mut_ptr().cast();
            msg.msg_controllen = control.len();
            let n = libc::recvmsg(fd, &mut msg, libc::MSG_CMSG_CLOEXEC);
            if n <= 0 {
                return Err(if n == 0 {
                    io::Error::new(io::ErrorKind::UnexpectedEof, "handoff socket closed")
                } else {
                    io::Error::last_os_error()
                });
            }
            // A truncated or undersized control block can never carry a
            // complete fd — reject before trusting the cmsg layout.
            if msg.msg_flags & libc::MSG_CTRUNC != 0
                || msg.msg_controllen < libc::CMSG_LEN(size_of::<RawFd>() as u32) as usize
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "listener handoff control data truncated",
                ));
            }
            let cmsg = libc::CMSG_FIRSTHDR(&msg);
            if cmsg.is_null()
                || (*cmsg).cmsg_level != libc::SOL_SOCKET
                || (*cmsg).cmsg_type != libc::SCM_RIGHTS
                || (*cmsg).cmsg_len < libc::CMSG_LEN(size_of::<RawFd>() as u32) as usize
            {
                // A datagram without an fd is a diagnostic byte the
                // child sent instead of the listener (e.g. `b'N'` when
                // it could not set no_new_privs) — surface it.
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "listener handoff carried no fd (diagnostic byte {:?})",
                        byte[0] as char
                    ),
                ));
            }
            let listener = libc::CMSG_DATA(cmsg).cast::<RawFd>().read_unaligned();
            Ok(File::from_raw_fd(listener))
        }
    }
}

// ---------------------------------------------------------------------------
// Supervisor-side kernel interface
// ---------------------------------------------------------------------------

/// Block until a task under the filter performs a watched syscall.
fn notify_recv(listener: RawFd) -> io::Result<libc::seccomp_notif> {
    let mut notif: libc::seccomp_notif = unsafe { std::mem::zeroed() };
    // Safety: `notif` is live and sized per the kernel ABI.
    let rc = unsafe { libc::ioctl(listener, libc::SECCOMP_IOCTL_NOTIF_RECV, &raw mut notif) };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(notif)
}

/// `true` while the notification's task still waits for an answer.
/// `arg` is the notification id *by value* (the uapi's `_IOW` encodes
/// the size only).
fn notify_id_valid(listener: RawFd, id: u64) -> bool {
    // Safety: scalar ioctl argument, no pointer.
    unsafe { libc::ioctl(listener, libc::SECCOMP_IOCTL_NOTIF_ID_VALID, id) == 0 }
}

/// Deliver the response to a pending notification. `ENOENT` means the
/// triggering task died in the meantime — counted, not fatal.
fn notify_send(listener: RawFd, resp: &libc::seccomp_notif_resp) -> io::Result<()> {
    // Safety: `resp` is live and sized per the kernel ABI.
    let rc = unsafe { libc::ioctl(listener, libc::SECCOMP_IOCTL_NOTIF_SEND, resp) };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Read exactly `buf.len()` bytes at `addr` in task `pid`'s address
/// space (works on a thread id too — the memory is shared).
fn read_remote(pid: u32, addr: u64, buf: &mut [u8]) -> io::Result<()> {
    let local = libc::iovec {
        iov_base: buf.as_mut_ptr().cast(),
        iov_len: buf.len(),
    };
    let remote = libc::iovec {
        iov_base: addr as usize as *mut libc::c_void,
        iov_len: buf.len(),
    };
    // Safety: both iovecs describe live, correctly-sized buffers.
    let n = unsafe {
        libc::syscall(
            libc::SYS_process_vm_readv,
            pid as libc::pid_t,
            &local,
            1,
            &remote,
            1,
            0,
        )
    };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    if n as usize != buf.len() {
        return Err(io::Error::from_raw_os_error(libc::EIO));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// sockaddr decode
// ---------------------------------------------------------------------------

/// What one `connect` notification's destination decoded to.
#[derive(Debug)]
enum SockTarget {
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

fn parse_sockaddr(bytes: &[u8], addrlen: u64) -> SockTarget {
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
/// input*, not the bytes the kernel finally uses ([`LIMITATIONS`]).
fn inspect_sockaddr(pid: u32, addr: u64, addrlen: u64) -> SockTarget {
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
enum SockProto {
    Stream,
    Datagram,
    Other,
    Unknown,
}

impl SockProto {
    fn label(&self) -> &'static str {
        match self {
            Self::Stream => "tcp",
            Self::Datagram => "udp",
            Self::Other => "other",
            Self::Unknown => "unknown",
        }
    }
}

fn socket_proto(pid: u32, fd: u64) -> SockProto {
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

// ---------------------------------------------------------------------------
// IP-layer evaluator — the policy's static CIDR/literal rules, in the
// same order `dnsgate::name_policy` decides the name layer.
// ---------------------------------------------------------------------------

/// One connect verdict — `rule` is the matching policy text when one
/// exists, `decision` the `sandbox.network_denied` vocabulary
/// (`deny-host`/`deny-cidr`/`not-allowed`, mirroring
/// `dnsgate::name_policy::DenyReason::decision`).
#[derive(Debug, PartialEq, Eq)]
pub enum IpVerdict {
    Allow {
        basis: &'static str,
        rule: Option<String>,
    },
    Deny {
        decision: &'static str,
        rule: Option<String>,
    },
}

/// The IP-layer half of `OutboundPolicy`, pre-projected for the
/// supervisor: literal `host=` entries stand as `/32`/`/128` routes
/// (a literal needs no resolution — the same projection
/// `OutboundPolicy::ip_layer_allows`/`ip_layer_denies` documents),
/// `cidr=` rules stay canonical.
pub struct IpLayerEvaluator {
    deny_all_others: bool,
    denied_any: bool,
    denied_literals: Vec<IpAddr>,
    denied_cidrs: Vec<String>,
    allow_any: bool,
    allowed_literals: Vec<IpAddr>,
    allowed_cidrs: Vec<String>,
}

impl IpLayerEvaluator {
    /// Build the evaluator, refusing what this layer cannot express:
    /// an `allow` entry carrying an explicit `:port` would widen to
    /// every port at the IP layer — the same refusal contract PSEC
    /// applies (`allowed_*_port_qualified` provenance lists).
    pub fn new(outbound: &OutboundPolicy) -> Result<Self, String> {
        let ported: Vec<String> = outbound
            .allowed_port_qualified
            .iter()
            .filter(|raw| outbound.allowed.contains(&host::normalize_policy_host(raw)))
            .map(|e| format!("'{e}'"))
            .collect();
        let ported_cidrs: Vec<String> = outbound
            .allowed_cidrs_port_qualified
            .iter()
            .filter(|raw| {
                host::analyze_policy_cidr(raw)
                    .map(|(cidr, _)| outbound.allowed_cidrs.contains(&cidr))
                    .unwrap_or(false)
            })
            .map(|e| format!("'{e}'"))
            .collect();
        let mut refused = ported;
        refused.extend(ported_cidrs);
        if !refused.is_empty() {
            return Err(format!(
                "outbound allow entries {} carry a port qualifier the IP layer \
                 cannot express — drop the port (every port to the destination \
                 is allowed) or do not use unotify-run",
                refused.join(", ")
            ));
        }
        // A `deny host=` on a name (or wildcard suffix) is inert at this
        // layer — a connect arrives as an address, never a hostname, and
        // grants only ever *allow*. Say so instead of leaving the rule
        // looking enforced.
        let name_only_denies: Vec<&str> = outbound
            .denied_hosts
            .iter()
            .map(String::as_str)
            .filter(|h| *h != "*" && !host::host_is_ip_literal(h))
            .collect();
        if !name_only_denies.is_empty() {
            tracing::warn!(
                rules = ?name_only_denies,
                "deny host rules on names are name-layer only — the IP layer \
                 never sees a hostname, so they stay unenforced here; dns-gate \
                 is the name-layer enforcement point"
            );
        }
        Ok(Self {
            deny_all_others: outbound.deny_all_others,
            denied_any: outbound.denied_hosts.iter().any(|d| d == "*"),
            denied_literals: outbound
                .denied_hosts
                .iter()
                .filter_map(|h| h.parse::<IpAddr>().ok())
                .collect(),
            denied_cidrs: outbound.denied_cidrs.clone(),
            allow_any: outbound.allowed.iter().any(|a| a == "*"),
            allowed_literals: outbound
                .allowed
                .iter()
                .filter_map(|h| h.parse::<IpAddr>().ok())
                .collect(),
            allowed_cidrs: outbound.allowed_cidrs.clone(),
        })
    }

    /// Decide one destination. `grant_names` is the live dynamic-grant
    /// set for `dest` (empty = no grant). Deny always precedes allow —
    /// a denied rule wins over every allow source, grants included.
    pub fn evaluate(&self, dest: &IpAddr, grant_names: &[String]) -> IpVerdict {
        if self.denied_any {
            return IpVerdict::Deny {
                decision: "deny-host",
                rule: Some("*".to_string()),
            };
        }
        if self.denied_literals.contains(dest) {
            return IpVerdict::Deny {
                decision: "deny-host",
                rule: Some(dest.to_string()),
            };
        }
        if let Some(rule) = self
            .denied_cidrs
            .iter()
            .find(|c| host::cidr_contains(c, dest))
        {
            return IpVerdict::Deny {
                decision: "deny-cidr",
                rule: Some(rule.clone()),
            };
        }
        if self.allow_any {
            return IpVerdict::Allow {
                basis: "allow-host",
                rule: Some("*".to_string()),
            };
        }
        if self.allowed_literals.contains(dest) {
            return IpVerdict::Allow {
                basis: "allow-host",
                rule: Some(dest.to_string()),
            };
        }
        if let Some(rule) = self
            .allowed_cidrs
            .iter()
            .find(|c| host::cidr_contains(c, dest))
        {
            return IpVerdict::Allow {
                basis: "allow-cidr",
                rule: Some(rule.clone()),
            };
        }
        if !grant_names.is_empty() {
            return IpVerdict::Allow {
                basis: "allowlist-grant",
                rule: Some(grant_names.join(",")),
            };
        }
        if self.deny_all_others {
            return IpVerdict::Deny {
                decision: "not-allowed",
                rule: None,
            };
        }
        IpVerdict::Allow {
            basis: "open",
            rule: None,
        }
    }
}

// ---------------------------------------------------------------------------
// Dynamic grants — the PR-06 TTL-scoped allow list.
// ---------------------------------------------------------------------------

/// Where live grants come from. The snapshot-file variant is the real
/// cross-process contract (`dns-gate --allowlist-export`); the
/// in-process variant pairs a supervisor with an embedded gate.
pub enum GrantSource {
    /// No dynamic source — static rules decide alone.
    None,
    /// Watch a `DynamicAllowList::export_to` snapshot — reloaded when
    /// the file changes; a missing/removed file is an empty grant set
    /// (fail closed).
    SnapshotFile(PathBuf),
    /// Consume the in-process allowlist directly.
    InProcess(std::sync::Arc<crate::dnsgate::DynamicAllowList>),
}

struct SnapshotGrant {
    addr: IpAddr,
    name: String,
    expires_at_unix_secs: u64,
}

struct Grants {
    source: GrantSource,
    // Snapshot-file cache state.
    sig: Option<(std::time::SystemTime, u64)>,
    entries: Vec<SnapshotGrant>,
}

impl Grants {
    fn new(source: GrantSource) -> Self {
        Self {
            source,
            sig: None,
            entries: Vec::new(),
        }
    }

    /// Live grant names covering `addr` — the TTL check against the
    /// caller's own clock is what keeps the snapshot's expiry contract.
    fn live_names(&mut self, addr: &IpAddr) -> Vec<String> {
        match &self.source {
            GrantSource::None => Vec::new(),
            GrantSource::InProcess(list) => list.names_for(addr),
            GrantSource::SnapshotFile(path) => {
                refresh_entries(path, &mut self.sig, &mut self.entries);
                let now = unix_secs_now();
                let mut names: Vec<String> = self
                    .entries
                    .iter()
                    .filter(|g| g.addr == *addr && g.expires_at_unix_secs > now)
                    .map(|g| g.name.clone())
                    .collect();
                names.sort();
                names
            }
        }
    }
}

/// Re-read the snapshot when it changed (mtime+len signature); an
/// absent or unparsable file leaves an empty grant set.
fn refresh_entries(
    path: &Path,
    sig: &mut Option<(std::time::SystemTime, u64)>,
    entries: &mut Vec<SnapshotGrant>,
) {
    let new_sig = std::fs::metadata(path)
        .ok()
        .and_then(|m| m.modified().ok().map(|t| (t, m.len())));
    if new_sig == *sig {
        return;
    }
    *sig = new_sig;
    *entries = match new_sig {
        Some(_) => std::fs::read_to_string(path)
            .ok()
            .map(|body| parse_snapshot(&body))
            .unwrap_or_default(),
        None => Vec::new(),
    };
}

fn unix_secs_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Parse the `DynamicAllowList::snapshot_json` contract:
/// `{"schema_version":"1.0","generated_at_unix_secs":N,"entries":
/// [{"name","addr","expires_at_unix_secs"}]}`. Anything unparsable
/// degrades to an empty grant set — never a guess.
fn parse_snapshot(body: &str) -> Vec<SnapshotGrant> {
    let parsed = match nojson::RawJson::parse(body) {
        Ok(p) => p,
        Err(_) => return Vec::new(),
    };
    fn member<'t, 'r>(
        v: nojson::RawJsonValue<'t, 'r>,
        key: &str,
    ) -> Option<nojson::RawJsonValue<'t, 'r>> {
        v.to_member(key).ok()?.required().ok()
    }
    let Some(entries) = member(parsed.value(), "entries").and_then(|v| v.to_array().ok()) else {
        return Vec::new();
    };
    entries
        .filter_map(|e| {
            let name = member(e, "name")?.to_unquoted_string_str().ok()?;
            let addr = member(e, "addr")?
                .to_unquoted_string_str()
                .ok()?
                .parse::<IpAddr>()
                .ok()?;
            let exp = member(e, "expires_at_unix_secs")?
                .as_number_str()
                .ok()?
                .parse::<u64>()
                .ok()?;
            Some(SnapshotGrant {
                addr,
                name: name.into_owned(),
                expires_at_unix_secs: exp,
            })
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Capability probe — startup refusal diagnostics
// ---------------------------------------------------------------------------

/// Verify the kernel supports what the supervisor needs. Refuses with a
/// stage-named diagnostic when any piece is missing — never silently
/// degrades; `sandbox.allow_degraded` does not cover this check.
///
/// Probes, in order:
/// 1. `seccomp(SECCOMP_GET_NOTIF_SIZES)` — the user-notification API
///    and the kernel's view of the ABI struct sizes.
/// 2. A live round trip: a forked child installs the real connect
///    filter, hands over its listener fd, and calls `connect` — the
///    parent answers `SECCOMP_USER_NOTIF_FLAG_CONTINUE`, proving both
///    notification delivery and the continue flag (kernel ≥ 5.5).
pub fn check_support() -> Result<(), String> {
    if AUDIT_ARCH_NATIVE == 0 {
        return Err("seccomp user notification is implemented for x86_64/aarch64 only".into());
    }
    let mut sizes: libc::seccomp_notif_sizes = unsafe { std::mem::zeroed() };
    // Safety: `sizes` is live and sized per the kernel ABI.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            libc::SECCOMP_GET_NOTIF_SIZES,
            &mut sizes,
            0,
        )
    };
    if rc != 0 {
        return Err(format!(
            "seccomp(SECCOMP_GET_NOTIF_SIZES) failed: {} — the kernel lacks \
             user-notification support (needs Linux ≥ 5.0; CONTINUE needs ≥ 5.5)",
            io::Error::last_os_error()
        ));
    }
    if (sizes.seccomp_notif as usize) < size_of::<libc::seccomp_notif>()
        || (sizes.seccomp_notif_resp as usize) < size_of::<libc::seccomp_notif_resp>()
        || (sizes.seccomp_data as usize) < size_of::<libc::seccomp_data>()
    {
        return Err(format!(
            "kernel reports smaller seccomp-notify structs ({}/{}/{}) than this \
             build uses ({}/{}/{}) — ABI mismatch",
            sizes.seccomp_notif,
            sizes.seccomp_notif_resp,
            sizes.seccomp_data,
            size_of::<libc::seccomp_notif>(),
            size_of::<libc::seccomp_notif_resp>(),
            size_of::<libc::seccomp_data>(),
        ));
    }
    continue_round_trip()
}

/// The live part of [`check_support`]: fork a probe child that installs
/// the real filter and calls `connect(127.0.0.1:9)`; the parent proves
/// the notification arrives and `CONTINUE` is honored. The child never
/// execs — it performs only async-signal-safe syscalls, so the fork is
/// safe even from a multithreaded process.
fn continue_round_trip() -> Result<(), String> {
    let mut pair = [0 as RawFd; 2];
    // Safety: `pair` receives two owned fds.
    if unsafe {
        libc::socketpair(
            libc::AF_UNIX,
            libc::SOCK_DGRAM | libc::SOCK_CLOEXEC,
            0,
            pair.as_mut_ptr(),
        )
    } < 0
    {
        return Err(format!(
            "probe socketpair failed: {}",
            io::Error::last_os_error()
        ));
    }
    // Safety: fork; the child below runs syscall-only code then _exit.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        unsafe {
            libc::close(pair[0]);
            libc::close(pair[1]);
        }
        return Err(format!("probe fork failed: {}", io::Error::last_os_error()));
    }
    if pid == 0 {
        // Child — plain syscalls only, never returns to Rust.
        let byte = unsafe {
            // seccomp(2) refuses filter installs without no_new_privs
            // (or CAP_SYS_ADMIN) — set it first so the probe measures
            // the mechanism, not the ambient privilege. An nnp refusal
            // is reported identifiably, not as a listener failure.
            if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
                b'N'
            } else {
                let program = notify_program(CONNECT_NR);
                match install_listener(&program) {
                    Err(_) => b'L', // listener install failed
                    Ok(listener) => {
                        let _ = send_listener(pair[0], listener);
                        libc::close(listener);
                        let s = libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0);
                        if s < 0 {
                            b'S' // socket() failed
                        } else {
                            // sockaddr_in: family, port 9 (discard), 127.0.0.1
                            let mut sa = [0u8; 16];
                            sa[0..2].copy_from_slice(&(libc::AF_INET as u16).to_ne_bytes());
                            sa[2..4].copy_from_slice(&9u16.to_be_bytes());
                            sa[4..8].copy_from_slice(&[127, 0, 0, 1]);
                            let rc = libc::connect(s, sa.as_ptr().cast(), 16);
                            libc::close(s);
                            // Any connect() return proves CONTINUE ran the
                            // syscall — ECONNREFUSED is the expected refusal.
                            if rc < 0 && *libc::__errno_location() == libc::ENOSYS {
                                b'C' // notification killed: listener dead/CONTINUE broken
                            } else {
                                b'R' // ran
                            }
                        }
                    }
                }
            }
        };
        unsafe {
            libc::send(pair[0], &byte as *const u8 as *const libc::c_void, 1, 0);
            libc::_exit(0);
        }
    }
    unsafe { libc::close(pair[0]) };
    let sock = unsafe { File::from_raw_fd(pair[1]) };
    let result = probe_parent(pid, &sock);
    // Reap the probe child whatever happened.
    let mut status = 0;
    unsafe { libc::waitpid(pid, &mut status, 0) };
    result
}

fn probe_parent(pid: libc::pid_t, sock: &File) -> Result<(), String> {
    // Borrow via a dup so this helper never owns `sock`.
    let dup_sock = unsafe { File::from_raw_fd(libc::dup(sock.as_raw_fd())) };
    let listener = match (UnotifyParent { sock: dup_sock }).recv_listener() {
        Ok(l) => l,
        Err(e) => {
            unsafe { libc::kill(pid, libc::SIGKILL) };
            return Err(format!("listener handoff failed in probe: {e}"));
        }
    };
    // Wait for the child's connect notification.
    let mut pfd = libc::pollfd {
        fd: listener.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    if unsafe { libc::poll(&mut pfd, 1, 10_000) } <= 0 {
        unsafe { libc::kill(pid, libc::SIGKILL) };
        return Err("probe notification never arrived (no connect event)".into());
    }
    let notif = match notify_recv(listener.as_raw_fd()) {
        Ok(n) => n,
        Err(e) => {
            unsafe { libc::kill(pid, libc::SIGKILL) };
            return Err(format!("SECCOMP_IOCTL_NOTIF_RECV failed: {e}"));
        }
    };
    let resp = libc::seccomp_notif_resp {
        id: notif.id,
        val: 0,
        error: 0,
        flags: libc::SECCOMP_USER_NOTIF_FLAG_CONTINUE as u32,
    };
    if let Err(e) = notify_send(listener.as_raw_fd(), &resp) {
        unsafe { libc::kill(pid, libc::SIGKILL) };
        return Err(format!(
            "SECCOMP_USER_NOTIF_FLAG_CONTINUE refused: {e} — kernel lacks continue support (needs Linux ≥ 5.5)"
        ));
    }
    // Read the child's status byte.
    let mut pfd2 = libc::pollfd {
        fd: sock.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    if unsafe { libc::poll(&mut pfd2, 1, 5_000) } <= 0 {
        unsafe { libc::kill(pid, libc::SIGKILL) };
        return Err("probe child stopped answering".into());
    }
    let mut byte = [0u8; 1];
    if unsafe { libc::recv(sock.as_raw_fd(), byte.as_mut_ptr().cast(), 1, 0) } != 1 {
        return Err("probe child exited without a status byte".into());
    }
    match byte[0] {
        b'R' => Ok(()),
        b'N' => Err("probe child could not set no_new_privs".into()),
        b'L' => Err("probe child failed to install the notification filter".into()),
        b'S' => Err("probe child could not create a socket".into()),
        b'C' => Err("the continued connect returned ENOSYS — notification channel broken".into()),
        other => Err(format!("probe child returned unexpected status {other:#x}")),
    }
}

// ---------------------------------------------------------------------------
// Supervisor loop
// ---------------------------------------------------------------------------

/// What the supervisor needs: the policy projection, the grant source,
/// the audit sink and correlation context.
pub struct SupervisorConfig {
    pub evaluator: IpLayerEvaluator,
    pub grants: GrantSource,
    pub logger: AuditLogger,
    pub launch_id: uuid::Uuid,
    pub policy_context: Option<PolicyAuditContext>,
}

/// Counters the report's capability block carries — what the
/// supervisor observably did, not a claim about every syscall.
#[derive(Debug, Default, Clone)]
pub struct SupervisorStats {
    /// Notifications received.
    pub notifications: u64,
    /// `connect` allowed by policy → `CONTINUE` sent.
    pub continued: u64,
    /// `connect` denied → `EACCES` sent after the audit record.
    pub denied: u64,
    /// Non-INET-family connects passed through unsupervised.
    pub noninet_skipped: u64,
    /// Notifications answered with a deny because the destination
    /// could not be read or decoded (fail closed).
    pub unreadable_denied: u64,
    /// Notifications whose task died before/while answering
    /// (ID_VALID failed, or SEND raced the death) — benign.
    pub expired: u64,
    /// Denial emitted because the fail-closed audit sink was dead
    /// (an allow verdict flipped to deny).
    pub audit_unavailable_denied: u64,
    /// SEND failures other than the dead-notification race.
    pub send_errors: u64,
    /// Denied-connect audit records whose commit failed.
    pub audit_errors: u64,
}

/// Why the supervisor loop exited.
#[derive(Debug)]
pub enum SupervisorExit {
    /// The stop fd was signalled (command-initiated shutdown).
    Shutdown,
    /// The listener/loop failed — monitoring is gone. The kernel makes
    /// pending + future connects fail (`ENOSYS`), and the command kills
    /// the supervised child — fail closed.
    Lost(String),
}

/// The supervisor's exit record: reason plus the counters it reached.
pub struct SupervisorEnd {
    pub reason: SupervisorExit,
    pub stats: SupervisorStats,
}

/// A running supervisor — the blocking notification loop on a
/// `spawn_blocking` task plus the eventfd the stop side writes.
pub struct Supervisor {
    task: tokio::task::JoinHandle<SupervisorEnd>,
    stop: File,
}

impl Supervisor {
    /// Start supervising `listener` — one blocking task per supervised
    /// launch. Must be called from inside the tokio runtime.
    pub fn start(listener: File, cfg: SupervisorConfig) -> io::Result<Self> {
        // Safety: eventfd creates a live fd; EFD_CLOEXEC keeps it out
        // of any exec'd image.
        let stop_raw = unsafe { libc::eventfd(0, libc::EFD_CLOEXEC) };
        if stop_raw < 0 {
            return Err(io::Error::last_os_error());
        }
        let stop = unsafe { File::from_raw_fd(stop_raw) };
        let loop_stop = stop.try_clone()?;
        let task = tokio::task::spawn_blocking(move || {
            let mut sup = Loop {
                listener,
                stop: loop_stop,
                evaluator: cfg.evaluator,
                grants: Grants::new(cfg.grants),
                logger: cfg.logger,
                launch_id: cfg.launch_id,
                policy_ctx: cfg.policy_context,
                stats: SupervisorStats::default(),
            };
            sup.run()
        });
        Ok(Self { task, stop })
    }

    /// The supervisor's exit future for `tokio::select!` — resolves the
    /// moment the loop ends for any reason (that's the fail-closed
    /// signal the command must act on while the child lives).
    pub fn exited(&mut self) -> &mut tokio::task::JoinHandle<SupervisorEnd> {
        &mut self.task
    }

    /// Signal the loop to stop and await its exit record.
    pub async fn shutdown(self) -> SupervisorEnd {
        let byte = 1u64.to_ne_bytes();
        // Safety: `stop` is a live eventfd; 8 bytes is the eventfd write.
        unsafe {
            libc::write(
                self.stop.as_raw_fd(),
                byte.as_ptr().cast::<std::ffi::c_void>(),
                8,
            )
        };
        match self.task.await {
            Ok(end) => end,
            Err(e) => SupervisorEnd {
                reason: SupervisorExit::Lost(format!("supervisor task join failed: {e}")),
                stats: SupervisorStats::default(),
            },
        }
    }
}

struct Loop {
    listener: File,
    stop: File,
    evaluator: IpLayerEvaluator,
    grants: Grants,
    logger: AuditLogger,
    launch_id: uuid::Uuid,
    policy_ctx: Option<PolicyAuditContext>,
    stats: SupervisorStats,
}

impl Loop {
    fn run(&mut self) -> SupervisorEnd {
        let listener_fd = self.listener.as_raw_fd();
        let stop_fd = self.stop.as_raw_fd();
        loop {
            let mut pfds = [
                libc::pollfd {
                    fd: listener_fd,
                    events: libc::POLLIN,
                    revents: 0,
                },
                libc::pollfd {
                    fd: stop_fd,
                    events: libc::POLLIN,
                    revents: 0,
                },
            ];
            // Safety: `pfds` is live for the call.
            let rc = unsafe { libc::poll(pfds.as_mut_ptr(), 2, 500) };
            if rc < 0 {
                let e = io::Error::last_os_error();
                if e.raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                return self.end(SupervisorExit::Lost(format!("poll failed: {e}")));
            }
            if pfds[1].revents & libc::POLLIN != 0 {
                return self.end(SupervisorExit::Shutdown);
            }
            if pfds[0].revents & libc::POLLIN != 0 {
                match notify_recv(listener_fd) {
                    Ok(notif) => self.handle(&notif),
                    Err(e) if e.raw_os_error() == Some(libc::EINTR) => continue,
                    // The pending notification expired with its task
                    // between poll and recv — nothing left to answer.
                    Err(e) if e.raw_os_error() == Some(libc::ENOENT) => {
                        self.stats.expired += 1;
                        continue;
                    }
                    // Listener dead/queue gone — monitoring is over.
                    Err(e) => {
                        return self.end(SupervisorExit::Lost(format!("NOTIF_RECV failed: {e}")));
                    }
                }
            }
        }
    }

    fn end(&mut self, reason: SupervisorExit) -> SupervisorEnd {
        SupervisorEnd {
            reason,
            stats: std::mem::take(&mut self.stats),
        }
    }

    /// One notification: inspect → revalidate → evaluate → respond.
    fn handle(&mut self, notif: &libc::seccomp_notif) {
        self.stats.notifications += 1;
        if notif.data.nr != CONNECT_NR as i32 {
            // Defensive: the filter only emits connect, but an unknown
            // notification must never hang the task — continue it.
            self.continue_notif(notif.id);
            return;
        }
        let pid = notif.pid;
        let fd = notif.data.args[0];
        let target = inspect_sockaddr(pid, notif.data.args[1], notif.data.args[2]);
        // Revalidate after the memory read, before acting on it: a
        // dead id means the task no longer waits — answering or
        // auditing a verdict for it would be wasted work.
        if !notify_id_valid(self.listener.as_raw_fd(), notif.id) {
            self.stats.expired += 1;
            return;
        }
        match target {
            SockTarget::OtherFamily { family } => {
                self.stats.noninet_skipped += 1;
                tracing::debug!(
                    pid,
                    family,
                    "connect: non-INET family — continued unsupervised"
                );
                self.continue_notif(notif.id);
            }
            SockTarget::Unreadable { detail } => {
                self.stats.unreadable_denied += 1;
                self.deny(
                    notif.id,
                    pid,
                    "unreadable-dest",
                    &format!("proto=? dest=? port=? detail={detail}"),
                    None,
                );
            }
            SockTarget::Inet { dest, port } => {
                let proto = socket_proto(pid, fd);
                let fields = format!("proto={} dest={} port={}", proto.label(), dest, port);
                let grant_names = self.grants.live_names(&dest);
                let verdict = self.evaluator.evaluate(&dest, &grant_names);
                match verdict {
                    IpVerdict::Deny { decision, rule } => {
                        self.deny(notif.id, pid, decision, &fields, rule.as_deref())
                    }
                    IpVerdict::Allow { basis, rule } => {
                        if self.logger.is_failed() {
                            // Fail-closed audit: an allowed connect must
                            // not pass unaudited — flip it to a denial.
                            self.stats.audit_unavailable_denied += 1;
                            self.deny(
                                notif.id,
                                pid,
                                "audit-unavailable",
                                &format!("{fields} verdict_basis={basis}"),
                                None,
                            );
                        } else {
                            self.allow(notif.id, pid, basis, &fields, rule.as_deref());
                        }
                    }
                }
            }
        }
    }

    /// A `sandbox.*` event stamped with the launch's policy context —
    /// the same boilerplate `dns-gate`'s `Core::event` applies.
    fn event(
        &self,
        event_type: EventType,
        severity: Severity,
        outcome: Outcome,
        action: Action,
    ) -> AuditEvent {
        let mut event = AuditEvent::new(self.launch_id, event_type, severity, outcome, action);
        event.policy_context = self.policy_ctx.clone();
        if let Some(p) = &self.policy_ctx
            && p.id != "default"
        {
            event.target_server = Some(p.id.clone());
        }
        event
    }

    /// Emit `sandbox.network_denied` through the launch's fail-closed
    /// audit path *before* answering the syscall — `log_committed` on a
    /// fail-closed logger returns after the record is durable, so the
    /// denial never lands unaudited. A commit failure does not lift the
    /// denial; the sink's `is_failed` flag flips later allows to deny.
    fn deny(&mut self, id: u64, pid: u32, decision: &str, fields: &str, rule: Option<&str>) {
        let mut event = self.event(
            EventType::SandboxNetworkDenied,
            Severity::High,
            Outcome::Failure,
            Action::Denied,
        );
        let mut details = format!(
            "layer=ip {fields} pid={pid} decision={decision} session_id={}",
            self.logger.session_id()
        );
        if let Some(rule) = rule {
            details.push_str(&format!(" rule={rule}"));
        }
        event.details = Some(details);
        let res = tokio::runtime::Handle::current().block_on(self.logger.log_committed(event));
        if let Err(e) = res {
            self.stats.audit_errors += 1;
            tracing::error!("audit commit for denied connect failed: {e}");
        }
        self.stats.denied += 1;
        self.send_err(notif_resp_error(id, libc::EACCES));
    }

    /// Emit `sandbox.network_allowed`, then answer CONTINUE — the allow
    /// half of the audit contract. Buffered (`log`, not
    /// `log_committed`): availability on the allow path is the
    /// `is_failed` gate in `handle`, not a per-record fsync — the same
    /// split `dns-gate` applies to its `sandbox.network_resolved`
    /// records. The record precedes the syscall it describes.
    fn allow(&mut self, id: u64, pid: u32, basis: &str, fields: &str, rule: Option<&str>) {
        let mut event = self.event(
            EventType::SandboxNetworkAllowed,
            Severity::Info,
            Outcome::Success,
            Action::Allowed,
        );
        let mut details = format!(
            "layer=ip {fields} pid={pid} basis={basis} session_id={}",
            self.logger.session_id()
        );
        if let Some(rule) = rule {
            details.push_str(&format!(" rule={rule}"));
        }
        event.details = Some(details);
        self.logger.log(event);
        self.stats.continued += 1;
        self.send_err(notif_resp_continue(id));
    }

    fn continue_notif(&mut self, id: u64) {
        self.send_err(notif_resp_continue(id));
    }

    fn send_err(&mut self, resp: libc::seccomp_notif_resp) {
        match notify_send(self.listener.as_raw_fd(), &resp) {
            Ok(()) => {}
            // The task died mid-answer — nothing to fail.
            Err(e) if matches!(e.raw_os_error(), Some(libc::ENOENT) | Some(libc::ESRCH)) => {
                self.stats.expired += 1;
            }
            Err(e) => {
                self.stats.send_errors += 1;
                tracing::warn!("NOTIF_SEND failed: {e}");
            }
        }
    }
}

fn notif_resp_continue(id: u64) -> libc::seccomp_notif_resp {
    libc::seccomp_notif_resp {
        id,
        val: 0,
        error: 0,
        flags: libc::SECCOMP_USER_NOTIF_FLAG_CONTINUE as u32,
    }
}

fn notif_resp_error(id: u64, errno: i32) -> libc::seccomp_notif_resp {
    libc::seccomp_notif_resp {
        id,
        val: -1,
        error: -errno,
        flags: 0,
    }
}

// ---------------------------------------------------------------------------
// Spawn — the opt-in supervised launch
// ---------------------------------------------------------------------------

/// A spawned, supervised child. `listener` is the notification fd the
/// child handed over; pass it to [`Supervisor::start`].
pub struct SupervisedSpawn {
    pub child: std::process::Child,
    pub listener: File,
}

/// Spawn `argv` under the full Linux sandbox pipeline plus the
/// notification filter — the opt-in entry point. Preparation runs in
/// the parent; the child only applies. On any post-spawn failure the
/// spawned child is killed before the error returns — an unsupervised
/// child never survives this call.
///
/// The launch contract beyond the OS sandbox is the `run` path's: the
/// child execs `resolved_exe` (the canonicalized, hash-verified image)
/// while keeping the caller's `argv[0]` spelling, the
/// `defaults.environment` restriction applies to the child's
/// environment block, and a [`SpawnPin`](crate::verifier::hash::SpawnPin)
/// re-checks the image's identity immediately before the spawn.
pub fn spawn_supervised(
    policy: &crate::policy::Policy,
    argv: &[String],
    resolved_exe: &Path,
    spawn_pin: Option<&crate::verifier::hash::SpawnPin>,
) -> Result<SupervisedSpawn, WardenError> {
    let Some(argv0) = argv.first() else {
        return Err(WardenError::sandbox_setup(
            SandboxStage::Policy,
            "unotify-run requires a command after `--`",
        ));
    };
    let mut bits = super::linux_spawn::prepare_linux_child_sandbox(policy)?;
    let parent = enable_unotify(&mut bits)?;

    let env_opts = super::SpawnOptions {
        restrict_environment: policy.environment.restrict,
        allowed_names: policy.environment.allowed.clone(),
        // No workload-private TMPDIR exists on this launch surface —
        // the guest contract's override belongs to the runner.
        tmpdir: None,
    };
    let mut cmd = std::process::Command::new(resolved_exe);
    std::os::unix::process::CommandExt::arg0(&mut cmd, argv0);
    cmd.args(&argv[1..])
        .stdin(std::process::Stdio::inherit())
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit());
    super::env::apply_spawn_env_sync(&mut cmd, &env_opts);
    // Own process group so the fail-closed teardown can kill the whole
    // supervised tree, not just the exec'd image.
    std::os::unix::process::CommandExt::process_group(&mut cmd, 0);
    let record = super::linux_spawn::attach_linux_pre_exec(&mut cmd, bits);
    // The last check before the pathname-based spawn opens the image —
    // the pin proves the resolved path still names the verified object
    // (the residual exec-internal gap is documented on the pin itself).
    if let Some(pin) = spawn_pin {
        pin.verify_spawn_path(resolved_exe).map_err(|e| {
            WardenError::sandbox_setup(
                SandboxStage::Policy,
                format!("supply chain verification failed at spawn: {e}"),
            )
        })?;
    }
    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            // Fold the child's apply record into the error text — the
            // recorded stage/errno is the only signal a pre_exec failure
            // leaves behind.
            let detail = record
                .as_ref()
                .map(|r| {
                    let s = r.snapshot();
                    format!(
                        " (sandbox apply record: stage={} failed_stage={} errno={})",
                        s.stage, s.failed_stage, s.errno
                    )
                })
                .unwrap_or_default();
            return Err(WardenError::ProcessSpawn(io::Error::new(
                e.kind(),
                format!("{e}{detail}"),
            )));
        }
    };
    // Spawn returning Ok means pre_exec completed — the handoff byte is
    // already queued or the spawn would have failed. A missing fd is
    // still fatal: kill the child rather than leave it supervised-None.
    match parent.recv_listener() {
        Ok(listener) => Ok(SupervisedSpawn { child, listener }),
        Err(e) => {
            kill_tree(&mut child);
            Err(WardenError::sandbox_setup(
                SandboxStage::Apply,
                format!("listener fd handoff failed after spawn: {e}"),
            ))
        }
    }
}

/// SIGKILL the child's process group, then reap — the supervised tree
/// never outlives a lost supervisor/handoff.
fn kill_tree(child: &mut std::process::Child) {
    let pid = child.id() as libc::pid_t;
    // Safety: kill() on a process group the child owns; -ESRCH when the
    // group already exited is fine.
    unsafe {
        libc::kill(-pid, libc::SIGKILL);
        libc::kill(pid, libc::SIGKILL);
    }
    let _ = child.wait();
}

// ---------------------------------------------------------------------------
// Capability report — the opt-in path's honest enforcement statement
// ---------------------------------------------------------------------------

/// Fixed limitations of the PoC — surfaced in `--report` output and the
/// docs. Keep this list in sync with `docs/guide*.md` and the PR guide.
pub const LIMITATIONS: &[&str] = &[
    "connect(2) only — sendto/sendmsg datagram egress (including TCP \
     setup via MSG_FASTOPEN, which never calls connect), io_uring \
     IORING_OP_CONNECT, proxy-style fd passing, and non-socket \
     channels are outside this layer",
    "TOCTOU: the supervisor reads the child's sockaddr with \
     process_vm_readv; a hostile workload may rewrite the buffer \
     between inspection and the kernel's use of it",
    "non-AF_INET/AF_INET6 families (AF_UNIX, AF_PACKET, ...) are \
     continued unsupervised",
    "the socket's protocol is read via pidfd_getfd+getsockopt(SO_TYPE); \
     when that fails proto reports 'unknown' (the IP/port verdict is \
     unaffected)",
    "supervisor death fails closed: the kernel returns ENOSYS to pending \
     and future connects; the command also kills the supervised child",
    "requires SECCOMP_USER_NOTIF_FLAG_CONTINUE (Linux ≥ 5.5); checked at \
     startup, never silently degraded",
    "foreign-architecture (compat) tasks are killed rather than \
     supervised — their syscall table is not this filter's table",
    "port-qualified allow rules refuse at startup — widening them to \
     every port would be silent",
    "the notification fires only when the policy's own seccomp filter \
     allows connect — a syscall-level connect deny stays denied but is \
     not audited at this layer",
    "the supervised tree is the child's process group; a workload that \
     escapes via setsid loses tree-kill coverage (its own connects stay \
     filtered — the filter is per-task, inherited at clone)",
];

/// JSON literal `null` for optional report fields.
struct JsonNull;

impl nojson::DisplayJson for JsonNull {
    fn fmt(&self, f: &mut nojson::JsonFormatter<'_, '_>) -> std::fmt::Result {
        write!(f.inner_mut(), "null")
    }
}

fn layer_status_json(
    lo: &mut nojson::JsonObjectFormatter<'_, '_, '_>,
    l: &crate::enforcement::EgressLayerStatus,
) -> std::fmt::Result {
    lo.member("layer", l.layer)?;
    lo.member("rpc", l.rpc)?;
    match &l.os {
        Some(os) => lo.member("os", os.as_str())?,
        None => lo.member("os", &JsonNull)?,
    }
    match &l.note {
        Some(n) => lo.member("note", n.as_str())?,
        None => lo.member("note", &JsonNull)?,
    }
    Ok(())
}

/// The `layer=ip` egress status under this PoC — the real mechanism
/// plus its honest ceiling, parallel to the Auditor-only note the
/// ordinary Linux path reports.
pub fn ip_layer_status() -> crate::enforcement::EgressLayerStatus {
    crate::enforcement::EgressLayerStatus {
        layer: "ip",
        rpc: "auditor",
        os: Some("seccomp-user-notif (PoC)".to_string()),
        note: Some(
            "connect(2) destinations evaluated against cidr rules, IP-literal \
             host rules, and live DNS-grant entries; TOCTOU + connect-only \
             scope + supervisor-lifetime limits apply (see report limitations)"
                .to_string(),
        ),
    }
}

/// Machine-readable PoC report for `unotify-run --report`: capability
/// state, the two-layer egress disposition, limitations, and (after
/// exit) supervisor counters. `policy` is `None` when the launch
/// refused before one loaded — the report then omits `egress_layers`.
pub fn report_json(
    launch_id: uuid::Uuid,
    state: &str,
    reason: Option<&str>,
    policy: Option<&crate::policy::Policy>,
    policy_ctx: Option<&PolicyAuditContext>,
    allowlist: Option<&Path>,
    stats: Option<&SupervisorStats>,
) -> String {
    let mut uname_buf: libc::utsname = unsafe { std::mem::zeroed() };
    // Safety: `uname_buf` is a live, correctly-sized out buffer.
    let kernel = if unsafe { libc::uname(&mut uname_buf) } == 0 {
        unsafe {
            std::ffi::CStr::from_ptr(uname_buf.release.as_ptr())
                .to_string_lossy()
                .into_owned()
        }
    } else {
        "unknown".to_string()
    };
    let name_status = crate::enforcement::EgressLayerStatus {
        layer: "name",
        rpc: "auditor",
        os: Some("dns-gate (optional, external)".to_string()),
        note: Some(
            "host rules are name-layer; the dns-gate resolver enforces them for \
             workloads pointed at it, and its allowlist export feeds this \
             supervisor's grant source"
                .to_string(),
        ),
    };
    nojson::object(|o| -> std::fmt::Result {
        o.member("schema_version", "1.0")?;
        o.member("component", "unotify-run")?;
        o.member("launch_id", launch_id.to_string().as_str())?;
        o.member(
            "capability",
            nojson::object(|c| -> std::fmt::Result {
                c.member("mechanism", "seccomp-user-notif")?;
                c.member("syscall", "connect")?;
                c.member("kernel_release", kernel.as_str())?;
                c.member("state", state)?;
                if let Some(r) = reason {
                    c.member("reason", r)?;
                }
                c.member(
                    "allowlist_source",
                    allowlist
                        .map(|p| p.display().to_string())
                        .as_deref()
                        .unwrap_or("none"),
                )?;
                Ok(())
            }),
        )?;
        if let Some(policy) = policy {
            let out = &policy.network.outbound;
            o.member(
                "egress_layers",
                nojson::object(|e| -> std::fmt::Result {
                    e.member(
                        "default_action",
                        if out.deny_all_others {
                            "deny_all"
                        } else {
                            "allow_all"
                        },
                    )?;
                    e.member(
                        "layers",
                        nojson::array(|a| {
                            for l in [&name_status, &ip_layer_status()] {
                                a.element(nojson::object(|lo| layer_status_json(lo, l)))?;
                            }
                            Ok(())
                        }),
                    )?;
                    e.member(
                        "rules",
                        nojson::array(|a| {
                            for r in super::plan::egress_rule_table(policy) {
                                a.element(nojson::object(|ro| {
                                    ro.member("effect", r.effect)?;
                                    ro.member("kind", r.kind)?;
                                    ro.member("rule", r.rule.as_str())?;
                                    ro.member("name_layer", r.name_layer)?;
                                    ro.member("ip_layer", r.ip_layer)?;
                                    Ok(())
                                }))?;
                            }
                            Ok(())
                        }),
                    )?;
                    Ok(())
                }),
            )?;
        }
        if let Some(ctx) = policy_ctx {
            o.member(
                "policy",
                nojson::object(|p| -> std::fmt::Result {
                    p.member("id", ctx.id.as_str())?;
                    p.member("version", ctx.version.as_str())?;
                    p.member("hash", ctx.hash.as_str())?;
                    Ok(())
                }),
            )?;
        }
        o.member(
            "limitations",
            nojson::array(|a| {
                for l in LIMITATIONS {
                    a.element(*l)?;
                }
                Ok(())
            }),
        )?;
        o.member(
            "supervisor_stats",
            nojson::object(|s| -> std::fmt::Result {
                let st = stats.cloned().unwrap_or_default();
                s.member("notifications", st.notifications)?;
                s.member("continued", st.continued)?;
                s.member("denied", st.denied)?;
                s.member("noninet_skipped", st.noninet_skipped)?;
                s.member("unreadable_denied", st.unreadable_denied)?;
                s.member("expired", st.expired)?;
                s.member("audit_unavailable_denied", st.audit_unavailable_denied)?;
                s.member("send_errors", st.send_errors)?;
                s.member("audit_errors", st.audit_errors)?;
                Ok(())
            }),
        )?;
        Ok(())
    })
    .to_string()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn outbound(
        allowed: &[&str],
        denied: &[&str],
        cidrs: &[&str],
        denied_cidrs: &[&str],
        deny_all: bool,
    ) -> OutboundPolicy {
        OutboundPolicy {
            allowed: allowed.iter().map(|s| s.to_string()).collect(),
            allowed_port_qualified: Vec::new(),
            allowed_cidrs: cidrs.iter().map(|s| s.to_string()).collect(),
            allowed_cidrs_port_qualified: Vec::new(),
            denied_hosts: denied.iter().map(|s| s.to_string()).collect(),
            denied_cidrs: denied_cidrs.iter().map(|s| s.to_string()).collect(),
            deny_all_others: deny_all,
        }
    }

    #[test]
    fn evaluator_deny_precedence_and_layers() {
        let p = outbound(
            &["10.0.0.0/8"],
            &["10.9.0.0/16"],
            &["10.0.0.0/8"],
            &["10.9.0.0/16"],
            true,
        );
        let ev = IpLayerEvaluator::new(&p).unwrap();
        // deny cidr wins over an enclosing allow cidr
        let dest: IpAddr = "10.9.1.1".parse().unwrap();
        assert_eq!(
            ev.evaluate(&dest, &[]),
            IpVerdict::Deny {
                decision: "deny-cidr",
                rule: Some("10.9.0.0/16".into())
            }
        );
        // allow cidr covers
        let dest: IpAddr = "10.1.2.3".parse().unwrap();
        assert!(matches!(ev.evaluate(&dest, &[]), IpVerdict::Allow { .. }));
        // unmatched → deny-all
        let dest: IpAddr = "192.0.2.9".parse().unwrap();
        assert_eq!(
            ev.evaluate(&dest, &[]),
            IpVerdict::Deny {
                decision: "not-allowed",
                rule: None
            }
        );
    }

    #[test]
    fn evaluator_literal_host_rules_project_to_ip_layer() {
        let p = outbound(&["203.0.113.7"], &["192.0.2.1"], &[], &[], true);
        let ev = IpLayerEvaluator::new(&p).unwrap();
        let allow: IpAddr = "203.0.113.7".parse().unwrap();
        assert!(matches!(
            ev.evaluate(&allow, &[]),
            IpVerdict::Allow {
                basis: "allow-host",
                ..
            }
        ));
        let deny: IpAddr = "192.0.2.1".parse().unwrap();
        assert_eq!(
            ev.evaluate(&deny, &[]),
            IpVerdict::Deny {
                decision: "deny-host",
                rule: Some("192.0.2.1".into())
            }
        );
    }

    #[test]
    fn evaluator_dynamic_grants_and_deny_all() {
        let p = outbound(&[], &[], &[], &[], true);
        let ev = IpLayerEvaluator::new(&p).unwrap();
        let dest: IpAddr = "93.184.216.34".parse().unwrap();
        assert!(matches!(ev.evaluate(&dest, &[]), IpVerdict::Deny { .. }));
        let names = vec!["www.example.com".to_string()];
        assert!(matches!(
            ev.evaluate(&dest, &names),
            IpVerdict::Allow {
                basis: "allowlist-grant",
                ..
            }
        ));
        // A deny rule still wins over a grant (deny precedence is
        // absolute at this layer).
        let p = outbound(&[], &[], &[], &["93.184.216.0/24"], true);
        let ev = IpLayerEvaluator::new(&p).unwrap();
        assert!(matches!(ev.evaluate(&dest, &names), IpVerdict::Deny { .. }));
    }

    #[test]
    fn evaluator_open_posture() {
        let p = outbound(&["*"], &[], &[], &[], false);
        let ev = IpLayerEvaluator::new(&p).unwrap();
        let dest: IpAddr = "8.8.8.8".parse().unwrap();
        assert!(matches!(
            ev.evaluate(&dest, &[]),
            IpVerdict::Allow {
                basis: "allow-host",
                ..
            }
        ));
        let p2 = outbound(&[], &[], &[], &[], false);
        let ev2 = IpLayerEvaluator::new(&p2).unwrap();
        assert!(matches!(
            ev2.evaluate(&dest, &[]),
            IpVerdict::Allow { basis: "open", .. }
        ));
    }

    #[test]
    fn evaluator_refuses_port_qualified_allows() {
        let mut p = outbound(&["api.example.com"], &[], &[], &[], true);
        p.allowed_port_qualified = vec!["api.example.com:443".into()];
        assert!(IpLayerEvaluator::new(&p).is_err());
        // A qualifier whose folded entry was pruned (deny-covered or
        // removed) does not refuse — same contract as PSEC.
        let mut p2 = outbound(&[], &[], &[], &[], true);
        p2.allowed_port_qualified = vec!["api.example.com:443".into()];
        p2.allowed = Vec::new();
        assert!(IpLayerEvaluator::new(&p2).is_ok());
        let mut p3 = outbound(&[], &[], &["10.0.0.1/32"], &[], true);
        p3.allowed_cidrs_port_qualified = vec!["10.0.0.1/32:443".into()];
        assert!(IpLayerEvaluator::new(&p3).is_err());
    }

    #[test]
    fn evaluator_wildcard_deny_wins_over_everything() {
        let p = outbound(&["10.0.0.0/8"], &["*"], &["10.0.0.0/8"], &[], true);
        let ev = IpLayerEvaluator::new(&p).unwrap();
        let dest: IpAddr = "10.1.2.3".parse().unwrap();
        assert_eq!(
            ev.evaluate(&dest, &[]),
            IpVerdict::Deny {
                decision: "deny-host",
                rule: Some("*".into())
            }
        );
    }

    #[test]
    fn sockaddr_decode_v4_v6_mapped_and_other() {
        // sockaddr_in for 192.0.2.7:443
        let mut sa = [0u8; 16];
        sa[0..2].copy_from_slice(&(libc::AF_INET as u16).to_ne_bytes());
        sa[2..4].copy_from_slice(&443u16.to_be_bytes());
        sa[4..8].copy_from_slice(&[192, 0, 2, 7]);
        match parse_sockaddr(&sa, 16) {
            SockTarget::Inet { dest, port } => {
                assert_eq!(dest, "192.0.2.7".parse::<IpAddr>().unwrap());
                assert_eq!(port, 443);
            }
            other => panic!("expected inet, got {other:?}"),
        }
        // sockaddr_in6 ::ffff:10.1.2.3:8080 folds to the v4 dest.
        // Layout: family(0..2) port(2..4) flowinfo(4..8) addr(8..24)
        // scope_id(24..28); a v4-mapped v6 addr is 10 zeros, ff ff, v4.
        let mut sa6 = [0u8; 28];
        sa6[0..2].copy_from_slice(&(libc::AF_INET6 as u16).to_ne_bytes());
        sa6[2..4].copy_from_slice(&8080u16.to_be_bytes());
        sa6[18] = 0xff;
        sa6[19] = 0xff;
        sa6[20..24].copy_from_slice(&[10, 1, 2, 3]);
        match parse_sockaddr(&sa6, 28) {
            SockTarget::Inet { dest, port } => {
                assert_eq!(dest, "10.1.2.3".parse::<IpAddr>().unwrap());
                assert_eq!(port, 8080);
            }
            other => panic!("expected inet, got {other:?}"),
        }
        // sockaddr_in6 ::10.1.2.3 — the deprecated IPv4-*compatible*
        // form does NOT fold: the policy layer (`analyze_policy_cidr` /
        // `canonicalize_url_host`) folds only `::ffff:`-mapped
        // spellings, so this destination must stay a v6 address that a
        // v4 CIDR rule can never match.
        let mut sa6c = [0u8; 28];
        sa6c[0..2].copy_from_slice(&(libc::AF_INET6 as u16).to_ne_bytes());
        sa6c[2..4].copy_from_slice(&8080u16.to_be_bytes());
        sa6c[20..24].copy_from_slice(&[10, 1, 2, 3]);
        match parse_sockaddr(&sa6c, 28) {
            SockTarget::Inet { dest, port } => {
                assert!(dest.is_ipv6(), "compatible spelling must stay v6");
                assert_eq!(dest, "::a01:203".parse::<IpAddr>().unwrap());
                assert_eq!(port, 8080);
            }
            other => panic!("expected inet, got {other:?}"),
        }
        // AF_UNIX → OtherFamily.
        let mut su = [0u8; 8];
        su[0..2].copy_from_slice(&(libc::AF_UNIX as u16).to_ne_bytes());
        assert!(matches!(
            parse_sockaddr(&su, 8),
            SockTarget::OtherFamily { .. }
        ));
        // Truncated sockaddr_in → fail-closed unreadable.
        assert!(matches!(
            parse_sockaddr(&sa[..8], 8),
            SockTarget::Unreadable { .. }
        ));
    }

    #[test]
    fn snapshot_parse_and_ttl_expiry() {
        let now = unix_secs_now();
        let body = format!(
            r#"{{"schema_version":"1.0","generated_at_unix_secs":{now},"entries":[{{"name":"a.example","addr":"93.184.216.34","expires_at_unix_secs":{}}},{{"name":"b.example","addr":"203.0.113.8","expires_at_unix_secs":{}}}]}}"#,
            now + 300,
            now - 1,
        );
        let entries = parse_snapshot(&body);
        assert_eq!(entries.len(), 2);

        // Real-file round trip — the same contract `dns-gate
        // --allowlist-export` writes for a supervisor.
        let path = std::env::temp_dir().join(format!(
            "mcp-writ-unotify-test-{}-{now}.json",
            std::process::id()
        ));
        std::fs::write(&path, &body).unwrap();
        let mut g = Grants::new(GrantSource::SnapshotFile(path.clone()));
        let live = g.live_names(&"93.184.216.34".parse().unwrap());
        assert_eq!(live, vec!["a.example".to_string()]);
        // Expired grant is closed even though it is in the file.
        assert!(g.live_names(&"203.0.113.8".parse().unwrap()).is_empty());
        // A missing file is an empty grant set (fail closed).
        std::fs::remove_file(&path).unwrap();
        assert!(g.live_names(&"93.184.216.34".parse().unwrap()).is_empty());
        // Garbage degrades to empty, never a guess.
        assert!(parse_snapshot("not json").is_empty());
        assert!(parse_snapshot(r#"{"schema_version":"1.0"}"#).is_empty());
    }

    #[test]
    fn bpf_program_shape() {
        let prog = notify_program(CONNECT_NR);
        assert_eq!(prog.len(), 8);
        assert_eq!(prog[5].k, libc::SECCOMP_RET_USER_NOTIF);
        assert_eq!(prog[6].k, libc::SECCOMP_RET_ALLOW);
        assert_eq!(prog[7].k, libc::SECCOMP_RET_KILL_PROCESS);
        assert_eq!(prog[4].k, CONNECT_NR);
        assert_eq!(prog[3].k, X32_SYSCALL_BIT);
        assert_eq!(prog[3].code, BPF_JMP | BPF_JGE | BPF_K);
        assert_eq!(prog[1].k, AUDIT_ARCH_NATIVE);
    }

    /// Real kernel round-trip: install the connect filter in a forked
    /// child, hand the listener over, answer the connect notification
    /// with CONTINUE. Skips gracefully where the kernel lacks support.
    #[test]
    fn live_notification_round_trip() {
        if check_support().is_err() {
            return;
        }
        let mut pair = [0 as RawFd; 2];
        assert_eq!(
            unsafe {
                libc::socketpair(
                    libc::AF_UNIX,
                    libc::SOCK_DGRAM | libc::SOCK_CLOEXEC,
                    0,
                    pair.as_mut_ptr(),
                )
            },
            0
        );
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0);
        if pid == 0 {
            // Filter install needs no_new_privs (or CAP_SYS_ADMIN) —
            // report an nnp refusal identifiably rather than letting
            // install_listener fail opaquely.
            if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
                unsafe {
                    libc::send(pair[0], &b'N' as *const u8 as *const libc::c_void, 1, 0);
                    libc::_exit(0);
                }
            }
            let program = notify_program(CONNECT_NR);
            let listener = install_listener(&program).expect("install");
            send_listener(pair[0], listener).expect("handoff");
            unsafe { libc::close(listener) };
            // Trigger: connect to the discard port on loopback.
            let s = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
            assert!(s >= 0);
            let mut sa = [0u8; 16];
            sa[0..2].copy_from_slice(&(libc::AF_INET as u16).to_ne_bytes());
            sa[2..4].copy_from_slice(&9u16.to_be_bytes());
            sa[4..8].copy_from_slice(&[127, 0, 0, 1]);
            let rc = unsafe { libc::connect(s, sa.as_ptr().cast(), 16) };
            let errno = unsafe { *libc::__errno_location() };
            unsafe { libc::close(s) };
            // connect ran (refused is expected) — ENOSYS would mean the
            // notification killed it.
            let byte = if rc < 0 && errno == libc::ENOSYS {
                b'C'
            } else {
                b'R'
            };
            unsafe {
                libc::send(pair[0], &byte as *const u8 as *const libc::c_void, 1, 0);
                libc::_exit(0);
            }
        }
        unsafe { libc::close(pair[0]) };
        let sock = unsafe { File::from_raw_fd(pair[1]) };
        let listener = (UnotifyParent {
            sock: sock.try_clone().unwrap(),
        })
        .recv_listener()
        .expect("listener fd");
        let notif = loop {
            match notify_recv(listener.as_raw_fd()) {
                Ok(n) => break n,
                Err(e) if e.raw_os_error() == Some(libc::EINTR) => continue,
                Err(e) => panic!("NOTIF_RECV failed: {e}"),
            }
        };
        assert_eq!(notif.data.nr, CONNECT_NR as i32);
        assert_eq!(notif.pid, pid as u32);
        // The child's sockaddr — decode proves the memory-read path.
        let target = inspect_sockaddr(notif.pid, notif.data.args[1], notif.data.args[2]);
        match target {
            SockTarget::Inet { dest, port } => {
                assert_eq!(dest, "127.0.0.1".parse::<IpAddr>().unwrap());
                assert_eq!(port, 9);
            }
            other => panic!("sockaddr decode failed: {other:?}"),
        }
        let resp = notif_resp_continue(notif.id);
        notify_send(listener.as_raw_fd(), &resp).expect("CONTINUE send");
        let mut byte = [0u8; 1];
        assert_eq!(
            unsafe { libc::recv(sock.as_raw_fd(), byte.as_mut_ptr().cast(), 1, 0) },
            1
        );
        assert_eq!(byte[0], b'R');
        let mut status = 0;
        unsafe { libc::waitpid(pid, &mut status, 0) };
    }

    /// A denied notification delivers an error to the child's
    /// connect — the "actually refused" half of the contract.
    #[test]
    fn denied_connect_gets_eacces() {
        if check_support().is_err() {
            return;
        }
        let mut pair = [0 as RawFd; 2];
        assert_eq!(
            unsafe {
                libc::socketpair(
                    libc::AF_UNIX,
                    libc::SOCK_DGRAM | libc::SOCK_CLOEXEC,
                    0,
                    pair.as_mut_ptr(),
                )
            },
            0
        );
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0);
        if pid == 0 {
            // Same nnp precondition as the round-trip child — report a
            // refusal identifiably instead of an opaque install error.
            if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
                unsafe {
                    libc::send(pair[0], &b'N' as *const u8 as *const libc::c_void, 1, 0);
                    libc::_exit(0);
                }
            }
            let program = notify_program(CONNECT_NR);
            let listener = install_listener(&program).expect("install");
            send_listener(pair[0], listener).expect("handoff");
            unsafe { libc::close(listener) };
            let s = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
            assert!(s >= 0);
            let mut sa = [0u8; 16];
            sa[0..2].copy_from_slice(&(libc::AF_INET as u16).to_ne_bytes());
            sa[2..4].copy_from_slice(&9u16.to_be_bytes());
            sa[4..8].copy_from_slice(&[127, 0, 0, 1]);
            let rc = unsafe { libc::connect(s, sa.as_ptr().cast(), 16) };
            let errno = unsafe { *libc::__errno_location() };
            unsafe { libc::close(s) };
            let byte = if rc < 0 && errno == libc::EACCES {
                b'D' // denied as designed
            } else {
                b'X'
            };
            unsafe {
                libc::send(pair[0], &byte as *const u8 as *const libc::c_void, 1, 0);
                libc::_exit(0);
            }
        }
        unsafe { libc::close(pair[0]) };
        let sock = unsafe { File::from_raw_fd(pair[1]) };
        let listener = (UnotifyParent {
            sock: sock.try_clone().unwrap(),
        })
        .recv_listener()
        .expect("listener fd");
        let notif = loop {
            match notify_recv(listener.as_raw_fd()) {
                Ok(n) => break n,
                Err(e) if e.raw_os_error() == Some(libc::EINTR) => continue,
                Err(e) => panic!("NOTIF_RECV failed: {e}"),
            }
        };
        notify_send(
            listener.as_raw_fd(),
            &notif_resp_error(notif.id, libc::EACCES),
        )
        .expect("deny send");
        let mut byte = [0u8; 1];
        assert_eq!(
            unsafe { libc::recv(sock.as_raw_fd(), byte.as_mut_ptr().cast(), 1, 0) },
            1
        );
        assert_eq!(byte[0], b'D');
        let mut status = 0;
        unsafe { libc::waitpid(pid, &mut status, 0) };
    }
}
