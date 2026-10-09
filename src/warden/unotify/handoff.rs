//! Child-side apply (`pre_exec` — no allocation, syscalls only) and the
//! `SCM_RIGHTS` listener-fd handoff to the parent.

use std::fs::File;
use std::io;
use std::mem::size_of;
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};

use crate::error::{SandboxStage, WardenError};
use crate::warden::linux_spawn::LinuxSandboxBits;

use super::filter::{AUDIT_ARCH_NATIVE, CONNECT_NR, notify_program};

/// `msg_control` storage for the `SCM_RIGHTS` send/recv — a `u8` array
/// is only byte-aligned, but `CMSG_FIRSTHDR`/`CMSG_DATA` compute a
/// `*mut cmsghdr` into it; the union gives the buffer `cmsghdr`
/// alignment while `bytes` keeps the byte-level size/address view.
union CmsgBuf {
    bytes: [u8; 64],
    _align: libc::cmsghdr,
}

/// What the `pre_exec` child installs: the notification filter plus the
/// socketpair end the listener fd is handed to the parent through.
/// `program` was allocated in the parent — the child only reads it.
pub(crate) struct UnotifyChild {
    program: Vec<libc::sock_filter>,
    handoff: RawFd,
}

/// Parent side of the listener handoff — the other end of the
/// socketpair. `recv_listener` collects the fd the child sent once
/// `spawn()` has returned.
pub(super) struct UnotifyParent {
    pub(super) sock: File,
}

/// `seccomp(SECCOMP_SET_MODE_FILTER, NEW_LISTENER, prog)` — returns the
/// notification listener fd. Syscall-only; safe in `pre_exec`.
pub(super) fn install_listener(program: &[libc::sock_filter]) -> io::Result<RawFd> {
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
pub(super) fn send_listener(sock: RawFd, listener: RawFd) -> io::Result<()> {
    let mut byte = [0u8; 1];
    let iov = libc::iovec {
        iov_base: byte.as_mut_ptr().cast(),
        iov_len: 1,
    };
    let mut control = CmsgBuf { bytes: [0u8; 64] };
    // Safety: `msg` points at live locals; `control` is large enough
    // for one SCM_RIGHTS fd (CMSG_SPACE(4) == 24 on LP64).
    unsafe {
        let mut msg: libc::msghdr = std::mem::zeroed();
        msg.msg_iov = &iov as *const _ as *mut _;
        msg.msg_iovlen = 1;
        msg.msg_control = control.bytes.as_mut_ptr().cast();
        msg.msg_controllen = control.bytes.len();
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
    pub(crate) fn apply(&self) -> io::Result<()> {
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
pub(super) fn enable_unotify(bits: &mut LinuxSandboxBits) -> Result<UnotifyParent, WardenError> {
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
        let mut control = CmsgBuf { bytes: [0u8; 64] };
        // Safety: same layout the child wrote; `control` fits one fd.
        unsafe {
            let mut msg: libc::msghdr = std::mem::zeroed();
            msg.msg_iov = &mut iov as *mut _;
            msg.msg_iovlen = 1;
            msg.msg_control = control.bytes.as_mut_ptr().cast();
            msg.msg_controllen = control.bytes.len();
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
