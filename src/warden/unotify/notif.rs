//! Supervisor-side kernel interface — the `SECCOMP_IOCTL_NOTIF_*`
//! ioctls, the `process_vm_readv` remote read, and the response
//! constructors.

use std::io;
use std::os::unix::io::RawFd;

/// Block until a task under the filter performs a watched syscall.
pub(super) fn notify_recv(listener: RawFd) -> io::Result<libc::seccomp_notif> {
    let mut notif: libc::seccomp_notif = unsafe { std::mem::zeroed() };
    // Safety: `notif` is live and sized per the kernel ABI.
    let rc = unsafe { libc::ioctl(listener, libc::SECCOMP_IOCTL_NOTIF_RECV, &raw mut notif) };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(notif)
}

/// `true` while the notification's task still waits for an answer.
/// `SECCOMP_IOCTL_NOTIF_ID_VALID` is `_IOW` — the third argument is a
/// *pointer* to the u64 cookie the kernel `copy_from_user`s, not the
/// cookie value itself. Passing the value makes the kernel read an
/// arbitrary userspace address and fail with EFAULT, which would drop
/// every live notification unanswered.
pub(super) fn notify_id_valid(listener: RawFd, id: u64) -> bool {
    // Safety: `id` is a live u64 the kernel reads for the call.
    unsafe {
        libc::ioctl(
            listener,
            libc::SECCOMP_IOCTL_NOTIF_ID_VALID,
            &id as *const u64,
        ) == 0
    }
}

/// Deliver the response to a pending notification. `ENOENT` means the
/// triggering task died in the meantime — counted, not fatal.
pub(super) fn notify_send(listener: RawFd, resp: &libc::seccomp_notif_resp) -> io::Result<()> {
    // Safety: `resp` is live and sized per the kernel ABI.
    let rc = unsafe { libc::ioctl(listener, libc::SECCOMP_IOCTL_NOTIF_SEND, resp) };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Read exactly `buf.len()` bytes at `addr` in task `pid`'s address
/// space (works on a thread id too — the memory is shared).
pub(super) fn read_remote(pid: u32, addr: u64, buf: &mut [u8]) -> io::Result<()> {
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

pub(super) fn notif_resp_continue(id: u64) -> libc::seccomp_notif_resp {
    libc::seccomp_notif_resp {
        id,
        val: 0,
        error: 0,
        flags: libc::SECCOMP_USER_NOTIF_FLAG_CONTINUE as u32,
    }
}

/// Emulated-syscall success answer — no CONTINUE: the supervisor
/// already ran the operation on the task's behalf, so the response
/// returns the emulated result (0) without letting the kernel re-run
/// the syscall on possibly-mutated arguments.
pub(super) fn notif_resp_result(id: u64, val: i64) -> libc::seccomp_notif_resp {
    libc::seccomp_notif_resp {
        id,
        val,
        error: 0,
        flags: 0,
    }
}

/// Duplicate fd `fd` of task `pid` into this process —
/// `pidfd_open` + `pidfd_getfd`. The dup names the same open file
/// description, so `connect(2)` on it performs the connect the
/// supervised task asked for, on the same socket, with the
/// supervisor's own (pinned) sockaddr — the seccomp-user-notif
/// "emulation" pattern that makes a sockaddr TOCTOU impossible.
///
/// Errors propagate to the caller's classification: `ESRCH` means the
/// task died, `EBADF` a sibling raced the fd closed (the native
/// connect would have failed the same way), `EPERM` a ptrace-scope or
/// credential boundary — refused by fail-closed policy.
pub(super) fn dup_child_fd(pid: u32, fd: u64) -> io::Result<RawFd> {
    // Safety: syscall args are scalars; both fds are closed/owned on
    // every path.
    let pidfd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid as libc::pid_t, 0) };
    if pidfd < 0 {
        return Err(io::Error::last_os_error());
    }
    let dup = unsafe { libc::syscall(libc::SYS_pidfd_getfd, pidfd, fd as libc::c_int, 0) };
    unsafe { libc::close(pidfd as libc::c_int) };
    if dup < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(dup as RawFd)
}

/// `connect(2)` on a supervisor-side dup of the child's socket with
/// the pinned sockaddr bytes — returns `0` or the errno the child's
/// own connect would have reported.
pub(super) fn emulate_connect(pid: u32, fd: u64, sockaddr: &[u8]) -> io::Result<i32> {
    let dup = dup_child_fd(pid, fd)?;
    // Safety: `sockaddr` is a live buffer of `len` bytes; `dup` is an
    // owned fd closed unconditionally below.
    let rc = unsafe {
        libc::connect(
            dup,
            sockaddr.as_ptr().cast::<libc::sockaddr>(),
            sockaddr.len() as libc::socklen_t,
        )
    };
    let out = if rc == 0 {
        0
    } else {
        io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(libc::EIO)
    };
    unsafe { libc::close(dup) };
    Ok(out)
}

pub(super) fn notif_resp_error(id: u64, errno: i32) -> libc::seccomp_notif_resp {
    libc::seccomp_notif_resp {
        id,
        val: -1,
        error: -errno,
        flags: 0,
    }
}
