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
/// `arg` is the notification id *by value* (the uapi's `_IOW` encodes
/// the size only).
pub(super) fn notify_id_valid(listener: RawFd, id: u64) -> bool {
    // Safety: scalar ioctl argument, no pointer.
    unsafe { libc::ioctl(listener, libc::SECCOMP_IOCTL_NOTIF_ID_VALID, id) == 0 }
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

pub(super) fn notif_resp_error(id: u64, errno: i32) -> libc::seccomp_notif_resp {
    libc::seccomp_notif_resp {
        id,
        val: -1,
        error: -errno,
        flags: 0,
    }
}
