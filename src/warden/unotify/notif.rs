//! Supervisor-side kernel interface — the `SECCOMP_IOCTL_NOTIF_*`
//! ioctls, the `process_vm_readv` remote read, and the response
//! constructors.

use std::io;
use std::os::unix::io::RawFd;

/// Block until a task under the filter performs a watched syscall.
pub(super) fn notify_recv(listener: RawFd) -> io::Result<libc::seccomp_notif> {
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    let mut notif: libc::seccomp_notif = unsafe { std::mem::zeroed() };
    // Safety: `notif` is live and sized per the kernel ABI.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
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
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
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
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
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
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
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
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    let pidfd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid as libc::pid_t, 0) };
    if pidfd < 0 {
        return Err(io::Error::last_os_error());
    }
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    let dup = unsafe { libc::syscall(libc::SYS_pidfd_getfd, pidfd, fd as libc::c_int, 0) };
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    unsafe { libc::close(pidfd as libc::c_int) };
    if dup < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(dup as RawFd)
}

/// Hard deadline for one emulated `connect(2)`. A blocking connect
/// parks a worker for the kernel's full SYN-retry schedule (minutes on
/// a black-holed peer); a workload could pin every emulation worker
/// that way. The deadline bounds worker lifetime so the fixed worker
/// pool and supervisor shutdown stay deterministic — on expiry the
/// child's connect reports `ETIMEDOUT`, the same errno a native
/// connect surfaces for an unresponsive peer.
const EMU_CONNECT_TIMEOUT_MS: i32 = 30_000;

/// `connect(2)` on a supervisor-side dup of the child's socket with
/// the pinned sockaddr bytes — returns `0` or the errno the child's
/// own connect would have reported (`ETIMEDOUT` at the emulation
/// deadline). The dup shares the child's open file description, so
/// `O_NONBLOCK` mutates *shared* status flags — snapshot before,
/// restored after. Only the notifying thread is stopped: sibling
/// threads in the same task keep running and can observe the transient
/// flag through the shared socket — a `read`/`write` inside the window
/// returns `EAGAIN` where the unsupervised connect would not have
/// produced one. The window is bounded by the emulation deadline and
/// the flag is always restored, so the residual is a co-sandboxed
/// thread briefly seeing its own supervised socket misbehave —
/// acceptable inside one trust domain.
pub(super) fn emulate_connect(pid: u32, fd: u64, sockaddr: &[u8]) -> io::Result<i32> {
    let dup = dup_child_fd(pid, fd)?;
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    let saved = unsafe { libc::fcntl(dup, libc::F_GETFL) };
    if saved < 0 {
        let e = io::Error::last_os_error();
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe { libc::close(dup) };
        return Err(e);
    }
    // Safety: `sockaddr` is a live buffer of `len` bytes; `dup` is an
    // owned fd closed unconditionally below.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    unsafe { libc::fcntl(dup, libc::F_SETFL, saved | libc::O_NONBLOCK) };
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
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
        match io::Error::last_os_error().raw_os_error() {
            Some(libc::EINPROGRESS) | Some(libc::EALREADY) => connect_wait(dup),
            // A non-INET socket (AF_UNIX full backlog) reports EAGAIN
            // *without initiating* the connect — `SO_ERROR` stays 0
            // and cannot witness completion, so only a fresh attempt
            // can finish it. Only when the child's socket was *blocking*:
            // on an originally-nonblocking socket EAGAIN is the verdict
            // the program must see — retrying here would block a socket
            // the child believes is nonblocking.
            Some(libc::EAGAIN) if saved & libc::O_NONBLOCK != 0 => libc::EAGAIN,
            Some(libc::EAGAIN) => connect_retry(dup, sockaddr),
            Some(e) => e,
            None => libc::EIO,
        }
    };
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    unsafe { libc::fcntl(dup, libc::F_SETFL, saved) };
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    unsafe { libc::close(dup) };
    Ok(out)
}

/// Wait out a nonblocking connect on `dup` up to the emulation
/// deadline; returns `0`, the connect's `SO_ERROR`, or `ETIMEDOUT`.
fn connect_wait(dup: RawFd) -> i32 {
    let deadline =
        std::time::Instant::now() + std::time::Duration::from_millis(EMU_CONNECT_TIMEOUT_MS as u64);
    loop {
        let left = deadline.saturating_duration_since(std::time::Instant::now());
        if left.is_zero() {
            return libc::ETIMEDOUT;
        }
        let mut pfd = libc::pollfd {
            fd: dup,
            events: libc::POLLOUT,
            revents: 0,
        };
        // Safety: `pfd` is live for the call; `dup` is owned by the
        // caller and outlives this wait.
        let ms = left.as_millis().min(i32::MAX as u128) as i32;
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        let rc = unsafe { libc::poll(&mut pfd, 1, ms.max(1)) };
        if rc < 0 {
            if io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return io::Error::last_os_error()
                .raw_os_error()
                .unwrap_or(libc::EIO);
        }
        if rc == 0 {
            return libc::ETIMEDOUT;
        }
        let mut err: libc::c_int = 0;
        let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        // Safety: `err`/`len` are live out-params; `dup` is a socket.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        let rc = unsafe {
            libc::getsockopt(
                dup,
                libc::SOL_SOCKET,
                libc::SO_ERROR,
                (&mut err as *mut libc::c_int).cast::<libc::c_void>(),
                &mut len,
            )
        };
        return if rc < 0 {
            io::Error::last_os_error()
                .raw_os_error()
                .unwrap_or(libc::EIO)
        } else {
            err
        };
    }
}

/// Retry `connect(2)` after `EAGAIN` — the non-INET emulation path.
/// The kernel did not start the connect on the first attempt, so no
/// in-progress state exists for `SO_ERROR` to observe; only another
/// attempt can complete it. `POLLOUT` paces each retry inside the same
/// [`EMU_CONNECT_TIMEOUT_MS`] budget, and a short sleep keeps a
/// stalled-listener socket from spinning the worker CPU-hot. `EISCONN`
/// means an earlier attempt connected under us; `EINPROGRESS`/
/// `EALREADY` means a connect really is in flight — `connect_wait`'s
/// `SO_ERROR` read finishes those.
fn connect_retry(dup: RawFd, sockaddr: &[u8]) -> i32 {
    let deadline =
        std::time::Instant::now() + std::time::Duration::from_millis(EMU_CONNECT_TIMEOUT_MS as u64);
    loop {
        let left = deadline.saturating_duration_since(std::time::Instant::now());
        if left.is_zero() {
            return libc::ETIMEDOUT;
        }
        let mut pfd = libc::pollfd {
            fd: dup,
            events: libc::POLLOUT,
            revents: 0,
        };
        let ms = left.as_millis().min(i32::MAX as u128) as i32;
        // Safety: `pfd` is live for the call; `dup` is owned by the
        // caller and outlives this wait.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        let rc = unsafe { libc::poll(&mut pfd, 1, ms.max(1)) };
        if rc < 0 {
            if io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return io::Error::last_os_error()
                .raw_os_error()
                .unwrap_or(libc::EIO);
        }
        if rc == 0 {
            return libc::ETIMEDOUT;
        }
        // Safety: `sockaddr`/`len` name the pinned bytes; `dup` is the
        // caller's owned fd.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        let rc = unsafe {
            libc::connect(
                dup,
                sockaddr.as_ptr().cast::<libc::sockaddr>(),
                sockaddr.len() as libc::socklen_t,
            )
        };
        if rc == 0 {
            return 0;
        }
        match io::Error::last_os_error().raw_os_error() {
            Some(libc::EAGAIN) => {
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
            Some(libc::EISCONN) => return 0,
            Some(libc::EINPROGRESS) | Some(libc::EALREADY) => return connect_wait(dup),
            Some(e) => return e,
            None => return libc::EIO,
        }
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
