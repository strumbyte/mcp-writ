//! Capability probe — startup refusal diagnostics.

use std::fs::File;
use std::io;
use std::mem::size_of;
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};

use super::filter::{AUDIT_ARCH_NATIVE, CONNECT_NR, notify_program};
use super::handoff::{UnotifyParent, install_listener, send_listener};
use super::notif::{notify_recv, notify_send};

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
    // seccomp(2) is (operation, flags, args): the sizes struct goes in
    // `args` — flags must be 0 for GET_NOTIF_SIZES, so passing the
    // pointer as `flags` would always be EINVAL. Safety: `sizes` is
    // live and sized per the kernel ABI.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            libc::SECCOMP_GET_NOTIF_SIZES,
            0,
            &mut sizes,
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
