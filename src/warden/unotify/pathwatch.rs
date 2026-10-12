//! Self-test evidence channel — a seccomp user-notification watcher
//! that denies `open*` calls on one configured absolute path and
//! records that it did so.
//!
//! The recorded flag is kernel-mediated evidence: it is set only when
//! the kernel reported the child's syscall to this watcher and the
//! watcher answered it with `EACCES`. A child cannot forge it by
//! printing a denial-shaped response or dying with a lookalike signal
//! (the flaw the previous SIGSYS-based classification had) — and it
//! cannot *lose* the evidence either: without the notification the
//! flag simply stays unset and the verdict is inconclusive, never
//! pass.

use std::fs::File;
use std::io;
use std::os::unix::io::{AsRawFd, FromRawFd};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use super::notif::{
    notif_resp_continue, notif_resp_error, notify_id_valid, notify_recv, notify_send, read_remote,
};

/// `PATH_MAX` — the path argument cannot legitimately exceed this.
const MAX_PATH_BYTES: usize = 4096;
/// Per-`process_vm_readv` chunk while scanning for the NUL terminator.
const READ_CHUNK: usize = 256;

/// Syscall numbers the open-path watcher asks the filter to notify
/// on. All take the pathname pointer in `args[1]` except `open`
/// (args[0]) — `open` exists only on x86_64 among our targets.
#[cfg(target_arch = "x86_64")]
pub const OPEN_PATH_NRS: &[u32] = &[
    libc::SYS_open as u32,
    libc::SYS_openat as u32,
    libc::SYS_openat2 as u32,
];
#[cfg(not(target_arch = "x86_64"))]
pub const OPEN_PATH_NRS: &[u32] = &[libc::SYS_openat as u32, libc::SYS_openat2 as u32];

/// The pathname pointer's position in `seccomp_data.args` for `nr`.
/// `open(path, …)` is arg 0; `openat`/`openat2(dirfd, path, …)` arg 1.
#[cfg(target_arch = "x86_64")]
fn path_arg_index(nr: i32) -> usize {
    if nr == libc::SYS_open as i32 { 0 } else { 1 }
}
#[cfg(not(target_arch = "x86_64"))]
fn path_arg_index(_nr: i32) -> usize {
    1
}

/// A running watcher over a received listener fd. `denied_observed`
/// reports whether a kernel-reported open on the denied path was
/// answered `EACCES` by this watcher — the authenticated evidence.
pub struct PathDenyWatcher {
    denied: Arc<AtomicBool>,
    stop: File,
    task: Option<tokio::task::JoinHandle<()>>,
}

impl PathDenyWatcher {
    /// Start answering notifications on `listener`: `EACCES` for an
    /// open whose pathname bytes equal `denied_path`, `CONTINUE` for
    /// everything else. Must be called inside the tokio runtime.
    pub fn start(listener: File, denied_path: &Path) -> io::Result<Self> {
        // Safety: eventfd creates a live fd; EFD_CLOEXEC keeps it out
        // of any exec'd image.
        let stop_raw = unsafe { libc::eventfd(0, libc::EFD_CLOEXEC) };
        if stop_raw < 0 {
            return Err(io::Error::last_os_error());
        }
        let stop = unsafe { File::from_raw_fd(stop_raw) };
        let loop_stop = stop.try_clone()?;
        let denied = Arc::new(AtomicBool::new(false));
        let loop_denied = Arc::clone(&denied);
        let denied_path = denied_path.as_os_str().as_encoded_bytes().to_vec();
        let task = tokio::task::spawn_blocking(move || {
            let mut w = Watch {
                listener,
                stop: loop_stop,
                denied_path,
                denied: loop_denied,
            };
            w.run();
        });
        Ok(Self {
            denied,
            stop,
            task: Some(task),
        })
    }

    /// `true` once this watcher answered `EACCES` to a kernel-reported
    /// open on the denied path.
    pub fn denied_observed(&self) -> bool {
        self.denied.load(Ordering::SeqCst)
    }

    /// Stop the loop and await its exit. Also wakes on listener close.
    pub async fn shutdown(mut self) {
        self.signal_stop();
        if let Some(task) = self.task.take() {
            let _ = task.await;
        }
    }

    fn signal_stop(&self) {
        let byte = 1u64.to_ne_bytes();
        // Safety: `stop` is a live eventfd; 8 bytes is the eventfd write.
        unsafe {
            libc::write(
                self.stop.as_raw_fd(),
                byte.as_ptr().cast::<std::ffi::c_void>(),
                8,
            )
        };
    }
}

/// If the watcher is dropped without `shutdown`, signal the loop to
/// stop — the task then exits on its next poll tick (≤500 ms). The
/// listener is released with the struct, which already makes the
/// kernel fail pending/future watched syscalls `ENOSYS`.
impl Drop for PathDenyWatcher {
    fn drop(&mut self) {
        self.signal_stop();
    }
}

struct Watch {
    listener: File,
    stop: File,
    denied_path: Vec<u8>,
    denied: Arc<AtomicBool>,
}

impl Watch {
    fn run(&mut self) {
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
                if io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                return;
            }
            if pfds[1].revents & libc::POLLIN != 0 {
                return;
            }
            if pfds[0].revents & libc::POLLIN != 0 {
                match notify_recv(listener_fd) {
                    Ok(notif) => self.handle(&notif),
                    Err(e)
                        if matches!(e.raw_os_error(), Some(libc::EINTR) | Some(libc::ENOENT)) => {}
                    Err(_) => return,
                }
            } else if pfds[0].revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0 {
                return;
            }
        }
    }

    /// One notification: deny the configured path, continue the rest.
    /// An unexpected nr or an unreadable pathname is continued — the
    /// task must never hang waiting for an answer.
    fn handle(&mut self, notif: &libc::seccomp_notif) {
        let arg = notif
            .data
            .args
            .get(path_arg_index(notif.data.nr))
            .copied()
            .unwrap_or(0);
        if arg == 0 {
            self.continue_notif(notif.id);
            return;
        }
        let hit = match read_remote_path(notif.pid, arg) {
            Ok(path) => path == self.denied_path,
            Err(_) => false,
        };
        // Revalidate before answering: a dead id means the task no
        // longer waits — recording or responding is pointless.
        if !notify_id_valid(self.listener.as_raw_fd(), notif.id) {
            return;
        }
        if !hit {
            self.continue_notif(notif.id);
            return;
        }
        // Order matters: the flag goes up *before* the deny answer, so
        // any consumer that sees the child's reaction also sees the
        // evidence — the flag is what `warden: pass` is classified from.
        self.denied.store(true, Ordering::SeqCst);
        match notify_send(
            self.listener.as_raw_fd(),
            &notif_resp_error(notif.id, libc::EACCES),
        ) {
            Ok(()) => {}
            Err(e) if matches!(e.raw_os_error(), Some(libc::ENOENT) | Some(libc::ESRCH)) => {}
            Err(e) => tracing::warn!("path-deny watcher NOTIF_SEND failed: {e}"),
        }
    }

    fn continue_notif(&mut self, id: u64) {
        if let Err(e) = notify_send(self.listener.as_raw_fd(), &notif_resp_continue(id))
            && !matches!(e.raw_os_error(), Some(libc::ENOENT) | Some(libc::ESRCH))
        {
            tracing::warn!("path-deny watcher NOTIF_SEND(continue) failed: {e}");
        }
    }
}

/// Read a NUL-terminated path at `addr` in task `pid`'s address space,
/// bounded by `MAX_PATH_BYTES`. A missing terminator within the bound
/// is an error — the compared value would be untrustworthy.
fn read_remote_path(pid: u32, addr: u64) -> io::Result<Vec<u8>> {
    let mut out = Vec::new();
    while out.len() < MAX_PATH_BYTES {
        let mut chunk = [0u8; READ_CHUNK];
        read_remote(pid, addr + out.len() as u64, &mut chunk)?;
        if let Some(end) = chunk.iter().position(|b| *b == 0) {
            out.extend_from_slice(&chunk[..end]);
            return Ok(out);
        }
        out.extend_from_slice(&chunk);
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "pathname exceeds PATH_MAX without a terminator",
    ))
}
