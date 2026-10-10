//! Parent side of the namespaced launch: socketpair → spawn
//! `namespaced-init` → handshake until `READY`+TUN-fd (or `ERR`) →
//! hold the child until the caller starts the proxy, then `GO`.
//!
//! The child is spawned in its own process group so teardown is a
//! group kill, identical to the `unotify-run` contract. `stdin`/`stdout`
//! are piped through unchanged — to the workload this is an ordinary
//! stdio MCP session; only its network sits inside the namespace.

use std::io;
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};

/// Inputs the parent prepares before spawning the init helper.
pub struct SpawnConfig {
    /// Workload argv — `[0]` keeps the caller's spelling inside the
    /// child (same `arg0` contract as `run`).
    pub argv: Vec<String>,
    /// Resolved argv[0] — the verified executable image init execs.
    pub resolved_exe: std::path::PathBuf,
    /// Read-only memfd carrying the *effective* (bound) policy as KDL
    /// — init re-loads it through `/proc/self/fd/N` so the bytes it
    /// builds Landlock/seccomp bits from are identical to the parent's
    /// view. Kept open by the parent until `go()` reports SANDBOXED.
    pub policy_kdl_fd: std::fs::File,
    /// Restricted child environment assembled by the caller
    /// (`spawn_env_pairs`); `None` inherits the parent env.
    pub env: Option<Vec<(std::ffi::OsString, std::ffi::OsString)>>,
}

/// The launched namespaced workload. `sock` is the handshake end —
/// after `go()` it can still report an `ERR`/`SANDBOXED` line from the
/// child's final stages; dropping it makes init abort before exec.
pub struct NamespacedChild {
    pub child: std::process::Child,
    /// The TUN device inside the child's netns — the proxy's only
    /// window into workload egress. Owned by the parent: if the proxy
    /// dies the fd closes and the workload's packets have nowhere to
    /// go (fail-closed).
    pub tun: std::fs::File,
    sock: std::fs::File,
    /// Set when init reported a successful sandbox apply (`SANDBOXED`)
    /// — read after [`Self::go`].
    pub sandbox_applied: std::cell::Cell<Option<bool>>,
}

impl NamespacedChild {
    /// Tell init to apply the sandbox and exec. Blocks until init's
    /// `SANDBOXED`/`ERR` reply (bounded — a wedged init is killed after
    /// the timeout and reported as a spawn failure).
    pub fn go(&mut self) -> Result<(), String> {
        use std::io::{Read, Write};
        set_sock_timeout(self.sock.as_raw_fd(), 10)
            .map_err(|e| format!("handshake timeout setup: {e}"))?;
        self.sock
            .write_all(b"G")
            .map_err(|e| format!("GO write failed: {e}"))?;
        let mut buf = [0u8; 512];
        let n = self
            .sock
            .read(&mut buf)
            .map_err(|e| format!("post-GO status read failed: {e}"))?;
        let line = String::from_utf8_lossy(&buf[..n]);
        if line.starts_with("ERR ") {
            return Err(format!("init post-GO failure: {}", line.trim()));
        }
        self.sandbox_applied
            .set(Some(line.starts_with("SANDBOXED")));
        Ok(())
    }

    /// The child's pid, for process-group teardown.
    pub fn pid(&self) -> i32 {
        self.child.id() as i32
    }
}

/// Blocking handshake read: returns on `READY` (fd attached),
/// `ERR <stage>` (init refused), EOF, or timeout — all non-READY
/// outcomes are launch failures.
fn await_ready(sock: &mut std::fs::File) -> Result<std::fs::File, String> {
    set_sock_timeout(sock.as_raw_fd(), 15).map_err(|e| format!("handshake timeout setup: {e}"))?;
    let mut data = [0u8; 512];
    let mut iov = libc::iovec {
        iov_base: data.as_mut_ptr() as *mut _,
        iov_len: data.len(),
    };
    let fd_size = std::mem::size_of::<RawFd>();
    let mut cmsg = vec![0u8; unsafe { libc::CMSG_SPACE(fd_size as u32) } as usize];
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg.as_mut_ptr() as *mut _;
    msg.msg_controllen = cmsg.len();
    let n = unsafe { libc::recvmsg(sock.as_raw_fd(), &mut msg, 0) };
    if n < 0 {
        return Err(format!(
            "handshake recvmsg failed: {}",
            io::Error::last_os_error()
        ));
    }
    if n == 0 {
        return Err("init exited before READY (no message)".to_string());
    }
    let line = String::from_utf8_lossy(&data[..n as usize]).to_string();
    if line.starts_with("ERR ") {
        return Err(format!("init refused: {}", line.trim()));
    }
    if !line.starts_with("READY") {
        return Err(format!("unexpected init message: {}", line.trim()));
    }
    // A truncated control message means the fd did not survive the
    // handoff — refuse rather than trust a partial cmsg parse.
    if msg.msg_flags & libc::MSG_CTRUNC != 0 {
        return Err("READY ancillary data truncated — TUN fd not received".to_string());
    }
    let cmsg_hdr = unsafe { libc::CMSG_FIRSTHDR(&msg) };
    if cmsg_hdr.is_null() {
        return Err("READY arrived without the TUN fd".to_string());
    }
    let fd = unsafe { std::ptr::read_unaligned(libc::CMSG_DATA(cmsg_hdr) as *const RawFd) };
    let tun = unsafe { std::fs::File::from_raw_fd(fd) };
    set_nonblocking(tun.as_raw_fd()).map_err(|e| format!("tun nonblocking failed: {e}"))?;
    Ok(tun)
}

/// Spawn `namespaced-init` and complete the READY handshake. On any
/// failure the half-spawned child is killed (group) and reaped.
pub fn spawn_namespaced_child(cfg: &SpawnConfig) -> Result<NamespacedChild, String> {
    if cfg.argv.is_empty() {
        return Err("empty workload argv".to_string());
    }
    let (parent_sock, child_sock) = socketpair()?;

    // The policy memfd must survive the exec into init — the caller
    // created it without CLOEXEC.
    let policy_fd_num = cfg.policy_kdl_fd.as_raw_fd();
    let policy_path = format!("/proc/self/fd/{policy_fd_num}");

    let mut cmd = std::process::Command::new("/proc/self/exe");
    cmd.arg(super::INIT_SUBCOMMAND)
        .arg("--")
        .args(&cfg.argv)
        // Inherit stdio — to the workload this is an ordinary stdio
        // MCP session (same contract as `unotify-run`/`run`); only its
        // network sits inside the namespace.
        .stdin(std::process::Stdio::inherit())
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit());
    if let Some(env) = &cfg.env {
        cmd.env_clear();
        for (k, v) in env {
            // The `MCP_WRIT_NS_*` contract is a parent→init control
            // channel, not environment: a policy `allowed_names` entry
            // must not be able to inject it through the filtered block.
            if super::init_env::ALL
                .iter()
                .any(|n| k.as_os_str() == std::ffi::OsStr::new(n))
            {
                continue;
            }
            cmd.env(k, v);
        }
    } else {
        // Inherit-all keeps the same rule — ambient `MCP_WRIT_NS_*`
        // values in the caller's environment are not forwarded; only
        // the explicit sets below reach init.
        for var in super::init_env::ALL {
            cmd.env_remove(var);
        }
    }
    // Init control vars are always written last so neither the ambient
    // environment nor the policy-filtered block can shadow them.
    cmd.env(super::init_env::SOCK_FD, child_sock.to_string())
        .env(super::init_env::EXE, cfg.resolved_exe.as_os_str())
        .env(super::init_env::POLICY, policy_path.as_str());
    if skip_sandbox_requested() {
        // Debug hatch — an explicit supervisor-side opt-in. Init
        // answers `SANDBOX-SKIPPED` so the run records the weakened
        // state honestly instead of claiming `sandbox_applied`.
        eprintln!(
            "Warning: {}=1 — the namespaced workload will run without \
             Landlock/seccomp (debug hatch; the report records the skip)",
            super::init_env::SKIP_SANDBOX
        );
        cmd.env(super::init_env::SKIP_SANDBOX, "1");
    }
    super::super::child::apply_unix_process_group(&mut cmd);
    // The child end must survive the exec into the init binary.
    let child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            unsafe { libc::close(child_sock) };
            unsafe { libc::close(parent_sock) };
            return Err(format!("init spawn failed: {e}"));
        }
    };
    unsafe { libc::close(child_sock) };
    let mut sock = unsafe { std::fs::File::from_raw_fd(parent_sock) };

    match await_ready(&mut sock) {
        Ok(tun) => Ok(NamespacedChild {
            child,
            tun,
            sock,
            sandbox_applied: std::cell::Cell::new(None),
        }),
        Err(e) => {
            let pid = child.id() as i32;
            unsafe { libc::kill(-pid, libc::SIGKILL) };
            drop(sock);
            let mut child = child;
            let _ = child.wait();
            Err(e)
        }
    }
}

/// The skip-sandbox hatch is honored only as an explicit parent-side
/// decision: `=1` on the supervisor's own environment forwards the
/// flag to init. It can never arrive through the policy-filtered env
/// block — the spawn above strips `MCP_WRIT_NS_*` from it first.
fn skip_sandbox_requested() -> bool {
    std::env::var(super::init_env::SKIP_SANDBOX).as_deref() == Ok("1")
}

fn socketpair() -> Result<(RawFd, RawFd), String> {
    let mut pair = [0i32; 2];
    // No SOCK_CLOEXEC on the child end — it must live through exec.
    if unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_SEQPACKET, 0, pair.as_mut_ptr()) } < 0 {
        return Err(format!("socketpair failed: {}", io::Error::last_os_error()));
    }
    unsafe {
        libc::fcntl(pair[0], libc::F_SETFD, libc::FD_CLOEXEC);
        // pair[1] deliberately stays inheritable.
    }
    Ok((pair[0], pair[1]))
}

fn set_nonblocking(fd: RawFd) -> io::Result<()> {
    unsafe {
        let flags = libc::fcntl(fd, libc::F_GETFL);
        if flags < 0 || libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) < 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

/// `SO_RCVTIMEO` — `File` has no read-timeout API.
fn set_sock_timeout(fd: RawFd, secs: u64) -> io::Result<()> {
    let tv = libc::timeval {
        tv_sec: secs as _,
        tv_usec: 0,
    };
    if unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            &tv as *const libc::timeval as *const libc::c_void,
            std::mem::size_of::<libc::timeval>() as u32,
        )
    } < 0
    {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}
