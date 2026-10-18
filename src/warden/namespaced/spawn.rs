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
    /// fd-exec handoff: the pin's `F_DUPFD_CLOEXEC` descriptor numbers —
    /// uncloaked in this spawn's `pre_exec` (so they survive init's own
    /// re-exec) and listed in `MCP_WRIT_NS_KEEPFDS` so init's fd scrub
    /// keeps them open for the workload exec.
    pub exec_uncloak_fds: Vec<std::os::fd::RawFd>,
}

/// The launched namespaced workload. `sock` is the handshake end —
/// `go()` reads it through the exec epoch (CLOEXEC EOF on success,
/// `ERR exec` on failure), so once `go` returns the socket's only
/// remaining meaning is "init died without execing".
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

/// PR-16 — the tokio-spawned twin of [`NamespacedChild`]: the `run`
/// route needs piped stdio and an async-reaped child, everything else
/// (socketpair handshake, TUN ownership, GO protocol) is identical.
pub struct NamespacedChildTokio {
    pub child: tokio::process::Child,
    /// The TUN device inside the child's netns — the proxy's only
    /// window into workload egress.
    pub tun: std::fs::File,
    sock: std::fs::File,
    /// Set when init reported a successful sandbox apply (`SANDBOXED`)
    /// — read after [`Self::go`].
    pub sandbox_applied: std::cell::Cell<Option<bool>>,
}

/// Tell init to apply the sandbox and exec; block until the exchange
/// completes (bounded — a wedged init is killed after the timeout and
/// reported as a spawn failure). Shared by the std and tokio child
/// types — the handshake protocol does not differ.
///
/// Two reads, fail-closed:
///
/// 1. The sandbox verdict — `SANDBOXED` / `SANDBOX-SKIPPED` (the debug
///    hatch) or `ERR <stage>`. EOF, a short write, or any unrecognized
///    reply is an error: init dying between READY and its status
///    report must read as a launch failure, never as a skipped sandbox.
/// 2. The exec epoch — init keeps the handshake socket CLOEXEC, so a
///    successful `execve` closes it and this read returns EOF. An
///    `execvp` failure instead reports `ERR exec` here: a workload
///    that never execed cannot be recorded as a launched one. The
///    residual is init dying between status and exec — the namespace
///    tree dies with it (pidns-init exit 97), so the run still cannot
///    go unenforced; the launch records it through the exit status.
fn go_handshake(
    sock: &std::fs::File,
    sandbox_applied: &std::cell::Cell<Option<bool>>,
) -> Result<(), String> {
    use std::io::{Read, Write};
    set_sock_timeout(sock.as_raw_fd(), 10).map_err(|e| format!("handshake timeout setup: {e}"))?;
    let mut sock = sock;
    sock.write_all(b"G")
        .map_err(|e| format!("GO write failed: {e}"))?;
    let mut buf = [0u8; 512];
    let n = sock
        .read(&mut buf)
        .map_err(|e| format!("post-GO status read failed: {e}"))?;
    if n == 0 {
        return Err(
            "init exited between READY and its sandbox verdict (EOF on the \
             handshake socket)"
                .to_string(),
        );
    }
    let line = String::from_utf8_lossy(&buf[..n]);
    // Stream reads can coalesce init's two writes (`SANDBOXED` then
    // `ERR exec`) into one buffer — match the verdict as a *prefix* so
    // the tail still reports as the exec-stage failure it is.
    let (applied, tail) = if let Some(t) = line.strip_prefix("SANDBOXED") {
        (true, t)
    } else if let Some(t) = line.strip_prefix("SANDBOX-SKIPPED") {
        (false, t)
    } else if line.starts_with("ERR ") {
        return Err(format!("init post-GO failure: {}", line.trim()));
    } else {
        return Err(format!("unrecognized init status: {}", line.trim()));
    };
    sandbox_applied.set(Some(applied));
    // Exec epoch: CLOEXEC close (EOF) = the workload execed; a second
    // message is the exec failure report. Anything else is a broken
    // helper — refuse.
    let tail = if tail.is_empty() {
        let n = sock
            .read(&mut buf)
            .map_err(|e| format!("post-status read failed: {e}"))?;
        String::from_utf8_lossy(&buf[..n]).into_owned()
    } else {
        tail.to_string()
    };
    if !tail.is_empty() {
        return Err(format!("init exec stage failed: {}", tail.trim()));
    }
    Ok(())
}

impl NamespacedChild {
    /// Tell init to apply the sandbox and exec. Blocks until init's
    /// `SANDBOXED`/`SANDBOX-SKIPPED`/`ERR` reply *and* the exec epoch
    /// (the handshake socket's CLOEXEC close proves `execve` ran; an
    /// exec failure reports `ERR exec`) — bounded by the socket
    /// timeout; a wedged init is killed after it and reported as a
    /// spawn failure.
    pub fn go(&mut self) -> Result<(), String> {
        go_handshake(&self.sock, &self.sandbox_applied)
    }

    /// The child's pid, for process-group teardown.
    pub fn pid(&self) -> i32 {
        self.child.id() as i32
    }
}

impl NamespacedChildTokio {
    /// Same [`NamespacedChild::go`] handshake on the tokio child — a
    /// bounded blocking socket exchange ending at the exec epoch; call
    /// inside `spawn_blocking` or accept the short stall (init answers
    /// within the timeout).
    pub fn go(&mut self) -> Result<(), String> {
        go_handshake(&self.sock, &self.sandbox_applied)
    }

    /// The child's pid, for process-group teardown.
    pub fn pid(&self) -> i32 {
        self.child.id().unwrap_or(0) as i32
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
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    let mut cmsg = vec![0u8; unsafe { libc::CMSG_SPACE(fd_size as u32) } as usize];
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg.as_mut_ptr() as *mut _;
    msg.msg_controllen = cmsg.len();
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
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
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    let cmsg_hdr = unsafe { libc::CMSG_FIRSTHDR(&msg) };
    if cmsg_hdr.is_null() {
        return Err("READY arrived without the TUN fd".to_string());
    }
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    let fd = unsafe { std::ptr::read_unaligned(libc::CMSG_DATA(cmsg_hdr) as *const RawFd) };
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    let tun = unsafe { std::fs::File::from_raw_fd(fd) };
    set_nonblocking(tun.as_raw_fd()).map_err(|e| format!("tun nonblocking failed: {e}"))?;
    Ok(tun)
}

/// Stdio wiring for the init child — `Inherit` keeps the
/// `namespaced-run` PoC contract (an interactive session), `Piped`
/// gives the `run` route the stdin/stdout it proxies.
pub enum SpawnStdio {
    Inherit,
    Piped,
}

/// Build the `namespaced-init` command — shared by the std and tokio
/// spawn paths so the env/fd/pre-exec contract can never drift. The
/// policy memfd must survive the exec into init — the caller created
/// it without CLOEXEC.
fn build_init_command(
    cfg: &SpawnConfig,
    policy_path: &str,
    child_sock: RawFd,
    stdio: SpawnStdio,
) -> std::process::Command {
    let mut cmd = std::process::Command::new("/proc/self/exe");
    cmd.arg(super::INIT_SUBCOMMAND).arg("--").args(&cfg.argv);
    match stdio {
        // Inherit stdio — to the workload this is an ordinary stdio
        // MCP session (same contract as `unotify-run`); only its
        // network sits inside the namespace.
        SpawnStdio::Inherit => {
            cmd.stdin(std::process::Stdio::inherit())
                .stdout(std::process::Stdio::inherit())
                .stderr(std::process::Stdio::inherit());
        }
        // The `run` route proxies stdin/stdout; stderr still inherits.
        SpawnStdio::Piped => {
            cmd.stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::inherit());
        }
    }
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
        .env(super::init_env::POLICY, policy_path);
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
    // fd-exec handoff: uncloak the pin's dup'd descriptors in this
    // child's pre_exec — never in the parent — so they survive init's
    // re-exec; `KEEPFDS` tells init's scrub to keep them for the
    // workload exec.
    if !cfg.exec_uncloak_fds.is_empty() {
        use std::os::unix::process::CommandExt;
        let fds: Vec<std::os::fd::RawFd> = cfg.exec_uncloak_fds.clone();
        // Safety: the closure performs `fcntl` only — no heap, no lock.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe {
            cmd.pre_exec(move || super::super::uncloak_exec_fds(&fds));
        }
        let keep = cfg
            .exec_uncloak_fds
            .iter()
            .map(|f| f.to_string())
            .collect::<Vec<_>>()
            .join(",");
        cmd.env(super::init_env::KEEPFDS, keep);
    }
    super::super::child::apply_unix_process_group(&mut cmd);
    cmd
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

    let mut cmd = build_init_command(cfg, &policy_path, child_sock, SpawnStdio::Inherit);
    // The child end must survive the exec into the init binary.
    let child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
            unsafe { libc::close(child_sock) };
            // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
            unsafe { libc::close(parent_sock) };
            return Err(format!("init spawn failed: {e}"));
        }
    };
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    unsafe { libc::close(child_sock) };
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    let mut sock = unsafe { std::fs::File::from_raw_fd(parent_sock) };

    match await_ready(&mut sock) {
        Ok(tun) => Ok(NamespacedChild {
            child,
            tun,
            sock,
            sandbox_applied: std::cell::Cell::new(None),
        }),
        Err(e) => {
            // `kill(0)` signals *this* process's own group — a pid that
            // never materialized must not reach the group call.
            let pid = child.id() as i32;
            if pid > 0 {
                // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
                unsafe { libc::kill(-pid, libc::SIGKILL) };
            }
            drop(sock);
            let mut child = child;
            let _ = child.wait();
            Err(e)
        }
    }
}

/// PR-16 — the `run`-route spawn: same init helper, same handshake,
/// but the child is a `tokio::process::Child` with piped stdin/stdout
/// so the MCP proxy can mediate the session. On any failure the
/// half-spawned child is group-killed and reaped exactly like the
/// sync path.
///
/// The whole sequence is blocking (socketpair handshake + bounded
/// READY read) — callers run it inside `tokio::task::spawn_blocking`
/// or accept the bounded stall; the parent `READY` wait is capped at
/// 15s by `await_ready`'s socket timeout.
pub fn spawn_namespaced_child_tokio(cfg: &SpawnConfig) -> Result<NamespacedChildTokio, String> {
    if cfg.argv.is_empty() {
        return Err("empty workload argv".to_string());
    }
    let (parent_sock, child_sock) = socketpair()?;

    let policy_fd_num = cfg.policy_kdl_fd.as_raw_fd();
    let policy_path = format!("/proc/self/fd/{policy_fd_num}");

    // `tokio::process::Command` wraps the std builder, so the pre_exec
    // uncloak closure and the env contract carry over unchanged.
    let cmd = build_init_command(cfg, &policy_path, child_sock, SpawnStdio::Piped);
    let mut cmd = tokio::process::Command::from(cmd);
    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
            unsafe { libc::close(child_sock) };
            // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
            unsafe { libc::close(parent_sock) };
            return Err(format!("init spawn failed: {e}"));
        }
    };
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    unsafe { libc::close(child_sock) };
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    let mut sock = unsafe { std::fs::File::from_raw_fd(parent_sock) };

    match await_ready(&mut sock) {
        Ok(tun) => Ok(NamespacedChildTokio {
            child,
            tun,
            sock,
            sandbox_applied: std::cell::Cell::new(None),
        }),
        Err(e) => {
            // `id()` is `None` once the handle can no longer name the
            // child — `kill(-0)` (`kill(0)`) would SIGKILL *this*
            // process's own group, so the group signal needs a real
            // pid. `start_kill` below still reaches the child itself.
            let pid = child.id().unwrap_or(0) as i32;
            if pid > 0 {
                // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
                unsafe { libc::kill(-pid, libc::SIGKILL) };
            }
            drop(sock);
            let _ = child.start_kill();
            Err(e)
        }
    }
}

/// Serialize the effective policy into a sealed read-only memfd init
/// inherits. `memfd_create` with `MFD_ALLOW_SEALING` (needed to seal
/// at all) and without `MFD_CLOEXEC` — the fd must survive the exec
/// into the helper. The bytes are then `F_SEAL_*`-frozen so no
/// fd-sharing writer can rewrite the policy between the handoff and
/// init's read. Shared by `namespaced-run` and the `run` namespaced
/// dispatch — one policy-serialization source, never two.
pub(crate) fn policy_memfd(policy: &crate::policy::Policy) -> io::Result<std::fs::File> {
    use std::io::{Seek, Write};
    const MFD_ALLOW_SEALING: u32 = 0x0002;
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    let fd = unsafe {
        libc::syscall(
            libc::SYS_memfd_create,
            c"mcp-writ-policy".as_ptr(),
            MFD_ALLOW_SEALING,
        ) as i32
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    let mut f = unsafe { std::fs::File::from_raw_fd(fd) };
    let kdl = crate::policy::kdl_emit::to_kdl(policy);
    f.write_all(kdl.as_bytes())?;
    f.seek(std::io::SeekFrom::Start(0))?;
    // Freeze the content: no writes, growth, shrink, or further
    // sealing changes. An init that inherits the fd reads exactly
    // the bytes written here.
    let seals = libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_SEAL;
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    if unsafe { libc::fcntl(fd, libc::F_ADD_SEALS, seals) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(f)
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
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    if unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_SEQPACKET, 0, pair.as_mut_ptr()) } < 0 {
        return Err(format!("socketpair failed: {}", io::Error::last_os_error()));
    }
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    unsafe {
        libc::fcntl(pair[0], libc::F_SETFD, libc::FD_CLOEXEC);
        // pair[1] deliberately stays inheritable.
    }
    Ok((pair[0], pair[1]))
}

fn set_nonblocking(fd: RawFd) -> io::Result<()> {
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
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
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
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
