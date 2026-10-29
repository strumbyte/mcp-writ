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
    /// Entrypoint pin handoff: `(dup fd, resolved payload path,
    /// sha256)` for a payload-bound `entrypoint-hash`. The fd uncloaks
    /// in this spawn's `pre_exec` like the exe pins but is *not*
    /// keep-listed — init re-hashes the bytes it reads through the
    /// descriptor and mounts the verified copy over the path inside
    /// its mount namespace (`MCP_WRIT_NS_ENTRYPIN_*`), after which the
    /// mount holds the pinned content and init's scrub closes the
    /// descriptor before the workload exec.
    pub entry_pin: Option<(std::os::fd::RawFd, std::path::PathBuf, String)>,
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
        return Err(format!(
            "init post-GO failure: {}",
            annotate_init_err(&line)
        ));
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
        return Err(format!(
            "init exec stage failed: {}",
            annotate_init_err(&tail)
        ));
    }
    Ok(())
}

/// Append a known-cause hint to init's `ERR <stage> errno=<n>` report
/// (PR-35): the stage name and errno stay verbatim — a diagnostic must
/// never re-label them — and the appended text names the environment
/// constraint the `<stage> <errno>` pair usually means. Lines that are
/// not `ERR`-shaped, and pairs with no established cause, return
/// unchanged (a guessed cause would be worse than a bare errno).
fn annotate_init_err(line: &str) -> String {
    let trimmed = line.trim();
    match err_stage_hint(trimmed) {
        Some(hint) => format!("{trimmed} — {hint}"),
        None => trimmed.to_string(),
    }
}

fn err_stage_hint(line: &str) -> Option<&'static str> {
    let rest = line.strip_prefix("ERR ")?;
    let (stage, errno_raw) = rest.split_once(' ')?;
    let errno: i32 = errno_raw.strip_prefix("errno=")?.parse().ok()?;
    match (stage, errno) {
        ("proc-mount", libc::EPERM) => Some(
            "remounting /proc inside the new user+pid namespace requires the \
             current /proc to be fully visible — inside a container or a \
             nested user namespace (where parts of /proc are masked) the \
             kernel refuses EPERM; this is an environment constraint, not a \
             product bug — use `--linux-mechanism native` on this host",
        ),
        ("unshare", libc::EPERM) => Some(
            "unprivileged user-namespace creation was refused — check the \
             kernel.unprivileged_userns_clone and user.max_user_namespaces \
             sysctls and any LSM/container profile; recent WSL2 kernels \
             support userns",
        ),
        ("idmap", libc::EPERM) => Some(
            "the uid_map/gid_map write was refused — the maps must be \
             written by a process in the new userns's parent namespace \
             (self-map after unshare(CLONE_NEWUSER) is EPERM on WSL2); \
             check the userns sysctl settings on this host",
        ),
        _ => None,
    }
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
    // SAFETY: CMSG_SPACE is pure size arithmetic on the length argument
    // — it dereferences nothing.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    let mut cmsg = vec![0u8; unsafe { libc::CMSG_SPACE(fd_size as u32) } as usize];
    // SAFETY: `msghdr` is a POD struct of pointers and scalars, so the
    // all-zero bit pattern is the valid "unset" value; the fields the
    // kernel reads are assigned immediately below.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg.as_mut_ptr() as *mut _;
    // `msg_controllen` is `size_t` on glibc and `socklen_t` on musl —
    // `as _` lands the field's own width on either ABI.
    msg.msg_controllen = cmsg.len() as _;
    // SAFETY: `msg` is fully initialized — `iov` names the writable
    // 512-byte `data` and msg_control the CMSG_SPACE-sized `cmsg` — so
    // recvmsg writes stay inside live buffers.
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
        return Err(format!("init refused: {}", annotate_init_err(&line)));
    }
    if !line.starts_with("READY") {
        return Err(format!("unexpected init message: {}", line.trim()));
    }
    // A truncated control message means the fd did not survive the
    // handoff — refuse rather than trust a partial cmsg parse.
    if msg.msg_flags & libc::MSG_CTRUNC != 0 {
        return Err("READY ancillary data truncated — TUN fd not received".to_string());
    }
    // SAFETY: `msg` still describes the message just received (control
    // buffer and controllen updated by the kernel); a null return is
    // handled on the next line, and MSG_CTRUNC was refused above.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    let cmsg_hdr = unsafe { libc::CMSG_FIRSTHDR(&msg) };
    if cmsg_hdr.is_null() {
        return Err("READY arrived without the TUN fd".to_string());
    }
    // SAFETY: `cmsg_hdr` is the non-null first header inside the live
    // `cmsg` buffer — CMSG_FIRSTHDR only returns non-null when
    // msg_controllen covers a full cmsghdr, so the read is in-bounds;
    // read_unaligned covers the alignment Vec<u8> cannot guarantee.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    let hdr = unsafe { std::ptr::read_unaligned(cmsg_hdr) };
    // Refuse anything but a complete SCM_RIGHTS fd pass: a wrong
    // level/type, a payload shorter than RawFd, or a declared length
    // beyond what the kernel delivered would read unwritten bytes
    // where the descriptor sits.
    // SAFETY: CMSG_LEN is pure size arithmetic on the length argument
    // — it dereferences nothing.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    let fd_payload = unsafe { libc::CMSG_LEN(fd_size as u32) } as usize;
    // `cmsg_len`/`msg_controllen` are `size_t` on glibc and `socklen_t`
    // on musl — compare in u64, where either width fits.
    if hdr.cmsg_level != libc::SOL_SOCKET
        || hdr.cmsg_type != libc::SCM_RIGHTS
        || (hdr.cmsg_len as u64) < fd_payload as u64
        || (hdr.cmsg_len as u64) > msg.msg_controllen as u64
    {
        return Err("READY ancillary data is not a complete SCM_RIGHTS fd".to_string());
    }
    // SAFETY: the header just validated declares a full-RawFd payload
    // inside the received control region, so CMSG_DATA names readable
    // bytes; read_unaligned covers the Vec<u8> buffer's alignment 1.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    let fd = unsafe { std::ptr::read_unaligned(libc::CMSG_DATA(cmsg_hdr) as *const RawFd) };
    // SAFETY: `fd` is the descriptor SCM_RIGHTS just delivered — a new
    // fd owned by this process, wrapped into File exactly once.
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
        // network sits inside the namespace. Stderr is piped in both
        // modes: the workload's diagnostics are attacker-controlled
        // bytes and cross to the terminal through the sanitized
        // relay, never raw.
        SpawnStdio::Inherit => {
            cmd.stdin(std::process::Stdio::inherit())
                .stdout(std::process::Stdio::inherit())
                .stderr(std::process::Stdio::piped());
        }
        // The `run` route proxies stdin/stdout; stderr is piped for
        // the same sanitized relay.
        SpawnStdio::Piped => {
            cmd.stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped());
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
    // fd handoff: uncloak the pin's dup'd descriptors in this child's
    // pre_exec — never in the parent — so they survive init's re-exec.
    // `KEEPFDS` lists only the exe's fds (init's scrub keeps them open
    // for the workload exec); the entrypoint pin fd rides the same
    // uncloak list but is *not* keep-listed — the staged copy mount
    // holds the verified content, so init's scrub closes the
    // descriptor before the workload exec.
    let mut uncloak = cfg.exec_uncloak_fds.clone();
    if let Some((fd, _, _)) = &cfg.entry_pin {
        uncloak.push(*fd);
    }
    if !uncloak.is_empty() {
        use std::os::unix::process::CommandExt;
        // Safety: the closure performs `fcntl` only — no heap, no lock.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe {
            cmd.pre_exec(move || super::super::uncloak_exec_fds(&uncloak));
        }
    }
    if !cfg.exec_uncloak_fds.is_empty() {
        let keep = cfg
            .exec_uncloak_fds
            .iter()
            .map(|f| f.to_string())
            .collect::<Vec<_>>()
            .join(",");
        cmd.env(super::init_env::KEEPFDS, keep);
    }
    if let Some((fd, target, sha)) = &cfg.entry_pin {
        cmd.env(super::init_env::ENTRYPIN_FD, fd.to_string())
            .env(super::init_env::ENTRYPIN_TARGET, target.as_os_str())
            .env(super::init_env::ENTRYPIN_SHA, sha);
    }
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
    // The lineage tag is bound beside the spawn so registration can
    // attribute this session's orphaned escapees by marker value.
    let launch_tag = super::super::child::apply_unix_process_group(&mut cmd);
    // The child end must survive the exec into the init binary.
    let child =
        match super::super::child::spawn_and_register(|| cmd.spawn(), |c| c.id(), launch_tag) {
            Ok(mut c) => {
                if let Some(err) = c.stderr.take() {
                    crate::termutil::relay_child_stderr_blocking(err);
                }
                c
            }
            Err(e) => {
                // SAFETY: the spawn failed, so no child inherited
                // `child_sock` — both socketpair ends are still owned by
                // this process and each is closed once.
                // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
                unsafe { libc::close(child_sock) };
                // SAFETY: `parent_sock` is this process's live socketpair
                // end, closed once on this error path.
                // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
                unsafe { libc::close(parent_sock) };
                return Err(format!("init spawn failed: {e}"));
            }
        };
    // SAFETY: the spawned child holds `child_sock` through its inherited
    // (non-CLOEXEC) copy; the parent's copy is closed exactly once.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    unsafe { libc::close(child_sock) };
    // SAFETY: `parent_sock` is this process's still-open socketpair end,
    // owned and not yet wrapped — `File` takes ownership once.
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
                // SAFETY: scalar arguments; the negative pid names the
                // child's dedicated process group
                // (`apply_unix_process_group`), and the `pid > 0` guard
                // keeps a null handle from reaching kill(0).
                // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
                unsafe { libc::kill(-pid, libc::SIGKILL) };
            }
            drop(sock);
            let mut child = child;
            let _ = child.wait();
            // The launch never left the spawn boundary — a stale
            // registration would shield a recycled pid.
            super::super::child::unregister_launch_root(pid as u32);
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
    let mut cmd = build_init_command(cfg, &policy_path, child_sock, SpawnStdio::Piped);
    // Stamped on the std builder before the tokio conversion — the env
    // contract carries over unchanged.
    let launch_tag = super::super::child::apply_unix_process_group(&mut cmd);
    let mut cmd = tokio::process::Command::from(cmd);
    // The registration pid, captured under the registration lock — the
    // failure arm below names this (a completed tokio child's `id()`
    // can already be `None`).
    let mut registered_pid = 0u32;
    let mut child = match super::super::child::spawn_and_register(
        || cmd.spawn(),
        |c| {
            registered_pid = c.id().unwrap_or(0);
            registered_pid
        },
        launch_tag,
    ) {
        Ok(mut c) => {
            if let Some(err) = c.stderr.take() {
                crate::termutil::relay_child_stderr(err);
            }
            c
        }
        Err(e) => {
            // SAFETY: the spawn failed, so no child inherited
            // `child_sock` — both socketpair ends are still owned by
            // this process and each is closed once.
            // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
            unsafe { libc::close(child_sock) };
            // SAFETY: `parent_sock` is this process's live socketpair
            // end, closed once on this error path.
            // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
            unsafe { libc::close(parent_sock) };
            return Err(format!("init spawn failed: {e}"));
        }
    };
    // SAFETY: the spawned child holds `child_sock` through its inherited
    // (non-CLOEXEC) copy; the parent's copy is closed exactly once.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    unsafe { libc::close(child_sock) };
    // SAFETY: `parent_sock` is this process's still-open socketpair end,
    // owned and not yet wrapped — `File` takes ownership once.
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
            // The pid pinned at registration — a completed tokio
            // child's `id()` may already be `None`, and `kill(-0)`
            // (`kill(0)`) would SIGKILL *this* process's own group, so
            // the group signal needs a real pid. `start_kill` below
            // still reaches the child itself.
            let pid = registered_pid as i32;
            if pid > 0 {
                // SAFETY: scalar arguments; the negative pid names the
                // child's dedicated process group, and the `pid > 0`
                // guard keeps a null handle from reaching kill(0).
                // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
                unsafe { libc::kill(-pid, libc::SIGKILL) };
            }
            drop(sock);
            let _ = child.start_kill();
            // Sync context (spawn_blocking): reap via a raw blocking
            // waitpid — the child is ours and was just SIGKILL'd.
            // EINTR is retried (a caught signal mid-wait is not a reap
            // report); ECHILD means tokio's reaper collected it first —
            // either way the registration only drops once the reap is
            // confirmed. The root stays registered until then, so no
            // orphan sweep sees it unprotected mid-teardown.
            // SAFETY: scalar pid guarded > 0; a null status pointer is
            // allowed; only ever our own child.
            if pid > 0 {
                loop {
                    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
                    let ret = unsafe { libc::waitpid(pid, std::ptr::null_mut(), 0) };
                    if ret == pid {
                        break;
                    }
                    let err = std::io::Error::last_os_error().raw_os_error();
                    if err == Some(libc::EINTR) {
                        continue;
                    }
                    if err != Some(libc::ECHILD) {
                        // Neither a reap nor "already collected" — a
                        // persistent wait failure leaves the child
                        // state unknown; the registration drops anyway
                        // because a stale entry would shield a recycled
                        // pid while a later orphan sweep can still
                        // collect the zombie as unattributed residue.
                        tracing::warn!(
                            pid,
                            ?err,
                            "namespaced spawn teardown could not reap the init child"
                        );
                    }
                    break;
                }
            }
            // Same contract as the sync arm — the launch never left the
            // spawn boundary, so its registration must not outlive it.
            super::super::child::unregister_launch_root(registered_pid);
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
    // SAFETY: the name is a NUL-terminated static C string and the flag
    // a scalar — memfd_create takes no writable pointers.
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
    // SAFETY: `fd` is the fresh memfd descriptor returned above — owned
    // by this process, not aliased, wrapped into File exactly once.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    let mut f = unsafe { std::fs::File::from_raw_fd(fd) };
    let kdl = crate::policy::kdl_emit::to_kdl(policy);
    f.write_all(kdl.as_bytes())?;
    f.seek(std::io::SeekFrom::Start(0))?;
    // Freeze the content: no writes, growth, shrink, or further
    // sealing changes. An init that inherits the fd reads exactly
    // the bytes written here.
    let seals = libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_SEAL;
    // SAFETY: `fd` is the live memfd owned by `f`; F_ADD_SEALS takes
    // scalar arguments and touches no user memory.
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
    // SAFETY: `pair` is a valid, writable `[c_int; 2]` — exactly the
    // two-fd array socketpair(2) fills.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    if unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_SEQPACKET, 0, pair.as_mut_ptr()) } < 0 {
        return Err(format!("socketpair failed: {}", io::Error::last_os_error()));
    }
    // SAFETY: `pair[0]` is a live descriptor the socketpair just
    // returned; F_SETFD takes scalar arguments.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    unsafe {
        libc::fcntl(pair[0], libc::F_SETFD, libc::FD_CLOEXEC);
        // pair[1] deliberately stays inheritable.
    }
    Ok((pair[0], pair[1]))
}

fn set_nonblocking(fd: RawFd) -> io::Result<()> {
    // SAFETY: `fd` is the caller's live descriptor; F_GETFL/F_SETFL take
    // scalar arguments and touch no user memory — a bad fd fails EBADF.
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
    // SAFETY: `tv` is an initialized timeval and the call passes its
    // exact size; `fd` is the caller's live descriptor — a bad fd fails
    // EBADF rather than touching memory.
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

#[cfg(test)]
mod tests {
    use super::annotate_init_err;

    #[test]
    fn proc_mount_eperm_gets_the_environment_hint() {
        let annotated = annotate_init_err("ERR proc-mount errno=1");
        // The stage name and errno stay verbatim; the hint names the
        // constraint and the native route.
        assert!(annotated.contains("ERR proc-mount errno=1"), "{annotated}");
        assert!(annotated.contains("fully visible"), "{annotated}");
        assert!(annotated.contains("linux-mechanism native"), "{annotated}");
    }

    #[test]
    fn unshare_and_idmap_eperm_get_userns_hints() {
        let unshare = annotate_init_err("ERR unshare errno=1");
        assert!(unshare.contains("unprivileged user-namespace"), "{unshare}");
        let idmap = annotate_init_err("ERR idmap errno=1");
        assert!(idmap.contains("parent namespace"), "{idmap}");
        assert!(idmap.contains("WSL2"), "{idmap}");
    }

    #[test]
    fn unrecognized_lines_and_pairs_pass_through() {
        // No hint is ever a guessed cause: unknown stages, other
        // errnos, and non-errno ERR forms keep the line verbatim.
        for line in [
            "ERR exec errno=2",
            "ERR unshare errno=0",
            "ERR proc-mount errno=22",
            "ERR sandbox policy-load bad kdl",
            "ERR argv missing-sockfd-or-workload",
            "something else entirely",
        ] {
            assert_eq!(annotate_init_err(line), line.trim());
        }
    }
}
