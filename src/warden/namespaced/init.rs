//! The `namespaced-init` helper — the process that becomes the
//! workload.
//!
//! Runs inside a re-exec'd `/proc/self/exe` (see `spawn.rs`): every
//! step below happens post-exec so ordinary Rust allocation is safe.
//! Steps, in fail-closed order — any failure sends `ERR <stage>` on the
//! handshake socket and exits non-zero, and the parent kills the
//! launch rather than fall back to a natively networked child:
//!
//! 0. `fork()` — uid_map writes must come from a process in the
//!    *parent* user namespace (a process cannot write its own map on
//!    kernels that require `CAP_SETUID` over the parent userns, and
//!    WSL2 enforces this). Init stays as the supervisor: it writes the
//!    grandchild's maps, then waitpid()s and forwards the exit status.
//! 1. `unshare(CLONE_NEWUSER|CLONE_NEWNET|CLONE_NEWNS)` in the
//!    grandchild — one call, so a partial grant (userns but no netns)
//!    cannot leave a half-isolated child.
//! 2. `setgroups=deny` + `uid_map`/`gid_map` written by the init
//!    parent into `/proc/<grandchild>/` — maps the launcher's
//!    euid/egid to namespace-root (the `unshare --map-root-user`
//!    mechanism) so the workload keeps its file identity without
//!    real privilege.
//!    inside the fresh netns this is the only non-loopback device.
//! 4. rtnetlink: `lo` up, `egress0` up with `10.250.0.2/24`,
//!    `default dev egress0`. No gateway: a point-to-point TUN routes
//!    every packet straight to our fd.
//! 5. IPv6 disabled (`net.ipv6.conf.all.disable_ipv6`) — the proxy is
//!    v4-only; disabling the stack keeps v6 fail-closed *inside* the
//!    child rather than silently blackholed (the proxy drops v6 too,
//!    as a second fence).
//! 6. `resolv.conf` — a private tmpfs over `/run` hides host daemon
//!    sockets, then a generated `nameserver 10.250.0.1` file replaces
//!    resolution: written at the resolved target when it lives under
//!    the new `/run`, otherwise bind-mounted over `/etc/resolv.conf`
//!    from a private `/tmp` tmpfs (a memfd path is EINVAL to mount).
//!    The host file is never touched; if `/etc/resolv.conf` does not
//!    exist we leave resolution broken (fail-closed — a workload that
//!    cannot resolve cannot turn name rules into flows).
//! 7. Handshake: `READY` + the TUN fd via `SCM_RIGHTS`; wait for `GO`.
//! 8. Linux sandbox: the effective policy is re-loaded from the
//!    serialized KDL the parent passed (`MCP_WRIT_NS_POLICY`) and the
//!    standard `no_new_privs → Landlock → seccomp` bits are applied
//!    with the socket-family narrowing relaxed — inside this netns a
//!    socket of any type still dead-ends at the TUN, and the workload
//!    legitimately needs datagram sockets for the UDP path. Landlock's
//!    TCP-connect port rules stay on: they express the same policy.
//! 9. Scrub `MCP_WRIT_NS_*` env vars, close every fd > 2, `execvp`.

use std::ffi::CString;
use std::os::unix::io::RawFd;

const STAGE_UNSHARE: &str = "unshare";
const STAGE_IDMAP: &str = "idmap";
const STAGE_TUN: &str = "tun";
const STAGE_NET: &str = "net";
const STAGE_SANDBOX: &str = "sandbox";
const STAGE_EXEC: &str = "exec";

const IFNAME: &[u8] = b"egress0";

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(-1)
}

/// Best-effort line to the parent; the socket may already be gone.
fn send(sock: RawFd, msg: &[u8]) {
    unsafe {
        libc::send(sock, msg.as_ptr() as *const libc::c_void, msg.len(), 0);
    }
}

fn send_err(sock: RawFd, stage: &str, e: i32) {
    send(sock, format!("ERR {stage} errno={e}").as_bytes());
}

/// Send `READY` with `fd` attached via SCM_RIGHTS.
fn send_ready_with_fd(sock: RawFd, fd: RawFd) -> std::io::Result<()> {
    let mut iov = libc::iovec {
        iov_base: b"READY".as_ptr() as *mut _,
        iov_len: 5,
    };
    let mut cmsg_buf =
        [0u8; unsafe { libc::CMSG_SPACE(std::mem::size_of::<RawFd>() as u32) } as usize];
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg_buf.as_mut_ptr() as *mut _;
    msg.msg_controllen = cmsg_buf.len();
    let cmsg = unsafe { libc::CMSG_FIRSTHDR(&msg) };
    unsafe {
        (*cmsg).cmsg_level = libc::SOL_SOCKET;
        (*cmsg).cmsg_type = libc::SCM_RIGHTS;
        (*cmsg).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<RawFd>() as u32) as usize;
        std::ptr::copy_nonoverlapping(
            &fd as *const RawFd as *const u8,
            libc::CMSG_DATA(cmsg),
            std::mem::size_of::<RawFd>(),
        );
    }
    msg.msg_controllen = unsafe { (*cmsg).cmsg_len };
    if unsafe { libc::sendmsg(sock, &msg, 0) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

fn write_file(path: &str, contents: &str) -> std::io::Result<()> {
    std::fs::write(path, contents)
}

/// uid/gid map: `0 <euid> 1` — namespace-root maps to the launcher.
/// Write `pid`'s maps from the *parent* side — the only mapping path
/// an unprivileged launcher has on this kernel (self-map after
/// `unshare(CLONE_NEWUSER)` is EPERM on WSL2; the writer must sit in
/// the new userns's parent and map a single euid/egid).
fn write_id_maps_for(pid: i32, euid: u32, egid: u32) -> std::io::Result<()> {
    write_file(&format!("/proc/{pid}/setgroups"), "deny")?;
    write_file(&format!("/proc/{pid}/uid_map"), &format!("0 {euid} 1"))?;
    write_file(&format!("/proc/{pid}/gid_map"), &format!("0 {egid} 1"))?;
    Ok(())
}

/// Plain blocking pipe pair for the map handshake — SOCK_SEQPACKET
/// would also work; pipes keep the read/write directions obvious.
fn pipe_pair() -> std::io::Result<(RawFd, RawFd)> {
    let mut p = [0i32; 2];
    if unsafe { libc::pipe(p.as_mut_ptr()) } < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok((p[0], p[1]))
    }
}

fn pipe_write(fd: RawFd) -> std::io::Result<()> {
    if unsafe { libc::write(fd, b"1".as_ptr() as *const libc::c_void, 1) } != 1 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// One byte or EOF — both mean "peer done" vs "peer died"; callers
/// distinguish by context.
fn pipe_read(fd: RawFd) -> std::io::Result<()> {
    let mut b = [0u8; 1];
    let n = unsafe { libc::read(fd, b.as_mut_ptr() as *mut libc::c_void, 1) };
    if n == 1 {
        Ok(())
    } else if n == 0 {
        Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "peer closed pipe",
        ))
    } else {
        Err(std::io::Error::last_os_error())
    }
}

fn create_tun() -> std::io::Result<RawFd> {
    let fd = unsafe { libc::open(c"/dev/net/tun".as_ptr(), libc::O_RDWR) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };
    ifr.ifr_ifru.ifru_flags = (libc::IFF_TUN | libc::IFF_NO_PI) as i16;
    for (slot, &b) in ifr.ifr_name.iter_mut().zip(IFNAME.iter()) {
        *slot = b as libc::c_char;
    }
    if unsafe { libc::ioctl(fd, libc::TUNSETIFF, &ifr) } < 0 {
        let e = std::io::Error::last_os_error();
        unsafe { libc::close(fd) };
        return Err(e);
    }
    Ok(fd)
}

/// Resolve `/etc/resolv.conf`'s real target BEFORE `/run` is covered —
/// a link like `/etc/resolv.conf` → `/run/resolvconf/resolv.conf`
/// must find its target inside the new tmpfs, and that decision needs
/// the resolved path, not the link spelling. Returns the target and
/// the contents to install.
fn resolv_conf_target(dns: &std::net::Ipv4Addr) -> std::io::Result<(std::path::PathBuf, String)> {
    if !std::path::Path::new("/etc/resolv.conf").exists() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "/etc/resolv.conf absent — name resolution stays broken (fail-closed)",
        ));
    }
    let target = std::fs::canonicalize("/etc/resolv.conf")?;
    Ok((target, format!("nameserver {dns}\noptions ndots:0\n")))
}

/// Give the workload a resolver that points at the proxy's gateway.
/// Runs AFTER the `/run` tmpfs: a resolved target under `/run` is
/// recreated inside the fresh tmpfs (the link then resolves to our
/// file); anything else gets a bind-mount of a real file — a
/// `/proc/self/fd/N` memfd symlink is EINVAL to `mount(2)`, so the
/// source lives on a private tmpfs over `/tmp`, which also means
/// workload scratch under `/tmp` never touches the host filesystem.
fn redirect_resolv_conf(target: &std::path::Path, contents: &str) -> std::io::Result<()> {
    if target.starts_with("/run") {
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent)?;
        }
        return std::fs::write(target, contents);
    }
    let ctmp = CString::new("/tmp").unwrap();
    if unsafe {
        libc::mount(
            c"tmpfs".as_ptr(),
            ctmp.as_ptr(),
            c"tmpfs".as_ptr(),
            0,
            c"mode=1777".as_ptr() as *const libc::c_void,
        )
    } < 0
    {
        return Err(std::io::Error::last_os_error());
    }
    let src = "/tmp/.resolv.conf";
    std::fs::write(src, contents)?;
    let csrc = CString::new(src).unwrap();
    let cdst = CString::new("/etc/resolv.conf").unwrap();
    if unsafe {
        libc::mount(
            csrc.as_ptr(),
            cdst.as_ptr(),
            std::ptr::null(),
            libc::MS_BIND,
            std::ptr::null(),
        )
    } < 0
    {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

fn disable_ipv6() -> std::io::Result<()> {
    write_file("/proc/sys/net/ipv6/conf/all/disable_ipv6", "1")
}

/// Hide host daemon IPC. The mountns shares the host filesystem, and
/// Landlock does not mediate `connect(2)` on `AF_UNIX` — a workload
/// that can resolve `/run/dbus/system_bus_socket` or
/// `/run/docker.sock` has a live channel to a host daemon that holds
/// *unsandboxed* authority (an egress/escape proxy). Cover `/run`
/// with a private tmpfs: those pathnames stop resolving here.
/// `/var/run` is a `/run` symlink on every modern distro, so it is
/// covered too. Socket paths outside `/run` remain governed by the
/// fs policy and are recorded in the report's limitations.
fn hide_host_ipc_sockets() {
    if unsafe {
        libc::mount(
            c"tmpfs".as_ptr(),
            c"/run".as_ptr(),
            c"tmpfs".as_ptr(),
            0,
            c"mode=755".as_ptr() as *const libc::c_void,
        )
    } < 0
    {
        // /run absent or unmountable — the workload just sees whatever
        // the host fs has; the channel risk is report-documented, and
        // IP egress is still TUN-only. Warn rather than fail.
        tracing::warn!(
            "namespaced-init: /run tmpfs failed ({})",
            std::io::Error::last_os_error()
        );
    }
}

fn scrub_env_and_fds() {
    for var in super::init_env::ALL {
        unsafe { std::env::remove_var(var) };
    }
    // Close everything above stderr — the workload inherits only
    // stdio (the handshake socket, policy memfd, and tun fd never
    // reach it). Collect the fd list first: closing the ReadDir's own
    // dirfd mid-iteration makes its drop panic on EBADF.
    let fds: Vec<i32> = std::fs::read_dir("/proc/self/fd")
        .map(|dir| {
            dir.flatten()
                .filter_map(|entry| entry.file_name().to_string_lossy().parse::<i32>().ok())
                .filter(|fd| *fd > 2)
                .collect()
        })
        .unwrap_or_default();
    for fd in fds {
        unsafe { libc::close(fd) };
    }
}

/// Apply the serialized policy's Linux sandbox, scrub init's env/fds,
/// and exec the workload. Never returns on success.
fn finish_with_sandbox(sock: RawFd, exe: &CString, argv: &[CString]) -> ! {
    // Only the exact `=1` spelling is the hatch — and it can only be
    // here because the parent forwarded it deliberately (the spawn
    // path strips `MCP_WRIT_NS_*` from ambient/policy-filtered env).
    let skip = std::env::var(super::init_env::SKIP_SANDBOX).as_deref() == Ok("1");
    if !skip {
        let path = std::env::var(super::init_env::POLICY).unwrap_or_default();
        // `load_policy` canonicalizes its path — and `realpath` on
        // `/proc/self/fd/N` pointing at a deleted memfd fails ENOENT.
        // Read the bytes ourselves and use the string entry point: the
        // memfd already carries the bound effective policy, so the
        // extends/include machinery the path loader performs has no
        // directives left to resolve anyway. Target validation is
        // re-run explicitly to keep the check identical.
        let policy: Result<crate::policy::Policy, crate::error::PolicyError> =
            std::fs::read_to_string(&path)
                .map_err(crate::error::PolicyError::FileRead)
                .and_then(|content| {
                    let p = crate::policy::kdl_parse::parse_kdl_policy(&content)?;
                    crate::policy::validator::validate_policy_for_target(
                        &p,
                        &crate::execution::ExecutionTarget::native(),
                    )?;
                    Ok(p)
                });
        let policy = match policy {
            Ok(p) => p,
            Err(e) => {
                send(
                    sock,
                    format!("ERR {STAGE_SANDBOX} policy-load {e}").as_bytes(),
                );
                std::process::exit(97);
            }
        };
        match super::super::linux_spawn::prepare_linux_child_sandbox_namespaced(&policy) {
            Ok(mut bits) => {
                if let Err(e) = bits.apply_in_child() {
                    send_err(sock, STAGE_SANDBOX, e.raw_os_error().unwrap_or(-1));
                    std::process::exit(97);
                }
            }
            Err(e) => {
                send(sock, format!("ERR {STAGE_SANDBOX} prepare {e}").as_bytes());
                std::process::exit(97);
            }
        }
    }
    send(
        sock,
        // A skipped sandbox must not read as applied — `go()` only
        // counts the exact `SANDBOXED` token.
        if skip {
            &b"SANDBOX-SKIPPED"[..]
        } else {
            b"SANDBOXED"
        },
    );
    // Policy consumed, sandbox on, socket reported — the workload
    // gets nothing but stdio.
    scrub_env_and_fds();
    let c_argv: Vec<*const libc::c_char> = argv
        .iter()
        .map(|a| a.as_ptr())
        .chain(std::iter::once(std::ptr::null()))
        .collect();
    unsafe {
        libc::execvp(exe.as_ptr(), c_argv.as_ptr());
    }
    send_err(sock, STAGE_EXEC, errno());
    std::process::exit(98);
}

pub(crate) fn init_main() -> i32 {
    let args: Vec<String> = std::env::args().collect();
    // argv: namespaced-init -- <argv0-spelling> <args...>
    let sep = args.iter().position(|a| a == "--");
    let workload: Vec<String> = match sep {
        Some(i) => args[i + 1..].to_vec(),
        None => Vec::new(),
    };
    let sock: RawFd = std::env::var(super::init_env::SOCK_FD)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(-1);
    if sock < 0 || workload.is_empty() {
        if sock >= 0 {
            send(sock, b"ERR argv missing-sockfd-or-workload");
        }
        return 96;
    }
    let exe_spelling = CString::new(workload[0].as_str()).unwrap();
    let resolved = std::env::var(super::init_env::EXE).unwrap_or_else(|_| workload[0].clone());
    let resolved = CString::new(resolved).unwrap_or_else(|_| exe_spelling.clone());
    let mut c_argv: Vec<CString> = workload
        .iter()
        .map(|a| CString::new(a.as_str()).unwrap())
        .collect();
    // The exec'd image is `resolved`; argv[0] keeps the caller's
    // spelling (same contract as `run`).
    let euid = unsafe { libc::geteuid() };
    let egid = unsafe { libc::getegid() };

    // Teardown cascade, link 1: this process is the forked
    // supervisor-side init; when the launching `mcp-writ` dies the
    // kernel SIGKILLs us, our death fires the grandchild's own
    // pdeathsig, and so on down to the pidns init — the whole
    // namespaced subtree disappears instead of leaking an
    // unsupervised workload. `PR_SET_PDEATHSIG` survives `execve`.
    unsafe {
        libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL);
    }
    if unsafe { libc::getppid() } == 1 {
        // Supervisor already gone (race between spawn and prctl).
        send_err(sock, STAGE_UNSHARE, libc::ESRCH);
        return 97;
    }

    macro_rules! bail {
        ($stage:expr, $e:expr) => {{
            send_err(sock, $stage, $e);
            return 97;
        }};
    }

    // Map-sync pipes: the grandchild unshares, the init parent writes
    // its uid/gid maps from the original user namespace (the only
    // mapping path an unprivileged launcher has on this kernel —
    // self-map after `unshare(CLONE_NEWUSER)` is EPERM on WSL2), then
    // releases the grandchild.
    let (c2p_r, c2p_w) = match pipe_pair() {
        Ok(p) => p,
        Err(e) => bail!("fork-pipe", e.raw_os_error().unwrap_or(-1)),
    };
    let (p2c_r, p2c_w) = match pipe_pair() {
        Ok(p) => p,
        Err(e) => bail!("fork-pipe", e.raw_os_error().unwrap_or(-1)),
    };
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        bail!("fork", errno());
    }
    if pid > 0 {
        // ---- init parent: map writer + exit-status forwarder ------
        unsafe {
            libc::close(c2p_w);
            libc::close(p2c_r);
        }
        let mut mapped = false;
        if pipe_read(c2p_r).is_ok() {
            if let Err(e) = write_id_maps_for(pid, euid, egid) {
                send_err(sock, STAGE_IDMAP, e.raw_os_error().unwrap_or(-1));
            } else {
                mapped = true;
            }
        } else {
            // Grandchild died on unshare — it already sent ERR.
            send_err(sock, STAGE_UNSHARE, 0);
        }
        // Release the grandchild either way: on a map failure it must
        // wake up to die rather than hang on the pipe.
        let _ = pipe_write(p2c_w);
        unsafe {
            libc::close(c2p_r);
            libc::close(p2c_w);
            libc::close(sock);
        }
        if !mapped {
            unsafe { libc::kill(pid, libc::SIGKILL) };
        }
        // Reap + forward the grandchild's exit status. Signal death is
        // re-raised so the supervisor sees signal semantics, not a
        // plain exit code.
        let mut status = 0i32;
        loop {
            let r = unsafe { libc::waitpid(pid, &mut status, 0) };
            if r == pid {
                break;
            }
            if r < 0 && errno() != libc::EINTR {
                break;
            }
        }
        if libc::WIFSIGNALED(status) {
            let sig = libc::WTERMSIG(status);
            unsafe {
                libc::signal(sig, libc::SIG_DFL);
                libc::raise(sig);
            }
            return 128 + sig;
        }
        let code = libc::WEXITSTATUS(status);
        return if mapped { code } else { 97 };
    }

    // ---- grandchild: the namespaced workload ----------------------
    // Teardown cascade, link 2: die with the init parent. Set before
    // unshare — the value is preserved across execve, so even the
    // final workload image keeps it pointed at its supervisor chain.
    unsafe {
        libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL);
    }
    unsafe {
        libc::close(c2p_r);
        libc::close(p2c_w);
    }
    // CLONE_NEWPID joins the same unshare: the *next* child enters the
    // new pid namespace, hiding the supervisor from the workload —
    // without it a workload could `kill` the parent (same mapped uid)
    // and silence the audit path while still holding its stdio.
    if unsafe {
        libc::unshare(
            libc::CLONE_NEWUSER | libc::CLONE_NEWNET | libc::CLONE_NEWNS | libc::CLONE_NEWPID,
        )
    } < 0
    {
        send_err(sock, STAGE_UNSHARE, errno());
        return 97;
    }
    if pipe_write(c2p_w).is_err() || pipe_read(p2c_r).is_err() {
        // Init parent gone — no map writer means no launch.
        return 97;
    }
    unsafe {
        libc::close(c2p_w);
        libc::close(p2c_r);
    }
    let tun = match create_tun() {
        Ok(fd) => fd,
        Err(e) => bail!(STAGE_TUN, e.raw_os_error().unwrap_or(-1)),
    };
    let net = (|| -> std::io::Result<()> {
        super::netlink::bring_loopback_up()?;
        let ifname = std::str::from_utf8(IFNAME).unwrap();
        super::netlink::addr_add(ifname, super::WORKLOAD_V4, 24)?;
        super::netlink::default_route_dev(ifname)?;
        Ok(())
    })();
    if let Err(e) = net {
        bail!(STAGE_NET, e.raw_os_error().unwrap_or(-1));
    }
    if let Err(e) = disable_ipv6() {
        tracing::warn!("namespaced-init: disable_ipv6 failed ({e}); proxy drops v6 anyway");
    }
    // The inherited mount table keeps its propagation flags — WSL
    // marks mounts shared, so a bind mount here would try to propagate
    // back into the host's peer group and fail EPERM (or worse,
    // succeed and leak). Detach first: the mountns contract is a
    // private view.
    if unsafe {
        libc::mount(
            std::ptr::null(),
            c"/".as_ptr(),
            std::ptr::null(),
            libc::MS_PRIVATE | libc::MS_REC,
            std::ptr::null(),
        )
    } < 0
    {
        send_err(sock, STAGE_NET, errno());
        return 97;
    }
    // Resolve the resolv.conf link target BEFORE covering `/run` —
    // whether the file install can go through a fresh tmpfs path or
    // needs the bind-mount depends on where the link points.
    let resolv = resolv_conf_target(&super::GATEWAY_V4);
    hide_host_ipc_sockets();
    if let Err(e) = resolv.and_then(|(target, contents)| redirect_resolv_conf(&target, &contents)) {
        tracing::warn!("namespaced-init: resolv.conf redirect failed: {e}");
    }

    if let Err(e) = send_ready_with_fd(sock, tun) {
        send_err(sock, STAGE_TUN, e.raw_os_error().unwrap_or(-1));
        return 97;
    }
    unsafe { libc::close(tun) };

    // Wait for GO — the parent only sends it once the proxy task is
    // running, so a dead parent means no egress anyway (fail-closed).
    let mut go = [0u8; 1];
    let n = unsafe { libc::recv(sock, go.as_mut_ptr() as *mut _, 1, 0) };
    if n != 1 || go[0] != b'G' {
        return 97;
    }

    c_argv.shrink_to_fit();

    // Fork once more: the child lands in the new pid namespace as its
    // init (pid 1) — every descendant stays inside the isolation and
    // dies with it — while this process stays in the ancestor pidns to
    // forward the exit status exactly like the init parent does for it.
    let wpid = unsafe { libc::fork() };
    if wpid < 0 {
        send_err(sock, "pidns-fork", errno());
        return 97;
    }
    if wpid == 0 {
        // Teardown cascade, link 3: the pidns init dies with the
        // grandchild, taking the whole inner namespace with it.
        unsafe {
            libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL);
        }
        // Remount proc in the new pid namespace — the mount records
        // *this* pidns, so the workload sees only its own tree. Left
        // on the host's /proc it could enumerate the supervisor by
        // number and signal it (same mapped uid). Failure is fatal:
        // the monitor-isolation contract would be silently broken.
        if unsafe {
            libc::mount(
                c"proc".as_ptr(),
                c"/proc".as_ptr(),
                c"proc".as_ptr(),
                0,
                std::ptr::null(),
            )
        } < 0
        {
            send_err(sock, "proc-mount", errno());
            return 97;
        }
        finish_with_sandbox(sock, &resolved, &c_argv);
    }
    unsafe {
        libc::close(sock);
    }
    let mut status = 0i32;
    loop {
        let r = unsafe { libc::waitpid(wpid, &mut status, 0) };
        if r == wpid || (r < 0 && errno() != libc::EINTR) {
            break;
        }
    }
    if libc::WIFSIGNALED(status) {
        let sig = libc::WTERMSIG(status);
        unsafe {
            libc::signal(sig, libc::SIG_DFL);
            libc::raise(sig);
        }
        return 128 + sig;
    }
    libc::WEXITSTATUS(status)
}
