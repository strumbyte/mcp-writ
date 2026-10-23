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
//! 4. rtnetlink: `lo` up, `egress0` up with `10.250.0.2/24` and
//!    `fd00:250::2/64`, `default dev egress0` in both families. No
//!    gateway: a point-to-point TUN routes every packet straight to
//!    our fd.
//! 5. IPv6 enabled (`net.ipv6.conf.all.disable_ipv6` = 0, consolidated
//!    in `enable_ipv6` so restoring the old disable call rolls the
//!    whole route back to v4-only) — the proxy is dual-stack since
//!    PR-26a; v6 frames it cannot inspect (extension chains,
//!    fragments, ICMPv6) are still dropped at the classifier. A kernel
//!    with no v6 stack at all (`ipv6_stack_present()` — an `AF_INET6`
//!    socket fails `EAFNOSUPPORT`) skips this leg: the route runs
//!    v4-only by environment rather than failing net setup.
//! 6. `resolv.conf` — a private tmpfs over `/run` hides host daemon
//!    sockets, then a generated `nameserver 10.250.0.1` file replaces
//!    resolution: written at the resolved target when it lives under
//!    the new `/run`, otherwise bind-mounted over `/etc/resolv.conf`
//!    from a private `/tmp` tmpfs (a memfd path is EINVAL to mount).
//!    The host file is never touched; if `/etc/resolv.conf` does not
//!    exist we leave resolution broken (fail-closed — a workload that
//!    cannot resolve cannot turn name rules into flows). A pinned
//!    entrypoint script then has its verified content staged and
//!    mounted over its payload path (`MCP_WRIT_NS_ENTRYPIN_*`): the
//!    real-path spelling stays while the bytes behind it are anchored
//!    to the pinned object for the session — the verify→exec window a
//!    pathname launch can only narrow elsewhere closes here.
//! 7. Handshake: `READY` + the TUN fd via `SCM_RIGHTS`; wait for `GO`.
//! 8. Linux sandbox: the effective policy is re-loaded from the
//!    serialized KDL the parent passed (`MCP_WRIT_NS_POLICY`) and the
//!    standard `no_new_privs → Landlock → seccomp` bits are applied
//!    with `socket()` pinned to an AF_INET/AF_INET6 allowlist — every
//!    other family either escapes the TUN boundary entirely (AF_VSOCK,
//!    AF_PACKET, AF_NETLINK are not namespaced by netns) or reaches
//!    host IPC through the shared mountns (AF_UNIX). Landlock's
//!    TCP-connect port rules stay on: they express the same policy.
//! 9. Report `SANDBOXED`/`SANDBOX-SKIPPED`, scrub `MCP_WRIT_NS_*` env
//!    vars, close every fd > 2, `execvp`. The handshake socket is kept
//!    through the scrub and marked CLOEXEC — `execve` success closes
//!    it (the parent's post-verdict read sees EOF = "execed"), while
//!    an `execvp` failure still has the fd to send `ERR exec`.

use std::ffi::CString;
use std::os::unix::io::{FromRawFd, RawFd};

const STAGE_UNSHARE: &str = "unshare";
const STAGE_IDMAP: &str = "idmap";
const STAGE_TUN: &str = "tun";
const STAGE_NET: &str = "net";
const STAGE_MOUNT: &str = "mount";
const STAGE_SANDBOX: &str = "sandbox";
const STAGE_EXEC: &str = "exec";

const IFNAME: &[u8] = b"egress0";

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(-1)
}

/// Best-effort line to the parent; the socket may already be gone.
/// `write`, not `send`: the `SANDBOXED` verdict is sent *after* the
/// workload's seccomp filter installs, and `write` is in every runtime
/// allowlist while `send`/`sendto` need not be — a runtime policy must
/// never have to admit a socket syscall just to carry init's own
/// handshake. The socket is a connected SOCK_SEQPACKET pair, so the
/// two calls are byte-for-byte equivalent here.
fn send(sock: RawFd, msg: &[u8]) {
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    unsafe {
        libc::write(sock, msg.as_ptr() as *const libc::c_void, msg.len());
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
    // The control buffer must be aligned for `cmsghdr` — a `[u8; N]`
    // has alignment 1 while `CMSG_FIRSTHDR`/`CMSG_DATA` treat the
    // storage as a `cmsghdr` (which embeds a `size_t`), so the header
    // writes below would be a misaligned reference. An array of
    // `cmsghdr` carries the required alignment in its element type;
    // two headers always cover `CMSG_SPACE(sizeof(RawFd))` on both
    // 32- and 64-bit.
    let mut cmsg_buf = [libc::cmsghdr {
        cmsg_len: 0,
        cmsg_level: 0,
        cmsg_type: 0,
    }; 2];
    let mut msg = libc::msghdr {
        msg_name: std::ptr::null_mut(),
        msg_namelen: 0,
        msg_iov: &mut iov,
        msg_iovlen: 1,
        msg_control: cmsg_buf.as_mut_ptr() as *mut _,
        msg_controllen: std::mem::size_of_val(&cmsg_buf),
        msg_flags: 0,
    };
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    let cmsg = unsafe { libc::CMSG_FIRSTHDR(&msg) };
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
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
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    msg.msg_controllen = unsafe { (*cmsg).cmsg_len };
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
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
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    if unsafe { libc::pipe(p.as_mut_ptr()) } < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok((p[0], p[1]))
    }
}

fn pipe_write(fd: RawFd) -> std::io::Result<()> {
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
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
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
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
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    let fd = unsafe { libc::open(c"/dev/net/tun".as_ptr(), libc::O_RDWR) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };
    ifr.ifr_ifru.ifru_flags = (libc::IFF_TUN | libc::IFF_NO_PI) as i16;
    for (slot, &b) in ifr.ifr_name.iter_mut().zip(IFNAME.iter()) {
        *slot = b as libc::c_char;
    }
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    if unsafe { libc::ioctl(fd, libc::TUNSETIFF, &ifr) } < 0 {
        let e = std::io::Error::last_os_error();
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
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
fn resolv_conf_target(
    dns4: &std::net::Ipv4Addr,
    dns6: Option<&std::net::Ipv6Addr>,
) -> std::io::Result<(std::path::PathBuf, String)> {
    if !std::path::Path::new("/etc/resolv.conf").exists() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "/etc/resolv.conf absent — name resolution stays broken (fail-closed)",
        ));
    }
    let target = std::fs::canonicalize("/etc/resolv.conf")?;
    // Both spellings point at the same gate — the intercept binds the
    // port, not the address, so either family reaches it. On a kernel
    // with no v6 stack the v6 line is omitted entirely rather than
    // pointing at an address the namespace could never reach.
    let contents = match dns6 {
        Some(dns6) => format!("nameserver {dns4}\nnameserver {dns6}\noptions ndots:0\n"),
        None => format!("nameserver {dns4}\noptions ndots:0\n"),
    };
    Ok((target, contents))
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
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
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
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
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

/// The single place IPv6 is enabled inside the child netns (PR-26a).
/// A fresh netns defaults `disable_ipv6` to 0, but writing the value
/// explicitly keeps the enablement honest if a kernel ever inherits a
/// disabled default — and restoring `disable_ipv6` here rolls the
/// whole route back to v4-only. `pub(crate)`: the capability probe
/// mirrors the same sequence when it measures the v6 stage.
pub(crate) fn enable_ipv6() -> std::io::Result<()> {
    write_file("/proc/sys/net/ipv6/conf/all/disable_ipv6", "0")
}

/// Whether the kernel exposes an IPv6 stack at all, probed by
/// creating an `AF_INET6` socket — the authoritative test, asked of
/// the kernel itself rather than of a sysctl path that may not be
/// mounted in this netns. A kernel booted `ipv6.disable=1` or built
/// without `CONFIG_IPV6` fails with `EAFNOSUPPORT`; there the route
/// is v4-only *by environment*, not by a setup failure — a
/// v6-needing policy is still refused at selection via the host-side
/// reachability check, while a v4-only policy must keep launching.
/// Only `EAFNOSUPPORT` proves the family unregistered — every other
/// socket error (`EMFILE`/`ENFILE` fd exhaustion, a seccomp `EPERM`,
/// …) means the stack is present and this probe fd merely failed, so
/// the v6 setup stage reports its own failure instead of the launch
/// misreading it as an absent stack. `pub(crate)`: the capability
/// probe gates its v6 stage on the same predicate.
pub(crate) fn ipv6_stack_present() -> bool {
    // No std API probes an address family without side effects —
    // `UdpSocket::bind` would fold a bind failure into the verdict —
    // so the raw `socket()` stays. `SOCK_DGRAM` protocol 0 exercises
    // family registration alone (no transport module needed) and
    // `SOCK_CLOEXEC` keeps the probe fd out of any exec'd image for
    // its brief lifetime.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    let fd = unsafe { libc::socket(libc::AF_INET6, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return errno() != libc::EAFNOSUPPORT;
    }
    // Ownership passes to File the moment the descriptor exists —
    // drop runs close(2) on every exit path, so no success path can
    // leak it.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    let _probe = unsafe { std::fs::File::from_raw_fd(fd) };
    true
}

/// Hide host daemon IPC. The mountns shares the host filesystem, and
/// Landlock does not mediate `connect(2)` on `AF_UNIX` — a workload
/// that can resolve `/run/dbus/system_bus_socket` or
/// `/run/docker.sock` has a live channel to a host daemon that holds
/// *unsandboxed* authority (an egress/escape proxy). Cover `/run`
/// with a private tmpfs: those pathnames stop resolving here.
/// `/var/run` is a `/run` symlink on every modern distro, so it is
/// covered too. Socket paths outside `/run` are unreachable for a
/// different reason — the seccomp filter denies `socket(AF_UNIX)`
/// outright, so no unix-domain endpoint can be opened at all.
///
/// Fail-closed: a mount failure must not launch the workload with
/// host IPC sockets still reachable — that is the channel this mount
/// exists to sever.
fn hide_host_ipc_sockets() -> std::io::Result<()> {
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
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
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// The fd numbers `MCP_WRIT_NS_KEEPFDS` names — the fd-exec pin
/// descriptors init must hold open through the workload exec. Read
/// before the env scrub removes the variable.
fn keep_fds_from_env() -> Vec<i32> {
    parse_keep_fds(&std::env::var(super::init_env::KEEPFDS).unwrap_or_default())
}

/// Comma-separated fd numbers in `raw`; non-numeric entries and the
/// stdio descriptors (`<=2`) never qualify as pins.
fn parse_keep_fds(raw: &str) -> Vec<i32> {
    raw.split(',')
        .filter_map(|s| s.parse::<i32>().ok())
        .filter(|fd| *fd > 2)
        .collect()
}

/// `(pin fd, payload path, sha256)` named by the
/// `MCP_WRIT_NS_ENTRYPIN_*` envs; `None` when the launch pins no
/// payload-bound entrypoint. Read before the env scrub removes the
/// variables. Stdio descriptors never qualify — a forged entry must
/// not alias a real fd.
fn entry_pin_from_env() -> Option<(RawFd, std::path::PathBuf, String)> {
    let fd: RawFd = std::env::var(super::init_env::ENTRYPIN_FD)
        .ok()?
        .parse()
        .ok()?;
    if fd <= 2 {
        return None;
    }
    let target = std::env::var_os(super::init_env::ENTRYPIN_TARGET)?;
    let sha = std::env::var(super::init_env::ENTRYPIN_SHA).ok()?;
    Some((fd, std::path::PathBuf::from(target), sha))
}

/// Anchor the pinned entrypoint's content at its payload path. The
/// interpreter opens the script by name — the path spelling must
/// stay — so init reads the pinned object through the inherited fd
/// (never the path: a host-side swap after the parent's last check
/// would re-resolve there), re-hashes the bytes against the
/// manifest's digest, writes the verified copy under this
/// namespace's private `/run` tmpfs, and bind-mounts it over the
/// path. A plain `mount(MS_BIND)` of `/proc/self/fd/<n>` cannot do
/// this — the fd's `vfsmount` belongs to the parent's mount table,
/// and `do_loopback` rejects a source foreign to this namespace
/// with EINVAL — while a file on the in-namespace tmpfs binds
/// cleanly. From the mount on, the interpreter's `open(2)` and every
/// later resolution land on the pinned content even if the host
/// pathname — or the object's own bytes — changed after the parent's
/// check: the verify→exec window other routes can only narrow closes
/// here. Runs at the mount stage (after `/run`/`/tmp` are covered,
/// so a payload under a masked tree fails the attach cleanly); a
/// no-op when the launch pins no payload-bound entrypoint.
fn pin_entrypoint_mount() -> std::io::Result<()> {
    let Some((fd, target, want_sha)) = entry_pin_from_env() else {
        return Ok(());
    };
    use std::io::Read;
    let mut bytes = Vec::new();
    std::fs::File::open(format!("/proc/self/fd/{fd}"))?.read_to_end(&mut bytes)?;
    if crate::verifier::hash::hash_bytes(&bytes) != want_sha {
        // An in-place rewrite after the parent's last check — the
        // digest gate refuses what a byte copy would have carried.
        return Err(std::io::Error::from_raw_os_error(libc::EPERM));
    }
    let stage = "/run/.mcp-writ-entrypoint";
    std::fs::create_dir_all(stage)?;
    let staged = format!("{stage}/payload");
    std::fs::write(&staged, &bytes)?;
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&staged, std::fs::Permissions::from_mode(0o400))?;
    let src = CString::new(staged).map_err(std::io::Error::other)?;
    let dst = CString::new(target.as_os_str().as_encoded_bytes()).map_err(std::io::Error::other)?;
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    if unsafe {
        libc::mount(
            src.as_ptr(),
            dst.as_ptr(),
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

fn scrub_env_and_fds(extra_keep: &[i32]) {
    // Read the keep list before the env scrub removes it — the fd-exec
    // pin descriptors init must hold open through the workload exec.
    let mut keep = keep_fds_from_env();
    keep.extend_from_slice(extra_keep);
    for var in super::init_env::ALL {
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe { std::env::remove_var(var) };
    }
    // Close everything above stderr — the workload inherits only
    // stdio plus the keep-listed pin fds (the handshake socket, policy
    // memfd, and tun fd never reach it). Collect the fd list first:
    // closing the ReadDir's own dirfd mid-iteration makes its drop
    // panic on EBADF.
    let fds: Vec<i32> = std::fs::read_dir("/proc/self/fd")
        .map(|dir| {
            dir.flatten()
                .filter_map(|entry| entry.file_name().to_string_lossy().parse::<i32>().ok())
                .filter(|fd| *fd > 2 && !keep.contains(fd))
                .collect()
        })
        .unwrap_or_default();
    for fd in fds {
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe { libc::close(fd) };
    }
}

/// Apply the serialized policy's Linux sandbox, scrub init's env/fds,
/// and exec the workload. Never returns on success.
///
/// The handshake socket stays open through the scrub and is marked
/// CLOEXEC just before `execvp`: a successful exec closes it (the
/// parent's second handshake read then sees EOF — the exec epoch),
/// while an `execvp` failure keeps the fd live long enough to report
/// `ERR exec` — a workload that never execed must not read as a
/// launched one.
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
                // The pin fds KEEPFDS names were uncloaked across
                // init's own re-exec, and the workload's exe spelling
                // names them as `/proc/self/fd/N` — they must survive
                // *its* exec too. `seal_ambient_fds` CLOEXECs every
                // ambient descriptor but its keep list, so the list
                // has to be handed over before the bits apply.
                bits.exec_uncloak_fds = keep_fds_from_env();
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
    // Policy consumed, sandbox on, verdict reported — the workload
    // gets nothing but stdio. The handshake socket survives the scrub
    // under `extra_keep`, then CLOEXEC makes `execve` itself the "exec
    // reached" signal: the parent's post-status read sees EOF. A failed
    // F_SETFD would leave the workload holding the socket open — the
    // parent would never see EOF and would misread the launch — so a
    // failure here is reported like any other exec-stage failure.
    scrub_env_and_fds(&[sock]);
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    if unsafe { libc::fcntl(sock, libc::F_SETFD, libc::FD_CLOEXEC) } < 0 {
        send_err(sock, STAGE_EXEC, errno());
        std::process::exit(98);
    }
    let c_argv: Vec<*const libc::c_char> = argv
        .iter()
        .map(|a| a.as_ptr())
        .chain(std::iter::once(std::ptr::null()))
        .collect();
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    unsafe {
        libc::execvp(exe.as_ptr(), c_argv.as_ptr());
    }
    // Only an `execvp` failure reaches this: the fd is still open
    // (CLOEXEC fires on success only), so the parent reads the report
    // instead of an EOF that would look like a successful exec.
    send_err(sock, STAGE_EXEC, errno());
    std::process::exit(98);
}

pub(crate) fn init_main() -> i32 {
    let args: Vec<String> = std::env::args().collect(); // nosemgrep: rust.lang.security.args.args
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
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    let euid = unsafe { libc::geteuid() };
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    let egid = unsafe { libc::getegid() };

    // Teardown cascade, link 1: this process is the forked
    // supervisor-side init; when the launching `mcp-writ` dies the
    // kernel SIGKILLs us, our death fires the grandchild's own
    // pdeathsig, and so on down to the pidns init — the whole
    // namespaced subtree disappears instead of leaking an
    // unsupervised workload. `PR_SET_PDEATHSIG` survives `execve`.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    unsafe {
        libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL);
    }
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
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
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        bail!("fork", errno());
    }
    if pid > 0 {
        // ---- init parent: map writer + exit-status forwarder ------
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
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
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe {
            libc::close(c2p_r);
            libc::close(p2c_w);
            libc::close(sock);
        }
        if !mapped {
            // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
            unsafe { libc::kill(pid, libc::SIGKILL) };
        }
        // Reap + forward the grandchild's exit status. Signal death is
        // re-raised so the supervisor sees signal semantics, not a
        // plain exit code.
        let mut status = 0i32;
        loop {
            // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
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
            // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
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
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    unsafe {
        libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL);
    }
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    unsafe {
        libc::close(c2p_r);
        libc::close(p2c_w);
    }
    // CLONE_NEWPID joins the same unshare: the *next* child enters the
    // new pid namespace, hiding the supervisor from the workload —
    // without it a workload could `kill` the parent (same mapped uid)
    // and silence the audit path while still holding its stdio.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
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
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
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
        if ipv6_stack_present() {
            if let Err(e) = enable_ipv6() {
                // Not fatal here: the v6 addr/route below decides — if the
                // stack is truly absent that step errors into the net stage.
                tracing::warn!("namespaced-init: enable_ipv6 write failed ({e})");
            }
            super::netlink::addr_add_v6(ifname, super::WORKLOAD_V6, 64)?;
            super::netlink::default_route_dev_v6(ifname)?;
        }
        // No IPv6 stack on this kernel — the namespace stays v4-only by
        // environment; the launch proceeds (selection refuses only
        // policies that actually name v6 destinations).
        Ok(())
    })();
    if let Err(e) = net {
        bail!(STAGE_NET, e.raw_os_error().unwrap_or(-1));
    }
    // The inherited mount table keeps its propagation flags — WSL
    // marks mounts shared, so a bind mount here would try to propagate
    // back into the host's peer group and fail EPERM (or worse,
    // succeed and leak). Detach first: the mountns contract is a
    // private view.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
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
    let resolv = resolv_conf_target(
        &super::GATEWAY_V4,
        ipv6_stack_present().then_some(&super::GATEWAY_V6),
    );
    if let Err(e) = hide_host_ipc_sockets() {
        bail!(STAGE_MOUNT, e.raw_os_error().unwrap_or(-1));
    }
    if let Err(e) = resolv.and_then(|(target, contents)| redirect_resolv_conf(&target, &contents)) {
        tracing::warn!("namespaced-init: resolv.conf redirect failed: {e}");
    }
    // The pinned entrypoint's exec-time binding: init re-hashes the
    // object the inherited fd names, stages the verified bytes on this
    // namespace's private `/run`, and mounts the copy over the payload
    // path — the ordinary spelling keeps resolving to the pinned
    // content inside this mountns, so a host-side swap or rewrite
    // after the parent's last check can no longer reach the
    // interpreter's open. After the tmpfs masks: a payload rooted
    // under `/run` or a masked `/tmp` fails the mount cleanly (the
    // parent's `masked_namespace_root` screen refuses it earlier).
    if let Err(e) = pin_entrypoint_mount() {
        bail!(STAGE_MOUNT, e.raw_os_error().unwrap_or(-1));
    }

    if let Err(e) = send_ready_with_fd(sock, tun) {
        send_err(sock, STAGE_TUN, e.raw_os_error().unwrap_or(-1));
        return 97;
    }
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    unsafe { libc::close(tun) };

    // Wait for GO — the parent only sends it once the proxy task is
    // running, so a dead parent means no egress anyway (fail-closed).
    let mut go = [0u8; 1];
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    let n = unsafe { libc::recv(sock, go.as_mut_ptr() as *mut _, 1, 0) };
    if n != 1 || go[0] != b'G' {
        return 97;
    }

    c_argv.shrink_to_fit();

    // Fork once more: the child lands in the new pid namespace as its
    // init (pid 1) — every descendant stays inside the isolation and
    // dies with it — while this process stays in the ancestor pidns to
    // forward the exit status exactly like the init parent does for it.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    let wpid = unsafe { libc::fork() };
    if wpid < 0 {
        send_err(sock, "pidns-fork", errno());
        return 97;
    }
    if wpid == 0 {
        // Teardown cascade, link 3: the pidns init dies with the
        // grandchild, taking the whole inner namespace with it.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe {
            libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL);
        }
        // Remount proc in the new pid namespace — the mount records
        // *this* pidns, so the workload sees only its own tree. Left
        // on the host's /proc it could enumerate the supervisor by
        // number and signal it (same mapped uid). Failure is fatal:
        // the monitor-isolation contract would be silently broken.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
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
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    unsafe {
        libc::close(sock);
    }
    let mut status = 0i32;
    loop {
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        let r = unsafe { libc::waitpid(wpid, &mut status, 0) };
        if r == wpid || (r < 0 && errno() != libc::EINTR) {
            break;
        }
    }
    if libc::WIFSIGNALED(status) {
        let sig = libc::WTERMSIG(status);
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe {
            libc::signal(sig, libc::SIG_DFL);
            libc::raise(sig);
        }
        return 128 + sig;
    }
    libc::WEXITSTATUS(status)
}

#[cfg(test)]
mod tests {
    use super::parse_keep_fds;

    #[test]
    fn keep_fds_parses_only_inheritable_pins() {
        assert_eq!(parse_keep_fds("3,4,10"), vec![3, 4, 10]);
        // Stdio descriptors are never pins — a forged entry must not
        // rescue fd 0-2 from the scrub's expectations.
        assert_eq!(parse_keep_fds("0,1,2,5"), vec![5]);
        // Malformed entries drop instead of failing the whole list.
        assert_eq!(parse_keep_fds("7,junk,,8x,9"), vec![7, 9]);
        assert!(parse_keep_fds("").is_empty());
    }
}
