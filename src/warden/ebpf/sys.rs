//! Raw `bpf(2)` syscall wrappers and the UAPI constants this module
//! needs. The PR-10 route deliberately avoids an external eBPF crate:
//! the programs are generated directly (see `prog.rs`), so the only
//! kernel surface required is `bpf()` itself plus the cgroup v2 mount.

use std::io;

/// bpf() command numbers (`enum bpf_cmd`).
pub const BPF_MAP_CREATE: i32 = 0;
pub const BPF_MAP_LOOKUP_ELEM: i32 = 1;
pub const BPF_MAP_UPDATE_ELEM: i32 = 2;
pub const BPF_MAP_DELETE_ELEM: i32 = 3;
pub const BPF_PROG_LOAD: i32 = 5;
pub const BPF_PROG_ATTACH: i32 = 8;
pub const BPF_PROG_DETACH: i32 = 9;
pub const BPF_PROG_QUERY: i32 = 11;

/// `enum bpf_map_type`.
pub const BPF_MAP_TYPE_ARRAY: u32 = 2;
pub const BPF_MAP_TYPE_RINGBUF: u32 = 27;

/// `enum bpf_prog_type` — the connect/sendmsg hooks' program type.
pub const BPF_PROG_TYPE_CGROUP_SOCK_ADDR: u32 = 18;

/// `enum bpf_attach_type` — the PR-10 hooks.
pub const BPF_CGROUP_INET4_CONNECT: u32 = 10;
pub const BPF_CGROUP_INET6_CONNECT: u32 = 11;

/// Helper ids.
pub const BPF_FUNC_MAP_LOOKUP_ELEM: i32 = 1;
pub const BPF_FUNC_GET_CURRENT_PID_TGID: i32 = 14;
pub const BPF_FUNC_KTIME_GET_BOOT_NS: i32 = 125;
pub const BPF_FUNC_RINGBUF_RESERVE: i32 = 131;
pub const BPF_FUNC_RINGBUF_SUBMIT: i32 = 132;

/// `struct bpf_sock_addr` field offsets (uapi `bpf/bpf_helpers.h`).
pub mod ctx {
    /// `user_family` — `AF_INET`/`AF_INET6` the userspace called with.
    pub const USER_FAMILY: i16 = 0;
    /// `user_ip4` — IPv4 destination, network byte order in a u32.
    pub const USER_IP4: i16 = 4;
    /// `user_ip6[4]` — IPv6 destination words, network byte order.
    pub const USER_IP6: i16 = 8;
    /// `user_port` — `__be16` destination port zero-extended into a u32
    /// (port 443 reads as `0xBB01`).
    pub const USER_PORT: i16 = 24;
    /// `family` — the kernel socket family.
    pub const FAMILY: i16 = 28;
    /// `type` — `SOCK_STREAM`/`SOCK_DGRAM`/...
    pub const TYPE: i16 = 32;
    /// `protocol` — `IPPROTO_TCP`/`IPPROTO_UDP`/...
    pub const PROTOCOL: i16 = 36;
}

/// Byte order: `ctx->user_port` reads as `htons(port)` zero-extended —
/// the raw field value a rule entry compares against (`port.to_be()`
/// on a little-endian host already produces that bit pattern).
pub fn raw_port(port: u16) -> u32 {
    port.to_be() as u32
}

/// One `bpf()` syscall. `attr` is the full `union bpf_attr` — always
/// passed with its real size so forward-compatible kernels accept it.
/// 160 bytes covers `prog_load.log_true_size` (offset 140); bytes past
/// the fields a command uses must stay zeroed.
pub fn bpf(cmd: i32, attr: &mut [u8; 160]) -> i64 {
    // Safety: SYS_bpf with a live attr buffer of the declared size.
    unsafe { libc::syscall(libc::SYS_bpf, cmd, attr.as_mut_ptr(), attr.len() as u32) }
}

/// `BPF_MAP_CREATE` for a fixed-size key/value map.
pub fn map_create(
    map_type: u32,
    key_size: u32,
    value_size: u32,
    max_entries: u32,
) -> io::Result<i32> {
    let mut a = [0u8; 160];
    a[0..4].copy_from_slice(&map_type.to_ne_bytes());
    a[4..8].copy_from_slice(&key_size.to_ne_bytes());
    a[8..12].copy_from_slice(&value_size.to_ne_bytes());
    a[12..16].copy_from_slice(&max_entries.to_ne_bytes());
    let r = bpf(BPF_MAP_CREATE, &mut a);
    if r < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(r as i32)
    }
}

/// `BPF_MAP_UPDATE_ELEM` with `BPF_ANY`.
pub fn map_update(map: i32, key: &[u8], value: &[u8]) -> io::Result<()> {
    let mut a = [0u8; 160];
    a[0..8].copy_from_slice(&(map as u64).to_ne_bytes());
    a[8..16].copy_from_slice(&(key.as_ptr() as u64).to_ne_bytes());
    a[16..24].copy_from_slice(&(value.as_ptr() as u64).to_ne_bytes());
    a[24..32].copy_from_slice(&0u64.to_ne_bytes()); // BPF_ANY
    if bpf(BPF_MAP_UPDATE_ELEM, &mut a) < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// `BPF_MAP_LOOKUP_ELEM` — copies `value` into `out` (sized exactly).
pub fn map_lookup(map: i32, key: &[u8], out: &mut [u8]) -> io::Result<()> {
    let mut a = [0u8; 160];
    a[0..8].copy_from_slice(&(map as u64).to_ne_bytes());
    a[8..16].copy_from_slice(&(key.as_ptr() as u64).to_ne_bytes());
    a[16..24].copy_from_slice(&(out.as_mut_ptr() as u64).to_ne_bytes());
    if bpf(BPF_MAP_LOOKUP_ELEM, &mut a) < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// One `BPF_PROG_LOAD` attempt. When `log` is empty the program is
/// loaded with `log_level=0`/no buffer; otherwise `log` is filled with
/// the verifier output and `log_true_size` (attr offset 140) is
/// returned alongside the errno so the caller can right-size a retry.
fn try_prog_load(
    insns: &[u64],
    expected_attach: u32,
    log: &mut Vec<u8>,
) -> Result<i32, (io::Error, u32)> {
    let license = b"GPL\0";
    let mut a = [0u8; 160];
    a[0..4].copy_from_slice(&BPF_PROG_TYPE_CGROUP_SOCK_ADDR.to_ne_bytes());
    a[4..8].copy_from_slice(&(insns.len() as u32).to_ne_bytes());
    a[8..16].copy_from_slice(&(insns.as_ptr() as u64).to_ne_bytes());
    a[16..24].copy_from_slice(&(license.as_ptr() as u64).to_ne_bytes());
    if !log.is_empty() {
        a[24..28].copy_from_slice(&1u32.to_ne_bytes()); // log_level
        a[28..32].copy_from_slice(&(log.len() as u32).to_ne_bytes());
        a[32..40].copy_from_slice(&(log.as_mut_ptr() as u64).to_ne_bytes());
    }
    a[68..72].copy_from_slice(&expected_attach.to_ne_bytes()); // expected_attach_type
    let r = bpf(BPF_PROG_LOAD, &mut a);
    if r < 0 {
        return Err((
            io::Error::last_os_error(),
            u32::from_ne_bytes(a[140..144].try_into().unwrap()),
        ));
    }
    Ok(r as i32)
}

/// `BPF_PROG_LOAD` for a `CGROUP_SOCK_ADDR` program. On rejection the
/// verifier log is folded into the error message — a failed load must
/// say *why*, never just `EINVAL`.
///
/// The first attempt runs with no log buffer: since ~6.7 the kernel
/// answers `-ENOSPC` when a user buffer truncates the verbose log even
/// for a program that verified cleanly, and a multi-thousand-insn
/// program's log dwarfs any fixed buffer. Logging is enabled only for
/// the diagnostic retry after a real failure, sized from
/// `log_true_size` when the kernel reports it.
pub fn prog_load(insns: &[u64], expected_attach: u32, log: &mut Vec<u8>) -> io::Result<i32> {
    const LOG_CAP: usize = 8 << 20;
    log.clear();
    let (err, _) = match try_prog_load(insns, expected_attach, log) {
        Ok(fd) => return Ok(fd),
        Err(e) => e,
    };
    // Retry once with logging for diagnostics; size by the kernel's
    // log_true_size report when the first logged attempt still
    // truncates (ENOSPC).
    let mut size = 1 << 20;
    for _ in 0..2 {
        log.clear();
        log.resize(size.min(LOG_CAP), 0);
        match try_prog_load(insns, expected_attach, log) {
            Ok(fd) => return Ok(fd),
            Err((e, true_size)) if e.raw_os_error() == Some(libc::ENOSPC) => {
                if (true_size as usize) <= log.len() || log.len() == LOG_CAP {
                    return Err(with_log(err, log));
                }
                size = true_size as usize;
            }
            Err((e, _)) => return Err(with_log(e, log)),
        }
    }
    Err(with_log(err, log))
}

fn with_log(err: io::Error, log: &[u8]) -> io::Error {
    let text = String::from_utf8_lossy(log)
        .trim_matches(|c| c == '\0' || c == '\n')
        .to_string();
    io::Error::new(
        err.kind(),
        if text.is_empty() {
            format!("bpf prog_load: {err}")
        } else {
            format!("bpf prog_load: {err} (verifier: {text})")
        },
    )
}

/// `BPF_PROG_ATTACH` — the legacy cgroup attach path. `BPF_LINK_CREATE`
/// returns `EINVAL` for `CGROUP_SOCK_ADDR` programs on the kernels this
/// route was validated against, so the legacy syscall is used; the
/// attach is still a *link* semantically (detached explicitly or on
/// cgroup removal).
pub fn prog_attach(cgroup_fd: i32, prog_fd: i32, attach_type: u32) -> io::Result<()> {
    let mut a = [0u8; 160];
    a[0..4].copy_from_slice(&(cgroup_fd as u32).to_ne_bytes());
    a[4..8].copy_from_slice(&(prog_fd as u32).to_ne_bytes());
    a[8..12].copy_from_slice(&attach_type.to_ne_bytes());
    if bpf(BPF_PROG_ATTACH, &mut a) < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// `BPF_PROG_DETACH` counterpart for cleanup.
pub fn prog_detach(cgroup_fd: i32, prog_fd: i32, attach_type: u32) -> io::Result<()> {
    let mut a = [0u8; 160];
    a[0..4].copy_from_slice(&(cgroup_fd as u32).to_ne_bytes());
    a[4..8].copy_from_slice(&(prog_fd as u32).to_ne_bytes());
    a[8..12].copy_from_slice(&attach_type.to_ne_bytes());
    if bpf(BPF_PROG_DETACH, &mut a) < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}
