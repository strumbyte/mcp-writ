//! The notification filter program — `connect` → `USER_NOTIF`, native
//! arch otherwise → `ALLOW`, foreign arch / x32 nr → `KILL_PROCESS`.

/// The syscall number watched for `connect` on this architecture.
pub(super) const CONNECT_NR: u32 = libc::SYS_connect as u32;

/// `seccomp_data.arch` value for the build's own architecture — a
/// foreign-arch task's syscall table is a different table, so its
/// `connect` number is not this filter's number.
#[cfg(target_arch = "x86_64")]
pub(super) const AUDIT_ARCH_NATIVE: u32 = 0xC000_003E; // AUDIT_ARCH_X86_64
#[cfg(target_arch = "aarch64")]
pub(super) const AUDIT_ARCH_NATIVE: u32 = 0xC000_00B7; // AUDIT_ARCH_AARCH64
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
pub(super) const AUDIT_ARCH_NATIVE: u32 = 0; // never matches — see check_support

// BPF instruction fields the kernel's `sock_filter` carries.
pub(super) const BPF_LD: u16 = 0x00;
pub(super) const BPF_W: u16 = 0x00;
pub(super) const BPF_ABS: u16 = 0x20;
pub(super) const BPF_JMP: u16 = 0x05;
pub(super) const BPF_JEQ: u16 = 0x10;
pub(super) const BPF_JGE: u16 = 0x30;
pub(super) const BPF_K: u16 = 0x00;
pub(super) const BPF_RET: u16 = 0x06;

/// `__X32_SYSCALL_BIT` — syscall numbers at or above this value belong
/// to the x32 ABI's own table, not the native table this filter was
/// written against. An x32 task reports the same `AUDIT_ARCH_X86_64`
/// `arch` word as a native one, so without this bound an x32 `connect`
/// would fail the `watched_nr` compare and land on `ALLOW`
/// unsupervised. No native nr reaches the bound on any arch we build
/// for, so the check is unconditional.
pub(super) const X32_SYSCALL_BIT: u32 = 0x4000_0000;

fn stmt(code: u16, k: u32) -> libc::sock_filter {
    libc::sock_filter {
        code,
        jt: 0,
        jf: 0,
        k,
    }
}

fn jump(code: u16, k: u32, jt: u8, jf: u8) -> libc::sock_filter {
    libc::sock_filter { code, jt, jf, k }
}

/// The notification filter: `connect` → `USER_NOTIF`, anything else on
/// the native arch → `ALLOW`, a foreign arch or an x32-ABI syscall
/// number → `KILL_PROCESS` (fail-closed — both carry a syscall table
/// this program was not written against).
///
/// ```text
/// 0: ld  arch          (seccomp_data.arch)
/// 1: jeq AUDIT_ARCH_NATIVE → 2 ; else → 7
/// 2: ld  nr            (seccomp_data.nr)
/// 3: jge X32_SYSCALL_BIT   → 7 ; else → 4
/// 4: jeq connect_nr    → 5 ; else → 6
/// 5: ret USER_NOTIF
/// 6: ret ALLOW
/// 7: ret KILL_PROCESS
/// ```
pub(super) fn notify_program(watched_nr: u32) -> [libc::sock_filter; 8] {
    let arch_off = std::mem::offset_of!(libc::seccomp_data, arch) as u32;
    let nr_off = std::mem::offset_of!(libc::seccomp_data, nr) as u32;
    [
        stmt(BPF_LD | BPF_W | BPF_ABS, arch_off),
        jump(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_NATIVE, 0, 5),
        stmt(BPF_LD | BPF_W | BPF_ABS, nr_off),
        jump(BPF_JMP | BPF_JGE | BPF_K, X32_SYSCALL_BIT, 3, 0),
        jump(BPF_JMP | BPF_JEQ | BPF_K, watched_nr, 0, 1),
        stmt(BPF_RET | BPF_K, libc::SECCOMP_RET_USER_NOTIF),
        stmt(BPF_RET | BPF_K, libc::SECCOMP_RET_ALLOW),
        stmt(BPF_RET | BPF_K, libc::SECCOMP_RET_KILL_PROCESS),
    ]
}
