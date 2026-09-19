/// Linux x86-64 syscall number to name mapping.
///
/// Returns `None` for unknown syscall numbers.
pub fn syscall_name(number: u64) -> Option<&'static str> {
    // Table based on Linux kernel x86-64 syscall table (arch/x86/entry/syscalls/syscall_64.tbl)
    match number {
        0 => Some("read"),
        1 => Some("write"),
        2 => Some("open"),
        3 => Some("close"),
        4 => Some("stat"),
        5 => Some("fstat"),
        6 => Some("lstat"),
        7 => Some("poll"),
        8 => Some("lseek"),
        9 => Some("mmap"),
        10 => Some("mprotect"),
        11 => Some("munmap"),
        12 => Some("brk"),
        13 => Some("rt_sigaction"),
        14 => Some("rt_sigprocmask"),
        15 => Some("rt_sigreturn"),
        16 => Some("ioctl"),
        17 => Some("pread64"),
        18 => Some("pwrite64"),
        19 => Some("readv"),
        20 => Some("writev"),
        21 => Some("access"),
        22 => Some("pipe"),
        23 => Some("select"),
        24 => Some("sched_yield"),
        25 => Some("mremap"),
        26 => Some("msync"),
        27 => Some("mincore"),
        28 => Some("madvise"),
        29 => Some("shmget"),
        30 => Some("shmat"),
        31 => Some("shmctl"),
        32 => Some("dup"),
        33 => Some("dup2"),
        34 => Some("pause"),
        35 => Some("nanosleep"),
        36 => Some("getitimer"),
        37 => Some("alarm"),
        38 => Some("setitimer"),
        39 => Some("getpid"),
        40 => Some("sendfile"),
        41 => Some("socket"),
        42 => Some("connect"),
        43 => Some("accept"),
        44 => Some("sendto"),
        45 => Some("recvfrom"),
        46 => Some("sendmsg"),
        47 => Some("recvmsg"),
        48 => Some("shutdown"),
        49 => Some("bind"),
        50 => Some("listen"),
        51 => Some("getsockname"),
        52 => Some("getpeername"),
        53 => Some("socketpair"),
        54 => Some("setsockopt"),
        55 => Some("getsockopt"),
        56 => Some("clone"),
        57 => Some("fork"),
        58 => Some("vfork"),
        59 => Some("execve"),
        60 => Some("exit"),
        61 => Some("wait4"),
        62 => Some("kill"),
        63 => Some("uname"),
        72 => Some("fcntl"),
        73 => Some("flock"),
        74 => Some("fsync"),
        75 => Some("fdatasync"),
        76 => Some("truncate"),
        77 => Some("ftruncate"),
        78 => Some("getdents"),
        79 => Some("getcwd"),
        80 => Some("chdir"),
        81 => Some("fchdir"),
        82 => Some("rename"),
        83 => Some("mkdir"),
        84 => Some("rmdir"),
        85 => Some("creat"),
        86 => Some("link"),
        87 => Some("unlink"),
        88 => Some("symlink"),
        89 => Some("readlink"),
        90 => Some("chmod"),
        91 => Some("fchmod"),
        92 => Some("chown"),
        93 => Some("fchown"),
        94 => Some("lchown"),
        95 => Some("umask"),
        96 => Some("gettimeofday"),
        97 => Some("getrlimit"),
        98 => Some("getrusage"),
        99 => Some("sysinfo"),
        100 => Some("times"),
        101 => Some("ptrace"),
        102 => Some("getuid"),
        103 => Some("syslog"),
        104 => Some("getgid"),
        105 => Some("setuid"),
        106 => Some("setgid"),
        107 => Some("geteuid"),
        108 => Some("getegid"),
        109 => Some("setpgid"),
        110 => Some("getppid"),
        111 => Some("getpgrp"),
        112 => Some("setsid"),
        113 => Some("setreuid"),
        114 => Some("setregid"),
        131 => Some("sigaltstack"),
        137 => Some("statfs"),
        138 => Some("fstatfs"),
        157 => Some("prctl"),
        158 => Some("arch_prctl"),
        186 => Some("gettid"),
        200 => Some("tkill"),
        202 => Some("futex"),
        217 => Some("getdents64"),
        228 => Some("clock_gettime"),
        229 => Some("clock_getres"),
        230 => Some("clock_nanosleep"),
        231 => Some("exit_group"),
        232 => Some("epoll_wait"),
        233 => Some("epoll_ctl"),
        257 => Some("openat"),
        258 => Some("mkdirat"),
        259 => Some("mknodat"),
        260 => Some("fchownat"),
        262 => Some("newfstatat"),
        263 => Some("unlinkat"),
        264 => Some("renameat"),
        265 => Some("linkat"),
        266 => Some("symlinkat"),
        267 => Some("readlinkat"),
        268 => Some("fchmodat"),
        269 => Some("faccessat"),
        272 => Some("unshare"),
        281 => Some("epoll_pwait"),
        284 => Some("eventfd"),
        288 => Some("accept4"),
        290 => Some("eventfd2"),
        291 => Some("epoll_create1"),
        292 => Some("dup3"),
        293 => Some("pipe2"),
        302 => Some("prlimit64"),
        316 => Some("renameat2"),
        318 => Some("getrandom"),
        322 => Some("execveat"),
        332 => Some("statx"),
        435 => Some("clone3"),
        439 => Some("faccessat2"),
        _ => None,
    }
}

/// Linux AArch64 syscall number to name mapping.
///
/// Returns `None` for syscall numbers not present in the table.
///
/// Provenance (runbook P5-5): arm64 uses the kernel's asm-generic syscall
/// table. This table was transcribed from `include/uapi/asm-generic/unistd.h`
/// at Linux v6.12 (GPL-2.0 WITH Linux-syscall-note — the note explicitly
/// permits use of these numbers in userspace tools) with the arm64 uapi
/// options `__ARCH_WANT_NEW_STAT` (fstat=80, newfstatat=79),
/// `__ARCH_WANT_RENAMEAT` (38), `__ARCH_WANT_SET_GET_RLIMIT` (163/164) and
/// `__ARCH_WANT_SYS_CLONE` (220) applied, and `__SC_3264` numbers resolved to
/// their 64-bit names (e.g. fcntl=25, mmap=222). It was cross-checked against
/// glibc 2.40 `sysdeps/unix/sysv/linux/aarch64/arch-syscall.h` (autogenerated
/// per-arch list) and seccompiler 0.5.0's generated aarch64 table (kernel
/// 6.12). Excluded on purpose: numbers 244–259 (`__NR_arch_specific_syscall`
/// range — arm64 implements none), 295–402 (unassigned), 403–423 (`*_time64`
/// duplicates that only exist for 32-bit compat), and marker 463
/// (`__NR_syscalls`, not a syscall). Host `libc::SYS_*` constants are
/// deliberately not used — they describe the host ISA, not the analyzed one.
pub fn syscall_name_aarch64(number: u64) -> Option<&'static str> {
    match number {
        0 => Some("io_setup"),
        1 => Some("io_destroy"),
        2 => Some("io_submit"),
        3 => Some("io_cancel"),
        4 => Some("io_getevents"),
        5 => Some("setxattr"),
        6 => Some("lsetxattr"),
        7 => Some("fsetxattr"),
        8 => Some("getxattr"),
        9 => Some("lgetxattr"),
        10 => Some("fgetxattr"),
        11 => Some("listxattr"),
        12 => Some("llistxattr"),
        13 => Some("flistxattr"),
        14 => Some("removexattr"),
        15 => Some("lremovexattr"),
        16 => Some("fremovexattr"),
        17 => Some("getcwd"),
        18 => Some("lookup_dcookie"),
        19 => Some("eventfd2"),
        20 => Some("epoll_create1"),
        21 => Some("epoll_ctl"),
        22 => Some("epoll_pwait"),
        23 => Some("dup"),
        24 => Some("dup3"),
        25 => Some("fcntl"),
        26 => Some("inotify_init1"),
        27 => Some("inotify_add_watch"),
        28 => Some("inotify_rm_watch"),
        29 => Some("ioctl"),
        30 => Some("ioprio_set"),
        31 => Some("ioprio_get"),
        32 => Some("flock"),
        33 => Some("mknodat"),
        34 => Some("mkdirat"),
        35 => Some("unlinkat"),
        36 => Some("symlinkat"),
        37 => Some("linkat"),
        38 => Some("renameat"),
        39 => Some("umount2"),
        40 => Some("mount"),
        41 => Some("pivot_root"),
        42 => Some("nfsservctl"),
        43 => Some("statfs"),
        44 => Some("fstatfs"),
        45 => Some("truncate"),
        46 => Some("ftruncate"),
        47 => Some("fallocate"),
        48 => Some("faccessat"),
        49 => Some("chdir"),
        50 => Some("fchdir"),
        51 => Some("chroot"),
        52 => Some("fchmod"),
        53 => Some("fchmodat"),
        54 => Some("fchownat"),
        55 => Some("fchown"),
        56 => Some("openat"),
        57 => Some("close"),
        58 => Some("vhangup"),
        59 => Some("pipe2"),
        60 => Some("quotactl"),
        61 => Some("getdents64"),
        62 => Some("lseek"),
        63 => Some("read"),
        64 => Some("write"),
        65 => Some("readv"),
        66 => Some("writev"),
        67 => Some("pread64"),
        68 => Some("pwrite64"),
        69 => Some("preadv"),
        70 => Some("pwritev"),
        71 => Some("sendfile"),
        72 => Some("pselect6"),
        73 => Some("ppoll"),
        74 => Some("signalfd4"),
        75 => Some("vmsplice"),
        76 => Some("splice"),
        77 => Some("tee"),
        78 => Some("readlinkat"),
        79 => Some("newfstatat"),
        80 => Some("fstat"),
        81 => Some("sync"),
        82 => Some("fsync"),
        83 => Some("fdatasync"),
        84 => Some("sync_file_range"),
        85 => Some("timerfd_create"),
        86 => Some("timerfd_settime"),
        87 => Some("timerfd_gettime"),
        88 => Some("utimensat"),
        89 => Some("acct"),
        90 => Some("capget"),
        91 => Some("capset"),
        92 => Some("personality"),
        93 => Some("exit"),
        94 => Some("exit_group"),
        95 => Some("waitid"),
        96 => Some("set_tid_address"),
        97 => Some("unshare"),
        98 => Some("futex"),
        99 => Some("set_robust_list"),
        100 => Some("get_robust_list"),
        101 => Some("nanosleep"),
        102 => Some("getitimer"),
        103 => Some("setitimer"),
        104 => Some("kexec_load"),
        105 => Some("init_module"),
        106 => Some("delete_module"),
        107 => Some("timer_create"),
        108 => Some("timer_gettime"),
        109 => Some("timer_getoverrun"),
        110 => Some("timer_settime"),
        111 => Some("timer_delete"),
        112 => Some("clock_settime"),
        113 => Some("clock_gettime"),
        114 => Some("clock_getres"),
        115 => Some("clock_nanosleep"),
        116 => Some("syslog"),
        117 => Some("ptrace"),
        118 => Some("sched_setparam"),
        119 => Some("sched_setscheduler"),
        120 => Some("sched_getscheduler"),
        121 => Some("sched_getparam"),
        122 => Some("sched_setaffinity"),
        123 => Some("sched_getaffinity"),
        124 => Some("sched_yield"),
        125 => Some("sched_get_priority_max"),
        126 => Some("sched_get_priority_min"),
        127 => Some("sched_rr_get_interval"),
        128 => Some("restart_syscall"),
        129 => Some("kill"),
        130 => Some("tkill"),
        131 => Some("tgkill"),
        132 => Some("sigaltstack"),
        133 => Some("rt_sigsuspend"),
        134 => Some("rt_sigaction"),
        135 => Some("rt_sigprocmask"),
        136 => Some("rt_sigpending"),
        137 => Some("rt_sigtimedwait"),
        138 => Some("rt_sigqueueinfo"),
        139 => Some("rt_sigreturn"),
        140 => Some("setpriority"),
        141 => Some("getpriority"),
        142 => Some("reboot"),
        143 => Some("setregid"),
        144 => Some("setgid"),
        145 => Some("setreuid"),
        146 => Some("setuid"),
        147 => Some("setresuid"),
        148 => Some("getresuid"),
        149 => Some("setresgid"),
        150 => Some("getresgid"),
        151 => Some("setfsuid"),
        152 => Some("setfsgid"),
        153 => Some("times"),
        154 => Some("setpgid"),
        155 => Some("getpgid"),
        156 => Some("getsid"),
        157 => Some("setsid"),
        158 => Some("getgroups"),
        159 => Some("setgroups"),
        160 => Some("uname"),
        161 => Some("sethostname"),
        162 => Some("setdomainname"),
        163 => Some("getrlimit"),
        164 => Some("setrlimit"),
        165 => Some("getrusage"),
        166 => Some("umask"),
        167 => Some("prctl"),
        168 => Some("getcpu"),
        169 => Some("gettimeofday"),
        170 => Some("settimeofday"),
        171 => Some("adjtimex"),
        172 => Some("getpid"),
        173 => Some("getppid"),
        174 => Some("getuid"),
        175 => Some("geteuid"),
        176 => Some("getgid"),
        177 => Some("getegid"),
        178 => Some("gettid"),
        179 => Some("sysinfo"),
        180 => Some("mq_open"),
        181 => Some("mq_unlink"),
        182 => Some("mq_timedsend"),
        183 => Some("mq_timedreceive"),
        184 => Some("mq_notify"),
        185 => Some("mq_getsetattr"),
        186 => Some("msgget"),
        187 => Some("msgctl"),
        188 => Some("msgrcv"),
        189 => Some("msgsnd"),
        190 => Some("semget"),
        191 => Some("semctl"),
        192 => Some("semtimedop"),
        193 => Some("semop"),
        194 => Some("shmget"),
        195 => Some("shmctl"),
        196 => Some("shmat"),
        197 => Some("shmdt"),
        198 => Some("socket"),
        199 => Some("socketpair"),
        200 => Some("bind"),
        201 => Some("listen"),
        202 => Some("accept"),
        203 => Some("connect"),
        204 => Some("getsockname"),
        205 => Some("getpeername"),
        206 => Some("sendto"),
        207 => Some("recvfrom"),
        208 => Some("setsockopt"),
        209 => Some("getsockopt"),
        210 => Some("shutdown"),
        211 => Some("sendmsg"),
        212 => Some("recvmsg"),
        213 => Some("readahead"),
        214 => Some("brk"),
        215 => Some("munmap"),
        216 => Some("mremap"),
        217 => Some("add_key"),
        218 => Some("request_key"),
        219 => Some("keyctl"),
        220 => Some("clone"),
        221 => Some("execve"),
        222 => Some("mmap"),
        223 => Some("fadvise64"),
        224 => Some("swapon"),
        225 => Some("swapoff"),
        226 => Some("mprotect"),
        227 => Some("msync"),
        228 => Some("mlock"),
        229 => Some("munlock"),
        230 => Some("mlockall"),
        231 => Some("munlockall"),
        232 => Some("mincore"),
        233 => Some("madvise"),
        234 => Some("remap_file_pages"),
        235 => Some("mbind"),
        236 => Some("get_mempolicy"),
        237 => Some("set_mempolicy"),
        238 => Some("migrate_pages"),
        239 => Some("move_pages"),
        240 => Some("rt_tgsigqueueinfo"),
        241 => Some("perf_event_open"),
        242 => Some("accept4"),
        243 => Some("recvmmsg"),
        260 => Some("wait4"),
        261 => Some("prlimit64"),
        262 => Some("fanotify_init"),
        263 => Some("fanotify_mark"),
        264 => Some("name_to_handle_at"),
        265 => Some("open_by_handle_at"),
        266 => Some("clock_adjtime"),
        267 => Some("syncfs"),
        268 => Some("setns"),
        269 => Some("sendmmsg"),
        270 => Some("process_vm_readv"),
        271 => Some("process_vm_writev"),
        272 => Some("kcmp"),
        273 => Some("finit_module"),
        274 => Some("sched_setattr"),
        275 => Some("sched_getattr"),
        276 => Some("renameat2"),
        277 => Some("seccomp"),
        278 => Some("getrandom"),
        279 => Some("memfd_create"),
        280 => Some("bpf"),
        281 => Some("execveat"),
        282 => Some("userfaultfd"),
        283 => Some("membarrier"),
        284 => Some("mlock2"),
        285 => Some("copy_file_range"),
        286 => Some("preadv2"),
        287 => Some("pwritev2"),
        288 => Some("pkey_mprotect"),
        289 => Some("pkey_alloc"),
        290 => Some("pkey_free"),
        291 => Some("statx"),
        292 => Some("io_pgetevents"),
        293 => Some("rseq"),
        294 => Some("kexec_file_load"),
        424 => Some("pidfd_send_signal"),
        425 => Some("io_uring_setup"),
        426 => Some("io_uring_enter"),
        427 => Some("io_uring_register"),
        428 => Some("open_tree"),
        429 => Some("move_mount"),
        430 => Some("fsopen"),
        431 => Some("fsconfig"),
        432 => Some("fsmount"),
        433 => Some("fspick"),
        434 => Some("pidfd_open"),
        435 => Some("clone3"),
        436 => Some("close_range"),
        437 => Some("openat2"),
        438 => Some("pidfd_getfd"),
        439 => Some("faccessat2"),
        440 => Some("process_madvise"),
        441 => Some("epoll_pwait2"),
        442 => Some("mount_setattr"),
        443 => Some("quotactl_fd"),
        444 => Some("landlock_create_ruleset"),
        445 => Some("landlock_add_rule"),
        446 => Some("landlock_restrict_self"),
        447 => Some("memfd_secret"),
        448 => Some("process_mrelease"),
        449 => Some("futex_waitv"),
        450 => Some("set_mempolicy_home_node"),
        451 => Some("cachestat"),
        452 => Some("fchmodat2"),
        453 => Some("map_shadow_stack"),
        454 => Some("futex_wake"),
        455 => Some("futex_wait"),
        456 => Some("futex_requeue"),
        457 => Some("statmount"),
        458 => Some("listmount"),
        459 => Some("lsm_get_self_attr"),
        460 => Some("lsm_set_self_attr"),
        461 => Some("lsm_list_modules"),
        462 => Some("mseal"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_read() {
        assert_eq!(syscall_name(0), Some("read"));
    }

    #[test]
    fn test_write() {
        assert_eq!(syscall_name(1), Some("write"));
    }

    #[test]
    fn test_execve() {
        assert_eq!(syscall_name(59), Some("execve"));
    }

    #[test]
    fn test_exit() {
        assert_eq!(syscall_name(60), Some("exit"));
    }

    #[test]
    fn test_openat() {
        assert_eq!(syscall_name(257), Some("openat"));
    }

    #[test]
    fn test_socket() {
        assert_eq!(syscall_name(41), Some("socket"));
    }

    #[test]
    fn test_connect() {
        assert_eq!(syscall_name(42), Some("connect"));
    }

    #[test]
    fn test_clone() {
        assert_eq!(syscall_name(56), Some("clone"));
    }

    #[test]
    fn test_exit_group() {
        assert_eq!(syscall_name(231), Some("exit_group"));
    }

    #[test]
    fn test_getrandom() {
        assert_eq!(syscall_name(318), Some("getrandom"));
    }

    #[test]
    fn test_newfstatat() {
        assert_eq!(syscall_name(262), Some("newfstatat"));
    }

    #[test]
    fn test_unknown_number() {
        assert_eq!(syscall_name(9999), None);
    }

    #[test]
    fn test_ptrace() {
        assert_eq!(syscall_name(101), Some("ptrace"));
    }

    #[test]
    fn test_mmap() {
        assert_eq!(syscall_name(9), Some("mmap"));
    }

    #[test]
    fn test_mprotect() {
        assert_eq!(syscall_name(10), Some("mprotect"));
    }

    // ---- AArch64 table ----

    #[test]
    fn test_aarch64_common_syscalls() {
        assert_eq!(syscall_name_aarch64(63), Some("read"));
        assert_eq!(syscall_name_aarch64(64), Some("write"));
        assert_eq!(syscall_name_aarch64(56), Some("openat"));
        assert_eq!(syscall_name_aarch64(57), Some("close"));
        assert_eq!(syscall_name_aarch64(221), Some("execve"));
        assert_eq!(syscall_name_aarch64(93), Some("exit"));
        assert_eq!(syscall_name_aarch64(94), Some("exit_group"));
        assert_eq!(syscall_name_aarch64(198), Some("socket"));
        assert_eq!(syscall_name_aarch64(203), Some("connect"));
        assert_eq!(syscall_name_aarch64(222), Some("mmap"));
        assert_eq!(syscall_name_aarch64(226), Some("mprotect"));
        assert_eq!(syscall_name_aarch64(278), Some("getrandom"));
        assert_eq!(syscall_name_aarch64(435), Some("clone3"));
    }

    #[test]
    fn test_aarch64_table_is_not_x86_numbering() {
        // The same number must resolve to the aarch64 name, never the x86-64
        // one — e.g. 2 is `open` on x86-64 but `io_submit` on AArch64, and
        // x86-64 `execve`=59 is AArch64 `pipe2`.
        assert_eq!(syscall_name_aarch64(2), Some("io_submit"));
        assert_eq!(syscall_name_aarch64(59), Some("pipe2"));
        assert_eq!(syscall_name_aarch64(62), Some("lseek"));
        assert_eq!(syscall_name_aarch64(101), Some("nanosleep"));
    }

    #[test]
    fn test_aarch64_unknown_number() {
        assert_eq!(syscall_name_aarch64(9999), None);
        // Numbers never assigned on native AArch64 stay unnamed.
        assert_eq!(syscall_name_aarch64(300), None);
        assert_eq!(syscall_name_aarch64(410), None);
        assert_eq!(syscall_name_aarch64(463), None);
    }
}
