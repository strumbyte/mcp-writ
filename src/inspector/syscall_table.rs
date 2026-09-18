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
}
