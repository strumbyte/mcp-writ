use super::*;
use crate::policy::Policy;

#[test]
fn go_runtime_syscalls_are_mapped_but_not_implicitly_allowed() {
    let policy = Policy::default();
    let baseline = compile_seccomp(&policy).unwrap();
    for (name, expected) in [
        ("gettid", libc::SYS_gettid),
        ("tgkill", libc::SYS_tgkill),
        ("eventfd2", libc::SYS_eventfd2),
    ] {
        assert_eq!(syscall_numbers(name), vec![expected]);
        assert!(
            !policy
                .syscalls
                .allowed
                .iter()
                .any(|allowed| allowed == name)
        );
        let mut opted_in = policy.clone();
        opted_in.syscalls.allowed.push(name.into());
        assert!(
            compile_seccomp(&opted_in).unwrap().len() > baseline.len(),
            "{name} must produce an actual rule"
        );
    }
}

#[test]
fn legacy_names_resolve_to_canonical_syscalls() {
    // On every arch, `open` must grant `openat` — that is the syscall
    // libc actually emits for open(2).
    assert!(syscall_numbers("open").contains(&libc::SYS_openat));
    assert!(syscall_numbers("stat").contains(&libc::SYS_newfstatat));
    // fstat is a native fd-based syscall on both arches (aarch64 nr
    // 80); it must not be swallowed by the stat->newfstatat alias.
    assert_eq!(syscall_numbers("fstat"), vec![libc::SYS_fstat]);
    assert!(syscall_numbers("access").contains(&libc::SYS_faccessat));
    assert!(syscall_numbers("access").contains(&libc::SYS_faccessat2));
    assert!(syscall_numbers("poll").contains(&libc::SYS_ppoll));
    assert!(syscall_numbers("fork").contains(&libc::SYS_clone));
    assert!(syscall_numbers("accept").contains(&libc::SYS_accept4));
}

#[cfg(target_arch = "aarch64")]
#[test]
fn aarch64_has_no_legacy_nr_but_aliases_cover_them() {
    // The operations a typical policy names must still produce rules
    // even though the legacy syscall nrs do not exist on aarch64.
    for name in [
        "open",
        "stat",
        "fstat",
        "lstat",
        "access",
        "readlink",
        "pipe",
        "dup2",
        "poll",
        "select",
        "epoll_wait",
        "mkdir",
        "unlink",
        "rmdir",
        "chmod",
        "chown",
        "link",
        "symlink",
        "fork",
        "vfork",
        "accept",
    ] {
        assert!(
            !syscall_numbers(name).is_empty(),
            "{name} must resolve on aarch64"
        );
    }
    // arch_prctl is genuinely x86_64-only — nothing to alias to.
    assert!(syscall_numbers("arch_prctl").is_empty());
}

#[cfg(target_arch = "x86_64")]
#[test]
fn x86_64_aliases_keep_the_native_nr() {
    // x86_64 keeps the legacy nr AND gains the canonical one libc
    // uses internally (glibc open() emits openat on x86_64 too).
    let nrs = syscall_numbers("open");
    assert!(nrs.contains(&libc::SYS_open));
    assert!(nrs.contains(&libc::SYS_openat));
}

#[cfg(target_arch = "aarch64")]
#[test]
fn aarch64_rename_resolves_renameat_only() {
    // aarch64 wires renameat at nr 38; libc emits renameat for
    // rename()/renameat() there — and only that nr must reach the
    // filter. renameat2's flag operations stay behind an explicit
    // "renameat2" entry.
    for name in ["rename", "renameat"] {
        let nrs = syscall_numbers(name);
        assert!(
            nrs.contains(&libc::SYS_renameat),
            "{name} must map to renameat"
        );
        assert!(
            !nrs.contains(&libc::SYS_renameat2),
            "{name} must not grant renameat2"
        );
    }
    let mut policy = Policy::default();
    policy.syscalls.allowed = vec!["renameat".to_string()];
    let rules = collect_syscall_rules(&policy, &policy.syscalls.allowed, false).unwrap();
    assert!(rules.contains_key(&libc::SYS_renameat));
    assert!(!rules.contains_key(&libc::SYS_renameat2));
    // The flagged variant stays reachable under its own name.
    policy.syscalls.allowed = vec!["renameat2".to_string()];
    let rules = collect_syscall_rules(&policy, &policy.syscalls.allowed, false).unwrap();
    assert!(rules.contains_key(&libc::SYS_renameat2));
}

#[test]
fn fork_vfork_expand_to_flag_constrained_clone() {
    // fork/vfork grants must not become an unconstrained clone grant:
    // clone's flag word is pinned to the bits those operations need.
    let mut policy = Policy::default();
    policy.syscalls.allowed = vec!["fork".to_string(), "vfork".to_string()];
    let rules = collect_syscall_rules(&policy, &policy.syscalls.allowed, false).unwrap();
    let clone_rules = rules
        .get(&libc::SYS_clone)
        .expect("fork/vfork must produce clone rules");
    assert_eq!(clone_rules.len(), 2, "one conditioned clone rule per name");

    // An explicit "clone" entry stays unconditional and is not
    // narrowed by fork/vfork expansion, in either policy order.
    for names in [["clone", "fork"], ["fork", "clone"]] {
        let mut policy = Policy::default();
        policy.syscalls.allowed = names.iter().map(|s| s.to_string()).collect();
        let rules = collect_syscall_rules(&policy, &policy.syscalls.allowed, false).unwrap();
        assert!(
            rules.get(&libc::SYS_clone).is_some_and(|r| r.is_empty()),
            "explicit clone must stay unconditional for {names:?}"
        );
    }
}

#[test]
fn fork_pinned_reason_matches_clone_allowance() {
    let fork_grant = |names: &[&str]| {
        let mut policy = Policy::default();
        policy.syscalls.allowed = names.iter().map(|s| s.to_string()).collect();
        syscall_grant_intents(&policy, false, false)
            .into_iter()
            .find(|g| matches!(&g.subject, GrantSubject::Syscall { name } if name == "fork"))
            .unwrap()
            .reason
    };
    // Without an explicit clone grant, SYS_clone's flag word is
    // pinned by the fork expansion.
    assert_eq!(
        fork_grant(&["fork"]).as_deref(),
        Some("clone(2) flag word pinned to the fork form")
    );
    // With clone allowed unconditionally the claim is false and the
    // reason is omitted.
    assert_eq!(fork_grant(&["fork", "clone"]), None);
}

#[test]
fn io_uring_grants_are_surfaced_as_dangerous() {
    let mut policy = Policy::default();
    policy.syscalls.allowed = ["io_uring_setup", "io_uring_enter", "io_uring_register"]
        .iter()
        .map(|s| s.to_string())
        .collect();
    for name in ["io_uring_setup", "io_uring_enter", "io_uring_register"] {
        let grant = syscall_grant_intents(&policy, false, false)
            .into_iter()
            .find(|g| matches!(&g.subject, GrantSubject::Syscall { name: n } if n == name))
            .unwrap_or_else(|| panic!("missing grant for {name}"));
        assert_eq!(grant.state, ControlState::Planned);
        assert!(
            grant
                .reason
                .as_deref()
                .is_some_and(|r| r.contains("dangerous syscall")),
            "{name} must carry the dangerous-syscall reason: {:?}",
            grant.reason
        );
    }
    // The mapping itself is intact: the names still produce rules.
    let rules = collect_syscall_rules(&policy, &policy.syscalls.allowed, false).unwrap();
    assert!(rules.contains_key(&libc::SYS_io_uring_setup));
    assert!(rules.contains_key(&libc::SYS_io_uring_enter));
    assert!(rules.contains_key(&libc::SYS_io_uring_register));
}

#[test]
fn namespaced_socket_rule_pins_non_unix_domains() {
    // In namespaced mode the mountns shares the host filesystem and
    // Landlock cannot mediate AF_UNIX connect — socket() must deny
    // the unix domain regardless of the egress posture. An
    // unconditional allow (empty rule vec) would leave host daemon
    // sockets reachable.
    let mut policy = Policy::default();
    policy.syscalls.allowed = vec!["socket".to_string()];
    for deny_all in [true, false] {
        policy.network.outbound.deny_all_others = deny_all;
        let rules = collect_syscall_rules(&policy, &policy.syscalls.allowed, true).unwrap();
        let socket_rules = rules
            .get(&libc::SYS_socket)
            .expect("socket grant must produce a rule");
        // The AF_INET/AF_INET6 allowlist is expressed as OR'd
        // single-condition rules — one Eq condition on arg0 per
        // listed family — so exactly two rules, regardless of the
        // egress posture.
        assert_eq!(
            socket_rules.len(),
            2,
            "namespaced socket is pinned to the IP-family allowlist \
                 (deny_all={deny_all})"
        );
    }
    // PR-18: the native path pins the same way under deny-all —
    // AF_UNIX pathnames resolve on the shared host filesystem and
    // Landlock mediates neither path nor abstract sockets below
    // ABI v6/v9, so the family closes at socket() creation on both
    // routes. Under an open posture it stays unconditional.
    policy.network.outbound.deny_all_others = false;
    let rules = collect_syscall_rules(&policy, &policy.syscalls.allowed, false).unwrap();
    assert!(
        rules.get(&libc::SYS_socket).is_some_and(|r| r.is_empty()),
        "native unrestricted socket stays unconditional"
    );
    policy.network.outbound.deny_all_others = true;
    let rules = collect_syscall_rules(&policy, &policy.syscalls.allowed, false).unwrap();
    assert_eq!(
        rules.get(&libc::SYS_socket).map(|r| r.len()),
        Some(2),
        "native deny-all socket pins to the IP-family allowlist"
    );
}

#[test]
fn namespaced_socket_grant_reason_notes_af_unix_deny() {
    let mut policy = Policy::default();
    policy.syscalls.allowed = vec!["socket".to_string()];
    let reason = syscall_grant_intents(&policy, false, true)
        .into_iter()
        .find(|g| matches!(&g.subject, GrantSubject::Syscall { name } if name == "socket"))
        .expect("socket grant")
        .reason
        .expect("namespaced socket grant carries a reason");
    assert!(reason.contains("AF_INET/AF_INET6"), "{reason}");
    assert!(reason.contains("AF_UNIX"), "{reason}");
    // deny_all_others does not relax the namespaced family pin.
    policy.network.outbound.deny_all_others = true;
    let reason_deny_all = syscall_grant_intents(&policy, false, true)
        .into_iter()
        .find(|g| matches!(&g.subject, GrantSubject::Syscall { name } if name == "socket"))
        .expect("socket grant")
        .reason
        .expect("namespaced socket grant carries a reason");
    assert_eq!(reason, reason_deny_all, "{reason_deny_all}");
    // PR-18: the native grant under deny-all names the same AF_UNIX
    // closure — the family pin exists on both routes now. Under an
    // open posture it pins nothing and claims no pin.
    let native_reason = syscall_grant_intents(&policy, false, false)
        .into_iter()
        .find(|g| matches!(&g.subject, GrantSubject::Syscall { name } if name == "socket"))
        .expect("socket grant")
        .reason;
    assert!(
        native_reason
            .as_deref()
            .is_some_and(|r| r.contains("AF_UNIX")),
        "native deny-all socket must disclose the AF_UNIX closure: {native_reason:?}"
    );
    policy.network.outbound.deny_all_others = false;
    let native_open = syscall_grant_intents(&policy, false, false)
        .into_iter()
        .find(|g| matches!(&g.subject, GrantSubject::Syscall { name } if name == "socket"))
        .expect("socket grant")
        .reason;
    assert!(
        !native_open
            .as_deref()
            .is_some_and(|r| r.contains("AF_UNIX")),
        "open-posture native socket must not claim an AF_UNIX pin: {native_open:?}"
    );
}

#[test]
fn namespaced_socketpair_denies_unix_datagram_escape() {
    // The AF_UNIX+SOCK_DGRAM combination must be the only pair
    // refused: a datagram pair can sendto(2) any host unix pathname
    // over the shared mountns — the same escape the socket() family
    // pin closes. Or-rules accept a non-Unix domain or a
    // connection-bound type; PR-18 shares the denial with the
    // native route since socketpair's domain word sits outside the
    // socket() pin.
    let mut policy = Policy::default();
    policy.syscalls.allowed = vec!["socketpair".to_string()];
    let rules = collect_syscall_rules(&policy, &policy.syscalls.allowed, true).unwrap();
    let pair_rules = rules
        .get(&libc::SYS_socketpair)
        .expect("socketpair grant must produce rules");
    assert_eq!(
        pair_rules.len(),
        3,
        "non-Unix domain, stream type or seqpacket type"
    );
    // PR-18: the native route carries the same datagram-pair
    // denial — socketpair's domain word is not covered by the
    // socket() family pin, so the sendto escape would stay open
    // without it. `allow unix="*"` lifts it with the family opt-in.
    let rules = collect_syscall_rules(&policy, &policy.syscalls.allowed, false).unwrap();
    assert_eq!(
        rules.get(&libc::SYS_socketpair).map(|r| r.len()),
        Some(3),
        "native socketpair denies the unix datagram pair too"
    );
    let mut star_policy = Policy::default();
    star_policy.network.outbound.egress_rules = vec![crate::policy::EgressRule {
        allow: true,
        dest: crate::policy::EgressDest::Unix("*".to_string()),
        proto: crate::policy::EgressProto::Tcp,
        port: None,
    }];
    star_policy.syscalls.allowed = vec!["socketpair".to_string()];
    let rules = collect_syscall_rules(&star_policy, &star_policy.syscalls.allowed, false).unwrap();
    assert!(
        rules
            .get(&libc::SYS_socketpair)
            .is_some_and(|r| r.is_empty()),
        "'allow unix=\"*\"' opens the family — socketpair stays unconditional"
    );

    // Live check: a forked child applies the namespaced filter and
    // proves the escape closed — socketpair(AF_UNIX, SOCK_DGRAM)
    // fails with the filter's EPERM so no sendto(2) can reach the
    // host pathname listener (bound outside /run by the parent),
    // while a connection-bound pair still works.
    policy.syscalls.allowed = ["socketpair", "sendto", "exit", "exit_group"]
        .iter()
        .map(|s| s.to_string())
        .collect();
    let program = compile_seccomp_inner_namespaced(&policy, false).unwrap();

    let dir = std::env::temp_dir().join(format!("mcp-writ-sp-{}", std::process::id())); // nosemgrep: rust.lang.security.temp-dir.temp-dir
    std::fs::create_dir_all(&dir).unwrap();
    let sock_path = dir.join("listener.sock");
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    let listener = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_DGRAM, 0) };
    assert!(
        listener >= 0,
        "listener socket: {}",
        std::io::Error::last_os_error()
    );
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
    use std::os::unix::ffi::OsStrExt;
    let path_bytes = sock_path.as_os_str().as_bytes();
    assert!(path_bytes.len() < addr.sun_path.len());
    for (d, &b) in addr.sun_path.iter_mut().zip(path_bytes) {
        *d = b as libc::c_char;
    }
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    let rc = unsafe {
        libc::bind(
            listener,
            &addr as *const libc::sockaddr_un as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_un>() as libc::socklen_t,
        )
    };
    assert_eq!(rc, 0, "bind listener: {}", std::io::Error::last_os_error());

    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0, "fork: {}", std::io::Error::last_os_error());
    if pid == 0 {
        let _ = set_no_new_privs();
        if apply_seccomp_program(&program).is_err() {
            // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
            unsafe { libc::_exit(90) };
        }
        let mut sv = [-1i32; 2];
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        if unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_DGRAM, 0, sv.as_mut_ptr()) } == 0 {
            // The pair exists — the escape is open; prove the harm
            // by delivering a datagram to the host pathname, then
            // report failure.
            // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
            unsafe {
                libc::sendto(
                    sv[0],
                    b"x".as_ptr() as *const libc::c_void,
                    1,
                    0,
                    &addr as *const libc::sockaddr_un as *const libc::sockaddr,
                    std::mem::size_of::<libc::sockaddr_un>() as libc::socklen_t,
                );
                libc::_exit(91);
            }
        }
        if std::io::Error::last_os_error().raw_os_error() != Some(libc::EPERM) {
            // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
            unsafe { libc::_exit(92) };
        }
        // Connection-bound pairs stay usable — the pin is the
        // datagram type, not the family.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        if unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, sv.as_mut_ptr()) } != 0 {
            // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
            unsafe { libc::_exit(93) };
        }
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe { libc::_exit(0) };
    }
    let mut status = 0i32;
    let mut done = false;
    for _ in 0..50 {
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        let r = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
        if r == pid {
            done = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    if !done {
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe {
            libc::kill(pid, libc::SIGKILL);
            libc::waitpid(pid, &mut status, 0);
        }
    }
    std::fs::remove_dir_all(&dir).ok();
    assert!(done, "filtered child did not exit");
    assert!(
        libc::WIFEXITED(status),
        "child did not exit cleanly: {status:#x}"
    );
    assert_eq!(
        libc::WEXITSTATUS(status),
        0,
        "filtered child failed via exit {}",
        libc::WEXITSTATUS(status)
    );
    // And nothing arrived at the host pathname socket.
    let mut pfd = libc::pollfd {
        fd: listener,
        events: libc::POLLIN,
        revents: 0,
    };
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    let n = unsafe { libc::poll(&mut pfd, 1, 0) };
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    unsafe { libc::close(listener) };
    assert_eq!(
        n, 0,
        "a datagram reached the host pathname — the escape is open"
    );
}
