use std::fs::File;
use std::net::IpAddr;
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};

use crate::policy::OutboundPolicy;
use crate::policy::{EgressDest, EgressProto, EgressRule};

use super::filter::{
    AUDIT_ARCH_NATIVE, BPF_JGE, BPF_JMP, BPF_K, CONNECT_NR, X32_SYSCALL_BIT, notify_program,
};
use super::grants::{Grants, parse_snapshot, unix_secs_now};
use super::handoff::{UnotifyParent, install_listener, send_listener};
use super::inspect::{SockTarget, inspect_sockaddr, parse_sockaddr};
use super::notif::{
    emulate_connect, notif_resp_continue, notif_resp_error, notif_resp_result, notify_recv,
    notify_send,
};
use super::*;

fn outbound(
    allowed: &[&str],
    denied: &[&str],
    cidrs: &[&str],
    denied_cidrs: &[&str],
    deny_all: bool,
) -> OutboundPolicy {
    OutboundPolicy {
        allowed: allowed.iter().map(|s| s.to_string()).collect(),
        allowed_port_qualified: Vec::new(),
        allowed_cidrs: cidrs.iter().map(|s| s.to_string()).collect(),
        allowed_cidrs_port_qualified: Vec::new(),
        denied_hosts: denied.iter().map(|s| s.to_string()).collect(),
        denied_cidrs: denied_cidrs.iter().map(|s| s.to_string()).collect(),
        deny_all_others: deny_all,
        egress_rules: Vec::new(),
    }
}

#[test]
fn evaluator_deny_precedence_and_layers() {
    let p = outbound(
        &["10.0.0.0/8"],
        &["10.9.0.0/16"],
        &["10.0.0.0/8"],
        &["10.9.0.0/16"],
        true,
    );
    let ev = IpLayerEvaluator::new(&p).unwrap();
    // deny cidr wins over an enclosing allow cidr
    let dest: IpAddr = "10.9.1.1".parse().unwrap();
    assert_eq!(
        ev.evaluate(&dest, EgressProto::Tcp, 443, &[], false),
        IpVerdict::Deny {
            decision: "deny-cidr",
            rule: Some("10.9.0.0/16".into())
        }
    );
    // allow cidr covers
    let dest: IpAddr = "10.1.2.3".parse().unwrap();
    assert!(matches!(
        ev.evaluate(&dest, EgressProto::Tcp, 443, &[], false),
        IpVerdict::Allow { .. }
    ));
    // unmatched → deny-all
    let dest: IpAddr = "192.0.2.9".parse().unwrap();
    assert_eq!(
        ev.evaluate(&dest, EgressProto::Tcp, 443, &[], false),
        IpVerdict::Deny {
            decision: "not-allowed",
            rule: None
        }
    );
}

#[test]
fn evaluator_literal_host_rules_project_to_ip_layer() {
    let p = outbound(&["203.0.113.7"], &["192.0.2.1"], &[], &[], true);
    let ev = IpLayerEvaluator::new(&p).unwrap();
    let allow: IpAddr = "203.0.113.7".parse().unwrap();
    assert!(matches!(
        ev.evaluate(&allow, EgressProto::Tcp, 443, &[], false),
        IpVerdict::Allow {
            basis: "allow-host",
            ..
        }
    ));
    let deny: IpAddr = "192.0.2.1".parse().unwrap();
    assert_eq!(
        ev.evaluate(&deny, EgressProto::Tcp, 443, &[], false),
        IpVerdict::Deny {
            decision: "deny-host",
            rule: Some("192.0.2.1".into())
        }
    );
}

#[test]
fn evaluator_dynamic_grants_and_deny_all() {
    let p = outbound(&[], &[], &[], &[], true);
    let ev = IpLayerEvaluator::new(&p).unwrap();
    let dest: IpAddr = "93.184.216.34".parse().unwrap();
    assert!(matches!(
        ev.evaluate(&dest, EgressProto::Tcp, 443, &[], false),
        IpVerdict::Deny { .. }
    ));
    let names = vec!["www.example.com".to_string()];
    assert!(matches!(
        ev.evaluate(&dest, EgressProto::Tcp, 443, &names, true),
        IpVerdict::Allow {
            basis: "allowlist-grant",
            ..
        }
    ));
    // A deny rule still wins over a grant (deny precedence is
    // absolute at this layer).
    let p = outbound(&[], &[], &[], &["93.184.216.0/24"], true);
    let ev = IpLayerEvaluator::new(&p).unwrap();
    assert!(matches!(
        ev.evaluate(&dest, EgressProto::Tcp, 443, &names, true),
        IpVerdict::Deny { .. }
    ));
}

#[test]
fn evaluator_open_posture() {
    let p = outbound(&["*"], &[], &[], &[], false);
    let ev = IpLayerEvaluator::new(&p).unwrap();
    let dest: IpAddr = "8.8.8.8".parse().unwrap();
    assert!(matches!(
        ev.evaluate(&dest, EgressProto::Tcp, 443, &[], false),
        IpVerdict::Allow {
            basis: "allow-host",
            ..
        }
    ));
    let p2 = outbound(&[], &[], &[], &[], false);
    let ev2 = IpLayerEvaluator::new(&p2).unwrap();
    assert!(matches!(
        ev2.evaluate(&dest, EgressProto::Tcp, 443, &[], false),
        IpVerdict::Allow { basis: "open", .. }
    ));
}

#[test]
fn evaluator_enforces_qualified_rules() {
    // The connect tuple carries proto+port, so qualifiers are
    // *enforced* — never widened, never refused.
    let mut p = outbound(&[], &[], &[], &[], true);
    p.egress_rules = vec![
        EgressRule {
            allow: true,
            dest: EgressDest::Cidr("10.0.0.0/8".into()),
            proto: EgressProto::Tcp,
            port: Some(443),
        },
        EgressRule {
            allow: true,
            dest: EgressDest::Host("dns.example".into()),
            proto: EgressProto::Udp,
            port: Some(53),
        },
        EgressRule {
            allow: true,
            dest: EgressDest::Host("*".into()),
            proto: EgressProto::Any,
            port: Some(8443),
        },
    ];
    let ev = IpLayerEvaluator::new(&p).unwrap();
    let dest: IpAddr = "10.1.2.3".parse().unwrap();
    // TCP:443 covered by the cidr rule — allowed.
    assert!(matches!(
        ev.evaluate(&dest, EgressProto::Tcp, 443, &[], false),
        IpVerdict::Allow {
            basis: "allow-cidr",
            ..
        }
    ));
    // TCP:80 — the port qualifier does not cover.
    assert!(matches!(
        ev.evaluate(&dest, EgressProto::Tcp, 80, &[], false),
        IpVerdict::Deny {
            decision: "not-allowed",
            ..
        }
    ));
    // UDP:443 — the proto qualifier does not cover.
    assert!(matches!(
        ev.evaluate(&dest, EgressProto::Udp, 443, &[], false),
        IpVerdict::Deny {
            decision: "not-allowed",
            ..
        }
    ));
    // A name dest is inert at the IP layer — the UDP rule's grants
    // arrive through the DNS path instead.
    let granted: IpAddr = "93.184.216.34".parse().unwrap();
    assert!(matches!(
        ev.evaluate(
            &granted,
            EgressProto::Udp,
            53,
            &["dns.example".into()],
            true
        ),
        IpVerdict::Allow {
            basis: "allowlist-grant",
            ..
        }
    ));
    // The -scoped port rule covers any destination on 8443, either
    // transport.
    let any_dest: IpAddr = "203.0.113.1".parse().unwrap();
    assert!(matches!(
        ev.evaluate(&any_dest, EgressProto::Udp, 8443, &[], false),
        IpVerdict::Allow {
            basis: "allow-host",
            ..
        }
    ));
    assert!(matches!(
        ev.evaluate(&any_dest, EgressProto::Tcp, 8443, &[], false),
        IpVerdict::Allow { .. }
    ));
    assert!(matches!(
        ev.evaluate(&any_dest, EgressProto::Tcp, 443, &[], false),
        IpVerdict::Deny { .. }
    ));
}

#[test]
fn evaluator_wildcard_deny_wins_over_everything() {
    let p = outbound(&["10.0.0.0/8"], &["*"], &["10.0.0.0/8"], &[], true);
    let ev = IpLayerEvaluator::new(&p).unwrap();
    let dest: IpAddr = "10.1.2.3".parse().unwrap();
    assert_eq!(
        ev.evaluate(&dest, EgressProto::Tcp, 443, &[], false),
        IpVerdict::Deny {
            decision: "deny-host",
            rule: Some("*".into())
        }
    );
}

#[test]
fn sockaddr_decode_v4_v6_mapped_and_other() {
    // sockaddr_in for 192.0.2.7:443
    let mut sa = [0u8; 16];
    sa[0..2].copy_from_slice(&(libc::AF_INET as u16).to_ne_bytes());
    sa[2..4].copy_from_slice(&443u16.to_be_bytes());
    sa[4..8].copy_from_slice(&[192, 0, 2, 7]);
    match parse_sockaddr(&sa, 16) {
        SockTarget::Inet { dest, port, .. } => {
            assert_eq!(dest, "192.0.2.7".parse::<IpAddr>().unwrap());
            assert_eq!(port, 443);
        }
        other => panic!("expected inet, got {other:?}"),
    }
    // sockaddr_in6 ::ffff:10.1.2.3:8080 folds to the v4 dest.
    // Layout: family(0..2) port(2..4) flowinfo(4..8) addr(8..24)
    // scope_id(24..28); a v4-mapped v6 addr is 10 zeros, ff ff, v4.
    let mut sa6 = [0u8; 28];
    sa6[0..2].copy_from_slice(&(libc::AF_INET6 as u16).to_ne_bytes());
    sa6[2..4].copy_from_slice(&8080u16.to_be_bytes());
    sa6[18] = 0xff;
    sa6[19] = 0xff;
    sa6[20..24].copy_from_slice(&[10, 1, 2, 3]);
    match parse_sockaddr(&sa6, 28) {
        SockTarget::Inet { dest, port, .. } => {
            assert_eq!(dest, "10.1.2.3".parse::<IpAddr>().unwrap());
            assert_eq!(port, 8080);
        }
        other => panic!("expected inet, got {other:?}"),
    }
    // sockaddr_in6 ::10.1.2.3 — the deprecated IPv4-*compatible*
    // form does NOT fold: the policy layer (`analyze_policy_cidr` /
    // `canonicalize_url_host`) folds only `::ffff:`-mapped
    // spellings, so this destination must stay a v6 address that a
    // v4 CIDR rule can never match.
    let mut sa6c = [0u8; 28];
    sa6c[0..2].copy_from_slice(&(libc::AF_INET6 as u16).to_ne_bytes());
    sa6c[2..4].copy_from_slice(&8080u16.to_be_bytes());
    sa6c[20..24].copy_from_slice(&[10, 1, 2, 3]);
    match parse_sockaddr(&sa6c, 28) {
        SockTarget::Inet { dest, port, .. } => {
            assert!(dest.is_ipv6(), "compatible spelling must stay v6");
            assert_eq!(dest, "::a01:203".parse::<IpAddr>().unwrap());
            assert_eq!(port, 8080);
        }
        other => panic!("expected inet, got {other:?}"),
    }
    // AF_UNIX → OtherFamily.
    let mut su = [0u8; 8];
    su[0..2].copy_from_slice(&(libc::AF_UNIX as u16).to_ne_bytes());
    assert!(matches!(
        parse_sockaddr(&su, 8),
        SockTarget::OtherFamily { .. }
    ));
    // Truncated sockaddr_in → fail-closed unreadable.
    assert!(matches!(
        parse_sockaddr(&sa[..8], 8),
        SockTarget::Unreadable { .. }
    ));
}

#[test]
fn snapshot_parse_and_ttl_expiry() {
    let now = unix_secs_now();
    let body = format!(
        r#"{{"schema_version":"1.0","generated_at_unix_secs":{now},"entries":[{{"name":"a.example","addr":"93.184.216.34","expires_at_unix_secs":{}}},{{"name":"b.example","addr":"203.0.113.8","expires_at_unix_secs":{}}}]}}"#,
        now + 300,
        now - 1,
    );
    let entries = parse_snapshot(&body);
    assert_eq!(entries.len(), 2);

    // Real-file round trip — the same contract `dns-gate
    // --allowlist-export` writes for a supervisor.
    let path = std::env::temp_dir().join(format!(
        "mcp-writ-unotify-test-{}-{now}.json",
        std::process::id()
    ));
    std::fs::write(&path, &body).unwrap();
    let mut g = Grants::new(GrantSource::SnapshotFile(path.clone()));
    let live = g.live_names(&"93.184.216.34".parse().unwrap());
    assert_eq!(live, vec!["a.example".to_string()]);
    // Expired grant is closed even though it is in the file.
    assert!(g.live_names(&"203.0.113.8".parse().unwrap()).is_empty());
    // A missing file is an empty grant set (fail closed).
    std::fs::remove_file(&path).unwrap();
    assert!(g.live_names(&"93.184.216.34".parse().unwrap()).is_empty());
    // Garbage degrades to empty, never a guess.
    assert!(parse_snapshot("not json").is_empty());
    assert!(parse_snapshot(r#"{"schema_version":"1.0"}"#).is_empty());
}

#[test]
fn bpf_program_refuses_unencodable_watch_lists() {
    // u8 jump offsets cap the program at ~250 compares — an empty or
    // oversized watch list is refused outright rather than emitted
    // with wrapped offsets.
    assert!(notify_program(&[]).is_none());
    assert!(notify_program(&[0; 250]).is_none());
    assert!(notify_program(&[0; 249]).is_some());
}

#[test]
fn bpf_program_shape() {
    let prog = notify_program(&[CONNECT_NR]).unwrap();
    assert_eq!(prog.len(), 8);
    assert_eq!(prog[5].k, libc::SECCOMP_RET_USER_NOTIF);
    assert_eq!(prog[6].k, libc::SECCOMP_RET_ALLOW);
    assert_eq!(prog[7].k, libc::SECCOMP_RET_KILL_PROCESS);
    assert_eq!(prog[4].k, CONNECT_NR);
    assert_eq!(prog[3].k, X32_SYSCALL_BIT);
    assert_eq!(prog[3].code, BPF_JMP | BPF_JGE | BPF_K);
    assert_eq!(prog[1].k, AUDIT_ARCH_NATIVE);
}

#[test]
fn bpf_program_shape_multi_watched() {
    // Three watched nrs: each compare jumps match→notif, miss→next
    // compare; only the last miss falls to ALLOW.
    let prog = notify_program(&[CONNECT_NR, 42, 43]).unwrap();
    assert_eq!(prog.len(), 4 + 3 + 3);
    let notif_idx = 4 + 3;
    assert_eq!(prog[notif_idx].k, libc::SECCOMP_RET_USER_NOTIF);
    assert_eq!(prog[notif_idx + 1].k, libc::SECCOMP_RET_ALLOW);
    assert_eq!(prog[notif_idx + 2].k, libc::SECCOMP_RET_KILL_PROCESS);
    // First compare: match jumps +2 (past the second compare) to
    // notif; miss falls through to the second compare.
    assert_eq!(prog[4].k, CONNECT_NR);
    assert_eq!(prog[4].jt, 2);
    assert_eq!(prog[4].jf, 0);
    // Second compare: match lands on notif directly; miss falls to the
    // third compare.
    assert_eq!(prog[5].k, 42);
    assert_eq!(prog[5].jt, 1);
    assert_eq!(prog[5].jf, 0);
    // Last compare: match lands on notif; miss skips notif to ALLOW.
    assert_eq!(prog[6].k, 43);
    assert_eq!(prog[6].jt, 0);
    assert_eq!(prog[6].jf, 1);
}

/// Real kernel round-trip: install the connect filter in a forked
/// child, hand the listener over, answer the connect notification
/// with CONTINUE. Skips gracefully where the kernel lacks support.
#[test]
fn live_notification_round_trip() {
    if check_support().is_err() {
        return;
    }
    let mut pair = [0 as RawFd; 2];
    assert_eq!(
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe {
            libc::socketpair(
                libc::AF_UNIX,
                libc::SOCK_DGRAM | libc::SOCK_CLOEXEC,
                0,
                pair.as_mut_ptr(),
            )
        },
        0
    );
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0);
    if pid == 0 {
        // Filter install needs no_new_privs (or CAP_SYS_ADMIN) —
        // report an nnp refusal identifiably rather than letting
        // install_listener fail opaquely.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
            // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
            unsafe {
                libc::send(pair[0], &b'N' as *const u8 as *const libc::c_void, 1, 0);
                libc::_exit(0);
            }
        }
        let program = notify_program(&[CONNECT_NR]).unwrap();
        let listener = install_listener(&program).expect("install");
        send_listener(pair[0], listener).expect("handoff");
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe { libc::close(listener) };
        // Trigger: connect to the discard port on loopback.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        let s = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
        assert!(s >= 0);
        let mut sa = [0u8; 16];
        sa[0..2].copy_from_slice(&(libc::AF_INET as u16).to_ne_bytes());
        sa[2..4].copy_from_slice(&9u16.to_be_bytes());
        sa[4..8].copy_from_slice(&[127, 0, 0, 1]);
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        let rc = unsafe { libc::connect(s, sa.as_ptr().cast(), 16) };
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        let errno = unsafe { *libc::__errno_location() };
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe { libc::close(s) };
        // connect ran (refused is expected) — ENOSYS would mean the
        // notification killed it.
        let byte = if rc < 0 && errno == libc::ENOSYS {
            b'C'
        } else {
            b'R'
        };
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe {
            libc::send(pair[0], &byte as *const u8 as *const libc::c_void, 1, 0);
            libc::_exit(0);
        }
    }
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    unsafe { libc::close(pair[0]) };
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    let sock = unsafe { File::from_raw_fd(pair[1]) };
    let listener = (UnotifyParent {
        sock: sock.try_clone().unwrap(),
    })
    .recv_listener()
    .expect("listener fd");
    let notif = loop {
        match notify_recv(listener.as_raw_fd()) {
            Ok(n) => break n,
            Err(e) if e.raw_os_error() == Some(libc::EINTR) => continue,
            Err(e) => panic!("NOTIF_RECV failed: {e}"),
        }
    };
    assert_eq!(notif.data.nr, CONNECT_NR as i32);
    assert_eq!(notif.pid, pid as u32);
    // The child's sockaddr — decode proves the memory-read path.
    let target = inspect_sockaddr(notif.pid, notif.data.args[1], notif.data.args[2]);
    match target {
        SockTarget::Inet { dest, port, .. } => {
            assert_eq!(dest, "127.0.0.1".parse::<IpAddr>().unwrap());
            assert_eq!(port, 9);
        }
        other => panic!("sockaddr decode failed: {other:?}"),
    }
    let resp = notif_resp_continue(notif.id);
    notify_send(listener.as_raw_fd(), &resp).expect("CONTINUE send");
    let mut byte = [0u8; 1];
    assert_eq!(
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe { libc::recv(sock.as_raw_fd(), byte.as_mut_ptr().cast(), 1, 0) },
        1
    );
    assert_eq!(byte[0], b'R');
    let mut status = 0;
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    unsafe { libc::waitpid(pid, &mut status, 0) };
}

/// A denied notification delivers an error to the child's
/// connect — the "actually refused" half of the contract.
#[test]
fn denied_connect_gets_eacces() {
    if check_support().is_err() {
        return;
    }
    let mut pair = [0 as RawFd; 2];
    assert_eq!(
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe {
            libc::socketpair(
                libc::AF_UNIX,
                libc::SOCK_DGRAM | libc::SOCK_CLOEXEC,
                0,
                pair.as_mut_ptr(),
            )
        },
        0
    );
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0);
    if pid == 0 {
        // Same nnp precondition as the round-trip child — report a
        // refusal identifiably instead of an opaque install error.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
            // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
            unsafe {
                libc::send(pair[0], &b'N' as *const u8 as *const libc::c_void, 1, 0);
                libc::_exit(0);
            }
        }
        let program = notify_program(&[CONNECT_NR]).unwrap();
        let listener = install_listener(&program).expect("install");
        send_listener(pair[0], listener).expect("handoff");
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe { libc::close(listener) };
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        let s = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
        assert!(s >= 0);
        let mut sa = [0u8; 16];
        sa[0..2].copy_from_slice(&(libc::AF_INET as u16).to_ne_bytes());
        sa[2..4].copy_from_slice(&9u16.to_be_bytes());
        sa[4..8].copy_from_slice(&[127, 0, 0, 1]);
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        let rc = unsafe { libc::connect(s, sa.as_ptr().cast(), 16) };
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        let errno = unsafe { *libc::__errno_location() };
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe { libc::close(s) };
        let byte = if rc < 0 && errno == libc::EACCES {
            b'D' // denied as designed
        } else {
            b'X'
        };
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe {
            libc::send(pair[0], &byte as *const u8 as *const libc::c_void, 1, 0);
            libc::_exit(0);
        }
    }
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    unsafe { libc::close(pair[0]) };
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    let sock = unsafe { File::from_raw_fd(pair[1]) };
    let listener = (UnotifyParent {
        sock: sock.try_clone().unwrap(),
    })
    .recv_listener()
    .expect("listener fd");
    let notif = loop {
        match notify_recv(listener.as_raw_fd()) {
            Ok(n) => break n,
            Err(e) if e.raw_os_error() == Some(libc::EINTR) => continue,
            Err(e) => panic!("NOTIF_RECV failed: {e}"),
        }
    };
    notify_send(
        listener.as_raw_fd(),
        &notif_resp_error(notif.id, libc::EACCES),
    )
    .expect("deny send");
    let mut byte = [0u8; 1];
    assert_eq!(
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe { libc::recv(sock.as_raw_fd(), byte.as_mut_ptr().cast(), 1, 0) },
        1
    );
    assert_eq!(byte[0], b'D');
    let mut status = 0;
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    unsafe { libc::waitpid(pid, &mut status, 0) };
}

/// Emulated connect, happy path under a live rewrite: the child's
/// connect reads its sockaddr from a MAP_SHARED page; once the
/// notification arrives, a co-process rewrites the page to a different
/// (refused) destination before the supervisor answers. Emulation
/// replays the *pinned* bytes the verdict inspected, so the child's
/// socket still lands on the original listener — under a
/// answer the kernel would instead consume the rewritten sockaddr and
/// this connect would fail with ECONNREFUSED.
///
/// Retried as a whole scenario, not per-assertion: a `NOTIF_SEND`
/// `ENOENT` means the kernel discarded the notification (the parked
/// task died under it — a race the supervisor itself treats as benign),
/// which cannot be undone by answering again. The assertion being
/// verified is identical every attempt.
#[test]
fn emulated_connect_uses_pinned_sockaddr() {
    if check_support().is_err() {
        return;
    }
    for attempt in 0..3 {
        if emulated_connect_attempt() {
            return;
        }
        assert!(attempt + 1 < 3, "pinned-sockaddr scenario raced 3 times");
    }
}

/// One full fork/notif/emulate cycle; `true` on success, `false` when
/// the notified task died mid-window (unreadable sockaddr, emulation
/// setup failure, `ENOENT` on `NOTIF_SEND`, or the child never
/// answering) — safe to retry after the child is reaped. Real
/// assertion failures still panic; a deterministic bug fails all
/// retries identically.
fn emulated_connect_attempt() -> bool {
    // Loopback listener: the pinned sockaddr's destination.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    let srv = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
    assert!(srv >= 0);
    let mut sa = [0u8; 16];
    sa[0..2].copy_from_slice(&(libc::AF_INET as u16).to_ne_bytes());
    sa[4..8].copy_from_slice(&[127, 0, 0, 1]);
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    assert_eq!(unsafe { libc::bind(srv, sa.as_ptr().cast(), 16) }, 0);
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    assert_eq!(unsafe { libc::listen(srv, 4) }, 0);
    let mut got_len: libc::socklen_t = 16;
    assert_eq!(
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe { libc::getsockname(srv, sa.as_mut_ptr().cast(), &mut got_len) },
        0
    );
    let srv_port = u16::from_be_bytes([sa[2], sa[3]]);
    assert_ne!(srv_port, 0);

    // Shared page the child's connect() reads its sockaddr from; the
    // rewriter process flips it mid-notification.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    let page = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            4096,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    assert_ne!(page, libc::MAP_FAILED);
    let page = page.cast::<u8>();
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    let write_sa = |port: u16| unsafe {
        std::ptr::write_bytes(page, 0, 16);
        std::ptr::copy_nonoverlapping((libc::AF_INET as u16).to_ne_bytes().as_ptr(), page, 2);
        std::ptr::copy_nonoverlapping(port.to_be_bytes().as_ptr(), page.add(2), 2);
        std::ptr::copy_nonoverlapping([127u8, 0, 0, 1].as_ptr(), page.add(4), 4);
    };
    write_sa(srv_port);

    let mut res = [0 as RawFd; 2];
    let mut trig = [0 as RawFd; 2];
    for pair in [&mut res, &mut trig] {
        assert_eq!(
            // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
            unsafe {
                libc::socketpair(
                    libc::AF_UNIX,
                    libc::SOCK_DGRAM | libc::SOCK_CLOEXEC,
                    0,
                    pair.as_mut_ptr(),
                )
            },
            0
        );
    }
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0);
    if pid == 0 {
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe { libc::close(res[1]) };
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe { libc::close(trig[1]) };
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
            // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
            unsafe {
                libc::send(res[0], &b'N' as *const u8 as *const libc::c_void, 1, 0);
                libc::_exit(0);
            }
        }
        let program = notify_program(&[CONNECT_NR]).unwrap();
        let listener = install_listener(&program).expect("install");
        send_listener(res[0], listener).expect("handoff");
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe { libc::close(listener) };
        // Rewriter: waits for the supervisor's trigger, then flips the
        // shared sockaddr to 127.0.0.1:1 (guaranteed refused) — the
        // window a CONTINUE answer would expose.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        let rw = unsafe { libc::fork() };
        assert!(rw >= 0);
        if rw == 0 {
            let mut b = [0u8; 1];
            // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
            unsafe { libc::recv(trig[0], b.as_mut_ptr().cast(), 1, 0) };
            write_sa(1);
            // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
            unsafe { libc::_exit(0) };
        }
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe { libc::close(trig[0]) };
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        let s = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
        assert!(s >= 0);
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        let rc = unsafe { libc::connect(s, page.cast::<libc::sockaddr>(), 16) };
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        let errno = unsafe { *libc::__errno_location() };
        let byte = if rc == 0 {
            b'S'
        } else {
            errno.to_le_bytes()[0]
        };
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe {
            libc::send(res[0], &byte as *const u8 as *const libc::c_void, 1, 0);
            libc::_exit(0);
        }
    }
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    unsafe { libc::close(res[0]) };
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    unsafe { libc::close(trig[0]) };
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    let sock = unsafe { File::from_raw_fd(res[1]) };
    let listener = (UnotifyParent {
        sock: sock.try_clone().unwrap(),
    })
    .recv_listener()
    .expect("listener fd");
    let notif = loop {
        match notify_recv(listener.as_raw_fd()) {
            Ok(n) => break n,
            Err(e) if e.raw_os_error() == Some(libc::EINTR) => continue,
            Err(e) => panic!("NOTIF_RECV failed: {e}"),
        }
    };
    assert_eq!(notif.data.nr, CONNECT_NR as i32);
    // Tear down an attempt whose child is presumed dead (or parked on
    // a notification the kernel already discarded): wake the rewriter
    // grandchild off its `recv(trig[0])` first — an early-failed
    // attempt never sent the 'X' trigger, and `close(trig[1])` alone
    // only reaches it via EOF — then kill any survivor, reap it, and
    // release this attempt's resources. The `sock` and `listener`
    // Files close on scope exit.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    let reap = |pid: libc::pid_t| unsafe {
        let _ = libc::send(trig[1], &b'X' as *const u8 as *const libc::c_void, 1, 0);
        libc::kill(pid, libc::SIGKILL);
        let mut status = 0;
        libc::waitpid(pid, &mut status, 0);
        libc::close(srv);
        libc::close(trig[1]);
        libc::munmap(page.cast(), 4096);
    };
    let raw = match inspect_sockaddr(notif.pid, notif.data.args[1], notif.data.args[2]) {
        SockTarget::Inet { dest, port, raw } => {
            assert_eq!(dest, "127.0.0.1".parse::<IpAddr>().unwrap());
            assert_eq!(port, srv_port);
            raw
        }
        // The read only fails on a dead task — a machinery race, not a
        // decode verdict.
        SockTarget::Unreadable { .. } => {
            reap(pid);
            return false;
        }
        other => panic!("sockaddr decode failed: {other:?}"),
    };
    // Let the rewriter clobber the child's buffer *after* inspection.
    assert_eq!(
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe { libc::send(trig[1], &b'X' as *const u8 as *const libc::c_void, 1, 0) },
        1
    );
    std::thread::sleep(std::time::Duration::from_millis(100));
    // Emulate: dup the child's socket, connect on the pinned bytes. A
    // dead child fails the pidfd dup — the same death race.
    let errno = match emulate_connect(notif.pid, notif.data.args[0], &raw) {
        Ok(e) => e,
        Err(_) => {
            reap(pid);
            return false;
        }
    };
    assert_eq!(errno, 0, "emulated connect to the loopback listener");
    match notify_send(listener.as_raw_fd(), &notif_resp_result(notif.id, 0)) {
        Ok(()) => {}
        // ENOENT: the kernel discarded the notification — the parked
        // task died under it (or was reaped by an outside force) before
        // the response landed. Kill in case it somehow still waits,
        // reap, and let the caller re-run the whole scenario.
        Err(e) if e.raw_os_error() == Some(libc::ENOENT) => {
            reap(pid);
            return false;
        }
        Err(e) => panic!("result send: {e}"),
    }
    let mut byte = [0u8; 1];
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    if unsafe { libc::recv(sock.as_raw_fd(), byte.as_mut_ptr().cast(), 1, 0) } != 1 {
        reap(pid);
        return false;
    }
    // The connect succeeded — on the *original* sockaddr despite the
    // rewrite (CONTINUE would have returned ECONNREFUSED here).
    assert_eq!(byte[0], b'S');
    let mut status = 0;
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    unsafe { libc::waitpid(pid, &mut status, 0) };
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    unsafe { libc::close(srv) };
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    unsafe { libc::close(trig[1]) };
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    unsafe { libc::munmap(page.cast(), 4096) };
    true
}

/// An emulated connect that the kernel refuses returns the real errno
/// to the child — the emulation propagates, not hides, the result.
#[test]
fn emulated_connect_propagates_errno() {
    if check_support().is_err() {
        return;
    }
    let mut pair = [0 as RawFd; 2];
    assert_eq!(
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe {
            libc::socketpair(
                libc::AF_UNIX,
                libc::SOCK_DGRAM | libc::SOCK_CLOEXEC,
                0,
                pair.as_mut_ptr(),
            )
        },
        0
    );
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0);
    if pid == 0 {
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
            // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
            unsafe {
                libc::send(pair[0], &b'N' as *const u8 as *const libc::c_void, 1, 0);
                libc::_exit(0);
            }
        }
        let program = notify_program(&[CONNECT_NR]).unwrap();
        let listener = install_listener(&program).expect("install");
        send_listener(pair[0], listener).expect("handoff");
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe { libc::close(listener) };
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        let s = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
        assert!(s >= 0);
        // 127.0.0.1:1 — nothing listens; ECONNREFUSED.
        let mut sa = [0u8; 16];
        sa[0..2].copy_from_slice(&(libc::AF_INET as u16).to_ne_bytes());
        sa[2..4].copy_from_slice(&1u16.to_be_bytes());
        sa[4..8].copy_from_slice(&[127, 0, 0, 1]);
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        let rc = unsafe { libc::connect(s, sa.as_ptr().cast(), 16) };
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        let errno = unsafe { *libc::__errno_location() };
        let byte = if rc < 0 && errno == libc::ECONNREFUSED {
            b'R'
        } else {
            b'X'
        };
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe {
            libc::send(pair[0], &byte as *const u8 as *const libc::c_void, 1, 0);
            libc::_exit(0);
        }
    }
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    unsafe { libc::close(pair[0]) };
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    let sock = unsafe { File::from_raw_fd(pair[1]) };
    let listener = (UnotifyParent {
        sock: sock.try_clone().unwrap(),
    })
    .recv_listener()
    .expect("listener fd");
    let notif = loop {
        match notify_recv(listener.as_raw_fd()) {
            Ok(n) => break n,
            Err(e) if e.raw_os_error() == Some(libc::EINTR) => continue,
            Err(e) => panic!("NOTIF_RECV failed: {e}"),
        }
    };
    let target = inspect_sockaddr(notif.pid, notif.data.args[1], notif.data.args[2]);
    let raw = match target {
        SockTarget::Inet { raw, .. } => raw,
        other => panic!("sockaddr decode failed: {other:?}"),
    };
    let errno = emulate_connect(notif.pid, notif.data.args[0], &raw).expect("emulate dup");
    assert_eq!(errno, libc::ECONNREFUSED);
    notify_send(listener.as_raw_fd(), &notif_resp_error(notif.id, errno)).expect("errno send");
    let mut byte = [0u8; 1];
    assert_eq!(
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe { libc::recv(sock.as_raw_fd(), byte.as_mut_ptr().cast(), 1, 0) },
        1
    );
    assert_eq!(byte[0], b'R');
    let mut status = 0;
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    unsafe { libc::waitpid(pid, &mut status, 0) };
}
