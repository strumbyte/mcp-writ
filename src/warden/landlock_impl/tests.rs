use super::*;

// -- landlock_base_path ---------------------------------------------------

#[test]
fn test_landlock_base_path_strips_recursive_glob() {
    assert_eq!(landlock_base_path("/usr/lib/**"), Some("/usr/lib"));
    assert_eq!(landlock_base_path("/workspace/**"), Some("/workspace"));
}

#[test]
fn test_landlock_base_path_strips_single_star() {
    assert_eq!(landlock_base_path("/tmp/*"), Some("/tmp"));
}

#[test]
fn test_landlock_base_path_plain_directory() {
    assert_eq!(landlock_base_path("/usr/bin"), Some("/usr/bin"));
}

#[test]
fn test_landlock_base_path_rejects_mid_glob() {
    assert_eq!(landlock_base_path("/home/*/.ssh/**"), None);
    assert_eq!(landlock_base_path(""), None);
}

// -- collect_allowed_ports -------------------------------------------------

/// Shim for the pre-schema port-collection tests: the policy a set
/// of `host=` spellings produces (trimmed, unnormalized — only the
/// bare-port form is read back as a port rule) then the netport
/// rule set derived from it. [`OutboundPolicy::tcp_port_rules`]
/// sorts and deduplicates, so assertions below expect canonical
/// order.
fn collect_allowed_ports(allowed: &[String]) -> Vec<u16> {
    let policy = crate::policy::OutboundPolicy {
        allowed: allowed.iter().map(|s| s.trim().to_string()).collect(),
        ..Default::default()
    };
    policy.tcp_port_rules()
}

#[test]
fn test_collect_bare_ports() {
    let allowed = vec!["80".to_string(), "443".to_string(), "8080".to_string()];
    let ports = collect_allowed_ports(&allowed);
    assert_eq!(ports, vec![80, 443, 8080]);
}

#[test]
fn test_collect_https_url() {
    let allowed = vec!["https://api.example.com".to_string()];
    let ports = collect_allowed_ports(&allowed);
    assert!(ports.is_empty());
}

#[test]
fn test_collect_http_url() {
    let allowed = vec!["http://example.com".to_string()];
    let ports = collect_allowed_ports(&allowed);
    assert!(ports.is_empty());
}

#[test]
fn test_collect_url_with_explicit_port() {
    let allowed = vec!["https://api.example.com:8443".to_string()];
    let ports = collect_allowed_ports(&allowed);
    assert!(ports.is_empty());
}

#[test]
fn test_collect_http_url_with_explicit_port() {
    let allowed = vec!["http://example.com:3000".to_string()];
    let ports = collect_allowed_ports(&allowed);
    assert!(ports.is_empty());
}

#[test]
fn test_collect_bare_hostname() {
    let allowed = vec!["api.openai.com".to_string()];
    let ports = collect_allowed_ports(&allowed);
    assert!(ports.is_empty());
}

#[test]
fn test_collect_bare_hostname_with_port() {
    let allowed = vec!["api.example.com:9090".to_string()];
    let ports = collect_allowed_ports(&allowed);
    assert!(ports.is_empty());
}

#[test]
fn test_collect_localhost() {
    let allowed = vec!["localhost".to_string()];
    let ports = collect_allowed_ports(&allowed);
    assert!(ports.is_empty());
}

#[test]
fn test_collect_mixed_inputs() {
    let allowed = vec![
        "443".to_string(),
        "https://api.openai.com".to_string(),
        "http://example.com".to_string(),
        "https://api.anthropic.com:8443".to_string(),
        "cdn.example.com".to_string(),
    ];
    let ports = collect_allowed_ports(&allowed);
    assert_eq!(ports, vec![443]);
}

#[test]
fn test_collect_ports_skips_invalid() {
    let allowed = vec![
        "443".to_string(),
        "not_a_port".to_string(), // no dots, not a number → skipped
        "99999".to_string(),      // > u16::MAX, no dots → skipped
        "80".to_string(),
    ];
    let ports = collect_allowed_ports(&allowed);
    assert_eq!(ports, vec![80, 443]);
}

#[test]
fn test_collect_ports_empty() {
    let allowed: Vec<String> = vec![];
    let ports = collect_allowed_ports(&allowed);
    assert!(ports.is_empty());
}

#[test]
fn test_collect_ports_boundary_values() {
    let allowed = vec!["0".to_string(), "65535".to_string(), "65536".to_string()];
    let ports = collect_allowed_ports(&allowed);
    // Port 0 is not a valid connect target (skipped), 65536 exceeds u16::MAX (skipped)
    assert_eq!(ports, vec![65535]);
}

#[test]
fn test_collect_ports_negative() {
    let allowed = vec!["-1".to_string(), "443".to_string()];
    let ports = collect_allowed_ports(&allowed);
    assert_eq!(ports, vec![443]); // negative is invalid for u16
}

#[test]
fn test_collect_url_with_path() {
    let allowed = vec!["https://api.example.com/v1/chat".to_string()];
    let ports = collect_allowed_ports(&allowed);
    assert!(ports.is_empty());
}

#[test]
fn test_collect_deduplicates() {
    let allowed = vec![
        "443".to_string(),
        "https://api.example.com".to_string(),
        "443".to_string(),
    ];
    let ports = collect_allowed_ports(&allowed);
    assert_eq!(ports, vec![443]);
}

#[test]
fn test_collect_localhost_with_port() {
    let allowed = vec!["localhost:8080".to_string()];
    let ports = collect_allowed_ports(&allowed);
    assert!(ports.is_empty());
}

#[test]
fn test_collect_empty_string_entry() {
    let allowed = vec!["".to_string(), "443".to_string()];
    let ports = collect_allowed_ports(&allowed);
    assert_eq!(ports, vec![443]);
}

#[test]
fn test_collect_whitespace_port() {
    let allowed = vec![" 443 ".to_string()];
    let ports = collect_allowed_ports(&allowed);
    assert_eq!(ports, vec![443]);
}

// -- namespaced_netport_plan -------------------------------------------------

use crate::policy::{EgressDest, EgressProto, EgressRule};

fn allow_rule(dest: &str, proto: EgressProto, port: Option<u16>) -> EgressRule {
    EgressRule {
        allow: true,
        dest: EgressDest::Host(dest.to_string()),
        proto,
        port,
    }
}

/// Regression: a bare `allow host="*"` flips the posture open but
/// is NOT an `egress_rules` entry — the port collection sees an
/// empty set, which must not become a handled deny-all.
#[test]
fn test_namespaced_netport_plan_open_posture_delegates() {
    let out = crate::policy::OutboundPolicy {
        deny_all_others: false,
        ..Default::default()
    };
    assert_eq!(namespaced_netport_plan(&out), None);
}

/// Open posture stays delegated even beside port-qualified
/// (non-TCP) rules — the TCP surface is still "any port".
#[test]
fn test_namespaced_netport_plan_open_posture_with_udp_rules() {
    let out = crate::policy::OutboundPolicy {
        deny_all_others: false,
        egress_rules: vec![allow_rule("*", EgressProto::Udp, Some(53))],
        ..Default::default()
    };
    assert_eq!(namespaced_netport_plan(&out), None);
}

/// Deny-all posture with every TCP allow port-qualified → the
/// union of their ports is the netport set.
#[test]
fn test_namespaced_netport_plan_collects_qualified_ports() {
    let out = crate::policy::OutboundPolicy {
        deny_all_others: true,
        egress_rules: vec![
            allow_rule("1.1.1.1", EgressProto::Tcp, Some(443)),
            allow_rule("example.com", EgressProto::Tcp, Some(8443)),
            allow_rule("9.9.9.9", EgressProto::Udp, Some(53)),
            allow_rule("*", EgressProto::Tcp, Some(80)),
        ],
        ..Default::default()
    };
    assert_eq!(namespaced_netport_plan(&out), Some(vec![80, 443, 8443]));
}

/// Any TCP-covering allow without a port cannot be expressed —
/// the whole handling delegates to the proxy.
#[test]
fn test_namespaced_netport_plan_unqualified_tcp_allow_delegates() {
    let out = crate::policy::OutboundPolicy {
        deny_all_others: true,
        egress_rules: vec![
            allow_rule("1.1.1.1", EgressProto::Tcp, Some(443)),
            allow_rule("example.com", EgressProto::Tcp, None),
        ],
        ..Default::default()
    };
    assert_eq!(namespaced_netport_plan(&out), None);
}

/// `proto="any"` covers TCP — an unport'd any-rule is unqualified
/// for this purpose too.
#[test]
fn test_namespaced_netport_plan_any_proto_without_port_delegates() {
    let out = crate::policy::OutboundPolicy {
        deny_all_others: true,
        egress_rules: vec![allow_rule("1.1.1.1", EgressProto::Any, None)],
        ..Default::default()
    };
    assert_eq!(namespaced_netport_plan(&out), None);
}

/// Deny-all posture with no TCP-covering allows at all → `Some([])`
/// keeps `ConnectTcp` handled so every connect is refused — the
/// kernel mirrors the posture as defense-in-depth.
#[test]
fn test_namespaced_netport_plan_deny_all_no_tcp_is_empty_some() {
    let out = crate::policy::OutboundPolicy {
        deny_all_others: true,
        egress_rules: vec![allow_rule("9.9.9.9", EgressProto::Udp, Some(53))],
        ..Default::default()
    };
    assert_eq!(namespaced_netport_plan(&out), Some(vec![]));
}

/// A programmatically built policy (`egress_rules` field empty)
/// derives the same plan through the flat lists: a bare-port
/// `allowed` entry is the pre-schema spelling of the port-only
/// rule; a bare hostname is an unqualified TCP allow → delegate.
#[test]
fn test_namespaced_netport_plan_derived_flat_rules() {
    let qualified = crate::policy::OutboundPolicy {
        deny_all_others: true,
        allowed: vec!["443".to_string(), "80".to_string()],
        ..Default::default()
    };
    assert_eq!(namespaced_netport_plan(&qualified), Some(vec![80, 443]));
    let unqualified = crate::policy::OutboundPolicy {
        deny_all_others: true,
        allowed: vec!["443".to_string(), "api.example.com".to_string()],
        ..Default::default()
    };
    assert_eq!(namespaced_netport_plan(&unqualified), None);
}

// -- path_beneath file/dir access masking ----------------------------------
// A file rule carrying directory-only rights (e.g. ReadDir on /dev/null)
// makes the crate downgrade the ruleset to PartiallyEnforced, which the
// enforcement gate rejects with EACCES unless allow_degraded is set.
// These tests pin the predicate and the masked right set.

#[test]
fn test_fd_is_non_dir_detects_files_and_dirs() {
    assert!(fd_is_non_dir(&PathFd::new("/dev/null").unwrap()));
    assert!(!fd_is_non_dir(&PathFd::new("/").unwrap()));
}

#[test]
fn test_file_access_mask_drops_directory_only_rights() {
    let file_ok = AccessFs::from_file(ABI::V3);
    let read = AccessFs::from_read(ABI::V3);
    let rw = read | AccessFs::from_write(ABI::V3);
    assert!(file_ok.contains(AccessFs::ReadFile));
    assert!(file_ok.contains(AccessFs::WriteFile));
    assert!(file_ok.contains(AccessFs::Execute));
    assert!(file_ok.contains(AccessFs::Truncate));
    assert!(!file_ok.contains(AccessFs::ReadDir));
    assert!(!file_ok.contains(AccessFs::MakeReg));
    // A masked file rule still keeps the rights that matter for files.
    assert_eq!(read & file_ok, AccessFs::Execute | AccessFs::ReadFile);
    assert_eq!(
        rw & file_ok,
        AccessFs::Execute | AccessFs::ReadFile | AccessFs::WriteFile | AccessFs::Truncate
    );
}

// -- apply_landlock is not called in-process ------------------------------
// restrict_self() would lock down the cargo test binary (and parallel tests).
// These tests only verify that the policy used by apply_landlock is well-formed.

#[test]
fn test_network_policy_ports_are_collectable() {
    use crate::policy::{NetworkPolicy, OutboundPolicy, default_policy};

    let mut policy = default_policy();
    policy.network = NetworkPolicy {
        outbound: OutboundPolicy {
            // Pre-schema programmatic spelling of the port-only
            // rules — the derived `egress_rules` maps them to the
            // same `ConnectTcp` netport grants a parsed
            // `allow host="443"` produces.
            allowed: vec!["443".to_string(), "80".to_string()],
            allowed_port_qualified: vec![],
            allowed_cidrs: vec![],
            allowed_cidrs_port_qualified: vec![],
            denied_hosts: vec![],
            denied_cidrs: vec![],
            deny_all_others: true,
            egress_rules: vec![],
        },
        inbound: Default::default(),
    };

    assert_eq!(policy.network.outbound.tcp_port_rules(), vec![80, 443]);
}

#[test]
fn test_empty_network_policy_collects_no_ports() {
    use crate::policy::default_policy;

    let policy = default_policy();
    assert!(policy.network.outbound.tcp_port_rules().is_empty());
}

// -- per-route net handle set ----------------------------------------

/// PR-10: the ebpf route claims `BindTcp` alone — `ConnectTcp`
/// must stay *unhandled* so a denied connect reaches the cgroup
/// hook (the deny event would never be emitted if Landlock
/// short-circuited it first); `BindTcp` handled-with-no-rules
/// keeps the all-bind-denied contract the other routes enforce.
#[test]
fn test_ebpf_net_handle_set_is_bind_only() {
    let set = net_handle_set(NetMode::Ebpf, None);
    assert!(set.contains(AccessNet::BindTcp));
    assert!(!set.contains(AccessNet::ConnectTcp));
    assert_eq!(set, BitFlags::from(AccessNet::BindTcp));
}

/// The default and exactly-expressible namespaced routes claim
/// the full V4 net set; an inexpressible namespaced plan claims
/// nothing (the TUN proxy owns connect decisions).
#[test]
fn test_net_handle_set_default_and_namespaced() {
    assert_eq!(
        net_handle_set(NetMode::Default, None),
        AccessNet::from_all(ABI::V4)
    );
    let ports = vec![443u16];
    assert_eq!(
        net_handle_set(NetMode::Namespaced, Some(&ports)),
        AccessNet::from_all(ABI::V4)
    );
    assert_eq!(net_handle_set(NetMode::Namespaced, None), BitFlags::EMPTY);
}

// -- F85/F86/F87: grant identity and deny coverage -----------------

#[test]
fn test_partial_star_is_literal_not_prefix() {
    // F87: `/a/foo*` names the literal entry `foo*` — it must not
    // reduce to a base directory the Auditor never authorized.
    assert_eq!(landlock_base_path("/a/foo*"), None);
    assert_eq!(landlock_base_path("/a/foo*bar"), None);
    assert_eq!(landlock_base_path("/a/*"), Some("/a"));
    assert_eq!(landlock_base_path("/a/**"), Some("/a"));
}

#[test]
fn test_deny_covers_descendant_allow() {
    // F86: a parent deny suppresses a descendant allow — the
    // additive ruleset has no negative rule to carve it out.
    let denies = ["/srv".to_string()];
    assert!(deny_covers_grant(denies.iter(), "/srv/child"));
    assert!(deny_covers_grant(denies.iter(), "/srv"));
    assert!(!deny_covers_grant(denies.iter(), "/other"));
    // Literal-star spellings do not prefix-cover a sibling path.
    let denies = ["/srv/foo*".to_string()];
    assert!(!deny_covers_grant(denies.iter(), "/srv/foo"));
}

#[test]
#[cfg(unix)]
fn test_open_landlock_path_binds_resolved_object() {
    // F85: a spelling through a symlink binds the resolved object
    // the Auditor would authorize, not the mutable name.
    let dir = std::env::temp_dir().join(format!("llbind-{}", std::process::id()));
    let real = dir.join("real");
    std::fs::create_dir_all(&real).unwrap();
    let link = dir.join("link");
    std::os::unix::fs::symlink(&real, &link).unwrap();
    let (_fd, resolved) = open_landlock_path(&link.to_string_lossy()).unwrap();
    assert_eq!(resolved, real.canonicalize().unwrap());
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
#[cfg(unix)]
fn test_deny_of_target_suppresses_symlinked_allow() {
    // F85+F86: deny the real tree, allow the alias — the resolved
    // coverage check suppresses the grant anyway.
    let dir = std::env::temp_dir().join(format!("llcov-{}", std::process::id()));
    let real = dir.join("real");
    std::fs::create_dir_all(&real).unwrap();
    let link = dir.join("link");
    std::os::unix::fs::symlink(&real, &link).unwrap();
    let denies = [real.to_string_lossy().to_string()];
    assert!(deny_covers_grant(
        denies.iter(),
        &format!("{}/inside", link.display())
    ));
    std::fs::remove_dir_all(&dir).ok();
}

// -- PR-18 (D-2): `allow unix=` opt-ins ---------------------------------

/// `unix="*"` supersedes a path-bound opt-in declared beside it: the
/// family is opened without handling `ResolveUnix`, so the path rule
/// must be recorded as superseded — never added (an `UnhandledAccess`
/// failure) — on any kernel ABI.
#[test]
#[cfg(unix)]
fn test_unix_star_supersedes_path_optin() {
    let mut policy = crate::policy::Policy::default();
    policy.network.outbound.deny_all_others = true;
    policy.network.outbound.egress_rules = vec![
        crate::policy::EgressRule {
            allow: true,
            dest: crate::policy::EgressDest::Unix("*".to_string()),
            proto: crate::policy::EgressProto::Tcp,
            port: None,
        },
        crate::policy::EgressRule {
            allow: true,
            dest: crate::policy::EgressDest::Unix("/nonexistent-mcp-writ-dir/sock".to_string()),
            proto: crate::policy::EgressProto::Tcp,
            port: None,
        },
    ];
    let build = create_landlock_ruleset(&policy)
        .expect("a '*' opt-in must supersede a path opt-in, not fail the build");
    let star = build
        .grants
        .iter()
        .find(|g| matches!(&g.subject, GrantSubject::Rule { name, .. } if name == "unix=*"))
        .expect("grant record for unix=*");
    assert_eq!(star.state, ControlState::Planned);
    let path = build
        .grants
        .iter()
        .find(|g| matches!(&g.subject, GrantSubject::Rule { name, .. } if name == "unix=/nonexistent-mcp-writ-dir/sock"))
        .expect("grant record for the path opt-in");
    assert_eq!(path.state, ControlState::Skipped);
    assert!(
        path.reason.as_deref().unwrap_or("").contains("superseded"),
        "the superseded opt-in must say so: {:?}",
        path.reason
    );
}

/// A non-superseded path opt-in still hard-refuses on kernels without
/// `ResolveUnix` (ABI v9); on v9+ the unresolvable parent degrades to a
/// skipped grant rather than an error.
#[test]
#[cfg(unix)]
fn test_unix_path_optin_abi_floor() {
    let mut policy = crate::policy::Policy::default();
    policy.network.outbound.deny_all_others = true;
    policy.network.outbound.egress_rules = vec![crate::policy::EgressRule {
        allow: true,
        dest: crate::policy::EgressDest::Unix("/nonexistent-mcp-writ-dir/sock".to_string()),
        proto: crate::policy::EgressProto::Tcp,
        port: None,
    }];
    let res = create_landlock_ruleset(&policy);
    if kernel_abi() < 9 {
        assert!(
            res.is_err(),
            "a path opt-in must refuse when the kernel predates ABI v9"
        );
    } else {
        let build = res.expect("v9 kernels build the ruleset");
        let grant = build
            .grants
            .iter()
            .find(|g| matches!(&g.subject, GrantSubject::Rule { name, .. } if name == "unix=/nonexistent-mcp-writ-dir/sock"))
            .expect("grant record for the path opt-in");
        assert_eq!(grant.state, ControlState::Skipped);
    }
}

#[test]
#[cfg(unix)]
fn test_ruleset_skips_deny_covered_allow() {
    // F86 end-to-end: the grant record reports the covered allow as
    // Skipped rather than installing a PathBeneath rule.
    let dir = std::env::temp_dir().join(format!("lldeny-{}", std::process::id()));
    let denied = dir.join("deny_root");
    let allow = denied.join("child");
    std::fs::create_dir_all(&allow).unwrap();
    let mut policy = crate::policy::Policy::default();
    policy
        .fs
        .read_only
        .push(allow.to_string_lossy().to_string());
    policy
        .fs
        .denied_paths
        .push(denied.to_string_lossy().to_string());
    let build = create_landlock_ruleset(&policy).unwrap();
    let grant = build
        .grants
        .iter()
        .find(
            |g| matches!(&g.subject, GrantSubject::FsPath { path, .. } if path.ends_with("child")),
        )
        .expect("grant record for the covered allow");
    assert_eq!(grant.state, ControlState::Skipped);
    std::fs::remove_dir_all(&dir).ok();
}
