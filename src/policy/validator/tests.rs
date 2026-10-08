use super::*;
use crate::policy::{FsToolPolicy, InputResponsesMode, ToolPolicy, TransportType, default_policy};

#[test]
fn test_valid_default_policy_passes() {
    let policy = default_policy();
    assert!(validate_policy(&policy).is_ok());
}

// --- version ---

#[test]
fn test_unsupported_version() {
    let mut policy = default_policy();
    policy.version = 99;
    let err = validate_policy(&policy).unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("unsupported policy version 99"));
    assert!(msg.contains("expected 1"));
}

#[test]
fn test_version_zero_rejected() {
    let mut policy = default_policy();
    policy.version = 0;
    assert!(validate_policy(&policy).is_err());
}

#[test]
fn test_version_two_accepted() {
    let mut policy = default_policy();
    policy.version = 2;
    validate_policy(&policy).expect("v2 is a supported schema");
}

#[test]
fn test_version_three_rejected() {
    let mut policy = default_policy();
    policy.version = 3;
    let err = validate_policy(&policy).unwrap_err();
    assert!(err.to_string().contains("unsupported policy version 3"));
}

// --- required fields ---

#[test]
fn test_http_without_listen_addr() {
    let mut policy = default_policy();
    policy.transport.type_ = TransportType::Http;
    let err = validate_policy(&policy).unwrap_err();
    assert!(err.to_string().contains("listen_addr"));
}

#[test]
fn test_http_with_listen_addr_passes() {
    let mut policy = default_policy();
    policy.transport.type_ = TransportType::Http;
    policy.transport.listen_addr = Some("127.0.0.1:8080".to_string());
    assert!(validate_policy(&policy).is_ok());
}

#[test]
fn test_empty_tool_name() {
    let mut policy = default_policy();
    policy.tools.push(ToolPolicy {
        name: String::new(),
        allowed: true,
        args_schema: None,
        side_effect: None,
        server: None,
        fs: None,
        syscalls: None,
        network: None,
        input_responses: InputResponsesMode::Auto,
        input_responses_specified: false,
        fs_explicit: false,
        network_explicit: false,
        syscalls_explicit: false,
        environment_explicit: false,
        process_exec_allowed: false,
        process_explicit: false,
        deputy: None,
    });
    let err = validate_policy(&policy).unwrap_err();
    assert!(err.to_string().contains("empty 'name'"));
}

#[test]
fn test_whitespace_tool_name() {
    let mut policy = default_policy();
    policy.tools.push(ToolPolicy {
        name: "  ".to_string(),
        allowed: true,
        args_schema: None,
        side_effect: None,
        server: None,
        fs: None,
        syscalls: None,
        network: None,
        input_responses: InputResponsesMode::Auto,
        input_responses_specified: false,
        fs_explicit: false,
        network_explicit: false,
        syscalls_explicit: false,
        environment_explicit: false,
        process_exec_allowed: false,
        process_explicit: false,
        deputy: None,
    });
    let err = validate_policy(&policy).unwrap_err();
    assert!(err.to_string().contains("empty 'name'"));
}

// --- duplicate tools ---

#[test]
fn test_duplicate_tool_names() {
    let mut policy = default_policy();
    policy.tools.push(ToolPolicy {
        name: "read_file".to_string(),
        allowed: true,
        args_schema: None,
        side_effect: None,
        server: None,
        fs: None,
        syscalls: None,
        network: None,
        input_responses: InputResponsesMode::Auto,
        input_responses_specified: false,
        fs_explicit: false,
        network_explicit: false,
        syscalls_explicit: false,
        environment_explicit: false,
        process_exec_allowed: false,
        process_explicit: false,
        deputy: None,
    });
    policy.tools.push(ToolPolicy {
        name: "read_file".to_string(),
        allowed: false,
        args_schema: None,
        side_effect: None,
        server: None,
        fs: None,
        syscalls: None,
        network: None,
        input_responses: InputResponsesMode::Auto,
        input_responses_specified: false,
        fs_explicit: false,
        network_explicit: false,
        syscalls_explicit: false,
        environment_explicit: false,
        process_exec_allowed: false,
        process_explicit: false,
        deputy: None,
    });
    let err = validate_policy(&policy).unwrap_err();
    assert!(err.to_string().contains("duplicate tool name 'read_file'"));
}

#[test]
fn test_duplicate_tool_names_after_trimming() {
    let mut policy = default_policy();
    policy.tools.push(ToolPolicy {
        name: "read_file".to_string(),
        allowed: true,
        args_schema: None,
        side_effect: None,
        server: None,
        fs: None,
        syscalls: None,
        network: None,
        input_responses: InputResponsesMode::Auto,
        input_responses_specified: false,
        fs_explicit: false,
        network_explicit: false,
        syscalls_explicit: false,
        environment_explicit: false,
        process_exec_allowed: false,
        process_explicit: false,
        deputy: None,
    });
    policy.tools.push(ToolPolicy {
        name: " read_file ".to_string(),
        allowed: false,
        args_schema: None,
        side_effect: None,
        server: None,
        fs: None,
        syscalls: None,
        network: None,
        input_responses: InputResponsesMode::Auto,
        input_responses_specified: false,
        fs_explicit: false,
        network_explicit: false,
        syscalls_explicit: false,
        environment_explicit: false,
        process_exec_allowed: false,
        process_explicit: false,
        deputy: None,
    });
    let err = validate_policy(&policy).unwrap_err();
    assert!(err.to_string().contains("duplicate tool name 'read_file'"));
}

#[test]
fn test_unique_tool_names_pass() {
    let mut policy = default_policy();
    policy.tools.push(ToolPolicy {
        name: "read_file".to_string(),
        allowed: true,
        args_schema: None,
        side_effect: None,
        server: None,
        fs: None,
        syscalls: None,
        network: None,
        input_responses: InputResponsesMode::Auto,
        input_responses_specified: false,
        fs_explicit: false,
        network_explicit: false,
        syscalls_explicit: false,
        environment_explicit: false,
        process_exec_allowed: false,
        process_explicit: false,
        deputy: None,
    });
    policy.tools.push(ToolPolicy {
        name: "write_file".to_string(),
        allowed: true,
        args_schema: None,
        side_effect: None,
        server: None,
        fs: None,
        syscalls: None,
        network: None,
        input_responses: InputResponsesMode::Auto,
        input_responses_specified: false,
        fs_explicit: false,
        network_explicit: false,
        syscalls_explicit: false,
        environment_explicit: false,
        process_exec_allowed: false,
        process_explicit: false,
        deputy: None,
    });
    assert!(validate_policy(&policy).is_ok());
}

// --- paths ---

#[test]
fn test_empty_allowed_path_in_tool() {
    let mut policy = default_policy();
    policy.tools.push(ToolPolicy {
        name: "read_file".to_string(),
        allowed: true,
        args_schema: None,
        side_effect: None,
        server: None,
        fs: Some(FsToolPolicy::new(vec![String::new()], vec![])),
        syscalls: None,
        network: None,
        input_responses: InputResponsesMode::Auto,
        input_responses_specified: false,
        fs_explicit: false,
        network_explicit: false,
        syscalls_explicit: false,
        environment_explicit: false,
        process_exec_allowed: false,
        process_explicit: false,
        deputy: None,
    });
    let err = validate_policy(&policy).unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("empty 'allowed_paths'"));
    assert!(msg.contains("read_file"));
}

#[test]
fn test_whitespace_denied_path_in_tool() {
    let mut policy = default_policy();
    policy.tools.push(ToolPolicy {
        name: "write_file".to_string(),
        allowed: true,
        args_schema: None,
        side_effect: None,
        server: None,
        fs: Some(FsToolPolicy::new(
            vec!["/workspace/**".to_string()],
            vec!["  ".to_string()],
        )),
        syscalls: None,
        network: None,
        input_responses: InputResponsesMode::Auto,
        input_responses_specified: false,
        fs_explicit: false,
        network_explicit: false,
        syscalls_explicit: false,
        environment_explicit: false,
        process_exec_allowed: false,
        process_explicit: false,
        deputy: None,
    });
    let err = validate_policy(&policy).unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("empty 'denied_paths'"));
    assert!(msg.contains("write_file"));
}

#[test]
fn test_empty_global_read_only_path() {
    let mut policy = default_policy();
    policy.fs.read_only.push(String::new());
    let err = validate_policy(&policy).unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("fs.read_only"));
    assert!(msg.contains("empty path"));
}

#[test]
fn test_empty_global_read_write_path() {
    let mut policy = default_policy();
    policy.fs.read_write.push("  ".to_string());
    let err = validate_policy(&policy).unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("fs.read_write"));
    assert!(msg.contains("empty path"));
}

#[test]
fn test_valid_paths_pass() {
    let mut policy = default_policy();
    policy.tools.push(ToolPolicy {
        name: "read_file".to_string(),
        allowed: true,
        args_schema: None,
        side_effect: None,
        server: None,
        fs: Some(FsToolPolicy::new(
            vec!["/workspace/**".to_string()],
            vec!["/home/*/.ssh/**".to_string()],
        )),
        syscalls: None,
        network: None,
        input_responses: InputResponsesMode::Auto,
        input_responses_specified: false,
        fs_explicit: false,
        network_explicit: false,
        syscalls_explicit: false,
        environment_explicit: false,
        process_exec_allowed: false,
        process_explicit: false,
        deputy: None,
    });
    policy.fs.read_only = vec!["/usr/lib/**".to_string()];
    policy.fs.read_write = vec!["/workspace/**".to_string()];
    assert!(validate_policy(&policy).is_ok());
}

// --- integration: example policy ---

#[test]
fn test_example_policy_passes_validation() {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("policy.example.kdl");
    let policy = crate::policy::loader::load_policy(&path).unwrap();
    assert!(validate_policy(&policy).is_ok());
}

// --- execution target ---

fn target_with_os(os: TargetOs) -> ExecutionTarget {
    ExecutionTarget {
        workload_os: os,
        ..ExecutionTarget::native()
    }
}

fn allowlist_plus_deny_all_policy() -> Policy {
    let mut policy = default_policy();
    policy.network.outbound.deny_all_others = true;
    policy.network.outbound.allowed = vec!["api.example.com".to_string()];
    policy
}

#[test]
fn test_windows_target_rejects_per_destination_outbound_allowlist() {
    let policy = allowlist_plus_deny_all_policy();
    let err = validate_policy_for_target(&policy, &target_with_os(TargetOs::Windows))
        .expect_err("Windows cannot pin outbound destinations");
    assert!(err.to_string().contains("Windows AppContainer"));
}

#[test]
fn test_non_windows_targets_accept_per_destination_outbound_allowlist() {
    let policy = allowlist_plus_deny_all_policy();
    for os in [TargetOs::Linux, TargetOs::MacOs, TargetOs::Other("freebsd")] {
        validate_policy_for_target(&policy, &target_with_os(os)).unwrap_or_else(|e| {
            panic!("{} target must not apply the Windows rule: {e}", os.name())
        });
    }
}

// --- PSEC mechanism-aware validation ---

fn psec_target() -> ExecutionTarget {
    target_with_os(TargetOs::Windows)
        .with_native_windows_mechanism(crate::execution::WindowsNativeMechanism::Psec)
}

#[test]
fn test_psec_target_accepts_ipv4_allowlist_under_deny_all() {
    let mut policy = allowlist_plus_deny_all_policy();
    policy.network.outbound.allowed = vec!["10.0.0.1".to_string()];
    validate_policy_for_target(&policy, &psec_target())
        .expect("an IPv4 literal is a PSEC egress destination");
}

#[test]
fn test_psec_target_rejects_non_ipv4_allowlist_entries() {
    // Hostnames, wildcards and port-qualified entries have no verified
    // PSEC representation — each refuses at load, named in the error.
    for entry in ["api.example.com", "10.0.0.1:443", "::1", "*"] {
        let mut policy = allowlist_plus_deny_all_policy();
        policy.network.outbound.allowed = vec![entry.to_string()];
        let err = validate_policy_for_target(&policy, &psec_target())
            .expect_err("non-IPv4 entry must refuse under psec");
        assert!(err.to_string().contains(entry), "{entry}: {err}");
    }
}

#[test]
fn test_psec_target_rejects_named_environment_allowlist() {
    let mut policy = default_policy();
    policy.environment.restrict = true;
    policy.environment.allowed = vec!["FOO".to_string()];
    let err = validate_policy_for_target(&policy, &psec_target())
        .expect_err("a PSEC child cannot receive a named env allow list");
    assert!(err.to_string().contains("'FOO'"), "{err}");
}

#[test]
fn test_psec_target_accepts_bare_environment_restrict() {
    let mut policy = default_policy();
    policy.environment.restrict = true;
    validate_policy_for_target(&policy, &psec_target())
        .expect("a bare restrict holds by construction under PSEC");
}

#[test]
fn test_psec_target_rejects_unrestricted_egress_inbound_and_http() {
    // Unrestricted egress is unexpressible (measured deny-all posture).
    let mut policy = default_policy();
    policy.network.outbound.deny_all_others = false;
    let err = validate_policy_for_target(&policy, &psec_target())
        .expect_err("unrestricted egress must refuse under psec");
    assert!(err.to_string().contains("unrestricted"), "{err}");

    let mut policy = default_policy();
    policy.network.inbound.allow_listen = true;
    let err = validate_policy_for_target(&policy, &psec_target())
        .expect_err("inbound listen must refuse under psec");
    assert!(err.to_string().contains("ingress"), "{err}");

    let mut policy = default_policy();
    policy.transport.type_ = TransportType::Http;
    policy.transport.listen_addr = Some("127.0.0.1:8080".to_string());
    let err = validate_policy_for_target(&policy, &psec_target())
        .expect_err("HTTP transport must refuse under psec");
    assert!(err.to_string().contains("loopback"), "{err}");
}

#[test]
fn test_psec_rules_apply_only_to_native_windows_psec_target() {
    // A VM/container Windows target (or a psec selection on a
    // non-Windows workload) does not take the native-mechanism
    // refusals — the in-guest runner makes its own mechanism choice.
    let mut policy = default_policy();
    policy.environment.allowed = vec!["FOO".to_string()];
    let container_target = ExecutionTarget {
        workload_os: TargetOs::Windows,
        substrate: crate::execution::ExecutionSubstrate::Vm,
        native_windows_mechanism: Some(crate::execution::WindowsNativeMechanism::Psec),
        ..ExecutionTarget::native()
    };
    validate_policy_for_target(&policy, &container_target)
        .expect("non-native substrate ignores the native mechanism field");
}

#[test]
fn test_psec_target_rejects_port_qualified_allow_entries() {
    // A `host:port` allow folds to the bare host at parse — the
    // recorded qualifier must refuse under psec rather than
    // silently widen to an every-port egress rule.
    let mut policy = allowlist_plus_deny_all_policy();
    policy.network.outbound.allowed = vec!["10.0.0.1".to_string()];
    policy.network.outbound.allowed_port_qualified = vec!["10.0.0.1:443".to_string()];
    let err = validate_policy_for_target(&policy, &psec_target())
        .expect_err("a port-qualified allow entry must refuse under psec");
    let msg = err.to_string();
    assert!(msg.contains("port"), "{msg}");
    assert!(msg.contains("10.0.0.1:443"), "{msg}");

    // The same destination without the qualifier stays accepted.
    policy.network.outbound.allowed_port_qualified = Vec::new();
    validate_policy_for_target(&policy, &psec_target())
        .expect("a bare IPv4 literal is expressible");

    // A qualifier record whose folded host left `allowed` (e.g. via
    // deny-precedence) does not refuse on its own.
    let mut policy = allowlist_plus_deny_all_policy();
    policy.network.outbound.allowed = vec!["192.0.2.1".to_string()];
    policy.network.outbound.allowed_port_qualified = vec!["10.0.0.1:443".to_string()];
    validate_policy_for_target(&policy, &psec_target())
        .expect("a stale qualifier record for a removed entry must not refuse");

    // And a non-native target never reads the field.
    let mut policy = allowlist_plus_deny_all_policy();
    policy.network.outbound.allowed = vec!["10.0.0.1".to_string()];
    policy.network.outbound.allowed_port_qualified = vec!["10.0.0.1:443".to_string()];
    let vm_target = ExecutionTarget {
        workload_os: TargetOs::Windows,
        substrate: crate::execution::ExecutionSubstrate::Vm,
        native_windows_mechanism: Some(crate::execution::WindowsNativeMechanism::Psec),
        ..ExecutionTarget::native()
    };
    let err = validate_policy_for_target(&policy, &vm_target)
        .expect_err("per-destination allowlists refuse for a VM guest too");
    // …but with the AppContainer reason — the in-guest runner's
    // mechanism — never the PSEC contract text.
    assert!(err.to_string().contains("AppContainer"), "{err}");
}

#[test]
fn test_psec_target_accepts_ipv4_32_cidr_allowlist() {
    // `allow cidr=` IPv4 /32 entries are the host-route form the
    // measured PSEC egress contract encodes.
    let mut policy = allowlist_plus_deny_all_policy();
    policy.network.outbound.allowed = Vec::new();
    policy.network.outbound.allowed_cidrs = vec!["10.0.0.1/32".to_string()];
    validate_policy_for_target(&policy, &psec_target())
        .expect("an IPv4 /32 cidr is a PSEC egress destination");
}

#[test]
fn test_psec_target_rejects_non_host_route_cidrs() {
    // Wider prefixes and IPv6 have no verified PSEC representation —
    // each refuses at load, named in the error.
    for cidr in ["10.0.0.0/8", "0.0.0.0/0", "2001:db8::/32", "::1/128"] {
        let mut policy = allowlist_plus_deny_all_policy();
        policy.network.outbound.allowed = Vec::new();
        policy.network.outbound.allowed_cidrs = vec![cidr.to_string()];
        let err = validate_policy_for_target(&policy, &psec_target())
            .expect_err("a non-/32 cidr must refuse under psec");
        assert!(err.to_string().contains(cidr), "{cidr}: {err}");
    }
}

#[test]
fn test_psec_target_rejects_port_qualified_cidr_entries() {
    // A `cidr:port` allow folds to the bare range at parse — the
    // recorded qualifier must refuse under psec rather than silently
    // widen to an every-port egress rule.
    let mut policy = allowlist_plus_deny_all_policy();
    policy.network.outbound.allowed = Vec::new();
    policy.network.outbound.allowed_cidrs = vec!["10.0.0.1/32".to_string()];
    policy.network.outbound.allowed_cidrs_port_qualified =
        vec!["10.0.0.1/32:443".to_string()];
    let err = validate_policy_for_target(&policy, &psec_target())
        .expect_err("a port-qualified cidr entry must refuse under psec");
    let msg = err.to_string();
    assert!(msg.contains("port"), "{msg}");
    assert!(msg.contains("10.0.0.1/32:443"), "{msg}");

    // A stale qualifier whose rule left `allowed_cidrs` does not refuse.
    policy.network.outbound.allowed_cidrs = Vec::new();
    validate_policy_for_target(&policy, &psec_target())
        .expect("a stale qualifier record for a removed entry must not refuse");
}

#[test]
fn test_psec_target_rejects_deny_overlapping_allow_cidr() {
    // PSEC has no except-form: an IP-layer deny intersecting a
    // surviving allow would be silently swallowed by the encoded rule.
    let mut policy = allowlist_plus_deny_all_policy();
    policy.network.outbound.allowed = Vec::new();
    policy.network.outbound.allowed_cidrs = vec!["10.0.0.1/32".to_string()];
    policy.network.outbound.denied_cidrs = vec!["10.0.0.0/24".to_string()];
    let err = validate_policy_for_target(&policy, &psec_target())
        .expect_err("a deny overlapping an allow must refuse under psec");
    assert!(err.to_string().contains("overlap"), "{err}");

    // A disjoint deny is covered by the default-deny and passes.
    let mut policy = allowlist_plus_deny_all_policy();
    policy.network.outbound.allowed = Vec::new();
    policy.network.outbound.allowed_cidrs = vec!["10.0.0.1/32".to_string()];
    policy.network.outbound.denied_cidrs = vec!["192.0.2.0/24".to_string()];
    validate_policy_for_target(&policy, &psec_target())
        .expect("a disjoint deny is covered by the default-deny");
}

#[test]
fn test_psec_target_rejects_inexpressible_fs_paths_at_load() {
    // The same per-entry contract `build_launch_spec` applies at
    // spawn — globs and relative spellings refuse while the policy
    // loads, so `run` never reaches `policy-check` with them.
    let mut policy = default_policy();
    policy.fs.read_only = vec!["C:\\data\\**".to_string()];
    policy.fs.denied_paths = vec!["rel\\path".to_string()];
    let err = validate_policy_for_target(&policy, &psec_target())
        .expect_err("glob/relative fs spellings must refuse under psec");
    let msg = err.to_string();
    assert!(msg.contains("fs.read_only"), "{msg}");
    assert!(msg.contains("fs.denied_paths"), "{msg}");

    // Literal absolute paths — including the `\\?\` verbatim and
    // `\\?\UNC\` spellings the runtime itself reports — pass.
    let mut policy = default_policy();
    policy.fs.read_only = vec![
        "C:\\data".to_string(),
        "\\\\?\\C:\\data".to_string(),
        "\\\\?\\UNC\\server\\share".to_string(),
    ];
    policy.fs.denied_paths = vec!["\\\\server\\share\\dir".to_string()];
    validate_policy_for_target(&policy, &psec_target())
        .expect("absolute and verbatim fs spellings are expressible");

    // A bare `UNC\…` spelling is a relative path (its first
    // component is literally named "UNC") — the form is UNC only
    // inside a `\\?\` verbatim prefix. And a UNC path without both
    // a server and a share names no usable target.
    for bad in [
        "UNC\\server\\share",
        "\\\\server",
        "\\\\server\\",
        "\\\\\\share",
        "\\\\?\\UNC\\server",
        "\\\\?\\UNC\\",
    ] {
        let mut policy = default_policy();
        policy.fs.read_only = vec![bad.to_string()];
        let err = validate_policy_for_target(&policy, &psec_target())
            .expect_err("a bare UNC\\ or server/share-less spelling must refuse");
        assert!(err.to_string().contains(bad), "{err}");
    }
}

#[test]
fn test_native_wrapper_matches_host_target() {
    let policy = allowlist_plus_deny_all_policy();
    let host_result = validate_policy(&policy).map_err(|e| e.to_string());
    let explicit =
        validate_policy_for_target(&policy, &ExecutionTarget::native()).map_err(|e| e.to_string());
    assert_eq!(host_result, explicit);
}

#[test]
fn test_subpath_deny_case_sensitivity_follows_target() {
    // `Secret/` vs `secret/`: a case-insensitive filesystem makes the
    // deny unreachable under the allowed parent, so only the
    // case-insensitive targets reject the policy.
    let mut policy = default_policy();
    policy.fs.read_only = vec!["/data/Secret/**".to_string()];
    policy.fs.denied_paths = vec!["/data/secret/key.pem".to_string()];

    for os in [TargetOs::Windows, TargetOs::MacOs] {
        let err = validate_policy_for_target(&policy, &target_with_os(os))
            .expect_err("case-insensitive target must reject the unreachable deny");
        assert!(err.to_string().contains("sub-path denials"), "got: {err}");
    }
    for os in [TargetOs::Linux, TargetOs::Other("freebsd")] {
        validate_policy_for_target(&policy, &target_with_os(os))
            .unwrap_or_else(|e| panic!("{} target must not reject: {e}", os.name()));
    }
}

#[test]
fn test_subpath_deny_separator_follows_target() {
    // `data\secret` is a path *under* `data` only when `\` separates
    // components — on POSIX targets it is a literal filename.
    let mut policy = default_policy();
    policy.fs.read_only = vec!["/data/**".to_string()];
    policy.fs.denied_paths = vec!["/data\\secret".to_string()];

    let err = validate_policy_for_target(&policy, &target_with_os(TargetOs::Windows))
        .expect_err("Windows target must treat \\ as a separator");
    assert!(err.to_string().contains("sub-path denials"), "got: {err}");

    for os in [TargetOs::Linux, TargetOs::MacOs] {
        validate_policy_for_target(&policy, &target_with_os(os))
            .unwrap_or_else(|e| panic!("{} target must treat \\ literally: {e}", os.name()));
    }
}

#[test]
fn test_subpath_deny_drive_letter_follows_target() {
    // Drive-letter notation only nests under Windows rules.
    let mut policy = default_policy();
    policy.fs.read_only = vec!["C:\\Shared\\**".to_string()];
    policy.fs.denied_paths = vec!["C:\\Shared\\secret.txt".to_string()];

    let err = validate_policy_for_target(&policy, &target_with_os(TargetOs::Windows))
        .expect_err("Windows target must nest the deny under the allowed drive path");
    assert!(err.to_string().contains("sub-path denials"), "got: {err}");

    validate_policy_for_target(&policy, &target_with_os(TargetOs::Linux))
        .expect("Linux target treats the whole pattern as one literal component");
}

#[test]
fn test_normalize_dotdot_pops_relative_and_preserves_anchors() {
    // `..` removes the preceding segment in relative patterns too —
    // not only once the segment vector is longer than the anchor.
    assert_eq!(
        paths::normalize_fs_pattern_for("a/../b", TargetOs::Linux),
        "b"
    );
    assert_eq!(
        paths::normalize_fs_pattern_for("a/b/../../c", TargetOs::Linux),
        "c"
    );
    // Root and Windows drive prefixes are anchors `..` cannot climb.
    assert_eq!(
        paths::normalize_fs_pattern_for("/a/../b", TargetOs::Linux),
        "/b"
    );
    assert_eq!(
        paths::normalize_fs_pattern_for("C:/a/../b", TargetOs::Windows),
        "C:/b"
    );
    assert_eq!(
        paths::normalize_fs_pattern_for("C:/../x", TargetOs::Windows),
        "C:/x"
    );
    // On POSIX `C:` is a plain component — `..` pops it like any other.
    assert_eq!(
        paths::normalize_fs_pattern_for("C:/../x", TargetOs::Linux),
        "x"
    );
}

#[test]
fn test_pattern_components_preserves_drive_prefix_anchor() {
    // `path_covers`'s component walk anchors `..` at a Windows drive
    // prefix the same way `normalize_fs_pattern_for` does — otherwise
    // `C:/../x` would collapse to a bare `x` and cover relative denies.
    assert_eq!(
        paths::pattern_components("C:/../x", TargetOs::Windows).join("/"),
        "C:/x"
    );
    assert!(!paths::path_covers("C:/../x", "x", TargetOs::Windows));
    assert!(paths::path_covers("C:/../x", "C:/x/y", TargetOs::Windows));
    // POSIX target: `C:` is a regular component and pops normally.
    assert_eq!(
        paths::pattern_components("C:/../x", TargetOs::Linux).join("/"),
        "x"
    );
}

#[test]
fn test_subpath_denial_still_rejected_on_posix_target() {
    // The check itself is not Windows-specific; identical POSIX paths
    // still reject on a Linux target.
    let mut policy = default_policy();
    policy.fs.read_only = vec!["/workspace/**".to_string()];
    policy.fs.denied_paths = vec!["/workspace/secret.txt".to_string()];
    let err = validate_policy_for_target(&policy, &target_with_os(TargetOs::Linux))
        .expect_err("deny under allowed parent must reject on Linux too");
    assert!(err.to_string().contains("sub-path denials"), "got: {err}");
}

#[test]
fn test_r06_parent_allow_child_deny_rejected() {
    let mut policy = default_policy();
    policy.tools.push(ToolPolicy {
        name: "write_file".to_string(),
        allowed: true,
        args_schema: None,
        side_effect: None,
        server: None,
        fs: Some(FsToolPolicy::new(
            vec!["/workspace/**".to_string()],
            vec!["/workspace/secret.txt".to_string()],
        )),
        syscalls: None,
        network: None,
        input_responses: InputResponsesMode::Auto,
        input_responses_specified: false,
        fs_explicit: false,
        network_explicit: false,
        syscalls_explicit: false,
        environment_explicit: false,
        process_exec_allowed: false,
        process_explicit: false,
        deputy: None,
    });
    let err = validate_policy(&policy).unwrap_err();
    assert!(
        err.to_string()
            .contains("Landlock additive rulesets cannot carve out sub-path denials")
    );
}

#[test]
fn test_per_tool_syscalls_are_rejected() {
    let mut policy = default_policy();
    policy.tools.push(ToolPolicy {
        name: "exec_cmd".to_string(),
        allowed: true,
        args_schema: None,
        side_effect: None,
        server: None,
        fs: None,
        syscalls: Some(crate::policy::ToolSyscallPolicy {
            allowed: vec!["read".to_string()],
            denied: vec!["execve".to_string()],
        }),
        network: None,
        input_responses: InputResponsesMode::Auto,
        input_responses_specified: false,
        fs_explicit: false,
        network_explicit: false,
        syscalls_explicit: true,
        environment_explicit: false,
        process_exec_allowed: false,
        process_explicit: false,
        deputy: None,
    });
    let err = validate_policy(&policy).unwrap_err();
    assert!(err.to_string().contains("per-tool syscalls"), "got: {err}");
}

#[test]
fn test_per_tool_environment_is_rejected() {
    let mut policy = default_policy();
    let mut tool = ToolPolicy::named("read_file", true);
    tool.environment_explicit = true;
    policy.tools.push(tool);
    let err = validate_policy(&policy).unwrap_err();
    assert!(
        err.to_string().contains("per-tool environment"),
        "got: {err}"
    );
    assert!(
        err.to_string().contains("defaults.environment"),
        "rejection must point at defaults.environment: {err}"
    );
}

#[test]
fn test_environment_names_rejected_when_unusable() {
    for name in ["", "A=B", "A\0B"] {
        let mut policy = default_policy();
        policy.environment.restrict = true;
        policy.environment.allowed = vec![name.to_string()];
        let err = validate_policy(&policy).unwrap_err();
        assert!(
            matches!(err, PolicyError::Validation(_)),
            "name {name:?} must be a validation error, got: {err}"
        );
        assert!(
            err.to_string().contains("environment variable name"),
            "got: {err}"
        );
    }
}

#[test]
fn test_environment_names_valid_pass() {
    let mut policy = default_policy();
    policy.environment.restrict = true;
    policy.environment.allowed = vec!["MEMORY_FILE_PATH".to_string(), "LANG".to_string()];
    assert!(validate_policy(&policy).is_ok());
}

#[test]
fn test_side_effect_read_only_with_write_glob_fails() {
    let kdl = r#"
        policy version=1
        server "s" {
            tool "read_file" side_effect="read_only" {
                filesystem {
                    allow "/workspace/**" mode="write"
                }
            }
        }
    "#;
    let policy = crate::policy::kdl_loader::parse_kdl_policy(kdl).unwrap();
    let err = validate_policy(&policy).unwrap_err();
    assert!(
        err.to_string().contains("read_only") && err.to_string().contains("write"),
        "got: {err}"
    );
}

#[test]
fn test_side_effect_read_only_with_network_subpolicy_fails() {
    let kdl = r#"
        policy version=1
        server "s" {
            tool "read_file" side_effect="read_only" {
                filesystem {
                    allow "/workspace/**"
                }
                network {
                    allow host="api.example.com"
                }
            }
        }
    "#;
    let policy = crate::policy::kdl_loader::parse_kdl_policy(kdl).unwrap();
    let err = validate_policy(&policy).unwrap_err();
    assert!(err.to_string().contains("network"), "got: {err}");
}

#[test]
fn test_side_effect_write_plus_exec_fails() {
    let kdl = r#"
        policy version=1
        server "s" {
            tool "write_file" side_effect="write" {
                filesystem {
                    allow "/workspace/**" mode="write"
                }
                process deny-all=#false
            }
        }
    "#;
    let policy = crate::policy::kdl_loader::parse_kdl_policy(kdl).unwrap();
    let err = validate_policy(&policy).unwrap_err();
    assert!(
        err.to_string().contains("write") && err.to_string().contains("process"),
        "got: {err}"
    );
}

#[test]
fn test_side_effect_write_with_process_deny_all_passes() {
    let kdl = r#"
        policy version=1
        server "s" {
            tool "write_file" side_effect="write" {
                filesystem {
                    allow "/workspace/**" mode="write"
                }
                process deny-all=#true
            }
        }
    "#;
    let policy = crate::policy::kdl_loader::parse_kdl_policy(kdl).unwrap();
    assert!(validate_policy(&policy).is_ok());
}

#[test]
fn test_side_effect_consistent_read_only_passes() {
    let kdl = r#"
        policy version=1
        server "s" {
            tool "read_file" side_effect="read_only" {
                filesystem {
                    allow "/workspace/**"
                }
            }
        }
    "#;
    let policy = crate::policy::kdl_loader::parse_kdl_policy(kdl).unwrap();
    assert!(validate_policy(&policy).is_ok());
}

#[test]
fn test_unknown_side_effect_is_load_error() {
    let kdl = r#"
        policy version=1
        server "s" {
            tool "read_file" side_effect="mutate"
        }
    "#;
    let err = crate::policy::kdl_loader::parse_kdl_policy(kdl).unwrap_err();
    assert!(
        err.to_string().contains("unknown side_effect"),
        "got: {err}"
    );
}

#[test]
fn test_trajectory_requires_side_effect_on_allowed_tools() {
    let kdl = r#"
        policy version=1
        trajectory #true {
            after side_effect="read_only" deny-next="network"
        }
        server "s" {
            tool "read_file"
        }
    "#;
    let policy = crate::policy::kdl_loader::parse_kdl_policy(kdl).unwrap();
    let err = validate_policy(&policy).unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("side_effect"), "got: {err}");
    assert!(msg.contains("read_file"), "got: {err}");
}

#[test]
fn test_trajectory_allows_denied_tools_without_side_effect() {
    let kdl = r#"
        policy version=1
        trajectory #true {
            after side_effect="read_only" deny-next="network"
        }
        server "s" {
            tool "evil" deny=#true
            tool "read_file" side_effect="read_only"
        }
    "#;
    let policy = crate::policy::kdl_loader::parse_kdl_policy(kdl).unwrap();
    validate_policy(&policy).unwrap();
}
