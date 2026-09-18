use super::{FsToolPolicy, ToolNetworkPolicy, ToolSyscallPolicy};
use crate::error::PolicyError;

/// A single layer of policy configuration.
///
/// Each field is `Option` to distinguish "not specified" (inherit from lower layer)
/// from "specified" (override).  Layers are merged in priority order:
///
///   defaults → profile → server-defaults → tool
///
/// Later (higher-priority) layers override earlier ones, **except** that explicit
/// deny entries are sticky and accumulate across all layers.
#[derive(Debug, Clone, Default)]
pub struct PolicyLayer {
    /// Whether the tool is allowed.  `Some(false)` is an explicit deny.
    pub allowed: Option<bool>,
    pub fs: Option<FsToolPolicy>,
    pub syscalls: Option<ToolSyscallPolicy>,
    pub network: Option<ToolNetworkPolicy>,
}

/// The effective policy for a single tool after all layers have been merged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MergedToolPolicy {
    pub allowed: bool,
    pub fs: FsToolPolicy,
    pub syscalls: ToolSyscallPolicy,
    pub network: ToolNetworkPolicy,
}

/// Merge policy layers in priority order (lowest-priority first).
///
/// # Rules
///
/// 1. **Override**: If a higher-priority layer specifies a category (`Some(..)`),
///    its `allow`-side values **replace** the lower layers' values.
/// 2. **Deny is sticky**: `denied_*` / `denied` lists **accumulate** across all
///    layers.  An item denied at *any* layer stays denied regardless of later allows.
/// 3. **Tool-level deny**: If *any* layer sets `allowed = Some(false)`, the tool
///    is denied and cannot be un-denied by a later layer.
/// 4. **Inheritance**: Unspecified (`None`) categories inherit the running value
///    from lower layers.
pub fn merge_policy(layers: &[&PolicyLayer]) -> MergedToolPolicy {
    let mut result = MergedToolPolicy {
        allowed: true,
        fs: FsToolPolicy {
            allowed_paths: Vec::new(),
            read_only_paths: Vec::new(),
            read_write_paths: Vec::new(),
            denied_paths: Vec::new(),
            allow_specified: false,
            require_path: None,
        },
        syscalls: ToolSyscallPolicy {
            allowed: Vec::new(),
            denied: Vec::new(),
        },
        network: ToolNetworkPolicy {
            allowed_hosts: Vec::new(),
            denied_hosts: Vec::new(),
            allow_specified: false,
        },
    };

    let mut explicitly_denied = false;

    for layer in layers {
        // ── allowed (deny-wins) ─────────────────────────────────
        if let Some(allowed) = layer.allowed
            && !allowed
        {
            explicitly_denied = true;
        }

        // ── filesystem ──────────────────────────────────────────
        if let Some(ref fs) = layer.fs {
            if fs.require_path.is_some() {
                result.fs.require_path = fs.require_path;
            }
            // If this layer specifies any allow rules, overwrite the entire allow category
            // (allowed_paths, read_only_paths, read_write_paths) to prevent leaking old permissions.
            let has_allow_rules = fs.allow_specified
                || !fs.allowed_paths.is_empty()
                || !fs.read_only_paths.is_empty()
                || !fs.read_write_paths.is_empty();

            if has_allow_rules {
                result.fs.allowed_paths = fs.allowed_paths.clone();
                result.fs.read_only_paths = fs.read_only_paths.clone();
                result.fs.read_write_paths = fs.read_write_paths.clone();
                result.fs.allow_specified = true;
            }

            // Denied paths accumulate (deny-sticky)
            for path in &fs.denied_paths {
                if !result.fs.denied_paths.contains(path) {
                    result.fs.denied_paths.push(path.clone());
                }
            }
        }

        // ── syscalls ────────────────────────────────────
        if let Some(ref sc) = layer.syscalls {
            if !sc.allowed.is_empty() {
                result.syscalls.allowed = sc.allowed.clone();
            }
            for name in &sc.denied {
                if !result.syscalls.denied.contains(name) {
                    result.syscalls.denied.push(name.clone());
                }
            }
        }

        // ── network ─────────────────────────────────────
        if let Some(ref net) = layer.network {
            let has_allow_rules = net.allow_specified || !net.allowed_hosts.is_empty();
            if has_allow_rules {
                result.network.allowed_hosts = net.allowed_hosts.clone();
                result.network.allow_specified = true;
            }
            for host in &net.denied_hosts {
                if !result.network.denied_hosts.contains(host) {
                    result.network.denied_hosts.push(host.clone());
                }
            }
        }
    }

    // Apply deny-wins for the tool-level allowed flag
    if explicitly_denied {
        result.allowed = false;
    }

    // Remove denied items from allowed lists (deny-wins at item level)
    result
        .fs
        .allowed_paths
        .retain(|p| !result.fs.denied_paths.contains(p));
    result
        .fs
        .read_only_paths
        .retain(|p| !result.fs.denied_paths.contains(p));
    result
        .fs
        .read_write_paths
        .retain(|p| !result.fs.denied_paths.contains(p));
    result
        .syscalls
        .allowed
        .retain(|s| !result.syscalls.denied.contains(s));
    result
        .network
        .allowed_hosts
        .retain(|h| !result.network.denied_hosts.contains(h));

    result
}

/// Validate a merged tool policy.
///
/// Checks:
/// - Denied paths / hosts / syscalls are non-empty strings
pub fn validate_merged(merged: &MergedToolPolicy) -> Result<(), PolicyError> {
    super::validator::validate_fs_target_contract(&merged.fs, "merged policy")?;
    for path in &merged.fs.allowed_paths {
        if path.trim().is_empty() {
            return Err(PolicyError::Validation(
                "merged policy contains an empty allowed_paths entry".into(),
            ));
        }
    }
    for path in &merged.fs.denied_paths {
        if path.trim().is_empty() {
            return Err(PolicyError::Validation(
                "merged policy contains an empty denied_paths entry".into(),
            ));
        }
    }
    for name in &merged.syscalls.allowed {
        if name.trim().is_empty() {
            return Err(PolicyError::Validation(
                "merged policy contains an empty allowed syscall entry".into(),
            ));
        }
    }
    for name in &merged.syscalls.denied {
        if name.trim().is_empty() {
            return Err(PolicyError::Validation(
                "merged policy contains an empty denied syscall entry".into(),
            ));
        }
    }
    for host in &merged.network.allowed_hosts {
        if host.trim().is_empty() {
            return Err(PolicyError::Validation(
                "merged policy contains an empty allowed_hosts entry".into(),
            ));
        }
    }
    for host in &merged.network.denied_hosts {
        if host.trim().is_empty() {
            return Err(PolicyError::Validation(
                "merged policy contains an empty denied_hosts entry".into(),
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_layer() -> PolicyLayer {
        PolicyLayer::default()
    }

    fn fs_layer(allowed: &[&str], denied: &[&str]) -> PolicyLayer {
        PolicyLayer {
            fs: Some(FsToolPolicy::new(
                allowed.iter().map(|s| s.to_string()).collect(),
                denied.iter().map(|s| s.to_string()).collect(),
            )),
            ..Default::default()
        }
    }

    fn syscall_layer(allowed: &[&str], denied: &[&str]) -> PolicyLayer {
        PolicyLayer {
            syscalls: Some(ToolSyscallPolicy {
                allowed: allowed.iter().map(|s| s.to_string()).collect(),
                denied: denied.iter().map(|s| s.to_string()).collect(),
            }),
            ..Default::default()
        }
    }

    fn network_layer(allowed: &[&str], denied: &[&str]) -> PolicyLayer {
        PolicyLayer {
            network: Some(ToolNetworkPolicy {
                allowed_hosts: allowed.iter().map(|s| s.to_string()).collect(),
                denied_hosts: denied.iter().map(|s| s.to_string()).collect(),
                allow_specified: !allowed.is_empty(),
            }),
            ..Default::default()
        }
    }

    // ── Basic inheritance ────────────────────────────────────────

    #[test]
    fn test_empty_layers_produce_empty_result() {
        let layer = empty_layer();
        let result = merge_policy(&[&layer]);
        assert!(result.allowed);
        assert!(result.fs.allowed_paths.is_empty());
        assert!(result.fs.denied_paths.is_empty());
        assert!(result.syscalls.allowed.is_empty());
        assert!(result.network.allowed_hosts.is_empty());
    }

    #[test]
    fn test_single_defaults_layer_inherited() {
        let defaults = fs_layer(&["/usr/lib/**"], &[]);
        let result = merge_policy(&[&defaults]);
        assert_eq!(result.fs.allowed_paths, vec!["/usr/lib/**"]);
    }

    #[test]
    fn test_unspecified_category_inherits_from_lower_layer() {
        let defaults = PolicyLayer {
            fs: Some(FsToolPolicy {
                allowed_paths: vec!["/usr/lib/**".into()],
                denied_paths: Vec::new(),
                ..Default::default()
            }),
            syscalls: Some(ToolSyscallPolicy {
                allowed: vec!["read".into(), "write".into()],
                denied: Vec::new(),
            }),
            ..Default::default()
        };
        // Tool layer only specifies fs, syscalls should inherit
        let tool = fs_layer(&["/workspace/**"], &[]);
        let result = merge_policy(&[&defaults, &tool]);
        assert_eq!(result.fs.allowed_paths, vec!["/workspace/**"]);
        assert_eq!(result.syscalls.allowed, vec!["read", "write"]);
    }

    // ── Override ─────────────────────────────────────────────────

    #[test]
    fn test_higher_priority_overrides_allowed_paths() {
        let defaults = fs_layer(&["/usr/lib/**"], &[]);
        let tool = fs_layer(&["/workspace/**"], &[]);
        let result = merge_policy(&[&defaults, &tool]);
        assert_eq!(result.fs.allowed_paths, vec!["/workspace/**"]);
    }

    #[test]
    fn test_higher_priority_overrides_allowed_syscalls() {
        let defaults = syscall_layer(&["read", "write", "openat"], &[]);
        let tool = syscall_layer(&["read"], &[]);
        let result = merge_policy(&[&defaults, &tool]);
        assert_eq!(result.syscalls.allowed, vec!["read"]);
    }

    #[test]
    fn test_higher_priority_overrides_allowed_hosts() {
        let defaults = network_layer(&["api.example.com"], &[]);
        let tool = network_layer(&["cdn.example.com"], &[]);
        let result = merge_policy(&[&defaults, &tool]);
        assert_eq!(result.network.allowed_hosts, vec!["cdn.example.com"]);
    }

    // ── Deny is sticky ──────────────────────────────────────────

    #[test]
    fn test_denied_paths_accumulate_across_layers() {
        let defaults = fs_layer(&["/usr/lib/**"], &["/etc/shadow"]);
        let server_defaults = fs_layer(&[], &["/root/**"]);
        let tool = fs_layer(&["/workspace/**"], &["/tmp/secrets"]);
        let result = merge_policy(&[&defaults, &server_defaults, &tool]);
        assert_eq!(result.fs.allowed_paths, vec!["/workspace/**"]);
        assert_eq!(
            result.fs.denied_paths,
            vec!["/etc/shadow", "/root/**", "/tmp/secrets"]
        );
    }

    #[test]
    fn test_denied_syscalls_accumulate_across_layers() {
        let defaults = syscall_layer(&["read", "write"], &["execve"]);
        let tool = syscall_layer(&["read", "write", "openat"], &["fork"]);
        let result = merge_policy(&[&defaults, &tool]);
        assert_eq!(result.syscalls.allowed, vec!["read", "write", "openat"]);
        assert_eq!(result.syscalls.denied, vec!["execve", "fork"]);
    }

    #[test]
    fn test_denied_hosts_accumulate_across_layers() {
        let defaults = network_layer(&["api.example.com"], &["evil.com"]);
        let tool = network_layer(&["cdn.example.com"], &["malware.org"]);
        let result = merge_policy(&[&defaults, &tool]);
        assert_eq!(result.network.allowed_hosts, vec!["cdn.example.com"]);
        assert_eq!(result.network.denied_hosts, vec!["evil.com", "malware.org"]);
    }

    #[test]
    fn test_deny_duplicates_are_deduplicated() {
        let layer1 = fs_layer(&[], &["/etc/shadow"]);
        let layer2 = fs_layer(&[], &["/etc/shadow"]);
        let result = merge_policy(&[&layer1, &layer2]);
        assert_eq!(result.fs.denied_paths, vec!["/etc/shadow"]);
    }

    // ── Deny-wins: item-level ───────────────────────────────────

    #[test]
    fn test_denied_item_removed_from_allowed() {
        // defaults allows some paths, but a later layer denies one of them
        let defaults = fs_layer(&["/workspace/**", "/tmp/**"], &[]);
        let tool = PolicyLayer {
            fs: Some(FsToolPolicy {
                allowed_paths: Vec::new(),
                denied_paths: vec!["/tmp/**".into()],
                ..Default::default()
            }),
            ..Default::default()
        };
        let result = merge_policy(&[&defaults, &tool]);
        // /tmp/** was in allowed but later denied → removed from allowed
        assert_eq!(result.fs.allowed_paths, vec!["/workspace/**"]);
        assert_eq!(result.fs.denied_paths, vec!["/tmp/**"]);
    }

    #[test]
    fn test_denied_syscall_removed_from_allowed() {
        let defaults = syscall_layer(&["read", "write", "execve"], &[]);
        let tool = syscall_layer(&[], &["execve"]);
        let result = merge_policy(&[&defaults, &tool]);
        assert_eq!(result.syscalls.allowed, vec!["read", "write"]);
        assert_eq!(result.syscalls.denied, vec!["execve"]);
    }

    #[test]
    fn test_denied_host_removed_from_allowed() {
        let defaults = network_layer(&["api.example.com", "evil.com"], &[]);
        let tool = network_layer(&[], &["evil.com"]);
        let result = merge_policy(&[&defaults, &tool]);
        assert_eq!(result.network.allowed_hosts, vec!["api.example.com"]);
        assert_eq!(result.network.denied_hosts, vec!["evil.com"]);
    }

    // ── Tool-level deny-wins ────────────────────────────────────

    #[test]
    fn test_explicit_deny_at_any_layer_denies_tool() {
        let defaults = PolicyLayer {
            allowed: Some(true),
            ..Default::default()
        };
        let server_defaults = PolicyLayer {
            allowed: Some(false), // explicit deny
            ..Default::default()
        };
        let tool = PolicyLayer {
            allowed: Some(true), // try to re-allow → denied still wins
            ..Default::default()
        };
        let result = merge_policy(&[&defaults, &server_defaults, &tool]);
        assert!(!result.allowed);
    }

    #[test]
    fn test_deny_at_defaults_cannot_be_overridden() {
        let defaults = PolicyLayer {
            allowed: Some(false),
            ..Default::default()
        };
        let tool = PolicyLayer {
            allowed: Some(true),
            ..Default::default()
        };
        let result = merge_policy(&[&defaults, &tool]);
        assert!(!result.allowed);
    }

    #[test]
    fn test_no_explicit_allowed_defaults_to_true() {
        let layer = empty_layer();
        let result = merge_policy(&[&layer]);
        assert!(result.allowed);
    }

    #[test]
    fn test_explicit_allow_without_deny() {
        let layer = PolicyLayer {
            allowed: Some(true),
            ..Default::default()
        };
        let result = merge_policy(&[&layer]);
        assert!(result.allowed);
    }

    // ── Four-stage merge (full scenario) ────────────────────────

    #[test]
    fn test_four_stage_merge() {
        // Stage 1: defaults (global)
        let defaults = PolicyLayer {
            allowed: Some(true),
            fs: Some(FsToolPolicy {
                allowed_paths: vec!["/usr/lib/**".into()],
                denied_paths: vec!["/etc/shadow".into()],
                ..Default::default()
            }),
            syscalls: Some(ToolSyscallPolicy {
                allowed: vec!["read".into(), "write".into(), "openat".into()],
                denied: vec!["execve".into()],
            }),
            network: Some(ToolNetworkPolicy {
                allowed_hosts: vec!["api.example.com".into()],
                denied_hosts: Vec::new(),
                ..Default::default()
            }),
        };

        // Stage 2: profile (reusable)
        let profile = PolicyLayer {
            fs: Some(FsToolPolicy {
                allowed_paths: vec!["/workspace/**".into()],
                denied_paths: vec!["/root/**".into()],
                ..Default::default()
            }),
            ..Default::default()
        };

        // Stage 3: server-defaults
        let server_defaults = PolicyLayer {
            network: Some(ToolNetworkPolicy {
                allowed_hosts: vec!["cdn.example.com".into()],
                denied_hosts: vec!["evil.com".into()],
                ..Default::default()
            }),
            ..Default::default()
        };

        // Stage 4: tool override
        let tool = PolicyLayer {
            fs: Some(FsToolPolicy {
                allowed_paths: vec!["/workspace/output/**".into()],
                denied_paths: Vec::new(),
                ..Default::default()
            }),
            syscalls: Some(ToolSyscallPolicy {
                allowed: vec!["read".into(), "write".into()],
                denied: vec!["fork".into()],
            }),
            ..Default::default()
        };

        let result = merge_policy(&[&defaults, &profile, &server_defaults, &tool]);

        // Tool is allowed (no deny at any stage)
        assert!(result.allowed);

        // FS: tool overrode allowed_paths; denied accumulated from defaults + profile
        assert_eq!(result.fs.allowed_paths, vec!["/workspace/output/**"]);
        assert_eq!(result.fs.denied_paths, vec!["/etc/shadow", "/root/**"]);

        // Syscalls: tool overrode allowed; denied accumulated from defaults + tool
        assert_eq!(result.syscalls.allowed, vec!["read", "write"]);
        assert_eq!(result.syscalls.denied, vec!["execve", "fork"]);

        // Network: server-defaults overrode allowed_hosts; denied from server-defaults
        assert_eq!(result.network.allowed_hosts, vec!["cdn.example.com"]);
        assert_eq!(result.network.denied_hosts, vec!["evil.com"]);
    }

    #[test]
    fn test_four_stage_merge_with_deny_at_tool_level() {
        let defaults = PolicyLayer {
            allowed: Some(true),
            fs: Some(FsToolPolicy {
                allowed_paths: vec!["/usr/lib/**".into()],
                denied_paths: Vec::new(),
                ..Default::default()
            }),
            ..Default::default()
        };
        let profile = empty_layer();
        let server_defaults = empty_layer();
        let tool = PolicyLayer {
            allowed: Some(false), // tool explicitly denied
            ..Default::default()
        };
        let result = merge_policy(&[&defaults, &profile, &server_defaults, &tool]);
        assert!(!result.allowed);
        // FS inherited from defaults
        assert_eq!(result.fs.allowed_paths, vec!["/usr/lib/**"]);
    }

    // ── Validation ──────────────────────────────────────────────

    #[test]
    fn test_validate_merged_ok() {
        let merged = MergedToolPolicy {
            allowed: true,
            fs: FsToolPolicy {
                allowed_paths: vec!["/workspace/**".into()],
                denied_paths: vec!["/etc/shadow".into()],
                ..Default::default()
            },
            syscalls: ToolSyscallPolicy {
                allowed: vec!["read".into()],
                denied: vec!["execve".into()],
            },
            network: ToolNetworkPolicy {
                allowed_hosts: vec!["api.example.com".into()],
                denied_hosts: Vec::new(),
                ..Default::default()
            },
        };
        assert!(validate_merged(&merged).is_ok());
    }

    #[test]
    fn test_validate_merged_empty_allowed_path() {
        let merged = MergedToolPolicy {
            allowed: true,
            fs: FsToolPolicy {
                allowed_paths: vec!["".into()],
                denied_paths: Vec::new(),
                ..Default::default()
            },
            syscalls: ToolSyscallPolicy::default(),
            network: ToolNetworkPolicy::default(),
        };
        let err = validate_merged(&merged).unwrap_err();
        assert!(err.to_string().contains("empty allowed_paths"));
    }

    #[test]
    fn test_validate_merged_empty_denied_path() {
        let merged = MergedToolPolicy {
            allowed: true,
            fs: FsToolPolicy {
                allowed_paths: Vec::new(),
                denied_paths: vec!["  ".into()],
                ..Default::default()
            },
            syscalls: ToolSyscallPolicy::default(),
            network: ToolNetworkPolicy::default(),
        };
        let err = validate_merged(&merged).unwrap_err();
        assert!(err.to_string().contains("empty denied_paths"));
    }

    #[test]
    fn test_validate_merged_empty_syscall() {
        let merged = MergedToolPolicy {
            allowed: true,
            fs: FsToolPolicy::default(),
            syscalls: ToolSyscallPolicy {
                allowed: vec!["".into()],
                denied: Vec::new(),
            },
            network: ToolNetworkPolicy::default(),
        };
        let err = validate_merged(&merged).unwrap_err();
        assert!(err.to_string().contains("empty allowed syscall"));
    }

    #[test]
    fn test_validate_merged_empty_denied_syscall() {
        let merged = MergedToolPolicy {
            allowed: true,
            fs: FsToolPolicy::default(),
            syscalls: ToolSyscallPolicy {
                allowed: Vec::new(),
                denied: vec!["  ".into()],
            },
            network: ToolNetworkPolicy::default(),
        };
        let err = validate_merged(&merged).unwrap_err();
        assert!(err.to_string().contains("empty denied syscall"));
    }

    #[test]
    fn test_validate_merged_empty_host() {
        let merged = MergedToolPolicy {
            allowed: true,
            fs: FsToolPolicy::default(),
            syscalls: ToolSyscallPolicy::default(),
            network: ToolNetworkPolicy {
                allowed_hosts: vec!["".into()],
                denied_hosts: Vec::new(),
                ..Default::default()
            },
        };
        let err = validate_merged(&merged).unwrap_err();
        assert!(err.to_string().contains("empty allowed_hosts"));
    }

    #[test]
    fn test_validate_merged_empty_denied_host() {
        let merged = MergedToolPolicy {
            allowed: true,
            fs: FsToolPolicy::default(),
            syscalls: ToolSyscallPolicy::default(),
            network: ToolNetworkPolicy {
                allowed_hosts: Vec::new(),
                denied_hosts: vec!["  ".into()],
                ..Default::default()
            },
        };
        let err = validate_merged(&merged).unwrap_err();
        assert!(err.to_string().contains("empty denied_hosts"));
    }

    #[test]
    fn test_validate_merged_empty_result_ok() {
        let merged = MergedToolPolicy {
            allowed: true,
            fs: FsToolPolicy::default(),
            syscalls: ToolSyscallPolicy::default(),
            network: ToolNetworkPolicy::default(),
        };
        assert!(validate_merged(&merged).is_ok());
    }

    // ── Edge cases ──────────────────────────────────────────────

    #[test]
    fn test_zero_layers() {
        let result = merge_policy(&[]);
        assert!(result.allowed);
        assert!(result.fs.allowed_paths.is_empty());
    }

    #[test]
    fn test_many_layers_deny_wins() {
        // 5 layers: allow, allow, deny, allow, allow → denied
        let allow = PolicyLayer {
            allowed: Some(true),
            ..Default::default()
        };
        let deny = PolicyLayer {
            allowed: Some(false),
            ..Default::default()
        };
        let result = merge_policy(&[&allow, &allow, &deny, &allow, &allow]);
        assert!(!result.allowed);
    }

    #[test]
    fn test_later_layer_with_empty_allowed_does_not_clear_inherited() {
        // defaults specifies allowed_paths, tool specifies empty denied only
        let defaults = fs_layer(&["/usr/lib/**"], &[]);
        let tool = PolicyLayer {
            fs: Some(FsToolPolicy {
                allowed_paths: Vec::new(), // empty → don't override
                denied_paths: vec!["/etc/shadow".into()],
                ..Default::default()
            }),
            ..Default::default()
        };
        let result = merge_policy(&[&defaults, &tool]);
        // allowed_paths inherited from defaults (tool's empty list doesn't replace)
        assert_eq!(result.fs.allowed_paths, vec!["/usr/lib/**"]);
        assert_eq!(result.fs.denied_paths, vec!["/etc/shadow"]);
    }

    #[test]
    fn test_conflict_same_item_allowed_and_denied() {
        // An item in both allowed and denied → denied wins
        let layer = PolicyLayer {
            syscalls: Some(ToolSyscallPolicy {
                allowed: vec!["execve".into(), "read".into()],
                denied: vec!["execve".into()],
            }),
            ..Default::default()
        };
        let result = merge_policy(&[&layer]);
        // execve should be removed from allowed
        assert_eq!(result.syscalls.allowed, vec!["read"]);
        assert_eq!(result.syscalls.denied, vec!["execve"]);
    }

    #[test]
    fn test_deny_from_lower_layer_removes_from_higher_allowed() {
        let defaults = syscall_layer(&[], &["execve"]); // deny at defaults
        let tool = syscall_layer(&["execve", "read"], &[]); // tool tries to allow execve
        let result = merge_policy(&[&defaults, &tool]);
        // execve denied at defaults → removed from tool's allowed
        assert_eq!(result.syscalls.allowed, vec!["read"]);
        assert_eq!(result.syscalls.denied, vec!["execve"]);
    }

    #[test]
    fn test_r03_write_permission_overwritten_by_read_only() {
        // Profile grants write to /old/**, tool layer overrides with read-only /new/**.
        // Old write permissions must NOT leak through into read_write_paths.
        let profile = PolicyLayer {
            fs: Some(FsToolPolicy {
                allowed_paths: vec!["/old/**".into()],
                read_only_paths: Vec::new(),
                read_write_paths: vec!["/old/**".into()],
                denied_paths: Vec::new(),
                allow_specified: true,
                require_path: None,
            }),
            ..Default::default()
        };

        let tool = PolicyLayer {
            fs: Some(FsToolPolicy {
                allowed_paths: vec!["/new/**".into()],
                read_only_paths: vec!["/new/**".into()],
                read_write_paths: Vec::new(),
                denied_paths: Vec::new(),
                allow_specified: true,
                require_path: None,
            }),
            ..Default::default()
        };

        let result = merge_policy(&[&profile, &tool]);
        assert_eq!(result.fs.allowed_paths, vec!["/new/**"]);
        assert_eq!(result.fs.read_only_paths, vec!["/new/**"]);
        assert!(
            result.fs.read_write_paths.is_empty(),
            "old write path /old/** must not remain in read_write_paths"
        );
    }
}
