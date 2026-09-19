use crate::inspector::profile::CapabilityProfile;
use crate::legislator::heuristics::{IntentProfile, Permission};
use crate::legislator::sinks::ToolCapability;

/// Result of cross-validating Capability (binary analysis) against Intent (tool definitions).
#[derive(Debug, Clone)]
pub struct CrossValidationResult {
    /// Case A: Capability and Intent agree — permission is justified.
    pub allowed: Vec<PermissionVerdict>,
    /// Case B: Capability exists but no Intent requires it — excess capability.
    pub blocked: Vec<PermissionVerdict>,
    /// Case C: Intent requires it but Capability lacks evidence — suspicious or dynamic.
    pub warnings: Vec<PermissionVerdict>,
}

/// A single permission verdict from cross-validation.
#[derive(Debug, Clone)]
pub struct PermissionVerdict {
    pub permission: Permission,
    pub tool_name: Option<String>,
    pub reason: String,
    pub case: VerdictCase,
}

/// Which cross-validation case produced this verdict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerdictCase {
    A,
    B,
    C,
}

/// Syscall names that indicate file-read capability.
const FS_READ_SYSCALLS: &[&str] = &[
    "read",
    "openat",
    "open",
    "stat",
    "fstat",
    "lstat",
    "access",
    "readlink",
    "readlinkat",
    "getdents",
    "getdents64",
    "faccessat",
    "faccessat2",
    "newfstatat",
    "statx",
    "lseek",
    "pread64",
];

/// Syscall names that indicate file-write capability.
const FS_WRITE_SYSCALLS: &[&str] = &[
    "write",
    "unlink",
    "unlinkat",
    "rename",
    "renameat",
    "renameat2",
    "mkdir",
    "mkdirat",
    "rmdir",
    "creat",
    "link",
    "linkat",
    "symlink",
    "symlinkat",
    "chmod",
    "fchmod",
    "fchmodat",
    "chown",
    "fchown",
    "fchownat",
    "lchown",
    "truncate",
    "ftruncate",
    "pwrite64",
    "writev",
];

/// Syscall names that indicate network capability.
const NETWORK_SYSCALLS: &[&str] = &[
    "socket",
    "connect",
    "bind",
    "listen",
    "accept",
    "accept4",
    "sendto",
    "recvfrom",
    "sendmsg",
    "recvmsg",
    "shutdown",
    "setsockopt",
    "getsockopt",
    "socketpair",
    "getsockname",
    "getpeername",
];

/// Syscall names that indicate process execution capability.
const PROCESS_SYSCALLS: &[&str] = &["execve", "execveat", "fork", "vfork", "clone", "clone3"];

/// DB connection string patterns to look for in URLs.
const DB_URL_PATTERNS: &[&str] = &[
    "postgres://",
    "postgresql://",
    "mysql://",
    "mongodb://",
    "redis://",
    "sqlite://",
    "mssql://",
];

/// Check if the capability profile has evidence for the given permission.
fn capability_supports(cap: &CapabilityProfile, perm: &Permission) -> bool {
    match perm {
        Permission::FileRead => {
            cap.symbols.risk_flags.file_system || has_any_syscall(cap, FS_READ_SYSCALLS)
        }
        Permission::FileWrite => {
            cap.symbols.risk_flags.file_system || has_any_syscall(cap, FS_WRITE_SYSCALLS)
        }
        Permission::NetworkOutbound => {
            cap.symbols.risk_flags.network || has_any_syscall(cap, NETWORK_SYSCALLS)
        }
        Permission::ProcessExec => {
            cap.symbols.risk_flags.process || has_any_syscall(cap, PROCESS_SYSCALLS)
        }
        Permission::DatabaseAccess => has_db_url_in_strings(cap) || cap.symbols.risk_flags.network,
        Permission::Unknown => false, // always Case C
    }
}

/// Check if any resolved syscall matches one of the given names.
fn has_any_syscall(cap: &CapabilityProfile, names: &[&str]) -> bool {
    cap.syscalls.iter().any(|sc| {
        sc.syscall_name
            .as_deref()
            .is_some_and(|n| names.contains(&n))
    })
}

/// Check if any URL in the string findings matches a DB connection pattern.
fn has_db_url_in_strings(cap: &CapabilityProfile) -> bool {
    cap.strings.urls.iter().any(|url| {
        let lower = url.to_lowercase();
        DB_URL_PATTERNS.iter().any(|pat| lower.starts_with(pat))
    })
}

/// Detect which "excess" capabilities exist in the binary
/// (capabilities not required by any intent).
fn detect_excess_capabilities(
    cap: &CapabilityProfile,
    intents: &[IntentProfile],
) -> Vec<(Permission, String)> {
    let mut excess = Vec::new();

    // Collect all permissions required by intents
    let all_required: Vec<&Permission> = intents
        .iter()
        .flat_map(|i| &i.required_permissions)
        .collect();

    // Check for excess process execution
    if has_any_syscall(cap, PROCESS_SYSCALLS) && !all_required.contains(&&Permission::ProcessExec) {
        let found: Vec<&str> = cap
            .syscalls
            .iter()
            .filter_map(|sc| sc.syscall_name.as_deref())
            .filter(|n| PROCESS_SYSCALLS.contains(n))
            .collect();
        excess.push((
            Permission::ProcessExec,
            format!(
                "Binary has process execution syscalls ({}) but no tool requires ProcessExec",
                found.join(", ")
            ),
        ));
    }

    // Check for excess network
    if (has_any_syscall(cap, NETWORK_SYSCALLS) || cap.symbols.risk_flags.network)
        && !all_required.contains(&&Permission::NetworkOutbound)
        && !all_required.contains(&&Permission::DatabaseAccess)
    {
        let mut reasons = Vec::new();
        if cap.symbols.risk_flags.network {
            reasons.push("network symbols".to_string());
        }
        let net_sc: Vec<&str> = cap
            .syscalls
            .iter()
            .filter_map(|sc| sc.syscall_name.as_deref())
            .filter(|n| NETWORK_SYSCALLS.contains(n))
            .collect();
        if !net_sc.is_empty() {
            reasons.push(format!("syscalls ({})", net_sc.join(", ")));
        }
        excess.push((
            Permission::NetworkOutbound,
            format!(
                "Binary has network capabilities ({}) but no tool requires NetworkOutbound",
                reasons.join(", ")
            ),
        ));
    }

    // Check for excess file-write
    if (has_any_syscall(cap, FS_WRITE_SYSCALLS) || cap.symbols.risk_flags.file_system)
        && !all_required.contains(&&Permission::FileWrite)
        && !all_required.contains(&&Permission::FileRead)
    {
        excess.push((
            Permission::FileWrite,
            "Binary has file system capabilities but no tool requires FileRead or FileWrite"
                .to_string(),
        ));
    }

    excess
}

/// Cross-validate Capability (from binary analysis) against Intent (from tool definitions).
///
/// Produces three categories of verdicts:
/// - **Case A** (allowed): Intent requires the permission and the binary has matching capability.
/// - **Case B** (blocked): Binary has capability but no tool requested the corresponding permission.
/// - **Case C** (warnings): Tool requests a permission not evidenced in binary capabilities.
pub fn cross_validate(
    capability: &CapabilityProfile,
    intents: &[IntentProfile],
) -> CrossValidationResult {
    let mut allowed = Vec::new();
    let mut warnings = Vec::new();

    // For each intent, check each required permission
    for intent in intents {
        for perm in &intent.required_permissions {
            if capability_supports(capability, perm) {
                allowed.push(PermissionVerdict {
                    permission: perm.clone(),
                    tool_name: Some(intent.tool_name.clone()),
                    reason: format!(
                        "Capability({}) intersects Intent({}) for tool '{}'",
                        perm, perm, intent.tool_name
                    ),
                    case: VerdictCase::A,
                });
            } else {
                warnings.push(PermissionVerdict {
                    permission: perm.clone(),
                    tool_name: Some(intent.tool_name.clone()),
                    reason: format!(
                        "Tool '{}' requires {} but binary lacks matching capability",
                        intent.tool_name, perm
                    ),
                    case: VerdictCase::C,
                });
            }
        }
    }

    // Detect excess capabilities (Case B)
    let excess = detect_excess_capabilities(capability, intents);
    let blocked: Vec<PermissionVerdict> = excess
        .into_iter()
        .map(|(perm, reason)| PermissionVerdict {
            permission: perm,
            tool_name: None,
            reason,
            case: VerdictCase::B,
        })
        .collect();

    CrossValidationResult {
        allowed,
        blocked,
        warnings,
    }
}

fn is_read_named(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    const PREFIXES: &[&str] = &["get_", "list_", "find_", "read_", "fetch_", "search_"];
    const EXACT: &[&str] = &["get", "list", "find", "read", "fetch", "search"];
    PREFIXES.iter().any(|p| n.starts_with(p)) || EXACT.contains(&n.as_str())
}

fn intent_claims_exec(intent: Option<&IntentProfile>) -> bool {
    intent.is_some_and(|i| i.required_permissions.contains(&Permission::ProcessExec))
}

fn read_only_claim(tool_name: &str, intent: Option<&IntentProfile>) -> bool {
    if intent_claims_exec(intent) {
        return false;
    }
    if is_read_named(tool_name) {
        return true;
    }
    match intent {
        Some(i) => {
            !i.required_permissions.is_empty()
                && i.required_permissions
                    .iter()
                    .all(|p| matches!(p, Permission::FileRead | Permission::Unknown))
        }
        None => false,
    }
}

/// Cross-validate per-tool AST Capability against tools/list Intent.
///
/// ELF `CapabilityProfile` is not reshaped. Interpreters use this path so
/// CPython/Node syscalls are never treated as MCP server Capability.
pub fn cross_validate_source(
    tool_caps: &[ToolCapability],
    intents: &[IntentProfile],
) -> CrossValidationResult {
    let mut allowed = Vec::new();
    let mut blocked = Vec::new();
    let mut warnings = Vec::new();
    let mut seen = std::collections::HashSet::new();

    for cap in tool_caps {
        seen.insert(cap.tool_name.clone());
        let intent = intents.iter().find(|i| i.tool_name == cap.tool_name);

        if !cap.bound {
            warnings.push(PermissionVerdict {
                permission: Permission::Unknown,
                tool_name: Some(cap.tool_name.clone()),
                reason: cap.warning.clone().unwrap_or_else(|| {
                    format!(
                        "Tool '{}' is Unbound; Capability is not proven",
                        cap.tool_name
                    )
                }),
                case: VerdictCase::C,
            });
            continue;
        }

        let deny_exec = cap.permissions.contains(&Permission::ProcessExec)
            && (read_only_claim(&cap.tool_name, intent)
                || (intent.is_some() && !intent_claims_exec(intent)));

        if deny_exec {
            blocked.push(PermissionVerdict {
                permission: Permission::ProcessExec,
                tool_name: Some(cap.tool_name.clone()),
                reason: format!(
                    "Tool '{}' claims read-only/read-named intent but source has ProcessExec",
                    cap.tool_name
                ),
                case: VerdictCase::B,
            });
        }

        for perm in &cap.permissions {
            if deny_exec && *perm == Permission::ProcessExec {
                continue;
            }
            allowed.push(PermissionVerdict {
                permission: perm.clone(),
                tool_name: Some(cap.tool_name.clone()),
                reason: format!("Source Capability({}) for tool '{}'", perm, cap.tool_name),
                case: VerdictCase::A,
            });
        }

        if let Some(intent) = intent {
            for perm in &intent.required_permissions {
                let proven = cap.permissions.contains(perm);
                if !proven {
                    warnings.push(PermissionVerdict {
                        permission: perm.clone(),
                        tool_name: Some(cap.tool_name.clone()),
                        reason: format!(
                            "Tool '{}' requires {} but source lacks a matching sink",
                            intent.tool_name, perm
                        ),
                        case: VerdictCase::C,
                    });
                }
            }
        }

        for risk in &cap.audit_risks {
            warnings.push(PermissionVerdict {
                permission: Permission::Unknown,
                tool_name: Some(cap.tool_name.clone()),
                reason: format!(
                    "Tool '{}' has dynamic-code/deserialization audit risk ({risk}); not ProcessExec",
                    cap.tool_name
                ),
                case: VerdictCase::C,
            });
        }
    }

    for intent in intents {
        if seen.contains(&intent.tool_name) {
            continue;
        }
        for perm in &intent.required_permissions {
            warnings.push(PermissionVerdict {
                permission: perm.clone(),
                tool_name: Some(intent.tool_name.clone()),
                reason: format!(
                    "Tool '{}' is not bound to a literal handler; Capability is not proven",
                    intent.tool_name
                ),
                case: VerdictCase::C,
            });
        }
    }

    CrossValidationResult {
        allowed,
        blocked,
        warnings,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inspector::disasm::SyscallSite;
    use crate::inspector::elf_parser::{RiskFlags, SymbolProfile};
    use crate::inspector::slicer::{Resolution, ResolvedSyscall};
    use crate::inspector::strings::StringFindings;
    use crate::legislator::heuristics::{Confidence, IntentProfile, Permission, RiskLevel};

    fn make_capability(
        risk_flags: RiskFlags,
        syscall_names: &[&str],
        urls: Vec<&str>,
        paths: Vec<&str>,
    ) -> CapabilityProfile {
        let syscalls: Vec<ResolvedSyscall> = syscall_names
            .iter()
            .enumerate()
            .map(|(i, name)| ResolvedSyscall {
                site: SyscallSite {
                    address: 0x1000 + i as u64 * 0x10,
                    offset_in_section: i as u64 * 0x10,
                },
                syscall_number: Some(i as u64),
                syscall_name: Some(name.to_string()),
                resolution: Resolution::Resolved,
            })
            .collect();

        CapabilityProfile {
            analysis: crate::inspector::target::AnalysisReport::analyzed_linux_x86_64(),
            symbols: SymbolProfile {
                libraries: vec![],
                imports: vec![],
                risk_flags,
                is_stripped: false,
            },
            syscalls,
            strings: StringFindings {
                urls: urls.into_iter().map(String::from).collect(),
                paths: paths.into_iter().map(String::from).collect(),
                env_vars: vec![],
            },
            risk_score: 0,
            risk_summary: vec![],
        }
    }

    fn make_intent(tool_name: &str, perms: Vec<Permission>) -> IntentProfile {
        IntentProfile {
            tool_name: tool_name.to_string(),
            required_permissions: perms,
            confidence: Confidence::High,
            risk_level: RiskLevel::Medium,
        }
    }

    // === Case A: Intent + Capability match ===

    #[test]
    fn test_case_a_file_read_with_fs_syscall() {
        let cap = make_capability(RiskFlags::default(), &["read", "openat"], vec![], vec![]);
        let intents = vec![make_intent("read_file", vec![Permission::FileRead])];
        let result = cross_validate(&cap, &intents);

        assert_eq!(result.allowed.len(), 1);
        assert_eq!(result.allowed[0].case, VerdictCase::A);
        assert_eq!(result.allowed[0].permission, Permission::FileRead);
        assert!(result.warnings.is_empty());
    }

    #[test]
    fn test_case_a_file_read_with_risk_flag() {
        let cap = make_capability(
            RiskFlags {
                file_system: true,
                ..Default::default()
            },
            &[],
            vec![],
            vec![],
        );
        let intents = vec![make_intent("read_file", vec![Permission::FileRead])];
        let result = cross_validate(&cap, &intents);

        assert_eq!(result.allowed.len(), 1);
        assert_eq!(result.allowed[0].case, VerdictCase::A);
    }

    #[test]
    fn test_case_a_network_outbound() {
        let cap = make_capability(RiskFlags::default(), &["socket", "connect"], vec![], vec![]);
        let intents = vec![make_intent("fetch_url", vec![Permission::NetworkOutbound])];
        let result = cross_validate(&cap, &intents);

        assert_eq!(result.allowed.len(), 1);
        assert_eq!(result.allowed[0].permission, Permission::NetworkOutbound);
    }

    #[test]
    fn test_case_a_process_exec() {
        let cap = make_capability(RiskFlags::default(), &["execve"], vec![], vec![]);
        let intents = vec![make_intent(
            "execute_command",
            vec![Permission::ProcessExec],
        )];
        let result = cross_validate(&cap, &intents);

        assert_eq!(result.allowed.len(), 1);
        assert_eq!(result.allowed[0].permission, Permission::ProcessExec);
    }

    #[test]
    fn test_case_a_database_access_via_url() {
        let cap = make_capability(
            RiskFlags::default(),
            &[],
            vec!["postgres://localhost:5432/mydb"],
            vec![],
        );
        let intents = vec![make_intent("query_db", vec![Permission::DatabaseAccess])];
        let result = cross_validate(&cap, &intents);

        assert_eq!(result.allowed.len(), 1);
        assert_eq!(result.allowed[0].permission, Permission::DatabaseAccess);
    }

    #[test]
    fn test_case_a_database_access_via_network_flag() {
        let cap = make_capability(
            RiskFlags {
                network: true,
                ..Default::default()
            },
            &[],
            vec![],
            vec![],
        );
        let intents = vec![make_intent("query_db", vec![Permission::DatabaseAccess])];
        let result = cross_validate(&cap, &intents);

        assert_eq!(result.allowed.len(), 1);
        assert_eq!(result.allowed[0].permission, Permission::DatabaseAccess);
    }

    // === Case B: Capability only (excess) ===

    #[test]
    fn test_case_b_excess_execve() {
        let cap = make_capability(RiskFlags::default(), &["execve", "read"], vec![], vec![]);
        let intents = vec![make_intent("read_file", vec![Permission::FileRead])];
        let result = cross_validate(&cap, &intents);

        assert!(!result.blocked.is_empty());
        let exec_blocked = result
            .blocked
            .iter()
            .find(|v| v.permission == Permission::ProcessExec);
        assert!(exec_blocked.is_some());
        assert_eq!(exec_blocked.unwrap().case, VerdictCase::B);
    }

    #[test]
    fn test_case_b_excess_socket() {
        let cap = make_capability(RiskFlags::default(), &["socket", "read"], vec![], vec![]);
        let intents = vec![make_intent("read_file", vec![Permission::FileRead])];
        let result = cross_validate(&cap, &intents);

        let net_blocked = result
            .blocked
            .iter()
            .find(|v| v.permission == Permission::NetworkOutbound);
        assert!(net_blocked.is_some());
        assert_eq!(net_blocked.unwrap().case, VerdictCase::B);
    }

    #[test]
    fn test_case_b_network_symbols_excess() {
        let cap = make_capability(
            RiskFlags {
                network: true,
                ..Default::default()
            },
            &["read"],
            vec![],
            vec![],
        );
        let intents = vec![make_intent("read_file", vec![Permission::FileRead])];
        let result = cross_validate(&cap, &intents);

        let net_blocked = result
            .blocked
            .iter()
            .find(|v| v.permission == Permission::NetworkOutbound);
        assert!(net_blocked.is_some());
    }

    // === Case C: Intent only (warning) ===

    #[test]
    fn test_case_c_intent_without_capability() {
        let cap = make_capability(RiskFlags::default(), &[], vec![], vec![]);
        let intents = vec![make_intent("fetch_url", vec![Permission::NetworkOutbound])];
        let result = cross_validate(&cap, &intents);

        assert!(result.allowed.is_empty());
        assert_eq!(result.warnings.len(), 1);
        assert_eq!(result.warnings[0].case, VerdictCase::C);
        assert_eq!(result.warnings[0].permission, Permission::NetworkOutbound);
    }

    #[test]
    fn test_case_c_unknown_permission() {
        let cap = make_capability(
            RiskFlags {
                file_system: true,
                ..Default::default()
            },
            &["read"],
            vec![],
            vec![],
        );
        let intents = vec![make_intent("mystery_tool", vec![Permission::Unknown])];
        let result = cross_validate(&cap, &intents);

        assert_eq!(result.warnings.len(), 1);
        assert_eq!(result.warnings[0].permission, Permission::Unknown);
        assert_eq!(result.warnings[0].case, VerdictCase::C);
    }

    // === Multi-tool / multi-permission combinations ===

    #[test]
    fn test_multiple_tools_multiple_permissions() {
        let cap = make_capability(
            RiskFlags {
                file_system: true,
                ..Default::default()
            },
            &["read", "openat", "socket"],
            vec![],
            vec![],
        );
        let intents = vec![
            make_intent("read_file", vec![Permission::FileRead]),
            make_intent("fetch_url", vec![Permission::NetworkOutbound]),
            make_intent("execute_command", vec![Permission::ProcessExec]),
        ];
        let result = cross_validate(&cap, &intents);

        // FileRead → Case A (fs flag + read syscall)
        assert!(
            result
                .allowed
                .iter()
                .any(|v| v.permission == Permission::FileRead)
        );
        // NetworkOutbound → Case A (socket syscall)
        assert!(
            result
                .allowed
                .iter()
                .any(|v| v.permission == Permission::NetworkOutbound)
        );
        // ProcessExec → Case C (no execve)
        assert!(
            result
                .warnings
                .iter()
                .any(|v| v.permission == Permission::ProcessExec)
        );
    }

    #[test]
    fn test_tool_with_multiple_permissions() {
        let cap = make_capability(
            RiskFlags {
                file_system: true,
                ..Default::default()
            },
            &["read", "write"],
            vec![],
            vec![],
        );
        let intents = vec![make_intent(
            "move_file",
            vec![Permission::FileRead, Permission::FileWrite],
        )];
        let result = cross_validate(&cap, &intents);

        assert_eq!(result.allowed.len(), 2);
        assert!(
            result
                .allowed
                .iter()
                .any(|v| v.permission == Permission::FileRead)
        );
        assert!(
            result
                .allowed
                .iter()
                .any(|v| v.permission == Permission::FileWrite)
        );
    }

    // === Edge cases ===

    #[test]
    fn test_empty_capability_empty_intents() {
        let cap = make_capability(RiskFlags::default(), &[], vec![], vec![]);
        let result = cross_validate(&cap, &[]);

        assert!(result.allowed.is_empty());
        assert!(result.blocked.is_empty());
        assert!(result.warnings.is_empty());
    }

    #[test]
    fn test_empty_intents_with_capabilities() {
        let cap = make_capability(RiskFlags::default(), &["execve", "socket"], vec![], vec![]);
        let result = cross_validate(&cap, &[]);

        assert!(result.allowed.is_empty());
        assert!(result.warnings.is_empty());
        // Should detect excess capabilities
        assert!(!result.blocked.is_empty());
    }

    #[test]
    fn test_empty_capability_with_intents() {
        let cap = make_capability(RiskFlags::default(), &[], vec![], vec![]);
        let intents = vec![
            make_intent("read_file", vec![Permission::FileRead]),
            make_intent("fetch_url", vec![Permission::NetworkOutbound]),
        ];
        let result = cross_validate(&cap, &intents);

        assert!(result.allowed.is_empty());
        assert!(result.blocked.is_empty());
        assert_eq!(result.warnings.len(), 2);
    }

    #[test]
    fn test_all_permission_types_mapping() {
        // Verify each permission type can be matched via appropriate capability
        let cap = make_capability(
            RiskFlags {
                network: true,
                file_system: true,
                process: true,
                crypto: false,
                memory: false,
            },
            &["read", "write", "socket", "connect", "execve", "fork"],
            vec!["postgres://localhost/db"],
            vec![],
        );

        let intents = vec![
            make_intent("t1", vec![Permission::FileRead]),
            make_intent("t2", vec![Permission::FileWrite]),
            make_intent("t3", vec![Permission::NetworkOutbound]),
            make_intent("t4", vec![Permission::ProcessExec]),
            make_intent("t5", vec![Permission::DatabaseAccess]),
        ];
        let result = cross_validate(&cap, &intents);

        // All 5 permissions should be in allowed (Case A)
        assert_eq!(result.allowed.len(), 5);
        assert!(result.warnings.is_empty());
    }

    #[test]
    fn test_file_write_syscall_mapping() {
        let cap = make_capability(RiskFlags::default(), &["unlink", "rename"], vec![], vec![]);
        let intents = vec![make_intent("delete_file", vec![Permission::FileWrite])];
        let result = cross_validate(&cap, &intents);

        assert_eq!(result.allowed.len(), 1);
        assert_eq!(result.allowed[0].permission, Permission::FileWrite);
    }

    fn source_cap(name: &str, perms: Vec<Permission>, bound: bool) -> ToolCapability {
        ToolCapability {
            tool_name: name.into(),
            permissions: perms,
            bound,
            audit_risks: vec![],
            warning: if bound {
                None
            } else {
                Some(format!("Unbound: {name}"))
            },
        }
    }

    #[test]
    fn source_read_name_plus_subprocess_is_deny() {
        let tools = vec![source_cap("read_file", vec![Permission::ProcessExec], true)];
        let result = cross_validate_source(&tools, &[]);
        assert!(
            result
                .blocked
                .iter()
                .any(|v| v.tool_name.as_deref() == Some("read_file")
                    && v.permission == Permission::ProcessExec),
            "{result:?}"
        );
    }

    #[test]
    fn source_unbound_is_case_c() {
        let tools = vec![source_cap("dynamic", vec![], false)];
        let result = cross_validate_source(&tools, &[]);
        assert!(result.blocked.is_empty());
        assert!(result.warnings.iter().any(|v| v.case == VerdictCase::C));
    }

    #[test]
    fn source_eval_risk_is_not_process_exec_block() {
        let tools = vec![ToolCapability {
            tool_name: "read_file".into(),
            permissions: vec![Permission::FileRead],
            bound: true,
            audit_risks: vec!["eval".into()],
            warning: None,
        }];
        let result = cross_validate_source(&tools, &[]);
        assert!(result.blocked.is_empty());
        assert!(result.warnings.iter().any(|v| v.reason.contains("eval")));
        assert!(
            !result
                .blocked
                .iter()
                .any(|v| v.permission == Permission::ProcessExec)
        );
    }

    #[test]
    fn native_elf_path_unchanged_with_empty_source_tools() {
        let cap = make_capability(RiskFlags::default(), &["read", "openat"], vec![], vec![]);
        let intents = vec![make_intent("read_file", vec![Permission::FileRead])];
        let result = cross_validate(&cap, &intents);
        assert_eq!(result.allowed.len(), 1);
        assert_eq!(result.allowed[0].case, VerdictCase::A);
    }
}
