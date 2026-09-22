pub(crate) mod host;
pub mod kdl_canon;
mod kdl_emit;
mod kdl_inherit;
pub mod kdl_loader;
mod kdl_parse;
pub mod loader;
pub mod merge;
pub mod validator;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Policy {
    pub version: u32,
    pub transport: TransportConfig,
    pub tools: Vec<ToolPolicy>,
    pub fs: FsPolicy,
    pub syscalls: SyscallPolicy,
    pub network: NetworkPolicy,
    /// Environment the spawned server child receives (`defaults.environment`).
    /// `restrict == false` keeps the default full parent-env inheritance.
    pub environment: EnvironmentPolicy,
    pub logging: LoggingPolicy,
    pub sandbox: SandboxPolicy,
    pub confused_deputy_protection: bool,
    /// Opt-in process-local trajectory rules. Default off (omitted = current behavior).
    pub trajectory: bool,
    /// Ordered `after` children of `trajectory`. Property order is not significant.
    pub trajectory_rules: Vec<TrajectoryRule>,
    pub hash_entries: Vec<HashEntry>,
    pub tools_list_hashes: Vec<ToolsListHashEntry>,
}

/// One deterministic cross-tool trajectory rule (`after` child of `trajectory`).
///
/// Properties are name-keyed (`side_effect`, `deny-next`). Child node order is
/// significant; property appearance order is not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrajectoryRule {
    pub after_side_effect: SideEffect,
    pub deny_next: SideEffect,
}

/// OS-sandbox degradation policy. Default is fail-closed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SandboxPolicy {
    /// When true, Landlock NotEnforced/Partial states are allowed. Default false.
    pub allow_degraded: bool,
}

/// Child-process environment policy (`defaults { environment { ... } }`).
///
/// Default (`restrict: false`, empty `allowed`) inherits the parent
/// environment unchanged at spawn. When `restrict` is true — i.e. the
/// `environment` node was declared — the child receives only the launch
/// contract's base set (`PATH`, the Windows system roots, and the
/// `TMPDIR`/`TMP`/`TEMP` override when one is configured) plus each
/// `allowed` name that exists in the parent environment; a listed name
/// missing from the parent stays unset.
///
/// This is a launch contract, not OS sandboxing: it applies in dry-run and
/// `MCP_WRIT_SKIP_SANDBOX` modes as well.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EnvironmentPolicy {
    /// `defaults { environment { ... } }` was declared: restrict the child's
    /// environment to the base set plus `allowed` names.
    pub restrict: bool,
    /// Parent-environment variable names copied to the child when present.
    pub allowed: Vec<String>,
}

/// Type of hash entry in the KDL policy for supply chain verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashType {
    /// Native binary hash (ELF/Mach-O)
    Binary,
    /// Lock file hash (package-lock.json, requirements.txt, etc.)
    Lockfile,
    /// Entry point hash (index.js, main.py, etc.)
    Entrypoint,
    /// Docker image manifest digest
    DockerManifest,
}

impl HashType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Binary => "binary-hash",
            Self::Lockfile => "lockfile-hash",
            Self::Entrypoint => "entrypoint-hash",
            Self::DockerManifest => "docker-manifest-hash",
        }
    }
}

/// A hash entry parsed from a KDL policy `server` block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HashEntry {
    pub server_name: String,
    pub hash_type: HashType,
    pub hash_value: String,
    pub target: String,
    pub approved: Option<String>,
}

/// A tools-list-hash entry parsed from a KDL policy `server` block.
/// Used for supply chain verification of MCP server tool definitions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolsListHashEntry {
    pub server_name: String,
    pub hash_value: String,
    pub approved: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransportConfig {
    pub type_: TransportType,
    pub listen_addr: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransportType {
    Stdio,
    Http,
}

/// Error type for parsing [`TransportType`] from a string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransportParseError {
    pub input: String,
}

impl std::fmt::Display for TransportParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "unknown transport type '{}', expected 'stdio' or 'http'",
            self.input
        )
    }
}

impl std::error::Error for TransportParseError {}

impl std::str::FromStr for TransportType {
    type Err = TransportParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "stdio" => Ok(Self::Stdio),
            "http" => Ok(Self::Http),
            _ => Err(TransportParseError {
                input: s.to_string(),
            }),
        }
    }
}

impl TransportType {
    pub fn as_str(&self) -> &str {
        match self {
            Self::Stdio => "stdio",
            Self::Http => "http",
        }
    }
}

/// How the Auditor treats MCP MRTR `params.inputResponses` on `tools/call`.
///
/// `inputResponses` is a sibling of `params.arguments` and is therefore **not**
/// covered by `args_schema`. Elicitation content (secrets, “user confirmed
/// delete”, extra paths) would otherwise bypass the same security intent.
///
/// Secure default (`Auto`):
/// - `args_schema` is set → treat as [`InputResponsesMode::Deny`]
/// - no schema → treat as [`InputResponsesMode::Allow`] (nothing to bypass)
///
/// Spec: <https://modelcontextprotocol.io/specification/2026-07-28/basic/patterns/mrtr>
/// and <https://modelcontextprotocol.io/specification/2026-07-28/server/tools>
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum InputResponsesMode {
    /// Implicit secure default (see type docs).
    #[default]
    Auto,
    /// Reject the `tools/call` if `inputResponses` is present.
    Deny,
    /// Pass `inputResponses` through without schema inspection.
    Allow,
    /// Pass through, but record presence in the audit log.
    Inspect,
}

impl InputResponsesMode {
    /// Parse a KDL `input_responses` property value.
    pub fn parse_kdl(value: &str) -> Result<Self, String> {
        match value {
            "auto" => Ok(Self::Auto),
            "deny" => Ok(Self::Deny),
            "allow" => Ok(Self::Allow),
            "inspect" => Ok(Self::Inspect),
            other => Err(format!(
                "invalid input_responses '{other}', expected auto|deny|allow|inspect"
            )),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Deny => "deny",
            Self::Allow => "allow",
            Self::Inspect => "inspect",
        }
    }

    /// Resolve `Auto` using whether any security-sensitive tool contract exists.
    ///
    /// `args_schema`, filesystem, network, syscall, or side-effect contracts all
    /// mean `inputResponses` could bypass the same intent.
    pub fn resolve(self, has_security_contract: bool) -> ResolvedInputResponses {
        match self {
            Self::Auto => {
                if has_security_contract {
                    ResolvedInputResponses::Deny
                } else {
                    ResolvedInputResponses::Allow
                }
            }
            Self::Deny => ResolvedInputResponses::Deny,
            Self::Allow => ResolvedInputResponses::Allow,
            Self::Inspect => ResolvedInputResponses::Inspect,
        }
    }
}

/// Effective `inputResponses` decision after resolving [`InputResponsesMode::Auto`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolvedInputResponses {
    Deny,
    Allow,
    Inspect,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolPolicy {
    pub name: String,
    pub allowed: bool,
    pub args_schema: Option<String>,
    pub side_effect: Option<String>,
    pub server: Option<String>,
    pub fs: Option<FsToolPolicy>,
    pub syscalls: Option<ToolSyscallPolicy>,
    pub network: Option<ToolNetworkPolicy>,
    pub input_responses: InputResponsesMode,
    /// True when `input_responses` was written in source (including explicit `auto`).
    pub input_responses_specified: bool,
    /// True when this tool declared its own `filesystem` block.
    pub fs_explicit: bool,
    /// True when this tool declared its own `network` block.
    pub network_explicit: bool,
    /// True when this tool declared its own `syscalls` block.
    pub syscalls_explicit: bool,
    /// True when an `environment` block appeared under this tool, its
    /// profile, or its server-defaults. Per-tool environment is not
    /// enforced; the validator rejects it at load time.
    pub environment_explicit: bool,
    /// True when a `process` block grants exec (`deny-all #false` or an allow).
    pub process_exec_allowed: bool,
    /// True when this tool declared its own `process` block (including deny-all).
    pub process_explicit: bool,
}

impl ToolPolicy {
    /// Construct a tool policy with optional fields unset and `input_responses = Auto`.
    pub fn named(name: impl Into<String>, allowed: bool) -> Self {
        Self {
            name: name.into(),
            allowed,
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
        }
    }

    /// True when this tool has a contract that `inputResponses` could bypass.
    pub fn has_security_contract(&self) -> bool {
        self.args_schema.is_some()
            || self.side_effect.is_some()
            || self.fs.as_ref().is_some_and(|fs| {
                fs.allow_specified
                    || fs.require_path.is_some()
                    || !fs.allowed_paths.is_empty()
                    || !fs.denied_paths.is_empty()
            })
            || self.network.as_ref().is_some_and(|net| {
                net.allow_specified || !net.allowed_hosts.is_empty() || !net.denied_hosts.is_empty()
            })
            || self
                .syscalls
                .as_ref()
                .is_some_and(|sc| !sc.allowed.is_empty() || !sc.denied.is_empty())
    }

    /// Effective `input_responses` mode after treating unspecified as Auto.
    pub fn input_responses_mode(&self) -> InputResponsesMode {
        self.input_responses
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ToolSyscallPolicy {
    pub allowed: Vec<String>,
    pub denied: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ToolNetworkPolicy {
    pub allowed_hosts: Vec<String>,
    pub denied_hosts: Vec<String>,
    pub allow_specified: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FsToolPolicy {
    pub allowed_paths: Vec<String>,
    pub read_only_paths: Vec<String>,
    pub read_write_paths: Vec<String>,
    pub denied_paths: Vec<String>,
    pub allow_specified: bool,
    /// Tool/profile-only opt-in. None preserves the mandatory-path default.
    /// False is valid only with an explicitly empty filesystem allow-list.
    pub require_path: Option<bool>,
}

impl FsToolPolicy {
    pub fn new(allowed_paths: Vec<String>, denied_paths: Vec<String>) -> Self {
        let allow_specified = !allowed_paths.is_empty();
        Self {
            allowed_paths: allowed_paths.clone(),
            read_only_paths: allowed_paths,
            read_write_paths: Vec::new(),
            denied_paths,
            allow_specified,
            require_path: None,
        }
    }

    /// No target is needed only when the policy explicitly forbids every path.
    /// Keep this guard in the checker as well as load-time validation.
    pub fn allows_pathless_call(&self) -> bool {
        self.require_path == Some(false)
            && self.allow_specified
            && self.allowed_paths.is_empty()
            && self.read_only_paths.is_empty()
            && self.read_write_paths.is_empty()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FsPolicy {
    pub read_only: Vec<String>,
    pub read_write: Vec<String>,
    pub denied_paths: Vec<String>,
    /// True when a layer specified at least one global allow rule.
    pub allow_specified: bool,
    /// Default-on overlay: well-known secret paths are denied even when an
    /// explicit allow glob would match. KDL `secret-overlay #false` disables.
    pub secret_overlay: bool,
}

impl Default for FsPolicy {
    fn default() -> Self {
        Self {
            read_only: Vec::new(),
            read_write: Vec::new(),
            denied_paths: Vec::new(),
            allow_specified: false,
            secret_overlay: true,
        }
    }
}

/// Documented `side_effect` values. Unknown strings are a load error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SideEffect {
    ReadOnly,
    Write,
    Network,
    Execute,
}

impl SideEffect {
    /// Parse a KDL `side_effect` property. Unknown values fail closed.
    pub fn parse(value: &str) -> Result<Self, String> {
        match value {
            "read_only" => Ok(Self::ReadOnly),
            "write" => Ok(Self::Write),
            "network" => Ok(Self::Network),
            "execute" => Ok(Self::Execute),
            other => Err(format!(
                "unknown side_effect '{other}', expected read_only|write|network|execute"
            )),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::ReadOnly => "read_only",
            Self::Write => "write",
            Self::Network => "network",
            Self::Execute => "execute",
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SyscallPolicy {
    pub allowed: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NetworkPolicy {
    pub outbound: OutboundPolicy,
    pub inbound: InboundPolicy,
}

/// Separate listen/bind authorization from outbound client access.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct InboundPolicy {
    /// When true, the OS sandbox may grant listener/server capabilities.
    pub allow_listen: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboundPolicy {
    pub allowed: Vec<String>,
    pub denied_hosts: Vec<String>,
    pub deny_all_others: bool,
}

impl Default for OutboundPolicy {
    fn default() -> Self {
        Self {
            allowed: Vec::new(),
            denied_hosts: Vec::new(),
            deny_all_others: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoggingPolicy {
    pub level: String,
    /// When true (default), audit channel/write failures fail closed.
    pub fail_closed: bool,
}

impl Default for LoggingPolicy {
    fn default() -> Self {
        Self {
            level: "info".to_string(),
            fail_closed: true,
        }
    }
}

/// Remove allowed destinations that are covered by a deny rule.
pub fn apply_outbound_deny_precedence(outbound: &mut OutboundPolicy) {
    outbound.allowed.retain(|allowed| {
        !outbound
            .denied_hosts
            .iter()
            .any(|denied| host_covered_by_deny(allowed, denied))
    });
}

/// Apply the same wildcard-aware deny reducer to a per-tool network policy.
pub fn apply_tool_network_deny_precedence(network: &mut ToolNetworkPolicy) {
    network.allowed_hosts.retain(|allowed| {
        !network
            .denied_hosts
            .iter()
            .any(|denied| host_covered_by_deny(allowed, denied))
    });
}

pub fn host_covered_by_deny(allowed: &str, denied: &str) -> bool {
    let a = canonicalize_policy_host(allowed);
    let d = canonicalize_policy_host(denied);
    if d == "*" || a == d {
        return true;
    }
    if let Some(suffix) = d.strip_prefix("*.") {
        let with_dot = format!(".{suffix}");
        return a == suffix || a.ends_with(&with_dot);
    }
    false
}

/// Lowercase, strip a trailing DNS root dot, and fold decimal/hex IPv4 forms.
pub fn canonicalize_policy_host(host: &str) -> String {
    let trimmed = host.trim().trim_end_matches('.').to_ascii_lowercase();
    if let Some(ipv4) = parse_ipv4_like(&trimmed) {
        return ipv4;
    }
    trimmed
}

fn parse_ipv4_like(host: &str) -> Option<String> {
    if host.contains(':') || host.contains('/') {
        return None;
    }
    let parts: Vec<&str> = host.split('.').collect();
    if parts.is_empty() || parts.len() > 4 {
        return None;
    }
    let mut nums = Vec::with_capacity(parts.len());
    for part in &parts {
        nums.push(parse_ipv4_component(part)?);
    }
    let addr = match nums.as_slice() {
        [a] => *a,
        [a, b] => (*a << 24) | *b,
        [a, b, c] => (*a << 24) | (*b << 16) | *c,
        [a, b, c, d] => (*a << 24) | (*b << 16) | (*c << 8) | *d,
        _ => return None,
    };
    Some(format!(
        "{}.{}.{}.{}",
        (addr >> 24) & 0xff,
        (addr >> 16) & 0xff,
        (addr >> 8) & 0xff,
        addr & 0xff
    ))
}

fn parse_ipv4_component(part: &str) -> Option<u32> {
    if part.is_empty() {
        return None;
    }
    let value = if let Some(hex) = part.strip_prefix("0x") {
        u32::from_str_radix(hex, 16).ok()?
    } else if part.len() > 1 && part.starts_with('0') && part.bytes().all(|b| b.is_ascii_digit()) {
        u32::from_str_radix(part, 8).ok()?
    } else {
        part.parse().ok()?
    };
    (value <= 255).then_some(value)
}

/// Map a policy `logging.level` value to a tracing level.
///
/// Unknown values fall back to `info`. `warning` is accepted as an alias of `warn`.
pub fn tracing_level_from_policy(level: &str) -> tracing::Level {
    match level.to_ascii_lowercase().as_str() {
        "error" => tracing::Level::ERROR,
        "warn" | "warning" => tracing::Level::WARN,
        "debug" => tracing::Level::DEBUG,
        "trace" => tracing::Level::TRACE,
        _ => tracing::Level::INFO,
    }
}

const SUPPORTED_VERSION: u32 = 1;

impl Default for Policy {
    fn default() -> Self {
        default_policy()
    }
}

impl Policy {
    /// Validate for the OS this process runs on (native compatibility).
    /// Use [`Policy::validate_for_target`] when the workload runs under a
    /// different OS (e.g. a container guest).
    pub fn validate(&self) -> Result<(), crate::error::PolicyError> {
        validator::validate_policy(self)
    }

    /// Validate against an explicit execution target — the workload's OS
    /// decides representability, not the build host.
    pub fn validate_for_target(
        &self,
        target: &crate::execution::ExecutionTarget,
    ) -> Result<(), crate::error::PolicyError> {
        validator::validate_policy_for_target(self, target)
    }

    /// Return a copy of the policy with all `@path` args_schema references loaded
    /// and replaced with inline JSON string contents, relative to `base_dir`.
    pub fn inlined_schemas(&self, base_dir: &std::path::Path) -> Result<Policy, String> {
        let mut policy = self.clone();
        for tool in &mut policy.tools {
            if let Some(ref schema_ref) = tool.args_schema
                && let Some(file_path) = schema_ref.strip_prefix('@')
            {
                let file_path = file_path.trim();
                let resolved = if std::path::Path::new(file_path).is_absolute() {
                    std::path::PathBuf::from(file_path)
                } else {
                    base_dir.join(file_path)
                };
                let content = std::fs::read_to_string(&resolved).map_err(|e| {
                    format!("failed to read schema file '{}': {e}", resolved.display())
                })?;
                tool.args_schema = Some(content);
            }
        }
        Ok(policy)
    }

    /// Unique server identities declared on tools and integrity entries.
    pub fn declared_servers(&self) -> Vec<String> {
        let mut names = std::collections::BTreeSet::new();
        for tool in &self.tools {
            if let Some(ref server) = tool.server {
                names.insert(server.clone());
            }
        }
        for entry in &self.hash_entries {
            names.insert(entry.server_name.clone());
        }
        for entry in &self.tools_list_hashes {
            names.insert(entry.server_name.clone());
        }
        names.into_iter().collect()
    }

    /// Bind this policy to exactly one server identity.
    ///
    /// Multi-server policies require `selector`. The returned policy retains
    /// only that server's tools and integrity records so Warden/Auditor cannot
    /// borrow another server's grants.
    pub fn bind_to_server(
        &self,
        selector: Option<&str>,
    ) -> Result<Policy, crate::error::PolicyError> {
        let servers = self.declared_servers();
        let selected = match (servers.as_slice(), selector) {
            ([], None) => return Ok(self.clone()),
            ([], Some(name)) => {
                return Err(crate::error::PolicyError::Validation(format!(
                    "unknown server '{name}'; policy declares no server identities"
                )));
            }
            ([only], None) => only.clone(),
            ([only], Some(name)) if name == only => only.clone(),
            ([only], Some(name)) => {
                return Err(crate::error::PolicyError::Validation(format!(
                    "unknown server '{name}'; policy declares '{only}'"
                )));
            }
            (_, None) => {
                return Err(crate::error::PolicyError::Validation(format!(
                    "policy declares multiple servers ({}); pass --server <name>",
                    servers.join(", ")
                )));
            }
            (_, Some(name)) if servers.iter().any(|s| s == name) => name.to_string(),
            (_, Some(name)) => {
                return Err(crate::error::PolicyError::Validation(format!(
                    "unknown server '{name}'; declared servers: {}",
                    servers.join(", ")
                )));
            }
        };

        let mut bound = self.clone();
        let unnamed_tools = self.tools.iter().any(|t| t.server.is_none());
        if unnamed_tools && !servers.is_empty() {
            return Err(crate::error::PolicyError::Validation(
                "policy mixes named server blocks with a nameless server block that declares tools"
                    .to_string(),
            ));
        }
        bound
            .tools
            .retain(|t| t.server.as_deref() == Some(selected.as_str()));
        bound.hash_entries.retain(|e| e.server_name == selected);
        bound
            .tools_list_hashes
            .retain(|e| e.server_name == selected);
        Ok(bound)
    }

    /// Serialize the effective policy into a self-contained KDL string.
    ///
    /// The resulting KDL has all inheritance (extends), includes, profiles,
    /// and server-defaults already merged into concrete rules, suitable for
    /// embedding into container images or environments without external files.
    pub fn to_kdl(&self) -> String {
        kdl_emit::to_kdl(self)
    }

    /// Serialize like [`Policy::to_kdl`] and prove the result round-trips:
    /// the emitted KDL is re-parsed, re-validated for `target`'s workload
    /// OS, and compared semantically against `self` so no control node is
    /// dropped silently on export.
    ///
    /// Fails closed: a policy whose effective state cannot be represented in
    /// the self-contained format is an error, not a lossy export.
    pub(crate) fn to_kdl_verified(
        &self,
        target: &crate::execution::ExecutionTarget,
    ) -> Result<String, crate::error::PolicyError> {
        let kdl = self.to_kdl();
        let reparsed = kdl_loader::parse_kdl_policy(&kdl).map_err(|e| {
            crate::error::PolicyError::Validation(format!(
                "self-contained KDL export does not re-parse: {e}"
            ))
        })?;
        validator::validate_policy_for_target(&reparsed, target).map_err(|e| {
            crate::error::PolicyError::Validation(format!(
                "self-contained KDL export fails validation for target '{}': {e}",
                target.workload_os.name()
            ))
        })?;
        if !kdl_emit::policies_equivalent_for_export(self, &reparsed) {
            return Err(crate::error::PolicyError::Validation(
                "self-contained KDL export does not reproduce the effective policy".to_string(),
            ));
        }
        Ok(kdl)
    }
}

pub fn default_policy() -> Policy {
    Policy {
        version: 1,
        transport: TransportConfig {
            type_: TransportType::Stdio,
            listen_addr: None,
        },
        tools: Vec::new(),
        fs: FsPolicy {
            read_only: Vec::new(),
            read_write: Vec::new(),
            denied_paths: Vec::new(),
            allow_specified: false,
            secret_overlay: true,
        },
        syscalls: SyscallPolicy {
            allowed: Vec::new(),
        },
        network: NetworkPolicy {
            outbound: OutboundPolicy {
                allowed: Vec::new(),
                denied_hosts: Vec::new(),
                deny_all_others: true,
            },
            inbound: InboundPolicy::default(),
        },
        environment: EnvironmentPolicy::default(),
        logging: LoggingPolicy::default(),
        sandbox: SandboxPolicy::default(),
        confused_deputy_protection: false,
        trajectory: false,
        trajectory_rules: Vec::new(),
        hash_entries: Vec::new(),
        tools_list_hashes: Vec::new(),
    }
}

#[cfg(test)]
mod input_responses_mode_tests {
    use super::{InputResponsesMode, ResolvedInputResponses};

    #[test]
    fn parse_and_as_str_roundtrip() {
        for raw in ["auto", "deny", "allow", "inspect"] {
            let mode = InputResponsesMode::parse_kdl(raw).unwrap();
            assert_eq!(mode.as_str(), raw);
            match mode {
                InputResponsesMode::Auto => assert_eq!(raw, "auto"),
                InputResponsesMode::Deny => assert_eq!(raw, "deny"),
                InputResponsesMode::Allow => assert_eq!(raw, "allow"),
                InputResponsesMode::Inspect => assert_eq!(raw, "inspect"),
            }
        }
        assert!(InputResponsesMode::parse_kdl("maybe").is_err());
    }

    #[test]
    fn side_effect_parse_and_as_str_roundtrip() {
        for raw in ["read_only", "write", "network", "execute"] {
            let se = super::SideEffect::parse(raw).unwrap();
            assert_eq!(se.as_str(), raw);
            match se {
                super::SideEffect::ReadOnly => assert_eq!(raw, "read_only"),
                super::SideEffect::Write => assert_eq!(raw, "write"),
                super::SideEffect::Network => assert_eq!(raw, "network"),
                super::SideEffect::Execute => assert_eq!(raw, "execute"),
            }
        }
        let err = super::SideEffect::parse("mutate").unwrap_err();
        assert!(err.contains("unknown side_effect"));
    }

    #[test]
    fn resolve_auto_depends_on_schema() {
        assert_eq!(
            InputResponsesMode::Auto.resolve(true),
            ResolvedInputResponses::Deny
        );
        assert_eq!(
            InputResponsesMode::Auto.resolve(false),
            ResolvedInputResponses::Allow
        );
    }
}

#[cfg(test)]
mod bind_to_server_tests {
    use super::*;
    use crate::error::PolicyError;

    #[test]
    fn mixed_named_and_unnamed_is_validation_error() {
        let mut policy = default_policy();
        let mut named = ToolPolicy::named("read_file", true);
        named.server = Some("fs".into());
        policy.tools.push(named);
        policy.tools.push(ToolPolicy::named("other", true));
        let err = policy.bind_to_server(Some("fs")).unwrap_err();
        assert!(matches!(err, PolicyError::Validation(_)));
    }

    #[test]
    fn named_only_filters_to_selected_server() {
        let mut policy = default_policy();
        let mut a = ToolPolicy::named("a", true);
        a.server = Some("fs".into());
        let mut b = ToolPolicy::named("b", true);
        b.server = Some("git".into());
        policy.tools.push(a);
        policy.tools.push(b);
        let bound = policy.bind_to_server(Some("fs")).unwrap();
        assert_eq!(bound.tools.len(), 1);
        assert_eq!(bound.tools[0].name, "a");
    }
}

#[cfg(test)]
mod host_canonicalization_tests {
    use super::canonicalize_policy_host;

    #[test]
    fn dotted_decimal_roundtrips() {
        assert_eq!(canonicalize_policy_host("127.0.0.1"), "127.0.0.1");
        assert_eq!(canonicalize_policy_host("010.0.0.1"), "8.0.0.1");
        assert_eq!(canonicalize_policy_host("0x7f.0.0.1"), "127.0.0.1");
    }

    #[test]
    fn out_of_range_components_are_not_folded() {
        assert_eq!(canonicalize_policy_host("1.256"), "1.256");
        assert_eq!(canonicalize_policy_host("1.0x100"), "1.0x100");
        assert_eq!(canonicalize_policy_host("256.1.1.1"), "256.1.1.1");
    }
}
