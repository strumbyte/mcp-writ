pub mod deputy;
pub(crate) mod host;
pub mod kdl_canon;
pub(crate) mod kdl_emit;
mod kdl_inherit;
pub mod kdl_loader;
pub(crate) mod kdl_parse;
pub(crate) mod kdl_strict;
pub mod provenance;

/// Per-file byte budget for a KDL policy document — configuration
/// text, not payload; anything larger is a flood, not a policy.
pub(crate) const MAX_POLICY_FILE_BYTES: u64 = 1024 * 1024;
/// Byte budget for `@file` tool-args schemas loaded beside policies.
pub(crate) const MAX_SCHEMA_FILE_BYTES: u64 = 1024 * 1024;
pub mod loader;
pub mod mcp;
pub mod merge;
mod outbound;
pub mod review;
pub mod validator;

pub use outbound::*;

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
    /// `mcp` passage rules per server (KDL schema v2 only). Independent
    /// of tool allow/deny: these rules govern MCP method passage, not
    /// tool execution.
    pub mcp_rules: Vec<mcp::ServerMcpRules>,
    /// The write log the KDL load left behind — which file set, unioned
    /// into, replaced, or pruned each effective field (`extends`,
    /// `include`, `when` composition). `None` for policies built
    /// directly or from the legacy JSON path. Shared via `Arc` so
    /// `bind_to_server` and launch-path clones keep it cheaply.
    pub provenance: Option<std::sync::Arc<provenance::PolicyProvenance>>,
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
/// Default (`restrict: true`, empty `allowed`, `inherit_parent: false`)
/// gives the child only the launch contract's base set (`PATH`, the
/// Windows system roots plus `LOCALAPPDATA` — required for AppContainer
/// spawns — and the `TMPDIR`/`TMP`/`TEMP` override when one is
/// configured); the parent environment is not inherited. `allow`
/// entries copy the named parent variables through the restricted
/// environment; a listed name missing from the parent stays unset.
///
/// Ambient inheritance is a deliberate downgrade and must be declared:
/// `defaults { environment { inherit-parent #true } }` sets
/// `inherit_parent` (and clears `restrict`), so the spawn passes the
/// parent environment through unchanged. The opt-in is recorded on the
/// launch record (`server.connected`) and launch report rather than
/// reading as a neutral default.
///
/// This is a launch contract, not OS sandboxing: it applies in dry-run and
/// `MCP_WRIT_SKIP_SANDBOX` modes as well.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvironmentPolicy {
    /// Restrict the child's environment to the base set plus `allowed`
    /// names. True unless `inherit_parent` was declared.
    pub restrict: bool,
    /// Parent-environment variable names copied to the child when present.
    pub allowed: Vec<String>,
    /// An `environment` node was declared — under `defaults` or inside a
    /// matching `when` block — making `allowed` authoritative even when
    /// empty. Without this marker an include/extends merge cannot tell
    /// "declared empty" apart from "never declared" and would inherit the
    /// other side's allow list instead of replacing it.
    pub declared: bool,
    /// `environment { inherit-parent #true }` was declared: the child
    /// inherits the parent environment unchanged. An explicit security
    /// downgrade — never combinable with `allowed` entries.
    pub inherit_parent: bool,
}

impl Default for EnvironmentPolicy {
    fn default() -> Self {
        Self {
            restrict: true,
            allowed: Vec::new(),
            declared: false,
            inherit_parent: false,
        }
    }
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
    /// `policy version=3`: this tool's `filesystem` block carried
    /// `replace=#true`, so it replaces (not unions) the accumulated
    /// allow side wherever the tool merges.
    pub fs_replace: bool,
    /// Same for the tool's `network` block.
    pub network_replace: bool,
    /// Same for the tool's `syscalls` block.
    pub syscalls_replace: bool,
    /// True when an `environment` block appeared under this tool, its
    /// profile, or its server-defaults. Per-tool environment is not
    /// enforced; the validator rejects it at load time.
    pub environment_explicit: bool,
    /// True when a `process` block grants exec (`deny-all #false` or an allow).
    pub process_exec_allowed: bool,
    /// True when this tool declared its own `process` block (including deny-all).
    pub process_explicit: bool,
    /// `deputy` block: explicit Confused Deputy role + extraction rules
    /// (KDL schema v2). `None` leaves the fixed-name compatibility
    /// mapping in effect — see `deputy::deputy_binding`.
    pub deputy: Option<deputy::DeputyPolicy>,
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
            fs_replace: false,
            network_replace: false,
            syscalls_replace: false,
            environment_explicit: false,
            process_exec_allowed: false,
            process_explicit: false,
            deputy: None,
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
                net.allow_specified
                    || !net.allowed_hosts.is_empty()
                    || !net.denied_hosts.is_empty()
                    || !net.allowed_cidrs.is_empty()
                    || !net.denied_cidrs.is_empty()
                    || !net.egress_rules.is_empty()
            })
            || self
                .syscalls
                .as_ref()
                .is_some_and(|sc| !sc.allowed.is_empty() || !sc.denied.is_empty())
            // A `use`-role deputy contract vets the paths it extracts —
            // unchecked `inputResponses` would bypass exactly that.
            || self
                .deputy
                .as_ref()
                .is_some_and(|d| d.role == deputy::DeputyRole::Use)
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
    /// Name-layer allow rules (`allow host=`).
    pub allowed_hosts: Vec<String>,
    /// IP-layer allow rules (`allow cidr=`) — canonical `addr/prefix`.
    pub allowed_cidrs: Vec<String>,
    /// Deny rules evaluated at both layers — an IP literal here is an
    /// IP-layer deny as well as a name-layer deny.
    pub denied_hosts: Vec<String>,
    /// IP-layer deny rules (`deny cidr=`) — canonical `addr/prefix`.
    pub denied_cidrs: Vec<String>,
    /// Declared rules with their `proto=`/`port=` qualifiers — the same
    /// grammar the defaults-level `network` block parses, kept so a
    /// tool-level `network` block round-trips through emit with its
    /// qualifiers intact. The auditor evaluates the flat lists; the
    /// qualifiers matter to launch mechanisms only.
    pub egress_rules: Vec<EgressRule>,
    pub allow_specified: bool,
}

impl ToolNetworkPolicy {
    /// The effective egress rule set for this tool block: the stored
    /// rules when declared, or the default projection (every allow
    /// becomes `tcp`/any-port, every deny becomes `any`-proto —
    /// mirroring [`OutboundPolicy::egress_rules`]) when the field is
    /// empty — e.g. a programmatically built policy.
    pub fn egress_rule_set(&self) -> Vec<EgressRule> {
        if !self.egress_rules.is_empty() {
            return self.egress_rules.clone();
        }
        let mut rules = Vec::with_capacity(
            self.allowed_hosts.len()
                + self.allowed_cidrs.len()
                + self.denied_hosts.len()
                + self.denied_cidrs.len(),
        );
        for h in &self.allowed_hosts {
            let (dest, port) = match host::bare_port_spelling(h) {
                Some(port) => (EgressDest::Host("*".to_string()), Some(port)),
                None => (EgressDest::Host(h.clone()), None),
            };
            rules.push(EgressRule {
                allow: true,
                dest,
                proto: EgressProto::Tcp,
                port,
            });
        }
        for c in &self.allowed_cidrs {
            rules.push(EgressRule {
                allow: true,
                dest: EgressDest::Cidr(c.clone()),
                proto: EgressProto::Tcp,
                port: None,
            });
        }
        for h in &self.denied_hosts {
            rules.push(EgressRule {
                allow: false,
                dest: EgressDest::Host(h.clone()),
                proto: EgressProto::Any,
                port: None,
            });
        }
        for c in &self.denied_cidrs {
            rules.push(EgressRule {
                allow: false,
                dest: EgressDest::Cidr(c.clone()),
                proto: EgressProto::Any,
                port: None,
            });
        }
        rules
    }
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
    /// `mode="exec"` allow paths: readable AND mappable as machine code
    /// (a runtime prefix or project dir with native modules). Exec
    /// implies read but never write — the grammar has no writable+exec
    /// combination, keeping the launch's writable-never-executable
    /// invariant intact. Counts as an allow for `allow_specified`.
    pub executable: Vec<String>,
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
            executable: Vec::new(),
            denied_paths: Vec::new(),
            allow_specified: false,
            secret_overlay: true,
        }
    }
}

/// Documented `side_effect` values. Unknown strings are a load error.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
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
    /// `deny` entries under `defaults.syscalls` — a `policy version=3`
    /// declaration. Union semantics make the allow side monotonically
    /// additive across `extends`/`include`/`when`, so denying is the only
    /// way a later document narrows an inherited syscall grant;
    /// deny-wins prunes covered allows wherever the two merge.
    pub denied: Vec<String>,
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

/// Supported `policy version=` range. v1 keeps the legacy open `tool`
/// shape and the default passage profile; v2 adds the closed `tool`
/// shape and `server` `mcp` passage rules (MRTR additional requests are
/// denied without an explicit rule either way). v3 keeps the v2 schema
/// but changes merge semantics: allow lists union across composition
/// layers by default, an allow side is replaced only by an explicit
/// `replace=#true`, `defaults.syscalls` gains `deny`, and a tool may
/// name multiple profiles (their layers union).
const MIN_SUPPORTED_VERSION: u32 = 1;
const MAX_SUPPORTED_VERSION: u32 = 3;

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
                let content =
                    crate::fspriv::read_text_bounded_follow_links(&resolved, MAX_SCHEMA_FILE_BYTES)
                        .map_err(|e| {
                            format!("failed to read schema file '{}': {e}", resolved.display())
                        })?;
                tool.args_schema = Some(content);
            }
        }
        Ok(policy)
    }

    /// Every file the policy load read — the root document, each
    /// `extends`/`include` ancestor, and each resolved `@file`
    /// `args_schema` — canonicalized and deduplicated, plus each file's
    /// spelled absolute path alongside its canonical target. A workload
    /// write grant covering any of them — or a directory whose symlink
    /// a spelled path resolves through — would let it rewrite what a
    /// *later* launch loads, so launchers refuse that overlap before
    /// spawning. Empty for policies built without a load (no provenance
    /// attached).
    pub fn source_files(&self) -> Vec<std::path::PathBuf> {
        self.provenance
            .as_ref()
            .map(|p| p.sources.clone())
            .unwrap_or_default()
    }

    /// Every path spelling that hands the workload filesystem write
    /// access: `defaults.filesystem` `read_write` entries plus each
    /// *allowed* tool's `fs.read_write_paths`, minus `denied_paths`
    /// carve-outs — the same coverage reduction the OS grant builders
    /// (Landlock, AppContainer DACL, SBPL, PSEC) apply, so a deny that
    /// covers a spelled grant (normalized or pattern-covered) removes
    /// it here as well.
    /// Callers checking "can the workload write X" (audit-sink
    /// integrity, cgroup control-plane protection) compare against
    /// this list.
    pub fn write_grant_spellings(&self) -> Vec<String> {
        let denied = &self.fs.denied_paths;
        let covered = |p: &&String| denied.iter().any(|d| validator::deny_pattern_covers(d, p));
        let mut v: Vec<String> = self
            .fs
            .read_write
            .iter()
            .filter(|p| !covered(p))
            .cloned()
            .collect();
        for tool in &self.tools {
            if !tool.allowed {
                continue;
            }
            let Some(fs) = &tool.fs else {
                continue;
            };
            v.extend(
                fs.read_write_paths
                    .iter()
                    .filter(|p| {
                        !fs.denied_paths
                            .iter()
                            .any(|d| validator::deny_pattern_covers(d, p))
                            && !covered(p)
                    })
                    .cloned(),
            );
        }
        v
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
        for rules in &self.mcp_rules {
            if let Some(ref name) = rules.server_name {
                names.insert(name.clone());
            }
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
        let unnamed_mcp = self.mcp_rules.iter().any(|r| r.server_name.is_none());
        if (unnamed_tools || unnamed_mcp) && !servers.is_empty() {
            return Err(crate::error::PolicyError::Validation(
                "policy mixes named server blocks with a nameless server block that declares rules"
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
        bound
            .mcp_rules
            .retain(|r| r.server_name.as_deref() == Some(selected.as_str()));
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

    /// `sha256:<hex>` of this policy's canonical effective KDL — the value
    /// that ties an audit event or launch report to the exact ruleset that
    /// was enforced.
    pub fn effective_hash(&self) -> Result<String, crate::error::PolicyError> {
        kdl_canon::hash_canonical_kdl(&self.to_kdl())
    }

    /// Identity stamped on audit events and the launch report: the bound
    /// server name (or `default` for a server-less policy), the declared
    /// `policy version`, and [`Policy::effective_hash`].
    pub fn audit_context(
        &self,
    ) -> Result<crate::audit_log::PolicyAuditContext, crate::error::PolicyError> {
        Ok(crate::audit_log::PolicyAuditContext {
            id: self
                .declared_servers()
                .first()
                .cloned()
                .unwrap_or_else(|| "default".to_string()),
            version: self.version.to_string(),
            hash: self.effective_hash()?,
        })
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
            executable: Vec::new(),
            denied_paths: Vec::new(),
            allow_specified: false,
            secret_overlay: true,
        },
        syscalls: SyscallPolicy {
            allowed: Vec::new(),
            denied: Vec::new(),
        },
        network: NetworkPolicy {
            outbound: OutboundPolicy::default(),
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
        mcp_rules: Vec::new(),
        provenance: None,
    }
}

#[cfg(test)]
mod tests;
