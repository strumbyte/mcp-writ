use std::fmt;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, Instant};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};

use crate::protocol::tools_list::{
    MAX_PAGES, MAX_TOTAL_PAGE_BYTES, MAX_TOTAL_TOOLS, ToolsListParseError,
    parse_tools_list_response_page,
};
use crate::protocol::{
    MCP_VERSION_2025_11_25, MCP_VERSION_2026_07_28, ProtocolStep, SUPPORTED_PROTOCOL_VERSIONS,
    SupportedProtocolVersion, UNSUPPORTED_PROTOCOL_VERSION, VersionProbeOutcome,
    build_initialized_notification, build_mcp_2025_11_25_initialize,
    build_mcp_2025_11_25_tools_list_with_cursor, build_mcp_2026_07_28_request,
    build_mcp_2026_07_28_request_with_cursor, classification_to_outcome, classify_probe_line,
    is_jsonrpc_notification, jsonrpc_has_result, jsonrpc_id_as_i64,
    parse_initialize_protocol_version, parse_jsonrpc_error,
};

pub use crate::tool_def::ToolDefinition;

/// Default timeout for each request on the real child (5 seconds).
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);

/// Default stdio version-probe timeout. A timeout tries MCP `2025-11-25`.
/// Kept shorter than the request timeout so pre-`initialize` servers fail over quickly.
const DEFAULT_PROBE_TIMEOUT: Duration = Duration::from_secs(2);

/// Shared page aggregation for MCP `2026-07-28` and `2025-11-25` pagination.
struct PageAccumulator {
    tools: Vec<ToolDefinition>,
    reached_limit: bool,
    has_more_in_page: bool,
    /// Cumulative serialized page bytes charged so far — the
    /// aggregate budget the Auditor relay also enforces
    /// (`MAX_TOTAL_PAGE_BYTES`): page-count and frame caps alone let
    /// fifty near-limit pages retain hundreds of MiB of tool
    /// definitions (schemas, annotations, raw JSON).
    page_bytes: usize,
}

impl PageAccumulator {
    fn new() -> Self {
        Self {
            tools: Vec::new(),
            reached_limit: false,
            has_more_in_page: false,
            page_bytes: 0,
        }
    }

    /// Charge a received page line against the session byte budget —
    /// before the page is retained, so an over-budget listing fails
    /// closed without accumulating its tool definitions.
    fn note_page_bytes(&mut self, bytes: usize, version_label: &str) -> Result<(), ToolsListError> {
        self.page_bytes = self.page_bytes.saturating_add(bytes);
        if self.page_bytes > MAX_TOTAL_PAGE_BYTES {
            return Err(ToolsListError::PaginationIncomplete(format!(
                "MCP {version_label} tools/list exceeded max accumulated page bytes ({MAX_TOTAL_PAGE_BYTES})"
            )));
        }
        Ok(())
    }

    fn accept_page(&mut self, page_tools: Vec<ToolDefinition>) {
        let mut tools_iter = page_tools.into_iter();
        for tool in tools_iter.by_ref() {
            if self.tools.iter().any(|existing| existing.name == tool.name) {
                tracing::warn!(tool = %crate::termutil::sanitize_for_terminal(&tool.name), "duplicate tool name in tools/list; skipping");
            } else {
                self.tools.push(tool);
            }
            if self.tools.len() >= MAX_TOTAL_TOOLS {
                self.reached_limit = true;
                break;
            }
        }
        self.has_more_in_page = tools_iter.next().is_some();
    }

    fn incomplete_if_truncated(
        &self,
        version_label: &str,
        next_cursor: Option<&str>,
    ) -> Result<(), ToolsListError> {
        let has_next_cursor = next_cursor.map(|s| !s.trim().is_empty()).unwrap_or(false);
        if self.reached_limit && (self.has_more_in_page || has_next_cursor) {
            return Err(ToolsListError::PaginationIncomplete(format!(
                "MCP {version_label} tools/list reached max tool limit ({MAX_TOTAL_TOOLS}) with additional tools remaining"
            )));
        }
        Ok(())
    }

    fn next_cursor(next_cursor: Option<String>) -> Option<String> {
        match next_cursor {
            Some(next) if !next.trim().is_empty() => Some(next),
            _ => None,
        }
    }
}

/// Successful `tools/list` fetch, including the exact MCP revision used.
#[derive(Debug, Clone)]
pub struct ToolsListFetch {
    pub tools: Vec<ToolDefinition>,
    pub protocol_version: SupportedProtocolVersion,
}

/// Errors that can occur during tools/list retrieval.
#[derive(Debug)]
pub enum ToolsListError {
    /// Failed to spawn the MCP server process.
    ProcessSpawn(std::io::Error),
    /// Timed out waiting for a response at a specific version/step.
    Timeout {
        protocol_version: SupportedProtocolVersion,
        step: ProtocolStep,
    },
    /// IO error communicating with the MCP server.
    Io {
        protocol_version: SupportedProtocolVersion,
        step: ProtocolStep,
        source: std::io::Error,
    },
    /// Failed to parse the JSON-RPC response.
    ParseError(String),
    /// Protocol-level failure (JSON-RPC error, missing result, closed stdout).
    Protocol {
        protocol_version: SupportedProtocolVersion,
        step: ProtocolStep,
        detail: String,
    },
    /// Server selected or advertised only revisions mcp-writ does not implement.
    UnsupportedProtocolVersion {
        requested: SupportedProtocolVersion,
        server_versions: Vec<String>,
    },
    /// Pagination could not be completed safely (exceeded limit or loop detected).
    PaginationIncomplete(String),
}

impl fmt::Display for ToolsListError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ProcessSpawn(e) => write!(f, "Failed to spawn MCP server: {e}"),
            Self::Timeout {
                protocol_version,
                step,
            } => {
                write!(
                    f,
                    "Timed out waiting for {step} response from MCP {protocol_version} server"
                )
            }
            Self::Io {
                protocol_version,
                step,
                source,
            } => {
                write!(
                    f,
                    "IO error during {step} on MCP {protocol_version} server: {source}"
                )
            }
            Self::ParseError(e) => write!(f, "Failed to parse tools/list response: {e}"),
            Self::Protocol {
                protocol_version,
                step,
                detail,
            } => {
                write!(
                    f,
                    "Protocol error during {step} on MCP {protocol_version} server: {detail}"
                )
            }
            Self::UnsupportedProtocolVersion {
                requested,
                server_versions,
            } => write!(
                f,
                "MCP {requested} is required for this request; server reported {:?}; mcp-writ supports {:?}",
                server_versions, SUPPORTED_PROTOCOL_VERSIONS
            ),
            Self::PaginationIncomplete(detail) => {
                write!(f, "Pagination incomplete: {detail}")
            }
        }
    }
}

impl std::error::Error for ToolsListError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::ProcessSpawn(e) => Some(e),
            Self::Io { source, .. } => Some(source),
            Self::Timeout { .. }
            | Self::ParseError(_)
            | Self::Protocol { .. }
            | Self::UnsupportedProtocolVersion { .. }
            | Self::PaginationIncomplete(_) => None,
        }
    }
}

impl From<ToolsListParseError> for ToolsListError {
    fn from(e: ToolsListParseError) -> Self {
        Self::ParseError(e.0)
    }
}

/// Fetch tool definitions from an MCP server over stdio.
///
/// Client supporting MCP `2026-07-28` and `2025-11-25` simultaneously:
/// 1. Probe `server/discover` with `2026-07-28` `_meta` on a **disposable
///    sibling** process (some rmcp servers exit on pre-`initialize` traffic).
/// 2. For `2026-07-28`, spawn a fresh child and send `tools/list` with the
///    required `_meta`.
/// 3. Otherwise, spawn a fresh child and try MCP `2025-11-25` via
///    `initialize` → `notifications/initialized` → `tools/list`.
///
/// A server that advertises only a revision other than those two is rejected.
/// In particular, a date later than `2026-07-28` is not assumed compatible.
///
/// Result-envelope extras (`ttlMs`, `cacheScope`, `resultType`) are ignored.
/// Per-tool fields (`title`, `outputSchema`, `annotations`, `icons`,
/// `execution`, `_meta`) are retained for scanning, hash v4, and verified forwarding.
pub async fn fetch_tools_list(
    command: &[String],
    timeout: Option<Duration>,
) -> Result<Vec<ToolDefinition>, ToolsListError> {
    Ok(fetch_tools_list_detailed(command, timeout).await?.tools)
}

/// Options for live tools/list discovery.
#[derive(Debug, Clone)]
pub struct DiscoveryOptions {
    /// `true` (default) — the discovery server runs inside the Warden:
    /// environment stripped to the same contract a supervised launch
    /// gets, deny-all egress, an fs surface limited to the command's
    /// own tree plus a private writable TMPDIR, and the descendant
    /// process tree owned by `RunningChild`. When that isolation
    /// cannot be established the spawn fails closed.
    ///
    /// `false` — the explicit `--unsafe-unsandboxed-discovery`
    /// downgrade: ambient environment, no OS sandbox. It is a
    /// documented trust decision, not a silent fallback.
    pub restrict_environment: bool,
}

impl Default for DiscoveryOptions {
    fn default() -> Self {
        Self {
            restrict_environment: true,
        }
    }
}

/// Same as [`fetch_tools_list`], but also returns the exact selected revision.
pub async fn fetch_tools_list_detailed(
    command: &[String],
    timeout: Option<Duration>,
) -> Result<ToolsListFetch, ToolsListError> {
    fetch_tools_list_detailed_with(command, timeout, &DiscoveryOptions::default()).await
}

/// Same as [`fetch_tools_list_detailed`] with explicit discovery options.
pub async fn fetch_tools_list_detailed_with(
    command: &[String],
    timeout: Option<Duration>,
    opts: &DiscoveryOptions,
) -> Result<ToolsListFetch, ToolsListError> {
    if command.is_empty() {
        return Err(ToolsListError::ProcessSpawn(io::Error::new(
            io::ErrorKind::InvalidInput,
            "empty MCP server command",
        )));
    }

    let timeout = timeout.unwrap_or(DEFAULT_TIMEOUT);
    let probe_timeout = timeout.min(DEFAULT_PROBE_TIMEOUT);

    let outcome = probe_protocol_version(command, probe_timeout, opts).await?;
    match outcome {
        VersionProbeOutcome::UseMcp2026July28 => {
            tracing::debug!(
                protocol_version = MCP_VERSION_2026_07_28,
                "stdio version probe selected MCP 2026-07-28"
            );
            fetch_mcp_2026_07_28(command, timeout, opts).await
        }
        VersionProbeOutcome::UseMcp2025November25 => {
            tracing::debug!(
                protocol_version = MCP_VERSION_2025_11_25,
                "stdio version probe selected advertised MCP 2025-11-25"
            );
            fetch_mcp_2025_11_25(command, timeout, opts).await
        }
        VersionProbeOutcome::TryMcp2025November25 => {
            tracing::debug!(
                protocol_version = MCP_VERSION_2025_11_25,
                "stdio version probe is trying MCP 2025-11-25 on a fresh process"
            );
            fetch_mcp_2025_11_25(command, timeout, opts).await
        }
        VersionProbeOutcome::Unsupported { server_versions } => {
            Err(ToolsListError::UnsupportedProtocolVersion {
                requested: SupportedProtocolVersion::Mcp2026July28,
                server_versions,
            })
        }
    }
}

struct StdioSession {
    stdin: Box<dyn AsyncWrite + Unpin + Send>,
    reader: BufReader<Box<dyn AsyncRead + Unpin + Send>>,
    next_id: i64,
}

impl StdioSession {
    fn from_io(
        stdin: Box<dyn AsyncWrite + Unpin + Send>,
        stdout: Box<dyn AsyncRead + Unpin + Send>,
    ) -> Self {
        Self {
            stdin,
            reader: BufReader::new(stdout),
            next_id: 1,
        }
    }

    fn alloc_id(&mut self) -> i64 {
        let id = self.next_id;
        self.next_id += 1;
        id
    }

    async fn send(
        &mut self,
        line: &str,
        protocol_version: SupportedProtocolVersion,
        step: ProtocolStep,
    ) -> Result<(), ToolsListError> {
        self.stdin
            .write_all(line.as_bytes())
            .await
            .map_err(|source| ToolsListError::Io {
                protocol_version,
                step,
                source,
            })?;
        self.stdin
            .write_all(b"\n")
            .await
            .map_err(|source| ToolsListError::Io {
                protocol_version,
                step,
                source,
            })?;
        self.stdin
            .flush()
            .await
            .map_err(|source| ToolsListError::Io {
                protocol_version,
                step,
                source,
            })?;
        Ok(())
    }

    async fn recv_response(
        &mut self,
        expected_id: i64,
        protocol_version: SupportedProtocolVersion,
        step: ProtocolStep,
        timeout: Duration,
    ) -> Result<String, ToolsListError> {
        let read = async {
            loop {
                let line = match crate::framing::read_line_bounded(
                    &mut self.reader,
                    crate::framing::DEFAULT_MAX_FRAME_BYTES,
                )
                .await
                {
                    Ok(Some(line)) => line,
                    Ok(None) => {
                        return Err(ToolsListError::Protocol {
                            protocol_version,
                            step,
                            detail: "server closed stdout without responding".to_string(),
                        });
                    }
                    Err(crate::framing::FramingError::TooLarge { bytes, limit }) => {
                        return Err(ToolsListError::Protocol {
                            protocol_version,
                            step,
                            detail: format!(
                                "JSON-RPC frame exceeds the {limit}-byte limit ({bytes} bytes)"
                            ),
                        });
                    }
                    Err(crate::framing::FramingError::Io(source)) => {
                        return Err(ToolsListError::Io {
                            protocol_version,
                            step,
                            source,
                        });
                    }
                };
                let trimmed = line.trim();
                if trimmed.is_empty() || !trimmed.starts_with('{') {
                    continue;
                }
                if is_jsonrpc_notification(trimmed) {
                    continue;
                }
                if let Some(id) = jsonrpc_id_as_i64(trimmed)
                    && id != expected_id
                {
                    tracing::debug!(
                        expected_id,
                        got_id = id,
                        "skipping JSON-RPC line with unexpected id"
                    );
                    continue;
                }
                return Ok(trimmed.to_string());
            }
        };

        match tokio::time::timeout(timeout, read).await {
            Ok(inner) => inner,
            Err(_elapsed) => Err(ToolsListError::Timeout {
                protocol_version,
                step,
            }),
        }
    }
}

/// The discovery server child. `Sandboxed` is the default — the
/// Warden owns environment, egress, the fs surface, and the whole
/// descendant process tree. `Plain` is the explicit
/// `--unsafe-unsandboxed-discovery` downgrade.
enum DiscoveryChild {
    Sandboxed(Box<crate::warden::RunningChild>),
    // tokio's Child is the wide variant on Windows — box both so the
    // enum stays small on every platform (large_enum_variant).
    Plain(Box<tokio::process::Child>),
}

impl DiscoveryChild {
    fn take_stdio(
        &mut self,
        protocol_version: SupportedProtocolVersion,
        step: ProtocolStep,
    ) -> Result<StdioSession, ToolsListError> {
        let io_err = |detail: &'static str| ToolsListError::Io {
            protocol_version,
            step,
            source: io::Error::other(detail),
        };
        let (stdin, stdout) = match self {
            Self::Sandboxed(c) => c
                .take_io()
                .ok_or_else(|| io_err("failed to capture sandboxed child stdio"))?,
            Self::Plain(c) => (
                Box::new(
                    c.stdin
                        .take()
                        .ok_or_else(|| io_err("failed to capture child stdin"))?,
                ) as Box<dyn AsyncWrite + Unpin + Send>,
                Box::new(
                    c.stdout
                        .take()
                        .ok_or_else(|| io_err("failed to capture child stdout"))?,
                ) as Box<dyn AsyncRead + Unpin + Send>,
            ),
        };
        Ok(StdioSession::from_io(stdin, stdout))
    }
}

/// Spawn the discovery server. `opts.restrict_environment` selects the
/// isolation contract — it is not an env-only flag: `true` means the
/// Warden path (fail closed when the sandbox cannot be established),
/// `false` means the documented ambient-inheritance downgrade.
/// `MCP_WRIT_SKIP_SANDBOX` takes the same documented downgrade `run`
/// does — the environment contract stays, the OS sandbox steps aside.
async fn spawn_server(
    command: &[String],
    inherit_stderr: bool,
    opts: &DiscoveryOptions,
) -> Result<(DiscoveryChild, Option<PathBuf>), ToolsListError> {
    if opts.restrict_environment {
        if env_skip_sandbox() {
            return spawn_server_plain_restricted(command, inherit_stderr)
                .map(|(c, t)| (DiscoveryChild::Plain(Box::new(c)), t));
        }
        return spawn_server_sandboxed(command)
            .await
            .map(|(c, t)| (DiscoveryChild::Sandboxed(Box::new(c)), Some(t)));
    }
    spawn_server_plain_ambient(command, inherit_stderr)
        .map(|(c, t)| (DiscoveryChild::Plain(Box::new(c)), t))
}

/// True when `MCP_WRIT_SKIP_SANDBOX` is set truthy — the same rule
/// `run` and `plan` apply, so discovery takes the same documented
/// downgrade rather than inventing a second escape hatch.
fn env_skip_sandbox() -> bool {
    std::env::var("MCP_WRIT_SKIP_SANDBOX")
        .map(|v| {
            let v = v.trim().to_lowercase();
            v == "1" || v == "true"
        })
        .unwrap_or(false)
}

/// The deny-by-default policy a discovery server runs under: egress
/// stays fully denied (tools/list is stdio-only), the fs surface
/// covers the command's own tree plus the interpreter runtime, the
/// private TMPDIR is the only writable surface, and the secrets
/// overlay stays on — the server must not read credentials while
/// answering the protocol handshake.
///
/// Command-tree grants are carved around reserved secret names
/// (`.env`, `.env.*`, `.ssh`, `.gnupg`, `.aws/credentials`): the
/// overlay itself is an Auditor RPC check a discovery child never
/// passes through, and no supported backend can subtract a child from
/// a recursive parent grant — additive Landlock rules and DACL ACEs
/// only widen access. A tree holding a reserved name therefore expands
/// to per-entry grants for everything except the reserved paths
/// (recursively, so deeper secrets carve too); a clean tree keeps its
/// single root grant. A secret still covered by a grant the carve does
/// not own — e.g. a command parent beneath a runtime directory —
/// becomes an explicit `denied_paths` entry, which every backend
/// refuses rather than silently re-allow.
fn discovery_policy(
    command: &[String],
    tmpdir: &Path,
) -> Result<crate::policy::Policy, ToolsListError> {
    let mut policy = crate::legislator::self_test_warden::prepare_warden_probe_policy(
        &crate::policy::Policy::default(),
        tmpdir,
        command,
    );
    carve_command_grants(&mut policy, command)?;
    // `prepare_warden_probe_policy` waives the secrets overlay for the
    // self-test control file — a discovery server gets no such pass.
    policy.fs.secret_overlay = true;
    // macOS carries no kernel descendant-lifetime boundary, and the
    // launch host may have no writable cgroup — discovery accepts the
    // RunningChild's best-effort process-tree sweep rather than
    // refusing outright.
    policy.sandbox.require_lifetime_boundary = false;
    Ok(policy)
}

/// Directory entries the secret scan may touch across all command-tree
/// roots — a workload tree larger than this cannot be proven
/// secret-free, so the spawn refuses rather than grant an unproven
/// surface.
const SECRET_SCAN_MAX_ENTRIES: usize = 262_144;

/// Grants one command-tree root may produce when it carves around
/// reserved names — a pathological sibling count beside a secret still
/// keeps the ruleset bounded, and over the cap the spawn refuses.
const SECRET_CARVE_MAX_GRANTS: usize = 4_096;

/// A plain spelling for a policy-bound path: `canonicalize` returns
/// `\\?\`-verbatim paths on Windows, and every downstream comparison
/// is spelled — `resolve_grant_spelling` reads the `?` as a wildcard,
/// and the LPAC/deny coverage checks compare literal strings. The
/// carve emits only paths reachable beneath the parent, so stripping
/// the prefix keeps the object identity while restoring the form the
/// backends compare.
fn plain_spelling(path: &Path) -> PathBuf {
    let s = path.to_string_lossy();
    #[cfg(windows)]
    {
        if let Some(rest) = s.strip_prefix(r"\\?\UNC\") {
            return PathBuf::from(format!(r"\\{rest}"));
        }
        if let Some(rest) = s.strip_prefix(r"\\?\") {
            return PathBuf::from(rest);
        }
    }
    PathBuf::from(s.into_owned())
}

/// The directories the probe walk grants for a discovery command — the
/// executable's parent plus the parent of every path-valued argument
/// (the workload's own tree), and any interpreter install prefix the
/// base grants do not already cover. Canonicalized so the probe's
/// `dir/**` spellings and literal parents compare equal through links,
/// then stripped of verbatim prefixes so carved children stay in the
/// spelled form the backends compare.
fn command_parent_dirs(command: &[String]) -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    if let Some(argv0) = command.first()
        && let Ok(resolved) = crate::workload::resolve_command_path(argv0)
        && let Some(parent) = resolved.parent()
    {
        push(&mut dirs, parent);
    }
    for parent in arg_parent_dirs(command) {
        push(&mut dirs, &parent);
    }
    for dir in interpreter_prefix_dirs(command) {
        push(&mut dirs, &dir);
    }
    dirs
}

/// The interpreter install prefixes the discovery sandbox must reach:
/// a `bin`-adjacent executable's stdlib, `site-packages`, or
/// `lib/node_modules` lives in the *sibling* `lib/` tree, which a bare
/// executable-parent grant misses. Both spellings of argv0 contribute —
/// a venv `python` resolves into its base install while the payload
/// packages stay under the spelled venv tree — and a Windows `Scripts`
/// dir is the venv analogue of `bin`. A `bin` already beneath the
/// probe's base grants (`/usr/bin` → `/usr`) yields no prefix: the
/// fixed dirs cover that install tree and carving it would scan the
/// whole root.
pub(crate) fn interpreter_prefix_dirs(command: &[String]) -> Vec<PathBuf> {
    fn push_prefix(dirs: &mut Vec<PathBuf>, exe: &Path) {
        let Some(parent) = exe.parent() else {
            return;
        };
        let is_prefix_layout = parent
            .file_name()
            .and_then(|n| n.to_str())
            .map(|n| n.eq_ignore_ascii_case("bin") || n == "sbin" || n == "Scripts")
            .unwrap_or(false);
        let Some(prefix) = parent.parent().filter(|_| is_prefix_layout) else {
            return;
        };
        // A `bin` already inside the probe's base grants — `/usr/bin`'s
        // prefix is `/usr` itself — needs no new grant: the fixed dirs
        // cover the whole install tree, and a carve root there would
        // scan it all. Compare the canonical parent so a
        // `/bin -> /usr/bin` link still reads as covered.
        let resolved = parent
            .canonicalize()
            .unwrap_or_else(|_| parent.to_path_buf());
        if crate::legislator::self_test_warden::PROBE_BASE_DIRS
            .iter()
            .any(|root| resolved.starts_with(*root))
        {
            return;
        }
        // An empty or root prefix names no install tree — a `/`
        // carve root would scan the entire filesystem.
        if prefix.as_os_str().is_empty() || prefix.parent().is_none() {
            return;
        }
        push(dirs, prefix);
        // A venv names its base install in `pyvenv.cfg` — `home =` is
        // the base's executable dir, and the install prefix sits one
        // level up of a `bin`/`Scripts` spelling (or *is* `home` on
        // Windows, where python.exe lives at the install root). A
        // copied `python.exe` exposes the base nowhere else: without
        // this the child dies at interpreter init with no stdlib.
        if let Some(home) = pyvenv_home(prefix) {
            let home_is_bin = home
                .file_name()
                .and_then(|n| n.to_str())
                .map(|n| n.eq_ignore_ascii_case("bin") || n == "sbin" || n == "Scripts")
                .unwrap_or(false);
            match (home_is_bin, home.parent()) {
                (true, Some(base)) => push(dirs, base),
                _ => push(dirs, &home),
            }
        }
    }
    let mut dirs = Vec::new();
    if let Some(argv0) = command.first() {
        if let Ok(resolved) = crate::workload::resolve_command_path(argv0) {
            push_prefix(&mut dirs, &resolved);
        }
        let spelled = Path::new(argv0);
        if spelled.exists() {
            push_prefix(&mut dirs, spelled);
        }
    }
    dirs
}

/// The `home =` entry of a venv's `pyvenv.cfg` — the directory holding
/// the base install's interpreter. `None` when the file is absent or
/// carries no usable line.
fn pyvenv_home(venv_root: &Path) -> Option<PathBuf> {
    let cfg = std::fs::read_to_string(venv_root.join("pyvenv.cfg")).ok()?;
    for line in cfg.lines() {
        if let Some(value) = line.trim().strip_prefix("home") {
            let value = value.trim_start_matches([' ', '=', '\t']).trim();
            if !value.is_empty() {
                return Some(PathBuf::from(value));
            }
        }
    }
    None
}

/// True when any argument is a relative path that exists — such an
/// arg resolves against the launcher's cwd, so the discovery child
/// must inherit it (and gains getcwd through that arg's `./` grant).
fn needs_inherited_cwd(command: &[String]) -> bool {
    command.iter().skip(1).any(|arg| {
        if arg.starts_with('-') {
            return false;
        }
        let path = Path::new(arg);
        path.is_relative() && path.exists()
    })
}

/// The nearest `node_modules` ancestor of each existing path argument.
/// A server entry point under `node_modules/<pkg>/dist/` resolves its
/// dependencies by walking *up* to the shared `node_modules` root —
/// granting only the entry's own package directory leaves its sibling
/// packages (the SDK, transport libs) unreadable inside the sandbox.
fn node_modules_roots(command: &[String]) -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    for arg in command.iter().skip(1) {
        if arg.starts_with('-') {
            continue;
        }
        let path = Path::new(arg);
        if !path.exists() {
            continue;
        }
        for ancestor in path.ancestors() {
            if ancestor
                .file_name()
                .and_then(|n| n.to_str())
                .map(|n| n == "node_modules")
                .unwrap_or(false)
            {
                if preserves_probe_deny(ancestor) {
                    push(&mut dirs, ancestor);
                }
                break;
            }
        }
    }
    dirs
}

/// One canonical, verbatim-stripped carve root into `dirs`, deduped.
fn push(list: &mut Vec<PathBuf>, dir: &Path) {
    let dir = dir.canonicalize().unwrap_or_else(|_| dir.to_path_buf());
    let dir = plain_spelling(&dir);
    if !list.contains(&dir) {
        list.push(dir);
    }
}

/// True when a candidate root keeps the probe's deny evidence: a
/// resolved root covering the resolved WARDEN_PROBE_PATH would let the
/// child serve the probe path, so it is rejected from the lists that
/// feed both the policy grants and the discovery carve. Each side
/// falls back to its spelled form when it cannot be resolved — the
/// probe path is a Linux absolute path, so non-Linux hosts compare it
/// as spelled (which never matches their roots).
fn preserves_probe_deny(dir: &Path) -> bool {
    let canonical = dir.canonicalize().unwrap_or_else(|_| dir.to_path_buf());
    let probe = Path::new(crate::legislator::self_test::WARDEN_PROBE_PATH);
    let probe = probe.canonicalize().unwrap_or_else(|_| probe.to_path_buf());
    !probe.starts_with(&canonical)
}

/// The argument-parent carve roots alone — the self-test keeps its
/// executable-parent grant untouched but must still carve the argument
/// roots a bare argument's workspace falls under.
pub(crate) fn arg_parent_dirs(command: &[String]) -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    for arg in command.iter().skip(1) {
        // Same option guard as the probe walk — a bare `--mode` never
        // names a path, so it earns no carve root.
        if arg.starts_with('-') {
            continue;
        }
        let path = Path::new(arg);
        // The same root rule `prepare_warden_probe_policy` grants —
        // canonical parent for an existing argument, plain parent for
        // a missing one. Any other root leaves its `dir/**` grant
        // outside the carve and back inside the policy.
        let parent = if path.exists() {
            path.canonicalize()
                .ok()
                .and_then(|c| c.parent().map(Path::to_path_buf))
                .or_else(|| path.parent().map(Path::to_path_buf))
        } else if !crate::pathutil::selector_plausible(arg) {
            // Parity with the probe walk: a bare literal such as
            // `stdio` is no path and contributes no carve root.
            None
        } else {
            // A bare argument names a file beside the process — the
            // probe grants the current directory for it, so an empty
            // `parent()` normalizes to `.` for the same carve root.
            path.parent().map(|p| {
                if p.as_os_str().is_empty() {
                    PathBuf::from(".")
                } else {
                    p.to_path_buf()
                }
            })
        };
        // Keep parity with the probe walk: a grant covering
        // WARDEN_PROBE_PATH would erase OS-deny evidence.
        if let Some(parent) = parent
            && preserves_probe_deny(&parent)
        {
            push(&mut dirs, &parent);
        }
    }
    for dir in node_modules_roots(command) {
        push(&mut dirs, &dir);
    }
    dirs
}

/// Directories on PATH the child may exec helpers from — server
/// subprocess machinery resolves `git`, `sh`, and friends by PATH, so
/// the runtime surface needs them readable (and, under sandbox-exec,
/// mappable). Entries already beneath the probe's base grants are
/// skipped; a root covering the probe path keeps the deny evidence
/// and is skipped too.
fn path_dir_roots() -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    let Some(path) = std::env::var_os("PATH") else {
        return dirs;
    };
    for dir in std::env::split_paths(&path) {
        if !dir.is_dir() || !preserves_probe_deny(&dir) {
            continue;
        }
        let resolved = dir.canonicalize().unwrap_or_else(|_| dir.clone());
        if crate::legislator::self_test_warden::PROBE_BASE_DIRS
            .iter()
            .any(|root| resolved.starts_with(*root))
        {
            continue;
        }
        push(&mut dirs, &dir);
        // A `<prefix>/bin` PATH entry belongs to a toolchain prefix —
        // binaries there link dylibs under the prefix's `lib`/`opt`
        // siblings (Homebrew `/opt/homebrew`, `/usr/local`), the same
        // `bin`-parent reasoning `interpreter_prefix_dirs` applies to
        // argv[0]. The prefix must not cover the probe path either.
        if matches!(
            dir.file_name().and_then(|n| n.to_str()),
            Some("bin" | "sbin" | "Scripts")
        ) && let Some(prefix) = dir.parent()
            && prefix.parent().is_some()
            && preserves_probe_deny(prefix)
        {
            push(&mut dirs, prefix);
        }
    }
    dirs
}

/// The runtime surface a real interpreter needs beyond the command's
/// own tree: [`interpreter_prefix_dirs`] plus [`node_modules_roots`]
/// plus the PATH dirs helper subprocesses resolve from. Shared by the
/// probe-policy grant emission and the carve-root computation so both
/// spell the same set.
pub(crate) fn runtime_grant_dirs(command: &[String]) -> Vec<PathBuf> {
    let mut dirs = interpreter_prefix_dirs(command);
    for dir in node_modules_roots(command) {
        push(&mut dirs, &dir);
    }
    for dir in path_dir_roots() {
        push(&mut dirs, &dir);
    }
    dirs
}

/// True when a `read_only` spelling grants exactly `dir` — `dir`,
/// `dir/**`, or `dir/*` all reduce to the same root the carve
/// replaces.
fn grant_names_dir(entry: &str, dir: &Path) -> bool {
    let mut base = entry.trim();
    while let Some(rest) = base.strip_suffix("/**") {
        base = rest;
    }
    while let Some(rest) = base.strip_suffix("/*") {
        base = rest;
    }
    let base_path = Path::new(base);
    if base_path == dir {
        return true;
    }
    match (base_path.canonicalize(), dir.canonicalize()) {
        (Ok(b), Ok(d)) => b == d,
        _ => false,
    }
}

/// Reserved basenames, mirroring the `secret_paths` overlay: `.ssh`
/// and `.gnupg` are reserved as whole directories, `.env` and
/// `.env.*` (minus the documented `.env.example` exclusion) as names,
/// and `credentials` only beneath a `.aws` directory. Names compare
/// ASCII-case-insensitively like the overlay.
fn is_reserved_entry_name(name_lower: &str, inside_aws: bool) -> bool {
    name_lower == ".ssh"
        || name_lower == ".gnupg"
        || name_lower == ".env"
        || (name_lower.starts_with(".env.") && name_lower != ".env.example")
        || (inside_aws && name_lower == "credentials")
}

/// A symlink or reparse point: its target resolves outside the
/// spelling's own tree, so a grant on the node never covers it — such
/// entries are skipped entirely rather than granted.
fn is_reparse(meta: &std::fs::Metadata) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        meta.file_attributes() & 0x400 != 0 // FILE_ATTRIBUTE_REPARSE_POINT
    }
    #[cfg(not(windows))]
    {
        meta.file_type().is_symlink()
    }
}

/// One directory's carve outcome: `Clean` means nothing reserved was
/// found anywhere beneath it (callers may grant the dir wholesale);
/// `Grants` carries the per-entry replacements — clean subtrees keep
/// their own root, everything else lists individually.
enum Carve {
    Clean,
    Grants(Vec<PathBuf>),
}

/// Enumerate `dir` recursively and decide which of its entries may be
/// granted. Reserved names are never granted (skipped outright, like
/// symlinks and junctions found *inside* the tree — their targets were
/// never beneath the spelled grant anyway); everything else keeps a
/// literal grant. A reparse point *as the walked root* is an error:
/// the spelled grant would resolve to an unproven target. `secrets`
/// collects every reserved path seen so the caller can deny whatever
/// some other grant still covers.
fn carve_dir(
    dir: &Path,
    inside_aws: bool,
    budget: &mut usize,
    secrets: &mut Vec<PathBuf>,
    deadline: Option<Instant>,
) -> Result<Carve, String> {
    // A deadline bounds the walk itself — dropping the await that
    // watches it never stops a blocking scan already in flight. Check
    // before the scan, per entry, and again before the outcome is
    // granted so an expired deadline fails even for an empty
    // directory or one expiring during the last entry.
    let expired = || deadline.is_some_and(|d| Instant::now() >= d);
    // Every carve outcome — a clean early-out included — respects the
    // bound: a deadline that expired mid-walk must not still grant.
    let clean_or_expired = |expired: bool| {
        if expired {
            Err("carve deadline expired".to_string())
        } else {
            Ok(Carve::Clean)
        }
    };
    if expired() {
        return Err("carve deadline expired".to_string());
    }
    let meta = match std::fs::symlink_metadata(dir) {
        Ok(m) => m,
        // The root may have vanished between resolution and walk —
        // treat it as clean so the spelled grant does what the old
        // policy did (the backends skip unopenable paths anyway).
        Err(_) => return clean_or_expired(expired()),
    };
    if is_reparse(&meta) {
        // A reparse resolves outside the spelled tree — carving cannot
        // prove its target secret-free, and `Clean` here would let the
        // caller grant the link wholesale (the backend resolves it to
        // the whole target). The caller resolves the root up front, so
        // reaching this arm means the node was swapped beneath the
        // walk or a nested check raced — either way, fail closed.
        return Err(format!(
            "'{}' is a symlink/reparse point — cannot prove the carved tree secret-free",
            dir.display()
        ));
    }
    if !meta.is_dir() {
        return clean_or_expired(expired());
    }
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        // A directory the operator cannot read is unreadable to the
        // same-uid server too — the wholesale grant hides nothing.
        Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
            return clean_or_expired(expired());
        }
        Err(e) => return Err(format!("cannot enumerate '{}': {e}", dir.display())),
    };
    if expired() {
        return Err("carve deadline expired".to_string());
    }
    let mut grants: Vec<PathBuf> = Vec::new();
    let mut clean = true;
    for entry in entries {
        if expired() {
            return Err("carve deadline expired".to_string());
        }
        let entry = entry.map_err(|e| format!("cannot enumerate '{}': {e}", dir.display()))?;
        *budget = budget
            .checked_sub(1)
            .ok_or_else(|| "secret-path scan budget exhausted".to_string())?;
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().to_ascii_lowercase();
        if is_reserved_entry_name(&name, inside_aws) {
            clean = false;
            secrets.push(path);
            continue;
        }
        let meta = match entry.path().symlink_metadata() {
            Ok(m) => m,
            // Unstattable entries (a dangling link, an exotic reparse)
            // get no grant — they cannot be classified safely.
            Err(_) => continue,
        };
        if meta.is_dir() && !is_reparse(&meta) {
            match carve_dir(
                &path,
                inside_aws || name == ".aws",
                budget,
                secrets,
                deadline,
            )? {
                Carve::Clean => grants.push(path),
                Carve::Grants(children) => {
                    clean = false;
                    grants.extend(children);
                }
            }
        } else if !meta.is_dir() && !is_reparse(&meta) {
            grants.push(path);
        }
        // Reparse points and links fall through ungranted — their
        // targets never were beneath the parent grant.
    }
    if expired() {
        return Err("carve deadline expired".to_string());
    }
    if clean {
        Ok(Carve::Clean)
    } else {
        Ok(Carve::Grants(grants))
    }
}

/// Carve one command-tree root so no reserved secret name stays
/// reachable beneath it. Returns the literal grant paths plus every
/// reserved path found (for the coverage deny check).
fn carved_grant_paths(
    root: &Path,
    budget: &mut usize,
    deadline: Option<Instant>,
) -> Result<(Vec<PathBuf>, Vec<PathBuf>), String> {
    // A symlink or junction root resolves outside its own spelling —
    // granting `root` wholesale would grant the target's tree,
    // reserved secrets included. Carve must speak of the real tree the
    // backend reaches; a reparse that cannot be resolved fails closed
    // rather than guess (the link could also be re-pointed after this
    // walk). A root that vanished between listing and walk keeps the
    // spelled grant — nothing exists for it to hide.
    let root = match std::fs::symlink_metadata(root) {
        Ok(meta) if is_reparse(&meta) => {
            let resolved = root.canonicalize().map_err(|e| {
                format!(
                    "cannot resolve reparse-point grant root '{}': {e}",
                    root.display()
                )
            })?;
            plain_spelling(&resolved)
        }
        _ => root.to_path_buf(),
    };
    let root = root.as_path();
    let mut secrets = Vec::new();
    let grants = match carve_dir(root, false, budget, &mut secrets, deadline)? {
        Carve::Clean => vec![root.to_path_buf()],
        Carve::Grants(g) => g,
    };
    if grants.len() > SECRET_CARVE_MAX_GRANTS {
        return Err(format!(
            "carving '{}' produces {} grants — the tree is too irregular to prove secret-free",
            root.display(),
            grants.len()
        ));
    }
    Ok((grants, secrets))
}

/// Component-wise coverage for resolved paths. `path_covers` compares
/// raw components, but secrets enumerated under a canonicalized parent
/// carry `\\?\` verbatim prefixes while spelled grants may not — fold
/// verbatim prefixes onto their plain spellings (and case-fold, the
/// same rule the filesystem applies) so the comparison never splits on
/// spelling alone.
#[cfg(target_os = "windows")]
fn resolved_path_covers(grant: &Path, target: &Path) -> bool {
    use std::path::{Component, Prefix};
    fn fold(p: &Path) -> Vec<String> {
        p.components()
            .map(|c| match c {
                Component::Prefix(pr) => match pr.kind() {
                    Prefix::Disk(b) | Prefix::VerbatimDisk(b) => {
                        format!("\\{}", (b as char).to_ascii_lowercase())
                    }
                    Prefix::UNC(s, n) | Prefix::VerbatimUNC(s, n) => format!(
                        "\\\\{}\\{}",
                        s.to_string_lossy().to_lowercase(),
                        n.to_string_lossy().to_lowercase()
                    ),
                    Prefix::Verbatim(s) | Prefix::DeviceNS(s) => {
                        format!("\\\\.\\{}", s.to_string_lossy().to_lowercase())
                    }
                },
                other => other.as_os_str().to_string_lossy().to_lowercase(),
            })
            .collect()
    }
    let g = fold(grant);
    let t = fold(target);
    t.len() >= g.len() && t[..g.len()] == g[..]
}

#[cfg(not(target_os = "windows"))]
fn resolved_path_covers(grant: &Path, target: &Path) -> bool {
    crate::fsoverlap::path_covers(grant, target)
}

/// True when `grant` covers `secret` — on the spelling and on the
/// resolved base, mirroring the Landlock overlap check exactly. The
/// secret side is a real enumerated path, so it canonicalizes
/// directly: `resolve_grant_spelling` would (correctly) refuse a
/// `\\?\` verbatim spelling as carrying a wildcard.
fn grant_covers_secret(grant: &str, secret: &Path) -> bool {
    let secret_str = secret.to_string_lossy();
    if crate::policy::validator::covers_or_same(grant, &secret_str) {
        return true;
    }
    let Some(g) = crate::fsoverlap::resolve_grant_spelling(grant) else {
        return false;
    };
    let s = secret
        .canonicalize()
        .unwrap_or_else(|_| secret.to_path_buf());
    resolved_path_covers(&g, &s)
}

/// Replace the broad command-parent grants the probe policy spelled —
/// its `dir/**` glob and the literal parent — with carved grants that
/// leave no reserved secret reachable, and deny whatever a surviving
/// grant still covers. A runtime-directory overlap (a command parent
/// beneath `/usr`, say) lands in `denied_paths`, where every backend's
/// own overlap checks refuse the launch rather than silently re-allow
/// the secret.
/// The resolved executable's parent, normalized the way `push`
/// normalizes carve roots — an argument root that lands here doubles
/// as the executable-parent grant and must be preserved, not carved.
fn exe_parent_dir(command: &[String]) -> Option<PathBuf> {
    let resolved = crate::workload::resolve_command_path(command.first()?).ok()?;
    let parent = resolved.parent()?;
    let canonical = parent
        .canonicalize()
        .unwrap_or_else(|_| parent.to_path_buf());
    Some(plain_spelling(&canonical))
}

/// Argument roots that coincide with the executable's own parent —
/// preserving them keeps the `dir/**` grant the image needs while
/// their reserved names still feed `denied_paths`.
fn shared_exe_roots(command: &[String], arg_roots: &[PathBuf]) -> Vec<PathBuf> {
    let Some(exe_parent) = exe_parent_dir(command) else {
        return Vec::new();
    };
    arg_roots
        .iter()
        .filter(|r| **r == exe_parent)
        .cloned()
        .collect()
}

fn carve_command_grants(
    policy: &mut crate::policy::Policy,
    command: &[String],
) -> Result<(), ToolsListError> {
    let args = arg_parent_dirs(command);
    let preserve = shared_exe_roots(command, &args);
    carve_roots(policy, &command_parent_dirs(command), &preserve, None)
}

/// The self-test side of the carve: the probe's argument-parent
/// `dir/**` grants leave the same secrets reachable a discovery grant
/// would, so they are carved identically — while its
/// executable-parent grant (which Landlock needs to exec the probe
/// image at all) stays untouched. `deadline` bounds the walk itself:
/// a caller that times out an in-flight scan still stops.
#[cfg(any(target_os = "linux", test))]
pub(crate) fn carve_arg_grants(
    policy: &mut crate::policy::Policy,
    command: &[String],
    deadline: Option<Instant>,
) -> Result<(), ToolsListError> {
    let args = arg_parent_dirs(command);
    let preserve = shared_exe_roots(command, &args);
    carve_roots(policy, &args, &preserve, deadline)
}

fn carve_roots(
    policy: &mut crate::policy::Policy,
    parents: &[PathBuf],
    preserve: &[PathBuf],
    deadline: Option<Instant>,
) -> Result<(), ToolsListError> {
    // A preserved root keeps its `dir/**` grant — it doubles as the
    // executable's own parent — so it is retained here and only
    // *scanned* below; reserved names beneath it go to `denied_paths`,
    // where every backend's covered-grant check refuses the launch.
    policy.fs.read_only.retain(|entry| {
        !parents
            .iter()
            .any(|p| grant_names_dir(entry, p) && !preserve.contains(p))
    });
    let mut budget = SECRET_SCAN_MAX_ENTRIES;
    let mut secrets = Vec::new();
    for parent in parents {
        let (grants, found) =
            carved_grant_paths(parent, &mut budget, deadline).map_err(|detail| {
                ToolsListError::ProcessSpawn(io::Error::other(format!(
                    "cannot carve a secret-free discovery grant for '{}': {detail}",
                    parent.display()
                )))
            })?;
        if preserve.contains(parent) {
            // Preserve means keep the spelled `dir/**` — a platform
            // whose grant filter dropped the spelling leaves nothing
            // behind, so the carved children still land as grants or
            // the parent loses access entirely.
            if !policy
                .fs
                .read_only
                .iter()
                .any(|g| grant_names_dir(g, parent))
            {
                for grant in grants {
                    let s = grant.to_string_lossy().into_owned();
                    if !policy.fs.read_only.contains(&s) {
                        policy.fs.read_only.push(s);
                    }
                }
            }
            secrets.extend(found);
            continue;
        }
        for grant in grants {
            let s = grant.to_string_lossy().into_owned();
            if !policy.fs.read_only.contains(&s) {
                policy.fs.read_only.push(s);
            }
        }
        secrets.extend(found);
    }
    deny_covered_secrets(policy, &secrets);
    Ok(())
}

/// Every reserved secret a surviving grant still covers becomes an
/// explicit `denied_paths` entry — each backend's own overlap check
/// refuses the launch rather than silently re-allowing the secret.
/// Entries already denied are not duplicated.
fn deny_covered_secrets(policy: &mut crate::policy::Policy, secrets: &[PathBuf]) {
    for secret in secrets {
        let covered = policy
            .fs
            .read_only
            .iter()
            .chain(policy.fs.read_write.iter())
            .chain(policy.fs.executable.iter())
            .any(|grant| grant_covers_secret(grant, secret));
        if covered {
            let s = secret.to_string_lossy().into_owned();
            if !policy.fs.denied_paths.contains(&s) {
                policy.fs.denied_paths.push(s);
            }
        }
    }
}

fn create_discovery_tmpdir() -> Result<PathBuf, ToolsListError> {
    let tmp = std::env::temp_dir() // nosemgrep: rust.lang.security.temp-dir.temp-dir
        .join(format!(
            "mcp-writ-discover-{}",
            crate::fspriv::unique_suffix()
        ));
    // Exclusive create at the requested mode: the private TMPDIR
    // never exists first with default (or pre-existing) permissions.
    #[cfg(unix)]
    let created = {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new().mode(0o700).create(&tmp)
    };
    #[cfg(not(unix))]
    let created = std::fs::DirBuilder::new().create(&tmp);
    created.map_err(ToolsListError::ProcessSpawn)?;
    #[cfg(unix)]
    {
        // The creation mode is masked by the process umask — chmod
        // the exact 0700 so owner access cannot be masked away. On
        // failure the fresh dir is removed: neither discovery path
        // may run against a directory with unusable permissions.
        if let Err(e) = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o700)) {
            let _ = std::fs::remove_dir_all(&tmp);
            return Err(ToolsListError::ProcessSpawn(e));
        }
    }
    Ok(tmp)
}

/// The Warden-isolated spawn. Fail closed: when the sandbox cannot be
/// established (unsupported mechanism, unbuildable ruleset), discovery
/// errors rather than run the server outside it.
async fn spawn_server_sandboxed(
    command: &[String],
) -> Result<(crate::warden::RunningChild, PathBuf), ToolsListError> {
    let tmp = create_discovery_tmpdir()?;
    // The secret-scan carve is synchronous filesystem traversal — a
    // large command tree would stall the Tokio worker, so the policy
    // build runs on the blocking pool. A panicking or cancelled task
    // fails the spawn exactly like a policy error does.
    let policy = match tokio::task::spawn_blocking({
        let command = command.to_vec();
        let tmp = tmp.clone();
        move || discovery_policy(&command, &tmp)
    })
    .await
    {
        Ok(policy) => policy.inspect_err(|_| {
            let _ = std::fs::remove_dir_all(&tmp);
        })?,
        Err(e) => {
            let _ = std::fs::remove_dir_all(&tmp);
            return Err(ToolsListError::ProcessSpawn(io::Error::other(format!(
                "discovery policy worker failed: {e}"
            ))));
        }
    };
    let resolved = crate::workload::resolve_command_path(&command[0]).map_err(|e| {
        let _ = std::fs::remove_dir_all(&tmp);
        ToolsListError::ProcessSpawn(io::Error::other(format!(
            "cannot resolve '{}': {e}",
            command[0]
        )))
    })?;
    let opts = crate::warden::SpawnOptions {
        restrict_environment: true,
        allowed_names: Vec::new(),
        tmpdir: Some(tmp.clone()),
        // The deny-by-default filesystem never grants the caller's
        // workspace, and an ungranted inherited cwd makes getcwd(2)
        // fail under sandbox-exec — which kills shells and the
        // subprocess machinery servers like mcp-server-git rely on.
        // Start the child in its (already write-granted) private
        // tmpdir instead — unless a relative-path argument would
        // resolve against the real cwd; that arg's `./` grant covers
        // getcwd, and a tmp cwd would break its resolution.
        cwd: if needs_inherited_cwd(command) {
            None
        } else {
            Some(tmp.clone())
        },
        ..Default::default()
    };
    // A discovery workload is a real spawn: dyld needs the same
    // derived code-map grants a `run` launch computes (argv[0] is
    // resolved).
    #[cfg(target_os = "macos")]
    let opts = {
        let mut o = opts;
        o.exec_map_dirs = crate::warden::macos_sandbox::code_map_dirs(&resolved, command);
        // Helpers the server may exec mid-discovery — `git` for
        // mcp-server-git, `sh` for subprocess machinery — sit outside
        // the command tree, and the profile grants the standard exec
        // dirs read but not file-map-executable.
        for d in ["/bin", "/sbin", "/usr/bin", "/usr/sbin", "/usr/libexec"] {
            o.exec_map_dirs.push(PathBuf::from(d));
        }
        for d in path_dir_roots() {
            o.exec_map_dirs.push(d);
        }
        o
    };
    // The verified image rides `lpApplicationName`; the child's argv[0]
    // keeps the caller's spelling. `resolve_command_path` canonicalizes
    // to a `\\?\` verbatim path on Windows, and a verbatim module path —
    // whether as argv[0] or as the image name — leaves CLR children
    // (powershell.exe, any .NET server) unable to load assemblies, so
    // the program is handed over in plain spelling.
    let program = plain_spelling(&resolved);
    match crate::warden::Warden::new(policy)
        .spawn_child_async_exe_with(&program, command, &opts)
        .await
    {
        Ok(child) => Ok((child, tmp)),
        Err(e) => {
            let _ = std::fs::remove_dir_all(&tmp);
            Err(ToolsListError::ProcessSpawn(io::Error::other(format!(
                "sandboxed discovery spawn failed: {e}"
            ))))
        }
    }
}

/// The `MCP_WRIT_SKIP_SANDBOX` downgrade: no OS sandbox, but the same
/// restricted environment contract a supervised launch keeps — PATH,
/// the Windows system vars, and a private TMPDIR. Discovery runs
/// attacker-controlled code, so the ambient environment still does
/// not cross.
fn spawn_server_plain_restricted(
    command: &[String],
    inherit_stderr: bool,
) -> Result<(tokio::process::Child, Option<PathBuf>), ToolsListError> {
    static WARNED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
    if !WARNED.swap(true, std::sync::atomic::Ordering::Relaxed) {
        eprintln!(
            "WARNING: MCP_WRIT_SKIP_SANDBOX is set — tools/list discovery runs \
             without the OS sandbox (restricted environment only)."
        );
    }
    let tmp = create_discovery_tmpdir()?;
    let mut cmd = tokio::process::Command::new(&command[0]);
    cmd.args(&command[1..])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .kill_on_drop(true);
    if inherit_stderr {
        cmd.stderr(Stdio::piped());
    } else {
        cmd.stderr(Stdio::null());
    }
    cmd.env_clear();
    if let Ok(path) = std::env::var("PATH") {
        cmd.env("PATH", path);
    }
    #[cfg(windows)]
    {
        for key in [
            "SYSTEMROOT",
            "WINDIR",
            "PATHEXT",
            "COMSPEC",
            "SYSTEMDRIVE",
            "LOCALAPPDATA",
        ] {
            if let Ok(val) = std::env::var(key) {
                cmd.env(key, val);
            }
        }
    }
    cmd.env("TMPDIR", &tmp);
    cmd.env("TMP", &tmp);
    cmd.env("TEMP", &tmp);
    match cmd.spawn() {
        Ok(mut child) => {
            if inherit_stderr {
                relay_discovery_stderr(child.stderr.take());
            }
            Ok((child, Some(tmp)))
        }
        Err(e) => {
            let _ = std::fs::remove_dir_all(&tmp);
            Err(ToolsListError::ProcessSpawn(e))
        }
    }
}

/// The `--unsafe-unsandboxed-discovery` path: ambient environment, no
/// OS sandbox — only invoked on the explicit flag.
fn spawn_server_plain_ambient(
    command: &[String],
    inherit_stderr: bool,
) -> Result<(tokio::process::Child, Option<PathBuf>), ToolsListError> {
    let mut cmd = tokio::process::Command::new(&command[0]);
    cmd.args(&command[1..])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .kill_on_drop(true);
    // Discovery runs attacker-controlled code: raw stderr inherit would
    // hand the server's bytes straight to the operator's TTY, so the
    // stream is piped and relayed through the control-character
    // sanitizer with a hard cap instead.
    if inherit_stderr {
        cmd.stderr(Stdio::piped());
    } else {
        cmd.stderr(Stdio::null());
    }
    match cmd.spawn() {
        Ok(mut child) => {
            if inherit_stderr {
                relay_discovery_stderr(child.stderr.take());
            }
            Ok((child, None))
        }
        Err(e) => Err(ToolsListError::ProcessSpawn(e)),
    }
}

/// Relay a discovery child's stderr to ours in bounded chunks with
/// terminal control characters escaped and a hard byte cap — the server
/// being probed is attacker-controlled, so its diagnostics cross as
/// text, never raw bytes. Shared implementation:
/// [`crate::termutil::relay_child_stderr`]. (The Warden path relays
/// the child's stderr through the same sanitizer internally.)
fn relay_discovery_stderr(stderr: Option<tokio::process::ChildStderr>) {
    let Some(stderr) = stderr else { return };
    crate::termutil::relay_child_stderr(stderr);
}

async fn shutdown_child(child: &mut DiscoveryChild) {
    match child {
        DiscoveryChild::Sandboxed(c) => {
            // stdin was moved into the session and closed with it —
            // give the server a brief window to exit on EOF, then take
            // the process group / descendant tree down with it.
            let _ =
                tokio::time::timeout(Duration::from_millis(200), c.wait_for_natural_exit()).await;
            let _ = c.kill().await;
            let _ = c.wait().await;
        }
        DiscoveryChild::Plain(c) => {
            drop(c.stdin.take());
            match tokio::time::timeout(Duration::from_millis(200), c.wait()).await {
                Ok(_) => {}
                Err(_) => {
                    let _ = c.kill().await;
                    let _ = c.wait().await;
                }
            }
        }
    }
}

fn remove_discovery_tmpdir(dir: Option<PathBuf>) {
    if let Some(dir) = dir {
        let _ = std::fs::remove_dir_all(dir);
    }
}

/// Probe `server/discover` on a disposable sibling. Never leaves the real
/// session child holding pre-`initialize` traffic.
async fn probe_protocol_version(
    command: &[String],
    timeout: Duration,
    opts: &DiscoveryOptions,
) -> Result<VersionProbeOutcome, ToolsListError> {
    let (mut child, tmpdir) = spawn_server(command, false, opts).await?;
    let outcome = probe_protocol_version_on_sibling(&mut child, timeout).await;
    shutdown_child(&mut child).await;
    remove_discovery_tmpdir(tmpdir);
    Ok(outcome)
}

async fn probe_protocol_version_on_sibling(
    child: &mut DiscoveryChild,
    timeout: Duration,
) -> VersionProbeOutcome {
    let version = SupportedProtocolVersion::Mcp2026July28;
    let mut session = match child.take_stdio(version, ProtocolStep::Probe) {
        Ok(session) => session,
        Err(_) => return VersionProbeOutcome::TryMcp2025November25,
    };

    let request = build_mcp_2026_07_28_request(1, "server/discover");
    if session
        .send(&request, version, ProtocolStep::Probe)
        .await
        .is_err()
    {
        return VersionProbeOutcome::TryMcp2025November25;
    }

    match session
        .recv_response(1, version, ProtocolStep::Probe, timeout)
        .await
    {
        Ok(line) => classification_to_outcome(classify_probe_line(&line)),
        Err(_) => VersionProbeOutcome::TryMcp2025November25,
    }
}

async fn fetch_mcp_2026_07_28(
    command: &[String],
    timeout: Duration,
    opts: &DiscoveryOptions,
) -> Result<ToolsListFetch, ToolsListError> {
    let (mut child, tmpdir) = spawn_server(command, true, opts).await?;
    let result = fetch_mcp_2026_07_28_on_child(&mut child, timeout).await;
    shutdown_child(&mut child).await;
    remove_discovery_tmpdir(tmpdir);
    result
}

async fn fetch_mcp_2026_07_28_on_child(
    child: &mut DiscoveryChild,
    timeout: Duration,
) -> Result<ToolsListFetch, ToolsListError> {
    let version = SupportedProtocolVersion::Mcp2026July28;
    let mut session = child.take_stdio(version, ProtocolStep::ToolsList)?;
    let mut pages = PageAccumulator::new();
    let mut current_cursor: Option<String> = None;
    let mut seen_cursors = std::collections::HashSet::new();
    let mut page_count = 0;

    loop {
        if page_count >= MAX_PAGES {
            return Err(ToolsListError::PaginationIncomplete(format!(
                "MCP {MCP_VERSION_2026_07_28} tools/list exceeded max page limit ({MAX_PAGES})"
            )));
        }

        if let Some(ref c) = current_cursor
            && !seen_cursors.insert(c.clone())
        {
            return Err(ToolsListError::PaginationIncomplete(format!(
                "MCP {MCP_VERSION_2026_07_28} tools/list detected repeated cursor '{c}', terminating pagination"
            )));
        }

        let id = session.alloc_id();
        let request =
            build_mcp_2026_07_28_request_with_cursor(id, "tools/list", current_cursor.as_deref());
        session
            .send(&request, version, ProtocolStep::ToolsList)
            .await?;
        let line = session
            .recv_response(id, version, ProtocolStep::ToolsList, timeout)
            .await?;
        pages.note_page_bytes(line.len(), MCP_VERSION_2026_07_28)?;

        if let Some(err) = parse_jsonrpc_error(&line) {
            if err.code == UNSUPPORTED_PROTOCOL_VERSION {
                return Err(ToolsListError::UnsupportedProtocolVersion {
                    requested: version,
                    server_versions: err.supported,
                });
            }
            return Err(ToolsListError::Protocol {
                protocol_version: version,
                step: ProtocolStep::ToolsList,
                detail: format!("server returned error: {}", err.display_detail()),
            });
        }

        let page = parse_tools_list_response_page(&line)?;
        page_count += 1;
        pages.accept_page(page.tools);
        pages.incomplete_if_truncated(MCP_VERSION_2026_07_28, page.next_cursor.as_deref())?;

        match PageAccumulator::next_cursor(page.next_cursor) {
            Some(next) => current_cursor = Some(next),
            None => break,
        }
    }

    Ok(ToolsListFetch {
        tools: pages.tools,
        protocol_version: version,
    })
}

async fn fetch_mcp_2025_11_25(
    command: &[String],
    timeout: Duration,
    opts: &DiscoveryOptions,
) -> Result<ToolsListFetch, ToolsListError> {
    let (mut child, tmpdir) = spawn_server(command, true, opts).await?;
    let result = fetch_mcp_2025_11_25_on_child(&mut child, timeout).await;
    shutdown_child(&mut child).await;
    remove_discovery_tmpdir(tmpdir);
    result
}

async fn fetch_mcp_2025_11_25_on_child(
    child: &mut DiscoveryChild,
    timeout: Duration,
) -> Result<ToolsListFetch, ToolsListError> {
    let version = SupportedProtocolVersion::Mcp2025November25;
    let mut session = child.take_stdio(version, ProtocolStep::Initialize)?;

    let init_id = session.alloc_id();
    session
        .send(
            &build_mcp_2025_11_25_initialize(init_id),
            version,
            ProtocolStep::Initialize,
        )
        .await?;
    let init_line = session
        .recv_response(init_id, version, ProtocolStep::Initialize, timeout)
        .await?;
    if let Some(err) = parse_jsonrpc_error(&init_line) {
        return Err(ToolsListError::Protocol {
            protocol_version: version,
            step: ProtocolStep::Initialize,
            detail: format!("server returned error: {}", err.display_detail()),
        });
    }
    if !jsonrpc_has_result(&init_line) {
        return Err(ToolsListError::Protocol {
            protocol_version: version,
            step: ProtocolStep::Initialize,
            detail: "initialize response missing result".to_string(),
        });
    }
    let selected_version =
        parse_initialize_protocol_version(&init_line).ok_or_else(|| ToolsListError::Protocol {
            protocol_version: version,
            step: ProtocolStep::Initialize,
            detail: "initialize response missing result.protocolVersion".to_string(),
        })?;
    if selected_version != MCP_VERSION_2025_11_25 {
        return Err(ToolsListError::UnsupportedProtocolVersion {
            requested: version,
            server_versions: vec![selected_version],
        });
    }

    session
        .send(
            &build_initialized_notification(),
            version,
            ProtocolStep::Initialized,
        )
        .await?;

    let mut pages = PageAccumulator::new();
    let mut current_cursor: Option<String> = None;
    let mut seen_cursors = std::collections::HashSet::new();
    let mut page_count = 0;

    loop {
        if page_count >= MAX_PAGES {
            return Err(ToolsListError::PaginationIncomplete(format!(
                "MCP {MCP_VERSION_2025_11_25} tools/list exceeded max page limit ({MAX_PAGES})"
            )));
        }

        if let Some(ref c) = current_cursor
            && !seen_cursors.insert(c.clone())
        {
            return Err(ToolsListError::PaginationIncomplete(format!(
                "MCP {MCP_VERSION_2025_11_25} tools/list detected repeated cursor '{c}', terminating pagination"
            )));
        }

        let list_id = session.alloc_id();
        let request =
            build_mcp_2025_11_25_tools_list_with_cursor(list_id, current_cursor.as_deref());
        session
            .send(&request, version, ProtocolStep::ToolsList)
            .await?;
        let list_line = session
            .recv_response(list_id, version, ProtocolStep::ToolsList, timeout)
            .await?;
        pages.note_page_bytes(list_line.len(), MCP_VERSION_2025_11_25)?;
        if let Some(err) = parse_jsonrpc_error(&list_line) {
            return Err(ToolsListError::Protocol {
                protocol_version: version,
                step: ProtocolStep::ToolsList,
                detail: format!("server returned error: {}", err.display_detail()),
            });
        }

        let page = parse_tools_list_response_page(&list_line)?;
        page_count += 1;
        pages.accept_page(page.tools);
        pages.incomplete_if_truncated(MCP_VERSION_2025_11_25, page.next_cursor.as_deref())?;

        match PageAccumulator::next_cursor(page.next_cursor) {
            Some(next) => current_cursor = Some(next),
            None => break,
        }
    }

    Ok(ToolsListFetch {
        tools: pages.tools,
        protocol_version: version,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A temp fixture mirroring a payload tree: secrets beside and
    /// below the payload, clean siblings, and the non-secret
    /// `.env.example` / `.aws/config` counterparts.
    struct SecretFixture {
        root: tempfile::TempDir,
    }

    impl SecretFixture {
        fn new() -> Self {
            let root = tempfile::tempdir().unwrap();
            let r = root.path();
            std::fs::write(r.join("server.py"), b"print('x')").unwrap();
            std::fs::create_dir_all(r.join("lib")).unwrap();
            std::fs::write(r.join("lib").join("util.py"), b"x = 1").unwrap();
            // Secrets adjacent to the payload and one level deeper.
            std::fs::write(r.join(".env"), b"KEY=x").unwrap();
            std::fs::create_dir_all(r.join(".ssh")).unwrap();
            std::fs::write(r.join(".ssh").join("id_rsa"), b"key").unwrap();
            std::fs::create_dir_all(r.join(".gnupg")).unwrap();
            std::fs::create_dir_all(r.join(".aws")).unwrap();
            std::fs::write(r.join(".aws").join("credentials"), b"aws").unwrap();
            std::fs::write(r.join(".aws").join("config"), b"region=x").unwrap();
            std::fs::create_dir_all(r.join("config")).unwrap();
            std::fs::write(r.join("config").join(".env.local"), b"KEY=x").unwrap();
            std::fs::write(r.join("config").join("app.toml"), b"x").unwrap();
            // Deliberately non-secret lookalikes that must stay granted.
            std::fs::write(r.join(".env.example"), b"KEY=").unwrap();
            Self { root }
        }

        fn path(&self, rel: &str) -> PathBuf {
            self.root.path().join(rel)
        }
    }

    fn grants_cover(grants: &[PathBuf], target: &Path) -> bool {
        grants.iter().any(|g| {
            let g = g.to_string_lossy();
            crate::policy::validator::covers_or_same(&g, &target.to_string_lossy())
                || target.starts_with(Path::new(g.as_ref()))
        })
    }

    /// P1/F-discovery-secret: carving a payload tree must leave no
    /// grant covering a reserved secret — adjacent or nested — while
    /// keeping the payload and its clean siblings reachable.
    #[test]
    fn carve_leaves_no_reserved_path_covered() {
        let fx = SecretFixture::new();
        let mut budget = SECRET_SCAN_MAX_ENTRIES;
        let (grants, secrets) = carved_grant_paths(fx.root.path(), &mut budget, None).unwrap();

        for reserved in [
            ".env",
            ".ssh",
            ".ssh/id_rsa",
            ".gnupg",
            ".aws/credentials",
            "config/.env.local",
        ] {
            let p = fx.path(reserved);
            assert!(
                !grants_cover(&grants, &p),
                "grant must not cover {reserved}: {grants:?}"
            );
        }
        // `.ssh` is reserved as a whole directory — its contents are
        // never enumerated, so the scan records the dir, not id_rsa.
        for recorded in [
            ".env",
            ".ssh",
            ".gnupg",
            ".aws/credentials",
            "config/.env.local",
        ] {
            assert!(
                secrets.contains(&fx.path(recorded)),
                "scan must record {recorded}"
            );
        }
        for needed in ["server.py", ".env.example", "config/app.toml", "lib"] {
            let p = fx.path(needed);
            assert!(
                grants_cover(&grants, &p),
                "legitimate path must stay covered: {needed}"
            );
        }
        // `.aws/config` is not reserved — the `.aws` dir is carved only
        // around `credentials`.
        let cfg = fx.path(".aws/config");
        assert!(grants_cover(&grants, &cfg), "non-secret .aws contents stay");
    }

    /// P1: a clean tree keeps its single root grant — the common case
    /// adds no rules.
    #[test]
    fn clean_tree_collapses_to_root_grant() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("server.py"), b"x").unwrap();
        std::fs::create_dir_all(dir.path().join("lib")).unwrap();
        std::fs::write(dir.path().join("lib").join("u.py"), b"x").unwrap();
        let mut budget = SECRET_SCAN_MAX_ENTRIES;
        let (grants, secrets) = carved_grant_paths(dir.path(), &mut budget, None).unwrap();
        assert!(secrets.is_empty());
        assert_eq!(grants, vec![dir.path().to_path_buf()]);
    }

    /// Create a directory symlink/junction — privileges are not always
    /// available (Windows needs SeCreateSymbolicLinkPrivilege or dev
    /// mode), so callers skip on `Err`.
    #[cfg(unix)]
    fn symlink_dir(target: &Path, link: &Path) -> std::io::Result<()> {
        std::os::unix::fs::symlink(target, link)
    }
    #[cfg(windows)]
    fn symlink_dir(target: &Path, link: &Path) -> std::io::Result<()> {
        std::os::windows::fs::symlink_dir(target, link)
    }

    /// P1: a symlinked carve root resolves to its real tree — the
    /// spelled grants name the target's paths (never the link, whose
    /// wholesale grant would cover the target's reserved secrets).
    /// Skips when the OS cannot mint the fixture link.
    #[test]
    fn carve_root_symlink_resolves_to_real_tree() {
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("real");
        std::fs::create_dir_all(&real).unwrap();
        std::fs::write(real.join("app.py"), b"x").unwrap();
        std::fs::write(real.join(".env"), b"K=1").unwrap();
        let link = dir.path().join("link");
        if symlink_dir(&real, &link).is_err() {
            eprintln!("symlink fixture unavailable — skipping");
            return;
        }
        let mut budget = SECRET_SCAN_MAX_ENTRIES;
        let (grants, secrets) = carved_grant_paths(&link, &mut budget, None).unwrap();
        // The link spelling must not survive as a grant — the backend
        // would resolve it to the target's whole tree, `.env` included.
        assert!(!grants_cover(&grants, &link.join(".env")));
        // The real tree is carved instead: `.env` recorded, payload granted.
        let env = real.join(".env").canonicalize().unwrap();
        assert!(
            secrets
                .iter()
                .any(|s| resolved_path_covers(s, &env) && resolved_path_covers(&env, s)),
            "resolved .env must be recorded"
        );
        let app = real.join("app.py").canonicalize().unwrap();
        assert!(
            grants
                .iter()
                .any(|g| resolved_path_covers(g, &app) && resolved_path_covers(&app, g)),
            "payload file must keep its grant"
        );
    }

    /// P1: a symlink *inside* the tree is never granted — the spelled
    /// grant would resolve wherever the link points.
    #[test]
    fn carve_skips_symlink_entries() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target");
        std::fs::create_dir_all(&target).unwrap();
        std::fs::write(target.join(".env"), b"K=1").unwrap();
        let root = dir.path().join("payload");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("app.py"), b"x").unwrap();
        if symlink_dir(&target, &root.join("link")).is_err() {
            eprintln!("symlink fixture unavailable — skipping");
            return;
        }
        let mut budget = SECRET_SCAN_MAX_ENTRIES;
        let (grants, secrets) = carved_grant_paths(&root, &mut budget, None).unwrap();
        // The link itself must never become a grant path — a spelled
        // grant on the symlink would resolve to whatever it points at
        // (the wholesale-target hole). A `root` grant over the spelled
        // tree stays safe: backends cover the tree as spelled, not the
        // link's target, which lives outside it.
        assert!(
            !grants.iter().any(|g| *g == root.join("link")),
            "symlink must not be granted: {grants:?}"
        );
        // The link's target lives outside the carved root — the walk
        // saw nothing reserved and the payload tree stays clean.
        assert!(secrets.is_empty());
    }

    /// P1: a reparse root that cannot be resolved fails closed — its
    /// spelled grant could never be proven secret-free.
    #[test]
    fn carve_unresolvable_reparse_root_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("missing-target");
        let link = dir.path().join("dangling");
        if symlink_dir(&missing, &link).is_err() {
            eprintln!("symlink fixture unavailable — skipping");
            return;
        }
        let mut budget = SECRET_SCAN_MAX_ENTRIES;
        assert!(carved_grant_paths(&link, &mut budget, None).is_err());
    }

    /// P1: `carve_dir` itself refuses a reparse root — `Clean` would
    /// let the caller grant the link wholesale, so the walk must fail
    /// closed even if the node was swapped beneath the resolution.
    #[test]
    fn carve_dir_refuses_reparse_root() {
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("real");
        std::fs::create_dir_all(&real).unwrap();
        let link = dir.path().join("link");
        if symlink_dir(&real, &link).is_err() {
            eprintln!("symlink fixture unavailable — skipping");
            return;
        }
        let mut budget = SECRET_SCAN_MAX_ENTRIES;
        let mut secrets = Vec::new();
        assert!(carve_dir(&link, false, &mut budget, &mut secrets, None).is_err());
    }

    /// P1: the scan budget refuses a tree it cannot prove secret-free
    /// — discovery fails closed rather than grant the unexplored rest.
    #[test]
    fn carve_budget_exhaustion_fails_closed() {
        let fx = SecretFixture::new();
        let mut budget = 2usize; // far below the fixture's entry count
        assert!(carved_grant_paths(fx.root.path(), &mut budget, None).is_err());
    }

    /// P1: a reserved path a surviving grant still covers lands in
    /// `denied_paths` — every backend refuses on that overlap rather
    /// than silently re-allowing it.
    #[test]
    fn covered_secret_becomes_explicit_deny() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("server.py"), b"x").unwrap();
        std::fs::write(dir.path().join(".env"), b"K=1").unwrap();
        let mut policy = crate::policy::Policy::default();
        // Simulate a runtime grant covering the command tree (e.g. a
        // payload beneath /usr): the carve cannot reach through it.
        policy
            .fs
            .read_only
            .push(format!("{}/**", dir.path().display()));
        // Mimic the probe's spelling so retain() does not drop it.
        let mut budget = SECRET_SCAN_MAX_ENTRIES;
        let parent = plain_spelling(&dir.path().canonicalize().unwrap());
        let (grants, secrets) = carved_grant_paths(&parent, &mut budget, None).unwrap();
        for g in grants {
            if !policy
                .fs
                .read_only
                .contains(&g.to_string_lossy().into_owned())
            {
                policy.fs.read_only.push(g.to_string_lossy().into_owned());
            }
        }
        deny_covered_secrets(&mut policy, &secrets);
        // Secrets are enumerated under a canonicalized parent, so the
        // deny carries the resolved spelling — canonicalize the
        // expectation the same way before comparing.
        let env = dir.path().join(".env").canonicalize().unwrap();
        assert!(
            policy.fs.denied_paths.iter().any(|d| {
                let d = Path::new(d);
                resolved_path_covers(d, &env) && resolved_path_covers(&env, d)
            }),
            "covered secret must become a deny: {:?}",
            policy.fs.denied_paths
        );
    }

    /// The probe grants a directory argument's *parent* — the carve
    /// must reach that same root or the broad `dir/**` grant survives
    /// beside the carved children, reserved siblings included.
    #[test]
    fn discovery_policy_carves_dir_arg_parent() {
        let dir = tempfile::tempdir().unwrap();
        let proj = dir.path().join("proj");
        let work = proj.join("work");
        std::fs::create_dir_all(&work).unwrap();
        let env = proj.join(".env");
        std::fs::write(&env, b"K=1").unwrap();
        let command = vec![
            "definitely-not-a-resolvable-tool".to_string(),
            work.to_string_lossy().into_owned(),
        ];
        let policy = discovery_policy(&command, dir.path()).unwrap();
        let env = env.canonicalize().unwrap();
        let covered = policy
            .fs
            .read_only
            .iter()
            .any(|g| grant_covers_secret(g, &env));
        if covered {
            assert!(
                policy.fs.denied_paths.iter().any(|d| {
                    let d = Path::new(d);
                    resolved_path_covers(d, &env) && resolved_path_covers(&env, d)
                }),
                "a surviving grant covers the reserved path with no deny: {:?}",
                policy.fs.denied_paths
            );
        }
    }

    /// A bare argument names a file beside the process — the carve
    /// root is the current directory, same as the probe grants, never
    /// an empty path that would fail the walk.
    #[test]
    fn command_parent_dirs_normalizes_bare_args() {
        let parents = command_parent_dirs(&[
            "definitely-not-a-resolvable-tool".to_string(),
            "missing-config.json".to_string(),
        ]);
        let cwd = plain_spelling(&std::env::current_dir().unwrap().canonicalize().unwrap());
        assert!(
            parents.contains(&cwd),
            "bare arg must root at the current directory: {parents:?}"
        );
        assert!(parents.iter().all(|p| !p.as_os_str().is_empty()));
    }

    /// An already-expired deadline fails the walk even where nothing
    /// would be scanned — the grant never outlives its bound.
    #[test]
    fn carve_deadline_expired_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        let mut budget = SECRET_SCAN_MAX_ENTRIES;
        let past = Instant::now() - Duration::from_secs(1);
        assert!(carved_grant_paths(dir.path(), &mut budget, Some(past)).is_err());
        // The clean early-outs gate on the deadline too — a vanished
        // root still fails closed rather than granting after expiry.
        let missing = dir.path().join("no-such-dir");
        assert!(carved_grant_paths(&missing, &mut budget, Some(past)).is_err());
    }

    /// The self-test carves argument roots like discovery while every
    /// other grant — the executable-parent `dir/**` the probe needs to
    /// exec its image — survives untouched.
    #[test]
    fn self_test_arg_carve_keeps_non_arg_grants() {
        let dir = tempfile::tempdir().unwrap();
        let proj = dir.path().join("proj");
        let work = proj.join("work");
        std::fs::create_dir_all(&work).unwrap();
        let env = proj.join(".env");
        std::fs::write(&env, b"K=1").unwrap();
        #[cfg(windows)]
        let exe = "cmd";
        #[cfg(not(windows))]
        let exe = "echo";
        let command = vec![exe.to_string(), work.to_string_lossy().into_owned()];
        let mut policy = crate::legislator::self_test_warden::prepare_warden_probe_policy(
            &crate::policy::Policy::default(),
            dir.path(),
            &command,
        );
        // The executable-parent grant Landlock needs to exec the probe
        // image — spelled here as `prepare_warden_probe_policy` adds it
        // on Linux (`push_landlock_dir` drops `\\?\`-verbatim spellings
        // on Windows, so the test spells the grant itself).
        let exe_parent = crate::workload::resolve_command_path(exe)
            .unwrap()
            .parent()
            .unwrap()
            .to_path_buf();
        policy
            .fs
            .read_only
            .push(format!("{}/**", exe_parent.display()));
        carve_arg_grants(&mut policy, &command, None).unwrap();
        let exe_parent = exe_parent.canonicalize().unwrap();
        assert!(
            policy
                .fs
                .read_only
                .iter()
                .any(|g| grant_names_dir(g, &exe_parent)),
            "executable-parent grant must survive: {:?}",
            policy.fs.read_only
        );
        let env = env.canonicalize().unwrap();
        if policy
            .fs
            .read_only
            .iter()
            .any(|g| grant_covers_secret(g, &env))
        {
            assert!(
                policy.fs.denied_paths.iter().any(|d| {
                    let d = Path::new(d);
                    resolved_path_covers(d, &env) && resolved_path_covers(&env, d)
                }),
                "surviving grant covers .env with no deny: {:?}",
                policy.fs.denied_paths
            );
        }
    }

    /// An argument parent that coincides with the executable's own
    /// parent must not delete the access the image launches under: a
    /// `dir/**` grant the probe already spelled stays and its reserved
    /// names are denied, while a platform whose grant filter dropped
    /// the spelling still gets the carved children — the parent keeps
    /// access either way. The stand-in exe lives in a tempdir so no
    /// file beside a real image is touched — nothing execs it, the
    /// path only needs to resolve.
    #[test]
    fn shared_exe_parent_grant_preserved_and_secret_denied() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();
        let exe = dir.join("carve-shared-parent-exe");
        std::fs::write(&exe, b"probe image").unwrap();
        let arg_file = dir.join("carve-shared-parent-arg.txt");
        let env = dir.join(".env");
        std::fs::write(&arg_file, b"x").unwrap();
        std::fs::write(&env, b"K=1").unwrap();

        let command = vec![
            exe.to_string_lossy().into_owned(),
            arg_file.to_string_lossy().into_owned(),
        ];
        let mut policy = crate::legislator::self_test_warden::prepare_warden_probe_policy(
            &crate::policy::Policy::default(),
            dir,
            &command,
        );
        carve_arg_grants(&mut policy, &command, None).unwrap();

        // The parent's access survives either as its preserved
        // `dir/**` (where the spelled grant landed) or as carved
        // children (where a platform's grant filter dropped it).
        let dir_canon = dir.canonicalize().unwrap();
        let arg_canon = arg_file.canonicalize().unwrap();
        let preserved = policy
            .fs
            .read_only
            .iter()
            .any(|g| grant_names_dir(g, &dir_canon));
        let carved_cover = policy.fs.read_only.iter().any(|g| {
            let g = Path::new(g);
            resolved_path_covers(g, &arg_canon) && resolved_path_covers(&arg_canon, g)
        });
        assert!(
            preserved || carved_cover,
            "shared executable parent must keep access: {:?}",
            policy.fs.read_only
        );
        // `.env` is never left covered-but-undenied: under a preserved
        // `dir/**` it lands in `denied_paths`, under carved grants it
        // simply has no grant.
        let env_canon = env.canonicalize().unwrap();
        if policy
            .fs
            .read_only
            .iter()
            .any(|g| grant_covers_secret(g, &env_canon))
        {
            assert!(
                policy.fs.denied_paths.iter().any(|d| {
                    let d = Path::new(d);
                    resolved_path_covers(d, &env_canon) && resolved_path_covers(&env_canon, d)
                }),
                "secret under the preserved grant must be denied: {:?}",
                policy.fs.denied_paths
            );
        }
    }

    /// Option spellings and punctuation-free literals are never
    /// filesystem paths — `--mode` and `stdio` contribute neither a
    /// carve root nor a probe grant.
    #[test]
    fn non_path_args_add_no_grant_or_carve_root() {
        let command = vec![
            "definitely-not-a-resolvable-tool".to_string(),
            "--mode".to_string(),
            "stdio".to_string(),
        ];
        let parents = command_parent_dirs(&command);
        assert!(
            parents.is_empty(),
            "options and literals must yield no carve root: {parents:?}"
        );
        let tmp = tempfile::tempdir().unwrap();
        let policy = crate::legislator::self_test_warden::prepare_warden_probe_policy(
            &crate::policy::Policy::default(),
            tmp.path(),
            &command,
        );
        let cwd = std::env::current_dir().unwrap().canonicalize().unwrap();
        assert!(
            !policy.fs.read_only.iter().any(|g| grant_names_dir(g, &cwd)),
            "non-path args must not grant the current directory: {:?}",
            policy.fs.read_only
        );
    }

    /// The probe policy itself must spell that same access — a bare
    /// argument's `//`-less parent becomes `./**`, not a dropped
    /// grant.
    #[test]
    fn probe_policy_keeps_cwd_for_bare_args() {
        let tmp = tempfile::tempdir().unwrap();
        let command = vec![
            "definitely-not-a-resolvable-tool".to_string(),
            "missing-config.json".to_string(),
        ];
        let policy = crate::legislator::self_test_warden::prepare_warden_probe_policy(
            &crate::policy::Policy::default(),
            tmp.path(),
            &command,
        );
        assert!(
            policy.fs.read_only.iter().any(|g| g == "./**"),
            "bare arg must retain current-directory access: {:?}",
            policy.fs.read_only
        );
    }

    /// F64/F-budget: page-count and per-frame caps alone let fifty
    /// near-limit pages retain hundreds of MiB — the cumulative byte
    /// budget must trip well before `MAX_PAGES`.
    #[test]
    fn page_byte_budget_fails_closed_before_page_limit() {
        let mut acc = PageAccumulator::new();
        let fat_page = 512 * 1024; // well under the 10 MiB frame cap
        let mut charged = 0usize;
        let mut err = None;
        for _ in 0..MAX_PAGES {
            match acc.note_page_bytes(fat_page, "test") {
                Ok(()) => charged += 1,
                Err(e) => {
                    err = Some(e);
                    break;
                }
            }
        }
        let err = err.expect("near-limit pages must trip the aggregate budget");
        assert!(matches!(err, ToolsListError::PaginationIncomplete(_)));
        assert!(
            charged < MAX_PAGES,
            "budget must trip before the page count limit ({charged} pages charged)"
        );
        assert!(charged > 1, "a normal listing is nowhere near the cap");
    }

    #[tokio::test]
    async fn test_fetch_tools_list_timeout() {
        #[cfg(windows)]
        let cmd = vec![
            "powershell".to_string(),
            "-NoProfile".to_string(),
            "-Command".to_string(),
            "Start-Sleep -Seconds 10".to_string(),
        ];
        #[cfg(not(windows))]
        let cmd = vec!["sleep".to_string(), "60".to_string()];

        let result = fetch_tools_list(&cmd, Some(Duration::from_millis(100))).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, ToolsListError::Timeout { .. }),
            "expected Timeout, got {err:?}"
        );
    }

    #[tokio::test]
    async fn test_fetch_tools_list_bad_command() {
        let result = fetch_tools_list(
            &["__nonexistent_binary_that_should_not_exist__".to_string()],
            Some(Duration::from_millis(500)),
        )
        .await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, ToolsListError::ProcessSpawn(_)));
    }
}
