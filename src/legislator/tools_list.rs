use std::fmt;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};

use crate::protocol::tools_list::{
    MAX_PAGES, MAX_TOTAL_TOOLS, ToolsListParseError, parse_tools_list_response_page,
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
}

impl PageAccumulator {
    fn new() -> Self {
        Self {
            tools: Vec::new(),
            reached_limit: false,
            has_more_in_page: false,
        }
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
    Sandboxed(crate::warden::RunningChild),
    Plain(tokio::process::Child),
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
                .map(|(c, t)| (DiscoveryChild::Plain(c), t));
        }
        return spawn_server_sandboxed(command)
            .await
            .map(|(c, t)| (DiscoveryChild::Sandboxed(c), Some(t)));
    }
    spawn_server_plain_ambient(command, inherit_stderr).map(|(c, t)| (DiscoveryChild::Plain(c), t))
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
fn discovery_policy(command: &[String], tmpdir: &Path) -> crate::policy::Policy {
    let mut policy = crate::legislator::self_test_warden::prepare_warden_probe_policy(
        &crate::policy::Policy::default(),
        tmpdir,
        command,
    );
    push_literal_dirs(&mut policy, command);
    // `prepare_warden_probe_policy` waives the secrets overlay for the
    // self-test control file — a discovery server gets no such pass.
    policy.fs.secret_overlay = true;
    // macOS carries no kernel descendant-lifetime boundary, and the
    // launch host may have no writable cgroup — discovery accepts the
    // RunningChild's best-effort process-tree sweep rather than
    // refusing outright.
    policy.sandbox.require_lifetime_boundary = false;
    policy
}

/// Literal spellings of the directories `prepare_warden_probe_policy`
/// grants as `dir/**`. Landlock strips the glob to the same root, so a
/// literal entry is equivalent there — and it is the only spelling
/// Windows DACL grants and macOS literal subpaths can express. The
/// literal set mirrors the probe walk: the executable's parent plus
/// the parent of every path-valued argument (the workload's own tree).
fn push_literal_dirs(policy: &mut crate::policy::Policy, command: &[String]) {
    fn push(list: &mut Vec<String>, dir: &Path) {
        let dir = dir.to_string_lossy().into_owned();
        if !list.contains(&dir) {
            list.push(dir);
        }
    }
    if let Some(argv0) = command.first()
        && let Ok(resolved) = crate::workload::resolve_command_path(argv0)
        && let Some(parent) = resolved.parent()
    {
        push(&mut policy.fs.read_only, parent);
    }
    for arg in command.iter().skip(1) {
        let path = Path::new(arg);
        if !path.exists() {
            continue;
        }
        let parent = if path.is_dir() {
            Some(path.to_path_buf())
        } else {
            path.canonicalize()
                .ok()
                .and_then(|c| c.parent().map(Path::to_path_buf))
                .or_else(|| path.parent().map(Path::to_path_buf))
        };
        if let Some(parent) = parent {
            // Keep parity with the probe walk: a grant covering
            // WARDEN_PROBE_PATH would erase OS-deny evidence.
            let canonical = parent.canonicalize().unwrap_or_else(|_| parent.clone());
            if !Path::new(crate::legislator::self_test::WARDEN_PROBE_PATH).starts_with(&canonical) {
                push(&mut policy.fs.read_only, &parent);
            }
        }
    }
}

fn create_discovery_tmpdir() -> Result<PathBuf, ToolsListError> {
    let tmp = std::env::temp_dir() // nosemgrep: rust.lang.security.temp-dir.temp-dir
        .join(format!(
            "mcp-writ-discover-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
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
    let policy = discovery_policy(command, &tmp);
    let resolved = crate::workload::resolve_command_path(&command[0]).map_err(|e| {
        let _ = std::fs::remove_dir_all(&tmp);
        ToolsListError::ProcessSpawn(io::Error::other(format!(
            "cannot resolve '{}': {e}",
            command[0]
        )))
    })?;
    let mut argv = command.to_vec();
    argv[0] = resolved.to_string_lossy().into_owned();
    let opts = crate::warden::SpawnOptions {
        restrict_environment: true,
        allowed_names: Vec::new(),
        tmpdir: Some(tmp.clone()),
        ..Default::default()
    };
    // A discovery workload is a real spawn: dyld needs the same
    // derived code-map grants a `run` launch computes (argv[0] is
    // resolved).
    #[cfg(target_os = "macos")]
    let opts = {
        let mut o = opts;
        o.exec_map_dirs =
            crate::warden::macos_sandbox::code_map_dirs(std::path::Path::new(&argv[0]), &argv);
        o
    };
    match crate::warden::Warden::new(policy)
        .spawn_child_async_with(&argv, &opts)
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
        assert!(matches!(err, ToolsListError::Timeout { .. }));
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
