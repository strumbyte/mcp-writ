use std::fmt;
use std::io;
use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

use tokio::io::{AsyncWriteExt, BufReader};

use crate::protocol::tools_list::{MAX_PAGES, ToolsListParseError, parse_tools_list_response_page};
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

const MAX_TOTAL_TOOLS: usize = 1000;

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
                tracing::warn!(tool = %tool.name, "duplicate tool name in tools/list; skipping");
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
    /// When true, clear the child environment except PATH and a private TMPDIR.
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
    stdin: tokio::process::ChildStdin,
    reader: BufReader<tokio::process::ChildStdout>,
    next_id: i64,
}

impl StdioSession {
    fn from_child(
        child: &mut tokio::process::Child,
        protocol_version: SupportedProtocolVersion,
        step: ProtocolStep,
    ) -> Result<Self, ToolsListError> {
        let stdin = child.stdin.take().ok_or_else(|| ToolsListError::Io {
            protocol_version,
            step,
            source: io::Error::other("failed to capture child stdin"),
        })?;
        let stdout = child.stdout.take().ok_or_else(|| ToolsListError::Io {
            protocol_version,
            step,
            source: io::Error::other("failed to capture child stdout"),
        })?;
        Ok(Self {
            stdin,
            reader: BufReader::new(stdout),
            next_id: 1,
        })
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
                                "JSON-RPC frame exceeds {limit} bytes ({bytes} without newline)"
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

fn spawn_server(
    command: &[String],
    inherit_stderr: bool,
    opts: &DiscoveryOptions,
) -> Result<(tokio::process::Child, Option<PathBuf>), ToolsListError> {
    let mut cmd = tokio::process::Command::new(&command[0]);
    cmd.args(&command[1..])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .kill_on_drop(true);
    if inherit_stderr {
        cmd.stderr(Stdio::inherit());
    } else {
        cmd.stderr(Stdio::null());
    }
    let mut tmpdir = None;
    if opts.restrict_environment {
        cmd.env_clear();
        if let Ok(path) = std::env::var("PATH") {
            cmd.env("PATH", path);
        }
        #[cfg(windows)]
        {
            if let Ok(sr) = std::env::var("SYSTEMROOT") {
                cmd.env("SYSTEMROOT", sr);
            }
            if let Ok(windir) = std::env::var("WINDIR") {
                cmd.env("WINDIR", windir);
            }
            if let Ok(pathext) = std::env::var("PATHEXT") {
                cmd.env("PATHEXT", pathext);
            }
        }
        let tmp = std::env::temp_dir().join(format!(
            "mcp-writ-discover-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        if std::fs::create_dir_all(&tmp).is_ok() {
            #[cfg(unix)]
            {
                if let Err(e) =
                    std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o700))
                {
                    let _ = std::fs::remove_dir_all(&tmp);
                    return Err(ToolsListError::ProcessSpawn(e));
                }
            }
            cmd.env("TMPDIR", &tmp);
            cmd.env("TMP", &tmp);
            cmd.env("TEMP", &tmp);
            tmpdir = Some(tmp);
        }
    }
    match cmd.spawn() {
        Ok(child) => Ok((child, tmpdir)),
        Err(e) => {
            if let Some(dir) = tmpdir {
                let _ = std::fs::remove_dir_all(dir);
            }
            Err(ToolsListError::ProcessSpawn(e))
        }
    }
}

async fn shutdown_child(child: &mut tokio::process::Child) {
    drop(child.stdin.take());
    match tokio::time::timeout(Duration::from_millis(200), child.wait()).await {
        Ok(_) => {}
        Err(_) => {
            let _ = child.kill().await;
            let _ = child.wait().await;
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
    let (mut child, tmpdir) = spawn_server(command, false, opts)?;
    let outcome = probe_protocol_version_on_sibling(&mut child, timeout).await;
    shutdown_child(&mut child).await;
    remove_discovery_tmpdir(tmpdir);
    Ok(outcome)
}

async fn probe_protocol_version_on_sibling(
    child: &mut tokio::process::Child,
    timeout: Duration,
) -> VersionProbeOutcome {
    let version = SupportedProtocolVersion::Mcp2026July28;
    let mut session = match StdioSession::from_child(child, version, ProtocolStep::Probe) {
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
    let (mut child, tmpdir) = spawn_server(command, true, opts)?;
    let result = fetch_mcp_2026_07_28_on_child(&mut child, timeout).await;
    shutdown_child(&mut child).await;
    remove_discovery_tmpdir(tmpdir);
    result
}

async fn fetch_mcp_2026_07_28_on_child(
    child: &mut tokio::process::Child,
    timeout: Duration,
) -> Result<ToolsListFetch, ToolsListError> {
    let version = SupportedProtocolVersion::Mcp2026July28;
    let mut session = StdioSession::from_child(child, version, ProtocolStep::ToolsList)?;
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
    let (mut child, tmpdir) = spawn_server(command, true, opts)?;
    let result = fetch_mcp_2025_11_25_on_child(&mut child, timeout).await;
    shutdown_child(&mut child).await;
    remove_discovery_tmpdir(tmpdir);
    result
}

async fn fetch_mcp_2025_11_25_on_child(
    child: &mut tokio::process::Child,
    timeout: Duration,
) -> Result<ToolsListFetch, ToolsListError> {
    let version = SupportedProtocolVersion::Mcp2025November25;
    let mut session = StdioSession::from_child(child, version, ProtocolStep::Initialize)?;

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
