//! Legislator client coverage for MCP `2026-07-28` and `2025-11-25`.
//!
//! Fixtures live in `tests/fixtures/mcp_servers/`. No network, no rmcp.

use std::time::Duration;

#[cfg(unix)]
use std::path::PathBuf;

mod common;

use mcp_writ::legislator::tools_list::{DiscoveryOptions, ToolsListError, ToolsListFetch};
use mcp_writ::protocol::SupportedProtocolVersion;

fn fixture_server(name: &str) -> Vec<String> {
    common::python3_script_argv(&format!("tests/fixtures/mcp_servers/{name}"))
}

/// Sandboxed discovery mutates the fixture dirs' DACLs; parallel
/// fetches race grant/restore read-modify-write and can drop a sibling
/// session's ACE mid-run, so these fetches serialize. Fixture fetches
/// run with `allow_best_effort_lifetime` so hosts without a writable
/// cgroup v2 hierarchy (or macOS, which has no descendant-lifetime
/// boundary at all) still exercise the fetch — the production default
/// stays strict.
async fn fetch_tools_list_detailed(
    command: &[String],
    timeout: Option<Duration>,
) -> Result<ToolsListFetch, ToolsListError> {
    let _g = common::sandbox_spawn_lock().lock().await;
    mcp_writ::legislator::tools_list::fetch_tools_list_detailed_with(
        command,
        timeout,
        &DiscoveryOptions {
            allow_best_effort_lifetime: true,
            ..DiscoveryOptions::default()
        },
    )
    .await
}

fn fetch_timeout() -> Option<Duration> {
    Some(Duration::from_secs(5))
}

#[tokio::test]
async fn fetch_mcp_2025_11_25_server() {
    let fetched = fetch_tools_list_detailed(&fixture_server("mcp_2025_11_25.py"), fetch_timeout())
        .await
        .expect("MCP 2025-11-25 initialize server should succeed");

    assert_eq!(
        fetched.protocol_version,
        SupportedProtocolVersion::Mcp2025November25
    );
    assert_eq!(fetched.tools.len(), 1);
    assert_eq!(fetched.tools[0].name, "read_file");
    assert_eq!(fetched.tools[0].description, "Read a file from disk");
    assert!(
        fetched.tools[0]
            .input_schema
            .as_ref()
            .is_some_and(|s| s.contains("path")),
        "inputSchema should be preserved"
    );
}

#[tokio::test]
async fn fetch_mcp_2026_07_28_meta_discover_server() {
    let fetched = fetch_tools_list_detailed(&fixture_server("mcp_2026_07_28.py"), fetch_timeout())
        .await
        .expect("MCP 2026-07-28 _meta server should succeed");

    assert_eq!(
        fetched.protocol_version,
        SupportedProtocolVersion::Mcp2026July28
    );
    assert_eq!(fetched.tools.len(), 1);
    assert_eq!(fetched.tools[0].name, "read_file");
    assert_eq!(fetched.tools[0].description, "Read a file from disk");
    let schema = fetched.tools[0].input_schema.as_ref().expect("schema");
    assert!(schema.contains("path"));
    assert!(
        !schema.contains("ttlMs") && !schema.contains("cacheScope"),
        "parser must ignore list cache fields"
    );
}

#[tokio::test]
async fn fetch_rejects_unimplemented_future_protocol_version() {
    let mut command = fixture_server("mcp_2026_07_28.py");
    command.extend(["--accept-version".to_string(), "2026-08-01".to_string()]);

    let err = fetch_tools_list_detailed(&command, fetch_timeout())
        .await
        .expect_err("an unimplemented future revision must not be retried as supported");

    assert!(matches!(
        err,
        ToolsListError::UnsupportedProtocolVersion {
            requested: SupportedProtocolVersion::Mcp2026July28,
            ref server_versions,
        } if server_versions == &["2026-08-01".to_string()]
    ));
}

#[tokio::test]
async fn fetch_rejects_unimplemented_initialize_protocol_version() {
    let mut command = fixture_server("mcp_2025_11_25.py");
    command.extend(["--protocol-version".to_string(), "2025-06-18".to_string()]);

    let err = fetch_tools_list_detailed(&command, fetch_timeout())
        .await
        .expect_err("an unimplemented initialize revision must not be accepted");

    assert!(matches!(
        err,
        ToolsListError::UnsupportedProtocolVersion {
            requested: SupportedProtocolVersion::Mcp2025November25,
            ref server_versions,
        } if server_versions == &["2025-06-18".to_string()]
    ));
}

#[cfg(unix)]
#[tokio::test]
async fn sibling_probe_must_not_kill_real_child() {
    let marker = std::env::temp_dir() // nosemgrep: rust.lang.security.temp-dir.temp-dir
        .join(format!(
            "mcp_writ_preinit_marker_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
    let _ = std::fs::remove_file(&marker);

    let script = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/mcp_servers/mcp_2025_11_25_preinit_exit.py");
    let command = vec![
        "env".to_string(),
        format!("MCP_WRIT_TEST_MARKER={}", marker.display()),
        "python3".to_string(),
        script.to_string_lossy().into_owned(),
    ];

    // The marker lives in the shared temp dir — outside the child's
    // writable surface under discovery sandboxing (its own tree plus
    // the private TMPDIR), so a sandboxed fixture could never append
    // to it. This lifecycle check therefore runs the documented
    // `MCP_WRIT_SKIP_SANDBOX` downgrade rather than widening the
    // discovery policy. The env toggle is process-global, so it is
    // held across the fetch inside the same lock sibling fetches
    // take: no concurrent fetch in this binary can observe it.
    let fetched = {
        let _g = common::sandbox_spawn_lock().lock().await;
        let prior = std::env::var_os("MCP_WRIT_SKIP_SANDBOX");
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe { std::env::set_var("MCP_WRIT_SKIP_SANDBOX", "1") };
        let result =
            mcp_writ::legislator::tools_list::fetch_tools_list_detailed(&command, fetch_timeout())
                .await;
        // Restore the exact prior value — set back when it was
        // present, removed only when it was originally absent.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe {
            match prior {
                Some(v) => std::env::set_var("MCP_WRIT_SKIP_SANDBOX", v),
                None => std::env::remove_var("MCP_WRIT_SKIP_SANDBOX"),
            }
        };
        result.expect("real child must survive after sibling probe dies")
    };

    assert_eq!(
        fetched.protocol_version,
        SupportedProtocolVersion::Mcp2025November25
    );
    assert_eq!(fetched.tools.len(), 1);
    assert_eq!(fetched.tools[0].name, "echo");

    let log = std::fs::read_to_string(&marker).expect("marker written");
    let events: Vec<&str> = log.lines().collect();
    assert!(
        events.contains(&"die_preinit"),
        "sibling probe must hit the pre-initialize death path: {log}"
    );
    assert!(
        events.contains(&"init_ok"),
        "fresh real child must accept initialize: {log}"
    );

    let starts = events.iter().filter(|e| **e == "start").count();
    assert!(
        starts >= 2,
        "expected disposable sibling + real child (starts={starts}): {log}"
    );

    let _ = std::fs::remove_file(&marker);
}

#[tokio::test]
async fn fetch_empty_command_is_spawn_error() {
    let err = fetch_tools_list_detailed(&[], fetch_timeout())
        .await
        .expect_err("empty command");
    assert!(matches!(err, ToolsListError::ProcessSpawn(_)));
}
