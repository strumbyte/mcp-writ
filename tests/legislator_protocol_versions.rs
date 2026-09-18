//! Legislator client coverage for MCP `2026-07-28` and `2025-11-25`.
//!
//! Fixtures live in `tests/fixtures/mcp_servers/`. No network, no rmcp.

use std::path::PathBuf;
use std::time::Duration;

use mcp_writ::legislator::protocol::SupportedProtocolVersion;
use mcp_writ::legislator::tools_list::{ToolsListError, fetch_tools_list_detailed};

fn fixture_server(name: &str) -> Vec<String> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/mcp_servers")
        .join(name);
    if cfg!(windows) {
        vec![
            "py".to_string(),
            "-3".to_string(),
            path.to_string_lossy().into_owned(),
        ]
    } else {
        vec!["python3".to_string(), path.to_string_lossy().into_owned()]
    }
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
    let marker = std::env::temp_dir().join(format!(
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

    let fetched = fetch_tools_list_detailed(&command, fetch_timeout())
        .await
        .expect("real child must survive after sibling probe dies");

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
