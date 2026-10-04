//! Windows Sandbox guest relay. Install alongside the matching runner and CLI.
fn main() {
    std::hint::black_box(concat!(
        "MCP_WRIT_WSB_RELAY:",
        env!("CARGO_PKG_VERSION"),
        ":1\0"
    ));
    if std::env::args().nth(1).as_deref() == Some("--version") {
        println!(
            "mcp-writ-wsb-relay {} protocol=1",
            env!("CARGO_PKG_VERSION")
        );
        return;
    }
    mcp_writ::container::backends::windows_sandbox::agent::main();
}
