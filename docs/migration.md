# Moving to mcp-writ

The project is published at [strumbyte/mcp-writ](https://github.com/strumbyte/mcp-writ).
It starts with a new Git history; the previous repository remains separate.

1. Install the new CLI from a source checkout with
   `cargo install --locked --path . --bin mcp-writ`.
2. Update MCP client configuration and scripts to launch `mcp-writ` instead of
   `mcp-guard`. Rust consumers use the crate name `mcp_writ`.
3. Rename the environment variables below. The old names are not aliases and
   are no longer read by mcp-writ.
4. Rebuild wrapped/containerized images with the new CLI and the
   `mcp-secure-runner` from the same version. The runner filename and the
   `/etc/mcp-secure/` and `/var/log/mcp-secure/` container paths are unchanged.
5. Verify the selected policy environment, server selection, audit output,
   and allowed/denied operations before switching the MCP client configuration.

| Previous variable | New variable |
|---|---|
| `MCP_GUARD_ENV` | `MCP_WRIT_ENV` |
| `MCP_GUARD_SERVER` | `MCP_WRIT_SERVER` |
| `MCP_GUARD_FAIL_ON` | `MCP_WRIT_FAIL_ON` |
| `MCP_GUARD_SKIP_SANDBOX` | `MCP_WRIT_SKIP_SANDBOX` |
| `MCP_GUARD_REQUIRE_CONTAINER_TESTS` | `MCP_WRIT_REQUIRE_CONTAINER_TESTS` |

KDL syntax and the tools-list hash v4 algorithm are unchanged. The internal
`mcp-guard-tools-list-v4:` hash prefix remains part of that format, so renaming
the project alone does not require re-pinning tool hashes. Changes to the
server or its tool definitions still require the normal verification process.

The original MIT license and copyright notice are retained.
