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

## Planned KDL schema v2 migration

MCP passage rules (the `mcp` block inside `server`) are only accepted under
`policy version=2`. A v1 policy keeps working with no extra rules — its
default profile stays closed through the tool allowlist and the existing
checks alone. v2 is not yet enabled for generation or enforcement: current
binaries reject any `version` other than 1 during validation (older binaries
reject it the same way, as `unsupported policy version`). v2 is planned to go
live together with MRTR additional-request control.

When migrating a v1 policy to v2, traffic that previously passed without a
rule needs an explicit `allow`. Example:

```kdl
policy version=2
server "docs" {
    tool "search"
    mcp {
        // Read-side methods that passed implicitly in 2025
        allow "resources/list"
        allow "resources/templates/list"
        allow "resources/read" {
            uri "file:///srv/docs/**"
        }
        allow "resources/subscribe" {
            uri "file:///srv/docs/**"
        }
        allow "resources/unsubscribe" {
            uri "file:///srv/docs/**"
        }
        allow "prompts/list"
        allow "prompts/get"
        allow "completion/complete"
        allow "logging/setLevel"
        // Server-originated features need explicit rules too
        allow "elicitation/create"
    }
}
```

Under `2026-07-28`, URI subscriptions and `logging/setLevel` are removed;
subscriptions move to `subscriptions/listen` filters. The per-request
`logLevel` replaces only the removed `logging/setLevel` RPC — it is not
the recommended migration target for the Logging feature itself. The
Logging feature as a whole is deprecated but remains in the
specification for at least 12 months; the recommended migration is
stderr for stdio transports and OpenTelemetry for structured logs.

```kdl
server "docs" {
    mcp {
        // toolsListChanged alone is allowed by default; other
        // notification kinds and URI ranges need explicit rules.
        allow "subscriptions/listen" {
            filter "toolsListChanged"
            filter "resourceSubscriptions"
            uri "file:///srv/docs/**"
        }
    }
}
```

Requests or extensions not registered in the method ledger — experimental
`tasks`, extension `resultType` values, and the like — are denied until the
ledger grows an entry for them; there is no rule that silently lets them
through. Also note that `2026-07-28` log notifications are correlated
against the originating request's `progressToken`/`logLevel` — on stdio the
HTTP response stream is not a correlation source, and a notification whose
origin request cannot be identified is dropped and audited on its own. No
custom required fields are added on top of the official spec's requirements.

The original MIT license and copyright notice are retained.
