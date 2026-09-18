# Module guide

This guide describes the Rust source layout and key implementation invariants.
See the [user guide](guide.md) for configuration and behavior.

| Module | Responsibility | Main boundaries |
|---|---|---|
| `policy` | Policy types, KDL loading, composition, validation and output | `loader`/`kdl_loader` are entry points; parsing, inheritance and emission are internal |
| `verifier` | Workload hashes, tools/list differences and manifest checks | `manifest`, `tools_diff`, `hash`, `fail_on` and `ris` expose entry points; canonicalization and detector helpers are internal |
| `auditor` | Request checks, session tracking, audit logging and JSON-RPC relay | `proxy` coordinates C2S/S2C; tools/list handling owns pagination and revalidation |
| `legislator` | Discovery, source capabilities and draft policy generation | Language-specific hints, tools/list parsing/storage and self-test probes are separated |
| `cli` / `commands` | Argument parsing and command presentation | CLI types are converted to execution options at the application boundary |
| `runtime` | Shared verified launch and process shutdown | Host and container-runner shutdown policies remain distinct |
| `container` | Image wrapping, containerization and execution | Execution options belong to this module; presenters format outcomes |
| `inspector` | Native ELF analysis and capability profiles | Analysis, scoring and output formatting are separated; section bounds checks are shared |
| `warden` | OS sandbox setup and child-process ownership | OS implementations and environment handling are private behind `Warden` and child wrappers |
| `tool_def` | Shared MCP tool representation | Shared by discovery, verification and auditing |

`main.rs` and `bin/mcp-secure-runner.rs` are executable entry points.
`commands` and `runtime` are public so these binaries can call into the same
library crate; they are hidden from generated API documentation and are
application wiring rather than a stable embedding API.

## Invariants to preserve

- Policy inheritance keeps deny precedence and server binding. Serialization
  preserves the policy contract when loaded again.
- Manifest checks run before a tools/list result is released. Hash matches do
  not override blocking manifest findings.
- A tools/list response is assembled across pages before verification.
  Internally generated request IDs are never exposed as client request IDs.
- `notifications/tools/list_changed` is held during revalidation; calls remain
  denied until verification succeeds. Revalidation errors abort the session.
- Audit failures remain fail-closed when configured. Request state does not
  replace process-local trajectory or confused-deputy tracking.
- Workload verification precedes spawn. Linux restrictions run in the child,
  and Windows handles, Job objects and ACL restoration retain clear ownership.

See [Development](development.md) for checks and workflow responsibilities.
