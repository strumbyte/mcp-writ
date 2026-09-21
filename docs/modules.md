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
| `inspector` | Native ELF/Mach-O analysis and capability profiles | Analysis, scoring and output formatting are separated; section bounds checks are shared; ELF, Mach-O and Darwin syscall-table handling stay in separate modules |
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
- The manifest scan, `tools-list-hash` verification, and the recorded digest
  all cover the full advertised tool set; the policy allowlist filter applies
  only to the verified output sent to the client. `--dry-run` does not filter
  — it forwards the full list and records a `tools_list.filtered` `observed`
  audit event for the tools a normal run would hide.
- `notifications/tools/list_changed` is held during revalidation; calls remain
  denied until verification succeeds. Revalidation errors abort the session.
- Audit failures remain fail-closed when configured. Request state does not
  replace process-local trajectory or confused-deputy tracking.
- Workload verification precedes spawn. Linux restrictions run in the child,
  and Windows handles, Job objects and ACL restoration retain clear ownership.
- `defaults.environment` restriction is part of the launch contract, not the
  OS sandbox: `runtime/launch.rs` builds `SpawnOptions.allowed_names` from the
  policy and passes it through every spawn variant, so the allowlist applies
  identically under `--dry-run` and `MCP_WRIT_SKIP_SANDBOX`. When the policy
  has no `environment` node the child inherits the full parent environment —
  `apply_spawn_env` must keep returning `None` in that case so `Command`
  keeps its default inheritance.
- Diagnostics name only established facts. `WardenError::SandboxSetup`
  carries the provably failing `SandboxStage`; undetermined spawn failures
  stay `ProcessSpawn` and are never rendered as sandbox-apply failures. A
  child-side `EPERM`/`EACCES` or stderr text is not re-classified as a Warden
  denial. Denied requests keep the client's raw request id in the audit
  event, and tools/list verification aborts are `VerificationFailed`, not
  per-request policy violations. stdout carries JSON-RPC frames only.
- Inspector findings are only meaningful under an `Analyzed` state. An empty
  `syscalls` list with a `Partial`/`Unsupported`/`NotApplicable`/`Failed`
  state means "not analyzed" and must never be rendered as a clean zero or
  used to lower risk or broaden a policy. Backend-specific decoder types
  (iced-x86, yaxpeax-arm) stay inside `inspector::decoder`.
- Mach-O containers are analyzed per slice: only the selected `arm64` slice
  is decoded and every other slice keeps its own `Unsupported` state, so a
  fat binary never looks fully validated from one slice. Darwin syscall
  numbers (`x16`, `svc #0x80`) resolve against XNU BSD/Mach-trap tables in
  separate namespaces and must never reach a Linux seccomp allowlist.

See [Development](development.md) for checks and workflow responsibilities.
