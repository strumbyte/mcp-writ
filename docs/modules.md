# Module guide

This guide describes the Rust source layout and key implementation invariants.
See the [user guide](guide.md) for configuration and behavior.

| Module | Responsibility | Main boundaries |
|---|---|---|
| `policy` | Policy types, KDL loading, composition, validation and output | `loader`/`kdl_loader` are entry points; parsing, inheritance and emission are internal |
| `verifier` | Workload hashes, tools/list baselines and differences, and manifest checks | `manifest`, `tools_diff`, `tools_baseline`, `hash`, `fail_on` and `ris` expose entry points; canonicalization and detector helpers are internal |
| `auditor` | Request checks, session tracking and the JSON-RPC relay | `proxy` coordinates C2S/S2C; tools/list handling owns pagination and revalidation; events go through `audit_log` |
| `legislator` | Discovery, source capabilities and draft policy generation | Language-specific hints, the tools/list client and self-test probes are separated |
| `cli` / `commands` | Argument parsing and command presentation | CLI types are converted to execution options at the application boundary; `inspect` output members that reference Legislator types are appended in `commands::inspect_format` |
| `runtime` | Shared verified launch and process shutdown | Host and container-runner shutdown policies remain distinct |
| `container` | Image wrapping, containerization and execution | Execution options belong to this module; presenters format outcomes |
| `inspector` | Native ELF/Mach-O analysis and capability profiles | Analysis, scoring and output formatting are separated; section bounds checks are shared; ELF, Mach-O and Darwin syscall-table handling stay in separate modules |
| `warden` | OS sandbox setup and child-process ownership | OS implementations and environment handling are private behind `Warden` and child wrappers |
| `tool_def` | Shared MCP tool representation | Shared by discovery, verification and auditing |
| `protocol` | MCP protocol-version helpers and `tools/list` wire parsing | Request builders and response decoding shared by the Auditor proxy, the Legislator client and the Verifier baseline loader |
| `audit_log` | Audit event types and the audit logger | Single-writer JSONL/tracing sink shared by the Auditor, Verifier, runtime and the binaries |
| `execution` | Execution-target context (host/substrate/workload OS and arch, substrate, engine identity) | Leaf value types only; `EngineKind` conversion lives in `container`; policy validation decides against `workload_os`, never the build host |
| `enforcement` | Enforcement plan / observation / launch-report shared model | Leaf value types and `nojson` serialization only; `Policy` → plan conversion lives in `warden`, report assembly in `runtime` |
| `secret_paths` | Secret-overlay path classification | Deny decisions shared by the Auditor and the Verifier |
| `workload` | Executable/path resolution and interpreter classification | `argv[0]` resolution, PATH search, file identity, payload-argument scanning and interpreter families shared by Warden, Legislator, runtime and Verifier |

`main.rs` and `bin/mcp-secure-runner.rs` are executable entry points.
`commands` and `runtime` are public so these binaries can call into the same
library crate; they are hidden from generated API documentation and are
application wiring rather than a stable embedding API. The same applies to
the rest of the public module surface — the crate ships binaries, and module
paths may move between releases.

## Dependency direction

Modules are arranged in layers; a module may only reference modules at a
strictly lower layer, and modules on the same layer must not reference one
another. Layer 0 holds the shared leaves: they carry no dependencies on any
other crate module, every module may reference them, and one leaf may
reference another.

| Layer | Modules |
|---|---|
| 8 | `lib.rs`, `main.rs`, `bin/mcp-secure-runner.rs` |
| 7 | `commands` |
| 6 | `cli` |
| 5 | `runtime`, `container` |
| 4 | `legislator` |
| 3 | `auditor`, `warden` |
| 2 | `verifier`, `inspector` |
| 1 | `policy` |
| 0 | `error`, `termutil`, `pathutil`, `fspriv`, `tool_def`, `framing`, `protocol`, `audit_log`, `secret_paths`, `workload`, `execution`, `enforcement` |

`tests/module_layering.rs` enforces the rule: it scans `src/` for
`crate::<module>` and `mcp_writ::<module>` references (including grouped and
nested `use` trees and `pub use` re-exports) and fails when a module names a
module at its own or a higher layer, except for layer-0 targets. `#[path]`
attributes, `include!`, and `extern crate` are rejected outright — they would
hide a dependency from the scan. Its owning workflows are listed in the
[test matrix](test-matrix.md).

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
  `spawn_env_pairs` must keep returning `None` in that case so `Command`
  keeps its default inheritance.
- The enforcement report keeps intent and observation separate. An
  `EnforcementPlan` entry states what a launch intends to enforce (and
  why anything was skipped or cannot be expressed); an
  `EnforcementObservation` states what applying it observably did. A
  control with no observation channel reports `Unknown` — never a guessed
  success. `plan.grants` entries are process-wide permissions; `origin`
  records which policy element contributed them, which is provenance, not
  per-tool kernel isolation.
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
