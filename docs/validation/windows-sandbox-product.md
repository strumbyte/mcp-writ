# Windows Sandbox command backend (PR-24)

This opt-in backend runs one Windows x86-64 MCP server per disposable VM.
The default `run` path remains native. It uses the authenticated stdio relay
validated in [PR-23](windows-sandbox.md), plus the existing Windows guest
runner, Warden, Auditor, hash checks and tool-definition checks.

## Setup and supported scope

- Tested host: Windows 11 Business 25H2, build 26200.9457, x86-64, interactive
  session 1; Store Windows Sandbox / `wsb` 0.8.107.0. The CLI accepts the
  0.8 family from build 107 and verifies ID-based management responses.
- Enable `Containers-DisposableClientVM`, reboot and finish the Sandbox Store
  update before use. `wsb list --raw` and the Default Switch IPv4 must work.
  `MCP_WRIT_WSB_EXE` may name an installed `wsb.exe` outside PATH.
- An interactive host desktop and guest logon are required. `wsb connect`
  opens the Sandbox session. Services in session 0, headless operation,
  concurrent sessions and reuse of a user's existing Sandbox are unsupported.
- Install matching `mcp-writ.exe`, `mcp-secure-runner.exe` and
  `mcp-writ-wsb-relay.exe` together. Source builds use `cargo build --locked
  --bins`. `--sandbox-runtime` selects their directory when they are separate
  from the CLI. Update all three together. Windows amd64 release packaging
  includes both helpers; publication of the changed package is a release step.
- Bundle the workload, interpreter if needed, and dependencies in one payload
  directory. The command must be a relative Windows x86-64 PE executable in
  that directory. Links/junctions, more than 10,000 entries, more than 1 GiB,
  or nesting deeper than 32 levels are refused. The command JSON is capped
  at 64 KiB. Required MSVC runtime DLLs for the helpers and entry executable
  are staged app-local; other workload dependencies belong in the payload.

## Run and diagnose

Create a dedicated state directory on a drive with space for payload copies,
audit logs and output. Policy paths and trailing arguments refer to the guest;
the host does not translate arbitrary paths in arguments or policies.

```powershell
New-Item -ItemType Directory -Force D:\mcp-sandbox-state

.\mcp-writ.exe plan --isolation windows-sandbox `
  --sandbox-payload D:\my-server --sandbox-state D:\mcp-sandbox-state `
  --policy .\sandbox.kdl -- server.exe

.\mcp-writ.exe run --isolation windows-sandbox `
  --sandbox-payload D:\my-server --sandbox-state D:\mcp-sandbox-state `
  --policy .\sandbox.kdl --report .\launch.json -- server.exe
```

The payload is copied into `C:/mcp-secure/workload`; that is also the working
directory. An interpreter example is `-- python.exe C:/mcp-secure/workload/server.py`.
The policy is exported with includes/inheritance/schema references resolved,
then revalidated by the guest runner against Windows. Use `--server` for a
multi-server policy. Explicit policy and fail-closed logging are required.
`--dry-run`, `--audit-log`, a non-stdio transport, an image or container engine
are not accepted for this path. `MCP_WRIT_SKIP_SANDBOX` cannot disable the guest
Warden. Guest network policies retain the existing Windows limitations.

Fixed guest locations:

| Location | Purpose |
|---|---|
| `C:/relay-ro` | Read-only staged helpers, policy, command and launch credentials |
| `C:/mcp-secure/workload` | Copied payload on guest NTFS |
| `C:/relay-rw/workspace` | Explicit host-visible workload output, when granted by policy |
| `C:/relay-rw/logs` | Guest audit log; excluded from workload grants by default |
| `C:/relay-rw/report` | Guest report channel; distinct from MCP stdout |
| `C:/Windows/Temp` | Guest workload temporary directory |

The policy must grant the workload the guest files it needs. The validation
[policy](../../tests/fixtures/windows_sandbox/policy.kdl) demonstrates explicit
workspace grants, network denial and tool rules; it is a test policy, not a
general-purpose server policy.

## Bounds, ownership and evidence

The host and guest prove distinct per-launch credentials before stdin is
accepted. Framing is `kind + u32 length + payload`, with a 1 MiB frame cap,
15-second complete-frame/handshake/write deadlines and bounded queues. The
guest stdin queue holds two frames; host bridges hold 64 KiB each. Guest
stderr sends at most 64 KiB over the relay, retains at most 256 KiB in
`stderr.log` and continues draining. The host consumes diagnostic frames;
it prints the record path instead of blocking MCP on a host stderr pipe.
The agent's status and diagnostic logs share a 1 MiB budget.
The guest agent owns a kill-on-close Job before spawning the runner. EOF,
disconnect, a stalled peer and ignored EOF all have bounded shutdown paths.

The relay uses plaintext TCP. The host OS, management stack, guest relay and
Default Switch path are trusted. Bearer credentials provide launch/peer
binding, not protection from a network observer or a compromised guest agent.
The VM is configured for 4096 MiB with clipboard, GPU, audio/video input and
printer redirection disabled. Networking is enabled for the relay; Warden
applies the workload's separate AppContainer network capabilities.

A per-user process lock serializes product launches. Existing IDs or interactive
Sandbox clients cause refusal. Start reserves a fresh UUID and verifies that
exact ID in `wsb list`. Stop targets only that ID and waits for its disappearance
and the connection UI to close. A failed cleanup returns failure with recovery
information; it never kills processes by a global name or PID difference.
During a session the host also checks that its ID still exists, so external
VM stop terminates an idle host even when client stdin remains open.
The backend uses the shared PR-15 session driver and never falls back to native
or Hyper-V execution.

`--sandbox-state/<launch-id>/launch-report.json` is always retained, together
with the RW audit/report/workspace and `unit-id`. `--report` writes an additional
host report. Staged executables and credentials in `ro` are removed once stop
is confirmed. Retained output/logs consume disk; remove a completed session
directory when it is no longer needed. If cleanup is unconfirmed, use
`wsb stop --id <unit-id>` before removing its files.

The host validates guest report size, schema, launch ID, runner version and
required Windows control observations before forwarding MCP. Final reports
are collected on normal and abnormal exits; missing report/audit prevents a
successful result. Guest observations remain self-reported under `guest`.
They are not remote attestation or independent host proof of guest enforcement.

## Acceptance commands

```powershell
# All local relay tests plus real VM prototype and product tests (21 tests).
.\scripts\validate-windows-sandbox.ps1 -Vm

# Product subset: normal sessions/restarts, child exit, external stop,
# missing audit/report, v2 wire rules and MRTR.
$env:MCP_WRIT_REQUIRE_WSB_TESTS = '1'
cargo test --locked --test windows_sandbox_vm_e2e wsb_product_ -- --nocapture
```

The script keeps staging on the repository drive, checks the 40 GiB floor,
records source hashes and environment, and retains bounded evidence without
launch credentials. Hosted Windows CI runs the 14 local relay/probe tests; the VM
tier stays manual. See the [test matrix](../test-matrix.md).

### Execution record (2026-10-04 JST, UTC+09:00)

Base: `aecb48c` plus the PR-24 working tree (`codex/pr24-windows-sandbox`).
Host: Windows 11 Business 25H2 26200.9457 AMD64, interactive session 1,
Store Sandbox 0.8.107.0, Rust 1.99.0. Guest: Windows 10.0.26100,
WDAGUtilityAccount. These are local runs; release publication and remote CI
were not performed.

- Complete relay/VM suite: **20/20 passed**, comprising 13 local tests,
  three prototype VM tests and four product VM tests. Includes authentication
  failures, wrong/colliding IDs, partial starts, fragmented/oversized frames,
  slow or stalled peers, EOF, cancellation, crashes, audit/report failures,
  existing-VM refusal, large MCP messages and repeated fresh sessions.
- Final product rerun: **4/4 passed** after adding the independent owned-ID
  monitor. External VM stop terminates the host with stdin still open.
  Both MCP revisions, v2 MRTR permission/capability checks and suppression
  of unsolicited server requests passed through the real product CLI.
- T-BASE: fmt and clippy passed; **1,742 library tests** passed, with zero
  bin/doctest cases. `cargo doc` succeeded with the two existing warnings in
  `hyperv.rs` and `guest_layout.rs`.
- T-PROTOCOL: **54/54 passed**. Windows T-NATIVE: **18/18 passed** across the
  recorded runs, with `MCP_WRIT_REQUIRE_E2E_TESTS=1`. The environment test
  initially exceeded its 15-second startup deadline while the shared helper
  also granted the installed real-server package trees. Setting
  `MCP_WRIT_REAL_SERVERS_DIR` to an empty dedicated fixture directory removed
  those unrelated grants; all five environment tests passed with real OS
  confinement, without changing or skipping assertions.
- Additional wire tests: **39/39 passed**; plan/report tests: **13/13 passed**.
  A real `plan` returned `ready`, created no state entries and left the VM list
  empty.
- Documentation checks: **11/11 passed**; module layering: **16/16 passed**.

Final product measurements (three fresh sessions, 30 small RPCs per session
and a 900 KiB echo):

| Session | First response (s) | RPC p95 (ms) | EOF to stopped (s) |
|---|---:|---:|---:|
| 1 | 14.580 | 4.392 | 1.752 |
| 2 | 13.844 | 4.363 | 1.752 |
| 3 | 13.959 | 4.644 | 1.752 |
| PR-23 budget | <30 | <20 | <10 |

Each VM used the 4096 MiB configuration and reported 4,293,857,280 bytes of
physical memory. Host available-memory snapshots were retained before,
during and after each session. These are snapshots rather than peaks;
background host/WSL use affects the totals. A host reboot and cold-start
memory peak were not measured. Every measured session removed its owned ID
and RO credentials; the next fresh session succeeded.

Evidence (local, excluded from Git):

- `.local/wsb-validation/20261003-171838-7645ced0d96941749a6a13164d580e3b/`:
  full 20-test log, environment/source hashes, guest reports, audit records,
  performance, host/guest memory and successful staging cleanup.
- `.local/pr24-product-final/`: final product source/binary hashes and the
  three measured sessions; `.local/pr24-product-final.txt` records 4/4.
- `.local/pr24-base-final.txt`, `.local/pr24-protocol-native-rest.txt`,
  `.local/pr24-environment-isolated.txt`, `.local/pr24-plan-ready.json`,
  `.local/pr24-cargo-doc.txt`, `.local/pr24-doctest.txt` and
  `.local/pr24-doc-layer.txt`: regression results.
