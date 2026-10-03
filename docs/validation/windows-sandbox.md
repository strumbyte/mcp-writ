# Windows Sandbox stdio relay validation (PR-23)

Feasibility prototype for running the MCP stdio contract inside
**Windows Sandbox** — the disposable-VM feature
(`Containers-DisposableClientVM`), not a container engine. Scope:
whether a **bidirectional stdio relay** carrying the existing Windows
Warden + runner contract is viable in a Sandbox guest, and what its
security properties are. This is **not** a product backend: wiring a
`run-image --isolation windows-sandbox` path is PR-24 and must not
read this result as covering it.

Recorded: 2026-10-03 · branch `improvement-PR-23` + fixture/test
additions under `tests/fixtures/windows_sandbox/`,
`tests/windows_sandbox_vm_e2e.rs`, and `tests/common/mod.rs`.

## Environment (pinned)

| Item | Value |
|---|---|
| Host | Windows 11 Business (build **26200**), x86_64 |
| Virtualization | `hns` + `vmcompute` services running; VBS/hypervisor infrastructure present |
| Sandbox feature | **`Containers-DisposableClientVM` staged but DISABLED** — CBS packages `CurrentState=64`; `WindowsSandbox.exe`, `WindowsSandboxClient.exe`, `WindowsSandboxServer.exe`, `wsbexec.exe` all absent from `%SystemRoot%\System32`; enabling requires administrator + reboot, unavailable in this session |
| Runner | `mcp-secure-runner` 0.1.0, `x86_64-pc-windows-msvc` debug build, carries `MCP_WRIT_RUNNER_CAPS` marker |
| Agent | `tests/fixtures/windows_sandbox/wsb_relay_agent.rs` — std-only, plain `rustc` (~640 lines), no crates |
| Probe | `tests/fixtures/windows_sandbox/wsb_probe_server.rs` — fork of the Hyper-V probe, same tool/leg surface |
| Policy | `tests/fixtures/windows_sandbox/policy.kdl` — no `sandbox allow_degraded`; same control surface as the Hyper-V fixture |
| Test | `tests/windows_sandbox_vm_e2e.rs` — gated by `MCP_WRIT_REQUIRE_WSB_TESTS=1` |

## The problem this PR answers

Windows Sandbox gives the host exactly two channels:

- **Mapped folders** (`<MappedFolder>` in the `.wsb`) — live host-dir
  projections into the guest (vSMB), declared ReadOnly or writable.
- **NAT networking** (`<Networking>`) — the guest sits on the Hyper-V
  Default Switch subnet; the host reaches the guest directly at its
  vSwitch address, and vice versa.

There is **no guest process channel**: `WindowsSandbox.exe` launches a
VM and nothing else — no exec, no stdio pipes, no signal channel
(`wsbexec` does not ship in this build). A stock `.wsb` can run one
`LogonCommand` at user logon. So bidirectional MCP stdio requires a
purpose-built relay pair: a guest-side agent (launched as the
`LogonCommand`) plus a host-side peer. That pair is what PR-23
prototypes and this document measures.

## Architecture

```
host ─────────────────────────────────────────────────────────
  test harness (.wsb writer + relay client + assertions)
   │
   │  <MappedFolder> RO  →  C:\relay-ro    config, runner, probe,
   │                                      policy, agent binary
   │  <MappedFolder> RW  →  C:\relay-rw    hello, status, logs/,
   │                                      report/, stderr.log
   │  TCP (Default Switch) ── framed ──→   wsb-relay-agent
   │                                       (LogonCommand, admin
   │                                        inside disposable VM)
   │                                         │ pipes
   │                                         ▼
   │                                    mcp-secure-runner
   │                                    (unchanged product binary)
   │                                         │ stdio
   │                                         ▼
   │                                    warden → wsb-probe
   │                                    (AppContainer + Job + DACL
   │                                     + capability SIDs)
   └─────────────────────────────────────────────────────────
guest: disposable VM, WDAGUtilityAccount, host-shared kernel
```

Channel discipline, matching the runner's existing contract:

- Child **stdout** (the MCP stream) → `stdout` frames → host. Nothing
  else is ever written there.
- Child **stderr** (runner tracing, launch failures) → `stderr` frames
  (first 64 KiB) + bounded `stderr.log` on the RW share (first
  256 KiB), and the pipe is always drained so a chatty child cannot
  wedge.
- **Diagnostics/lifecycle** → `relay-status.txt` + `agent.log` on the
  RW share, never on the socket's stdout frame kind.
- **Guest report + audit** → `report/report.json`, `logs/audit.jsonl`
  on the RW share via the runner's own `MCP_WRIT_REPORT_OUT` /
  `MCP_WRIT_AUDIT_DIR` channel variables — the same variables the
  Hyper-V validation uses.

## Wire protocol (v1)

All relay traffic is length-prefixed frames on one TCP connection:

```
u8 kind | u32 BE len | payload[len]          len ≤ 1 MiB
```

| kind | dir | name | payload |
|---|---|---|---|
| `0x01` | H→G | hello | `{v, launch_id, token}` JSON |
| `0x02` | G→H | hello-ack | `{v, launch_id, agent}` JSON |
| `0x03` | H→G | stdin-data | raw child-stdin bytes |
| `0x04` | H→G | stdin-eof | empty |
| `0x05` | G→H | stdout-data | raw child-stdout bytes |
| `0x06` | G→H | stderr-data | raw child-stderr bytes |
| `0x07` | G→H | exit | `{code}` |
| `0x08` | G→H | agent-error | `{error}` |

Handshake rules the agent enforces, in order: peer IP must be in the
config's `allowed_peers` (when set — it is set to the host's Default
Switch address); the first frame must be `hello` within 15 s; its
`launch_id` + `token` must equal this launch's values. Any violation
closes the connection and appends the reason to `relay-status.txt`.
The listener keeps accepting until a correct handshake or a 180 s
deadline — a probe cannot pin the listener by connecting and stalling.

**No command channel exists toward the host.** The workload argv comes
from `relay-config.txt` on the read-only share the host itself wrote
before launch; nothing received on the socket can change what runs.
A guest-side caller that somehow acquired the port cannot attach to a
session without the per-launch token, and cannot redirect the argv at
all.

### Bounds recorded per the PR task list

| Bound | Value | Where |
|---|---|---|
| Frame payload cap | 1 MiB (matches the auditor's `DEFAULT_MAX_FRAME_BYTES`) | both endpoints reject larger |
| In-flight buffering | **none** — every pump blocks on write and only reads the next chunk (64 KiB) after the previous write returned; backpressure is structural | agent `pump_*` |
| stderr forwarded | first 64 KiB on-wire; first 256 KiB to `stderr.log`; pipe always drained | agent `pump_stderr` |
| hello read timeout | 15 s per connection | `HELLO_TIMEOUT` |
| wait-for-host deadline | 180 s after `relay-hello.txt` | `ACCEPT_DEADLINE` |
| child kill grace | 20 s poll after socket loss before declaring the kill wedged | `POST_KILL_WAIT` |
| session | one connection per agent; agent exits when the child does | `run()` |

## Lifecycle contract

| Event | Agent behavior | Verified |
|---|---|---|
| host stdin EOF | `stdin-eof` frame → child stdin closed → child exits → `exit {code}` → socket closed | yes (loopback tier) |
| guest child abnormal exit | `wait_child` sees exit → `exit {code}` → close | yes — `exit_child` tool, code 3 propagated |
| relay socket death mid-session | `socket_dead` → `child.kill()` → 20 s grace → `exit`/fatal status | yes — the Windows `accept()` nonblocking-inheritance bug found during bring-up is exactly this path firing (fixed: `set_nonblocking(false)` after accept) |
| host kill of the VM | socket fails; VM teardown reaps the guest processes | implemented, **unexecuted** — feature disabled |
| sandbox stopped | only the pids this launch added are killed (pid-set diff); pre-existing user sandboxes are never targeted | implemented, **unexecuted** — feature disabled |

## Verification results on this host

`cargo test --test windows_sandbox_vm_e2e` (2026-10-03):

| Test | Result | Evidence |
|---|---|---|
| `wsb_relay_loopback_protocol` | **PASS** (2.4 s) | full session on host loopback with the real runner + probe |
| `wsb_relay_loopback_child_exit` | **PASS** | guest abnormal exit → `exit {code:3}` frame → relay closed |
| `wsb_relay_stdio_session` | **SKIP** — `WindowsSandbox.exe` absent | feature disabled; unexecuted, not passed |
| `wsb_relay_sandbox_kill_cleans_up` | **SKIP** — same | unexecuted, not passed |

The loopback tier is a real protocol + warden verification — the only
difference from the sandbox tier is the transport substrate (loopback
vs the Default Switch NAT) and the isolation claim (none vs VM). What
it proved on this host:

- **Handshake rejection evidence**: bad token, bad launch_id, and a
  non-hello first frame are each closed without an ack and logged in
  `relay-status.txt` (`rejected` lines asserted).
- **Bidirectional MCP session through the relay**: `initialize`
  (pinned `2025-11-25`), `tools/list` (probe inventory), 10 tool legs,
  unknown-method rejection — all through `stdin`/`stdout` frames.
- **stdout purity**: every response line is a JSON-RPC frame; runner
  tracing (`Policy loaded`, warden spawn logs) appears **only** on the
  stderr frame channel + `stderr.log`.
- **Windows Warden inside the relayed child**: `vm_identity` reports
  `appcontainer=true` + `in_job=true`; `C:\Windows` write → `os error 5`;
  ungranted deny dir → `os error 5`; `net_probe` → `os error 10013`
  (WSAEACCES capability deny); `env_probe` → `mcp_vars_present=[]`;
  `exec_shell` denied by the auditor; `.ssh` path denied at the
  secret-overlay RPC layer.
- **Session correlation**: `report.json` validated by
  `validate_guest_report_text` — same launch_id, runner identity and
  `appcontainer + job` / `appcontainer + dacl` /
  `appcontainer capabilities` mechanisms as the Hyper-V tier asserts.
- **Audit**: `logs/audit.jsonl` contains `tool_call.denied` +
  `mcp_message.allowed`.
- **Abnormal exit**: `exit_child` tool (exit 3) → `exit {"code":3}`
  frame, then the relay closes — the child code propagates through
  runner → agent → frame.

A substrate finding already logged: a descendant spawned under the
warden **runs** (`spawn ok: CHILD_OK`) — matching the native Windows
warden (descendants stay inside the same AppContainer/Job), unlike the
Hyper-V container where its process-limit Job denies the inner spawn.
Inside Windows Sandbox the same warden binary runs, so the expected
in-guest result is `spawn ok`; a denial there would be a recorded
substrate difference, not a relay defect.

## Not verified yet (feature-gated)

Because `Containers-DisposableClientVM` is disabled on this host, the
following remain **unexecuted** — they must not be reported as passed:

- `.wsb` launch → `LogonCommand` → agent boot inside a real disposable
  VM.
- Mapped-folder fidelity: whether the RO mapping truly denies writes
  (leg 12), whether the AppContainer DACL grant applies inside a vSMB
  projection (`C:\relay-rw\workspace` write), guest report/audit
  landing through the share.
- `vm_identity` inside the sandbox: `WDAGUtilityAccount`, generated
  hostname, host-equal build number (Sandbox shares the host kernel —
  the build number cannot discriminate the substrate; identity is the
  evidence).
- Engine evidence: `vmwp.exe` present while the sandbox runs, gone
  after teardown; only-our-pids kill scoping.
- Host→guest connect-back over the Default Switch with the peer-IP
  gate.
- Boot latency / memory footprint numbers for the adoption judgment.

## How to complete the run on an enabled host

1. Enable the feature (admin): Settings → optional features, or
   `Enable-WindowsOptionalFeature -Online -FeatureName
   Containers-DisposableClientVM -All`, then reboot.
2. Verify `C:\Windows\System32\WindowsSandbox.exe` exists and the
   `vEthernet (Default Switch)` interface has an IPv4 address
   (`Get-NetIPAddress`).
3. `cargo test --test windows_sandbox_vm_e2e` — or with
   `MCP_WRIT_REQUIRE_WSB_TESTS=1` to fail rather than skip.
4. Interactive logon session required: `WindowsSandbox.exe` is the GUI
   client; there is no headless launch API.

## Findings that shape PR-24

- **Session requirement is the adoption question.** The launch path is
  an interactive GUI app running a `LogonCommand` — viable for a
  per-invocation sandbox CLI on a workstation, but not headless/CI
  service usage. This matches the PR's "interactive UI/session
  requirements" acceptance question; the answer on this design is:
  acceptable for an opt-in backend, unusable for service deployment.
- **The relay is transport-pluggable.** TCP was chosen because it is
  the only channel WSB offers for bidirectional streaming; the frame
  protocol does not care — a named-pipe or vsock transport (if a future
  WSB build exposes one) drops into the same codec.
- **RO-share config = launch authority.** Keeping argv on the
  read-only share means the sandbox cannot be talked into running
  anything else; the token binds the TCP session to the launch. For a
  product backend, the same shape maps to: write launch manifest →
  launch → authenticated connect-back.
- **Mapped-folder ACL fidelity is the remaining unknown** that gates
  PR-24: whether policy fs grants inside a vSMB projection enforce at
  the kernel layer. The legs are built to measure it; the answer needs
  the feature enabled.
- **One-sandbox-at-a-time in the test** via `VM_LOCK`; the test's kill
  only targets pids added by its own launch. A product backend must
  likewise scope teardown to owned instances.

## Teardown (戻し方)

All artifacts are test-owned: the `%TEMP%\mcp_writ_wsb_*` session dirs
(tempfile guard), the `.wsb` file inside them, fixture binaries under
`mcp_writ_wsb_build_*`, and the sandbox VM (killed via the guard's
pid-diff teardown). Nothing installs on the host; nothing touches a
user-owned sandbox. Remove the fixture/test/doc files to revert the
change set itself.
