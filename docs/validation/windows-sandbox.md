# Windows Sandbox stdio relay validation (PR-23 / PR-24)

The PR-23 feasibility record below is retained. The shipped command backend
and its separate acceptance record are described in
[Windows Sandbox command backend](windows-sandbox-product.md) (PR-24).

Feasibility prototype for running the MCP stdio contract inside
**Windows Sandbox** — the disposable-VM feature
(`Containers-DisposableClientVM`), not a container engine. Scope:
whether a **bidirectional stdio relay** carrying the existing Windows
Warden + runner contract is viable in a Sandbox guest, and what its
security properties are. The original record covers the prototype. PR-24
uses `run --isolation windows-sandbox` with a command/payload contract and
has separate product-command tests.

Status (2026-10-03): **PR-23 acceptance completed on the real VM**. All 16
tests passed, followed by two additional measured VM sessions. PR-24 may
proceed for an explicitly selected, interactive, single-instance workflow
under the trust assumptions below. This does not establish a headless or
concurrent backend. Earlier disabled-feature results are retained as history.

Recorded: 2026-10-03 · base `ed8b3c6`, branch `improvement-PR-23` + fixture/test
additions under `tests/fixtures/windows_sandbox/`,
`tests/windows_sandbox_vm_e2e.rs`, and `tests/common/mod.rs`.

## Environment (pinned)

| Item | Value |
|---|---|
| Host | Windows 11 Business / Professional, 25H2, build **26200.9457**, x86_64 |
| Virtualization | `hns` + `vmcompute` services running; VBS/hypervisor infrastructure present |
| Sandbox feature | **Enabled and rebooted**; `WindowsSandbox.exe` present. First launch installed Store package `MicrosoftWindows.WindowsSandbox` **0.8.107.0** and the `wsb.exe` alias; tests run as the ordinary logged-on user in session 1 |
| Runner | `mcp-secure-runner` 0.1.0, `x86_64-pc-windows-msvc` debug build, carries `MCP_WRIT_RUNNER_CAPS` marker |
| Agent | `tests/fixtures/windows_sandbox/wsb_relay_agent.rs` — std-only, plain `rustc` (shared codec + owned Job module), no crates |
| Probe | `tests/fixtures/windows_sandbox/wsb_probe_server.rs` — fork of the Hyper-V probe, same tool/leg surface |
| Policy | `tests/fixtures/windows_sandbox/policy.kdl` — no `sandbox allow_degraded`; same control surface as the Hyper-V fixture |
| Test | `tests/windows_sandbox_vm_e2e.rs` — gated by `MCP_WRIT_REQUIRE_WSB_TESTS=1` |

## The problem this PR answers

This prototype uses two Windows Sandbox channels:

- **Mapped folders** (`<MappedFolder>` in the `.wsb`) — live host-dir
  projections into the guest (vSMB), declared ReadOnly or writable.
- **NAT networking** (`<Networking>`) — the guest sits on the Hyper-V
  Default Switch subnet; the host reaches the guest directly at its
  vSwitch address, and vice versa.

The documented [Windows Sandbox CLI](https://learn.microsoft.com/en-us/windows/security/application-security/application-isolation/windows-sandbox/windows-sandbox-cli)
has `start`, `list`, `exec`, `connect`, and `stop` commands with instance IDs.
`exec` does not expose process I/O. The prototype therefore uses a dedicated
relay, started through `LogonCommand` after guest logon. It requires the CLI's
ID-based lifecycle API; legacy GUI-only installations cannot establish safe
ownership with this harness. `wsb connect` supplies the interactive session.
The harness does not validate System-context or headless operation.

The [configuration reference](https://learn.microsoft.com/en-us/windows/security/application-security/application-isolation/windows-sandbox/windows-sandbox-configure-using-wsb-file)
defines mapped folders, LogonCommand and the Default Switch. The prototype
disables clipboard, audio, video, printers and vGPU, and requests 4096 MiB.
The [overview](https://learn.microsoft.com/en-us/windows/security/application-security/application-isolation/windows-sandbox/)
describes a **separate guest kernel** and currently documents a single-instance
restriction. Matching host/guest build numbers do not imply a shared kernel.
Consequently the harness refuses existing Sandbox clients, serializes its VM
tests across processes, and does not claim coexistence or multiple live VMs.

## Architecture

```
host ─────────────────────────────────────────────────────────
  test harness (wsb start --id + connect + relay client)
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
guest: disposable VM, WDAGUtilityAccount, separate guest kernel
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
| `0x09` | G→H | peer proof (first) | canonical `{v:1, launch_id, token:peer_token}` JSON |
| `0x01` | H→G | hello | canonical `{v:1, launch_id, token:host_token}` JSON |
| `0x02` | G→H | hello-ack | `{v, launch_id, agent}` JSON |
| `0x03` | H→G | stdin-data | raw child-stdin bytes |
| `0x04` | H→G | stdin-eof | empty |
| `0x0a` | H→G | cancel | empty |
| `0x05` | G→H | stdout-data | raw child-stdout bytes |
| `0x06` | G→H | stderr-data | raw child-stderr bytes |
| `0x07` | G→H | exit | `{code}` |
| `0x08` | G→H | agent-error | `{error}` |

Handshake order: the agent checks the required `allowed_peers` IP list,
sends the launch ID and its independent peer credential, and only then accepts
the host credential. The host validates the peer proof before sending its own
credential. Each credential contains two fresh UUIDv7 values. Entire canonical
messages are compared, including version; malformed JSON, duplicates, trailing
input, wrong IDs and wrong credentials are rejected. One 15 s deadline covers
the entire handshake, within the 180 s accept window. Rejections contain no
credential values in the logs. No timeout counts as a successful rejection.

These are per-launch bearer credentials over plain TCP, **not encrypted or
replay-resistant authentication against a network observer**. The prototype
trusts the host, Sandbox management stack, RO launch material and virtual-switch
transport. The confined workload has no network capability or grant to the
config files. A hostile virtual-switch administrator or compromised guest
agent/kernel remains outside this experiment's trust boundary. PR-24 must
review whether this transport assumption is acceptable before adoption.

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
| In-flight buffering | stdin: two queued frames plus one pending frame and one pipe write (at most 4 MiB); stdout/stderr: one 64 KiB chunk per pump; host pending stdout: 4 MiB / 64 lines | shared codec and agent/host pumps |
| stderr forwarded | first 64 KiB on-wire; first 256 KiB to `stderr.log`; pipe always drained | agent `pump_stderr` |
| Complete handshake / partial-frame / write deadline | 15 s each; fragment offsets survive 100 ms polls; trickle traffic does not reset deadlines | `relay_protocol.rs` |
| Full stdin queue / output drain deadline | 15 s each | agent pumps |
| Agent/status logs combined | at most 1 MiB | shared logging budget |
| stdin EOF grace | 20 s; cancel/disconnect still monitored after EOF | `wait_child` |
| wait-for-host deadline | 180 s after `relay-hello.txt` | `ACCEPT_DEADLINE` |
| child kill grace | 20 s poll after socket loss before declaring the kill wedged | `POST_KILL_WAIT` |
| session | one connection per agent; agent exits when the child does | `run()` |

## Lifecycle contract

| Event | Agent behavior | Verified |
|---|---|---|
| host stdin EOF | `stdin-eof` frame → child stdin closed → child exits → `exit {code}` → socket closed | passed on loopback and VM |
| guest child abnormal exit | `wait_child` sees exit → `exit {code}` → close | loopback real runner code 3 propagated; VM transport-child crash returned nonzero |
| relay socket death mid-session | `socket_dead` → `child.kill()` → 20 s grace → `exit`/fatal status | yes — explicit disconnect/cancel-after-EOF and stalled-input/output tests; agent process termination and descendant cleanup asserted |
| host kill of the VM | socket fails; VM teardown reaps the guest processes | passed: live MCP round trip, owned-ID stop, then socket failure |
| sandbox stopped | `wsb stop --id <owned ID>` only; guard armed before start, including partial-start failure | management stub and VM passed; ID removal and interactive-client shutdown checked before reuse |
| agent crash / cancel / socket loss after EOF | private non-inheritable Job with `KILL_ON_JOB_CLOSE` reaps runner and descendants | agent crash/tree cleanup passed on loopback; VM cancel, disconnect and ignored EOF reached terminal status and owned-ID cleanup |

## Original verification at `ed8b3c6`

`cargo test --test windows_sandbox_vm_e2e` (2026-10-03):

| Test | Result | Evidence |
|---|---|---|
| `wsb_relay_loopback_protocol` | **PASS** (2.4 s) | full session on host loopback with the real runner + probe |
| `wsb_relay_loopback_child_exit` | **PASS** | guest abnormal exit → `exit {code:3}` frame → relay closed |
| `wsb_relay_stdio_session` | **SKIP** — `WindowsSandbox.exe` absent | feature disabled; unexecuted, not passed |
| `wsb_relay_sandbox_kill_cleans_up` | **SKIP** — same | unexecuted, not passed |

The loopback tier exercised the real runner and host Windows Warden. Guest
accounts, vSMB mapping behavior, firewall setup, management APIs and the VM
resource lifecycle still need independent real-VM verification. The original
run proved the following on the host:

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

## Real-VM acceptance evidence

The enabled-host run verified `.wsb` configuration through `wsb start --id`,
guest logon, the agent, and bidirectional MCP over the Default Switch. The
real runner's report verified `os.process`, `os.fs` and `os.net.outbound`;
the probe confirmed AppContainer/Job membership, write denials and the
network capability denial. Allowed workspace writes reached the host RW
mapping, and report/audit files survived teardown. Both the AppContainer
probe and the unconfined agent were denied writes to the RO mapping.

`guest-identity.json` records WDAGUtilityAccount, the generated hostname,
guest build and memory snapshot. `lifecycle.json` records the owned Sandbox
ID, its absence from the management list after stop, client shutdown and
stop time. Global process counts remain supplemental evidence. The nine
adverse VM cases passed: large echo, stalled output/input, cancel, disconnect,
ignored EOF, child crash, invalid runner policy and failed audit creation.

## How to complete the run on an enabled host

1. Enable the feature (admin): Settings → optional features, or
   `Enable-WindowsOptionalFeature -Online -FeatureName
   Containers-DisposableClientVM -All`, then reboot.
2. Launch Windows Sandbox once, allow its Store update to finish, then close
   the desktop. The [Microsoft FAQ](https://learn.microsoft.com/en-us/windows/security/application-security/application-isolation/windows-sandbox/windows-sandbox-faq)
   explains the first-launch update and how to distinguish the older client.
3. Verify `C:\Windows\System32\WindowsSandbox.exe` exists, the
   `vEthernet (Default Switch)` interface has an IPv4 address
   (`Get-NetIPAddress`), and `Get-Command wsb` / `wsb list --raw` work.
   This harness needs
   `start --id`, `connect --id`, and `stop --id`. A GUI-only installation
   is insufficient. Run from an interactive host logon session.
4. Run the evidence-collecting commands below. The required-test flag makes
   missing prerequisites fail instead of silently skipping.

## Current acceptance coverage and restart procedure

Run from the repository root in normal PowerShell:

```powershell
# Local protocol/Windows Warden tests, without a VM (13 tests).
.\scripts\validate-windows-sandbox.ps1 -Repetitions 3

# After enabling the feature, rebooting, and verifying the wsb CLI:
.\scripts\validate-windows-sandbox.ps1 -Vm -Repetitions 3
```

The script always sets `MCP_WRIT_REQUIRE_WSB_TESTS=1`. The local mode explicitly
excludes the three VM tests; VM mode requires all 16 tests. Subsequent repetitions
rerun only the measured real-runner session. `MCP_WRIT_WSB_EXE` can identify an
installed `wsb.exe` if it is not on PATH. No command enables features, installs
software, changes the host firewall or restarts the host. Only `guest=true`
under `WDAGUtilityAccount` permits the guest firewall rule.

The script records commit, source/script/fixture SHA-256 hashes, OS/build,
Sandbox version, architecture, Rust version, command output, reports, audit,
bounded diagnostics, guest identity, memory snapshots and RPC/stop timing
in `.local/wsb-validation/<run>/`. It keeps build/session/temp data on the repo
drive, checks the 40 GiB disk floor and removes only its own work directory.
Launch credentials and staged binaries are excluded from retained evidence.

Local cases added after the original record:

- 16 MiB transfer using maximum-size 1 MiB frames with a slow receiver; exact
  payload equality, EOF and trailing-output-before-exit checked.
- Stalled receiver and stalled child stdin, partial-frame deadline, malformed
  session/control frames and oversized length rejected within bounded time.
- 8 MiB stderr drained, with 64 KiB forwarded and 256 KiB logged.
- Cancel, disconnect after EOF, ignored EOF and agent crash; runner and lingering
  descendant PIDs disappear. The private Job is established before child spawn.
- Bad handshake version, duplicate fields, trailing input, credentials and ID;
  forged agent rejected before the host sends its credential; fragmented frames
  retain their offsets across read timeouts.
- Real runner policy and audit-open failures return nonzero and serve no MCP.
- Management stub exercises success, partial-start failure, timeout and ID
  collision. Only the generated owned ID is stopped; a collision never starts
  or stops anything.
- Real runner accepts an intact 900 KiB JSON-RPC echo and 30 small echo requests
  per measured session. `metrics.json` reports contact time, median and p95.

The real-VM suite includes the Warden/RO/RW/audit/report session, mid-session
owned-ID stop, and nine adverse transport/startup cases (large echo, stalled
output/input, cancel, disconnect, ignored EOF, child abort, policy failure and
audit failure). The RO mapping is also probed by the unconfined guest agent;
a Warden denial alone would not establish mapping enforcement. These tests
all passed after feature enablement and reboot.

## Follow-up execution record (2026-10-03)

Host: Windows 11 Business `10.0.26200`, AMD64, interactive session 1,
Rust `1.99.0 (b940084d7 2026-09-28)`. Base commit:
`ed8b3c631b83e6efbfe8bf3cefa944448db0b514` plus this PR's working-tree changes.
Each saved `result.json` pins the tested source files by SHA-256.

| Check | Result |
|---|---|
| `validate-windows-sandbox.ps1 -Repetitions 3` | 13/13 local cases passed, then two additional measured-session passes; three VM tests explicitly excluded |
| Final `validate-windows-sandbox.ps1` | 13/13 passed, evidence present and work cleanup passed |
| Required VM gate: `MCP_WRIT_REQUIRE_WSB_TESTS=1 cargo test --locked --test windows_sandbox_vm_e2e wsb_relay_stdio_session -- --exact --nocapture` | Expected prerequisite failure, exit 101: WindowsSandbox.exe absent. VM unexecuted |
| T-BASE | fmt and clippy passed; 1,734 library tests passed; binaries and doctests contain 0 tests; cargo doc succeeded with two pre-existing warnings in hyperv.rs and guest_layout.rs |
| T-DOC / T-LAYER | 11 / 16 passed |
| Cleanup / storage | Script work directories removed; no Sandbox launched and no host firewall changes; final C: and D: free space recorded in `.local/pr23-final-checks.json` |

Initial T-BASE used a TEMP under the checkout, violating an existing unit
test's explicit outside-cwd premise. Moving TEMP to a dedicated directory
outside the checkout on D: yielded 1,734/1,734 passing tests without changing
product code.

The three-session measurement record is
`.local/wsb-validation/20261003-084104-e9fe1d46397f4201a0780ffded1ca2c3/`.
The final strengthened report/JSON assertions and evidence checks passed in
`.local/wsb-validation/20261003-084642-0c2fdf2b28094811b09da5d4a25e163e/`.
These are local evidence locations, not published CI results.

| Host loopback sample | First contact (s) | RPC median (ms) | RPC p95 (ms) | RPC count |
|---|---:|---:|---:|---:|
| First of three | 0.895 | 1.824 | 2.578 | 30 |
| Repeat 1 | 0.956 | 1.454 | 2.168 | 30 |
| Repeat 2 | 0.958 | 1.408 | 1.793 | 30 |
| Final verification | 0.896 | 2.019 | 2.809 | 30 |

These debug-build measurements include runner/Auditor work on host loopback.
They are not VM cold/warm boot times, isolated relay overhead or performance
guarantees. The enabled-host VM measurements follow.

## Enabled-host execution record (2026-10-03)

Command: `scripts/validate-windows-sandbox.ps1 -Vm -Repetitions 3`.
Evidence: `.local/wsb-validation/20261003-135440-90c8e5fe1a7243cfa2f4d46b38a8d4ec/`
(directory timestamps are UTC). All **16/16** cases passed, followed by two
additional measured VM sessions. Source hashes and `wsb` version are pinned in
`result.json`; evidence checks and work-directory cleanup passed. No test VM
remained in `wsb list --raw`.

Three issues were fixed during bring-up:

- The Store management server can remain alive without a VM. Only interactive
  clients block launch; the parsed management list also rejects existing IDs.
  The parser reads `WindowsSandboxEnvironments[].Id`, not UUID-looking text
  elsewhere in the JSON. The stub covers unrelated IDs and invalid list data.
- Stop can return before the remote-session window exits. Teardown now waits
  for ID removal and client shutdown before allowing the next test to launch.
- `resolve_policy_pattern` dropped the root separator before a wildcard, so
  `C:/**` resolved against the guest's current directory. Preserving `C:/`
  fixed the actual RPC denials; a Windows regression test covers both separator
  spellings. The fix applies to policy allow and deny matching.

The validation script distinguishes loopback and VM metrics: the full VM suite
also runs one loopback measurement, which must not count toward the requested
number of VM samples.

| Fresh VM on an already initialized host | First authenticated contact (s) | RPC median (ms) | RPC p95 (ms) | Owned stop + client close (s) |
|---|---:|---:|---:|---:|
| Full-suite session | 7.602 | 2.901 | 3.180 | 0.954 |
| Repeat 1 | 7.122 | 3.728 | 8.869 | 1.007 |
| Repeat 2 | 7.058 | 2.834 | 4.000 | 0.997 |

Each sample verified a 900 KiB JSON-RPC echo and 30 small RPCs. These are
debug-runner session measurements with warm host caches. They do not measure
first-install or first-boot-after-restart latency, isolated relay overhead,
peak memory, or production service-level guarantees.

Memory request: **4096 MiB**. The guest's
[GlobalMemoryStatusEx](https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-globalmemorystatusex)
snapshot reported 4,293,857,280 physical bytes (about 4095 MiB), with
**1.57–1.65 GiB** unavailable at the measurement point. Host available memory
dropped **2.60–2.89 GiB** during these sessions. The host-wide Hyper-V memory
counter values changed from `[1024]` to `[4096, 1024]` and returned to `[1024]`
after stop in every sample. Counter instance names were empty / `#1`, so this
is a host-wide observation, not exact per-ID charged or peak memory. The three
raw snapshots per session retain that limitation rather than presenting an
unattributed process working set as the VM's footprint.

Post-fix checks: fmt and clippy passed; **1,735** library tests and **18** KDL
integration tests passed. Binaries and doctests contain zero tests; cargo doc
succeeded with the same two existing warnings. Additional path-resolution
coverage initially passed **5/6** cases; the symlink case failed its required
prerequisite because this ordinary host account lacked symlink privilege/Developer
Mode. After the user enabled Developer Mode, the exact symlink test was rerun
with `MCP_WRIT_REQUIRE_E2E_TESTS=1` and passed. Together, the two runs cover
**6/6** cases. The records are `.local/pr23-reboot-base-tests.txt` and
`.local/pr23-symlink-test.txt`; follow-up metadata and source hashes are in
`.local/pr23-symlink-test.json`.
After updating the acceptance documents, all 11 documentation checks and 16
module-layering checks passed. The 16 changed/new text files were verified as
UTF-8 without BOM, with LF endings and no replacement characters.

The validation script removed its work directory. A later cleanup attempt for
the separate bring-up cache `.local/wsb-bringup/work` and unit-test TEMP
`D:\Temp\mcp-writ-pr23-reboot-20261003` was rejected by automatic approval review
with `blocked by policy`; those two directories remain on D:. No workaround
deletion was attempted, and neither directory contains a running test VM.

## PR-24 decision

**Conditionally adopt for PR-24.** The tested workflow is viable for an explicit
desktop-session option with one VM per MCP stdio session. The startup cost is
paid once for the session, while subsequent RPCs take milliseconds. Keep the
native default and reject an already running Sandbox before starting work.

PR-24 must preserve these boundaries:

1. Require the tested ID-based CLI, an interactive host logon, guest logon,
   dedicated RO/RW launch directories, and the authenticated bounded relay.
   Headless services, concurrent VMs and sharing an existing user Sandbox are
   outside the accepted scope.
2. State the trusted-host/virtual-switch and plaintext bearer-credential
   assumptions. Do not claim protection against a network observer or a
   compromised guest agent. A broader threat model requires a different
   transport decision before release.
3. Start regression budgets on this host at 30 s to first contact, 20 ms small
   RPC p95 and 10 s normal owned stop, with the 4096 MiB configuration. These
   are proposed product acceptance budgets with headroom over this baseline,
   not cross-machine guarantees. Measure restart-cold startup, workload peaks
   and host memory accounting during product validation.
4. Revalidate PR-10/11 framing, PR-08/21 reports and PR-15 lifecycle behavior
   through the actual product command. This prototype does not implement that
   command or establish its release readiness.

The Hyper-V and native product paths remain available. The prototype has no
connection to the default CLI or `run-image` backend selection.

## Manual CI job (PR-25)

`scripts/validate-windows-sandbox.ps1 -Vm` is the owned, repeatable
validation job — also the `windows-sandbox` leg of the dispatch-only
[VM tests workflow](../../.github/workflows/vm-tests.yml) on a
`[self-hosted, windows, windows-sandbox]` runner. Shared conventions,
result states, and the evidence layout live in
[manual-ci.md](manual-ci.md). The method-specific environment contract
(feature enabled, `wsb` CLI with instance IDs, interactive session,
Default Switch IPv4) and the `-Vm` / loopback distinction are the ones
described throughout this document — the script's `-Vm` path is the
VM-tier gate; the workflow always runs `-Vm`.

## Teardown (戻し方)

All artifacts are test-owned. The validation script cleans its isolated work
directory and retains evidence. Direct cargo invocations use `target/wsb-tests`
(including cached fixture builds), removable through `cargo clean`. Every
Sandbox guard stops only its preallocated ID, including failed launches. Failed
cleanup prints that ID and a recovery command. It never kills a global process
name, PID-set difference, or unrelated `vmwp.exe`. Enabling the optional Windows
feature is an explicit host setup action, not part of these tests.
