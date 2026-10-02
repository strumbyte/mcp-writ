# Windows Hyper-V isolated container validation (PR-20)

Real-machine verification that the existing **Windows Warden**
(AppContainer + DACL + capability SIDs + Job object) and the MCP stdio
execution contract hold inside a **Hyper-V isolated Windows container**.
Scope: **Docker Engine on Windows, `docker run --isolation=hyperv`
equivalent stdio session only** — a validation prototype driven by a
dedicated test, **not a product backend**. Wiring an `IsolationBackend`
for this substrate (`run-image --isolation hyperv`) is PR-22 and must
not read this result as covering the product path.

Recorded: 2026-10-02 · repo HEAD `3a5efe1` + fixture/test changes under
`tests/fixtures/hyperv/`, `tests/hyperv_vm_e2e.rs`, and
`tests/common/mod.rs`.

## Environment (pinned)

| Item | Value |
|---|---|
| Host | Windows Pro 25H2 (build **26200.9457**), x86_64 |
| Virtualization | Hyper-V available; `vmcompute` + `hns` services running; user in `docker-users` + `Administrators` |
| Engine | Docker Desktop 4.90.0, engine **29.7.2**, `OSType=windows`, `DefaultIsolation=hyperv`, storage `windowsfilter`, root `C:\ProgramData\Docker` |
| Guest image | `mcr.microsoft.com/windows/servercore@sha256:e18a49cbc074dfaa8e106296d51cebd62bbf6effb999f134a5c48eed1c2334e1` (`ltsc2025`, `OsVersion` **10.0.26100.33438**, amd64, 5.62 GB) — Server Core chosen deliberately; Nano Server's reduced API surface was not required to be proven |
| Probe image | `mcp-writ-hyperv-probe:test` built from `tests/fixtures/hyperv/Dockerfile` (COPY-only, no build-time `RUN`), 5.63 GB |
| Runner | `mcp-secure-runner` 0.1.0, `x86_64-pc-windows-msvc` debug build (~7.8 MB), baked into the image as `ENTRYPOINT` |
| Probe | `tests/fixtures/hyperv/hyperv_probe_server.rs` — std-only + inline Win32 FFI, compiled by the test via plain `rustc` |
| Policy | `tests/fixtures/hyperv/policy.kdl` — no `sandbox allow_degraded`; mounted into the guest at `C:\etc\mcp-secure` at launch and baked into the image |

Host setup used: Docker Desktop → "Switch to Windows containers"
(`DockerCli.exe -SwitchWindowsEngine`) → pull the pinned Server Core.

## Where the controls live (host vs guest)

```
Windows 26200 host ─────────────────────────────────────────────
  mcp-writ run            → Windows native path: AppContainer +
                            Job on the host kernel     ← Win T-NATIVE
  docker run --isolation hyperv <img>
      └─ utility VM running the image kernel 10.0.26100 (vmcompute)
           └─ mcp-secure-runner → warden: AppContainer profile +
              capability SIDs + per-object DACL + Job object
                                                   ← this doc (T-VM)
```

This validation exercises the **guest** column only. `IsolationKind::
HyperV` exists in `src/execution.rs` as a reserved kind (PR-22+); the
prototype never connects it to `run-image`. No fallback exists: a launch
whose recorded isolation is not `hyperv` is a failure, and the e2e adds
a leg proving `--isolation=process` is **refused** for this image on
this host (mismatched kernel builds), so process isolation could not
have silently stood in.

## Host requirements / platform refusals

- Windows host (the fixture compiles a windows/amd64 PE and bind-mounts
  host directories), a running Docker engine reporting
  `OSType=windows`, `rustc` for the probe, a Windows PE
  `mcp-secure-runner`, and the pinned base image. Missing prerequisites
  skip the test; `MCP_WRIT_REQUIRE_HYPERV_TESTS=1` fails instead.
- `docker run --isolation=process` on `servercore@…e18a49cb…`
  (kernel 26100) against host build 26200 is refused by the engine
  (`exit≠0`, message names the OS-version mismatch) — durable evidence
  that `hyperv` and `process` are not interchangeable on this rig.
- Linux/WSL2 or a Linux-mode engine does not satisfy the contract; the
  prerequisite probe checks `docker info`'s daemon-side `OSType`, not
  the CLI's host.

## Runtime entity evidence (engine layer)

While the unit runs (`docker run --isolation hyperv …`):

- `docker inspect <name>` → `HostConfig.Isolation = "hyperv"` —
  recorded on the live container, polled until present by the test.
- `tasklist /FI "IMAGENAME eq vmwp.exe"` shows a Hyper-V worker process
  per running unit (the utility-VM analogue of the Kata test's QEMU
  check); count includes Docker Desktop's own utility VMs if any, so the
  test asserts presence-while-running rather than an exact count.
- `docker stats <name> --no-stream` reports real per-unit accounting:
  **MEM ≈ 494 MiB** for the idle probe unit (`cmd /c ping -t` variant).
- Guest-side identity (`vm_identity` leg): `os.version=10.0.26100`
  (the *image's* kernel — the host runs 26200, so the guest kernel is a
  distinct boundary), `computer=<random unit hostname>`,
  `user=ContainerAdministrator`. None of these alone prove the VM; they
  corroborate the engine-side record.

## MCP session evidence (stdio JSON-RPC)

Driven by `tests/hyperv_vm_e2e.rs::hyperv_vm_stdio_session` — the same
real-client handshake as the Kata/Apple sessions (`initialize` → wait →
`notifications/initialized` → `tools/list` → wait → calls) over
`docker run -i --rm --isolation hyperv` with stdin held by the test.
The guest-side stack mirrors the product wrap contract: runner as
`ENTRYPOINT`, `MCP_ORIG_ENTRYPOINT`/`MCP_WRIT_*` env, policy mounted at
`C:\etc\mcp-secure`, audit at `C:\var\log\mcp-secure`, report at
`C:\run\mcp-secure\report`, workspace at `C:\workspace`, plus an
ungranted `C:\share` bind mount.

Observed per-leg results (verbatim from the run):

| leg | result | attributed to |
|---|---|---|
| `vm_identity` | `os.version=10.0.26100 … appcontainer=true groups=11 all_app_packages=false in_job=true` | guest kernel + AppContainer token + Job membership |
| `create_file C:/workspace/hyperv-ok.txt` | `created … (6 bytes)`; file visible on the host mount | literal DACL grant (workspace) |
| `read_file C:/workspace/hyperv-ok.txt` | `opened … head="hyperv"` | DACL grant |
| `read_file C:/workspace/.ssh/id_rsa` | `-32001` `secret-path overlay` | auditor RPC layer |
| `create_file C:/Windows/hyperv-evil.txt` | `Access is denied. (os error 5)` | AppContainer DACL on in-image NTFS |
| `create_file C:/writ-deny/evil.txt` | `Access is denied. (os error 5)` | AppContainer DACL on in-image NTFS |
| `net_probe 192.0.2.1:80` | `…access a socket in a way forbidden… (os error 10013)` WSAEACCES | AppContainer capability — policy grants no network SID |
| `spawn_child` (`cmd /c echo`) | `spawn failed: Access is denied. (os error 5)` | warden launch conditions — no descendant creation |
| `env_probe` | `USERNAME=<absent>` … `mcp_vars_present=[]` | restricted environment (no `MCP_*` reach the workload) |
| `exec_shell` | `-32001` `tool is not allowed` | auditor tool gate |
| `create_file C:/share/probe.txt` | **created**; visible on the host | see "bind-mount ACL finding" below |
| `evil/method` | `-32001` `unknown-method` | auditor method gate |
| stdin EOF | container exits; unit destroyed | runner EOF shutdown |

Additional protocol evidence observed while debugging: requests sent
before the handshake completes are denied `init-order` (the auditor's
ordering gate) — recorded in `audit.jsonl` as `mcp_message.denied`.

## Guest launch report + audit log

- `report.json` arrives through the dedicated mount
  (`MCP_WRIT_REPORT_OUT` → `C:\run\mcp-secure\report`), carries the
  host-issued `launch_id`, `guest_runner` identity, and validates via
  `validate_guest_report_text`. `plan.controls` record the Windows
  warden layers (`"os.process","layer":"os","mechanism":"appcontainer +
  job"`, `"os.fs" → "appcontainer + dacl"`, `"os.net.outbound" →
  "appcontainer capabilities"`).
- `audit.jsonl` on the host mount carries `server.connected`
  (`details: spawned \\?\C:\mcp-secure\hyperv-probe.exe`),
  `mcp_message.allowed`/`denied`/`dropped`, `tool_call.allowed`/
  `tool_call.denied`, each correlated via `correlation_id` = launch id.
- Both channels are guest-produced files arriving over the dedicated
  mounts — never through the MCP stdout relay.

## Lifecycle

- **stdin EOF**: runner finalizes the report (`"status":"exited"`,
  `exit_code:0`), exits; `--rm` removes the unit; `docker inspect`
  becomes unresolvable. Observed end-to-end in the session test.
- **`docker kill`**: the utility VM is destroyed with the container
  (`hyperv_vm_kill_terminates_and_cleans_up` — inspect unresolvable,
  CLI exits nonzero, no report written — the expected shape for an
  abrupt kill).
- **Abnormal child termination** (`exit_child` tool, code 7): the guest
  payload dies, the session terminates, the container reaches `exited`.
  Originally recorded limitation (PR-20 run): the runner's non-Unix
  PID1 wait raced `auditor relay finished first` against `child
  exited`, so the container's recorded `State.ExitCode` (and the
  report's `exit_code`) was **0**, not the child's 7. **Fixed in
  PR-21**: `runtime/wait.rs` now gives the exiting child a bounded
  settle window when the auditor relay finishes first, so the workload's
  own code is what the report records; the e2e asserts
  `exit_code:7`. The Windows docker CLI also does **not** propagate
  the container exit code to `docker run`'s own status (observed: CLI 0
  vs `State.ExitCode` 7) — PR-22 must read `.State.ExitCode`, never the
  CLI status.
- **Windows has no SIGINT-to-PID1 equivalent** for a console-less
  container process; `docker kill` is the honest cancellation surface
  and is what the e2e exercises.

## Performance (warm image cache, this host)

| measure | observed |
|---|---|
| Base pull (cold, first time) | 5.62 GB layer set, several minutes on this connection (~8 min observed) |
| Unit boot → exit, base image (`cmd /c echo`) | **≈2.5 s** (n=2) |
| Session: first initialize response | **≈2.9 s** |
| Session: last leg response | ≈3.1 s |
| Session: exit after stdin EOF | ≈4.5–5.1 s total |
| Probe image size | 5.63 GB (base 5.62 GB + ~8 MB payload) |
| Idle unit memory | `docker stats` ≈ **494 MiB**; `vmwp.exe` worker WS ≈ 25–29 MB |

## Findings that shape PR-21/PR-22

- **Server Core does not ship `VCRUNTIME140.dll`** — an MSVC-built exe
  fails loader lock (`0xC0000135`) inside the guest. The fixture ships
  the redistributable **app-local** next to the exes (`C:\mcp-secure\`).
  PR-21 images must either bundle the CRT the same way or build the
  guest binaries with `+crt-static`. This is now part of the image
  contract, documented in `tests/fixtures/hyperv/Dockerfile`.
- **Bind-mounted directories are not covered by the AppContainer DACL
  layer**: writing `C:\share\probe.txt` (ungranted mount) succeeded and
  materialized on the host. The per-object deny demonstrably holds only
  for in-image NTFS paths (`C:\Windows`, `C:\writ-deny`). Policy mounts
  are read-only at the Docker layer already; anything sensitive should
  not be reachable through a host share — treat bind mounts as
  host-trusted, not warden-enforced, surface in PR-22's design.
- **Drive-relative runner paths work but are accidental**:
  `/etc/mcp-secure/policy.kdl`, `/var/log/mcp-secure`, and the default
  report path are POSIX-spelled constants that resolve against the
  CWD drive inside the guest. The launch pins
  `MCP_WRIT_REPORT_OUT=C:\run\mcp-secure\report` explicitly so the
  report channel does not depend on that accident; PR-21 should define
  Windows-native guest paths instead of relying on CWD.
- **WSL-interop argument mangling**: invoking `docker.exe` from a WSL
  shell with `\` inside `-e` values stripped the backslashes
  (`C:runmcp-securereport`). Not a product path — the test spawns via
  Rust `Command` — but manual reproducers should use `/` separators.
- **Network control is deny-all only on Windows** — no per-destination
  allowlist (validator rejects it for `TargetOs::Windows`); the fixture
  policy uses `network { deny host="*" }` and the capability check
  produces WSAEACCES. That is the strongest outbound control this
  substrate+warden combination offers.
- **Descendant creation is denied** under the warden's launch conditions
  (`spawn failed: Access is denied`) — matches the Windows-native
  `spawn_child` behavior recorded for the host path.
- **`tools/list-hash` absent → warn-and-allow** — the fixture policy
  carries no tools hash; the guest logs `No tools-list-hash in policy;
  allowing tools/list`. Acceptable for validation; PR-22 images that
  ship a manifest should pin the hash.

## Not verified / limits

- **SIGINT/cancel mid-request**, multi-workload units, `docker exec`
  into the unit, non-Docker Windows container runtimes (containerd /
  Podman on Windows), image **build inside** the guest, Nano Server —
  out of scope or unverified.
- **Podman on Windows**, containerd `ctr`/`hcsshim` direct use — not
  evaluated; do not infer support.
- **Cold-start pull figure** is this connection's observation only;
  registry/proxy variance not measured.
- **Interactive/`docker exec` attach** into a running unit — not
  exercised.
- The **exit-code race** noted above was fixed in PR-21 (auditor-first
  settle window in `runtime/wait.rs`); the e2e now asserts the child's
  own exit code reaches the report.

## Adoption judgment (for PR-22)

Hyper-V isolated Windows containers are **viable** as the Windows VM
isolation substrate: the engine records real `hyperv` isolation, a
utility VM boots the image kernel per launch, the Windows Warden's full
control set (AppContainer profile, capability deny, DACL on in-image
NTFS, Job membership, restricted env, no descendant creation) applies
inside the guest unchanged, and the stdio MCP contract + audit + guest
report all work end to end at ~3 s to first response. The acceptance
condition "AppContainer cannot be omitted" holds — the probe legs prove
the token, job, DACL and capability layers are all live.

Costs and constraints: ~2.5 s unit boot, ~0.5 GiB per idle unit,
5.6 GB pinned Server Core base (pull once per host), the CRT bundling
requirement, deny-all-only outbound network control, bind mounts
bypassing the DACL layer, and docker-CLI exit-code non-propagation.
None block adoption; all are documented above for PR-21/PR-22.

**Initial performance budget for the PR-22 decision** (validation-
derived proposals, not product requirements; method = this doc's
measures, regression target = `hyperv_vm_e2e.rs`):

| measure | measured | proposed budget |
|---|---|---|
| unit boot → first initialize response | ≈2.9 s | ≤10 s |
| full init→exit lifecycle | ≈4.5–5.1 s | ≤15 s |
| idle unit memory (`docker stats`) | ≈494 MiB | ≤1 GiB |
| image footprint | 5.63 GB | pin digest; ≤8 GB |

**PR-20 closes here.** The Dockerfile, fixture, and test above are
validation assets. Product-path adoption (`run-image --isolation
hyperv`, engine/mode probing, budget enforcement) is PR-22 and must
not read this result as covering it.

## PR-21 addendum: the runner/image contract is product code

PR-21 turned the fixture contract into the shipped one:

- **Guest layout** (`src/container/guest_layout.rs`): Windows guests
  get native paths — runner `C:/mcp-secure/mcp-secure-runner.exe`,
  policy `C:/etc/mcp-secure/policy.kdl` (directory bind mount, not a
  single file), logs `C:/var/log/mcp-secure`, report
  `C:/run/mcp-secure/report`, workload temp `C:/Windows/Temp`. The
  drive-relative accident noted above is gone: every channel path is an
  explicit drive-lettered contract path or a cleared/re-set channel
  env (`MCP_WRIT_POLICY_PATH`, `MCP_WRIT_AUDIT_DIR`,
  `MCP_WRIT_TEMP_DIR`, `MCP_WRIT_REPORT_OUT`).
- **`wrap-image` produces the Windows contract**: PE machine/arch
  inspection (`pe_magic.rs`), ELF↔PE cross-copy refusal, JSON-form
  `COPY`/`ENTRYPOINT` under `# escape=\`, no `RUN`/`chmod`, and
  `--crt-dll` (repeatable) or auto-staging from `runners/crt/` /
  `System32` for MSVC-redist imports.
- **Shipped runner is `crt-static`**: the release job builds
  `mcp-secure-runner` for `x86_64-pc-windows-msvc` with
  `-C target-feature=+crt-static`, so the artifact imports no
  `vcruntime140*`/`msvcp140*` and needs no app-local DLL on Server
  Core (`pe-imports --require-clean` enforces it in CI). App-local CRT
  staging remains for user-supplied `--runner-binary` PEs.
- **Distribution**: `mcp-writ-windows-amd64.zip` carries
  `runners/mcp-secure-runner-windows-amd64.exe` beside the linux-amd64
  runner; `runners-checksums-sha256.txt` pins every runner's bytes.
  Windows arm64 guests are out of contract (no artifact).
- **Product-path e2e**: `hyperv_wrap_image_product_path` in
  `tests/hyperv_vm_e2e.rs` builds a payload image, wraps it with the
  real `mcp-writ wrap-image`, boots it with `--isolation=hyperv`, and
  exercises initialize / tools/list / vm_identity / create_file /
  env_probe plus the guest report — the same launch shape PR-22's
  backend will drive.
- **Exit-code race fixed** (see Lifecycle above).

**PR-21 re-validation on the recorded host:** `MCP_WRIT_REQUIRE_HYPERV_TESTS=1
cargo test --test hyperv_vm_e2e` (Windows toolchain, engine
`OSType=windows`) — **5/5 pass**, including the product-path leg: the
real `wrap-image` built a Windows-contract image (PE arch check, CRT
staging, caps env), the unit booted under Hyper-V, answered
initialize/tools/list and tool calls, and the guest wrote its launch
report to `C:\run\mcp-secure\report`. First response ≈2.6 s, EOF exit
≈3.9 s — in line with the PR-20 measurements. Two defects found and
fixed by this run: the `MCP_WRIT_RUNNER_CAPS` marker is dead-stripped
from MSVC builds unless referenced (`black_box` now retains it), and a
wrapped workload's install dir needs an explicit policy grant (only the
exe image + ancestor traverse are auto-granted — `C:/probe` read was
added to the fixture policy).

Not in PR-21: the `hyperv` isolation backend itself (`run-image
--isolation hyperv` still refuses — PR-22), Windows Sandbox placement
(PR-23/24), windows-arm64 guests.

## PR-22 addendum: the hyperv backend is product code

PR-22 made `run-image --isolation hyperv` a product path
(`src/container/backends/hyperv.rs`), still scoped to exactly the
configuration this document pins:

- **Explicit substrate, verified after launch**: the launch passes
  `--isolation=hyperv` and then re-reads the unit's
  `HostConfig.Isolation` (`docker inspect`, 5 s bound). Only `hyperv`
  continues; `process`, any other value, an unreadable record, or a
  missing `--cidfile` unit id all refuse and tear the unit down before
  the workload is trusted. Requesting Hyper-V is never the evidence;
  the daemon's record is.
- **Fail-closed gates, no fallback**: `check` refuses anything outside
  the validated shape — non-Windows host, non-x86-64 host, non-docker
  engine, daemon in Linux-containers mode (`OSType` other than
  `windows` or unreported), unparseable host `OSVersion`, missing
  `vmcompute`/`hns` services, non-Windows or non-amd64 image guest, an
  image with no `OsVersion`, or an image build newer than the host's.
  Nothing degrades to process isolation, a plain container, native
  Windows execution, or a Linux VM.
- **PR-21 guest contract unchanged**: the unit runs the image's
  `C:/mcp-secure/mcp-secure-runner.exe` entrypoint under
  `--user ContainerAdministrator` (the in-guest PID 1 needs the
  administrator-in-VM token to install DACL grants, register the
  AppContainer profile, and build the Job object — the workload child
  still drops to the low-rights token). Policy/log/report mounts use
  the `C:`-spelled layout.
- **Two evidence channels stay separate**: the launch report records
  the engine boundary (`isolation.configured`/`verified`: `hyperv`,
  `unit: vm`, unit id) while the guest report carries the in-guest
  Warden observations (AppContainer, Job object, DACL, capabilities) —
  a backend launch alone is not guest-control evidence.
- **`plan` reports it**: `hyperv.engine` (driver version, OSType, host
  build, service states) and `hyperv.image` (guest build ≤ host build)
  checks with remediation text; a failed gate blocks the plan with a
  stable reason.

**Supported combinations** (the only ones `check` accepts): Windows
x86-64 host; docker engine in Windows-containers mode; `vmcompute` and
`hns` installed (demand-started is fine); windows/amd64 image whose
recorded `OsVersion` build ≤ the host build — e.g. the pinned Server
Core LTSC2025 (`10.0.26100.33438`) on this host (`10.0.26200`).

**PR-22 validation on the recorded host:** `MCP_WRIT_REQUIRE_HYPERV_TESTS=1
cargo test --locked --test hyperv_vm_e2e -- --nocapture` — **8/8 pass**,
~198 s total:

- `hyperv_vm_stdio_session` — harness stdio session; guest controls
  verified (AppContainer, Job, DACL/capability denials), audit log and
  guest report read back; first response ≈2.7 s, EOF exit ≈4.1 s.
- `hyperv_vm_kill_terminates_and_cleans_up` / `hyperv_vm_child_exit_terminates_session`
  — external `docker kill` and child-exit unwinds both end the session
  and remove the unit.
- `hyperv_process_isolation_refused_for_mismatched_image` — a direct
  `docker run --isolation=process` of the 26100-build image is refused
  by the engine on this 26200 host (kernel build mismatch): the refusal
  is the evidence that process isolation cannot silently stand in for
  the requested hyperv boundary. It does not drive the backend's
  `check`/`hyperv.image` gate — newer-than-host image rejection is
  covered by the `image_version_check` unit tests in
  `src/container/backends/hyperv.rs`.
- `run_image_hyperv_stdio_session` — the product `run-image
  --isolation hyperv` path: stdio exchange plus launch-report
  assertions (`isolation.configured`/`verified` = `hyperv`, `unit` =
  `vm`, unit id recorded) and the guest report.
- `run_image_hyperv_external_kill_cleans_up` — `docker kill <unit id>`
  during a product session: session ends, unit removed.
- `run_image_hyperv_refusal_leaves_nothing_running` — product-path
  refusal leaves no running unit.
- `hyperv_wrap_image_product_path` — PR-21 wrap leg, unchanged.

Two product defects found and fixed by this validation:

1. `run-image` passed `\\?\`-verbatim canonicalized host paths into
   `-v` bind mounts, which docker's Windows CLI rejects —
   `host_share_path` in `src/container/backends/oci.rs` now strips the
   verbatim prefix for engine arguments.
2. The fixture image carried no `MCP_WRIT_RUNNER_CAPS` env, so
   `--report` launches refused at image inspection — the fixture
   Dockerfile now embeds the runner's capability marker.

Not in PR-22: Windows Sandbox (PR-23/24), manual CI wiring (PR-25),
windows-arm64 guests, non-docker engines. Disabling the method is
selective: `--isolation hyperv` on an unsuitable host refuses; every
other isolation path is untouched.

## Teardown (戻し方)

`docker rm -f` any leftover `hyperv-e2e-*` container; `docker rmi
mcp-writ-hyperv-probe:test` and, if desired, the pinned servercore
image. No host virtualization settings were changed by the validation —
only Docker Desktop's engine mode switch, which the user can revert via
"Switch to Linux containers".
