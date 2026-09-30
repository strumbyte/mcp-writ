# Kata Containers validation (PR-16) + product-path record (PR-17)

Real-machine verification that the existing Linux Warden + MCP execution
contract holds inside a Kata guest VM. Scope: **Docker + Kata 4.2.0 +
QEMU, `run`-equivalent stdio session only** — a single-workload VM per
launch. PR-16 validated the stack against a `docker run --runtime kata`
harness; PR-17 wired the same backend into the product
(`run-image --isolation kata`, implemented by
`src/container/backends/kata.rs`) and the PR-17 section at the end of
this document records that path's evidence.

Recorded: 2026-09-29 · repo HEAD `f6a1508` + fixture/test changes under
`tests/fixtures/kata/` and `tests/kata_vm_e2e.rs`; the PR-17 product-path
record below was taken on the same pinned host.

## Environment (pinned)

| Item | Value |
|---|---|
| Host | Windows 10.0.26200.9457, WSL2 2.4.12.0, Ubuntu 24.04.2 LTS |
| Host kernel | `5.15.167.4-microsoft-standard-WSL2` (x86_64, 4 vCPU, 3.8 GiB) |
| Virtualization | `/dev/kvm` present (nested virt enabled) |
| `/dev/vhost-vsock` | **not shipped by the stock WSL2 kernel** — loaded via a locally built module (see below) |
| Docker Engine | 29.1.3 (server linux/amd64, overlayfs) |
| Kata Containers | 4.2.0 static amd64 tarball (`kata-static-4.2.0-amd64.tar.zst`), sha256 `b828904fa3f1e49ddd7dc799c72cb1503cd1e772d354c3987c8d4189b2a623a8`; `containerd-shim-kata-v2` (runtime-rs), commit `c7351e797efff8bfc6bd73da0eb1909be12e2cfe` |
| QEMU | 11.0.1 (kata-static) |
| Guest kernel | `vmlinux-6.18.35-202` — `CONFIG_SECURITY_LANDLOCK=y`, `CONFIG_SECCOMP=y`, `CONFIG_SECCOMP_FILTER=y`, `LSM=landlock,…` |
| Guest rootfs | `kata-ubuntu-resolute.image` (NVDIMM, read-only) |
| Workload image | base `ubuntu@sha256:008173c23f95b170204355c12626cb5a965d779a7e1283b09e9cffbb1bf33ca3` (ubuntu:24.04); secure `localhost:5000/kata-probe-secure@sha256:33b7d94429b7b73a3b26b442f39709dc6907970f848764a55b667ca4a9046bf5` |
| Runner | `mcp-secure-runner` 0.1.0, `guest-report-1` capability |
| Policy | `tests/fixtures/kata/policy.kdl` — no `sandbox allow_degraded` |

Host setup is captured in
[`tests/fixtures/kata/setup-wsl2.sh`](../../tests/fixtures/kata/setup-wsl2.sh)
(daemon config, runtime registration, and the vsock workaround). The
workaround is scoped to this WSL distro and removable; it is **not** a
portable Kata prerequisite — a distribution kernel with
`CONFIG_VHOST_VSOCK` needs nothing of it.

## Virtualization prerequisites

- `/dev/kvm`: present. Kata runs with `accel=kvm`.
- `/dev/vhost-vsock`: **absent on stock WSL2 5.15**
  (`CONFIG_VHOST_VSOCK` unset). Kata 4.x has no proxy fallback — the
  shim fails at `generate vhost vsock cid` without it. Fixed by building
  `vhost_vsock.ko` + `vmw_vsock_virtio_transport_common.ko` from the
  matching kernel source tag `linux-msft-wsl-5.15.167.4` and loading
  them via a oneshot systemd unit (`/lib/modules` is rebuilt per boot,
  so `depmod` alone does not persist). Verifies as
  `crw-rw---- … 10, 241 /dev/vhost-vsock`.
- Host kernel note: 5.15 is below Landlock ABI v4 — the **host** cannot
  fully enforce network rules; the **guest** kernel (6.18) can, which is
  what this validation exercises (see comparison below).

## Runtime entity evidence (engine layer)

While the container runs (`docker run --runtime kata …`):

- `docker inspect`: `Runtime=kata`, container id `b0fac6bc…`
- Host processes: `containerd-shim-kata-v2 -id <cid>`, two `virtiofsd`
  daemons (`kataShared`), and QEMU:

  ```
  /opt/kata/bin/qemu-system-x86_64 -name sandbox-<cid>
    -kernel /opt/kata/share/kata-containers/vmlinux-6.18.35-202
    -machine q35,accel=kvm … -m 1G,slots=10,maxmem=3920M
    -device vhost-vsock-pci … guest-cid=3218220928
    -device nvdimm … kata-ubuntu-resolute.image … -nographic -no-reboot
  ```

  A dedicated KVM VM with its own kernel — not a namespace container.
- Guest-side identity (`vm_identity` probe, in-VM):
  `uname.osrelease=6.18.35`, `NoNewPrivs=1`, `Seccomp=2`,
  `Seccomp_filters=1`, `virtiofs` in `/proc/filesystems`,
  `cmdline_has_kata=true`. Guest kernel ≠ host kernel — the workload ran
  inside the VM, not on the host kernel.

## MCP session evidence (stdio JSON-RPC)

Driven by `tests/kata_vm_e2e.rs::kata_vm_stdio_session` (a real-client
handshake: `initialize` → wait → `notifications/initialized` →
`tools/list` → wait → calls). Read-only policy mount, audit + report +
workspace mounts, launch-id env. The recorded session ran the secure
image by registry digest (`localhost:5000/…@sha256:33b7d944…`); the
durable test builds `mcp-writ-kata-probe-secure:test` locally and runs
that tag — a locally built image has no manifest digest to pin, while
its *base* stays digest-pinned via `BASE_IMAGE_PINNED`.

| leg | request | result | proves |
|---|---|---|---|
| init | `initialize` | `result` with `protocolVersion":"2025-11-25"` | handshake; the auditor rejects a negotiated version ≠ 2025-11-25 (`shape`) |
| list | `tools/list` | 5 tools | tool inventory through the VM |
| vm identity | `vm_identity /proc/self/status` | `uname.osrelease`, `NoNewPrivs=1`, `Seccomp=2`, `cmdline_has_kata`, `virtiofs` | guest kernel ≠ host kernel; controls live on the probe; kata-agent handoff marker |
| read | `read_file /workspace/kata-ok.txt` | `opened … dev=40` (virtiofs) | allowed read |
| write | `create_file /workspace/kata-ok.txt` | `created (4 bytes)` | allowed write grant |
| secret deny | `read_file /etc/shadow` | `-32001` *secret-path overlay* | RPC-layer deny, never reaches the kernel |
| syscall deny | `chmod_666 /workspace/kata-ok.txt` | `isError` `EPERM` (os error 1) | **seccomp** — `chmod*` outside the allowlist |
| net deny | `net_probe connect 192.0.2.1:80` | `isError` `EPERM` | **seccomp** — `socket` dropped under `deny host="*"` |
| fs write deny | `create_file /etc/evil.txt` | `isError` `EACCES` (os error 13) | **Landlock** — no `/etc` grant |
| fs read deny | `read_file /etc/hostname` | `isError` `EACCES` | **Landlock** — file exists and is world-readable; only the sandbox denies it |
| tool deny | `exec_shell` | `-32001` *tool is not allowed* | auditor `deny=#true` |
| method deny | `evil/method` | `-32001` *unknown-method* | auditor method gate |

Deny legs attribute cleanly: `EPERM` = seccomp, `EACCES` = Landlock,
`-32001` = the in-guest Auditor. The per-tool `/*` grants exist to
separate those layers — the Auditor resolves a root glob to the whole
tree (permits the call) while the Landlock builder strips it to an
unmappable base (skips it), so the kernel defaults decide. `/**` would
be dead at *both* layers (the Auditor normalizes it to `.` — matches
nothing — and Landlock cannot open it).

## Guest launch report + audit log

`report.json` is collected through the dedicated report mount
(`/run/mcp-secure/report`) and validated host-side (schema, launch_id,
runner identity). The session's report records:

- `result.status="exited"`, `exit_code=0`
- `guest_runner`: `{"version":"0.1.0","capabilities":["guest-report-1"]}`
- observations (mechanism results, in-guest):
  - `os.privileges` **verified** — `no_new_privs` confirmed in `pre_exec`
  - `os.fs` **verified** — `restrict_self` reported **FullyEnforced**
    (kernel Landlock ABI v7)
  - `os.net.outbound` **verified** — FullyEnforced (ABI v7)
  - `os.syscalls` **verified** — seccomp program installed
- `isolation: null` — correct by design: the guest report is the
  runner's self-report and does not claim VM identity; VM evidence lives
  on the host side (QEMU/shim/`Runtime=kata`).

`audit.jsonl` records `server.connected`, `mcp_message.allowed` for
init/list/call traffic, and `tool_call.denied` for every denied leg —
the audit channel survives the VM boundary.

## Lifecycle

| event | result |
|---|---|
| stdin EOF | guest exits 0; `"auditor relay finished"`; report written |
| `docker stop` (SIGTERM) | container `exited`, code 255; QEMU/shim/virtiofsd all gone; `/run/kata` removed |
| `docker kill -s SIGINT` | container `exited`, code 130; VM processes gone |
| `docker kill` (SIGKILL) | container `exited`, code 137 in <1 s; no leftovers |
| container ID / VM | `--rm` + shim teardown leaves no container, no QEMU, no `/run/kata/<id>` |

## Performance (warm image cache, this host)

| measure | kata | runc | note |
|---|---|---|---|
| cold run — uncached image (pull + start + `uname` + teardown) | ~3.5 s | ~0.9 s | pull from the local registry is ~0.15 s of it; VM boot dominates the delta |
| warm run — cached image (same command) | ~3.1 s | ~0.7 s | VM boot ≈ +2.4 s per launch |
| session first response | 2.26–2.71 s | n/a | VM boot + runner + policy + spawn |
| full session (init→list→10 legs→EOF exit) | 3.0–3.5 s | n/a | |
| QEMU VmRSS | ~254 MiB | — | guest mem `-m 1G`, `VmSize` ~1.6 GiB |
| `docker stats` | `0B` | works | host cgroup is blind to the VM — use QEMU RSS |

runc comparison caveat: on **this** host the same session under `runc`
fails closed — the 5.15 kernel predates Landlock ABI v4, so the ruleset
reports `PartiallyEnforced` and the spawn is refused (`EACCES`). That is
correct product behavior, not a Kata regression — and incidentally the
cleanest demonstration that the Kata guest kernel supplies controls the
host cannot. On a 6.7+ host kernel the container path would run fully
enforced; the VM still adds a second kernel boundary regardless.

## Prototype and test

- `tests/fixtures/kata/kata_probe_server.rs` — std-only MCP probe; each
  tool performs a real guest-side operation (open/create/chmod/connect +
  `/proc/self/status` identity).
- `tests/fixtures/kata/policy.kdl` — fixture policy (see its comments
  for the `/*`/`/**` layering rationale).
- `tests/fixtures/kata/setup-wsl2.sh` — host setup (Docker, Kata static,
  dockerd runtime registration, vsock workaround, optional local
  registry for real manifest digests).
- `tests/kata_vm_e2e.rs` — the durable version of the session above:
  `kata_vm_stdio_session` asserts every leg, the guest report and audit
  trail; `kata_vm_sigint_terminates_and_cleans_up` asserts signal
  handling + VM teardown. Skips without prerequisites;
  `MCP_WRIT_REQUIRE_KATA_TESTS=1` fails instead.

Re-run: `MCP_WRIT_REQUIRE_KATA_TESTS=1 cargo test --locked --test kata_vm_e2e -- --nocapture`.

## Not verified / limits

- **Cold start through a remote registry** — the cold figure above pulls
  130 MB from `localhost:5000`; a WAN pull adds the real download time.
- **In-flight request interruption** — SIGINT/SIGKILL were tested on an
  idle session; cancellation mid-tool-call not exercised.
- **Podman / containerd / other hypervisors** — not validated; do not
  infer support from this Docker+QEMU run.
- **Multi-workload VMs, exec/attach, Windows guests, image build under
  Kata** — out of scope; unimplemented.
- **`docker stats` memory accounting** — reports `0` for Kata VMs; QEMU
  RSS is the usable metric.

## Adoption judgment

Kata is **viable** for the Linux VM isolation backend: the guest kernel
fully enforces Landlock (ABI v7) + seccomp + no_new_privs, the MCP stdio
contract, audit, and guest-report channels all work end to end, and
teardown is complete. Costs and constraints found here: ~+2.4 s VM boot
per launch, ~250 MiB QEMU RSS per unit, and a `/dev/vhost-vsock`
requirement some host kernels (stock WSL2) do not meet. Hosts without
it fail closed — the product never silently falls back to `runc`.

**Initial performance budget for the PR-17 decision** (validation-
derived proposals, not product requirements; method = this doc's
measures, regression target = `kata_vm_e2e.rs`):

| measure | measured | proposed budget |
|---|---|---|
| session first response | ≤2.7 s | ≤5 s |
| full init→exit lifecycle | ≤3.5 s | ≤8 s |
| QEMU VmRSS per workload VM | ~254 MiB | ≤512 MiB |

**PR-16 closes here.** The runtime registration, image flow, and
fixtures above are validation assets. Product-path adoption (default
`IsolationKind::Kata` wiring, runtime auto-detection, budget
enforcement, multi-engine coverage) is PR-17+ and must not read this
result as covering Podman, containerd, Windows guests, or build/exec
paths.

## Product path (PR-17)

`run-image --isolation kata` is now the product entry point for this
backend — the same Kata/QEMU stack, driven through the shared
`IsolationBackend` contract (`check` → `launch` → `drive_stdio_session`)
instead of a hand-assembled `docker run`. Validation on the pinned host:

- **Backend scope**: `KataBackend` requires a Linux host, the **docker**
  engine, a registered `kata` runtime in `docker info .Runtimes`, and
  `/dev/kvm` + `/dev/vhost-vsock`. Engine `info` probes run with a 5 s
  bound; every missing piece refuses with a named prerequisite — the
  launch never degrades to `runc`, and the backend installs/registers
  nothing itself. A foreign-arch image is also refused: the guest kernel
  is pinned host-arch by the Kata installation, so exec would certainly
  fail.
- **Launch**: the backend renders `--runtime kata` plus the shared spec
  options (policy share, audit/report mounts, `--cidfile`, `-i`). The
  recorded `unit_id` is the container id the shim names its VM
  (`sandbox-<cid>`), so the engine-driven `--cidfile`/`rm -f` teardown
  covers VM cleanup unchanged.
- **Confirmed isolation**: `IsolationCheck` returns `verified=kata`,
  `unit=vm` only after the runtime registration and device nodes probe
  green; the launch report records `isolation.configured="kata"`,
  `verified="kata"`, `unit="vm"`, `unit_id=<container id>`, and
  `target.substrate="vm"` with `engine="docker"` kept (the launch is
  engine-driven). Live evidence collected during the session:
  `docker inspect` reports `HostConfig.Runtime=kata` and a
  `qemu-system-x86_64 -name sandbox-<cid>` process exists for the VM.
- **Session**: `kata_vm_e2e.rs::run_image_kata_stdio_session` drives
  `mcp-writ run-image --isolation kata` over the shared secure image —
  initialize/tools.list/tool calls through the stdio relay, in-guest
  `vm_identity` markers (`cmdline_has_kata`, `virtiofs`), auditor denies,
  EOF exit 0, guest report received and validated by launch id, audit
  log on the mounted log dir. First response ≈2.4 s — inside the ≤5 s
  budget proposed above.
- **Interrupt + cleanup**:
  `kata_vm_e2e.rs::run_image_kata_sigint_interrupts_and_cleans_up` sends
  SIGINT to the `run-image` process; the shared session driver
  terminates the unit (`docker rm -f` by the recorded id), the container
  and its QEMU/shim are gone afterwards, and the report records
  `result.status="interrupted"` with the verified kata isolation.
- **No fallback**:
  `kata_vm_e2e.rs::run_image_kata_refusal_leaves_nothing_running` drives
  `--isolation kata --engine podman`: the run refuses (engine resolution
  or the backend's docker-only gate, whichever binds first), nothing is
  launched, and the report keeps `configured="kata"` with `verified` /
  `unit` null — a silent runc fallback would have recorded
  `verified="container"`.
- **`plan`**: `plan --image <ref> --isolation kata` reports
  `isolation.backend` pass on a Linux host (fail off-Linux — the backend
  declares `host_os=[linux]`) plus a dedicated `kata.runtime` check that
  probes `docker info .Runtimes["kata"]` and both device nodes; a
  missing prerequisite blocks the plan as `isolation_unsupported` with
  per-prerequisite remediation, never planned as a normal container.
  `image_target` records `substrate="vm"` and keeps the resolved engine.

Re-run the product path:
`MCP_WRIT_REQUIRE_KATA_TESTS=1 cargo test --locked --test kata_vm_e2e run_image_kata -- --nocapture`.

Still not covered (unchanged from above): Podman/containerd kata,
non-QEMU hypervisors, Windows guests, Kata image build, exec/attach,
multi-workload VMs — these remain unimplemented and refuse.
