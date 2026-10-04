# Apple `container` validation (PR-18)

Real-machine verification that the existing Linux Warden + MCP execution
contract holds inside an Apple `container` lightweight VM on macOS
arm64. Scope: **Apple `container` 1.5.0, `container run`-equivalent
stdio session only** — a validation prototype driven by a dedicated
test, **not a product backend**. Apple's substrate boots one
`Virtualization.framework` Linux VM per container on a Kata-derived
guest kernel, so the in-guest control evidence is the same
Landlock/seccomp/no_new_privs layer as `docs/validation/kata.md`, while
the host-side VM evidence is Apple-specific. Wiring an
`IsolationBackend` for this substrate into the product
(`run-image --isolation apple`) is PR-19 and must not read this result
as covering the product path.

Recorded: 2026-09-29 · repo HEAD `f75660f` + fixture/test changes under
`tests/apple_container_vm_e2e.rs` and `tests/common/mod.rs`.

## Environment (pinned)

| Item | Value |
|---|---|
| Host | macOS 26.6.2 (Build 25G83), Apple silicon arm64, 8 CPUs |
| `container` CLI | 1.5.0 (Homebrew bottle) — client 1.5.0 / server 1.5.0 (`container-apiserver`), `container system status` = `running` |
| Install root | `/opt/homebrew/Cellar/container/1.5.0/` |
| App root | `~/Library/Application Support/com.apple.container/` (containers, snapshots, kernels, content) |
| Guest kernel | `vmlinux-6.18.35-197-debug`, installed by `container system start` as `kernels/default.kernel-arm64`; pinned in `container system property list` → `[kernel] digest sha256:8736c054d9223974735394f822000823baef509e1c33405ec798240fa9b6e4b5`, url `kata-static-3.32.0-arm64.tar.zst` |
| Workload image | `gcr.io/distroless/static-debian12@sha256:d75cdd72874d4790092fcb1b058493ecf6bb5bf2b2b897045b00ff01d91843f2` (OCI index; arm64 manifest `sha256:b6d8cd9eeccef7a63b91771ba943056f484c0dc92396ec3140a5fe2c6279d581`, ~0.7 MiB per variant). A **standard** minimal image is used deliberately — users run `run-image` against the distro image of their choice, so the validation must not depend on a bespoke image; distroless `static` is the smallest standard image matching the musl-static workload (no shell/libc; only ca-certs, passwd, zoneinfo). The ubuntu 24.04 index (`ubuntu@sha256:008173c23f95…` — same pinned digest as the Kata validation, arm64 manifest `sha256:11dc1ccb…`, 28,944,073 bytes) was additionally exercised for multi-arch pull/build evidence |
| Runner | `mcp-secure-runner` 0.1.0, `aarch64-unknown-linux-musl` release build (~3.1 MiB, stripped, `guest-report-1` capability marker retained), bind-mounted read-only into the guest |
| Probe | `tests/fixtures/kata/kata_probe_server.rs` → static musl ELF (`-C linker=rust-lld`, no external cross toolchain), aarch64 for the session + x86_64 for the emulation leg |
| Policy | `tests/fixtures/kata/policy.kdl` — no `sandbox allow_degraded`; mounted read-only from the host at launch |

Host setup: `brew install container` → `container system start`
(installs the pinned default kernel on first start) →
`container image pull --platform linux/arm64 <image@digest>`.

## Where the controls live (host vs guest)

Two unrelated enforcement layers must not be conflated in this result:

```
macOS arm64 host ─────────────────────────────────────────────
  mcp-writ run            → macOS native path: seatbelt via
                            sandbox-exec (no Landlock/seccomp —
                            not Linux)      ← macOS T-NATIVE
  container run -i <img>  → Virtualization.framework VM per unit
      └─ Linux guest 6.18.35 (Kata-derived, vminitd)
           └─ mcp-secure-runner → warden: Landlock ABI v7 +
              seccomp + no_new_privs      ← Apple T-VM (this doc)
```

This validation exercises the **guest** column only. The host native
path is exercised separately on this machine — `environment_e2e`
(`environment_applies_under_sandbox`, real sandbox-exec), the
`warden::macos_sandbox` unit tests in `--lib`, `diagnostics_e2e`, and
`self_test` (`non_linux_marks_warden_skipped`: the Linux warden controls
correctly do not claim enforcement off Linux). All green on this host —
the Linux-guest result is never a substitute for the macOS-native suite,
per the PR guide's verification clause.

## Host requirements / platform refusals

- macOS arm64 with a running `container system`. The e2e helper
  (`tests/apple_container_vm_e2e.rs::check_prereqs`) requires all of:
  host `TargetOs::MacOs` + `TargetArch::Aarch64`, `container` on PATH,
  `container system status` = `running`. Missing prerequisites skip;
  `MCP_WRIT_REQUIRE_APPLE_TESTS=1` fails instead — it never substitutes
  a weaker path (there is none on this substrate anyway).
- `--os windows` is refused at launch (`Error: platform windows/arm64`,
  exit 1): this substrate has no Windows guest.
- `--platform linux/amd64` is **not** refused — the unit runs emulated.
  `container inspect` records it honestly:
  `"platform" : {"architecture":"amd64","os":"linux"}` with
  `"rosetta" : true`. Consequence for PR-19: the backend must gate
  `guest_arch` itself — the substrate will happily run a translated
  workload where the contract expects a native one.
- Older macOS / Intel hosts: Apple `container` requires macOS 26+ on
  Apple silicon; other combinations are unsupported by the vendor, not
  validated here (this host cannot produce them).

## Runtime entity evidence (engine layer)

While a unit runs (`container run … <image@digest>`):

- `container inspect <id>` records the launch verbatim:
  `configuration.image.descriptor.digest` is the pinned index digest,
  `platform` = `linux/arm64`, `runtimeHandler` =
  `container-runtime-linux`, `resources` = `cpus: 4,
  memoryInBytes: 1073741824` (the `[container]` defaults from
  `system property list`), `status.state` = `running`, and every
  `-v`/env/entrypoint under `mounts` / `initProcess.environment`.
- Host process per unit:
  `…/container-plugins/container-runtime-linux/bin/container-runtime-linux
  start --root …/containers/<id> --uuid <id>` — the per-VM manager, the
  Apple-side analogue of the kata shim owning a sandbox.
- `container stats <id> --no-stream --format json` reports real
  per-guest accounting (unlike `docker stats` on Kata, which reported
  `0B`): `memoryUsageBytes ≈ 5.9 MiB` at the idle probe,
  `memoryLimitBytes = 1 GiB`, `numProcesses = 1`, plus block/network
  counters.
- Guest-side identity (`vm_identity` probe leg):
  `uname.osrelease=6.18.35`, `NoNewPrivs=1`, `Seccomp=2`,
  `Seccomp_filters=1`, `virtiofs_in_filesystems=true`. The guest kernel
  is the Kata-derived 6.18.35 — not the Darwin host — and each unit is
  its own VM. There is **no** `cmdline_has_kata` marker (the guest init
  is `vminitd`, not kata-agent); VM identity here rests on the host-side
  `container-runtime-linux` unit plus the guest's own mechanism state.

## MCP session evidence (stdio JSON-RPC)

Driven by `tests/apple_container_vm_e2e.rs::apple_vm_stdio_session` —
the same real-client handshake and leg set as the Kata session
(`initialize` → wait → `notifications/initialized` → `tools/list` →
wait → calls), over `container run -i --rm` with stdin held by the test.
The guest-side fixture stack mirrors — rather than byte-identically
reproduces — the product contract: the runner runs as PID 1 via the
`--entrypoint` flag (a wrapped image's baked `Entrypoint` path is not
exercised here), `MCP_ORIG_ENTRYPOINT`/
`MCP_WRIT_*` env, read-only policy share (`policy.kdl:ro` — a write to
the mount path failed earlier with `Operation not permitted`),
`/workspace` + `/var/log/mcp-secure` audit dir + `/run/mcp-secure/report`
writable mounts, `MCP_WRIT_LAUNCH_ID` env.

The base image is the standard `distroless/static-debian12` (pinned by
index digest) with the runner and probe injected as read-only bind
mounts — the same injection shape the product's wrap step produces
baked into a user-chosen image. The policy mounts read-only from the
host (`policy.kdl:ro` — a write to the mount path failed earlier with
`Operation not permitted`), so the guest cannot tamper with it. A
hand-assembled scratch image was also evaluated (an ~8 MiB OCI tar of
just the two binaries + mount dirs ran the full leg set fine — the
smallest possible TCB), but it was dropped: the substrate's ~1.1 GiB
per-image snapshot floor makes the disk saving negligible, and a
standard minimal image better represents the arbitrary-user-image
contract without maintaining a bespoke image format.

Real-image layering evidence the scratch image could not have
produced: `/etc/os-release` reads **succeed** — it is a symlink into
the granted `/usr` tree (`/usr/lib/os-release`), so grant resolution
is path-real; `/etc/passwd` hits the **auditor's** secret overlay
(RPC-layer deny, never reaches the kernel); `/etc/hostname` is
vminitd-managed and hits the **Landlock** deny (`EACCES`); and
`/usr/share/zoneinfo/UTC` is an allowed read over real distro content.
Deny legs therefore stay attributable per layer.

| leg | request | result | proves |
|---|---|---|---|
| init | `initialize` | `result` with `protocolVersion":"2025-11-25"` | handshake through the VM boundary; negotiated version pinned |
| list | `tools/list` | 5 tools | tool inventory through the VM |
| vm identity | `vm_identity /proc/self/status` | `uname.osrelease=6.18.35`, `NoNewPrivs=1`, `Seccomp=2`, `virtiofs_in_filesystems=true` | guest kernel ≠ Darwin host; no_new_privs + seccomp live on the probe; virtiofs is the share mechanism |
| write | `create_file /workspace/apple-ok.txt` | `created …` | allowed write grant |
| read | `read_file /workspace/apple-ok.txt` | `opened …` | allowed read |
| secret deny | `read_file /etc/shadow` | `-32001` *secret-path overlay* | RPC-layer deny, never reaches the kernel |
| syscall deny | `chmod_666 /workspace/apple-ok.txt` | `isError` `EPERM` (os error 1) | **seccomp** — `chmod*` outside the allowlist |
| net deny | `net_probe connect 192.0.2.1:80` | `isError` `EPERM` | **seccomp** — `socket` dropped under `deny host="*"` |
| fs write deny | `create_file /etc/evil.txt` | `isError` `EACCES` (os error 13) | **Landlock** — no `/etc` grant |
| fs read deny | `read_file /etc/hostname` | `isError` `EACCES` | **Landlock** — exists + world-readable; only the sandbox denies it |
| tool deny | `exec_shell` | `-32001` *tool is not allowed* | auditor `deny=#true` |
| method deny | `evil/method` | `-32001` *unknown-method* | auditor method gate |

Deny legs attribute identically to the Kata run (`EPERM` = seccomp,
`EACCES` = Landlock, `-32001` = Auditor) — the per-tool `/*` grants keep
the Auditor permissive so the kernel defaults decide. stdout carries
JSON-RPC only; the CLI's progress lines and the runner's tracing go to
stderr (no stdio contamination observed — every frame parsed).

Runner startup warnings recorded for completeness: Landlock skips
`/lib64/**` (absent in this rootfs — warns, not fails) and the unmappable
per-tool `/*` roots (by design); seccomp warns `arch_prctl` has no
mapping on aarch64 and skips that name — the same name-mapping
convention `self_test` exercises on AArch64.

## Guest launch report + audit log

`report.json` collected through the dedicated report mount and validated
host-side (`validate_guest_report_text`: schema, launch_id, runner
identity). The session's report records:

- `result.status="exited"`, `exit_code=0` — and
  `result.status="interrupted"` under SIGINT (see lifecycle)
- `guest_runner`: `{"version":"0.1.0","capabilities":["guest-report-1"]}`
- observations (mechanism results, in-guest):
  - `os.privileges` **verified** — `no_new_privs` confirmed in `pre_exec`
  - `os.fs` **verified** — `restrict_self` reported **FullyEnforced**
    (kernel Landlock ABI v7)
  - `os.net.outbound` **verified** — FullyEnforced (ABI v7)
  - `os.syscalls` **verified** — seccomp program installed
- `isolation: null` — correct by design: the guest report is the
  runner's self-report; VM identity evidence is host-side
  (`container-runtime-linux`, inspect, stats).

`audit.jsonl` records `server.connected`, `mcp_message.allowed` for
init/list/call traffic, and `tool_call.denied` for every denied leg —
the audit channel survives the VM boundary.

## Lifecycle

| event | result |
|---|---|
| stdin EOF | guest exits 0 (`"auditor relay finished"`); report written; unit auto-removed (`--rm`) |
| `container kill -s SIGINT` | runner forwards → `child terminated by signal 2`; report `interrupted`; unit removed; manager process gone |
| `container kill` (default signal) | unit `stopped` and persists without `--rm`; `container-runtime-linux` process gone |
| `container run -d` | **does not hold the workload's stdin** — detached `cat` exits immediately (`state: stopped`). A session workload must be driven attached (`-i`); a PR-19 backend cannot reuse a docker-style detached launch |
| post-exit | `container ls -a` empty after `--rm` runs; no residual units, no `container-runtime-linux` processes, snapshots are per-image (not per-run) |

## Performance (warm image cache, this host)

| measure | value | note |
|---|---|---|
| cold pull, `--platform linux/arm64` | ~7.9 s | 28 MiB compressed → 96.1 MiB rootfs unpack (3,440 entries), on this host's link |
| warm run, `container run --rm … uname` end-to-end | ~1.5 s | VM boot + exec + teardown — faster than Kata/QEMU's ~3.1 s on the reference host |
| session first response (`run` → `initialize` result) | ~1.4 s | includes VM boot + runner + policy + spawn |
| full session (init → list → 10 legs → EOF exit) | ~3.8 s | the three-test file completes in ~11 s total |
| guest memory at idle probe | ~5.9 MiB | of the 1 GiB default unit limit |
| per-image snapshot cost | **~1.2 GiB each** | `snapshots/<manifest digest>` holds a formatted block image — cost is per stored image and mostly independent of image size |
| builder VM (when present) | ~2.3 GiB | `container builder start` runs a `buildkit` container |

## Storage / operational findings

Costs and behaviours that matter for adoption, all measured on this
host:

- **Snapshot model**: each stored image consumes a formatted APFS
  block snapshot with a **~1.1 GiB floor that barely tracks image
  size** — `du` measured ~1.2 GiB for the 96 MiB-rootfs ubuntu AND
  ~1.1 GiB for the ~8 MiB scratch workload image (`mcp-writ-apple-min`).
  Shrinking the image does not shrink this cost; the usable levers are
  fewer stored images and no multi-arch pulls. Pulling without
  `--platform` stores **every** index variant — a plain
  `ubuntu@sha256:0081…` pull fetched amd64+arm64 and `image rm`
  reclaimed ~2.6 GiB. Always pull/run with `--platform linux/arm64`
  (or `--arch arm64`).
- `container image save` on a multi-arch index fails opaquely
  (`Error: content with digest …`) unless `--platform` is given; with
  it, the arm64 image exports as a 28 MiB OCI tar.
- `container image load` of that tar records a **different descriptor
  digest** than the pinned index — digest identity is not preserved
  across save/load (`image ls` showed `e7ba78d2…`; a re-pull restored
  `008173c2…`). Pin by digest against a registry, never against a
  locally loaded image.
- `container build` works — a dedicated `buildkit` builder VM builds the
  two-stage (base + secure) probe images fine — but the VM alone costs
  ~2.3 GiB and each produced image another ~1.2 GiB. On a nearly full
  disk the build fails at image export (`NSPOSIXErrorDomain 28`).
  `container image load` of a hand-assembled OCI tar is the cheaper path
  (no builder needed), but it is not what the harness uses: the harness
  pulls the digest-pinned distroless image and bind-mounts the runner
  and probe binaries read-only. Locally loaded images carry a
  store-assigned descriptor digest, so local builds cannot be
  digest-pinned — pin against registry-pulled refs only. (The scratch
  image above was evaluated through `image load` only, then dropped.)
- `container system start` prompts interactively to install the default
  kernel on first start (`[Y/n]`) — automation must pre-answer or
  pre-install the kernel.
- **Fresh-store initialisation gap (seen 2026-10-05, CLI 1.5.0):** on a
  host whose app root was just created, the first `container system
  start` can leave `content/blobs/` absent — every `image pull`/`build`
  then fails at the ingest move
  (`NSCocoaErrorDomain 4`, `…couldn't be moved to "sha256"…`,
  `NSPOSIXErrorDomain 2`) though fetching itself works. A
  `container system stop` + `start` cycle creates the directory; check
  `~/Library/Application Support/com.apple.container/content/blobs`
  exists before treating the environment as ready.
- `container system status --format json` is the parseable status
  contract (the product backend's probe): `{"status":"running",…}` +
  exit 0 when up, `{"status":"unregistered"}` + exit 1 when stopped.
  The default table output prints `apiserver is not running and not
  registered with launchd` **on stdout** when stopped — a substring
  match on `running` false-positives there, so every gate (product
  probe, e2e `check_prereqs`, `validate-apple-container.sh`,
  `clean-test-container-artifacts.sh`) must read the `status` field or
  the exit code, never the message text.
- `container image inspect` pretty-prints JSON with spaced colons
  (`"digest" : "sha256:…"`) — extract the descriptor digest with a
  whitespace-tolerant pattern, not `"digest":"`.

## Official-CLI coverage

Every operation this validation needed was covered by the official
`container` CLI — **no Swift/`Containerization.framework` layer is
required** for the launch/session/mount/signal/cleanup contract, so
adoption carries no extra library surface or maintenance cost. The CLI
gaps found are operational, not architectural: `image save` needs
`--platform` on a multi-arch index, `image save`/`load` does not
preserve digest identity, `-d` does not hold stdin, and storage
accounting is heavy (snapshot model below). None forces a different
integration mechanism; all become backend-side requirements.

## Prototype and test

- `tests/fixtures/kata/kata_probe_server.rs`,
  `tests/fixtures/kata/policy.kdl` — shared with PR-16; the
  guest-control contract under test is substrate-independent.
- `tests/apple_container_vm_e2e.rs` — the durable version of the session
  above: `apple_vm_stdio_session` asserts every leg, the host-side unit
  evidence (state/`container-runtime-linux`/stats), the guest report and
  the audit trail; `apple_vm_sigint_terminates_and_cleans_up` asserts
  signal forwarding + VM teardown; `apple_vm_platform_refusals` asserts
  the `--os windows` refusal and the rosetta-emulated amd64 record.
  The PR-19 product path adds `run_image_apple_stdio_session` (`mcp-writ
  run-image --isolation apple-container` over a `container build`
  scratch-wrapped image — report records `verified=apple-container`,
  `unit=vm`, `unit_id` matching the live `container ls` id),
  `run_image_apple_sigint_interrupts_and_cleans_up`, and
  `run_image_apple_engine_flag_refuses` (`--engine` with apple isolation
  refuses at engine resolution; `verified` stays null).
  Skips without prerequisites; `MCP_WRIT_REQUIRE_APPLE_TESTS=1` fails
  instead.
- `tests/common/mod.rs::skip_apple_test` — the matching gate.

Re-run:
`MCP_WRIT_REQUIRE_APPLE_TESTS=1 cargo test --locked --test apple_container_vm_e2e -- --nocapture`
(observed: 3 passed in ~11 s on this host; with the PR-19 product-path
tests: 10 passed in ~24 s).

## Not verified / limits

- **In-flight cancellation** — SIGINT was tested on an idle session;
  interruption mid-tool-call is unexercised.
- **`container build` as the durable image path** — the PR-19
  product-path tests build the wrapped image with `container build`
  (`FROM scratch` + runner/probe/policy COPY + ENV + ENTRYPOINT), so
  that path is regression-covered; multi-stage/base-image builds are
  still manual-only evidence.
- **Remote-registry cold pull over WAN** — the ~7.9 s figure is this
  host's link.
- **amd64 emulation legs** — only the rosetta record is asserted; the
  full MCP leg set was not run under emulation.
- **macOS < 26, Intel hosts, Windows guests** — unsupported by the
  vendor; refuse, do not infer.
- **Volumes (`container volume`), custom DNS, `exec`/`attach`,
  multi-workload units** — not exercised.
- **PR-11 communication-control and PR-15 backend-contract specifics**
  — validated only insofar as the runner/session legs exercise them;
  no claim beyond the recorded legs.

## Adoption judgment (for PR-19)

Apple `container` is **viable** as a macOS-arm64 VM isolation backend:
the guest kernel enforces Landlock ABI v7 + seccomp + no_new_privs, the
stdio MCP contract, audit, and guest-report channels all work end to
end, lifecycle teardown is complete, and warm launches are ~1.5 s.
Constraints found here, which a PR-19 backend must own rather than
inherit:

- macOS 26+ on Apple silicon only — refuse everything else explicitly.
- Arch gate: `--platform linux/amd64` silently emulates; the backend
  must reject non-arm64 workloads itself.
- Sessions must be attached — `-d` closes stdin and ends the workload.
- Digest pinning only against registry-pulled refs; `image save`/`load`
  does not preserve digest identity.
- Storage budget: ~1.2 GiB per stored image + ~2.3 GiB builder VM +
  write layers; check headroom before pulls/builds.

**Initial performance budget for the PR-19 decision** (validation-
derived proposals, not product requirements; method = this doc's
measures, regression target = `apple_container_vm_e2e.rs`):

| measure | measured | proposed budget |
|---|---|---|
| session first response | ~1.4 s | ≤5 s |
| full init→exit lifecycle | ~3.8 s | ≤10 s |
| warm launch (`run` → exec → teardown) | ~1.5 s | ≤4 s |
| guest memory at idle workload | ~5.9 MiB | ≤64 MiB |

Validated here is the **substrate**, on the pinned host above — not the
product path. PR-19 owns `IsolationBackend` wiring, `plan`/`run-image`
integration, and budget enforcement; none of that exists yet and this
document does not claim it.

**Update (PR-19, 2026-09-30):** the product path now exists and carries
this boundary. `run-image --isolation apple-container` resolves the
Apple backend (`src/container/backends/apple.rs`), probes the substrate
(apiserver identity `container-apiserver`, CLI/apiserver on the
validated 1.5.x line, macOS 26+ arm64 host, `system` running, guest
kernel recorded), launches `container run -i --rm --platform
linux/arm64` with the shared spec options (`-v` shares incl. read-only
policy, `-e` channel env, `--cidfile` unit-id record), and records
`isolation.verified=apple-container`/`unit=vm`/`unit_id` on the launch
report. `plan --isolation apple-container` diagnoses the same probe as
`apple.system`. The backend refuses foreign architectures itself (the
rosetta-emulation trap recorded above), non-Linux guests, argv-only
workloads, and any `--engine` selection — `container build`/`run-image`
are deliberately not fused: image builds stay an explicit CLI step.
Product-path evidence: the `run_image_apple_*` legs of
`apple_container_vm_e2e.rs` (10 tests total on this host), the
`plan` run and the run-log rows in `docs/test-matrix.md`.

## Teardown (戻し方)

All resources this validation created are stopped or deleted; macOS
native execution is untouched — no product-path wiring was added. The
`src/` diff is review-hardening only (auditor/policy/path fixes, the
runner-caps marker scan, `launch.identity` observation wording, and the
`src/warden/child.rs` teardown ordering that sweeps the process group
while the leader's pid is still reserved — the ordering that also
governs shutdown of the `container run` session carrying the Linux
guest runner); the rest is the new test, the skip helper, and docs.

- Workloads: none persist — every run used `--rm`; `container ls -a` is
  empty. If a unit ever leaks: `container rm -f <id>`.
- Images: the pinned distroless base (arm64+amd64 variants) remains in
  the store as normal engine cache for re-runs (`container image rm`
  removes it); the earlier `mcp-writ-apple-*` prototype builds and the
  `ubuntu` base used for the base-image measurements were removed
  (`image rm` reclaimed ~3.8 GiB). The substrate's init/builder images
  are normal engine cache.
- Fixture artifacts live under `target/` (probe ELFs under
  `target/apple-e2e/`, the musl runner under the cargo target dir) plus
  auto-cleaned `tempfile` dirs — `cargo clean` reaps the build tree if
  space requires it.
- Full rollback of the substrate itself: `container system stop` idles
  the apiserver/machine/network services; `brew uninstall container`
  removes the CLI; `~/Library/Application Support/com.apple.container`
  holds the remaining data.

Nothing falls back silently: a host without `container` (or with the
system stopped) skips the test or fails under
`MCP_WRIT_REQUIRE_APPLE_TESTS=1` — no run ever substitutes the native
path for the VM path, in either direction.

## Manual CI job (PR-25)

`scripts/validate-apple-container.sh` is the owned, repeatable
validation job — also the `apple-container` leg of the dispatch-only
[VM tests workflow](../../.github/workflows/vm-tests.yml) on a
`[self-hosted, macos, apple-container]` runner. Shared conventions,
result states, and the evidence layout live in
[manual-ci.md](manual-ci.md); this section records only the
method-specific parts.

- Environment gate, evaluated before any test work (all must hold or
  the run ends `failed`): Darwin arm64 host, `container` CLI on PATH,
  `container system status` reports running (the buildkit builder is
  started lazily by `container build` and is recorded, not gated),
  `rustc` on PATH.
- Runs `cargo test --locked --test apple_container_vm_e2e --
  --nocapture` with `MCP_WRIT_REQUIRE_APPLE_TESTS=1`,
  `MCP_WRIT_APPLE_TEST_ROOT=$work`, `MCP_WRIT_APPLE_EVIDENCE_DIR=$evidence`.
- Requires all 10 tests executed (none `ignored`), 2 `metrics.json`
  sessions (harness + product, each with `report/report.json` and
  `logs/audit.jsonl`; the product session additionally carries
  `host-identity.json` — unit id plus the `container-runtime-linux`
  manager identity — and `report/host-launch-report.json`), and 4
  `lifecycle.json` records (VM SIGINT teardown, platform refusal +
  rosetta record, product SIGINT teardown, `--engine` refusal).
- `result.json` additionally records `sw_vers` host identity, the
  `container` CLI + system + builder versions, and the digest-pinned
  base and wrapped-image digests.

