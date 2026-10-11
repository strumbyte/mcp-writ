# Test execution matrix

Which workflow owns each integration test target, how a new test gets an
owner, and how execution evidence is recorded. Local commands are in
[Development](development.md); the release procedure is in
[Releasing](releasing.md).

## Workflow inventory

All verification workflows are manual (`workflow_dispatch`) or callable
(`workflow_call`); none runs on a pull request or branch push. Do not
convert manual triggers into automatic PR triggers.

| Workflow | File | Trigger | Called by Release | Runners | Unexecuted-is-failure gate |
|---|---|---|---|---|---|
| CI | [ci.yml](../.github/workflows/ci.yml) | dispatch / call | yes (`verify` job) | `ubuntu-latest` | `MCP_WRIT_REQUIRE_E2E_TESTS=1` |
| Platform tests | [platform-tests.yml](../.github/workflows/platform-tests.yml) | dispatch / call | yes | `windows-latest`, `macos-latest` | `MCP_WRIT_REQUIRE_E2E_TESTS=1` |
| Linux tests | [linux-tests.yml](../.github/workflows/linux-tests.yml) | dispatch / call | no — dispatch on the release commit | `ubuntu-latest`, `ubuntu-24.04-arm` | `MCP_WRIT_REQUIRE_E2E_TESTS=1` |
| Container tests | [container-tests.yml](../.github/workflows/container-tests.yml) | dispatch / call | yes | `ubuntu-22.04` (requires a Docker daemon) | `MCP_WRIT_REQUIRE_CONTAINER_TESTS=1` |
| MCP server verification | [mcp-servers.yml](../.github/workflows/mcp-servers.yml) | dispatch | no — dispatch on the release commit | `ubuntu-24.04`, `macos-latest`, `windows-latest` | `MCP_WRIT_REQUIRE_SERVER_TESTS=1` |
| Go MCP runtime compatibility | [go-runtime.yml](../.github/workflows/go-runtime.yml) | dispatch / call | yes | `ubuntu-24.04`, `windows-latest` | none (fixture build + probe compare always run) |
| VM tests | [vm-tests.yml](../.github/workflows/vm-tests.yml) | dispatch only (per-method input) | no — self-hosted virtualization hosts only | `[self-hosted, linux, kata]`, `[self-hosted, macos, apple-container]`, `[self-hosted, windows, hyperv]`, `[self-hosted, windows, windows-sandbox]`, `[self-hosted, windows, wslc]`, `[self-hosted, windows, winiso]` | `MCP_WRIT_REQUIRE_{KATA,APPLE,HYPERV,WSB,WSLC,WINISO}_TESTS=1` set inside each `scripts/validate-*` job |
| Release | [release.yml](../.github/workflows/release.yml) | pushed `v*` tag | — | packaging runners | — |

Release calls CI, Platform tests, Container tests, and Go runtime before
building artifacts. Linux tests and MCP server verification stay
manual-dispatch on the release commit (see [Releasing](releasing.md)),
and the real-server fixture versions stay pinned by their setup scripts.
VM tests is dispatch-only on self-hosted virtualization hosts and is
never invoked by Release — a published archive does not imply VM-method
acceptance. Each method job runs `scripts/validate-<method>.*`, which
fixes the tested commit and environment in `result.json`, keeps the
run's scratch and evidence under `.local/<method>-validation/<run>/`,
and uploads that bundle as a workflow artifact even on failure.

## Test target ownership

Every `tests/*.rs` integration target appears below with its owning
workflow(s) or an explicit reason it is not run there. `tests/common/`
and `tests/fixtures/` are shared helpers, not targets. Non-`--test`
checks (fmt, clippy, `cargo doc`, `--lib --bins`, doc tests, the Go
fixture build, `check-server`) run as part of each workflow's job and are
not listed per target.

| Test target | Owning workflow(s) | Prerequisites / why there |
|---|---|---|
| `apple_container_vm_e2e` | VM tests `apple-container` job / `scripts/validate-apple-container.sh` (manual; see `docs/validation/apple-container.md`) — `container run` stdio session on the digest-pinned distroless base, SIGINT teardown, `--os windows` refusal + rosetta-emulation record, plus the product `run-image --isolation apple-container` path (stdio session with launch-report VM assertions, SIGINT teardown, `--engine` refusal) over a `container build` wrapped image | macOS arm64 host, Apple `container` CLI with `container system` running, network for the distroless pulls, rustc + cargo musl targets (`aarch64-unknown-linux-musl` session, `x86_64-unknown-linux-musl` emulation leg); `MCP_WRIT_REQUIRE_APPLE_TESTS` |
| `audit_durability_e2e` | CI, Platform tests, Linux tests | re-execs the test binary as an audit-emitter child and force-kills it: SIGKILL tail-loss measurement (High-severity prefix survives, buffered tail shed), `--audit-sync` zero-loss, per-mode drain latency; no prerequisites — cannot skip |
| `container_e2e` | Container tests | Docker daemon; `MCP_WRIT_REQUIRE_CONTAINER_TESTS` |
| `containerize_e2e` | Container tests | Docker daemon; `MCP_WRIT_REQUIRE_CONTAINER_TESTS` |
| `wrap_image_e2e` | Container tests | Docker daemon; `MCP_WRIT_REQUIRE_CONTAINER_TESTS` |
| `denial_audit_e2e` | CI, Platform tests, Linux tests | PR-08 denial-audit scenario regression (improvement plan §1.6/§5.4) — Scenario A: denied `tools/call`/`resources/read` over the `scripted_stdio` fixture leave `tool_call.denied`/`mcp_message.denied` (request-id correlated, `action=denied`, `reason=no-rule`) beside the refused client responses; Scenario B: the real `unotify-run` command refuses a literal `192.0.2.1:443` `connect` (EACCES) and audits `sandbox.network_denied` `layer=ip`; the real `dns-gate` binary refuses `deny host=`/unlisted names (REFUSED and `--refuse-rcode nxdomain`) and audits `sandbox.network_denied` `layer=name`; the Landlock/seccomp legs pin kernel-internal denials as **unobservable by specification** — `kernel_deny_probe` reports EACCES/EPERM under `enforcement.backend=landlock+seccomp` while no `sandbox.*_denied` record exists (absence asserted as spec, never as "nothing denied"). `python3`/`py` for Scenario A; rustc fixture builds, `unotify::check_support`, and a Landlock-capable kernel for the Linux legs — skips route `MCP_WRIT_REQUIRE_E2E_TESTS`; evidence: [denial-audit.md](validation/denial-audit.md) |
| `diagnostics_e2e` | CI, Platform tests, Linux tests | spawns the built binary; `MCP_WRIT_SKIP_SANDBOX` selects the unsandboxed vs sandboxed legs |
| `dns_gate_e2e` | CI, Platform tests, Linux tests | in-process `dnsgate` server on loopback against a scripted mock upstream — allow/deny/wildcard/CNAME-chain observation, deny-all posture vs `allow host="*"` open posture, chain-min-TTL grants, malformed/size bounds, upstream timeout/mismatch, TCP connection capacity, `sandbox.network_denied`/`sandbox.network_resolved` audit emission, fail-closed audit gating; no external resolver or privileges needed — cannot skip |
| `docs_check` | CI, Platform tests, Linux tests | repository docs hygiene (UTF-8/LF/links/anchors) |
| `ebpf_e2e` | Linux tests | Linux-only (`#![cfg(target_os = "linux")]`); drives the real `ebpf-run` command — rustc-compiled `connect_probe` fixture, `BPF_CGROUP_INET4_CONNECT`/`INET6_CONNECT` in-kernel deny (`EPERM`) + `sandbox.network_denied` `layer=ip` audit over the ring buffer, deny-all posture, static CIDR rules, IPv6 deny, dynamic allowlist grant and TTL expiry, private-cgroup lifecycle (join in `pre_exec`, removed after exit), `--report` capability (`cgroup-ebpf`, hooks, kernel release)/egress layers/limitations/drain stats, and the unprivileged launch refusal (positive assertion when `CAP_BPF`/`CAP_SYS_ADMIN` are absent, skip-assert when present). Skips via `common::skip_e2e_test` when `ebpf::check_support` refuses — the same probe the command runs; `MCP_WRIT_REQUIRE_E2E_TESTS=1` fails the skip instead of passing unexecuted. Requires a privileged Linux environment (CAP_BPF or CAP_SYS_ADMIN, CAP_NET_ADMIN, writable cgroup v2, kernel cgroup-BPF with the socket-addr hooks); verified on WSL2 kernel 6.18 in a privileged container (9/9) |
| `environment_e2e` | CI, Platform tests, Linux tests | `python3`/`py` fixture; includes a real sandboxed spawn per OS; `MCP_WRIT_REQUIRE_E2E_TESTS` |
| `go_runtime_policy` | CI, Platform tests, Linux tests; also Go runtime | in-process policy/auditor checks; the Go runtime job repeats it next to the Go fixture checks |
| `hyperv_vm_e2e` | VM tests `hyperv` job / `scripts/validate-hyperv.ps1` (manual; see `docs/validation/windows-hyperv.md`) — `docker run --isolation hyperv` stdio session on the digest-pinned Server Core base, `docker kill` teardown, child-exit unwind, `--isolation=process` refusal for the build-mismatched image, `wrap-image` product path, plus the product `run-image --isolation hyperv` path (stdio session with launch-report VM assertions, external unit-kill teardown, non-docker refusal) | Windows x86-64 host, Docker engine in Windows mode (`OSType=windows`) with the Hyper-V stack (`vmcompute`/`hns`), rustc fixture build, Windows PE `mcp-secure-runner`, network for the Server Core pull; `MCP_WRIT_REQUIRE_HYPERV_TESTS` |
| `inspector_arm64_p4` | CI, Platform tests | host-independent in-memory ELF analysis; see note below |
| `inspector_arm64_p5` | CI, Platform tests | host-independent in-memory ELF analysis; see note below |
| `inspector_macho_p6` | CI, Platform tests | host-independent in-memory Mach-O analysis; see note below |
| `integration` | CI, Platform tests, Linux tests | spawns the built binary unsandboxed (`MCP_WRIT_SKIP_SANDBOX=1`) |
| `kdl_policy_e2e` | CI, Platform tests, Linux tests | spawns the built binary unsandboxed (`MCP_WRIT_SKIP_SANDBOX=1`) |
| `kata_vm_e2e` | VM tests `kata` job / `scripts/validate-kata.sh` (manual; see `docs/validation/kata.md`) — the direct `docker run --runtime kata` harness plus the product `run-image --isolation kata` path (stdio session, SIGINT teardown, non-docker refusal) | Docker daemon with a registered `kata` runtime, `/dev/kvm`, `/dev/vhost-vsock`, rustc fixture build; `MCP_WRIT_REQUIRE_KATA_TESTS` |
| `manifest_fixtures` | CI, Platform tests | host-independent fixture parsing; see note below |
| `mcp_wire_e2e` | CI, Platform tests, Linux tests | `python3`/`py` scripted stdio fixture; spawns the built binary unsandboxed (`MCP_WRIT_SKIP_SANDBOX=1`); `MCP_WRIT_REQUIRE_E2E_TESTS` |
| `module_layering` | CI, Platform tests | host-independent `src/` scan; see note below |
| `namespaced-run` manual legs | manual (PR-09 PoC validation; see `docs/validation/linux-namespaced-proxy.md` for the command recipe and recorded evidence) — the real `namespaced-run` command on a capable kernel: capability probe, DNS-gate intercept + TTL grants, TCP allow/deny + `sandbox.network_denied`, UDP per-datagram allow/deny, IPv6/fragment/non-TCP-UDP drops, `/run` AF_UNIX hiding, pidns monitor isolation, `setns`/`unshare`/`io_uring` seccomp denials, supervisor-SIGKILL pdeathsig teardown, `--report` capability/layers | Linux host with unprivileged userns + `/dev/net/tun` (verified on WSL2 kernel 6.18); not yet a `cargo test` target — a committed e2e harness is future work |
| `path_resolution_e2e` | CI, Platform tests, Linux tests | rustc fixture build, sandboxed spawn, symlink/junction; `MCP_WRIT_REQUIRE_E2E_TESTS` |
| `plan_report_e2e` | CI, Platform tests, Linux tests | spawns the built binary for `plan` (four fixed statuses/exit codes, no workload launch, nonexistent-path command check, default `fail_closed` audit warn, `hash.identity` role check — a content-only pin set fails rather than counting as a process binding) and `run --report` (dry-run session, launch-id ↔ audit correlation, stdout stays JSON-RPC, unwritable report fails before spawn, `server.connected`/`server.error` carry the `enforcement` member — backend/`dry_run`/per-control states checked against the report's own plan+observations) |
| `protocol_versions` | CI, Platform tests, Linux tests | `python3`/`py` fixture servers against the in-process legislator client |
| `real_servers_e2e` | MCP server verification | pinned servers via `tests/fixtures/real_servers/setup.*`, Node + Python; `MCP_WRIT_REQUIRE_SERVER_TESTS` |
| `self_test` | CI, Platform tests, Linux tests | Linux leg compiles the rustc fixture (`python3`/`py` fallback) and runs Warden probes incl. on AArch64; non-Linux asserts the skipped verdict |
| `tool_enforcement_e2e` | CI, Platform tests, Linux tests | spawns the built binary unsandboxed (`MCP_WRIT_SKIP_SANDBOX=1`) |
| `unotify_e2e` | CI, Platform tests, Linux tests | Linux-only (`#![cfg(target_os = "linux")]`, empty elsewhere): drives the real `unotify-run` command — rustc-compiled `connect_probe` fixture, seccomp user-notification round-trip, CIDR deny + `sandbox.network_denied` audit, allow-side `sandbox.network_allowed` record, deny-all posture, dynamic allowlist grant and TTL expiry, `defaults.environment` restriction on the supervised child, `binary-hash` pin match/mismatch, dropped-listener ENOSYS fail-close, fail-closed audit-log requirement, SIGTERM teardown, `--report` capability/layers. Skips via `common::skip_e2e_test` when the kernel lacks user notification or `SECCOMP_USER_NOTIF_FLAG_CONTINUE` (< 5.5) — `MCP_WRIT_REQUIRE_E2E_TESTS=1` fails the skip instead of passing unexecuted |
| `windows_probe_e2e` | CI, Platform tests, Linux tests | rustc fixture build (`tests/fixtures/windows_probe_stub.rs` plays `wsl`/`wslc`/`reg`/`powershell` from a `scenario.txt` next to the exe via `MCP_WRIT_*_EXE` overrides); drives `plan --engine wslc` on any host: legacy/inbox WSL, below-floor WSL (< 2.9.3), `wslc` absent, disabled feature, unparseable version, UTF-16 output, and the non-Windows proof that native plans spawn no Windows tools |
| `windows_isolation_e2e` | VM tests `windows-isolation` job / `scripts/validate-windows-isolation.ps1` (see `docs/validation/windows-isolation.md`); golden contract layer runs in any `cargo test` | PR-30 mechanism comparison + PR-32 product legs: `tests/fixtures/windows_isolation/winiso_probe.rs` (std-only, `rustc -O`, raw-dylib only) legs `facts`/`contracts`/`attempts`/`ac-run[--lpac --net]`/`psec-run`/`psec-spec-test`; golden JSONs pin the contract and the fail-closed evidence classification (denied/refused/filtered/unavailable) plus per-candidate dispositions; live legs on Windows assert the AppContainer baseline (fs deny, ACL restore, profile cleanup, job kill-on-close) and PSEC v1.0 enforcement (create/spawn/fs+egress deny/env non-inheritance/close); `winiso_live_product_run` launches `mcp-writ run --windows-mechanism <m>` itself — report mechanism/`os.process`/`result`, audit log, and the named env allow-list refusal under PSEC; PR-08 additionally parses the JSONL `enforcement` member on `server.connected` — `backend` matching the requested mechanism, `psec` state (pinned `schema_version` + egress disposition) only on the PSEC launch, and no `server.connected` claiming `appcontainer` on a refused PSEC run | Windows x86-64 host, interactive session, rustc; golden layer is host-independent. Live legs degrade to recorded `unavailable` on hosts without a candidate — never a pass-by-absence. `MCP_WRIT_REQUIRE_WINISO_TESTS` |
| `windows_sandbox_vm_e2e` | `platform-tests` Windows job runs the filtered cargo target (14 local tests; same selection as `scripts/validate-windows-sandbox.ps1`); manual host validation uses `-Vm` (all 21 tests: 14 local, 3 prototype VM, 4 product VM) — also the VM tests `windows-sandbox` job on a `[self-hosted, windows, windows-sandbox]` runner. See `docs/validation/windows-sandbox.md` and `docs/validation/windows-sandbox-product.md`. Covers authenticated/bounded relay, runner/Warden, owned-ID management, product command/payload sessions, v2/MRTR gates, audit/report failure and restart | Windows x86-64, rustc, PE runner and required app-local CRT DLLs; VM tier additionally needs `Containers-DisposableClientVM`, ID-based `wsb` CLI, interactive logon and Default Switch IPv4. `MCP_WRIT_REQUIRE_WSB_TESTS=1` is mandatory in both script modes |
| `workload_hash_e2e` | CI, Platform tests, Linux tests | rustc fixture build + `python3`/`py`; spawns the built binary; `MCP_WRIT_REQUIRE_E2E_TESTS`; `run --report` `code_identity` records each pin's role and which check points (`initial` / `bind_*` / `pre_spawn_*`) passed, on success and on a tampered launch |
| `wslc_container_e2e` | VM tests `wslc` job / `scripts/validate-wslc.ps1` (manual; see `docs/validation/wslc.md`) — `wslc run` capability map (required args honored, docker-isms refused), stdio contract (bidirectional, EOF, exit codes, non-TTY), session model (default + owned dedicated sessions), virtiofs share semantics (RO/RW/unicode/case/reparse), Consommé network semantics (DNS/host-loopback/`none`/`-p`), the runner-wrapped secure-image session (same leg set as Kata/Apple), `kill`/CLI-death/launch-failure lifecycle, storage layout, and the PR-29 *product* legs (`product.rs`): `run-image --engine wslc` end-to-end + report identity, unwrapped-image refusal, external SIGINT teardown, `plan --engine wslc` diagnostics | Windows x86-64 host, interactive logon session, WSL product ≥ 2.9.3 with `wslc` resolvable (`MCP_WRIT_WSLC_EXE`, PATH, or `C:\Program Files\WSL\wslc.exe`), rustc + `x86_64-unknown-linux-musl`, cargo musl runner build, network for the digest-pinned `ubuntu:24.04` pull; `MCP_WRIT_REQUIRE_WSLC_TESTS` |

### Coverage notes

- The three inspector targets analyze fixture bytes in memory — the
  AArch64/Mach-O names describe the analyzed format, not a required host
  (the fixtures are never executed). CI (`ubuntu-latest`) plus Platform
  tests (`windows-latest`, `macos-latest`) already cover all three OSes,
  so Linux tests deliberately does not repeat them: that workflow exists
  for real AArch64 hardware and Linux-only enforcement paths, which
  these tests do not exercise.
- `module_layering` and `manifest_fixtures` scan or parse repository
  files without spawning a workload or applying a sandbox; results are
  host-independent. They are owned by CI + Platform tests and are not
  duplicated into Linux tests for the same reason.
- `environment_e2e` and `workload_hash_e2e` spawn real processes (the
  former also applies the real OS sandbox), so they run on every OS —
  including the AArch64 runner, where `workload_hash_e2e` also exercises
  the aarch64 build and `environment_e2e` the aarch64 seccomp name
  mapping.
- `go_runtime_policy` is additionally owned by Go MCP runtime
  compatibility, which runs it next to the Go fixture build and the
  direct-vs-sandboxed probe comparison (plus the
  `go_runtime_syscalls_are_mapped_but_not_implicitly_allowed` lib test).

### Skip gates

A skip helper turns a missing prerequisite into a skip locally and into
a failure wherever the matching variable is set:

| Variable | Helper (`tests/common/mod.rs`) | Set by |
|---|---|---|
| `MCP_WRIT_REQUIRE_E2E_TESTS=1` | `skip_e2e_test` — used by `path_resolution_e2e`, `environment_e2e`, `workload_hash_e2e`, `diagnostics_e2e` (via `compiled_open_path_fixture`), `denial_audit_e2e` | CI, Platform tests, Linux tests |
| `MCP_WRIT_REQUIRE_CONTAINER_TESTS=1` | `skip_container_test` — used by `container_e2e`, `containerize_e2e`, `wrap_image_e2e` | Container tests |
| `MCP_WRIT_REQUIRE_SERVER_TESTS=1` | `skip_server_test` — used by `real_servers_e2e` | MCP server verification |
| `MCP_WRIT_REQUIRE_KATA_TESTS=1` | `skip_kata_test` — used by `kata_vm_e2e` | `scripts/validate-kata.sh` / VM tests `kata` job (`docs/validation/kata.md`) |
| `MCP_WRIT_REQUIRE_APPLE_TESTS=1` | `skip_apple_test` — used by `apple_container_vm_e2e` | `scripts/validate-apple-container.sh` / VM tests `apple-container` job (`docs/validation/apple-container.md`) |
| `MCP_WRIT_REQUIRE_HYPERV_TESTS=1` | `skip_hyperv_test` — used by `hyperv_vm_e2e` | `scripts/validate-hyperv.ps1` / VM tests `hyperv` job (`docs/validation/windows-hyperv.md`) |
| `MCP_WRIT_REQUIRE_WSB_TESTS=1` | `skip_wsb_test` — used by `windows_sandbox_vm_e2e` | `platform-tests` Windows relay step, `scripts/validate-windows-sandbox.ps1 -Vm`, and the VM tests `windows-sandbox` job (`docs/validation/windows-sandbox.md`) |
| `MCP_WRIT_REQUIRE_WSLC_TESTS=1` | `skip_wslc_test` — used by `wslc_container_e2e` | `scripts/validate-wslc.ps1` / VM tests `wslc` job (`docs/validation/wslc.md`) |
| `MCP_WRIT_REQUIRE_WINISO_TESTS=1` | `skip_winiso_test` — used by `windows_isolation_e2e` live legs | `scripts/validate-windows-isolation.ps1` (`docs/validation/windows-isolation.md`) |

These variables only cover tests that call the matching helper — they
cannot detect a target missing from a job. The ownership table above is
the record of what runs where; do not assume the gates make that table
redundant. A new mandatory test with its own prerequisites (for example
the VM verification planned in the PR guide) needs its own
unexecuted-is-failure mechanism. A run under `MCP_WRIT_SKIP_SANDBOX`
never counts as having exercised OS enforcement.

## Registering a new test

When a PR adds a `tests/*.rs` target (or removes one):

1. Pick the owning workflow(s) from what the test exercises: OS sandbox
   or spawned binaries → CI + Platform tests + Linux tests; real AArch64
   or Linux-only enforcement paths → Linux tests; host-independent
   repository/library analysis → CI + Platform tests; Docker image
   workflows → Container tests; pinned real servers → MCP server
   verification.
2. Add `--test <name>` to the owning workflows in the same PR that adds
   the target.
3. If the test can skip on a missing prerequisite, route the skip
   through a `common::skip_*` helper and make sure an owning mandatory
   job sets the matching `MCP_WRIT_REQUIRE_*` variable. If none fits,
   add a new gate together with the job that sets it — a mandatory test
   must not be able to end silently unexecuted.
4. Update the ownership table in the same PR. If the test intentionally
   runs nowhere yet, record the exclusion reason in the table instead.
5. Record the run evidence in the PR body using the format below; fold
   it into the record table when the PR closes.

This matrix was introduced by PR-01. PRs that proceeded before it must
have their target / workflow / result / not-run rows collected from
their PR bodies into the record table; none existed at creation.

## Windows supplement environment matrix (PR-32)

The Windows supplement's environments and methods stay on separate
rows — the verified cells name their recorded evidence, and
unverified/held rows are never merged into a supported one. "Verified
host" is Windows 11 25H2 `26200.9457` x86-64 retail, interactive
session, non-elevated.

| Environment / method | Contract | Recorded evidence | Kept out of supported rows |
|---|---|---|---|
| Windows + legacy/inbox WSL only, or WSL < 2.9.3, or `wslc` absent | `--engine wslc` refuses at selection/`plan` (`engine.resolve` fail — never a docker substitute, never auto-detected) | `windows_probe_e2e` stub legs (inbox WSL, below-floor 2.4.12, absent `wslc`, disabled feature, unparseable/UTF-16 answers) — CI on every host; `validate-wslc.ps1` environment-unavailable record on WSL 2.4.12.0 (2026-10-06) | not a `wslc` host; no fallback row exists |
| Windows + GA WSL line with `wslc` (WSL ≥ 2.9.3; measured 3.0.1.0) | `container` isolation, `--engine wslc`, `unit=container` — the shared session VM is substrate plumbing, not a VM boundary | `wslc_container_e2e` 16/16 gated suite (2026-10-06) — [wslc.md](validation/wslc.md) | ARM64 Windows, elevated sessions, Windows-container guests, SDK invocation, enterprise-policy/MDE interaction — unverified |
| Windows native, AppContainer (default) | `run`/`plan`, `native_windows_mechanism="appcontainer"` | `windows-latest` hosted CI + `windows_isolation_e2e` live legs + `winiso_live_product_run` AppContainer launch | — |
| Windows native, PSEC (opt-in) | `--windows-mechanism psec`; capability probe + per-policy expressibility; refusal never falls back to AppContainer | `windows_isolation_e2e` PSEC legs + product legs on the verified host (schema 1.x, flags `0x3`) — [windows-isolation.md](validation/windows-isolation.md) | 24H2/Server editions, ARM64, Insider builds — unverified; Win32 app isolation, IsolationSession, MXC stay on Hold |
| `hyperv` | Windows-mode dockerd (`OSType=windows`) + `vmcompute`/`hns`; guest build ≤ host | `validate-hyperv.ps1` recorded `environment unavailable` (2026-10-04, dockerd not running); job pending | — |
| `windows-sandbox` | `Containers-DisposableClientVM` + Store `wsb` + interactive session | `validate-windows-sandbox.ps1 -Vm` accepted 2026-10-04 (Store 0.8.107.0) — [windows-sandbox-product.md](validation/windows-sandbox-product.md) | non-interactive/session-0 hosts refuse |
| Insider/preview-only surfaces | dedicated lab host via `validate-windows-isolation.ps1 -Lab` | recorded not-run on the verified retail host | never a standard-row claim |

`wslc` diagnostics for the not-installed / below-floor / disabled cases
are covered by `windows_probe_e2e` on every hosted leg (the stub plays
each probed CLI from a scenario file, so the assertions do not depend on
the runner's real WSL state). Resource-shortage handling is the shared
40 GiB disk gate in every `scripts/validate-*` — insufficient space is
`environment unavailable`/`failed`, never a partial pass.

## Execution evidence

A verification record keeps these fields and distinguishes results that
must never be merged:

| Field | Content |
|---|---|
| Date | when the run happened |
| Commit | the tested commit |
| Job | workflow + matrix leg, with the run URL when available |
| Environment | OS/arch plus kernel or runner image where relevant |
| Command | the executed command |
| Result | `pass` / `fail` / `skipped` / `not run` / `environment unavailable` |
| Notes | failure cause, skip reason, or why the environment was missing |

Rules: `pass` means the test actually executed and passed. A prerequisite
`skipped` inside a `MCP_WRIT_REQUIRE_*` job is a job failure, not a pass.
`not run` and `environment unavailable` are recorded as-is — neither
counts as verification.

| Date | Commit | Job | Environment | Command | Result | Notes |
|---|---|---|---|---|---|---|
| 2026-09-22 | `8347f51` + PR-01 working tree | local (PR-01 verification) | WSL2 on Windows 11, kernel 5.15.167.4-microsoft-standard-WSL2, x86_64 | `cargo test --locked --test module_layering --test manifest_fixtures --test environment_e2e --test workload_hash_e2e` | pass | 20 tests; `environment_applies_under_sandbox` ran the real Landlock/seccomp sandbox; `workload_hash_e2e` built the rustc fixture via a `zig cc` linker shim |
| 2026-09-22 | `8347f51` + PR-01 working tree | local (PR-01 verification) | same | `cargo test --locked --test docs_check` (T-DOC) | pass | 12 tests; covers the new/updated docs for links, anchors, UTF-8, BOM, LF |
| 2026-09-22 | `8347f51` + PR-01 working tree | local (PR-01 verification) | same | `cargo fmt --all -- --check`, `cargo clippy --locked --all-targets -- -D warnings`, `cargo test --locked --lib --bins` (T-BASE subset) | pass | 1371 lib tests; `tests/common/mod.rs` comment updated |
| 2026-09-22 | `8347f51` + PR-01 working tree | windows-latest, macos-latest, ubuntu-24.04-arm legs | — | — | environment unavailable | WSL2 is not a CI leg; Platform tests and the AArch64 leg must run as dispatched workflows on the PR merge commit |
| 2026-09-23 | `2242ac3` | local (PR-01 verification, macos-latest leg equivalent) | macOS 26.6.2 (25G83), arm64, rustc 1.98.1 | `MCP_WRIT_REQUIRE_E2E_TESTS=1 cargo test --locked` with the platform-tests target list (16 `tests/*.rs` targets) | pass | 190 tests; `environment_applies_under_sandbox` and `sandboxed_os_boundary_and_process_shared_access` exercised the real sandbox-exec path; no prerequisite skips. The dispatched macos-latest leg still has to run on the merge commit — this row is the local equivalent |
| 2026-09-23 | `2242ac3` | local (PR-01 verification) | same | `cargo fmt --all -- --check`, `cargo clippy --locked --all-targets -- -D warnings`, `cargo test --locked --lib --bins`, `cargo test --locked --doc` (T-BASE) | pass | 1374 lib tests; the crate has no doc tests |
| 2026-09-23 | working tree (PR-07) | local (PR-07 verification) | Windows 11 x86_64 host, GNU bash | `cargo test --test plan_report_e2e` | pass | 10 tests: `plan` four statuses (`ready` 0 / `blocked` 1 / `invalid` 2 / `error` 1), no-workload-launch marker check, `--report` JSON-to-file vs stdout separation, `run --report` dry-run session (result `exited` 0, launch_id ↔ `server.connected`/`server.error` correlation, stdout JSON-RPC only); the unwritable-`--report`-before-spawn check is `#[cfg(unix)]` and did not run here |
| 2026-09-26 | working tree (PR-07 review fixes) | local (post-review verification) | Windows 11 x86_64 host, GNU bash | `cargo fmt --all -- --check`, `cargo clippy --locked --all-targets -- -D warnings`, `cargo test --locked --lib --bins`, `cargo test --locked --test plan_report_e2e --test module_layering --test docs_check` | pass | 1450 lib tests + 16 module_layering + 11 docs_check + 12 `plan_report_e2e` (adds: nonexistent command path → `command_not_found`/`blocked`; default `fail_closed` policy → `audit.config` warn and still `ready`) |
| 2026-09-26 | `f613c17` + PR-08 working tree | local (PR-08 verification) | WSL2 on Windows 11, kernel 5.15.167.4-microsoft-standard-WSL2, x86_64 (user-local gcc toolchain) | `cargo fmt --all -- --check`, `cargo clippy --locked --all-targets -- -D warnings`, `cargo test --locked --all-targets` | pass | 1484 lib tests + all integration targets; new coverage: guest-report cap marker scan/parse, `MCP_WRIT_RUNNER_CAPS` env detection, non-Linux image refusal, `image_target_arch`, remote-daemon hint, report size/JSON/schema/launch-id/runner-version validation, report mount + cidfile args, `guest_runner`/`guest` serialization |
| 2026-09-26 | `f613c17` + PR-08 working tree | local (PR-08 verification) | same | `cargo test --locked --test plan_report_e2e` | fail (pre-existing) | 3 failures — `plan_ready_default_fail_closed_warns_audit_config`, `plan_ready_exits_0_with_plan`, `plan_report_goes_to_file_not_stdout` — all fail on the same `syscalls.allowed must include execve` sandbox-plan diagnostic; identical failures reproduced on the `f613c17` baseline checkout, so not a PR-08 regression |
| 2026-09-26 | `f613c17` + PR-08 working tree | local (PR-08 verification) | same | container E2E (`container_e2e`, `containerize_e2e`, `wrap_image_e2e` guest-report legs) | environment unavailable | no Docker daemon reachable from WSL2; the Container tests workflow owns those targets (`MCP_WRIT_REQUIRE_CONTAINER_TESTS=1`) and must run them on the PR merge commit |
| 2026-09-28 | working tree (PR-12) | local (PR-12 verification) | Windows 11 x86_64 host, GNU bash, rustc/cargo 1.98.1 | `cargo fmt --all -- --check`, `cargo clippy --locked --all-targets -- -D warnings`, `cargo test --locked --all-targets` | pass | 1535 lib tests + all integration targets; new coverage: `LaunchReport.code_identity` serialization (kind/role/check-point strings), `LaunchIdentity` check-point recording incl. mid-list verification failure, `for_image` digest vs mutable tag, `plan` `hash.identity` fails a docker-manifest-only policy and `guest.hash` marks workload pins guest-verified, `workload_hash_e2e` asserts per-pin check points on success and on a tampered launch |
| 2026-09-28 | working tree (PR-12) | local (PR-12 verification) | same | container E2E (`container_e2e` report legs) | environment unavailable | no Docker daemon on this host; the Container tests workflow owns the guest-report/`code_identity` attachment legs and must run them on the merge commit |
| 2026-09-28 | working tree (PR-12 review fixes) | local (post-review verification) | Windows 11 x86_64 host, GNU bash, rustc/cargo 1.98.1 | `cargo fmt --all -- --check`, `cargo clippy --locked --all-targets -- -D warnings`, `cargo test --locked --all-targets` | pass | 1539 lib tests + all integration targets; review fixes: per-pin `image_inspect` (digest + repository match, via `workload` image-ref helpers — verifier cannot reference `container`), bind/pre-spawn checks gated on the re-evaluated binding rule, `mark_server_failed` ignores `UnboundWorkload`, refused-tag `mutable` note, `launch.identity` plural fix; new tests: sibling docker-manifest pin, different-repo pin, refused tag, stray `binary-hash` pin, `UnboundWorkload` |
| 2026-09-29 | `f75660f` + PR-18 working tree | local (PR-18 verification) | macOS 26.6.2 (25G83) arm64, Apple `container` 1.5.0, guest kernel vmlinux-6.18.35-197-debug | `MCP_WRIT_REQUIRE_APPLE_TESTS=1 cargo test --locked --test apple_container_vm_e2e -- --nocapture` | pass | 3 tests: `apple_vm_stdio_session` (init→tools/list→10 legs; Landlock `EACCES` read/write denies, seccomp `EPERM` chmod/socket denies, auditor `-32001` secret/tool/method denies, guest report `exited` 0 + FullyEnforced ABI v7 observations, audit trail, exit after stdin EOF), `apple_vm_sigint_terminates_and_cleans_up` (SIGINT → `interrupted` report, unit + `container-runtime-linux` gone), `apple_vm_platform_refusals` (`--os windows` refused; `linux/amd64` runs rosetta-emulated, recorded not refused) — full evidence in `docs/validation/apple-container.md` |
| 2026-09-29 | `f75660f` + PR-18 working tree | local (PR-18 verification) | same | `cargo fmt --all -- --check`, `cargo clippy --locked --all-targets -- -D warnings`, `cargo test --locked --lib --bins` (T-BASE subset) | pass | 1637 lib tests; new target compiles clean under clippy -D warnings |
| 2026-09-29 | `f75660f` + PR-18 working tree | local (PR-18 macOS T-NATIVE leg) | same | `cargo test --locked --test environment_e2e --test diagnostics_e2e --test self_test` | pass | 13 tests on the macOS native path — `environment_applies_under_sandbox` exercised real sandbox-exec; `non_linux_marks_warden_skipped` confirmed Linux controls do not claim enforcement off Linux. Kept distinct from the Linux-guest T-VM result per the PR guide |
| 2026-09-30 | `bbc8f77` + PR-19 working tree | local (PR-19 verification) | macOS 26.6.2 (25G83) arm64, Apple `container` 1.5.0, guest kernel vmlinux-6.18.35-197-debug | `cargo test --locked --all-targets` | pass | 1702 lib tests + all integration targets; new coverage: `backends::apple` capability/prereq-probe/arg tests, Apple `image inspect` shape parse, `resolve_launch_engine` `--engine` refusal, plan `apple.system` diagnostics |
| 2026-09-30 | `bbc8f77` + PR-19 working tree | local (PR-19 verification) | same | `MCP_WRIT_REQUIRE_APPLE_TESTS=1 cargo test --locked --test apple_container_vm_e2e -- --nocapture` | pass | 10 tests — PR-18 substrate legs plus the product path: `run_image_apple_stdio_session` (`container build` scratch-wrapped image, init→tools/list→4 legs, live `container-runtime-linux --uuid` evidence, report `verified=apple-container`/`unit=vm`/`unit_id`=ls id, guest report correlated, exit 0 + unit gone), `run_image_apple_sigint_interrupts_and_cleans_up` (SIGINT → `interrupted` report, unit + runtime process gone), `run_image_apple_engine_flag_refuses` (`--engine docker` → `resolve engine` refusal, `verified=null`) |
| 2026-09-30 | `bbc8f77` + PR-19 working tree | local (PR-19 verification) | same | `mcp-writ plan --isolation apple-container --image <pinned> --policy policy.example.kdl` | pass | `apple.system` probe passed against the real apiserver (driver 1.5.0, runtime `container-runtime-linux`, kernel digest recorded); target `substrate=vm`, `engine=apple-container`, `host_os=macos`, `workload_os=linux`, `workload_arch=aarch64`; plan blocked only on the unwrapped image's missing runner — the expected downstream gate |
| 2026-10-02 | `3a5efe1` + PR-20 working tree | local (PR-20 verification) | Windows Pro 25H2 (26200.9457) x86_64, Docker engine 29.7.2 Windows mode (`OSType=windows`, default isolation hyperv), guest kernel 10.0.26100.33438 (servercore ltsc2025, digest-pinned) | `MCP_WRIT_REQUIRE_HYPERV_TESTS=1 cargo test --locked --test hyperv_vm_e2e -- --nocapture` | pass | 4 tests: `hyperv_vm_stdio_session` (init→tools/list→12 legs; AppContainer token + Job + DACL denies on `C:\Windows`/`C:\writ-deny`, capability deny `WSAEACCES` on TCP connect, secret-overlay and auditor denies, restricted env, live `vmwp.exe` + `Isolation=hyperv` inspect record, guest report + audit log correlated, EOF exit), `hyperv_vm_kill_terminates_and_cleans_up` (kill → unit + inspect record gone), `hyperv_vm_child_exit_terminates_session` (child exit unwinds session; exit-code fidelity race recorded), `hyperv_process_isolation_refused_for_mismatched_image` (`--isolation=process` refused) — full evidence in `docs/validation/windows-hyperv.md` |
| 2026-10-03 | `improvement-PR-23` working tree | local (PR-23 verification) | Windows 11 Business (26200) x86_64, `Containers-DisposableClientVM` staged but **disabled** (no `WindowsSandbox.exe`; hns/vmcompute running) | `cargo test --test windows_sandbox_vm_e2e -- --nocapture` | partial | 4 tests: `wsb_relay_loopback_protocol` pass (relay handshake rejections logged, framed MCP session through real runner+warden, stdout pure JSON-RPC, AppContainer/Job/DACL/capability denies, report+audit on the rw dir, stdin-EOF exit 0), `wsb_relay_loopback_child_exit` pass (`{"code":3}` exit frame, relay close), `wsb_relay_stdio_session` + `wsb_relay_sandbox_kill_cleans_up` **skipped — unexecuted** (feature disabled, not a pass) — full record in `docs/validation/windows-sandbox.md` |
| 2026-10-03 | `ed8b3c6` + PR-23 follow-up working tree (source hashes in local result.json) | local; `platform-tests` Windows relay step registered but remote job not dispatched | Windows 11 Business 26200 AMD64, Sandbox still disabled | `scripts/validate-windows-sandbox.ps1 -Repetitions 3`, final single run, T-BASE, T-DOC, T-LAYER | local passed; VM pending | 13 local relay tests passed plus two measured-session repeats; final 13/13 passed; 1,734 lib, 11 docs, 16 layering tests passed. fmt/clippy passed; cargo doc succeeded with two existing warnings; bins/doctests 0 cases. Required VM test failed with exit 101 on the missing feature as intended; three VM tests remain unexecuted. Work cleanup and evidence persistence passed. See `docs/validation/windows-sandbox.md` |
| 2026-10-03 | `ed8b3c6` + PR-23 enabled-host fixes; source/script/fixture hashes in result.json | local interactive session 1; remote CI not dispatched | Windows 11 Business 25H2 26200.9457 AMD64, Sandbox enabled, Store CLI 0.8.107.0 | `scripts/validate-windows-sandbox.ps1 -Vm -Repetitions 3`, T-BASE, KDL/path regression checks | VM acceptance passed; conditional adoption | 16/16 passed plus two measured VM repeats: Warden/RO/RW/audit/report, owned-ID stop and nine adverse guest cases. First contact 7.06–7.60 s, RPC p95 3.18–8.87 ms, stop 0.95–1.01 s; 4096 MiB configuration with guest and host memory snapshots. No owned VM remained; work cleanup passed. Root-glob and Store-client lifecycle fixes verified. 1,735 lib and 18 KDL tests passed, fmt/clippy passed, doc succeeded with two existing warnings; bins/doctests 0 cases. Path checks: five initially passed; after the user enabled Developer Mode, the remaining symlink case passed an exact retry with `MCP_WRIT_REQUIRE_E2E_TESTS=1`, covering all six across both runs. Follow-up evidence: `.local/pr23-symlink-test.txt` and `.local/pr23-symlink-test.json`. VM evidence: `.local/wsb-validation/20261003-135440-90c8e5fe1a7243cfa2f4d46b38a8d4ec/`; details in `docs/validation/windows-sandbox.md` |
| 2026-10-04 | `aecb48c` + PR-24 working tree; source/binary hashes retained | local interactive session 1; remote CI not dispatched | Windows 11 Business 25H2 26200.9457 AMD64, Store Sandbox 0.8.107.0, Rust 1.99.0 | `scripts/validate-windows-sandbox.ps1 -Vm`, final product subset, T-BASE, T-PROTOCOL, Windows T-NATIVE, wire and plan/report checks | product acceptance passed within the interactive single-VM scope | 20/20 relay/VM tests and final 4/4 product tests passed. Final three product sessions: first response 13.84–14.58 s, RPC p95 4.36–4.64 ms, stop 1.75 s, 4096 MiB configuration. 1,742 library, 54 protocol, 18 native, 39 wire and 13 plan/report tests passed; the environment test used an empty dedicated real-server fixture root to avoid unrelated package-tree grants exceeding its startup deadline. fmt/clippy passed; doc succeeded with two existing warnings. Evidence and limits: [Windows Sandbox product validation](validation/windows-sandbox-product.md) |
| 2026-10-04 | `b755a9e` + PR-25 working tree | local (`scripts/validate-kata.sh` — the same job the VM tests `kata` leg runs) | WSL2 on Windows 11 (Ubuntu 24.04.2, kernel 5.15.167.4-microsoft-standard-WSL2) x86_64, docker 29.1.3 + registered `kata` runtime, /dev/kvm + /dev/vhost-vsock, rustc 1.99.0 | `scripts/validate-kata.sh` | pass | `result.json` = `vm-tests-passed`; 5/5 `kata_vm_e2e` executed, none ignored; 2 metrics + 3 lifecycle session records; QEMU RSS 258–260 MiB; guest kernel 6.18.35 vs host 5.15 (kata cmdline/virtiofs markers are the identity evidence); record `.local/kata-validation/20261004-052818-8ee5d130c4d2803d57401486e7a2d970/`; run used `CARGO_TARGET_DIR` on the WSL ext4 because D: was under the 40 GiB gate; an earlier run also proved the disk gate fails closed with a complete host record |
| 2026-10-04 | `b755a9e` + PR-25 working tree | local (`scripts/validate-hyperv.ps1`) | Windows 11 Business 26200.9457 AMD64, session 1, rustc 1.99.0 | `scripts/validate-hyperv.ps1` | environment unavailable | fails closed at the environment gate — `docker engine is not reachable` (the Windows-mode dockerd is not running); `result.json` records commit/host/rustc and `failed`, never a pass |
| 2026-10-04 | `b755a9e` + PR-25 working tree | local (`scripts/validate-windows-sandbox.ps1 -Vm`) | same Windows host | `scripts/validate-windows-sandbox.ps1 -Vm` | environment unavailable | fails closed at the 40 GiB disk gate (`D:\ has less than 40 GiB free after cargo clean`) before any test work; host identity recorded in `result.json` |
| 2026-10-04 | `b755a9e` + PR-25 working tree | local (`scripts/validate-apple-container.sh`) | — | — | environment unavailable | no macOS arm64 host on this machine; `bash -n` clean, evidence contract identical in shape to the verified Kata job |
| 2026-10-05 | `b7f1ff2` + PR-25 working tree | local (`scripts/validate-apple-container.sh`, real run) | macOS 26.6.2 (25G83) arm64, Apple `container` CLI/server 1.5.0, rustc 1.99.0 | `scripts/validate-apple-container.sh` | environment unavailable | fails closed at the 40 GiB disk gate (`…/work has less than 40 GiB free after cargo clean`, ~33 GiB free) before any test work — environment gates (Darwin arm64, CLI, system `running`, rustc) all passed first; `result.json` records commit/host/rustc/CLI+system+builder and `failed` (`.local/apple-validation/20261004-191534-*/`); the run surfaced and this tree fixes two gate defects — exec bit missing on both `validate-*.sh` (`run:` fails on the self-hosted checkout) and a `system status` substring match that accepted the stopped message |
| 2026-10-05 | `b7f1ff2` + PR-25 working tree | local (the job's gated suite, same env vars) | same + guest kernel vmlinux-6.18.35-197-debug, digest-pinned distroless base | `MCP_WRIT_REQUIRE_APPLE_TESTS=1 MCP_WRIT_APPLE_TEST_ROOT=… MCP_WRIT_APPLE_EVIDENCE_DIR=… cargo test --locked --test apple_container_vm_e2e -- --nocapture` | pass | 10/10 executed, 0 ignored (47.2 s cold after a `container build`, 15.6 s warm); evidence verified per the job's own checks — 2 metrics sessions (vm first_response 1.17 s / memory 7.8 MiB; product 1.34 s / 10.2 MiB) with the required reports + audit, 4 lifecycle records; `container inspect`/`stats`/`ls` JSON contracts, `container-runtime-linux --uuid` manager, SIGINT and EOF teardown, and `--engine` refusal all hold on 1.5.0. Environment finding recorded in `docs/validation/apple-container.md`: a fresh app root needs a `system stop`+`start` before `content/blobs` exists. End-to-end `vm-tests-passed` still requires a host over the 40 GiB gate |
| 2026-10-06 | PR-28 working tree | local (`scripts/validate-wslc.ps1` environment gate + gated suite) | Windows 11 Pro 25H2 (26200.9457) x86-64, interactive session 1, WSL product 2.4.12.0, `wslc` absent, distros Ubuntu + docker-desktop | `scripts/validate-wslc.ps1` / `cargo test --locked --test wslc_container_e2e` | environment unavailable | fails closed before any test work — WSL 2.4.12.0 is below the documented 2.9.3 `wslc` floor and no `wslc` CLI is on PATH; `wsl --update` deliberately not run (would interrupt the live session, touch docker-desktop, disturb the pinned Kata kernel). Harness + job ship complete; the suite compiles on Linux (`cargo check --test wslc_container_e2e` clean, fixture probe builds a static musl x86-64 ELF and passes argv-mode smoke tests), skips correctly, and `MCP_WRIT_REQUIRE_WSLC_TESTS=1` turns the absence into a failure — see `docs/validation/wslc.md` |
| 2026-10-06 | PR-29 working tree | local (gated suite, direct cargo run — same host after WSL moved to 3.0.1.0) | Windows 11 25H2 (26200.9457) x86-64, interactive session, WSL product **3.0.1.0**, `wslc` client 3.0.1.0 resolved via `C:\Program Files\WSL\wslc.exe` (not on PATH), kernel 6.18.40.1-1, distros Ubuntu + docker-desktop | `cargo test --test wslc_container_e2e product:: cli::` + manual `plan`/`run-image --engine wslc` | pass | 4/4 product-path legs (`product.rs`) + 2/2 CLI-inventory legs executed on the live CLI through the install-dir resolver; `run-image` MCP round-trip, report identity (`engine=wslc`, `unit=container`, shared-session detail, guest report `received`, Landlock ABI v7 + seccomp verified in-guest), unwrapped-image refusal, external SIGINT teardown + unit reaping, `plan` diagnostics all hold — see `docs/validation/wslc.md` → *Product-path integration (PR-29)* |
| 2026-10-06 | PR-29 working tree + review remediation (bounded CLI probes, `system session run` warm-up, trait-routed `build`, wslc×non-container resolve refusal) | local (full gated suite, direct cargo run) | same host | `MCP_WRIT_REQUIRE_WSLC_TESTS=1 cargo test --locked --test wslc_container_e2e` | pass | **16/16 executed, 0 skipped** (~70 s): product legs, stdio contract/session, MRTR + wire stress, session model, virtiofs share semantics, network semantics, lifecycle (SIGINT teardown, CLI-death, launch-failure), storage layout, perf stats. Harness fix this run surfaced: interactive `Command::new("wslc")` spawns (9 sites) + one `run_cli` used the bare PATH name while the stock install exports no PATH — now routed through `wslc_prog()` like every other helper. Evidence: `target/wslc-evidence/run-pr29/` |
| 2026-10-06 | `a10b7bb` + PR-30 working tree (source hashes in result.json) | local (`scripts/validate-windows-isolation.ps1`) | Windows 11 Business 25H2 (26200.9457) x86-64, session 1, non-elevated, retail (`insider:false`), rustc 1.99.0, node v24.11.1 | `scripts/validate-windows-isolation.ps1` | pass — evaluation only | `winiso-tests-passed`; 10 probe legs recorded (`facts`/`contracts`/`attempts-host`/`ac-run`/`ac-run-net`/`ac-run-lpac`/`psec-spec`/`psec`/`ac-node`/`psec-node`), 12/12 `windows_isolation_e2e` (8 golden + 4 live), zero profile residue, `psec_enforced=true`; Node launch conditions preserved under both AppContainer and PSEC (`node -e` marker over stdio pipe, no grant needed on `Program Files`); verdicts — baseline unchanged, Win32 app isolation hold (API set absent), PSEC conditional (v1.0 enforced incl. egress dest/port deny, env not inherited), IsolationSession hold (activation-only, lab-gated), MXC hold/conditional; evidence `.local/winiso-validation/20261006-125656-48c07f26a0bb46a8a8185b9f3f601977/` — see `docs/validation/windows-isolation.md` |
| 2026-10-06 | PR-31 working tree (uncommitted) | local (manual product legs on the live CLI) | Windows 11 Pro 25H2 (26200.9457) x86-64, interactive session, non-elevated; PSEC probe: schema 1.x supported, minor 0, flags `0x3` | `cargo check` (linux+windows), `cargo clippy`, `mcp-writ run|plan --windows-mechanism psec`, AppContainer-default regression run | pass | live `run --windows-mechanism psec -- whoami.exe` created the child under a generated PSEC v1.0 env (suspended → Job → resumed); report records `native_windows_mechanism:"psec"`, fs/egress controls `verified`; env allow-list policy refused closed at policy-check (no fallback); `plan` `windows.mechanism` probe check passes and reports schema/flags; bogus value is a parse error; `--isolation windows-sandbox`/`--image` combinations refuse; AppContainer default launch unchanged — see `docs/validation/windows-isolation.md` → *PR-31 product integration* |
| 2026-10-06 | PR-31 working tree (uncommitted) | local (full lib suite) | same host | `cargo test` (lib suite incl. 8 `warden::psec_spec` legs) | fail (pre-existing) | all tests passed except one — `container::engine::bounded_cli_output_times_out_a_wedged_cli` — which reproduces independent of this change: the Windows `timeout` stub exits immediately under redirected stdin (WSL/interop environment), not a PR-31 regression |
| 2026-10-09 | improvement-plan PR-07 working tree (uncommitted) | local (PR-07 verification) | WSL2 on Windows 11, kernel 6.18.40.1-microsoft-standard-WSL2, x86-64, rustc/cargo 1.99.0 | `cargo test --locked --test unotify_e2e` + `cargo test --locked --lib` + `plan_report_e2e`/`module_layering`/`docs_check` grouped suites + `cargo clippy --all-targets` + `cargo fmt --check` | pass | 13/13 `unotify_e2e` executed (0 skipped) on the live kernel — notification round-trip, `EACCES` deny + `sandbox.network_denied` audit, deny-all, dynamic grant allow + `sandbox.network_allowed` record, TTL expiry deny, dropped-listener `ENOSYS` fail-close, fail-closed audit gate, SIGTERM teardown, `--report` capability/layers, parse error leg, plus review-follow-up legs: `defaults.environment` restriction on the supervised child, `binary-hash` pin match/mismatch; 1954 lib + 24 plan/report + grouped suites green — see `docs/validation/linux-unotify.md` |
| 2026-10-10 | improvement-plan PR-09 working tree (uncommitted) | local (PR-09 verification) | WSL2 on Windows 11, kernel 6.18.40.1-microsoft-standard-WSL2, x86-64, rustc/cargo 1.99.0 | `cargo test --locked --lib` + `cargo clippy --locked --all-targets -- -D warnings` + `cargo fmt --check` + manual `namespaced-run` legs (`docs/validation/linux-namespaced-proxy.md`) | pass | 1958/1958 lib tests, clippy/fmt clean; manual legs on the live kernel — probe all-true, DNS intercept + TTL grants + resolved audit, TCP 200/reset + `sandbox.network_denied`, UDP per-datagram allow/deny, IPv6/ICMP/fragment drops, workload as pidns pid 1 with private `/proc`, `/run` tmpfs hiding host AF_UNIX sockets (pre-fix connect to dbus *succeeded* — fixed), `setns`/`unshare`/`io_uring_setup` EPERM, SIGKILL-supervisor pdeathsig cascade leaves no leaked processes, host fs/netns untouched; unexercised matrix items recorded as unverified |

## Pre-release checklist (main-plan publication)

The release owner works through this list before publishing the
main-plan scope; it does not wait for the VM-extension PRs.

- [ ] Required verification is green on the target commit: CI, Platform
  tests, Container tests, and Go runtime (via Release or manual
  dispatch), plus Linux tests and MCP server verification dispatched
  manually on the same commit. Record the run links in the evidence
  table above.
- [ ] Every `tests/*.rs` target has an owner row or a documented
  exclusion above, and no `MCP_WRIT_REQUIRE_*`-gated job ended with a
  required test left unexecuted.
- [ ] Distribution cross-check (pre-publication): the planned tag,
  repository URL, release version, and the asset names defined in
  [release.yml](../.github/workflows/release.yml) match what
  [README.md](../README.md), [README.ja.md](../README.ja.md),
  [Cargo.toml](../Cargo.toml) (`version`, `repository`), and
  [releasing.md](releasing.md) describe. Record the compared values in
  the table below.
- [ ] Distribution verification (post-publication): after the Release
  workflow publishes, confirm the actual release — the URL resolves,
  the tag matches the crate version, and all six archives plus
  `checksums-sha256.txt` exist with the documented contents (CLI,
  matching-arch Linux runner, LICENSE, `policy.example.kdl`, docs).
  Record the confirmation date and result in the table below. If
  anything is unpublished or unconfirmed, record that state — do not
  describe it as published and do not defer this check.

### Distribution confirmation record

One row per item and phase: pre-publication rows compare planned values
against the workflow definitions; post-publication rows compare the
claimed values against the actual release. `Result` records `match`,
`mismatch`, `unconfirmed`, or `unpublished` — never `published` without
post-publication verification.

| Date | Confirmer | Item | Claimed (document, value) | Verified against | Result |
|---|---|---|---|---|---|
| 2026-10-05 | PR-26 alignment | Repository URL | `https://github.com/strumbyte/mcp-writ` ([releasing.md](releasing.md), [migration.md](archive/migration.md), [README.md](../README.md), [Cargo.toml](../Cargo.toml) `repository`) | the URL resolves to a public `strumbyte/mcp-writ` repository | match |
| 2026-10-05 | PR-26 alignment | Planned tag / version | `v<version>` tag triggers Release ([releasing.md](releasing.md) step 3); crate version `0.1.0` | [release.yml](../.github/workflows/release.yml) `on.push.tags: v*`; Cargo.toml `version = "0.1.0"` → planned tag `v0.1.0` | match |
| 2026-10-07 | PR-32 working tree | Planned tag / version | `v<version>` tag triggers Release ([releasing.md](releasing.md) step 3); crate version `0.2.0` | Cargo.toml `version = "0.2.0"` + Cargo.lock `0.2.0` → planned tag `v0.2.0`; [release.yml](../.github/workflows/release.yml) `version-check` job fails the pipeline when tag and manifest disagree | match |
| 2026-10-10 | v0.3.0 release prep | Planned tag / version | `v<version>` tag triggers Release ([releasing.md](releasing.md) step 3); crate version `0.3.0` | working tree Cargo.toml `version = "0.3.0"` + Cargo.lock `0.3.0` → planned tag `v0.3.0` (uncommitted); [release.yml](../.github/workflows/release.yml) `version-check` job fails the pipeline when tag and manifest disagree | match |
| 2026-10-05 | PR-26 alignment | Asset names | six archives + `checksums-sha256.txt` + `runners-checksums-sha256.txt` ([releasing.md](releasing.md)) | [release.yml](../.github/workflows/release.yml) release step emits `mcp-writ-{darwin,linux,windows}-{amd64,arm64}.{tar.gz,zip}` plus both checksum files | match |
| 2026-10-05 | PR-26 alignment | Archive contents | CLI + matching-arch Linux runner + LICENSE + `policy.example.kdl` + docs; `windows-amd64` additionally `runners/mcp-secure-runner-windows-amd64.exe`, `mcp-secure-runner.exe`, `mcp-writ-wsb-relay.exe` ([releasing.md](releasing.md)) | `package()` in [release.yml](../.github/workflows/release.yml) copies exactly this set (plus README.md/README.ja.md) | match |
| 2026-10-05 | PR-26 alignment | Published release | releasing.md describes the procedure; nothing claims a published release | `github.com/strumbyte/mcp-writ` shows no releases and no tags | unpublished |

### Publication-condition status (2026-10-05)

Recorded state of the publication conditions defined in the
[implementation plan](archive/implementation-plan.ja.md); this is a status summary,
not a release operation. The pre-release checklist above remains unchecked
and belongs to the release owner.

**Main plan** (PR-01–13 deliverables, 3-OS native tests, existing container
tests, MCP both-version migration tests, plus the distribution cross-check):

- PR-01–13: every section is implemented and verified per its own record in
  the [PR guide](archive/implementation-pr-guide.ja.md); the optional PR-14
  (Confused Deputy generalization) is also implemented (`deputy` blocks,
  commit `7532390`) — nothing in PR-01–14 remains deferred.
- Native tests: local pass records exist for all three OS hosts (WSL2,
  macOS 26.6.2 arm64, Windows 11 25H2 x86-64) in the evidence table; the
  dispatched workflow legs on a release commit are the release owner's
  checklist item.
- Container tests: owned by the Container tests workflow; the local legs
  recorded `environment unavailable` (no Docker daemon) — an actual
  dispatched run on the target commit remains to be executed.
- MCP migration tests: `protocol_versions` and the v1/v2 policy
  round-trip coverage pass in the recorded suites.
- Distribution: pre-publication values match (rows above); the actual
  release is **unpublished** as of 2026-10-05 — no release may be described
  as published until the post-publication check records one.

**VM methods** (per the plan: the method's prototype + integration PRs and
the PR-25 per-method verification, with unconfirmed ranges named in the
support matrix):

| Method | Prototype / integration | PR-25 per-method job | Status |
|---|---|---|---|
| `kata` | PR-16 ✓ / PR-17 ✓ | `validate-kata.sh` → `vm-tests-passed` (2026-10-04, WSL2 pinned config) | conditions met on the recorded configuration |
| `apple-container` | PR-18 ✓ / PR-19 ✓ | gated suite 10/10 executed (2026-10-05); `validate-apple-container.sh` script-level run stopped at the 40 GiB disk gate | script-level `vm-tests-passed` pending — environment, not coverage |
| `hyperv` | PR-20 ✓ / PR-21 ✓ / PR-22 ✓ | `validate-hyperv.ps1` → environment unavailable (Windows-mode dockerd not running) | PR-25 job pending on a Windows-mode Docker host |
| `windows-sandbox` | PR-23 ✓ / PR-24 ✓ | `validate-windows-sandbox.ps1 -Vm` → environment unavailable (disk gate) | PR-25 job pending on the Sandbox-enabled host |
| `wslc` | PR-28 harness ✓ / PR-29 product path ✓ (`--engine wslc` wired; explicit selection only) | **full suite 16/16 executed** on the reference host (2026-10-06, WSL 3.0.1.0) — product legs, stdio/stress, session model, shares, network, lifecycle, storage, perf | **adopted, conditional** — explicit `--engine wslc` on Windows x86-64 with WSL ≥ 2.9.3; never auto-detected; `unit=container`, no VM boundary claimed (`docs/validation/wslc.md`) |

A pending PR-25 leg does not block the main-plan release — the VM methods
stage independently, and the support matrix above carries the unconfirmed
ranges.
