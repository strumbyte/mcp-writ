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
| MCP server verification | [mcp-servers.yml](../.github/workflows/mcp-servers.yml) | dispatch / call | no — dispatch on the release commit | `ubuntu-24.04`, `macos-latest`, `windows-latest` | `MCP_WRIT_REQUIRE_SERVER_TESTS=1` |
| Go MCP runtime compatibility | [go-runtime.yml](../.github/workflows/go-runtime.yml) | dispatch / call | yes | `ubuntu-24.04`, `windows-latest` | none (fixture build + probe compare always run) |
| Release | [release.yml](../.github/workflows/release.yml) | pushed `v*` tag | — | packaging runners | — |

Release calls CI, Platform tests, Container tests, and Go runtime before
building artifacts. Linux tests and MCP server verification stay
manual-dispatch on the release commit (see [Releasing](releasing.md)),
and the real-server fixture versions stay pinned by their setup scripts.

## Test target ownership

Every `tests/*.rs` integration target appears below with its owning
workflow(s) or an explicit reason it is not run there. `tests/common/`
and `tests/fixtures/` are shared helpers, not targets. Non-`--test`
checks (fmt, clippy, `cargo doc`, `--lib --bins`, doc tests, the Go
fixture build, `check-server`) run as part of each workflow's job and are
not listed per target.

| Test target | Owning workflow(s) | Prerequisites / why there |
|---|---|---|
| `container_e2e` | Container tests | Docker daemon; `MCP_WRIT_REQUIRE_CONTAINER_TESTS` |
| `containerize_e2e` | Container tests | Docker daemon; `MCP_WRIT_REQUIRE_CONTAINER_TESTS` |
| `wrap_image_e2e` | Container tests | Docker daemon; `MCP_WRIT_REQUIRE_CONTAINER_TESTS` |
| `diagnostics_e2e` | CI, Platform tests, Linux tests | spawns the built binary; `MCP_WRIT_SKIP_SANDBOX` selects the unsandboxed vs sandboxed legs |
| `docs_check` | CI, Platform tests, Linux tests | repository docs hygiene (UTF-8/LF/links/anchors) |
| `environment_e2e` | CI, Platform tests, Linux tests | `python3`/`py` fixture; includes a real sandboxed spawn per OS; `MCP_WRIT_REQUIRE_E2E_TESTS` |
| `go_runtime_policy` | CI, Platform tests, Linux tests; also Go runtime | in-process policy/auditor checks; the Go runtime job repeats it next to the Go fixture checks |
| `inspector_arm64_p4` | CI, Platform tests | host-independent in-memory ELF analysis; see note below |
| `inspector_arm64_p5` | CI, Platform tests | host-independent in-memory ELF analysis; see note below |
| `inspector_macho_p6` | CI, Platform tests | host-independent in-memory Mach-O analysis; see note below |
| `integration` | CI, Platform tests, Linux tests | spawns the built binary unsandboxed (`MCP_WRIT_SKIP_SANDBOX=1`) |
| `kdl_policy_e2e` | CI, Platform tests, Linux tests | spawns the built binary unsandboxed (`MCP_WRIT_SKIP_SANDBOX=1`) |
| `manifest_fixtures` | CI, Platform tests | host-independent fixture parsing; see note below |
| `module_layering` | CI, Platform tests | host-independent `src/` scan; see note below |
| `path_resolution_e2e` | CI, Platform tests, Linux tests | rustc fixture build, sandboxed spawn, symlink/junction; `MCP_WRIT_REQUIRE_E2E_TESTS` |
| `protocol_versions` | CI, Platform tests, Linux tests | `python3`/`py` fixture servers against the in-process legislator client |
| `real_servers_e2e` | MCP server verification | pinned servers via `tests/fixtures/real_servers/setup.*`, Node + Python; `MCP_WRIT_REQUIRE_SERVER_TESTS` |
| `self_test` | CI, Platform tests, Linux tests | Linux leg compiles the rustc fixture (`python3`/`py` fallback) and runs Warden probes incl. on AArch64; non-Linux asserts the skipped verdict |
| `tool_enforcement_e2e` | CI, Platform tests, Linux tests | spawns the built binary unsandboxed (`MCP_WRIT_SKIP_SANDBOX=1`) |
| `workload_hash_e2e` | CI, Platform tests, Linux tests | rustc fixture build + `python3`/`py`; spawns the built binary; `MCP_WRIT_REQUIRE_E2E_TESTS` |

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
| `MCP_WRIT_REQUIRE_E2E_TESTS=1` | `skip_e2e_test` — used by `path_resolution_e2e`, `environment_e2e`, `workload_hash_e2e` | CI, Platform tests, Linux tests |
| `MCP_WRIT_REQUIRE_CONTAINER_TESTS=1` | `skip_container_test` — used by `container_e2e`, `containerize_e2e`, `wrap_image_e2e` | Container tests |
| `MCP_WRIT_REQUIRE_SERVER_TESTS=1` | `skip_server_test` — used by `real_servers_e2e` | MCP server verification |

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
