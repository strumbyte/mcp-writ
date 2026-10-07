# Development and verification

## Development setup

Install Rust through rustup and use the toolchain in `rust-toolchain.toml`.
The integration fixtures also need Python 3.9 or later (`python3` on Unix,
`py -3` on Windows). The real MCP server fixtures additionally need Python
3.10 or later (the `mcp` SDK's floor), plus Node.js, `npm`, and `git` on
`PATH`, and network access for the first fetch.
Windows AppContainer tests need a normal user environment that can
create and remove AppContainer profiles; a restricted agent sandbox may not
provide those permissions.

Source files use UTF-8 without BOM and LF line endings, as configured by
`.editorconfig` and `.gitattributes`. Preserve Japanese text when editing it.
If an encoding problem is suspected, make a backup before editing and compare
against the original source instead of reconstructing the text.

## Dependency and FFI policy

Pursue Pure Rust and minimize dependencies across the entire project, including
application logic, analysis, policy handling, runtime integration, and build and
test support. This policy is not limited to the disassembler.
Required functionality, correctness, security properties, platform support, and
performance are acceptance conditions. Do not reduce them to remove a dependency
or avoid FFI. The same conditions apply to an FFI-based replacement.

Prefer the standard library and existing dependencies, then consider a focused
Rust implementation or a minimal Pure Rust dependency. Remove unused dependencies,
redundant versions, and unnecessary features where verification shows they are
not needed. Review direct and transitive dependencies, target-specific features,
build and development dependencies, and native libraries and tools. A smaller
direct dependency count alone does not demonstrate a smaller dependency footprint.
Replacing a dependency with handwritten code must pass the same quality and
performance checks as any other implementation.

FFI is a last resort when the requirements cannot be met by the evaluated Rust
approaches. Record the concrete unmet requirement, alternatives and attempted
remedies, supporting measurements or tests, and evidence that the FFI option
meets the requirements. Convenience, a shorter implementation, or familiarity
with a library is not enough to justify FFI. A safe Rust wrapper or static linking
does not make a native implementation Pure Rust.

Apply this necessity check to existing OS bindings as well. Where required OS
functionality needs a native API boundary, retain the smallest binding that
provides it and keep the boundary inside the responsible platform module.
This does not justify native dependencies elsewhere. Preserve sandbox guarantees
when reducing bindings, and avoid adding raw FFI where an existing safe API suffices.

Before changing a dependency, record the affected behavior and performance
baseline on representative workloads and supported targets. Check latency,
throughput, memory use, and startup cost as applicable; also record build time
and artifact size. Set measurement conditions and a method for identifying noise
before comparison. Do not accept a measured performance regression or lost
functionality in exchange for fewer dependencies or Pure Rust. Missing evidence
means the change is not ready; lowering the requirements is not a completion path.

For the current dependency review and ARM64 work, see the
[work plan](archive/arm64-security-plan.ja.md) and [execution procedure](archive/arm64-security-runbook.ja.md).

## Verification

Run these commands from a source checkout:

```sh
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
cargo doc --locked --no-deps
```

Markdown encoding, local-link and anchor checks run as part of `cargo test`
(`tests/docs_check.rs`).

CI also treats rustdoc warnings as errors (`RUSTDOCFLAGS="-D warnings"`).
When modifying platform-specific code, run the relevant tests on that OS;
cross-target `cargo check` does not execute its sandbox implementation.

### Platform sandbox verification

The OS sandbox applies inside the spawned child, so `cargo test --lib` mostly
covers rule *construction*; real application is exercised by tests that spawn a
sandboxed child. Current coverage and known gaps:

| OS | Verified environment | What is exercised | Not covered |
|---|---|---|---|
| Linux | `ubuntu-latest` CI (unit/integration tests), `linux-tests` workflow (`ubuntu-latest` + `ubuntu-24.04-arm`, real AArch64 hardware), `go-runtime` workflow (sandboxed Go fixture) | Landlock ruleset/seccomp compile, spawn-path checks, sandboxed fixture execution incl. the sandboxed path-resolution and environment e2e on aarch64 | Kernels without Landlock and ABI-difference coverage (V1–V4) are not CI targets; `sandbox.allow_degraded` is an opt-in some integration fixtures enable so they still run on weaker kernels — those tests verify the guarded run, not the enforcement level, so degraded enforcement itself is not a tested configuration |
| macOS | `macos-latest` CI, local Apple Silicon (macOS 26.6.2) | `generate_sbpl` string tests plus real `sandbox-exec` spawns: write denial, private `TMPDIR`, loopback denial (`warden::` tests); all integration targets incl. the sandboxed path-resolution e2e on the local machine | SBPL is not a stable third-party contract ([Apple DTS](https://developer.apple.com/forums/thread/661939)); behavior on OS versions other than the current runner image and the recorded local version is unverified |
| Windows | `windows-latest` CI, `go-runtime` workflow (sandboxed Go fixture), local Windows 11 (build 26200) | AppContainer profile create/delete, capability and DACL grant paths, sandboxed spawn tests | Other Windows builds/editions; hosts where the user cannot create AppContainer profiles |

Required permissions: Windows tests need a user environment that can create and
remove AppContainer profiles (a restricted agent sandbox may not allow it). On
hosts without that permission, the Windows spawn tests log the spawn failure
and pass without exercising the sandboxed path — treat a green run there as
unverified for OS enforcement. macOS tests need `sandbox-exec` on `PATH`.
No test may widen its privileges to pass.

After a macOS upgrade, re-run `cargo test --locked --lib warden::` on the target
host and record the OS version on which `sandbox-exec` enforcement was last
verified; do not treat a green result from an older release as evidence for a
new one.

Container tests normally print a skip message when Docker or a fixture build
is unavailable. To require them to execute, use a Linux environment with a
running Docker daemon and run:

```sh
cargo build --locked --bins
MCP_WRIT_REQUIRE_CONTAINER_TESTS=1 cargo test --locked \
  --test container_e2e --test containerize_e2e --test wrap_image_e2e -- --nocapture
```

The container fixtures build and remove temporary test images. The full
container runtime fixture uses Debian trixie (glibc 2.41), so its GNU
runner must be built against a glibc no newer than the base image's; the
container workflow uses Ubuntu 22.04 for that reason. On a host whose
glibc is newer than the base's, `get_linux_runner` detects the runner's
`GLIBC_m.n` requirement (`required_glibc`) and falls back to the
in-Docker bookworm toolchain build.
The fixture policy carries no blanket `sandbox allow_degraded`: the
`copy_test_policy` helper in `container_e2e.rs` appends
`sandbox allow_degraded=#true` to its policy copy only when the
container engine's kernel — reported by `docker info` / `podman info`,
which can differ from the CLI host's kernel on a remote engine —
predates Landlock ABI V4 (< 6.7, e.g. WSL2); newer kernels run the
fixture unmodified — fully enforced only where Landlock ABI V4 is
actually available. A kernel version alone does not prove that:
Landlock can be compiled out (`CONFIG_SECURITY_LANDLOCK`), excluded
from the `lsm=` list, or filtered by a runtime seccomp profile, so this
gate expresses policy intent rather than a measured enforcement level.
Kernel-level enforcement depth is covered separately by the Linux
tests workflow and the `warden::` unit tests.

#### Disk hygiene for container tests

The container suites are disk-heavy: `cargo test` rebuilds `target/`
(several GiB), the fixtures `docker build`/`container build` real
images, and an in-Docker `cargo build --release` grows the engine's
builder cache. Check free space *before* a heavy build or test run —
`df -h /`; with less than 40 GiB free, run `cargo clean` first
(`target/` is fully regenerable).

Tagged test images are removed when a test finishes, but an
interrupted or failed run leaves them — and builder cache accumulates
on *every* run even on success (it is not tied to the tagged images;
check `docker system df`, not `docker images`). An interrupted run can
also orphan a `docker build`/`container build` CLI that keeps writing
detached — build invocations now `kill_on_drop`, but a killed test
process still detaches its children.

To reclaim test artifacts after a run — test-tagged images
(`mcp-writ-test-*`, `mcp-writ-ctrz-e2e-*`, `mcp-writ-kata-*`,
`mcp-writ-apple-*`, `mcp-writ-hyperv-*` — the Windows-daemon tags are
reached through `docker.exe` when it answers in Windows mode — plus
`mcp-writ-wslc-*` units/images through `wslc`/`wslc.exe` when the CLI
answers), leaked
`apple-e2e-*` units, the e2e's pinned
distroless base pull, orphaned test builds, and builder cache — run:

```sh
scripts/clean-test-container-artifacts.sh
```

It deletes only test-identifiable objects via tool-native commands
(`docker image rm`/`builder prune`, `container rm`/`container image rm`,
`wslc rm`/`wslc image rm` on `mcp-writ-wslc-*` only — it never runs
`wslc system session terminate`, `wsl --shutdown`, or touches a foreign
distro/session)
— never a broad `system prune -a`/`image prune`, and never store
directories by hand. A
Docker VM's disk file (`Docker.raw`) is sparse and may not shrink
after pruning — a Docker restart compacts it; anything beyond that is
a manual decision, not a test-cleanup step.

The `wslc` validation adds two owned scratch roots the same rule covers:
`MCP_WRIT_WSLC_TEST_ROOT` (scratch/session dirs — validate job's `work/`
else `target/wslc-tests/`) and `MCP_WRIT_WSLC_SESSION_ROOT` (dedicated
`wslc` session VHDs — `work/session-storage/`). Both are fully
test-owned and deleted by the validate run's verified-path cleanup;
`%LOCALAPPDATA%\wslc` (the *default* session's store) is measured but
never deleted — it belongs to the user.

`wslc_container_e2e` resolves the CLI with the product's own precedence —
`MCP_WRIT_WSLC_EXE`, then PATH, then the stock install dir
`C:\Program Files\WSL\wslc.exe` — so the suite runs on a stock install
that never exported PATH. The `product.rs` legs drive the real
`run-image --engine wslc`/`plan --engine wslc` product path (report
identity, entrypoint refusal, external SIGINT teardown); the other
modules measure the raw substrate contract.

The evidence e2e tests (`path_resolution_e2e`, `environment_e2e`,
`workload_hash_e2e`) skip when a prerequisite is missing: no `rustc` for
the `open_path_server` fixture, no interpreter, a sandboxed spawn the host
cannot perform, or unavailable symlink/junction creation. To require them
to execute — so a skipped test is never counted as verification evidence —
run with `MCP_WRIT_REQUIRE_E2E_TESTS=1`. The CI, Platform tests, and Linux
tests workflows set it.

### Real MCP server verification

`tests/real_servers_e2e.rs` exercises four pinned, real MCP servers end to
end — `@modelcontextprotocol/server-filesystem` and
`@modelcontextprotocol/server-memory` (Node), `mcp-server-time` and
`mcp-server-git` (Python) — rather than fixture binaries. Install them once
with the idempotent fetch scripts; they land in
`tests/fixtures/real_servers/` and are ignored by Git:

```sh
tests/fixtures/real_servers/setup.sh    # Linux/macOS
tests\fixtures\real_servers\setup.ps1   # Windows
```

Each server test runs six stages: live discovery, a dry-run handshake, a
sandboxed allowed call, an Auditor-layer denial, an OS-layer denial, and
tools-list hash pinning (correct and corrupted hashes). The pinned tool
counts and `tools-list-hash` values live in the test source. Run them with:

```sh
MCP_WRIT_REQUIRE_SERVER_TESTS=1 cargo test --locked --test real_servers_e2e
```

```powershell
$env:MCP_WRIT_REQUIRE_SERVER_TESTS = '1'
cargo test --locked --test real_servers_e2e
```

`MCP_WRIT_REQUIRE_SERVER_TESTS=1` turns prerequisite skips into failures —
the MCP server verification workflow sets it. On Windows the tests are
serialized: concurrent guards restore DACLs on the shared fixture trees when
they exit, which would race. The Windows runs also use two accommodations
recorded in [stdio-hardening-results.ja.md](archive/stdio-hardening-results.ja.md):
a fixture `win-realpath-stub.cjs` for Node's `fs.realpath` (AppContainer
returns `EPERM` for it on every path), and a pinned MinGit for
`mcp-server-git` (a `git.exe` under `Program Files` is neither grantable by
a non-admin nor covered by package ACEs, and its cwd resolution is denied).

`scripts/check-server.sh` and `scripts/check-server.ps1` verify one real
server against one policy without Cargo — a dry-run handshake plus
`tools/list`, the same exchange sandboxed, and an optional sandboxed
`tools/call`. They exist to sanity-check a server before writing or
deploying its policy:

```sh
scripts/check-server.sh --policy host.kdl \
  --call '{"name":"read_file","arguments":{"path":"/srv/data/marker.txt"}}' \
  -- node server-filesystem.js /srv/data
```

```powershell
# No `--` separator on PowerShell; everything past the named parameters is
# the server command. Windows launches preload `win-realpath-stub.cjs` and
# disable symlink resolution — the same startup shape as the real-server
# e2e tests and the MCP server verification workflow.
.\scripts\check-server.ps1 -Policy host.kdl `
  -Call '{"name":"read_file","arguments":{"path":"C:/srv/data/marker.txt"}}' `
  node.exe --preserve-symlinks-main --preserve-symlinks `
  --require (Resolve-Path tests\fixtures\real_servers\node\win-realpath-stub.cjs).Path `
  server-filesystem.js C:\srv\data
```

Both print the JSON-RPC responses per stage and the last 20 audit-log lines,
then exit non-zero if any response lacks `result`, carries `error`, or a
call response reports `isError`.

### VM isolation validation (manual)

Each adopted VM method has an owned validation job — a script plus a
`workflow_dispatch`-only leg of `vm-tests.yml` on a self-hosted
virtualization runner (see [manual-ci.md](validation/manual-ci.md) for
the shared evidence model and runner setup):

```sh
scripts/validate-kata.sh              # Linux + docker + kata runtime, /dev/kvm, /dev/vhost-vsock
scripts/validate-apple-container.sh   # macOS arm64 + Apple `container` system running
scripts/validate-hyperv.ps1           # Windows + Windows-mode dockerd (OSType=windows)
scripts/validate-windows-sandbox.ps1 -Vm
scripts/validate-wslc.ps1             # Windows x86-64 interactive + WSL >= 2.9.3 + wslc
```

The Windows native-mechanism job is not a VM method — it evaluates the
AppContainer baseline and the opt-in PSEC path (plus Insider-lab
candidate surfaces) and records a verdict per mechanism. It is the
`windows-isolation` leg of `vm-tests.yml` on `[self-hosted, windows,
winiso]`:

```powershell
scripts\validate-windows-isolation.ps1        # Windows x86-64 interactive + rustc
scripts\validate-windows-isolation.ps1 -Lab   # + Insider/preview lab legs (gated)
```

It runs the `windows_isolation_e2e` target — the golden contract layer
runs anywhere; the live legs need Windows + rustc: the `winiso_probe`
fixture legs plus the product legs (`mcp-writ run --windows-mechanism
appcontainer|psec` — launch report mechanism/`os.process`/`result`, audit
log, and the named-env-allowlist refusal under PSEC). Hosts lacking a
candidate record `unavailable`, not a pass. See
[windows-isolation.md](validation/windows-isolation.md).

Every job sets its `MCP_WRIT_REQUIRE_*_TESTS=1` gate, fails on a missing
prerequisite, an unexpected executed-test count, or missing evidence,
and leaves `.local/<method>-validation/<run>/` (kept evidence plus
`result.json`) for the workflow artifact upload. Record each run —
pass, fail, or `environment unavailable` — in
[test-matrix.md](test-matrix.md).

## Workflow responsibilities

Pull requests and ordinary branch pushes do not start verification workflows.

| Workflow | When it runs | Checks |
|---|---|---|
| CI | Manual runs, releases | Linux formatting, Clippy, rustdoc, unit and protocol/policy tests |
| Platform tests | Manual runs, releases | Windows/macOS Clippy and unit/protocol/policy tests |
| Container tests | Manual runs, releases | Docker E2E tests with missing prerequisites treated as failures |
| Go MCP runtime compatibility | Manual runs, releases | Direct and sandboxed Go fixture execution on Linux/Windows |
| Linux tests | Manual runs only | Linux unit/integration tests on `ubuntu-latest` and real AArch64 (`ubuntu-24.04-arm`), incl. Warden enforcement paths |
| MCP server verification | Manual runs only | Pinned real MCP servers on Ubuntu/macOS/Windows: six-stage e2e plus `check-server` against the filesystem server |
| VM tests | Manual dispatch only, self-hosted virtualization runners | Per-method `scripts/validate-*` jobs (Kata, Apple `container`, Hyper-V, Windows Sandbox, WSLC, Windows native mechanisms); evidence bundles uploaded as artifacts; never called by Release |
| Release | A pushed `v*` tag | Runs all four verification workflows before building and publishing artifacts |

Release verification checks the same commit as the release tag. Per-test
workflow ownership, the registration procedure for new tests, and the
execution-evidence format live in the [test matrix](test-matrix.md).

See [Releasing](releasing.md) for repository setup and binary publication.
