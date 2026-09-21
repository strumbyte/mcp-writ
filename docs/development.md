# Development and verification

## Development setup

Install Rust through rustup and use the toolchain in `rust-toolchain.toml`.
The integration fixtures also need Python 3.9 or later (`python3` on Unix,
`py -3` on Windows). The real MCP server fixtures additionally need Node.js,
`npm`, and `git` on `PATH`, plus network access for the first fetch.
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
| Linux | `ubuntu-latest` CI (unit/integration tests), `linux-tests` workflow (`ubuntu-latest` + `ubuntu-24.04-arm`, real AArch64 hardware), `go-runtime` workflow (sandboxed Go fixture) | Landlock ruleset/seccomp compile, spawn-path checks, sandboxed fixture execution incl. the sandboxed path-resolution e2e on aarch64 | Kernels without Landlock and ABI-difference coverage (V1–V4) are not CI targets; degraded enforcement is a `sandbox.allow_degraded` opt-in, not a tested configuration |
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
container runtime fixture uses Debian bookworm, so its GNU runner must be
built against a compatible glibc; the container workflow uses Ubuntu 22.04.
The fixture policy sets `sandbox allow_degraded=#true` so the tests also run
on kernels that cannot fully enforce the ruleset (Landlock ABI < V4, i.e.
kernels < 6.7 such as WSL2); on newer kernels enforcement is still
FullyEnforced. Kernel-level enforcement depth is covered separately by the
Linux tests workflow and the `warden::` unit tests.

The evidence e2e tests (`diagnostics_e2e`, `path_resolution_e2e`) skip when
a prerequisite is missing: no `rustc` for the `open_path_server` fixture, a
sandboxed spawn the host cannot perform, or unavailable symlink/junction
creation. To require them to execute — so a skipped test is never counted
as verification evidence — run with `MCP_WRIT_REQUIRE_E2E_TESTS=1`. The CI
and Platform tests workflows set it.

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

`MCP_WRIT_REQUIRE_SERVER_TESTS=1` turns prerequisite skips into failures —
the MCP server verification workflow sets it. On Windows the tests are
serialized: concurrent guards restore DACLs on the shared fixture trees when
they exit, which would race. The Windows runs also use two accommodations
recorded in [stdio-hardening-results.ja.md](stdio-hardening-results.ja.md):
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
# the server command.
.\scripts\check-server.ps1 -Policy host.kdl `
  -Call '{"name":"read_file","arguments":{"path":"C:/srv/data/marker.txt"}}' `
  node.exe server-filesystem.js C:\srv\data
```

Both print the JSON-RPC responses per stage and the last 20 audit-log lines,
then exit non-zero if any response lacks `result`, carries `error`, or a
call response reports `isError`.

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
| Release | A pushed `v*` tag | Runs all four verification workflows before building and publishing artifacts |

Release verification checks the same commit as the release tag.

See [Releasing](releasing.md) for repository setup and binary publication.
