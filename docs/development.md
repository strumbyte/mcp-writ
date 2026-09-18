# Development and verification

## Development setup

Install Rust through rustup and use the toolchain in `rust-toolchain.toml`.
The documentation checks and integration fixtures also need Python 3.9 or later (`python3` on Unix, `py -3` on
Windows). Windows AppContainer tests need a normal user environment that can
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
[work plan](arm64-security-plan.ja.md) and [execution procedure](arm64-security-runbook.ja.md).

## Verification

Run these commands from a source checkout:

```sh
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
cargo doc --locked --no-deps
python3 scripts/check_docs.py
```

CI also treats rustdoc warnings as errors (`RUSTDOCFLAGS="-D warnings"`).
On Windows, run the documentation check with `py -3 scripts/check_docs.py`.
When modifying platform-specific code, run the relevant tests on that OS;
cross-target `cargo check` does not execute its sandbox implementation.

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

## Workflow responsibilities

Pull requests and ordinary branch pushes do not start verification workflows.

| Workflow | When it runs | Checks |
|---|---|---|
| CI | Manual runs, releases | Linux formatting, Clippy, rustdoc, unit and protocol/policy tests |
| Platform tests | Manual runs, releases | Windows/macOS Clippy and unit/protocol/policy tests |
| Container tests | Manual runs, releases | Docker E2E tests with missing prerequisites treated as failures |
| Go MCP runtime compatibility | Manual runs, releases | Direct and sandboxed Go fixture execution on Linux/Windows |
| Release | A pushed `v*` tag | Runs all four verification workflows before building and publishing artifacts |

Release verification checks the same commit as the release tag.

See [Releasing](releasing.md) for repository setup and binary publication.
