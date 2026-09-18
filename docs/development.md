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
