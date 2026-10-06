//! Real-machine validation of WSL Containers (`wslc`) as a Linux
//! container substrate (PR-28).
//!
//! WSLC is the WSL-team container runtime: `wslc.exe` drives Linux
//! containers inside per-user **session VMs** managed by `wslservice` +
//! `wslcsession.exe` user-mode processes. Per the PR-27 vocabulary it is
//! `engine=wslc, substrate=container, unit=container` — the shared
//! session VHD is plumbing, never a `unit=vm` claim. This suite measures
//! that substrate contract directly: it does not assume Docker
//! compatibility, and it never substitutes an ordinary `wsl.exe` distro
//! or a Docker daemon for the `wslc` session substrate.
//!
//! What is asserted vs recorded:
//!   - asserted: the capabilities the product's run contract needs
//!     (`--entrypoint`, `-e`, RO policy + RW report/audit/workspace
//!     mounts, `--no-healthcheck`, id/stop/rm, bidirectional non-TTY
//!     stdio, EOF, exit codes, signal delivery, `--network none` deny,
//!     guest-control enforcement in the session VM)
//!   - recorded: the session/identity model, `-p` publish reachability
//!     (the `run -i` contract never publishes ports), storage layout,
//!     and every CLI surface detail a documented-but-unverified flag
//!     relies on —
//!     a missing capability is never silently skipped, it lands in the
//!     session's `capability-map.json`/`*-semantics.json` evidence.
//!
//! Prerequisites (any missing → skip, or fail with
//! `MCP_WRIT_REQUIRE_WSLC_TESTS=1`; see `docs/validation/wslc.md`):
//!   - Windows x86-64 host (PR-28 validates one configuration first)
//!   - WSL product version ≥ 2.9.3 (the documented `wslc` floor;
//!     `src/container/windows_probe.rs::WSLC_MIN_WSL`) — the suite does
//!     NOT run `wsl --update`: it records the environment as found
//!   - `wslc` CLI on PATH answering `wslc --version`
//!   - `rustc` + `x86_64-unknown-linux-musl` for the probe/runner (the
//!     cargo test binary on this host is a Windows PE — guest binaries
//!     are always cross-compiled here)
//!   - network access for the digest-pinned `ubuntu:24.04` amd64 pull
//!
//! Owned-resource rule: the suite creates only `mcp-writ-wslc-*` images
//! and `mcp-writ-wslc-*` container names inside the *default* session,
//! and `mcp-writ-wslc-sess-*` dedicated sessions (explicit storage path,
//! fully test-owned). Cleanup removes exactly those — never
//! `wsl --shutdown`, never a session it did not name, never a blanket
//! image prune.
//!
//! Suite layout — this `main.rs` is only the crate root (cargo maps
//! `tests/wslc_container_e2e/main.rs` to the `wslc_container_e2e`
//! target). The shared harness lives in `support.rs`; the ten tests
//! live in `{cli,stdio,substrate,lifecycle}.rs` next to it.

// The repo-wide test helpers stay in `tests/common/mod.rs`; from this
// nested root they are reached by path.
#[path = "../common/mod.rs"]
mod common;
mod support;

mod cli;
mod lifecycle;
mod product;
mod stdio;
mod substrate;
