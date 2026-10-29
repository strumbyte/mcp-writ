//! Test helpers shared by integration suites. Split by topic:
//! `paths` (temp/audit paths and path spelling), `env` (skip gates
//! and evidence copying), `binaries` (compiled binary and fixture
//! argv), `spawn` (sandboxed spawns and policy snippets),
//! `fixture_layout` (real-server fixture layout), `kdl` (block-edit
//! helpers), and `mcp` (wire framing). Every helper is re-exported
//! flat so callers keep writing `common::helper(...)`.
#![allow(dead_code)]

mod binaries;
mod env;
mod fixture_layout;
mod kdl;
mod mcp;
mod paths;
mod spawn;

// Not every integration binary touches every topic — the re-exports
// are allowed to be unused in any one test crate.
#[allow(unused_imports)]
pub use binaries::*;
#[allow(unused_imports)]
pub use env::*;
#[allow(unused_imports)]
pub use fixture_layout::*;
#[allow(unused_imports)]
pub use kdl::*;
#[allow(unused_imports)]
pub use mcp::*;
#[allow(unused_imports)]
pub use paths::*;
#[allow(unused_imports)]
pub use spawn::*;
