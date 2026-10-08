//! Shared harness for the plan/report e2e suite: binary path,
//! policy fixture, JSON member access, and the plan/run process
//! drivers used by every submodule.

use std::path::{Path, PathBuf};
use std::process::Stdio;

use tempfile::TempDir;
use tokio::process::Command;
use tokio::time::{Duration, timeout};

use crate::common;

pub const TIMEOUT_SECS: u64 = 20;

pub fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_mcp-writ")
}

/// Minimal policy that loads on every host OS (`fail_closed` off so no
/// `--audit-log` is required; no server blocks to bind). `plan` builds the
/// real Linux sandbox ruleset, so on unix the `defaults.syscalls` baseline
/// (with `execve`) is required for `ready` — a policy without it is not
/// runnable there.
pub fn write_policy(dir: &TempDir) -> PathBuf {
    let path = dir.path().join("policy.kdl");
    std::fs::write(&path, common::sandboxed_policy("", "")).expect("write policy");
    path
}

pub fn member<'j>(v: nojson::RawJsonValue<'j, 'j>, key: &str) -> nojson::RawJsonValue<'j, 'j> {
    v.to_member(key)
        .unwrap_or_else(|_| panic!("member '{key}' must exist"))
        .required()
        .unwrap_or_else(|_| panic!("member '{key}' must exist"))
}

pub async fn run_with_report(args: &[String]) -> std::process::Output {
    timeout(
        Duration::from_secs(TIMEOUT_SECS),
        Command::new(bin())
            .arg("run")
            .args(args)
            .env_remove("MCP_WRIT_SKIP_SANDBOX")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output(),
    )
    .await
    .expect("run timed out")
    .expect("run mcp-writ")
}

pub fn read_report(path: &Path) -> nojson::RawJson<'static> {
    let text = std::fs::read_to_string(path).expect("report file must exist");
    nojson::RawJson::parse(Box::leak(text.into_boxed_str())).expect("report must be valid JSON")
}
