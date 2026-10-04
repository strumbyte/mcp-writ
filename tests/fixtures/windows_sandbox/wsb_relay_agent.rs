// The PR-23 harness exercises the shipped relay implementation.
mod owned_job;
mod relay_protocol;
#[path = "../../../src/container/backends/windows_sandbox/agent.rs"]
mod agent;
fn main() { agent::main(); }
