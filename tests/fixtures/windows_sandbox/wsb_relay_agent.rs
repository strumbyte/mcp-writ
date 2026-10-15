// The PR-23 harness exercises the shipped relay implementation.
#[path = "../../../src/container/backends/windows_sandbox/agent.rs"]
mod agent;
mod container {
    pub(crate) mod engine;
}
mod fspriv;
mod owned_job;
mod relay_protocol;
mod trusted_path;
fn main() {
    agent::main();
}
