// The PR-23 harness exercises the shipped relay implementation.
#[path = "../../../src/container/backends/windows_sandbox/agent.rs"]
mod agent;
mod fspriv;
mod owned_job;
mod relay_protocol;
fn main() {
    agent::main();
}
