//! Deterministic adverse pipe behavior for the relay tests. Only this fixture
//! reads the test-mode policy; normal sessions still use mcp-secure-runner.
use std::io::{Read, Write};

fn main() {
    #[cfg(windows)]
    {
        #[link(name = "kernel32")]
        unsafe extern "system" {
            fn SetErrorMode(mode: u32) -> u32;
        }
        // Keep the deliberate abort leg unattended (no WER dialog).
        unsafe {
            SetErrorMode(0x0001 | 0x0002);
        }
    }
    if std::env::args().any(|a| a == "--linger") {
        loop {
            std::thread::sleep(std::time::Duration::from_secs(1));
        }
    }
    let policy = std::env::var("MCP_WRIT_POLICY_PATH").unwrap();
    let mode = std::fs::read_to_string(policy).unwrap();
    let rw = std::path::PathBuf::from(std::env::var("MCP_WRIT_REPORT_OUT").unwrap());
    std::fs::write(rw.join("child.pid"), std::process::id().to_string()).unwrap();
    match mode.trim() {
        "echo" => {
            std::io::copy(&mut std::io::stdin(), &mut std::io::stdout()).unwrap();
        }
        "flood" => {
            let bytes = [b'x'; 64 * 1024];
            for _ in 0..1024 {
                if std::io::stdout().write_all(&bytes).is_err() {
                    break;
                }
            }
        }
        "stderr" => {
            let bytes = [b'e'; 64 * 1024];
            for _ in 0..128 {
                std::io::stderr().write_all(&bytes).unwrap();
            }
            std::io::stdout().write_all(b"OK\n").unwrap();
        }
        "noinput" => {
            std::thread::sleep(std::time::Duration::from_secs(120));
        }
        "eof-hang" => {
            let mut child = std::process::Command::new(std::env::current_exe().unwrap())
                .arg("--linger")
                .spawn()
                .unwrap();
            std::fs::write(rw.join("descendant.pid"), child.id().to_string()).unwrap();
            let mut byte = [0];
            while std::io::stdin().read(&mut byte).unwrap_or(0) != 0 {}
            let _ = child.wait();
        }
        "crash" => std::process::abort(),
        _ => panic!("unknown transport test mode"),
    }
}
