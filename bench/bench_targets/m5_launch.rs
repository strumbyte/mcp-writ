//! M5 launch baseline: process-spawn → exit latency of the product
//! binary itself (`mcp-writ --version` — parse + print + exit), the
//! floor every supervised launch must exceed. The full supervised
//! launch (`run` with a workload) is OS-specific — native Linux and
//! macOS numbers need those hosts and stay unmeasured from Windows.
//!
//! `--exe` overrides the binary path (the A/B driver points each side
//! at its own build output); default is `target/<profile>/mcp-writ`
//! beside the workspace root.

use std::hint::black_box;
use std::time::Instant;

use mcp_writ_bench::{Args, emit, json_str, parse_args, quantiles, target_dir};

fn main() {
    let Args {
        iterations,
        warmup,
        out,
        seed,
        extra,
        ..
    } = parse_args("m5_launch", 25);
    let exe = extra
        .iter()
        .position(|a| a == "--exe")
        .and_then(|i| extra.get(i + 1))
        .map(std::path::PathBuf::from)
        .or_else(|| {
            std::env::var("MCP_WRIT_EXE")
                .ok()
                .map(std::path::PathBuf::from)
        })
        .unwrap_or_else(|| target_dir().join(format!("mcp-writ{}", std::env::consts::EXE_SUFFIX)));
    if !exe.exists() {
        eprintln!(
            "product binary not found at {} — build it first (cargo build --release) or pass -- --exe PATH",
            exe.display()
        );
        std::process::exit(2);
    }

    let run_once = || -> u64 {
        let t = Instant::now();
        let status = std::process::Command::new(black_box(&exe))
            .arg("--version")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .expect("spawn mcp-writ");
        let ns = t.elapsed().as_nanos() as u64;
        assert!(status.success(), "mcp-writ --version exited {status}");
        ns
    };

    for _ in 0..warmup {
        black_box(run_once());
    }
    let mut wall = Vec::with_capacity(iterations);
    for _ in 0..iterations {
        wall.push(run_once());
    }

    let report = format!(
        "{{\"target\":\"m5_launch\",\"exe\":{},\"argv\":{},\
         \"iterations\":{iterations},\"warmup\":{warmup},\"seed\":{seed},\
         \"os\":{},\"profile\":{},\"wall_ns\":{},\
         \"note\":{},\"measure\":{}}}",
        json_str(&exe.display().to_string()),
        json_str("--version"),
        json_str(std::env::consts::OS),
        json_str(if cfg!(debug_assertions) {
            "debug"
        } else {
            "release"
        }),
        quantiles(&wall).to_json(),
        json_str("process spawn+CLI+exit only; supervised `run` launch needs per-OS hosts"),
        "{}",
    );
    emit(&out, &report).expect("write report");
}
