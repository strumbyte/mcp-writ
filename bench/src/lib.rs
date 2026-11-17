//! Shared helpers for the RF00 measurement targets.
//!
//! Every binary under `bench_targets/` runs one fixed workload from
//! `tests/fixtures/refactoring/` against the instrumented product and
//! prints a JSON report (wall times, verdict distribution, `measure`
//! counter snapshot). The reports are the unit `ab_run` compares and
//! the records `.local/refactoring/RF00/<run>/` keeps — same fixture,
//! same flags, same output shape on parent and candidate.

use std::path::{Path, PathBuf};

/// `tests/fixtures/refactoring/` resolved from the package manifest —
/// the binaries may be invoked from any working directory.
pub fn fixture_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../tests/fixtures/refactoring")
}

/// `<target-dir>/<profile>` holding the product binaries this package's
/// `m5_launch` spawns. Any standard `cargo build`/`run` lands the bench
/// binary in that same directory, so `current_exe`'s parent is the
/// answer wherever the workspace root, the caller's CWD, or a relative
/// `CARGO_TARGET_DIR` happens to point — an explicit `--exe` /
/// `MCP_WRIT_EXE` at the call site still overrides. The env var stays
/// honored when the running binary cannot be located (a relative value
/// anchors on the workspace root, not the caller's CWD), and the
/// workspace `target/` is the last-resort default.
pub fn target_dir() -> PathBuf {
    if let Ok(exe) = std::env::current_exe() // nosemgrep: rust.lang.security.current-exe.current-exe
        && let Some(dir) = exe.parent()
    {
        return dir.to_path_buf();
    }
    let profile = if cfg!(debug_assertions) {
        "debug"
    } else {
        "release"
    };
    if let Some(dir) = std::env::var_os("CARGO_TARGET_DIR") {
        let dir = PathBuf::from(dir);
        let dir = if dir.is_absolute() {
            dir
        } else {
            Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join(dir)
        };
        return dir.join(profile);
    }
    Path::new(env!("CARGO_MANIFEST_DIR")).join(format!("../target/{profile}"))
}

/// sha256 hex of `data` — the input-hash field every report records.
pub fn sha256_hex(data: &[u8]) -> String {
    use sha2::Digest;
    let mut h = sha2::Sha256::new();
    h.update(data);
    let digest = h.finalize();
    let mut s = String::with_capacity(64);
    for b in digest {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// `--iterations N`, `--warmup N`, `--fixture FILE`, `--out FILE`,
/// `--seed N` — the shared flag set. `passthrough` collects anything
/// after `--` for targets that forward args.
pub struct Args {
    pub iterations: usize,
    pub warmup: usize,
    pub fixture: Option<PathBuf>,
    pub out: Option<PathBuf>,
    pub seed: u64,
    pub extra: Vec<String>,
}

pub fn parse_args(target: &str, default_iterations: usize) -> Args {
    let mut a = Args {
        iterations: default_iterations,
        warmup: 2,
        fixture: None,
        out: None,
        seed: 0x5eed_0001,
        extra: Vec::new(),
    };
    let mut it = std::env::args().skip(1); // nosemgrep: rust.lang.security.args.args
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--" => {
                a.extra = it.collect();
                break;
            }
            "--iterations" | "-n" => match it.next().and_then(|v| v.parse().ok()) {
                Some(n) => a.iterations = n,
                None => usage_fail(target, "--iterations needs an integer"),
            },
            "--warmup" => match it.next().and_then(|v| v.parse().ok()) {
                Some(n) => a.warmup = n,
                None => usage_fail(target, "--warmup needs an integer"),
            },
            "--fixture" => match it.next() {
                Some(v) => a.fixture = Some(PathBuf::from(v)),
                None => usage_fail(target, "--fixture needs a path"),
            },
            "--out" => match it.next() {
                Some(v) => a.out = Some(PathBuf::from(v)),
                None => usage_fail(target, "--out needs a path"),
            },
            "--seed" => match it.next().and_then(|v| v.parse().ok()) {
                Some(n) => a.seed = n,
                None => usage_fail(target, "--seed needs an integer"),
            },
            "--help" | "-h" => {
                eprintln!(
                    "usage: {target} [--iterations N] [--warmup N] [--fixture FILE] \
                     [--out FILE] [--seed N] [-- target-args]"
                );
                std::process::exit(0);
            }
            other => usage_fail(target, &format!("unknown argument {other}")),
        }
    }
    a
}

fn usage_fail(target: &str, msg: &str) -> ! {
    eprintln!("{target}: {msg}");
    std::process::exit(2);
}

/// JSON string literal with the escapes report fields need.
pub fn json_str(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// min/p50/p95/max/mean of a duration sample set, in ns.
#[derive(Debug, Clone)]
pub struct Quantiles {
    pub count: usize,
    pub min_ns: u64,
    pub p50_ns: u64,
    pub p95_ns: u64,
    pub max_ns: u64,
    pub mean_ns: u64,
}

pub fn quantiles(samples: &[u64]) -> Quantiles {
    assert!(!samples.is_empty(), "quantiles of an empty sample set");
    let mut s = samples.to_vec();
    s.sort_unstable();
    let at = |f: f64| s[((s.len() - 1) as f64 * f) as usize];
    let sum: u128 = s.iter().map(|v| *v as u128).sum();
    Quantiles {
        count: s.len(),
        min_ns: s[0],
        p50_ns: at(0.50),
        p95_ns: at(0.95),
        max_ns: s[s.len() - 1],
        mean_ns: (sum / s.len() as u128) as u64,
    }
}

impl Quantiles {
    pub fn to_json(&self) -> String {
        format!(
            "{{\"count\":{},\"min_ns\":{},\"p50_ns\":{},\"p95_ns\":{},\"max_ns\":{},\"mean_ns\":{}}}",
            self.count, self.min_ns, self.p50_ns, self.p95_ns, self.max_ns, self.mean_ns
        )
    }
}

/// `mcp_writ::measure::snapshot()` filtered to `prefix` and serialized —
/// a counter's meaning lives at its instrumented site, so the report
/// keeps the names verbatim.
pub fn measure_json(prefix: &str) -> String {
    let snap = mcp_writ::measure::snapshot();
    let mut out = String::from("{");
    let mut first = true;
    let push = |out: &mut String, first: &mut bool, name: &str, val: String| {
        if name.starts_with(prefix) {
            if !*first {
                out.push(',');
            }
            *first = false;
            out.push_str(&format!("{}:{}", json_str(name), val));
        }
    };
    for (name, v) in &snap.counters {
        push(&mut out, &mut first, name, v.to_string());
    }
    for (name, t) in &snap.timings {
        push(
            &mut out,
            &mut first,
            name,
            format!(
                "{{\"count\":{},\"sum_ns\":{},\"max_ns\":{}}}",
                t.count, t.sum_ns, t.max_ns
            ),
        );
    }
    for (name, v) in &snap.gauges {
        push(&mut out, &mut first, name, v.to_string());
    }
    out.push('}');
    out
}

/// Emit `report` to stdout and, when `--out` was given, the file —
/// the report is the artifact `.local/refactoring/RF00/<run>/` keeps.
/// A failed file write is an error, not a warning: callers propagate
/// it so the target exits nonzero rather than losing the record.
pub fn emit(out_path: &Option<PathBuf>, report: &str) -> std::io::Result<()> {
    println!("{report}");
    if let Some(path) = out_path {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        if let Err(e) = std::fs::write(path, format!("{report}\n")) {
            eprintln!("cannot write {}: {e}", path.display());
            return Err(e);
        }
    }
    Ok(())
}

/// A deterministic xorshift64 — the seeded-input generator for targets
/// that randomize work order; kept local so the dependency set stays
/// at the crates mcp-writ already builds.
pub struct Rng(u64);

impl Rng {
    pub fn new(seed: u64) -> Self {
        Self(seed | 1)
    }

    pub fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
}
