//! A/A and A/B comparison driver: alternates two already-built
//! measurement binaries over the same arguments and reports both
//! sides' wall-clock distributions.
//!
//! Ordering alternates A,B,B,A per pair so slow drift lands on both
//! sides equally (matching the guide's alternating A→B / B→A pairs).
//! Point `--a` and `--b` at the same binary for an A/A variance check,
//! or at the parent-checkout and candidate builds for A/B. Each child
//! is run with the args after `--`; `--keep` additionally saves each
//! child's own JSON report as `<out-stem>.<side>.<seq>.json` beside
//! `--out` (or in the current directory when `--out` is unset), else
//! the child output is only captured for the report digest.

use std::hint::black_box;
use std::time::Instant;

use mcp_writ_bench::{Args, emit, json_str, parse_args, quantiles, sha256_hex};

struct RunOut {
    wall_ns: u64,
    code: Option<i32>,
    stdout_sha: String,
}

fn spawn_one(
    exe: &std::path::Path,
    args: &[String],
    keep_to: Option<&std::path::Path>,
) -> std::io::Result<RunOut> {
    let t = Instant::now();
    let out = std::process::Command::new(black_box(exe))
        .args(args)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output()
        .expect("spawn measurement binary");
    let wall_ns = t.elapsed().as_nanos() as u64;
    let stdout_sha = sha256_hex(&out.stdout);
    // `--keep` writes the child's report to its own sibling file so an
    // A/B keeps both sides' full JSON — stdout digests alone lose the
    // measure counters inside. A failed save fails the run: the
    // child's zero exit code alone does not make the requested
    // record complete.
    if let Some(path) = keep_to {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        if let Err(e) = std::fs::write(path, &out.stdout) {
            eprintln!("cannot save child report {}: {e}", path.display());
            return Err(e);
        }
    }
    Ok(RunOut {
        wall_ns,
        code: out.status.code(),
        stdout_sha,
    })
}

/// Child-report filename for `--keep`: `<out-stem>.<side>.<seq>.json`
/// — unique per comparison side and run, placed beside `--out` (or in
/// the current directory when `--out` is unset).
fn keep_path(out: &Option<std::path::PathBuf>, side: &str, seq: usize) -> std::path::PathBuf {
    let base = out
        .clone()
        .unwrap_or_else(|| std::path::PathBuf::from("ab_run.json"));
    let stem = base
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "ab_run".to_string());
    base.with_file_name(format!("{stem}.{side}.{seq:02}.json"))
}

fn main() {
    let Args {
        iterations,
        warmup,
        out,
        seed,
        extra,
        ..
    } = parse_args("ab_run", 10);
    // The first `--` inside `extra` separates driver options from the
    // child's argv — `--a`/`--b`/`--keep` are recognized only ahead of
    // it; everything after it forwards verbatim, later `--` tokens and
    // option-looking strings included (they are the child's own).
    let split = extra.iter().position(|a| a == "--").unwrap_or(extra.len());
    let (driver_args, child_rest) = extra.split_at(split);
    let get = |name: &str| -> Option<String> {
        driver_args
            .iter()
            .position(|a| a == name)
            .and_then(|i| driver_args.get(i + 1))
            .cloned()
    };
    let (a, b) = (get("--a"), get("--b"));
    let (Some(a), Some(b)) = (a, b) else {
        eprintln!(
            "usage: ab_run [--iterations N] [--warmup N] -- --a EXE --b EXE [--keep] [-- [child-args]]"
        );
        std::process::exit(2);
    };
    // Strip the recognized driver flags out of the forwarded set; a
    // stray non-option arg in the driver head still reaches the child,
    // ahead of the separator's tail — same order as on the command line.
    let mut keep = false;
    let mut child_args: Vec<String> = Vec::new();
    let mut skip = 0usize;
    for a in driver_args {
        if skip > 0 {
            skip -= 1;
            continue;
        }
        match a.as_str() {
            "--a" | "--b" => skip = 1,
            "--keep" => keep = true,
            _ => child_args.push(a.clone()),
        }
    }
    child_args.extend(child_rest.iter().skip(1).cloned());
    let a = std::path::PathBuf::from(a);
    let b = std::path::PathBuf::from(b);
    for exe in [&a, &b] {
        if !exe.exists() {
            eprintln!("binary not found: {}", exe.display());
            std::process::exit(2);
        }
    }

    for _ in 0..warmup {
        black_box(spawn_one(&a, &child_args, None).expect("warmup child"));
        black_box(spawn_one(&b, &child_args, None).expect("warmup child"));
    }
    // ABBA ordering per pair.
    let mut a_ns = Vec::with_capacity(iterations * 2);
    let mut b_ns = Vec::with_capacity(iterations * 2);
    let mut runs = Vec::with_capacity(iterations * 4);
    let mut seq = 0usize;
    for _ in 0..iterations {
        for (side, exe) in [("a", &a), ("b", &b), ("b", &b), ("a", &a)] {
            let keep_to = keep.then(|| keep_path(&out, side, seq));
            let r = spawn_one(exe, &child_args, keep_to.as_deref()).expect("run child");
            seq += 1;
            assert!(r.code == Some(0), "{} exited {:?}", exe.display(), r.code);
            if side == "a" {
                a_ns.push(r.wall_ns);
            } else {
                b_ns.push(r.wall_ns);
            }
            runs.push(format!(
                "{{\"side\":\"{side}\",\"wall_ns\":{},\"stdout_sha256\":{}}}",
                r.wall_ns,
                json_str(&r.stdout_sha)
            ));
        }
    }

    let a_q = quantiles(&a_ns);
    let b_q = quantiles(&b_ns);
    let ratio = b_q.p50_ns as f64 / a_q.p50_ns as f64;
    let same_binary = a.canonicalize().ok() == b.canonicalize().ok();
    let child_args_json = format!(
        "[{}]",
        child_args
            .iter()
            .map(|s| json_str(s))
            .collect::<Vec<_>>()
            .join(",")
    );
    let report = format!(
        "{{\"target\":\"ab_run\",\"mode\":{},\"a\":{},\"b\":{},\
         \"child_args\":{child_args_json},\"pairs\":{iterations},\"warmup\":{warmup},\"seed\":{seed},\
         \"os\":{},\"a_ns\":{},\"b_ns\":{},\"p50_ratio_b_over_a\":{ratio:.4},\
         \"runs\":[{}]}}",
        json_str(if same_binary { "aa" } else { "ab" }),
        json_str(&a.display().to_string()),
        json_str(&b.display().to_string()),
        json_str(std::env::consts::OS),
        a_q.to_json(),
        b_q.to_json(),
        runs.join(","),
    );
    emit(&out, &report).expect("write report");
}
