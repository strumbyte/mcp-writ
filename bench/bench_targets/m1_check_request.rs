//! M1 request-analysis baseline: feed `tests/fixtures/refactoring/
//! rf00/m1_requests.jsonl` through the Auditor's public check path —
//! `fuzz::drain_frames` for the bounded-read stage, then
//! `checker::check_request`, `checker::extract_fs_targets`, and
//! `checker::request_has_host_or_url` per line.
//!
//! The report's `verdicts` vector is the allow/deny contract both
//! sides of an A/B must reproduce verbatim; the `measure` block shows
//! the internal work each pass did (parse calls, duplicate-key walk,
//! schema parses, regex builds) so a refactoring can compare the work,
//! not just the wall time.

use std::hint::black_box;
use std::time::Instant;

use mcp_writ_bench::{
    Args, emit, fixture_root, json_str, measure_json, parse_args, quantiles, sha256_hex,
};

fn policy() -> mcp_writ::policy::Policy {
    let mut p = mcp_writ::policy::default_policy();
    let mut read_file = mcp_writ::policy::ToolPolicy::named("read_file", true);
    read_file.args_schema = Some(
        r#"{"type":"object","properties":{"path":{"type":"string","pattern":"^/"}},"required":["path"]}"#
            .to_string(),
    );
    let mut fetch = mcp_writ::policy::ToolPolicy::named("fetch", true);
    fetch.args_schema = Some(
        r#"{"type":"object","properties":{"url":{"type":"string","pattern":"^https://"}},"required":["url"]}"#
            .to_string(),
    );
    p.tools = vec![
        read_file,
        fetch,
        mcp_writ::policy::ToolPolicy::named("write_file", false),
    ];
    p
}

/// One pass over the fixture: framing drain, then the checker and
/// extractors per line. Returns the per-line verdict strings and the
/// outcome distribution — the fields an A/B diff must reproduce.
fn run_once(lines: &[String], policy: &mcp_writ::policy::Policy) -> (Vec<String>, [usize; 4]) {
    use mcp_writ::auditor::checker;
    let mut verdicts = Vec::with_capacity(lines.len() * 3);
    let mut pass = 0usize;
    let mut deny = 0usize;
    let mut fs_target_total = 0usize;
    let mut host_or_url = 0usize;
    for line in lines {
        match black_box(checker::check_request(black_box(line), policy)) {
            Ok(_) => {
                verdicts.push("pass".to_string());
                pass += 1;
            }
            Err(v) => {
                // Reason text is the comparison unit — truncate to the
                // stable prefix so sizes stay bounded (a long attack
                // field inside a reason is not the metric).
                let reason: String = v.reason.chars().take(48).collect();
                verdicts.push(format!("deny:{reason}"));
                deny += 1;
            }
        }
        let targets = black_box(checker::extract_fs_targets(black_box(line)));
        fs_target_total += targets.len();
        let has_host = black_box(checker::request_has_host_or_url(black_box(line)));
        host_or_url += usize::from(has_host);
    }
    (verdicts, [pass, deny, fs_target_total, host_or_url])
}

fn main() {
    let Args {
        iterations,
        warmup,
        fixture,
        out,
        seed,
        ..
    } = parse_args("m1_check_request", 20);
    let path = fixture.unwrap_or_else(|| fixture_root().join("rf00/m1_requests.jsonl"));
    let raw = match std::fs::read(&path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("cannot read fixture {}: {e}", path.display());
            std::process::exit(2);
        }
    };
    let text = String::from_utf8_lossy(&raw).into_owned();
    let lines: Vec<String> = text
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(str::to_string)
        .collect();
    let policy = policy();

    mcp_writ::measure::reset();
    // The framing drain runs inside every measured pass — the bounded
    // read the relay's C2S arm performs before `check_request` sees a
    // line is part of wall_ns, not a one-off prelude.
    let frame_lines = mcp_writ::fuzz::drain_frames(black_box(&raw), 1024 * 1024, 0).lines;

    // Warmup passes (untimed) then measured iterations.
    for _ in 0..warmup {
        black_box(mcp_writ::fuzz::drain_frames(
            black_box(&raw),
            1024 * 1024,
            0,
        ));
        black_box(run_once(&lines, &policy));
    }
    let mut wall_ns = Vec::with_capacity(iterations);
    let mut last = None;
    for _ in 0..iterations {
        let t = Instant::now();
        let st = mcp_writ::fuzz::drain_frames(black_box(&raw), 1024 * 1024, 0);
        assert_eq!(st.lines, frame_lines, "framing drain not deterministic");
        let r = run_once(&lines, &policy);
        wall_ns.push(t.elapsed().as_nanos() as u64);
        last = Some(r);
    }
    let (verdicts, [pass, deny, fs_targets, host_or_url]) = last.unwrap();

    let verdicts_json = verdicts
        .iter()
        .map(|v| json_str(v))
        .collect::<Vec<_>>()
        .join(",");
    let report = format!(
        "{{\"target\":\"m1_check_request\",\"fixture\":{},\"fixture_sha256\":{},\
         \"seed\":{seed},\"iterations\":{iterations},\"warmup\":{warmup},\
         \"os\":{},\"profile\":{},\
         \"wall_ns\":{},\"verdicts\":[{}],\
         \"outcomes\":{{\"pass\":{pass},\"deny\":{deny},\"fs_targets\":{fs_targets},\"host_or_url\":{host_or_url},\"framed_lines\":{frame_lines}}},\
         \"measure\":{}}}",
        json_str(&path.display().to_string()),
        json_str(&sha256_hex(&raw)),
        json_str(std::env::consts::OS),
        json_str(if cfg!(debug_assertions) {
            "debug"
        } else {
            "release"
        }),
        quantiles(&wall_ns).to_json(),
        verdicts_json,
        measure_json(""),
    );
    emit(&out, &report).expect("write report");
}
