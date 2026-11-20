//! M2 schema-prep baseline — RF05b. For each schema shape the report
//! pairs `PreparedPolicy::new` (which now also builds each tool's
//! `PreparedSchema` — the parsed document plus its empty `$ref`/
//! `pattern` memos) with the request path it serves:
//! `check_request_prepared` first-call and steady-state quantiles
//! beside `check_request` on the bare `Policy` — the
//! parse-and-compile-every-request path the standalone entry still
//! runs and the evaluator used to run everywhere.
//!
//! `schema.*` counters bracket the phases: `schema.prepared.builds`
//! and `schema.parse.calls` at prep = the per-tool document count;
//! the request loop must add zero of either, and `schema.regex.builds`
//! = one per *distinct* pattern string, lazily on first reach.
//! `alloc_prep_bytes`/`peak_alloc_bytes` come from the shared
//! counting-allocator window (`mcp_writ_bench::counting`), and a
//! concurrent first-request burst on a fresh view measures the lazy
//! builders' dedup — N racing requests on one prepared document run
//! each memoized build once.

use std::hint::black_box;
use std::sync::atomic::Ordering;
use std::time::Instant;

use mcp_writ::policy::prepared::PreparedPolicy;
use mcp_writ::policy::{Policy, ToolPolicy};
use mcp_writ_bench::counting::{self, COUNTING, PEAK};
use mcp_writ_bench::{Args, emit, json_str, measure_json, parse_args, quantiles};

/// Tools per policy — every allowed entry carries the case's schema,
/// so prep builds one `PreparedSchema` each and the request mix can
/// round-robin real hits.
const TOOLS: usize = 8;
/// Threads racing a first request on one fresh view — the lazy-build
/// dedup measurement.
const BURST_THREADS: usize = 8;

/// A schema shape the RF05b spec asks M2 to compare: no schema, a
/// small object schema, an array `pattern`, a `local $ref` schema, a
/// branching schema, and an invalid one. `pass`/`deny` are the
/// `params.arguments` bodies the request mix alternates.
struct Case {
    name: &'static str,
    schema: Option<&'static str>,
    pass: &'static str,
    deny: &'static str,
}

const CASES: &[Case] = &[
    Case {
        name: "none",
        schema: None,
        pass: r#"{"q":"x","n":1}"#,
        deny: r#"{"q":"x"}"#,
    },
    Case {
        name: "small",
        schema: Some(
            r#"{"type":"object","properties":{"name":{"type":"string","minLength":1},"count":{"type":"integer","minimum":0}},"required":["name"]}"#,
        ),
        pass: r#"{"name":"x","count":3}"#,
        deny: r#"{"count":1}"#,
    },
    Case {
        name: "array_pattern",
        schema: Some(
            r#"{"type":"object","properties":{"tags":{"type":"array","items":{"type":"string","pattern":"^[a-z0-9_-]{1,32}$"},"minItems":1,"uniqueItems":true}},"required":["tags"]}"#,
        ),
        pass: r#"{"tags":["alpha_1","beta-2","gamma3"]}"#,
        deny: r#"{"tags":["BAD!"]}"#,
    },
    Case {
        name: "local_ref",
        schema: Some(
            r##"{"$defs":{"s":{"type":"string","minLength":1,"pattern":"^[a-z]+$"}},"type":"object","properties":{"a":{"$ref":"#/$defs/s"},"b":{"$ref":"#/$defs/s"},"c":{"$ref":"#/$defs/s"}},"required":["a"]}"##,
        ),
        pass: r#"{"a":"x","b":"y","c":"z"}"#,
        deny: r#"{"a":"X"}"#,
    },
    Case {
        name: "branches",
        schema: Some(
            r#"{"type":"object","properties":{"v":{"anyOf":[{"type":"string","pattern":"^[a-z]+$"},{"type":"integer","minimum":0},{"type":"array","items":{"type":"integer"},"minItems":1}]}},"required":["v"]}"#,
        ),
        pass: r#"{"v":"ok"}"#,
        deny: r#"{"v":-2}"#,
    },
    Case {
        name: "invalid",
        schema: Some("not json"),
        pass: r#"{"a":1}"#,
        deny: r#"{"a":1}"#,
    },
];

#[global_allocator]
static ALLOC: counting::Counting = counting::Counting;

/// `TOOLS` allowed entries all carrying the case schema, plus the
/// denied entry the mix uses for the listed-deny leg — the same
/// workload shape `m2_policy` measures around.
fn policy(schema: Option<&str>) -> Policy {
    let mut p = Policy::default();
    for i in 0..TOOLS {
        let mut t = ToolPolicy::named(format!("tool_{i}"), true);
        t.args_schema = schema.map(str::to_string);
        p.tools.push(t);
    }
    p.tools.push(ToolPolicy::named("denied_tool", false));
    p
}

fn call(id: u64, tool: &str, args: &str) -> String {
    format!(
        r#"{{"jsonrpc":"2.0","id":{id},"method":"tools/call","params":{{"name":"{tool}","arguments":{args}}}}}"#
    )
}

/// The deterministic request mix: a listed deny, schema denials, and
/// index-hit calls round-robin'd across the schema-carrying tools.
fn request_mix(case: &Case, count: usize) -> Vec<String> {
    (0..count)
        .map(|i| match i % 8 {
            0 => call(i as u64, "denied_tool", case.deny),
            4 => call(i as u64, &format!("tool_{}", i % TOOLS), case.deny),
            _ => call(i as u64, &format!("tool_{}", i % TOOLS), case.pass),
        })
        .collect()
}

/// `BURST_THREADS` racing a first request on a fresh view — the lazy
/// `$ref`/pattern builders dedupe under contention: after the burst
/// each interned entry ran its build once. Every worker parks on the
/// gate first; the extra barrier slot is this thread releasing them
/// together, so the timer starts at the release — thread spawn and
/// stragglers' startup stay outside `concurrent_first_ns`, and all
/// requests hit the uninitialized caches at once.
fn burst(prepared: &PreparedPolicy, probe: &str) -> u64 {
    let gate = std::sync::Barrier::new(BURST_THREADS + 1);
    let start = std::thread::scope(|s| {
        for _ in 0..BURST_THREADS {
            s.spawn(|| {
                gate.wait();
                let _ = black_box(mcp_writ::auditor::checker::check_request_prepared(
                    black_box(probe),
                    black_box(prepared),
                ));
            });
        }
        gate.wait();
        Instant::now()
    });
    start.elapsed().as_nanos() as u64
}

/// The untimed replay the allocator readings come from — same
/// discipline `m2_policy` documents: one self-contained counted
/// window, report buffers and measure snapshots outside it.
fn measure_allocations(
    doc: &Policy,
    requests: &[String],
    probe: &str,
    iterations: usize,
    warmup: usize,
) -> (u64, u64) {
    COUNTING.store(true, Ordering::Relaxed);
    let base = counting::outstanding();
    PEAK.store(base, Ordering::Relaxed);

    for _ in 0..iterations {
        let owned = black_box(doc.clone());
        let view = PreparedPolicy::new(owned);
        black_box(&view);
    }

    let owned = doc.clone();
    let alloc_base = counting::outstanding();
    let prepared = PreparedPolicy::new(black_box(owned));
    let prep_alloc_bytes = counting::outstanding() - alloc_base;

    let _ = black_box(mcp_writ::auditor::checker::check_request_prepared(
        black_box(probe),
        &prepared,
    ));
    for _ in 0..warmup {
        for line in requests {
            let _ = black_box(mcp_writ::auditor::checker::check_request_prepared(
                black_box(line),
                &prepared,
            ));
        }
    }
    for line in requests {
        let _ = black_box(mcp_writ::auditor::checker::check_request_prepared(
            black_box(line),
            &prepared,
        ));
    }

    let run_peak = counting::peak().saturating_sub(base);
    drop(prepared);
    COUNTING.store(false, Ordering::Relaxed);
    (prep_alloc_bytes, run_peak)
}

fn run_case(case: &Case, iterations: usize, warmup: usize) -> (String, u64) {
    let doc = policy(case.schema);
    let requests = request_mix(case, iterations);
    let probe = call(0, "tool_0", case.pass);

    // ── latency pass: counting off, only `System` in timed windows. ──

    let mut prep_ns = Vec::with_capacity(iterations);
    for _ in 0..iterations {
        let owned = black_box(doc.clone());
        let t = Instant::now();
        let view = PreparedPolicy::new(owned);
        prep_ns.push(t.elapsed().as_nanos() as u64);
        black_box(&view);
    }

    let prepared = PreparedPolicy::new(black_box(doc.clone()));
    let estimated_resident = prepared.estimated_resident_bytes();
    let prep_measure = measure_json("schema");

    // Cold first request on the fresh session view — the call that
    // fills the lazy `$ref`/pattern memos.
    let t = Instant::now();
    let first = mcp_writ::auditor::checker::check_request_prepared(black_box(&probe), &prepared);
    let first_request_ns = t.elapsed().as_nanos() as u64;
    black_box(&first);

    for _ in 0..warmup {
        for line in &requests {
            let _ = black_box(mcp_writ::auditor::checker::check_request_prepared(
                black_box(line),
                &prepared,
            ));
        }
    }

    let mut request_ns = Vec::with_capacity(iterations);
    let mut pass = 0usize;
    let mut deny = 0usize;
    for line in &requests {
        let t = Instant::now();
        match mcp_writ::auditor::checker::check_request_prepared(black_box(line), &prepared) {
            Ok(_) => pass += 1,
            Err(_) => deny += 1,
        }
        request_ns.push(t.elapsed().as_nanos() as u64);
    }
    let request_measure = measure_json("schema");

    // The bare-`Policy` path on the same requests — schema text
    // resolved and parsed per call, patterns compiled per reach: the
    // pre-RF05b per-request shape, still live for standalone checks.
    let mut bare_ns = Vec::with_capacity(iterations);
    for line in &requests {
        let t = Instant::now();
        let _ = black_box(mcp_writ::auditor::checker::check_request(
            black_box(line),
            black_box(&doc),
        ));
        bare_ns.push(t.elapsed().as_nanos() as u64);
    }
    let bare_measure = measure_json("schema");

    // Concurrent first requests on a *fresh* view: every lazy build
    // happens inside the burst, under contention — the counter delta
    // is the number of builds that actually ran.
    let burst_prepared = PreparedPolicy::new(black_box(doc.clone()));
    let concurrent_first_ns = burst(&burst_prepared, &probe);
    let burst_measure = measure_json("schema");

    // ── allocation pass: same workload, one counted window. ──
    let (prep_alloc_bytes, run_peak) =
        measure_allocations(&doc, &requests, &probe, iterations, warmup);

    (
        format!(
            "{{\"case\":{},\"tools\":{TOOLS},\"schema_bytes\":{},\
             \"prep_ns\":{},\"estimated_resident_bytes\":{estimated_resident},\"alloc_prep_bytes\":{prep_alloc_bytes},\"peak_alloc_bytes\":{run_peak},\
             \"first_request_ns\":{first_request_ns},\"request_ns\":{},\"bare_request_ns\":{},\"concurrent_first_ns\":{concurrent_first_ns},\
             \"outcomes\":{{\"pass\":{pass},\"deny\":{deny}}},\
             \"measure_prep\":{prep_measure},\"measure_requests\":{request_measure},\"measure_bare\":{bare_measure},\"measure_burst\":{burst_measure}}}",
            json_str(case.name),
            case.schema.map_or(0, str::len),
            quantiles(&prep_ns).to_json(),
            quantiles(&request_ns).to_json(),
            quantiles(&bare_ns).to_json(),
        ),
        run_peak,
    )
}

fn main() {
    let Args {
        iterations,
        warmup,
        out,
        seed,
        ..
    } = parse_args("m2_schema", 20);
    if iterations == 0 {
        eprintln!("m2_schema: --iterations must be at least 1");
        std::process::exit(2);
    }

    let mut runs = Vec::with_capacity(CASES.len());
    let mut global_peak = 0u64;
    for case in CASES {
        mcp_writ::measure::reset();
        let (run, run_peak) = run_case(case, iterations, warmup);
        global_peak = global_peak.max(run_peak);
        runs.push(run);
    }

    let report = format!(
        "{{\"target\":\"m2_schema\",\"cases\":{:?},\"tools_per_policy\":{TOOLS},\"seed\":{seed},\
         \"iterations\":{iterations},\"warmup\":{warmup},\
         \"os\":{},\"profile\":{},\"peak_alloc_bytes\":{global_peak},\
         \"note\":{},\"runs\":[{}]}}",
        CASES.iter().map(|c| c.name).collect::<Vec<_>>(),
        json_str(std::env::consts::OS),
        json_str(if cfg!(debug_assertions) {
            "debug"
        } else {
            "release"
        }),
        json_str(
            "prep_ns is PreparedPolicy::new per iteration (each tool's PreparedSchema included); \
             request_ns is check_request_prepared steady state, bare_request_ns the per-request \
             check_request path RF05b leaves for standalone use; concurrent_first_ns is \
             BURST_THREADS threads racing one fresh view's first call; measure_* snapshots \
             bracket the phases so schema.parse.calls/schema.prepared.builds flat across the \
             request loop and schema.regex.builds at one-per-distinct-pattern are the proof \
             requests rebuild nothing"
        ),
        runs.join(","),
    );
    emit(&out, &report).expect("write report");
}
