//! M2 policy-prep baseline: for tool counts 1 / 100 / 1,000 the
//! report pairs the one-time `PreparedPolicy::new` cost — `prep_ns`
//! wall quantiles plus the resident bytes the view adds beyond the
//! document — with the request path it serves (first-call and
//! steady-state `check_request_prepared` quantiles).
//!
//! Two `measure` snapshots bracket the phases: `measure_prep` after
//! the preparation loop, `measure_requests` after the request loop.
//! `policy.prepare.calls` / `policy.opaque.matcher.builds` unchanged
//! between them is the "requests rebuild nothing" observation RF05a
//! must preserve.
//!
//! A counting global allocator adds a real allocator reading beside
//! the structural `resident_bytes`: `prep_alloc_bytes` is the net
//! heap delta of the session view (its `Policy` is moved in, not
//! rebuilt, so the delta is the index + per-tool rules), and
//! `peak_alloc_bytes` is the high-water mark across the whole run.

use std::alloc::{GlobalAlloc, Layout, System};
use std::hint::black_box;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use mcp_writ::policy::opaque::OpaqueField;
use mcp_writ::policy::prepared::PreparedPolicy;
use mcp_writ::policy::{Policy, ToolNetworkPolicy, ToolPolicy};
use mcp_writ_bench::{Args, emit, json_str, measure_json, parse_args, quantiles};

const TOOL_COUNTS: [usize; 3] = [1, 100, 1000];

/// Outstanding bytes (alloc minus dealloc) and the high-water mark —
/// the resident/peak pair the M2 spec asks for without an OS-specific
/// RSS read, so the same formula runs on every bench host.
struct Counting;

static OUTSTANDING: AtomicU64 = AtomicU64::new(0);
static PEAK: AtomicU64 = AtomicU64::new(0);

#[allow(unsafe_code)]
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let p = unsafe { System.alloc(layout) };
        if !p.is_null() {
            let now = OUTSTANDING.fetch_add(layout.size() as u64, Ordering::Relaxed)
                + layout.size() as u64;
            PEAK.fetch_max(now, Ordering::Relaxed);
        }
        p
    }

    unsafe fn dealloc(&self, p: *mut u8, layout: Layout) {
        OUTSTANDING.fetch_sub(layout.size() as u64, Ordering::Relaxed);
        unsafe { System.dealloc(p, layout) };
    }
}

#[global_allocator]
static ALLOC: Counting = Counting;

fn outstanding() -> u64 {
    OUTSTANDING.load(Ordering::Relaxed)
}

fn peak() -> u64 {
    PEAK.load(Ordering::Relaxed)
}

/// A policy of `tools` entries — every tenth is network-restricted and
/// declares two opaque fields (a bare member and a nested pointer), so
/// the prep-time matcher build and the request-time opaque walk scale
/// with the tool count the way a real policy's would; every `i % 10
/// == 3` carries a `read_only` side effect the prepared view parses
/// once. A network contract (not fs) is the restricted shape because
/// path-pattern resolution is host-dependent while a host allow-list
/// is not. One denied entry keeps the listed-deny half of admission
/// in the request mix.
fn policy(tools: usize) -> Policy {
    let mut p = Policy::default();
    // The default outbound posture is closed (`deny_all_others`), so
    // the global gate needs an explicit allow for the workload's one
    // destination — the same shape a session policy would carry.
    p.network.outbound.allowed = vec!["example.com".to_string()];
    for i in 0..tools {
        let mut t = ToolPolicy::named(format!("tool_{i}"), true);
        if i % 10 == 0 {
            t.network = Some(ToolNetworkPolicy {
                allowed_hosts: vec!["example.com".to_string()],
                allow_specified: true,
                ..Default::default()
            });
            t.opaque_fields = vec![
                OpaqueField::parse("note").unwrap(),
                OpaqueField::parse("/params/arguments/meta/extra").unwrap(),
            ];
        }
        if i % 10 == 3 {
            t.side_effect = Some("read_only".to_string());
        }
        p.tools.push(t);
    }
    p.tools.push(ToolPolicy::named("denied_tool", false));
    p
}

/// A `tools/call` for a network-restricted, opaque-declaring tool:
/// the URL clears the host allow-list and `note`/`meta.extra` ride on
/// the prepared `OpaqueMatcher` — without it the opaque members would
/// be refused as unrecognized arguments under the closed contract.
fn call_url(id: u64, tool: &str) -> String {
    format!(
        r#"{{"jsonrpc":"2.0","id":{id},"method":"tools/call","params":{{"name":"{tool}","arguments":{{"url":"https://example.com/f{id}","note":{{"free":["form",{id}]}},"meta":{{"extra":{{"k":{id}}}}}}}}}}}"#
    )
}

/// The same call for an unrestricted or `read_only` tool — `path` is
/// a recognized selector so nothing unclassified reaches the refusal.
fn call_path(id: u64, tool: &str) -> String {
    format!(
        r#"{{"jsonrpc":"2.0","id":{id},"method":"tools/call","params":{{"name":"{tool}","arguments":{{"path":"/workspace/f{id}.txt"}}}}}}"#
    )
}

/// The deterministic request mix: a listed deny, a not-found deny,
/// and index-hit calls that always target an opaque-declaring tool —
/// the same request class (URL + net contract + prepared matcher
/// descent) at every tool count, so the distributions compare like
/// for like instead of mixing in cheaper unrestricted calls at the
/// larger counts.
fn request_mix(tools: usize, count: usize) -> Vec<String> {
    let opaque_tools = tools.div_ceil(10);
    (0..count)
        .map(|i| match i % 8 {
            0 => call_path(i as u64, "denied_tool"),
            4 => call_path(i as u64, "missing_tool"),
            _ => call_url(i as u64, &format!("tool_{}", ((i * 7) % opaque_tools) * 10)),
        })
        .collect()
}

fn run_count(tools: usize, iterations: usize, warmup: usize) -> String {
    let doc = policy(tools);

    // Preparation distribution: the same finalized document prepped
    // `iterations` times. The `clone` materializes the input *before*
    // the timed window — a session preps a policy it already owns.
    let mut prep_ns = Vec::with_capacity(iterations);
    for _ in 0..iterations {
        let owned = black_box(doc.clone());
        let t = Instant::now();
        let view = PreparedPolicy::new(owned);
        prep_ns.push(t.elapsed().as_nanos() as u64);
        black_box(&view);
    }

    // The session view: prepped once, kept resident. `alloc_base` is
    // taken after the document clone so the net delta is only the
    // structures `PreparedPolicy::new` itself adds (index, per-tool
    // rules) — the moved-in document's heap predates the baseline.
    let owned = doc.clone();
    let alloc_base = outstanding();
    let prepared = PreparedPolicy::new(black_box(owned));
    let prep_alloc_bytes = outstanding() - alloc_base;
    let estimated_resident = prepared.estimated_resident_bytes();
    let prep_measure = measure_json("policy");

    // First request on the fresh view (cold): an independent probe —
    // the opaque+net class at every count — so a single-iteration run
    // never indexes into the measured mix. Then warmup, then the
    // steady-state distribution — the same mix every pass.
    let requests = request_mix(tools, iterations);
    let probe = call_url(0, "tool_0");
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
    let request_measure = measure_json("policy");

    format!(
        "{{\"tools\":{tools},\"opaque_tools\":{},\
         \"prep_ns\":{},\"estimated_resident_bytes\":{estimated_resident},\"alloc_prep_bytes\":{prep_alloc_bytes},\
         \"first_request_ns\":{first_request_ns},\"request_ns\":{},\
         \"outcomes\":{{\"pass\":{pass},\"deny\":{deny}}},\
         \"measure_prep\":{prep_measure},\"measure_requests\":{request_measure}}}",
        (tools + 9) / 10,
        quantiles(&prep_ns).to_json(),
        quantiles(&request_ns).to_json(),
    )
}

fn main() {
    let Args {
        iterations,
        warmup,
        out,
        seed,
        ..
    } = parse_args("m2_policy", 20);
    if iterations == 0 {
        // An empty sample set would only fail inside `quantiles` —
        // reject it at the boundary, before any preparation runs.
        eprintln!("m2_policy: --iterations must be at least 1");
        std::process::exit(2);
    }

    let mut runs = Vec::with_capacity(TOOL_COUNTS.len());
    for &tools in &TOOL_COUNTS {
        mcp_writ::measure::reset();
        runs.push(run_count(tools, iterations, warmup));
    }

    let report = format!(
        "{{\"target\":\"m2_policy\",\"tool_counts\":{:?},\"seed\":{seed},\
         \"iterations\":{iterations},\"warmup\":{warmup},\
         \"os\":{},\"profile\":{},\"peak_alloc_bytes\":{},\
         \"note\":{},\"runs\":[{}]}}",
        TOOL_COUNTS,
        json_str(std::env::consts::OS),
        json_str(if cfg!(debug_assertions) {
            "debug"
        } else {
            "release"
        }),
        peak(),
        json_str(
            "prep_ns is PreparedPolicy::new per iteration; estimated_resident_bytes is the \
             capacity-based structural estimate, alloc_prep_bytes the allocator net delta; \
             measure_requests proves zero request-path rebuilds"
        ),
        runs.join(","),
    );
    emit(&out, &report).expect("write report");
}
