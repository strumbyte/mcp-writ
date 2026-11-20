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
//! the structural `resident_bytes`. Counting is gated by `COUNTING`
//! so the timed passes run untracked on `System` — the production
//! allocator path — while a separate pass replays the same workload
//! untimed inside one counted window for the allocator readings:
//! `alloc_prep_bytes` is the net heap delta of the session view (its
//! `Policy` is moved in, not rebuilt, so the delta is the index +
//! per-tool rules), and `peak_alloc_bytes` is the run's own workload
//! high-water mark. Latency and allocation results are measured
//! independently, and every snapshot/report serialization stays
//! outside the counted window — nothing the harness allocates is
//! counted and then subtracted back out.

use std::alloc::{GlobalAlloc, Layout, System};
use std::hint::black_box;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Instant;

use mcp_writ::policy::opaque::OpaqueField;
use mcp_writ::policy::prepared::PreparedPolicy;
use mcp_writ::policy::{Policy, ToolNetworkPolicy, ToolPolicy};
use mcp_writ_bench::{Args, emit, json_str, measure_json, parse_args, quantiles};

const TOOL_COUNTS: [usize; 3] = [1, 100, 1000];

/// Outstanding bytes (alloc minus dealloc) and the high-water mark —
/// the resident/peak pair the M2 spec asks for without an OS-specific
/// RSS read, so the same formula runs on every bench host. Counting
/// runs only while `COUNTING` is set, so a counted window must be
/// self-contained: every block counted on alloc gets freed before the
/// window closes (one freed while untracked would leak into
/// `OUTSTANDING`; an untracked block freed or shrunk inside a window
/// would underflow it), and no measurement buffer crosses the boundary.
struct Counting;

static COUNTING: AtomicBool = AtomicBool::new(false);
static OUTSTANDING: AtomicU64 = AtomicU64::new(0);
static PEAK: AtomicU64 = AtomicU64::new(0);

impl Counting {
    /// `OUTSTANDING` += `size` with `PEAK` raised to the new mark —
    /// the bookkeeping for every successful grow (`alloc`,
    /// `alloc_zeroed`, `realloc` growth). Shrinks subtract from
    /// `OUTSTANDING` only: the mark is a high-water, never lowered.
    fn note_growth(size: u64) {
        let now = OUTSTANDING.fetch_add(size, Ordering::Relaxed) + size;
        PEAK.fetch_max(now, Ordering::Relaxed);
    }
}

// SAFETY: `Counting` upholds the `GlobalAlloc` contract by delegating
// every call to `System` — the allocator the default would have been —
// so blocks always round-trip alloc→realloc→dealloc through the same
// backend; the atomics add size bookkeeping only and never touch the
// memory.
#[allow(unsafe_code)]
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: forwards `layout` to `System` and returns its pointer
        // verbatim; the counting below reads `layout.size()` only,
        // never the memory `p` addresses.
        let p = unsafe { System.alloc(layout) };
        if !p.is_null() && COUNTING.load(Ordering::Relaxed) {
            Self::note_growth(layout.size() as u64);
        }
        p
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        // SAFETY: same pass-through as `alloc`, via the zeroed entry
        // point the default impl would have reached only through a
        // fresh `alloc` plus a manual memset.
        let p = unsafe { System.alloc_zeroed(layout) };
        if !p.is_null() && COUNTING.load(Ordering::Relaxed) {
            Self::note_growth(layout.size() as u64);
        }
        p
    }

    unsafe fn realloc(&self, p: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        // SAFETY: forwards the block, its layout, and `new_size` to
        // `System` verbatim, keeping the backend's in-place growth —
        // the default impl's alloc-copy-dealloc would double the
        // block's footprint mid-call and skew the measured marks.
        let q = unsafe { System.realloc(p, layout, new_size) };
        // Counted on success only: a failed realloc returns null with
        // `p`'s block still owned by the caller, so the books stay
        // unchanged — and a shrink never raises the high-water mark.
        if !q.is_null() && COUNTING.load(Ordering::Relaxed) {
            let old = layout.size() as u64;
            let new = new_size as u64;
            if new > old {
                Self::note_growth(new - old);
            } else {
                OUTSTANDING.fetch_sub(old - new, Ordering::Relaxed);
            }
        }
        q
    }

    unsafe fn dealloc(&self, p: *mut u8, layout: Layout) {
        if COUNTING.load(Ordering::Relaxed) {
            OUTSTANDING.fetch_sub(layout.size() as u64, Ordering::Relaxed);
        }
        // SAFETY: forwards the pointer and layout the runtime supplies
        // for a block this `alloc` returned straight to `System`; the
        // impl adds no memory access of its own.
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

/// The untimed replay the allocator readings come from: the same prep
/// iterations, session view, and request traffic the timed pass ran,
/// inside one self-contained counted window (see `Counting`). Returns
/// `(alloc_prep_bytes, peak_alloc_bytes)` — the session view's net
/// heap delta and this run's own workload high-water mark.
fn measure_allocations(
    doc: &Policy,
    requests: &[String],
    probe: &str,
    iterations: usize,
    warmup: usize,
) -> (u64, u64) {
    COUNTING.store(true, Ordering::Relaxed);
    let base = outstanding();
    // Reset the mark to this window's baseline so the reported peak is
    // the run's own, not the cumulative process maximum.
    PEAK.store(base, Ordering::Relaxed);

    // Preparation distribution replay: the transient clone + view of
    // each iteration, dropped inside the window.
    for _ in 0..iterations {
        let owned = black_box(doc.clone());
        let view = PreparedPolicy::new(owned);
        black_box(&view);
    }

    // The session view: `alloc_base` is taken after the document clone
    // so the net delta is only the structures `PreparedPolicy::new`
    // itself adds (index, per-tool rules) — the moved-in document's
    // heap predates the baseline.
    let owned = doc.clone();
    let alloc_base = outstanding();
    let prepared = PreparedPolicy::new(black_box(owned));
    let prep_alloc_bytes = outstanding() - alloc_base;

    // The request path the view serves — first call, warmup, then the
    // steady-state mix — replayed untimed so its transient heap lifts
    // the same high-water mark the timed pass produced.
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

    let run_peak = peak().saturating_sub(base);
    // `prepared`'s counted heap returns before the window closes so a
    // later run's baseline is not inflated by this run's view.
    drop(prepared);
    COUNTING.store(false, Ordering::Relaxed);
    (prep_alloc_bytes, run_peak)
}

fn run_count(tools: usize, iterations: usize, warmup: usize) -> (String, u64) {
    // Inputs exist before either pass — a session preps a policy it
    // already owns, and the mix is the request workload's own input.
    let doc = policy(tools);
    let requests = request_mix(tools, iterations);
    let probe = call_url(0, "tool_0");

    // ── latency pass: counting stays off, so every timed window pays
    // only `System` — the allocator path production runs. ──

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

    // The session view the request timings run against — prepped once,
    // kept resident for the whole pass.
    let prepared = PreparedPolicy::new(black_box(doc.clone()));
    let estimated_resident = prepared.estimated_resident_bytes();
    let prep_measure = measure_json("policy");

    // First request on the fresh view (cold): an independent probe —
    // the opaque+net class at every count — so a single-iteration run
    // never indexes into the measured mix. Then warmup, then the
    // steady-state distribution — the same mix every pass.
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

    // ── allocation pass: the same workload replayed untimed inside
    // one self-contained counted window. The measure snapshots and
    // the report string below stay untracked, so no serialization
    // buffer — transient or retained — ever enters the accounting. ──
    let (prep_alloc_bytes, run_peak) =
        measure_allocations(&doc, &requests, &probe, iterations, warmup);

    (
        format!(
            "{{\"tools\":{tools},\"opaque_tools\":{},\
             \"prep_ns\":{},\"estimated_resident_bytes\":{estimated_resident},\"alloc_prep_bytes\":{prep_alloc_bytes},\"peak_alloc_bytes\":{run_peak},\
             \"first_request_ns\":{first_request_ns},\"request_ns\":{},\
             \"outcomes\":{{\"pass\":{pass},\"deny\":{deny}}},\
             \"measure_prep\":{prep_measure},\"measure_requests\":{request_measure}}}",
            tools.div_ceil(10),
            quantiles(&prep_ns).to_json(),
            quantiles(&request_ns).to_json(),
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
    } = parse_args("m2_policy", 20);
    if iterations == 0 {
        // An empty sample set would only fail inside `quantiles` —
        // reject it at the boundary, before any preparation runs.
        eprintln!("m2_policy: --iterations must be at least 1");
        std::process::exit(2);
    }

    let mut runs = Vec::with_capacity(TOOL_COUNTS.len());
    let mut global_peak = 0u64;
    for &tools in &TOOL_COUNTS {
        mcp_writ::measure::reset();
        let (run, run_peak) = run_count(tools, iterations, warmup);
        global_peak = global_peak.max(run_peak);
        runs.push(run);
    }

    let report = format!(
        "{{\"target\":\"m2_policy\",\"tool_counts\":{:?},\"seed\":{seed},\
         \"iterations\":{iterations},\"warmup\":{warmup},\
         \"os\":{},\"profile\":{},\"peak_alloc_bytes\":{global_peak},\
         \"note\":{},\"runs\":[{}]}}",
        TOOL_COUNTS,
        json_str(std::env::consts::OS),
        json_str(if cfg!(debug_assertions) {
            "debug"
        } else {
            "release"
        }),
        json_str(
            "prep_ns is PreparedPolicy::new per iteration; estimated_resident_bytes is the \
             capacity-based structural estimate, alloc_prep_bytes the allocator net delta; \
             each run's peak_alloc_bytes is its own workload high-water mark, taken in a \
             separate counted pass so timed windows and report serialization stay out of \
             the accounting (top-level: largest across counts); measure_requests proves \
             zero request-path rebuilds"
        ),
        runs.join(","),
    );
    emit(&out, &report).expect("write report");
}
