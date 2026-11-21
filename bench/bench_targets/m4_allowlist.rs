//! M4 allowlist baseline: `DynamicAllowList` churn — register/staged/
//! commit/drop, lookups, snapshots — plus the RF02 reproducer shape
//! (capacity-1 duplicate reservations across two staging tokens).
//!
//! The `dns.scan.entries` counter shows the full-set walks RF07's
//! indexed lookups remove; `dns.staged.scan.entries` shows the
//! capacity re-check rebuild RF07 replaces; `dns.lock.hold.ns` is the
//! critical-section time both changes shrink; `dns.deadline.entries`
//! tracks the expiry queue's retained size under update churn. The
//! `rf02` block is the stored reproducer input's outcome — the fix
//! itself lands in RF02's PR; RF00 records the input and the
//! parent-side observations.
//!
//! `scenarios` is the RF07 axis matrix: live counts 0/100/1,000/
//! 16,384, distributed versus concentrated IPs, expired-grant
//! ratios, and repeated-update churn — each phase timed separately
//! with its own counter snapshot and a counting-allocator retained
//! reading. Note that a concentrated lookup's cost tracks the
//! *names on that one address*, not the table size — the scenario's
//! `names_per_ip` is that dependency.

use std::hint::black_box;
use std::net::IpAddr;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use mcp_writ::dnsgate::DynamicAllowList;
use mcp_writ::policy::{EgressProto, GrantQual};
use mcp_writ_bench::counting::{self, COUNTING, PEAK};
use mcp_writ_bench::{Args, Rng, emit, json_str, measure_json, parse_args, quantiles};

const TCP_ANY: GrantQual = GrantQual::TCP_ANY;

#[global_allocator]
static ALLOC: counting::Counting = counting::Counting;

fn addr(i: u64) -> IpAddr {
    IpAddr::from([
        10,
        ((i >> 16) & 0xff) as u8,
        ((i >> 8) & 0xff) as u8,
        (i & 0xff) as u8,
    ])
}

/// One cell of the RF07 axis matrix — a table shape plus the work
/// run against it. `expired` grants are minted with a near-now TTL
/// that lapses before measurement: they occupy the table's expiry
/// bookkeeping until a write reaps them, the shape update churn
/// meets on every call.
struct Scenario {
    /// Report label.
    name: &'static str,
    /// Live (unexpired at mint) grants.
    live: usize,
    /// Grants stacked on each live address — 1 is fully
    /// distributed; larger values concentrate the table so a hit
    /// scans this many names, not `live`.
    names_per_ip: usize,
    /// Additional grants minted already-expiring — the table's
    /// expired ratio is `expired / (live + expired)`.
    expired: usize,
    /// Re-registrations on existing keys — the update churn every
    /// stale deadline entry comes from.
    updates: usize,
    /// `is_allowed` probes run after fill and expired sleep.
    lookups: usize,
}

/// Staged keys per token in `staged_same_key` — the table must fit
/// `live + expired + STAGED_KEYS` reservations or refusals silently
/// shrink what the scenario measures.
const STAGED_KEYS: u64 = 64;

const SCENARIOS: &[Scenario] = &[
    Scenario {
        name: "live_0",
        live: 0,
        names_per_ip: 1,
        expired: 0,
        updates: 0,
        lookups: 4_000,
    },
    Scenario {
        name: "live_100",
        live: 100,
        names_per_ip: 1,
        expired: 0,
        updates: 0,
        lookups: 4_000,
    },
    Scenario {
        name: "live_1k",
        live: 1_000,
        names_per_ip: 1,
        expired: 0,
        updates: 0,
        lookups: 4_000,
    },
    Scenario {
        name: "live_16k",
        live: 16_384,
        names_per_ip: 1,
        expired: 0,
        updates: 0,
        lookups: 4_000,
    },
    // 64 names per address — a hit walks that address's whole name
    // set; the cost tracks `names_per_ip`, not 16,384.
    Scenario {
        name: "concentrated_16k",
        live: 16_384,
        names_per_ip: 64,
        expired: 0,
        updates: 0,
        lookups: 4_000,
    },
    Scenario {
        name: "expired_half_16k",
        live: 16_384,
        names_per_ip: 1,
        expired: 16_384,
        updates: 0,
        lookups: 4_000,
    },
    Scenario {
        name: "expired_most_16k",
        live: 1_638,
        names_per_ip: 1,
        expired: 14_746,
        updates: 0,
        lookups: 4_000,
    },
    // Refresh churn strands one deadline per update — the bounded
    // heap the gauge reports must not grow with `updates`.
    Scenario {
        name: "churn_1k",
        live: 1_000,
        names_per_ip: 1,
        expired: 0,
        updates: 10_000,
        lookups: 1_000,
    },
    Scenario {
        name: "churn_16k",
        live: 16_384,
        names_per_ip: 1,
        expired: 0,
        updates: 65_536,
        lookups: 1_000,
    },
    // The RF02 shape at scale: staged rounds sharing keys across
    // tokens, then committing.
    Scenario {
        name: "staged_same_key",
        live: 100,
        names_per_ip: 1,
        expired: 0,
        updates: 0,
        lookups: 1_000,
    },
];

/// The fill + expired-sleep + lookup + churn cycle for one scenario,
/// phase-timed and phase-instrumented. Returns the report fragment.
fn run_scenario(sc: &Scenario, iterations: usize, warmup: usize, seed: u64) -> String {
    let distinct_addrs = sc.live.div_ceil(sc.names_per_ip);
    // Keys are prebuilt outside the counted window so `retained_bytes`
    // is the table's own heap, not the input strings'.
    let keys: Vec<(String, IpAddr)> = (0..sc.live as u64)
        .map(|i| {
            (
                format!("n{}.example", i % sc.names_per_ip as u64),
                addr(i / sc.names_per_ip as u64),
            )
        })
        .collect();
    let expired_keys: Vec<(String, IpAddr)> = (0..sc.expired as u64)
        .map(|i| (format!("x{i}.example"), addr(distinct_addrs as u64 + i)))
        .collect();
    let churn_keys: Vec<(String, IpAddr)> = if sc.live == 0 || sc.updates == 0 {
        Vec::new()
    } else {
        (0..sc.updates as u64)
            .map(|i| keys[(i % sc.live as u64) as usize].clone())
            .collect()
    };

    let mut fill_ns = Vec::with_capacity(iterations);
    let mut lookup_ns = Vec::with_capacity(iterations);
    let mut churn_ns = Vec::with_capacity(iterations);
    let mut fill_measure = String::from("{}");
    let mut lookup_measure = String::from("{}");
    let mut churn_measure = String::from("{}");
    let mut staged_ok = 0usize;
    // The final pass is the allocator reading — counting stays off
    // during timed passes so every timed window pays only `System`,
    // the allocator path production runs (same discipline as m2).
    let mut mem_last = (0u64, 0u64);
    for it_no in 0..=(warmup + iterations) {
        let is_mem = it_no == warmup + iterations;
        let timed = it_no >= warmup && !is_mem;
        let base = if is_mem {
            COUNTING.store(true, Ordering::Relaxed);
            let b = counting::outstanding();
            PEAK.store(b, Ordering::Relaxed);
            b
        } else {
            0
        };
        mcp_writ::measure::reset();
        let t = Instant::now();
        // Headroom covers every reservation a scenario can mint —
        // `staged_same_key` stages STAGED_KEYS new keys on top of
        // its live fill.
        let al = DynamicAllowList::new(sc.live + sc.expired + STAGED_KEYS as usize + 8);
        for (n, a) in &keys {
            black_box(al.register(n, *a, &[TCP_ANY], Duration::from_secs(300)));
        }
        for (n, a) in &expired_keys {
            // ~50ms TTL: minted live, lapsed by measurement time —
            // nothing reaps staged-expired grants but the writes
            // below, so the fill itself keeps them resident.
            black_box(al.register(n, *a, &[TCP_ANY], Duration::from_millis(50)));
        }
        if timed {
            fill_ns.push(t.elapsed().as_nanos() as u64);
            fill_measure = measure_json("dns.");
        }
        if sc.expired > 0 {
            std::thread::sleep(Duration::from_millis(100));
        }

        // Lookups — hits concentrate on the live domain; expired
        // addresses scan their dead names then deny.
        let mut rng = Rng::new(seed + it_no as u64);
        let domain = ((distinct_addrs + sc.expired) as u64).max(1) * 2;
        mcp_writ::measure::reset();
        let t = Instant::now();
        let mut hits = 0usize;
        for _ in 0..sc.lookups {
            let i = rng.next_u64() % domain;
            if black_box(al.is_allowed(black_box(&addr(i)), EgressProto::Tcp, 443)) {
                hits += 1;
            }
        }
        if timed {
            lookup_ns.push(t.elapsed().as_nanos() as u64);
            lookup_measure = measure_json("dns.");
        }
        black_box(hits);

        // Update churn — every refresh strands a stale deadline; the
        // gauge must stay proportional to live count, not updates.
        if sc.updates > 0 {
            mcp_writ::measure::reset();
            let t = Instant::now();
            let mut ok = 0usize;
            for (n, a) in &churn_keys {
                if black_box(al.register(n, *a, &[TCP_ANY], Duration::from_secs(300))) {
                    ok += 1;
                }
            }
            if timed {
                churn_ns.push(t.elapsed().as_nanos() as u64);
                churn_measure = measure_json("dns.");
            }
            black_box(ok);
        }

        // The staged axis: two tokens sharing each key — RF02's
        // reservation sharing under load.
        if sc.name == "staged_same_key" {
            mcp_writ::measure::reset();
            let t = Instant::now();
            let s1 = al.begin_staging();
            let s2 = al.begin_staging();
            let mut s1_ok = 0u64;
            let mut s2_ok = 0u64;
            for i in 0..STAGED_KEYS {
                let n = format!("st{i}.example");
                let a = addr(40_000 + i);
                if al.register_staged(s1, &n, a, &[TCP_ANY], Duration::from_secs(300)) {
                    s1_ok += 1;
                }
                if al.register_staged(s2, &n, a, &[TCP_ANY], Duration::from_secs(300)) {
                    s2_ok += 1;
                }
            }
            al.commit_staged(s1);
            al.drop_staged(s2);
            // A refused reservation would silently shrink the
            // measured set — the scenario only means what it says
            // when both tokens staged every key.
            assert_eq!(
                (s1_ok, s2_ok),
                (STAGED_KEYS, STAGED_KEYS),
                "staged_same_key reservations refused — capacity under-provisioned"
            );
            staged_ok += (s1_ok + s2_ok) as usize;
            if timed {
                churn_ns.push(t.elapsed().as_nanos() as u64);
                churn_measure = measure_json("dns.");
            }
        }

        if is_mem {
            // Retained table bytes and the high-water mark including
            // expired entries + the deadline heap.
            mem_last = (
                counting::outstanding() - base,
                counting::peak().saturating_sub(base),
            );
        }
        drop(al);
        if is_mem {
            COUNTING.store(false, Ordering::Relaxed);
        }
    }
    black_box(staged_ok);
    let (retained, peak) = mem_last;
    format!(
        "{{\"name\":{},\"live\":{},\"names_per_ip\":{},\"expired\":{},\
         \"updates\":{},\"lookups\":{},\"fill_ns\":{},\"lookup_ns\":{},\
         \"churn_ns\":{},\"retained_bytes\":{},\"peak_bytes\":{},\
         \"fill_measure\":{},\"lookup_measure\":{},\"churn_measure\":{}}}",
        json_str(sc.name),
        sc.live,
        sc.names_per_ip,
        sc.expired,
        sc.updates,
        sc.lookups,
        quantiles(&fill_ns).to_json(),
        quantiles(&lookup_ns).to_json(),
        if churn_ns.is_empty() {
            "{\"count\":0}".to_string()
        } else {
            quantiles(&churn_ns).to_json()
        },
        retained,
        peak,
        fill_measure,
        lookup_measure,
        churn_measure,
    )
}

fn main() {
    let Args {
        iterations,
        warmup,
        out,
        seed,
        extra,
        ..
    } = parse_args("m4_allowlist", 5);
    let mut grants = 2_000usize;
    let mut lookups = 4_000usize;
    let mut staged_rounds = 400usize;
    let mut it = extra.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--grants" => grants = it.next().and_then(|v| v.parse().ok()).unwrap_or(grants),
            "--lookups" => lookups = it.next().and_then(|v| v.parse().ok()).unwrap_or(lookups),
            "--staged-rounds" => {
                staged_rounds = it
                    .next()
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(staged_rounds)
            }
            other => {
                eprintln!("m4_allowlist: unknown target argument {other}");
                std::process::exit(2);
            }
        }
    }
    // The lookup stage samples `rng % domain` — an empty grant/staged
    // domain would divide by zero, so require a nonzero table whenever
    // lookups are requested.
    let domain = (grants + staged_rounds * 8) as u64 * 2;
    if lookups > 0 {
        assert!(
            domain > 0,
            "m4_allowlist: --lookups needs nonzero --grants or --staged-rounds"
        );
    }

    // --- RF02 reproducer: capacity 2 with one live grant, two staging
    // tokens holding the same key — headroom exists for the shared key
    // (a distinct third key would still overflow), so a refusal can
    // only come from counting the same staged key once per token. The
    // report stores inputs + outcomes; the verdict lives in RF02's PR.
    let rf02 = {
        let al = DynamicAllowList::new(2);
        let live = IpAddr::from([192, 0, 2, 1]);
        let staged_addr = IpAddr::from([192, 0, 2, 2]);
        assert!(al.register("live.example", live, &[TCP_ANY], Duration::from_secs(60)));
        let s1 = al.begin_staging();
        let s2 = al.begin_staging();
        let r1 = al.register_staged(
            s1,
            "x.example",
            staged_addr,
            &[TCP_ANY],
            Duration::from_secs(60),
        );
        let r2 = al.register_staged(
            s2,
            "x.example",
            staged_addr,
            &[TCP_ANY],
            Duration::from_secs(60),
        );
        let live_before = al.live_len();
        al.commit_staged(s1);
        let live_after_c1 = al.live_len();
        let allowed_after_c1 = al.is_allowed(&staged_addr, EgressProto::Tcp, 443);
        al.drop_staged(s2);
        let live_after_drop = al.live_len();
        let allowed_after_drop = al.is_allowed(&staged_addr, EgressProto::Tcp, 443);
        format!(
            "{{\"capacity\":2,\"staged_same_key\":[{r1},{r2}],\
             \"live_before_commit\":{live_before},\"live_after_commit1\":{live_after_c1},\
             \"allowed_after_commit1\":{allowed_after_c1},\
             \"live_after_drop2\":{live_after_drop},\"allowed_after_drop2\":{allowed_after_drop}}}"
        )
    };

    // --- Main workload: a full-ish table, staged churn, lookups.
    mcp_writ::measure::reset();
    let mut wall = Vec::with_capacity(iterations);
    let mut counters_last = String::new();
    for it_no in 0..(warmup + iterations) {
        let timed = it_no >= warmup;
        let t = Instant::now();
        let al = DynamicAllowList::new(grants + staged_rounds * 8);
        let mut rng = Rng::new(seed);
        // Fill live grants.
        for i in 0..grants as u64 {
            black_box(al.register(
                black_box("h.example"),
                black_box(addr(i)),
                &[TCP_ANY],
                Duration::from_secs(300),
            ));
        }
        // Staged churn: register under a token, commit; every staged
        // insert re-walks all staged keys for the capacity check.
        let mut staged_ok = 0usize;
        for i in 0..staged_rounds as u64 {
            let s = al.begin_staging();
            for j in 0..8u64 {
                if al.register_staged(
                    s,
                    "s.example",
                    addr(grants as u64 + i * 8 + j),
                    &[TCP_ANY],
                    Duration::from_secs(300),
                ) {
                    staged_ok += 1;
                }
            }
            al.commit_staged(s);
        }
        // Lookups — mixed hits/misses via the seeded order.
        let mut hits = 0usize;
        for _ in 0..lookups {
            let i = rng.next_u64() % domain;
            if black_box(al.is_allowed(black_box(&addr(i)), EgressProto::Tcp, 443)) {
                hits += 1;
            }
        }
        black_box(al.names_for(&addr(0)));
        black_box(al.quals_for(&addr(0)));
        black_box(al.live_len());
        let snap = black_box(al.snapshot_json());
        assert!(!snap.is_empty());
        black_box(hits);
        black_box(staged_ok);
        if timed {
            wall.push(t.elapsed().as_nanos() as u64);
        }
        counters_last = measure_json("dns.");
    }

    // --- RF07 axis matrix: live counts, concentrated versus
    // distributed IPs, expired ratios, and update churn — one report
    // object per cell.
    let scenarios: Vec<String> = SCENARIOS
        .iter()
        .map(|sc| run_scenario(sc, iterations, warmup, seed))
        .collect();

    let report = format!(
        "{{\"target\":\"m4_allowlist\",\"grants\":{grants},\"lookups\":{lookups},\
         \"staged_rounds\":{staged_rounds},\"iterations\":{iterations},\
         \"warmup\":{warmup},\"seed\":{seed},\"os\":{},\"profile\":{},\
         \"wall_ns\":{},\"rf02\":{rf02},\"measure\":{counters_last},\
         \"scenarios\":[{}]}}",
        json_str(std::env::consts::OS),
        json_str(if cfg!(debug_assertions) {
            "debug"
        } else {
            "release"
        }),
        quantiles(&wall).to_json(),
        scenarios.join(","),
    );
    emit(&out, &report).expect("write report");
}
