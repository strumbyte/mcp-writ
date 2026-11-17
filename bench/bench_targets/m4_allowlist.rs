//! M4 allowlist baseline: `DynamicAllowList` churn — register/staged/
//! commit/drop, lookups, snapshots — plus the RF02 reproducer shape
//! (capacity-1 duplicate reservations across two staging tokens).
//!
//! The `dns.scan.entries` counter shows the full-set walks RF07's
//! indexed lookups remove; `dns.staged.scan.entries` shows the
//! capacity re-check rebuild RF07 replaces; `dns.lock.hold.ns` is the
//! critical-section time both changes shrink. The `rf02` block is the
//! stored reproducer input's outcome — the fix itself lands in RF02's
//! PR; RF00 records the input and the parent-side observations.

use std::hint::black_box;
use std::net::IpAddr;
use std::time::{Duration, Instant};

use mcp_writ::dnsgate::DynamicAllowList;
use mcp_writ::policy::{EgressProto, GrantQual};
use mcp_writ_bench::{Args, Rng, emit, json_str, measure_json, parse_args, quantiles};

const TCP_ANY: GrantQual = GrantQual::TCP_ANY;

fn addr(i: u64) -> IpAddr {
    IpAddr::from([
        10,
        ((i >> 16) & 0xff) as u8,
        ((i >> 8) & 0xff) as u8,
        (i & 0xff) as u8,
    ])
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

    let report = format!(
        "{{\"target\":\"m4_allowlist\",\"grants\":{grants},\"lookups\":{lookups},\
         \"staged_rounds\":{staged_rounds},\"iterations\":{iterations},\
         \"warmup\":{warmup},\"seed\":{seed},\"os\":{},\"profile\":{},\
         \"wall_ns\":{},\"rf02\":{rf02},\"measure\":{counters_last}}}",
        json_str(std::env::consts::OS),
        json_str(if cfg!(debug_assertions) {
            "debug"
        } else {
            "release"
        }),
        quantiles(&wall).to_json(),
    );
    emit(&out, &report).expect("write report");
}
