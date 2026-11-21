//! M3 audit-path baseline: sustained load on the product file-writer
//! (`AuditLogger::log_ordered` from `producers` concurrent tasks),
//! drain, then `reopen()` latency.
//!
//! The RF03 starvation signal is `audit.sync.start_delay.ns`: with the
//! event arm polled ahead of the periodic fsync arm under `biased`, a
//! busy event channel delays the arm past its scheduled 5 s tick —
//! the stat records `scheduled → actual` delay, so an overdue timer
//! is visible on its very first late fire. The load phase runs at
//! least `--busy-secs` (default 7 s) so the channel stays busy past
//! that deadline — producers keep sending past their `events` floor
//! until it elapses. After the drain a bounded wait confirms the
//! writer serviced every periodic deadline that elapsed during the
//! load — the metric's count is exactly the arm-execution count —
//! then `sync_start_delay_load_ns` snapshots the stat. When
//! confirmation does not arrive the field is `null` and
//! `sync_start_delay_load_complete` reports `false`, instead of
//! saving a figure that silently omits an unserviced tick. The
//! `measure` block's `audit.sync.start_delay.ns` still records the
//! whole-process figure.
//!
//! The Unix signal-driven trigger is not exercised on Windows;
//! `reopen()`'s writer-side path is shared code and runs on both
//! hosts, but the recorded OS marks which value is a product
//! measurement vs. smoke.
//!
//! RF06 adds `heartbeat_delay_ns`: a fixed number of audit-unrelated
//! tasks (`--heartbeats`, default 4) each loop a `--heartbeat-ms`
//! sleep (default 1 ms) on the same runtime while the producers run,
//! recording every wake's lateness. A synchronous `write`/`fsync`
//! executed inside a runtime task parks a worker for the I/O's whole
//! duration — audit-unrelated wakes then queue behind it and the
//! p95/p99 tail shows it; the dedicated writer thread takes that I/O
//! off the executor, so the same load should leave the probe's tail
//! flat. The `--every-event` sync-mode is the slow-sink condition:
//! every record pays a flush + `sync_all` on the writer's own
//! execution unit. `--spins N` (default 0) adds a sharper probe:
//! N audit-unrelated tasks looping `yield_now` and sampling every
//! 1024th yield-to-repoll gap — worker availability directly,
//! without the OS timer granularity the sleep probe bottoms out in.
//! On a small `--workers` pool with constant sync I/O, an occupied
//! worker shows up as the spin gap's tail stretching to the I/O's
//! own length; a dedicated writer thread keeps the gaps at
//! scheduling-jitter scale.

use std::hint::black_box;
use std::time::Instant;

use mcp_writ::audit_log::{
    Action, AuditEvent, AuditLogger, AuditSyncMode, EventType, Outcome, Severity,
};
use mcp_writ_bench::{Args, emit, json_str, measure_json, parse_args, quantiles};

fn event(i: usize, producer: usize) -> AuditEvent {
    let mut e = AuditEvent::new(
        uuid_v4(),
        EventType::ToolCallAllowed,
        Severity::Info,
        Outcome::Success,
        Action::Allowed,
    );
    e.target_tool = Some("read_file".to_string());
    e.details = Some(format!("rf00 sustained-load event p{producer} #{i}"));
    e
}

/// Correlation ids are noise for this workload — fresh v4 per event.
fn uuid_v4() -> uuid::Uuid {
    uuid::Uuid::new_v4()
}

fn reopen_marker(_: Option<String>) -> AuditEvent {
    AuditEvent::new(
        uuid_v4(),
        EventType::AuditReopened,
        Severity::Info,
        Outcome::Success,
        Action::Observed,
    )
}

/// p50/p95/p99/max over the heartbeat-delay samples — the shared
/// `quantiles` stops at p95 and the RF06 report needs the p99 tail.
fn delay_quantiles(samples: &[u64]) -> String {
    if samples.is_empty() {
        return "null".to_string();
    }
    let mut s = samples.to_vec();
    s.sort_unstable();
    let at = |f: f64| s[((s.len() - 1) as f64 * f) as usize];
    let sum: u128 = s.iter().map(|v| *v as u128).sum();
    format!(
        "{{\"count\":{},\"min_ns\":{},\"p50_ns\":{},\"p95_ns\":{},\
         \"p99_ns\":{},\"max_ns\":{},\"mean_ns\":{}}}",
        s.len(),
        s[0],
        at(0.50),
        at(0.95),
        at(0.99),
        s[s.len() - 1],
        sum / s.len() as u128
    )
}

/// First candidate root every ancestor of which passes
/// `fspriv::require_parent_write_restricted` — the test harness's
/// `restricted_tempdir` selection re-done over public APIs (temp,
/// then the user's profile dir — owner-locked on both OS families).
fn private_sink_dir() -> std::path::PathBuf {
    use std::path::PathBuf;
    let mut candidates = vec![
        std::env::temp_dir(), // nosemgrep: rust.lang.security.temp-dir.temp-dir
    ];
    for var in ["USERPROFILE", "HOME"] {
        if let Some(home) = std::env::var_os(var).map(PathBuf::from)
            && !candidates.contains(&home)
        {
            candidates.push(home);
        }
    }
    for base in candidates {
        let Ok(base) = base.canonicalize() else {
            continue;
        };
        #[cfg(windows)]
        if base.to_string_lossy().starts_with(r"\\") {
            continue;
        }
        let dir = base.join(format!("rf00-m3-{}", std::process::id()));
        if std::fs::create_dir(&dir).is_err()
            || mcp_writ::fspriv::restrict_owner_only(&dir).is_err()
        {
            continue;
        }
        if mcp_writ::fspriv::require_parent_write_restricted(&dir.join("probe")).is_ok() {
            return dir;
        }
    }
    // No write-restricted root on this host (e.g. volume roots granting
    // Authenticated Users Modify). The operator opt-out keeps the
    // measurement runnable — the report records that the sink's
    // anti-substitution guarantee was waived for it. The opt-out waives
    // the *ancestry* check, not the leaf's own lock-down, so prefer the
    // product helper's unpredictable owner-only tempdir; only a
    // filesystem that cannot carry the restriction at all (an ACL-less
    // %TEMP%) gets the plain per-process dir.
    if mcp_writ::fspriv::replaceable_paths_permitted() {
        if let Ok(dir) = mcp_writ::fspriv::create_private_tempdir("m3") {
            return dir;
        }
        let dir = std::env::temp_dir() // nosemgrep: rust.lang.security.temp-dir.temp-dir
            .join(format!("rf00-m3-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("fallback sink dir");
        return dir;
    }
    panic!("no write-restricted root available for the audit sink dir");
}

fn main() {
    let Args {
        iterations,
        warmup: _,
        out,
        seed,
        extra,
        ..
    } = parse_args("m3_audit", 1);
    let mut events = 20_000usize;
    let mut producers = 4usize;
    let mut every_event = false;
    // The periodic fsync deadline is 5 s — keep the channel busy past
    // it by default so an overdue timer can actually be observed;
    // `--busy-secs 0` restores the old send-and-drain shape.
    let mut busy_secs = 7u64;
    // Non-audit responsiveness probe: `--heartbeats` unrelated tasks
    // each wake every `--heartbeat-ms` during the load window; their
    // lateness is the RF06 worker-occupation signal. `--workers`
    // sizes the runtime pool — on a pool much larger than the load
    // one occupied worker is absorbed and the signal stays flat;
    // a small pool is where synchronous writer I/O can actually
    // starve unrelated wakes.
    let mut heartbeats = 4usize;
    let mut heartbeat_ms = 1u64;
    // Sharper occupancy probe: `--spins N` yield-loops sampling every
    // 1024th repoll gap — no timer granularity between the stall and
    // the sample.
    let mut spins = 0usize;
    let mut workers = 0usize;
    let mut dir_arg: Option<std::path::PathBuf> = None;
    let mut it = extra.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--events" => events = it.next().and_then(|v| v.parse().ok()).unwrap_or(events),
            "--producers" => {
                producers = it.next().and_then(|v| v.parse().ok()).unwrap_or(producers)
            }
            "--busy-secs" => {
                busy_secs = it.next().and_then(|v| v.parse().ok()).unwrap_or(busy_secs)
            }
            "--every-event" => every_event = true,
            "--heartbeats" => {
                heartbeats = it.next().and_then(|v| v.parse().ok()).unwrap_or(heartbeats)
            }
            "--heartbeat-ms" => {
                heartbeat_ms = it
                    .next()
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(heartbeat_ms)
            }
            "--workers" => workers = it.next().and_then(|v| v.parse().ok()).unwrap_or(workers),
            "--spins" => spins = it.next().and_then(|v| v.parse().ok()).unwrap_or(spins),
            "--dir" => dir_arg = it.next().map(std::path::PathBuf::from),
            other => {
                eprintln!("m3_audit: unknown target argument {other}");
                std::process::exit(2);
            }
        }
    }
    assert!(
        iterations == 1,
        "m3_audit runs a single sustained workload — --iterations other than 1 is not supported"
    );
    assert!(producers >= 1);
    let _ = seed; // workload is fixed; seed kept in the report for symmetry

    // The sink must satisfy the same ancestor-ACL trust check the
    // launch's audit path does — a shared temp dir fails it on hosts
    // where Temp grants broad replace access, so fall back through
    // the same candidates the test harness uses. An operator `--dir`
    // is used as-is without triggering the automatic search.
    let (dir, auto_selected) = match dir_arg {
        Some(d) => (d, false),
        None => (private_sink_dir(), true),
    };
    // With an operator-supplied `--dir` the benchmark's files go in a
    // dedicated scratch subdir — cleanup removes only that subdir and
    // can never delete the supplied directory itself. The
    // auto-selected dir is already a dedicated per-process root and
    // is removed whole.
    let run_dir = if auto_selected {
        dir
    } else {
        dir.join(format!("m3-bench-{}", std::process::id()))
    };

    let mut rt_builder = tokio::runtime::Builder::new_multi_thread();
    rt_builder.enable_all();
    if workers > 0 {
        rt_builder.worker_threads(workers);
    }
    let rt = rt_builder.build().expect("tokio runtime");
    std::fs::create_dir_all(&run_dir).expect("temp dir");
    let log_path = run_dir.join("audit.jsonl");

    mcp_writ::measure::reset();
    let (
        enqueue_ns,
        drain_ns,
        reopen_ns,
        sent,
        sync_start_delay_load,
        sync_start_delay_complete,
        heartbeat_delay,
        spin_delay,
        spin_stall,
        dropped,
        failed,
    ) = rt.block_on(async {
        let logger = AuditLogger::to_file_with_options(
            &log_path,
            true,
            if every_event {
                AuditSyncMode::EveryEvent
            } else {
                AuditSyncMode::Buffered
            },
        )
        .expect("audit logger");

        // Sustained load: `producers` tasks queueing via `log_ordered`
        // — the fail-closed path's bounded backpressure (no drops, so
        // `sent` stays exact; `log` would silently count saturation
        // drops under this burst shape and `log_committed` would
        // serialize on disk per record, neither of which is the
        // sustained shape RF03 targets). Each producer sends at least
        // its `events` share (the remainder goes to the first `rem`
        // producers) then keeps sending until `busy` elapses — the
        // load outlasts the 5 s periodic deadline by default. The
        // task returns its actual count because the deadline can push
        // it past the floor.
        let per = events / producers;
        let rem = events % producers;
        let busy = std::time::Duration::from_secs(busy_secs);
        // The RF06 probe: audit-unrelated heartbeats looping a
        // fixed-period sleep on the same runtime for the whole load
        // window. Each wake records its lateness — where synchronous
        // sink I/O runs decides whether audit work can stall these
        // wakes at all. The stop signal interrupts the sleep itself,
        // so teardown joins promptly instead of waiting out a full
        // period.
        let hb_samples = std::sync::Arc::new(std::sync::Mutex::new(Vec::<u64>::new()));
        let (hb_stop, _) = tokio::sync::watch::channel(false);
        let hb_period = std::time::Duration::from_millis(heartbeat_ms.max(1));
        let mut hb_handles = Vec::with_capacity(heartbeats);
        for _ in 0..heartbeats {
            let samples = hb_samples.clone();
            let mut stop_rx = hb_stop.subscribe();
            hb_handles.push(tokio::spawn(async move {
                let mut expected = std::time::Instant::now() + hb_period;
                loop {
                    tokio::select! {
                        _ = tokio::time::sleep_until(expected.into()) => {
                            let now = std::time::Instant::now();
                            samples.lock().unwrap().push(
                                now.saturating_duration_since(expected).as_nanos() as u64,
                            );
                            // Owed periods are not replayed — a wake
                            // stalled past its own period already
                            // recorded the lateness once.
                            expected = (expected + hb_period).max(now + hb_period);
                        }
                        _ = stop_rx.changed() => break,
                    }
                }
            }));
        }
        let t0 = Instant::now();
        let mut handles = Vec::with_capacity(producers);
        for p in 0..producers {
            let l = logger.clone();
            let n = per + usize::from(p < rem);
            handles.push(tokio::spawn(async move {
                let mut sent = 0u64;
                while (sent as usize) < n || t0.elapsed() < busy {
                    l.log_ordered(black_box(event(sent as usize, p)))
                        .await
                        .expect("log_ordered");
                    sent += 1;
                }
                sent
            }));
        }
        // Optional spin probe: each yield requeues the task — the
        // repoll gap is exactly "how long an unrelated runnable task
        // waited for a free worker", the direct RF06 signal with no
        // timer between. Every 1024th gap is sampled uniformly so the
        // quantiles reflect the real gap distribution; gaps stalled
        // past 100 µs are also recorded in a separate stall list so a
        // fully blocked probe still leaves its evidence without
        // skewing the uniform sample.
        let sp_samples = std::sync::Arc::new(std::sync::Mutex::new(Vec::<u64>::new()));
        let sp_stall = std::sync::Arc::new(std::sync::Mutex::new(Vec::<u64>::new()));
        let mut sp_handles = Vec::with_capacity(spins);
        for _ in 0..spins {
            let samples = sp_samples.clone();
            let stalls = sp_stall.clone();
            let stop_rx = hb_stop.subscribe();
            sp_handles.push(tokio::spawn(async move {
                let mut n = 0u64;
                while !*stop_rx.borrow() {
                    let t = std::time::Instant::now();
                    tokio::task::yield_now().await;
                    let gap = t.elapsed().as_nanos() as u64;
                    n += 1;
                    if n & 1023 == 0 {
                        samples.lock().unwrap().push(gap);
                    }
                    if gap > 100_000 {
                        stalls.lock().unwrap().push(gap);
                    }
                }
            }));
        }
        let mut sent = 0u64;
        for h in handles {
            sent += h.await.expect("producer task");
        }
        let enqueue_ns = t0.elapsed().as_nanos() as u64;
        // The drain window starts at production end — the probe
        // teardown below runs while the writer keeps draining and is
        // part of the time the queue takes to empty.
        let t1 = Instant::now();
        let _ = hb_stop.send(true);
        for h in hb_handles {
            let _ = h.await;
        }
        for h in sp_handles {
            let _ = h.await;
        }
        let heartbeat_delay = delay_quantiles(&hb_samples.lock().unwrap());
        let spin_delay = delay_quantiles(&sp_samples.lock().unwrap());
        let spin_stall = delay_quantiles(&sp_stall.lock().unwrap());

        // Drain: the writer reports consumption through the measure
        // façade's dequeued counter; saturation drops count toward
        // sent-without-durability the same way.
        loop {
            let dequeued = mcp_writ::measure::snapshot()
                .counters
                .iter()
                .find(|(n, _)| *n == "audit.events.dequeued")
                .map(|(_, v)| *v)
                .unwrap_or(0);
            if dequeued + logger.dropped_count() >= sent {
                break;
            }
            assert!(
                t1.elapsed().as_secs() < 120,
                "audit writer did not drain {sent} events in 120s"
            );
            tokio::time::sleep(std::time::Duration::from_millis(2)).await;
        }
        let drain_ns = t1.elapsed().as_nanos() as u64;

        // A periodic fsync deadline passes every 5 s of writer
        // uptime, and `audit.sync.start_delay.ns` is recorded only
        // in that arm — its count is exactly the number of periodic
        // executions so far. A deadline passed but unserviced is a
        // starved tick that discharges as soon as the channel
        // empties, so wait (bounded) for the count to catch up to
        // the elapsed-deadline count rather than sleeping a fixed
        // guess. The slack covers the logger-creation gap and a
        // deadline that falls inside the wait itself — an
        // overestimate only waits for the due tick to arrive. If
        // confirmation does not come within the bound, the
        // load-window figure would omit a tick and is reported
        // incomplete.
        let delay_stat = || {
            mcp_writ::measure::snapshot()
                .timings
                .iter()
                .find(|(n, _)| *n == "audit.sync.start_delay.ns")
                .map(|(_, t)| (t.count, t.sum_ns, t.max_ns))
        };
        let expected = (t0.elapsed() + std::time::Duration::from_millis(250)).as_secs() / 5;
        let confirm_deadline = Instant::now() + std::time::Duration::from_secs(2);
        let mut seen = delay_stat().map(|s| s.0).unwrap_or(0);
        while seen < expected && Instant::now() < confirm_deadline {
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            seen = delay_stat().map(|s| s.0).unwrap_or(0);
        }
        let sync_start_delay_complete = seen >= expected;
        let sync_start_delay_load = if sync_start_delay_complete {
            delay_stat()
                .map(|(count, sum_ns, max_ns)| {
                    format!("{{\"count\":{count},\"sum_ns\":{sum_ns},\"max_ns\":{max_ns}}}")
                })
                .unwrap_or_else(|| "null".to_string())
        } else {
            "null".to_string()
        };

        // Reopen latency across a few rotations — the caller-visible
        // wait the M3 item records.
        let mut reopen_ns = Vec::with_capacity(3);
        for _ in 0..3 {
            let t = Instant::now();
            match logger.reopen(Box::new(reopen_marker)).await {
                Ok(true) => reopen_ns.push(t.elapsed().as_nanos() as u64),
                other => panic!("reopen failed: {other:?}"),
            }
        }

        let dropped = logger.dropped_count();
        let failed = logger.is_failed();
        logger.shutdown().await.expect("shutdown");
        (
            enqueue_ns,
            drain_ns,
            reopen_ns,
            sent,
            sync_start_delay_load,
            sync_start_delay_complete,
            heartbeat_delay,
            spin_delay,
            spin_stall,
            dropped,
            failed,
        )
    });

    let opt_out = mcp_writ::fspriv::replaceable_paths_permitted();
    let report = format!(
        "{{\"target\":\"m3_audit\",\"events\":{events},\"producers\":{producers},\
         \"busy_secs\":{busy_secs},\"sent\":{sent},\
         \"heartbeats\":{heartbeats},\"heartbeat_ms\":{heartbeat_ms},\
         \"workers\":{workers},\"spins\":{spins},\
         \"spin_delay_ns\":{spin_delay},\"spin_stall_ns\":{spin_stall},\
         \"sync_mode\":{},\"iterations\":{iterations},\"seed\":{seed},\
         \"os\":{},\"profile\":{},\"allow_replaceable_paths\":{opt_out},\
         \"enqueue_ns\":{enqueue_ns},\"drain_ns\":{drain_ns},\
         \"heartbeat_delay_ns\":{heartbeat_delay},\
         \"sync_start_delay_load_ns\":{sync_start_delay_load},\
         \"sync_start_delay_load_complete\":{sync_start_delay_complete},\
         \"reopen_ns\":{},\"dropped\":{dropped},\"writer_failed\":{failed},\
         \"measure\":{}}}",
        json_str(if every_event {
            "every_event"
        } else {
            "buffered"
        }),
        json_str(std::env::consts::OS),
        json_str(if cfg!(debug_assertions) {
            "debug"
        } else {
            "release"
        }),
        quantiles(&reopen_ns).to_json(),
        measure_json("audit."),
    );
    let res = emit(&out, &report);

    // Only the dedicated run dir is removed — an operator-supplied
    // `--dir` keeps everything except this run's scratch subdir.
    let _ = std::fs::remove_dir_all(&run_dir);
    res.expect("write report");
}
