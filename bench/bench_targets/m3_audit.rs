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

/// First candidate root every ancestor of which passes
/// `fspriv::require_parent_write_restricted` — the test harness's
/// `restricted_tempdir` selection re-done over public APIs (temp,
/// then the user's profile dir — owner-locked on both OS families).
fn private_sink_dir() -> std::path::PathBuf {
    use std::path::PathBuf;
    let mut candidates = vec![
        std::env::temp_dir() // nosemgrep: rust.lang.security.temp-dir.temp-dir
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

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
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
        let mut sent = 0u64;
        for h in handles {
            sent += h.await.expect("producer task");
        }
        let enqueue_ns = t0.elapsed().as_nanos() as u64;

        // Drain: the writer reports consumption through the measure
        // façade's dequeued counter; saturation drops count toward
        // sent-without-durability the same way.
        let t1 = Instant::now();
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
            dropped,
            failed,
        )
    });

    let opt_out = mcp_writ::fspriv::replaceable_paths_permitted();
    let report = format!(
        "{{\"target\":\"m3_audit\",\"events\":{events},\"producers\":{producers},\
         \"busy_secs\":{busy_secs},\"sent\":{sent},\
         \"sync_mode\":{},\"iterations\":{iterations},\"seed\":{seed},\
         \"os\":{},\"profile\":{},\"allow_replaceable_paths\":{opt_out},\
         \"enqueue_ns\":{enqueue_ns},\"drain_ns\":{drain_ns},\
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
