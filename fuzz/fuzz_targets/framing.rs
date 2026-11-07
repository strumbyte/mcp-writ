//! Fuzz target: bounded stdio JSON-RPC framing.
//!
//! Input layout: `[b"FRM1"][u64 max_bytes LE][u32 window LE][stream]`.
//! `window` caps each `fill_buf` chunk the readers see (0 = the whole
//! stream at once), so frames also span buffer refills. The property
//! drains the stream through both boundary readers —
//! `read_frame_bounded` (resumable, the Auditor's proxy loops) and
//! `read_line_bounded` (fail-fast, the launcher) — asserting the
//! framing invariants and cross-checking the two verdicts. The tag
//! rejects stale artifacts: a `.bin` saved under an older layout
//! would silently shift the stream, replaying a different input.
//!
//! Search space: caps biased to 0, window edges (8 KiB head/tail
//! windows) and powers of two; frame lengths biased to `max±1`,
//! window edges, and long newline-free runs — frame bodies carry no
//! `\n`, since a random newline would silently split a boundary-length
//! frame before the readers see it; CRLF and unterminated tails
//! included; `fill_buf` chunk sizes biased to tiny splits and the
//! oversize transition.

use std::cell::Cell;

use mcp_writ::fuzz::{FrameStats, drain_frames, drain_lines};

/// Largest generated stream — big enough for multi-frame cases,
/// small enough that a tiny-window case still finishes quickly.
const MAX_STREAM: usize = 96 * 1024;

/// Format tag prefixed to every generated input — a saved artifact
/// from a different layout fails loudly instead of decoding into a
/// shifted, unrecognizable stream.
const INPUT_TAG: &[u8; 4] = b"FRM1";

/// Coverage counters the property ticks — the gate at the end of a
/// passing run asserts each reader path actually ran.
#[derive(Default)]
struct Gates {
    cases: Cell<usize>,
    lines: Cell<usize>,
    oversize: Cell<usize>,
    fail_fast: Cell<usize>,
    unterminated: Cell<usize>,
    partial_consume: Cell<usize>,
    chunked: Cell<usize>,
}

/// Emit one tagged input: `[FRM1][u64 max_bytes LE][u32 window
/// LE][stream]` — caps and `fill_buf` window biased to boundaries,
/// frame bodies kept newline-free.
fn gen_input(ctx: &mut noprop::TestCaseContext) -> Vec<u8> {
    let max = noprop::sample_with_boundaries(
        ctx,
        &[
            0usize, 1, 2, 63, 64, 65, 4095, 4096, 8191, 8192, 8193, 65535,
        ],
        noprop::Ratio::new(1, 2),
        |ctx| noprop::sample_usize_in(ctx, 0..=MAX_STREAM),
    );
    // `fill_buf` chunk size — biased to tiny splits and the `max`±1
    // oversize transition; 0 hands the readers the whole stream at
    // once.
    let window = noprop::sample_with_boundaries(
        ctx,
        &[
            0usize,
            1,
            3,
            8,
            64,
            255,
            4096,
            8 * 1024,
            max.saturating_sub(1),
            max,
            max.saturating_add(1),
        ],
        noprop::Ratio::new(1, 2),
        |ctx| noprop::sample_usize_in(ctx, 0..=MAX_STREAM),
    );
    let mut stream = Vec::new();
    for _ in 0..noprop::sample_usize_in(ctx, 0..=6) {
        let len = noprop::sample_with_boundaries(
            ctx,
            &[
                0usize,
                1,
                max.saturating_sub(1),
                max,
                max.saturating_add(1),
                8 * 1024 - 1,
                8 * 1024,
                8 * 1024 + 1,
            ],
            noprop::Ratio::new(1, 2),
            |ctx| noprop::sample_usize_in(ctx, 0..=MAX_STREAM),
        );
        let mut body = noprop::sample_bytes_vec(ctx, len);
        // A random `\n` inside the body would split the frame early —
        // the boundary lengths sampled above must reach the readers.
        for b in &mut body {
            if *b == b'\n' {
                *b = b'x';
            }
        }
        stream.extend_from_slice(&body);
        match noprop::sample_weighted_index(ctx, &[6, 1, 1]) {
            0 => stream.push(b'\n'),
            1 => stream.extend_from_slice(b"\r\n"),
            _ => {} // unterminated tail — EOF ends the frame
        }
    }
    // A sub-64-byte window costs one `fill_buf` per byte — cap the
    // stream so a tiny window cannot turn one case into a time hog.
    if (1..64).contains(&window) {
        stream.truncate(8 * 1024);
    }
    let mut input = INPUT_TAG.to_vec();
    input.extend_from_slice(&(max as u64).to_le_bytes());
    input.extend_from_slice(&(window as u32).to_le_bytes());
    input.extend_from_slice(&stream);
    input
}

/// Drain one stream through both bounded readers, assert the
/// framing invariants, and cross-check the two verdicts.
fn property(g: &Gates, data: &[u8]) {
    let Some(data) = data.strip_prefix(INPUT_TAG) else {
        panic!(
            "framing input lacks the {} tag — stale or foreign artifact",
            String::from_utf8_lossy(INPUT_TAG)
        );
    };
    if data.len() < 12 {
        return;
    }
    let max = (u64::from_le_bytes(data[..8].try_into().unwrap())).min(usize::MAX as u64) as usize;
    let window = u32::from_le_bytes(data[8..12].try_into().unwrap()) as usize;
    let stream = &data[12..];
    let frames = drain_frames(stream, max, window);
    let lines = drain_lines(stream, max, window);
    cross_check(&frames, &lines);

    g.cases.set(g.cases.get() + 1);
    g.chunked
        .set(g.chunked.get() + usize::from(window > 0 && window < stream.len()));
    g.lines.set(g.lines.get() + usize::from(frames.lines > 0));
    g.oversize
        .set(g.oversize.get() + usize::from(frames.oversize > 0));
    g.fail_fast
        .set(g.fail_fast.get() + usize::from(lines.fail_fast));
    g.unterminated
        .set(g.unterminated.get() + usize::from(frames.unterminated_oversize > 0));
    g.partial_consume
        .set(g.partial_consume.get() + usize::from(lines.consumed < stream.len()));
}

/// The two readers see the same stream: a frame over `max` is
/// `Oversize` in the resumable read and `TooLarge` in the fail-fast
/// read — so fail-fast happens iff at least one oversize exists, and
/// the fail-fast line count is a prefix of the resumable one.
fn cross_check(frames: &FrameStats, lines: &FrameStats) {
    assert_eq!(
        lines.fail_fast,
        frames.oversize > 0,
        "reader disagreement: fail_fast={} vs oversize={}",
        lines.fail_fast,
        frames.oversize
    );
    // Every line the fail-fast reader returned is an in-limit frame
    // the resumable reader counted too — the fail-fast total is a
    // prefix of `frames.lines`, and a run that never hit `TooLarge`
    // drained the stream, so the totals then agree exactly.
    assert!(lines.lines <= frames.lines);
    if !lines.fail_fast {
        assert_eq!(lines.lines, frames.lines);
    }
}

/// Parse the shared CLI and run the harness for this target.
fn main() {
    let args = mcp_writ_fuzz::parse_args("framing");
    let g = Gates::default();
    std::process::exit(mcp_writ_fuzz::run(
        "framing",
        &args,
        gen_input,
        |data| property(&g, data),
        || {
            assert!(g.cases.get() > 0, "no cases ran");
            assert!(g.lines.get() > 0, "no in-limit frame seen");
            assert!(g.oversize.get() > 0, "no oversized frame seen");
            assert!(g.fail_fast.get() > 0, "fail-fast path never hit");
            assert!(g.chunked.get() > 0, "no case spanned buffer refills");
            format!(
                "lines={} oversize={} fail_fast={} unterminated={} partial={} chunked={}",
                g.lines.get(),
                g.oversize.get(),
                g.fail_fast.get(),
                g.unterminated.get(),
                g.partial_consume.get(),
                g.chunked.get()
            )
        },
    ));
}
