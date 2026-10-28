//! Neutralize untrusted strings before they reach a terminal.

/// Render `input` so C0/C1 controls, ESC, BEL, and bidi marks cannot hijack
/// a terminal. Raw values stay unchanged in structurally encoded files.
pub fn sanitize_for_terminal(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        match ch {
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\x08' => out.push_str("\\b"),
            '\x0c' => out.push_str("\\f"),
            c if c.is_control() || is_bidi_or_format(c) => {
                out.push_str(&format!("\\u{{{:04x}}}", c as u32));
            }
            c => out.push(c),
        }
    }
    out
}

fn is_bidi_or_format(c: char) -> bool {
    matches!(
        c,
        '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}' | '\u{200B}'..='\u{200F}' | '\u{061C}'
    )
}

/// Byte budget one child's stderr may spend on our terminal — past it
/// the relay keeps draining (so the pipe can never back up into the
/// child's writes and deadlock it) but stops emitting, which also
/// bounds the work a flooding child can cause.
const STDERR_RELAY_CAP: usize = 64 * 1024;

/// Emitted once when the relay starts dropping output — an over-cap
/// flood must read as truncated, never as the child having gone quiet.
const STDERR_TRUNCATED_NOTICE: &[u8] =
    b"[mcp-writ] child stderr exceeded the relay cap; further output suppressed";

/// Relay a spawned workload's stderr to ours in bounded chunks with
/// terminal control characters escaped — a spawned MCP server is
/// attacker-controlled, so its diagnostics cross as text, never raw
/// bytes: a raw `Stdio::inherit` would let it move the cursor, clear
/// the screen, or write OSC sequences into the operator's terminal.
/// The relay is detached and ends when the child's writer closes —
/// at exit, or when the workload itself drops stderr.
///
/// The line splitter carries a partial line in `pending` bounded by
/// the same budget, so a newline-free flood can never accumulate an
/// unbounded buffer the way `read_line` would.
pub fn relay_child_stderr<R>(stderr: R) -> tokio::task::JoinHandle<()>
where
    R: tokio::io::AsyncRead + Unpin + Send + 'static,
{
    tokio::spawn(async move {
        use tokio::io::AsyncBufReadExt;
        let mut reader = tokio::io::BufReader::new(stderr);
        let mut budget = STDERR_RELAY_CAP;
        let mut truncating = false;
        let mut pending: Vec<u8> = Vec::new();
        loop {
            let available = match reader.fill_buf().await {
                Ok([]) | Err(_) => break,
                Ok(bytes) => bytes,
            };
            let consumed = available.len();
            if budget > 0 {
                let take = consumed.min(budget);
                split_and_write(
                    &available[..take],
                    &mut pending,
                    &mut write_clean_stderr_line,
                );
                budget -= take;
            } else if !truncating {
                truncating = true;
                write_clean_stderr_line(STDERR_TRUNCATED_NOTICE);
            }
            reader.consume(consumed);
        }
        flush_pending(&mut pending, &mut write_clean_stderr_line);
    })
}

/// Blocking twin of [`relay_child_stderr`] for `std::process` spawns —
/// the synchronous launch paths have no runtime driving a detached
/// task, so the relay runs on its own thread and ends when the
/// child's writer closes.
pub fn relay_child_stderr_blocking<R>(stderr: R) -> std::thread::JoinHandle<()>
where
    R: std::io::Read + Send + 'static,
{
    std::thread::spawn(move || {
        use std::io::BufRead;
        let mut reader = std::io::BufReader::new(stderr);
        let mut budget = STDERR_RELAY_CAP;
        let mut truncating = false;
        let mut pending: Vec<u8> = Vec::new();
        loop {
            let available = match reader.fill_buf() {
                Ok([]) | Err(_) => break,
                Ok(bytes) => bytes,
            };
            let consumed = available.len();
            if budget > 0 {
                let take = consumed.min(budget);
                split_and_write(
                    &available[..take],
                    &mut pending,
                    &mut write_clean_stderr_line,
                );
                budget -= take;
            } else if !truncating {
                truncating = true;
                write_clean_stderr_line(STDERR_TRUNCATED_NOTICE);
            }
            reader.consume(consumed);
        }
        flush_pending(&mut pending, &mut write_clean_stderr_line);
    })
}

/// Emit complete lines from `chunk` to `sink` and carry the
/// unterminated remainder in `pending`. `pending`'s growth is bounded
/// by the caller's relay budget, never by the child's output.
fn split_and_write(chunk: &[u8], pending: &mut Vec<u8>, sink: &mut impl FnMut(&[u8])) {
    let mut rest = chunk;
    while let Some(nl) = rest.iter().position(|&b| b == b'\n') {
        pending.extend_from_slice(&rest[..nl]);
        let line = std::mem::take(pending);
        sink(&line);
        rest = &rest[nl + 1..];
    }
    pending.extend_from_slice(rest);
}

/// The unterminated tail, emitted once the writer closes — a child
/// that never sent a newline still gets its last line through.
fn flush_pending(pending: &mut Vec<u8>, sink: &mut impl FnMut(&[u8])) {
    if !pending.is_empty() {
        sink(pending);
        pending.clear();
    }
}

fn write_clean_stderr_line(line: &[u8]) {
    use std::io::Write;
    let clean = sanitize_for_terminal(&String::from_utf8_lossy(line));
    let _ = writeln!(std::io::stderr().lock(), "{clean}");
}

/// Escape a string interpolated into a `//` KDL comment.
///
/// This is a syntax boundary, not a display concern: every code point
/// the KDL grammar counts as a newline terminates the comment and lets
/// the remainder parse as real nodes — `\n`, `\r`, `\u{0B}` (VT),
/// `\u{0C}` (FF), `\u{85}` (NEL), `\u{2028}` (LS), `\u{2029}` (PS).
/// [`sanitize_for_terminal`] misses LS/PS (they are separators, not
/// control characters), which is enough for an untrusted fragment to
/// break out of a comment line and inject policy settings.
pub fn escape_kdl_comment(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        match ch {
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() || is_bidi_or_format(c) || matches!(c, '\u{2028}' | '\u{2029}') => {
                out.push_str(&format!("\\u{{{:04x}}}", c as u32));
            }
            c => out.push(c),
        }
    }
    out
}

/// Escape a string for a KDL quoted value, including control characters.
pub fn escape_kdl_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() || is_bidi_or_format(c) => {
                out.push_str(&format!("\\u{{{:04x}}}", c as u32));
            }
            c => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escape_sequences_are_visible() {
        assert_eq!(
            sanitize_for_terminal("ok\x1b[31mX\x07"),
            "ok\\u{001b}[31mX\\u{0007}"
        );
        assert_eq!(sanitize_for_terminal("a\nb"), "a\\nb");
    }

    /// Regression coverage for the terminal-injection classes a hostile
    /// tool name / violation reason can carry: CSI escapes (ESC), BEL,
    /// CR/LF log injection, bidi overrides, and OSC hyperlinks.
    #[test]
    fn attacker_control_classes_are_neutralized() {
        // A JSON-decoded tool name as it reaches a warn! field.
        let hostile =
            "ls\x1b[2J\x07\r\nFAKE ok\n\u{202e}tre\x1b]8;;https://evil\x07link\x1b]8;;\x07";
        let out = sanitize_for_terminal(hostile);
        assert!(!out.contains('\x1b'), "ESC must be escaped: {out:?}");
        assert!(!out.contains('\x07'), "BEL must be escaped: {out:?}");
        assert!(
            !out.contains(['\r', '\n']),
            "CR/LF must be escaped: {out:?}"
        );
        assert!(
            !out.chars().any(|c| ('\u{202A}'..='\u{202E}').contains(&c)),
            "bidi overrides must be escaped: {out:?}"
        );
        // The payload text stays legible.
        assert!(out.contains("ls\\u{001b}[2J"));
        assert!(out.contains("FAKE ok"));
        assert!(out.contains("\\u{202e}tre"));
        assert!(out.contains("https://evil"));
    }

    /// The relay splits on newlines, carries the unterminated tail
    /// between chunks, and flushes it at writer close — the shape both
    /// the async and blocking pumps share.
    #[test]
    fn relay_split_carries_pending_and_flushes_tail() {
        let mut pending = Vec::new();
        let lines = std::cell::RefCell::new(Vec::<Vec<u8>>::new());
        let mut sink = |line: &[u8]| lines.borrow_mut().push(line.to_vec());
        split_and_write(b"first\nsec", &mut pending, &mut sink);
        assert_eq!(*lines.borrow(), vec![b"first".to_vec()]);
        assert_eq!(pending, b"sec".to_vec());
        split_and_write(b"ond\nrest", &mut pending, &mut sink);
        assert_eq!(*lines.borrow(), vec![b"first".to_vec(), b"second".to_vec()]);
        assert_eq!(pending, b"rest".to_vec());
        flush_pending(&mut pending, &mut sink);
        assert_eq!(
            *lines.borrow(),
            vec![b"first".to_vec(), b"second".to_vec(), b"rest".to_vec()]
        );
        assert!(pending.is_empty());
    }

    /// `escape_kdl_comment` must neutralize every code point the KDL
    /// grammar counts as a newline — otherwise the remainder of an
    /// interpolated fragment parses as real policy nodes.
    #[test]
    fn kdl_comment_escape_closes_newline_breakout() {
        for nl in [
            '\n', '\r', '\u{0B}', '\u{0C}', '\u{85}', '\u{2028}', '\u{2029}',
        ] {
            let hostile = format!("safe{nl}tool \"evil\"");
            let doc = format!("policy version=1\n// {}\n", escape_kdl_comment(&hostile));
            let parsed: kdl::KdlDocument = doc.parse().unwrap();
            assert_eq!(
                parsed.nodes().len(),
                1,
                "newline {nl:?} escaped the comment in: {doc}"
            );
        }
    }
}
