//! Bounded line reading for JSON-RPC framing.
//!
//! Both the launcher and the in-sandbox runner transport one JSON-RPC
//! object per line over stdio.  [`read_line_bounded`] is the primitive:
//! newline-terminated, length-capped, lossy UTF-8.  The Auditor's proxy
//! loops use [`read_frame_bounded`] instead — same contract plus a
//! recoverable oversize outcome, so a frame that exceeds the configured
//! cap fails *that* request while the framing boundary survives and the
//! session continues on the next line.

use std::collections::VecDeque;

use tokio::io::{AsyncBufRead, AsyncBufReadExt};

/// Default maximum UTF-8 byte length of a single JSON-RPC line,
/// excluding the newline.  Matches the bound the MCP TypeScript SDK's
/// stdio transport applies (`STDIO_DEFAULT_MAX_BUFFER_SIZE`, 10 MiB —
/// packages/core-internal/src/shared/stdio.ts); `run --max-frame-bytes`
/// overrides it for the Auditor.
pub const DEFAULT_MAX_FRAME_BYTES: usize = 10 * 1024 * 1024;

/// Bytes retained from the head and the tail of an oversized frame for
/// correlation-id recovery and diagnostics — a frame's `id` member sits
/// within a few bytes of either edge on every MCP SDK we target (the TS
/// SDK serializes `id` last), so two bounded windows recover it without
/// holding the refused frame in memory.
const OVERSIZE_WINDOW_BYTES: usize = 8 * 1024;

/// Bytes kept from both ends of a frame that exceeded the configured
/// cap — the payload itself is dropped byte at a time, not buffered.
pub struct OversizeFrame {
    /// First bytes of the frame (up to `OVERSIZE_WINDOW_BYTES`).
    pub head: Vec<u8>,
    /// Last bytes of the frame, ending at the newline or EOF (up to
    /// `OVERSIZE_WINDOW_BYTES`).
    pub tail: Vec<u8>,
    /// Total frame length in bytes, excluding the terminating newline.
    pub bytes: usize,
    /// `false` when EOF ended the frame without a newline — the peer is
    /// gone and no next frame exists to resynchronize to.
    pub terminated: bool,
}

/// One bounded read's outcome.
pub enum BoundedFrame {
    /// A complete frame within the limit — newline (and a trailing CR)
    /// stripped.
    Line(String),
    /// A frame that exceeded `max_bytes`, consumed through its
    /// terminating newline (or to EOF) so the next read resumes at a
    /// clean boundary.
    Oversize(OversizeFrame),
}

/// Errors from bounded line reading.
#[derive(Debug)]
pub enum FramingError {
    /// I/O error from the underlying reader.
    Io(std::io::Error),
    /// Frame exceeded the byte limit.
    TooLarge {
        /// Bytes observed for the frame when the error was raised —
        /// the frame's exact length when its terminating newline was
        /// already buffered, otherwise a lower bound: the read fails
        /// fast rather than draining the rest of an oversized frame.
        bytes: usize,
        /// Configured maximum.
        limit: usize,
    },
}

impl std::fmt::Display for FramingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "I/O error: {e}"),
            Self::TooLarge { bytes, limit } => write!(
                f,
                "JSON-RPC frame exceeds the {limit}-byte limit ({bytes} bytes)"
            ),
        }
    }
}

impl std::error::Error for FramingError {}

impl From<std::io::Error> for FramingError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

/// Read one newline-terminated frame.
///
/// - `Ok(None)` on EOF with no bytes buffered.
/// - `Ok(Some(BoundedFrame::Line))` for a frame within `max_bytes` —
///   the trailing newline and a `\r` are stripped.
/// - `Ok(Some(BoundedFrame::Oversize))` when the frame exceeds
///   `max_bytes`: the whole frame is still consumed through its
///   terminating newline (bounded memory — only the head/tail windows
///   are kept) so the next call starts at the following frame.  EOF
///   without a newline also returns `Oversize` once `max_bytes` was
///   crossed, with `terminated: false`.
/// - `Err` on underlying I/O failure only.
///
/// Newline-free input is accumulated until the limit is crossed, after
/// which the same oversize drain applies — memory stays bounded
/// regardless of whether a newline ever arrives.
pub async fn read_frame_bounded<R: AsyncBufRead + Unpin>(
    reader: &mut R,
    max_bytes: usize,
) -> Result<Option<BoundedFrame>, FramingError> {
    let mut acc: Vec<u8> = Vec::new();
    let mut tail: VecDeque<u8> = VecDeque::new();
    let mut total: usize = 0;
    let mut oversize = false;
    loop {
        let available = reader.fill_buf().await?;
        if available.is_empty() {
            if oversize {
                return Ok(Some(BoundedFrame::Oversize(OversizeFrame {
                    head: acc,
                    tail: tail.into(),
                    bytes: total,
                    terminated: false,
                })));
            }
            if acc.is_empty() {
                return Ok(None);
            }
            let line = String::from_utf8_lossy(&acc).into_owned();
            return Ok(Some(BoundedFrame::Line(line)));
        }

        let nl = available.iter().position(|&b| b == b'\n');
        let seg_end = nl.unwrap_or(available.len());
        let seg = &available[..seg_end];

        if !oversize && total + seg_end > max_bytes {
            oversize = true;
            // `acc` holds every byte of the frame so far: the head is
            // its first window, and the tail seeds from its last one —
            // bytes seen before the flip still belong to the frame's
            // trailing window when it ends up oversized.
            tail.extend(
                acc[acc.len().saturating_sub(OVERSIZE_WINDOW_BYTES)..]
                    .iter()
                    .copied(),
            );
            acc.truncate(OVERSIZE_WINDOW_BYTES);
        }
        if oversize {
            // Head keeps the frame's first OVERSIZE_WINDOW_BYTES — the
            // first segment may itself cross the cap, so `acc` can
            // still have room to fill. Tail tracks the last window; a
            // frame smaller than the window lands whole in both.
            if acc.len() < OVERSIZE_WINDOW_BYTES {
                let room = OVERSIZE_WINDOW_BYTES - acc.len();
                acc.extend_from_slice(&seg[..room.min(seg.len())]);
            }
            tail.extend(seg.iter().copied());
            while tail.len() > OVERSIZE_WINDOW_BYTES {
                tail.pop_front();
            }
        } else {
            acc.extend_from_slice(seg);
        }
        total += seg_end;
        reader.consume(seg_end);

        if nl.is_some() {
            reader.consume(1);
            if oversize {
                return Ok(Some(BoundedFrame::Oversize(OversizeFrame {
                    head: acc,
                    tail: tail.into(),
                    bytes: total,
                    terminated: true,
                })));
            }
            if acc.last() == Some(&b'\r') {
                acc.pop();
            }
            return Ok(Some(BoundedFrame::Line(
                String::from_utf8_lossy(&acc).into_owned(),
            )));
        }
    }
}

/// Read one newline-terminated line (UTF-8 lossy) with a byte cap.
///
/// Fails fast on an oversized frame: [`FramingError::TooLarge`] fires as
/// soon as the accumulated bytes cross `max_bytes`, and the rest of the
/// frame is *not* drained — every caller treats oversize as a fatal
/// protocol error, and a peer streaming a newline-free frame must not
/// get unbounded read time. Callers that need the framing boundary to
/// survive the refusal use [`read_frame_bounded`] instead.
pub async fn read_line_bounded<R: AsyncBufRead + Unpin>(
    reader: &mut R,
    max_bytes: usize,
) -> Result<Option<String>, FramingError> {
    let mut acc = Vec::new();
    loop {
        let available = reader.fill_buf().await?;
        if available.is_empty() {
            if acc.is_empty() {
                return Ok(None);
            }
            if acc.len() > max_bytes {
                return Err(FramingError::TooLarge {
                    bytes: acc.len(),
                    limit: max_bytes,
                });
            }
            let line = String::from_utf8_lossy(&acc).into_owned();
            return Ok(Some(line));
        }

        if let Some(i) = available.iter().position(|&b| b == b'\n') {
            if acc.len() + i > max_bytes {
                return Err(FramingError::TooLarge {
                    bytes: acc.len() + i,
                    limit: max_bytes,
                });
            }
            acc.extend_from_slice(&available[..i]);
            reader.consume(i + 1);
            if acc.last() == Some(&b'\r') {
                acc.pop();
            }
            let line = String::from_utf8_lossy(&acc).into_owned();
            return Ok(Some(line));
        }

        if acc.len() + available.len() > max_bytes {
            return Err(FramingError::TooLarge {
                bytes: acc.len() + available.len(),
                limit: max_bytes,
            });
        }
        let n = available.len();
        acc.extend_from_slice(available);
        reader.consume(n);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::BufReader;

    async fn read(data: &[u8], max: usize) -> Result<Option<String>, FramingError> {
        let mut r = BufReader::new(data);
        read_line_bounded(&mut r, max).await
    }

    #[tokio::test]
    async fn simple_line() {
        assert_eq!(read(b"hello\n", 1024).await.unwrap(), Some("hello".into()));
    }

    #[tokio::test]
    async fn eof_without_newline() {
        assert_eq!(read(b"hello", 1024).await.unwrap(), Some("hello".into()));
    }

    #[tokio::test]
    async fn eof_empty() {
        assert_eq!(read(b"", 1024).await.unwrap(), None);
    }

    #[tokio::test]
    async fn crlf() {
        assert_eq!(
            read(b"hello\r\n", 1024).await.unwrap(),
            Some("hello".into())
        );
    }

    #[tokio::test]
    async fn exactly_at_limit() {
        let line = "x".repeat(100);
        let mut data = line.clone().into_bytes();
        data.push(b'\n');
        assert_eq!(read(&data, 100).await.unwrap(), Some(line));
    }

    #[tokio::test]
    async fn exceeds_limit() {
        let line = "x".repeat(200);
        let mut data = line.into_bytes();
        data.push(b'\n');
        match read(&data, 100).await {
            Err(FramingError::TooLarge { bytes, limit }) => {
                assert_eq!(bytes, 200);
                assert_eq!(limit, 100);
            }
            other => panic!("expected TooLarge, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn too_large_message_names_counts_not_newline() {
        let err = FramingError::TooLarge {
            bytes: 200,
            limit: 100,
        };
        assert_eq!(
            err.to_string(),
            "JSON-RPC frame exceeds the 100-byte limit (200 bytes)"
        );
    }

    #[tokio::test]
    async fn oversize_frame_is_drained_to_newline() {
        // An oversized line followed by a normal one: the oversized
        // frame is consumed through its newline so the next read lands
        // on a clean boundary — the session continues.
        let big = "x".repeat(200);
        let data = format!("{big}\nnext\n").into_bytes();
        let mut r = BufReader::new(&data[..]);
        let first = read_frame_bounded(&mut r, 100).await.unwrap().unwrap();
        let BoundedFrame::Oversize(f) = first else {
            panic!("expected Oversize");
        };
        assert!(f.terminated);
        assert_eq!(f.bytes, 200);
        // The frame is smaller than a window: head and tail each hold
        // it whole.
        assert_eq!(f.head, big.as_bytes());
        assert_eq!(f.tail, big.as_bytes());
        let second = read_frame_bounded(&mut r, 100).await.unwrap().unwrap();
        assert!(matches!(second, BoundedFrame::Line(l) if l == "next"));
    }

    /// A reader that hands out at most `window` bytes per `fill_buf`,
    /// forcing reads to span multiple buffer refills.
    struct Chunked<'a> {
        data: &'a [u8],
        pos: usize,
        window: usize,
    }
    impl AsyncBufRead for Chunked<'_> {
        fn poll_fill_buf(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<&[u8]>> {
            let me: &Self = &self;
            let end = (me.pos + me.window).min(me.data.len());
            std::task::Poll::Ready(Ok(&me.data[me.pos..end]))
        }
        fn consume(mut self: std::pin::Pin<&mut Self>, amt: usize) {
            self.pos += amt;
        }
    }
    impl tokio::io::AsyncRead for Chunked<'_> {
        fn poll_read(
            mut self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            let avail = &self.data[self.pos.min(self.data.len())..];
            let n = avail.len().min(buf.remaining());
            buf.put_slice(&avail[..n]);
            self.pos += n;
            std::task::Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn oversize_frame_spans_buffer_refills() {
        // A reader that hands out 16-byte chunks forces the overflow to
        // land mid-frame — the drain still consumes through the newline.
        let big = "x".repeat(300);
        let data = format!("{big}\nok\n").into_bytes();
        let mut r = Chunked {
            data: &data,
            pos: 0,
            window: 16,
        };
        let first = read_frame_bounded(&mut r, 64).await.unwrap().unwrap();
        let BoundedFrame::Oversize(f) = first else {
            panic!("expected Oversize");
        };
        assert!(f.terminated);
        assert_eq!(f.bytes, 300);
        assert_eq!(f.head, big.as_bytes());
        assert_eq!(f.tail, big.as_bytes());
        let second = read_frame_bounded(&mut r, 64).await.unwrap().unwrap();
        assert!(matches!(second, BoundedFrame::Line(l) if l == "ok"));
    }

    #[tokio::test]
    async fn oversize_windows_keep_head_and_tail() {
        // Head keeps the frame's first bytes, tail its last — the middle
        // is dropped without buffering it.
        let mut frame = Vec::new();
        frame.extend_from_slice(b"HEAD-");
        frame.extend(std::iter::repeat_n(b'm', 20_000));
        frame.extend_from_slice(b"-TAIL");
        let mut data = frame.clone();
        data.push(b'\n');
        let mut r = BufReader::new(&data[..]);
        let BoundedFrame::Oversize(f) = read_frame_bounded(&mut r, 4096).await.unwrap().unwrap()
        else {
            panic!("expected Oversize");
        };
        assert_eq!(&f.head[..5], b"HEAD-");
        assert_eq!(&f.tail[f.tail.len() - 5..], b"-TAIL");
        assert_eq!(f.bytes, frame.len());
    }

    #[tokio::test]
    async fn oversize_at_eof_reports_unterminated() {
        let data = "x".repeat(300).into_bytes();
        let mut r = BufReader::new(&data[..]);
        let BoundedFrame::Oversize(f) = read_frame_bounded(&mut r, 64).await.unwrap().unwrap()
        else {
            panic!("expected Oversize");
        };
        assert!(!f.terminated);
        assert_eq!(f.bytes, 300);
        // EOF already consumed everything — the next read sees None.
        assert!(read_frame_bounded(&mut r, 64).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn read_line_bounded_fails_fast_without_draining() {
        // The terminating newline sits in the same buffer, so the count
        // is exact — but the reader is left mid-frame: every caller
        // treats oversize as fatal, so nothing drains for resync.
        let mut data = "x".repeat(200).into_bytes();
        data.push(b'\n');
        data.extend_from_slice(b"next\n");
        let mut r = BufReader::new(&data[..]);
        match read_line_bounded(&mut r, 100).await {
            Err(FramingError::TooLarge { bytes, .. }) => assert_eq!(bytes, 200),
            other => panic!("expected TooLarge, got {other:?}"),
        }
        // Not drained: the next read re-encounters the oversized frame.
        assert!(matches!(
            read_line_bounded(&mut r, 100).await,
            Err(FramingError::TooLarge { .. })
        ));
    }
}
