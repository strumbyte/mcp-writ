//! Bounded JSON-RPC stdio framing.
//!
//! `AsyncBufReadExt::lines()` grows without a cap until a newline arrives.
//! All proxy and discovery readers must use this helper instead.

use tokio::io::{AsyncBufRead, AsyncBufReadExt};

/// Default maximum UTF-8 byte length of a single JSON-RPC line, excluding the newline.
pub const DEFAULT_MAX_FRAME_BYTES: usize = 1_048_576;

/// Error from bounded frame reads.
#[derive(Debug)]
pub enum FramingError {
    Io(std::io::Error),
    /// The peer sent more than `limit` bytes without a newline.
    TooLarge {
        bytes: usize,
        limit: usize,
    },
}

impl std::fmt::Display for FramingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "{e}"),
            Self::TooLarge { bytes, limit } => {
                write!(
                    f,
                    "JSON-RPC frame exceeds {limit} bytes ({bytes} read without newline)"
                )
            }
        }
    }
}

impl std::error::Error for FramingError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            Self::TooLarge { .. } => None,
        }
    }
}

impl From<std::io::Error> for FramingError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

/// Read one newline-terminated frame, aborting before allocating beyond `max_bytes`.
///
/// Returns `Ok(None)` on clean EOF with no partial data. A truncated final line
/// without a newline is returned if it is within the limit.
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
            let add = i; // exclude newline from the stored line
            if acc.len() + add > max_bytes {
                return Err(FramingError::TooLarge {
                    bytes: acc.len() + add,
                    limit: max_bytes,
                });
            }
            acc.extend_from_slice(&available[..add]);
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

    #[tokio::test]
    async fn reads_a_normal_line() {
        let mut reader = BufReader::new(&b"hello\nworld\n"[..]);
        assert_eq!(
            read_line_bounded(&mut reader, 64).await.unwrap(),
            Some("hello".into())
        );
        assert_eq!(
            read_line_bounded(&mut reader, 64).await.unwrap(),
            Some("world".into())
        );
        assert_eq!(read_line_bounded(&mut reader, 64).await.unwrap(), None);
    }

    #[tokio::test]
    async fn rejects_newline_free_oversize_frame() {
        let data = [b'x'; 32];
        let mut reader = BufReader::new(&data[..]);
        let err = read_line_bounded(&mut reader, 8).await.unwrap_err();
        assert!(matches!(err, FramingError::TooLarge { .. }), "got {err}");
    }

    #[tokio::test]
    async fn crlf_is_stripped() {
        let mut reader = BufReader::new(&b"ok\r\n"[..]);
        assert_eq!(
            read_line_bounded(&mut reader, 64).await.unwrap(),
            Some("ok".into())
        );
    }
}
