//! Upstream forwarding: the gate relays an allowed query to the
//! configured resolver over UDP, retries a truncated answer over TCP,
//! and serves TCP clients over TCP. The upstream is a configured IP —
//! never resolved through the gate itself, so bootstrap cannot recurse.
//!
//! Every exchange validates the answer before relaying: the response
//! ID must match and the echoed question must name the canonical name
//! we asked — off-path or unrelated datagrams are dropped, never
//! forwarded to the client.

use std::net::SocketAddr;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::timeout;

use super::wire;

/// Whole-exchange upstream budget — a fixed contract, not a tuning
/// dial: the gate's job is policy enforcement, not latency shaping.
pub(crate) const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(5);

/// Largest upstream answer read (TCP framing and EDNS both bound at
/// 65535). UDP reads use the same allocation — the client's OPT is
/// relayed verbatim, so the upstream may legitimately answer large.
pub(crate) const MAX_RESPONSE: usize = 65_535;

/// Why an upstream exchange failed. Mapped to SERVFAIL on the wire —
/// the client learns "cannot answer", the audit record carries which.
pub(crate) enum ForwardError {
    /// No matching answer arrived within the budget.
    Timeout,
    /// Socket/connect/read/write failure.
    Io(std::io::Error),
    /// The exchange ended without an answer echoing our query.
    Mismatch,
}

impl std::fmt::Display for ForwardError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Timeout => write!(f, "upstream timeout"),
            Self::Io(e) => write!(f, "upstream io: {e}"),
            Self::Mismatch => write!(f, "upstream answer did not echo the query"),
        }
    }
}

/// Forward `query` to `upstream` for a UDP client: UDP first, then one
/// TCP retry when the answer comes back truncated — the relay performs
/// the fallback so UDP clients still receive full answers.
///
/// `id`/`canonical` are the forwarded query's ID and question name —
/// the answer must echo them or it is not ours.
pub(crate) async fn forward_udp(
    upstream: SocketAddr,
    query: &[u8],
    id: u16,
    canonical: &str,
) -> Result<Vec<u8>, ForwardError> {
    let resp = udp_exchange(upstream, query, id, canonical).await?;
    if wire::response_truncated(&resp) {
        return tcp_exchange(upstream, query, id, canonical).await;
    }
    Ok(resp)
}

/// Forward `query` to `upstream` over TCP (length-prefixed per RFC
/// 7766) — used for TCP clients and the TC retry.
pub(crate) async fn forward_tcp(
    upstream: SocketAddr,
    query: &[u8],
    id: u16,
    canonical: &str,
) -> Result<Vec<u8>, ForwardError> {
    tcp_exchange(upstream, query, id, canonical).await
}

async fn udp_exchange(
    upstream: SocketAddr,
    query: &[u8],
    id: u16,
    canonical: &str,
) -> Result<Vec<u8>, ForwardError> {
    let bind_addr: SocketAddr = match upstream {
        SocketAddr::V4(_) => "0.0.0.0:0".parse().unwrap(),
        SocketAddr::V6(_) => "[::]:0".parse().unwrap(),
    };
    let sock = UdpSocket::bind(bind_addr).await.map_err(ForwardError::Io)?;
    sock.connect(upstream).await.map_err(ForwardError::Io)?;
    sock.send(query).await.map_err(ForwardError::Io)?;

    let mut buf = vec![0u8; MAX_RESPONSE];
    // One budget for the whole exchange: mismatched datagrams are
    // dropped without restarting the clock, so a noisy source cannot
    // extend the wait indefinitely.
    timeout(UPSTREAM_TIMEOUT, async {
        loop {
            let n = sock.recv(&mut buf).await.map_err(ForwardError::Io)?;
            if wire::response_matches(&buf[..n], id, canonical) {
                return Ok(buf[..n].to_vec());
            }
        }
    })
    .await
    .map_err(|_| ForwardError::Timeout)?
}

async fn tcp_exchange(
    upstream: SocketAddr,
    query: &[u8],
    id: u16,
    canonical: &str,
) -> Result<Vec<u8>, ForwardError> {
    timeout(UPSTREAM_TIMEOUT, async {
        let mut stream = TcpStream::connect(upstream)
            .await
            .map_err(ForwardError::Io)?;
        let frame_len = u16::try_from(query.len().min(u16::MAX as usize)).unwrap();
        let mut frame = Vec::with_capacity(query.len() + 2);
        frame.extend_from_slice(&frame_len.to_be_bytes());
        frame.extend_from_slice(&query[..frame_len as usize]);
        stream.write_all(&frame).await.map_err(ForwardError::Io)?;

        let mut len_buf = [0u8; 2];
        stream
            .read_exact(&mut len_buf)
            .await
            .map_err(ForwardError::Io)?;
        let resp_len = u16::from_be_bytes(len_buf) as usize;
        let mut resp = vec![0u8; resp_len];
        stream
            .read_exact(&mut resp)
            .await
            .map_err(ForwardError::Io)?;
        if !wire::response_matches(&resp, id, canonical) {
            return Err(ForwardError::Mismatch);
        }
        Ok(resp)
    })
    .await
    .map_err(|_| ForwardError::Timeout)?
}
