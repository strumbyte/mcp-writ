//! Per-connection backend tasks — the host-side half of each spliced
//! flow.
//!
//! [`tcp_backend`] dials the flow's original destination and relays
//! bytes until either side closes; [`dns_tcp_backend`] answers
//! intercepted DNS-over-TCP through the embedded gate instead of a
//! real socket. Both respect the conn's `FlowCredit` backlog cap, so a
//! workload that never drains replies throttles the remote — or the
//! gate — instead of growing `Conn::pending` unboundedly.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::Ordering;

use tokio::net::TcpStream;
use tokio::sync::mpsc;

use crate::dnsgate::server::QueryCore;
use crate::warden::namespaced::nat::OrigDst;

use super::{CONN_PENDING_CAP, ConnEvent, ConnKey, FlowCredit, SOCK_BUF, ToBackend};

/// Whether `ip` is a destination the kernel's connect path would
/// silently retarget to loopback — `::`→`::1`, `0.0.0.0`→`127.0.0.1`,
/// `::ffff:0.0.0.0`→`::ffff:127.0.0.1` (the BSD fold `select`'s route
/// probe relies on). A verdict names the spelled destination, never
/// loopback: dialing the unspecified form would reach a host-local
/// service no rule allowed, so such flows fail closed here.
pub(super) fn unspecified_target(ip: IpAddr) -> bool {
    crate::policy::host::socket_endpoint(ip).is_unspecified()
}

/// Real-TCP splice: connect to the original destination, then relay
/// until either side closes.
pub(super) async fn tcp_backend(
    key: ConnKey,
    orig: OrigDst,
    events: mpsc::Sender<ConnEvent>,
    mut from_stack: mpsc::Receiver<ToBackend>,
    credit: Arc<FlowCredit>,
) {
    let target = SocketAddr::new(orig.addr, orig.port);
    if unspecified_target(target.ip()) {
        tracing::debug!("namespaced tcp connect {target} refused: unspecified destination");
        let _ = events.send(ConnEvent::Fail { key }).await;
        return;
    }
    let mut stream = match TcpStream::connect(target).await {
        Ok(s) => s,
        Err(e) => {
            tracing::debug!("namespaced tcp connect {target} failed: {e}");
            let _ = events.send(ConnEvent::Fail { key }).await;
            return;
        }
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut buf = vec![0u8; SOCK_BUF];
    loop {
        // Per-conn backlog cap: while this flow's unwritten queue sits
        // at the ceiling the backend stops reading — the TCP window
        // then throttles the remote instead of growing `pending`.
        // Each pass builds a fresh `Notified` (`enable()` before the
        // re-check avoids a missed wake); a `Notified` is one-shot, so
        // re-awaiting a spent one would spin instead of sleeping.
        loop {
            // A dropped conn drops its sender too — stop waiting.
            if from_stack.is_closed() {
                return;
            }
            if credit.bytes.load(Ordering::Acquire) < CONN_PENDING_CAP {
                break;
            }
            let wait = credit.drained.notified();
            tokio::pin!(wait);
            wait.as_mut().enable();
            if credit.bytes.load(Ordering::Acquire) < CONN_PENDING_CAP {
                break;
            }
            wait.await;
        }
        tokio::select! {
            read = stream.read(&mut buf) => {
                match read {
                    Ok(0) => {
                        let _ = events.send(ConnEvent::Eof { key }).await;
                        return;
                    }
                    Ok(n) => {
                        // Blocking on the bounded channel is the
                        // backpressure: a workload not draining stops
                        // our backend reads instead of growing pending.
                        credit.bytes.fetch_add(n, Ordering::Release);
                        if events.send(ConnEvent::Data {
                            key,
                            bytes: buf[..n].to_vec(),
                        }).await.is_err() {
                            return;
                        }
                    }
                    Err(_) => {
                        let _ = events.send(ConnEvent::Fail { key }).await;
                        return;
                    }
                }
            }
            msg = from_stack.recv() => match msg {
                Some(ToBackend::Data(b)) => {
                    if stream.write_all(&b).await.is_err() {
                        let _ = events.send(ConnEvent::Fail { key }).await;
                        return;
                    }
                }
                Some(ToBackend::Fin) => {
                    let _ = stream.shutdown().await;
                }
                None => {
                    // Stack dropped the channel — conn torn down.
                    return;
                }
            },
        }
    }
}

/// DNS-over-TCP intercept backend: RFC 7766 framing in, gate pipeline
/// out — no real socket exists behind this conn. Replies share the
/// conn's `FlowCredit` backlog cap with the splice backend, so a
/// workload that floods queries without reading answers stalls at
/// `from_stack` instead of growing `Conn::pending` unboundedly.
pub(super) async fn dns_tcp_backend(
    key: ConnKey,
    gate: Arc<QueryCore>,
    peer: SocketAddr,
    events: mpsc::Sender<ConnEvent>,
    mut from_stack: mpsc::Receiver<ToBackend>,
    credit: Arc<FlowCredit>,
) {
    let mut buf: Vec<u8> = Vec::new();
    while let Some(msg) = from_stack.recv().await {
        match msg {
            ToBackend::Data(b) => buf.extend_from_slice(&b),
            ToBackend::Fin => {
                let _ = events.send(ConnEvent::Eof { key }).await;
                return;
            }
        }
        loop {
            if buf.len() < 2 {
                break;
            }
            let len = u16::from_be_bytes([buf[0], buf[1]]) as usize;
            if buf.len() < 2 + len {
                break;
            }
            let pkt: Vec<u8> = buf.drain(..2 + len).skip(2).collect();
            if let Some(resp) = gate.answer(&pkt, peer, true).await {
                // RFC 7766 on the way out too — the workload's stub
                // resolver reads a 2-byte length prefix before each
                // DNS message on a TCP transport.
                let Ok(resp_len) = u16::try_from(resp.len()) else {
                    // An unframeable answer is unanswerable — close
                    // rather than desync the stream.
                    let _ = events.send(ConnEvent::Fail { key }).await;
                    return;
                };
                let mut framed = Vec::with_capacity(2 + resp.len());
                framed.extend_from_slice(&resp_len.to_be_bytes());
                framed.extend_from_slice(&resp);
                credit.bytes.fetch_add(framed.len(), Ordering::Release);
                if events
                    .send(ConnEvent::Data { key, bytes: framed })
                    .await
                    .is_err()
                {
                    return;
                }
                // Same throttle as `tcp_backend`: while the conn's
                // unwritten queue sits at the ceiling, stop answering
                // further queries — the `from_stack` channel fills and
                // TCP backpressure, not `pending`, absorbs the flood.
                // Each pass builds a fresh `Notified` (`enable()` before
                // the re-check avoids a missed wake).
                loop {
                    // A dropped conn drops its sender too — stop waiting.
                    if from_stack.is_closed() {
                        return;
                    }
                    if credit.bytes.load(Ordering::Acquire) < CONN_PENDING_CAP {
                        break;
                    }
                    let wait = credit.drained.notified();
                    tokio::pin!(wait);
                    wait.as_mut().enable();
                    if credit.bytes.load(Ordering::Acquire) < CONN_PENDING_CAP {
                        break;
                    }
                    wait.await;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::net::Ipv4Addr;

    use crate::dnsgate::allowlist::DynamicAllowList;

    #[test]
    fn unspecified_targets_would_dial_loopback() {
        // Every spelling the kernel's connect path folds to loopback
        // must be refused at the dial sites — the verdict named the
        // spelled address, never `::1`/`127.0.0.1`.
        for a in ["::", "0.0.0.0", "::ffff:0.0.0.0"] {
            let ip: IpAddr = a.parse().unwrap();
            assert!(unspecified_target(ip), "{a} must be refused");
        }
        // Explicit opt-ins are not folded — loopback literals, mapped
        // addresses, and ordinary destinations stay dialable.
        for a in ["::1", "127.0.0.1", "::ffff:8.8.8.8", "2001:4860:4860::8888"] {
            let ip: IpAddr = a.parse().unwrap();
            assert!(!unspecified_target(ip), "{a} must not be refused");
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn dns_tcp_response_carries_rfc7766_length_prefix() {
        // Regression: the intercept backend used to emit the bare DNS
        // message — a stub resolver on TCP reads a 2-byte big-endian
        // length first, so an unframed reply desynced every answer.
        let log_dir = std::env::temp_dir().join(format!("dnstcp-{}", std::process::id())); // nosemgrep: rust.lang.security.temp-dir.temp-dir
        std::fs::create_dir_all(&log_dir).unwrap();
        let logger = crate::audit_log::AuditLogger::to_file(&log_dir.join("audit.jsonl")).unwrap();
        let gate = Arc::new(QueryCore::new(
            crate::dnsgate::server::GateConfig::default(),
            Arc::new(crate::policy::OutboundPolicy::default()),
            Arc::new(DynamicAllowList::new(16)),
            logger,
            uuid::Uuid::new_v4(),
            None,
        ));
        let key = ConnKey {
            ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            port: 53,
        };
        let peer: SocketAddr = "10.0.0.2:5333".parse().unwrap();
        let (events_tx, mut events_rx) = mpsc::channel(4);
        let (to_backend_tx, to_backend_rx) = mpsc::channel(4);
        let credit = Arc::new(FlowCredit {
            bytes: std::sync::atomic::AtomicUsize::new(0),
            drained: tokio::sync::Notify::new(),
        });
        let backend = tokio::spawn(dns_tcp_backend(
            key,
            gate,
            peer,
            events_tx,
            to_backend_rx,
            credit,
        ));
        // A framed query that cannot parse — the gate answers REFUSED
        // without ever consulting an upstream resolver.
        let pkt = b"\x12\x34not-a-dns-message";
        let mut frame = Vec::with_capacity(2 + pkt.len());
        frame.extend_from_slice(&(pkt.len() as u16).to_be_bytes());
        frame.extend_from_slice(pkt);
        to_backend_tx.send(ToBackend::Data(frame)).await.unwrap();
        let ev = tokio::time::timeout(std::time::Duration::from_secs(10), events_rx.recv())
            .await
            .expect("backend answers within timeout")
            .expect("event channel stays open");
        let ConnEvent::Data { bytes, .. } = ev else {
            panic!("expected a Data event carrying the framed answer");
        };
        let len = u16::from_be_bytes([bytes[0], bytes[1]]) as usize;
        assert_eq!(
            len + 2,
            bytes.len(),
            "the response must carry its RFC 7766 length prefix"
        );
        drop(to_backend_tx);
        let _ = tokio::time::timeout(std::time::Duration::from_secs(10), backend)
            .await
            .expect("backend exits once the channel closes");
        std::fs::remove_dir_all(&log_dir).ok();
    }
}
