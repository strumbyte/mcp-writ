//! The DNS gate service: UDP+TCP listeners, the per-query policy
//! pipeline, and audit emission.
//!
//! Per-query pipeline (each step maps to a documented decision):
//!
//! 1. `parse_query` — malformed/unanswerable packets get FORMERR /
//!    NOTIMP (or are dropped when no header exists to answer).
//! 2. `name_policy::evaluate` — the workload's queried name only,
//!    through the same canonicalization + `host_matches` semantics as
//!    the Auditor's argument checks. Denied names get NXDOMAIN/REFUSED
//!    and a `sandbox.network_denied` record — committed durably before
//!    the answer under `fail_closed`.
//! 3. `upstream::forward_*` — the allowed query is rebuilt under the
//!    canonical name and relayed; the answer must echo it.
//! 4. `wire::parse_response` + `DynamicAllowList` — the answer's CNAME
//!    chain is followed for the audit record (never re-judged), A/AAAA
//!    records on the chain mint TTL-scoped grants, and the answer is
//!    relayed verbatim (with a TC hint when it exceeds the client's
//!    UDP size).
//!
//! Nothing here inspects payload content — names, types, chain shape
//! and addresses are control-plane facts, which is all the gate needs.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::Semaphore;

use uuid::Uuid;

use crate::audit_log::{
    Action, AuditEvent, AuditLogger, EventType, Outcome, PolicyAuditContext, Severity,
};

use super::allowlist::DynamicAllowList;
use super::name_policy::{self, Verdict};
use super::upstream::{self, ForwardError};
use super::wire;

/// Largest UDP datagram read — anything bigger is truncated by the
/// socket and fails `parse_query` (FORMERR), which is the honest answer
/// to a packet we could not fully read.
const MAX_UDP_DATAGRAM: usize = 4096;
/// Upper bound on in-flight queries (UDP datagrams and per-connection
/// TCP messages share it). Saturation refuses new work with REFUSED —
/// a capacity refusal, not a policy verdict.
const MAX_INFLIGHT_QUERIES: usize = 256;
/// Upper bound on simultaneous TCP client connections.
const MAX_TCP_CONNECTIONS: usize = 64;
/// Idle timeout on a client TCP connection — keeps a parked connection
/// from holding its slot forever.
const TCP_IDLE_TIMEOUT: Duration = Duration::from_secs(60);
/// Default ceiling on live name→address grants.
const DEFAULT_MAX_GRANTS: usize = 16_384;
/// Largest TCP message frame accepted from a client (RFC 7766 framing
/// is 16-bit; a frame under the header length can never be a query).
const MAX_TCP_FRAME: usize = 65_535;

/// The refusal RCODE the gate answers denied names with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// NXDOMAIN — the name "does not exist" (the conventional signal a
    /// filtering resolver gives; resolvers treat it as cacheable).
    Nxdomain,
    /// REFUSED — the resolver refuses service for the name.
    Refused,
}

impl Refusal {
    pub fn parse(s: &str) -> Result<Self, String> {
        match s {
            "nxdomain" => Ok(Self::Nxdomain),
            "refused" => Ok(Self::Refused),
            other => Err(format!(
                "invalid refusal rcode '{other}', expected nxdomain or refused"
            )),
        }
    }

    pub(crate) fn rcode(self) -> u8 {
        match self {
            Self::Nxdomain => wire::RCODE_NXDOMAIN,
            Self::Refused => wire::RCODE_REFUSED,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Nxdomain => "nxdomain",
            Self::Refused => "refused",
        }
    }
}

/// Static gate configuration — parsed once at startup.
pub struct GateConfig {
    /// UDP and TCP listen address (one socket per protocol).
    pub listen: SocketAddr,
    /// Upstream resolver, an IP literal with optional port (default
    /// 53) — resolution never recurses through the gate.
    pub upstream: SocketAddr,
    /// RCODE for policy refusals.
    pub refusal: Refusal,
    /// Optional path the live allow list is exported to after every
    /// registration batch — the file contract for an IP-layer consumer
    /// in another process/namespace.
    pub allowlist_export: Option<PathBuf>,
    /// Live-grant ceiling for the allow list.
    pub max_grants: usize,
}

impl Default for GateConfig {
    fn default() -> Self {
        Self {
            listen: "127.0.0.1:1053".parse().unwrap(),
            upstream: "1.1.1.1:53".parse().unwrap(),
            refusal: Refusal::Refused,
            allowlist_export: None,
            max_grants: DEFAULT_MAX_GRANTS,
        }
    }
}

/// Shared per-query state, cheap to clone into spawned tasks.
struct Core {
    config: Arc<GateConfig>,
    outbound: Arc<crate::policy::OutboundPolicy>,
    allowlist: Arc<DynamicAllowList>,
    logger: AuditLogger,
    /// Launch correlation id stamped on every emitted record.
    launch_id: Uuid,
    /// Bound policy identity for `policy_context` / `target_server` —
    /// mirrors the lifecycle convention that a `default` id never
    /// names a server.
    policy_ctx: Option<PolicyAuditContext>,
    /// In-flight query ceiling shared by both transports.
    inflight: Arc<Semaphore>,
}

impl Core {
    fn event(
        &self,
        event_type: EventType,
        severity: Severity,
        outcome: Outcome,
        action: Action,
    ) -> AuditEvent {
        let mut event = AuditEvent::new(self.launch_id, event_type, severity, outcome, action);
        event.policy_context = self.policy_ctx.clone();
        if let Some(policy) = &self.policy_ctx
            && policy.id != "default"
        {
            event.target_server = Some(policy.id.clone());
        }
        event
    }

    /// Emit `sandbox.network_denied` — via `log_committed`, so a
    /// fail-closed logger persists the record before the refusal
    /// answer goes out (on a best-effort logger the call degrades to
    /// the ordinary non-blocking `log`).
    async fn emit_denied(
        &self,
        name: &str,
        qtype: Option<u16>,
        decision: &str,
        rule: Option<&str>,
        rcode: &'static str,
        client: SocketAddr,
    ) {
        let mut event = self.event(
            EventType::SandboxNetworkDenied,
            Severity::High,
            Outcome::Failure,
            Action::Denied,
        );
        let qtype = qtype.map(wire::qtype_name).unwrap_or_else(|| "-".into());
        let mut details = format!(
            "layer=name name={name} qtype={qtype} decision={decision} rcode={rcode} client={client} session_id={}",
            self.logger.session_id()
        );
        if let Some(rule) = rule {
            details.push_str(&format!(" rule={rule}"));
        }
        event.details = Some(details);
        if let Err(e) = self.logger.log_committed(event).await {
            // The writer is already marked failed; the refusal itself
            // does not depend on the record landing.
            tracing::error!("audit commit for denied query failed: {e}");
        }
    }

    /// Emit `sandbox.network_resolved` — an allowed query's resolution
    /// outcome, including the followed CNAME chain and the minted
    /// grants. Buffered (`log`): the availability guarantee on the
    /// allow path comes from `ensure_available`, not per-record fsync.
    fn emit_resolved(&self, obs: &ResolutionObs<'_>) {
        let ok = obs.result == "ok";
        let mut event = self.event(
            EventType::SandboxNetworkResolved,
            Severity::Info,
            if ok {
                Outcome::Success
            } else {
                Outcome::Failure
            },
            Action::Allowed,
        );
        let mut details = format!(
            "layer=name name={} qtype={} result={} client={} session_id={}",
            obs.name,
            wire::qtype_name(obs.qtype),
            obs.result,
            obs.client,
            self.logger.session_id()
        );
        if let Some(p) = obs.parsed {
            details.push_str(&format!(" rcode={}", wire::rcode_name(p.rcode)));
            if !p.chain.is_empty() {
                details.push_str(&format!(" chain={}", p.chain.join(">")));
            }
            if p.chain_truncated {
                details.push_str(" chain_truncated=true");
            }
            if !p.addrs.is_empty() {
                let addrs: Vec<String> = p.addrs.iter().map(|(a, _)| a.to_string()).collect();
                details.push_str(&format!(" addrs=[{}]", addrs.join(",")));
            }
            if let Some(ttl) = p.min_ttl {
                details.push_str(&format!(" ttl_min={ttl}"));
            }
            if !p.decoded {
                details.push_str(" wire=partially-undecoded");
            }
        }
        if obs.grants > 0 {
            details.push_str(&format!(" grants={}", obs.grants));
        }
        if obs.grants_refused > 0 {
            details.push_str(&format!(" grants_refused={}", obs.grants_refused));
        }
        event.details = Some(details);
        self.logger.log(event);
    }
}

/// One resolved-query observation for [`Core::emit_resolved`].
struct ResolutionObs<'a> {
    name: &'a str,
    qtype: u16,
    /// Outcome word recorded in details: `ok`, `upstream-timeout`, …
    result: &'a str,
    parsed: Option<&'a wire::ParsedResponse>,
    grants: usize,
    grants_refused: usize,
    client: SocketAddr,
}

/// Serve the gate until `shutdown` resolves. Binds both transports on
/// `config.listen`; a bind failure fails startup (the gate either
/// serves both or says why not).
///
/// `launch_id` correlates every emitted record with the caller's audit
/// bracket; `policy_ctx` stamps the bound policy identity (a `default`
/// id is never recorded as `target_server`, matching the lifecycle
/// convention).
pub async fn serve(
    config: GateConfig,
    policy: crate::policy::Policy,
    allowlist: Arc<DynamicAllowList>,
    logger: AuditLogger,
    launch_id: Uuid,
    policy_ctx: Option<PolicyAuditContext>,
    shutdown: impl std::future::Future<Output = ()>,
) -> std::io::Result<()> {
    let config = Arc::new(config);
    let core = Arc::new(Core {
        config: config.clone(),
        outbound: Arc::new(policy.network.outbound.clone()),
        allowlist,
        logger,
        launch_id,
        policy_ctx,
        inflight: Arc::new(Semaphore::new(MAX_INFLIGHT_QUERIES)),
    });

    let udp = Arc::new(UdpSocket::bind(config.listen).await?);
    let tcp = TcpListener::bind(config.listen).await?;
    tracing::info!(
        listen = %config.listen,
        upstream = %config.upstream,
        refusal = config.refusal.as_str(),
        "DNS gate listening (udp+tcp)"
    );

    tokio::pin!(shutdown);
    let tcp_conns = Arc::new(Semaphore::new(MAX_TCP_CONNECTIONS));
    let mut buf = vec![0u8; MAX_UDP_DATAGRAM];
    loop {
        tokio::select! {
            _ = &mut shutdown => break,
            accepted = tcp.accept() => {
                let (stream, peer) = match accepted {
                    Ok(v) => v,
                    Err(e) => {
                        tracing::warn!("dns-gate tcp accept failed: {e}");
                        continue;
                    }
                };
                let Ok(conn_permit) = tcp_conns.clone().try_acquire_owned() else {
                    tracing::warn!(%peer, "dns-gate tcp connection refused: at capacity");
                    drop(stream);
                    continue;
                };
                let core = core.clone();
                tokio::spawn(async move {
                    let _conn_permit = conn_permit;
                    serve_tcp_connection(stream, peer, core).await;
                });
            }
            received = udp.recv_from(&mut buf) => {
                let (n, peer) = match received {
                    Ok(v) => v,
                    Err(e) => {
                        tracing::warn!("dns-gate udp recv failed: {e}");
                        continue;
                    }
                };
                let pkt = buf[..n].to_vec();
                let permit = match core.inflight.clone().try_acquire_owned() {
                    Ok(p) => p,
                    Err(_) => {
                        // Saturated — refuse cheaply. Best-effort log
                        // (not committed): a capacity refusal is not a
                        // policy verdict.
                        if let Some(resp) = wire::refusal_answer(
                            &pkt,
                            wire::parse_query(&pkt).ok().as_ref(),
                            wire::RCODE_REFUSED,
                        ) {
                            let _ = udp.send_to(&resp, peer).await;
                        }
                        continue;
                    }
                };
                let core = core.clone();
                let udp = udp.clone();
                tokio::spawn(async move {
                    let _permit = permit;
                    if let Some(resp) = process_query(&pkt, peer, Transport::Udp, &core).await {
                        let _ = udp.send_to(&resp, peer).await;
                    }
                });
            }
        }
    }
    Ok(())
}

enum Transport {
    Udp,
    Tcp,
}

/// One TCP client connection: RFC 7766 length-prefixed messages,
/// answered in order until EOF, a malformed frame, or the idle
/// timeout. Each message still takes an in-flight slot so a single
/// pipelining client cannot crowd out the gate.
async fn serve_tcp_connection(mut stream: TcpStream, peer: SocketAddr, core: Arc<Core>) {
    loop {
        let frame = match tokio::time::timeout(TCP_IDLE_TIMEOUT, read_frame(&mut stream)).await {
            Ok(Some(frame)) => frame,
            _ => return,
        };
        let Ok(_permit) = core.inflight.clone().try_acquire_owned() else {
            if let Ok(q) = wire::parse_query(&frame)
                && let Some(resp) = wire::refusal_answer(&frame, Some(&q), wire::RCODE_REFUSED)
            {
                // Same budget as the read side — a client that never
                // drains must not hold its connection slot forever.
                match tokio::time::timeout(TCP_IDLE_TIMEOUT, write_frame(&mut stream, &resp)).await
                {
                    Ok(Ok(())) => {}
                    Ok(Err(_)) | Err(_) => return,
                }
            }
            continue;
        };
        match process_query(&frame, peer, Transport::Tcp, &core).await {
            Some(resp) => {
                match tokio::time::timeout(TCP_IDLE_TIMEOUT, write_frame(&mut stream, &resp)).await
                {
                    Ok(Ok(())) => {}
                    // Write error or a stalled client — close rather
                    // than hold the slot.
                    Ok(Err(_)) | Err(_) => return,
                }
            }
            // Unanswerable packet — close rather than desync.
            None => return,
        }
    }
}

async fn read_frame(stream: &mut TcpStream) -> Option<Vec<u8>> {
    let mut len_buf = [0u8; 2];
    stream.read_exact(&mut len_buf).await.ok()?;
    let len = u16::from_be_bytes(len_buf) as usize;
    if !(wire::HEADER_LEN..=MAX_TCP_FRAME).contains(&len) {
        return None;
    }
    let mut frame = vec![0u8; len];
    stream.read_exact(&mut frame).await.ok()?;
    Some(frame)
}

async fn write_frame(stream: &mut TcpStream, msg: &[u8]) -> std::io::Result<()> {
    let len = u16::try_from(msg.len())
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "oversize answer"))?;
    stream.write_all(&len.to_be_bytes()).await?;
    stream.write_all(msg).await
}

/// The full per-query pipeline. Returns the answer bytes to send, or
/// `None` when the packet was unanswerable (Drop) or the connection is
/// better closed than answered.
async fn process_query(
    pkt: &[u8],
    peer: SocketAddr,
    transport: Transport,
    core: &Core,
) -> Option<Vec<u8>> {
    let q = match wire::parse_query(pkt) {
        Ok(q) => q,
        Err(e) => {
            return match e.reject {
                wire::QueryReject::Drop => None,
                wire::QueryReject::FormErr | wire::QueryReject::NotImp => {
                    let (decision, rcode) = match e.reject {
                        wire::QueryReject::FormErr => ("protocol-error", wire::RCODE_FORMERR),
                        _ => ("protocol-error", wire::RCODE_NOTIMP),
                    };
                    core.emit_denied(
                        e.qname.as_deref().unwrap_or("-"),
                        e.qtype,
                        decision,
                        None,
                        match e.reject {
                            wire::QueryReject::FormErr => "formerr",
                            _ => "notimp",
                        },
                        peer,
                    )
                    .await;
                    wire::refusal_answer(pkt, None, rcode)
                }
            };
        }
    };

    // The gate serves name→address resolution only — a non-IN class
    // (CHAOS, HS, ANY) is outside the name layer's scope and refused.
    if q.qclass != 1 {
        core.emit_denied(
            &q.qname,
            Some(q.qtype),
            "unsupported-class",
            None,
            "refused",
            peer,
        )
        .await;
        return wire::refusal_answer(pkt, Some(&q), wire::RCODE_REFUSED);
    }

    let eval = name_policy::evaluate(&core.outbound, &q.qname);
    if let Verdict::Deny(reason) = &eval.verdict {
        core.emit_denied(
            &eval.canonical,
            Some(q.qtype),
            reason.decision(),
            reason.rule(),
            core.config.refusal.as_str(),
            peer,
        )
        .await;
        return wire::refusal_answer(pkt, Some(&q), core.config.refusal.rcode());
    }

    // Fail-closed audit availability gate — an allowed answer must be
    // recordable before it goes out; refuse rather than resolve
    // unaudited. (No-op on a best-effort logger.)
    if let Err(e) = core.logger.ensure_available() {
        tracing::error!("audit unavailable, refusing allowed query (fail-closed): {e}");
        return wire::refusal_answer(pkt, Some(&q), wire::RCODE_SERVFAIL);
    }

    let Some(fwd) = wire::build_forward_query(pkt, &q, &eval.canonical) else {
        // The canonical name could not be wire-encoded — unreachable in
        // practice (canonicalization bounds the name), but never panic:
        // answer SERVFAIL and record it.
        core.emit_resolved(&ResolutionObs {
            name: &eval.canonical,
            qtype: q.qtype,
            result: "encode-error",
            parsed: None,
            grants: 0,
            grants_refused: 0,
            client: peer,
        });
        return wire::refusal_answer(pkt, Some(&q), wire::RCODE_SERVFAIL);
    };

    let resp = match transport {
        Transport::Udp => {
            upstream::forward_udp(core.config.upstream, &fwd, q.id, &eval.canonical).await
        }
        Transport::Tcp => {
            upstream::forward_tcp(core.config.upstream, &fwd, q.id, &eval.canonical).await
        }
    };
    let resp = match resp {
        Ok(r) => r,
        Err(e) => {
            let result = match e {
                ForwardError::Timeout => "upstream-timeout",
                ForwardError::Io(_) => "upstream-io-error",
                ForwardError::Mismatch => "upstream-mismatch",
            };
            if let ForwardError::Io(io) = &e {
                tracing::warn!("dns-gate upstream io error: {io}");
            }
            core.emit_resolved(&ResolutionObs {
                name: &eval.canonical,
                qtype: q.qtype,
                result,
                parsed: None,
                grants: 0,
                grants_refused: 0,
                client: peer,
            });
            return wire::refusal_answer(pkt, Some(&q), wire::RCODE_SERVFAIL);
        }
    };

    let parsed = wire::parse_response(&resp, &eval.canonical);

    // Fail-closed audit availability, again — the sink may have died
    // during the upstream exchange. Check BEFORE minting grants: an
    // unrecorded resolution must not leave name→address authority in
    // the allow list an IP-layer consumer trusts. (No-op on a
    // best-effort logger.)
    if let Err(e) = core.logger.ensure_available() {
        tracing::error!("audit unavailable after resolution, refusing to relay (fail-closed): {e}");
        return wire::refusal_answer(pkt, Some(&q), wire::RCODE_SERVFAIL);
    }

    // The answer mints grants under the canonical name — chain members
    // are observed, but grants name what the workload asked for. The
    // lifetime is the chain-MINIMUM ttl: an address reached through a
    // CNAME must not outlive the alias that vended it. A zero minimum
    // expires before use — nothing is registered.
    let mut registered = 0usize;
    let mut refused_grants = 0usize;
    if parsed.decoded
        && let Some(grant_ttl) = parsed.min_ttl.filter(|t| *t > 0)
    {
        for (addr, _) in &parsed.addrs {
            if core.allowlist.register(
                &eval.canonical,
                *addr,
                Duration::from_secs(u64::from(grant_ttl)),
            ) {
                registered += 1;
            } else {
                refused_grants += 1;
            }
        }
    }
    if refused_grants > 0 {
        tracing::warn!(
            name = %eval.canonical,
            refused_grants,
            "dns-gate allow list at capacity — grants refused"
        );
    }
    if let Some(path) = &core.config.allowlist_export
        && let Err(e) = core.allowlist.export_to(path)
    {
        tracing::error!("dns-gate allow list export failed: {e}");
    }
    core.emit_resolved(&ResolutionObs {
        name: &eval.canonical,
        qtype: q.qtype,
        result: "ok",
        parsed: Some(&parsed),
        grants: registered,
        grants_refused: refused_grants,
        client: peer,
    });

    // UDP answers are capped at the client's advertised size — anything
    // bigger gets a TC hint so the client retries over TCP.
    match transport {
        Transport::Tcp => Some(resp),
        Transport::Udp => {
            let cap = q.edns_udp_size.unwrap_or(512).max(512) as usize;
            if resp.len() > cap {
                Some(wire::truncated_answer(pkt, &q))
            } else {
                Some(resp)
            }
        }
    }
}
