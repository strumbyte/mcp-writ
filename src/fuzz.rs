//! Boundary-parser entry points for the sibling `fuzz/` crate.
//!
//! These functions front the code paths that first interpret
//! attacker-controlled bytes: stdio JSON-RPC frames, MCP/JSON-RPC
//! interpretation, the DNS wire format the embedded gate handles, and —
//! on Linux — TUN frames entering the namespaced egress proxy. Each
//! maps a parser to a bytes-in / summary-out shape the fuzz harness
//! can drive without runtimes, sockets, or other OS resources.
//!
//! Hidden from the documented API: the module exists so the fuzz
//! package (a sibling kept out of `default-members`) reaches
//! `pub(crate)`-level parsers through one reviewed seam instead of
//! widening each parser's own visibility. Summaries carry verdicts and
//! bounded wire fields — attacker input the harness generated anyway.

use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll, Waker};

// --------------------------------------------------------------------
// framing — stdio JSON-RPC frames
// --------------------------------------------------------------------

/// Drive a future that only ever polls synchronous in-memory readers.
/// The fuzz harness drives `&[u8]`-backed readers, which never park —
/// a `Pending` here means a sleeping/syscall future escaped into the
/// boundary, which is a bug, not a state to wait on.
fn block_on<F: Future>(fut: F) -> F::Output {
    let waker = Waker::noop();
    let mut cx = Context::from_waker(waker);
    let mut fut = std::pin::pin!(fut);
    match fut.as_mut().poll(&mut cx) {
        Poll::Ready(v) => v,
        // A noop waker can never be re-polled, so a Pending here is a
        // bug escaping into the boundary — not a state to wait on.
        Poll::Pending => panic!("boundary reader parked on an in-memory reader"),
    }
}

/// In-memory `AsyncBufRead` that records consumption so the harness can
/// check the reader drained (or, on fail-fast, deliberately did not).
/// `window` caps the slice each `fill_buf` hands out — 0 serves the
/// whole remainder at once — so the generator can also drive frames
/// that span buffer refills (the multi-`fill_buf` accumulation paths a
/// single-shot buffer never reaches).
struct Tracked<'a> {
    data: &'a [u8],
    pos: usize,
    window: usize,
}

impl Tracked<'_> {
    /// End offset of the slice the next `fill_buf`/`read` exposes.
    fn chunk_end(&self) -> usize {
        if self.window == 0 {
            self.data.len()
        } else {
            self.pos.saturating_add(self.window).min(self.data.len())
        }
    }
}

impl tokio::io::AsyncBufRead for Tracked<'_> {
    fn poll_fill_buf(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<&[u8]>> {
        Poll::Ready(Ok(&self.data[self.pos..self.chunk_end()]))
    }
    fn consume(mut self: Pin<&mut Self>, amt: usize) {
        self.pos += amt;
    }
}

impl tokio::io::AsyncRead for Tracked<'_> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let avail = &self.data[self.pos..self.chunk_end()];
        let n = avail.len().min(buf.remaining());
        buf.put_slice(&avail[..n]);
        self.pos += n;
        Poll::Ready(Ok(()))
    }
}

/// Outcome counters for one bounded-read sweep over an input.
#[derive(Debug, Default)]
pub struct FrameStats {
    /// Complete frames within `max_bytes` (`Line` outcomes).
    pub lines: usize,
    /// Oversized frames (`Oversize` outcomes — the resumable variant).
    pub oversize: usize,
    /// Oversized frames EOF ended without a newline.
    pub unterminated_oversize: usize,
    /// Longest in-limit frame body. Lossy-UTF8 can inflate past
    /// `max_bytes` (one bad byte becomes 3-byte U+FFFD), so this is a
    /// statistic, not a bound.
    pub longest_line: usize,
    /// Longest oversized frame body.
    pub longest_oversize: usize,
    /// `read_line_bounded` stopped on `TooLarge` (fail-fast variant).
    pub fail_fast: bool,
    /// Bytes the reader consumed before EOF/error — the resumable
    /// variant must always end at `data.len()`.
    pub consumed: usize,
}

/// Feed `data` through [`framing::read_frame_bounded`](crate::framing)
/// until EOF — the Auditor's resumable variant, which drains oversized
/// frames through their newline. `window` caps each `fill_buf` chunk
/// (0 = one shot) so frames spanning buffer refills are exercised too.
/// Asserts the module's own invariants
/// (bounded head/tail windows, `bytes > max_bytes`, full consumption)
/// so a violation is the fuzz finding rather than a quiet statistic.
pub fn drain_frames(data: &[u8], max_bytes: usize, window: usize) -> FrameStats {
    use crate::framing::{BoundedFrame, read_frame_bounded};

    let mut r = Tracked {
        data,
        pos: 0,
        window,
    };
    let mut stats = FrameStats::default();
    loop {
        match block_on(read_frame_bounded(&mut r, max_bytes)) {
            Ok(None) => break,
            Ok(Some(BoundedFrame::Line(line))) => {
                stats.lines += 1;
                stats.longest_line = stats.longest_line.max(line.len());
            }
            Ok(Some(BoundedFrame::Oversize(f))) => {
                // OVERSIZE_WINDOW_BYTES — the bounded head/tail windows.
                assert!(f.head.len() <= 8 * 1024, "oversize head window overflowed");
                assert!(f.tail.len() <= 8 * 1024, "oversize tail window overflowed");
                assert!(f.bytes > max_bytes, "undersized frame marked oversize");
                stats.oversize += 1;
                stats.unterminated_oversize += usize::from(!f.terminated);
                stats.longest_oversize = stats.longest_oversize.max(f.bytes);
            }
            Err(e) => panic!("read_frame_bounded on an in-memory reader: {e}"),
        }
    }
    stats.consumed = r.pos;
    assert_eq!(stats.consumed, data.len(), "frame drain stopped before EOF");
    stats
}

/// Feed `data` through [`framing::read_line_bounded`](crate::framing)
/// until EOF or `TooLarge` — the launcher's fail-fast variant: oversize
/// is fatal and the reader keeps the refused frame mid-stream, which
/// `consumed` < `data.len()` then records. `window` caps each
/// `fill_buf` chunk (0 = one shot).
pub fn drain_lines(data: &[u8], max_bytes: usize, window: usize) -> FrameStats {
    use crate::framing::{FramingError, read_line_bounded};

    let mut r = Tracked {
        data,
        pos: 0,
        window,
    };
    let mut stats = FrameStats::default();
    loop {
        match block_on(read_line_bounded(&mut r, max_bytes)) {
            Ok(None) => break,
            Ok(Some(line)) => {
                stats.lines += 1;
                stats.longest_line = stats.longest_line.max(line.len());
            }
            Err(FramingError::TooLarge { bytes, limit }) => {
                assert!(bytes > limit, "TooLarge fired inside the byte limit");
                stats.fail_fast = true;
                break;
            }
            Err(e) => panic!("read_line_bounded on an in-memory reader: {e}"),
        }
    }
    stats.consumed = r.pos;
    stats
}

// --------------------------------------------------------------------
// protocol — JSON-RPC interpretation of one frame body
// --------------------------------------------------------------------

/// Everything the protocol layer concluded about one line. One call
/// walks every line-level classifier plus, when the text parses as
/// JSON, the `fields` member extractors on `params`/`result`.
#[derive(Debug, Default)]
pub struct JsonrpcSummary {
    /// `nojson` accepted the line as JSON.
    pub valid_json: bool,
    pub is_response: bool,
    pub is_notification: bool,
    pub id: Option<i64>,
    /// JSON-RPC error code, when an `error` member parsed.
    pub error_code: Option<i64>,
    /// `result.protocolVersion` of an initialize response, verbatim.
    pub initialize_result_version: Option<String>,
    /// `ProbeClassification` variant name — the enum itself stays a
    /// protocol detail.
    pub probe: &'static str,
    /// `VersionProbeOutcome` variant name.
    pub outcome: &'static str,
    /// `parse_tools_list_response_page` accepted the line.
    pub tools_page_ok: bool,
    pub tool_count: usize,
    /// `_meta` was present on `params` or `result` (maybe malformed).
    pub meta_present: bool,
    pub meta_malformed: bool,
    /// Flattened capability names across `params`/`result`.
    pub capability_names: usize,
    /// `initialize` params carried the three required members.
    pub initialize_shape_complete: bool,
    /// `notifications` filter names the extractor could not map.
    pub listen_unknowns: usize,
    /// `inputRequests` member state: "absent" | "map" | "malformed" | "overrun".
    pub input_requests: &'static str,
    pub input_request_entries: usize,
    /// Member count of the `inputRequests` object itself — 0 for
    /// absent/null/non-object. The harness compares this against the
    /// verdict to check the cap exactly, not just its lower bound.
    pub input_request_members: usize,
}

/// Run the protocol interpretation boundary on one frame body.
pub fn jsonrpc_line(line: &str) -> JsonrpcSummary {
    use crate::protocol::{self as p, fields, tools_list};

    let mut s = JsonrpcSummary {
        input_requests: "absent",
        ..JsonrpcSummary::default()
    };
    s.is_response = p::jsonrpc_is_response(line);
    s.is_notification = p::is_jsonrpc_notification(line);
    s.id = p::jsonrpc_id_as_i64(line);
    s.error_code = p::parse_jsonrpc_error(line).map(|e| e.code);
    s.initialize_result_version = p::parse_initialize_protocol_version(line);
    let probe = p::classify_probe_line(line);
    s.probe = match &probe {
        p::ProbeClassification::Mcp2026July28Discover { .. } => "discover",
        p::ProbeClassification::Mcp2026July28Error { .. } => "error",
        p::ProbeClassification::TryMcp2025November25 => "try-2025-11-25",
    };
    s.outcome = match p::classification_to_outcome(probe) {
        p::VersionProbeOutcome::UseMcp2026July28 => "use-2026-07-28",
        p::VersionProbeOutcome::UseMcp2025November25 => "use-2025-11-25",
        p::VersionProbeOutcome::TryMcp2025November25 => "try-2025-11-25",
        p::VersionProbeOutcome::Unsupported { .. } => "unsupported",
    };
    if let Ok(page) = tools_list::parse_tools_list_response_page(line) {
        s.tools_page_ok = true;
        s.tool_count = page.tools.len();
    }

    // The line-level helpers parse `line.trim()` — mirror that here so
    // `valid_json` agrees with what they saw.
    let Ok(json) = nojson::RawJson::parse(line.trim()) else {
        return s;
    };
    s.valid_json = true;
    let root = json.value();
    let params = root.to_member("params").ok().and_then(|m| m.optional());
    let result = root.to_member("result").ok().and_then(|m| m.optional());
    for holder in [params, result].into_iter().flatten() {
        if let Some(meta) = fields::request_meta(holder) {
            s.meta_present = true;
            s.meta_malformed |= meta.malformed;
        }
        if let Some(caps) = holder
            .to_member("capabilities")
            .ok()
            .and_then(|m| m.optional())
        {
            s.capability_names += fields::capability_names(caps).len();
        }
    }
    s.initialize_shape_complete = fields::initialize_shape(params).complete();
    s.listen_unknowns = fields::listen_filters(params).unknown.len();
    for name in ["uri", "level", "reason", "name", "cursor"] {
        let _ = fields::string_param(params, name);
    }
    let _ = fields::request_id_param(params);
    let _ = fields::progress_token_param(params);
    let _ = fields::listen_subscription_id(params);
    if let Some(result) = result {
        let _ = fields::result_type(result);
        let _ = fields::ttl_ms(result);
        let _ = fields::cache_scope(result);
        let _ = fields::request_state(result);
        if let Some(members) = result
            .to_member("inputRequests")
            .ok()
            .and_then(|m| m.optional())
            .and_then(|v| v.to_object().ok())
        {
            s.input_request_members = members.count();
        }
        match fields::input_requests(result) {
            fields::InputRequests::Absent => {}
            fields::InputRequests::Map(entries) => {
                s.input_requests = "map";
                s.input_request_entries = entries.len();
            }
            fields::InputRequests::Malformed => s.input_requests = "malformed",
            fields::InputRequests::Overrun => s.input_requests = "overrun",
        }
    }
    s
}

// --------------------------------------------------------------------
// dnsgate — DNS wire format between workloads, gate, and upstreams
// --------------------------------------------------------------------

/// `parse_query` verdict translated out of the wire types.
#[derive(Debug)]
pub enum DnsQueryOutcome {
    /// Unanswerable — dropped without a reply.
    Drop,
    /// FORMERR reply owed.
    FormErr,
    /// NOTIMP reply owed.
    NotImp,
    /// Accepted query.
    Ok(DnsQuerySummary),
}

/// Fields of an accepted [`DnsQueryOutcome::Ok`] worth asserting on.
#[derive(Debug)]
pub struct DnsQuerySummary {
    pub id: u16,
    /// Header flag bits the gate relays verbatim.
    pub flags_relay: u16,
    pub qname: String,
    pub qtype: u16,
    pub qclass: u16,
    /// Offset just past the question section.
    pub question_end: usize,
    /// Offset where the additional section begins.
    pub additional_start: usize,
    pub arcount: u16,
    pub edns_udp_size: Option<u16>,
}

/// Decode a workload→gate query (`wire::parse_query`).
pub fn dns_parse_query(pkt: &[u8]) -> DnsQueryOutcome {
    use crate::dnsgate::wire::{self, QueryReject};
    match wire::parse_query(pkt) {
        Ok(q) => DnsQueryOutcome::Ok(DnsQuerySummary {
            id: q.id,
            flags_relay: q.flags_relay,
            qname: q.qname,
            qtype: q.qtype,
            qclass: q.qclass,
            question_end: q.question_end,
            additional_start: q.additional_start,
            arcount: q.arcount,
            edns_udp_size: q.edns_udp_size,
        }),
        Err(e) => match e.reject {
            QueryReject::Drop => DnsQueryOutcome::Drop,
            QueryReject::FormErr => DnsQueryOutcome::FormErr,
            QueryReject::NotImp => DnsQueryOutcome::NotImp,
        },
    }
}

/// The gate's forward composition: decode the workload query, then
/// rebuild it under `canonical` (`wire::build_forward_query`). `None`
/// when the query was refused at decode.
pub fn dns_forward_query(pkt: &[u8], canonical: &str) -> Option<Vec<u8>> {
    let q = crate::dnsgate::wire::parse_query(pkt).ok()?;
    crate::dnsgate::wire::build_forward_query(pkt, &q, canonical)
}

/// The gate's refusal answer (`wire::refusal_answer`) — works on
/// unparseable packets too (header echo only).
pub fn dns_refusal(pkt: &[u8], rcode: u8) -> Option<Vec<u8>> {
    let q = crate::dnsgate::wire::parse_query(pkt).ok();
    crate::dnsgate::wire::refusal_answer(pkt, q.as_ref(), rcode)
}

/// The gate's truncated-TC answer (`wire::truncated_answer`); `None`
/// when the query cannot be decoded far enough to echo.
pub fn dns_truncated(pkt: &[u8]) -> Option<Vec<u8>> {
    let q = crate::dnsgate::wire::parse_query(pkt).ok()?;
    Some(crate::dnsgate::wire::truncated_answer(pkt, &q))
}

/// `wire::encode_name` — dotted text to wire labels.
pub fn dns_encode_name(name: &str) -> Option<Vec<u8>> {
    crate::dnsgate::wire::encode_name(name)
}

/// `parse_response` output translated out of the wire types.
#[derive(Debug)]
pub struct DnsResponseSummary {
    pub rcode: u8,
    /// `false` — the response failed closed (malformed records or
    /// trailing garbage); the gate answers SERVFAIL rather than
    /// trusting anything extracted.
    pub decoded: bool,
    /// Alias chain (CNAME/DNAME/SVCB/HTTPS) — bounded by the parser.
    pub chain: Vec<String>,
    pub chain_truncated: bool,
    /// (address, TTL) pairs collected from the alias leaf.
    pub addrs: Vec<(std::net::IpAddr, u32)>,
    pub min_ttl: Option<u32>,
    /// Names in the authority/additional sections the verdict needs.
    pub extra_names: Vec<String>,
    pub extra_addrs: Vec<std::net::IpAddr>,
}

/// `canonical_name` — the forwarded-name identity the gate computes
/// before upstream exchange; `parse_response`/`build_forward_query`
/// expect this form, not a wire-verbatim qname.
pub fn dns_canonical_name(name: &str) -> String {
    crate::dnsgate::canonical_name(name)
}

/// Parse an upstream→gate response against the forwarded name
/// (`wire::parse_response`).
pub fn dns_parse_response(resp: &[u8], forwarded_name: &str) -> DnsResponseSummary {
    let p = crate::dnsgate::wire::parse_response(resp, forwarded_name);
    DnsResponseSummary {
        rcode: p.rcode,
        decoded: p.decoded,
        chain: p.chain,
        chain_truncated: p.chain_truncated,
        addrs: p.addrs,
        min_ttl: p.min_ttl,
        extra_names: p.extra_names,
        extra_addrs: p.extra_addrs,
    }
}

/// `wire::response_matches` — plausibility gate for upstream answers.
pub fn dns_response_matches(
    resp: &[u8],
    id: u16,
    canonical: &str,
    qtype: u16,
    qclass: u16,
) -> bool {
    crate::dnsgate::wire::response_matches(resp, id, canonical, qtype, qclass)
}

/// `wire::response_truncated` — TC bit check.
pub fn dns_response_truncated(resp: &[u8]) -> bool {
    crate::dnsgate::wire::response_truncated(resp)
}

// --------------------------------------------------------------------
// namespaced egress proxy — TUN frames and NAT rewrite (Linux only)
// --------------------------------------------------------------------

#[cfg(target_os = "linux")]
mod ns {
    use std::net::IpAddr;

    /// `packet::Classified` translated to a pub shape — same verdicts
    /// and bounded wire fields (the payload is harness-generated
    /// attacker input, not secret state).
    #[derive(Debug)]
    pub enum TunClassified {
        /// TCP segment handed to the smoltcp stack — `len` is the
        /// captured IP packet length.
        Tcp {
            len: usize,
        },
        /// UDP/53 intercepted for the embedded DNS gate — the payload
        /// is the gate-bound DNS packet itself.
        UdpDns {
            src_port: u16,
            dst_port: u16,
            payload: Vec<u8>,
        },
        /// UDP datagram for the per-datagram relay.
        Udp {
            src_port: u16,
            dst_port: u16,
            payload: Vec<u8>,
        },
        /// Version nibble neither IPv4 nor IPv6.
        DropNonIp,
        /// IPv6 next-header not bare TCP/UDP (extension chains, ICMPv6).
        DropV6Ext,
        DropFragment,
        DropProto,
        DropMalformed,
    }

    /// `packet::classify` — the reader task's first decision per frame.
    pub fn tun_classify(frame: &[u8], dns_intercept: bool) -> TunClassified {
        use crate::warden::namespaced::stack::packet::{Classified, GateCtx, classify};
        match classify(frame, dns_intercept) {
            Classified::Tcp(pkt) => TunClassified::Tcp { len: pkt.len() },
            Classified::UdpDns(req) => {
                let (src_port, dst_port) = match req.ctx {
                    GateCtx::Udp {
                        src_port, dst_port, ..
                    } => (src_port, dst_port),
                };
                TunClassified::UdpDns {
                    src_port,
                    dst_port,
                    payload: req.pkt,
                }
            }
            Classified::Udp(d) => TunClassified::Udp {
                src_port: d.src_port,
                dst_port: d.dst_port,
                payload: d.payload,
            },
            Classified::DropNonIp => TunClassified::DropNonIp,
            Classified::DropV6Ext => TunClassified::DropV6Ext,
            Classified::DropFragment => TunClassified::DropFragment,
            Classified::DropProto => TunClassified::DropProto,
            Classified::DropMalformed => TunClassified::DropMalformed,
        }
    }

    /// `nat::parse_tcp_tuple` — the DNAT path's refusal check; the
    /// harness also uses it to verify rewrites.
    pub fn tun_tcp_tuple(frame: &[u8]) -> Option<(IpAddr, IpAddr, u16, u16)> {
        crate::warden::namespaced::nat::parse_tcp_tuple(frame)
    }

    /// `packet::craft_udp_packet` — build the IP/UDP reply; the harness
    /// re-classifies the output for a round-trip check.
    pub fn craft_udp_reply(
        src: IpAddr,
        src_port: u16,
        dst: IpAddr,
        dst_port: u16,
        payload: &[u8],
    ) -> Vec<u8> {
        crate::warden::namespaced::stack::packet::craft_udp_packet(
            src, src_port, dst, dst_port, payload,
        )
    }

    /// A `dnat_in` rewrite plus the post-rewrite tuple, so the harness
    /// asserts without re-parsing.
    #[derive(Debug)]
    pub struct NatRewrite {
        /// The original destination the workload dialed.
        pub orig_addr: IpAddr,
        pub orig_port: u16,
        /// Intercepted as DNS-over-TCP (`orig_port == 53` under an
        /// armed gate).
        pub dns_tcp: bool,
        /// Allocated stack-side source port.
        pub new_src_port: u16,
        /// Rewritten destination — the proxy gateway.
        pub new_dst: IpAddr,
        /// Rewritten destination port (`TCP_NAT_PORT`/`DNS_TCP_NAT_PORT`).
        pub new_dst_port: u16,
    }

    /// `nat::NatTable` driven statefully by the harness: workload
    /// frames in via `dnat_in`, stack replies out via `rev_nat_out`.
    pub struct NatProbe {
        inner: crate::warden::namespaced::nat::NatTable,
    }

    impl NatProbe {
        pub fn new(dns_intercept: bool) -> Self {
            Self {
                inner: crate::warden::namespaced::nat::NatTable::new(dns_intercept),
            }
        }

        /// `dnat_in` plus the post-rewrite tuple. `None` = the NAT
        /// path's own refusal (non-TCP, malformed, no flow behind it,
        /// table cap).
        pub fn dnat_in(&mut self, frame: &mut [u8]) -> Option<NatRewrite> {
            let orig = self.inner.dnat_in(frame)?;
            let (_, new_dst, new_src_port, new_dst_port) =
                crate::warden::namespaced::nat::parse_tcp_tuple(frame)?;
            Some(NatRewrite {
                orig_addr: orig.addr,
                orig_port: orig.port,
                dns_tcp: orig.dns_tcp,
                new_src_port,
                new_dst,
                new_dst_port,
            })
        }

        /// `rev_nat_out` plus the restored (src, src_port, dst_port) —
        /// the original destination the workload dialed and its real
        /// source port.
        pub fn rev_nat_out(&mut self, frame: &mut [u8]) -> Option<(IpAddr, u16, u16)> {
            if !self.inner.rev_nat_out(frame) {
                return None;
            }
            let (src, _, src_port, dst_port) =
                crate::warden::namespaced::nat::parse_tcp_tuple(frame)?;
            Some((src, src_port, dst_port))
        }

        /// `NatTable::mark_associated` — the stack accepted the flow.
        pub fn mark_associated(&mut self, workload: IpAddr, port: u16) {
            self.inner.mark_associated(workload, port);
        }

        /// `NatTable::remove` — forget a closed flow by its stack-side
        /// (allocated) port.
        pub fn remove(&mut self, workload: IpAddr, port: u16) {
            self.inner.remove(workload, port);
        }

        /// `NatTable::reap_if_due` — the harness supplies the clock so
        /// expired-mapping paths are reachable without wall time.
        pub fn reap_at(&mut self, at: std::time::Instant) {
            self.inner.reap_if_due(at);
        }
    }

    // Fixed addressing the workload legitimately emits from — exposed
    // so the generator can aim flows at mintable tuples rather than
    // hardcoding the constants.
    pub const WORKLOAD_V4: std::net::Ipv4Addr = crate::warden::namespaced::WORKLOAD_V4;
    pub const WORKLOAD_V6: std::net::Ipv6Addr = crate::warden::namespaced::WORKLOAD_V6;
    pub const GATEWAY_V4: std::net::Ipv4Addr = crate::warden::namespaced::GATEWAY_V4;
    pub const GATEWAY_V6: std::net::Ipv6Addr = crate::warden::namespaced::GATEWAY_V6;
    pub const TCP_NAT_PORT: u16 = crate::warden::namespaced::TCP_NAT_PORT;
    pub const DNS_TCP_NAT_PORT: u16 = crate::warden::namespaced::DNS_TCP_NAT_PORT;
    /// First allocatable stack-side source port (`nat::ALLOC_BASE`) —
    /// the minted-port lower bound the harness asserts.
    pub const ALLOC_BASE: u16 = crate::warden::namespaced::nat::ALLOC_BASE;
    /// Live-mapping ceiling (`nat::MAX_NAT_MAPPINGS`) — the refusal
    /// bound the harness asserts floods hit exactly.
    pub const MAX_NAT_MAPPINGS: usize = crate::warden::namespaced::nat::MAX_NAT_MAPPINGS;
}

#[cfg(target_os = "linux")]
pub use ns::*;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn drain_frames_recovers_oversize() {
        let big = vec![b'x'; 300];
        let mut data = big.clone();
        data.push(b'\n');
        data.extend_from_slice(b"ok\n");
        // One-shot and chunked readers see the same stream.
        for window in [0usize, 7] {
            let stats = drain_frames(&data, 64, window);
            assert_eq!(stats.oversize, 1);
            assert_eq!(stats.lines, 1);
            assert_eq!(stats.consumed, data.len());
        }
    }

    #[test]
    fn drain_lines_fails_fast() {
        let mut data = vec![b'x'; 200];
        data.push(b'\n');
        data.extend_from_slice(b"next\n");
        for window in [0usize, 5] {
            let stats = drain_lines(&data, 100, window);
            assert!(stats.fail_fast);
            // Not drained: the reader stops mid-frame.
            assert!(stats.consumed < data.len());
        }
    }

    #[test]
    fn jsonrpc_line_handles_garbage_and_valid() {
        let s = jsonrpc_line("not json at all");
        assert!(!s.valid_json);
        let s = jsonrpc_line(r#"{"jsonrpc":"2.0","id":1,"result":{"tools":[]}}"#);
        assert!(s.valid_json);
        assert!(s.is_response);
        assert!(s.tools_page_ok);
    }

    #[test]
    fn dns_round_trip_smoke() {
        // A minimal query: id, RD-flag header, one A/IN question for a.b.
        let mut pkt = vec![0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
        pkt.extend_from_slice(&[1, b'a', 1, b'b', 0, 0, 1, 0, 1]);
        let q = match dns_parse_query(&pkt) {
            DnsQueryOutcome::Ok(q) => q,
            other => panic!("expected Ok, got {other:?}"),
        };
        assert_eq!(q.qname, "a.b");
        let fwd = dns_forward_query(&pkt, "example.com").expect("forward build");
        assert!(matches!(dns_parse_query(&fwd), DnsQueryOutcome::Ok(_)));
    }
}
