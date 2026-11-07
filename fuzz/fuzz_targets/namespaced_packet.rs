//! Fuzz target: namespaced egress proxy packet path (Linux only).
//!
//! Input layout: `[u8 flags][u8 n_frames][frames][u8 n_ops][ops]`.
//! - flags bit0 arms the DNS intercept (gate exists or not).
//! - Each frame is `[u16 len][bytes]` — one TUN frame fed to
//!   `packet::classify`, then through the NAT table when it is TCP.
//! - Each op is `[u16 len][bytes]` — `0` mark-associated, `1` remove,
//!   `2` reap-at (`+secs`), `3` craft+reclassify a UDP reply —
//!   driving the stateful NAT lifecycle deterministically from bytes.
//!
//! Properties: classification never panics and bounds payload to the
//! frame; a minted DNAT flow rewrites to the gateway listener and its
//! reverse restores the original tuple; reaped/removed flows are
//! gone, associated ones survive; crafted replies re-classify as UDP.

#[cfg(target_os = "linux")]
mod imp {
    use std::cell::Cell;
    use std::collections::{HashMap, HashSet};
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::time::{Duration, Instant};

    use mcp_writ::fuzz::{
        ALLOC_BASE, DNS_TCP_NAT_PORT, GATEWAY_V4, GATEWAY_V6, MAX_NAT_MAPPINGS, NatProbe,
        TCP_NAT_PORT, TunClassified, WORKLOAD_V4, WORKLOAD_V6, craft_udp_reply, dns_parse_query,
        tun_classify, tun_tcp_tuple,
    };

    #[derive(Default)]
    pub struct Gates {
        pub cases: Cell<usize>,
        pub tcp: Cell<usize>,
        pub udp: Cell<usize>,
        pub udp_dns: Cell<usize>,
        pub drops: Cell<usize>,
        pub minted: Cell<usize>,
        pub rev_ok: Cell<usize>,
        pub reaped: Cell<usize>,
        pub removed: Cell<usize>,
        pub crafted: Cell<usize>,
        pub nat_cap: Cell<usize>,
    }

    struct Flow {
        workload: IpAddr,
        alloc: u16,
        /// Reply frame (post-DNAT tuple flipped) — reusable since
        /// `rev_nat_out` does not consume the mapping.
        reply: Vec<u8>,
        orig_addr: IpAddr,
        orig_port: u16,
        orig_src_port: u16,
        associated: bool,
        removed: bool,
        /// Killed by a deterministic reap (age past the 5 s deadline).
        reaped: bool,
        /// Touched by a reap landing exactly on the deadline — real
        /// elapsed µs decide which side it fell, so do not assert.
        maybe_reaped: bool,
        /// Wall-clock mint time — mirrors `FlowOrig::minted`, which
        /// the cap refusal path's internal `reap_expired` measures
        /// against real `Instant::now()`, not an injected clock.
        minted_at: Instant,
    }

    fn v4(ctx: &mut noprop::TestCaseContext) -> Ipv4Addr {
        Ipv4Addr::from(noprop::sample_u32(ctx))
    }

    fn v6(ctx: &mut noprop::TestCaseContext) -> Ipv6Addr {
        Ipv6Addr::from(noprop::sample_u128(ctx))
    }

    fn ports(ctx: &mut noprop::TestCaseContext) -> (u16, u16) {
        let pick = |ctx: &mut noprop::TestCaseContext| {
            noprop::sample_with_boundaries(
                ctx,
                &[53u16, 80, 443, 853, 8080, 0, 65535],
                noprop::Ratio::new(1, 3),
                |ctx| noprop::sample_u16(ctx),
            )
        };
        (pick(ctx), pick(ctx))
    }

    fn tcp_header(ctx: &mut noprop::TestCaseContext, f: &mut Vec<u8>) {
        let (sp, dp) = ports(ctx);
        f.extend_from_slice(&sp.to_be_bytes());
        f.extend_from_slice(&dp.to_be_bytes());
        f.extend_from_slice(&noprop::sample_u32(ctx).to_be_bytes()); // seq
        f.extend_from_slice(&noprop::sample_u32(ctx).to_be_bytes()); // ack
        // data offset — usually a valid 5, sometimes garbage.
        let off = noprop::sample_choice(ctx, &[5u8, 5, 5, 6, 15, 0]);
        f.push(off << 4);
        // flags — SYN-heavy so minted flows are common; some odd combos.
        let flags = noprop::sample_choice(
            ctx,
            &[0x02u8, 0x02, 0x02, 0x10, 0x12, 0x04, 0x01, 0x29, 0x00, 0xff],
        );
        f.push(flags);
        f.extend_from_slice(&noprop::sample_u16(ctx).to_be_bytes()); // window
        f.extend_from_slice(&[0; 4]); // checksum + urgent
    }

    /// IPv4 frame — mostly well-formed, sometimes inconsistent lengths
    /// or fragment bits to reach the drop paths.
    fn v4_frame(ctx: &mut noprop::TestCaseContext, f: &mut Vec<u8>, workload_src: bool) {
        let proto = noprop::sample_choice(ctx, &[6u8, 6, 17, 17, 1, 47]);
        let payload_len = noprop::sample_usize_in(ctx, 0..=600);
        let l4 = match proto {
            6 => 20usize,
            17 => 8,
            _ => 0,
        };
        let total = 20 + l4 + payload_len;
        f.push(0x45);
        f.push(0);
        let claimed = if noprop::sample_ratio(ctx, noprop::Ratio::new(3, 4)) {
            total
        } else {
            noprop::sample_usize_in(ctx, 0..=total + 64)
        };
        f.extend_from_slice(&(claimed as u16).to_be_bytes());
        f.extend_from_slice(&[0; 2]); // id
        let frag = if noprop::sample_ratio(ctx, noprop::Ratio::new(1, 5)) {
            noprop::sample_u16(ctx)
        } else {
            0x4000
        };
        f.extend_from_slice(&frag.to_be_bytes());
        f.push(64);
        f.push(proto);
        f.extend_from_slice(&[0; 2]); // header checksum (parser ignores)
        let src = if workload_src || noprop::sample_ratio(ctx, noprop::Ratio::new(1, 4)) {
            WORKLOAD_V4
        } else {
            v4(ctx)
        };
        let dst = if noprop::sample_ratio(ctx, noprop::Ratio::new(1, 5)) {
            GATEWAY_V4
        } else {
            v4(ctx)
        };
        f.extend_from_slice(&src.octets());
        f.extend_from_slice(&dst.octets());
        match proto {
            6 => tcp_header(ctx, f),
            17 => {
                let (sp, dp) = ports(ctx);
                f.extend_from_slice(&sp.to_be_bytes());
                f.extend_from_slice(&dp.to_be_bytes());
                // UDP length — mostly right, sometimes off.
                let ulen = if noprop::sample_ratio(ctx, noprop::Ratio::new(3, 4)) {
                    8 + payload_len
                } else {
                    noprop::sample_usize_in(ctx, 0..=payload_len + 24)
                };
                f.extend_from_slice(&(ulen as u16).to_be_bytes());
                f.extend_from_slice(&[0; 2]);
            }
            _ => {}
        }
        f.extend_from_slice(&noprop::sample_bytes_vec(ctx, payload_len));
    }

    /// IPv6 frame — bare TCP/UDP plus extension/fragment/ICMP next
    /// headers for the v6 drop list.
    fn v6_frame(ctx: &mut noprop::TestCaseContext, f: &mut Vec<u8>, workload_src: bool) {
        let next = noprop::sample_choice(ctx, &[6u8, 6, 17, 17, 0, 43, 44, 58, 60, 255]);
        let payload_len = noprop::sample_usize_in(ctx, 0..=600);
        let l4 = match next {
            6 => 20usize,
            17 => 8,
            _ => 0,
        };
        f.push(0x60);
        f.extend_from_slice(&[0; 3]); // tc + flow
        let claimed = if noprop::sample_ratio(ctx, noprop::Ratio::new(3, 4)) {
            l4 + payload_len
        } else {
            noprop::sample_usize_in(ctx, 0..=l4 + payload_len + 32)
        };
        f.extend_from_slice(&(claimed as u16).to_be_bytes());
        f.push(next);
        f.push(64); // hop limit
        let src = if workload_src || noprop::sample_ratio(ctx, noprop::Ratio::new(1, 4)) {
            // Both mintable v6 source forms: the fixed v6 address and
            // the v4-mapped spelling a v6 socket uses for `::ffff:<v4>`.
            if noprop::sample_bool(ctx) {
                WORKLOAD_V6
            } else {
                WORKLOAD_V4.to_ipv6_mapped()
            }
        } else {
            v6(ctx)
        };
        let dst = if noprop::sample_ratio(ctx, noprop::Ratio::new(1, 5)) {
            GATEWAY_V6
        } else {
            v6(ctx)
        };
        f.extend_from_slice(&src.octets());
        f.extend_from_slice(&dst.octets());
        match next {
            6 => tcp_header(ctx, f),
            17 => {
                let (sp, dp) = ports(ctx);
                f.extend_from_slice(&sp.to_be_bytes());
                f.extend_from_slice(&dp.to_be_bytes());
                let ulen = if noprop::sample_ratio(ctx, noprop::Ratio::new(3, 4)) {
                    8 + payload_len
                } else {
                    noprop::sample_usize_in(ctx, 0..=payload_len + 24)
                };
                f.extend_from_slice(&(ulen as u16).to_be_bytes());
                f.extend_from_slice(&[0; 2]);
            }
            _ => {}
        }
        f.extend_from_slice(&noprop::sample_bytes_vec(ctx, payload_len));
    }

    pub fn gen_input(ctx: &mut noprop::TestCaseContext) -> Vec<u8> {
        let flags: u8 = u8::from(noprop::sample_bool(ctx));
        let n_frames = noprop::sample_usize_in(ctx, 0..=10);
        let n_ops = noprop::sample_usize_in(ctx, 0..=6);
        let mut out = vec![flags, n_frames.min(255) as u8];
        for _ in 0..n_frames {
            let mut f = Vec::new();
            match noprop::sample_weighted_index(ctx, &[15, 30, 20, 35]) {
                0 => {
                    let n = noprop::sample_with_boundaries(
                        ctx,
                        &[0usize, 1, 19, 20, 39, 40, 60, 1500],
                        noprop::Ratio::new(1, 3),
                        |ctx| noprop::sample_usize_in(ctx, 0..=1600),
                    );
                    f.extend_from_slice(&noprop::sample_bytes_vec(ctx, n));
                }
                1 => v4_frame(ctx, &mut f, false),
                2 => v6_frame(ctx, &mut f, false),
                // Workload-sourced TCP — the NAT-mintable shape.
                _ => {
                    if noprop::sample_bool(ctx) {
                        v4_frame(ctx, &mut f, true)
                    } else {
                        v6_frame(ctx, &mut f, true)
                    }
                }
            }
            out.extend_from_slice(&(f.len().min(0xffff) as u16).to_be_bytes());
            out.extend_from_slice(&f);
        }
        out.push(n_ops.min(255) as u8);
        for _ in 0..n_ops {
            let mut op = Vec::new();
            match noprop::sample_weighted_index(ctx, &[9, 9, 9, 12, 1]) {
                0 | 1 => {
                    // 0 = mark_associated, 1 = remove — the index into
                    // the flow list is decoded modulo length.
                    op.push(noprop::sample_weighted_index(ctx, &[1, 1]) as u8);
                    op.extend_from_slice(&noprop::sample_u16(ctx).to_be_bytes());
                }
                2 => {
                    op.push(2u8);
                    // reap offset seconds — straddle the 5s deadline.
                    let secs = noprop::sample_with_boundaries(
                        ctx,
                        &[0u16, 1, 4, 5, 6, 7, 60, 3600],
                        noprop::Ratio::new(2, 3),
                        |ctx| noprop::sample_u16(ctx),
                    );
                    op.extend_from_slice(&secs.to_be_bytes());
                }
                3 => {
                    op.push(3u8);
                    op.push(u8::from(noprop::sample_bool(ctx))); // v6?
                    let (sp, dp) = ports(ctx);
                    op.extend_from_slice(&sp.to_be_bytes());
                    op.extend_from_slice(&dp.to_be_bytes());
                    let n = noprop::sample_usize_in(ctx, 0..=1200);
                    op.extend_from_slice(&noprop::sample_bytes_vec(ctx, n));
                }
                _ => {
                    // 4 = SYN flood — mint `count` distinct flows.
                    // Mostly shallow walks (≤512 mints — alloc churn,
                    // tuple reuse); ~10% reach for the 4096-mapping cap
                    // — a saturation costs ~50 ms, so it stays rare.
                    op.push(4u8);
                    let n = match noprop::sample_weighted_index(ctx, &[9, 1]) {
                        0 => noprop::sample_usize_in(ctx, 0..=512) as u16,
                        _ => noprop::sample_with_boundaries(
                            ctx,
                            &[4096usize, 4097, 5000, 8192],
                            noprop::Ratio::new(1, 2),
                            |ctx| noprop::sample_usize_in(ctx, 4000..=8192),
                        ) as u16,
                    };
                    op.extend_from_slice(&n.to_be_bytes());
                    op.extend_from_slice(&noprop::sample_u16(ctx).to_be_bytes()); // base sport
                    op.extend_from_slice(&noprop::sample_u16(ctx).to_be_bytes()); // dst port
                    op.extend_from_slice(&v4(ctx).octets()); // dst addr
                }
            }
            out.extend_from_slice(&(op.len() as u16).to_be_bytes());
            out.extend_from_slice(&op);
        }
        out
    }

    /// A minimal workload→`dst` IPv4/TCP SYN — headers only; the NAT
    /// path reads the tuple and flags, and recomputes the checksums.
    fn syn_v4(sport: u16, dport: u16, dst: Ipv4Addr) -> Vec<u8> {
        let mut f = vec![0u8; 40];
        f[0] = 0x45;
        f[2..4].copy_from_slice(&40u16.to_be_bytes()); // total len
        f[8] = 64; // ttl
        f[9] = 6; // tcp
        f[12..16].copy_from_slice(&WORKLOAD_V4.octets());
        f[16..20].copy_from_slice(&dst.octets());
        f[20..22].copy_from_slice(&sport.to_be_bytes());
        f[22..24].copy_from_slice(&dport.to_be_bytes());
        f[32] = 5 << 4; // data offset
        f[33] = 0x02; // SYN
        f
    }

    /// Workload-side 4-tuple — mirrors `nat::FlowKey`, what a repeat
    /// SYN (or an ACK) must hit to reuse a live mapping.
    type FlowKey = (IpAddr, u16, IpAddr, u16);

    fn flow_key(f: &Flow) -> FlowKey {
        (f.workload, f.orig_src_port, f.orig_addr, f.orig_port)
    }

    /// Model of the NAT flow state: one row per `(workload, alloc)` —
    /// `NatTable::by_alloc`'s key — indexed by `by_alloc` so repeated
    /// mint recording stays O(1). Rows are never deleted (dead rows
    /// are marked in place and can be reset on a recycled alloc), so
    /// the index positions stay valid for the life of the model.
    #[derive(Default)]
    struct FlowModel {
        flows: Vec<Flow>,
        by_alloc: HashMap<(IpAddr, u16), usize>,
        /// Live workload-side tuples — shadows `NatTable::by_flow` so
        /// `flood`'s hit check stays O(1) at table-cap sizes.
        live_keys: HashSet<FlowKey>,
    }

    impl FlowModel {
        /// Record a `dnat_in` Some — fresh mint or re-emit. A live hit
        /// keeps its state — `maybe_reaped` included: the impl may
        /// have dropped and re-minted the mapping, so the real
        /// deadline stays unknowable. A dead-row hit means
        /// `next_alloc` wrapped onto a fresh mapping — floods plus
        /// drive mints reach the 49152→65535→wrap inside
        /// `mint_budget` — so the row takes the current dial's tuple
        /// and restarts unassociated, unexpired, and freshly clocked;
        /// the old mapping is definitely gone, so `maybe_reaped`
        /// clears along with the deadline markers.
        fn record_mint(
            &mut self,
            alloc_key: (IpAddr, u16),
            reply: Vec<u8>,
            orig_dst: (IpAddr, u16),
            orig_src_port: u16,
        ) {
            let (workload, alloc) = alloc_key;
            match self.by_alloc.get(&alloc_key).copied() {
                Some(i) => {
                    let fl = &mut self.flows[i];
                    let was_live = !(fl.removed || fl.reaped);
                    self.live_keys.remove(&flow_key(fl));
                    fl.reply = reply;
                    fl.orig_addr = orig_dst.0;
                    fl.orig_port = orig_dst.1;
                    fl.orig_src_port = orig_src_port;
                    fl.removed = false;
                    fl.reaped = false;
                    if !was_live {
                        fl.associated = false;
                        fl.maybe_reaped = false;
                        fl.minted_at = Instant::now();
                    }
                    // The reinsert must claim the key — a false return
                    // means a second live model row holds this tuple,
                    // which `by_flow` can map to only one alloc:
                    // model/table divergence.
                    assert!(
                        self.live_keys.insert(flow_key(fl)),
                        "flow key duplicated across live model rows"
                    );
                }
                None => {
                    self.by_alloc.insert(alloc_key, self.flows.len());
                    self.flows.push(Flow {
                        workload,
                        alloc,
                        reply,
                        orig_addr: orig_dst.0,
                        orig_port: orig_dst.1,
                        orig_src_port,
                        associated: false,
                        removed: false,
                        reaped: false,
                        maybe_reaped: false,
                        minted_at: Instant::now(),
                    });
                    self.live_keys
                        .insert((workload, orig_src_port, orig_dst.0, orig_dst.1));
                }
            }
        }
    }

    /// Decoded flood op: `count` distinct workload→`dst:dport` SYNs,
    /// source ports walking `base..`.
    struct FloodOp {
        count: usize,
        base: u16,
        dport: u16,
        dst: Ipv4Addr,
    }

    /// Consecutive refusals proving the cap before the flood stops —
    /// past the first `None` every new tuple pays the same O(table)
    /// reap-then-refuse, so a short streak is plenty.
    const REFUSAL_STREAK: usize = 64;

    /// Mint `op.count` distinct SYNs back-to-back. For this shape the
    /// [`MAX_NAT_MAPPINGS`] table cap is the only legal `dnat_in`
    /// refusal — the first `None` must land exactly at the cap, never
    /// before, and no new tuple may mint past it.
    fn flood(
        g: &Gates,
        model: &mut FlowModel,
        nat: &mut NatProbe,
        op: FloodOp,
        next_reap_at: &mut Instant,
        mint_budget: &mut usize,
    ) {
        // Two situations where the model cannot know the table's true
        // occupancy — skip rather than guess:
        // - a `maybe_reaped` row straddles the deadline, so it may or
        //   may not still hold a slot;
        // - a row minted >3 s ago could die to the *internal* reap the
        //   refusal path runs on the wall clock before the model's
        //   injected-clock bookkeeping notices.
        if model.flows.iter().any(|f| {
            !(f.removed || f.reaped)
                && (f.maybe_reaped || f.minted_at.elapsed() > Duration::from_secs(3))
        }) {
            return;
        }
        let workload: IpAddr = WORKLOAD_V4.into();
        let dst_ip: IpAddr = op.dst.into();
        let live = model
            .flows
            .iter()
            .filter(|f| !(f.removed || f.reaped))
            .count();
        let mut minted = 0usize;
        let mut none_streak = 0usize;
        for i in 0..op.count.min(8192) {
            let sport = op.base.wrapping_add(i as u16);
            // A SYN replaying a live tuple reuses its mapping rather
            // than minting — `live_keys` shadows `by_flow`.
            let known = model
                .live_keys
                .contains(&(workload, sport, dst_ip, op.dport));
            if !known && *mint_budget == 0 {
                break; // this case's mint budget is spent
            }
            let mut fr = syn_v4(sport, op.dport, op.dst);
            match nat.dnat_in(&mut fr) {
                Some(rw) => {
                    none_streak = 0;
                    if known {
                        continue;
                    }
                    assert!(
                        live + minted < MAX_NAT_MAPPINGS,
                        "NAT table admitted past the {MAX_NAT_MAPPINGS} cap"
                    );
                    minted += 1;
                    *mint_budget -= 1;
                    let mut reply = fr.clone();
                    swap_tcp(&mut reply);
                    model.record_mint(
                        (workload, rw.new_src_port),
                        reply,
                        (dst_ip, op.dport),
                        sport,
                    );
                    g.minted.set(g.minted.get() + 1);
                }
                None => {
                    assert!(!known, "NAT refused a SYN on a live flow");
                    assert_eq!(
                        live + minted,
                        MAX_NAT_MAPPINGS,
                        "NAT refusal below the {MAX_NAT_MAPPINGS} cap"
                    );
                    // The saturated branch ran `reap_expired` on the
                    // wall clock and re-armed `next_reap` at ~now+1 s,
                    // shadowed here so later reap ops resolve against
                    // the reset throttle.
                    *next_reap_at = Instant::now() + Duration::from_secs(1);
                    g.nat_cap.set(g.nat_cap.get() + 1);
                    none_streak += 1;
                    if none_streak >= REFUSAL_STREAK {
                        break;
                    }
                }
            }
        }
    }

    /// Flip src/dst addrs + ports of a bare TCP packet in place — the
    /// shape a stack reply takes.
    fn swap_tcp(f: &mut [u8]) {
        if f.first().is_some_and(|b| b >> 4 == 4) && f.len() >= 20 {
            for i in 0..4 {
                f.swap(12 + i, 16 + i);
            }
            let ihl = usize::from(f[0] & 0x0f) * 4;
            for i in 0..2 {
                f.swap(ihl + i, ihl + 2 + i);
            }
        } else if f.first().is_some_and(|b| b >> 4 == 6) && f.len() >= 60 {
            for i in 0..16 {
                f.swap(8 + i, 24 + i);
            }
            for i in 0..2 {
                f.swap(40 + i, 42 + i);
            }
        }
    }

    fn drive_frame(
        g: &Gates,
        model: &mut FlowModel,
        nat: &mut NatProbe,
        intercept: bool,
        frame: &[u8],
    ) {
        match tun_classify(frame, intercept) {
            TunClassified::Tcp { len } => {
                assert!(len <= frame.len(), "TCP capture exceeded frame");
                assert!(len >= 40, "TCP capture below the header minimum");
                g.tcp.set(g.tcp.get() + 1);
                // The pre-rewrite tuple, parsed independently of the
                // NAT path — every expectation below derives from it,
                // never from a value `dnat_in`/`rev_nat_out` returned,
                // so a mis-recorded flow cannot launder its own check.
                let orig = tun_tcp_tuple(frame);
                let mut f = frame.to_vec();
                if let Some(rw) = nat.dnat_in(&mut f) {
                    g.minted.set(g.minted.get() + 1);
                    let (osrc, odst, osport, odport) = orig.expect("classified TCP has a tuple");
                    assert_eq!(
                        (rw.orig_addr, rw.orig_port),
                        (odst, odport),
                        "dnat_in misreported the original destination"
                    );
                    let expect_gw: IpAddr = match osrc {
                        IpAddr::V4(_) => GATEWAY_V4.into(),
                        IpAddr::V6(_) => GATEWAY_V6.into(),
                    };
                    assert_eq!(rw.new_dst, expect_gw, "DNAT landed off-gateway");
                    // DNS-over-TCP intercept: only an armed gate on a
                    // port-53 dial.
                    let expect_dns = intercept && odport == 53;
                    assert_eq!(rw.dns_tcp, expect_dns, "dns_tcp flag diverged");
                    assert_eq!(
                        rw.new_dst_port,
                        if expect_dns {
                            DNS_TCP_NAT_PORT
                        } else {
                            TCP_NAT_PORT
                        },
                        "unexpected NAT listener port"
                    );
                    assert!(rw.new_src_port >= ALLOC_BASE);
                    let mut reply = f.clone();
                    swap_tcp(&mut reply);
                    // `rev_nat_out` rewrites the frame in place — keep
                    // `reply` as the pristine stack→workload template
                    // and burn a clone for the proof-of-reversal check.
                    let mut probe = reply.clone();
                    let (src, sport, dport) = nat
                        .rev_nat_out(&mut probe)
                        .expect("minted flow missing on the reverse path");
                    g.rev_ok.set(g.rev_ok.get() + 1);
                    assert_eq!((src, sport), (odst, odport));
                    assert_eq!(dport, osport);
                    // `dnat_in` answers Some on retransmits and on any
                    // packet riding an existing mapping — not just the
                    // SYN that minted it. Track one model entry per
                    // (workload, alloc) key or a `remove`/`reap` op would
                    // split two tracked rows for the same real mapping.
                    model.record_mint((osrc, rw.new_src_port), reply, (odst, odport), osport);
                }
            }
            TunClassified::UdpDns {
                dst_port, payload, ..
            } => {
                assert_eq!(dst_port, 53);
                g.udp_dns.set(g.udp_dns.get() + 1);
                // Gate-bound payload — exercise the query decode too.
                let _ = dns_parse_query(&payload);
            }
            TunClassified::Udp { payload, .. } => {
                g.udp.set(g.udp.get() + 1);
                assert!(payload.len() <= frame.len());
            }
            TunClassified::DropNonIp
            | TunClassified::DropV6Ext
            | TunClassified::DropFragment
            | TunClassified::DropProto
            | TunClassified::DropMalformed => {
                g.drops.set(g.drops.get() + 1);
            }
        }
    }

    pub fn property(g: &Gates, data: &[u8]) {
        let Some(&flags) = data.first() else { return };
        let intercept = flags & 1 != 0;
        let Some(&n_frames) = data.get(1) else { return };
        let mut pos = 2;
        let mut nat = NatProbe::new(intercept);
        let mut model = FlowModel::default();
        for _ in 0..n_frames {
            let Some(h) = data.get(pos..pos + 2) else {
                break;
            };
            let len = u16::from_be_bytes([h[0], h[1]]) as usize;
            pos += 2;
            let Some(frame) = data.get(pos..pos + len) else {
                break;
            };
            pos += len;
            drive_frame(g, &mut model, &mut nat, intercept, frame);
        }
        // Shadow of `NatTable::next_reap` in real Instants —
        // `reap_if_due` runs only when the supplied `at` reaches it,
        // then re-arms to `at + 1 s`. Kept on the wall clock because
        // the cap-refusal path can also re-arm it internally.
        let mut next_reap_at = Instant::now() + Duration::from_secs(1);
        // Per-case bound on fresh mints — reaching the cap costs ~4 k
        // mints, and a couple of saturate→reap→re-saturate cycles are
        // all the coverage the oracle needs.
        let mut mint_budget: usize = 16384;
        if let Some(&n_ops) = data.get(pos) {
            pos += 1;
            for _ in 0..n_ops {
                let Some(h) = data.get(pos..pos + 2) else {
                    break;
                };
                let len = u16::from_be_bytes([h[0], h[1]]) as usize;
                pos += 2;
                let Some(op) = data.get(pos..pos + len) else {
                    break;
                };
                pos += len;
                match op.first() {
                    Some(&0) => {
                        if let Some(i) = op
                            .get(1..3)
                            .map(|b| u16::from_be_bytes([b[0], b[1]]) as usize)
                            && !model.flows.is_empty()
                        {
                            let fl = {
                                let idx = i % model.flows.len();
                                &mut model.flows[idx]
                            };
                            nat.mark_associated(fl.workload, fl.alloc);
                            fl.associated = true;
                        }
                    }
                    Some(&1) => {
                        if let Some(i) = op
                            .get(1..3)
                            .map(|b| u16::from_be_bytes([b[0], b[1]]) as usize)
                            && !model.flows.is_empty()
                        {
                            let fl = {
                                let idx = i % model.flows.len();
                                &mut model.flows[idx]
                            };
                            nat.remove(fl.workload, fl.alloc);
                            fl.removed = true;
                            model.live_keys.remove(&flow_key(fl));
                            g.removed.set(g.removed.get() + 1);
                        }
                    }
                    Some(&2) => {
                        if let Some(secs) = op.get(1..3).map(|b| u16::from_be_bytes([b[0], b[1]])) {
                            let at = Instant::now() + Duration::from_secs(u64::from(secs));
                            nat.reap_at(at);
                            // A run drops unassociated rows past the 5 s
                            // deadline and re-arms the throttle at
                            // `at + 1 s`. `at` landing just under the
                            // throttle is ambiguous — the impl's clock
                            // read may fall either side — so model the
                            // marks as `maybe` and keep the earlier
                            // deadline, biasing later ops to "ran".
                            let ambiguous = at < next_reap_at
                                && next_reap_at.duration_since(at) < Duration::from_millis(50);
                            if ambiguous || at >= next_reap_at {
                                let definite = !ambiguous;
                                for fl in model.flows.iter_mut() {
                                    if fl.associated || fl.removed || fl.reaped {
                                        continue;
                                    }
                                    let age = at.saturating_duration_since(fl.minted_at);
                                    if definite && age > Duration::from_millis(5050) {
                                        fl.reaped = true;
                                        model.live_keys.remove(&flow_key(fl));
                                    } else if age > Duration::from_millis(4950) {
                                        fl.maybe_reaped = true;
                                    }
                                }
                                if definite {
                                    next_reap_at = at + Duration::from_secs(1);
                                }
                            }
                            g.reaped.set(g.reaped.get() + 1);
                        }
                    }
                    Some(&3) => {
                        if let Some(&v6) = op.get(1)
                            && let Some(sp) = op.get(2..4).map(|b| u16::from_be_bytes([b[0], b[1]]))
                            && let Some(dp) = op.get(4..6).map(|b| u16::from_be_bytes([b[0], b[1]]))
                        {
                            let payload = &op[6..];
                            let (src, dst): (IpAddr, IpAddr) = if v6 != 0 {
                                (GATEWAY_V6.into(), WORKLOAD_V6.into())
                            } else {
                                (GATEWAY_V4.into(), WORKLOAD_V4.into())
                            };
                            let pkt = craft_udp_reply(src, sp, dst, dp, payload);
                            g.crafted.set(g.crafted.get() + 1);
                            // Re-classify the crafted reply — it must
                            // parse back as UDP toward dst:dp.
                            match tun_classify(&pkt, false) {
                                TunClassified::Udp {
                                    dst_port,
                                    payload: p,
                                    ..
                                } => {
                                    assert_eq!(dst_port, dp);
                                    assert_eq!(p, payload);
                                }
                                other => panic!("crafted reply reclassified as {other:?}"),
                            }
                            match tun_classify(&pkt, true) {
                                TunClassified::UdpDns { dst_port, .. } => assert_eq!(dst_port, 53),
                                TunClassified::Udp { dst_port, .. } => {
                                    assert_ne!(dst_port, 53, "port-53 evaded the intercept")
                                }
                                other => panic!("crafted reply dropped under intercept: {other:?}"),
                            }
                        }
                    }
                    Some(&4) => {
                        if let Some(count) = op.get(1..3).map(|b| u16::from_be_bytes([b[0], b[1]]))
                            && let Some(base) =
                                op.get(3..5).map(|b| u16::from_be_bytes([b[0], b[1]]))
                            && let Some(dport) =
                                op.get(5..7).map(|b| u16::from_be_bytes([b[0], b[1]]))
                            && let Some(dst) = op.get(7..11)
                        {
                            flood(
                                g,
                                &mut model,
                                &mut nat,
                                FloodOp {
                                    count: count as usize,
                                    base,
                                    dport,
                                    dst: Ipv4Addr::new(dst[0], dst[1], dst[2], dst[3]),
                                },
                                &mut next_reap_at,
                                &mut mint_budget,
                            );
                        }
                    }
                    _ => {}
                }
            }
        }
        // Reap/remove consistency: a flow whose mapping was removed or
        // deterministically reaped must be gone; every other flow —
        // associated or still inside its deadline — keeps reversing.
        // `maybe_reaped` entries straddle the 5 s boundary and are
        // skipped rather than guessed at.
        for fl in &mut model.flows {
            if fl.maybe_reaped && !fl.reaped {
                continue;
            }
            let mut reply = fl.reply.clone();
            let got = nat.rev_nat_out(&mut reply);
            let expect_gone = fl.removed || fl.reaped;
            assert_eq!(
                got.is_some(),
                !expect_gone,
                "flow (assoc={} removed={} reaped={} maybe={}) gave {:?}",
                fl.associated,
                fl.removed,
                fl.reaped,
                fl.maybe_reaped,
                got
            );
            if let Some((src, sport, dport)) = got {
                assert_eq!(
                    (src, sport, dport),
                    (fl.orig_addr, fl.orig_port, fl.orig_src_port)
                );
            }
        }
        g.cases.set(g.cases.get() + 1);
    }

    pub fn main() -> i32 {
        let args = mcp_writ_fuzz::parse_args("namespaced_packet");
        let g = Gates::default();
        mcp_writ_fuzz::run(
            "namespaced_packet",
            &args,
            gen_input,
            |data| property(&g, data),
            || {
                assert!(g.tcp.get() > 0, "no TCP frame classified");
                assert!(g.udp.get() + g.udp_dns.get() > 0, "no UDP classified");
                assert!(g.minted.get() > 0, "no DNAT flow minted");
                assert!(g.crafted.get() > 0, "no reply crafted");
                assert!(g.nat_cap.get() > 0, "NAT table cap never hit");
                format!(
                    "tcp={} udp={} udp_dns={} drops={} minted={} rev={} reaped_ops={} removed={} crafted={} nat_cap={}",
                    g.tcp.get(),
                    g.udp.get(),
                    g.udp_dns.get(),
                    g.drops.get(),
                    g.minted.get(),
                    g.rev_ok.get(),
                    g.reaped.get(),
                    g.removed.get(),
                    g.crafted.get(),
                    g.nat_cap.get()
                )
            },
        )
    }
}

#[cfg(target_os = "linux")]
fn main() {
    std::process::exit(imp::main());
}

#[cfg(not(target_os = "linux"))]
fn main() {
    println!("[namespaced_packet] linux-only target — skipped on this platform");
}
