//! eBPF program generation for the `BPF_CGROUP_INET*_CONNECT` hooks.
//!
//! Programs are emitted directly as `bpf_insn` words — no external
//! crate, no prebuilt object file. Every rule-map slot is a straight-
//! line "lookup → field compares → jump" block generated at launch
//! from the compiled [`RuleTable`], so instruction count stays bounded
//! by `MAX_RULES_PER_MAP`/`GRANT_SLOTS` and there is no loop for the
//! verifier to reason about.
//!
//! Verdict semantics: a matched entry's `action` is fixed at build
//! time — deny entries (placed first by `rules::compile`) jump to the
//! shared deny tail (ring-buffer event + `return 0`), allow entries
//! and grants jump to `return 1`, and fall-through runs the policy's
//! default (`deny_all_others` → deny tail, else `return 1`).

use super::sys;

// --- encoding ------------------------------------------------------------

/// One `struct bpf_insn` (u64).
pub fn ins(code: u8, dst: u8, src: u8, off: i16, imm: i32) -> u64 {
    code as u64
        | (dst as u64) << 8
        | (src as u64) << 12
        | ((off as u16) as u64) << 16
        | ((imm as u32) as u64) << 32
}

const BPF_MOV64_REG: u8 = 0xbf;
const BPF_MOV64_IMM: u8 = 0xb7;
const BPF_ALU64_AND_REG: u8 = 0x5f;
const BPF_ALU64_ADD_IMM: u8 = 0x07;
const BPF_ALU64_ADD_REG: u8 = 0x0f;
const BPF_LDX_MEM_W: u8 = 0x61;
const BPF_LDX_MEM_DW: u8 = 0x79;
const BPF_ST_MEM_W: u8 = 0x62;
const BPF_STX_MEM_W: u8 = 0x63;
const BPF_STX_MEM_DW: u8 = 0x7b;
const BPF_STX_XADD_DW: u8 = 0xdb; // lock *(u64*)(dst+off) += src
const BPF_LDDW_IMM: u8 = 0x18;
const BPF_PSEUDO_MAP_FD: u8 = 1;
const BPF_CALL: u8 = 0x85;
const BPF_EXIT: u8 = 0x95;
const BPF_JA: u8 = 0x05;
const BPF_JEQ_K: u8 = 0x15;
const BPF_JNE_X: u8 = 0x5d;
const BPF_JLE_X: u8 = 0xbd;

/// Stack slots (negative offsets from fp).
const SLOT_KEY: i16 = -4; // u32 lookup key
const SLOT_NOW: i16 = -16; // u64 wall-clock estimate for grant expiry
const SLOT_MATCH: i16 = -24; // u32 matched-rule index for the deny event
const SLOT_PID: i16 = -32; // u64 pid_tgid saved across helper calls
const SLOT_ADDR_HI: i16 = -48; // u64 IPv6 addr words 2-3 (helper calls clobber r1-r5)

/// The deny-event record — 48 bytes; see `events.rs` for the reader.
pub const EVENT_SIZE: u32 = 48;
/// Sanity tag a drained record is checked against before parsing.
pub const EVENT_MAGIC: u32 = 0xeb0f_5001;

/// `stats` map slot layout (`u64[2]`).
pub const STAT_DENIED: i16 = 0;
pub const STAT_DROPPED: i16 = 8;

/// Which attach type / family a generated program is for.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ProgKind {
    V4Connect,
    V6Connect,
}

impl ProgKind {
    pub fn attach_type(self) -> u32 {
        match self {
            Self::V4Connect => sys::BPF_CGROUP_INET4_CONNECT,
            Self::V6Connect => sys::BPF_CGROUP_INET6_CONNECT,
        }
    }
    /// `AF_INET`/`AF_INET6` value stamped into deny events.
    pub fn family(self) -> u32 {
        match self {
            Self::V4Connect => libc::AF_INET as u32,
            Self::V6Connect => libc::AF_INET6 as u32,
        }
    }
}

/// Maps the generated program references.
#[derive(Clone, Copy)]
pub struct ProgMaps {
    /// Static rules (ARRAY of `RuleEntry`, one slot per rule).
    pub rules: i32,
    /// Dynamic grants (ARRAY of `RuleEntry`, `GRANT_SLOTS` slots).
    pub grants: i32,
    /// `BPF_MAP_TYPE_RINGBUF` deny-event buffer.
    pub events: i32,
    /// One-slot ARRAY of `u64` counters: `[denied, denied_dropped]`.
    pub stats: i32,
    /// One-slot ARRAY holding the wall-clock epoch (unix ns at
    /// `ktime == 0`) the program adds to `ktime_get_boot_ns`. Kept in
    /// a map — not an immediate — so the drain refreshes it each
    /// resync tick and a post-load realtime step (NTP, manual
    /// clock change) cannot skew grant expiry beyond one tick.
    pub clock: i32,
}

/// Named jump destination, patched in at `finish`.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Mark {
    Allow,
    Deny,
    /// Ring-buffer reserve failed — the deny still applies; bump the
    /// dropped counter and return 0.
    DenyDrop,
    /// Clock-map lookup returned NULL — epoch reads as 0 (every unix
    /// expiry is in the past: all grants dead, fail closed).
    NoEpoch,
    /// Epoch acquired (from the map or the zero fallback) — continue.
    HaveEpoch,
    /// Fall-through past the current entry — resolved to the position
    /// where `next_here` is called.
    Next(usize),
}

/// Instruction stream builder with forward-jump fixups.
struct Builder {
    v: Vec<u64>,
    /// (insn index, mark) pairs whose `off` field is patched at resolve.
    fixups: Vec<(usize, Mark)>,
    marks: Vec<(Mark, usize)>,
}

impl Builder {
    fn new() -> Self {
        Self {
            v: Vec::new(),
            fixups: Vec::new(),
            marks: Vec::new(),
        }
    }
    fn emit(&mut self, i: u64) -> &mut Self {
        self.v.push(i);
        self
    }
    /// Conditional/unconditional jump to a `Mark` (offset patched later).
    fn jump(&mut self, code: u8, dst: u8, src: u8, mark: Mark, imm: i32) -> &mut Self {
        self.fixups.push((self.v.len(), mark));
        self.emit(ins(code, dst, src, 0, imm));
        self
    }
    /// Bind `mark` to the current position.
    fn mark(&mut self, m: Mark) -> &mut Self {
        self.marks.push((m, self.v.len()));
        self
    }
    /// Jump skipping the remainder of the current entry block.
    fn next(&mut self, code: u8, dst: u8, src: u8, slot: usize) -> &mut Self {
        self.jump(code, dst, src, Mark::Next(slot), 0)
    }
    fn resolve(mut self) -> Vec<u64> {
        for (at, mark) in &self.fixups {
            let Some((_, target)) = self.marks.iter().find(|(m, _)| m == mark) else {
                unreachable!("program builder emitted jump to unresolved mark");
            };
            let off = (*target as i64 - *at as i64 - 1) as i16;
            // off replaces the 16-bit field of the emitted insn.
            let w = &mut self.v[*at];
            *w = (*w & !(0xffffu64 << 16)) | (((off as u16) as u64) << 16);
        }
        self.v
    }
}

/// `lddw reg, <map fd>` — the BPF_PSEUDO_MAP_FD pair the loader rewrites.
fn ld_map(b: &mut Builder, reg: u8, fd: i32) {
    b.emit(ins(BPF_LDDW_IMM, reg, BPF_PSEUDO_MAP_FD, 0, fd));
    b.emit(ins(0, 0, 0, 0, 0));
}

/// Build the connect program for `kind`.
///
/// Entry blocks are emitted by `rule_block_ex`. Register use across
/// the scan: r6=ctx, r7=addr word(s), r8=raw port, r9=protocol — all
/// callee-saved so `map_lookup` calls (which clobber r1-r5) never
/// touch them. The IPv6 address' high u64 does not fit the
/// callee-saved set, so it lives on the stack at `SLOT_ADDR_HI` and
/// is reloaded where needed. Entry loads reuse r0-r3.
///
/// `rules`/`grants` are ARRAY maps of `RuleEntry`; `entries` is the
/// static rule set (denies first, then allows — the same order
/// `rules::compile` produces; each entry's verdict comes from its own
/// `action` field). Static entries are written once at
/// `Runtime::prepare` and never updated, so each block is emitted with
/// the entry's own compares constant-folded (see [`PairCmp`]) — grant
/// slots stay generic because the drain rewrites them at runtime.
/// `default_allow` is the fall-through verdict. Grant expiry runs on
/// a unix timescale built as `clock[0]` (the realtime/boottime epoch
/// the drain refreshes) + `ktime_get_boot_ns`.
///
/// Folding keeps even the largest table-shaped program under the
/// legacy 4096-insn bound (pre-5.2 kernels) — the worst case is 96
/// generic-ish v6 static blocks + 64 grant blocks ≈ 4.1K insns, where
/// the un-folded form could exceed it and `prog_load` would refuse
/// `E2BIG`.
pub fn build(
    kind: ProgKind,
    maps: ProgMaps,
    entries: &[super::rules::RuleEntry],
    grant_slots: usize,
    default_allow: bool,
) -> Vec<u64> {
    let mut b = Builder::new();
    // prologue — ctx-derived values into callee-saved regs.
    b.emit(ins(BPF_MOV64_REG, 6, 1, 0, 0)); // r6 = ctx
    match kind {
        ProgKind::V4Connect => {
            b.emit(ins(BPF_LDX_MEM_W, 7, 6, sys::ctx::USER_IP4, 0));
        }
        ProgKind::V6Connect => {
            b.emit(ins(BPF_LDX_MEM_DW, 7, 6, sys::ctx::USER_IP6, 0)); // words 0-1
            // words 2-3 → stack: r1-r5 die at the first helper call.
            b.emit(ins(BPF_LDX_MEM_DW, 5, 6, sys::ctx::USER_IP6 + 8, 0));
            b.emit(ins(BPF_STX_MEM_DW, 10, 5, SLOT_ADDR_HI, 0));
        }
    }
    b.emit(ins(BPF_LDX_MEM_W, 8, 6, sys::ctx::USER_PORT, 0));
    // r9 = ctx->protocol — the socket's real IPPROTO_*. unotify
    // derives the flow protocol from SO_TYPE (SOCK_STREAM→tcp)
    // instead, so a non-TCP stream socket (e.g. SCTP) is `tcp` there
    // but its real protocol here: a proto=tcp allow is stricter on
    // this route — the safe side.
    b.emit(ins(BPF_LDX_MEM_W, 9, 6, sys::ctx::PROTOCOL, 0));
    // wall_now = clock[0] + ktime_get_boot_ns() → [fp+SLOT_NOW]. The
    // epoch lives in a one-slot map the drain refreshes each resync
    // tick — a post-load realtime step (NTP sync, a manual clock
    // change) skews grant expiry by at most that interval instead of
    // permanently. A lookup miss reads epoch=0, which puts every
    // unix-domain expiry in the past — fail closed.
    b.emit(ins(BPF_CALL, 0, 0, 0, sys::BPF_FUNC_KTIME_GET_BOOT_NS));
    b.emit(ins(BPF_STX_MEM_DW, 10, 0, SLOT_NOW, 0)); // stash boot ns
    b.emit(ins(BPF_ST_MEM_W, 10, 0, SLOT_KEY, 0));
    ld_map(&mut b, 1, maps.clock);
    b.emit(ins(BPF_MOV64_REG, 2, 10, 0, 0));
    b.emit(ins(BPF_ALU64_ADD_IMM, 2, 0, 0, SLOT_KEY as i32));
    b.emit(ins(BPF_CALL, 0, 0, 0, sys::BPF_FUNC_MAP_LOOKUP_ELEM));
    b.jump(BPF_JEQ_K, 0, 0, Mark::NoEpoch, 0);
    b.emit(ins(BPF_LDX_MEM_DW, 1, 0, 0, 0)); // r1 = *clock
    b.jump(BPF_JA, 0, 0, Mark::HaveEpoch, 0);
    b.mark(Mark::NoEpoch);
    b.emit(ins(BPF_MOV64_IMM, 1, 0, 0, 0));
    b.mark(Mark::HaveEpoch);
    b.emit(ins(BPF_LDX_MEM_DW, 0, 10, SLOT_NOW, 0)); // r0 = boot ns
    b.emit(ins(BPF_ALU64_ADD_REG, 0, 1, 0, 0));
    b.emit(ins(BPF_STX_MEM_DW, 10, 0, SLOT_NOW, 0));
    // matched-rule slot sentinel
    b.emit(ins(
        BPF_ST_MEM_W,
        10,
        0,
        SLOT_MATCH,
        super::rules::RULE_IDX_NONE as i32,
    ));

    // static rules — each entry's verdict comes from its own `action`
    // field, not its position (`rules::compile`'s deny-first ordering
    // is what gives denies precedence; an unexpected action value
    // reads as deny — fail closed).
    for (i, e) in entries.iter().enumerate() {
        rule_block_ex(
            &mut b,
            kind,
            maps,
            i as u32,
            Some(e),
            e.action == super::rules::ACTION_ALLOW,
        );
    }
    for i in 0..grant_slots {
        rule_block_ex(&mut b, kind, maps, i as u32, None, true);
    }

    // fall-through = policy default
    if default_allow {
        b.jump(BPF_JA, 0, 0, Mark::Allow, 0);
    } else {
        b.jump(BPF_JA, 0, 0, Mark::Deny, 0);
    }

    // --- tails ------------------------------------------------------
    b.mark(Mark::Allow);
    b.emit(ins(BPF_MOV64_IMM, 0, 0, 0, 1));
    b.emit(ins(BPF_EXIT, 0, 0, 0, 0));

    b.mark(Mark::Deny);
    // stats.denied++
    bump_stat(&mut b, maps.stats, STAT_DENIED);
    // event: pid_tgid first — helper calls clobber r1-r5.
    b.emit(ins(BPF_CALL, 0, 0, 0, sys::BPF_FUNC_GET_CURRENT_PID_TGID));
    b.emit(ins(BPF_STX_MEM_DW, 10, 0, SLOT_PID, 0));
    ld_map(&mut b, 1, maps.events);
    b.emit(ins(BPF_MOV64_IMM, 2, 0, 0, EVENT_SIZE as i32));
    b.emit(ins(BPF_MOV64_IMM, 3, 0, 0, 0));
    b.emit(ins(BPF_CALL, 0, 0, 0, sys::BPF_FUNC_RINGBUF_RESERVE));
    // r0 == NULL → drop path (stat + return 0, no event)
    b.jump(BPF_JEQ_K, 0, 0, Mark::DenyDrop, 0);
    b.emit(ins(BPF_MOV64_REG, 4, 0, 0, 0)); // r4 = record
    b.emit(ins(BPF_ST_MEM_W, 4, 0, 0, EVENT_MAGIC as i32)); // magic
    b.emit(ins(BPF_LDX_MEM_W, 1, 10, SLOT_MATCH, 0));
    b.emit(ins(BPF_STX_MEM_W, 4, 1, 4, 0)); // rule_idx
    b.emit(ins(BPF_ST_MEM_W, 4, 0, 8, kind.family() as i32)); // family
    b.emit(ins(BPF_STX_MEM_W, 4, 9, 12, 0)); // proto
    match kind {
        ProgKind::V4Connect => {
            b.emit(ins(BPF_STX_MEM_W, 4, 7, 16, 0)); // addr[0]
            b.emit(ins(BPF_ST_MEM_W, 4, 0, 20, 0));
            b.emit(ins(BPF_ST_MEM_W, 4, 0, 24, 0));
            b.emit(ins(BPF_ST_MEM_W, 4, 0, 28, 0));
        }
        ProgKind::V6Connect => {
            b.emit(ins(BPF_STX_MEM_DW, 4, 7, 16, 0)); // words 0-1
            b.emit(ins(BPF_LDX_MEM_DW, 1, 10, SLOT_ADDR_HI, 0));
            b.emit(ins(BPF_STX_MEM_DW, 4, 1, 24, 0)); // words 2-3
        }
    }
    b.emit(ins(BPF_STX_MEM_W, 4, 8, 32, 0)); // port_raw
    b.emit(ins(BPF_ST_MEM_W, 4, 0, 36, 0)); // pad
    b.emit(ins(BPF_LDX_MEM_DW, 1, 10, SLOT_PID, 0));
    b.emit(ins(BPF_STX_MEM_DW, 4, 1, 40, 0)); // pid_tgid
    b.emit(ins(BPF_MOV64_REG, 1, 4, 0, 0));
    b.emit(ins(BPF_MOV64_IMM, 2, 0, 0, 0));
    b.emit(ins(BPF_CALL, 0, 0, 0, sys::BPF_FUNC_RINGBUF_SUBMIT));
    b.emit(ins(BPF_MOV64_IMM, 0, 0, 0, 0));
    b.emit(ins(BPF_EXIT, 0, 0, 0, 0));

    // ring buffer full — the deny still applies; count the lost record.
    b.mark(Mark::DenyDrop);
    bump_stat(&mut b, maps.stats, STAT_DROPPED);
    b.emit(ins(BPF_MOV64_IMM, 0, 0, 0, 0));
    b.emit(ins(BPF_EXIT, 0, 0, 0, 0));

    b.resolve()
}

/// `lock *(u64*)(stats[0] + off) += 1` — best-effort counter; a lookup
/// failure leaves the deny verdict intact (observability never decides).
fn bump_stat(b: &mut Builder, stats: i32, off: i16) {
    b.emit(ins(BPF_ST_MEM_W, 10, 0, SLOT_KEY, 0));
    ld_map(b, 1, stats);
    b.emit(ins(BPF_MOV64_REG, 2, 10, 0, 0));
    b.emit(ins(BPF_ALU64_ADD_IMM, 2, 0, 0, SLOT_KEY as i32));
    b.emit(ins(BPF_CALL, 0, 0, 0, sys::BPF_FUNC_MAP_LOOKUP_ELEM));
    // r0 == NULL → skip the bump (jump over mov+xadd)
    b.emit(ins(BPF_JEQ_K, 0, 0, 2, 0));
    b.emit(ins(BPF_MOV64_IMM, 1, 0, 0, 1));
    b.emit(ins(BPF_STX_XADD_DW, 0, 1, off, 0));
}

/// How one address compare for a static entry is emitted — folded
/// from the entry's own words. Folding is only sound for *static*
/// entries: the rule maps are written once at `Runtime::prepare` and
/// never updated, so a compare that provably always-true or only needs
/// raw equality can take its constant form — same verdict, fewer
/// instructions. Grant slots stay generic: the drain rewrites them.
enum PairCmp {
    /// `mask` word(s) all zero with `addr` word(s) zero — the pair
    /// matches unconditionally; emit nothing.
    Skip,
    /// `mask` word(s) all-ones — `ctx == addr`; no AND needed.
    Raw,
    /// General `ctx & mask == addr` (including the non-canonical
    /// mask=0/addr≠0 case, which must still never match).
    Masked,
}

/// Fold a static entry's single compare word (v4).
fn word_cmp(mask: u32, addr: u32) -> PairCmp {
    match (mask, addr) {
        (0, 0) => PairCmp::Skip,
        (u32::MAX, _) => PairCmp::Raw,
        _ => PairCmp::Masked,
    }
}

/// Fold a static entry's 64-bit compare pair (v6 emits pairs).
fn pair_cmp(mask: [u32; 2], addr: [u32; 2]) -> PairCmp {
    match (mask, addr) {
        ([0, 0], [0, 0]) => PairCmp::Skip,
        ([u32::MAX, u32::MAX], _) => PairCmp::Raw,
        _ => PairCmp::Masked,
    }
}

/// Entry-block variant with the verdict wired statically.
///
/// `entry` is `Some` for static-rule slots (its fields constant-fold
/// the emitted compares — the map contents cannot change after
/// `Runtime::prepare` fills it) and `None` for grant slots (their
/// contents are dynamic, so every check stays a runtime read).
fn rule_block_ex(
    b: &mut Builder,
    kind: ProgKind,
    maps: ProgMaps,
    i: u32,
    entry: Option<&super::rules::RuleEntry>,
    allow: bool,
) {
    let grants = entry.is_none();
    let slot = i as usize + if grants { 1_000_000 } else { 0 };
    let key = i;
    // key on stack; lookup
    b.emit(ins(BPF_ST_MEM_W, 10, 0, SLOT_KEY, key as i32));
    ld_map(b, 1, if grants { maps.grants } else { maps.rules });
    b.emit(ins(BPF_MOV64_REG, 2, 10, 0, 0));
    b.emit(ins(BPF_ALU64_ADD_IMM, 2, 0, 0, SLOT_KEY as i32));
    b.emit(ins(BPF_CALL, 0, 0, 0, sys::BPF_FUNC_MAP_LOOKUP_ELEM));
    b.next(BPF_JEQ_K, 0, 0, slot); // NULL → next

    if grants {
        // exp==0 → empty slot; exp<=now → expired grant → skip.
        // (expires_at_ns at RuleEntry offset 48 — unix ns, same clock
        // domain as SLOT_NOW.)
        b.emit(ins(BPF_LDX_MEM_DW, 1, 0, 48, 0));
        b.next(BPF_JEQ_K, 1, 0, slot);
        b.emit(ins(BPF_LDX_MEM_DW, 2, 10, SLOT_NOW, 0));
        b.next(BPF_JLE_X, 1, 2, slot);
    }

    match kind {
        ProgKind::V4Connect => {
            let cmp = entry.map_or(PairCmp::Masked, |e| word_cmp(e.mask[0], e.addr[0]));
            match cmp {
                PairCmp::Skip => {}
                PairCmp::Raw => {
                    b.emit(ins(BPF_LDX_MEM_W, 1, 0, 0, 0)); // addr[0]
                    b.next(BPF_JNE_X, 7, 1, slot);
                }
                PairCmp::Masked => {
                    b.emit(ins(BPF_LDX_MEM_W, 1, 0, 16, 0)); // mask[0]
                    b.emit(ins(BPF_MOV64_REG, 3, 7, 0, 0));
                    b.emit(ins(BPF_ALU64_AND_REG, 3, 1, 0, 0));
                    b.emit(ins(BPF_LDX_MEM_W, 2, 0, 0, 0)); // addr[0]
                    b.next(BPF_JNE_X, 3, 2, slot);
                }
            }
        }
        ProgKind::V6Connect => {
            // word pair (0-1) from r7; pair (2-3) from the stack slot —
            // no callee-saved register survives to hold it.
            let cmp0 = entry.map_or(PairCmp::Masked, |e| {
                pair_cmp([e.mask[0], e.mask[1]], [e.addr[0], e.addr[1]])
            });
            match cmp0 {
                PairCmp::Skip => {}
                PairCmp::Raw => {
                    b.emit(ins(BPF_LDX_MEM_DW, 1, 0, 0, 0)); // addr[0-1]
                    b.next(BPF_JNE_X, 7, 1, slot);
                }
                PairCmp::Masked => {
                    b.emit(ins(BPF_LDX_MEM_DW, 1, 0, 16, 0)); // mask[0-1]
                    b.emit(ins(BPF_MOV64_REG, 3, 7, 0, 0));
                    b.emit(ins(BPF_ALU64_AND_REG, 3, 1, 0, 0));
                    b.emit(ins(BPF_LDX_MEM_DW, 2, 0, 0, 0)); // addr[0-1]
                    b.next(BPF_JNE_X, 3, 2, slot);
                }
            }
            let cmp1 = entry.map_or(PairCmp::Masked, |e| {
                pair_cmp([e.mask[2], e.mask[3]], [e.addr[2], e.addr[3]])
            });
            match cmp1 {
                PairCmp::Skip => {}
                PairCmp::Raw => {
                    b.emit(ins(BPF_LDX_MEM_DW, 1, 0, 8, 0)); // addr[2-3]
                    b.emit(ins(BPF_LDX_MEM_DW, 3, 10, SLOT_ADDR_HI, 0));
                    b.next(BPF_JNE_X, 3, 1, slot);
                }
                PairCmp::Masked => {
                    b.emit(ins(BPF_LDX_MEM_DW, 1, 0, 24, 0)); // mask[2-3]
                    b.emit(ins(BPF_LDX_MEM_DW, 3, 10, SLOT_ADDR_HI, 0));
                    b.emit(ins(BPF_ALU64_AND_REG, 3, 1, 0, 0));
                    b.emit(ins(BPF_LDX_MEM_DW, 2, 0, 8, 0)); // addr[2-3]
                    b.next(BPF_JNE_X, 3, 2, slot);
                }
            }
        }
    }

    // proto/port qualifiers — `0` in the entry means "any". Static
    // entries fold that away at build time; grant slots keep the
    // runtime zero-check because their fields change under the drain.
    let proto_any = entry.is_some_and(|e| e.proto == 0);
    if !proto_any {
        b.emit(ins(BPF_LDX_MEM_W, 1, 0, 32, 0)); // proto
        if grants {
            b.emit(ins(BPF_JEQ_K, 1, 0, 1, 0)); // 0=any → skip
        }
        b.next(BPF_JNE_X, 1, 9, slot);
    }
    let port_any = entry.is_some_and(|e| e.port_raw == 0);
    if !port_any {
        b.emit(ins(BPF_LDX_MEM_W, 1, 0, 36, 0)); // port_raw
        if grants {
            b.emit(ins(BPF_JEQ_K, 1, 0, 1, 0)); // 0=any → skip
        }
        b.next(BPF_JNE_X, 1, 8, slot);
    }

    // matched — record the rule index for the deny event (grant
    // hits never deny, so they skip the store), take the verdict.
    if !grants {
        b.emit(ins(BPF_ST_MEM_W, 10, 0, SLOT_MATCH, i as i32));
    }
    if allow {
        b.jump(BPF_JA, 0, 0, Mark::Allow, 0);
    } else {
        b.jump(BPF_JA, 0, 0, Mark::Deny, 0);
    }
    // `Next(slot)` resolves here — the fall-through position.
    b.mark(Mark::Next(slot));
}
