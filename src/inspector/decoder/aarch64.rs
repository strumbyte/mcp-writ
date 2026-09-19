//! AArch64 decode backend: thin wrapper over `yaxpeax-arm`.
//!
//! All `yaxpeax_arm` / `yaxpeax_arch` types stay inside this module; callers
//! see only [`A64Insn`], [`A64Scan`], [`A64Resolution`], and the semantic
//! queries below. The backend was selected by the P4 evaluation (Pure Rust,
//! no FFI — see the ARM64 runbook) and wired to the slicer in P5.
//!
//! The register-effect logic (writeback forms, pair loads, exclusive-store
//! status registers, `w8`→`x8` zero extension, `movz`/`movn`/`movk` constant
//! construction) lives here so the slicer stays backend-agnostic.

use yaxpeax_arch::{Decoder, U8Reader};
use yaxpeax_arm::armv8::a64::{InstDecoder, Instruction, Opcode, Operand, SizeCode};

/// AArch64 instructions are fixed-width 4-byte words.
pub(crate) const INSN_LEN: u64 = 4;

/// Syscall-entry convention for a scanned AArch64 region.
///
/// The instruction set is identical; only the *entry convention* differs —
/// which `svc` immediates are syscall entries and which register carries
/// the number. This distinction is what keeps Darwin `x16` values from
/// ever being resolved against the Linux `x8` table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SyscallConvention {
    /// Linux: every `svc` is a syscall entry; the kernel dispatches on `x8`
    /// regardless of the immediate (it is only recorded in ESR_ELx.ISS).
    /// `svc #0` is the conventional encoding; other immediates are still
    /// sites, recorded as nonstandard auxiliary info.
    Linux,
    /// Darwin (XNU): only `svc #0x80` is a syscall entry and the number
    /// register is `x16` (negative = Mach trap). `svc` instructions with
    /// any other immediate are not syscall entries and are recorded only
    /// as auxiliary info.
    Darwin,
}

impl SyscallConvention {
    /// Register holding the syscall/trap number at an `svc` site. Writes to
    /// the corresponding W register zero-extend into it.
    pub(crate) fn syscall_reg(self) -> u16 {
        match self {
            Self::Linux => 8,
            Self::Darwin => 16,
        }
    }

    /// The conventional `svc` immediate for this convention.
    fn conventional_imm(self) -> u16 {
        match self {
            Self::Linux => 0,
            Self::Darwin => 0x80,
        }
    }

    /// Whether a `svc` with this immediate is a syscall entry under this
    /// convention.
    fn is_syscall_entry(self, imm: Option<u16>) -> bool {
        match self {
            Self::Linux => true,
            Self::Darwin => imm == Some(0x80),
        }
    }
}

/// Maximum number of instructions to scan backward from a syscall site.
const MAX_BACKWARD_SCAN: usize = 32;

/// Maximum number of bytes before the syscall to consider for backward
/// decoding. Same budget as the x86 path (32 instructions * 15 bytes); for
/// fixed-width AArch64 this is 120 words — comfortably over the instruction
/// limit.
const MAX_BACKWARD_BYTES: u64 = 480;

/// One decoded AArch64 instruction. `offset` is relative to the region start;
/// the virtual address is `offset + region_vaddr`.
pub(crate) struct A64Insn {
    inner: Instruction,
    offset: u64,
}

impl A64Insn {
    /// Byte offset within the decoded region.
    #[allow(dead_code)]
    pub fn offset(&self) -> u64 {
        self.offset
    }

    /// Instruction byte length. Part of the minimal decoder interface
    /// (instruction length/position) — always 4 for AArch64.
    #[allow(dead_code)]
    pub fn len(&self) -> u64 {
        INSN_LEN
    }

    /// Virtual address of this instruction. `region_vaddr` is untrusted
    /// input; wrap rather than panic near u64::MAX.
    #[allow(dead_code)]
    pub fn address(&self, region_vaddr: u64) -> u64 {
        region_vaddr.wrapping_add(self.offset)
    }

    /// True when the word decoded to an architecturally allocated encoding.
    /// `Opcode::Invalid` instructions occupy a word but carry no semantics —
    /// they count as uninterpreted coverage and stop backward tracking.
    pub fn is_interpreted(&self) -> bool {
        self.inner.opcode != Opcode::Invalid
    }

    /// True for `svc` with any immediate.
    pub fn is_svc(&self) -> bool {
        self.inner.opcode == Opcode::SVC
    }

    /// The `svc` immediate when this is an `svc` instruction.
    pub fn svc_imm(&self) -> Option<u16> {
        if !self.is_svc() {
            return None;
        }
        match self.inner.operands[0] {
            Operand::Imm16(i) => Some(i),
            Operand::Immediate(i) => Some(i as u16),
            _ => None,
        }
    }

    /// True if control may leave the fall-through path (branches, calls,
    /// returns — including pointer-authenticated forms) or transfer
    /// elsewhere via an exception (svc/hvc/smc/brk/hlt/dcps/udf), which ends
    /// backward constant tracking. A preceding `svc` is a boundary too: the
    /// kernel owns the register file across the trap.
    pub fn is_control_flow(&self) -> bool {
        matches!(
            self.inner.opcode,
            Opcode::B
                | Opcode::Bcc(_)
                | Opcode::BCcc(_)
                | Opcode::BL
                | Opcode::BR
                | Opcode::BLR
                | Opcode::RET
                | Opcode::ERET
                | Opcode::DRPS
                | Opcode::CBZ
                | Opcode::CBNZ
                | Opcode::TBZ
                | Opcode::TBNZ
                // Pointer-authenticated branches/returns (FEAT_PAuth,
                // FEAT_PAuth_LR): `retaa`/`braa`/`blraa` end tracking just
                // like the plain forms.
                | Opcode::BRAA
                | Opcode::BRAAZ
                | Opcode::BRAB
                | Opcode::BRABZ
                | Opcode::BLRAA
                | Opcode::BLRAAZ
                | Opcode::BLRAB
                | Opcode::BLRABZ
                | Opcode::RETAA
                | Opcode::RETAB
                | Opcode::RETAASPPC
                | Opcode::RETABSPPC
                | Opcode::RETAASPPCR
                | Opcode::RETABSPPCR
                | Opcode::ERETAA
                | Opcode::ERETAB
                | Opcode::SVC
                | Opcode::HVC
                | Opcode::SMC
                | Opcode::BRK
                | Opcode::HLT
                | Opcode::DCPS1
                | Opcode::DCPS2
                | Opcode::DCPS3
                | Opcode::UDF
        )
    }

    /// True when the instruction writes the syscall-number register
    /// (`x8`/`w8` for Linux, `x16`/`w16` for Darwin) — explicitly or
    /// implicitly — in a form we could not prove constant. This includes
    /// loads (memory-derived), conditional selects, atomics, exclusive-store
    /// status registers, and load/store writeback of a matching base.
    pub fn writes_syscall_reg(&self, reg: u16) -> bool {
        // operand[0] is the destination GPR unless the opcode uses it as a
        // pure source (plain stores, compares, tag stores, flag producers).
        if let Some((n, _)) = gpr(&self.inner.operands[0])
            && n == reg
            && !op0_is_source(self.inner.opcode)
        {
            return true;
        }
        // GPR destinations past operand[0]: pair loads write operand[1],
        // the swp/ldadd atomic families decode `[Rs (source), Rt
        // (destination), addr]`, and `sysl` returns its result in
        // operand[2].
        if writes_later_operand(self.inner.opcode)
            && self.inner.operands[1..]
                .iter()
                .filter_map(gpr)
                .any(|(n, _)| n == reg)
        {
            return true;
        }
        // Pair-register operands (casp's compare/store pair) write n and n+1.
        for op in &self.inner.operands {
            if let Operand::RegisterPair(_, n) = op
                && (*n == reg || *n + 1 == reg)
            {
                return true;
            }
        }
        // Writeback forms write the base register.
        for op in &self.inner.operands {
            match op {
                Operand::RegPreIndex(n, _, true)
                | Operand::RegPostIndex(n, _)
                | Operand::RegPostIndexReg(n, _)
                    if *n == reg =>
                {
                    return true;
                }
                _ => {}
            }
        }
        false
    }

    /// If the instruction provably writes a compile-time constant to the
    /// syscall-number register `reg`, return `(value, defined_mask)` — the
    /// value bits that are defined and a mask of the register bits this
    /// write determines. `movz`/`movn` define the whole register (W
    /// destinations additionally zero bits 63:32); `movk` defines only its
    /// 16-bit field — a lone `movk` never resolves a value.
    /// The bitmask-immediate `mov` alias (`orr wd, wzr, #imm`) also defines
    /// the whole register.
    pub fn syscall_reg_const_write(&self, reg: u16) -> Option<(u64, u64)> {
        let (n, dst64) = gpr(&self.inner.operands[0])?;
        if n != reg {
            return None;
        }
        // A W-register write zeroes bits 63:32 of x8 — those bits become
        // known-zero regardless of the instruction's own field coverage.
        let upper32: u64 = if dst64 { 0 } else { 0xFFFF_FFFF_0000_0000 };
        let width: u64 = if dst64 { u64::MAX } else { 0xFFFF_FFFF };
        match self.inner.opcode {
            Opcode::MOVZ => {
                let (imm, shift) = imm_shift(&self.inner.operands[1])?;
                let value = ((imm as u64) << shift) & width;
                Some((value, u64::MAX))
            }
            Opcode::MOVN => {
                let (imm, shift) = imm_shift(&self.inner.operands[1])?;
                let value = (!((imm as u64) << shift)) & width;
                Some((value, u64::MAX))
            }
            Opcode::MOVK => {
                let (imm, shift) = imm_shift(&self.inner.operands[1])?;
                let field = 0xFFFFu64 << shift;
                let value = ((imm as u64) << shift) & field;
                Some((value, field | upper32))
            }
            // `mov wd, #imm` when only encodable as a bitmask immediate
            // decodes as `orr wd, wzr, #imm`: wzr contributes 0, so the
            // register takes the immediate exactly. Only the plain Register
            // operand is the zero register — RegisterOrSP(31) would be sp.
            Opcode::ORR => {
                if !matches!(self.inner.operands[1], Operand::Register(_, 31)) {
                    return None;
                }
                let value = match &self.inner.operands[2] {
                    Operand::Immediate(i) => *i as u64,
                    Operand::Imm64(i) => *i,
                    _ => return None,
                };
                if !matches!(self.inner.operands[3], Operand::Nothing) {
                    return None;
                }
                Some((value & width, u64::MAX))
            }
            _ => None,
        }
    }
}

/// GPR operand → (register number, is 64-bit).
fn gpr(op: &Operand) -> Option<(u16, bool)> {
    match op {
        Operand::Register(sz, n) | Operand::RegisterOrSP(sz, n) => Some((*n, *sz == SizeCode::X)),
        _ => None,
    }
}

/// Opcodes whose operand[0] is a read-only GPR source, not a destination.
/// Anything else with a GPR operand[0] is conservatively treated as a write;
/// that direction can only over-report `x8` writes, never miss one.
fn op0_is_source(op: Opcode) -> bool {
    matches!(
        op,
        Opcode::STR
            | Opcode::STRB
            | Opcode::STRH
            | Opcode::STRW
            | Opcode::STUR
            | Opcode::STURB
            | Opcode::STURH
            | Opcode::STLUR
            | Opcode::STLURB
            | Opcode::STLURH
            | Opcode::STTR
            | Opcode::STTRB
            | Opcode::STTRH
            | Opcode::STNP
            | Opcode::STP
            | Opcode::STLR
            | Opcode::STLLR
            | Opcode::STLRB
            | Opcode::STLLRB
            | Opcode::STLRH
            | Opcode::STLLRH
            // Memory-tag stores read operand[0] as the tagged address.
            | Opcode::STG
            | Opcode::ST2G
            | Opcode::STZG
            | Opcode::STZGM
            | Opcode::STGM
            // Compare-with-flags and flag producers read operand[0].
            | Opcode::CCMN
            | Opcode::CCMP
            | Opcode::RMIF
            | Opcode::SETF8
            | Opcode::SETF16
            // `sys` reads operand[0] as the input register (`dc zva, x8`,
            // `tlbi ...`); the result-returning form is `sysl`.
            | Opcode::SYS(_)
            // Atomics read operand[0] (`Rs`, the swap-in/RMW operand) — the
            // destination sits in operand[1], handled by
            // `writes_later_operand`.
            | Opcode::SWP(_)
            | Opcode::SWPB(_)
            | Opcode::SWPH(_)
            | Opcode::LDADD(_)
            | Opcode::LDADDB(_)
            | Opcode::LDADDH(_)
            | Opcode::LDCLR(_)
            | Opcode::LDCLRB(_)
            | Opcode::LDCLRH(_)
            | Opcode::LDEOR(_)
            | Opcode::LDEORB(_)
            | Opcode::LDEORH(_)
            | Opcode::LDSET(_)
            | Opcode::LDSETB(_)
            | Opcode::LDSETH(_)
            | Opcode::LDSMAX(_)
            | Opcode::LDSMAXB(_)
            | Opcode::LDSMAXH(_)
            | Opcode::LDSMIN(_)
            | Opcode::LDSMINB(_)
            | Opcode::LDSMINH(_)
            | Opcode::LDUMAX(_)
            | Opcode::LDUMAXB(_)
            | Opcode::LDUMAXH(_)
            | Opcode::LDUMIN(_)
            | Opcode::LDUMINB(_)
            | Opcode::LDUMINH(_)
    )
}

/// Opcodes that write a GPR destination at operand[1] or later. Pair loads
/// write operand[1]; `swp` and the `ldadd`-family atomics decode
/// `[Rs (source), Rt (destination), addr]`; `sysl` returns in operand[2].
/// Pair stores are covered by `op0_is_source`; exclusive stores write
/// operand[0] (the status register) so they are *not* listed anywhere.
fn writes_later_operand(op: Opcode) -> bool {
    matches!(
        op,
        Opcode::LDP
            | Opcode::LDPSW
            | Opcode::LDNP
            | Opcode::LDAXP
            | Opcode::LDXP
            | Opcode::SWP(_)
            | Opcode::SWPB(_)
            | Opcode::SWPH(_)
            | Opcode::LDADD(_)
            | Opcode::LDADDB(_)
            | Opcode::LDADDH(_)
            | Opcode::LDCLR(_)
            | Opcode::LDCLRB(_)
            | Opcode::LDCLRH(_)
            | Opcode::LDEOR(_)
            | Opcode::LDEORB(_)
            | Opcode::LDEORH(_)
            | Opcode::LDSET(_)
            | Opcode::LDSETB(_)
            | Opcode::LDSETH(_)
            | Opcode::LDSMAX(_)
            | Opcode::LDSMAXB(_)
            | Opcode::LDSMAXH(_)
            | Opcode::LDSMIN(_)
            | Opcode::LDSMINB(_)
            | Opcode::LDSMINH(_)
            | Opcode::LDUMAX(_)
            | Opcode::LDUMAXB(_)
            | Opcode::LDUMAXH(_)
            | Opcode::LDUMIN(_)
            | Opcode::LDUMINB(_)
            | Opcode::LDUMINH(_)
            | Opcode::SYSL(_)
    )
}

/// Extract `(imm16, shift)` from a MOVZ/MOVN/MOVK immediate operand.
fn imm_shift(op: &Operand) -> Option<(u16, u8)> {
    match op {
        Operand::Imm16(i) => Some((*i, 0)),
        Operand::ImmShift(i, s) => Some((*i, *s)),
        Operand::Immediate(i) => Some((*i as u16, 0)),
        _ => None,
    }
}

/// Decode the 4-byte word at `offset` in `code`.
///
/// `None` means the decoder rejected the word (`DecodeError`). A returned
/// instruction may still carry `Opcode::Invalid` for encodings the decoder
/// materializes but does not allocate — [`A64Insn::is_interpreted`]
/// distinguishes the two.
fn decode_at(code: &[u8], offset: usize) -> Option<A64Insn> {
    let word = code.get(offset..offset + INSN_LEN as usize)?;
    let decoder = InstDecoder::default();
    let mut reader = U8Reader::new(word);
    decoder.decode(&mut reader).ok().map(|inner| A64Insn {
        inner,
        offset: offset as u64,
    })
}

/// Coverage accounting from scanning one code region as AArch64 words.
#[derive(Debug, Clone, Default)]
pub(crate) struct A64Coverage {
    /// `svc` sites that are syscall entries under the scan convention —
    /// every `svc` under Linux, only `svc #0x80` under Darwin.
    pub sites: Vec<u64>,
    /// `svc` instructions whose immediate is not the convention's
    /// conventional one, recorded as `(offset, immediate)` auxiliary info.
    /// Under Linux the immediate does not change dispatch; under Darwin a
    /// non-`#0x80` `svc` is not a syscall entry at all.
    pub nonstandard_svc: Vec<(u64, Option<u16>)>,
    /// 4-byte words that failed to decode or carry an invalid encoding.
    pub uninterpreted_words: u64,
    /// Bytes left over when the region length is not a multiple of 4.
    pub trailing_bytes: u64,
    /// Offset of the first uninterpreted word, for diagnostics.
    pub first_uninterpreted: Option<u64>,
}

/// Scan a code region as fixed-width AArch64 instructions under the given
/// syscall-entry convention.
///
/// Every 4-byte word is decoded independently; a word that fails to decode
/// (or yields `Opcode::Invalid`) is recorded as uninterpreted and scanning
/// continues at the next word — fixed-width instructions mean a gap cannot
/// hide a real `svc` behind misalignment.
pub(crate) fn scan_region(code: &[u8], convention: SyscallConvention) -> A64Coverage {
    let mut cov = A64Coverage::default();
    let words = code.len() / INSN_LEN as usize;
    cov.trailing_bytes = (code.len() % INSN_LEN as usize) as u64;
    for i in 0..words {
        let offset = i * INSN_LEN as usize;
        match decode_at(code, offset) {
            Some(insn) if insn.is_interpreted() => {
                if insn.is_svc() {
                    let imm = insn.svc_imm();
                    if convention.is_syscall_entry(imm) {
                        cov.sites.push(offset as u64);
                    }
                    if imm != Some(convention.conventional_imm()) {
                        // Nonstandard (or undecoded) immediate — auxiliary
                        // info rather than silently assuming the
                        // conventional entry encoding.
                        cov.nonstandard_svc.push((offset as u64, imm));
                    }
                }
            }
            _ => {
                cov.uninterpreted_words += 1;
                if cov.first_uninterpreted.is_none() {
                    cov.first_uninterpreted = Some(offset as u64);
                }
            }
        }
    }
    cov
}

/// The proven syscall-register value at a `svc` site, or why it could not
/// be proven.
pub(crate) enum A64Resolution {
    /// The syscall-number register provably held this constant when the
    /// `svc` executed. Interpretation (Linux `x8` vs Darwin `x16` sign
    /// semantics) is the caller's concern.
    Resolved(u64),
    /// Why the register value could not be proven (stable tag for
    /// reporting).
    Unresolved(&'static str),
}

/// Backward-track the convention's syscall register to the `svc` at
/// `site_offset` within `code`.
///
/// Walks at most `MAX_BACKWARD_SCAN` instructions within `MAX_BACKWARD_BYTES`
/// before the site. The walk stops unresolved at control flow, decode gaps,
/// and any register write whose value cannot be proven constant — it never
/// skips an unknown instruction to adopt an older constant.
pub(crate) fn resolve_syscall_reg(
    code: &[u8],
    site_offset: u64,
    convention: SyscallConvention,
) -> A64Resolution {
    let reg = convention.syscall_reg();
    let window_start = site_offset.saturating_sub(MAX_BACKWARD_BYTES);
    let site = site_offset as usize;
    // `site` must be the offset of a word inside the region — an offset at
    // or beyond the end cannot be an svc instruction.
    if site >= code.len() {
        return A64Resolution::Unresolved("svc site outside code region");
    }
    let window = &code[window_start as usize..site];

    // Decode the window word-wise so a bad word mid-window is a precise gap
    // rather than a truncation of everything before it.
    let mut insns: Vec<Option<A64Insn>> = Vec::with_capacity(window.len() / 4);
    for i in (0..window.len()).step_by(INSN_LEN as usize) {
        insns.push(decode_at(window, i).map(|insn| A64Insn {
            inner: insn.inner,
            offset: window_start + insn.offset,
        }));
    }

    // Register-name-aware detail strings.
    let (nonconst_write, no_write) = match reg {
        16 => (
            "non-constant write to x16",
            "no x16 write found in backward window",
        ),
        _ => (
            "non-constant write to x8",
            "no x8 write found in backward window",
        ),
    };

    // Accumulate the proven bits of the register: `known` holds values for
    // bits in `mask`, established by later (program-order) instructions.
    let mut known: u64 = 0;
    let mut mask: u64 = 0;
    for slot in insns.iter().rev().take(MAX_BACKWARD_SCAN) {
        let Some(insn) = slot else {
            return A64Resolution::Unresolved("decode gap in backward window");
        };
        if !insn.is_interpreted() {
            return A64Resolution::Unresolved("unallocated encoding in backward window");
        }
        if insn.is_control_flow() {
            return A64Resolution::Unresolved("control-flow boundary before svc");
        }
        if let Some((value, defined)) = insn.syscall_reg_const_write(reg) {
            let fresh = defined & !mask;
            known = (known & !fresh) | (value & fresh);
            mask |= defined;
            if mask == u64::MAX {
                return A64Resolution::Resolved(known);
            }
            continue;
        }
        if insn.writes_syscall_reg(reg) {
            return A64Resolution::Unresolved(nonconst_write);
        }
    }
    if mask != 0 {
        A64Resolution::Unresolved("incomplete movz/movn/movk constant construction")
    } else {
        A64Resolution::Unresolved(no_write)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const X8: u16 = 8;

    fn word(b: &[u8; 4]) -> Option<A64Insn> {
        decode_at(b, 0)
    }

    #[test]
    fn svc_and_nop_decode() {
        // svc #0 = 0xD4000001, nop = 0xD503201F
        let svc = word(&[0x01, 0x00, 0x00, 0xD4]).expect("svc decodes");
        assert!(svc.is_svc());
        assert_eq!(svc.svc_imm(), Some(0));
        let nop = word(&[0x1F, 0x20, 0x03, 0xD5]).expect("nop decodes");
        assert!(!nop.is_svc());
        assert!(!nop.is_control_flow());
        assert!(!nop.writes_syscall_reg(X8));
    }

    #[test]
    fn mov_variants_decode() {
        // movz w8, #64 = 0x52800808; movz x8, #0x1234 = 0xD2824688
        let w = word(&[0x08, 0x08, 0x80, 0x52]).expect("movz w8");
        assert_eq!(w.syscall_reg_const_write(X8), Some((64, u64::MAX)));
        let x = word(&[0x88, 0x46, 0x82, 0xD2]).expect("movz x8");
        assert_eq!(x.syscall_reg_const_write(X8), Some((0x1234, u64::MAX)));
        // movn w8, #0 = 0x12800008 → w8 = 0xFFFFFFFF, x8 upper half zeroed
        let n = word(&[0x08, 0x00, 0x80, 0x12]).expect("movn w8");
        assert_eq!(n.syscall_reg_const_write(X8), Some((0xFFFF_FFFF, u64::MAX)));
        // movk x8, #5, lsl #16 = 0xF2A000A8 → only field[31:16] defined
        let k = word(&[0xA8, 0x00, 0xA0, 0xF2]).expect("movk x8");
        assert_eq!(k.syscall_reg_const_write(X8), Some((0x5_0000, 0xFFFF_0000)));
        // mov x8, x9 = orr x8, xzr, x9 = 0xAA0903E8 → non-constant write
        let mov = word(&[0xE8, 0x03, 0x09, 0xAA]).expect("mov x8, x9");
        assert_eq!(mov.syscall_reg_const_write(X8), None);
        assert!(mov.writes_syscall_reg(X8));
        // mov w8, #0x55555555 = orr w8, wzr, #0x55555555 = 0x3200F3E8 →
        // bitmask-immediate mov alias: full constant write.
        let orr = word(&[0xE8, 0xF3, 0x00, 0x32]).expect("orr w8 bitmask");
        assert_eq!(
            orr.syscall_reg_const_write(X8),
            Some((0x5555_5555, u64::MAX))
        );
        // mov x8, #0x5555555555555555 = orr x8, xzr, #... = 0xB200F3E8
        let orr64 = word(&[0xE8, 0xF3, 0x00, 0xB2]).expect("orr x8 bitmask");
        assert_eq!(
            orr64.syscall_reg_const_write(X8),
            Some((0x5555_5555_5555_5555, u64::MAX))
        );
        // orr w8, w9, #imm — source is not wzr → not a mov alias.
        // orr w8, w9, #0x55555555 = 0x3200F128
        let orr_src = word(&[0x28, 0xF1, 0x00, 0x32]).expect("orr w8,w9");
        assert_eq!(orr_src.syscall_reg_const_write(X8), None);
        assert!(orr_src.writes_syscall_reg(X8));
    }

    #[test]
    fn write_effect_queries() {
        // ldr w8, [x0] = 0xB9400008 — memory-derived write
        let ldr = word(&[0x08, 0x00, 0x40, 0xB9]).expect("ldr w8");
        assert!(ldr.writes_syscall_reg(X8));
        // str x8, [x0] = 0xF9000008 — store reads x8, no write
        let str_ = word(&[0x08, 0x00, 0x00, 0xF9]).expect("str x8");
        assert!(!str_.writes_syscall_reg(X8));
        // cmp x8, #1 = subs xzr, x8, #1 = 0xF100051F — compare, no write
        let cmp = word(&[0x1F, 0x05, 0x00, 0xF1]).expect("cmp x8,#1");
        assert!(!cmp.writes_syscall_reg(X8));
        // csel w8, w9, w10, eq = 0x1A8A0128 — conditional write
        let csel = word(&[0x28, 0x01, 0x8A, 0x1A]).expect("csel w8");
        assert!(csel.writes_syscall_reg(X8));
        // add x8, x8, #1 = 0x91000508 — arithmetic write
        let add = word(&[0x08, 0x05, 0x00, 0x91]).expect("add x8");
        assert!(add.writes_syscall_reg(X8));
        // ldr x0, [x8, #8]! = 0xF8408508 — writeback writes base x8
        let ldr_wb = word(&[0x08, 0x85, 0x40, 0xF8]).expect("ldr wb");
        assert!(ldr_wb.writes_syscall_reg(X8));
    }

    #[test]
    fn unallocated_word_is_uninterpreted() {
        // 0xFFFFFFFF is an unallocated encoding.
        assert!(word(&[0xFF, 0xFF, 0xFF, 0xFF]).is_none_or(|i| !i.is_interpreted()));
    }

    #[test]
    fn authenticated_control_flow_is_a_boundary() {
        // retaa = 0xD65F0BFF — authenticated return (FEAT_PAuth).
        let retaa = word(&[0xFF, 0x0B, 0x5F, 0xD6]).expect("retaa decodes");
        assert!(retaa.is_control_flow());
        // braaz x8 = 0xD71F091F — authenticated indirect branch.
        let braaz = word(&[0x1F, 0x09, 0x1F, 0xD7]).expect("braaz decodes");
        assert!(braaz.is_control_flow());
        // blraaz x8 = 0xD73F091F — authenticated indirect call.
        let blraaz = word(&[0x1F, 0x09, 0x3F, 0xD7]).expect("blraaz decodes");
        assert!(blraaz.is_control_flow());
        // eretaa = 0xD69F0BFF — authenticated exception return.
        let eretaa = word(&[0xFF, 0x0B, 0x9F, 0xD6]).expect("eretaa decodes");
        assert!(eretaa.is_control_flow());
        // bc.eq +0 = 0x54000010 — consistent conditional branch (FEAT_HBC).
        let bc = word(&[0x10, 0x00, 0x00, 0x54]).expect("bc.eq decodes");
        assert!(bc.is_control_flow());
    }

    #[test]
    fn atomic_op1_destination_is_a_write() {
        // swp w9, w8, [x0] = 0xB8298008 — operand[1] (w8) receives the old
        // memory value: a non-constant write to x8.
        let swp = word(&[0x08, 0x80, 0x29, 0xB8]).expect("swp decodes");
        assert!(swp.writes_syscall_reg(X8));
        // ldadd w9, w8, [x0] = 0xB8290008 — same operand[1] destination.
        let ldadd = word(&[0x08, 0x00, 0x29, 0xB8]).expect("ldadd decodes");
        assert!(ldadd.writes_syscall_reg(X8));
        // swp w8, w0, [x1] = 0xB8288020 — w8 is operand[0], the read-only
        // swap-in source: it must not stop tracking.
        let swp_src = word(&[0x20, 0x80, 0x28, 0xB8]).expect("swp src decodes");
        assert!(!swp_src.writes_syscall_reg(X8));
        // sysl x8, #0, c0, c0, #0 = 0xD5280008 — result register sits in
        // operand[2].
        let sysl = word(&[0x08, 0x00, 0x28, 0xD5]).expect("sysl decodes");
        assert!(sysl.writes_syscall_reg(X8));
        // sys #3, c7, c4, #1, x8 = 0xD50B7428 — `dc zva, x8` reads x8 only.
        let sys = word(&[0x28, 0x74, 0x0B, 0xD5]).expect("sys decodes");
        assert!(!sys.writes_syscall_reg(X8));
    }

    #[test]
    fn atomic_write_stops_backward_tracking() {
        // movz w8, #64 ; swp w9, w8, [x0] ; svc #0 — the atomic clobbers x8
        // via operand[1], so the earlier movz must not resolve the site.
        let code: &[u8] = &[
            0x08, 0x08, 0x80, 0x52, // movz w8, #64
            0x08, 0x80, 0x29, 0xB8, // swp w9, w8, [x0]
            0x01, 0x00, 0x00, 0xD4, // svc #0
        ];
        assert!(matches!(
            resolve_syscall_reg(code, 8, SyscallConvention::Linux),
            A64Resolution::Unresolved(_)
        ));
        // movz w8, #1 ; swp w8, w0, [x1] ; svc #0 — w8 is only the swap-in
        // source; the constant survives and resolves to 1.
        let code: &[u8] = &[
            0x28, 0x00, 0x80, 0x52, // movz w8, #1
            0x20, 0x80, 0x28, 0xB8, // swp w8, w0, [x1]
            0x01, 0x00, 0x00, 0xD4, // svc #0
        ];
        assert!(matches!(
            resolve_syscall_reg(code, 8, SyscallConvention::Linux),
            A64Resolution::Resolved(1)
        ));
        // movz w8, #64 ; retaa ; svc #0 — an authenticated return is a
        // control-flow boundary; the constant belongs to a different frame.
        let code: &[u8] = &[
            0x08, 0x08, 0x80, 0x52, // movz w8, #64
            0xFF, 0x0B, 0x5F, 0xD6, // retaa
            0x01, 0x00, 0x00, 0xD4, // svc #0
        ];
        assert!(matches!(
            resolve_syscall_reg(code, 8, SyscallConvention::Linux),
            A64Resolution::Unresolved(_)
        ));
    }
}
