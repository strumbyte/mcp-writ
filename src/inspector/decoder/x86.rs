//! x86-64 decode backend: thin wrapper over iced-x86.
//!
//! All `iced_x86` types stay inside this module; callers see only
//! [`X86Insn`] and the semantic queries below. The register-effect logic
//! (partial registers, implicit writes, constant construction) mirrors the
//! rules that used to live in `inspector::slicer` — moved here so the slicer
//! is backend-agnostic.

use iced_x86::{Code, Decoder, DecoderOptions, FlowControl, Instruction, OpKind, Register};

/// One decoded x86-64 instruction.
///
/// Callers see only semantic queries — `iced_x86` types never leave the
/// module. The offset of an instruction within a decoded region is
/// `address() - region_vaddr`.
pub(crate) struct X86Insn {
    inner: Instruction,
}

/// Stateful helper for explicit + implicit register-write queries.
///
/// Wraps `iced_x86::InstructionInfoFactory` so its type stays private to the
/// backend.
pub(crate) struct RegWriteTracker {
    factory: iced_x86::InstructionInfoFactory,
}

impl RegWriteTracker {
    pub fn new() -> Self {
        Self {
            factory: iced_x86::InstructionInfoFactory::new(),
        }
    }
}

impl X86Insn {
    /// Instruction byte length. Part of the minimal decoder interface
    /// (instruction length/position); consumed by coverage checks added
    /// alongside the AArch64 backend.
    #[allow(dead_code)]
    pub fn len(&self) -> u64 {
        self.inner.len() as u64
    }

    /// Virtual address of this instruction.
    pub fn address(&self) -> u64 {
        self.inner.ip()
    }

    /// True if this is a `syscall` entry instruction.
    pub fn is_syscall_entry(&self) -> bool {
        self.inner.code() == Code::Syscall
    }

    /// True if control may leave the fall-through path (call/jmp/ret/int/…),
    /// which ends backward constant tracking.
    pub fn is_control_flow(&self) -> bool {
        matches!(
            self.inner.flow_control(),
            FlowControl::Call
                | FlowControl::IndirectCall
                | FlowControl::Return
                | FlowControl::UnconditionalBranch
                | FlowControl::IndirectBranch
                | FlowControl::ConditionalBranch
        )
    }

    /// If the instruction provably writes a compile-time constant to the full
    /// RAX register (mov imm forms, `xor rax,rax`), return that value.
    ///
    /// `mov eax,imm32` zero-extends; `mov r/m64,imm32` sign-extends. Partial
    /// writes (al/ah) are *not* constants — they read-modify-write RAX and
    /// are reported via [`Self::writes_rax`] instead.
    pub fn rax_constant_write(&self) -> Option<u64> {
        match self.inner.code() {
            // mov eax, imm32 (zero-extends to rax)
            Code::Mov_r32_imm32 if self.inner.op0_register() == Register::EAX => {
                Some(self.inner.immediate32() as u64)
            }
            // mov rax, imm64
            Code::Mov_r64_imm64 if self.inner.op0_register() == Register::RAX => {
                Some(self.inner.immediate64())
            }
            // mov rm64, imm32 (sign-extended)
            Code::Mov_rm64_imm32
                if self.inner.op0_kind() == OpKind::Register
                    && self.inner.op0_register() == Register::RAX =>
            {
                Some(self.inner.immediate32to64() as u64)
            }
            // xor r32/rm32 or rm32/r32 with both operands EAX → 0
            Code::Xor_r32_rm32 | Code::Xor_rm32_r32
                if self.inner.op0_register() == Register::EAX
                    && self.inner.op1_kind() == OpKind::Register
                    && self.inner.op1_register() == Register::EAX =>
            {
                Some(0)
            }
            // xor r64/rm64 or rm64/r64 with both operands RAX → 0
            Code::Xor_r64_rm64 | Code::Xor_rm64_r64
                if self.inner.op0_register() == Register::RAX
                    && self.inner.op1_kind() == OpKind::Register
                    && self.inner.op1_register() == Register::RAX =>
            {
                Some(0)
            }
            _ => None,
        }
    }

    /// True when the instruction writes to RAX or any of its subregisters
    /// (EAX, AX, AL, AH), explicitly or implicitly. Conditional writes
    /// (`cmovcc`) and read-modify-write forms count as writes.
    ///
    /// Uses `InstructionInfoFactory` (all operand accesses, including XADD's
    /// second operand) plus a supplementary table for instructions whose
    /// accumulator effect is architectural (`cpuid`, `mul`, `cmpxchg`, …).
    pub fn writes_rax(&self, tracker: &mut RegWriteTracker) -> bool {
        use iced_x86::OpAccess;

        let info = tracker.factory.info(&self.inner);
        for ur in info.used_registers() {
            if ur.register().full_register() == Register::RAX {
                match ur.access() {
                    OpAccess::Write
                    | OpAccess::CondWrite
                    | OpAccess::ReadWrite
                    | OpAccess::ReadCondWrite => return true,
                    _ => {}
                }
            }
        }
        self.modifies_rax_implicitly()
    }

    /// Instructions that implicitly modify RAX/EAX (accumulator effects).
    fn modifies_rax_implicitly(&self) -> bool {
        use iced_x86::Mnemonic;
        matches!(
            self.inner.mnemonic(),
            Mnemonic::Cpuid
                | Mnemonic::Rdtsc
                | Mnemonic::Rdtscp
                | Mnemonic::Mul
                | Mnemonic::Imul
                | Mnemonic::Div
                | Mnemonic::Idiv
                | Mnemonic::Cqo
                | Mnemonic::Cdq
                | Mnemonic::Cwd
                | Mnemonic::Cbw
                | Mnemonic::Cwde
                | Mnemonic::Cdqe
                | Mnemonic::Syscall
                | Mnemonic::Sysenter
                | Mnemonic::Int
                | Mnemonic::Cmpxchg
                | Mnemonic::Cmpxchg8b
                | Mnemonic::Cmpxchg16b
                | Mnemonic::Xlatb
                | Mnemonic::Aam
                | Mnemonic::Aad
        )
    }
}

/// Decode a whole code region into instructions.
///
/// `code` is the raw region content; `vaddr` is the virtual address where it
/// is loaded. iced-x86 yields `INVALID` instructions rather than failing, so
/// the returned vector always covers decodable prefixes; a trailing invalid
/// or truncated tail simply produces `Invalid` entries — callers that care
/// about coverage check whether the last decoded offset+len reaches
/// `code.len()`.
pub(crate) fn decode_region(code: &[u8], vaddr: u64) -> Vec<X86Insn> {
    let mut decoder = Decoder::with_ip(64, code, vaddr, DecoderOptions::NONE);
    decoder.iter().map(|inner| X86Insn { inner }).collect()
}

/// Decode `code` and invoke `f` on each instruction, without collecting.
///
/// Same decode semantics as [`decode_region`]. Whole-region scans must use
/// this rather than `decode_region`: `iced_x86::Instruction` is a large
/// struct, so materializing every instruction of a multi-MB `.text` into a
/// `Vec` is a needless memory spike when the caller only filters.
pub(crate) fn for_each_insn(code: &[u8], vaddr: u64, mut f: impl FnMut(&X86Insn)) {
    let mut decoder = Decoder::with_ip(64, code, vaddr, DecoderOptions::NONE);
    for inner in decoder.iter() {
        f(&X86Insn { inner });
    }
}
