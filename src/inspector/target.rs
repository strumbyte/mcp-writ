//! Static target identification and analysis-state model for the Inspector.
//!
//! These types separate *what* an input is (container format, ISA, ABI,
//! endianness, code ranges) from *how far* analysis got. A status other than
//! [`AnalysisStatus::Analyzed`] must never be read as "no findings" — it
//! means findings were not produced and the reason explains why.

use crate::error::InspectorError;

/// Binary container format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinaryFormat {
    /// Executable and Linkable Format (Linux, *BSD, …).
    Elf,
    /// Mach-O (Darwin); recognized, analysis planned in a later phase.
    MachO,
    /// PE/COFF (Windows); recognized but not analyzed.
    Pe,
    /// Magic bytes do not match a known format.
    Unknown,
}

/// CPU instruction set of the slice being analyzed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Isa {
    /// x86-64 / AMD64.
    X86_64,
    /// AArch64 / ARM64.
    AArch64,
    /// A recognized machine ID with no decoder backend in this build.
    Other,
    /// ISA could not be determined from the input.
    Unknown,
}

/// Syscall numbering convention applicable to the target.
///
/// This is about which syscall table applies to decoded entry instructions,
/// not about which OS the *host* runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyscallAbi {
    /// Linux syscall table for the target ISA.
    Linux,
    /// Convention could not be determined (non-Linux EI_OSABI, non-ELF
    /// formats, …). Syscall numbers must not be mapped to Linux names.
    Unknown,
}

/// Byte order of the analyzed code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Endianness {
    Little,
    Big,
    /// Not recorded or not applicable for the format.
    Unknown,
}

/// ELF container class (bitness).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ElfClass {
    Elf32,
    Elf64,
}

/// An executable code range inside the input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodeRegion {
    /// Section name (e.g. `.text`).
    pub name: String,
    /// File offset of the region.
    pub file_offset: u64,
    /// Region size in bytes.
    pub size: u64,
    /// Virtual address where the region is loaded.
    pub vaddr: u64,
    /// Whether this range was decoded end to end by analysis. A partially
    /// decoded region stays `false` alongside the `Partial` state.
    pub analyzed: bool,
}

/// Statically identified analysis target (a single slice).
#[derive(Debug, Clone)]
pub struct AnalysisTarget {
    pub format: BinaryFormat,
    pub isa: Isa,
    pub abi: SyscallAbi,
    pub endianness: Endianness,
    pub elf_class: Option<ElfClass>,
    /// Arch slice inside multi-arch containers (fat Mach-O); always `None`
    /// for plain ELF inputs.
    pub slice: Option<String>,
    /// Raw ELF `e_machine` value when `format == Elf`.
    pub machine: Option<u16>,
    /// Executable code ranges discovered in the input.
    pub code_regions: Vec<CodeRegion>,
}

/// Coarse status of one analysis component.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnalysisStatus {
    /// The declared code ranges were analyzed end to end. A zero finding
    /// count is meaningful only in this state.
    Analyzed,
    /// Some instructions or ranges could not be handled.
    Partial,
    /// Format, ISA, or ABI is out of scope for this build.
    Unsupported,
    /// Native instruction analysis does not apply to this input.
    NotApplicable,
    /// Analysis could not run (malformed input, decoder failure, …).
    Failed,
}

/// Stable machine-readable reason attached to a non-`Analyzed` status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReasonCode {
    /// Container format out of scope.
    UnsupportedFormat,
    /// ISA has no decoder backend in this build.
    UnsupportedIsa,
    /// ISA is decodable but the syscall ABI convention is unknown.
    UnknownAbi,
    /// ELF class/endianness combination not supported.
    UnsupportedVariant,
    /// No executable code region present in the input.
    NoCodeRegion,
    /// Input is corrupt or truncated beyond safe handling.
    MalformedInput,
    /// Native analysis does not apply (interpreter payloads).
    NonNativePayload,
    /// Only part of the executable ranges could be analyzed.
    PartialCoverage,
}

/// Status + reason for one analysis component.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnalysisState {
    pub status: AnalysisStatus,
    /// Machine-stable reason code; `None` when `status == Analyzed`.
    pub reason: Option<ReasonCode>,
    /// Optional human-facing detail (kept out of machine contracts).
    pub detail: Option<String>,
}

impl AnalysisState {
    pub fn analyzed() -> Self {
        Self {
            status: AnalysisStatus::Analyzed,
            reason: None,
            detail: None,
        }
    }

    pub fn unsupported(reason: ReasonCode, detail: impl Into<String>) -> Self {
        Self {
            status: AnalysisStatus::Unsupported,
            reason: Some(reason),
            detail: Some(detail.into()),
        }
    }

    pub fn failed(reason: ReasonCode, detail: impl Into<String>) -> Self {
        Self {
            status: AnalysisStatus::Failed,
            reason: Some(reason),
            detail: Some(detail.into()),
        }
    }

    pub fn not_applicable(detail: impl Into<String>) -> Self {
        Self {
            status: AnalysisStatus::NotApplicable,
            reason: Some(ReasonCode::NonNativePayload),
            detail: Some(detail.into()),
        }
    }

    pub fn partial(detail: impl Into<String>) -> Self {
        Self {
            status: AnalysisStatus::Partial,
            reason: Some(ReasonCode::PartialCoverage),
            detail: Some(detail.into()),
        }
    }
}

/// Per-component analysis state attached to a `CapabilityProfile`.
#[derive(Debug, Clone)]
pub struct AnalysisReport {
    pub target: AnalysisTarget,
    /// ELF symbol/import analysis state.
    pub symbols: AnalysisState,
    /// String extraction/classification state.
    pub strings: AnalysisState,
    /// Syscall site detection + number resolution state.
    pub syscalls: AnalysisState,
}

impl AnalysisReport {
    /// Report for a fully analyzed target.
    pub fn analyzed(target: AnalysisTarget) -> Self {
        Self {
            target,
            symbols: AnalysisState::analyzed(),
            strings: AnalysisState::analyzed(),
            syscalls: AnalysisState::analyzed(),
        }
    }

    /// Linux x86-64 ELF target metadata (used by tests and callers that build
    /// synthetic profiles for the primary supported target).
    pub fn analyzed_linux_x86_64() -> Self {
        Self::analyzed(AnalysisTarget {
            format: BinaryFormat::Elf,
            isa: Isa::X86_64,
            abi: SyscallAbi::Linux,
            endianness: Endianness::Little,
            elf_class: Some(ElfClass::Elf64),
            slice: None,
            machine: Some(goblin::elf::header::EM_X86_64),
            code_regions: Vec::new(),
        })
    }

    /// Report used when native ELF analysis does not apply at all
    /// (interpreter payloads analyzed via the source path).
    pub fn not_applicable() -> Self {
        Self {
            target: AnalysisTarget {
                format: BinaryFormat::Unknown,
                isa: Isa::Unknown,
                abi: SyscallAbi::Unknown,
                endianness: Endianness::Unknown,
                elf_class: None,
                slice: None,
                machine: None,
                code_regions: Vec::new(),
            },
            symbols: AnalysisState::not_applicable(
                "non-native payload; ELF analysis not applicable",
            ),
            strings: AnalysisState::not_applicable(
                "non-native payload; ELF analysis not applicable",
            ),
            syscalls: AnalysisState::not_applicable(
                "non-native payload; native code analysis not applicable",
            ),
        }
    }
}

impl AnalysisStatus {
    /// Stable snake_case token used in JSON/KDL output.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Analyzed => "analyzed",
            Self::Partial => "partial",
            Self::Unsupported => "unsupported",
            Self::NotApplicable => "not_applicable",
            Self::Failed => "failed",
        }
    }
}

impl ReasonCode {
    /// Stable snake_case token used in JSON/KDL output.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::UnsupportedFormat => "unsupported_format",
            Self::UnsupportedIsa => "unsupported_isa",
            Self::UnknownAbi => "unknown_abi",
            Self::UnsupportedVariant => "unsupported_variant",
            Self::NoCodeRegion => "no_code_region",
            Self::MalformedInput => "malformed_input",
            Self::NonNativePayload => "non_native_payload",
            Self::PartialCoverage => "partial_coverage",
        }
    }
}

impl Isa {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::X86_64 => "x86_64",
            Self::AArch64 => "aarch64",
            Self::Other => "other",
            Self::Unknown => "unknown",
        }
    }
}

impl BinaryFormat {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Elf => "elf",
            Self::MachO => "macho",
            Self::Pe => "pe",
            Self::Unknown => "unknown",
        }
    }
}

impl SyscallAbi {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Linux => "linux",
            Self::Unknown => "unknown",
        }
    }
}

impl Endianness {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Little => "little",
            Self::Big => "big",
            Self::Unknown => "unknown",
        }
    }
}

impl ElfClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Elf32 => "elf32",
            Self::Elf64 => "elf64",
        }
    }
}

/// Identify the analysis target from raw input bytes.
///
/// Returns `Err` only when the input is too short or an ELF header is too
/// damaged to identify class/endianness/machine — the caller treats that as
/// a failed analysis. Unrecognized or recognized-but-unsupported formats are
/// returned as `BinaryFormat` values so callers can report state instead of
/// silently producing zero findings.
pub fn identify(bytes: &[u8]) -> Result<AnalysisTarget, InspectorError> {
    let magic = bytes
        .get(..4)
        .ok_or_else(|| InspectorError::ParseError("input too small to identify".into()))?;

    let mut target = AnalysisTarget {
        format: BinaryFormat::Unknown,
        isa: Isa::Unknown,
        abi: SyscallAbi::Unknown,
        endianness: Endianness::Unknown,
        elf_class: None,
        slice: None,
        machine: None,
        code_regions: Vec::new(),
    };

    match magic {
        [0x7f, b'E', b'L', b'F'] => {
            target.format = BinaryFormat::Elf;
            identify_elf(bytes, &mut target)?;
        }
        // Mach-O: 32/64-bit, both byte orders, plus fat/universal headers.
        // Note: CA FE BA BE also heads Java .class files; those are labeled
        // "macho" and both end at unsupported_format, so the ambiguity is
        // display-only.
        [0xFE, 0xED, 0xFA, 0xCE]
        | [0xFE, 0xED, 0xFA, 0xCF]
        | [0xCE, 0xFA, 0xED, 0xFE]
        | [0xCF, 0xFA, 0xED, 0xFE]
        | [0xCA, 0xFE, 0xBA, 0xBE]
        | [0xCA, 0xFE, 0xBA, 0xBF]
        | [0xBE, 0xBA, 0xFE, 0xCA]
        | [0xBF, 0xBA, 0xFE, 0xCA] => {
            target.format = BinaryFormat::MachO;
        }
        [b'M', b'Z', ..] => {
            target.format = BinaryFormat::Pe;
        }
        _ => {}
    }
    Ok(target)
}

/// Read ELF identification fields (class, data encoding, osabi, e_machine)
/// directly from the header without full parsing.
fn identify_elf(bytes: &[u8], target: &mut AnalysisTarget) -> Result<(), InspectorError> {
    // e_ident[16] + e_type(2) + e_machine(2) = need at least 20 bytes.
    let ehdr = bytes
        .get(..20)
        .ok_or_else(|| InspectorError::ParseError("truncated ELF header".into()))?;

    target.elf_class = match ehdr[4] {
        1 => Some(ElfClass::Elf32),
        2 => Some(ElfClass::Elf64),
        _ => {
            return Err(InspectorError::ParseError(format!(
                "unknown ELF class {}",
                ehdr[4]
            )));
        }
    };
    target.endianness = match ehdr[5] {
        1 => Endianness::Little,
        2 => Endianness::Big,
        _ => Endianness::Unknown,
    };

    // EI_OSABI: 0 (System V, used by Linux toolchains) and 3 (GNU/Linux)
    // both mean the Linux syscall convention applies. Anything else —
    // FreeBSD, Solaris, … — uses different tables, so stay Unknown rather
    // than misattributing numbers.
    target.abi = match ehdr[7] {
        0 | 3 => SyscallAbi::Linux,
        _ => SyscallAbi::Unknown,
    };

    let machine = match target.endianness {
        Endianness::Big => u16::from_be_bytes([ehdr[18], ehdr[19]]),
        _ => u16::from_le_bytes([ehdr[18], ehdr[19]]),
    };
    target.machine = Some(machine);
    target.isa = match machine {
        goblin::elf::header::EM_X86_64 => Isa::X86_64,
        goblin::elf::header::EM_AARCH64 => Isa::AArch64,
        _ => Isa::Other,
    };
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal ELF64 identification header (not a full ELF).
    fn elf_header(class: u8, data: u8, osabi: u8, machine: u16) -> Vec<u8> {
        let mut b = vec![0u8; 64];
        b[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
        b[4] = class;
        b[5] = data;
        b[6] = 1;
        b[7] = osabi;
        b[16..18].copy_from_slice(&2u16.to_le_bytes());
        b[18..20].copy_from_slice(&machine.to_le_bytes());
        b
    }

    #[test]
    fn test_identify_x86_64_linux_elf() {
        let t = identify(&elf_header(2, 1, 0, 62)).unwrap();
        assert_eq!(t.format, BinaryFormat::Elf);
        assert_eq!(t.isa, Isa::X86_64);
        assert_eq!(t.abi, SyscallAbi::Linux);
        assert_eq!(t.endianness, Endianness::Little);
        assert_eq!(t.elf_class, Some(ElfClass::Elf64));
        assert_eq!(t.machine, Some(62));
        assert_eq!(t.slice, None);
    }

    #[test]
    fn test_identify_aarch64_linux_elf() {
        let t = identify(&elf_header(2, 1, 0, 183)).unwrap();
        assert_eq!(t.format, BinaryFormat::Elf);
        assert_eq!(t.isa, Isa::AArch64);
        assert_eq!(t.abi, SyscallAbi::Linux);
    }

    #[test]
    fn test_identify_gnu_osabi_is_linux() {
        let t = identify(&elf_header(2, 1, 3, 62)).unwrap();
        assert_eq!(t.abi, SyscallAbi::Linux);
    }

    #[test]
    fn test_identify_freebsd_osabi_is_unknown_abi() {
        // ELFOSABI_FREEBSD = 9: same ISA, different syscall numbering.
        let t = identify(&elf_header(2, 1, 9, 62)).unwrap();
        assert_eq!(t.isa, Isa::X86_64);
        assert_eq!(t.abi, SyscallAbi::Unknown);
    }

    #[test]
    fn test_identify_unknown_machine() {
        let t = identify(&elf_header(2, 1, 0, 0xFFFF)).unwrap();
        assert_eq!(t.isa, Isa::Other);
        assert_eq!(t.machine, Some(0xFFFF));
    }

    #[test]
    fn test_identify_big_endian() {
        let mut b = elf_header(2, 2, 0, 183);
        b[18..20].copy_from_slice(&183u16.to_be_bytes());
        let t = identify(&b).unwrap();
        assert_eq!(t.endianness, Endianness::Big);
        assert_eq!(t.machine, Some(183));
        assert_eq!(t.isa, Isa::AArch64);
    }

    #[test]
    fn test_identify_macho_thin_and_fat() {
        for magic in [
            [0xFE, 0xED, 0xFA, 0xCF],
            [0xCF, 0xFA, 0xED, 0xFE],
            [0xCA, 0xFE, 0xBA, 0xBE],
        ] {
            let mut b = magic.to_vec();
            b.extend_from_slice(&[0u8; 60]);
            let t = identify(&b).unwrap();
            assert_eq!(t.format, BinaryFormat::MachO);
            assert_eq!(t.isa, Isa::Unknown);
        }
    }

    #[test]
    fn test_identify_pe() {
        let t = identify(b"MZ\x90\x00").unwrap();
        assert_eq!(t.format, BinaryFormat::Pe);
    }

    #[test]
    fn test_identify_unknown_magic() {
        let t = identify(b"#! /usr/bin/env python3\n").unwrap();
        assert_eq!(t.format, BinaryFormat::Unknown);
    }

    #[test]
    fn test_identify_truncated_inputs() {
        assert!(identify(&[]).is_err());
        assert!(identify(&[0x7f]).is_err());
        assert!(identify(&[0x7f, b'E', b'L', b'F']).is_err()); // header too short
        assert!(identify(&elf_header(2, 1, 0, 62)[..19]).is_err());
    }

    #[test]
    fn test_identify_bad_elf_class() {
        assert!(identify(&elf_header(9, 1, 0, 62)).is_err());
    }

    #[test]
    fn test_status_reason_tokens() {
        // Output tokens are a documented contract; keep them stable.
        assert_eq!(AnalysisStatus::Analyzed.as_str(), "analyzed");
        assert_eq!(AnalysisStatus::Partial.as_str(), "partial");
        assert_eq!(AnalysisStatus::Unsupported.as_str(), "unsupported");
        assert_eq!(AnalysisStatus::NotApplicable.as_str(), "not_applicable");
        assert_eq!(AnalysisStatus::Failed.as_str(), "failed");
        assert_eq!(ReasonCode::UnsupportedIsa.as_str(), "unsupported_isa");
        assert_eq!(ReasonCode::UnknownAbi.as_str(), "unknown_abi");
        assert_eq!(ReasonCode::NoCodeRegion.as_str(), "no_code_region");
        assert_eq!(ReasonCode::MalformedInput.as_str(), "malformed_input");
        assert_eq!(ReasonCode::NonNativePayload.as_str(), "non_native_payload");
        assert_eq!(ReasonCode::PartialCoverage.as_str(), "partial_coverage");
    }
}
