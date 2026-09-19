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
    /// Mach-O (Darwin); thin and fat containers are analyzed.
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
    /// Darwin (XNU) ARM64 convention: `svc #0x80` with the number in `x16`;
    /// negative values are Mach traps. Numbers/names are not Linux seccomp
    /// names and must never feed a Linux syscall allowlist.
    Darwin,
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

/// Darwin platform a Mach-O slice targets (`LC_BUILD_VERSION` platform or
/// the `LC_VERSION_MIN_*` command identity).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MachOPlatform {
    MacOs,
    Ios,
    Tvos,
    WatchOs,
    BridgeOs,
    MacCatalyst,
    IosSimulator,
    TvosSimulator,
    WatchosSimulator,
    DriverKit,
    VisionOs,
    VisionosSimulator,
    /// A platform value outside the known Darwin set — the ABI convention
    /// cannot be assumed, so syscall analysis stays unsupported.
    Other(u32),
    /// No platform load command was recorded.
    Unknown,
}

/// One architecture slice inside a Mach-O container (thin files have
/// exactly one entry; fat files have one per `fat_arch` record).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MachOSlice {
    /// Display name (e.g. "arm64", "arm64e", "x86_64").
    pub arch: String,
    /// Mach-O `cputype`.
    pub cputype: u32,
    /// Mach-O `cpusubtype` with capability bits masked off.
    pub cpusubtype: u32,
    /// File-absolute offset of the slice header (0 for thin files).
    pub offset: u64,
    /// Declared byte size of the slice (file length for thin files).
    pub size: u64,
    /// Whether this slice is the one under analysis (at most one).
    pub selected: bool,
    /// Why this slice is not analyzed; `None` for the selected slice, whose
    /// outcome is reported under `analysis.syscalls`.
    pub state: Option<AnalysisState>,
}

/// An executable code range inside the input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodeRegion {
    /// Section name (e.g. `.text`, `__TEXT,__text`).
    pub name: String,
    /// File offset of the region inside the *whole input* (for a fat
    /// Mach-O this is the offset within the container file, not the
    /// slice — see `slice_offset`).
    pub file_offset: u64,
    /// Offset within the containing slice for fat Mach-O regions;
    /// `None` for non-sliced formats. Never conflated with `file_offset`.
    pub slice_offset: Option<u64>,
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
    /// Mach-O architecture slices (one for thin files, N for fat). Empty
    /// for non-Mach-O inputs. Slice `offset`/`size` are file-absolute.
    pub slices: Vec<MachOSlice>,
    /// Mach-O target platform from `LC_BUILD_VERSION`/`LC_VERSION_MIN_*`;
    /// `None` for non-Mach-O inputs.
    pub platform: Option<MachOPlatform>,
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
            slices: Vec::new(),
            platform: None,
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
                slices: Vec::new(),
                platform: None,
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
            Self::Darwin => "darwin",
            Self::Unknown => "unknown",
        }
    }
}

impl MachOPlatform {
    /// Stable snake_case token used in JSON/KDL output.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MacOs => "macos",
            Self::Ios => "ios",
            Self::Tvos => "tvos",
            Self::WatchOs => "watchos",
            Self::BridgeOs => "bridgeos",
            Self::MacCatalyst => "maccatalyst",
            Self::IosSimulator => "ios_simulator",
            Self::TvosSimulator => "tvos_simulator",
            Self::WatchosSimulator => "watchos_simulator",
            Self::DriverKit => "driverkit",
            Self::VisionOs => "visionos",
            Self::VisionosSimulator => "visionos_simulator",
            Self::Other(_) => "other",
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
        slices: Vec::new(),
        platform: None,
        code_regions: Vec::new(),
    };

    match magic {
        [0x7f, b'E', b'L', b'F'] => {
            target.format = BinaryFormat::Elf;
            identify_elf(bytes, &mut target)?;
        }
        // Mach-O: 32/64-bit, both byte orders, plus fat/universal headers.
        // Note: CA FE BA BE also heads Java .class files; the fat table
        // enumeration will fail on those, so analysis ends at
        // malformed_input — the ambiguity stays display-only.
        [0xFE, 0xED, 0xFA, 0xCE]
        | [0xFE, 0xED, 0xFA, 0xCF]
        | [0xCE, 0xFA, 0xED, 0xFE]
        | [0xCF, 0xFA, 0xED, 0xFE]
        | [0xCA, 0xFE, 0xBA, 0xBE]
        | [0xCA, 0xFE, 0xBA, 0xBF]
        | [0xBE, 0xBA, 0xFE, 0xCA]
        | [0xBF, 0xBA, 0xFE, 0xCA] => {
            target.format = BinaryFormat::MachO;
            identify_macho(bytes, &mut target);
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

/// Mach-O `cputype` → ISA. The subtype (arm64e/arm64_32 variants) does not
/// change the ISA; variant gating happens in the analyzer.
fn macho_isa(cputype: u32) -> Isa {
    use goblin::mach::constants::cputype;
    match cputype {
        cputype::CPU_TYPE_ARM64 | cputype::CPU_TYPE_ARM64_32 => Isa::AArch64,
        cputype::CPU_TYPE_X86_64 => Isa::X86_64,
        _ => Isa::Other,
    }
}

/// Human-facing arch name for a Mach-O slice ("arm64", "arm64e", …).
fn macho_arch_name(cputype: u32, cpusubtype: u32) -> String {
    use goblin::mach::constants::cputype;
    match cputype::get_arch_name_from_types(cputype, cpusubtype) {
        Some(name) => name.to_owned(),
        None => format!("cpu_{cputype:#x}_{cpusubtype:#x}"),
    }
}

/// Enumerate the `fat_arch` records of a fat/universal Mach-O container.
///
/// Handles both the 20-byte (`FAT_MAGIC`) and 32-byte (`FAT_MAGIC_64`)
/// record layouts in either byte order. Returns `None` when the input is
/// not a fat container, when the arch table is truncated, or when a
/// declared slice range falls outside the file — all caller-visible as
/// malformed input.
pub(crate) fn enumerate_fat_slices(bytes: &[u8]) -> Option<Vec<MachOSlice>> {
    use goblin::mach::constants::cputype;
    let magic = bytes.get(..4)?;
    // Fat headers: FAT_MAGIC (CA FE BA BE) uses 20-byte records with 32-bit
    // offsets; FAT_MAGIC_64 (CA FE BA BF) uses 32-byte records with 64-bit
    // offsets. The CIGAM forms store multi-byte fields little-endian.
    let (be, wide) = match magic {
        [0xCA, 0xFE, 0xBA, 0xBE] => (true, false),
        [0xCA, 0xFE, 0xBA, 0xBF] => (true, true),
        [0xBE, 0xBA, 0xFE, 0xCA] => (false, false),
        [0xBF, 0xBA, 0xFE, 0xCA] => (false, true),
        _ => return None,
    };
    let read32 = |o: usize| -> Option<u32> {
        let b: [u8; 4] = bytes.get(o..o + 4)?.try_into().ok()?;
        Some(if be {
            u32::from_be_bytes(b)
        } else {
            u32::from_le_bytes(b)
        })
    };
    let read64 = |o: usize| -> Option<u64> {
        let b: [u8; 8] = bytes.get(o..o + 8)?.try_into().ok()?;
        Some(if be {
            u64::from_be_bytes(b)
        } else {
            u64::from_le_bytes(b)
        })
    };

    let nfat = read32(4)? as usize;
    let rec = if wide { 32usize } else { 20 };
    let table_end = nfat.checked_mul(rec)?.checked_add(8)?;
    if bytes.len() < table_end {
        return None;
    }
    let mut slices = Vec::with_capacity(nfat);
    for i in 0..nfat {
        let base = 8 + i * rec;
        let cputype = read32(base)?;
        let cpusubtype = read32(base + 4)? & !cputype::CPU_SUBTYPE_MASK;
        let (offset, size) = if wide {
            (read64(base + 8)?, read64(base + 16)?)
        } else {
            (read32(base + 8)? as u64, read32(base + 12)? as u64)
        };
        // A slice whose declared range leaves the file means the arch table
        // itself cannot be trusted; fail the enumeration as malformed.
        let end = offset.checked_add(size)?;
        if end > bytes.len() as u64 {
            return None;
        }
        slices.push(MachOSlice {
            arch: macho_arch_name(cputype, cpusubtype),
            cputype,
            cpusubtype,
            offset,
            size,
            selected: false,
            state: None,
        });
    }
    Some(slices)
}

/// Pick the analyzable slice of a Mach-O container: the first plain arm64
/// slice. Every other slice records an explicit `Unsupported` skip state —
/// arm64e/arm64_32 as `unsupported_variant`, other ISAs as
/// `unsupported_isa` — so a fat binary never looks universally validated
/// after analyzing only its arm64 slice.
pub(crate) fn select_macho_slice(slices: &mut [MachOSlice]) {
    use goblin::mach::constants::cputype;
    let selected = slices.iter().position(|s| {
        s.cputype == cputype::CPU_TYPE_ARM64 && s.cpusubtype != cputype::CPU_SUBTYPE_ARM64_E
    });
    for (i, s) in slices.iter_mut().enumerate() {
        if Some(i) == selected {
            s.selected = true;
            continue;
        }
        s.state = Some(if s.cputype == cputype::CPU_TYPE_ARM64 {
            if s.cpusubtype == cputype::CPU_SUBTYPE_ARM64_E {
                AnalysisState::unsupported(
                    ReasonCode::UnsupportedVariant,
                    "arm64e slice (pointer-authentication variant) is out of scope",
                )
            } else {
                AnalysisState::unsupported(
                    ReasonCode::UnsupportedVariant,
                    "additional arm64 slice not analyzed; the first arm64 slice is selected",
                )
            }
        } else if s.cputype == cputype::CPU_TYPE_ARM64_32 {
            AnalysisState::unsupported(
                ReasonCode::UnsupportedVariant,
                "arm64_32 (ILP32) slice is out of scope",
            )
        } else {
            AnalysisState::unsupported(
                ReasonCode::UnsupportedIsa,
                format!("slice arch '{}' is not analyzed in this build", s.arch),
            )
        });
    }
}

/// Read Mach-O identification fields without full parsing: slice table and
/// ISA for thin and fat containers. All Mach-O inputs carry the Darwin
/// syscall ABI; whether the selected slice is analyzable is decided by the
/// analyzer gate, so unsupported variants stay recorded rather than
/// silently dropped.
fn identify_macho(bytes: &[u8], target: &mut AnalysisTarget) {
    use goblin::mach::constants::cputype;
    target.abi = SyscallAbi::Darwin;
    let magic: [u8; 4] = bytes[..4].try_into().expect("magic already read");

    match magic {
        [0xCA, 0xFE, 0xBA, 0xBE]
        | [0xCA, 0xFE, 0xBA, 0xBF]
        | [0xBE, 0xBA, 0xFE, 0xCA]
        | [0xBF, 0xBA, 0xFE, 0xCA] => {
            // Fat container. Slices of interest are little-endian arm64.
            target.endianness = Endianness::Little;
            let Some(mut slices) = enumerate_fat_slices(bytes) else {
                // Arch table unreadable: leave slices empty; analysis
                // reports malformed_input rather than guessing.
                return;
            };
            select_macho_slice(&mut slices);
            target.isa = match slices.iter().find(|s| s.selected) {
                Some(sel) => {
                    target.slice = Some(sel.arch.clone());
                    macho_isa(sel.cputype)
                }
                // No analyzable slice: report the best-effort ISA (an
                // arm64-family slice keeps aarch64 so the gate can say
                // unsupported_variant rather than unsupported_isa).
                None => slices
                    .iter()
                    .find(|s| {
                        s.cputype == cputype::CPU_TYPE_ARM64
                            || s.cputype == cputype::CPU_TYPE_ARM64_32
                    })
                    .or_else(|| slices.first())
                    .map(|s| macho_isa(s.cputype))
                    .unwrap_or(Isa::Unknown),
            };
            target.slices = slices;
        }
        _ => {
            // Thin Mach-O: byte order and bitness come from the magic.
            let be = matches!(magic, [0xFE, 0xED, 0xFA, 0xCE] | [0xFE, 0xED, 0xFA, 0xCF]);
            target.endianness = if be {
                Endianness::Big
            } else {
                Endianness::Little
            };
            let read32 = |o: usize| -> Option<u32> {
                let b: [u8; 4] = bytes.get(o..o + 4)?.try_into().ok()?;
                Some(if be {
                    u32::from_be_bytes(b)
                } else {
                    u32::from_le_bytes(b)
                })
            };
            let cputype = read32(4).unwrap_or(0);
            let cpusubtype = read32(8).unwrap_or(0) & !cputype::CPU_SUBTYPE_MASK;
            target.isa = if cputype == 0 {
                Isa::Unknown
            } else {
                macho_isa(cputype)
            };
            let mut slices = vec![MachOSlice {
                arch: if cputype == 0 {
                    "unknown".to_owned()
                } else {
                    macho_arch_name(cputype, cpusubtype)
                },
                cputype,
                cpusubtype,
                offset: 0,
                size: bytes.len() as u64,
                selected: false,
                state: None,
            }];
            select_macho_slice(&mut slices);
            target.slices = slices;
        }
    }
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
