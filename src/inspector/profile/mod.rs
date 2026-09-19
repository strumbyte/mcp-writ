use crate::error::InspectorError;
use crate::inspector::elf_parser::{self, RiskFlags, SymbolProfile};
use crate::inspector::macho_parser;
use crate::inspector::slicer::{self, ResolvedSyscall};
use crate::inspector::strings::{self, StringFindings};
use crate::inspector::target::{
    AnalysisReport, AnalysisState, AnalysisTarget, BinaryFormat, CodeRegion, ElfClass, Endianness,
    Isa, MachOPlatform, ReasonCode, SyscallAbi,
};
use crate::inspector::text_section;

mod format;
mod score;
#[cfg(test)]
mod test_support;

pub use format::{
    format_human, format_json, format_json_with_extras, format_json_with_project, format_kdl,
    format_kdl_with_project,
};

/// Integrated capability profile summarizing a binary's detected capabilities.
#[derive(Debug, Clone)]
pub struct CapabilityProfile {
    /// Target metadata + per-component analysis states.
    ///
    /// IMPORTANT: `syscalls`/`symbols`/`strings` findings are only
    /// trustworthy to the extent the matching `analysis` state is
    /// `Analyzed`. An empty `syscalls` vector under any other status means
    /// "not analyzed", never "no syscalls present".
    pub analysis: AnalysisReport,
    /// ELF symbol analysis results.
    pub symbols: SymbolProfile,
    /// Detected syscalls with resolved numbers.
    pub syscalls: Vec<ResolvedSyscall>,
    /// String analysis results.
    pub strings: StringFindings,
    /// Overall risk score (0–100).
    pub risk_score: u32,
    /// Human-readable risk summary lines.
    pub risk_summary: Vec<String>,
}

impl CapabilityProfile {
    /// Empty profile used when native ELF analysis is skipped (interpreters).
    pub fn empty() -> Self {
        Self {
            analysis: AnalysisReport::not_applicable(),
            symbols: SymbolProfile {
                libraries: vec![],
                imports: vec![],
                risk_flags: RiskFlags::default(),
                is_stripped: false,
            },
            syscalls: vec![],
            strings: StringFindings::default(),
            risk_score: 0,
            risk_summary: vec![],
        }
    }
}

/// Analyze raw ELF bytes and produce an integrated `CapabilityProfile`.
///
/// Orchestrates all inspector sub-modules:
/// 1. Target identification (format/ISA/ABI/endianness)
/// 2. ELF symbol parsing
/// 3. Syscall site detection
/// 4. Syscall number resolution (backward slicing)
/// 5. String extraction and classification
///
/// Non-ELF inputs produce a profile whose analysis states are all
/// `Unsupported` — never a silently empty successful result.
pub fn analyze(elf_bytes: &[u8]) -> Result<CapabilityProfile, InspectorError> {
    let target = crate::inspector::target::identify(elf_bytes)?;

    match target.format {
        BinaryFormat::Elf => {}
        BinaryFormat::MachO => return Ok(analyze_macho(elf_bytes, target)),
        _ => return Ok(non_elf_profile(target)),
    }

    let symbols = elf_parser::parse_elf(elf_bytes)?;
    let string_findings = strings::extract_strings(elf_bytes)?;

    // Resolve syscalls: need .text section bytes and vaddr
    let (target, syscall_state, syscalls) = resolve_syscalls_from_elf(elf_bytes, target);

    let analysis = AnalysisReport {
        target,
        symbols: AnalysisState::analyzed(),
        strings: AnalysisState::analyzed(),
        syscalls: syscall_state,
    };

    let risk_score =
        score::compute_risk_score(&symbols, &syscalls, &string_findings, &analysis.syscalls);
    let risk_summary =
        score::build_risk_summary(&symbols, &syscalls, &string_findings, &analysis.syscalls);

    Ok(CapabilityProfile {
        analysis,
        symbols,
        syscalls,
        strings: string_findings,
        risk_score,
        risk_summary,
    })
}

/// Profile for recognized-but-unsupported container formats: every
/// component is marked `Unsupported` so consumers cannot mistake the empty
/// findings for a clean bill of health.
fn non_elf_profile(target: AnalysisTarget) -> CapabilityProfile {
    let detail = format!(
        "{} container format is not analyzable",
        target.format.as_str()
    );
    let state = AnalysisState::unsupported(ReasonCode::UnsupportedFormat, detail);

    let symbols = SymbolProfile {
        libraries: vec![],
        imports: vec![],
        risk_flags: RiskFlags::default(),
        is_stripped: false,
    };
    let strings = StringFindings::default();
    let syscalls: Vec<ResolvedSyscall> = Vec::new();

    let risk_score = score::compute_risk_score(&symbols, &syscalls, &strings, &state);
    let risk_summary = score::build_risk_summary(&symbols, &syscalls, &strings, &state);

    CapabilityProfile {
        analysis: AnalysisReport {
            target,
            symbols: state.clone(),
            strings: state.clone(),
            syscalls: state,
        },
        symbols,
        syscalls,
        strings,
        risk_score,
        risk_summary,
    }
}

/// Extract .text section from ELF and resolve syscalls.
///
/// Returns the updated target metadata (with code regions populated), the
/// analysis state, and the resolved sites. Unsupported ISA/ABI/variant
/// combinations return an `Unsupported` state with an empty vector — an
/// empty vector is only meaningful when the state is `Analyzed`.
fn resolve_syscalls_from_elf(
    elf_bytes: &[u8],
    mut target: AnalysisTarget,
) -> (AnalysisTarget, AnalysisState, Vec<ResolvedSyscall>) {
    let elf = match goblin::elf::Elf::parse(elf_bytes) {
        Ok(elf) => elf,
        // Unreachable in practice: analyze() already ran
        // elf_parser::parse_elf (the same goblin parse) and propagated any
        // error. Kept so this function stays correct if ever called on a
        // different path.
        Err(e) => {
            return (
                target,
                AnalysisState::failed(ReasonCode::MalformedInput, format!("{e}")),
                Vec::new(),
            );
        }
    };

    // Record executable code ranges for downstream consumers/policy drafts.
    // Capped so a malformed ELF cannot force unbounded metadata growth.
    const MAX_CODE_REGIONS: usize = 4096;
    for sh in &elf.section_headers {
        if sh.is_executable() {
            if target.code_regions.len() >= MAX_CODE_REGIONS {
                break;
            }
            let name = elf.shdr_strtab.get_at(sh.sh_name).unwrap_or("").to_string();
            target.code_regions.push(CodeRegion {
                name,
                file_offset: sh.sh_offset,
                slice_offset: None,
                size: sh.sh_size,
                vaddr: sh.sh_addr,
                analyzed: false,
            });
        }
    }

    // Gate on ISA/ABI/class/endianness before decoding.
    if let Some(state) = unsupported_gate(&target) {
        return (target, state, Vec::new());
    }

    // Find the executable .text section — the only range the decoder covers.
    let text = text_section::find_text_section(&elf);
    let (sh_offset, sh_size, sh_addr) = match text {
        Some(s) => s,
        None => {
            if target.code_regions.is_empty() {
                // No executable code anywhere: zero syscall findings is a
                // truthful, fully-analyzed result.
                let mut state = AnalysisState::analyzed();
                state.detail = Some("no executable code regions present".to_string());
                return (target, state, Vec::new());
            }
            // Executable regions exist but none is an executable .text
            // (e.g. renamed or split code sections): nothing was decoded,
            // so empty findings must not be reported as a completed
            // analysis.
            let state = AnalysisState::partial(format!(
                "{} executable region(s) present but no executable .text section; \
                 only .text is decoded",
                target.code_regions.len()
            ));
            return (target, state, Vec::new());
        }
    };

    let code_bytes = match text_section::section_bytes(elf_bytes, sh_offset, sh_size) {
        Ok(b) => b,
        Err(e) => {
            return (
                target,
                AnalysisState::failed(ReasonCode::MalformedInput, format!("{e}")),
                Vec::new(),
            );
        }
    };

    match target.isa {
        Isa::X86_64 => {
            mark_text_analyzed(&mut target, sh_addr, sh_offset, sh_size, true);
            (
                target,
                AnalysisState::analyzed(),
                slicer::resolve_syscalls(code_bytes, sh_addr),
            )
        }
        Isa::AArch64 => {
            let (syscalls, scan) =
                slicer::resolve_syscalls_aarch64(code_bytes, sh_addr, target.abi);
            // `analyzed` must agree with the completeness check below:
            // uninterpreted words mean part of .text was never decoded, so
            // the region reports analyzed=false alongside the Partial state.
            mark_text_analyzed(&mut target, sh_addr, sh_offset, sh_size, scan.is_complete());
            // Fixed-width decode covers every 4-byte word; words that fail to
            // decode (literal pools, corrupt bytes) or a trailing partial word
            // mean part of .text was never interpreted — that is Partial, not
            // Analyzed, so empty findings cannot be misread as "no syscalls".
            let mut state = if !scan.is_complete() {
                AnalysisState::partial(format!(
                    "{} .text word(s) not decoded (first at offset {}), {} trailing byte(s); \
                     syscall list is a lower bound",
                    scan.uninterpreted_words,
                    scan.first_uninterpreted
                        .map(|o| format!("0x{o:x}"))
                        .unwrap_or_else(|| "n/a".to_string()),
                    scan.trailing_bytes
                ))
            } else {
                AnalysisState::analyzed()
            };
            if !scan.nonstandard_svc.is_empty() {
                // The immediate is auxiliary info under the Linux ABI — every
                // svc dispatches on x8 — but nonzero values are nonstandard
                // (e.g. svc #0x80 is the Darwin convention), so keep them
                // visible instead of silently resolving like svc #0.
                let mut listed: Vec<String> = scan
                    .nonstandard_svc
                    .iter()
                    .take(4)
                    .map(|(off, imm)| match imm {
                        Some(imm) => format!("svc #0x{imm:x} at +0x{off:x}"),
                        None => format!("svc at +0x{off:x}"),
                    })
                    .collect();
                if scan.nonstandard_svc.len() > listed.len() {
                    listed.push("...".to_string());
                }
                let note = format!(
                    "{} svc instruction(s) with nonzero immediate ({}) resolved via x8; \
                     the immediate does not select a different ABI under Linux",
                    scan.nonstandard_svc.len(),
                    listed.join(", ")
                );
                state.detail = Some(match state.detail.take() {
                    Some(existing) => format!("{existing}; {note}"),
                    None => note,
                });
            }
            (target, state, syscalls)
        }
        // unsupported_gate guarantees only wired ISAs reach this point.
        _ => (
            target,
            AnalysisState::failed(
                ReasonCode::UnsupportedIsa,
                "decoder gate passed an ISA with no backend".to_string(),
            ),
            Vec::new(),
        ),
    }
}

/// Flag the `.text` code region matching the decoded section. `analyzed`
/// follows decode completeness — a partially decoded region must not report
/// as analyzed. The match mirrors `find_text_section`: name, vaddr,
/// file offset, and size must all agree, so an executable section that
/// shares `.text`'s address or offset cannot take the flag.
fn mark_text_analyzed(
    target: &mut AnalysisTarget,
    sh_addr: u64,
    sh_offset: u64,
    sh_size: u64,
    analyzed: bool,
) {
    if let Some(region) = target.code_regions.iter_mut().find(|r| {
        r.name == ".text" && r.vaddr == sh_addr && r.file_offset == sh_offset && r.size == sh_size
    }) {
        region.analyzed = analyzed;
    }
}

/// Returns the `Unsupported`/`NotApplicable` state when the target cannot be
/// decoded by this build, or `None` when a Linux syscall analysis applies.
fn unsupported_gate(target: &AnalysisTarget) -> Option<AnalysisState> {
    // Only ELF64 little-endian is wired to decoder backends today.
    if target.elf_class != Some(ElfClass::Elf64) || target.endianness != Endianness::Little {
        return Some(AnalysisState::unsupported(
            ReasonCode::UnsupportedVariant,
            format!(
                "class={} endianness={}",
                target.elf_class.map(|c| c.as_str()).unwrap_or("unknown"),
                target.endianness.as_str()
            ),
        ));
    }

    match target.isa {
        Isa::X86_64 | Isa::AArch64 => match target.abi {
            SyscallAbi::Linux => None,
            SyscallAbi::Unknown => Some(AnalysisState::unsupported(
                ReasonCode::UnknownAbi,
                format!(
                    "{} ELF with non-Linux/unknown EI_OSABI; syscall numbers not \
                     mapped to Linux names",
                    target.isa.as_str()
                ),
            )),
            // An ELF carrying a Darwin-identified ABI (e.g. embedded slice
            // metadata) has no ELF/Darwin convention to decode against.
            SyscallAbi::Darwin => Some(AnalysisState::unsupported(
                ReasonCode::UnknownAbi,
                format!(
                    "{} ELF with Darwin ABI identification; no ELF/Darwin syscall \
                     convention exists",
                    target.isa.as_str()
                ),
            )),
        },
        Isa::Other | Isa::Unknown => Some(AnalysisState::unsupported(
            ReasonCode::UnsupportedIsa,
            format!(
                "e_machine={} has no decoder backend",
                target
                    .machine
                    .map(|m| m.to_string())
                    .unwrap_or_else(|| "unknown".to_string())
            ),
        )),
    }
}

/// Analyze a Mach-O input (thin or fat).
///
/// Slice handling: `identify` already enumerated `target.slices` and marked
/// the analyzable arm64 slice (`selected`). Exactly one slice is analyzed;
/// every other slice keeps its own `Unsupported` state in the report, so a
/// fat binary never looks validated end to end when only arm64 was
/// decoded. Symbols/strings are ISA-agnostic metadata and are extracted
/// from the parsed slice even when syscall decoding is unsupported.
fn analyze_macho(bytes: &[u8], mut target: AnalysisTarget) -> CapabilityProfile {
    // A fat header whose arch table could not be enumerated leaves
    // `slices` empty — there is nothing trustworthy to parse.
    if target.slices.is_empty() {
        let state = AnalysisState::failed(
            ReasonCode::MalformedInput,
            "Mach-O slice table unreadable or truncated",
        );
        return macho_profile(
            target,
            SymbolProfile::empty(),
            StringFindings::default(),
            Vec::new(),
            state.clone(),
            state.clone(),
            state,
        );
    }

    // The slice we parse for metadata: the selected arm64 slice, else the
    // first slice (symbols/strings carry over even when no slice is
    // analyzable for syscalls).
    let idx = target.slices.iter().position(|s| s.selected).unwrap_or(0);
    let slice = target.slices[idx].clone();
    let Some(slice_bytes) = bytes
        .get(slice.offset as usize..(slice.offset as usize).saturating_add(slice.size as usize))
    else {
        let state = AnalysisState::failed(
            ReasonCode::MalformedInput,
            format!(
                "slice {} range 0x{:x}..+0x{:x} outside input ({} bytes)",
                slice.arch,
                slice.offset,
                slice.size,
                bytes.len()
            ),
        );
        return macho_profile(
            target,
            SymbolProfile::empty(),
            StringFindings::default(),
            Vec::new(),
            state.clone(),
            state.clone(),
            state,
        );
    };

    let macho = match macho_parser::parse_slice(slice_bytes) {
        Ok(m) => m,
        Err(e) => {
            let state = AnalysisState::failed(
                ReasonCode::MalformedInput,
                format!("Mach-O slice parse failed: {e}"),
            );
            return macho_profile(
                target,
                SymbolProfile::empty(),
                StringFindings::default(),
                Vec::new(),
                state.clone(),
                state.clone(),
                state,
            );
        }
    };

    target.platform = Some(macho_parser::detect_platform(&macho));

    // ISA-agnostic metadata: libraries, imports, symbols, strings.
    let (symbols, sym_partial) = macho_parser::symbol_profile(&macho);
    let symbols_state = match sym_partial {
        Some(detail) => AnalysisState::partial(detail),
        None => AnalysisState::analyzed(),
    };
    let (strings, strings_state) = match macho_parser::string_findings(&macho) {
        Ok(f) => (f, AnalysisState::analyzed()),
        Err(e) => (
            StringFindings::default(),
            AnalysisState::failed(ReasonCode::MalformedInput, format!("{e}")),
        ),
    };

    // Executable code regions; file_offset is file-absolute inside the
    // container, slice_offset stays slice-relative — never conflated.
    let (syscalls_state, syscalls) = match macho_parser::executable_sections(&macho, slice.size) {
        Ok(regions) => {
            for r in &regions {
                target.code_regions.push(CodeRegion {
                    name: r.name.clone(),
                    file_offset: slice.offset + r.slice_offset,
                    slice_offset: Some(r.slice_offset),
                    size: r.bytes.len() as u64,
                    vaddr: r.vaddr,
                    analyzed: false,
                });
            }
            analyze_macho_syscalls(&macho, &mut target, &regions)
        }
        Err(e) => (
            AnalysisState::failed(
                ReasonCode::MalformedInput,
                format!("Mach-O sections unreadable: {e}"),
            ),
            Vec::new(),
        ),
    };

    macho_profile(
        target,
        symbols,
        strings,
        syscalls,
        symbols_state,
        strings_state,
        syscalls_state,
    )
}

/// Decode the selected slice's executable regions under the Darwin ABI and
/// flag each analyzed region in `target.code_regions`.
fn analyze_macho_syscalls(
    macho: &goblin::mach::MachO<'_>,
    target: &mut AnalysisTarget,
    regions: &[macho_parser::MachOCodeRegion<'_>],
) -> (AnalysisState, Vec<ResolvedSyscall>) {
    // --- gates: the slice must be analyzable and the ABI convention known ---
    let Some(slice) = target.slices.iter().find(|s| s.selected) else {
        // No analyzable slice: report the skip state of the slice nearest
        // to analyzable — an arm64-family variant (arm64e/arm64_32)
        // explains the gap better than a foreign ISA — so the aggregate
        // state never depends on fat arch-table order. Every skipped
        // slice keeps its own state in the report.
        use goblin::mach::constants::cputype;
        let representative = target
            .slices
            .iter()
            .find(|s| {
                s.state.is_some()
                    && matches!(
                        s.cputype,
                        cputype::CPU_TYPE_ARM64 | cputype::CPU_TYPE_ARM64_32
                    )
            })
            .or_else(|| target.slices.iter().find(|s| s.state.is_some()));
        let state = representative
            .and_then(|s| s.state.clone())
            .unwrap_or_else(|| {
                AnalysisState::unsupported(
                    ReasonCode::UnsupportedIsa,
                    "no analyzable arm64 slice present",
                )
            });
        return (state, Vec::new());
    };
    let _ = slice;
    if let Err(detail) = macho_parser::supported_slice_variant(macho) {
        return (
            AnalysisState::unsupported(ReasonCode::UnsupportedVariant, detail),
            Vec::new(),
        );
    }
    if let Some(MachOPlatform::Other(p)) = target.platform {
        return (
            AnalysisState::unsupported(
                ReasonCode::UnsupportedVariant,
                format!("unrecognized Darwin platform {p}; ABI convention unverified"),
            ),
            Vec::new(),
        );
    }
    // The target's ABI selects the decode convention. `identify` sets
    // Darwin for every Mach-O, but gate explicitly so a future ABI value
    // can never silently decode under the wrong convention.
    if target.abi != SyscallAbi::Darwin {
        return (
            AnalysisState::unsupported(
                ReasonCode::UnknownAbi,
                format!(
                    "Mach-O slice carries {} syscall ABI; only the Darwin \
                     convention is decodable",
                    target.abi.as_str()
                ),
            ),
            Vec::new(),
        );
    }

    let mut syscalls = Vec::new();
    let mut complete = true;
    let mut uninterpreted = 0u64;
    let mut nonstandard: Vec<(u64, Option<u16>)> = Vec::new();
    for r in regions {
        let (resolved, scan) = slicer::resolve_syscalls_aarch64(r.bytes, r.vaddr, target.abi);
        syscalls.extend(resolved);
        if !scan.is_complete() {
            complete = false;
            uninterpreted += scan.uninterpreted_words;
        }
        nonstandard.extend(scan.nonstandard_svc.iter().copied());
        // Flag the region this scan decoded — matched on identity (name,
        // slice-relative offset, size, vaddr), never by position, so a
        // code_regions list that is not positional with `regions` cannot
        // take a wrong `analyzed` flag.
        if let Some(region) = target.code_regions.iter_mut().find(|cr| {
            cr.slice_offset == Some(r.slice_offset)
                && cr.size == r.bytes.len() as u64
                && cr.vaddr == r.vaddr
                && cr.name == r.name
        }) {
            region.analyzed = scan.is_complete();
        }
    }

    let mut state = if regions.is_empty() {
        let mut s = AnalysisState::analyzed();
        s.detail = Some("no executable code regions present".to_string());
        s
    } else if !complete {
        AnalysisState::partial(format!(
            "{uninterpreted} code word(s) not decoded; syscall list is a lower bound"
        ))
    } else {
        AnalysisState::analyzed()
    };
    if !nonstandard.is_empty() {
        let mut listed: Vec<String> = nonstandard
            .iter()
            .take(4)
            .map(|(off, imm)| match imm {
                Some(imm) => format!("svc #0x{imm:x} at +0x{off:x}"),
                None => format!("svc at +0x{off:x}"),
            })
            .collect();
        if nonstandard.len() > listed.len() {
            listed.push("...".to_string());
        }
        let note = format!(
            "{} svc instruction(s) with an immediate other than #0x80 ({}) are not \
             syscall entries under the Darwin ABI and were not resolved",
            nonstandard.len(),
            listed.join(", ")
        );
        state.detail = Some(match state.detail.take() {
            Some(existing) => format!("{existing}; {note}"),
            None => note,
        });
    }
    (state, syscalls)
}

/// Assemble a `CapabilityProfile` for a Mach-O target.
#[allow(clippy::too_many_arguments)]
fn macho_profile(
    target: AnalysisTarget,
    symbols: SymbolProfile,
    strings: StringFindings,
    syscalls: Vec<ResolvedSyscall>,
    symbols_state: AnalysisState,
    strings_state: AnalysisState,
    syscalls_state: AnalysisState,
) -> CapabilityProfile {
    let analysis = AnalysisReport {
        target,
        symbols: symbols_state,
        strings: strings_state,
        syscalls: syscalls_state,
    };
    let risk_score = score::compute_risk_score(&symbols, &syscalls, &strings, &analysis.syscalls);
    let risk_summary = score::build_risk_summary(&symbols, &syscalls, &strings, &analysis.syscalls);
    CapabilityProfile {
        analysis,
        symbols,
        syscalls,
        strings,
        risk_score,
        risk_summary,
    }
}
