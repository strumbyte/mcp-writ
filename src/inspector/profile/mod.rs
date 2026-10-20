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
pub(crate) mod test_support;

pub(crate) use format::format_json_internal;
pub use format::{format_human, format_json, format_kdl};

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
        // A resource bound cutting extraction short is Partial —
        // never a silently complete result.
        strings: if string_findings.truncated {
            AnalysisState::partial(
                "string extraction cut off by aggregate resource bounds; \
                 findings are a subset"
                    .to_string(),
            )
        } else {
            AnalysisState::analyzed()
        },
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
    // Capped so a malformed ELF cannot force unbounded metadata growth —
    // in count *and* in name bytes: thousands of executable headers can
    // all index one long shstrtab entry, and a per-section `to_string`
    // would otherwise hold that entry's bytes once per region.
    const MAX_CODE_REGIONS: usize = 4096;
    const MAX_CODE_REGION_NAME_BYTES: usize = 1 << 20;
    let mut name_budget = MAX_CODE_REGION_NAME_BYTES;
    for sh in &elf.section_headers {
        if sh.is_executable() {
            if target.code_regions.len() >= MAX_CODE_REGIONS {
                break;
            }
            let full_name = elf.shdr_strtab.get_at(sh.sh_name).unwrap_or("");
            let name = if full_name.len() <= name_budget {
                name_budget -= full_name.len();
                full_name
            } else {
                // Over-budget names are dropped whole rather than
                // sliced — metadata only, never an analyzer input.
                name_budget = 0;
                ""
            };
            target.code_regions.push(CodeRegion {
                name: name.to_string(),
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
            let (syscalls, truncated) = slicer::resolve_syscalls(code_bytes, sh_addr);
            // A capped collection is a lower bound — Partial, never a
            // silently short Analyzed. The retained count is the bound
            // the cap actually kept.
            let state = if truncated {
                AnalysisState::partial(format!(
                    "syscall-site bound reached ({} site(s) retained); findings \
                     are a lower bound",
                    syscalls.len()
                ))
            } else {
                AnalysisState::analyzed()
            };
            (target, state, syscalls)
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
            if scan.site_truncated {
                let note = format!(
                    "syscall-site bound reached ({} site(s) retained); findings \
                     are a lower bound",
                    scan.sites.len()
                );
                state = AnalysisState::partial(match state.detail.take() {
                    Some(existing) => format!("{existing}; {note}"),
                    None => note,
                });
            }
            if scan.aux_truncated {
                // Auxiliary diagnostics are not findings — the svc list is
                // complete, so a cut `nonstandard_svc` collection is a
                // detail note, not a partial-analysis state.
                let note = "auxiliary nonstandard-svc diagnostic bound reached; \
                            the list is a subset"
                    .to_string();
                state.detail = Some(match state.detail.take() {
                    Some(existing) => format!("{existing}; {note}"),
                    None => note,
                });
            }
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
        Ok(f) if f.truncated => (
            f,
            AnalysisState::partial(
                "string extraction cut off by aggregate resource bounds; \
                 findings are a subset"
                    .to_string(),
            ),
        ),
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
    let mut budget_hit = false;
    let mut aux_hit = false;
    for r in regions {
        if budget_hit {
            // The site bound is per analysis, not per region — a fat
            // binary's regions share it. Remaining regions keep
            // `analyzed: false` — honestly never decoded. (An
            // auxiliary-diagnostic bound never stops the site scan.)
            break;
        }
        let (resolved, scan) = slicer::resolve_syscalls_aarch64(r.bytes, r.vaddr, target.abi);
        let remaining = crate::inspector::disasm::MAX_SYSCALL_SITES.saturating_sub(syscalls.len());
        if resolved.len() > remaining {
            syscalls.extend(resolved.into_iter().take(remaining));
            budget_hit = true;
        } else {
            syscalls.extend(resolved);
        }
        // Only the syscall-site bound is the budget — an auxiliary
        // `nonstandard_svc` overflow cuts diagnostics, never findings,
        // so it must not stop the site scan of later regions.
        budget_hit |= scan.site_truncated;
        aux_hit |= scan.aux_truncated;
        if !scan.is_complete() {
            complete = false;
            uninterpreted += scan.uninterpreted_words;
        }
        let aux_remaining =
            crate::inspector::disasm::MAX_NONSTANDARD_SVC.saturating_sub(nonstandard.len());
        if scan.nonstandard_svc.len() > aux_remaining {
            nonstandard.extend(scan.nonstandard_svc.iter().copied().take(aux_remaining));
            aux_hit = true;
        } else {
            nonstandard.extend(scan.nonstandard_svc.iter().copied());
        }
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
    if budget_hit {
        let note = format!(
            "aggregate syscall-site bound reached ({} retained); findings \
             are a lower bound",
            syscalls.len()
        );
        state = AnalysisState::partial(match state.detail.take() {
            Some(existing) => format!("{existing}; {note}"),
            None => note,
        });
    }
    if aux_hit {
        // Auxiliary diagnostics are not findings — a cut list is a
        // detail note, not a partial-analysis state.
        let note = format!(
            "auxiliary nonstandard-svc diagnostic bound reached ({} retained); \
             the list is a subset",
            nonstandard.len()
        );
        state.detail = Some(match state.detail.take() {
            Some(existing) => format!("{existing}; {note}"),
            None => note,
        });
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal ELF64 (LE, x86-64) with two executable PROGBITS sections
    /// whose names come from one shared shstrtab, plus the null and
    /// shstrtab headers goblin needs to parse it.
    fn elf64_with_two_exec_sections(name1: &[u8], name2: &[u8]) -> Vec<u8> {
        let mut buf = Vec::new();
        // e_ident: magic, ELFCLASS64, ELFDATA2LSB, EV_CURRENT, OSABI none
        buf.extend_from_slice(&[0x7f, b'E', b'L', b'F', 2, 1, 1, 0]);
        buf.extend_from_slice(&[0u8; 8]);
        buf.extend_from_slice(&2u16.to_le_bytes()); // e_type: ET_EXEC
        buf.extend_from_slice(&62u16.to_le_bytes()); // e_machine: EM_X86_64
        buf.extend_from_slice(&1u32.to_le_bytes()); // e_version
        buf.extend_from_slice(&0u64.to_le_bytes()); // e_entry
        buf.extend_from_slice(&0u64.to_le_bytes()); // e_phoff
        buf.extend_from_slice(&0u64.to_le_bytes()); // e_shoff (patched below)
        buf.extend_from_slice(&0u32.to_le_bytes()); // e_flags
        buf.extend_from_slice(&64u16.to_le_bytes()); // e_ehsize
        buf.extend_from_slice(&56u16.to_le_bytes()); // e_phentsize
        buf.extend_from_slice(&0u16.to_le_bytes()); // e_phnum
        buf.extend_from_slice(&64u16.to_le_bytes()); // e_shentsize
        buf.extend_from_slice(&4u16.to_le_bytes()); // e_shnum
        buf.extend_from_slice(&3u16.to_le_bytes()); // e_shstrndx

        let strtab_off = buf.len() as u64;
        let mut strtab = vec![0u8];
        let name1_off = strtab.len() as u32;
        strtab.extend_from_slice(name1);
        strtab.push(0);
        let name2_off = strtab.len() as u32;
        strtab.extend_from_slice(name2);
        strtab.push(0);
        let strtab_len = strtab.len() as u64;
        buf.extend_from_slice(&strtab);

        let shoff = buf.len() as u64;
        buf[40..48].copy_from_slice(&shoff.to_le_bytes());

        let mut push_sh = |name: u32, sh_type: u32, flags: u64, off: u64, size: u64| {
            buf.extend_from_slice(&name.to_le_bytes()); // sh_name
            buf.extend_from_slice(&sh_type.to_le_bytes()); // sh_type
            buf.extend_from_slice(&flags.to_le_bytes()); // sh_flags
            buf.extend_from_slice(&0u64.to_le_bytes()); // sh_addr
            buf.extend_from_slice(&off.to_le_bytes()); // sh_offset
            buf.extend_from_slice(&size.to_le_bytes()); // sh_size
            buf.extend_from_slice(&0u32.to_le_bytes()); // sh_link
            buf.extend_from_slice(&0u32.to_le_bytes()); // sh_info
            buf.extend_from_slice(&1u64.to_le_bytes()); // sh_addralign
            buf.extend_from_slice(&0u64.to_le_bytes()); // sh_entsize
        };
        const SHT_PROGBITS: u32 = 1;
        const SHT_STRTAB: u32 = 3;
        // goblin's `is_executable` requires SHF_ALLOC | SHF_EXECINSTR.
        const SHF_ALLOC_EXEC: u64 = 0x6;
        push_sh(0, 0, 0, 0, 0); // null section
        push_sh(name1_off, SHT_PROGBITS, SHF_ALLOC_EXEC, strtab_off, 16);
        push_sh(name2_off, SHT_PROGBITS, SHF_ALLOC_EXEC, strtab_off, 16);
        push_sh(0, SHT_STRTAB, 0, strtab_off, strtab_len);
        buf
    }

    fn linux_x86_target() -> AnalysisTarget {
        AnalysisTarget {
            format: BinaryFormat::Elf,
            isa: Isa::X86_64,
            abi: SyscallAbi::Linux,
            endianness: Endianness::Little,
            elf_class: Some(ElfClass::Elf64),
            slice: None,
            machine: Some(62),
            slices: Vec::new(),
            platform: None,
            code_regions: Vec::new(),
        }
    }

    #[test]
    fn section_name_budget_drops_oversized_names_whole() {
        // The aggregate name budget is 1 MiB: the first 700 KiB name
        // fits, the second does not — it must be dropped whole, never
        // sliced mid-name or duplicated per region.
        let big1 = "A".repeat(700 * 1024);
        let big2 = "B".repeat(700 * 1024);
        let elf = elf64_with_two_exec_sections(big1.as_bytes(), big2.as_bytes());
        let (target, _state, _sites) = resolve_syscalls_from_elf(&elf, linux_x86_target());
        assert_eq!(target.code_regions.len(), 2);
        assert_eq!(target.code_regions[0].name, big1);
        assert!(
            target.code_regions[1].name.is_empty(),
            "over-budget name must be dropped, got {} bytes",
            target.code_regions[1].name.len()
        );
    }

    #[test]
    fn section_name_budget_keeps_small_names() {
        let elf = elf64_with_two_exec_sections(b".text.exec", b".init");
        let (target, _state, _sites) = resolve_syscalls_from_elf(&elf, linux_x86_target());
        assert_eq!(target.code_regions.len(), 2);
        assert_eq!(target.code_regions[0].name, ".text.exec");
        assert_eq!(target.code_regions[1].name, ".init");
    }
}
