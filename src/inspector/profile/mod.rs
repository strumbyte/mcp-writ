use crate::error::InspectorError;
use crate::inspector::elf_parser::{self, RiskFlags, SymbolProfile};
use crate::inspector::slicer::{self, ResolvedSyscall};
use crate::inspector::strings::{self, StringFindings};
use crate::inspector::target::{
    AnalysisReport, AnalysisState, AnalysisTarget, BinaryFormat, CodeRegion, ElfClass, Endianness,
    Isa, ReasonCode, SyscallAbi,
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

    if target.format != BinaryFormat::Elf {
        return Ok(non_elf_profile(target));
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

    // Find .text section
    let text = text_section::find_text_section(&elf);
    let (sh_offset, sh_size, sh_addr) = match text {
        Some(s) => s,
        None => {
            let mut state = AnalysisState::analyzed();
            state.detail = Some("no .text section present".to_string());
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

    if let Some(region) = target
        .code_regions
        .iter_mut()
        .find(|r| r.vaddr == sh_addr && r.file_offset == sh_offset)
    {
        region.analyzed = true;
    }

    (
        target,
        AnalysisState::analyzed(),
        slicer::resolve_syscalls(code_bytes, sh_addr),
    )
}

/// Returns the `Unsupported`/`NotApplicable` state when the target cannot be
/// decoded by this build, or `None` when the x86-64 Linux analysis applies.
fn unsupported_gate(target: &AnalysisTarget) -> Option<AnalysisState> {
    // Only ELF64 little-endian is wired to a decoder backend today.
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
        Isa::X86_64 => match target.abi {
            SyscallAbi::Linux => None,
            SyscallAbi::Unknown => Some(AnalysisState::unsupported(
                ReasonCode::UnknownAbi,
                "x86-64 ELF with non-Linux/unknown EI_OSABI; syscall numbers not \
                 mapped to Linux names"
                    .to_string(),
            )),
        },
        Isa::AArch64 => Some(AnalysisState::unsupported(
            ReasonCode::UnsupportedIsa,
            "AArch64 ELF detected; syscall entry would be SVC/x8 but the backend \
             is not wired yet"
                .to_string(),
        )),
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
