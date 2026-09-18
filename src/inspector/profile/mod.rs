use crate::error::InspectorError;
use crate::inspector::elf_parser::{self, RiskFlags, SymbolProfile};
use crate::inspector::slicer::{self, ResolvedSyscall};
use crate::inspector::strings::{self, StringFindings};
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
/// 1. ELF symbol parsing
/// 2. Syscall site detection
/// 3. Syscall number resolution (backward slicing)
/// 4. String extraction and classification
pub fn analyze(elf_bytes: &[u8]) -> Result<CapabilityProfile, InspectorError> {
    let symbols = elf_parser::parse_elf(elf_bytes)?;
    let string_findings = strings::extract_strings(elf_bytes)?;

    // Resolve syscalls: need .text section bytes and vaddr
    let syscalls = resolve_syscalls_from_elf(elf_bytes)?;

    let risk_score = score::compute_risk_score(&symbols, &syscalls, &string_findings);
    let risk_summary = score::build_risk_summary(&symbols, &syscalls, &string_findings);

    Ok(CapabilityProfile {
        symbols,
        syscalls,
        strings: string_findings,
        risk_score,
        risk_summary,
    })
}

/// Extract .text section from ELF and resolve syscalls.
fn resolve_syscalls_from_elf(elf_bytes: &[u8]) -> Result<Vec<ResolvedSyscall>, InspectorError> {
    let elf = goblin::elf::Elf::parse(elf_bytes)
        .map_err(|e| InspectorError::ParseError(format!("{e}")))?;

    // Only x86-64 binaries have syscall instructions we can analyze
    if elf.header.e_machine != goblin::elf::header::EM_X86_64 {
        return Ok(Vec::new());
    }

    // Find .text section
    let text = text_section::find_text_section(&elf);
    let (sh_offset, sh_size, sh_addr) = match text {
        Some(s) => s,
        None => return Ok(Vec::new()),
    };

    let code_bytes = text_section::section_bytes(elf_bytes, sh_offset, sh_size)?;
    Ok(slicer::resolve_syscalls(code_bytes, sh_addr))
}
