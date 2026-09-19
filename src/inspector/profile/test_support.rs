use crate::inspector::disasm::SyscallSite;
use crate::inspector::elf_parser::{ImportSymbol, RiskCategory, RiskFlags, SymbolProfile};
use crate::inspector::profile::CapabilityProfile;
use crate::inspector::profile::score::{build_risk_summary, compute_risk_score};
use crate::inspector::slicer::{Resolution, ResolvedSyscall};
use crate::inspector::strings::StringFindings;
use crate::inspector::target::AnalysisReport;

/// Helper: build a CapabilityProfile with the given parameters.
pub(crate) fn make_profile(
    libraries: Vec<&str>,
    imports: Vec<(&str, RiskCategory)>,
    syscalls: Vec<(u64, Option<i64>, Option<&str>, Resolution)>,
    urls: Vec<&str>,
    paths: Vec<&str>,
    env_vars: Vec<&str>,
    is_stripped: bool,
) -> CapabilityProfile {
    let import_symbols: Vec<ImportSymbol> = imports
        .into_iter()
        .map(|(name, cat)| ImportSymbol {
            name: name.to_string(),
            library: None,
            category: cat,
        })
        .collect();

    let risk_flags = RiskFlags {
        network: import_symbols
            .iter()
            .any(|i| i.category == RiskCategory::Network),
        file_system: import_symbols
            .iter()
            .any(|i| i.category == RiskCategory::FileSystem),
        process: import_symbols
            .iter()
            .any(|i| i.category == RiskCategory::Process),
        crypto: import_symbols
            .iter()
            .any(|i| i.category == RiskCategory::Crypto),
        memory: import_symbols
            .iter()
            .any(|i| i.category == RiskCategory::Memory),
    };

    let symbols = SymbolProfile {
        libraries: libraries.into_iter().map(String::from).collect(),
        imports: import_symbols,
        risk_flags,
        is_stripped,
    };

    let resolved_syscalls: Vec<ResolvedSyscall> = syscalls
        .into_iter()
        .map(|(addr, num, name, res)| ResolvedSyscall {
            site: SyscallSite {
                address: addr,
                offset_in_section: addr,
            },
            syscall_number: num,
            syscall_name: name.map(String::from),
            kind: crate::inspector::slicer::SyscallKind::Unix,
            resolution: res,
            resolution_detail: None,
        })
        .collect();

    let string_findings = StringFindings {
        urls: urls.into_iter().map(String::from).collect(),
        paths: paths.into_iter().map(String::from).collect(),
        env_vars: env_vars.into_iter().map(String::from).collect(),
    };

    let analysis = AnalysisReport::analyzed_linux_x86_64();
    let risk_score = compute_risk_score(
        &symbols,
        &resolved_syscalls,
        &string_findings,
        &analysis.syscalls,
    );
    let risk_summary = build_risk_summary(
        &symbols,
        &resolved_syscalls,
        &string_findings,
        &analysis.syscalls,
    );

    CapabilityProfile {
        analysis,
        symbols,
        syscalls: resolved_syscalls,
        strings: string_findings,
        risk_score,
        risk_summary,
    }
}
