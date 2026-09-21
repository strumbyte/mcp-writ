//! P4 regression tests for the Inspector target/analysis-state model.
//!
//! Covers:
//! - x86-64 fixture invariance (`x86_64_linux_syscalls.elf` baselines)
//! - AArch64 / non-Linux / non-ELF inputs producing explicit `Unsupported`
//!   states instead of silent empty results
//! - malformed/truncated inputs failing without panics
//! - state propagation into human/JSON/KDL output and policy drafts

use mcp_writ::inspector::profile;
use mcp_writ::inspector::slicer::Resolution;
use mcp_writ::inspector::target::{AnalysisStatus, BinaryFormat, Isa, ReasonCode, SyscallAbi};
use mcp_writ::legislator::cross_validator::CrossValidationResult;
use mcp_writ::legislator::policy_generator::generate_policy;

const EM_X86_64: u16 = 62;
const EM_AARCH64: u16 = 183;

/// Build a minimal ELF64 image with an optional executable `.text` section.
fn elf64_with_text(
    machine: u16,
    osabi: u8,
    text: Option<(&[u8], u64)>,
    text_size_override: Option<u64>,
) -> Vec<u8> {
    elf64_with_section(machine, osabi, ".text", 0x6, text, text_size_override)
}

/// Build a minimal ELF64 image with an optional named section.
///
/// Layout: ehdr(64) | pad to 0x100 | section | .shstrtab | pad to 0x200 |
/// shdrs. `text_size_override` lets tests declare a section larger than its
/// content (out-of-bounds malformed input). `section_flags` is the raw
/// `sh_flags` value (0x6 = SHF_ALLOC|SHF_EXECINSTR).
fn elf64_with_section(
    machine: u16,
    osabi: u8,
    section_name: &str,
    section_flags: u64,
    text: Option<(&[u8], u64)>,
    text_size_override: Option<u64>,
) -> Vec<u8> {
    let text_off: u64 = 0x100;
    let shstrtab_off: u64 = 0x180;
    let shoff: u64 = 0x200;
    let shnum: u16 = if text.is_some() { 3 } else { 2 };

    // shstrtab: \0 <section_name>\0 .shstrtab\0
    let mut shstrtab: Vec<u8> = vec![0];
    let section_name_off = shstrtab.len() as u32;
    shstrtab.extend_from_slice(section_name.as_bytes());
    shstrtab.push(0);
    let shstrtab_name_off = shstrtab.len() as u32;
    shstrtab.extend_from_slice(b".shstrtab");
    shstrtab.push(0);

    let mut b = vec![0u8; 0x400];
    // e_ident
    b[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
    b[4] = 2; // ELFCLASS64
    b[5] = 1; // little-endian
    b[6] = 1; // EV_CURRENT
    b[7] = osabi;
    // e_type=ET_EXEC, e_machine, e_version
    b[16..18].copy_from_slice(&2u16.to_le_bytes());
    b[18..20].copy_from_slice(&machine.to_le_bytes());
    b[20..24].copy_from_slice(&1u32.to_le_bytes());
    // e_entry, e_phoff=0, e_shoff
    let entry = text.map(|(_, v)| v).unwrap_or(0);
    b[24..32].copy_from_slice(&entry.to_le_bytes());
    b[32..40].copy_from_slice(&0u64.to_le_bytes());
    b[40..48].copy_from_slice(&shoff.to_le_bytes());
    // e_ehsize, e_phentsize, e_phnum=0, e_shentsize, e_shnum, e_shstrndx
    b[52..54].copy_from_slice(&64u16.to_le_bytes());
    b[54..56].copy_from_slice(&56u16.to_le_bytes());
    b[58..60].copy_from_slice(&64u16.to_le_bytes());
    b[60..62].copy_from_slice(&shnum.to_le_bytes());
    b[62..64].copy_from_slice(&(shnum - 1).to_le_bytes());

    if let Some((bytes, _)) = text {
        b[text_off as usize..text_off as usize + bytes.len()].copy_from_slice(bytes);
    }
    b[shstrtab_off as usize..shstrtab_off as usize + shstrtab.len()].copy_from_slice(&shstrtab);

    #[allow(clippy::too_many_arguments)]
    fn shdr(
        b: &mut [u8],
        idx: usize,
        shoff: usize,
        name: u32,
        ty: u32,
        flags: u64,
        addr: u64,
        off: u64,
        size: u64,
    ) {
        let base = shoff + idx * 64;
        b[base..base + 4].copy_from_slice(&name.to_le_bytes());
        b[base + 4..base + 8].copy_from_slice(&ty.to_le_bytes());
        b[base + 8..base + 16].copy_from_slice(&flags.to_le_bytes());
        b[base + 16..base + 24].copy_from_slice(&addr.to_le_bytes());
        b[base + 24..base + 32].copy_from_slice(&off.to_le_bytes());
        b[base + 32..base + 40].copy_from_slice(&size.to_le_bytes());
        b[base + 48..base + 56].copy_from_slice(&1u64.to_le_bytes()); // addralign
    }

    let shoff_usize = shoff as usize;
    if let Some((bytes, vaddr)) = text {
        let size = text_size_override.unwrap_or(bytes.len() as u64);
        // SHT_PROGBITS=1
        shdr(
            &mut b,
            1,
            shoff_usize,
            section_name_off,
            1,
            section_flags,
            vaddr,
            text_off,
            size,
        );
        shdr(
            &mut b,
            2,
            shoff_usize,
            shstrtab_name_off,
            3,
            0,
            0,
            shstrtab_off,
            shstrtab.len() as u64,
        );
    } else {
        shdr(
            &mut b,
            1,
            shoff_usize,
            shstrtab_name_off,
            3,
            0,
            0,
            shstrtab_off,
            shstrtab.len() as u64,
        );
    }
    b
}

fn empty_validation() -> CrossValidationResult {
    CrossValidationResult {
        allowed: vec![],
        blocked: vec![],
        warnings: vec![],
    }
}

// ---- x86-64 fixture regression (P0 baselines must not drift) ----

#[test]
fn fixture_x86_64_syscall_baselines_hold() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/inspector/x86_64_linux_syscalls.elf"
    );
    let bytes = std::fs::read(path).expect("fixture must exist");
    let profile = profile::analyze(&bytes).expect("fixture must analyze");

    assert_eq!(profile.analysis.target.format, BinaryFormat::Elf);
    assert_eq!(profile.analysis.target.isa, Isa::X86_64);
    assert_eq!(profile.analysis.target.abi, SyscallAbi::Linux);
    assert_eq!(profile.analysis.syscalls.status, AnalysisStatus::Analyzed);
    assert_eq!(profile.analysis.symbols.status, AnalysisStatus::Analyzed);
    assert_eq!(profile.analysis.strings.status, AnalysisStatus::Analyzed);
    // The .text region must be recorded as analyzed.
    assert!(
        profile
            .analysis
            .target
            .code_regions
            .iter()
            .any(|r| r.name == ".text" && r.analyzed),
        "code_regions: {:?}",
        profile.analysis.target.code_regions
    );

    // The .s source documents sites A–J; expected (number, name, resolution).
    let expected: [(Option<i64>, Option<&str>, Resolution); 10] = [
        (Some(1), Some("write"), Resolution::Resolved),    // A
        (Some(257), Some("openat"), Resolution::Resolved), // B
        (Some(59), Some("execve"), Resolution::Resolved),  // C
        (Some(0), Some("read"), Resolution::Resolved),     // D
        (Some(9999), None, Resolution::Resolved),          // E
        (None, None, Resolution::Unresolved),              // F (mov al)
        (None, None, Resolution::Unresolved),              // G (no write)
        (None, None, Resolution::Unresolved),              // H (call)
        (Some(231), Some("exit_group"), Resolution::Resolved), // I
        (Some(60), Some("exit"), Resolution::Resolved),    // J
    ];
    assert_eq!(
        profile.syscalls.len(),
        expected.len(),
        "sites: {:?}",
        profile.syscalls
    );
    for (sc, (num, name, res)) in profile.syscalls.iter().zip(expected.iter()) {
        assert_eq!(&sc.syscall_number, num);
        assert_eq!(sc.syscall_name.as_deref(), *name);
        assert_eq!(&sc.resolution, res);
    }

    // execve is detected → process-execution risk must be reported.
    assert!(
        profile
            .risk_summary
            .iter()
            .any(|l| l.contains("Process execution"))
    );
}

// ---- unsupported targets never look like clean empty scans ----

#[test]
fn aarch64_linux_elf_is_analyzed() {
    // movz w8, #1 ; svc #0 (Linux AArch64 encoding). AArch64 syscall 1 is
    // `io_destroy` — on x86-64 the same number is `write`, so the name also
    // proves the AArch64 table is in use.
    let text: &[u8] = &[0x28, 0x00, 0x80, 0x52, 0x01, 0x00, 0x00, 0xD4];
    let elf = elf64_with_text(EM_AARCH64, 0, Some((text, 0x400000)), None);
    let profile = profile::analyze(&elf).expect("aarch64 ELF must not error");

    assert_eq!(profile.analysis.target.isa, Isa::AArch64);
    assert_eq!(profile.analysis.target.abi, SyscallAbi::Linux);
    assert_eq!(profile.analysis.syscalls.status, AnalysisStatus::Analyzed);
    assert_eq!(profile.syscalls.len(), 1);
    assert_eq!(profile.syscalls[0].syscall_number, Some(1));
    assert_eq!(
        profile.syscalls[0].syscall_name.as_deref(),
        Some("io_destroy")
    );
    assert_eq!(profile.syscalls[0].resolution, Resolution::Resolved);
    assert!(
        profile
            .analysis
            .target
            .code_regions
            .iter()
            .any(|r| r.name == ".text" && r.analyzed)
    );
}

#[test]
fn non_linux_osabi_keeps_numbers_unresolved() {
    let text: &[u8] = &[0xB8, 1, 0, 0, 0, 0x0F, 0x05];
    // ELFOSABI_FREEBSD=9: same ISA, different syscall numbering.
    let elf = elf64_with_text(EM_X86_64, 9, Some((text, 0x400000)), None);
    let profile = profile::analyze(&elf).expect("ELF must analyze");

    assert_eq!(
        profile.analysis.syscalls.status,
        AnalysisStatus::Unsupported
    );
    assert_eq!(
        profile.analysis.syscalls.reason,
        Some(ReasonCode::UnknownAbi)
    );
    assert!(profile.syscalls.is_empty());
}

#[test]
fn elf_without_text_is_analyzed_empty() {
    let elf = elf64_with_text(EM_X86_64, 0, None, None);
    let profile = profile::analyze(&elf).expect("ELF must analyze");

    assert_eq!(profile.analysis.syscalls.status, AnalysisStatus::Analyzed);
    assert!(profile.syscalls.is_empty());
    assert!(profile.analysis.target.code_regions.is_empty());
}

#[test]
fn exec_code_without_text_is_partial_not_analyzed() {
    // Code lives in a renamed exec section: the decoder only covers an
    // executable .text, so empty findings must not read as a completed
    // analysis.
    let text: &[u8] = &[0xB8, 1, 0, 0, 0, 0x0F, 0x05];
    let elf = elf64_with_section(EM_X86_64, 0, ".init", 0x6, Some((text, 0x400000)), None);
    let profile = profile::analyze(&elf).expect("ELF must analyze");

    assert_eq!(profile.analysis.syscalls.status, AnalysisStatus::Partial);
    assert_eq!(
        profile.analysis.syscalls.reason,
        Some(ReasonCode::PartialCoverage)
    );
    assert!(profile.syscalls.is_empty());
    assert!(
        profile
            .analysis
            .target
            .code_regions
            .iter()
            .all(|r| !r.analyzed)
    );
    // The gap must surface in the risk summary and policy draft.
    assert!(
        profile
            .risk_summary
            .iter()
            .any(|l| l.contains("Syscall analysis partial"))
    );
    let kdl_str = generate_policy(
        &empty_validation(),
        &profile,
        None,
        &[],
        &mcp_writ::legislator::source_bind::WorkloadHashes::default(),
    );
    assert!(
        kdl_str.contains("REVIEW: syscall analysis status=partial"),
        "{kdl_str}"
    );
}

#[test]
fn non_exec_text_section_is_not_decoded() {
    // .text without SHF_EXECINSTR is data, not code: no executable regions
    // exist, so Analyzed with zero findings is the truthful result.
    let text: &[u8] = &[0xB8, 1, 0, 0, 0, 0x0F, 0x05];
    let elf = elf64_with_section(EM_X86_64, 0, ".text", 0x2, Some((text, 0x400000)), None);
    let profile = profile::analyze(&elf).expect("ELF must analyze");

    assert_eq!(profile.analysis.syscalls.status, AnalysisStatus::Analyzed);
    assert!(profile.syscalls.is_empty());
    assert!(profile.analysis.target.code_regions.is_empty());
}

#[test]
fn pe_is_unsupported_and_truncated_macho_fails() {
    // PE stays outside the supported formats.
    let profile = profile::analyze(b"MZ\x90\x00\x00\x00\x00\x00").expect("PE must not error");
    assert_eq!(
        profile.analysis.syscalls.status,
        AnalysisStatus::Unsupported
    );
    assert_eq!(
        profile.analysis.syscalls.reason,
        Some(ReasonCode::UnsupportedFormat)
    );
    assert_eq!(profile.analysis.symbols.status, AnalysisStatus::Unsupported);
    assert!(profile.syscalls.is_empty());

    // P6: Mach-O is a recognized format. A truncated thin header cannot be
    // parsed, so it reports Failed/malformed_input rather than a clean
    // empty analysis.
    let truncated = &[0xCF, 0xFA, 0xED, 0xFE, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0][..];
    let profile = profile::analyze(truncated).expect("Mach-O must not error");
    assert_eq!(profile.analysis.syscalls.status, AnalysisStatus::Failed);
    assert_eq!(
        profile.analysis.syscalls.reason,
        Some(ReasonCode::MalformedInput)
    );
}

#[test]
fn malformed_inputs_fail_without_panic() {
    // Truncated before format identification.
    assert!(profile::analyze(&[]).is_err());
    assert!(profile::analyze(&[0x7f, b'E']).is_err());
    assert!(profile::analyze(&[0x7f, b'E', b'L', b'F', 2, 1]).is_err());

    // .text declares a range beyond EOF → Failed state, not a panic or Ok([]).
    let text: &[u8] = &[0x0F, 0x05];
    let elf = elf64_with_text(EM_X86_64, 0, Some((text, 0x400000)), Some(0xFFFF));
    let profile = profile::analyze(&elf).expect("profile must be produced");
    assert_eq!(profile.analysis.syscalls.status, AnalysisStatus::Failed);
    assert_eq!(
        profile.analysis.syscalls.reason,
        Some(ReasonCode::MalformedInput)
    );

    // .text at a load address near u64::MAX: instruction address math must
    // wrap rather than panic, and the in-section offset stays exact.
    let text: &[u8] = &[0xB8, 0x01, 0x00, 0x00, 0x00, 0x0F, 0x05]; // mov eax,1; syscall
    let elf = elf64_with_text(EM_X86_64, 0, Some((text, 0xFFFF_FFFF_FFFF_FFFC)), None);
    let profile = profile::analyze(&elf).expect("profile must be produced");
    assert_eq!(profile.syscalls.len(), 1);
    assert_eq!(profile.syscalls[0].site.offset_in_section, 5);
    assert_eq!(profile.syscalls[0].syscall_number, Some(1));
}

// ---- state propagation into output formats and policy drafts ----

#[test]
fn output_formats_surface_analysis_state() {
    // movz w8, #1 ; svc #0 — analyzed as io_destroy under the Linux ABI.
    let text: &[u8] = &[0x28, 0x00, 0x80, 0x52, 0x01, 0x00, 0x00, 0xD4];
    let elf = elf64_with_text(EM_AARCH64, 0, Some((text, 0x400000)), None);
    let profile = profile::analyze(&elf).unwrap();

    let human = profile::format_human(&profile);
    assert!(human.contains("Target: elf aarch64"), "{human}");
    assert!(human.contains("syscalls=analyzed"), "{human}");
    assert!(human.contains("io_destroy"), "{human}");

    let json = profile::format_json(&profile);
    let parsed = nojson::RawJson::parse(&json).expect("JSON must parse");
    let v = parsed.value();
    assert!(v.to_member("target").is_ok());
    assert!(v.to_member("analysis").is_ok());
    assert!(json.contains("\"aarch64\""), "{json}");
    assert!(json.contains("\"io_destroy\""), "{json}");

    let kdl_str = profile::format_kdl(&profile);
    let doc: kdl::KdlDocument = kdl_str.parse().expect("KDL must parse");
    assert!(doc.get("target").is_some());
    assert!(doc.get("analysis").is_some());
    assert!(kdl_str.contains("status=\"analyzed\""), "{kdl_str}");
    assert!(kdl_str.contains("\"io_destroy\""), "{kdl_str}");
}

#[test]
fn x86_output_formats_stay_analyzed() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/inspector/x86_64_linux_syscalls.elf"
    );
    let bytes = std::fs::read(path).unwrap();
    let profile = profile::analyze(&bytes).unwrap();

    let human = profile::format_human(&profile);
    assert!(human.contains("Target: elf x86_64"));
    assert!(human.contains("syscalls=analyzed"));

    let kdl_str = profile::format_kdl(&profile);
    let doc: kdl::KdlDocument = kdl_str.parse().expect("KDL must parse");
    assert!(doc.get("analysis").is_some());
    assert!(kdl_str.contains("status=\"analyzed\""));
}

#[test]
fn policy_draft_for_aarch64_uses_linux_table() {
    // movz w8, #1 ; svc #0 → io_destroy in the generated allowlist, no
    // unsupported-analysis REVIEW banner.
    let text: &[u8] = &[0x28, 0x00, 0x80, 0x52, 0x01, 0x00, 0x00, 0xD4];
    let elf = elf64_with_text(EM_AARCH64, 0, Some((text, 0x400000)), None);
    let profile = profile::analyze(&elf).unwrap();

    let kdl_str = generate_policy(
        &empty_validation(),
        &profile,
        None,
        &[],
        &mcp_writ::legislator::source_bind::WorkloadHashes::default(),
    );
    assert!(!kdl_str.contains("status=unsupported"), "{kdl_str}");
    assert!(kdl_str.contains("isa=aarch64"), "{kdl_str}");
    assert!(kdl_str.contains("\"io_destroy\""), "{kdl_str}");
    let doc: Result<kdl::KdlDocument, _> = kdl_str.parse();
    assert!(doc.is_ok(), "policy draft must parse: {kdl_str}");
}

#[test]
fn aarch64_non_linux_abi_stays_unsupported() {
    // ELFOSABI_FREEBSD=9 on AArch64: the ISA is decodable but the syscall
    // numbering convention is not Linux — never resolve through the table.
    let text: &[u8] = &[0x28, 0x00, 0x80, 0x52, 0x01, 0x00, 0x00, 0xD4];
    let elf = elf64_with_text(EM_AARCH64, 9, Some((text, 0x400000)), None);
    let profile = profile::analyze(&elf).expect("ELF must analyze");

    assert_eq!(profile.analysis.target.isa, Isa::AArch64);
    assert_eq!(profile.analysis.target.abi, SyscallAbi::Unknown);
    assert_eq!(
        profile.analysis.syscalls.status,
        AnalysisStatus::Unsupported
    );
    assert_eq!(
        profile.analysis.syscalls.reason,
        Some(ReasonCode::UnknownAbi)
    );
    assert!(profile.syscalls.is_empty());

    let kdl_str = generate_policy(
        &empty_validation(),
        &profile,
        None,
        &[],
        &mcp_writ::legislator::source_bind::WorkloadHashes::default(),
    );
    assert!(
        kdl_str.contains("REVIEW: syscall analysis status=unsupported"),
        "{kdl_str}"
    );
}

#[test]
fn policy_draft_for_analyzed_binary_has_no_gap_warning() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/inspector/x86_64_linux_syscalls.elf"
    );
    let bytes = std::fs::read(path).unwrap();
    let profile = profile::analyze(&bytes).unwrap();

    let kdl_str = generate_policy(
        &empty_validation(),
        &profile,
        None,
        &[],
        &mcp_writ::legislator::source_bind::WorkloadHashes::default(),
    );
    assert!(!kdl_str.contains("status=unsupported"), "{kdl_str}");
    assert!(kdl_str.contains("isa=x86_64"), "{kdl_str}");
    // Resolved execve must land in the allowlist.
    assert!(kdl_str.contains("\"execve\""), "{kdl_str}");
    let doc: Result<kdl::KdlDocument, _> = kdl_str.parse();
    assert!(doc.is_ok(), "policy draft must parse: {kdl_str}");
}
