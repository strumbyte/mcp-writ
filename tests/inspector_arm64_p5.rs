//! P5 tests for Linux AArch64 ELF analysis in the Inspector.
//!
//! Covers:
//! - the managed `aarch64_linux_syscalls.elf` fixture baseline (sites A–N)
//! - nonzero-immediate `svc` resolved via `x8` while kept as auxiliary info
//! - `w8`/`x8` constant tracking (movz/movn/movk, width/shift/zero-extension)
//! - conservative unresolved results (unknown/conditional/memory writes,
//!   calls, branches, returns, decode gaps, scan-window limits)
//! - Partial coverage reporting for uninterpreted words/trailing bytes
//! - unsupported variants (ELF32, big-endian) and unknown ABI
//! - state propagation into human/JSON/KDL output and policy drafts
//!
//! The fixture is built with the LLVM toolchain (see the .s header) and is
//! never executed — this host has no AArch64 hardware.

use mcp_writ::inspector::profile;
use mcp_writ::inspector::slicer::Resolution;
use mcp_writ::inspector::target::{
    AnalysisStatus, BinaryFormat, ElfClass, Endianness, Isa, ReasonCode, SyscallAbi,
};
use mcp_writ::legislator::cross_validator::CrossValidationResult;
use mcp_writ::legislator::policy_generator::generate_policy;

const EM_AARCH64: u16 = 183;

// AArch64 instruction words used below (little-endian byte order in memory):
const NOP: [u8; 4] = [0x1F, 0x20, 0x03, 0xD5]; // nop
const SVC0: [u8; 4] = [0x01, 0x00, 0x00, 0xD4]; // svc #0
const SVC80: [u8; 4] = [0x01, 0x10, 0x00, 0xD4]; // svc #0x80
const MOVZ_W8_64: [u8; 4] = [0x08, 0x08, 0x80, 0x52]; // movz w8, #64
const MOVZ_W8_1: [u8; 4] = [0x28, 0x00, 0x80, 0x52]; // movz w8, #1
const MOVZ_X8_HI: [u8; 4] = [0x88, 0x46, 0x82, 0xD2]; // movz x8, #0x1234
const MOVK_W8_5: [u8; 4] = [0xA8, 0x00, 0x80, 0x72]; // movk w8, #5
const MOV_W8_W9: [u8; 4] = [0xE8, 0x03, 0x09, 0x2A]; // mov w8, w9 (orr)
const BR_X9: [u8; 4] = [0x20, 0x01, 0x1F, 0xD6]; // br x9
const RET: [u8; 4] = [0xC0, 0x03, 0x5F, 0xD6]; // ret
const CBZ_W8: [u8; 4] = [0x48, 0x00, 0x00, 0x34]; // cbz w8, +8
const INVALID_WORD: [u8; 4] = [0xFF, 0xFF, 0xFF, 0xFF]; // unallocated

fn words(words: &[[u8; 4]]) -> Vec<u8> {
    let mut v = Vec::with_capacity(words.len() * 4);
    for w in words {
        v.extend_from_slice(w);
    }
    v
}

/// Build a minimal ELF64 image with an optional executable `.text` section
/// (same layout as the P4 helper: ehdr|pad 0x100|section|.shstrtab|0x200|shdrs).
fn elf64_with_text(
    machine: u16,
    osabi: u8,
    text: Option<(&[u8], u64)>,
    text_size_override: Option<u64>,
) -> Vec<u8> {
    elf64_with_section(machine, osabi, ".text", 0x6, text, text_size_override)
}

fn elf64_with_section(
    machine: u16,
    osabi: u8,
    section_name: &str,
    section_flags: u64,
    text: Option<(&[u8], u64)>,
    text_size_override: Option<u64>,
) -> Vec<u8> {
    let text_off: u64 = 0x100;
    // .shstrtab must begin after the largest .text any test writes — the
    // backward-window test fills 0xA8 bytes, so .text spans 0x100..0x1A8.
    let shstrtab_off: u64 = 0x1B0;
    let shoff: u64 = 0x200;
    let shnum: u16 = if text.is_some() { 3 } else { 2 };

    let mut shstrtab: Vec<u8> = vec![0];
    let section_name_off = shstrtab.len() as u32;
    shstrtab.extend_from_slice(section_name.as_bytes());
    shstrtab.push(0);
    let shstrtab_name_off = shstrtab.len() as u32;
    shstrtab.extend_from_slice(b".shstrtab");
    shstrtab.push(0);

    let mut b = vec![0u8; 0x400];
    b[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
    b[4] = 2; // ELFCLASS64
    b[5] = 1; // little-endian
    b[6] = 1; // EV_CURRENT
    b[7] = osabi;
    b[16..18].copy_from_slice(&2u16.to_le_bytes());
    b[18..20].copy_from_slice(&machine.to_le_bytes());
    b[20..24].copy_from_slice(&1u32.to_le_bytes());
    let entry = text.map(|(_, v)| v).unwrap_or(0);
    b[24..32].copy_from_slice(&entry.to_le_bytes());
    b[40..48].copy_from_slice(&shoff.to_le_bytes());
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
        b[base + 48..base + 56].copy_from_slice(&1u64.to_le_bytes());
    }

    let shoff_usize = shoff as usize;
    if let Some((bytes, vaddr)) = text {
        let size = text_size_override.unwrap_or(bytes.len() as u64);
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

/// Minimal ELF32 AArch64 image: the ISA is AArch64 but the class is ELF32 —
/// an unsupported variant regardless of ABI.
fn elf32_with_text(machine: u16, osabi: u8, text: &[u8], vaddr: u64) -> Vec<u8> {
    let text_off: usize = 0x100;
    let shstrtab_off: usize = 0x180;
    let shoff: usize = 0x200;

    let mut shstrtab: Vec<u8> = vec![0];
    let text_name_off = shstrtab.len() as u32;
    shstrtab.extend_from_slice(b".text\0");
    let shstrtab_name_off = shstrtab.len() as u32;
    shstrtab.extend_from_slice(b".shstrtab\0");

    let mut b = vec![0u8; 0x400];
    b[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
    b[4] = 1; // ELFCLASS32
    b[5] = 1; // little-endian
    b[6] = 1;
    b[7] = osabi;
    b[16..18].copy_from_slice(&2u16.to_le_bytes());
    b[18..20].copy_from_slice(&machine.to_le_bytes());
    b[20..24].copy_from_slice(&1u32.to_le_bytes());
    b[24..28].copy_from_slice(&(vaddr as u32).to_le_bytes()); // e_entry
    b[28..32].copy_from_slice(&0u32.to_le_bytes()); // e_phoff
    b[32..36].copy_from_slice(&(shoff as u32).to_le_bytes()); // e_shoff
    b[40..42].copy_from_slice(&52u16.to_le_bytes()); // e_ehsize
    b[42..44].copy_from_slice(&32u16.to_le_bytes()); // e_phentsize
    b[46..48].copy_from_slice(&40u16.to_le_bytes()); // e_shentsize
    b[48..50].copy_from_slice(&3u16.to_le_bytes()); // e_shnum
    b[50..52].copy_from_slice(&2u16.to_le_bytes()); // e_shstrndx

    b[text_off..text_off + text.len()].copy_from_slice(text);
    b[shstrtab_off..shstrtab_off + shstrtab.len()].copy_from_slice(&shstrtab);

    // ELF32 section headers are 40 bytes, all fields 32-bit.
    #[allow(clippy::too_many_arguments)]
    fn shdr32(
        b: &mut [u8],
        idx: usize,
        shoff: usize,
        name: u32,
        ty: u32,
        flags: u32,
        addr: u32,
        off: u32,
        size: u32,
    ) {
        let base = shoff + idx * 40;
        b[base..base + 4].copy_from_slice(&name.to_le_bytes());
        b[base + 4..base + 8].copy_from_slice(&ty.to_le_bytes());
        b[base + 8..base + 12].copy_from_slice(&flags.to_le_bytes());
        b[base + 12..base + 16].copy_from_slice(&addr.to_le_bytes());
        b[base + 16..base + 20].copy_from_slice(&off.to_le_bytes());
        b[base + 20..base + 24].copy_from_slice(&size.to_le_bytes());
        b[base + 32..base + 36].copy_from_slice(&1u32.to_le_bytes());
    }
    shdr32(
        &mut b,
        1,
        shoff,
        text_name_off,
        1,
        0x6,
        vaddr as u32,
        text_off as u32,
        text.len() as u32,
    );
    shdr32(
        &mut b,
        2,
        shoff,
        shstrtab_name_off,
        3,
        0,
        0,
        shstrtab_off as u32,
        shstrtab.len() as u32,
    );
    b
}

/// Minimal big-endian ELF64 AArch64 image: all multi-byte header fields are
/// BE-encoded so goblin parses it; the decoder gate must still reject it.
fn elf64_be_with_text(machine: u16, osabi: u8, text: &[u8], vaddr: u64) -> Vec<u8> {
    let text_off: u64 = 0x100;
    let shstrtab_off: u64 = 0x180;
    let shoff: u64 = 0x200;

    let mut shstrtab: Vec<u8> = vec![0];
    let text_name_off = shstrtab.len() as u32;
    shstrtab.extend_from_slice(b".text\0");
    let shstrtab_name_off = shstrtab.len() as u32;
    shstrtab.extend_from_slice(b".shstrtab\0");

    let mut b = vec![0u8; 0x400];
    b[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
    b[4] = 2; // ELFCLASS64
    b[5] = 2; // big-endian
    b[6] = 1;
    b[7] = osabi;
    b[16..18].copy_from_slice(&2u16.to_be_bytes());
    b[18..20].copy_from_slice(&machine.to_be_bytes());
    b[20..24].copy_from_slice(&1u32.to_be_bytes());
    b[24..32].copy_from_slice(&vaddr.to_be_bytes());
    b[32..40].copy_from_slice(&0u64.to_be_bytes());
    b[40..48].copy_from_slice(&shoff.to_be_bytes());
    b[52..54].copy_from_slice(&64u16.to_be_bytes());
    b[54..56].copy_from_slice(&56u16.to_be_bytes());
    b[58..60].copy_from_slice(&64u16.to_be_bytes());
    b[60..62].copy_from_slice(&3u16.to_be_bytes());
    b[62..64].copy_from_slice(&2u16.to_be_bytes());

    b[text_off as usize..text_off as usize + text.len()].copy_from_slice(text);
    b[shstrtab_off as usize..shstrtab_off as usize + shstrtab.len()].copy_from_slice(&shstrtab);

    #[allow(clippy::too_many_arguments)]
    fn shdr64_be(
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
        b[base..base + 4].copy_from_slice(&name.to_be_bytes());
        b[base + 4..base + 8].copy_from_slice(&ty.to_be_bytes());
        b[base + 8..base + 16].copy_from_slice(&flags.to_be_bytes());
        b[base + 16..base + 24].copy_from_slice(&addr.to_be_bytes());
        b[base + 24..base + 32].copy_from_slice(&off.to_be_bytes());
        b[base + 32..base + 40].copy_from_slice(&size.to_be_bytes());
        b[base + 48..base + 56].copy_from_slice(&1u64.to_be_bytes());
    }
    shdr64_be(
        &mut b,
        1,
        shoff as usize,
        text_name_off,
        1,
        0x6,
        vaddr,
        text_off,
        text.len() as u64,
    );
    shdr64_be(
        &mut b,
        2,
        shoff as usize,
        shstrtab_name_off,
        3,
        0,
        0,
        shstrtab_off,
        shstrtab.len() as u64,
    );
    b
}

fn empty_validation() -> CrossValidationResult {
    CrossValidationResult {
        allowed: vec![],
        blocked: vec![],
        warnings: vec![],
    }
}

fn fixture_bytes() -> Vec<u8> {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/inspector/aarch64_linux_syscalls.elf"
    );
    std::fs::read(path).expect("fixture must exist")
}

// ---- managed fixture baseline ----

#[test]
fn fixture_aarch64_syscall_baselines_hold() {
    let bytes = fixture_bytes();
    let profile = profile::analyze(&bytes).expect("fixture must analyze");

    assert_eq!(profile.analysis.target.format, BinaryFormat::Elf);
    assert_eq!(profile.analysis.target.isa, Isa::AArch64);
    assert_eq!(profile.analysis.target.abi, SyscallAbi::Linux);
    assert_eq!(profile.analysis.target.endianness, Endianness::Little);
    assert_eq!(profile.analysis.target.elf_class, Some(ElfClass::Elf64));
    assert_eq!(profile.analysis.syscalls.status, AnalysisStatus::Analyzed);
    assert_eq!(profile.analysis.symbols.status, AnalysisStatus::Analyzed);
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

    // Sites A–N per the .s source. Non-immediates use AArch64 numbering:
    // 64=write, 56=openat, 221=execve, 94=exit_group, 93=exit.
    let expected: [(Option<i64>, Option<&str>, Resolution); 14] = [
        (Some(64), Some("write"), Resolution::Resolved), // A: w8 zero-extend
        (Some(56), Some("openat"), Resolution::Resolved), // B: aarch64 numbering
        (Some(221), Some("execve"), Resolution::Resolved), // C: x8 write
        (Some(0xFFFF_FFFF), None, Resolution::Resolved), // D: movn w8,#0
        (Some(0x1234_0001), None, Resolution::Resolved), // E: movz+movk 64-bit
        (None, None, Resolution::Unresolved),            // F: lone movk
        (None, None, Resolution::Unresolved),            // G: no write
        (None, None, Resolution::Unresolved),            // H: bl boundary
        (Some(94), Some("exit_group"), Resolution::Resolved), // I
        (Some(93), Some("exit"), Resolution::Resolved),  // J
        (Some(64), Some("write"), Resolution::Resolved), // K: svc #0x80, x8=64
        (None, None, Resolution::Unresolved),            // L: csel
        (None, None, Resolution::Unresolved),            // M: ldr
        (None, None, Resolution::Unresolved),            // N: ret boundary
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

    // All 14 `svc` instructions appear as Linux sites — including site K's
    // `svc #0x80`, which resolves via x8 like any other. Its nonzero
    // immediate is still distinguished as auxiliary info in the detail.
    let detail = profile
        .analysis
        .syscalls
        .detail
        .as_deref()
        .unwrap_or_default();
    assert!(detail.contains("nonzero immediate"), "{detail}");
    assert!(detail.contains("0x80"), "{detail}");
}

// ---- scan-level discrimination ----

#[test]
fn nonzero_svc_immediate_resolves_via_x8() {
    // Under the Linux ABI every svc dispatches on x8 — the immediate does not
    // select a different ABI. `svc #0x80` is nonstandard (the Darwin
    // convention), so it is kept as auxiliary info while still resolving.
    let text = words(&[MOVZ_W8_64, SVC80]);
    let elf = elf64_with_text(EM_AARCH64, 0, Some((&text, 0x400000)), None);
    let profile = profile::analyze(&elf).unwrap();

    assert_eq!(profile.analysis.syscalls.status, AnalysisStatus::Analyzed);
    assert_eq!(profile.syscalls.len(), 1);
    assert_eq!(profile.syscalls[0].syscall_number, Some(64));
    assert_eq!(profile.syscalls[0].syscall_name.as_deref(), Some("write"));
    assert_eq!(profile.syscalls[0].resolution, Resolution::Resolved);
    let detail = profile
        .analysis
        .syscalls
        .detail
        .as_deref()
        .unwrap_or_default();
    assert!(detail.contains("nonzero immediate"), "{detail}");
    assert!(detail.contains("0x80"), "{detail}");
}

#[test]
fn svc0_amid_nops_resolves() {
    let text = words(&[NOP, MOVZ_W8_64, NOP, SVC0]);
    let elf = elf64_with_text(EM_AARCH64, 0, Some((&text, 0x400000)), None);
    let profile = profile::analyze(&elf).unwrap();

    assert_eq!(profile.analysis.syscalls.status, AnalysisStatus::Analyzed);
    assert_eq!(profile.syscalls.len(), 1);
    assert_eq!(profile.syscalls[0].syscall_number, Some(64));
    assert_eq!(profile.syscalls[0].syscall_name.as_deref(), Some("write"));
}

#[test]
fn multiple_sites_resolve_independently() {
    let text = words(&[MOVZ_W8_1, SVC0, MOVZ_W8_64, SVC0]);
    let elf = elf64_with_text(EM_AARCH64, 0, Some((&text, 0x400000)), None);
    let profile = profile::analyze(&elf).unwrap();

    assert_eq!(profile.syscalls.len(), 2);
    assert_eq!(profile.syscalls[0].syscall_number, Some(1));
    assert_eq!(
        profile.syscalls[0].syscall_name.as_deref(),
        Some("io_destroy")
    );
    assert_eq!(profile.syscalls[1].syscall_number, Some(64));
    assert_eq!(profile.syscalls[1].syscall_name.as_deref(), Some("write"));
}

#[test]
fn same_number_resolves_per_isa_table() {
    // The same numeric syscall argument must resolve through each ISA's own
    // table: 56 is openat on AArch64 but clone on x86-64; 1 is io_destroy on
    // AArch64 but write on x86-64.
    const EM_X86_64: u16 = 62;
    // movz w8, #56 = 0x52800708
    let a64 = elf64_with_text(
        EM_AARCH64,
        0,
        Some((&words(&[[0x08, 0x07, 0x80, 0x52], SVC0]), 0x400000)),
        None,
    );
    let x64_code: &[u8] = &[0xB8, 56, 0, 0, 0, 0x0F, 0x05]; // mov eax,56; syscall
    let x64 = elf64_with_text(EM_X86_64, 0, Some((x64_code, 0x400000)), None);

    let pa = profile::analyze(&a64).unwrap();
    let px = profile::analyze(&x64).unwrap();

    assert_eq!(pa.syscalls[0].syscall_name.as_deref(), Some("openat"));
    assert_eq!(px.syscalls[0].syscall_name.as_deref(), Some("clone"));

    let a64_1 = elf64_with_text(
        EM_AARCH64,
        0,
        Some((&words(&[MOVZ_W8_1, SVC0]), 0x400000)),
        None,
    );
    let x64_1_code: &[u8] = &[0xB8, 1, 0, 0, 0, 0x0F, 0x05]; // mov eax,1; syscall
    let x64_1 = elf64_with_text(EM_X86_64, 0, Some((x64_1_code, 0x400000)), None);
    let pa1 = profile::analyze(&a64_1).unwrap();
    let px1 = profile::analyze(&x64_1).unwrap();
    assert_eq!(pa1.syscalls[0].syscall_name.as_deref(), Some("io_destroy"));
    assert_eq!(px1.syscalls[0].syscall_name.as_deref(), Some("write"));
}

// ---- constant-construction semantics ----

#[test]
fn movk_completing_movz_resolves_full_width() {
    // movz x8, #0x1234 ; movk x8, #0x5678, lsl #16 ; svc #0 -> x8=0x5678_1234.
    // movk x8,#0x5678,lsl#16 = 0xF2A00000 | (0x5678<<5) | 8 = 0xF2AACF08.
    let movk_hi: [u8; 4] = 0xF2AACF08u32.to_le_bytes();
    let text = words(&[MOVZ_X8_HI, movk_hi, SVC0]);
    let elf = elf64_with_text(EM_AARCH64, 0, Some((&text, 0x400000)), None);
    let profile = profile::analyze(&elf).unwrap();

    assert_eq!(profile.syscalls.len(), 1);
    assert_eq!(profile.syscalls[0].syscall_number, Some(0x5678_1234));
    assert_eq!(profile.syscalls[0].resolution, Resolution::Resolved);
    assert_eq!(profile.syscalls[0].syscall_name, None); // unknown number, still resolved
}

#[test]
fn movz_w8_overrides_x8_high_bits() {
    // movz x8, #0x1234, lsl #32 is impossible (w-form has no lsl#32); instead:
    // movz x8, #0x1234 then movz w8, #64 -> the W write zero-extends, so the
    // high bits die: resolved 64, not 0x1234_0040.
    let text = words(&[MOVZ_X8_HI, MOVZ_W8_64, SVC0]);
    let elf = elf64_with_text(EM_AARCH64, 0, Some((&text, 0x400000)), None);
    let profile = profile::analyze(&elf).unwrap();

    assert_eq!(profile.syscalls[0].syscall_number, Some(64));
    assert_eq!(profile.syscalls[0].resolution, Resolution::Resolved);
}

#[test]
fn mov_alias_bitmask_immediate_resolves() {
    // mov w8, #0x55555555 is only encodable as `orr w8, wzr, #0x55555555`
    // (0x3200F3E8) — a confirmed mov alias producing a constant.
    let text = words(&[[0xE8, 0xF3, 0x00, 0x32], SVC0]);
    let elf = elf64_with_text(EM_AARCH64, 0, Some((&text, 0x400000)), None);
    let profile = profile::analyze(&elf).unwrap();

    assert_eq!(profile.syscalls[0].syscall_number, Some(0x5555_5555));
    assert_eq!(profile.syscalls[0].resolution, Resolution::Resolved);
    assert_eq!(profile.syscalls[0].syscall_name, None);
}

#[test]
fn orr_with_nonzero_source_is_unresolved() {
    // orr w8, w9, #imm is not a mov alias: the value depends on w9.
    let text = words(&[MOVZ_W8_1, [0x28, 0xF1, 0x00, 0x32], SVC0]);
    let elf = elf64_with_text(EM_AARCH64, 0, Some((&text, 0x400000)), None);
    let profile = profile::analyze(&elf).unwrap();

    assert_eq!(profile.syscalls[0].resolution, Resolution::Unresolved);
    assert_eq!(profile.syscalls[0].syscall_number, None);
}

#[test]
fn lone_movk_is_unresolved() {
    let text = words(&[MOVK_W8_5, SVC0]);
    let elf = elf64_with_text(EM_AARCH64, 0, Some((&text, 0x400000)), None);
    let profile = profile::analyze(&elf).unwrap();

    assert_eq!(profile.syscalls[0].resolution, Resolution::Unresolved);
    assert_eq!(profile.syscalls[0].syscall_number, None);
}

#[test]
fn register_move_is_unresolved() {
    // mov w8, w9 is a non-constant write — the previous constant must die.
    let text = words(&[MOVZ_W8_1, MOV_W8_W9, SVC0]);
    let elf = elf64_with_text(EM_AARCH64, 0, Some((&text, 0x400000)), None);
    let profile = profile::analyze(&elf).unwrap();

    assert_eq!(profile.syscalls[0].resolution, Resolution::Unresolved);
    assert_eq!(profile.syscalls[0].syscall_number, None);
}

// ---- conservative boundaries ----

#[test]
fn indirect_branch_is_unresolved() {
    // br x9 between the write and the svc: execution may not be sequential.
    let text = words(&[MOVZ_W8_64, BR_X9, SVC0]);
    let elf = elf64_with_text(EM_AARCH64, 0, Some((&text, 0x400000)), None);
    let profile = profile::analyze(&elf).unwrap();

    assert_eq!(profile.syscalls[0].resolution, Resolution::Unresolved);
}

#[test]
fn conditional_branch_is_unresolved() {
    // cbz w8, +8 — a conditional branch ends the backward chain even though
    // it also reads w8.
    let text = words(&[MOVZ_W8_64, CBZ_W8, SVC0]);
    let elf = elf64_with_text(EM_AARCH64, 0, Some((&text, 0x400000)), None);
    let profile = profile::analyze(&elf).unwrap();

    assert_eq!(profile.syscalls[0].resolution, Resolution::Unresolved);
}

#[test]
fn ret_is_unresolved() {
    let text = words(&[MOVZ_W8_64, RET, SVC0]);
    let elf = elf64_with_text(EM_AARCH64, 0, Some((&text, 0x400000)), None);
    let profile = profile::analyze(&elf).unwrap();

    assert_eq!(profile.syscalls[0].resolution, Resolution::Unresolved);
}

#[test]
fn backward_window_limit_is_enforced() {
    // 40 nops between the write and the svc exceed MAX_BACKWARD_SCAN (32);
    // the site must be unresolved rather than skipping beyond the window.
    let mut v = Vec::new();
    v.extend_from_slice(&MOVZ_W8_64);
    for _ in 0..40 {
        v.extend_from_slice(&NOP);
    }
    v.extend_from_slice(&SVC0);
    let elf = elf64_with_text(EM_AARCH64, 0, Some((&v, 0x400000)), None);
    let profile = profile::analyze(&elf).unwrap();

    assert_eq!(profile.syscalls.len(), 1);
    assert_eq!(profile.syscalls[0].resolution, Resolution::Unresolved);
    assert_eq!(profile.syscalls[0].syscall_number, None);
}

// ---- coverage / malformed inputs ----

#[test]
fn uninterpreted_word_marks_partial_coverage() {
    // movz w8,#64 ; <unallocated word> ; svc #0 — the gap sits inside the
    // backward window, so the site is Unresolved and the coverage Partial.
    let text = words(&[MOVZ_W8_64, INVALID_WORD, SVC0]);
    let elf = elf64_with_text(EM_AARCH64, 0, Some((&text, 0x400000)), None);
    let profile = profile::analyze(&elf).unwrap();

    assert_eq!(
        profile.analysis.syscalls.status,
        AnalysisStatus::Partial,
        "{:?}",
        profile.analysis.syscalls
    );
    assert_eq!(
        profile.analysis.syscalls.reason,
        Some(ReasonCode::PartialCoverage)
    );
    assert!(
        profile
            .risk_summary
            .iter()
            .any(|l| l.contains("Syscall analysis partial"))
    );
}

#[test]
fn uninterpreted_word_after_all_sites_still_partial() {
    // The gap comes *after* the last svc: every site resolves, but part of
    // .text was never interpreted — Partial, not Analyzed.
    let text = words(&[MOVZ_W8_64, SVC0, INVALID_WORD, NOP]);
    let elf = elf64_with_text(EM_AARCH64, 0, Some((&text, 0x400000)), None);
    let profile = profile::analyze(&elf).unwrap();

    assert_eq!(profile.analysis.syscalls.status, AnalysisStatus::Partial);
    assert_eq!(profile.syscalls.len(), 1);
    assert_eq!(profile.syscalls[0].syscall_number, Some(64));
}

#[test]
fn trailing_bytes_mark_partial() {
    // .text whose size is not a multiple of 4 — a truncated instruction tail.
    let mut text = words(&[MOVZ_W8_64, SVC0]);
    text.extend_from_slice(&[0x00, 0x00]); // 2 trailing bytes
    let elf = elf64_with_text(EM_AARCH64, 0, Some((&text, 0x400000)), None);
    let profile = profile::analyze(&elf).unwrap();

    assert_eq!(profile.analysis.syscalls.status, AnalysisStatus::Partial);
    assert_eq!(profile.syscalls.len(), 1);
    assert_eq!(profile.syscalls[0].syscall_number, Some(64));
}

#[test]
fn empty_text_is_analyzed_empty() {
    // An executable-but-empty .text (zero instructions) fully decodes.
    let text: &[u8] = &[];
    let elf = elf64_with_section(EM_AARCH64, 0, ".text", 0x6, Some((text, 0x400000)), Some(0));
    let profile = profile::analyze(&elf).unwrap();
    // Section size 0 — but it exists; goblin still reports it as a region.
    assert_eq!(profile.analysis.syscalls.status, AnalysisStatus::Analyzed);
    assert!(profile.syscalls.is_empty());
}

// ---- unsupported variants ----

#[test]
fn aarch64_elf32_is_unsupported_variant() {
    let text = words(&[MOVZ_W8_64, SVC0]);
    let elf = elf32_with_text(EM_AARCH64, 0, &text, 0x400000);
    let profile = profile::analyze(&elf).unwrap();

    assert_eq!(profile.analysis.target.isa, Isa::AArch64);
    assert_eq!(profile.analysis.target.elf_class, Some(ElfClass::Elf32));
    assert_eq!(
        profile.analysis.syscalls.status,
        AnalysisStatus::Unsupported
    );
    assert_eq!(
        profile.analysis.syscalls.reason,
        Some(ReasonCode::UnsupportedVariant)
    );
    assert!(profile.syscalls.is_empty());
}

#[test]
fn aarch64_big_endian_is_unsupported_variant() {
    let text = words(&[MOVZ_W8_64, SVC0]);
    let elf = elf64_be_with_text(EM_AARCH64, 0, &text, 0x400000);
    let profile = profile::analyze(&elf).unwrap();

    assert_eq!(profile.analysis.target.isa, Isa::AArch64);
    assert_eq!(profile.analysis.target.endianness, Endianness::Big);
    assert_eq!(
        profile.analysis.syscalls.status,
        AnalysisStatus::Unsupported
    );
    assert_eq!(
        profile.analysis.syscalls.reason,
        Some(ReasonCode::UnsupportedVariant)
    );
    assert!(profile.syscalls.is_empty());
}

#[test]
fn aarch64_unknown_abi_is_unsupported() {
    // ELFOSABI_FREEBSD=9 — AArch64 decoder exists but the Linux table does
    // not apply.
    let text = words(&[MOVZ_W8_64, SVC0]);
    let elf = elf64_with_text(EM_AARCH64, 9, Some((&text, 0x400000)), None);
    let profile = profile::analyze(&elf).unwrap();

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

// ---- output/policy propagation ----

#[test]
fn aarch64_outputs_and_policy_propagate() {
    let bytes = fixture_bytes();
    let profile = profile::analyze(&bytes).unwrap();

    let human = profile::format_human(&profile);
    assert!(human.contains("Target: elf aarch64"), "{human}");
    assert!(human.contains("syscalls=analyzed"), "{human}");
    assert!(human.contains("openat"), "{human}");
    assert!(human.contains("execve"), "{human}");

    let json = profile::format_json(&profile);
    let parsed = nojson::RawJson::parse(&json).expect("JSON must parse");
    assert!(parsed.value().to_member("analysis").is_ok());
    assert!(json.contains("\"openat\""), "{json}");

    let kdl_str = profile::format_kdl(&profile);
    let doc: kdl::KdlDocument = kdl_str.parse().expect("KDL must parse");
    assert!(doc.get("analysis").is_some());
    assert!(kdl_str.contains("status=\"analyzed\""), "{kdl_str}");

    let policy = generate_policy(&empty_validation(), &profile, None, &[]);
    assert!(policy.contains("\"openat\""), "{policy}");
    assert!(policy.contains("\"execve\""), "{policy}");
    assert!(!policy.contains("status=unsupported"), "{policy}");
    let pdoc: Result<kdl::KdlDocument, _> = policy.parse();
    assert!(pdoc.is_ok(), "policy draft must parse: {policy}");
}
