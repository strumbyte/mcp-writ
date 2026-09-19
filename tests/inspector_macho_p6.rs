//! P6 tests: Mach-O thin/fat containers and Darwin ARM64 (AArch64) analysis.
//!
//! Covers:
//! - Mach-O identification: thin 64-bit, fat/fat64 universal headers
//! - slice selection and per-slice `Unsupported` states (arm64e, x86_64)
//! - Darwin syscall convention: `x16` carries the number, `svc #0x80` is
//!   the entry point; BSD syscalls (non-negative) and Mach traps
//!   (negative) resolve against XNU tables in separate namespaces
//! - symbol/import/string extraction from Mach-O slices
//! - code-region metadata (file vs slice offsets, analyzed flags)
//! - human/JSON/KDL output propagation of Mach-O metadata
//! - policy safety: Darwin names never reach a Linux seccomp allowlist
//!
//! All Mach-O inputs are constructed in-test; nothing here is executed.

use mcp_writ::inspector::profile::{self, format_human, format_json, format_kdl};
use mcp_writ::inspector::slicer::{Resolution, SyscallKind};
use mcp_writ::inspector::target::{
    AnalysisStatus, BinaryFormat, Endianness, Isa, MachOPlatform, ReasonCode, SyscallAbi,
};
use mcp_writ::legislator::cross_validator::CrossValidationResult;
use mcp_writ::legislator::policy_generator::generate_policy;

// ---- Mach-O constants ----

const MH_MAGIC_64: [u8; 4] = [0xCF, 0xFA, 0xED, 0xFE]; // little-endian 64-bit
const MH_MAGIC_64_BE: [u8; 4] = [0xFE, 0xED, 0xFA, 0xCF];
const FAT_MAGIC: [u8; 4] = [0xCA, 0xFE, 0xBA, 0xBE]; // big-endian fat header
const FAT_MAGIC_64: [u8; 4] = [0xCA, 0xFE, 0xBA, 0xBF];

const CPU_TYPE_ARM64: u32 = 0x0100_000C;
const CPU_TYPE_X86_64: u32 = 0x0100_0007;
const CPU_SUBTYPE_ARM64_ALL: u32 = 0;
const CPU_SUBTYPE_ARM64_E: u32 = 2;
const CPU_SUBTYPE_X86_64_ALL: u32 = 3;

const MH_EXECUTE: u32 = 2;
const LC_SEGMENT_64: u32 = 0x19;
const LC_SYMTAB: u32 = 0x02;
const LC_LOAD_DYLIB: u32 = 0x0C;
const LC_BUILD_VERSION: u32 = 0x32;
const PLATFORM_MACOS: u32 = 1;
const PLATFORM_IOS: u32 = 2;

const S_ATTR_INSTRUCTIONS: u32 = 0x8000_0400; // PURE_INSTRUCTIONS|SOME_INSTRUCTIONS
const VM_PROT_RX: i32 = 0x5; // READ|EXECUTE

const N_UNDF_EXT: u8 = 0x01; // N_UNDF|N_EXT — undefined external (an import)
const N_SECT_EXT: u8 = 0x0F; // N_SECT|N_EXT — defined external

// ---- AArch64 instruction words (little-endian in memory) ----
// movz x16, #N = 0xD2800000 | (N<<5) | 16 ; movn/movz w16 use 0x928_/0x528_.
const SVC_80: [u8; 4] = [0x01, 0x10, 0x00, 0xD4]; // svc #0x80
const SVC_0: [u8; 4] = [0x01, 0x00, 0x00, 0xD4]; // svc #0 — not an entry under Darwin
const RET: [u8; 4] = [0xC0, 0x03, 0x5F, 0xD6]; // ret
const INVALID_WORD: [u8; 4] = [0xFF, 0xFF, 0xFF, 0xFF]; // unallocated encoding

fn movz_x16(n: u16) -> [u8; 4] {
    (0xD2800000u32 | ((n as u32) << 5) | 16).to_le_bytes()
}
fn movn_x16(n: u16) -> [u8; 4] {
    (0x92800000u32 | ((n as u32) << 5) | 16).to_le_bytes()
}
fn movz_w16(n: u16) -> [u8; 4] {
    (0x52800000u32 | ((n as u32) << 5) | 16).to_le_bytes()
}
fn movz_w8(n: u16) -> [u8; 4] {
    (0x52800000u32 | ((n as u32) << 5) | 8).to_le_bytes()
}

fn words(ws: &[[u8; 4]]) -> Vec<u8> {
    ws.iter().flat_map(|w| w.iter().copied()).collect()
}

fn align(v: usize, a: usize) -> usize {
    (v + a - 1) & !(a - 1)
}

fn put32(b: &mut [u8], off: usize, v: u32) {
    b[off..off + 4].copy_from_slice(&v.to_le_bytes());
}
fn put32be(b: &mut [u8], off: usize, v: u32) {
    b[off..off + 4].copy_from_slice(&v.to_be_bytes());
}
fn put64(b: &mut [u8], off: usize, v: u64) {
    b[off..off + 8].copy_from_slice(&v.to_le_bytes());
}
fn put_name(b: &mut [u8], off: usize, name: &str) {
    let n = name.len().min(16);
    b[off..off + n].copy_from_slice(&name.as_bytes()[..n]);
}

/// One Mach-O section inside the single `__TEXT` segment our fixtures use.
struct Sect {
    name: &'static str,
    flags: u32,
    vaddr: u64,
    bytes: Vec<u8>,
}

fn text_sect(vaddr: u64, code: Vec<u8>) -> Sect {
    Sect {
        name: "__text",
        flags: S_ATTR_INSTRUCTIONS,
        vaddr,
        bytes: code,
    }
}

fn cstring_sect(vaddr: u64, data: &[u8]) -> Sect {
    Sect {
        name: "__cstring",
        flags: 0,
        vaddr,
        bytes: data.to_vec(),
    }
}

/// Build a minimal 64-bit Mach-O (single `__TEXT` segment).
///
/// `syms` entries are `(name, n_type, n_sect, n_value)` — the raw Mach-O
/// `_` prefix is expected on names. Layout:
/// `header(32) | load commands | pad | section data | nlist_64 | strtab`.
fn thin_macho64(
    cputype: u32,
    cpusubtype: u32,
    sections: &[Sect],
    syms: &[(&str, u8, u8, u64)],
    dylibs: &[&str],
    platform: Option<u32>,
) -> Vec<u8> {
    let nsects = sections.len();
    let mut sizeofcmds = 72 + 80 * nsects;
    if !syms.is_empty() {
        sizeofcmds += 24;
    }
    for d in dylibs {
        sizeofcmds += align(24 + d.len() + 1, 8);
    }
    if platform.is_some() {
        sizeofcmds += 24;
    }
    let ncmds = 1 + usize::from(!syms.is_empty()) + dylibs.len() + usize::from(platform.is_some());

    // Assign section file offsets after the commands.
    let data_base = align(32 + sizeofcmds, 16);
    let mut cursor = data_base;
    let mut sect_offs = Vec::new();
    for s in sections {
        cursor = align(cursor, 8);
        sect_offs.push(cursor as u32);
        cursor += s.bytes.len();
    }
    cursor = align(cursor, 8);
    let symoff = cursor;
    let stroff = symoff + syms.len() * 16;
    let mut strtab: Vec<u8> = vec![0];
    let mut strx = Vec::new();
    for (name, _, _, _) in syms {
        strx.push(strtab.len() as u32);
        strtab.extend_from_slice(name.as_bytes());
        strtab.push(0);
    }
    let total = (stroff + strtab.len()).max(data_base + 1);
    let mut buf = vec![0u8; total];

    // mach_header_64
    buf[0..4].copy_from_slice(&MH_MAGIC_64);
    put32(&mut buf, 4, cputype);
    put32(&mut buf, 8, cpusubtype);
    put32(&mut buf, 12, MH_EXECUTE);
    put32(&mut buf, 16, ncmds as u32);
    put32(&mut buf, 20, sizeofcmds as u32);

    // LC_SEGMENT_64 __TEXT
    let mut co = 32usize;
    let seg_fileoff = sect_offs.first().copied().unwrap_or(0) as u64;
    let seg_filesize = if sections.is_empty() {
        0
    } else {
        (cursor - data_base) as u64
    };
    let seg_vmaddr = sections.first().map(|s| s.vaddr & !0xFFF).unwrap_or(0);
    put32(&mut buf, co, LC_SEGMENT_64);
    put32(&mut buf, co + 4, (72 + 80 * nsects) as u32);
    put_name(&mut buf, co + 8, "__TEXT");
    put64(&mut buf, co + 24, seg_vmaddr);
    put64(&mut buf, co + 32, seg_filesize + 0x1000); // vmsize
    put64(&mut buf, co + 40, seg_fileoff);
    put64(&mut buf, co + 48, seg_filesize);
    put32(&mut buf, co + 56, VM_PROT_RX as u32);
    put32(&mut buf, co + 60, VM_PROT_RX as u32);
    put32(&mut buf, co + 64, nsects as u32);
    for (i, s) in sections.iter().enumerate() {
        let so = co + 72 + i * 80;
        put_name(&mut buf, so, s.name);
        put_name(&mut buf, so + 16, "__TEXT");
        put64(&mut buf, so + 32, s.vaddr);
        put64(&mut buf, so + 40, s.bytes.len() as u64);
        put32(&mut buf, so + 48, sect_offs[i]);
        put32(&mut buf, so + 52, 2); // align = 4
        put32(&mut buf, so + 64, s.flags);
        buf[sect_offs[i] as usize..sect_offs[i] as usize + s.bytes.len()].copy_from_slice(&s.bytes);
    }
    co += 72 + 80 * nsects;

    // LC_SYMTAB
    if !syms.is_empty() {
        put32(&mut buf, co, LC_SYMTAB);
        put32(&mut buf, co + 4, 24);
        put32(&mut buf, co + 8, symoff as u32);
        put32(&mut buf, co + 12, syms.len() as u32);
        put32(&mut buf, co + 16, stroff as u32);
        put32(&mut buf, co + 20, strtab.len() as u32);
        co += 24;
        for (i, (_, n_type, n_sect, n_value)) in syms.iter().enumerate() {
            let no = symoff + i * 16;
            put32(&mut buf, no, strx[i]);
            buf[no + 4] = *n_type;
            buf[no + 5] = *n_sect;
            put64(&mut buf, no + 8, *n_value);
        }
        buf[stroff..stroff + strtab.len()].copy_from_slice(&strtab);
    }

    // LC_LOAD_DYLIB
    for d in dylibs {
        let csz = align(24 + d.len() + 1, 8);
        put32(&mut buf, co, LC_LOAD_DYLIB);
        put32(&mut buf, co + 4, csz as u32);
        put32(&mut buf, co + 8, 24); // name offset within command
        buf[co + 24..co + 24 + d.len()].copy_from_slice(d.as_bytes());
        co += csz;
    }

    // LC_BUILD_VERSION
    if let Some(p) = platform {
        put32(&mut buf, co, LC_BUILD_VERSION);
        put32(&mut buf, co + 4, 24);
        put32(&mut buf, co + 8, p);
        put32(&mut buf, co + 12, 0x000C_0000); // minos 12.0
        put32(&mut buf, co + 16, 0x000C_0000); // sdk
    }

    buf
}

/// Build a fat/universal Mach-O (`FAT_MAGIC`, 20-byte arch records).
/// Each entry is `(cputype, cpusubtype, thin_macho_bytes)`.
fn fat_macho(arches: &[(u32, u32, Vec<u8>)]) -> Vec<u8> {
    let table_end = 8 + 20 * arches.len();
    let mut cursor = align(table_end, 16);
    let mut offs = Vec::new();
    for (_, _, bytes) in arches {
        offs.push(cursor);
        cursor = align(cursor + bytes.len(), 16);
    }
    let mut buf = vec![0u8; cursor];
    buf[0..4].copy_from_slice(&FAT_MAGIC);
    put32be(&mut buf, 4, arches.len() as u32);
    for (i, (cputype, cpusubtype, bytes)) in arches.iter().enumerate() {
        let base = 8 + i * 20;
        put32be(&mut buf, base, *cputype);
        put32be(&mut buf, base + 4, *cpusubtype);
        put32be(&mut buf, base + 8, offs[i] as u32);
        put32be(&mut buf, base + 12, bytes.len() as u32);
        put32be(&mut buf, base + 16, 4); // align
        buf[offs[i]..offs[i] + bytes.len()].copy_from_slice(bytes);
    }
    buf
}

fn empty_validation() -> CrossValidationResult {
    CrossValidationResult {
        allowed: vec![],
        blocked: vec![],
        warnings: vec![],
    }
}

// ---- identification ----

#[test]
fn identify_thin_macho_arm64() {
    let m = thin_macho64(
        CPU_TYPE_ARM64,
        CPU_SUBTYPE_ARM64_ALL,
        &[],
        &[],
        &[],
        Some(PLATFORM_MACOS),
    );
    let profile = profile::analyze(&m).expect("thin Mach-O must analyze");
    let t = &profile.analysis.target;
    assert_eq!(t.format, BinaryFormat::MachO);
    assert_eq!(t.isa, Isa::AArch64);
    assert_eq!(t.abi, SyscallAbi::Darwin);
    assert_eq!(t.endianness, Endianness::Little);
    assert_eq!(t.platform, Some(MachOPlatform::MacOs));
    assert_eq!(t.slices.len(), 1);
    assert_eq!(t.slices[0].arch, "arm64");
    assert!(t.slices[0].selected);
    // No code regions: analyzed with zero findings is meaningful here.
    assert_eq!(profile.analysis.syscalls.status, AnalysisStatus::Analyzed);
    assert!(profile.syscalls.is_empty());
}

#[test]
fn identify_ios_platform() {
    let m = thin_macho64(CPU_TYPE_ARM64, 0, &[], &[], &[], Some(PLATFORM_IOS));
    let profile = profile::analyze(&m).unwrap();
    assert_eq!(profile.analysis.target.platform, Some(MachOPlatform::Ios));
}

// ---- Darwin syscall convention ----

#[test]
fn darwin_bsd_syscalls_resolve_via_x16() {
    let code = words(&[
        movz_x16(59), // execve
        SVC_80,
        movz_w16(97), // socket via W write (zero-extends into x16)
        SVC_80,
        movz_w16(202), // sysctl
        SVC_80,
        RET,
    ]);
    let m = thin_macho64(
        CPU_TYPE_ARM64,
        0,
        &[text_sect(0x1000, code)],
        &[],
        &[],
        Some(PLATFORM_MACOS),
    );
    let profile = profile::analyze(&m).unwrap();

    assert_eq!(profile.analysis.syscalls.status, AnalysisStatus::Analyzed);
    let names: Vec<_> = profile
        .syscalls
        .iter()
        .map(|s| (s.syscall_number, s.syscall_name.as_deref(), s.kind))
        .collect();
    assert_eq!(
        names,
        vec![
            (Some(59), Some("execve"), SyscallKind::Unix),
            (Some(97), Some("socket"), SyscallKind::Unix),
            (Some(202), Some("sysctl"), SyscallKind::Unix),
        ]
    );
    assert!(
        profile
            .syscalls
            .iter()
            .all(|s| s.resolution == Resolution::Resolved)
    );
    // BSD names must never come from the Linux table: Darwin 59 is execve;
    // Linux aarch64 59 would be something else entirely.
}

#[test]
fn darwin_mach_traps_resolve_negative_numbers() {
    let code = words(&[
        movn_x16(30), // x16 = ~30 = -31 → mach_msg_trap
        SVC_80,
        movn_x16(27), // x16 = -28 → task_self_trap
        SVC_80,
        movn_x16(99), // x16 = -100 → iokit_user_client_trap
        SVC_80,
        RET,
    ]);
    let m = thin_macho64(
        CPU_TYPE_ARM64,
        0,
        &[text_sect(0x1000, code)],
        &[],
        &[],
        None,
    );
    let profile = profile::analyze(&m).unwrap();

    assert_eq!(profile.analysis.syscalls.status, AnalysisStatus::Analyzed);
    let found: Vec<_> = profile
        .syscalls
        .iter()
        .map(|s| (s.syscall_number, s.syscall_name.as_deref(), s.kind))
        .collect();
    assert_eq!(
        found,
        vec![
            (Some(-31), Some("mach_msg_trap"), SyscallKind::MachTrap),
            (Some(-28), Some("task_self_trap"), SyscallKind::MachTrap),
            (
                Some(-100),
                Some("iokit_user_client_trap"),
                SyscallKind::MachTrap
            ),
        ]
    );
}

#[test]
fn darwin_table_holes_stay_unnamed() {
    // BSD 0 and 8 are holes; Mach trap -30 is a gap. The number resolves,
    // the name stays None — never silently mapped to a wrong name.
    let code = words(&[
        movz_w16(8),
        SVC_80,
        movn_x16(29), // -30
        SVC_80,
        RET,
    ]);
    let m = thin_macho64(
        CPU_TYPE_ARM64,
        0,
        &[text_sect(0x1000, code)],
        &[],
        &[],
        None,
    );
    let profile = profile::analyze(&m).unwrap();

    assert_eq!(profile.syscalls.len(), 2);
    assert_eq!(profile.syscalls[0].syscall_number, Some(8));
    assert_eq!(profile.syscalls[0].syscall_name, None);
    assert_eq!(profile.syscalls[0].kind, SyscallKind::Unix);
    assert_eq!(profile.syscalls[0].resolution, Resolution::Resolved);
    assert_eq!(profile.syscalls[1].syscall_number, Some(-30));
    assert_eq!(profile.syscalls[1].syscall_name, None);
    assert_eq!(profile.syscalls[1].kind, SyscallKind::MachTrap);
}

#[test]
fn darwin_tracks_x16_not_x8() {
    // movz w8 writes the Linux register; under Darwin the number lives in
    // x16, which was never written → unresolved, kind unknown.
    let code = words(&[movz_w8(59), SVC_80, RET]);
    let m = thin_macho64(
        CPU_TYPE_ARM64,
        0,
        &[text_sect(0x1000, code)],
        &[],
        &[],
        None,
    );
    let profile = profile::analyze(&m).unwrap();

    assert_eq!(profile.syscalls.len(), 1);
    let sc = &profile.syscalls[0];
    assert_eq!(sc.syscall_number, None);
    assert_eq!(sc.syscall_name, None);
    assert_eq!(sc.kind, SyscallKind::Unknown);
    assert_eq!(sc.resolution, Resolution::Unresolved);
}

#[test]
fn darwin_svc_nonstandard_immediate_is_not_an_entry() {
    // Under Darwin only `svc #0x80` is a syscall entry. `svc #0` (the Linux
    // encoding) must not silently produce a syscall site — it is recorded
    // as nonstandard auxiliary info instead. (`svc #0` is placed after the
    // real entry: a preceding `svc` is a control-flow boundary that ends
    // backward register tracking.)
    let code = words(&[movz_x16(59), SVC_80, SVC_0, RET]);
    let m = thin_macho64(
        CPU_TYPE_ARM64,
        0,
        &[text_sect(0x1000, code)],
        &[],
        &[],
        None,
    );
    let profile = profile::analyze(&m).unwrap();

    // Only the svc #0x80 is an entry.
    assert_eq!(profile.syscalls.len(), 1);
    assert_eq!(profile.syscalls[0].syscall_number, Some(59));
    let detail = profile
        .analysis
        .syscalls
        .detail
        .as_deref()
        .unwrap_or_default();
    assert!(detail.contains("#0x80"), "{detail}");
    assert!(detail.contains("not resolved"), "{detail}");
}

#[test]
fn darwin_uninterpreted_word_marks_partial() {
    let code = words(&[movz_x16(59), INVALID_WORD, SVC_80, RET]);
    let m = thin_macho64(
        CPU_TYPE_ARM64,
        0,
        &[text_sect(0x1000, code)],
        &[],
        &[],
        None,
    );
    let profile = profile::analyze(&m).unwrap();

    assert_eq!(profile.analysis.syscalls.status, AnalysisStatus::Partial);
    assert_eq!(
        profile.analysis.syscalls.reason,
        Some(ReasonCode::PartialCoverage)
    );
    assert_eq!(profile.analysis.target.code_regions.len(), 1);
    assert!(!profile.analysis.target.code_regions[0].analyzed);
}

// ---- unsupported slices ----

#[test]
fn thin_macho_x86_64_is_unsupported_isa() {
    let m = thin_macho64(CPU_TYPE_X86_64, CPU_SUBTYPE_X86_64_ALL, &[], &[], &[], None);
    let profile = profile::analyze(&m).unwrap();
    let t = &profile.analysis.target;

    assert_eq!(t.format, BinaryFormat::MachO);
    assert_eq!(t.isa, Isa::X86_64);
    assert_eq!(
        profile.analysis.syscalls.status,
        AnalysisStatus::Unsupported
    );
    assert_eq!(
        profile.analysis.syscalls.reason,
        Some(ReasonCode::UnsupportedIsa)
    );
    assert_eq!(t.slices.len(), 1);
    assert!(!t.slices[0].selected);
    assert_eq!(
        t.slices[0].state.as_ref().map(|s| s.reason),
        Some(Some(ReasonCode::UnsupportedIsa))
    );
    assert!(profile.syscalls.is_empty());
}

#[test]
fn thin_macho_arm64e_is_unsupported_variant() {
    let m = thin_macho64(CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_E, &[], &[], &[], None);
    let profile = profile::analyze(&m).unwrap();
    let t = &profile.analysis.target;

    assert_eq!(t.isa, Isa::AArch64);
    assert_eq!(t.slices[0].arch, "arm64e");
    assert!(!t.slices[0].selected);
    assert_eq!(
        profile.analysis.syscalls.status,
        AnalysisStatus::Unsupported
    );
    assert_eq!(
        profile.analysis.syscalls.reason,
        Some(ReasonCode::UnsupportedVariant)
    );
}

// ---- fat containers ----

#[test]
fn fat_macho_selects_and_analyzes_arm64_slice() {
    let arm64 = thin_macho64(
        CPU_TYPE_ARM64,
        0,
        &[text_sect(0x4000, words(&[movz_x16(59), SVC_80, RET]))],
        &[],
        &[],
        Some(PLATFORM_MACOS),
    );
    let x64 = thin_macho64(CPU_TYPE_X86_64, CPU_SUBTYPE_X86_64_ALL, &[], &[], &[], None);
    let fat = fat_macho(&[
        (CPU_TYPE_X86_64, CPU_SUBTYPE_X86_64_ALL, x64),
        (CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_ALL, arm64),
    ]);
    let profile = profile::analyze(&fat).unwrap();
    let t = &profile.analysis.target;

    assert_eq!(t.format, BinaryFormat::MachO);
    assert_eq!(t.isa, Isa::AArch64);
    assert_eq!(t.abi, SyscallAbi::Darwin);
    assert_eq!(t.slice.as_deref(), Some("arm64"));
    assert_eq!(t.slices.len(), 2);
    assert!(!t.slices[0].selected); // x86_64 skipped
    assert_eq!(
        t.slices[0].state.as_ref().map(|s| s.reason),
        Some(Some(ReasonCode::UnsupportedIsa))
    );
    assert!(t.slices[1].selected); // arm64 analyzed

    assert_eq!(profile.analysis.syscalls.status, AnalysisStatus::Analyzed);
    assert_eq!(profile.syscalls.len(), 1);
    assert_eq!(profile.syscalls[0].syscall_name.as_deref(), Some("execve"));

    // Code-region offsets: file_offset is container-absolute, slice_offset
    // is relative to the arm64 slice start — never conflated.
    let region = &t.code_regions[0];
    let arm64_slice_off = t.slices[1].offset;
    assert_eq!(
        region.file_offset,
        arm64_slice_off + region.slice_offset.unwrap()
    );
    assert_eq!(region.name, "__TEXT,__text");
    assert!(region.analyzed);
}

#[test]
fn fat_macho_without_arm64_is_unsupported() {
    let x64 = thin_macho64(CPU_TYPE_X86_64, CPU_SUBTYPE_X86_64_ALL, &[], &[], &[], None);
    let arm64e = thin_macho64(CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_E, &[], &[], &[], None);
    let fat = fat_macho(&[
        (CPU_TYPE_X86_64, CPU_SUBTYPE_X86_64_ALL, x64),
        (CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_E, arm64e),
    ]);
    let profile = profile::analyze(&fat).unwrap();
    let t = &profile.analysis.target;

    assert_eq!(t.slices.len(), 2);
    assert!(t.slices.iter().all(|s| !s.selected));
    assert_eq!(
        profile.analysis.syscalls.status,
        AnalysisStatus::Unsupported
    );
    assert!(t.slices.iter().all(|s| {
        s.state
            .as_ref()
            .is_some_and(|st| st.status == AnalysisStatus::Unsupported)
    }));
    assert!(profile.syscalls.is_empty());
}

#[test]
fn fat_macho_aggregate_state_is_arch_order_independent() {
    // No analyzable slice: the aggregate syscalls state reports the
    // arm64-family skip reason (unsupported_variant) rather than whichever
    // slice happens to lead the arch table. Per-slice states still carry
    // each slice's own reason.
    let x64 = thin_macho64(CPU_TYPE_X86_64, CPU_SUBTYPE_X86_64_ALL, &[], &[], &[], None);
    let arm64e = thin_macho64(CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_E, &[], &[], &[], None);
    for arches in [
        [
            (CPU_TYPE_X86_64, CPU_SUBTYPE_X86_64_ALL, x64.clone()),
            (CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_E, arm64e.clone()),
        ],
        [
            (CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_E, arm64e.clone()),
            (CPU_TYPE_X86_64, CPU_SUBTYPE_X86_64_ALL, x64.clone()),
        ],
    ] {
        let profile = profile::analyze(&fat_macho(&arches)).unwrap();
        let st = &profile.analysis.syscalls;
        assert_eq!(st.status, AnalysisStatus::Unsupported);
        assert_eq!(
            st.reason,
            Some(ReasonCode::UnsupportedVariant),
            "arch-table order must not change the representative state"
        );
    }
}

#[test]
fn fat64_header_is_recognized() {
    // FAT_MAGIC_64 with 32-byte arch records.
    let arm64 = thin_macho64(CPU_TYPE_ARM64, 0, &[], &[], &[], None);
    let mut buf = Vec::new();
    buf.extend_from_slice(&FAT_MAGIC_64);
    buf.extend_from_slice(&1u32.to_be_bytes());
    let off = align(8 + 32, 16);
    buf.resize(off, 0);
    let base = 8;
    // 32-byte fat_arch_64 record, big-endian.
    let mut rec = [0u8; 32];
    rec[0..4].copy_from_slice(&CPU_TYPE_ARM64.to_be_bytes());
    rec[4..8].copy_from_slice(&CPU_SUBTYPE_ARM64_ALL.to_be_bytes());
    rec[8..16].copy_from_slice(&(off as u64).to_be_bytes());
    rec[16..24].copy_from_slice(&(arm64.len() as u64).to_be_bytes());
    buf[base..base + 32].copy_from_slice(&rec);
    buf.extend_from_slice(&arm64);

    let profile = profile::analyze(&buf).unwrap();
    let t = &profile.analysis.target;
    assert_eq!(t.format, BinaryFormat::MachO);
    assert_eq!(t.slices.len(), 1);
    assert!(t.slices[0].selected);
    assert_eq!(profile.analysis.syscalls.status, AnalysisStatus::Analyzed);
}

#[test]
fn truncated_fat_table_fails_closed() {
    // Fat magic + nfat=2 but no arch table: nothing trustworthy to parse.
    let mut b = FAT_MAGIC.to_vec();
    b.extend_from_slice(&2u32.to_be_bytes());
    let profile = profile::analyze(&b).unwrap();
    assert_eq!(profile.analysis.syscalls.status, AnalysisStatus::Failed);
    assert_eq!(
        profile.analysis.syscalls.reason,
        Some(ReasonCode::MalformedInput)
    );
}

#[test]
fn fat_slice_range_outside_file_fails_closed() {
    // The arch record declares a slice beyond EOF.
    let mut b = FAT_MAGIC.to_vec();
    b.extend_from_slice(&1u32.to_be_bytes());
    let mut rec = [0u8; 20];
    rec[0..4].copy_from_slice(&CPU_TYPE_ARM64.to_be_bytes());
    rec[8..12].copy_from_slice(&0x1000u32.to_be_bytes());
    rec[12..16].copy_from_slice(&0x5000u32.to_be_bytes());
    b.extend_from_slice(&rec);
    let profile = profile::analyze(&b).unwrap();
    assert_eq!(profile.analysis.syscalls.status, AnalysisStatus::Failed);
    assert_eq!(
        profile.analysis.syscalls.reason,
        Some(ReasonCode::MalformedInput)
    );
}

// ---- symbols, imports, strings ----

#[test]
fn macho_symbols_imports_and_strings() {
    let text = words(&[movz_x16(97), SVC_80, RET]);
    let cstr: &[u8] = b"https://example.com/hook\0/usr/lib/libSystem.B.dylib\0";
    let m = thin_macho64(
        CPU_TYPE_ARM64,
        0,
        &[text_sect(0x1000, text), cstring_sect(0x2000, cstr)],
        &[
            ("_socket", N_UNDF_EXT, 0, 0),
            ("_main", N_SECT_EXT, 1, 0x1000),
        ],
        &["/usr/lib/libSystem.B.dylib"],
        Some(PLATFORM_MACOS),
    );
    let profile = profile::analyze(&m).unwrap();

    // Undefined external syms become imports even without bind opcodes;
    // names keep their raw Mach-O `_` form (classification strips it).
    assert!(
        profile.symbols.imports.iter().any(|i| i.name == "_socket"),
        "imports: {:?}",
        profile.symbols.imports
    );
    assert!(
        profile
            .symbols
            .libraries
            .iter()
            .any(|l| l.contains("libSystem")),
        "libraries: {:?}",
        profile.symbols.libraries
    );
    assert!(!profile.symbols.is_stripped);
    assert!(
        matches!(
            profile.analysis.symbols.status,
            AnalysisStatus::Analyzed | AnalysisStatus::Partial
        ),
        "symbols state: {:?}",
        profile.analysis.symbols
    );

    // Strings come from the slice's data-bearing sections.
    assert!(
        profile
            .strings
            .urls
            .iter()
            .any(|u| u.contains("example.com")),
        "urls: {:?}",
        profile.strings.urls
    );
}

#[test]
fn macho_code_region_metadata_is_precise() {
    let text = words(&[movz_x16(59), SVC_80, RET]);
    let m = thin_macho64(
        CPU_TYPE_ARM64,
        0,
        &[text_sect(0x1000, text)],
        &[],
        &[],
        None,
    );
    let profile = profile::analyze(&m).unwrap();

    let r = &profile.analysis.target.code_regions[0];
    assert_eq!(r.name, "__TEXT,__text");
    assert_eq!(r.size, 12);
    assert_eq!(r.vaddr, 0x1000);
    assert!(r.analyzed);
    // Thin file: slice-relative and file-absolute offsets coincide.
    assert_eq!(r.slice_offset, Some(r.file_offset));
    // The svc site address is the section vaddr + instruction offset.
    assert_eq!(profile.syscalls[0].site.address, 0x1004);
}

#[test]
fn per_region_analyzed_flags_track_each_section() {
    // __text decodes clean while __stubs carries an unallocated word: the
    // `analyzed` flag must land on the matching code region — the
    // incomplete region must not inherit __text's result.
    let stubs = Sect {
        name: "__stubs",
        flags: S_ATTR_INSTRUCTIONS,
        vaddr: 0x2000,
        bytes: words(&[INVALID_WORD, RET]),
    };
    let m = thin_macho64(
        CPU_TYPE_ARM64,
        0,
        &[
            text_sect(0x1000, words(&[movz_x16(59), SVC_80, RET])),
            stubs,
        ],
        &[],
        &[],
        None,
    );
    let profile = profile::analyze(&m).unwrap();

    let regions = &profile.analysis.target.code_regions;
    assert_eq!(regions.len(), 2);
    assert_eq!(regions[0].name, "__TEXT,__text");
    assert!(regions[0].analyzed);
    assert_eq!(regions[1].name, "__TEXT,__stubs");
    assert!(!regions[1].analyzed);
    assert_eq!(profile.analysis.syscalls.status, AnalysisStatus::Partial);
    assert_eq!(profile.syscalls.len(), 1);
    assert_eq!(profile.syscalls[0].syscall_name.as_deref(), Some("execve"));
}

// ---- output propagation ----

#[test]
fn output_formats_surface_macho_metadata() {
    let text = words(&[movn_x16(30), SVC_80, RET]);
    let m = thin_macho64(
        CPU_TYPE_ARM64,
        0,
        &[text_sect(0x1000, text)],
        &[],
        &[],
        Some(PLATFORM_MACOS),
    );
    let profile = profile::analyze(&m).unwrap();

    let human = format_human(&profile);
    assert!(human.contains("macho"), "{human}");
    assert!(human.contains("darwin"), "{human}");
    assert!(human.contains("platform=macos"), "{human}");
    assert!(human.contains("mach_msg_trap"), "{human}");

    let json = format_json(&profile);
    let _parsed = nojson::RawJson::parse(&json).expect("JSON must parse");
    assert!(json.contains("\"format\":\"macho\""), "{json}");
    assert!(json.contains("\"abi\":\"darwin\""), "{json}");
    assert!(json.contains("\"platform\":\"macos\""), "{json}");
    assert!(json.contains("\"kind\":\"mach_trap\""), "{json}");
    assert!(json.contains("\"syscall_number\":-31"), "{json}");

    let kdl = format_kdl(&profile);
    assert!(kdl.contains("format=\"macho\""), "{kdl}");
    assert!(kdl.contains("abi=\"darwin\""), "{kdl}");
    assert!(kdl.contains("syscall_number=-31"), "{kdl}");
    assert!(kdl.contains("kind=\"mach_trap\""), "{kdl}");
    let _doc: kdl::KdlDocument = kdl.parse().expect("KDL output must parse");
}

#[test]
fn fat_slices_surface_in_outputs() {
    let arm64 = thin_macho64(CPU_TYPE_ARM64, 0, &[], &[], &[], None);
    let x64 = thin_macho64(CPU_TYPE_X86_64, CPU_SUBTYPE_X86_64_ALL, &[], &[], &[], None);
    let fat = fat_macho(&[
        (CPU_TYPE_X86_64, CPU_SUBTYPE_X86_64_ALL, x64),
        (CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_ALL, arm64),
    ]);
    let profile = profile::analyze(&fat).unwrap();

    let human = format_human(&profile);
    assert!(human.contains("Slices (2)"), "{human}");
    assert!(human.contains("x86_64"), "{human}");
    assert!(human.contains("arm64"), "{human}");

    let json = format_json(&profile);
    assert!(json.contains("\"slices\""), "{json}");
    assert!(json.contains("\"selected\":true"), "{json}");
    assert!(json.contains("\"slice\":\"arm64\""), "{json}");
}

// ---- policy safety ----

#[test]
fn darwin_findings_never_enter_linux_seccomp_allowlist() {
    let code = words(&[
        movz_x16(59), // Darwin execve — NOT the Linux number for execve
        SVC_80,
        movn_x16(30), // mach_msg_trap
        SVC_80,
        RET,
    ]);
    let m = thin_macho64(
        CPU_TYPE_ARM64,
        0,
        &[text_sect(0x1000, code)],
        &[],
        &[],
        Some(PLATFORM_MACOS),
    );
    let profile = profile::analyze(&m).unwrap();
    let policy = generate_policy(&empty_validation(), &profile, None, &[]);

    // No `allow` lines may be emitted for a Darwin target: its names come
    // from XNU tables and would be wrong in a Linux seccomp profile.
    for line in policy.lines() {
        let l = line.trim_start();
        if l.starts_with("allow") && !l.contains("mode=") {
            panic!("Darwin target must not emit seccomp allow lines: {l}\n{policy}");
        }
        // Non-comment lines must never carry Darwin names.
        if !l.starts_with("//") {
            assert!(!l.contains("mach_msg_trap"), "Mach trap in policy: {l}");
        }
    }
    assert!(
        policy.contains("non-Linux syscall ABI"),
        "policy must flag the ABI mismatch:\n{policy}"
    );
    // The findings are still visible for review as comments.
    assert!(policy.contains("mach_trap"), "{policy}");
}

#[test]
fn macho_32bit_header_is_unsupported_variant() {
    // MH_MAGIC (32-bit, little-endian): parses as a Mach-O but is outside
    // the 64-bit analysis scope → Unsupported, never a clean empty scan.
    let mut b = Vec::new();
    b.extend_from_slice(&[0xCE, 0xFA, 0xED, 0xFE]);
    b.extend_from_slice(&CPU_TYPE_ARM64.to_le_bytes());
    b.extend_from_slice(&CPU_SUBTYPE_ARM64_ALL.to_le_bytes());
    b.extend_from_slice(&MH_EXECUTE.to_le_bytes());
    b.extend_from_slice(&[0u8; 12]); // ncmds=0 sizeofcmds=0 flags
    // goblin requires the buffer to be at least a 64-bit header in size
    // even for 32-bit files; real 32-bit Mach-Os are always larger.
    b.resize(64, 0);
    let profile = profile::analyze(&b).unwrap();
    assert_eq!(
        profile.analysis.syscalls.status,
        AnalysisStatus::Unsupported,
        "state: {:?}",
        profile.analysis.syscalls
    );
    assert_eq!(
        profile.analysis.syscalls.reason,
        Some(ReasonCode::UnsupportedVariant)
    );
}

#[test]
fn big_endian_macho_is_unsupported_not_misdecoded() {
    // MH_MAGIC_64 big-endian: header parses, but the code bytes are not
    // little-endian AArch64 — conservative Unsupported, not garbage output.
    let mut b = Vec::new();
    b.extend_from_slice(&MH_MAGIC_64_BE);
    b.extend_from_slice(&CPU_TYPE_ARM64.to_be_bytes());
    b.extend_from_slice(&CPU_SUBTYPE_ARM64_ALL.to_be_bytes());
    b.extend_from_slice(&MH_EXECUTE.to_be_bytes());
    b.extend_from_slice(&[0u8; 16]); // ncmds=0 sizeofcmds=0 flags reserved
    let profile = profile::analyze(&b).unwrap();
    // Either the parser rejects the header or the variant gate declines it;
    // the result must never be a clean Analyzed state.
    assert_ne!(profile.analysis.syscalls.status, AnalysisStatus::Analyzed);
}
