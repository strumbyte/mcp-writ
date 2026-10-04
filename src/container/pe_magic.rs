//! Minimal PE inspection for the Windows guest contract: whether a file
//! is a PE image at all, which machine architecture it targets, and
//! which MSVC-redistributable DLLs it imports.
//!
//! The import check is the one that keeps Server Core honest: the image
//! carries no `VCRUNTIME140.dll`, so an MSVC-built runner whose PE
//! import table names it fails loader lock in the guest
//! (`STATUS_DLL_NOT_FOUND`, 0xC0000135). `wrap-image` uses this to ship
//! the DLL app-local instead of assuming the runner happens to be
//! statically linked.

use std::path::Path;

use crate::execution::TargetArch;

/// MSVC redistributable families a Windows Server Core image does not
/// carry. A PE that imports any of these needs the DLL shipped app-local
/// (next to the exe). `ucrtbase.dll` / `msvcrt.dll` are deliberately
/// absent — both are OS components Server Core does ship.
const REDIST_PREFIXES: &[&str] = &[
    "vcruntime140",
    "vcruntime140_",
    "msvcp140",
    "concrt140",
    "vccorlib140",
];

/// Exact names outside the `vcruntime140`-family prefixes that still
/// belong to the MSVC redist (`msvcr120.dll` is the VS2013 runtime).
const REDIST_NAMES: &[&str] = &["msvcr120.dll"];

/// Read the fixed-size head of a PE from `path` — DOS `e_lfanew`, the
/// `PE\0\0` signature and the 20-byte COFF header — and return the open
/// file positioned at the optional header together with the COFF fields
/// the bounded scans need: machine, section count, optional-header size.
/// `None` on any IO or shape failure; never buffers the whole image.
fn pe_head(path: &Path) -> Option<(std::fs::File, u16, u16, u16)> {
    use std::io::{Read, Seek, SeekFrom};
    let mut file = std::fs::File::open(path).ok()?;
    let mut dos = [0u8; 64];
    file.read_exact(&mut dos).ok()?;
    if dos[0..2] != *b"MZ" {
        return None;
    }
    let pe_offset = u64::from(u32::from_le_bytes(dos[0x3C..0x40].try_into().ok()?));
    file.seek(SeekFrom::Start(pe_offset)).ok()?;
    let mut head = [0u8; 4 + 20];
    file.read_exact(&mut head).ok()?;
    if head[0..4] != *b"PE\0\0" {
        return None;
    }
    let coff = &head[4..];
    let machine = u16::from_le_bytes(coff[0..2].try_into().ok()?);
    let num_sections = u16::from_le_bytes(coff[2..4].try_into().ok()?);
    let opt_size = u16::from_le_bytes(coff[16..18].try_into().ok()?);
    Some((file, machine, num_sections, opt_size))
}

/// Machine architecture of the PE at `path`, reading only its headers —
/// DOS `e_lfanew`, `PE\0\0` signature and the COFF machine field — so
/// the answer costs tens of bytes regardless of image size. `None` on
/// any IO or shape failure; callers that need a full parse keep using
/// [`pe_arch`] on a buffered image.
pub fn pe_arch_path(path: &Path) -> Option<TargetArch> {
    let (_, machine, ..) = pe_head(path)?;
    Some(match machine {
        goblin::pe::header::COFF_MACHINE_X86_64 => TargetArch::X86_64,
        goblin::pe::header::COFF_MACHINE_ARM64 => TargetArch::Aarch64,
        _ => TargetArch::Other(format!("pe-machine-0x{machine:04x}")),
    })
}

/// Returns `true` when the file at `path` starts with the PE signature's
/// `MZ` magic. Non-existent files, files shorter than 2 bytes, and
/// non-PE files all return `false` (never an error).
pub fn looks_like_pe(path: &Path) -> bool {
    use std::io::Read;
    let Ok(file) = std::fs::File::open(path) else {
        return false;
    };
    let mut buf = [0u8; 2];
    let mut reader = std::io::BufReader::new(file);
    if reader.read_exact(&mut buf).is_err() {
        return false;
    }
    buf == *b"MZ"
}

/// Machine architecture of a PE image, or `None` when `data` is not a
/// parseable PE — callers distinguish "not a PE" from "PE of an arch we
/// do not name" so a foreign-arch image reports `Other` rather than
/// looking like a corrupt file.
pub fn pe_arch(data: &[u8]) -> Option<TargetArch> {
    let pe = goblin::pe::PE::parse(data).ok()?;
    Some(match pe.header.coff_header.machine {
        goblin::pe::header::COFF_MACHINE_X86_64 => TargetArch::X86_64,
        goblin::pe::header::COFF_MACHINE_ARM64 => TargetArch::Aarch64,
        _ => TargetArch::Other(format!(
            "pe-machine-0x{:04x}",
            pe.header.coff_header.machine
        )),
    })
}

/// The MSVC-redistributable DLL names `data`'s import table depends on —
/// the set that must ship app-local for the exe to load on Server Core.
/// Empty for statically-linked (`crt-static`, MinGW) PEs. Returns `None`
/// when `data` is not a parseable PE.
pub fn required_redist_dlls(data: &[u8]) -> Option<Vec<String>> {
    let pe = goblin::pe::PE::parse(data).ok()?;
    Some(redist_filter(
        pe.libraries.iter().map(|name| name.to_string()),
    ))
}

/// The MSVC-redistributable DLL imports of the PE at `path`, read
/// without buffering the image: the headers, the section table, then
/// only the byte ranges holding import descriptors and DLL name strings
/// — a multi-hundred-MiB executable costs a few KiB of IO. Returns
/// `None` on any IO or shape failure, the same "invalid PE" contract as
/// [`required_redist_dlls`]. This is a bounded import scan, not a full
/// parse; it trusts nothing outside the ranges it reads.
pub fn required_redist_dlls_path(path: &Path) -> Option<Vec<String>> {
    use std::io::{Read, Seek, SeekFrom};
    let (mut file, _machine, num_sections, opt_size) = pe_head(path)?;
    // The Windows loader refuses images with more than 96 sections; the
    // same bound keeps the per-section reads finite.
    if num_sections > 96 {
        return None;
    }
    let mut opt = vec![0u8; opt_size as usize];
    file.read_exact(&mut opt).ok()?;
    let magic = u16::from_le_bytes(opt.get(0..2)?.try_into().ok()?);
    // PE32 keeps the data-directory count at offset 92 and entries at 96;
    // PE32+ at 108 and 112. Entry 1 (offset +8) is the import directory.
    let (count_off, dir_off) = match magic {
        0x10B => (92usize, 96usize),
        0x20B => (108, 112),
        _ => return None,
    };
    let dir_count = u32::from_le_bytes(opt.get(count_off..count_off + 4)?.try_into().ok()?);
    if dir_count < 2 {
        return Some(Vec::new());
    }
    let import_rva = u32::from_le_bytes(opt.get(dir_off + 8..dir_off + 12)?.try_into().ok()?);
    if import_rva == 0 {
        return Some(Vec::new());
    }
    let mut sections = Vec::with_capacity(num_sections as usize);
    for _ in 0..num_sections {
        let mut sh = [0u8; 40];
        file.read_exact(&mut sh).ok()?;
        sections.push((
            u32::from_le_bytes(sh[12..16].try_into().ok()?), // VirtualAddress
            u32::from_le_bytes(sh[8..12].try_into().ok()?),  // VirtualSize
            u32::from_le_bytes(sh[20..24].try_into().ok()?), // PointerToRawData
            u32::from_le_bytes(sh[16..20].try_into().ok()?), // SizeOfRawData
        ));
    }
    let rva_to_off = |rva: u32| -> Option<u64> {
        sections
            .iter()
            .find(|(va, vs, _, raw)| {
                let span = u64::from((*vs).max(*raw).max(1));
                u64::from(rva) >= u64::from(*va) && u64::from(rva) - u64::from(*va) < span
            })
            .map(|(va, _, rp, _)| u64::from(*rp) + u64::from(rva) - u64::from(*va))
    };
    // Import descriptors are 20-byte entries ending in an all-zero one;
    // the count cap and the 512-byte name cap keep a corrupt image from
    // pinning the reader (a real DLL name never approaches either bound).
    let mut names = Vec::new();
    for i in 0..4096u32 {
        let desc_rva = import_rva.checked_add(i.checked_mul(20)?)?;
        file.seek(SeekFrom::Start(rva_to_off(desc_rva)?)).ok()?;
        let mut desc = [0u8; 20];
        file.read_exact(&mut desc).ok()?;
        if desc == [0u8; 20] {
            return Some(redist_filter(names.into_iter()));
        }
        let name_rva = u32::from_le_bytes(desc[12..16].try_into().ok()?);
        file.seek(SeekFrom::Start(rva_to_off(name_rva)?)).ok()?;
        let mut raw = [0u8; 512];
        let read = file.read(&mut raw).ok()?;
        let end = raw[..read].iter().position(|&b| b == 0)?;
        names.push(String::from_utf8(raw[..end].to_vec()).ok()?);
    }
    // No terminator inside the cap — a corrupt table, not a huge one.
    None
}

/// Filter imported library names down to the MSVC redist set that must
/// ship app-local, sorted and deduplicated.
fn redist_filter(libraries: impl Iterator<Item = String>) -> Vec<String> {
    let mut needed: Vec<String> = libraries
        .filter(|name| {
            let lower = name.to_ascii_lowercase();
            lower.ends_with(".dll")
                && (REDIST_PREFIXES.iter().any(|p| lower.starts_with(p))
                    || REDIST_NAMES.contains(&lower.as_str()))
        })
        .collect();
    needed.sort();
    needed.dedup();
    needed
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::container::elf_magic::looks_like_elf;

    /// A minimal but structurally valid PE32+ image: DOS header with
    /// `e_lfanew`, PE signature, COFF header, PE32+ optional header, and
    /// — when `import_dlls` is non-empty — one `.rdata` section carrying
    /// the import descriptors, the DLL name pool, and a zero-terminated
    /// thunk array each descriptor's ILT points at (goblin refuses a
    /// descriptor whose lookup/address-table RVA maps nowhere).
    fn synthetic_pe(machine: u16, import_dlls: &[&str]) -> Vec<u8> {
        let e_lfanew: u32 = 0x80;
        let num_sections: u16 = if import_dlls.is_empty() { 0 } else { 1 };
        let opt_size: u16 = 0xF0; // PE32+ optional header size
        let dll_names: Vec<u8> = import_dlls
            .iter()
            .flat_map(|n| n.bytes().chain(std::iter::once(0)))
            .collect();
        // Layout: import descriptors, DLL names, then one shared
        // zero-entry thunk area the descriptors' lookup tables resolve
        // to (an empty import list — only the DLL names matter here).
        let descs = (import_dlls.len() + 1) * 20;
        let thunk_len = 8; // one zeroed u64 entry terminates the array
        let section_data = descs + dll_names.len() + thunk_len;
        let section_raw_off =
            (e_lfanew as usize + 4 + 20 + opt_size as usize + 40 * num_sections as usize)
                .div_ceil(0x200)
                * 0x200;
        let section_rva = 0x1000u32;
        let mut b = vec![0u8; section_raw_off + section_data.max(1)];
        // DOS header.
        b[0] = b'M';
        b[1] = b'Z';
        b[0x3C..0x40].copy_from_slice(&e_lfanew.to_le_bytes());
        // PE signature + COFF header.
        let coff = e_lfanew as usize + 4;
        b[e_lfanew as usize..coff].copy_from_slice(b"PE\0\0");
        b[coff..coff + 2].copy_from_slice(&machine.to_le_bytes());
        b[coff + 2..coff + 4].copy_from_slice(&num_sections.to_le_bytes());
        b[coff + 16..coff + 18].copy_from_slice(&opt_size.to_le_bytes());
        // Optional header: PE32+ magic, then the data-directory table —
        // `NumberOfRvaAndSizes` sits at +108 and entry 1 (the import
        // directory) at +120 in the PE32+ layout. An empty import list
        // keeps the entry at 0/0 — a nonzero RVA that maps nowhere is a
        // malformed image, not "no imports".
        let opt = coff + 20;
        b[opt..opt + 2].copy_from_slice(&0x20Bu16.to_le_bytes());
        // Windows fields: section/file alignment — `find_offset`
        // refuses a zero or non-power-of-two file alignment.
        b[opt + 32..opt + 36].copy_from_slice(&0x1000u32.to_le_bytes());
        b[opt + 36..opt + 40].copy_from_slice(&0x200u32.to_le_bytes());
        b[opt + 108..opt + 112].copy_from_slice(&16u32.to_le_bytes());
        // Section header → raw data mapping.
        if num_sections == 1 {
            let dir1 = opt + 120; // data directory[1]
            b[dir1..dir1 + 4].copy_from_slice(&section_rva.to_le_bytes());
            b[dir1 + 4..dir1 + 8].copy_from_slice(&(descs as u32).to_le_bytes());
            let sh = opt + opt_size as usize;
            b[sh..sh + 8].copy_from_slice(b".rdata\0\0");
            b[sh + 8..sh + 12].copy_from_slice(&(section_data as u32).to_le_bytes());
            b[sh + 12..sh + 16].copy_from_slice(&section_rva.to_le_bytes());
            b[sh + 16..sh + 20].copy_from_slice(&(section_data as u32).to_le_bytes());
            b[sh + 20..sh + 24].copy_from_slice(&(section_raw_off as u32).to_le_bytes());
            // Import descriptors: OriginalFirstThunk (ILT) points at the
            // shared zero thunk, Name RVA into the name pool; the
            // (n+1)-th all-zero descriptor terminates the table.
            let thunk_rva = section_rva + (section_data - thunk_len) as u32;
            let mut name_off = section_raw_off + descs;
            for (i, dll) in import_dlls.iter().enumerate() {
                let desc = section_raw_off + i * 20;
                let name_rva = section_rva + (name_off - section_raw_off) as u32;
                b[desc..desc + 4].copy_from_slice(&thunk_rva.to_le_bytes());
                b[desc + 12..desc + 16].copy_from_slice(&name_rva.to_le_bytes());
                b[desc + 16..desc + 20].copy_from_slice(&thunk_rva.to_le_bytes());
                b[name_off..name_off + dll.len()].copy_from_slice(dll.as_bytes());
                name_off += dll.len() + 1;
            }
        }
        b
    }

    #[test]
    fn looks_like_pe_mz_only() {
        let dir = std::env::temp_dir()
            .join("mcp_writ_pe_test")
            .join(format!("mz_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("a.exe");
        std::fs::write(&p, b"MZ").unwrap();
        assert!(looks_like_pe(&p));
        let p2 = dir.join("b.exe");
        std::fs::write(&p2, [0x7f, b'E', b'L', b'F']).unwrap();
        assert!(!looks_like_pe(&p2));
        assert!(!looks_like_pe(&dir.join("nonexistent")));
    }

    #[test]
    fn pe_arch_from_synthetic() {
        let amd = synthetic_pe(0x8664, &[]);
        assert_eq!(pe_arch(&amd), Some(TargetArch::X86_64));
        let arm = synthetic_pe(0xAA64, &[]);
        assert_eq!(pe_arch(&arm), Some(TargetArch::Aarch64));
        let weird = synthetic_pe(0x1234, &[]);
        match pe_arch(&weird) {
            Some(TargetArch::Other(s)) => assert!(s.contains("0x1234")),
            other => panic!("expected Other arch, got {other:?}"),
        }
        assert_eq!(pe_arch(b"not a pe"), None);
    }

    #[test]
    fn pe_arch_path_reads_headers_only() {
        let dir = std::env::temp_dir()
            .join("mcp_writ_pe_test")
            .join(format!("path_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let pe = dir.join("arch.exe");
        std::fs::write(&pe, synthetic_pe(0x8664, &[])).unwrap();
        assert_eq!(pe_arch_path(&pe), Some(TargetArch::X86_64));
        std::fs::write(&pe, synthetic_pe(0xAA64, &[])).unwrap();
        assert_eq!(pe_arch_path(&pe), Some(TargetArch::Aarch64));
        std::fs::write(&pe, b"not a pe").unwrap();
        assert_eq!(pe_arch_path(&pe), None);
        assert_eq!(pe_arch_path(&dir.join("missing.exe")), None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn redist_imports_detected_from_path() {
        let dir = std::env::temp_dir()
            .join("mcp_writ_pe_test")
            .join(format!("pathredist_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let pe = dir.join("imports.exe");
        std::fs::write(
            &pe,
            synthetic_pe(
                0x8664,
                &["VCRUNTIME140.dll", "KERNEL32.dll", "msvcp140.dll"],
            ),
        )
        .unwrap();
        let need = required_redist_dlls_path(&pe).expect("valid PE");
        assert_eq!(
            need,
            required_redist_dlls(&std::fs::read(&pe).unwrap()).unwrap()
        );
        std::fs::write(&pe, synthetic_pe(0x8664, &["KERNEL32.dll"])).unwrap();
        assert_eq!(required_redist_dlls_path(&pe), Some(vec![]));
        std::fs::write(&pe, b"nope").unwrap();
        assert_eq!(required_redist_dlls_path(&pe), None);
        assert_eq!(required_redist_dlls_path(&dir.join("missing.exe")), None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn redist_imports_detected() {
        let data = synthetic_pe(
            0x8664,
            &["VCRUNTIME140.dll", "KERNEL32.dll", "msvcp140.dll"],
        );
        if let Err(e) = goblin::pe::PE::parse(&data) {
            panic!("PE parse failed: {e}");
        }
        let need = required_redist_dlls(&data).expect("valid PE");
        assert!(
            need.iter()
                .any(|n| n.eq_ignore_ascii_case("vcruntime140.dll")),
            "vcruntime140.dll must be detected: {need:?}"
        );
        assert!(
            need.iter().any(|n| n.eq_ignore_ascii_case("msvcp140.dll")),
            "msvcp140.dll must be detected: {need:?}"
        );
        assert!(
            !need.iter().any(|n| n.eq_ignore_ascii_case("kernel32.dll")),
            "kernel32.dll is an OS component, not redist: {need:?}"
        );
        let clean = synthetic_pe(0x8664, &["KERNEL32.dll"]);
        assert_eq!(required_redist_dlls(&clean), Some(vec![]));
        assert_eq!(required_redist_dlls(b"nope"), None);
    }

    #[test]
    fn pe_and_elf_magic_do_not_confuse_each_other() {
        let pe = synthetic_pe(0x8664, &[]);
        let dir = std::env::temp_dir()
            .join("mcp_writ_pe_test")
            .join(format!("x_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let pe_path = dir.join("runner.exe");
        std::fs::write(&pe_path, &pe).unwrap();
        assert!(looks_like_pe(&pe_path));
        assert!(!looks_like_elf(&pe_path));
        let elf_path = dir.join("runner");
        std::fs::write(&elf_path, [0x7f, b'E', b'L', b'F']).unwrap();
        assert!(looks_like_elf(&elf_path));
        assert!(!looks_like_pe(&elf_path));
    }
}
