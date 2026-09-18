use crate::error::InspectorError;
use crate::inspector::text_section;

/// A location where a `syscall` instruction was found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyscallSite {
    /// Virtual address of the syscall instruction.
    pub address: u64,
    /// Byte offset within the .text section.
    pub offset_in_section: u64,
}

/// Scan raw x86-64 code bytes for `syscall` instructions using iced-x86.
///
/// `code_bytes` is the raw content of the .text section.
/// `section_vaddr` is the virtual address where the section is loaded.
///
/// Returns a list of all syscall sites found. This is a low-level function
/// that can be tested without constructing a full ELF binary.
pub fn scan_syscalls_in_code(code_bytes: &[u8], section_vaddr: u64) -> Vec<SyscallSite> {
    use iced_x86::{Code, Decoder, DecoderOptions};

    if code_bytes.is_empty() {
        return Vec::new();
    }

    let mut decoder = Decoder::with_ip(64, code_bytes, section_vaddr, DecoderOptions::NONE);
    let mut sites = Vec::new();

    for instr in &mut decoder {
        if instr.code() == Code::Syscall {
            let offset = instr.ip() - section_vaddr;
            sites.push(SyscallSite {
                address: instr.ip(),
                offset_in_section: offset,
            });
        }
    }

    sites
}

/// Parse an ELF binary and find all `syscall` instruction sites in the .text section.
///
/// This function:
/// 1. Parses the ELF binary with goblin
/// 2. Verifies the binary is x86-64 (returns empty Vec with warning for other architectures)
/// 3. Locates the .text section
/// 4. Disassembles using iced-x86 to find syscall instructions
pub fn find_syscall_sites(elf_bytes: &[u8]) -> Result<Vec<SyscallSite>, InspectorError> {
    let elf = goblin::elf::Elf::parse(elf_bytes)
        .map_err(|e| InspectorError::ParseError(format!("{e}")))?;

    // EM_X86_64 = 62
    if elf.header.e_machine != goblin::elf::header::EM_X86_64 {
        // Non-x86-64: not an error, just return empty (caller may log a warning)
        return Ok(Vec::new());
    }

    // Find .text section
    let text = text_section::find_text_section(&elf);
    let (sh_offset, sh_size, sh_addr) = match text {
        Some(s) => s,
        None => {
            // No .text section found (e.g. stripped or unusual binary)
            return Ok(Vec::new());
        }
    };

    let code_bytes = text_section::section_bytes(elf_bytes, sh_offset, sh_size)?;
    Ok(scan_syscalls_in_code(code_bytes, sh_addr))
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- Low-level scan_syscalls_in_code tests ----

    #[test]
    fn test_scan_single_syscall() {
        // nop; syscall; nop
        let code: &[u8] = &[
            0x90, // nop
            0x0F, 0x05, // syscall
            0x90, // nop
        ];
        let sites = scan_syscalls_in_code(code, 0x1000);
        assert_eq!(sites.len(), 1);
        assert_eq!(sites[0].address, 0x1001);
        assert_eq!(sites[0].offset_in_section, 1);
    }

    #[test]
    fn test_scan_multiple_syscalls() {
        // syscall; nop; nop; syscall
        let code: &[u8] = &[
            0x0F, 0x05, // syscall at offset 0
            0x90, // nop
            0x90, // nop
            0x0F, 0x05, // syscall at offset 4
        ];
        let sites = scan_syscalls_in_code(code, 0x2000);
        assert_eq!(sites.len(), 2);
        assert_eq!(sites[0].address, 0x2000);
        assert_eq!(sites[0].offset_in_section, 0);
        assert_eq!(sites[1].address, 0x2004);
        assert_eq!(sites[1].offset_in_section, 4);
    }

    #[test]
    fn test_scan_no_syscalls() {
        let code: &[u8] = &[0x90, 0x90, 0x90, 0x90];
        let sites = scan_syscalls_in_code(code, 0x3000);
        assert!(sites.is_empty());
    }

    #[test]
    fn test_scan_empty_code() {
        let sites = scan_syscalls_in_code(&[], 0x4000);
        assert!(sites.is_empty());
    }

    #[test]
    fn test_scan_syscall_among_real_instructions() {
        // mov rax, 0x3b; syscall; ret
        let code: &[u8] = &[
            0x48, 0xC7, 0xC0, 0x3B, 0x00, 0x00, 0x00, // mov rax, 0x3b
            0x0F, 0x05, // syscall
            0xC3, // ret
        ];
        let sites = scan_syscalls_in_code(code, 0x5000);
        assert_eq!(sites.len(), 1);
        assert_eq!(sites[0].address, 0x5007);
        assert_eq!(sites[0].offset_in_section, 7);
    }

    #[test]
    fn test_scan_vaddr_zero() {
        let code: &[u8] = &[0x0F, 0x05];
        let sites = scan_syscalls_in_code(code, 0x0);
        assert_eq!(sites.len(), 1);
        assert_eq!(sites[0].address, 0);
        assert_eq!(sites[0].offset_in_section, 0);
    }

    #[test]
    fn test_scan_high_vaddr() {
        let code: &[u8] = &[0x0F, 0x05];
        let sites = scan_syscalls_in_code(code, 0x7FFF_FFFF_0000);
        assert_eq!(sites.len(), 1);
        assert_eq!(sites[0].address, 0x7FFF_FFFF_0000);
    }

    #[test]
    fn test_scan_does_not_match_sysenter() {
        // sysenter is 0F 34, not syscall (0F 05)
        let code: &[u8] = &[
            0x0F, 0x34, // sysenter
            0x90, // nop
        ];
        let sites = scan_syscalls_in_code(code, 0x6000);
        assert!(sites.is_empty());
    }

    #[test]
    fn test_scan_consecutive_syscalls() {
        let code: &[u8] = &[
            0x0F, 0x05, // syscall
            0x0F, 0x05, // syscall
            0x0F, 0x05, // syscall
        ];
        let sites = scan_syscalls_in_code(code, 0x7000);
        assert_eq!(sites.len(), 3);
        assert_eq!(sites[0].offset_in_section, 0);
        assert_eq!(sites[1].offset_in_section, 2);
        assert_eq!(sites[2].offset_in_section, 4);
    }

    // ---- ELF-level find_syscall_sites tests ----

    /// Build a minimal ELF64 binary with a .text section containing given code.
    fn build_elf_with_text(code: &[u8], machine: u16) -> Vec<u8> {
        let mut buf = Vec::new();

        let ehdr_size: u64 = 64;
        let text_offset = ehdr_size;
        let text_size = code.len() as u64;
        let text_vaddr: u64 = 0x40_1000;

        let shstrtab = b"\0.text\0.shstrtab\0";
        let name_text: u32 = 1;
        let name_shstrtab: u32 = 7;

        let shdr_entsize: u64 = 64;
        let shdr_count: u16 = 3;

        let shstrtab_offset = text_offset + text_size;
        let shstrtab_size = shstrtab.len() as u64;
        let shdr_offset = shstrtab_offset + shstrtab_size;

        // ELF header
        buf.extend_from_slice(&[0x7f, b'E', b'L', b'F']);
        buf.push(2);
        buf.push(1);
        buf.push(1);
        buf.push(0);
        buf.extend_from_slice(&[0u8; 8]);
        buf.extend_from_slice(&2u16.to_le_bytes());
        buf.extend_from_slice(&machine.to_le_bytes());
        buf.extend_from_slice(&1u32.to_le_bytes());
        buf.extend_from_slice(&text_vaddr.to_le_bytes());
        buf.extend_from_slice(&0u64.to_le_bytes());
        buf.extend_from_slice(&shdr_offset.to_le_bytes());
        buf.extend_from_slice(&0u32.to_le_bytes());
        buf.extend_from_slice(&64u16.to_le_bytes());
        buf.extend_from_slice(&56u16.to_le_bytes());
        buf.extend_from_slice(&0u16.to_le_bytes());
        buf.extend_from_slice(&(shdr_entsize as u16).to_le_bytes());
        buf.extend_from_slice(&shdr_count.to_le_bytes());
        buf.extend_from_slice(&2u16.to_le_bytes());

        assert_eq!(buf.len(), ehdr_size as usize);

        buf.extend_from_slice(code);
        buf.extend_from_slice(shstrtab);

        // Null section header
        buf.extend_from_slice(&[0u8; 64]);

        // .text section header
        let mut text_shdr = [0u8; 64];
        text_shdr[0..4].copy_from_slice(&name_text.to_le_bytes());
        text_shdr[4..8].copy_from_slice(&1u32.to_le_bytes());
        text_shdr[8..16].copy_from_slice(&6u64.to_le_bytes());
        text_shdr[16..24].copy_from_slice(&text_vaddr.to_le_bytes());
        text_shdr[24..32].copy_from_slice(&text_offset.to_le_bytes());
        text_shdr[32..40].copy_from_slice(&text_size.to_le_bytes());
        buf.extend_from_slice(&text_shdr);

        // .shstrtab section header
        let mut strtab_shdr = [0u8; 64];
        strtab_shdr[0..4].copy_from_slice(&name_shstrtab.to_le_bytes());
        strtab_shdr[4..8].copy_from_slice(&3u32.to_le_bytes());
        strtab_shdr[24..32].copy_from_slice(&shstrtab_offset.to_le_bytes());
        strtab_shdr[32..40].copy_from_slice(&shstrtab_size.to_le_bytes());
        buf.extend_from_slice(&strtab_shdr);

        buf
    }

    #[test]
    fn test_find_syscall_sites_basic() {
        let code: &[u8] = &[0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00, 0x0F, 0x05];
        let elf = build_elf_with_text(code, 62);
        let sites = find_syscall_sites(&elf).expect("should parse");
        assert_eq!(sites.len(), 1);
        assert_eq!(sites[0].address, 0x40_1000 + 7);
        assert_eq!(sites[0].offset_in_section, 7);
    }

    #[test]
    fn test_find_syscall_sites_multiple() {
        let code: &[u8] = &[0x0F, 0x05, 0x90, 0x0F, 0x05];
        let elf = build_elf_with_text(code, 62);
        let sites = find_syscall_sites(&elf).expect("should parse");
        assert_eq!(sites.len(), 2);
    }

    #[test]
    fn test_find_syscall_sites_no_syscall() {
        let code: &[u8] = &[0x90, 0x90, 0xC3];
        let elf = build_elf_with_text(code, 62);
        let sites = find_syscall_sites(&elf).expect("should parse");
        assert!(sites.is_empty());
    }

    #[test]
    fn test_find_syscall_sites_non_x86_64() {
        let code: &[u8] = &[0x0F, 0x05];
        let elf = build_elf_with_text(code, 183); // EM_AARCH64
        let sites = find_syscall_sites(&elf).expect("should not error");
        assert!(sites.is_empty());
    }

    #[test]
    fn test_find_syscall_sites_empty_text() {
        let elf = build_elf_with_text(&[], 62);
        let sites = find_syscall_sites(&elf).expect("should parse");
        assert!(sites.is_empty());
    }

    #[test]
    fn test_find_syscall_sites_invalid_elf() {
        let result = find_syscall_sites(b"not an elf");
        assert!(result.is_err());
    }

    #[test]
    fn test_syscall_site_equality() {
        let a = SyscallSite {
            address: 0x1000,
            offset_in_section: 0,
        };
        let b = SyscallSite {
            address: 0x1000,
            offset_in_section: 0,
        };
        let c = SyscallSite {
            address: 0x2000,
            offset_in_section: 0,
        };
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn test_find_syscall_sites_realistic_sequence() {
        let code: &[u8] = &[
            0x55, // push rbp
            0x48, 0x89, 0xE5, // mov rbp, rsp
            0x48, 0xC7, 0xC0, 0x01, 0x00, 0x00, 0x00, // mov rax, 1
            0x0F, 0x05, // syscall
            0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00, // mov rax, 60
            0x0F, 0x05, // syscall
            0x5D, // pop rbp
            0xC3, // ret
        ];
        let elf = build_elf_with_text(code, 62);
        let sites = find_syscall_sites(&elf).expect("should parse");
        assert_eq!(sites.len(), 2);
        assert_eq!(sites[0].offset_in_section, 11);
        assert_eq!(sites[1].offset_in_section, 20);
    }
}
