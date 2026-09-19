use crate::inspector::decoder::x86;

/// A location where a syscall-entry instruction was found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyscallSite {
    /// Virtual address of the syscall instruction.
    pub address: u64,
    /// Byte offset within the analyzed code region.
    pub offset_in_section: u64,
}

/// Scan raw x86-64 code bytes for `syscall` instructions.
///
/// `code_bytes` is the raw content of a code region (e.g. `.text`);
/// `region_vaddr` is the virtual address where it is loaded.
///
/// ELF dispatch (format/ISA/ABI gating) lives in `inspector::profile` and
/// `inspector::target` — callers must not feed non-x86-64 bytes here.
pub fn scan_syscalls_in_code(code_bytes: &[u8], region_vaddr: u64) -> Vec<SyscallSite> {
    if code_bytes.is_empty() {
        return Vec::new();
    }

    x86::decode_region(code_bytes, region_vaddr)
        .into_iter()
        .filter(|insn| insn.is_syscall_entry())
        .map(|insn| SyscallSite {
            address: insn.address(),
            offset_in_section: insn.address() - region_vaddr,
        })
        .collect()
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

    #[test]
    fn test_scan_invalid_bytes_do_not_panic() {
        // Invalid encodings produce INVALID instructions; scanning continues.
        let code: &[u8] = &[0xFF, 0xFF, 0x0F, 0x05];
        let sites = scan_syscalls_in_code(code, 0x8000);
        assert_eq!(sites.len(), 1);
        assert_eq!(sites[0].offset_in_section, 2);
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
}
