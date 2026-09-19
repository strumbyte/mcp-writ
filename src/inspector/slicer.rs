use crate::inspector::disasm::{SyscallSite, scan_syscalls_in_code};
use crate::inspector::syscall_table;

/// The result of resolving a syscall instruction's syscall number.
#[derive(Debug, Clone)]
pub struct ResolvedSyscall {
    pub site: SyscallSite,
    pub syscall_number: Option<u64>,
    pub syscall_name: Option<String>,
    pub resolution: Resolution,
}

/// How the syscall number was determined.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Resolution {
    /// RAX immediate value was found and resolved.
    Resolved,
    /// Could not determine RAX value (e.g., set via function return).
    Unresolved,
    /// Multiple code paths lead to this syscall with different RAX values.
    Ambiguous,
}

/// Maximum number of instructions to scan backward from a syscall site.
const MAX_BACKWARD_SCAN: usize = 32;

/// Maximum number of bytes before the syscall to consider for backward decoding.
/// x86-64 instructions are at most 15 bytes, so 32 instructions * 15 = 480 bytes max.
const MAX_BACKWARD_BYTES: u64 = 480;

/// Resolve syscall numbers for all syscall sites in the given code bytes.
///
/// Uses `disasm::scan_syscalls_in_code` to find syscall sites, then performs
/// backward slicing on each to determine the RAX register value.
pub fn resolve_syscalls(code_bytes: &[u8], section_vaddr: u64) -> Vec<ResolvedSyscall> {
    let sites = scan_syscalls_in_code(code_bytes, section_vaddr);

    sites
        .into_iter()
        .map(|site| {
            let result = backward_slice_rax(code_bytes, section_vaddr, site.offset_in_section);
            match result {
                Some(number) => {
                    let name = syscall_table::syscall_name(number).map(String::from);
                    ResolvedSyscall {
                        site,
                        syscall_number: Some(number),
                        syscall_name: name,
                        resolution: Resolution::Resolved,
                    }
                }
                None => ResolvedSyscall {
                    site,
                    syscall_number: None,
                    syscall_name: None,
                    resolution: Resolution::Unresolved,
                },
            }
        })
        .collect()
}

/// Attempt to determine the value loaded into RAX before a syscall instruction.
///
/// Since the x86-64 decoder only decodes forward, we decode from a window
/// before the syscall offset, build a list of instructions, then walk
/// backward to find the most recent RAX/EAX assignment.
fn backward_slice_rax(code_bytes: &[u8], section_vaddr: u64, syscall_offset: u64) -> Option<u64> {
    use crate::inspector::decoder::x86;

    // Determine the decode window: start from up to MAX_BACKWARD_BYTES before the syscall
    let window_start_offset = syscall_offset.saturating_sub(MAX_BACKWARD_BYTES) as usize;
    let window_end_offset = syscall_offset as usize; // decode up to (not including) the syscall

    if window_start_offset >= code_bytes.len() || window_end_offset > code_bytes.len() {
        return None;
    }

    let window = &code_bytes[window_start_offset..window_end_offset];
    if window.is_empty() {
        return None;
    }

    let window_vaddr = section_vaddr + window_start_offset as u64;
    let instructions = x86::decode_region(window, window_vaddr);

    // Walk backward through instructions, looking for RAX/EAX writes
    let mut tracker = x86::RegWriteTracker::new();
    let scan_limit = instructions.len().min(MAX_BACKWARD_SCAN);
    for instr in instructions.iter().rev().take(scan_limit) {
        if let Some(value) = instr.rax_constant_write() {
            return Some(value);
        }

        // If we hit a control flow instruction (call, jmp, ret), stop scanning.
        // The RAX value could come from a different basic block.
        if instr.is_control_flow() {
            return None;
        }

        // If the instruction writes to RAX/EAX/AX/AL/AH (explicit or implicit)
        // and wasn't resolved by rax_constant_write, we can't safely resolve.
        if instr.writes_rax(&mut tracker) {
            return None;
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resolve_mov_eax_write_syscall() {
        // mov eax, 1 (write); syscall
        let code: &[u8] = &[
            0xB8, 0x01, 0x00, 0x00, 0x00, // mov eax, 1
            0x0F, 0x05, // syscall
        ];
        let results = resolve_syscalls(code, 0x1000);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].syscall_number, Some(1));
        assert_eq!(results[0].syscall_name.as_deref(), Some("write"));
        assert_eq!(results[0].resolution, Resolution::Resolved);
    }

    #[test]
    fn test_resolve_mov_rax_execve_syscall() {
        // mov rax, 59 (execve); syscall
        let code: &[u8] = &[
            0x48, 0xC7, 0xC0, 0x3B, 0x00, 0x00, 0x00, // mov rax, 59
            0x0F, 0x05, // syscall
        ];
        let results = resolve_syscalls(code, 0x2000);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].syscall_number, Some(59));
        assert_eq!(results[0].syscall_name.as_deref(), Some("execve"));
        assert_eq!(results[0].resolution, Resolution::Resolved);
    }

    #[test]
    fn test_resolve_xor_eax_eax_read_syscall() {
        // xor eax, eax (rax=0 = read); syscall
        let code: &[u8] = &[
            0x31, 0xC0, // xor eax, eax
            0x0F, 0x05, // syscall
        ];
        let results = resolve_syscalls(code, 0x3000);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].syscall_number, Some(0));
        assert_eq!(results[0].syscall_name.as_deref(), Some("read"));
        assert_eq!(results[0].resolution, Resolution::Resolved);
    }

    #[test]
    fn test_resolve_unresolved_no_rax_set() {
        // nop; nop; syscall (no RAX assignment visible)
        let code: &[u8] = &[
            0x90, 0x90, // nop; nop
            0x0F, 0x05, // syscall
        ];
        let results = resolve_syscalls(code, 0x4000);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].syscall_number, None);
        assert_eq!(results[0].syscall_name, None);
        assert_eq!(results[0].resolution, Resolution::Unresolved);
    }

    #[test]
    fn test_resolve_multiple_syscalls() {
        // mov eax, 1; syscall; mov eax, 60; syscall
        let code: &[u8] = &[
            0xB8, 0x01, 0x00, 0x00, 0x00, // mov eax, 1 (write)
            0x0F, 0x05, // syscall
            0xB8, 0x3C, 0x00, 0x00, 0x00, // mov eax, 60 (exit)
            0x0F, 0x05, // syscall
        ];
        let results = resolve_syscalls(code, 0x5000);
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].syscall_number, Some(1));
        assert_eq!(results[0].syscall_name.as_deref(), Some("write"));
        assert_eq!(results[1].syscall_number, Some(60));
        assert_eq!(results[1].syscall_name.as_deref(), Some("exit"));
    }

    #[test]
    fn test_resolve_unknown_syscall_number() {
        // mov eax, 9999; syscall (unknown syscall number)
        let code: &[u8] = &[
            0xB8, 0x0F, 0x27, 0x00, 0x00, // mov eax, 9999
            0x0F, 0x05, // syscall
        ];
        let results = resolve_syscalls(code, 0x6000);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].syscall_number, Some(9999));
        assert_eq!(results[0].syscall_name, None); // unknown number
        assert_eq!(results[0].resolution, Resolution::Resolved);
    }

    #[test]
    fn test_resolve_syscall_at_code_start() {
        // syscall right at the start (no preceding instructions)
        let code: &[u8] = &[0x0F, 0x05]; // syscall
        let results = resolve_syscalls(code, 0x7000);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].resolution, Resolution::Unresolved);
    }

    #[test]
    fn test_resolve_mov_eax_exit_group() {
        // mov eax, 231 (exit_group); syscall
        let code: &[u8] = &[
            0xB8, 0xE7, 0x00, 0x00, 0x00, // mov eax, 231
            0x0F, 0x05, // syscall
        ];
        let results = resolve_syscalls(code, 0x8000);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].syscall_number, Some(231));
        assert_eq!(results[0].syscall_name.as_deref(), Some("exit_group"));
    }

    #[test]
    fn test_resolve_rax_set_through_intervening_instructions() {
        // mov rax, 59; mov rdi, 0; mov rsi, 0; mov rdx, 0; syscall
        // The RAX assignment should still be found through intervening instructions
        let code: &[u8] = &[
            0x48, 0xC7, 0xC0, 0x3B, 0x00, 0x00, 0x00, // mov rax, 59
            0x48, 0xC7, 0xC7, 0x00, 0x00, 0x00, 0x00, // mov rdi, 0
            0x48, 0xC7, 0xC6, 0x00, 0x00, 0x00, 0x00, // mov rsi, 0
            0x48, 0xC7, 0xC2, 0x00, 0x00, 0x00, 0x00, // mov rdx, 0
            0x0F, 0x05, // syscall
        ];
        let results = resolve_syscalls(code, 0x9000);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].syscall_number, Some(59));
        assert_eq!(results[0].syscall_name.as_deref(), Some("execve"));
    }

    #[test]
    fn test_resolve_call_before_syscall_blocks_resolution() {
        // call <somewhere>; syscall
        // The call means RAX could be anything (function return value)
        let code: &[u8] = &[
            0xB8, 0x01, 0x00, 0x00, 0x00, // mov eax, 1
            0xE8, 0x00, 0x00, 0x00, 0x00, // call +0 (to next instruction)
            0x0F, 0x05, // syscall
        ];
        let results = resolve_syscalls(code, 0xA000);
        assert_eq!(results.len(), 1);
        // The call breaks the backward chain
        assert_eq!(results[0].resolution, Resolution::Unresolved);
    }

    #[test]
    fn test_resolve_empty_code() {
        let results = resolve_syscalls(&[], 0xB000);
        assert!(results.is_empty());
    }

    #[test]
    fn test_resolve_openat_syscall() {
        // mov eax, 257 (openat); syscall
        let code: &[u8] = &[
            0xB8, 0x01, 0x01, 0x00, 0x00, // mov eax, 257
            0x0F, 0x05, // syscall
        ];
        let results = resolve_syscalls(code, 0xC000);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].syscall_number, Some(257));
        assert_eq!(results[0].syscall_name.as_deref(), Some("openat"));
    }

    #[test]
    fn test_resolve_realistic_function() {
        // A realistic function pattern:
        // push rbp; mov rbp, rsp; sub rsp, 0x20;
        // mov rdi, [rbp-8]; mov rsi, [rbp-16]; mov rdx, [rbp-24];
        // mov eax, 1; syscall;
        // leave; ret
        let code: &[u8] = &[
            0x55, // push rbp
            0x48, 0x89, 0xE5, // mov rbp, rsp
            0x48, 0x83, 0xEC, 0x20, // sub rsp, 0x20
            0x48, 0x8B, 0x7D, 0xF8, // mov rdi, [rbp-8]
            0x48, 0x8B, 0x75, 0xF0, // mov rsi, [rbp-16]
            0x48, 0x8B, 0x55, 0xE8, // mov rdx, [rbp-24]
            0xB8, 0x01, 0x00, 0x00, 0x00, // mov eax, 1 (write)
            0x0F, 0x05, // syscall
            0xC9, // leave
            0xC3, // ret
        ];
        let results = resolve_syscalls(code, 0xD000);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].syscall_number, Some(1));
        assert_eq!(results[0].syscall_name.as_deref(), Some("write"));
        assert_eq!(results[0].resolution, Resolution::Resolved);
    }

    #[test]
    fn test_resolved_syscall_struct_fields() {
        let resolved = ResolvedSyscall {
            site: SyscallSite {
                address: 0x1000,
                offset_in_section: 0,
            },
            syscall_number: Some(59),
            syscall_name: Some("execve".to_string()),
            resolution: Resolution::Resolved,
        };
        assert_eq!(resolved.site.address, 0x1000);
        assert_eq!(resolved.syscall_number, Some(59));
        assert_eq!(resolved.syscall_name.as_deref(), Some("execve"));
        assert_eq!(resolved.resolution, Resolution::Resolved);
    }

    #[test]
    fn test_resolution_enum_equality() {
        assert_eq!(Resolution::Resolved, Resolution::Resolved);
        assert_eq!(Resolution::Unresolved, Resolution::Unresolved);
        assert_eq!(Resolution::Ambiguous, Resolution::Ambiguous);
        assert_ne!(Resolution::Resolved, Resolution::Unresolved);
    }

    #[test]
    fn test_resolve_mov_rax_imm64_large_number() {
        // mov rax, 0x00000000000001FF (511 — not a real syscall but tests imm64 path)
        let code: &[u8] = &[
            0x48, 0xB8, 0xFF, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, 511
            0x0F, 0x05, // syscall
        ];
        let results = resolve_syscalls(code, 0xE000);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].syscall_number, Some(511));
        assert_eq!(results[0].resolution, Resolution::Resolved);
    }

    #[test]
    fn test_resolve_mov_al_partial_write_unresolved() {
        // mov eax, 0; mov al, 59; syscall
        // Should NOT resolve to 0 (read), but fall back to Unresolved (unknown)
        let code: &[u8] = &[
            0xB8, 0x00, 0x00, 0x00, 0x00, // mov eax, 0
            0xB0, 0x3B, // mov al, 59 (0x3B)
            0x0F, 0x05, // syscall
        ];
        let results = resolve_syscalls(code, 0x2000);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].syscall_number, None);
        assert_eq!(results[0].resolution, Resolution::Unresolved);
    }

    #[test]
    fn test_resolve_xchg_overwrites_rax() {
        // mov eax, 0; mov ebx, 59; xchg ebx, eax; syscall
        let code: &[u8] = &[
            0xB8, 0x00, 0x00, 0x00, 0x00, // mov eax, 0
            0xBB, 0x3B, 0x00, 0x00, 0x00, // mov ebx, 59
            0x87, 0xD8, // xchg eax, ebx
            0x0F, 0x05, // syscall
        ];
        let results = resolve_syscalls(code, 0x3000);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].syscall_number, None);
        assert_eq!(results[0].resolution, Resolution::Unresolved);
    }

    #[test]
    fn test_s14_xadd_overwrites_rax() {
        // mov eax, 0; mov ecx, 59; xadd ecx, eax; syscall
        // XADD modifies its second operand (EAX), so EAX becomes 59 (not 0).
        let code: &[u8] = &[
            0xB8, 0x00, 0x00, 0x00, 0x00, // mov eax, 0
            0xB9, 0x3B, 0x00, 0x00, 0x00, // mov ecx, 59
            0x0F, 0xC1, 0xC1, // xadd ecx, eax
            0x0F, 0x05, // syscall
        ];
        let results = resolve_syscalls(code, 0x4000);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].syscall_number, None);
        assert_eq!(results[0].resolution, Resolution::Unresolved);
    }
}
