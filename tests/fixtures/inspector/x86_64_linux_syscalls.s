# Managed x86-64 ELF fixture for Inspector baselines (runbook P0).
# Target ABI: Linux x86-64 (SYSV). Static analysis only; tests never execute it.
#
# Build (Windows, LLVM toolchain):
#   clang --target=x86_64-pc-linux-gnu -c x86_64_linux_syscalls.s -o x86_64_linux_syscalls.o
#   ld.lld -o x86_64_linux_syscalls.elf x86_64_linux_syscalls.o
#
# Instruction layout is deterministic: each syscall site below documents the
# expected resolution result of inspector::slicer::resolve_syscalls.
    .intel_syntax noprefix
    .text
    .globl _start
_start:
    # site A: resolved -> write (1)
    mov eax, 1
    syscall
    # site B: resolved -> openat (257)
    mov eax, 257
    syscall
    # site C: resolved -> execve (59) via mov r/m64, imm32 sign-extended
    mov rax, 59
    syscall
    # site D: resolved -> read (0) via xor eax, eax
    xor eax, eax
    syscall
    # site E: resolved number 9999, not present in the syscall table
    mov eax, 9999
    syscall
    # site F: unresolved -> partial register write (mov al) must not keep eax=0
    mov eax, 0
    mov al, 59
    syscall
    # site G: unresolved -> no rax assignment in the backward window
    nop
    nop
    syscall
    # site H: unresolved -> control flow (call) breaks the backward chain
    mov eax, 1
    call 1f
1:
    syscall
    # site I: resolved -> exit_group (231)
    mov eax, 231
    syscall
    # site J: resolved -> exit (60)
    mov eax, 60
    syscall

    .section .rodata
    .asciz "https://fixtures.invalid/mcp-writ/p0-baseline"
    .asciz "/etc/mcp-writ-fixture.conf"
    .asciz "MCP_WRIT_FIXTURE_ENV"
