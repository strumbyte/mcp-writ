# Managed AArch64 ELF fixture for Inspector baselines (runbook P5).
# Target ABI: Linux AArch64 (syscall entry `svc #0`, number in x8/w8).
# Static analysis only; tests never execute it.
#
# Build (Windows, LLVM toolchain):
#   clang --target=aarch64-linux-gnu -c aarch64_linux_syscalls.s -o aarch64_linux_syscalls.o
#   ld.lld -o aarch64_linux_syscalls.elf aarch64_linux_syscalls.o
#
# Instruction layout is deterministic: each syscall site below documents the
# expected resolution result of inspector::slicer::resolve_syscalls_aarch64.
    .text
    .globl _start
_start:
    # site A: resolved -> write (64) via w8 write; 32-bit writes zero-extend
    mov w8, #64
    svc #0
    # site B: resolved -> openat (56) — aarch64 numbering, not x86's 257
    mov w8, #56
    svc #0
    # site C: resolved -> execve (221) via x8 write
    mov x8, #221
    svc #0
    # site D: movn w8, #0 -> w8 = 0xFFFFFFFF; resolved number with no name
    movn w8, #0
    svc #0
    # site E: movz+movk completes a 64-bit constant -> resolved 0x12340001
    movz x8, #1
    movk x8, #0x1234, lsl #16
    svc #0
    # site F: lone movk is a partial write -> unresolved
    movk w8, #5
    svc #0
    # site G: no x8 write in the backward window -> unresolved
    nop
    nop
    svc #0
    # site H: a call breaks the backward chain -> unresolved
    mov w8, #1
    bl 1f
1:
    svc #0
    # site I: resolved -> exit_group (94)
    mov w8, #94
    svc #0
    # site J: resolved -> exit (93)
    mov w8, #93
    svc #0
    # site K: nonzero SVC immediate — under the Linux ABI it still dispatches
    # on x8 (the imm is auxiliary info, kept to distinguish nonstandard forms)
    mov w8, #64
    svc #0x80
    # site L: conditional write -> unresolved
    mov w8, #0
    csel w8, w9, w10, eq
    svc #0
    # site M: memory-derived value -> unresolved
    ldr w8, [x0]
    svc #0
    # site N: return breaks the backward chain -> unresolved
    ret
    svc #0

    .section .rodata
    .asciz "https://fixtures.invalid/mcp-writ/p5-baseline"
    .asciz "/etc/mcp-writ-fixture.conf"
    .asciz "MCP_WRIT_FIXTURE_ENV"
