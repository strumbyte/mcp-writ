mod darwin_syscalls;
mod decoder;
pub mod disasm;
pub mod elf_parser;
mod macho_parser;
pub mod profile;
pub mod slicer;
pub mod strings;
pub mod syscall_table;
pub mod target;
mod text_section;

/// Aggregate bound on a file submitted for static analysis. Whole
/// binaries are materialized for parsing and derived collections
/// (extracted strings, findings, code regions) scale with input size,
/// so an attacker-sized or sparse artifact is refused at the entry
/// point rather than exhausting analyzer memory mid-parse.
pub const MAX_ANALYZED_FILE_BYTES: u64 = 512 * 1024 * 1024;
