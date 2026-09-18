use std::path::Path;

/// Returns `true` when the file at `path` starts with the ELF magic
/// bytes (`\x7fELF`). Non-existent files, files shorter than 4 bytes,
/// and non-ELF files all return `false` (never an error).
pub fn looks_like_elf(path: &Path) -> bool {
    use std::io::Read;
    let Ok(file) = std::fs::File::open(path) else {
        return false;
    };
    let mut buf = [0u8; 4];
    let mut reader = std::io::BufReader::new(file);
    if reader.read_exact(&mut buf).is_err() {
        return false;
    }
    buf == [0x7f, b'E', b'L', b'F']
}
