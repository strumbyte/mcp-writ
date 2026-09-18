use crate::error::InspectorError;

/// Locate the .text section in an ELF binary.
/// Returns (sh_offset, sh_size, sh_addr) if found.
pub(crate) fn find_text_section(elf: &goblin::elf::Elf<'_>) -> Option<(u64, u64, u64)> {
    for sh in &elf.section_headers {
        let name = elf.shdr_strtab.get_at(sh.sh_name);
        if name == Some(".text") {
            return Some((sh.sh_offset, sh.sh_size, sh.sh_addr));
        }
    }
    None
}

/// Bounds-check a section's file range and return its bytes.
pub(crate) fn section_bytes(
    elf_bytes: &[u8],
    sh_offset: u64,
    sh_size: u64,
) -> Result<&[u8], InspectorError> {
    let start = usize::try_from(sh_offset)
        .map_err(|_| InspectorError::ParseError("section size overflow".to_string()))?;
    let size = usize::try_from(sh_size)
        .map_err(|_| InspectorError::ParseError("section size overflow".to_string()))?;
    let end = start
        .checked_add(size)
        .ok_or_else(|| InspectorError::ParseError("section size overflow".to_string()))?;
    if end > elf_bytes.len() {
        return Err(InspectorError::ParseError(
            "section extends beyond file boundary".to_string(),
        ));
    }
    Ok(&elf_bytes[start..end])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_section_bytes_valid() {
        let data = [0xAAu8; 16];
        let slice = section_bytes(&data, 4, 8).expect("in-bounds range");
        assert_eq!(slice.len(), 8);
        assert_eq!(slice, &data[4..12]);
    }

    #[test]
    fn test_section_bytes_empty_at_end() {
        let data = [0u8; 16];
        let slice = section_bytes(&data, 16, 0).expect("empty slice at end");
        assert!(slice.is_empty());
    }

    #[test]
    fn test_section_bytes_out_of_bounds() {
        let data = [0u8; 16];
        let err = section_bytes(&data, 8, 16).expect_err("range exceeds file");
        assert!(matches!(err, InspectorError::ParseError(_)));
        assert!(section_bytes(&data, 17, 0).is_err());
    }

    #[test]
    fn test_section_bytes_overflow() {
        let data = [0u8; 16];
        assert!(section_bytes(&data, u64::MAX - 4, 16).is_err());
        assert!(section_bytes(&data, u64::MAX, 1).is_err());
        assert!(section_bytes(&data, 8, u64::MAX).is_err());
    }
}
