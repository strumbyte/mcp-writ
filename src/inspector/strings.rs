use std::collections::HashSet;
use std::sync::LazyLock;

use crate::error::InspectorError;
use crate::inspector::text_section;
use regex_lite::Regex;

/// Findings from string analysis of an ELF binary.
#[derive(Debug, Clone, Default)]
pub struct StringFindings {
    pub urls: Vec<String>,
    pub paths: Vec<String>,
    pub env_vars: Vec<String>,
}

/// Extract URL, path, and environment variable strings from ELF binary bytes.
///
/// Reads `.rodata` and `.data` sections via goblin, extracts NULL-terminated
/// and UTF-8 strings (minimum 4 bytes), then classifies them using regex patterns.
pub fn extract_strings(elf_bytes: &[u8]) -> Result<StringFindings, InspectorError> {
    let elf = goblin::elf::Elf::parse(elf_bytes)
        .map_err(|e| InspectorError::ParseError(format!("{e}")))?;

    let raw_strings = extract_raw_strings_from_sections(elf_bytes, &elf);
    Ok(classify_strings(&raw_strings))
}

/// Section names that contain interesting string data.
const STRING_SECTIONS: &[&str] = &[".rodata", ".data"];

/// Extract raw strings from relevant ELF sections.
fn extract_raw_strings_from_sections(data: &[u8], elf: &goblin::elf::Elf<'_>) -> Vec<String> {
    let mut all_strings = Vec::new();

    for section in &elf.section_headers {
        let name = match elf.shdr_strtab.get_at(section.sh_name) {
            Some(n) => n,
            None => continue,
        };

        if !STRING_SECTIONS.contains(&name) {
            continue;
        }

        let offset = section.sh_offset;
        let size = section.sh_size;
        let Ok(section_data) = text_section::section_bytes(data, offset, size) else {
            continue;
        };
        let extracted = extract_strings_from_bytes(section_data);
        all_strings.extend(extracted);
    }

    all_strings
}

/// Minimum string length for extraction.
const MIN_STRING_LEN: usize = 4;

/// Extract NULL-terminated printable strings from a byte slice.
pub fn extract_strings_from_bytes(data: &[u8]) -> Vec<String> {
    let mut results = Vec::new();
    let mut current = Vec::new();

    for &byte in data {
        if byte == 0 {
            if current.len() >= MIN_STRING_LEN
                && let Ok(s) = std::str::from_utf8(&current)
            {
                results.push(s.to_string());
            }
            current.clear();
        } else if byte.is_ascii_graphic() || byte == b' ' {
            current.push(byte);
        } else if byte >= 0x80 {
            // Potential UTF-8 multi-byte: accumulate for later validation.
            current.push(byte);
        } else {
            // Non-printable ASCII control character — end the current string.
            if current.len() >= MIN_STRING_LEN
                && let Ok(s) = std::str::from_utf8(&current)
            {
                results.push(s.to_string());
            }
            current.clear();
        }
    }

    // Handle data that doesn't end with NULL.
    if current.len() >= MIN_STRING_LEN
        && let Ok(s) = std::str::from_utf8(&current)
    {
        results.push(s.to_string());
    }

    results
}

/// Compiler / linker artifact prefixes to filter out.
const NOISE_PREFIXES: &[&str] = &[
    "__libc_",
    "_GLOBAL_OFFSET_TABLE_",
    "_ITM_",
    "_Jv_",
    "__gmon_",
    "__cxa_",
    "__gcc_",
    "__gnu_",
    "__stack_chk",
    "__do_global",
    "__libc_csu",
    "_DYNAMIC",
    "_PROCEDURE_LINKAGE_TABLE_",
    "GCC_",
    ".text",
    ".data",
    ".bss",
    ".rodata",
    ".symtab",
    ".strtab",
    ".shstrtab",
    ".rel.",
    ".rela.",
    ".plt",
    ".got",
    ".init",
    ".fini",
    ".comment",
    ".note",
    ".debug_",
    ".eh_frame",
    ".dynstr",
    ".dynsym",
    ".interp",
    ".hash",
    ".gnu.",
];

static URL_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"https?://[^\s"'\x00]+"#).expect("valid regex"));
static PATH_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"/[a-zA-Z0-9._/-]+").expect("valid regex"));
static ENV_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[A-Z][A-Z0-9_]{2,}$").expect("valid regex"));

/// Classify extracted strings into URLs, paths, and environment variable names.
pub fn classify_strings(raw: &[String]) -> StringFindings {
    let mut urls = Vec::new();
    let mut seen_urls = HashSet::new();
    let mut paths = Vec::new();
    let mut seen_paths = HashSet::new();
    let mut env_vars = Vec::new();
    let mut seen_env = HashSet::new();

    for s in raw {
        if is_noise(s) {
            continue;
        }

        // URL extraction: find all URL patterns in the string.
        for m in URL_RE.find_iter(s) {
            let url_str = m.as_str();
            if !seen_urls.contains(url_str) {
                let url = url_str.to_string();
                seen_urls.insert(url.clone());
                urls.push(url);
            }
        }

        // Path extraction: only if NOT a URL (avoid extracting path part of URLs).
        if !URL_RE.is_match(s) {
            for m in PATH_RE.find_iter(s) {
                let p = m.as_str();
                if p.len() >= 3 && !is_noise(p) && !seen_paths.contains(p) {
                    let p_owned = p.to_string();
                    seen_paths.insert(p_owned.clone());
                    paths.push(p_owned);
                }
            }
        }

        // Environment variable name: must be the entire string.
        if ENV_RE.is_match(s) && !is_noise(s) && !seen_env.contains(s.as_str()) {
            let e = s.to_string();
            seen_env.insert(e.clone());
            env_vars.push(e);
        }
    }

    StringFindings {
        urls,
        paths,
        env_vars,
    }
}

/// Check whether a string is compiler/linker noise.
fn is_noise(s: &str) -> bool {
    if s.len() < 3 {
        return true;
    }
    for prefix in NOISE_PREFIXES {
        if s.starts_with(prefix) {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---------------------------------------------------------------
    // extract_strings_from_bytes tests (pure function, no ELF needed)
    // ---------------------------------------------------------------

    #[test]
    fn test_extract_urls() {
        let data = b"https://example.com\0http://evil.org/payload\0abc\0";
        let strings = extract_strings_from_bytes(data);
        let findings = classify_strings(&strings);

        assert_eq!(findings.urls.len(), 2);
        assert!(findings.urls.contains(&"https://example.com".to_string()));
        assert!(
            findings
                .urls
                .contains(&"http://evil.org/payload".to_string())
        );
    }

    #[test]
    fn test_extract_paths() {
        let data = b"/etc/passwd\0/usr/local/bin/tool\0short\0";
        let strings = extract_strings_from_bytes(data);
        let findings = classify_strings(&strings);

        assert_eq!(findings.paths.len(), 2);
        assert!(findings.paths.contains(&"/etc/passwd".to_string()));
        assert!(findings.paths.contains(&"/usr/local/bin/tool".to_string()));
    }

    #[test]
    fn test_extract_env_vars() {
        let data = b"HOME\0PATH\0AWS_SECRET_KEY\0TERM\0";
        let strings = extract_strings_from_bytes(data);
        let findings = classify_strings(&strings);

        assert!(findings.env_vars.contains(&"HOME".to_string()));
        assert!(findings.env_vars.contains(&"PATH".to_string()));
        assert!(findings.env_vars.contains(&"AWS_SECRET_KEY".to_string()));
        assert!(findings.env_vars.contains(&"TERM".to_string()));
    }

    #[test]
    fn test_deduplication() {
        let data = b"https://dup.com\0https://dup.com\0/etc/hosts\0/etc/hosts\0HOME\0HOME\0";
        let strings = extract_strings_from_bytes(data);
        let findings = classify_strings(&strings);

        assert_eq!(findings.urls.len(), 1);
        assert_eq!(findings.paths.len(), 1);
        assert_eq!(findings.env_vars.len(), 1);
    }

    #[test]
    fn test_noise_filter() {
        let data = b"__libc_start_main\0_GLOBAL_OFFSET_TABLE_\0.text\0.rodata\0";
        let strings = extract_strings_from_bytes(data);
        let findings = classify_strings(&strings);

        assert!(findings.urls.is_empty());
        assert!(findings.paths.is_empty());
        assert!(findings.env_vars.is_empty());
    }

    #[test]
    fn test_empty_data() {
        let data: &[u8] = b"";
        let strings = extract_strings_from_bytes(data);
        let findings = classify_strings(&strings);

        assert!(findings.urls.is_empty());
        assert!(findings.paths.is_empty());
        assert!(findings.env_vars.is_empty());
    }

    #[test]
    fn test_short_strings_filtered() {
        let data = b"ab\0cd\0long_enough\0";
        let strings = extract_strings_from_bytes(data);

        assert_eq!(strings.len(), 1);
        assert_eq!(strings[0], "long_enough");
    }

    #[test]
    fn test_url_path_not_double_extracted() {
        // A URL contains a path-like component; it should appear as URL only.
        let data = b"https://example.com/api/v1/resource\0";
        let strings = extract_strings_from_bytes(data);
        let findings = classify_strings(&strings);

        assert_eq!(findings.urls.len(), 1);
        assert!(findings.paths.is_empty());
    }

    #[test]
    fn test_mixed_content() {
        let data = b"https://api.example.com\0/var/log/syslog\0SECRET_KEY\0normal string\0";
        let strings = extract_strings_from_bytes(data);
        let findings = classify_strings(&strings);

        assert_eq!(findings.urls.len(), 1);
        assert_eq!(findings.paths.len(), 1);
        assert_eq!(findings.env_vars.len(), 1);
        assert_eq!(findings.urls[0], "https://api.example.com");
        assert_eq!(findings.paths[0], "/var/log/syslog");
        assert_eq!(findings.env_vars[0], "SECRET_KEY");
    }

    #[test]
    fn test_non_null_terminated() {
        let data = b"LONG_ENV_VAR_NAME";
        let strings = extract_strings_from_bytes(data);
        let findings = classify_strings(&strings);

        assert!(findings.env_vars.contains(&"LONG_ENV_VAR_NAME".to_string()));
    }

    #[test]
    fn test_section_names_excluded() {
        let data = b".debug_info\0.eh_frame_hdr\0.gnu.hash\0.plt.got\0";
        let strings = extract_strings_from_bytes(data);
        let findings = classify_strings(&strings);

        assert!(findings.paths.is_empty());
        assert!(findings.env_vars.is_empty());
    }
}
