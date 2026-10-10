use std::collections::HashSet;
use std::sync::LazyLock;

use crate::error::InspectorError;
use crate::inspector::text_section;
use regex_lite::Regex;

/// Findings from string analysis of a binary.
#[derive(Debug, Clone, Default)]
pub struct StringFindings {
    pub urls: Vec<String>,
    pub paths: Vec<String>,
    pub env_vars: Vec<String>,
    /// A resource bound cut the extraction or the findings off — the
    /// collections are a subset, never the complete picture.
    pub truncated: bool,
}

/// Extract URL, path, and environment variable strings from ELF binary bytes.
///
/// Reads `.rodata` and `.data` sections via goblin, extracts NULL-terminated
/// and UTF-8 strings (minimum 4 bytes), then classifies them using regex patterns.
pub fn extract_strings(elf_bytes: &[u8]) -> Result<StringFindings, InspectorError> {
    let elf = goblin::elf::Elf::parse(elf_bytes)
        .map_err(|e| InspectorError::ParseError(format!("{e}")))?;

    let (raw_strings, input_truncated) = extract_raw_strings_from_sections(elf_bytes, &elf);
    Ok(classify_strings(&raw_strings, input_truncated))
}

/// Section names that contain interesting string data.
const STRING_SECTIONS: &[&str] = &[".rodata", ".data"];

/// Aggregate bound on raw strings handed to classification — an
/// attacker-sized section set cannot grow the retained collection
/// without limit.
pub(crate) const MAX_RAW_STRINGS: usize = 300_000;

/// Per-buffer bound on collected strings.
const MAX_STRINGS_PER_BUFFER: usize = 100_000;

/// Bound on one extracted string — a run of printable bytes is cut at
/// this length so a hostile section cannot grow a single "string" to
/// section size.
const MAX_STRING_BYTES: usize = 8 * 1024;

/// Bound on retained findings per kind.
const MAX_FINDINGS_PER_KIND: usize = 20_000;

/// Extract raw strings from relevant ELF sections.
///
/// Returns the strings plus whether an aggregate bound cut the walk
/// short — the caller must not report a truncated collection as a
/// complete analysis.
fn extract_raw_strings_from_sections(
    data: &[u8],
    elf: &goblin::elf::Elf<'_>,
) -> (Vec<String>, bool) {
    let mut all_strings = Vec::new();
    let mut truncated = false;

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
        let (extracted, buf_truncated) = extract_strings_from_bytes(section_data);
        truncated |= buf_truncated;
        let remaining = MAX_RAW_STRINGS.saturating_sub(all_strings.len());
        if extracted.len() > remaining {
            all_strings.extend(extracted.into_iter().take(remaining));
            truncated = true;
        } else {
            all_strings.extend(extracted);
        }
        if all_strings.len() >= MAX_RAW_STRINGS {
            truncated = true;
            break;
        }
    }

    (all_strings, truncated)
}

/// Minimum string length for extraction.
const MIN_STRING_LEN: usize = 4;

/// Extract NULL-terminated printable strings from a byte slice.
///
/// Returns the strings plus whether a per-buffer bound cut the walk
/// short — `MAX_STRINGS_PER_BUFFER` on the collection or
/// `MAX_STRING_BYTES` on one run — so callers combine it with their
/// aggregate-limit state and never report a subset as a complete
/// analysis.
pub fn extract_strings_from_bytes(data: &[u8]) -> (Vec<String>, bool) {
    fn flush(
        results: &mut Vec<String>,
        current: &mut Vec<u8>,
        run_capped: &mut bool,
        truncated: &mut bool,
    ) {
        if current.len() >= MIN_STRING_LEN {
            if results.len() < MAX_STRINGS_PER_BUFFER {
                // A byte-capped run can end mid UTF-8 sequence — back up
                // to the last valid boundary and keep the prefix rather
                // than dropping the whole string.
                let bytes = match std::str::from_utf8(current) {
                    Ok(_) => &current[..],
                    Err(e) => &current[..e.valid_up_to()],
                };
                if bytes.len() >= MIN_STRING_LEN
                    && let Ok(s) = std::str::from_utf8(bytes)
                {
                    results.push(s.to_string());
                }
            } else {
                *truncated = true;
            }
        }
        if *run_capped {
            *truncated = true;
            *run_capped = false;
        }
        current.clear();
    }

    let mut results = Vec::new();
    let mut truncated = false;
    let mut run_capped = false;
    let mut current = Vec::new();

    for &byte in data {
        if results.len() >= MAX_STRINGS_PER_BUFFER {
            truncated = true;
            break;
        }
        if byte == 0 {
            flush(&mut results, &mut current, &mut run_capped, &mut truncated);
        } else if byte.is_ascii_graphic() || byte == b' ' || byte >= 0x80 {
            // Graphic ASCII, space, and potential UTF-8 multi-byte lead/
            // continuation bytes accumulate; the run itself is bounded.
            if current.len() < MAX_STRING_BYTES {
                current.push(byte);
            } else {
                // A byte past MAX_STRING_BYTES is ignored until the run ends.
                run_capped = true;
            }
        } else {
            // Non-printable ASCII control character — end the current string.
            flush(&mut results, &mut current, &mut run_capped, &mut truncated);
        }
    }

    // Handle data that doesn't end with NULL.
    flush(&mut results, &mut current, &mut run_capped, &mut truncated);

    (results, truncated)
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
///
/// `input_truncated` records that the raw collection was already cut by
/// an aggregate bound; each findings vector is itself bounded at
/// `MAX_FINDINGS_PER_KIND` — either bound marks the result
/// `truncated` so consumers cannot read a subset as complete analysis.
pub fn classify_strings(raw: &[String], input_truncated: bool) -> StringFindings {
    let mut urls = Vec::new();
    let mut seen_urls = HashSet::new();
    let mut paths = Vec::new();
    let mut seen_paths = HashSet::new();
    let mut env_vars = Vec::new();
    let mut seen_env = HashSet::new();
    let mut truncated = input_truncated;

    for s in raw {
        if is_noise(s) {
            continue;
        }

        // URL extraction: find all URL patterns in the string.
        for m in URL_RE.find_iter(s) {
            let url_str = m.as_str();
            if !seen_urls.contains(url_str) {
                if urls.len() >= MAX_FINDINGS_PER_KIND {
                    truncated = true;
                    break;
                }
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
                    if paths.len() >= MAX_FINDINGS_PER_KIND {
                        truncated = true;
                        break;
                    }
                    let p_owned = p.to_string();
                    seen_paths.insert(p_owned.clone());
                    paths.push(p_owned);
                }
            }
        }

        // Environment variable name: must be the entire string.
        if ENV_RE.is_match(s) && !is_noise(s) && !seen_env.contains(s.as_str()) {
            if env_vars.len() >= MAX_FINDINGS_PER_KIND {
                truncated = true;
                continue;
            }
            let e = s.to_string();
            seen_env.insert(e.clone());
            env_vars.push(e);
        }
    }

    StringFindings {
        urls,
        paths,
        env_vars,
        truncated,
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
        let (strings, _) = extract_strings_from_bytes(data);
        let findings = classify_strings(&strings, false);

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
        let (strings, _) = extract_strings_from_bytes(data);
        let findings = classify_strings(&strings, false);

        assert_eq!(findings.paths.len(), 2);
        assert!(findings.paths.contains(&"/etc/passwd".to_string()));
        assert!(findings.paths.contains(&"/usr/local/bin/tool".to_string()));
    }

    #[test]
    fn test_extract_env_vars() {
        let data = b"HOME\0PATH\0AWS_SECRET_KEY\0TERM\0";
        let (strings, _) = extract_strings_from_bytes(data);
        let findings = classify_strings(&strings, false);

        assert!(findings.env_vars.contains(&"HOME".to_string()));
        assert!(findings.env_vars.contains(&"PATH".to_string()));
        assert!(findings.env_vars.contains(&"AWS_SECRET_KEY".to_string()));
        assert!(findings.env_vars.contains(&"TERM".to_string()));
    }

    #[test]
    fn test_deduplication() {
        let data = b"https://dup.com\0https://dup.com\0/etc/hosts\0/etc/hosts\0HOME\0HOME\0";
        let (strings, _) = extract_strings_from_bytes(data);
        let findings = classify_strings(&strings, false);

        assert_eq!(findings.urls.len(), 1);
        assert_eq!(findings.paths.len(), 1);
        assert_eq!(findings.env_vars.len(), 1);
    }

    #[test]
    fn test_noise_filter() {
        let data = b"__libc_start_main\0_GLOBAL_OFFSET_TABLE_\0.text\0.rodata\0";
        let (strings, _) = extract_strings_from_bytes(data);
        let findings = classify_strings(&strings, false);

        assert!(findings.urls.is_empty());
        assert!(findings.paths.is_empty());
        assert!(findings.env_vars.is_empty());
    }

    #[test]
    fn test_empty_data() {
        let data: &[u8] = b"";
        let (strings, _) = extract_strings_from_bytes(data);
        let findings = classify_strings(&strings, false);

        assert!(findings.urls.is_empty());
        assert!(findings.paths.is_empty());
        assert!(findings.env_vars.is_empty());
    }

    #[test]
    fn test_short_strings_filtered() {
        let data = b"ab\0cd\0long_enough\0";
        let (strings, _) = extract_strings_from_bytes(data);

        assert_eq!(strings.len(), 1);
        assert_eq!(strings[0], "long_enough");
    }

    #[test]
    fn test_url_path_not_double_extracted() {
        // A URL contains a path-like component; it should appear as URL only.
        let data = b"https://example.com/api/v1/resource\0";
        let (strings, _) = extract_strings_from_bytes(data);
        let findings = classify_strings(&strings, false);

        assert_eq!(findings.urls.len(), 1);
        assert!(findings.paths.is_empty());
    }

    #[test]
    fn test_mixed_content() {
        let data = b"https://api.example.com\0/var/log/syslog\0SECRET_KEY\0normal string\0";
        let (strings, _) = extract_strings_from_bytes(data);
        let findings = classify_strings(&strings, false);

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
        let (strings, _) = extract_strings_from_bytes(data);
        let findings = classify_strings(&strings, false);

        assert!(findings.env_vars.contains(&"LONG_ENV_VAR_NAME".to_string()));
    }

    #[test]
    fn test_section_names_excluded() {
        let data = b".debug_info\0.eh_frame_hdr\0.gnu.hash\0.plt.got\0";
        let (strings, _) = extract_strings_from_bytes(data);
        let findings = classify_strings(&strings, false);

        assert!(findings.paths.is_empty());
        assert!(findings.env_vars.is_empty());
    }

    // ---------------------------------------------------------------
    // Aggregate resource bounds (attacker-sized inputs)
    // ---------------------------------------------------------------

    #[test]
    fn test_string_run_capped_at_max_bytes() {
        // A single unterminated run of printable bytes is cut at
        // MAX_STRING_BYTES — a hostile section cannot grow one "string"
        // to section size.
        let data = vec![b'A'; MAX_STRING_BYTES + 4096];
        let (strings, truncated) = extract_strings_from_bytes(&data);
        assert_eq!(strings.len(), 1);
        assert_eq!(strings[0].len(), MAX_STRING_BYTES);
        assert!(truncated, "a byte-capped run must report truncation");
    }

    #[test]
    fn test_utf8_boundary_split_keeps_valid_prefix() {
        // A multibyte character straddling MAX_STRING_BYTES must not
        // discard the string — the run backs up to the last complete
        // sequence and reports the truncation.
        let mut data = vec![b'a'; MAX_STRING_BYTES - 1];
        data.extend_from_slice("é".as_bytes()); // 2-byte char split by the cap
        data.extend_from_slice(&[b'b'; 16]);
        data.push(0);
        let (strings, truncated) = extract_strings_from_bytes(&data);
        assert_eq!(strings.len(), 1);
        assert_eq!(strings[0].len(), MAX_STRING_BYTES - 1);
        assert!(strings[0].bytes().all(|b| b == b'a'));
        assert!(truncated);
    }

    #[test]
    fn test_strings_per_buffer_capped() {
        let mut data = Vec::new();
        for _ in 0..MAX_STRINGS_PER_BUFFER + 10 {
            data.extend_from_slice(b"abcd\0");
        }
        let (strings, truncated) = extract_strings_from_bytes(&data);
        assert_eq!(strings.len(), MAX_STRINGS_PER_BUFFER);
        assert!(truncated, "a count-capped buffer must report truncation");
    }

    #[test]
    fn test_findings_cap_sets_truncated() {
        let raw: Vec<String> = (0..MAX_FINDINGS_PER_KIND + 5)
            .map(|i| format!("ENVVAR_{i}"))
            .collect();
        let findings = classify_strings(&raw, false);
        assert_eq!(findings.env_vars.len(), MAX_FINDINGS_PER_KIND);
        assert!(findings.truncated);
    }

    #[test]
    fn test_input_truncated_flag_propagates() {
        let findings = classify_strings(&["/etc/passwd".to_string()], true);
        assert!(findings.truncated);
        assert_eq!(findings.paths.len(), 1);
    }

    #[test]
    fn test_normal_input_not_truncated() {
        let data = b"HOME\0";
        let (strings, _) = extract_strings_from_bytes(data);
        let findings = classify_strings(&strings, false);
        assert!(!findings.truncated);
    }
}
