//! UTF-16 environment block encoding for `CreateProcessW`.
//!
//! Windows takes the child environment as a double-NUL-terminated UTF-16
//! block sorted by a case-insensitive ordinal comparison. Pair selection
//! (restricted vs inherited) is delegated to [`super::env::spawn_env_pairs`];
//! this module only encodes.

use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;

use windows::Win32::Globalization::{
    CSTR_EQUAL, CSTR_GREATER_THAN, CSTR_LESS_THAN, CompareStringOrdinal,
};

use super::SpawnOptions;

pub(super) fn encode_windows_env_block(opts: &SpawnOptions) -> Option<Vec<u16>> {
    let mut pairs = super::env::spawn_env_pairs(opts)?;
    Some(encode_env_pairs(&mut pairs))
}

fn encode_env_pairs(pairs: &mut Vec<(std::ffi::OsString, std::ffi::OsString)>) -> Vec<u16> {
    pairs.sort_by(|a, b| cmp_env_key_ci(&a.0, &b.0));
    let mut buf = Vec::new();
    for (key, value) in pairs {
        if key.is_empty()
            || env_key_has_embedded_eq(key)
            || os_contains_u16(key, 0)
            || os_contains_u16(value, 0)
        {
            continue;
        }
        buf.extend(key.encode_wide());
        buf.push(u16::from(b'='));
        buf.extend(value.encode_wide());
        buf.push(0);
    }
    buf.push(0);
    if buf.len() == 1 {
        buf.push(0);
    }
    buf
}

fn os_contains_u16(s: &OsStr, needle: u16) -> bool {
    s.encode_wide().any(|c| c == needle)
}

/// `=` after the first character is illegal in a Windows env key.
/// Keys that *start* with `=` (`=C:`, `=D:`, …) are drive current-directory vars.
fn env_key_has_embedded_eq(key: &OsStr) -> bool {
    let mut units = key.encode_wide();
    let Some(_) = units.next() else {
        return false;
    };
    units.any(|c| c == u16::from(b'='))
}

fn cmp_env_key_ci(a: &OsStr, b: &OsStr) -> std::cmp::Ordering {
    let a: Vec<u16> = a.encode_wide().collect();
    let b: Vec<u16> = b.encode_wide().collect();
    let result = unsafe { CompareStringOrdinal(&a, &b, true) };
    if result == CSTR_LESS_THAN {
        std::cmp::Ordering::Less
    } else if result == CSTR_EQUAL {
        std::cmp::Ordering::Equal
    } else if result == CSTR_GREATER_THAN {
        std::cmp::Ordering::Greater
    } else {
        a.cmp(&b)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn env_block_entries_are_sorted_case_insensitively() {
        let _env = crate::warden::env::lock_process_env();
        unsafe {
            std::env::set_var("MCP_WRIT_ENV_SORT_B", "b");
            std::env::set_var("MCP_WRIT_ENV_SORT_a", "a");
        }
        let tmp = std::env::temp_dir().join("mcp-writ-env-sort");
        let opts = SpawnOptions {
            restrict_environment: false,
            allowed_names: Vec::new(),
            tmpdir: Some(tmp),
        };
        let block = encode_windows_env_block(&opts).expect("inherited env with tmpdir");
        let keys = decode_env_block_keys(&block);
        use std::cmp::Ordering;
        for pair in keys.windows(2) {
            assert_ne!(
                cmp_env_key_ci(OsStr::new(&pair[0]), OsStr::new(&pair[1])),
                Ordering::Greater,
                "Windows env block keys must be ordinal case-insensitive sorted, got {keys:?}"
            );
        }
        let pos_a = keys
            .iter()
            .position(|k| k.eq_ignore_ascii_case("MCP_WRIT_ENV_SORT_a"));
        let pos_b = keys
            .iter()
            .position(|k| k.eq_ignore_ascii_case("MCP_WRIT_ENV_SORT_B"));
        assert!(
            pos_a.is_some() && pos_b.is_some() && pos_a < pos_b,
            "a should sort before B, keys={keys:?}"
        );
    }

    #[test]
    fn drive_current_directory_keys_are_kept() {
        use std::ffi::OsString;
        assert!(
            !env_key_has_embedded_eq(OsStr::new("=C:")),
            "leading = must be kept"
        );
        assert!(
            !env_key_has_embedded_eq(OsStr::new("=")),
            "a lone = key must be kept"
        );
        assert!(
            env_key_has_embedded_eq(OsStr::new("FOO=BAR")),
            "embedded = must be rejected"
        );
        assert!(!env_key_has_embedded_eq(OsStr::new("PATH")));

        let mut pairs = vec![
            (OsString::from("FOO=BAR"), OsString::from("nope")),
            (OsString::from("=C:"), OsString::from("C:\\tmp")),
            (OsString::from("PATH"), OsString::from("x")),
        ];
        let keys = decode_env_block_keys(&encode_env_pairs(&mut pairs));
        assert!(
            keys.iter().any(|k| k == "=C:"),
            "drive current-directory key must be encoded, got {keys:?}"
        );
        assert!(
            !keys.iter().any(|k| k.contains("FOO=BAR")),
            "embedded = keys must stay excluded, got {keys:?}"
        );
        assert!(keys.iter().any(|k| k == "PATH"), "got {keys:?}");
    }

    #[test]
    fn env_key_ordinal_compare_is_case_insensitive() {
        use std::cmp::Ordering;
        assert_eq!(
            cmp_env_key_ci(OsStr::new("PATH"), OsStr::new("path")),
            Ordering::Equal
        );
        assert_eq!(
            cmp_env_key_ci(OsStr::new("a"), OsStr::new("B")),
            Ordering::Less
        );
        assert_eq!(
            cmp_env_key_ci(OsStr::new("B"), OsStr::new("a")),
            Ordering::Greater
        );
    }

    fn decode_env_block_keys(buf: &[u16]) -> Vec<String> {
        let mut keys = Vec::new();
        let mut i = 0;
        while i < buf.len() {
            if buf[i] == 0 {
                break;
            }
            let start = i;
            while i < buf.len() && buf[i] != 0 {
                i += 1;
            }
            let entry = String::from_utf16_lossy(&buf[start..i]);
            if let Some(eq) = entry
                .char_indices()
                .skip(1)
                .find(|(_, c)| *c == '=')
                .map(|(i, _)| i)
            {
                keys.push(entry[..eq].to_string());
            }
            i += 1;
        }
        keys
    }
}
