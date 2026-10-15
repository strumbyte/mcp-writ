//! `// REVIEW` marker handling for `legislator` policy drafts.
//!
//! `legislator::policy_generator` tags each generated line that needs an
//! operator decision with a `// REVIEW` comment, plus an unconditional
//! `// REVIEW all entries before deploying` header. KDL comments carry no
//! representation in the parsed document, so the load path scans the raw
//! source text: every loaded file (the entry policy and each `extends`
//! / `include` ancestor) is lexed for line and block comments, and a
//! comment whose body begins with the `REVIEW` token is recorded as a
//! marker. String and raw-string contents are not comments.
//!
//! `ReviewMode` — resolved from `MCP_WRIT_REVIEW_MODE` — decides what the
//! loaders do with a non-empty marker list:
//!
//! - `warn` (default, also unset/`""`): print the markers to stderr and
//!   keep loading — the default load outcome never changes;
//! - `refuse`: fail the load (`PolicyError::Validation`) — the opt-in
//!   strict gate for deployments that must not run an unreviewed draft;
//! - `off`: no output (explicit silence for an intentionally accepted
//!   draft).
//!
//! An unrecognized value fails closed (`refuse`), matching the
//! `MCP_WRIT_FAIL_ON` precedence convention.
//!
//! `check` does not gate on the environment variable: it receives the
//! marker list from `load_kdl_policy_for_target_scanned` and reports it
//! in-band (`review_markers`, status `drifted` /
//! `unresolved_review`).

use std::path::{Path, PathBuf};

use crate::error::PolicyError;
use crate::termutil::sanitize_for_terminal;

/// One unresolved `REVIEW` marker in a loaded policy file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReviewMarker {
    /// File the marker was found in (may be an `extends`/`include` file).
    pub path: PathBuf,
    /// 1-based line where the marker's comment starts.
    pub line: u32,
    /// Trimmed comment body (sanitized before display).
    pub text: String,
}

/// What a policy load does with unresolved `REVIEW` markers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReviewMode {
    /// No output; loading is unaffected.
    Off,
    /// Print markers to stderr and continue loading (default).
    Warn,
    /// Refuse to load a policy that still carries markers.
    Refuse,
}

impl ReviewMode {
    /// Resolve the mode from `MCP_WRIT_REVIEW_MODE`.
    ///
    /// Unset or empty selects the default `Warn` so the operator still
    /// sees unresolved markers without a failing load (a wrap-time
    /// `ENV MCP_WRIT_REVIEW_MODE=""` keeps that default). `warn`,
    /// `refuse` (alias `strict`), and `off` select the named modes; any
    /// other value fails closed as `Refuse`.
    pub fn from_env() -> Self {
        match std::env::var("MCP_WRIT_REVIEW_MODE") {
            Ok(value) => Self::parse(&value),
            Err(_) => Self::Warn,
        }
    }
}

/// Parse a mode value: `""` (unset-equivalent) / `warn` → `Warn`,
/// `refuse` / `strict` → `Refuse`, `off` → `Off`; anything else fails
/// closed as `Refuse`.
fn parse_review_mode(value: &str) -> ReviewMode {
    match value.trim() {
        "" | "warn" => ReviewMode::Warn,
        "refuse" | "strict" => ReviewMode::Refuse,
        "off" => ReviewMode::Off,
        _ => ReviewMode::Refuse,
    }
}

impl ReviewMode {
    fn parse(value: &str) -> Self {
        parse_review_mode(value)
    }

    /// Apply the mode to the markers found during a policy load.
    ///
    /// `Warn` prints each marker once; `Refuse` returns a `Validation`
    /// error naming the markers. `Off` and an empty list are no-ops.
    pub fn enforce(&self, markers: &[ReviewMarker]) -> Result<(), PolicyError> {
        if markers.is_empty() {
            return Ok(());
        }
        match self {
            Self::Off => Ok(()),
            Self::Warn => {
                eprintln!(
                    "Warning: policy carries {} unresolved REVIEW marker(s) — generated draft \
                     entries that still need an operator decision (MCP_WRIT_REVIEW_MODE=refuse \
                     rejects this load; `mcp-writ check` lists them as drift):",
                    markers.len()
                );
                for marker in markers {
                    eprintln!(
                        "  {}:{}: {}",
                        marker.path.display(),
                        marker.line,
                        sanitize_for_terminal(&marker.text)
                    );
                }
                Ok(())
            }
            Self::Refuse => Err(PolicyError::Validation(format!(
                "unresolved REVIEW markers ({}): {}",
                markers.len(),
                markers
                    .iter()
                    .map(|m| format!("{}:{}", m.path.display(), m.line))
                    .collect::<Vec<_>>()
                    .join(", ")
            ))),
        }
    }
}

/// Scan `content` — the raw text of policy file `path` — for `REVIEW`
/// markers inside KDL comments.
///
/// A marker is a `//` line comment or a `/* … */` block comment whose
/// body, after leading whitespace, begins with the `REVIEW` token
/// followed by `:` or whitespace. `REVIEWED` and lowercase `review` do
/// not match. Text inside `"…"` / `"""…"""` strings and `#"…"#` /
/// `##"…"##` raw strings is not a comment, and `/*` nesting is honored
/// so a `REVIEW` inside an already-closed inner comment still counts.
pub fn scan_review_markers(path: &Path, content: &str) -> Vec<ReviewMarker> {
    let bytes = content.as_bytes();
    let mut markers = Vec::new();
    let mut i = 0usize;
    let mut line = 1u32;
    let n = bytes.len();

    while i < n {
        let b = bytes[i];
        if b == b'\n' {
            line = line.saturating_add(1);
            i += 1;
        } else if b == b'/' && i + 1 < n && bytes[i + 1] == b'/' {
            // Line comment: body runs to the next newline / EOF.
            let body_start = i + 2;
            let mut j = body_start;
            while j < n && bytes[j] != b'\n' {
                j += 1;
            }
            if let Some(text) = review_text(&content[body_start..j]) {
                markers.push(ReviewMarker {
                    path: path.to_path_buf(),
                    line,
                    text,
                });
            }
            i = j;
        } else if b == b'/' && i + 1 < n && bytes[i + 1] == b'*' {
            // Block comment: KDL nests `/* … /* … */ … */`.
            let start_line = line;
            let body_start = i + 2;
            let mut j = body_start;
            let mut depth = 1usize;
            while j + 1 < n && depth > 0 {
                if bytes[j] == b'/' && bytes[j + 1] == b'*' {
                    depth += 1;
                    j += 2;
                } else if bytes[j] == b'*' && bytes[j + 1] == b'/' {
                    depth -= 1;
                    j += 2;
                } else {
                    if bytes[j] == b'\n' {
                        line = line.saturating_add(1);
                    }
                    j += 1;
                }
            }
            if depth > 0 {
                // Unterminated comment: the body runs to EOF.
                while j < n {
                    if bytes[j] == b'\n' {
                        line = line.saturating_add(1);
                    }
                    j += 1;
                }
            }
            let body_end = if depth == 0 { j - 2 } else { j };
            if let Some(text) = review_text(&content[body_start..body_end.max(body_start)]) {
                markers.push(ReviewMarker {
                    path: path.to_path_buf(),
                    line: start_line,
                    text,
                });
            }
            i = j;
        } else if b == b'"' {
            // Plain or `"""` multiline string.
            if bytes.get(i + 1) == Some(&b'"') && bytes.get(i + 2) == Some(&b'"') {
                let mut j = i + 3;
                while j < n {
                    if bytes[j] == b'\n' {
                        line = line.saturating_add(1);
                        j += 1;
                    } else if bytes[j] == b'\\' {
                        j += 2;
                    } else if bytes[j] == b'"'
                        && bytes.get(j + 1) == Some(&b'"')
                        && bytes.get(j + 2) == Some(&b'"')
                    {
                        j += 3;
                        break;
                    } else {
                        j += 1;
                    }
                }
                i = j;
            } else {
                let mut j = i + 1;
                while j < n {
                    if bytes[j] == b'\\' {
                        j += 2;
                    } else if bytes[j] == b'"' {
                        j += 1;
                        break;
                    } else {
                        j += 1;
                    }
                }
                i = j;
            }
        } else if b == b'#' {
            // Raw string: `#"…"#` … `###"…"###`.
            let mut j = i;
            while j < n && bytes[j] == b'#' {
                j += 1;
            }
            let hashes = j - i;
            if j < n && bytes[j] == b'"' {
                j += 1;
                while j < n {
                    if bytes[j] == b'"' {
                        let mut k = j + 1;
                        let mut seen = 0usize;
                        while k < n && bytes[k] == b'#' && seen < hashes {
                            k += 1;
                            seen += 1;
                        }
                        if seen == hashes {
                            j = k;
                            break;
                        }
                        j += 1;
                    } else {
                        if bytes[j] == b'\n' {
                            line = line.saturating_add(1);
                        }
                        j += 1;
                    }
                }
                i = j;
            } else {
                i += 1;
            }
        } else {
            i += 1;
        }
    }
    markers
}

/// Return the trimmed comment body when it starts with the `REVIEW`
/// token (`REVIEW`, `REVIEW:`, `REVIEW <rest>`), else `None`.
fn review_text(body: &str) -> Option<String> {
    let body = body.trim_start();
    let rest = body.strip_prefix("REVIEW")?;
    match rest.chars().next() {
        None => Some("REVIEW".to_string()),
        Some(':') => {
            let text = rest[1..].trim();
            Some(if text.is_empty() {
                "REVIEW:".to_string()
            } else {
                format!("REVIEW: {text}")
            })
        }
        Some(c) if c.is_whitespace() => Some(body.trim_end().to_string()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn scan(content: &str) -> Vec<ReviewMarker> {
        scan_review_markers(Path::new("policy.kdl"), content)
    }

    #[test]
    fn line_comment_marker_is_detected_with_line_number() {
        let src =
            "policy version=1\n\n// REVIEW: per-tool denied syscall differs\nserver \"s\" {}\n";
        let markers = scan(src);
        assert_eq!(markers.len(), 1);
        assert_eq!(markers[0].line, 3);
        assert_eq!(markers[0].text, "REVIEW: per-tool denied syscall differs");
    }

    #[test]
    fn generated_header_counts_like_any_marker() {
        // The draft header is itself unresolved until the operator removes
        // it — a draft whose owner never opens it still carries markers.
        let src = "// Policy Draft - Auto-generated by MCP Writ\n// REVIEW all entries before deploying\npolicy version=1\n";
        let markers = scan(src);
        assert_eq!(markers.len(), 1);
        assert_eq!(markers[0].line, 2);
        assert_eq!(markers[0].text, "REVIEW all entries before deploying");
    }

    #[test]
    fn marker_without_space_after_slashes_is_detected() {
        let src = "//REVIEW: fix me\n";
        let markers = scan(src);
        assert_eq!(markers.len(), 1);
        assert_eq!(markers[0].text, "REVIEW: fix me");
    }

    #[test]
    fn bare_review_token_is_detected() {
        let src = "// REVIEW\n";
        assert_eq!(scan(src).len(), 1);
    }

    #[test]
    fn reviewed_and_lowercase_do_not_match() {
        assert!(scan("// REVIEWED already\n").is_empty());
        assert!(scan("// review: lowercase\n").is_empty());
        assert!(scan("// REVIEWX nope\n").is_empty());
    }

    #[test]
    fn review_inside_strings_is_not_a_comment() {
        let src = "tool \"x\" {\n  note \"// REVIEW: not a marker\"\n}\n";
        assert!(scan(src).is_empty());
    }

    #[test]
    fn review_inside_multiline_string_is_not_a_comment() {
        let src = "tool \"x\" {\n  note \"\"\"\n  // REVIEW: not a marker\n  \"\"\"\n}\n";
        assert!(scan(src).is_empty());
    }

    #[test]
    fn review_inside_raw_string_is_not_a_comment() {
        let src = "note #\"// REVIEW: not a marker\"#\nnote2 ##\" /* REVIEW: no */ \"##\n";
        assert!(scan(src).is_empty());
    }

    #[test]
    fn block_comment_marker_is_detected() {
        let src = "/* REVIEW: block marker */\npolicy version=1\n";
        let markers = scan(src);
        assert_eq!(markers.len(), 1);
        assert_eq!(markers[0].line, 1);
    }

    #[test]
    fn nested_block_comment_marker_is_detected() {
        // A REVIEW that is not at the start of the outer comment body is
        // prose, not a generator marker.
        let src = "/* outer /* inner */ REVIEW: outer marker */\npolicy version=1\n";
        assert!(scan(src).is_empty());
        let src2 = "/* REVIEW: outer /* inner */ still */\npolicy version=1\n";
        assert_eq!(scan(src2).len(), 1);
    }

    #[test]
    fn escaped_quote_does_not_end_string_early() {
        let src = "note \"a \\\" b\" // REVIEW: after\n";
        assert_eq!(scan(src).len(), 1);
    }

    #[test]
    fn marker_after_nodes_on_same_line() {
        let src = "tool \"x\" deny=#true // REVIEW: confirmed?\n";
        let markers = scan(src);
        assert_eq!(markers.len(), 1);
        assert_eq!(markers[0].text, "REVIEW: confirmed?");
    }

    #[test]
    fn parse_modes() {
        assert_eq!(parse_review_mode(""), ReviewMode::Warn);
        assert_eq!(parse_review_mode("warn"), ReviewMode::Warn);
        assert_eq!(parse_review_mode("refuse"), ReviewMode::Refuse);
        assert_eq!(parse_review_mode("strict"), ReviewMode::Refuse);
        assert_eq!(parse_review_mode("off"), ReviewMode::Off);
        assert_eq!(parse_review_mode("bogus"), ReviewMode::Refuse);
    }

    #[test]
    fn refuse_enforce_errors_and_off_passes() {
        let markers = scan("// REVIEW: x\n");
        assert!(ReviewMode::Off.enforce(&markers).is_ok());
        assert!(ReviewMode::Warn.enforce(&markers).is_ok());
        let err = ReviewMode::Refuse.enforce(&markers).unwrap_err();
        assert!(matches!(err, PolicyError::Validation(_)));
        assert!(err.to_string().contains("policy.kdl:1"));
        assert!(ReviewMode::Refuse.enforce(&[]).is_ok());
    }
}
