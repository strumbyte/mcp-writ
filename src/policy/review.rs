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

/// Which generated template a `// REVIEW` marker came from — the single
/// ledger the draft generator and `check` both read, so an unresolved
/// marker carries guidance, not just a location.
///
/// A generated marker's body starts with the kind's token (its
/// `as_str()` name) and continues with `:`, whitespace, or ends the
/// line: `// REVIEW: <token>: <detail>`. `check` classifies the
/// recorded marker text by that head under the same delimiter rule
/// `review_text` applies to `REVIEW` itself — a custom note that merely
/// shares a prefix with a token (`unbound-toolkit`) stays `Custom`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MarkerKind {
    /// `// REVIEW: header:` — the draft head's blanket review note.
    Header,
    /// `deny=#true` tool emitted without a verdict grounding an allow.
    UnboundTool,
    /// Manifest scan finding that blocks the tool it annotates.
    BlockedCapability,
    /// Live `inputSchema` dropped for using unsupported constructs.
    SchemaUnsupported,
    /// Workload hashes pin the generating host's files.
    HashPinHost,
    /// The draft must be regenerated on server/interpreter updates.
    RegenerateOnUpdate,
    /// Part of the launch could not be bound to a hashable file.
    UnboundWorkload,
    /// Syscall analysis did not complete; the allowlist may be short.
    SyscallAnalysis,
    /// Syscall detected but withheld under a blocked permission class.
    SyscallBlocked,
    /// Interpreter-baseline names dropped by blocked permissions.
    BaselineDropped,
    /// Shared interpreter baseline, not a workload measurement.
    InterpreterBaseline,
    /// The analyzed target is not a Linux-ABI binary.
    NonLinuxAbi,
    /// Outbound-network capability; destinations cannot be inferred.
    NetworkOutbound,
    /// Datagram-family syscalls; UDP is never inferred.
    Datagram,
    /// Marker text matched no known kind — hand-written or edited.
    Custom,
}

impl MarkerKind {
    /// Every kind `classify` can return except `Custom` — the fallback
    /// for marker text that carries no known head.
    const KNOWN: &'static [MarkerKind] = &[
        Self::Header,
        Self::UnboundTool,
        Self::BlockedCapability,
        Self::SchemaUnsupported,
        Self::HashPinHost,
        Self::RegenerateOnUpdate,
        Self::UnboundWorkload,
        Self::SyscallAnalysis,
        Self::SyscallBlocked,
        Self::BaselineDropped,
        Self::InterpreterBaseline,
        Self::NonLinuxAbi,
        Self::NetworkOutbound,
        Self::Datagram,
    ];

    /// The kind's stable name — the `kind` member in `check`'s JSON
    /// result and the token a generated marker body starts with.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Header => "header",
            Self::UnboundTool => "unbound-tool",
            Self::BlockedCapability => "blocked-capability",
            Self::SchemaUnsupported => "schema-unsupported",
            Self::HashPinHost => "hash-pin-host",
            Self::RegenerateOnUpdate => "regenerate-on-update",
            Self::UnboundWorkload => "unbound-workload",
            Self::SyscallAnalysis => "syscall-analysis",
            Self::SyscallBlocked => "syscall-blocked",
            Self::BaselineDropped => "baseline-dropped",
            Self::InterpreterBaseline => "interpreter-baseline",
            Self::NonLinuxAbi => "non-linux-abi",
            Self::NetworkOutbound => "network-outbound",
            Self::Datagram => "datagram",
            Self::Custom => "custom",
        }
    }

    /// Why the marker needs an operator decision — the fixed text
    /// `check` reports under `why`.
    pub fn why(self) -> &'static str {
        match self {
            Self::Header => {
                "this file is a generated draft — every entry is provisional \
                 until a human has read it"
            }
            Self::UnboundTool => {
                "the tool was emitted deny=#true with no verdict grounding an \
                 allow — the draft cannot show the tool is safe, so it stays \
                 closed until a human decides"
            }
            Self::BlockedCapability => {
                "a permission verdict or a manifest-scan finding blocked \
                 this tool — evidence was found, but it grounded a deny \
                 rather than an allow"
            }
            Self::SchemaUnsupported => {
                "the discovered inputSchema uses constructs the args_schema \
                 evaluator does not support; it was dropped rather than \
                 emitted unenforceably"
            }
            Self::HashPinHost => {
                "the digests pin the generating host's files — the \
                 deployment host's artifacts may differ"
            }
            Self::RegenerateOnUpdate => {
                "a server or interpreter update invalidates the pinned \
                 digests and the tools/list this draft was built from"
            }
            Self::UnboundWorkload => {
                "part of the launch could not be bound to a hashable file — \
                 nothing pins what actually runs"
            }
            Self::SyscallAnalysis => {
                "syscall analysis did not complete, so the emitted allowlist \
                 was built on incomplete data and may be missing names the \
                 workload needs"
            }
            Self::SyscallBlocked => {
                "a syscall the binary can make was kept out of the allowlist \
                 because its permission class was denied as excess"
            }
            Self::BaselineDropped => {
                "shared interpreter-baseline syscalls were dropped because \
                 their permission class is blocked — the runtime may still \
                 need them"
            }
            Self::InterpreterBaseline => {
                "the allowlist is a shared interpreter baseline, not a \
                 measurement of this workload — needed calls may be missing \
                 and unused ones included"
            }
            Self::NonLinuxAbi => {
                "the analyzed target is not a Linux-ABI binary — its call \
                 numbers and names do not map onto a Linux seccomp \
                 allowlist, so none was emitted"
            }
            Self::NetworkOutbound => {
                "the workload can open outbound connections but destinations \
                 cannot be inferred — the draft keeps deny-all rather than \
                 guess"
            }
            Self::Datagram => {
                "datagram-family syscalls are UDP-compatible but not proof \
                 UDP is required — UDP/QUIC is never inferred and a TCP \
                 allow never covers it"
            }
            Self::Custom => {
                "a marker matching no known generator kind — a hand-written \
                 or hand-edited note"
            }
        }
    }

    /// Representative way to resolve the marker — the fixed text
    /// `check` reports under `how` and enumerates in `remediation`.
    pub fn how(self) -> &'static str {
        match self {
            Self::Header => {
                "work through the REVIEW items, edit or accept each, and \
                 remove their markers — the draft is deployable when none \
                 remain"
            }
            Self::UnboundTool => {
                "check what the tool does (source, manifest, a dry-run \
                 call); for a tool you keep, remove deny=#true and set \
                 side_effect plus any sub-policies — otherwise keep the \
                 deny and delete the marker (guide §4.3, Case C)"
            }
            Self::BlockedCapability => {
                "read the named reason; if the verdict or finding is a \
                 false positive or an accepted risk, remove deny=#true \
                 and set side_effect plus any sub-policies — otherwise \
                 keep the deny and delete the marker"
            }
            Self::SchemaUnsupported => {
                "write a reviewed args_schema inside the supported subset \
                 (policy-authoring, \"Constraining argument structure\")"
            }
            Self::HashPinHost => {
                "re-hash the same targets on the deployment host — or \
                 regenerate there — and update the pins; check/run report \
                 the drift until then (guide §4.15)"
            }
            Self::RegenerateOnUpdate => {
                "on updates, regenerate into a separate file on the \
                 deployment host, diff it against this policy, review, and \
                 merge"
            }
            Self::UnboundWorkload => {
                "read the named reason; bind the payload explicitly — a \
                 resolved script path for entrypoint-hash — or accept the \
                 gap deliberately, then delete the marker (guide §8.2, \
                 launcher workloads)"
            }
            Self::SyscallAnalysis => {
                "read the status and reason; run the workload and add the \
                 syscalls that `unknown syscall` or EPERM denials name"
            }
            Self::SyscallBlocked => {
                "confirm the class stays blocked; if the workload genuinely \
                 needs the call, revisit the permission verdict rather \
                 than editing the allowlist"
            }
            Self::BaselineDropped => {
                "if the workload breaks on these calls, revisit the \
                 blocked-permission verdict and re-allow only what the \
                 runtime proves it needs"
            }
            Self::InterpreterBaseline => {
                "run the workload; add what `unknown syscall` or EPERM \
                 names — a child `syscalls` allow REPLACES the whole list, \
                 it does not append"
            }
            Self::NonLinuxAbi => {
                "write the syscall policy by hand for the target runtime, \
                 or rely on the platform's own sandbox controls"
            }
            Self::NetworkOutbound => {
                "declare each needed destination explicitly, e.g. \
                 network { allow host=\"<ip-or-name>\" proto=\"tcp\" \
                 port=<port> } (guide §5, defaults.network)"
            }
            Self::Datagram => {
                "if the workload needs UDP, declare proto=\"udp\" \
                 explicitly; on Linux `run`, UDP grants are enforced only \
                 on the namespaced route"
            }
            Self::Custom => {
                "read the note and decide what it asks; delete the comment \
                 once resolved"
            }
        }
    }

    /// The `// REVIEW: <token>:` head a generated marker line starts
    /// with — the form `classify` requires (token, then `:`, whitespace,
    /// or end-of-line).
    pub fn comment_head(self) -> String {
        format!("// REVIEW: {}:", self.as_str())
    }

    /// A generated `// REVIEW: <token>: <detail>` comment line — no
    /// leading indent, no trailing newline. `detail` is text already
    /// escaped for a KDL comment.
    pub fn comment(self, detail: &str) -> String {
        format!("{} {}", self.comment_head(), detail)
    }

    /// Classify a marker's recorded `text` (`REVIEW …` as
    /// `scan_review_markers` produces it) by the leading kind token:
    /// the body after `REVIEW` must begin with the token followed by
    /// end-of-text, `:`, or whitespace — the same delimiter rule
    /// `review_text` applies to `REVIEW` itself. Anything else,
    /// including text that merely shares a prefix with a token, is
    /// `Custom`.
    pub fn classify(marker_text: &str) -> Self {
        let body = marker_body(marker_text);
        for kind in Self::KNOWN {
            if let Some(rest) = body.strip_prefix(kind.as_str()) {
                match rest.chars().next() {
                    None | Some(':') => return *kind,
                    Some(c) if c.is_whitespace() => return *kind,
                    _ => {}
                }
            }
        }
        Self::Custom
    }
}

/// The marker body after the `REVIEW` token and its delimiter (`:` or
/// whitespace) — what `classify` head-matches against.
fn marker_body(text: &str) -> &str {
    let rest = text.strip_prefix("REVIEW").unwrap_or(text).trim_start();
    rest.strip_prefix(':').unwrap_or(rest).trim_start()
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

    // --- MarkerKind classification -------------------------------------

    #[test]
    fn classify_recognizes_every_generated_form() {
        // The emitted `// REVIEW: <token>: <detail>` shape must classify
        // back to its kind — this is the contract that keeps a changed
        // 文面 from silently drifting out of the ledger.
        for kind in MarkerKind::KNOWN {
            let comment = kind.comment("some detail");
            let text = review_text(&comment[2..]).expect("emits a REVIEW line");
            assert_eq!(
                MarkerKind::classify(&text),
                *kind,
                "{comment} must classify as {}",
                kind.as_str()
            );
        }
    }

    #[test]
    fn classify_accepts_token_delimiters() {
        assert_eq!(
            MarkerKind::classify("REVIEW: unbound-tool: Capability(A) [Case C]"),
            MarkerKind::UnboundTool
        );
        assert_eq!(
            MarkerKind::classify("REVIEW unbound-tool detail text"),
            MarkerKind::UnboundTool
        );
        assert_eq!(
            MarkerKind::classify("REVIEW: unbound-tool"),
            MarkerKind::UnboundTool
        );
        // `REVIEW :` and extra whitespace still expose the body token.
        assert_eq!(
            MarkerKind::classify("REVIEW  :hash-pin-host: x"),
            MarkerKind::HashPinHost
        );
    }

    #[test]
    fn classify_rejects_token_prefix_without_delimiter() {
        // A custom note that merely shares a token prefix must stay
        // `custom`.
        for text in [
            "REVIEW: unbound-toolkit needs a look",
            "REVIEW: unbound",
            "REVIEW: hash-pin",
            "REVIEW: hash-pin-hostile",
            "REVIEW: datagrams on the wire",
            "REVIEW: syscall-analysisx",
            "REVIEW: blocked-capabilities here",
        ] {
            assert_eq!(
                MarkerKind::classify(text),
                MarkerKind::Custom,
                "{text:?} must not be claimed by a known kind"
            );
        }
    }

    #[test]
    fn classify_custom_for_hand_written_and_unrelated_text() {
        for text in [
            "REVIEW",
            "REVIEW:",
            "REVIEW: confirm the workload list before pinning",
            "REVIEW: payload not bindable",
            "REVIEW all entries before deploying",
        ] {
            assert_eq!(MarkerKind::classify(text), MarkerKind::Custom, "{text:?}");
        }
        // A hand-written note that heads with a kind token + delimiter
        // classifies under the same rule — the delimiter, not authorship,
        // is what the match keys on.
        assert_eq!(
            MarkerKind::classify(
                "REVIEW: datagram syscalls (sendto, recvmsg) — compatible with UDP"
            ),
            MarkerKind::Datagram
        );
    }

    #[test]
    fn kind_guidance_is_fixed_non_empty_text() {
        for kind in MarkerKind::KNOWN
            .iter()
            .copied()
            .chain([MarkerKind::Custom])
        {
            assert!(!kind.why().is_empty(), "{} why", kind.as_str());
            assert!(!kind.how().is_empty(), "{} how", kind.as_str());
        }
        // The ledger is the single source of the JSON-facing kind names —
        // pin the full set so a rename is a deliberate change.
        let names: Vec<_> = MarkerKind::KNOWN
            .iter()
            .chain([&MarkerKind::Custom])
            .map(|k| k.as_str())
            .collect();
        assert_eq!(
            names,
            [
                "header",
                "unbound-tool",
                "blocked-capability",
                "schema-unsupported",
                "hash-pin-host",
                "regenerate-on-update",
                "unbound-workload",
                "syscall-analysis",
                "syscall-blocked",
                "baseline-dropped",
                "interpreter-baseline",
                "non-linux-abi",
                "network-outbound",
                "datagram",
                "custom",
            ]
        );
    }
}
