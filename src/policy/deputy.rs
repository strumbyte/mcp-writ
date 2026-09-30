//! Configurable Confused Deputy roles and path-extraction rules.
//!
//! Upstream change: generalize the protection from the three fixed tool
//! names (`list_files`, `list_directory`, `read_file`) to explicit v2
//! per-tool roles. A `deputy` block inside `tool` declares
//!
//!   - `role="discover"`: a successful, correlated response seeds
//!     `known_paths` using the block's rules.
//!   - `role="use"`: every path the rules extract from the request must
//!     already be in `known_paths`; missing paths or extraction failures
//!     deny the call.
//!   - `role="none"`: opts a fixed-name tool out of the compatibility
//!     mapping below.
//!
//! Extraction is deliberately constrained: `extract` is a restricted
//! JSON pointer (member names, `*` wildcard, decimal indices, `~0`/`~1`
//! escapes — no code, no expressions) and `shape` names a built-in
//! extractor over known response/request structures. Both are bounded
//! ([`MAX_DEPUTY_RULES`], [`MAX_POINTER_BYTES`], [`MAX_POINTER_SEGMENTS`],
//! [`MAX_EXTRACT_VALUES`]) and `use`-role tools deny when a pointer
//! truncates or resolves nothing. This is NOT session or state
//! separation: roles share the single process-local `known_paths` set.
//!
//! Compatibility mapping (applied only when the tool has no `deputy`
//! block): `list_files` / `list_directory` behave as
//! `role="discover" { shape "mcp_list_result" }` and `read_file` as
//! `role="use" { shape "fs_targets" }`. The `deputy` block lives under
//! `tool` on purpose: the v2 tool children are a closed set, so a
//! v1-only or pre-change v2 loader rejects the new setting instead of
//! silently ignoring it (a top-level node would be skipped by design).

use std::collections::HashSet;

use super::Policy;

/// Maximum `extract`/`shape` rules in one `deputy` block.
pub const MAX_DEPUTY_RULES: usize = 16;
/// Maximum byte length of an `extract` pointer source string.
pub const MAX_POINTER_BYTES: usize = 256;
/// Maximum `/`-separated segments in an `extract` pointer.
pub const MAX_POINTER_SEGMENTS: usize = 16;
/// Maximum leaf values a pointer evaluation may collect or produce;
/// exceeding it marks the evaluation `truncated` (a `use`-role call then
/// denies because part of the path set is unknowable).
pub const MAX_EXTRACT_VALUES: usize = 256;

/// `role=` on a `deputy` block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeputyRole {
    /// Response paths seed `known_paths` (successful results only).
    Discover,
    /// Request paths must be members of `known_paths`.
    Use,
    /// Explicit opt-out; suppresses the fixed-name compatibility mapping.
    None,
}

impl DeputyRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Discover => "discover",
            Self::Use => "use",
            Self::None => "none",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "discover" => Some(Self::Discover),
            "use" => Some(Self::Use),
            "none" => Some(Self::None),
            _ => Option::None,
        }
    }

    /// The frame root an `extract` pointer must start from.
    pub fn pointer_root(self) -> Option<&'static str> {
        match self {
            Self::Discover => Some("result"),
            Self::Use => Some("params"),
            Self::None => Option::None,
        }
    }
}

/// A named, built-in extraction structure (`shape "<name>"`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KnownShape {
    /// `use`-role only: the same filesystem-target walk
    /// `checker::extract_fs_targets` performs over `params.arguments` and
    /// `params.inputResponses` (path-classified argument strings).
    FsTargets,
    /// `discover`-role only: the typed fields
    /// `session::extract_paths_from_response` reads —
    /// `result.content[].text` lines, `content[].resource.uri`,
    /// `resources[].uri`, `roots[].uri`, `files[].path`.
    McpListResult,
}

impl KnownShape {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::FsTargets => "fs_targets",
            Self::McpListResult => "mcp_list_result",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "fs_targets" => Some(Self::FsTargets),
            "mcp_list_result" => Some(Self::McpListResult),
            _ => Option::None,
        }
    }

    /// The only role this shape is valid for.
    pub fn role(self) -> DeputyRole {
        match self {
            Self::FsTargets => DeputyRole::Use,
            Self::McpListResult => DeputyRole::Discover,
        }
    }
}

/// One `extract`/`shape` child of a `deputy` block.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum DeputyRule {
    /// Restricted JSON pointer into the request or response frame.
    Pointer(ExtractPointer),
    /// Built-in known-structure extractor.
    Shape(KnownShape),
}

/// A restricted JSON pointer (`extract "/seg/seg"`).
///
/// Subset of RFC 6901: segments are member names, the wildcard `*`
/// (every array element or object member value), or a decimal array
/// index; `~0`/`~1` escapes decode inside segments. `split="lines"`
/// splits each resolved string leaf on newlines like the `content[].text`
/// handling does. A literal member named `*` is not addressable.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ExtractPointer {
    /// The KDL source text; emitted verbatim by `to_kdl`.
    pub source: String,
    /// Escapes decoded; `*` marks the wildcard segment.
    segments: Vec<String>,
    /// `split="lines"`: split resolved strings on newlines.
    pub split_lines: bool,
}

/// The strings a pointer evaluation produced.
#[derive(Debug, Clone, Default)]
pub struct PointerOutcome {
    /// String leaf values (line-split when `split="lines"`).
    pub values: Vec<String>,
    /// The value bound was hit — `values` is a strict prefix of what the
    /// pointer matched. `use`-role callers must treat this as an
    /// extraction failure: the unchecked tail cannot be waived through.
    pub truncated: bool,
}

impl ExtractPointer {
    /// Parse and validate `source`; `root` is the required first segment
    /// (`"params"` for `use`, `"result"` for `discover`).
    pub fn parse(source: &str, root: &str) -> Result<Self, String> {
        if !source.starts_with('/') {
            return Err("extract pointer must start with '/'".to_string());
        }
        if source.len() > MAX_POINTER_BYTES {
            return Err(format!("extract pointer exceeds {MAX_POINTER_BYTES} bytes"));
        }
        let mut segments = Vec::new();
        for raw in source[1..].split('/') {
            segments.push(decode_segment(raw)?);
        }
        if segments.len() > MAX_POINTER_SEGMENTS {
            return Err(format!(
                "extract pointer exceeds {MAX_POINTER_SEGMENTS} segments"
            ));
        }
        if segments.len() < 2 {
            return Err("extract pointer must address a member below the frame root".to_string());
        }
        if segments[0] != root {
            return Err(format!(
                "extract pointer for this role must start with \"/{root}/\""
            ));
        }
        Ok(Self {
            source: source.to_string(),
            segments,
            split_lines: false,
        })
    }

    /// First segment — the enforced frame root (`params` or `result`).
    pub fn root_segment(&self) -> &str {
        &self.segments[0]
    }

    /// Evaluate against a request or response frame root. Non-string
    /// leaves and values that fail to unquote are ignored; an absent
    /// location simply yields no values.
    pub fn resolve<'j, 'p>(&self, root: nojson::RawJsonValue<'j, 'p>) -> PointerOutcome {
        let mut outcome = PointerOutcome::default();
        let mut current = vec![root];
        for seg in &self.segments {
            let mut next = Vec::new();
            for value in current {
                expand_segment(value, seg, &mut next);
                if next.len() > MAX_EXTRACT_VALUES {
                    next.truncate(MAX_EXTRACT_VALUES);
                    outcome.truncated = true;
                    break;
                }
            }
            current = next;
            // Truncation does not stop traversal: the capped collection
            // is still a proper prefix of matches, so the remaining
            // segments keep applying to it and the final values stay a
            // prefix of the full-depth results (each later expansion
            // caps the same way). Only an exhausted location ends the
            // walk.
            if current.is_empty() {
                break;
            }
        }
        for value in current {
            let Ok(text) = value.to_unquoted_string_str() else {
                continue;
            };
            if self.split_lines {
                outcome.values.extend(
                    text.lines()
                        .map(str::trim)
                        .filter(|l| !l.is_empty())
                        .map(str::to_string),
                );
            } else {
                outcome.values.push(text.into_owned());
            }
        }
        if outcome.values.len() > MAX_EXTRACT_VALUES {
            outcome.values.truncate(MAX_EXTRACT_VALUES);
            outcome.truncated = true;
        }
        outcome
    }
}

/// Decode one pointer segment's `~0`/`~1` escapes; any other `~` use is
/// invalid.
fn decode_segment(raw: &str) -> Result<String, String> {
    if !raw.contains('~') {
        return Ok(raw.to_string());
    }
    let mut out = String::with_capacity(raw.len());
    let mut chars = raw.chars();
    while let Some(c) = chars.next() {
        if c == '~' {
            match chars.next() {
                Some('0') => out.push('~'),
                Some('1') => out.push('/'),
                _ => return Err(format!("invalid '~' escape in pointer segment \"{raw}\"")),
            }
        } else {
            out.push(c);
        }
    }
    Ok(out)
}

/// Expand one segment: `*` iterates member values / array elements, a
/// name resolves an object member, a decimal resolves an array index.
fn expand_segment<'j, 'p>(
    value: nojson::RawJsonValue<'j, 'p>,
    seg: &str,
    next: &mut Vec<nojson::RawJsonValue<'j, 'p>>,
) {
    if seg == "*" {
        if let Ok(members) = value.to_object() {
            next.extend(members.map(|(_, v)| v));
        } else if let Ok(items) = value.to_array() {
            next.extend(items);
        }
        return;
    }
    if let Ok(member) = value.to_member(seg)
        && let Some(v) = member.optional()
    {
        next.push(v);
        return;
    }
    if let (Ok(items), Ok(index)) = (value.to_array(), seg.parse::<usize>()) {
        // `items` is consumed by `nth`; re-request is cheap either way.
        drop(items);
        if let Some(v) = value.to_array().ok().and_then(|mut it| it.nth(index)) {
            next.push(v);
        }
    }
}

/// Parsed `deputy` block on a `tool`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeputyPolicy {
    pub role: DeputyRole,
    /// `extract`/`shape` children in declaration order. Required for
    /// `Discover`/`Use`; rejected for `None`.
    pub rules: Vec<DeputyRule>,
}

impl DeputyPolicy {
    /// Structural validation shared by the parser and the validator (the
    /// latter also covers policies built without parsing).
    pub fn validate(&self) -> Result<(), String> {
        if self.role == DeputyRole::None {
            if !self.rules.is_empty() {
                return Err("deputy role \"none\" cannot declare extraction rules".to_string());
            }
            return Ok(());
        }
        if self.rules.is_empty() {
            return Err(format!(
                "deputy role \"{}\" requires at least one `extract`/`shape` rule",
                self.role.as_str()
            ));
        }
        if self.rules.len() > MAX_DEPUTY_RULES {
            return Err(format!("deputy block exceeds {MAX_DEPUTY_RULES} rules"));
        }
        let mut seen = HashSet::new();
        for rule in &self.rules {
            match (self.role, rule) {
                (DeputyRole::Discover, DeputyRule::Shape(KnownShape::FsTargets))
                | (DeputyRole::Use, DeputyRule::Shape(KnownShape::McpListResult)) => {
                    return Err(format!(
                        "shape \"{}\" is not valid for deputy role \"{}\"",
                        match rule {
                            DeputyRule::Shape(s) => s.as_str(),
                            DeputyRule::Pointer(_) => unreachable!(),
                        },
                        self.role.as_str()
                    ));
                }
                (DeputyRole::Discover, DeputyRule::Pointer(p)) if p.root_segment() != "result" => {
                    return Err(format!(
                        "extract \"{}\" must start with \"/result/\" for role \"discover\"",
                        p.source
                    ));
                }
                (DeputyRole::Use, DeputyRule::Pointer(p)) if p.root_segment() != "params" => {
                    return Err(format!(
                        "extract \"{}\" must start with \"/params/\" for role \"use\"",
                        p.source
                    ));
                }
                _ => {}
            }
            if !seen.insert(rule) {
                return Err("duplicate extraction rule in deputy block".to_string());
            }
        }
        Ok(())
    }
}

/// The fixed-name compatibility rules (PR-13 behavior).
const LEGACY_DISCOVER_RULES: &[DeputyRule] = &[DeputyRule::Shape(KnownShape::McpListResult)];
const LEGACY_USE_RULES: &[DeputyRule] = &[DeputyRule::Shape(KnownShape::FsTargets)];

/// The role a tool call binds to, including the extraction rules that
/// apply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeputyBinding<'a> {
    /// No Confused Deputy check applies to this tool.
    None,
    /// A successful, correlated response seeds `known_paths`.
    Discover(&'a [DeputyRule]),
    /// Request paths must all be members of `known_paths`.
    Use(&'a [DeputyRule]),
}

/// Resolve the effective deputy binding for a tool name.
///
/// An explicit `deputy` block on the tool wins — including
/// `role="none"`, which suppresses the compatibility mapping. Tools
/// without a `deputy` block keep the PR-13 fixed-name roles.
pub fn deputy_binding<'a>(policy: &'a Policy, tool_name: &str) -> DeputyBinding<'a> {
    if let Some(dep) = policy
        .tools
        .iter()
        .find(|t| t.name == tool_name)
        .and_then(|t| t.deputy.as_ref())
    {
        return match dep.role {
            DeputyRole::None => DeputyBinding::None,
            DeputyRole::Discover => DeputyBinding::Discover(&dep.rules),
            DeputyRole::Use => DeputyBinding::Use(&dep.rules),
        };
    }
    match tool_name {
        "list_files" | "list_directory" => DeputyBinding::Discover(LEGACY_DISCOVER_RULES),
        "read_file" => DeputyBinding::Use(LEGACY_USE_RULES),
        _ => DeputyBinding::None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn json(src: &str) -> nojson::RawJson<'_> {
        nojson::RawJson::parse(src).unwrap()
    }

    #[test]
    fn pointer_parse_accepts_valid_subset() {
        let p = ExtractPointer::parse("/params/arguments/files/*/path", "params").unwrap();
        assert_eq!(p.root_segment(), "params");
        assert!(!p.split_lines);
        let p = ExtractPointer::parse("/result/files/0/path", "result").unwrap();
        assert_eq!(p.root_segment(), "result");
        // `~1` decodes a literal '/' inside a member name.
        ExtractPointer::parse("/params/a~1b/c", "params").unwrap();
    }

    #[test]
    fn pointer_parse_rejects_invalid() {
        for (src, root) in [
            ("params/arguments/path", "params"),   // no leading '/'
            ("/result/files", "params"),           // wrong root for use-role
            ("/params", "params"),                 // no member below root
            ("/params/arguments/pa~th", "params"), // bad '~' escape
            ("/params/arguments/path~2x", "params"),
        ] {
            assert!(
                ExtractPointer::parse(src, root).is_err(),
                "expected rejection: {src}"
            );
        }
        // Bound checks.
        let long = format!("/params/{}", "a".repeat(MAX_POINTER_BYTES));
        assert!(ExtractPointer::parse(&long, "params").is_err());
        let deep = format!("/params{}", "/x".repeat(MAX_POINTER_SEGMENTS));
        assert!(ExtractPointer::parse(&deep, "params").is_err());
    }

    #[test]
    fn pointer_resolve_members_indices_and_wildcards() {
        let frame = json(
            r#"{"params":{"name":"t","arguments":{"files":[{"path":"/a"},{"path":"/b"}],"dir":{"path":"/c"}}}}"#,
        );
        let p = ExtractPointer::parse("/params/arguments/files/*/path", "params").unwrap();
        let out = p.resolve(frame.value());
        assert_eq!(out.values, vec!["/a", "/b"]);
        assert!(!out.truncated);

        let p = ExtractPointer::parse("/params/arguments/files/1/path", "params").unwrap();
        assert_eq!(p.resolve(frame.value()).values, vec!["/b"]);

        let p = ExtractPointer::parse("/params/arguments/dir/path", "params").unwrap();
        assert_eq!(p.resolve(frame.value()).values, vec!["/c"]);

        // Missing location resolves to nothing.
        let p = ExtractPointer::parse("/params/arguments/nope/*/x", "params").unwrap();
        assert!(p.resolve(frame.value()).values.is_empty());

        // Wildcard over an object yields member values.
        let p = ExtractPointer::parse("/params/arguments/dir/*", "params").unwrap();
        assert_eq!(p.resolve(frame.value()).values, vec!["/c"]);
    }

    #[test]
    fn pointer_resolve_truncated_expansion_stays_a_prefix() {
        // 300 matching items: the `*` expansion caps at
        // MAX_EXTRACT_VALUES but the remaining segment must still apply
        // to the capped prefix — the result is the first 256 leaf
        // values with `truncated` set, not an empty outcome.
        let items: Vec<String> = (0..300).map(|i| format!("{{\"name\":\"n{i}\"}}")).collect();
        let src = format!("{{\"result\":{{\"items\":[{}]}}}}", items.join(","));
        let frame = json(&src);
        let p = ExtractPointer::parse("/result/items/*/name", "result").unwrap();
        let out = p.resolve(frame.value());
        assert!(out.truncated);
        assert_eq!(out.values.len(), MAX_EXTRACT_VALUES);
        // The values are a proper prefix — first match keeps its index.
        assert_eq!(out.values[0], "n0");
        assert_eq!(out.values[MAX_EXTRACT_VALUES - 1], "n255");

        // A terminal expansion under the cap reports the same way.
        let flat: Vec<String> = (0..300).map(|i| format!("\"v{i}\"")).collect();
        let src = format!("{{\"result\":{{\"vals\":[{}]}}}}", flat.join(","));
        let frame = json(&src);
        let p = ExtractPointer::parse("/result/vals/*", "result").unwrap();
        let out = p.resolve(frame.value());
        assert!(out.truncated);
        assert_eq!(out.values.len(), MAX_EXTRACT_VALUES);
        assert_eq!(out.values[0], "v0");
    }

    #[test]
    fn pointer_resolve_skips_non_string_leaves() {
        let frame = json(r#"{"result":{"files":[{"path":"/a"},{"path":7}]}}"#);
        let p = ExtractPointer::parse("/result/files/*/path", "result").unwrap();
        assert_eq!(p.resolve(frame.value()).values, vec!["/a"]);
    }

    #[test]
    fn pointer_resolve_split_lines() {
        let mut p = ExtractPointer::parse("/result/content/0/text", "result").unwrap();
        p.split_lines = true;
        let frame = json(r#"{"result":{"content":[{"text":"/a\n /b \n\n/c"}]}}"#);
        assert_eq!(p.resolve(frame.value()).values, vec!["/a", "/b", "/c"]);
    }

    #[test]
    fn deputy_policy_validate_rejects_bad_combinations() {
        let rules = || vec![DeputyRule::Shape(KnownShape::McpListResult)];
        assert!(
            DeputyPolicy {
                role: DeputyRole::None,
                rules: rules()
            }
            .validate()
            .is_err()
        );
        assert!(
            DeputyPolicy {
                role: DeputyRole::Discover,
                rules: Vec::new()
            }
            .validate()
            .is_err()
        );
        assert!(
            DeputyPolicy {
                role: DeputyRole::Discover,
                rules: rules()
            }
            .validate()
            .is_ok()
        );
        // Shape/role mismatch.
        assert!(
            DeputyPolicy {
                role: DeputyRole::Discover,
                rules: vec![DeputyRule::Shape(KnownShape::FsTargets)]
            }
            .validate()
            .is_err()
        );
        // Wrong pointer root.
        assert!(
            DeputyPolicy {
                role: DeputyRole::Use,
                rules: vec![DeputyRule::Pointer(
                    ExtractPointer::parse("/result/files", "result").unwrap()
                )]
            }
            .validate()
            .is_err()
        );
        // Duplicate rules.
        assert!(
            DeputyPolicy {
                role: DeputyRole::Discover,
                rules: vec![rules()[0].clone(), rules()[0].clone()]
            }
            .validate()
            .is_err()
        );
        assert!(
            DeputyPolicy {
                role: DeputyRole::None,
                rules: Vec::new()
            }
            .validate()
            .is_ok()
        );
    }

    #[test]
    fn deputy_binding_compat_and_explicit_override() {
        let mut policy = Policy::default();
        // No deputy blocks: the fixed-name mapping binds legacy roles.
        assert!(matches!(
            deputy_binding(&policy, "list_files"),
            DeputyBinding::Discover(_)
        ));
        assert!(matches!(
            deputy_binding(&policy, "list_directory"),
            DeputyBinding::Discover(_)
        ));
        assert!(matches!(
            deputy_binding(&policy, "read_file"),
            DeputyBinding::Use(_)
        ));
        assert!(matches!(
            deputy_binding(&policy, "unrelated"),
            DeputyBinding::None
        ));

        // An explicit block wins over the fixed-name mapping — including
        // `role="none"`, which suppresses it entirely.
        let mut t = crate::policy::ToolPolicy::named("read_file", true);
        t.deputy = Some(DeputyPolicy {
            role: DeputyRole::None,
            rules: Vec::new(),
        });
        policy.tools.push(t);
        assert!(matches!(
            deputy_binding(&policy, "read_file"),
            DeputyBinding::None
        ));
    }
}
