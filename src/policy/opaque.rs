//! Per-tool declarations for free-form argument members.
//!
//! `arguments { opaque "<field>" ... }` inside a `tool` names the
//! `params.arguments` members whose values are free-form text for that
//! tool — memory annotations, descriptions, free-text search terms —
//! strings that can never name a resource. The declaration is narrow:
//! it waives only the unrecognized-argument refusal the classification
//! walk applies to unclassified payload values under a constrained
//! tool. Every other gate still applies to the same values: reserved
//! secret spellings are still refused, resource-shaped values (paths,
//! `scheme://` URLs, IP literals, `host:port`) are still classified and
//! still face the tool's fs/network contracts, `args_schema` still
//! validates, and `deputy` extraction is unaffected.
//!
//! Two spellings declare a member:
//!
//!   - a bare member name (`opaque "observations"`) — a top-level
//!     `params.arguments` member; the name is literal, no escapes;
//!   - a pointer (`opaque "/params/arguments/entities/name"`) — the
//!     same restricted JSON-pointer notation `deputy extract` uses,
//!     rooted at `/params/arguments/` so a pointer can only name
//!     members below it; `~0`/`~1` decode inside segments. The `*`
//!     wildcard is not accepted: an opaque declaration names concrete
//!     fields, never whole shapes.
//!
//! A terminal path marks the declared member itself; arrays stay
//! transparent (a declared `entities/name` covers every element's
//! `name`). The declaration is a tool property — it has no meaning
//! under `defaults` or a profile, and policy `version=1` rejects it.

use std::collections::HashMap;

use super::deputy::{MAX_POINTER_BYTES, MAX_POINTER_SEGMENTS, decode_segment};

/// Maximum `opaque` entries in one tool's `arguments` block.
pub const MAX_OPAQUE_FIELDS: usize = 64;

/// One `opaque` entry: the member path it declares, decoded into
/// segments (`source` keeps the KDL spelling for re-emission).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct OpaqueField {
    /// The KDL source text; emitted verbatim by `kdl_emit`.
    pub source: String,
    /// Member-name segments below `params.arguments` — never empty.
    segments: Vec<String>,
}

impl OpaqueField {
    /// Parse one `opaque` argument value. A bare name declares a
    /// top-level member; a `/params/arguments/…` pointer declares a
    /// member path (deputy `extract` notation minus the wildcard).
    pub fn parse(source: &str) -> Result<Self, String> {
        if source.is_empty() {
            return Err("opaque field name must not be empty".to_string());
        }
        if source.len() > MAX_POINTER_BYTES {
            return Err(format!(
                "opaque field declaration exceeds {MAX_POINTER_BYTES} bytes"
            ));
        }
        let segments = if source.starts_with('/') {
            Self::parse_pointer(source)?
        } else {
            // A bare name is literal member text — no escapes. A '/'
            // inside one is almost certainly an un-rooted pointer
            // spelling, and a bare `*` reads as "every field"; refuse
            // both so the operator writes the pointer form or names
            // the member concretely.
            if source.contains('/') {
                return Err(format!(
                    "opaque field \"{source}\" contains '/' — write the /params/arguments/… pointer form"
                ));
            }
            if source == "*" {
                return Err("opaque field \"*\" is a wildcard — name concrete fields".to_string());
            }
            vec![source.to_string()]
        };
        Ok(Self {
            source: source.to_string(),
            segments,
        })
    }

    /// Decode a `/params/arguments/…` pointer into member segments.
    fn parse_pointer(source: &str) -> Result<Vec<String>, String> {
        let mut segments = Vec::new();
        for raw in source[1..].split('/') {
            if raw == "*" {
                return Err(format!(
                    "opaque field \"{source}\" uses the '*' wildcard — name concrete fields"
                ));
            }
            segments.push(decode_segment(raw)?);
        }
        if segments.len() > MAX_POINTER_SEGMENTS {
            return Err(format!(
                "opaque field pointer exceeds {MAX_POINTER_SEGMENTS} segments"
            ));
        }
        if segments.len() < 3
            || segments[0] != "params"
            || segments[1] != "arguments"
            || segments[2].is_empty()
        {
            return Err(format!(
                "opaque field pointer \"{source}\" must start with \"/params/arguments/\" and name a member"
            ));
        }
        Ok(segments.split_off(2))
    }

    /// Member-name segments below `params.arguments`.
    pub fn segments(&self) -> &[String] {
        &self.segments
    }
}

/// Prefix matcher over a tool's declared opaque fields — one trie node
/// per member-path segment. The request walk descends it alongside the
/// JSON object structure; a `terminal` node marks a declared subtree,
/// and arrays stay transparent because array elements never consume a
/// segment.
#[derive(Debug, Default)]
pub struct OpaqueMatcher {
    terminal: bool,
    children: HashMap<String, OpaqueMatcher>,
}

impl OpaqueMatcher {
    /// Build the matcher for a tool's declared fields — `None` when the
    /// tool declares none, so the walk pays nothing.
    pub fn build(fields: &[OpaqueField]) -> Option<Self> {
        if fields.is_empty() {
            return Option::None;
        }
        let mut root = Self::default();
        for field in fields {
            let mut node = &mut root;
            for seg in &field.segments {
                node = node.children.entry(seg.clone()).or_default();
            }
            node.terminal = true;
        }
        Some(root)
    }

    /// The node one member name deeper, when a declared path still
    /// prefixes it.
    pub fn child(&self, member: &str) -> Option<&OpaqueMatcher> {
        self.children.get(member)
    }

    /// Whether the member path reaching this node was itself declared —
    /// every scalar under it is free-form for this tool.
    pub fn terminal(&self) -> bool {
        self.terminal
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_accepts_bare_names_and_pointers() {
        let f = OpaqueField::parse("observations").unwrap();
        assert_eq!(f.segments(), &["observations"]);
        let f = OpaqueField::parse("/params/arguments/entities/name").unwrap();
        assert_eq!(f.segments(), &["entities", "name"]);
        // `~0`/`~1` escapes decode inside pointer segments.
        let f = OpaqueField::parse("/params/arguments/a~1b/c~0d").unwrap();
        assert_eq!(f.segments(), &["a/b", "c~d"]);
        // Both spellings of the same member share segments (dedup key).
        assert_eq!(
            OpaqueField::parse("name").unwrap().segments(),
            OpaqueField::parse("/params/arguments/name")
                .unwrap()
                .segments()
        );
    }

    #[test]
    fn parse_rejects_invalid_spellings() {
        for src in [
            "",                            // empty
            "*",                           // bare wildcard
            "entities/name",               // un-rooted pointer spelling
            "/params/arguments",           // no member below arguments
            "/params/arguments/",          // empty member name
            "/params/inputResponses/text", // wrong scope
            "/result/content/text",        // wrong root
            "/params/arguments/*/name",    // wildcard segment
            "/params/arguments/a~2b",      // bad escape
        ] {
            assert!(
                OpaqueField::parse(src).is_err(),
                "expected rejection: {src:?}"
            );
        }
        let long = format!("/params/arguments/{}", "a".repeat(MAX_POINTER_BYTES));
        assert!(OpaqueField::parse(&long).is_err());
        let deep = format!("/params/arguments{}", "/x".repeat(MAX_POINTER_SEGMENTS));
        assert!(OpaqueField::parse(&deep).is_err());
    }

    #[test]
    fn matcher_marks_terminals_along_paths() {
        let fields = [
            OpaqueField::parse("observations").unwrap(),
            OpaqueField::parse("/params/arguments/entities/name").unwrap(),
            OpaqueField::parse("/params/arguments/note").unwrap(),
        ];
        let m = OpaqueMatcher::build(&fields).unwrap();
        // Top-level member prefix.
        let obs = m.child("observations").unwrap();
        assert!(obs.terminal());
        // Nested path: intermediate nodes are non-terminal prefixes.
        let ent = m.child("entities").unwrap();
        assert!(!ent.terminal());
        assert!(ent.child("name").unwrap().terminal());
        assert!(ent.child("type").is_none());
        // Undeclared members have no matcher node.
        assert!(m.child("content").is_none());
        // An empty declaration list builds no matcher.
        assert!(OpaqueMatcher::build(&[]).is_none());
    }
}
