//! KDL block-edit helpers: line-initial node matching, comment-
//! and string-aware brace matching, and insert positions.

// ─── KDL block edits ─────────────────────────────────────────────────

/// If `bytes[i]` opens a `"..."`/`"""..."""` string (with `\` escapes) or
/// a `//`/`/* ... */` (nested) comment, return the index just past it —
/// `None` when `i` is ordinary code. Slashdashed nodes (`\\`) and raw
/// strings (`#"..."#`) are not expected in generated test policies.
fn kdl_skip_trivia(bytes: &[u8], i: usize) -> Option<usize> {
    match bytes.get(i).copied()? {
        b'"' if bytes.get(i + 1) == Some(&b'"') && bytes.get(i + 2) == Some(&b'"') => {
            let mut j = i + 3;
            while j < bytes.len()
                && !(bytes[j] == b'"'
                    && bytes.get(j + 1) == Some(&b'"')
                    && bytes.get(j + 2) == Some(&b'"'))
            {
                j += if bytes[j] == b'\\' { 2 } else { 1 };
            }
            Some((j + 3).min(bytes.len()))
        }
        b'"' => {
            let mut j = i + 1;
            while j < bytes.len() && bytes[j] != b'"' {
                j += if bytes[j] == b'\\' { 2 } else { 1 };
            }
            Some((j + 1).min(bytes.len()))
        }
        b'/' if bytes.get(i + 1) == Some(&b'/') => {
            let mut j = i;
            while j < bytes.len() && bytes[j] != b'\n' {
                j += 1;
            }
            Some(j)
        }
        b'/' if bytes.get(i + 1) == Some(&b'*') => {
            let mut j = i + 2;
            let mut nested = 1usize;
            while j < bytes.len() && nested > 0 {
                if bytes[j] == b'/' && bytes.get(j + 1) == Some(&b'*') {
                    nested += 1;
                    j += 2;
                } else if bytes[j] == b'*' && bytes.get(j + 1) == Some(&b'/') {
                    nested -= 1;
                    j += 2;
                } else {
                    j += 1;
                }
            }
            Some(j)
        }
        _ => None,
    }
}

/// Byte offset of the `{` that opens node `name` at or after `from` in a
/// KDL string. Comments and strings are skipped with the same lexical
/// rules as [`kdl_matching_brace`], and a match must also start its line
/// (only spaces/tabs may precede `name`) — `name` inside a comment,
/// string, or a longer identifier cannot match.
pub fn kdl_block_open(text: &str, name: &str, from: usize) -> Option<usize> {
    assert!(!name.is_empty());
    let bytes = text.as_bytes();
    let mut i = from;
    while i < bytes.len() {
        if let Some(j) = kdl_skip_trivia(bytes, i) {
            i = j;
            continue;
        }
        if bytes[i..].starts_with(name.as_bytes()) {
            // The byte after `name` must end it — whitespace, the `{`
            // itself, or a trivia opener. Anything else means the hit
            // is a prefix of a longer identifier (`filesystemx`,
            // `defaults-2`) or another token, not the node.
            match bytes.get(i + name.len()) {
                Some(b) if b.is_ascii_whitespace() || *b == b'{' || *b == b'/' || *b == b'"' => {}
                _ => {
                    i += name.len();
                    continue;
                }
            }
            // Leading boundary: `name` must start its line's content —
            // only spaces/tabs may precede it, so a hit inside a longer
            // identifier (`xdefaults`) or mid-line is not the node.
            let indented_only = text[..i]
                .rsplit('\n')
                .next()
                .is_some_and(|l| l.bytes().all(|b| b == b' ' || b == b'\t'));
            if indented_only {
                // Whitespace and comments may sit between the name and
                // `{` — skip both so a brace inside them cannot be the
                // one selected.
                let mut j = i + name.len();
                loop {
                    while j < bytes.len() && bytes[j].is_ascii_whitespace() {
                        j += 1;
                    }
                    match kdl_skip_trivia(bytes, j) {
                        Some(k) => j = k,
                        None => break,
                    }
                }
                if bytes.get(j) == Some(&b'{') {
                    return Some(j);
                }
            }
            i += name.len();
            continue;
        }
        i += 1;
    }
    None
}

/// Byte offset of the `}` matching the `{` at `open`. Braces inside
/// `"..."`/`"""..."""` strings (with `\` escapes), `//` line comments,
/// and nested `/* ... */` block comments are skipped — generated test
/// policies carry none of those inside the edited blocks, but a stray
/// one must not throw the count off. Slashdashed nodes (`\\`) and raw
/// strings (`#"..."#`) are not expected.
pub fn kdl_matching_brace(text: &str, open: usize) -> usize {
    let bytes = text.as_bytes();
    let mut depth = 0usize;
    let mut i = open;
    while i < bytes.len() {
        if let Some(j) = kdl_skip_trivia(bytes, i) {
            i = j;
            continue;
        }
        match bytes[i] {
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return i;
                }
            }
            _ => {}
        }
        i += 1;
    }
    panic!("unbalanced braces in KDL text");
}

/// Insert position for new lines inside the block opened at `open` —
/// the start of the line holding its closing `}`, so inserted text lands
/// between the last child and the close regardless of indent depth.
pub fn kdl_insert_pos(text: &str, open: usize) -> usize {
    let close = kdl_matching_brace(text, open);
    text[..close].rfind('\n').map_or(0, |i| i + 1)
}

/// `kdl_insert_pos` for the `name` node opened at or after `from`.
pub fn kdl_named_insert_pos(text: &str, name: &str, from: usize) -> Option<usize> {
    kdl_block_open(text, name, from).map(|open| kdl_insert_pos(text, open))
}

#[cfg(test)]
mod tests {
    //! Boundary and brace matching for the `kdl_*` block-edit helpers —
    //! a node-name hit must be a whole token that starts its line's
    //! content, and braces inside strings or comments must not count.
    use super::{kdl_block_open, kdl_matching_brace, kdl_named_insert_pos};

    #[test]
    fn block_open_finds_line_initial_node() {
        let text = "server \"x\" {\n    defaults {\n        filesystem {\n        }\n    }\n}\n";
        let open = kdl_block_open(text, "defaults", 0).expect("defaults node");
        assert_eq!(text.as_bytes()[open], b'{');
        assert_eq!(text[..open].lines().last().unwrap().trim(), "defaults");
    }

    #[test]
    fn block_open_rejects_name_inside_longer_identifier() {
        // A hit that is the suffix of a longer identifier fails the
        // leading boundary — only whitespace may precede the name.
        assert_eq!(kdl_block_open("xdefaults {\n", "defaults", 0), None);
        assert_eq!(kdl_block_open("    xdefaults {\n", "defaults", 0), None);
        // A trailing token char means the hit is a prefix of a longer
        // identifier, not the node.
        assert_eq!(kdl_block_open("defaults-2 {\n", "defaults", 0), None);
        assert_eq!(kdl_block_open("defaultsx {\n", "defaults", 0), None);
    }

    #[test]
    fn block_open_rejects_mid_line_name() {
        assert_eq!(kdl_block_open("x defaults {\n", "defaults", 0), None);
        assert_eq!(
            kdl_block_open("} defaults {\n", "defaults", 0),
            None,
            "a name after another token on the line is not a node start"
        );
    }

    #[test]
    fn block_open_skips_comments_and_strings() {
        assert_eq!(kdl_block_open("// defaults {\n", "defaults", 0), None);
        assert_eq!(kdl_block_open("/* defaults { */", "defaults", 0), None);
        assert_eq!(kdl_block_open("\"defaults\" {\n", "defaults", 0), None);
    }

    #[test]
    fn block_open_allows_trivia_between_name_and_brace() {
        let text = "defaults // {\n    {\n";
        let open = kdl_block_open(text, "defaults", 0).expect("comment hides no brace");
        assert_eq!(text.as_bytes()[open], b'{');
        assert_eq!(text[..open].lines().last().unwrap(), "    ");
    }

    #[test]
    fn block_open_requires_a_brace() {
        assert_eq!(kdl_block_open("defaults x\n", "defaults", 0), None);
        assert_eq!(kdl_block_open("defaults\n", "defaults", 0), None);
        assert_eq!(kdl_block_open("defaults", "defaults", 0), None);
    }

    #[test]
    fn block_open_from_offset_stays_in_enclosing_block() {
        // inject_fs_grants relies on this: searching for `filesystem`
        // from `defaults`'s brace must find the nested block, not the
        // later top-level one.
        let text = "defaults {\n    filesystem {\n    }\n}\nfilesystem {\n}\n";
        let d_open = kdl_block_open(text, "defaults", 0).unwrap();
        let fs_open = kdl_block_open(text, "filesystem", d_open).expect("nested filesystem");
        assert!(fs_open < kdl_matching_brace(text, d_open));
    }

    #[test]
    fn matching_brace_skips_braces_in_comments_and_strings() {
        let text = "defaults {\n    // }\n    x \"{\"\n}\n";
        let open = kdl_block_open(text, "defaults", 0).unwrap();
        let close = kdl_matching_brace(text, open);
        assert_eq!(text.as_bytes()[close], b'}');
        assert_eq!(&text[close..], "}\n");
    }

    #[test]
    fn named_insert_pos_lands_on_closing_line() {
        let text = "defaults {\n    filesystem {\n        a 1\n    }\n}\n";
        let pos = kdl_named_insert_pos(text, "filesystem", 0).expect("filesystem block");
        assert!(text[..pos].ends_with("        a 1\n"), "{pos}");
        assert!(text[pos..].starts_with("    }"), "{pos}");
    }
}
