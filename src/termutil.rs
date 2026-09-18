//! Neutralize untrusted strings before they reach a terminal.

/// Render `input` so C0/C1 controls, ESC, BEL, and bidi marks cannot hijack
/// a terminal. Raw values stay unchanged in structurally encoded files.
pub fn sanitize_for_terminal(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        match ch {
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\x08' => out.push_str("\\b"),
            '\x0c' => out.push_str("\\f"),
            c if c.is_control() || is_bidi_or_format(c) => {
                out.push_str(&format!("\\u{{{:04x}}}", c as u32));
            }
            c => out.push(c),
        }
    }
    out
}

fn is_bidi_or_format(c: char) -> bool {
    matches!(
        c,
        '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}' | '\u{200B}'..='\u{200F}' | '\u{061C}'
    )
}

/// Escape a string for a KDL quoted value, including control characters.
pub fn escape_kdl_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() || is_bidi_or_format(c) => {
                out.push_str(&format!("\\u{{{:04x}}}", c as u32));
            }
            c => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escape_sequences_are_visible() {
        assert_eq!(
            sanitize_for_terminal("ok\x1b[31mX\x07"),
            "ok\\u{001b}[31mX\\u{0007}"
        );
        assert_eq!(sanitize_for_terminal("a\nb"), "a\\nb");
    }
}
