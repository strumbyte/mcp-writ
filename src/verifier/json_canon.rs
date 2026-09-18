//! JSON normalization (no serde — hand-written recursive descent).
//!
//! Produces a canonical representation (sorted object keys, no whitespace)
//! suitable for hashing tools/list payloads.

/// Maximum nesting depth accepted by the parser. Matches the schema-walk
/// depth budget (`MAX_SCHEMA_STRING_DEPTH`) so deeply nested input is
/// rejected instead of overflowing the stack.
const MAX_JSON_DEPTH: usize = 64;

/// Normalize a JSON string by sorting object keys and removing whitespace.
/// This produces a canonical representation suitable for hashing.
pub fn normalize_json(input: &str) -> Result<String, String> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err("empty input".to_string());
    }
    let bytes = trimmed.as_bytes();
    let (val, pos) = parse_value(bytes, 0)?;
    // Ensure we consumed all input (ignoring trailing whitespace)
    let remaining = skip_ws(bytes, pos);
    if remaining < bytes.len() {
        return Err(format!("trailing characters at position {remaining}"));
    }
    let mut out = String::with_capacity(input.len());
    write_normalized(&val, &mut out);
    Ok(out)
}

#[derive(Debug)]
pub(crate) enum JsonVal {
    Null,
    Bool(bool),
    Num(String),
    Str(String),
    Array(Vec<JsonVal>),
    Object(Vec<(String, JsonVal)>),
}

fn skip_ws(b: &[u8], mut i: usize) -> usize {
    while i < b.len() && matches!(b[i], b' ' | b'\t' | b'\n' | b'\r') {
        i += 1;
    }
    i
}

pub(crate) fn parse_value(b: &[u8], pos: usize) -> Result<(JsonVal, usize), String> {
    parse_value_at(b, pos, 0)
}

fn parse_value_at(b: &[u8], pos: usize, depth: usize) -> Result<(JsonVal, usize), String> {
    if depth > MAX_JSON_DEPTH {
        return Err(format!("maximum nesting depth {MAX_JSON_DEPTH} exceeded"));
    }
    let i = skip_ws(b, pos);
    if i >= b.len() {
        return Err("unexpected end of input".to_string());
    }
    match b[i] {
        b'{' => parse_object(b, i, depth),
        b'[' => parse_array(b, i, depth),
        b'"' => {
            let (s, next) = parse_string(b, i)?;
            Ok((JsonVal::Str(s), next))
        }
        b't' | b'f' => parse_bool(b, i),
        b'n' => parse_null(b, i),
        _ => parse_number(b, i),
    }
}

fn parse_object(b: &[u8], pos: usize, depth: usize) -> Result<(JsonVal, usize), String> {
    let mut i = pos + 1; // skip '{'
    let mut pairs: Vec<(String, JsonVal)> = Vec::new();
    i = skip_ws(b, i);
    if i < b.len() && b[i] == b'}' {
        return Ok((JsonVal::Object(pairs), i + 1));
    }
    loop {
        i = skip_ws(b, i);
        let (key, next) = parse_string(b, i)?;
        i = skip_ws(b, next);
        if i >= b.len() || b[i] != b':' {
            return Err(format!("expected ':' at {i}"));
        }
        i += 1;
        let (val, next) = parse_value_at(b, i, depth + 1)?;
        pairs.push((key, val));
        i = skip_ws(b, next);
        if i >= b.len() {
            return Err("unexpected end in object".to_string());
        }
        if b[i] == b'}' {
            break;
        }
        if b[i] != b',' {
            return Err(format!("expected ',' or '}}' at {i}"));
        }
        i += 1;
    }
    // Sort by key for canonical form
    pairs.sort_by(|a, b_pair| a.0.cmp(&b_pair.0));
    Ok((JsonVal::Object(pairs), i + 1))
}

fn parse_array(b: &[u8], pos: usize, depth: usize) -> Result<(JsonVal, usize), String> {
    let mut i = pos + 1; // skip '['
    let mut elems: Vec<JsonVal> = Vec::new();
    i = skip_ws(b, i);
    if i < b.len() && b[i] == b']' {
        return Ok((JsonVal::Array(elems), i + 1));
    }
    loop {
        let (val, next) = parse_value_at(b, i, depth + 1)?;
        elems.push(val);
        i = skip_ws(b, next);
        if i >= b.len() {
            return Err("unexpected end in array".to_string());
        }
        if b[i] == b']' {
            break;
        }
        if b[i] != b',' {
            return Err(format!("expected ',' or ']' at {i}"));
        }
        i += 1;
    }
    Ok((JsonVal::Array(elems), i + 1))
}

fn parse_hex4(b: &[u8], hex_start: usize) -> Result<u32, String> {
    if hex_start + 3 >= b.len() {
        return Err("incomplete unicode escape".to_string());
    }
    let hex = std::str::from_utf8(&b[hex_start..hex_start + 4])
        .map_err(|_| "invalid unicode escape".to_string())?;
    u32::from_str_radix(hex, 16).map_err(|_| "invalid unicode escape".to_string())
}

/// `pos` points at `u` in `\uXXXX`. Returns `(codepoint, last_consumed_index)`.
fn parse_json_unicode(b: &[u8], pos: usize) -> Result<(u32, usize), String> {
    let cp = parse_hex4(b, pos + 1)?;
    let last = pos + 4;
    if (0xD800..=0xDBFF).contains(&cp) {
        let next = last + 1;
        if next + 5 >= b.len() || b[next] != b'\\' || b[next + 1] != b'u' {
            return Err(format!("unpaired high surrogate U+{cp:04X}"));
        }
        let low = parse_hex4(b, next + 2)?;
        if !(0xDC00..=0xDFFF).contains(&low) {
            return Err(format!(
                "expected low surrogate after U+{cp:04X}, got U+{low:04X}"
            ));
        }
        let combined = 0x10000 + ((cp - 0xD800) << 10) + (low - 0xDC00);
        Ok((combined, next + 5))
    } else if (0xDC00..=0xDFFF).contains(&cp) {
        Err(format!("unpaired low surrogate U+{cp:04X}"))
    } else {
        Ok((cp, last))
    }
}

fn parse_string(b: &[u8], pos: usize) -> Result<(String, usize), String> {
    let i = skip_ws(b, pos);
    if i >= b.len() || b[i] != b'"' {
        return Err(format!("expected '\"' at {i}"));
    }
    let mut j = i + 1;
    let mut s = String::new();
    // Track the start of the current raw UTF-8 byte span so that multibyte
    // characters (e.g. CJK, emoji) are decoded correctly via from_utf8
    // instead of the broken per-byte `b[j] as char` cast.
    let mut raw_start = j;
    while j < b.len() {
        if b[j] == b'\\' {
            // Flush accumulated raw bytes before handling the escape
            if j > raw_start {
                let raw_str = std::str::from_utf8(&b[raw_start..j])
                    .map_err(|e| format!("invalid UTF-8 in string at byte {raw_start}: {e}"))?;
                s.push_str(raw_str);
            }
            j += 1;
            if j >= b.len() {
                return Err("unexpected end in string escape".to_string());
            }
            match b[j] {
                b'"' => s.push('"'),
                b'\\' => s.push('\\'),
                b'/' => s.push('/'),
                b'b' => s.push('\u{0008}'),
                b'f' => s.push('\u{000C}'),
                b'n' => s.push('\n'),
                b'r' => s.push('\r'),
                b't' => s.push('\t'),
                b'u' => {
                    let (cp, last) = parse_json_unicode(b, j)?;
                    match char::from_u32(cp) {
                        Some(c) => s.push(c),
                        None => {
                            return Err(format!("invalid Unicode codepoint U+{cp:04X}"));
                        }
                    }
                    j = last;
                }
                other => {
                    return Err(format!(
                        "invalid escape '\\{}' in string",
                        (other as char).escape_debug()
                    ));
                }
            }
            j += 1;
            raw_start = j;
        } else if b[j] == b'"' {
            // Flush remaining raw bytes before returning
            if j > raw_start {
                let raw_str = std::str::from_utf8(&b[raw_start..j])
                    .map_err(|e| format!("invalid UTF-8 in string at byte {raw_start}: {e}"))?;
                s.push_str(raw_str);
            }
            return Ok((s, j + 1));
        } else if b[j] < 0x20 {
            return Err(format!("unescaped control character in string at byte {j}"));
        } else {
            j += 1;
        }
    }
    Err("unterminated string".to_string())
}

fn parse_number(b: &[u8], pos: usize) -> Result<(JsonVal, usize), String> {
    let mut j = pos;
    if j < b.len() && b[j] == b'-' {
        j += 1;
    }
    // Integer part: `0` alone or [1-9][0-9]* — leading zeros are invalid.
    match b.get(j) {
        Some(b'0') => {
            j += 1;
            if b.get(j).is_some_and(|c| c.is_ascii_digit()) {
                return Err(format!("invalid number at {pos}"));
            }
        }
        Some(c) if c.is_ascii_digit() => {
            while j < b.len() && b[j].is_ascii_digit() {
                j += 1;
            }
        }
        _ => return Err(format!("invalid number at {pos}")),
    }
    // Fraction: `.` must be followed by at least one digit.
    if j < b.len() && b[j] == b'.' {
        j += 1;
        let frac_start = j;
        while j < b.len() && b[j].is_ascii_digit() {
            j += 1;
        }
        if j == frac_start {
            return Err(format!("invalid number at {pos}"));
        }
    }
    // Exponent: `e`/`E` plus optional sign must be followed by digits.
    if j < b.len() && (b[j] == b'e' || b[j] == b'E') {
        j += 1;
        if j < b.len() && (b[j] == b'+' || b[j] == b'-') {
            j += 1;
        }
        let exp_start = j;
        while j < b.len() && b[j].is_ascii_digit() {
            j += 1;
        }
        if j == exp_start {
            return Err(format!("invalid number at {pos}"));
        }
    }
    let s = std::str::from_utf8(&b[pos..j]).map_err(|_| "invalid utf8 in number".to_string())?;
    Ok((JsonVal::Num(s.to_string()), j))
}

fn parse_bool(b: &[u8], pos: usize) -> Result<(JsonVal, usize), String> {
    if b[pos..].starts_with(b"true") {
        Ok((JsonVal::Bool(true), pos + 4))
    } else if b[pos..].starts_with(b"false") {
        Ok((JsonVal::Bool(false), pos + 5))
    } else {
        Err(format!("invalid literal at {pos}"))
    }
}

fn parse_null(b: &[u8], pos: usize) -> Result<(JsonVal, usize), String> {
    if b[pos..].starts_with(b"null") {
        Ok((JsonVal::Null, pos + 4))
    } else {
        Err(format!("invalid literal at {pos}"))
    }
}

pub(crate) fn write_json_string(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{0008}' => out.push_str("\\b"),
            '\u{000C}' => out.push_str("\\f"),
            c if c < '\u{0020}' => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

pub(crate) fn write_normalized(val: &JsonVal, out: &mut String) {
    match val {
        JsonVal::Null => out.push_str("null"),
        JsonVal::Bool(true) => out.push_str("true"),
        JsonVal::Bool(false) => out.push_str("false"),
        JsonVal::Num(n) => out.push_str(n),
        JsonVal::Str(s) => write_json_string(s, out),
        JsonVal::Array(elems) => {
            out.push('[');
            for (idx, e) in elems.iter().enumerate() {
                if idx > 0 {
                    out.push(',');
                }
                write_normalized(e, out);
            }
            out.push(']');
        }
        JsonVal::Object(pairs) => {
            out.push('{');
            for (idx, (k, v)) in pairs.iter().enumerate() {
                if idx > 0 {
                    out.push(',');
                }
                write_json_string(k, out);
                out.push(':');
                write_normalized(v, out);
            }
            out.push('}');
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_object_keys_are_escaped() {
        // Distinct objects whose keys contain quotes/backslashes must not collide.
        let a = r#"{"a\\":null,"b":true}"#;
        let b = r#"{"a":null,"b":true}"#;
        let na = normalize_json(a).unwrap();
        let nb = normalize_json(b).unwrap();
        assert_ne!(
            na, nb,
            "canonical bytes must distinguish escaped keys: {na} vs {nb}"
        );
    }

    #[test]
    fn test_normalize_sorted_keys() {
        let input = r#"{"z": 1, "a": 2, "m": 3}"#;
        let result = normalize_json(input).unwrap();
        assert_eq!(result, r#"{"a":2,"m":3,"z":1}"#);
    }

    #[test]
    fn test_normalize_nested_sorted() {
        let input = r#"{"b": {"d": 1, "c": 2}, "a": 3}"#;
        let result = normalize_json(input).unwrap();
        assert_eq!(result, r#"{"a":3,"b":{"c":2,"d":1}}"#);
    }

    #[test]
    fn test_normalize_array() {
        let input = r#"[3, 1, 2]"#;
        let result = normalize_json(input).unwrap();
        // Arrays preserve order
        assert_eq!(result, "[3,1,2]");
    }

    #[test]
    fn test_normalize_string_escapes() {
        let input = r#"{"key": "value with \"quotes\""}"#;
        let result = normalize_json(input).unwrap();
        assert_eq!(result, r#"{"key":"value with \"quotes\""}"#);
    }

    #[test]
    fn test_normalize_empty_object() {
        assert_eq!(normalize_json("{}").unwrap(), "{}");
    }

    #[test]
    fn test_normalize_empty_array() {
        assert_eq!(normalize_json("[]").unwrap(), "[]");
    }

    #[test]
    fn test_normalize_multibyte_utf8() {
        // CJK characters (3-byte UTF-8)
        let input = r#"{"name":"日本語テスト","value":"OK"}"#;
        let result = normalize_json(input).unwrap();
        assert_eq!(result, r#"{"name":"日本語テスト","value":"OK"}"#);
    }

    #[test]
    fn test_normalize_emoji_utf8() {
        // Emoji (4-byte UTF-8)
        let input = r#"{"emoji":"🎉","text":"hello"}"#;
        let result = normalize_json(input).unwrap();
        assert_eq!(result, r#"{"emoji":"🎉","text":"hello"}"#);
    }

    #[test]
    fn test_normalize_mixed_utf8_and_escapes() {
        // Multibyte chars mixed with JSON escape sequences
        let input = r#"{"msg":"こんにちは\nworld","ok":true}"#;
        let result = normalize_json(input).unwrap();
        assert_eq!(result, r#"{"msg":"こんにちは\nworld","ok":true}"#);
    }

    #[test]
    fn test_normalize_primitives() {
        assert_eq!(normalize_json("null").unwrap(), "null");
        assert_eq!(normalize_json("true").unwrap(), "true");
        assert_eq!(normalize_json("false").unwrap(), "false");
        assert_eq!(normalize_json("42").unwrap(), "42");
        assert_eq!(normalize_json("\"hello\"").unwrap(), "\"hello\"");
    }

    #[test]
    fn test_normalize_whitespace_removal() {
        let input = "  {  \"a\" : 1 ,  \"b\" :  [ 2 , 3 ]  }  ";
        let result = normalize_json(input).unwrap();
        assert_eq!(result, r#"{"a":1,"b":[2,3]}"#);
    }

    #[test]
    fn test_normalize_invalid_json() {
        assert!(normalize_json("{invalid}").is_err());
        assert!(normalize_json("").is_err());
    }

    #[test]
    fn test_normalize_rejects_excessive_nesting() {
        let at_limit = format!("{}1{}", "[".repeat(64), "]".repeat(64));
        assert!(normalize_json(&at_limit).is_ok());
        let over_limit = format!("{}1{}", "[".repeat(65), "]".repeat(65));
        assert!(normalize_json(&over_limit).is_err());
    }

    #[test]
    fn test_normalize_rejects_unknown_escapes() {
        // `\q` is not a JSON escape sequence. Accepting it would canonicalize
        // to "\\q", colliding with the valid input {"a":"\\q"}.
        for bad in [r#"{"a":"\q"}"#, r#"{"a":"\'"}"#, r#"{"a":"\x41"}"#] {
            assert!(
                normalize_json(bad).is_err(),
                "invalid escape must be rejected: {bad}"
            );
        }
        assert_eq!(normalize_json(r#"{"a":"\\q"}"#).unwrap(), r#"{"a":"\\q"}"#);
    }

    #[test]
    fn test_normalize_rejects_raw_control_characters() {
        // Control characters must be escaped in JSON strings; a raw tab would
        // canonicalize identically to the valid "\u0009" escape.
        assert!(normalize_json("{\"a\":\"x\ty\"}").is_err());
        assert_eq!(
            normalize_json(r#"{"a":"x\ty"}"#).unwrap(),
            r#"{"a":"x\ty"}"#
        );
    }

    #[test]
    fn test_normalize_number_syntax_is_strict() {
        for bad in ["-", "1.", "1e", "1e+", ".5", "0123", "-x"] {
            assert!(
                normalize_json(bad).is_err(),
                "invalid JSON number must be rejected: {bad}"
            );
        }
        for good in ["0", "-0", "0.5", "-12.34E-5", "1e+3", "42"] {
            assert!(
                normalize_json(good).is_ok(),
                "valid JSON number must parse: {good}"
            );
        }
    }
}
