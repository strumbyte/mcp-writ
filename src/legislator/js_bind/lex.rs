//! Shared JS/TS scanners used by child_process detection and the binder.

/// Advance past whitespace, comments, and quoted strings.
///
/// Template literals skip static text only. A `${` interpolation is left at the
/// expression so callers can scan it as JavaScript.
pub(super) fn skip_inert_js(source: &str, i: usize) -> usize {
    let after_ws = skip_ws_and_comments(source, i);
    if after_ws > i {
        return after_ws;
    }
    let Some(b) = source.as_bytes().get(i).copied() else {
        return i;
    };
    match b {
        b'"' | b'\'' => take_string(source, i)
            .map(|(_, end)| end)
            .unwrap_or_else(|| next_index(source, i)),
        b'`' => skip_template(source, i, true),
        _ => i,
    }
}

/// Code cursor that resumes template-static text after `${...}` interpolations.
pub(super) struct JsScan {
    pub i: usize,
    /// Brace-depth of the current `${` interpolation per nested template.
    /// `0` means the cursor is in that template's static text.
    frames: Vec<i32>,
}

impl JsScan {
    pub(super) fn new() -> Self {
        Self {
            i: 0,
            frames: Vec::new(),
        }
    }

    fn in_template_static(&self) -> bool {
        self.frames.last() == Some(&0)
    }

    /// Skip comments, strings, and template-static text. Returns true if `i` moved.
    pub(super) fn skip_inert(&mut self, source: &str) -> bool {
        let start = self.i;
        if self.in_template_static() {
            let n = skip_template(source, self.i, false);
            if interpolation_started(source, n) {
                if let Some(depth) = self.frames.last_mut() {
                    *depth = 1;
                }
            } else {
                self.frames.pop();
            }
            self.i = n;
            return n > start;
        }

        let n = skip_inert_js(source, self.i);
        if n > start {
            if source.as_bytes().get(start) == Some(&b'`') && interpolation_started(source, n) {
                self.frames.push(1);
            }
            self.i = n;
            return true;
        }
        false
    }

    pub(super) fn bump(&mut self, source: &str) {
        let Some(&b) = source.as_bytes().get(self.i) else {
            return;
        };
        if let Some(depth) = self.frames.last_mut()
            && *depth > 0
        {
            match b {
                b'{' => *depth += 1,
                b'}' => *depth -= 1,
                _ => {}
            }
        }
        self.i = next_index(source, self.i);
    }
}

fn interpolation_started(src: &str, i: usize) -> bool {
    i >= 2
        && src.is_char_boundary(i - 2)
        && src.as_bytes()[i - 2] == b'$'
        && src.as_bytes()[i - 1] == b'{'
}

pub(super) fn next_index(source: &str, i: usize) -> usize {
    source
        .get(i..)
        .and_then(|s| s.chars().next())
        .map(|c| i + c.len_utf8())
        .unwrap_or_else(|| i.saturating_add(1).min(source.len()))
}

pub(super) fn slice_at(source: &str, i: usize) -> &str {
    source.get(i..).unwrap_or("")
}

pub(super) fn skip_opening_parens(source: &str, mut i: usize) -> usize {
    loop {
        i = skip_ws_and_comments(source, i);
        if source.as_bytes().get(i) == Some(&b'(') {
            i += 1;
            continue;
        }
        return i;
    }
}

pub(super) fn skip_closing_parens(source: &str, mut i: usize) -> usize {
    loop {
        i = skip_ws_and_comments(source, i);
        if source.as_bytes().get(i) == Some(&b')') {
            i += 1;
            continue;
        }
        return i;
    }
}

pub(super) fn find_matching(source: &str, start: usize, open: char, close: char) -> Option<usize> {
    let bytes = source.as_bytes();
    if start >= bytes.len() || bytes[start] as char != open {
        return None;
    }
    let mut depth = 0i32;
    let mut i = start;
    while i < bytes.len() {
        i = skip_ws_and_comments(source, i);
        if i >= bytes.len() {
            break;
        }
        if let Some((_, next)) = take_string(source, i) {
            i = next;
            continue;
        }
        let c = bytes[i] as char;
        if c == open {
            depth += 1;
        } else if c == close {
            depth -= 1;
            if depth == 0 {
                return Some(i);
            }
        }
        i += 1;
    }
    None
}

pub(super) fn skip_member_named(source: &str, at: usize, want: &str) -> Option<usize> {
    let bytes = source.as_bytes();
    let mut i = skip_ws_and_comments(source, at);
    if bytes.get(i) == Some(&b'?') && bytes.get(i + 1) == Some(&b'.') {
        i = skip_ws_and_comments(source, i + 2);
    } else if bytes.get(i) == Some(&b'.') {
        i = skip_ws_and_comments(source, i + 1);
    } else if bytes.get(i) != Some(&b'[') {
        return None;
    }
    if bytes.get(i) == Some(&b'[') {
        let inner = skip_ws_and_comments(source, i + 1);
        let (name, after_name) = take_string(source, inner)?;
        if name != want {
            return None;
        }
        let i = skip_ws_and_comments(source, after_name);
        if bytes.get(i) != Some(&b']') {
            return None;
        }
        return Some(i + 1);
    }
    let (name, after) = take_ident(source, i)?;
    if name == want { Some(after) } else { None }
}

pub(super) fn is_call_open(source: &str, i: usize) -> bool {
    let bytes = source.as_bytes();
    if bytes.get(i) == Some(&b'(') {
        return true;
    }
    if bytes.get(i) == Some(&b'?') && bytes.get(i + 1) == Some(&b'.') {
        let after = skip_ws_and_comments(source, i + 2);
        return bytes.get(after) == Some(&b'(');
    }
    false
}

/// After a CP method or `promisify(...)`: `(` / `.call(` / `.apply(` / `.bind(...)(`.
///
/// Also treats comma-unwrap grouping as transparent so
/// `(0, child_process.exec)(` / `(0, importedFn)(` count as invokes.
pub(super) fn is_invoked(source: &str, at: usize) -> bool {
    let i = skip_closing_parens(source, skip_ws_and_comments(source, at));
    if is_call_open(source, i) {
        return true;
    }
    let Some((adapter, after_adapter)) = take_fn_adapter(source, i) else {
        return false;
    };
    let after = skip_ws_and_comments(source, after_adapter);
    if source.as_bytes().get(after) != Some(&b'(') {
        return false;
    }
    let Some(close) = find_matching(source, after, '(', ')') else {
        return false;
    };
    let next = skip_ws_and_comments(source, close + 1);
    match adapter.as_str() {
        "call" | "apply" => true,
        "bind" => is_invoked(source, next),
        _ => false,
    }
}

pub(super) fn take_fn_adapter(source: &str, at: usize) -> Option<(String, usize)> {
    let bytes = source.as_bytes();
    let mut i = skip_ws_and_comments(source, at);
    if bytes.get(i) == Some(&b'?') && bytes.get(i + 1) == Some(&b'.') {
        i = skip_ws_and_comments(source, i + 2);
    } else if bytes.get(i) == Some(&b'.') {
        i = skip_ws_and_comments(source, i + 1);
    } else if bytes.get(i) != Some(&b'[') {
        return None;
    }
    let (name, after) = if bytes.get(i) == Some(&b'[') {
        let inner = skip_ws_and_comments(source, i + 1);
        let (name, after_name) = take_string(source, inner)?;
        let i = skip_ws_and_comments(source, after_name);
        if bytes.get(i) != Some(&b']') {
            return None;
        }
        (name, i + 1)
    } else {
        take_ident(source, i)?
    };
    match name.as_str() {
        "bind" | "call" | "apply" => Some((name, after)),
        _ => None,
    }
}

pub(super) fn preceded_by_dot(source: &str, ident_at: usize) -> bool {
    let mut j = ident_at;
    while j > 0 {
        j -= 1;
        let c = source.as_bytes()[j];
        if c.is_ascii_whitespace() {
            continue;
        }
        return c == b'.';
    }
    false
}

pub(super) fn is_line_or_block_comment(source: &str, i: usize) -> bool {
    slice_at(source, i).starts_with("//") || slice_at(source, i).starts_with("/*")
}

pub(super) fn skip_regex_or_slash(source: &str, i: usize) -> usize {
    let bytes = source.as_bytes();
    if i + 1 < bytes.len() && (bytes[i + 1] == b'/' || bytes[i + 1] == b'*') {
        return skip_ws_and_comments(source, i);
    }
    if looks_like_regex_start(source, i) {
        return skip_regex_literal(source, i);
    }
    i + 1
}

pub(super) fn looks_like_regex_start(source: &str, i: usize) -> bool {
    let Some(prefix) = source.get(..i) else {
        return true;
    };
    let trimmed = prefix.trim_end();
    if trimmed.is_empty() {
        return true;
    }
    if trimmed.ends_with("=>") || trimmed.ends_with("return") || trimmed.ends_with("case") {
        return true;
    }
    let Some(c) = trimmed.chars().next_back() else {
        return true;
    };
    matches!(
        c,
        '=' | '('
            | '['
            | ','
            | ':'
            | '!'
            | '&'
            | '|'
            | '?'
            | '{'
            | '}'
            | ';'
            | '+'
            | '-'
            | '*'
            | '%'
            | '~'
            | '^'
            | '<'
            | '>'
    )
}

pub(super) fn skip_regex_literal(source: &str, start: usize) -> usize {
    let bytes = source.as_bytes();
    let mut i = start + 1;
    let mut escaped = false;
    let mut clazz = false;
    while i < bytes.len() {
        let c = bytes[i];
        if escaped {
            escaped = false;
            i += 1;
            continue;
        }
        if c == b'\\' {
            escaped = true;
            i += 1;
            continue;
        }
        if c == b'[' {
            clazz = true;
        } else if c == b']' {
            clazz = false;
        } else if c == b'/' && !clazz {
            i += 1;
            while i < bytes.len() && bytes[i].is_ascii_alphabetic() {
                i += 1;
            }
            return i;
        }
        i += 1;
    }
    source.len()
}

pub(super) fn skip_ws_and_comments(source: &str, mut i: usize) -> usize {
    let bytes = source.as_bytes();
    loop {
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if i < bytes.len() && !source.is_char_boundary(i) {
            i += 1;
            continue;
        }
        if slice_at(source, i).starts_with("//") {
            while i < bytes.len() && bytes[i] != b'\n' {
                i += 1;
            }
            continue;
        }
        if slice_at(source, i).starts_with("/*") {
            i += 2;
            while i + 1 < bytes.len() && !(bytes[i] == b'*' && bytes[i + 1] == b'/') {
                i += 1;
            }
            i = i.saturating_add(2);
            continue;
        }
        return i;
    }
}

pub(super) fn take_ident(source: &str, start: usize) -> Option<(String, usize)> {
    if start >= source.len() {
        return None;
    }
    let c = source.get(start..)?.chars().next()?;
    if !is_ident_start(c) {
        return None;
    }
    let (name, end) = read_ident(source, start);
    if name.is_empty() {
        None
    } else {
        Some((name, end))
    }
}

pub(super) fn take_string(source: &str, start: usize) -> Option<(String, usize)> {
    let bytes = source.as_bytes();
    let quote = *bytes.get(start)?;
    if quote != b'"' && quote != b'\'' {
        return None;
    }
    let mut out = String::new();
    let mut i = start + 1;
    while i < bytes.len() {
        if bytes[i] == b'\\' {
            i += 2;
            continue;
        }
        if bytes[i] == quote {
            return Some((out, i + 1));
        }
        out.push(source[i..].chars().next()?);
        i += source[i..].chars().next()?.len_utf8();
    }
    None
}

pub(super) fn is_ident_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || b == b'$'
}

pub(super) fn skip_quoted(src: &str, start: usize) -> usize {
    let quote = src.as_bytes()[start];
    let mut i = start + 1;
    let bytes = src.as_bytes();
    while i < bytes.len() {
        if bytes[i] == b'\\' {
            i += 2;
            continue;
        }
        if bytes[i] == quote {
            return i + 1;
        }
        i += 1;
    }
    src.len()
}

/// Skip template-static text.
///
/// `from_opener` is true when `start` is the opening backtick. After `${...}`,
/// call with `from_opener = false` so a following backtick is the closer, not a
/// new template.
pub(super) fn skip_template(src: &str, start: usize, from_opener: bool) -> usize {
    let bytes = src.as_bytes();
    let mut i = start;
    if from_opener && bytes.get(i) == Some(&b'`') {
        i += 1;
    }
    while i < bytes.len() {
        if bytes[i] == b'\\' {
            i += 1;
            if i < bytes.len() {
                i += 1;
            }
            continue;
        }
        if bytes[i] == b'`' {
            return i + 1;
        }
        if bytes[i] == b'$' && bytes.get(i + 1) == Some(&b'{') {
            return i + 2;
        }
        i += 1;
    }
    src.len()
}

/// Skip a whole template literal, including interpolations, as one atom.
pub(super) fn skip_template_literal(src: &str, start: usize) -> usize {
    let mut i = start;
    let mut from_opener = true;
    loop {
        if i >= src.len() {
            return i;
        }
        let next = skip_template(src, i, from_opener);
        if next <= i {
            return next_index(src, i);
        }
        i = next;
        if interpolation_started(src, i) {
            i = skip_interpolation_expr(src, i);
            from_opener = false;
            continue;
        }
        return i;
    }
}

fn skip_interpolation_expr(src: &str, start: usize) -> usize {
    let bytes = src.as_bytes();
    let mut i = start;
    let mut depth = 1i32;
    while i < bytes.len() && depth > 0 {
        match bytes[i] {
            b'/' => i = skip_regex_or_slash(src, i),
            b'\'' | b'"' => i = skip_quoted(src, i),
            b'`' => i = skip_template_literal(src, i),
            b'{' => {
                depth += 1;
                i += 1;
            }
            b'}' => {
                depth -= 1;
                i += 1;
            }
            _ => i += 1,
        }
    }
    i
}

pub(super) fn extract_brace_block(src: &str, start: usize) -> (String, usize) {
    let bytes = src.as_bytes();
    if start >= bytes.len() || bytes[start] != b'{' {
        return (String::new(), start);
    }
    let mut depth = 0i32;
    let mut i = start;
    while i < bytes.len() {
        let c = bytes[i];
        if c == b'"' || c == b'\'' {
            i = skip_quoted(src, i);
            continue;
        }
        if c == b'`' {
            i = skip_template_literal(src, i);
            continue;
        }
        if c == b'{' {
            depth += 1;
        } else if c == b'}' {
            depth -= 1;
            if depth == 0 {
                return (src[start + 1..i].to_string(), i + 1);
            }
        }
        i += 1;
    }
    (src[start + 1..].to_string(), src.len())
}

pub(super) fn is_ident_start(c: char) -> bool {
    c.is_ascii_alphabetic() || c == '_' || c == '$'
}

pub(super) fn read_ident(src: &str, start: usize) -> (String, usize) {
    let mut end = start;
    for (idx, c) in src[start..].char_indices() {
        if idx == 0 {
            if !is_ident_start(c) {
                return (String::new(), start + 1);
            }
            end = start + c.len_utf8();
            continue;
        }
        if c.is_ascii_alphanumeric() || c == '_' || c == '$' {
            end = start + idx + c.len_utf8();
        } else {
            break;
        }
    }
    (src[start..end].to_string(), end)
}

/// Walk an expression until `,`, `)`, or `;` at paren/bracket/brace depth 0.
pub(super) fn scan_js_expression_until(src: &str, start: usize) -> usize {
    let bytes = src.as_bytes();
    let mut i = start;
    let mut paren = 0i32;
    let mut bracket = 0i32;
    let mut brace = 0i32;
    while i < bytes.len() {
        let c = bytes[i];
        if paren == 0 && bracket == 0 && brace == 0 && (c == b',' || c == b')' || c == b';') {
            return i;
        }
        match c {
            b'/' => {
                i = skip_regex_or_slash(src, i);
            }
            b'\'' | b'"' => {
                i = skip_quoted(src, i);
            }
            b'`' => {
                i = skip_template_literal(src, i);
            }
            b'(' => {
                paren += 1;
                i += 1;
            }
            b')' => {
                paren -= 1;
                i += 1;
            }
            b'[' => {
                bracket += 1;
                i += 1;
            }
            b']' => {
                bracket -= 1;
                i += 1;
            }
            b'{' => {
                brace += 1;
                i += 1;
            }
            b'}' => {
                brace -= 1;
                i += 1;
            }
            _ => i += 1,
        }
    }
    i
}
