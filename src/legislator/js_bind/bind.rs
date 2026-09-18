use crate::legislator::source_bind::{SourceFunction, ToolBinding};

use super::lex::*;

/// Shallow JS/TS binder: literal `server.tool("name"` / `registerTool("name"`.
/// Template literals and non-literal first arguments are Unbound.
pub fn bind_js(source: &str) -> Vec<ToolBinding> {
    let functions = extract_functions(source);
    let mut bindings = Vec::new();
    let mut scan = JsScan::new();
    let bytes = source.as_bytes();
    while scan.i < bytes.len() {
        if scan.skip_inert(source) {
            continue;
        }
        if let Some((kind, start)) = match_tool_call(source, scan.i) {
            let after = match kind {
                CallKind::DotTool => start + ".tool".len(),
                CallKind::RegisterTool => start + "registerTool".len(),
            };
            let rest = source[after..].trim_start();
            if let Some(args) = rest.strip_prefix('(') {
                bindings.push(parse_js_tool_args(args, &functions));
                scan.i = after + 1;
                continue;
            }
        }
        scan.bump(source);
    }
    bindings
}

#[derive(Clone, Copy)]
enum CallKind {
    DotTool,
    RegisterTool,
}

fn match_tool_call(source: &str, i: usize) -> Option<(CallKind, usize)> {
    let rest = source.get(i..)?;
    if rest.starts_with(".tool") {
        let after = i + ".tool".len();
        let next = source.as_bytes().get(after).copied();
        if next.is_none_or(|b| !is_ident_byte(b)) {
            return Some((CallKind::DotTool, i));
        }
    }
    if rest.starts_with("registerTool") {
        let before_ok = i == 0 || !is_ident_byte(source.as_bytes()[i - 1]);
        let after = i + "registerTool".len();
        let after_ok = source
            .as_bytes()
            .get(after)
            .is_none_or(|b| !is_ident_byte(*b));
        if before_ok && after_ok {
            return Some((CallKind::RegisterTool, i));
        }
    }
    None
}

fn parse_js_tool_args(after_paren: &str, functions: &[SourceFunction]) -> ToolBinding {
    let trimmed = after_paren.trim_start();
    match take_js_string_literal(trimmed) {
        Some((name, after_name)) => {
            let (fn_name, body) = callback_from_args(after_name, functions);
            ToolBinding {
                tool_name: name,
                function_name: fn_name,
                body,
                bound: true,
                warning: None,
            }
        }
        None => {
            let reason = if trimmed.starts_with('`') {
                "Unbound: template literal tool name"
            } else {
                "Unbound: tool name is not a string literal"
            };
            ToolBinding {
                tool_name: "<unbound>".into(),
                function_name: None,
                body: String::new(),
                bound: false,
                warning: Some(reason.into()),
            }
        }
    }
}

fn take_js_string_literal(s: &str) -> Option<(String, &str)> {
    let s = s.trim_start();
    let quote = s.chars().next()?;
    if quote != '"' && quote != '\'' {
        return None;
    }
    let mut out = String::new();
    let mut idx = 1;
    let bytes = s.as_bytes();
    while idx < bytes.len() {
        let c = bytes[idx];
        if c == b'\\' {
            return None;
        }
        if c == quote as u8 {
            return Some((out, &s[idx + 1..]));
        }
        out.push(s[idx..].chars().next()?);
        idx += s[idx..].chars().next()?.len_utf8();
    }
    None
}

fn callback_from_args(after_name: &str, functions: &[SourceFunction]) -> (Option<String>, String) {
    let mut depth = 1i32;
    let mut i = 0;
    let bytes = after_name.as_bytes();
    let mut last_ident: Option<String> = None;
    let mut inline_body: Option<String> = None;
    while i < bytes.len() && depth > 0 {
        let c = bytes[i] as char;
        match c {
            '(' => {
                depth += 1;
                i += 1;
            }
            ')' => {
                depth -= 1;
                i += 1;
            }
            '"' | '\'' => {
                i = skip_quoted(after_name, i);
            }
            '`' => {
                i = skip_template_literal(after_name, i);
            }
            '/' => {
                i = skip_regex_or_slash(after_name, i);
            }
            '=' if bytes.get(i + 1) == Some(&b'>') => {
                let after_arrow = skip_ws_and_comments(after_name, i + 2);
                if inline_body.is_none() && after_arrow < bytes.len() && bytes[after_arrow] != b'{'
                {
                    let end = scan_js_expression_until(after_name, after_arrow);
                    if end > after_arrow {
                        inline_body = Some(after_name[after_arrow..end].trim().to_string());
                    }
                    i = end.max(i + 2);
                } else {
                    i += 2;
                }
            }
            '{' => {
                if inline_body.is_none() && looks_like_function_before(after_name, i) {
                    let (body, end) = extract_brace_block(after_name, i);
                    inline_body = Some(body);
                    i = end;
                } else {
                    let (_, end) = extract_brace_block(after_name, i);
                    i = end;
                }
            }
            c if is_ident_start(c) => {
                let (ident, next) = read_ident(after_name, i);
                if ident != "async" && ident != "function" && ident != "await" {
                    last_ident = Some(ident);
                }
                i = next;
            }
            _ => i += 1,
        }
    }
    if let Some(body) = inline_body {
        return (None, body);
    }
    if let Some(name) = last_ident {
        let body = functions
            .iter()
            .find(|f| f.name == name)
            .map(|f| f.body.clone())
            .unwrap_or_default();
        return (Some(name), body);
    }
    (None, String::new())
}

fn looks_like_function_before(src: &str, brace_at: usize) -> bool {
    let before = src[..brace_at].trim_end();
    before.ends_with("=>")
        || before.ends_with(')')
        || before.ends_with("function")
        || before.ends_with("=> {")
}

pub fn extract_functions(source: &str) -> Vec<SourceFunction> {
    let mut out = Vec::new();
    let bytes = source.as_bytes();
    let mut scan = JsScan::new();
    while scan.i < bytes.len() {
        if scan.skip_inert(source) {
            continue;
        }
        if let Some((name, body_start)) = match_fn_decl(source, scan.i)
            && body_start < bytes.len()
            && bytes[body_start] == b'{'
        {
            let (body, end) = extract_brace_block(source, body_start);
            out.push(SourceFunction { name, body });
            scan.i = end;
            continue;
        }
        scan.bump(source);
    }
    out
}

fn match_fn_decl(source: &str, i: usize) -> Option<(String, usize)> {
    let rest = source.get(i..)?;
    let before_ok = i == 0 || !is_ident_byte(source.as_bytes()[i - 1]);
    if !before_ok {
        return None;
    }
    for prefix in [
        "async function ",
        "function ",
        "async function*",
        "function* ",
    ] {
        if let Some(after) = rest.strip_prefix(prefix) {
            let after_at = i + prefix.len();
            let trimmed = after.trim_start();
            let trim_off = after.len() - trimmed.len();
            let (name, name_end) = read_ident(source, after_at + trim_off);
            if name.is_empty() {
                continue;
            }
            if let Some(brace) = function_body_brace_after_name(source, name_end) {
                return Some((name, brace));
            }
        }
    }
    for prefix in ["const ", "let ", "var "] {
        if let Some(after_kw) = rest.strip_prefix(prefix) {
            let kw_at = i + prefix.len();
            let trimmed = after_kw.trim_start();
            let trim_off = after_kw.len() - trimmed.len();
            let name_at = kw_at + trim_off;
            let (name, name_end) = read_ident(source, name_at);
            if name.is_empty() {
                continue;
            }
            if let Some(rel) = source[name_end..].find('{') {
                let between = source[name_end..name_end + rel].trim();
                if between.contains('=') && (between.contains("=>") || between.contains("function"))
                {
                    return Some((name, name_end + rel));
                }
            }
        }
    }
    None
}

/// `{` of the function body: skip destructuring `{` in the parameter list, then
/// TypeScript return types, newlines, and comments. Does not search for a later
/// `{`, so a different declaration's body cannot be attached to this name.
fn function_body_brace_after_name(source: &str, name_end: usize) -> Option<usize> {
    let i = skip_ws_and_comments(source, name_end);
    if source.as_bytes().get(i) != Some(&b'(') {
        return None;
    }
    let close = find_matching(source, i, '(', ')')?;
    let mut i = skip_ws_and_comments(source, close + 1);
    if source.as_bytes().get(i) == Some(&b':') {
        i = skip_ts_type(source, i + 1);
        i = skip_ws_and_comments(source, i);
    }
    if source.as_bytes().get(i) == Some(&b'{') {
        Some(i)
    } else {
        None
    }
}

/// Skip a TypeScript type so the following `{` is the function body, not an
/// object type or a later declaration.
fn skip_ts_type(source: &str, start: usize) -> usize {
    let bytes = source.as_bytes();
    let mut i = start;
    let mut paren = 0i32;
    let mut bracket = 0i32;
    let mut angle = 0i32;
    let mut brace = 0i32;
    let mut seen_atom = false;
    loop {
        i = skip_ws_and_comments(source, i);
        if i >= bytes.len() {
            return i;
        }
        let b = bytes[i];
        let depth0 = paren == 0 && bracket == 0 && angle == 0 && brace == 0;
        if depth0 && b == b'{' && seen_atom {
            return i;
        }
        if depth0 && matches!(b, b';' | b',' | b')') {
            return i;
        }
        match b {
            b'"' | b'\'' => {
                i = skip_quoted(source, i);
                seen_atom = true;
            }
            b'`' => {
                i = skip_template_literal(source, i);
                seen_atom = true;
            }
            b'/' => i = skip_regex_or_slash(source, i),
            b'(' => {
                paren += 1;
                i += 1;
            }
            b')' => {
                if paren == 0 {
                    return i;
                }
                paren -= 1;
                i += 1;
                seen_atom = true;
            }
            b'[' => {
                bracket += 1;
                i += 1;
            }
            b']' => {
                if bracket == 0 {
                    return i;
                }
                bracket -= 1;
                i += 1;
                seen_atom = true;
            }
            b'{' => {
                brace += 1;
                i += 1;
            }
            b'}' => {
                if brace == 0 {
                    return i;
                }
                brace -= 1;
                i += 1;
                seen_atom = true;
            }
            b'<' => {
                angle += 1;
                i += 1;
            }
            b'>' => {
                if angle == 0 {
                    return i;
                }
                angle -= 1;
                i += 1;
                seen_atom = true;
            }
            b'|' | b'&' | b'?' | b':' => {
                seen_atom = false;
                i += 1;
            }
            b'=' if bytes.get(i + 1) == Some(&b'>') => {
                seen_atom = false;
                i += 2;
            }
            _ => {
                if let Some((ident, next)) = take_ident(source, i) {
                    if depth0 && seen_atom && is_fn_body_stop_ident(&ident) {
                        return i;
                    }
                    seen_atom = true;
                    i = next;
                } else {
                    i = next_index(source, i);
                }
            }
        }
    }
}

fn is_fn_body_stop_ident(name: &str) -> bool {
    matches!(
        name,
        "function"
            | "async"
            | "const"
            | "let"
            | "var"
            | "class"
            | "export"
            | "import"
            | "return"
            | "interface"
            | "type"
            | "enum"
            | "declare"
    )
}
