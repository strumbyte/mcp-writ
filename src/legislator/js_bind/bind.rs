use std::rc::Rc;

use crate::legislator::source_bind::{
    MAX_FUNCTION_BODY_BYTES, MAX_SOURCE_FUNCTIONS, MAX_TOOL_BINDINGS, SourceFunction, ToolBinding,
};

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
        if bindings.len() >= MAX_TOOL_BINDINGS {
            break;
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
            let cb = callback_from_args(after_name, functions);
            ToolBinding {
                tool_name: name,
                function_name: cb.fn_name,
                body: cb.body,
                bound: cb.warning.is_none(),
                warning: cb.warning,
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
                body: Rc::default(),
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

/// The handler half of a `tool`/`registerTool` call. `warning` set means
/// the callback expression was *compound* — a logical/conditional/comma/
/// member/call form whose runtime target cannot be proven — so the
/// binding is marked Unbound for review instead of attributing the wrong
/// function body to the tool.
struct CallbackBind {
    fn_name: Option<String>,
    body: Rc<str>,
    warning: Option<String>,
}

/// How one top-level argument classifies for the callback position.
enum ArgClass {
    /// Nothing between the commas/parens.
    Empty,
    /// Provably not function-valued: `{`/`[` literal, string, template,
    /// number, unary literal, or a keyword literal (`null`, `this`, …).
    NonCallback,
    /// A bare identifier — the handler reference resolves by name.
    Ident(String),
    /// A `function`/`async function` expression or an arrow function —
    /// the body slice to analyze.
    Inline { body_start: usize, body_end: usize },
    /// Everything else (member access, call, `?:`, `||`, `&&`, `,`,
    /// `new`, unary, …) — the runtime target is ambiguous.
    Compound,
}

/// Split `after_name` — the text between the tool-name literal and the
/// call's closing `)` — into top-level argument ranges. Strings,
/// templates, and regex literals are skipped so commas inside them do
/// not split.
fn top_level_args(src: &str) -> Vec<(usize, usize)> {
    let bytes = src.as_bytes();
    let mut out = Vec::new();
    let mut depth = 0i32;
    let mut i = 0;
    let mut arg_start = 0;
    while i < bytes.len() && out.len() < 64 {
        match bytes[i] {
            b'(' | b'[' | b'{' => {
                depth += 1;
                i += 1;
            }
            b')' | b']' | b'}' => {
                if depth == 0 {
                    break; // the call's own closer ends the arg list
                }
                depth -= 1;
                i += 1;
            }
            b',' if depth == 0 => {
                out.push((arg_start, i));
                arg_start = i + 1;
                i += 1;
            }
            b'"' | b'\'' => i = skip_quoted(src, i),
            b'`' => i = skip_template_literal(src, i),
            b'/' => i = skip_regex_or_slash(src, i),
            _ => i += 1,
        }
    }
    // Trailing arg: normally ends at the call's `)` (the break above);
    // a malformed or regex-eaten tail still classifies — as Compound.
    out.push((arg_start, i.min(bytes.len())));
    out
}

/// Classify the argument in `src[lo..hi]` — the callback binding only
/// accepts forms whose runtime target is unambiguous.
fn classify_arg(src: &str, lo: usize, hi: usize) -> ArgClass {
    /// The consumed expression must reach the end of the argument —
    /// trailing text means the callback is part of a compound form.
    fn is_whole(src: &str, consumed: usize, hi: usize) -> bool {
        skip_ws_and_comments(src, consumed) >= hi
    }
    /// `=>` directly ahead? On success returns the callback body slice.
    fn arrow_body(src: &str, i: usize, hi: usize) -> Option<ArgClass> {
        let bytes = src.as_bytes();
        let mut i = skip_ws_and_comments(src, i);
        if bytes.get(i) == Some(&b':') {
            // TypeScript return-type annotation between params and `=>`.
            i = skip_ws_and_comments(src, skip_ts_type(src, i + 1));
        }
        if bytes.get(i) != Some(&b'=') || bytes.get(i + 1) != Some(&b'>') {
            return None;
        }
        let body = skip_ws_and_comments(src, i + 2);
        if body >= src.len() {
            return Some(ArgClass::Compound);
        }
        let (body_start, body_end) = if src.as_bytes()[body] == b'{' {
            let (_, end) = extract_brace_block(src, body);
            (body, end)
        } else {
            (body, scan_js_expression_until(src, body))
        };
        if is_whole(src, body_end, hi) {
            Some(ArgClass::Inline {
                body_start,
                body_end,
            })
        } else {
            Some(ArgClass::Compound)
        }
    }

    let bytes = src.as_bytes();
    let i = skip_ws_and_comments(src, lo);
    if i >= hi {
        return ArgClass::Empty;
    }
    match bytes[i] {
        // Literals and obvious non-callback primaries.
        b'{' | b'[' | b'"' | b'\'' | b'`' | b'0'..=b'9' | b'-' | b'+' | b'!' | b'~' => {
            ArgClass::NonCallback
        }
        // `(` opens either arrow params or a parenthesized expression.
        b'(' => match find_matching(src, i, '(', ')') {
            Some(close) => arrow_body(src, close + 1, hi).unwrap_or(ArgClass::Compound),
            None => ArgClass::Compound,
        },
        _ => {
            let Some((ident, next)) = take_ident(src, i) else {
                return ArgClass::Compound;
            };
            match ident.as_str() {
                // Keyword literals are not function-valued.
                "null" | "true" | "false" | "undefined" | "this" | "NaN" | "Infinity" => {
                    ArgClass::NonCallback
                }
                "async" => {
                    let j = skip_ws_and_comments(src, next);
                    match take_ident(src, j).map(|(k, _)| k).as_deref() {
                        Some("function") => classify_fn_expr(src, j, hi),
                        _ => classify_arrow_head(src, j, hi),
                    }
                }
                "function" => classify_fn_expr(src, i, hi),
                // Prefix operators / `new` make the target compound.
                "new" | "typeof" | "delete" | "await" | "yield" | "void" => ArgClass::Compound,
                _ => {
                    if is_whole(src, next, hi) {
                        ArgClass::Ident(ident)
                    } else {
                        // `x => …` or `x: T => …` — a bare-param arrow.
                        classify_arrow_head(src, i, hi)
                    }
                }
            }
        }
    }
}

/// `function`/`async function` expression: the keyword is at `kw_at`.
/// Returns `Inline` with the `{…}` body slice when the expression is the
/// whole argument, `Compound` otherwise.
fn classify_fn_expr(src: &str, kw_at: usize, hi: usize) -> ArgClass {
    let after_kw = kw_at + "function".len();
    let i = skip_ws_and_comments(src, after_kw);
    // Optional function name.
    let name_end = match take_ident(src, i) {
        Some((_, end)) => end,
        None => i,
    };
    let Some(brace) = function_body_brace_after_name(src, name_end) else {
        return ArgClass::Compound;
    };
    let (_, end) = extract_brace_block(src, brace);
    if skip_ws_and_comments(src, end) >= hi {
        ArgClass::Inline {
            body_start: brace,
            body_end: end,
        }
    } else {
        ArgClass::Compound
    }
}

/// Arrow head starting at `head_at`: `<ident> =>` or `(<params>) =>`,
/// each optionally preceded by `async` already consumed and optionally
/// followed by a TS return-type annotation.
fn classify_arrow_head(src: &str, head_at: usize, hi: usize) -> ArgClass {
    let bytes = src.as_bytes();
    let i = skip_ws_and_comments(src, head_at);
    if i >= bytes.len() {
        return ArgClass::Compound;
    }
    let after_params = match bytes[i] {
        b'(' => match find_matching(src, i, '(', ')') {
            Some(close) => close + 1,
            None => return ArgClass::Compound,
        },
        _ => match take_ident(src, i) {
            Some((_, end)) => end,
            None => return ArgClass::Compound,
        },
    };
    let mut j = skip_ws_and_comments(src, after_params);
    if bytes.get(j) == Some(&b':') {
        // `x: T => …` / `(p): T => …` — TS annotation before the arrow.
        j = skip_ws_and_comments(src, skip_ts_type(src, j + 1));
    }
    if bytes.get(j) == Some(&b'=') && bytes.get(j + 1) == Some(&b'>') {
        let body = skip_ws_and_comments(src, j + 2);
        let (body_start, body_end) = if bytes.get(body) == Some(&b'{') {
            let (_, end) = extract_brace_block(src, body);
            (body, end)
        } else {
            (body, scan_js_expression_until(src, body))
        };
        if body_start <= body_end && skip_ws_and_comments(src, body_end) >= hi {
            return ArgClass::Inline {
                body_start,
                body_end,
            };
        }
    }
    ArgClass::Compound
}

/// Resolve the tool's handler argument. Only a single identifier, a
/// `function` expression, or an arrow function is a provable target;
/// compound expressions mark the binding Unbound with a review warning
/// rather than guessing which of the combined names is the handler.
fn callback_from_args(after_name: &str, functions: &[SourceFunction]) -> CallbackBind {
    const AMBIGUOUS: &str = "Unbound: ambiguous callback expression — the handler \
        target is not a plain identifier or function/arrow expression; review required";

    let args = top_level_args(after_name);
    if args.is_empty() {
        return CallbackBind {
            fn_name: None,
            body: Rc::default(),
            warning: None,
        };
    }
    // The handler occupies the last argument position; a config object or
    // options literal there means the callback sits one position earlier.
    let classes: Vec<ArgClass> = args
        .iter()
        .map(|&(lo, hi)| classify_arg(after_name, lo, hi))
        .collect();
    let pick = |class: &ArgClass| -> Option<(Option<String>, Rc<str>)> {
        match class {
            ArgClass::Ident(name) => {
                let body = functions
                    .iter()
                    .find(|f| f.name == *name)
                    .map(|f| Rc::clone(&f.body))
                    .unwrap_or_default();
                Some((Some(name.clone()), body))
            }
            ArgClass::Inline {
                body_start,
                body_end,
            } => {
                // A `{…}` body slice carries its braces; the scanned body
                // is the block's interior.
                let raw = after_name[*body_start..*body_end].trim();
                let inner = raw
                    .strip_prefix('{')
                    .and_then(|r| r.strip_suffix('}'))
                    .unwrap_or(raw);
                Some((None, Rc::from(inner)))
            }
            _ => None,
        }
    };
    let ambiguous = || CallbackBind {
        fn_name: None,
        body: Rc::default(),
        warning: Some(AMBIGUOUS.into()),
    };
    let none = || CallbackBind {
        fn_name: None,
        body: Rc::default(),
        warning: None,
    };
    match classes.last().unwrap() {
        last @ (ArgClass::Ident(_) | ArgClass::Inline { .. }) => {
            let (fn_name, body) = pick(last).unwrap();
            CallbackBind {
                fn_name,
                body,
                warning: None,
            }
        }
        ArgClass::Compound => ambiguous(),
        _ => {
            // Last arg is a literal/empty: look one position back for a
            // single unambiguous callback form.
            let earlier = &classes[..classes.len() - 1];
            let callbackish: Vec<&ArgClass> = earlier
                .iter()
                .filter(|c| matches!(c, ArgClass::Ident(_) | ArgClass::Inline { .. }))
                .collect();
            if callbackish.len() == 1 && earlier.iter().all(|c| !matches!(c, ArgClass::Compound)) {
                let (fn_name, body) = pick(callbackish[0]).unwrap();
                CallbackBind {
                    fn_name,
                    body,
                    warning: None,
                }
            } else if callbackish.is_empty()
                && earlier
                    .iter()
                    .all(|c| matches!(c, ArgClass::Empty | ArgClass::NonCallback))
            {
                none()
            } else {
                ambiguous()
            }
        }
    }
}

pub fn extract_functions(source: &str) -> Vec<SourceFunction> {
    let mut out = Vec::new();
    let mut body_bytes = 0usize;
    let bytes = source.as_bytes();
    let mut scan = JsScan::new();
    while scan.i < bytes.len() {
        if out.len() >= MAX_SOURCE_FUNCTIONS || body_bytes >= MAX_FUNCTION_BODY_BYTES {
            break;
        }
        if scan.skip_inert(source) {
            continue;
        }
        if let Some((name, body_start)) = match_fn_decl(source, scan.i)
            && body_start < bytes.len()
            && bytes[body_start] == b'{'
        {
            let (body, end) = extract_brace_block(source, body_start);
            body_bytes += body.len();
            out.push(SourceFunction {
                name,
                body: Rc::from(body),
            });
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
