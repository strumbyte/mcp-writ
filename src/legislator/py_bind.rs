use crate::legislator::source_bind::{SourceFunction, ToolBinding};

/// Bind literal decorators and `add_tool` calls without executing Python.
/// This bounded scanner avoids a full interpreter/parser dependency; dynamic
/// registrations remain unresolved and need manual review.
pub fn bind_python(source: &str) -> Vec<ToolBinding> {
    let functions = extract_functions(source);
    let mut bindings = Vec::new();
    collect_decorator_bindings(source, &functions, &mut bindings);
    collect_add_tool_bindings(source, &functions, &mut bindings);
    bindings
}

pub fn extract_functions(source: &str) -> Vec<SourceFunction> {
    let lines: Vec<&str> = source.lines().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < lines.len() {
        let trimmed = lines[i].trim_start();
        if let Some(name) = def_name(trimmed) {
            let def_indent = indent_width(lines[i]);
            let (body, next) = function_body(&lines, i, def_indent);
            out.push(SourceFunction { name, body });
            i = next;
            continue;
        }
        i += 1;
    }
    out
}

fn def_name(trimmed: &str) -> Option<String> {
    let rest = if let Some(r) = trimmed.strip_prefix("async def ") {
        r
    } else {
        trimmed.strip_prefix("def ")?
    };
    let name: String = rest
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
        .collect();
    if name.is_empty() || !is_ident_start(name.chars().next()?) {
        return None;
    }
    Some(name)
}

fn is_ident_start(c: char) -> bool {
    c.is_ascii_alphabetic() || c == '_'
}

fn indent_width(line: &str) -> usize {
    line.chars().take_while(|c| *c == ' ' || *c == '\t').count()
}

fn function_body(lines: &[&str], def_idx: usize, def_indent: usize) -> (String, usize) {
    let mut i = def_idx + 1;
    while i < lines.len() {
        let t = lines[i].trim();
        if t.is_empty() || t.starts_with('#') {
            i += 1;
            continue;
        }
        break;
    }
    if i >= lines.len() {
        return (String::new(), i);
    }
    let body_indent = indent_width(lines[i]);
    if body_indent <= def_indent {
        return (String::new(), i);
    }
    let mut body = String::new();
    while i < lines.len() {
        let raw = lines[i];
        let t = raw.trim();
        if t.is_empty() {
            body.push('\n');
            i += 1;
            continue;
        }
        if indent_width(raw) < body_indent {
            break;
        }
        if !body.is_empty() {
            body.push('\n');
        }
        body.push_str(raw);
        i += 1;
    }
    (body, i)
}

fn collect_decorator_bindings(
    source: &str,
    functions: &[SourceFunction],
    out: &mut Vec<ToolBinding>,
) {
    let lines: Vec<&str> = source.lines().collect();
    let mut pending: Vec<String> = Vec::new();
    let mut i = 0;
    while i < lines.len() {
        let trimmed = lines[i].trim_start();
        if let Some(deco) = take_tool_decorator(&lines, &mut i) {
            pending.push(deco);
            continue;
        }
        if trimmed.starts_with('@') {
            i += 1;
            continue;
        }
        if trimmed.is_empty() || trimmed.starts_with('#') {
            i += 1;
            continue;
        }
        if let Some(fn_name) = def_name(trimmed) {
            let body = functions
                .iter()
                .find(|f| f.name == fn_name)
                .map(|f| f.body.clone())
                .unwrap_or_default();
            for deco in pending.drain(..) {
                out.push(binding_from_decorator(&deco, &fn_name, &body));
            }
            i += 1;
            continue;
        }
        pending.clear();
        i += 1;
    }
}

fn take_tool_decorator(lines: &[&str], i: &mut usize) -> Option<String> {
    let trimmed = lines.get(*i)?.trim_start();
    if !is_tool_decorator_start(trimmed) {
        return None;
    }
    let mut text = trimmed.to_string();
    *i += 1;
    if !trimmed.contains('(') {
        return Some(text);
    }
    while paren_balance(&text) > 0 && *i < lines.len() {
        text.push(' ');
        text.push_str(lines[*i].trim());
        *i += 1;
    }
    Some(text)
}

fn is_tool_decorator_start(trimmed: &str) -> bool {
    let rest = match trimmed.strip_prefix('@') {
        Some(r) => r,
        None => return false,
    };
    let ident: String = rest
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
        .collect();
    if ident.is_empty() {
        return false;
    }
    rest[ident.len()..].starts_with(".tool")
}

fn paren_balance(s: &str) -> i32 {
    let mut n = 0i32;
    for c in s.chars() {
        if c == '(' {
            n += 1;
        } else if c == ')' {
            n -= 1;
        }
    }
    n
}

fn binding_from_decorator(deco: &str, fn_name: &str, body: &str) -> ToolBinding {
    match decorator_tool_name(deco, fn_name) {
        DecoratorName::Literal(name) => ToolBinding {
            tool_name: name,
            function_name: Some(fn_name.to_string()),
            body: body.to_string(),
            bound: true,
            warning: None,
        },
        DecoratorName::Unbound(reason) => ToolBinding {
            tool_name: fn_name.to_string(),
            function_name: Some(fn_name.to_string()),
            body: body.to_string(),
            bound: false,
            warning: Some(reason),
        },
    }
}

enum DecoratorName {
    Literal(String),
    Unbound(String),
}

fn decorator_tool_name(deco: &str, fn_name: &str) -> DecoratorName {
    let Some(open) = deco.find('(') else {
        return DecoratorName::Literal(fn_name.to_string());
    };
    let close = deco.rfind(')').unwrap_or(deco.len());
    if close <= open {
        return DecoratorName::Literal(fn_name.to_string());
    }
    let inner = deco[open + 1..close].trim();
    if inner.is_empty() {
        return DecoratorName::Literal(fn_name.to_string());
    }
    if let Some(lit) = named_string_kwarg(inner, "name") {
        return DecoratorName::Literal(lit);
    }
    if has_name_kwarg(inner) {
        return DecoratorName::Unbound(format!("Unbound: dynamic tool name in decorator ({deco})"));
    }
    DecoratorName::Literal(fn_name.to_string())
}

fn has_name_kwarg(inner: &str) -> bool {
    named_kwarg_value(inner, "name").is_some()
}

fn is_ident_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

fn named_string_kwarg(inner: &str, key: &str) -> Option<String> {
    let value = named_kwarg_value(inner, key)?;
    take_plain_string_literal(value)
}

fn named_kwarg_value<'a>(inner: &'a str, key: &str) -> Option<&'a str> {
    for (i, _) in inner.char_indices() {
        if inner[i..].starts_with(key) {
            let before_ok = i == 0 || !is_ident_byte(inner.as_bytes()[i - 1]);
            let after = i + key.len();
            if before_ok && inner.is_char_boundary(after) {
                let rest = inner[after..].trim_start();
                if let Some(eq) = rest.strip_prefix('=') {
                    return Some(eq.trim_start());
                }
            }
        }
    }
    None
}

fn take_plain_string_literal(s: &str) -> Option<String> {
    let s = s.trim_start();
    let quote = s.chars().next()?;
    if quote != '"' && quote != '\'' {
        return None;
    }
    if s.starts_with("'''") || s.starts_with("\"\"\"") || s.starts_with("f") || s.starts_with("F") {
        return None;
    }
    let mut out = String::new();
    let mut chars = s[1..].chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            return None;
        }
        if c == quote {
            let rest = chars.as_str().trim_start();
            if rest.is_empty() || rest.starts_with(',') || rest.starts_with('#') {
                return Some(out);
            }
            return None;
        }
        out.push(c);
    }
    None
}

fn collect_add_tool_bindings(
    source: &str,
    functions: &[SourceFunction],
    out: &mut Vec<ToolBinding>,
) {
    let scan = strip_py_strings_and_comments(source);
    let bytes = scan.as_bytes();
    let needle = b"add_tool";
    let mut i = 0;
    while i + needle.len() < bytes.len() {
        if &bytes[i..i + needle.len()] == needle {
            let before_ok = i == 0 || !is_ident_byte(bytes[i - 1]);
            let after = i + needle.len();
            let after_ok = after >= bytes.len() || !is_ident_byte(bytes[after]);
            if before_ok && after_ok {
                let rest = source[after..].trim_start();
                if let Some(args) = rest.strip_prefix('(') {
                    out.push(parse_add_tool_args(args, functions));
                }
            }
        }
        i += 1;
    }
}

fn parse_add_tool_args(after_paren: &str, functions: &[SourceFunction]) -> ToolBinding {
    let trimmed = after_paren.trim_start();
    if let Some(name) = take_plain_string_literal(trimmed) {
        let after_str = skip_string_literal(trimmed);
        let after_comma = after_str
            .trim_start()
            .strip_prefix(',')
            .unwrap_or("")
            .trim_start();
        let fn_name = leading_ident(after_comma);
        let body = fn_name
            .as_ref()
            .and_then(|n| functions.iter().find(|f| f.name == *n))
            .map(|f| f.body.clone())
            .unwrap_or_default();
        return ToolBinding {
            tool_name: name,
            function_name: fn_name,
            body,
            bound: true,
            warning: None,
        };
    }
    ToolBinding {
        tool_name: "<unbound>".into(),
        function_name: None,
        body: String::new(),
        bound: false,
        warning: Some("Unbound: add_tool first argument is not a string literal".into()),
    }
}

fn skip_string_literal(s: &str) -> &str {
    let s = s.trim_start();
    let quote = match s.chars().next() {
        Some(q) if q == '"' || q == '\'' => q,
        _ => return s,
    };
    let mut idx = 1;
    let bytes = s.as_bytes();
    while idx < bytes.len() {
        if bytes[idx] == b'\\' {
            idx += 2;
            continue;
        }
        if bytes[idx] == quote as u8 {
            return &s[idx + 1..];
        }
        idx += 1;
    }
    &s[s.len()..]
}

fn leading_ident(s: &str) -> Option<String> {
    let s = s.trim_start();
    let mut out = String::new();
    for c in s.chars() {
        if out.is_empty() {
            if !is_ident_start(c) {
                return None;
            }
            out.push(c);
        } else if c.is_ascii_alphanumeric() || c == '_' {
            out.push(c);
        } else {
            break;
        }
    }
    if out.is_empty() { None } else { Some(out) }
}

/// Replace string literals and comments with spaces so scanners ignore them.
///
/// f-string / fr-string literal text is blanked, but `{...}` replacement
/// expressions are kept so sinks inside interpolations stay visible.
pub(crate) fn strip_py_strings_and_comments(source: &str) -> String {
    let mut out = String::with_capacity(source.len());
    mask_py_code(source, 0, source.len(), &mut out, false);
    out
}

fn mask_py_code(
    src: &str,
    mut i: usize,
    end: usize,
    out: &mut String,
    until_rbrace: bool,
) -> usize {
    let bytes = src.as_bytes();
    let mut depth = if until_rbrace { 1 } else { 0 };
    while i < end {
        if until_rbrace && depth == 0 {
            return i;
        }
        if bytes[i] == b'#' {
            i = blank_py_comment(src, i, out);
            continue;
        }
        if let Some(kind) = py_string_kind_at(src, i) {
            if kind.is_fstring {
                i = mask_py_fstring(src, kind, out);
            } else {
                i = blank_py_quoted(src, kind, out);
            }
            continue;
        }
        let c = src[i..].chars().next().unwrap_or('\0');
        if until_rbrace {
            if c == '{' {
                depth += 1;
            } else if c == '}' {
                depth -= 1;
                out.push('}');
                i += 1;
                if depth == 0 {
                    return i;
                }
                continue;
            }
        }
        out.push(c);
        i += c.len_utf8();
    }
    i
}

pub(crate) struct PyStringKind {
    pub(crate) prefix_at: usize,
    pub(crate) quote_at: usize,
    pub(crate) quote: u8,
    pub(crate) triple: bool,
    pub(crate) is_fstring: bool,
}

impl PyStringKind {
    pub(crate) fn body_start(&self) -> usize {
        if self.triple {
            self.quote_at + 3
        } else {
            self.quote_at + 1
        }
    }
}

pub(crate) fn py_string_kind_at(src: &str, i: usize) -> Option<PyStringKind> {
    let bytes = src.as_bytes();
    if i >= bytes.len() {
        return None;
    }
    let ident_start = i == 0 || !is_ident_byte(bytes[i - 1]);
    let (quote_at, is_fstring) = if ident_start && is_ident_start(bytes[i] as char) {
        let mut j = i;
        while j < bytes.len() && is_ident_byte(bytes[j]) {
            j += 1;
        }
        let prefix = &src[i..j];
        if !is_py_string_prefix(prefix) {
            return quote_kind_at(src, i, false);
        }
        if bytes.get(j) != Some(&b'"') && bytes.get(j) != Some(&b'\'') {
            return None;
        }
        (j, is_py_fstring_prefix(prefix))
    } else {
        return quote_kind_at(src, i, false);
    };
    quote_kind_from(src, i, quote_at, is_fstring)
}

fn quote_kind_at(src: &str, i: usize, is_fstring: bool) -> Option<PyStringKind> {
    quote_kind_from(src, i, i, is_fstring)
}

fn quote_kind_from(
    src: &str,
    prefix_at: usize,
    quote_at: usize,
    is_fstring: bool,
) -> Option<PyStringKind> {
    let bytes = src.as_bytes();
    let quote = *bytes.get(quote_at)?;
    if quote != b'"' && quote != b'\'' {
        return None;
    }
    let triple =
        quote_at + 2 < bytes.len() && bytes[quote_at + 1] == quote && bytes[quote_at + 2] == quote;
    Some(PyStringKind {
        prefix_at,
        quote_at,
        quote,
        triple,
        is_fstring,
    })
}

pub(crate) fn is_py_string_prefix(prefix: &str) -> bool {
    matches!(
        prefix.to_ascii_lowercase().as_str(),
        "r" | "u" | "f" | "b" | "fr" | "rf" | "br" | "rb"
    )
}

pub(crate) fn is_py_fstring_prefix(prefix: &str) -> bool {
    let lower = prefix.to_ascii_lowercase();
    lower.contains('f') && !lower.contains('b')
}

fn blank_py_comment(src: &str, start: usize, out: &mut String) -> usize {
    let bytes = src.as_bytes();
    let mut i = start;
    while i < bytes.len() {
        if bytes[i] == b'\n' {
            out.push('\n');
            return i + 1;
        }
        out.push(' ');
        i += 1;
    }
    i
}

fn emit_spaces(out: &mut String, src: &str, from: usize, to: usize) {
    let bytes = src.as_bytes();
    let to = to.min(bytes.len());
    let from = from.min(to);
    for &b in &bytes[from..to] {
        out.push(if b == b'\n' { '\n' } else { ' ' });
    }
}

fn blank_py_quoted(src: &str, kind: PyStringKind, out: &mut String) -> usize {
    emit_spaces(out, src, kind.prefix_at, kind.quote_at);
    let end = skip_py_quoted_end(src, kind.quote_at, kind.quote, kind.triple);
    emit_spaces(out, src, kind.quote_at, end);
    end
}

pub(crate) fn skip_py_quoted_end(src: &str, quote_at: usize, quote: u8, triple: bool) -> usize {
    let bytes = src.as_bytes();
    let mut i = if triple { quote_at + 3 } else { quote_at + 1 };
    while i < bytes.len() {
        if bytes[i] == b'\\' {
            i += 1;
            if i < bytes.len() {
                i += 1;
            }
            continue;
        }
        if triple {
            if i + 2 < bytes.len()
                && bytes[i] == quote
                && bytes[i + 1] == quote
                && bytes[i + 2] == quote
            {
                return i + 3;
            }
            i += 1;
        } else if bytes[i] == quote {
            return i + 1;
        } else if bytes[i] == b'\n' {
            return i;
        } else {
            i += 1;
        }
    }
    bytes.len()
}

/// Skip f-string literal text. If `stop_at_interp`, return at `{` so the caller
/// can scan the replacement expression. `{{` is literal.
pub(crate) fn skip_fstring_static(
    src: &str,
    start: usize,
    quote: u8,
    triple: bool,
    stop_at_interp: bool,
) -> usize {
    let bytes = src.as_bytes();
    let mut i = start;
    while i < bytes.len() {
        if bytes[i] == b'\\' {
            i += 1;
            if i < bytes.len() {
                i += 1;
            }
            continue;
        }
        if bytes[i] == b'{' && bytes.get(i + 1) == Some(&b'{') {
            i += 2;
            continue;
        }
        if bytes[i] == b'}' && bytes.get(i + 1) == Some(&b'}') {
            i += 2;
            continue;
        }
        if stop_at_interp && bytes[i] == b'{' {
            return i;
        }
        if triple {
            if i + 2 < bytes.len()
                && bytes[i] == quote
                && bytes[i + 1] == quote
                && bytes[i + 2] == quote
            {
                return i + 3;
            }
            i += 1;
        } else if bytes[i] == quote {
            return i + 1;
        } else if bytes[i] == b'\n' {
            return i;
        } else {
            i += 1;
        }
    }
    bytes.len()
}

fn mask_py_fstring(src: &str, kind: PyStringKind, out: &mut String) -> usize {
    emit_spaces(out, src, kind.prefix_at, kind.quote_at);
    emit_spaces(out, src, kind.quote_at, kind.body_start());
    let mut i = kind.body_start();
    loop {
        let n = skip_fstring_static(src, i, kind.quote, kind.triple, true);
        emit_spaces(out, src, i, n);
        if src.as_bytes().get(n) == Some(&b'{') {
            out.push('{');
            i = mask_py_code(src, n + 1, src.len(), out, true);
            continue;
        }
        return n;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn fixture(name: &str) -> String {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/py_mcp")
            .join(name);
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
    }

    fn bound_names(src: &str) -> Vec<String> {
        bind_python(src)
            .into_iter()
            .filter(|b| b.bound)
            .map(|b| b.tool_name)
            .collect()
    }

    #[test]
    fn decorator_uses_function_name() {
        let src = fixture("fastmcp_literal.py");
        let names = bound_names(&src);
        assert!(names.contains(&"read_file".into()), "{names:?}");
        let b = bind_python(&src)
            .into_iter()
            .find(|b| b.tool_name == "read_file")
            .unwrap();
        assert_eq!(b.function_name.as_deref(), Some("read_file"));
        assert!(b.bound);
    }

    #[test]
    fn decorator_literal_name_kwarg() {
        let src = fixture("named_tool.py");
        let names = bound_names(&src);
        assert!(names.contains(&"custom_read".into()), "{names:?}");
        let b = bind_python(&src)
            .into_iter()
            .find(|b| b.tool_name == "custom_read")
            .unwrap();
        assert_eq!(b.function_name.as_deref(), Some("impl_read"));
    }

    #[test]
    fn server_tool_decorator() {
        let src = r#"
@server.tool()
def list_files(path: str):
    return os.listdir(path)
"#;
        assert_eq!(bound_names(src), vec!["list_files"]);
    }

    #[test]
    fn add_tool_literal() {
        let src = fixture("add_tool_literal.py");
        let names = bound_names(&src);
        assert!(names.contains(&"literal_tool".into()), "{names:?}");
        let b = bind_python(&src)
            .into_iter()
            .find(|b| b.tool_name == "literal_tool")
            .unwrap();
        assert_eq!(b.function_name.as_deref(), Some("handle_literal"));
        assert!(b.body.contains("return"));
    }

    #[test]
    fn strip_keeps_byte_offsets_for_multibyte_string_literals() {
        let src = "msg = \"日本語\"\nmcp.add_tool(\"literal_tool\", handle_literal)\n";
        let scan = strip_py_strings_and_comments(src);
        assert_eq!(scan.len(), src.len());
        let at = scan.find("add_tool").expect("add_tool remains aligned");
        assert_eq!(&src[at..at + 8], "add_tool");
        let names = bound_names(src);
        assert_eq!(names, vec!["literal_tool"]);
    }

    #[test]
    fn dynamic_name_is_unbound() {
        let src = fixture("unbound_dynamic.py");
        let bindings = bind_python(&src);
        assert!(
            bindings
                .iter()
                .any(|b| !b.bound && b.warning.as_deref().is_some_and(|w| w.contains("Unbound"))),
            "{bindings:?}"
        );
        assert!(!bindings.iter().any(|b| b.bound && b.tool_name == "dynamic"));
    }

    #[test]
    fn add_tool_dynamic_first_arg_unbound() {
        let src = r#"
def fn():
    return 1
mcp.add_tool(os.environ["X"], fn)
"#;
        let bindings = bind_python(src);
        assert!(bindings.iter().any(|b| !b.bound));
        assert!(!bindings.iter().any(|b| b.bound));
    }

    #[test]
    fn multiline_decorator_name() {
        let src = r#"
@mcp.tool(
    name="pretty",
    description="x",
)
def inner():
    pass
"#;
        assert_eq!(bound_names(src), vec!["pretty"]);
    }

    #[test]
    fn japanese_description_before_name_does_not_panic() {
        let src = r#"
@mcp.tool(description="説明", name="read_file")
def read_file(path):
    return open(path).read()
"#;
        let names = bound_names(src);
        assert_eq!(names, vec!["read_file"]);
    }

    #[test]
    fn emoji_description_before_name_does_not_panic() {
        let src = r#"
@mcp.tool(description="🔍", name="scan")
def scan(path):
    return path
"#;
        assert_eq!(bound_names(src), vec!["scan"]);
    }
}
