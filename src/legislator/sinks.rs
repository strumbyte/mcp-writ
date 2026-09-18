use crate::legislator::heuristics::Permission;
use crate::legislator::py_bind::{
    py_string_kind_at, skip_fstring_static, skip_py_quoted_end, strip_py_strings_and_comments,
};
use crate::legislator::source_bind::{InterpreterKind, SourceFunction, ToolBinding};

/// Per-tool Capability derived from bound handler sinks (not ELF-shaped).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolCapability {
    pub tool_name: String,
    pub permissions: Vec<Permission>,
    pub bound: bool,
    pub audit_risks: Vec<String>,
    pub warning: Option<String>,
}

pub fn capabilities_from_bindings(
    bindings: &[ToolBinding],
    functions: &[SourceFunction],
    language: InterpreterKind,
    source: &str,
) -> Vec<ToolCapability> {
    bindings
        .iter()
        .map(|b| {
            if !b.bound {
                return ToolCapability {
                    tool_name: b.tool_name.clone(),
                    permissions: Vec::new(),
                    bound: false,
                    audit_risks: Vec::new(),
                    warning: b.warning.clone(),
                };
            }
            let (permissions, audit_risks) =
                scan_with_one_hop(&b.body, functions, language, false, source);
            ToolCapability {
                tool_name: b.tool_name.clone(),
                permissions,
                bound: true,
                audit_risks,
                warning: b.warning.clone(),
            }
        })
        .collect()
}

fn scan_with_one_hop(
    body: &str,
    functions: &[SourceFunction],
    language: InterpreterKind,
    hopped: bool,
    source: &str,
) -> (Vec<Permission>, Vec<String>) {
    let (mut perms, mut risks) = match language {
        InterpreterKind::Python => scan_python_sinks(body),
        InterpreterKind::Node | InterpreterKind::Npx => scan_js_sinks(body, source),
    };
    if !hopped {
        for helper in functions {
            if contains_call(body, &helper.name) {
                let (hp, hr) = match language {
                    InterpreterKind::Python => scan_python_sinks(&helper.body),
                    InterpreterKind::Node | InterpreterKind::Npx => {
                        scan_js_sinks(&helper.body, source)
                    }
                };
                merge_perms(&mut perms, hp);
                for r in hr {
                    if !risks.contains(&r) {
                        risks.push(r);
                    }
                }
            }
        }
    }
    (perms, risks)
}

fn merge_perms(dst: &mut Vec<Permission>, extra: Vec<Permission>) {
    for p in extra {
        if !dst.contains(&p) {
            dst.push(p);
        }
    }
}

fn contains_call(body: &str, name: &str) -> bool {
    let bytes = body.as_bytes();
    let n = name.as_bytes();
    let mut i = 0;
    while i + n.len() < bytes.len() {
        if &bytes[i..i + n.len()] == n {
            let before_ok = i == 0 || !is_ident_byte(bytes[i - 1]);
            let after = i + n.len();
            if before_ok {
                let rest = body[after..].trim_start();
                if rest.starts_with('(') {
                    return true;
                }
            }
        }
        i += 1;
    }
    false
}

fn is_ident_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || b == b'$'
}

fn scan_python_sinks(body: &str) -> (Vec<Permission>, Vec<String>) {
    let scan = strip_py_strings_and_comments(body);
    let mut perms = Vec::new();
    let mut risks = Vec::new();

    if has_open_write(body) {
        push_perm(&mut perms, Permission::FileWrite);
    }
    if has_open_read(body) || contains_ident_prefix(&scan, "Path.read") {
        push_perm(&mut perms, Permission::FileRead);
    }
    if contains_substr(&scan, "Path.write")
        || contains_substr(&scan, ".write_text(")
        || contains_substr(&scan, ".write_bytes(")
    {
        push_perm(&mut perms, Permission::FileWrite);
    }

    if contains_ident_then_dot(&scan, "subprocess")
        || contains_attr_call(&scan, "os", "system")
        || contains_attr_call(&scan, "os", "popen")
        || contains_os_exec(&scan)
    {
        push_perm(&mut perms, Permission::ProcessExec);
    }

    if contains_substr(&scan, "urllib")
        || contains_substr(&scan, "urlopen")
        || contains_substr(&scan, "requests.")
        || contains_substr(&scan, "httpx")
        || contains_substr(&scan, "socket.")
    {
        push_perm(&mut perms, Permission::NetworkOutbound);
    }

    if contains_call(&scan, "eval") {
        push_risk(&mut risks, "eval");
    }
    if contains_call(&scan, "exec") {
        push_risk(&mut risks, "exec");
    }
    if contains_substr(&scan, "pickle.loads") || contains_substr(&scan, "pickle.load(") {
        push_risk(&mut risks, "pickle.loads");
    }

    (perms, risks)
}

fn scan_js_sinks(body: &str, file_source: &str) -> (Vec<Permission>, Vec<String>) {
    let scan = strip_js_strings_and_comments(body);
    let mut perms = Vec::new();
    let mut risks = Vec::new();

    if crate::legislator::js_bind::body_has_child_process_exec(body, file_source) {
        push_perm(&mut perms, Permission::ProcessExec);
    }
    if contains_substr(&scan, "writeFile")
        || contains_substr(&scan, "appendFile")
        || contains_substr(&scan, "writeFileSync")
    {
        push_perm(&mut perms, Permission::FileWrite);
    }
    if contains_substr(&scan, "readFile") || contains_substr(&scan, "readFileSync") {
        push_perm(&mut perms, Permission::FileRead);
    }
    if contains_substr(&scan, "http.")
        || contains_substr(&scan, "https.")
        || contains_call(&scan, "fetch")
        || contains_substr(&scan, "axios")
        || contains_substr(&scan, "node-fetch")
        || contains_substr(&scan, "net.")
    {
        push_perm(&mut perms, Permission::NetworkOutbound);
    }
    if contains_call(&scan, "eval") {
        push_risk(&mut risks, "eval");
    }
    (perms, risks)
}

fn push_perm(perms: &mut Vec<Permission>, p: Permission) {
    if !perms.contains(&p) {
        perms.push(p);
    }
}

fn push_risk(risks: &mut Vec<String>, r: &str) {
    if !risks.iter().any(|x| x == r) {
        risks.push(r.to_string());
    }
}

fn contains_substr(s: &str, pat: &str) -> bool {
    s.contains(pat)
}

fn contains_ident_prefix(s: &str, prefix: &str) -> bool {
    s.contains(prefix)
}

/// `subprocess.run` / `subprocess . check_output` — not `subprocess_helper`.
fn contains_ident_then_dot(s: &str, name: &str) -> bool {
    let bytes = s.as_bytes();
    let n = name.as_bytes();
    let mut i = 0;
    while i + n.len() < bytes.len() {
        if &bytes[i..i + n.len()] == n {
            let before_ok = i == 0 || !is_ident_byte(bytes[i - 1]);
            let after = i + n.len();
            if before_ok {
                let rest = s[after..].trim_start();
                if rest.starts_with('.') {
                    return true;
                }
            }
        }
        i += 1;
    }
    false
}

fn contains_attr_call(s: &str, obj: &str, attr: &str) -> bool {
    let pat = format!("{obj}.{attr}");
    let bytes = s.as_bytes();
    let n = pat.as_bytes();
    let mut i = 0;
    while i + n.len() <= bytes.len() {
        if &bytes[i..i + n.len()] == n {
            let before_ok = i == 0 || !is_ident_byte(bytes[i - 1]);
            let after = i + n.len();
            if before_ok {
                let rest = s[after..].trim_start();
                if rest.starts_with('(') {
                    return true;
                }
            }
        }
        i += 1;
    }
    false
}

fn contains_os_exec(s: &str) -> bool {
    const NAMES: &[&str] = &[
        "execl", "execle", "execlp", "execlpe", "execv", "execve", "execvp", "execvpe",
    ];
    NAMES.iter().any(|n| contains_attr_call(s, "os", n))
}

fn has_open_write(s: &str) -> bool {
    for args in open_arg_lists(s) {
        if mode_implies_write(&args) {
            return true;
        }
    }
    false
}

fn has_open_read(s: &str) -> bool {
    let mut saw = false;
    for args in open_arg_lists(s) {
        saw = true;
        if !mode_implies_write(&args) {
            return true;
        }
    }
    saw && !has_open_write(s)
}

fn open_arg_lists(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let bytes = s.as_bytes();
    let needle = b"open";
    let mut scan = PyScan::new();
    while scan.i + needle.len() <= bytes.len() {
        if scan.skip_inert(s) {
            continue;
        }
        if &bytes[scan.i..scan.i + needle.len()] == needle {
            let before_ok = scan.i == 0 || !is_ident_byte(bytes[scan.i - 1]);
            let after = scan.i + needle.len();
            let after_ok = after == bytes.len() || !is_ident_byte(bytes[after]);
            if before_ok && after_ok && !scan.preceded_by_dot() {
                let rest_start = skip_py_ws(s, after);
                if bytes.get(rest_start) == Some(&b'(') {
                    out.push(take_paren_args(&s[rest_start + 1..]));
                }
            }
        }
        scan.bump(s);
    }
    out
}

fn skip_py_ws(s: &str, mut i: usize) -> usize {
    let bytes = s.as_bytes();
    while i < bytes.len() && bytes[i].is_ascii_whitespace() {
        i += 1;
    }
    i
}

fn next_py_index(s: &str, i: usize) -> usize {
    s.get(i..)
        .and_then(|rest| rest.chars().next())
        .map(|c| i + c.len_utf8())
        .unwrap_or_else(|| i.saturating_add(1).min(s.len()))
}

struct FStringFrame {
    quote: u8,
    triple: bool,
    interp_depth: i32,
}

struct PyScan {
    i: usize,
    /// Last non-whitespace code byte consumed. Comments never update it;
    /// a skipped string token leaves its closing quote. Used by
    /// `preceded_by_dot` so `.` inside comments/strings cannot leak.
    prev: Option<u8>,
    fstrings: Vec<FStringFrame>,
}

impl PyScan {
    fn new() -> Self {
        Self {
            i: 0,
            prev: None,
            fstrings: Vec::new(),
        }
    }

    /// True when the previous non-whitespace code byte is `.` (`fp.open`,
    /// `Path(p).open`, `p . open`). Attribute receivers are not builtin `open`.
    fn preceded_by_dot(&self) -> bool {
        self.prev == Some(b'.')
    }

    fn in_fstring_static(&self) -> bool {
        self.fstrings.last().is_some_and(|f| f.interp_depth == 0)
    }

    fn in_fstring_interp(&self) -> bool {
        self.fstrings.last().is_some_and(|f| f.interp_depth > 0)
    }

    fn skip_inert(&mut self, src: &str) -> bool {
        let start = self.i;
        if self.in_fstring_static() {
            let frame = self.fstrings.last().expect("f-string frame");
            let n = skip_fstring_static(src, self.i, frame.quote, frame.triple, true);
            if src.as_bytes().get(n) == Some(&b'{') {
                if let Some(frame) = self.fstrings.last_mut() {
                    frame.interp_depth = 1;
                }
                self.i = n + 1;
                self.prev = Some(b'{');
                return true;
            }
            let quote = self.fstrings.pop().expect("f-string frame").quote;
            self.i = n;
            if n > start {
                self.prev = Some(quote);
            }
            return n > start;
        }

        if src.as_bytes().get(self.i) == Some(&b'#') {
            let mut j = self.i + 1;
            let bytes = src.as_bytes();
            while j < bytes.len() && bytes[j] != b'\n' {
                j += 1;
            }
            self.i = j;
            return true;
        }
        if let Some(kind) = py_string_kind_at(src, self.i) {
            if kind.is_fstring {
                self.fstrings.push(FStringFrame {
                    quote: kind.quote,
                    triple: kind.triple,
                    interp_depth: 0,
                });
                self.i = kind.body_start();
                return true;
            }
            self.i = skip_py_quoted_end(src, kind.quote_at, kind.quote, kind.triple);
            self.prev = Some(kind.quote);
            return true;
        }
        false
    }

    fn bump(&mut self, src: &str) {
        let Some(&b) = src.as_bytes().get(self.i) else {
            return;
        };
        if let Some(frame) = self.fstrings.last_mut()
            && frame.interp_depth > 0
        {
            match b {
                b'{' => frame.interp_depth += 1,
                b'}' => frame.interp_depth -= 1,
                _ => {}
            }
        }
        if !b.is_ascii_whitespace() {
            self.prev = Some(b);
        }
        self.i = next_py_index(src, self.i);
    }
}

fn take_paren_args(after_open: &str) -> String {
    let mut scan = PyScan::new();
    let mut depth = 1i32;
    while scan.i < after_open.len() && depth > 0 {
        if scan.skip_inert(after_open) {
            continue;
        }
        let Some(&b) = after_open.as_bytes().get(scan.i) else {
            break;
        };
        if b == b'(' {
            depth += 1;
        } else if b == b')' {
            depth -= 1;
            if depth == 0 {
                break;
            }
        }
        scan.bump(after_open);
    }
    after_open[..scan.i].to_string()
}

fn mode_implies_write(args: &str) -> bool {
    if let Some(mode) = first_string_after_comma(args) {
        return mode_chars_write(&mode);
    }
    if has_mode_kwarg(args) {
        if let Some(mode) = named_mode_literal(args) {
            return mode_chars_write(&mode);
        }
        // Unknown mode expression — fail-secure: treat as write-capable.
        return true;
    }
    false
}

fn mode_chars_write(mode: &str) -> bool {
    mode.contains('w') || mode.contains('a') || mode.contains('x') || mode.contains('+')
}

fn first_string_after_comma(args: &str) -> Option<String> {
    let comma = top_level_comma(args)?;
    take_quoted(&args[comma + 1..])
}

/// First `,` at bracket depth 0 outside string literals, comments, and
/// f-string interpolations. `open("a,b", "w")` must skip the comma inside
/// the filename; `open(f"{a,b}", "w")` must skip the interpolation comma.
fn top_level_comma(args: &str) -> Option<usize> {
    let mut scan = PyScan::new();
    let mut depth = 0i32;
    while scan.i < args.len() {
        if scan.skip_inert(args) {
            continue;
        }
        if !scan.in_fstring_interp() {
            match args.as_bytes()[scan.i] {
                b'(' | b'[' | b'{' => depth += 1,
                b')' | b']' | b'}' => depth = depth.saturating_sub(1),
                b',' if depth == 0 => return Some(scan.i),
                _ => {}
            }
        }
        scan.bump(args);
    }
    None
}

fn has_mode_kwarg(args: &str) -> bool {
    mode_kwarg_value_start(args).is_some()
}

fn named_mode_literal(args: &str) -> Option<String> {
    take_quoted(mode_kwarg_value_start(args)?)
}

/// Value after `mode=` at bracket depth 0, skipping string contents.
/// A `mode=` inside a filename (`open("mode=w.txt")`) or nested call is
/// not a keyword argument.
fn mode_kwarg_value_start(args: &str) -> Option<&str> {
    let bytes = args.as_bytes();
    let needle = b"mode";
    let mut scan = PyScan::new();
    let mut depth = 0i32;
    while scan.i + needle.len() <= bytes.len() {
        if scan.skip_inert(args) {
            continue;
        }
        if !scan.in_fstring_interp() {
            match bytes[scan.i] {
                b'(' | b'[' | b'{' => depth += 1,
                b')' | b']' | b'}' => depth = depth.saturating_sub(1),
                _ => {}
            }
            if depth == 0 && &bytes[scan.i..scan.i + needle.len()] == needle {
                let before_ok = scan.i == 0 || !is_ident_byte(bytes[scan.i - 1]);
                let after = scan.i + needle.len();
                let after_ok = after == bytes.len() || !is_ident_byte(bytes[after]);
                if before_ok && after_ok {
                    let rest = args[after..].trim_start();
                    if let Some(eq) = rest.strip_prefix('=') {
                        return Some(eq);
                    }
                }
            }
        }
        scan.bump(args);
    }
    None
}

fn take_quoted(s: &str) -> Option<String> {
    let s = s.trim_start();
    let q = s.chars().next()?;
    if q != '"' && q != '\'' {
        return None;
    }
    let mut out = String::new();
    let mut escaped = false;
    for c in s[1..].chars() {
        if escaped {
            out.push(c);
            escaped = false;
            continue;
        }
        if c == '\\' {
            escaped = true;
            continue;
        }
        if c == q {
            return Some(out);
        }
        out.push(c);
    }
    None
}

fn strip_js_strings_and_comments(source: &str) -> String {
    let mut out = String::with_capacity(source.len());
    let bytes = source.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'/' && bytes.get(i + 1) == Some(&b'/') {
            out.push(' ');
            out.push(' ');
            i += 2;
            while i < bytes.len() && bytes[i] != b'\n' {
                out.push(' ');
                i += 1;
            }
            continue;
        }
        if bytes[i] == b'/' && bytes.get(i + 1) == Some(&b'*') {
            out.push(' ');
            out.push(' ');
            i += 2;
            while i + 1 < bytes.len() && !(bytes[i] == b'*' && bytes[i + 1] == b'/') {
                out.push(if bytes[i] == b'\n' { '\n' } else { ' ' });
                i += 1;
            }
            i = i.saturating_add(2);
            continue;
        }
        if bytes[i] == b'"' || bytes[i] == b'\'' || bytes[i] == b'`' {
            let q = bytes[i];
            out.push(' ');
            i += 1;
            while i < bytes.len() {
                if bytes[i] == b'\\' {
                    out.push(' ');
                    i += 1;
                    if i < bytes.len() {
                        out.push(if bytes[i] == b'\n' { '\n' } else { ' ' });
                        i += 1;
                    }
                    continue;
                }
                if bytes[i] == q {
                    out.push(' ');
                    i += 1;
                    break;
                }
                out.push(if bytes[i] == b'\n' { '\n' } else { ' ' });
                i += 1;
            }
            continue;
        }
        out.push(bytes[i] as char);
        i += 1;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::legislator::py_bind::{bind_python, extract_functions};
    use crate::legislator::source_bind::analyze_source;
    use std::path::Path;

    fn fixture_path(name: &str) -> std::path::PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/py_mcp")
            .join(name)
    }

    fn fixture(name: &str) -> String {
        std::fs::read_to_string(fixture_path(name)).unwrap()
    }

    fn caps_for(name: &str) -> Vec<ToolCapability> {
        let src = fixture(name);
        let bindings = bind_python(&src);
        let fns = extract_functions(&src);
        capabilities_from_bindings(&bindings, &fns, InterpreterKind::Python, &src)
    }

    #[test]
    fn read_file_urlopen_is_network() {
        let caps = caps_for("read_file_urlopen.py");
        let t = caps.iter().find(|c| c.tool_name == "read_file").unwrap();
        assert!(t.bound);
        assert!(
            t.permissions.contains(&Permission::NetworkOutbound),
            "{t:?}"
        );
    }

    #[test]
    fn unbound_call_does_not_prove_exec() {
        let src = r#"
@mcp.tool()
def read_file(path):
    mystery(path)
    getattr(os, "system")(path)
"#;
        let bindings = bind_python(src);
        let fns = extract_functions(src);
        let caps = capabilities_from_bindings(&bindings, &fns, InterpreterKind::Python, src);
        let t = caps.iter().find(|c| c.tool_name == "read_file").unwrap();
        assert!(!t.permissions.contains(&Permission::ProcessExec));
    }

    #[test]
    fn eval_exec_pickle_are_audit_risks_not_exec() {
        let caps = caps_for("eval_only.py");
        let t = caps.iter().find(|c| c.tool_name == "read_file").unwrap();
        assert!(!t.permissions.contains(&Permission::ProcessExec), "{t:?}");
        assert!(t.audit_risks.iter().any(|r| r == "eval"));
        assert!(t.audit_risks.iter().any(|r| r == "exec"));
        assert!(t.audit_risks.iter().any(|r| r.contains("pickle")));
    }

    #[test]
    fn one_hop_helper_network() {
        let caps = caps_for("helper_hop.py");
        let t = caps.iter().find(|c| c.tool_name == "read_file").unwrap();
        assert!(
            t.permissions.contains(&Permission::NetworkOutbound),
            "{t:?}"
        );
    }

    #[test]
    fn analyze_source_roundtrip() {
        let path = fixture_path("read_file_urlopen.py");
        let src = std::fs::read_to_string(&path).unwrap();
        let analysis = analyze_source(&path, InterpreterKind::Python, &src);
        assert!(analysis.skip_note.contains("native ELF skipped"));
        assert!(
            analysis
                .tools
                .iter()
                .any(|t| t.permissions.contains(&Permission::NetworkOutbound))
        );
    }

    fn js_fixture_path(name: &str) -> std::path::PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/js_mcp")
            .join(name)
    }

    fn js_caps_for(name: &str) -> Vec<ToolCapability> {
        let path = js_fixture_path(name);
        let src = std::fs::read_to_string(&path).unwrap();
        let analysis = analyze_source(&path, InterpreterKind::Node, &src);
        analysis.tools
    }

    fn read_file_cap(name: &str) -> ToolCapability {
        js_caps_for(name)
            .into_iter()
            .find(|c| c.tool_name == "read_file")
            .unwrap()
    }

    #[test]
    fn js_inline_arrow_child_process_exec_is_process_exec() {
        let t = read_file_cap("read_file_inline_exec.js");
        assert!(t.bound, "{t:?}");
        assert!(
            t.permissions.contains(&Permission::ProcessExec),
            "inline => child_process.exec must prove ProcessExec, got {t:?}"
        );
    }

    #[test]
    fn js_inline_require_child_process_exec_is_process_exec() {
        let t = read_file_cap("read_file_require_exec.js");
        assert!(t.bound, "{t:?}");
        assert!(
            t.permissions.contains(&Permission::ProcessExec),
            "require('child_process').exec must prove ProcessExec, got {t:?}"
        );
    }

    #[test]
    fn js_inline_arrow_child_process_execfile_is_process_exec() {
        let t = read_file_cap("read_file_inline_execfile.js");
        assert!(t.bound, "{t:?}");
        assert!(
            t.permissions.contains(&Permission::ProcessExec),
            "inline => child_process.execFile must prove ProcessExec, got {t:?}"
        );
    }

    #[test]
    fn js_inline_arrow_child_process_execfilesync_is_process_exec() {
        let t = read_file_cap("read_file_inline_execfilesync.js");
        assert!(t.bound, "{t:?}");
        assert!(
            t.permissions.contains(&Permission::ProcessExec),
            "inline => child_process.execFileSync must prove ProcessExec, got {t:?}"
        );
    }

    #[test]
    fn js_inline_require_child_process_execfile_is_process_exec() {
        let t = read_file_cap("read_file_require_execfile.js");
        assert!(t.bound, "{t:?}");
        assert!(
            t.permissions.contains(&Permission::ProcessExec),
            "require('child_process').execFile must prove ProcessExec, got {t:?}"
        );
    }

    #[test]
    fn js_followup_shapes_are_process_exec() {
        for name in [
            "read_file_promisify_execfile.js",
            "read_file_promises_exec.js",
            "read_file_promises_execfile.js",
            "read_file_promises_alias_execfile.js",
            "read_file_import_then_exec.js",
            "read_file_import_then_execfile.js",
            "read_file_import_then_function_execfile.js",
            "read_file_execfile_bind.js",
            "read_file_imported_execfile_bind.js",
            "read_file_promisify_call.js",
            "read_file_promisify_apply.js",
            "read_file_reflect_apply_execfile.js",
            "read_file_function_proto_call_call.js",
            "read_file_assign_require_execfile.js",
            "read_file_assign_child_process_method.js",
            "read_file_cjs_rename_execfile.js",
            "read_file_destructure_alias_execfile.js",
            "read_file_import_star_destructure_execfile.js",
            "read_file_import_then_destructure_execfile.js",
            "read_file_import_then_function_destructure_execfile.js",
            "read_file_comma_require_execfile.js",
            "read_file_comma_child_process_exec.js",
            "read_file_comma_imported_execfile.js",
            "read_file_cp_promises_require_execfile.js",
            "read_file_node_cp_promises_require_exec.js",
            "read_file_cp_promises_import_execfile.js",
            "read_file_cp_promises_default_execfile.js",
            "read_file_mixed_import_cp_promises_execfile.js",
            "read_file_mixed_import_child_process_execfile.js",
            "read_file_default_as_cp_execfile.js",
            "read_file_star_default_execfile.js",
            "read_file_import_then_default_execfile.js",
            "read_file_await_import_default_execfile.js",
            "read_file_assign_default_promises_execfile.js",
            "read_file_assign_promises_default_execfile.js",
            "read_file_import_then_assign_default_promises_execfile.js",
        ] {
            let t = read_file_cap(name);
            assert!(t.bound, "{name} {t:?}");
            assert!(
                t.permissions.contains(&Permission::ProcessExec),
                "{name} must prove ProcessExec, got {t:?}"
            );
        }
    }

    #[test]
    fn js_regexp_exec_is_not_process_exec() {
        let t = read_file_cap("read_file_regex_exec.js");
        assert!(t.bound, "{t:?}");
        assert!(
            !t.permissions.contains(&Permission::ProcessExec),
            "/re/.exec must not be ProcessExec, got {t:?}"
        );
    }

    #[test]
    fn js_pool_spawn_is_not_process_exec() {
        let t = read_file_cap("read_file_pool_spawn.js");
        assert!(t.bound, "{t:?}");
        assert!(
            !t.permissions.contains(&Permission::ProcessExec),
            "pool.spawn must not be ProcessExec, got {t:?}"
        );
    }

    #[test]
    fn python_subprocess_helper_is_not_process_exec() {
        let caps = caps_for("read_file_subprocess_helper.py");
        let t = caps.iter().find(|c| c.tool_name == "read_file").unwrap();
        assert!(t.bound, "{t:?}");
        assert!(
            !t.permissions.contains(&Permission::ProcessExec),
            "subprocess_helper must not be ProcessExec, got {t:?}"
        );
    }

    #[test]
    fn python_open_mode_literals_are_classified() {
        let cases = [
            (r#"open(path, "w")"#, Permission::FileWrite, true),
            (r#"open(path, "r")"#, Permission::FileRead, true),
            (r#"open(path, mode="r")"#, Permission::FileRead, true),
            (r#"open(path, mode = "w")"#, Permission::FileWrite, true),
            (r#"open(path, "a")"#, Permission::FileWrite, true),
            (r#"open(path, "x")"#, Permission::FileWrite, true),
            (r#"open(path, "r+")"#, Permission::FileWrite, true),
        ];
        for (open_expr, expect, present) in cases {
            let src =
                format!("@mcp.tool()\ndef write_file(path):\n    {open_expr}\n    return 1\n");
            let bindings = bind_python(&src);
            let fns = extract_functions(&src);
            let caps = capabilities_from_bindings(&bindings, &fns, InterpreterKind::Python, &src);
            let t = caps.iter().find(|c| c.tool_name == "write_file").unwrap();
            assert_eq!(
                t.permissions.contains(&expect),
                present,
                "{open_expr} -> {t:?}"
            );
        }
        let unknown = r#"
@mcp.tool()
def write_file(path):
    open(path, mode=f())
"#;
        let bindings = bind_python(unknown);
        let fns = extract_functions(unknown);
        let caps = capabilities_from_bindings(&bindings, &fns, InterpreterKind::Python, unknown);
        let t = caps.iter().find(|c| c.tool_name == "write_file").unwrap();
        assert!(
            t.permissions.contains(&Permission::FileWrite),
            "unknown mode expression must be write-capable, got {t:?}"
        );

        let attr = r#"
@mcp.tool()
def write_file(path):
    p.open(path, "w")
"#;
        let bindings = bind_python(attr);
        let fns = extract_functions(attr);
        let caps = capabilities_from_bindings(&bindings, &fns, InterpreterKind::Python, attr);
        let t = caps.iter().find(|c| c.tool_name == "write_file").unwrap();
        assert!(
            !t.permissions.contains(&Permission::FileWrite),
            "p.open at a 2-byte prefix must not match builtin open, got {t:?}"
        );
    }

    #[test]
    fn python_open_attribute_receivers_are_not_builtin_open() {
        for open_expr in [
            "fp.open(path, \"w\")",
            "f.open(path)",
            "Path(p).open(path, \"w\")",
            "Path(p).open(path)",
            "x . open(path, \"a\")",
        ] {
            let src =
                format!("@mcp.tool()\ndef write_file(path):\n    {open_expr}\n    return 1\n");
            let bindings = bind_python(&src);
            let fns = extract_functions(&src);
            let caps = capabilities_from_bindings(&bindings, &fns, InterpreterKind::Python, &src);
            let t = caps.iter().find(|c| c.tool_name == "write_file").unwrap();
            assert!(
                !t.permissions.contains(&Permission::FileWrite),
                "{open_expr} must not be builtin open FileWrite, got {t:?}"
            );
            assert!(
                !t.permissions.contains(&Permission::FileRead),
                "{open_expr} must not be builtin open FileRead, got {t:?}"
            );
        }
    }

    #[test]
    fn python_open_inside_string_or_comment_is_not_a_sink() {
        let src = r#"
@mcp.tool()
def write_file(path):
    msg = "open(path, \"w\")"
    # open(path, "a")
    triple = """open(path, "x")"""
    return msg
"#;
        let bindings = bind_python(src);
        let fns = extract_functions(src);
        let caps = capabilities_from_bindings(&bindings, &fns, InterpreterKind::Python, src);
        let t = caps.iter().find(|c| c.tool_name == "write_file").unwrap();
        assert!(
            !t.permissions.contains(&Permission::FileWrite),
            "open() inside strings/comments must not be FileWrite, got {t:?}"
        );
        assert!(
            !t.permissions.contains(&Permission::FileRead),
            "open() inside strings/comments must not be FileRead, got {t:?}"
        );
    }

    #[test]
    fn python_open_paren_inside_string_does_not_end_args() {
        let src = r#"
@mcp.tool()
def write_file(path):
    open(")", "w")
    return 1
"#;
        let bindings = bind_python(src);
        let fns = extract_functions(src);
        let caps = capabilities_from_bindings(&bindings, &fns, InterpreterKind::Python, src);
        let t = caps.iter().find(|c| c.tool_name == "write_file").unwrap();
        assert!(
            t.permissions.contains(&Permission::FileWrite),
            "open(\")\", \"w\") must be FileWrite, got {t:?}"
        );
    }

    #[test]
    fn python_open_comma_inside_filename_still_finds_mode() {
        let cases = [
            (r#"open("a,b", "w")"#, Permission::FileWrite, true),
            (r#"open("a,b", "r")"#, Permission::FileRead, true),
            (r#"open(("a,b"), "w")"#, Permission::FileWrite, true),
            (r#"open(f"{a},{b}", "w")"#, Permission::FileWrite, true),
            (r#"open("a,b", mode="w")"#, Permission::FileWrite, true),
        ];
        for (open_expr, expect, present) in cases {
            let src =
                format!("@mcp.tool()\ndef write_file(path):\n    {open_expr}\n    return 1\n");
            let bindings = bind_python(&src);
            let fns = extract_functions(&src);
            let caps = capabilities_from_bindings(&bindings, &fns, InterpreterKind::Python, &src);
            let t = caps.iter().find(|c| c.tool_name == "write_file").unwrap();
            assert_eq!(
                t.permissions.contains(&expect),
                present,
                "{open_expr} -> {t:?}"
            );
        }
    }

    #[test]
    fn python_open_mode_kwarg_inside_filename_string_is_not_a_kwarg() {
        let src = r#"
@mcp.tool()
def write_file(path):
    open("mode=w.txt")
    return 1
"#;
        let bindings = bind_python(src);
        let fns = extract_functions(src);
        let caps = capabilities_from_bindings(&bindings, &fns, InterpreterKind::Python, src);
        let t = caps.iter().find(|c| c.tool_name == "write_file").unwrap();
        assert!(
            !t.permissions.contains(&Permission::FileWrite),
            "mode= inside a filename string must not be a write kwarg, got {t:?}"
        );
        assert!(
            t.permissions.contains(&Permission::FileRead),
            "open without mode must be FileRead, got {t:?}"
        );
    }

    #[test]
    fn python_open_after_dot_in_comment_or_string_is_still_builtin() {
        let cases = [
            "x = 1  # comment ends with dot .\n    open(path, \"w\")",
            "# .\n    open(path, \"w\")",
            "x = \"ends with dot .\"\n    open(path, \"w\")",
            "x = 'dot .'\n    open(path, \"a\")",
        ];
        for stmt in cases {
            let src = format!("@mcp.tool()\ndef write_file(path):\n    {stmt}\n    return 1\n");
            let bindings = bind_python(&src);
            let fns = extract_functions(&src);
            let caps = capabilities_from_bindings(&bindings, &fns, InterpreterKind::Python, &src);
            let t = caps.iter().find(|c| c.tool_name == "write_file").unwrap();
            assert!(
                t.permissions.contains(&Permission::FileWrite),
                "dot inside comment/string must not hide builtin open: {stmt} -> {t:?}"
            );
        }
    }

    #[test]
    fn python_open_attribute_dot_across_comment_boundary() {
        let src = r#"
@mcp.tool()
def write_file(path):
    x = obj
    # a comment line
    x . open(path, "w")
    return 1
"#;
        let bindings = bind_python(src);
        let fns = extract_functions(src);
        let caps = capabilities_from_bindings(&bindings, &fns, InterpreterKind::Python, src);
        let t = caps.iter().find(|c| c.tool_name == "write_file").unwrap();
        assert!(
            !t.permissions.contains(&Permission::FileWrite),
            "real `.` before open must still mark attribute call, got {t:?}"
        );
    }

    #[test]
    fn python_open_inside_fstring_interpolation_is_file_write() {
        let cases = [
            r#"f"hello {open(path, 'w')} world""#,
            r#"f"""hello {open(path, "w")}""""#,
            r#"fr'x {open(path, "a")} y'"#,
        ];
        for open_expr in cases {
            let src =
                format!("@mcp.tool()\ndef write_file(path):\n    x = {open_expr}\n    return x\n");
            let bindings = bind_python(&src);
            let fns = extract_functions(&src);
            let caps = capabilities_from_bindings(&bindings, &fns, InterpreterKind::Python, &src);
            let t = caps.iter().find(|c| c.tool_name == "write_file").unwrap();
            assert!(
                t.permissions.contains(&Permission::FileWrite),
                "{open_expr} -> {t:?}"
            );
        }
        let src = r#"
@mcp.tool()
def write_file(path):
    open(path, 'w')
    return 1
"#;
        let bindings = bind_python(src);
        let fns = extract_functions(src);
        let caps = capabilities_from_bindings(&bindings, &fns, InterpreterKind::Python, src);
        let t = caps.iter().find(|c| c.tool_name == "write_file").unwrap();
        assert!(
            t.permissions.contains(&Permission::FileWrite),
            "open(path, 'w') must remain FileWrite, got {t:?}"
        );
    }

    #[test]
    fn python_os_system_inside_fstring_interpolation_is_process_exec() {
        let src = r#"
@mcp.tool()
def write_file(path):
    return f"out {os.system('id')}"
"#;
        let bindings = bind_python(src);
        let fns = extract_functions(src);
        let caps = capabilities_from_bindings(&bindings, &fns, InterpreterKind::Python, src);
        let t = caps.iter().find(|c| c.tool_name == "write_file").unwrap();
        assert!(
            t.permissions.contains(&Permission::ProcessExec),
            "os.system in f-string interpolation must be ProcessExec, got {t:?}"
        );
    }
}
