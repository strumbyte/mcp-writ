use std::collections::HashSet;

use super::lex::*;

/// Names that refer to the Node `child_process` module or its named exports.
#[derive(Debug, Clone)]
pub struct ChildProcessBindings {
    pub module_aliases: HashSet<String>,
    pub imported_fns: HashSet<String>,
}

const CP_METHODS: &[&str] = &[
    "exec",
    "execFile",
    "execFileSync",
    "execSync",
    "spawn",
    "spawnSync",
    "fork",
];

fn is_child_process_module(spec: &str) -> bool {
    matches!(
        spec,
        "child_process"
            | "node:child_process"
            | "child_process/promises"
            | "node:child_process/promises"
    )
}

fn is_cp_method(name: &str) -> bool {
    CP_METHODS.contains(&name)
}

/// ESM interop / promises namespace: `cp.default.execFile(` / `cp.promises.exec(`.
fn is_cp_namespace_hop(name: &str) -> bool {
    name == "promises" || name == "default"
}

fn skip_js_atom(scan: &mut JsScan, source: &str) -> bool {
    if scan.skip_inert(source) {
        return true;
    }
    if source.as_bytes().get(scan.i) == Some(&b'/') && !is_line_or_block_comment(source, scan.i) {
        scan.i = skip_regex_or_slash(source, scan.i);
        return true;
    }
    false
}

/// Collect `require` / `import` aliases for `child_process` from a whole file.
pub fn child_process_bindings(source: &str) -> ChildProcessBindings {
    let mut module_aliases = HashSet::new();
    module_aliases.insert("child_process".to_string());
    let mut imported_fns = HashSet::new();
    let mut scan = JsScan::new();
    while scan.i < source.len() {
        if skip_js_atom(&mut scan, source) {
            continue;
        }
        if let Some((ident, next)) = take_ident(source, scan.i) {
            match ident.as_str() {
                "const" | "let" | "var" => {
                    collect_require_binding(source, next, &mut module_aliases, &mut imported_fns);
                    scan.i = next;
                }
                "import" => {
                    collect_import_binding(source, next, &mut module_aliases, &mut imported_fns);
                    scan.i = next;
                }
                _ => scan.i = next,
            }
            continue;
        }
        scan.bump(source);
    }
    ChildProcessBindings {
        module_aliases,
        imported_fns,
    }
}

fn collect_require_binding(
    source: &str,
    after_kw: usize,
    aliases: &mut HashSet<String>,
    imported: &mut HashSet<String>,
) {
    let mut i = skip_ws_and_comments(source, after_kw);
    loop {
        if source.as_bytes().get(i) == Some(&b'{') {
            let Some(close) = find_matching(source, i, '{', '}') else {
                return;
            };
            let names = parse_import_list(&source[i + 1..close]);
            let after = skip_ws_and_comments(source, close + 1);
            if !source[after..].starts_with('=') {
                return;
            }
            let rhs_start = skip_ws_and_comments(source, after + 1);
            let after_eq = skip_opening_parens(source, rhs_start);
            if matches!(
                classify_cp_rhs(source, after_eq, aliases, imported),
                Some(CpRhs::Module | CpRhs::PromisesNs)
            ) {
                absorb_cp_imports(&names, aliases, imported);
            }
            i = skip_ws_and_comments(source, scan_js_expression_until(source, rhs_start));
        } else {
            let Some((name, after_name)) = take_ident(source, i) else {
                return;
            };
            let after = skip_ws_and_comments(source, after_name);
            if source[after..].starts_with('=') {
                let rhs_start = skip_ws_and_comments(source, after + 1);
                let after_eq = skip_opening_parens(source, rhs_start);
                match classify_cp_rhs(source, after_eq, aliases, imported) {
                    Some(CpRhs::Module | CpRhs::PromisesNs) => {
                        aliases.insert(name);
                    }
                    Some(CpRhs::Method) => {
                        imported.insert(name);
                    }
                    None => {}
                }
                i = skip_ws_and_comments(source, scan_js_expression_until(source, rhs_start));
            } else {
                i = after;
            }
        }
        if source.as_bytes().get(i) == Some(&b',') {
            i = skip_ws_and_comments(source, i + 1);
            continue;
        }
        return;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CpRhs {
    /// `require("child_process")` / `child_process` — member calls like `cp.execFile(`.
    Module,
    /// `.promises` namespace — still a module-like receiver.
    PromisesNs,
    /// `.execFile` / `.exec` / … — local name is a bare-callable imported function.
    Method,
}

fn classify_cp_rhs(
    source: &str,
    i: usize,
    aliases: &HashSet<String>,
    imported: &HashSet<String>,
) -> Option<CpRhs> {
    if let Some(after_mod) = cp_module_expr_at(source, i) {
        return classify_after_cp_module(source, after_mod);
    }
    if promisify_callee_end(source, i).is_some() {
        let tmp = ChildProcessBindings {
            module_aliases: aliases.clone(),
            imported_fns: imported.clone(),
        };
        if promisify_cp_call_close(source, i, &tmp).is_some() {
            return Some(CpRhs::Method);
        }
    }
    let (ident, after_ident) = take_ident(source, i)?;
    if aliases.contains(&ident) {
        return classify_after_cp_module(source, after_ident);
    }
    None
}

fn classify_after_cp_module(source: &str, after_mod: usize) -> Option<CpRhs> {
    let after = skip_closing_parens(source, skip_ws_and_comments(source, after_mod));
    let Some((mut member, mut after_member)) = take_member_name(source, after) else {
        return Some(CpRhs::Module);
    };
    // Same hops as `member_cp_path`: `.default` / `.promises` in any order/count.
    while is_cp_namespace_hop(&member) {
        match take_member_name(source, after_member) {
            Some((next, next_after)) => {
                member = next;
                after_member = next_after;
            }
            None => return Some(CpRhs::PromisesNs),
        }
    }
    if is_cp_method(&member) {
        Some(CpRhs::Method)
    } else {
        None
    }
}

fn take_member_name(source: &str, at: usize) -> Option<(String, usize)> {
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
        let i = skip_ws_and_comments(source, after_name);
        if bytes.get(i) != Some(&b']') {
            return None;
        }
        return Some((name, i + 1));
    }
    take_ident(source, i)
}

fn collect_import_binding(
    source: &str,
    after_import: usize,
    aliases: &mut HashSet<String>,
    imported: &mut HashSet<String>,
) {
    let i = skip_ws_and_comments(source, after_import);
    if let Some((alias, after_alias)) = take_star_as_alias(source, i) {
        if import_from_cp_module(source, after_alias) {
            aliases.insert(alias);
        }
        return;
    }

    let (default_local, after_default) = match take_ident(source, i) {
        Some((name, after)) => (Some(name), after),
        None => (None, i),
    };
    let mut i = skip_ws_and_comments(source, after_default);
    if source.as_bytes().get(i) == Some(&b',') {
        i = skip_ws_and_comments(source, i + 1);
    }

    if let Some((alias, after_alias)) = take_star_as_alias(source, i) {
        if import_from_cp_module(source, after_alias) {
            bind_default_import(default_local, aliases, imported);
            aliases.insert(alias);
        }
        return;
    }
    if source.as_bytes().get(i) == Some(&b'{') {
        let Some(close) = find_matching(source, i, '{', '}') else {
            return;
        };
        let names = parse_import_list(&source[i + 1..close]);
        if import_from_cp_module(source, close + 1) {
            bind_default_import(default_local, aliases, imported);
            absorb_cp_imports(&names, aliases, imported);
        }
        return;
    }
    if let Some(name) = default_local
        && import_from_cp_module(source, after_default)
    {
        bind_default_import(Some(name), aliases, imported);
    }
}

fn take_star_as_alias(source: &str, i: usize) -> Option<(String, usize)> {
    if !slice_at(source, i).starts_with('*') {
        return None;
    }
    let after_star = skip_ws_and_comments(source, i + 1);
    let (as_kw, after_as) = take_ident(source, after_star)?;
    if as_kw != "as" {
        return None;
    }
    let after_as = skip_ws_and_comments(source, after_as);
    take_ident(source, after_as)
}

fn bind_default_import(
    name: Option<String>,
    aliases: &mut HashSet<String>,
    imported: &mut HashSet<String>,
) {
    let Some(name) = name else {
        return;
    };
    aliases.insert(name.clone());
    // `import execFile from "…"` / `{ default as execFile }` used bare.
    if is_cp_method(&name) {
        imported.insert(name);
    }
}

fn import_from_cp_module(source: &str, from_i: usize) -> bool {
    let i = skip_ws_and_comments(source, from_i);
    let Some((from_kw, after_from)) = take_ident(source, i) else {
        return false;
    };
    if from_kw != "from" {
        return false;
    }
    let i = skip_ws_and_comments(source, after_from);
    take_string(source, i).is_some_and(|(spec, _)| is_child_process_module(&spec))
}

/// `require("child_process")` / `await import("child_process")` / `import("node:child_process")`.
fn cp_module_expr_at(source: &str, i: usize) -> Option<usize> {
    let i = skip_ws_and_comments(source, i);
    require_module_at(source, i).or_else(|| dynamic_import_module_at(source, i))
}

fn dynamic_import_module_at(source: &str, i: usize) -> Option<usize> {
    let mut i = skip_ws_and_comments(source, i);
    if let Some((ident, after)) = take_ident(source, i) {
        if ident == "await" {
            i = skip_ws_and_comments(source, after);
        } else if ident == "import" {
            return import_call_module_at(source, i);
        } else {
            return None;
        }
    }
    let (ident, _) = take_ident(source, i)?;
    if ident != "import" {
        return None;
    }
    import_call_module_at(source, i)
}

fn import_call_module_at(source: &str, at_import: usize) -> Option<usize> {
    let (ident, after_ident) = take_ident(source, at_import)?;
    if ident != "import" {
        return None;
    }
    let i = skip_ws_and_comments(source, after_ident);
    let bytes = source.as_bytes();
    if bytes.get(i) != Some(&b'(') {
        return None;
    }
    let i = skip_ws_and_comments(source, i + 1);
    let (spec, after_spec) = take_string(source, i)?;
    if !is_child_process_module(&spec) {
        return None;
    }
    let i = skip_ws_and_comments(source, after_spec);
    if bytes.get(i) == Some(&b')') {
        Some(i + 1)
    } else {
        None
    }
}

fn require_module_at(source: &str, i: usize) -> Option<usize> {
    require_spec_matching(source, i, is_child_process_module)
}

fn require_spec_at(source: &str, i: usize, specs: &[&str]) -> Option<usize> {
    require_spec_matching(source, i, |spec| specs.contains(&spec))
}

fn require_spec_matching(source: &str, i: usize, ok: impl Fn(&str) -> bool) -> Option<usize> {
    let i = skip_ws_and_comments(source, i);
    let (ident, after) = take_ident(source, i)?;
    if ident != "require" {
        return None;
    }
    let i = skip_ws_and_comments(source, after);
    let bytes = source.as_bytes();
    if bytes.get(i) != Some(&b'(') {
        return None;
    }
    let i = skip_ws_and_comments(source, i + 1);
    let (spec, after_spec) = take_string(source, i)?;
    if !ok(&spec) {
        return None;
    }
    let i = skip_ws_and_comments(source, after_spec);
    if bytes.get(i) == Some(&b')') {
        Some(i + 1)
    } else {
        None
    }
}

#[derive(Debug, Clone)]
struct ImportedName {
    local: String,
    original: String,
}

fn parse_import_list(inner: &str) -> Vec<ImportedName> {
    let mut out = Vec::new();
    for part in inner.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        if let Some((orig, local)) = split_cjs_rename(part) {
            out.push(ImportedName {
                local,
                original: orig,
            });
            continue;
        }
        let tokens: Vec<&str> = part.split_whitespace().collect();
        let (local, original) = match tokens.as_slice() {
            [name] => ((*name).to_string(), (*name).to_string()),
            [orig, "as", alias, ..] => ((*alias).to_string(), (*orig).to_string()),
            other => {
                let first = other.first().copied().unwrap_or("");
                (first.to_string(), first.to_string())
            }
        };
        if !local.is_empty() {
            out.push(ImportedName { local, original });
        }
    }
    out
}

/// CJS destructure rename: `{ execFile: run }` → local `run`, original `execFile`.
fn split_cjs_rename(part: &str) -> Option<(String, String)> {
    let (orig, local) = part.split_once(':')?;
    let orig = simple_ident(orig)?;
    let local = simple_ident(local)?;
    Some((orig, local))
}

fn simple_ident(s: &str) -> Option<String> {
    let i = skip_ws_and_comments(s, 0);
    let (name, end) = take_ident(s, i)?;
    if skip_ws_and_comments(s, end) == s.len() {
        Some(name)
    } else {
        None
    }
}

/// `promises` / `default` are namespaces (`cp.execFile`), not bare callables.
/// `{ default as execFile }` still allows a bare call when the local name is a CP method.
fn absorb_cp_imports(
    names: &[ImportedName],
    aliases: &mut HashSet<String>,
    imported: &mut HashSet<String>,
) {
    for n in names {
        if n.original == "promises" {
            aliases.insert(n.local.clone());
        } else if n.original == "default" {
            bind_default_import(Some(n.local.clone()), aliases, imported);
        } else {
            imported.insert(n.local.clone());
        }
    }
}

/// True when `body` calls `child_process` exec/spawn/fork (not RegExp.exec / pool.spawn).
///
/// Known limits (not treated as Capability proof):
/// - computed keys `child_process[name](` where `name` is not a string literal
pub fn body_has_child_process_exec(body: &str, file_source: &str) -> bool {
    let bindings = child_process_bindings(file_source);
    js_has_cp_exec(body, &bindings)
}

fn js_has_cp_exec(body: &str, bindings: &ChildProcessBindings) -> bool {
    let mut scan = JsScan::new();
    while scan.i < body.len() {
        if skip_js_atom(&mut scan, body) {
            continue;
        }
        if reflect_or_proto_invoke_cp(body, scan.i, bindings) {
            return true;
        }
        if promisify_cp_invoked(body, scan.i, bindings) {
            return true;
        }
        if let Some(after_mod) = cp_module_expr_at(body, scan.i) {
            let after = skip_closing_parens(body, skip_ws_and_comments(body, after_mod));
            if member_cp_call(body, after) || then_callback_has_cp_exec(body, after, bindings) {
                return true;
            }
            scan.i = after_mod;
            continue;
        }
        if let Some((ident, after_ident)) = take_ident(body, scan.i) {
            let after = skip_ws_and_comments(body, after_ident);
            if bindings.module_aliases.contains(&ident) && member_cp_call(body, after) {
                return true;
            }
            if bindings.imported_fns.contains(&ident)
                && !preceded_by_dot(body, scan.i)
                && is_invoked(body, after)
            {
                return true;
            }
            scan.i = after_ident;
            continue;
        }
        scan.bump(body);
    }
    false
}

/// After a `child_process` receiver: `.exec(`, `?.exec(`, `.default.execFile(`, `.promises.execFile(`, `["execFile"](`.
fn member_cp_call(source: &str, at: usize) -> bool {
    member_cp_path(source, at, true)
}

fn member_cp_path(source: &str, at: usize, require_call: bool) -> bool {
    let bytes = source.as_bytes();
    let mut i = skip_ws_and_comments(source, at);
    if bytes.get(i) == Some(&b'?') && bytes.get(i + 1) == Some(&b'.') {
        i = skip_ws_and_comments(source, i + 2);
    } else if bytes.get(i) == Some(&b'.') {
        i = skip_ws_and_comments(source, i + 1);
    } else if bytes.get(i) != Some(&b'[') {
        return false;
    }
    if bytes.get(i) == Some(&b'[') {
        return bracket_cp_method_path(source, i, require_call);
    }
    let Some((method, after_method)) = take_ident(source, i) else {
        return false;
    };
    let after_method = skip_ws_and_comments(source, after_method);
    if is_cp_namespace_hop(&method) {
        return member_cp_path(source, after_method, require_call);
    }
    if !is_cp_method(&method) {
        return false;
    }
    if require_call {
        is_invoked(source, after_method)
    } else {
        true
    }
}

fn bracket_cp_method_path(source: &str, at_bracket: usize, require_call: bool) -> bool {
    let bytes = source.as_bytes();
    if bytes.get(at_bracket) != Some(&b'[') {
        return false;
    }
    let i = skip_ws_and_comments(source, at_bracket + 1);
    let Some((name, after_name)) = take_string(source, i) else {
        return false;
    };
    let i = skip_ws_and_comments(source, after_name);
    if bytes.get(i) != Some(&b']') {
        return false;
    }
    let after = skip_ws_and_comments(source, i + 1);
    if is_cp_namespace_hop(&name) {
        return member_cp_path(source, after, require_call);
    }
    if !is_cp_method(&name) {
        return false;
    }
    if require_call {
        is_invoked(source, after)
    } else {
        true
    }
}

fn promisify_cp_invoked(source: &str, i: usize, bindings: &ChildProcessBindings) -> bool {
    let Some(close) = promisify_cp_call_close(source, i, bindings) else {
        return false;
    };
    is_invoked(source, skip_ws_and_comments(source, close + 1))
}

fn promisify_cp_call_close(
    source: &str,
    i: usize,
    bindings: &ChildProcessBindings,
) -> Option<usize> {
    let after_name = promisify_callee_end(source, i)?;
    let i = skip_ws_and_comments(source, after_name);
    if source.as_bytes().get(i) != Some(&b'(') {
        return None;
    }
    let close = find_matching(source, i, '(', ')')?;
    if !args_ref_cp_method(&source[i + 1..close], bindings) {
        return None;
    }
    Some(close)
}

fn promisify_callee_end(source: &str, i: usize) -> Option<usize> {
    let i = skip_ws_and_comments(source, i);
    if let Some(after_req) = require_spec_at(source, i, &["util", "node:util"]) {
        return skip_member_named(source, skip_ws_and_comments(source, after_req), "promisify");
    }
    let (ident, after_ident) = take_ident(source, i)?;
    if ident == "promisify" {
        return Some(after_ident);
    }
    if ident == "util" {
        return skip_member_named(
            source,
            skip_ws_and_comments(source, after_ident),
            "promisify",
        );
    }
    None
}

fn args_ref_cp_method(args: &str, bindings: &ChildProcessBindings) -> bool {
    let mut scan = JsScan::new();
    while scan.i < args.len() {
        if skip_js_atom(&mut scan, args) {
            continue;
        }
        if let Some(after_mod) = cp_module_expr_at(args, scan.i) {
            let after = skip_closing_parens(args, skip_ws_and_comments(args, after_mod));
            if member_cp_path(args, after, false) {
                return true;
            }
            scan.i = after_mod;
            continue;
        }
        if let Some((ident, after_ident)) = take_ident(args, scan.i) {
            let after = skip_ws_and_comments(args, after_ident);
            if bindings.module_aliases.contains(&ident) && member_cp_path(args, after, false) {
                return true;
            }
            if bindings.imported_fns.contains(&ident) && !preceded_by_dot(args, scan.i) {
                return true;
            }
            scan.i = after_ident;
            continue;
        }
        scan.bump(args);
    }
    false
}

fn then_callback_has_cp_exec(
    body: &str,
    after_import: usize,
    bindings: &ChildProcessBindings,
) -> bool {
    let Some(after_then) = skip_member_named(body, after_import, "then") else {
        return false;
    };
    let i = skip_ws_and_comments(body, after_then);
    if body.as_bytes().get(i) != Some(&b'(') {
        return false;
    }
    let i = skip_ws_and_comments(body, i + 1);
    let Some((param, cb)) = take_callback_param_and_body(body, i) else {
        return false;
    };
    let mut extra = bindings.clone();
    match param {
        ThenFirstParam::ModuleAlias(alias) => {
            extra.module_aliases.insert(alias);
        }
        ThenFirstParam::Destructure(names) => {
            absorb_cp_imports(&names, &mut extra.module_aliases, &mut extra.imported_fns);
        }
    }
    collect_assign_bindings(&cb, &mut extra.module_aliases, &mut extra.imported_fns);
    js_has_cp_exec(&cb, &extra)
}

/// `const run = m.default.promises.execFile` inside a `.then` callback.
fn collect_assign_bindings(
    source: &str,
    aliases: &mut HashSet<String>,
    imported: &mut HashSet<String>,
) {
    let mut i = 0;
    while i < source.len() {
        i = skip_ws_and_comments(source, i);
        if i >= source.len() {
            break;
        }
        if let Some((ident, next)) = take_ident(source, i) {
            if matches!(ident.as_str(), "const" | "let" | "var") {
                collect_require_binding(source, next, aliases, imported);
            }
            i = next;
            continue;
        }
        i = next_index(source, i);
    }
}

#[derive(Debug, Clone)]
enum ThenFirstParam {
    ModuleAlias(String),
    Destructure(Vec<ImportedName>),
}

fn take_callback_param_and_body(source: &str, mut i: usize) -> Option<(ThenFirstParam, String)> {
    i = skip_ws_and_comments(source, i);
    if let Some((kw, next)) = take_ident(source, i)
        && kw == "async"
    {
        i = skip_ws_and_comments(source, next);
    }
    let bytes = source.as_bytes();
    let is_fn = if let Some((kw, next)) = take_ident(source, i) {
        if kw == "function" {
            i = skip_ws_and_comments(source, next);
            if let Some((_, next_name)) = take_ident(source, i) {
                i = skip_ws_and_comments(source, next_name);
            }
            true
        } else {
            false
        }
    } else {
        false
    };
    let param;
    if bytes.get(i) == Some(&b'(') {
        let close = find_matching(source, i, '(', ')')?;
        param = first_then_param(&source[i + 1..close])?;
        i = skip_ws_and_comments(source, close + 1);
    } else if !is_fn {
        let (a, next) = take_ident(source, i)?;
        param = ThenFirstParam::ModuleAlias(a);
        i = skip_ws_and_comments(source, next);
    } else {
        return None;
    }
    let body = if is_fn {
        if bytes.get(i) != Some(&b'{') {
            return None;
        }
        extract_brace_block(source, i).0
    } else {
        if !slice_at(source, i).starts_with("=>") {
            return None;
        }
        i = skip_ws_and_comments(source, i + 2);
        if bytes.get(i) == Some(&b'{') {
            extract_brace_block(source, i).0
        } else {
            let end = scan_js_expression_until(source, i);
            source.get(i..end)?.to_string()
        }
    };
    Some((param, body))
}

fn first_then_param(inner: &str) -> Option<ThenFirstParam> {
    let i = skip_ws_and_comments(inner, 0);
    if inner.as_bytes().get(i) == Some(&b'{') {
        let close = find_matching(inner, i, '{', '}')?;
        let names = parse_import_list(&inner[i + 1..close]);
        if names.is_empty() {
            return None;
        }
        return Some(ThenFirstParam::Destructure(names));
    }
    take_ident(inner, i).map(|(n, _)| ThenFirstParam::ModuleAlias(n))
}

fn reflect_or_proto_invoke_cp(source: &str, i: usize, bindings: &ChildProcessBindings) -> bool {
    if let Some(at_paren) = reflect_apply_call_paren(source, i) {
        return first_arg_is_cp_method(source, at_paren, bindings);
    }
    if let Some(at_paren) = function_proto_double_adapter_paren(source, i) {
        return first_arg_is_cp_method(source, at_paren, bindings);
    }
    false
}

fn reflect_apply_call_paren(source: &str, i: usize) -> Option<usize> {
    let i = skip_ws_and_comments(source, i);
    let (ident, after) = take_ident(source, i)?;
    if ident != "Reflect" {
        return None;
    }
    let after = skip_ws_and_comments(source, after);
    let after_name = skip_member_named(source, after, "apply")
        .or_else(|| skip_member_named(source, after, "call"))?;
    let after = skip_ws_and_comments(source, after_name);
    if source.as_bytes().get(after) == Some(&b'(') {
        Some(after)
    } else {
        None
    }
}

fn function_proto_double_adapter_paren(source: &str, i: usize) -> Option<usize> {
    let i = skip_ws_and_comments(source, i);
    let (ident, after) = take_ident(source, i)?;
    if ident != "Function" {
        return None;
    }
    let after_proto = skip_member_named(source, skip_ws_and_comments(source, after), "prototype")?;
    let (_, after_a1) = take_fn_adapter(source, skip_ws_and_comments(source, after_proto))?;
    let (_, after_a2) = take_fn_adapter(source, skip_ws_and_comments(source, after_a1))?;
    let after = skip_ws_and_comments(source, after_a2);
    if source.as_bytes().get(after) == Some(&b'(') {
        Some(after)
    } else {
        None
    }
}

fn first_arg_is_cp_method(source: &str, at_paren: usize, bindings: &ChildProcessBindings) -> bool {
    if source.as_bytes().get(at_paren) != Some(&b'(') {
        return false;
    }
    let Some(close) = find_matching(source, at_paren, '(', ')') else {
        return false;
    };
    let inner = &source[at_paren + 1..close];
    let start = skip_ws_and_comments(inner, 0);
    let end = scan_js_expression_until(inner, start);
    let first = inner.get(start..end).unwrap_or("").trim();
    !first.is_empty() && args_ref_cp_method(first, bindings)
}
