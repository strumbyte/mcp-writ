use std::collections::HashSet;

use super::lex::*;

/// Names that refer to the Node `child_process` module or its named exports.
#[derive(Debug, Clone, Default)]
pub struct ChildProcessBindings {
    pub module_aliases: HashSet<String>,
    pub imported_fns: HashSet<String>,
    /// Local names bound to a `child_process` member access the
    /// analyzer could not resolve — `const f = cp[name]` or a computed
    /// destructure `const { [k]: f } = require("child_process")`. Any
    /// call or member use of one is an unresolved dynamic invocation:
    /// the tool it appears in is unproven, never "clean".
    pub dynamic_fns: HashSet<String>,
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
    let mut dynamic_fns = HashSet::new();
    let mut scan = JsScan::new();
    while scan.i < source.len() {
        if skip_js_atom(&mut scan, source) {
            continue;
        }
        if let Some((ident, next)) = take_ident(source, scan.i) {
            match ident.as_str() {
                "const" | "let" | "var" => {
                    collect_require_binding(
                        source,
                        next,
                        &mut module_aliases,
                        &mut imported_fns,
                        &mut dynamic_fns,
                    );
                    scan.i = next;
                }
                "import" => {
                    collect_import_binding(
                        source,
                        next,
                        &mut module_aliases,
                        &mut imported_fns,
                        &mut dynamic_fns,
                    );
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
        dynamic_fns,
    }
}

fn collect_require_binding(
    source: &str,
    after_kw: usize,
    aliases: &mut HashSet<String>,
    imported: &mut HashSet<String>,
    dynamic: &mut HashSet<String>,
) {
    let mut i = skip_ws_and_comments(source, after_kw);
    loop {
        if source.as_bytes().get(i) == Some(&b'{') {
            let Some(close) = find_matching(source, i, '{', '}') else {
                return;
            };
            let inner = &source[i + 1..close];
            let names = parse_import_list(inner);
            let after = skip_ws_and_comments(source, close + 1);
            if !source[after..].starts_with('=') {
                return;
            }
            let rhs_start = skip_ws_and_comments(source, after + 1);
            let after_eq = skip_opening_parens(source, rhs_start);
            match classify_cp_rhs(source, after_eq, aliases, imported, dynamic) {
                Some(CpRhs::Module | CpRhs::PromisesNs) => {
                    absorb_cp_imports(&names, aliases, imported);
                }
                Some(CpRhs::Unresolved) => {
                    // `const {…} = cp[name]` — every destructured local
                    // could be a CP method.
                    for n in &names {
                        dynamic.insert(n.local.clone());
                    }
                }
                _ => {}
            }
            // A computed destructure key (`const { [k]: f } = …`) binds
            // its locals to members the parse cannot name — they are
            // dynamic regardless of the RHS shape.
            if inner.contains('[') {
                computed_destructure_locals(inner, dynamic);
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
                match classify_cp_rhs(source, after_eq, aliases, imported, dynamic) {
                    Some(CpRhs::Module | CpRhs::PromisesNs) => {
                        aliases.insert(name);
                    }
                    Some(CpRhs::Method) => {
                        imported.insert(name);
                    }
                    Some(CpRhs::Unresolved) => {
                        dynamic.insert(name);
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

/// `{ [key]: local }` — each computed-key destructure binds `local`
/// to a member the parse cannot name.
fn computed_destructure_locals(inner: &str, dynamic: &mut HashSet<String>) {
    for part in inner.split(',') {
        let Some((key, local)) = part.split_once(':') else {
            continue;
        };
        if !key.contains('[') {
            continue;
        }
        if let Some(name) = simple_ident(local) {
            dynamic.insert(name);
        }
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
    /// `cp[name]` — a member access the analyzer cannot resolve; the
    /// bound local is a `dynamic_fns` entry, not a proven alias.
    Unresolved,
}

fn classify_cp_rhs(
    source: &str,
    i: usize,
    aliases: &HashSet<String>,
    imported: &HashSet<String>,
    dynamic: &HashSet<String>,
) -> Option<CpRhs> {
    if let Some(after_mod) = cp_module_expr_at(source, i) {
        return classify_after_cp_module(source, after_mod);
    }
    if promisify_callee_end(source, i).is_some() {
        let tmp = ChildProcessBindings {
            module_aliases: aliases.clone(),
            imported_fns: imported.clone(),
            dynamic_fns: dynamic.clone(),
        };
        match promisify_cp_call_close(source, i, &tmp) {
            Some((_, CpMember::Exec)) => return Some(CpRhs::Method),
            Some((_, CpMember::Unresolved)) => return Some(CpRhs::Unresolved),
            _ => {}
        }
    }
    let (ident, after_ident) = take_ident(source, i)?;
    if aliases.contains(&ident) {
        return classify_after_cp_module(source, after_ident);
    }
    // A re-alias carries the source's provenance: a dynamically-bound
    // name stays unresolvable (`const g = f` where `f = cp[name]` —
    // including as a destructure's source), an imported method name
    // stays a bare callable (`const g = execFile`).
    if dynamic.contains(&ident) {
        return Some(CpRhs::Unresolved);
    }
    if imported.contains(&ident) {
        return Some(CpRhs::Method);
    }
    None
}

fn classify_after_cp_module(source: &str, after_mod: usize) -> Option<CpRhs> {
    let after = skip_closing_parens(source, skip_ws_and_comments(source, after_mod));
    let Some((mut member, mut after_member)) = take_member_name(source, after) else {
        // `cp[name]` — a computed member the parse cannot name: the
        // bound local is dynamically opaque, not the module.
        if source.as_bytes().get(after) == Some(&b'[') {
            return Some(CpRhs::Unresolved);
        }
        return Some(CpRhs::Module);
    };
    // Same hops as `member_cp_usage`: `.default` / `.promises` in any order/count.
    while is_cp_namespace_hop(&member) {
        match take_member_name(source, after_member) {
            Some((next, next_after)) => {
                member = next;
                after_member = next_after;
            }
            None => {
                if source
                    .as_bytes()
                    .get(skip_ws_and_comments(source, after_member))
                    == Some(&b'[')
                {
                    return Some(CpRhs::Unresolved);
                }
                return Some(CpRhs::PromisesNs);
            }
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
    dynamic: &mut HashSet<String>,
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
        let inner = &source[i + 1..close];
        let names = parse_import_list(inner);
        if import_from_cp_module(source, close + 1) {
            bind_default_import(default_local, aliases, imported);
            absorb_cp_imports(&names, aliases, imported);
        }
        // `import { [k]: f }` is not valid JS — but the tolerant scan
        // still records its locals as dynamic rather than dropping
        // them into a name it made up.
        if inner.contains('[') {
            computed_destructure_locals(inner, dynamic);
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
    /// `...rest` — binds the remaining exports as one namespace-like
    /// object (a module alias), never a single imported function.
    rest: bool,
}

fn parse_import_list(inner: &str) -> Vec<ImportedName> {
    let mut out = Vec::new();
    for part in inner.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        if let Some(rest) = part.strip_prefix("...")
            && let Some(local) = simple_ident(rest)
        {
            out.push(ImportedName {
                local: local.clone(),
                original: local,
                rest: true,
            });
            continue;
        }
        if let Some((orig, local)) = split_cjs_rename(part) {
            out.push(ImportedName {
                local,
                original: orig,
                rest: false,
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
            out.push(ImportedName {
                local,
                original,
                rest: false,
            });
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

/// `promises` / `default` / `...rest` are namespaces (`cp.execFile`),
/// not bare callables.
/// `{ default as execFile }` still allows a bare call when the local name is a CP method.
fn absorb_cp_imports(
    names: &[ImportedName],
    aliases: &mut HashSet<String>,
    imported: &mut HashSet<String>,
) {
    for n in names {
        if n.rest || n.original == "promises" {
            aliases.insert(n.local.clone());
        } else if n.original == "default" {
            bind_default_import(Some(n.local.clone()), aliases, imported);
        } else {
            imported.insert(n.local.clone());
        }
    }
}

/// The tri-state verdict for one `child_process` receiver member
/// access — whether it is provably a cp exec/spawn/fork method, or a
/// form the analyzer cannot prove either way (non-literal computed
/// key, computed subscript on a method object). `Unresolved` is *not*
/// "no exec": the containing scan reports the body unproven.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CpMember {
    Exec,
    Unresolved,
    No,
}

/// What one body proved about its `child_process` use.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct CpScan {
    /// A provable `child_process` exec/spawn/fork invocation (or
    /// uninvoked reference inside a promisify/Reflect wrapper).
    pub exec: bool,
    /// A `child_process` receiver carried a member access or the body
    /// called a dynamically-bound cp name the analyzer cannot resolve
    /// (`cp[name](…)`, `cp?.[k](…)`, `const f = cp[name]; f(…)`). The
    /// body's capability is unproven — its tool stays denied pending
    /// review, never silently clean.
    pub unresolved: bool,
}

/// True when `body` calls `child_process` exec/spawn/fork (not RegExp.exec / pool.spawn).
///
/// Computed member keys (`child_process[name](…)`) are not "no exec"
/// — this convenience wrapper answers only the `exec` half; the
/// `unresolved` half lives on `js_scan_cp_usage`, which the
/// capability pipeline consults to keep the tool denied.
///
/// Prefer `js_scan_cp_usage` with a bindings table computed once per
/// file — this convenience wrapper reparses `file_source` on every
/// call, which is quadratic across a per-binding scan loop.
pub fn body_has_child_process_exec(body: &str, file_source: &str) -> bool {
    let bindings = child_process_bindings(file_source);
    js_scan_cp_usage(body, &bindings).exec
}

/// [`body_has_child_process_exec`] against an already-parsed binding
/// table — `child_process_bindings(file_source)` computed once, then
/// reused for every function body scanned in that file.
pub(crate) fn js_scan_cp_usage(body: &str, bindings: &ChildProcessBindings) -> CpScan {
    let mut scan = JsScan::new();
    let mut out = CpScan::default();
    while scan.i < body.len() && !(out.exec && out.unresolved) {
        if skip_js_atom(&mut scan, body) {
            continue;
        }
        match reflect_or_proto_cp_usage(body, scan.i, bindings) {
            CpMember::Exec => out.exec = true,
            CpMember::Unresolved => out.unresolved = true,
            CpMember::No => {}
        }
        if out.exec && out.unresolved {
            break;
        }
        match promisify_cp_invoked(body, scan.i, bindings) {
            CpMember::Exec => out.exec = true,
            CpMember::Unresolved => out.unresolved = true,
            CpMember::No => {}
        }
        if let Some(after_mod) = cp_module_expr_at(body, scan.i) {
            let after = skip_closing_parens(body, skip_ws_and_comments(body, after_mod));
            match member_cp_usage(body, after, true) {
                CpMember::Exec => out.exec = true,
                CpMember::Unresolved => out.unresolved = true,
                CpMember::No => {}
            }
            let cb = then_callback_cp_usage(body, after, bindings);
            out.exec |= cb.exec;
            out.unresolved |= cb.unresolved;
            scan.i = after_mod;
            continue;
        }
        if let Some((ident, after_ident)) = take_ident(body, scan.i) {
            let after = skip_ws_and_comments(body, after_ident);
            // A name can sit in several sets — `import execFile from
            // "child_process"` is both a module alias and a bare
            // callable — so member lookup first, bare-call lookup when
            // the member access proves nothing.
            let mut member = if bindings.module_aliases.contains(&ident) {
                member_cp_usage(body, after, true)
            } else {
                CpMember::No
            };
            if member == CpMember::No && !preceded_by_dot(body, scan.i) {
                if bindings.dynamic_fns.contains(&ident) && dynamic_fn_used(body, after) {
                    member = CpMember::Unresolved;
                } else if bindings.imported_fns.contains(&ident) && is_invoked(body, after) {
                    member = CpMember::Exec;
                }
            }
            match member {
                CpMember::Exec => out.exec = true,
                CpMember::Unresolved => out.unresolved = true,
                CpMember::No => {}
            }
            scan.i = after_ident;
            continue;
        }
        scan.bump(body);
    }
    out
}

/// `f` — a name bound to an unresolvable cp member — is called or has
/// a member extracted. Either way the cp side of the body is
/// unproven (the local could be `exec`, the `promises` namespace, or
/// anything else).
fn dynamic_fn_used(source: &str, after: usize) -> bool {
    let bytes = source.as_bytes();
    if matches!(bytes.get(after), Some(b'.') | Some(b'[')) {
        return true;
    }
    if bytes.get(after) == Some(&b'?') && bytes.get(after + 1) == Some(&b'.') {
        return true;
    }
    is_invoked(source, after)
}

/// `[`, or `?.[` — a member subscript whose key is not a static
/// string.
fn next_is_computed_member(source: &str, at: usize) -> bool {
    let bytes = source.as_bytes();
    if bytes.get(at) == Some(&b'[') {
        return true;
    }
    bytes.get(at) == Some(&b'?')
        && bytes.get(at + 1) == Some(&b'.')
        && bytes.get(skip_ws_and_comments(source, at + 2)) == Some(&b'[')
}

/// After a `child_process` receiver: `.exec(`, `?.exec(`, `.default.execFile(`, `.promises.execFile(`, `["execFile"](` —
/// or `[name]`/`?.[k]`, which cannot be proven either way.
fn member_cp_usage(source: &str, at: usize, require_call: bool) -> CpMember {
    let bytes = source.as_bytes();
    let mut i = skip_ws_and_comments(source, at);
    if bytes.get(i) == Some(&b'?') && bytes.get(i + 1) == Some(&b'.') {
        i = skip_ws_and_comments(source, i + 2);
    } else if bytes.get(i) == Some(&b'.') {
        i = skip_ws_and_comments(source, i + 1);
    } else if bytes.get(i) != Some(&b'[') {
        return CpMember::No;
    }
    if bytes.get(i) == Some(&b'[') {
        return bracket_cp_usage(source, i, require_call);
    }
    let Some((method, after_method)) = take_ident(source, i) else {
        return CpMember::No;
    };
    let after_method = skip_ws_and_comments(source, after_method);
    if is_cp_namespace_hop(&method) {
        return member_cp_usage(source, after_method, require_call);
    }
    if !is_cp_method(&method) {
        return CpMember::No;
    }
    // `is_invoked`'s adapter walk resolves `["call"]`-style literal
    // spellings — what remains under `[`/`?.[` is a computed property
    // of the method object (`call`/`apply`/`bind` cannot be ruled
    // out), which is unprovable rather than clean.
    if is_invoked(source, after_method) {
        return CpMember::Exec;
    }
    if next_is_computed_member(source, after_method) {
        return CpMember::Unresolved;
    }
    if require_call {
        CpMember::No
    } else {
        CpMember::Exec
    }
}

fn bracket_cp_usage(source: &str, at_bracket: usize, require_call: bool) -> CpMember {
    let bytes = source.as_bytes();
    if bytes.get(at_bracket) != Some(&b'[') {
        return CpMember::No;
    }
    let i = skip_ws_and_comments(source, at_bracket + 1);
    let Some((name, after_name)) = take_string(source, i) else {
        // `cp[name]` — a computed key on a cp receiver; the member it
        // picks is unprovable.
        return CpMember::Unresolved;
    };
    let i = skip_ws_and_comments(source, after_name);
    if bytes.get(i) != Some(&b']') {
        return CpMember::Unresolved;
    }
    let after = skip_ws_and_comments(source, i + 1);
    if is_cp_namespace_hop(&name) {
        return member_cp_usage(source, after, require_call);
    }
    if !is_cp_method(&name) {
        return CpMember::No;
    }
    if is_invoked(source, after) {
        return CpMember::Exec;
    }
    if next_is_computed_member(source, after) {
        return CpMember::Unresolved;
    }
    if require_call {
        CpMember::No
    } else {
        CpMember::Exec
    }
}

fn promisify_cp_invoked(source: &str, i: usize, bindings: &ChildProcessBindings) -> CpMember {
    let Some((close, member)) = promisify_cp_call_close(source, i, bindings) else {
        return CpMember::No;
    };
    if member == CpMember::Unresolved {
        return CpMember::Unresolved;
    }
    if is_invoked(source, skip_ws_and_comments(source, close + 1)) {
        CpMember::Exec
    } else {
        CpMember::No
    }
}

fn promisify_cp_call_close(
    source: &str,
    i: usize,
    bindings: &ChildProcessBindings,
) -> Option<(usize, CpMember)> {
    let after_name = promisify_callee_end(source, i)?;
    let i = skip_ws_and_comments(source, after_name);
    if source.as_bytes().get(i) != Some(&b'(') {
        return None;
    }
    let close = find_matching(source, i, '(', ')')?;
    match args_ref_cp_usage(&source[i + 1..close], bindings) {
        CpMember::No => None,
        member => Some((close, member)),
    }
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

fn args_ref_cp_usage(args: &str, bindings: &ChildProcessBindings) -> CpMember {
    let mut scan = JsScan::new();
    let mut out = CpMember::No;
    while scan.i < args.len() {
        if skip_js_atom(&mut scan, args) {
            continue;
        }
        if let Some(after_mod) = cp_module_expr_at(args, scan.i) {
            let after = skip_closing_parens(args, skip_ws_and_comments(args, after_mod));
            match member_cp_usage(args, after, false) {
                CpMember::Exec => return CpMember::Exec,
                CpMember::Unresolved => out = CpMember::Unresolved,
                CpMember::No => {}
            }
            scan.i = after_mod;
            continue;
        }
        if let Some((ident, after_ident)) = take_ident(args, scan.i) {
            let after = skip_ws_and_comments(args, after_ident);
            let mut member = if bindings.module_aliases.contains(&ident) {
                member_cp_usage(args, after, false)
            } else {
                CpMember::No
            };
            if member == CpMember::No && !preceded_by_dot(args, scan.i) {
                if bindings.dynamic_fns.contains(&ident) {
                    // `promisify(f)` / `Reflect.apply(f, …)` where `f` is a
                    // dynamically-bound cp member — the wrapped callable
                    // could be exec.
                    member = CpMember::Unresolved;
                } else if bindings.imported_fns.contains(&ident) {
                    member = CpMember::Exec;
                }
            }
            match member {
                CpMember::Exec => return CpMember::Exec,
                CpMember::Unresolved => out = CpMember::Unresolved,
                CpMember::No => {}
            }
            scan.i = after_ident;
            continue;
        }
        scan.bump(args);
    }
    out
}

fn then_callback_cp_usage(
    body: &str,
    after_import: usize,
    bindings: &ChildProcessBindings,
) -> CpScan {
    let Some(after_then) = skip_member_named(body, after_import, "then") else {
        return CpScan::default();
    };
    let i = skip_ws_and_comments(body, after_then);
    if body.as_bytes().get(i) != Some(&b'(') {
        return CpScan::default();
    }
    let i = skip_ws_and_comments(body, i + 1);
    let Some((param, cb)) = take_callback_param_and_body(body, i) else {
        return CpScan::default();
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
    collect_assign_bindings(
        &cb,
        &mut extra.module_aliases,
        &mut extra.imported_fns,
        &mut extra.dynamic_fns,
    );
    js_scan_cp_usage(&cb, &extra)
}

/// `const run = m.default.promises.execFile` inside a `.then` callback.
fn collect_assign_bindings(
    source: &str,
    aliases: &mut HashSet<String>,
    imported: &mut HashSet<String>,
    dynamic: &mut HashSet<String>,
) {
    let mut i = 0;
    while i < source.len() {
        i = skip_ws_and_comments(source, i);
        if i >= source.len() {
            break;
        }
        if let Some((ident, next)) = take_ident(source, i) {
            if matches!(ident.as_str(), "const" | "let" | "var") {
                collect_require_binding(source, next, aliases, imported, dynamic);
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

fn reflect_or_proto_cp_usage(source: &str, i: usize, bindings: &ChildProcessBindings) -> CpMember {
    if let Some(at_paren) = reflect_apply_call_paren(source, i) {
        return first_arg_cp_usage(source, at_paren, bindings);
    }
    if let Some(at_paren) = function_proto_double_adapter_paren(source, i) {
        return first_arg_cp_usage(source, at_paren, bindings);
    }
    CpMember::No
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

fn first_arg_cp_usage(source: &str, at_paren: usize, bindings: &ChildProcessBindings) -> CpMember {
    if source.as_bytes().get(at_paren) != Some(&b'(') {
        return CpMember::No;
    }
    let Some(close) = find_matching(source, at_paren, '(', ')') else {
        return CpMember::No;
    };
    let inner = &source[at_paren + 1..close];
    let start = skip_ws_and_comments(inner, 0);
    let end = scan_js_expression_until(inner, start);
    let first = inner.get(start..end).unwrap_or("").trim();
    if first.is_empty() {
        CpMember::No
    } else {
        args_ref_cp_usage(first, bindings)
    }
}
