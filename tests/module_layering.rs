//! Static check of the module dependency direction documented in
//! `docs/modules.md` ("Dependency direction").
//!
//! Every `crate::<module>` reference under `src/` is collected — including
//! grouped imports (`use crate::{a, b};`), nested trees
//! (`use crate::{a::x, b::y};`), and `pub use crate::…` re-exports — and
//! must point at the same module or a lower layer. Layer-0 modules are the
//! shared leaves: any module may reference them, and leaves may reference
//! one another (see the runbook's "葉同士なので許容する").
//!
//! Uses only `std` and the existing `regex-lite` dependency.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use regex_lite::Regex;

/// Layer table — keep in sync with `docs/modules.md`.
///
/// Lower numbers are deeper layers. `main`/`lib`/`bin` are the crate roots
/// and binaries; they sit at the top and may reference everything.
const LAYERS: &[(&str, u8)] = &[
    ("error", 0),
    ("termutil", 0),
    ("pathutil", 0),
    ("fspriv", 0),
    ("tool_def", 0),
    ("framing", 0),
    ("protocol", 0),
    ("audit_log", 0),
    ("secret_paths", 0),
    ("workload", 0),
    ("policy", 1),
    ("verifier", 2),
    ("inspector", 2),
    ("auditor", 3),
    ("warden", 3),
    ("legislator", 4),
    ("runtime", 5),
    ("container", 5),
    ("cli", 6),
    ("commands", 7),
    ("lib", 8),
    ("main", 8),
    ("bin", 8),
];

/// Allowed `(source_module, target_module)` edges that violate the rule.
/// Must stay empty; an entry requires a comment explaining why.
const EXCEPTIONS: &[(&str, &str)] = &[];

/// Top-level module name for a `src/`-relative path:
/// `src/foo.rs` → `foo`, `src/foo/…` → `foo`, `src/bin/x.rs` → `bin`.
fn module_of(path: &Path) -> String {
    let mut comps = path.components();
    let first = comps.next().expect("non-empty relative path");
    let s = first.as_os_str().to_string_lossy();
    if s.ends_with(".rs") {
        s.trim_end_matches(".rs").to_string()
    } else {
        s.into_owned()
    }
}

/// Remove `//` line comments, nested `/* … */` block comments, string
/// literals (`"…"`, `b"…"`), raw strings (`r"…"`, `r#"…"#`, …), and char
/// literals (`'x'`, `'\n'`, `'\u{…}'`). Kept text is replaced by spaces so
/// byte offsets of real code stay stable for error messages.
fn strip_comments_and_strings(src: &str) -> String {
    let bytes = src.as_bytes();
    let mut out = vec![b' '; bytes.len()];
    let mut i = 0;
    let n = bytes.len();
    let blank = |out: &mut [u8], from: usize, to: usize| {
        for (b, &orig) in out[from..to].iter_mut().zip(&bytes[from..to]) {
            *b = if orig == b'\n' { orig } else { b' ' };
        }
    };
    while i < n {
        // line comment
        if bytes[i] == b'/' && i + 1 < n && bytes[i + 1] == b'/' {
            let mut j = i;
            while j < n && bytes[j] != b'\n' {
                j += 1;
            }
            blank(&mut out, i, j);
            i = j;
            continue;
        }
        // block comment (Rust nests them)
        if bytes[i] == b'/' && i + 1 < n && bytes[i + 1] == b'*' {
            let mut j = i + 2;
            let mut depth = 1;
            while j < n && depth > 0 {
                if bytes[j] == b'/' && j + 1 < n && bytes[j + 1] == b'*' {
                    depth += 1;
                    j += 2;
                } else if bytes[j] == b'*' && j + 1 < n && bytes[j + 1] == b'/' {
                    depth -= 1;
                    j += 2;
                } else {
                    j += 1;
                }
            }
            blank(&mut out, i, j.min(n));
            i = j;
            continue;
        }
        // raw string: r"…", r#"…"#, r##"…"##, … (also br"…" / br#"…"#)
        let mut k = i;
        if bytes[k] == b'b' && k + 1 < n && bytes[k + 1] == b'r' {
            k += 1;
        }
        if bytes[k] == b'r' {
            let mut h = k + 1;
            while h < n && bytes[h] == b'#' {
                h += 1;
            }
            if h < n && bytes[h] == b'"' {
                // candidate raw string — but only if `r` is not part of an
                // identifier (e.g. `parser` ends with `r`).
                let ident_before =
                    i > 0 && (bytes[i - 1].is_ascii_alphanumeric() || bytes[i - 1] == b'_');
                if !ident_before {
                    let hashes = h - (k + 1);
                    let mut j = h + 1;
                    loop {
                        if j >= n {
                            break;
                        }
                        if bytes[j] == b'"' {
                            let mut ok = true;
                            for m in 0..hashes {
                                if j + 1 + m >= n || bytes[j + 1 + m] != b'#' {
                                    ok = false;
                                    break;
                                }
                            }
                            if ok {
                                j += 1 + hashes;
                                break;
                            }
                        }
                        j += 1;
                    }
                    blank(&mut out, i, j.min(n));
                    i = j;
                    continue;
                }
            }
        }
        // byte / plain string literal: b"…" or "…" with \-escapes.
        let str_start = if bytes[i] == b'b' && i + 1 < n && bytes[i + 1] == b'"' {
            let ident_before =
                i > 0 && (bytes[i - 1].is_ascii_alphanumeric() || bytes[i - 1] == b'_');
            if ident_before { None } else { Some(i + 1) }
        } else if bytes[i] == b'"' {
            Some(i)
        } else {
            None
        };
        if let Some(q) = str_start {
            let mut j = q + 1;
            while j < n {
                if bytes[j] == b'\\' {
                    j += 2;
                    continue;
                }
                if bytes[j] == b'"' {
                    j += 1;
                    break;
                }
                j += 1;
            }
            blank(&mut out, i, j.min(n));
            i = j;
            continue;
        }
        // char literal: 'x', '\n', '\u{1f600}' — never contains `crate::`,
        // but a '"' inside would confuse string tracking, so consume it.
        if bytes[i] == b'\'' {
            let mut j = i + 1;
            let mut is_char = false;
            if j < n && bytes[j] == b'\\' {
                // escape sequence
                j += 1;
                if j < n && bytes[j] == b'u' && j + 1 < n && bytes[j + 1] == b'{' {
                    j += 2;
                    while j < n && bytes[j] != b'}' {
                        j += 1;
                    }
                    j += 1; // consume '}'
                } else if j < n && bytes[j] == b'x' {
                    j += 3; // \xNN
                } else {
                    j += 1; // \n \t \r \\ \' \" \0
                }
                if j < n && bytes[j] == b'\'' {
                    is_char = true;
                    j += 1;
                }
            } else if j + 1 < n && bytes[j + 1] == b'\'' {
                is_char = true;
                j += 2;
            }
            if is_char {
                blank(&mut out, i, j);
                i = j;
                continue;
            }
            // lifetime or label — fall through, keep the char
        }
        out[i] = bytes[i];
        i += 1;
    }
    String::from_utf8(out).expect("blanked source stays valid UTF-8")
}

/// Collect referenced top-level module names from `crate::` paths in
/// already-stripped source. `crate::{a, b::c}` expands to `a` and `b`.
fn collect_crate_refs(src: &str) -> Vec<(String, usize)> {
    let mut out = Vec::new();
    let keyword = Regex::new(r"\bcrate\s*::\s*").unwrap();
    let ident = Regex::new(r"^[a-zA-Z_][a-zA-Z0-9_]*").unwrap();
    for m in keyword.find_iter(src) {
        let pos = m.end();
        let rest = &src[pos..];
        if rest.starts_with('{') {
            // use-tree group: each top-level comma item's first ident is a
            // module name. Find the matching close brace.
            let bytes = src.as_bytes();
            let mut depth = 0;
            let mut j = pos;
            while j < bytes.len() {
                match bytes[j] {
                    b'{' => depth += 1,
                    b'}' => {
                        depth -= 1;
                        if depth == 0 {
                            break;
                        }
                    }
                    _ => {}
                }
                j += 1;
            }
            let inner = &src[pos + 1..j.min(bytes.len())];
            // split on top-level commas (depth 0)
            let mut depth = 0;
            let mut item_start = 0;
            let ibytes = inner.as_bytes();
            for (idx, &b) in ibytes.iter().enumerate() {
                match b {
                    b'{' => depth += 1,
                    b'}' => depth -= 1,
                    b',' if depth == 0 => {
                        if let Some(name) = first_ident(&inner[item_start..idx], &ident) {
                            out.push((name, pos + 1 + item_start));
                        }
                        item_start = idx + 1;
                    }
                    _ => {}
                }
            }
            if let Some(name) = first_ident(&inner[item_start..], &ident) {
                out.push((name, pos + 1 + item_start));
            }
        } else if let Some(name) = first_ident(rest, &ident) {
            out.push((name, m.end()));
        }
    }
    out
}

/// First identifier in `s`, skipping `self`/`super`/`crate`/`as`-style
/// keywords that never name a `src/` module.
fn first_ident(s: &str, ident: &Regex) -> Option<String> {
    let s = s.trim_start();
    let m = ident.find(s)?;
    let name = m.as_str();
    if matches!(name, "self" | "super" | "crate") {
        return None;
    }
    Some(name.to_string())
}

fn layer_of(name: &str) -> Option<u8> {
    LAYERS.iter().find(|(m, _)| *m == name).map(|(_, l)| *l)
}

fn collect_rs_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(dir).expect("read src dir") {
        let path = entry.expect("dir entry").path();
        if path.is_dir() {
            collect_rs_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

#[test]
fn module_references_only_point_downward() {
    let src_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    collect_rs_files(&src_dir, &mut files);
    files.sort();
    assert!(!files.is_empty(), "no sources under {}", src_dir.display());

    let exceptions: BTreeSet<(&str, &str)> = EXCEPTIONS.iter().copied().collect();
    let mut violations = Vec::new();
    let mut unknown_sources = Vec::new();

    for file in &files {
        let rel = file.strip_prefix(&src_dir).unwrap();
        let module = module_of(rel);
        let Some(src_layer) = layer_of(&module) else {
            unknown_sources.push(format!(
                "{}: module '{module}' is missing from the LAYERS table",
                rel.display()
            ));
            continue;
        };
        let text = fs::read_to_string(file).expect("read source file");
        let stripped = strip_comments_and_strings(&text);
        for (target, offset) in collect_crate_refs(&stripped) {
            if target == module {
                continue;
            }
            let Some(target_layer) = layer_of(&target) else {
                violations.push(format!(
                    "{}: '{module}' references unknown module 'crate::{target}'",
                    rel.display()
                ));
                continue;
            };
            if target_layer == 0 || target_layer < src_layer {
                continue;
            }
            if exceptions.contains(&(module.as_str(), target.as_str())) {
                continue;
            }
            let line = stripped[..offset].matches('\n').count() + 1;
            violations.push(format!(
                "{}:{line}: layer-{src_layer} module '{module}' references \
                 layer-{target_layer} 'crate::{target}' (upward or same-layer)",
                rel.display()
            ));
        }
    }

    assert!(
        unknown_sources.is_empty(),
        "modules missing from the LAYERS table:\n{}",
        unknown_sources.join("\n")
    );
    assert!(
        violations.is_empty(),
        "dependency-direction violations (see docs/modules.md):\n{}",
        violations.join("\n")
    );
}

// ---- unit tests for the scanner itself ----

#[test]
fn refs_direct_path() {
    let refs = collect_crate_refs("use crate::verifier::hash::foo;");
    assert_eq!(refs.len(), 1);
    assert_eq!(refs[0].0, "verifier");
}

#[test]
fn refs_grouped_import() {
    let refs = collect_crate_refs("use crate::{auditor, verifier};");
    let names: Vec<&str> = refs.iter().map(|r| r.0.as_str()).collect();
    assert_eq!(names, ["auditor", "verifier"]);
}

#[test]
fn refs_nested_use_tree() {
    let refs = collect_crate_refs("use crate::{auditor::checker, verifier::hash};");
    let names: Vec<&str> = refs.iter().map(|r| r.0.as_str()).collect();
    assert_eq!(names, ["auditor", "verifier"]);
}

#[test]
fn refs_deeply_nested_and_pub_use() {
    let src = "pub use crate::{a::{x, y}, b};\nlet _ = crate::c::f();";
    let refs = collect_crate_refs(src);
    let names: Vec<&str> = refs.iter().map(|r| r.0.as_str()).collect();
    assert_eq!(names, ["a", "b", "c"]);
}

#[test]
fn comments_and_strings_do_not_count() {
    let src = concat!(
        "/// doc mention crate::warden::spawn should not count\n",
        "// line comment crate::warden::x\n",
        "/* block crate::warden::y */ let s = \"crate::warden::z\";\n",
        "let r = r#\"crate::warden::raw\"#;\n",
        "let c = '\"';\n",
        "use crate::policy::Policy;\n",
    );
    let stripped = strip_comments_and_strings(src);
    let refs = collect_crate_refs(&stripped);
    let names: Vec<&str> = refs.iter().map(|r| r.0.as_str()).collect();
    assert_eq!(names, ["policy"]);
}

#[test]
fn block_comments_nest() {
    let src = "/* outer /* inner crate::warden::x */ still comment */ use crate::policy::P;";
    let refs = collect_crate_refs(&strip_comments_and_strings(src));
    assert_eq!(refs.len(), 1);
    assert_eq!(refs[0].0, "policy");
}

#[test]
fn masked_regions_keep_newlines() {
    let src = "/* a\nb\ncrate::warden::x */ crate::policy::P;";
    let stripped = strip_comments_and_strings(src);
    assert_eq!(
        stripped.matches('\n').count(),
        src.matches('\n').count(),
        "masked bytes must keep original newlines so line numbers stay accurate"
    );
    let refs = collect_crate_refs(&stripped);
    assert_eq!(refs.len(), 1);
    assert_eq!(refs[0].0, "policy");
}
