//! Documentation checks, ported from the retired `scripts/check_docs.py`.
//!
//! Every `*.md` file under the repository root, `docs/`, `tests/` and
//! `.github/` must be UTF-8 without BOM, use LF line endings, and only
//! contain local links that resolve to an existing in-tree file. A link
//! carrying a `#fragment` additionally requires the target document to
//! have a matching heading anchor.
//!
//! The anchor slug rules mirror the Python `anchors()` implementation:
//! strip `<...>` tags from the heading text, lowercase, keep `_`, `-`,
//! whitespace and characters in Unicode general categories L/N/M, map
//! whitespace to `-`, and number duplicate slugs `-1`, `-2`, ...
//! `regex-lite` provides no Unicode classes, so `is_lnm` consults
//! `LNM_RANGES`, a table generated from the same `unicodedata` version
//! the script ran on (Python 3.12 / Unicode 15.0.0).
//!
//! Three malformed-input paths panic rather than produce an error line,
//! matching the script's uncaught exceptions: `urlsplit`'s `ValueError`
//! on a malformed netloc, `read_bytes()` on a `*.md` directory, and
//! `relative_to()` on a document resolving outside the root.

use std::collections::{HashMap, HashSet};
use std::ffi::OsString;
use std::fs;
use std::net::IpAddr;
use std::path::{Component, Path, PathBuf};

use regex_lite::Regex;
use unicode_normalization::UnicodeNormalization;

/// Python's whitespace set: `str.isspace()` and the `re` module's `\s`
/// accept exactly these code points (bidirectional WS/B/S plus the Z
/// separators). `regex-lite` `\s` is ASCII-only, so patterns spell this
/// set out instead.
const PY_WS: &str = "\\x{09}-\\x{0D}\\x{1C}-\\x{1F}\\x{20}\\x{85}\\x{A0}\\x{1680}\\x{2000}-\\x{200A}\\x{2028}\\x{2029}\\x{202F}\\x{205F}\\x{3000}";

fn is_py_space(c: char) -> bool {
    matches!(c,
        '\u{09}'..='\u{0D}' | '\u{1C}'..='\u{1F}' | '\u{20}' | '\u{85}'
        | '\u{A0}' | '\u{1680}' | '\u{2000}'..='\u{200A}' | '\u{2028}'
        | '\u{2029}' | '\u{202F}' | '\u{205F}' | '\u{3000}')
}

/// `str.splitlines()` boundaries: `\r\n` counts as one break.
fn py_lines(text: &str) -> Vec<&str> {
    fn is_break(c: char) -> bool {
        matches!(
            c,
            '\n' | '\r'
                | '\u{0B}'
                | '\u{0C}'
                | '\u{1C}'
                | '\u{1D}'
                | '\u{1E}'
                | '\u{85}'
                | '\u{2028}'
                | '\u{2029}'
        )
    }
    let mut lines = Vec::new();
    let mut start = 0usize;
    let mut it = text.char_indices().peekable();
    while let Some((i, c)) = it.next() {
        if !is_break(c) {
            continue;
        }
        lines.push(&text[start..i]);
        start = i + c.len_utf8();
        if c == '\r'
            && let Some(&(j, '\n')) = it.peek()
        {
            it.next();
            start = j + 1;
        }
    }
    if start < text.len() {
        lines.push(&text[start..]);
    }
    lines
}

/// `prose()`: drop fenced code blocks. A closing fence uses the same
/// character and is at least as long as the opening run.
fn prose(text: &str) -> String {
    let fence_re = Regex::new(&format!("^[{PY_WS}]*(`{{3,}}|~{{3,}})")).unwrap();
    let mut open: Option<(char, usize)> = None;
    let mut out: Vec<&str> = Vec::new();
    for line in py_lines(text) {
        if let Some(m) = fence_re.captures(line).and_then(|c| c.get(1)) {
            let token = m.as_str();
            match open {
                None => open = Some((token.chars().next().unwrap(), token.len())),
                Some((fc, fl)) if token.starts_with(fc) && token.len() >= fl => open = None,
                _ => {}
            }
            continue;
        }
        if open.is_none() {
            out.push(line);
        }
    }
    out.join("\n")
}

/// `anchors()`: heading slugs plus `<a id>`/`<a name>` targets.
fn anchors(text: &str) -> HashSet<String> {
    let heading_re =
        Regex::new(&format!("^#{{1,6}}[{PY_WS}]+(.+?)[{PY_WS}]*#*[{PY_WS}]*$")).unwrap();
    let tag_re = Regex::new("<[^>]*>").unwrap();
    let a_re = Regex::new(&format!("<a[{PY_WS}]+(?:id|name)=[\"']([^\"']+)[\"']")).unwrap();
    let mut ids = HashSet::new();
    let mut counts: HashMap<String, usize> = HashMap::new();
    for line in py_lines(&prose(text)) {
        let Some(m) = heading_re.captures(line).and_then(|c| c.get(1)) else {
            continue;
        };
        let title = tag_re.replace_all(m.as_str(), "").to_lowercase();
        let mut slug = String::with_capacity(title.len());
        for ch in title.chars() {
            if ch == '_' || ch == '-' || is_lnm(ch) {
                slug.push(ch);
            } else if is_py_space(ch) {
                slug.push('-');
            }
        }
        let count = counts.entry(slug.clone()).or_insert(0);
        let n = *count;
        *count += 1;
        ids.insert(if n == 0 { slug } else { format!("{slug}-{n}") });
    }
    for cap in a_re.captures_iter(text) {
        ids.insert(cap.get(1).unwrap().as_str().to_string());
    }
    ids
}

/// `urllib.parse.unquote`: `%XX` byte escapes decoded as UTF-8, with
/// invalid sequences replaced like `errors="replace"`.
fn unquote(s: &str) -> String {
    fn hex(b: u8) -> Option<u8> {
        match b {
            b'0'..=b'9' => Some(b - b'0'),
            b'a'..=b'f' => Some(b - b'a' + 10),
            b'A'..=b'F' => Some(b - b'A' + 10),
            _ => None,
        }
    }
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && i + 2 < bytes.len()
            && let (Some(h), Some(l)) = (hex(bytes[i + 1]), hex(bytes[i + 2]))
        {
            out.push(h * 16 + l);
            i += 3;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// The parts of `urllib.parse.urlsplit` the check uses.
struct UrlParts {
    /// `url.scheme or url.netloc` — the link is not local.
    external: bool,
    path: String,
    fragment: String,
}

fn url_split(value: &str) -> UrlParts {
    // urlsplit removes ASCII tab/CR/LF and strips leading C0 controls and
    // spaces before parsing.
    let cleaned = value
        .replace(['\t', '\r', '\n'], "")
        .trim_start_matches(|c: char| c <= ' ')
        .to_string();
    let mut url = cleaned.as_str();
    let mut external = false;
    // scheme = [A-Za-z][A-Za-z0-9+.-]* followed by ':'
    if let Some(i) = url.find(':')
        && i > 0
        && url.as_bytes()[0].is_ascii_alphabetic()
        && url[..i]
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'-' | b'.'))
    {
        external = true;
        url = &url[i + 1..];
    }
    if url.starts_with("//") {
        let delim = url[2..]
            .find(['/', '?', '#'])
            .map(|p| p + 2)
            .unwrap_or(url.len());
        check_netloc(&url[2..delim]);
        external = external || delim > 2;
        url = &url[delim..];
    }
    let mut fragment = "";
    if let Some(i) = url.find('#') {
        fragment = &url[i + 1..];
        url = &url[..i];
    }
    if let Some(i) = url.find('?') {
        url = &url[..i];
    }
    UrlParts {
        external,
        path: url.to_string(),
        fragment: fragment.to_string(),
    }
}

/// `urlsplit`'s netloc validation raises `ValueError`, crashing the
/// script; panic so the same inputs fail this check.
fn check_netloc(netloc: &str) {
    match (netloc.contains('['), netloc.contains(']')) {
        (true, false) | (false, true) => panic!("Invalid IPv6 URL: {netloc}"),
        (true, true) => check_bracketed_netloc(netloc),
        (false, false) => {}
    }
    // `_checknetloc`: a non-ASCII netloc is NFKC-normalized ignoring
    // '@', ':', '#' and '?'; a change introducing a URL delimiter means
    // an IDNA-equivalent character smuggled one in.
    if !netloc.is_ascii() {
        let n: String = netloc
            .chars()
            .filter(|c| !matches!(c, '@' | ':' | '#' | '?'))
            .collect();
        let normalized: String = n.chars().nfkc().collect();
        if normalized != n
            && normalized
                .chars()
                .any(|c| matches!(c, '/' | '?' | '#' | '@' | ':'))
        {
            panic!("netloc '{netloc}' contains invalid characters under NFKC normalization");
        }
    }
}

/// `_check_bracketed_netloc`: validate the host part of a netloc that
/// contains both brackets.
fn check_bracketed_netloc(netloc: &str) {
    let host_port = netloc.rsplit_once('@').map_or(netloc, |(_, t)| t);
    let hostname = match host_port.split_once('[') {
        Some(("", bracketed)) => {
            let (host, port) = bracketed.split_once(']').unwrap_or((bracketed, ""));
            if !port.is_empty() && !port.starts_with(':') {
                panic!("Invalid IPv6 URL: {netloc}");
            }
            host
        }
        Some(_) => panic!("Invalid IPv6 URL: {netloc}"),
        None => host_port.split(':').next().unwrap(),
    };
    check_bracketed_host(hostname);
}

/// `_check_bracketed_host`: `v…` must be an IPvFuture literal,
/// otherwise the host must be a valid IPv6 literal (bracketed IPv4 is
/// rejected separately).
fn check_bracketed_host(host: &str) {
    // \Av[a-fA-F0-9]+\..+\Z
    if let Some(rest) = host.strip_prefix('v') {
        let ok = rest.find('.').is_some_and(|dot| {
            dot > 0 && rest[..dot].bytes().all(|b| b.is_ascii_hexdigit()) && dot + 1 < rest.len()
        });
        if !ok {
            panic!("IPvFuture address is invalid: {host}");
        }
        return;
    }
    // `ipaddress.ip_address` also accepts a `%scope` suffix on IPv6;
    // an empty scope or one containing another '%' is rejected.
    let base = match host.split_once('%') {
        Some((b, scope)) if !scope.is_empty() && !scope.contains('%') => b,
        Some(_) => panic!("{host} does not appear to be an IPv4 or IPv6 address"),
        None => host,
    };
    match base.parse::<IpAddr>() {
        Ok(IpAddr::V6(_)) => {}
        Ok(IpAddr::V4(_)) => panic!("An IPv4 address cannot be in brackets: {host}"),
        Err(_) => panic!("{host} does not appear to be an IPv4 or IPv6 address"),
    }
}

/// `Path.resolve()` (`os.path.realpath`, strict=False): canonicalize
/// the longest existing prefix — the filesystem resolves `..` *after*
/// symlinks — then re-attach the missing tail and normalize lexically.
fn resolve(path: &Path) -> PathBuf {
    let mut cur = path.to_path_buf();
    let mut tail: Vec<OsString> = Vec::new();
    let mut expanded: HashSet<String> = HashSet::new();
    loop {
        match fs::canonicalize(&cur) {
            Ok(p) => {
                let mut out = strip_verbatim(&p);
                for c in tail.iter().rev() {
                    out.push(c);
                }
                return normalize(&out);
            }
            Err(_) => {
                // `realpath` expands a symlink even when its target is
                // missing: a following `..` cancels the link's expanded
                // tail, not the link name itself.
                if let Ok(target) = fs::read_link(&cur)
                    && expanded.insert(norm_key(&normalize(&cur)))
                {
                    cur = expand_link(&cur, target);
                    continue;
                }
                let Some(c) = cur.components().next_back() else {
                    return normalize(path);
                };
                if matches!(c, Component::Prefix(_) | Component::RootDir) {
                    return normalize(path);
                }
                tail.push(c.as_os_str().to_os_string());
                cur.pop();
            }
        }
    }
}

/// Symlink expansion during `resolve()`: a relative target resolves
/// against the link's parent; on Windows a `\`-rooted target keeps only
/// the parent's drive/UNC prefix, like `ntpath.join`.
fn expand_link(cur: &Path, target: PathBuf) -> PathBuf {
    if target.is_absolute() {
        return target;
    }
    let parent = cur.parent().unwrap_or_else(|| Path::new(""));
    if cfg!(windows) && target.has_root() {
        let mut out = PathBuf::new();
        for c in parent.components() {
            match c {
                Component::Prefix(_) | Component::RootDir => out.push(c.as_os_str()),
                _ => break,
            }
        }
        for c in target.components() {
            if !matches!(c, Component::RootDir) {
                out.push(c.as_os_str());
            }
        }
        out
    } else {
        parent.join(target)
    }
}

/// `canonicalize` reports verbatim `\\?\` paths on Windows; `resolve()`
/// yields the plain form instead (`\\?\UNC\s\p` becomes `\\s\p`).
#[cfg(windows)]
fn strip_verbatim(p: &Path) -> PathBuf {
    let s = p.as_os_str().to_string_lossy();
    if let Some(rest) = s.strip_prefix(r"\\?\UNC\") {
        PathBuf::from(format!(r"\\{rest}"))
    } else if let Some(rest) = s.strip_prefix(r"\\?\") {
        PathBuf::from(rest)
    } else {
        p.to_path_buf()
    }
}

#[cfg(not(windows))]
fn strip_verbatim(p: &Path) -> PathBuf {
    p.to_path_buf()
}

/// `base_dir / rel` joined lexically; `resolve()` at the call site
/// performs `Path.resolve()`. On Windows a `/`- or `\`-rooted `rel`
/// keeps only the drive/UNC prefix of `base_dir`, as `PureWindowsPath`
/// does; a drive-qualified `rel` never reaches here because `urlsplit`
/// reads `x:` as a scheme.
fn resolve_link(base_dir: &Path, rel: &str) -> PathBuf {
    let rooted = rel.starts_with('/') || (cfg!(windows) && rel.starts_with('\\'));
    let mut out = PathBuf::new();
    if rooted {
        for c in base_dir.components() {
            match c {
                Component::Prefix(_) | Component::RootDir => out.push(c.as_os_str()),
                _ => break,
            }
        }
        out.push(rel);
    } else {
        out = base_dir.join(rel);
    }
    normalize(&out)
}

/// Collapse `.` and `..` the way `os.path.normpath` does on an already
/// absolute path: parent links at the filesystem root disappear.
fn normalize(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for c in path.components() {
        match c {
            Component::CurDir => {}
            Component::ParentDir => {
                if matches!(out.components().next_back(), Some(Component::Normal(_))) {
                    out.pop();
                }
            }
            _ => out.push(c.as_os_str()),
        }
    }
    out
}

/// Comparison key matching pathlib's `normcase`: `\` separators and
/// lower-cased on Windows, byte-exact elsewhere.
fn norm_key(p: &Path) -> String {
    let s = p.to_string_lossy();
    if cfg!(windows) {
        s.replace('/', "\\").to_lowercase()
    } else {
        s.into_owned()
    }
}

/// `Path.is_relative_to`: component-wise prefix match, case-insensitive
/// on Windows like pathlib's `normcase`.
fn is_relative_to(target: &Path, root: &Path) -> bool {
    let mut t = target.components();
    root.components().all(|r| {
        t.next().is_some_and(|c| {
            if cfg!(windows) {
                c.as_os_str().to_string_lossy().to_lowercase()
                    == r.as_os_str().to_string_lossy().to_lowercase()
            } else {
                c == r
            }
        })
    })
}

/// `*.md` under root (top level), then `docs/`, `tests/`, `.github/`
/// recursively, sorted like `sorted()` on `Path` (normcased parts on
/// Windows).
fn collect_markdown(root: &Path) -> Vec<PathBuf> {
    fn is_md(p: &Path) -> bool {
        p.file_name().is_some_and(|n| {
            let n = n.to_string_lossy();
            if cfg!(windows) {
                n.to_lowercase().ends_with(".md")
            } else {
                n.ends_with(".md")
            }
        })
    }
    fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
        let Ok(rd) = fs::read_dir(dir) else { return };
        for e in rd.flatten() {
            let p = e.path();
            if is_md(&p) {
                out.push(p.clone());
            }
            // `rglob` walks with `follow_symlinks=False`: a symlinked
            // directory is matched by name but never descended into.
            if e.file_type().is_ok_and(|t| t.is_dir()) {
                walk(&p, out);
            }
        }
    }
    let mut files = Vec::new();
    // `glob` yields directories matching `*.md` too; `read_bytes()` then
    // raises `IsADirectoryError`, so no `is_file()` filter here either.
    if let Ok(rd) = fs::read_dir(root) {
        for e in rd.flatten() {
            let p = e.path();
            if is_md(&p) {
                files.push(p);
            }
        }
    }
    for sub in ["docs", "tests", ".github"] {
        walk(&root.join(sub), &mut files);
    }
    files.sort_by_key(|p| parts_key(p));
    files.dedup();
    files
}

fn parts_key(p: &Path) -> Vec<String> {
    p.components()
        .map(|c| {
            let s = c.as_os_str().to_string_lossy();
            if cfg!(windows) {
                s.to_lowercase()
            } else {
                s.into_owned()
            }
        })
        .collect()
}

fn rel_label(root: &Path, p: &Path) -> String {
    p.strip_prefix(root)
        .unwrap()
        .components()
        .map(|c| c.as_os_str().to_string_lossy().into_owned())
        .collect::<Vec<_>>()
        .join("/")
}

/// The full check; error lines are identical to the Python script's.
fn check_all(root: &Path) -> (usize, Vec<String>) {
    let link_re = Regex::new(&format!(
        "\\[[^\\]\\n]*\\]\\([{PY_WS}]*(<[^>]+>|[^{PY_WS})]+)(?:[{PY_WS}]+\"[^\"]*\")?[{PY_WS}]*\\)"
    ))
    .unwrap();
    let mut errors = Vec::new();
    let mut documents: Vec<(PathBuf, String)> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    for path in collect_markdown(root) {
        let label = rel_label(root, &path);
        let data = fs::read(&path).unwrap_or_else(|e| panic!("{label}: {e}"));
        let Ok(text) = std::str::from_utf8(&data) else {
            errors.push(format!("{label}: invalid UTF-8"));
            continue;
        };
        // `documents` is keyed by `path.resolve()`; two globs resolving
        // to the same file collapse like dict entries.
        let resolved = resolve(&path);
        if seen.insert(norm_key(&resolved)) {
            documents.push((resolved, text.to_string()));
        }
        if data.starts_with(b"\xEF\xBB\xBF") || data.contains(&b'\r') {
            errors.push(format!(
                "{label}: use UTF-8 without BOM and LF line endings"
            ));
        }
    }
    // `target in documents` and heading anchors per resolved target.
    let mut anchors_of: HashMap<String, HashSet<String>> = HashMap::new();
    for (path, text) in &documents {
        anchors_of.insert(norm_key(path), anchors(text));
    }
    for (path, text) in &documents {
        let label = rel_label(root, path);
        let parent = path.parent().unwrap();
        for cap in link_re.captures_iter(&prose(text)) {
            let value = cap
                .get(1)
                .unwrap()
                .as_str()
                .trim_matches(|c| c == '<' || c == '>');
            let url = url_split(value);
            if url.external {
                continue;
            }
            let target = if url.path.is_empty() {
                path.clone()
            } else {
                resolve(&resolve_link(parent, &unquote(&url.path)))
            };
            if !is_relative_to(&target, root) || !target.exists() {
                errors.push(format!("{label}: missing local target {value}"));
            } else if !url.fragment.is_empty()
                && let Some(target_anchors) = anchors_of.get(&norm_key(&target))
                && !target_anchors.contains(&unquote(&url.fragment))
            {
                errors.push(format!("{label}: missing heading anchor {value}"));
            }
        }
    }
    (documents.len(), errors)
}

#[test]
fn markdown_files_pass_documentation_checks() {
    // `ROOT = Path(__file__).resolve().parents[1]` is resolved too.
    let root = resolve(&PathBuf::from(env!("CARGO_MANIFEST_DIR")));
    let (count, errors) = check_all(&root);
    if errors.is_empty() {
        println!("Checked {count} Markdown files: encoding and local links OK");
    }
    assert!(errors.is_empty(), "{}", errors.join("\n"));
}

#[test]
fn py_lines_match_splitlines() {
    assert_eq!(py_lines("a\r\nb\rc\u{2028}d\n"), ["a", "b", "c", "d"]);
    assert_eq!(py_lines("a\n\nb"), ["a", "", "b"]);
    assert_eq!(py_lines("a\n"), ["a"]);
    assert_eq!(py_lines(""), Vec::<&str>::new());
}

#[test]
fn prose_drops_fenced_blocks() {
    let text =
        "pre\n```rust\n[x](a.md)\n```\nmid\n~~~\n[y](b.md)\n~~~~\n````\n[z](c.md)\n```\nend\n";
    assert_eq!(prose(text), "pre\nmid");
}

#[test]
fn anchors_slugify_and_dedup() {
    let text = "# Foo Bar!\n## Foo Bar\n## Foo ##\n### 文書チェックの Cargo Test 化\n\
                <a id=\"custom\">x</a>\n```\n# hidden\n```\n";
    let ids = anchors(text);
    assert!(ids.contains("foo-bar"));
    assert!(ids.contains("foo-bar-1"));
    assert!(ids.contains("foo"));
    assert!(ids.contains("文書チェックの-cargo-test-化"));
    assert!(ids.contains("custom"));
    assert!(!ids.contains("hidden"));
    // Combining marks (category M) are kept, like unicodedata does.
    assert!(anchors("# Cafe\u{301}").contains("cafe\u{301}"));
}

#[test]
fn link_re_captures_targets() {
    let link_re = Regex::new(&format!(
        "\\[[^\\]\\n]*\\]\\([{PY_WS}]*(<[^>]+>|[^{PY_WS})]+)(?:[{PY_WS}]+\"[^\"]*\")?[{PY_WS}]*\\)"
    ))
    .unwrap();
    let got: Vec<String> = link_re
        .captures_iter("[a](b.md) [c](<d e.md>) [f](g.md \"t\") [h](https://x)")
        .map(|c| c.get(1).unwrap().as_str().to_string())
        .collect();
    assert_eq!(got, ["b.md", "<d e.md>", "g.md", "https://x"]);
}

#[test]
fn url_split_marks_external() {
    assert!(url_split("https://x/y#f").external);
    assert!(url_split("//host/p").external);
    assert!(url_split("mailto:a@b").external);
    assert!(url_split("C:/x.md").external);
    assert!(url_split("a1+.-:b").external);
    assert!(url_split("localhost:8080").external);
    // urlsplit requires the first scheme char to be a letter and
    // rejects '_' anywhere in it.
    assert!(!url_split("123:foo").external);
    assert!(!url_split("+a:b").external);
    assert!(!url_split(".a:b").external);
    assert!(!url_split("a_b:c").external);
    let u = url_split("docs/a.md#sec");
    assert!(!u.external);
    assert_eq!(u.path, "docs/a.md");
    assert_eq!(u.fragment, "sec");
    let u = url_split("#only");
    assert!(!u.external);
    assert_eq!(u.path, "");
    assert_eq!(u.fragment, "only");
}

#[test]
fn unquote_decodes_percent_escapes() {
    assert_eq!(unquote("%E6%96%87.md"), "文.md");
    assert_eq!(unquote("a%20b"), "a b");
    assert_eq!(unquote("100%"), "100%");
}

#[test]
fn resolve_link_normalizes() {
    let (base, root_file) = if cfg!(windows) {
        (Path::new("D:/r/docs"), Path::new("D:/r/README.md"))
    } else {
        (Path::new("/r/docs"), Path::new("/r/README.md"))
    };
    assert_eq!(resolve_link(base, "../README.md"), root_file);
    assert_eq!(resolve_link(base, "./x.md"), base.join("x.md"));
    let rooted = resolve_link(base, "/a.md");
    assert!(rooted.is_absolute() || rooted.starts_with("D:"));
    assert!(rooted.ends_with("a.md"));
}

#[test]
fn url_split_rejects_python_valueerror_netlocs() {
    // These raise `ValueError` inside `urlsplit`, crashing the script.
    for bad in [
        "http://[",
        "http://x]",
        "//[",
        "//x[0]/",
        "//a]b[/",
        "//u[se]r@host/",
        "//[::1]x/",
        "//[zzz]/",
        "//[127.0.0.1]/",
        "//[v]/",
        "//[fe80::1%]/",
        "//[fe80::1%a%b]/",
    ] {
        assert!(
            std::panic::catch_unwind(|| url_split(bad)).is_err(),
            "{bad}"
        );
    }
    // Valid bracketed hosts stay external instead of panicking.
    assert!(url_split("//[::1]/x").external);
    assert!(url_split("//[v1.fe80::]/x").external);
    assert!(url_split("//[fe80::1%eth0]/x").external);
}

#[test]
fn resolve_canonicalizes_the_existing_prefix() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let real = strip_verbatim(&fs::canonicalize(root).unwrap());
    let file_key = norm_key(&real.join("Cargo.toml"));
    assert_eq!(norm_key(&resolve(&root.join("Cargo.toml"))), file_key);
    // A missing tail is re-attached and normalized like `realpath`.
    assert_eq!(
        norm_key(&resolve(&root.join("docs/../no-such-dir/../Cargo.toml"))),
        file_key
    );
}

#[cfg(unix)]
#[test]
fn resolve_expands_dangling_symlink_targets() {
    use std::os::unix::fs::symlink;
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    // `link -> missing/deep` is dangling; `..` cancels the expanded
    // tail (`deep`), matching `realpath` — not the link name itself.
    symlink("missing/deep", root.join("link")).unwrap();
    fs::write(root.join("x.md"), "").unwrap();
    assert_eq!(
        norm_key(&resolve(&root.join("link/../x.md"))),
        norm_key(&root.join("missing/x.md"))
    );
    assert_eq!(
        norm_key(&resolve(&root.join("link/y.md"))),
        norm_key(&root.join("missing/deep/y.md"))
    );
}

#[test]
fn is_lnm_matches_unicode_categories() {
    assert!(is_lnm('a'));
    assert!(is_lnm('5'));
    assert!(is_lnm('漢'));
    assert!(is_lnm('\u{301}')); // combining mark
    assert!(!is_lnm('!'));
    assert!(!is_lnm('\u{200B}')); // zero-width space (Cf)
}

/// Code points whose `unicodedata.category(chr(c))` starts with L, N or M
/// (Python 3.12, Unicode 15.0.0), as sorted inclusive ranges.
#[rustfmt::skip]
const LNM_RANGES: &[(u32, u32)] = &[
    (0x30, 0x39), (0x41, 0x5A), (0x61, 0x7A), (0xAA, 0xAA), (0xB2, 0xB3), (0xB5, 0xB5),
    (0xB9, 0xBA), (0xBC, 0xBE), (0xC0, 0xD6), (0xD8, 0xF6), (0xF8, 0x2C1), (0x2C6, 0x2D1),
    (0x2E0, 0x2E4), (0x2EC, 0x2EC), (0x2EE, 0x2EE), (0x300, 0x374), (0x376, 0x377), (0x37A, 0x37D),
    (0x37F, 0x37F), (0x386, 0x386), (0x388, 0x38A), (0x38C, 0x38C), (0x38E, 0x3A1), (0x3A3, 0x3F5),
    (0x3F7, 0x481), (0x483, 0x52F), (0x531, 0x556), (0x559, 0x559), (0x560, 0x588), (0x591, 0x5BD),
    (0x5BF, 0x5BF), (0x5C1, 0x5C2), (0x5C4, 0x5C5), (0x5C7, 0x5C7), (0x5D0, 0x5EA), (0x5EF, 0x5F2),
    (0x610, 0x61A), (0x620, 0x669), (0x66E, 0x6D3), (0x6D5, 0x6DC), (0x6DF, 0x6E8), (0x6EA, 0x6FC),
    (0x6FF, 0x6FF), (0x710, 0x74A), (0x74D, 0x7B1), (0x7C0, 0x7F5), (0x7FA, 0x7FA), (0x7FD, 0x7FD),
    (0x800, 0x82D), (0x840, 0x85B), (0x860, 0x86A), (0x870, 0x887), (0x889, 0x88E), (0x898, 0x8E1),
    (0x8E3, 0x963), (0x966, 0x96F), (0x971, 0x983), (0x985, 0x98C), (0x98F, 0x990), (0x993, 0x9A8),
    (0x9AA, 0x9B0), (0x9B2, 0x9B2), (0x9B6, 0x9B9), (0x9BC, 0x9C4), (0x9C7, 0x9C8), (0x9CB, 0x9CE),
    (0x9D7, 0x9D7), (0x9DC, 0x9DD), (0x9DF, 0x9E3), (0x9E6, 0x9F1), (0x9F4, 0x9F9), (0x9FC, 0x9FC),
    (0x9FE, 0x9FE), (0xA01, 0xA03), (0xA05, 0xA0A), (0xA0F, 0xA10), (0xA13, 0xA28), (0xA2A, 0xA30),
    (0xA32, 0xA33), (0xA35, 0xA36), (0xA38, 0xA39), (0xA3C, 0xA3C), (0xA3E, 0xA42), (0xA47, 0xA48),
    (0xA4B, 0xA4D), (0xA51, 0xA51), (0xA59, 0xA5C), (0xA5E, 0xA5E), (0xA66, 0xA75), (0xA81, 0xA83),
    (0xA85, 0xA8D), (0xA8F, 0xA91), (0xA93, 0xAA8), (0xAAA, 0xAB0), (0xAB2, 0xAB3), (0xAB5, 0xAB9),
    (0xABC, 0xAC5), (0xAC7, 0xAC9), (0xACB, 0xACD), (0xAD0, 0xAD0), (0xAE0, 0xAE3), (0xAE6, 0xAEF),
    (0xAF9, 0xAFF), (0xB01, 0xB03), (0xB05, 0xB0C), (0xB0F, 0xB10), (0xB13, 0xB28), (0xB2A, 0xB30),
    (0xB32, 0xB33), (0xB35, 0xB39), (0xB3C, 0xB44), (0xB47, 0xB48), (0xB4B, 0xB4D), (0xB55, 0xB57),
    (0xB5C, 0xB5D), (0xB5F, 0xB63), (0xB66, 0xB6F), (0xB71, 0xB77), (0xB82, 0xB83), (0xB85, 0xB8A),
    (0xB8E, 0xB90), (0xB92, 0xB95), (0xB99, 0xB9A), (0xB9C, 0xB9C), (0xB9E, 0xB9F), (0xBA3, 0xBA4),
    (0xBA8, 0xBAA), (0xBAE, 0xBB9), (0xBBE, 0xBC2), (0xBC6, 0xBC8), (0xBCA, 0xBCD), (0xBD0, 0xBD0),
    (0xBD7, 0xBD7), (0xBE6, 0xBF2), (0xC00, 0xC0C), (0xC0E, 0xC10), (0xC12, 0xC28), (0xC2A, 0xC39),
    (0xC3C, 0xC44), (0xC46, 0xC48), (0xC4A, 0xC4D), (0xC55, 0xC56), (0xC58, 0xC5A), (0xC5D, 0xC5D),
    (0xC60, 0xC63), (0xC66, 0xC6F), (0xC78, 0xC7E), (0xC80, 0xC83), (0xC85, 0xC8C), (0xC8E, 0xC90),
    (0xC92, 0xCA8), (0xCAA, 0xCB3), (0xCB5, 0xCB9), (0xCBC, 0xCC4), (0xCC6, 0xCC8), (0xCCA, 0xCCD),
    (0xCD5, 0xCD6), (0xCDD, 0xCDE), (0xCE0, 0xCE3), (0xCE6, 0xCEF), (0xCF1, 0xCF3), (0xD00, 0xD0C),
    (0xD0E, 0xD10), (0xD12, 0xD44), (0xD46, 0xD48), (0xD4A, 0xD4E), (0xD54, 0xD63), (0xD66, 0xD78),
    (0xD7A, 0xD7F), (0xD81, 0xD83), (0xD85, 0xD96), (0xD9A, 0xDB1), (0xDB3, 0xDBB), (0xDBD, 0xDBD),
    (0xDC0, 0xDC6), (0xDCA, 0xDCA), (0xDCF, 0xDD4), (0xDD6, 0xDD6), (0xDD8, 0xDDF), (0xDE6, 0xDEF),
    (0xDF2, 0xDF3), (0xE01, 0xE3A), (0xE40, 0xE4E), (0xE50, 0xE59), (0xE81, 0xE82), (0xE84, 0xE84),
    (0xE86, 0xE8A), (0xE8C, 0xEA3), (0xEA5, 0xEA5), (0xEA7, 0xEBD), (0xEC0, 0xEC4), (0xEC6, 0xEC6),
    (0xEC8, 0xECE), (0xED0, 0xED9), (0xEDC, 0xEDF), (0xF00, 0xF00), (0xF18, 0xF19), (0xF20, 0xF33),
    (0xF35, 0xF35), (0xF37, 0xF37), (0xF39, 0xF39), (0xF3E, 0xF47), (0xF49, 0xF6C), (0xF71, 0xF84),
    (0xF86, 0xF97), (0xF99, 0xFBC), (0xFC6, 0xFC6), (0x1000, 0x1049), (0x1050, 0x109D), (0x10A0, 0x10C5),
    (0x10C7, 0x10C7), (0x10CD, 0x10CD), (0x10D0, 0x10FA), (0x10FC, 0x1248), (0x124A, 0x124D), (0x1250, 0x1256),
    (0x1258, 0x1258), (0x125A, 0x125D), (0x1260, 0x1288), (0x128A, 0x128D), (0x1290, 0x12B0), (0x12B2, 0x12B5),
    (0x12B8, 0x12BE), (0x12C0, 0x12C0), (0x12C2, 0x12C5), (0x12C8, 0x12D6), (0x12D8, 0x1310), (0x1312, 0x1315),
    (0x1318, 0x135A), (0x135D, 0x135F), (0x1369, 0x137C), (0x1380, 0x138F), (0x13A0, 0x13F5), (0x13F8, 0x13FD),
    (0x1401, 0x166C), (0x166F, 0x167F), (0x1681, 0x169A), (0x16A0, 0x16EA), (0x16EE, 0x16F8), (0x1700, 0x1715),
    (0x171F, 0x1734), (0x1740, 0x1753), (0x1760, 0x176C), (0x176E, 0x1770), (0x1772, 0x1773), (0x1780, 0x17D3),
    (0x17D7, 0x17D7), (0x17DC, 0x17DD), (0x17E0, 0x17E9), (0x17F0, 0x17F9), (0x180B, 0x180D), (0x180F, 0x1819),
    (0x1820, 0x1878), (0x1880, 0x18AA), (0x18B0, 0x18F5), (0x1900, 0x191E), (0x1920, 0x192B), (0x1930, 0x193B),
    (0x1946, 0x196D), (0x1970, 0x1974), (0x1980, 0x19AB), (0x19B0, 0x19C9), (0x19D0, 0x19DA), (0x1A00, 0x1A1B),
    (0x1A20, 0x1A5E), (0x1A60, 0x1A7C), (0x1A7F, 0x1A89), (0x1A90, 0x1A99), (0x1AA7, 0x1AA7), (0x1AB0, 0x1ACE),
    (0x1B00, 0x1B4C), (0x1B50, 0x1B59), (0x1B6B, 0x1B73), (0x1B80, 0x1BF3), (0x1C00, 0x1C37), (0x1C40, 0x1C49),
    (0x1C4D, 0x1C7D), (0x1C80, 0x1C88), (0x1C90, 0x1CBA), (0x1CBD, 0x1CBF), (0x1CD0, 0x1CD2), (0x1CD4, 0x1CFA),
    (0x1D00, 0x1F15), (0x1F18, 0x1F1D), (0x1F20, 0x1F45), (0x1F48, 0x1F4D), (0x1F50, 0x1F57), (0x1F59, 0x1F59),
    (0x1F5B, 0x1F5B), (0x1F5D, 0x1F5D), (0x1F5F, 0x1F7D), (0x1F80, 0x1FB4), (0x1FB6, 0x1FBC), (0x1FBE, 0x1FBE),
    (0x1FC2, 0x1FC4), (0x1FC6, 0x1FCC), (0x1FD0, 0x1FD3), (0x1FD6, 0x1FDB), (0x1FE0, 0x1FEC), (0x1FF2, 0x1FF4),
    (0x1FF6, 0x1FFC), (0x2070, 0x2071), (0x2074, 0x2079), (0x207F, 0x2089), (0x2090, 0x209C), (0x20D0, 0x20F0),
    (0x2102, 0x2102), (0x2107, 0x2107), (0x210A, 0x2113), (0x2115, 0x2115), (0x2119, 0x211D), (0x2124, 0x2124),
    (0x2126, 0x2126), (0x2128, 0x2128), (0x212A, 0x212D), (0x212F, 0x2139), (0x213C, 0x213F), (0x2145, 0x2149),
    (0x214E, 0x214E), (0x2150, 0x2189), (0x2460, 0x249B), (0x24EA, 0x24FF), (0x2776, 0x2793), (0x2C00, 0x2CE4),
    (0x2CEB, 0x2CF3), (0x2CFD, 0x2CFD), (0x2D00, 0x2D25), (0x2D27, 0x2D27), (0x2D2D, 0x2D2D), (0x2D30, 0x2D67),
    (0x2D6F, 0x2D6F), (0x2D7F, 0x2D96), (0x2DA0, 0x2DA6), (0x2DA8, 0x2DAE), (0x2DB0, 0x2DB6), (0x2DB8, 0x2DBE),
    (0x2DC0, 0x2DC6), (0x2DC8, 0x2DCE), (0x2DD0, 0x2DD6), (0x2DD8, 0x2DDE), (0x2DE0, 0x2DFF), (0x2E2F, 0x2E2F),
    (0x3005, 0x3007), (0x3021, 0x302F), (0x3031, 0x3035), (0x3038, 0x303C), (0x3041, 0x3096), (0x3099, 0x309A),
    (0x309D, 0x309F), (0x30A1, 0x30FA), (0x30FC, 0x30FF), (0x3105, 0x312F), (0x3131, 0x318E), (0x3192, 0x3195),
    (0x31A0, 0x31BF), (0x31F0, 0x31FF), (0x3220, 0x3229), (0x3248, 0x324F), (0x3251, 0x325F), (0x3280, 0x3289),
    (0x32B1, 0x32BF), (0x3400, 0x4DBF), (0x4E00, 0xA48C), (0xA4D0, 0xA4FD), (0xA500, 0xA60C), (0xA610, 0xA62B),
    (0xA640, 0xA672), (0xA674, 0xA67D), (0xA67F, 0xA6F1), (0xA717, 0xA71F), (0xA722, 0xA788), (0xA78B, 0xA7CA),
    (0xA7D0, 0xA7D1), (0xA7D3, 0xA7D3), (0xA7D5, 0xA7D9), (0xA7F2, 0xA827), (0xA82C, 0xA82C), (0xA830, 0xA835),
    (0xA840, 0xA873), (0xA880, 0xA8C5), (0xA8D0, 0xA8D9), (0xA8E0, 0xA8F7), (0xA8FB, 0xA8FB), (0xA8FD, 0xA92D),
    (0xA930, 0xA953), (0xA960, 0xA97C), (0xA980, 0xA9C0), (0xA9CF, 0xA9D9), (0xA9E0, 0xA9FE), (0xAA00, 0xAA36),
    (0xAA40, 0xAA4D), (0xAA50, 0xAA59), (0xAA60, 0xAA76), (0xAA7A, 0xAAC2), (0xAADB, 0xAADD), (0xAAE0, 0xAAEF),
    (0xAAF2, 0xAAF6), (0xAB01, 0xAB06), (0xAB09, 0xAB0E), (0xAB11, 0xAB16), (0xAB20, 0xAB26), (0xAB28, 0xAB2E),
    (0xAB30, 0xAB5A), (0xAB5C, 0xAB69), (0xAB70, 0xABEA), (0xABEC, 0xABED), (0xABF0, 0xABF9), (0xAC00, 0xD7A3),
    (0xD7B0, 0xD7C6), (0xD7CB, 0xD7FB), (0xF900, 0xFA6D), (0xFA70, 0xFAD9), (0xFB00, 0xFB06), (0xFB13, 0xFB17),
    (0xFB1D, 0xFB28), (0xFB2A, 0xFB36), (0xFB38, 0xFB3C), (0xFB3E, 0xFB3E), (0xFB40, 0xFB41), (0xFB43, 0xFB44),
    (0xFB46, 0xFBB1), (0xFBD3, 0xFD3D), (0xFD50, 0xFD8F), (0xFD92, 0xFDC7), (0xFDF0, 0xFDFB), (0xFE00, 0xFE0F),
    (0xFE20, 0xFE2F), (0xFE70, 0xFE74), (0xFE76, 0xFEFC), (0xFF10, 0xFF19), (0xFF21, 0xFF3A), (0xFF41, 0xFF5A),
    (0xFF66, 0xFFBE), (0xFFC2, 0xFFC7), (0xFFCA, 0xFFCF), (0xFFD2, 0xFFD7), (0xFFDA, 0xFFDC), (0x10000, 0x1000B),
    (0x1000D, 0x10026), (0x10028, 0x1003A), (0x1003C, 0x1003D), (0x1003F, 0x1004D), (0x10050, 0x1005D), (0x10080, 0x100FA),
    (0x10107, 0x10133), (0x10140, 0x10178), (0x1018A, 0x1018B), (0x101FD, 0x101FD), (0x10280, 0x1029C), (0x102A0, 0x102D0),
    (0x102E0, 0x102FB), (0x10300, 0x10323), (0x1032D, 0x1034A), (0x10350, 0x1037A), (0x10380, 0x1039D), (0x103A0, 0x103C3),
    (0x103C8, 0x103CF), (0x103D1, 0x103D5), (0x10400, 0x1049D), (0x104A0, 0x104A9), (0x104B0, 0x104D3), (0x104D8, 0x104FB),
    (0x10500, 0x10527), (0x10530, 0x10563), (0x10570, 0x1057A), (0x1057C, 0x1058A), (0x1058C, 0x10592), (0x10594, 0x10595),
    (0x10597, 0x105A1), (0x105A3, 0x105B1), (0x105B3, 0x105B9), (0x105BB, 0x105BC), (0x10600, 0x10736), (0x10740, 0x10755),
    (0x10760, 0x10767), (0x10780, 0x10785), (0x10787, 0x107B0), (0x107B2, 0x107BA), (0x10800, 0x10805), (0x10808, 0x10808),
    (0x1080A, 0x10835), (0x10837, 0x10838), (0x1083C, 0x1083C), (0x1083F, 0x10855), (0x10858, 0x10876), (0x10879, 0x1089E),
    (0x108A7, 0x108AF), (0x108E0, 0x108F2), (0x108F4, 0x108F5), (0x108FB, 0x1091B), (0x10920, 0x10939), (0x10980, 0x109B7),
    (0x109BC, 0x109CF), (0x109D2, 0x10A03), (0x10A05, 0x10A06), (0x10A0C, 0x10A13), (0x10A15, 0x10A17), (0x10A19, 0x10A35),
    (0x10A38, 0x10A3A), (0x10A3F, 0x10A48), (0x10A60, 0x10A7E), (0x10A80, 0x10A9F), (0x10AC0, 0x10AC7), (0x10AC9, 0x10AE6),
    (0x10AEB, 0x10AEF), (0x10B00, 0x10B35), (0x10B40, 0x10B55), (0x10B58, 0x10B72), (0x10B78, 0x10B91), (0x10BA9, 0x10BAF),
    (0x10C00, 0x10C48), (0x10C80, 0x10CB2), (0x10CC0, 0x10CF2), (0x10CFA, 0x10D27), (0x10D30, 0x10D39), (0x10E60, 0x10E7E),
    (0x10E80, 0x10EA9), (0x10EAB, 0x10EAC), (0x10EB0, 0x10EB1), (0x10EFD, 0x10F27), (0x10F30, 0x10F54), (0x10F70, 0x10F85),
    (0x10FB0, 0x10FCB), (0x10FE0, 0x10FF6), (0x11000, 0x11046), (0x11052, 0x11075), (0x1107F, 0x110BA), (0x110C2, 0x110C2),
    (0x110D0, 0x110E8), (0x110F0, 0x110F9), (0x11100, 0x11134), (0x11136, 0x1113F), (0x11144, 0x11147), (0x11150, 0x11173),
    (0x11176, 0x11176), (0x11180, 0x111C4), (0x111C9, 0x111CC), (0x111CE, 0x111DA), (0x111DC, 0x111DC), (0x111E1, 0x111F4),
    (0x11200, 0x11211), (0x11213, 0x11237), (0x1123E, 0x11241), (0x11280, 0x11286), (0x11288, 0x11288), (0x1128A, 0x1128D),
    (0x1128F, 0x1129D), (0x1129F, 0x112A8), (0x112B0, 0x112EA), (0x112F0, 0x112F9), (0x11300, 0x11303), (0x11305, 0x1130C),
    (0x1130F, 0x11310), (0x11313, 0x11328), (0x1132A, 0x11330), (0x11332, 0x11333), (0x11335, 0x11339), (0x1133B, 0x11344),
    (0x11347, 0x11348), (0x1134B, 0x1134D), (0x11350, 0x11350), (0x11357, 0x11357), (0x1135D, 0x11363), (0x11366, 0x1136C),
    (0x11370, 0x11374), (0x11400, 0x1144A), (0x11450, 0x11459), (0x1145E, 0x11461), (0x11480, 0x114C5), (0x114C7, 0x114C7),
    (0x114D0, 0x114D9), (0x11580, 0x115B5), (0x115B8, 0x115C0), (0x115D8, 0x115DD), (0x11600, 0x11640), (0x11644, 0x11644),
    (0x11650, 0x11659), (0x11680, 0x116B8), (0x116C0, 0x116C9), (0x11700, 0x1171A), (0x1171D, 0x1172B), (0x11730, 0x1173B),
    (0x11740, 0x11746), (0x11800, 0x1183A), (0x118A0, 0x118F2), (0x118FF, 0x11906), (0x11909, 0x11909), (0x1190C, 0x11913),
    (0x11915, 0x11916), (0x11918, 0x11935), (0x11937, 0x11938), (0x1193B, 0x11943), (0x11950, 0x11959), (0x119A0, 0x119A7),
    (0x119AA, 0x119D7), (0x119DA, 0x119E1), (0x119E3, 0x119E4), (0x11A00, 0x11A3E), (0x11A47, 0x11A47), (0x11A50, 0x11A99),
    (0x11A9D, 0x11A9D), (0x11AB0, 0x11AF8), (0x11C00, 0x11C08), (0x11C0A, 0x11C36), (0x11C38, 0x11C40), (0x11C50, 0x11C6C),
    (0x11C72, 0x11C8F), (0x11C92, 0x11CA7), (0x11CA9, 0x11CB6), (0x11D00, 0x11D06), (0x11D08, 0x11D09), (0x11D0B, 0x11D36),
    (0x11D3A, 0x11D3A), (0x11D3C, 0x11D3D), (0x11D3F, 0x11D47), (0x11D50, 0x11D59), (0x11D60, 0x11D65), (0x11D67, 0x11D68),
    (0x11D6A, 0x11D8E), (0x11D90, 0x11D91), (0x11D93, 0x11D98), (0x11DA0, 0x11DA9), (0x11EE0, 0x11EF6), (0x11F00, 0x11F10),
    (0x11F12, 0x11F3A), (0x11F3E, 0x11F42), (0x11F50, 0x11F59), (0x11FB0, 0x11FB0), (0x11FC0, 0x11FD4), (0x12000, 0x12399),
    (0x12400, 0x1246E), (0x12480, 0x12543), (0x12F90, 0x12FF0), (0x13000, 0x1342F), (0x13440, 0x13455), (0x14400, 0x14646),
    (0x16800, 0x16A38), (0x16A40, 0x16A5E), (0x16A60, 0x16A69), (0x16A70, 0x16ABE), (0x16AC0, 0x16AC9), (0x16AD0, 0x16AED),
    (0x16AF0, 0x16AF4), (0x16B00, 0x16B36), (0x16B40, 0x16B43), (0x16B50, 0x16B59), (0x16B5B, 0x16B61), (0x16B63, 0x16B77),
    (0x16B7D, 0x16B8F), (0x16E40, 0x16E96), (0x16F00, 0x16F4A), (0x16F4F, 0x16F87), (0x16F8F, 0x16F9F), (0x16FE0, 0x16FE1),
    (0x16FE3, 0x16FE4), (0x16FF0, 0x16FF1), (0x17000, 0x187F7), (0x18800, 0x18CD5), (0x18D00, 0x18D08), (0x1AFF0, 0x1AFF3),
    (0x1AFF5, 0x1AFFB), (0x1AFFD, 0x1AFFE), (0x1B000, 0x1B122), (0x1B132, 0x1B132), (0x1B150, 0x1B152), (0x1B155, 0x1B155),
    (0x1B164, 0x1B167), (0x1B170, 0x1B2FB), (0x1BC00, 0x1BC6A), (0x1BC70, 0x1BC7C), (0x1BC80, 0x1BC88), (0x1BC90, 0x1BC99),
    (0x1BC9D, 0x1BC9E), (0x1CF00, 0x1CF2D), (0x1CF30, 0x1CF46), (0x1D165, 0x1D169), (0x1D16D, 0x1D172), (0x1D17B, 0x1D182),
    (0x1D185, 0x1D18B), (0x1D1AA, 0x1D1AD), (0x1D242, 0x1D244), (0x1D2C0, 0x1D2D3), (0x1D2E0, 0x1D2F3), (0x1D360, 0x1D378),
    (0x1D400, 0x1D454), (0x1D456, 0x1D49C), (0x1D49E, 0x1D49F), (0x1D4A2, 0x1D4A2), (0x1D4A5, 0x1D4A6), (0x1D4A9, 0x1D4AC),
    (0x1D4AE, 0x1D4B9), (0x1D4BB, 0x1D4BB), (0x1D4BD, 0x1D4C3), (0x1D4C5, 0x1D505), (0x1D507, 0x1D50A), (0x1D50D, 0x1D514),
    (0x1D516, 0x1D51C), (0x1D51E, 0x1D539), (0x1D53B, 0x1D53E), (0x1D540, 0x1D544), (0x1D546, 0x1D546), (0x1D54A, 0x1D550),
    (0x1D552, 0x1D6A5), (0x1D6A8, 0x1D6C0), (0x1D6C2, 0x1D6DA), (0x1D6DC, 0x1D6FA), (0x1D6FC, 0x1D714), (0x1D716, 0x1D734),
    (0x1D736, 0x1D74E), (0x1D750, 0x1D76E), (0x1D770, 0x1D788), (0x1D78A, 0x1D7A8), (0x1D7AA, 0x1D7C2), (0x1D7C4, 0x1D7CB),
    (0x1D7CE, 0x1D7FF), (0x1DA00, 0x1DA36), (0x1DA3B, 0x1DA6C), (0x1DA75, 0x1DA75), (0x1DA84, 0x1DA84), (0x1DA9B, 0x1DA9F),
    (0x1DAA1, 0x1DAAF), (0x1DF00, 0x1DF1E), (0x1DF25, 0x1DF2A), (0x1E000, 0x1E006), (0x1E008, 0x1E018), (0x1E01B, 0x1E021),
    (0x1E023, 0x1E024), (0x1E026, 0x1E02A), (0x1E030, 0x1E06D), (0x1E08F, 0x1E08F), (0x1E100, 0x1E12C), (0x1E130, 0x1E13D),
    (0x1E140, 0x1E149), (0x1E14E, 0x1E14E), (0x1E290, 0x1E2AE), (0x1E2C0, 0x1E2F9), (0x1E4D0, 0x1E4F9), (0x1E7E0, 0x1E7E6),
    (0x1E7E8, 0x1E7EB), (0x1E7ED, 0x1E7EE), (0x1E7F0, 0x1E7FE), (0x1E800, 0x1E8C4), (0x1E8C7, 0x1E8D6), (0x1E900, 0x1E94B),
    (0x1E950, 0x1E959), (0x1EC71, 0x1ECAB), (0x1ECAD, 0x1ECAF), (0x1ECB1, 0x1ECB4), (0x1ED01, 0x1ED2D), (0x1ED2F, 0x1ED3D),
    (0x1EE00, 0x1EE03), (0x1EE05, 0x1EE1F), (0x1EE21, 0x1EE22), (0x1EE24, 0x1EE24), (0x1EE27, 0x1EE27), (0x1EE29, 0x1EE32),
    (0x1EE34, 0x1EE37), (0x1EE39, 0x1EE39), (0x1EE3B, 0x1EE3B), (0x1EE42, 0x1EE42), (0x1EE47, 0x1EE47), (0x1EE49, 0x1EE49),
    (0x1EE4B, 0x1EE4B), (0x1EE4D, 0x1EE4F), (0x1EE51, 0x1EE52), (0x1EE54, 0x1EE54), (0x1EE57, 0x1EE57), (0x1EE59, 0x1EE59),
    (0x1EE5B, 0x1EE5B), (0x1EE5D, 0x1EE5D), (0x1EE5F, 0x1EE5F), (0x1EE61, 0x1EE62), (0x1EE64, 0x1EE64), (0x1EE67, 0x1EE6A),
    (0x1EE6C, 0x1EE72), (0x1EE74, 0x1EE77), (0x1EE79, 0x1EE7C), (0x1EE7E, 0x1EE7E), (0x1EE80, 0x1EE89), (0x1EE8B, 0x1EE9B),
    (0x1EEA1, 0x1EEA3), (0x1EEA5, 0x1EEA9), (0x1EEAB, 0x1EEBB), (0x1F100, 0x1F10C), (0x1FBF0, 0x1FBF9), (0x20000, 0x2A6DF),
    (0x2A700, 0x2B739), (0x2B740, 0x2B81D), (0x2B820, 0x2CEA1), (0x2CEB0, 0x2EBE0), (0x2F800, 0x2FA1D), (0x30000, 0x3134A),
    (0x31350, 0x323AF), (0xE0100, 0xE01EF),
];

fn is_lnm(c: char) -> bool {
    let cp = c as u32;
    LNM_RANGES
        .binary_search_by(|&(lo, hi)| {
            if cp < lo {
                std::cmp::Ordering::Greater
            } else if cp > hi {
                std::cmp::Ordering::Less
            } else {
                std::cmp::Ordering::Equal
            }
        })
        .is_ok()
}
