//! Workload identification: resolving `argv[0]` to the launched executable,
//! locating the payload argument inside an interpreter's argv, and
//! classifying interpreter families.
//!
//! Layer-0 module shared by Warden (spawn-time path checks), Legislator
//! (source payload discovery), runtime launch, and Verifier hash binding.
//! Hash computation and hash-policy verification stay in
//! `verifier::hash`.

use std::io;
use std::path::{Path, PathBuf};

/// Interpreter family whose ELF must not be treated as MCP Capability evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InterpreterKind {
    Python,
    Node,
    Npx,
}

impl InterpreterKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Python => "python",
            Self::Node => "node",
            Self::Npx => "npx",
        }
    }
}

impl std::fmt::Display for InterpreterKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Classify an interpreter by its `argv[0]` spelling (`python3`,
/// `C:\tools\node.exe`, `py`, `npx`, …). Versioned and `.exe`-suffixed
/// names resolve to their family.
pub fn interpreter_from_command(argv0: &str) -> Option<InterpreterKind> {
    let name = Path::new(argv0)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or(argv0);
    let name = name.rsplit(['/', '\\']).next().unwrap_or(name);
    let lower = name.to_ascii_lowercase();
    let lower = lower.strip_suffix(".exe").unwrap_or(lower.as_str());
    if lower == "python" || lower == "python3" || lower.starts_with("python3.") {
        return Some(InterpreterKind::Python);
    }
    if lower == "pythonw" || lower == "py" || lower == "pyw" {
        return Some(InterpreterKind::Python);
    }
    if lower == "node" || lower == "nodejs" {
        return Some(InterpreterKind::Node);
    }
    if lower == "npx" {
        return Some(InterpreterKind::Npx);
    }
    None
}

/// Resolve `argv0` to an absolute path via cwd or PATH.
pub fn resolve_command_path(argv0: &str) -> io::Result<PathBuf> {
    let p = Path::new(argv0);
    if p.is_absolute() || argv0.contains('/') || argv0.contains('\\') {
        return std::fs::canonicalize(p).or_else(|_| {
            let abs = if p.is_absolute() {
                p.to_path_buf()
            } else {
                std::env::current_dir()?.join(p)
            };
            Ok(abs)
        });
    }
    if let Some(found) = search_path(argv0) {
        return std::fs::canonicalize(&found).or(Ok(found));
    }
    Err(io::Error::new(
        io::ErrorKind::NotFound,
        format!("command '{argv0}' not found on PATH"),
    ))
}

/// First `name` hit on PATH, without canonicalizing — the symlink
/// spelling is what a venv's getpath discovery needs.
pub(crate) fn search_path(name: &str) -> Option<PathBuf> {
    let path_var = std::env::var_os("PATH")?;
    let windows_exts: Vec<String> = if cfg!(windows) {
        std::env::var_os("PATHEXT")
            .and_then(|v| v.into_string().ok())
            .unwrap_or_else(|| ".EXE;.CMD;.BAT;.COM".to_string())
            .split(';')
            .filter(|s| !s.is_empty())
            .map(|s| s.trim_start_matches('.').to_ascii_lowercase())
            .collect()
    } else {
        Vec::new()
    };
    for dir in std::env::split_paths(&path_var) {
        if cfg!(windows) {
            for ext in &windows_exts {
                let with_ext = dir.join(format!("{name}.{ext}"));
                if with_ext.is_file() {
                    return Some(with_ext);
                }
            }
            let candidate = dir.join(name);
            if candidate.is_file() {
                return Some(candidate);
            }
        } else {
            let candidate = dir.join(name);
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }
    None
}

pub(crate) fn same_file(a: &Path, b: &Path) -> bool {
    match (std::fs::canonicalize(a), std::fs::canonicalize(b)) {
        (Ok(ca), Ok(cb)) => ca == cb,
        _ => crate::pathutil::paths_equal(&a.to_string_lossy(), &b.to_string_lossy()),
    }
}

pub(crate) fn argv_contains_inline_eval(argv: &[String]) -> bool {
    let end = first_payload_arg_index(argv).unwrap_or(argv.len());
    argv[..end]
        .iter()
        .any(|a| matches!(a.as_str(), "-c" | "-e" | "--eval" | "--command"))
}

/// Index of the first non-flag argument after the interpreter (script/module).
pub(crate) fn first_payload_arg_index(argv: &[String]) -> Option<usize> {
    let argv0 = argv.first().map(String::as_str).unwrap_or("");
    let mut i = 1;
    while i < argv.len() {
        let a = argv[i].as_str();
        if a == "--" {
            return (i + 1 < argv.len()).then_some(i + 1);
        }
        if a.starts_with('-') {
            // Options that consume the next token as their operand: the
            // token after e.g. `--require` is the option's value, not the
            // payload script.
            i += if flag_consumes_operand(a, argv0) {
                2
            } else {
                1
            };
            continue;
        }
        return Some(i);
    }
    None
}

/// Options whose operand is the following argv token — that token is the
/// option's value, not the workload payload. `node --require stub.cjs
/// index.js` pins `index.js`, not `stub.cjs`; `python -W ignore server.py`
/// pins `server.py`, not `ignore`. `--flag=value` and attached spellings
/// (`-Wignore`) carry the operand inline, so they match nothing here and
/// consume only themselves. `-m` (for CPython) and the inline-eval flags are
/// deliberately absent from the shared table: after their operand the
/// interpreter's option parsing is over and the remaining tokens are the
/// payload's own arguments.
fn flag_consumes_operand(arg: &str, argv0: &str) -> bool {
    if arg.contains('=') {
        return false;
    }
    if matches!(
        arg,
        // CPython
        "-W" | "-X" | "--check-hash-based-pycs"
        // Node.js
        | "-r" | "--require" | "--loader" | "--experimental-loader"
        | "--import" | "--input-type" | "-C" | "--conditions"
        | "--icu-data-dir" | "--openssl-config" | "--redirect-warnings"
        | "--title" | "--diagnostic-dir" | "--report-directory"
        | "--report-filename" | "--heap-prof-dir" | "--heap-prof-name"
        | "--cpu-prof-dir" | "--cpu-prof-name" | "--cpu-prof-interval"
        | "--policy" | "--snapshot-blob" | "--inspect-publish-uid"
        | "--watch-path" | "--test-name-pattern"
    ) {
        return true;
    }
    interpreter_operand_extras(argv0).contains(&arg)
}

/// Operand-taking flags that exist only on some interpreters — `-I` is an
/// include-path operand for perl and ruby but a plain flag (isolated mode)
/// on CPython, so these cannot live in the shared table. Perl's `-M`/`-m`
/// take a module operand too (unlike `python -m`, perl keeps scanning its
/// own options after the operand, so `-e` later in argv is still eval).
fn interpreter_operand_extras(argv0: &str) -> &'static [&'static str] {
    let name = Path::new(argv0)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or(argv0);
    let lower = name.to_ascii_lowercase();
    let stem = lower.strip_suffix(".exe").unwrap_or(lower.as_str());
    if stem == "perl" || stem == "perl5" || stem.starts_with("perl5.") {
        &["-I", "-M", "-m"]
    } else if stem == "ruby"
        || stem
            .strip_prefix("ruby")
            .is_some_and(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit() || b == b'.'))
    {
        &["-I", "-r"]
    } else {
        &[]
    }
}

/// First non-flag argument after the interpreter (the script or module path).
pub(crate) fn first_payload_arg(argv: &[String]) -> Option<&str> {
    first_payload_arg_index(argv).map(|i| argv[i].as_str())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_inline_eval_ignores_payload_args() {
        let argv = vec![
            "python".into(),
            "server.py".into(),
            "--command".into(),
            "payload".into(),
        ];
        assert!(!argv_contains_inline_eval(&argv));
        let argv = vec!["python".into(), "-c".into(), "print(1)".into()];
        assert!(argv_contains_inline_eval(&argv));
    }

    #[test]
    fn test_first_payload_arg_skips_option_operands() {
        // `node --require stub.cjs index.js`: the preload is --require's
        // operand — the payload is the script after it.
        let argv = vec![
            "node".into(),
            "--require".into(),
            "stub.cjs".into(),
            "index.js".into(),
        ];
        assert_eq!(first_payload_arg(&argv), Some("index.js"));
        let argv = vec![
            "node".into(),
            "-r".into(),
            "stub.cjs".into(),
            "--watch".into(),
            "index.js".into(),
        ];
        assert_eq!(first_payload_arg(&argv), Some("index.js"));
        // `--flag=value` carries its operand inline.
        let argv = vec![
            "node".into(),
            "--require=stub.cjs".into(),
            "index.js".into(),
        ];
        assert_eq!(first_payload_arg(&argv), Some("index.js"));
        // CPython `-W` / `-X` take an operand; attached `-Wignore` does not
        // consume the next token.
        let argv = vec![
            "python".into(),
            "-W".into(),
            "ignore".into(),
            "server.py".into(),
        ];
        assert_eq!(first_payload_arg(&argv), Some("server.py"));
        let argv = vec!["python".into(), "-Wignore".into(), "server.py".into()];
        assert_eq!(first_payload_arg(&argv), Some("server.py"));
        // `-m` is not in the table: after its operand the remaining tokens
        // are the module's own arguments, so `-c` there is not inline eval.
        let argv = vec![
            "python".into(),
            "-m".into(),
            "mod".into(),
            "-c".into(),
            "x".into(),
        ];
        assert_eq!(first_payload_arg(&argv), Some("mod"));
        assert!(!argv_contains_inline_eval(&argv));
        // An operand-skipping flag still delimits the eval scan.
        let argv = vec![
            "python".into(),
            "-W".into(),
            "ignore".into(),
            "-c".into(),
            "print(1)".into(),
        ];
        assert!(argv_contains_inline_eval(&argv));
    }

    #[test]
    fn test_interpreter_specific_operand_flags() {
        // `perl -I lib -e 'code'`: -I consumes `lib`, so the scan must reach
        // `-e` — otherwise inline eval runs unpinned at `run` time too.
        let argv = vec![
            "perl".into(),
            "-I".into(),
            "lib".into(),
            "-e".into(),
            "print 1".into(),
        ];
        assert!(argv_contains_inline_eval(&argv));
        let argv = vec!["perl".into(), "-I".into(), "lib".into(), "script.pl".into()];
        assert_eq!(first_payload_arg(&argv), Some("script.pl"));
        // perl `-M`/`-m` take a module operand but option scanning continues.
        let argv = vec![
            "perl".into(),
            "-M".into(),
            "Foo".into(),
            "-e".into(),
            "print 1".into(),
        ];
        assert!(argv_contains_inline_eval(&argv));
        let argv = vec![
            "ruby".into(),
            "-I".into(),
            "lib".into(),
            "-e".into(),
            "puts 1".into(),
        ];
        assert!(argv_contains_inline_eval(&argv));
        // Versioned Ruby names (Debian `ruby3.3`, `ruby2.7`) get the same
        // operand handling.
        let argv = vec![
            "ruby3.3".into(),
            "-I".into(),
            "lib".into(),
            "-e".into(),
            "puts 1".into(),
        ];
        assert!(argv_contains_inline_eval(&argv));
        // A non-version suffix (`rubyfoo`) must not match.
        let argv = vec!["rubyfoo".into(), "-I".into(), "lib".into()];
        assert_eq!(first_payload_arg(&argv), Some("lib"));
        // CPython's `-I` is a flag (isolated mode), not operand-taking.
        let argv = vec!["python".into(), "-I".into(), "server.py".into()];
        assert_eq!(first_payload_arg(&argv), Some("server.py"));
        // perl `-Ilib` (attached) does not consume the next token.
        let argv = vec!["perl".into(), "-Ilib".into(), "script.pl".into()];
        assert_eq!(first_payload_arg(&argv), Some("script.pl"));
    }

    #[test]
    fn test_interpreter_from_command() {
        assert_eq!(
            interpreter_from_command("python3"),
            Some(InterpreterKind::Python)
        );
        assert_eq!(
            interpreter_from_command("python3.12"),
            Some(InterpreterKind::Python)
        );
        assert_eq!(
            interpreter_from_command("C:\\tools\\python.exe"),
            Some(InterpreterKind::Python)
        );
        assert_eq!(
            interpreter_from_command("py"),
            Some(InterpreterKind::Python)
        );
        assert_eq!(
            interpreter_from_command("/usr/bin/node"),
            Some(InterpreterKind::Node)
        );
        assert_eq!(interpreter_from_command("npx"), Some(InterpreterKind::Npx));
        assert_eq!(interpreter_from_command("server"), None);
    }
}
