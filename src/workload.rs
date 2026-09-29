//! Workload identification: resolving `argv[0]` to the launched executable,
//! locating the payload argument inside an interpreter's argv, classifying
//! interpreter families — including delegating launchers whose own pin
//! cannot bind the workload they select, module/exec spellings that name
//! no file, and a spawned file's `#!` interpreter selection — and
//! container image-reference repository matching for image pins.
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
    if lower == "python"
        || lower == "python2"
        || lower == "python3"
        || lower.starts_with("python2.")
        || lower.starts_with("python3.")
        || lower == "pypy"
        || lower == "pypy2"
        || lower == "pypy3"
        || lower.starts_with("pypy2.")
        || lower.starts_with("pypy3.")
    {
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
///
/// A path-spelled `argv0` (absolute or containing a separator) that does
/// not exist is a resolution failure, not an unresolved-but-valid path:
/// reporting it anyway would let `plan` certify a launch that `run` can
/// only fail at spawn.
pub fn resolve_command_path(argv0: &str) -> io::Result<PathBuf> {
    let p = Path::new(argv0);
    if p.is_absolute() || argv0.contains('/') || argv0.contains('\\') {
        return match std::fs::canonicalize(p) {
            Ok(c) => Ok(c),
            Err(e) => {
                let abs = if p.is_absolute() {
                    p.to_path_buf()
                } else {
                    std::env::current_dir()?.join(p)
                };
                match abs.try_exists() {
                    Ok(true) => Ok(abs),
                    Ok(false) => Err(io::Error::new(
                        io::ErrorKind::NotFound,
                        format!("command '{argv0}' does not exist"),
                    )),
                    // The canonicalize error (symlink loop, permission,
                    // ...) is usually the more precise cause.
                    Err(_) => Err(e),
                }
            }
        };
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

#[cfg(test)]
pub(crate) fn argv_contains_inline_eval(argv: &[String]) -> bool {
    argv_contains_inline_eval_with_exe(argv, None)
}

/// `argv_contains_inline_eval` over `argv[0]` plus the resolved
/// executable's file name — a flag evaluates if EITHER spelling's
/// grammar reads it as eval.
pub(crate) fn argv_contains_inline_eval_with_exe(
    argv: &[String],
    resolved_exe: Option<&Path>,
) -> bool {
    let names = command_names(argv, resolved_exe);
    let end = scan_index(argv, &names).unwrap_or(argv.len());
    if argv[..end].iter().any(|a| names.is_inline_eval(a)) {
        return true;
    }
    // Windows PowerShell (`powershell.exe`, unlike `pwsh`) binds a
    // positional argument that is not a script path as an implicit
    // `-Command`: `powershell Get-Process` evaluates `Get-Process`.
    // `-File` makes its operand a file regardless of extension, and a
    // `.ps1` payload is always a script.
    if !names.any_is(|s| command_stem(s) == "powershell") {
        return false;
    }
    let Some(idx) = scan_index(argv, &names) else {
        return false;
    };
    !argv[..idx]
        .iter()
        .any(|a| powershell_flag_is_named(a, "file"))
        && !argv[idx].to_ascii_lowercase().ends_with(".ps1")
}

/// `arg` spells the named PowerShell parameter by unambiguous prefix —
/// `-Fi`/`-File` bind `-File`. `-` alone, `--`-spellings, and `:`-valued
/// tokens match nothing.
fn powershell_flag_is_named(arg: &str, name: &str) -> bool {
    let Some(body) = arg.strip_prefix('-') else {
        return false;
    };
    let body = body.split(':').next().unwrap_or_default();
    !body.is_empty()
        && !body.starts_with('-')
        && name.starts_with(body.to_ascii_lowercase().as_str())
}

/// Inline-evaluation flag for this argv0's interpreter family. The bare
/// `-e`/`--eval`/`--command` and `--eval=`/`--command=` spellings
/// apply to Python and Node only — on other families the same letters
/// mean other things (`perl -c` checks syntax, `sh -e` sets errexit) and
/// on a native binary they are plain arguments (`-c config.yaml`). `-c`
/// is eval on CPython only — Node's `-c`/`--check` is a syntax check that
/// never executes the script, so the script stays a normal payload.
/// Attached and clustered spellings are family-scoped because
/// the same token means different things elsewhere (`perl -p script.pl` and
/// `python -E script.py` run file payloads and must not classify as eval):
/// CPython clusters short options (`-c'x'`, `-Ec'x'`), Node adds
/// `-p`/`--print`/`--print=` and the combined `-pe`, perl clusters
/// `-e`/`-E` (`-e'x'`, `-pe'x'`, `-nE`), ruby clusters `-e` (`-e'x'`,
/// `-we'x'`), and POSIX shells cluster `c` (`-ec`, `-lc`, `-xc`,
/// `-c'x'`). PowerShell (`powershell`, `pwsh`) reads its command through
/// `-Command`/`-c` and base64 through `-EncodedCommand`/`-e`/`-ec`;
/// `cmd` runs its command string through `/c` or `/k`. Interpreters
/// outside this set — renamed binaries, other runtimes — are outside
/// detection coverage.
pub(crate) fn is_inline_eval_flag(arg: &str, argv0: &str) -> bool {
    let kind = interpreter_from_command(argv0);
    if matches!(
        kind,
        Some(InterpreterKind::Python) | Some(InterpreterKind::Node)
    ) && (matches!(arg, "-e" | "--eval" | "--command")
        || arg.starts_with("--eval=")
        || arg.starts_with("--command="))
    {
        return true;
    }
    match kind {
        // CPython's `-c` is eval — the cluster parser catches the bare
        // spelling too (`python -c x` hits `c` in the cluster body).
        Some(InterpreterKind::Python) => python_cluster_is_eval(arg),
        Some(InterpreterKind::Node) => {
            matches!(arg, "-p" | "-pe" | "--print") || arg.starts_with("--print=")
        }
        _ if is_perl_command(argv0) => perl_cluster_is_eval(arg),
        _ if is_ruby_command(argv0) => ruby_cluster_is_eval(arg),
        _ if is_shell_command(argv0) => shell_cluster_is_eval(arg),
        _ if is_powershell_command(argv0) => powershell_flag_is_eval(arg),
        _ if is_cmd_command(argv0) => cmd_switch_is_eval(arg),
        _ => false,
    }
}

/// cmd reads its command string through `/c` (run and exit), `/k` (run
/// and stay), or `/r`. The command text may be concatenated directly
/// onto the switch (`/cdir`), and switch letters are case-insensitive —
/// matching is by the two-character prefix.
fn cmd_switch_is_eval(arg: &str) -> bool {
    let b = arg.as_bytes();
    b.len() >= 2 && b[0] == b'/' && matches!(b[1].to_ascii_lowercase(), b'c' | b'k' | b'r')
}

/// PowerShell (`powershell`, `pwsh`) reads its command through
/// `-Command`/`-CommandWithArgs` and base64 through `-EncodedCommand`.
/// Parameter binding accepts any unambiguous prefix — `-Comm`, `-Enc`,
/// `-Command:x` — case-insensitively, so matching is by prefix of the
/// canonical name, plus the documented aliases that are not prefixes
/// (`-ec` for `-EncodedCommand`, `-cwa` for `-CommandWithArgs`).
const POWERSHELL_EVAL_PARAMS: &[&str] = &["command", "commandwithargs", "encodedcommand"];
const POWERSHELL_EVAL_ALIASES: &[&str] = &["cwa", "ec"];

fn powershell_flag_is_eval(arg: &str) -> bool {
    let Some(body) = arg.strip_prefix('-') else {
        return false;
    };
    let name = body.split(':').next().unwrap_or_default();
    if name.is_empty() || name.starts_with('-') {
        return false;
    }
    let lower = name.to_ascii_lowercase();
    POWERSHELL_EVAL_ALIASES.contains(&lower.as_str())
        || POWERSHELL_EVAL_PARAMS
            .iter()
            .any(|name| name.starts_with(lower.as_str()))
}

pub(crate) fn is_powershell_command(argv0: &str) -> bool {
    matches!(command_stem(argv0).as_str(), "powershell" | "pwsh")
}

pub(crate) fn is_cmd_command(argv0: &str) -> bool {
    command_stem(argv0) == "cmd"
}

/// The spellings that can identify a launch's interpreter grammar:
/// `argv[0]` as the caller spelled it plus the file name of the
/// resolved executable — the image the kernel will actually exec. They
/// agree on ordinary launches; a renamed alias (`worker` → `python3.12`)
/// leaves `argv[0]` uninformative while the resolved name still names
/// the family, and spellings naming different families each apply their
/// own parser so the stricter reading wins.
#[derive(Clone, Copy)]
pub(crate) struct CommandNames<'a> {
    /// `argv[0]` as the caller spelled it.
    spelled: &'a str,
    /// `file_name` of the resolved executable, when the launch carried
    /// one.
    resolved: Option<&'a str>,
}

impl<'a> CommandNames<'a> {
    /// Grammar spellings for `argv0` plus an optional resolved
    /// executable — only the resolved path's `file_name` participates
    /// (the same identity [`interpreter_from_command`] reads).
    pub(crate) fn new(argv0: &'a str, resolved_exe: Option<&'a Path>) -> Self {
        Self {
            spelled: argv0,
            resolved: resolved_exe
                .and_then(|p| p.file_name())
                .and_then(|f| f.to_str()),
        }
    }

    /// `argv[0]` and, when it differs, the resolved image name.
    fn iter(&self) -> impl Iterator<Item = &'a str> {
        [
            Some(self.spelled),
            self.resolved.filter(|r| *r != self.spelled),
        ]
        .into_iter()
        .flatten()
    }

    /// The interpreter family this launch runs — the resolved image's
    /// family when it names one (it is the image exec'd), else
    /// `argv[0]`'s.
    pub(crate) fn interpreter(&self) -> Option<InterpreterKind> {
        self.resolved
            .and_then(interpreter_from_command)
            .or_else(|| interpreter_from_command(self.spelled))
    }

    /// One representative spelling per modeled option-grammar family —
    /// `python` plus `python3.12` collapse to one grammar, while
    /// `python` plus `node` yields two scans and the stricter answer
    /// wins.
    fn family_spellings(&self) -> Vec<&'a str> {
        let mut tags = Vec::new();
        let mut out = Vec::new();
        for s in self.iter() {
            let Some(tag) = grammar_family(s) else {
                continue;
            };
            if !tags.contains(&tag) {
                tags.push(tag);
                out.push(s);
            }
        }
        out
    }

    /// `arg` spells inline evaluation under ANY of this launch's
    /// grammars — `-c` evaluates if either reading treats it as eval.
    pub(crate) fn is_inline_eval(&self, arg: &str) -> bool {
        self.iter().any(|s| is_inline_eval_flag(arg, s))
    }

    /// The delegating-launcher kind — the resolved image's first (it is
    /// the image exec'd), then `argv[0]`'s.
    pub(crate) fn delegating_launcher(&self) -> Option<(DelegatingLauncher, String)> {
        self.resolved
            .and_then(delegating_launcher)
            .or_else(|| delegating_launcher(self.spelled))
    }

    /// Any spelling satisfies `pred` — unions the per-family predicates
    /// (`is_shell_command`, `is_perl_command`, …) over both spellings.
    pub(crate) fn any_is(&self, pred: impl Fn(&str) -> bool) -> bool {
        self.iter().any(pred)
    }
}

/// Grammar spellings for `argv[0]` plus an optional resolved executable.
fn command_names<'a>(argv: &'a [String], resolved_exe: Option<&'a Path>) -> CommandNames<'a> {
    CommandNames::new(argv.first().map(String::as_str).unwrap_or(""), resolved_exe)
}

/// Option-grammar families [`payload_scan`] models — every family
/// predicate in this module keys on one of these.
#[derive(Clone, Copy, PartialEq, Eq)]
enum GrammarFamily {
    Python,
    Node,
    Npx,
    Perl,
    Ruby,
    Shell,
    PowerShell,
    Cmd,
}

/// The grammar family a spelling belongs to, when modeled.
fn grammar_family(spelling: &str) -> Option<GrammarFamily> {
    match interpreter_from_command(spelling) {
        Some(InterpreterKind::Python) => return Some(GrammarFamily::Python),
        Some(InterpreterKind::Node) => return Some(GrammarFamily::Node),
        Some(InterpreterKind::Npx) => return Some(GrammarFamily::Npx),
        None => {}
    }
    if is_perl_command(spelling) {
        Some(GrammarFamily::Perl)
    } else if is_ruby_command(spelling) {
        Some(GrammarFamily::Ruby)
    } else if is_shell_command(spelling) {
        Some(GrammarFamily::Shell)
    } else if is_powershell_command(spelling) {
        Some(GrammarFamily::PowerShell)
    } else if is_cmd_command(spelling) {
        Some(GrammarFamily::Cmd)
    } else {
        None
    }
}

/// Node preload flags before the payload — `-r` / `--require`, `--import`,
/// `--loader` / `--experimental-loader`, and their `--flag=` spellings —
/// load modules that no entrypoint/binary hash entry covers.
#[cfg(test)]
pub(crate) fn node_preload_flags_present(argv: &[String]) -> bool {
    node_preload_flags_present_with_exe(argv, None)
}

/// `node_preload_flags_present` over `argv[0]` plus the resolved
/// executable's file name — the flag set applies when either spelling
/// names Node.
pub(crate) fn node_preload_flags_present_with_exe(
    argv: &[String],
    resolved_exe: Option<&Path>,
) -> bool {
    let names = command_names(argv, resolved_exe);
    if !names.any_is(|s| matches!(interpreter_from_command(s), Some(InterpreterKind::Node))) {
        return false;
    }
    let end = scan_index(argv, &names).unwrap_or(argv.len());
    argv[..end].iter().any(|a| {
        matches!(
            a.as_str(),
            "-r" | "--require" | "--import" | "--loader" | "--experimental-loader"
        ) || a.starts_with("--require=")
            || a.starts_with("--import=")
            || a.starts_with("--loader=")
            || a.starts_with("--experimental-loader=")
    })
}

/// CPython clusters single-letter options (`-Ec'x'`, `-Bdc 'x'`, `-c'x'`):
/// an eval `c` reached before an operand-taking letter is inline eval.
/// `-m` names a module — a payload boundary, not eval — and `-W` / `-X` /
/// `-Q` consume their operand, so the token's tail is never a flag.
fn python_cluster_is_eval(arg: &str) -> bool {
    let Some(body) = arg.strip_prefix('-') else {
        return false;
    };
    if body.is_empty() || body.starts_with('-') {
        return false;
    }
    for ch in body.chars() {
        match ch {
            'c' => return true,
            'm' | 'W' | 'X' | 'Q' => return false,
            _ if ch.is_ascii_alphabetic() => {}
            _ => return false,
        }
    }
    false
}

/// perl clusters single-letter options and attaches `-e`/`-E` operands
/// (`-e'x'`, `-pe'x'`, `-nE'x'`): an eval letter reached before an
/// operand-consuming letter is inline eval. `-F`/`-I`/`-M`/`-m` always take
/// an operand, `-i`/`-x`/`-C`/`-D` consume an attached operand, and `:`
/// (as in `-d:Mod`) or `=` ends the flag run — the tail is then the
/// option's value, not a flag (`-MTime::HiRes` is not eval).
fn perl_cluster_is_eval(arg: &str) -> bool {
    let Some(body) = arg.strip_prefix('-') else {
        return false;
    };
    if body.is_empty() || body.starts_with('-') {
        return false;
    }
    for ch in body.chars() {
        match ch {
            'e' | 'E' => return true,
            'F' | 'I' | 'M' | 'm' | 'C' | 'D' | 'x' | 'i' | ':' | '=' => return false,
            _ if ch.is_ascii_alphanumeric() => {}
            _ => return false,
        }
    }
    false
}

/// ruby clusters short options (`-e'x'`, `-we'x'`, `-ne'x'`): a lowercase
/// `e` reached before an operand letter is inline eval. Uppercase `-E` is
/// encoding (`-Eutf-8`), not eval; `-i`/`-I`/`-r`/`-C`/`-F`/`-K`/`-S`/`-T`/
/// `-x` and `:`/`=` consume the rest of the token.
fn ruby_cluster_is_eval(arg: &str) -> bool {
    let Some(body) = arg.strip_prefix('-') else {
        return false;
    };
    if body.is_empty() || body.starts_with('-') {
        return false;
    }
    for ch in body.chars() {
        match ch {
            'e' => return true,
            'E' | 'K' | 'I' | 'r' | 'S' | 'T' | 'x' | 'i' | 'C' | 'F' | ':' | '=' => {
                return false;
            }
            _ if ch.is_ascii_alphanumeric() => {}
            _ => return false,
        }
    }
    false
}

/// POSIX shells cluster single-letter options and `-c` takes the command
/// string (`-ec`, `-lc`, `-xc`, `-c'x'`): an eval `c` reached before an
/// operand-taking letter is inline eval. `-o` and `-O` consume an operand
/// (`-o pipefail`, `-O extglob`), so the token's tail after them is the
/// option's value, not flags — the flag run ends there.
fn shell_cluster_is_eval(arg: &str) -> bool {
    let Some(body) = arg.strip_prefix('-') else {
        return false;
    };
    if body.is_empty() || body.starts_with('-') {
        return false;
    }
    for ch in body.chars() {
        match ch {
            'c' => return true,
            'o' | 'O' => return false,
            _ if ch.is_ascii_alphabetic() => {}
            _ => return false,
        }
    }
    false
}

/// Result of scanning argv for the payload boundary.
enum PayloadScan {
    /// Index of the first non-option payload argument.
    Found(usize),
    /// argv carried only recognized options/operands — no payload token.
    Missing,
    /// A modeled family's unrecognized long option may consume the
    /// following argument, so the payload boundary cannot be resolved.
    Ambiguous(String),
}

/// Index of the first non-flag argument after the interpreter (script/module).
/// `None` when the scan fails closed before reaching it — bare `-`
/// (stdin) ends the scan since the payload is not a hash-bindable file.
/// `payload_boundary_blocker` reports which option caused an ambiguous
/// boundary.
///
/// Modeled families only — callers gate with `interpreter_from_command`.
#[cfg(test)]
pub(crate) fn first_payload_arg_index(argv: &[String]) -> Option<usize> {
    first_payload_arg_index_with_exe(argv, None)
}

/// `first_payload_arg_index` with the resolved executable's file
/// name as a second grammar spelling — the image the kernel execs.
pub(crate) fn first_payload_arg_index_with_exe(
    argv: &[String],
    resolved_exe: Option<&Path>,
) -> Option<usize> {
    scan_index(argv, &command_names(argv, resolved_exe))
}

fn scan_index(argv: &[String], names: &CommandNames) -> Option<usize> {
    match payload_scan(argv, names) {
        PayloadScan::Found(i) => Some(i),
        _ => None,
    }
}

/// The unrecognized long option that kept the scan from locating the
/// payload boundary — `Some` exactly when `first_payload_arg_index`
/// fails closed on a modeled family's `--long` option.
#[cfg(test)]
pub(crate) fn payload_boundary_blocker(argv: &[String]) -> Option<String> {
    payload_boundary_blocker_with_exe(argv, None)
}

/// `payload_boundary_blocker` over both spellings — either grammar's
/// ambiguous option, or a cross-spelling disagreement, is the blocker.
pub(crate) fn payload_boundary_blocker_with_exe(
    argv: &[String],
    resolved_exe: Option<&Path>,
) -> Option<String> {
    match payload_scan(argv, &command_names(argv, resolved_exe)) {
        PayloadScan::Ambiguous(flag) => Some(flag),
        _ => None,
    }
}

/// Scan argv under each modeled spelling's grammar and merge —
/// disagreement fails closed as ambiguous. An unmodeled `argv[0]`
/// still scans under the generic rules.
fn payload_scan(argv: &[String], names: &CommandNames) -> PayloadScan {
    let spellings = names.family_spellings();
    if spellings.is_empty() {
        return payload_scan_one(argv, names.spelled);
    }
    spellings
        .iter()
        .map(|spelling| payload_scan_one(argv, spelling))
        .reduce(merge_scans)
        .unwrap_or(PayloadScan::Missing)
}

/// The fail-closed combination of two family scans: identical results
/// pass through; any disagreement — including one side locating a
/// payload the other missed — is ambiguous.
fn merge_scans(a: PayloadScan, b: PayloadScan) -> PayloadScan {
    match (a, b) {
        (PayloadScan::Ambiguous(f), _) | (_, PayloadScan::Ambiguous(f)) => {
            PayloadScan::Ambiguous(f)
        }
        (PayloadScan::Found(i), PayloadScan::Found(j)) if i == j => PayloadScan::Found(i),
        (PayloadScan::Missing, PayloadScan::Missing) => PayloadScan::Missing,
        _ => PayloadScan::Ambiguous(
            "conflicting payload boundaries across argv0 and resolved spellings".to_string(),
        ),
    }
}

/// Scan argv under ONE spelling's option grammar — `argv0` selects the
/// family tables. [`payload_scan`] merges the per-spelling results.
fn payload_scan_one(argv: &[String], argv0: &str) -> PayloadScan {
    let mut i = 1;
    while i < argv.len() {
        let a = argv[i].as_str();
        if a == "--" {
            return if i + 1 < argv.len() {
                PayloadScan::Found(i + 1)
            } else {
                PayloadScan::Missing
            };
        }
        // A standalone `-` is the stdin spelling — the payload is not a
        // hash-bindable file, and it is not an option to skip either.
        if a == "-" {
            return PayloadScan::Missing;
        }
        // `cmd` options are `/`-prefixed (`/c`, `/k`, `/q`, …); POSIX
        // shells also take `+`-spellings that disable the matching `-`
        // option (`+e`, `+o errexit`, `+O extglob`).
        if a.starts_with('-')
            || (is_cmd_command(argv0) && a.starts_with('/'))
            || (is_shell_command(argv0) && a.len() > 1 && a.starts_with('+'))
        {
            // A live `-m` in a Python cluster names a module — the module
            // is the executable payload, so the scan ends here just as it
            // does at a script path. Attached (`-mhttp.server`, `-BmW`)
            // keeps the module inside the token; trailing (`-Bm`) puts it
            // on the next argv token.
            if matches!(
                interpreter_from_command(argv0),
                Some(InterpreterKind::Python)
            ) && python_cluster_names_module(a)
            {
                // The live `m` is the FIRST `m` in the cluster body —
                // `python_cluster_names_module` already proved no
                // operand-taking letter or `c` precedes it. It is
                // trailing only when that `m` is the body's final byte;
                // a later-attached module name may itself end in `m`
                // (`-Bmplatform`), which `a.ends_with('m')` would
                // misread as trailing.
                let body = &a[1..];
                let m_trailing = body
                    .bytes()
                    .position(|b| b == b'm')
                    .is_some_and(|pos| pos == body.len() - 1);
                return if m_trailing {
                    if i + 1 < argv.len() {
                        PayloadScan::Found(i + 1)
                    } else {
                        PayloadScan::Missing
                    }
                } else {
                    PayloadScan::Found(i)
                };
            }
            // Options that consume the next token as their operand: the
            // token after e.g. `--require` is the option's value, not the
            // payload script.
            if flag_consumes_operand(a, argv0) {
                i += 2;
                continue;
            }
            // A `--long` option with no inline `=value` is ambiguous on a
            // family whose option grammar this parser models — it may
            // consume the next token, so the payload boundary cannot be
            // trusted. Report the workload unbound instead of guessing:
            // callers map a failed scan to `argv.len()`, so the
            // inline-eval scan still covers the whole argv and a later
            // `-e`/`--eval` cannot slip past the refusal.
            if a.starts_with("--")
                && !a.contains('=')
                && known_option_family(argv0)
                && !is_valueless_long_option(argv0, a)
            {
                return PayloadScan::Ambiguous(a.to_string());
            }
            i += 1;
            continue;
        }
        return PayloadScan::Found(i);
    }
    PayloadScan::Missing
}

/// Options whose operand is the following argv token — that token is the
/// option's value, not the workload payload. `node --require stub.cjs
/// index.js` pins `index.js`, not `stub.cjs`; `python -W ignore server.py`
/// pins `server.py`, not `ignore`. The tables are per interpreter family:
/// a spelling that takes an operand on one interpreter is a plain flag on
/// another (`bash -r` is restricted-shell, `perl -W` is warnings), so a
/// token is consumed only when the flag is operand-taking on *this*
/// argv0's family. `--flag=value` and attached spellings (`-Wignore`)
/// carry the operand inline, so they match nothing here and consume only
/// themselves. `-m` (for CPython) and the inline-eval flags are
/// deliberately absent from the shared table: after their operand the
/// interpreter's option parsing is over and the remaining tokens are the
/// payload's own arguments.
fn flag_consumes_operand(arg: &str, argv0: &str) -> bool {
    if arg.contains('=') {
        return false;
    }
    let family_flag = match interpreter_from_command(argv0) {
        Some(InterpreterKind::Python) => {
            matches!(arg, "-W" | "-X" | "-Q" | "--check-hash-based-pycs")
        }
        Some(InterpreterKind::Node) => matches!(
            arg,
            "-r" | "--require"
                | "--loader"
                | "--experimental-loader"
                | "--import"
                | "--input-type"
                | "-C"
                | "--conditions"
                | "--icu-data-dir"
                | "--openssl-config"
                | "--redirect-warnings"
                | "--title"
                | "--diagnostic-dir"
                | "--report-directory"
                | "--report-filename"
                | "--heap-prof-dir"
                | "--heap-prof-name"
                | "--cpu-prof-dir"
                | "--cpu-prof-name"
                | "--cpu-prof-interval"
                | "--policy"
                | "--snapshot-blob"
                | "--inspect-publish-uid"
                | "--watch-path"
                | "--test-name-pattern"
        ),
        _ => false,
    };
    family_flag
        || interpreter_operand_extras(argv0).contains(&arg)
        || cluster_trailing_operand(arg, argv0)
        || (is_powershell_command(argv0) && powershell_flag_consumes_operand(arg))
}

/// PowerShell parameters whose value is the following argv token
/// (canonical lowercase names). PowerShell binds parameters by
/// unambiguous prefix — `-Work` binds `-WorkingDirectory` — so any flag
/// that *could* spell one of these must consume the next token:
/// under-consumption would let the operand pose as the payload and hide
/// a later eval flag; over-consumption only leaves the workload unbound.
/// `-File` and its prefixes are absent on purpose: the file operand *is*
/// the payload script, so the boundary lands on the next token rather
/// than past it.
const POWERSHELL_OPERAND_PARAMS: &[&str] = &[
    "command",
    "commandwithargs",
    "encodedcommand",
    "executionpolicy",
    "inputformat",
    "outputformat",
    "windowstyle",
    "version",
    "psconsolefile",
    "configurationname",
    "custompipename",
    "settingsfile",
    "workingdirectory",
];

/// Documented PowerShell aliases that are NOT prefixes of the canonical
/// names — `-ep` (ExecutionPolicy), `-if` (InputFormat), `-of`
/// (OutputFormat), `-sf` (SettingsFile), `-wd` (WorkingDirectory), `-cwa`
/// (CommandWithArgs). Prefix matching alone would miss them; the other
/// documented spellings already are prefixes (`-c`, `-e`, `-ex`, `-in`,
/// `-o`, `-v`, `-w`, `-cn`, `-config`, …).
const POWERSHELL_OPERAND_ALIASES: &[&str] = &["cwa", "ep", "if", "of", "sf", "wd"];

fn powershell_flag_consumes_operand(arg: &str) -> bool {
    let Some(body) = arg.strip_prefix('-') else {
        return false;
    };
    if body.is_empty() || body.starts_with('-') || body.contains(':') {
        return false;
    }
    let lower = body.to_ascii_lowercase();
    POWERSHELL_OPERAND_ALIASES.contains(&lower.as_str())
        || POWERSHELL_OPERAND_PARAMS
            .iter()
            .any(|name| name.starts_with(lower.as_str()))
}

/// A single-dash cluster whose LAST letter takes an operand consumes the
/// next argv token (`python -BW ignore`, `bash -eo pipefail`). An operand
/// letter earlier in the token absorbs the rest as its attached operand
/// (`python -Wignore`), so it consumes nothing extra.
fn cluster_trailing_operand(arg: &str, argv0: &str) -> bool {
    let body = if let Some(b) = arg.strip_prefix('-') {
        b
    } else if is_shell_command(argv0) {
        // Shells spell the disabling forms with `+` (`+eo pipefail`) —
        // the trailing-operand letters are the same as `-` clusters.
        arg.strip_prefix('+').unwrap_or("")
    } else {
        return false;
    };
    if body.len() < 2 || body.starts_with('-') {
        return false;
    }
    let operand_letters: &[char] = match interpreter_from_command(argv0) {
        // `-W`/`-X`/`-Q` take option values. `-m` is absent: it names the
        // module payload — `first_payload_arg_index` stops there via
        // `python_cluster_names_module`, it does not skip past it.
        Some(InterpreterKind::Python) => &['W', 'X', 'Q'],
        // `-o`/`-O` take the option-name operand.
        _ if is_shell_command(argv0) => &['o', 'O'],
        _ => return false,
    };
    match body.chars().position(|c| operand_letters.contains(&c)) {
        Some(pos) => pos == body.len() - 1,
        None => false,
    }
}

/// Interpreter families whose option grammar this module models. An
/// unrecognized `--long` option on one of these makes the payload
/// boundary ambiguous — it may take the next token as its operand — so
/// the workload fails closed as unbound. `npx` is excluded: its flags
/// belong to npm's grammar, which this parser does not model.
fn known_option_family(argv0: &str) -> bool {
    matches!(
        interpreter_from_command(argv0),
        Some(InterpreterKind::Python) | Some(InterpreterKind::Node)
    ) || is_perl_command(argv0)
        || is_ruby_command(argv0)
        || is_shell_command(argv0)
        || is_powershell_command(argv0)
        || is_cmd_command(argv0)
}

/// `--long` options that consume no operand on this family. The
/// per-family tables below enumerate the valueless spellings; on Node,
/// boolean negations follow a closed prefix rule instead — every
/// `--no-<flag>` is valueless — so they match by spelling.
fn is_valueless_long_option(argv0: &str, arg: &str) -> bool {
    valueless_long_options(argv0).contains(&arg)
        || (matches!(interpreter_from_command(argv0), Some(InterpreterKind::Node))
            && arg.starts_with("--no-"))
}

/// Long options that take no following operand, per interpreter family —
/// the spellings a launch line can plausibly carry. Anything else `--`
/// prefixed on a known family fails closed in `first_payload_arg_index`
/// as an ambiguous payload boundary; `--flag=value` forms are unambiguous
/// and never reach this table.
fn valueless_long_options(argv0: &str) -> &'static [&'static str] {
    match interpreter_from_command(argv0) {
        Some(InterpreterKind::Python) => &[
            "--help",
            "--version",
            "--help-env",
            "--help-xoptions",
            "--help-all",
            "--help-debug",
        ],
        Some(InterpreterKind::Node) => &[
            "--check",
            "--preserve-symlinks",
            "--preserve-symlinks-main",
            "--inspect",
            "--inspect-brk",
            "--watch",
            "--test",
            "--expose-gc",
            "--prof",
            "--pending-deprecation",
            "--trace-warnings",
            "--trace-deprecation",
            "--trace-exit",
            "--trace-uncaught",
            "--abort-on-uncaught-exception",
            "--permission",
            "--no-warnings",
            "--no-addons",
            "--enable-source-maps",
            "--experimental-strip-types",
            "--experimental-transform-types",
            "--experimental-vm-modules",
            "--disable-proto",
            "--help",
            "--version",
        ],
        _ if is_perl_command(argv0) => &["--help", "--version"],
        _ if is_ruby_command(argv0) => &["--help", "--version", "--verbose", "--yydebug"],
        _ if is_shell_command(argv0) => &[
            "--help",
            "--version",
            "--norc",
            "--noprofile",
            "--posix",
            "--login",
            "--restricted",
            "--interactive",
        ],
        _ => &[],
    }
}

/// Operand-taking flags that exist only on some interpreters — `-I` is an
/// include-path operand for perl and ruby but a plain flag (isolated mode)
/// on CPython, so these cannot live in the shared table. Perl's `-M`/`-m`
/// take a module operand too (unlike `python -m`, perl keeps scanning its
/// own options after the operand, so `-e` later in argv is still eval).
/// Ruby's `-C`/`-X` (chdir) and `-E` (encoding) consume the next token
/// just like `-I`/`-r` when not attached (`ruby -C dir -e x`).
fn interpreter_operand_extras(argv0: &str) -> &'static [&'static str] {
    if is_perl_command(argv0) {
        &["-I", "-M", "-m"]
    } else if is_ruby_command(argv0) {
        &["-I", "-r", "-C", "-X", "-E"]
    } else if is_shell_command(argv0) {
        // `-o errexit` / `-O extglob` — and the disabling `+` spellings —
        // consume the next token as the option's value, not the payload.
        &["-o", "-O", "+o", "+O"]
    } else {
        &[]
    }
}

/// Lowercased argv0 file stem with a `.exe` suffix removed — the spelling
/// the interpreter-family predicates match on.
fn command_stem(argv0: &str) -> String {
    let name = Path::new(argv0)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or(argv0);
    let lower = name.to_ascii_lowercase();
    lower
        .strip_suffix(".exe")
        .unwrap_or(lower.as_str())
        .to_string()
}

pub(crate) fn is_perl_command(argv0: &str) -> bool {
    let stem = command_stem(argv0);
    stem == "perl" || stem == "perl5" || stem.starts_with("perl5.")
}

pub(crate) fn is_ruby_command(argv0: &str) -> bool {
    let stem = command_stem(argv0);
    stem == "ruby"
        || stem
            .strip_prefix("ruby")
            .is_some_and(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit() || b == b'.'))
}

/// True when a single-dash Python option cluster contains a live `-m`:
/// an `m` reached before any operand-taking letter (`-W`/`-X`/`-Q`, whose
/// operand absorbs the rest of the token) or before `c` (whose command
/// string absorbs it) names a module — `-m`, `-mhttp.server`,
/// `-Bm http.server`, `-BmQ`. `-Wm` does not: there the `m` is `-W`'s
/// operand value; `-cm` does not either: the `m` is part of the `-c`
/// command string, so the token is eval, not a module option.
pub(crate) fn python_cluster_names_module(arg: &str) -> bool {
    let Some(body) = arg.strip_prefix('-') else {
        return false;
    };
    if body.is_empty() || body.starts_with('-') {
        return false;
    }
    for ch in body.chars() {
        match ch {
            'm' => return true,
            'c' | 'W' | 'X' | 'Q' => return false,
            _ if ch.is_ascii_alphabetic() => {}
            _ => return false,
        }
    }
    false
}

/// POSIX-style shells whose single-letter options cluster and whose `-c`
/// reads the command from a string operand.
pub(crate) fn is_shell_command(argv0: &str) -> bool {
    matches!(
        command_stem(argv0).as_str(),
        "sh" | "bash" | "dash" | "ash" | "zsh" | "ksh" | "mksh"
    )
}

/// First non-flag argument after the interpreter (the script or module path).
#[cfg(test)]
pub(crate) fn first_payload_arg(argv: &[String]) -> Option<&str> {
    first_payload_arg_index(argv).map(|i| argv[i].as_str())
}

/// `first_payload_arg` with the resolved executable's file name as a
/// second grammar spelling.
pub(crate) fn first_payload_arg_with_exe<'a>(
    argv: &'a [String],
    resolved_exe: Option<&Path>,
) -> Option<&'a str> {
    first_payload_arg_index_with_exe(argv, resolved_exe).map(|i| argv[i].as_str())
}

/// True when the argv names a module rather than a script file —
/// `-m <name>`, the attached `-m<name>` spelling, or a clustered live
/// `-m` (`-Bm <name>`). The module name is the payload but is not a
/// hash-bindable file: it resolves through the interpreter's module
/// search path at run time. The resolved executable's file name is a
/// second grammar spelling — a cluster `-m` counts when either
/// spelling's family is Python.
///
/// Only meaningful when `argv[0]` is one of [`interpreter_from_command`]'s
/// modeled interpreters — other families' `-m` spellings mean other
/// things (`sh -m` is monitor mode, `perl -m` takes an operand).
pub(crate) fn payload_is_module_with_exe(argv: &[String], resolved_exe: Option<&Path>) -> bool {
    let names = command_names(argv, resolved_exe);
    let end = scan_index(argv, &names).unwrap_or(argv.len());
    argv[..end].iter().any(|a| a == "-m")
        || (names.any_is(|s| matches!(interpreter_from_command(s), Some(InterpreterKind::Python)))
            && (argv[..end].iter().any(|a| python_cluster_names_module(a))
                || argv
                    .get(end)
                    .is_some_and(|a| python_cluster_names_module(a))))
}

/// Why a launcher's own `binary-hash` pin cannot bind the workload it
/// selects — the launch-shape vocabulary the launcher caveats and the
/// launch report's `code_identity` share.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DelegatingLauncher {
    /// execs whatever command its arguments name (`env`, `sudo`,
    /// `timeout`, `nice`, `nohup`, `setsid`, `stdbuf`, `chrt`,
    /// `taskset`, `ionice`, `gtimeout`, `doas`).
    ExecsArgv,
    /// The `py`/`pyw` launcher selects the Python interpreter at run
    /// time — a pin on the launcher does not pin the interpreter.
    PythonSelector,
    /// `cmd`, `powershell`, `pwsh` run a command string (`/c`,
    /// `-Command`) — the command text is argv, not a bindable file.
    CommandShell,
    /// Package executors (`npx`, `bunx`, `uvx`, `pipx`, `pnpx`) resolve
    /// the package and the runtime at run time.
    PackageExecutor,
    /// Workload resolvers (`uv`, `poetry`, `pipenv`, `pdm`, `hatch`,
    /// `conda`, `npm`, `pnpm`, `yarn`, `deno`, `bun`, `docker`,
    /// `podman`) resolve the payload from a manifest, subcommand, or
    /// image at run time.
    WorkloadResolver,
}

/// `argv[0]`s that launch a workload selected at run time — a hash pin
/// on the launcher binary does not bind the command, package, module,
/// or image it selects. Returns the launcher category and the
/// normalized stem (lowercased, `.exe` stripped) for messages.
pub(crate) fn delegating_launcher(argv0: &str) -> Option<(DelegatingLauncher, String)> {
    let name = Path::new(argv0)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or(argv0);
    let name = name.rsplit(['/', '\\']).next().unwrap_or(name);
    let lower = name.to_ascii_lowercase();
    let stem = lower.strip_suffix(".exe").unwrap_or(lower.as_str());
    let kind = match stem {
        "env" | "nice" | "nohup" | "timeout" | "gtimeout" | "setsid" | "stdbuf" | "chrt"
        | "taskset" | "ionice" | "sudo" | "doas" => DelegatingLauncher::ExecsArgv,
        "py" | "pyw" => DelegatingLauncher::PythonSelector,
        "cmd" | "powershell" | "pwsh" => DelegatingLauncher::CommandShell,
        "npx" | "bunx" | "uvx" | "pipx" | "pnpx" => DelegatingLauncher::PackageExecutor,
        "uv" | "poetry" | "pipenv" | "pdm" | "hatch" | "conda" | "npm" | "pnpm" | "yarn"
        | "deno" | "bun" | "docker" | "podman" => DelegatingLauncher::WorkloadResolver,
        _ => return None,
    };
    Some((kind, stem.to_string()))
}

/// The content of `path`'s shebang line without the `#!` prefix
/// (`#!/usr/bin/env python3` → `/usr/bin/env python3`), when present.
pub(crate) fn shebang_line(path: &Path) -> Option<String> {
    let mut buf = [0u8; 256];
    let n = std::fs::File::open(path)
        .and_then(|mut f| {
            use std::io::Read;
            f.read(&mut buf)
        })
        .ok()?;
    // Only the first line is the shebang — invalid UTF-8 further into the
    // file must not hide it, and a CRLF ending loses its `\r`.
    let end = buf[..n].iter().position(|&b| b == b'\n').unwrap_or(n);
    let line = buf[..end].strip_suffix(b"\r").unwrap_or(&buf[..end]);
    let first = std::str::from_utf8(line).ok()?;
    first.strip_prefix("#!").map(|s| s.trim().to_string())
}

/// Repository portion of an image reference (tag and digest stripped).
pub(crate) fn image_repository(reference: &str) -> String {
    let mut s = reference;
    if let Some((repo, digest)) = reference.rsplit_once('@')
        && digest.starts_with("sha256:")
    {
        s = repo;
    }
    if let Some(slash) = s.rfind('/') {
        if let Some(colon) = s[slash + 1..].rfind(':') {
            return s[..slash + 1 + colon].to_string();
        }
    } else if let Some(colon) = s.rfind(':') {
        return s[..colon].to_string();
    }
    s.to_string()
}

/// Whether two image repositories name the same image source —
/// `container::inspect`'s RepoDigests match and `verifier::identity`'s
/// pin-target check share it.
pub(crate) fn repos_match(entry_repo: &str, wanted: &str) -> bool {
    if wanted.is_empty() {
        return false;
    }
    normalize_repository(entry_repo) == normalize_repository(wanted)
}

/// Canonicalize a repository by filling in Docker Hub (`docker.io`) and the
/// omitted official-image namespace (`library`) only. Other registries are
/// left unchanged so a suffix cannot match a different registry.
fn normalize_repository(repo: &str) -> String {
    let (registry, path) = match repo.split_once('/') {
        Some((first, rest)) if is_registry_host(first) => (first, rest.to_string()),
        Some(_) => ("docker.io", repo.to_string()),
        None => ("docker.io", repo.to_string()),
    };
    let path = if registry == "docker.io" && !path.contains('/') {
        format!("library/{path}")
    } else {
        path
    };
    format!("{registry}/{path}")
}

fn is_registry_host(first: &str) -> bool {
    first == "localhost" || first.contains('.') || first.contains(':')
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
        // Node's print-eval and perl's feature-eval classify as inline eval;
        // the same spellings on other families are not evaluation.
        let argv = vec!["node".into(), "-p".into(), "1+1".into()];
        assert!(argv_contains_inline_eval(&argv));
        // `-pe` is node's combined print-eval form (`-ep`/`-pie` are not
        // valid options) — the next argument is code, not a payload file.
        let argv = vec!["node".into(), "-pe".into(), "console.log(1)".into()];
        assert!(argv_contains_inline_eval(&argv));
        assert_eq!(first_payload_arg(&argv), Some("console.log(1)"));
        let argv = vec!["node".into(), "--print".into(), "1+1".into()];
        assert!(argv_contains_inline_eval(&argv));
        let argv = vec!["perl".into(), "-E".into(), "say 1".into()];
        assert!(argv_contains_inline_eval(&argv));
        let argv = vec!["perl".into(), "-p".into(), "script.pl".into()];
        assert!(!argv_contains_inline_eval(&argv));
        assert_eq!(first_payload_arg(&argv), Some("script.pl"));
        let argv = vec!["python".into(), "-E".into(), "server.py".into()];
        assert!(!argv_contains_inline_eval(&argv));
        assert_eq!(first_payload_arg(&argv), Some("server.py"));
    }

    #[test]
    fn test_inline_eval_attached_and_equals_forms() {
        // Equals spellings on modeled interpreter families.
        for argv in [
            vec!["node".into(), "--eval=x".into()],
            vec!["node".into(), "--command=x".into()],
        ] {
            assert!(argv_contains_inline_eval(&argv), "{argv:?}");
        }
        // Model-unknown argv0: eval spellings are plain arguments — a
        // native binary's `-c config.yaml` / `--eval=x` is not inline eval.
        for argv in [
            vec!["someserver".into(), "--eval=x".into()],
            vec!["someserver".into(), "-c".into(), "config.yaml".into()],
        ] {
            assert!(!argv_contains_inline_eval(&argv), "{argv:?}");
        }
        // On non-Python/Node families the bare letters are other options:
        // `sh -e` is errexit, `perl -c` / `ruby -c` are syntax checks —
        // their eval spellings come from the cluster parsers. Node's
        // `-c`/`--check` is a syntax check too: the script stays the
        // payload, so the launch binds instead of reading as eval.
        for argv in [
            vec!["sh".into(), "-e".into(), "script.sh".into()],
            vec!["perl".into(), "-c".into(), "script.pl".into()],
            vec!["ruby".into(), "-c".into(), "script.rb".into()],
            vec!["node".into(), "-c".into(), "server.js".into()],
            vec!["node".into(), "--check".into(), "server.js".into()],
        ] {
            assert!(!argv_contains_inline_eval(&argv), "{argv:?}");
        }
        for argv in [
            vec!["node".into(), "-c".into(), "server.js".into()],
            vec!["node".into(), "--check".into(), "server.js".into()],
        ] {
            assert_eq!(first_payload_arg(&argv), Some("server.js"), "{argv:?}");
        }
        // `+`-prefixed shell options are flags too — `+e` disables
        // errexit and `+o`/`+O` take an operand — so a `+` token must
        // not become the payload boundary and hide a later `-c`.
        for argv in [
            vec!["bash".into(), "+e".into(), "-c".into(), "x".into()],
            vec![
                "bash".into(),
                "+o".into(),
                "errexit".into(),
                "-c".into(),
                "x".into(),
            ],
            vec![
                "bash".into(),
                "+eo".into(),
                "pipefail".into(),
                "-c".into(),
                "x".into(),
            ],
        ] {
            assert!(argv_contains_inline_eval(&argv), "{argv:?}");
        }
        // PowerShell and cmd take their command strings through their own
        // spellings; `pwsh -File` is a payload, not eval.
        for argv in [
            vec!["pwsh".into(), "-c".into(), "x".into()],
            vec!["powershell.exe".into(), "-Command".into(), "x".into()],
            vec!["pwsh".into(), "-EncodedCommand".into(), "eA==".into()],
            // Unambiguous prefixes bind too — `-Comm`, `-Enc`, and a
            // `:`-attached operand on an abbreviated name.
            vec!["pwsh".into(), "-Comm".into(), "x".into()],
            vec!["pwsh".into(), "-EN".into(), "eA==".into()],
            vec!["pwsh".into(), "-Command:x".into()],
            // `-ec`/`-cwa` are documented aliases that are not prefixes of
            // their canonical names; `-CommandWithArgs` runs its operand.
            vec!["pwsh".into(), "-ec".into(), "eA==".into()],
            vec!["pwsh".into(), "-cwa".into(), "x".into()],
            vec!["pwsh".into(), "-CommandWithArgs".into(), "x".into()],
            vec!["cmd".into(), "/c".into(), "dir".into()],
            vec!["cmd.exe".into(), "/K".into(), "dir".into()],
            // `/r` runs the command too, and the switch accepts the
            // command text concatenated onto it.
            vec!["cmd".into(), "/R".into(), "dir".into()],
            vec!["cmd".into(), "/cdir".into()],
        ] {
            assert!(argv_contains_inline_eval(&argv), "{argv:?}");
        }
        let argv = vec!["pwsh".into(), "-File".into(), "server.ps1".into()];
        assert!(!argv_contains_inline_eval(&argv));
        // Windows PowerShell (`powershell.exe`, unlike `pwsh`) binds a
        // positional non-script argument as an implicit `-Command`.
        for argv in [
            vec!["powershell".into(), "Get-Process".into()],
            vec![
                "powershell.exe".into(),
                "-NoProfile".into(),
                "Get-Process".into(),
            ],
        ] {
            assert!(argv_contains_inline_eval(&argv), "{argv:?}");
        }
        // `pwsh` keeps requiring `-Command`, a `.ps1` payload is always a
        // script, and `-File` marks its operand a file at any extension.
        for argv in [
            vec!["pwsh".into(), "Get-Process".into()],
            vec!["powershell".into(), "server.ps1".into()],
            vec!["powershell".into(), "SERVER.PS1".into()],
            vec!["powershell".into(), "-File".into(), "bootstrap".into()],
        ] {
            assert!(!argv_contains_inline_eval(&argv), "{argv:?}");
        }
        // Operand-taking options must not swallow the eval flag — their
        // operand is consumed, but the scan continues past it. PowerShell
        // parameters match case-insensitively (`-EP`, `-WD`); ruby's
        // `-C`/`-X`/`-E` take their operand like `-I`/`-r` do.
        for argv in [
            vec![
                "pwsh".into(),
                "-EP".into(),
                "Bypass".into(),
                "-c".into(),
                "x".into(),
            ],
            vec![
                "pwsh".into(),
                "-WorkingDirectory".into(),
                "dir".into(),
                "-Command".into(),
                "x".into(),
            ],
            // An abbreviated operand-taking flag (`-Work` →
            // `-WorkingDirectory`) must consume its operand the same way,
            // or `dir` would pose as the payload and hide `-c`. `-WD` and
            // `-Of` are documented aliases that are not prefixes of the
            // canonical names.
            vec![
                "pwsh".into(),
                "-Work".into(),
                "dir".into(),
                "-c".into(),
                "x".into(),
            ],
            vec![
                "pwsh".into(),
                "-WD".into(),
                "dir".into(),
                "-c".into(),
                "x".into(),
            ],
            vec![
                "pwsh".into(),
                "-Of".into(),
                "Text".into(),
                "-c".into(),
                "x".into(),
            ],
            vec![
                "ruby".into(),
                "-C".into(),
                "dir".into(),
                "-e".into(),
                "x".into(),
            ],
            vec![
                "ruby".into(),
                "-X".into(),
                "dir".into(),
                "-e".into(),
                "x".into(),
            ],
            vec![
                "ruby".into(),
                "-E".into(),
                "utf-8".into(),
                "-e".into(),
                "x".into(),
            ],
        ] {
            assert!(argv_contains_inline_eval(&argv), "{argv:?}");
        }
        // A cluster whose trailing letter takes an operand consumes the
        // next token — the eval scan must reach past it to a later flag.
        for argv in [
            vec![
                "bash".into(),
                "-eo".into(),
                "pipefail".into(),
                "-c".into(),
                "echo hi".into(),
            ],
            vec![
                "python".into(),
                "-BW".into(),
                "ignore".into(),
                "-c".into(),
                "print(1)".into(),
            ],
        ] {
            assert!(argv_contains_inline_eval(&argv), "{argv:?}");
        }
        // Attached/clustered CPython spellings (`-c'x'`, `-Ec'x'`).
        for argv in [
            vec!["python".into(), "-cprint(1)".into()],
            vec!["python".into(), "-Ecprint(1)".into()],
            vec!["python".into(), "-Bdc".into(), "print(1)".into()],
        ] {
            assert!(argv_contains_inline_eval(&argv), "{argv:?}");
        }
        // `-Wignore` / `-X dev` style operands are not eval.
        let argv = vec!["python".into(), "-Wignore".into(), "server.py".into()];
        assert!(!argv_contains_inline_eval(&argv));
        // Node's `--print=`; bare `-p`/`--print` stay scoped to node.
        let argv = vec!["node".into(), "--print=1+1".into()];
        assert!(argv_contains_inline_eval(&argv));
        let argv = vec!["perl".into(), "--print".into(), "script.pl".into()];
        assert!(!argv_contains_inline_eval(&argv));
        // perl concatenated eval (`-e'x'`, `-pe'x'`, `-nE'x'`); `-M`/`-I`
        // operands end the flag run (`-MTime::HiRes` is not eval).
        for argv in [
            vec!["perl".into(), "-eprint 1".into()],
            vec!["perl".into(), "-pes/x/y/".into()],
            vec!["perl".into(), "-nEsay 1".into()],
            vec!["perl".into(), "-wleprint 1".into()],
        ] {
            assert!(argv_contains_inline_eval(&argv), "{argv:?}");
        }
        for argv in [
            vec!["perl".into(), "-MTime::HiRes".into(), "script.pl".into()],
            vec!["perl".into(), "-Ilib".into(), "script.pl".into()],
        ] {
            assert!(!argv_contains_inline_eval(&argv), "{argv:?}");
        }
        // ruby clustered `-e`; `-Eutf-8` is encoding, not eval.
        for argv in [
            vec!["ruby".into(), "-eputs 1".into()],
            vec!["ruby".into(), "-weputs 1".into()],
        ] {
            assert!(argv_contains_inline_eval(&argv), "{argv:?}");
        }
        let argv = vec!["ruby".into(), "-Eutf-8".into(), "server.rb".into()];
        assert!(!argv_contains_inline_eval(&argv));
        // POSIX shells cluster options and `-c` takes the command string:
        // `-ec`/`-lc`/`-xc` and the attached `-c'x'` are inline eval.
        for argv in [
            vec!["sh".into(), "-ec".into(), "echo hi".into()],
            vec!["bash".into(), "-lc".into(), "echo hi".into()],
            vec!["dash".into(), "-xc".into(), "echo hi".into()],
            vec!["zsh".into(), "-cecho hi".into()],
        ] {
            assert!(argv_contains_inline_eval(&argv), "{argv:?}");
        }
        // `-o`/`-O` take an operand, so a `c` inside their token tail is
        // the option's value, not a flag; and `-o` consumes the next argv
        // token, leaving a later `-c` detectable.
        for argv in [
            vec!["bash".into(), "-oc".into(), "echo hi".into()],
            vec!["bash".into(), "-Ox".into(), "script.sh".into()],
            // `sh -ex script.sh` runs the file with errexit+xtrace — no `c`.
            vec!["sh".into(), "-ex".into(), "script.sh".into()],
        ] {
            assert!(!argv_contains_inline_eval(&argv), "{argv:?}");
        }
        let argv = vec![
            "sh".into(),
            "-o".into(),
            "errexit".into(),
            "-c".into(),
            "echo hi".into(),
        ];
        assert!(argv_contains_inline_eval(&argv));
        // Non-interpreter argv0: attached single-dash spellings are not
        // assumed eval (a Go-style `-config` is a file operand, not code).
        let argv = vec!["myserver".into(), "-config.yaml".into()];
        assert!(!argv_contains_inline_eval(&argv));
    }

    #[test]
    fn test_resolved_exe_second_grammar_spelling() {
        // A renamed alias: argv[0] is uninformative, but the resolved
        // image's file name names the interpreter family.
        let resolved = Path::new("/usr/bin/python3.12");
        let argv = vec!["worker".into(), "-c".into(), "print(1)".into()];
        assert!(argv_contains_inline_eval_with_exe(&argv, Some(resolved)));
        // The spelled argv[0] alone sees no modeled family.
        assert!(!argv_contains_inline_eval(&argv));

        let argv = vec!["worker".into(), "server.py".into()];
        assert_eq!(
            first_payload_arg_with_exe(&argv, Some(resolved)),
            Some("server.py")
        );

        // Node preload flags under the resolved name.
        let node = Path::new("/usr/bin/node");
        let argv = vec![
            "worker".into(),
            "-r".into(),
            "stub.cjs".into(),
            "index.js".into(),
        ];
        assert!(node_preload_flags_present_with_exe(&argv, Some(node)));
        assert_eq!(
            first_payload_arg_with_exe(&argv, Some(node)),
            Some("index.js")
        );
    }

    #[test]
    fn test_resolved_exe_conflicting_grammar_fails_closed() {
        // Cross-family disagreement fails closed: a shell reads `-o x`
        // as an option operand while python reads `x` as the payload —
        // the boundary is ambiguous, not guessed.
        let bash = Path::new("/bin/bash");
        let argv = vec!["python3".into(), "-o".into(), "x".into()];
        assert_eq!(first_payload_arg_index_with_exe(&argv, Some(bash)), None);
        assert!(payload_boundary_blocker_with_exe(&argv, Some(bash)).is_some());

        // Eval under EITHER reading still classifies as eval — the
        // spelled grammar's `-c` reads eval even though the resolved
        // image names python.
        let python = Path::new("/usr/bin/python3.12");
        let argv = vec!["bash".into(), "-c".into(), "echo hi".into()];
        assert!(argv_contains_inline_eval_with_exe(&argv, Some(python)));

        // A module spelling under the resolved python grammar.
        let argv = vec!["worker".into(), "-m".into(), "http.server".into()];
        assert!(payload_is_module_with_exe(&argv, Some(python)));
    }

    #[test]
    fn test_node_preload_flags() {
        // Separated and equals spellings before the payload.
        for argv in [
            vec![
                "node".into(),
                "-r".into(),
                "stub.cjs".into(),
                "index.js".into(),
            ],
            vec![
                "node".into(),
                "--require".into(),
                "stub.cjs".into(),
                "index.js".into(),
            ],
            vec![
                "node".into(),
                "--require=stub.cjs".into(),
                "index.js".into(),
            ],
            vec!["node".into(), "--import=mod.mjs".into(), "index.js".into()],
            vec![
                "node".into(),
                "--loader".into(),
                "ts-node".into(),
                "index.js".into(),
            ],
            vec![
                "node".into(),
                "--experimental-loader=esm.mjs".into(),
                "index.js".into(),
            ],
        ] {
            assert!(node_preload_flags_present(&argv), "{argv:?}");
        }
        // A `--require` after the payload is the script's own argument, and
        // the flags are node-only.
        let argv = vec![
            "node".into(),
            "server.js".into(),
            "--require".into(),
            "x".into(),
        ];
        assert!(!node_preload_flags_present(&argv));
        let argv = vec![
            "ruby".into(),
            "-r".into(),
            "json".into(),
            "server.rb".into(),
        ];
        assert!(!node_preload_flags_present(&argv));
        let argv = vec!["node".into(), "index.js".into()];
        assert!(!node_preload_flags_present(&argv));
    }

    #[test]
    fn test_python_attached_module_is_payload_boundary() {
        // `python -m<mod>` glues the module to the flag — the module token
        // is the executable payload, and later tokens are its arguments.
        let argv = vec!["python".into(), "-mhttp.server".into(), "8080".into()];
        assert_eq!(first_payload_arg(&argv), Some("-mhttp.server"));
        assert!(!argv_contains_inline_eval(&argv));
        // The separated spelling keeps resolving to the module name.
        let argv = vec!["python".into(), "-m".into(), "http.server".into()];
        assert_eq!(first_payload_arg(&argv), Some("http.server"));
        // Scoped to CPython — perl's `-m` consumes its operand separately.
        let argv = vec!["perl".into(), "-mFoo".into(), "script.pl".into()];
        assert_eq!(first_payload_arg(&argv), Some("script.pl"));
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
        // Clustered spellings whose final letter takes an operand consume
        // the next token too — the operand is not the payload.
        let argv = vec![
            "bash".into(),
            "-eo".into(),
            "pipefail".into(),
            "script.sh".into(),
        ];
        assert_eq!(first_payload_arg(&argv), Some("script.sh"));
        let argv = vec![
            "python".into(),
            "-BW".into(),
            "ignore".into(),
            "server.py".into(),
        ];
        assert_eq!(first_payload_arg(&argv), Some("server.py"));
        // A cluster ending in a live `-m` bounds the scan at the module
        // name on the next token, like bare `-m` does.
        let argv = vec![
            "python".into(),
            "-Bm".into(),
            "http.server".into(),
            "8080".into(),
        ];
        assert_eq!(first_payload_arg(&argv), Some("http.server"));
        assert!(python_cluster_names_module("-Bm"));
        // `-Wm` is `-W` with attached operand `m`, not a module flag.
        assert!(!python_cluster_names_module("-Wm"));
        let argv = vec!["python".into(), "-Wm".into(), "server.py".into()];
        assert_eq!(first_payload_arg(&argv), Some("server.py"));
        // `-cm` is `-c` with the command string `m` — eval, not a module
        // flag; the token must not become a payload boundary that hides
        // the eval letter from the scan.
        assert!(!python_cluster_names_module("-cm"));
        let argv = vec!["python".into(), "-cm".into()];
        assert!(argv_contains_inline_eval(&argv));
        // An attached module name may itself end in `m` — `-Bmplatform`
        // is `-B` + module `platform`, so the boundary stays on the
        // token; only a live `m` as the body's final byte moves it to
        // the next argument.
        let argv = vec!["python".into(), "-mplatform".into(), "8080".into()];
        assert_eq!(first_payload_arg_index(&argv), Some(1));
        let argv = vec!["python".into(), "-Bmplatform".into(), "8080".into()];
        assert_eq!(first_payload_arg_index(&argv), Some(1));
        let argv = vec!["python".into(), "-mm".into(), "8080".into()];
        assert_eq!(first_payload_arg_index(&argv), Some(1));
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
        // CPython 2's `-Q` division flag consumes the next token — its
        // operand must not pose as the payload and hide a later `-c`.
        let argv = vec![
            "python2".into(),
            "-Q".into(),
            "new".into(),
            "-c".into(),
            "x".into(),
        ];
        assert!(argv_contains_inline_eval(&argv));
        // perl `-Ilib` (attached) does not consume the next token.
        let argv = vec!["perl".into(), "-Ilib".into(), "script.pl".into()];
        assert_eq!(first_payload_arg(&argv), Some("script.pl"));
        // Operand tables are per family: spellings that take an operand
        // on Node/CPython are plain flags elsewhere — `bash -r` is
        // restricted mode and `perl -W` is warnings, so the next token
        // stays the payload script.
        let argv = vec!["bash".into(), "-r".into(), "script.sh".into()];
        assert_eq!(first_payload_arg(&argv), Some("script.sh"));
        let argv = vec!["perl".into(), "-W".into(), "script.pl".into()];
        assert_eq!(first_payload_arg(&argv), Some("script.pl"));
    }

    #[test]
    fn test_unknown_long_option_fails_closed_as_unbound() {
        // A `--long` option with no `=value` on a family whose option
        // grammar is modeled may consume the next token — the payload
        // boundary is ambiguous, so the workload reports unbound.
        for argv in [
            vec!["node".into(), "--unknown-opt".into(), "server.js".into()],
            vec!["python3".into(), "--unknown-opt".into(), "server.py".into()],
            vec!["bash".into(), "--unknown-opt".into(), "server.sh".into()],
            vec!["perl".into(), "--unknown-opt".into(), "server.pl".into()],
            vec!["ruby".into(), "--unknown-opt".into(), "server.rb".into()],
        ] {
            assert_eq!(first_payload_arg_index(&argv), None, "{argv:?}");
        }
        // …and a later inline-eval flag cannot bypass the refusal: an
        // unbound boundary widens the eval scan to the whole argv.
        let argv = vec![
            "node".into(),
            "--unknown-opt".into(),
            "server.js".into(),
            "--eval".into(),
            "x".into(),
        ];
        assert_eq!(first_payload_arg_index(&argv), None);
        assert!(argv_contains_inline_eval(&argv));
        // `--flag=value` carries its operand inline — unambiguous.
        let argv = vec!["node".into(), "--unknown-opt=1".into(), "server.js".into()];
        assert_eq!(first_payload_arg_index(&argv), Some(2));
        // Recognized valueless and operand-taking long options still bind.
        let argv = vec![
            "node".into(),
            "--preserve-symlinks".into(),
            "server.js".into(),
        ];
        assert_eq!(first_payload_arg_index(&argv), Some(2));
        let argv = vec!["node".into(), "--watch".into(), "server.js".into()];
        assert_eq!(first_payload_arg_index(&argv), Some(2));
        // Node `--no-<flag>` boolean negations are valueless by prefix —
        // they do not consume the script token.
        let argv = vec![
            "node".into(),
            "--no-network-family-autoselection".into(),
            "server.js".into(),
        ];
        assert_eq!(first_payload_arg_index(&argv), Some(2));
        // Common valueless flags keep the boundary unambiguous.
        for flag in [
            "--permission",
            "--trace-uncaught",
            "--abort-on-uncaught-exception",
        ] {
            let argv = vec!["node".into(), flag.into(), "server.js".into()];
            assert_eq!(first_payload_arg_index(&argv), Some(2), "{flag}");
        }
        // `payload_boundary_blocker` names the option behind an ambiguous
        // boundary; a plain no-payload argv reports no blocker.
        let argv = vec!["node".into(), "--unknown-opt".into(), "server.js".into()];
        assert_eq!(
            payload_boundary_blocker(&argv).as_deref(),
            Some("--unknown-opt")
        );
        let argv = vec!["node".into(), "server.js".into()];
        assert_eq!(payload_boundary_blocker(&argv), None);
        // The negation prefix stays Node-scoped: on a modeled non-Node
        // family an unrecognized `--no-*` still fails closed.
        let argv = vec![
            "python3".into(),
            "--no-something".into(),
            "server.py".into(),
        ];
        assert_eq!(first_payload_arg_index(&argv), None);
        let argv = vec![
            "node".into(),
            "--require".into(),
            "stub.cjs".into(),
            "server.js".into(),
        ];
        assert_eq!(first_payload_arg_index(&argv), Some(3));
        // Unknown argv0 keeps the lenient boundary — not a modeled family.
        let argv = vec![
            "someserver".into(),
            "--unknown-opt".into(),
            "payload".into(),
        ];
        assert_eq!(first_payload_arg_index(&argv), Some(2));
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
        // CPython 2.x and PyPy spellings share the Python option grammar.
        for name in ["python2", "python2.7", "pypy", "pypy2", "pypy3", "pypy3.10"] {
            assert_eq!(
                interpreter_from_command(name),
                Some(InterpreterKind::Python),
                "{name}"
            );
        }
        for name in ["python2", "pypy3"] {
            let argv = vec![name.into(), "-c".into(), "print(1)".into()];
            assert!(argv_contains_inline_eval(&argv), "{name}");
        }
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
