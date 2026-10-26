//! Child-process environment block construction.
//!
//! [`spawn_env_pairs`] produces the complete environment for a spawned child,
//! or `None` when the child inherits the parent environment unchanged.
//! [`apply_spawn_env`] applies that block to a `tokio::process::Command`.
//!
//! Synchronous `std::process::Command` spawns never touch the environment —
//! that is the existing contract of the sync Linux path. The one exception is
//! the `unotify-run` supervised spawn ([`apply_spawn_env_sync`]): it is a
//! launch path like `run`, so the `defaults.environment` restriction applies
//! there too.

use std::ffi::{OsStr, OsString};
use std::path::PathBuf;

use super::SpawnOptions;

/// Apply the [`SpawnOptions`] environment to an async command.
///
/// `None` (inherit parent) leaves the command untouched: no `env_clear`.
/// `exec_dyld_fallback` applies either way — it is exec plumbing the
/// launcher derives (a staged executable's relocated rpath lookup), not
/// parent-environment passthrough subject to the restriction. When the
/// env block legitimately carries `DYLD_FALLBACK_LIBRARY_PATH` (inherit
/// mode, or an allowlisted name under restriction) the derived dirs are
/// appended to that search list rather than replacing it; a name the
/// restriction dropped stays dropped.
pub(crate) fn apply_spawn_env(cmd: &mut tokio::process::Command, opts: &SpawnOptions) {
    let pairs = spawn_env_pairs(opts);
    if let Some(ref p) = pairs {
        cmd.env_clear();
        for (key, value) in p {
            cmd.env(key, value);
        }
    }
    if !opts.exec_dyld_fallback.is_empty()
        && let Some(joined) = merged_dyld_fallback(
            dyld_fallback_inherited(pairs.as_deref()),
            &opts.exec_dyld_fallback,
        )
    {
        cmd.env("DYLD_FALLBACK_LIBRARY_PATH", joined);
    }
}

/// The `DYLD_FALLBACK_LIBRARY_PATH` value the spawn would carry before
/// the derived dirs are appended: `None` env block means the parent's
/// value passes through untouched; an explicit block means whatever
/// the block holds — the parent snapshot under tmpdir-override, or an
/// allowlisted copy under restriction.
fn dyld_fallback_inherited(pairs: Option<&[(OsString, OsString)]>) -> Option<OsString> {
    match pairs {
        None => std::env::var_os("DYLD_FALLBACK_LIBRARY_PATH"),
        Some(p) => p
            .iter()
            .find(|(k, _)| env_key_eq(k, OsStr::new("DYLD_FALLBACK_LIBRARY_PATH")))
            .map(|(_, v)| v.clone()),
    }
}

/// dyld's built-in fallback for an `@rpath` reference with no matching
/// `LC_RPATH` (`~/lib` is deliberately absent — a home-dir library root
/// is not a system code source we bless). `macos_sandbox`'s dep walk
/// uses the same platform constant.
pub(crate) const DYLD_FALLBACK_DIRS: &[&str] = &["/usr/local/lib", "/usr/lib"];

/// The fallback dir list the spawn would merge for `opts` —
/// [`merged_dyld_fallback`]'s composition (inherited entries + derived
/// dirs + the platform defaults when no inherited list survives),
/// expressed as dirs so the `sandbox-exec` bash wrapper can re-join and
/// quote it inside its `-c` string. Empty when the launch carries no
/// relocation fallback. macOS-only — its sole consumer is the
/// `sandbox-exec` wrapper construction.
#[cfg(target_os = "macos")]
pub(crate) fn spawn_dyld_fallback_dirs(opts: &SpawnOptions) -> Vec<PathBuf> {
    if opts.exec_dyld_fallback.is_empty() {
        return Vec::new();
    }
    merged_dyld_fallback_dirs(
        dyld_fallback_inherited(spawn_env_pairs(opts).as_deref()),
        &opts.exec_dyld_fallback,
    )
}

/// Concatenate `inherited` + `dirs` into one
/// `DYLD_FALLBACK_LIBRARY_PATH` spelling — the derived fallback extends
/// the inherited search list instead of replacing it. `split_paths`
/// decomposes the inherited list on the platform separator; its empty
/// elements (a `::` gap in the spelling) are dropped — a search-path
/// empty entry reads as cwd. `join_paths` re-assembles the survivors,
/// so no literal separator is written here.
fn merged_dyld_fallback(inherited: Option<OsString>, dirs: &[PathBuf]) -> Option<OsString> {
    let parts = merged_dyld_fallback_dirs(inherited, dirs);
    if parts.is_empty() {
        return None;
    }
    std::env::join_paths(&parts).ok()
}

fn merged_dyld_fallback_dirs(inherited: Option<OsString>, dirs: &[PathBuf]) -> Vec<PathBuf> {
    let mut parts: Vec<PathBuf> = Vec::new();
    if let Some(v) = inherited.filter(|v| !v.is_empty()) {
        parts.extend(std::env::split_paths(&v).filter(|p| !p.as_os_str().is_empty()));
    }
    let has_inherited = !parts.is_empty();
    // A dir itself containing the list separator cannot join a path
    // list — exclude it alone rather than let `join_paths` discard the
    // entire fallback for one unusable entry.
    parts.extend(
        dirs.iter()
            .filter(|d| std::env::join_paths([d]).is_ok())
            .cloned(),
    );
    // Setting the var replaces dyld's built-in fallback list entirely —
    // with no usable inherited entries the platform defaults are
    // re-appended after the derived dirs so the relocated exe keeps
    // them. They are appended even when an environment restriction
    // dropped the parent's value: the defaults are platform constants,
    // not the removed spelling.
    if !has_inherited {
        parts.extend(DYLD_FALLBACK_DIRS.iter().map(PathBuf::from));
    }
    parts
}

/// Apply the [`SpawnOptions`] environment to a synchronous command —
/// [`unotify-run`'s supervised spawn](crate::warden::unotify) is the only
/// caller; other `std::process::Command` spawns keep the no-env contract.
///
/// `None` (inherit parent) leaves the command untouched: no `env_clear`.
#[cfg(target_os = "linux")]
pub(crate) fn apply_spawn_env_sync(cmd: &mut std::process::Command, opts: &SpawnOptions) {
    if let Some(pairs) = spawn_env_pairs(opts) {
        cmd.env_clear();
        for (key, value) in pairs {
            cmd.env(key, value);
        }
    }
}

/// The `defaults.environment` allowlist diagnosis: for each consulted
/// name, whether the parent environment defined it — and, when the
/// value reads as a single absolute path, whether that path exists.
/// The report carries **names only** — a variable's value, including
/// the checked path spelling, never enters it. Nothing here gates the
/// launch: a missing name or a dangling path is an observation, never
/// a refusal (D-8).
///
/// `present` and `missing` partition the consulted allowlist;
/// `path_missing` is a subset of `present` — the variable is set, its
/// value just names a path with nothing behind it.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct EnvContractReport {
    /// Allowlisted names the parent environment defines — copied into
    /// the child's restricted environment.
    pub present: Vec<String>,
    /// Allowlisted names the parent environment does not define — they
    /// stay unset in the child.
    pub missing: Vec<String>,
    /// Present names whose value is a single absolute path with no
    /// filesystem object behind it — the variable reaches the child;
    /// the path may not.
    pub path_missing: Vec<String>,
}

impl EnvContractReport {
    /// The deduplicated count of allowlist names the contract actually
    /// consulted — `present` + `missing` partition that set
    /// (`path_missing` is a subset of `present`). Plan and observation
    /// text report the "N allowlisted name(s)" count from this, so the
    /// numbers always reconcile with `describe()` even when the
    /// declared list carries duplicates or pair-unsafe spellings.
    pub(crate) fn consulted(&self) -> usize {
        self.present.len() + self.missing.len()
    }

    /// `"K present, M missing"`, plus `(missing: A, B; path missing: C)`
    /// when either list is non-empty — the allowlist diagnosis the
    /// `launch.env` plan reason and launch-report observation share.
    /// Names only; a value never enters this string. Names render
    /// percent-encoded (the `env_missing=` audit-token convention):
    /// ordinary env names are all-unreserved and pass through verbatim,
    /// while a legal-but-exotic name — the validator only forbids
    /// `=`/NUL — cannot smuggle a comma that reads as a second list
    /// member or a `; path missing:` fragment that forges structure.
    pub(crate) fn describe(&self) -> String {
        let mut out = format!(
            "{} present, {} missing",
            self.present.len(),
            self.missing.len()
        );
        let mut notes = Vec::new();
        if !self.missing.is_empty() {
            notes.push(format!("missing: {}", encode_name_list(&self.missing)));
        }
        if !self.path_missing.is_empty() {
            notes.push(format!(
                "path missing: {}",
                encode_name_list(&self.path_missing)
            ));
        }
        if !notes.is_empty() {
            out.push_str(&format!(" ({})", notes.join("; ")));
        }
        out
    }

    /// The stderr warnings this contract produces — one line per gap
    /// class, names only, percent-encoded (terminal-safe by
    /// construction, and the same spelling [`describe`] and the
    /// `env_missing=` audit token carry). `run`/`mcp-secure-runner`
    /// emit them pre-spawn through [`warn_env_allowlist_gaps`]; the PoC
    /// launch front-ends call the same helper so the diagnosis is not a
    /// `run`-only surface.
    pub(crate) fn stderr_warnings(&self) -> Vec<String> {
        let mut out = Vec::new();
        if !self.missing.is_empty() {
            out.push(format!(
                "warning: allowlisted environment variable(s) not set in the \
                 parent environment: {}",
                encode_name_list(&self.missing)
            ));
        }
        if !self.path_missing.is_empty() {
            out.push(format!(
                "warning: allowlisted environment variable(s) whose value names \
                 a path that does not exist: {}",
                encode_name_list(&self.path_missing)
            ));
        }
        out
    }

    /// Print [`Self::stderr_warnings`] to stderr.
    pub(crate) fn emit_stderr_warnings(&self) {
        for w in self.stderr_warnings() {
            eprintln!("{w}");
        }
    }
}

/// Join `names` with `", "` after percent-encoding each — the
/// `env_missing=` audit-token convention shared by [`EnvContractReport::describe`]
/// and the stderr warnings, so the same name renders identically on
/// every surface and a comma inside a name cannot read as a second
/// list member. Ordinary env names are all-unreserved and pass through
/// verbatim.
fn encode_name_list(names: &[String]) -> String {
    names
        .iter()
        .map(|n| crate::audit_log::encode_audit_field_value(n))
        .collect::<Vec<_>>()
        .join(", ")
}

/// The allowlist diagnosis for `opts` — `Some` only when
/// `restrict_environment` consults a non-empty `allowed_names`; an
/// inherited, base-set-only, or tmpdir-only environment has no
/// allowlist to report on (matching the plan wording where an empty
/// `allow` reads "restricted to the base set" with no contract
/// summary). Each call re-reads the parent environment through
/// [`consult_allowlist`] — the same allowlist pass the env block is
/// built from, run again here — so the report is a snapshot at call
/// time: `plan` and `run` can be different processes with different
/// parents, and each surface reports the snapshot it observed.
pub(crate) fn env_contract_report(opts: &SpawnOptions) -> Option<EnvContractReport> {
    (opts.restrict_environment && !opts.allowed_names.is_empty())
        .then(|| consult_allowlist(&opts.allowed_names).1)
}

/// Compute `opts`' allowlist diagnosis and emit its stderr warnings —
/// one line per gap class, names only, sanitized for the terminal.
/// Every launch front-end calls this where it assembles the spawn env,
/// so the diagnosis is uniform across `run`, `mcp-secure-runner`, and
/// the PoC surfaces. Returns the report so a caller that also records
/// the diagnosis (`server.connected` details) reuses the same snapshot.
/// Silent when no allowlist is consulted or nothing is missing.
pub(crate) fn warn_env_allowlist_gaps(opts: &SpawnOptions) -> Option<EnvContractReport> {
    let report = env_contract_report(opts);
    if let Some(c) = &report {
        c.emit_stderr_warnings();
    }
    report
}

/// Whether [`spawn_env_pairs`] produces an env block for `opts` — the
/// `Option`'s cheap predicate, for callers that need the boolean only.
/// The full build runs the allowlist pass (a parent-env read plus a
/// `metadata()` stat per path-valued name); a yes/no question must not
/// pay for it.
pub(crate) fn env_block_applies(opts: &SpawnOptions) -> bool {
    opts.restrict_environment || opts.tmpdir.is_some()
}

/// Environment entries applied to a sandboxed child.
///
/// `None` means inherit the parent environment (and do not override TMPDIR).
/// `Some` is the complete environment block: restricted allow-list, or a
/// snapshot of the parent with TMPDIR/TMP/TEMP overridden.
pub(crate) fn spawn_env_pairs(opts: &SpawnOptions) -> Option<Vec<(OsString, OsString)>> {
    if !env_block_applies(opts) {
        return None;
    }
    let mut pairs = if opts.restrict_environment {
        restricted_base_env(&opts.allowed_names).0
    } else {
        std::env::vars_os().collect()
    };
    if let Some(ref tmp) = opts.tmpdir {
        let tmp = tmp.as_os_str().to_os_string();
        upsert_env(&mut pairs, OsString::from("TMPDIR"), tmp.clone());
        upsert_env(&mut pairs, OsString::from("TMP"), tmp.clone());
        upsert_env(&mut pairs, OsString::from("TEMP"), tmp);
    }
    Some(pairs)
}

fn restricted_base_env(allowed_names: &[String]) -> (Vec<(OsString, OsString)>, EnvContractReport) {
    let mut pairs = Vec::new();
    if let Some(path) = std::env::var_os("PATH") {
        pairs.push((OsString::from("PATH"), path));
    }
    #[cfg(windows)]
    {
        // LOCALAPPDATA is load-bearing, not cosmetic: CreateProcessW fails
        // with ERROR_ENVVAR_NOT_FOUND when a SECURITY_CAPABILITIES
        // (AppContainer) child gets an environment block without it — the
        // container-private profile path is derived from it.
        for key in [
            "SYSTEMROOT",
            "WINDIR",
            "PATHEXT",
            "COMSPEC",
            "SYSTEMDRIVE",
            "LOCALAPPDATA",
        ] {
            if let Some(val) = std::env::var_os(key) {
                upsert_env(&mut pairs, OsString::from(key), val);
            }
        }
    }
    let (allow_pairs, report) = consult_allowlist(allowed_names);
    for (key, val) in allow_pairs {
        upsert_env(&mut pairs, key, val);
    }
    (pairs, report)
}

/// The allowlist pass shared by the restricted env block and the
/// launch diagnosis: each pair-safe listed name is looked up once in
/// the parent environment — present names yield a `(key, value)` pair
/// for the block, absent names land in the report's `missing`, and a
/// present name whose value reads as a single absolute path with
/// nothing behind it lands in `path_missing`.
/// Names that cannot form a `KEY=value` pair are skipped — the policy
/// validator rejects them at load, so this only guards programmatic
/// SpawnOptions misuse (var_os would panic on an empty/`=`/NUL name
/// otherwise).
/// `env_key_eq` on the dedupe keeps the report consistent with the
/// env block on Windows, where "Path"/"PATH" resolve to the same
/// variable — the diagnosis counts the consulted names exactly as
/// often as the block writes them.
fn consult_allowlist(allowed_names: &[String]) -> (Vec<(OsString, OsString)>, EnvContractReport) {
    let mut pairs = Vec::new();
    let mut report = EnvContractReport::default();
    let already = |list: &[String], name: &str| {
        list.iter()
            .any(|n| env_key_eq(OsStr::new(n), OsStr::new(name)))
    };
    for name in allowed_names {
        if name.is_empty() || name.contains('=') || name.contains('\0') {
            continue;
        }
        let key = OsString::from(name);
        if let Some(val) = std::env::var_os(&key) {
            if !already(&report.present, name) {
                report.present.push(name.clone());
                // The path check applies to every allowlisted name, but
                // only when the value reads as one absolute path — a
                // PATH-list spelling or a non-path value has nothing to
                // stat (PR-33: the checked path itself is never recorded).
                if single_absolute_path(&val) && path_unresolvable(&val) {
                    report.path_missing.push(name.clone());
                }
            }
            upsert_env(&mut pairs, key, val);
        } else if !already(&report.missing, name) {
            report.missing.push(name.clone());
        }
    }
    (pairs, report)
}

/// True when `value` reads as exactly one absolute path — a PATH-list
/// spelling (`a:b` / `a;b` splits into several `split_paths` entries)
/// or a relative/bare value is not a path claim the diagnosis can
/// check, so those stay unreported.
fn single_absolute_path(value: &OsStr) -> bool {
    !value.is_empty()
        && std::env::split_paths(value).nth(1).is_none()
        && std::path::Path::new(value).is_absolute()
}

/// True when `metadata` fails because nothing can exist at `path` —
/// `NotFound` (ENOENT; a dangling symlink included) or `NotADirectory`
/// (a non-directory component mid-path). Other failures — EACCES and
/// the like — mean the check could not decide, not that the path is
/// absent; the name stays out of `path_missing` rather than reporting
/// an accessible-or-not guess as a missing path.
fn path_unresolvable(path: &OsStr) -> bool {
    match std::fs::metadata(path) {
        Err(e) => matches!(
            e.kind(),
            std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory
        ),
        Ok(_) => false,
    }
}

fn env_key_eq(a: &OsStr, b: &OsStr) -> bool {
    #[cfg(windows)]
    {
        a.to_string_lossy()
            .eq_ignore_ascii_case(&b.to_string_lossy())
    }
    #[cfg(not(windows))]
    {
        a == b
    }
}

fn upsert_env(pairs: &mut Vec<(OsString, OsString)>, key: OsString, value: OsString) {
    if let Some(existing) = pairs.iter_mut().find(|(k, _)| env_key_eq(k, &key)) {
        existing.0 = key;
        existing.1 = value;
        return;
    }
    pairs.push((key, value));
}

#[cfg(test)]
pub(crate) fn lock_process_env() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn restricted_env_omits_parent_sentinel_and_sets_tmpdir() {
        let _env = lock_process_env();
        let sentinel = "MCP_WRIT_ENV_CONTRACT_SENTINEL";
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe {
            std::env::set_var(sentinel, "inherited");
        }
        let tmp_fixture = crate::testutil::real_tempdir().expect("tempdir");
        let tmp = tmp_fixture.path().to_path_buf();
        let opts = SpawnOptions {
            restrict_environment: true,
            allowed_names: Vec::new(),
            tmpdir: Some(tmp.clone()),
            ..Default::default()
        };
        let pairs = spawn_env_pairs(&opts).expect("restricted env is explicit");
        assert!(
            pairs
                .iter()
                .all(|(k, _)| { !k.to_string_lossy().eq_ignore_ascii_case(sentinel) }),
            "restricted env must not copy arbitrary parent vars: {pairs:?}"
        );
        for key in ["TMPDIR", "TMP", "TEMP"] {
            let found = pairs
                .iter()
                .find(|(k, _)| k.to_string_lossy().eq_ignore_ascii_case(key));
            assert_eq!(
                found.map(|(_, v)| v.as_os_str()),
                Some(tmp.as_os_str()),
                "{key} missing or wrong in {pairs:?}"
            );
        }
        let inherited = spawn_env_pairs(&SpawnOptions::default());
        assert!(inherited.is_none(), "default spawn inherits parent env");

        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe {
            std::env::set_var("MCP_WRIT_ENV_INHERIT_SENTINEL", "keep-me");
        }
        let inherit_opts = SpawnOptions {
            restrict_environment: false,
            allowed_names: Vec::new(),
            tmpdir: Some(tmp.clone()),
            ..Default::default()
        };
        let inherited_pairs =
            spawn_env_pairs(&inherit_opts).expect("tmpdir override keeps parent env");
        assert!(
            inherited_pairs.iter().any(|(k, v)| {
                k.to_string_lossy() == "MCP_WRIT_ENV_INHERIT_SENTINEL"
                    && v.to_string_lossy() == "keep-me"
            }),
            "restrict_environment=false must keep parent vars: {inherited_pairs:?}"
        );
        for key in ["TMPDIR", "TMP", "TEMP"] {
            let found = inherited_pairs
                .iter()
                .find(|(k, _)| k.to_string_lossy().eq_ignore_ascii_case(key));
            assert_eq!(
                found.map(|(_, v)| v.as_os_str()),
                Some(tmp.as_os_str()),
                "{key} missing or wrong in inherited tmpdir override: {inherited_pairs:?}"
            );
        }
    }

    /// Policy `defaults.environment`: the allowlist is copied from the parent,
    /// unlisted parent variables are dropped, and PATH stays.
    #[test]
    fn restricted_env_copies_allowed_names_and_keeps_path() {
        let _env = lock_process_env();
        let keep = "MCP_WRIT_ENV_ALLOWLIST_KEEP";
        let drop = "MCP_WRIT_ENV_ALLOWLIST_DROP";
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe {
            std::env::set_var(keep, "keep-value");
            std::env::set_var(drop, "drop-value");
        }
        let opts = SpawnOptions {
            restrict_environment: true,
            allowed_names: vec![keep.to_string()],
            tmpdir: None,
            ..Default::default()
        };
        let pairs = spawn_env_pairs(&opts).expect("restricted env is explicit");
        assert!(
            pairs
                .iter()
                .any(|(k, v)| k == OsStr::new(keep) && v == OsStr::new("keep-value")),
            "allowed name must be copied from the parent: {pairs:?}"
        );
        assert!(
            pairs.iter().all(|(k, _)| k != OsStr::new(drop)),
            "unlisted parent var must be dropped: {pairs:?}"
        );
        assert!(
            pairs.iter().any(|(k, _)| k == OsStr::new("PATH")),
            "PATH must remain in the restricted env: {pairs:?}"
        );
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe {
            std::env::remove_var(keep);
            std::env::remove_var(drop);
        }
    }

    /// A listed name missing from the parent is not an error and stays unset.
    #[test]
    fn restricted_env_missing_allowed_name_stays_unset() {
        let _env = lock_process_env();
        let missing = "MCP_WRIT_ENV_ALLOWLIST_MISSING";
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe {
            std::env::remove_var(missing);
        }
        let opts = SpawnOptions {
            restrict_environment: true,
            allowed_names: vec![missing.to_string()],
            tmpdir: None,
            ..Default::default()
        };
        let pairs = spawn_env_pairs(&opts).expect("restricted env is explicit");
        assert!(
            pairs.iter().all(|(k, _)| k != OsStr::new(missing)),
            "absent parent var must not appear in the child env: {pairs:?}"
        );
    }

    /// `allowed_names` alone does not restrict: without `restrict_environment`
    /// the parent environment is inherited unchanged.
    #[test]
    fn allowed_names_do_not_restrict_without_flag() {
        let _env = lock_process_env();
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe {
            std::env::set_var("MCP_WRIT_ENV_ALLOWLIST_INHERIT", "present");
        }
        let opts = SpawnOptions {
            restrict_environment: false,
            allowed_names: vec!["MCP_WRIT_ENV_ALLOWLIST_INHERIT".to_string()],
            tmpdir: None,
            ..Default::default()
        };
        assert!(
            spawn_env_pairs(&opts).is_none(),
            "allowed_names without restrict_environment must inherit the parent env"
        );
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe {
            std::env::remove_var("MCP_WRIT_ENV_ALLOWLIST_INHERIT");
        }
    }

    /// `exec_dyld_fallback` merges onto an inherited
    /// `DYLD_FALLBACK_LIBRARY_PATH` instead of replacing it; a
    /// restriction-dropped name stays dropped. Unix-only: the var and
    /// its `:`-joined values are a dyld (macOS) concept — Windows
    /// `split_paths` would treat `:` as path content, not a separator.
    #[cfg(unix)]
    #[test]
    fn dyld_fallback_appends_to_inherited_and_respects_restriction() {
        let _env = lock_process_env();
        let var = "DYLD_FALLBACK_LIBRARY_PATH";
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe {
            std::env::set_var(var, "/inherited/lib:/opt/extra");
        }
        let derived = vec![PathBuf::from("/real/lib"), PathBuf::from("/real2/lib")];
        // Decode merged values back through split_paths — the platform
        // separator (`:` / `;`) must not leak into the assertions.
        let parts_of = |v: &OsString| -> Vec<String> {
            std::env::split_paths(v)
                .map(|p| p.to_string_lossy().into_owned())
                .collect()
        };

        // Inherit mode (no env block): parent value + derived.
        let merged =
            merged_dyld_fallback(dyld_fallback_inherited(None), &derived).expect("merged fallback");
        assert_eq!(
            parts_of(&merged),
            vec![
                "/inherited/lib".to_string(),
                "/opt/extra".to_string(),
                "/real/lib".to_string(),
                "/real2/lib".to_string(),
            ],
            "inherited dirs must lead, derived append; got {}",
            merged.to_string_lossy()
        );

        // Restricted + allowlisted: the copied parent value is kept.
        let pairs = vec![
            (OsString::from("PATH"), OsString::from("/bin")),
            (OsString::from(var), OsString::from("/allowed/lib")),
        ];
        let merged = merged_dyld_fallback(dyld_fallback_inherited(Some(&pairs)), &derived).unwrap();
        assert_eq!(
            parts_of(&merged),
            vec![
                "/allowed/lib".to_string(),
                "/real/lib".to_string(),
                "/real2/lib".to_string(),
            ],
            "allowlisted parent dirs must lead; got {}",
            merged.to_string_lossy()
        );

        // Restricted without the name: derived dirs + the platform
        // defaults the var now stands in for — nothing the policy
        // excluded is restored.
        let merged =
            merged_dyld_fallback(dyld_fallback_inherited(Some(&pairs[..1])), &derived).unwrap();
        assert_eq!(
            parts_of(&merged),
            vec![
                "/real/lib".to_string(),
                "/real2/lib".to_string(),
                "/usr/local/lib".to_string(),
                "/usr/lib".to_string(),
            ],
            "restriction must not restore excluded dirs; got {}",
            merged.to_string_lossy()
        );

        // An inherited-but-empty spelling behaves like absent — same
        // derived + defaults composition.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe {
            std::env::set_var(var, "");
        }
        let merged = merged_dyld_fallback(dyld_fallback_inherited(None), &derived).unwrap();
        assert_eq!(
            parts_of(&merged),
            vec![
                "/real/lib".to_string(),
                "/real2/lib".to_string(),
                "/usr/local/lib".to_string(),
                "/usr/lib".to_string(),
            ],
            "empty inherited value must still yield platform defaults; got {}",
            merged.to_string_lossy()
        );
        // Inherited spellings with empty elements (`::` gaps, a leading
        // or trailing `:`) must not carry cwd-reading empty entries into
        // the merged list.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe {
            std::env::set_var(var, ":lead::mid:/trail:");
        }
        let merged = merged_dyld_fallback(dyld_fallback_inherited(None), &derived).unwrap();
        assert_eq!(
            parts_of(&merged),
            vec![
                "lead".to_string(),
                "mid".to_string(),
                "/trail".to_string(),
                "/real/lib".to_string(),
                "/real2/lib".to_string(),
            ],
            "empty inherited entries must be dropped; got {}",
            merged.to_string_lossy()
        );

        // A derived dir itself containing the separator is unusable in a
        // path list — excluded individually, the rest still join.
        let derived_with_bad = vec![
            PathBuf::from("/real/lib"),
            PathBuf::from("/bad:dir/lib"),
            PathBuf::from("/real2/lib"),
        ];
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe {
            std::env::remove_var(var);
        }
        let merged =
            merged_dyld_fallback(dyld_fallback_inherited(None), &derived_with_bad).unwrap();
        assert_eq!(
            parts_of(&merged),
            vec![
                "/real/lib".to_string(),
                "/real2/lib".to_string(),
                "/usr/local/lib".to_string(),
                "/usr/lib".to_string(),
            ],
            "separator-containing dir must drop alone; got {}",
            merged.to_string_lossy()
        );
    }

    /// Duplicate allowlist entries collapse to a single env pair.
    #[test]
    fn restricted_env_allowed_names_dedupe() {
        let _env = lock_process_env();
        let name = "MCP_WRIT_ENV_ALLOWLIST_DUP";
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe {
            std::env::set_var(name, "v1");
        }
        let opts = SpawnOptions {
            restrict_environment: true,
            allowed_names: vec![name.to_string(), name.to_string()],
            tmpdir: None,
            ..Default::default()
        };
        let pairs = spawn_env_pairs(&opts).expect("restricted env is explicit");
        let count = pairs
            .iter()
            .filter(|(k, _)| k.to_string_lossy().eq_ignore_ascii_case(name))
            .count();
        assert_eq!(count, 1, "duplicate allow names must dedupe: {pairs:?}");
        // The report dedupes on the same key equality — the diagnosis
        // never counts a consulted name more often than the block writes
        // it.
        let report = env_contract_report(&opts).expect("restricted env is consulted");
        assert_eq!(
            report.present,
            vec![name.to_string()],
            "the report dedupes the same way the env block does: {report:?}"
        );
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe {
            std::env::remove_var(name);
        }
    }

    /// PR-33 — the contract report partitions the allowlist into
    /// present/missing by name only: values never enter it, and a
    /// single-absolute-path value that names nothing on disk lands in
    /// `path_missing` *while staying* `present`.
    #[test]
    fn env_contract_report_partitions_names_without_values() {
        let _env = lock_process_env();
        let present = "MCP_WRIT_ENV_CONTRACT_PRESENT";
        let missing = "MCP_WRIT_ENV_CONTRACT_MISSING";
        let path_gone = "MCP_WRIT_ENV_CONTRACT_PATH_GONE";
        let list = "MCP_WRIT_ENV_CONTRACT_LIST";
        let dir = crate::testutil::real_tempdir().expect("tempdir");
        let gone = dir.path().join("mcp-writ-env-contract-no-such-file");
        assert!(!gone.exists(), "fixture path must not exist");
        let secret = "s3cr3t-value-that-must-not-appear";
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe {
            std::env::set_var(present, secret);
            std::env::remove_var(missing);
            std::env::set_var(path_gone, &gone);
            // A PATH-list spelling is not a single-path claim.
            std::env::set_var(list, std::env::join_paths([&gone, &gone]).unwrap());
        }
        let opts = SpawnOptions {
            restrict_environment: true,
            allowed_names: vec![
                present.to_string(),
                missing.to_string(),
                path_gone.to_string(),
                list.to_string(),
            ],
            tmpdir: None,
            ..Default::default()
        };
        let report = env_contract_report(&opts).expect("restricted env is consulted");
        assert_eq!(
            report.present,
            vec![present.to_string(), path_gone.to_string(), list.to_string()]
        );
        assert_eq!(report.missing, vec![missing.to_string()]);
        assert_eq!(report.path_missing, vec![path_gone.to_string()]);
        // The structure cannot hold a value — assert the rendered
        // diagnosis carries names only.
        let text = report.describe();
        assert!(
            !text.contains(secret) && !text.contains(gone.to_string_lossy().as_ref()),
            "report must carry names only, never values: {text}"
        );
        assert!(
            text.contains(missing) && text.contains(path_gone),
            "the diagnosis names the gaps: {text}"
        );
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe {
            std::env::remove_var(present);
            std::env::remove_var(path_gone);
            std::env::remove_var(list);
        }
    }

    /// `env_contract_report` is `None` when the allowlist is not
    /// consulted — an inherited parent environment has no contract.
    #[test]
    fn env_contract_report_none_without_restriction() {
        let _env = lock_process_env();
        let opts = SpawnOptions {
            restrict_environment: false,
            allowed_names: vec!["MCP_WRIT_ENV_ALLOWLIST_INHERIT".to_string()],
            tmpdir: None,
            ..Default::default()
        };
        assert!(env_contract_report(&opts).is_none());
    }

    /// A present name whose value is an existing absolute path is not a
    /// `path_missing` — only a dangling path is.
    #[test]
    fn env_contract_report_existing_path_is_not_path_missing() {
        let _env = lock_process_env();
        let name = "MCP_WRIT_ENV_CONTRACT_PATH_OK";
        let dir = crate::testutil::real_tempdir().expect("tempdir");
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe {
            std::env::set_var(name, dir.path());
        }
        let opts = SpawnOptions {
            restrict_environment: true,
            allowed_names: vec![name.to_string()],
            tmpdir: None,
            ..Default::default()
        };
        let report = env_contract_report(&opts).unwrap();
        assert_eq!(report.present, vec![name.to_string()]);
        assert!(report.path_missing.is_empty());
        assert!(report.missing.is_empty());
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe {
            std::env::remove_var(name);
        }
    }

    /// A present name whose value is a single absolute path beneath an
    /// existing *file* cannot resolve — `NotADirectory` classifies the
    /// same "nothing behind it" gap as `NotFound`.
    #[test]
    fn env_contract_report_path_under_a_file_is_path_missing() {
        let _env = lock_process_env();
        let name = "MCP_WRIT_ENV_CONTRACT_NOTDIR";
        let dir = crate::testutil::real_tempdir().expect("tempdir");
        let file = dir.path().join("mcp-writ-env-contract-file");
        std::fs::write(&file, b"x").expect("fixture file");
        let under_file = file.join("child");
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe {
            std::env::set_var(name, &under_file);
        }
        let opts = SpawnOptions {
            restrict_environment: true,
            allowed_names: vec![name.to_string()],
            tmpdir: None,
            ..Default::default()
        };
        let report = env_contract_report(&opts).unwrap();
        assert_eq!(report.present, vec![name.to_string()]);
        assert_eq!(
            report.path_missing,
            vec![name.to_string()],
            "a path with a non-directory component is unresolvable"
        );
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe {
            std::env::remove_var(name);
        }
    }

    /// `describe()` percent-encodes names so a legal-but-exotic
    /// allowlist spelling — the validator forbids only `=`/NUL —
    /// cannot smuggle a comma that reads as a second list member or a
    /// `; path missing:` fragment that forges structure.
    #[test]
    fn env_contract_describe_encodes_exotic_names() {
        let report = EnvContractReport {
            present: vec![],
            missing: vec![
                "A,B".to_string(),
                "X) (missing: FORGED".to_string(),
                "PLAIN_NAME".to_string(),
            ],
            path_missing: vec![],
        };
        let text = report.describe();
        assert!(
            text.contains("missing: A%2CB, X%29%20%28missing%3A%20FORGED, PLAIN_NAME"),
            "exotic names are encoded, ordinary names pass through: {text}"
        );
        assert!(
            !text.contains("(missing: FORGED"),
            "the forged fragment must not render: {text}"
        );
    }

    /// One stderr line per non-empty gap class — names only, sanitized.
    #[test]
    fn env_contract_stderr_warnings_cover_both_gap_classes() {
        let none = EnvContractReport::default();
        assert!(none.stderr_warnings().is_empty());
        let report = EnvContractReport {
            present: vec![],
            missing: vec!["GONE".to_string()],
            path_missing: vec!["DANGLING".to_string()],
        };
        let warnings = report.stderr_warnings();
        assert_eq!(warnings.len(), 2);
        assert!(
            warnings[0].contains("not set in the parent environment: GONE"),
            "{warnings:?}"
        );
        assert!(
            warnings[1].contains("a path that does not exist: DANGLING"),
            "{warnings:?}"
        );
        // A comma inside a name is percent-encoded — it cannot read as
        // a second list member.
        let exotic = EnvContractReport {
            present: vec![],
            missing: vec!["A,B".to_string()],
            path_missing: vec![],
        };
        let warnings = exotic.stderr_warnings();
        assert!(warnings[0].ends_with("environment: A%2CB"), "{warnings:?}");
    }

    /// `env_block_applies` is the cheap predicate `spawn_env_pairs`'s
    /// `Option` stands on — they must agree for every combination.
    #[test]
    fn env_block_applies_matches_spawn_env_pairs_presence() {
        let _env = lock_process_env();
        let fixture = crate::testutil::real_tempdir().expect("tempdir");
        for restrict in [false, true] {
            for tmpdir in [None, Some(fixture.path().to_path_buf())] {
                let opts = SpawnOptions {
                    restrict_environment: restrict,
                    tmpdir: tmpdir.clone(),
                    ..Default::default()
                };
                assert_eq!(
                    env_block_applies(&opts),
                    spawn_env_pairs(&opts).is_some(),
                    "predicate must agree with the Option: {opts:?}"
                );
            }
        }
    }
}
