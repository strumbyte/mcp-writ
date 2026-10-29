//! Real-server fixture layout: the `tests/fixtures/real_servers`
//! directory, runtime syscall lists, interpreter grant dirs, and the
//! host `defaults` KDL assembled for real-server policies.

use std::path::{Path, PathBuf};

use super::paths::plain_spelling;

// ─── real-server fixture layout ──────────────────────────────────────────

/// Root of the pinned real-server fixtures (`tests/fixtures/real_servers`).
/// `MCP_WRIT_REAL_SERVERS_DIR` overrides it so the missing-prerequisite
/// path is exercisable without touching the checkout.
pub fn real_servers_dir() -> PathBuf {
    if let Some(dir) = std::env::var_os("MCP_WRIT_REAL_SERVERS_DIR") {
        return PathBuf::from(dir);
    }
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/real_servers")
}

/// Read the syscall allowlist out of `examples/policies/runtime/<name>.kdl`
/// so the host `defaults` block and the runtime file share one source —
/// the observed lists are not duplicated in test code.
fn runtime_syscalls(runtime: &str) -> Vec<String> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("examples/policies/runtime")
        .join(format!("{runtime}.kdl"));
    let text =
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    let mut names = Vec::new();
    let mut in_syscalls = false;
    for line in text.lines() {
        let t = line.trim();
        if t.starts_with("//") {
            continue;
        }
        if t.starts_with("syscalls") {
            in_syscalls = true;
            continue;
        }
        if in_syscalls {
            if t.starts_with('}') {
                break;
            }
            let mut chars = t.chars();
            loop {
                match chars.next() {
                    Some('"') => {
                        let name: String = chars.by_ref().take_while(|&c| c != '"').collect();
                        if !name.is_empty() {
                            names.push(name);
                        }
                    }
                    Some(_) => continue,
                    None => break,
                }
            }
        }
    }
    names
}

fn push_unique(dirs: &mut Vec<PathBuf>, p: PathBuf) {
    // Strip a verbatim prefix: the Windows DACL grant and `exists()`
    // checks in the sandbox path need a regular path spelling.
    let p = plain_spelling(&p);
    if !dirs.contains(&p) {
        dirs.push(p);
    }
}

/// The `home =` line of a `pyvenv.cfg` names the base interpreter prefix —
/// needed on Windows where `Scripts\python.exe` is a copy, not a symlink,
/// so canonicalization alone does not reach the base installation.
fn pyvenv_home(venv_dir: &Path) -> Option<PathBuf> {
    let text = std::fs::read_to_string(venv_dir.join("pyvenv.cfg")).ok()?;
    for line in text.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("home")
            && let Some(value) = rest.trim_start().strip_prefix('=')
        {
            return Some(PathBuf::from(value.trim()));
        }
    }
    None
}

/// Directories a spawned executable needs read-granted under a
/// deny-default sandbox: the executable's own directory, that directory's
/// parent (the install prefix), and the package-store root when the exe
/// sits under a `<prefix>/Cellar/<keg>/<ver>` keg — a Homebrew binary
/// links sibling kegs' shared libraries through `<prefix>/opt/*`, which
/// the two-level prefix rule never reaches.
pub fn exe_read_grant_dirs(exe: &Path) -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    if let Some(parent) = exe.parent() {
        dirs.push(parent.to_path_buf());
        // The install prefix stops below the filesystem root: granting
        // `/` itself would read-open everything under deny-default.
        if let Some(prefix) = parent.parent()
            && prefix.parent().is_some()
        {
            dirs.push(prefix.to_path_buf());
        }
    }
    for anc in exe.ancestors() {
        if anc.file_name().is_some_and(|n| n == "Cellar")
            && let Some(prefix) = anc.parent()
        {
            dirs.push(prefix.to_path_buf());
        }
    }
    dirs
}

/// Build the host-specific `defaults { ... }` block for a real-server run.
///
/// `argv0` is the child argv[0]. The block grants, read-only:
/// - the directory containing `argv0` and its parent (the install prefix)
/// - the same for the resolved executable (`PATH` lookup + canonicalize,
///   which follows a Unix venv's `bin/python` symlink to the base image)
/// - the package-store root (`<prefix>/Cellar`'s parent) when the resolved
///   exe lives in a keg — a Homebrew interpreter links sibling kegs'
///   dylibs under `<prefix>/opt/*`
/// - for a Windows venv, the base interpreter prefix from `pyvenv.cfg`
/// - the pinned fixture package trees (`node_modules`, `.venv`)
/// - platform runtime dirs (Linux shared-library/config roots; macOS adds
///   the fixed system paths its SBPL profile also grants)
///
/// On Linux the `syscalls` block carries the observed baseline read from
/// `examples/policies/runtime/{node,python}.kdl` — single source, no
/// duplicated constants.
pub fn host_defaults_kdl(argv0: &str) -> String {
    let mut read_dirs: Vec<PathBuf> = Vec::new();

    // The path as given — covers a venv's bin/Scripts and the `.venv` root.
    let given = Path::new(argv0);
    if given.is_absolute() || argv0.contains(['/', '\\']) {
        for d in exe_read_grant_dirs(given) {
            push_unique(&mut read_dirs, d);
        }
    }
    if let Ok(resolved) = mcp_writ::workload::resolve_command_path(argv0) {
        for d in exe_read_grant_dirs(&resolved) {
            push_unique(&mut read_dirs, d);
        }
        // A Windows venv `Scripts\python.exe` is not a symlink; recover the
        // base interpreter prefix from pyvenv.cfg.
        for base in [given, resolved.as_path()] {
            for anc in base.ancestors() {
                if anc.file_name().is_some_and(|n| n == ".venv")
                    && let Some(home) = pyvenv_home(anc)
                {
                    if let Some(prefix) = home.parent() {
                        push_unique(&mut read_dirs, prefix.to_path_buf());
                    }
                    push_unique(&mut read_dirs, home);
                }
            }
        }
    }
    // The pinned package trees the server loads from (`node` also carries
    // the Windows realpath stub preloaded via `--require`).
    for sub in ["node", "python/.venv"] {
        let d = real_servers_dir().join(sub);
        if d.exists() {
            push_unique(&mut read_dirs, d);
        }
    }
    // Platform runtime dirs the interpreters touch.
    #[cfg(target_os = "linux")]
    for dir in [
        "/usr/lib",
        "/usr/bin",
        "/lib",
        "/lib64",
        "/usr/local/lib",
        "/etc/ssl",
        "/etc",
        "/proc",
        "/dev",
        // CPython zoneinfo.TZPATH: ZoneInfo searches the host TZDB before
        // falling back to the `tzdata` package, and a *denied* lookup path
        // aborts the search (only ENOENT falls through) — a tz-aware server
        // needs the real directories readable, not just the venv copy.
        "/usr/share/zoneinfo",
        "/usr/lib/zoneinfo",
        "/usr/share/lib/zoneinfo",
        "/etc/zoneinfo",
    ] {
        if Path::new(dir).exists() {
            push_unique(&mut read_dirs, PathBuf::from(dir));
        }
    }
    #[cfg(target_os = "macos")]
    for dir in [
        "/usr/lib",
        "/System/Library",
        "/usr/share",
        "/bin",
        "/sbin",
        "/usr/bin",
        "/usr/sbin",
        "/usr/libexec",
        "/private/etc/ssl",
    ] {
        if Path::new(dir).exists() {
            push_unique(&mut read_dirs, PathBuf::from(dir));
        }
    }

    let f = |p: &Path| p.to_string_lossy().replace('\\', "/");
    let mut out = String::from("defaults {\n    filesystem {\n");
    for dir in &read_dirs {
        // Literal directory paths only: Landlock covers the subtree, the
        // macOS SBPL emitter maps them to `subpath`, and the Windows DACL
        // grant skips nonexistent paths — a `/**` suffix never exists.
        out.push_str(&format!("        allow \"{}\" mode=\"read\"\n", f(dir)));
    }
    // Interpreters open /dev/null O_RDWR (libuv stream setup, Python
    // subprocess stdio): a read grant alone cannot satisfy the write half.
    #[cfg(target_os = "linux")]
    if Path::new("/dev/null").exists() {
        out.push_str("        allow \"/dev/null\" mode=\"write\"\n");
    }
    out.push_str("    }\n");

    #[cfg(target_os = "linux")]
    {
        let runtime = match mcp_writ::workload::interpreter_from_command(argv0) {
            Some(mcp_writ::workload::InterpreterKind::Node) => Some("node"),
            Some(mcp_writ::workload::InterpreterKind::Python) => Some("python"),
            _ => None,
        };
        if let Some(runtime) = runtime {
            let names = runtime_syscalls(runtime);
            assert!(
                !names.is_empty(),
                "examples/policies/runtime/{runtime}.kdl carries no syscall allowlist"
            );
            out.push_str("    syscalls {\n        allow");
            for name in &names {
                out.push_str(&format!(" \"{name}\""));
            }
            out.push_str("\n    }\n");
        }
    }
    out.push_str("}\n");
    out
}
