//! Capture `tools/list` snapshots from public MCP servers into the
//! manifest regression corpus at `tests/fixtures/manifest_corpus/`.
//!
//! For each server in [`SERVERS`] the tool launches the real package over
//! stdio, performs the MCP `2025-11-25` handshake, issues `tools/list`,
//! and writes the JSON-RPC response — pretty-printed — to
//! `<name>.tools-list.json`. `provenance.json` is refreshed with the
//! resolved package, pinned version, license, launch argv, and capture
//! date.
//!
//! Sources:
//! - `pinned`: the vendored installs under `tests/fixtures/real_servers/`
//!   (populate them first with `tests/fixtures/real_servers/setup.sh` /
//!   `setup.ps1`). The installed version is read back from the vendored
//!   package's own metadata and must match the spec pin.
//! - `npm`: integrity-locked `npm install` of the pinned version into a
//!   scratch dir under `target/manifest-corpus/` (kept on the data drive
//!   per `AGENTS.md` disk hygiene; removed after the run). The pin is
//!   written to a scratch `package.json`, `npm install
//!   --package-lock-only` mints a lockfile covering the whole resolved
//!   graph, and `npm ci --ignore-scripts` installs exactly the locked,
//!   integrity-verified tree — registry drift cannot substitute a
//!   different transitive dependency than what was resolved.
//! - `pypi`: ephemeral venv + integrity-locked install, same root. The
//!   pinned requirement is resolved once with `pip download
//!   --only-binary :all: --report`, every downloaded wheel is hashed
//!   (sha256), the locked set is written to `requirements.txt`, and
//!   `pip install --no-index --find-links --require-hashes` installs
//!   exactly those verified artifacts. Wheels only — an sdist's
//!   `setup.py` is unfixed registry code and is never executed.
//!
//! Execution: every captured server — vendored or ephemeral — runs
//! under the built `mcp-writ` binary with a deny-by-default policy
//! (read access enumerated to system/install roots — user profiles,
//! `/tmp`, and `/mnt` are simply not granted, so secret paths have no
//! grant to reach; exec everywhere; no writes; `deny host="*"`; empty
//! environment allowlist) when a guard binary is available at
//! `target/debug/mcp-writ` or `target/release/mcp-writ`, overridable
//! via `MCP_CORPUS_GUARD=<path>`. The spawned process also receives a
//! scrubbed environment (PATH + home/temp/system vars only) and an
//! empty per-server working directory, never the checkout. When no
//! guard exists (Windows binary under WSL, or binary not yet built)
//! the capture refuses unless `MCP_CORPUS_UNSAFE_HOST=1` explicitly
//! opts into running the registry package on the host.
//!
//! Requirements: `node` + `npm` on PATH for npm sources, a `venv`-capable
//! `python3` with pip >= 22.2 (or a Windows `py` launcher under WSL) for
//! pypi sources. Under WSL, Windows `node.exe`/`python.exe` fixtures run
//! through interop and path arguments are translated via `wslpath`.
//!
//! Usage:
//!   cargo run --example capture_manifest_corpus                # all
//!   cargo run --example capture_manifest_corpus -- fetch git   # named
//!
//! Positional arguments are exact `name` matches against the static
//! [`SERVERS`] allowlist — they select which predefined specs to
//! capture and are never forwarded to a spawned command line.

use sha2::Digest;
use std::collections::{HashMap, VecDeque};
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, ExitCode, Stdio};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const PROTOCOL_VERSION: &str = "2025-11-25";
const CLIENT_INFO: &str = r#"{"name":"mcp-writ-manifest-corpus","version":"0.1.0"}"#;
/// Slow starters (browser-tool servers load big dependency graphs) get
/// this whole budget; capture fails rather than writing a partial file.
const CAPTURE_TIMEOUT: Duration = Duration::from_secs(180);
/// Package installs (npm/pip/venv bootstrap) run outside the per-request
/// capture budget — a wedged install must still die eventually.
const INSTALL_TIMEOUT: Duration = Duration::from_secs(600);

fn repo_root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

fn corpus_dir() -> PathBuf {
    repo_root().join("tests/fixtures/manifest_corpus")
}

fn real_servers() -> PathBuf {
    repo_root().join("tests/fixtures/real_servers")
}

fn scratch_root() -> PathBuf {
    repo_root().join("target/manifest-corpus")
}

#[derive(Clone, Copy)]
enum Source {
    Pinned,
    Npm,
    Pypi,
}

impl Source {
    fn as_str(self) -> &'static str {
        match self {
            Self::Pinned => "pinned",
            Self::Npm => "npm",
            Self::Pypi => "pypi",
        }
    }
}

struct ServerSpec {
    name: &'static str,    // fixture file stem
    package: &'static str, // npm or PyPI package name
    version: &'static str, // pinned version
    license: &'static str, // SPDX identifier of the upstream project
    upstream: &'static str,
    source: Source,
    note: &'static str,
    args: &'static [&'static str],
}

const SERVERS: &[ServerSpec] = &[
    // Official reference servers — github.com/modelcontextprotocol/servers (MIT).
    ServerSpec {
        name: "filesystem",
        package: "@modelcontextprotocol/server-filesystem",
        version: "2026.8.31",
        license: "MIT",
        upstream: "https://github.com/modelcontextprotocol/servers",
        source: Source::Pinned,
        note: "",
        // One allowed dir is required at startup; tools/list does not
        // touch it.
        args: &["."],
    },
    ServerSpec {
        name: "memory",
        package: "@modelcontextprotocol/server-memory",
        version: "2026.8.31",
        license: "MIT",
        upstream: "https://github.com/modelcontextprotocol/servers",
        source: Source::Pinned,
        note: "",
        args: &[],
    },
    ServerSpec {
        name: "time",
        package: "mcp-server-time",
        version: "2026.8.18",
        license: "MIT",
        upstream: "https://github.com/modelcontextprotocol/servers",
        source: Source::Pinned,
        note: "",
        // The server embeds the detected local zone in its tool schemas;
        // pin it so the snapshot is host-independent.
        args: &["--local-timezone", "UTC"],
    },
    ServerSpec {
        name: "git",
        package: "mcp-server-git",
        version: "2026.8.18",
        license: "MIT",
        upstream: "https://github.com/modelcontextprotocol/servers",
        source: Source::Pinned,
        note: "",
        args: &["--repository", "."],
    },
    ServerSpec {
        name: "fetch",
        package: "mcp-server-fetch",
        version: "2026.10.10",
        license: "MIT",
        upstream: "https://github.com/modelcontextprotocol/servers",
        source: Source::Pypi,
        // 2026.8.18 carried no annotations; 2026.10.10 is the first
        // release that advertises the F-07 combination.
        note: "F-07 regression case: readOnlyHint + url key + openWorldHint.",
        args: &[],
    },
    ServerSpec {
        name: "everything",
        package: "@modelcontextprotocol/server-everything",
        version: "2026.8.31",
        license: "MIT",
        upstream: "https://github.com/modelcontextprotocol/servers",
        source: Source::Npm,
        note: "",
        args: &[],
    },
    ServerSpec {
        name: "sequential-thinking",
        package: "@modelcontextprotocol/server-sequential-thinking",
        version: "2026.8.31",
        license: "MIT",
        upstream: "https://github.com/modelcontextprotocol/servers",
        source: Source::Npm,
        note: "",
        args: &[],
    },
    // Widely used third-party servers.
    ServerSpec {
        name: "playwright",
        package: "@playwright/mcp",
        version: "0.0.83",
        license: "Apache-2.0",
        upstream: "https://github.com/microsoft/playwright-mcp",
        source: Source::Npm,
        note: "",
        args: &[],
    },
    ServerSpec {
        name: "chrome-devtools",
        package: "chrome-devtools-mcp",
        version: "1.11.0",
        license: "Apache-2.0",
        upstream: "https://github.com/ChromeDevTools/chrome-devtools-mcp",
        source: Source::Npm,
        note: "",
        args: &[],
    },
];

fn wsl() -> bool {
    static WSL: OnceLock<bool> = OnceLock::new();
    *WSL.get_or_init(|| {
        cfg!(target_os = "linux")
            && std::fs::read_to_string("/proc/sys/kernel/osrelease")
                .map(|s| s.to_lowercase().contains("microsoft"))
                .unwrap_or(false)
    })
}

/// True when `path` execs through WSL/Windows interop (.exe).
fn is_windows_binary(path: &Path) -> bool {
    wsl() && path.to_string_lossy().to_lowercase().ends_with(".exe")
}

/// Spell `p` for the child's address space: Windows binaries get a
/// `D:\...` spelling, native processes keep the POSIX spelling.
fn child_path(p: &Path, windows: bool) -> Result<String, String> {
    if !windows {
        return Ok(p.to_string_lossy().into_owned());
    }
    let out = Command::new("wslpath")
        .arg("-w")
        .arg(p)
        .output()
        .map_err(|e| format!("wslpath: {e}"))?;
    if !out.status.success() {
        return Err(format!("wslpath -w {} failed", p.display()));
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

fn is_executable(p: &Path) -> bool {
    if !p.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(p)
            .map(|m| m.permissions().mode() & 0o111 != 0)
            .unwrap_or(false)
    }
    #[cfg(not(unix))]
    {
        true
    }
}

fn which_one(name: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    let exts: Vec<String> = if cfg!(windows) {
        std::env::var("PATHEXT")
            .unwrap_or_else(|_| ".COM;.EXE;.BAT;.CMD".into())
            .split(';')
            .map(|s| s.to_string())
            .collect()
    } else {
        Vec::new()
    };
    for dir in std::env::split_paths(&path) {
        let cand = dir.join(name);
        if is_executable(&cand) {
            return Some(cand);
        }
        // On Windows a bare name matches each PATHEXT suffix too.
        for ext in &exts {
            let cand = dir.join(format!("{name}{ext}"));
            if is_executable(&cand) {
                return Some(cand);
            }
        }
    }
    None
}

fn which_any(names: &[&str]) -> Option<PathBuf> {
    names.iter().find_map(|n| which_one(n))
}

fn node_bin() -> Result<PathBuf, String> {
    which_any(&["node", "node.exe"])
        .ok_or_else(|| "node not found on PATH (needed for npm/pinned servers)".to_string())
}

/// Scrub `cmd`'s environment to the small set installers and captured
/// servers legitimately need. Registry-supplied code must never see the
/// developer's API keys, tokens, SSH agent state, or editor vars.
fn minimal_env(cmd: &mut Command) {
    const KEEP: &[&str] = &[
        "PATH",
        "HOME",
        "USERPROFILE",
        "APPDATA",
        "LOCALAPPDATA",
        "SystemRoot",
        "SystemDrive",
        "windir",
        "ComSpec",
        "TMPDIR",
        "TMP",
        "TEMP",
        "LANG",
        "LC_ALL",
        "WSLENV",
        "WSL_INTEROP",
    ];
    let saved: Vec<(std::ffi::OsString, std::ffi::OsString)> = KEEP
        .iter()
        .filter_map(|k| std::env::var_os(k).map(|v| (std::ffi::OsString::from(k), v)))
        .collect();
    cmd.env_clear();
    for (k, v) in saved {
        cmd.env(k, v);
    }
}

/// Run `cmd` to completion under a deadline; kill it on timeout so a
/// wedged install cannot hang the capture. The child always gets the
/// scrubbed environment — installs and launches alike.
fn run_timeout(
    cmd: &mut Command,
    budget: Duration,
    what: &str,
) -> Result<std::process::ExitStatus, String> {
    minimal_env(cmd);
    let mut child = cmd.spawn().map_err(|e| format!("{what}: spawn: {e}"))?;
    let end = Instant::now() + budget;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Ok(status),
            Ok(None) if Instant::now() < end => {
                std::thread::sleep(Duration::from_millis(50));
            }
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!("{what}: timed out after {}s", budget.as_secs()));
            }
            Err(e) => return Err(format!("{what}: wait: {e}")),
        }
    }
}

/// Quote one token for a `cmd /c` inner line when it carries whitespace
/// or a cmd metacharacter — inside `"..."` these stay literal, so the
/// token still parses as a single argument. `%` is the exception: cmd
/// expands it even inside quotes and offers no command-line escape, so a
/// path containing `%name%` fails loudly downstream instead of
/// misparsing here.
fn cmd_quote(arg: &str) -> String {
    if arg
        .chars()
        .any(|c| c.is_whitespace() || "&|<>()^%!".contains(c))
    {
        format!("\"{arg}\"")
    } else {
        arg.to_string()
    }
}

/// `cmd /c "<inner>"` — the inner line wrapped in one more pair of
/// quotes: cmd's /c handling strips the outer pair and keeps the
/// per-token quoting intact, so a `Program Files` path holds.
#[cfg(windows)]
fn cmd_c(inner: &str) -> Command {
    use std::os::windows::process::CommandExt;
    // raw_arg reaches CreateProcess verbatim — the only way to control
    // cmd's quote handling (arg() would MSVC-escape the inner quotes).
    let mut c = Command::new("cmd");
    c.arg("/c").raw_arg(format!("\"{inner}\""));
    c
}

#[cfg(unix)]
fn cmd_c(inner: &str) -> Command {
    // WSL interop re-quotes the spaced element for the Windows command
    // line, producing the wrapped form described above.
    let mut c = Command::new("cmd.exe");
    c.arg("/c").arg(inner);
    c
}

fn npm_install(prefix: &Path, spec: &str) -> Result<(), String> {
    // Under WSL a bare `npm` resolved on a drvfs mount is the Windows
    // POSIX shim — it hands node.exe a `/mnt/...` script path it cannot
    // read. Prefer the `.cmd`/`.exe` launchers interop executes properly.
    let names: &[&str] = if wsl() {
        &["npm.cmd", "npm.exe", "npm"]
    } else {
        &["npm", "npm.cmd", "npm.exe"]
    };
    let npm = which_any(names).ok_or("npm not found on PATH")?;
    let npm_s = npm.to_string_lossy().to_lowercase();
    // A `npm` resolved under a drvfs mount (or a `.cmd`/`.exe` shim) is
    // Windows code reached through WSL interop: hand it a Windows prefix
    // path. Native `npm`/`npm.cmd` on Windows already takes native paths.
    let windows_npm =
        wsl() && (npm_s.contains("/mnt/") || npm_s.ends_with(".cmd") || npm_s.ends_with(".exe"));
    let run_npm = |args: &[String], what: &str| -> Result<(), String> {
        let status = if npm_s.ends_with(".cmd") {
            let npm_cli = npm
                .parent()
                .unwrap_or(npm.as_path())
                .join("node_modules/npm/bin/npm-cli.js");
            if npm_cli.is_file() {
                // Drive npm-cli.js with node directly and skip cmd
                // entirely — npm.cmd sits next to node_modules/npm/bin
                // in the standard Node layout, and cmd's /c
                // quote-stripping mangles spaced paths.
                let node = node_bin()?;
                let win = is_windows_binary(&node);
                run_timeout(
                    Command::new(&node)
                        .arg(child_path(&npm_cli, win)?)
                        .args(args),
                    INSTALL_TIMEOUT,
                    what,
                )?
            } else {
                // Batch shims need a Windows shell — `cmd.exe` resolves
                // through WSL interop as well, and wants a
                // Windows-spelled npm path.
                let npm_arg = child_path(&npm, wsl())?;
                let inner = std::iter::once(npm_arg)
                    .chain(args.iter().cloned())
                    .map(|a| cmd_quote(&a))
                    .collect::<Vec<_>>()
                    .join(" ");
                run_timeout(&mut cmd_c(&inner), INSTALL_TIMEOUT, what)?
            }
        } else {
            run_timeout(Command::new(&npm).args(args), INSTALL_TIMEOUT, what)?
        };
        if status.success() {
            Ok(())
        } else {
            Err(format!("{what} exited {status}"))
        }
    };

    // Integrity-locked install: the pin lands in the scratch manifest,
    // `npm install --package-lock-only` resolves the complete graph and
    // records integrity hashes for every resolved package, and `npm ci`
    // then installs exactly that locked set — registry drift cannot
    // substitute a different transitive dependency than what the
    // resolution recorded. `--ignore-scripts` keeps package code
    // unexecuted on every phase.
    let (pkg, ver) = spec
        .rsplit_once('@')
        .ok_or_else(|| format!("npm spec {spec} carries no @version pin"))?;
    std::fs::create_dir_all(prefix).map_err(|e| format!("mkdir {}: {e}", prefix.display()))?;
    let json_str = |s: &str| -> String {
        s.replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('\n', " ")
    };
    std::fs::write(
        prefix.join("package.json"),
        format!(
            "{{\"name\":\"corpus-scratch\",\"private\":true,\"dependencies\":{{\"{}\":\"{}\"}}}}",
            json_str(pkg),
            json_str(ver)
        ),
    )
    .map_err(|e| format!("write {}: {e}", prefix.join("package.json").display()))?;
    let prefix_arg = child_path(prefix, windows_npm)?;
    run_npm(
        &[
            "install".into(),
            "--prefix".into(),
            prefix_arg.clone(),
            "--package-lock-only".into(),
            "--ignore-scripts".into(),
            "--no-audit".into(),
            "--no-fund".into(),
        ],
        "npm install --package-lock-only",
    )?;
    run_npm(
        &[
            "ci".into(),
            "--prefix".into(),
            prefix_arg,
            "--ignore-scripts".into(),
            "--no-audit".into(),
            "--no-fund".into(),
        ],
        "npm ci",
    )
}

/// Install `spec` into an isolated venv under `prefix`; return its
/// python.
///
/// Tries a `python3`/`python`/`py` on PATH with `ensurepip` first.
/// Minimal WSL distros often lack ensurepip, so under WSL a Windows `py`
/// launcher is the fallback — it builds a Windows venv (Windows paths
/// via wslpath) whose `Scripts/python.exe` runs through interop.
fn pypi_install(prefix: &Path, spec: &str) -> Result<PathBuf, String> {
    let venv = prefix.join("venv");
    let venv_py = if cfg!(windows) {
        venv.join("Scripts/python.exe")
    } else {
        venv.join("bin/python")
    };
    let mut attempts: Vec<(Vec<String>, PathBuf)> = Vec::new();
    // Interpreters without ensurepip cannot bootstrap a venv — skip them
    // quietly rather than letting `venv` print its install instructions.
    // A wedged interpreter (probe timeout) counts as unavailable too, so
    // the fallback attempts still run.
    let candidates: &[&[&str]] = if cfg!(windows) {
        &[&["py", "-3"], &["python"], &["python3"]]
    } else {
        &[&["python3"], &["python"]]
    };
    for cand in candidates {
        let Some(prog) = which_one(cand[0]) else {
            continue;
        };
        let mut argv: Vec<String> = vec![prog.to_string_lossy().into_owned()];
        argv.extend(cand[1..].iter().map(|s| s.to_string()));
        let has_ensurepip = run_timeout(
            Command::new(&argv[0])
                .args(&argv[1..])
                .args(["-c", "import ensurepip"]),
            Duration::from_secs(60),
            "ensurepip probe",
        )
        .map(|s| s.success())
        .unwrap_or(false);
        if has_ensurepip {
            argv.extend([
                "-m".into(),
                "venv".into(),
                venv.to_string_lossy().into_owned(),
            ]);
            attempts.push((argv, venv_py.clone()));
            break;
        }
    }
    if wsl()
        && let Some(py) = which_any(&["py.exe", "py"])
    {
        attempts.push((
            vec![
                py.to_string_lossy().into_owned(),
                "-3".into(),
                "-m".into(),
                "venv".into(),
                child_path(&venv, true)?,
            ],
            venv.join("Scripts/python.exe"),
        ));
    }
    let mut python = None;
    for (argv, pybin) in &attempts {
        match run_timeout(
            Command::new(&argv[0]).args(&argv[1..]),
            INSTALL_TIMEOUT,
            "venv creation",
        ) {
            Ok(s) if s.success() && pybin.is_file() => {
                python = Some(pybin.clone());
                break;
            }
            _ => continue,
        }
    }
    let Some(python) = python else {
        return Err(
            "could not create a venv for pypi capture (no ensurepip / no py launcher)".into(),
        );
    };
    // Integrity-locked install. `pip download --only-binary :all:`
    // resolves the complete graph and fetches wheels only — an sdist's
    // `setup.py` is unfixed registry code and must never run. Each
    // downloaded artifact is hashed, the locked set is written to
    // requirements.txt, and `pip install --no-index --require-hashes`
    // installs exactly those verified bytes. Name and version come
    // from the wheel filename (`{name}-{version}-…`) itself — no
    // pip-version-specific report format is assumed.
    let py_win = is_windows_binary(&python);
    let dl = prefix.join("wheels");
    std::fs::create_dir_all(&dl).map_err(|e| format!("mkdir {}: {e}", dl.display()))?;
    let status = run_timeout(
        Command::new(&python).args([
            "-m".into(),
            "pip".into(),
            "download".into(),
            "--dest".into(),
            child_path(&dl, py_win)?,
            "--only-binary".into(),
            ":all:".into(),
            "--quiet".into(),
            spec.to_string(),
        ]),
        INSTALL_TIMEOUT,
        "pip download",
    )?;
    if !status.success() {
        return Err(format!("pip download {spec} exited {status}"));
    }
    // `dl` holds only this run's downloads; wheel filenames are
    // `{name}-{version}(-{build})?-{py}-{abi}-{plat}.whl` with `-`
    // forbidden inside the name/version fields (PEP 427 normalization
    // replaces it with `_`). Sorted for a deterministic lockfile.
    let mut wheels: Vec<String> = Vec::new();
    for entry in std::fs::read_dir(&dl).map_err(|e| format!("read {}: {e}", dl.display()))? {
        let entry = entry.map_err(|e| format!("read {}: {e}", dl.display()))?;
        let file_name = entry.file_name().to_string_lossy().into_owned();
        if file_name.ends_with(".whl") {
            wheels.push(file_name);
        }
    }
    wheels.sort();
    let mut reqs = String::new();
    let mut count = 0usize;
    for file_name in &wheels {
        let stem = &file_name[..file_name.len() - ".whl".len()];
        let mut fields = stem.split('-');
        let (Some(name), Some(version)) = (fields.next(), fields.next()) else {
            return Err(format!(
                "wheel '{file_name}' is not a '<name>-<version>-…' filename"
            ));
        };
        let artifact = dl.join(file_name);
        let bytes =
            std::fs::read(&artifact).map_err(|e| format!("read {}: {e}", artifact.display()))?;
        // sha2 0.11's digest output does not implement LowerHex.
        let mut hex = String::with_capacity(64);
        for b in sha2::Sha256::digest(&bytes) {
            hex.push_str(&format!("{b:02x}"));
        }
        reqs.push_str(&format!("{name}=={version} --hash=sha256:{hex}\n"));
        count += 1;
    }
    if count == 0 {
        return Err(format!("pip download {spec} produced no artifacts"));
    }
    let req_path = prefix.join("requirements.txt");
    std::fs::write(&req_path, &reqs).map_err(|e| format!("write {}: {e}", req_path.display()))?;
    let status = run_timeout(
        Command::new(&python).args([
            "-m".into(),
            "pip".into(),
            "install".into(),
            "--no-index".into(),
            "--find-links".into(),
            child_path(&dl, py_win)?,
            "--require-hashes".into(),
            "-r".into(),
            child_path(&req_path, py_win)?,
            "--quiet".into(),
        ]),
        INSTALL_TIMEOUT,
        "pip install",
    )?;
    if status.success() {
        Ok(python)
    } else {
        Err(format!("pip install -r requirements.txt exited {status}"))
    }
}

fn pinned_node_entry(spec: &ServerSpec) -> PathBuf {
    real_servers()
        .join("node/node_modules")
        .join(spec.package)
        .join("dist/index.js")
}

fn pinned_python() -> Result<PathBuf, String> {
    let venv = real_servers().join("python/.venv");
    for cand in [venv.join("bin/python"), venv.join("Scripts/python.exe")] {
        if cand.is_file() {
            return Ok(cand);
        }
    }
    Err("real_servers python venv missing: run tests/fixtures/real_servers/setup.* first".into())
}

fn member<'t, 'r>(
    v: nojson::RawJsonValue<'t, 'r>,
    key: &str,
) -> Option<nojson::RawJsonValue<'t, 'r>> {
    v.to_member(key).ok().and_then(|m| m.optional())
}

fn member_str(v: nojson::RawJsonValue<'_, '_>, key: &str) -> Option<String> {
    member(v, key)
        .and_then(|v| v.to_unquoted_string_str().ok())
        .map(|s| s.into_owned())
}

fn package_bin(pkg_root: &Path) -> Result<PathBuf, String> {
    let text = std::fs::read_to_string(pkg_root.join("package.json"))
        .map_err(|e| format!("read {}: {e}", pkg_root.join("package.json").display()))?;
    let json = nojson::RawJson::parse(&text).map_err(|e| format!("package.json: {e}"))?;
    let meta = json.value();
    let rel = match member(meta, "bin") {
        Some(v) if v.kind() == nojson::JsonValueKind::String => v
            .to_unquoted_string_str()
            .map_err(|e| e.to_string())?
            .into_owned(),
        Some(v) if v.kind() == nojson::JsonValueKind::Object => {
            let entries: Vec<(String, String)> = v
                .to_object()
                .map_err(|e| e.to_string())?
                .filter_map(|(k, v)| {
                    Some((
                        k.to_unquoted_string_str().ok()?.into_owned(),
                        v.to_unquoted_string_str().ok()?.into_owned(),
                    ))
                })
                .collect();
            if entries.len() == 1 {
                entries[0].1.clone()
            } else {
                // Chrome DevTools and friends declare several bins; the
                // *-mcp / package-named entry is the server — pick the
                // longest (most specific) name for stability, first
                // declared on ties.
                match entries.iter().find(|(k, _)| k.ends_with("-mcp")) {
                    Some((_, v)) => v.clone(),
                    None => entries
                        .iter()
                        .max_by(|a, b| a.0.cmp(&b.0))
                        .map(|(_, v)| v.clone())
                        .ok_or("package.json bin is an empty object")?,
                }
            }
        }
        _ => member_str(meta, "main").unwrap_or_else(|| "dist/index.js".into()),
    };
    Ok(pkg_root.join(rel))
}

/// Like `run_timeout` but returns captured stdout. A reader thread
/// drains the pipe while the child runs — output bigger than the pipe
/// buffer would otherwise block the child's write and hit the timeout.
fn run_stdout(cmd: &mut Command, budget: Duration, what: &str) -> Result<String, String> {
    minimal_env(cmd);
    let mut child = cmd
        .stdout(Stdio::piped())
        .spawn()
        .map_err(|e| format!("{what}: spawn: {e}"))?;
    let mut stdout = child.stdout.take().expect("piped stdout");
    let reader = std::thread::spawn(move || {
        let mut out = String::new();
        stdout.read_to_string(&mut out).map(|_| out)
    });
    let end = Instant::now() + budget;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if Instant::now() < end => std::thread::sleep(Duration::from_millis(50)),
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!("{what}: timed out after {}s", budget.as_secs()));
            }
            Err(e) => return Err(format!("{what}: wait: {e}")),
        }
    };
    // Exited + EOF means the reader has finished; join only waits for
    // the thread to hand its result back.
    let res = reader
        .join()
        .map_err(|_| format!("{what}: stdout reader panicked"))?;
    if !status.success() {
        return Err(format!("{what}: exited {status}"));
    }
    res.map_err(|e| format!("{what}: read stdout: {e}"))
}

/// The version actually vendored under `real_servers/` for a pinned
/// spec — provenance records what is installed, and a drift from
/// `spec.version` fails the capture instead of pinning a lie.
fn pinned_version(spec: &ServerSpec) -> Result<String, String> {
    let version = if spec.package.starts_with('@') {
        let pkg_json = real_servers()
            .join("node/node_modules")
            .join(spec.package)
            .join("package.json");
        let text = std::fs::read_to_string(&pkg_json)
            .map_err(|e| format!("read {}: {e}", pkg_json.display()))?;
        let json =
            nojson::RawJson::parse(&text).map_err(|e| format!("{}: {e}", pkg_json.display()))?;
        member_str(json.value(), "version")
            .ok_or_else(|| format!("{}: no version field", pkg_json.display()))?
    } else {
        let py = pinned_python()?;
        let out = run_stdout(
            Command::new(&py).args([
                "-c",
                "import importlib.metadata,sys;print(importlib.metadata.version(sys.argv[1]))",
                spec.package,
            ]),
            Duration::from_secs(60),
            "version probe",
        )?;
        out.trim().to_string()
    };
    if version != spec.version {
        return Err(format!(
            "{}: vendored {} is {version}, spec pins {}",
            spec.name, spec.package, spec.version
        ));
    }
    Ok(version)
}

/// `entry` relative to `base`, joined with `/` — provenance argv must be
/// machine-independent, so Windows drives never appear.
fn posix_rel(p: &Path, base: &Path) -> String {
    p.strip_prefix(base)
        .unwrap_or(p)
        .components()
        .filter_map(|c| match c {
            std::path::Component::Normal(s) => Some(s.to_string_lossy().into_owned()),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join("/")
}

/// (resolved argv, logical argv) for a `node <entry>` launch —
/// `logical_entry` is the machine-independent spelling recorded in
/// provenance (a repo-relative path or `pkg@ver/path`).
fn node_argv(
    entry: &Path,
    logical_entry: String,
    args: &[String],
) -> Result<(Vec<String>, Vec<String>), String> {
    let node = node_bin()?;
    let mut argv = vec![
        node.to_string_lossy().into_owned(),
        child_path(entry, is_windows_binary(&node))?,
    ];
    argv.extend(args.iter().cloned());
    let mut logical = vec!["node".into(), logical_entry];
    logical.extend(args.iter().cloned());
    Ok((argv, logical))
}

/// (resolved argv, logical argv, installed version). The resolved argv
/// is spawned; the logical argv and version are recorded in provenance —
/// machine-local paths would churn the committed file on every recapture,
/// and for `pinned` sources the version is read back from the vendored
/// tree rather than trusted from `spec.version`.
fn argv_for(
    spec: &ServerSpec,
    scratch: &Path,
) -> Result<(Vec<String>, Vec<String>, String), String> {
    let args: Vec<String> = spec.args.iter().map(|s| s.to_string()).collect();
    match spec.source {
        Source::Pinned if spec.package.starts_with('@') => {
            let entry = pinned_node_entry(spec);
            if !entry.is_file() {
                return Err(format!(
                    "pinned fixture missing: {} — run tests/fixtures/real_servers/setup.* first",
                    entry.display()
                ));
            }
            let version = pinned_version(spec)?;
            let (argv, logical) = node_argv(&entry, posix_rel(&entry, repo_root()), &args)?;
            Ok((argv, logical, version))
        }
        Source::Pinned => {
            let module = match spec.package {
                "mcp-server-time" => "mcp_server_time",
                "mcp-server-git" => "mcp_server_git",
                p => return Err(format!("no module mapping for pinned package {p}")),
            };
            let py = pinned_python()?;
            let version = pinned_version(spec)?;
            let mut argv = vec![
                py.to_string_lossy().into_owned(),
                "-m".into(),
                module.into(),
            ];
            argv.extend(args.iter().cloned());
            let mut logical = vec!["python".into(), "-m".into(), module.into()];
            logical.extend(args);
            Ok((argv, logical, version))
        }
        Source::Npm => {
            let install_root = scratch.join("npm").join(spec.name);
            npm_install(&install_root, &format!("{}@{}", spec.package, spec.version))?;
            let pkg_root = install_root.join("node_modules").join(spec.package);
            let entry = package_bin(&pkg_root)?;
            let rel = posix_rel(&entry, &pkg_root);
            let (argv, logical) = node_argv(
                &entry,
                format!("{}@{}/{}", spec.package, spec.version, rel),
                &args,
            )?;
            // npm/pypi pin `pkg@version` / `pkg==version` at install —
            // the installer enforces it, so spec.version is the version.
            Ok((argv, logical, spec.version.to_string()))
        }
        Source::Pypi => {
            let py = pypi_install(
                &scratch.join("pypi").join(spec.name),
                &format!("{}=={}", spec.package, spec.version),
            )?;
            let module = spec.package.replace('-', "_");
            let mut argv = vec![
                py.to_string_lossy().into_owned(),
                "-m".into(),
                module.clone(),
            ];
            argv.extend(args.iter().cloned());
            let mut logical = vec!["python".into(), "-m".into(), module];
            logical.extend(args);
            Ok((argv, logical, spec.version.to_string()))
        }
    }
}

/// Line-delimited JSON-RPC over the child's stdin/stdout, with reader
/// threads so a chatty or stalled server cannot wedge the capture.
struct StdioRpc {
    child: Child,
    stdin: Option<ChildStdin>,
    lines: Receiver<Option<String>>,
    stderr_tail: Arc<Mutex<VecDeque<String>>>,
}

impl StdioRpc {
    fn spawn(argv: &[String], cwd: &Path, guarded: bool) -> Result<Self, String> {
        let mut cmd = Command::new(&argv[0]);
        cmd.args(&argv[1..])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .current_dir(cwd);
        minimal_env(&mut cmd);
        if guarded {
            // The corpus deliberately generates its policy and works
            // under the operator's scratch tree, whose ACLs need not be
            // write-restricted — the documented shared-tree opt-out
            // belongs on the guard process so the spawned guard's
            // trusted-source gate accepts the staged policy. It never
            // reaches the workload: the guard strips every guard var
            // from the child env, and `guarded == false` skips this
            // entirely so an unsandboxed capture cannot inherit it
            // into a nested launch either.
            cmd.env("MCP_WRIT_ALLOW_REPLACEABLE_PATHS", "1");
        }
        let mut child = cmd.spawn().map_err(|e| format!("spawn {}: {e}", argv[0]))?;
        let stdout = child.stdout.take().expect("piped stdout");
        let (tx, lines) = mpsc::channel();
        std::thread::spawn(move || {
            let mut reader = BufReader::new(stdout);
            let mut line = String::new();
            loop {
                line.clear();
                match reader.read_line(&mut line) {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {
                        if tx
                            .send(Some(line.trim_end_matches(['\r', '\n']).to_string()))
                            .is_err()
                        {
                            return;
                        }
                    }
                }
            }
            let _ = tx.send(None);
        });
        // stderr must be drained while the server runs — a chatty server
        // otherwise blocks once the pipe buffer fills. Bounded deque:
        // only the tail is wanted for error reporting.
        let stderr = child.stderr.take().expect("piped stderr");
        let stderr_tail = Arc::new(Mutex::new(VecDeque::with_capacity(64)));
        let tail = Arc::clone(&stderr_tail);
        std::thread::spawn(move || {
            let mut reader = BufReader::new(stderr);
            let mut line = String::new();
            loop {
                line.clear();
                match reader.read_line(&mut line) {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {
                        let mut g = tail.lock().expect("stderr tail");
                        if g.len() == 64 {
                            g.pop_front();
                        }
                        g.push_back(line.clone());
                    }
                }
            }
        });
        let stdin = child.stdin.take().expect("piped stdin");
        Ok(Self {
            child,
            stdin: Some(stdin),
            lines,
            stderr_tail,
        })
    }

    fn stderr_text(&self) -> String {
        let tail = self.stderr_tail.lock().expect("stderr tail");
        tail.iter().cloned().collect::<Vec<_>>().join("")
    }

    fn send(&mut self, text: &str) -> Result<(), String> {
        let stdin = self.stdin.as_mut().ok_or("stdin closed")?;
        stdin
            .write_all(text.as_bytes())
            .and_then(|()| stdin.write_all(b"\n"))
            .and_then(|()| stdin.flush())
            .map_err(|e| format!("stdin write: {e}"))
    }

    fn request(&mut self, req_id: u64, method: &str, params: &str) -> Result<String, String> {
        self.send(&format!(
            "{{\"jsonrpc\":\"2.0\",\"id\":{req_id},\"method\":\"{method}\",\"params\":{params}}}"
        ))?;
        let end = Instant::now() + CAPTURE_TIMEOUT;
        loop {
            let Some(left) = end.checked_duration_since(Instant::now()) else {
                return Err(format!(
                    "{method}: no response within {}s",
                    CAPTURE_TIMEOUT.as_secs()
                ));
            };
            let line = match self.lines.recv_timeout(left) {
                Ok(Some(line)) => line,
                Ok(None) => {
                    let tail = self.stderr_text();
                    // Slice on one snapshot at a char boundary — a
                    // mid-character index panics, and a second snapshot
                    // could disagree with the length of the first.
                    let mut start = tail.len().saturating_sub(2000);
                    while !tail.is_char_boundary(start) {
                        start += 1;
                    }
                    return Err(format!(
                        "{method}: server exited (code {:?}) stderr: {}",
                        self.child.try_wait().ok().flatten(),
                        &tail[start..],
                    ));
                }
                Err(RecvTimeoutError::Timeout) | Err(RecvTimeoutError::Disconnected) => {
                    return Err(format!(
                        "{method}: no response within {}s",
                        CAPTURE_TIMEOUT.as_secs()
                    ));
                }
            };
            let Ok(json) = nojson::RawJson::parse(&line) else {
                continue; // log chatter on stdout; not JSON-RPC
            };
            let msg = json.value();
            // Classify by `method` first: a server→client request carries
            // an id from the same numeric space as ours, so an id match
            // alone would return the request as if it were our response.
            if member(msg, "method").is_some() {
                if let Some(id) = member(msg, "id") {
                    // We implement no server→client methods — answer
                    // -32601 so the server does not wait out the budget.
                    self.send(&format!(
                        "{{\"jsonrpc\":\"2.0\",\"id\":{},\"error\":{{\"code\":-32601,\"message\":\"method not found\"}}}}",
                        id.as_raw_str()
                    ))?;
                }
                continue; // notifications drop
            }
            // A response carries `result`/`error` for our outstanding id;
            // anything else (stray or malformed ids) is ignored.
            let id_match = member(msg, "id")
                .map(|v| v.as_raw_str() == req_id.to_string())
                .unwrap_or(false);
            let has_payload = member(msg, "result").is_some() || member(msg, "error").is_some();
            if id_match && has_payload {
                return Ok(line);
            }
        }
    }

    fn notify(&mut self, method: &str) -> Result<(), String> {
        self.send(&format!(
            "{{\"jsonrpc\":\"2.0\",\"method\":\"{method}\",\"params\":{{}}}}"
        ))
    }

    fn close(&mut self) {
        drop(self.stdin.take());
        let end = Instant::now() + Duration::from_secs(5);
        loop {
            match self.child.try_wait() {
                Ok(Some(_)) | Err(_) => break,
                Ok(None) if Instant::now() < end => {
                    std::thread::sleep(Duration::from_millis(50));
                }
                Ok(None) => {
                    let _ = self.child.kill();
                    let _ = self.child.wait();
                    break;
                }
            }
        }
    }
}

impl Drop for StdioRpc {
    fn drop(&mut self) {
        self.close();
    }
}

fn error_detail(line: &str) -> Option<String> {
    let json = nojson::RawJson::parse(line).ok()?;
    member(json.value(), "error").map(|v| v.as_raw_str().to_string())
}

/// The guard binary every captured server runs under — `mcp-writ run`
/// wraps the workload in the deny-by-default policy below. Defaults to
/// the locally built binary; `MCP_CORPUS_GUARD=<path>` overrides.
fn guard_bin() -> Option<PathBuf> {
    if let Some(p) = std::env::var_os("MCP_CORPUS_GUARD") {
        let p = PathBuf::from(p);
        if p.is_file() {
            return Some(p);
        }
        eprintln!(
            "warning: MCP_CORPUS_GUARD={} is not a file — ignoring",
            p.display()
        );
        return None;
    }
    let exe = if cfg!(windows) {
        "mcp-writ.exe"
    } else {
        "mcp-writ"
    };
    for profile in ["debug", "release"] {
        let cand = repo_root().join("target").join(profile).join(exe);
        if is_executable(&cand) {
            return Some(cand);
        }
    }
    None
}

/// Deny-by-default capture policy: the interpreter and its modules must
/// load: `exec` on everything (an interpreter can live anywhere), but
/// `read` only on the roots [`corpus_read_roots`] enumerates — system
/// trees, pseudo-devices, the resolved interpreter's own install
/// prefix, the corpus scratch dir, and the repo checkout. Nothing
/// writes anywhere, no network flows, and an empty environment
/// allowlist hands the child only PATH + system vars.
///
/// The protection model is *absence of grant*, not deny rules: the
/// fs grammar cannot carve a denied subpath out of a broad grant —
/// Landlock's `path_beneath` rules are additive and refuse the policy
/// at setup, and regular AppContainer has no deny ACEs at all — so a
/// `read /**` + `deny` combination makes the guard launch refuse.
/// Instead, read access is enumerated: `$HOME`/`USERPROFILE` (`~/.ssh`,
/// `~/.aws`, `~/.npmrc`, `~/.env`, …), `/root`, `/tmp`, and `/mnt/*`
/// (WSL's drvfs view of the Windows profiles) are simply not granted.
/// `/etc` is included wholesale because the credential material there
/// (`shadow`, `sudoers`) is already root-only at the DAC layer — a
/// workload running as the capture user cannot open it regardless.
/// `exec /**` stays broad on purpose: the execute right cannot read a
/// file's contents, and interpreters resolve from arbitrary prefixes
/// (`~/.nvm`, `/opt`, Homebrew). A captured package trying to open a
/// secret path fails closed; a package needing a root we missed fails
/// *visibly* — the capture comes back empty, never silently wider.
fn corpus_policy(argv0: &str, cwd: &Path, scratch: &Path) -> String {
    let mut kdl = String::from(
        r#"policy version=2
defaults {
    filesystem {
"#,
    );
    let mut seen: std::collections::HashSet<(String, String)> =
        std::collections::HashSet::new();
    let mut allow = |mode: &str, path: String| {
        if seen.insert((mode.to_string(), path.clone())) {
            kdl.push_str(&format!("        allow \"{path}\" mode=\"{mode}\"\n"));
        }
    };
    for root in corpus_read_roots(argv0, cwd, scratch) {
        // Grant only roots that exist: Landlock and AppContainer both
        // fail policy construction on absent paths.
        if Path::new(&root).exists() {
            allow("read", root);
        }
    }
    allow("exec", "/**".to_string());
    kdl.push_str(
        r#"    }
    network {
        deny host="*"
    }
    environment {
    }
}
"#,
    );
    kdl
}

/// The read roots [`corpus_policy`] grants. Order is cosmetic — the set
/// is deduplicated on emit — but the composition is the security
/// contract above: everything a captured server legitimately reads,
/// nothing under a user profile or a cross-OS mount.
fn corpus_read_roots(argv0: &str, cwd: &Path, scratch: &Path) -> Vec<String> {
    let spell = |p: &Path| p.to_string_lossy().replace('\\', "/");
    let mut roots: Vec<String> = if cfg!(windows) {
        // The POSIX-side guard never wraps a Windows binary, but emit a
        // sane set anyway so the policy parses and confines if run.
        vec![
            "C:/Windows".into(),
            "C:/Program Files".into(),
            "C:/Program Files (x86)".into(),
        ]
    } else {
        vec![
            "/usr".into(),
            "/bin".into(),
            "/sbin".into(),
            "/lib".into(),
            "/lib64".into(),
            "/opt".into(),
            "/snap".into(),
            "/etc".into(),
            // macOS resolves /etc through /private/etc.
            "/private/etc".into(),
            "/System".into(),
            "/Library".into(),
            "/Applications".into(),
            // Pseudo-devices stdio/interpreters open. `/dev/fd` is a
            // symlink into /proc/self/fd — `/proc/self` covers the
            // resolved targets (the workload's own maps/environ only).
            "/dev/null".into(),
            "/dev/zero".into(),
            "/dev/full".into(),
            "/dev/urandom".into(),
            "/dev/random".into(),
            "/dev/tty".into(),
            "/dev/fd".into(),
            "/proc/self".into(),
        ]
    };
    // npm/pypi install roots, the per-server work dir, and the policy
    // dir itself all live under scratch.
    roots.push(spell(scratch));
    // Pinned fixtures keep the checkout cwd — `git --repository .`
    // specs read .git, vendored servers read their own tree.
    roots.push(spell(repo_root()));
    // The launch cwd when it differs (pinned == repo_root; ephemeral ==
    // a work dir under scratch — both already covered, dedup handles
    // it, but spell it for the invariant).
    roots.push(spell(cwd));
    // Interpreters under user prefixes (nvm, pyenv, uv, venvs) sit
    // outside every system root — grant their own install prefix
    // without touching $HOME: `<env>/bin/<exe>` gets `<env>/bin` plus
    // `<env>/{lib,lib64,libexec,include,share,Scripts,pyvenv.cfg}`.
    if let Some(exe) = resolve_on_path(argv0, cwd)
        && let Ok(real) = exe.canonicalize()
        && let Some(dir) = real.parent()
    {
        roots.push(spell(dir));
        if matches!(
            dir.file_name().and_then(|n| n.to_str()),
            Some("bin" | "sbin" | "Scripts" | "bin64")
        ) && let Some(env_root) = dir.parent()
        {
            // Expand only when the parent really is an interpreter
            // prefix (venv marker or npm's global root); an arbitrary
            // `bin` directory like `~/.local/bin/foo` must not grant
            // sibling trees under a profile root.
            if env_root.join("pyvenv.cfg").is_file()
                || env_root.join("lib").join("node_modules").is_dir()
            {
                for sub in ["lib", "lib64", "libexec", "include", "share", "Scripts"] {
                    roots.push(spell(&env_root.join(sub)));
                }
                roots.push(spell(&env_root.join("pyvenv.cfg")));
            }
        }
    }
    roots
}

/// Resolve `argv0` to an executable path — an explicit `/`-bearing
/// spelling resolves against `cwd`, otherwise the child's PATH search
/// is replayed against this process's PATH (the guard launch inherits
/// the same PATH the empty environment allowlist restores).
fn resolve_on_path(argv0: &str, cwd: &Path) -> Option<PathBuf> {
    if argv0.contains('/') || argv0.contains('\\') {
        let p = PathBuf::from(argv0);
        let p = if p.is_absolute() { p } else { cwd.join(p) };
        return p.is_file().then_some(p);
    }
    std::env::var_os("PATH").and_then(|path| {
        std::env::split_paths(&path)
            .map(|dir| dir.join(argv0))
            .find(|p| p.is_file())
    })
}

/// Wrap `argv` in the guard and pick the launch cwd. Every captured
/// server runs inside `mcp-writ run --policy <deny-all>` — the registry
/// package is the workload, not a trusted tool. Ephemeral sources also
/// get an empty per-server work dir as cwd; pinned fixtures keep the
/// checkout cwd because specs like `git --repository .` resolve their
/// arguments there (the policy still confines them to read+exec).
fn guard_wrap(
    spec: &ServerSpec,
    argv: &[String],
    scratch: &Path,
) -> Result<(Vec<String>, PathBuf, bool), String> {
    let work = scratch.join("work").join(spec.name);
    std::fs::create_dir_all(&work).map_err(|e| format!("mkdir {}: {e}", work.display()))?;
    let cwd = match spec.source {
        Source::Pinned => repo_root().to_path_buf(),
        _ => work,
    };
    let unsafe_host = std::env::var_os("MCP_CORPUS_UNSAFE_HOST")
        .map(|v| v == "1")
        .unwrap_or(false);
    let Some(guard) = guard_bin() else {
        return if unsafe_host {
            eprintln!(
                "warning: {} running WITHOUT sandbox (MCP_CORPUS_UNSAFE_HOST=1)",
                spec.name
            );
            Ok((argv.to_vec(), cwd, false))
        } else {
            Err(format!(
                "{}: no mcp-writ guard binary — build `cargo build --bin mcp-writ`, \
                 set MCP_CORPUS_GUARD=<path>, or opt into unsandboxed capture with \
                 MCP_CORPUS_UNSAFE_HOST=1",
                spec.name
            ))
        };
    };
    // A Windows binary cannot exec under the POSIX-side guard.
    if is_windows_binary(Path::new(&argv[0])) {
        return if unsafe_host {
            eprintln!(
                "warning: {} is a Windows binary — running WITHOUT sandbox \
                 (MCP_CORPUS_UNSAFE_HOST=1)",
                spec.name
            );
            Ok((argv.to_vec(), cwd, false))
        } else {
            Err(format!(
                "{}: Windows child cannot run under the POSIX guard — \
                 set MCP_CORPUS_UNSAFE_HOST=1 to capture unsandboxed",
                spec.name
            ))
        };
    }
    let policy_dir = scratch.join("policies");
    std::fs::create_dir_all(&policy_dir)
        .map_err(|e| format!("mkdir {}: {e}", policy_dir.display()))?;
    let policy_path = policy_dir.join(format!("{}.kdl", spec.name));
    std::fs::write(&policy_path, corpus_policy(&argv[0], &cwd, scratch))
        .map_err(|e| format!("write {}: {e}", policy_path.display()))?;
    let mut wrapped = vec![
        guard.to_string_lossy().into_owned(),
        "run".into(),
        "--policy".into(),
        policy_path.to_string_lossy().into_owned(),
        "--".into(),
    ];
    wrapped.extend(argv.iter().cloned());
    Ok((wrapped, cwd, true))
}

fn capture(spec: &ServerSpec, scratch: &Path) -> Result<(Vec<String>, String, String), String> {
    let (argv, logical_argv, version) = argv_for(spec, scratch)?;
    let (argv, cwd, guarded) = guard_wrap(spec, &argv, scratch)?;
    let mut rpc = StdioRpc::spawn(&argv, &cwd, guarded)?;
    let out = (|| {
        let init = rpc.request(
            1,
            "initialize",
            &format!(
                "{{\"protocolVersion\":\"{PROTOCOL_VERSION}\",\"capabilities\":{{}},\"clientInfo\":{CLIENT_INFO}}}"
            ),
        )?;
        if let Some(e) = error_detail(&init) {
            return Err(format!("initialize rejected: {e}"));
        }
        rpc.notify("notifications/initialized")?;
        let response = rpc.request(2, "tools/list", "{}")?;
        if let Some(e) = error_detail(&response) {
            return Err(format!("tools/list rejected: {e}"));
        }
        Ok((logical_argv, response))
    })();
    rpc.close();
    out.map(|(logical_argv, response)| (logical_argv, response, version))
}

/// Pretty-print `line` as `json.dumps(indent=2, ensure_ascii=False)`
/// would: two-space indents, `"key": value` spacing, non-ASCII literal.
fn pretty_json(line: &str) -> Result<String, String> {
    let json = nojson::RawJson::parse(line).map_err(|e| format!("response is not JSON: {e}"))?;
    Ok(format!(
        "{}",
        nojson::json(|f| {
            f.set_indent_size(2);
            f.set_spacing(true);
            f.value(json.value())
        })
    ))
}

fn today_utc() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    // Civil-from-days (Howard Hinnant's algorithm).
    let z = (secs / 86_400) as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02}")
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

/// Recorded value of the `generator` field — what produced the file.
const GENERATOR: &str = "examples/capture_manifest_corpus.rs";

/// Top-level members of provenance.json preserved verbatim on rewrite,
/// plus previously captured server entries retained for specs not run
/// this time.
struct Provenance {
    /// All top-level keys in file order.
    order: Vec<String>,
    /// `key` → member value for keys this tool does not manage.
    verbatim: HashMap<String, nojson::RawJsonOwned>,
    /// `name` → entry object, for servers not recaptured this run.
    servers: HashMap<String, nojson::RawJsonOwned>,
}

fn load_provenance(path: &Path) -> Provenance {
    let mut prov = Provenance {
        order: Vec::new(),
        verbatim: HashMap::new(),
        servers: HashMap::new(),
    };
    let Ok(text) = std::fs::read_to_string(path) else {
        return prov;
    };
    let Ok(json) = nojson::RawJson::parse(&text) else {
        return prov;
    };
    let Ok(obj) = json.value().to_object() else {
        return prov;
    };
    for (k, v) in obj {
        let Ok(key) = k.to_unquoted_string_str() else {
            continue;
        };
        let key = key.into_owned();
        prov.order.push(key.clone());
        match key.as_str() {
            "servers" => {
                if let Ok(arr) = v.to_array() {
                    for entry in arr {
                        if let Some(name) = member_str(entry, "name") {
                            prov.servers.insert(name, entry.extract().into_owned());
                        }
                    }
                }
            }
            "captured_at_utc" | "generator" => {}
            _ => {
                prov.verbatim.insert(key, v.extract().into_owned());
            }
        }
    }
    prov
}

/// One provenance server entry, field order matching the committed file.
/// `version` is the version detected at capture time (the vendored
/// package's own metadata for `pinned` sources), not the spec's pin.
fn server_entry_json(
    spec: &ServerSpec,
    file: &str,
    fetched: &str,
    argv: &[String],
    tool_count: usize,
    version: &str,
) -> nojson::RawJsonOwned {
    nojson::RawJsonOwned::object(|f| {
        f.member("name", spec.name)?;
        f.member("file", file)?;
        f.member("package", spec.package)?;
        f.member("version", version)?;
        f.member("license", spec.license)?;
        f.member("upstream", spec.upstream)?;
        f.member("source", spec.source.as_str())?;
        f.member("fetched_at", fetched)?;
        f.member("argv", argv)?;
        f.member("tool_count", tool_count)?;
        if !spec.note.is_empty() {
            f.member("note", spec.note)?;
        }
        Ok(())
    })
}

fn run() -> Result<(), String> {
    // Positional args only *select* specs: each is resolved against the
    // static `SERVERS` allowlist by exact `name` match, and an unknown
    // name aborts the run before anything is spawned or installed. The
    // argv strings are consumed by this lookup and never reach a
    // spawned process — every executable, package, and argv comes from
    // `ServerSpec` itself.
    let mut wanted: Vec<&'static str> = Vec::new();
    for arg in std::env::args_os().skip(1) {
        // `env::args` panics on non-UTF-8 argv; lossy conversion lets a
        // malformed name fall through to the unknown-name error below.
        let arg = arg.to_string_lossy().into_owned();
        match SERVERS.iter().find(|s| s.name == arg) {
            Some(spec) => wanted.push(spec.name),
            None => {
                let known: Vec<&str> = SERVERS.iter().map(|s| s.name).collect();
                return Err(format!("unknown server {arg:?}; known: {known:?}"));
            }
        }
    }
    // Empty `wanted` means all specs; `specs` keeps `SERVERS` order.
    let specs: Vec<&ServerSpec> = SERVERS
        .iter()
        .filter(|s| wanted.is_empty() || wanted.contains(&s.name))
        .collect();
    let corpus = corpus_dir();
    std::fs::create_dir_all(&corpus).map_err(|e| format!("mkdir {}: {e}", corpus.display()))?;
    let scratch_root = scratch_root();
    std::fs::create_dir_all(&scratch_root)
        .map_err(|e| format!("mkdir {}: {e}", scratch_root.display()))?;
    let fetched = today_utc();
    let prov_path = corpus.join("provenance.json");
    let mut prov = load_provenance(&prov_path);

    let scratch = tempfile::Builder::new()
        .prefix("scratch-")
        .tempdir_in(&scratch_root)
        .map_err(|e| format!("scratch dir: {e}"))?;
    // Capture every spec before touching the corpus: a failed capture
    // must leave fixtures and provenance unchanged rather than a
    // half-updated set.
    let mut captured: Vec<(String, String, String, nojson::RawJsonOwned)> =
        Vec::with_capacity(specs.len());
    for spec in &specs {
        println!(
            "[{}] {}@{} ({})",
            spec.name,
            spec.package,
            spec.version,
            spec.source.as_str()
        );
        let (argv, response, version) = capture(spec, scratch.path())?;
        // The crate's own parser is the strictest check available: it
        // enforces the envelope shape the regression corpus relies on.
        let tools = mcp_writ::protocol::tools_list::parse_tools_list_response(&response)
            .map_err(|e| format!("{}: tools/list unparseable: {e}", spec.name))?;
        if tools.is_empty() {
            return Err(format!("{}: tools/list carried no tools", spec.name));
        }
        let file = format!("{}.tools-list.json", spec.name);
        let body = format!("{}\n", pretty_json(&response)?);
        let entry = server_entry_json(spec, &file, &fetched, &argv, tools.len(), &version);
        println!("  {} tools captured", tools.len());
        captured.push((spec.name.to_string(), file, body, entry));
    }
    drop(scratch);
    // Stage every write as a temp file in the corpus dir and rename
    // only once all writes have succeeded — a failed write drops its
    // staging files, leaving committed fixtures and provenance
    // unchanged rather than a half-updated set.
    let mut staged: Vec<(tempfile::NamedTempFile, PathBuf)> = Vec::new();
    for (name, file, body, entry) in captured {
        let tmp =
            tempfile::NamedTempFile::new_in(&corpus).map_err(|e| format!("stage {file}: {e}"))?;
        std::fs::write(tmp.path(), body)
            .map_err(|e| format!("write {}: {e}", tmp.path().display()))?;
        prov.servers.insert(name, entry);
        staged.push((tmp, corpus.join(&file)));
    }

    // Top-level key order is preserved; managed keys (`servers`,
    // `captured_at_utc`, `generator`) rewrite in place and append when
    // absent — matching the previous generator's dict-update order.
    if prov.order.is_empty() {
        prov.order = vec!["schema".into(), "servers".into()];
        prov.verbatim.insert(
            "schema".into(),
            nojson::RawJsonOwned::parse("\"mcp-writ-manifest-corpus-v1\"")
                .map_err(|e| format!("schema literal: {e}"))?,
        );
    }
    let servers_json: Vec<&nojson::RawJsonOwned> = SERVERS
        .iter()
        .filter_map(|s| prov.servers.get(s.name))
        .collect();
    let pretty = format!(
        "{}",
        nojson::json(|f| {
            f.set_indent_size(2);
            f.set_spacing(true);
            f.object(|f| {
                for key in &prov.order {
                    match key.as_str() {
                        "servers" => f.member("servers", &servers_json),
                        "captured_at_utc" => f.member("captured_at_utc", fetched.as_str()),
                        "generator" => f.member("generator", GENERATOR),
                        _ => f.member(
                            key.as_str(),
                            prov.verbatim.get(key).expect("verbatim member"),
                        ),
                    }?;
                }
                for key in ["servers", "captured_at_utc", "generator"] {
                    if prov.order.iter().any(|k| k == key) {
                        continue;
                    }
                    match key {
                        "servers" => f.member("servers", &servers_json),
                        "captured_at_utc" => f.member("captured_at_utc", fetched.as_str()),
                        _ => f.member("generator", GENERATOR),
                    }?;
                }
                Ok(())
            })
        })
    );
    let prov_tmp = tempfile::NamedTempFile::new_in(&corpus)
        .map_err(|e| format!("stage {}: {e}", prov_path.display()))?;
    std::fs::write(prov_tmp.path(), format!("{pretty}\n"))
        .map_err(|e| format!("write {}: {e}", prov_tmp.path().display()))?;

    // Commit: snapshot every destination's current bytes, then rename
    // the staged files into place (provenance last). A mid-commit
    // persist failure restores the snapshots — best effort — so the
    // corpus never keeps new fixtures beside a stale provenance.
    let mut pending = staged;
    pending.push((prov_tmp, prov_path.clone()));
    let backups: Vec<Option<Vec<u8>>> = pending
        .iter()
        .map(|(_, dst)| match std::fs::read(dst) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(format!("backup {}: {e}", dst.display())),
        })
        .collect::<Result<_, String>>()?;
    let mut done: Vec<(PathBuf, Option<Vec<u8>>)> = Vec::new();
    for ((tmp, dst), bak) in pending.into_iter().zip(backups) {
        if let Err(e) = tmp.persist(&dst) {
            // Restore already-replaced destinations; collect failures
            // rather than discard them so an unrestored corpus is
            // reported as inconsistent.
            let mut unrestored: Vec<String> = Vec::new();
            for (d, b) in &done {
                let res = match b {
                    Some(bytes) => std::fs::write(d, bytes),
                    None => std::fs::remove_file(d),
                };
                if let Err(re) = res {
                    unrestored.push(format!("{}: {re}", d.display()));
                }
            }
            let mut msg = format!("rename {}: {e}", dst.display());
            if !unrestored.is_empty() {
                msg.push_str(&format!(
                    "; rollback failed for {} — corpus may be inconsistent",
                    unrestored.join("; ")
                ));
            }
            return Err(msg);
        }
        done.push((dst, bak));
    }
    for (dst, _) in &done[..done.len() - 1] {
        println!("  wrote {}", posix_rel(dst, repo_root()));
    }
    println!("provenance -> {}", posix_rel(&prov_path, repo_root()));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The generated corpus policy must parse under the real loader —
    /// a KDL the validator rejects would turn every guarded capture
    /// into a launch refusal. The assertions double as the contract
    /// check: no deny rules (a deny under a broad grant is
    /// unexpressible on Landlock/AppContainer and refuses the launch),
    /// read access enumerated to system/install roots only, exec open.
    #[test]
    fn corpus_policy_parses_and_grants_no_secret_roots() {
        let scratch = tempfile::tempdir().unwrap();
        let kdl = corpus_policy("node", Path::new("/tmp/work"), scratch.path());
        let path = scratch.path().join("corpus.kdl");
        std::fs::write(&path, &kdl).unwrap();
        let policy = mcp_writ::policy::loader::load_policy(&path)
            .unwrap_or_else(|e| panic!("generated corpus policy must parse: {e}\n{kdl}"));
        assert!(
            policy.fs.denied_paths.is_empty(),
            "deny rules are unexpressible under the launch mechanisms: {:?}",
            policy.fs.denied_paths
        );
        assert!(
            policy
                .fs
                .executable
                .iter()
                .any(|p| p == "/**" || p == "*"),
            "exec stays open for arbitrary interpreter prefixes: {:?}",
            policy.fs.executable
        );
        // No read root may spell a glob (a '*' root would widen the
        // grant to every sibling — e.g. '/home/*' reaches every user's
        // dotfiles), and the whole-home mounts themselves never appear.
        for root in &policy.fs.read_only {
            assert!(
                !root.contains('*'),
                "read root must be a concrete path, not a glob: {root}"
            );
        }
        for forbidden in ["/home", "/root", "/mnt", "/tmp", "/Users", "C:/Users"] {
            assert!(
                !policy.fs.read_only.iter().any(|p| p == forbidden),
                "read root must not grant {forbidden}: {:?}",
                policy.fs.read_only
            );
        }
        // The user's own profile dir is never a root — an interpreter
        // under $HOME grants only its own install prefix, never the
        // profile itself.
        for var in ["HOME", "USERPROFILE"] {
            if let Some(home) = std::env::var_os(var) {
                let home = home.to_string_lossy().replace('\\', "/");
                let home = home.trim_end_matches('/');
                assert!(
                    !policy.fs.read_only.iter().any(|p| p == home),
                    "read root must not grant {home}: {:?}",
                    policy.fs.read_only
                );
            }
        }
    }
}
