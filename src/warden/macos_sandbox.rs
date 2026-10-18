//! macOS sandbox implementation using `sandbox-exec` and SBPL.
//!
//! Generates deny-default SBPL profiles from the existing [`Policy`] struct
//! and spawns child processes via `sandbox-exec -p <profile> -- <command>`.

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

#[cfg(unix)]
use libc::{SIGKILL, kill as libc_kill};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
#[cfg(unix)]
use std::os::unix::process::CommandExt;

use crate::enforcement::{ControlState, FsAccess, GrantOrigin, GrantSubject, ProcessGrant};
use crate::error::{SandboxStage, WardenError};
use crate::execution::TargetOs;
use crate::policy::Policy;
use crate::policy::validator::covers_or_same_for;

fn is_local_hostname(name: &str) -> bool {
    name == "localhost" || name == "*" || name == "127.0.0.1" || name == "[::1]" || name == "::1"
}

/// Whether `host` names an explicit loopback endpoint —
/// `localhost`, `127.0.0.1`, `::1`, or `[::1]` — with an optional
/// `:port`. Bare-port (`"443"`), wildcard (`"*:443"`, `":443"`), and
/// every other host form are NOT explicit: their destination set is
/// wider than loopback, so proxy mode routes them to the CONNECT
/// proxy rather than granting a direct `localhost:port` rule.
///
/// The `:port` split only applies where `:` can be a port separator:
/// `[v6]:port`, `name:port`, `v4:port`. A bare string with more than
/// one colon is an IPv6 literal — its colons are hex-field
/// separators, never a port split. The parser stores
/// `host="::1:8080"` as the v6 address `::1:8080` (not `::1` port
/// 8080), and stores `[::1]:8080` / `host="::1" port=8080` as the
/// bare literal `::1` plus a port qualifier — so the whole literal
/// is the host identity here.
fn is_explicit_loopback_host(host: &str) -> bool {
    let lower = host.trim().to_ascii_lowercase();
    if let Some((v6, _)) = lower
        .strip_prefix('[')
        .and_then(|rest| rest.split_once(']'))
    {
        return v6 == "::1";
    }
    if lower.matches(':').count() > 1 {
        return lower == "::1";
    }
    // At most one ':' remains — it can only be a port separator.
    let name = lower.split(':').next().unwrap_or(lower.as_str());
    matches!(name, "localhost" | "127.0.0.1")
}

/// Extract a port number from a host string.
///
/// Supports formats: `"localhost:8080"`, `"*:443"`, `":80"`, `"127.0.0.1:80"`,
/// or plain `"8080"`. Remote hostnames are not converted to localhost.
fn extract_local_port(host: &str) -> Result<Option<u16>, WardenError> {
    let trimmed = host.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    if let Ok(port) = trimmed.parse::<u16>() {
        return Ok(if port == 0 { None } else { Some(port) });
    }
    let lower = trimmed.to_ascii_lowercase();
    // Check the whole string before splitting on ':'. Bare IPv6 loopback
    // "::1" would otherwise become (":", "1") via rsplit_once.
    if is_local_hostname(&lower) {
        return Ok(None);
    }
    // A bare multi-colon string is an IPv6 literal, not host:port —
    // `::1:8080` is the v6 address `::1:8080`, never `::1` port 8080
    // (the policy grammar stores it exactly that way and rejects
    // unbracketed `v6:port` spellings for the same reason; the port
    // form is `[v6]:port`). Any non-loopback v6 literal is a remote
    // host for the localhost-only mechanism.
    if !lower.starts_with('[') && lower.matches(':').count() > 1 {
        return Err(WardenError::sandbox_setup(
            crate::error::SandboxStage::Policy,
            format!(
                "macOS SBPL cannot pin remote host '{trimmed}'; refuse rather than mapping to localhost"
            ),
        ));
    }
    let (name, port_part) = if let Some((h, p)) = lower.rsplit_once(':') {
        (h, Some(p))
    } else {
        (lower.as_str(), None)
    };
    let local = is_local_hostname(name) || name.is_empty();
    if !local {
        return Err(WardenError::sandbox_setup(
            crate::error::SandboxStage::Policy,
            format!(
                "macOS SBPL cannot pin remote host '{trimmed}'; refuse rather than mapping to localhost"
            ),
        ));
    }
    match port_part {
        Some(p) => p
            .parse::<u16>()
            .ok()
            .filter(|port| *port != 0)
            .map(Some)
            .ok_or_else(|| {
                WardenError::sandbox_setup(
                    crate::error::SandboxStage::Policy,
                    format!("invalid local port in '{trimmed}'"),
                )
            }),
        None => Ok(None),
    }
}

/// Escape a path for embedding in an SBPL string literal.
///
/// Only produces escapes that SBPL (TinyScheme) actually supports:
/// `\\`, `\"`, `\n`, `\r`, `\t`. Returns an error if the path contains
/// control characters that SBPL cannot represent (NUL or 0x01–0x1F
/// other than `\n`, `\r`, `\t`), since emitting unsupported escapes
/// would cause the sandbox rule to match a different path than intended.
fn escape_sbpl_path(path: &str) -> Result<String, WardenError> {
    let mut result = String::with_capacity(path.len());
    for ch in path.chars() {
        match ch {
            '\\' => result.push_str("\\\\"),
            '"' => result.push_str("\\\""),
            '\n' => result.push_str("\\n"),
            '\r' => result.push_str("\\r"),
            '\t' => result.push_str("\\t"),
            c if (c as u32) <= 0x1F || (c as u32) == 0x7F => {
                return Err(WardenError::sandbox_setup(
                    crate::error::SandboxStage::Policy,
                    format!(
                        "escape_sbpl_path: path contains control character U+{:04X} \
                         which SBPL cannot represent",
                        c as u32
                    ),
                ));
            }
            c => result.push(c),
        }
    }
    Ok(result)
}

// ---------------------------------------------------------------------------
// Workload code-map derivation
//
// A deny-default profile gates `file-map-executable`, which dyld needs
// for every dylib it loads from disk (shared-cache system libraries are
// covered by the /usr/lib + /System/Library grants below). A runtime
// whose code lives in a package-manager tree — Homebrew, MacPorts, Nix,
// a pyenv/nvm toolchain dir, the CommandLineTools a /usr/bin xcselect
// shim execs — dies in dyld before the workload runs. `code_map_dirs`
// derives the directories legitimately supplying that code at launch
// time from the resolved executable and argv, so no policy input is
// needed for the workload's own runtime.
//
// Every derived grant is read-only to the child (no file-write* on these
// dirs), so a granted dir can never become a drop-and-run channel — the
// same reason the private TMPDIR is never map-executable. The child can
// still try to exec anything it can map (process-exec is already
// unconditional); the grant merely says which already-installed code
// dyld may map.
// ---------------------------------------------------------------------------

/// Install trees whose whole subtree may supply code — granting the
/// prefix covers the package's dylibs, its dlopen'd modules, and every
/// sibling package the dependency walk would otherwise surface one root
/// at a time. Each is operator-installed, child-read-only content.
const RUNTIME_PREFIXES: &[&str] = &[
    "/opt/homebrew",                       // Homebrew (arm64)
    "/usr/local",                          // Homebrew (Intel) / manual installs
    "/opt/local",                          // MacPorts
    "/nix/store",                          // Nix store — content-addressed, read-only
    "/sw",                                 // Fink
    "/Library/Developer/CommandLineTools", // CLT toolchain + its python3
];

/// Immediate-parent names that mark the file's grandparent as the
/// package/toolchain root — `…/bin/python` ⇒ the venv/env dir that also
/// carries `lib/…/lib-dynload` or `node_modules`.
const CODE_LAYOUT_DIRS: &[&str] = &["bin", "sbin", "lib", "libexec", ".bin"];

/// Package/layout dirs one level above a payload file — `dist/`,
/// `build/` etc. — whose parent is the project root that may vendor
/// native code (node_modules with `.node` addons).
const PAYLOAD_LAYOUT_DIRS: &[&str] = &["dist", "build", "out", "src", "lib"];

/// Paths the base profile already makes readable — deriving a code root
/// inside them is redundant noise (their dyld-mappable subset,
/// /usr/lib + /System/Library, is already granted exec-map below).
const BASE_READ_ROOTS: &[&str] = &[
    "/bin",
    "/sbin",
    "/usr/bin",
    "/usr/sbin",
    "/usr/lib",
    "/usr/libexec",
    "/usr/share",
    "/System",
    "/private/etc",
    "/etc",
    "/dev",
    "/private/var/db/timezone",
];

/// `/usr/bin` interpreter shims (python3, ruby, …) are libxcselect
/// trampolines that re-exec the real binary inside CommandLineTools —
/// an indirection invisible to load-command analysis. Seeing the shim
/// library in a dep list means the CLT tree must be mappable.
const XCSELECT_DYLIB: &str = "libxcselect.dylib";
const CLT_ROOT: &str = "/Library/Developer/CommandLineTools";

/// dyld's built-in fallback for an `@rpath` reference with no matching
/// LC_RPATH (`~/lib` is deliberately absent — a home-dir library root
/// is not a system code source we bless).
const DYLD_FALLBACK_DIRS: &[&str] = &["/usr/local/lib", "/usr/lib"];

/// Dep-walk bounds: hostile or corrupt binaries cannot balloon the
/// derivation. Real interpreter closures (python → a dozen dylibs) sit
/// far below these.
const MAX_DEP_FILES: usize = 512;
const MAX_DEP_DEPTH: usize = 8;
const MAX_MACHO_BYTES: u64 = 64 * 1024 * 1024;

/// Whether `file` already sits under a base-profile read grant — such
/// files need no derived root (their exec/mmap coverage is unchanged
/// from today; only files *outside* need new grants).
fn under_base_read_roots(file: &Path) -> bool {
    BASE_READ_ROOTS
        .iter()
        .map(Path::new)
        .any(|root| file.starts_with(root))
}

/// The directory that supplies `file`'s code context:
/// - under a package-manager runtime prefix → that prefix;
/// - `…/<code-layout-dir>/<file>` → the package root (the dir that also
///   holds `lib/` with the runtime's dlopen'd modules);
/// - `payload` files under a `…/<payload-layout-dir>/` → the project
///   root that may vendor native addons next to it (`node_modules/`);
/// - otherwise → the file's own directory.
///
/// Returns `None` for files already covered by the base profile and for
/// candidates too shallow to bless (`/usr`, `/`) — the two-levels-below-
/// root minimum keeps the grant from ever reaching a system root.
fn code_root_for(file: &Path, payload: bool) -> Option<PathBuf> {
    if under_base_read_roots(file) {
        return None;
    }
    for prefix in RUNTIME_PREFIXES {
        let p = Path::new(prefix);
        if file.starts_with(p) && p.is_dir() {
            return Some(p.to_path_buf());
        }
    }
    let parent = file.parent()?;
    let climbed = match parent.file_name().and_then(|n| n.to_str()) {
        Some(name) if CODE_LAYOUT_DIRS.contains(&name) => parent.parent().unwrap_or(parent),
        Some(name) if payload && PAYLOAD_LAYOUT_DIRS.contains(&name) => {
            parent.parent().unwrap_or(parent)
        }
        _ => parent,
    };
    accept_code_dir(climbed).or_else(|| accept_code_dir(parent))
}

fn accept_code_dir(dir: &Path) -> Option<PathBuf> {
    // Depth ≥ 3 (`/a/b/c`…, i.e. two components below root) keeps the
    // grant below component roots like `/usr`, `/opt`, or `/Library`;
    // nonexistent or base-covered dirs are out.
    if dir.components().count() < 3 || under_base_read_roots(dir) || !dir.is_dir() {
        return None;
    }
    Some(dir.to_path_buf())
}

/// Expand `@loader_path`/`@executable_path` inside an install name or
/// LC_RPATH value. Anything else is returned unchanged.
fn expand_dyld_var(name: &str, loader_dir: &Path, exe_dir: &Path) -> PathBuf {
    if let Some(rest) = name.strip_prefix("@loader_path/") {
        loader_dir.join(rest)
    } else if let Some(rest) = name.strip_prefix("@executable_path/") {
        exe_dir.join(rest)
    } else {
        PathBuf::from(name)
    }
}

/// Candidate real paths for one Mach-O library reference. `@rpath`
/// expands against the accumulated rpath set plus dyld's fallback
/// dirs; candidates that do not exist are simply never queued.
fn dep_candidates(
    name: &str,
    loader_dir: &Path,
    exe_dir: &Path,
    rpaths: &[PathBuf],
) -> Vec<PathBuf> {
    if let Some(rest) = name.strip_prefix("@rpath/") {
        let mut out: Vec<PathBuf> = rpaths.iter().map(|rp| rp.join(rest)).collect();
        out.extend(DYLD_FALLBACK_DIRS.iter().map(|d| Path::new(d).join(rest)));
        out
    } else {
        vec![expand_dyld_var(name, loader_dir, exe_dir)]
    }
}

/// `(libs, rpaths)` pairs for every Mach-O slice in `bytes` — fat
/// containers contribute all arches so the grant set stays correct
/// regardless of which slice the machine runs.
fn macho_linkage(bytes: &[u8]) -> Vec<(Vec<String>, Vec<String>)> {
    use goblin::mach::{Mach, SingleArch};
    let mut slices = Vec::new();
    match Mach::parse(bytes) {
        Ok(Mach::Binary(m)) => slices.push(m),
        Ok(Mach::Fat(multi)) => {
            // Each arch slice parses lazily — a corrupt slice skips,
            // it does not poison the others.
            for arch in &multi {
                if let Ok(SingleArch::MachO(m)) = arch {
                    slices.push(m);
                }
            }
        }
        _ => return Vec::new(),
    }
    slices
        .iter()
        .map(|m| {
            (
                m.libs
                    .iter()
                    .filter(|l| **l != "self")
                    .map(|l| l.to_string())
                    .collect(),
                m.rpaths.iter().map(|r| r.to_string()).collect(),
            )
        })
        .collect()
}

/// The directories the workload legitimately maps code from — every
/// entry lands as `file-read* + file-map-executable` in the profile.
///
/// Inputs: the *resolved* executable path (spelling and canonical forms
/// are both considered — a `venv/bin/python` spelling contributes the
/// venv root even though its canonical target lives in Homebrew) and
/// the launch argv, from which an interpreted payload's package dir is
/// derived (the interpreter reads the script by path, and the project
/// dir may vendor native addons it dlopens).
///
/// The executable's Mach-O dylib references are followed transitively —
/// that is what surfaces out-of-prefix dependencies a prefix table
/// cannot see (a `/usr/bin/python3` shim reaching CommandLineTools, a
/// vendored binary linking `/opt/other/lib`). Bounded by
/// `MAX_DEP_FILES`/`MAX_DEP_DEPTH`/`MAX_MACHO_BYTES`; a file that fails
/// to parse simply contributes no deps — the derivation is best-effort
/// because a missed grant surfaces as a dyld error at exec, never as a
/// widened profile.
pub(crate) fn code_map_dirs(exe: &Path, argv: &[String]) -> Vec<PathBuf> {
    use std::collections::{BTreeSet, HashSet, VecDeque};

    let mut roots: BTreeSet<PathBuf> = BTreeSet::new();
    // Keyed by (canonical path, payload flag): a payload file that is
    // also a Mach-O dep must still contribute its project-root climb.
    let mut seen: HashSet<(PathBuf, bool)> = HashSet::new();
    let mut rpaths: Vec<PathBuf> = Vec::new();
    let mut queue: VecDeque<(PathBuf, usize, bool)> = VecDeque::new();
    let mut xcselect = false;

    let canon_exe = exe.canonicalize().unwrap_or_else(|_| exe.to_path_buf());
    let exe_dir = canon_exe
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("/"));

    // Seeds: spelled exe (venv/toolchain link spellings carry their own
    // package root), canonical exe (drives the dep walk), and — for an
    // interpreted launch — the payload script.
    let mut seeds = vec![(exe.to_path_buf(), false), (canon_exe.clone(), false)];
    if exe
        .file_name()
        .and_then(|n| n.to_str())
        .and_then(crate::workload::interpreter_from_command)
        .is_some()
        && let Some(i) = crate::workload::first_payload_arg_index_with_exe(argv, Some(exe))
    {
        seeds.push((PathBuf::from(&argv[i]), true));
    }
    for (seed, payload) in seeds {
        queue.push_back((seed, 0, payload));
    }

    while let Some((file, depth, payload)) = queue.pop_front() {
        if seen.len() >= MAX_DEP_FILES {
            break;
        }
        let canon = file.canonicalize().unwrap_or(file);
        if !seen.insert((canon.clone(), payload)) {
            continue;
        }
        if let Some(root) = code_root_for(&canon, payload) {
            roots.insert(root);
        }
        if depth >= MAX_DEP_DEPTH {
            continue;
        }
        match std::fs::metadata(&canon) {
            Ok(m) if m.is_file() && m.len() <= MAX_MACHO_BYTES => {}
            _ => continue,
        }
        let bytes = match std::fs::read(&canon) {
            Ok(b) => b,
            Err(_) => continue,
        };
        let loader_dir = canon
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from("/"));
        for (libs, file_rpaths) in macho_linkage(&bytes) {
            for rp in file_rpaths {
                let expanded = expand_dyld_var(&rp, &loader_dir, &exe_dir);
                if !rpaths.contains(&expanded) {
                    rpaths.push(expanded);
                }
            }
            for lib in libs {
                if lib.contains(XCSELECT_DYLIB) {
                    xcselect = true;
                }
                for cand in dep_candidates(&lib, &loader_dir, &exe_dir, &rpaths) {
                    if cand.exists() {
                        queue.push_back((cand, depth + 1, false));
                    }
                }
            }
        }
    }

    // A libxcselect shim re-execs CommandLineTools binaries whose whole
    // tree must map — the one indirection load commands cannot show.
    if xcselect {
        let clt = Path::new(CLT_ROOT);
        if clt.is_dir() {
            roots.insert(clt.to_path_buf());
        }
    }
    roots.into_iter().collect()
}

/// Generate a deny-default SBPL profile from the given policy.
#[cfg(test)]
pub fn generate_sbpl(policy: &Policy) -> Result<String, WardenError> {
    generate_sbpl_with_tmpdir(policy, "/private/tmp/mcp-writ-unused")
}

/// Generate SBPL that permits writes only under `tmpdir` (a private directory).
pub fn generate_sbpl_with_tmpdir(policy: &Policy, tmpdir: &str) -> Result<String, WardenError> {
    Ok(sbpl_profile(policy, tmpdir, &[])?.0)
}

/// How the profile's network section is built.
///
/// `Native` is the historical behavior: under `deny_all_others` only
/// `localhost:port` entries extracted from `allow host=` rules emit
/// remote-TCP allows, everything else is kernel-denied; without it the
/// profile grants unrestricted `network-outbound` (+ `network-bind`
/// when `allow_listen` is set). `ConnectProxy` is the PR-11 opt-in:
/// the only remote-TCP endpoint the kernel lets the workload reach is
/// the loopback CONNECT proxy (plus any `localhost:port` rules the
/// policy declares) — the policy's real destination rules are enforced
/// by the proxy, not by SBPL, so `deny_all_others` never widens to
/// unrestricted outbound and the OS resolver (mDNSResponder) is not
/// granted at all (an OS-resolved name could reach an external DNS
/// server the policy never judged — resolution is the proxy's job).
pub(super) enum EgressProfile {
    Native,
    ConnectProxy { proxy_port: u16 },
}

/// Generate the SBPL profile together with the grant entries the same
/// emission produced — the launch report lists exactly these entries, so
/// the permission table can never diverge from the generated profile.
///
/// `grants` describes the *profile contents* (what the profile would
/// permit). Whether the kernel accepted the profile is a separate,
/// control-level observation — `sandbox-exec` does not expose it.
pub(super) fn sbpl_profile(
    policy: &Policy,
    tmpdir: &str,
    exec_map_dirs: &[PathBuf],
) -> Result<(String, Vec<ProcessGrant>), WardenError> {
    sbpl_profile_with_egress(policy, tmpdir, EgressProfile::Native, exec_map_dirs)
}

/// [`sbpl_profile`] with an explicit egress mode — see
/// [`EgressProfile`] for what the two modes emit. `exec_map_dirs`
/// names the dirs whose contents the child may map executable: a pin
/// plan's snapshot staging dirs plus the workload's derived code roots
/// (see [`code_map_dirs`]). Empty when nothing sandbox-mappable is
/// pinned or derivable — the profile then permits code only from the
/// base system-library grants.
pub(super) fn sbpl_profile_with_egress(
    policy: &Policy,
    tmpdir: &str,
    egress: EgressProfile,
    exec_map_dirs: &[PathBuf],
) -> Result<(String, Vec<ProcessGrant>), WardenError> {
    let mut p = String::with_capacity(2048);
    let mut grants: Vec<ProcessGrant> = Vec::new();

    fn fs_grant(
        grants: &mut Vec<ProcessGrant>,
        path: &str,
        access: FsAccess,
        origin: GrantOrigin,
        reason: Option<&str>,
    ) {
        grants.push(ProcessGrant {
            subject: GrantSubject::FsPath {
                path: path.to_string(),
                access,
            },
            origin,
            state: ControlState::Planned,
            reason: reason.map(str::to_string),
        });
    }
    fn rule_grant(
        grants: &mut Vec<ProcessGrant>,
        kind: &'static str,
        name: &str,
        origin: GrantOrigin,
    ) {
        grants.push(ProcessGrant {
            subject: GrantSubject::Rule {
                kind,
                name: name.to_string(),
            },
            origin,
            state: ControlState::Planned,
            reason: None,
        });
    }
    /// Emit `(allow <rule_body>)` and record the matching grant — one
    /// call keeps the profile line and the grant entry on the same
    /// inputs, so the launch report cannot diverge from the profile.
    fn emit_rule(
        p: &mut String,
        grants: &mut Vec<ProcessGrant>,
        rule_body: &str,
        kind: &'static str,
        name: &str,
        origin: GrantOrigin,
    ) {
        p.push_str(&format!("(allow {rule_body})\n"));
        rule_grant(grants, kind, name, origin);
    }
    /// Emit `(allow <op> (<selector> "<path>"))`, record the matching fs
    /// grant, and queue `path` as an ancestor/symlink walk input — the
    /// SBPL line, the grant entry, and the walk input share one source.
    #[expect(clippy::too_many_arguments)]
    fn emit_fs(
        p: &mut String,
        grants: &mut Vec<ProcessGrant>,
        walk_inputs: &mut Vec<String>,
        op: &str,
        selector: &str,
        path: &str,
        access: FsAccess,
        origin: GrantOrigin,
    ) {
        p.push_str(&format!("(allow {op} ({selector} \"{path}\"))\n"));
        fs_grant(grants, path, access, origin, None);
        walk_inputs.push(path.to_string());
    }
    // Paths the ancestor/symlink walk must cover — every path the
    // profile grants, collected as each rule emits. The launch report
    // and this walk can never diverge from the generated profile.
    let mut walk_inputs: Vec<String> = Vec::new();

    // --- Base: deny-default ---
    p.push_str("(version 1)\n(deny default)\n");

    // --- Essential process operations ---
    for op in [
        "process-fork",
        "process-exec",
        "signal (target self)",
        "process-info* (target same-sandbox)",
        "sysctl-read",
    ] {
        emit_rule(
            &mut p,
            &mut grants,
            op,
            "operation",
            op,
            GrantOrigin::OsImplementation,
        );
    }

    // --- System library reads (required by most processes) ---
    for path in ["/usr/lib", "/System/Library", "/usr/share"] {
        emit_fs(
            &mut p,
            &mut grants,
            &mut walk_inputs,
            "file-read*",
            "subpath",
            path,
            FsAccess::Read,
            GrantOrigin::OsImplementation,
        );
    }

    // --- Dynamic library/framework mapping (required by dyld) ---
    for path in ["/usr/lib", "/System/Library"] {
        emit_rule(
            &mut p,
            &mut grants,
            &format!("file-map-executable (subpath \"{path}\")"),
            "file_map_executable",
            path,
            GrantOrigin::OsImplementation,
        );
    }

    // --- Executable binary paths (required for exec to load binaries) ---
    for path in ["/bin", "/sbin", "/usr/bin", "/usr/sbin", "/usr/libexec"] {
        emit_fs(
            &mut p,
            &mut grants,
            &mut walk_inputs,
            "file-read-data file-read-metadata",
            "subpath",
            path,
            FsAccess::Read,
            GrantOrigin::OsImplementation,
        );
    }

    // --- Standard config and metadata paths ---
    for path in [
        "/etc/hosts",
        "/etc/resolv.conf",
        "/private/etc/hosts",
        "/private/etc/resolv.conf",
        "/",
    ] {
        emit_fs(
            &mut p,
            &mut grants,
            &mut walk_inputs,
            "file-read*",
            "literal",
            path,
            FsAccess::Read,
            GrantOrigin::OsImplementation,
        );
    }

    // Local timezone data: tz detection (tzlocal, ICU) reads
    // /etc/localtime -> /var/db/timezone/zoneinfo/…; without it a
    // sandboxed server silently computes a different local zone than the
    // unsandboxed host.
    for (selector, path) in [
        ("literal", "/etc/localtime"),
        ("literal", "/private/etc/localtime"),
        ("subpath", "/private/var/db/timezone"),
    ] {
        emit_fs(
            &mut p,
            &mut grants,
            &mut walk_inputs,
            "file-read*",
            selector,
            path,
            FsAccess::Read,
            GrantOrigin::OsImplementation,
        );
    }

    // --- Symlink resolution metadata ---
    p.push_str("(allow file-read-metadata (literal \"/var\"))\n");
    fs_grant(
        &mut grants,
        "/var",
        FsAccess::Traverse,
        GrantOrigin::OsImplementation,
        None,
    );

    // --- Device nodes ---
    for (op, selector, path, access) in [
        ("file-read*", "literal", "/dev/null", FsAccess::Read),
        ("file-read*", "literal", "/dev/urandom", FsAccess::Read),
        ("file-read*", "literal", "/dev/random", FsAccess::Read),
        (
            "file-write-data",
            "literal",
            "/dev/null",
            FsAccess::ReadWrite,
        ),
        (
            "file-read-data file-write-data",
            "subpath",
            "/dev/fd",
            FsAccess::ReadWrite,
        ),
    ] {
        emit_fs(
            &mut p,
            &mut grants,
            &mut walk_inputs,
            op,
            selector,
            path,
            access,
            GrantOrigin::OsImplementation,
        );
    }

    // --- Private TMPDIR only (no shared /tmp or /private/tmp) ---
    let escaped_tmp = escape_sbpl_path(tmpdir)?;
    p.push_str(&format!(
        "(allow file-read* file-write* (subpath \"{escaped_tmp}\"))\n"
    ));
    grants.push(ProcessGrant {
        subject: GrantSubject::PrivateTmpdir,
        origin: GrantOrigin::Runtime,
        state: ControlState::Planned,
        reason: None,
    });
    walk_inputs.push(tmpdir.to_string());

    // --- IOKit (required for basic system queries) ---
    emit_rule(
        &mut p,
        &mut grants,
        "iokit-open (iokit-registry-entry-class \"RootDomainUserClient\")",
        "iokit_open",
        "RootDomainUserClient",
        GrantOrigin::OsImplementation,
    );

    // --- Mach services (required for basic operation) ---
    let mach_services = [
        "com.apple.system.logger",
        "com.apple.system.opendirectoryd.libinfo",
        "com.apple.system.DirectoryService.libinfo_v1",
        "com.apple.trustd",
        "com.apple.trustd.agent",
        "com.apple.cfprefsd.daemon",
        "com.apple.cfprefsd.agent",
        "com.apple.logd",
        "com.apple.secinitd",
        "com.apple.bsd.dirhelper",
    ];
    p.push_str("(allow mach-lookup\n");
    for (i, service) in mach_services.iter().enumerate() {
        let closing = if i + 1 == mach_services.len() {
            ")"
        } else {
            ""
        };
        p.push_str(&format!("  (global-name \"{service}\"){closing}\n"));
        rule_grant(
            &mut grants,
            "mach_lookup",
            service,
            GrantOrigin::OsImplementation,
        );
    }

    // --- Syslog socket (required for logging) ---
    emit_rule(
        &mut p,
        &mut grants,
        "network-outbound (literal \"/private/var/run/syslog\")",
        "unix_socket_outbound",
        "/private/var/run/syslog",
        GrantOrigin::OsImplementation,
    );

    // Spelled-path conflict checks ran at load time, but a grant like
    // `/etc` canonicalizes to `/private/etc` and could still reach a
    // denied subtree the spelled comparison never saw — under
    // deny-default SBPL an `(allow …)` line is the only thing that would
    // reopen it, so re-check the canonical forms.
    let denied_canon: Vec<String> = policy
        .fs
        .denied_paths
        .iter()
        .map(|d| canonical_grant_path(d))
        .collect();

    // The same canonical-form argument applies to the writable set: the
    // load-time writable∩executable check compares spelled paths, and
    // runtime-derived exec roots never pass through it at all, so the
    // drop-and-run check has to re-run here on resolved spellings.
    // `tmpdir` is part of the writable surface — its `(allow …
    // file-write* (subpath))` line is emitted above.
    let writable_canon: Vec<String> = policy
        .fs
        .read_write
        .iter()
        .map(|w| canonical_grant_path(w))
        .chain(std::iter::once(canonical_grant_path(tmpdir)))
        .collect();
    // Writable paths sitting strictly inside an exec grant — carved out
    // of exec-map coverage below, after every allow lands.
    let mut writable_carves: std::collections::BTreeSet<usize> = std::collections::BTreeSet::new();

    // --- Policy: read-only paths ---
    for path in &policy.fs.read_only {
        let canon = canonical_grant_path(path);
        reject_denied_grant(path, &canon, &denied_canon)?;
        let escaped = escape_sbpl_path(&canon)?;
        p.push_str(&format!("(allow file-read* (subpath \"{escaped}\"))\n"));
        // Record the canonical path the SBPL line actually grants; keep the
        // spelled form in the reason when canonicalization rewrote it, and
        // feed the spelled form to the ancestor/symlink walk — the spelled
        // chain is where its symlink hops live.
        let reason = (canon != *path).then(|| format!("canonicalized from {path}"));
        fs_grant(
            &mut grants,
            &canon,
            FsAccess::Read,
            GrantOrigin::Policy,
            reason.as_deref(),
        );
        walk_inputs.push(path.clone());
    }

    // --- Policy: read-write paths ---
    for path in &policy.fs.read_write {
        let canon = canonical_grant_path(path);
        reject_denied_grant(path, &canon, &denied_canon)?;
        let escaped = escape_sbpl_path(&canon)?;
        p.push_str(&format!(
            "(allow file-read* file-write* (subpath \"{escaped}\"))\n"
        ));
        let reason = (canon != *path).then(|| format!("canonicalized from {path}"));
        fs_grant(
            &mut grants,
            &canon,
            FsAccess::ReadWrite,
            GrantOrigin::Policy,
            reason.as_deref(),
        );
        walk_inputs.push(path.clone());
    }

    // --- Policy: executable paths (`mode="exec"`) ---
    // Readable AND mappable as code — a runtime prefix or project dir
    // the user opts in to as a code source. Never writable: the grammar
    // keeps exec disjoint from mode="write" so the profile's
    // writable-never-executable invariant cannot be escaped by policy.
    for path in &policy.fs.executable {
        let canon = canonical_grant_path(path);
        reject_denied_grant(path, &canon, &denied_canon)?;
        reject_exec_in_writable(path, &canon, &writable_canon, &mut writable_carves)?;
        let escaped = escape_sbpl_path(&canon)?;
        p.push_str(&format!(
            "(allow file-read* file-map-executable (subpath \"{escaped}\"))\n"
        ));
        let reason = (canon != *path).then(|| format!("canonicalized from {path}"));
        fs_grant(
            &mut grants,
            &canon,
            FsAccess::Execute,
            GrantOrigin::Policy,
            reason.as_deref(),
        );
        walk_inputs.push(path.clone());
    }

    // --- Exec-mappable dirs: staged snapshot dirs (a pinned workload
    //     execs the staged copies by path — macOS has no exec'able fd
    //     spelling) and derived workload code roots (runtime prefixes,
    //     dylib package dirs, payload dirs). Read + executable-map but
    //     no write — the child can never turn one into a drop-and-run
    //     channel, matching the private-TMPDIR posture. BTreeSet dedups
    //     overlapping derivations and keeps the profile text sorted.
    for staged in {
        let mut set = std::collections::BTreeSet::new();
        for d in exec_map_dirs {
            set.insert(d.to_string_lossy().into_owned());
        }
        set
    } {
        let canon = canonical_grant_path(&staged);
        reject_denied_grant(&staged, &canon, &denied_canon)?;
        reject_exec_in_writable(&staged, &canon, &writable_canon, &mut writable_carves)?;
        let escaped = escape_sbpl_path(&canon)?;
        p.push_str(&format!(
            "(allow file-read* file-map-executable (subpath \"{escaped}\"))\n"
        ));
        fs_grant(
            &mut grants,
            &canon,
            FsAccess::Execute,
            GrantOrigin::Runtime,
            None,
        );
        walk_inputs.push(staged);
    }

    // --- Exec-map carve-outs: a writable path nested inside an exec
    //     grant keeps its declared read+write coverage but can never
    //     supply code — the derived exec-map breadth is what narrows.
    //     Emitted after every map-executable allow because SBPL takes
    //     the last matching rule.
    for i in writable_carves {
        let escaped = escape_sbpl_path(&writable_canon[i])?;
        p.push_str(&format!(
            "(deny file-map-executable (subpath \"{escaped}\"))\n"
        ));
    }

    // --- Traversal: a granted path is unreachable when its ancestors
    // cannot even be stat'd — runtimes walk components explicitly
    // (Node's realpathSync module loader, CPython's getpath realpath).
    // Grant metadata on every ancestor of every granted path; "/" is
    // already covered by the literal above. Symlink hops in the spelled
    // form additionally need file-read-data — following the link is a
    // read of the link vnode (e.g. /tmp -> private/tmp).
    // BTreeSet: SBPL lines and grant entries are emitted in sorted order
    // so the same policy always produces the same profile text.
    //
    // /bin/sh is a shim that opens this symlink at startup to pick the
    // real shell; it is a walk input only — the leaf-symlink check below
    // grants file-read* on it.
    walk_inputs.push("/private/var/select/sh".to_string());
    let mut ancestors = std::collections::BTreeSet::new();
    let mut links = std::collections::BTreeSet::new();
    for spelled in &walk_inputs {
        for anc in Path::new(&canonical_grant_path(spelled))
            .ancestors()
            .skip(1)
        {
            let s = anc.to_string_lossy().into_owned();
            if s != "/" {
                ancestors.insert(s);
            }
        }
        let spelled_path = Path::new(spelled.as_str());
        for anc in spelled_path.ancestors() {
            if anc.parent().is_none() {
                continue;
            }
            let s = anc.to_string_lossy().into_owned();
            let is_link = std::fs::symlink_metadata(anc)
                .map(|m| m.file_type().is_symlink())
                .unwrap_or(false);
            if is_link {
                links.insert(s);
            } else if anc != spelled_path {
                ancestors.insert(s);
            }
        }
    }
    for s in links {
        let escaped = escape_sbpl_path(&s)?;
        p.push_str(&format!("(allow file-read* (literal \"{escaped}\"))\n"));
        fs_grant(
            &mut grants,
            &s,
            FsAccess::Read,
            GrantOrigin::Runtime,
            Some("symlink hop on a granted path"),
        );
    }
    for s in ancestors {
        let escaped = escape_sbpl_path(&s)?;
        p.push_str(&format!(
            "(allow file-read-metadata (literal \"{escaped}\"))\n"
        ));
        fs_grant(
            &mut grants,
            &s,
            FsAccess::Traverse,
            GrantOrigin::Runtime,
            Some("ancestor of a granted path"),
        );
    }

    // --- Network rules ---
    let proxied = matches!(egress, EgressProfile::ConnectProxy { .. });
    if let EgressProfile::ConnectProxy { proxy_port } = egress {
        // The single endpoint every outbound TCP connect is pinned to —
        // the loopback CONNECT proxy, which evaluates the policy's real
        // destination rules. Emitted unconditionally so the kernel
        // never sees an unrestricted `network-outbound`, whatever the
        // policy's default posture says.
        emit_rule(
            &mut p,
            &mut grants,
            &format!("network-outbound (remote tcp \"localhost:{proxy_port}\")"),
            "connect_proxy",
            &format!("localhost:{proxy_port}"),
            GrantOrigin::Runtime,
        );
    }
    if proxied || policy.network.outbound.deny_all_others {
        // Consume the allow rules *with* their qualifiers, not the
        // flat `allowed`/`allowed_cidrs` lists: a parsed
        // `allow host="localhost:8080"` folds its port out of
        // `allowed` (`allowed_port_qualified` keeps the spelling), and
        // bare-port / scoped-wildcard entries (`443`, `* port=443`)
        // exist only in `egress_rules` — iterating the flat lists
        // would emit no rule for any of them. The qualifiers also
        // gate the emit itself: SBPL `remote tcp` rules carry no
        // proto, so a `proto=udp`-only rule must be skipped rather
        // than silently widened to a TCP grant it never declared.
        for rule in policy
            .network
            .outbound
            .egress_rules()
            .iter()
            .filter(|r| r.allow)
        {
            let host = match &rule.dest {
                crate::policy::EgressDest::Host(h) => h.as_str(),
                // `cidr` entries are IP-layer rules — the SBPL profile
                // can only express `localhost:port` remote endpoints,
                // so none of them emit a rule.
                crate::policy::EgressDest::Cidr(cidr) => {
                    grants.push(ProcessGrant {
                        subject: GrantSubject::Rule {
                            kind: "net_destination_cidr",
                            name: cidr.clone(),
                        },
                        origin: GrantOrigin::Policy,
                        state: ControlState::Skipped,
                        reason: Some(if proxied {
                            "SBPL remote rules express localhost ports only — this \
                             IP-layer entry is enforced by the CONNECT proxy"
                                .to_string()
                        } else {
                            "SBPL remote rules express localhost ports only — this \
                             IP-layer entry is enforced at the RPC layer only"
                                .to_string()
                        }),
                    });
                    continue;
                }
                // `allow unix=` is a Linux-only opt-in — the schema
                // validator refuses it off Linux, so the arm only
                // guards a programmatic policy that skipped
                // validation.
                crate::policy::EgressDest::Unix(u) => {
                    grants.push(ProcessGrant {
                        subject: GrantSubject::Rule {
                            kind: "unix_connect",
                            name: format!("unix={u}"),
                        },
                        origin: GrantOrigin::Policy,
                        state: ControlState::Skipped,
                        reason: Some(
                            "AF_UNIX opt-ins are a Linux-only opt-in — the SBPL \
                             profile cannot express socket-path grants"
                                .to_string(),
                        ),
                    });
                    continue;
                }
            };
            // The grant row names the effective destination spelling
            // (`host` plus a declared `:port` the flat list folded).
            let rule_name = match rule.port {
                Some(port) => format!("{host}:{port}"),
                None => host.to_string(),
            };
            let skip = |grants: &mut Vec<ProcessGrant>, reason: String| {
                grants.push(ProcessGrant {
                    subject: GrantSubject::Rule {
                        kind: "tcp_host",
                        name: rule_name.clone(),
                    },
                    origin: GrantOrigin::Policy,
                    state: ControlState::Skipped,
                    reason: Some(reason),
                });
            };
            // A rule whose qualifiers cover no TCP gets no rule —
            // emitting `remote tcp` would grant a TCP reach the
            // policy never allowed (the SBPL form cannot express
            // proto).
            let tcp_blocked = !rule.proto.covers(crate::policy::EgressProto::Tcp);
            let extracted = match extract_local_port(host) {
                Ok(spelled_port) => {
                    // `Ok` = a local shape (loopback name, wildcard,
                    // or bare port); the effective port is the
                    // spelling's own port else the rule qualifier's.
                    spelled_port.or(rule.port)
                }
                Err(e) => {
                    // In proxy mode a remote host/name is not a build
                    // failure (the proxy enforces it); under the native
                    // path the refusal contract of `extract_local_port`
                    // still applies — propagate it there.
                    if !proxied {
                        return Err(e);
                    }
                    let reason = if tcp_blocked {
                        "no local port extracted and no TCP coverage — no SBPL rule \
                         is emitted; UDP has no CONNECT-proxy path and is denied \
                         outright, so the rule authorizes nothing on this path"
                            .to_string()
                    } else {
                        "no local port extracted; no SBPL rule is emitted — \
                         this destination is enforced by the CONNECT proxy"
                            .to_string()
                    };
                    skip(&mut grants, reason);
                    continue;
                }
            };
            match extracted {
                Some(port) => {
                    if proxied && !is_explicit_loopback_host(host) {
                        // Proxy mode: only an entry that names an
                        // explicit loopback endpoint gets a direct
                        // `localhost:port` rule — bare-port and
                        // `*`-wildcard spellings name a wider
                        // destination set than loopback, so they route
                        // to the CONNECT proxy (which judges each
                        // CONNECT authority) instead of a direct SBPL
                        // grant the policy did not declare.
                        skip(
                            &mut grants,
                            "not an explicit loopback endpoint; no SBPL rule is \
                             emitted — this destination is enforced by the CONNECT \
                             proxy"
                                .to_string(),
                        );
                    } else if tcp_blocked {
                        skip(
                            &mut grants,
                            if proxied {
                                "rule covers no TCP and UDP egress is denied outright \
                                 on this path — no SBPL rule is emitted"
                                    .to_string()
                            } else {
                                "rule covers no TCP — SBPL remote rules are tcp-only, \
                                 so emitting one would widen it; enforced at the RPC \
                                 layer only"
                                    .to_string()
                            },
                        );
                    } else {
                        emit_rule(
                            &mut p,
                            &mut grants,
                            &format!("network-outbound (remote tcp \"localhost:{port}\")"),
                            "tcp_loopback",
                            &format!("localhost:{port}"),
                            GrantOrigin::Policy,
                        );
                    }
                }
                None => {
                    if tcp_blocked {
                        skip(
                            &mut grants,
                            if proxied {
                                "rule covers no TCP and UDP egress is denied outright \
                                 on this path — no SBPL rule is emitted"
                                    .to_string()
                            } else {
                                "rule covers no TCP — SBPL remote rules are tcp-only, \
                                 so emitting one would widen it; enforced at the RPC \
                                 layer only"
                                    .to_string()
                            },
                        );
                    } else {
                        skip(
                            &mut grants,
                            if proxied {
                                "no local port extracted; no SBPL rule is emitted — \
                                 this destination is enforced by the CONNECT proxy"
                                    .to_string()
                            } else {
                                "no local port extracted; no SBPL rule is emitted — \
                                 this entry is enforced at the RPC layer only"
                                    .to_string()
                            },
                        );
                    }
                }
            }
        }
        // In proxy mode `allow_listen` is honored as loopback-only: the
        // workload may bind/accept TCP on loopback, never an external
        // interface. UDP has no proxy path and stays fully denied.
        if proxied && policy.network.inbound.allow_listen {
            emit_rule(
                &mut p,
                &mut grants,
                "network-bind (local tcp \"localhost:*\")",
                "network_bind",
                "loopback-only (proxy mode)",
                GrantOrigin::Policy,
            );
            emit_rule(
                &mut p,
                &mut grants,
                "network-inbound (local tcp \"localhost:*\")",
                "network_inbound",
                "loopback-only (proxy mode)",
                GrantOrigin::Policy,
            );
        }
    } else {
        emit_rule(
            &mut p,
            &mut grants,
            "network-outbound",
            "network_outbound",
            "unrestricted",
            GrantOrigin::Policy,
        );
        if policy.network.inbound.allow_listen {
            emit_rule(
                &mut p,
                &mut grants,
                "network-bind",
                "network_bind",
                "unrestricted",
                GrantOrigin::Policy,
            );
        }
    }

    // --- DNS resolution (allow mDNSResponder for name resolution) ---
    // In CONNECT-proxy mode the OS resolver stays denied: an
    // OS-resolved name could reach an upstream DNS server the policy
    // never judged (a covert egress channel), and proxied clients do
    // not need it — they hand the hostname to the proxy, which resolves
    // outside the sandbox. `getaddrinfo` inside the workload simply
    // fails — the fail-closed posture the improvement plan prescribes.
    if !proxied {
        emit_rule(
            &mut p,
            &mut grants,
            "mach-lookup (global-name \"com.apple.mDNSResponder\")",
            "mach_lookup",
            "com.apple.mDNSResponder",
            GrantOrigin::OsImplementation,
        );
    }

    Ok((p, grants))
}

/// Resolve a policy path to the form the kernel matches. Sandbox filters
/// compare the fully-resolved vnode path, so a grant written as `/tmp/x`
/// would never match `/private/tmp/x`. Canonicalize the deepest existing
/// ancestor and reattach the remainder so write targets that do not
/// exist yet still resolve; fall back to the literal when nothing does.
fn canonical_grant_path(path: &str) -> String {
    let mut cursor = Path::new(path).to_path_buf();
    let mut tail = Vec::new();
    loop {
        match cursor.canonicalize() {
            Ok(mut canon) => {
                for seg in tail.iter().rev() {
                    canon.push(seg);
                }
                return canon.to_string_lossy().into_owned();
            }
            Err(_) => match cursor.file_name() {
                Some(name) => {
                    tail.push(name.to_os_string());
                    cursor.pop();
                }
                None => return path.to_string(),
            },
        }
    }
}

/// A canonicalized grant must not equal, contain, or sit inside a
/// canonicalized denied path — any overlap means the `(allow …)` line
/// would silently re-allow what the policy denied.
fn reject_denied_grant(
    spelled: &str,
    canon: &str,
    denied_canon: &[String],
) -> Result<(), WardenError> {
    for denied in denied_canon {
        if covers_or_same_for(canon, denied, TargetOs::MacOs)
            || covers_or_same_for(denied, canon, TargetOs::MacOs)
        {
            return Err(WardenError::sandbox_setup(
                SandboxStage::Policy,
                format!(
                    "filesystem grant '{spelled}' resolves to '{canon}', which overlaps denied path '{denied}'"
                ),
            ));
        }
    }
    Ok(())
}

/// A canonicalized exec grant must not sit inside (or equal) a
/// canonicalized writable path — a writable code root is the
/// drop-and-run channel the writable-never-executable invariant exists
/// to close, and no narrowing can preserve both halves. The opposite
/// direction resolves differently: a writable path strictly *inside*
/// the exec dir is declared data-writability colliding with derived
/// exec-map breadth, so the writable grant keeps its declared coverage
/// while exec-map is carved back out of the writable subtree at
/// emission (SBPL is last-match-wins — the carve-out deny lands after
/// every map-executable allow). Records those carve-outs, as indexes
/// into `writable_canon`, for the caller to emit.
fn reject_exec_in_writable(
    spelled: &str,
    canon: &str,
    writable_canon: &[String],
    carves: &mut std::collections::BTreeSet<usize>,
) -> Result<(), WardenError> {
    for (i, writable) in writable_canon.iter().enumerate() {
        if covers_or_same_for(writable, canon, TargetOs::MacOs) {
            return Err(WardenError::sandbox_setup(
                SandboxStage::Policy,
                format!(
                    "executable filesystem grant '{spelled}' resolves to '{canon}', which overlaps writable path '{writable}': a writable+executable directory is a drop-and-run channel"
                ),
            ));
        }
        if covers_or_same_for(canon, writable, TargetOs::MacOs) {
            carves.insert(i);
        }
    }
    Ok(())
}

/// Per-launch private directory used as TMPDIR inside the sandbox.
/// Removed when dropped (kept alive by the child wrapper).
pub struct PrivateTmpDir {
    path: PathBuf,
}

impl PrivateTmpDir {
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for PrivateTmpDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// Create a per-launch private directory used as TMPDIR inside the sandbox.
pub fn create_private_tmpdir() -> Result<PrivateTmpDir, WardenError> {
    let dir = std::env::temp_dir() // nosemgrep: rust.lang.security.temp-dir.temp-dir
        .join(format!(
            "mcp-writ-sbx-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
    std::fs::create_dir_all(&dir).map_err(|e| {
        WardenError::sandbox_setup(
            crate::error::SandboxStage::Prepare,
            format!("failed to create private TMPDIR: {e}"),
        )
    })?;
    #[cfg(unix)]
    {
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).map_err(|e| {
            let _ = std::fs::remove_dir_all(&dir);
            WardenError::sandbox_setup(
                crate::error::SandboxStage::Prepare,
                format!("failed to restrict private TMPDIR permissions: {e}"),
            )
        })?;
    }
    // SBPL matches the real path. On macOS, /var/folders is reached
    // through /private/var/folders, so retain the canonical private path.
    let canonical = dir.canonicalize().map_err(|e| {
        let _ = std::fs::remove_dir(&dir);
        WardenError::sandbox_setup(
            crate::error::SandboxStage::Prepare,
            format!("failed to resolve private TMPDIR: {e}"),
        )
    })?;
    Ok(PrivateTmpDir { path: canonical })
}

/// Child process plus the private TMPDIR that must outlive it.
pub struct MacosChild {
    child: Child,
    /// Process group id captured at spawn (`process_group(0)` ⇒ pgid ==
    /// child pid). The group outlives its leader while any descendant
    /// still belongs to it, so the retained id stays a valid kill target
    /// after the leader has exited — unlike a `child.id()` read.
    pgid: u32,
    /// Whether the leader has been reaped by `wait`/`try_wait`. Once
    /// reaped, the freed pid/pgid may name a recycled, unrelated
    /// process group — group signaling must stop.
    reaped: bool,
    _tmpdir: PrivateTmpDir,
}

impl MacosChild {
    /// Observe the leader's exit before reaping it. A blocking `WNOWAIT`
    /// waitid keeps the zombie — and therefore the pgid the sweep names —
    /// allocated; sweeping after `wait` has already reaped could signal a
    /// recycled, unrelated process group.
    pub fn wait(&mut self) -> std::io::Result<std::process::ExitStatus> {
        if !self.reaped && self.leader_exited_unreaped(true) {
            // Leader is a zombie still pinning the group — sweep the
            // surviving descendants, then the real wait reaps it below.
            self.kill_group();
        }
        let status = self.child.wait();
        if status.is_ok() {
            self.reaped = true;
        }
        status
    }

    /// True when the leader has exited but not yet been reaped — see
    /// [`exited_unreaped`] for the probe semantics.
    #[cfg(unix)]
    fn leader_exited_unreaped(&self, blocking: bool) -> bool {
        exited_unreaped(self.child.id(), blocking)
    }

    /// SIGKILL the process group by the pgid captured at spawn —
    /// descendants of an exited leader still hold the group and are
    /// reachable through it. Skipped once the leader has been reaped:
    /// the freed pgid could then name a recycled, unrelated group.
    fn kill_group(&self) {
        if self.reaped {
            return;
        }
        #[cfg(unix)]
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe {
            let _ = libc_kill(-(self.pgid as i32), SIGKILL);
        }
    }

    pub fn kill(&mut self) -> std::io::Result<()> {
        self.kill_group();
        self.child.kill()
    }

    /// Non-blocking poll that reaps on `Some`. Probes the exit without
    /// reaping first: a leader the inner `try_wait` already reaped frees
    /// its pid, and the recorded pgid may by then name a recycled group
    /// that must not be signaled — so the sweep runs only while the
    /// zombie still pins it. Narrow gap a caller must accept: if the
    /// leader exits between the probe and the inner call — the probe saw
    /// it alive — the sweep never ran and detached descendants can
    /// outlive the session (the freed pgid must still never be signaled,
    /// so skipping is the safe direction; `wait` closes the gap with a
    /// blocking probe).
    pub fn try_wait(&mut self) -> std::io::Result<Option<std::process::ExitStatus>> {
        if !self.reaped && self.leader_exited_unreaped(false) {
            self.kill_group();
        }
        let status = self.child.try_wait();
        if matches!(status, Ok(Some(_))) {
            self.reaped = true;
        }
        status
    }

    pub fn id(&self) -> u32 {
        self.child.id()
    }
}

impl std::ops::Deref for MacosChild {
    type Target = Child;

    fn deref(&self) -> &Child {
        &self.child
    }
}

impl std::ops::DerefMut for MacosChild {
    fn deref_mut(&mut self) -> &mut Child {
        &mut self.child
    }
}

impl Drop for MacosChild {
    fn drop(&mut self) {
        // The group is killed whether or not the leader already exited:
        // descendants it spawned still hold the pgid and must not
        // outlive the session. `kill_group` skips a reaped leader —
        // the freed pgid may have been recycled into another group.
        self.kill_group();
        match self.try_wait() {
            Ok(Some(_)) => {}
            _ => {
                let _ = self.child.kill();
                let _ = self.wait();
            }
        }
    }
}

/// Spawn a child process sandboxed via `sandbox-exec`.
///
/// The helper is invoked by its validated absolute path only — `PATH`
/// order can never substitute a fake helper that skips the profile.
pub fn spawn_sandboxed(
    policy: &Policy,
    command: &str,
    args: &[String],
) -> Result<MacosChild, WardenError> {
    let helper = super::sandbox_exec::sandbox_exec_path()?;
    let tmpdir = create_private_tmpdir()?;
    let sbpl = generate_sbpl_with_tmpdir(policy, tmpdir.path().to_string_lossy().as_ref())?;

    let mut cmd = Command::new(&helper);
    cmd.arg("-p")
        .arg(&sbpl)
        .arg("--")
        .arg(command)
        .args(args)
        .env("TMPDIR", tmpdir.path())
        .env("TMP", tmpdir.path())
        .env("TEMP", tmpdir.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit());
    #[cfg(unix)]
    {
        cmd.process_group(0);
        // fd hygiene: the child seals every ambient descriptor above
        // stdio — sandboxed or not, inherited fds are capabilities the
        // SBPL path rules never mediated.
        super::attach_fd_hygiene(&mut cmd, &[])
            .map_err(|e| WardenError::sandbox_setup(SandboxStage::Prepare, e.to_string()))?;
    }
    let child = cmd.spawn().map_err(WardenError::ProcessSpawn)?;
    let pgid = child.id();
    Ok(MacosChild {
        child,
        pgid,
        reaped: false,
        _tmpdir: tmpdir,
    })
}

/// True when `pid` exited but has not yet been reaped. The `WNOWAIT`
/// waitid reports the exit while keeping the zombie, so the pid — and
/// the process-group id a sweep names — stays reserved until a real
/// wait consumes it. `blocking` omits `WNOHANG` so the probe itself
/// waits for the exit (used by `MacosChild::wait`); callers polling
/// pass `WNOHANG`. `waitid` is the call where `WNOWAIT` is specified;
/// under `WNOHANG` it returns 0 for both a report and "nothing to
/// report", so `si_pid` distinguishes the two. EINTR is retried — a
/// caught signal landing mid-probe is not evidence of state.
#[cfg(unix)]
fn exited_unreaped(pid: u32, blocking: bool) -> bool {
    let flags = libc::WEXITED | libc::WNOWAIT | if blocking { 0 } else { libc::WNOHANG };
    loop {
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        let ret = unsafe { libc::waitid(libc::P_PID, pid as libc::id_t, &mut info, flags) };
        if ret == 0 {
            // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
            return unsafe { info.si_pid() } == pid as libc::pid_t;
        }
        if std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
            return false;
        }
    }
}

/// Result of the post-spawn liveness probe ([`initial_exit_check`]).
///
/// `sandbox-exec` applies the profile to itself and then execs the
/// workload, so a rejected profile or an un-exec'able command exits the
/// process within milliseconds — though a workload that simply finishes
/// quickly exits the same way, so an early exit alone does not prove
/// rejection. Surviving the window is the only post-spawn fact the
/// mechanism exposes — it never proves the kernel accepted individual
/// rules.
pub(crate) enum SpawnLiveness {
    /// The process was still running when the probe window ended.
    Running,
    /// The process exited inside the probe window (status recorded).
    Exited(std::process::ExitStatus),
    /// The probe itself failed (`try_wait` error); state is unknown.
    PollFailed,
}

/// Total window [`initial_exit_check`] observes. A `sandbox-exec`
/// startup failure exits in single-digit milliseconds; the window
/// bounds the check without adding noticeable latency to a healthy
/// launch.
const INITIAL_EXIT_WINDOW: Duration = Duration::from_millis(150);
/// Poll granularity inside the window.
const INITIAL_EXIT_POLL: Duration = Duration::from_millis(10);

/// Bounded post-spawn liveness probe: polls until the child exits or
/// [`INITIAL_EXIT_WINDOW`] elapses. This is the only way to catch a
/// `sandbox-exec` startup rejection — `spawn()` succeeding only proves
/// the binary ran, and the child's stderr is the workload's own
/// channel, never parsed as evidence. Awaits between polls so the
/// spawn path never holds a runtime worker thread for the window.
///
/// The exit is observed through a non-reaping `WNOWAIT` probe first:
/// while the zombie still pins its pid/pgid the process group is
/// swept (`process_group(0)` ⇒ pgid == pid), and only then does
/// `try_wait` reap the leader. Sweeping after the reap could signal a
/// recycled, unrelated group. An exit landing between the probe and
/// the inner `try_wait` reaps without a sweep — the freed pgid must
/// still never be signaled, so skipping is the safe direction.
pub(super) async fn initial_exit_check(child: &mut tokio::process::Child) -> SpawnLiveness {
    let deadline = Instant::now() + INITIAL_EXIT_WINDOW;
    loop {
        #[cfg(unix)]
        if let Some(pid) = child.id()
            && exited_unreaped(pid, false)
        {
            // Leader is a zombie pinning the group — descendants it
            // spawned still hold the pgid and must not outlive the
            // session. The `try_wait` below then reaps the leader.
            // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
            let _ = unsafe { libc_kill(-(pid as i32), SIGKILL) };
        }
        match child.try_wait() {
            Ok(Some(status)) => return SpawnLiveness::Exited(status),
            Ok(None) if Instant::now() >= deadline => return SpawnLiveness::Running,
            Ok(None) => tokio::time::sleep(INITIAL_EXIT_POLL).await,
            Err(_) => return SpawnLiveness::PollFailed,
        }
    }
}

#[cfg(test)]
mod tests;
