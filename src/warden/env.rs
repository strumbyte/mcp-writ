//! Child-process environment block construction.
//!
//! [`spawn_env_pairs`] produces the complete environment for a spawned child,
//! or `None` when the child inherits the parent environment unchanged.
//! [`apply_spawn_env`] applies that block to a `tokio::process::Command`.
//!
//! Synchronous `std::process::Command` spawns never touch the environment —
//! that is the existing contract of the sync Linux path.

use std::ffi::{OsStr, OsString};

use super::SpawnOptions;

/// Apply the [`SpawnOptions`] environment to an async command.
///
/// `None` (inherit parent) leaves the command untouched: no `env_clear`.
pub(crate) fn apply_spawn_env(cmd: &mut tokio::process::Command, opts: &SpawnOptions) {
    if let Some(pairs) = spawn_env_pairs(opts) {
        cmd.env_clear();
        for (key, value) in pairs {
            cmd.env(key, value);
        }
    }
}

/// Environment entries applied to a sandboxed child.
///
/// `None` means inherit the parent environment (and do not override TMPDIR).
/// `Some` is the complete environment block: restricted allow-list, or a
/// snapshot of the parent with TMPDIR/TMP/TEMP overridden.
pub(crate) fn spawn_env_pairs(opts: &SpawnOptions) -> Option<Vec<(OsString, OsString)>> {
    if !opts.restrict_environment && opts.tmpdir.is_none() {
        return None;
    }
    let mut pairs = if opts.restrict_environment {
        restricted_base_env(&opts.allowed_names)
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

fn restricted_base_env(allowed_names: &[String]) -> Vec<(OsString, OsString)> {
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
    // Policy allowlist: copy each name from the parent when present; a listed
    // name the parent does not define stays unset. Names that cannot form a
    // `KEY=value` pair are skipped — the policy validator rejects them at
    // load, so this only guards programmatic SpawnOptions misuse (var_os
    // would panic on an empty/`=`/NUL name otherwise).
    for name in allowed_names {
        if name.is_empty() || name.contains('=') || name.contains('\0') {
            continue;
        }
        let key = OsString::from(name);
        if let Some(val) = std::env::var_os(&key) {
            upsert_env(&mut pairs, key, val);
        }
    }
    pairs
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
        unsafe {
            std::env::set_var(sentinel, "inherited");
        }
        let tmp = std::env::temp_dir().join("mcp-writ-env-contract");
        let opts = SpawnOptions {
            restrict_environment: true,
            allowed_names: Vec::new(),
            tmpdir: Some(tmp.clone()),
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

        unsafe {
            std::env::set_var("MCP_WRIT_ENV_INHERIT_SENTINEL", "keep-me");
        }
        let inherit_opts = SpawnOptions {
            restrict_environment: false,
            allowed_names: Vec::new(),
            tmpdir: Some(tmp.clone()),
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
        unsafe {
            std::env::set_var(keep, "keep-value");
            std::env::set_var(drop, "drop-value");
        }
        let opts = SpawnOptions {
            restrict_environment: true,
            allowed_names: vec![keep.to_string()],
            tmpdir: None,
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
        unsafe {
            std::env::remove_var(missing);
        }
        let opts = SpawnOptions {
            restrict_environment: true,
            allowed_names: vec![missing.to_string()],
            tmpdir: None,
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
        unsafe {
            std::env::set_var("MCP_WRIT_ENV_ALLOWLIST_INHERIT", "present");
        }
        let opts = SpawnOptions {
            restrict_environment: false,
            allowed_names: vec!["MCP_WRIT_ENV_ALLOWLIST_INHERIT".to_string()],
            tmpdir: None,
        };
        assert!(
            spawn_env_pairs(&opts).is_none(),
            "allowed_names without restrict_environment must inherit the parent env"
        );
        unsafe {
            std::env::remove_var("MCP_WRIT_ENV_ALLOWLIST_INHERIT");
        }
    }

    /// Duplicate allowlist entries collapse to a single env pair.
    #[test]
    fn restricted_env_allowed_names_dedupe() {
        let _env = lock_process_env();
        let name = "MCP_WRIT_ENV_ALLOWLIST_DUP";
        unsafe {
            std::env::set_var(name, "v1");
        }
        let opts = SpawnOptions {
            restrict_environment: true,
            allowed_names: vec![name.to_string(), name.to_string()],
            tmpdir: None,
        };
        let pairs = spawn_env_pairs(&opts).expect("restricted env is explicit");
        let count = pairs
            .iter()
            .filter(|(k, _)| k.to_string_lossy().eq_ignore_ascii_case(name))
            .count();
        assert_eq!(count, 1, "duplicate allow names must dedupe: {pairs:?}");
        unsafe {
            std::env::remove_var(name);
        }
    }
}
