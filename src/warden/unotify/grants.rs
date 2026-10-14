//! Dynamic grants — the PR-06 TTL-scoped allow list.

use std::net::IpAddr;
use std::path::{Path, PathBuf};

/// Where live grants come from. The snapshot-file variant is the real
/// cross-process contract (`dns-gate --allowlist-export`); the
/// in-process variant pairs a supervisor with an embedded gate.
pub enum GrantSource {
    /// No dynamic source — static rules decide alone.
    None,
    /// Watch a `DynamicAllowList::export_to` snapshot — reloaded when
    /// the file changes; a missing/removed file is an empty grant set
    /// (fail closed). The file must also authenticate its producer
    /// (see `open_trusted_snapshot`): a regular file owned by this euid
    /// or root, not group/other-writable, in a directory a third
    /// party cannot rename into. A forged or replaceable snapshot is
    /// treated the same as an absent one.
    SnapshotFile(PathBuf),
    /// Consume the in-process allowlist directly.
    InProcess(std::sync::Arc<crate::dnsgate::DynamicAllowList>),
}

/// Snapshot byte budget — a grant entry costs ~150 B on the wire, so
/// 1 MiB already covers tens of thousands of entries; anything larger
/// is a forged or runaway producer and decodes as an empty grant set.
pub(crate) const MAX_SNAPSHOT_BYTES: u64 = 1024 * 1024;
/// Hard caps applied while parsing — an overflow anywhere degrades the
/// whole snapshot to empty (fail closed), never a truncated guess.
const MAX_SNAPSHOT_ENTRIES: usize = 4096;
const MAX_SNAPSHOT_NAME_BYTES: usize = 256;
const MAX_SNAPSHOT_QUALS: usize = 64;

pub(crate) struct SnapshotGrant {
    pub(crate) addr: IpAddr,
    pub(crate) name: String,
    pub(crate) expires_at_unix_secs: u64,
    /// Proto/port scope the grant was minted under — `[]` decodes as
    /// the pre-schema semantics (`tcp`, any port), which is what a
    /// `schema_version: 1.0` gate minted.
    pub(crate) quals: Vec<crate::policy::GrantQual>,
}

pub(super) struct Grants {
    source: GrantSource,
    // Snapshot-file cache state.
    sig: Option<(std::time::SystemTime, u64)>,
    entries: Vec<SnapshotGrant>,
    /// Set after the first producer-trust rejection — the warning is
    /// emitted once per launch rather than once per network event.
    trust_rejected_logged: bool,
    /// Set after the first over-budget snapshot — same once-per-launch
    /// bound on diagnostics.
    oversize_logged: bool,
}

impl Grants {
    pub(super) fn new(source: GrantSource) -> Self {
        Self {
            source,
            sig: None,
            entries: Vec::new(),
            trust_rejected_logged: false,
            oversize_logged: false,
        }
    }

    /// Live grant names covering `addr` — the TTL check against the
    /// caller's own clock is what keeps the snapshot's expiry contract.
    pub(super) fn live_names(&mut self, addr: &IpAddr) -> Vec<String> {
        self.refresh_snapshot();
        match &self.source {
            GrantSource::None => Vec::new(),
            GrantSource::InProcess(list) => list.names_for(addr),
            GrantSource::SnapshotFile(_) => {
                let now = unix_secs_now();
                let mut names: Vec<String> = self
                    .entries
                    .iter()
                    .filter(|g| g.addr == *addr && g.expires_at_unix_secs > now)
                    .map(|g| g.name.clone())
                    .collect();
                names.sort();
                names
            }
        }
    }

    /// Whether a live grant authorizes a `proto`/`port` flow to `addr`
    /// — the qualifier-aware half of `live_names`.
    pub(super) fn has_grant(
        &mut self,
        addr: &IpAddr,
        proto: crate::policy::EgressProto,
        port: u16,
    ) -> bool {
        self.refresh_snapshot();
        match &self.source {
            GrantSource::None => false,
            GrantSource::InProcess(list) => list.is_allowed(addr, proto, port),
            GrantSource::SnapshotFile(_) => {
                let now = unix_secs_now();
                self.entries.iter().any(|g| {
                    g.addr == *addr
                        && g.expires_at_unix_secs > now
                        && g.quals.iter().any(|q| q.covers(proto, port))
                })
            }
        }
    }

    /// Refresh the snapshot cache when the source is a file — the
    /// path is cloned out first so the immutable borrow of `source`
    /// ends before `refresh_entries` takes `&mut self`.
    fn refresh_snapshot(&mut self) {
        let path = match &self.source {
            GrantSource::SnapshotFile(p) => p.clone(),
            _ => return,
        };
        self.refresh_entries(&path);
    }

    /// Re-read the snapshot when it changed (mtime+len signature on the
    /// *trusted* open object). An absent, untrusted, or unparsable file
    /// leaves an empty grant set.
    fn refresh_entries(&mut self, path: &Path) {
        let file = match open_trusted_snapshot(path) {
            Ok(Some(f)) => {
                self.trust_rejected_logged = false;
                f
            }
            Ok(None) => {
                if !self.trust_rejected_logged {
                    self.trust_rejected_logged = true;
                    tracing::warn!(
                        path = %path.display(),
                        "allowlist snapshot rejected: producer trust checks failed \
                         (forged or third-party-replaceable file) — treating as empty"
                    );
                }
                self.sig = None;
                self.entries = Vec::new();
                return;
            }
            Err(_) => {
                self.sig = None;
                self.entries = Vec::new();
                return;
            }
        };
        let new_sig = file
            .metadata()
            .ok()
            .and_then(|m| m.modified().ok().map(|t| (t, m.len())));
        if new_sig == self.sig {
            return;
        }
        self.sig = new_sig;
        self.entries = match new_sig {
            Some(_) => match read_snapshot_body(file) {
                Some(body) => parse_snapshot(&body),
                None => {
                    if !self.oversize_logged {
                        self.oversize_logged = true;
                        tracing::warn!(
                            path = %path.display(),
                            limit = MAX_SNAPSHOT_BYTES,
                            "allowlist snapshot exceeds the byte budget — treating as empty"
                        );
                    }
                    Vec::new()
                }
            },
            None => Vec::new(),
        };
    }
}

/// Producer authentication for the snapshot contract: the file is
/// opened `O_NOFOLLOW` and must be a regular file owned by this
/// process's euid or root, not writable by group/other, in a parent
/// directory that is not group/other-writable unless it is sticky
/// (a world-writable sticky dir like /tmp can still swap names only
/// for files the actor owns). `Ok(None)` = present but untrusted.
#[cfg(unix)]
fn open_trusted_snapshot(path: &Path) -> std::io::Result<Option<std::fs::File>> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        let pmode = std::fs::metadata(parent)?.permissions().mode();
        if pmode & 0o022 != 0 && pmode & 0o1000 == 0 {
            return Ok(None);
        }
    }
    let file = match std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
    {
        Ok(f) => f,
        Err(e) if e.raw_os_error() == Some(libc::ELOOP) => return Ok(None),
        Err(e) => return Err(e),
    };
    let meta = file.metadata()?;
    let euid = unsafe { libc::geteuid() };
    let trusted = meta.is_file()
        && (meta.uid() == euid || meta.uid() == 0)
        && meta.permissions().mode() & 0o022 == 0;
    Ok(trusted.then_some(file))
}

/// Non-unix platforms have no uid/mode trust model here — this module
/// is only exercised on Linux; keep the conservative fallback.
#[cfg(not(unix))]
fn open_trusted_snapshot(_path: &Path) -> std::io::Result<Option<std::fs::File>> {
    Ok(None)
}

pub(super) fn unix_secs_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Read a trusted snapshot handle under the byte budget: metadata
/// length rejects oversize files *before* any allocation, and the
/// `take` cap bounds the read itself so even a producer lying about
/// its length cannot grow the buffer. Over-budget or unreadable →
/// `None`, which every caller degrades to an empty grant set.
fn read_snapshot_body(file: std::fs::File) -> Option<String> {
    use std::io::Read;
    if file.metadata().ok()?.len() > MAX_SNAPSHOT_BYTES {
        return None;
    }
    let mut body = String::new();
    file.take(MAX_SNAPSHOT_BYTES + 1)
        .read_to_string(&mut body)
        .ok()?;
    (body.len() as u64 <= MAX_SNAPSHOT_BYTES).then_some(body)
}

/// Read + parse a snapshot file through the same producer-trust check
/// as the live watch — `[]` when the file is missing, untrusted,
/// over-budget, or unparsable (fail closed: an absent snapshot is an
/// empty grant set). Shared with the PR-10 eBPF route's grant-map
/// resync.
pub(crate) fn load_snapshot(path: &Path) -> Vec<SnapshotGrant> {
    match open_trusted_snapshot(path) {
        Ok(Some(file)) => read_snapshot_body(file)
            .map(|body| parse_snapshot(&body))
            .unwrap_or_default(),
        _ => Vec::new(),
    }
}

/// Parse the `DynamicAllowList::snapshot_json` contract:
/// `{"schema_version":"1.1","generated_at_unix_secs":N,"entries":
/// [{"name","addr","expires_at_unix_secs","quals":[{"proto","port"}]}]}`.
/// An entry without `quals` (a `1.0` snapshot) decodes as the pre-schema
/// grant scope — `tcp`, any port — exactly what those gates minted.
/// Anything unparsable degrades to an empty grant set — never a guess.
pub(super) fn parse_snapshot(body: &str) -> Vec<SnapshotGrant> {
    let parsed = match nojson::RawJson::parse(body) {
        Ok(p) => p,
        Err(_) => return Vec::new(),
    };
    fn member<'t, 'r>(
        v: nojson::RawJsonValue<'t, 'r>,
        key: &str,
    ) -> Option<nojson::RawJsonValue<'t, 'r>> {
        v.to_member(key).ok()?.required().ok()
    }
    let Some(entries) = member(parsed.value(), "entries").and_then(|v| v.to_array().ok()) else {
        return Vec::new();
    };
    // Body size is already budgeted, so materializing is bounded — the
    // count check turns an entry flood into a whole-snapshot refusal
    // rather than a truncated grant set.
    let entries: Vec<_> = entries.collect();
    if entries.len() > MAX_SNAPSHOT_ENTRIES {
        return Vec::new();
    }
    let mut grants = Vec::with_capacity(entries.len());
    for e in entries {
        let Some(name) = member(e, "name").and_then(|v| v.to_unquoted_string_str().ok()) else {
            continue;
        };
        if name.len() > MAX_SNAPSHOT_NAME_BYTES {
            return Vec::new();
        }
        let Some(addr) = member(e, "addr")
            .and_then(|v| v.to_unquoted_string_str().ok())
            .and_then(|s| s.parse::<IpAddr>().ok())
        else {
            continue;
        };
        let Some(exp) = member(e, "expires_at_unix_secs")
            .and_then(|v| v.as_number_str().ok())
            .and_then(|s| s.parse::<u64>().ok())
        else {
            continue;
        };
        let quals = match member(e, "quals").and_then(|q| q.to_array().ok()) {
            Some(arr) => {
                let arr: Vec<_> = arr.collect();
                if arr.len() > MAX_SNAPSHOT_QUALS {
                    return Vec::new();
                }
                let mut quals = Vec::with_capacity(arr.len());
                for q in arr {
                    let Some(proto) = member(q, "proto")
                        .and_then(|p| p.to_unquoted_string_str().ok())
                        .and_then(|s| crate::policy::EgressProto::parse(&s).ok())
                    else {
                        continue;
                    };
                    // An absent or explicit-null `port` scopes to every
                    // port; a present-but-unparseable one drops the
                    // qual rather than widening.
                    let port = match member(q, "port") {
                        None => None,
                        Some(p) if p.kind().is_null() => None,
                        Some(p) => match p.as_number_str().ok().and_then(|s| s.parse().ok()) {
                            Some(port) => Some(port),
                            None => continue,
                        },
                    };
                    quals.push(crate::policy::GrantQual { proto, port });
                }
                quals
            }
            None => vec![crate::policy::GrantQual::TCP_ANY],
        };
        grants.push(SnapshotGrant {
            addr,
            name: name.into_owned(),
            expires_at_unix_secs: exp,
            quals,
        });
    }
    grants
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    const SNAPSHOT: &str = r#"{"schema_version":"1.1","generated_at_unix_secs":0,"entries":[{"name":"a.example","addr":"192.0.2.1","expires_at_unix_secs":9999999999,"quals":[{"proto":"tcp","port":443}]}]}"#;

    fn write_mode(path: &Path, body: &str, mode: u32) {
        std::fs::write(path, body).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    #[test]
    fn self_owned_snapshot_is_trusted_and_parses() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("g.json");
        write_mode(&p, SNAPSHOT, 0o600);
        assert!(open_trusted_snapshot(&p).unwrap().is_some());
        let grants = load_snapshot(&p);
        assert_eq!(grants.len(), 1);
        assert_eq!(grants[0].name, "a.example");
    }

    #[test]
    fn group_writable_snapshot_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("g.json");
        write_mode(&p, SNAPSHOT, 0o660);
        assert!(open_trusted_snapshot(&p).unwrap().is_none());
        assert!(load_snapshot(&p).is_empty());
    }

    #[test]
    fn symlink_snapshot_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("real.json");
        write_mode(&target, SNAPSHOT, 0o600);
        let link = dir.path().join("g.json");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(open_trusted_snapshot(&link).unwrap().is_none());
        assert!(load_snapshot(&link).is_empty());
    }

    #[test]
    fn world_writable_parent_without_sticky_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let sub = dir.path().join("shared");
        std::fs::create_dir(&sub).unwrap();
        std::fs::set_permissions(&sub, std::fs::Permissions::from_mode(0o777)).unwrap();
        let p = sub.join("g.json");
        write_mode(&p, SNAPSHOT, 0o600);
        assert!(open_trusted_snapshot(&p).unwrap().is_none());
        assert!(load_snapshot(&p).is_empty());
    }

    #[test]
    fn world_writable_parent_with_sticky_is_accepted() {
        let dir = tempfile::tempdir().unwrap();
        let sub = dir.path().join("tmp-like");
        std::fs::create_dir(&sub).unwrap();
        std::fs::set_permissions(&sub, std::fs::Permissions::from_mode(0o1777)).unwrap();
        let p = sub.join("g.json");
        write_mode(&p, SNAPSHOT, 0o600);
        assert!(open_trusted_snapshot(&p).unwrap().is_some());
        assert_eq!(load_snapshot(&p).len(), 1);
    }

    #[test]
    fn oversized_snapshot_file_decodes_empty() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("g.json");
        let mut body = String::from("{\"entries\":[");
        while body.len() as u64 <= MAX_SNAPSHOT_BYTES {
            body.push_str("{\"name\":\"a.example\",\"addr\":\"192.0.2.1\",\"expires_at_unix_secs\":9999999999},");
        }
        write_mode(&p, &body, 0o600);
        assert!(load_snapshot(&p).is_empty());
    }

    #[test]
    fn entry_flood_snapshot_decodes_empty() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("g.json");
        let mut body = String::from("{\"entries\":[");
        for _ in 0..=MAX_SNAPSHOT_ENTRIES {
            body.push_str(
                "{\"name\":\"a.example\",\"addr\":\"192.0.2.1\",\"expires_at_unix_secs\":9999999999},",
            );
        }
        body.push_str("]}");
        write_mode(&p, &body, 0o600);
        assert!(load_snapshot(&p).is_empty());
    }

    #[test]
    fn oversized_name_and_quals_decode_empty() {
        let dir = tempfile::tempdir().unwrap();
        // A name past the per-entry byte budget poisons the snapshot.
        let long_name = "a".repeat(MAX_SNAPSHOT_NAME_BYTES + 1);
        let p = dir.path().join("g.json");
        write_mode(
            &p,
            &format!(
                "{{\"entries\":[{{\"name\":\"{long_name}\",\"addr\":\"192.0.2.1\",\"expires_at_unix_secs\":9999999999}}]}}"
            ),
            0o600,
        );
        assert!(load_snapshot(&p).is_empty());
        // Same for a qualifier flood inside one entry.
        let mut quals = String::new();
        for _ in 0..=MAX_SNAPSHOT_QUALS {
            quals.push_str("{\"proto\":\"tcp\",\"port\":443},");
        }
        write_mode(
            &p,
            &format!(
                "{{\"entries\":[{{\"name\":\"a.example\",\"addr\":\"192.0.2.1\",\"expires_at_unix_secs\":9999999999,\"quals\":[{quals}]}}]}}"
            ),
            0o600,
        );
        assert!(load_snapshot(&p).is_empty());
    }

    #[test]
    fn export_to_produces_a_trusted_snapshot() {
        // The producer half of the contract: `export_to`'s create_new
        // temp + 0600 mode lands as a file the consumer accepts.
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("g.json");
        let list = crate::dnsgate::DynamicAllowList::new(4);
        list.register(
            "a.example",
            "192.0.2.1".parse().unwrap(),
            &[crate::policy::GrantQual::TCP_ANY],
            std::time::Duration::from_secs(60),
        );
        list.export_to(&p).unwrap();
        assert_eq!(load_snapshot(&p).len(), 1);
    }
}
