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
    /// (fail closed).
    SnapshotFile(PathBuf),
    /// Consume the in-process allowlist directly.
    InProcess(std::sync::Arc<crate::dnsgate::DynamicAllowList>),
}

pub(super) struct SnapshotGrant {
    addr: IpAddr,
    name: String,
    expires_at_unix_secs: u64,
    /// Proto/port scope the grant was minted under — `[]` decodes as
    /// the pre-schema semantics (`tcp`, any port), which is what a
    /// `schema_version: 1.0` gate minted.
    quals: Vec<crate::policy::GrantQual>,
}

pub(super) struct Grants {
    source: GrantSource,
    // Snapshot-file cache state.
    sig: Option<(std::time::SystemTime, u64)>,
    entries: Vec<SnapshotGrant>,
}

impl Grants {
    pub(super) fn new(source: GrantSource) -> Self {
        Self {
            source,
            sig: None,
            entries: Vec::new(),
        }
    }

    /// Live grant names covering `addr` — the TTL check against the
    /// caller's own clock is what keeps the snapshot's expiry contract.
    pub(super) fn live_names(&mut self, addr: &IpAddr) -> Vec<String> {
        match &self.source {
            GrantSource::None => Vec::new(),
            GrantSource::InProcess(list) => list.names_for(addr),
            GrantSource::SnapshotFile(path) => {
                refresh_entries(path, &mut self.sig, &mut self.entries);
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
        match &self.source {
            GrantSource::None => false,
            GrantSource::InProcess(list) => list.is_allowed(addr, proto, port),
            GrantSource::SnapshotFile(path) => {
                refresh_entries(path, &mut self.sig, &mut self.entries);
                let now = unix_secs_now();
                self.entries.iter().any(|g| {
                    g.addr == *addr
                        && g.expires_at_unix_secs > now
                        && g.quals.iter().any(|q| q.covers(proto, port))
                })
            }
        }
    }
}

/// Re-read the snapshot when it changed (mtime+len signature); an
/// absent or unparsable file leaves an empty grant set.
fn refresh_entries(
    path: &Path,
    sig: &mut Option<(std::time::SystemTime, u64)>,
    entries: &mut Vec<SnapshotGrant>,
) {
    let new_sig = std::fs::metadata(path)
        .ok()
        .and_then(|m| m.modified().ok().map(|t| (t, m.len())));
    if new_sig == *sig {
        return;
    }
    *sig = new_sig;
    *entries = match new_sig {
        Some(_) => std::fs::read_to_string(path)
            .ok()
            .map(|body| parse_snapshot(&body))
            .unwrap_or_default(),
        None => Vec::new(),
    };
}

pub(super) fn unix_secs_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
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
    entries
        .filter_map(|e| {
            let name = member(e, "name")?.to_unquoted_string_str().ok()?;
            let addr = member(e, "addr")?
                .to_unquoted_string_str()
                .ok()?
                .parse::<IpAddr>()
                .ok()?;
            let exp = member(e, "expires_at_unix_secs")?
                .as_number_str()
                .ok()?
                .parse::<u64>()
                .ok()?;
            let quals = member(e, "quals")
                .and_then(|q| q.to_array().ok())
                .map(|arr| {
                    arr.filter_map(|q| {
                        let proto = member(q, "proto")
                            .and_then(|p| p.to_unquoted_string_str().ok())
                            .and_then(|s| crate::policy::EgressProto::parse(&s).ok())?;
                        // An absent or explicit-null `port` scopes to
                        // every port; a present-but-unparseable one
                        // drops the qual rather than widening.
                        let port = match member(q, "port") {
                            None => None,
                            Some(p) if p.kind().is_null() => None,
                            Some(p) => Some(p.as_number_str().ok()?.parse::<u16>().ok()?),
                        };
                        Some(crate::policy::GrantQual { proto, port })
                    })
                    .collect::<Vec<_>>()
                })
                .unwrap_or_else(|| vec![crate::policy::GrantQual::TCP_ANY]);
            Some(SnapshotGrant {
                addr,
                name: name.into_owned(),
                expires_at_unix_secs: exp,
                quals,
            })
        })
        .collect()
}
