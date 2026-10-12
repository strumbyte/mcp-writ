//! TTL-scoped dynamic IP allow list — the name→address grants the gate
//! mints from upstream answers.
//!
//! This table is the contract between the name layer and the IP layer:
//! every A/AAAA the gate relays is registered under the response's
//! chain-minimum TTL, and an IP-layer enforcement point (PR-07
//! supervisor / PR-09 namespaced proxy — separate components, not this
//! one) consults `is_allowed` to decide whether a connection attempt
//! lands on an address the resolver actually vended. An address with a
//! live grant is allowed; expiry closes it again — the grant lifetime
//! is bounded by the DNS answer, not by the gate's uptime.
//!
//! `snapshot_json` / `export_to` serialize the live grants for a
//! consumer in another process (a netns-resident proxy cannot share
//! this map). Consumers MUST honor `expires_at_unix_secs` themselves —
//! a snapshot goes stale the moment it is written, and re-checking
//! expiry is what keeps the TTL contract intact.

use std::collections::HashMap;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// One name→address grant keyed separately so a name's re-resolution
/// refreshes only its own grants and two names can share an address
/// without merging each other's expiries.
#[derive(PartialEq, Eq, Hash)]
struct GrantKey {
    addr: IpAddr,
    name: String,
}

struct GrantEntry {
    expires: Instant,
    /// The proto/port qualifiers under which the grant was minted —
    /// the allow rules that covered the name decide what the resolved
    /// address may carry (a `proto=udp` name rule authorizes only UDP
    /// flows to it). An empty set is never stored — `register` treats
    /// it as a refusal, since a qualifier-less grant would authorize
    /// nothing.
    quals: Vec<crate::policy::GrantQual>,
}

struct Inner {
    grants: HashMap<GrantKey, GrantEntry>,
}

/// Dynamic allow list for DNS-gate answers. Thread-safe; reaping of
/// expired grants runs lazily inside the mutating calls, so the table
/// stays bounded without a sweeper task.
pub struct DynamicAllowList {
    inner: Mutex<Inner>,
    /// Serializes `export_to`'s serialize+write+rename — two exports on
    /// the same destination must not interleave tmp writes or let a
    /// slower snapshot rename over a newer one.
    export_lock: Mutex<()>,
    /// Live-grant ceiling — a bound on memory growth from churning
    /// answers. Registration past the cap refuses; the refusal is a
    /// capacity signal (`guard` details mark it), never a verdict.
    max_grants: usize,
}

impl DynamicAllowList {
    pub fn new(max_grants: usize) -> Self {
        Self {
            inner: Mutex::new(Inner {
                grants: HashMap::new(),
            }),
            export_lock: Mutex::new(()),
            max_grants,
        }
    }

    /// Register or refresh a `name → addr` grant for `ttl`, minted
    /// under `quals` — the covering allow rules' proto/port scope.
    /// Returns `false` when the table is full of live grants, `ttl`
    /// is zero, or `quals` is empty — a zero-TTL grant expires before
    /// it can be used and a qualifier-less grant authorizes nothing,
    /// so neither is recorded (and the response is still relayed).
    pub fn register(
        &self,
        name: &str,
        addr: IpAddr,
        quals: &[crate::policy::GrantQual],
        ttl: Duration,
    ) -> bool {
        self.register_at(name, addr, quals, Instant::now() + ttl)
    }

    /// Register with an absolute expiry — the testable core of
    /// [`Self::register`].
    pub(crate) fn register_at(
        &self,
        name: &str,
        addr: IpAddr,
        quals: &[crate::policy::GrantQual],
        expires: Instant,
    ) -> bool {
        if expires <= Instant::now() || quals.is_empty() {
            return false;
        }
        let mut inner = self.inner.lock().unwrap();
        inner.grants.retain(|_, e| e.expires > Instant::now());
        let key = GrantKey {
            addr,
            name: name.to_string(),
        };
        if let Some(e) = inner.grants.get_mut(&key) {
            // A fresh answer for the same name→addr replaces the
            // grant's expiry and scope — a longer-lived answer renews
            // it, a shorter one is the resolver's newer truth and
            // wins too.
            e.expires = expires;
            e.quals = quals.to_vec();
            return true;
        }
        if inner.grants.len() >= self.max_grants {
            return false;
        }
        inner.grants.insert(
            key,
            GrantEntry {
                expires,
                quals: quals.to_vec(),
            },
        );
        true
    }

    /// Whether a live grant authorizes a flow of `proto` to
    /// `addr`:`port` — the IP-layer question, qualifier-aware: a grant
    /// minted under a `proto=udp` name rule never authorizes TCP.
    pub fn is_allowed(&self, addr: &IpAddr, proto: crate::policy::EgressProto, port: u16) -> bool {
        self.is_allowed_at(addr, proto, port, Instant::now())
    }

    pub(crate) fn is_allowed_at(
        &self,
        addr: &IpAddr,
        proto: crate::policy::EgressProto,
        port: u16,
        now: Instant,
    ) -> bool {
        let inner = self.inner.lock().unwrap();
        inner.grants.iter().any(|(k, e)| {
            k.addr == *addr && e.expires > now && e.quals.iter().any(|q| q.covers(proto, port))
        })
    }

    /// Live grants on `addr` — the names that vended it, for
    /// diagnostics and reporting.
    pub fn names_for(&self, addr: &IpAddr) -> Vec<String> {
        let now = Instant::now();
        let inner = self.inner.lock().unwrap();
        let mut names: Vec<String> = inner
            .grants
            .iter()
            .filter(|(k, e)| k.addr == *addr && e.expires > now)
            .map(|(k, _)| k.name.clone())
            .collect();
        names.sort();
        names
    }

    /// The live qualifiers covering `addr` — every grant's scope,
    /// unioned, for consumers that evaluate flows themselves (the
    /// namespaced proxy's per-datagram check).
    pub fn quals_for(&self, addr: &IpAddr) -> Vec<crate::policy::GrantQual> {
        let now = Instant::now();
        let inner = self.inner.lock().unwrap();
        let mut quals: Vec<crate::policy::GrantQual> = inner
            .grants
            .iter()
            .filter(|(k, e)| k.addr == *addr && e.expires > now)
            .flat_map(|(_, e)| e.quals.iter().copied())
            .collect();
        quals.sort();
        quals.dedup();
        quals
    }

    /// Number of live (unexpired) grants.
    pub fn live_len(&self) -> usize {
        let now = Instant::now();
        let inner = self.inner.lock().unwrap();
        inner.grants.values().filter(|e| e.expires > now).count()
    }

    /// Serialize the live grants to the JSON snapshot contract:
    /// `{"schema_version":"1.1","generated_at_unix_secs":N,"entries":
    /// [{"name","addr","expires_at_unix_secs","quals":[{"proto",
    /// "port"}]}]}` — expiry as epoch seconds so a consumer compares
    /// it against its own clock; `quals` are the proto/port scope the
    /// grant was minted under (`port: null` = any port). A `1.0`
    /// snapshot without `quals` decodes as the pre-schema semantics
    /// (`tcp`, any port) — exactly what those gates minted.
    pub fn snapshot_json(&self) -> String {
        let now = Instant::now();
        let now_wall = SystemTime::now();
        let inner = self.inner.lock().unwrap();
        nojson::object(|o| -> std::fmt::Result {
            o.member("schema_version", "1.1")?;
            o.member("generated_at_unix_secs", unix_secs(now_wall))?;
            o.member(
                "entries",
                nojson::array(|a| {
                    for (k, e) in inner.grants.iter().filter(|(_, e)| e.expires > now) {
                        let expires_wall = now_wall + e.expires.saturating_duration_since(now);
                        let addr = k.addr.to_string();
                        a.element(nojson::object(|e2| {
                            e2.member("name", k.name.as_str())?;
                            e2.member("addr", addr.as_str())?;
                            e2.member("expires_at_unix_secs", unix_secs(expires_wall))?;
                            e2.member(
                                "quals",
                                nojson::array(|qa| {
                                    for q in &e.quals {
                                        qa.element(nojson::object(|qo| {
                                            qo.member("proto", q.proto.as_str())?;
                                            qo.member("port", q.port)
                                        }))?;
                                    }
                                    Ok(())
                                }),
                            )
                        }))?;
                    }
                    Ok(())
                }),
            )
        })
        .to_string()
    }

    /// Atomically write the snapshot to `path` (temp file + rename), so
    /// a consumer never reads a half-written table. Exports are
    /// serialized under `export_lock`.
    ///
    /// The temp name carries an unpredictable suffix and is opened with
    /// `create_new`: a predictable sibling path would let a co-located
    /// writer squat a symlink at `<path>.tmp` and have the write land
    /// (and then be renamed from) an attacker-chosen target.
    pub fn export_to(&self, path: &Path) -> std::io::Result<()> {
        let _guard = self.export_lock.lock().unwrap();
        let tmp = export_temp_path(path);
        // `create_new` failing means the temp name is already taken
        // (e.g. planted) — that file is not ours to delete, so cleanup
        // only runs once the create succeeded.
        let mut file = create_temp_file(&tmp)?;
        let result = write_temp_file(&mut file, self.snapshot_json().as_bytes())
            .and_then(|()| std::fs::rename(&tmp, path));
        if result.is_err() {
            let _ = std::fs::remove_file(&tmp);
        }
        result
    }
}

fn export_temp_path(path: &Path) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or_default();
    let mut tmp_os = path.as_os_str().to_os_string();
    tmp_os.push(format!(".tmp-{}-{nanos}", std::process::id()));
    PathBuf::from(tmp_os)
}

fn create_temp_file(tmp: &Path) -> std::io::Result<std::fs::File> {
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    opts.open(tmp)
}

fn write_temp_file(file: &mut std::fs::File, contents: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    file.write_all(contents)?;
    file.sync_data()
}

fn unix_secs(t: SystemTime) -> u64 {
    t.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    const TCP_ANY: crate::policy::GrantQual = crate::policy::GrantQual::TCP_ANY;

    #[test]
    fn register_and_query() {
        let al = DynamicAllowList::new(16);
        let addr = IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34));
        assert!(al.register("www.example.com", addr, &[TCP_ANY], Duration::from_secs(60)));
        assert!(al.is_allowed(&addr, crate::policy::EgressProto::Tcp, 443));
        // A TCP_ANY grant never authorizes UDP.
        assert!(!al.is_allowed(&addr, crate::policy::EgressProto::Udp, 53));
        assert!(!al.is_allowed(
            &IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            crate::policy::EgressProto::Tcp,
            443
        ));
        assert_eq!(al.names_for(&addr), vec!["www.example.com"]);
        assert_eq!(al.live_len(), 1);
    }

    #[test]
    fn qualifier_scopes_the_grant() {
        let al = DynamicAllowList::new(16);
        let addr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9));
        let udp53 = crate::policy::GrantQual {
            proto: crate::policy::EgressProto::Udp,
            port: Some(53),
        };
        assert!(al.register("ns.example", addr, &[udp53], Duration::from_secs(60)));
        assert!(al.is_allowed(&addr, crate::policy::EgressProto::Udp, 53));
        assert!(!al.is_allowed(&addr, crate::policy::EgressProto::Udp, 5353));
        assert!(!al.is_allowed(&addr, crate::policy::EgressProto::Tcp, 53));
        // A grant with no quals is never recorded.
        assert!(!al.register("none.example", addr, &[], Duration::from_secs(60)));
        assert_eq!(al.quals_for(&addr), vec![udp53]);
    }

    #[test]
    fn expiry_closes_the_grant() {
        let al = DynamicAllowList::new(16);
        let addr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
        let now = Instant::now();
        assert!(al.register_at("a.example", addr, &[TCP_ANY], now + Duration::from_secs(5)));
        assert!(al.is_allowed_at(
            &addr,
            crate::policy::EgressProto::Tcp,
            443,
            now + Duration::from_secs(4)
        ));
        assert!(!al.is_allowed_at(
            &addr,
            crate::policy::EgressProto::Tcp,
            443,
            now + Duration::from_secs(6)
        ));
        assert_eq!(al.live_len(), 1); // lazily reaped, not eagerly
    }

    #[test]
    fn zero_ttl_is_never_recorded() {
        let al = DynamicAllowList::new(16);
        let addr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 9));
        assert!(!al.register("a.example", addr, &[TCP_ANY], Duration::ZERO));
        assert!(!al.is_allowed(&addr, crate::policy::EgressProto::Tcp, 443));
    }

    #[test]
    fn capacity_refuses_grants() {
        let al = DynamicAllowList::new(1);
        let a1 = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
        let a2 = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2));
        assert!(al.register("a.example", a1, &[TCP_ANY], Duration::from_secs(60)));
        assert!(!al.register("b.example", a2, &[TCP_ANY], Duration::from_secs(60)));
        // The same name→addr pair still refreshes under a full table.
        assert!(al.register("a.example", a1, &[TCP_ANY], Duration::from_secs(120)));
        assert!(al.is_allowed(&a1, crate::policy::EgressProto::Tcp, 443));
        assert!(!al.is_allowed(&a2, crate::policy::EgressProto::Tcp, 443));
    }

    #[test]
    fn snapshot_serializes_live_entries() {
        let al = DynamicAllowList::new(16);
        let addr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7));
        al.register("svc.example", addr, &[TCP_ANY], Duration::from_secs(300));
        let json = al.snapshot_json();
        let parsed = nojson::RawJson::parse(&json).unwrap();
        let entries_member = parsed.value().to_member("entries").unwrap();
        let entries: Vec<_> = entries_member
            .required()
            .unwrap()
            .to_array()
            .unwrap()
            .collect();
        assert_eq!(entries.len(), 1);
        let entry = entries[0];
        assert_eq!(
            entry
                .to_member("name")
                .unwrap()
                .required()
                .unwrap()
                .to_unquoted_string_str()
                .unwrap(),
            "svc.example"
        );
        assert_eq!(
            entry
                .to_member("addr")
                .unwrap()
                .required()
                .unwrap()
                .to_unquoted_string_str()
                .unwrap(),
            "203.0.113.7"
        );
        let exp: u64 = entry
            .to_member("expires_at_unix_secs")
            .unwrap()
            .required()
            .unwrap()
            .as_number_str()
            .unwrap()
            .parse()
            .unwrap();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        assert!(exp > now && exp <= now + 300);
    }

    #[test]
    fn two_names_can_share_one_address() {
        let al = DynamicAllowList::new(16);
        let addr = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 10));
        al.register("a.example", addr, &[TCP_ANY], Duration::from_secs(60));
        al.register("b.example", addr, &[TCP_ANY], Duration::from_secs(30));
        let mut names = al.names_for(&addr);
        names.sort();
        assert_eq!(names, vec!["a.example", "b.example"]);
    }

    #[test]
    fn export_to_tmp_suffixed_destination_stays_atomic() {
        // A destination already spelled `x.tmp` must not collide with
        // its own temp path — the temp name is a suffix on the whole
        // name (`x.tmp.tmp`), never a replacement extension.
        let dir = std::env::temp_dir()
            .join("mcp_writ_test")
            .join(format!("export_tmp_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let dest = dir.join("allowlist.tmp");
        let al = DynamicAllowList::new(16);
        al.register(
            "a.example",
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 5)),
            &[TCP_ANY],
            Duration::from_secs(60),
        );
        al.export_to(&dest).unwrap();
        let body = std::fs::read_to_string(&dest).unwrap();
        assert!(body.contains("a.example"));
        // The temp file was consumed by the rename — the destination
        // (itself spelled `.tmp`) is the only entry left.
        let names: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(
            names,
            vec![dest.file_name().unwrap().to_os_string()],
            "no temp residue expected"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn export_to_symlink_destination_does_not_write_through() {
        // A symlink planted at the destination must be replaced by the
        // rename, never followed: the link target keeps its contents.
        let dir = std::env::temp_dir()
            .join("mcp_writ_test")
            .join(format!("export_link_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let victim = dir.join("victim");
        std::fs::write(&victim, "keep-me").unwrap();
        let dest = dir.join("allowlist.json");
        std::os::unix::fs::symlink(&victim, &dest).unwrap();

        let al = DynamicAllowList::new(16);
        al.register(
            "a.example",
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 5)),
            &[TCP_ANY],
            Duration::from_secs(60),
        );
        al.export_to(&dest).unwrap();

        assert_eq!(std::fs::read_to_string(&victim).unwrap(), "keep-me");
        let meta = std::fs::symlink_metadata(&dest).unwrap();
        assert!(meta.is_file(), "dest must be a regular file, not a link");
        assert!(
            std::fs::read_to_string(&dest)
                .unwrap()
                .contains("a.example")
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// When the temp create itself fails (unwritable directory), the
    /// destination and siblings must be left untouched — cleanup only
    /// runs on a file this call created.
    #[cfg(unix)]
    #[test]
    fn export_to_failed_create_touches_nothing() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir()
            .join("mcp_writ_test")
            .join(format!("export_ro_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let dest = dir.join("allowlist.json");
        std::fs::write(&dest, "pre-existing").unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o555)).unwrap();

        let al = DynamicAllowList::new(16);
        al.register(
            "a.example",
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 5)),
            &[TCP_ANY],
            Duration::from_secs(60),
        );
        assert!(al.export_to(&dest).is_err());
        assert_eq!(std::fs::read_to_string(&dest).unwrap(), "pre-existing");
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 1);

        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The exported file must not inherit an over-permissive umask —
    /// an allowlist snapshot is a security artifact.
    #[cfg(unix)]
    #[test]
    fn export_to_uses_restrictive_mode() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir()
            .join("mcp_writ_test")
            .join(format!("export_mode_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let dest = dir.join("allowlist.json");
        let al = DynamicAllowList::new(16);
        al.register(
            "a.example",
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 5)),
            &[TCP_ANY],
            Duration::from_secs(60),
        );
        al.export_to(&dest).unwrap();
        let mode = std::fs::metadata(&dest).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "export mode was {mode:o}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
