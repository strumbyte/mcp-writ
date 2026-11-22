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

/// Staged grants carry the mint→commit ordering: invisible to every
/// consumer until `commit_staged`, discarded by `drop_staged`.
#[test]
fn staged_grants_are_invisible_until_commit() {
    let al = DynamicAllowList::new(16);
    let a = IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34));
    let s = al.begin_staging();
    assert!(al.register_staged(s, "x.example", a, &[TCP_ANY], Duration::from_secs(60)));
    // Not yet committed: no consumer may see the authority.
    assert!(!al.is_allowed(&a, crate::policy::EgressProto::Tcp, 443));
    assert!(al.names_for(&a).is_empty());
    assert!(al.quals_for(&a).is_empty());
    assert_eq!(al.live_len(), 0);
    assert!(!al.snapshot_json().contains("x.example"));

    al.commit_staged(s);
    assert!(al.is_allowed(&a, crate::policy::EgressProto::Tcp, 443));
    assert_eq!(al.names_for(&a), vec!["x.example"]);
    assert_eq!(al.live_len(), 1);
}

/// Commit failure path: `drop_staged` removes only the staged set —
/// a live grant an earlier committed resolution vended stays.
#[test]
fn drop_staged_leaves_committed_grants() {
    let al = DynamicAllowList::new(16);
    let a = IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34));
    assert!(al.register("y.example", a, &[TCP_ANY], Duration::from_secs(60)));

    let s = al.begin_staging();
    // A staged refresh of the live key does not disturb it...
    assert!(al.register_staged(s, "y.example", a, &[TCP_ANY], Duration::from_secs(120)));
    // ...and a new staged key stays invisible.
    let b = IpAddr::V4(Ipv4Addr::new(93, 184, 216, 35));
    assert!(al.register_staged(s, "y.example", b, &[TCP_ANY], Duration::from_secs(60)));
    assert!(!al.is_allowed(&b, crate::policy::EgressProto::Tcp, 443));

    al.drop_staged(s);
    assert!(al.is_allowed(&a, crate::policy::EgressProto::Tcp, 443));
    assert!(!al.is_allowed(&b, crate::policy::EgressProto::Tcp, 443));
    assert_eq!(al.live_len(), 1);
}

/// Two resolutions for the same name stage independently: one
/// commit must not activate the other's still-pending grants.
#[test]
fn staging_tokens_are_isolated() {
    let al = DynamicAllowList::new(16);
    let a = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
    let s1 = al.begin_staging();
    let s2 = al.begin_staging();
    assert!(al.register_staged(s1, "n.example", a, &[TCP_ANY], Duration::from_secs(60)));
    assert!(al.register_staged(s2, "n.example", a, &[TCP_ANY], Duration::from_secs(90)));

    al.commit_staged(s2);
    assert!(al.is_allowed(&a, crate::policy::EgressProto::Tcp, 443));
    // s1's drop removes its own staged copy only.
    al.drop_staged(s1);
    assert!(al.is_allowed(&a, crate::policy::EgressProto::Tcp, 443));
}

/// Two resolutions racing the same name→addr under a full table
/// must both stage: the second token re-reserves the key the first
/// already holds — the reservation merges into one live grant on
/// commit, so it consumes no new capacity.
#[test]
fn staged_same_key_two_tokens_at_capacity() {
    let al = DynamicAllowList::new(1);
    let a = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10));
    let s1 = al.begin_staging();
    let s2 = al.begin_staging();
    assert!(al.register_staged_at(
        s1,
        "dup.example",
        a,
        &[TCP_ANY],
        Instant::now() + Duration::from_secs(60)
    ));
    assert!(al.register_staged_at(
        s2,
        "dup.example",
        a,
        &[TCP_ANY],
        Instant::now() + Duration::from_secs(90)
    ));
    // Neither reservation is visible before commit.
    assert!(!al.is_allowed(&a, crate::policy::EgressProto::Tcp, 443));
    assert!(al.names_for(&a).is_empty());
    assert_eq!(al.live_len(), 0);
    assert!(!al.snapshot_json().contains("dup.example"));

    al.commit_staged(s1);
    assert!(al.is_allowed(&a, crate::policy::EgressProto::Tcp, 443));
    assert_eq!(al.live_len(), 1);
    // s2's leftover staged copy drops without touching the grant
    // s1 committed.
    al.drop_staged(s2);
    assert!(al.is_allowed(&a, crate::policy::EgressProto::Tcp, 443));
    assert_eq!(al.live_len(), 1);
}

/// The stored RF02 reproducer's shape — capacity 2 holding one
/// live grant: both tokens reserve the shared key, `commit:s1`
/// publishes it once, `drop:s2` removes only s2's hold
/// (tests/fixtures/refactoring/rf02/capacity1_duplicate.json).
#[test]
fn staged_same_key_two_tokens_one_live() {
    let al = DynamicAllowList::new(2);
    let live = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
    let staged_addr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2));
    assert!(al.register("live.example", live, &[TCP_ANY], Duration::from_secs(60)));
    let s1 = al.begin_staging();
    let s2 = al.begin_staging();
    assert!(al.register_staged(
        s1,
        "x.example",
        staged_addr,
        &[TCP_ANY],
        Duration::from_secs(60)
    ));
    assert!(al.register_staged(
        s2,
        "x.example",
        staged_addr,
        &[TCP_ANY],
        Duration::from_secs(60)
    ));
    assert_eq!(al.live_len(), 1);
    al.commit_staged(s1);
    assert_eq!(al.live_len(), 2);
    assert!(al.is_allowed(&staged_addr, crate::policy::EgressProto::Tcp, 443));
    al.drop_staged(s2);
    assert_eq!(al.live_len(), 2);
    assert!(al.is_allowed(&staged_addr, crate::policy::EgressProto::Tcp, 443));
}

/// Either drop/commit order publishes the shared key once — a
/// token's cancellation never removes a reservation another token
/// still holds, and a second commit on the same key is a refresh.
#[test]
fn staged_same_key_drop_then_commit_and_reverse_commit() {
    // Drop the first stager, then commit the second.
    let al = DynamicAllowList::new(1);
    let a = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 11));
    let s1 = al.begin_staging();
    let s2 = al.begin_staging();
    assert!(al.register_staged(s1, "ord.example", a, &[TCP_ANY], Duration::from_secs(60)));
    assert!(al.register_staged(s2, "ord.example", a, &[TCP_ANY], Duration::from_secs(90)));
    al.drop_staged(s1);
    al.commit_staged(s2);
    assert!(al.is_allowed(&a, crate::policy::EgressProto::Tcp, 443));
    assert_eq!(al.live_len(), 1);

    // Commit in reverse registration order — the second commit
    // refreshes the same key (TTL/scope update), still one grant.
    let al = DynamicAllowList::new(1);
    let a = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 12));
    let s1 = al.begin_staging();
    let s2 = al.begin_staging();
    assert!(al.register_staged(s1, "ord.example", a, &[TCP_ANY], Duration::from_secs(60)));
    assert!(al.register_staged(s2, "ord.example", a, &[TCP_ANY], Duration::from_secs(90)));
    al.commit_staged(s2);
    al.commit_staged(s1);
    assert!(al.is_allowed(&a, crate::policy::EgressProto::Tcp, 443));
    assert_eq!(al.live_len(), 1);
}

/// A staged refresh of a *live* key never needs headroom — at
/// capacity 1 the refresh stages and its commit replaces expiry
/// and scope, the same update `register` performs in place.
#[test]
fn staged_refresh_of_live_key_at_capacity() {
    let al = DynamicAllowList::new(1);
    let a = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 20));
    let udp53 = crate::policy::GrantQual {
        proto: crate::policy::EgressProto::Udp,
        port: Some(53),
    };
    assert!(al.register("svc.example", a, &[TCP_ANY], Duration::from_secs(60)));
    let s = al.begin_staging();
    assert!(al.register_staged(s, "svc.example", a, &[udp53], Duration::from_secs(120)));
    // The refresh is invisible until commit — the live grant still
    // carries its original scope.
    assert!(al.is_allowed(&a, crate::policy::EgressProto::Tcp, 443));
    assert!(!al.is_allowed(&a, crate::policy::EgressProto::Udp, 53));
    al.commit_staged(s);
    assert!(!al.is_allowed(&a, crate::policy::EgressProto::Tcp, 443));
    assert!(al.is_allowed(&a, crate::policy::EgressProto::Udp, 53));
    assert_eq!(al.quals_for(&a), vec![udp53]);
    assert_eq!(al.live_len(), 1);
}

/// Move every entry staged under `token` into the past — the
/// resolution's answer aged out between mint and audit commit.
/// Registration still needs a future deadline (`register_staged_at`
/// refuses an already-lapsed one), so the expiry is rewound after
/// the fact instead of racing the real clock.
fn expire_staged(al: &DynamicAllowList, token: GrantStaging) {
    let mut inner = al.inner.lock().unwrap();
    let past = Instant::now()
        .checked_sub(Duration::from_secs(60))
        .unwrap_or_else(Instant::now);
    for e in inner.staged.get_mut(&token.0).unwrap().values_mut() {
        e.expires = past;
    }
}

/// A reservation that expires while staged commits as the
/// resolver's newer truth — landing the lapsed expiry closes the
/// key rather than letting stale authority linger.
#[test]
fn staged_entry_expiring_before_commit() {
    let al = DynamicAllowList::new(16);
    let a = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 30));
    // An unexpired reservation commits normally.
    let s = al.begin_staging();
    assert!(al.register_staged_at(
        s,
        "ttl.example",
        a,
        &[TCP_ANY],
        Instant::now() + Duration::from_secs(60)
    ));
    al.commit_staged(s);
    assert!(al.is_allowed(&a, crate::policy::EgressProto::Tcp, 443));
    // A reservation whose answer lapsed before commit lands the
    // newer truth — the expired entry overwrites the live grant.
    let s = al.begin_staging();
    assert!(al.register_staged_at(
        s,
        "ttl.example",
        a,
        &[TCP_ANY],
        Instant::now() + Duration::from_secs(60)
    ));
    expire_staged(&al, s);
    al.commit_staged(s);
    assert!(!al.is_allowed(&a, crate::policy::EgressProto::Tcp, 443));
    assert_eq!(al.live_len(), 0);

    // The same overwrite applies to a staged refresh of a live
    // key: an unexpired refresh renews the grant, an expired one
    // closes it.
    let b = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 31));
    assert!(al.register("live.example", b, &[TCP_ANY], Duration::from_secs(300)));
    let s = al.begin_staging();
    assert!(al.register_staged_at(
        s,
        "live.example",
        b,
        &[TCP_ANY],
        Instant::now() + Duration::from_secs(120)
    ));
    al.commit_staged(s);
    assert!(al.is_allowed(&b, crate::policy::EgressProto::Tcp, 443));
    let s = al.begin_staging();
    assert!(al.register_staged_at(
        s,
        "live.example",
        b,
        &[TCP_ANY],
        Instant::now() + Duration::from_secs(120)
    ));
    expire_staged(&al, s);
    al.commit_staged(s);
    assert!(!al.is_allowed(&b, crate::policy::EgressProto::Tcp, 443));
    assert_eq!(al.live_len(), 0);
}

/// Shared-key reservations share one reservation; *distinct* keys
/// still count separately — a different name on the same address
/// or a different address under the same name must be refused
/// once every unique key is spoken for.
#[test]
fn staged_distinct_key_at_capacity_refused() {
    let al = DynamicAllowList::new(1);
    let a = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 40));
    let b = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 41));
    let s1 = al.begin_staging();
    let s2 = al.begin_staging();
    assert!(al.register_staged(s1, "n.example", a, &[TCP_ANY], Duration::from_secs(60)));
    // Same key again from s2 — shares s1's reservation.
    assert!(al.register_staged(s2, "n.example", a, &[TCP_ANY], Duration::from_secs(60)));
    // A different name on the same address is a different key.
    assert!(!al.register_staged(s2, "m.example", a, &[TCP_ANY], Duration::from_secs(60)));
    // A different address under the same name is a different key.
    assert!(!al.register_staged(s2, "n.example", b, &[TCP_ANY], Duration::from_secs(60)));
    // The refusals stage nothing: s2 commits only its shared copy.
    al.commit_staged(s2);
    assert_eq!(al.live_len(), 1);
    assert_eq!(al.names_for(&a), vec!["n.example"]);
    al.drop_staged(s1);
}

/// Uncommitted reservations stay invisible to the exported
/// snapshot too — `export_to` serializes the same live-only view
/// `snapshot_json` produces.
#[test]
fn staged_grants_absent_from_export() {
    let dir = std::env::temp_dir() // nosemgrep: rust.lang.security.temp-dir.temp-dir
        .join("mcp_writ_test")
        .join(format!("export_staged_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let dest = dir.join("allowlist.json");
    let al = DynamicAllowList::new(16);
    let a = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 50));
    al.register("live.example", a, &[TCP_ANY], Duration::from_secs(60));
    let s = al.begin_staging();
    assert!(al.register_staged(
        s,
        "pending.example",
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 51)),
        &[TCP_ANY],
        Duration::from_secs(60)
    ));
    al.export_to(&dest).unwrap();
    let body = std::fs::read_to_string(&dest).unwrap();
    assert!(body.contains("live.example"));
    assert!(!body.contains("pending.example"));
    let _ = std::fs::remove_dir_all(&dir);
}

/// Direct registration counts live grants only — it never
/// consults the staged set. Callers do not mix the two modes on
/// one list (the gate stages, the CONNECT proxy registers), so
/// this overlap is a contract pin, not a production path.
#[test]
fn register_ignores_staged_capacity() {
    let al = DynamicAllowList::new(1);
    let a = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 60));
    let b = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 61));
    let s = al.begin_staging();
    assert!(al.register_staged(s, "staged.example", a, &[TCP_ANY], Duration::from_secs(60)));
    assert!(al.register("direct.example", b, &[TCP_ANY], Duration::from_secs(60)));
    assert_eq!(al.live_len(), 1);
    al.drop_staged(s);
}

/// `drop_staged_unwind_safe` must not panic on a poisoned lock —
/// `StagingGuard` runs it inside `Drop`, where a second panic
/// during unwind would abort the process. The bucket discard is
/// memory-safe even on possibly-inconsistent state.
#[test]
fn drop_staged_unwind_safe_tolerates_a_poisoned_lock() {
    let al = std::sync::Arc::new(DynamicAllowList::new(4));
    let a = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 70));
    let s = al.begin_staging();
    assert!(al.register_staged(s, "p.example", a, &[TCP_ANY], Duration::from_secs(60)));
    // Poison the lock: a thread panics while holding it.
    let al2 = al.clone();
    let _ = std::thread::spawn(move || {
        let _guard = al2.inner.lock().unwrap();
        panic!("intentional poison");
    })
    .join();
    assert!(al.inner.lock().is_err(), "lock must be poisoned");
    // No panic — and the stranded bucket is still discarded.
    al.drop_staged_unwind_safe(s);
    let inner = al.inner.lock().unwrap_or_else(|e| e.into_inner());
    assert!(inner.staged.is_empty());
}

/// Rollback for the fail-closed ordering contract: a grant minted
/// before its audit record committed is revoked when the commit
/// fails — the revoked key no longer authorizes.
#[test]
fn revoke_removes_only_the_named_grant() {
    let al = DynamicAllowList::new(16);
    let a = IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34));
    let b = IpAddr::V4(Ipv4Addr::new(93, 184, 216, 35));
    assert!(al.register("x.example", a, &[TCP_ANY], Duration::from_secs(60)));
    assert!(al.register("x.example", b, &[TCP_ANY], Duration::from_secs(60)));
    assert!(al.register("y.example", a, &[TCP_ANY], Duration::from_secs(60)));

    al.revoke("x.example", a);
    // The address stays authorized: `y.example` independently vended
    // it, and that grant carries its own committed audit record.
    assert!(al.is_allowed(&a, crate::policy::EgressProto::Tcp, 443));
    assert_eq!(al.names_for(&a), vec!["y.example"]);
    // The other addr under the revoked name survives — the key is
    // (name, addr).
    assert!(al.is_allowed(&b, crate::policy::EgressProto::Tcp, 443));
    // Once every name→a grant is revoked the address no longer
    // authorizes — the rollback property the DNS gate relies on.
    al.revoke("y.example", a);
    assert!(
        !al.is_allowed(&a, crate::policy::EgressProto::Tcp, 443),
        "last grant for an addr must close it"
    );
    // Revoking an absent key is a no-op.
    al.revoke("x.example", a);
    al.revoke("absent.example", a);
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
    let dir = std::env::temp_dir() // nosemgrep: rust.lang.security.temp-dir.temp-dir
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
    // The fixture dir is the product's owner-only tempdir — a
    // security-operation test must not stage in a shared,
    // pre-creatable temp path.
    let dir = crate::fspriv::create_private_tempdir("export_link").unwrap();
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
    if crate::fspriv::running_as_root() {
        eprintln!("SKIP: root bypasses the 0o555 mode — cannot exercise EACCES");
        return;
    }
    let dir = crate::fspriv::create_private_tempdir("export_ro").unwrap();
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
    let dir = crate::fspriv::create_private_tempdir("export_mode").unwrap();
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

// ---- RF07: indexed layout, staged refcounts, deadline heap ------

/// xorshift64* — a tiny deterministic stream so the reference-
/// model trace replays identically run to run.
struct Xor64(u64);

impl Xor64 {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn pick(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

/// The flat, full-scan semantics the indexed layout replaced —
/// the reference the seeded op trace validates every state
/// transition against. Test-only; never part of the shipped
/// table.
struct RefEntry {
    expires: Instant,
    quals: Vec<crate::policy::GrantQual>,
}

struct RefList {
    max: usize,
    live: HashMap<(IpAddr, String), RefEntry>,
    staged: HashMap<u64, HashMap<(IpAddr, String), RefEntry>>,
    next_token: u64,
}

impl RefList {
    fn new(max: usize) -> Self {
        Self {
            max,
            live: HashMap::new(),
            staged: HashMap::new(),
            next_token: 1,
        }
    }

    fn begin_staging(&mut self) -> u64 {
        let t = self.next_token;
        self.next_token += 1;
        t
    }

    /// The `retain` sweep the flat table ran on every register.
    fn reap(&mut self, now: Instant) {
        self.live.retain(|_, e| e.expires > now);
    }

    fn register_at(
        &mut self,
        name: &str,
        addr: IpAddr,
        quals: &[crate::policy::GrantQual],
        expires: Instant,
        now: Instant,
    ) -> bool {
        if expires <= now || quals.is_empty() {
            return false;
        }
        self.reap(now);
        let k = (addr, name.to_string());
        if let Some(e) = self.live.get_mut(&k) {
            e.expires = expires;
            e.quals = quals.to_vec();
            return true;
        }
        if self.live.len() >= self.max {
            return false;
        }
        self.live.insert(
            k,
            RefEntry {
                expires,
                quals: quals.to_vec(),
            },
        );
        true
    }

    /// Unique staged keys that would land as new live grants —
    /// the `staged_new` set the flat code rebuilt per call.
    fn staged_new_len(&self) -> usize {
        let mut keys = std::collections::HashSet::new();
        for entries in self.staged.values() {
            for k in entries.keys() {
                if !self.live.contains_key(k) {
                    keys.insert(k);
                }
            }
        }
        keys.len()
    }

    fn register_staged_at(
        &mut self,
        staging: u64,
        name: &str,
        addr: IpAddr,
        quals: &[crate::policy::GrantQual],
        expires: Instant,
        now: Instant,
    ) -> bool {
        if expires <= now || quals.is_empty() {
            return false;
        }
        self.reap(now);
        let k = (addr, name.to_string());
        if let Some(e) = self.staged.get_mut(&staging).and_then(|m| m.get_mut(&k)) {
            e.expires = expires;
            e.quals = quals.to_vec();
            return true;
        }
        if !self.live.contains_key(&k) {
            let already_staged = self.staged.values().any(|m| m.contains_key(&k));
            if !already_staged && self.live.len() + self.staged_new_len() >= self.max {
                return false;
            }
        }
        self.staged.entry(staging).or_default().insert(
            k,
            RefEntry {
                expires,
                quals: quals.to_vec(),
            },
        );
        true
    }

    /// Commit lands every staged entry — including one whose
    /// deadline lapsed while held: it is inserted dead, not promoted,
    /// identical to the table (present until a reap, filtered by
    /// expiry on every read).
    fn commit_staged(&mut self, staging: u64) {
        if let Some(entries) = self.staged.remove(&staging) {
            for (k, e) in entries {
                self.live.insert(k, e);
            }
        }
    }

    fn drop_staged(&mut self, staging: u64) {
        self.staged.remove(&staging);
    }

    fn revoke(&mut self, name: &str, addr: IpAddr) {
        self.live.remove(&(addr, name.to_string()));
    }

    /// The same question `grant_view_at` answers, asked of the
    /// flat map: live names on `addr` (sorted) plus coverage.
    fn view_at(
        &self,
        addr: IpAddr,
        proto: crate::policy::EgressProto,
        port: u16,
        now: Instant,
    ) -> (Vec<String>, bool) {
        let mut names = Vec::new();
        let mut covered = false;
        for ((a, name), e) in &self.live {
            if *a == addr && e.expires > now {
                names.push(name.clone());
                if !covered {
                    covered = e.quals.iter().any(|q| q.covers(proto, port));
                }
            }
        }
        names.sort();
        (names, covered)
    }
}

/// Structural invariants tying the derived counters back to the
/// maps they summarize — checked after every traced op.
fn assert_bookkeeping(al: &DynamicAllowList, rf: &RefList) {
    let inner = al.inner.lock().unwrap();
    let live: usize = inner.by_addr.values().map(|m| m.len()).sum();
    assert_eq!(inner.live_total, live);
    assert_eq!(live, rf.live.len());
    assert_eq!(inner.staged_new, rf.staged_new_len());
    // staged_counts == the multiset of staged keys across tokens.
    let mut holds: HashMap<&GrantKey, usize> = HashMap::new();
    for entries in inner.staged.values() {
        for k in entries.keys() {
            *holds.entry(k).or_default() += 1;
        }
    }
    assert_eq!(inner.staged_counts.len(), holds.len());
    for (k, c) in &inner.staged_counts {
        assert_eq!(holds.get(k), Some(c));
    }
    // staged_new == the staged keys that are not live — the set
    // the reference computes outright.
    let new_keys = holds.keys().filter(|k| !inner.live_has(k)).count();
    assert_eq!(inner.staged_new, new_keys);
    // Every live entry's current generation sits in the heap —
    // reaping relies on that pairing.
    for (addr, names) in &inner.by_addr {
        for (name, e) in names {
            assert!(
                inner
                    .deadlines
                    .iter()
                    .any(|Reverse((d, g, a, n))| *d == e.expires
                        && *g == e.generation
                        && *a == *addr
                        && n.as_ref() == name.as_str()),
                "live entry {name}@{addr} lost its deadline"
            );
        }
    }
}

/// Drive identical register / stage / commit / drop / revoke /
/// reap / check sequences through the indexed table and the flat
/// reference model — same-key updates, exact expiry boundaries,
/// TTL shortening, and capacity recovery all fall out of the
/// seeded trace.
#[test]
fn indexed_state_matches_flat_reference_model() {
    use crate::policy::{EgressProto, GrantQual};
    let names = [
        "a.example",
        "b.example",
        "c.example",
        "d.example",
        "e.example",
        "f.example",
    ];
    // Several names pile onto one address — the concentrated-IP
    // shape the index is built for.
    let hot = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10));
    let addrs = [
        hot,
        hot,
        IpAddr::V4(Ipv4Addr::new(198, 51, 100, 20)),
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 30)),
        "2001:db8::40".parse().unwrap(),
        "2001:db8::41".parse().unwrap(),
    ];
    let never_addr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 200));
    let quals_pool: [&[GrantQual]; 4] = [
        &[GrantQual::TCP_ANY],
        &[GrantQual {
            proto: EgressProto::Any,
            port: None,
        }],
        &[GrantQual {
            proto: EgressProto::Udp,
            port: Some(53),
        }],
        &[
            GrantQual {
                proto: EgressProto::Tcp,
                port: Some(443),
            },
            GrantQual {
                proto: EgressProto::Udp,
                port: Some(443),
            },
        ],
    ];
    let flows: [(EgressProto, u16); 6] = [
        (EgressProto::Tcp, 443),
        (EgressProto::Tcp, 53),
        (EgressProto::Udp, 53),
        (EgressProto::Udp, 443),
        (EgressProto::Any, 80),
        (EgressProto::Tcp, 80),
    ];
    // One monotone test clock shared by both implementations: every
    // mutating op — stage, register, reap — runs at `t`, so a
    // simulated reap can never land behind the mint it is meant to
    // clean up (the old grid reaps mixed simulated instants with the
    // wall-clock `Instant::now()` inside registrations, letting time
    // move backward). Lookups are pure queries: they are checked at
    // `t` plus a deadline-relative spread, where stepping ahead is
    // consistent by construction.
    let mut t = Instant::now();
    let offsets: [u64; 17] = [
        0, 5, 20, 29, 30, 31, 44, 45, 60, 61, 74, 75, 76, 89, 90, 91, 120,
    ];
    let mut rng = Xor64(0x9E37_79B9_7F4A_7C15);
    let al = DynamicAllowList::new(24);
    let mut rf = RefList::new(24);
    let mut tokens: Vec<(GrantStaging, u64)> = Vec::new();

    // Expiries are either clearly past `t` (refused identically on
    // both sides) or 30–90s ahead of it. As `t` advances, a staged
    // token can outlive the deadline it minted — the expired-commit
    // case both sides must land dead rather than promote.
    let expiry_for = |rng: &mut Xor64, now: Instant| -> Instant {
        match rng.pick(8) {
            0 => now.checked_sub(Duration::from_secs(1)).unwrap_or(now),
            n => now + Duration::from_secs([30, 45, 60, 60, 75, 75, 90][n - 1]),
        }
    };

    for step in 0..600 {
        // The shared clock advances before each op — 0–700ms steps
        // carry the trace past every generated deadline.
        t += Duration::from_millis(rng.pick(8) as u64 * 100);
        let op = rng.pick(100);
        if op < 12 && tokens.len() < 8 {
            tokens.push((al.begin_staging(), rf.begin_staging()));
        } else if !tokens.is_empty() || op >= 75 {
            let name = names[rng.pick(names.len())];
            let addr = addrs[rng.pick(addrs.len())];
            match op {
                // Stage a grant under a live token — the same key
                // from a second token shares its reservation.
                12..=36 => {
                    let i = rng.pick(tokens.len());
                    let (tok, rtok) = tokens[i];
                    let quals = quals_pool[rng.pick(quals_pool.len())];
                    let exp = expiry_for(&mut rng, t);
                    assert_eq!(
                        al.register_staged_at_clock(tok, name, addr, quals, exp, t),
                        rf.register_staged_at(rtok, name, addr, quals, exp, t),
                        "register_staged diverged at step {step}"
                    );
                }
                // Direct refresh/insert — same-key TTL updates
                // (including shortenings) land here.
                37..=52 => {
                    let quals = quals_pool[rng.pick(quals_pool.len())];
                    let exp = expiry_for(&mut rng, t);
                    assert_eq!(
                        al.register_at_clock(name, addr, quals, exp, t),
                        rf.register_at(name, addr, quals, exp, t),
                        "register diverged at step {step}"
                    );
                }
                53..=64 => {
                    let i = rng.pick(tokens.len());
                    let (tok, rtok) = tokens.swap_remove(i);
                    al.commit_staged(tok);
                    rf.commit_staged(rtok);
                }
                65..=74 => {
                    let i = rng.pick(tokens.len());
                    let (tok, rtok) = tokens.swap_remove(i);
                    al.drop_staged(tok);
                    rf.drop_staged(rtok);
                }
                75..=79 => {
                    al.revoke(name, addr);
                    rf.revoke(name, addr);
                }
                // A lazy reap at the shared instant — expiry-driven
                // capacity recovery, run identically on both.
                80..=89 => {
                    reap_expired(&mut al.inner.lock().unwrap(), t);
                    rf.reap(t);
                }
                _ => {}
            }
        }
        assert_bookkeeping(&al, &rf);
        let at = t + Duration::from_secs(offsets[rng.pick(offsets.len())]);
        for &addr in addrs.iter().chain(std::iter::once(&never_addr)) {
            for &(proto, port) in &flows {
                let v = al.grant_view_at(&addr, proto, port, at);
                let (rn, rc) = rf.view_at(addr, proto, port, at);
                assert_eq!(
                    (v.names.as_slice(), v.covered),
                    (rn.as_slice(), rc),
                    "view diverged at step {step}: {addr} {proto:?}:{port} @{at:?}"
                );
                assert_eq!(al.is_allowed_at(&addr, proto, port, at), v.covered);
            }
        }
    }
}

/// One lock's worth of state: the verdict's `covered` flag and the
/// audit's name list come from the same read — and `names` keeps
/// the sorted order `names_for` has always returned.
#[test]
fn grant_view_names_and_coverage_from_one_snapshot() {
    use crate::policy::{EgressProto, GrantQual};
    let al = DynamicAllowList::new(16);
    let a = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 60));
    let udp53 = GrantQual {
        proto: EgressProto::Udp,
        port: Some(53),
    };
    al.register("b.example", a, &[TCP_ANY], Duration::from_secs(60));
    al.register("a.example", a, &[udp53], Duration::from_secs(60));
    let v = al.grant_view(&a, EgressProto::Tcp, 8443);
    assert_eq!(v.names, vec!["a.example", "b.example"]);
    assert!(v.covered);
    let v = al.grant_view(&a, EgressProto::Udp, 443);
    assert_eq!(v.names, vec!["a.example", "b.example"]);
    assert!(!v.covered);
    let v = al.grant_view(&a, EgressProto::Udp, 53);
    assert!(v.covered);
    // An expired name leaves both halves of the view.
    let v = al.grant_view_at(
        &a,
        EgressProto::Tcp,
        443,
        Instant::now() + Duration::from_secs(90),
    );
    assert!(v.names.is_empty() && !v.covered);
}

/// Two names sharing one address keep independent expiries — the
/// index must not merge them into a single TTL.
#[test]
fn same_addr_names_expire_independently() {
    let al = DynamicAllowList::new(16);
    let a = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 61));
    let t0 = Instant::now();
    al.register_at("short.example", a, &[TCP_ANY], t0 + Duration::from_secs(30));
    al.register_at("long.example", a, &[TCP_ANY], t0 + Duration::from_secs(120));
    let at = |s: u64| t0 + Duration::from_secs(s);
    assert_eq!(
        al.grant_view_at(&a, crate::policy::EgressProto::Tcp, 443, at(20))
            .names,
        vec!["long.example", "short.example"]
    );
    reap_expired(&mut al.inner.lock().unwrap(), at(60));
    assert_eq!(
        al.grant_view_at(&a, crate::policy::EgressProto::Tcp, 443, at(61))
            .names,
        vec!["long.example"]
    );
    assert_eq!(al.live_len(), 1);
    assert_eq!(al.names_for(&a), vec!["long.example"]);
}

/// Re-staging a key that is already live reserves nothing — but
/// once that live grant is reaped or revoked, the still-held
/// staged copy resumes counting as a new-key reservation.
#[test]
fn staged_hold_resumes_reservation_when_live_key_reaps() {
    let al = DynamicAllowList::new(2);
    let a = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 62));
    let t0 = Instant::now();
    al.register_at("n.example", a, &[TCP_ANY], t0 + Duration::from_secs(30));
    let s = al.begin_staging();
    // Staging the live key needs no headroom.
    assert!(al.register_staged_at(s, "n.example", a, &[TCP_ANY], t0 + Duration::from_secs(120)));
    // A second live grant fills the remaining slot.
    assert!(al.register_at("m.example", a, &[TCP_ANY], t0 + Duration::from_secs(120)));
    // n's live grant reaps out from under the staged copy — the
    // hold is a new-key reservation again, and the table is full:
    // live(m)=1 + staged_new(n)=1 == max 2.
    reap_expired(&mut al.inner.lock().unwrap(), t0 + Duration::from_secs(60));
    assert_eq!(al.live_len(), 1);
    let s2 = al.begin_staging();
    assert!(!al.register_staged_at(
        s2,
        "p.example",
        a,
        &[TCP_ANY],
        t0 + Duration::from_secs(120)
    ));
    // Committing s lands n against the reservation it resumed.
    al.commit_staged(s);
    assert_eq!(al.live_len(), 2);
    assert!(al.is_allowed_at(
        &a,
        crate::policy::EgressProto::Tcp,
        443,
        t0 + Duration::from_secs(70)
    ));
}

/// A refreshed expiry pushes a new deadline under a bumped
/// generation; the superseded heap entry must never reap the
/// refreshed grant — TTL shortenings included.
#[test]
fn stale_deadline_never_reaps_refreshed_grant() {
    let al = DynamicAllowList::new(16);
    let a = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 63));
    let t0 = Instant::now();
    // Shortening refresh: the resolver's newer truth (30s) wins,
    // and the superseded 120s deadline reaps nothing it shouldn't.
    al.register_at("n.example", a, &[TCP_ANY], t0 + Duration::from_secs(120));
    al.register_at("n.example", a, &[TCP_ANY], t0 + Duration::from_secs(30));
    reap_expired(&mut al.inner.lock().unwrap(), t0 + Duration::from_secs(45));
    assert_eq!(al.live_len(), 0);
    // Lengthening refresh: the stale 30s deadline pops first and
    // must skip — the grant lives to its 120s truth.
    al.register_at("n.example", a, &[TCP_ANY], t0 + Duration::from_secs(30));
    al.register_at("n.example", a, &[TCP_ANY], t0 + Duration::from_secs(120));
    reap_expired(&mut al.inner.lock().unwrap(), t0 + Duration::from_secs(60));
    assert!(al.is_allowed_at(
        &a,
        crate::policy::EgressProto::Tcp,
        443,
        t0 + Duration::from_secs(90)
    ));
}

/// Every refresh strands one stale heap entry — the rebuild bound
/// keeps the heap proportional to live count, not update count.
#[test]
fn deadline_heap_stays_bounded_under_update_churn() {
    let al = DynamicAllowList::new(16);
    let a = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 64));
    for _ in 0..600 {
        assert!(al.register("n.example", a, &[TCP_ANY], Duration::from_secs(60)));
    }
    let inner = al.inner.lock().unwrap();
    assert!(
        inner.deadlines.len() <= usize::max(2 * inner.live_total, DEADLINE_REBUILD_FLOOR),
        "heap {} vs live {}",
        inner.deadlines.len(),
        inner.live_total
    );
    drop(inner);
    // Churn across many keys tells the same story — a list sized for
    // the whole key set so every registration is accepted (a refusal
    // would only shrink the churn it claims to measure), and enough
    // complete refresh rounds to push the heap past the rebuild
    // threshold: 200 initial pushes plus rounds of 200 cross
    // max(2*live, floor) = 400 mid-round and rebuild repeatedly.
    let al = DynamicAllowList::new(200);
    let addr_of = |i: u32| IpAddr::V4(Ipv4Addr::new(192, 0, 3, i as u8));
    for i in 0..200u32 {
        assert!(al.register("n.example", addr_of(i), &[TCP_ANY], Duration::from_secs(60)));
    }
    for _ in 0..3 {
        for i in 0..200u32 {
            assert!(al.register("n.example", addr_of(i), &[TCP_ANY], Duration::from_secs(60)));
        }
    }
    let inner = al.inner.lock().unwrap();
    assert_eq!(inner.live_total, 200);
    assert!(
        inner.deadlines.len() <= usize::max(2 * inner.live_total, DEADLINE_REBUILD_FLOOR),
        "heap {} vs live {}",
        inner.deadlines.len(),
        inner.live_total
    );
}

/// Commit batches and revocations strand stale deadlines the
/// same way refreshes do — both paths compact against the bound
/// on their own, without a register having to trigger it first.
#[test]
fn deadline_heap_compacts_on_commit_and_revoke() {
    let al = DynamicAllowList::new(400);
    let t0 = Instant::now();
    let addr_of = |i: u32| IpAddr::V4(Ipv4Addr::new(192, 0, 5 + (i / 256) as u8, (i % 256) as u8));
    for i in 0..300u32 {
        assert!(al.register_at(
            &format!("n{i}.example"),
            addr_of(i),
            &[TCP_ANY],
            t0 + Duration::from_secs(300)
        ));
    }
    // Refresh-commit rounds strand the previous generation per
    // key; the commit-side compaction must hold the bound
    // between rounds — no register intervenes.
    for round in 0..3u32 {
        let s = al.begin_staging();
        for i in 0..300u32 {
            assert!(al.register_staged_at(
                s,
                &format!("n{i}.example"),
                addr_of(i),
                &[TCP_ANY],
                t0 + Duration::from_secs(300)
            ));
        }
        al.commit_staged(s);
        let inner = al.inner.lock().unwrap();
        assert!(
            inner.deadlines.len() <= usize::max(2 * inner.live_total, DEADLINE_REBUILD_FLOOR),
            "commit round {round} left {} deadlines over the bound (live {})",
            inner.deadlines.len(),
            inner.live_total
        );
    }
    // Mass-revoke shrinks `live_total` out from under the heap —
    // each successful revoke compacts, so stranded deadlines
    // leave with their grants instead of waiting for a write.
    for i in 0..280u32 {
        al.revoke(&format!("n{i}.example"), addr_of(i));
    }
    let inner = al.inner.lock().unwrap();
    assert_eq!(inner.live_total, 20);
    assert!(
        inner.deadlines.len() <= usize::max(2 * inner.live_total, DEADLINE_REBUILD_FLOOR),
        "revoke left {} deadlines over the bound (live {})",
        inner.deadlines.len(),
        inner.live_total
    );
}

/// `expires > now` is strict: at the exact deadline instant the
/// grant is already closed — the lookup-side check never waits
/// for the reaper to catch up.
#[test]
fn grant_expires_at_its_exact_deadline() {
    let al = DynamicAllowList::new(16);
    let a = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 65));
    let t0 = Instant::now();
    let exp = t0 + Duration::from_secs(30);
    al.register_at("n.example", a, &[TCP_ANY], exp);
    assert!(al.is_allowed_at(
        &a,
        crate::policy::EgressProto::Tcp,
        443,
        exp - Duration::from_millis(1)
    ));
    assert!(!al.is_allowed_at(&a, crate::policy::EgressProto::Tcp, 443, exp));
    let v = al.grant_view_at(&a, crate::policy::EgressProto::Tcp, 443, exp);
    assert!(v.names.is_empty() && !v.covered);
    // And the not-yet-reaped entry denies exactly like a reaped
    // one would.
    assert!(!al.is_allowed_at(
        &a,
        crate::policy::EgressProto::Tcp,
        443,
        t0 + Duration::from_secs(31)
    ));
}
