use std::fs;

use super::*;

#[cfg(windows)]
use super::winsec::{
    SdGuard, dacl_grants_replace_rights, dacl_has_untrusted_grant, dir_replace_rights,
    file_write_rights, on_disk_entry_name, process_user_sid,
};
#[cfg(unix)]
use std::io;
#[cfg(windows)]
use std::path::PathBuf;

#[test]
fn private_tempdir_is_directory() {
    let dir = create_private_tempdir("test").unwrap();
    assert!(dir.is_dir());
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn skip_nested_secrets() {
    assert!(should_skip_build_entry(".env"));
    assert!(should_skip_build_entry("node_modules"));
    assert!(!should_skip_build_entry("src"));
}

/// The Windows restriction is a real protected DACL — user + SYSTEM
/// only — that children inherit, not a default-ACL no-op.
#[cfg(windows)]
#[test]
fn windows_restriction_is_protected_owner_and_system_dacl() {
    use windows::Win32::Foundation::HLOCAL;
    use windows::Win32::Security::{
        ACL, DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, SE_DACL_PROTECTED,
    };
    use windows::core::HSTRING;

    let dir = create_private_tempdir("acl").unwrap();
    let child = dir.join("child.txt");
    fs::write(&child, "credentials").unwrap();

    let mut dacl: *mut ACL = std::ptr::null_mut();
    let mut sd = PSECURITY_DESCRIPTOR(std::ptr::null_mut());
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    unsafe {
        windows::Win32::Security::Authorization::GetNamedSecurityInfoW(
            &HSTRING::from(dir.to_string_lossy().as_ref()),
            windows::Win32::Security::Authorization::SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            None,
            None,
            Some(&mut dacl),
            None,
            &mut sd,
        )
        .ok()
        .expect("DACL query");
        let mut control = 0u16;
        let mut revision = 0u32;
        windows::Win32::Security::GetSecurityDescriptorControl(sd, &mut control, &mut revision)
            .expect("SD control");
        assert_ne!(
            control & SE_DACL_PROTECTED.0,
            0,
            "session DACL must block inherited entries"
        );
        // SetEntriesInAclW splits each entry into a direct ACE and an
        // inherit-only (OI|CI|IO) ACE: user + SYSTEM twice over.
        assert_eq!((*dacl).AceCount, 4, "user + SYSTEM ACEs only");
        windows::Win32::Foundation::LocalFree(Some(HLOCAL(sd.0)));
    }
    // The restriction inherits to files created after it was applied.
    let mut child_dacl: *mut ACL = std::ptr::null_mut();
    let mut child_sd = PSECURITY_DESCRIPTOR(std::ptr::null_mut());
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    unsafe {
        windows::Win32::Security::Authorization::GetNamedSecurityInfoW(
            &HSTRING::from(child.to_string_lossy().as_ref()),
            windows::Win32::Security::Authorization::SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            None,
            None,
            Some(&mut child_dacl),
            None,
            &mut child_sd,
        )
        .ok()
        .expect("child DACL query");
        assert_eq!((*child_dacl).AceCount, 2, "children inherit the DACL");
        windows::Win32::Foundation::LocalFree(Some(HLOCAL(child_sd.0)));
    }
    let _ = fs::remove_dir_all(&dir);
}

// ── safe_copy_file / safe_copy_dir ───────────────────────────────

#[test]
fn safe_copy_file_copies_contents() {
    let dir = create_private_tempdir("cp").unwrap();
    let src = dir.join("src.txt");
    fs::write(&src, b"payload bytes").unwrap();
    let dst = dir.join("nested").join("dst.txt");
    let root = canonical_root(&dir).unwrap();
    assert_eq!(
        safe_copy_file(&src, &dst, &root).unwrap(),
        SafeCopyOutcome::Copied(13)
    );
    assert_eq!(fs::read(&dst).unwrap(), b"payload bytes");
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn safe_copy_file_refuses_outside_root() {
    let dir = create_private_tempdir("cp-out").unwrap();
    let outside = create_private_tempdir("cp-root").unwrap();
    let src = dir.join("src.txt");
    fs::write(&src, b"data").unwrap();
    let dst = outside.join("dst.txt");
    let wrong_root = canonical_root(&outside).unwrap();
    // A root that does not contain the source fails the containment
    // proof — the same check a swapped-in link trips.
    assert!(safe_copy_file(&src, &dst, &wrong_root).is_err());
    assert!(!dst.exists());
    let _ = fs::remove_dir_all(&dir);
    let _ = fs::remove_dir_all(&outside);
}

#[cfg(unix)]
#[test]
fn safe_copy_file_skips_symlink() {
    let dir = create_private_tempdir("cp-link").unwrap();
    let real = dir.join("real.txt");
    fs::write(&real, b"secret").unwrap();
    let link = dir.join("link.txt");
    std::os::unix::fs::symlink(&real, &link).unwrap();
    let dst = dir.join("dst.txt");
    let root = canonical_root(&dir).unwrap();
    assert_eq!(
        safe_copy_file(&link, &dst, &root).unwrap(),
        SafeCopyOutcome::Skipped
    );
    assert!(!dst.exists());
    let _ = fs::remove_dir_all(&dir);
}

#[cfg(unix)]
#[test]
fn safe_copy_dir_skips_links_and_filtered_names() {
    let dir = create_private_tempdir("cpdir").unwrap();
    let src = dir.join("src");
    fs::create_dir_all(src.join("sub")).unwrap();
    fs::write(src.join("main.js"), "code").unwrap();
    fs::write(src.join("sub/helper.js"), "more").unwrap();
    fs::write(src.join(".env"), "SECRET=x").unwrap();
    std::os::unix::fs::symlink(&src, src.join("loop")).unwrap();
    std::os::unix::fs::symlink("/etc/passwd", src.join("evil")).unwrap();

    let dst = dir.join("dst");
    let root = canonical_root(&src).unwrap();
    safe_copy_dir(
        &src,
        &dst,
        &root,
        0,
        &|name| should_skip_build_entry(name),
        &mut CopyBudget::new(1024, 1 << 20, 1 << 20),
    )
    .unwrap();

    assert!(dst.join("main.js").exists());
    assert!(dst.join("sub/helper.js").exists());
    assert!(!dst.join(".env").exists());
    assert!(!dst.join("loop").exists());
    assert!(!dst.join("evil").exists());
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn read_file_bounded_refuses_oversize() {
    let dir = create_private_tempdir("bounded").unwrap();
    let path = dir.join("f.bin");
    fs::write(&path, vec![0xABu8; 100]).unwrap();
    assert_eq!(read_file_bounded(&path, 100).unwrap().len(), 100);
    assert!(read_file_bounded(&path, 99).is_err());
    assert!(read_text_bounded(&path, 4).is_err());
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn write_file_atomic_writes_and_overwrites() {
    let dir = create_private_tempdir("atomic").unwrap();
    let path = dir.join("report.json");
    write_file_atomic(&path, b"one").unwrap();
    assert_eq!(fs::read(&path).unwrap(), b"one");
    // A second write replaces via rename — no residue.
    write_file_atomic(&path, b"two").unwrap();
    assert_eq!(fs::read(&path).unwrap(), b"two");
    assert_eq!(
        fs::read_dir(&dir).unwrap().count(),
        1,
        "temp file leaked alongside destination"
    );
    let _ = fs::remove_dir_all(&dir);
}

/// When the temp create itself fails (unwritable directory), the
/// destination and every sibling must be left exactly as found —
/// cleanup only runs on files we created.
#[cfg(unix)]
#[test]
fn write_file_atomic_failed_create_touches_nothing() {
    use std::os::unix::fs::PermissionsExt;
    if running_as_root() {
        eprintln!("SKIP: root bypasses the 0o555 mode — cannot exercise EACCES");
        return;
    }
    let dir = create_private_tempdir("atomic-ro").unwrap();
    let dest = dir.join("report.json");
    fs::write(&dest, b"pre-existing").unwrap();
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o555)).unwrap();

    let err = write_file_atomic(&dest, b"new").unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
    assert_eq!(fs::read(&dest).unwrap(), b"pre-existing");
    assert_eq!(fs::read_dir(&dir).unwrap().count(), 1);

    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
    let _ = fs::remove_dir_all(&dir);
}

/// The pinned mode must not depend on the process umask: a report
/// carries policy detail and is never other-readable.
#[cfg(unix)]
#[test]
fn write_file_atomic_uses_restrictive_mode() {
    use std::os::unix::fs::PermissionsExt;
    let dir = create_private_tempdir("atomic-mode").unwrap();
    let path = dir.join("report.json");
    write_file_atomic(&path, b"{}").unwrap();
    let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "report mode was {mode:o}");
    let _ = fs::remove_dir_all(&dir);
}

/// A pinned directory verifies while it is the same object, and a
/// rename-away + recreate (a replacement that would redirect a
/// guest mount) fails verification.
#[cfg(unix)]
#[test]
fn pinned_dir_detects_replacement() {
    let root = create_private_tempdir("pin").unwrap();
    let dir = root.join("logs");
    fs::create_dir(&dir).unwrap();
    let pinned = PinnedDir::pin(&dir).unwrap();
    pinned.verify_current().expect("same object verifies");

    // Swap: rename the real dir away and plant a fresh one —
    // same path, different inode.
    let decoy = root.join("logs-moved");
    fs::rename(&dir, &decoy).unwrap();
    fs::create_dir(&dir).unwrap();
    assert!(
        pinned.verify_current().is_err(),
        "a replaced directory must fail the identity check"
    );

    let _ = fs::remove_dir_all(&root);
}

/// A symlink where the directory is expected never pins — the mount
/// would otherwise follow the link to an unintended host path.
#[cfg(unix)]
#[test]
fn pinned_dir_rejects_symlink() {
    let root = create_private_tempdir("pin-link").unwrap();
    let real = root.join("real");
    fs::create_dir(&real).unwrap();
    let link = root.join("link");
    std::os::unix::fs::symlink(&real, &link).unwrap();
    assert!(PinnedDir::pin(&link).is_err());
    let _ = fs::remove_dir_all(&root);
}

/// A group/world-writable parent without the sticky bit allows a
/// lower-trust principal to rename the pinned object away — the
/// launch must refuse it. A sticky parent (/tmp-style) is fine.
#[cfg(unix)]
#[test]
fn parent_write_restriction() {
    use std::os::unix::fs::PermissionsExt;
    let root = create_private_tempdir("parent-restrict").unwrap();
    let loose = root.join("loose");
    fs::create_dir(&loose).unwrap();
    fs::set_permissions(&loose, fs::Permissions::from_mode(0o777)).unwrap();
    let child = loose.join("logs");
    fs::create_dir(&child).unwrap();
    assert!(
        require_parent_write_restricted(&child).is_err(),
        "world-writable non-sticky parent must refuse"
    );

    fs::set_permissions(&loose, fs::Permissions::from_mode(0o1777)).unwrap();
    assert!(
        require_parent_write_restricted(&child).is_ok(),
        "sticky world-writable parent (/tmp-style) is safe"
    );
    fs::set_permissions(&loose, fs::Permissions::from_mode(0o755)).unwrap();
    assert!(require_parent_write_restricted(&child).is_ok());

    let _ = fs::remove_dir_all(&root);
}

/// The default drive-root DACL carries an *inherit-only*
/// `Authenticated Users` Modify ACE — it grants rights to children
/// created below, never to the root itself. An earlier revision
/// tested `AceFlags` against `INHERITED_ACE` (0x10) instead of
/// `INHERIT_ONLY_ACE` (0x08): the root's inherit-only grant was
/// evaluated and refused every absolute path on the volume, while
/// genuinely inherited broad ACEs on deeper directories were
/// skipped. The root must pass; a path under a *broadly
/// replaceable* ancestor must still fail.
#[cfg(windows)]
#[test]
fn inherit_only_grants_do_not_replace_the_directory_itself() {
    let root = PathBuf::from(r"C:\");
    if !root.exists() {
        return;
    }
    assert!(
        matches!(dacl_grants_replace_rights(&root, true), Ok(false)),
        "drive root's inherit-only Authenticated Users ACE must be skipped: {:?}",
        dacl_grants_replace_rights(&root, true)
    );
}

/// `on_disk_entry_name` folds a spelled component to the real
/// directory-entry name — a case-only variant resolves to the on-disk
/// casing, while a missing entry or a wildcard-shaped spelling returns
/// `None` rather than folding to an unrelated entry.
#[cfg(windows)]
#[test]
fn on_disk_entry_name_resolves_and_refuses() {
    let dir = create_private_tempdir("entry-name").unwrap();
    fs::write(dir.join("MixedCase.txt"), b"x").unwrap();
    assert_eq!(
        on_disk_entry_name(&dir.join("mixedcase.txt")).as_deref(),
        Some("MixedCase.txt")
    );
    assert_eq!(on_disk_entry_name(&dir.join("absent.txt")), None);
    // `*`/`?` are FindFirstFileW metacharacters, never real names —
    // the spelled component must not fold to a sibling.
    assert_eq!(on_disk_entry_name(&dir.join("*.txt")), None);
    assert_eq!(on_disk_entry_name(&dir.join("Mixed?.txt")), None);
    let _ = fs::remove_dir_all(&dir);
}

/// A path past MAX_PATH resolves under its verbatim `\\?\` spelling —
/// the form `literal_normalized_path` hands the query for deep
/// driver/audit trees.
#[cfg(windows)]
#[test]
fn on_disk_entry_name_resolves_verbatim_long_path() {
    use std::os::windows::ffi::OsStrExt;
    let dir = create_private_tempdir("entry-long").unwrap();
    let mut p = dir.canonicalize().unwrap();
    for _ in 0..10 {
        p = p.join("component-name-padding-the-path-past-max-path");
    }
    fs::create_dir_all(&p).unwrap();
    let leaf = p.join("leaf-entry.txt");
    fs::write(&leaf, b"x").unwrap();
    assert!(
        leaf.as_os_str().encode_wide().count() > 260,
        "fixture must exceed MAX_PATH: {leaf:?}"
    );
    assert_eq!(on_disk_entry_name(&leaf).as_deref(), Some("leaf-entry.txt"));
    let _ = fs::remove_dir_all(dir.canonicalize().unwrap());
}

/// Evaluate `dacl_has_untrusted_grant` on a DACL spelled in SDDL —
/// `ConvertStringSecurityDescriptorToSecurityDescriptorW` builds a
/// real descriptor in memory, so trustee-matrix tests need no file
/// mutation and no machine-specific accounts.
#[cfg(windows)]
fn sddl_untrusted_grant(sddl: &str, rights: u32, caller_ok: bool) -> bool {
    use windows::Win32::Security::Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW;
    use windows::Win32::Security::{ACL, GetSecurityDescriptorDacl, PSECURITY_DESCRIPTOR};
    use windows::core::HSTRING;

    let mut sd = PSECURITY_DESCRIPTOR(std::ptr::null_mut());
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            &HSTRING::from(sddl),
            1, // SDDL_REVISION_1
            &mut sd,
            None,
        )
    }
    .unwrap_or_else(|e| panic!("SDDL '{sddl}' must parse: {e}"));
    let _sd = SdGuard(sd.0);
    let mut present = windows::core::BOOL(0);
    let mut defaulted = windows::core::BOOL(0);
    let mut dacl: *mut ACL = std::ptr::null_mut();
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    unsafe { GetSecurityDescriptorDacl(sd, &mut present, &mut dacl, &mut defaulted) }
        .unwrap_or_else(|e| panic!("GetSecurityDescriptorDacl: {e}"));
    assert!(present.as_bool(), "test SDDL must carry a DACL");
    dacl_has_untrusted_grant(dacl, rights, caller_ok)
        .expect("the SDDL fixture's ACEs are all inspectable")
}

/// The process token's user SID as an SDDL string — the fixture for
/// grants to the caller itself.
#[cfg(windows)]
fn current_user_sddl() -> String {
    use windows::Win32::Security::Authorization::ConvertSidToStringSidW;
    use windows::Win32::Security::TOKEN_USER;

    let user = process_user_sid().expect("process user SID");
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    let sid = unsafe { (*user.as_ptr().cast::<TOKEN_USER>()).User.Sid };
    let mut text = windows::core::PWSTR::null();
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    unsafe { ConvertSidToStringSidW(sid, &mut text) }
        .unwrap_or_else(|e| panic!("ConvertSidToStringSidW: {e}"));
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    let s = unsafe { text.to_string() }.expect("SID text");
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    unsafe {
        let _ = windows::Win32::Foundation::LocalFree(Some(windows::Win32::Foundation::HLOCAL(
            text.0.cast(),
        )));
    }
    s
}

/// The finding-2 matrix, evaluated on real DACLs built from SDDL:
/// every allow-ACE trustee carrying dangerous rights must be a
/// trusted principal — administrators, TrustedInstaller, or the
/// owner-delegating placeholders (and the caller under the caller
/// class). A grant to any *named* non-administrative trustee —
/// user or group — flags the object replaceable under either
/// class: exactly the gap the old broad-SID check missed.
#[cfg(windows)]
#[test]
fn dacl_trustee_matrix_flags_named_principals() {
    let file_rights = file_write_rights();
    // Administrators and SYSTEM are the trusted class.
    assert!(!sddl_untrusted_grant("D:(A;;FA;;;BA)", file_rights, false));
    assert!(!sddl_untrusted_grant("D:(A;;FA;;;SY)", file_rights, false));
    // TrustedInstaller's well-known string SID is trusted too.
    assert!(!sddl_untrusted_grant(
        "D:(A;;FA;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)",
        file_rights,
        false
    ));
    // Owner-delegating placeholders resolve to the (separately
    // verified) owner — not an untrusted grant.
    assert!(!sddl_untrusted_grant("D:(A;;FA;;;CO)", file_rights, false));
    assert!(!sddl_untrusted_grant("D:(A;;FA;;;OW)", file_rights, false));
    // The caller counts only under the caller class — administrator
    // provenance flags a grant to the invoking user itself.
    let caller = current_user_sddl();
    let caller_dacl = format!("D:(A;;FA;;;{caller})");
    assert!(!sddl_untrusted_grant(&caller_dacl, file_rights, true));
    assert!(sddl_untrusted_grant(&caller_dacl, file_rights, false));
    // Named non-administrative trustees — a specific domain-style
    // user and the local Guests group — carry write rights: the
    // scan's exact miss, flagged under both classes.
    let named_user = "D:(A;;GW;;;S-1-5-21-1000-1000-1000-1001)";
    assert!(sddl_untrusted_grant(named_user, file_rights, true));
    assert!(sddl_untrusted_grant(named_user, file_rights, false));
    let guests = "D:(A;;GW;;;BG)";
    assert!(sddl_untrusted_grant(guests, file_rights, true));
    assert!(sddl_untrusted_grant(guests, file_rights, false));
    // A named group holding full access on a directory is the
    // ancestor-replacement right — flagged too.
    let dir_rights = dir_replace_rights();
    let guests_dir = "D:(A;;FA;;;BG)";
    assert!(sddl_untrusted_grant(guests_dir, dir_rights, true));
    // Read-only grants to untrusted trustees carry no replacement
    // right and stay unflagged.
    assert!(!sddl_untrusted_grant("D:(A;;GR;;;BG)", file_rights, false));
    // A mixed DACL: one untrusted grant among trusted ones flags.
    assert!(sddl_untrusted_grant(
        "D:(A;;FA;;;BA)(A;;FA;;;SY)(A;;GW;;;BG)",
        file_rights,
        false
    ));
}
