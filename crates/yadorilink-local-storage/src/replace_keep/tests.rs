use super::*;
use std::ffi::CString;

fn put(dir: &Path, name: &str, mode: u32) -> std::path::PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, b"x").unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
    path
}

fn mode(path: &Path) -> u32 {
    std::fs::metadata(path).unwrap().permissions().mode() & 0o7777
}

/// Sets an attribute with the platform's own call; `false` when the volume cannot hold it.
fn set_attr(path: &Path, name: &str, value: &[u8]) -> bool {
    let (c, n) = (c_path(path).unwrap(), CString::new(name).unwrap());
    sys::set(&c, &n, value) == 0
}

fn attr(path: &Path, name: &str) -> Option<Vec<u8>> {
    read_attributes(path).unwrap().into_iter().find(|(n, _)| n == name.as_bytes()).map(|(_, v)| v)
}

#[test]
fn permission_bits_other_than_setuid_and_setgid_follow_the_replaced_file() {
    let dir = tempfile::tempdir().unwrap();
    let old = put(dir.path(), "old", 0o640);
    let new = put(dir.path(), "new", 0o644);
    carry_over(&old, &new).unwrap();
    assert_eq!(mode(&new), 0o640);

    let old = put(dir.path(), "old2", 0o644);
    std::fs::set_permissions(&old, std::fs::Permissions::from_mode(0o6755)).unwrap();
    let new = put(dir.path(), "new2", 0o600);
    carry_over(&old, &new).unwrap();
    assert_eq!(
        mode(&new),
        0o644,
        "setuid, setgid and the execute bits are not copied, the rest follows"
    );
}

#[test]
fn execute_bits_are_left_to_the_replicated_flag_and_the_owner_keeps_read() {
    let dir = tempfile::tempdir().unwrap();
    let old = put(dir.path(), "old", 0o650);
    let new = put(dir.path(), "new", 0o644);
    carry_over(&old, &new).unwrap();
    assert_eq!(mode(&new), 0o640);

    // An owner who cannot read the old file keeps read access on the new one (Linux lists attributes
    // without read access; macOS refuses, which stops the replace rather than dropping them).
    let old = put(dir.path(), "old2", 0o000);
    let new = put(dir.path(), "new2", 0o644);
    let result = carry_over(&old, &new);
    if cfg!(target_os = "linux") {
        result.unwrap();
        assert_eq!(mode(&new), 0o400);
    } else {
        assert!(result.is_err());
        assert_eq!(mode(&new), 0o644, "nothing was changed");
    }
}

#[test]
fn a_missing_or_non_file_target_has_nothing_to_carry() {
    let dir = tempfile::tempdir().unwrap();
    let new = put(dir.path(), "new", 0o600);
    carry_over(&dir.path().join("absent"), &new).unwrap();
    carry_over(dir.path(), &new).unwrap();
    assert_eq!(mode(&new), 0o600);
}

#[cfg(target_os = "linux")]
#[test]
fn the_owners_user_attributes_follow_and_others_do_not() {
    let dir = tempfile::tempdir().unwrap();
    let old = put(dir.path(), "old", 0o644);
    if !set_attr(&old, "user.note", b"kept") {
        return; // the volume has no user attributes
    }
    let new = put(dir.path(), "new", 0o644);
    carry_over(&old, &new).unwrap();
    assert_eq!(attr(&new, "user.note").as_deref(), Some(&b"kept"[..]));
}

#[cfg(target_os = "linux")]
#[test]
fn an_access_acl_follows_and_the_mode_reflects_its_mask() {
    // version 2; USER_OBJ rw, USER 12345 r, GROUP_OBJ r, MASK r, OTHER none
    let mut acl = 2u32.to_le_bytes().to_vec();
    for (tag, perm, id) in [
        (1u16, 6u16, u32::MAX),
        (2, 4, 12345),
        (4, 4, u32::MAX),
        (0x10, 4, u32::MAX),
        (0x20, 0, u32::MAX),
    ] {
        acl.extend_from_slice(&tag.to_le_bytes());
        acl.extend_from_slice(&perm.to_le_bytes());
        acl.extend_from_slice(&id.to_le_bytes());
    }
    let dir = tempfile::tempdir().unwrap();
    let old = put(dir.path(), "old", 0o644);
    if !set_attr(&old, "system.posix_acl_access", &acl) {
        return; // the volume has no ACLs
    }
    let new = put(dir.path(), "new", 0o600);
    carry_over(&old, &new).unwrap();
    assert_eq!(attr(&new, "system.posix_acl_access"), attr(&old, "system.posix_acl_access"));
    assert_eq!(mode(&new), mode(&old), "the group bits are the ACL mask, as on the old file");
}

#[cfg(target_vendor = "apple")]
#[test]
fn origin_attributes_are_not_carried_and_the_owners_are() {
    assert!(is_origin_attribute(b"com.apple.quarantine"));
    assert!(is_origin_attribute(b"com.apple.metadata:kMDItemWhereFroms"));
    assert!(!is_origin_attribute(b"com.example.note"));
    let dir = tempfile::tempdir().unwrap();
    let old = put(dir.path(), "old", 0o644);
    assert!(set_attr(&old, "com.example.note", b"kept"));
    assert!(set_attr(&old, "com.apple.metadata:kMDItemWhereFroms", b"from"));
    let new = put(dir.path(), "new", 0o644);
    carry_over(&old, &new).unwrap();
    assert_eq!(attr(&new, "com.example.note").as_deref(), Some(&b"kept"[..]));
    assert_eq!(attr(&new, "com.apple.metadata:kMDItemWhereFroms"), None);
}

#[test]
fn the_attribute_filter_names_what_is_kept() {
    #[cfg(target_os = "linux")]
    {
        assert!(is_kept_attribute(b"user.x"));
        assert!(!is_kept_attribute(b"security.selinux"));
        assert!(!is_kept_attribute(b"trusted.x"));
        assert!(!is_kept_attribute(b"system.posix_acl_default"));
    }
    #[cfg(target_vendor = "apple")]
    {
        assert!(is_kept_attribute(b"com.example.note"));
        assert!(!is_kept_attribute(b"com.apple.provenance"));
    }
}

#[cfg(target_vendor = "apple")]
#[test]
fn an_extended_acl_follows_the_replaced_file() {
    let dir = tempfile::tempdir().unwrap();
    let old = put(dir.path(), "old", 0o644);
    let status = std::process::Command::new("chmod")
        .args(["+a", "everyone deny delete"])
        .arg(&old)
        .status()
        .unwrap();
    assert!(status.success());
    let new = put(dir.path(), "new", 0o644);
    assert!(acl::read(&new).unwrap().is_none());
    carry_over(&old, &new).unwrap();
    assert!(acl::read(&new).unwrap().is_some(), "the ACL was not carried");
}

/// Through the real publish: the replaced file's mode and owner attribute are on the published file, and a
/// first write to a free name is unchanged.
#[test]
fn a_published_replacement_keeps_the_replaced_files_mode() {
    use crate::materialize_write::{persist_reconstructed_file_durable, Durability, NoTempLedger};
    let dir = tempfile::tempdir().unwrap();
    let out = put(dir.path(), "doc", 0o640);
    let tmp = dir.path().join("doc.tmp");
    std::fs::write(&tmp, b"new content").unwrap();
    persist_reconstructed_file_durable(&tmp, &out, &NoTempLedger, Durability::Full, None).unwrap();
    assert_eq!(std::fs::read(&out).unwrap(), b"new content");
    assert_eq!(mode(&out), 0o640);

    let fresh = dir.path().join("fresh");
    let tmp = dir.path().join("fresh.tmp");
    std::fs::write(&tmp, b"a").unwrap();
    persist_reconstructed_file_durable(&tmp, &fresh, &NoTempLedger, Durability::Full, None)
        .unwrap();
    assert_eq!(std::fs::read(&fresh).unwrap(), b"a");
}

/// The replicated execute flag is applied to the temp after the carry-over (which drops every
/// execute bit) and before the rename: the published file has the final mode, whether the
/// replaced file was executable or not, and the replaced file's other bits are kept.
#[test]
fn the_execute_flag_is_on_the_file_when_it_is_published() {
    use crate::materialize_write::{persist_reconstructed_file_durable, Durability, NoTempLedger};
    let dir = tempfile::tempdir().unwrap();
    for (name, old_mode, exec, expected) in [
        ("plain-to-exec", 0o640, true, 0o750),
        ("exec-to-plain", 0o755, false, 0o644),
        ("exec-stays", 0o700, true, 0o700),
    ] {
        let out = put(dir.path(), name, old_mode);
        let tmp = dir.path().join(format!("{name}.tmp"));
        std::fs::write(&tmp, b"new content").unwrap();
        persist_reconstructed_file_durable(&tmp, &out, &NoTempLedger, Durability::Full, Some(exec))
            .unwrap();
        assert_eq!(mode(&out), expected, "{name}");
    }
    // A free name has nothing to carry over; the flag still lands before the rename.
    let fresh = dir.path().join("fresh-exec");
    let tmp = dir.path().join("fresh-exec.tmp");
    std::fs::write(&tmp, b"a").unwrap();
    persist_reconstructed_file_durable(&tmp, &fresh, &NoTempLedger, Durability::Full, Some(true))
        .unwrap();
    assert_ne!(mode(&fresh) & 0o100, 0);
}

/// A staged file that inherited an access ACL (a directory default ACL) loses it when the replaced file
/// had none, so the new file is not more open than the old one.
#[cfg(target_os = "linux")]
#[test]
fn an_inherited_acl_is_removed_when_the_replaced_file_had_none() {
    let mut acl = 2u32.to_le_bytes().to_vec();
    for (tag, perm, id) in [
        (1u16, 6u16, u32::MAX),
        (2, 4, 12345),
        (4, 4, u32::MAX),
        (0x10, 4, u32::MAX),
        (0x20, 0, u32::MAX),
    ] {
        acl.extend_from_slice(&tag.to_le_bytes());
        acl.extend_from_slice(&perm.to_le_bytes());
        acl.extend_from_slice(&id.to_le_bytes());
    }
    let dir = tempfile::tempdir().unwrap();
    let old = put(dir.path(), "old", 0o600);
    let new = put(dir.path(), "new", 0o600);
    if !set_attr(&new, "system.posix_acl_access", &acl) {
        return; // the volume has no ACLs
    }
    carry_over(&old, &new).unwrap();
    assert_eq!(attr(&new, "system.posix_acl_access"), None);
    assert_eq!(mode(&new), 0o600);
}

#[cfg(target_os = "linux")]
#[test]
fn an_attribute_name_that_is_not_utf8_is_carried() {
    use std::os::unix::ffi::OsStrExt;
    let dir = tempfile::tempdir().unwrap();
    let old = put(dir.path(), "old", 0o644);
    let name = CString::new(&b"user.\xff"[..]).unwrap();
    let c = c_path(&old).unwrap();
    if sys::set(&c, &name, b"v") != 0 {
        return;
    }
    let new = put(dir.path(), "new", 0o644);
    carry_over(&old, &new).unwrap();
    let _ = std::ffi::OsStr::from_bytes(b"");
    assert!(read_attributes(&new).unwrap().iter().any(|(n, v)| n == b"user.\xff" && v == b"v"));
}
