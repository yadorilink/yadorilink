//! A replacing publish on Windows keeps what the replaced file's owner set on it, and a read-only file can be
//! replaced at all (it used to be refused with "access denied" for ever).
#![cfg(windows)]

use std::fs;
use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;
use std::process::Command;

use yadorilink_fs_platform::durable_dir::{publish_durably, Replace};

const READONLY: u32 = 0x1;
const HIDDEN: u32 = 0x2;

fn attributes(path: &Path) -> u32 {
    fs::metadata(path).unwrap().file_attributes()
}

fn set_attributes(path: &Path, flags: &str) {
    let status = Command::new("attrib").args(flags.split(' ')).arg(path).status().unwrap();
    assert!(status.success(), "attrib {flags}");
}

fn icacls(path: &Path, args: &[&str]) -> String {
    let out = Command::new("icacls").arg(path).args(args).output().unwrap();
    assert!(out.status.success(), "icacls {args:?}: {}", String::from_utf8_lossy(&out.stdout));
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn staged(dir: &Path, name: &str, content: &[u8]) -> std::path::PathBuf {
    let path = dir.join(name);
    fs::write(&path, content).unwrap();
    path
}

#[test]
fn a_read_only_target_is_replaced_and_stays_read_only() {
    let dir = tempfile::tempdir().unwrap();
    let target = staged(dir.path(), "t.txt", b"old");
    set_attributes(&target, "+R");
    let stage = staged(dir.path(), "s.tmp", b"new");

    publish_durably(&stage, &target, Replace::Yes).unwrap();

    assert_eq!(fs::read(&target).unwrap(), b"new");
    assert_ne!(attributes(&target) & READONLY, 0, "the read-only mark was lost");
    assert!(!stage.exists());
    set_attributes(&target, "-R");
}

#[test]
fn hidden_and_an_explicit_access_entry_survive_a_replace() {
    let dir = tempfile::tempdir().unwrap();
    let target = staged(dir.path(), "t.txt", b"old");
    // BUILTIN\Guests: read, an explicit entry.
    icacls(&target, &["/grant", "*S-1-5-32-546:(R)"]);
    set_attributes(&target, "+H");
    assert!(icacls(&target, &[]).contains("Guests"), "fixture: the entry is there");
    let stage = staged(dir.path(), "s.tmp", b"new");
    assert!(!icacls(&stage, &[]).contains("Guests"));

    publish_durably(&stage, &target, Replace::Yes).unwrap();

    assert_eq!(fs::read(&target).unwrap(), b"new");
    assert_ne!(attributes(&target) & HIDDEN, 0, "the hidden attribute was lost");
    assert!(icacls(&target, &[]).contains("Guests"), "the explicit entry was lost");
}

#[test]
fn a_target_with_only_inherited_access_is_replaced_as_before() {
    let dir = tempfile::tempdir().unwrap();
    let target = staged(dir.path(), "t.txt", b"old");
    let before = icacls(&target, &[]);
    let stage = staged(dir.path(), "s.tmp", b"new");

    publish_durably(&stage, &target, Replace::Yes).unwrap();

    assert_eq!(fs::read(&target).unwrap(), b"new");
    assert_eq!(attributes(&target) & (READONLY | HIDDEN), 0);
    // Same entries, whatever the file's name in the listing.
    let strip = |s: &str| s.replace(&target.display().to_string(), "");
    assert_eq!(strip(&icacls(&target, &[])), strip(&before));
}

#[test]
fn a_replace_that_fails_leaves_the_read_only_target_read_only_and_the_stage_removable() {
    let dir = tempfile::tempdir().unwrap();
    let target = staged(dir.path(), "t.txt", b"old");
    set_attributes(&target, "+R");
    // Another handle with no sharing keeps the replace from ever succeeding.
    let _lock = fs::OpenOptions::new().read(true).share_mode(0).open(&target).unwrap();
    let stage = staged(dir.path(), "s.tmp", b"new");

    let result = publish_durably(&stage, &target, Replace::Yes);

    assert!(result.is_err(), "the locked target must refuse the replace");
    drop(_lock);
    assert_eq!(fs::read(&target).unwrap(), b"old");
    assert_ne!(attributes(&target) & READONLY, 0, "the read-only mark was not restored");
    // `publish_durably` removes the stage on failure; if it stayed it must not be read-only.
    if stage.exists() {
        assert_eq!(attributes(&stage) & READONLY, 0);
    }
    set_attributes(&target, "-R");
}

#[test]
fn a_first_write_to_a_free_name_needs_no_target() {
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("t.txt");
    let stage = staged(dir.path(), "s.tmp", b"new");
    publish_durably(&stage, &target, Replace::Yes).unwrap();
    assert_eq!(fs::read(&target).unwrap(), b"new");
}
