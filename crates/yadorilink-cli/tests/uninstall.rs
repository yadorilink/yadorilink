//! `yadorilink uninstall` through the real binary: another channel's install, or an unreadable
//! ownership record, is refused with the "managed elsewhere" code and changes nothing; a binary
//! outside the installer layout removes nothing. No daemon, no network.
#![cfg(unix)]

use std::process::{Command, Output};

fn uninstall(config: &std::path::Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_yadorilink"))
        .arg("uninstall")
        .args(args)
        .env("YADORILINK_CONFIG_DIR", config)
        .env("YADORILINK_CONTROL_SOCKET", config.join("none.sock"))
        .output()
        .unwrap()
}

fn listing(dir: &std::path::Path) -> Vec<String> {
    let mut names: Vec<_> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    names.sort();
    names
}

#[test]
fn another_channels_install_is_refused_with_its_own_uninstall_steps() {
    let dir = tempfile::tempdir().unwrap();
    let record = r#"{"owner":"cli","install_source":"homebrew","install_root":"/opt/homebrew","release_id":"","written_at":1}"#;
    std::fs::write(dir.path().join("install-owner.json"), record).unwrap();
    let before = listing(dir.path());
    let out = uninstall(dir.path(), &["--yes", "--purge-data"]);
    assert_eq!(out.status.code(), Some(19));
    assert!(String::from_utf8_lossy(&out.stderr).contains("brew uninstall --cask yadorilink"));
    assert_eq!(listing(dir.path()), before);
}

#[test]
fn an_unreadable_record_is_refused_and_left_alone() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("install-owner.json"), b"{ not json").unwrap();
    let before = listing(dir.path());
    let out = uninstall(dir.path(), &["--yes"]);
    assert_eq!(out.status.code(), Some(19));
    assert_eq!(listing(dir.path()), before);
}

#[test]
fn a_build_tree_binary_is_not_an_install_and_nothing_is_removed() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("device.json"), b"{}").unwrap();
    let out = uninstall(dir.path(), &["--yes", "--purge-data"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("installer layout"));
    // (The binary's own startup may add an empty working directory; the data stays.)
    assert!(dir.path().join("device.json").exists());
}
