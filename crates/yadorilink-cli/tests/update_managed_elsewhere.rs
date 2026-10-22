//! `yadorilink update download` on an installation another updater owns: exits "managed
//! elsewhere" (19), says how the owner updates it, and changes nothing, with no daemon running.
#![cfg(unix)]

use std::process::{Command, Output};

fn update_download(config: &std::path::Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_yadorilink"))
        .args(["update", "download"])
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
fn an_app_owned_data_area_is_refused_with_the_managed_elsewhere_code_and_left_alone() {
    let dir = tempfile::tempdir().unwrap();
    let record = r#"{"owner":"gui","install_source":"app_bundle","install_root":"/Applications/YadoriLink.app","release_id":"","written_at":1}"#;
    std::fs::write(dir.path().join("install-owner.json"), record).unwrap();
    let before = listing(dir.path());

    let out = update_download(dir.path());
    assert_eq!(out.status.code(), Some(19), "{out:?}");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("Check for Updates"), "{stderr}");
    assert_eq!(listing(dir.path()), before);
    assert_eq!(std::fs::read_to_string(dir.path().join("install-owner.json")).unwrap(), record);
}

#[test]
fn a_leftover_command_line_install_the_app_took_over_is_refused_too() {
    let dir = tempfile::tempdir().unwrap();
    let record = r#"{"owner":"gui","install_source":"script","install_root":"/Applications/YadoriLink.app","release_id":"","written_at":1}"#;
    std::fs::write(dir.path().join("install-owner.json"), record).unwrap();
    assert_eq!(update_download(dir.path()).status.code(), Some(19));
}

#[test]
fn an_unknown_owner_fails_closed_with_the_same_code() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("install-owner.json"), b"{").unwrap();
    let out = update_download(dir.path());
    assert_eq!(out.status.code(), Some(19), "{out:?}");
    assert!(String::from_utf8_lossy(&out.stderr).contains("doctor"));
}

#[test]
fn the_command_lines_own_install_is_not_refused() {
    let dir = tempfile::tempdir().unwrap();
    let record = r#"{"owner":"cli","install_source":"script","install_root":"/home/u/.local/lib/yadorilink","release_id":"","written_at":1}"#;
    std::fs::write(dir.path().join("install-owner.json"), record).unwrap();
    // No daemon runs here, so it stops at "daemon not running" instead: not the managed-elsewhere code.
    assert_ne!(update_download(dir.path()).status.code(), Some(19));
}
