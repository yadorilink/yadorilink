//! `yadorilink doctor` reports a disagreement between the ownership record and the install it
//! names, with the fix, without a daemon running and without changing anything.
#![cfg(unix)]

use std::process::Command;

fn doctor(config: &std::path::Path) -> String {
    let out = Command::new(env!("CARGO_BIN_EXE_yadorilink"))
        .arg("doctor")
        .env("YADORILINK_CONFIG_DIR", config)
        .env("YADORILINK_CONTROL_SOCKET", config.join("none.sock"))
        .output()
        .unwrap();
    String::from_utf8_lossy(&out.stdout).into_owned()
}

#[test]
fn a_record_that_disagrees_with_its_install_root_is_reported_with_the_fix_and_left_alone() {
    let dir = tempfile::tempdir().unwrap();
    let record = r#"{"owner":"gui","install_source":"app_bundle","install_root":"/usr/bin","release_id":"","written_at":1}"#;
    std::fs::write(dir.path().join("install-owner.json"), record).unwrap();

    let report = doctor(dir.path());
    assert!(report.contains("[ERROR] install source:"), "{report}");
    assert!(report.contains("delete "), "{report}");
    assert_eq!(
        std::fs::read_to_string(dir.path().join("install-owner.json")).unwrap(),
        record,
        "doctor must not rewrite the record"
    );
}

#[test]
fn an_unreadable_record_is_an_error_row() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("install-owner.json"), b"{").unwrap();
    assert!(doctor(dir.path()).contains("[ERROR] ownership record:"));
}
