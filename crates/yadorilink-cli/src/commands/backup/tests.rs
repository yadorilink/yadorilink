#![cfg(test)]

use super::*;

#[test]
fn present_labels_are_stable() {
    assert_eq!(present(true), "present");
    assert_eq!(present(false), "missing");
}

/// The recovery guidance describes the Google-login/new-device model.
#[test]
fn recovery_guidance_describes_google_login_new_device_model() {
    let guidance = recovery_guidance();
    let lower = guidance.to_lowercase();
    assert!(guidance.contains("Google"));
    assert!(lower.contains("new device"));
    assert!(lower.contains("register"));
}

fn entry() -> LinkEntry {
    LinkEntry { local_path: "/f/Docs".into(), group_id: "g1".into() }
}

/// An unreadable folder list must not become a successful, folder-less backup.
#[test]
fn export_fails_and_writes_nothing_when_the_folder_list_is_unavailable() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("backup.json");

    let result = write_export(&out, None, Err(CliError::Other("daemon down".into())), false);

    let message = result.unwrap_err().to_string();
    assert!(message.contains("--without-folders"), "{message}");
    assert!(!out.exists());
}

#[test]
fn export_writes_the_folder_list_when_it_is_available() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("backup.json");

    write_export(&out, Some("coord".into()), Ok(vec![entry()]), false).unwrap();

    let written: NonSensitiveBackup =
        serde_json::from_str(&std::fs::read_to_string(&out).unwrap()).unwrap();
    assert_eq!(written.links.len(), 1);
    assert_eq!(written.coordination_addr.as_deref(), Some("coord"));
}

/// An existing output file is only replaced with `--yes`.
#[test]
fn export_does_not_overwrite_an_existing_file_without_yes() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("backup.json");
    std::fs::write(&out, "precious").unwrap();

    let result = write_export(&out, None, Ok(vec![entry()]), false);

    assert!(result.unwrap_err().to_string().contains("--yes"));
    assert_eq!(std::fs::read_to_string(&out).unwrap(), "precious");

    write_export(&out, None, Ok(vec![entry()]), true).unwrap();
    assert_ne!(std::fs::read_to_string(&out).unwrap(), "precious");
}
