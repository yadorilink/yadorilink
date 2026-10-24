//! Real OS credential store round trip for the device key mirror (Windows Credential Manager,
//! Linux Secret Service). Ignored by default: it needs an interactive logon session with a
//! reachable store (over ssh or a service session Credential Manager refuses), and it must run
//! with `KeyMirror::OsKeyring`.
//!
//! Lab step: from an interactive session on the machine,
//! `cargo test -p yadorilink-transport --test os_keyring_device_key -- --ignored`,
//! then `cmdkey /list` shows no `device-key:` entry for the temp directory used.
#![cfg(all(not(turmoil), any(windows, target_os = "linux")))]

use yadorilink_transport::{DeviceSigningKeyPair, KeyMirror, KeyringDelete};

fn entry_exists(path: &std::path::Path) -> bool {
    let abs = std::path::absolute(path).unwrap();
    let username = format!("device-key:{}", abs.to_string_lossy());
    keyring::Entry::new("yadorilink", &username).unwrap().get_password().is_ok()
}

#[test]
#[ignore = "needs a reachable OS credential store (interactive logon session)"]
fn deleting_the_mirror_removes_the_real_entry_and_keeps_the_key_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("signing_key");
    let pair = DeviceSigningKeyPair::generate_and_persist(&path, KeyMirror::OsKeyring).unwrap();
    assert!(entry_exists(&path), "the key was mirrored into the OS store");

    assert_eq!(
        DeviceSigningKeyPair::delete_keyring_entry(&path, KeyMirror::OsKeyring).unwrap(),
        KeyringDelete::Deleted
    );
    assert!(!entry_exists(&path));
    assert_eq!(
        DeviceSigningKeyPair::delete_keyring_entry(&path, KeyMirror::OsKeyring).unwrap(),
        KeyringDelete::NotFound,
        "deleting again is success"
    );
    assert!(path.exists(), "the key file stays");
    drop(pair);
}
