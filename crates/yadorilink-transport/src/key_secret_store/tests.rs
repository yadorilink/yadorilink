#![cfg(test)]

use super::*;

fn sample_secret() -> [u8; 32] {
    let mut bytes = [0u8; 32];
    for (i, b) in bytes.iter_mut().enumerate() {
        *b = (i as u8).wrapping_mul(7).wrapping_add(3);
    }
    bytes
}

/// A second, clearly distinct secret, for the cases where two identities
/// have to be told apart.
fn other_secret() -> [u8; 32] {
    [0xAB; 32]
}

fn read_secret(path: &Path) -> Option<[u8; 32]> {
    match read_secret_file(path).unwrap() {
        KeyFile::Secret(secret) => Some(*secret),
        _ => None,
    }
}

/// Temporary files must never outlive a write: they hold the private key.
fn temp_leftovers(dir: &Path) -> Vec<String> {
    std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|name| name.contains(".tmp."))
        .collect()
}

#[test]
fn persist_then_load_round_trips_via_file_when_keyring_down() {
    test_keyring::reset(); // keyring unavailable
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("k");
    let secret = sample_secret();

    persist_new_secret(&path, &secret, KeyMirror::OsKeyring).unwrap();
    assert!(path.exists());
    assert!(keyring_load(&path, KeyMirror::OsKeyring).is_none(), "keyring is down in this test");

    let loaded = load_persisted_secret(&path, KeyMirror::OsKeyring).unwrap().unwrap();
    assert_eq!(loaded.as_slice(), &secret);
    assert!(temp_leftovers(dir.path()).is_empty());
}

#[cfg(unix)]
#[test]
fn persist_creates_owner_only_file() {
    use std::os::unix::fs::PermissionsExt;

    test_keyring::reset();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("k");
    persist_new_secret(&path, &sample_secret(), KeyMirror::OsKeyring).unwrap();

    let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
}

#[test]
fn migration_populates_keyring_without_losing_the_file() {
    test_keyring::reset();
    test_keyring::set_available(true);
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("k");
    let secret = sample_secret();

    // Simulate a pre-keyring plaintext identity file already on disk.
    std::fs::write(&path, hex::encode(secret)).unwrap();
    assert!(keyring_load(&path, KeyMirror::OsKeyring).is_none());

    let loaded = load_persisted_secret(&path, KeyMirror::OsKeyring).unwrap().unwrap();
    assert_eq!(loaded.as_slice(), &secret);
    // The identity file must survive migration untouched.
    assert!(path.exists(), "migration must never delete the identity file");
    // And the keyring now mirrors it.
    assert_eq!(keyring_load(&path, KeyMirror::OsKeyring).unwrap().as_slice(), &secret);

    test_keyring::reset();
}

#[test]
fn recovers_identity_from_keyring_when_file_is_lost() {
    test_keyring::reset();
    test_keyring::set_available(true);
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("k");
    let secret = sample_secret();

    // Identity only in the keyring, nothing on disk yet.
    assert_eq!(keyring_mirror(&path, &secret, KeyMirror::OsKeyring), KeyringMirror::Present);
    assert!(!path.exists());

    let loaded = load_persisted_secret(&path, KeyMirror::OsKeyring).unwrap().unwrap();
    assert_eq!(loaded.as_slice(), &secret);
    // Recovery restores the on-disk source of truth.
    assert!(path.exists(), "recovery must rewrite the hardened file");

    test_keyring::reset();
}

#[test]
fn missing_file_and_empty_keyring_returns_none() {
    test_keyring::reset();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("absent");
    assert!(load_persisted_secret(&path, KeyMirror::OsKeyring).unwrap().is_none());
}

/// A power cut can leave the key file empty or half-written. The identity
/// is not lost when the keyring still has it, so a truncated file must send
/// us to the keyring rather than straight to the caller as an error.
#[test]
fn truncated_key_file_is_restored_from_the_keyring() {
    test_keyring::reset();
    test_keyring::set_available(true);
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("k");
    let secret = sample_secret();

    persist_new_secret(&path, &secret, KeyMirror::OsKeyring).unwrap();
    assert_eq!(keyring_load(&path, KeyMirror::OsKeyring).unwrap().as_slice(), &secret);

    for damaged in [b"".as_slice(), b"0102030405".as_slice(), &[0xFF, 0xFE, 0x00]] {
        std::fs::write(&path, damaged).unwrap();

        let loaded = load_persisted_secret(&path, KeyMirror::OsKeyring).unwrap().unwrap();
        assert_eq!(loaded.as_slice(), &secret, "identity must survive a torn write");
        assert_eq!(
            read_secret(&path),
            Some(secret),
            "the damaged file must be repaired on disk, not just in memory"
        );
    }
    assert!(temp_leftovers(dir.path()).is_empty());

    test_keyring::reset();
}

/// The opposite guard rail: with no keyring copy to vouch for the identity,
/// an unreadable key file is a hard error. Silently regenerating would mint
/// a new identity and orphan the device's history.
#[test]
fn unreadable_key_file_without_a_keyring_copy_is_an_error() {
    test_keyring::reset(); // keyring unavailable
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("k");
    std::fs::write(&path, b"not hex at all").unwrap();

    let err = load_persisted_secret(&path, KeyMirror::OsKeyring).unwrap_err();
    assert!(matches!(err, TransportError::InvalidKey(_)), "expected a decode error, got {err:?}");
}

/// The keyring is only an independent copy if the file cannot silently
/// overwrite it. On disagreement the file still wins as the source of
/// truth, but the keyring entry has to survive for a human to inspect.
#[test]
fn a_disagreeing_keyring_entry_is_never_overwritten_by_the_file() {
    test_keyring::reset();
    test_keyring::set_available(true);
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("k");

    assert_eq!(
        keyring_mirror(&path, &other_secret(), KeyMirror::OsKeyring),
        KeyringMirror::Present,
        "seed the keyring with a different identity"
    );
    std::fs::write(&path, hex::encode(sample_secret())).unwrap();

    let loaded = load_persisted_secret(&path, KeyMirror::OsKeyring).unwrap().unwrap();
    assert_eq!(loaded.as_slice(), &sample_secret(), "the file stays the source of truth");
    assert_eq!(
        keyring_load(&path, KeyMirror::OsKeyring).unwrap().as_slice(),
        &other_secret(),
        "the keyring copy must survive as an independent anchor"
    );

    test_keyring::reset();
}

/// Two daemons starting at once must not both publish an identity: the
/// loser has to lose the create race and adopt the winner's key, or it
/// keeps running with a secret that is no longer the one on disk. This is
/// exactly what publishing with `rename` instead of `hard_link` would break.
#[test]
fn publishing_an_identity_never_clobbers_one_that_appeared_first() {
    test_keyring::reset();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("k");
    let winner = sample_secret();

    persist_new_secret(&path, &winner, KeyMirror::OsKeyring).unwrap();

    let err = persist_new_secret(&path, &other_secret(), KeyMirror::OsKeyring).unwrap_err();
    assert!(
        matches!(&err, TransportError::Io(e) if e.kind() == std::io::ErrorKind::AlreadyExists),
        "the loser must see AlreadyExists so it re-reads the winner's file, got {err:?}"
    );
    assert_eq!(read_secret(&path), Some(winner), "the identity already on disk must be untouched");
    assert!(
        temp_leftovers(dir.path()).is_empty(),
        "a lost race must not strand a temporary file holding a private key"
    );
}

/// Loading tightens a key file that predates hardening — the load path's
/// re-assert has to be real work on unix, not a no-op.
#[cfg(unix)]
#[test]
fn loading_tightens_permissions_on_a_world_readable_key_file() {
    use std::os::unix::fs::PermissionsExt;

    test_keyring::reset();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("k");
    std::fs::write(&path, hex::encode(sample_secret())).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();

    load_persisted_secret(&path, KeyMirror::OsKeyring).unwrap().unwrap();

    let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "a loosened key file must be tightened on load");
}

/// The parent directory is created on demand, and a bare relative file name
/// (parent `""`) must not send the temporary file to another filesystem.
#[test]
fn creates_missing_parent_directories() {
    test_keyring::reset();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("nested/deeper/k");
    let secret = sample_secret();

    persist_new_secret(&path, &secret, KeyMirror::OsKeyring).unwrap();

    assert_eq!(read_secret(&path), Some(secret));
    assert!(temp_leftovers(dir.path().join("nested/deeper").as_path()).is_empty());
}

#[test]
fn only_the_literal_one_disables_the_keyring() {
    assert_eq!(KeyMirror::from_disable_flag(Some("1")), KeyMirror::Disabled);
    for off in [None, Some(""), Some("0"), Some("true")] {
        assert_eq!(
            KeyMirror::from_disable_flag(off),
            KeyMirror::OsKeyring,
            "{off:?} must leave the keyring on"
        );
    }
}

#[test]
fn disabled_keyring_is_never_read_or_written_and_the_file_still_works() {
    test_keyring::reset();
    test_keyring::set_available(true); // a keyring that WOULD work
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("k");
    let secret = sample_secret();

    persist_new_secret(&path, &secret, KeyMirror::Disabled).unwrap();
    let loaded = load_persisted_secret(&path, KeyMirror::Disabled).unwrap().unwrap();
    assert_eq!(loaded.as_slice(), &secret);
    // A lost file cannot be recovered from a keyring that is switched off.
    std::fs::remove_file(&path).unwrap();
    assert!(load_persisted_secret(&path, KeyMirror::Disabled).unwrap().is_none());

    assert_eq!(test_keyring::calls(), 0, "the switch must prevent every keyring operation");
    assert!(
        keyring_load(&path, KeyMirror::OsKeyring).is_none(),
        "nothing was mirrored while disabled"
    );
    test_keyring::reset();
}

#[test]
fn enabled_keyring_is_still_used() {
    test_keyring::reset();
    test_keyring::set_available(true);
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("k");
    persist_new_secret(&path, &sample_secret(), KeyMirror::OsKeyring).unwrap();
    assert!(test_keyring::calls() > 0);
    assert_eq!(keyring_load(&path, KeyMirror::OsKeyring).unwrap().as_slice(), &sample_secret());
    test_keyring::reset();
}

/// Retiring an identity keeps its file under the retired name, drops its keyring copy, and makes the new secret the one a lost file recovers: the old key
/// must not come back from the keyring entry of the live path.
#[test]
fn a_retired_identity_is_kept_and_does_not_come_back_from_the_keyring() {
    test_keyring::reset();
    test_keyring::set_available(true);
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("signing_key");
    let retired = dir.path().join("retired").join("signing_key");
    persist_new_secret(&path, &sample_secret(), KeyMirror::OsKeyring).unwrap();

    replace_retiring(&path, &retired, &other_secret(), KeyMirror::OsKeyring).unwrap();

    assert_eq!(read_secret(&path), Some(other_secret()));
    assert_eq!(read_secret(&retired), Some(sample_secret()));
    assert!(keyring_load(&retired, KeyMirror::OsKeyring).is_none());

    std::fs::remove_file(&path).unwrap();
    let recovered = load_persisted_secret(&path, KeyMirror::OsKeyring).unwrap().unwrap();
    assert_eq!(
        recovered.as_slice(),
        &other_secret(),
        "a lost key file must not recover the retired key"
    );
    assert!(temp_leftovers(dir.path()).is_empty());
    test_keyring::reset();
}

/// A crash after the old identity was copied but before the new one was
/// published leaves the old one in place; running the step again finishes it.
#[test]
fn retiring_again_after_an_interruption_finishes_the_replacement() {
    test_keyring::reset();
    test_keyring::set_available(true);
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("signing_key");
    let retired = dir.path().join("retired_key");
    persist_new_secret(&path, &sample_secret(), KeyMirror::OsKeyring).unwrap();
    persist_new_secret(&retired, &sample_secret(), KeyMirror::OsKeyring).unwrap();

    replace_retiring(&path, &retired, &other_secret(), KeyMirror::OsKeyring).unwrap();

    assert_eq!(read_secret(&path), Some(other_secret()));
    assert_eq!(read_secret(&retired), Some(sample_secret()));
    test_keyring::reset();
}

/// The retired name already holds a different identity: nothing is replaced.
#[test]
fn retiring_never_overwrites_a_different_retired_identity() {
    test_keyring::reset();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("signing_key");
    let retired = dir.path().join("retired_key");
    persist_new_secret(&path, &sample_secret(), KeyMirror::OsKeyring).unwrap();
    persist_new_secret(&retired, &[0x11; 32], KeyMirror::OsKeyring).unwrap();

    assert!(replace_retiring(&path, &retired, &other_secret(), KeyMirror::OsKeyring).is_err());

    assert_eq!(read_secret(&path), Some(sample_secret()));
    assert_eq!(read_secret(&retired), Some([0x11; 32]));
    test_keyring::reset();
}

/// A keyring that refuses the replacement is an error, not a silent success: the live key file
/// would otherwise be backed by an entry that still holds the retired identity. Running the step
/// again once the keyring accepts writes repairs the entry.
#[test]
fn a_keyring_that_refuses_the_replacement_is_reported_and_repaired_on_retry() {
    test_keyring::reset();
    test_keyring::set_available(true);
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("signing_key");
    let retired = dir.path().join("retired_key");
    persist_new_secret(&path, &sample_secret(), KeyMirror::OsKeyring).unwrap();

    test_keyring::set_fail_writes(true);
    assert!(replace_retiring(&path, &retired, &other_secret(), KeyMirror::OsKeyring).is_err());
    assert_eq!(read_secret(&path), Some(other_secret()));
    assert_eq!(
        keyring_load(&path, KeyMirror::OsKeyring).as_deref(),
        Some(&sample_secret()),
        "still the old entry"
    );

    test_keyring::set_fail_writes(false);
    replace_retiring(&path, &retired, &other_secret(), KeyMirror::OsKeyring).unwrap();
    assert_eq!(keyring_load(&path, KeyMirror::OsKeyring).as_deref(), Some(&other_secret()));
    std::fs::remove_file(&path).unwrap();
    let recovered = load_persisted_secret(&path, KeyMirror::OsKeyring).unwrap().unwrap();
    assert_eq!(recovered.as_slice(), &other_secret());
    test_keyring::reset();
}

/// A keyring that cannot be read (locked) is not an absent entry: it may still hold the retired
/// key, so the replacement is reported as unfinished, and running it again once the keyring is
/// readable repairs the entry.
#[test]
fn a_locked_keyring_is_reported_not_treated_as_absent_and_is_repaired_on_retry() {
    test_keyring::reset();
    test_keyring::set_available(true);
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("signing_key");
    let retired = dir.path().join("retired_key");
    persist_new_secret(&path, &sample_secret(), KeyMirror::OsKeyring).unwrap();

    test_keyring::set_available(false);
    assert!(replace_retiring(&path, &retired, &other_secret(), KeyMirror::OsKeyring).is_err());
    assert_eq!(read_secret(&path), Some(other_secret()));

    test_keyring::set_available(true);
    assert_eq!(
        keyring_load(&path, KeyMirror::OsKeyring).as_deref(),
        Some(&sample_secret()),
        "still the old entry"
    );
    replace_retiring(&path, &retired, &other_secret(), KeyMirror::OsKeyring).unwrap();
    assert_eq!(keyring_load(&path, KeyMirror::OsKeyring).as_deref(), Some(&other_secret()));
    std::fs::remove_file(&path).unwrap();
    let recovered = load_persisted_secret(&path, KeyMirror::OsKeyring).unwrap().unwrap();
    assert_eq!(recovered.as_slice(), &other_secret());
    test_keyring::reset();
}

#[test]
fn deleting_the_keyring_copy_leaves_the_key_file_and_reports_it() {
    test_keyring::reset();
    test_keyring::set_available(true);
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("k");
    persist_new_secret(&path, &sample_secret(), KeyMirror::OsKeyring).unwrap();
    assert!(keyring_load(&path, KeyMirror::OsKeyring).is_some());

    assert_eq!(delete_keyring_entry(&path, KeyMirror::OsKeyring).unwrap(), KeyringDelete::Deleted);
    assert!(keyring_load(&path, KeyMirror::OsKeyring).is_none());
    assert_eq!(read_secret(&path), Some(sample_secret()), "the key file is not touched");
}

#[test]
fn deleting_a_missing_keyring_entry_is_success() {
    test_keyring::reset();
    test_keyring::set_available(true);
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("k");
    assert_eq!(delete_keyring_entry(&path, KeyMirror::OsKeyring).unwrap(), KeyringDelete::NotFound);
    persist_new_secret(&path, &sample_secret(), KeyMirror::OsKeyring).unwrap();
    assert_eq!(delete_keyring_entry(&path, KeyMirror::OsKeyring).unwrap(), KeyringDelete::Deleted);
    assert_eq!(delete_keyring_entry(&path, KeyMirror::OsKeyring).unwrap(), KeyringDelete::NotFound);
}

#[test]
fn a_refused_or_unavailable_keyring_delete_is_an_error_not_success() {
    test_keyring::reset();
    test_keyring::set_available(true);
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("k");
    persist_new_secret(&path, &sample_secret(), KeyMirror::OsKeyring).unwrap();

    test_keyring::set_fail_deletes(true);
    let err = delete_keyring_entry(&path, KeyMirror::OsKeyring).unwrap_err().to_string();
    assert!(err.contains("could not delete"), "{err}");
    assert!(keyring_load(&path, KeyMirror::OsKeyring).is_some(), "the entry is still there");

    test_keyring::set_fail_deletes(false);
    test_keyring::set_available(false);
    assert!(delete_keyring_entry(&path, KeyMirror::OsKeyring).is_err());
}

#[test]
fn a_disabled_keyring_deletes_nothing() {
    test_keyring::reset();
    test_keyring::set_available(true);
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("k");
    persist_new_secret(&path, &sample_secret(), KeyMirror::OsKeyring).unwrap();
    assert_eq!(
        delete_keyring_entry(&path, KeyMirror::Disabled).unwrap(),
        KeyringDelete::KeyringDisabled
    );
    assert!(keyring_load(&path, KeyMirror::OsKeyring).is_some());
}

#[test]
fn retiring_a_key_removes_the_retired_keyring_copy_and_keeps_the_new_one() {
    test_keyring::reset();
    test_keyring::set_available(true);
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("k");
    let retired = dir.path().join("old");
    persist_new_secret(&path, &sample_secret(), KeyMirror::OsKeyring).unwrap();

    replace_retiring(&path, &retired, &other_secret(), KeyMirror::OsKeyring).unwrap();

    assert_eq!(read_secret(&retired), Some(sample_secret()), "the retired key file is kept");
    assert!(
        keyring_load(&retired, KeyMirror::OsKeyring).is_none(),
        "the retired keyring copy is gone"
    );
    assert_eq!(keyring_load(&path, KeyMirror::OsKeyring).unwrap().as_slice(), &other_secret());
}
