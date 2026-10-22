#![cfg(test)]

use super::*;

#[cfg(unix)]
#[test]
fn signing_key_load_or_generate_creates_private_key_with_owner_only_permissions() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("sign_key");

    DeviceSigningKeyPair::load_or_generate(&path).unwrap();

    let mode = std::fs::metadata(path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
}

#[test]
fn signing_key_load_or_generate_reuses_existing_private_key() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("sign_key");
    let first = DeviceSigningKeyPair::load_or_generate(&path).unwrap();

    let second = DeviceSigningKeyPair::load_or_generate(&path).unwrap();

    assert_eq!(second.signing.to_bytes(), first.signing.to_bytes());
    assert_eq!(second.public_bytes(), first.public_bytes());
}

#[test]
fn signing_public_key_round_trips_through_bytes() {
    let keypair = DeviceSigningKeyPair::generate();
    let recovered = verifying_key_from_bytes(&keypair.public_bytes()).unwrap();
    assert_eq!(recovered.to_bytes(), keypair.public_bytes());
}

#[test]
fn verifying_key_from_bytes_rejects_wrong_length() {
    assert!(verifying_key_from_bytes(&[0u8; 31]).is_err());
}

/// The core of the split: a device whose key is simply absent gets
/// `Missing` rather than a freshly minted identity. A registered daemon
/// maps this to a startup failure; nothing in this crate can quietly turn
/// it into a new key.
#[test]
fn signing_key_load_existing_reports_a_missing_key_instead_of_generating_one() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("sign_key");

    let Err(err) = DeviceSigningKeyPair::load_existing(&path) else {
        panic!("load_existing must not mint a signing identity for a device that has none");
    };

    assert!(matches!(err, KeyLoadError::Missing { .. }), "got {err:?}");
    assert!(!path.exists(), "load_existing must not create a signing key file");
}

/// A key that exists but cannot be read is `Unreadable`, never `Missing`.
/// The distinction is the whole point: a caller that fails hard on both is
/// safe, but one that regenerates on `Missing` would mint a second identity
/// over a live one the moment a read hiccups.
///
/// A directory standing where the key file belongs is the portable way to
/// force a non-`NotFound` read error — unlike `chmod 000` it fails for root
/// too, so this cannot quietly stop testing anything under a root CI
/// container.
#[test]
fn load_existing_separates_an_unreadable_key_from_a_missing_one() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("device_key");
    std::fs::create_dir(&path).unwrap();

    let Err(err) = DeviceSigningKeyPair::load_existing(&path) else {
        panic!("a key path that cannot be read must not load as a usable identity");
    };

    assert!(matches!(err, KeyLoadError::Unreadable { .. }), "got {err:?}");
}

#[test]
fn signing_key_load_existing_returns_the_persisted_identity() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("sign_key");
    let created = DeviceSigningKeyPair::generate_and_persist(&path).unwrap();

    let loaded = DeviceSigningKeyPair::load_existing(&path).unwrap();

    assert_eq!(loaded.signing.to_bytes(), created.signing.to_bytes());
    assert_eq!(loaded.public_bytes(), created.public_bytes());
}

/// Registration must still work: an unregistered device with no key gets
/// one. Guards against "fix" the vulnerability by making key creation
/// impossible, which would leave no device able to register at all.
#[test]
fn load_or_generate_still_creates_an_identity_for_an_unkeyed_device() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("device_key");

    let created = DeviceSigningKeyPair::load_or_generate(&path).unwrap();

    assert!(path.exists());
    assert_eq!(
        DeviceSigningKeyPair::load_existing(&path).unwrap().public_bytes(),
        created.public_bytes()
    );
}

/// `generate_and_persist` must not clobber an identity that is already
/// there: it adopts the existing one instead. This is the create-race
/// contract the `link`-based publication in `key_secret_store` exists to
/// provide — two daemons starting at once must converge on one identity,
/// not each keep a secret the other overwrote.
#[test]
fn generate_and_persist_adopts_an_identity_that_already_exists() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("device_key");
    let first = DeviceSigningKeyPair::generate_and_persist(&path).unwrap();

    let second = DeviceSigningKeyPair::generate_and_persist(&path).unwrap();

    assert_eq!(
        second.public_bytes(),
        first.public_bytes(),
        "the loser of a create race must adopt the winner's identity, not overwrite it"
    );
}
