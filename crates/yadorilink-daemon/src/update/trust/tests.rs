#![cfg(test)]

use ed25519_dalek::SigningKey;

use super::super::manifest::test_support::*;
use super::super::manifest::{
    self, ManifestError, ReleaseEntry, UpdateManifest, MANIFEST_SCHEMA_VERSION,
};
use super::*;

fn doc() -> UpdateManifest {
    UpdateManifest {
        schema_version: MANIFEST_SCHEMA_VERSION,
        generated_at: "2026-07-01T00:00:00Z".into(),
        expires_at: "2099-01-01T00:00:00Z".into(),
        withdrawn_versions: Vec::new(),
        releases: vec![ReleaseEntry {
            channel: "beta".into(),
            platform: "macos".into(),
            arch: "aarch64".into(),
            install_source: "standalone".into(),
            version: "0.2.0".into(),
            minimum_supported_version: "0.1.0".into(),
            rollout_percentage: 100,
            kill_switch: false,
            mandatory: false,
            artifact_url: "https://example.invalid/x.pkg".into(),
            artifact_sha256: "0".repeat(64),
            artifact_size: 1,
            artifact_publisher_identity: String::new(),
            release_notes_url: String::new(),
            state_schema_version: None,
            state_schema_min_readable: None,
            sparkle_build: None,
        }],
    }
}

fn verify(
    key: &SigningKey,
    id: &str,
    chain: &[SignedTrustRecord],
    genesis: &[manifest::TrustedKey],
) -> Result<UpdateManifest, ManifestError> {
    let envelope = sign_manifest_as(key, id, &doc(), chain.to_vec());
    manifest::verify_and_parse_with_keys(&serde_json::to_string(&envelope).unwrap(), genesis)
}

struct Fixture {
    a: SigningKey,
    b: SigningKey,
    genesis: Vec<manifest::TrustedKey>,
}

fn fixture() -> Fixture {
    let a = numbered_key(1);
    let b = numbered_key(2);
    let genesis = genesis_of(&[("old", &a)]);
    Fixture { a, b, genesis }
}

#[test]
fn planned_rotation_accepts_both_keys_during_overlap_then_only_the_new_one() {
    let f = fixture();
    let announce = sign_record(&f.a, "old", 1, &[("new", &f.b)], &[]);
    // Overlap: the old key still signs and the new key already verifies.
    assert!(verify(&f.a, "old", std::slice::from_ref(&announce), &f.genesis).is_ok());
    assert!(verify(&f.b, "new", std::slice::from_ref(&announce), &f.genesis).is_ok());
    // Retire the old key with a record signed by the new key.
    let retire = sign_record(&f.b, "new", 2, &[], &["old"]);
    let chain = [announce, retire];
    assert!(verify(&f.b, "new", &chain, &f.genesis).is_ok());
    assert_eq!(
        verify(&f.a, "old", &chain, &f.genesis).unwrap_err(),
        ManifestError::RevokedKey("old".into())
    );
}

#[test]
fn a_client_without_the_announcement_does_not_know_the_new_key() {
    let f = fixture();
    assert_eq!(
        verify(&f.b, "new", &[], &f.genesis).unwrap_err(),
        ManifestError::UnknownKey("new".into())
    );
}

#[test]
fn a_third_key_is_rejected() {
    let f = fixture();
    let announce = sign_record(&f.a, "old", 1, &[("new", &f.b)], &[]);
    let c = numbered_key(3);
    assert_eq!(
        verify(&c, "third", &[announce], &f.genesis).unwrap_err(),
        ManifestError::UnknownKey("third".into())
    );
}

#[test]
fn a_valid_signature_under_the_wrong_key_id_is_rejected() {
    let f = fixture();
    let announce = sign_record(&f.a, "old", 1, &[("new", &f.b)], &[]);
    assert_eq!(
        verify(&f.b, "old", &[announce], &f.genesis).unwrap_err(),
        ManifestError::SignatureVerificationFailed
    );
}

#[test]
fn emergency_revocation_signed_by_the_next_key_kills_the_compromised_key() {
    let f = fixture();
    let announce = sign_record(&f.a, "old", 1, &[("new", &f.b)], &[]);
    let revoke = sign_record(&f.b, "new", 2, &[], &["old"]);
    // The attacker holds `a` and produces a perfectly valid signature.
    let err = verify(&f.a, "old", &[announce, revoke], &f.genesis).unwrap_err();
    assert_eq!(err, ManifestError::RevokedKey("old".into()));
}

#[test]
fn a_revoked_key_cannot_sign_a_new_record() {
    let f = fixture();
    let announce = sign_record(&f.a, "old", 1, &[("new", &f.b)], &[]);
    let revoke = sign_record(&f.b, "new", 2, &[], &["old"]);
    let c = numbered_key(3);
    let comeback = sign_record(&f.a, "old", 3, &[("c", &c)], &[]);
    let err = TrustState::replay(&f.genesis, &[announce, revoke, comeback]).unwrap_err();
    assert_eq!(err, TrustError::SignerRevoked("old".into()));
}

#[test]
fn a_revoked_key_cannot_return_under_a_new_id() {
    let f = fixture();
    let announce = sign_record(&f.a, "old", 1, &[("new", &f.b)], &[]);
    let revoke = sign_record(&f.b, "new", 2, &[], &["old"]);
    let readd = sign_record(&f.b, "new", 3, &[("old-again", &f.a)], &[]);
    assert_eq!(
        TrustState::replay(&f.genesis, &[announce.clone(), revoke.clone(), readd]).unwrap_err(),
        TrustError::DuplicateKey("old-again".into())
    );
    let reuse_id = sign_record(&f.b, "new", 3, &[("old", &numbered_key(9))], &[]);
    assert_eq!(
        TrustState::replay(&f.genesis, &[announce, revoke, reuse_id]).unwrap_err(),
        TrustError::DuplicateKey("old".into())
    );
}

#[test]
fn record_rules_fail_closed() {
    let f = fixture();
    let g = &f.genesis;
    // Signed by a key nobody trusts.
    let rogue = numbered_key(8);
    let r = sign_record(&rogue, "rogue", 1, &[("x", &rogue)], &[]);
    assert_eq!(
        TrustState::replay(g, &[r]).unwrap_err(),
        TrustError::SignerNotTrusted("rogue".into())
    );
    // Signed by a key before it was added.
    let early = sign_record(&f.b, "new", 1, &[("c", &numbered_key(3))], &[]);
    assert_eq!(
        TrustState::replay(g, &[early]).unwrap_err(),
        TrustError::SignerNotTrusted("new".into())
    );
    // Serial skipped, repeated.
    let skip = sign_record(&f.a, "old", 2, &[("new", &f.b)], &[]);
    assert_eq!(
        TrustState::replay(g, &[skip]).unwrap_err(),
        TrustError::BadSerial { expected: 1, found: 2 }
    );
    let one = sign_record(&f.a, "old", 1, &[("new", &f.b)], &[]);
    let again = sign_record(&f.a, "old", 1, &[("c", &numbered_key(3))], &[]);
    assert!(matches!(
        TrustState::replay(g, &[one.clone(), again]).unwrap_err(),
        TrustError::BadSerial { .. }
    ));
    // Self revocation, revoking an unknown id, revoking the last key, no-op.
    let selfrev = sign_record(&f.a, "old", 1, &[("new", &f.b)], &["old"]);
    assert_eq!(
        TrustState::replay(g, &[selfrev]).unwrap_err(),
        TrustError::SelfRevoke("old".into())
    );
    let unknown = sign_record(&f.a, "old", 1, &[], &["nope"]);
    assert_eq!(
        TrustState::replay(g, &[unknown]).unwrap_err(),
        TrustError::RevokeUnknown("nope".into())
    );
    let noop = sign_record(&f.a, "old", 1, &[], &[]);
    assert_eq!(TrustState::replay(g, &[noop]).unwrap_err(), TrustError::Empty);
    let swap_out = sign_record(&f.a, "old", 1, &[("new", &f.b)], &[]);
    let kill_all = sign_record(&f.b, "new", 2, &[], &["old", "new"]);
    assert!(TrustState::replay(g, &[swap_out, kill_all]).is_err());
    // The development key can never be trusted through a record.
    let dev = SigningKey::from_bytes(&[0u8; 32]);
    let mut record = sign_record(&f.a, "old", 1, &[("dev", &dev)], &[]);
    record.record_json = record.record_json.replace(
        &public_hex(&dev),
        "00e033f866c263139ff4afd165e75bae3cfca67eb32399dddd6e33a3251af1e3",
    );
    assert!(TrustState::replay(g, &[record]).is_err());
}

#[test]
fn tampered_or_mis_domained_records_are_rejected() {
    let f = fixture();
    let good = sign_record(&f.a, "old", 1, &[("new", &f.b)], &[]);
    let c = numbered_key(3);
    let mut tampered = good.clone();
    tampered.record_json = tampered.record_json.replace(&public_hex(&f.b), &public_hex(&c));
    assert_eq!(
        TrustState::replay(&f.genesis, &[tampered]).unwrap_err(),
        TrustError::SignatureInvalid
    );
    let mut bad_sig = good.clone();
    bad_sig.signature_base64 = "AAAA".into();
    assert_eq!(
        TrustState::replay(&f.genesis, &[bad_sig]).unwrap_err(),
        TrustError::SignatureInvalid
    );
    // A signature over the bare record bytes (no domain prefix) is not accepted.
    use base64::Engine;
    use ed25519_dalek::Signer;
    let mut bare = good.clone();
    bare.signature_base64 = base64::engine::general_purpose::STANDARD
        .encode(f.a.sign(bare.record_json.as_bytes()).to_bytes());
    assert_eq!(TrustState::replay(&f.genesis, &[bare]).unwrap_err(), TrustError::SignatureInvalid);
    // Unknown fields are refused, not ignored.
    let mut extra = good;
    extra.record_json = extra.record_json.replace("\"serial\"", "\"flag\":1,\"serial\"");
    assert!(TrustState::replay(&f.genesis, &[extra]).is_err());
}

#[test]
fn a_manifest_signature_is_not_a_trust_record() {
    let f = fixture();
    // Sign a record-shaped document the way a manifest is signed.
    let record = TrustRecord {
        schema_version: 1,
        serial: 1,
        add: vec![KeyEntry { key_id: "new".into(), public_key_hex: public_hex(&f.b) }],
        revoke: vec![],
    };
    let record_json = serde_json::to_string(&record).unwrap();
    use base64::Engine;
    use ed25519_dalek::Signer;
    let forged = SignedTrustRecord {
        key_id: "old".into(),
        signature_base64: base64::engine::general_purpose::STANDARD
            .encode(f.a.sign(record_json.as_bytes()).to_bytes()),
        record_json,
    };
    assert!(TrustState::replay(&f.genesis, &[forged]).is_err());
}

#[test]
fn chain_length_is_bounded() {
    let f = fixture();
    let chain = vec![sign_record(&f.a, "old", 1, &[("new", &f.b)], &[]); MAX_CHAIN_LEN + 1];
    assert_eq!(TrustState::replay(&f.genesis, &chain).unwrap_err(), TrustError::ChainTooLong);
}

#[test]
fn persisted_revocation_survives_restart_and_a_stripped_or_replayed_chain() {
    let f = fixture();
    let dir = tempfile::tempdir().unwrap();
    let announce = sign_record(&f.a, "old", 1, &[("new", &f.b)], &[]);
    let revoke = sign_record(&f.b, "new", 2, &[], &["old"]);

    let state =
        TrustStore::new(dir.path()).sync(&f.genesis, &[announce.clone(), revoke.clone()]).unwrap();
    assert!(state.is_revoked("old"));

    // "Restart": a fresh store over the same directory, and a host that now
    // serves no chain at all, or only the older announcement.
    for offered in [vec![], vec![announce.clone()]] {
        let state = TrustStore::new(dir.path()).sync(&f.genesis, &offered).unwrap();
        assert_eq!(state.serial, 2);
        assert!(state.is_revoked("old"));
        assert_eq!(state.active_key_ids(), vec!["new"]);
    }
}

#[test]
fn an_offered_chain_that_forks_the_persisted_one_is_refused() {
    let f = fixture();
    let dir = tempfile::tempdir().unwrap();
    let announce = sign_record(&f.a, "old", 1, &[("new", &f.b)], &[]);
    TrustStore::new(dir.path()).sync(&f.genesis, &[announce]).unwrap();
    let c = numbered_key(3);
    let fork = sign_record(&f.a, "old", 1, &[("c", &c)], &[]);
    assert_eq!(
        TrustStore::new(dir.path()).sync(&f.genesis, &[fork]).unwrap_err(),
        TrustError::Conflict(1)
    );
}

#[test]
fn a_bad_extension_is_not_persisted() {
    let f = fixture();
    let dir = tempfile::tempdir().unwrap();
    let announce = sign_record(&f.a, "old", 1, &[("new", &f.b)], &[]);
    let bad = sign_record(&numbered_key(9), "rogue", 2, &[], &["old"]);
    assert!(TrustStore::new(dir.path()).sync(&f.genesis, &[announce.clone(), bad]).is_err());
    let state = TrustStore::new(dir.path()).sync(&f.genesis, &[]).unwrap();
    assert_eq!(state.serial, 0);
    assert!(!state.is_revoked("old"));
}

#[test]
fn a_tampered_persisted_chain_fails_closed() {
    let f = fixture();
    let dir = tempfile::tempdir().unwrap();
    let announce = sign_record(&f.a, "old", 1, &[("new", &f.b)], &[]);
    TrustStore::new(dir.path()).sync(&f.genesis, &[announce]).unwrap();
    let path = dir.path().join("update_trust_chain.json");
    let text = std::fs::read_to_string(&path).unwrap();
    std::fs::write(&path, text.replace("serial", "serial2")).unwrap();
    assert!(TrustStore::new(dir.path()).sync(&f.genesis, &[]).is_err());
    std::fs::write(&path, "not json").unwrap();
    assert!(matches!(
        TrustStore::new(dir.path()).sync(&f.genesis, &[]),
        Err(TrustError::Storage(_))
    ));
}

#[test]
fn concurrent_syncs_never_roll_back_a_longer_persisted_chain() {
    let f = fixture();
    let dir = tempfile::tempdir().unwrap();
    let announce = sign_record(&f.a, "old", 1, &[("new", &f.b)], &[]);
    let retire = sign_record(&f.b, "new", 2, &[], &["old"]);
    let store = std::sync::Arc::new(TrustStore::new(dir.path()));
    let handles: Vec<_> = (0..8)
        .map(|i| {
            let store = store.clone();
            let genesis = f.genesis.clone();
            let offered = if i % 2 == 0 {
                vec![announce.clone()]
            } else {
                vec![announce.clone(), retire.clone()]
            };
            std::thread::spawn(move || store.sync(&genesis, &offered).map(|s| s.serial))
        })
        .collect();
    for h in handles {
        h.join().unwrap().expect("every sync succeeds");
    }
    let state = TrustStore::new(dir.path()).sync(&f.genesis, &[]).unwrap();
    assert_eq!(state.serial, 2);
    assert!(state.is_revoked("old"));
}

fn chain_file(dir: &std::path::Path) -> std::path::PathBuf {
    dir.join("update_trust_chain.json")
}

fn leftovers(dir: &std::path::Path) -> Vec<String> {
    std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|name| name != "update_trust_chain.json")
        .collect()
}

/// A save cut at any step leaves either the previous complete chain or the
/// complete new one, and the failure surfaces to the caller.
#[test]
fn an_interrupted_save_leaves_the_old_or_the_new_complete_chain() {
    let f = fixture();
    let announce = sign_record(&f.a, "old", 1, &[("new", &f.b)], &[]);
    let retire = sign_record(&f.b, "new", 2, &[], &["old"]);
    for cut in [SaveStep::TempWritten, SaveStep::TempSynced, SaveStep::Published] {
        let dir = tempfile::tempdir().unwrap();
        TrustStore::new(dir.path()).sync(&f.genesis, std::slice::from_ref(&announce)).unwrap();
        let store = TrustStore::new(dir.path());
        let result = store.save_chain_with(&[announce.clone(), retire.clone()], &mut |step| {
            if step == cut {
                Err(std::io::Error::other("injected failure"))
            } else {
                Ok(())
            }
        });
        assert!(result.is_err(), "the failure at {cut:?} must surface");
        let state = TrustStore::new(dir.path()).sync(&f.genesis, &[]).unwrap();
        let expected = if cut == SaveStep::Published { 2 } else { 1 };
        assert_eq!(state.serial, expected, "cut at {cut:?}");
    }
}

/// A process killed inside the durable publish (before the move, or right
/// after it) leaves a complete chain on disk and at worst a stray temporary.
#[test]
fn a_crash_inside_the_durable_publish_never_tears_the_chain() {
    use yadorilink_fs_platform::durable_dir::{arm_failpoint, disarm_failpoint, NsFailpoint};
    let f = fixture();
    let announce = sign_record(&f.a, "old", 1, &[("new", &f.b)], &[]);
    let retire = sign_record(&f.b, "new", 2, &[], &["old"]);
    for (point, serial) in
        [(NsFailpoint::AfterStage, 1), (NsFailpoint::BeforeMove, 1), (NsFailpoint::AfterMove, 2)]
    {
        let dir = tempfile::tempdir().unwrap();
        TrustStore::new(dir.path()).sync(&f.genesis, std::slice::from_ref(&announce)).unwrap();
        arm_failpoint(point);
        let result =
            TrustStore::new(dir.path()).sync(&f.genesis, &[announce.clone(), retire.clone()]);
        disarm_failpoint();
        assert!(matches!(result, Err(TrustError::Storage(_))), "{point:?}: {result:?}");
        let state = TrustStore::new(dir.path()).sync(&f.genesis, &[]).unwrap();
        assert_eq!(state.serial, serial, "crash at {point:?}");
        assert_eq!(state.is_revoked("old"), serial == 2);
    }
}

/// A failed persist is an error, not an accepted check: the revocation the
/// server offered is not honoured as if it had been saved, and nothing on
/// disk advances.
#[test]
fn a_failed_persist_refuses_the_check_and_does_not_advance_acceptance() {
    use yadorilink_fs_platform::durable_dir::{arm_failpoint, disarm_failpoint, NsFailpoint};
    let f = fixture();
    let dir = tempfile::tempdir().unwrap();
    let announce = sign_record(&f.a, "old", 1, &[("new", &f.b)], &[]);
    arm_failpoint(NsFailpoint::BeforeMove);
    let result = TrustStore::new(dir.path()).sync(&f.genesis, std::slice::from_ref(&announce));
    disarm_failpoint();
    assert!(matches!(result, Err(TrustError::Storage(_))));
    assert!(!chain_file(dir.path()).exists());
    let state = TrustStore::new(dir.path()).sync(&f.genesis, &[]).unwrap();
    assert_eq!(state.serial, 0);
    assert!(state.active_public_key("new").is_none());
}

/// A torn temporary from an earlier crash is never read as the chain, and the
/// next save replaces it.
#[test]
fn a_torn_temp_file_is_ignored_on_load_and_replaced_on_save() {
    let f = fixture();
    let dir = tempfile::tempdir().unwrap();
    let announce = sign_record(&f.a, "old", 1, &[("new", &f.b)], &[]);
    let store = TrustStore::new(dir.path());
    std::fs::write(store.temp_path(), "{ torn").unwrap();
    assert_eq!(store.sync(&f.genesis, &[]).unwrap().serial, 0);
    assert_eq!(store.sync(&f.genesis, &[announce]).unwrap().serial, 1);
    assert!(leftovers(dir.path()).is_empty(), "the next save consumes the stray temporary");
    assert_eq!(TrustStore::new(dir.path()).sync(&f.genesis, &[]).unwrap().serial, 1);
}
