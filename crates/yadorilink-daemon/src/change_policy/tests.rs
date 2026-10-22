#![cfg(test)]

use ed25519_dalek::SigningKey;

use super::policy_signing::{
    grant_record, grant_record_at_epoch, revoke_record, revoke_record_at_epoch, rotate_record,
};
use super::*;

fn service_key() -> SigningKey {
    SigningKey::from_bytes(&[7u8; 32])
}

#[test]
fn verified_rotation_updates_final_authority_key() {
    let old_key = service_key();
    let new_key = SigningKey::from_bytes(&[8u8; 32]);
    let group_id = "group";
    let rotate =
        rotate_record(&old_key, group_id, 1, ZERO_HASH, new_key.verifying_key().to_bytes());
    let rotate_hash: [u8; HASH_LEN] = rotate.record_hash.as_slice().try_into().unwrap();

    let log = GroupPolicyLog {
        group_id: group_id.to_string(),
        current_seq: 1,
        current_epoch: 0,
        policy_head: rotate_hash.to_vec(),
        records: vec![rotate],
    };
    let policy = verify_group_policy_log(&old_key.verifying_key().to_bytes(), &log).unwrap();
    assert_eq!(policy.final_authority_key, new_key.verifying_key().to_bytes());
    // One rotation record -> generation 1.
    assert_eq!(policy.authority_generation, 1);
}

fn hash_of(record: &PolicyRecord) -> [u8; HASH_LEN] {
    record.record_hash.as_slice().try_into().unwrap()
}

#[test]
fn resolve_authority_key_answers_the_genesis_bootstrap_point() {
    let key = service_key();
    let log = GroupPolicyLog {
        group_id: "group".to_string(),
        current_seq: 0,
        current_epoch: 0,
        policy_head: ZERO_HASH.to_vec(),
        records: vec![],
    };
    let policy = verify_group_policy_log(&key.verifying_key().to_bytes(), &log).unwrap();
    let signer_key_id: [u8; HASH_LEN] = Sha256::digest(key.verifying_key().to_bytes()).into();

    let resolved = policy.resolve_authority_key(&signer_key_id, &ZERO_HASH).unwrap();
    assert_eq!(resolved.to_bytes(), key.verifying_key().to_bytes());
}

#[test]
fn resolve_authority_key_finds_the_pre_rotation_key_at_the_pre_rotation_policy_head_even_after_rotation(
) {
    // The property that actually matters: after a RotateAuthority
    // record lands, resolve_authority_key must STILL be able to
    // answer "which key was valid BEFORE this rotation" for anyone
    // holding an AuthorizationCheckpoint pinned to that earlier
    // policy_head -- final_authority_key alone cannot do this, it
    // only ever answers "what is current."
    let old_key = service_key();
    let new_key = SigningKey::from_bytes(&[8u8; 32]);
    let group_id = "group";

    let grant = grant_record(
        &old_key,
        group_id,
        1,
        ZERO_HASH,
        "device-a",
        [9u8; HASH_LEN],
        WriterRole::Editor,
    );
    let grant_hash = hash_of(&grant);
    let rotate =
        rotate_record(&old_key, group_id, 2, grant_hash, new_key.verifying_key().to_bytes());
    let rotate_hash = hash_of(&rotate);

    let log = GroupPolicyLog {
        group_id: group_id.to_string(),
        current_seq: 2,
        current_epoch: 0,
        policy_head: rotate_hash.to_vec(),
        records: vec![grant, rotate],
    };
    let policy = verify_group_policy_log(&old_key.verifying_key().to_bytes(), &log).unwrap();
    assert_eq!(policy.final_authority_key, new_key.verifying_key().to_bytes());

    let old_signer_key_id: [u8; HASH_LEN] =
        Sha256::digest(old_key.verifying_key().to_bytes()).into();
    let new_signer_key_id: [u8; HASH_LEN] =
        Sha256::digest(new_key.verifying_key().to_bytes()).into();

    // Pre-rotation policy point (the grant's own head) resolves to
    // the OLD key -- this is the key that actually signed it, and
    // signed the rotation record itself.
    let resolved_old = policy.resolve_authority_key(&old_signer_key_id, &grant_hash).unwrap();
    assert_eq!(resolved_old.to_bytes(), old_key.verifying_key().to_bytes());
    let resolved_rotate_record =
        policy.resolve_authority_key(&old_signer_key_id, &rotate_hash).unwrap();
    assert_eq!(
        resolved_rotate_record.to_bytes(),
        old_key.verifying_key().to_bytes(),
        "the rotate record's OWN head is still signed by the OLD key -- the new key only \
         takes effect for records AFTER it"
    );

    // The old key must never resolve for the genesis point wrongly
    // either, and the NEW key must not resolve at any point BEFORE
    // the rotation actually took effect.
    assert!(policy.resolve_authority_key(&new_signer_key_id, &grant_hash).is_none());
    assert!(policy.resolve_authority_key(&new_signer_key_id, &rotate_hash).is_none());
}

#[test]
fn resolve_authority_key_rejects_a_signer_key_id_that_does_not_match_the_real_key_at_that_point() {
    let key = service_key();
    let wrong_key = SigningKey::from_bytes(&[42u8; 32]);
    let log = GroupPolicyLog {
        group_id: "group".to_string(),
        current_seq: 0,
        current_epoch: 0,
        policy_head: ZERO_HASH.to_vec(),
        records: vec![],
    };
    let policy = verify_group_policy_log(&key.verifying_key().to_bytes(), &log).unwrap();
    let wrong_signer_key_id: [u8; HASH_LEN] =
        Sha256::digest(wrong_key.verifying_key().to_bytes()).into();

    assert!(policy.resolve_authority_key(&wrong_signer_key_id, &ZERO_HASH).is_none());
}

#[test]
fn resolve_authority_key_returns_none_for_a_policy_head_that_was_never_a_real_chain_point() {
    let key = service_key();
    let log = GroupPolicyLog {
        group_id: "group".to_string(),
        current_seq: 0,
        current_epoch: 0,
        policy_head: ZERO_HASH.to_vec(),
        records: vec![],
    };
    let policy = verify_group_policy_log(&key.verifying_key().to_bytes(), &log).unwrap();
    let signer_key_id: [u8; HASH_LEN] = Sha256::digest(key.verifying_key().to_bytes()).into();

    assert!(policy.resolve_authority_key(&signer_key_id, &[0xffu8; HASH_LEN]).is_none());
}

/// A three-record chain (grant a, grant b, revoke a) and its verified
/// state, reused by the watermark tests below.
fn revoke_chain() -> (SigningKey, [u8; HASH_LEN], [u8; HASH_LEN], GroupPolicyState) {
    let key = service_key();
    let group_id = "group";
    let a =
        grant_record(&key, group_id, 1, ZERO_HASH, "device-a", [9u8; HASH_LEN], WriterRole::Editor);
    let a_hash = hash_of(&a);
    let b =
        grant_record(&key, group_id, 2, a_hash, "device-b", [7u8; HASH_LEN], WriterRole::Editor);
    let b_hash = hash_of(&b);
    let revoke = revoke_record(&key, group_id, 3, b_hash, "device-a");
    let revoke_hash = hash_of(&revoke);
    let log = GroupPolicyLog {
        group_id: group_id.to_string(),
        current_seq: 3,
        current_epoch: 1,
        policy_head: revoke_hash.to_vec(),
        records: vec![a, b, revoke],
    };
    let verified = verify_group_policy_log(&key.verifying_key().to_bytes(), &log).unwrap();
    (key, a_hash, b_hash, verified)
}

#[test]
fn watermark_accepts_first_sight() {
    let (_key, _a, _b, verified) = revoke_chain();
    match verified.watermark_verdict(None) {
        WatermarkVerdict::Accept(w) => {
            assert_eq!(w.highest_verified_seq, 3);
            assert_eq!(w.highest_verified_head, verified.policy_head);
        }
        other => panic!("expected first-sight accept, got {other:?}"),
    }
}

#[test]
fn watermark_rejects_restart_rollback() {
    // The device verified the full chain (through the seq-3 revoke) and
    // persisted that watermark.
    let (key, a_hash, b_hash, verified) = revoke_chain();
    let watermark = verified.to_watermark();

    // After a restart the in-memory state is gone (base = None); a peer
    // replays the OLD chain up to seq 2 — signature-valid, but a rollback
    // that hides the seq-3 revoke of device-a.
    let a =
        grant_record(&key, "group", 1, ZERO_HASH, "device-a", [9u8; HASH_LEN], WriterRole::Editor);
    assert_eq!(hash_of(&a), a_hash);
    let b = grant_record(&key, "group", 2, a_hash, "device-b", [7u8; HASH_LEN], WriterRole::Editor);
    let old_log = GroupPolicyLog {
        group_id: "group".to_string(),
        current_seq: 2,
        current_epoch: 0,
        policy_head: b_hash.to_vec(),
        records: vec![a, b],
    };
    let replayed = verify_group_policy_log(&key.verifying_key().to_bytes(), &old_log).unwrap();
    assert!(matches!(replayed.watermark_verdict(Some(&watermark)), WatermarkVerdict::Reject(_)));
}

#[test]
fn watermark_rejects_fork_at_same_seq() {
    let key = service_key();
    let group_id = "group";
    // Two distinct seq-1 chains signed by the same authority: granting
    // different devices yields different record hashes (heads).
    let x =
        grant_record(&key, group_id, 1, ZERO_HASH, "device-a", [9u8; HASH_LEN], WriterRole::Editor);
    let x_hash = hash_of(&x);
    let y =
        grant_record(&key, group_id, 1, ZERO_HASH, "device-b", [7u8; HASH_LEN], WriterRole::Editor);
    let y_hash = hash_of(&y);
    assert_ne!(x_hash, y_hash);

    let x_log = GroupPolicyLog {
        group_id: group_id.to_string(),
        current_seq: 1,
        current_epoch: 0,
        policy_head: x_hash.to_vec(),
        records: vec![x],
    };
    let watermark =
        verify_group_policy_log(&key.verifying_key().to_bytes(), &x_log).unwrap().to_watermark();

    let y_log = GroupPolicyLog {
        group_id: group_id.to_string(),
        current_seq: 1,
        current_epoch: 0,
        policy_head: y_hash.to_vec(),
        records: vec![y],
    };
    let forked = verify_group_policy_log(&key.verifying_key().to_bytes(), &y_log).unwrap();
    assert!(matches!(forked.watermark_verdict(Some(&watermark)), WatermarkVerdict::Reject(_)));
}

#[test]
fn watermark_accepts_forward_extension() {
    let key = service_key();
    let group_id = "group";
    // Watermark at seq 2 (grant a, grant b).
    let a =
        grant_record(&key, group_id, 1, ZERO_HASH, "device-a", [9u8; HASH_LEN], WriterRole::Editor);
    let a_hash = hash_of(&a);
    let b =
        grant_record(&key, group_id, 2, a_hash, "device-b", [7u8; HASH_LEN], WriterRole::Editor);
    let b_hash = hash_of(&b);
    let base_log = GroupPolicyLog {
        group_id: group_id.to_string(),
        current_seq: 2,
        current_epoch: 0,
        policy_head: b_hash.to_vec(),
        records: vec![a.clone(), b.clone()],
    };
    let watermark =
        verify_group_policy_log(&key.verifying_key().to_bytes(), &base_log).unwrap().to_watermark();

    // A longer chain that genuinely extends the watermark head at seq 2.
    let revoke = revoke_record(&key, group_id, 3, b_hash, "device-a");
    let revoke_hash = hash_of(&revoke);
    let ext_log = GroupPolicyLog {
        group_id: group_id.to_string(),
        current_seq: 3,
        current_epoch: 1,
        policy_head: revoke_hash.to_vec(),
        records: vec![a, b, revoke],
    };
    let extended = verify_group_policy_log(&key.verifying_key().to_bytes(), &ext_log).unwrap();
    match extended.watermark_verdict(Some(&watermark)) {
        WatermarkVerdict::Accept(w) => {
            assert_eq!(w.highest_verified_seq, 3);
            assert_eq!(w.highest_verified_head, revoke_hash);
        }
        other => panic!("expected forward-extension accept, got {other:?}"),
    }
}

#[test]
fn watermark_accepts_identical_resend() {
    let (_key, _a, _b, verified) = revoke_chain();
    let watermark = verified.to_watermark();
    // The coordination plane resends the same head; nothing to advance.
    assert!(matches!(
        verified.watermark_verdict(Some(&watermark)),
        WatermarkVerdict::Accept(w) if w == watermark
    ));
}

#[test]
fn watermark_rejects_authority_key_swap_at_same_generation() {
    // Two chains at the SAME authority generation must share the same
    // authority key. A snapshot whose authority-key fingerprint differs
    // from the verified watermark's — with no rotation to justify it — is a
    // fork at the trust root, and the fingerprint guard rejects it directly
    // even where the seq/head would otherwise line up.
    let (_key, _a, _b, verified) = revoke_chain();
    let mut watermark = verified.to_watermark();
    let mut swapped = verified.authority_key_fingerprint();
    swapped[0] ^= 0xFF;
    watermark.authority_key_fingerprint = swapped;
    // Generation is unchanged (revoke_chain performs no rotation), so the
    // equal-generation fingerprint comparison is what fires here.
    assert_eq!(watermark.authority_key_generation, verified.authority_generation);
    assert!(matches!(verified.watermark_verdict(Some(&watermark)), WatermarkVerdict::Reject(_)));
}

#[test]
fn watermark_accepts_authority_rotation_and_records_new_fingerprint() {
    let key1 = service_key();
    let group_id = "group";
    // Watermark at seq 1 under the original authority key (generation 0).
    let a = grant_record(
        &key1,
        group_id,
        1,
        ZERO_HASH,
        "device-a",
        [9u8; HASH_LEN],
        WriterRole::Editor,
    );
    let a_hash = hash_of(&a);
    let base_log = GroupPolicyLog {
        group_id: group_id.to_string(),
        current_seq: 1,
        current_epoch: 0,
        policy_head: a_hash.to_vec(),
        records: vec![a.clone()],
    };
    let base = verify_group_policy_log(&key1.verifying_key().to_bytes(), &base_log).unwrap();
    let watermark = base.to_watermark();
    assert_eq!(watermark.authority_key_generation, 0);

    // A longer chain rotates the authority key at seq 2 — a legitimate
    // rotation, signed by the current (key1) authority, that bumps the
    // generation to 1 and changes the authority key to key2.
    let key2 = SigningKey::from_bytes(&[11u8; 32]);
    let rotate = rotate_record(&key1, group_id, 2, a_hash, key2.verifying_key().to_bytes());
    let rotate_hash = hash_of(&rotate);
    let rotated_log = GroupPolicyLog {
        group_id: group_id.to_string(),
        current_seq: 2,
        current_epoch: 0,
        policy_head: rotate_hash.to_vec(),
        records: vec![a, rotate],
    };
    let rotated = verify_group_policy_log(&key1.verifying_key().to_bytes(), &rotated_log).unwrap();
    assert_eq!(rotated.authority_generation, 1);

    match rotated.watermark_verdict(Some(&watermark)) {
        WatermarkVerdict::Accept(w) => {
            assert_eq!(w.authority_key_generation, 1);
            // The persisted fingerprint is the rotated-to key's, not the
            // pre-rotation one.
            assert_eq!(w.authority_key_fingerprint, rotated.authority_key_fingerprint());
            assert_ne!(w.authority_key_fingerprint, watermark.authority_key_fingerprint);
        }
        other => panic!("expected rotation accept, got {other:?}"),
    }
}

#[test]
fn current_writers_reflects_grants_and_revokes() {
    // grant a, grant b, revoke a -- device-a should not appear at the
    // current (post-revoke) writer set, only device-b should.
    let (_key, _a_hash, _b_hash, verified) = revoke_chain();
    let writers = verified.current_writers();
    assert_eq!(writers.len(), 1);
    assert_eq!(writers[0].device_id, "device-b");
    assert_eq!(writers[0].signing_key_fingerprint, [7u8; HASH_LEN]);
}

#[test]
fn writers_at_reconstructs_a_historical_seq() {
    // At seq 2 (after both grants, before the seq-3 revoke), both
    // device-a and device-b must appear -- writers_at must reconstruct
    // that historical set exactly, not just the final one.
    let (_key, _a_hash, _b_hash, verified) = revoke_chain();
    let mut writers = verified.writers_at(2).unwrap();
    writers.sort_by(|a, b| a.device_id.cmp(&b.device_id));
    assert_eq!(writers.len(), 2);
    assert_eq!(writers[0].device_id, "device-a");
    assert_eq!(writers[1].device_id, "device-b");

    // At seq 1 (only the first grant), only device-a is a writer.
    let writers_at_1 = verified.writers_at(1).unwrap();
    assert_eq!(writers_at_1.len(), 1);
    assert_eq!(writers_at_1[0].device_id, "device-a");
}

#[test]
fn writers_at_rejects_a_sequence_beyond_what_was_verified() {
    // revoke_chain's verified state tops out at seq 3 -- asking for a
    // seq beyond that must fail closed, not silently replay everything
    // it does have and call that "the writer set at seq 10".
    let (_key, _a_hash, _b_hash, verified) = revoke_chain();
    assert_eq!(
        verified.writers_at(10),
        Err(WriterSnapshotError::FutureSequence { requested: 10, current: 3 })
    );
}

#[test]
fn writers_at_zero_is_the_empty_pre_genesis_set() {
    // Seq 0 is a real, valid answer (no grants applied yet), not an
    // error -- distinct from asking beyond the verified chain.
    let (_key, _a_hash, _b_hash, verified) = revoke_chain();
    assert_eq!(verified.writers_at(0), Ok(Vec::new()));
}

#[test]
fn writers_at_is_sorted_by_device_id_regardless_of_grant_order() {
    // Grant order is z, then a -- the returned set must still be sorted
    // by device_id, not by grant/insertion order, so two devices that
    // replay the same chain always compute byte-identical `Vec`s.
    let key = service_key();
    let group_id = "group";
    let z =
        grant_record(&key, group_id, 1, ZERO_HASH, "device-z", [1u8; HASH_LEN], WriterRole::Editor);
    let z_hash = hash_of(&z);
    let a =
        grant_record(&key, group_id, 2, z_hash, "device-a", [2u8; HASH_LEN], WriterRole::Editor);
    let a_hash = hash_of(&a);
    let log = GroupPolicyLog {
        group_id: group_id.to_string(),
        current_seq: 2,
        current_epoch: 0,
        policy_head: a_hash.to_vec(),
        records: vec![z, a],
    };
    let policy = verify_group_policy_log(&key.verifying_key().to_bytes(), &log).unwrap();
    let writers = policy.current_writers();
    assert_eq!(
        writers.iter().map(|w| w.device_id.as_str()).collect::<Vec<_>>(),
        vec!["device-a", "device-z"]
    );
}

#[test]
fn current_writers_is_empty_for_an_empty_chain() {
    let policy = GroupPolicyState {
        current_seq: 0,
        current_epoch: 0,
        policy_head: ZERO_HASH,
        final_authority_key: ZERO_HASH,
        authority_generation: 0,
        records: BTreeMap::new(),
        authority_key_history: BTreeMap::new(),
    };
    assert!(policy.current_writers().is_empty());
}

#[test]
fn writers_at_rejects_a_gap_in_the_verified_chain() {
    // A hand-built state whose current_seq claims 3 but is missing the
    // record at seq 2 -- something `verify_group_policy_log`'s own
    // gap-free sequencing check should make impossible, but writers_at
    // must not silently replay past the hole and call the result "the
    // writer set at seq 2".
    let key = service_key();
    let group_id = "group";
    let a =
        grant_record(&key, group_id, 1, ZERO_HASH, "device-a", [9u8; HASH_LEN], WriterRole::Editor);
    let a_hash = hash_of(&a);
    let c =
        grant_record(&key, group_id, 3, a_hash, "device-c", [3u8; HASH_LEN], WriterRole::Editor);
    let log = GroupPolicyLog {
        group_id: group_id.to_string(),
        current_seq: 1,
        current_epoch: 0,
        policy_head: a_hash.to_vec(),
        records: vec![a],
    };
    let base = verify_group_policy_log(&key.verifying_key().to_bytes(), &log).unwrap();
    let mut records = base.records;
    // Insert seq 3 directly, bypassing verify_group_policy_log's
    // gap-free sequencing check, to construct the otherwise-impossible
    // gapped state this test exists to guard against.
    let VerifiedPolicyRecord {
        seq,
        prev_record_hash,
        record_hash,
        epoch,
        signer_key_id,
        action,
        signature,
    } = verify_record(&c, &base.final_authority_key, a_hash).unwrap();
    records.insert(
        seq,
        VerifiedPolicyRecord {
            seq,
            prev_record_hash,
            record_hash,
            epoch,
            signer_key_id,
            action,
            signature,
        },
    );
    let gapped = GroupPolicyState {
        current_seq: 3,
        current_epoch: base.current_epoch,
        policy_head: record_hash,
        final_authority_key: base.final_authority_key,
        authority_generation: base.authority_generation,
        records,
        authority_key_history: base.authority_key_history.clone(),
    };

    assert_eq!(gapped.writers_at(2), Err(WriterSnapshotError::MissingSequence { requested: 2 }));
}

// --- WriterRole regression tests -----------------------------------

/// The core security property this whole mechanism exists for: a
/// Viewer-role grant must never be treated as a writer -- neither
/// `current_writers()` nor `writers_at()` may surface it, the same
/// membership set `resolve_authority_key`'s callers and checkpoint
/// issuance both rely on.
#[test]
fn a_viewer_role_grant_is_never_treated_as_a_writer() {
    let key = service_key();
    let group_id = "group";
    let viewer_fp = [9u8; HASH_LEN];
    let grant =
        grant_record(&key, group_id, 1, ZERO_HASH, "device-viewer", viewer_fp, WriterRole::Viewer);
    let hash = hash_of(&grant);
    let log = GroupPolicyLog {
        group_id: group_id.to_string(),
        current_seq: 1,
        current_epoch: 0,
        policy_head: hash.to_vec(),
        records: vec![grant],
    };
    let policy = verify_group_policy_log(&key.verifying_key().to_bytes(), &log).unwrap();

    assert!(
        policy.current_writers().is_empty(),
        "a Viewer is a group member, not a writer -- current_writers() must exclude it"
    );
    assert_eq!(
        policy.writers_at(1).unwrap(),
        Vec::new(),
        "writers_at() must exclude a Viewer-role grant at every historical sequence too"
    );
}

/// The mirror image of the test above: a Viewer-role grant is excluded
/// from the WRITER set, but it IS a group MEMBER -- `current_members()`
/// must surface it with `role: Viewer`, distinct from
/// `current_writers()`'s own exclusion. Backs the "people with access"
/// listing, where a Viewer is a real, visible member even though its
/// changes are never admitted.
#[test]
fn a_viewer_role_grant_is_a_member_but_not_a_writer() {
    let key = service_key();
    let group_id = "group";
    let viewer_fp = [9u8; HASH_LEN];
    let grant =
        grant_record(&key, group_id, 1, ZERO_HASH, "device-viewer", viewer_fp, WriterRole::Viewer);
    let hash = hash_of(&grant);
    let log = GroupPolicyLog {
        group_id: group_id.to_string(),
        current_seq: 1,
        current_epoch: 0,
        policy_head: hash.to_vec(),
        records: vec![grant],
    };
    let policy = verify_group_policy_log(&key.verifying_key().to_bytes(), &log).unwrap();

    assert!(
        policy.current_writers().is_empty(),
        "a Viewer must still be excluded from the writer set"
    );
    assert_eq!(
        policy.current_members(),
        vec![GroupMember {
            device_id: "device-viewer".to_string(),
            role: WriterRole::Viewer,
            signing_key_fingerprint: viewer_fp,
        }],
        "a Viewer-role grant is a group member -- current_members() must include it with \
         role Viewer"
    );
}

/// Editor and Owner grants are both writers -- this verifier makes no
/// distinction between them (see `WriterRole`'s own doc comment for why
/// Owner's extra authority, if any, belongs to the signing service, not
/// here).
#[test]
fn editor_and_owner_role_grants_are_both_writers() {
    let key = service_key();
    let group_id = "group";
    let editor_fp = [1u8; HASH_LEN];
    let owner_fp = [2u8; HASH_LEN];
    let editor =
        grant_record(&key, group_id, 1, ZERO_HASH, "device-editor", editor_fp, WriterRole::Editor);
    let editor_hash = hash_of(&editor);
    let owner =
        grant_record(&key, group_id, 2, editor_hash, "device-owner", owner_fp, WriterRole::Owner);
    let owner_hash = hash_of(&owner);
    let log = GroupPolicyLog {
        group_id: group_id.to_string(),
        current_seq: 2,
        current_epoch: 0,
        policy_head: owner_hash.to_vec(),
        records: vec![editor, owner],
    };
    let policy = verify_group_policy_log(&key.verifying_key().to_bytes(), &log).unwrap();

    let mut writers = policy.current_writers();
    writers.sort_by(|a, b| a.device_id.cmp(&b.device_id));
    assert_eq!(
        writers.iter().map(|w| w.device_id.as_str()).collect::<Vec<_>>(),
        vec!["device-editor", "device-owner"]
    );
}

/// Revoke must remove a device from the writer set regardless of what
/// role its grant carried -- a Viewer revoke is a no-op on the writer
/// set (it was never in it), and an Editor/Owner revoke removes it same
/// as before roles existed.
#[test]
fn revoke_removes_a_grant_from_the_writer_set_regardless_of_its_role() {
    let key = service_key();
    let group_id = "group";
    let editor_fp = [1u8; HASH_LEN];
    let editor =
        grant_record(&key, group_id, 1, ZERO_HASH, "device-editor", editor_fp, WriterRole::Editor);
    let editor_hash = hash_of(&editor);
    let revoke = revoke_record(&key, group_id, 2, editor_hash, "device-editor");
    let revoke_hash = hash_of(&revoke);
    let log = GroupPolicyLog {
        group_id: group_id.to_string(),
        current_seq: 2,
        current_epoch: 1,
        policy_head: revoke_hash.to_vec(),
        records: vec![editor, revoke],
    };
    let policy = verify_group_policy_log(&key.verifying_key().to_bytes(), &log).unwrap();

    assert!(policy.current_writers().is_empty());
}

/// A live role CHANGE (the coordination plane's downgrade mechanism) is
/// expressed as a chained Revoke immediately followed by a Grant for
/// the SAME device, at the SAME bumped epoch -- this proves the replay
/// this crate performs (`current_writers`/`writers_at`/`current_members`'s
/// shared fold) correctly ends up with the device holding the NEW
/// granted role, not stuck "revoked" and not in any other inconsistent
/// state. This is the exact record shape
/// the coordination service's downgrade endpoint produces: it was not
/// obvious from reading the fold alone that a same-seq-adjacent
/// Revoke-then-Grant pair for one device converges correctly rather
/// than leaving some artifact of the intermediate revoked state.
#[test]
fn a_chained_revoke_then_grant_for_the_same_device_leaves_it_holding_the_new_role_not_revoked() {
    let key = service_key();
    let group_id = "group";
    let fp = [3u8; HASH_LEN];
    let original_grant =
        grant_record(&key, group_id, 1, ZERO_HASH, "device-a", fp, WriterRole::Editor);
    let original_hash = hash_of(&original_grant);
    let revoke = revoke_record_at_epoch(&key, group_id, 2, original_hash, 1, "device-a");
    let revoke_hash = hash_of(&revoke);
    let downgrade_grant = grant_record_at_epoch(
        &key,
        group_id,
        3,
        revoke_hash,
        1,
        "device-a",
        fp,
        WriterRole::Viewer,
    );
    let downgrade_hash = hash_of(&downgrade_grant);
    let log = GroupPolicyLog {
        group_id: group_id.to_string(),
        current_seq: 3,
        current_epoch: 1,
        policy_head: downgrade_hash.to_vec(),
        records: vec![original_grant, revoke, downgrade_grant],
    };
    let policy = verify_group_policy_log(&key.verifying_key().to_bytes(), &log).unwrap();

    // Not revoked -- still a genuine group member with a real grant.
    // `current_writers` intentionally excludes Viewers (see its own doc
    // comment), so its emptiness alone is ambiguous between "revoked"
    // and "downgraded to Viewer"; `current_members` disambiguates it
    // directly by surfacing the member's actual role and bound
    // fingerprint.
    assert!(policy.current_writers().is_empty());
    let member = policy
        .current_members()
        .into_iter()
        .find(|m| m.device_id == "device-a")
        .expect("a Viewer-downgraded device must remain a group member, not be removed");
    assert_eq!(member.role, WriterRole::Viewer, "must hold the new (Viewer) role, not revoked");
    assert_eq!(
        member.signing_key_fingerprint, fp,
        "the grant's own fingerprint binding still applies to the downgraded member"
    );

    // Upgrading the SAME device back to Editor in the same chain
    // converges correctly too -- the fold is not somehow "poisoned" by
    // having passed through a Revoke.
    let reupgrade = grant_record_at_epoch(
        &key,
        group_id,
        4,
        downgrade_hash,
        1,
        "device-a",
        fp,
        WriterRole::Editor,
    );
    let reupgrade_hash = hash_of(&reupgrade);
    let reupgraded_log = GroupPolicyLog {
        group_id: group_id.to_string(),
        current_seq: 4,
        current_epoch: 1,
        policy_head: reupgrade_hash.to_vec(),
        records: vec![
            log.records[0].clone(),
            log.records[1].clone(),
            log.records[2].clone(),
            reupgrade,
        ],
    };
    let reupgraded_policy =
        verify_group_policy_log(&key.verifying_key().to_bytes(), &reupgraded_log).unwrap();
    assert_eq!(
        reupgraded_policy
            .current_writers()
            .iter()
            .map(|w| w.device_id.as_str())
            .collect::<Vec<_>>(),
        vec!["device-a"]
    );
}

/// The role is part of what gets signed: a record with its `role` field
/// tampered after signing (Viewer -> Editor, a privilege escalation)
/// must fail signature verification, exactly like tampering with the
/// device_id or fingerprint would. This is the property that makes the
/// role a real security boundary rather than an unauthenticated hint --
/// without it, anything that can touch a `PolicyRecord` in transit or
/// storage (a compromised relay, a corrupted cache) could silently
/// upgrade a Viewer to a full writer.
#[test]
fn tampering_with_a_grants_role_after_signing_invalidates_the_signature() {
    let key = service_key();
    let group_id = "group";
    let mut viewer_grant =
        grant_record(&key, group_id, 1, ZERO_HASH, "device-a", [9u8; HASH_LEN], WriterRole::Viewer);
    // Escalate the wire record's role after signing, without
    // re-signing -- simulates an in-transit/in-storage tamper attempt.
    viewer_grant.role = WriterRole::Editor.to_wire();

    let log = GroupPolicyLog {
        group_id: group_id.to_string(),
        current_seq: 1,
        current_epoch: 0,
        policy_head: viewer_grant.record_hash.clone(),
        records: vec![viewer_grant],
    };
    let result = verify_group_policy_log(&key.verifying_key().to_bytes(), &log);
    assert!(
        result.is_err(),
        "a record whose role was changed after signing must fail verification -- got {result:?}"
    );
}

/// `parse_action` must fail closed on an out-of-range role value rather
/// than silently defaulting to some role -- a malformed or
/// forward-incompatible record must never be interpreted as granting
/// write access.
#[test]
fn an_out_of_range_role_value_is_rejected() {
    assert!(WriterRole::from_wire(3).is_err());
    assert!(WriterRole::from_wire(u32::MAX).is_err());
    assert_eq!(WriterRole::from_wire(0), Ok(WriterRole::Viewer));
    assert_eq!(WriterRole::from_wire(1), Ok(WriterRole::Editor));
    assert_eq!(WriterRole::from_wire(2), Ok(WriterRole::Owner));
}

// --- Cross-implementation golden-vector tests -----------------------
//
// These pin the EXACT byte layout the coordination service
// service.ts::canonicalSigningBytes` must also produce -- see that
// file's own module doc comment and the coordination service
// policy.test.ts`'s identical assertion. If either side's encoding
// drifts from the other, every Grant record either side signs fails
// `verify_strict` on the other -- the exact incident that motivated
// adding these tests. Update BOTH sides in lockstep, never just one.

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The role-carrying Grant preimage, byte for byte. Must equal
/// the coordination service's "a role-carrying grant
/// produces a distinct, versioned signing-bytes shape" assertion.
///
/// `ACTION_GRANT_WITH_ROLE` is the only Grant shape either side can
/// still produce, so this is the whole cross-implementation contract:
/// if it drifts on one side, every Grant that side signs fails
/// `verify_strict` on the other, every group resolves Withhold, and
/// sync halts in both directions.
#[test]
fn role_carrying_grant_signing_bytes_match_the_cross_implementation_golden_vector() {
    let record = VerifiedPolicyRecord {
        seq: 1,
        prev_record_hash: [0u8; HASH_LEN],
        record_hash: [0u8; HASH_LEN],
        epoch: 0,
        signer_key_id: [0u8; HASH_LEN],
        action: PolicyAction::Grant {
            device_id: "d".to_string(),
            signing_key_fingerprint: [0u8; HASH_LEN],
            role: WriterRole::Editor,
        },
        signature: [0u8; SIGNATURE_LEN],
    };

    let expected = format!(
        "{}{}{}{}{}{}{}{}{}{}",
        "796c706f6c696331", // POLICY_DOMAIN_TAG, b"ylpolic1"
        "0000000167",       // group_id: len=1, "g"
        "0000000000000001", // seq = 1
        "00".repeat(32),    // prev_record_hash
        "0000000000000000", // epoch = 0
        "00".repeat(32),    // signer_key_id
        "03",               // ACTION_GRANT_WITH_ROLE -- never 0x00
        "0000000164",       // device_id: len=1, "d"
        "00".repeat(32),    // signing_key_fingerprint
        "01",               // role = Editor
    );

    assert_eq!(hex(&signing_bytes("g", &record)), expected);
}

fn rotated_chain() -> (GroupPolicyState, SigningKey, [u8; HASH_LEN], [u8; HASH_LEN]) {
    let old_key = service_key();
    let new_key = SigningKey::from_bytes(&[8u8; 32]);
    let grant = grant_record(
        &old_key,
        "group",
        1,
        ZERO_HASH,
        "device-a",
        [9u8; HASH_LEN],
        WriterRole::Editor,
    );
    let grant_hash = hash_of(&grant);
    let rotate =
        rotate_record(&old_key, "group", 2, grant_hash, new_key.verifying_key().to_bytes());
    let rotate_hash = hash_of(&rotate);
    let log = GroupPolicyLog {
        group_id: "group".to_string(),
        current_seq: 2,
        current_epoch: 0,
        policy_head: rotate_hash.to_vec(),
        records: vec![grant, rotate],
    };
    let policy = verify_group_policy_log(&old_key.verifying_key().to_bytes(), &log).unwrap();
    (policy, old_key, grant_hash, rotate_hash)
}

#[test]
fn a_retired_key_does_not_resolve_at_the_empty_chain_point_after_a_rotation() {
    let (policy, old_key, grant_hash, _) = rotated_chain();
    let old_id: [u8; HASH_LEN] = Sha256::digest(old_key.verifying_key().to_bytes()).into();
    assert!(
        policy.resolve_authority_key(&old_id, &ZERO_HASH).is_none(),
        "the retired key must not vouch for a checkpoint pinned at the empty chain"
    );
    // A real pre-rotation point still resolves: checkpoints issued before the rotation stay valid.
    assert!(policy.resolve_authority_key(&old_id, &grant_hash).is_some());
}

#[test]
fn a_checkpoint_policy_point_must_be_on_the_chain_and_name_a_writer_there() {
    let (policy, _, grant_hash, rotate_hash) = rotated_chain();
    let fp = [9u8; HASH_LEN];
    assert!(policy.writer_at_policy_point("device-a", &fp, 1, &grant_hash));
    assert!(policy.writer_at_policy_point("device-a", &fp, 2, &rotate_hash));
    // A head that is not the chain's record at that sequence.
    assert!(!policy.writer_at_policy_point("device-a", &fp, 1, &rotate_hash));
    assert!(!policy.writer_at_policy_point("device-a", &fp, 3, &rotate_hash));
    // A device that held no grant, or another key, at that point.
    assert!(!policy.writer_at_policy_point("device-b", &fp, 1, &grant_hash));
    assert!(!policy.writer_at_policy_point("device-a", &[1u8; HASH_LEN], 1, &grant_hash));
    // The empty chain's point holds no grants and is closed once the authority rotated.
    assert!(!policy.writer_at_policy_point("device-a", &fp, 0, &ZERO_HASH));
}

#[test]
fn a_viewer_or_a_later_revoked_device_is_judged_at_the_pinned_point() {
    let key = service_key();
    let fp = [9u8; HASH_LEN];
    let viewer = grant_record(&key, "group", 1, ZERO_HASH, "viewer", fp, WriterRole::Viewer);
    let h1 = hash_of(&viewer);
    let editor = grant_record(&key, "group", 2, h1, "editor", fp, WriterRole::Editor);
    let h2 = hash_of(&editor);
    let revoke = revoke_record(&key, "group", 3, h2, "editor");
    let h3 = hash_of(&revoke);
    let log = GroupPolicyLog {
        group_id: "group".to_string(),
        current_seq: 3,
        current_epoch: 1,
        policy_head: h3.to_vec(),
        records: vec![viewer, editor, revoke],
    };
    let policy = verify_group_policy_log(&key.verifying_key().to_bytes(), &log).unwrap();
    assert!(!policy.writer_at_policy_point("viewer", &fp, 1, &h1), "a viewer does not write");
    assert!(
        policy.writer_at_policy_point("editor", &fp, 2, &h2),
        "a delta published before the revoke stays admissible"
    );
    assert!(!policy.writer_at_policy_point("editor", &fp, 3, &h3), "revoked at that point");
    // Before any rotation the empty-chain point is valid for its own head only.
    assert!(policy.writer_at_policy_point("anyone", &fp, 0, &ZERO_HASH));
    assert!(!policy.writer_at_policy_point("anyone", &fp, 0, &h1));
}

/// The Writer fallback for a losing head is decided from the verified policy
/// chain alone. Two replicas folding the same chain agree; a replica whose
/// verified chain stops before the revocation answers "not yet", which only
/// delays the fallback; a replica that has seen the revocation answers yes.
#[test]
fn fallback_fork_eligibility_follows_the_verified_policy_point() {
    use yadorilink_replica_domain::native_fork::fallback_may_fork;

    let key = service_key();
    let group_id = "group";
    let a =
        grant_record(&key, group_id, 1, ZERO_HASH, "device-a", [9u8; HASH_LEN], WriterRole::Editor);
    let a_hash = hash_of(&a);
    let b =
        grant_record(&key, group_id, 2, a_hash, "device-b", [7u8; HASH_LEN], WriterRole::Editor);
    let b_hash = hash_of(&b);
    let revoke = revoke_record(&key, group_id, 3, b_hash, "device-a");
    let revoke_hash = hash_of(&revoke);
    let verify = |records: Vec<_>, head: [u8; HASH_LEN], epoch: u64| {
        let log = GroupPolicyLog {
            group_id: group_id.to_string(),
            current_seq: records.len() as u64,
            current_epoch: epoch,
            policy_head: head.to_vec(),
            records,
        };
        verify_group_policy_log(&key.verifying_key().to_bytes(), &log).unwrap()
    };
    let lagging = verify(vec![a.clone(), b.clone()], b_hash, 0);
    let advanced = verify(vec![a.clone(), b.clone(), revoke.clone()], revoke_hash, 1);
    let advanced_again = verify(vec![a, b, revoke], revoke_hash, 1);

    let is_writer = |policy: &GroupPolicyState, device: &str| {
        policy.current_writers().iter().any(|w| w.device_id == device)
    };
    // Same chain, same answer, whoever folds it.
    for seq in 0..=3 {
        assert_eq!(advanced.writers_at(seq), advanced_again.writers_at(seq));
    }
    // The lagging replica's whole history is a prefix of the advanced one's.
    assert_eq!(lagging.current_writers(), advanced.writers_at(2).unwrap());

    // An open author that is still a writer is forked by its own device only.
    assert!(!fallback_may_fork(false, is_writer(&lagging, "device-a")));
    // After the revocation any Writer may; the lagging replica merely waits.
    assert!(fallback_may_fork(false, is_writer(&advanced, "device-a")));
    // A closed author is eligible at every policy point.
    assert!(fallback_may_fork(true, is_writer(&lagging, "device-a")));
    assert!(fallback_may_fork(true, is_writer(&advanced, "device-a")));
    // The signing Writer itself is a writer at both points, so a lagging
    // replica admits its fork delta as an ordinary writer delta.
    assert!(is_writer(&lagging, "device-b") && is_writer(&advanced, "device-b"));
}
