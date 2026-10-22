//! Corruption, and the one rule that governs all of it.
//!
//! > **`present_blocks`, `exists` and `get` must agree.**
//!
//! The failure mode this file exists to prevent is not "a block got
//! damaged" -- bit rot happens, and the content is re-fetchable from any
//! peer that holds it. It is a block that is *permanently present and
//! permanently unreadable*: the index says the device has it, so nothing
//! ever fetches it again, and every read fails forever. That state is
//! unreachable only if every way of discovering damage also retracts the
//! claim.
//!
//! So each case here damages the store a different way and then asserts
//! the same shape: the damage is detected, the claim is retracted, and the
//! content can be acquired again afterwards.

use yadorilink_local_storage::segment_store::testing;
use yadorilink_local_storage::{
    BlockStore, GroupCommitLimits, LocallyHashedBlock, SegmentBlockStore, StorageError,
};

fn limits() -> GroupCommitLimits {
    GroupCommitLimits { segment_target_bytes: 8192, ..GroupCommitLimits::default() }
}

fn block(tag: &str, len: usize) -> LocallyHashedBlock {
    let mut payload = vec![b'-'; len];
    let bytes = tag.as_bytes();
    let take = bytes.len().min(len);
    payload[..take].copy_from_slice(&bytes[..take]);
    LocallyHashedBlock::from_bytes(payload)
}

/// The rule, as an assertion: whatever the store says about a block
/// through one entry point, it must say through the others.
fn assert_presence_is_consistent(store: &SegmentBlockStore, hash: &str) {
    let exists = store.exists(hash).unwrap();
    let present = store.present_blocks(&[hash.to_string()]).unwrap()[0];
    assert_eq!(exists, present, "`exists` and `present_blocks` disagree about {hash}");
    let listed = store.list_by_prefix(&hash[..4]).unwrap().contains(&hash.to_string());
    assert_eq!(exists, listed, "`exists` and `list_by_prefix` disagree about {hash}");
    match store.get(hash) {
        Ok(_) => assert!(exists, "`get` served a block the store says it does not have"),
        Err(StorageError::NotFound(_)) => {
            assert!(!exists, "`get` reported {hash} absent while `exists` said present")
        }
        Err(other) => panic!("unexpected error reading {hash}: {other}"),
    }
}

#[test]
fn a_flipped_payload_bit_is_detected_and_the_claim_retracted() {
    let dir = tempfile::tempdir().unwrap();
    let store = SegmentBlockStore::with_limits_and_verdict(dir.path(), limits(), |_| true).unwrap();
    let damaged = block("bit-rot-victim", 400);
    let neighbour = block("the-block-next-door", 400);
    store.put_durable_batch(&[damaged.clone(), neighbour.clone()]).unwrap();

    testing::flip_one_payload_bit(dir.path(), damaged.hash()).unwrap();

    let error = store.get(damaged.hash()).unwrap_err();
    assert!(
        matches!(error, StorageError::ChecksumMismatch { .. }),
        "damage must be reported as a checksum mismatch, got {error}"
    );

    // The claim is gone, so the layer above will re-acquire it rather than
    // believing forever that this device holds it.
    assert!(!store.exists(damaged.hash()).unwrap());
    assert_presence_is_consistent(&store, damaged.hash());
    // And the block beside it in the same segment is untouched.
    assert_eq!(store.get(neighbour.hash()).unwrap(), neighbour.bytes());

    // Re-acquisition works, and the repaired copy is appended fresh rather
    // than written back over the damaged bytes.
    store.put_durable_batch(std::slice::from_ref(&damaged)).unwrap();
    assert_eq!(store.get(damaged.hash()).unwrap(), damaged.bytes());
    assert!(store.detailed_usage().unwrap().dead_bytes > 0, "the damaged record is now dead space");
    assert!(store.verify_store(true).unwrap().is_consistent());
}

#[test]
fn a_put_over_a_damaged_mapping_repairs_it_instead_of_deduplicating_onto_it() {
    let dir = tempfile::tempdir().unwrap();
    let store = SegmentBlockStore::with_limits_and_verdict(dir.path(), limits(), |_| true).unwrap();
    let damaged = block("dedup-over-damage", 400);
    store.put_durable_batch(std::slice::from_ref(&damaged)).unwrap();

    // The index row stays; the bytes behind it are no longer right.
    testing::flip_one_payload_bit(dir.path(), damaged.hash()).unwrap();

    // A put carrying the correct bytes must not be dropped as a dedup hit.
    let receipts = store.put_durable_batch(std::slice::from_ref(&damaged)).unwrap();
    assert!(!receipts[0].deduplicated, "a damaged mapping is not a dedup hit");
    assert_eq!(store.get(damaged.hash()).unwrap(), damaged.bytes());
    assert!(store.verify_store(true).unwrap().is_consistent());

    // An intact mapping is still a dedup hit.
    let receipts = store.put_durable_batch(std::slice::from_ref(&damaged)).unwrap();
    assert!(receipts[0].deduplicated);
}

#[test]
fn a_put_over_a_mapping_whose_open_segment_vanished_lands_in_a_reachable_segment() {
    let dir = tempfile::tempdir().unwrap();
    let store = SegmentBlockStore::with_limits_and_verdict(dir.path(), limits(), |_| true).unwrap();
    let victim = block("vanished-open-segment", 400);
    store.put_durable_batch(std::slice::from_ref(&victim)).unwrap();

    // The segment the store still holds open is unlinked underneath it.
    for entry in std::fs::read_dir(dir.path().join("segments")).unwrap() {
        std::fs::remove_file(entry.unwrap().path()).unwrap();
    }

    // The batch also carries a brand-new block: it must not land in the vanished file either.
    let fresh = block("new-beside-vanished", 400);
    store.put_durable_batch(&[victim.clone(), fresh.clone()]).unwrap();
    assert_eq!(store.get(victim.hash()).unwrap(), victim.bytes());
    assert_eq!(store.get(fresh.hash()).unwrap(), fresh.bytes());
}

#[test]
fn an_unverified_read_still_catches_a_damaged_payload() {
    // `get_unchecked` skips the SHA-256, which is the expensive half -- it
    // does not skip the record's own checksum. A caller using the fast
    // path must not be handed bytes the store can already tell are wrong.
    let dir = tempfile::tempdir().unwrap();
    let store = SegmentBlockStore::with_limits_and_verdict(dir.path(), limits(), |_| true).unwrap();
    let damaged = block("fast-path-victim", 400);
    store.put_durable_batch(std::slice::from_ref(&damaged)).unwrap();

    testing::flip_one_payload_bit(dir.path(), damaged.hash()).unwrap();

    assert!(
        store.get_unchecked(damaged.hash()).is_err(),
        "an unverified read must still refuse a record whose own checksum fails"
    );
    assert_presence_is_consistent(&store, damaged.hash());
}

#[test]
fn a_wholesale_payload_overwrite_is_detected() {
    let dir = tempfile::tempdir().unwrap();
    let store = SegmentBlockStore::with_limits_and_verdict(dir.path(), limits(), |_| true).unwrap();
    let damaged = block("overwritten", 400);
    store.put_durable_batch(std::slice::from_ref(&damaged)).unwrap();

    testing::corrupt_block_payload(dir.path(), damaged.hash(), &vec![0xFFu8; 400]).unwrap();

    assert!(store.get(damaged.hash()).is_err());
    assert_presence_is_consistent(&store, damaged.hash());
    assert!(!store.exists(damaged.hash()).unwrap());
}

#[test]
fn a_truncated_sealed_segment_drops_exactly_the_mappings_that_no_longer_fit() {
    let dir = tempfile::tempdir().unwrap();
    let blocks: Vec<LocallyHashedBlock> =
        (0..32).map(|i| block(&format!("truncation-victim-{i}"), 200)).collect();
    let (segment_id, keep_bytes) = {
        let store = SegmentBlockStore::with_limits(dir.path(), limits())
            .unwrap()
            .with_volume_verdict(|_| true);
        store.put_durable_batch(&blocks).unwrap();
        store.seal_active_segment().unwrap();
        let segment_id = store.segment_ids().unwrap()[0];
        let (_, durable_end, _) = testing::segment_row(dir.path(), segment_id).unwrap().unwrap();
        drop(store);
        (segment_id, durable_end / 2)
    };

    testing::truncate_segment(dir.path(), segment_id, keep_bytes).unwrap();

    let store = SegmentBlockStore::with_limits_and_verdict(dir.path(), limits(), |_| true).unwrap();
    let report = store.recovery_report();
    assert_eq!(report.damaged_segments, vec![segment_id]);
    assert!(report.dropped_mappings > 0, "the records past the cut must lose their mappings");
    assert!(
        report.dropped_mappings < blocks.len() as u64,
        "the records before the cut must keep theirs -- a partial loss is not a total one"
    );

    let mut survived = 0;
    for b in &blocks {
        assert_presence_is_consistent(&store, b.hash());
        if store.exists(b.hash()).unwrap() {
            assert_eq!(store.get(b.hash()).unwrap(), b.bytes());
            survived += 1;
        }
    }
    assert_eq!(survived, blocks.len() as u64 - report.dropped_mappings);
    assert!(store.verify_store(true).unwrap().is_consistent());

    // Everything lost can be written again.
    store.put_durable_batch(&blocks).unwrap();
    for b in &blocks {
        assert_eq!(store.get(b.hash()).unwrap(), b.bytes());
    }
}

#[test]
fn a_missing_segment_file_drops_its_mappings_instead_of_refusing_to_start() {
    // Fail-closed here means "stop claiming what cannot be served", not
    // "refuse to open". A store that will not start cannot re-fetch
    // anything, which would turn recoverable damage into a dead device.
    let dir = tempfile::tempdir().unwrap();
    let lost: Vec<LocallyHashedBlock> =
        (0..8).map(|i| block(&format!("lost-segment-block-{i}"), 300)).collect();
    let kept: Vec<LocallyHashedBlock> =
        (0..8).map(|i| block(&format!("surviving-segment-block-{i}"), 300)).collect();
    let doomed = {
        let store = SegmentBlockStore::with_limits(dir.path(), limits())
            .unwrap()
            .with_volume_verdict(|_| true);
        store.put_durable_batch(&lost).unwrap();
        store.seal_active_segment().unwrap();
        let doomed = store.segment_ids().unwrap()[0];
        store.put_durable_batch(&kept).unwrap();
        drop(store);
        doomed
    };

    testing::delete_segment(dir.path(), doomed).unwrap();

    let store = SegmentBlockStore::with_limits_and_verdict(dir.path(), limits(), |_| true).unwrap();
    assert_eq!(store.recovery_report().damaged_segments, vec![doomed]);
    assert_eq!(store.recovery_report().dropped_mappings, lost.len() as u64);

    for b in &lost {
        assert!(!store.exists(b.hash()).unwrap(), "a block in a lost segment must not be claimed");
        assert_presence_is_consistent(&store, b.hash());
    }
    for b in &kept {
        assert_eq!(store.get(b.hash()).unwrap(), b.bytes());
    }
    assert!(store.verify_store(true).unwrap().is_consistent());

    store.put_durable_batch(&lost).unwrap();
    for b in &lost {
        assert_eq!(store.get(b.hash()).unwrap(), b.bytes());
    }
}

#[test]
fn a_segment_that_vanishes_under_a_running_store_retracts_its_claims_on_read() {
    let dir = tempfile::tempdir().unwrap();
    let store = SegmentBlockStore::with_limits_and_verdict(dir.path(), limits(), |_| true).unwrap();
    let blocks: Vec<LocallyHashedBlock> =
        (0..4).map(|i| block(&format!("vanishing-{i}"), 300)).collect();
    store.put_durable_batch(&blocks).unwrap();
    let segment_id = store.segment_ids().unwrap()[0];

    testing::delete_segment(dir.path(), segment_id).unwrap();
    // An already-open descriptor keeps serving an unlinked file on Unix --
    // which is exactly the property that makes compaction safe. Dropping
    // the cached handle is what makes this test about a missing file
    // rather than about handle caching.
    store.evict_reader_for_tests(segment_id);

    for b in &blocks {
        assert!(matches!(store.get(b.hash()), Err(StorageError::NotFound(_))));
        assert!(
            !store.exists(b.hash()).unwrap(),
            "a read that could not find the bytes must retract the claim, not merely fail"
        );
        assert_presence_is_consistent(&store, b.hash());
    }
}

#[test]
fn garbage_appended_past_durable_end_is_truncated_rather_than_interpreted() {
    // The "corrupt active tail" case: bytes past `durable_end` that are
    // not a record at all. Recovery must not try to parse them, and must
    // not let them survive to be parsed later.
    let dir = tempfile::tempdir().unwrap();
    let blocks: Vec<LocallyHashedBlock> =
        (0..8).map(|i| block(&format!("before-the-garbage-{i}"), 200)).collect();
    let segment_id = {
        let store = SegmentBlockStore::with_limits(dir.path(), limits())
            .unwrap()
            .with_volume_verdict(|_| true);
        store.put_durable_batch(&blocks).unwrap();
        let id = store.segment_ids().unwrap()[0];
        drop(store);
        id
    };

    testing::append_uncommitted_bytes(dir.path(), segment_id, &vec![0x5Au8; 777]).unwrap();

    let store = SegmentBlockStore::with_limits_and_verdict(dir.path(), limits(), |_| true).unwrap();
    assert_eq!(store.recovery_report().truncated_segments, vec![segment_id]);
    assert_eq!(store.recovery_report().truncated_bytes, 777);
    for b in &blocks {
        assert_eq!(store.get(b.hash()).unwrap(), b.bytes());
    }
    assert!(store.verify_store(true).unwrap().is_consistent());

    // The segment is still the active one and takes further appends.
    let after = store.put(b"appended after the garbage was cut back").unwrap();
    assert_eq!(store.get(&after).unwrap(), b"appended after the garbage was cut back");
    assert!(store.verify_store(true).unwrap().is_consistent());
}

#[test]
fn a_foreign_file_in_the_segments_directory_is_left_alone() {
    // The store removes segment files it can account for. It must not
    // remove anything else: a directory it shares with a stray file is not
    // a licence to delete the stray file.
    let dir = tempfile::tempdir().unwrap();
    let store = SegmentBlockStore::with_limits_and_verdict(dir.path(), limits(), |_| true).unwrap();
    let hash = store.put(b"an ordinary block").unwrap();
    drop(store);

    let stray = dir.path().join("segments").join("not-a-segment.txt");
    std::fs::write(&stray, b"someone else's file").unwrap();

    let store = SegmentBlockStore::with_limits_and_verdict(dir.path(), limits(), |_| true).unwrap();
    assert!(stray.exists(), "a file the store does not recognise must not be deleted");
    assert_eq!(store.get(&hash).unwrap(), b"an ordinary block");
}

#[test]
fn compaction_drops_a_block_it_cannot_read_rather_than_copying_it_forward() {
    let dir = tempfile::tempdir().unwrap();
    let store = SegmentBlockStore::with_limits_and_verdict(dir.path(), limits(), |_| true).unwrap();
    let blocks: Vec<LocallyHashedBlock> =
        (0..16).map(|i| block(&format!("compaction-corruption-{i}"), 200)).collect();
    store.put_durable_batch(&blocks).unwrap();
    store.seal_active_segment().unwrap();
    // Delete most of them so the segment becomes a compaction candidate,
    // and damage one of the survivors.
    for b in blocks.iter().skip(4) {
        store.delete(b.hash()).unwrap();
    }
    testing::flip_one_payload_bit(dir.path(), blocks[0].hash()).unwrap();

    let report = store.compact_with_thresholds(0.5, 1).unwrap();
    assert_eq!(
        report.unreadable_blocks_dropped, 1,
        "a block that does not read back must be dropped, never propagated into a new segment"
    );

    assert!(!store.exists(blocks[0].hash()).unwrap());
    assert_presence_is_consistent(&store, blocks[0].hash());
    for b in &blocks[1..4] {
        assert_eq!(store.get(b.hash()).unwrap(), b.bytes());
    }
    assert!(store.verify_store(true).unwrap().is_consistent());
}

#[test]
fn an_offline_scrub_reports_damage_without_changing_anything() {
    let dir = tempfile::tempdir().unwrap();
    let store = SegmentBlockStore::with_limits_and_verdict(dir.path(), limits(), |_| true).unwrap();
    let blocks: Vec<LocallyHashedBlock> =
        (0..8).map(|i| block(&format!("scrub-{i}"), 300)).collect();
    store.put_durable_batch(&blocks).unwrap();

    let clean = store.verify_store(true).unwrap();
    assert!(clean.is_consistent());
    assert_eq!(clean.records_scanned, 8);
    assert_eq!(clean.unindexed_records, 0);

    testing::flip_one_payload_bit(dir.path(), blocks[3].hash()).unwrap();
    let scrubbed = store.verify_store(true).unwrap();
    assert_eq!(scrubbed.corrupt_records, vec![blocks[3].hash().clone()]);
    assert!(!scrubbed.is_consistent());
    assert!(
        store.exists(blocks[3].hash()).unwrap(),
        "the scrub reports; it is the read path that retracts"
    );

    // A structural-only scrub does not read payloads, so it does not see
    // payload damage -- and must not claim to.
    let structural = store.verify_store(false).unwrap();
    assert!(structural.corrupt_records.is_empty());
    assert!(structural.is_consistent());
}

#[test]
fn dead_records_show_up_as_unindexed_rather_than_as_damage() {
    let dir = tempfile::tempdir().unwrap();
    let store = SegmentBlockStore::with_limits_and_verdict(dir.path(), limits(), |_| true).unwrap();
    let blocks: Vec<LocallyHashedBlock> =
        (0..8).map(|i| block(&format!("dead-space-{i}"), 300)).collect();
    store.put_durable_batch(&blocks).unwrap();
    store.delete(blocks[2].hash()).unwrap();
    store.delete(blocks[5].hash()).unwrap();

    let scrub = store.verify_store(true).unwrap();
    assert!(scrub.is_consistent(), "deleted blocks are dead space, not damage");
    assert_eq!(scrub.unindexed_records, 2);
    assert_eq!(scrub.records_scanned, 8);
}
