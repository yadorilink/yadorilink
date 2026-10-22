//! The crash matrix.
//!
//! The store's central claim is an ordering claim:
//!
//! > **The index never names a block whose bytes are not already durable.**
//!
//! An ordering claim cannot be tested by exercising the happy path -- a
//! store that recovered correctly and a store that never crashed are
//! indistinguishable afterwards. It can only be tested by cutting the
//! commit sequence at each of its boundaries and reopening.
//!
//! Every case here asserts the same three things after the restart:
//!
//! 1. **nothing the store claims is unreadable** -- every mapping in the
//!    index resolves to a record that reads back and hashes to its key;
//! 2. **nothing already committed was lost** -- blocks whose receipts the
//!    caller had in hand before the crash are still there;
//! 3. **the store still works** -- a write after recovery succeeds, so
//!    recovery leaves a usable store rather than a readable corpse.
//!
//! The victim blocks (the group the crash interrupted) are allowed to be
//! absent or present depending on where the cut fell, and each case says
//! which it must be. What is never allowed is *present but broken*.

use yadorilink_local_storage::segment_store::testing;
use yadorilink_local_storage::{
    hash_block_bytes, BlockStore, CommitPoint, FaultPlan, GroupCommitLimits, LocallyHashedBlock,
    SegmentBlockStore, StorageError,
};

/// Small on purpose: a 4 KiB segment target makes roll-over reachable with
/// a handful of 600-byte blocks, so the roll-over boundary is exercised by
/// the same harness as every other one.
/// Removes `path` if it exists. On Windows a just-closed SQLite file can
/// stay briefly locked by the OS (scanner/indexer), so a failure is retried
/// for a bounded time rather than silently leaving the file behind (which
/// would make the test open an intact store instead of a missing-index one).
fn remove_file_if_present(path: &std::path::Path) {
    let mut last = None;
    for _ in 0..100 {
        match std::fs::remove_file(path) {
            Ok(()) => return,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return,
            Err(e) => {
                last = Some(e);
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
        }
    }
    panic!("could not remove {}: {:?}", path.display(), last);
}

fn limits() -> GroupCommitLimits {
    GroupCommitLimits { segment_target_bytes: 4096, ..GroupCommitLimits::default() }
}

fn block(tag: &str, len: usize) -> LocallyHashedBlock {
    let mut payload = vec![b'.'; len];
    let bytes = tag.as_bytes();
    let take = bytes.len().min(len);
    payload[..take].copy_from_slice(&bytes[..take]);
    LocallyHashedBlock::from_bytes(payload)
}

/// Claim 1, in full: every mapping the index holds resolves to bytes that
/// read back and hash to their own key.
fn assert_index_names_only_readable_blocks(store: &SegmentBlockStore) {
    let verification = store.verify_store(true).unwrap();
    assert!(
        verification.unbacked_mappings.is_empty(),
        "the index names {} block(s) with no record behind them: {:?}",
        verification.unbacked_mappings.len(),
        verification.unbacked_mappings
    );
    assert!(
        verification.corrupt_records.is_empty(),
        "the index names {} block(s) whose bytes do not hash to their key: {:?}",
        verification.corrupt_records.len(),
        verification.corrupt_records
    );
    assert!(
        verification.segments_with_incomplete_tail.is_empty(),
        "a segment's durable range runs past its last complete record: {:?}",
        verification.segments_with_incomplete_tail
    );

    // Independently of the scrub, go through the ordinary read path: a
    // store that verifies but cannot serve is still a store that lies.
    for hash in store.list_by_prefix("").unwrap() {
        let bytes =
            store.get(&hash).unwrap_or_else(|e| panic!("indexed block {hash} is unreadable: {e}"));
        assert_eq!(hash_block_bytes(&bytes), hash, "indexed block {hash} hashes to something else");
    }
}

/// Whether the interrupted group's blocks must be present after recovery.
///
/// Only one boundary is past the point of no return: the index
/// transaction has committed, so the blocks are durable whether or not the
/// caller ever learned it. Everywhere earlier, the group must have left
/// nothing behind.
fn victim_must_be_present(point: CommitPoint) -> bool {
    matches!(point, CommitPoint::AfterIndexCommitBeforeReceipt)
}

/// Whether reaching `point` requires the group to create a segment.
fn needs_a_fresh_segment(point: CommitPoint) -> bool {
    matches!(point, CommitPoint::AfterSegmentStaged | CommitPoint::AfterSegmentPublished)
}

fn crash_scenario(point: CommitPoint) {
    let dir = tempfile::tempdir().unwrap();
    let baseline: Vec<LocallyHashedBlock> =
        (0..8).map(|i| block(&format!("baseline-{i}"), 600)).collect();
    // Enough blocks, at this size, that laying them out crosses the 4 KiB
    // segment target -- which is what makes the roll-over boundary
    // reachable.
    let victim: Vec<LocallyHashedBlock> =
        (0..8).map(|i| block(&format!("victim-{i}"), 600)).collect();

    {
        let store = SegmentBlockStore::with_limits(dir.path(), limits())
            .unwrap()
            .with_volume_verdict(|_| true);
        store.put_durable_batch(&baseline).unwrap();
        for committed in &baseline {
            assert!(store.exists(committed.hash()).unwrap());
        }
        if needs_a_fresh_segment(point) {
            // Close the segment the baseline went into, so the faulted
            // group has to create one and the create-related boundaries
            // are actually reached.
            store.seal_active_segment().unwrap();
        }

        store.arm_commit_fault_for_tests(FaultPlan::crash_at(point));
        let outcome = store.put_durable_batch(&victim);
        assert!(outcome.is_err(), "the armed crash at {point:?} did not fail the commit");
        assert!(
            store.is_halted_for_tests(),
            "a crash must halt the store at {point:?}; a dead process does not keep serving"
        );
        assert!(
            store.put(b"a write after the process is gone").is_err(),
            "a halted store must refuse further writes"
        );
        // Dropped without any graceful shutdown -- nothing here flushes,
        // truncates, or tidies up, which is the point.
        drop(store);
    }

    let store = SegmentBlockStore::with_limits_and_verdict(dir.path(), limits(), |_| true).unwrap();

    // Claim 2: everything the caller was told was durable, still is.
    for committed in &baseline {
        assert_eq!(
            store.get(committed.hash()).unwrap(),
            committed.bytes(),
            "a block committed before the {point:?} crash was lost"
        );
    }

    // The interrupted group is all-or-nothing, and which it is depends on
    // whether its transaction committed.
    let expected = victim_must_be_present(point);
    for interrupted in &victim {
        let present = store.exists(interrupted.hash()).unwrap();
        assert_eq!(
            present,
            expected,
            "after a crash at {point:?} the interrupted group must be {} -- an index \
             transaction is atomic, so a partially-visible group means the group was not \
             committed as one",
            if expected { "entirely present" } else { "entirely absent" }
        );
        if present {
            assert_eq!(store.get(interrupted.hash()).unwrap(), interrupted.bytes());
        }
    }

    // Claim 1.
    assert_index_names_only_readable_blocks(&store);

    // Claim 3.
    let after = store.put(b"written after recovery").unwrap();
    assert_eq!(store.get(&after).unwrap(), b"written after recovery");
    for committed in &baseline {
        assert_eq!(store.get(committed.hash()).unwrap(), committed.bytes());
    }
}

#[test]
fn no_commit_boundary_leaves_the_index_naming_a_block_that_is_not_durable() {
    for point in CommitPoint::ALL {
        crash_scenario(point);
    }
}

#[test]
fn crashing_mid_record_leaves_a_tail_recovery_truncates() {
    // The specific shape `MidRecordAppend` produces: the file is longer
    // than any committed transaction accounts for, and the extra bytes are
    // half a record. Recovery must cut them back rather than try to
    // interpret them, and must say it did.
    let dir = tempfile::tempdir().unwrap();
    let baseline = block("baseline", 400);
    let victim: Vec<LocallyHashedBlock> =
        (0..4).map(|i| block(&format!("half-written-{i}"), 400)).collect();

    let (segment_id, durable_end) = {
        let store = SegmentBlockStore::with_limits(dir.path(), limits())
            .unwrap()
            .with_volume_verdict(|_| true);
        store.put_durable_batch(std::slice::from_ref(&baseline)).unwrap();
        let segment_id = store.segment_ids().unwrap()[0];
        let (_, durable_end, _) = testing::segment_row(dir.path(), segment_id).unwrap().unwrap();

        store.arm_commit_fault_for_tests(
            FaultPlan::crash_at(CommitPoint::MidRecordAppend).with_partial_append_bytes(700),
        );
        assert!(store.put_durable_batch(&victim).is_err());
        drop(store);
        (segment_id, durable_end)
    };

    let on_disk =
        std::fs::metadata(dir.path().join("segments").join(format!("{segment_id:016}.seg")))
            .unwrap()
            .len();
    assert!(
        on_disk > durable_end,
        "the half-written record should still be on disk before recovery runs"
    );

    let store = SegmentBlockStore::with_limits_and_verdict(dir.path(), limits(), |_| true).unwrap();
    assert_eq!(
        store.recovery_report().truncated_segments,
        vec![segment_id],
        "recovery must report the truncation rather than doing it silently"
    );
    assert_eq!(store.recovery_report().truncated_bytes, on_disk - durable_end);
    let (_, recovered_end, _) = testing::segment_row(dir.path(), segment_id).unwrap().unwrap();
    assert_eq!(recovered_end, durable_end);
    assert_eq!(store.get(baseline.hash()).unwrap(), baseline.bytes());
    for interrupted in &victim {
        assert!(!store.exists(interrupted.hash()).unwrap());
    }
    assert_index_names_only_readable_blocks(&store);
}

#[test]
fn a_segment_created_by_an_uncommitted_group_is_removed_on_the_next_open() {
    let dir = tempfile::tempdir().unwrap();
    let baseline = block("baseline", 300);
    {
        let store = SegmentBlockStore::with_limits(dir.path(), limits())
            .unwrap()
            .with_volume_verdict(|_| true);
        store.put_durable_batch(std::slice::from_ref(&baseline)).unwrap();
        store.seal_active_segment().unwrap();
        store.arm_commit_fault_for_tests(FaultPlan::crash_at(CommitPoint::AfterFsyncBeforeIndex));
        assert!(store.put(b"in a segment whose transaction never lands").is_err());
        drop(store);
    }

    let on_disk_before = testing::segment_ids_on_disk(dir.path()).unwrap();
    assert_eq!(on_disk_before.len(), 2, "the orphaned segment file should still be there");

    let store = SegmentBlockStore::with_limits_and_verdict(dir.path(), limits(), |_| true).unwrap();
    assert_eq!(
        store.recovery_report().removed_orphan_segments.len(),
        1,
        "a segment no committed transaction mentions has nothing referencing it and must go"
    );
    assert_eq!(testing::segment_ids_on_disk(dir.path()).unwrap().len(), 1);
    assert_eq!(store.get(baseline.hash()).unwrap(), baseline.bytes());
    assert_index_names_only_readable_blocks(&store);
}

#[test]
fn durable_bytes_whose_transaction_never_committed_are_never_served() {
    // The subtle one. `AfterFsyncBeforeIndex` is the window where the
    // bytes really are on the platter and the index has never heard of
    // them. A store that rebuilt its index by scanning segments would
    // resurrect this group; this one must not.
    let dir = tempfile::tempdir().unwrap();
    let victim: Vec<LocallyHashedBlock> =
        (0..4).map(|i| block(&format!("fsynced-but-uncommitted-{i}"), 300)).collect();
    {
        let store = SegmentBlockStore::with_limits(dir.path(), limits())
            .unwrap()
            .with_volume_verdict(|_| true);
        store.put(b"something committed first").unwrap();
        store.arm_commit_fault_for_tests(FaultPlan::crash_at(CommitPoint::AfterFsyncBeforeIndex));
        assert!(store.put_durable_batch(&victim).is_err());
        drop(store);
    }

    let store = SegmentBlockStore::with_limits_and_verdict(dir.path(), limits(), |_| true).unwrap();
    for interrupted in &victim {
        assert!(
            !store.exists(interrupted.hash()).unwrap(),
            "bytes that reached the platter but whose transaction never committed must not \
             be served: durability is what the index says, not what the disk happens to hold"
        );
        assert!(matches!(store.get(interrupted.hash()), Err(StorageError::NotFound(_))));
    }
    assert_index_names_only_readable_blocks(&store);
}

#[test]
fn a_crash_inside_the_index_transaction_rolls_the_whole_group_back() {
    let dir = tempfile::tempdir().unwrap();
    let victim: Vec<LocallyHashedBlock> =
        (0..16).map(|i| block(&format!("rolled-back-{i}"), 200)).collect();
    {
        let store = SegmentBlockStore::with_limits(dir.path(), limits())
            .unwrap()
            .with_volume_verdict(|_| true);
        store.arm_commit_fault_for_tests(FaultPlan::crash_at(CommitPoint::DuringIndexTransaction));
        assert!(store.put_durable_batch(&victim).is_err());
        drop(store);
    }

    let store = SegmentBlockStore::with_limits_and_verdict(dir.path(), limits(), |_| true).unwrap();
    assert!(
        testing::indexed_hashes(dir.path()).unwrap().is_empty(),
        "an aborted transaction must leave no row at all, not the rows it had staged"
    );
    for interrupted in &victim {
        assert!(!store.exists(interrupted.hash()).unwrap());
    }
    assert_index_names_only_readable_blocks(&store);
}

// ---------------------------------------------------------------------
// Survivable failures: the process lives, so the store has to stay both
// correct and usable -- which is a stronger requirement than crashing.
// ---------------------------------------------------------------------

fn io_failure_scenario(point: CommitPoint) {
    let dir = tempfile::tempdir().unwrap();
    let store = SegmentBlockStore::with_limits_and_verdict(dir.path(), limits(), |_| true).unwrap();
    let baseline = block("baseline", 300);
    store.put_durable_batch(std::slice::from_ref(&baseline)).unwrap();
    if needs_a_fresh_segment(point) {
        store.seal_active_segment().unwrap();
    }

    let victim: Vec<LocallyHashedBlock> =
        (0..8).map(|i| block(&format!("failed-{point:?}-{i}"), 600)).collect();
    store.arm_commit_fault_for_tests(FaultPlan::io_failure_at(point));
    let outcome = store.put_durable_batch(&victim);
    assert!(outcome.is_err(), "an injected I/O failure at {point:?} must fail the commit");
    assert!(
        !store.is_halted_for_tests(),
        "a survivable I/O failure must not halt the store at {point:?}"
    );
    store.clear_commit_fault_for_tests();

    // Fail-closed: nothing the failed commit touched is claimed, except
    // where the transaction genuinely committed before the failure.
    let expected = victim_must_be_present(point);
    for interrupted in &victim {
        assert_eq!(
            store.exists(interrupted.hash()).unwrap(),
            expected,
            "a failed commit at {point:?} left an inconsistent claim"
        );
    }
    assert_eq!(store.get(baseline.hash()).unwrap(), baseline.bytes());
    assert_index_names_only_readable_blocks(&store);

    // Usable afterwards, with no restart: the retry of the very batch that
    // failed must succeed and be readable.
    store.put_durable_batch(&victim).unwrap();
    for retried in &victim {
        assert_eq!(store.get(retried.hash()).unwrap(), retried.bytes());
    }
    assert_index_names_only_readable_blocks(&store);

    // And it all still holds across a restart.
    drop(store);
    let store = SegmentBlockStore::with_limits_and_verdict(dir.path(), limits(), |_| true).unwrap();
    for retried in &victim {
        assert_eq!(store.get(retried.hash()).unwrap(), retried.bytes());
    }
    assert_index_names_only_readable_blocks(&store);
}

#[test]
fn every_boundary_fails_closed_and_leaves_the_store_usable() {
    for point in CommitPoint::ALL {
        io_failure_scenario(point);
    }
}

#[test]
fn a_survivable_failure_after_the_append_leaves_no_orphan_tail() {
    // A crash may leave bytes past `durable_end` -- truncating them is
    // recovery's job precisely because a dead process cannot. A process
    // that survives has no such excuse: the group's bytes must be gone by
    // the time the failure is reported, without waiting for a restart.
    //
    // This is what an earlier version got wrong. The writer's open segment
    // was taken out of the writer state to lay the group out and, on the
    // error paths, never handed back -- so the rollback found nothing to
    // truncate, the next group quietly started a different segment, and
    // the abandoned one kept an orphan tail and an "active" row until the
    // next open.
    let dir = tempfile::tempdir().unwrap();
    let store = SegmentBlockStore::with_limits_and_verdict(dir.path(), limits(), |_| true).unwrap();
    store.put(b"a committed block the segment starts with").unwrap();
    let segment_id = store.segment_ids().unwrap()[0];
    let (_, durable_end, _) = testing::segment_row(dir.path(), segment_id).unwrap().unwrap();
    let on_disk = |id: u64| {
        std::fs::metadata(dir.path().join("segments").join(format!("{id:016}.seg"))).unwrap().len()
    };
    assert_eq!(on_disk(segment_id), durable_end);

    let victim: Vec<LocallyHashedBlock> =
        (0..8).map(|i| block(&format!("rolled-back-{i}"), 500)).collect();
    store.arm_commit_fault_for_tests(FaultPlan::io_failure_at(CommitPoint::AfterFsyncBeforeIndex));
    assert!(store.put_durable_batch(&victim).is_err());
    store.clear_commit_fault_for_tests();

    assert_eq!(
        on_disk(segment_id),
        durable_end,
        "the failed group's bytes must be gone already, not left for the next open"
    );
    assert_eq!(
        store.segment_ids().unwrap(),
        vec![segment_id],
        "a failed group must not strand its segment and start a new one"
    );
    assert_index_names_only_readable_blocks(&store);

    // And the very batch that failed commits cleanly on a retry. It rolls
    // over on the way (eight 552-byte records do not fit the 4 KiB target
    // this test uses), which is the point of using a group that spans two
    // segments: the rollback above had to undo both.
    store.put_durable_batch(&victim).unwrap();
    let after_retry = store.segment_ids().unwrap();
    assert!(after_retry.starts_with(&[segment_id]), "got {after_retry:?}");
    assert!(after_retry.len() > 1, "the retried group should have rolled over: {after_retry:?}");
    for block in &victim {
        assert_eq!(store.get(block.hash()).unwrap(), block.bytes());
    }
    assert_index_names_only_readable_blocks(&store);
}

#[test]
fn a_headroom_rejection_writes_nothing_at_all() {
    // The ENOSPC shape the store checks for itself, rather than one
    // injected underneath it: the preflight runs before any byte is laid
    // out, so a rejected batch must not move the physical size by one
    // byte.
    let dir = tempfile::tempdir().unwrap();
    let store = SegmentBlockStore::with_limits_and_verdict(dir.path(), limits(), |_| true).unwrap();
    let existing = store.put(b"written while there was room").unwrap();
    let before = store.detailed_usage().unwrap();

    store.set_headroom_override_bytes(Some(u64::MAX / 2));
    store.set_headroom_enforced(true);

    let rejected: Vec<LocallyHashedBlock> =
        (0..4).map(|i| block(&format!("no-room-{i}"), 400)).collect();
    assert!(matches!(store.put_durable_batch(&rejected), Err(StorageError::DiskPressure { .. })));

    assert_eq!(
        store.detailed_usage().unwrap(),
        before,
        "a headroom rejection happens before any layout or append; nothing may change"
    );
    for block in &rejected {
        assert!(!store.exists(block.hash()).unwrap());
    }
    assert_eq!(store.get(&existing).unwrap(), b"written while there was room");

    // Releasing the pressure makes the same batch succeed.
    store.set_headroom_enforced(false);
    store.put_durable_batch(&rejected).unwrap();
    for block in &rejected {
        assert_eq!(store.get(block.hash()).unwrap(), block.bytes());
    }
    assert_index_names_only_readable_blocks(&store);
}

// ---------------------------------------------------------------------
// Compaction. The same ordering, applied to bytes that already exist: at
// every cut, at least one valid copy is reachable from the index.
// ---------------------------------------------------------------------

/// Builds a store with one sealed, mostly-dead segment ready to compact,
/// and returns the blocks that must survive it.
fn store_with_a_compactable_segment(
    dir: &std::path::Path,
) -> (SegmentBlockStore, Vec<LocallyHashedBlock>) {
    let store = SegmentBlockStore::with_limits_and_verdict(dir, limits(), |_| true).unwrap();
    let blocks: Vec<LocallyHashedBlock> =
        (0..32).map(|i| block(&format!("compaction-source-{i}"), 200)).collect();
    store.put_durable_batch(&blocks).unwrap();
    store.seal_active_segment().unwrap();
    let mut survivors = Vec::new();
    for (i, b) in blocks.iter().enumerate() {
        if i % 4 == 0 {
            survivors.push(b.clone());
        } else {
            store.delete(b.hash()).unwrap();
        }
    }
    (store, survivors)
}

fn compaction_crash_scenario(point: CommitPoint) {
    let dir = tempfile::tempdir().unwrap();
    let survivors = {
        let (store, survivors) = store_with_a_compactable_segment(dir.path());
        store.arm_commit_fault_for_tests(FaultPlan::crash_at(point));
        let outcome = store.compact_with_thresholds(0.5, 1);
        assert!(outcome.is_err(), "the armed crash at {point:?} did not fail the compaction");
        drop(store);
        survivors
    };

    let store = SegmentBlockStore::with_limits_and_verdict(dir.path(), limits(), |_| true).unwrap();
    for survivor in &survivors {
        assert_eq!(
            store.get(survivor.hash()).unwrap(),
            survivor.bytes(),
            "a crash at {point:?} during compaction lost a live block -- at every cut, at \
             least one valid copy must stay reachable from the index"
        );
    }
    assert_index_names_only_readable_blocks(&store);

    // The compaction can simply be run again.
    store.compact_with_thresholds(0.5, 1).unwrap();
    for survivor in &survivors {
        assert_eq!(store.get(survivor.hash()).unwrap(), survivor.bytes());
    }
    assert_index_names_only_readable_blocks(&store);
}

#[test]
fn a_crash_at_any_point_in_a_compaction_keeps_every_live_block_reachable() {
    for point in [
        CommitPoint::AfterAppendBeforeFsync,
        CommitPoint::AfterFsyncBeforeIndex,
        CommitPoint::DuringIndexTransaction,
    ] {
        compaction_crash_scenario(point);
    }
}

/// Opening runs recovery, which unlinks retired segments and cuts torn tails. On a volume that is
/// not known durable that is a byte deletion like any other: the open is refused and nothing on
/// disk changes.
#[test]
fn opening_a_store_on_a_refused_volume_deletes_and_truncates_nothing() {
    let dir = tempfile::tempdir().unwrap();
    {
        let (store, _) = store_with_a_compactable_segment(dir.path());
        store.compact_without_reclaim_for_tests(0.5, 1).unwrap();
        assert!(store.detailed_usage().unwrap().retired_segments > 0);
    }
    let files_before = testing::segment_ids_on_disk(dir.path()).unwrap();

    let refused = SegmentBlockStore::with_limits_and_verdict(dir.path(), limits(), |_| false);

    assert!(matches!(refused, Err(StorageError::DeletionRefused(_))), "the open must be refused");
    assert_eq!(testing::segment_ids_on_disk(dir.path()).unwrap(), files_before);

    // Where the volume is durable the same open recovers as before.
    let store = SegmentBlockStore::with_limits_and_verdict(dir.path(), limits(), |_| true).unwrap();
    assert!(!store.recovery_report().reclaimed_segments.is_empty());
}

/// The reclaim's verdict is taken where it unlinks, not from an earlier look at the index: a
/// retired segment is never deleted on a volume that is not known durable, and a reclaim that
/// finds nothing retired asks nothing.
#[test]
fn reclaiming_retired_segments_asks_the_verdict_at_each_unlink() {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::Arc;

    let dir = tempfile::tempdir().unwrap();
    let asked = Arc::new(AtomicUsize::new(0));
    let durable = Arc::new(AtomicBool::new(false));
    let store = {
        let (store, _) = store_with_a_compactable_segment(dir.path());
        drop(store);
        let (asked, durable) = (asked.clone(), durable.clone());
        SegmentBlockStore::with_limits_and_verdict(dir.path(), limits(), move |_| {
            asked.fetch_add(1, Ordering::SeqCst);
            durable.load(Ordering::SeqCst)
        })
        .unwrap()
    };
    assert_eq!(store.reclaim_retired().unwrap(), 0, "nothing retired yet");
    assert_eq!(asked.load(Ordering::SeqCst), 0, "nothing to delete, nothing to ask");

    durable.store(true, Ordering::SeqCst);
    store.compact_without_reclaim_for_tests(0.5, 1).unwrap();
    assert!(store.detailed_usage().unwrap().retired_segments > 0);
    let files = testing::segment_ids_on_disk(dir.path()).unwrap();
    durable.store(false, Ordering::SeqCst);

    assert!(matches!(store.reclaim_retired(), Err(StorageError::DeletionRefused(_))));
    assert_eq!(testing::segment_ids_on_disk(dir.path()).unwrap(), files);

    durable.store(true, Ordering::SeqCst);
    assert!(store.reclaim_retired().unwrap() > 0);
}

#[test]
fn a_crash_between_the_mapping_swap_and_the_old_files_deletion_is_finished_by_recovery() {
    let dir = tempfile::tempdir().unwrap();
    let survivors = {
        let (store, survivors) = store_with_a_compactable_segment(dir.path());
        // Swap the mappings, then stop -- exactly the window where both
        // copies exist on disk and the index points at the new one.
        let report = store.compact_without_reclaim_for_tests(0.5, 1).unwrap();
        assert!(report.segments_compacted > 0);
        assert!(
            store.detailed_usage().unwrap().retired_segments > 0,
            "the source segment should be retired but not yet deleted"
        );
        for survivor in &survivors {
            assert_eq!(store.get(survivor.hash()).unwrap(), survivor.bytes());
        }
        drop(store);
        survivors
    };

    let segments_before = testing::segment_ids_on_disk(dir.path()).unwrap().len();
    let store = SegmentBlockStore::with_limits_and_verdict(dir.path(), limits(), |_| true).unwrap();
    assert!(
        !store.recovery_report().reclaimed_segments.is_empty(),
        "recovery must delete a segment the index already retired"
    );
    assert!(testing::segment_ids_on_disk(dir.path()).unwrap().len() < segments_before);
    assert_eq!(store.detailed_usage().unwrap().retired_segments, 0);
    for survivor in &survivors {
        assert_eq!(store.get(survivor.hash()).unwrap(), survivor.bytes());
    }
    assert_index_names_only_readable_blocks(&store);
}

/// Losing only the index must not look like "every segment is an orphan":
/// the segment files still hold the only copy of the bytes, so opening has
/// to refuse and leave them alone rather than delete them.
#[test]
fn a_missing_index_beside_surviving_segments_fails_closed_and_keeps_them() {
    let dir = tempfile::tempdir().unwrap();
    let kept = block("kept", 300);
    {
        let store = SegmentBlockStore::with_limits(dir.path(), limits())
            .unwrap()
            .with_volume_verdict(|_| true);
        store.put_durable_batch(std::slice::from_ref(&kept)).unwrap();
    }
    assert!(SegmentBlockStore::holds_segment_data(dir.path()).unwrap());
    let segments_before = testing::segment_ids_on_disk(dir.path()).unwrap();
    assert!(!segments_before.is_empty());

    for entry in ["index.sqlite3", "index.sqlite3-wal", "index.sqlite3-shm"] {
        remove_file_if_present(&dir.path().join(entry));
    }

    match SegmentBlockStore::with_limits(dir.path(), limits()) {
        Err(StorageError::CorruptStore(_)) => {}
        Err(other) => panic!("expected a fail-closed CorruptStore error, got {other}"),
        Ok(_) => panic!("a store with segments but no index must not open as a fresh one"),
    }
    assert_eq!(
        testing::segment_ids_on_disk(dir.path()).unwrap(),
        segments_before,
        "the surviving segment files must be untouched"
    );
}

/// A store with no data in it is not "holding" anything, whatever files
/// opening it created.
#[test]
fn an_empty_store_holds_no_segment_data() {
    let dir = tempfile::tempdir().unwrap();
    assert!(!SegmentBlockStore::holds_segment_data(dir.path()).unwrap());
    drop(SegmentBlockStore::with_limits(dir.path(), limits()).unwrap());
    assert!(!SegmentBlockStore::holds_segment_data(dir.path()).unwrap());
}

#[test]
fn a_segment_still_under_its_stage_name_is_removed_on_the_next_open_and_its_id_is_not_reused() {
    let dir = tempfile::tempdir().unwrap();
    let baseline = block("baseline", 300);
    let committed_ids = {
        let store = SegmentBlockStore::with_limits(dir.path(), limits())
            .unwrap()
            .with_volume_verdict(|_| true);
        store.put_durable_batch(std::slice::from_ref(&baseline)).unwrap();
        store.seal_active_segment().unwrap();
        let committed = testing::segment_ids_on_disk(dir.path()).unwrap();
        store.arm_commit_fault_for_tests(FaultPlan::crash_at(CommitPoint::AfterSegmentStaged));
        assert!(store.put(b"in a segment that is never published").is_err());
        drop(store);
        committed
    };
    let leftovers = |dir: &std::path::Path| -> Vec<String> {
        std::fs::read_dir(dir.join("segments"))
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|n| n.starts_with(".yadorilink-v1-stage."))
            .collect()
    };
    // Where the volume offers durable moves the segment is waiting under a reserved
    // name; elsewhere it was created in place and the ordinary orphan rule applies.
    let staged = leftovers(dir.path());

    let store = SegmentBlockStore::with_limits_and_verdict(dir.path(), limits(), |_| true).unwrap();

    assert!(leftovers(dir.path()).is_empty(), "{staged:?} was left");
    assert_eq!(testing::segment_ids_on_disk(dir.path()).unwrap(), committed_ids);
    assert_eq!(store.get(baseline.hash()).unwrap(), baseline.bytes());
    let after = store.put(b"written after recovery").unwrap();
    assert_eq!(store.get(&after).unwrap(), b"written after recovery");
    for id in store.segment_ids().unwrap() {
        assert!(!staged.iter().any(|n| n.ends_with(&format!("seg-{id:016}"))), "id {id} reused");
    }
    assert_index_names_only_readable_blocks(&store);
}

// ---------------------------------------------------------------------
// Rollback authority: bytes are deleted only on proof the failed batch
// created them. An index read failure is uncertainty, never absence.
// ---------------------------------------------------------------------

fn segment_files(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut files: Vec<_> = std::fs::read_dir(dir.join("segments"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "seg"))
        .collect();
    files.sort();
    files
}

fn segment_file(dir: &std::path::Path, id: u64) -> std::path::PathBuf {
    dir.join("segments").join(format!("{id:016}.seg"))
}

#[test]
fn an_index_read_failure_during_rollback_never_deletes_committed_bytes() {
    let dir = tempfile::tempdir().unwrap();
    let store = SegmentBlockStore::with_limits_and_verdict(dir.path(), limits(), |_| true).unwrap();
    let committed = block("committed-before-the-failure", 300);
    store.put_durable_batch(std::slice::from_ref(&committed)).unwrap();
    let segment_id = store.segment_ids().unwrap()[0];

    // One small block: the failed batch continues the committed segment.
    let victim = block("failed-append", 200);
    store.arm_commit_fault_for_tests(
        FaultPlan::io_failure_at(CommitPoint::AfterFsyncBeforeIndex)
            .with_rollback_index_read_failure(),
    );
    assert!(store.put_durable_batch(std::slice::from_ref(&victim)).is_err());
    store.clear_commit_fault_for_tests();

    assert!(
        segment_file(dir.path(), segment_id).exists(),
        "a committed segment must survive an index read failure during rollback"
    );
    drop(store);

    let store = SegmentBlockStore::with_limits_and_verdict(dir.path(), limits(), |_| true).unwrap();
    assert_eq!(store.get(committed.hash()).unwrap(), committed.bytes());
    assert!(!store.exists(victim.hash()).unwrap());
    assert_index_names_only_readable_blocks(&store);
}

#[test]
fn a_rollback_with_a_readable_index_removes_only_the_segment_it_created() {
    let dir = tempfile::tempdir().unwrap();
    let store = SegmentBlockStore::with_limits_and_verdict(dir.path(), limits(), |_| true).unwrap();
    store.put_durable_batch(&[block("baseline", 300)]).unwrap();
    store.seal_active_segment().unwrap();
    let before = store.segment_ids().unwrap();
    let files_before = segment_files(dir.path());

    let victim = block("fresh-segment-victim", 200);
    store.arm_commit_fault_for_tests(FaultPlan::io_failure_at(CommitPoint::AfterFsyncBeforeIndex));
    assert!(store.put_durable_batch(std::slice::from_ref(&victim)).is_err());
    store.clear_commit_fault_for_tests();

    assert_eq!(store.segment_ids().unwrap(), before);
    assert_eq!(
        segment_files(dir.path()),
        files_before,
        "the segment the failed batch created must be removed by rollback itself"
    );
    drop(store);
    let store = SegmentBlockStore::with_limits_and_verdict(dir.path(), limits(), |_| true).unwrap();
    assert!(!store.exists(victim.hash()).unwrap());
    assert_index_names_only_readable_blocks(&store);
}

#[test]
fn an_index_read_failure_on_a_freshly_created_segment_preserves_it_and_reopens_clean() {
    let dir = tempfile::tempdir().unwrap();
    let store = SegmentBlockStore::with_limits_and_verdict(dir.path(), limits(), |_| true).unwrap();
    let baseline = block("baseline", 300);
    store.put_durable_batch(std::slice::from_ref(&baseline)).unwrap();
    store.seal_active_segment().unwrap();
    let files_before = segment_files(dir.path());

    let victim = block("fresh-segment-victim", 200);
    store.arm_commit_fault_for_tests(
        FaultPlan::io_failure_at(CommitPoint::AfterFsyncBeforeIndex)
            .with_rollback_index_read_failure(),
    );
    assert!(store.put_durable_batch(std::slice::from_ref(&victim)).is_err());
    store.clear_commit_fault_for_tests();
    assert!(
        segment_files(dir.path()).len() > files_before.len(),
        "an unproven segment must be preserved by rollback, not deleted"
    );
    drop(store);

    let store = SegmentBlockStore::with_limits_and_verdict(dir.path(), limits(), |_| true).unwrap();
    assert_eq!(store.get(baseline.hash()).unwrap(), baseline.bytes());
    assert!(!store.exists(victim.hash()).unwrap());
    assert_index_names_only_readable_blocks(&store);
    store.put_durable_batch(std::slice::from_ref(&victim)).unwrap();
}

fn verdict_flag(
    flag: &std::sync::Arc<std::sync::atomic::AtomicBool>,
) -> impl Fn(Option<&std::path::Path>) -> bool + Send + Sync + 'static {
    let flag = std::sync::Arc::clone(flag);
    move |_| flag.load(std::sync::atomic::Ordering::SeqCst)
}

#[test]
fn a_rollback_on_a_volume_without_a_verdict_neither_truncates_nor_unlinks() {
    use std::sync::atomic::{AtomicBool, Ordering};
    let dir = tempfile::tempdir().unwrap();
    let flag = std::sync::Arc::new(AtomicBool::new(true));
    let store =
        SegmentBlockStore::with_limits_and_verdict(dir.path(), limits(), verdict_flag(&flag))
            .unwrap();
    let committed = block("committed", 300);
    store.put_durable_batch(std::slice::from_ref(&committed)).unwrap();
    let continued = store.segment_ids().unwrap()[0];
    let (_, durable_end, _) = testing::segment_row(dir.path(), continued).unwrap().unwrap();

    // Case 1: the failed batch continues a committed segment (rollback would truncate).
    flag.store(false, Ordering::SeqCst);
    let victim = block("continues-committed", 200);
    store.arm_commit_fault_for_tests(FaultPlan::io_failure_at(CommitPoint::AfterFsyncBeforeIndex));
    assert!(store.put_durable_batch(std::slice::from_ref(&victim)).is_err());
    store.clear_commit_fault_for_tests();
    assert!(
        segment_file(dir.path(), continued).metadata().unwrap().len() > durable_end,
        "without a Supported verdict the rollback must not truncate"
    );

    // Case 2: the failed batch creates a segment (rollback would unlink it).
    flag.store(true, Ordering::SeqCst);
    store.seal_active_segment().unwrap();
    let files_before = segment_files(dir.path());
    flag.store(false, Ordering::SeqCst);
    let fresh = block("fresh-segment-victim", 200);
    store.arm_commit_fault_for_tests(FaultPlan::io_failure_at(CommitPoint::AfterFsyncBeforeIndex));
    assert!(store.put_durable_batch(std::slice::from_ref(&fresh)).is_err());
    store.clear_commit_fault_for_tests();
    assert!(
        segment_files(dir.path()).len() > files_before.len(),
        "without a Supported verdict the rollback must not unlink"
    );
    drop(store);

    // A supported volume recovers both on the next open.
    flag.store(true, Ordering::SeqCst);
    let store =
        SegmentBlockStore::with_limits_and_verdict(dir.path(), limits(), verdict_flag(&flag))
            .unwrap();
    assert_eq!(store.get(committed.hash()).unwrap(), committed.bytes());
    assert!(!store.exists(victim.hash()).unwrap());
    assert!(!store.exists(fresh.hash()).unwrap());
    assert_index_names_only_readable_blocks(&store);
}

/// Recovery's other deletion, cutting a torn tail, is gated the same way: on a refused volume the
/// open fails and the file keeps its length.
#[test]
fn opening_a_store_with_a_torn_tail_on_a_refused_volume_truncates_nothing() {
    let dir = tempfile::tempdir().unwrap();
    {
        let store =
            SegmentBlockStore::with_limits_and_verdict(dir.path(), limits(), |_| true).unwrap();
        store.put_durable_batch(&[block("committed", 300)]).unwrap();
        store.arm_commit_fault_for_tests(FaultPlan::crash_at(CommitPoint::AfterAppendBeforeFsync));
        assert!(store.put_durable_batch(&[block("torn", 200)]).is_err());
    }
    let segment_id = testing::segment_ids_on_disk(dir.path()).unwrap()[0];
    let len = segment_file(dir.path(), segment_id).metadata().unwrap().len();
    let (_, durable_end, _) = testing::segment_row(dir.path(), segment_id).unwrap().unwrap();
    assert!(len > durable_end, "the crash must leave a tail");

    let refused = SegmentBlockStore::with_limits_and_verdict(dir.path(), limits(), |_| false);
    assert!(matches!(refused, Err(StorageError::DeletionRefused(_))));
    assert_eq!(segment_file(dir.path(), segment_id).metadata().unwrap().len(), len);

    let store = SegmentBlockStore::with_limits_and_verdict(dir.path(), limits(), |_| true).unwrap();
    assert_eq!(store.recovery_report().truncated_segments, vec![segment_id]);
}
