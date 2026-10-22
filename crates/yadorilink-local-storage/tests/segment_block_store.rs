//! The segment block store's behavioural contract: put/get, dedup,
//! deletion, accounting, restart, and the rules that hold under concurrent
//! callers.
//!
//! The crash matrix lives in `segment_store_crash.rs` and the corruption
//! matrix in `segment_store_corruption.rs`; this file is the ordinary
//! behaviour those two assume.

use std::collections::HashSet;
use std::sync::{Arc, Barrier};

use yadorilink_local_storage::segment_store::testing;
use yadorilink_local_storage::{
    hash_block_bytes, BlockStore, GroupCommitLimits, LocallyHashedBlock, SegmentBlockStore,
    StorageError,
};

fn store() -> (SegmentBlockStore, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let store = SegmentBlockStore::new(dir.path()).unwrap().with_volume_verdict(|_| true);
    (store, dir)
}

fn prepared(payload: &[u8]) -> LocallyHashedBlock {
    LocallyHashedBlock::from_bytes(payload.to_vec())
}

/// A block of exactly `len` bytes whose content is unique per index.
///
/// Worth a helper rather than `vec![i as u8; len]`: that wraps at 256, so
/// a "512 distinct blocks" set is silently 251 of them plus duplicates,
/// and a test that then partitions the set into kept and deleted halves
/// deletes blocks it also expects to survive. Content-addressed storage
/// makes that mistake look like a store bug.
fn distinct_block_of(len: usize) -> impl Fn(u32) -> LocallyHashedBlock {
    move |i| {
        let mut payload = vec![0u8; len];
        let tag = format!("block-{i:08}-");
        let take = tag.len().min(len);
        payload[..take].copy_from_slice(&tag.as_bytes()[..take]);
        LocallyHashedBlock::from_bytes(payload)
    }
}

#[test]
fn put_then_get_roundtrips() {
    let (store, _dir) = store();
    let hash = store.put(b"hello world").unwrap();
    assert_eq!(store.get(&hash).unwrap(), b"hello world");
    assert_eq!(store.get_unchecked(&hash).unwrap(), b"hello world");
}

#[test]
fn an_empty_block_roundtrips() {
    // A zero-length payload still gets a record, and its framing has to
    // stay decodable -- the length field and the payload checksum both
    // degenerate here, and a record whose payload is empty must not be
    // mistaken for the end of the segment.
    let (store, _dir) = store();
    let hash = store.put(b"").unwrap();
    assert_eq!(store.get(&hash).unwrap(), b"");
    assert!(store.exists(&hash).unwrap());
    let after = store.put(b"a block after the empty one").unwrap();
    assert_eq!(store.get(&after).unwrap(), b"a block after the empty one");
}

#[test]
fn identical_content_is_stored_once() {
    let (store, _dir) = store();
    let first = store.put(b"same bytes").unwrap();
    let physical_after_first = store.detailed_usage().unwrap().physical_bytes;

    let second = store.put(b"same bytes").unwrap();
    assert_eq!(first, second);

    let usage = store.detailed_usage().unwrap();
    assert_eq!(usage.live_blocks, 1, "one block, whatever the caller asked for");
    assert_eq!(
        usage.physical_bytes, physical_after_first,
        "a duplicate must write no new record; if it did, this would grow"
    );
    assert_eq!(usage.dead_bytes, 0);
}

#[test]
fn a_hash_repeated_inside_one_batch_produces_one_record() {
    // Within-batch dedup is a separate mechanism from index dedup: the
    // second copy is not in the index yet when the group is laid out, so
    // only the group's own pass can catch it.
    let (store, _dir) = store();
    let block = prepared(b"repeated within one batch");
    let batch = vec![block.clone(), block.clone(), block.clone()];
    let receipts = store.put_durable_batch(&batch).unwrap();

    assert_eq!(receipts.len(), 3, "every requested block gets a receipt");
    assert!(
        receipts
            .iter()
            .all(|r| r.segment_id == receipts[0].segment_id && r.offset == receipts[0].offset),
        "identical content must resolve to one physical record"
    );
    let usage = store.detailed_usage().unwrap();
    assert_eq!(usage.live_blocks, 1);
    assert_eq!(usage.dead_bytes, 0, "a deduplicated copy must not become dead space");
}

#[test]
fn a_batch_of_distinct_blocks_shares_one_durability_group() {
    let (store, _dir) = store();
    let blocks: Vec<LocallyHashedBlock> =
        (0..64u32).map(|i| prepared(format!("block number {i}").as_bytes())).collect();
    let receipts = store.put_durable_batch(&blocks).unwrap();

    assert_eq!(receipts.len(), 64);
    assert!(receipts.iter().all(|r| !r.deduplicated));
    assert_eq!(
        receipts.iter().map(|r| r.segment_id).collect::<HashSet<_>>().len(),
        1,
        "a batch this small fits one segment"
    );
    for (block, receipt) in blocks.iter().zip(&receipts) {
        assert_eq!(&receipt.hash, block.hash());
        assert_eq!(store.get(block.hash()).unwrap(), block.bytes());
    }
}

#[test]
fn a_second_put_of_existing_content_reports_deduplication() {
    let (store, _dir) = store();
    let block = prepared(b"content the store already holds");
    let first = store.put_durable_batch(std::slice::from_ref(&block)).unwrap();
    assert!(!first[0].deduplicated);

    let second = store.put_durable_batch(std::slice::from_ref(&block)).unwrap();
    assert!(second[0].deduplicated, "the store already held it");
    assert_eq!(second[0].segment_id, first[0].segment_id);
    assert_eq!(second[0].offset, first[0].offset);
}

#[test]
fn concurrent_writers_of_the_same_hash_produce_one_record() {
    let (store, _dir) = store();
    let store = Arc::new(store);
    let payload = b"contended content written by every thread at once".to_vec();

    let threads = 8;
    let barrier = Arc::new(Barrier::new(threads));
    let handles: Vec<_> = (0..threads)
        .map(|_| {
            let store = Arc::clone(&store);
            let payload = payload.clone();
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                barrier.wait();
                store.put(&payload).unwrap()
            })
        })
        .collect();
    let hashes: HashSet<String> = handles.into_iter().map(|h| h.join().unwrap()).collect();

    assert_eq!(hashes.len(), 1, "every writer must agree on the hash");
    let usage = store.detailed_usage().unwrap();
    assert_eq!(usage.live_blocks, 1, "one block, however many writers asked for it");
    assert_eq!(
        usage.dead_bytes, 0,
        "concurrent writers must not each append their own copy -- dead bytes here would \
         mean the group and index dedup both missed"
    );
    assert_eq!(store.get(hashes.iter().next().unwrap()).unwrap(), payload);
}

#[test]
fn many_concurrent_writers_share_far_fewer_barriers_than_they_have_blocks() {
    // The design's whole claim, asserted structurally rather than by
    // timing: N concurrent callers must not cost N durability groups.
    // Whichever caller holds leadership commits everything queued behind
    // it, so groups track contention, not block count.
    let (store, _dir) = store();
    let store = Arc::new(store);
    let threads = 8;
    let per_thread = 32;
    let barrier = Arc::new(Barrier::new(threads));
    let handles: Vec<_> = (0..threads)
        .map(|t| {
            let store = Arc::clone(&store);
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                let batch: Vec<LocallyHashedBlock> = (0..per_thread)
                    .map(|i| prepared(format!("thread {t} block {i}").as_bytes()))
                    .collect();
                barrier.wait();
                store.put_durable_batch(&batch).unwrap();
                batch
            })
        })
        .collect();
    let all: Vec<LocallyHashedBlock> =
        handles.into_iter().flat_map(|h| h.join().unwrap()).collect();

    assert_eq!(all.len(), threads * per_thread);
    for block in &all {
        assert_eq!(store.get(block.hash()).unwrap(), block.bytes());
    }
    assert_eq!(store.detailed_usage().unwrap().live_blocks, (threads * per_thread) as u64);
}

#[test]
fn present_blocks_reports_a_mixed_present_missing_list() {
    let (store, _dir) = store();
    let present_a = store.put(b"present a").unwrap();
    let present_b = store.put(b"present b").unwrap();
    let absent = hash_block_bytes(b"never stored");

    let answers =
        store.present_blocks(&[present_a.clone(), absent.clone(), present_b.clone()]).unwrap();
    assert_eq!(answers, vec![true, false, true]);

    // `exists` and `present_blocks` must never disagree.
    for (hash, expected) in [(present_a, true), (absent, false), (present_b, true)] {
        assert_eq!(store.exists(&hash).unwrap(), expected);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn present_blocks_is_correct_under_a_multi_thread_runtime() {
    let (store, _dir) = store();
    let hash = store.put(b"stored under a multi-thread runtime").unwrap();
    let absent = hash_block_bytes(b"absent");
    assert_eq!(store.present_blocks(&[hash, absent]).unwrap(), vec![true, false]);
}

#[tokio::test]
async fn present_blocks_is_correct_under_a_current_thread_runtime() {
    let (store, _dir) = store();
    let hash = store.put(b"stored under a current-thread runtime").unwrap();
    let absent = hash_block_bytes(b"absent");
    assert_eq!(store.present_blocks(&[hash, absent]).unwrap(), vec![true, false]);
}

#[test]
fn deleting_a_block_removes_it_and_leaves_its_bytes_as_dead_space() {
    let (store, _dir) = store();
    let keep = store.put(b"a block that stays").unwrap();
    let drop_me = store.put(b"a block that goes away").unwrap();
    let before = store.detailed_usage().unwrap();

    store.delete(&drop_me).unwrap();

    let after = store.detailed_usage().unwrap();
    assert_eq!(after.live_blocks, before.live_blocks - 1);
    assert_eq!(after.live_bytes, before.live_bytes - b"a block that goes away".len() as u64);
    assert_eq!(
        after.physical_bytes, before.physical_bytes,
        "a delete moves no bytes; a segment is immutable below durable_end"
    );
    assert!(after.dead_bytes > 0, "the deleted block's record is now dead space");

    assert!(!store.exists(&drop_me).unwrap());
    assert!(matches!(store.get(&drop_me), Err(StorageError::NotFound(_))));
    assert_eq!(store.get(&keep).unwrap(), b"a block that stays");

    // Deleting something absent is a no-op, not an error -- a retried
    // deletion has to be safe.
    store.delete(&drop_me).unwrap();
}

#[test]
fn a_deleted_block_can_be_added_again_and_read_back() {
    let (store, _dir) = store();
    let payload = b"deleted then written again";
    let hash = store.put(payload).unwrap();
    store.delete(&hash).unwrap();
    assert!(!store.exists(&hash).unwrap());

    let again = store.put(payload).unwrap();
    assert_eq!(again, hash);
    assert_eq!(store.get(&hash).unwrap(), payload);
    assert_eq!(store.detailed_usage().unwrap().live_blocks, 1);
}

#[test]
fn usage_accounting_tracks_live_physical_and_dead_bytes() {
    let (store, _dir) = store();
    assert_eq!(store.usage().unwrap().block_count, 0);
    assert_eq!(store.usage().unwrap().total_bytes, 0);

    let a = store.put(b"abc").unwrap();
    store.put(b"12345").unwrap();
    store.put(b"abc").unwrap(); // duplicate

    let usage = store.usage().unwrap();
    assert_eq!(usage.block_count, 2);
    assert_eq!(usage.total_bytes, 8, "payload bytes, not framing");

    let detailed = store.detailed_usage().unwrap();
    assert_eq!(detailed.live_bytes, 8);
    assert!(
        detailed.physical_bytes > detailed.live_bytes,
        "physical bytes include per-record framing"
    );
    assert_eq!(detailed.dead_bytes, 0);
    assert_eq!(detailed.active_segments, 1);

    store.delete(&a).unwrap();
    let after = store.usage().unwrap();
    assert_eq!(after.block_count, 1);
    assert_eq!(after.total_bytes, 5);
}

#[test]
fn a_reopened_store_serves_everything_the_previous_one_committed() {
    let dir = tempfile::tempdir().unwrap();
    let payloads: Vec<Vec<u8>> =
        (0..200u32).map(|i| format!("durable across restart: {i}").into_bytes()).collect();
    let hashes: Vec<String> = {
        let store = SegmentBlockStore::new(dir.path()).unwrap().with_volume_verdict(|_| true);
        let blocks: Vec<LocallyHashedBlock> =
            payloads.iter().map(|p| LocallyHashedBlock::from_bytes(p.clone())).collect();
        store.put_durable_batch(&blocks).unwrap().into_iter().map(|receipt| receipt.hash).collect()
    };

    let store = SegmentBlockStore::new(dir.path()).unwrap().with_volume_verdict(|_| true);
    assert!(store.recovery_report().is_clean(), "a clean shutdown needs no repair");
    assert_eq!(store.usage().unwrap().block_count, 200);
    for (hash, payload) in hashes.iter().zip(&payloads) {
        assert_eq!(&store.get(hash).unwrap(), payload);
    }
    assert!(store.verify_store(true).unwrap().is_consistent());
}

#[test]
fn a_reopened_store_starts_a_new_segment_rather_than_resuming_the_old_one() {
    // Resuming the previous handle's open segment would be tidier on disk
    // and is where this started. It also makes the one genuinely
    // destructive overlap possible: two handles on one root -- a restart
    // whose outgoing store has not finished dropping, or two daemons aimed
    // at one directory -- would both reopen the same segment at the same
    // offset and overwrite each other's records. Sealing on open costs the
    // tail of one segment and removes the shared append target entirely.
    let dir = tempfile::tempdir().unwrap();
    let before = {
        let store = SegmentBlockStore::new(dir.path()).unwrap().with_volume_verdict(|_| true);
        store.put(b"written before the restart").unwrap();
        store.segment_ids().unwrap()
    };
    assert_eq!(before.len(), 1);

    let store = SegmentBlockStore::new(dir.path()).unwrap().with_volume_verdict(|_| true);
    store.put(b"written after the restart").unwrap();
    let after = store.segment_ids().unwrap();
    assert_eq!(after.len(), 2, "the reopened store must append somewhere new");
    assert!(after.starts_with(&before), "the earlier segment stays, sealed");
    assert_eq!(
        store.get(&hash_block_bytes(b"written before the restart")).unwrap(),
        b"written before the restart"
    );
    assert_eq!(
        store.get(&hash_block_bytes(b"written after the restart")).unwrap(),
        b"written after the restart"
    );
    assert!(store.verify_store(true).unwrap().is_consistent());
}

#[test]
fn reopening_a_store_that_wrote_nothing_does_not_accumulate_empty_segments() {
    // The flip side of sealing on open: a daemon that starts, writes
    // nothing and stops must not leave a segment behind every time, or a
    // machine that reboots daily grows a segment a day forever.
    let dir = tempfile::tempdir().unwrap();
    {
        let store = SegmentBlockStore::new(dir.path()).unwrap().with_volume_verdict(|_| true);
        store.put(b"the only block this store will ever hold").unwrap();
    }
    for _ in 0..8 {
        let store = SegmentBlockStore::new(dir.path()).unwrap().with_volume_verdict(|_| true);
        store.reclaim_retired().unwrap();
        drop(store);
    }

    let store = SegmentBlockStore::new(dir.path()).unwrap().with_volume_verdict(|_| true);
    store.reclaim_retired().unwrap();
    assert_eq!(
        store.segment_ids().unwrap().len(),
        1,
        "eight idle restarts must leave one segment, not nine"
    );
    assert_eq!(store.usage().unwrap().block_count, 1);
    assert!(store.verify_store(true).unwrap().is_consistent());
}

#[test]
fn sealing_forces_the_next_group_onto_a_new_segment() {
    let (store, _dir) = store();
    store.put(b"in the first segment").unwrap();
    store.seal_active_segment().unwrap();
    store.put(b"in the second segment").unwrap();

    let segments = store.segment_ids().unwrap();
    assert_eq!(segments.len(), 2);
    assert_eq!(store.usage().unwrap().block_count, 2);
    assert!(store.verify_store(true).unwrap().is_consistent());
}

#[test]
fn a_group_larger_than_the_segment_target_rolls_over_without_splitting_a_record() {
    let dir = tempfile::tempdir().unwrap();
    let limits = GroupCommitLimits { segment_target_bytes: 4096, ..GroupCommitLimits::default() };
    let store = SegmentBlockStore::with_limits_and_verdict(dir.path(), limits, |_| true).unwrap();

    let blocks: Vec<LocallyHashedBlock> = (0..32u32).map(distinct_block_of(1000)).collect();
    let receipts = store.put_durable_batch(&blocks).unwrap();

    let segments: HashSet<u64> = receipts.iter().map(|r| r.segment_id).collect();
    assert!(segments.len() > 1, "32 KiB of blocks must not fit one 4 KiB segment");
    for block in &blocks {
        assert_eq!(store.get(block.hash()).unwrap(), block.bytes());
    }
    assert!(store.verify_store(true).unwrap().is_consistent());

    // And the same after a restart: roll-over is recorded durably, not
    // held only in the writer's head.
    drop(store);
    let store = SegmentBlockStore::with_limits_and_verdict(dir.path(), limits, |_| true).unwrap();
    assert!(store.recovery_report().is_clean());
    for block in &blocks {
        assert_eq!(store.get(block.hash()).unwrap(), block.bytes());
    }
}

#[test]
fn a_store_written_one_block_at_a_time_still_rolls_over() {
    // The roll-over decision has to consider the segment an earlier group
    // left open, not just the batch the current group has already started.
    // A caller that commits one block per group -- the ordinary
    // interactive shape -- never has an open batch to compare against, so
    // a check that only looked there would grow a single unbounded
    // segment, and compaction would have nothing it could ever act on.
    let dir = tempfile::tempdir().unwrap();
    let limits = GroupCommitLimits { segment_target_bytes: 4096, ..GroupCommitLimits::default() };
    let store = SegmentBlockStore::with_limits_and_verdict(dir.path(), limits, |_| true).unwrap();

    let blocks: Vec<LocallyHashedBlock> = (0..40u32).map(distinct_block_of(500)).collect();
    for block in &blocks {
        store.put_durable_batch(std::slice::from_ref(block)).unwrap();
    }

    let segments = store.segment_ids().unwrap();
    assert!(
        segments.len() > 1,
        "20 KiB of blocks committed one at a time must not all land in one 4 KiB segment; \
         got {} segment(s)",
        segments.len()
    );
    for block in &blocks {
        assert_eq!(store.get(block.hash()).unwrap(), block.bytes());
    }
    assert!(store.verify_store(true).unwrap().is_consistent());
}

#[test]
fn a_block_larger_than_the_segment_target_still_stores_in_one_record() {
    let dir = tempfile::tempdir().unwrap();
    let limits = GroupCommitLimits { segment_target_bytes: 1024, ..GroupCommitLimits::default() };
    let store = SegmentBlockStore::with_limits_and_verdict(dir.path(), limits, |_| true).unwrap();

    let big = vec![0xA5u8; 64 * 1024];
    let hash = store.put(&big).unwrap();
    assert_eq!(store.get(&hash).unwrap(), big);
    assert!(store.verify_store(true).unwrap().is_consistent());
}

#[test]
fn path_traversal_is_rejected_on_every_hash_taking_entry_point() {
    let (store, _dir) = store();
    let bad = "../../../../etc/passwd";
    assert!(matches!(store.get(bad), Err(StorageError::InvalidPath(_))));
    assert!(matches!(store.get_unchecked(bad), Err(StorageError::InvalidPath(_))));
    assert!(matches!(store.exists(bad), Err(StorageError::InvalidPath(_))));
    assert!(matches!(store.delete(bad), Err(StorageError::InvalidPath(_))));
    assert!(matches!(store.list_by_prefix("../etc"), Err(StorageError::InvalidPath(_))));
    assert!(matches!(store.present_blocks(&[bad.to_string()]), Err(StorageError::InvalidPath(_))));
}

#[test]
fn listing_by_prefix_matches_hex_prefixes_of_either_parity() {
    let (store, _dir) = store();
    let mut hashes: Vec<String> =
        (0..64u32).map(|i| store.put(format!("prefix probe {i}").as_bytes()).unwrap()).collect();
    hashes.sort();

    assert_eq!(store.list_by_prefix("").unwrap().len(), 64);
    let sample = hashes[0].clone();
    for width in [1usize, 2, 3, 4, 8] {
        let prefix = &sample[..width];
        let listed = store.list_by_prefix(prefix).unwrap();
        assert!(listed.contains(&sample), "prefix {prefix:?} must match its own hash");
        assert!(
            listed.iter().all(|h| h.starts_with(prefix)),
            "prefix {prefix:?} returned a non-matching hash"
        );
        let expected = hashes.iter().filter(|h| h.starts_with(prefix)).count();
        assert_eq!(listed.len(), expected);
    }
}

#[test]
fn a_missing_block_is_reported_not_found() {
    let (store, _dir) = store();
    let absent = hash_block_bytes(b"never stored anywhere");
    assert!(matches!(store.get(&absent), Err(StorageError::NotFound(_))));
    assert!(!store.exists(&absent).unwrap());
}

#[test]
fn sweep_deletes_unreferenced_blocks_outside_the_grace_window_only() {
    let dir = tempfile::tempdir().unwrap();
    let store = SegmentBlockStore::new(dir.path()).unwrap().with_volume_verdict(|_| true);
    let live_hash = store.put(b"referenced by a retained version").unwrap();
    let old_orphan = store.put(b"unreferenced and old").unwrap();
    let fresh_orphan = store.put(b"unreferenced but written just now").unwrap();

    let long_ago = std::time::SystemTime::now() - std::time::Duration::from_secs(86_400);
    store.backdate_block_for_tests(&old_orphan, long_ago).unwrap();
    store.backdate_block_for_tests(&live_hash, long_ago).unwrap();

    let live: HashSet<String> = [live_hash.clone()].into_iter().collect();
    let cutoff = std::time::SystemTime::now() - std::time::Duration::from_secs(3600);

    let dry = store.sweep(&live, cutoff, true).unwrap();
    assert_eq!(dry.blocks_deleted, 1, "only the old orphan is a candidate");
    assert!(store.exists(&old_orphan).unwrap(), "a dry run deletes nothing");

    let real = store.sweep(&live, cutoff, false).unwrap();
    assert_eq!(real.blocks_deleted, dry.blocks_deleted);
    assert_eq!(real.bytes_reclaimed, dry.bytes_reclaimed);
    assert!(!store.exists(&old_orphan).unwrap());
    assert!(store.exists(&live_hash).unwrap(), "a referenced block survives the sweep");
    assert!(store.exists(&fresh_orphan).unwrap(), "the grace window protects a fresh block");
}

/// Putting a block the store already holds is a new reference to it: the grace window starts
/// again, so a sweep right after cannot take what the caller was just told is stored.
#[test]
fn a_dedup_hit_restarts_the_grace_window() {
    let (store, _dir) = store();
    let hash = store.put(b"stored long ago, unreferenced until now").unwrap();
    let long_ago = std::time::SystemTime::now() - std::time::Duration::from_secs(86_400);
    store.backdate_block_for_tests(&hash, long_ago).unwrap();

    assert_eq!(store.put(b"stored long ago, unreferenced until now").unwrap(), hash);

    let cutoff = std::time::SystemTime::now() - std::time::Duration::from_secs(3600);
    let report = store.sweep(&HashSet::new(), cutoff, false).unwrap();
    assert_eq!(report.blocks_deleted, 0);
    assert!(store.exists(&hash).unwrap());
    store.get(&hash).unwrap();
}

/// The sweep removes a block only if it is still outside the grace window when it is removed:
/// a put that lands between choosing the candidates and removing them keeps its block.
#[test]
fn a_put_between_choosing_and_removing_sweep_candidates_keeps_the_block() {
    let (store, _dir) = store();
    let store = Arc::new(store);
    let hash = store.put(b"a candidate that is put back mid-sweep").unwrap();
    let long_ago = std::time::SystemTime::now() - std::time::Duration::from_secs(86_400);
    store.backdate_block_for_tests(&hash, long_ago).unwrap();
    let again = store.clone();
    store.install_sweep_candidates_hook_for_tests(move || {
        again.put(b"a candidate that is put back mid-sweep").unwrap();
    });

    let cutoff = std::time::SystemTime::now() - std::time::Duration::from_secs(3600);
    let report = store.sweep(&HashSet::new(), cutoff, false).unwrap();

    assert_eq!(report.blocks_deleted, 0, "the put refreshed the block before it was removed");
    assert!(store.exists(&hash).unwrap());
    store.get(&hash).unwrap();
}

/// The grace window of a dedup hit starts when the put is about to return its receipt, not when
/// its group began: if the group's other work is slow, a sweep right after the receipt still
/// finds the block inside the window.
#[test]
fn a_dedup_hit_is_stamped_after_the_slow_work_of_its_group() {
    let (store, _dir) = store();
    let old = store.put(b"stored long ago").unwrap();
    let long_ago = std::time::SystemTime::now() - std::time::Duration::from_secs(86_400);
    store.backdate_block_for_tests(&old, long_ago).unwrap();
    let slow_started = Arc::new(std::sync::Mutex::new(None));
    let started = slow_started.clone();
    store.install_before_dedup_stamp_hook_for_tests(move || {
        *started.lock().unwrap() = Some(std::time::SystemTime::now());
        std::thread::sleep(std::time::Duration::from_millis(40));
    });

    store
        .put_durable_batch(&[prepared(b"stored long ago"), prepared(b"new in the same group")])
        .unwrap();

    // The window a sweep that began while the group was still working would have used.
    let cutoff = slow_started.lock().unwrap().expect("the hook ran");
    let report = store.sweep(&HashSet::new(), cutoff, false).unwrap();
    assert!(store.exists(&old).unwrap(), "{report:?}");
    store.get(&old).unwrap();
}

#[test]
fn a_malformed_live_hash_refuses_both_sweeps_and_deletes_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let store = SegmentBlockStore::new(dir.path()).unwrap().with_volume_verdict(|_| true);
    let live_hash = store.put(b"referenced by a retained version").unwrap();
    let old_orphan = store.put(b"unreferenced and old").unwrap();
    let long_ago = std::time::SystemTime::now() - std::time::Duration::from_secs(86_400);
    store.backdate_block_for_tests(&old_orphan, long_ago).unwrap();
    store.backdate_block_for_tests(&live_hash, long_ago).unwrap();
    let cutoff = std::time::SystemTime::now() - std::time::Duration::from_secs(3600);

    // An incomplete liveness set is evidence uncertainty, not non-liveness:
    // a malformed entry must stop the sweep, valid siblings notwithstanding.
    for malformed in ["not-hex", "abcd", ""] {
        let live: HashSet<String> =
            [live_hash.clone(), malformed.to_string()].into_iter().collect();
        for dry_run in [true, false] {
            assert!(
                store.sweep(&live, cutoff, dry_run).is_err(),
                "malformed live hash {malformed:?} must refuse the sweep (dry_run={dry_run})"
            );
        }
        assert!(store.exists(&old_orphan).unwrap(), "nothing may be deleted on refusal");
        assert!(store.exists(&live_hash).unwrap());
    }

    // The same set without the malformed entry still sweeps as before.
    let live: HashSet<String> = [live_hash.clone()].into_iter().collect();
    assert_eq!(store.sweep(&live, cutoff, false).unwrap().blocks_deleted, 1);
    assert!(!store.exists(&old_orphan).unwrap());
}

#[test]
fn reclaiming_cached_blocks_frees_exactly_the_named_hashes() {
    let (store, _dir) = store();
    let a = store.put(b"cached block a").unwrap();
    let b = store.put(b"cached block b").unwrap();
    let keep = store.put(b"a block nobody asked to reclaim").unwrap();

    let report = store.reclaim_cached_blocks(&[a.clone(), b.clone()]).unwrap();
    assert_eq!(report.blocks_deleted, 2);
    assert_eq!(report.bytes_reclaimed, (b"cached block a".len() + b"cached block b".len()) as u64);
    assert!(!store.exists(&a).unwrap());
    assert!(!store.exists(&b).unwrap());
    assert!(store.exists(&keep).unwrap());

    // Idempotent: a retry of a partially-completed reclamation must not
    // double-count or error.
    let retry = store.reclaim_cached_blocks(&[a, b]).unwrap();
    assert_eq!(retry.blocks_deleted, 0);
}

#[test]
fn compaction_reclaims_dead_space_and_keeps_every_live_block_readable() {
    let dir = tempfile::tempdir().unwrap();
    let limits = GroupCommitLimits { segment_target_bytes: 8192, ..GroupCommitLimits::default() };
    let store = SegmentBlockStore::with_limits_and_verdict(dir.path(), limits, |_| true).unwrap();

    // Two segments' worth, so at least one gets sealed and becomes
    // eligible; compaction never touches the segment still being appended
    // to.
    let blocks: Vec<LocallyHashedBlock> = (0..64u32).map(distinct_block_of(500)).collect();
    store.put_durable_batch(&blocks).unwrap();
    store.seal_active_segment().unwrap();

    // Delete three quarters of them, which puts the sealed segments well
    // past the dead ratio.
    let survivors: Vec<&LocallyHashedBlock> = blocks
        .iter()
        .enumerate()
        .filter_map(|(i, block)| {
            if i % 4 == 0 {
                Some(block)
            } else {
                store.delete(block.hash()).unwrap();
                None
            }
        })
        .collect();

    let before = store.detailed_usage().unwrap();
    assert!(before.dead_bytes > before.live_bytes);

    let report = store.compact_with_thresholds(0.5, 1).unwrap();
    assert!(report.segments_compacted > 0, "a mostly-dead segment must be a candidate");
    assert_eq!(report.unreadable_blocks_dropped, 0);

    let after = store.detailed_usage().unwrap();
    assert!(
        after.physical_bytes < before.physical_bytes,
        "compaction must give physical bytes back: {} -> {}",
        before.physical_bytes,
        after.physical_bytes
    );
    assert_eq!(after.live_blocks, survivors.len() as u64);
    for block in &survivors {
        assert_eq!(store.get(block.hash()).unwrap(), block.bytes());
    }
    assert!(store.verify_store(true).unwrap().is_consistent());

    // And it all survives a restart.
    drop(store);
    let store = SegmentBlockStore::with_limits_and_verdict(dir.path(), limits, |_| true).unwrap();
    for block in &survivors {
        assert_eq!(store.get(block.hash()).unwrap(), block.bytes());
    }
}

#[test]
fn a_fully_dead_segment_is_retired_and_its_file_removed() {
    let dir = tempfile::tempdir().unwrap();
    let store = SegmentBlockStore::new(dir.path()).unwrap().with_volume_verdict(|_| true);
    let blocks: Vec<LocallyHashedBlock> =
        (0..16u32).map(|i| prepared(format!("doomed block {i}").as_bytes())).collect();
    store.put_durable_batch(&blocks).unwrap();
    store.seal_active_segment().unwrap();
    let doomed = store.segment_ids().unwrap();
    assert_eq!(doomed.len(), 1);

    for block in &blocks {
        store.delete(block.hash()).unwrap();
    }
    store.compact_with_thresholds(0.5, 1).unwrap();

    assert!(
        !testing::segment_ids_on_disk(dir.path()).unwrap().contains(&doomed[0]),
        "a segment with nothing live left must have its file removed"
    );
    assert_eq!(store.detailed_usage().unwrap().live_blocks, 0);
    // The store is still perfectly usable afterwards.
    let hash = store.put(b"written after every segment was reclaimed").unwrap();
    assert_eq!(store.get(&hash).unwrap(), b"written after every segment was reclaimed");
}

#[test]
fn reads_proceed_while_a_group_commit_is_in_flight() {
    // The negative claim this file exists to pin: no store-wide lock is
    // held across a durability barrier. A reader blocked behind the
    // writer's `fsync` would make this hang rather than fail.
    let (store, _dir) = store();
    let store = Arc::new(store);
    let readable = store.put(b"a block written before the contended commit").unwrap();

    let writer_store = Arc::clone(&store);
    let started = Arc::new(Barrier::new(2));
    let writer_started = Arc::clone(&started);
    let writer = std::thread::spawn(move || {
        // Big enough that its barrier is not instantaneous.
        let batch: Vec<LocallyHashedBlock> = (0..2048u32).map(distinct_block_of(512)).collect();
        writer_started.wait();
        writer_store.put_durable_batch(&batch).unwrap();
    });

    started.wait();
    // Reads keep succeeding throughout the commit.
    for _ in 0..200 {
        assert_eq!(store.get(&readable).unwrap(), b"a block written before the contended commit");
        assert!(store.exists(&readable).unwrap());
    }
    writer.join().unwrap();
    assert_eq!(store.detailed_usage().unwrap().live_blocks, 2049);
}

#[test]
fn reads_and_deletes_proceed_while_compaction_rewrites_a_segment() {
    let dir = tempfile::tempdir().unwrap();
    let limits = GroupCommitLimits { segment_target_bytes: 16384, ..GroupCommitLimits::default() };
    let store =
        Arc::new(SegmentBlockStore::with_limits_and_verdict(dir.path(), limits, |_| true).unwrap());

    let blocks: Vec<LocallyHashedBlock> = (0..512u32).map(distinct_block_of(200)).collect();
    store.put_durable_batch(&blocks).unwrap();
    store.seal_active_segment().unwrap();
    let survivors: Vec<LocallyHashedBlock> = blocks
        .iter()
        .enumerate()
        .filter_map(|(i, block)| {
            if i % 3 == 0 {
                Some(block.clone())
            } else {
                store.delete(block.hash()).unwrap();
                None
            }
        })
        .collect();

    let reader_store = Arc::clone(&store);
    let reader_blocks = survivors.clone();
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let reader_stop = Arc::clone(&stop);
    let reader = std::thread::spawn(move || {
        let mut reads = 0u64;
        while !reader_stop.load(std::sync::atomic::Ordering::Relaxed) {
            for block in &reader_blocks {
                // The compaction race is a *stale answer*, not a failure:
                // `get` re-resolves and retries, so this must never error.
                assert_eq!(
                    reader_store.get(block.hash()).unwrap(),
                    block.bytes(),
                    "a read racing compaction must still return the right bytes"
                );
                reads += 1;
            }
        }
        reads
    });

    store.compact_with_thresholds(0.5, 1).unwrap();
    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    let reads = reader.join().unwrap();
    assert!(reads > 0, "the reader must actually have run during the compaction");

    for block in &survivors {
        assert_eq!(store.get(block.hash()).unwrap(), block.bytes());
    }
    assert!(store.verify_store(true).unwrap().is_consistent());
}

#[test]
fn simultaneous_bulk_imports_from_many_threads_all_land() {
    let (store, _dir) = store();
    let store = Arc::new(store);
    let threads = 6;
    let per_thread = 500;

    let handles: Vec<_> = (0..threads)
        .map(|t| {
            let store = Arc::clone(&store);
            std::thread::spawn(move || {
                let mut hashes = Vec::new();
                for chunk in 0..10 {
                    let batch: Vec<LocallyHashedBlock> = (0..per_thread / 10)
                        .map(|i| {
                            LocallyHashedBlock::from_bytes(
                                format!("importer {t} chunk {chunk} block {i}").into_bytes(),
                            )
                        })
                        .collect();
                    for receipt in store.put_durable_batch(&batch).unwrap() {
                        hashes.push(receipt.hash);
                    }
                }
                hashes
            })
        })
        .collect();
    let all: Vec<String> = handles.into_iter().flat_map(|h| h.join().unwrap()).collect();

    assert_eq!(all.len(), threads * per_thread);
    assert_eq!(store.detailed_usage().unwrap().live_blocks, (threads * per_thread) as u64);
    for hash in &all {
        assert_eq!(hash_block_bytes(&store.get(hash).unwrap()), *hash);
    }
    assert!(store.verify_store(true).unwrap().is_consistent());
}

#[test]
fn gc_runs_concurrently_with_reads_without_losing_a_live_block() {
    let (store, _dir) = store();
    let store = Arc::new(store);
    let keep: Vec<LocallyHashedBlock> =
        (0..200u32).map(|i| prepared(format!("kept block {i}").as_bytes())).collect();
    let discard: Vec<LocallyHashedBlock> =
        (0..200u32).map(|i| prepared(format!("discarded block {i}").as_bytes())).collect();
    store.put_durable_batch(&keep).unwrap();
    store.put_durable_batch(&discard).unwrap();

    let long_ago = std::time::SystemTime::now() - std::time::Duration::from_secs(86_400);
    for block in keep.iter().chain(&discard) {
        store.backdate_block_for_tests(block.hash(), long_ago).unwrap();
    }

    let reader_store = Arc::clone(&store);
    let reader_blocks = keep.clone();
    let reader = std::thread::spawn(move || {
        for _ in 0..20 {
            for block in &reader_blocks {
                assert_eq!(reader_store.get(block.hash()).unwrap(), block.bytes());
            }
        }
    });

    let live: HashSet<String> = keep.iter().map(|b| b.hash().clone()).collect();
    let cutoff = std::time::SystemTime::now();
    let report = store.sweep(&live, cutoff, false).unwrap();
    reader.join().unwrap();

    assert_eq!(report.blocks_deleted, discard.len() as u64);
    for block in &keep {
        assert_eq!(store.get(block.hash()).unwrap(), block.bytes());
    }
    for block in &discard {
        assert!(!store.exists(block.hash()).unwrap());
    }
}

#[test]
fn a_store_directory_stamped_with_a_foreign_format_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("FORMAT"), "some-other-block-store\nformat_version=1\n")
        .unwrap();
    assert!(matches!(SegmentBlockStore::new(dir.path()), Err(StorageError::CorruptStore(_))));
}

#[test]
fn a_fresh_store_stamps_its_own_format_marker() {
    let dir = tempfile::tempdir().unwrap();
    let _store = SegmentBlockStore::new(dir.path()).unwrap().with_volume_verdict(|_| true);
    let marker = std::fs::read_to_string(dir.path().join("FORMAT")).unwrap();
    assert!(marker.starts_with("yadorilink-block-store"));
    assert!(marker.contains("format_version="));
}

/// The verdict that gates deletion is taken on `root/segments` (where the segment files live),
/// afresh for every deletion, and a refusal removes nothing on any path that deletes bytes.
#[test]
fn every_physical_deletion_needs_a_positive_verdict_on_the_segments_directory() {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Mutex;
    use std::time::SystemTime;

    let dir = tempfile::tempdir().unwrap();
    let asked: Arc<Mutex<Vec<Option<std::path::PathBuf>>>> = Arc::default();
    let durable = Arc::new(AtomicBool::new(false));
    let limits = GroupCommitLimits { segment_target_bytes: 8192, ..GroupCommitLimits::default() };
    let store = SegmentBlockStore::with_limits(dir.path(), limits).unwrap().with_volume_verdict({
        let (asked, durable) = (asked.clone(), durable.clone());
        move |d| {
            asked.lock().unwrap().push(d.map(|d| d.to_path_buf()));
            durable.load(Ordering::SeqCst)
        }
    });
    assert_eq!(store.storage_root(), Some(dir.path().join("segments").as_path()));

    let blocks: Vec<LocallyHashedBlock> = (0..64u32).map(distinct_block_of(500)).collect();
    store.put_durable_batch(&blocks).unwrap();
    store.seal_active_segment().unwrap();
    let all: HashSet<String> = blocks.iter().map(|b| b.hash().to_string()).collect();
    let none = HashSet::new();
    let later = SystemTime::now() + std::time::Duration::from_secs(60);
    let refused = |r: Result<_, StorageError>| {
        assert!(matches!(r, Err(StorageError::DeletionRefused(_))), "expected a refusal");
    };

    // Refused: nothing is removed, by any path.
    refused(store.sweep(&none, later, false).map(|_| ()));
    refused(store.delete(blocks[0].hash()));
    refused(store.reclaim_cached_blocks(&[blocks[1].hash().to_string()]).map(|_| ()));
    refused(store.compact_with_thresholds(0.0, 0).map(|_| ()));
    assert_eq!(store.reclaim_retired().unwrap(), 0, "nothing retired, nothing to delete");
    for block in &blocks {
        assert!(store.exists(block.hash()).unwrap());
    }
    assert!(store.sweep(&none, later, true).is_ok(), "a dry run deletes nothing");
    assert!(all.len() == 64);
    for asked in asked.lock().unwrap().iter() {
        assert_eq!(asked.as_deref(), Some(dir.path().join("segments").as_path()));
    }

    // Verdict flips positive: the same calls delete. Flip back: refused again at once.
    durable.store(true, Ordering::SeqCst);
    store.delete(blocks[0].hash()).unwrap();
    durable.store(false, Ordering::SeqCst);
    refused(store.delete(blocks[1].hash()));
    assert!(store.exists(blocks[1].hash()).unwrap());
}

/// With the Windows durability gate open, a store with the production verdict deletes bytes
/// exactly where the volume holding them is judged durable, and nowhere else.
#[cfg(windows)]
#[test]
fn a_store_on_windows_deletes_only_on_a_volume_the_production_verdict_accepts() {
    let dir = tempfile::tempdir().unwrap();
    let store = SegmentBlockStore::new(dir.path()).unwrap();
    let hash = store.put(b"kept").unwrap();
    let offered = yadorilink_fs_platform::durable_dir::volume_offers_durable_namespace(Some(
        &dir.path().join("segments"),
    ));
    if offered {
        store.delete(&hash).unwrap();
        assert!(!store.exists(&hash).unwrap());
    } else {
        assert!(matches!(store.delete(&hash), Err(StorageError::DeletionRefused(_))));
        assert!(store.exists(&hash).unwrap());
    }
}
