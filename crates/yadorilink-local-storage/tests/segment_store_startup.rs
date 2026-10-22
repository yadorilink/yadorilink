//! Opening a store must cost `O(segments)`, never `O(bytes)`.
//!
//! This is the property the earlier packed-store prototype did not have:
//! it rebuilt its index by reading and hashing every segment's payload at
//! startup, so a device's boot time grew with everything it had ever
//! stored. That alone disqualified it as canonical storage, however well
//! it wrote.
//!
//! The assertion here is structural rather than a stopwatch. A timing
//! bound would be flaky on a loaded machine and would not actually say
//! what is meant; "the open read zero blocks" says exactly what is meant
//! and cannot pass for the wrong reason. The elapsed times are printed
//! alongside as corroboration, not as the test.
//!
//! This file deliberately holds ONE test: `io_diag`'s counters are
//! process-global, so a second test in the same binary reading blocks
//! concurrently would perturb the measurement.

use std::time::Instant;

use yadorilink_local_storage::io_diag::{self, Op};
use yadorilink_local_storage::{GroupCommitLimits, LocallyHashedBlock, SegmentBlockStore};

#[test]
fn opening_a_store_reads_no_block_payloads_however_many_it_holds() {
    let dir = tempfile::tempdir().unwrap();
    // A small segment target so a modest corpus still produces many
    // segments -- the point is to have `O(segments)` be a number worth
    // distinguishing from `O(bytes)`.
    let limits =
        GroupCommitLimits { segment_target_bytes: 256 * 1024, ..GroupCommitLimits::default() };

    let payload_bytes: u64;
    let segments: usize;
    {
        let store = SegmentBlockStore::with_limits(dir.path(), limits).unwrap();
        let blocks: Vec<LocallyHashedBlock> = (0..4096u32)
            .map(|i| {
                let mut payload = vec![0u8; 4096];
                payload[..8].copy_from_slice(&(i as u64).to_le_bytes());
                LocallyHashedBlock::from_bytes(payload)
            })
            .collect();
        for chunk in blocks.chunks(256) {
            store.put_durable_batch(chunk).unwrap();
        }
        payload_bytes = store.detailed_usage().unwrap().physical_bytes;
        segments = store.segment_ids().unwrap().len();
        assert!(segments > 32, "the corpus must span many segments, got {segments}");
    }

    io_diag::set_enabled(true);
    io_diag::reset();
    let started = Instant::now();
    let store = SegmentBlockStore::with_limits(dir.path(), limits).unwrap();
    let open_elapsed = started.elapsed();
    let reads = io_diag::stat(Op::BlockRead);
    let compaction_reads = io_diag::stat(Op::CompactionRead);
    io_diag::set_enabled(false);

    assert_eq!(
        reads.calls, 0,
        "opening a store must not read a single block payload; it read {} ({} bytes). \
         Startup that touches payloads is startup that scales with everything the device \
         has ever stored.",
        reads.calls, reads.bytes
    );
    assert_eq!(compaction_reads.calls, 0, "opening a store must not compact");
    assert!(store.recovery_report().is_clean(), "a clean shutdown needs no repair");

    // Corroboration, not the assertion: an open that read the payloads
    // could not be this much faster than reading them.
    let read_back = Instant::now();
    let scrub = store.verify_store(true).unwrap();
    let scrub_elapsed = read_back.elapsed();
    println!(
        "open {open_elapsed:?} for {segments} segments / {payload_bytes} bytes; \
         a full payload scrub of the same store took {scrub_elapsed:?} \
         ({} records, {} bytes)",
        scrub.records_scanned, scrub.bytes_scanned
    );
    assert!(scrub.is_consistent());
    assert_eq!(scrub.records_scanned, 4096);
}
