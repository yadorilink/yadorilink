#![cfg(test)]

use super::*;

fn index() -> (BlockIndex, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let index = BlockIndex::open(&dir.path().join("index.sqlite3")).unwrap();
    (index, dir)
}

fn hash(seed: u8) -> [u8; RAW_HASH_LEN] {
    [seed; RAW_HASH_LEN]
}

#[test]
fn a_group_commit_records_mappings_and_segment_accounting_together() {
    let (index, _dir) = index();
    let plan = GroupCommitPlan {
        appends: vec![SegmentAppend {
            segment_id: 1,
            created: true,
            durable_end: SEGMENT_HEADER_LEN + 200,
            blocks: vec![
                NewBlockRow {
                    hash: hash(1),
                    record_offset: SEGMENT_HEADER_LEN,
                    payload_len: 48,
                    record_len: 100,
                    added_at_nanos: 5,
                },
                NewBlockRow {
                    hash: hash(2),
                    record_offset: SEGMENT_HEADER_LEN + 100,
                    payload_len: 48,
                    record_len: 100,
                    added_at_nanos: 6,
                },
            ],
        }],
        sealed: Vec::new(),
        next_segment_id: 2,
    };
    index.commit_group(&plan, &no_injected_fault).unwrap();

    assert_eq!(
        index.lookup(&hash(1)).unwrap(),
        Some(BlockLocation { segment_id: 1, record_offset: SEGMENT_HEADER_LEN, length: 48 })
    );
    let usage = index.usage().unwrap();
    assert_eq!(usage.live_blocks, 2);
    assert_eq!(usage.live_payload_bytes, 96);
    assert_eq!(usage.live_record_bytes, 200);
    assert_eq!(usage.physical_bytes, 200);
    assert_eq!(usage.dead_bytes(), 0);
    assert_eq!(index.recorded_next_segment_id().unwrap(), 2);
}

#[test]
fn removing_a_block_debits_its_segment_without_touching_physical_bytes() {
    let (index, _dir) = index();
    index
        .commit_group(
            &GroupCommitPlan {
                appends: vec![SegmentAppend {
                    segment_id: 1,
                    created: true,
                    durable_end: SEGMENT_HEADER_LEN + 200,
                    blocks: vec![
                        NewBlockRow {
                            hash: hash(1),
                            record_offset: SEGMENT_HEADER_LEN,
                            payload_len: 48,
                            record_len: 100,
                            added_at_nanos: 1,
                        },
                        NewBlockRow {
                            hash: hash(2),
                            record_offset: SEGMENT_HEADER_LEN + 100,
                            payload_len: 48,
                            record_len: 100,
                            added_at_nanos: 1,
                        },
                    ],
                }],
                sealed: Vec::new(),
                next_segment_id: 2,
            },
            &no_injected_fault,
        )
        .unwrap();

    let summary = index.remove_blocks(&[hash(1)]).unwrap();
    assert_eq!(summary, RemovalSummary { blocks_removed: 1, payload_bytes_removed: 48 });

    let usage = index.usage().unwrap();
    assert_eq!(usage.live_blocks, 1);
    assert_eq!(usage.physical_bytes, 200, "physical bytes stay until compaction reclaims them");
    assert_eq!(usage.dead_bytes(), 100);
    assert!(index.lookup(&hash(1)).unwrap().is_none());
    // Removing a hash that is not there is a no-op, not an error.
    assert_eq!(index.remove_blocks(&[hash(9)]).unwrap(), RemovalSummary::default());
}

#[test]
fn removing_a_block_at_a_location_leaves_a_mapping_that_moved_since() {
    let (index, _dir) = index();
    let plan = |segment_id: u64| GroupCommitPlan {
        appends: vec![SegmentAppend {
            segment_id,
            created: true,
            durable_end: SEGMENT_HEADER_LEN + 100,
            blocks: vec![NewBlockRow {
                hash: hash(1),
                record_offset: SEGMENT_HEADER_LEN,
                payload_len: 48,
                record_len: 100,
                added_at_nanos: 1,
            }],
        }],
        sealed: Vec::new(),
        next_segment_id: segment_id + 1,
    };
    index.commit_group(&plan(1), &no_injected_fault).unwrap();
    let stale = index.lookup(&hash(1)).unwrap().unwrap();
    assert_eq!(stale.segment_id, 1);

    // The mapping is replaced (retracted and rewritten into segment 2) after the caller looked.
    index.remove_blocks(&[hash(1)]).unwrap();
    index.commit_group(&plan(2), &no_injected_fault).unwrap();

    // Retracting by the stale location must not drop, or debit, the repaired mapping.
    index.remove_block_at(&hash(1), &stale).unwrap();
    assert_eq!(index.lookup(&hash(1)).unwrap().map(|l| l.segment_id), Some(2));
    assert_eq!(index.segment(2).unwrap().unwrap().live_blocks, 1);

    // By its current location it is retracted and the segment debited.
    let current = index.lookup(&hash(1)).unwrap().unwrap();
    index.remove_block_at(&hash(1), &current).unwrap();
    assert_eq!(index.lookup(&hash(1)).unwrap(), None);
    assert_eq!(index.segment(2).unwrap().unwrap().live_blocks, 0);
}

#[test]
fn a_hex_prefix_becomes_an_exact_raw_key_range() {
    let (low, high) = raw_key_range_for_hex_prefix("").unwrap();
    assert_eq!(low, [0x00; RAW_HASH_LEN]);
    assert_eq!(high, [0xFF; RAW_HASH_LEN]);

    // Odd length: only the high nibble of byte 1 is constrained.
    let (low, high) = raw_key_range_for_hex_prefix("ab3").unwrap();
    assert_eq!(low[0], 0xAB);
    assert_eq!(low[1], 0x30);
    assert_eq!(low[2], 0x00);
    assert_eq!(high[0], 0xAB);
    assert_eq!(high[1], 0x3F);
    assert_eq!(high[2], 0xFF);

    assert!(raw_key_range_for_hex_prefix("../etc").is_err());
}

#[test]
fn listing_by_prefix_returns_only_matching_hashes() {
    let (index, _dir) = index();
    let mut a = [0u8; RAW_HASH_LEN];
    a[0] = 0xAB;
    a[1] = 0x30;
    let mut b = [0u8; RAW_HASH_LEN];
    b[0] = 0xAB;
    b[1] = 0xF0;
    index
        .commit_group(
            &GroupCommitPlan {
                appends: vec![SegmentAppend {
                    segment_id: 1,
                    created: true,
                    durable_end: SEGMENT_HEADER_LEN + 200,
                    blocks: vec![
                        NewBlockRow {
                            hash: a,
                            record_offset: SEGMENT_HEADER_LEN,
                            payload_len: 48,
                            record_len: 100,
                            added_at_nanos: 1,
                        },
                        NewBlockRow {
                            hash: b,
                            record_offset: SEGMENT_HEADER_LEN + 100,
                            payload_len: 48,
                            record_len: 100,
                            added_at_nanos: 1,
                        },
                    ],
                }],
                sealed: Vec::new(),
                next_segment_id: 2,
            },
            &no_injected_fault,
        )
        .unwrap();

    assert_eq!(index.hashes_with_hex_prefix("").unwrap().len(), 2);
    assert_eq!(index.hashes_with_hex_prefix("ab").unwrap().len(), 2);
    assert_eq!(index.hashes_with_hex_prefix("ab3").unwrap(), vec![hex::encode(a)]);
    assert!(index.hashes_with_hex_prefix("cd").unwrap().is_empty());
}

#[test]
fn a_store_stamped_with_another_format_version_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("index.sqlite3");
    {
        let index = BlockIndex::open(&path).unwrap();
        index
            .db
            .write::<_, DatabaseError>(|conn| {
                conn.execute(
                    "UPDATE store_meta SET value = '99' WHERE key = 'format_version'",
                    [],
                )?;
                Ok(())
            })
            .unwrap();
    }
    let Err(err) = BlockIndex::open(&path) else {
        panic!("a store stamped with a foreign format version must not open");
    };
    assert!(
        matches!(&err, StorageError::Index(message) if message.contains("format version")),
        "unexpected error: {err}"
    );
}
