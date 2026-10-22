//! Reclaiming the space a deleted block leaves behind.
//!
//! Deleting a block drops its mapping and debits its segment; it moves no
//! bytes, because a segment is immutable below `durable_end` and rewriting
//! it in place would break every reader currently `pread`ing it. Space
//! comes back later, in bulk, by copying whatever is still live out of a
//! mostly-dead segment and retiring the original.
//!
//! # Crash semantics, by construction
//!
//! The copies are appended and fsynced through the *same* single writer
//! and the *same* ordering an ingest commit uses, and the mapping swap is
//! one transaction. That gives four windows, and a valid copy is reachable
//! from the index in all of them:
//!
//! | crash point | index points at | file state |
//! |---|---|---|
//! | during the copy | the old segment | new segment holds unreferenced bytes |
//! | after the new segment's `fsync`, before the swap | the old segment | both copies durable, new one orphaned |
//! | after the swap, before the old file is deleted | the new segment | both copies present, old one retired |
//! | after the delete | the new segment | only the new copy |
//!
//! Recovery cleans up rows one and two by truncating the orphan tail, and
//! row three by deleting retired files. None of them can leave a mapping
//! without bytes.
//!
//! # Races with readers
//!
//! A reader holds no lock and may be mid-`pread` on a segment that is
//! being retired underneath it. On Unix an already-open descriptor keeps
//! working after the unlink, so that reader finishes normally. The window
//! that remains is narrow and specific -- a reader that resolved a mapping
//! *before* the swap and opens the file *after* the delete -- and `get`
//! closes it by re-resolving the mapping and retrying rather than by
//! locking anything. On Windows a delete can fail outright while a handle
//! is open; that is not an error condition here, it just means the file is
//! reclaimed on a later pass.

use std::sync::Arc;

use crate::error::StorageError;
use crate::io_diag::{self, Op};
use crate::segment_store::coordinator::DurabilityCoordinator;
use crate::segment_store::format::RAW_HASH_LEN;
use crate::segment_store::index::{BlockIndex, SegmentRow, SegmentState};
use crate::traits::ContentHash;

/// A sealed segment is worth rewriting once this much of it is dead *and*
/// the absolute saving is worth the copy. Both bounds are needed: a ratio
/// alone would rewrite a 4 KiB segment forever, and a byte threshold alone
/// would rewrite a nearly-full 1 GiB segment to reclaim 64 MiB.
pub const COMPACTION_DEAD_RATIO: f64 = 0.5;
pub const COMPACTION_MIN_DEAD_BYTES: u64 = 64 * 1024 * 1024;

/// What one compaction pass moved and freed.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CompactionReport {
    pub segments_compacted: u64,
    pub blocks_relocated: u64,
    pub bytes_reclaimed: u64,
    /// Mappings dropped because the live block they named could not be
    /// read back out of the segment being compacted. A compaction is the
    /// one place the whole store gets re-read, so it is also where latent
    /// corruption surfaces.
    pub unreadable_blocks_dropped: u64,
}

/// Segments worth rewriting, worst first. Never the active segment: it is
/// still being appended to, and its dead ratio is not yet meaningful.
pub(crate) fn candidates(
    index: &BlockIndex,
    dead_ratio: f64,
    min_dead_bytes: u64,
) -> Result<Vec<SegmentRow>, StorageError> {
    let mut rows: Vec<SegmentRow> = index
        .segments()?
        .into_iter()
        .filter(|row| row.state == SegmentState::Sealed)
        .filter(|row| row.dead_bytes() >= min_dead_bytes && row.dead_ratio() >= dead_ratio)
        .collect();
    rows.sort_by_key(|row| std::cmp::Reverse(row.dead_bytes()));
    Ok(rows)
}

/// How many of a segment's live blocks one relocation transaction carries,
/// and how many of their bytes it holds in memory at once.
///
/// Both bounds matter, for the same reason the group commit needs both: a
/// segment of tiny blocks reaches the count first and a segment of large
/// ones reaches the byte budget first. Without them, compacting a 1 GiB
/// segment would mean holding a gigabyte of payloads and millions of index
/// rows in memory to rewrite it in one shot.
const RELOCATION_BATCH_BLOCKS: usize = 2048;
const RELOCATION_BATCH_BYTES: u64 = 32 * 1024 * 1024;

/// Rewrites one segment's live blocks into fresh storage and retires it.
///
/// `read_block` is the store's own verified read, passed in rather than
/// reached for, so compaction cannot copy bytes the read path would have
/// rejected: a block that does not read back cleanly is dropped from the
/// index here instead of being propagated into a new segment.
///
/// The rewrite happens in bounded batches, each a complete relocation
/// transaction of its own. A crash between batches therefore leaves some
/// of the segment's blocks pointing at their new copies and the rest at
/// their originals -- every one of them valid, which is exactly the
/// property a single-transaction rewrite would also have had, without the
/// memory cost. The source is retired only once nothing live points into
/// it, which the retirement's own `live_blocks = 0` guard enforces inside
/// the transaction rather than from this side of it.
pub(crate) fn compact_segment(
    index: &Arc<BlockIndex>,
    coordinator: &DurabilityCoordinator,
    segment_id: u64,
    mut read_block: impl FnMut(&ContentHash) -> Result<Vec<u8>, StorageError>,
) -> Result<CompactionReport, StorageError> {
    let Some(row) = index.segment(segment_id)? else { return Ok(CompactionReport::default()) };
    if row.state == SegmentState::Active {
        return Ok(CompactionReport::default());
    }
    let mut report = CompactionReport { segments_compacted: 1, ..CompactionReport::default() };
    let reclaimable =
        row.durable_end.saturating_sub(crate::segment_store::format::SEGMENT_HEADER_LEN);

    let mut cursor: Option<u64> = None;
    loop {
        let live = index.live_blocks_in_segment(segment_id, cursor, RELOCATION_BATCH_BLOCKS)?;
        if live.is_empty() {
            break;
        }
        cursor = live.last().map(|(_, location)| location.record_offset);

        let mut payloads: Vec<(ContentHash, [u8; RAW_HASH_LEN], Vec<u8>)> = Vec::new();
        let mut payload_bytes = 0u64;
        for (raw, location) in &live {
            let hex_hash = hex::encode(raw);
            match io_diag::time(Op::CompactionRead, u64::from(location.length), || {
                read_block(&hex_hash)
            }) {
                Ok(payload) => {
                    payload_bytes += payload.len() as u64;
                    payloads.push((hex_hash, *raw, payload));
                }
                Err(StorageError::NotFound(_)) => {
                    // Deleted between the page and now, or already
                    // self-healed away by the read path. Either way there
                    // is nothing left to relocate.
                    report.unreadable_blocks_dropped += 1;
                }
                Err(StorageError::ChecksumMismatch { .. } | StorageError::CorruptStore(_)) => {
                    index.remove_block_at(raw, location)?;
                    report.unreadable_blocks_dropped += 1;
                }
                Err(other) => return Err(other),
            }
            if payload_bytes >= RELOCATION_BATCH_BYTES {
                // Stop short of the page's end rather than growing past
                // the byte budget; the next iteration resumes from here.
                cursor = Some(location.record_offset);
                break;
            }
        }

        if payloads.is_empty() {
            continue;
        }
        let moved = coordinator.with_writer_leadership(|coordinator, handle| {
            coordinator.commit_relocation(handle, &[segment_id], &payloads)
        })?;
        report.blocks_relocated += moved as u64;
    }

    // Retire the source whether or not anything moved: a segment whose
    // blocks were all deleted has nothing to relocate and is exactly the
    // one most worth reclaiming. The guard inside the transaction is what
    // makes this safe against a block that landed in the meantime.
    index.retire_empty_segment(segment_id)?;
    report.bytes_reclaimed = reclaimable;
    Ok(report)
}

/// Deletes the files of segments the index has already retired, then
/// forgets their rows. Idempotent and retryable -- a file that cannot be
/// removed right now (an open handle on Windows) simply stays retired
/// until the next pass or the next open.
pub(crate) fn reclaim_retired_segments(
    root: &std::path::Path,
    index: &BlockIndex,
    may_delete: impl Fn() -> Result<(), StorageError>,
    remove: impl Fn(&std::path::Path) -> Result<std::io::Result<()>, StorageError>,
    mut evict_reader: impl FnMut(u64),
) -> Result<u64, StorageError> {
    let retired: Vec<u64> = index
        .segments()?
        .into_iter()
        .filter(|row| row.state == SegmentState::Retired)
        .map(|row| row.segment_id)
        .collect();
    let mut removed = 0;
    for segment_id in retired {
        may_delete()?;
        evict_reader(segment_id);
        let path = crate::segment_store::segment::segment_path(root, segment_id);
        match remove(&path)? {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            // Still referenced by an open handle (Windows), or a transient
            // failure. Retiring is durable; reclaiming is not urgent.
            Err(_) => continue,
        }
        index.forget_segment(segment_id)?;
        removed += 1;
    }
    if removed > 0 {
        crate::fs_ops::sync_directory(&root.join(crate::segment_store::segment::SEGMENTS_DIR))?;
    }
    Ok(removed)
}
