//! What opening a store does, and deliberately does not do.
//!
//! **Does not**: read a single payload byte, hash anything, or rebuild the
//! index. The index *is* the metadata; re-deriving it from the segments
//! would make startup cost proportional to the bytes the store holds,
//! which is the specific failure the earlier packed-store prototype had
//! and the reason it could never be the canonical store.
//!
//! **Does**: reconcile each segment's physical length against the
//! `durable_end` the index recorded for it, and resolve the three
//! discrepancies a crash can leave.
//!
//! | on disk vs. index | what it means | what happens |
//! |---|---|---|
//! | `len > durable_end` | bytes were appended (perhaps fsynced) but their transaction never committed | truncate the orphan tail |
//! | `len == durable_end` | clean | nothing |
//! | `len < durable_end` | the file lost bytes the index still points at | drop exactly the mappings that no longer fit, and say so |
//! | file absent, index row present | the file was lost | drop every mapping in it |
//! | file present, no index row | a segment was created by a group that never committed | delete it |
//!
//! The third and fourth rows are the self-healing ones. Refusing to start
//! would be the wrong kind of fail-closed: the blocks are re-fetchable
//! from any peer that has them, and a store that cannot start cannot
//! re-fetch anything. What matters is that the store never *claims* a
//! block it cannot serve -- so the mappings go, `present_blocks` and `get`
//! agree again, and the layer above re-acquires the content.
//!
//! Cost is `O(number of segments)` metadata operations plus, only when
//! damage is found, one index query over the damaged segment's own rows.

use std::collections::BTreeMap;
use std::path::Path;

use crate::error::StorageError;
use crate::fs_ops::sync_directory;
use crate::segment_store::format::SEGMENT_HEADER_LEN;
use crate::segment_store::index::{BlockIndex, SegmentState};
use crate::segment_store::segment::{
    segment_id_from_file_name, segment_id_from_stage_name, segment_path, SegmentWriter,
    SEGMENTS_DIR,
};

/// What opening the store had to repair, for the log line and for tests
/// that assert a specific crash left a specific trace.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RecoveryReport {
    /// Segments whose physical tail ran past `durable_end` and was cut
    /// back -- the ordinary shape of a crash mid-append or after an
    /// `fsync` whose transaction never landed.
    pub truncated_segments: Vec<u64>,
    /// Bytes discarded by those truncations.
    pub truncated_bytes: u64,
    /// Segment files that no committed transaction ever referenced, and
    /// were therefore removed.
    pub removed_orphan_segments: Vec<u64>,
    /// Segments whose file was missing or short, and the mappings dropped
    /// because of it. Non-zero here is real data loss on this device --
    /// recoverable by re-fetching, but never silent.
    pub damaged_segments: Vec<u64>,
    pub dropped_mappings: u64,
    /// Retired segments whose files were deleted on this open.
    pub reclaimed_segments: Vec<u64>,
}

impl RecoveryReport {
    pub fn is_clean(&self) -> bool {
        self.truncated_segments.is_empty()
            && self.removed_orphan_segments.is_empty()
            && self.damaged_segments.is_empty()
            && self.reclaimed_segments.is_empty()
    }
}

/// What a completed recovery hands the store: the repairs it made and the
/// next segment id to hand out.
///
/// Deliberately no "segment to resume": opening always seals whatever was
/// active, so the first group after an open creates its own segment. See
/// the sealing step below for why.
pub(crate) struct RecoveredStore {
    pub(crate) report: RecoveryReport,
    pub(crate) next_segment_id: u64,
}

/// `may_delete` is asked immediately before every unlink or truncation and fails the open when the
/// volume is not known durable.
pub(crate) fn recover(
    root: &Path,
    index: &BlockIndex,
    may_delete: impl Fn() -> Result<(), StorageError>,
    remove: impl Fn(&Path) -> Result<std::io::Result<()>, StorageError>,
) -> Result<RecoveredStore, StorageError> {
    let mut report = RecoveryReport::default();
    let on_disk = enumerate_segment_files(root)?;
    let rows = index.segments()?;

    let mut highest_id = on_disk.keys().copied().max().unwrap_or(0);
    let mut deleted_any_file = false;

    for row in &rows {
        highest_id = highest_id.max(row.segment_id);
        let path = segment_path(root, row.segment_id);
        let present = on_disk.contains_key(&row.segment_id);

        if row.state == SegmentState::Retired {
            // Retirement is decided durably, in the transaction that
            // emptied the segment. Removing the file is the only part left,
            // and it is safe to retry on any later open.
            if present {
                may_delete()?;
            }
            if present && remove(&path)?.is_err() {
                continue;
            }
            deleted_any_file |= present;
            index.forget_segment(row.segment_id)?;
            report.reclaimed_segments.push(row.segment_id);
            continue;
        }

        let Some(&file_len) = on_disk.get(&row.segment_id) else {
            let dropped = index.drop_segment_mappings(row.segment_id)?;
            index.forget_segment(row.segment_id)?;
            report.damaged_segments.push(row.segment_id);
            report.dropped_mappings += dropped;
            tracing::error!(
                segment_id = row.segment_id,
                dropped_mappings = dropped,
                "block-store segment file is missing; its blocks are now reported absent \
                 and must be re-acquired"
            );
            continue;
        };

        if file_len > row.durable_end {
            // The tail past `durable_end` is, by the commit ordering,
            // referenced by nothing: either its transaction never
            // committed or it was never even fsynced. Cutting it back is
            // what keeps the file's length and the index's claim equal.
            may_delete()?;
            let mut writer = SegmentWriter::reopen(root, row.segment_id, file_len)?;
            writer.truncate(row.durable_end)?;
            report.truncated_segments.push(row.segment_id);
            report.truncated_bytes += file_len - row.durable_end;
        } else if file_len < row.durable_end {
            let dropped = index.repair_segment_to_length(row.segment_id, file_len)?;
            report.damaged_segments.push(row.segment_id);
            report.dropped_mappings += dropped;
            tracing::error!(
                segment_id = row.segment_id,
                file_len,
                recorded_durable_end = row.durable_end,
                dropped_mappings = dropped,
                "block-store segment is shorter than its index recorded; the mappings that no \
                 longer fit are now reported absent and must be re-acquired"
            );
        }
    }

    // A segment file no committed transaction ever mentioned cannot be
    // referenced by anything, so it is removable without further proof.
    let known: std::collections::HashSet<u64> = rows.iter().map(|row| row.segment_id).collect();
    for &segment_id in on_disk.keys() {
        if known.contains(&segment_id) {
            continue;
        }
        may_delete()?;
        if remove(&segment_path(root, segment_id))?.is_ok() {
            deleted_any_file = true;
            report.removed_orphan_segments.push(segment_id);
        }
    }
    // A segment a crash left under its Stage name, before it was published: no
    // committed transaction mentions its id, so nothing refers to it.
    for stage in staged_segment_files(root)? {
        if known.contains(&stage.0) {
            continue;
        }
        may_delete()?;
        if remove(&stage.1)?.is_ok() {
            deleted_any_file = true;
            highest_id = highest_id.max(stage.0);
        }
    }
    if deleted_any_file {
        // Make the unlinks themselves durable, so a crash right here does
        // not resurrect a file this open already accounted as gone.
        sync_directory(&root.join(SEGMENTS_DIR))?;
    }

    let next_segment_id = index.recorded_next_segment_id()?.max(highest_id + 1);

    // Opening never resumes appending to a segment a previous handle had
    // open: whatever was active is sealed, and the first group after this
    // starts a fresh one.
    //
    // Resuming would be a little tidier on disk and is how this started,
    // but it makes the one genuinely destructive overlap possible. Two
    // handles on one root -- a restart where the outgoing store has not
    // finished dropping, a misconfiguration that aims two daemons at one
    // directory -- would both reopen the same segment at the same offset
    // and overwrite each other's records. Refusing the second open was
    // tried and is worse: an `Arc` that outlives a `drop` by a moment is
    // an ordinary thing for a restart to do, and it turned that into a
    // hard failure at exactly the moment the old handle was going away.
    //
    // Sealing costs the tail of one segment per open and removes the
    // shared append target entirely. An empty one left by an open that
    // wrote nothing is retired below rather than accumulating.
    for row in rows.iter().filter(|row| row.state == SegmentState::Active) {
        if row.live_blocks == 0 && row.durable_end <= SEGMENT_HEADER_LEN {
            index.retire_empty_segment(row.segment_id)?;
        } else {
            index.set_segment_state(row.segment_id, SegmentState::Sealed)?;
        }
    }
    // Segments that hold nothing live -- emptied by deletion, or opened by
    // a run that never committed a block -- have no reason to exist. Their
    // files go on the next reclamation pass.
    for row in rows.iter().filter(|row| row.state != SegmentState::Retired) {
        if row.live_blocks == 0 {
            index.retire_empty_segment(row.segment_id)?;
        }
    }

    Ok(RecoveredStore { report, next_segment_id })
}

/// Every segment file waiting under its Stage name, with the segment id it was
/// made for.
fn staged_segment_files(root: &Path) -> Result<Vec<(u64, std::path::PathBuf)>, StorageError> {
    let dir = root.join(SEGMENTS_DIR);
    let entries = match std::fs::read_dir(&dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(StorageError::Io(e)),
    };
    let mut out = Vec::new();
    for entry in entries {
        let entry = entry?;
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else { continue };
        if let Some(id) = segment_id_from_stage_name(&name) {
            out.push((id, entry.path()));
        }
    }
    Ok(out)
}

/// Every `segments/NNNNNNNNNNNNNNNN.seg` and its length. Entries that do
/// not match the naming scheme are ignored rather than deleted -- the
/// store never removes a file it does not recognise as its own.
pub(crate) fn enumerate_segment_files(root: &Path) -> Result<BTreeMap<u64, u64>, StorageError> {
    let mut out = BTreeMap::new();
    let dir = root.join(SEGMENTS_DIR);
    let entries = match std::fs::read_dir(&dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(out),
        Err(e) => return Err(StorageError::Io(e)),
    };
    for entry in entries {
        let entry = entry?;
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else { continue };
        let Some(segment_id) = segment_id_from_file_name(&name) else { continue };
        let metadata = entry.metadata()?;
        if metadata.is_file() {
            out.insert(segment_id, metadata.len());
        }
    }
    Ok(out)
}
