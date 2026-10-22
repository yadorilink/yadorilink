//! Scan-wide, cross-file bulk block ingestion for a reconciliation scan.
//!
//! # What this is for
//!
//! A reconciliation scan hashes every file it finds changed and has to make
//! those blocks durable before the rows and changes describing them can
//! commit. Doing that per file is what the block store's own batching
//! cannot fix from the inside: `chunk_file` commits per block, and
//! `chunk_file_content_defined_with_callback`/`chunk_file_fixed_with_
//! callback` batch only *within one file*, so a folder of small files —
//! where every file is one block — turns every batch into a one-block
//! batch. That is not a hypothetical shape; it is the ordinary one for a
//! source tree, and it was measured: importing 10,000 50-byte files cost
//! 9,286 `dir_fsync_first_shard` calls (27.97s of the 117.5s import), where
//! the store's two-level `root/aa/bb` layout only ever needs ~256 — one per
//! distinct `aa` prefix. `dir_fsync_root` firing exactly 256 times in the
//! same run is the corroboration: the prefixes really are 256-way, and the
//! other 9,030 fsyncs bought nothing.
//!
//! So the batch has to be pooled at a level that can see across file
//! boundaries, which is the scan. This type is that pool: blocks are hashed
//! by [`yadorilink_local_storage::hash_file_blocks`] (which commits
//! nothing), staged here as they are produced regardless of which file they
//! came from, and flushed in one `put_prepared_batch` when either bound
//! below is reached.
//!
//! What the store does with such a batch is its own business, and the
//! answer changed underneath this type: blocks that share a batch now also
//! share one durability barrier and one index transaction, where they used
//! to be one fsynced file each. This pool is what lets a folder of tiny
//! files reach the store as batches wide enough for that to matter at all
//! — without it, every batch is one block from one file, and there is
//! nothing to amortize.
//!
//! # The invariant this type must not break
//!
//! **No `FileRecord` and no native delta may become authoritative before
//! every block it references is durable.** Staging is what makes that
//! violable — a staged block is not durable, and the record describing it
//! is sitting in the scan's `prepared` set looking exactly as ready to
//! commit as it ever did.
//!
//! This type deliberately owns only half of that invariant, and it is the
//! half it can actually enforce: [`flush`](ScanBlockStaging::flush) does
//! not return `Ok` until `put_prepared_batch` has. The other half — that a
//! flush covering every staged block happens *before* the first commit —
//! lives at the single point in `local_change.rs` that can see both the
//! walk and the commit loop, and is asserted there. Anything that moves
//! block staging closer to the commit, or the commit closer to the walk,
//! has to re-establish it; it is not enforced by the type system.
//!
//! Group block provenance is recorded here, per flush, rather than per file
//! by the caller, for the same reason: provenance is a claim that this
//! device holds these blocks for this group, and recording it for a block
//! still sitting in this buffer would make that claim before it is true.

use yadorilink_local_storage::io_diag::{self, Op};
use yadorilink_local_storage::{BlockContentStore, LocallyHashedBlock};

use crate::error::LocalCaptureError;
use crate::ports::LocalMutationStore;

/// Blocks pooled before a flush. 4096 rather than the per-file batch size
/// because the whole point is to cross file boundaries: at one block per
/// file, this is 4096 files' worth of durability barriers collapsed into
/// one, which is the entire saving.
///
/// Matches the store's own default group-commit block bound, so a full
/// pool is exactly one group rather than one-and-a-bit. Not raised
/// further because the pool is memory this scan holds, and a batch wider
/// than the store's own bound only gets split again on arrival.
const SCAN_BULK_BLOCK_LIMIT: usize = 4096;

/// Bytes pooled before a flush, whichever bound is reached first. This is
/// the one that binds for large files: blocks scale to
/// `MAX_BLOCK_SIZE_BYTES` (16 MiB) each, so a 4096-block bound alone would
/// let this buffer reach tens of gigabytes. Sized to stay comfortably
/// inside the daemon's ordinary working set while still pooling thousands
/// of small-file blocks, which is where the barrier amortization is.
const SCAN_BULK_BYTE_LIMIT: usize = 32 * 1024 * 1024;

/// A reconciliation scan's cross-file block pool. One per scan; see the
/// module doc for the ordering obligation the caller keeps.
pub(crate) struct ScanBlockStaging<'a> {
    store: &'a dyn BlockContentStore,
    state: &'a dyn LocalMutationStore,
    group_id: &'a str,
    /// Staged, NOT durable. Every block here is one whose record must not
    /// reach a commit yet.
    pending: Vec<LocallyHashedBlock>,
    /// `pending`'s block hashes in raw (decoded) form, kept alongside so a
    /// flush records provenance without re-decoding every hash.
    pending_hashes: Vec<Vec<u8>>,
    pending_bytes: usize,
    flushes: u64,
    blocks_flushed: u64,
    bytes_flushed: u64,
}

impl<'a> ScanBlockStaging<'a> {
    pub(crate) fn new(
        store: &'a dyn BlockContentStore,
        state: &'a dyn LocalMutationStore,
        group_id: &'a str,
    ) -> Self {
        Self {
            store,
            state,
            group_id,
            pending: Vec::new(),
            pending_hashes: Vec::new(),
            pending_bytes: 0,
            flushes: 0,
            blocks_flushed: 0,
            bytes_flushed: 0,
        }
    }

    /// Takes one freshly hashed block. Flushes first if adding it would
    /// carry the pool past either bound, so the bounds are what this
    /// buffer actually holds rather than what it holds before the block
    /// that exceeded them.
    ///
    /// Returning `Ok` says nothing about durability — see the module doc.
    pub(crate) fn stage(
        &mut self,
        hash: &[u8],
        block: LocallyHashedBlock,
    ) -> Result<(), LocalCaptureError> {
        let bytes = block.bytes().len();
        if !self.pending.is_empty()
            && (self.pending.len() + 1 > SCAN_BULK_BLOCK_LIMIT
                || self.pending_bytes + bytes > SCAN_BULK_BYTE_LIMIT)
        {
            self.flush()?;
        }
        self.pending.push(block);
        self.pending_hashes.push(hash.to_vec());
        self.pending_bytes += bytes;
        Ok(())
    }

    /// Commits everything staged as one bulk batch and records the group
    /// block provenance for it. Returns `Ok` only once every block in the
    /// batch is durable — that is the whole contract this type provides.
    ///
    /// Provenance is written after the batch, never before: it is a claim
    /// that this device holds these blocks, and a failed flush must not
    /// leave one standing.
    pub(crate) fn flush(&mut self) -> Result<(), LocalCaptureError> {
        if self.pending.is_empty() {
            return Ok(());
        }
        let bytes = self.pending_bytes as u64;
        let blocks = self.pending.len() as u64;
        io_diag::time(Op::CommitBatch, bytes, || self.store.put_prepared_batch(&self.pending))?;
        self.state.record_group_block_provenance(self.group_id, &self.pending_hashes)?;
        self.pending.clear();
        self.pending_hashes.clear();
        self.pending_bytes = 0;
        self.flushes += 1;
        self.blocks_flushed += blocks;
        self.bytes_flushed += bytes;
        Ok(())
    }

    /// Whether anything is staged but not yet durable. The caller asserts
    /// this is false before it commits anything.
    pub(crate) fn has_staged_blocks(&self) -> bool {
        !self.pending.is_empty()
    }

    /// `(flushes, blocks, bytes)` actually committed through this pool, for
    /// the scan's own log line.
    pub(crate) fn flushed_totals(&self) -> (u64, u64, u64) {
        (self.flushes, self.blocks_flushed, self.bytes_flushed)
    }
}
