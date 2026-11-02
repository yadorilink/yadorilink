//! Writing a large received file while it arrives (single-pass receive).
//!
//! The file's temp is created beside its target before the first block is fetched. Each block that
//! arrives is checked against the hash it was requested under and written at its offset (or offsets,
//! when the file repeats a block), in any order, on the blocking pool. When every block is in, the
//! blocks the peer was not asked for (the block store already held them) are read from the store
//! and written the same way, and the file is completed: its data flushed and every range read back
//! against the record. Only then is it a ready temp that the settle may rename into place.

use std::collections::HashSet;
use std::sync::Arc;

use yadorilink_local_storage::{BlockContentStore, StagedFile, StorageError};
use yadorilink_replica_domain::file::FileRecord;

use super::filled_temps::ParkedTemp;
use super::reconcile::HeadroomReservation;

/// A file above this size is written while it arrives; smaller ones are held in memory for the pass
/// (see `window_blocks`).
pub(crate) const LARGE_FILE_MIN_BYTES: u64 = super::window_blocks::WINDOW_BLOCKS_FILE_MAX_BYTES;

/// The bytes written between two data flushes of the file while it fills.
pub(crate) const CHECKPOINT_BYTES: u64 = 64 * 1024 * 1024;

/// Flushes allowed in flight at once; a third waits for the oldest.
const MAX_FLUSHES_IN_FLIGHT: usize = 2;

pub(crate) struct LargeFileSink {
    pub(crate) staged: Arc<StagedFile>,
    pub(crate) reservation: Arc<HeadroomReservation>,
    /// Hashes already written at all their offsets.
    written: HashSet<Vec<u8>>,
    /// Bytes written since the last data flush was started.
    unflushed: u64,
    checkpoint_bytes: u64,
    /// Data flushes running on the blocking pool. Every one is awaited before the file is completed,
    /// and a failure of any of them is the file's failure.
    flushes: std::collections::VecDeque<tokio::task::JoinHandle<std::io::Result<()>>>,
}

/// Why a block could not be written.
#[derive(Debug)]
pub(crate) enum SinkError {
    Io(std::io::Error),
}

impl LargeFileSink {
    pub(crate) fn new(staged: StagedFile, reservation: Arc<HeadroomReservation>) -> Self {
        Self::with_checkpoint(staged, reservation, CHECKPOINT_BYTES)
    }

    pub(crate) fn with_checkpoint(
        staged: StagedFile,
        reservation: Arc<HeadroomReservation>,
        checkpoint_bytes: u64,
    ) -> Self {
        Self {
            staged: Arc::new(staged),
            reservation,
            written: HashSet::new(),
            unflushed: 0,
            checkpoint_bytes,
            flushes: std::collections::VecDeque::new(),
        }
    }

    /// A sink that goes on with a temp kept from an earlier attempt. Its claims are unverified
    /// until [`Self::verify_claims`] has run.
    pub(crate) fn resume(parked: ParkedTemp) -> Self {
        let ParkedTemp { staged, reservation, written, .. } = parked;
        Self {
            staged,
            reservation,
            written,
            unflushed: 0,
            checkpoint_bytes: CHECKPOINT_BYTES,
            flushes: std::collections::VecDeque::new(),
        }
    }

    /// Keeps the temp for a later attempt, or `None` when nothing was written into it.
    pub(crate) fn into_parked(self) -> Option<ParkedTemp> {
        if self.written.is_empty() {
            return None;
        }
        Some(ParkedTemp {
            staged: self.staged,
            reservation: self.reservation,
            written: self.written,
            parked_at: std::time::Instant::now(),
        })
    }

    /// Whether the block is already in the file (and, after [`Self::verify_claims`], read back).
    pub(crate) fn has_written(&self, hash: &[u8]) -> bool {
        self.written.contains(hash)
    }

    /// Reads back every block the earlier attempt claimed, at every offset the record gives it,
    /// and keeps only the claims whose bytes hash to the block. A temp that is no longer the file
    /// at its name keeps none.
    pub(crate) async fn verify_claims(&mut self, record: &FileRecord) -> bool {
        if self.written.is_empty() {
            return self.staged.is_still_at_its_path();
        }
        let claimed = std::mem::take(&mut self.written);
        let staged = Arc::clone(&self.staged);
        let blocks = record.blocks.clone();
        let verified = tokio::task::spawn_blocking(move || {
            if !staged.is_still_at_its_path() {
                return HashSet::new();
            }
            let mut by_hash: std::collections::HashMap<
                &[u8],
                Vec<&yadorilink_replica_domain::file::BlockInfo>,
            > = std::collections::HashMap::new();
            for block in &blocks {
                by_hash.entry(block.hash.as_slice()).or_default().push(block);
            }
            claimed
                .into_iter()
                .filter(|hash| {
                    by_hash
                        .get(hash.as_slice())
                        .is_some_and(|at| at.iter().all(|block| staged.block_matches(block)))
                })
                .collect::<HashSet<_>>()
        })
        .await
        .unwrap_or_default();
        self.written = verified;
        self.staged.is_still_at_its_path()
    }

    /// Starts a data flush of what has been written once enough has accumulated, without waiting
    /// for it: the fetch goes on while the disk works.
    async fn checkpoint(&mut self, written: u64) -> Result<(), SinkError> {
        self.unflushed += written;
        if self.unflushed < self.checkpoint_bytes {
            return Ok(());
        }
        self.unflushed = 0;
        while self.flushes.len() >= MAX_FLUSHES_IN_FLIGHT {
            self.await_oldest_flush().await?;
        }
        let staged = Arc::clone(&self.staged);
        self.flushes.push_back(tokio::task::spawn_blocking(move || staged.flush_data()));
        Ok(())
    }

    async fn await_oldest_flush(&mut self) -> Result<(), SinkError> {
        let Some(handle) = self.flushes.pop_front() else { return Ok(()) };
        match handle.await {
            Ok(result) => result.map_err(SinkError::Io),
            Err(error) => Err(SinkError::Io(std::io::Error::other(error.to_string()))),
        }
    }

    /// Writes `block` at every offset of `record` that names its hash. The block was shown to be
    /// the block asked for when it was fetched and is not hashed again here. The writes run on the
    /// blocking pool; the write job owns a clone of the staged file, so dropping this future cannot
    /// let the file be removed under it.
    pub(crate) async fn write_block(
        &mut self,
        record: &FileRecord,
        block: &yadorilink_local_storage::VerifiedBlock,
    ) -> Result<(), SinkError> {
        let hash = block.raw_hash();
        let offsets: Vec<u64> = record
            .blocks
            .iter()
            .filter(|listed| listed.hash == hash)
            .map(|listed| listed.offset)
            .collect();
        let data_len = block.bytes().len() as u64;
        let staged = Arc::clone(&self.staged);
        let bytes = block.bytes_arc();
        let outcome = tokio::task::spawn_blocking(move || {
            for offset in offsets {
                yadorilink_local_storage::io_diag::time(
                    yadorilink_local_storage::io_diag::Op::SinkWrite,
                    bytes.len() as u64,
                    || staged.write_at(offset, &bytes),
                )
                .map_err(SinkError::Io)?;
            }
            Ok(())
        })
        .await
        .map_err(|error| SinkError::Io(std::io::Error::other(error.to_string())))?;
        if outcome.is_ok() {
            self.written.insert(hash.to_vec());
            self.checkpoint(data_len).await?;
        }
        outcome
    }

    /// Writes the blocks that were not fetched (read from `store`, checked) and completes the file.
    pub(crate) async fn finalize(
        &mut self,
        store: Arc<dyn BlockContentStore>,
        record: &FileRecord,
    ) -> Result<(), StorageError> {
        let missing: Vec<(Vec<u8>, Vec<u64>)> = {
            let mut seen = HashSet::new();
            record
                .blocks
                .iter()
                .filter(|block| !self.written.contains(&block.hash) && seen.insert(&block.hash))
                .map(|block| {
                    let offsets = record
                        .blocks
                        .iter()
                        .filter(|other| other.hash == block.hash)
                        .map(|other| other.offset)
                        .collect();
                    (block.hash.clone(), offsets)
                })
                .collect()
        };
        // The flushes started while the file filled have finished, and none of them failed.
        while !self.flushes.is_empty() {
            match self.await_oldest_flush().await {
                Ok(()) => {}
                Err(SinkError::Io(error)) => return Err(StorageError::Io(error)),
            }
        }
        let blocks = record.blocks.clone();
        let mtime = record.mtime_unix_nanos;
        let staged = Arc::clone(&self.staged);
        tokio::task::spawn_blocking(move || -> Result<(), StorageError> {
            for (hash, offsets) in missing {
                let hash_hex = hex::encode(&hash);
                // `get` checks what it reads against the block's hash (the store verifies at
                // rest, and a block the window holds was verified when it was fetched), so the
                // bytes are not hashed a second time here.
                let data = store.get(&hash_hex)?;
                for offset in offsets {
                    staged.write_at(offset, &data)?;
                }
            }
            staged.finish(&blocks, mtime)
        })
        .await
        .map_err(|error| StorageError::Io(std::io::Error::other(error.to_string())))?
    }
}
