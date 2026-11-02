//! Keeping the replaced versions of many files with one durable commit.
//!
//! A sync that replaces a file whose bytes are not in the block store first reads the old file
//! into the store (see `version_retention`). A window of a bulk receive replaces many such files
//! at once, and doing it file by file costs a durable store commit and a provenance transaction
//! for each. Here the files that ask within a few milliseconds of each other are served by one
//! background drain: it reads and verifies each file's blocks, puts the blocks of a group of
//! files into the store in one durable batch (the limits of a receive commit), records their
//! provenance once, and only then answers each file.
//!
//! What a file is told:
//!
//! - `InStore` only after every one of its blocks is in a batch whose store commit and provenance
//!   record both succeeded. A batch that fails answers every file in it with that failure, so
//!   none of them is claimed kept and the replacement waits for a later attempt, exactly as a
//!   failure of a single file's ingest does.
//! - A file whose bytes are not the version (a different length, or a block that does not hash to
//!   what the version lists) is not read into the store: it holds no bytes of that version here
//!   (`NoLocalBytes`), as when it is ingested alone. The blocks are checked when they are read,
//!   not when the batch was planned.
//!
//! The drain owns nothing a caller holds: a caller that stops waiting only closes its reply
//! channel, and the drain skips a request whose channel is closed before reading its file.
//! Memory is one batch plus the file being read; at most one old file is open at a time. A file
//! with more blocks or bytes than a batch is ingested alone in bounded batches.

use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::sync::oneshot;
use yadorilink_local_storage::{
    BlockContentStore, LocallyHashedBlock, StorageError, VerifiedBlock,
};
use yadorilink_peer_session::PeerSessionError;
use yadorilink_replica_domain::file::BlockInfo;
use yadorilink_sync_sqlite::retention::{RetentionProof, SupersededRow};

use super::version_retention::{ingest_in_batches, IngestOutcome, ProofError};
use crate::replica_coordinator::ReplicaCoordinator;

/// How long the first request waits for others to join its batch.
const COALESCE: Duration = Duration::from_millis(2);

/// The most files a batch holds open at once. A file stays open until its batch is durable, so
/// that its length can be looked at once more before it is reported kept.
const MAX_FILES_PER_BATCH: usize = 64;

pub(crate) struct RetentionRequest {
    pub(crate) group: String,
    pub(crate) path: String,
    pub(crate) row: SupersededRow,
    pub(crate) blocks: Vec<BlockInfo>,
    pub(crate) out_path: std::path::PathBuf,
}

pub(crate) type RetentionReply = Result<RetentionProof, ProofError<PeerSessionError>>;

struct Queued {
    request: RetentionRequest,
    reply: oneshot::Sender<RetentionReply>,
}

#[derive(Default)]
struct QueueState {
    pending: Vec<Queued>,
    draining: bool,
}

pub(crate) struct RetentionIngestQueue {
    store: Arc<dyn BlockContentStore>,
    state: Arc<ReplicaCoordinator>,
    queue: Mutex<QueueState>,
    batch_blocks: usize,
    batch_bytes: u64,
}

impl RetentionIngestQueue {
    pub(crate) fn new(
        store: Arc<dyn BlockContentStore>,
        state: Arc<ReplicaCoordinator>,
    ) -> Arc<Self> {
        Self::with_limits(
            store,
            state,
            super::types::Tuning::RECEIVE_COMMIT_BATCH_BLOCKS,
            super::types::Tuning::RECEIVE_COMMIT_BATCH_BYTES,
        )
    }

    pub(crate) fn with_limits(
        store: Arc<dyn BlockContentStore>,
        state: Arc<ReplicaCoordinator>,
        batch_blocks: usize,
        batch_bytes: u64,
    ) -> Arc<Self> {
        Arc::new(Self {
            store,
            state,
            queue: Mutex::new(QueueState::default()),
            batch_blocks,
            batch_bytes,
        })
    }

    /// Reads the file of `request` into the store as part of a batch and answers once the batch
    /// is decided.
    pub(crate) async fn ingest(self: &Arc<Self>, request: RetentionRequest) -> RetentionReply {
        let (reply, answer) = oneshot::channel();
        let start_drain = {
            let mut queue = self.queue.lock().unwrap_or_else(|p| p.into_inner());
            queue.pending.push(Queued { request, reply });
            !std::mem::replace(&mut queue.draining, true)
        };
        if start_drain {
            let queue = Arc::clone(self);
            tokio::spawn(async move { queue.drain().await });
        }
        answer.await.unwrap_or_else(|_| {
            Err(ProofError::Store(StorageError::Io(std::io::Error::other(
                "the retention ingest ended before it answered",
            ))))
        })
    }

    async fn drain(self: Arc<Self>) {
        tokio::time::sleep(COALESCE).await;
        loop {
            let mut taken = {
                let mut queue = self.queue.lock().unwrap_or_else(|p| p.into_inner());
                if queue.pending.is_empty() {
                    queue.draining = false;
                    return;
                }
                std::mem::take(&mut queue.pending)
            };
            taken.retain(|queued| !queued.reply.is_closed());
            // A fixed order, so that what a failing or full volume does to a window does not
            // depend on which task happened to ask first.
            taken.sort_by(|a, b| {
                (a.request.group.as_str(), a.request.path.as_str())
                    .cmp(&(b.request.group.as_str(), b.request.path.as_str()))
            });
            let queue = Arc::clone(&self);
            // A panic in the batch drops its reply channels: each file then sees an error.
            let _ = tokio::task::spawn_blocking(move || queue.process(taken)).await;
        }
    }

    fn process(&self, taken: Vec<Queued>) {
        let mut batch = Batch::default();
        for queued in taken {
            if queued.reply.is_closed() {
                continue;
            }
            // Before this file is opened, so that no more than the limit are ever open at once.
            if batch.files.len() >= MAX_FILES_PER_BATCH {
                self.flush(&mut batch);
            }
            if batch.group.as_deref().is_some_and(|group| group != queued.request.group) {
                self.flush(&mut batch);
            }
            match self.read_version(&queued.request) {
                Read::Answer(reply) => {
                    let _ = queued.reply.send(reply);
                }
                Read::TooLarge(file) => {
                    // Alone, in bounded batches of its own, after what is waiting is durable.
                    self.flush(&mut batch);
                    let _ = queued.reply.send(self.ingest_alone(&queued.request, &file));
                }
                Read::Verified(blocks, file, expected_len) => {
                    let new_blocks = blocks
                        .iter()
                        .filter(|block| !batch.hashes.contains(block.hash().as_bytes()))
                        .count();
                    let new_bytes: u64 = blocks
                        .iter()
                        .filter(|block| !batch.hashes.contains(block.hash().as_bytes()))
                        .map(|block| block.bytes().len() as u64)
                        .sum();
                    if batch.blocks.len() + new_blocks > self.batch_blocks
                        || batch.bytes + new_bytes > self.batch_bytes
                    {
                        self.flush(&mut batch);
                    }
                    batch.group = Some(queued.request.group.clone());
                    for block in blocks {
                        if batch.hashes.insert(block.hash().as_bytes().to_vec()) {
                            batch.bytes += block.bytes().len() as u64;
                            batch.blocks.push(block);
                        }
                    }
                    batch.files.push(BatchedFile {
                        row: queued.request.row.clone(),
                        file,
                        expected_len,
                        reply: queued.reply,
                    });
                }
            }
        }
        self.flush(&mut batch);
    }

    fn ingest_alone(&self, request: &RetentionRequest, file: &std::fs::File) -> RetentionReply {
        let state = &self.state;
        let record =
            |hashes: &[Vec<u8>]| state.record_retained_blocks_provenance(&request.group, hashes);
        match ingest_in_batches(
            self.store.as_ref(),
            file,
            &request.blocks,
            &record,
            self.batch_blocks,
            self.batch_bytes,
        )? {
            IngestOutcome::Ingested => Ok(RetentionProof::InStore(request.row.clone())),
            IngestOutcome::NotTheVersion => Ok(RetentionProof::NoLocalBytes(request.row.clone())),
        }
    }

    /// Reads and checks the blocks of the version from its file, one file open at a time.
    fn read_version(&self, request: &RetentionRequest) -> Read {
        use crate::file_block_source::{open_source, Opened};
        let file = match open_source(&request.out_path) {
            Opened::File(file) => file,
            Opened::Gone => {
                return Read::Answer(Ok(RetentionProof::NoLocalBytes(request.row.clone())))
            }
            Opened::Unavailable => return Read::Answer(Err(ProofError::FileUnavailable)),
        };
        let no_bytes = || Read::Answer(Ok(RetentionProof::NoLocalBytes(request.row.clone())));
        let expected_len = request
            .blocks
            .iter()
            .map(|block| block.offset + u64::from(block.size))
            .max()
            .unwrap_or(0);
        let length_is_the_versions = |file: &std::fs::File| -> Result<bool, std::io::Error> {
            Ok(file.metadata()?.len() == expected_len)
        };
        match length_is_the_versions(&file) {
            Ok(true) => {}
            Ok(false) => return no_bytes(),
            Err(error) => return Read::Answer(Err(ProofError::Read(error))),
        }
        let mut seen = HashSet::new();
        let (distinct_blocks, distinct_bytes) = request
            .blocks
            .iter()
            .filter(|block| seen.insert(block.hash.as_slice()))
            .fold((0usize, 0u64), |(blocks, bytes), block| {
                (blocks + 1, bytes + u64::from(block.size))
            });
        if distinct_blocks > self.batch_blocks || distinct_bytes > self.batch_bytes {
            return Read::TooLarge(file);
        }
        let mut verified: Vec<LocallyHashedBlock> = Vec::with_capacity(distinct_blocks);
        let mut have = HashSet::new();
        for block in &request.blocks {
            let mut bytes = vec![0u8; block.size as usize];
            match read_exact_at(&file, &mut bytes, block.offset) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => {
                    return no_bytes();
                }
                Err(error) => return Read::Answer(Err(ProofError::Read(error))),
            }
            let Ok(checked) = VerifiedBlock::check(&bytes, &block.hash, block.size) else {
                return no_bytes();
            };
            drop(bytes);
            if have.insert(block.hash.as_slice()) {
                verified.push(checked.into_hashed());
            }
        }
        match length_is_the_versions(&file) {
            Ok(true) => Read::Verified(verified, file, expected_len),
            Ok(false) => no_bytes(),
            Err(error) => Read::Answer(Err(ProofError::Read(error))),
        }
    }

    /// Makes the batch durable, then records its provenance, then answers its files.
    fn flush(&self, batch: &mut Batch) {
        let files = std::mem::take(&mut batch.files);
        let blocks = std::mem::take(&mut batch.blocks);
        let bytes = std::mem::take(&mut batch.bytes);
        let group = batch.group.take();
        batch.hashes.clear();
        if files.is_empty() {
            return;
        }
        let started = std::time::Instant::now();
        let outcome: Result<(), ProofError<PeerSessionError>> = if blocks.is_empty() {
            Ok(())
        } else {
            let hashes: Vec<Vec<u8>> =
                blocks.iter().map(|block| block.hash().as_bytes().to_vec()).collect();
            // The provenance is recorded only for blocks that are durable.
            self.store.put_prepared_batch(&blocks).map_err(ProofError::Store).and_then(|()| {
                let group = group.as_deref().unwrap_or_default();
                // `hash()` is the hex text; the index keys on the raw digest.
                let raw: Vec<Vec<u8>> =
                    hashes.iter().filter_map(|hex_text| decode_hex(hex_text)).collect();
                self.state
                    .record_retained_blocks_provenance(group, &raw)
                    .map_err(ProofError::Provenance)
            })
        };
        crate::receive_diag::record_retention_ingest(
            files.len(),
            blocks.len(),
            bytes,
            started.elapsed().as_nanos() as u64,
        );
        for BatchedFile { row, file, expected_len, reply } in files {
            let answer = match &outcome {
                // The length is looked at again once the bytes are durable: a file that grew or
                // shrank while its batch was being read and committed is not reported as the
                // version (a block overwritten in place is the residual the caller's identity
                // check before the rename covers).
                Ok(()) => match file.metadata() {
                    Ok(metadata) if metadata.len() == expected_len => {
                        Ok(RetentionProof::InStore(row))
                    }
                    Ok(_) => Ok(RetentionProof::NoLocalBytes(row)),
                    Err(error) => Err(ProofError::Read(error)),
                },
                Err(error) => Err(duplicate(error)),
            };
            let _ = reply.send(answer);
        }
    }
}

fn decode_hex(text: &[u8]) -> Option<Vec<u8>> {
    hex::decode(text).ok()
}

/// The same failure for each file of a failed batch.
fn duplicate(error: &ProofError<PeerSessionError>) -> ProofError<PeerSessionError> {
    match error {
        ProofError::Store(StorageError::DiskPressure {
            path,
            volume,
            available_bytes,
            headroom_bytes,
        }) => ProofError::Store(StorageError::DiskPressure {
            path: path.clone(),
            volume: volume.clone(),
            available_bytes: *available_bytes,
            headroom_bytes: *headroom_bytes,
        }),
        ProofError::Store(other) => {
            ProofError::Store(StorageError::Io(std::io::Error::other(other.to_string())))
        }
        ProofError::Read(other) => ProofError::Read(std::io::Error::other(other.to_string())),
        ProofError::Provenance(other) => {
            ProofError::Provenance(PeerSessionError::Io(std::io::Error::other(other.to_string())))
        }
        ProofError::FileUnavailable => ProofError::FileUnavailable,
    }
}

#[derive(Default)]
struct Batch {
    group: Option<String>,
    blocks: Vec<LocallyHashedBlock>,
    hashes: HashSet<Vec<u8>>,
    bytes: u64,
    files: Vec<BatchedFile>,
}

struct BatchedFile {
    row: SupersededRow,
    file: std::fs::File,
    expected_len: u64,
    reply: oneshot::Sender<RetentionReply>,
}

enum Read {
    /// Decided without adding anything to the store.
    Answer(RetentionReply),
    /// The blocks, read and checked against the version.
    Verified(Vec<LocallyHashedBlock>, std::fs::File, u64),
    /// More than a batch holds: ingested on its own.
    TooLarge(std::fs::File),
}

#[cfg(unix)]
fn read_exact_at(file: &std::fs::File, buf: &mut [u8], offset: u64) -> std::io::Result<()> {
    std::os::unix::fs::FileExt::read_exact_at(file, buf, offset)
}

#[cfg(windows)]
fn read_exact_at(file: &std::fs::File, mut buf: &mut [u8], mut offset: u64) -> std::io::Result<()> {
    while !buf.is_empty() {
        let read = std::os::windows::fs::FileExt::seek_read(file, buf, offset)?;
        if read == 0 {
            return Err(std::io::ErrorKind::UnexpectedEof.into());
        }
        buf = &mut buf[read..];
        offset += read as u64;
    }
    Ok(())
}
