//! Keeping the bytes of a version that a sync is about to replace.
//!
//! A version's index row can outlive its bytes once received and captured content is no longer
//! copied into the block store on arrival. Before a sync makes a row stop being current, the
//! bytes this device holds for it must be in the store, or this device must never have had them.
//! This module is the check that tells whether the store already holds a version.

use std::collections::HashSet;
use std::sync::Arc;

use yadorilink_fs_platform::fs_identity::TimestampGranularity;
use yadorilink_local_storage::{BlockContentStore, StorageError, VerifiedBlock};
use yadorilink_peer_session::PeerSessionError;
use yadorilink_replica_domain::file::BlockInfo;
use yadorilink_replica_domain::ids::VersionHash;
use yadorilink_sync_sqlite::retention::{RetentionProof, RetentionProofs, SupersededRow};

use crate::sync_error::SyncError;
use yadorilink_sync_sqlite::materialized_generation::{
    revalidate_identity_against_disk, DiskGenerationBasis, IdentityRevalidation,
    MaterializedObjectKind,
};

/// The subset of the hashes it is given that the group has provenance for.
pub(crate) type ProvenanceLookup<'a, E> = dyn Fn(&[Vec<u8>]) -> Result<HashSet<Vec<u8>>, E> + 'a;

/// How many distinct blocks are checked together. Presence and provenance are asked of the store
/// and the index a chunk at a time, so neither the memory used nor the size of a query depends on
/// the size of the file.
const CHECK_CHUNK_BLOCKS: usize = 512;

/// Whether the store holds every block of a version in a form that can be relied on: each block
/// is present, the group has provenance for it, and the store's framing-checked read accepts it
/// (the record's header names the block and its payload matches the checksum written beside it).
///
/// That read does not re-derive the SHA-256, which on a version of a gigabyte costs as much CPU as
/// the receive of the replacing version. It finds what the medium does to a record (torn,
/// truncated, rotted) and a record that is not the block it names. It does not find a record that is
/// consistent with itself but whose bytes are not the block (a writer's bug that checksummed the
/// wrong bytes, or someone who can compute the checksum): that is found where the bytes are used
/// and verified (a restore, a handoff), by which time the file may be gone.
///
/// A block that is present but fails any of the three counts as absent: `Ok(false)`, and the
/// caller takes the blocks from the file instead. So does a block whose hash is not a SHA-256
/// digest at all, which no store can hold. A failure of the store itself (an I/O error) is an
/// `Err`, because it says nothing about the block and the caller must not treat the version as
/// either kept or lost.
///
/// `provenance` returns the subset of the hashes it is given that the group has provenance for.
///
/// This is not a read-only question: the store's read drops the index mapping of a
/// block whose record it cannot read, so a second check of the same damaged block answers
/// "absent" where the first found it damaged. Both answers are `Ok(false)`.
// Called by the proof that decides a replacement, which is built on this; until then only the
// tests call it.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn version_kept_in_store<E>(
    store: &dyn BlockContentStore,
    provenance: &ProvenanceLookup<'_, E>,
    blocks: &[BlockInfo],
) -> Result<bool, KeptCheckError<E>> {
    if blocks.iter().any(|block| block.hash.len() != SHA256_BYTES) {
        return Ok(false);
    }
    let mut seen = HashSet::new();
    let distinct: Vec<&Vec<u8>> =
        blocks.iter().map(|block| &block.hash).filter(|hash| seen.insert(*hash)).collect();
    for chunk in distinct.chunks(CHECK_CHUNK_BLOCKS) {
        let hex_hashes: Vec<String> = chunk.iter().map(hex::encode).collect();
        let present = store.present_blocks(&hex_hashes).map_err(KeptCheckError::Store)?;
        if present.len() != hex_hashes.len() || present.iter().any(|held| !held) {
            return Ok(false);
        }
        let raw: Vec<Vec<u8>> = chunk.iter().map(|hash| (*hash).clone()).collect();
        let with_provenance = provenance(&raw).map_err(KeptCheckError::Provenance)?;
        if raw.iter().any(|hash| !with_provenance.contains(hash)) {
            return Ok(false);
        }
        for hash in &hex_hashes {
            match store.get_framing_checked(hash) {
                Ok(_) => {}
                Err(StorageError::NotFound(_) | StorageError::ChecksumMismatch { .. }) => {
                    return Ok(false);
                }
                Err(other) => return Err(KeptCheckError::Store(other)),
            }
        }
    }
    Ok(true)
}

const SHA256_BYTES: usize = 32;

/// Why a check could not give an answer.
#[derive(Debug)]
// Matched by the callers of `version_kept_in_store`, which come with the proof; until then only the
// tests construct and match it.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) enum KeptCheckError<E> {
    Store(StorageError),
    Provenance(E),
}

/// What the file at a path is, when a sync is about to replace the version the index records for
/// it. Decided from the file and from the record of what the daemon last wrote there, never from
/// the row's materialization state alone: that state does not say which version the file holds (a
/// row committed without its content is `Present` over an older file, and a crash between the
/// rename and the close of the in-flight state leaves `Hydrating` over the new bytes).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
// Matched by the proof that decides a replacement, which is built on this; until then only the
// tests use it.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) enum ReplacedFile {
    /// The daemon's own write of exactly this version, untouched since: the file is the version.
    /// Its bytes still have to be read and verified before they are kept.
    IsThisVersion,
    /// The daemon's own write of an older version, untouched since: this device never held the
    /// bytes of the version being replaced, so there is nothing of it to keep. Not an error, and
    /// never a reason to hold the sync back.
    OlderVersionUntouched,
    /// No usable record of a write, or the file is no longer the object that was recorded: only its
    /// content can say whether it is the version (a write whose record was not made, bytes that
    /// are already in place) or an edit nobody captured (which belongs to the guard against
    /// replacing unrecorded local state).
    MustCompareContent,
    /// Nothing is at the path, or it is not a regular file: there are no bytes to keep.
    NoRegularFile,
}

/// Classifies the file at `out_path` against the daemon's record of what it last wrote there
/// (`recorded`, read with the mutation fence, so a record the path has moved past is `None`) and
/// the version hash of the row being replaced.
// Called by the proof that decides a replacement; until then only the tests call it.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn classify_replaced_file(
    recorded: Option<&DiskGenerationBasis>,
    out_path: &std::path::Path,
    birth_time_granularity: TimestampGranularity,
    replaced_version: &VersionHash,
) -> ReplacedFile {
    match std::fs::symlink_metadata(out_path) {
        Ok(meta) if meta.is_file() => {}
        _ => return ReplacedFile::NoRegularFile,
    }
    let Some(recorded) = recorded else { return ReplacedFile::MustCompareContent };
    if recorded.object_kind != MaterializedObjectKind::RegularFile {
        return ReplacedFile::MustCompareContent;
    }
    if revalidate_identity_against_disk(recorded, out_path, birth_time_granularity)
        != IdentityRevalidation::Confirmed
    {
        return ReplacedFile::MustCompareContent;
    }
    match &recorded.version {
        Some(written) if written == replaced_version => ReplacedFile::IsThisVersion,
        Some(_) => ReplacedFile::OlderVersionUntouched,
        None => ReplacedFile::MustCompareContent,
    }
}

/// Records the group's provenance for the raw hashes of blocks that are already durable.
pub(crate) type ProvenanceRecorder<'a, E> = dyn Fn(&[Vec<u8>]) -> Result<(), E> + 'a;

/// The result of reading a file's blocks into the store.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
// Matched by the proof that decides a replacement; until then only the tests use it.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) enum IngestOutcome {
    /// Every block of the version was read from the file, matched its hash and size, and is now
    /// durable in the store, with the group's provenance recorded for it.
    Ingested,
    /// The file is not the version: its length is not the version's, or a block's bytes are not
    /// the block the version lists at that offset. Blocks of earlier batches may already be in the
    /// store (each of them is a verified block of the version, so they are harmless); the caller
    /// treats the file as something the index does not describe.
    NotTheVersion,
}

/// Why the blocks of a file could not be put into the store.
#[derive(Debug)]
// The payloads are read by the callers that come with the proof; the tests read them where the
// platform allows (a failing read is only built on Unix), so the lint is silenced for all builds.
#[allow(dead_code)]
pub(crate) enum IngestError<E> {
    /// The store refused a batch; nothing of that batch is recorded as held.
    Store(StorageError),
    /// The file could not be read (not a short file: that is `NotTheVersion`).
    Read(std::io::Error),
    Provenance(E),
}

/// Puts the blocks `blocks` lists into the store, reading them from `file` and checking each
/// against the hash and size the version lists for it (`VerifiedBlock::check`; the bytes in the
/// file are never trusted on the strength of anything but their own hash).
///
/// The work is done in bounded batches, as the receive path commits them (the same block and byte
/// limits), and **each batch is durable in the store before the next is read**, so what is held in
/// memory is one batch and the block being read (its buffer and the verified copy of it), and not
/// the file: the only local copy of a 20 GiB file is put into the store without the memory used
/// depending on its size. The group's provenance for a batch's blocks is recorded only after the
/// batch is durable, never before.
///
/// What `Ingested` says: every block of the version is in the store, durable, with provenance. It
/// does **not** say the file is unchanged when this returns. The length is checked before the
/// reads and again after them, which catches a file that grew or shrank meanwhile, but a block
/// overwritten in place after it was read is not seen here. The caller that goes on to replace the
/// file must still make the check it makes before any replacement (the identity of the object
/// immediately before the rename); the residual between that check and the rename is the one the
/// receive path already has.
///
/// `record_provenance` is given the raw hashes of the blocks of one batch that is already durable.
// Called by the proof that decides a replacement; until then only the tests call it.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn ingest_version_from_file<E>(
    store: &dyn BlockContentStore,
    file: &std::fs::File,
    blocks: &[BlockInfo],
    record_provenance: &ProvenanceRecorder<'_, E>,
) -> Result<IngestOutcome, IngestError<E>> {
    ingest_in_batches(
        store,
        file,
        blocks,
        record_provenance,
        super::types::Tuning::RECEIVE_COMMIT_BATCH_BLOCKS,
        super::types::Tuning::RECEIVE_COMMIT_BATCH_BYTES,
    )
}

pub(crate) fn ingest_in_batches<E>(
    store: &dyn BlockContentStore,
    file: &std::fs::File,
    blocks: &[BlockInfo],
    record_provenance: &ProvenanceRecorder<'_, E>,
    batch_blocks: usize,
    batch_bytes: u64,
) -> Result<IngestOutcome, IngestError<E>> {
    // An empty version is an empty file: a file with bytes in it is not that version, whatever the
    // blocks listed (none).
    let expected_len =
        blocks.iter().map(|block| block.offset + u64::from(block.size)).max().unwrap_or(0);
    let length_is_the_versions = |file: &std::fs::File| -> Result<bool, IngestError<E>> {
        Ok(file.metadata().map_err(IngestError::Read)?.len() == expected_len)
    };
    if !length_is_the_versions(file)? {
        return Ok(IngestOutcome::NotTheVersion);
    }
    let mut batch: Vec<yadorilink_local_storage::LocallyHashedBlock> = Vec::new();
    let mut batch_hashes: Vec<Vec<u8>> = Vec::new();
    let mut held_bytes = 0u64;
    for block in blocks {
        let mut bytes = vec![0u8; block.size as usize];
        match read_exact_at(file, &mut bytes, block.offset) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => {
                return Ok(IngestOutcome::NotTheVersion);
            }
            Err(error) => return Err(IngestError::Read(error)),
        }
        let Ok(verified) = VerifiedBlock::check(&bytes, &block.hash, block.size) else {
            return Ok(IngestOutcome::NotTheVersion);
        };
        drop(bytes);
        if batch_hashes.contains(&block.hash) {
            continue;
        }
        held_bytes += u64::from(block.size);
        batch_hashes.push(block.hash.clone());
        batch.push(verified.into_hashed());
        if batch.len() >= batch_blocks || held_bytes >= batch_bytes {
            commit_batch(store, &mut batch, &mut batch_hashes, record_provenance)?;
            held_bytes = 0;
        }
    }
    commit_batch(store, &mut batch, &mut batch_hashes, record_provenance)?;
    // The length is looked at again once everything has been read: a file that grew or shrank
    // while it was read is not reported as the version.
    if !length_is_the_versions(file)? {
        return Ok(IngestOutcome::NotTheVersion);
    }
    Ok(IngestOutcome::Ingested)
}

/// Makes the batch durable, then records its provenance, then empties it.
fn commit_batch<E>(
    store: &dyn BlockContentStore,
    batch: &mut Vec<yadorilink_local_storage::LocallyHashedBlock>,
    hashes: &mut Vec<Vec<u8>>,
    record_provenance: &ProvenanceRecorder<'_, E>,
) -> Result<(), IngestError<E>> {
    if batch.is_empty() {
        return Ok(());
    }
    store.put_prepared_batch(batch).map_err(IngestError::Store)?;
    record_provenance(hashes).map_err(IngestError::Provenance)?;
    batch.clear();
    hashes.clear();
    Ok(())
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

/// Why a proof could not be made.
#[derive(Debug)]
pub(crate) enum ProofError<E> {
    Store(StorageError),
    Read(std::io::Error),
    Provenance(E),
    /// The file cannot be read as a source right now (busy, or not fully on this device) and
    /// nothing is wrong with it: the replacement waits and is tried again.
    FileUnavailable,
}

impl<E> From<KeptCheckError<E>> for ProofError<E> {
    fn from(error: KeptCheckError<E>) -> Self {
        match error {
            KeptCheckError::Store(error) => ProofError::Store(error),
            KeptCheckError::Provenance(error) => ProofError::Provenance(error),
        }
    }
}

impl<E> From<IngestError<E>> for ProofError<E> {
    fn from(error: IngestError<E>) -> Self {
        match error {
            IngestError::Store(error) => ProofError::Store(error),
            IngestError::Read(error) => ProofError::Read(error),
            IngestError::Provenance(error) => ProofError::Provenance(error),
        }
    }
}

/// What can be decided about the proof for a replaced version before any byte is added to the store.
#[derive(Debug)]
pub(crate) enum Prepared {
    /// The proof is settled without adding anything.
    Proof(RetentionProof),
    /// The file is the version and its blocks are not all in the store: keeping the version means
    /// reading the file into the store, which adds bytes and so needs room (see
    /// [`ingest_replacement_proof`] and `proofs_before_replacing`, which asks for it).
    NeedsIngest(SupersededRow),
}

/// The proof for replacing the version `row` (whose blocks are `blocks`) of the file at `out_path`,
/// as far as it can be made without adding bytes to the store.
///
/// The bytes of the version are in the store already (every block present, its record intact by the
/// record's own checksum, with the group's provenance; the SHA-256 is not re-derived): `InStore`.
/// Otherwise the file is looked at: if it is an older write of this device, or is not there, this
/// device holds no bytes of the version and the proof is `NoLocalBytes`; if it may be the
/// version, its bytes have to be read into the store, which is [`Prepared::NeedsIngest`].
#[allow(clippy::too_many_arguments)]
pub(crate) fn prepare_replacement_proof<E>(
    store: &dyn BlockContentStore,
    provenance: &ProvenanceLookup<'_, E>,
    row: SupersededRow,
    blocks: &[BlockInfo],
    recorded_write: Option<&DiskGenerationBasis>,
    out_path: &std::path::Path,
    birth_time_granularity: TimestampGranularity,
) -> Result<Prepared, ProofError<E>> {
    if version_kept_in_store(store, provenance, blocks)? {
        return Ok(Prepared::Proof(RetentionProof::InStore(row)));
    }
    match classify_replaced_file(
        recorded_write,
        out_path,
        birth_time_granularity,
        &row.version_hash,
    ) {
        ReplacedFile::NoRegularFile | ReplacedFile::OlderVersionUntouched => {
            Ok(Prepared::Proof(RetentionProof::NoLocalBytes(row)))
        }
        ReplacedFile::IsThisVersion | ReplacedFile::MustCompareContent => {
            Ok(Prepared::NeedsIngest(row))
        }
    }
}

/// Reads the file at `out_path` into the store when it is the version `row` names: `InStore`. A
/// file that is not the version, or is gone, holds no bytes of it: `NoLocalBytes`.
///
/// A file that is not the version is not an error here and does not hold the replacement back: the
/// guard against replacing a local edit nobody captured runs before any replacement, at every call
/// site, and has already accepted what is at the path. What this decides is only whether bytes of
/// the version exist here to be kept.
pub(crate) fn ingest_replacement_proof<E>(
    store: &dyn BlockContentStore,
    record_provenance: &ProvenanceRecorder<'_, E>,
    row: SupersededRow,
    blocks: &[BlockInfo],
    out_path: &std::path::Path,
) -> Result<RetentionProof, ProofError<E>> {
    match crate::file_block_source::open_source(out_path) {
        crate::file_block_source::Opened::File(file) => {
            match ingest_version_from_file(store, &file, blocks, record_provenance)? {
                IngestOutcome::Ingested => Ok(RetentionProof::InStore(row)),
                IngestOutcome::NotTheVersion => Ok(RetentionProof::NoLocalBytes(row)),
            }
        }
        crate::file_block_source::Opened::Gone => Ok(RetentionProof::NoLocalBytes(row)),
        crate::file_block_source::Opened::Unavailable => Err(ProofError::FileUnavailable),
    }
}

/// How many bytes reading a version into the store would add: the sizes of its distinct blocks the
/// store does not hold. Presence only; nothing is read or written.
pub(crate) fn bytes_an_ingest_would_add(
    store: &dyn BlockContentStore,
    blocks: &[BlockInfo],
) -> Result<u64, StorageError> {
    let mut seen = HashSet::new();
    let distinct: Vec<&BlockInfo> =
        blocks.iter().filter(|block| seen.insert(block.hash.clone())).collect();
    let mut missing = 0u64;
    for chunk in distinct.chunks(CHECK_CHUNK_BLOCKS) {
        let hex_hashes: Vec<String> = chunk.iter().map(|block| hex::encode(&block.hash)).collect();
        let present = store.present_blocks(&hex_hashes)?;
        for (index, block) in chunk.iter().enumerate() {
            if !present.get(index).copied().unwrap_or(false) {
                missing = missing.saturating_add(u64::from(block.size));
            }
        }
    }
    Ok(missing)
}

/// The whole proof in one step, with no question asked about room (tests of the pieces above).
#[allow(clippy::too_many_arguments)]
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn prove_replacement<E>(
    store: &dyn BlockContentStore,
    provenance: &ProvenanceLookup<'_, E>,
    record_provenance: &ProvenanceRecorder<'_, E>,
    row: SupersededRow,
    blocks: &[BlockInfo],
    recorded_write: Option<&DiskGenerationBasis>,
    out_path: &std::path::Path,
    birth_time_granularity: TimestampGranularity,
) -> Result<RetentionProof, ProofError<E>> {
    match prepare_replacement_proof(
        store,
        provenance,
        row,
        blocks,
        recorded_write,
        out_path,
        birth_time_granularity,
    )? {
        Prepared::Proof(proof) => Ok(proof),
        Prepared::NeedsIngest(row) => {
            ingest_replacement_proof(store, record_provenance, row, blocks, out_path)
        }
    }
}

/// What identifies the object at `path` for the purpose of noticing that it was replaced or
/// edited: its length, modification time and (where there is one) inode and change time. The change
/// time is the one an editor cannot set back: restoring the modification time after a same-length
/// overwrite moves it.
type ObjectFingerprint = (u64, Option<std::time::SystemTime>, u64, i64, i64);

fn object_fingerprint(path: &std::path::Path) -> Option<ObjectFingerprint> {
    let metadata = std::fs::symlink_metadata(path).ok()?;
    #[cfg(unix)]
    let (inode, ctime, ctime_nsec) = {
        use std::os::unix::fs::MetadataExt;
        (metadata.ino(), metadata.ctime(), metadata.ctime_nsec())
    };
    #[cfg(not(unix))]
    let (inode, ctime, ctime_nsec) = (0, 0, 0);
    Some((metadata.len(), metadata.modified().ok(), inode, ctime, ctime_nsec))
}

impl super::LocalConvergenceExecutor {
    /// [`Self::proofs_before_replacing`] for a removal of the file at `out_path`, which is checked
    /// again once the proofs are made: making them can take as long as reading the file, and an
    /// edit (or an editor's atomic save) that lands meanwhile is not the object the guard against
    /// removing an uncaptured edit looked at. `None` when the object changed; the caller declines
    /// the removal and tries again, and the guard looks at what is there now.
    ///
    /// This does not close the gap between that check and the unlink: an edit saved in that
    /// instant is still removed, as it is by every removal of a file by a sync. It makes that gap
    /// no longer than it was before the proofs existed, instead of as long as they take.
    pub(crate) async fn proofs_before_removing(
        &self,
        group_id: &str,
        record: &yadorilink_replica_domain::file::FileRecord,
        out_path: &std::path::Path,
    ) -> Result<Option<RetentionProofs>, PeerSessionError> {
        let before = object_fingerprint(out_path);
        let proofs = self.proofs_before_replacing(group_id, record).await?;
        #[cfg(test)]
        super::removal_ordering_probe::fire_after_proof(out_path);
        if object_fingerprint(out_path) != before {
            tracing::info!(
                group_id,
                path = %record.path,
                "not removing a file that changed while the version it holds was being kept; \
                 it is looked at again"
            );
            return Ok(None);
        }
        Ok(Some(proofs))
    }

    /// The proofs a sync needs before it replaces the version the index records at
    /// `new_record.path` with `new_record`: nothing, when the path has no current row, the row has
    /// no bytes to keep (a deletion, a directory, a symlink, an empty file) or the new version
    /// keeps the same blocks; otherwise the proof for that row (see [`prove_replacement`]).
    ///
    /// The reads and the ingest run on the blocking pool. The write that uses the proofs checks
    /// them against the row it finds, so a path that moves on in the meantime refuses the write
    /// and the materialization is tried again.
    pub(crate) async fn proofs_before_replacing(
        &self,
        group_id: &str,
        new_record: &yadorilink_replica_domain::file::FileRecord,
    ) -> Result<RetentionProofs, PeerSessionError> {
        let path = new_record.path.as_str();
        let repository = self.state.file_index_repository();
        let Some((row, holds_bytes, blocks)) =
            repository.current_row_for_retention(group_id, path).map_err(SyncError::from)?
        else {
            return Ok(RetentionProofs::new());
        };
        if !holds_bytes || blocks == new_record.blocks {
            return Ok(RetentionProofs::new());
        }
        let out_path = self.local_file_path(group_id, path)?;
        let granularity =
            yadorilink_fs_platform::fs_capabilities::cached_probe_birth_time_granularity(
                &self.sync_root(group_id)?,
            );
        let recorded_write = self.state.recorded_write_at(group_id, path)?;
        let store = Arc::clone(&self.durable_store);
        let state = Arc::clone(&self.state);
        let group = group_id.to_string();
        let prepared = {
            let (store, state, group, out_path, blocks, row) = (
                Arc::clone(&store),
                Arc::clone(&state),
                group.clone(),
                out_path.clone(),
                blocks.clone(),
                row,
            );
            tokio::task::spawn_blocking(move || {
                let lookup =
                    |hashes: &[Vec<u8>]| state.group_has_block_provenance_batch(&group, hashes);
                prepare_replacement_proof(
                    store.as_ref(),
                    &lookup,
                    row,
                    &blocks,
                    recorded_write.as_ref(),
                    &out_path,
                    granularity,
                )
            })
            .await
            .map_err(|error| {
                PeerSessionError::CorruptState(format!("retention proof task failed: {error}"))
            })?
            .map_err(|error| proof_error(path, error))?
        };
        let proof = match prepared {
            Prepared::Proof(proof) => {
                crate::receive_diag::record_retention_no_ingest(matches!(
                    proof,
                    RetentionProof::InStore(_)
                ));
                proof
            }
            Prepared::NeedsIngest(row) => {
                self.ingest_or_give_up(group_id, path, row, blocks, out_path, store).await?
            }
        };
        let mut proofs = RetentionProofs::new();
        proofs.insert(path, proof);
        Ok(proofs)
    }

    /// Keeps the replaced version by reading its file into the store, asking first whether the
    /// volume has room for the bytes that adds, like any write (the same admission, held while the
    /// bytes are added).
    ///
    /// With no room, the version is given up (`Skipped`) when nothing protects it: the sync is not
    /// held back, nothing is read, and nothing else is removed. A protected version (pinned, or
    /// named by a lease) is never given up: the refusal is returned and the replacement waits for
    /// disk space like any other write. A store that refuses a batch for room while the bytes are
    /// being added is the same case, decided the same way.
    #[allow(clippy::too_many_arguments)]
    async fn ingest_or_give_up(
        &self,
        group_id: &str,
        path: &str,
        row: SupersededRow,
        blocks: Vec<BlockInfo>,
        out_path: std::path::PathBuf,
        store: Arc<dyn BlockContentStore>,
    ) -> Result<RetentionProof, PeerSessionError> {
        let missing = {
            let (store, blocks) = (Arc::clone(&store), blocks.clone());
            tokio::task::spawn_blocking(move || bytes_an_ingest_would_add(store.as_ref(), &blocks))
                .await
                .map_err(|error| {
                    PeerSessionError::CorruptState(format!("retention proof task failed: {error}"))
                })?
                .map_err(PeerSessionError::from)?
        };
        let give_up = |row: SupersededRow| RetentionProof::Skipped {
            row,
            reason: yadorilink_sync_sqlite::retention::SkipReason::LowSpace,
        };
        let protected = || crate::ingest_policy::must_keep_in_store(&self.state, group_id, path);
        // Held until the bytes are in the store.
        // The ingest writes into the block store, so the volume asked is the store's, not the
        // sync root's. A store with no directory on a volume of its own is asked nothing here.
        let store_dir = store.data_dir().map(std::path::Path::to_path_buf);
        let _admission = if let Some(store_dir) = store_dir.filter(|_| missing > 0) {
            match self.preflight_disk_headroom_on(store_dir, &out_path, missing) {
                Ok(reservation) => Some(reservation),
                Err(PeerSessionError::DiskPressure { .. }) if !protected() => {
                    tracing::info!(
                        group_id,
                        path,
                        needed_bytes = missing,
                        "not keeping the version being replaced: the disk is nearly full"
                    );
                    return Ok(give_up(row));
                }
                Err(error) => return Err(error),
            }
        } else {
            None
        };
        let kept_row = row.clone();
        let ingested = self
            .retention_queue
            .ingest(super::retention_batch::RetentionRequest {
                group: group_id.to_string(),
                path: path.to_string(),
                row,
                blocks,
                out_path,
            })
            .await;
        match ingested {
            Err(ProofError::Store(StorageError::DiskPressure { .. })) if !protected() => {
                Ok(give_up(kept_row))
            }
            other => other.map_err(|error| proof_error(path, error)),
        }
    }
}

/// The error a failed proof is reported as.
fn proof_error(path: &str, error: ProofError<PeerSessionError>) -> PeerSessionError {
    match error {
        ProofError::Store(error) => PeerSessionError::from(error),
        ProofError::Read(error) => PeerSessionError::from(error),
        ProofError::Provenance(error) => error,
        ProofError::FileUnavailable => PeerSessionError::Io(std::io::Error::new(
            std::io::ErrorKind::WouldBlock,
            format!("{path}: the file cannot be read as a source right now"),
        )),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{HashMap, HashSet};
    use std::sync::Mutex;

    use yadorilink_local_storage::{
        hash_block_bytes, BlockContentStore, ContentHash, LocallyHashedBlock, StorageError,
    };
    use yadorilink_replica_domain::file::BlockInfo;

    use super::*;

    /// A store whose answers the test scripts, and which counts the framing-checked reads.
    #[derive(Default)]
    struct ScriptedStore {
        held: HashSet<String>,
        get_fails: HashMap<String, fn(&str) -> StorageError>,
        gets: Mutex<Vec<String>>,
    }

    impl BlockContentStore for ScriptedStore {
        fn put(&self, _: &[u8]) -> Result<ContentHash, StorageError> {
            unreachable!("the check never writes")
        }
        fn put_prepared(&self, _: &LocallyHashedBlock) -> Result<(), StorageError> {
            unreachable!("the check never writes")
        }
        fn put_prepared_batch(&self, _: &[LocallyHashedBlock]) -> Result<(), StorageError> {
            unreachable!("the check never writes")
        }
        fn get(&self, _: &str) -> Result<Vec<u8>, StorageError> {
            unreachable!("the check reads framing-checked, never with the SHA-256 read")
        }
        fn get_framing_checked(&self, hash: &str) -> Result<Vec<u8>, StorageError> {
            self.gets.lock().unwrap().push(hash.to_string());
            match self.get_fails.get(hash) {
                Some(make) => Err(make(hash)),
                None => Ok(Vec::new()),
            }
        }
        fn present_blocks(&self, hashes: &[ContentHash]) -> Result<Vec<bool>, StorageError> {
            Ok(hashes.iter().map(|hash| self.held.contains(hash)).collect())
        }
    }

    fn block(content: &[u8], offset: u64) -> BlockInfo {
        let hash = hex::decode(hash_block_bytes(content)).unwrap();
        BlockInfo { hash, offset, size: content.len() as u32 }
    }

    fn store_holding(blocks: &[&BlockInfo]) -> ScriptedStore {
        ScriptedStore {
            held: blocks.iter().map(|block| hex::encode(&block.hash)).collect(),
            ..ScriptedStore::default()
        }
    }

    fn all_have_provenance(hashes: &[Vec<u8>]) -> Result<HashSet<Vec<u8>>, ()> {
        Ok(hashes.iter().cloned().collect())
    }

    #[test]
    fn a_version_whose_blocks_are_all_present_proven_and_intact_is_kept() {
        let (a, b) = (block(b"first", 0), block(b"second", 5));
        let store = store_holding(&[&a, &b]);

        assert!(version_kept_in_store(&store, &all_have_provenance, &[a, b]).unwrap());
    }

    #[test]
    fn a_missing_block_means_not_kept_and_nothing_is_read() {
        let (a, b) = (block(b"first", 0), block(b"second", 5));
        let store = store_holding(&[&a]);

        assert!(!version_kept_in_store(&store, &all_have_provenance, &[a, b]).unwrap());
        assert!(store.gets.lock().unwrap().is_empty(), "the cheap checks come before any read");
    }

    #[test]
    fn a_present_block_without_group_provenance_is_not_kept() {
        let (a, b) = (block(b"first", 0), block(b"second", 5));
        let store = store_holding(&[&a, &b]);
        let only_first = |hashes: &[Vec<u8>]| -> Result<HashSet<Vec<u8>>, ()> {
            Ok(hashes.iter().filter(|hash| **hash == a.hash).cloned().collect())
        };

        assert!(!version_kept_in_store(&store, &only_first, &[a.clone(), b]).unwrap());
    }

    #[test]
    fn a_present_block_the_framing_checked_read_refuses_is_not_kept() {
        let (a, b) = (block(b"first", 0), block(b"second", 5));
        let mut store = store_holding(&[&a, &b]);
        store.get_fails.insert(hex::encode(&b.hash), |hash| StorageError::ChecksumMismatch {
            expected: hash.to_string(),
            actual: "other".to_string(),
        });

        assert!(!version_kept_in_store(&store, &all_have_provenance, &[a, b]).unwrap());
    }

    #[test]
    fn a_failure_of_the_store_itself_is_an_error_not_an_answer() {
        let a = block(b"first", 0);
        let mut store = store_holding(&[&a]);
        store.get_fails.insert(hex::encode(&a.hash), |_| {
            StorageError::Io(std::io::Error::other("the disk went away"))
        });

        let result = version_kept_in_store(&store, &all_have_provenance, &[a]);

        assert!(matches!(result, Err(KeptCheckError::Store(StorageError::Io(_)))));
    }

    #[test]
    fn a_block_that_repeats_in_the_file_is_checked_once() {
        let a = block(b"same", 0);
        let again = BlockInfo { offset: 4, ..a.clone() };
        let store = store_holding(&[&a]);

        assert!(version_kept_in_store(&store, &all_have_provenance, &[a, again]).unwrap());
        assert_eq!(store.gets.lock().unwrap().len(), 1);
    }

    #[test]
    fn a_failure_of_the_provenance_lookup_is_an_error_not_an_answer() {
        let a = block(b"first", 0);
        let store = store_holding(&[&a]);
        let failing =
            |_: &[Vec<u8>]| -> Result<HashSet<Vec<u8>>, &'static str> { Err("index busy") };

        let result = version_kept_in_store(&store, &failing, &[a]);

        assert!(matches!(result, Err(KeptCheckError::Provenance("index busy"))));
    }

    #[test]
    fn a_block_that_vanished_between_the_presence_check_and_the_read_is_not_kept() {
        let a = block(b"first", 0);
        let mut store = store_holding(&[&a]);
        store
            .get_fails
            .insert(hex::encode(&a.hash), |hash| StorageError::NotFound(hash.to_string()));

        assert!(!version_kept_in_store(&store, &all_have_provenance, &[a]).unwrap());
    }

    #[test]
    fn a_hash_that_is_not_a_digest_is_not_kept_and_the_store_is_not_asked() {
        let a = block(b"first", 0);
        let bad = BlockInfo { hash: vec![1, 2, 3], offset: 5, size: 3 };
        let store = store_holding(&[&a]);

        assert!(!version_kept_in_store(&store, &all_have_provenance, &[a, bad]).unwrap());
        assert!(store.gets.lock().unwrap().is_empty());
    }

    #[test]
    fn more_blocks_than_one_chunk_are_all_checked() {
        let blocks: Vec<BlockInfo> = (0..CHECK_CHUNK_BLOCKS * 2 + 1)
            .map(|index| block(format!("block number {index}").as_bytes(), index as u64))
            .collect();
        let refs: Vec<&BlockInfo> = blocks.iter().collect();
        let mut store = store_holding(&refs);
        let last = blocks.last().unwrap();
        store.get_fails.insert(hex::encode(&last.hash), |hash| StorageError::ChecksumMismatch {
            expected: hash.to_string(),
            actual: "other".to_string(),
        });

        assert!(
            !version_kept_in_store(&store, &all_have_provenance, &blocks).unwrap(),
            "a damaged block in the last chunk is found"
        );
    }

    /// The residual of reading by the record's checksum alone: a record that is consistent with
    /// itself but whose bytes are not the block it names is taken for a kept one here, and is found
    /// where the bytes are used, by the read that re-derives the SHA-256. By then the file may be
    /// gone; the design states this.
    #[test]
    fn a_record_consistent_with_itself_but_not_the_block_is_found_by_the_sha_read_not_here() {
        use yadorilink_local_storage::segment_store::testing::replace_block_payload_with_valid_checksum;
        use yadorilink_local_storage::SegmentBlockStore;
        let dir = tempfile::tempdir().unwrap();
        let store = SegmentBlockStore::new(dir.path()).unwrap();
        let content = b"a block whose record will lie".to_vec();
        let hash_hex = BlockContentStore::put(&store, &content).unwrap();
        let info = block(&content, 0);
        replace_block_payload_with_valid_checksum(
            dir.path(),
            &hash_hex,
            &vec![b'x'; content.len()],
        )
        .unwrap();

        assert!(
            version_kept_in_store(&store, &all_have_provenance, std::slice::from_ref(&info))
                .unwrap(),
            "the checksum-only read cannot tell"
        );
        assert!(
            matches!(
                BlockContentStore::get(&store, &hash_hex),
                Err(StorageError::ChecksumMismatch { .. })
            ),
            "the SHA-256 read does"
        );
    }

    /// The real store, with a real damaged record: the error the read gives for it is
    /// the one this function turns into "not kept".
    #[test]
    fn a_block_damaged_in_the_real_store_is_not_kept() {
        use yadorilink_local_storage::segment_store::testing::flip_one_payload_bit;
        use yadorilink_local_storage::SegmentBlockStore;
        let dir = tempfile::tempdir().unwrap();
        let store = SegmentBlockStore::new(dir.path()).unwrap();
        let content = b"a block that will be damaged on disk".to_vec();
        let hash_hex = BlockContentStore::put(&store, &content).unwrap();
        let info = block(&content, 0);
        assert!(version_kept_in_store(&store, &all_have_provenance, std::slice::from_ref(&info))
            .unwrap());

        flip_one_payload_bit(dir.path(), &hash_hex).unwrap();

        assert!(!version_kept_in_store(&store, &all_have_provenance, &[info]).unwrap());
    }

    mod classification {
        use yadorilink_fs_platform::fs_identity::{FileIdentity, TimestampGranularity};
        use yadorilink_replica_domain::ids::VersionHash;
        use yadorilink_sync_sqlite::file_identity_codec::GenerationId;
        use yadorilink_sync_sqlite::materialization_basis::ReflectedHeads;
        use yadorilink_sync_sqlite::materialized_generation::{
            DiskGenerationBasis, MaterializedObjectKind,
        };

        use super::super::{classify_replaced_file, ReplacedFile};

        // A volume whose birth time is fine enough to trust. On a coarse one an equal birth time
        // proves nothing and an untouched file is also sent to the content comparison: the safe
        // direction, so it is not what these tests are about.
        const GRANULARITY: TimestampGranularity = TimestampGranularity::Fine;

        fn version(tag: u8) -> VersionHash {
            VersionHash([tag; 32])
        }

        /// The record of a write of `written` that left the file at `path` as it is now.
        fn recorded_write(path: &std::path::Path, written: VersionHash) -> DiskGenerationBasis {
            DiskGenerationBasis {
                generation_id: GenerationId("test:generation".to_string()),
                basis: ReflectedHeads::of(&[], b""),
                resolved_path_state_hash: [0; 32],
                object_kind: MaterializedObjectKind::RegularFile,
                version: Some(written),
                filesystem_identity: Some(FileIdentity::observe_path(path).unwrap()),
            }
        }

        fn classify(
            recorded: Option<&DiskGenerationBasis>,
            path: &std::path::Path,
            replaced: u8,
        ) -> ReplacedFile {
            classify_replaced_file(recorded, path, GRANULARITY, &version(replaced))
        }

        #[test]
        fn the_untouched_write_of_the_replaced_version_is_that_version() {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("file");
            std::fs::write(&path, b"version two").unwrap();
            let recorded = recorded_write(&path, version(2));

            assert_eq!(classify(Some(&recorded), &path, 2), ReplacedFile::IsThisVersion);
        }

        /// A row committed without its content leaves the older file in place under the newer
        /// row; replacing the newer row must not wait on that file.
        #[test]
        fn an_untouched_older_file_under_a_newer_row_is_not_the_replaced_version() {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("file");
            std::fs::write(&path, b"version one").unwrap();
            let recorded = recorded_write(&path, version(1));

            assert_eq!(classify(Some(&recorded), &path, 2), ReplacedFile::OlderVersionUntouched);
        }

        /// A crash between the rename and the record of the write: the new bytes are in place and
        /// the record still names the object that was there before.
        #[test]
        fn a_file_renamed_over_the_recorded_one_must_be_compared_by_content() {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("file");
            std::fs::write(&path, b"version one").unwrap();
            let recorded = recorded_write(&path, version(1));
            let replacement = dir.path().join("incoming");
            std::fs::write(&replacement, b"version two").unwrap();
            std::fs::rename(&replacement, &path).unwrap();

            assert_eq!(classify(Some(&recorded), &path, 2), ReplacedFile::MustCompareContent);
        }

        #[test]
        fn a_file_rewritten_in_place_after_the_recorded_write_is_not_taken_for_untouched() {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("file");
            std::fs::write(&path, b"version one").unwrap();
            let recorded = recorded_write(&path, version(1));
            std::thread::sleep(std::time::Duration::from_millis(20));
            std::fs::write(&path, b"an edit made afterwards, longer").unwrap();

            assert_eq!(classify(Some(&recorded), &path, 2), ReplacedFile::MustCompareContent);
        }

        #[test]
        fn no_record_of_a_write_means_the_content_decides() {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("file");
            std::fs::write(&path, b"bytes").unwrap();

            assert_eq!(classify(None, &path, 2), ReplacedFile::MustCompareContent);
        }

        #[test]
        fn a_record_of_something_other_than_a_regular_file_means_the_content_decides() {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("file");
            std::fs::write(&path, b"bytes").unwrap();
            let mut recorded = recorded_write(&path, version(2));
            recorded.object_kind = MaterializedObjectKind::Symlink;

            assert_eq!(classify(Some(&recorded), &path, 2), ReplacedFile::MustCompareContent);
        }

        #[test]
        fn a_record_without_a_version_does_not_vouch_for_the_file() {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("file");
            std::fs::write(&path, b"bytes").unwrap();
            let mut recorded = recorded_write(&path, version(2));
            recorded.version = None;

            assert_eq!(classify(Some(&recorded), &path, 2), ReplacedFile::MustCompareContent);
        }

        #[test]
        fn nothing_at_the_path_or_something_that_is_not_a_file_has_no_bytes_to_keep() {
            let dir = tempfile::tempdir().unwrap();
            let missing = dir.path().join("missing");
            let folder = dir.path().join("folder");
            std::fs::create_dir(&folder).unwrap();

            assert_eq!(classify(None, &missing, 2), ReplacedFile::NoRegularFile);
            assert_eq!(classify(None, &folder, 2), ReplacedFile::NoRegularFile);
            #[cfg(unix)]
            {
                let target = dir.path().join("target");
                std::fs::write(&target, b"bytes").unwrap();
                let link = dir.path().join("link");
                std::os::unix::fs::symlink(&target, &link).unwrap();
                assert_eq!(classify(None, &link, 2), ReplacedFile::NoRegularFile);
            }
        }
    }

    mod ingest {
        use std::sync::Mutex;

        use yadorilink_local_storage::{
            hash_block_bytes, BlockContentStore, ContentHash, LocallyHashedBlock, StorageError,
        };
        use yadorilink_replica_domain::file::BlockInfo;

        use super::super::{
            ingest_in_batches, ingest_version_from_file, IngestError, IngestOutcome,
        };

        /// What happened, in order: `put` with the batch's block count and bytes, `provenance`
        /// with the number of hashes.
        type Events = Mutex<Vec<(&'static str, usize, u64)>>;

        #[derive(Default)]
        struct RecordingStore {
            events: Events,
            fail_on_put: Option<usize>,
            puts: Mutex<usize>,
        }

        impl BlockContentStore for RecordingStore {
            fn put(&self, _: &[u8]) -> Result<ContentHash, StorageError> {
                unreachable!("the ingest puts prepared batches only")
            }
            fn put_prepared(&self, _: &LocallyHashedBlock) -> Result<(), StorageError> {
                unreachable!("the ingest puts prepared batches only")
            }
            fn put_prepared_batch(&self, batch: &[LocallyHashedBlock]) -> Result<(), StorageError> {
                let mut puts = self.puts.lock().unwrap();
                *puts += 1;
                if self.fail_on_put == Some(*puts) {
                    return Err(StorageError::Io(std::io::Error::other("the disk is full")));
                }
                let bytes: u64 = batch.iter().map(|block| block.bytes().len() as u64).sum();
                self.events.lock().unwrap().push(("put", batch.len(), bytes));
                Ok(())
            }
            fn get(&self, _: &str) -> Result<Vec<u8>, StorageError> {
                unreachable!("the ingest never reads the store")
            }
            fn present_blocks(&self, _: &[ContentHash]) -> Result<Vec<bool>, StorageError> {
                unreachable!("the ingest never asks what is held")
            }
        }

        /// A file of `count` distinct blocks of `size` bytes, and the blocks that list it.
        fn file_of_distinct_blocks(
            dir: &std::path::Path,
            count: usize,
            size: usize,
        ) -> (std::fs::File, Vec<BlockInfo>) {
            let mut content = Vec::with_capacity(count * size);
            let mut blocks = Vec::new();
            for index in 0..count {
                let mut block = vec![(index % 251) as u8; size];
                block[..8].copy_from_slice(&(index as u64).to_be_bytes());
                blocks.push(BlockInfo {
                    hash: hex::decode(hash_block_bytes(&block)).unwrap(),
                    offset: (index * size) as u64,
                    size: size as u32,
                });
                content.extend_from_slice(&block);
            }
            let path = dir.join("file");
            std::fs::write(&path, &content).unwrap();
            (std::fs::File::open(&path).unwrap(), blocks)
        }

        fn provenance_into<'a>(
            store: &'a RecordingStore,
        ) -> impl Fn(&[Vec<u8>]) -> Result<(), ()> + 'a {
            move |hashes| {
                store.events.lock().unwrap().push(("provenance", hashes.len(), 0));
                Ok(())
            }
        }

        #[test]
        fn every_block_is_put_in_bounded_batches_and_its_provenance_follows_its_batch() {
            let dir = tempfile::tempdir().unwrap();
            let (file, blocks) = file_of_distinct_blocks(dir.path(), 10, 1024);
            let store = RecordingStore::default();

            let outcome =
                ingest_in_batches(&store, &file, &blocks, &provenance_into(&store), 4, u64::MAX)
                    .unwrap();

            assert_eq!(outcome, IngestOutcome::Ingested);
            let events = store.events.lock().unwrap().clone();
            assert_eq!(
                events,
                vec![
                    ("put", 4, 4096),
                    ("provenance", 4, 0),
                    ("put", 4, 4096),
                    ("provenance", 4, 0),
                    ("put", 2, 2048),
                    ("provenance", 2, 0),
                ],
                "each batch is durable before its provenance and before the next is read"
            );
        }

        /// The memory bound does not depend on the size of the file: a file sixty-four times the
        /// byte limit is put in batches none of which exceeds the limit by more than one block.
        #[test]
        fn a_file_many_times_the_byte_limit_is_never_held_more_than_one_batch_at_a_time() {
            let dir = tempfile::tempdir().unwrap();
            let block_size = 4096usize;
            let limit = 16 * block_size as u64;
            let (file, blocks) = file_of_distinct_blocks(dir.path(), 64 * 16, block_size);
            let store = RecordingStore::default();

            ingest_in_batches(&store, &file, &blocks, &provenance_into(&store), usize::MAX, limit)
                .unwrap();

            let events = store.events.lock().unwrap().clone();
            let puts: Vec<u64> =
                events.iter().filter(|(kind, ..)| *kind == "put").map(|(_, _, b)| *b).collect();
            assert_eq!(puts.len(), 64);
            assert!(puts.iter().all(|bytes| *bytes <= limit + block_size as u64), "{puts:?}");
            assert_eq!(puts.iter().sum::<u64>(), 64 * limit, "every byte of the file is put");
        }

        #[test]
        fn a_block_whose_bytes_are_not_the_listed_block_stops_the_ingest() {
            let dir = tempfile::tempdir().unwrap();
            let (_, blocks) = file_of_distinct_blocks(dir.path(), 8, 1024);
            let path = dir.path().join("file");
            let mut content = std::fs::read(&path).unwrap();
            content[5 * 1024 + 100] ^= 0xff;
            std::fs::write(&path, &content).unwrap();
            let file = std::fs::File::open(&path).unwrap();
            let store = RecordingStore::default();

            let outcome =
                ingest_in_batches(&store, &file, &blocks, &provenance_into(&store), 4, u64::MAX)
                    .unwrap();

            assert_eq!(outcome, IngestOutcome::NotTheVersion);
            let events = store.events.lock().unwrap().clone();
            assert_eq!(
                events,
                vec![("put", 4, 4096), ("provenance", 4, 0)],
                "only the batch read before the damaged block was put"
            );
        }

        #[test]
        fn a_file_longer_or_shorter_than_the_version_is_not_the_version() {
            let dir = tempfile::tempdir().unwrap();
            let (_, blocks) = file_of_distinct_blocks(dir.path(), 4, 1024);
            let path = dir.path().join("file");
            let original = std::fs::read(&path).unwrap();
            let store = RecordingStore::default();

            let mut longer = original.clone();
            longer.extend_from_slice(b"an appended tail");
            std::fs::write(&path, &longer).unwrap();
            let outcome = ingest_version_from_file(
                &store,
                &std::fs::File::open(&path).unwrap(),
                &blocks,
                &provenance_into(&store),
            )
            .unwrap();
            assert_eq!(outcome, IngestOutcome::NotTheVersion);

            std::fs::write(&path, &original[..original.len() - 1]).unwrap();
            let outcome = ingest_version_from_file(
                &store,
                &std::fs::File::open(&path).unwrap(),
                &blocks,
                &provenance_into(&store),
            )
            .unwrap();
            assert_eq!(outcome, IngestOutcome::NotTheVersion);
            assert!(store.events.lock().unwrap().is_empty(), "nothing was put");
        }

        #[test]
        fn a_batch_the_store_refuses_is_an_error_and_its_provenance_is_never_recorded() {
            let dir = tempfile::tempdir().unwrap();
            let (file, blocks) = file_of_distinct_blocks(dir.path(), 8, 1024);
            let store = RecordingStore { fail_on_put: Some(2), ..RecordingStore::default() };

            let result =
                ingest_in_batches(&store, &file, &blocks, &provenance_into(&store), 4, u64::MAX);

            assert!(matches!(result, Err(IngestError::Store(StorageError::Io(_)))));
            let events = store.events.lock().unwrap().clone();
            assert_eq!(events, vec![("put", 4, 4096), ("provenance", 4, 0)]);
        }

        #[test]
        fn a_file_with_bytes_is_not_the_empty_version() {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("not-empty");
            std::fs::write(&path, b"someone's work").unwrap();
            let store = RecordingStore::default();

            let outcome = ingest_version_from_file(
                &store,
                &std::fs::File::open(&path).unwrap(),
                &[],
                &provenance_into(&store),
            )
            .unwrap();

            assert_eq!(outcome, IngestOutcome::NotTheVersion);
        }

        /// The file grows while its blocks are being put: the answer is not "the version".
        #[test]
        fn a_file_that_changes_length_during_the_ingest_is_not_reported_as_the_version() {
            let dir = tempfile::tempdir().unwrap();
            let (file, blocks) = file_of_distinct_blocks(dir.path(), 4, 1024);
            let path = dir.path().join("file");
            let store = RecordingStore::default();
            let grow_after_first_batch = |hashes: &[Vec<u8>]| -> Result<(), ()> {
                store.events.lock().unwrap().push(("provenance", hashes.len(), 0));
                let mut appended = std::fs::OpenOptions::new().append(true).open(&path).unwrap();
                std::io::Write::write_all(&mut appended, b"typed meanwhile").unwrap();
                Ok(())
            };

            let outcome =
                ingest_in_batches(&store, &file, &blocks, &grow_after_first_batch, 2, u64::MAX)
                    .unwrap();

            assert_eq!(outcome, IngestOutcome::NotTheVersion);
        }

        #[test]
        fn a_block_that_repeats_within_a_batch_is_put_once() {
            let dir = tempfile::tempdir().unwrap();
            let (file, blocks) = file_of_distinct_blocks(dir.path(), 2, 1024);
            let path = dir.path().join("file");
            let mut doubled = std::fs::read(&path).unwrap();
            doubled.extend_from_slice(&doubled.clone());
            std::fs::write(&path, &doubled).unwrap();
            let again: Vec<BlockInfo> = blocks
                .iter()
                .map(|block| BlockInfo { offset: block.offset + 2048, ..block.clone() })
                .collect();
            let listed: Vec<BlockInfo> = blocks.into_iter().chain(again).collect();
            drop(file);
            let store = RecordingStore::default();

            ingest_version_from_file(
                &store,
                &std::fs::File::open(&path).unwrap(),
                &listed,
                &provenance_into(&store),
            )
            .unwrap();

            assert_eq!(
                store.events.lock().unwrap().clone(),
                vec![("put", 2, 2048), ("provenance", 2, 0)]
            );
        }

        /// A read that fails is an error, not "the file is not the version": the caller must not
        /// take a transient fault for evidence about the file.
        #[cfg(unix)]
        #[test]
        fn a_file_that_cannot_be_read_is_an_error_not_an_answer() {
            let dir = tempfile::tempdir().unwrap();
            let (_, blocks) = file_of_distinct_blocks(dir.path(), 2, 1024);
            let unreadable =
                std::fs::OpenOptions::new().write(true).open(dir.path().join("file")).unwrap();
            let store = RecordingStore::default();

            let result =
                ingest_version_from_file(&store, &unreadable, &blocks, &provenance_into(&store));

            let Err(IngestError::Read(error)) = result else {
                panic!("a read that fails is an error");
            };
            assert_ne!(error.kind(), std::io::ErrorKind::UnexpectedEof, "{error}");
            assert!(store.events.lock().unwrap().is_empty());
        }

        #[test]
        fn an_empty_version_has_nothing_to_put() {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("empty");
            std::fs::write(&path, b"").unwrap();
            let store = RecordingStore::default();

            let outcome = ingest_version_from_file(
                &store,
                &std::fs::File::open(&path).unwrap(),
                &[],
                &provenance_into(&store),
            )
            .unwrap();

            assert_eq!(outcome, IngestOutcome::Ingested);
            assert!(store.events.lock().unwrap().is_empty());
        }

        /// The real store: what the ingest puts is what the check of the previous change accepts.
        #[test]
        fn what_is_ingested_into_the_real_store_is_then_found_kept() {
            use std::collections::HashSet;
            use yadorilink_local_storage::SegmentBlockStore;

            use super::super::version_kept_in_store;

            let dir = tempfile::tempdir().unwrap();
            let (file, blocks) = file_of_distinct_blocks(dir.path(), 6, 2048);
            let store_dir = tempfile::tempdir().unwrap();
            let store = SegmentBlockStore::new(store_dir.path()).unwrap();
            let recorded: Mutex<HashSet<Vec<u8>>> = Mutex::new(HashSet::new());
            let record = |hashes: &[Vec<u8>]| -> Result<(), ()> {
                recorded.lock().unwrap().extend(hashes.iter().cloned());
                Ok(())
            };
            let lookup = |hashes: &[Vec<u8>]| -> Result<HashSet<Vec<u8>>, ()> {
                let held = recorded.lock().unwrap();
                Ok(hashes.iter().filter(|hash| held.contains(*hash)).cloned().collect())
            };

            assert!(!version_kept_in_store(&store, &lookup, &blocks).unwrap());
            let outcome = ingest_in_batches(&store, &file, &blocks, &record, 2, u64::MAX).unwrap();

            assert_eq!(outcome, IngestOutcome::Ingested);
            assert!(version_kept_in_store(&store, &lookup, &blocks).unwrap());
        }
    }

    /// The proof for a replacement, end to end on a real store and real files.
    mod proof {
        use std::collections::HashSet;
        use std::sync::Mutex;

        use yadorilink_fs_platform::fs_identity::{FileIdentity, TimestampGranularity};
        use yadorilink_local_storage::{hash_block_bytes, SegmentBlockStore};
        use yadorilink_replica_domain::file::BlockInfo;
        use yadorilink_replica_domain::ids::VersionHash;
        use yadorilink_sync_sqlite::file_identity_codec::GenerationId;
        use yadorilink_sync_sqlite::materialization_basis::ReflectedHeads;
        use yadorilink_sync_sqlite::materialized_generation::{
            DiskGenerationBasis, MaterializedObjectKind,
        };
        use yadorilink_sync_sqlite::retention::{RetentionProof, SupersededRow};

        use super::super::{prove_replacement, version_kept_in_store, ProofError};

        const GRANULARITY: TimestampGranularity = TimestampGranularity::Fine;

        struct World {
            _store_dir: tempfile::TempDir,
            store: SegmentBlockStore,
            provenance: Mutex<HashSet<Vec<u8>>>,
            dir: tempfile::TempDir,
        }

        impl World {
            fn new() -> Self {
                let store_dir = tempfile::tempdir().unwrap();
                Self {
                    store: SegmentBlockStore::new(store_dir.path()).unwrap(),
                    _store_dir: store_dir,
                    provenance: Mutex::new(HashSet::new()),
                    dir: tempfile::tempdir().unwrap(),
                }
            }

            fn lookup(&self, hashes: &[Vec<u8>]) -> Result<HashSet<Vec<u8>>, ()> {
                let held = self.provenance.lock().unwrap();
                Ok(hashes.iter().filter(|hash| held.contains(*hash)).cloned().collect())
            }

            fn record(&self, hashes: &[Vec<u8>]) -> Result<(), ()> {
                self.provenance.lock().unwrap().extend(hashes.iter().cloned());
                Ok(())
            }

            /// A file of `count` distinct blocks and the version row and block list for it.
            fn file(
                &self,
                count: usize,
                tag: u8,
            ) -> (std::path::PathBuf, SupersededRow, Vec<BlockInfo>) {
                let size = 2048usize;
                let mut content = Vec::new();
                let mut blocks = Vec::new();
                for index in 0..count {
                    let mut block = vec![tag; size];
                    block[..8].copy_from_slice(&(index as u64).to_be_bytes());
                    blocks.push(BlockInfo {
                        hash: hex::decode(hash_block_bytes(&block)).unwrap(),
                        offset: (index * size) as u64,
                        size: size as u32,
                    });
                    content.extend_from_slice(&block);
                }
                let path = self.dir.path().join(format!("file-{tag}"));
                std::fs::write(&path, &content).unwrap();
                let row = SupersededRow {
                    version_seq: 3,
                    version_hash: VersionHash([tag; 32]),
                    materialization_state: "present".to_string(),
                };
                (path, row, blocks)
            }

            fn prove(
                &self,
                row: &SupersededRow,
                blocks: &[BlockInfo],
                recorded: Option<&DiskGenerationBasis>,
                path: &std::path::Path,
            ) -> Result<RetentionProof, ProofError<()>> {
                prove_replacement(
                    &self.store,
                    &|hashes| self.lookup(hashes),
                    &|hashes| self.record(hashes),
                    row.clone(),
                    blocks,
                    recorded,
                    path,
                    GRANULARITY,
                )
            }

            fn kept(&self, blocks: &[BlockInfo]) -> bool {
                version_kept_in_store(&self.store, &|hashes| self.lookup(hashes), blocks).unwrap()
            }
        }

        fn recorded_write(path: &std::path::Path, written: VersionHash) -> DiskGenerationBasis {
            DiskGenerationBasis {
                generation_id: GenerationId("test:generation".to_string()),
                basis: ReflectedHeads::of(&[], b""),
                resolved_path_state_hash: [0; 32],
                object_kind: MaterializedObjectKind::RegularFile,
                version: Some(written),
                filesystem_identity: Some(FileIdentity::observe_path(path).unwrap()),
            }
        }

        /// The version exists only in the user's file: the proof reads it into the store, and
        /// afterwards the store holds it.
        #[test]
        fn a_version_only_in_its_file_is_read_into_the_store() {
            let world = World::new();
            let (path, row, blocks) = world.file(5, 7);
            assert!(!world.kept(&blocks));

            let proof = world.prove(&row, &blocks, None, &path).unwrap();

            assert_eq!(proof, RetentionProof::InStore(row));
            assert!(world.kept(&blocks), "the old version is now restorable from the store");
        }

        #[test]
        fn a_version_the_store_already_holds_is_proved_without_touching_the_file() {
            let world = World::new();
            let (path, row, blocks) = world.file(3, 8);
            world.prove(&row, &blocks, None, &path).unwrap();
            std::fs::remove_file(&path).unwrap();

            let proof = world.prove(&row, &blocks, None, &path).unwrap();

            assert_eq!(proof, RetentionProof::InStore(row));
        }

        /// A file nobody can vouch for that is not the version: this device holds no bytes of the
        /// version, and nothing is put into the store.
        #[test]
        fn a_file_that_is_not_the_version_gives_no_local_bytes_and_stores_nothing() {
            let world = World::new();
            let (_, row, blocks) = world.file(3, 9);
            let other = world.dir.path().join("something-else");
            std::fs::write(&other, b"an edit of an entirely different length").unwrap();

            let proof = world.prove(&row, &blocks, None, &other).unwrap();

            assert_eq!(proof, RetentionProof::NoLocalBytes(row));
            assert!(!world.kept(&blocks));
        }

        /// A row committed without its content leaves the older file in place: the version being
        /// replaced was never here as bytes, and the older untouched file does not hold it back.
        #[test]
        fn an_older_untouched_file_under_a_newer_row_gives_no_local_bytes() {
            let world = World::new();
            let (older_path, _, _) = world.file(2, 10);
            let (_, newer_row, newer_blocks) = world.file(4, 11);
            let recorded = recorded_write(&older_path, VersionHash([10; 32]));

            let proof =
                world.prove(&newer_row, &newer_blocks, Some(&recorded), &older_path).unwrap();

            assert_eq!(proof, RetentionProof::NoLocalBytes(newer_row));
            assert!(!world.kept(&newer_blocks));
        }

        #[test]
        fn nothing_at_the_path_gives_no_local_bytes() {
            let world = World::new();
            let (_, row, blocks) = world.file(2, 12);
            let missing = world.dir.path().join("missing");

            let proof = world.prove(&row, &blocks, None, &missing).unwrap();

            assert_eq!(proof, RetentionProof::NoLocalBytes(row));
        }

        /// The recorded write names exactly the version being replaced, and the file is untouched:
        /// it is read in.
        #[test]
        fn the_untouched_write_of_the_replaced_version_is_read_in() {
            let world = World::new();
            let (path, row, blocks) = world.file(4, 13);
            let recorded = recorded_write(&path, row.version_hash);

            let proof = world.prove(&row, &blocks, Some(&recorded), &path).unwrap();

            assert_eq!(proof, RetentionProof::InStore(row));
            assert!(world.kept(&blocks));
        }

        /// The store has a block the file's copy of the version does not match: the proof does not
        /// take the damaged block for a kept one.
        #[test]
        fn a_stored_block_whose_record_is_damaged_is_taken_from_the_file_instead() {
            use yadorilink_local_storage::segment_store::testing::flip_one_payload_bit;
            let world = World::new();
            let (path, row, blocks) = world.file(3, 14);
            world.prove(&row, &blocks, None, &path).unwrap();
            flip_one_payload_bit(world._store_dir.path(), &hex::encode(&blocks[1].hash)).unwrap();
            assert!(!world.kept(&blocks), "the damaged block is not a kept one");

            let proof = world.prove(&row, &blocks, None, &path).unwrap();

            assert_eq!(proof, RetentionProof::InStore(row));
            assert!(world.kept(&blocks), "the damaged block was rewritten from the file");
        }
    }
}
