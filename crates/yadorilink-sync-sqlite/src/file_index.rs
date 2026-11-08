//! `FileIndexRepository` owns the plain file-record CRUD subset of the
//! `files` table -- upserts, tombstones, version listing, and per-file
//! metadata columns (record kind, symlink target, exec bit, pinning,
//! last-accessed, block provenance queries that read `files` directly).

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use yadorilink_sqlite_runtime::CachedStatements as _;

use rusqlite::{Connection, OptionalExtension};

use crate::dag_store;
use crate::error::SyncSqliteError;
use crate::materialized_generation::MaterializedObjectKind;
use crate::retention::Retention;
use yadorilink_fs_platform::fs_identity::FileIdentity;
use yadorilink_replica_domain::file::FileVersion;
use yadorilink_replica_domain::file::{BlockInfo, FileRecord, RecordKind};
use yadorilink_replica_domain::ids::{DeviceId, SyncPath};
use yadorilink_replica_domain::local_op::{encoded_op_len, Op, MAX_CHANGE_OP_BYTES};
use yadorilink_replica_domain::recursive_operation::{
    RecursiveOperationId, RecursiveOperationKind, RecursiveOperationRef,
};
/// Re-exported from its home next to the types it hashes. It used to live
/// here, but the digest is now also computed by the peer-facing summary path
/// and by this crate's test doubles, and two definitions of one digest
/// eventually disagree about what they cover.
pub use yadorilink_replica_domain::session_state::durability_roots_digest;
use yadorilink_replica_domain::session_state::{
    ConflictCopyFile, DurabilityRoot, DurabilityRoots, LocalFileMetaColumns, MaterializationState,
    PreparedLocalMutation, RootSetSummary, TrashedFile, VersionRecord, VersionState,
};
use yadorilink_root_authority::root_commit::RootCommitPermit;
use yadorilink_sqlite_runtime::SyncDatabase;

/// Capabilities of a signed local emission: the author and
/// key it signs with, and the permit it commits under.
#[derive(Clone, Copy)]
pub struct SignedEmissionContext<'a> {
    pub author: &'a crate::local_author::LocalAuthor<'a>,
    pub permit: &'a RootCommitPermit<'a>,
}

/// Current wall-clock time in nanoseconds since the Unix epoch, or `None`
/// when this device's clock reads before the epoch.
///
/// The `None` case exists because the `admitted_at_unix_nanos` stamp cannot
/// tolerate the usual `unwrap_or(0)` fallback the sibling helpers below use.
/// A `0` there is not a harmlessly-wrong number: it reads as "admitted at
/// the epoch", which makes the row look present at every possible rewind
/// target and turns an unreadable clock into a confident wrong answer about
/// what a folder held at some past instant. NULL is the honest encoding of
/// "this device does not know when it admitted this row", and the planning
/// layer already has an explicit outcome for it -- see the column's own
/// migration comment in `yadorilink-sqlite-runtime`'s schema, which spells
/// out why neither `0` nor "now" is an acceptable substitute.
pub(crate) fn now_unix_nanos_checked() -> Option<i64> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .map(|d| d.as_nanos() as i64)
}

/// Current wall-clock time in nanoseconds since the Unix epoch, clamped to
/// `0` if the clock reads before the epoch. Same shape as this crate's
/// other `dag_store`/`materialization_job_repository`/`retention_roots`
/// copies. Not for `admitted_at_unix_nanos`: use
/// [`now_unix_nanos_checked`] there, for the reason given on it.
fn now_unix_nanos() -> i64 {
    now_unix_nanos_checked().unwrap_or(0)
}

/// What the index holds about a path that a comparison with the disk by size and time needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexedStatRow {
    pub path: String,
    pub kind: RecordKind,
    pub size: u64,
    pub mtime_unix_nanos: i64,
    pub deleted: bool,
}

pub struct FileIndexRepository {
    database: Arc<SyncDatabase>,
    block_lists: std::sync::Mutex<BlockListCache>,
}

/// A path's current record with its block list shared, not copied: what block serving reads once per
/// request (see [`FileIndexRepository::get_file_shared`]).
#[derive(Clone, Debug)]
pub struct SharedFileRecord {
    pub size: u64,
    pub mtime_unix_nanos: i64,
    pub blocks: Arc<Vec<BlockInfo>>,
    pub deleted: bool,
}

/// Decoded block lists of recently served paths, each kept with the stored text it was decoded from.
/// A lookup reads the stored text again and uses the decoded list only when the text is equal, so
/// a changed row can never be answered from an older list.
/// The stored text of a block list and what it decoded to.
type DecodedBlockList = (String, Arc<Vec<BlockInfo>>);

#[derive(Default)]
struct BlockListCache {
    entries: std::collections::HashMap<(String, String), DecodedBlockList>,
}

/// Paths whose decoded block list is kept: one big file needs one entry for all its block requests.
const BLOCK_LIST_CACHE_PATHS: usize = 64;

impl FileIndexRepository {
    pub fn new(database: Arc<SyncDatabase>) -> Self {
        Self { database, block_lists: Default::default() }
    }

    /// [`get_file`](Self::get_file) for block serving: the same row, the block list shared. A request for
    /// a block of a file with hundreds of blocks used to decode the whole stored list (a JSON array of
    /// numbers per hash) twice per request; the decoded list is now reused while the stored text is
    /// byte-identical, and a different text is decoded fresh.
    pub fn get_file_shared(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<Option<SharedFileRecord>, SyncSqliteError> {
        let row: Option<(u64, i64, String, i64)> =
            self.database.read::<_, SyncSqliteError>(|conn| {
                Ok(conn
                    .query_row_cached(
                        "SELECT size, mtime_unix_nanos, blocks_json, deleted
                     FROM files WHERE group_id = ?1 AND path = ?2 AND state = 'current'",
                        rusqlite::params![group_id, path],
                        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
                    )
                    .optional()?)
            })?;
        let Some((size, mtime_unix_nanos, blocks_json, deleted)) = row else { return Ok(None) };
        let key = (group_id.to_owned(), path.to_owned());
        let cached = {
            let cache = self.block_lists.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            cache
                .entries
                .get(&key)
                .filter(|(text, _)| *text == blocks_json)
                .map(|(_, blocks)| Arc::clone(blocks))
        };
        let blocks = match cached {
            Some(blocks) => blocks,
            None => {
                let record =
                    row_to_record(path.to_string(), size, mtime_unix_nanos, &blocks_json, deleted)?;
                let blocks = Arc::new(record.blocks);
                let mut cache =
                    self.block_lists.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
                if cache.entries.len() >= BLOCK_LIST_CACHE_PATHS
                    && !cache.entries.contains_key(&key)
                {
                    if let Some(victim) = cache.entries.keys().next().cloned() {
                        cache.entries.remove(&victim);
                    }
                }
                cache.entries.insert(key, (blocks_json, Arc::clone(&blocks)));
                blocks
            }
        };
        Ok(Some(SharedFileRecord { size, mtime_unix_nanos, blocks, deleted: deleted != 0 }))
    }

    pub(crate) fn database(&self) -> &Arc<SyncDatabase> {
        &self.database
    }

    /// Plain, origin-agnostic upsert — delegates to
    /// `upsert_file_with_origin` with an empty (unknown) origin. Kept for
    /// every existing caller (overwhelmingly test fixtures that don't care
    /// who "wrote" a record) so this signature never needed to change; see
    /// `upsert_file_with_origin`'s doc comment for the real semantics and
    /// which two production call sites use it directly instead.
    #[cfg(any(test, feature = "test-support"))]
    pub fn upsert_file(
        &self,
        group_id: &str,
        record: &FileRecord,
        permit: &RootCommitPermit,
    ) -> Result<(), SyncSqliteError> {
        self.upsert_file_with_origin(group_id, record, "", permit)
    }

    /// The version-retaining write path — see the free function `upsert_file_in_tx` (this
    /// method's entire implementation) for the exact supersede/trash/
    /// promote-scaffold logic. `origin_device_id` is the local device id
    /// for a local edit, or the sending peer's device id when adopting a
    /// remote version; an empty string means "unknown" (`upsert_file`'s
    /// default), recorded as SQL `NULL` rather than the literal empty
    /// string.
    ///
    /// For fixtures: the replaced version is this device's own, so nothing is asked of it. Code that
    /// writes on a sync's behalf uses [`Self::upsert_file_with_origin_retaining`].
    #[cfg(any(test, feature = "test-support"))]
    pub fn upsert_file_with_origin(
        &self,
        group_id: &str,
        record: &FileRecord,
        origin_device_id: &str,
        permit: &RootCommitPermit,
    ) -> Result<(), SyncSqliteError> {
        self.upsert_file_with_origin_retaining(
            group_id,
            record,
            origin_device_id,
            Retention::OwnEdit,
            permit,
        )
    }

    /// [`Self::upsert_file_with_origin`] with what the write says about the version it replaces.
    pub fn upsert_file_with_origin_retaining(
        &self,
        group_id: &str,
        record: &FileRecord,
        origin_device_id: &str,
        retention: Retention<'_>,
        permit: &RootCommitPermit,
    ) -> Result<(), SyncSqliteError> {
        self.database.write_immediate::<_, SyncSqliteError>(|tx| {
            upsert_file_in_tx(tx, group_id, record, origin_device_id, retention)?;
            permit.verify()?;
            Ok(())
        })
    }

    /// Projected-row upsert for a row that may be produced under NativeState:
    /// `authoring` is the native head the row shows (see
    /// [`upsert_file_with_authoring_in_tx`]). With none it is the plain
    /// [`Self::upsert_file_with_origin`].
    #[allow(clippy::too_many_arguments)] // one argument per input of the persisted row
    pub fn upsert_file_with_origin_and_authoring(
        &self,
        group_id: &str,
        record: &FileRecord,
        origin_device_id: &str,
        authoring: Option<&yadorilink_replica_domain::native_plan::NativeRowIdentity>,
        meta: Option<&LocalFileMetaColumns>,
        retention: Retention<'_>,
        permit: &RootCommitPermit,
    ) -> Result<(), SyncSqliteError> {
        self.database.write_immediate::<_, SyncSqliteError>(|tx| {
            Self::upsert_file_with_origin_and_authoring_in_tx(
                tx,
                group_id,
                record,
                origin_device_id,
                authoring,
                meta,
                retention,
            )?;
            permit.verify()?;
            Ok(())
        })
    }

    /// `_in_tx` counterpart of [`Self::upsert_file_with_origin_and_authoring`]
    /// for a caller whose transaction commits more than this row; the caller
    /// verifies its permit inside that transaction.
    pub fn upsert_file_with_origin_and_authoring_in_tx(
        tx: &rusqlite::Transaction,
        group_id: &str,
        record: &FileRecord,
        origin_device_id: &str,
        authoring: Option<&yadorilink_replica_domain::native_plan::NativeRowIdentity>,
        meta: Option<&LocalFileMetaColumns>,
        retention: Retention<'_>,
    ) -> Result<(), SyncSqliteError> {
        upsert_file_with_meta_in_tx(
            tx,
            group_id,
            record,
            origin_device_id,
            authoring,
            meta,
            retention,
        )?;
        require_row_shows_native_head(tx, group_id, &record.path, authoring)
    }

    /// Upserts many records for one group inside a single SQLite
    /// transaction (batch processing) — used by
    /// `LocalChangeProcessor::scan_existing_files` so a large initial scan
    /// commits once instead of once per file. Semantically identical to
    /// calling `upsert_file_with_origin` for each record in order (same
    /// `origin_device_id` for the whole batch — a scan is always this
    /// device's own local device id); a no-op (no transaction opened) for
    /// an empty batch.
    ///
    /// `metas` is each record's local metadata (record kind, symlink
    /// target/out-of-root, unix mode, xattrs), aligned 1:1 with `records`,
    /// or empty to leave those columns as `upsert_file_in_tx` left them.
    /// It is written in the SAME transaction as the row it belongs to, for
    /// the same reason `upsert_files_batch_emitting_change` does it: a row
    /// and the metadata the scan observed for it must become durable
    /// together or not at all.
    ///
    /// The scan that calls this used to stamp those columns afterwards,
    /// one `UPDATE` per path. The rows were durable before the first of
    /// those ran, and they already satisfy every "the scan finished"
    /// readiness check a caller has, so a restart in the middle came back
    /// to an index that looked complete and was not: most rows carried no
    /// mode. The next boot's scan then compared the real on-disk mode
    /// against that missing value, concluded the path had changed offline,
    /// and authored a metadata-only version for content nobody had
    /// touched — one per affected path, on every such restart.
    ///
    /// `observed` is aligned the same way: index `i`'s `Some` value is
    /// what the scan saw on disk for `records[i]` -- the exact version it
    /// derived for those bytes, the object's kind, and the identity it
    /// observed -- and is what lets this transaction publish the path's
    /// actual-state proof. It carries the version rather than leaving it
    /// to be recomputed here because the scan already has it: it built
    /// the record from the same read.
    pub fn upsert_files_batch(
        &self,
        group_id: &str,
        records: &[FileRecord],
        origin_device_id: &str,
        metas: &[Option<LocalFileMetaColumns>],
        observed: &[Option<ImportedActualState>],
        permit: &RootCommitPermit,
    ) -> Result<(), SyncSqliteError> {
        if records.is_empty() {
            return Ok(());
        }
        if !metas.is_empty() && metas.len() != records.len() {
            return Err(SyncSqliteError::CorruptState(format!(
                "upsert_files_batch length mismatch: {} metas for {} records (metas must be empty or aligned 1:1 with records)",
                metas.len(),
                records.len()
            )));
        }
        if !observed.is_empty() && observed.len() != records.len() {
            return Err(SyncSqliteError::CorruptState(format!(
                "upsert_files_batch length mismatch: {} observations for {} records \
                 (observations must be empty or aligned 1:1 with records)",
                observed.len(),
                records.len()
            )));
        }
        self.database.write_immediate::<_, SyncSqliteError>(|tx| {
            for (idx, record) in records.iter().enumerate() {
                upsert_file_in_tx(tx, group_id, record, origin_device_id, Retention::OwnEdit)?;
                // After the row exists: these columns are an `UPDATE`
                // against the just-written `current` row.
                if let Some(Some(meta)) = metas.get(idx) {
                    apply_local_meta_columns_in_tx(tx, group_id, &record.path, meta)?;
                }
                // Hydrated is published only together with the proof that
                // earns it, in this one transaction -- and where there is
                // no proof to publish, the row is left saying so, rather
                // than inheriting the superseded version's claim. Both
                // arms are mandatory: an unproven upsert that wrote
                // nothing here would leave `Present` carried forward over
                // content this scan never verified.
                //
                // Kind comes from the observation, not from `metas`: the
                // desired state this proof has to match is derived from
                // the version's own metadata, so taking the kind from the
                // index column instead would be a second source of truth
                // for one of the two fields the proof is hashed over.
                match (record.deleted, observed.get(idx)) {
                    (false, Some(Some(observation))) => {
                        adopt_local_capture_actual_state(
                            tx,
                            group_id,
                            &record.path,
                            observation.record_kind,
                            &observation.version_hash,
                            &observation.filesystem_identity,
                        )?;
                        stamp_hydrated_after_local_emission_in_tx(tx, group_id, &record.path)?;
                    }
                    _ => retire_unproven_actual_state_in_tx(tx, group_id, &record.path)?,
                }
            }
            permit.verify()?;
            Ok(())
        })
    }

    /// Marks a file deleted (tombstone), preserving its version vector
    /// lineage so the deletion itself propagates as a normal index update.
    /// Stamps the tombstone's `mtime_unix_nanos` with "now" — the right
    /// choice for every caller of this method (a full-rescan recovery, a
    /// direct test, `hydration.rs`'s bookkeeping): none of them have an
    /// earlier, more accurate observation of when the deletion actually
    /// happened to prefer instead. `mark_deleted_at` is the one exception
    /// (see its own doc comment).
    pub fn mark_deleted(
        &self,
        group_id: &str,
        path: &str,
        device_id: &str,
        permit: &RootCommitPermit,
    ) -> Result<(), SyncSqliteError> {
        self.mark_deleted_at(group_id, path, device_id, now_unix_nanos(), permit)
    }

    /// Like `mark_deleted`, but stamps the tombstone with a caller-supplied
    /// observed time instead of "now".
    ///
    /// `local_change.rs`'s
    /// debounced dispatch of a `Removed` event is the one caller that
    /// needs this — a local deletion can sit in the debounce accumulator
    /// for up to `DebounceConfig::quiet_period` (default 300ms) before
    /// `mark_deleted` actually runs, so stamping "now" *at dispatch time*
    /// would record a tombstone time systematically *later* than the
    /// deletion's true, watcher-observed moment — unlike a concurrent
    /// edit's `mtime_unix_nanos`, which is always the file's own real
    /// content-modification time (`std::fs::metadata`), never delayed by
    /// debounce. That asymmetry alone can invert the correct chronological
    /// order between a genuinely-earlier delete and a genuinely-later
    /// edit once `conflict.rs` compares them — confirmed via
    /// `concurrent_edit_delete_edit_wins_when_later_leaves_no_conflict_artifact`
    /// regressing under a naive "now at dispatch time" stamp. Passing the
    /// debounce accumulator's own per-path last-observed timestamp here
    /// (`debounce::DebounceFlush::Paths`'s third tuple element) closes
    /// that gap.
    pub fn mark_deleted_at(
        &self,
        group_id: &str,
        path: &str,
        device_id: &str,
        observed_at_unix_nanos: i64,
        permit: &RootCommitPermit,
    ) -> Result<(), SyncSqliteError> {
        let mut record = self.get_file(group_id, path)?.unwrap_or(FileRecord {
            path: path.to_string(),
            size: 0,
            mtime_unix_nanos: 0,
            blocks: vec![],
            deleted: false,
        });
        record.deleted = true;
        // Stamp the tombstone
        // with the deletion's own observed time, not the mtime carried
        // forward from the file's last live content (the field above is
        // only overwritten here, nowhere else in this function) — a stale
        // content mtime gives `conflict.rs`'s `a_is_loser`/
        // `resolve_conflict_names` no correct chronological signal to
        // order a concurrent edit against this delete once the race that
        // used to mask the conflict path entirely is fixed (see
        // `peer_session::PeerSyncSession::reconcile_one_file`).
        record.mtime_unix_nanos = observed_at_unix_nanos;
        // `device_id` is a known origin (this device, for a local delete)
        // — recorded on the tombstone row itself, and the row it
        // supersedes (the file's last live content, if any) is retained as
        // `state = 'trashed'` rather than discarded — see
        // `upsert_file_in_tx`'s doc comment for the exact rule.
        //
        // Open-coded rather than delegated to `upsert_file_with_origin`
        // because of the second statement, which has to share this
        // transaction. This method has no evidence about the path: its
        // callers reach it from a watcher event, or from a lock-free
        // snapshot of paths orphaned by a vanished directory, and none of
        // them revalidated absence under this path's own lock. So the
        // proof naming the content that used to be here -- still current
        // against the fence, and still paired with the `Present` this
        // tombstone inherits from the row it supersedes -- must not
        // survive the write that says the file is gone.
        self.database.write_immediate::<_, SyncSqliteError>(|tx| {
            upsert_file_in_tx(tx, group_id, &record, device_id, Retention::OwnEdit)?;
            retire_unproven_actual_state_in_tx(tx, group_id, path)?;
            permit.verify()?;
            Ok(())
        })
    }

    /// Commits a bounded batch of prepared local mutations in one
    /// transaction as signed native deltas: each mutation is one delta,
    /// committed with its row in one transaction only while the row still
    /// shows what the mutation's native witness recorded at capture. A row
    /// that no longer shows it refuses the whole batch with
    /// [`SyncSqliteError::LocalWriteCaptureStale`] and nothing is written.
    pub fn commit_local_mutations_batch(
        &self,
        group_id: &str,
        mutations: &[PreparedLocalMutation],
        evidence: &[Option<LocalCaptureActualStateEvidence>],
        origin_device_id: &str,
        emission: SignedEmissionContext<'_>,
    ) -> Result<(), SyncSqliteError> {
        if mutations.is_empty() {
            return Ok(());
        }
        if !evidence.is_empty() && evidence.len() != mutations.len() {
            return Err(SyncSqliteError::CorruptState(format!(
                "commit_local_mutations_batch length mismatch: {} evidence entries for {} \
                 mutations (evidence must be empty or aligned 1:1 with mutations)",
                evidence.len(),
                mutations.len()
            )));
        }
        self.database.write_immediate::<_, SyncSqliteError>(|tx| {
            for mutation in mutations {
                crate::held_path::refuse_local_authoring_if_held(
                    tx,
                    group_id,
                    &mutation.record().path,
                )?;
                crate::paused_items::refuse_local_authoring_if_paused(
                    tx,
                    group_id,
                    &mutation.record().path,
                )?;
            }
            // One signed multi-op delta per run of mutations at unrelated paths
            // (a bulk capture), so a batch costs one signature per run, not one
            // per file; a lone mutation (a live edit) is still its own delta.
            // The whole batch is one transaction: a stale or unauthorable
            // mutation fails every run, as it did when each was its own delta.
            let items: Vec<crate::native_authoring::BulkOp<'_>> = mutations
                .iter()
                .map(|mutation| crate::native_authoring::BulkOp {
                    op: mutation.op(),
                    witness: mutation.native_witness(),
                })
                .collect();
            for run in crate::native_authoring::bulk_groups(&items) {
                let run_evidence: Vec<Option<&LocalCaptureActualStateEvidence>> =
                    run.clone().map(|i| evidence.get(i).and_then(|e| e.as_ref())).collect();
                commit_local_mutation_group_in_tx(
                    tx,
                    group_id,
                    &mutations[run],
                    &run_evidence,
                    origin_device_id,
                    emission.author,
                )?;
            }
            emission.permit.verify()?;
            Ok(())
        })
    }

    /// Commits a recursive operation as signed native deltas: copies are
    /// written through to their sources, each part a delta committed only
    /// while the rows it acts on still show what their native witnesses
    /// recorded at capture. A row that no longer shows it refuses the whole
    /// operation with [`SyncSqliteError::LocalWriteCaptureStale`].
    pub fn commit_recursive_operation(
        &self,
        group_id: &str,
        kind: RecursiveOperationKind,
        mutations: &[PreparedLocalMutation],
        evidence: &[Option<LocalCaptureActualStateEvidence>],
        origin_device_id: &str,
        emission: SignedEmissionContext<'_>,
    ) -> Result<(), SyncSqliteError> {
        if mutations.is_empty() {
            return Ok(());
        }
        if !evidence.is_empty() && evidence.len() != mutations.len() {
            return Err(SyncSqliteError::CorruptState(format!(
                "commit_recursive_operation length mismatch: {} evidence entries for {} \
                 mutations",
                evidence.len(),
                mutations.len()
            )));
        }
        self.database.write_immediate::<_, SyncSqliteError>(|tx| {
            for mutation in mutations {
                crate::paused_items::refuse_local_authoring_if_paused(
                    tx,
                    group_id,
                    &mutation.record().path,
                )?;
            }
            commit_recursive_operation_in_tx(
                tx,
                group_id,
                &kind,
                mutations,
                evidence,
                origin_device_id,
                emission.author,
                true,
            )?;
            emission.permit.verify()?;
            Ok(())
        })
    }

    /// Deletes every version row for one path -- not a tombstone, an
    /// erasure of this device's local index entry. Every caller says why
    /// ([`ErasureReason`]): the ignore sweep, for a path that has just become
    /// ignored (sync must stop considering it, but nothing about
    /// it is deleted for anyone else), or the retirement of a purely local
    /// artifact that no admitted change ever touched.
    ///
    /// A path with a native authoring head has replicated history, which a
    /// sync's replacement keeps for a while (a version that a sync replaces
    /// is kept for up to 10 versions and 30 days): erasing it as a "local
    /// artifact" is refused, and such a path goes through the supersede path
    /// instead. The ignore sweep is the user's own act, and a namespace
    /// displacement keeps today's behaviour; neither is refused.
    ///
    /// The erasure takes the path's admission history with it, and
    /// un-ignoring it later re-indexes it from `version_seq = 1`. So the
    /// same transaction records the path in `path_local_history_erased`,
    /// which tells the rewind planning layer that this path's surviving
    /// rows no longer reach back to its own first version: for a target
    /// before the re-index it answers `Unavailable`, never `Delete`. A
    /// per-path record rather than `group_local_history_floor`, which would
    /// make every OTHER path in the group unanswerable as well.
    pub fn remove_file(
        &self,
        group_id: &str,
        path: &str,
        reason: ErasureReason,
        permit: &RootCommitPermit,
    ) -> Result<bool, SyncSqliteError> {
        permit.verify()?;
        self.database.write_immediate::<_, SyncSqliteError>(|tx| {
            // A row of a frozen group stays until the rebootstrap has finished.
            crate::native_rebootstrap::refuse_materialization_if_frozen(tx, group_id)?;
            if reason == ErasureReason::LocalOnlyArtifact {
                let has_native_history: bool = tx.query_row_cached(
                    "SELECT EXISTS(SELECT 1 FROM files WHERE group_id = ?1 AND path = ?2 \
                     AND native_authoring_identity IS NOT NULL)",
                    rusqlite::params![group_id, path],
                    |row| row.get(0),
                )?;
                if has_native_history {
                    return Err(SyncSqliteError::InvalidInput(format!(
                        "{path:?} has replicated history; it is not a local-only artifact"
                    )));
                }
            }
            let newest_admission: Option<i64> = tx.query_row_cached(
                "SELECT MAX(admitted_at_unix_nanos) FROM files WHERE group_id = ?1 AND path = ?2",
                rusqlite::params![group_id, path],
                |row| row.get(0),
            )?;
            let removed = tx.execute_cached(
                "DELETE FROM files WHERE group_id = ?1 AND path = ?2",
                rusqlite::params![group_id, path],
            )? > 0;
            if removed {
                crate::rewind_plan::record_path_history_erased(
                    tx,
                    group_id,
                    path,
                    newest_admission,
                )?;
            }
            Ok(removed)
        })
    }

    pub fn get_file(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<Option<FileRecord>, SyncSqliteError> {
        // Retried like every writer below: a shared-cache in-memory database
        // (every test's `open_in_memory`) can hand a plain read `DatabaseLocked`
        // (or, under sustained contention past `busy_timeout`'s window,
        // `DatabaseBusy` — see `retry_on_database_locked`'s own doc comment)
        // while a concurrent writer holds the table, so a caller polling state
        // from a background task (e.g. a wire-convergence test reading while a
        // real `PeerSyncSession::run()` loop writes) must retry a read here too.
        self.database.read::<_, SyncSqliteError>(|conn| {
            let row: Option<(u64, i64, String, i64)> = conn
                .query_row_cached(
                    "SELECT size, mtime_unix_nanos, blocks_json, deleted
                     FROM files WHERE group_id = ?1 AND path = ?2 AND state = 'current'",
                    rusqlite::params![group_id, path],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
                )
                .optional()?;
            row.map(|(size, mtime, blocks_json, deleted)| {
                row_to_record(path.to_string(), size, mtime, &blocks_json, deleted)
            })
            .transpose()
        })
    }

    /// The `state = 'current'` row for `(group, path)` read as ONE atomic
    /// statement, carrying every column a `FileVersion` identity needs
    /// (blocks, size, mtime, record kind, symlink target, exec bit). Unlike
    /// stitching `get_file` together with the separate `get_record_kind`/
    /// `get_symlink_target`/`get_unix_mode` accessors — each its own
    /// `SELECT ... state = 'current'` — this cannot tear across a concurrent
    /// metadata/content transition: every field comes from the same row, so
    /// the `change::VersionHash` derived via [`CurrentVersionRecord::
    /// to_file_version`] always describes a version some single row actually
    /// held, never a hybrid snapshot of two. This is the read the durability
    /// custody path (eviction querier + responder) must use to reconstruct
    /// the current version's identity. `None` if there is no current row.
    pub fn list_files(&self, group_id: &str) -> Result<Vec<FileRecord>, SyncSqliteError> {
        // See `get_file`'s comment: retried for the same read-vs-writer
        // `DatabaseLocked` reason.
        self.database.read::<_, SyncSqliteError>(|conn| {
            let mut stmt = conn.prepare_cached(
                "SELECT path, size, mtime_unix_nanos, blocks_json, deleted FROM \
                 files WHERE group_id = ?1 AND state = 'current'",
            )?;
            let rows = stmt.query_map([group_id], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get(1)?,
                    r.get(2)?,
                    r.get::<_, String>(3)?,
                    r.get(4)?,
                ))
            })?;
            let mut out = Vec::new();
            for row in rows {
                let (path, size, mtime, blocks_json, deleted) = row?;
                // Fail the whole listing closed on a corrupt row rather than
                // silently dropping content or emitting a defaulted record: a
                // directory listing built from partially-corrupt index rows is a
                // worse failure than a hard, diagnosable error (the corrupt path is
                // named by `row_to_record`'s `warn!`).
                out.push(row_to_record(path, size, mtime, &blocks_json, deleted)?);
            }
            Ok(out)
        })
    }

    /// Every live (not deleted) current row of `group_id` with its kind and symlink target, in
    /// path order, from ONE statement, so each row's fields describe a single incarnation of it.
    /// What the replacement confirm compares the disk against.
    pub fn list_current_entries(
        &self,
        group_id: &str,
    ) -> Result<Vec<CurrentEntry>, SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| {
            let mut stmt = conn.prepare_cached(
                "SELECT path, blocks_json, record_kind, symlink_target FROM files \
                 WHERE group_id = ?1 AND state = 'current' AND deleted = 0 ORDER BY path",
            )?;
            let rows = stmt.query_map([group_id], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, Option<String>>(2)?,
                    r.get::<_, Option<Vec<u8>>>(3)?,
                ))
            })?;
            let mut out = Vec::new();
            for row in rows {
                let (path, blocks_json, kind, symlink_target) = row?;
                let record = row_to_record(path, 0, 0, &blocks_json, 0)?;
                out.push(CurrentEntry {
                    path: record.path,
                    kind: kind.as_deref().map_or(RecordKind::File, RecordKind::from_db_str),
                    blocks: record.blocks,
                    symlink_target,
                });
            }
            Ok(out)
        })
    }

    /// The live, current rows of `group_id` other than `path` itself whose
    /// stored `key` column equals `folded`, in path order. An index lookup:
    /// the receive path asks this once per file, so it must not grow with
    /// the group.
    pub fn name_fold_matches(
        &self,
        group_id: &str,
        key: NameFoldKey,
        folded: &str,
        path: &str,
    ) -> Result<Vec<String>, SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| {
            name_fold_matches_on(conn, group_id, key, folded, path)
        })
    }

    /// The live rows of `group_id` whose path carries the conflict-copy
    /// marker anywhere in it, read through `files_conflict_copy_candidates`
    /// so the cost follows the number of such rows, not the group's size.
    /// A superset of `is_conflict_copy_path` (which looks at the filename
    /// only): callers apply that rule to what this returns.
    pub fn list_live_conflict_copy_candidates(
        &self,
        group_id: &str,
    ) -> Result<Vec<FileRecord>, SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| {
            let mut stmt = conn.prepare(CONFLICT_COPY_CANDIDATES_SQL)?;
            let rows = stmt.query_map([group_id], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get(1)?,
                    r.get(2)?,
                    r.get::<_, String>(3)?,
                    r.get(4)?,
                ))
            })?;
            let mut out = Vec::new();
            for row in rows {
                let (path, size, mtime, blocks_json, deleted) = row?;
                out.push(row_to_record(path, size, mtime, &blocks_json, deleted)?);
            }
            Ok(out)
        })
    }

    /// [`Self::list_files`] with each row's own `record_kind`, read from the
    /// same statement so a listing can never pair one row's content with
    /// another row's kind. For surfaces that list entries by kind (the
    /// shell's folder listing); sync paths keep using `list_files`.
    pub fn list_files_with_kind(
        &self,
        group_id: &str,
    ) -> Result<Vec<(FileRecord, RecordKind)>, SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| {
            let mut stmt = conn.prepare_cached(
                "SELECT path, size, mtime_unix_nanos, blocks_json, deleted, record_kind \
                 FROM files WHERE group_id = ?1 AND state = 'current'",
            )?;
            let rows = stmt.query_map([group_id], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get(1)?,
                    r.get(2)?,
                    r.get::<_, String>(3)?,
                    r.get(4)?,
                    r.get::<_, String>(5)?,
                ))
            })?;
            let mut out = Vec::new();
            for row in rows {
                let (path, size, mtime, blocks_json, deleted, record_kind) = row?;
                // Fails closed on a corrupt row, same as `list_files`.
                out.push((
                    row_to_record(path, size, mtime, &blocks_json, deleted)?,
                    RecordKind::from_db_str(&record_kind),
                ));
            }
            Ok(out)
        })
    }

    /// The path and kind of every current row of `group_id` (tombstones
    /// included), without reading the rows' content columns: what
    /// [`Self::list_files_with_kind`] lists, for a caller that only asks
    /// whether the index has a path.
    pub fn list_indexed_paths_with_kind(
        &self,
        group_id: &str,
    ) -> Result<Vec<(String, RecordKind)>, SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| {
            let mut stmt = conn.prepare_cached(
                "SELECT path, record_kind FROM files WHERE group_id = ?1 AND state = 'current'",
            )?;
            let rows = stmt
                .query_map([group_id], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?;
            let mut out = Vec::new();
            for row in rows {
                let (path, record_kind) = row?;
                out.push((path, RecordKind::from_db_str(&record_kind)));
            }
            Ok(out)
        })
    }

    /// The path, kind, size, modification time and tombstone mark of every current row of
    /// `group_id`, without reading the rows' content columns (block lists): what a metadata-only
    /// comparison against the disk needs, for the periodic drift check.
    pub fn list_indexed_stat_rows(
        &self,
        group_id: &str,
    ) -> Result<Vec<IndexedStatRow>, SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| {
            let mut stmt = conn.prepare_cached(
                "SELECT path, record_kind, size, mtime_unix_nanos, deleted FROM files \
                 WHERE group_id = ?1 AND state = 'current'",
            )?;
            let rows = stmt.query_map([group_id], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, i64>(2)?,
                    r.get::<_, i64>(3)?,
                    r.get::<_, i64>(4)?,
                ))
            })?;
            let mut out = Vec::new();
            for row in rows {
                let (path, record_kind, size, mtime_unix_nanos, deleted) = row?;
                out.push(IndexedStatRow {
                    path,
                    kind: RecordKind::from_db_str(&record_kind),
                    size: size.max(0) as u64,
                    mtime_unix_nanos,
                    deleted: deleted != 0,
                });
            }
            Ok(out)
        })
    }

    /// Bulk-loads every local
    /// `FileRecord` (including tombstones — deleted rows are not filtered
    /// here, matching `get_file`'s own behavior) whose `path` is in
    /// `paths`, for `group_id`, keyed by path — the batched counterpart to
    /// calling `get_file` once per path. Mirrors the existing bulk-load
    /// pattern `LocalChangeProcessor::scan_existing_files` already uses via
    /// `list_files` — collecting the batch of incoming paths/hashes and
    /// issuing set-based queries, then diffing in memory — but scoped to
    /// exactly the requested paths via `WHERE path IN (...)`
    /// rather than loading the whole group — the right shape for
    /// materialization audits, where the requested paths are often a handful
    /// of records out of a much larger indexed group, not the whole file list.
    ///
    /// Chunks the `IN (...)` query at `GET_FILES_BY_PATHS_CHUNK_SIZE`
    /// paths per round trip (SQLite's compiled bound-parameter limit is a
    /// real, if generous, ceiling — chunking avoids ever depending on it
    /// being large enough for an arbitrarily big `paths`). A no-op query
    /// for an empty `paths`. A path with no matching row is simply absent
    /// from the returned map, exactly as `get_file` returning `None` for a
    /// path with no row.
    pub fn get_files_by_paths(
        &self,
        group_id: &str,
        paths: &[String],
    ) -> Result<HashMap<String, FileRecord>, SyncSqliteError> {
        const GET_FILES_BY_PATHS_CHUNK_SIZE: usize = 500;
        if paths.is_empty() {
            return Ok(HashMap::new());
        }
        self.database.read::<_, SyncSqliteError>(|conn| {
            let mut out = HashMap::with_capacity(paths.len());
            for chunk in paths.chunks(GET_FILES_BY_PATHS_CHUNK_SIZE) {
                let placeholders =
                    std::iter::repeat_n("?", chunk.len()).collect::<Vec<_>>().join(",");
                let sql = format!(
                    "SELECT path, size, mtime_unix_nanos, blocks_json, deleted \
                     FROM files WHERE group_id = ? AND state = 'current' AND path IN \
                     ({placeholders})"
                );
                let mut stmt = conn.prepare(&sql)?;
                let params = std::iter::once(&group_id as &dyn rusqlite::ToSql)
                    .chain(chunk.iter().map(|p| p as &dyn rusqlite::ToSql));
                let rows = stmt.query_map(rusqlite::params_from_iter(params), |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get(1)?,
                        r.get(2)?,
                        r.get::<_, String>(3)?,
                        r.get(4)?,
                    ))
                })?;
                for row in rows {
                    let (path, size, mtime, blocks_json, deleted) = row?;
                    // Fail closed on a corrupt row (same rationale as `list_files`).
                    let record = row_to_record(path.clone(), size, mtime, &blocks_json, deleted)?;
                    out.insert(path, record);
                }
            }
            Ok(out)
        })
    }

    /// Every column of `path`'s `state = 'current'` row that a
    /// materialization decision or a proof can depend on, read as ONE
    /// statement -- see [`crate::read_canonical_current_row`], which this
    /// is a repository-level handle for.
    ///
    /// Exists so a caller that needs more than one of those columns never
    /// assembles them from several point queries. `get_file` plus
    /// `get_record_kind` plus `get_symlink_target` plus `get_unix_mode`
    /// plus `get_xattrs` plus `get_origin_device_id` plus
    /// `get_unix_mode` is a handful of independent read
    /// transactions, and nothing holds the row still across them: the
    /// result can pair the blocks of one incarnation with the mode of
    /// another. Each of those accessors stays, for the callers that
    /// genuinely want one column as a guard.
    pub fn canonical_current_row(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<Option<crate::CanonicalCurrentRow>, SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| {
            crate::read_canonical_current_row(conn, group_id, path)
        })
    }

    /// Native's own capture witness for `path`, read at the same
    /// moment a caller reads [`canonical_current_row`] -- see
    /// [`crate::native_capture::capture_native_witness`] for
    /// the exact semantics.
    pub fn native_capture_witness(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<yadorilink_replica_domain::native_state::NativeCaptureWitness, SyncSqliteError>
    {
        let group_id = yadorilink_replica_domain::ids::FolderGroupId(group_id.to_string());
        // One snapshot: the placement, the row and the class must describe the
        // same instant, or a head that arrives between the reads would be
        // recorded as one the writer saw.
        self.database.read_snapshot::<_, SyncSqliteError>(|conn| {
            crate::native_capture::capture_native_witness(conn, &group_id, path)
        })
    }

    /// [`Self::native_capture_witness`] for every path native knows in the
    /// group, from one read; a path missing from the result is absent
    /// ([`crate::native_capture::absent_native_witness`]).
    pub fn native_capture_witnesses(
        &self,
        group_id: &str,
    ) -> Result<
        std::collections::HashMap<
            String,
            yadorilink_replica_domain::native_state::NativeCaptureWitness,
        >,
        SyncSqliteError,
    > {
        let group = yadorilink_replica_domain::ids::FolderGroupId(group_id.to_string());
        self.database.read_snapshot::<_, SyncSqliteError>(|conn| {
            crate::native_capture::capture_native_witnesses(conn, &group)
        })
    }

    /// Raises an obligation for every planned entry that has no live row (see
    /// [`Self::native_plan_gap_paths`]) so the convergence engine projects it,
    /// and returns how many paths were armed.
    pub fn arm_native_plan_gaps(&self, group_id: &str) -> Result<usize, SyncSqliteError> {
        self.database.write_immediate::<_, SyncSqliteError>(|tx| {
            let gaps = crate::native_desired_state::native_plan_gap_paths(tx, group_id)?;
            let paths: Vec<&str> = gaps.iter().map(String::as_str).collect();
            crate::projection_obligations::bump_projection_obligations_for_touched_paths(
                tx,
                group_id,
                &paths,
                now_unix_nanos(),
            )?;
            Ok(paths.len())
        })
    }

    /// The source paths whose planned entry has no live row here: the plan
    /// names a file, copy or directory at a physical path and this device's
    /// index holds nothing there. A missed wake-up leaves exactly this, with
    /// no obligation to repair it, so the periodic audit seeds these paths.
    pub fn native_plan_gap_paths(
        &self,
        group_id: &str,
    ) -> Result<std::collections::BTreeSet<String>, SyncSqliteError> {
        self.database.write_immediate::<_, SyncSqliteError>(|tx| {
            crate::native_desired_state::native_plan_gap_paths(tx, group_id)
        })
    }

    /// The number of contested paths of `group_id`
    /// ([`crate::native_contest_candidates::count`]).
    pub fn contested_path_count(&self, group_id: &str) -> Result<u64, SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| {
            crate::native_contest_candidates::count(conn, group_id)
        })
    }

    /// [`crate::displacement_guard::version_present_elsewhere`].
    pub fn version_present_elsewhere(
        &self,
        group_id: &str,
        path: &str,
        version: &yadorilink_replica_domain::ids::VersionHash,
    ) -> Result<bool, SyncSqliteError> {
        self.database.read_snapshot::<_, SyncSqliteError>(|conn| {
            crate::displacement_guard::version_present_elsewhere(conn, group_id, path, version)
        })
    }

    /// The displacement guard for `path` about to show `planned`
    /// ([`crate::displacement_guard::displacement_guard`]).
    pub fn displacement_guard(
        &self,
        group_id: &str,
        path: &str,
        planned: Option<&yadorilink_replica_domain::ids::VersionHash>,
        folds_onto_path: &dyn Fn(&str) -> bool,
    ) -> Result<crate::displacement_guard::DisplacementGuard, SyncSqliteError> {
        self.database.read_snapshot::<_, SyncSqliteError>(|conn| {
            crate::displacement_guard::displacement_guard(
                conn,
                group_id,
                path,
                planned,
                folds_onto_path,
            )
        })
    }

    /// One directory level of native's materialization plan
    /// ([`crate::native_desired_state::native_plan_level`]).
    pub fn native_plan_level(
        &self,
        group_id: &str,
        parent: &str,
    ) -> Result<yadorilink_replica_domain::native_plan::NativeLevelPlan, SyncSqliteError> {
        self.database.read_snapshot::<_, SyncSqliteError>(|conn| {
            crate::native_desired_state::native_plan_level(conn, group_id, parent)
        })
    }

    /// The node of [`Self::native_plan_level`] at `path`, computed without reading the
    /// siblings of `path` ([`crate::native_desired_state::native_plan_node`]).
    pub fn native_plan_node(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<Option<yadorilink_replica_domain::native_plan::NativePlannedNode>, SyncSqliteError>
    {
        self.database.read_snapshot::<_, SyncSqliteError>(|conn| {
            crate::native_desired_state::native_plan_node(conn, group_id, path)
        })
    }

    /// The nodes of [`Self::native_plan_level`] that `names` are or stand for
    /// ([`crate::native_desired_state::native_plan_nodes`]).
    pub fn native_plan_nodes(
        &self,
        group_id: &str,
        parent: &str,
        names: &std::collections::BTreeSet<String>,
    ) -> Result<yadorilink_replica_domain::native_plan::NativeLevelPlan, SyncSqliteError> {
        self.database.read_snapshot::<_, SyncSqliteError>(|conn| {
            crate::native_desired_state::native_plan_nodes(conn, group_id, parent, names)
        })
    }

    /// Whether native still shows `witness` at its physical path: the
    /// verdict [`crate::native_capture::require_fresh_native_capture`]
    /// enforces at commit, asked early so capture can leave a stale path
    /// journaled dirty instead of failing a whole batch.
    pub fn native_capture_is_fresh(
        &self,
        group_id: &str,
        witness: &yadorilink_replica_domain::native_state::NativeCaptureWitness,
    ) -> Result<bool, SyncSqliteError> {
        let group = yadorilink_replica_domain::ids::FolderGroupId(group_id.to_string());
        self.database.read_snapshot::<_, SyncSqliteError>(|conn| {
            Ok(matches!(
                crate::native_capture::verify_native_capture_witness(conn, &group, witness)?,
                crate::native_capture::NativeStaleCaptureVerdict::Fresh
            ))
        })
    }

    /// What the kept history holds that nothing current needs, from the file index: the unique
    /// stored size of blocks named only by non-current rows (superseded or trashed, with bytes),
    /// and how many such versions there are (a version counts when at least one of its blocks is
    /// named by no current row). Across all groups, as the block store is shared.
    ///
    /// Only blocks this device holds (`is_held`) count: a version kept without its bytes (this
    /// device never had them, so only its row is history) takes no space and frees none.
    pub fn kept_history_usage(
        &self,
        is_held: &dyn Fn(&[u8]) -> bool,
    ) -> Result<(u64, u64), SyncSqliteError> {
        const CURRENT_BLOCKS: &str = "SELECT json_extract(c.value, '$.hash') \
             FROM files cur, json_each(cur.blocks_json) c \
             WHERE cur.state = 'current' AND cur.deleted = 0";
        let rows: Vec<(String, String, i64, i64)> =
            self.database.read::<_, SyncSqliteError>(|conn| {
                let mut stmt = conn.prepare(&format!(
                    "SELECT f.group_id || '/' || f.path || '#' || f.version_seq, \
                            json_extract(j.value, '$.hash'), json_extract(j.value, '$.size'), 0 \
                     FROM files f, json_each(f.blocks_json) j \
                     WHERE f.state IN ('superseded', 'trashed') AND f.deleted = 0 \
                       AND json_extract(j.value, '$.hash') NOT IN ({CURRENT_BLOCKS})"
                ))?;
                let rows = stmt
                    .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))?
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(rows)
            })?;
        let mut held_hashes: HashSet<String> = HashSet::new();
        let mut versions: HashSet<String> = HashSet::new();
        let mut bytes: u64 = 0;
        let mut checked: HashMap<String, bool> = HashMap::new();
        for (version, hash_json, size, _) in rows {
            let held = *checked.entry(hash_json.clone()).or_insert_with(|| {
                serde_json::from_str::<Vec<u8>>(&hash_json).is_ok_and(|hash| is_held(&hash))
            });
            if !held {
                continue;
            }
            versions.insert(version);
            if held_hashes.insert(hash_json) {
                bytes += size.max(0) as u64;
            }
        }
        Ok((bytes, versions.len() as u64))
    }

    /// Whether a retained older version of `path` (superseded or trashed, with bytes) names any of
    /// `blocks`.
    pub fn history_names_any_block(
        &self,
        group_id: &str,
        path: &str,
        blocks: &[yadorilink_replica_domain::file::VersionBlock],
    ) -> Result<bool, SyncSqliteError> {
        let wanted: HashSet<Vec<u8>> = blocks.iter().map(|b| b.hash.0.clone()).collect();
        self.database.read::<_, SyncSqliteError>(|conn| {
            let mut stmt = conn.prepare_cached(
                "SELECT blocks_json FROM files WHERE group_id = ?1 AND path = ?2 \
                 AND state IN ('superseded', 'trashed') AND deleted = 0",
            )?;
            let rows =
                stmt.query_map(rusqlite::params![group_id, path], |r| r.get::<_, String>(0))?;
            for row in rows {
                let blocks: Vec<BlockInfo> = serde_json::from_str(&row?)?;
                if blocks.iter().any(|block| wanted.contains(&block.hash)) {
                    return Ok(true);
                }
            }
            Ok(false)
        })
    }

    /// The recorded event that dropped version number `version_seq` of `path`, when
    /// [`Self::get_version`] finds nothing: it says why the version is gone. No event covering the
    /// number means the version never existed here.
    pub fn version_not_kept(
        &self,
        group_id: &str,
        path: &str,
        version_seq: i64,
    ) -> Result<Option<crate::history_freed::FreedSpan>, SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| {
            crate::history_freed::span_covering_seq(conn, group_id, path, version_seq)
        })
    }

    /// A single retained version by its exact `version_seq` — the restore
    /// engine's lookup for `yadorilink restore <path> --version
    /// <id>`. `None` if no row exists at all for this exact
    /// `(group_id, path, version_seq)`.
    pub fn get_version(
        &self,
        group_id: &str,
        path: &str,
        version_seq: i64,
    ) -> Result<Option<VersionRecord>, SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| {
            #[allow(clippy::type_complexity)]
            let row: Option<(
                u64,
                i64,
                String,
                i64,
                String,
                Option<String>,
                String,
                Option<Vec<u8>>,
                i64,
            )> = conn
                .query_row_cached(
                    "SELECT size, mtime_unix_nanos, blocks_json, deleted, state, \
                            origin_device_id, record_kind, symlink_target, exec \
                     FROM files WHERE group_id = ?1 AND path = ?2 AND version_seq = ?3",
                    rusqlite::params![group_id, path, version_seq],
                    |r| {
                        Ok((
                            r.get(0)?,
                            r.get(1)?,
                            r.get(2)?,
                            r.get(3)?,
                            r.get(4)?,
                            r.get(5)?,
                            r.get(6)?,
                            r.get(7)?,
                            r.get(8)?,
                        ))
                    },
                )
                .optional()?;
            row.map(
                |(
                    size,
                    mtime,
                    blocks_json,
                    deleted,
                    state,
                    origin_device_id,
                    record_kind,
                    symlink_target,
                    exec,
                )| {
                    version_record(
                        path.to_string(),
                        version_seq,
                        size,
                        mtime,
                        &blocks_json,
                        deleted,
                        &state,
                        origin_device_id,
                        &record_kind,
                        symlink_target,
                        exec,
                    )
                },
            )
            .transpose()
        })
    }

    /// spec "Deletion Enters Recoverable Trash" / CLI "trash list": every
    /// path currently in the trashed state for `group_id` — i.e. a path
    /// whose `current` row is itself a tombstone (`deleted = 1`) and that
    /// has at least one retained `state = 'trashed'` row (the last live
    /// content before that deletion). Returns the *most recent* trashed
    /// row per path (its highest `version_seq`) alongside the tombstone's
    /// own `mtime_unix_nanos` as the deletion time — the pair `trash
    /// restore` needs (last-known size/content, and when it was deleted).
    /// A path deleted, restored, and deleted again correctly surfaces only
    /// its latest trashed version, not every historical one (`list_versions`
    /// is the place for full history).
    pub fn list_trashed(&self, group_id: &str) -> Result<Vec<TrashedFile>, SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| {
            let mut stmt = conn.prepare_cached(
                "SELECT t.path, t.version_seq, t.size, t.mtime_unix_nanos, t.origin_device_id, \
                        c.mtime_unix_nanos, t.trashed_by_operation_author, \
                        t.trashed_by_operation_id, t.record_kind
                 FROM files t
                 JOIN (
                     SELECT path, MAX(version_seq) AS max_seq FROM files
                     WHERE group_id = ?1 AND state = 'trashed' GROUP BY path
                 ) latest ON latest.path = t.path AND latest.max_seq = t.version_seq
                 JOIN files c ON c.group_id = ?1 AND c.path = t.path AND c.state = 'current'
                 WHERE t.group_id = ?1 AND t.state = 'trashed' AND c.deleted = 1
                 ORDER BY c.mtime_unix_nanos DESC",
            )?;
            let rows = stmt.query_map([group_id], trashed_file_from_row)?;
            let rows: Vec<TrashedFile> = rows.collect::<Result<_, _>>()?;
            without_live_history(conn, group_id, rows)
        })
    }

    /// Every file currently in the trash because of one recursive delete
    /// or directory rename, in path order -- the set a folder restore
    /// puts back. Read from the trashed rows themselves, so it does not
    /// depend on the deleting changes still being retained. Like
    /// [`Self::list_trashed`], only a path's latest trashed version counts:
    /// a path the operation deleted that was since restored and deleted
    /// again by something else is not the operation's to put back, and its
    /// older version would overwrite what came after. Pair it with
    /// [`crate::dag_store::recursive_operation`]'s completeness to tell
    /// the user when the operation's parts are not all here and the
    /// restore would be partial.
    pub fn list_trashed_by_recursive_operation(
        &self,
        group_id: &str,
        operation: &RecursiveOperationRef,
    ) -> Result<Vec<TrashedFile>, SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| {
            let mut stmt = conn.prepare_cached(
                "SELECT t.path, t.version_seq, t.size, t.mtime_unix_nanos, t.origin_device_id, \
                        c.mtime_unix_nanos, t.trashed_by_operation_author, \
                        t.trashed_by_operation_id, t.record_kind
                 FROM files t
                 JOIN (
                     SELECT path, MAX(version_seq) AS max_seq FROM files
                     WHERE group_id = ?1 AND state = 'trashed' GROUP BY path
                 ) latest ON latest.path = t.path AND latest.max_seq = t.version_seq
                 JOIN files c ON c.group_id = ?1 AND c.path = t.path AND c.state = 'current'
                 WHERE t.group_id = ?1 AND t.state = 'trashed' AND c.deleted = 1
                   AND t.trashed_by_operation_author = ?2 AND t.trashed_by_operation_id = ?3
                 ORDER BY t.path",
            )?;
            let rows = stmt.query_map(
                rusqlite::params![
                    group_id,
                    operation.author.as_str(),
                    &operation.operation_id.0[..]
                ],
                trashed_file_from_row,
            )?;
            let rows: Vec<TrashedFile> = rows.collect::<Result<_, _>>()?;
            without_live_history(conn, group_id, rows)
        })
    }

    /// Every currently-live (non-deleted) conflicted-copy file for
    /// `group_id` -- the single source of truth both
    /// `FileHistoryQueryService::list_conflicts` and
    /// `LinkStatusReadPort::list_links`'s `conflict_count` must read from,
    /// so the two can never disagree about which paths count (a
    /// conflict-copy row is routinely deleted by the retirement sweep, so
    /// a caller that forgets the `deleted` filter silently counts a
    /// different, larger set than one that remembers it).
    ///
    /// Like `list_trashed`, a targeted query rather than `list_files`
    /// filtered in memory: selects only `path`/`size`/`mtime_unix_nanos`,
    /// never `blocks_json`, so this doesn't pay to deserialize every live
    /// file's full block map just to substring-test its path. The `LIKE`
    /// clause is a cheap SQL pre-filter, not the authoritative check --
    /// it can only ever produce a superset (it doesn't distinguish a
    /// filename's stem from a directory component, or account for the
    /// suffix landing before the extension) -- so every candidate row is
    /// re-validated in Rust against the canonical
    /// [`yadorilink_replica_domain::conflict::is_conflict_copy_path`],
    /// the same predicate `peer_session.rs`'s own conflict-copy dedup
    /// guard uses.
    pub fn list_live_conflict_copies(
        &self,
        group_id: &str,
    ) -> Result<Vec<ConflictCopyFile>, SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| {
            let mut stmt = conn.prepare_cached(
                "SELECT path, size, mtime_unix_nanos, record_kind FROM files \
                 WHERE group_id = ?1 AND state = 'current' AND deleted = 0 \
                 AND path LIKE '%(conflicted copy, %'",
            )?;
            let rows = stmt.query_map([group_id], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, u64>(1)?,
                    r.get::<_, i64>(2)?,
                    r.get::<_, String>(3)?,
                ))
            })?;
            let mut out = Vec::new();
            for row in rows {
                let (path, size, mtime_unix_nanos, record_kind) = row?;
                if yadorilink_replica_domain::conflict::is_conflict_copy_path(&path) {
                    out.push(ConflictCopyFile {
                        path,
                        size,
                        mtime_unix_nanos,
                        record_kind: RecordKind::from_db_str(&record_kind),
                    });
                }
            }
            Ok(out)
        })
    }

    /// Whether any live current row lies strictly below `path` -- the
    /// index's answer to whether `path` is a directory holding synced
    /// content. See [`crate::held_path::has_live_descendant_row`].
    pub fn has_live_descendant_row(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<bool, SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| {
            crate::held_path::has_live_descendant_row(conn, group_id, path)
        })
    }

    /// Whether a live current row strictly below `path` (anywhere in the
    /// group when `path` is empty, the link root) is a conflict copy --
    /// the one per-file status worse than synced that an indexed row
    /// carries, which a directory's aggregate status raises. `LIKE` only
    /// narrows the candidates; each is confirmed by the same
    /// [`yadorilink_replica_domain::conflict::is_conflict_copy_path`] the
    /// per-file status uses.
    pub fn has_live_conflict_copy_descendant(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<bool, SyncSqliteError> {
        let (lower, upper) = if path.is_empty() {
            (String::new(), "\u{10FFFF}".to_string())
        } else {
            (format!("{path}/"), format!("{path}0"))
        };
        self.database.read::<_, SyncSqliteError>(|conn| {
            let mut stmt = conn.prepare_cached(
                "SELECT path FROM files WHERE group_id = ?1 AND path > ?2 AND path < ?3 \
                   AND state = 'current' AND deleted = 0 \
                   AND path LIKE '% (conflicted copy, %'",
            )?;
            let mut rows = stmt.query(rusqlite::params![group_id, lower, upper])?;
            while let Some(row) = rows.next()? {
                let candidate: String = row.get(0)?;
                if yadorilink_replica_domain::conflict::is_conflict_copy_path(&candidate) {
                    return Ok(true);
                }
            }
            Ok(false)
        })
    }

    /// Whether `(group_id, path)` has a genuine current row -- one this
    /// device actually indexed at some point -- as opposed to no row at
    /// all, or only the `version_seq = 0` scaffold
    /// [`ensure_bootstrap_row_for_metadata`] creates for a path it has
    /// never seen. `get_file(...).is_some()` alone cannot make this
    /// distinction: a database written by an earlier receive path can hold
    /// that scaffold for a never-before-seen incoming record (a tombstone
    /// included), so a caller that only checks `is_some()` to decide "is
    /// there real content here to protect" sees the scaffold and wrongly
    /// answers yes. The receive path no longer creates one.
    pub fn has_real_current_row(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<bool, SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| {
            conn.query_row_cached(
                "SELECT 1 FROM files WHERE group_id = ?1 AND path = ?2 AND state = 'current' \
                 AND version_seq > 0 LIMIT 1",
                rusqlite::params![group_id, path],
                |_| Ok(()),
            )
            .optional()
            .map(|row| row.is_some())
            .map_err(SyncSqliteError::from)
        })
    }

    /// Creates a `version_seq = 0` scaffold row
    /// for `path` if (and only if) no `current` row exists for it yet — the
    /// receiving side's bootstrap need: its four metadata setters (`set_record_kind`/`set_symlink_target`/
    /// `set_symlink_out_of_root`/`set_unix_mode`) are `UPDATE`-only and error
    /// if no row exists yet for a path this device has genuinely never seen
    /// before. `version_seq = 0` is a sentinel `upsert_file_in_tx`'s own
    /// `files_supersede_prior_current` trigger recognizes specially: the
    /// *next* real `upsert_file`/`upsert_file_with_origin` call for this
    /// path deletes this scaffold outright and starts real history at
    /// `version_seq = 1`, rather than leaving a spurious empty first
    /// version behind. A no-op if a current row already exists (an update
    /// to a previously-seen path) — the bootstrap is only ever needed for a
    /// path this device has never indexed at all.
    pub fn ensure_bootstrap_row_for_metadata(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<(), SyncSqliteError> {
        // This write, like every sibling
        // per-path metadata setter below it (`set_record_kind`,
        // `set_symlink_target`, `set_symlink_out_of_root`, `set_unix_mode`,
        // `set_held`/`clear_held`) sits directly on `reconcile_one_file`'s
        // "adopt a brand-new path from a peer" hot path, called
        // concurrently (up to `MAX_CONCURRENT_RECONCILES` at a time, times
        // however many `handle_message` tasks are in flight) against the
        // exact same shared-cache-mode connection pool
        // `upsert_file_with_origin`'s doc comment on `retry_on_database_
        // locked`/`new_immediate_write_transaction` describes -- but,
        // unlike that function, this one was never wrapped, so a burst
        // large enough to produce real concurrent writers hit an
        // unretried `SQLITE_LOCKED` here and the whole reconcile attempt
        // was dropped, indistinguishable in effect from the semaphore/
        // head-of-line-blocking stall this change's periodic resync
        // exists to recover from. Found via this change's own burst
        // reproduction (real `database table is locked: files` errors
        // observed under load, not a hypothetical) -- fixed the same way
        // `upsert_file_with_origin` already is, so a resync round's own
        // retried reconciles aren't undermined by this same gap.
        //
        // Stamped with `admitted_at_unix_nanos` like every other `files`
        // insert -- see `upsert_file_in_tx`'s "stamping invariant" section.
        // A scaffold row is short-lived (the next real upsert promotes it in
        // place) but it is a genuine row this device held, and leaving it
        // unstamped would make the path's whole history unreadable for
        // rewind purposes rather than merely imprecise.
        let (case_key, canonical_key) = name_fold_keys(path);
        self.database.write::<_, SyncSqliteError>(|conn| {
            conn.execute_cached("INSERT INTO files (group_id, path, size, mtime_unix_nanos, blocks_json, deleted, version_seq, state, origin_device_id, admitted_at_unix_nanos, case_fold_key, canonical_fold_key)
                 SELECT ?1, ?2, 0, 0, '[]', 0, 0, 'current', NULL, ?3, ?4, ?5
                  WHERE NOT EXISTS (SELECT 1 FROM files WHERE group_id = ?1 AND path = ?2 AND state = 'current')",
                rusqlite::params![group_id, path, now_unix_nanos_checked(), case_key, canonical_key],
            )?;
            Ok(())
        })
    }

    /// Drops the `version_seq = 0` scaffold of `path` and nothing else: a real row, and every
    /// version the path ever had, stay. For the scaffold a metadata step made of a path whose
    /// head then went away, so the path is as it was before the step. Returns whether one was
    /// dropped.
    pub fn retire_bootstrap_scaffold(
        &self,
        group_id: &str,
        path: &str,
        permit: &RootCommitPermit,
    ) -> Result<bool, SyncSqliteError> {
        permit.verify()?;
        self.database.write::<_, SyncSqliteError>(|conn| {
            crate::native_rebootstrap::refuse_materialization_if_frozen(conn, group_id)?;
            Ok(conn.execute_cached(
                "DELETE FROM files WHERE group_id = ?1 AND path = ?2 \
                 AND state = 'current' AND version_seq = 0",
                rusqlite::params![group_id, path],
            )? > 0)
        })
    }

    /// The kind of on-disk entry this record represents. `None`
    /// if no row exists for `group_id`/`path` at all — distinct from `Some
    /// (RecordKind::File)`, which is a real row that just hasn't been
    /// classified as anything else.
    pub fn get_record_kind(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<Option<RecordKind>, SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| {
            let kind: Option<String> = conn
                .query_row_cached(
                    "SELECT record_kind FROM files WHERE group_id = ?1 AND path = ?2 AND \
                     state = 'current'",
                    rusqlite::params![group_id, path],
                    |r| r.get(0),
                )
                .optional()?;
            Ok(kind.as_deref().map(RecordKind::from_db_str))
        })
    }

    /// Fails closed when a live current row of `group_id` stores a block list that is not valid
    /// JSON, naming one such path: one statement inside SQLite, no decoding. For a caller that
    /// decides something from the answer; a status is served by the audit, which also judges
    /// whether a list decodes and adds up, and marks only the folder it finds (so a gate is not
    /// stopped by a record the audit merely reports).
    pub fn verify_live_block_lists(&self, group_id: &str) -> Result<(), SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| {
            let corrupt: Option<String> = conn
                .query_row_cached(
                    "SELECT path FROM files WHERE group_id = ?1 AND state = 'current' \
                     AND deleted = 0 AND NOT json_valid(blocks_json) LIMIT 1",
                    rusqlite::params![group_id],
                    |r| r.get(0),
                )
                .optional()?;
            match corrupt {
                Some(path) => {
                    tracing::warn!(path = %path, "stored block list is corrupt; failing closed");
                    Err(SyncSqliteError::CorruptState(format!(
                        "stored block list for {path} is corrupt"
                    )))
                }
                None => Ok(()),
            }
        })
    }

    /// One bounded step of the audit that re-reads stored block lists: up to `limit` live current
    /// rows after `after_rowid`, in rowid order, each checked as a write checks it. Reads only.
    /// `next_rowid` is where the next step resumes, `None` once the table's end was reached.
    pub fn audit_live_block_lists(
        &self,
        after_rowid: i64,
        limit: usize,
    ) -> Result<BlockListAudit, SyncSqliteError> {
        let limit = i64::try_from(limit).unwrap_or(i64::MAX);
        self.database.read::<_, SyncSqliteError>(|conn| {
            let mut stmt = conn.prepare_cached(
                "SELECT rowid, group_id, path, size, blocks_json FROM files \
                 WHERE rowid > ?1 AND state = 'current' AND deleted = 0 ORDER BY rowid LIMIT ?2",
            )?;
            let mut rows = stmt.query(rusqlite::params![after_rowid, limit])?;
            let (mut damaged, mut last, mut seen) = (Vec::new(), after_rowid, 0_i64);
            while let Some(row) = rows.next()? {
                // Read without trusting the columns' types: a value the database cannot hand back
                // as the type it should be is itself the damage, and must not stop the walk.
                let rowid: i64 = row.get(0)?;
                if stored_block_list_is_damaged(row.get_ref(3)?, row.get_ref(4)?) {
                    let (group_id, path) =
                        (lossy_text(row.get_ref(1)?), lossy_text(row.get_ref(2)?));
                    tracing::warn!(%path, "a stored block list cannot be read back");
                    damaged.push(DamagedRow { rowid, group_id, path });
                }
                last = rowid;
                seen += 1;
            }
            Ok(BlockListAudit { damaged, next_rowid: (seen == limit).then_some(last) })
        })
    }

    /// Whether `damaged` is still a live current row whose block list cannot be read back; false
    /// when it is no longer one (a write replaces a row by inserting a new one). The row is found
    /// by its rowid, not by a name a damaged value might not give back faithfully; a rowid that now
    /// holds a row of another group or path (SQLite reuses the rowid of a deleted row) is not the
    /// row, and the audit records that one under its own name.
    pub fn live_block_list_damaged(&self, damaged: &DamagedRow) -> Result<bool, SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| {
            let mut stmt = conn.prepare_cached(
                "SELECT group_id, path, size, blocks_json FROM files WHERE rowid = ?1 \
                 AND state = 'current' AND deleted = 0",
            )?;
            let mut rows = stmt.query(rusqlite::params![damaged.rowid])?;
            match rows.next()? {
                Some(row) => Ok(lossy_text(row.get_ref(0)?) == damaged.group_id
                    && lossy_text(row.get_ref(1)?) == damaged.path
                    && stored_block_list_is_damaged(row.get_ref(2)?, row.get_ref(3)?)),
                None => Ok(false),
            }
        })
    }

    /// How many live current rows of `group_id` are symlinks, from one statement.
    pub fn count_live_symlinks(&self, group_id: &str) -> Result<u64, SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| {
            let count: i64 = conn.query_row_cached(
                "SELECT COUNT(*) FROM files WHERE group_id = ?1 AND state = 'current' \
                 AND deleted = 0 AND record_kind = 'symlink'",
                rusqlite::params![group_id],
                |r| r.get(0),
            )?;
            Ok(count.max(0) as u64)
        })
    }

    // `retry_on_database_locked`-wrapped
    // for the same reason as `ensure_bootstrap_row_for_metadata` just
    // above -- see its doc comment for the full diagnostic story.
    pub fn set_record_kind(
        &self,
        group_id: &str,
        path: &str,
        kind: RecordKind,
        permit: &RootCommitPermit,
    ) -> Result<(), SyncSqliteError> {
        self.database.write::<_, SyncSqliteError>(|conn| {
            permit.verify()?;
            let affected = conn.execute_cached("UPDATE files SET record_kind = ?1 WHERE group_id = ?2 AND path = ?3 AND state = 'current'",
                rusqlite::params![kind.as_db_str(), group_id, path],
            )?;
            if affected == 0 {
                return Err(SyncSqliteError::NotFound(format!("file {group_id}/{path}")));
            }
            if kind == RecordKind::Directory {
                conn.execute_cached("DELETE FROM activity_events WHERE group_id = ?1 AND path = ?2 AND version_seq = \
                     (SELECT version_seq FROM files WHERE group_id = ?1 AND path = ?2 AND state = 'current')",
                    rusqlite::params![group_id, path],
                )?;
            }
            Ok(())
        })
    }

    /// The raw, unresolved symlink target bytes, exactly as captured — only
    /// meaningful when `get_record_kind` returns `Symlink`; `None`
    /// otherwise (either no row, or a row that isn't a symlink).
    pub fn get_symlink_target(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<Option<Vec<u8>>, SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| {
            let target: Option<Option<Vec<u8>>> = conn
                .query_row_cached(
                    "SELECT symlink_target FROM files WHERE group_id = ?1 AND path = ?2 AND \
                     state = 'current'",
                    rusqlite::params![group_id, path],
                    |r| r.get(0),
                )
                .optional()?;
            Ok(target.flatten())
        })
    }

    // Retry-wrapped, same reason as
    // `ensure_bootstrap_row_for_metadata`.
    pub fn set_symlink_target(
        &self,
        group_id: &str,
        path: &str,
        target: Option<&[u8]>,
    ) -> Result<(), SyncSqliteError> {
        self.database.write::<_, SyncSqliteError>(|conn| {
            let affected = conn.execute_cached("UPDATE files SET symlink_target = ?1 WHERE group_id = ?2 AND path = ?3 AND state = 'current'",
                rusqlite::params![target, group_id, path],
            )?;
            if affected == 0 {
                return Err(SyncSqliteError::NotFound(format!("file {group_id}/{path}")));
            }
            Ok(())
        })
    }

    /// `true` when this symlink's raw target is an absolute
    /// path, or resolves (syntactically — see
    /// `local_change::symlink_target_is_out_of_root`, never by
    /// dereferencing) outside the linked folder's root. Only meaningful
    /// when `get_record_kind` returns `Symlink`; defaults to `false`
    /// otherwise, matching `get_unix_mode`'s default-to-`false` shape for
    /// an unknown/never-set row. Deliberately a distinct column from
    /// `held_reason`/`held_since_unix_nanos` — see the migration comment
    /// in `init` for why this flag doesn't gate materialization the way
    /// held state does.
    pub fn get_symlink_out_of_root(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<bool, SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| {
            let flag: Option<i64> = conn
                .query_row_cached(
                    "SELECT symlink_out_of_root FROM files WHERE group_id = ?1 AND path = ?2 \
                     AND state = 'current'",
                    rusqlite::params![group_id, path],
                    |r| r.get(0),
                )
                .optional()?;
            Ok(flag.unwrap_or(0) != 0)
        })
    }

    /// Whether the row for `path` is executable. `false` for a path with no row and for every row of a
    /// directory or a symlink.
    pub fn get_exec(&self, group_id: &str, path: &str) -> Result<bool, SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| {
            let exec: Option<i64> = conn
                .query_row_cached(
                    "SELECT exec FROM files WHERE group_id = ?1 AND path = ?2 AND \
                     state = 'current'",
                    rusqlite::params![group_id, path],
                    |r| r.get(0),
                )
                .optional()?;
            Ok(exec.unwrap_or(0) != 0)
        })
    }

    // Retry-wrapped, same reason as
    // `ensure_bootstrap_row_for_metadata`.
    pub fn set_exec(
        &self,
        group_id: &str,
        path: &str,
        exec: bool,
        permit: &RootCommitPermit,
    ) -> Result<(), SyncSqliteError> {
        self.database.write::<_, SyncSqliteError>(|conn| {
            permit.verify()?;
            let affected = conn.execute_cached("UPDATE files SET exec = ?1 WHERE group_id = ?2 AND path = ?3 AND state = 'current'",
                rusqlite::params![i64::from(exec), group_id, path],
            )?;
            if affected == 0 {
                return Err(SyncSqliteError::NotFound(format!("file {group_id}/{path}")));
            }
            Ok(())
        })
    }

    /// `upsert_file_with_authoring_in_tx` (the full row -- blocks/size/
    /// mtime/deleted/origin/authoring identity) plus `apply_local_meta_
    /// columns_in_tx` (record_kind/symlink_target/symlink_out_of_root/
    /// unix_mode/xattrs) in ONE transaction, for the peer-projection
    /// "content already matches, but something in the row/metadata/
    /// authoring/origin differs" case -- rather than two separate calls
    /// (`upsert_file_with_origin_and_authoring` + `apply_incoming_wire_
    /// metadata`), each its own `writer_gate` acquisition, even though
    /// nothing about this case needs two commits. `authoring` is the native
    /// head the row shows, if any.
    #[allow(clippy::too_many_arguments)] // one argument per input of the persisted row
    pub fn apply_projected_row_with_authoring_atomic(
        &self,
        group_id: &str,
        record: &FileRecord,
        origin_device_id: &str,
        authoring: Option<&yadorilink_replica_domain::native_plan::NativeRowIdentity>,
        meta: &LocalFileMetaColumns,
        retention: Retention<'_>,
        permit: &RootCommitPermit,
    ) -> Result<(), SyncSqliteError> {
        self.database.write_immediate::<_, SyncSqliteError>(|tx| {
            upsert_file_with_authoring_in_tx(
                tx,
                group_id,
                record,
                origin_device_id,
                authoring,
                retention,
            )?;
            apply_local_meta_columns_in_tx(tx, group_id, &record.path, meta)?;
            require_row_shows_native_head(tx, group_id, &record.path, authoring)?;
            permit.verify()?;
            Ok(())
        })
    }

    /// The native head the current row at `path` shows (see
    /// [`row_authoring_in_tx`]).
    pub fn row_authoring(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<Option<yadorilink_replica_domain::native_plan::NativeRowIdentity>, SyncSqliteError>
    {
        self.database.read::<_, SyncSqliteError>(|conn| row_authoring_in_tx(conn, group_id, path))
    }

    /// The device id that
    /// actually produced this path's *current* content, as already
    /// recorded by every `upsert_file_with_origin` call (the
    /// `origin_device_id` column has existed since file-version-history
    /// support was added, previously write-only from this query's point of
    /// view — used for version-history attribution, never read back
    /// during conflict resolution). `None` for a row with no recorded
    /// origin (an empty string is stored as SQL `NULL`, per
    /// `upsert_file_in_tx`'s existing convention) — callers fall back to
    /// their own best guess (typically `self.local_device_id`/
    /// `self.peer_device_id`) in that case, matching the pre-this-fix
    /// behavior for a record that predates this column being consulted.
    pub fn get_origin_device_id(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<Option<String>, SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| {
            let origin: Option<String> = conn
                .query_row_cached(
                    "SELECT origin_device_id FROM files WHERE group_id = ?1 AND path = ?2 AND \
                     state = 'current'",
                    rusqlite::params![group_id, path],
                    |r| r.get(0),
                )
                .optional()?
                .flatten();
            Ok(origin)
        })
    }

    /// The device that authored the *live* current version of `path`: `None` when the path has no
    /// current row, its current row is a tombstone (nobody holds the path), or the author was not
    /// recorded. One indexed row read, for callers that name who holds a path now.
    pub fn get_live_origin_device_id(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<Option<String>, SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| {
            let origin: Option<String> = conn
                .query_row_cached(
                    "SELECT origin_device_id FROM files WHERE group_id = ?1 AND path = ?2 AND \
                     state = 'current' AND deleted = 0",
                    rusqlite::params![group_id, path],
                    |r| r.get(0),
                )
                .optional()?
                .flatten();
            Ok(origin.filter(|device| !device.is_empty()))
        })
    }

    /// Every live current file at or below the directory `prefix` (`""`
    /// is the link root), in path order: what a directory's eviction or
    /// hydration acts on.
    pub fn list_live_files_under(
        &self,
        group_id: &str,
        prefix: &str,
    ) -> Result<Vec<String>, SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| {
            let mut stmt = conn.prepare_cached(
                "SELECT path FROM files WHERE group_id = ?1 AND state = 'current' AND \
                 deleted = 0 AND record_kind = 'file' AND \
                 (?2 = '' OR substr(path, 1, length(?2) + 1) = ?2 || '/') ORDER BY path",
            )?;
            let rows = stmt.query_map(rusqlite::params![group_id, prefix], |r| r.get(0))?;
            Ok(rows.collect::<Result<_, _>>()?)
        })
    }

    /// Every user-recoverable durability root for `group_id`: the single set
    /// a full-replica handoff must cover so that demoting/unlinking/revoking
    /// the group's last eager replica can never silently lose recoverable
    /// history, not just the current head. A root is `(path, change::
    /// VersionHash)`, one entry per still-restorable `(path, version_seq)`
    /// row, so the same `path` legitimately appears more than once when
    /// several of its versions are each still retained.
    ///
    /// The three categories that actually exist in this schema today all
    /// live in the same `files` table, distinguished only by `state`
    /// ([`VersionState`]) — there is no separate version-history, trash, or
    /// conflict-copy table:
    ///
    /// - **current** (`state = 'current'`): the live head of every file —
    ///   the same set `list_files` returns.
    /// - **retained superseded** (`state = 'superseded'`): prior versions not
    ///   yet swept by [`Self::expire_superseded_and_trashed_versions`],
    ///   restorable via `versions`/`restore --version`.
    /// - **trash-restorable** (`state = 'trashed'`): deleted-but-in-retention
    ///   content, restorable via `trash restore`, not yet swept by the same
    ///   expiry.
    ///
    /// Conflict copies are NOT a fourth category — there is no
    /// `RecordKind::ConflictCopy` or marker column (see
    /// `conflict::is_conflict_copy_of`): a conflict copy is written as an
    /// ordinary `state = 'current'` row under a synthetic
    /// `"name (conflicted copy, ...)"` path, so it is already covered by the
    /// `current` scan above with no extra query.
    ///
    /// A non-deleted row of any of the three states carries real, restorable
    /// block content — `live_block_hashes_with_extra_roots`'s own doc
    /// comment establishes the identical fact for the block-store GC live
    /// set. Directories and symlinks carry no blocks and are excluded
    /// (`record_kind != 'file'`, itself a per-row column so this can filter
    /// in SQL directly rather than needing a second per-path lookup); a
    /// `deleted = 1` row is also excluded — its `blocks_json` is always `[]`
    /// by construction.
    ///
    /// Also returns a stable digest over the root set (roots sorted by path,
    /// each root's block sequence kept ordered — see
    /// [`durability_roots_digest`]) so a caller can capture it when
    /// readiness is first confirmed and re-check it immediately before
    /// committing a role loss, detecting the set changing out from under
    /// that confirmation. For the daemon-driven commit paths that must be
    /// atomic against a concurrent index write, use
    /// [`Self::recheck_digest_then_set_materialization_policy`] /
    /// [`Self::recheck_digest_then_remove_link`] instead of comparing a
    /// separately-read digest, which re-enumerate and commit in one
    /// transaction so no write can interleave.
    ///
    /// Deliberately NOT used by per-file eviction custody
    /// ([`Self::list_versions`]/the daemon's `confirm_version_present_via_
    /// peer`), which stays a `VersionPresent` check for the ONE evicted
    /// exact version — routing eviction through the whole-group root set
    /// would ask an on-demand device to prove custody of history it was
    /// never asked to hold in the first place. GC unification (a future
    /// block-store sweep computing its live set from roots ∪
    /// hydration-in-progress (`MaterializationState::Hydrating`) ∪
    /// dirty/in-flight (`Self::list_dirty_paths`) ∪ a grace window) is out
    /// of scope here; this function only answers the handoff/durability
    /// question.
    pub fn enumerate_group_durability_roots(
        &self,
        group_id: &str,
    ) -> Result<DurabilityRoots, SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| {
            enumerate_group_durability_roots_on_conn(conn, group_id)
        })
    }

    /// `group_id`'s current `file_root_set_generation` counter — `0` if the
    /// group has never had a `files` row written for it.
    ///
    /// Maintained by triggers on `files` (see that table's own comment in
    /// `yadorilink_sqlite_runtime::schema`), so it moves for every insert,
    /// update and delete, in the same transaction as the write. Two reads
    /// returning the same value mean no `files` row for the group changed in
    /// between; they do not mean the *set* is unchanged in any deeper sense,
    /// since a write that nets out still moves it. That asymmetry is the
    /// right one for a cache key: it can only ever cause an unnecessary
    /// recomputation, never a stale hit.
    pub fn root_set_generation(&self, group_id: &str) -> Result<u64, SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| root_set_generation_on_conn(conn, group_id))
    }

    /// `group_id`'s durability-root set reduced to [`RootSetSummary`] — two
    /// digests, two counts, and the generation they were taken at — in one
    /// scan, without reading a single block.
    ///
    /// The generation is read FIRST, before the rows. A concurrent write
    /// landing during the scan then produces a summary stamped with a
    /// generation older than the state it describes, so the next read sees a
    /// moved generation and recomputes. Reading it afterwards would stamp a
    /// possibly-torn summary as current, which is the one ordering that can
    /// cache a digest the table does not support.
    ///
    /// `block_in_store` answers whether this device's block store holds a block (raw hash): a
    /// materialized row counts as backed by the store only where the group's provenance names every
    /// block AND the store still has it (provenance outlives a block that was swept or lost). A
    /// caller that does not use `file_only_current_count` passes `&|_| true`.
    pub fn group_root_set_summary(
        &self,
        group_id: &str,
        block_in_store: &dyn Fn(&[u8]) -> bool,
    ) -> Result<RootSetSummary, SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| {
            let generation = root_set_generation_on_conn(conn, group_id)?;
            group_root_set_summary_on_conn(conn, group_id, generation, block_in_store)
        })
    }

    /// The retention-expiry sweep — deletes the index row (never the
    /// blocks; leaves actual block reclamation to a future
    /// block-store GC) for any `superseded`/`trashed` version of
    /// `group_id` that exceeds *both* the built-in version-count bound
    /// ([`RETENTION_MAX_VERSIONS`], by recency rank among that path's own
    /// superseded/trashed rows) and the built-in age bound
    /// ([`RETENTION_MAX_AGE_DAYS`], by wall-clock age from `now_unix_nanos`).
    /// This is the union-retain / intersection-expire rule: a version is kept
    /// while it is within *either* bound, and expired only once it is beyond
    /// *both*, so recent history and recently-changed history are both kept.
    /// Retention is a fixed built-in policy applied to every link; it is not
    /// configurable. The `current` row for any path is never a candidate —
    /// the `WHERE state IN ('superseded', 'trashed')` below structurally
    /// excludes it, matching the rule that the current live version is never
    /// subject to retention expiry. Returns the number of rows deleted.
    ///
    /// The `(path, version_seq)` set an outstanding handoff lease still
    /// protects (see `HandoffLease`'s doc comment) is read inside the same
    /// transaction as the deletes, so a lease granted while the sweep runs
    /// either is seen or makes the sweep's write fail on its stale snapshot;
    /// it can never lose its pinned rows. A pinned row is retained past both
    /// bounds until the lease is confirmed/released/expires.
    pub fn expire_superseded_and_trashed_versions(
        &self,
        group_id: &str,
        now_unix_nanos: i64,
    ) -> Result<usize, SyncSqliteError> {
        // Opens its own DEFERRED transaction (rather than going through
        // `write_immediate`, which is always IMMEDIATE) on purpose: this
        // sweep is read-heavy (the whole candidate SELECT below) before its
        // handful of DELETEs, and taking the write lock only once a
        // candidate is actually found to delete -- SQLite's default
        // deferred-lock-upgrade behavior -- is the original, deliberate
        // choice here, preserved unchanged by this conversion.
        self.database.write::<_, SyncSqliteError>(|conn| {
            let tx = conn.transaction()?;
            let pinned = crate::handoff_lease::leased_version_keys_all_groups(
                &tx,
                now_unix_nanos / 1_000_000_000,
            )?
            .remove(group_id)
            .unwrap_or_default();
            let expired = expire_superseded_and_trashed_versions_in_tx(
                &tx,
                group_id,
                now_unix_nanos,
                &pinned,
            )?;
            tx.commit()?;
            Ok(expired)
        })
    }
}

/// The body of [`FileIndexRepository::expire_superseded_and_trashed_versions`],
/// in the caller's transaction: the same rule, the same rows deleted, the
/// number deleted returned.
pub(crate) fn expire_superseded_and_trashed_versions_in_tx(
    tx: &Connection,
    group_id: &str,
    now_unix_nanos: i64,
    pinned: &HashSet<(String, i64)>,
) -> Result<usize, SyncSqliteError> {
    const NANOS_PER_DAY: i64 = 86_400 * 1_000_000_000;
    let age_cutoff_unix_nanos =
        now_unix_nanos.saturating_sub(RETENTION_MAX_AGE_DAYS.saturating_mul(NANOS_PER_DAY));
    let candidates: Vec<(String, i64)> = {
        // `rnk = 1` is the most recently superseded/trashed row for a
        // given path; the newest `RETENTION_MAX_VERSIONS` rows survive on
        // the count axis alone. A row is deleted only when it is beyond
        // both the count bound and the age bound. Age is measured from
        // the instant the version stopped being the path's latest, which
        // is when its successor was admitted (`next_admitted`, the next
        // `version_seq` row's `admitted_at_unix_nanos`) -- so a version
        // that stayed current for a long time is not expired the moment
        // it is replaced -- and never from the file's own mtime, which can
        // be arbitrarily old. The anchor is never earlier than the
        // version's own admission, so this can only lengthen retention
        // relative to aging from admission. With no successor stamp the
        // version's own admission is used. A NULL own stamp (admission
        // time unknown) is bounded by the count axis alone, so such rows
        // cannot pile up.
        let mut stmt = tx.prepare_cached(
            "SELECT path, version_seq FROM (
            SELECT path, version_seq, admitted_at_unix_nanos, next_admitted,
                   ROW_NUMBER() OVER (PARTITION BY path ORDER BY version_seq DESC) AS rnk
            FROM (
                SELECT path, version_seq, state, admitted_at_unix_nanos,
                       LEAD(admitted_at_unix_nanos) OVER (
                           PARTITION BY path ORDER BY version_seq
                       ) AS next_admitted
                FROM files WHERE group_id = ?1
            ) WHERE state IN ('superseded', 'trashed')
         )
         WHERE rnk > ?2 AND (
            admitted_at_unix_nanos IS NULL
            OR MAX(admitted_at_unix_nanos, COALESCE(next_admitted, admitted_at_unix_nanos)) < ?3
         )",
        )?;
        let rows = stmt.query_map(
            rusqlite::params![group_id, RETENTION_MAX_VERSIONS, age_cutoff_unix_nanos],
            |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)),
        )?;
        rows.collect::<Result<Vec<_>, _>>()?
            .into_iter()
            // A leased row is retained past both bounds until the lease is
            // confirmed/released/expires -- see the `pinned` note on
            // `FileIndexRepository::expire_superseded_and_trashed_versions`
            // for why the time check (not merely `state`) is what actually
            // matters.
            .filter(|key| !pinned.contains(key))
            .collect()
    };
    drop_versions_in_tx(
        tx,
        group_id,
        &candidates,
        crate::history_freed::FreedReason::Expired,
        now_unix_nanos,
    )?;
    crate::history_freed::prune(tx, group_id, now_unix_nanos)?;
    Ok(candidates.len())
}

/// Drops the kept versions `keys` of `group_id` from the index, recording each path's dropped
/// runs in `history_freed` first, in this transaction, so a version the index no longer holds is
/// never without its record. The bytes are not touched: the GC frees them once no row names them.
pub(crate) fn drop_versions_in_tx(
    tx: &Connection,
    group_id: &str,
    keys: &[(String, i64)],
    reason: crate::history_freed::FreedReason,
    now_unix_nanos: i64,
) -> Result<(), SyncSqliteError> {
    let mut dropped_by_path: HashMap<&str, HashSet<i64>> = HashMap::new();
    for (path, version_seq) in keys {
        dropped_by_path.entry(path.as_str()).or_default().insert(*version_seq);
    }
    for (path, dropped) in &dropped_by_path {
        let rows: Vec<crate::history_freed::Member> = {
            let mut stmt = tx.prepare_cached(
                "SELECT version_seq, admitted_at_unix_nanos FROM files \
                 WHERE group_id = ?1 AND path = ?2",
            )?;
            let rows = stmt.query_map(rusqlite::params![group_id, path], |r| {
                Ok(crate::history_freed::Member { seq: r.get(0)?, admitted: r.get(1)? })
            })?;
            rows.collect::<Result<Vec<_>, _>>()?
        };
        crate::history_freed::record(tx, group_id, path, &rows, dropped, reason, now_unix_nanos)?;
    }
    for (path, version_seq) in keys {
        tx.execute_cached(
            "DELETE FROM files WHERE group_id = ?1 AND path = ?2 AND version_seq = ?3",
            rusqlite::params![group_id, path, version_seq],
        )?;
    }
    Ok(())
}

/// The most ops one part of a recursive operation carries. Each part is
/// one change, delivered whole, so this keeps a part small; the byte bound
/// below applies too.
pub const RECURSIVE_PART_OP_LIMIT: usize = 256;

/// The most encoded op bytes one part of a recursive operation carries:
/// half of [`MAX_CHANGE_OP_BYTES`].
pub const RECURSIVE_PART_OP_BYTES: usize = MAX_CHANGE_OP_BYTES / 2;

/// Cuts `mutations` into the index ranges of a recursive operation's
/// parts, in order: each at most [`RECURSIVE_PART_OP_LIMIT`] ops and
/// [`RECURSIVE_PART_OP_BYTES`] encoded bytes (a single op larger than that
/// still gets a part of its own).
fn recursive_operation_parts(mutations: &[PreparedLocalMutation]) -> Vec<std::ops::Range<usize>> {
    let mut parts = Vec::new();
    let mut start = 0;
    let mut ops = 0;
    let mut bytes = 0;
    for (index, mutation) in mutations.iter().enumerate() {
        let len = encoded_op_len(mutation.op());
        if index > start
            && (ops >= RECURSIVE_PART_OP_LIMIT || bytes + len > RECURSIVE_PART_OP_BYTES)
        {
            parts.push(start..index);
            start = index;
            ops = 0;
            bytes = 0;
        }
        ops += 1;
        bytes += len;
    }
    parts.push(start..mutations.len());
    parts
}

/// Publishes the proof of a present object local capture observed at `path`, then tries to close
/// the path's obligation against it. `stamp_hydrated` is false for a row written already
/// `Present`.
fn adopt_and_settle_local_presence_in_tx(
    tx: &rusqlite::Transaction,
    group_id: &str,
    path: &str,
    record_kind: RecordKind,
    version_hash: &yadorilink_replica_domain::ids::VersionHash,
    filesystem_identity: &FileIdentity,
    stamp_hydrated: bool,
) -> Result<(), SyncSqliteError> {
    adopt_local_capture_actual_state(
        tx,
        group_id,
        path,
        record_kind,
        version_hash,
        filesystem_identity,
    )?;
    if stamp_hydrated {
        stamp_hydrated_after_local_emission_in_tx(tx, group_id, path)?;
    }
    settle_obligation_against_local_presence_in_tx(tx, group_id, path)
}

/// The index half of one prepared local mutation, in the transaction that
/// just emitted a delta for it: the row, its metadata, the local
/// capture provenance, and what `evidence` proves about the disk (or the
/// retirement of any earlier proof when it proves nothing).
fn apply_local_mutation_in_tx(
    tx: &rusqlite::Transaction,
    group_id: &str,
    mutation: &PreparedLocalMutation,
    evidence: Option<&LocalCaptureActualStateEvidence>,
    origin_device_id: &str,
    native: Option<&yadorilink_replica_domain::native_plan::NativeRowIdentity>,
) -> Result<(), SyncSqliteError> {
    crate::local_capture_provenance::record_native_local_capture_in_tx(
        tx,
        group_id,
        &mutation.record().path,
        native,
    )?;
    if let PreparedLocalMutation::Upsert { version, .. } = mutation {
        dag_store::put_file_version(tx, group_id, version)?;
    }
    apply_local_mutation_stored_in_tx(tx, group_id, mutation, evidence, origin_device_id, native)
}

/// [`apply_local_mutation_in_tx`] for a mutation whose content version and capture record the
/// caller has already written (a bulk group writes both for all its mutations together).
fn apply_local_mutation_stored_in_tx(
    tx: &rusqlite::Transaction,
    group_id: &str,
    mutation: &PreparedLocalMutation,
    evidence: Option<&LocalCaptureActualStateEvidence>,
    origin_device_id: &str,
    native: Option<&yadorilink_replica_domain::native_plan::NativeRowIdentity>,
) -> Result<(), SyncSqliteError> {
    match mutation {
        PreparedLocalMutation::Upsert { record, version, meta, .. } => {
            // The row shows the native head the edit put.
            upsert_file_with_authoring_in_tx(
                tx,
                group_id,
                record,
                origin_device_id,
                native,
                Retention::OwnEdit,
            )?;
            if let Some(meta) = meta {
                apply_local_meta_columns_in_tx(tx, group_id, &record.path, meta)?;
            }
            require_row_shows_native_head(tx, group_id, &record.path, native)?;
            // THE production hot path for an ordinary live local edit --
            // `process_event` defers every non-symlink create/modify into a
            // pending batch flushed through here, so
            // `upsert_file_emitting_change` alone (also stamped) is not the
            // whole story. Same local-emission precondition as that
            // sibling: `record`'s bytes were this device's own disk content
            // when the batch was prepared.
            match (meta, evidence) {
                (
                    Some(meta),
                    Some(LocalCaptureActualStateEvidence::Present { filesystem_identity }),
                ) if !record.deleted => {
                    adopt_and_settle_local_presence_in_tx(
                        tx,
                        group_id,
                        &record.path,
                        meta.record_kind,
                        &version.version_hash,
                        filesystem_identity,
                        true,
                    )?;
                }
                // The batch prepared this mutation but could not vouch for
                // the bytes it leaves on disk. The row it just superseded
                // may have been `Present` with a proof naming its version;
                // neither may carry over onto this one.
                _ => retire_unproven_actual_state_in_tx(tx, group_id, &record.path)?,
            }
        }
        PreparedLocalMutation::Delete { record, .. } => {
            upsert_file_in_tx(tx, group_id, record, origin_device_id, Retention::OwnEdit)?;
            if matches!(evidence, Some(LocalCaptureActualStateEvidence::Absent)) {
                adopt_local_capture_absent_state(tx, group_id, &record.path)?;
                // The resolved close, not the absence one: a delete leaves
                // any head its writer did not see, and the path must then
                // hold that head, so the obligation closes only when the
                // resolved desired state is the absence just proven.
                settle_obligation_against_local_presence_in_tx(tx, group_id, &record.path)?;
            } else {
                // Same reasoning as the `Upsert` arm's, and the one that
                // matters most here: a tombstone whose absence nobody
                // revalidated must not leave the path's last present proof
                // readable as current.
                retire_unproven_actual_state_in_tx(tx, group_id, &record.path)?;
            }
        }
    }
    Ok(())
}

/// The transaction body of [`FileIndexRepository::commit_recursive_operation`], for a caller that
/// has its own checks and writes in the same transaction. `check_fresh` is false only for a
/// writer whose witnesses name the version the user SAW rather than the row as it stands (the
/// provider write path), where "the row moved on" is the point, not an error.
#[allow(clippy::too_many_arguments)]
pub fn commit_recursive_operation_in_tx(
    tx: &rusqlite::Transaction,
    group_id: &str,
    kind: &RecursiveOperationKind,
    mutations: &[PreparedLocalMutation],
    evidence: &[Option<LocalCaptureActualStateEvidence>],
    origin_device_id: &str,
    author: &crate::local_author::LocalAuthor<'_>,
    check_fresh: bool,
) -> Result<(), SyncSqliteError> {
    for mutation in mutations {
        crate::held_path::refuse_local_authoring_if_held(tx, group_id, &mutation.record().path)?;
    }
    // A directory rename keeps its provider items' ids, in this transaction and
    // before the delete/put rows are written (their triggers then find
    // nothing left at the old path to retire).
    if let RecursiveOperationKind::RenameTree { from, to } = &kind {
        crate::provider::rename_tree_in_tx(tx, group_id, from.as_str(), to.as_str())?;
    }
    let evidence: Vec<Option<&LocalCaptureActualStateEvidence>> =
        (0..mutations.len()).map(|index| evidence.get(index).and_then(|e| e.as_ref())).collect();
    if check_fresh {
        for mutation in mutations {
            crate::native_capture::require_fresh_native_capture(
                tx,
                group_id,
                &mutation.record().path,
                mutation.native_witness(),
            )?;
        }
    }
    let parts = recursive_operation_parts(mutations);
    // The content versions first (see `commit_local_mutation_in_tx`).
    for mutation in mutations {
        if let PreparedLocalMutation::Upsert { version, .. } = mutation {
            dag_store::put_file_version(tx, group_id, version)?;
        }
    }
    // One native delta per part.
    let mut authored = crate::native_authoring::AuthoredPuts::default();
    let operation_id = RecursiveOperationId(rand::random());
    let group = yadorilink_replica_domain::ids::FolderGroupId(group_id.to_owned());
    // The parts that sign a delta: a part whose deletes all find nothing
    // left to remove authors none, and the operation's count must not
    // wait for it.
    let part_ops = |range: &std::ops::Range<usize>| {
        mutations[range.clone()].iter().map(|m| m.op().clone()).collect::<Vec<Op>>()
    };
    let part_witnesses = |range: &std::ops::Range<usize>| {
        mutations[range.clone()].iter().map(|m| m.native_witness()).collect::<Vec<_>>()
    };
    // Every delta of a part's chain is a part of the operation, so the
    // removal provenance of each is recorded and the operation is
    // complete only once all of them are admitted.
    let mut authoring_parts = Vec::new();
    let mut part_count = 0u32;
    for range in &parts {
        let deltas = crate::native_authoring::recursive_part_delta_count(
            tx,
            &group,
            &author.author,
            &part_ops(range),
            &part_witnesses(range),
        )?;
        if deltas > 0 {
            authoring_parts.push((range.clone(), part_count));
            part_count += deltas;
        }
    }
    for (range, first_index) in &authoring_parts {
        authored.extend(crate::native_authoring::author_recursive_part_tagged(
            tx,
            &group,
            author,
            &part_ops(range),
            &part_witnesses(range),
            Some(yadorilink_replica_domain::signed_delta::RecursivePart {
                operation_id,
                part_index: *first_index,
                part_count,
            }),
        )?);
    }
    for range in &parts {
        for (offset, mutation) in mutations[range.clone()].iter().enumerate() {
            let native_put = match mutation.op() {
                Op::Put { path, .. } => authored.put_at(path),
                _ => None,
            };
            apply_local_mutation_in_tx(
                tx,
                group_id,
                mutation,
                evidence[range.start + offset],
                origin_device_id,
                native_put,
            )?;
        }
    }
    Ok(())
}

/// Commits one local mutation as a native delta authored by `author`, inside
/// `tx`: what the row the mutation acts on showed when it was captured (for a
/// write through a conflict copy, the copy's row, at the source) is what the
/// delta supersedes, and the row is written showing the head it put in the same
/// transaction. A row that no longer shows what was captured refuses the
/// mutation with [`SyncSqliteError::LocalWriteCaptureStale`].
pub fn commit_local_mutation_in_tx(
    tx: &rusqlite::Transaction,
    group_id: &str,
    mutation: &PreparedLocalMutation,
    evidence: Option<&LocalCaptureActualStateEvidence>,
    origin_device_id: &str,
    author: &crate::local_author::LocalAuthor<'_>,
) -> Result<(), SyncSqliteError> {
    commit_local_mutation_group_in_tx(
        tx,
        group_id,
        std::slice::from_ref(mutation),
        &[evidence],
        origin_device_id,
        author,
    )
}

/// Commits `mutations` -- which must touch pairwise unrelated paths (see
/// [`crate::native_authoring::bulk_groups`]) -- as ONE multi-op native delta
/// authored by `author`, inside `tx`. Every mutation keeps its own semantics:
/// its capture-freshness check, the heads its witness shows are the ones it
/// supersedes, its write-through resolution, and its own row, provenance and
/// evidence writes reading the head the delta put at its path. The mutations
/// share the delta's single display rank, one above everything any of them
/// observed. One mutation is committed exactly as it always was: one delta.
/// A stale or unauthorable mutation refuses the whole group.
pub fn commit_local_mutation_group_in_tx(
    tx: &rusqlite::Transaction,
    group_id: &str,
    mutations: &[PreparedLocalMutation],
    evidence: &[Option<&LocalCaptureActualStateEvidence>],
    origin_device_id: &str,
    author: &crate::local_author::LocalAuthor<'_>,
) -> Result<(), SyncSqliteError> {
    commit_local_mutation_group_checked_in_tx(
        tx,
        group_id,
        mutations,
        evidence,
        origin_device_id,
        author,
        true,
    )
}

/// [`commit_local_mutation_group_in_tx`] with the freshness check optional: `check_fresh` is
/// false only for a writer whose witnesses name the version the user SAW (the provider write
/// path), where the row having moved on is the point, not an error.
#[allow(clippy::too_many_arguments)]
pub fn commit_local_mutation_group_checked_in_tx(
    tx: &rusqlite::Transaction,
    group_id: &str,
    mutations: &[PreparedLocalMutation],
    evidence: &[Option<&LocalCaptureActualStateEvidence>],
    origin_device_id: &str,
    author: &crate::local_author::LocalAuthor<'_>,
    check_fresh: bool,
) -> Result<(), SyncSqliteError> {
    for mutation in mutations {
        let row_path = mutation.record().path.as_str();
        if check_fresh {
            crate::native_capture::require_fresh_native_capture(
                tx,
                group_id,
                row_path,
                mutation.native_witness(),
            )?;
        }
    }

    // The paths no row, hold, head or placement names yet, read before authoring puts their
    // first head: their rows are written finished, in one insert, and what they need afterwards
    // comes from the authoring's own writes.
    let NewPaths { fresh: new_paths, open_namespace } =
        brand_new_put_paths(tx, group_id, mutations, evidence)?;

    // The content versions first: storing a version that is new re-arms the
    // paths whose heads name it as remote news, which would undo the local
    // origin the authoring below gives its own paths.
    let versions: Vec<&FileVersion> = mutations
        .iter()
        .filter_map(|mutation| match mutation {
            PreparedLocalMutation::Upsert { version, .. } => Some(version),
            PreparedLocalMutation::Delete { .. } => None,
        })
        .collect();
    dag_store::put_file_versions_batch(tx, group_id, &versions)?;

    // Native observes the ops under the same author; it is inside the same
    // transaction as the rows, so its failure fails the whole commit.
    let items: Vec<crate::native_authoring::BulkOp<'_>> = mutations
        .iter()
        .map(|mutation| crate::native_authoring::BulkOp {
            op: mutation.op(),
            witness: mutation.native_witness(),
        })
        .collect();
    let authored = crate::native_authoring::author_bulk_group(
        tx,
        &yadorilink_replica_domain::ids::FolderGroupId(group_id.to_owned()),
        author,
        &items,
    )?;

    let natives: Vec<_> = mutations
        .iter()
        .map(|mutation| match mutation.op() {
            Op::Put { path, .. } => authored.put_at(path),
            _ => None,
        })
        .collect();
    let captures: Vec<_> = mutations
        .iter()
        .zip(&natives)
        .map(|(mutation, native)| (mutation.record().path.as_str(), *native))
        .collect();
    crate::local_capture_provenance::record_native_local_captures_in_tx(tx, group_id, &captures)?;

    // The rows of the new paths, finished, before any per-path step reads them. Their paths are
    // unrelated to every other path of the group, so no other mutation reads or writes them.
    let mut new_rows = Vec::new();
    let mut finished = vec![false; mutations.len()];
    for (index, mutation) in mutations.iter().enumerate() {
        let PreparedLocalMutation::Upsert { record, meta: Some(meta), .. } = mutation else {
            continue;
        };
        if let (true, Some(identity)) = (new_paths.contains(&record.path), natives[index]) {
            new_rows.push(crate::new_path_rows::NewPathRow { record, meta, identity });
            finished[index] = true;
        }
    }
    crate::new_path_rows::insert_hydrated_rows(tx, group_id, origin_device_id, &new_rows)?;

    // The proofs of the new paths whose heads and obligation the authoring left known: published
    // and settled in batches from what it returned.
    let mut settled = vec![false; mutations.len()];
    if crate::new_path_rows::settlement_enabled() {
        let mut proofs = Vec::new();
        for (index, mutation) in mutations.iter().enumerate() {
            let (
                true,
                PreparedLocalMutation::Upsert { record, version, .. },
                Some(LocalCaptureActualStateEvidence::Present { filesystem_identity }),
                Some(identity),
            ) = (finished[index], mutation, evidence.get(index).copied().flatten(), natives[index])
            else {
                continue;
            };
            let path = SyncPath(record.path.clone());
            if !open_namespace.contains(&record.path) {
                continue;
            }
            if let Some(proof) = crate::new_path_settlement::NewPathProof::new(
                &record.path,
                version,
                filesystem_identity,
                identity,
                authored.installed_heads_at(&path),
                authored.armed_obligation_at(&record.path),
            ) {
                proofs.push(proof);
                settled[index] = true;
            }
        }
        crate::new_path_settlement::publish_and_settle(tx, group_id, &proofs, now_unix_nanos())?;
    }

    for (index, mutation) in mutations.iter().enumerate() {
        let native_put = natives[index];
        let evidence = evidence.get(index).copied().flatten();
        match (finished[index], mutation, evidence) {
            // Proven and settled with the rest of its chunk.
            _ if settled[index] => {}
            // The row is written, shows its head, and is `Present`; what is left is the proof
            // of the observed state and the obligation it settles.
            (
                true,
                PreparedLocalMutation::Upsert { record, version, meta: Some(meta), .. },
                Some(LocalCaptureActualStateEvidence::Present { filesystem_identity }),
            ) => adopt_and_settle_local_presence_in_tx(
                tx,
                group_id,
                &record.path,
                meta.record_kind,
                &version.version_hash,
                filesystem_identity,
                false,
            )?,
            _ => apply_local_mutation_stored_in_tx(
                tx,
                group_id,
                mutation,
                evidence,
                origin_device_id,
                native_put,
            )?,
        }
    }
    Ok(())
}

/// The record paths of `mutations` whose row is a brand-new regular file put with `Present`
/// evidence: an `Upsert` of its own path (no write-through, no conflict copy, no move) that
/// carries its metadata columns, whose capture saw nothing at the path, which no other mutation
/// of the group touches, and that no row, hold, head, placement, binding or kept copy names.
fn brand_new_put_paths(
    tx: &rusqlite::Transaction,
    group_id: &str,
    mutations: &[PreparedLocalMutation],
    evidence: &[Option<&LocalCaptureActualStateEvidence>],
) -> Result<NewPaths, SyncSqliteError> {
    if !crate::new_path_rows::enabled() {
        return Ok(NewPaths::default());
    }
    let mut touched: HashMap<&str, usize> = HashMap::new();
    for mutation in mutations {
        let mut own: Vec<&str> = vec![mutation.record().path.as_str()];
        match mutation.op() {
            Op::Put { path, .. } | Op::Delete { path } => own.push(path.as_str()),
            Op::Move { from, to, .. } => {
                own.push(from.as_str());
                own.push(to.as_str());
            }
        }
        if let Some(witness) = mutation.native_witness() {
            own.push(witness.path.as_str());
        }
        own.sort_unstable();
        own.dedup();
        for path in own {
            *touched.entry(path).or_default() += 1;
        }
    }
    let candidates: Vec<&str> = mutations
        .iter()
        .enumerate()
        .filter(|(index, mutation)| {
            let PreparedLocalMutation::Upsert { record, meta: Some(meta), native_witness, .. } =
                mutation
            else {
                return false;
            };
            let Op::Put { path, .. } = mutation.op() else { return false };
            !record.deleted
                && path.as_str() == record.path
                && meta.record_kind == RecordKind::File
                && matches!(
                    evidence.get(*index).copied().flatten(),
                    Some(LocalCaptureActualStateEvidence::Present { .. })
                )
                && touched.get(record.path.as_str()) == Some(&1)
                && native_witness.as_ref().is_none_or(|witness| {
                    witness.shown_class.is_empty()
                        && witness.shown_version.is_none()
                        && witness.path.as_str() == record.path
                })
        })
        .map(|(_, mutation)| mutation.record().path.as_str())
        .collect();
    let fresh = crate::new_path_rows::brand_new_paths(tx, group_id, &candidates)?;
    let fresh_paths: Vec<&str> =
        candidates.iter().copied().filter(|p| fresh.contains(*p)).collect();
    let open_namespace = if crate::new_path_rows::settlement_enabled() {
        crate::new_path_settlement::open_namespace_paths(tx, group_id, &fresh_paths)?
    } else {
        HashSet::new()
    };
    Ok(NewPaths { fresh, open_namespace })
}

/// What [`brand_new_put_paths`] found: the new paths, and those of them with no head at an
/// ancestor or below.
#[derive(Default)]
struct NewPaths {
    fresh: HashSet<String>,
    open_namespace: HashSet<String>,
}

/// The one-mutation-one-delta commit bulk capture replaced, kept as the
/// reference the differential tests compare the grouped commit against.
#[cfg(test)]
pub(crate) fn commit_local_mutation_reference_in_tx(
    tx: &rusqlite::Transaction,
    group_id: &str,
    mutation: &PreparedLocalMutation,
    evidence: Option<&LocalCaptureActualStateEvidence>,
    origin_device_id: &str,
    author: &crate::local_author::LocalAuthor<'_>,
) -> Result<(), SyncSqliteError> {
    let row_path = mutation.record().path.as_str();
    crate::native_capture::require_fresh_native_capture(
        tx,
        group_id,
        row_path,
        mutation.native_witness(),
    )?;

    // The content version first: storing a version that is new re-arms the
    // paths whose heads name it as remote news, which would undo the local
    // origin the authoring below gives its own paths.
    if let PreparedLocalMutation::Upsert { version, .. } = mutation {
        dag_store::put_file_version(tx, group_id, version)?;
    }

    // Native observes the op under the same author; it is inside the same
    // transaction as the row, so its failure fails the whole commit.
    let authored = crate::native_authoring::author_op_witnessed(
        tx,
        &yadorilink_replica_domain::ids::FolderGroupId(group_id.to_owned()),
        author,
        mutation.op(),
        mutation.native_witness(),
    )?;

    let native_put = match mutation.op() {
        Op::Put { path, .. } => authored.put_at(path),
        _ => None,
    };
    apply_local_mutation_in_tx(tx, group_id, mutation, evidence, origin_device_id, native_put)?;

    Ok(())
}

/// Drops the trashed paths the history holds live again. The index keeps a
/// path's tombstone until the projection places what replaced it, and a
/// restore the projection places (beside a directory, say) may never write
/// a live row at the path at all; the path is not in the trash either way,
/// and restoring it again would only author another change.
fn without_live_history(
    conn: &Connection,
    group_id: &str,
    rows: Vec<TrashedFile>,
) -> Result<Vec<TrashedFile>, SyncSqliteError> {
    let mut kept = Vec::with_capacity(rows.len());
    // The group's history is its native state.
    let group = yadorilink_replica_domain::ids::FolderGroupId(group_id.to_owned());
    for row in rows {
        let live =
            !crate::native_store::native_heads_at(conn, &group, &SyncPath(row.path.clone()))?
                .is_empty();
        if !live {
            kept.push(row);
        }
    }
    Ok(kept)
}

/// One `TrashedFile` from a row shaped like `list_trashed`'s select list.
fn trashed_file_from_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<TrashedFile> {
    let author: Option<String> = r.get(6)?;
    let operation_id: Option<Vec<u8>> = r.get(7)?;
    let deleted_by_operation = match (author, operation_id) {
        (Some(author), Some(id)) => {
            let id: [u8; 16] = id.try_into().map_err(|_| {
                rusqlite::Error::FromSqlConversionFailure(
                    7,
                    rusqlite::types::Type::Blob,
                    "trashed_by_operation_id is not 16 bytes".into(),
                )
            })?;
            Some(RecursiveOperationRef {
                author: DeviceId(author),
                operation_id: RecursiveOperationId(id),
            })
        }
        _ => None,
    };
    Ok(TrashedFile {
        path: r.get(0)?,
        version_seq: r.get(1)?,
        last_known_size: r.get::<_, u64>(2)?,
        origin_device_id: r.get(4)?,
        deleted_at_unix_nanos: r.get(5)?,
        deleted_by_operation,
        record_kind: RecordKind::from_db_str(&r.get::<_, String>(8)?),
    })
}

/// Marks the row a deletion just trashed with the recursive operation that
/// deletion was a part of, if it was one. The trashed row's native head names
/// the operation, and its part record is already in this database by the
/// time any row is projected from it: a delta is admitted (and its part
/// recorded) before anything is materialized from it, and local emission
/// appends and records in the transaction that writes the row.
fn stamp_trashed_row_operation(
    tx: &rusqlite::Transaction,
    group_id: &str,
    path: &str,
    trashed_seq: i64,
    trashed_native_identity: Option<&[u8]>,
) -> Result<(), SyncSqliteError> {
    // The removal of a native head names its operation by the removed head's
    // provenance, which leads the row's native identity.
    let operation = match trashed_native_identity {
        Some(identity) => {
            match yadorilink_replica_domain::native_plan::NativeRowIdentity::from_bytes(identity) {
                Ok(identity) => crate::native_recursive_operation::operation_removing(
                    tx,
                    group_id,
                    identity.source_path.as_str(),
                    &identity.provenance.0,
                )?,
                Err(_) => None,
            }
        }
        None => None,
    };
    let Some(operation) = operation else {
        return Ok(());
    };
    tx.execute_cached(
        "UPDATE files SET trashed_by_operation_author = ?1, trashed_by_operation_id = ?2 \
         WHERE group_id = ?3 AND path = ?4 AND version_seq = ?5 AND state = 'trashed'",
        rusqlite::params![
            operation.author.as_str(),
            &operation.operation_id.0[..],
            group_id,
            path,
            trashed_seq
        ],
    )?;
    Ok(())
}

/// The shared version-retaining write
/// path behind `SyncState::upsert_file_with_origin` and
/// `SyncState::upsert_files_batch` — see `upsert_file_with_origin`'s doc
/// comment for the full semantics. Takes an open `Transaction` rather than
/// checking out its own pooled connection so a batch caller can commit
/// once for many records (mirroring the pre-existing `upsert_files_batch`
/// shape) while a single-record caller still gets the same atomicity via
/// its own one-record transaction — see `new_immediate_write_transaction`'s
/// doc comment for why that transaction must be opened `IMMEDIATE`, not
/// rusqlite's default `DEFERRED`.
///
/// sync-performance: `upsert_file_with_origin` is the hot path for every
/// local edit and every peer-adopted change, so this is written for two
/// SQLite round trips, not the more obvious three (a `SELECT` to find the
/// current row, an `INSERT` for the new one, an `UPDATE` to flip the old
/// one). An earlier draft chased this down to a *single* round trip with
/// an `AFTER INSERT` trigger; that turned out not to be the actual
/// bottleneck (see `new_immediate_write_transaction`) and introduced its
/// own correctness risk (a trigger recursing into the same table its own
/// statement is still executing over), so it was reverted in favor of this
/// plainer two-statement version.
///
/// The first round trip below is an `UPDATE... RETURNING`: it flips
/// whatever row is currently `state = 'current'` (if any) to
/// `superseded`/`trashed` per 's rule *and* returns everything
/// needed to build the new current row, so no separate up-front `SELECT`
/// is needed before it.
///
/// Every row this function writes -- all three branches -- is stamped with
/// `admitted_at_unix_nanos`, this device's own local clock read at the
/// moment of the write. Captured inside this function rather than passed
/// in, so no caller can supply it and no caller site needed to change.
/// Never `record.mtime_unix_nanos` -- see that column's own migration
/// comment in `yadorilink-sqlite-runtime`'s schema for why a replicated
/// filesystem timestamp is untrusted input here.
///
/// # The stamping invariant
///
/// This function is the ordinary per-path version write path, but it is
/// deliberately NOT the only writer of `files` rows, and the correctness of
/// everything reading `admitted_at_unix_nanos` rests on the whole set
/// agreeing. The invariant, stated once here because it is easy to break by
/// adding a fourth writer without noticing:
///
/// > **Every statement anywhere that inserts a `files` row stamps
/// > `admitted_at_unix_nanos` from this device's own clock at the moment of
/// > that write. A NULL means only "this row predates the column".**
///
/// The complete set of writers, all of which do:
///
/// * this function (three branches: new path, `version_seq = 0` scaffold
///   promotion, and superseding version bump),
/// * [`FileIndexRepository::ensure_bootstrap_row_for_metadata`] and
///   [`ensure_bootstrap_row_for_metadata_in_tx`], which insert the
///   `version_seq = 0` metadata scaffold.
///
/// Two consequences follow, and both are load-bearing rather than
/// incidental:
///
/// * Because every writer stamps, a NULL genuinely does mean "written
///   before the column existed" -- so `crate::rewind_plan` is entitled to
///   treat NULL rows as a prefix of a path's history and to report the
///   affected path as unanswerable rather than guessing.
/// * Several rows for one path can share a stamp when the clock is coarse.
///   The reader's `version_seq DESC` tie-break is what resolves that to the
///   path's current row.
pub fn upsert_file_in_tx(
    tx: &rusqlite::Transaction,
    group_id: &str,
    record: &FileRecord,
    origin_device_id: &str,
    retention: Retention<'_>,
) -> Result<(), SyncSqliteError> {
    upsert_file_with_authoring_in_tx(tx, group_id, record, origin_device_id, None, retention)
}

/// Records the evidence behind a row's native identity: the identity is good
/// only if this replica holds exactly that head now -- the same source path,
/// dot and provenance. The evidence is that whole identity, kept in its own
/// table so the row stays authored after the head is superseded and the log is
/// truncated, and so it can never license another row to cite a provenance
/// that merely once existed. With no such head nothing is recorded and the
/// authoring trigger refuses the row.
pub(crate) fn record_native_authoring_witness(
    tx: &Connection,
    group_id: &str,
    identity: &yadorilink_replica_domain::native_plan::NativeRowIdentity,
) -> Result<(), SyncSqliteError> {
    tx.prepare_cached(
        "INSERT OR IGNORE INTO native_authoring_witness (group_id, identity, version) \
         SELECT ?1, ?2, version FROM native_heads \
             WHERE group_id = ?1 AND path = ?3 AND author = ?4 AND incarnation = ?5 \
               AND seq = ?6 AND provenance = ?7",
    )?
    .execute(rusqlite::params![
        group_id,
        identity.to_bytes(),
        identity.source_path.as_str(),
        identity.dot.author.device.0,
        identity.dot.author.incarnation.0.as_slice(),
        identity.dot.seq.get() as i64,
        &identity.provenance.0[..],
    ])?;
    Ok(())
}

/// Refuses a row that cites a native head while showing another version than
/// that head carried. Run once the row is completely written (its columns
/// included), inside the writing transaction. A row citing an identity with no
/// witness is left to the authoring trigger.
pub(crate) fn require_row_shows_native_head(
    conn: &Connection,
    group_id: &str,
    path: &str,
    authoring: Option<&yadorilink_replica_domain::native_plan::NativeRowIdentity>,
) -> Result<(), SyncSqliteError> {
    let Some(identity) = authoring else { return Ok(()) };
    let Some(row) = crate::store::read_canonical_current_row(conn, group_id, path)? else {
        return Ok(());
    };
    if row.snapshot.deleted {
        return Ok(());
    }
    let recorded: Option<Vec<u8>> = conn
        .prepare_cached(
            "SELECT version FROM native_authoring_witness WHERE group_id = ?1 AND identity = ?2",
        )?
        .query_row(rusqlite::params![group_id, identity.to_bytes()], |r| r.get(0))
        .optional()?;
    refuse_row_not_showing_head(path, &row, recorded.as_deref())
}

/// The refusal [`require_row_shows_native_head`] makes, given the version the row's identity was
/// witnessed for (`None` when no witness exists, which the authoring trigger handles).
pub(crate) fn refuse_row_not_showing_head(
    path: &str,
    row: &crate::store::CanonicalCurrentRow,
    recorded: Option<&[u8]>,
) -> Result<(), SyncSqliteError> {
    match recorded {
        Some(version) if version != row.version_hash().0.as_slice() => {
            Err(SyncSqliteError::InvalidInput(format!(
                "the row at {path:?} cites a native head of another version than it shows"
            )))
        }
        _ => Ok(()),
    }
}

/// The native head the current row at `path` shows, if it shows one. `None`
/// for a path with no current row and for a row produced from no head.
pub fn row_authoring_in_tx(
    conn: &Connection,
    group_id: &str,
    path: &str,
) -> Result<Option<yadorilink_replica_domain::native_plan::NativeRowIdentity>, SyncSqliteError> {
    use yadorilink_replica_domain::native_plan::NativeRowIdentity;
    let native: Option<Option<Vec<u8>>> = conn
        .prepare_cached(
            "SELECT native_authoring_identity FROM files \
             WHERE group_id = ?1 AND path = ?2 AND state = 'current'",
        )?
        .query_row(rusqlite::params![group_id, path], |r| r.get(0))
        .optional()?;
    native
        .flatten()
        .map(|bytes| {
            NativeRowIdentity::from_bytes(&bytes).map_err(|error| {
                SyncSqliteError::CorruptState(format!("native identity of {path:?}: {error}"))
            })
        })
        .transpose()
}

/// [`upsert_file_in_tx`] for a row that may be produced under NativeState:
/// `authoring` is the native head the row shows. With no head (a tombstone,
/// or a row written from none) the identity of the row this one supersedes is
/// carried forward.
pub fn upsert_file_with_authoring_in_tx(
    tx: &rusqlite::Transaction,
    group_id: &str,
    record: &FileRecord,
    origin_device_id: &str,
    authoring: Option<&yadorilink_replica_domain::native_plan::NativeRowIdentity>,
    retention: Retention<'_>,
) -> Result<(), SyncSqliteError> {
    upsert_file_with_meta_in_tx(tx, group_id, record, origin_device_id, authoring, None, retention)
}

/// A live current row whose block list cannot be read back. `group_id` and `path` are for display
/// and for matching a folder; the row is identified by `rowid`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DamagedRow {
    pub rowid: i64,
    pub group_id: String,
    pub path: String,
}

/// What one step of [`FileIndexRepository::audit_live_block_lists`] found.
#[derive(Debug, Default)]
pub struct BlockListAudit {
    /// Every live current row whose block list cannot be read back.
    pub damaged: Vec<DamagedRow>,
    pub next_rowid: Option<i64>,
}

/// A stored block list that is not valid JSON, does not decode to blocks, or fails the check a
/// write applies.
fn block_list_is_damaged(size: i64, blocks_json: &str) -> bool {
    match serde_json::from_str::<Vec<yadorilink_replica_domain::file::BlockInfo>>(blocks_json) {
        Ok(blocks) => u64::try_from(size).map_or(true, |size| {
            yadorilink_replica_domain::file::check_block_list(size, &blocks).is_err()
        }),
        Err(_) => true,
    }
}

/// A stored `size` and `blocks_json`, judged without trusting the columns' types: anything but an
/// integer size and a UTF-8 text block list that [`block_list_is_damaged`] accepts is damaged.
fn stored_block_list_is_damaged(
    size: rusqlite::types::ValueRef<'_>,
    blocks_json: rusqlite::types::ValueRef<'_>,
) -> bool {
    match (size, blocks_json) {
        (rusqlite::types::ValueRef::Integer(size), rusqlite::types::ValueRef::Text(bytes)) => {
            std::str::from_utf8(bytes).map_or(true, |json| block_list_is_damaged(size, json))
        }
        _ => true,
    }
}

fn lossy_text(value: rusqlite::types::ValueRef<'_>) -> String {
    match value {
        rusqlite::types::ValueRef::Text(bytes) => String::from_utf8_lossy(bytes).into_owned(),
        _ => String::new(),
    }
}

/// Refuses, before anything is written, a record whose block list could not be read back (see
/// [`yadorilink_replica_domain::file::check_block_list`]). Every `files.blocks_json` write goes
/// through here, so a row that fails never reaches the ledger.
///
/// Only the row about to be written is judged. A tombstone is let through: it records a deletion,
/// and refusing it would keep a damaged row from being removed. Overwriting a damaged row with a
/// correct record passes the check as any correct record does.
pub(crate) fn refuse_unreadable_block_list(record: &FileRecord) -> Result<(), SyncSqliteError> {
    if record.deleted {
        return Ok(());
    }
    yadorilink_replica_domain::file::check_block_list(record.size, &record.blocks).map_err(|e| {
        SyncSqliteError::InvalidInput(format!(
            "refusing to store the block list of {}: {e}",
            record.path
        ))
    })
}

/// [`upsert_file_with_authoring_in_tx`] for a version whose metadata columns
/// are known: `meta` is written onto the row this call inserts, in the same
/// transaction, and onto no other. The row it supersedes keeps the columns
/// it was authored with, which is what history readers (rewind, the removal
/// guard) compare the disk against. With none, the columns are carried
/// forward from the superseded row, as for a version bump that changes no
/// metadata.
pub fn upsert_file_with_meta_in_tx(
    tx: &rusqlite::Transaction,
    group_id: &str,
    record: &FileRecord,
    origin_device_id: &str,
    authoring: Option<&yadorilink_replica_domain::native_plan::NativeRowIdentity>,
    meta: Option<&LocalFileMetaColumns>,
    retention: Retention<'_>,
) -> Result<(), SyncSqliteError> {
    refuse_unreadable_block_list(record)?;
    // Before the row stops being current: a sync may not replace a version that has bytes to keep
    // without the proof that they are kept.
    let supersede = crate::retention::check_before_supersede(
        tx,
        group_id,
        &record.path,
        &record.blocks,
        retention,
    )?;
    let native_blob: Option<Vec<u8>> = authoring.map(|identity| identity.to_bytes());
    if let Some(identity) = authoring {
        record_native_authoring_witness(tx, group_id, identity)?;
    }
    let blocks_json = serde_json::to_string(&record.blocks)?;
    let (case_key, canonical_key) = name_fold_keys(&record.path);
    let origin: Option<&str> =
        if origin_device_id.is_empty() { None } else { Some(origin_device_id) };
    // Read once, before any branch, so all three branches stamp the exact
    // same instant for one call -- a scaffold promotion in particular
    // writes what is logically the same admission as the insert that
    // preceded it, and two clock reads could otherwise straddle a rewind
    // target and split them.
    let admitted_at_unix_nanos = now_unix_nanos_checked();

    #[allow(clippy::type_complexity)]
    let flipped: Option<(
        i64,
        i64,
        String,
        String,
        Option<Vec<u8>>,
        i64,
        Option<String>,
        Option<i64>,
        i64,
        Option<Vec<u8>>,
        String,
    )> = tx
        .prepare_cached(
            "UPDATE files SET state = CASE WHEN deleted = 0 AND ?3 = 1 THEN 'trashed' ELSE 'superseded' END
             WHERE group_id = ?1 AND path = ?2 AND state = 'current'
             RETURNING version_seq, deleted, materialization_state, record_kind,
                       symlink_target, exec, held_reason, held_since_unix_nanos,
                       symlink_out_of_root,
                       native_authoring_identity, blocks_json",
        )?
        .query_row(
            rusqlite::params![group_id, record.path, record.deleted as i64],
            |r| {
                Ok((
                    r.get(0)?,
                    r.get(1)?,
                    r.get(2)?,
                    r.get(3)?,
                    r.get(4)?,
                    r.get(5)?,
                    r.get(6)?,
                    r.get(7)?,
                    r.get(8)?,
                    r.get(9)?,
                    r.get(10)?,
                ))
            },
        )
        .optional()?;

    // A scaffold (`version_seq = 0`) was never a genuine version, so it is no
    // previous row for the activity log.
    let previous =
        flipped.as_ref().filter(|row| row.0 != 0).map(|row| crate::activity::PreviousRow {
            deleted: row.1 != 0,
            record_kind: row.3.clone(),
            blocks_json: row.10.clone(),
        });
    match flipped {
        None => {
            // No current row: a brand new path, or one whose rows are all
            // history. A base install leaves the latter where the path's
            // row moved away -- a leaf relocated to its copy name when the
            // path became a directory, or a row the base keeps only as
            // history -- so the new version is numbered after whatever the
            // path already has, never as its first.
            tx.prepare_cached(
                "INSERT INTO files (group_id, path, size, mtime_unix_nanos, blocks_json, deleted, version_seq, state, origin_device_id, admitted_at_unix_nanos, native_authoring_identity, case_fold_key, canonical_fold_key)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6,
                         (SELECT COALESCE(MAX(version_seq), 0) + 1 FROM files
                           WHERE group_id = ?1 AND path = ?2),
                         'current', ?7, ?8, ?9, ?10, ?11)",
            )?
            .execute(rusqlite::params![
                group_id,
                record.path,
                record.size,
                record.mtime_unix_nanos,
                blocks_json,
                record.deleted as i64,
                origin,
                admitted_at_unix_nanos,
                native_blob,
                case_key,
                canonical_key,
            ])?;
        }
        // The receiving side's metadata bootstrap scaffold
        // (`version_seq = 0`, created by `ensure_bootstrap_row_for_metadata`)
        // was never a genuine observed version — the `UPDATE` above
        // incorrectly flipped it to superseded/trashed as a side effect of
        // matching `state = 'current'`; undo that and promote it to
        // version 1 in place (an `UPDATE`, not a fresh `INSERT`, so
        // whatever `record_kind`/`symlink_target`/`unix_mode`/etc. its own
        // setters already wrote onto it survives untouched) instead of
        // leaving a spurious empty first version in this path's history.
        // The scaffold exists exactly when the path has no current row,
        // which includes a path that holds only history (a merged base
        // that made it structural, a relocation's source): the promoted
        // row is numbered after that history, never as version 1.
        // Rare (a scaffold row exists for at most the moment between its
        // own creation and this call), so the extra round trip here
        // doesn't cost the common case anything.
        Some((0, ..)) => {
            tx.execute_cached(
                "UPDATE files SET size = ?1, mtime_unix_nanos = ?2, blocks_json = ?3, deleted = ?4,
                        version_seq = (SELECT COALESCE(MAX(version_seq), 0) + 1 FROM files
                                        WHERE group_id = ?7 AND path = ?8),
                        state = 'current', origin_device_id = ?5, admitted_at_unix_nanos = ?6,
                        native_authoring_identity = ?9
                 WHERE group_id = ?7 AND path = ?8 AND version_seq = 0",
                rusqlite::params![
                    record.size,
                    record.mtime_unix_nanos,
                    blocks_json,
                    record.deleted as i64,
                    origin,
                    admitted_at_unix_nanos,
                    group_id,
                    record.path,
                    native_blob,
                ],
            )?;
        }
        Some((
            old_seq,
            old_deleted,
            materialization_state,
            record_kind,
            symlink_target,
            exec,
            held_reason,
            held_since_unix_nanos,
            symlink_out_of_root,
            native_carried,
            _,
        )) => {
            // Every per-file column `FileRecord` doesn't carry
            // (materialization state, record kind, symlink target,
            // exec bit, extended attributes, held state) is copied forward
            // from the row just superseded — already in hand from the
            // `RETURNING` above, no extra read needed — so a version bump
            // alone never silently resets any of them to their column
            // defaults. Which new `state` the old row ended up as
            // (`trashed` vs `superseded`) was already decided by the `CASE`
            // in the `UPDATE` above.
            //
            // `materialization_state` specifically is an explicit CARRY-
            // FORWARD, not a missing-column case -- the schema's own
            // default (`'remote'` as of v25, see `SCHEMA_VERSION`'s
            // doc comment) never applies here, so it cannot protect this
            // branch the way it protects a genuinely brand-new path's
            // first-ever row below. Carrying `Present` forward onto a
            // version bump whose NEW content is not yet confirmed on disk
            // reintroduces the identical "claims Hydrated with nothing to
            // back it up" bug this whole file's callers exist to avoid --
            // it is the caller's job, not this function's, to correct this
            // afterward (in the SAME transaction, same as `stamp_hydrated_
            // after_local_emission_in_tx` does for local emission) whenever
            // the new content is not already known-present. Every current
            // production caller either IS local emission (does correct it,
            // via that stamp), or is `materialize`/`materialize_symlink_at`
            // in `yadorilink-peer-session`, each of which already performs
            // its own explicit, targeted correction (a hazard hold or a
            // policy-skipped symlink demotes to `Remote`; the
            // content-identical fast path only reaches this branch after
            // verifying the disk bytes already match, so the carried-
            // forward value is factually correct, not a guess) -- verified
            // by enumerating every non-test caller of this function's own
            // wrappers, not assumed. A FUTURE caller that upserts an
            // existing row for content it has not itself verified is
            // already on disk MUST perform the same explicit correction;
            // this carry-forward alone is not a safe default for it.
            let gives_up = matches!(supersede, crate::retention::Supersede::GiveUp(_));
            // A row that is not kept needs no mark of the operation that trashed it.
            if record.deleted && old_deleted == 0 && !gives_up {
                stamp_trashed_row_operation(
                    tx,
                    group_id,
                    &record.path,
                    old_seq,
                    native_carried.as_deref(),
                )?;
            }
            tx.execute_cached("INSERT INTO files (
                    group_id, path, size, mtime_unix_nanos, blocks_json, deleted,
                    version_seq, state, origin_device_id,
                    materialization_state, record_kind,
                    symlink_target, exec, held_reason, held_since_unix_nanos,
                    symlink_out_of_root,
                    admitted_at_unix_nanos, native_authoring_identity,
                    case_fold_key, canonical_fold_key
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'current', ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19)",
                rusqlite::params![
                    group_id,
                    record.path,
                    record.size,
                    record.mtime_unix_nanos,
                    blocks_json,
                    record.deleted as i64,
                    old_seq + 1,
                    origin,
                    materialization_state,
                    record_kind,
                    symlink_target,
                    exec,
                    held_reason,
                    held_since_unix_nanos,
                    symlink_out_of_root,
                    // NOT carried forward from the row just superseded --
                    // this is a NEW admission of a NEW version, and its
                    // admission time is now, not the previous version's.
                    admitted_at_unix_nanos,
                    // The head this row was produced from; a row written from
                    // none keeps the identity of the one it replaces.
                    native_blob.or(native_carried),
                    case_key,
                    canonical_key,
                ],
            )?;
            if let crate::retention::Supersede::GiveUp(reason) = supersede {
                give_up_replaced_row(
                    tx,
                    group_id,
                    &record.path,
                    old_seq,
                    reason,
                    admitted_at_unix_nanos.unwrap_or(0),
                )?;
            }
        }
    }
    crate::activity::record_version_in_tx(
        tx,
        group_id,
        &record.path,
        record.deleted,
        &blocks_json,
        origin,
        previous.as_ref(),
    )?;
    if let Some(meta) = meta {
        apply_local_meta_columns_in_tx(tx, group_id, &record.path, meta)?;
    }
    Ok(())
}

/// A supersede that gives up the version it replaces (a `Skipped` retention proof): records the
/// gap the missing version leaves, then removes the row, in the caller's transaction. The new
/// current row (the successor, numbered after the old one) is already written, so the recorded
/// span ends at its admission. Nothing else is removed: older versions stay as they are.
fn give_up_replaced_row(
    tx: &rusqlite::Transaction,
    group_id: &str,
    path: &str,
    old_seq: i64,
    reason: crate::retention::SkipReason,
    now_unix_nanos: i64,
) -> Result<(), SyncSqliteError> {
    let rows: Vec<crate::history_freed::Member> = {
        let mut stmt = tx.prepare_cached(
            "SELECT version_seq, admitted_at_unix_nanos FROM files \
             WHERE group_id = ?1 AND path = ?2",
        )?;
        let rows = stmt.query_map(rusqlite::params![group_id, path], |r| {
            Ok(crate::history_freed::Member { seq: r.get(0)?, admitted: r.get(1)? })
        })?;
        rows.collect::<Result<Vec<_>, _>>()?
    };
    let crate::retention::SkipReason::LowSpace = reason;
    crate::history_freed::record(
        tx,
        group_id,
        path,
        &rows,
        &HashSet::from([old_seq]),
        crate::history_freed::FreedReason::LowSpace,
        now_unix_nanos,
    )?;
    tx.execute_cached(
        "DELETE FROM files WHERE group_id = ?1 AND path = ?2 AND version_seq = ?3",
        rusqlite::params![group_id, path, old_seq],
    )?;
    Ok(())
}

/// The two name-collision keys stored with every `files` row: the
/// case-folded path and the case-and-normalization-folded path, computed by
/// the same functions the hazard check compares with.
pub(crate) fn name_fold_keys(path: &str) -> (String, String) {
    (
        yadorilink_fs_platform::canonical_fold::case_fold(path),
        yadorilink_fs_platform::canonical_fold::canonical_fold(path),
    )
}

/// Which stored name key a collision lookup matches on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NameFoldKey {
    /// Unicode case folding of the whole path.
    Case,
    /// Case folding combined with NFC normalization. Every pair equal under
    /// NFC alone is equal here, so it is also the candidate key for the
    /// normalization-only check.
    Canonical,
}

pub(crate) const NAME_FOLD_MATCHES_SQL_CASE: &str = "SELECT path FROM files \
     WHERE group_id = ?1 AND state = 'current' AND deleted = 0 AND case_fold_key = ?2 \
       AND path <> ?3";
pub(crate) const NAME_FOLD_MATCHES_SQL_CANONICAL: &str = "SELECT path FROM files \
     WHERE group_id = ?1 AND state = 'current' AND deleted = 0 AND canonical_fold_key = ?2 \
       AND path <> ?3";

pub(crate) fn name_fold_matches_on(
    conn: &Connection,
    group_id: &str,
    key: NameFoldKey,
    folded: &str,
    path: &str,
) -> Result<Vec<String>, SyncSqliteError> {
    let sql = match key {
        NameFoldKey::Case => NAME_FOLD_MATCHES_SQL_CASE,
        NameFoldKey::Canonical => NAME_FOLD_MATCHES_SQL_CANONICAL,
    };
    let mut stmt = conn.prepare_cached(sql)?;
    let rows = stmt.query_map(rusqlite::params![group_id, folded, path], |r| r.get(0))?;
    let mut paths = rows.collect::<Result<Vec<String>, _>>()?;
    // Sorted here rather than by the statement: an ORDER BY on `path` lets the
    // planner walk the primary key in order and scan the whole group.
    paths.sort();
    Ok(paths)
}

/// Writes a path's local metadata columns (record kind, symlink target /
/// out-of-root flag, exec bit) inside `tx`, the SAME transaction that just
/// wrote its `current` row via [`upsert_file_in_tx`]. This is the atomic,
/// in-transaction counterpart to the standalone `set_record_kind`/
/// `set_symlink_target`/`set_symlink_out_of_root`/`set_exec` setters — it
/// must run strictly after `upsert_file_in_tx` (these are `UPDATE`s and need
/// the row to already exist), so the index columns and the emitted change's
/// `FileVersion` commit as one unit.
pub fn apply_local_meta_columns_in_tx(
    tx: &rusqlite::Transaction,
    group_id: &str,
    path: &str,
    meta: &LocalFileMetaColumns,
) -> Result<(), SyncSqliteError> {
    tx.prepare_cached(
        "UPDATE files SET record_kind = ?1, symlink_target = ?2, symlink_out_of_root = ?3, exec = ?4
         WHERE group_id = ?5 AND path = ?6 AND state = 'current'",
    )?
    .execute(rusqlite::params![
        meta.record_kind.as_db_str(),
        meta.symlink_target,
        meta.symlink_out_of_root as i64,
        i64::from(meta.exec),
        group_id,
        path,
    ])?;
    if meta.record_kind == RecordKind::Directory {
        crate::activity::forget_directory_event_in_tx(tx, group_id, path)?;
    }
    Ok(())
}

/// Stamps `Present` on a just-locally-authored, non-deleted row, in the
/// SAME transaction as its index/change commit -- the explicit counterpart
/// to `files.materialization_state`'s schema-level default
/// (`'remote'` as of schema v25; see that column's own migration
/// comment for the full reasoning). A schema default fires for ANY insert
/// that omits the column, including ones this device has no evidence about
/// (a peer's incoming record, a hazard hold, a policy skip) -- those must
/// default to `Remote` and earn `Present` only once real content is
/// confirmed. Called only for `!record.deleted` -- a tombstone has no
/// materialized content to claim, and its own row's
/// `materialization_state` is moot.
pub fn stamp_hydrated_after_local_emission_in_tx(
    tx: &rusqlite::Transaction,
    group_id: &str,
    path: &str,
) -> Result<(), SyncSqliteError> {
    tx.execute_cached(
        "UPDATE files SET materialization_state = ?1 \
         WHERE group_id = ?2 AND path = ?3 AND state = 'current'",
        rusqlite::params![MaterializationState::Present.as_db_str(), group_id, path],
    )?;
    Ok(())
}

/// What the initial import observed on disk for one path, so the
/// transaction that puts that path into history can also record the proof
/// that the path is already materialized.
///
/// The same idea as [`LocalCaptureActualStateEvidence`], for the one
/// capture path that is not a live edit: an import of files that were
/// already sitting in the folder when it was linked. Those files are
/// already correct on disk -- nothing has to be fetched or written to
/// make them so -- and without a proof saying that, this device has no
/// way to conclude it, so it waits for a peer to tell it something it
/// already knows.
#[derive(Clone, Debug)]
pub struct ImportedActualState {
    pub filesystem_identity: yadorilink_fs_platform::fs_identity::FileIdentity,
    pub record_kind: RecordKind,
    pub version_hash: yadorilink_replica_domain::ids::VersionHash,
}

/// What actual-state evidence local capture has for one already-prepared
/// batch mutation, if any -- see `adopt_local_capture_actual_state`/
/// `adopt_observed_actual_generation_in_tx`'s own doc comments for the
/// full design. No evidence for a path means: commit the delta/index
/// exactly as before, publish no proof -- never a correctness
/// requirement, only a forgone optimization.
#[derive(Clone, Debug)]
pub enum LocalCaptureActualStateEvidence {
    /// A present object this capture just authored: `filesystem_identity`
    /// must be freshly observed from the real path, immediately before
    /// the batch commit, under the path's lock -- not reused from an
    /// earlier prepare-time observation without a fresh disk-fingerprint
    /// match confirming nothing changed since.
    Present { filesystem_identity: yadorilink_fs_platform::fs_identity::FileIdentity },
    /// A deletion local capture just observed and revalidated as still
    /// absent immediately before this commit.
    Absent,
}

/// Adopts a just-locally-authored path's actual state, in the SAME
/// transaction as the local delta/index commit that produced it -- see
/// `materialized_generation::adopt_observed_actual_generation_in_tx`'s own
/// doc comment for the full design (why this differs from an internal
/// mutator's bump-then-mutate-then-CAS ordering, and the external-writer
/// consistency boundary this proof is exact relative to).
///
/// `object_kind`/`version` describe a PRESENT object; there is no
/// `Absent` case here -- a locally observed deletion is a structurally
/// different call (no version, no filesystem identity, kind `Absent`),
/// handled at its own call site, not through this present-only helper.
///
/// # Race/crash arguments (mandatory regression list, items B/C/F/G)
///
/// Items A/D/E of that list are exercised as real tests (disk-changes-
/// mid-prepare, second-edit supersession, delete). B/C/F/G are argued here
/// instead, per the same list's own allowance to prove a structural
/// call-graph/lock property rather than write a test for an interleaving
/// the design makes impossible:
///
/// - **B (a concurrent internal mutator advances E while local capture is
///   mid-flight)**: cannot interleave with this call. Both an internal
///   mutator's [`materialized_generation::bump_mutation_fence`] and this
///   path's own call into [`materialized_generation::
///   adopt_observed_actual_generation_in_tx`] happen only under the same
///   path lock local capture already holds for the whole prepare-through-
///   commit window (see the call site's own lock-scope comments), and the
///   fence bump plus generation write both happen inside one SQLite
///   `IMMEDIATE` transaction (`write_immediate`), so a second writer for
///   the same `(group_id, path)` blocks at the SQLite layer until this
///   transaction commits or aborts -- there is no window in which a
///   concurrent bump can land between this call's own bump and its own
///   write. A stale local proof from a *prior* completed transaction is
///   simply never written in the first place, because the row this call
///   writes always carries the epoch it just minted, not an older one.
/// - **C (a new admission lands after this proof publishes)**: not
///   prevented by locking -- allowed to happen, and handled by the
///   pre-existing, unchanged mechanism: [`materialized_generation::
///   lookup_materialized_generation`] is a fail-closed CAS read that
///   requires `published_under_mutation_generation` to still equal the
///   live fence value. A subsequent admission that mutates the same path
///   goes through the ordinary internal-mutator path, which bumps the
///   fence again before its own mutation -- at that instant this call's
///   row's captured epoch stops matching the live fence, so the lookup
///   used by zero-work settlement stops returning it (reads as absent, not
///   as a stale hit). Nothing added by this function weakens that
///   existing guarantee; it only ever produces rows that participate in
///   it.
/// - **F (crash before this transaction's commit)**: `write_immediate`'s
///   underlying `BEGIN IMMEDIATE ... COMMIT` is SQLite's own atomic unit --
///   a crash before `COMMIT` leaves neither the fence bump, the generation
///   row, nor the admitted local delta durable, because none of the
///   transaction's writes are visible outside it until commit succeeds.
///   The dirty-journal entry that triggered this capture in the first
///   place was written before the transaction started and survives
///   untouched, so the ordinary local-capture re-drive path picks the path
///   back up exactly as if this attempt never happened. No new failure
///   mode: this is the same atomicity every other `write_immediate` caller
///   in this file already relies on.
/// - **G (commit succeeds, but clearing the dirty-journal entry fails or
///   is delayed)**: the generation row and the admitted delta are now
///   durable; a redundant re-drive later observes the same disk state,
///   revalidates it (fingerprint/index/identity all still match), and
///   this function runs again -- `bump_mutation_fence` mints a new epoch,
///   `write_generation_row` writes a new row under it, replacing the
///   prior one (see `materialized_generation`'s "Immutability" doc: a row
///   is always replaced whole, never edited in place). The redundant
///   proof is content-identical to the one it replaces (same
///   `resolved_path_state_hash`, since content and kind are unchanged),
///   so this is idempotent from zero-work settlement's point of view --
///   a second, unnecessary proof publication, never an incorrect one.
///
/// `version_hash` is by value, not `Option`, and that is the whole point
/// of the parameter rather than a convention: a present object with no
/// version is a proof that matches no desired resolution at all --
/// `resolved_path_state_hash` encodes version presence -- so it cannot
/// close anything, while looking healthy enough to stop a repair pass
/// from noticing. Every caller here has the exact version in hand,
/// because the same transaction is committing it.
pub fn adopt_local_capture_actual_state(
    tx: &rusqlite::Transaction,
    group_id: &str,
    path: &str,
    record_kind: RecordKind,
    version_hash: &yadorilink_replica_domain::ids::VersionHash,
    filesystem_identity: &yadorilink_fs_platform::fs_identity::FileIdentity,
) -> Result<(), SyncSqliteError> {
    let object_kind = match record_kind {
        RecordKind::File => MaterializedObjectKind::RegularFile,
        RecordKind::Directory => MaterializedObjectKind::Directory,
        RecordKind::Symlink => MaterializedObjectKind::Symlink,
    };
    crate::materialized_generation::adopt_observed_actual_generation_in_tx(
        tx,
        group_id,
        path,
        object_kind,
        Some(version_hash),
        Some(filesystem_identity),
        now_unix_nanos(),
    )?;
    Ok(())
}

/// Present-object counterpart to
/// [`settle_obligation_against_local_absence_in_tx`], and the answer to a
/// measured question: a bulk local emission of N paths published N exact
/// actual-state proofs and still left N obligations runnable, because only
/// the absent direction was ever closed here. Every one of those is a wake,
/// a claim and a full desired-state re-derivation for the Convergence
/// Engine, to reach a conclusion this transaction had already proven and
/// written down.
///
/// The justification is the absent case's, unchanged: the caller
/// revalidated the object on disk immediately before this commit (that
/// observation is what produced the change being emitted), holds that
/// observation's fingerprint through it, and
/// [`adopt_local_capture_actual_state`] has just published the matching
/// generation under a fresh fence epoch. `emit_local_change` says the same
/// thing in its own words where it tags this obligation `Local`: the bytes
/// "were already observed on this device's own disk", so the obligation
/// "can never represent content not yet placed locally". That knowledge was
/// already being used to stop a bogus tombstone veto; this uses it to close
/// the obligation it describes.
///
/// Desired state is RESOLVED, never assumed. It would be easy, and wrong,
/// to close against the version this change happens to carry: that assumes
/// our own op wins the path, which a divergent branch or conflict
/// resolution can deny. `desired_path_state` computes what the engine
/// itself would place at the path -- the per-path winner, with the tree
/// constraint of live descendants applied -- inside this transaction and
/// after this change was appended, and the CAS then closes only if the
/// proof just published IS that state. Anything else -- a losing branch, a
/// file a live descendant displaces, a winner whose version this replica
/// cannot resolve -- leaves the
/// obligation exactly where it was, for the engine to handle as it always
/// has. Fail-safe in the direction that matters: the failure mode of this
/// function is "the engine still does the work", never "nobody does".
fn settle_obligation_against_local_presence_in_tx(
    tx: &rusqlite::Transaction,
    group_id: &str,
    path: &str,
) -> Result<(), SyncSqliteError> {
    let Some(obligation) =
        crate::projection_obligations::lookup_projection_obligation(tx, group_id, path)?
    else {
        return Ok(());
    };
    if obligation.state != "pending" {
        return Ok(());
    }
    // The namespace decides what the path must be, not the path's own
    // heads alone: a captured File at a path a live descendant needs makes
    // the path contested, and a contested path is owed nothing yet. Read in
    // this transaction, after the write was authored.
    let desired = match crate::native_desired_state::native_desired_path_state(tx, group_id, path) {
        Ok(state) => state,
        // "Not yet resolvable", not "absent" -- see that function's own
        // fail-closed contract. Leave the obligation for the engine.
        Err(SyncSqliteError::NotFound(_)) => return Ok(()),
        Err(e) => return Err(e),
    };
    if let crate::desired_state::DesiredPathState::StructuralDirectory = desired {
        // The directory the path has to be is the engine's to place.
        return Ok(());
    }
    let desired = desired.resolved_path_state_hash(group_id, path);
    crate::projection_obligations::complete_obligation_if_exact_proof_current(
        tx,
        group_id,
        path,
        obligation.invalidation_generation,
        obligation.obligation_incarnation,
        &desired,
    )?;
    Ok(())
}

fn adopt_local_capture_absent_state(
    tx: &rusqlite::Transaction,
    group_id: &str,
    path: &str,
) -> Result<(), SyncSqliteError> {
    crate::materialized_generation::adopt_observed_actual_generation_in_tx(
        tx,
        group_id,
        path,
        MaterializedObjectKind::Absent,
        None,
        None,
        now_unix_nanos(),
    )?;
    // An exactly-absent path has no local object, so its row may not also
    // claim to have one -- the same rule `commit_internal_materialized_state_
    // if_fence_current` applies to its own `Absent` arm. The tombstone row
    // this proof belongs to inherited its predecessor's
    // `materialization_state` (see `upsert_file_in_tx`), and for a path that
    // used to be `Present` that inheritance names an object this same
    // transaction has just proven is gone.
    mark_remote_after_proven_absence_in_tx(tx, group_id, path)?;
    Ok(())
}

/// Marks the path `Remote` once a transaction has proven it exactly absent.
///
/// [`upsert_file_in_tx`] carries `materialization_state` forward like every
/// other per-file column, which is right for a version bump over an object
/// that is still there (`Present` stays `Present`: the state says an object
/// exists, never that it equals the new version -- exactness is the proof's
/// business). It is wrong for a row whose object this transaction has just
/// shown to be gone. Anything other than `Present` is left as it is: a
/// `Hydrating` or `Evicting` marker still names an in-flight attempt.
fn mark_remote_after_proven_absence_in_tx(
    tx: &rusqlite::Transaction,
    group_id: &str,
    path: &str,
) -> Result<(), SyncSqliteError> {
    tx.prepare_cached(
        "UPDATE files SET materialization_state = ?1 \
         WHERE group_id = ?2 AND path = ?3 AND state = 'current' \
           AND materialization_state = ?4",
    )?
    .execute(rusqlite::params![
        MaterializationState::Remote.as_db_str(),
        group_id,
        path,
        MaterializationState::Present.as_db_str(),
    ])?;
    Ok(())
}

/// The other outcome of a transaction that moves a path to a new version
/// (or tombstones it), and the reason [`adopt_local_capture_actual_state`]
/// alone was not enough: what to do when the transaction cannot say what
/// that leaves on disk.
///
/// Doing nothing is not neutral. The row's `Present` is inherited from
/// the version just superseded, and the proof backing it still names that
/// old version and is still current against the path's fence -- so the
/// pair reads as "this path exactly holds its current content" while
/// naming, between them, two different versions. Local capture reaches
/// this whenever its evidence is missing or does not line up with the op
/// it emitted: an editor's write the watcher saw only after the fact, a
/// delete whose absence nobody revalidated under this path's lock, a
/// caller whose ops and versions disagree. A restore reaches it when its
/// own physical write was declined by policy and it observed nothing.
///
/// So the transaction that writes the row also retires the proof:
///
/// ```text
/// fence -> a fresh epoch    (every published proof stops being usable)
/// ```
///
/// `materialization_state` is left alone: it says only whether a local
/// object exists, which this transaction did not change, and the object
/// that is there is no longer vouched for by any proof. The path becomes
/// one that has no proof, which is the truth: this device knows what the
/// path should be and does not know what it is. Ordinary reconciliation
/// then does the work and publishes real evidence for the result.
pub fn retire_unproven_actual_state_in_tx(
    tx: &rusqlite::Transaction,
    group_id: &str,
    path: &str,
) -> Result<(), SyncSqliteError> {
    crate::materialized_generation::invalidate_published_generations(
        tx,
        group_id,
        path,
        "unproven-new-version",
        now_unix_nanos(),
    )?;
    Ok(())
}

/// In-transaction counterpart to [`FileIndexRepository::ensure_bootstrap_
/// row_for_metadata`], for a caller that already has a `tx` open --
/// same idempotent `INSERT ... WHERE NOT EXISTS`, no separate `writer_
/// gate` acquisition of its own, and the same `admitted_at_unix_nanos`
/// stamp (see [`upsert_file_in_tx`]'s "stamping invariant" section).
pub fn ensure_bootstrap_row_for_metadata_in_tx(
    tx: &rusqlite::Transaction,
    group_id: &str,
    path: &str,
) -> Result<(), SyncSqliteError> {
    let (case_key, canonical_key) = name_fold_keys(path);
    tx.execute_cached("INSERT INTO files (group_id, path, size, mtime_unix_nanos, blocks_json, deleted, version_seq, state, origin_device_id, admitted_at_unix_nanos, case_fold_key, canonical_fold_key)
         SELECT ?1, ?2, 0, 0, '[]', 0, 0, 'current', NULL, ?3, ?4, ?5
          WHERE NOT EXISTS (SELECT 1 FROM files WHERE group_id = ?1 AND path = ?2 AND state = 'current')",
        rusqlite::params![group_id, path, now_unix_nanos_checked(), case_key, canonical_key],
    )?;
    Ok(())
}

/// Shared enumeration of `group_id`'s durability roots over an arbitrary
/// connection (a pooled read connection, or a write transaction for the
/// atomic re-check-and-commit paths). See
/// [`SyncState::enumerate_group_durability_roots`] for the category
/// semantics; keeping the query in one place guarantees the digest the
/// atomic commit re-checks is computed exactly like the one the readiness
/// check first captured.
pub fn enumerate_group_durability_roots_on_conn(
    conn: &Connection,
    group_id: &str,
) -> Result<DurabilityRoots, SyncSqliteError> {
    // `record_kind = 'file'` in the WHERE clause fixes the record kind for
    // every row this returns, so `RecordKind::File` below is not an
    // assumption. `symlink_target` is NOT inferred the same way, even though
    // a regular file has no business carrying one: nothing in the schema
    // forbids the column being set on a `'file'` row, the version hash binds
    // it either way, and the peer that answers a handoff query for one of
    // these roots reconstructs its own version from the column it actually
    // has. Reading it here rather than assuming `None` is what keeps the two
    // reconstructions of one row from disagreeing about its identity.
    let mut stmt = conn.prepare_cached(
        "SELECT path, size, mtime_unix_nanos, blocks_json, exec, \
                symlink_target FROM files \
         WHERE group_id = ?1 AND deleted = 0 AND record_kind = 'file' \
           AND state IN ('current', 'superseded', 'trashed') \
         ORDER BY path, version_seq",
    )?;
    let rows = stmt.query_map([group_id], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, u64>(1)?,
            r.get::<_, i64>(2)?,
            r.get::<_, String>(3)?,
            r.get::<_, i64>(4)?,
            r.get::<_, Option<Vec<u8>>>(5)?,
        ))
    })?;
    let mut roots = Vec::new();
    for row in rows {
        let (path, size, mtime_unix_nanos, blocks_json, exec, symlink_target) = row?;
        // A malformed stored block list is locally-corrupt state — report it as
        // `CorruptState` (like every other malformed-block-list path) rather
        // than letting the bare `?` classify it as a generic `Json`/protocol
        // error.
        let blocks: Vec<BlockInfo> = serde_json::from_str(&blocks_json).map_err(|error| {
            SyncSqliteError::CorruptState(format!(
                "stored block list for {path} is corrupt: {error}"
            ))
        })?;
        // Reconstruct the exact `FileVersion` this row describes and derive
        // its `version_hash` via the SAME `compute_hash()` native
        // itself hashes versions with — see `FileVersion::from_index_row`.
        let version = FileVersion::from_index_row(
            blocks,
            size,
            mtime_unix_nanos,
            RecordKind::File,
            exec != 0,
            symlink_target,
        );
        roots.push(DurabilityRoot {
            path,
            blocks: version.blocks,
            version_hash: version.version_hash,
        });
    }
    let digest = durability_roots_digest(&roots);
    Ok(DurabilityRoots { roots, digest })
}

/// See [`FileIndexRepository::root_set_generation`].
pub fn root_set_generation_on_conn(
    conn: &Connection,
    group_id: &str,
) -> Result<u64, SyncSqliteError> {
    let generation: Option<i64> = conn
        .query_row_cached(
            "SELECT generation FROM file_root_set_generation WHERE group_id = ?1",
            [group_id],
            |r| r.get(0),
        )
        .optional()?;
    // The counter only ever increments from 1, so a negative value cannot
    // be produced by the triggers that maintain it. Clamping rather than
    // erroring keeps this a pure cache key: the worst a nonsense value can
    // do is force a recomputation.
    Ok(generation.unwrap_or(0).max(0) as u64)
}

/// See [`FileIndexRepository::group_root_set_summary`].
///
/// Shares its `WHERE` clause with
/// [`enumerate_group_durability_roots_on_conn`] on purpose: the digest a
/// peer compares must be computed over exactly the rows the handoff proof
/// would enumerate, or the comparison answers a different question than the
/// one it is trusted for. The two queries differ only in which columns they
/// read back.
pub fn group_root_set_summary_on_conn(
    conn: &Connection,
    group_id: &str,
    generation: u64,
    block_in_store: &dyn Fn(&[u8]) -> bool,
) -> Result<RootSetSummary, SyncSqliteError> {
    let mut stmt = conn.prepare_cached(
        "SELECT path, size, mtime_unix_nanos, blocks_json, exec, \
                symlink_target, state, materialization_state FROM files \
         WHERE group_id = ?1 AND deleted = 0 AND record_kind = 'file' \
           AND state IN ('current', 'superseded', 'trashed') \
         ORDER BY path, version_seq",
    )?;
    let rows = stmt.query_map([group_id], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, u64>(1)?,
            r.get::<_, i64>(2)?,
            r.get::<_, String>(3)?,
            r.get::<_, i64>(4)?,
            r.get::<_, Option<Vec<u8>>>(5)?,
            r.get::<_, String>(6)?,
            r.get::<_, String>(7)?,
        ))
    })?;
    // `Present` says only that an object exists at the path, never that it
    // equals the row's version: a row counts as materialized only where a
    // usable proof names exactly the version the row holds.
    let proven_versions = usable_proof_versions_by_path(conn, group_id)?;
    let mut roots = Vec::new();
    let mut current = Vec::new();
    let mut unmaterialized_current_count = 0u64;
    let mut file_only_current_count = 0u64;
    let mut provenance = conn.prepare_cached(
        "SELECT 1 FROM group_block_provenance WHERE group_id = ?1 AND block_hash = ?2",
    )?;
    let mut stored: std::collections::HashSet<yadorilink_replica_domain::ids::BlockHash> =
        std::collections::HashSet::new();
    for row in rows {
        let (
            path,
            size,
            mtime_unix_nanos,
            blocks_json,
            exec,
            symlink_target,
            state,
            materialization_state,
        ) = row?;
        let blocks: Vec<BlockInfo> = serde_json::from_str(&blocks_json).map_err(|error| {
            SyncSqliteError::CorruptState(format!(
                "stored block list for {path} is corrupt: {error}"
            ))
        })?;
        let version = FileVersion::from_index_row(
            blocks,
            size,
            mtime_unix_nanos,
            RecordKind::File,
            exec != 0,
            symlink_target,
        );
        let proven_current_version = proven_versions.get(&path) == Some(&version.version_hash.0);
        let root =
            DurabilityRoot { path, blocks: version.blocks, version_hash: version.version_hash };
        if state == "current" {
            // Anything but a `Present` object proven to be this version means
            // the content behind this row has not been fetched, is still
            // being fetched, or is an older version's bytes. The row itself
            // exists from the moment its change is projected, which is why
            // counting rows alone would let a device that has downloaded
            // nothing describe itself exactly like one that holds
            // everything.
            let proven = proven_current_version;
            if materialization_state != MaterializationState::Present.as_db_str() || !proven {
                unmaterialized_current_count += 1;
            } else {
                // Materialized: is it also in the block store? A block without the group's
                // provenance was never put there, and provenance alone outlives a swept block.
                let mut in_store = true;
                for block in &root.blocks {
                    if stored.contains(&block.hash) {
                        continue;
                    }
                    if provenance.exists(rusqlite::params![group_id, &block.hash.0])?
                        && block_in_store(&block.hash.0)
                    {
                        stored.insert(block.hash.clone());
                    } else {
                        in_store = false;
                        break;
                    }
                }
                if !in_store {
                    file_only_current_count += 1;
                }
            }
            current.push(root.clone());
        }
        roots.push(root);
    }
    Ok(RootSetSummary {
        current_digest: durability_roots_digest(&current),
        current_count: current.len() as u64,
        unmaterialized_current_count,
        file_only_current_count,
        roots_digest: durability_roots_digest(&roots),
        roots_count: roots.len() as u64,
        generation,
    })
}

/// The version each path of `group_id` is currently proven to hold on disk:
/// the version of every regular-file proof whose fence is still current (see
/// [`crate::materialized_generation::lookup_materialized_generation`], whose
/// join this repeats for the whole group in one query).
fn usable_proof_versions_by_path(
    conn: &Connection,
    group_id: &str,
) -> Result<std::collections::HashMap<String, [u8; 32]>, SyncSqliteError> {
    let mut stmt = conn.prepare_cached(
        "SELECT g.path, g.version_hash \
           FROM path_materialized_generations g \
           JOIN path_actual_mutation_fences f \
             ON f.group_id = g.group_id AND f.path = g.path \
          WHERE g.group_id = ?1 \
            AND g.published_under_mutation_generation = f.mutation_generation \
            AND g.object_kind = 'regular_file' AND g.version_hash IS NOT NULL",
    )?;
    let rows =
        stmt.query_map([group_id], |r| Ok((r.get::<_, String>(0)?, r.get::<_, Vec<u8>>(1)?)))?;
    let mut out = std::collections::HashMap::new();
    for row in rows {
        let (path, hash) = row?;
        let hash: [u8; 32] = hash.try_into().map_err(|_| {
            SyncSqliteError::CorruptState(format!(
                "invalid version_hash length for {group_id}/{path}"
            ))
        })?;
        out.insert(path, hash);
    }
    Ok(out)
}

/// The fixed, built-in version-retention bounds applied to every link: a
/// superseded or trashed version is retained while it is within *either*
/// bound and expired only once it exceeds *both* (union-retain, intersection-
/// expire). The current/live version is never subject to retention. Retention
/// is not per-link configurable.
pub const RETENTION_MAX_VERSIONS: i64 = 10;

pub const RETENTION_MAX_AGE_DAYS: i64 = 30;

/// Why a path's rows are erased rather than superseded or tombstoned. Required by
/// [`FileIndexRepository::remove_file`], so that a new caller has to say which it is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErasureReason {
    /// A purely local artifact that no admitted change ever touched (a displaced leaf with no
    /// native authoring head): there is no replicated history to lose. Refused for a path that
    /// has or ever had a native head.
    LocalOnlyArtifact,
    /// A sync gives up the name so that another entry can take it: a file standing where
    /// descendants of the path need a directory, or an explicit directory entry the path no longer
    /// is. The row may well carry replicated history, and it is erased with it, as it always has
    /// been; keeping that history is a separate piece of work that needs the supersede path.
    DisplacedByNamespace,
    /// The path has become ignored: its rows go (history included), the file stays on disk. The
    /// user's own act, not a sync overwriting, deleting or evicting a version.
    IgnoreSweep,
}

// One parameter per SQLite row column this constructs from; grouping into
// a params struct is out of scope for a lint cleanup.
#[allow(clippy::too_many_arguments)]
pub(crate) fn version_record(
    path: String,
    version_seq: i64,
    size: u64,
    mtime_unix_nanos: i64,
    blocks_json: &str,
    deleted: i64,
    state: &str,
    origin_device_id: Option<String>,
    record_kind: &str,
    symlink_target: Option<Vec<u8>>,
    exec: i64,
) -> Result<VersionRecord, SyncSqliteError> {
    // Fail closed on a corrupt `blocks_json` column rather than coercing it to
    // an empty block list. A silent default would mask genuine index/DB
    // corruption as a legitimately empty version; a valid `"[]"` still parses
    // to an empty list and stays a valid empty record — only an unparseable
    // column errors. Log the offending path so the corruption is diagnosable.
    let blocks: Vec<BlockInfo> = serde_json::from_str(blocks_json).map_err(|error| {
        tracing::warn!(path = %path, %error, "stored block list for a retained version is corrupt; failing closed");
        SyncSqliteError::CorruptState(format!("stored block list for {path} is corrupt: {error}"))
    })?;
    let record_kind = RecordKind::from_db_str(record_kind);
    let exec = exec != 0;
    // Derive this exact row's `version_hash` the same way the durability-root
    // enumeration does — reconstruct the `FileVersion` this row describes and
    // hash it via `compute_hash()` — so a caller comparing a peer's queried
    // hash against this field is comparing against the canonical identity,
    // never a value re-derived from a different subset of columns.
    let version_hash = FileVersion::from_index_row(
        blocks.clone(),
        size,
        mtime_unix_nanos,
        record_kind,
        exec,
        symlink_target.clone(),
    )
    .version_hash;
    let state = VersionState::try_from_db_str(state)
        .map_err(|e| SyncSqliteError::InvalidInput(format!("{path}: {e}")))?;
    Ok(VersionRecord {
        path,
        version_seq,
        size,
        mtime_unix_nanos,
        blocks,
        deleted: deleted != 0,
        state,
        origin_device_id,
        record_kind,
        symlink_target,
        exec,
        version_hash,
    })
}

/// The candidate read, spelled once so a test can ask the planner about
/// exactly the statement that runs. Its `WHERE` repeats the predicate of
/// `files_conflict_copy_candidates`, which the planner needs to use it.
pub const CONFLICT_COPY_CANDIDATES_SQL: &str = "SELECT path, size, mtime_unix_nanos, blocks_json, \
     deleted FROM files WHERE group_id = ?1 AND state = 'current' AND deleted = 0 \
     AND instr(path, ' (conflicted copy, ') > 0";

/// One live current row, as [`FileIndexRepository::list_current_entries`] reads it.
#[derive(Clone, Debug)]
pub struct CurrentEntry {
    pub path: String,
    pub kind: RecordKind,
    pub blocks: Vec<BlockInfo>,
    pub symlink_target: Option<Vec<u8>>,
}

pub(crate) fn row_to_record(
    path: String,
    size: u64,
    mtime_unix_nanos: i64,
    blocks_json: &str,
    deleted: i64,
) -> Result<FileRecord, SyncSqliteError> {
    // Fail closed on a corrupt stored block list rather than coercing it to a
    // default: a defaulted (empty) block list would read as "file has no
    // content" and mask genuine index/DB corruption. A valid `"[]"` still
    // parses to a valid empty record; only an unparseable column errors. Log
    // the offending path so the corruption is diagnosable.
    let blocks: Vec<BlockInfo> = serde_json::from_str(blocks_json).map_err(|error| {
        tracing::warn!(path = %path, %error, "stored block list is corrupt; failing closed");
        SyncSqliteError::CorruptState(format!("stored block list for {path} is corrupt: {error}"))
    })?;
    Ok(FileRecord { path, size, mtime_unix_nanos, blocks, deleted: deleted != 0 })
}

/// The trash and conflict listings report each row's own kind.
#[cfg(test)]
mod shared_block_list_tests;

#[cfg(test)]
mod entry_kind_listing_tests;

/// The stored name-collision keys and their index lookups.
#[cfg(test)]
mod name_fold_tests;

/// Local capture retires what it could not observe and proves what it did.
#[cfg(test)]
#[cfg(test)]
mod row_authoring_tests;

/// A version's metadata columns land on its own row only.
#[cfg(test)]
mod version_meta_tests;

/// A block list that cannot be read back is refused at write and found by the audit.
#[cfg(test)]
mod block_list_tests;
