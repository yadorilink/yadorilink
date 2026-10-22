//! A folder rewind's commit phase: the approved plan authored as ordinary
//! signed changes, one bounded chunk per transaction.
//!
//! Nothing here is rewind-specific namespace machinery. A chunk is a run of
//! ordinary `Put`s (the exact historical version, so its mtime comes back
//! with it) and `Delete`s, authored by the bulk authoring path every bulk
//! capture uses, admitted, armed for projection and replicated like any
//! other local change. The ordinary projection writes the disk. A rename is
//! a create plus a delete. The chunk bound is the bulk path's own
//! ([`BULK_DELTA_MAX_OPS`] ops; [`author_bulk_group`] also splits by
//! bytes), so there is no rewind constant.
//!
//! What a rewind adds is the check that it changes only what was approved.
//! Inside the chunk's transaction, before anything is authored, every path
//! of the chunk must still be what the plan saw: its `current` row has the
//! plan's (seq, hash), and its live native heads all hold that content (a
//! tombstone: none). The second half catches a peer's change that was
//! admitted but not projected yet, which the row alone does not show. Any
//! difference rolls the whole chunk back and stops the run; there is no
//! per-path skip, which would be a partial rewind reported as done, and no
//! force: the concurrent change stays live and follows ordinary conflict
//! semantics.
//!
//! The journal row advances in the same transaction as the chunk's
//! changes, guarded by the chunk's index, so the journal and the signed
//! changes cannot disagree and a chunk can never be authored twice.

use std::collections::HashSet;

use rusqlite::Connection;
use yadorilink_replica_domain::file::FileVersion;
use yadorilink_replica_domain::ids::{FolderGroupId, SyncPath, VersionHash};
use yadorilink_replica_domain::local_op::Op;
use yadorilink_replica_domain::rewind::{RewindPathAction, RewindPathEntry, RewindPlan};
use yadorilink_root_authority::root_commit::RootCommitPermit;

use crate::error::SyncSqliteError;
use crate::local_author::LocalAuthor;
use crate::native_authoring::{author_bulk_group, bulk_groups, BulkOp, BULK_DELTA_MAX_OPS};
use crate::rewind_run::RewindRunRepository;

/// Test failpoint inside the chunk transaction: the (run, chunk index) whose
/// commit is aborted after its changes are authored and before the journal
/// row advances. Armed once, consumed by the commit it names, so a parallel
/// run in the same process is never hit.
#[cfg(any(test, feature = "test-support"))]
static ABORT_CHUNK_IN_TX: std::sync::Mutex<Option<(String, u64)>> = std::sync::Mutex::new(None);

/// Aborts the next commit of chunk `chunk_index` of run `run_id`
/// mid-transaction, as a crash there would: whatever the transaction wrote
/// must not survive.
#[cfg(any(test, feature = "test-support"))]
pub fn abort_chunk_in_tx_for_test(run_id: &str, chunk_index: u64) {
    *ABORT_CHUNK_IN_TX.lock().unwrap() = Some((run_id.to_string(), chunk_index));
}

/// The plan's actionable entries in commit order, cut into chunks of at
/// most [`BULK_DELTA_MAX_OPS`] entries.
///
/// Restores come first, shallowest path first (a restored directory before
/// what it contains), then removals, deepest path first (what a directory
/// contains before the directory). An interruption between chunks
/// therefore leaves both the current and the restored copies rather than
/// neither, and a restored version is a live head (which retention never
/// expires) as soon as its chunk commits.
///
/// The one restore held back is a path that has removals beneath it: a
/// directory that turns back into a file. It is put after the removals,
/// so the path is emptied before it is filled.
pub fn rewind_chunks(plan: &RewindPlan) -> Vec<Vec<RewindPathEntry>> {
    let mut deletes: Vec<&RewindPathEntry> = Vec::new();
    let mut restores: Vec<&RewindPathEntry> = Vec::new();
    for entry in &plan.entries {
        match entry.action {
            RewindPathAction::Delete => deletes.push(entry),
            RewindPathAction::Create { .. } | RewindPathAction::Replace { .. } => {
                restores.push(entry)
            }
            RewindPathAction::Unchanged | RewindPathAction::Unavailable { .. } => {}
        }
    }
    deletes.sort_by(|a, b| b.path.as_bytes().cmp(a.path.as_bytes()));
    restores.sort_by(|a, b| a.path.as_bytes().cmp(b.path.as_bytes()));
    let deleted: std::collections::BTreeSet<&str> =
        deletes.iter().map(|entry| entry.path.as_str()).collect();
    let has_removal_beneath = |path: &str| {
        let below = format!("{path}/");
        deleted
            .range::<&str, _>(below.as_str()..)
            .next()
            .is_some_and(|next| next.starts_with(&below))
    };
    let (after_removals, first): (Vec<&RewindPathEntry>, Vec<&RewindPathEntry>) =
        restores.into_iter().partition(|entry| has_removal_beneath(&entry.path));
    first
        .into_iter()
        .chain(deletes)
        .chain(after_removals)
        .collect::<Vec<_>>()
        .chunks(BULK_DELTA_MAX_OPS)
        .map(|chunk| chunk.iter().map(|entry| (*entry).clone()).collect())
        .collect()
}

/// Why a chunk committed nothing. The run stops either way.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RewindChunkStop {
    /// `path` is no longer what the plan approved: its row, its live
    /// heads, or the historical version it restores changed.
    FolderChanged { path: String },
    /// The commit path refused the chunk: this device is not a writer any
    /// more, the group is frozen, a path is held, the root was lost, or
    /// authoring refused (own-head cap, stale author).
    Refused { detail: String },
}

/// What committing one chunk did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RewindChunkOutcome {
    /// The chunk's changes and the journal advance committed together.
    /// `done`: it was the last chunk and the run is now `done`.
    Committed { done: bool },
    /// Nothing of the chunk was written.
    Stopped(RewindChunkStop),
}

/// The transaction's error: a stop (rolls back, reported as an outcome) or
/// a database failure.
enum ChunkError {
    Stop(RewindChunkStop),
    Db(SyncSqliteError),
}

impl From<SyncSqliteError> for ChunkError {
    fn from(error: SyncSqliteError) -> Self {
        // The commit path's own refusals stop the run like any other
        // refusal; they are not storage failures.
        match error {
            SyncSqliteError::GroupFrozen { .. }
            | SyncSqliteError::PathAwaitingHeldPathReconciliation { .. }
            | SyncSqliteError::AuthoringRefused { .. }
            | SyncSqliteError::PolicyUnavailable => {
                ChunkError::Stop(RewindChunkStop::Refused { detail: error.to_string() })
            }
            other => ChunkError::Db(other),
        }
    }
}

impl From<rusqlite::Error> for ChunkError {
    fn from(error: rusqlite::Error) -> Self {
        ChunkError::Db(error.into())
    }
}

impl From<r2d2::Error> for ChunkError {
    fn from(error: r2d2::Error) -> Self {
        ChunkError::Db(error.into())
    }
}

impl yadorilink_sqlite_runtime::SqlOperationError for ChunkError {
    fn is_locked(&self) -> bool {
        matches!(self, ChunkError::Db(error) if error.is_locked())
    }
}

/// The first path of `entries` that is not what the plan approved, read in
/// `conn`'s transaction. Two halves, both required:
///
/// 1. the `current` row has the entry's (seq, hash): an ordinary edit
///    advances the seq, a dropped-and-reindexed path changes the hash;
/// 2. the live heads at the path hold exactly that content: every head of
///    a live row's version (several heads of the same content are one
///    valid class), none for a tombstone. A head with other content is a
///    peer's change admitted but not projected yet.
pub fn first_changed_path(
    conn: &Connection,
    group_id: &str,
    entries: &[RewindPathEntry],
) -> Result<Option<String>, SyncSqliteError> {
    let paths: Vec<&str> = entries.iter().map(|entry| entry.path.as_str()).collect();
    let rows = crate::rewind_plan::current_rows_at(conn, group_id, &paths)?;
    let sync_paths: Vec<SyncPath> = paths.iter().map(|path| SyncPath(path.to_string())).collect();
    let heads = crate::native_store::load_heads_at_paths(
        conn,
        &FolderGroupId(group_id.to_string()),
        &sync_paths.iter().collect::<Vec<_>>(),
    )?;
    for (entry, path) in entries.iter().zip(&sync_paths) {
        let Some(row) = rows.get(&entry.path) else {
            return Ok(Some(entry.path.clone()));
        };
        if row.version_seq != entry.current_version_seq
            || row.version_hash != entry.current_version_hash
        {
            return Ok(Some(entry.path.clone()));
        }
        let live: Vec<VersionHash> =
            heads.heads_at(path).map(|head| head.payload.version).collect();
        let heads_match = if row.deleted {
            live.is_empty()
        } else {
            !live.is_empty() && live.iter().all(|version| *version == row.version_hash)
        };
        if !heads_match {
            return Ok(Some(entry.path.clone()));
        }
    }
    Ok(None)
}

impl RewindRunRepository {
    /// [`first_changed_path`] in a read transaction, for the cheap check
    /// before any content is gathered.
    pub fn first_changed_path(
        &self,
        group_id: &str,
        entries: &[RewindPathEntry],
    ) -> Result<Option<String>, SyncSqliteError> {
        self.database()
            .read::<_, SyncSqliteError>(|conn| first_changed_path(conn, group_id, entries))
    }

    /// Commits chunk `chunk_index` of run `run_id`: in one transaction,
    /// verifies the root permit, the writer verdict the caller just read
    /// (`writer`), the group's freeze, each path's hold, and
    /// [`first_changed_path`]; stores each restored historical version;
    /// authors the chunk as ordinary signed changes as `author`; checks the
    /// heads it left are exactly the approved effect; and advances the
    /// journal row (to `done` after the last chunk).
    ///
    /// A stop rolls everything of the chunk back and is returned as
    /// [`RewindChunkOutcome::Stopped`]; the caller ends the run. The row
    /// must be `prefetched` or `committing` with exactly `chunk_index`
    /// chunks done, so a chunk cannot be committed twice.
    #[allow(clippy::too_many_arguments)]
    pub fn commit_chunk(
        &self,
        run_id: &str,
        group_id: &str,
        chunk_index: u64,
        entries: &[RewindPathEntry],
        author: &LocalAuthor<'_>,
        permit: &RootCommitPermit,
        writer: bool,
    ) -> Result<RewindChunkOutcome, SyncSqliteError> {
        let result = self.database().write_immediate::<_, ChunkError>(|tx| {
            commit_chunk_in_tx(tx, run_id, group_id, chunk_index, entries, author, permit, writer)
        });
        match result {
            Ok(done) => Ok(RewindChunkOutcome::Committed { done }),
            Err(ChunkError::Stop(stop)) => Ok(RewindChunkOutcome::Stopped(stop)),
            Err(ChunkError::Db(error)) => Err(error),
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn commit_chunk_in_tx(
    tx: &rusqlite::Transaction<'_>,
    run_id: &str,
    group_id: &str,
    chunk_index: u64,
    entries: &[RewindPathEntry],
    author: &LocalAuthor<'_>,
    permit: &RootCommitPermit,
    writer: bool,
) -> Result<bool, ChunkError> {
    let refused = |detail: String| ChunkError::Stop(RewindChunkStop::Refused { detail });
    let changed =
        |path: &str| ChunkError::Stop(RewindChunkStop::FolderChanged { path: path.into() });

    let (chunks_done, chunks_total): (i64, i64) = tx.query_row(
        "SELECT chunks_done, chunks_total FROM rewind_runs \
         WHERE run_id = ?1 AND group_id = ?2 AND state IN ('prefetched', 'committing')",
        rusqlite::params![run_id, group_id],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    if chunks_done as u64 != chunk_index || chunk_index >= chunks_total as u64 {
        return Err(ChunkError::Db(SyncSqliteError::CorruptState(format!(
            "rewind run {run_id} has {chunks_done} of {chunks_total} chunks done, so chunk \
             {chunk_index} cannot be committed"
        ))));
    }
    permit.verify().map_err(|error| refused(format!("the folder's root is not held: {error}")))?;
    if !writer {
        return Err(refused("this device is no longer a writer of the folder".into()));
    }
    if crate::native_rebootstrap::group_frozen(tx, group_id)? {
        return Err(refused("the folder is being re-established".into()));
    }
    for entry in entries {
        if crate::held_path::is_held(tx, group_id, &entry.path)? {
            return Err(refused(format!("{} is held for reconciliation", entry.path)));
        }
    }
    if let Some(path) = first_changed_path(tx, group_id, entries)? {
        return Err(changed(&path));
    }

    // The exact historical versions, from their retained rows: the row must
    // still be the one the plan names.
    let mut versions: Vec<(usize, FileVersion)> = Vec::new();
    for (index, entry) in entries.iter().enumerate() {
        let (seq, hash) = match &entry.action {
            RewindPathAction::Create { version_seq, version_hash } => (*version_seq, *version_hash),
            RewindPathAction::Replace { to_version_seq, to_version_hash } => {
                (*to_version_seq, *to_version_hash)
            }
            _ => continue,
        };
        let row = crate::rewind_plan::version_row(tx, group_id, &entry.path, seq)?
            .filter(|row| !row.deleted && row.version_hash == hash)
            .ok_or_else(|| changed(&entry.path))?;
        let version = FileVersion::from_index_row(
            row.blocks,
            row.size,
            row.mtime_unix_nanos,
            row.record_kind,
            row.unix_mode,
            row.symlink_target,
            row.xattrs,
        );
        if version.version_hash != hash {
            return Err(changed(&entry.path));
        }
        versions.push((index, version));
    }
    crate::dag_store::put_file_versions_batch(
        tx,
        group_id,
        &versions.iter().map(|(_, version)| version).collect::<Vec<_>>(),
    )?;

    let mut restore_of: Vec<Option<VersionHash>> = vec![None; entries.len()];
    for (index, version) in &versions {
        restore_of[*index] = Some(version.version_hash);
    }
    let ops: Vec<Op> = entries
        .iter()
        .zip(&restore_of)
        .map(|(entry, restore)| {
            let path = SyncPath(entry.path.clone());
            match restore {
                Some(version) => Op::Put { path, version: *version },
                None => Op::Delete { path },
            }
        })
        .collect();
    let items: Vec<BulkOp<'_>> = ops.iter().map(|op| BulkOp { op, witness: None }).collect();
    let group = FolderGroupId(group_id.to_string());
    for run in bulk_groups(&items) {
        author_bulk_group(tx, &group, author, &items[run])?;
    }

    // The effect must be exactly the approved one: a restored path holds
    // only the restored version, a removed path holds nothing. Anything
    // else means authoring did not supersede what the check approved.
    let sync_paths: Vec<SyncPath> = entries.iter().map(|e| SyncPath(e.path.clone())).collect();
    let after = crate::native_store::load_heads_at_paths(
        tx,
        &group,
        &sync_paths.iter().collect::<Vec<_>>(),
    )?;
    for ((entry, path), restore) in entries.iter().zip(&sync_paths).zip(&restore_of) {
        let live: HashSet<VersionHash> =
            after.heads_at(path).map(|head| head.payload.version).collect();
        let exact = match restore {
            Some(version) => live.len() == 1 && live.contains(version),
            None => live.is_empty(),
        };
        if !exact {
            return Err(changed(&entry.path));
        }
    }

    #[cfg(any(test, feature = "test-support"))]
    {
        let mut armed = ABORT_CHUNK_IN_TX.lock().unwrap();
        if armed.as_ref().is_some_and(|(run, index)| run == run_id && *index == chunk_index) {
            *armed = None;
            return Err(ChunkError::Db(SyncSqliteError::CorruptState(
                "rewind chunk aborted inside its transaction (test failpoint)".into(),
            )));
        }
    }

    let restored = restore_of.iter().filter(|restore| restore.is_some()).count() as i64;
    let deleted = entries.len() as i64 - restored;
    let done = chunk_index + 1 == chunks_total as u64;
    tx.execute(
        "UPDATE rewind_runs \
         SET chunks_done = chunks_done + 1, restored = restored + ?3, deleted = deleted + ?4, \
             state = ?5 \
         WHERE run_id = ?1 AND chunks_done = ?2",
        rusqlite::params![
            run_id,
            chunk_index as i64,
            restored,
            deleted,
            if done { "done" } else { "committing" }
        ],
    )?;
    Ok(done)
}

#[cfg(test)]
mod tests;
