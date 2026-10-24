//! `MaterializationIntentRepository` owns the crash-recovery intent
//! journal, `materialization_intents`, whose rows record "a
//! materialization write for this path is in progress" so a startup repair
//! can disambiguate a `Present`-but-missing file from an interrupted
//! write. `begin_materialization_intent`/`clear_materialization_intent`/
//! `has_materialization_intent` are plain CRUD directly on
//! `materialization_intents`.

use std::sync::Arc;

use rusqlite::OptionalExtension;

use crate::error::SyncSqliteError;
use yadorilink_root_authority::root_commit::RootCommitPermit;
use yadorilink_sqlite_runtime::SyncDatabase;

/// Current wall-clock time in nanoseconds since the Unix epoch, clamped to
/// `0` if the clock reads before the epoch. Same reasoning as this crate's
/// existing `RESERVED_NAMESPACE_RULES_VERSION` constant duplication in
/// `store.rs`.
fn now_unix_nanos() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as i64)
        .unwrap_or(0)
}

/// Before an intent for `path` is (re)written to `target`, keeps the target
/// of the intent it replaces when that differs: an unproven earlier write
/// whose bytes may already be on disk (see `materialization_replaced_targets`).
fn keep_replaced_target(
    conn: &rusqlite::Connection,
    group_id: &str,
    path: &str,
    target: &[u8],
) -> Result<(), SyncSqliteError> {
    conn.execute(
        "INSERT OR IGNORE INTO materialization_replaced_targets \
         (group_id, path, target_version_hash) \
         SELECT group_id, path, target_version_hash FROM materialization_intents \
          WHERE group_id = ?1 AND path = ?2 AND kind = 'write' AND target_version_hash != ?3",
        rusqlite::params![group_id, path, target],
    )?;
    Ok(())
}

/// Clears `path`'s intent and, with it, the targets it had replaced --
/// the targets first. Where the two statements commit separately, a crash
/// between them then leaves the intent with no recorded targets (a capture
/// may author one of those contents again, as before they were recorded),
/// never recorded targets with no intent, which a later unrelated write of
/// the path would inherit and refuse a genuine edit restoring that content.
fn delete_intent(
    conn: &rusqlite::Connection,
    group_id: &str,
    path: &str,
) -> Result<(), SyncSqliteError> {
    conn.execute(
        "DELETE FROM materialization_replaced_targets WHERE group_id = ?1 AND path = ?2",
        rusqlite::params![group_id, path],
    )?;
    conn.execute(
        "DELETE FROM materialization_intents WHERE group_id = ?1 AND path = ?2 AND kind = 'write'",
        rusqlite::params![group_id, path],
    )?;
    Ok(())
}

/// What a close does with the write intent of a file it publishes a proof for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum IntentDisposition {
    /// Clear it: the bytes are durable. The default everywhere.
    #[default]
    Clear,
    /// Keep it open, marked as waiting for the batch flush of a received file
    /// whose proof was published under fence `mutation_generation`. The writer
    /// of the batch clears it with [`clear_flush_pending_in_tx`] once the file
    /// is on stable storage; startup repair of a file that is not what the proof
    /// says rebuilds it from the blocks.
    FlushPending { mutation_generation: i64 },
}

/// Marks `path`'s open write intent as waiting for a batch flush (see
/// [`IntentDisposition::FlushPending`]). The marker is the intent row's
/// `mutation_generation`, which a write intent otherwise leaves NULL.
pub fn mark_flush_pending_in_tx(
    tx: &rusqlite::Transaction,
    group_id: &str,
    path: &str,
    mutation_generation: i64,
) -> Result<(), SyncSqliteError> {
    tx.execute(
        "UPDATE materialization_intents SET mutation_generation = ?3 \
         WHERE group_id = ?1 AND path = ?2 AND kind = 'write'",
        rusqlite::params![group_id, path, mutation_generation],
    )?;
    Ok(())
}

/// Clears `path`'s intent if it is still the one waiting for the flush of the
/// write published under `mutation_generation`: a newer write of the path
/// reopened its intent (marker reset), and is not this flush's to clear.
/// Returns whether it was cleared.
pub fn clear_flush_pending_in_tx(
    tx: &rusqlite::Transaction,
    group_id: &str,
    path: &str,
    mutation_generation: i64,
) -> Result<bool, SyncSqliteError> {
    let waiting: i64 = tx.query_row(
        "SELECT COUNT(*) FROM materialization_intents \
         WHERE group_id = ?1 AND path = ?2 AND kind = 'write' AND mutation_generation = ?3",
        rusqlite::params![group_id, path, mutation_generation],
        |r| r.get(0),
    )?;
    if waiting == 0 {
        return Ok(false);
    }
    delete_intent(tx, group_id, path)?;
    Ok(true)
}

/// Whether `path`'s open write intent was marked as landed (see
/// [`MaterializationIntentRepository::mark_write_landed`]) and nothing has
/// proven or moved the write since: the fence is still the one the mark names
/// and no proof was published under it. A write waiting for its batch flush
/// has a proof under its fence and is excluded: its file may not have reached
/// stable storage, so its absence says nothing about the user.
pub fn write_landed_unproven(
    conn: &rusqlite::Connection,
    group_id: &str,
    path: &str,
) -> Result<bool, SyncSqliteError> {
    let count: i64 = conn.query_row(
        "SELECT COUNT(*) FROM materialization_intents i \
           JOIN path_actual_mutation_fences f \
             ON f.group_id = i.group_id AND f.path = i.path \
          WHERE i.group_id = ?1 AND i.path = ?2 AND i.kind = 'write' \
            AND i.mutation_generation IS NOT NULL \
            AND f.mutation_generation = i.mutation_generation \
            AND NOT EXISTS ( \
                SELECT 1 FROM path_materialized_generations g \
                 WHERE g.group_id = i.group_id AND g.path = i.path \
                   AND g.published_under_mutation_generation = i.mutation_generation)",
        rusqlite::params![group_id, path],
        |r| r.get(0),
    )?;
    Ok(count > 0)
}

/// The proof's recorded identity when `path`'s write intent is waiting for a
/// batch flush AND the proof it waits for still stands (published under that
/// very fence, which is still the live one). `None` when the path has no such
/// intent or the proof moved on; `Some(None)` for a proof without an identity.
pub fn flush_pending_proof_identity(
    conn: &rusqlite::Connection,
    group_id: &str,
    path: &str,
) -> Result<Option<Option<yadorilink_fs_platform::fs_identity::FileIdentity>>, SyncSqliteError> {
    let blob: Option<Option<Vec<u8>>> = conn
        .query_row(
            "SELECT g.filesystem_identity FROM materialization_intents i \
               JOIN path_materialized_generations g \
                 ON g.group_id = i.group_id AND g.path = i.path \
               JOIN path_actual_mutation_fences f \
                 ON f.group_id = i.group_id AND f.path = i.path \
              WHERE i.group_id = ?1 AND i.path = ?2 AND i.kind = 'write' \
                AND i.mutation_generation IS NOT NULL \
                AND g.published_under_mutation_generation = i.mutation_generation \
                AND f.mutation_generation = i.mutation_generation",
            rusqlite::params![group_id, path],
            |r| r.get::<_, Option<Vec<u8>>>(0),
        )
        .optional()?;
    match blob {
        None => Ok(None),
        Some(None) => Ok(Some(None)),
        Some(Some(bytes)) => {
            Ok(Some(Some(crate::file_identity_codec::decode_file_identity(&bytes)?)))
        }
    }
}

pub struct MaterializationIntentRepository {
    database: Arc<SyncDatabase>,
}

impl MaterializationIntentRepository {
    pub fn new(database: Arc<SyncDatabase>) -> Self {
        Self { database }
    }

    /// Records the durable "materialization write in progress" intent for
    /// `(group_id, path)`, targeting `target_version_hash`'s content. MUST be
    /// called (and its write committed — `PRAGMA synchronous = FULL` is set at
    /// open) *before* the temp-write-then-rename that materializes that content
    /// begins, so a crash between the two leaves the intent durably present.
    /// Overwrites any prior intent for the same path.
    pub fn begin_materialization_intent(
        &self,
        group_id: &str,
        path: &str,
        target_version_hash: &[u8],
        permit: &RootCommitPermit,
    ) -> Result<(), SyncSqliteError> {
        let now = now_unix_nanos();
        self.database.write::<_, SyncSqliteError>(|conn| {
            permit.verify()?;
            keep_replaced_target(conn, group_id, path, target_version_hash)?;
            conn.execute(
                "INSERT INTO materialization_intents \
                 (group_id, path, target_version_hash, created_at_unix_nanos) \
                 VALUES (?1, ?2, ?3, ?4) \
                 ON CONFLICT(group_id, path, kind) DO UPDATE SET \
                  target_version_hash = excluded.target_version_hash, \
                  created_at_unix_nanos = excluded.created_at_unix_nanos, \
                  mutation_generation = NULL",
                rusqlite::params![group_id, path, target_version_hash, now],
            )?;
            Ok(())
        })
    }

    /// Records, durably, that the bytes of the write `path`'s intent is open
    /// for were renamed into place and the rename reached stable storage, under
    /// the mutation fence `mutation_generation` the write bumped. From here on
    /// the name's absence is the user's doing (a remove or a move), never a
    /// rename that did not happen, which is what an open intent alone cannot
    /// tell. Only the intent of that same write is marked: a newer write
    /// reopened it, and a moved fence is no longer this write's.
    pub fn mark_write_landed(
        &self,
        group_id: &str,
        path: &str,
        mutation_generation: i64,
        permit: &RootCommitPermit,
    ) -> Result<(), SyncSqliteError> {
        self.database.write::<_, SyncSqliteError>(|conn| {
            permit.verify()?;
            conn.execute(
                "UPDATE materialization_intents SET mutation_generation = ?3 \
                 WHERE group_id = ?1 AND path = ?2 AND kind = 'write' \
                   AND mutation_generation IS NULL \
                   AND EXISTS (SELECT 1 FROM path_actual_mutation_fences f \
                                WHERE f.group_id = ?1 AND f.path = ?2 \
                                  AND f.mutation_generation = ?3)",
                rusqlite::params![group_id, path, mutation_generation],
            )?;
            Ok(())
        })
    }

    /// Clears the materialization intent for `(group_id, path)` once the write
    /// + rename + fsync has completed. Idempotent: a no-op when no intent
    ///   exists (e.g. a redundant clear, or a path that was never journaled).
    pub fn clear_materialization_intent(
        &self,
        group_id: &str,
        path: &str,
        permit: &RootCommitPermit,
    ) -> Result<(), SyncSqliteError> {
        self.database.write::<_, SyncSqliteError>(|conn| {
            permit.verify()?;
            delete_intent(conn, group_id, path)
        })
    }

    /// `_in_tx` counterpart of [`Self::begin_materialization_intent`], for a
    /// caller that already holds an open transaction spanning more writes
    /// than just this one (bounded batching of receiver-side
    /// materialization commits). Identical SQL/semantics.
    pub fn begin_materialization_intent_in_tx(
        tx: &rusqlite::Transaction,
        group_id: &str,
        path: &str,
        target_version_hash: &[u8],
        now: i64,
    ) -> Result<(), SyncSqliteError> {
        keep_replaced_target(tx, group_id, path, target_version_hash)?;
        tx.execute(
            "INSERT INTO materialization_intents \
             (group_id, path, target_version_hash, created_at_unix_nanos) \
             VALUES (?1, ?2, ?3, ?4) \
             ON CONFLICT(group_id, path, kind) DO UPDATE SET \
              target_version_hash = excluded.target_version_hash, \
              created_at_unix_nanos = excluded.created_at_unix_nanos, \
              mutation_generation = NULL",
            rusqlite::params![group_id, path, target_version_hash, now],
        )?;
        Ok(())
    }

    /// `_in_tx` counterpart of [`Self::clear_materialization_intent`]. See
    /// [`Self::begin_materialization_intent_in_tx`]'s doc comment for why
    /// this exists.
    pub fn clear_materialization_intent_in_tx(
        tx: &rusqlite::Transaction,
        group_id: &str,
        path: &str,
    ) -> Result<(), SyncSqliteError> {
        delete_intent(tx, group_id, path)
    }

    /// Whether an in-progress materialization intent exists for
    /// `(group_id, path)` — the crash-vs-offline-delete disambiguator repair
    /// consults for a `Present`-but-missing file.
    pub fn has_materialization_intent(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<bool, SyncSqliteError> {
        let count: i64 = self.database.read::<_, SyncSqliteError>(|conn| {
            Ok(conn.query_row(
                "SELECT COUNT(*) FROM materialization_intents WHERE group_id = ?1 AND path = ?2 \
                     AND kind = 'write'",
                rusqlite::params![group_id, path],
                |r| r.get(0),
            )?)
        })?;
        Ok(count > 0)
    }

    /// The live intent's `target_version_hash` for `(group_id, path)`, if one
    /// is open right now -- the projection fence local capture consults to
    /// tell a materialize-in-flight echo apart from a genuine concurrent
    /// local edit. `has_materialization_intent` alone cannot do this job: it
    /// answers "is *a* write in flight" but not "in flight toward *what*",
    /// and a caller that suppressed on presence alone would just as
    /// willingly suppress a real edit racing a DIFFERENT target. See
    /// `LocalMutationStore::materialization_intent_target`'s own doc comment
    /// for the full mechanism this backs.
    pub fn materialization_intent_target(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<Option<Vec<u8>>, SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| {
            Ok(conn
                .query_row(
                    "SELECT target_version_hash FROM materialization_intents \
                     WHERE group_id = ?1 AND path = ?2 AND kind = 'write'",
                    rusqlite::params![group_id, path],
                    |r| r.get::<_, Vec<u8>>(0),
                )
                .optional()?)
        })
    }

    /// Every path in `group_id` that currently carries an intent, as one read.
    ///
    /// The table is empty in steady state (an intent lives only for the
    /// duration of one materialize, or past a crash inside it), so this is a
    /// near-free way for a whole-group sweep to learn the exact set instead of
    /// paying a per-path question -- or a per-path unconditional write -- for
    /// an answer that is almost always "none".
    pub fn list_materialization_intent_paths(
        &self,
        group_id: &str,
    ) -> Result<std::collections::HashSet<String>, SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| {
            let mut stmt = conn.prepare(
                "SELECT path FROM materialization_intents WHERE group_id = ?1 AND kind = 'write'",
            )?;
            let rows = stmt.query_map([group_id], |r| r.get::<_, String>(0))?;
            let mut paths = std::collections::HashSet::new();
            for row in rows {
                paths.insert(row?);
            }
            Ok(paths)
        })
    }
}

/// Releases not yet written. A released record only names a file that is
/// gone, which recovery clears without touching anything, so the delete does
/// not have to be durable before the writer moves on: it is carried by the next
/// record's transaction instead of costing a write of its own. One queue is
/// shared by every ledger of a database.
///
/// The same object carries the group commit of the records themselves
/// (`MaterializationTempLedger::record`): temp names recorded at the same time
/// by different writers share one transaction, so one durable commit serves
/// all of them. It is per database by construction (every ledger sharing it
/// holds the same database).
#[derive(Default)]
pub struct TempReleaseQueue {
    releases: std::sync::Mutex<Vec<(String, String)>>,
    records: std::sync::Mutex<RecordGroup>,
    recorded: std::sync::Condvar,
    #[cfg(test)]
    record_commits: std::sync::atomic::AtomicUsize,
}

/// Records waiting for, or finished by, a group commit.
#[derive(Default)]
struct RecordGroup {
    next_id: u64,
    /// `(id, group_id, tmp_path)` of writers waiting for the next commit.
    pending: Vec<(u64, String, String)>,
    /// A finished record's outcome, until its writer picks it up: whether the
    /// name was newly recorded (`false`: it was already held by someone else).
    done: std::collections::HashMap<u64, Result<bool, String>>,
    /// A writer is committing a group right now.
    leading: bool,
}

/// Ends a leader's turn however it ends, so waiting writers are never left
/// without anyone to commit for them.
struct LeaderTurn<'a>(&'a TempReleaseQueue);

impl Drop for LeaderTurn<'_> {
    fn drop(&mut self) {
        self.0.records.lock().unwrap_or_else(|p| p.into_inner()).leading = false;
        self.0.recorded.notify_all();
    }
}

/// Past this many unwritten releases the next release writes them itself.
const MAX_QUEUED_RELEASES: usize = 256;

/// The durable record of temp files writers are about to create:
/// `materialization_tmp_files`. See that table's schema comment. The
/// repository is a [`yadorilink_local_storage::TempFileLedger`] bound to one
/// group, so a writer in `yadorilink-local-storage` records through it without
/// knowing about the database.
#[derive(Clone)]
pub struct MaterializationTempLedger {
    database: Arc<SyncDatabase>,
    group_id: String,
    releases: Arc<TempReleaseQueue>,
}

impl MaterializationTempLedger {
    pub fn new(
        database: Arc<SyncDatabase>,
        group_id: &str,
        releases: Arc<TempReleaseQueue>,
    ) -> Self {
        Self { database, group_id: group_id.to_string(), releases }
    }

    fn take_queued(&self) -> Vec<(String, String)> {
        std::mem::take(&mut *self.releases.releases.lock().unwrap_or_else(|p| p.into_inner()))
    }

    fn requeue(&self, mut released: Vec<(String, String)>) {
        let mut queue = self.releases.releases.lock().unwrap_or_else(|p| p.into_inner());
        released.append(&mut queue);
        *queue = released;
    }

    /// Records `tmp_path` and returns once it is durable. Writers that arrive
    /// while another writer is committing wait for it and are committed
    /// together by the next one: a record is never acknowledged before the
    /// commit that holds it, so the order "name durable, then the file is
    /// created" is exactly what it was with one commit per record; only the
    /// number of commits changes. `Ok(false)`: the name was already recorded.
    fn record_grouped(&self, tmp_path: &str) -> Result<bool, String> {
        let shared = &*self.releases;
        let mut group = shared.records.lock().unwrap_or_else(|p| p.into_inner());
        let id = group.next_id;
        group.next_id += 1;
        group.pending.push((id, self.group_id.clone(), tmp_path.to_string()));
        loop {
            if let Some(outcome) = group.done.remove(&id) {
                return outcome;
            }
            if group.leading {
                group = shared.recorded.wait(group).unwrap_or_else(|p| p.into_inner());
                continue;
            }
            group.leading = true;
            drop(group);
            {
                let _turn = LeaderTurn(shared);
                self.commit_pending_records();
            }
            group = shared.records.lock().unwrap_or_else(|p| p.into_inner());
        }
    }

    /// Commits every pending record, and the releases queued so far, in one
    /// transaction. The group is taken once the writer gate is held, so
    /// everything that queued while this writer waited for it rides along.
    fn commit_pending_records(&self) {
        let shared = &*self.releases;
        let take_pending = || {
            std::mem::take(&mut shared.records.lock().unwrap_or_else(|p| p.into_inner()).pending)
        };
        let mut group: Option<Vec<(u64, String, String)>> = None;
        let mut released: Option<Vec<(String, String)>> = None;
        let outcome = self.database.write_immediate::<_, SyncSqliteError>(|tx| {
            let group = group.get_or_insert_with(take_pending);
            let released = released.get_or_insert_with(|| self.take_queued());
            Self::delete_released(tx, released)?;
            // A row already held for a path is another writer's (or a
            // crashed one's): it is left exactly as it is and reported, not
            // adopted.
            let mut inserted = Vec::with_capacity(group.len());
            for (_, group_id, tmp_path) in group.iter() {
                let n = tx.execute(
                    "INSERT OR IGNORE INTO materialization_tmp_files (group_id, tmp_path) \
                     VALUES (?1, ?2)",
                    rusqlite::params![group_id, tmp_path],
                )?;
                inserted.push(n == 1);
            }
            Ok(inserted)
        });
        let group = group.unwrap_or_else(take_pending);
        let mut state = shared.records.lock().unwrap_or_else(|p| p.into_inner());
        match outcome {
            Ok(inserted) => {
                #[cfg(test)]
                shared.record_commits.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                for ((id, ..), inserted) in group.iter().zip(inserted) {
                    state.done.insert(*id, Ok(inserted));
                }
            }
            Err(error) => {
                if let Some(released) = released {
                    self.requeue(released);
                }
                for (id, ..) in &group {
                    state.done.insert(*id, Err(error.to_string()));
                }
            }
        }
    }

    fn delete_released(
        conn: &rusqlite::Connection,
        released: &[(String, String)],
    ) -> Result<(), SyncSqliteError> {
        for (group_id, tmp_path) in released {
            conn.execute(
                "DELETE FROM materialization_tmp_files WHERE group_id = ?1 AND tmp_path = ?2",
                rusqlite::params![group_id, tmp_path],
            )?;
        }
        Ok(())
    }

    /// Every temp file recorded for `group_id`, as the absolute paths the
    /// writers recorded, after the queued releases are written.
    pub fn list(&self) -> Result<Vec<String>, SyncSqliteError> {
        let released = self.take_queued();
        if !released.is_empty() {
            self.database
                .write::<_, SyncSqliteError>(|conn| Self::delete_released(conn, &released))
                .inspect_err(|_| self.requeue(released.clone()))?;
        }
        self.database.read::<_, SyncSqliteError>(|conn| {
            let mut stmt = conn.prepare(
                "SELECT tmp_path FROM materialization_tmp_files WHERE group_id = ?1 \
                 ORDER BY tmp_path",
            )?;
            let rows = stmt.query_map([&self.group_id], |r| r.get::<_, String>(0))?;
            Ok(rows.collect::<Result<Vec<_>, _>>()?)
        })
    }

    /// How many directories recorded as stranded for this group still stand.
    /// A record whose path is gone is not counted but is kept: an unmounted
    /// volume looks the same, and the record is all that tells the user when
    /// it comes back. A path that cannot be examined counts.
    pub fn standing_stranded_count(&self) -> Result<u64, SyncSqliteError> {
        let recorded = self.database.read::<_, SyncSqliteError>(|conn| {
            let mut stmt =
                conn.prepare("SELECT dir_path FROM stranded_directories WHERE group_id = ?1")?;
            let rows = stmt.query_map([&self.group_id], |r| r.get::<_, String>(0))?;
            Ok(rows.collect::<Result<Vec<_>, _>>()?)
        })?;
        Ok(recorded
            .iter()
            .filter(|dir| {
                !matches!(
                    std::fs::symlink_metadata(dir),
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound
                )
            })
            .count() as u64)
    }

    /// Forgets a recorded temp file (recovery, after the file is gone).
    pub fn forget(&self, tmp_path: &str) -> Result<(), SyncSqliteError> {
        self.database.write::<_, SyncSqliteError>(|conn| {
            Self::delete_released(conn, &[(self.group_id.clone(), tmp_path.to_string())])
        })
    }
}

fn utf8_tmp_path(
    tmp_path: &std::path::Path,
) -> Result<&str, yadorilink_local_storage::StorageError> {
    tmp_path.to_str().ok_or_else(|| {
        yadorilink_local_storage::StorageError::Io(std::io::Error::other(
            "a temp file path that is not UTF-8 cannot be recorded",
        ))
    })
}

impl yadorilink_local_storage::TempFileLedger for MaterializationTempLedger {
    fn record(
        &self,
        tmp_path: &std::path::Path,
    ) -> Result<(), yadorilink_local_storage::StorageError> {
        let tmp_path = utf8_tmp_path(tmp_path)?;
        match self.record_grouped(tmp_path) {
            Ok(true) => Ok(()),
            Ok(false) => Err(yadorilink_local_storage::StorageError::Io(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                format!("temp file ledger: {tmp_path} is already recorded"),
            ))),
            Err(error) => Err(yadorilink_local_storage::StorageError::Io(std::io::Error::other(
                format!("temp file ledger: {error}"),
            ))),
        }
    }

    fn strand(
        &self,
        dir_path: &std::path::Path,
    ) -> Result<(), yadorilink_local_storage::StorageError> {
        let dir_path = utf8_tmp_path(dir_path)?;
        self.database
            .write::<_, SyncSqliteError>(|conn| {
                conn.execute(
                    "INSERT OR IGNORE INTO stranded_directories (group_id, dir_path) \
                     VALUES (?1, ?2)",
                    rusqlite::params![self.group_id, dir_path],
                )?;
                Ok(())
            })
            .map_err(|e| {
                yadorilink_local_storage::StorageError::Io(std::io::Error::other(format!(
                    "stranded directory ledger: {e}"
                )))
            })
    }

    fn release(&self, tmp_path: &std::path::Path) {
        let Some(tmp_path) = tmp_path.to_str() else { return };
        let full = {
            let mut queue = self.releases.releases.lock().unwrap_or_else(|p| p.into_inner());
            queue.push((self.group_id.clone(), tmp_path.to_string()));
            queue.len() >= MAX_QUEUED_RELEASES
        };
        if full {
            let released = self.take_queued();
            if let Err(error) = self
                .database
                .write::<_, SyncSqliteError>(|conn| Self::delete_released(conn, &released))
            {
                self.requeue(released);
                tracing::warn!(%error, "could not write queued temp file releases; recovery clears them");
            }
        }
    }
}

#[cfg(test)]
mod stranded_tests {
    use super::*;
    use yadorilink_local_storage::TempFileLedger;

    fn ledger(group: &str, database: &Arc<SyncDatabase>) -> MaterializationTempLedger {
        MaterializationTempLedger::new(database.clone(), group, Arc::default())
    }

    /// A stranded directory is counted while it stands, per group. Once its
    /// path is gone it is not counted, but the record stays (an unmounted
    /// volume looks the same) and counts again when the path is back.
    #[test]
    fn a_stranded_directory_counts_while_it_stands_and_returns_with_its_path() {
        let database = crate::replica_tables::open_for_tests();
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join(".d.discard");
        std::fs::create_dir(&dir).unwrap();
        let (a, b) = (ledger("a", &database), ledger("b", &database));
        assert_eq!(a.standing_stranded_count().unwrap(), 0);

        a.strand(&dir).unwrap();
        a.strand(&dir).unwrap();
        assert_eq!(a.standing_stranded_count().unwrap(), 1, "recording twice is one record");
        assert_eq!(b.standing_stranded_count().unwrap(), 0, "another group is unaffected");

        std::fs::remove_dir(&dir).unwrap();
        assert_eq!(a.standing_stranded_count().unwrap(), 0);
        std::fs::create_dir(&dir).unwrap();
        assert_eq!(a.standing_stranded_count().unwrap(), 1, "the record was kept");
    }

    /// A name already recorded is another writer's: recording it again is an
    /// error that leaves the existing record alone, in every group's own terms.
    #[test]
    fn recording_a_name_already_held_is_an_error_and_keeps_the_record() {
        let database = crate::replica_tables::open_for_tests();
        let (a, b) = (ledger("a", &database), ledger("b", &database));
        let tmp = std::path::Path::new("/r/.yadorilink-tmp.0123");

        a.record(tmp).unwrap();
        let again = a.record(tmp);

        assert!(matches!(
            again,
            Err(yadorilink_local_storage::StorageError::Io(e))
                if e.kind() == std::io::ErrorKind::AlreadyExists
        ));
        assert_eq!(a.list().unwrap(), vec!["/r/.yadorilink-tmp.0123".to_string()]);
        b.record(tmp).unwrap();

        // Once its owner released it, the name is free again.
        a.release(tmp);
        a.record(tmp).unwrap();
        assert_eq!(a.list().unwrap().len(), 1);
    }

    fn wait_for_queued(queue: &TempReleaseQueue, writers: usize) -> usize {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
        loop {
            let queued = queue.records.lock().unwrap().pending.len();
            if queued == writers || std::time::Instant::now() > deadline {
                return queued;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
    }

    /// Records made at the same time share a commit, and each still returns
    /// only after the commit that holds it: while the writer gate is held, 8
    /// writers queue, and the single commit that follows serves all of them.
    #[test]
    fn records_made_together_share_one_commit_and_each_is_durable_on_return() {
        use std::sync::atomic::Ordering;
        let database = crate::replica_tables::open_for_tests();
        let queue = Arc::new(TempReleaseQueue::default());
        let ledger = MaterializationTempLedger::new(database.clone(), "g", queue.clone());
        let writers = 8;

        let (returned_tx, returned_rx) = std::sync::mpsc::channel();
        let mut handles = Vec::new();
        let waiting_for = queue.clone();
        let (gate_taken_tx, gate_taken_rx) = std::sync::mpsc::channel();
        let gate_holder = std::thread::spawn({
            let database = database.clone();
            move || {
                database
                    .write_immediate::<_, SyncSqliteError>(|_| {
                        // Hold the gate until every writer has queued its record.
                        gate_taken_tx.send(()).unwrap();
                        Ok(wait_for_queued(&waiting_for, writers))
                    })
                    .unwrap()
            }
        });
        // The gate must be taken before the writers start.
        gate_taken_rx.recv().unwrap();
        for n in 0..writers {
            let ledger = ledger.clone();
            let returned_tx = returned_tx.clone();
            handles.push(std::thread::spawn(move || {
                let tmp = std::path::PathBuf::from(format!("/r/.yadorilink-tmp.{n}"));
                ledger.record(&tmp).unwrap();
                returned_tx.send(n).unwrap();
            }));
        }
        drop(returned_tx);
        assert_eq!(gate_holder.join().unwrap(), writers, "every writer queued behind the gate");
        for handle in handles {
            handle.join().unwrap();
        }
        assert_eq!(returned_rx.iter().count(), writers);
        assert_eq!(queue.record_commits.load(Ordering::SeqCst), 1, "one commit served the group");
        // Durable: a second connection to the same file would see them; here the
        // rows are visible to a read after the commit.
        assert_eq!(ledger.list().unwrap().len(), writers);
    }

    /// Two writers recording the same name in one group: one wins, the other
    /// is told the name is held, and the winner's row is untouched.
    #[test]
    fn the_same_name_recorded_twice_in_one_group_is_held_once() {
        let database = crate::replica_tables::open_for_tests();
        let ledger = MaterializationTempLedger::new(database.clone(), "g", Arc::default());
        let tmp = std::path::Path::new("/r/.yadorilink-tmp.same");
        let results: Vec<_> = std::thread::scope(|scope| {
            let handles: Vec<_> =
                (0..4).map(|_| scope.spawn(|| ledger.record(tmp).is_ok())).collect();
            handles.into_iter().map(|h| h.join().unwrap()).collect()
        });
        assert_eq!(results.iter().filter(|ok| **ok).count(), 1);
        assert_eq!(ledger.list().unwrap().len(), 1);
    }
}
