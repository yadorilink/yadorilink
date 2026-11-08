//! `MaterializationIntentRepository` owns the crash-recovery intent
//! journal, `materialization_intents`, whose rows record "a
//! materialization write for this path is in progress" so a startup repair
//! can disambiguate a `Present`-but-missing file from an interrupted
//! write. `begin_materialization_intent`/`clear_materialization_intent`/
//! `has_materialization_intent` are plain CRUD directly on
//! `materialization_intents`.

use std::sync::Arc;
use yadorilink_sqlite_runtime::CachedStatements as _;

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
    conn.execute_cached(
        "INSERT OR IGNORE INTO materialization_replaced_targets \
         (group_id, path, target_version_hash) \
         SELECT group_id, path, target_version_hash FROM materialization_intents \
          WHERE group_id = ?1 AND path = ?2 AND kind = 'write' AND target_version_hash != ?3",
        rusqlite::params![group_id, path, target],
    )?;
    Ok(())
}

/// The statements of a write intent's open, in the caller's transaction.
///
/// A reopen starts the intent over, because the caller's fence bump retires the proof of the
/// write it replaces. `keep_flush_debt` is for an open that bumps nothing: an earlier write that
/// is waiting for its batch flush has published its proof, still stands, and its rename may not
/// be durable yet, so the phase that says so must survive (the intent is the only record of the
/// debt).
fn open_write_intent_in_tx(
    tx: &rusqlite::Transaction,
    group_id: &str,
    path: &str,
    target_version_hash: &[u8],
    now: i64,
    keep_flush_debt: bool,
) -> Result<(), SyncSqliteError> {
    keep_replaced_target(tx, group_id, path, target_version_hash)?;
    drop_stale_delete_intent(tx, group_id, path)?;
    let (generation, phase) = if keep_flush_debt {
        (
            "CASE WHEN phase = 'flush_pending' THEN mutation_generation ELSE NULL END",
            "CASE WHEN phase = 'flush_pending' THEN phase ELSE 'prepared' END",
        )
    } else {
        ("NULL", "'prepared'")
    };
    tx.execute(
        &format!(
            "INSERT INTO materialization_intents \
                 (group_id, path, target_version_hash, created_at_unix_nanos, phase) \
                 VALUES (?1, ?2, ?3, ?4, 'prepared') \
                 ON CONFLICT(group_id, path, kind) DO UPDATE SET \
                  target_version_hash = excluded.target_version_hash, \
                  created_at_unix_nanos = excluded.created_at_unix_nanos, \
                  mutation_generation = {generation}, \
                  phase = {phase}"
        ),
        rusqlite::params![group_id, path, target_version_hash, now],
    )?;
    Ok(())
}

/// Names (or, with `None`, clears) the temp file the write intent of `path` will publish, in the
/// transaction that opens the intent. A pointer only: recovery checks the file it names against
/// the version's blocks. Opens that carry no temp of their own (a repair's, a hydration's) leave
/// the pointer as it is, so a repair that re-opens the intent to finish a write from its temp does
/// not lose the name to a crash.
pub(crate) fn set_write_intent_tmp_path_in_tx(
    tx: &rusqlite::Transaction,
    group_id: &str,
    path: &str,
    tmp_path: Option<&str>,
) -> Result<(), SyncSqliteError> {
    tx.execute_cached(
        "UPDATE materialization_intents SET tmp_path = ?3 \
          WHERE group_id = ?1 AND path = ?2 AND kind = 'write'",
        rusqlite::params![group_id, path, tmp_path],
    )?;
    Ok(())
}

/// Opens the delete intent of `path` in the caller's transaction (phase `prepared`; its target is
/// empty, since a delete has no content to name, and no content hash is empty). A path carries
/// one intent at a time: the write intent it replaces keeps its target as a replaced target, as a
/// write intent that a later write replaces does.
pub(crate) fn begin_delete_intent_in_tx(
    tx: &rusqlite::Transaction,
    group_id: &str,
    path: &str,
    now: i64,
) -> Result<(), SyncSqliteError> {
    tx.execute_cached(
        "INSERT OR IGNORE INTO materialization_replaced_targets \
         (group_id, path, target_version_hash) \
         SELECT group_id, path, target_version_hash FROM materialization_intents \
          WHERE group_id = ?1 AND path = ?2 AND kind = 'write'",
        rusqlite::params![group_id, path],
    )?;
    tx.execute_cached(
        "DELETE FROM materialization_intents WHERE group_id = ?1 AND path = ?2 AND kind = 'write'",
        rusqlite::params![group_id, path],
    )?;
    tx.execute_cached(
        "INSERT INTO materialization_intents \
         (group_id, path, kind, target_version_hash, created_at_unix_nanos, phase) \
         VALUES (?1, ?2, 'delete', x'', ?3, 'prepared') \
         ON CONFLICT(group_id, path, kind) DO UPDATE SET \
          created_at_unix_nanos = excluded.created_at_unix_nanos, \
          mutation_generation = NULL, \
          tmp_path = NULL, \
          phase = 'prepared'",
        rusqlite::params![group_id, path, now],
    )?;
    Ok(())
}

/// Removes a delete intent a write replaces: a path carries one intent at a time.
fn drop_stale_delete_intent(
    conn: &rusqlite::Connection,
    group_id: &str,
    path: &str,
) -> Result<(), SyncSqliteError> {
    conn.execute_cached(
        "DELETE FROM materialization_intents WHERE group_id = ?1 AND path = ?2 AND kind = 'delete'",
        rusqlite::params![group_id, path],
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
    conn.execute_cached(
        "DELETE FROM materialization_replaced_targets WHERE group_id = ?1 AND path = ?2",
        rusqlite::params![group_id, path],
    )?;
    conn.execute_cached(
        "DELETE FROM materialization_intents \
          WHERE group_id = ?1 AND path = ?2 AND kind IN ('write', 'delete')",
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
/// [`IntentDisposition::FlushPending`]): phase `flush_pending`, with the fence the proof was
/// published under in `mutation_generation`.
pub fn mark_flush_pending_in_tx(
    tx: &rusqlite::Transaction,
    group_id: &str,
    path: &str,
    mutation_generation: i64,
) -> Result<(), SyncSqliteError> {
    tx.execute_cached(
        "UPDATE materialization_intents SET phase = 'flush_pending', mutation_generation = ?3 \
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
    let waiting: i64 = tx.query_row_cached(
        "SELECT COUNT(*) FROM materialization_intents \
         WHERE group_id = ?1 AND path = ?2 AND kind = 'write' \
           AND phase = 'flush_pending' AND mutation_generation = ?3",
        rusqlite::params![group_id, path, mutation_generation],
        |r| r.get(0),
    )?;
    if waiting == 0 {
        return Ok(false);
    }
    delete_intent(tx, group_id, path)?;
    Ok(true)
}

/// Whether `path`'s open write intent is in phase `landed` (see
/// [`MaterializationIntentRepository::mark_write_landed`]) and no proof was published under that
/// write's fence since. The phase is set exactly when the placement's rename reached stable
/// storage, which is why a landed intent's missing name is a removal by someone (the user; a
/// daemon-side removal has its own delete intent, which repair reads first), never a rename that
/// did not happen. A write whose rename is left unflushed for a batch never lands before its
/// proof: its phase goes from `prepared` to `flush_pending`. A landed mark does not lapse when
/// another mutator moves the fence afterwards.
pub fn write_landed_unproven(
    conn: &rusqlite::Connection,
    group_id: &str,
    path: &str,
) -> Result<bool, SyncSqliteError> {
    let count: i64 = conn.query_row_cached(
        "SELECT COUNT(*) FROM materialization_intents i \
          WHERE i.group_id = ?1 AND i.path = ?2 AND i.kind = 'write' \
            AND i.phase = 'landed' \
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
        .query_row_cached(
            "SELECT g.filesystem_identity FROM materialization_intents i \
               JOIN path_materialized_generations g \
                 ON g.group_id = i.group_id AND g.path = i.path \
               JOIN path_actual_mutation_fences f \
                 ON f.group_id = i.group_id AND f.path = i.path \
              WHERE i.group_id = ?1 AND i.path = ?2 AND i.kind = 'write' \
                AND i.phase = 'flush_pending' \
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
        self.database.write_immediate::<_, SyncSqliteError>(|tx| {
            permit.verify()?;
            // Bumps no fence: an earlier write's flush debt stays.
            open_write_intent_in_tx(tx, group_id, path, target_version_hash, now, true)
        })
    }

    /// Records, durably, that the bytes of the write `path`'s intent is open
    /// for were renamed into place and the rename reached stable storage, under
    /// the mutation fence `mutation_generation` the write bumped: phase `landed`.
    /// From here on the name's absence is the user's doing (a remove or a move),
    /// never a rename that did not happen, which is what an open intent alone
    /// cannot tell. Only the intent of that same write is marked: a newer write
    /// reopened it (phase `prepared` again), and a moved fence is no longer
    /// this write's. The result says whether this call marked it.
    pub fn mark_write_landed(
        &self,
        group_id: &str,
        path: &str,
        mutation_generation: i64,
        permit: &RootCommitPermit,
    ) -> Result<bool, SyncSqliteError> {
        self.database.write::<_, SyncSqliteError>(|conn| {
            permit.verify()?;
            let marked = conn.execute_cached(
                "UPDATE materialization_intents \
                    SET phase = 'landed', mutation_generation = ?3 \
                 WHERE group_id = ?1 AND path = ?2 AND kind = 'write' \
                   AND phase = 'prepared' \
                   AND ?3 > 0 \
                   AND EXISTS (SELECT 1 FROM path_actual_mutation_fences f \
                                WHERE f.group_id = ?1 AND f.path = ?2 \
                                  AND f.mutation_generation = ?3)",
                rusqlite::params![group_id, path, mutation_generation],
            )?;
            // Zero rows: another mutator moved the fence between the placement and this mark
            // (or a newer write reopened the intent). The write loses its proof commit on the
            // same fence and is re-driven; nothing is marked for it.
            Ok(marked == 1)
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
        open_write_intent_in_tx(tx, group_id, path, target_version_hash, now, false)
    }

    /// Prepares an in-place write of `path` that has no row to commit (an on-demand
    /// hydration): opens the write intent for `target_version_hash` (phase `prepared`) and
    /// bumps the path's mutation fence, in ONE transaction, and returns the bumped fence. The
    /// root permit is verified inside it. There is no committed state with an open intent and an
    /// unbumped fence, or the reverse.
    pub fn open_write_and_bump_fence(
        &self,
        group_id: &str,
        path: &str,
        target_version_hash: &[u8],
        mutation_kind: &str,
        permit: &RootCommitPermit,
    ) -> Result<i64, SyncSqliteError> {
        let now = now_unix_nanos();
        self.database.write_immediate::<_, SyncSqliteError>(|tx| {
            permit.verify()?;
            crate::content_write_open::open_write_and_bump_fence_in_tx(
                tx,
                group_id,
                path,
                target_version_hash,
                mutation_kind,
                now,
            )
        })
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
            Ok(conn.query_row_cached(
                "SELECT COUNT(*) FROM materialization_intents WHERE group_id = ?1 AND path = ?2 \
                     AND kind IN ('write', 'delete')",
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
                .query_row_cached(
                    "SELECT target_version_hash FROM materialization_intents \
                     WHERE group_id = ?1 AND path = ?2 AND kind IN ('write', 'delete')",
                    rusqlite::params![group_id, path],
                    |r| r.get::<_, Vec<u8>>(0),
                )
                .optional()?)
        })
    }

    /// What the intent open on `(group_id, path)` is for: `write` or `delete`, `None` when no
    /// intent is open.
    pub fn materialization_intent_row_kind(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<Option<String>, SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| {
            Ok(conn
                .query_row_cached(
                    "SELECT kind FROM materialization_intents \
                     WHERE group_id = ?1 AND path = ?2 AND kind IN ('write', 'delete')",
                    rusqlite::params![group_id, path],
                    |r| r.get::<_, String>(0),
                )
                .optional()?)
        })
    }

    /// Prepares a tombstone delete of `path` (one tx): opens its delete intent and bumps the
    /// path's mutation fence, and returns the bumped fence. The live row is untouched: the
    /// tombstone is committed only after the verified removal. The root permit is verified
    /// inside the transaction.
    pub fn open_delete_and_bump_fence(
        &self,
        group_id: &str,
        path: &str,
        permit: &RootCommitPermit,
    ) -> Result<i64, SyncSqliteError> {
        let now = now_unix_nanos();
        self.database.write_immediate::<_, SyncSqliteError>(|tx| {
            permit.verify()?;
            crate::content_write_open::open_delete_and_bump_fence_in_tx(tx, group_id, path, now)
        })
    }

    /// Every path in `group_id` that currently carries an intent, as one read.
    ///
    /// The table is empty in steady state (an intent lives only for the
    /// duration of one materialize, or past a crash inside it), so this is a
    /// near-free way for a whole-group sweep to learn the exact set instead of
    /// paying a per-path question -- or a per-path unconditional write -- for
    /// an answer that is almost always "none".
    /// The temp file the open write intent of `path` names, if any.
    pub fn write_intent_tmp_path(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<Option<String>, SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| {
            Ok(conn
                .query_row(
                    "SELECT tmp_path FROM materialization_intents \
                      WHERE group_id = ?1 AND path = ?2 AND kind = 'write'",
                    rusqlite::params![group_id, path],
                    |r| r.get::<_, Option<String>>(0),
                )
                .optional()?
                .flatten())
        })
    }

    /// Every temp file an open write intent of the group names: the link-start temp sweep leaves
    /// these to the repair that can finish the write from them.
    pub fn write_intent_tmp_paths(
        &self,
        group_id: &str,
    ) -> Result<std::collections::HashSet<String>, SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| {
            let mut stmt = conn.prepare_cached(
                "SELECT tmp_path FROM materialization_intents \
                  WHERE group_id = ?1 AND kind = 'write' AND tmp_path IS NOT NULL",
            )?;
            let rows = stmt.query_map([group_id], |r| r.get::<_, String>(0))?;
            let mut paths = std::collections::HashSet::new();
            for row in rows {
                paths.insert(row?);
            }
            Ok(paths)
        })
    }

    pub fn list_materialization_intent_paths(
        &self,
        group_id: &str,
    ) -> Result<std::collections::HashSet<String>, SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| {
            let mut stmt = conn.prepare_cached(
                "SELECT path FROM materialization_intents \
                  WHERE group_id = ?1 AND kind IN ('write', 'delete')",
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
                let n = tx.execute_cached(
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
            conn.execute_cached(
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
            let mut stmt = conn.prepare_cached(
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
            let mut stmt = conn
                .prepare_cached("SELECT dir_path FROM stranded_directories WHERE group_id = ?1")?;
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
                conn.execute_cached(
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

#[cfg(test)]
mod phase_tests {
    use super::*;

    fn open(database: &Arc<SyncDatabase>, path: &str) -> i64 {
        database
            .write_immediate::<_, SyncSqliteError>(|tx| {
                MaterializationIntentRepository::begin_materialization_intent_in_tx(
                    tx, "g", path, &[1; 32], 1,
                )?;
                crate::materialized_generation::bump_mutation_fence(tx, "g", path, "test", 1)
            })
            .unwrap()
    }

    fn phase(database: &Arc<SyncDatabase>, path: &str) -> Option<String> {
        database
            .read::<_, SyncSqliteError>(|conn| {
                Ok(conn
                    .query_row(
                        "SELECT phase FROM materialization_intents \
                          WHERE group_id = 'g' AND path = ?1 AND kind = 'write'",
                        [path],
                        |r| r.get(0),
                    )
                    .optional()?)
            })
            .unwrap()
    }

    fn landed(database: &Arc<SyncDatabase>, path: &str) -> bool {
        database.read::<_, SyncSqliteError>(|conn| write_landed_unproven(conn, "g", path)).unwrap()
    }

    fn mark_landed(database: &Arc<SyncDatabase>, path: &str, fence: i64) -> bool {
        database
            .write_immediate::<_, SyncSqliteError>(|tx| {
                Ok(tx.execute(
                    "UPDATE materialization_intents SET phase = 'landed', mutation_generation = ?2 \
                      WHERE path = ?1 AND phase = 'prepared'",
                    rusqlite::params![path, fence],
                )? == 1)
            })
            .unwrap()
    }

    /// An intent is opened `prepared`, and every reopen starts over: a landed or
    /// flush-pending phase of an older write does not describe the newer one.
    #[test]
    fn an_intent_opens_prepared_and_a_reopen_resets_the_phase() {
        let database = crate::replica_tables::open_for_tests();
        let fence = open(&database, "p");
        assert_eq!(phase(&database, "p").as_deref(), Some("prepared"));
        assert!(!landed(&database, "p"));

        assert!(mark_landed(&database, "p", fence));
        assert_eq!(phase(&database, "p").as_deref(), Some("landed"));
        assert!(landed(&database, "p"));

        open(&database, "p");
        assert_eq!(phase(&database, "p").as_deref(), Some("prepared"));
        assert!(!landed(&database, "p"));

        database
            .write_immediate::<_, SyncSqliteError>(|tx| mark_flush_pending_in_tx(tx, "g", "p", 7))
            .unwrap();
        assert_eq!(phase(&database, "p").as_deref(), Some("flush_pending"));
        assert!(!landed(&database, "p"), "a flush-pending intent has a proof, it is not landed");
        open(&database, "p");
        assert_eq!(phase(&database, "p").as_deref(), Some("prepared"));
    }

    /// An open that bumps no fence (an on-demand record of a newer version over an object that is
    /// still unflushed) must not erase the debt of a write waiting for its batch flush: its
    /// proof stands and its name may be lost with a power cut, and the phase is the only record.
    #[test]
    fn an_open_that_bumps_nothing_keeps_a_flush_pending_phase() {
        let database = crate::replica_tables::open_for_tests();
        open(&database, "p");
        database
            .write_immediate::<_, SyncSqliteError>(|tx| mark_flush_pending_in_tx(tx, "g", "p", 7))
            .unwrap();
        assert_eq!(phase(&database, "p").as_deref(), Some("flush_pending"));

        database
            .write_immediate::<_, SyncSqliteError>(|tx| {
                open_write_intent_in_tx(tx, "g", "p", &[2; 32], 2, true)
            })
            .unwrap();

        assert_eq!(phase(&database, "p").as_deref(), Some("flush_pending"));
        // And one that does bump starts over, as before.
        open(&database, "p");
        assert_eq!(phase(&database, "p").as_deref(), Some("prepared"));
    }

    /// Preparing an in-place write is one transaction: the intent and the fence bump commit
    /// together or not at all.
    #[test]
    fn the_intent_and_the_fence_bump_of_an_in_place_write_commit_together() {
        let database = crate::replica_tables::open_for_tests();
        let counts = |database: &Arc<SyncDatabase>| -> (i64, i64) {
            database
                .read::<_, SyncSqliteError>(|conn| {
                    let intents = conn.query_row(
                        "SELECT COUNT(*) FROM materialization_intents WHERE kind = 'write'",
                        [],
                        |r| r.get(0),
                    )?;
                    let fences = conn.query_row(
                        "SELECT COUNT(*) FROM path_actual_mutation_fences",
                        [],
                        |r| r.get(0),
                    )?;
                    Ok((intents, fences))
                })
                .unwrap()
        };
        let rolled_back: Result<(), SyncSqliteError> = database
            .write_immediate::<_, SyncSqliteError>(|tx| {
                crate::content_write_open::open_write_and_bump_fence_in_tx(
                    tx, "g", "p", &[1; 32], "test", 1,
                )?;
                Err(SyncSqliteError::CorruptState("a later statement failed".into()))
            });
        assert!(rolled_back.is_err());
        assert_eq!(counts(&database), (0, 0), "a failed prepare leaves neither");

        let fence = database
            .write_immediate::<_, SyncSqliteError>(|tx| {
                crate::content_write_open::open_write_and_bump_fence_in_tx(
                    tx, "g", "p", &[1; 32], "test", 1,
                )
            })
            .unwrap();
        assert_eq!(fence, 1);
        assert_eq!(counts(&database), (1, 1), "a committed prepare leaves both");
        assert_eq!(phase(&database, "p").as_deref(), Some("prepared"));
    }

    /// The fence bump refuses a frozen group; the prepare as a whole then leaves no intent
    /// behind (the intent must not be committed before the bump is known to hold).
    #[test]
    fn a_prepare_refused_at_the_fence_bump_leaves_no_intent() {
        let database = crate::replica_tables::open_for_tests();
        database
            .write_immediate::<_, SyncSqliteError>(|tx| {
                tx.execute(
                    "INSERT INTO native_rebootstrap_journal \
                     (group_id, recovery_id, state, target_checkpoint_hash, started_at, updated_at) \
                     VALUES ('g', 'r', 'capturing', x'00', 1, 1)",
                    [],
                )?;
                Ok(())
            })
            .unwrap();
        let permit = yadorilink_root_authority::root_commit::RootCommitPermit::for_tests();

        let refused = MaterializationIntentRepository::new(database.clone())
            .open_write_and_bump_fence("g", "p", &[1; 32], "test", &permit);

        assert!(matches!(refused, Err(SyncSqliteError::GroupFrozen { .. })), "{refused:?}");
        assert_eq!(phase(&database, "p"), None, "the intent was committed without its bump");
    }

    fn row_kind(database: &Arc<SyncDatabase>, path: &str) -> Option<String> {
        MaterializationIntentRepository::new(database.clone())
            .materialization_intent_row_kind("g", path)
            .unwrap()
    }

    /// A delete intent is its own kind with an empty target, opened together with the fence
    /// bump; a path carries one intent at a time, and a write replaces a stale delete intent as
    /// a delete replaces a write (keeping the write's target as a replaced target).
    #[test]
    fn a_delete_intent_is_its_own_kind_and_replaces_a_write_intent_and_back() {
        let database = crate::replica_tables::open_for_tests();
        let permit = yadorilink_root_authority::root_commit::RootCommitPermit::for_tests();
        let repository = MaterializationIntentRepository::new(database.clone());
        open(&database, "p");
        assert_eq!(row_kind(&database, "p").as_deref(), Some("write"));

        let fence = repository.open_delete_and_bump_fence("g", "p", &permit).unwrap();

        assert_eq!(fence, 2, "the bump follows the write's");
        assert_eq!(row_kind(&database, "p").as_deref(), Some("delete"));
        assert_eq!(repository.materialization_intent_target("g", "p").unwrap(), Some(Vec::new()));
        assert!(repository.has_materialization_intent("g", "p").unwrap());
        assert_eq!(phase(&database, "p"), None, "the phase read is for write intents");
        let writes: i64 = database
            .read::<_, SyncSqliteError>(|conn| {
                Ok(conn.query_row(
                    "SELECT COUNT(*) FROM materialization_intents WHERE path = 'p'",
                    [],
                    |r| r.get(0),
                )?)
            })
            .unwrap();
        assert_eq!(writes, 1, "one intent at a time");
        assert!(repository.list_materialization_intent_paths("g").unwrap().contains("p"));

        open(&database, "p");
        assert_eq!(row_kind(&database, "p").as_deref(), Some("write"), "a write replaces it");

        repository.open_delete_and_bump_fence("g", "p", &permit).unwrap();
        repository.clear_materialization_intent("g", "p", &permit).unwrap();
        assert_eq!(row_kind(&database, "p"), None, "a clear removes a delete intent");
    }

    /// Only a flush-pending intent under the fence the flush was told about is cleared.
    #[test]
    fn a_flush_clears_only_the_flush_pending_intent_of_its_own_write() {
        let database = crate::replica_tables::open_for_tests();
        let fence = open(&database, "p");
        let clear = |fence: i64| {
            database
                .write_immediate::<_, SyncSqliteError>(|tx| {
                    clear_flush_pending_in_tx(tx, "g", "p", fence)
                })
                .unwrap()
        };
        assert!(!clear(fence), "a prepared intent is not waiting for a flush");
        database
            .write_immediate::<_, SyncSqliteError>(|tx| {
                mark_flush_pending_in_tx(tx, "g", "p", fence)
            })
            .unwrap();
        assert!(!clear(fence + 1), "another write's flush");
        assert!(clear(fence));
        assert_eq!(phase(&database, "p"), None);
    }
}
